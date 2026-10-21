/**
 * Round-5 fault injection for the used-nonce registry.
 *
 * The scenario in tests/support/fault-child.js runs in a real child process. The
 * child is faulted at every fs call the registry makes, in three ways: SIGKILL
 * before the call, an errno instead of the call, and an errno after the call
 * ran. The fs calls are numbered in the fault-free run, and the faulted runs are
 * identical to it up to the faulted call, so every index must fire.
 *
 * After each run, with the dead child's lock cleared the way an operator would,
 * the registry must reopen (liveness), and the invariants must hold:
 *
 *  I1  every record that may have produced a signature is durable: it is in the
 *      recovered log, and the child checked that before printing SIGNED
 *  I2  no durable nonce can sign a different message or event (reuse is refused),
 *      so a crash never re-opens a nonce for reuse
 *  I3  after recovery the anchor is the log tip (the one-entry adoption completed)
 *  I4  inside the child, after every step the log is at most one entry ahead of
 *      the anchor, and the anchor covers every record at the moment it signs
 */
import { spawnSync } from "child_process";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import * as ts from "typescript";

import {
  NonceReuseError,
  UsedNonceRegistry,
} from "../src/attestation/used-nonce-registry";

const REGISTRY_SRC = path.join(__dirname, "..", "src", "attestation", "used-nonce-registry.ts");
const CHILD = path.join(__dirname, "support", "fault-child.js");

jest.setTimeout(900_000);

/**
 * Transpiles the production registry and the one local module it imports (the
 * event-id rule in tagged-hash) into a scratch tree with the same relative layout,
 * so the child loads exactly the production code. node_modules is linked in for
 * the hash dependency.
 */
function compileRegistry(dir: string): string {
  for (const rel of ["attestation/used-nonce-registry", "crypto/tagged-hash"]) {
    const src = path.join(__dirname, "..", "src", `${rel}.ts`);
    const out = ts.transpileModule(fs.readFileSync(src, "utf8"), {
      compilerOptions: {
        module: ts.ModuleKind.CommonJS,
        target: ts.ScriptTarget.ES2020,
        esModuleInterop: true,
      },
    });
    const file = path.join(dir, `${rel}.js`);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, out.outputText);
  }
  fs.symlinkSync(path.join(__dirname, "..", "node_modules"), path.join(dir, "node_modules"));
  return path.join(dir, "attestation", "used-nonce-registry.js");
}

interface Fault {
  at: number;
  kind: "kill-before" | "fail-before" | "fail-after" | "none";
}

interface ChildRun {
  label: string;
  killed: boolean;
  fired: boolean;
  lines: string[];
}

function runChild(modulePath: string, registryPath: string, fault: Fault): ChildRun {
  const result = spawnSync(
    process.execPath,
    [CHILD, modulePath, registryPath, JSON.stringify(fault)],
    { encoding: "utf8", timeout: 60_000 }
  );
  const lines = (result.stdout ?? "").split("\n").filter((line) => line.length > 0);
  return {
    label: `${fault.kind}@${fault.at}`,
    killed: result.signal === "SIGKILL",
    fired: lines.some((line) => line.startsWith("FIRED ")),
    lines,
  };
}

function readJson(file: string): unknown | null {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") {
      return null;
    }
    throw e;
  }
}

/**
 * Operator recovery plus invariant checks on the state a crashed or failed run
 * left behind. Returns the list of violations (empty = all invariants hold).
 */
function recoverAndCheck(run: ChildRun, registryPath: string): string[] {
  const violations: string[] = [];
  for (const line of run.lines) {
    if (line.startsWith("VIOLATION")) {
      violations.push(`${run.label}: child ${line}`);
    }
    // An error may surface to the caller only when it is the injected fault itself.
    if (line.startsWith("ERROR ") && !line.includes("injected")) {
      violations.push(`${run.label}: unexpected error ${line}`);
    }
  }

  // The child is dead, so no process holds the lock. Clear it as an operator would.
  const lockPath = `${registryPath}.lock`;
  if (fs.existsSync(lockPath)) {
    fs.unlinkSync(lockPath);
  }

  let registry: UsedNonceRegistry;
  try {
    registry = new UsedNonceRegistry({ persistPath: registryPath, initialize: true });
  } catch (e) {
    violations.push(`${run.label}: liveness: registry refused to reopen: ${(e as Error).message}`);
    return violations;
  }

  try {
    // I2: every durable record (anything that may have signed) refuses reuse.
    const log = (readJson(registryPath) as { entries: Array<Record<string, string>> } | null)
      ?.entries ?? [];
    for (const entry of log) {
      const otherMessage = "ff".repeat(32);
      try {
        registry.checkAndRecord(entry.nonceId, entry.eventId, otherMessage);
        violations.push(`${run.label}: I2 nonce ${entry.nonceId} accepted a different message`);
      } catch (e) {
        if (!(e instanceof NonceReuseError)) {
          violations.push(`${run.label}: I2 unexpected error ${(e as Error).message}`);
        }
      }
      try {
        registry.checkAndRecord(entry.nonceId, "other-event", entry.messageHash);
        violations.push(`${run.label}: I2 nonce ${entry.nonceId} accepted a different event`);
      } catch (e) {
        if (!(e instanceof NonceReuseError)) {
          violations.push(`${run.label}: I2 unexpected error ${(e as Error).message}`);
        }
      }
    }

    // I1: every printed signature has its record in the recovered log.
    for (const line of run.lines.filter((l) => l.startsWith("SIGNED "))) {
      const [, nonceId, eventId, messageHash] = line.split(" ");
      const found = log.some(
        (entry) =>
          entry.nonceId === nonceId &&
          entry.eventId === eventId &&
          entry.messageHash === messageHash
      );
      if (!found) {
        violations.push(`${run.label}: I1 signed record missing after recovery: ${nonceId}`);
      }
    }

    // I3: the anchor is the tip of the recovered log.
    const anchor = readJson(`${registryPath}.anchor`) as { tip: string | null } | null;
    const tip = log.length > 0 ? log[log.length - 1]!.chain : null;
    if (anchor === null || anchor.tip !== tip) {
      violations.push(`${run.label}: I3 anchor ${anchor?.tip ?? "missing"} != log tip ${tip}`);
    }
  } finally {
    registry.close();
  }
  return violations;
}

describe("R5 fault injection: every fs call of the registry, faulted in a real child", () => {
  let dir: string;
  let modulePath: string;

  beforeAll(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "r5-faults-"));
    modulePath = compileRegistry(dir);
  });

  afterAll(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("the fault-free scenario signs every record and reopens cleanly", () => {
    const registryPath = path.join(dir, "baseline", "used-nonces.json");
    fs.mkdirSync(path.dirname(registryPath), { recursive: true });
    const run = runChild(modulePath, registryPath, { at: 0, kind: "none" });
    expect(run.lines.filter((l) => l.startsWith("VIOLATION"))).toEqual([]);
    expect(run.lines.filter((l) => l.startsWith("SIGNED ")).length).toBe(4);
    expect(run.lines).toContain("DONE");
    expect(recoverAndCheck(run, registryPath)).toEqual([]);
  });

  it("no crash or injected error at any fs call breaks I1-I4 or liveness", () => {
    const baselinePath = path.join(dir, "count", "used-nonces.json");
    fs.mkdirSync(path.dirname(baselinePath), { recursive: true });
    const baseline = runChild(modulePath, baselinePath, { at: 0, kind: "none" });
    const callLine = baseline.lines.find((l) => l.startsWith("CALLS "));
    const calls = Number(callLine?.split(" ")[1]);
    expect(calls).toBeGreaterThan(50);

    const failures: string[] = [];
    const kinds: Fault["kind"][] = ["kill-before", "fail-before", "fail-after"];
    let index = 0;
    for (let at = 1; at <= calls; at += 1) {
      for (const kind of kinds) {
        index += 1;
        const registryPath = path.join(dir, `run-${index}`, "used-nonces.json");
        fs.mkdirSync(path.dirname(registryPath), { recursive: true });
        const run = runChild(modulePath, registryPath, { at, kind });
        if (!run.fired) {
          failures.push(`${run.label}: the injected fault did not fire`);
          continue;
        }
        if (kind === "kill-before" && !run.killed) {
          failures.push(`${run.label}: expected SIGKILL, child exited normally`);
        }
        failures.push(...recoverAndCheck(run, registryPath));
      }
    }
    // Reported as one list, so every violation is visible in a single run.
    expect(failures).toEqual([]);
  });
});
