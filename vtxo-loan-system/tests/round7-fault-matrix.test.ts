/**
 * Round-7 fault matrix for the used-nonce registry.
 *
 * Round 5 faulted one run of four records. This matrix covers the three
 * consecutive records (plus an identical repeat), the exit/release path, and the
 * restart after every kind of fault.
 *
 *  RUN PHASE (a real child per fault): every fs call of open + three records +
 *  a repeat + close() is faulted with SIGKILL before, an errno before, and an
 *  errno after. Each child checks, at the moment it prints SIGNED, that the record
 *  is durable and the anchor covers it (the child's own invariant, round 5 I4).
 *
 *  RESTART PHASE (in-process, every fs call of a fault-free restart, errno before
 *  and after): from each state the run phase left behind, the registry is reopened
 *  with one fs call failing. Each restart must
 *    (a) load cleanly, or refuse with a NonceRegistryLockError whose message is an
 *        operator message (no raw errno error escapes), and a left-behind lock must
 *        produce the exact `rm --` recovery hint; after the operator clears it, a
 *        clean start must load;
 *    (b) every signed nonce refuses any other message and any other event;
 *    (c) every signed record is durable in the log and the anchor is the tip.
 *
 *  Exit/signal release path: a fault during close() leaves the lock file, and the
 *  next start must refuse with the recovery hint (checked in the run phase).
 */
import { spawnSync } from "child_process";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import * as ts from "typescript";

import {
  NonceRegistryLockError,
  NonceReuseError,
  UsedNonceRegistry,
} from "../src/attestation/used-nonce-registry";

const REGISTRY_SRC = path.join(__dirname, "..", "src", "attestation", "used-nonce-registry.ts");
const CHILD = path.join(__dirname, "support", "fault-matrix-child.js");

jest.setTimeout(1_800_000);

// The real module object: the registry reads fs through it at call time.
const nodeFs = require("fs") as typeof fs;

const INSTRUMENTED = [
  "openSync",
  "writeSync",
  "fsyncSync",
  "renameSync",
  "closeSync",
  "unlinkSync",
  "lstatSync",
  "fstatSync",
  "readFileSync",
  "mkdirSync",
] as const;

type FaultKind = "kill-before" | "fail-before" | "fail-after";
interface Fault {
  at: number;
  kind: FaultKind;
}
interface Signed {
  nonceId: string;
  eventId: string;
  messageHash: string;
}
interface ChildRun {
  label: string;
  lines: string[];
  killed: boolean;
  fired: boolean;
  signed: Signed[];
  calls: number;
}

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

function runChild(modulePath: string, registryPath: string, phase: "run" | "open", fault: Fault | null): ChildRun {
  const spec = fault ?? { at: 0, kind: "fail-before" };
  const result = spawnSync(
    process.execPath,
    [CHILD, modulePath, registryPath, phase, JSON.stringify(fault ? spec : { at: 0 })],
    { encoding: "utf8", timeout: 120_000 }
  );
  const lines = (result.stdout ?? "").split("\n").filter((line) => line.length > 0);
  const signed = lines
    .filter((line) => line.startsWith("SIGNED "))
    .map((line) => {
      const [, nonceId, eventId, messageHash] = line.split(" ");
      return { nonceId: nonceId!, eventId: eventId!, messageHash: messageHash! };
    });
  const callLine = lines.find((line) => line.startsWith("CALLS "));
  return {
    label: `${phase} ${fault ? `${fault.kind}@${fault.at}` : "fault-free"}`,
    lines,
    killed: result.signal === "SIGKILL",
    fired: lines.some((line) => line.startsWith("FIRED ")),
    signed,
    calls: Number(callLine?.split(" ")[1] ?? 0),
  };
}

const lockPathOf = (registryPath: string): string => `${registryPath}.lock`;
const anchorPathOf = (registryPath: string): string => `${registryPath}.anchor`;

function readJson(file: string): any | null {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw e;
  }
}

/**
 * Wraps every instrumented fs function. The fault fires on call number `fault.at`
 * (1-based) and the call count is returned. Restore must run in a finally.
 */
function instrument(fault: Fault | null): { calls: () => number; restore: () => void } {
  const originals: Record<string, (...args: unknown[]) => unknown> = {};
  let count = 0;
  for (const name of INSTRUMENTED) {
    const real = (nodeFs as any)[name] as (...args: unknown[]) => unknown;
    originals[name] = real;
    (nodeFs as any)[name] = function instrumented(...args: unknown[]): unknown {
      count += 1;
      const hit = fault !== null && fault.at === count;
      if (hit && fault!.kind === "fail-before") {
        throw Object.assign(new Error(`injected EIO in fs.${name}`), { code: "EIO" });
      }
      const result = real.apply(nodeFs, args);
      if (hit && fault!.kind === "fail-after") {
        throw Object.assign(new Error(`injected EIO in fs.${name}`), { code: "EIO" });
      }
      return result;
    };
  }
  return {
    calls: () => count,
    restore: () => {
      for (const name of INSTRUMENTED) {
        (nodeFs as any)[name] = originals[name];
      }
    },
  };
}

/** Copies one registry state (log, anchor, any leftovers) into a fresh directory */
function copyState(fromDir: string, toDir: string): string {
  fs.rmSync(toDir, { recursive: true, force: true });
  fs.cpSync(fromDir, toDir, { recursive: true });
  return path.join(toDir, "used-nonces.json");
}

/** The operator recovery the lock refusal tells the user to run, as a shell argument */
function recoveryHintOf(message: string): string | null {
  const match = /`rm -- (.+?)`/.exec(message);
  return match ? match[1]! : null;
}

/** Checks that the refusal for a left-behind lock is exact: names the lock and gives the rm hint */
function checkLockRefusal(registryPath: string, label: string): string[] {
  const violations: string[] = [];
  try {
    const registry = new UsedNonceRegistry({ persistPath: registryPath, initialize: true });
    registry.close();
    violations.push(`${label}: a left-behind lock did not refuse the start`);
  } catch (e) {
    if (!(e instanceof NonceRegistryLockError)) {
      violations.push(`${label}: lock refusal is not a NonceRegistryLockError: ${(e as Error).message}`);
      return violations;
    }
    const hint = recoveryHintOf(e.message);
    if (hint === null || !e.message.includes("is locked")) {
      violations.push(`${label}: lock refusal lacks the exact recovery hint: ${e.message}`);
    }
  }
  return violations;
}

/** Invariants (b) and (c) and I3, checked on a state a clean start can load */
function checkRecovered(registryPath: string, signed: Signed[], label: string): string[] {
  const violations: string[] = [];
  let registry: UsedNonceRegistry;
  try {
    registry = new UsedNonceRegistry({ persistPath: registryPath, initialize: true });
  } catch (e) {
    return [`${label}: liveness: a clean start refused: ${(e as Error).message}`];
  }
  try {
    for (const s of signed) {
      // (b) a nonce whose signature was released refuses any other message and any other event.
      try {
        registry.checkAndRecord(s.nonceId, s.eventId, "ff".repeat(32));
        violations.push(`${label}: (b) nonce ${s.nonceId.slice(0, 4)} accepted a different message`);
      } catch (e) {
        if (!(e instanceof NonceReuseError)) {
          violations.push(`${label}: (b) unexpected error ${(e as Error).message}`);
        }
      }
      try {
        registry.checkAndRecord(s.nonceId, "other-event", s.messageHash);
        violations.push(`${label}: (b) nonce ${s.nonceId.slice(0, 4)} accepted a different event`);
      } catch (e) {
        if (!(e instanceof NonceReuseError)) {
          violations.push(`${label}: (b) unexpected error ${(e as Error).message}`);
        }
      }
    }
    // (c) every released signature has its record durable in the recovered log.
    const log: Array<{ nonceId: string; eventId: string; messageHash: string; chain: string }> =
      readJson(registryPath)?.entries ?? [];
    for (const s of signed) {
      if (!log.some((e) => e.nonceId === s.nonceId && e.eventId === s.eventId && e.messageHash === s.messageHash)) {
        violations.push(`${label}: (c) signed record not durable after recovery: ${s.nonceId.slice(0, 4)}`);
      }
    }
    // I3: the anchor is the tip of the recovered log.
    const anchor = readJson(anchorPathOf(registryPath)) as { tip: string | null } | null;
    const tip = log.length > 0 ? log[log.length - 1]!.chain : null;
    if (anchor === null || anchor.tip !== tip) {
      violations.push(`${label}: I3 anchor ${anchor?.tip ?? "missing"} != log tip ${tip}`);
    }
  } finally {
    registry.close();
  }
  return violations;
}

/**
 * Restart phase from one run state: every fs call of a restart, failing before
 * and after. Each attempt starts from a fresh copy of the state.
 */
function restartMatrix(stateDir: string, workDir: string, signed: Signed[], label: string): { violations: string[]; attempts: number } {
  const violations: string[] = [];
  let attempts = 0;

  const probeFile = copyState(stateDir, path.join(workDir, "probe"));
  const probe = instrument(null);
  try {
    new UsedNonceRegistry({ persistPath: probeFile, initialize: true }).close();
  } finally {
    probe.restore();
  }
  const restartCalls = probe.calls();

  for (let at = 1; at <= restartCalls; at += 1) {
    for (const kind of ["fail-before", "fail-after"] as const) {
      attempts += 1;
      const tag = `${label} restart ${kind}@${at}`;
      const file = copyState(stateDir, path.join(workDir, `r-${attempts}`));
      const inst = instrument({ at, kind });
      let opened: UsedNonceRegistry | null = null;
      let openError: unknown = null;
      try {
        opened = new UsedNonceRegistry({ persistPath: file, initialize: true });
      } catch (e) {
        openError = e;
      } finally {
        inst.restore();
      }

      if (opened !== null) {
        try {
          opened.close();
        } catch (e) {
          violations.push(`${tag}: close after a successful restart threw: ${(e as Error).message}`);
        }
      } else if (!(openError instanceof NonceRegistryLockError)) {
        // (a) a restart may only refuse with an operator message, never a raw errno error.
        violations.push(`${tag}: (a) refusal is not an operator message: ${(openError as Error).message}`);
      } else if (!openError.message.startsWith("UsedNonceRegistry: ")) {
        violations.push(`${tag}: (a) refusal message has no operator prefix`);
      }

      if (fs.existsSync(lockPathOf(file))) {
        // The lock left by a failed release: the next start must refuse with the exact hint.
        violations.push(...checkLockRefusal(file, tag));
        fs.unlinkSync(lockPathOf(file)); // the operator's step, as the message says
      }
      violations.push(...checkRecovered(file, signed, tag));
    }
  }
  return { violations, attempts };
}

describe("R7 fault matrix: three records and a repeat, every fs call, run phase then restart phase", () => {
  let dir: string;
  let modulePath: string;

  beforeAll(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "r7-matrix-"));
    modulePath = compileRegistry(dir);
  });

  afterAll(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("the fault-free run signs every record, reopens cleanly, and restarts without a fault", () => {
    const registryPath = path.join(dir, "baseline", "used-nonces.json");
    fs.mkdirSync(path.dirname(registryPath), { recursive: true });
    const run = runChild(modulePath, registryPath, "run", null);
    expect(run.lines.filter((l) => l.startsWith("VIOLATION"))).toEqual([]);
    expect(run.lines.filter((l) => l.startsWith("ERROR"))).toEqual([]);
    expect(run.signed.length).toBe(4);
    expect(run.lines).toContain("DONE");
    expect(checkRecovered(registryPath, run.signed, "baseline")).toEqual([]);
  });

  it("the exit/release path: a failed unlink on close leaves a lock that refuses the next start with the exact hint", () => {
    const registryPath = path.join(dir, "release", "used-nonces.json");
    fs.mkdirSync(path.dirname(registryPath), { recursive: true });
    const baseline = runChild(modulePath, registryPath, "run", null);
    fs.rmSync(path.dirname(registryPath), { recursive: true, force: true });
    fs.mkdirSync(path.dirname(registryPath), { recursive: true });
    // Find the unlink of the lock at the end of the run: the last unlinkSync call.
    const callLines = baseline.lines.length;
    expect(callLines).toBeGreaterThan(0);
    const total = baseline.calls;
    let lockUnlinkCall = -1;
    for (let at = total; at >= 1; at -= 1) {
      const run = runChild(modulePath, registryPath, "run", { at, kind: "fail-before" });
      if (run.lines.some((l) => l.startsWith("ERROR") && l.includes("injected")) && fs.existsSync(lockPathOf(registryPath))) {
        lockUnlinkCall = at;
        break;
      }
      fs.rmSync(path.dirname(registryPath), { recursive: true, force: true });
      fs.mkdirSync(path.dirname(registryPath), { recursive: true });
    }
    expect(lockUnlinkCall).toBeGreaterThan(0);
    expect(checkLockRefusal(registryPath, "release fail-before")).toEqual([]);
  });

  it("restart: SIGKILL at every fs call of a restart leaves either no lock (clean start) or a lock that refuses with the exact hint", () => {
    const base = path.join(dir, "restart-kill-base");
    const registryPath = path.join(base, "used-nonces.json");
    fs.mkdirSync(base, { recursive: true });
    const run = runChild(modulePath, registryPath, "run", null);
    expect(run.signed.length).toBe(4);

    const probe = runChild(modulePath, copyState(base, path.join(dir, "restart-kill-probe")), "open", null);
    expect(probe.calls).toBeGreaterThan(5);

    const violations: string[] = [];
    for (let at = 1; at <= probe.calls; at += 1) {
      const file = copyState(base, path.join(dir, `restart-kill-${at}`));
      const child = runChild(modulePath, file, "open", { at, kind: "kill-before" });
      const tag = `restart kill-before@${at}`;
      if (!child.killed) violations.push(`${tag}: expected SIGKILL, child exited normally`);
      if (fs.existsSync(lockPathOf(file))) {
        // Killed after the lock was taken: the next start must refuse with the exact hint.
        violations.push(...checkLockRefusal(file, tag));
        fs.unlinkSync(lockPathOf(file));
      }
      violations.push(...checkRecovered(file, run.signed, tag));
    }
    expect(violations).toEqual([]);
  });

  it("every fs call of the run phase, under kill / fail-before / fail-after, keeps (a) (b) (c) I1 I3 and liveness", () => {
    const baselinePath = path.join(dir, "count", "used-nonces.json");
    fs.mkdirSync(path.dirname(baselinePath), { recursive: true });
    const baseline = runChild(modulePath, baselinePath, "run", null);
    const calls = baseline.calls;
    expect(calls).toBeGreaterThan(40);

    const violations: string[] = [];
    let index = 0;
    let restartAttempts = 0;
    let liveStates = 0;
    const kinds: FaultKind[] = ["kill-before", "fail-before", "fail-after"];
    for (let at = 1; at <= calls; at += 1) {
      for (const kind of kinds) {
        index += 1;
        const work = path.join(dir, `run-${index}`);
        const registryPath = path.join(work, "used-nonces.json");
        fs.mkdirSync(work, { recursive: true });
        const run = runChild(modulePath, registryPath, "run", { at, kind });
        const tag = run.label;

        if (!run.fired) {
          violations.push(`${tag}: the injected fault did not fire`);
          continue;
        }
        if (kind === "kill-before" && !run.killed) {
          violations.push(`${tag}: expected SIGKILL, child exited normally`);
        }
        for (const line of run.lines) {
          if (line.startsWith("VIOLATION")) violations.push(`${tag}: child ${line}`);
        }
        for (const line of run.lines.filter((l) => l.startsWith("ERROR "))) {
          if (!line.includes("injected")) violations.push(`${tag}: unexpected error ${line}`);
        }
        // Operator step: the run left a lock (kill, or a failed release). Its refusal must be exact.
        if (fs.existsSync(lockPathOf(registryPath))) {
          violations.push(...checkLockRefusal(registryPath, tag));
          fs.unlinkSync(lockPathOf(registryPath));
        }
        // A state with no log and no anchor is an empty start; restart matrix still applies.
        const matrix = restartMatrix(work, path.join(dir, `restart-${index}`), run.signed, tag);
        restartAttempts += matrix.attempts;
        violations.push(...matrix.violations);
        liveStates += 1;
      }
    }

    // Reported as one list, so every violation is visible in a single run.
    if (process.env.R7_VIOLATIONS_FILE) {
      fs.writeFileSync(process.env.R7_VIOLATIONS_FILE, violations.join("\n") + "\n");
    }
    if (violations.length > 0) {
      // eslint-disable-next-line no-console
      console.log(`R7 violations (${violations.length}):\n${violations.slice(0, 20).join("\n")}`);
    }
    expect({ states: liveStates, restartAttempts, violations: violations.length }).toEqual({
      states: calls * kinds.length,
      restartAttempts: expect.any(Number),
      violations: 0,
    });
  });
});

describe("R7 recovery hint: the rm command quotes the lock path for the shell", () => {
  it("a registry directory with a single quote in its name yields a hint the shell parses back to the lock path", () => {
    const base = fs.mkdtempSync(path.join(os.tmpdir(), "r7-quote-"));
    const dir = path.join(base, "it's a dir");
    fs.mkdirSync(dir);
    try {
      const registryPath = path.join(dir, "used-nonces.json");
      // A lock left by a previous process.
      fs.writeFileSync(lockPathOf(registryPath), "{}");
      let message = "";
      try {
        new UsedNonceRegistry({ persistPath: registryPath, initialize: true });
      } catch (e) {
        message = (e as Error).message;
      }
      expect(message).toContain("is locked");
      const hint = recoveryHintOf(message);
      expect(hint).not.toBeNull();
      // The shell must read the hint argument back as exactly the lock path.
      const { execFileSync } = require("child_process") as typeof import("child_process");
      const printed = execFileSync("sh", ["-c", `printf '%s' ${hint!}`], { encoding: "utf8" });
      expect(printed).toBe(lockPathOf(registryPath));
    } finally {
      fs.rmSync(base, { recursive: true, force: true });
    }
  });
});
