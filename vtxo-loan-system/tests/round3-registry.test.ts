/**
 * Round-3 regression tests, used-nonce registry (anchor lag, anchor adoption,
 * alias reads, lock release on clean exit and SIGTERM, engine shutdown).
 *
 *  R3-1  a failed anchor write cannot let the log run ahead of the anchor
 *  R3-2  startup adopts exactly one entry beyond the anchor, never more
 *  R3-3  the anchor is read through O_NOFOLLOW: a symlinked anchor is refused
 *  R3-4  the lock is released on clean process exit (no stale lock)
 *  R3-5  SIGTERM releases the lock when the registry owns signal handling
 *  R3-6  AttestationEngine.close() releases the registry lock
 */
import { spawn } from "child_process";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import { BitcoinNetworks } from "bitcoin-networks";

import { AttestationEngine } from "../src/attestation/attestation-engine";
import {
  NonceRegistryLockError,
  UsedNonceRegistry,
} from "../src/attestation/used-nonce-registry";
import { MockKeyProvider } from "../src/keys/key-provider";

const ROOT = path.join(__dirname, "..");
const CHILD = path.join(__dirname, "support", "registry-child.js");
const MNEMONIC = "test test test test test test test test test test test junk";

jest.setTimeout(60_000);

function tmpRegistry(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "r3-registry-"));
  return path.join(dir, "used-nonces.json");
}

function logEntryCount(registryPath: string): number {
  return (JSON.parse(fs.readFileSync(registryPath, "utf8")) as { entries: unknown[] }).entries
    .length;
}

describe("R3-1: a failed anchor write cannot let the log run ahead", () => {
  it("refuses further records while the anchor is behind, then catches up", () => {
    const registryPath = tmpRegistry();
    const anchorPath = `${registryPath}.anchor`;
    const registry = new UsedNonceRegistry({ persistPath: registryPath, initialize: true });
    registry.checkAndRecord("11".repeat(32), "event-1", "aa".repeat(32));

    // Make the next anchor write fail: a directory cannot be replaced by a rename.
    fs.unlinkSync(anchorPath);
    fs.mkdirSync(anchorPath);

    // Log commit succeeds, anchor commit fails: the call throws (not signed).
    expect(() => registry.checkAndRecord("22".repeat(32), "event-2", "bb".repeat(32))).toThrow();
    expect(logEntryCount(registryPath)).toBe(2);

    // The anchor is still behind: a new record must not extend the log further.
    expect(() => registry.checkAndRecord("33".repeat(32), "event-3", "cc".repeat(32))).toThrow();
    expect(logEntryCount(registryPath)).toBe(2);

    // Fix the anchor location; retrying the already-committed record catches up.
    fs.rmdirSync(anchorPath);
    registry.checkAndRecord("22".repeat(32), "event-2", "bb".repeat(32));
    registry.close();

    // Record 3 was refused before it was recorded (R6-1: a new record is added only
    // to a fully committed log), so the retry commits record 2 alone. Record 3 was
    // never signed and can still be recorded later.
    const restarted = new UsedNonceRegistry({ persistPath: registryPath, initialize: true });
    expect(restarted.size).toBe(2);
    expect(restarted.get("33".repeat(32))).toBeUndefined();
    restarted.close();
  });
});

describe("R3-2: startup adopts at most one entry beyond the anchor", () => {
  it("refuses a log that is two entries ahead of the anchor", () => {
    const registryPath = tmpRegistry();
    const anchorPath = `${registryPath}.anchor`;
    const registry = new UsedNonceRegistry({ persistPath: registryPath, initialize: true });
    registry.checkAndRecord("11".repeat(32), "event-1", "aa".repeat(32));
    const anchorAtOne = fs.readFileSync(anchorPath);
    registry.checkAndRecord("22".repeat(32), "event-2", "bb".repeat(32));
    registry.checkAndRecord("33".repeat(32), "event-3", "cc".repeat(32));
    registry.close();

    // Roll the anchor back two commits: no crash produces this state.
    fs.writeFileSync(anchorPath, anchorAtOne);
    expect(() => new UsedNonceRegistry({ persistPath: registryPath, initialize: true })).toThrow(
      /more than one entry ahead/
    );
  });

  it("still adopts exactly one entry beyond the anchor (crash after log commit)", () => {
    const registryPath = tmpRegistry();
    const anchorPath = `${registryPath}.anchor`;
    const registry = new UsedNonceRegistry({ persistPath: registryPath, initialize: true });
    registry.checkAndRecord("11".repeat(32), "event-1", "aa".repeat(32));
    const anchorAtOne = fs.readFileSync(anchorPath);
    registry.checkAndRecord("22".repeat(32), "event-2", "bb".repeat(32));
    registry.close();

    fs.writeFileSync(anchorPath, anchorAtOne);
    const restarted = new UsedNonceRegistry({ persistPath: registryPath, initialize: true });
    expect(restarted.get("22".repeat(32))).toEqual({
      eventId: "event-2",
      messageHash: "bb".repeat(32),
    });
    restarted.close();
  });
});

describe("R3-3: the anchor is read without following links", () => {
  it("refuses a symlinked anchor", () => {
    const registryPath = tmpRegistry();
    const anchorPath = `${registryPath}.anchor`;
    const registry = new UsedNonceRegistry({ persistPath: registryPath, initialize: true });
    registry.checkAndRecord("11".repeat(32), "event-1", "aa".repeat(32));
    registry.close();

    const elsewhere = `${anchorPath}.moved`;
    fs.renameSync(anchorPath, elsewhere);
    fs.symlinkSync(elsewhere, anchorPath);
    expect(() => new UsedNonceRegistry({ persistPath: registryPath, initialize: true })).toThrow(
      NonceRegistryLockError
    );
  });
});

function spawnAndWait(
  args: string[]
): Promise<{ code: number | null; signal: NodeJS.Signals | null; out: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CHILD, ...args], { cwd: ROOT });
    let out = "";
    child.stdout.on("data", (chunk) => (out += String(chunk)));
    child.stderr.on("data", (chunk) => (out += String(chunk)));
    child.on("error", reject);
    child.on("exit", (code, signal) => resolve({ code, signal, out }));
  });
}

describe("R3-4 / R3-5: the lock is released on clean exit and on SIGTERM", () => {
  it("a clean process.exit() leaves no lock behind", async () => {
    const registryPath = tmpRegistry();
    const result = await spawnAndWait([registryPath, "exit"]);
    expect(result.out).toContain("RECORDED");
    expect(fs.existsSync(`${registryPath}.lock`)).toBe(false);
    const registry = new UsedNonceRegistry({ persistPath: registryPath, initialize: true });
    expect(registry.get("ee".repeat(32))).toEqual({
      eventId: "event-exit",
      messageHash: "ff".repeat(32),
    });
    registry.close();
  });

  it("SIGTERM releases the lock and terminates with the signal", async () => {
    const registryPath = tmpRegistry();
    const child = spawn(process.execPath, [CHILD, registryPath, "hold"], { cwd: ROOT });
    await new Promise<void>((resolve, reject) => {
      child.stdout.on("data", (chunk) => {
        if (String(chunk).includes("HELD")) resolve();
      });
      child.on("error", reject);
      child.on("exit", () => reject(new Error("child exited before HELD")));
    });
    const exited = new Promise<NodeJS.Signals | null>((resolve) =>
      child.on("exit", (_code, signal) => resolve(signal))
    );
    child.kill("SIGTERM");
    expect(await exited).toBe("SIGTERM");
    expect(fs.existsSync(`${registryPath}.lock`)).toBe(false);
    const registry = new UsedNonceRegistry({ persistPath: registryPath, initialize: true });
    registry.close();
  });
});

describe("R3-6: AttestationEngine.close() releases the registry lock", () => {
  it("a closed engine no longer blocks a new writer on the same registry", async () => {
    const registryPath = tmpRegistry();
    const engine = new AttestationEngine({
      network: BitcoinNetworks.bitcoin_regtest,
      keyProvider: new MockKeyProvider(MNEMONIC),
      usedNonceRegistryPath: registryPath,
      usedNonceRegistryInit: true,
      developmentMode: true,
    } as any);
    await engine.initialize();
    expect(() => new UsedNonceRegistry({ persistPath: registryPath, initialize: true })).toThrow(
      NonceRegistryLockError
    );
    engine.close();
    const registry = new UsedNonceRegistry({ persistPath: registryPath, initialize: true });
    registry.close();
  });
});
