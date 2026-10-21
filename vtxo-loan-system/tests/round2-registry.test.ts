/**
 * Round-2 regression tests, used-nonce registry (Ark-TradeLayer findings N1-N4).
 *
 *  N1  two processes racing a registry must never both acquire it; a stale
 *      lock is never taken over; lock ownership is re-verified before commit
 *  N2  a crash between the log commit and the anchor update recovers without
 *      losing the record, and a failed commit is retried before it is answered
 *  N3  a lock left by a dead writer is never reclaimed automatically
 *  N4  symlink and hard-link aliases of the registry cannot open a second lock
 *
 * The two-writer cases use real child processes (tests/support/registry-child.js).
 */
import { spawn } from "child_process";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import {
  NonceRegistryLockError,
  NonceReuseError,
  UsedNonceRegistry,
} from "../src/attestation/used-nonce-registry";

const ROOT = path.join(__dirname, "..");
const CHILD = path.join(__dirname, "support", "registry-child.js");

jest.setTimeout(60_000);

function tmpRegistry(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "r2-registry-"));
  return path.join(dir, "used-nonces.json");
}

/** Spawns a registry-child.js process and collects its output and exit code */
function spawnChild(args: string[]): Promise<{ code: number | null; out: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CHILD, ...args], { cwd: ROOT });
    let out = "";
    child.stdout.on("data", (chunk) => (out += String(chunk)));
    child.stderr.on("data", (chunk) => (out += String(chunk)));
    child.on("error", reject);
    child.on("exit", (code) => resolve({ code, out }));
  });
}

// Node's fs module object: jest.spyOn must patch the object the registry reads
// (the TS namespace import in tests is a separate wrapper).
const nodeFs = require("fs") as typeof fs;

describe("N1: two-writer reclaim race", () => {
  it("two processes racing a fresh registry: exactly one acquires, in every round", async () => {
    for (let round = 0; round < 3; round++) {
      const registryPath = tmpRegistry();
      const startAt = Date.now() + 1000;
      const results = await Promise.all([
        spawnChild([registryPath, "race", String(startAt)]),
        spawnChild([registryPath, "race", String(startAt)]),
      ]);
      const acquired = results.filter((r) => /ACQUIRED/.test(r.out)).length;
      const refused = results.filter((r) => /REFUSED/.test(r.out)).length;
      expect({ round, acquired, refused }).toEqual({ round, acquired: 1, refused: 1 });
    }
  });

  it("a stale lock from a dead pid is never taken over, even by racing starters", async () => {
    for (let round = 0; round < 3; round++) {
      const registryPath = tmpRegistry();
      // Same shape as the round-2 probe: a dead owner on this host, no history digest
      fs.writeFileSync(
        `${registryPath}.lock`,
        JSON.stringify({
          pid: 999999,
          hostname: os.hostname(),
          acquiredAt: "",
          token: "stale",
          historyDigest: null,
        })
      );
      const startAt = Date.now() + 1000;
      const results = await Promise.all([
        spawnChild([registryPath, "race", String(startAt)]),
        spawnChild([registryPath, "race", String(startAt)]),
      ]);
      expect(results.filter((r) => /ACQUIRED/.test(r.out))).toHaveLength(0);
      expect(results.every((r) => r.code === 3)).toBe(true);
    }
  });

  it("re-verifies lock ownership before every commit: a replaced lock stops persistence", () => {
    const registryPath = tmpRegistry();
    const registry = new UsedNonceRegistry({ persistPath: registryPath, initialize: true });
    registry.checkAndRecord("11".repeat(32), "event-1", "aa".repeat(32));
    const committed = fs.readFileSync(registryPath, "utf8");

    // An operator or attacker replaces the lock file while this instance runs.
    fs.unlinkSync(`${registryPath}.lock`);
    fs.writeFileSync(`${registryPath}.lock`, "{}");

    expect(() => registry.checkAndRecord("22".repeat(32), "event-2", "bb".repeat(32))).toThrow(
      NonceRegistryLockError
    );
    expect(fs.readFileSync(registryPath, "utf8")).toBe(committed);
    // The failed commit is not released by a repeat call either
    expect(() => registry.checkAndRecord("22".repeat(32), "event-2", "bb".repeat(32))).toThrow(
      NonceRegistryLockError
    );
    // close() never removes a lock it does not own
    expect(() => registry.close()).toThrow(NonceRegistryLockError);
    expect(fs.existsSync(`${registryPath}.lock`)).toBe(true);
  });
});

describe("N2: crash-consistent commit and anchor", () => {
  it("a crash between the log commit and the anchor update recovers without losing the record", () => {
    const registryPath = tmpRegistry();
    const registry = new UsedNonceRegistry({ persistPath: registryPath, initialize: true });
    registry.checkAndRecord("11".repeat(32), "event-1", "aa".repeat(32));

    // The second record's log commit succeeds; the anchor rename then fails.
    const realRename = nodeFs.renameSync;
    const spy = jest.spyOn(nodeFs, "renameSync").mockImplementation((from, to) => {
      if (String(to).endsWith(".anchor")) {
        throw new Error("simulated crash before anchor update");
      }
      return realRename(from, to);
    });
    try {
      expect(() => registry.checkAndRecord("22".repeat(32), "event-2", "bb".repeat(32))).toThrow(
        /simulated crash before anchor update/
      );
    } finally {
      spy.mockRestore();
    }

    // The process "dies" and the operator clears its lock.
    fs.unlinkSync(`${registryPath}.lock`);
    const restarted = new UsedNonceRegistry({ persistPath: registryPath, initialize: true });
    expect(restarted.get("22".repeat(32))).toEqual({
      eventId: "event-2",
      messageHash: "bb".repeat(32),
    });
    expect(() =>
      restarted.checkAndRecord("22".repeat(32), "event-x", "cc".repeat(32))
    ).toThrow(NonceReuseError);
    restarted.close();
  });

  it("a failed log commit is retried before a repeat call answers, so no signature precedes durability", () => {
    const registryPath = tmpRegistry();
    const registry = new UsedNonceRegistry({ persistPath: registryPath, initialize: true });

    const realRename = nodeFs.renameSync;
    let failuresLeft = 1;
    const spy = jest.spyOn(nodeFs, "renameSync").mockImplementation((from, to) => {
      const target = String(to);
      if (target.endsWith("used-nonces.json") && failuresLeft-- > 0) {
        throw new Error("simulated ENOSPC on log commit");
      }
      return realRename(from, to);
    });
    try {
      expect(() => registry.checkAndRecord("11".repeat(32), "event-1", "aa".repeat(32))).toThrow(
        /ENOSPC/
      );
      // Same request again: the record must be committed before it is answered.
      registry.checkAndRecord("11".repeat(32), "event-1", "aa".repeat(32));
    } finally {
      spy.mockRestore();
    }

    const onDisk = JSON.parse(fs.readFileSync(registryPath, "utf8"));
    expect(onDisk.entries.map((e: { eventId: string }) => e.eventId)).toEqual(["event-1"]);
    registry.close();
  });
});

describe("N3: no automatic reclaim of a crashed writer's lock", () => {
  it("a lock whose owner pid is dead on this host is not reclaimed, and the operator is told how to clear it", () => {
    const registryPath = tmpRegistry();
    fs.writeFileSync(
      `${registryPath}.lock`,
      JSON.stringify({ pid: 999999, hostname: os.hostname(), acquiredAt: "", historyDigest: null })
    );
    expect(() => new UsedNonceRegistry({ persistPath: registryPath, initialize: true })).toThrow(
      /is locked: .* Locks are never taken over automatically/s
    );
    // the lock file is still there: nothing was reclaimed
    expect(fs.existsSync(`${registryPath}.lock`)).toBe(true);
  });

  it("locks owned by an alive pid, a pid on another host, or of unreadable form all block startup", () => {
    for (const content of [
      JSON.stringify({ pid: 1, hostname: os.hostname(), acquiredAt: "", historyDigest: null }),
      JSON.stringify({ pid: 999999, hostname: `${os.hostname()}-other`, acquiredAt: "" }),
      "not-json",
      "",
    ]) {
      const registryPath = tmpRegistry();
      fs.writeFileSync(`${registryPath}.lock`, content);
      expect(() => new UsedNonceRegistry({ persistPath: registryPath, initialize: true })).toThrow(/is locked/);
    }
  });
});

describe("N4: symlink and hard-link aliases", () => {
  it("a symlink alias resolves to the same lock: the second instance is refused", () => {
    const registryPath = tmpRegistry();
    const alias = path.join(path.dirname(registryPath), "alias.json");
    const first = new UsedNonceRegistry({ persistPath: registryPath, initialize: true });
    fs.symlinkSync(registryPath, alias);
    try {
      expect(() => new UsedNonceRegistry({ persistPath: alias, initialize: true })).toThrow(NonceRegistryLockError);
    } finally {
      first.close();
    }
  });

  it("a hard-linked alias is refused at startup", () => {
    const registryPath = tmpRegistry();
    const alias = path.join(path.dirname(registryPath), "hardlink.json");
    const first = new UsedNonceRegistry({ persistPath: registryPath, initialize: true });
    first.checkAndRecord("11".repeat(32), "event-1", "aa".repeat(32));
    first.close();
    fs.linkSync(registryPath, alias);
    expect(() => new UsedNonceRegistry({ persistPath: alias, initialize: true })).toThrow(
      /exactly one hard link/
    );
    expect(() => new UsedNonceRegistry({ persistPath: registryPath, initialize: true })).toThrow(
      /exactly one hard link/
    );
  });

  it("a running writer refuses to commit once a hard link to its registry exists", () => {
    const registryPath = tmpRegistry();
    const alias = path.join(path.dirname(registryPath), "late-hardlink.json");
    const registry = new UsedNonceRegistry({ persistPath: registryPath, initialize: true });
    registry.checkAndRecord("11".repeat(32), "event-1", "aa".repeat(32));
    fs.linkSync(registryPath, alias);

    expect(() => registry.checkAndRecord("22".repeat(32), "event-2", "bb".repeat(32))).toThrow(
      /exactly one hard link/
    );
    const onDisk = JSON.parse(fs.readFileSync(registryPath, "utf8"));
    expect(onDisk.entries.map((e: { eventId: string }) => e.eventId)).toEqual(["event-1"]);
    registry.close();
  });
});
