/**
 * Round-5 regression tests: the nonce registry and the signing path.
 *
 *  R5-1  the registry log holds the public nonce point R, never the base point P
 *        (with P and one published signature the oracle key is computable)
 *  R5-2  a format-version-2 log (which stored P) is refused at startup
 *  R5-3  an event whose nonce indices collide is refused at announcement
 *  R5-4  nonceId and messageHash must be 32-byte hex (fail closed on bad input)
 *  R5-5  a directory fsync that fails after the log rename yields no signature,
 *        and the retry signs once with the anchor covering the record
 *  R5-6  a failed directory fsync followed by a failed anchor write, with no retry
 *        of the first record, leaves the log at most one entry ahead (restart adopts)
 */
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import { BitcoinNetworks } from "bitcoin-networks";

import { AttestationEngine, AttestationType } from "../src/attestation/attestation-engine";
import {
  NonceRegistryLockError,
  NonceReuseError,
  UsedNonceRegistry,
} from "../src/attestation/used-nonce-registry";
import { deriveSchnorrPublicKey } from "../src/crypto/bitcoin-primitives";
import { MockKeyProvider } from "../src/keys/key-provider";

const MNEMONIC = "test test test test test test test test test test test junk";

function tmpRegistry(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "r5-registry-"));
  return path.join(dir, "used-nonces.json");
}

function newEngine(registryPath: string): AttestationEngine {
  return new AttestationEngine({
    network: BitcoinNetworks.bitcoin_regtest,
    keyProvider: new MockKeyProvider(MNEMONIC),
    usedNonceRegistryPath: registryPath,
    usedNonceRegistryInit: true,
    developmentMode: true,
  } as any);
}

function logEntries(registryPath: string): Array<Record<string, string>> {
  return (JSON.parse(fs.readFileSync(registryPath, "utf8")) as { entries: Array<Record<string, string>> })
    .entries;
}

describe("R5-1: the registry never persists the base nonce point", () => {
  it("stores the announced public nonce points and no base point", async () => {
    const registryPath = tmpRegistry();
    const engine = newEngine(registryPath);
    await engine.initialize();
    const eventId = "r5-no-secret";
    const descriptor = {
      type: AttestationType.NUMERIC,
      base: 10,
      numDigits: 2,
      unit: "u",
      precision: 0,
      signed: true,
    };
    const announcement = await engine.createAnnouncement(eventId, descriptor, 1767225600 /* 2026-01-01T00:00:00Z: matured, signing refuses future events */);
    await engine.attestNumeric(announcement, 42);

    const base: string[] = [];
    for (let i = 0; i < announcement.noncePoints.length; i += 1) {
      const noncePrivKey = await (engine as any).deriveNonceKey(eventId, i);
      base.push(deriveSchnorrPublicKey(noncePrivKey).toString("hex"));
    }
    const raw = fs.readFileSync(registryPath, "utf8");
    for (const basePoint of base) {
      expect(raw).not.toContain(basePoint);
    }
    const announced = announcement.noncePoints.map((r) => r.toString("hex"));
    for (const entry of logEntries(registryPath)) {
      expect(announced).toContain(entry.nonceId);
    }
    engine.close();
  });
});

describe("R5-2: format version 2 is refused", () => {
  it("refuses a version-2 log with the rotation instruction", () => {
    const registryPath = tmpRegistry();
    fs.writeFileSync(registryPath, JSON.stringify({ version: 2, entries: [] }));
    expect(() => new UsedNonceRegistry({ persistPath: registryPath, initialize: true })).toThrow(
      /format-version-2 registry[\s\S]*rotate it/
    );
  });

  it("refuses an unknown format version", () => {
    const registryPath = tmpRegistry();
    fs.writeFileSync(registryPath, JSON.stringify({ version: 9, entries: [] }));
    expect(() => new UsedNonceRegistry({ persistPath: registryPath, initialize: true })).toThrow(
      NonceRegistryLockError
    );
  });
});

describe("R5-3: colliding nonce indices are refused at announcement", () => {
  it("refuses to announce an event whose nonce points repeat", async () => {
    const engine = newEngine(tmpRegistry());
    await engine.initialize();
    // Force every index to the same derivation index, as a 31-bit collision would.
    (engine as any).computeNonceDerivationIndex = () => 7;
    const descriptor = {
      type: AttestationType.NUMERIC,
      base: 10,
      numDigits: 2,
      unit: "u",
      precision: 0,
      signed: false,
    };
    await expect(
      engine.createAnnouncement("r5-collision", descriptor, 1767225600 /* 2026-01-01T00:00:00Z: matured, signing refuses future events */)
    ).rejects.toThrow(/Nonce index collision/);
    engine.close();
  });
});

describe("R5-3b: a 31-bit index collision across two events cannot share a nonce", () => {
  it("two events with one derivation index get different nonce points and both attest", async () => {
    const engine = newEngine(tmpRegistry());
    await engine.initialize();
    // Both events get the same base point P; the tweak binds the eventId, so k differs.
    (engine as any).computeNonceDerivationIndex = () => 7;
    const binary = { type: AttestationType.BINARY, outcomes: ["yes", "no"] };
    const a = await engine.createAnnouncement("r5-cross-a", binary as any, 1767225600 /* 2026-01-01T00:00:00Z: matured, signing refuses future events */);
    const b = await engine.createAnnouncement("r5-cross-b", binary as any, 1767225600 /* 2026-01-01T00:00:00Z: matured, signing refuses future events */);
    expect(a.noncePoints[0]!.equals(b.noncePoints[0]!)).toBe(false);
    await expect(engine.attestBinary(a, true)).resolves.toBeDefined();
    await expect(engine.attestBinary(b, true)).resolves.toBeDefined();
    engine.close();
  });
});

describe("R5-4: the registry rejects malformed identifiers", () => {
  it("refuses a nonceId or messageHash that is not 32-byte lowercase hex", () => {
    const registry = new UsedNonceRegistry({ persistPath: tmpRegistry(), initialize: true });
    expect(() => registry.checkAndRecord("aa", "event", "bb".repeat(32))).toThrow(
      /32-byte lowercase hex/
    );
    expect(() => registry.checkAndRecord("aa".repeat(32), "event", "BB".repeat(32))).toThrow(
      /32-byte lowercase hex/
    );
    expect(registry.size).toBe(0);
    registry.close();
  });
});

describe("R5-5: a failed directory fsync after the log rename cannot sign early", () => {
  it("returns no signature, and the retry signs once with the anchor covering the record", async () => {
    const registryPath = tmpRegistry();
    const engine = newEngine(registryPath);
    await engine.initialize();
    const announcement = await engine.createAnnouncement(
      "r5-fsync",
      { type: AttestationType.BINARY, outcomes: ["yes", "no"] },
      1767225600 /* 2026-01-01T00:00:00Z: matured, signing refuses future events */
    );

    // The first directory fsync after this point is the log commit's.
    // The real module object (the import above is a read-only namespace view).
    const nodeFs = require("fs") as typeof fs;
    const realFsync = nodeFs.fsyncSync;
    let armed = true;
    nodeFs.fsyncSync = (fd: number) => {
      if (armed && nodeFs.fstatSync(fd).isDirectory()) {
        armed = false;
        throw Object.assign(new Error("injected EIO on directory fsync"), { code: "EIO" });
      }
      return realFsync(fd);
    };
    try {
      await expect(engine.attestBinary(announcement, true)).rejects.toThrow(/injected EIO/);
    } finally {
      nodeFs.fsyncSync = realFsync;
    }

    // The record is in the log, the anchor is still behind, and nothing was returned.
    const afterFailure = logEntries(registryPath);
    expect(afterFailure.length).toBe(1);

    const attestation = await engine.attestBinary(announcement, true);
    expect(attestation.signatures.length).toBe(1);

    // Anchor covers the log tip, and the same nonce cannot sign the other outcome.
    const anchor = JSON.parse(fs.readFileSync(`${registryPath}.anchor`, "utf8")) as { tip: string };
    expect(anchor.tip).toBe(logEntries(registryPath)[0]!.chain);
    await expect(engine.attestBinary(announcement, false)).rejects.toThrow(NonceReuseError);
    engine.close();
  });
});

describe("R5-6: a failed directory fsync then a failed anchor write cannot leave the log two ahead", () => {
  it("the log stays at most one entry ahead, and a restart adopts it", () => {
    const registryPath = tmpRegistry();
    // The real module object (the import above is a read-only namespace view).
    const nodeFs = require("fs") as typeof fs;
    const realFsync = nodeFs.fsyncSync;
    const realRename = nodeFs.renameSync;
    let dirFsyncArmed = false;
    let anchorRenameArmed = false;
    nodeFs.fsyncSync = (fd: number) => {
      const result = realFsync(fd);
      if (dirFsyncArmed && nodeFs.fstatSync(fd).isDirectory()) {
        dirFsyncArmed = false;
        throw Object.assign(new Error("injected EIO on directory fsync"), { code: "EIO" });
      }
      return result;
    };
    nodeFs.renameSync = (from: fs.PathLike, to: fs.PathLike) => {
      if (anchorRenameArmed && String(to).endsWith(".anchor")) {
        anchorRenameArmed = false;
        throw Object.assign(new Error("injected ENOSPC on anchor rename"), { code: "ENOSPC" });
      }
      return realRename(from, to);
    };
    try {
      const registry = new UsedNonceRegistry({ persistPath: registryPath, initialize: true });
      dirFsyncArmed = true;
      expect(() => registry.checkAndRecord("11".repeat(32), "e1", "aa".repeat(32))).toThrow(
        /injected EIO/
      );
      anchorRenameArmed = true;
      expect(() => registry.checkAndRecord("22".repeat(32), "e2", "bb".repeat(32))).toThrow(
        /injected ENOSPC/
      );
      // Nothing was signed for e2, and the log is at most one entry past the anchor.
      expect(logEntries(registryPath).length).toBe(1);
      registry.close();
    } finally {
      nodeFs.fsyncSync = realFsync;
      nodeFs.renameSync = realRename;
    }

    const restarted = new UsedNonceRegistry({ persistPath: registryPath, initialize: true });
    expect(restarted.get("11".repeat(32))).toEqual({ eventId: "e1", messageHash: "aa".repeat(32) });
    restarted.close();
  });
});
