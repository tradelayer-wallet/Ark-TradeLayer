/**
 * Round-6 regression tests: the nonce registry commit ordering, record validation,
 * the format-version-2 refusal text, and the verifier's nonce-point check.
 *
 *  R6-1  a failed log commit followed by a new record cannot leave the log two
 *        entries ahead of the anchor (the next start would refuse the registry)
 *  R6-2  eventId must be printable ASCII (1 to 255) on write and on load
 *  R6-3  the format-version-2 refusal tells the operator not to restart with the
 *        same oracle key
 *  R6-4  a verifier refuses an announcement whose nonce points repeat, and the
 *        announcement path still refuses to publish one
 */
import * as crypto from "crypto";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import { BitcoinNetworks } from "bitcoin-networks";

import {
  AttestationEngine,
  AttestationType,
  serializeAnnouncementMessage,
  serializeAttestationMessage,
} from "../src/attestation/attestation-engine";
import {
  NonceRegistryLockError,
  UsedNonceRegistry,
} from "../src/attestation/used-nonce-registry";
import {
  schnorrSign,
  schnorrSignWithNonce,
} from "../src/crypto/bitcoin-primitives";
import { hashAnnouncement, hashAttestation } from "../src/crypto/tagged-hash";
import { MockKeyProvider } from "../src/keys/key-provider";

const MNEMONIC = "test test test test test test test test test test test junk";
const MATURITY = Math.floor(Date.now() / 1000) - 3600;
const tmpDirs: string[] = [];

// The real module object: the registry reads fs through the same object.
const nodeFs = require("fs") as typeof fs;

function tmpRegistry(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "r6-registry-"));
  tmpDirs.push(dir);
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

function diskEntries(registryPath: string): Array<Record<string, string>> {
  return (JSON.parse(fs.readFileSync(registryPath, "utf8")) as { entries: Array<Record<string, string>> })
    .entries;
}

afterAll(() => {
  for (const dir of tmpDirs) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

describe("R6-1: a failed log commit followed by a new record cannot leave the log two ahead", () => {
  it("commits the pending record first, so the restart is accepted", () => {
    const registryPath = tmpRegistry();
    const realRename = nodeFs.renameSync;
    let failLogRename = false;
    let failAnchorRename = false;
    nodeFs.renameSync = (from: fs.PathLike, to: fs.PathLike) => {
      const target = String(to);
      if (failAnchorRename && target.endsWith(".anchor")) {
        failAnchorRename = false;
        throw Object.assign(new Error("injected ENOSPC on anchor rename"), { code: "ENOSPC" });
      }
      if (failLogRename && target === registryPath) {
        failLogRename = false;
        throw Object.assign(new Error("injected EIO on log rename"), { code: "EIO" });
      }
      return realRename(from, to);
    };
    const R = (i: number) => i.toString(16).padStart(2, "0").repeat(32);
    const M = (i: number) => "ab".repeat(31) + i.toString(16).padStart(2, "0");
    try {
      const registry = new UsedNonceRegistry({ persistPath: registryPath, initialize: true });
      registry.checkAndRecord(R(1), "ev-1", M(1));

      // The log commit for record 2 fails before its rename: record 2 stays pending.
      failLogRename = true;
      expect(() => registry.checkAndRecord(R(2), "ev-2", M(2))).toThrow(/injected EIO/);

      // Record 3: the log commit of record 2 succeeds, then the anchor write fails.
      failAnchorRename = true;
      expect(() => registry.checkAndRecord(R(3), "ev-3", M(3))).toThrow(/injected ENOSPC/);

      // The log holds at most one entry beyond the anchor, and record 3 was never recorded.
      expect(diskEntries(registryPath).length).toBe(2);
      expect(registry.get(R(3))).toBeUndefined();
      registry.close();
    } finally {
      nodeFs.renameSync = realRename;
    }

    const restarted = new UsedNonceRegistry({ persistPath: registryPath, initialize: true });
    expect(restarted.get(R(2))).toEqual({ eventId: "ev-2", messageHash: M(2) });
    expect(restarted.get(R(3))).toBeUndefined();
    // Record 3 can still be recorded after the restart.
    restarted.checkAndRecord(R(3), "ev-3", M(3));
    restarted.close();
  });
});

describe("R6-2: eventId must be printable ASCII (1 to 255 characters)", () => {
  it("refuses control, non-ASCII, empty and over-long event ids on write", () => {
    const registry = new UsedNonceRegistry({ persistPath: tmpRegistry(), initialize: true });
    const nonce = "11".repeat(32);
    const message = "aa".repeat(32);
    for (const bad of ["bad\nid", "nul\u0000id", "café", "", "x".repeat(256), "tab\tid"]) {
      expect(() => registry.checkAndRecord(nonce, bad, message)).toThrow(/printable ASCII/);
    }
    expect(registry.size).toBe(0);
    registry.close();
  });

  it("refuses a log whose event id is not printable ASCII (even with a valid chain)", () => {
    const registryPath = tmpRegistry();
    const registry = new UsedNonceRegistry({ persistPath: registryPath, initialize: true });
    registry.checkAndRecord("11".repeat(32), "ok", "aa".repeat(32));
    registry.close();

    // Rewrite the single entry with a newline in its event id, recomputing its chain
    // and the anchor exactly as the digest chain defines them (the anchor is unkeyed).
    const payload = JSON.parse(fs.readFileSync(registryPath, "utf8")) as {
      version: number;
      entries: Array<Record<string, string>>;
    };
    const entry = payload.entries[0]!;
    entry.eventId = "ok\nforged";
    const record = crypto
      .createHash("sha256")
      .update(`${entry.nonceId}\n${entry.eventId}\n${entry.messageHash}`, "utf8")
      .digest("hex");
    entry.chain = crypto.createHash("sha256").update("0".repeat(64) + record, "utf8").digest("hex");
    fs.writeFileSync(registryPath, JSON.stringify(payload, null, 2));
    fs.writeFileSync(
      `${registryPath}.anchor`,
      JSON.stringify({ version: 1, tip: entry.chain }, null, 2)
    );

    expect(() => new UsedNonceRegistry({ persistPath: registryPath, initialize: true })).toThrow(
      /malformed entry/
    );
  });
});

describe("R6-3: the format-version-2 refusal forbids a same-key restart", () => {
  it("names the same-key restart and the pre-R5 provenance check", () => {
    const registryPath = tmpRegistry();
    fs.writeFileSync(registryPath, JSON.stringify({ version: 2, entries: [] }));
    let caught: unknown;
    try {
      new UsedNonceRegistry({ persistPath: registryPath, initialize: true });
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(NonceRegistryLockError);
    const message = (caught as Error).message;
    expect(message).toMatch(/format-version-2/);
    expect(message).toMatch(/Do NOT restart with the same oracle key/);
    expect(message).toMatch(/pre-R5 build/);
  });
});

describe("R6-4: repeated nonce points are refused by the verifier and the announcer", () => {
  it("a verifier rejects an oracle-signed announcement that repeats a nonce point", async () => {
    const registryPath = tmpRegistry();
    const engine = newEngine(registryPath);
    await engine.initialize();
    const eventId = "r6-repeat";
    const descriptor = {
      type: AttestationType.NUMERIC,
      base: 10,
      numDigits: 2,
      unit: "u",
      precision: 0,
      signed: false,
    } as const;
    const engineAny = engine as any;
    const oracleKey: Buffer = engineAny.oraclePrivateKey;
    const oraclePub: Buffer = engine.getPublicKey();
    const { k, R } = await engineAny.deriveSigningNonce(eventId, 0);

    // A forged announcement that repeats R (the oracle signs it, so only the check
    // on repeated points can refuse it).
    const points = [R, R];
    const announcementSig = schnorrSign(
      oracleKey,
      hashAnnouncement(
        serializeAnnouncementMessage(eventId, oraclePub, descriptor as any, MATURITY, points)
      )
    );
    const forged = {
      eventId,
      oraclePublicKey: oraclePub,
      descriptor,
      maturityTime: MATURITY,
      noncePoints: points,
      announcementSignature: announcementSig,
    } as any;

    // Two signatures that share k: both carry R, so each position's R check passes.
    const outcomes = ["3", "7"];
    const signatures = outcomes.map((outcome) =>
      schnorrSignWithNonce(
        oracleKey,
        hashAttestation(
          serializeAttestationMessage(eventId, oraclePub, descriptor as any, MATURITY, outcome)
        ),
        k
      )
    );
    const attestation = {
      eventId,
      oraclePublicKey: oraclePub,
      outcomes,
      signatures,
      attestationTime: Math.floor(Date.now() / 1000),
    } as any;

    expect(engine.verifyAttestation(forged, attestation, oraclePub)).toBe(false);
    engine.close();
  });

  it("the announcer refuses an event whose nonce indices collide", async () => {
    const registryPath = tmpRegistry();
    const engine = newEngine(registryPath);
    await engine.initialize();
    const engineAny = engine as any;
    const real = engineAny.deriveSigningNonce.bind(engine);
    // Force index 1 to derive the same nonce point as index 0 (a 31-bit index collision).
    jest.spyOn(engineAny, "deriveSigningNonce").mockImplementation(async (eventId: string, i: number) =>
      i === 1 ? real(eventId, 0) : real(eventId, i)
    );
    await expect(
      engine.createAnnouncement(
        "r6-collide",
        {
          type: AttestationType.NUMERIC,
          base: 10,
          numDigits: 2,
          unit: "u",
          precision: 0,
          signed: false,
        } as any,
        MATURITY
      )
    ).rejects.toThrow(/Nonce index collision/);
    jest.restoreAllMocks();
    engine.close();
  });
});
