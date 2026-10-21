/**
 * PR test suite (20 tests) for the oracle attestation core:
 * C1 (event-bound attestations), C2 (fail-closed verification),
 * C3 (fail-closed config) and H1 (used-nonce registry).
 *
 * Vector-based tests read tests/vectors/attestation-vectors.json, the SHARED
 * byte-exact vectors that both the TypeScript signer and the .ark on-chain
 * matchers must reproduce (see scripts/generate-vectors.js).
 */
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import { BitcoinNetworks } from "bitcoin-networks";

import {
  AttestationEngine,
  AttestationType,
  EventAnnouncement,
  hashDescriptor,
  isValidDescriptor,
  serializeAttestationMessage,
  serializeAnnouncementMessage,
  serializeDescriptor,
} from "../src/attestation/attestation-engine";
import { NonceReuseError } from "../src/attestation/used-nonce-registry";
import {
  DLC_TAGS,
  hashAnnouncement,
  hashAttestation,
  hashEventId,
} from "../src/crypto/tagged-hash";
import { MockKeyProvider } from "../src/keys/key-provider";
import {
  DEFAULT_API_AUTH_KEY,
  SystemConfig,
  validateConfig,
} from "../src/config/system-config";

const ark = require("./support/ark-matcher-emulation");
const cfdjs = require("./shims/cfd-js.js");

const MNEMONIC = "test test test test test test test test test test test junk";
const MATURITY_TIME = 1767225600; // 2026-01-01T00:00:00Z (in the past)

interface VectorFile {
  vectors: Array<{
    name: string;
    eventId: string;
    eventIdHash: string;
    oraclePublicKey: string;
    oraclePrivateKey: string;
    descriptor: any;
    descriptorHash: string;
    maturityTime: number;
    outcomes: string[];
    outcomesHex: string[];
    attestationMessages: string[];
    attestationMessageHashes: string[];
    attestationSignatures: string[];
    noncePoints: string[];
    announcementMessage: string;
    announcementMessageHash: string;
  }>;
}

const vectorFile: VectorFile = JSON.parse(
  fs.readFileSync(path.join(__dirname, "vectors", "attestation-vectors.json"), "utf8")
);

function tmpRegistryPath(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "att-suite-"));
  return path.join(dir, "used-nonces.json");
}

async function makeEngine(): Promise<AttestationEngine> {
  const engine = new AttestationEngine({
    network: BitcoinNetworks.bitcoin_regtest,
    keyProvider: new MockKeyProvider(MNEMONIC),
    usedNonceRegistryPath: tmpRegistryPath(),
    usedNonceRegistryInit: true,
    developmentMode: true,
    trustedOraclePublicKey:
      "8eead9aaf2bb8800aae8dfe44382eac6c731c8bb2ced4a2eed807ecb7861469e",
  });
  await engine.initialize();
  return engine;
}

const NUMERIC_SIGNED = {
  type: AttestationType.NUMERIC,
  base: 10,
  numDigits: 4,
  unit: "USD",
  precision: 2,
  signed: true,
} as const;

function makeConfig(overrides: Partial<SystemConfig> = {}): SystemConfig {
  return {
    network: "testnet",
    mode: "production",
    keys: { provider: "gcp", projectId: "proj", secretId: "secret", allowLocalKeys: false },
    database: { uri: "mongodb://localhost:27017", database: "test" },
    redis: { host: "127.0.0.1", port: 6379 },
    externalData: { priceFeeds: { enabled: ["coingecko"] }, blockchainClients: {} },
    api: {
      publicPort: 3000,
      internalPort: 3001,
      authKey: "strong-random-api-key",
      cors: { enabled: true, origins: ["*"] },
    },
    monitoring: { logLevel: "info" },
    scheduler: { priceCheckInterval: 5, paymentCheckInterval: 2, announcementLookahead: 13 },
    vtxo: { defaultExitDelay: 1008, serverPublicKey: "aabbcc", minContractValue: 10000 },
    usedNonceRegistryPath: "/srv/vtxo/used-nonces.json",
    usedNonceRegistryInit: true,
    ...overrides,
  };
}

describe("oracle attestation core (PR suite)", () => {
  // ---------------------------------------------------------------- C1
  it("1. serializeDescriptor is deterministic and length-prefixed", () => {
    const a = serializeDescriptor(NUMERIC_SIGNED);
    const b = serializeDescriptor({ ...NUMERIC_SIGNED });
    expect(a.equals(b)).toBe(true);
    // length-prefixed: 4-byte prefix of the first field ("numeric" = 7)
    expect(a.readUInt32BE(0)).toBe(7);
  });

  it("2. hashDescriptor is 32 bytes and distinct per descriptor", () => {
    const h1 = hashDescriptor(NUMERIC_SIGNED);
    const h2 = hashDescriptor({ ...NUMERIC_SIGNED, unit: "EUR" });
    expect(h1.length).toBe(32);
    expect(h1.equals(h2)).toBe(false);
  });

  it("3. the attestation message binds every field", () => {
    const eventId = "btc-usd-2026-01-01";
    const key = Buffer.alloc(32, 1);
    const base = serializeAttestationMessage(eventId, key, NUMERIC_SIGNED, MATURITY_TIME, "+");
    const variants = [
      serializeAttestationMessage("btc-usd-2026-01-02", key, NUMERIC_SIGNED, MATURITY_TIME, "+"),
      serializeAttestationMessage(eventId, Buffer.alloc(32, 2), NUMERIC_SIGNED, MATURITY_TIME, "+"),
      serializeAttestationMessage(
        eventId,
        key,
        { ...NUMERIC_SIGNED, numDigits: 5 },
        MATURITY_TIME,
        "+"
      ),
      serializeAttestationMessage(eventId, key, NUMERIC_SIGNED, MATURITY_TIME + 1, "+"),
      serializeAttestationMessage(eventId, key, NUMERIC_SIGNED, MATURITY_TIME, "-"),
    ];
    for (const variant of variants) {
      expect(variant.equals(base)).toBe(false);
    }
  });

  it("4. attestation message hashes match the committed shared vectors", () => {
    for (const vector of vectorFile.vectors) {
      for (let i = 0; i < vector.outcomes.length; i++) {
        const message = serializeAttestationMessage(
          vector.eventId,
          Buffer.from(vector.oraclePublicKey, "hex"),
          vector.descriptor,
          vector.maturityTime,
          vector.outcomes[i]!
        );
        expect(message.toString("hex")).toBe(vector.attestationMessages[i]);
        expect(hashAttestation(message).toString("hex")).toBe(
          vector.attestationMessageHashes[i]
        );
      }
    }
  });

  it("5. announcement message hashes match the committed shared vectors", () => {
    for (const vector of vectorFile.vectors) {
      const message = serializeAnnouncementMessage(
        vector.eventId,
        Buffer.from(vector.oraclePublicKey, "hex"),
        vector.descriptor,
        vector.maturityTime,
        vector.noncePoints.map((r) => Buffer.from(r, "hex"))
      );
      expect(message.toString("hex")).toBe(vector.announcementMessage);
      expect(hashAnnouncement(message).toString("hex")).toBe(vector.announcementMessageHash);
    }
  });

  // ---------------------------------------------------------------- C2
  it("6. announce -> attest -> verify round-trips", async () => {
    const engine = await makeEngine();
    const announcement = await engine.createAnnouncement(
      "round-trip-event",
      NUMERIC_SIGNED,
      MATURITY_TIME
    );
    const attestation = await engine.attestNumeric(announcement, 12.34);
    expect(engine.verifyAttestation(announcement, attestation)).toBe(true);
  });

  it("7. verifyAttestation rejects a tampered outcome", async () => {
    const engine = await makeEngine();
    const announcement = await engine.createAnnouncement(
      "tamper-event",
      NUMERIC_SIGNED,
      MATURITY_TIME
    );
    const attestation = await engine.attestNumeric(announcement, 12.34);
    const tampered = {
      ...attestation,
      outcomes: [...attestation.outcomes],
    };
    tampered.outcomes[1] = "9";
    expect(engine.verifyAttestation(announcement, tampered)).toBe(false);
  });

  it("8. verifyAttestation rejects an attestation not signed by the pinned key", async () => {
    const engine = await makeEngine();
    const announcement = await engine.createAnnouncement(
      "pin-event",
      NUMERIC_SIGNED,
      MATURITY_TIME
    );
    const attestation = await engine.attestNumeric(announcement, 12.34);
    // Self-consistent forgery: both objects carry the attacker's key, but it
    // is not the pinned trusted key.
    const otherKey = Buffer.alloc(32, 7);
    expect(
      engine.verifyAttestation(
        { ...announcement, oraclePublicKey: otherKey },
        { ...attestation, oraclePublicKey: otherKey }
      )
    ).toBe(false);
  });

  it("9. verifyAttestation fails closed without a trusted oracle key", async () => {
    const engine = new AttestationEngine({
      network: BitcoinNetworks.bitcoin_regtest,
      keyProvider: new MockKeyProvider(MNEMONIC),
      usedNonceRegistryPath: tmpRegistryPath(),
      usedNonceRegistryInit: true,
      developmentMode: true,
      // no trustedOraclePublicKey
    });
    await engine.initialize();
    const announcement = await engine.createAnnouncement(
      "no-pin-event",
      NUMERIC_SIGNED,
      MATURITY_TIME
    );
    const attestation = await engine.attestNumeric(announcement, 12.34);
    expect(engine.verifyAttestation(announcement, attestation)).toBe(false);
  });

  it("10. verifyAttestation rejects a forged announcement signature", async () => {
    const engine = await makeEngine();
    const announcement = await engine.createAnnouncement(
      "forged-ann",
      NUMERIC_SIGNED,
      MATURITY_TIME
    );
    const attestation = await engine.attestNumeric(announcement, 12.34);
    const forged = {
      ...announcement,
      announcementSignature: Buffer.alloc(64, 9),
    };
    expect(engine.verifyAttestation(forged, attestation)).toBe(false);
  });

  it("11. verifyAttestation rejects signatures whose R is not the pre-committed nonce", async () => {
    const engine = await makeEngine();
    const announcement = await engine.createAnnouncement("r-mismatch", NUMERIC_SIGNED, MATURITY_TIME);
    const attestation = await engine.attestNumeric(announcement, 12.34);

    // Valid BIP-340 signature over the same message, but under a DIFFERENT
    // nonce k -> R is not the announced nonce point.
    const vector = vectorFile.vectors[0]!;
    const messageHash = Buffer.from(vector.attestationMessageHashes[0]!, "hex");
    const rogueK = Buffer.alloc(32, 3);
    const rogueSig = Buffer.from(
      cfdjs.SchnorrSign({
        privkey: vector.oraclePrivateKey,
        message: messageHash.toString("hex"),
        nonceOrAux: rogueK.toString("hex"),
        isHashed: true,
        isNonce: true,
      }).hex,
      "hex"
    );
    // note: this signature is over the vector's message, so it will also fail
    // the message check; construct the R check with the real message below.
    const realMessageHash = hashAttestation(
      serializeAttestationMessage(
        announcement.eventId,
        announcement.oraclePublicKey,
        announcement.descriptor,
        announcement.maturityTime,
        attestation.outcomes[0]!
      )
    );
    const rogueSigReal = Buffer.from(
      cfdjs.SchnorrSign({
        privkey: vector.oraclePrivateKey,
        message: realMessageHash.toString("hex"),
        nonceOrAux: rogueK.toString("hex"),
        isHashed: true,
        isNonce: true,
      }).hex,
      "hex"
    );
    expect(rogueSig.length).toBe(64);
    expect(
      engine.verifyAttestation(announcement, {
        ...attestation,
        signatures: [rogueSigReal, ...attestation.signatures.slice(1)],
      })
    ).toBe(false);
  });

  it("12. verifyAttestation rejects wrong outcome counts", async () => {
    const engine = await makeEngine();
    const announcement = await engine.createAnnouncement("count-event", NUMERIC_SIGNED, MATURITY_TIME);
    const attestation = await engine.attestNumeric(announcement, 12.34);
    expect(
      engine.verifyAttestation(announcement, {
        ...attestation,
        outcomes: attestation.outcomes.slice(1),
        signatures: attestation.signatures.slice(1),
      })
    ).toBe(false);
  });

  it("13. verifyAttestation rejects outcomes outside the declared set", async () => {
    const engine = await makeEngine();
    const announcement = await engine.createAnnouncement("set-event", NUMERIC_SIGNED, MATURITY_TIME);
    const attestation = await engine.attestNumeric(announcement, 12.34);
    const withBadSign = {
      ...attestation,
      outcomes: ["*", ...attestation.outcomes.slice(1)],
    };
    expect(engine.verifyAttestation(announcement, withBadSign)).toBe(false);
  });

  it("14. verifyAttestation rejects premature attestations", async () => {
    const engine = await makeEngine();
    const maturity = MATURITY_TIME;
    const announcement = await engine.createAnnouncement("future-event", NUMERIC_SIGNED, maturity);
    // The signer refuses to sign before maturity, so sign with the clock past
    // maturity, then verify the same attestation with the clock before it.
    const clock = jest.spyOn(Date, "now");
    try {
      clock.mockReturnValue((maturity + 1) * 1000);
      const attestation = await engine.attestNumeric(announcement, 12.34);
      clock.mockReturnValue((maturity - 10_000) * 1000);
      expect(engine.verifyAttestation(announcement, attestation)).toBe(false);
      clock.mockReturnValue((maturity + 1) * 1000);
      expect(engine.verifyAttestation(announcement, attestation)).toBe(true);
    } finally {
      clock.mockRestore();
    }
  });

  it("15. verifyAttestation returns false (never throws) on malformed input", async () => {
    const engine = await makeEngine();
    expect(engine.verifyAttestation({} as any, {} as any)).toBe(false);
    const announcement = await engine.createAnnouncement("malformed", NUMERIC_SIGNED, MATURITY_TIME);
    const attestation = await engine.attestNumeric(announcement, 12.34);
    expect(
      engine.verifyAttestation(announcement, {
        ...attestation,
        signatures: [Buffer.alloc(65), ...attestation.signatures.slice(1)],
      })
    ).toBe(false);
    expect(
      engine.verifyAttestation(
        { ...announcement, noncePoints: [] },
        { ...attestation, signatures: [], outcomes: [] }
      )
    ).toBe(false);
  });

  it("16. attestations cannot be replayed across events with the same oracle key", async () => {
    const engine = await makeEngine();
    const eventA = await engine.createAnnouncement("event-A", NUMERIC_SIGNED, MATURITY_TIME);
    const eventB = await engine.createAnnouncement("event-B", NUMERIC_SIGNED, MATURITY_TIME);
    const attestationA = await engine.attestNumeric(eventA, 12.34);

    // Same engine key, same descriptor, same maturity, same outcome - only
    // the eventId differs. The v1 digest binds the eventId, so the signature
    // must not verify against event B even with both ids rewritten.
    expect(
      engine.verifyAttestation(
        { ...eventB, noncePoints: eventA.noncePoints, announcementSignature: eventA.announcementSignature },
        { ...attestationA, eventId: "event-B" }
      )
    ).toBe(false);
  });

  // ------------------------------------------------------------- H1/C3
  it("17. attestNumeric rejects values exceeding the digit capacity", async () => {
    const engine = await makeEngine();
    const announcement = await engine.createAnnouncement("capacity", NUMERIC_SIGNED, MATURITY_TIME);
    await expect(engine.attestNumeric(announcement, 12345.67)).rejects.toThrow(/exceeds digit capacity/);
  });

  it("18. the used-nonce registry refuses reuse of a derived nonce", async () => {
    const engine = await makeEngine();
    const announcement = await engine.createAnnouncement("nonce-reuse", NUMERIC_SIGNED, MATURITY_TIME);
    await engine.attestNumeric(announcement, 12.34);
    // Same event, different message -> same derived nonces -> must refuse
    await expect(engine.attestNumeric(announcement, 56.78)).rejects.toThrow(NonceReuseError);
  });

  it("19. validateConfig refuses mock key custody outside development", () => {
    expect(() =>
      validateConfig(makeConfig({ keys: { provider: "mock", allowLocalKeys: false } }))
    ).toThrow(/KEY_PROVIDER=mock/);
  });

  it("20. validateConfig refuses the default API auth key outside development", () => {
    expect(() =>
      validateConfig(
        makeConfig({
          api: {
            publicPort: 3000,
            internalPort: 3001,
            authKey: DEFAULT_API_AUTH_KEY,
            cors: { enabled: true, origins: ["*"] },
          },
        })
      )
    ).toThrow(/insecure default/);
  });
});

describe(".ark matcher reproduction (shared vectors)", () => {
  it("the .ark matcher emulation reproduces the committed vectors and verifies the signatures", () => {
    for (const vector of vectorFile.vectors) {
      expect(ark.arkEventIdHash(vector.eventId).toString("hex")).toBe(vector.eventIdHash);
      for (let i = 0; i < vector.outcomes.length; i++) {
        const fields = {
          eventIdHash: Buffer.from(vector.eventIdHash, "hex"),
          oracleKeyXonly: Buffer.from(vector.oraclePublicKey, "hex"),
          descriptorHash: Buffer.from(vector.descriptorHash, "hex"),
          maturityTime: vector.maturityTime,
          outcome: Buffer.from(vector.outcomesHex[i]!, "hex"),
        };
        expect(ark.arkAttestationMessage(fields).toString("hex")).toBe(
          vector.attestationMessages[i]
        );
        expect(ark.arkAttestationMessageHash(fields).toString("hex")).toBe(
          vector.attestationMessageHashes[i]
        );
        expect(
          cfdjs.SchnorrVerify({
            pubkey: vector.oraclePublicKey,
            message: vector.attestationMessageHashes[i],
            signature: vector.attestationSignatures[i],
          }).valid
        ).toBe(true);
      }
    }
  });

  it("a fresh engine reproduces the committed vectors byte-for-byte (deterministic nonces)", async () => {
    const engine = await makeEngine();
    expect(engine.getPublicKey().toString("hex")).toBe(vectorFile.vectors[0]!.oraclePublicKey);
    for (const vector of vectorFile.vectors) {
      const announcement = await engine.createAnnouncement(
        vector.eventId,
        vector.descriptor,
        vector.maturityTime
      );
      expect(announcement.noncePoints.map((r) => r.toString("hex"))).toEqual(vector.noncePoints);
      expect(hashEventId(vector.eventId).toString("hex")).toBe(vector.eventIdHash);
      expect(hashDescriptor(vector.descriptor).toString("hex")).toBe(vector.descriptorHash);

      let attestation;
      if (vector.descriptor.type === "numeric") {
        attestation = await engine.attestNumeric(announcement, vector.name === "numeric-signed-decimal" ? 12.34 : 5);
      } else if (vector.descriptor.type === "binary") {
        attestation = await engine.attestBinary(announcement, true);
      } else {
        attestation = await engine.attestEnum(announcement, 1);
      }
      expect(attestation.outcomes).toEqual(vector.outcomes);
      expect(attestation.signatures.map((s) => s.toString("hex"))).toEqual(
        vector.attestationSignatures
      );
    }
  });

  it("valid descriptors are accepted and malformed ones rejected", () => {
    expect(isValidDescriptor(NUMERIC_SIGNED)).toBe(true);
    expect(isValidDescriptor({ ...NUMERIC_SIGNED, numDigits: 0 })).toBe(false);
    expect(isValidDescriptor({ ...NUMERIC_SIGNED, base: 1 })).toBe(false);
    expect(isValidDescriptor({ type: AttestationType.BINARY, outcomes: ["a", "a"] })).toBe(false);
    expect(isValidDescriptor({ type: AttestationType.BINARY, outcomes: ["a", "b"] })).toBe(true);
    expect(isValidDescriptor({ type: AttestationType.ENUM, outcomes: [] })).toBe(false);
    expect(isValidDescriptor({ type: AttestationType.ENUM, outcomes: ["x", "x"] })).toBe(false);
    expect(DLC_TAGS.ORACLE_NONCE_INDEX).not.toBe(DLC_TAGS.ORACLE_NONCE_TWEAK);
  });
});
