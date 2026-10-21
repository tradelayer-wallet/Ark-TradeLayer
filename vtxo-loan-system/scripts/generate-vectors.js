/**
 * Generates tests/vectors/attestation-vectors.json - the SHARED, byte-exact
 * test vectors that both the TypeScript signer and the .ark on-chain matcher
 * must reproduce (the .ark contracts reference this file).
 *
 * Regenerate with:  node scripts/generate-vectors.js
 *
 * The vectors are deterministic: the oracle key is derived from the fixed
 * test mnemonic below and the signing nonces are the deterministic
 * derivations of attestation-engine.ts. The generator REFUSES to write any
 * vector where the TypeScript serialization and the independent .ark matcher
 * emulation (tests/support/ark-matcher-emulation.js) disagree.
 */
"use strict";

require("../tests/support/register.js");

const fs = require("fs");
const path = require("path");

const { BitcoinNetworks } = require("bitcoin-networks");

const { AttestationEngine, serializeAttestationMessage, serializeAnnouncementMessage, hashDescriptor } = require("../src/attestation/attestation-engine");
const { hashEventId, hashAttestation, hashAnnouncement } = require("../src/crypto/tagged-hash");
const { MockKeyProvider } = require("../src/keys/key-provider");
const ark = require("../tests/support/ark-matcher-emulation");

const MNEMONIC = "test test test test test test test test test test test junk";
const NETWORK = BitcoinNetworks.bitcoin_regtest;
const ORACLE_PATH = "m/48'/1'/0'/0'/0";
const MATURITY_TIME = 1767225600; // 2026-01-01T00:00:00Z (past; verifiable)

const CASES = [
  {
    name: "numeric-signed-decimal",
    eventId: "btc-usd-2026-01-01",
    descriptor: {
      type: "numeric",
      base: 10,
      numDigits: 4,
      unit: "USD",
      precision: 2,
      signed: true,
    },
    attest: ["numeric", 12.34],
  },
  {
    name: "numeric-unsigned-binary-base",
    eventId: "loan-42-repaid",
    descriptor: {
      type: "numeric",
      base: 2,
      numDigits: 4,
      unit: "BTC",
      precision: 0,
      signed: false,
    },
    attest: ["numeric", 5],
  },
  {
    name: "binary-payment",
    eventId: "loan-42-payment-2026-01",
    descriptor: {
      type: "binary",
      outcomes: ["paid", "unpaid"],
    },
    attest: ["binary", true],
  },
  {
    name: "enum-loan-state",
    eventId: "loan-7-state-2026-01",
    descriptor: {
      type: "enum",
      outcomes: ["fulfilled", "defaulted", "expired"],
    },
    attest: ["enum", 1],
  },
];

async function main() {
  const registryDir = fs.mkdtempSync(path.join(require("os").tmpdir(), "vector-gen-"));

  const keyProvider = new MockKeyProvider(MNEMONIC);
  const engine = new AttestationEngine({
    network: NETWORK,
    keyProvider,
    usedNonceRegistryPath: path.join(registryDir, "used-nonces.json"),
    usedNonceRegistryInit: true,
    developmentMode: true,
  });
  await engine.initialize();
  const oraclePublicKey = engine.getPublicKey();

  // Test-only oracle secret for signature reproducibility (like BIP-340's
  // own test vectors, secret keys in TEST vectors are published on purpose).
  const keyResult = await keyProvider.deriveKey(ORACLE_PATH);
  if (keyResult.isErr()) throw keyResult.error;
  const oraclePrivateKey = Buffer.from(keyResult.value);

  const vectors = [];
  for (const testCase of CASES) {
    const { name, eventId, descriptor, attest } = testCase;
    const announcement = await engine.createAnnouncement(eventId, descriptor, MATURITY_TIME);

    let attestation;
    if (attest[0] === "numeric") attestation = await engine.attestNumeric(announcement, attest[1]);
    else if (attest[0] === "binary") attestation = await engine.attestBinary(announcement, attest[1]);
    else attestation = await engine.attestEnum(announcement, attest[1]);

    const descriptorHash = hashDescriptor(descriptor);
    const eventIdHash = hashEventId(eventId);

    // Announcements are signed with fresh randomness; the canonical MESSAGE
    // and its digest are deterministic and vector-pinned.
    const announcementMessage = serializeAnnouncementMessage(
      eventId,
      oraclePublicKey,
      descriptor,
      MATURITY_TIME,
      announcement.noncePoints
    );

    const outcomesHex = [];
    const attestationMessages = [];
    const attestationMessageHashes = [];
    for (let i = 0; i < attestation.outcomes.length; i++) {
      const outcome = attestation.outcomes[i];
      const outcomeBuf = Buffer.from(outcome, "utf8");
      const message = serializeAttestationMessage(
        eventId,
        oraclePublicKey,
        descriptor,
        MATURITY_TIME,
        outcome
      );
      const messageHash = hashAttestation(message);

      // --- cross-check: .ark matcher emulation must produce identical bytes
      const arkMessage = ark.arkAttestationMessage({
        eventIdHash,
        oracleKeyXonly: oraclePublicKey,
        descriptorHash,
        maturityTime: MATURITY_TIME,
        outcome: outcomeBuf,
      });
      const arkMessageHash = ark.arkAttestationMessageHash({
        eventIdHash,
        oracleKeyXonly: oraclePublicKey,
        descriptorHash,
        maturityTime: MATURITY_TIME,
        outcome: outcomeBuf,
      });
      if (!arkMessage.equals(message)) {
        throw new Error(`vector ${name}: TS and .ark matcher messages diverge`);
      }
      if (!arkMessageHash.equals(messageHash)) {
        throw new Error(`vector ${name}: TS and .ark matcher message hashes diverge`);
      }
      // The signature must verify against the matcher-side digest
      const ok = require("../tests/shims/cfd-js.js").SchnorrVerify({
        pubkey: oraclePublicKey.toString("hex"),
        message: arkMessageHash.toString("hex"),
        signature: attestation.signatures[i].toString("hex"),
      }).valid;
      if (!ok) {
        throw new Error(`vector ${name}: signature does not verify on the .ark side`);
      }

      outcomesHex.push(outcomeBuf.toString("hex"));
      attestationMessages.push(message.toString("hex"));
      attestationMessageHashes.push(messageHash.toString("hex"));
    }

    vectors.push({
      name,
      eventId,
      eventIdHash: eventIdHash.toString("hex"),
      oraclePublicKey: oraclePublicKey.toString("hex"),
      oraclePrivateKey: oraclePrivateKey.toString("hex"),
      descriptor,
      descriptorHash: descriptorHash.toString("hex"),
      maturityTime: MATURITY_TIME,
      outcomes: attestation.outcomes,
      outcomesHex,
      attestationMessages,
      attestationMessageHashes,
      attestationSignatures: attestation.signatures.map((s) => s.toString("hex")),
      noncePoints: announcement.noncePoints.map((r) => r.toString("hex")),
      announcementMessage: announcementMessage.toString("hex"),
      announcementMessageHash: hashAnnouncement(announcementMessage).toString("hex"),
    });
  }

  const output = {
    $comment:
      "SHARED test vectors: vtxo-loan-system TypeScript signer AND the .ark " +
      "on-chain matchers (CollateralizedLoan.ark / UnsecuredLoan.ark) must " +
      "reproduce these bytes exactly. Field encodings: eventIdHash = " +
      "sha256(utf8(eventId)); oraclePublicKey is the 32-byte x-only key; " +
      "lenpfx(x) = 4-byte big-endian length of x followed by x (the .ark " +
      "builtin encoding); each attestation message = lenpfx(eventIdHash) || lenpfx(oracleKeyX) " +
      "|| lenpfx(descriptorHash) || lenpfx(maturityTime u64 BE) || " +
      "lenpfx(outcome utf8) hashed under BIP-340 tag " +
      "'DLC/oracle/attestation/v1'. Signatures are standard BIP-340 over the " +
      "message hash. The private key here is TEST-ONLY (published on purpose, " +
      "like the BIP-340 test vectors).",
    version: 1,
    network: "bitcoin_regtest",
    keyDerivation: {
      mnemonic: MNEMONIC,
      oraclePath: ORACLE_PATH,
      noncePurpose: 585,
    },
    maturityTime: MATURITY_TIME,
    // Inputs both sides must REFUSE (no eventIdHash, message or signature may be produced)
    refusals: [
      { name: "empty eventId", eventId: "", expect: "refused" },
    ],
    vectors,
  };

  const outPath = path.join(__dirname, "..", "tests", "vectors", "attestation-vectors.json");
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, JSON.stringify(output, null, 2) + "\n", "utf8");
  fs.rmSync(registryDir, { recursive: true, force: true });
  console.log(`wrote ${vectors.length} vectors to ${outPath}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
