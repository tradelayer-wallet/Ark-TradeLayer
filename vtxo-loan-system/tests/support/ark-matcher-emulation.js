/**
 * Independent re-implementation of the `.ark` on-chain matcher's canonical
 * attestation serialization (CollateralizedLoan.ark verifyOracleAttestation /
 * UnsecuredLoan.ark verifyRepayment).
 *
 * This module deliberately shares NO code with vtxo-loan-system/src: it is a
 * literal, byte-level transcription of the pseudo-code an on-chain matcher
 * would implement, used to prove that the TypeScript signer and the matcher
 * compute identical bytes. If either side changes, the shared vectors in
 * tests/vectors/attestation-vectors.json catch the divergence.
 *
 * Matcher semantics (from the .ark):
 *
 *   blob  := eventIdHash(32) || descriptorHash(32) || maturityTime(8 BE)
 *            || outcome(var) || signature(64)
 *
 *   message :=
 *     lenpfx(bytes(attestedEventId))   // 32-byte sha256(utf8(eventId))
 *     || lenpfx(bytes(xonly(oracleKey)))  // 32-byte x-only key
 *     || lenpfx(bytes(descriptorHash))    // 32 raw bytes
 *     || lenpfx(maturityTime)             // 8 bytes, uint64 BE
 *     || lenpfx(outcome)                  // utf8 bytes
 *
 *   messageHash := taggedHash("DLC/oracle/attestation/v1", message)
 *                = sha256(sha256(tag) || sha256(tag) || message)
 */
"use strict";

const crypto = require("crypto");

const ATTESTATION_TAG = "DLC/oracle/attestation/v1";

function sha256(...parts) {
  const h = crypto.createHash("sha256");
  for (const part of parts) h.update(part);
  return h.digest();
}

function lenpfx(field) {
  const prefix = Buffer.alloc(4);
  prefix.writeUInt32BE(field.length, 0);
  return Buffer.concat([prefix, field]);
}

function taggedHash(tag, message) {
  const tagHash = sha256(Buffer.from(tag, "utf8"));
  return sha256(tagHash, tagHash, message);
}

function u64be(value) {
  const out = Buffer.alloc(8);
  out.writeBigUInt64BE(BigInt(value), 0);
  return out;
}

/**
 * Computes the matcher-side attestation message bytes.
 *
 * @param {{eventIdHash: Buffer, oracleKeyXonly: Buffer, descriptorHash: Buffer,
 *          maturityTime: number, outcome: Buffer}} fields
 * @returns {Buffer}
 */
function arkAttestationMessage(fields) {
  return Buffer.concat([
    lenpfx(fields.eventIdHash),
    lenpfx(fields.oracleKeyXonly),
    lenpfx(fields.descriptorHash),
    lenpfx(u64be(fields.maturityTime)),
    lenpfx(fields.outcome),
  ]);
}

/**
 * Computes the matcher-side attestation message hash (what the oracle signs
 * and what checkSchnorrSig verifies against).
 */
function arkAttestationMessageHash(fields) {
  return taggedHash(ATTESTATION_TAG, arkAttestationMessage(fields));
}

/** sha256(utf8(eventId)) - the pinned bytes32 event id of the contracts */
function arkEventIdHash(eventId) {
  return sha256(Buffer.from(eventId, "utf8"));
}

/**
 * Builds the v1 attestation blob the matcher parses:
 *   eventIdHash(32) || descriptorHash(32) || maturityTime(8) || outcome(var) || signature(64)
 */
function arkAttestationBlob(fields, signature) {
  return Buffer.concat([
    fields.eventIdHash,
    fields.descriptorHash,
    u64be(fields.maturityTime),
    fields.outcome,
    signature,
  ]);
}

/**
 * The matcher's verifyOracleAttestation / verifyRepayment: parses the blob and accepts it only for the pinned event
 * id, descriptor, maturity and outcome, with the pinned announced nonce point R as the signature's first 32 bytes,
 * and a valid BIP-340 signature by the oracle key. checkSchnorrSig alone accepts any R, so the R pin is what keeps
 * a second outcome under a fresh nonce from counting.
 *
 * `schnorrVerify(pubkeyXonlyHex, messageHashHex, signatureHex) => boolean` is passed in, so this module still
 * shares no code with src.
 *
 * @param {Buffer} blob
 * @param {{eventIdHash: Buffer, oracleKeyXonly: Buffer, descriptorHash: Buffer, maturityTime: number,
 *          outcome: Buffer, nonceR: Buffer}} pinned
 * @param {(pubkey: string, message: string, signature: string) => boolean} schnorrVerify
 * @returns {boolean}
 */
function arkVerifyOracleAttestation(blob, pinned, schnorrVerify) {
  if (blob.length < 32 + 32 + 8 + 64) return false;
  const attestedEventId = blob.subarray(0, 32);
  const descriptorHash = blob.subarray(32, 64);
  const maturityTime = blob.subarray(64, 72);
  const outcome = blob.subarray(72, blob.length - 64);
  const signature = blob.subarray(blob.length - 64);
  if (!attestedEventId.equals(pinned.eventIdHash)) return false;
  if (!descriptorHash.equals(pinned.descriptorHash)) return false;
  if (!maturityTime.equals(u64be(pinned.maturityTime))) return false;
  if (!outcome.equals(pinned.outcome)) return false;
  if (!signature.subarray(0, 32).equals(pinned.nonceR)) return false;
  const messageHash = arkAttestationMessageHash({
    eventIdHash: attestedEventId,
    oracleKeyXonly: pinned.oracleKeyXonly,
    descriptorHash,
    maturityTime: pinned.maturityTime,
    outcome,
  });
  return schnorrVerify(pinned.oracleKeyXonly.toString("hex"), messageHash.toString("hex"), signature.toString("hex"));
}

module.exports = {
  ATTESTATION_TAG,
  arkAttestationMessage,
  arkAttestationMessageHash,
  arkAttestationBlob,
  arkVerifyOracleAttestation,
  arkEventIdHash,
  lenpfx,
  sha256,
  taggedHash,
  u64be,
};
