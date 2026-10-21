/**
 * Tagged Hash Utilities
 * 
 * Implements BIP-340 tagged hashing for domain separation in Bitcoin protocols.
 * Used extensively in DLCs for nonce derivation and message signing.
 */

import { sha256 } from "@node-lightning/crypto";

/**
 * Cache for pre-computed tag hashes to avoid redundant computation
 */
const TAG_HASH_CACHE = new Map<string, Buffer>();

/**
 * Computes SHA256(tag) and caches the result
 */
function getOrComputeTagHash(tag: string | Buffer): Buffer {
  const tagKey = typeof tag === "string" ? tag : tag.toString("hex");
  
  let tagHash = TAG_HASH_CACHE.get(tagKey);
  if (!tagHash) {
    tagHash = sha256(Buffer.from(tag));
    TAG_HASH_CACHE.set(tagKey, tagHash);
  }
  
  return tagHash;
}

/**
 * Creates a tagged hash following BIP-340 specification
 * 
 * Tagged hash = SHA256(SHA256(tag) || SHA256(tag) || data)
 * 
 * This provides domain separation, ensuring that hashes for different
 * purposes cannot collide even with the same input data.
 * 
 * @param tag - Domain separation tag (e.g., "DLC/oracle/nonce-index/v1")
 * @param data - Data to hash
 * @returns 32-byte tagged hash
 */
export function createTaggedHash(tag: string | Buffer, data: Buffer): Buffer {
  const tagHash = getOrComputeTagHash(tag);
  const combined = Buffer.concat([tagHash, tagHash, data]);
  return sha256(combined);
}

/**
 * Standard tags used in DLC protocol
 *
 * NOTE: the attestation/announcement tags were bumped to v1 when the signed
 * messages were redefined as canonical length-prefixed commitments that bind
 * the eventId (see attestation-engine.ts). Signatures produced under the old
 * v0 tags are intentionally no longer valid.
 *
 * The nonce derivation index and the nonce tweak previously shared the single
 * tag "DLC/oracle/nonce/v0". Two different derivations under one tag is a
 * domain-separation failure: any relation between the index hash and the
 * tweak hash would be usable across derivations. They now have dedicated,
 * disjoint tags.
 */
export const DLC_TAGS = {
  ORACLE_ANNOUNCEMENT: "DLC/oracle/announcement/v1",
  ORACLE_ATTESTATION: "DLC/oracle/attestation/v1",
  ORACLE_DESCRIPTOR: "DLC/oracle/descriptor/v1",
  ORACLE_NONCE_INDEX: "DLC/oracle/nonce-index/v1",
  ORACLE_NONCE_TWEAK: "DLC/oracle/nonce-tweak/v1",
  CONTRACT_INFO: "DLC/contract/info/v0",
  FUNDING_INPUT: "DLC/funding/input/v0",
} as const;

/**
 * Encodes a single field as a 4-byte big-endian length prefix followed by the
 * field bytes. Length-prefixing every field removes the concatenation
 * ambiguity that allows distinct field tuples to serialize to identical bytes.
 */
export function encodeLengthPrefixed(field: Buffer): Buffer {
  const prefix = Buffer.alloc(4);
  prefix.writeUInt32BE(field.length, 0);
  return Buffer.concat([prefix, field]);
}

/**
 * Serializes fields as a canonical, unambiguous byte string:
 * each field is encoded as uint32_be(len(field)) || field.
 */
export function concatLengthPrefixed(fields: Buffer[]): Buffer {
  return Buffer.concat(fields.map(encodeLengthPrefixed));
}

/**
 * Encodes an unsigned integer as a fixed-width 8-byte big-endian value
 * (canonical integer serialization for hashed fields).
 */
export function encodeUint64BE(value: number): Buffer {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`encodeUint64BE: value must be a non-negative safe integer, got ${value}`);
  }
  const out = Buffer.alloc(8);
  out.writeBigUInt64BE(BigInt(value), 0);
  return out;
}

/**
 * Asserts that a string is printable ASCII (0x20-0x7E) and within the
 * allowed length.
 *
 * JavaScript strings are UTF-16 and `Buffer.from(s, "utf8")` maps every
 * unpaired surrogate (e.g. "\uD800") onto the U+FFFD replacement character.
 * Two distinct event ids would therefore serialize - and hash - to identical
 * bytes, letting one event's attestation collide with another's. Restricting
 * event ids (and outcome labels) to printable ASCII removes the collision
 * class entirely.
 */
export function assertPrintableAscii(text: string, what: string): void {
  if (typeof text !== "string" || text.length === 0 || text.length > 255) {
    throw new Error(`${what} must be a 1..255 character string`);
  }
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if (code < 0x20 || code > 0x7e) {
      throw new Error(
        `${what} must be printable ASCII (0x20-0x7E); got non-ASCII/control ` +
          `character U+${code.toString(16).toUpperCase().padStart(4, "0")} at index ${i}`
      );
    }
  }
}

/** True when assertPrintableAscii accepts the text (the boolean form, for validators) */
export function isPrintableAsciiId(text: string): boolean {
  try {
    assertPrintableAscii(text, "identifier");
    return true;
  } catch {
    return false;
  }
}

/**
 * Canonical 32-byte event id commitment: sha256(utf8(eventId)).
 *
 * This is THE eventId on every hashed/signed path (attestation message,
 * announcement message, nonce derivation index, nonce tweak) and the value
 * the on-chain matcher compares against its pinned `bytes32 eventId` (the
 * .ark contracts call it `repaymentOracleId` / `priceOracleId`). Both sides
 * MUST use these 32 raw bytes - hashing the utf8 string on one side and the
 * bytes32 on the other produced two incompatible serializations (see the
 * shared test vectors in tests/vectors/attestation-vectors.json).
 */
export function hashEventId(eventId: string): Buffer {
  assertPrintableAscii(eventId, "eventId");
  return sha256(Buffer.from(eventId, "utf8"));
}

/**
 * Creates announcement hash for oracle event pre-commitment
 *
 * @param announcementData - canonical length-prefixed announcement serialization
 */
export function hashAnnouncement(announcementData: Buffer): Buffer {
  return createTaggedHash(DLC_TAGS.ORACLE_ANNOUNCEMENT, announcementData);
}

/**
 * Creates attestation hash for oracle outcome signing
 *
 * @param message - canonical length-prefixed attestation serialization
 *   (eventId, oraclePubkey, descriptorHash, maturityTime, outcome). The
 *   outcome alone must never be signed: it is replayable across events.
 */
export function hashAttestation(message: Buffer): Buffer {
  return createTaggedHash(DLC_TAGS.ORACLE_ATTESTATION, message);
}

/**
 * Creates nonce tweak for deterministic R-value generation
 *
 * This is critical for DLC security - each event must have unique nonces
 * that can be deterministically regenerated for signing.
 *
 * Both fields are length-prefixed (previously they were concatenated raw,
 * so distinct (basePoint, eventId) tuples could serialize to the same bytes
 * and derive the same tweak - and therefore the same signing nonce k).
 *
 * The eventId is folded in as its 32-byte sha256(utf8(eventId)) commitment
 * (hashEventId), the same id the signed messages bind, and the tweak has a
 * dedicated tag disjoint from the nonce-derivation-index hash
 * (DLC_TAGS.ORACLE_NONCE_INDEX).
 *
 * @param basePoint - Base public point (typically the derived nonce point)
 * @param eventId - Unique event identifier (printable ASCII)
 */
export function deriveNonceTweak(basePoint: Buffer, eventId: string): Buffer {
  const combined = concatLengthPrefixed([basePoint, hashEventId(eventId)]);
  return createTaggedHash(DLC_TAGS.ORACLE_NONCE_TWEAK, combined);
}

/**
 * Clears the tag hash cache (useful for testing or memory management)
 */
export function clearTagHashCache(): void {
  TAG_HASH_CACHE.clear();
}

/**
 * Returns the current cache size (for monitoring)
 */
export function getTagHashCacheSize(): number {
  return TAG_HASH_CACHE.size;
}
