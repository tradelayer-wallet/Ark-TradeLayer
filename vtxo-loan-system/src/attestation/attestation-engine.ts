/**
 * Attestation Engine
 * 
 * Core module for creating and verifying cryptographic attestations.
 * Supports multiple attestation types for DLC loan contracts.
 */

import { BitcoinNetwork } from "bitcoin-networks";
import { timingSafeEqual } from "crypto";
import { inspect } from "util";
import {
  deriveSchnorrPublicKey,
  schnorrSign,
  schnorrSignWithNonce,
  schnorrVerify,
  tweakPrivateKey,
} from "../crypto/bitcoin-primitives";
import {
  DLC_TAGS,
  concatLengthPrefixed,
  createTaggedHash,
  deriveNonceTweak,
  encodeUint64BE,
  hashAnnouncement,
  hashAttestation,
  hashEventId,
  isPrintableAsciiId,
} from "../crypto/tagged-hash";
import { KeyProvider } from "../keys/key-provider";
import { inspectRedacted, redactedView } from "../redaction";
import { UsedNonceRegistry } from "./used-nonce-registry";

export { NonceRegistryLockError, NonceReuseError, UsedNonceRegistry } from "./used-nonce-registry";

/**
 * Maximum tolerated clock skew (seconds) past maturityTime before an
 * attestation is rejected as premature.
 */
export const MATURITY_SKEW_SECONDS = 300;

/**
 * Mainnet always implies production semantics for security checks
 * (development mode is never an excuse to weaken a mainnet deployment).
 */
function isMainnetNetwork(network: BitcoinNetwork): boolean {
  return network.name === "bitcoin";
}

/**
 * Types of attestations supported
 */
export enum AttestationType {
  /** Numeric value (e.g., price, amount) */
  NUMERIC = "numeric",
  /** Binary outcome (e.g., paid/unpaid, yes/no) */
  BINARY = "binary",
  /** Enumerated outcome (e.g., fulfilled, defaulted, expired) */
  ENUM = "enum",
}

/**
 * Event descriptor for numeric attestations
 */
export interface NumericEventDescriptor {
  type: AttestationType.NUMERIC;
  /** Base for digit decomposition (integer, 2..36) */
  base: number;
  /** Number of digits in decomposition (integer, >= 1) */
  numDigits: number;
  /** Unit of measurement (printable ASCII, non-empty) */
  unit: string;
  /**
   * Decimal precision: the attested digit vector encodes
   * value * 10^precision as an integer (e.g. precision 2 attests "12.34"
   * as the digit vector of 1234).
   */
  precision: number;
  /** Whether the number can be negative */
  signed: boolean;
}

/**
 * Event descriptor for binary attestations
 */
export interface BinaryEventDescriptor {
  type: AttestationType.BINARY;
  /** Labels for true/false outcomes (printable ASCII, distinct) */
  outcomes: [string, string];
}

/**
 * Event descriptor for enum attestations
 */
export interface EnumEventDescriptor {
  type: AttestationType.ENUM;
  /** Possible outcome values (printable ASCII, distinct) */
  outcomes: string[];
}

export type EventDescriptor =
  | NumericEventDescriptor
  | BinaryEventDescriptor
  | EnumEventDescriptor;

/**
 * Pre-commitment to an oracle event
 */
export interface EventAnnouncement {
  /** Unique event identifier */
  eventId: string;
  /** Oracle's Schnorr public key */
  oraclePublicKey: Buffer;
  /** Event descriptor defining possible outcomes */
  descriptor: EventDescriptor;
  /** Maturity timestamp (Unix epoch seconds) */
  maturityTime: number;
  /** R-values (nonce commitments) for signing */
  noncePoints: Buffer[];
  /** Signature over the announcement by oracle */
  announcementSignature: Buffer;
}

/**
 * Cryptographic attestation to an event outcome
 */
export interface EventAttestation {
  /** Event ID this attests to */
  eventId: string;
  /** Oracle's public key */
  oraclePublicKey: Buffer;
  /** Actual outcome values */
  outcomes: string[];
  /** Schnorr signatures for each outcome */
  signatures: Buffer[];
  /** Timestamp when attestation was created */
  attestationTime: number;
}

/**
 * Configuration for attestation engine
 */
export interface AttestationEngineConfig {
  network: BitcoinNetwork;
  keyProvider: KeyProvider;
  /** HD path prefix for nonce derivation */
  noncePurpose?: number;
  /**
   * Trusted oracle x-only public key (32-byte Buffer or 64-char hex).
   * verifyAttestation refuses anything not signed by this key (C2).
   */
  trustedOraclePublicKey?: string | Buffer;
  /**
   * Absolute path of the JSON file that persists the used-nonce registry across
   * restarts. Required: a relative path would make the registry depend on the
   * working directory.
   * Pass null for in-memory only - this is refused unless `developmentMode` is
   * true AND the network is not mainnet: an in-memory registry forgets every used
   * nonce on restart, which allows the deterministic derivation to sign twice
   * with the same k.
   */
  usedNonceRegistryPath: string | null;
  /**
   * Creates the registry at usedNonceRegistryPath when it does not exist yet (the
   * first start of a signer). Without it a missing registry refuses to start.
   */
  usedNonceRegistryInit?: boolean;
  /**
   * Explicit development-mode marker. Only development mode may run with an
   * in-memory nonce registry; mainnet always implies production semantics.
   */
  developmentMode?: boolean;
}

/**
 * Canonical descriptor serialization (deterministic, length-prefixed).
 *
 * Replaces JSON.stringify(): JSON output is not canonical (key order,
 * whitespace) and was previously concatenated into an unsigned context,
 * making announcements malleable. Every field is encoded as
 * uint32_be(len) || utf8(field).
 */
export function serializeDescriptor(descriptor: EventDescriptor): Buffer {
  const str = (s: string): Buffer => Buffer.from(s, "utf8");
  const parts: Buffer[] = [];

  switch (descriptor.type) {
    case AttestationType.NUMERIC:
      parts.push(
        str("numeric"),
        str(String(descriptor.base)),
        str(String(descriptor.numDigits)),
        str(descriptor.unit),
        str(String(descriptor.precision)),
        str(descriptor.signed ? "1" : "0")
      );
      break;
    case AttestationType.BINARY: {
      const [labelTrue, labelFalse] = descriptor.outcomes;
      parts.push(str("binary"), str(labelTrue), str(labelFalse));
      break;
    }
    case AttestationType.ENUM:
      parts.push(str("enum"), ...descriptor.outcomes.map(str));
      break;
  }

  return concatLengthPrefixed(parts);
}

/**
 * Fixed-size (32-byte) commitment to an event descriptor.
 */
export function hashDescriptor(descriptor: EventDescriptor): Buffer {
  return createTaggedHash(DLC_TAGS.ORACLE_DESCRIPTOR, serializeDescriptor(descriptor));
}

/**
 * Range-validates an event descriptor.
 *
 * Descriptors arrive in announcements supplied by untrusted peers as well as
 * from local configuration, so they must be checked structurally - a
 * malformed descriptor (e.g. `numDigits: 0`) would otherwise make
 * `calculateNoncesNeeded` return 0 and an EMPTY attestation verify as true.
 * Called with fail-closed semantics at announcement creation and at every
 * verification.
 */
export function isValidDescriptor(descriptor: EventDescriptor): boolean {
  if (!descriptor || typeof descriptor !== "object") {
    return false;
  }
  switch (descriptor.type) {
    case AttestationType.NUMERIC: {
      const { base, numDigits, unit, precision, signed } = descriptor;
      return (
        Number.isInteger(base) &&
        base >= 2 &&
        base <= 36 &&
        Number.isInteger(numDigits) &&
        numDigits >= 1 &&
        numDigits <= 64 &&
        isPrintableAsciiId(unit) &&
        Number.isInteger(precision) &&
        precision >= 0 &&
        precision <= 18 &&
        typeof signed === "boolean"
      );
    }
    case AttestationType.BINARY: {
      const outcomes = descriptor.outcomes;
      return (
        Array.isArray(outcomes) &&
        outcomes.length === 2 &&
        outcomes[0] !== outcomes[1] &&
        isPrintableAsciiId(outcomes[0]!) &&
        isPrintableAsciiId(outcomes[1]!)
      );
    }
    case AttestationType.ENUM: {
      const outcomes = descriptor.outcomes;
      if (!Array.isArray(outcomes) || outcomes.length < 1) {
        return false;
      }
      const seen = new Set<string>();
      for (const outcome of outcomes) {
        if (!isPrintableAsciiId(outcome) || seen.has(outcome)) {
          return false;
        }
        seen.add(outcome);
      }
      return true;
    }
    default:
      return false;
  }
}

/**
 * Throwing form of isValidDescriptor: the ONLY descriptor validator. Used by
 * announcement creation and by every attest* method (before any value is
 * scaled or any nonce is derived).
 */
export function assertValidDescriptor(descriptor: EventDescriptor): void {
  if (!isValidDescriptor(descriptor)) {
    throw new Error(
      "Invalid event descriptor: numeric descriptors need integer base 2..36, " +
        "numDigits >= 1, precision 0..18 and a printable-ASCII unit; binary/enum " +
        "descriptors need distinct, non-empty, printable-ASCII outcome labels"
    );
  }
}

/**
 * Canonical attestation message (v1).
 *
 * The signed digest covers - in this exact order, each field prefixed with a
 * 4-byte big-endian length:
 *
 *   lenpfx(eventIdHash)                   (32 raw bytes, sha256(utf8(eventId)))
 *   || lenpfx(oraclePubkeyXonly)          (32 raw bytes)
 *   || lenpfx(descriptorHash)             (32 raw bytes, see hashDescriptor)
 *   || lenpfx(maturityTime as uint64 BE)  (8 raw bytes)
 *   || lenpfx(utf8(outcome))
 *
 * Binding all five fields prevents cross-contract replay: a signature for one
 * (eventId, descriptor, maturity, outcome) tuple is invalid for any other.
 *
 * The eventId field is the 32-byte commitment `sha256(utf8(eventId))`
 * (hashEventId), NOT the raw utf8 string bytes: the on-chain matcher only
 * has a `bytes32` event id to compare against (see the .ark contracts and
 * tests/vectors/attestation-vectors.json, which both sides must reproduce
 * byte-for-byte).
 */
export function serializeAttestationMessage(
  eventId: string,
  oraclePublicKey: Buffer,
  descriptor: EventDescriptor,
  maturityTime: number,
  outcome: string
): Buffer {
  return concatLengthPrefixed([
    hashEventId(eventId),
    oraclePublicKey,
    hashDescriptor(descriptor),
    encodeUint64BE(maturityTime),
    Buffer.from(outcome, "utf8"),
  ]);
}

/**
 * Canonical announcement message (v1): the attestation fields above with the
 * nonce pre-commitments appended, each length-prefixed:
 *
 *   lenpfx(eventIdHash) || lenpfx(oraclePubkeyXonly) || lenpfx(descriptorHash)
 *   || lenpfx(maturityTime as uint64 BE) || lenpfx(noncePoint[0]) || ...
 */
export function serializeAnnouncementMessage(
  eventId: string,
  oraclePublicKey: Buffer,
  descriptor: EventDescriptor,
  maturityTime: number,
  noncePoints: Buffer[]
): Buffer {
  return concatLengthPrefixed([
    hashEventId(eventId),
    oraclePublicKey,
    hashDescriptor(descriptor),
    encodeUint64BE(maturityTime),
    ...noncePoints,
  ]);
}

/**
 * Parses a trusted oracle key (x-only, 32 bytes) from a Buffer or hex string.
 * Returns undefined for anything malformed.
 */
export function parseOraclePublicKey(key: string | Buffer | undefined): Buffer | undefined {
  if (key === undefined) {
    return undefined;
  }
  if (Buffer.isBuffer(key)) {
    return key.length === 32 ? Buffer.from(key) : undefined;
  }
  if (typeof key === "string" && /^[0-9a-fA-F]{64}$/.test(key)) {
    return Buffer.from(key, "hex");
  }
  return undefined;
}

/**
 * Constant-time equality for fixed-length public key material. Key
 * comparisons must not leak match position through timing
 * (crypto.timingSafeEqual instead of Buffer.equals).
 */
export function constantTimeEquals(a: Buffer, b: Buffer): boolean {
  if (a.length !== b.length || a.length === 0) {
    return false;
  }
  return timingSafeEqual(a, b);
}

/** A value that can be attested: exact decimal string, bigint, or a JS number */
export type AttestableValue = number | string | bigint;

/** Largest decimal exponent accepted in a value (bounds the BigInt work) */
const MAX_DECIMAL_EXPONENT = 400;
/** Longest decimal text accepted for a value */
const MAX_DECIMAL_TEXT_LENGTH = 128;

/**
 * Scales a decimal value by 10^precision exactly, into an integer BigInt.
 *
 * - bigint: scaled exactly.
 * - string: parsed as an exact decimal ("12.34", "-7", "1e-7"). Use this form
 *   for any value that is not exactly representable as a JS number.
 * - number: its shortest round-trip decimal form is parsed (never by
 *   floating-point multiplication). Numbers beyond Number.MAX_SAFE_INTEGER in
 *   magnitude are REJECTED: the double has already lost the digits the caller
 *   wrote (123456789012345678 is stored as 123456789012345680), so attesting it
 *   would silently attest a different value.
 *
 * Values with more decimal places than `precision` are rejected, not rounded.
 */
export function scaleValueByPrecision(value: AttestableValue, precision: number): bigint {
  if (!Number.isInteger(precision) || precision < 0) {
    throw new Error(`Invalid precision: ${precision}`);
  }

  if (typeof value === "bigint") {
    return value * 10n ** BigInt(precision);
  }

  let text: string;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error(`Cannot attest non-finite value: ${value}`);
    }
    if (Math.abs(value) > Number.MAX_SAFE_INTEGER) {
      throw new Error(
        `Cannot attest ${value}: the magnitude exceeds Number.MAX_SAFE_INTEGER, so the ` +
          `number cannot hold the intended digits. Pass the value as a decimal string or bigint.`
      );
    }
    text = String(value);
  } else if (typeof value === "string") {
    text = value;
  } else {
    throw new Error(`Cannot attest value of type ${typeof value}`);
  }

  // Exact parse of the decimal form (handles "1e-7", "12.34", ...)
  if (text.length > MAX_DECIMAL_TEXT_LENGTH) {
    throw new Error(`Cannot attest value: decimal text longer than ${MAX_DECIMAL_TEXT_LENGTH} characters`);
  }
  const match = /^(-?)(\d+)(?:\.(\d+))?(?:[eE]([+-]?\d+))?$/.exec(text);
  if (!match) {
    throw new Error(`Cannot attest non-decimal value: ${text}`);
  }
  const negative = match[1] === "-";
  const intPart = match[2] ?? "0";
  const fracPart = match[3] ?? "";
  const exponent = match[4] === undefined ? 0 : parseInt(match[4], 10);
  if (Math.abs(exponent) > MAX_DECIMAL_EXPONENT) {
    throw new Error(`Cannot attest value ${text}: exponent out of range`);
  }

  // value = sign * digits * 10^(exponent - fracPart.length)
  const digits = BigInt(intPart + fracPart);
  const totalShift = exponent - fracPart.length + precision;

  let scaled: bigint;
  if (totalShift > 0) {
    scaled = digits * 10n ** BigInt(totalShift);
  } else if (totalShift < 0) {
    const divisor = 10n ** BigInt(-totalShift);
    if (digits % divisor !== 0n) {
      throw new Error(
        `Value ${text} has more decimal places than the descriptor precision ${precision}; ` +
          `refusing to round`
      );
    }
    scaled = digits / divisor;
  } else {
    scaled = digits;
  }

  return negative ? -scaled : scaled;
}

/**
 * True when no two nonce points are equal. A repeated point means one signing
 * nonce k serves two indices, which leaks the oracle key once both are signed.
 * Shared by createAnnouncement (refuse to publish) and verifyAttestation (refuse
 * to accept).
 */
function hasDistinctNoncePoints(noncePoints: Buffer[]): boolean {
  return new Set(noncePoints.map((r) => r.toString("hex"))).size === noncePoints.length;
}

/** Maturity is Unix seconds: a safe, positive integer */
function isValidMaturity(maturityTime: number): boolean {
  return Number.isSafeInteger(maturityTime) && maturityTime > 0;
}

/**
 * The one maturity rule. An event is premature while its maturity lies more than
 * `toleranceSeconds` after `now`: the signer tolerates nothing, the verifier
 * tolerates MATURITY_SKEW_SECONDS.
 */
function isPremature(maturityTime: number, now: number, toleranceSeconds: number): boolean {
  return maturityTime > now + toleranceSeconds;
}

/**
 * The one announcement-authentication rule: true when the announcement carries a
 * valid signature by `oracleKey` over its canonical message (which covers
 * maturityTime and the nonce points). The signer and the verifier both call it.
 * Any malformed field makes the check fail; it never throws.
 */
function isAuthenticAnnouncement(announcement: EventAnnouncement, oracleKey: Buffer): boolean {
  try {
    if (!isValidMaturity(announcement.maturityTime)) {
      return false;
    }
    if (
      !Buffer.isBuffer(announcement.announcementSignature) ||
      announcement.announcementSignature.length !== 64
    ) {
      return false;
    }
    const announcementHash = hashAnnouncement(
      serializeAnnouncementMessage(
        announcement.eventId,
        announcement.oraclePublicKey,
        announcement.descriptor,
        announcement.maturityTime,
        announcement.noncePoints
      )
    );
    return schnorrVerify(oracleKey, announcementHash, announcement.announcementSignature);
  } catch (error) {
    return false;
  }
}

/**
 * Main attestation engine for DLC operations
 */
export class AttestationEngine {
  private network: BitcoinNetwork;
  private keyProvider: KeyProvider;
  private noncePurpose: number;
  private trustedOraclePublicKey?: Buffer;
  private usedNonces: UsedNonceRegistry;
  private oraclePrivateKey?: Buffer;
  private oraclePublicKey?: Buffer;

  constructor(config: AttestationEngineConfig) {
    this.network = config.network;
    this.keyProvider = config.keyProvider;
    this.noncePurpose = config.noncePurpose ?? 585; // BIP-0085 style purpose
    if (config.trustedOraclePublicKey !== undefined) {
      this.trustedOraclePublicKey = parseOraclePublicKey(config.trustedOraclePublicKey);
      if (!this.trustedOraclePublicKey) {
        throw new Error(
          "trustedOraclePublicKey must be a 32-byte x-only key (64 hex characters or a 32-byte Buffer)"
        );
      }
    }

    // Nonce registry (H1): a single writer per registry file, held for the
    // lifetime of this process. In-memory-only mode is a development-only
    // escape hatch - mainnet always implies production semantics.
    const registryPath = config.usedNonceRegistryPath;
    if (registryPath === undefined) {
      throw new Error(
        "usedNonceRegistryPath is required: pass the registry file path, or null for " +
          "in-memory operation in development"
      );
    }
    if (registryPath === null) {
      const developmentAllowed =
        config.developmentMode === true && !isMainnetNetwork(this.network);
      if (!developmentAllowed) {
        throw new Error(
          "usedNonceRegistryPath: null (in-memory nonce registry) is only allowed in " +
            `development mode on a non-mainnet network (got network=${this.network.name}, ` +
            `developmentMode=${config.developmentMode === true}). An in-memory registry ` +
            "forgets used nonces on restart and would let the oracle sign twice with the " +
            "same k, leaking the key."
        );
      }
      this.usedNonces = new UsedNonceRegistry({ persistPath: null, allowInMemory: true });
    } else {
      this.usedNonces = new UsedNonceRegistry({
        persistPath: registryPath,
        initialize: config.usedNonceRegistryInit === true,
      });
    }
  }

  /**
   * Initializes the oracle's master key
   */
  async initialize(): Promise<void> {
    // Derive master oracle key
    const keyPath = `m/48'/${this.network.coinType}'/0'/0'/0`;
    const keyResult = await this.keyProvider.deriveKey(keyPath);

    if (keyResult.isErr()) {
      throw new Error(`Failed to initialize oracle key: ${keyResult.error.message}`);
    }

    this.oraclePrivateKey = keyResult.value;
    this.oraclePublicKey = deriveSchnorrPublicKey(this.oraclePrivateKey);
    // Startup log of the derived oracle key (C3): operators must be able to
    // verify what is configured as the trusted key.
    console.log(
      `[oracle] Derived oracle public key (x-only): ${this.oraclePublicKey.toString("hex")}`
    );
  }

  /**
   * Computes the hardened BIP-32 index used to derive the nonce key for
   * (eventId, nonceIndex).
   *
   * The index is the first 31 bits of a tagged hash over the length-prefixed
   * (eventIdHash, nonceIndex) pair - not a bare counter - so the derivation is
   * bound to the event and cannot be correlated across events. 31 bits keep
   * the index valid for hardened derivation (index < 2^31).
   *
   * Uses the dedicated ORACLE_NONCE_INDEX tag (disjoint from the nonce
   * tweak's ORACLE_NONCE_TWEAK tag) and the same 32-byte eventIdHash the
   * signed messages bind.
   */
  private computeNonceDerivationIndex(eventId: string, nonceIndex: number): number {
    const indexBuf = Buffer.alloc(4);
    indexBuf.writeUInt32BE(nonceIndex, 0);
    const digest = createTaggedHash(
      DLC_TAGS.ORACLE_NONCE_INDEX,
      concatLengthPrefixed([hashEventId(eventId), indexBuf])
    );
    return digest.readUInt32BE(0) & 0x7fffffff;
  }

  /**
   * Derives a nonce private key for a specific event and index
   *
   * Path: m/{purpose}'/{coinType}'/0'/0'/{index}' - fully hardened to avoid
   * cross-event correlation through unhardened extended public keys.
   */
  private async deriveNonceKey(eventId: string, nonceIndex: number): Promise<Buffer> {
    const index = this.computeNonceDerivationIndex(eventId, nonceIndex);
    const keyPath = `m/${this.noncePurpose}'/${this.network.coinType}'/0'/0'/${index}'`;
    const keyResult = await this.keyProvider.deriveKey(keyPath);

    if (keyResult.isErr()) {
      throw new Error(
        `Failed to derive nonce key for event ${eventId} index ${nonceIndex}: ${keyResult.error.message}`
      );
    }

    return keyResult.value;
  }

  /**
   * Derives the signing nonce for (eventId, index).
   *
   * Let P be the base point of the derived nonce key. Then
   *   t = deriveNonceTweak(P, eventId),  k = oracleKey + t,  R = k*G.
   * R is the nonce commitment announced for the index and is public. P is
   * secret-derived and must never be stored or published: with P, anyone can
   * compute t, and one published signature s = k + e*oracleKey (up to BIP-340
   * sign conventions) then gives oracleKey = (s - t) / (1 + e). For this reason
   * the used-nonce registry is keyed by R, never by P.
   */
  private async deriveSigningNonce(
    eventId: string,
    index: number
  ): Promise<{ k: Buffer; R: Buffer }> {
    const noncePrivKey = await this.deriveNonceKey(eventId, index);
    const basePoint = deriveSchnorrPublicKey(noncePrivKey);
    const tweak = deriveNonceTweak(basePoint, eventId);
    const k = tweakPrivateKey(this.oraclePrivateKey!, tweak);
    return { k, R: deriveSchnorrPublicKey(k) };
  }

  /**
   * Calculates the number of nonces needed for an event descriptor.
   *
   * Always at least 1: a descriptor that would need zero nonces (e.g. a
   * numeric descriptor with numDigits: 0) must never make an empty
   * attestation verifiable. Descriptors are additionally range-validated by
   * isValidDescriptor at announcement and verification time.
   */
  private calculateNoncesNeeded(descriptor: EventDescriptor): number {
    switch (descriptor.type) {
      case AttestationType.NUMERIC:
        // One nonce per digit, plus one for sign if signed
        return Math.max(1, descriptor.numDigits + (descriptor.signed ? 1 : 0));
      case AttestationType.BINARY:
      case AttestationType.ENUM:
        // Single nonce for enum/binary outcomes
        return 1;
    }
  }

  /**
   * Checks that an outcome vector is consistent with the descriptor:
   * correct length, and every outcome inside the descriptor's declared
   * outcome set (digits of the declared base for numeric events, declared
   * labels for binary/enum events).
   */
  private outcomesMatchDescriptor(
    descriptor: EventDescriptor,
    outcomes: string[]
  ): boolean {
    if (outcomes.length !== this.calculateNoncesNeeded(descriptor)) {
      return false;
    }

    switch (descriptor.type) {
      case AttestationType.NUMERIC: {
        // base is range-checked by isValidDescriptor (the caller's contract)
        const { base, signed } = descriptor;
        const digits = new Set<string>();
        for (let d = 0; d < base; d++) {
          digits.add(d.toString(base));
        }
        let digitOutcomes = outcomes;
        if (signed) {
          const sign = outcomes[0];
          if (sign !== "+" && sign !== "-") {
            return false;
          }
          digitOutcomes = outcomes.slice(1);
        }
        return digitOutcomes.every((o) => o.length === 1 && digits.has(o));
      }
      case AttestationType.BINARY:
      case AttestationType.ENUM: {
        const outcome = outcomes[0];
        return outcome !== undefined && descriptor.outcomes.includes(outcome);
      }
    }
  }

  /**
   * Creates a new event announcement
   *
   * The descriptor is range-validated here (announcement time) so malformed
   * descriptors - numDigits: 0, non-ASCII labels, duplicate outcomes - can
   * never be pre-committed to, and the eventId must be printable ASCII (see
   * hashEventId).
   */
  async createAnnouncement(
    eventId: string,
    descriptor: EventDescriptor,
    maturityTime: number
  ): Promise<EventAnnouncement> {
    if (!this.oraclePrivateKey || !this.oraclePublicKey) {
      throw new Error("Attestation engine not initialized");
    }
    // Throws for non-printable-ASCII event ids (would collide under utf8)
    hashEventId(eventId);
    assertValidDescriptor(descriptor);
    if (!isValidMaturity(maturityTime)) {
      throw new Error(`Invalid maturityTime: ${maturityTime}`);
    }

    const noncesNeeded = this.calculateNoncesNeeded(descriptor);
    const noncePoints: Buffer[] = [];

    // Generate nonce commitments (R-values)
    for (let i = 0; i < noncesNeeded; i++) {
      const { R } = await this.deriveSigningNonce(eventId, i);
      noncePoints.push(R);
    }
    // The 31-bit index can collide within one event. Two indices with one
    // nonce point would sign with one k, so refuse to announce such an event.
    if (!hasDistinctNoncePoints(noncePoints)) {
      throw new Error(
        `Nonce index collision for event ${eventId}: refusing to announce it (use another eventId)`
      );
    }

    // Serialize announcement for signing (canonical, length-prefixed)
    const announcementData = serializeAnnouncementMessage(
      eventId,
      this.oraclePublicKey,
      descriptor,
      maturityTime,
      noncePoints
    );

    // Sign the announcement
    const announcementHash = hashAnnouncement(announcementData);
    const announcementSignature = schnorrSign(
      this.oraclePrivateKey,
      announcementHash
    );

    return {
      eventId,
      oraclePublicKey: this.oraclePublicKey,
      descriptor,
      maturityTime,
      noncePoints,
      announcementSignature,
    };
  }

  /**
   * Creates an attestation for a numeric event
   *
   * The attested digit vector encodes value * 10^precision as an integer
   * (NumericEventDescriptor.precision defines the number of decimal places).
   * A value with more decimal places than the descriptor's precision is
   * REJECTED, never silently rounded. Negative values are refused for
   * unsigned descriptors (previously the sign was dropped and |value| was
   * attested instead).
   */
  async attestNumeric(
    announcement: EventAnnouncement,
    value: AttestableValue
  ): Promise<EventAttestation> {
    const descriptor = this.requireAttestable(announcement, AttestationType.NUMERIC);
    const { base, numDigits, signed, precision } = descriptor;

    const scaled = scaleValueByPrecision(value, precision);
    const negative = scaled < 0n;
    if (negative && !signed) {
      throw new Error(
        `Refusing to attest negative value ${value} for an unsigned descriptor ` +
          `(signed=false would silently attest the absolute value)`
      );
    }

    // Decompose the scaled magnitude into digits
    const magnitude = negative ? -scaled : scaled;
    const valueStr = magnitude.toString(base).padStart(numDigits, "0");

    if (valueStr.length > numDigits) {
      throw new Error(`Value ${value} exceeds digit capacity`);
    }

    const outcomes = valueStr.split("");

    // Add sign if needed
    if (signed) {
      outcomes.unshift(negative ? "-" : "+");
    }

    return this.signOutcomes(announcement, outcomes);
  }

  /**
   * Creates an attestation for a binary event
   */
  async attestBinary(
    announcement: EventAnnouncement,
    outcome: boolean
  ): Promise<EventAttestation> {
    const descriptor = this.requireAttestable(announcement, AttestationType.BINARY);
    const [labelTrue, labelFalse] = descriptor.outcomes;
    const outcomeString = outcome ? labelTrue : labelFalse;

    return this.signOutcomes(announcement, [outcomeString]);
  }

  /**
   * Creates an attestation for an enum event
   */
  async attestEnum(
    announcement: EventAnnouncement,
    outcomeIndex: number
  ): Promise<EventAttestation> {
    const descriptor = this.requireAttestable(announcement, AttestationType.ENUM);

    if (outcomeIndex < 0 || outcomeIndex >= descriptor.outcomes.length) {
      throw new Error(`Invalid outcome index ${outcomeIndex}`);
    }

    const outcome = descriptor.outcomes[outcomeIndex];
    if (outcome === undefined) {
      throw new Error(`Invalid outcome index ${outcomeIndex}`);
    }
    return this.signOutcomes(announcement, [outcome]);
  }

  /**
   * The shared entry check of every attest* method: the announcement must be
   * of the expected type and carry a valid descriptor. It runs before any value
   * is scaled, any label is read, or any nonce is derived, so a malformed
   * descriptor cannot reach signing.
   */
  private requireAttestable<T extends AttestationType>(
    announcement: EventAnnouncement,
    expected: T
  ): Extract<EventDescriptor, { type: T }> {
    if (announcement.descriptor.type !== expected) {
      throw new Error(`Announcement is not ${expected} type`);
    }
    assertValidDescriptor(announcement.descriptor);
    return announcement.descriptor as Extract<EventDescriptor, { type: T }>;
  }

  /**
   * Signs outcome messages with the corresponding nonces
   *
   * Each signature covers the canonical v1 attestation message binding
   * (eventId, oraclePubkey, descriptorHash, maturityTime, outcome), and every
   * derived nonce is checked against / recorded in the used-nonce registry
   * before signing.
   */
  private async signOutcomes(
    announcement: EventAnnouncement,
    outcomes: string[]
  ): Promise<EventAttestation> {
    if (!this.oraclePrivateKey || !this.oraclePublicKey) {
      throw new Error("Attestation engine not initialized");
    }
    if (!announcement.oraclePublicKey.equals(this.oraclePublicKey)) {
      throw new Error("Announcement oracle key does not match this engine's key");
    }
    // The gate below reads announcement.maturityTime from the caller's object. That field is
    // only trustworthy if this engine's own signature over the canonical announcement (which
    // covers maturityTime) verifies, so the announcement is authenticated first. A caller-edited
    // announcement, for example with a past maturity, is refused before any nonce is derived.
    if (!isAuthenticAnnouncement(announcement, this.oraclePublicKey)) {
      throw new Error(
        `Refusing to attest event ${announcement.eventId}: the announcement is not signed by this engine's oracle key`
      );
    }
    // Maturity gate (every attest* path goes through here, before any nonce is
    // derived or recorded): signing an outcome before the event matures
    // discloses it early and consumes the nonce, so the wrong value could never
    // be corrected. verifyAttestation already refuses premature attestations;
    // the signer must refuse to create them.
    const now = Math.floor(Date.now() / 1000);
    if (isPremature(announcement.maturityTime, now, 0)) {
      throw new Error(
        `Refusing to attest event ${announcement.eventId}: maturity ${announcement.maturityTime} ` +
          `is in the future (now ${now})`
      );
    }
    if (!this.outcomesMatchDescriptor(announcement.descriptor, outcomes)) {
      throw new Error(
        `Outcomes [${outcomes.join(", ")}] do not match the announcement descriptor`
      );
    }

    const signatures: Buffer[] = [];

    for (let i = 0; i < outcomes.length; i++) {
      const outcome = outcomes[i];
      if (outcome === undefined) {
        throw new Error(`Missing outcome at index ${i}`);
      }
      const message = serializeAttestationMessage(
        announcement.eventId,
        this.oraclePublicKey,
        announcement.descriptor,
        announcement.maturityTime,
        outcome
      );
      const messageHash = hashAttestation(message);

      // Derive first (no side effects), then record (R, eventId, message) in the
      // registry, then sign. The record and the signature are separated by no
      // await, so no other event-loop callback (including a signal handler) can
      // run between a durable record and the signature it authorizes.
      const { k, R } = await this.deriveSigningNonce(announcement.eventId, i);
      // The signature must carry the nonce point announced for this index. Contracts pin
      // announcement.noncePoints[i], and the registry, keyed by R, can only keep the oracle key
      // safe for the nonce a second outcome would have to reuse. An engine whose nonce derivation
      // differs from the one that announced (another noncePurpose, key path or seed behind the
      // same oracle key) would otherwise sign under an unannounced R: an outcome no announced R
      // commits to, and a second outcome for the event that reveals nothing. Refused before
      // anything is recorded.
      const announcedR = announcement.noncePoints[i];
      if (!Buffer.isBuffer(announcedR) || !announcedR.equals(R)) {
        throw new Error(
          `Refusing to attest event ${announcement.eventId}: the nonce derived for index ${i} is not ` +
            `the announced nonce point`
        );
      }
      this.usedNonces.checkAndRecord(
        R.toString("hex"),
        announcement.eventId,
        messageHash.toString("hex")
      );
      signatures.push(schnorrSignWithNonce(this.oraclePrivateKey, messageHash, k));
    }

    return {
      eventId: announcement.eventId,
      oraclePublicKey: this.oraclePublicKey,
      outcomes,
      signatures,
      attestationTime: Math.floor(Date.now() / 1000),
    };
  }

  /**
   * Verifies an attestation against an announcement
   *
   * Fail-closed checks (C2):
   *  (a) a trusted oracle key must be pinned (config/explicit argument) and
   *      both announcement and attestation must carry exactly that key;
   *  (b) the announcement itself must carry a valid oracle signature over the
   *      canonical v1 announcement message;
   *  (c) every signature's R must equal the announcement's pre-committed
   *      nonce point for that position;
   *  (d) the outcome vector must match the descriptor's declared outcome set
   *      and nonce count;
   *  (e) attestations for events that have not matured yet (beyond a small
   *      clock skew) are rejected.
   */
  verifyAttestation(
    announcement: EventAnnouncement,
    attestation: EventAttestation,
    trustedOraclePublicKey?: Buffer | string
  ): boolean {
    try {
      // (a) Pin the oracle key: self-consistency between the two supplied
      // objects is NOT sufficient - both must equal the trusted key.
      let trusted: Buffer | undefined;
      if (trustedOraclePublicKey !== undefined) {
        trusted = parseOraclePublicKey(trustedOraclePublicKey);
        if (!trusted) {
          return false; // fail closed: malformed explicit key
        }
      } else {
        trusted = this.trustedOraclePublicKey;
      }
      if (!trusted) {
        return false; // fail closed: no trusted oracle key configured
      }
      if (!constantTimeEquals(announcement.oraclePublicKey, trusted)) {
        return false;
      }
      if (!constantTimeEquals(attestation.oraclePublicKey, trusted)) {
        return false;
      }

      // Event IDs must match, and the attestation must be for this event
      if (announcement.eventId !== attestation.eventId) {
        return false;
      }

      // The descriptor must be structurally valid (fail closed): a malformed
      // descriptor (e.g. numDigits: 0) would otherwise make
      // calculateNoncesNeeded return 0 and an EMPTY attestation verify true.
      if (!isValidDescriptor(announcement.descriptor)) {
        return false;
      }

      // Nonce points are x-only 32-byte values (explicit, in addition to the
      // announcement signature and the per-signature R equality check).
      if (announcement.noncePoints.some((p) => !Buffer.isBuffer(p) || p.length !== 32)) {
        return false;
      }

      // (b) The announcement must be signed by the pinned key over its canonical message
      if (!isAuthenticAnnouncement(announcement, trusted)) {
        return false;
      }

      // (e) Reject premature attestations (maturity beyond the clock-skew tolerance)
      const now = Math.floor(Date.now() / 1000);
      if (isPremature(announcement.maturityTime, now, MATURITY_SKEW_SECONDS)) {
        return false;
      }

      // (d) Outcome vector must match the descriptor (count + declared set)
      const noncesNeeded = this.calculateNoncesNeeded(announcement.descriptor);
      if (announcement.noncePoints.length !== noncesNeeded) {
        return false;
      }
      if (!hasDistinctNoncePoints(announcement.noncePoints)) {
        return false; // a repeated nonce point means a key-leaking announcement
      }
      if (
        attestation.outcomes.length !== noncesNeeded ||
        attestation.signatures.length !== noncesNeeded
      ) {
        return false;
      }
      if (!this.outcomesMatchDescriptor(announcement.descriptor, attestation.outcomes)) {
        return false;
      }

      // Verify each signature
      for (let i = 0; i < attestation.outcomes.length; i++) {
        const outcome = attestation.outcomes[i];
        const signature = attestation.signatures[i];
        const noncePoint = announcement.noncePoints[i];
        if (outcome === undefined || signature === undefined || noncePoint === undefined) {
          return false;
        }
        if (signature.length !== 64) {
          return false;
        }

        // (c) The signature's R must be the pre-committed nonce point
        if (!constantTimeEquals(signature.slice(0, 32), noncePoint)) {
          return false;
        }

        const messageHash = hashAttestation(
          serializeAttestationMessage(
            announcement.eventId,
            announcement.oraclePublicKey,
            announcement.descriptor,
            announcement.maturityTime,
            outcome
          )
        );
        const valid = schnorrVerify(trusted, messageHash, signature);
        if (!valid) {
          return false;
        }
      }

      return true;
    } catch (e) {
      // Malformed inputs must fail closed, not throw
      return false;
    }
  }

  /**
   * Releases the used-nonce registry's single-writer lock. The engine must not
   * sign after this. Shutdown paths should call it; a clean process exit and
   * SIGINT/SIGTERM release the lock too (see used-nonce-registry.ts, guarantee 7).
   */
  close(): void {
    this.usedNonces.close();
  }

  /**
   * Gets the oracle's public key
   */
  getPublicKey(): Buffer {
    if (!this.oraclePublicKey) {
      throw new Error("Attestation engine not initialized");
    }
    return this.oraclePublicKey;
  }

  /**
   * Engine objects reach logs through console.log, util.inspect, error
   * reporters and JSON serializers. The oracle private key (and the key
   * material behind keyProvider) must never appear in any of them, so each
   * view is redacted to the public key.
   */
  toJSON(): Record<string, unknown> {
    return redactedView(
      {
        network: this.network.name,
        keyProvider: this.keyProvider.getProviderType(),
        oraclePublicKey: this.oraclePublicKey ? this.oraclePublicKey.toString("hex") : null,
      },
      ["oraclePrivateKey"]
    );
  }

  [inspect.custom](): string {
    return inspectRedacted("AttestationEngine", this.toJSON());
  }
}
