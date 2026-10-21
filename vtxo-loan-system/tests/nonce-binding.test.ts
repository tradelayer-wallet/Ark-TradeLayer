/**
 * An attestation's nonce point is the announced one, at the signer and at the contracts:
 *  - the signer refuses to sign under a nonce it did not announce: an engine with the same oracle key but another
 *    nonce derivation (here another noncePurpose) cannot attest the first engine's announcement, and records nothing;
 *  - the .ark matcher accepts an attestation only with the pinned announced R. A second outcome signed by the same
 *    oracle key under a fresh nonce passes checkSchnorrSig alone, and is refused by the R pin.
 */
import { BitcoinNetworks } from "bitcoin-networks";

import { AttestationEngine, AttestationType, hashDescriptor } from "../src/attestation/attestation-engine";
import { schnorrSign } from "../src/crypto/bitcoin-primitives";
import { hashAttestation, hashEventId } from "../src/crypto/tagged-hash";
import { serializeAttestationMessage } from "../src/attestation/attestation-engine";
import { MockKeyProvider } from "../src/keys/key-provider";

const ark = require("./support/ark-matcher-emulation");
const cfdjs = require("./shims/cfd-js.js");

const MNEMONIC = "test test test test test test test test test test test junk";
const BINARY = { type: AttestationType.BINARY, outcomes: ["paid", "unpaid"] } as const;

async function engineWith(noncePurpose: number): Promise<AttestationEngine> {
  const engine = new AttestationEngine({
    network: BitcoinNetworks.bitcoin_regtest,
    keyProvider: new MockKeyProvider(MNEMONIC),
    noncePurpose,
    usedNonceRegistryPath: null,
    developmentMode: true,
  });
  await engine.initialize();
  return engine;
}

const schnorrVerify = (pubkey: string, message: string, signature: string): boolean =>
  cfdjs.SchnorrVerify({ pubkey, message, signature }).valid;

describe("the attestation nonce is the announced nonce point", () => {
  it("the signer refuses an announcement whose nonce point it does not derive, before recording anything", async () => {
    const announcer = await engineWith(585);
    const drifted = await engineWith(586);
    expect(drifted.getPublicKey().equals(announcer.getPublicKey())).toBe(true);
    const past = Math.floor(Date.now() / 1000) - 5;
    const announcement = await announcer.createAnnouncement("loan-r-binding", BINARY, past);

    const recorded: unknown[] = [];
    const registry = (drifted as any).usedNonces;
    const realRecord = registry.checkAndRecord.bind(registry);
    registry.checkAndRecord = (...args: unknown[]) => {
      recorded.push(args);
      return realRecord(...args);
    };
    await expect(drifted.attestBinary(announcement, true)).rejects.toThrow(/not the announced nonce point/);
    expect(recorded).toEqual([]);

    const attestation = await announcer.attestBinary(announcement, true);
    expect(attestation.signatures[0]!.subarray(0, 32).equals(announcement.noncePoints[0]!)).toBe(true);
  });

  it("the .ark matcher accepts only the announced R: a second outcome under a fresh nonce is refused", async () => {
    const engine = await engineWith(585);
    const past = Math.floor(Date.now() / 1000) - 5;
    const announcement = await engine.createAnnouncement("loan-r-binding-matcher", BINARY, past);
    const attestation = await engine.attestBinary(announcement, true);
    const oracleKeyXonly: Buffer = engine.getPublicKey();
    const pinned = (outcome: string) => ({
      eventIdHash: hashEventId(announcement.eventId),
      oracleKeyXonly,
      descriptorHash: hashDescriptor(announcement.descriptor),
      maturityTime: announcement.maturityTime,
      outcome: Buffer.from(outcome, "utf8"),
      nonceR: announcement.noncePoints[0]!,
    });
    const blobFor = (outcome: string, signature: Buffer) => {
      const fields = pinned(outcome);
      return ark.arkAttestationBlob(fields, signature);
    };

    // The honest attestation, under the announced R.
    expect(ark.arkVerifyOracleAttestation(blobFor("paid", attestation.signatures[0]!), pinned("paid"), schnorrVerify)).toBe(true);

    // The same oracle key signs the other outcome under a fresh nonce: a valid BIP-340 signature by the oracle over
    // the contract's message, which checkSchnorrSig alone accepts, but not under the announced R.
    const oraclePrivateKey: Buffer = (engine as any).oraclePrivateKey;
    const unpaidHash = hashAttestation(
      serializeAttestationMessage(announcement.eventId, oracleKeyXonly, announcement.descriptor, announcement.maturityTime, "unpaid")
    );
    const freshNonceSignature = schnorrSign(oraclePrivateKey, unpaidHash);
    expect(schnorrVerify(oracleKeyXonly.toString("hex"), unpaidHash.toString("hex"), freshNonceSignature.toString("hex"))).toBe(true);
    expect(freshNonceSignature.subarray(0, 32).equals(announcement.noncePoints[0]!)).toBe(false);
    expect(ark.arkVerifyOracleAttestation(blobFor("unpaid", freshNonceSignature), pinned("unpaid"), schnorrVerify)).toBe(false);

    // And the honest signature does not count for a contract that pinned some other R.
    const otherR = Buffer.from(announcement.noncePoints[0]!);
    otherR[31] ^= 1;
    expect(ark.arkVerifyOracleAttestation(blobFor("paid", attestation.signatures[0]!), { ...pinned("paid"), nonceR: otherR }, schnorrVerify)).toBe(false);
  });
});
