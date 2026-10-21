/**
 * Round-2 regression tests, attestation engine (Ark-TradeLayer findings N6, N9, R2).
 *
 *  N6  attestBinary / attestEnum validate the descriptor like attestNumeric
 *  N9  numeric values are attested exactly, or refused
 *  R2  an empty eventId is refused on every path that hashes or announces it
 */
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import { BitcoinNetworks } from "bitcoin-networks";

import {
  AttestationEngine,
  AttestationType,
  scaleValueByPrecision,
} from "../src/attestation/attestation-engine";
import { MockKeyProvider } from "../src/keys/key-provider";
import { hashEventId } from "../src/crypto/tagged-hash";

const MNEMONIC = "test test test test test test test test test test test junk";
const MATURITY = 1767225600;

const NUMERIC_UNSIGNED = {
  type: AttestationType.NUMERIC,
  base: 10,
  numDigits: 4,
  unit: "USD",
  precision: 2,
  signed: false,
} as const;

jest.setTimeout(60_000);

function tmpRegistry(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "r2-attest-"));
  return path.join(dir, "used-nonces.json");
}

async function makeEngine(registryPath: string): Promise<AttestationEngine> {
  const engine = new AttestationEngine({
    network: BitcoinNetworks.bitcoin_regtest,
    keyProvider: new MockKeyProvider(MNEMONIC),
    usedNonceRegistryPath: registryPath,
    usedNonceRegistryInit: true,
    developmentMode: true,
  });
  await engine.initialize();
  return engine;
}

describe("N6: every attest* method validates the descriptor", () => {
  it("attestBinary and attestEnum refuse malformed descriptors before any nonce is recorded", async () => {
    const registryPath = tmpRegistry();
    const engine = await makeEngine(registryPath);

    const binary = await engine.createAnnouncement(
      "binary-event",
      { type: AttestationType.BINARY, outcomes: ["yes", "no"] },
      MATURITY
    );
    const forgedBinary = {
      ...binary,
      descriptor: { type: AttestationType.BINARY, outcomes: ["yes\u0001", "no"] },
    } as any;
    await expect(engine.attestBinary(forgedBinary, true)).rejects.toThrow(
      /Invalid event descriptor/
    );

    const enumAnn = await engine.createAnnouncement(
      "enum-event",
      { type: AttestationType.ENUM, outcomes: ["a", "b"] },
      MATURITY
    );
    const forgedEnum = {
      ...enumAnn,
      descriptor: { type: AttestationType.ENUM, outcomes: ["a", "a"] },
    } as any;
    await expect(engine.attestEnum(forgedEnum, 0)).rejects.toThrow(/Invalid event descriptor/);

    // Nothing was recorded, so nothing was signed.
    expect((engine as any).usedNonces.size).toBe(0);
    (engine as any).usedNonces.close();
  });
});

describe("N9: exact value scaling", () => {
  it("a JS number beyond MAX_SAFE_INTEGER is refused; the exact string form attests exactly", async () => {
    expect(() => scaleValueByPrecision(123456789012345678, 0)).toThrow(/MAX_SAFE_INTEGER/);
    expect(scaleValueByPrecision("123456789012345678", 0)).toBe(123456789012345678n);
    expect(scaleValueByPrecision("1.5", 2)).toBe(150n);
    expect(scaleValueByPrecision(12345678901234567890n, 0)).toBe(12345678901234567890n);

    // Pathological exponents are refused before any BigInt work
    expect(() => scaleValueByPrecision("1e100000000", 0)).toThrow(/exponent out of range/);

    const registryPath = tmpRegistry();
    const engine = await makeEngine(registryPath);
    const announcement = await engine.createAnnouncement(
      "big-event",
      { ...NUMERIC_UNSIGNED, numDigits: 18, precision: 0 },
      MATURITY
    );
    await expect(
      engine.attestNumeric(announcement, 123456789012345678 as unknown as number)
    ).rejects.toThrow(/MAX_SAFE_INTEGER/);
    const attestation = await engine.attestNumeric(announcement, "123456789012345678");
    expect(attestation.outcomes).toEqual("123456789012345678".split(""));
    (engine as any).usedNonces.close();
  });
});

describe("R2: an empty eventId is refused on every path", () => {
  it("hashEventId and createAnnouncement both refuse the empty eventId", async () => {
    expect(() => hashEventId("")).toThrow(/eventId must be a 1..255/);
    const engine = await makeEngine(tmpRegistry());
    await expect(engine.createAnnouncement("", NUMERIC_UNSIGNED, MATURITY)).rejects.toThrow(
      /eventId/
    );
    (engine as any).usedNonces.close();
  });
});
