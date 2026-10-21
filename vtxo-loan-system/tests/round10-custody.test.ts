/**
 * Round-10 regression tests, maturity gate (Clone B, regression review).
 *
 *  B1  a caller-edited announcement cannot pass the maturity gate: the gate reads
 *      maturityTime from the object passed in, so the object must carry this engine's
 *      signature over the canonical message (which covers maturityTime) before any
 *      signing. Before this round a past maturity on a forged copy was signed, which
 *      disclosed the outcome early and consumed the event's nonce.
 *  B2  a forged announcement with a zero, NaN or unsafe maturity is refused the same way.
 */
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import { BitcoinNetworks } from "bitcoin-networks";

import {
  AttestationEngine,
  AttestationType,
} from "../src/attestation/attestation-engine";
import { MockKeyProvider } from "../src/keys/key-provider";

const MNEMONIC = "test test test test test test test test test test test junk";
const PAST_MATURITY = 1767225600;

jest.setTimeout(120_000);

function tmpRegistry(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "r10-custody-"));
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

const BINARY = { type: AttestationType.BINARY, outcomes: ["yes", "no"] } as const;

describe("R10-B1: a forged announcement cannot pass the maturity gate", () => {
  it("an announcement edited to a past maturity is refused and records no nonce", async () => {
    const engine = await makeEngine(tmpRegistry());
    const future = Math.floor(Date.now() / 1000) + 86_400;
    const real = await engine.createAnnouncement("r10-forged-past", BINARY, future);
    const forged = { ...real, maturityTime: PAST_MATURITY };
    const usedBefore = (engine as any).usedNonces.size;

    await expect(engine.attestBinary(forged, true)).rejects.toThrow(/not signed by this engine/);
    expect((engine as any).usedNonces.size).toBe(usedBefore);

    // The real announcement is still refused for its real (future) maturity, not for the forgery.
    await expect(engine.attestBinary(real, true)).rejects.toThrow(/in the future/);
    engine.close();
  });
});

describe("R10-B2: malformed maturity values on a forged announcement are refused", () => {
  it("zero, NaN and unsafe maturities are refused before any nonce is recorded", async () => {
    const engine = await makeEngine(tmpRegistry());
    const future = Math.floor(Date.now() / 1000) + 86_400;
    const real = await engine.createAnnouncement("r10-forged-malformed", BINARY, future);
    const usedBefore = (engine as any).usedNonces.size;

    for (const maturityTime of [0, Number.NaN, 2 ** 60, -1]) {
      const forged = { ...real, maturityTime };
      await expect(engine.attestBinary(forged, false)).rejects.toThrow(/not signed by this engine/);
    }
    expect((engine as any).usedNonces.size).toBe(usedBefore);
    engine.close();
  });
});
