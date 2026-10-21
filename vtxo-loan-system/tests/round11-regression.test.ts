/**
 * Round-11 regression tests (review of the round-10 tree):
 *
 *  R11-1  the nonce registry path is never implied by the working directory
 *  R11-2  numeric configuration is parsed strictly, never truncated or NaN
 *  R11-3  a malformed pinned oracle key is refused at construction
 *  R11-4  the anchor is single-link checked on every commit, like the log
 *  R11-5  a witness that would decide without evidence is refused
 *  R11-6  the insecure API_AUTH_KEY placeholder is refused in any spelling
 */
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import { BitcoinNetworks } from "bitcoin-networks";

import {
  AttestationEngine,
  AttestationType,
} from "../src/attestation/attestation-engine";
import {
  NonceRegistryLockError,
  UsedNonceRegistry,
} from "../src/attestation/used-nonce-registry";
import {
  DEFAULT_API_AUTH_KEY,
  apiAuthKeyViolation,
  loadConfigFromEnv,
} from "../src/config/system-config";
import { MockKeyProvider } from "../src/keys/key-provider";
import { BlockchainClient, CompositeWitness, PaymentWitness } from "../src/witness/event-witness";

const MNEMONIC = "test test test test test test test test test test test junk";

jest.setTimeout(60_000);

function tmpDir(prefix: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

const BINARY = { type: AttestationType.BINARY, outcomes: ["yes", "no"] } as const;

describe("R11-1: the nonce registry path is never implied by the working directory", () => {
  it("an engine without usedNonceRegistryPath is refused, in every mode", () => {
    const previous = process.cwd();
    const scratch = tmpDir("r11-cwd-");
    process.chdir(scratch);
    try {
      const keyProvider = new MockKeyProvider(MNEMONIC);
      expect(() =>
        new AttestationEngine({ network: BitcoinNetworks.bitcoin_regtest, keyProvider } as any)
      ).toThrow(/usedNonceRegistryPath is required/);
      expect(() =>
        new AttestationEngine({
          network: BitcoinNetworks.bitcoin_regtest,
          keyProvider,
          developmentMode: true,
        } as any)
      ).toThrow(/usedNonceRegistryPath is required/);
      expect(fs.existsSync(path.join(scratch, "data"))).toBe(false);
    } finally {
      process.chdir(previous);
    }
  });

  it("a registry without a path is refused rather than opened in the working directory", () => {
    const previous = process.cwd();
    const scratch = tmpDir("r11-cwd-registry-");
    process.chdir(scratch);
    try {
      expect(() => new UsedNonceRegistry({} as any)).toThrow(NonceRegistryLockError);
      expect(fs.existsSync(path.join(scratch, "data"))).toBe(false);
    } finally {
      process.chdir(previous);
    }
  });
});

describe("R11-2: numeric configuration is parsed strictly", () => {
  const KEYS = [
    "MIN_CONTRACT_VALUE",
    "VTXO_EXIT_DELAY",
    "PUBLIC_API_PORT",
    "REDIS_PORT",
    "PRICE_CHECK_INTERVAL",
  ];
  let saved: Record<string, string | undefined> = {};

  beforeEach(() => {
    saved = {};
    for (const key of KEYS) {
      saved[key] = process.env[key];
      delete process.env[key];
    }
  });

  afterEach(() => {
    for (const key of KEYS) {
      if (saved[key] === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = saved[key];
      }
    }
  });

  it("scientific notation is refused, not read as its leading digit", () => {
    process.env.MIN_CONTRACT_VALUE = "1e4";
    expect(() => loadConfigFromEnv()).toThrow(/MIN_CONTRACT_VALUE/);
  });

  it("trailing garbage is refused, not dropped", () => {
    process.env.VTXO_EXIT_DELAY = "1008abc";
    expect(() => loadConfigFromEnv()).toThrow(/VTXO_EXIT_DELAY/);
  });

  it("non-numeric and negative values are refused", () => {
    process.env.PUBLIC_API_PORT = "abc";
    expect(() => loadConfigFromEnv()).toThrow(/PUBLIC_API_PORT/);
    process.env.PUBLIC_API_PORT = "-1";
    expect(() => loadConfigFromEnv()).toThrow(/PUBLIC_API_PORT/);
  });

  it("values beyond the safe integer range are refused", () => {
    process.env.REDIS_PORT = "99999999999999999999";
    expect(() => loadConfigFromEnv()).toThrow(/REDIS_PORT/);
  });

  it("plain decimal values (with surrounding whitespace) and defaults still load", () => {
    process.env.MIN_CONTRACT_VALUE = " 25000 ";
    process.env.PRICE_CHECK_INTERVAL = "7";
    const config = loadConfigFromEnv();
    expect(config.vtxo.minContractValue).toBe(25000);
    expect(config.scheduler.priceCheckInterval).toBe(7);
    expect(config.vtxo.defaultExitDelay).toBe(1008);
  });
});

describe("R11-3: a malformed pinned oracle key is refused at construction", () => {
  it("a compressed or non-hex trusted key throws instead of pinning nothing", () => {
    const registryPath = path.join(tmpDir("r11-key-"), "used-nonces.json");
    const keyProvider = new MockKeyProvider(MNEMONIC);
    const base = {
      network: BitcoinNetworks.bitcoin_regtest,
      keyProvider,
      usedNonceRegistryPath: registryPath,
      usedNonceRegistryInit: true,
      developmentMode: true,
    };
    expect(
      () => new AttestationEngine({ ...base, trustedOraclePublicKey: `02${"ab".repeat(32)}` })
    ).toThrow(/trustedOraclePublicKey/);
    expect(() => new AttestationEngine({ ...base, trustedOraclePublicKey: "xyz" })).toThrow(
      /trustedOraclePublicKey/
    );
    expect(fs.existsSync(`${registryPath}.lock`)).toBe(false);
  });

  it("a valid 32-byte key, as a Buffer or as 64 hex characters, is accepted", () => {
    const keyProvider = new MockKeyProvider(MNEMONIC);
    const dir = tmpDir("r11-key-ok-");
    const base = { network: BitcoinNetworks.bitcoin_regtest, keyProvider, developmentMode: true };
    const asBuffer = new AttestationEngine({
      ...base,
      usedNonceRegistryPath: path.join(dir, "a.json"),
      usedNonceRegistryInit: true,
      trustedOraclePublicKey: Buffer.alloc(32, 7),
    });
    const asHex = new AttestationEngine({
      ...base,
      usedNonceRegistryPath: path.join(dir, "b.json"),
      usedNonceRegistryInit: true,
      trustedOraclePublicKey: "07".repeat(32),
    });
    asBuffer.close();
    asHex.close();
  });
});

describe("R11-4: the anchor is single-link checked on every commit", () => {
  it("a hard link to the anchor refuses the commit: nothing is signed", () => {
    const registryPath = path.join(tmpDir("r11-anchor-"), "used-nonces.json");
    const anchorPath = `${registryPath}.anchor`;
    const registry = new UsedNonceRegistry({ persistPath: registryPath, initialize: true });
    registry.checkAndRecord("11".repeat(32), "event-1", "aa".repeat(32));

    const alias = `${anchorPath}.alias`;
    fs.linkSync(anchorPath, alias);
    try {
      expect(() => registry.checkAndRecord("22".repeat(32), "event-2", "bb".repeat(32))).toThrow(
        /must be a regular file with exactly one hard link/
      );
    } finally {
      fs.unlinkSync(alias);
    }
    registry.close();
  });
});

describe("R11-5: witnesses that cannot decide are refused", () => {
  const blockchain: BlockchainClient = { getTransfers: async () => [] };

  it("a composite witness with no members is refused (it would report satisfied)", () => {
    expect(() => new CompositeWitness([], "and")).toThrow(/at least one witness/);
    expect(() => new CompositeWitness([], "or")).toThrow(/at least one witness/);
  });

  it("a payment witness with a zero or non-finite expected amount is refused", () => {
    const base = {
      network: "bitcoin",
      recipientAddress: "bc1qexample",
      asset: "BTC",
      fromBlock: 0,
    };
    expect(() => new PaymentWitness({ ...base, expectedAmount: 0 }, blockchain)).toThrow(
      /expectedAmount must be a positive number/
    );
    expect(() => new PaymentWitness({ ...base, expectedAmount: Number.NaN }, blockchain)).toThrow(
      /expectedAmount must be a positive number/
    );
  });

});

describe("R11-6: the insecure API_AUTH_KEY placeholder is refused in any spelling", () => {
  it("the placeholder with surrounding or inner whitespace is still the insecure default", () => {
    expect(apiAuthKeyViolation(DEFAULT_API_AUTH_KEY)).toMatch(/insecure default/);
    expect(apiAuthKeyViolation(`${DEFAULT_API_AUTH_KEY} `)).toMatch(/insecure default/);
    expect(apiAuthKeyViolation(` ${DEFAULT_API_AUTH_KEY}\n`)).toMatch(/insecure default/);
    expect(apiAuthKeyViolation("dev-key-insecure\t")).toMatch(/insecure default/);
  });

  it("the placeholder in another letter case is still the insecure default", () => {
    expect(apiAuthKeyViolation("DEV-KEY-INSECURE")).toMatch(/insecure default/);
  });

  it("a different key that merely contains the placeholder is not refused as the default", () => {
    expect(apiAuthKeyViolation("dev-key-insecure-but-longer")).toBeNull();
  });
});
