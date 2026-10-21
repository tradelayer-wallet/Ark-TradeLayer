/**
 * Round-13 regression tests (review of the round-12 tree):
 *
 *  R13-1  a relative nonce registry path is refused, so the registry cannot
 *         depend on the working directory of the process
 *  R13-2  a port setting outside 1-65535 is refused when the config loads
 *  R13-3  the configuration carries the registry path, so the documented
 *         startup flow (config -> engine) works and needs an absolute path
 *  R13-4  each key holder redacts its real secret fields, under their real names
 */
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import { BitcoinNetworks } from "bitcoin-networks";

import { AttestationEngine } from "../src/attestation/attestation-engine";
import { UsedNonceRegistry } from "../src/attestation/used-nonce-registry";
import { inspect } from "util";
import * as util from "util";

import { CloudKeyProvider, LocalKeyProvider, MockKeyProvider } from "../src/keys/key-provider";
import { loadConfig, loadConfigFromEnv } from "../src/config/system-config";

const MNEMONIC = "test test test test test test test test test test test junk";

jest.setTimeout(60_000);

function tmpDir(prefix: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

describe("R13-1: a relative nonce registry path is refused", () => {
  it("the registry refuses a relative path and creates nothing in the working directory", () => {
    const previous = process.cwd();
    const scratch = tmpDir("r13-relative-");
    process.chdir(scratch);
    try {
      expect(() => new UsedNonceRegistry({ persistPath: "data/used-nonces.json", initialize: true })).toThrow(
        /absolute/
      );
      expect(fs.existsSync(path.join(scratch, "data"))).toBe(false);
    } finally {
      process.chdir(previous);
    }
  });

  it("the engine refuses a relative usedNonceRegistryPath at construction", () => {
    const previous = process.cwd();
    const scratch = tmpDir("r13-relative-engine-");
    process.chdir(scratch);
    try {
      expect(
        () =>
          new AttestationEngine({
            network: BitcoinNetworks.bitcoin_regtest,
            keyProvider: new MockKeyProvider(MNEMONIC),
            usedNonceRegistryPath: "data/used-nonces.json",
            usedNonceRegistryInit: true,
            developmentMode: true,
          })
      ).toThrow(/absolute/);
      expect(fs.existsSync(path.join(scratch, "data"))).toBe(false);
    } finally {
      process.chdir(previous);
    }
  });

  it("an absolute path is accepted, and the same file is found from another directory", () => {
    const registryPath = path.join(tmpDir("r13-absolute-"), "data", "used-nonces.json");
    const previous = process.cwd();
    const first = new UsedNonceRegistry({ persistPath: registryPath, initialize: true });
    first.checkAndRecord("11".repeat(32), "event-1", "aa".repeat(32));
    first.close();

    process.chdir(os.tmpdir());
    try {
      const restarted = new UsedNonceRegistry({ persistPath: registryPath, initialize: true });
      expect(() =>
        restarted.checkAndRecord("11".repeat(32), "event-1", "bb".repeat(32))
      ).toThrow(/nonce/i);
      restarted.close();
    } finally {
      process.chdir(previous);
    }
  });
});

describe("R13-2: port settings are refused outside 1-65535 when the config loads", () => {
  const KEYS = ["PUBLIC_API_PORT", "INTERNAL_API_PORT", "REDIS_PORT"];
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

  /** Loads the config with exactly these port settings in the environment */
  function loadWith(ports: Record<string, string>) {
    for (const key of KEYS) {
      delete process.env[key];
    }
    Object.assign(process.env, ports);
    return loadConfigFromEnv();
  }

  it("a port above 65535 is refused, not found at listen time", () => {
    expect(() => loadWith({ PUBLIC_API_PORT: "99999" })).toThrow(/PUBLIC_API_PORT/);
    expect(() => loadWith({ PUBLIC_API_PORT: "65536" })).toThrow(/PUBLIC_API_PORT/);
    expect(() => loadWith({ INTERNAL_API_PORT: "70000" })).toThrow(/INTERNAL_API_PORT/);
    expect(() => loadWith({ REDIS_PORT: "99999" })).toThrow(/REDIS_PORT/);
  });

  it("port 0 is refused for every port setting", () => {
    expect(() => loadWith({ PUBLIC_API_PORT: "0" })).toThrow(/PUBLIC_API_PORT/);
    expect(() => loadWith({ INTERNAL_API_PORT: "0" })).toThrow(/INTERNAL_API_PORT/);
    expect(() => loadWith({ REDIS_PORT: "0" })).toThrow(/REDIS_PORT/);
  });

  it("the bounds 1 and 65535 are accepted", () => {
    const config = loadWith({ PUBLIC_API_PORT: "1", INTERNAL_API_PORT: "65535", REDIS_PORT: " 6380 " });
    expect(config.api.publicPort).toBe(1);
    expect(config.api.internalPort).toBe(65535);
    expect(config.redis.port).toBe(6380);
  });
});

describe("R13-3: the configuration carries the nonce registry path", () => {
  const KEYS = [
    "NETWORK",
    "ORACLE_MODE",
    "KEY_PROVIDER",
    "USED_NONCE_REGISTRY_PATH",
    "USED_NONCE_REGISTRY_INIT",
  ];
  let saved: Record<string, string | undefined> = {};

  beforeEach(() => {
    saved = {};
    for (const key of KEYS) {
      saved[key] = process.env[key];
      delete process.env[key];
    }
    process.env.NETWORK = "regtest";
    process.env.ORACLE_MODE = "development";
    process.env.KEY_PROVIDER = "mock";
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

  it("USED_NONCE_REGISTRY_PATH is read into the configuration", () => {
    const registryPath = path.join(tmpDir("r13-config-"), "used-nonces.json");
    process.env.USED_NONCE_REGISTRY_PATH = registryPath;
    expect(loadConfigFromEnv().usedNonceRegistryPath).toBe(registryPath);
  });

  it("loading refuses a missing or relative registry path", () => {
    expect(() => loadConfig()).toThrow(/USED_NONCE_REGISTRY_PATH must be an absolute path/);
    process.env.USED_NONCE_REGISTRY_PATH = "data/used-nonces.json";
    expect(() => loadConfig()).toThrow(/USED_NONCE_REGISTRY_PATH must be an absolute path/);
  });

  it("the documented startup flow (config, then engine) opens the configured registry", () => {
    const registryPath = path.join(tmpDir("r13-startup-"), "used-nonces.json");
    process.env.USED_NONCE_REGISTRY_PATH = registryPath;
    process.env.USED_NONCE_REGISTRY_INIT = "1";
    const config = loadConfig();
    const engine = new AttestationEngine({
      network: BitcoinNetworks.bitcoin_regtest,
      keyProvider: new MockKeyProvider(MNEMONIC),
      usedNonceRegistryPath: config.usedNonceRegistryPath,
      usedNonceRegistryInit: config.usedNonceRegistryInit,
      developmentMode: true,
    });
    // The engine holds the writer lock of the configured registry.
    expect(() => new UsedNonceRegistry({ persistPath: registryPath })).toThrow(/locked/);
    engine.close();
  });
});

describe("R13-4: redaction names the real secret fields", () => {
  const CLOUD = { type: "cloud" as const, provider: "gcp" as const, projectId: "p", secretId: "s" };

  /** The printed forms a secret could leak through: inspect, JSON, and util.format */
  function printedForms(holder: object): string[] {
    return [
      inspect(holder),
      inspect(holder, { showHidden: true, depth: 6 }),
      JSON.stringify(holder),
      util.format("%o", holder),
      util.format("%O", holder),
      util.format("%s", holder),
    ];
  }

  /** Each secret, as the hex and spaced-byte forms util.inspect may print */
  function secretSpellings(hex: string): string[] {
    return [hex, hex.match(/../g)!.join(" ")];
  }

  it("the local, cloud and mock providers hide their root keys and seed", () => {
    const local = new LocalKeyProvider(MNEMONIC);
    const rootHex = (local as any).root.privateKey.toString("hex") as string;

    const cloud = new CloudKeyProvider(CLOUD);
    (cloud as any).cachedRoot = (local as any).root;

    const mock = new MockKeyProvider(MNEMONIC);
    const mockRootHex = (mock as any).root.privateKey.toString("hex") as string;
    const mockSeed = (mock as any).seed as string;

    for (const text of printedForms(local)) {
      for (const secret of secretSpellings(rootHex)) expect(text.includes(secret)).toBe(false);
    }
    expect(JSON.parse(JSON.stringify(local))).toEqual({
      keyProvider: "local",
      root: "[REDACTED]",
    });

    for (const text of printedForms(cloud)) {
      for (const secret of secretSpellings(rootHex)) expect(text.includes(secret)).toBe(false);
    }
    expect(JSON.parse(JSON.stringify(cloud))).toEqual({
      keyProvider: "cloud-gcp",
      cachedRoot: "[REDACTED]",
    });

    for (const text of printedForms(mock)) {
      expect(text.includes(mockSeed)).toBe(false);
      for (const secret of secretSpellings(mockRootHex)) expect(text.includes(secret)).toBe(false);
    }
    expect(JSON.parse(JSON.stringify(mock))).toEqual({
      keyProvider: "mock",
      root: "[REDACTED]",
      seed: "[REDACTED]",
    });
  });

  it("the engine hides its oracle private key under its real field name", async () => {
    const registryPath = path.join(tmpDir("r13-redact-"), "used-nonces.json");
    const engine = new AttestationEngine({
      network: BitcoinNetworks.bitcoin_regtest,
      keyProvider: new MockKeyProvider(MNEMONIC),
      usedNonceRegistryPath: registryPath,
      usedNonceRegistryInit: true,
      developmentMode: true,
    });
    try {
      await engine.initialize();
      const oracleHex = (engine as any).oraclePrivateKey.toString("hex") as string;
      for (const text of printedForms(engine)) {
        for (const secret of secretSpellings(oracleHex)) expect(text.includes(secret)).toBe(false);
      }
      expect(JSON.parse(JSON.stringify(engine))).toMatchObject({
        oraclePrivateKey: "[REDACTED]",
      });
    } finally {
      engine.close();
    }
  });
});
