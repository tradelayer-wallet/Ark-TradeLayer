/**
 * Round-11 characterization tests. They pin the current behaviour of every
 * caller of the rules that round 11 unifies, before anything is collapsed:
 *
 *  C1  configuration defaults and the error text of the enum/key checks
 *  C2  redaction: the exact toJSON / util.inspect output of every key holder
 *  C3  announcement authentication and the maturity gate: refusal texts
 *  C4  used-nonce registry file formats (log and anchor) and the chain digest
 *  C5  event-id and descriptor boundaries shared by the registry and the engine
 */
import * as crypto from "crypto";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { inspect } from "util";

import { BitcoinNetworks } from "bitcoin-networks";

import {
  AttestationEngine,
  AttestationType,
  EventAnnouncement,
  isValidDescriptor,
} from "../src/attestation/attestation-engine";
import { UsedNonceRegistry } from "../src/attestation/used-nonce-registry";
import { hashEventId } from "../src/crypto/tagged-hash";
import {
  CloudKeyProvider,
  LocalKeyProvider,
  MockKeyProvider,
} from "../src/keys/key-provider";
import {
  DEFAULT_API_AUTH_KEY,
  loadConfigFromEnv,
  validateConfig,
} from "../src/config/system-config";

const MNEMONIC = "test test test test test test test test test test test junk";
const MATURITY = Math.floor(Date.now() / 1000) - 3600;
const FUTURE = Math.floor(Date.now() / 1000) + 86_400;

jest.setTimeout(120_000);

function tmpDir(prefix: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function tmpRegistry(): string {
  return path.join(tmpDir("r11-char-"), "used-nonces.json");
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

function sha256Hex(text: string): string {
  return crypto.createHash("sha256").update(text, "utf8").digest("hex");
}

describe("C1: configuration defaults", () => {
  const KEYS = [
    "NETWORK", "ORACLE_MODE", "KEY_PROVIDER", "MNEMONIC", "CLOUD_PROJECT_ID", "CLOUD_SECRET_ID",
    "ALLOW_LOCAL_KEYS", "MONGODB_URI", "MONGODB_DATABASE", "MONGODB_POOL_SIZE", "REDIS_HOST",
    "REDIS_PORT", "REDIS_PASSWORD", "REDIS_DB", "COINGECKO_API_KEY", "COINBASE_API_KEY",
    "PRICE_FEED_SOURCES", "ETHEREUM_ENABLED", "BITCOIN_RPC_URL", "PUBLIC_API_PORT",
    "INTERNAL_API_PORT", "API_AUTH_KEY", "CORS_ENABLED", "CORS_ORIGINS", "LOG_LEVEL",
    "PRICE_CHECK_INTERVAL", "PAYMENT_CHECK_INTERVAL", "ANNOUNCEMENT_LOOKAHEAD",
    "VTXO_EXIT_DELAY", "VTXO_SERVER_PUBKEY", "MIN_CONTRACT_VALUE",
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

  it("an empty environment yields the documented development defaults", () => {
    const config = loadConfigFromEnv();
    expect(config.network).toBe("regtest");
    expect(config.mode).toBe("development");
    expect(config.keys).toEqual({
      provider: "mock",
      mnemonic: undefined,
      projectId: undefined,
      secretId: "oracle-mnemonic",
      allowLocalKeys: false,
    });
    expect(config.database).toEqual({
      uri: "mongodb://localhost:27017",
      database: "vtxo-loans",
      poolSize: 10,
    });
    expect(config.redis).toEqual({ host: "127.0.0.1", port: 6379, password: undefined, db: 0 });
    expect(config.api.publicPort).toBe(3000);
    expect(config.api.internalPort).toBe(3001);
    expect(config.api.authKey).toBe(DEFAULT_API_AUTH_KEY);
    expect(config.api.cors).toEqual({ enabled: true, origins: ["*"] });
    expect(config.monitoring.logLevel).toBe("info");
    expect(config.scheduler).toEqual({
      priceCheckInterval: 5,
      paymentCheckInterval: 2,
      announcementLookahead: 13,
    });
    expect(config.vtxo).toEqual({
      defaultExitDelay: 1008,
      serverPublicKey: "",
      minContractValue: 10000,
    });
    expect(config.externalData.priceFeeds.enabled).toEqual(["coingecko", "coinbase", "kraken"]);
    expect(config.externalData.blockchainClients.ethereum).toBeUndefined();
    expect(config.externalData.blockchainClients.bitcoin).toBeUndefined();
  });

  it("ALLOW_LOCAL_KEYS is an exact opt-in and ETHEREUM_ENABLED an exact switch", () => {
    process.env.ALLOW_LOCAL_KEYS = "true";
    process.env.ETHEREUM_ENABLED = "1";
    const config = loadConfigFromEnv();
    expect(config.keys.allowLocalKeys).toBe(false);
    expect(config.externalData.blockchainClients.ethereum).toBeUndefined();
  });

  it("the enum checks name the variable and the allowed values", () => {
    const base = loadConfigFromEnv();
    expect(() => validateConfig({ ...base, keys: { ...base.keys, provider: "hsm" } })).toThrow(
      /Unrecognized KEY_PROVIDER "hsm"; allowed values: local, gcp, aws, mock/
    );
    expect(() => validateConfig({ ...base, network: "moonnet" as any })).toThrow(
      /Unrecognized network "moonnet"; allowed values: mainnet, testnet, regtest, signet/
    );
    expect(() => validateConfig({ ...base, mode: "prod" as any })).toThrow(
      /Unrecognized mode "prod"; allowed values: development, staging, production/
    );
  });
});

describe("C2: redaction output of every key holder", () => {
  it("the key providers print only their type and a redaction marker", () => {
    const local = new LocalKeyProvider(MNEMONIC);
    const cloud = new CloudKeyProvider({ type: "cloud", provider: "gcp", projectId: "p", secretId: "s" });
    const mock = new MockKeyProvider(MNEMONIC);

    expect(JSON.stringify(local)).toBe('{"keyProvider":"local","root":"[REDACTED]"}');
    expect(JSON.stringify(cloud)).toBe('{"keyProvider":"cloud-gcp","cachedRoot":"[REDACTED]"}');
    expect(JSON.stringify(mock)).toBe('{"keyProvider":"mock","root":"[REDACTED]","seed":"[REDACTED]"}');

    expect(inspect(local)).toBe('LocalKeyProvider {"keyProvider":"local","root":"[REDACTED]"}');
    expect(inspect(cloud)).toBe('CloudKeyProvider {"keyProvider":"cloud-gcp","cachedRoot":"[REDACTED]"}');
    expect(inspect(mock)).toBe('MockKeyProvider {"keyProvider":"mock","root":"[REDACTED]","seed":"[REDACTED]"}');
    for (const text of [inspect(local), JSON.stringify(local)]) {
      expect(text).not.toContain("test test");
    }
  });

  it("the engine prints its public key and a redaction marker, never the private key", async () => {
    const engine = await makeEngine(tmpRegistry());
    const publicKey = engine.getPublicKey().toString("hex");
    expect(JSON.stringify(engine)).toBe(
      JSON.stringify({
        network: "bitcoin_regtest",
        keyProvider: "mock",
        oraclePublicKey: publicKey,
        oraclePrivateKey: "[REDACTED]",
      })
    );
    expect(inspect(engine)).toBe(
      `AttestationEngine ${JSON.stringify({
        network: "bitcoin_regtest",
        keyProvider: "mock",
        oraclePublicKey: publicKey,
        oraclePrivateKey: "[REDACTED]",
      })}`
    );
    engine.close();
  });
});

describe("C3: announcement authentication and the maturity gate", () => {
  it("refusal texts of the signer for a future event and a forged announcement", async () => {
    const registry = tmpRegistry();
    const engine = await makeEngine(registry);
    const future = await engine.createAnnouncement("c3-future", BINARY, FUTURE);
    await expect(engine.attestBinary(future, true)).rejects.toThrow(
      /Refusing to attest event c3-future: maturity \d+ is in the future \(now \d+\)/
    );

    const past = await engine.createAnnouncement("c3-forged", BINARY, MATURITY);
    const forged: EventAnnouncement = { ...past, maturityTime: FUTURE };
    await expect(engine.attestBinary(forged, true)).rejects.toThrow(
      /Refusing to attest event c3-forged: the announcement is not signed by this engine's oracle key/
    );
    engine.close();
  });

  it("a verifier accepts 300 seconds of prematurity and refuses 301", async () => {
    const engine = await makeEngine(tmpRegistry());
    const base = 1_900_000_000;
    const nowSpy = jest.spyOn(Date, "now");
    try {
      nowSpy.mockReturnValue(base * 1000);
      const ann = await engine.createAnnouncement("c3-skew", BINARY, base + 300);
      nowSpy.mockReturnValue((base + 400) * 1000);
      const att = await engine.attestBinary(ann, true);
      const pinned = engine.getPublicKey();
      nowSpy.mockReturnValue(base * 1000);
      expect(engine.verifyAttestation(ann, att, pinned)).toBe(true);
      nowSpy.mockReturnValue((base - 1) * 1000);
      expect(engine.verifyAttestation(ann, att, pinned)).toBe(false);
    } finally {
      nowSpy.mockRestore();
    }
    engine.close();
  });

  it("a malformed maturity on an announcement is refused as not authentic", async () => {
    const engine = await makeEngine(tmpRegistry());
    const ann = await engine.createAnnouncement("c3-zero", BINARY, MATURITY);
    await expect(
      engine.attestBinary({ ...ann, maturityTime: 0 }, true)
    ).rejects.toThrow(/not signed by this engine's oracle key/);
    await expect(
      engine.attestBinary({ ...ann, maturityTime: Number.NaN }, true)
    ).rejects.toThrow(/not signed by this engine's oracle key/);
    engine.close();
  });
});

describe("C4: registry log and anchor formats", () => {
  it("the log holds version 3 entries with the four fields, and the anchor holds the tip", () => {
    const registryPath = tmpRegistry();
    const registry = new UsedNonceRegistry({ persistPath: registryPath, initialize: true });
    const r1 = "11".repeat(32);
    const r2 = "22".repeat(32);
    const m1 = "aa".repeat(32);
    const m2 = "bb".repeat(32);
    registry.checkAndRecord(r1, "event-1", m1);
    registry.checkAndRecord(r2, "event-2", m2);
    registry.close();

    const log = JSON.parse(fs.readFileSync(registryPath, "utf8"));
    expect(log.version).toBe(3);
    expect(Object.keys(log)).toEqual(["version", "entries"]);
    expect(log.entries).toHaveLength(2);
    expect(Object.keys(log.entries[0])).toEqual(["nonceId", "eventId", "messageHash", "chain"]);

    const genesis = "0".repeat(64);
    const digest = (prev: string, nonce: string, ev: string, msg: string) =>
      sha256Hex(prev + sha256Hex(`${nonce}\n${ev}\n${msg}`));
    const c1 = digest(genesis, r1, "event-1", m1);
    const c2 = digest(c1, r2, "event-2", m2);
    expect(log.entries[0]).toEqual({ nonceId: r1, eventId: "event-1", messageHash: m1, chain: c1 });
    expect(log.entries[1]).toEqual({ nonceId: r2, eventId: "event-2", messageHash: m2, chain: c2 });

    const anchor = JSON.parse(fs.readFileSync(`${registryPath}.anchor`, "utf8"));
    expect(anchor).toEqual({ version: 1, tip: c2 });
  });

  it("the anchor of an empty history records a null tip", () => {
    const registryPath = tmpRegistry();
    new UsedNonceRegistry({ persistPath: registryPath, initialize: true }).close();
    const anchor = JSON.parse(fs.readFileSync(`${registryPath}.anchor`, "utf8"));
    expect(anchor).toEqual({ version: 1, tip: null });
  });

  it("a repeat of an identical record does not grow the log", () => {
    const registryPath = tmpRegistry();
    const registry = new UsedNonceRegistry({ persistPath: registryPath, initialize: true });
    registry.checkAndRecord("33".repeat(32), "event-3", "cc".repeat(32));
    registry.checkAndRecord("33".repeat(32), "event-3", "cc".repeat(32));
    registry.close();
    const log = JSON.parse(fs.readFileSync(registryPath, "utf8"));
    expect(log.entries).toHaveLength(1);
  });

  it("the lock file names its holder and is removed on close", () => {
    const registryPath = tmpRegistry();
    const registry = new UsedNonceRegistry({ persistPath: registryPath, initialize: true });
    const lock = JSON.parse(fs.readFileSync(`${registryPath}.lock`, "utf8"));
    expect(lock.pid).toBe(process.pid);
    expect(typeof lock.hostname).toBe("string");
    expect(typeof lock.acquiredAt).toBe("string");
    registry.close();
    expect(fs.existsSync(`${registryPath}.lock`)).toBe(false);
  });
});

describe("C5: event id and descriptor boundaries", () => {
  it("event ids of 1 and 255 printable characters are accepted, 0 and 256 are refused", () => {
    expect(() => hashEventId("x")).not.toThrow();
    expect(() => hashEventId("x".repeat(255))).not.toThrow();
    expect(() => hashEventId("")).toThrow(/eventId must be a 1..255 character string/);
    expect(() => hashEventId("x".repeat(256))).toThrow(/eventId must be a 1..255 character string/);
    expect(() => hashEventId("\x7f")).toThrow(/printable ASCII/);
    expect(() => hashEventId(" ~")).not.toThrow();
  });

  it("the registry enforces the same event id rule on write", () => {
    const registry = new UsedNonceRegistry({ persistPath: tmpRegistry(), initialize: true });
    const nonce = "44".repeat(32);
    const message = "dd".repeat(32);
    expect(() => registry.checkAndRecord(nonce, "x".repeat(255), message)).not.toThrow();
    expect(() => registry.checkAndRecord("55".repeat(32), "x".repeat(256), message)).toThrow(
      /eventId must be 1 to 255 printable ASCII characters/
    );
    expect(() => registry.checkAndRecord("66".repeat(32), "\x7f", message)).toThrow(
      /eventId must be 1 to 255 printable ASCII characters/
    );
    registry.close();
  });

  it("descriptor ranges: numDigits 1..64, precision 0..18, base 2..36", () => {
    const numeric = (over: Record<string, unknown>) =>
      isValidDescriptor({
        type: AttestationType.NUMERIC,
        base: 10,
        numDigits: 4,
        unit: "USD",
        precision: 2,
        signed: false,
        ...over,
      } as any);
    expect(numeric({ numDigits: 1 })).toBe(true);
    expect(numeric({ numDigits: 64 })).toBe(true);
    expect(numeric({ numDigits: 65 })).toBe(false);
    expect(numeric({ precision: 18 })).toBe(true);
    expect(numeric({ precision: 19 })).toBe(false);
    expect(numeric({ base: 2 })).toBe(true);
    expect(numeric({ base: 36 })).toBe(true);
    expect(numeric({ base: 37 })).toBe(false);
    expect(numeric({ unit: "" })).toBe(false);
    expect(numeric({ unit: "é" })).toBe(false);
  });
});
