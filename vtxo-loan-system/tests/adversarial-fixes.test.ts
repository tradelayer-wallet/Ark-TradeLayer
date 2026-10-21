/**
 * Adversarial review fixes: regression tests for the red-team findings.
 *
 *  1. used-nonce registry fail-closed (single-writer lock, durable atomic
 *     writes, deletion/truncation detection, no in-memory mode outside dev)
 *  2. .ark matcher vs TS canonicalization on eventId (shared vectors)
 *  3. C3 config bypass (KEY_PROVIDER normalization + mainnet implies
 *     outside-development)
 *  4. divergent unhardened validator copy (byte-identical mirror)
 *  5. attestNumeric decimal scaling + unsigned negatives
 *  6. numDigits: 0 -> empty attestation must not verify
 *  7. timing-safe key compare, split nonce tags, ASCII-only event ids
 */
import { execFileSync, spawn, SpawnOptionsWithoutStdio } from "child_process";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import { BitcoinNetworks } from "bitcoin-networks";

import {
  AttestationEngine,
  AttestationType,
  constantTimeEquals,
  scaleValueByPrecision,
  serializeAttestationMessage,
} from "../src/attestation/attestation-engine";
import {
  NonceRegistryLockError,
  NonceReuseError,
  UsedNonceRegistry,
} from "../src/attestation/used-nonce-registry";
import {
  DLC_TAGS,
  createTaggedHash,
  hashEventId,
} from "../src/crypto/tagged-hash";
import { MockKeyProvider } from "../src/keys/key-provider";
import {
  DEFAULT_API_AUTH_KEY,
  SystemConfig,
  loadConfig,
  normalizeKeyProvider,
  validateConfig,
} from "../src/config/system-config";

const MNEMONIC = "test test test test test test test test test test test junk";
const ROOT = path.join(__dirname, "..");
const CHILD = path.join(__dirname, "support", "registry-child.js");

function tmpPath(name = "used-nonces.json"): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "adv-suite-"));
  return path.join(dir, name);
}

function makeConfig(overrides: Partial<SystemConfig> = {}): SystemConfig {
  return {
    network: "testnet",
    mode: "production",
    keys: { provider: "gcp", projectId: "proj", secretId: "secret", allowLocalKeys: false },
    database: { uri: "mongodb://localhost:27017", database: "test" },
    redis: { host: "127.0.0.1", port: 6379 },
    externalData: { priceFeeds: { enabled: ["coingecko"] }, blockchainClients: {} },
    api: {
      publicPort: 3000,
      internalPort: 3001,
      authKey: "strong-random-api-key",
      cors: { enabled: true, origins: ["*"] },
    },
    monitoring: { logLevel: "info" },
    scheduler: { priceCheckInterval: 5, paymentCheckInterval: 2, announcementLookahead: 13 },
    vtxo: { defaultExitDelay: 1008, serverPublicKey: "aabbcc", minContractValue: 10000 },
    usedNonceRegistryPath: "/srv/vtxo/used-nonces.json",
    usedNonceRegistryInit: true,
    ...overrides,
  };
}

function apiConfig(authKey: string) {
  return {
    publicPort: 3000,
    internalPort: 3001,
    authKey,
    cors: { enabled: true, origins: ["*"] },
  };
}

async function withEnv(vars: Record<string, string>, fn: () => void): Promise<void> {
  const saved: Record<string, string | undefined> = {};
  for (const key of Object.keys(vars)) {
    saved[key] = process.env[key];
    process.env[key] = vars[key];
  }
  try {
    fn();
  } finally {
    for (const key of Object.keys(vars)) {
      if (saved[key] === undefined) delete process.env[key];
      else process.env[key] = saved[key];
    }
  }
}

function runChild(mode: string, registryPath: string, extra: SpawnOptionsWithoutStdio = {}) {
  return execFileSync(process.execPath, [CHILD, registryPath, mode], {
    cwd: ROOT,
    encoding: "utf8",
    ...extra,
  });
}

const NUMERIC_UNSIGNED = {
  type: AttestationType.NUMERIC,
  base: 10,
  numDigits: 4,
  unit: "USD",
  precision: 2,
  signed: false,
} as const;

async function makeEngine(overrides: Record<string, unknown> = {}): Promise<AttestationEngine> {
  const engine = new AttestationEngine({
    network: BitcoinNetworks.bitcoin_regtest,
    keyProvider: new MockKeyProvider(MNEMONIC),
    usedNonceRegistryPath: tmpPath(),
    usedNonceRegistryInit: true,
    developmentMode: true,
    ...overrides,
  } as any);
  await engine.initialize();
  return engine;
}

jest.setTimeout(30_000);

describe("fix 1: used-nonce registry is fail-closed", () => {
  it("refuses a second instance on the same file (in-process single-writer lock)", () => {
    const registryPath = tmpPath();
    const first = new UsedNonceRegistry({ persistPath: registryPath, initialize: true });
    first.checkAndRecord("11".repeat(32), "event-1", "aa".repeat(32));
    expect(() => new UsedNonceRegistry({ persistPath: registryPath, initialize: true })).toThrow(
      NonceRegistryLockError
    );
    first.close();
  });

  it("refuses startup while another OS process holds the lock", async () => {
    const registryPath = tmpPath();
    const child = spawn(process.execPath, [CHILD, registryPath, "hold"], { cwd: ROOT });
    try {
      await new Promise<void>((resolve, reject) => {
        let out = "";
        child.stdout.on("data", (chunk) => {
          out += String(chunk);
          if (out.includes("HELD")) resolve();
        });
        child.on("error", reject);
        child.on("exit", (code) => reject(new Error(`child exited early: ${code}`)));
      });

      // Child is alive and holding the lock: a second writer must fail at
      // startup, not silently share the file.
      expect(() => new UsedNonceRegistry({ persistPath: registryPath, initialize: true })).toThrow(
        NonceRegistryLockError
      );
    } finally {
      child.kill("SIGKILL");
    }
  });

  it("never takes over a crashed writer's lock; operator removal restores full history", () => {
    const registryPath = tmpPath();
    // Child records a nonce and exits WITHOUT close() (crash semantics).
    let out = "";
    try {
      runChild("record", registryPath);
    } catch (e) {
      // the child SIGKILLs itself after recording: a true crash, no exit hook
      expect((e as { signal?: string }).signal).toBe("SIGKILL");
      out = String((e as { stdout?: unknown }).stdout);
    }
    expect(out).toContain("RECORDED");

    // The stale lock blocks startup, whatever its contents.
    expect(() => new UsedNonceRegistry({ persistPath: registryPath, initialize: true })).toThrow(
      /is locked.*Locks are never taken over automatically/s
    );

    // After the operator removes it, history is intact and reuse is refused.
    fs.unlinkSync(`${registryPath}.lock`);
    const restarted = new UsedNonceRegistry({ persistPath: registryPath, initialize: true });
    expect(restarted.get("aa".repeat(32))).toEqual({
      eventId: "event-child",
      messageHash: "bb".repeat(32),
    });
    expect(() =>
      restarted.checkAndRecord("aa".repeat(32), "event-other", "cc".repeat(32))
    ).toThrow(NonceReuseError);
    restarted.close();
  });

  it("detects deletion of the registry behind the lock (history cannot be reset)", () => {
    const registryPath = tmpPath();
    const first = new UsedNonceRegistry({ persistPath: registryPath, initialize: true });
    first.checkAndRecord("11".repeat(32), "event-1", "aa".repeat(32));
    first.close(); // the anchor keeps the history tip
    fs.unlinkSync(registryPath); // attacker deletes the registry
    expect(() => new UsedNonceRegistry({ persistPath: registryPath, initialize: true })).toThrow(
      /is missing but its history anchor records tip/
    );
  });

  it("detects truncation/rewriting of the append-only log via the digest chain", () => {
    const registryPath = tmpPath();
    const first = new UsedNonceRegistry({ persistPath: registryPath, initialize: true });
    first.checkAndRecord("11".repeat(32), "event-1", "aa".repeat(32));
    first.checkAndRecord("22".repeat(32), "event-2", "bb".repeat(32));
    first.checkAndRecord("33".repeat(32), "event-3", "cc".repeat(32));
    first.close(); // releases the writer lock but keeps its history-tip anchor

    // (a) Tail truncation ("forget the newest nonce") is caught by the anchor.
    const tail = JSON.parse(fs.readFileSync(registryPath, "utf8"));
    tail.entries.pop();
    fs.writeFileSync(registryPath, JSON.stringify(tail));
    expect(() => new UsedNonceRegistry({ persistPath: registryPath, initialize: true })).toThrow(
      /does not extend the anchored history tip/
    );

    // (b) Mid-chain rewriting is caught by the digest chain itself.
    const mid = JSON.parse(fs.readFileSync(registryPath, "utf8"));
    mid.entries[0].messageHash = "ee".repeat(32);
    fs.writeFileSync(registryPath, JSON.stringify(mid));
    expect(() => new UsedNonceRegistry({ persistPath: registryPath, initialize: true })).toThrow(
      /digest-chain check/
    );
  });

  it("refuses in-memory-only mode without an explicit development opt-in", () => {
    expect(() => new UsedNonceRegistry({ persistPath: null })).toThrow(NonceRegistryLockError);
    const mem = new UsedNonceRegistry({ persistPath: null, allowInMemory: true });
    mem.checkAndRecord("11".repeat(32), "e", "aa".repeat(32));
    expect(mem.size).toBe(1);
    mem.close();
  });

  it("persists durably and survives a clean restart with history intact", () => {
    const registryPath = tmpPath();
    const first = new UsedNonceRegistry({ persistPath: registryPath, initialize: true });
    first.checkAndRecord("11".repeat(32), "event-1", "aa".repeat(32));
    first.close();

    const second = new UsedNonceRegistry({ persistPath: registryPath, initialize: true });
    expect(second.get("11".repeat(32))).toBeDefined();
    expect(() => second.checkAndRecord("11".repeat(32), "event-2", "bb".repeat(32))).toThrow(
      NonceReuseError
    );
    second.close();
  });
});

describe("fix 1: engine wiring for the nonce registry", () => {
  it("refuses an in-memory registry outside development / on mainnet", () => {
    expect(
      () =>
        new AttestationEngine({
          network: BitcoinNetworks.bitcoin_regtest,
          keyProvider: new MockKeyProvider(MNEMONIC),
          usedNonceRegistryPath: null,
          developmentMode: false,
        })
    ).toThrow(/only allowed in development mode/);

    expect(
      () =>
        new AttestationEngine({
          network: BitcoinNetworks.bitcoin, // mainnet
          keyProvider: new MockKeyProvider(MNEMONIC),
          usedNonceRegistryPath: null,
          developmentMode: true,
        })
    ).toThrow(/only allowed in development mode/);

    // development + non-mainnet is the one allowed case
    const ok = new AttestationEngine({
      network: BitcoinNetworks.bitcoin_regtest,
      keyProvider: new MockKeyProvider(MNEMONIC),
      usedNonceRegistryPath: null,
      developmentMode: true,
    });
    expect(ok).toBeDefined();
  });

  it("an engine that already attested cannot be restarted to reuse its nonces", async () => {
    const registryPath = tmpPath();
    const descriptor = NUMERIC_UNSIGNED;
    const engine = new AttestationEngine({
      network: BitcoinNetworks.bitcoin_regtest,
      keyProvider: new MockKeyProvider(MNEMONIC),
      usedNonceRegistryPath: registryPath,
      usedNonceRegistryInit: true,
      developmentMode: true,
    });
    await engine.initialize();
    const announcement = await engine.createAnnouncement("restart-event", descriptor, 1767225600);
    await engine.attestNumeric(announcement, 12.34);
    // Simulate operator restart on the same registry file
    expect(
      () =>
        new AttestationEngine({
          network: BitcoinNetworks.bitcoin_regtest,
          keyProvider: new MockKeyProvider(MNEMONIC),
          usedNonceRegistryPath: registryPath,
          usedNonceRegistryInit: true,
          developmentMode: true,
        })
    ).toThrow(NonceRegistryLockError);
  });
});

describe("fix 3: config normalization and mainnet-implied hardening", () => {
  it("normalizes KEY_PROVIDER and refuses casing/padding bypasses outside development", async () => {
    expect(normalizeKeyProvider("Mock")).toBe("mock");
    expect(normalizeKeyProvider(" MOCK ")).toBe("mock");
    await withEnv(
      {
        KEY_PROVIDER: "Mock",
        ORACLE_MODE: "production",
        NETWORK: "testnet",
        API_AUTH_KEY: "strong-random-api-key",
        VTXO_SERVER_PUBKEY: "aabbcc",
      },
      () => {
        expect(() => loadConfig()).toThrow(/KEY_PROVIDER=mock/);
      }
    );
    await withEnv(
      {
        KEY_PROVIDER: " mock ",
        ORACLE_MODE: "production",
        NETWORK: "testnet",
        API_AUTH_KEY: "strong-random-api-key",
        VTXO_SERVER_PUBKEY: "aabbcc",
      },
      () => {
        expect(() => loadConfig()).toThrow(/KEY_PROVIDER=mock/);
      }
    );
  });

  it("throws on unrecognized KEY_PROVIDER values in any mode", async () => {
    // loadConfigFromEnv only reads the environment; normalization (and the
    // refusal) happens in loadConfig / validateConfig.
    await withEnv({ KEY_PROVIDER: "nonsense", ORACLE_MODE: "development", NETWORK: "regtest" }, () => {
      expect(() => loadConfig()).toThrow(/Unrecognized KEY_PROVIDER/);
    });
    expect(() => normalizeKeyProvider("hsm")).toThrow(/Unrecognized KEY_PROVIDER/);
    // programmatic construction with a garbage provider is caught too
    const config = makeConfig({
      keys: { provider: "nonsense" as any, allowLocalKeys: false },
    });
    expect(() => validateConfig(config)).toThrow(/Unrecognized KEY_PROVIDER/);
  });

  it("still allows mock key custody in development on non-mainnet", async () => {
    await withEnv(
      {
        KEY_PROVIDER: "mock",
        ORACLE_MODE: "development",
        NETWORK: "regtest",
        USED_NONCE_REGISTRY_PATH: "/srv/vtxo/used-nonces.json",
      },
      () => {
        const config = loadConfig();
        expect(config.keys.provider).toBe("mock");
      }
    );
  });

  it("mainnet implies outside-development: the default auth key is refused", () => {
    expect(() =>
      validateConfig(
        makeConfig({
          network: "mainnet",
          mode: "development",
          api: apiConfig(DEFAULT_API_AUTH_KEY),
        })
      )
    ).toThrow(/insecure default/);
  });

  it("mainnet implies outside-development: mock keys are refused even in development mode", () => {
    expect(() =>
      validateConfig(
        makeConfig({ network: "mainnet", mode: "development", keys: { provider: "mock" } })
      )
    ).toThrow(/KEY_PROVIDER=mock/);
    // and NETWORK=Mainnet cannot dodge it either (normalized at load)
    expect(normalizeKeyProvider("MOCK")).toBe("mock");
  });

  it("ALLOW_LOCAL_KEYS=1 never permits local mnemonics on mainnet", () => {
    expect(() =>
      validateConfig(
        makeConfig({
          network: "mainnet",
          mode: "production",
          keys: { provider: "local", mnemonic: "abandon abandon", allowLocalKeys: true },
        })
      )
    ).toThrow(/network=mainnet/);

    // ... while the opt-in still works outside mainnet
    const errors = validateConfig(
      makeConfig({
        network: "testnet",
        mode: "production",
        keys: { provider: "local", mnemonic: "abandon abandon", allowLocalKeys: true },
      })
    );
    expect(errors).toEqual([]);
  });

  it("NETWORK=Mainnet cannot dodge the mainnet checks (load-time normalization)", async () => {
    await withEnv(
      {
        KEY_PROVIDER: "mock",
        ORACLE_MODE: "development",
        NETWORK: "Mainnet",
        API_AUTH_KEY: "strong-random-api-key",
        VTXO_SERVER_PUBKEY: "aabbcc",
      },
      () => {
        expect(() => loadConfig()).toThrow(/KEY_PROVIDER=mock/);
      }
    );
  });
});

describe("fix 5: attestNumeric semantics", () => {
  it("scales decimal values by the descriptor precision exactly", async () => {
    expect(scaleValueByPrecision(12.34, 2)).toBe(1234n);
    expect(scaleValueByPrecision(12, 2)).toBe(1200n);
    expect(scaleValueByPrecision(-5, 0)).toBe(-5n);

    const engine = await makeEngine();
    const announcement = await engine.createAnnouncement(
      "decimal-event",
      { ...NUMERIC_UNSIGNED, signed: true },
      1767225600
    );
    const attestation = await engine.attestNumeric(announcement, 12.34);
    expect(attestation.outcomes).toEqual(["+", "1", "2", "3", "4"]);
  });

  it("rejects negative values for unsigned descriptors", async () => {
    const engine = await makeEngine();
    const announcement = await engine.createAnnouncement(
      "unsigned-negative",
      NUMERIC_UNSIGNED,
      1767225600
    );
    await expect(engine.attestNumeric(announcement, -5)).rejects.toThrow(/negative value/);
  });

  it("rejects values with more decimal places than the precision (no silent rounding)", async () => {
    const engine = await makeEngine();
    const announcement = await engine.createAnnouncement(
      "precision-overflow",
      { ...NUMERIC_UNSIGNED, precision: 0 },
      1767225600
    );
    await expect(engine.attestNumeric(announcement, 1.5)).rejects.toThrow(/decimal places/);
  });
});

describe("fix 6: degenerate descriptors cannot produce verifying empty attestations", () => {
  it("numDigits: 0 descriptors are refused at announcement time", async () => {
    const engine = await makeEngine();
    await expect(
      engine.createAnnouncement(
        "zero-digits",
        { type: AttestationType.NUMERIC, base: 10, numDigits: 0, unit: "USD", precision: 0, signed: false },
        1767225600
      )
    ).rejects.toThrow(/Invalid event descriptor/);
  });

  it("a forged numDigits: 0 announcement makes even an EMPTY attestation fail verification", async () => {
    const engine = await makeEngine({
      trustedOraclePublicKey: "8eead9aaf2bb8800aae8dfe44382eac6c731c8bb2ced4a2eed807ecb7861469e",
    });
    const descriptor = {
      type: AttestationType.NUMERIC,
      base: 10,
      numDigits: 0,
      unit: "USD",
      precision: 0,
      signed: false,
    } as const;
    const key = engine.getPublicKey();
    const forgedAnnouncement = {
      eventId: "empty-attestation",
      oraclePublicKey: key,
      descriptor,
      maturityTime: 1767225600,
      noncePoints: [],
      announcementSignature: Buffer.alloc(64, 1),
    };
    const emptyAttestation = {
      eventId: "empty-attestation",
      oraclePublicKey: key,
      outcomes: [],
      signatures: [],
      attestationTime: 1767225600,
    };
    expect(engine.verifyAttestation(forgedAnnouncement as any, emptyAttestation as any)).toBe(
      false
    );
  });
});

describe("fix 7: minor hardening", () => {
  it("pinned-key comparison is constant-time and correct", () => {
    const a = Buffer.alloc(32, 1);
    const b = Buffer.alloc(32, 1);
    expect(constantTimeEquals(a, b)).toBe(true);
    b[31] = 2;
    expect(constantTimeEquals(a, b)).toBe(false);
    expect(constantTimeEquals(a, Buffer.alloc(31, 1))).toBe(false);
  });

  it("nonce-derivation-index and nonce-tweak hashes are domain-separated", () => {
    const preimage = Buffer.from("identical-preimage", "utf8");
    const indexHash = createTaggedHash(DLC_TAGS.ORACLE_NONCE_INDEX, preimage);
    const tweakHash = createTaggedHash(DLC_TAGS.ORACLE_NONCE_TWEAK, preimage);
    expect(DLC_TAGS.ORACLE_NONCE_INDEX).not.toBe(DLC_TAGS.ORACLE_NONCE_TWEAK);
    expect(indexHash.equals(tweakHash)).toBe(false);
  });

  it("non-ASCII event ids are rejected (no surrogate/U+FFFD collision)", () => {
    const key = Buffer.alloc(32, 1);
    const descriptor = NUMERIC_UNSIGNED;
    // Buffer.from("\uD800","utf8") === Buffer.from("\uFFFD","utf8"): hashing the
    // utf8 bytes would make these two DISTINCT event ids collide. Both must
    // now be rejected outright.
    expect(() => hashEventId("\uD800-event")).toThrow(/printable ASCII/);
    expect(() => hashEventId("\uFFFD-event")).toThrow(/printable ASCII/);
    expect(() =>
      serializeAttestationMessage("\uD800-event", key, descriptor, 1767225600, "0")
    ).toThrow(/printable ASCII/);
    expect(() =>
      serializeAttestationMessage("\uFFFD-event", key, descriptor, 1767225600, "0")
    ).toThrow(/printable ASCII/);
    // and ordinary ASCII ids still work
    expect(hashEventId("btc-usd-2026-01-01").length).toBe(32);
  });

  it("the .ark/TS eventId commitment is sha256(utf8(eventId)) on both sides", () => {
    const ark = require("./support/ark-matcher-emulation");
    expect(ark.arkEventIdHash("loan-42").equals(hashEventId("loan-42"))).toBe(true);
  });
});

describe("fix 4: validator copies stay identical and reject-by-default", () => {
  const hardened = path.join(
    ROOT,
    "..",
    "tl-vtxo-handshake-optimized",
    "tradelayer-dlc-vtxo-validation-v2.js"
  );
  const mirror = path.join(
    ROOT,
    "..",
    "tl-vtxo-handshake-optimized",
    "ark-tradelayer-handshake-complete",
    "tradelayer-dlc-vtxo-validation-v2.js"
  );

  it("both validator copies are byte-identical", () => {
    expect(fs.readFileSync(mirror)).toEqual(fs.readFileSync(hardened));
  });

  it("both validators are reject-by-default (H6)", () => {
    for (const file of [hardened, mirror]) {
      const src = fs.readFileSync(file, "utf8");
      expect(src.match(/Reject-then-validate \(H6\)/g)).toHaveLength(2);
      // The first `params.valid` assignment in each validator must be `false`
      const first = src.indexOf("params.valid");
      expect(src.slice(first, first + 22)).toContain("= false");
    }
  });
});
