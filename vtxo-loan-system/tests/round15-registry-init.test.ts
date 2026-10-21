/**
 * Round-15 regression tests (A2): the nonce registry is never created implicitly.
 *
 *  R15-A2-1  a missing registry is refused without USED_NONCE_REGISTRY_INIT=1, the
 *            refusal explains the migration, and nothing is created
 *  R15-A2-2  the first start with initialize creates the registry and its anchor;
 *            later starts need no flag
 *  R15-A2-3  initialize over an existing registry changes nothing: the history
 *            stays and an already used nonce is still refused
 *  R15-A2-4  a registry moved to a new path needs its anchor with it
 *  R15-A2-5  an interrupted first start (anchor, no registry) is finished by
 *            initialize, and a deleted history is refused even with initialize
 *  R15-A2-6  the flag is read by the configuration and passed by the engine
 *
 *  R15-A1    the registry path is trimmed when it is read, as the numeric settings are
 */
import * as crypto from "crypto";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import { BitcoinNetworks } from "bitcoin-networks";

import { AttestationEngine } from "../src/attestation/attestation-engine";
import {
  NonceRegistryLockError,
  NonceReuseError,
  UsedNonceRegistry,
} from "../src/attestation/used-nonce-registry";
import { MockKeyProvider } from "../src/keys/key-provider";
import { loadConfig, loadConfigFromEnv } from "../src/config/system-config";

const MNEMONIC = "test test test test test test test test test test test junk";

jest.setTimeout(60_000);

function tmpDir(prefix: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function digest(label: string): string {
  return crypto.createHash("sha256").update(label).digest("hex");
}

function layout(registryPath: string): { anchor: string; lock: string } {
  return { anchor: `${registryPath}.anchor`, lock: `${registryPath}.lock` };
}

describe("R15-A2-1: a missing registry is refused without the init flag", () => {
  it("refuses, explains the migration, and creates nothing", () => {
    const base = tmpDir("r15-missing-");
    const registryPath = path.join(base, "new-place", "used-nonces.json");

    expect(() => new UsedNonceRegistry({ persistPath: registryPath })).toThrow(
      NonceRegistryLockError
    );
    let message = "";
    try {
      new UsedNonceRegistry({ persistPath: registryPath });
    } catch (e) {
      message = (e as Error).message;
    }
    expect(message).toMatch(/does not exist/);
    expect(message).toMatch(/\.anchor/);
    expect(message).toMatch(/data\/used-nonces\.json/);
    expect(message).toMatch(/USED_NONCE_REGISTRY_INIT=1/);

    expect(fs.existsSync(path.join(base, "new-place"))).toBe(false);
  });

  it("a missing registry in an existing directory creates no file, anchor or lock", () => {
    const dir = tmpDir("r15-missing-dir-");
    const registryPath = path.join(dir, "used-nonces.json");

    expect(() => new UsedNonceRegistry({ persistPath: registryPath })).toThrow(/does not exist/);

    const paths = layout(registryPath);
    expect(fs.existsSync(registryPath)).toBe(false);
    expect(fs.existsSync(paths.anchor)).toBe(false);
    expect(fs.existsSync(paths.lock)).toBe(false);
  });
});

describe("R15-A2-2: the first start creates the registry once", () => {
  it("initialize creates an empty registry and anchor, and later starts need no flag", () => {
    const registryPath = path.join(tmpDir("r15-init-"), "used-nonces.json");
    const paths = layout(registryPath);

    const first = new UsedNonceRegistry({ persistPath: registryPath, initialize: true });
    expect(fs.existsSync(registryPath)).toBe(true);
    expect(fs.existsSync(paths.anchor)).toBe(true);
    first.checkAndRecord(digest("k1"), "event-1", digest("m1"));
    first.close();

    const restarted = new UsedNonceRegistry({ persistPath: registryPath });
    expect(restarted.get(digest("k1"))).toEqual({ eventId: "event-1", messageHash: digest("m1") });
    restarted.close();
  });
});

describe("R15-A2-3: initialize never empties an existing registry", () => {
  it("keeps the history and still refuses a reused nonce", () => {
    const registryPath = path.join(tmpDir("r15-keep-"), "used-nonces.json");
    const first = new UsedNonceRegistry({ persistPath: registryPath, initialize: true });
    first.checkAndRecord(digest("k1"), "event-1", digest("m1"));
    first.close();

    const again = new UsedNonceRegistry({ persistPath: registryPath, initialize: true });
    expect(again.size).toBe(1);
    expect(() => again.checkAndRecord(digest("k1"), "event-2", digest("m1"))).toThrow(
      NonceReuseError
    );
    again.close();
  });
});

describe("R15-A2-4: moving the registry needs its anchor", () => {
  it("a registry moved with its anchor starts and keeps the history", () => {
    const oldDir = tmpDir("r15-move-old-");
    const oldPath = path.join(oldDir, "used-nonces.json");
    const first = new UsedNonceRegistry({ persistPath: oldPath, initialize: true });
    first.checkAndRecord(digest("k1"), "event-1", digest("m1"));
    first.close();

    const newDir = tmpDir("r15-move-new-");
    const newPath = path.join(newDir, "used-nonces.json");
    fs.renameSync(oldPath, newPath);
    fs.renameSync(layout(oldPath).anchor, layout(newPath).anchor);

    const moved = new UsedNonceRegistry({ persistPath: newPath });
    expect(() => moved.checkAndRecord(digest("k1"), "event-2", digest("m2"))).toThrow(
      NonceReuseError
    );
    moved.close();
  });

  it("a registry moved without its anchor is refused, even with initialize", () => {
    const oldDir = tmpDir("r15-moveonly-old-");
    const oldPath = path.join(oldDir, "used-nonces.json");
    const first = new UsedNonceRegistry({ persistPath: oldPath, initialize: true });
    first.checkAndRecord(digest("k1"), "event-1", digest("m1"));
    first.close();

    const newPath = path.join(tmpDir("r15-moveonly-new-"), "used-nonces.json");
    fs.renameSync(oldPath, newPath);

    expect(() => new UsedNonceRegistry({ persistPath: newPath })).toThrow(/anchor/);
    expect(() => new UsedNonceRegistry({ persistPath: newPath, initialize: true })).toThrow(
      /anchor/
    );
    expect(fs.existsSync(layout(newPath).anchor)).toBe(false);
    expect(fs.existsSync(layout(newPath).lock)).toBe(false);
  });
});

describe("R15-A2-5: an interrupted first start is finished by initialize only", () => {
  it("an anchor with no registry is completed by initialize, and refused without it", () => {
    const registryPath = path.join(tmpDir("r15-interrupted-"), "used-nonces.json");
    const created = new UsedNonceRegistry({ persistPath: registryPath, initialize: true });
    created.close();
    // The state of a start that stopped after the anchor: no registry, no marker.
    fs.unlinkSync(registryPath);
    fs.unlinkSync(`${registryPath}.created`);

    expect(() => new UsedNonceRegistry({ persistPath: registryPath })).toThrow(/does not exist/);
    expect(fs.existsSync(layout(registryPath).lock)).toBe(false);

    const finished = new UsedNonceRegistry({ persistPath: registryPath, initialize: true });
    expect(fs.existsSync(registryPath)).toBe(true);
    finished.close();
  });

  it("a deleted history is refused even with initialize", () => {
    const registryPath = path.join(tmpDir("r15-deleted-"), "used-nonces.json");
    const first = new UsedNonceRegistry({ persistPath: registryPath, initialize: true });
    first.checkAndRecord(digest("k1"), "event-1", digest("m1"));
    first.close();
    fs.unlinkSync(registryPath);

    expect(() => new UsedNonceRegistry({ persistPath: registryPath, initialize: true })).toThrow(
      /history was deleted/
    );
    expect(fs.existsSync(registryPath)).toBe(false);
  });
});

describe("R15-A2-6: the flag reaches the registry through the configuration", () => {
  const KEYS = ["NETWORK", "ORACLE_MODE", "KEY_PROVIDER", "USED_NONCE_REGISTRY_PATH", "USED_NONCE_REGISTRY_INIT"];
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

  it("USED_NONCE_REGISTRY_INIT=1 is read; unset means no initialization", () => {
    expect(loadConfigFromEnv().usedNonceRegistryInit).toBe(false);
    process.env.USED_NONCE_REGISTRY_INIT = "1";
    expect(loadConfigFromEnv().usedNonceRegistryInit).toBe(true);
  });

  it("any other value is refused when the configuration loads", () => {
    process.env.USED_NONCE_REGISTRY_PATH = path.join(tmpDir("r15-env-"), "used-nonces.json");
    process.env.USED_NONCE_REGISTRY_INIT = "yes";
    expect(() => loadConfig()).toThrow(/USED_NONCE_REGISTRY_INIT must be 1 or 0/);
  });

  it("the documented flow creates the registry only when the flag is set", () => {
    const registryPath = path.join(tmpDir("r15-flow-"), "used-nonces.json");
    process.env.USED_NONCE_REGISTRY_PATH = registryPath;

    const start = () =>
      new AttestationEngine({
        network: BitcoinNetworks.bitcoin_regtest,
        keyProvider: new MockKeyProvider(MNEMONIC),
        usedNonceRegistryPath: loadConfig().usedNonceRegistryPath,
        usedNonceRegistryInit: loadConfig().usedNonceRegistryInit,
        developmentMode: true,
      });
    expect(start).toThrow(/does not exist/);
    expect(fs.existsSync(registryPath)).toBe(false);

    process.env.USED_NONCE_REGISTRY_INIT = "1";
    const engine = start();
    expect(fs.existsSync(registryPath)).toBe(true);
    engine.close();
  });
});

describe("R15-A1: the registry path is trimmed like the numeric settings", () => {
  const KEYS = ["NETWORK", "ORACLE_MODE", "KEY_PROVIDER", "USED_NONCE_REGISTRY_PATH", "REDIS_PORT"];
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

  it("surrounding whitespace is removed; the trimmed path is what the registry opens", () => {
    const registryPath = path.join(tmpDir("r15-trim-"), "used-nonces.json");
    process.env.USED_NONCE_REGISTRY_PATH = `  ${registryPath} \n`;
    expect(loadConfigFromEnv().usedNonceRegistryPath).toBe(registryPath);
    expect(() => loadConfig()).not.toThrow();
  });

  it("a numeric setting with the same padding is read the same way", () => {
    process.env.REDIS_PORT = " 6380 ";
    expect(loadConfigFromEnv().redis.port).toBe(6380);
  });
});
