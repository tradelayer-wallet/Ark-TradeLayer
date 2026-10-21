/**
 * Red-team behavioral harness.
 *
 * Re-runs every adversarial probe from the security review against the fixed
 * code and prints PASS/FAIL per probe. Exits non-zero if any probe fails.
 *
 *   node scripts/redteam-harness.js
 *
 * Probes:
 *   P1  shared vectors: TS signer == .ark matcher emulation (byte equality)
 *   P2  a fresh engine reproduces the committed shared vectors exactly
 *   P3  two-process nonce-registry race is refused at startup (the lock)
 *   P4  used-nonce history survives crashes/restarts and cannot be reset
 *   P5  KEY_PROVIDER casing/padding/nonsense bypasses are dead
 *   P6  mainnet implies production (auth key, local keys, mock keys)
 *   P7  attestNumeric: precision scaling + unsigned negatives
 *   P8  numDigits: 0 descriptors cannot produce verifying empty attestations
 *   P9  non-ASCII event ids are rejected (no \uD800 / \uFFFD collision)
 *   P10 nonce index / nonce tweak derivations are domain-separated
 *   P11 validator copies are byte-identical and reject-by-default
 *   P12 in-memory nonce registry refused outside development
 */
"use strict";

require("../tests/support/register.js");

const { spawn, execFileSync } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { BitcoinNetworks } = require("bitcoin-networks");

const {
  AttestationEngine,
  AttestationType,
  serializeAttestationMessage,
  hashDescriptor,
  scaleValueByPrecision,
} = require("../src/attestation/attestation-engine");
const {
  UsedNonceRegistry,
  NonceRegistryLockError,
  NonceReuseError,
} = require("../src/attestation/used-nonce-registry");
const {
  DLC_TAGS,
  createTaggedHash,
  hashEventId,
  hashAttestation,
} = require("../src/crypto/tagged-hash");
const { MockKeyProvider } = require("../src/keys/key-provider");
const {
  loadConfig,
  normalizeKeyProvider,
  validateConfig,
  DEFAULT_API_AUTH_KEY,
} = require("../src/config/system-config");
const ark = require("../tests/support/ark-matcher-emulation");
const cfdjs = require("../tests/shims/cfd-js.js");

const ROOT = path.join(__dirname, "..");
const CHILD = path.join(ROOT, "tests", "support", "registry-child.js");
const MNEMONIC = "test test test test test test test test test test test junk";
const MATURITY_TIME = 1767225600;

let passed = 0;
let failed = 0;

async function probe(name, fn) {
  try {
    await fn();
    passed++;
    console.log(`PASS  ${name}`);
  } catch (e) {
    failed++;
    console.log(`FAIL  ${name}`);
    console.log(`      -> ${e && e.message ? e.message.split("\n")[0] : String(e)}`);
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function tmpRegistry() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "redteam-"));
  return path.join(dir, "used-nonces.json");
}

async function makeEngine(overrides = {}) {
  const engine = new AttestationEngine({
    network: BitcoinNetworks.bitcoin_regtest,
    keyProvider: new MockKeyProvider(MNEMONIC),
    usedNonceRegistryPath: tmpRegistry(),
    usedNonceRegistryInit: true,
    developmentMode: true,
    ...overrides,
  });
  await engine.initialize();
  return engine;
}

const NUMERIC = {
  type: AttestationType.NUMERIC,
  base: 10,
  numDigits: 4,
  unit: "USD",
  precision: 2,
  signed: true,
};

function withEnv(vars, fn) {
  const saved = {};
  for (const key of Object.keys(vars)) {
    saved[key] = process.env[key];
    process.env[key] = vars[key];
  }
  try {
    return fn();
  } finally {
    for (const key of Object.keys(vars)) {
      if (saved[key] === undefined) delete process.env[key];
      else process.env[key] = saved[key];
    }
  }
}

function expectThrow(fn, pattern, message) {
  let threw = false;
  try {
    fn();
  } catch (e) {
    threw = true;
    if (pattern && !pattern.test(String(e && e.message))) {
      throw new Error(`${message}: wrong error: ${e && e.message}`);
    }
  }
  if (!threw) throw new Error(`${message}: no error thrown`);
}

async function expectReject(fn, pattern, message) {
  try {
    await fn();
  } catch (e) {
    if (pattern && !pattern.test(String(e && e.message))) {
      throw new Error(`${message}: wrong error: ${e && e.message}`);
    }
    return;
  }
  throw new Error(`${message}: no error thrown`);
}

/** Runs the child that records a nonce and SIGKILLs itself; returns its stdout */
function runCrashingChild(registryPath) {
  try {
    execFileSync(process.execPath, [CHILD, registryPath, "record"], { cwd: ROOT, encoding: "utf8" });
  } catch (e) {
    if (e.signal !== "SIGKILL") throw e;
    return String(e.stdout);
  }
  throw new Error("crash child was expected to be killed by SIGKILL");
}

async function main() {
  const vectors = JSON.parse(
    fs.readFileSync(path.join(ROOT, "tests", "vectors", "attestation-vectors.json"), "utf8")
  );

  // ------------------------------------------------------------------ P1
  await probe("P1  TS signer and .ark matcher agree byte-for-byte on the shared vectors", () => {
    for (const vector of vectors.vectors) {
      assert(
        ark.arkEventIdHash(vector.eventId).toString("hex") === vector.eventIdHash,
        `${vector.name}: eventIdHash mismatch`
      );
      for (let i = 0; i < vector.outcomes.length; i++) {
        const fields = {
          eventIdHash: Buffer.from(vector.eventIdHash, "hex"),
          oracleKeyXonly: Buffer.from(vector.oraclePublicKey, "hex"),
          descriptorHash: Buffer.from(vector.descriptorHash, "hex"),
          maturityTime: vector.maturityTime,
          outcome: Buffer.from(vector.outcomesHex[i], "hex"),
        };
        const tsMessage = serializeAttestationMessage(
          vector.eventId,
          fields.oracleKeyXonly,
          vector.descriptor,
          vector.maturityTime,
          vector.outcomes[i]
        );
        const arkMessage = ark.arkAttestationMessage(fields);
        assert(tsMessage.equals(arkMessage), `${vector.name}[${i}]: message bytes diverge`);
        assert(
          hashAttestation(tsMessage).equals(ark.arkAttestationMessageHash(fields)),
          `${vector.name}[${i}]: message hashes diverge`
        );
        assert(
          tsMessage.toString("hex") === vector.attestationMessages[i],
          `${vector.name}[${i}]: committed vector message mismatch`
        );
        assert(
          cfdjs.SchnorrVerify({
            pubkey: vector.oraclePublicKey,
            message: ark.arkAttestationMessageHash(fields).toString("hex"),
            signature: vector.attestationSignatures[i],
          }).valid,
          `${vector.name}[${i}]: signature does not verify on the .ark side`
        );
      }
    }
    console.log(
      `      (${vectors.vectors.length} vectors, ` +
        `${vectors.vectors.reduce((n, v) => n + v.outcomes.length, 0)} outcomes, ` +
        "reproduced by both the TS signer and the .ark matcher emulation)"
    );
  });

  // ------------------------------------------------------------------ P2
  await probe("P2  a fresh engine reproduces the committed vectors exactly", async () => {
    const engine = await makeEngine();
    assert(
      engine.getPublicKey().toString("hex") === vectors.vectors[0].oraclePublicKey,
      "oracle key mismatch"
    );
    for (const vector of vectors.vectors) {
      const announcement = await engine.createAnnouncement(
        vector.eventId,
        vector.descriptor,
        vector.maturityTime
      );
      assert(
        JSON.stringify(announcement.noncePoints.map((r) => r.toString("hex"))) ===
          JSON.stringify(vector.noncePoints),
        `${vector.name}: nonce points mismatch`
      );
      assert(
        hashDescriptor(vector.descriptor).toString("hex") === vector.descriptorHash,
        `${vector.name}: descriptor hash mismatch`
      );
      let attestation;
      if (vector.descriptor.type === "numeric") {
        attestation = await engine.attestNumeric(
          announcement,
          vector.name === "numeric-signed-decimal" ? 12.34 : 5
        );
      } else if (vector.descriptor.type === "binary") {
        attestation = await engine.attestBinary(announcement, true);
      } else {
        attestation = await engine.attestEnum(announcement, 1);
      }
      assert(
        JSON.stringify(attestation.signatures.map((s) => s.toString("hex"))) ===
          JSON.stringify(vector.attestationSignatures),
        `${vector.name}: deterministic signatures mismatch`
      );
    }
  });

  // ------------------------------------------------------------------ P3
  await probe("P3  two-process nonce race: the second writer is refused at startup", async () => {
    const registryPath = tmpRegistry();
    const child = spawn(process.execPath, [CHILD, registryPath, "hold"], { cwd: ROOT });
    try {
      await new Promise((resolve, reject) => {
        let out = "";
        child.stdout.on("data", (chunk) => {
          out += String(chunk);
          if (out.includes("HELD")) resolve();
        });
        child.on("error", reject);
        child.on("exit", (code) => reject(new Error(`holder exited early (${code})`)));
      });

      // (a) in-process second instance
      expectThrow(
        () => new UsedNonceRegistry({ persistPath: registryPath, initialize: true }),
        /is locked/,
        "second in-process registry was not refused"
      );

      // (b) second OS process must refuse too
      const second = spawn(process.execPath, [CHILD, registryPath, "open"], { cwd: ROOT });
      const result = await new Promise((resolve) => {
        let out = "";
        second.stdout.on("data", (chunk) => (out += String(chunk)));
        second.on("exit", (code) => resolve({ code, out }));
      });
      assert(result.code === 3, `second process did not refuse (exit=${result.code})`);
      assert(/REFUSED/.test(result.out), "second process did not report REFUSED");
    } finally {
      child.kill("SIGKILL");
    }
  });

  // ------------------------------------------------------------------ P4
  await probe("P4  nonce history survives crashes/restarts and cannot be reset", () => {
    // (a) crash-style exit leaves the lock behind. The stale lock blocks
    // startup (never taken over); once the operator removes it, history
    // survives and reuse is still refused
    const crashPath = tmpRegistry();
    const out = runCrashingChild(crashPath);
    assert(/RECORDED/.test(out), "child did not record");
    expectThrow(
      () => new UsedNonceRegistry({ persistPath: crashPath, initialize: true }),
      /is locked/,
      "stale lock from a crashed writer was taken over"
    );
    fs.unlinkSync(`${crashPath}.lock`);

    const restarted = new UsedNonceRegistry({ persistPath: crashPath, initialize: true });
    assert(restarted.get("aa".repeat(32)) !== undefined, "history lost across restart");
    expectThrow(
      () => restarted.checkAndRecord("aa".repeat(32), "other-event", "bb".repeat(32)),
      /already used/,
      "nonce reuse after restart was not refused"
    );
    restarted.close();

    // (b) tail truncation is detected against the lockfile's history anchor
    const truncatePath = tmpRegistry();
    runCrashingChild(truncatePath);
    fs.unlinkSync(`${truncatePath}.lock`); // operator clears the crashed writer's lock
    const truncatable = new UsedNonceRegistry({ persistPath: truncatePath, initialize: true });
    truncatable.close();
    const truncated = JSON.parse(fs.readFileSync(truncatePath, "utf8"));
    truncated.entries.pop();
    fs.writeFileSync(truncatePath, JSON.stringify(truncated));
    expectThrow(
      () => new UsedNonceRegistry({ persistPath: truncatePath, initialize: true }),
      /does not extend the anchored history tip/,
      "tail truncation was not detected"
    );

    // (c) deletion of the registry behind its anchor is detected
    const deletePath = tmpRegistry();
    runCrashingChild(deletePath);
    fs.unlinkSync(`${deletePath}.lock`);
    fs.unlinkSync(deletePath);
    expectThrow(
      () => new UsedNonceRegistry({ persistPath: deletePath, initialize: true }),
      /is missing but its history anchor records tip/,
      "registry deletion was not detected"
    );

    // (d) and a fresh writer is STILL refused on the tampered file: the
    // truncated history cannot be laundered into service
    expectThrow(
      () => new UsedNonceRegistry({ persistPath: truncatePath, initialize: true }),
      /does not extend the anchored history tip/,
      "tampered registry came back into service"
    );
  });

  // ------------------------------------------------------------------ P5
  await probe("P5  KEY_PROVIDER=Mock|MOCK|' mock' and nonsense are refused outside development", () => {
    for (const value of ["Mock", "MOCK", " mock "]) {
      assert(normalizeKeyProvider(value) === "mock", `normalizeKeyProvider(${value}) != mock`);
    }
    for (const value of ["nonsense", "GCPX", "", "locall"]) {
      expectThrow(
        () => normalizeKeyProvider(value),
        /Unrecognized KEY_PROVIDER/,
        `normalizeKeyProvider(${JSON.stringify(value)})`
      );
    }
    for (const value of ["Mock", "MOCK", " mock "]) {
      withEnv(
        {
          KEY_PROVIDER: value,
          ORACLE_MODE: "production",
          NETWORK: "testnet",
          API_AUTH_KEY: "strong-random-api-key",
          VTXO_SERVER_PUBKEY: "aabbcc",
        },
        () => expectThrow(() => loadConfig(), /KEY_PROVIDER=mock/, `KEY_PROVIDER=${value}`)
      );
    }
    withEnv(
      { KEY_PROVIDER: "nonsense", ORACLE_MODE: "development", NETWORK: "regtest" },
      () => expectThrow(() => loadConfig(), /Unrecognized KEY_PROVIDER/, "nonsense provider")
    );
    // and the normalized value is what runs in development
    withEnv(
      { KEY_PROVIDER: "Mock", ORACLE_MODE: "development", NETWORK: "regtest" },
      () => assert(loadConfig().keys.provider === "mock", "Mock was not normalized to mock")
    );
  });

  // ------------------------------------------------------------------ P6
  await probe("P6  mainnet implies production (auth key, local keys, mock keys)", () => {
    const base = {
      network: "testnet",
      mode: "production",
      keys: { provider: "gcp", projectId: "p", secretId: "s", allowLocalKeys: false },
      database: { uri: "mongodb://localhost:27017", database: "t" },
      redis: { host: "127.0.0.1", port: 6379 },
      externalData: { priceFeeds: { enabled: ["coingecko"] }, blockchainClients: {} },
      api: {
        publicPort: 3000,
        internalPort: 3001,
        authKey: DEFAULT_API_AUTH_KEY,
        cors: { enabled: true, origins: ["*"] },
      },
      monitoring: { logLevel: "info" },
      scheduler: { priceCheckInterval: 5, paymentCheckInterval: 2, announcementLookahead: 13 },
      vtxo: { defaultExitDelay: 1008, serverPublicKey: "aabb", minContractValue: 10000 },
      usedNonceRegistryPath: "/srv/vtxo/used-nonces.json",
      usedNonceRegistryInit: true,
    };

    // dev-key-insecure no longer survives ORACLE_MODE=development + mainnet
    expectThrow(
      () => validateConfig({ ...base, network: "mainnet", mode: "development" }),
      /insecure default/,
      "default auth key accepted on mainnet"
    );

    // ALLOW_LOCAL_KEYS=1 no longer permits a local mnemonic on mainnet
    expectThrow(
      () =>
        validateConfig({
          ...base,
          network: "mainnet",
          mode: "production",
          api: { ...base.api, authKey: "strong-key-0123456789" },
          keys: { provider: "local", mnemonic: "m", allowLocalKeys: true },
        }),
      /network=mainnet/,
      "local keys accepted on mainnet"
    );

    // mock keys are refused on mainnet even with ORACLE_MODE=development
    expectThrow(
      () =>
        validateConfig({
          ...base,
          network: "mainnet",
          mode: "development",
          api: { ...base.api, authKey: "strong-key-0123456789" },
          keys: { provider: "mock", allowLocalKeys: false },
        }),
      /KEY_PROVIDER=mock/,
      "mock keys accepted on mainnet"
    );
  });

  // ------------------------------------------------------------------ P7
  await probe("P7  attestNumeric: precision scaling + unsigned negatives", async () => {
    assert(scaleValueByPrecision(12.34, 2) === 1234n, "12.34 @ precision 2 != 1234");
    const engine = await makeEngine();
    const announcement = await engine.createAnnouncement("harness-decimal", NUMERIC, MATURITY_TIME);
    const attestation = await engine.attestNumeric(announcement, 12.34);
    assert(
      JSON.stringify(attestation.outcomes) === JSON.stringify(["+", "1", "2", "3", "4"]),
      `unexpected digit vector: ${attestation.outcomes}`
    );
    const unsigned = { ...NUMERIC, signed: false };
    const unsignedAnn = await engine.createAnnouncement("harness-unsigned", unsigned, MATURITY_TIME);
    await expectReject(
      () => engine.attestNumeric(unsignedAnn, -5),
      /negative value/,
      "unsigned negative was not refused"
    );
    expectThrow(
      () => scaleValueByPrecision(1.25, 1),
      /decimal places/,
      "precision overflow was not refused"
    );
  });

  // ------------------------------------------------------------------ P8
  await probe("P8  numDigits: 0 cannot produce a verifying empty attestation", async () => {
    const engine = await makeEngine({
      trustedOraclePublicKey: "8eead9aaf2bb8800aae8dfe44382eac6c731c8bb2ced4a2eed807ecb7861469e",
    });
    await expectReject(
      () =>
        engine.createAnnouncement(
          "harness-zero",
          { type: AttestationType.NUMERIC, base: 10, numDigits: 0, unit: "USD", precision: 0, signed: false },
          MATURITY_TIME
        ),
      /Invalid event descriptor/,
      "numDigits: 0 announcement was not refused"
    );
    const key = engine.getPublicKey();
    const valid = engine.verifyAttestation(
      {
        eventId: "harness-empty",
        oraclePublicKey: key,
        descriptor: { type: AttestationType.NUMERIC, base: 10, numDigits: 0, unit: "USD", precision: 0, signed: false },
        maturityTime: MATURITY_TIME,
        noncePoints: [],
        announcementSignature: Buffer.alloc(64, 1),
      },
      { eventId: "harness-empty", oraclePublicKey: key, outcomes: [], signatures: [], attestationTime: MATURITY_TIME }
    );
    assert(valid === false, "EMPTY attestation verified as true");
  });

  // ------------------------------------------------------------------ P9
  await probe("P9  non-ASCII event ids are rejected (no surrogate/U+FFFD collision)", () => {
    for (const eventId of ["\uD800-collide", "\uFFFD-collide"]) {
      expectThrow(
        () => hashEventId(eventId),
        /printable ASCII/,
        `hashEventId(${JSON.stringify(eventId)})`
      );
      expectThrow(
        () =>
          serializeAttestationMessage(eventId, Buffer.alloc(32, 1), NUMERIC, MATURITY_TIME, "+"),
        /printable ASCII/,
        `serializeAttestationMessage(${JSON.stringify(eventId)})`
      );
    }
  });

  // ---------------------------------------------------------------- P10
  await probe("P10 nonce-index and nonce-tweak derivations are domain-separated", () => {
    const preimage = Buffer.from("same-preimage", "utf8");
    const a = createTaggedHash(DLC_TAGS.ORACLE_NONCE_INDEX, preimage);
    const b = createTaggedHash(DLC_TAGS.ORACLE_NONCE_TWEAK, preimage);
    assert(DLC_TAGS.ORACLE_NONCE_INDEX !== DLC_TAGS.ORACLE_NONCE_TWEAK, "tags identical");
    assert(!a.equals(b), "tagged hashes identical under the two tags");
  });

  // ---------------------------------------------------------------- P11
  await probe("P11 validator copies are byte-identical and reject-by-default", () => {
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
    const a = fs.readFileSync(hardened);
    const b = fs.readFileSync(mirror);
    assert(a.equals(b), "validator copies diverge");
    const src = a.toString("utf8");
    assert((src.match(/Reject-then-validate \(H6\)/g) || []).length === 2, "H6 pattern missing");
    const first = src.indexOf("params.valid");
    assert(src.slice(first, first + 22).includes("= false"), "validator is not reject-by-default");
  });

  // ---------------------------------------------------------------- P12
  await probe("P12 in-memory nonce registry is refused outside development", () => {
    expectThrow(
      () =>
        new AttestationEngine({
          network: BitcoinNetworks.bitcoin_regtest,
          keyProvider: new MockKeyProvider(MNEMONIC),
          usedNonceRegistryPath: null,
          developmentMode: false,
        }),
      /only allowed in development mode/,
      "engine accepted in-memory registry outside development"
    );
    expectThrow(
      () =>
        new AttestationEngine({
          network: BitcoinNetworks.bitcoin,
          keyProvider: new MockKeyProvider(MNEMONIC),
          usedNonceRegistryPath: null,
          developmentMode: true,
        }),
      /only allowed in development mode/,
      "engine accepted in-memory registry on mainnet"
    );
    expectThrow(
      () => new UsedNonceRegistry({ persistPath: null }),
      /refused outside/,
      "registry accepted persistPath: null without opt-in"
    );
  });

  console.log("");
  console.log(`harness: ${passed} passed, ${failed} failed`);
  process.exit(failed > 0 ? 1 : 0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
