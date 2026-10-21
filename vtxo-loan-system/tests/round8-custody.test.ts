/**
 * Round-8 regression tests, key custody (Clone A, adversarial review).
 *
 *  A1  signing refuses an event that has not matured (any attest* path)
 *  A2  engine and key-provider objects never print or serialize key material
 *  A3  signing primitives match BIP-340 for odd-Y and odd-R keys
 *  A4  concurrent attest calls on one event never yield two outcome vectors
 *
 * The A3 fixtures are generated offline with an independent BIP-340
 * implementation (@noble/curves). The nonce-path fixtures were verified with the
 * same independent verifier. No test depends on the network or on the dev-only
 * cfd-js shim beyond the primitives under test.
 */
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { inspect } from "util";

import { BitcoinNetworks } from "bitcoin-networks";

import {
  AttestationEngine,
  AttestationType,
} from "../src/attestation/attestation-engine";
import {
  schnorrSign,
  schnorrSignWithNonce,
  schnorrVerify,
} from "../src/crypto/bitcoin-primitives";
import { MockKeyProvider } from "../src/keys/key-provider";

const MNEMONIC = "test test test test test test test test test test test junk";
const PAST_MATURITY = 1767225600;

jest.setTimeout(120_000);

function tmpRegistry(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "r8-custody-"));
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

describe("R8-A1: signing refuses events that have not matured", () => {
  it("every attest* path refuses a future event and records no nonce", async () => {
    const engine = await makeEngine(tmpRegistry());
    const future = Math.floor(Date.now() / 1000) + 86_400;
    const annBinary = await engine.createAnnouncement("r8-future-binary", BINARY, future);
    const annEnum = await engine.createAnnouncement(
      "r8-future-enum",
      { type: AttestationType.ENUM, outcomes: ["a", "b"] },
      future
    );
    const annNumeric = await engine.createAnnouncement(
      "r8-future-numeric",
      { type: AttestationType.NUMERIC, base: 10, numDigits: 2, unit: "u", precision: 0, signed: false },
      future
    );
    const usedBefore = (engine as any).usedNonces.size;

    await expect(engine.attestBinary(annBinary, true)).rejects.toThrow(/in the future/);
    await expect(engine.attestEnum(annEnum, 0)).rejects.toThrow(/in the future/);
    await expect(engine.attestNumeric(annNumeric, 42)).rejects.toThrow(/in the future/);
    expect((engine as any).usedNonces.size).toBe(usedBefore);
    engine.close();
  });

  it("a matured event is still attested and verifies", async () => {
    const engine = await makeEngine(tmpRegistry());
    const ann = await engine.createAnnouncement("r8-past-binary", BINARY, PAST_MATURITY);
    const att = await engine.attestBinary(ann, false);
    expect(engine.verifyAttestation(ann, att, engine.getPublicKey())).toBe(true);
    engine.close();
  });
});

describe("R8-A2: key material is never printed or serialized", () => {
  it("util.inspect and JSON of the engine and key provider expose no private key", async () => {
    const keyProvider = new MockKeyProvider(MNEMONIC);
    const engine = new AttestationEngine({
      network: BitcoinNetworks.bitcoin_regtest,
      keyProvider,
      usedNonceRegistryPath: tmpRegistry(),
      usedNonceRegistryInit: true,
      developmentMode: true,
    });
    await engine.initialize();

    const oracleHex = (engine as any).oraclePrivateKey.toString("hex") as string;
    const rootHex = (keyProvider as any).root.privateKey.toString("hex") as string;
    // util.inspect prints Buffers as space-separated bytes: check both spellings
    const spaced = (hex: string): string => hex.match(/../g)!.join(" ");

    const printed = [
      inspect(engine, { depth: 6 }),
      inspect(keyProvider, { depth: 6 }),
      JSON.stringify(engine),
      JSON.stringify(keyProvider),
    ].join("\n");
    for (const secret of [oracleHex, rootHex, spaced(oracleHex), spaced(rootHex)]) {
      expect(printed.includes(secret)).toBe(false);
    }
    expect(printed).toContain("[REDACTED]");
    engine.close();
  });
});

describe("R8-A3: signing primitives match BIP-340", () => {
  // BIP-340 test vector 0 (secret key 3, zero aux and message)
  it("BIP-340 vector 0 signs and verifies exactly", () => {
    const sk = Buffer.from("0000000000000000000000000000000000000000000000000000000000000003", "hex");
    const pk = Buffer.from("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9", "hex");
    const msg = Buffer.alloc(32);
    const aux = Buffer.alloc(32);
    const sig = Buffer.from(
      "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0",
      "hex"
    );
    expect(schnorrSign(sk, msg, aux).equals(sig)).toBe(true);
    expect(schnorrVerify(pk, msg, sig)).toBe(true);
  });

  // Default-nonce signing (aux path). Odd-Y keys exercise the even-Y normalization of the secret key.
  const AUX_FIXTURES = [
  {
    oddY: true,
    sk: "3fde5107545f22c35346b58bff1cf6d7f18a06a47b766155044d3491116df936",
    aux: "6fe1cf779a6946ab7b7efcf5aede2841c6e407101420ca9636c34f776d7197f7",
    msg: "b20e6a3a8d85485de98c165b1e74883595084719bbf6d3b7b3796cb64f02217b",
    pub: "f6761b94e4cf22131cf01411cc18539cd4d9efebe7ca94af37241059595231d8",
    sig: "a422cbe6a684a9318e12a33477ab203aa4f2343cd237c09282e9027ca5dd94e0a579aa3c1a06d9d1b313c1fa11e849ee619d89df4053b994d14bd7916a964812",
  },
  {
    oddY: false,
    sk: "c484a2b5019658e4a5607684f76145b9e4a41da8801f27661d8edfc920dbf865",
    aux: "5f84f22d570d074365dc611e7f841dbe9784950a51e8713f5a5849a600208896",
    msg: "efc045695e33e31469a8b5326e3c57e87b63af5aea45cc928dc2f21e5d996644",
    pub: "df04b92590420211c68040a4b777cdd243e36dc1a2e3ce1229f9291ffb12845f",
    sig: "a07c121758cb536d0a285745c5947fe7de93f20cbca8258fca00442c40c392b0ec285607ceefb6b37177bfa1e68c8b52a9cb57a825e9b4f6412dc56bbbac89c5",
  },
  {
    oddY: false,
    sk: "f9d0f54d1c29534b8514a5c8c20413da9ec74ae974dd670fd18638de3c297a65",
    aux: "49521e2b8b81a282c74c6873aabb8d467f6bb014d43820978dc019120038c0e8",
    msg: "17723a087cd880d4d190ebf810805fe8f12ec773dd5ed9836692638c6941ff56",
    pub: "1197a7b5fa60b1ff36126f1fff5d3af1e072941dd1a0269bddb5d47466d8b885",
    sig: "6f00d4bb1aed45a8ecdd814c168f28e87c04e796f55f1ce2d9be1424c0fa9af98badffbb24c0db85be496195fc9e6fb83e236b7e4969f9041785a8df2d8b7e93",
  },
  {
    oddY: true,
    sk: "4d6ca2d265571b47f96301d62e1d2e4b14ba1b80e9bfedd022813c366c34e4fe",
    aux: "666c8c2b51527bea9ce46170aff20b12e29a1186f7812793da46034eb0bbe9e3",
    msg: "2ddf95ca676da200463d262e0adcdeec3192debfc7de3dd541db1caf4efb75c7",
    pub: "e8e86a2ae70cb665550bcd9c4e058a0b21d4a781c63a4dd581bdabe4f6c9625b",
    sig: "bf60ac7604135af018301c38d872519f49ca854bc18db7b6d939fde6fba8e8e55368f5b8f802d5b7d01a326a9d92f88404983e7bd604babaa3f5cc504a045dcc",
  },
  {
    oddY: false,
    sk: "802095807960c50e3cae98feb0c004c0572d08230d34ad9a7d4092ea1032ebdb",
    aux: "ac6c11ced081509dbd98be178c25ff4fa654719377d549ebe360224710beac0e",
    msg: "649798af16c4d22b68ab6c291183b58eb5ed9dc7559141eb2c3bf2ac87399d04",
    pub: "a94509575c85895ac673df0344ad365db9491a0560251eff802face7d2c4faaf",
    sig: "5b18f45cfc2e3859639dcd26c5c9909bd52ff2355f6c6dfd5a2ca60630d5957458c9c9682a8532ff60e1b00f5ec521880133594b3e9080b26be25479f893f74f",
  },
  {
    oddY: false,
    sk: "3694e767fab6a8fefc2ab5a40910c022f584b34af81834d7968d7a23c204a6fb",
    aux: "a19c18f6e1d1f8fe1b5728b86b4bed63a94d322cbb84b80b544cc165b6b0a34d",
    msg: "73d649b360ebd63c2b8a15992bd192138ec693a5cc421a58fc062c4552765093",
    pub: "cbaa47385cee424b601ce789f2df6a41ce11ea9f17a24f4e7369ec198230e1fc",
    sig: "2ca58218a12df7aa847a3257fbb810214e910590b510a113ea7b6cf03cad759cbe61b894810dd8d692e4da643975ef8ad1a7f0909ba3f6d91a4b05ef204398d6",
  },
  ];
  it.each(AUX_FIXTURES.map((f, i) => [i, f.oddY] as const))(
    "aux-path fixture %i (oddY=%s) matches the reference signature",
    (i, _oddY) => {
      const f = AUX_FIXTURES[i]!;
      const sk = Buffer.from(f.sk, "hex");
      const msg = Buffer.from(f.msg, "hex");
      const sig = schnorrSign(sk, msg, Buffer.from(f.aux, "hex"));
      expect(sig.toString("hex")).toBe(f.sig);
      expect(schnorrVerify(Buffer.from(f.pub, "hex"), msg, sig)).toBe(true);
    }
  );

  // Explicit-nonce signing (the attestation path). Odd-Y P and odd-Y R exercise the negation of both.
  const NONCE_FIXTURES = [
  {
    pOdd: false,
    rOdd: true,
    sk: "bdded0eecc47a7a850c873048053f9f4ccce0ab174ff530bb408a23dad188cbf",
    k: "d551afe4d5a9002a0933dc2f079b1ca0e03cd1eb7f6024c684a132c16032e2e2",
    msg: "128fd980c70c1083f7fcbf8c0fb9e0be99fae57a020f1c81f146a1a643ed5f6f",
    pub: "63b0ea6699fc92fb980c333b158764f1f2b74014756114383277f8c0df034abf",
    sig: "cb019d3100f5a51e9b178552fdf90214c13828f514b7f1c4e154b09beca505088f4d86fbc90f799fbf3c62b8590e3482d65030b06e14065cf24f4b7593b1c434",
  },
  {
    pOdd: true,
    rOdd: false,
    sk: "a585b7c2728a0a9efab3ebe928d2b7877ac3b653e30845d24900257572410981",
    k: "eb8322cc783a3df008059656f83645d49c4f7fe6affa2a9af217bf1f69e6f750",
    msg: "b0aab5f3aa3db7ea4992d1671c5d17e6c3b2f5029e751ea3dcbbfbdf79b7c020",
    pub: "361e094c3eb10ba0096325e80d7cdad2bb5d0cf80a94c3758b1833fe30fdcb5b",
    sig: "e09d8840d7a4b7f52216ffb0d938b8ed87c2bb904754fe8795a61974e7174a3e4561ae03f49cdde87519d2e4c1f102a29e393b89419a6e77290454e1da874d16",
  },
  {
    pOdd: true,
    rOdd: true,
    sk: "79e93c6d30db4906f6e0d73f942c4a4880c774b6a84e1bf42538837c38d1bfd9",
    k: "884f26229f75a864ae879fd787174d64ee99bd619fd81cd2d7c420570c96659c",
    msg: "091d480f4cd785c6f9c337b134f4922db93c0d98feba30de6926fcf9c19d3ac0",
    pub: "1df18eb1d1779e508f2255604990bd19d05b0862573c7ec338d6a31777ad1ad7",
    sig: "70f7bc244de7133e9f9dd65d8f2bf35728ae525daccf3dbda945bd3895d0825838def6a7434f3884dd26f7bad00bdd390678fdf861ee677cfd559e838a252c02",
  },
  {
    pOdd: false,
    rOdd: false,
    sk: "502ce1746bc7058343f7e7333ed516e7557fef2fc4613b1a0a14c19f1e4d5640",
    k: "ab7bfcdddbe90c3c22d85a42f38e0b9c2536efeb6b0c16755adf32bf9e47d308",
    msg: "a3d80bb9639cf1991c1e45edccebe2da942d0d0fcea5f44d35cb60b0187fb233",
    pub: "c2cfbd6dea45ae9640373f1b20f36ab9dee4bf54d5a5757eae7341486b2508df",
    sig: "9276390e3082e623ce3ad7608475481dff79d6482ab6c4035a31cc277f552361253fcf1c044df14753c55e071a66556e39010720038cc77455a86765891279bc",
  },
  {
    pOdd: true,
    rOdd: false,
    sk: "1691e580de82da2457e0f2234cf8f42fcf1713ee96f7151f900332b63956f8d8",
    k: "39a7662fab5953a5fb53256dda9561837f06ec4132d0a3b4d1309a3a37c76253",
    msg: "a411e4a2649f9c011bcfb5ab5c792845202de2707b7b8878f9f39a9675eda8d2",
    pub: "c22aadbcc43182131bcb3f4c1f4069f7a3bdaf0b22e8fd63c5aeaa5f4ef657e1",
    sig: "de220524370638e685a5d1cb781ffa04e7bd64a68a4083a3cc7ff3ec5e7dacfa5f5522c4e84ca88971bd4bb114446ce1faa7f7750ca55f38572ed13c5ad40e67",
  },
  {
    pOdd: false,
    rOdd: false,
    sk: "7f4926e6ed2d1dfad0afeba6b3bb974a9f3a185e256c348de4e8c6c5bba03c02",
    k: "d53ffab352db196f5e45c999b6a95276197a89953ad7ad1bd6070cd4734fc392",
    msg: "6e5841394b84e15cde3101d89565565dbbf7e23a1f13f2f89686285ecc854126",
    pub: "5c18833728543e0b5fa539a268541a85ba0ec2292ac630ca789254ae9f2d9ffb",
    sig: "4596eede26a9b585b23cb50121605db6d2e5a7351dc575162c79a88957c5586d71afe4f2d71ea56b713f7b97c5f049b1143c8864eda79dad7dbb1d722797dcf6",
  },
  ];
  it.each(NONCE_FIXTURES.map((f, i) => [i, f.pOdd, f.rOdd] as const))(
    "nonce-path fixture %i (pOdd=%s, rOdd=%s) matches the reference signature",
    (i, _pOdd, _rOdd) => {
      const f = NONCE_FIXTURES[i]!;
      const sig = schnorrSignWithNonce(Buffer.from(f.sk, "hex"), Buffer.from(f.msg, "hex"), Buffer.from(f.k, "hex"));
      expect(sig.toString("hex")).toBe(f.sig);
      expect(schnorrVerify(Buffer.from(f.pub, "hex"), Buffer.from(f.msg, "hex"), sig)).toBe(true);
    }
  );
});

describe("R8-A4: concurrent attests on one event produce one outcome vector", () => {
  it("40 simultaneous attests with conflicting values never yield two vectors", async () => {
    const engine = await makeEngine(tmpRegistry());
    const desc = { type: AttestationType.NUMERIC, base: 10, numDigits: 3, unit: "USD", precision: 0, signed: false } as const;
    const ann = await engine.createAnnouncement("r8-concurrent", desc, PAST_MATURITY);
    const values = [111, 112, 121, 211, 999];
    const calls = Array.from({ length: 40 }, (_, i) => values[i % values.length]!);
    const results = await Promise.allSettled(calls.map((v) => engine.attestNumeric(ann, v)));
    const fulfilled = results.filter((r): r is PromiseFulfilledResult<any> => r.status === "fulfilled");
    const vectors = new Set(fulfilled.map((r) => r.value.outcomes.join("")));
    expect(fulfilled.length).toBeGreaterThan(0);
    expect(vectors.size).toBe(1);
    for (const r of fulfilled) {
      expect(engine.verifyAttestation(ann, r.value, engine.getPublicKey())).toBe(true);
    }
    engine.close();
  });
});
