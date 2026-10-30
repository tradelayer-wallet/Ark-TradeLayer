// Legacy vector generator for tl-ark-dlc (dependency-free; Node >= 22.7).
//
//   node --experimental-transform-types scripts/compare-legacy.mjs <Ark-TradeLayer clone root> > fixtures/legacy_vectors.json
//
// It copies the pinned legacy files UNMODIFIED into a temp tree, adds tiny shims for the only things
// that are not available offline (the sha256 helper package, cfd-js, bip39/bip32 key providers and the
// network-backed txUtils), and runs the real legacy functions on fixed synthetic inputs.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { createRequire, registerHooks } from 'node:module';
import { pathToFileURL } from 'node:url';

const root = path.resolve(process.argv[2] ?? '.');
const PINS = {
  'vtxo-loan-system/src/crypto/tagged-hash.ts': '14ae39c706fe4b819fa31dba4bbc6e5a7e11ec84',
  'vtxo-loan-system/src/attestation/attestation-engine.ts': '0421e240ca9bccf5e9d7181a2bb23587ec774f62',
  'tl-vtxo-handshake-optimized/ark-tradelayer-handshake.js': '45d93f08df2fe12efd61343d7fa4afc2afff82a8',
};
function blobSha(buf) {
  // tolerate autocrlf checkouts: hash the LF-normalised text
  const lf = Buffer.from(buf.toString('utf8').replace(/\r\n/g, '\n'), 'utf8');
  return crypto
    .createHash('sha1')
    .update(Buffer.concat([Buffer.from('blob ' + lf.length + '\u0000'), lf]))
    .digest('hex');
}
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'tl-ark-legacy-'));
const put = (rel, data) => {
  const p = path.join(tmp, rel);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, data);
};
for (const [rel, sha] of Object.entries(PINS)) {
  const buf = fs.readFileSync(path.join(root, rel));
  if (blobSha(buf) !== sha) throw new Error('pin mismatch for ' + rel);
  const dest = rel.startsWith('vtxo-loan-system/') ? rel.slice('vtxo-loan-system/'.length) : 'hs/' + path.basename(rel);
  put(dest, buf);
}
put('package.json', '{"type":"module"}');
put('node_modules/@node-lightning/crypto/index.js', "const c=require('crypto');exports.sha256=(b)=>c.createHash('sha256').update(b).digest();");
put('node_modules/@node-lightning/crypto/package.json', '{"name":"@node-lightning/crypto","main":"index.js"}');
put('node_modules/bitcoin-networks/index.js', 'module.exports={BitcoinNetwork:undefined};');
put('node_modules/bitcoin-networks/package.json', '{"name":"bitcoin-networks","main":"index.js"}');
put(
  'src/crypto/bitcoin-primitives.ts',
  "const na=()=>{throw new Error('shim')};export const derivePublicKey=na,deriveSchnorrPublicKey=na,schnorrSign=na,schnorrSignWithNonce=na,schnorrVerify=na,tweakPrivateKey=na;",
);
put('src/keys/key-provider.ts', 'export const KeyProvider = undefined;');
put('hs/package.json', '{"type":"commonjs"}');
put('hs/txUtils.js', 'module.exports={};');

// legacy TS uses extensionless relative imports (tsc style); resolve them to .ts without touching the files
registerHooks({
  resolve(spec, ctx, next) {
    try {
      return next(spec, ctx);
    } catch (err) {
      if (spec.startsWith('.') && !path.extname(spec)) return next(spec + '.ts', ctx);
      throw err;
    }
  },
});
const th = await import(pathToFileURL(path.join(tmp, 'src/crypto/tagged-hash.ts')).href);
const eng = await import(pathToFileURL(path.join(tmp, 'src/attestation/attestation-engine.ts')).href);
const require = createRequire(path.join(tmp, 'hs/x.js'));
const origWarn = console.warn;
const origLog = console.log;
console.warn = () => {};
console.log = () => {};
const hs = require(path.join(tmp, 'hs/ark-tradelayer-handshake.js'));

const hex = (b) => Buffer.from(b).toString('hex');
const out = { generator: 'rust/tl-ark-dlc/scripts/compare-legacy.mjs', pins: PINS };

// 1. tagged hashes
out.tagged_hash = [
  ['DLC/oracle/nonce/v0', ''],
  ['DLC/oracle/nonce/v0', '00'],
  ['DLC/oracle/attestation/v0', '70616964'],
  ['DLC/oracle/announcement/v0', '0102030405'],
  ['TestTag', 'ff'.repeat(40)],
].map(([tag, data]) => ({ tag, data, out: hex(th.createTaggedHash(tag, Buffer.from(data, 'hex'))) }));
out.hash_attestation = ['paid', 'unpaid', 'hit', 'miss', '+', '-', '0', '1', '', 'triggered', 'défaut'].map((o) => ({
  outcome: o,
  out: hex(th.hashAttestation(o)),
}));
const base = Buffer.from('11'.repeat(32), 'hex');
out.nonce_tweak = ['evt-1', 'evt-2', 'loan/ä'].map((e) => ({
  base: hex(base),
  event_id: e,
  out: hex(th.deriveNonceTweak(base, e)),
}));

// 2. announcement serialisation + hashing (real AttestationEngine private methods, called on the prototype)
const P = eng.AttestationEngine.prototype;
const R1 = Buffer.from('aa'.repeat(32), 'hex');
const R2 = Buffer.from('bb'.repeat(32), 'hex');
const descs = {
  enum: { type: 'enum', outcomes: ['fulfilled', 'defaulted', 'expired'] },
  binary: { type: 'binary', outcomes: ['paid', 'unpaid'] },
  numeric: { type: 'numeric', base: 2, numDigits: 8, unit: 'USD', precision: 0, signed: true },
};
out.announcement = [];
for (const [name, d] of Object.entries(descs)) {
  const n = P.calculateNoncesNeeded.call(null, d);
  const nonces = [R1, R2, R1, R2, R1, R2, R1, R2, R1].slice(0, n);
  const data = P.serializeAnnouncementData.call(null, 'evt-' + name, d, 1893456000, nonces);
  out.announcement.push({
    name,
    event_id: 'evt-' + name,
    descriptor_json: JSON.stringify(d),
    maturity: 1893456000,
    nonce_count: n,
    nonce_points: nonces.map(hex),
    data: hex(data),
    digest: hex(th.hashAnnouncement(data)),
  });
}

// 3. numeric decomposition (signOutcomes replaced by an identity recorder; the decomposition code is legacy)
const e = new eng.AttestationEngine({ network: { coinType: 1 }, keyProvider: {} });
e.signOutcomes = async (_a, outcomes) => ({ outcomes });
const ann = (d) => ({ descriptor: d });
out.numeric_decomposition = [];
for (const [v, d] of [
  [5, { type: 'numeric', base: 2, numDigits: 8, signed: true }],
  [-5, { type: 'numeric', base: 2, numDigits: 8, signed: true }],
  [0, { type: 'numeric', base: 2, numDigits: 4, signed: false }],
  [255, { type: 'numeric', base: 2, numDigits: 8, signed: false }],
  [256, { type: 'numeric', base: 2, numDigits: 8, signed: false }],
  [1234, { type: 'numeric', base: 10, numDigits: 6, signed: true }],
  [10, { type: 'numeric', base: 16, numDigits: 2, signed: false }],
]) {
  let r;
  try {
    r = (await e.attestNumeric(ann({ ...d }), v)).outcomes;
  } catch (err) {
    r = { error: err.message };
  }
  out.numeric_decomposition.push({ value: v, base: d.base, num_digits: d.numDigits, signed: d.signed, outcomes: r });
}
// legacy defect probes: fractional / NaN input does not fail closed
out.numeric_defect_probes = [];
for (const v of [1.5, NaN]) {
  let r;
  try {
    r = (await e.attestNumeric(ann({ type: 'numeric', base: 2, numDigits: 8, signed: false }), v)).outcomes;
  } catch (err) {
    r = { error: err.message };
  }
  out.numeric_defect_probes.push({ value: String(v), outcomes: r });
}

// 4. handshake
const reg = new hs.ArkTemplateRegistry();
const tpl = (over = {}) => ({
  version: 1,
  network: 'bitcoin-mainnet',
  internalKey: '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
  leafScripts: ['20<user_pk>ac20<server_pk>ac', '20<user_pk>ac02f003b2', '20<server_pk>ac02d007b2'],
  leafVersions: [0xc0, 0xc0, 0xc0],
  leafRoles: ['batch-settle', 'user-exit', 'asp-forfeit'],
  timeouts: { userExitCsv: 1008, aspForfeitCsv: 2000 },
  semantics: {
    userExit: 'Unilateral user exit after CSV timeout',
    batchSettle: 'Cooperative spend by user and server',
    aspForfeit: 'Server claims funds if user misbehaves',
  },
  merkleRoot: '00'.repeat(32),
  ...over,
});
const t1 = tpl();
const t2 = tpl({ leafScripts: t1.leafScripts.slice().reverse() }); // different script/role pairing, same legacy id
const t3 = tpl({ network: 'bitcoin-regtest', merkleRoot: 'ab'.repeat(32) });
out.template_id = [
  ['sample', t1],
  ['scripts_reversed_roles_unchanged', t2],
  ['regtest_root_ab', t3],
].map(([name, t]) => ({
  name,
  template: t,
  canonical_timeouts: JSON.stringify(reg.canonicalJSON(t.timeouts)),
  canonical_semantics: JSON.stringify(reg.canonicalJSON(t.semantics)),
  id: reg.computeTemplateId(t),
}));
out.canonical_json = [{ a: 1, b: { z: [3, { y: 1, x: 2 }], a: 'q"\\\n' }, c: null }, [], 'x'].map((v) => ({
  input: JSON.stringify(v),
  out: JSON.stringify(reg.canonicalJSON(v)),
}));
out.placeholder_taproot_key = {
  internal_key: t1.internalKey,
  merkle_root: t1.merkleRoot,
  out: reg.computeTaprootOutputKey(t1.internalKey, t1.merkleRoot),
};
const rec = new hs.ArkDepositRecognizer(reg);
const spk = (h) => {
  try {
    const r = rec.decodeSegwitOutput(h);
    return { version: r.version, program: hex(r.program) };
  } catch (err) {
    return { error: err.message };
  }
};
out.decode_segwit = [
  '5120' + 'cd'.repeat(32),
  '5120' + 'cd'.repeat(32) + 'ff',
  '0014' + '11'.repeat(20),
  '51',
  '6a',
  '5120' + 'cd'.repeat(31),
  '5220' + 'cd'.repeat(32),
  '0020' + 'ee'.repeat(32),
].map((h) => ({ script: h, out: spk(h) }));
const ex = new hs.ArkExitRecognizer(reg);
const leaf = Buffer.from('20' + '11'.repeat(32) + 'ac', 'hex');
const cb = Buffer.concat([Buffer.from([0xc0]), Buffer.from('22'.repeat(32), 'hex'), Buffer.from('33'.repeat(32), 'hex')]);
out.legacy_reconstruct = ex.reconstructTaprootKey(leaf, cb);
out.legacy_reconstruct.leaf = hex(leaf);
out.legacy_reconstruct.control_block = hex(cb);
out.compact_size = [0, 1, 252, 253, 300, 70000].map((n) => {
  try {
    return { n, out: hex(ex.compactSize(n)) };
  } catch (err) {
    return { n, error: err.constructor.name };
  }
});
console.warn = origWarn;
console.log = origLog;
process.stdout.write(JSON.stringify(out, null, 1) + '\n');
fs.rmSync(tmp, { recursive: true, force: true });
