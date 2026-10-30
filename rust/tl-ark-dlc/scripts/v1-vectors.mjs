// Independent (non-Rust) derivation of the v1 message layouts introduced by tl-ark-dlc.
// These are NOT legacy vectors: the legacy code has no event-bound message. They are an
// implementation-independent check of the documented encodings (Node crypto only).
//
//   node scripts/v1-vectors.mjs > fixtures/v1_vectors.json
import crypto from 'node:crypto';

const sha = (b) => crypto.createHash('sha256').update(b).digest();
const tagged = (tag, data) => {
  const t = sha(Buffer.from(tag, 'utf8'));
  return sha(Buffer.concat([t, t, data]));
};
const u32 = (n) => {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n);
  return b;
};
const u64 = (n) => {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(n));
  return b;
};
const lp = (b) => Buffer.concat([u32(b.length), b]);
const hex = (b) => Buffer.from(b).toString('hex');
const sortKeys = (o) =>
  typeof o !== 'object' || o === null
    ? o
    : Array.isArray(o)
      ? o.map(sortKeys)
      : Object.keys(o)
          .sort()
          .reduce((a, k) => ((a[k] = sortKeys(o[k])), a), {});

const out = {};

// attestation digests: pk | lp(event) | annDigest | u32 index | R | lp(outcome)
const att = (pk, ev, ad, idx, r, outcome) =>
  hex(
    tagged(
      'TL/ark-dlc/oracle-attestation/v1',
      Buffer.concat([Buffer.from(pk, 'hex'), lp(Buffer.from(ev)), Buffer.from(ad, 'hex'), u32(idx), Buffer.from(r, 'hex'), lp(Buffer.from(outcome))]),
    ),
  );
const pk = '09'.repeat(32), ad = '01'.repeat(32), r = '02'.repeat(32);
out.attestation_digest = [
  ['event-A', 0, r, 'paid'],
  ['event-B', 0, r, 'paid'],
  ['event-A', 1, r, 'paid'],
  ['ab', 0, r, 'c'],
  ['a', 0, r, 'bc'],
  ['evt-é', 7, '03'.repeat(32), 'défaut'],
].map(([ev, idx, rr, outcome]) => ({ pk, event_id: ev, announcement_digest: ad, index: idx, r: rr, outcome, digest: att(pk, ev, ad, idx, rr, outcome) }));

// descriptor encodings and announcement digests
const encEnum = (o) => Buffer.concat([Buffer.from([1]), u32(o.length), ...o.map((x) => lp(Buffer.from(x)))]);
const encBinary = (a, b) => Buffer.concat([Buffer.from([2]), lp(Buffer.from(a)), lp(Buffer.from(b))]);
const encNumeric = (base, digits, unit, precision, signed) =>
  Buffer.concat([Buffer.from([3, base]), u32(digits), lp(Buffer.from(unit)), Buffer.from([precision, signed ? 1 : 0])]);
const annDigest = (oracle, ev, desc, maturity, nonces) =>
  hex(tagged('TL/ark-dlc/oracle-announcement/v1', Buffer.concat([Buffer.from(oracle, 'hex'), lp(Buffer.from(ev)), lp(desc), u64(maturity), u32(nonces.length), ...nonces.map((n) => Buffer.from(n, 'hex'))])));
const n1 = 'aa'.repeat(32), n2 = 'bb'.repeat(32);
out.announcement = [
  { name: 'enum', event_id: 'evt-enum', desc: encEnum(['fulfilled', 'defaulted', 'expired']), nonces: [n1] },
  { name: 'binary', event_id: 'evt-binary', desc: encBinary('paid', 'unpaid'), nonces: [n2] },
  { name: 'numeric', event_id: 'evt-numeric', desc: encNumeric(2, 2, 'USD', 0, true), nonces: [n1, n2, n1] },
].map((a) => ({ name: a.name, oracle: pk, event_id: a.event_id, maturity: 1893456000, nonces: a.nonces, descriptor_encoding: hex(a.desc), digest: annDigest(pk, a.event_id, a.desc, 1893456000, a.nonces) }));

// template id v2
const tid = (t) => {
  const triples = t.scripts.map((s, i) => ({ s: Buffer.from(s, 'hex'), v: t.versions[i], r: t.roles[i] }));
  triples.sort((x, y) => Buffer.compare(x.s, y.s) || x.v - y.v || (x.r < y.r ? -1 : x.r > y.r ? 1 : 0));
  const body = Buffer.concat([
    u32(t.version), lp(Buffer.from(t.network)), Buffer.from(t.internal, 'hex'), Buffer.from(t.root, 'hex'), u32(triples.length),
    ...triples.map((x) => Buffer.concat([Buffer.from([x.v]), lp(x.s), lp(Buffer.from(x.r))])),
    lp(Buffer.from(JSON.stringify(sortKeys(t.timeouts)))), lp(Buffer.from(JSON.stringify(sortKeys(t.semantics)))),
  ]);
  return hex(tagged('TL/ark-dlc/template/v2', body));
};
const base = {
  version: 1, network: 'bitcoin-regtest',
  internal: '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798', root: 'ab'.repeat(32),
  scripts: ['2011ac', '2022ac', '2033ac'], versions: [0xc0, 0xc0, 0xc0], roles: ['batch-settle', 'user-exit', 'asp-forfeit'],
  timeouts: { userExitCsv: 1008, aspForfeitCsv: 2000 }, semantics: { userExit: 'u', aspForfeit: 'a' },
};
out.template_v2 = [
  { name: 'base', t: base },
  { name: 'reordered_with_roles', t: { ...base, scripts: [...base.scripts].reverse(), versions: [...base.versions].reverse(), roles: [...base.roles].reverse() } },
  { name: 'scripts_swapped_roles_fixed', t: { ...base, scripts: ['2022ac', '2011ac', '2033ac'] } },
  { name: 'mainnet', t: { ...base, network: 'bitcoin-mainnet' } },
].map(({ name, t }) => ({ name, template: t, id: tid(t) }));

process.stdout.write(JSON.stringify(out, null, 1) + '\n');
