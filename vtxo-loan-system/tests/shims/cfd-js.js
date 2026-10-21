/**
 * TEST-ONLY shim for the `cfd-js` package.
 *
 * `cfd-js` (pinned in package.json) has been unpublished from npm, so the
 * dependency cannot be installed anywhere. This shim implements the exact
 * API surface used by `src/crypto/bitcoin-primitives.ts` with standard,
 * spec-compliant BIP-340 signatures so the behavioral test suite and the
 * red-team harness can run.
 *
 * All curve/point operations are delegated to `tiny-secp256k1` (a real,
 * audited dependency of this project); only the BIP-340 signature algebra
 * (challenge/scalar arithmetic) is assembled here. The signatures produced
 * verify against any standard BIP-340 implementation.
 *
 * It is mapped in only via jest `moduleNameMapper` / the harness module
 * hook. It is NOT a production substitute for cfd-js.
 */

"use strict";

const crypto = require("crypto");
const ecc = require("tiny-secp256k1");

// secp256k1 domain parameters
const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const GX = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
const GY = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;

const G_COMPRESSED = Buffer.concat([
  Buffer.from([0x02 + Number(GY & 1n)]),
  toBuf32(GX),
]);

function toBuf32(value) {
  const hex = value.toString(16).padStart(64, "0");
  return Buffer.from(hex, "hex");
}

function toHex32(value) {
  return toBuf32(value).toString("hex");
}

function asBuf(value) {
  if (Buffer.isBuffer(value)) return value;
  return Buffer.from(value, "hex");
}

function taggedHash(tag, ...parts) {
  const tagHash = crypto.createHash("sha256").update(tag, "utf8").digest();
  const h = crypto.createHash("sha256");
  h.update(tagHash);
  h.update(tagHash);
  for (const part of parts) h.update(part);
  return h.digest();
}

function sha256(...parts) {
  const h = crypto.createHash("sha256");
  for (const part of parts) h.update(part);
  return h.digest();
}

function compressedFromPoint(point) {
  if (point === null || point === undefined) return null;
  return Buffer.from(point);
}

/** x-only lift: returns 33-byte compressed point with the given x, or null */
function liftX(x) {
  if (x >= P) return null;
  const y2 = (x * x * x + 7n) % P;
  let y = modPow(y2, (P + 1n) / 4n, P);
  if (y * y % P !== y2) return null;
  if (y & 1n) y = P - y; // BIP-340 lift_x returns the even-y point
  return Buffer.concat([Buffer.from([0x02]), toBuf32(x)]);
}

function modPow(base, exp, mod) {
  let result = 1n;
  base %= mod;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod;
    base = (base * base) % mod;
    exp >>= 1n;
  }
  return result;
}

function scalarFromBuf(buf) {
  return BigInt("0x" + asBuf(buf).toString("hex"));
}

/** BIP-340 signing with an explicit nonce k (cfd-js SchnorrSign isNonce:true) */
function signWithNonce(privHex, messageHex, nonceHex) {
  const dBuf = asBuf(privHex);
  const mBuf = asBuf(messageHex);
  const kBuf = asBuf(nonceHex);
  if (dBuf.length !== 32) throw new Error("privkey must be 32 bytes");
  if (mBuf.length !== 32) throw new Error("message must be 32 bytes");
  if (kBuf.length !== 32) throw new Error("nonce must be 32 bytes");

  const d0 = scalarFromBuf(dBuf);
  if (d0 === 0n || d0 >= N) throw new Error("invalid private key");

  const Ppoint = compressedFromPoint(ecc.pointFromScalar(dBuf));
  const d = Ppoint[0] === 0x03 ? N - d0 : d0;
  const px = Ppoint.slice(1);

  const k0 = scalarFromBuf(kBuf);
  const Rpoint = compressedFromPoint(ecc.pointMultiply(G_COMPRESSED, kBuf));
  if (Rpoint === null) throw new Error("invalid nonce");
  const k = Rpoint[0] === 0x03 ? N - k0 : k0;
  if (k === 0n) throw new Error("invalid nonce");

  const e = scalarFromBuf(taggedHash("BIP0340/challenge", Rpoint.slice(1), px, mBuf)) % N;
  const s = (k + e * d) % N;

  return Buffer.concat([Rpoint.slice(1), toBuf32(s)]).toString("hex");
}

/** BIP-340 signing with standard aux-randomness (cfd-js SchnorrSign isNonce:false) */
function signWithAux(privHex, messageHex, auxHex) {
  const dBuf = asBuf(privHex);
  const mBuf = asBuf(messageHex);
  const aux = asBuf(auxHex);
  const Ppoint = compressedFromPoint(ecc.pointFromScalar(dBuf));
  // BIP-340 default signing: the XOR mask uses the even-Y normalized secret key
  // (d = n - d' when P has odd Y), not the raw key. Using the raw key produced
  // valid but non-canonical signatures for every odd-Y key.
  const d0 = scalarFromBuf(dBuf);
  const dEven = Ppoint[0] === 0x03 ? N - d0 : d0;
  const t = xor32(dEven, scalarFromBuf(taggedHash("BIP0340/aux", aux)));
  const rand = taggedHash("BIP0340/nonce", toBuf32(t), Ppoint.slice(1), mBuf);
  const k = scalarFromBuf(rand) % N;
  if (k === 0n) throw new Error("invalid derived nonce");
  return signWithNonce(privHex, messageHex, toHex32(k));
}

function xor32(a, b) {
  return a ^ b;
}

/** Standard BIP-340 verification */
function verifySchnorr(pubXHex, messageHex, signatureHex) {
  try {
    const pkBuf = asBuf(pubXHex);
    const mBuf = asBuf(messageHex);
    const sig = asBuf(signatureHex);
    if (pkBuf.length !== 32 || mBuf.length !== 32 || sig.length !== 64) return false;

    const r = scalarFromBuf(sig.slice(0, 32));
    const s = scalarFromBuf(sig.slice(32));
    if (r >= P || s >= N) return false;

    const point = liftX(scalarFromBuf(pkBuf));
    if (point === null) return false;

    const e = scalarFromBuf(taggedHash("BIP0340/challenge", sig.slice(0, 32), pkBuf, mBuf)) % N;
    const negE = toBuf32((N - e) % N);
    const sG = ecc.pointMultiply(G_COMPRESSED, toBuf32(s));
    const eP = ecc.pointMultiply(point, negE);
    if (sG === null || eP === null) return false;
    const R = compressedFromPoint(ecc.pointAdd(sG, eP));
    if (R === null) return false;
    if (R[0] !== 0x02) return false; // BIP-340 requires even-y R
    return scalarFromBuf(R.slice(1)) === r;
  } catch (e) {
    return false;
  }
}

function requireString(value, what) {
  if (typeof value !== "string") throw new Error(`${what} must be a hex string`);
  return value;
}

const cfdjs = {
  CreateKeyPair(request) {
    const privkey = crypto.randomBytes(32);
    const d = scalarFromBuf(privkey);
    if (d === 0n || d >= N) return cfdjs.CreateKeyPair(request);
    const pub = compressedFromPoint(ecc.pointFromScalar(privkey));
    return {
      privkey: privkey.toString("hex"),
      pubkey: pub.toString("hex"),
      wif: undefined,
    };
  },

  GetPubkeyFromPrivkey(request) {
    const privkey = requireString(request.privkey, "privkey");
    const pub = compressedFromPoint(ecc.pointFromScalar(asBuf(privkey)));
    if (pub === null) throw new Error("invalid private key");
    return { pubkey: pub.toString("hex") };
  },

  GetSchnorrPubkeyFromPrivkey(request) {
    const privkey = requireString(request.privkey, "privkey");
    const pub = compressedFromPoint(ecc.pointFromScalar(asBuf(privkey)));
    if (pub === null) throw new Error("invalid private key");
    return { pubkey: pub.slice(1).toString("hex") }; // x-only
  },

  TweakAddPrivkey(request) {
    const privkey = requireString(request.privkey, "privkey");
    const tweak = requireString(request.tweak, "tweak");
    const d = scalarFromBuf(privkey);
    const t = scalarFromBuf(tweak);
    const sum = (d + t) % N;
    if (sum === 0n) throw new Error("tweaked private key is invalid");
    return { privkey: toHex32(sum) };
  },

  SchnorrSign(request) {
    const privkey = requireString(request.privkey, "privkey");
    const message = requireString(request.message, "message");
    const nonceOrAux = requireString(request.nonceOrAux, "nonceOrAux");
    const hex = request.isNonce
      ? signWithNonce(privkey, message, nonceOrAux)
      : signWithAux(privkey, message, nonceOrAux);
    return { hex };
  },

  SchnorrVerify(request) {
    const valid = verifySchnorr(request.pubkey, request.message, request.signature);
    return { valid };
  },

  GetPrivkeyFromWif(request) {
    throw new Error(`cfd-js test shim: GetPrivkeyFromWif not implemented (${request && request.wif})`);
  },

  DecodeRawTransaction(request) {
    throw new Error("cfd-js test shim: DecodeRawTransaction not implemented");
  },

  GetAddressInfo(request) {
    throw new Error("cfd-js test shim: GetAddressInfo not implemented");
  },
};

module.exports = cfdjs;
