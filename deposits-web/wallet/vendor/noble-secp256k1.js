// node_modules/@noble/secp256k1/index.js
var B256 = 2n ** 256n;
var P = B256 - 0x1000003d1n;
var N = B256 - 0x14551231950b75fc4402da1732fc9bebfn;
var Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
var Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;
var CURVE = {
  p: P,
  n: N,
  a: 0n,
  b: 7n,
  Gx,
  Gy
};
var fLen = 32;
var curve = (x) => M(M(x * x) * x + CURVE.b);
var err = (m = "") => {
  throw new Error(m);
};
var isB = (n) => typeof n === "bigint";
var isS = (s) => typeof s === "string";
var fe = (n) => isB(n) && 0n < n && n < P;
var ge = (n) => isB(n) && 0n < n && n < N;
var isu8 = (a) => a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array";
var au8 = (a, l) => (
  // assert is Uint8Array (of specific length)
  !isu8(a) || typeof l === "number" && l > 0 && a.length !== l ? err("Uint8Array expected") : a
);
var u8n = (data) => new Uint8Array(data);
var toU8 = (a, len) => au8(isS(a) ? h2b(a) : u8n(au8(a)), len);
var M = (a, b = P) => {
  const r = a % b;
  return r >= 0n ? r : b + r;
};
var aPoint = (p) => p instanceof Point ? p : err("Point expected");
var Point = class _Point {
  constructor(px, py, pz) {
    this.px = px;
    this.py = py;
    this.pz = pz;
    Object.freeze(this);
  }
  /** Create 3d xyz point from 2d xy. (0, 0) => (0, 1, 0), not (0, 0, 1) */
  static fromAffine(p) {
    return p.x === 0n && p.y === 0n ? I : new _Point(p.x, p.y, 1n);
  }
  /** Convert Uint8Array or hex string to Point. */
  static fromHex(hex) {
    hex = toU8(hex);
    let p = void 0;
    const head = hex[0], tail = hex.subarray(1);
    const x = slc(tail, 0, fLen), len = hex.length;
    if (len === 33 && [2, 3].includes(head)) {
      if (!fe(x))
        err("Point hex invalid: x not FE");
      let y = sqrt(curve(x));
      const isYOdd = (y & 1n) === 1n;
      const headOdd = (head & 1) === 1;
      if (headOdd !== isYOdd)
        y = M(-y);
      p = new _Point(x, y, 1n);
    }
    if (len === 65 && head === 4)
      p = new _Point(x, slc(tail, fLen, 2 * fLen), 1n);
    return p ? p.ok() : err("Point invalid: not on curve");
  }
  /** Create point from a private key. */
  static fromPrivateKey(k) {
    return G.mul(toPriv(k));
  }
  get x() {
    return this.aff().x;
  }
  // .x, .y will call expensive toAffine:
  get y() {
    return this.aff().y;
  }
  // should be used with care.
  /** Equality check: compare points P&Q. */
  equals(other) {
    const { px: X1, py: Y1, pz: Z1 } = this;
    const { px: X2, py: Y2, pz: Z2 } = aPoint(other);
    const X1Z2 = M(X1 * Z2), X2Z1 = M(X2 * Z1);
    const Y1Z2 = M(Y1 * Z2), Y2Z1 = M(Y2 * Z1);
    return X1Z2 === X2Z1 && Y1Z2 === Y2Z1;
  }
  /** Flip point over y coordinate. */
  negate() {
    return new _Point(this.px, M(-this.py), this.pz);
  }
  /** Point doubling: P+P, complete formula. */
  double() {
    return this.add(this);
  }
  /**
   * Point addition: P+Q, complete, exception-free formula
   * (Renes-Costello-Batina, algo 1 of [2015/1060](https://eprint.iacr.org/2015/1060)).
   * Cost: 12M + 0S + 3*a + 3*b3 + 23add.
   */
  add(other) {
    const { px: X1, py: Y1, pz: Z1 } = this;
    const { px: X2, py: Y2, pz: Z2 } = aPoint(other);
    const { a, b } = CURVE;
    let X3 = 0n, Y3 = 0n, Z3 = 0n;
    const b3 = M(b * 3n);
    let t0 = M(X1 * X2), t1 = M(Y1 * Y2), t2 = M(Z1 * Z2), t3 = M(X1 + Y1);
    let t4 = M(X2 + Y2);
    t3 = M(t3 * t4);
    t4 = M(t0 + t1);
    t3 = M(t3 - t4);
    t4 = M(X1 + Z1);
    let t5 = M(X2 + Z2);
    t4 = M(t4 * t5);
    t5 = M(t0 + t2);
    t4 = M(t4 - t5);
    t5 = M(Y1 + Z1);
    X3 = M(Y2 + Z2);
    t5 = M(t5 * X3);
    X3 = M(t1 + t2);
    t5 = M(t5 - X3);
    Z3 = M(a * t4);
    X3 = M(b3 * t2);
    Z3 = M(X3 + Z3);
    X3 = M(t1 - Z3);
    Z3 = M(t1 + Z3);
    Y3 = M(X3 * Z3);
    t1 = M(t0 + t0);
    t1 = M(t1 + t0);
    t2 = M(a * t2);
    t4 = M(b3 * t4);
    t1 = M(t1 + t2);
    t2 = M(t0 - t2);
    t2 = M(a * t2);
    t4 = M(t4 + t2);
    t0 = M(t1 * t4);
    Y3 = M(Y3 + t0);
    t0 = M(t5 * t4);
    X3 = M(t3 * X3);
    X3 = M(X3 - t0);
    t0 = M(t3 * t1);
    Z3 = M(t5 * Z3);
    Z3 = M(Z3 + t0);
    return new _Point(X3, Y3, Z3);
  }
  mul(n, safe = true) {
    if (!safe && n === 0n)
      return I;
    if (!ge(n))
      err("scalar invalid");
    if (this.equals(G))
      return wNAF(n).p;
    let p = I, f = G;
    for (let d = this; n > 0n; d = d.double(), n >>= 1n) {
      if (n & 1n)
        p = p.add(d);
      else if (safe)
        f = f.add(d);
    }
    return p;
  }
  mulAddQUns(R, u1, u2) {
    return this.mul(u1, false).add(R.mul(u2, false)).ok();
  }
  // to private keys. Doesn't use Shamir trick
  /** Convert point to 2d xy affine point. (x, y, z) ∋ (x=x/z, y=y/z) */
  toAffine() {
    const { px: x, py: y, pz: z } = this;
    if (this.equals(I))
      return { x: 0n, y: 0n };
    if (z === 1n)
      return { x, y };
    const iz = inv(z, P);
    if (M(z * iz) !== 1n)
      err("inverse invalid");
    return { x: M(x * iz), y: M(y * iz) };
  }
  /** Checks if the point is valid and on-curve. */
  assertValidity() {
    const { x, y } = this.aff();
    if (!fe(x) || !fe(y))
      err("Point invalid: x or y");
    return M(y * y) === curve(x) ? (
      // y² = x³ + ax + b, must be equal
      this
    ) : err("Point invalid: not on curve");
  }
  multiply(n) {
    return this.mul(n);
  }
  // Aliases to compress code
  aff() {
    return this.toAffine();
  }
  ok() {
    return this.assertValidity();
  }
  toHex(isCompressed = true) {
    const { x, y } = this.aff();
    const head = isCompressed ? (y & 1n) === 0n ? "02" : "03" : "04";
    return head + n2h(x) + (isCompressed ? "" : n2h(y));
  }
  toRawBytes(isCompressed = true) {
    return h2b(this.toHex(isCompressed));
  }
};
Point.BASE = new Point(Gx, Gy, 1n);
Point.ZERO = new Point(0n, 1n, 0n);
var { BASE: G, ZERO: I } = Point;
var padh = (n, pad) => n.toString(16).padStart(pad, "0");
var b2h = (b) => Array.from(au8(b)).map((e) => padh(e, 2)).join("");
var C = { _0: 48, _9: 57, A: 65, F: 70, a: 97, f: 102 };
var _ch = (ch) => {
  if (ch >= C._0 && ch <= C._9)
    return ch - C._0;
  if (ch >= C.A && ch <= C.F)
    return ch - (C.A - 10);
  if (ch >= C.a && ch <= C.f)
    return ch - (C.a - 10);
  return;
};
var h2b = (hex) => {
  const e = "hex invalid";
  if (!isS(hex))
    return err(e);
  const hl = hex.length, al = hl / 2;
  if (hl % 2)
    return err(e);
  const array = u8n(al);
  for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {
    const n1 = _ch(hex.charCodeAt(hi));
    const n2 = _ch(hex.charCodeAt(hi + 1));
    if (n1 === void 0 || n2 === void 0)
      return err(e);
    array[ai] = n1 * 16 + n2;
  }
  return array;
};
var b2n = (b) => BigInt("0x" + (b2h(b) || "0"));
var slc = (b, from, to) => b2n(b.slice(from, to));
var n2b = (num) => {
  return isB(num) && num >= 0n && num < B256 ? h2b(padh(num, 2 * fLen)) : err("bigint expected");
};
var n2h = (num) => b2h(n2b(num));
var concatB = (...arrs) => {
  const r = u8n(arrs.reduce((sum, a) => sum + au8(a).length, 0));
  let pad = 0;
  arrs.forEach((a) => {
    r.set(a, pad);
    pad += a.length;
  });
  return r;
};
var inv = (num, md) => {
  if (num === 0n || md <= 0n)
    err("no inverse n=" + num + " mod=" + md);
  let a = M(num, md), b = md, x = 0n, y = 1n, u = 1n, v = 0n;
  while (a !== 0n) {
    const q = b / a, r = b % a;
    const m = x - u * q, n = y - v * q;
    b = a, a = r, x = u, y = v, u = m, v = n;
  }
  return b === 1n ? M(x, md) : err("no inverse");
};
var sqrt = (n) => {
  let r = 1n;
  for (let num = n, e = (P + 1n) / 4n; e > 0n; e >>= 1n) {
    if (e & 1n)
      r = r * num % P;
    num = num * num % P;
  }
  return M(r * r) === n ? r : err("sqrt invalid");
};
var toPriv = (p) => {
  if (!isB(p))
    p = b2n(toU8(p, fLen));
  return ge(p) ? p : err("private key invalid 3");
};
var high = (n) => n > N >> 1n;
var getPublicKey = (privKey, isCompressed = true) => {
  return Point.fromPrivateKey(privKey).toRawBytes(isCompressed);
};
var Signature = class _Signature {
  constructor(r, s, recovery) {
    this.r = r;
    this.s = s;
    this.recovery = recovery;
    this.assertValidity();
  }
  // constructed outside.
  /** Create signature from 64b compact (r || s) representation. */
  static fromCompact(hex) {
    hex = toU8(hex, 64);
    return new _Signature(slc(hex, 0, fLen), slc(hex, fLen, 2 * fLen));
  }
  assertValidity() {
    return ge(this.r) && ge(this.s) ? this : err();
  }
  // 0 < r or s < CURVE.n
  /** Create new signature, with added recovery bit. */
  addRecoveryBit(rec) {
    return new _Signature(this.r, this.s, rec);
  }
  hasHighS() {
    return high(this.s);
  }
  normalizeS() {
    return high(this.s) ? new _Signature(this.r, M(-this.s, N), this.recovery) : this;
  }
  /** ECDSA public key recovery. Requires msg hash and recovery id. */
  recoverPublicKey(msgh) {
    const { r, s, recovery: rec } = this;
    if (![0, 1, 2, 3].includes(rec))
      err("recovery id invalid");
    const h = bits2int_modN(toU8(msgh, fLen));
    const radj = rec === 2 || rec === 3 ? r + N : r;
    if (radj >= P)
      err("q.x invalid");
    const head = (rec & 1) === 0 ? "02" : "03";
    const R = Point.fromHex(head + n2h(radj));
    const ir = inv(radj, N);
    const u1 = M(-h * ir, N);
    const u2 = M(s * ir, N);
    return G.mulAddQUns(R, u1, u2);
  }
  /** Uint8Array 64b compact (r || s) representation. */
  toCompactRawBytes() {
    return h2b(this.toCompactHex());
  }
  /** Hex string 64b compact (r || s) representation. */
  toCompactHex() {
    return n2h(this.r) + n2h(this.s);
  }
};
var bits2int = (bytes) => {
  const delta = bytes.length * 8 - 256;
  if (delta > 1024)
    err("msg invalid");
  const num = b2n(bytes);
  return delta > 0 ? num >> BigInt(delta) : num;
};
var bits2int_modN = (bytes) => {
  return M(bits2int(bytes), N);
};
var i2o = (num) => n2b(num);
var cr = () => (
  // We support: 1) browsers 2) node.js 19+ 3) deno, other envs with crypto
  typeof globalThis === "object" && "crypto" in globalThis ? globalThis.crypto : void 0
);
var _hmacSync;
var optS = { lowS: true };
var optV = { lowS: true };
var prepSig = (msgh, priv, opts = optS) => {
  if (["der", "recovered", "canonical"].some((k) => k in opts))
    err("option not supported");
  let { lowS } = opts;
  if (lowS == null)
    lowS = true;
  const h1i = bits2int_modN(toU8(msgh));
  const h1o = i2o(h1i);
  const d = toPriv(priv);
  const seed = [i2o(d), h1o];
  let ent = opts.extraEntropy;
  if (ent)
    seed.push(ent === true ? etc.randomBytes(fLen) : toU8(ent));
  const m = h1i;
  const k2sig = (kBytes) => {
    const k = bits2int(kBytes);
    if (!ge(k))
      return;
    const ik = inv(k, N);
    const q = G.mul(k).aff();
    const r = M(q.x, N);
    if (r === 0n)
      return;
    const s = M(ik * M(m + M(d * r, N), N), N);
    if (s === 0n)
      return;
    let normS = s;
    let rec = (q.x === r ? 0 : 2) | Number(q.y & 1n);
    if (lowS && high(s)) {
      normS = M(-s, N);
      rec ^= 1;
    }
    return new Signature(r, normS, rec);
  };
  return { seed: concatB(...seed), k2sig };
};
function hmacDrbg(asynchronous) {
  let v = u8n(fLen);
  let k = u8n(fLen);
  let i = 0;
  const reset = () => {
    v.fill(1);
    k.fill(0);
    i = 0;
  };
  const _e = "drbg: tried 1000 values";
  if (asynchronous) {
    const h = (...b) => etc.hmacSha256Async(k, v, ...b);
    const reseed = async (seed = u8n()) => {
      k = await h(u8n([0]), seed);
      v = await h();
      if (seed.length === 0)
        return;
      k = await h(u8n([1]), seed);
      v = await h();
    };
    const gen = async () => {
      if (i++ >= 1e3)
        err(_e);
      v = await h();
      return v;
    };
    return async (seed, pred) => {
      reset();
      await reseed(seed);
      let res = void 0;
      while (!(res = pred(await gen())))
        await reseed();
      reset();
      return res;
    };
  } else {
    const h = (...b) => {
      const f = _hmacSync;
      if (!f)
        err("etc.hmacSha256Sync not set");
      return f(k, v, ...b);
    };
    const reseed = (seed = u8n()) => {
      k = h(u8n([0]), seed);
      v = h();
      if (seed.length === 0)
        return;
      k = h(u8n([1]), seed);
      v = h();
    };
    const gen = () => {
      if (i++ >= 1e3)
        err(_e);
      v = h();
      return v;
    };
    return (seed, pred) => {
      reset();
      reseed(seed);
      let res = void 0;
      while (!(res = pred(gen())))
        reseed();
      reset();
      return res;
    };
  }
}
var signAsync = async (msgh, priv, opts = optS) => {
  const { seed, k2sig } = prepSig(msgh, priv, opts);
  return hmacDrbg(true)(seed, k2sig);
};
var sign = (msgh, priv, opts = optS) => {
  const { seed, k2sig } = prepSig(msgh, priv, opts);
  return hmacDrbg(false)(seed, k2sig);
};
var verify = (sig, msgh, pub, opts = optV) => {
  let { lowS } = opts;
  if (lowS == null)
    lowS = true;
  if ("strict" in opts)
    err("option not supported");
  let sig_, h, P2;
  const rs = sig && typeof sig === "object" && "r" in sig;
  if (!rs && toU8(sig).length !== 2 * fLen)
    err("signature must be 64 bytes");
  try {
    sig_ = rs ? new Signature(sig.r, sig.s).assertValidity() : Signature.fromCompact(sig);
    h = bits2int_modN(toU8(msgh));
    P2 = pub instanceof Point ? pub.ok() : Point.fromHex(pub);
  } catch (e) {
    return false;
  }
  if (!sig_)
    return false;
  const { r, s } = sig_;
  if (lowS && high(s))
    return false;
  let R;
  try {
    const is = inv(s, N);
    const u1 = M(h * is, N);
    const u2 = M(r * is, N);
    R = G.mulAddQUns(P2, u1, u2).aff();
  } catch (error) {
    return false;
  }
  if (!R)
    return false;
  const v = M(R.x, N);
  return v === r;
};
var getSharedSecret = (privA, pubB, isCompressed = true) => {
  return Point.fromHex(pubB).mul(toPriv(privA)).toRawBytes(isCompressed);
};
var hashToPrivateKey = (hash) => {
  hash = toU8(hash);
  if (hash.length < fLen + 8 || hash.length > 1024)
    err("expected 40-1024b");
  const num = M(b2n(hash), N - 1n);
  return n2b(num + 1n);
};
var etc = {
  hexToBytes: h2b,
  bytesToHex: b2h,
  concatBytes: concatB,
  bytesToNumberBE: b2n,
  numberToBytesBE: n2b,
  mod: M,
  invert: inv,
  // math utilities
  hmacSha256Async: async (key, ...msgs) => {
    const c = cr();
    const s = c && c.subtle;
    if (!s)
      return err("etc.hmacSha256Async or crypto.subtle must be defined");
    const k = await s.importKey("raw", key, { name: "HMAC", hash: { name: "SHA-256" } }, false, ["sign"]);
    return u8n(await s.sign("HMAC", k, concatB(...msgs)));
  },
  hmacSha256Sync: _hmacSync,
  // For TypeScript. Actual logic is below
  hashToPrivateKey,
  randomBytes: (len = 32) => {
    const crypto = cr();
    if (!crypto || !crypto.getRandomValues)
      err("crypto.getRandomValues must be defined");
    return crypto.getRandomValues(u8n(len));
  }
};
var utils = {
  normPrivateKeyToScalar: toPriv,
  isValidPrivateKey: (key) => {
    try {
      return !!toPriv(key);
    } catch (e) {
      return false;
    }
  },
  randomPrivateKey: () => hashToPrivateKey(etc.randomBytes(fLen + 16)),
  // FIPS 186 B.4.1.
  precompute: (w = 8, p = G) => {
    p.multiply(3n);
    w;
    return p;
  }
  // no-op
};
Object.defineProperties(etc, { hmacSha256Sync: {
  configurable: false,
  get() {
    return _hmacSync;
  },
  set(f) {
    if (!_hmacSync)
      _hmacSync = f;
  }
} });
var W = 8;
var precompute = () => {
  const points = [];
  const windows = 256 / W + 1;
  let p = G, b = p;
  for (let w = 0; w < windows; w++) {
    b = p;
    points.push(b);
    for (let i = 1; i < 2 ** (W - 1); i++) {
      b = b.add(p);
      points.push(b);
    }
    p = b.double();
  }
  return points;
};
var Gpows = void 0;
var wNAF = (n) => {
  const comp = Gpows || (Gpows = precompute());
  const neg = (cnd, p2) => {
    let n2 = p2.negate();
    return cnd ? n2 : p2;
  };
  let p = I, f = G;
  const windows = 1 + 256 / W;
  const wsize = 2 ** (W - 1);
  const mask = BigInt(2 ** W - 1);
  const maxNum = 2 ** W;
  const shiftBy = BigInt(W);
  for (let w = 0; w < windows; w++) {
    const off = w * wsize;
    let wbits = Number(n & mask);
    n >>= shiftBy;
    if (wbits > wsize) {
      wbits -= maxNum;
      n += 1n;
    }
    const off1 = off, off2 = off + Math.abs(wbits) - 1;
    const cnd1 = w % 2 !== 0, cnd2 = wbits < 0;
    if (wbits === 0) {
      f = f.add(neg(cnd1, comp[off1]));
    } else {
      p = p.add(neg(cnd2, comp[off2]));
    }
  }
  return { p, f };
};
export {
  CURVE,
  Point as ProjectivePoint,
  Signature,
  etc,
  getPublicKey,
  getSharedSecret,
  sign,
  signAsync,
  utils,
  verify
};
/*! Bundled license information:

@noble/secp256k1/index.js:
  (*! noble-secp256k1 - MIT License (c) 2019 Paul Miller (paulmillr.com) *)
*/
