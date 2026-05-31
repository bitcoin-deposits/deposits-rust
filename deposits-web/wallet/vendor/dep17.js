// dep-17 operation preimage construction and signing for the web wallet.
//
// Mirrors `third_party/rust-miniscript/src/calculus/encode.rs` (operation_preimage,
// operation_sighash, tagged_hash, put_*) and `deposits-core/src/dep16/operations.rs`
// (to_dep16 for the four signature-bearing variants), then signs the sighash with
// ECDSA via noble-secp256k1 — the algorithm `Dep16Authorizer`'s `EcdsaVerifier`
// checks against.
//
// Wire layout: every signature-bearing op is built as a JS object matching the
// Rust `LedgerOperation` variant's fields (snake_case, msats/sats as documented
// per variant); buildXxxOp helpers wrap the dep-16 OperationData translation;
// signOp(op, secretKey) returns a 64-byte compact ECDSA signature.

import { sha256 } from './noble-hashes-sha256.js';
import { hmac } from './noble-hashes-hmac.js';
import * as secp from './noble-secp256k1.js';

// noble-secp256k1's sync sign() path needs hmacSha256Sync wired up; without
// this, `secp.sign(...)` throws "etc.hmacSha256Sync not set". The async path
// uses crypto.subtle, but dep17.js exposes a sync signOp. Wire once at module
// load so every caller (browser and Node test runner) works the same way.
if (!secp.etc.hmacSha256Sync) {
  secp.etc.hmacSha256Sync = (key, ...msgs) => {
    // Concatenate msg fragments — noble's hmac takes a single message.
    let total = 0;
    for (const m of msgs) total += m.length;
    const buf = new Uint8Array(total);
    let off = 0;
    for (const m of msgs) { buf.set(m, off); off += m.length; }
    return hmac(sha256, key, buf);
  };
}

// ---- low-level encoders ----------------------------------------------------

function concat(...parts) {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

function u32BE(n) {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n >>> 0, false);
  return b;
}

function u64BE(n) {
  // n: BigInt or Number
  const big = typeof n === 'bigint' ? n : BigInt(n);
  const b = new Uint8Array(8);
  const view = new DataView(b.buffer);
  view.setBigUint64(0, big, false);
  return b;
}

// i128 BE (16 bytes). For non-negative values from JS Number ≤ 2^53, the high
// 64 bits are zero. Negatives are encoded in two's complement via 128-bit mask.
function i128BE(n) {
  const big = typeof n === 'bigint' ? n : BigInt(n);
  const mask128 = (1n << 128n) - 1n;
  const norm = big & mask128;
  const lowMask = 0xFFFFFFFFFFFFFFFFn;
  const b = new Uint8Array(16);
  const view = new DataView(b.buffer);
  view.setBigUint64(0, (norm >> 64n) & lowMask, false);
  view.setBigUint64(8, norm & lowMask, false);
  return b;
}

function putBytes(b) {
  return concat(u32BE(b.length), b);
}

// Value tags (match encode.rs put_value):
//   0x00 Int(i128)
//   0x03 Bytes(var)
//   0x06 Symbol(var)
// Other tags (Key/Hash/Path/List/Subtree) aren't used in the four
// signature-bearing variants and are intentionally omitted.
function putValue(v) {
  switch (v.tag) {
    case 'int':    return concat(new Uint8Array([0x00]), i128BE(v.value));
    case 'bytes':  return concat(new Uint8Array([0x03]), putBytes(v.value));
    case 'symbol': return concat(new Uint8Array([0x06]), putBytes(new TextEncoder().encode(v.value)));
    default: throw new Error(`unsupported Value tag: ${v.tag}`);
  }
}

// Pad a 16-byte deposit_id to 32 bytes (zero-extend to match Rust pad_deposit_id).
function padDepositId(d) {
  if (d.length === 32) return d;
  if (d.length !== 16) throw new Error(`deposit_id must be 16 or 32 bytes, got ${d.length}`);
  const out = new Uint8Array(32);
  out.set(d, 0);
  return out;
}

// BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg).
function taggedHash(tag, msg) {
  const tagHash = sha256(new TextEncoder().encode(tag));
  return sha256(concat(tagHash, tagHash, msg));
}

// ---- dep-17 operation preimage --------------------------------------------

// op = { op_type: string, args: {[name]: value}, deposit_id: Uint8Array(16|32),
//        nonce: u64 (Number/BigInt), expiry: u32 (Number) }
function operationPreimage(op) {
  const out = [];
  out.push(new Uint8Array([0x01])); // version
  out.push(padDepositId(op.deposit_id));
  out.push(putBytes(new TextEncoder().encode(op.op_type)));
  const entries = Object.entries(op.args).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0);
  out.push(u32BE(entries.length));
  for (const [name, value] of entries) {
    out.push(putBytes(new TextEncoder().encode(name)));
    out.push(putValue(value));
  }
  out.push(u64BE(op.nonce));
  out.push(u32BE(op.expiry));
  return concat(...out);
}

function operationSighash(preimage) {
  return taggedHash('dep17/operation', preimage);
}

// ---- per-variant op builders ----------------------------------------------

// All buildXxx helpers take a single object whose fields match the wire-side
// LedgerOperation variant (16-byte deposit ids, sats/msats as noted). They
// return an OperationData ready for operationPreimage().

export function buildInvoiceLockOp({deposit_id, amount_msats, payment_id, nonce, expiry}) {
  return {
    op_type: 'spend',
    args: {
      amount:     { tag: 'int',    value: amount_msats },
      kind:       { tag: 'symbol', value: 'invoice' },
      payment_id: { tag: 'bytes',  value: payment_id },
    },
    deposit_id,
    nonce,
    expiry,
  };
}

export function buildOnchainLockOp({deposit_id, amount_msats, fee_sats, destination_address, withdrawal_id, nonce, expiry}) {
  return {
    op_type: 'spend',
    args: {
      amount:        { tag: 'int',    value: amount_msats },
      destination:   { tag: 'bytes',  value: new TextEncoder().encode(destination_address) },
      fee:           { tag: 'int',    value: fee_sats },
      kind:          { tag: 'symbol', value: 'onchain' },
      withdrawal_id: { tag: 'bytes',  value: withdrawal_id },
    },
    deposit_id,
    nonce,
    expiry,
  };
}

export function buildTransferLockOp({transfer_nonce, source_deposit_id, destination_deposit_id, amount_msats, fee_msats, completion_script, timeout_height, transfer_id, nonce, expiry}) {
  return {
    op_type: 'spend',
    args: {
      amount:                  { tag: 'int',    value: amount_msats },
      completion_script:       { tag: 'bytes',  value: new TextEncoder().encode(completion_script) },
      destination_deposit_id:  { tag: 'bytes',  value: destination_deposit_id },
      fee:                     { tag: 'int',    value: fee_msats },
      kind:                    { tag: 'symbol', value: 'transfer' },
      timeout_height:          { tag: 'int',    value: timeout_height },
      transfer_id:             { tag: 'bytes',  value: transfer_id },
      transfer_nonce:          { tag: 'bytes',  value: transfer_nonce },
    },
    deposit_id: source_deposit_id,
    nonce,
    expiry,
  };
}

// Receive-side authorization. Used by `make_invoice` / `make_offer` for
// deposits with `receive_requires_sig`, and the destination-side check
// in a transfer-release. Op shape mirrors `deposits_core::dep16::operations::
// receive_op`: op_type='receive', args carries optional transfer_id only.
//
// Wire format documented in RECEIVE-WITNESS.md at the workspace root.
export function buildReceiveOp({deposit_id, nonce, expiry, transfer_id}) {
  const args = {};
  if (transfer_id !== undefined && transfer_id !== null) {
    args.transfer_id = { tag: 'bytes', value: transfer_id };
  }
  return {
    op_type: 'receive',
    args,
    deposit_id,
    nonce,
    expiry,
  };
}

// ---- signing --------------------------------------------------------------

// Sign the dep-17 sighash of `op` with ECDSA (low-s, deterministic) under
// `secretKey`. Returns a 64-byte compact signature suitable for the
// DescriptorWitness stack — what Dep16Authorizer's EcdsaVerifier checks.
export function signOp(op, secretKey) {
  const preimage = operationPreimage(op);
  const sighash = operationSighash(preimage);
  const sig = secp.sign(sighash, secretKey);
  return sig.toCompactRawBytes();
}

// Convenience: returns the DescriptorWitness JSON shape ({stack: [hex]}) that
// every operator handler expects in the `witness` request param.
export function signOpAsWitness(op, secretKey) {
  const sigBytes = signOp(op, secretKey);
  const hex = Array.from(sigBytes).map(b => b.toString(16).padStart(2, '0')).join('');
  return { stack: [hex] };
}

// Receive-side authorization: signs the receive-op preimage under one or more
// participant keys and returns the ReceiveWitness JSON shape:
//   { nonce, expiry, signatures: { <pubkey-hex>: <sig-hex>, ... } }
//
// `signers` is an iterable of {secretKey: Uint8Array(32), publicKey: Uint8Array(33)}
// — single-key descriptors pass one; threshold descriptors pass one per signing
// participant. Each signs the SAME preimage; the operator-side authorizer accepts
// any combination that satisfies the descriptor's threshold.
//
// Wire format spec: RECEIVE-WITNESS.md (workspace root).
export function signReceiveWitness(op, signers) {
  const preimage = operationPreimage(op);
  const sighash = operationSighash(preimage);
  const signatures = {};
  for (const {secretKey, publicKey} of signers) {
    const sig = secp.sign(sighash, secretKey);
    const sigHex = Array.from(sig.toCompactRawBytes())
      .map(b => b.toString(16).padStart(2, '0')).join('');
    const keyHex = Array.from(publicKey)
      .map(b => b.toString(16).padStart(2, '0')).join('');
    signatures[keyHex] = sigHex;
  }
  return {
    nonce: typeof op.nonce === 'bigint' ? Number(op.nonce) : op.nonce,
    expiry: op.expiry,
    signatures,
  };
}

// Wallet-side helper: pick a fresh u64 op_nonce. The protocol's seen_nonces GC
// only requires uniqueness within the expiry window, so Date.now() (millis
// since epoch, ~1.76e12, well within JS Number's 2^53 safe range) is fine.
// Returns a Number suitable for both arithmetic and JSON.
export function freshOpNonce() {
  return Date.now();
}

// Expose low-level pieces for callers that want them.
export { operationPreimage, operationSighash, taggedHash, padDepositId };
