// Round-trip cross-implementation test.
//
// JS side (vendor/dep17.js) produces a ReceiveWitness JSON; rust side
// (target/release/authorize-receive) validates via Dep16Authorizer. Asserts
// happy path + adversarial inputs match each side's expectations.
//
// Run with: `npm test` (after `cargo build --release --bin authorize-receive`
// from the workspace root). If the binary is missing the test self-skips
// with a clear message rather than failing — saves CI from running into a
// build-order trap.

import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import {
  buildReceiveOp,
  signReceiveWitness,
} from '../vendor/dep17.js';
import * as secp from '../vendor/noble-secp256k1.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, '../../..');
const AUTHORIZE_RECEIVE_BIN = join(REPO_ROOT, 'target/release/authorize-receive');

// Skip the whole file if the binary isn't built yet. CI / dev environments
// without rust still get the rest of the test run.
const BIN_AVAILABLE = existsSync(AUTHORIZE_RECEIVE_BIN);

function toHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/// Spawn the rust verifier. Returns { verdict: 'authorized'|'rejected'|'error', stderr }.
function authorize(witness, { descriptor, depositId, transferId }) {
  const args = [
    '--descriptor', descriptor,
    '--deposit-id', toHex(depositId),
  ];
  if (transferId !== undefined) {
    args.push('--transfer-id', toHex(transferId));
  }
  const result = spawnSync(AUTHORIZE_RECEIVE_BIN, args, {
    input: JSON.stringify(witness),
    encoding: 'utf8',
  });
  if (result.status === 0) return { verdict: 'authorized', stderr: result.stderr };
  if (result.status === 1) return { verdict: 'rejected', stderr: result.stderr };
  return { verdict: 'error', stderr: result.stderr };
}

// Stable single-key test setup. Real wallets generate from BIP-39 / user input;
// fixed bytes here for reproducibility.
function makeSetup(seed = 0x11) {
  const secretKey = new Uint8Array(32).fill(seed);
  const publicKey = secp.getPublicKey(secretKey, true); // compressed
  const descriptor = `wsh(prove(pk(${toHex(publicKey)})))`;
  return { secretKey, publicKey, descriptor };
}

test('round-trip: happy path single-key receive', { skip: !BIN_AVAILABLE && 'authorize-receive binary not built; run `cargo build --release --bin authorize-receive`' }, () => {
  const { secretKey, publicKey, descriptor } = makeSetup(0x11);
  const depositId = new Uint8Array(16).fill(0xCC);
  const op = buildReceiveOp({
    deposit_id: depositId,
    nonce: 1,
    expiry: 0xFFFFFFFF,
  });
  const witness = signReceiveWitness(op, [{ secretKey, publicKey }]);
  const { verdict, stderr } = authorize(witness, { descriptor, depositId });
  assert.equal(verdict, 'authorized', `expected authorized, got ${verdict} (stderr: ${stderr})`);
});

test('round-trip: transfer-release receive with transfer_id', { skip: !BIN_AVAILABLE && 'binary not built' }, () => {
  const { secretKey, publicKey, descriptor } = makeSetup(0x11);
  const depositId = new Uint8Array(16).fill(0xCC);
  const transferId = new Uint8Array(32).fill(0xAB);
  const op = buildReceiveOp({
    deposit_id: depositId,
    nonce: 1,
    expiry: 0xFFFFFFFF,
    transfer_id: transferId,
  });
  const witness = signReceiveWitness(op, [{ secretKey, publicKey }]);
  const { verdict, stderr } = authorize(witness, { descriptor, depositId, transferId });
  assert.equal(verdict, 'authorized', `transfer-release: ${verdict} (stderr: ${stderr})`);
});

test('round-trip: cross-deposit replay rejected', { skip: !BIN_AVAILABLE && 'binary not built' }, () => {
  const { secretKey, publicKey, descriptor } = makeSetup(0x11);
  const depositA = new Uint8Array(16).fill(0xAA);
  const depositB = new Uint8Array(16).fill(0xBB);
  const op = buildReceiveOp({ deposit_id: depositA, nonce: 1, expiry: 0xFFFFFFFF });
  const witness = signReceiveWitness(op, [{ secretKey, publicKey }]);
  // Same witness against deposit B — preimage binds depositA, so rust rebuilds
  // with depositB and signature doesn't match.
  const { verdict } = authorize(witness, { descriptor, depositId: depositB });
  assert.equal(verdict, 'rejected');
});

test('round-trip: cross-transfer replay rejected', { skip: !BIN_AVAILABLE && 'binary not built' }, () => {
  const { secretKey, publicKey, descriptor } = makeSetup(0x11);
  const depositId = new Uint8Array(16).fill(0xCC);
  const transferA = new Uint8Array(32).fill(0xAA);
  const transferB = new Uint8Array(32).fill(0xBB);
  const op = buildReceiveOp({
    deposit_id: depositId,
    nonce: 1,
    expiry: 0xFFFFFFFF,
    transfer_id: transferA,
  });
  const witness = signReceiveWitness(op, [{ secretKey, publicKey }]);
  const { verdict } = authorize(witness, { descriptor, depositId, transferId: transferB });
  assert.equal(verdict, 'rejected');
});

test('round-trip: wrong-key signature rejected', { skip: !BIN_AVAILABLE && 'binary not built' }, () => {
  const { publicKey: ownerPk } = makeSetup(0x11);
  const { secretKey: attackerSk, publicKey: attackerPk } = makeSetup(0x22);
  const descriptor = `wsh(prove(pk(${toHex(ownerPk)})))`;
  const depositId = new Uint8Array(16).fill(0xCC);
  const op = buildReceiveOp({ deposit_id: depositId, nonce: 1, expiry: 0xFFFFFFFF });
  // Sign with attacker, claim to be the owner — descriptor expects ownerPk's key.
  const witness = signReceiveWitness(op, [{ secretKey: attackerSk, publicKey: attackerPk }]);
  const { verdict } = authorize(witness, { descriptor, depositId });
  assert.equal(verdict, 'rejected');
});
