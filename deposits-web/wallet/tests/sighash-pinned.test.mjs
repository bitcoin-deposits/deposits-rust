// Cross-implementation drift detector for dep17.js.
//
// Mirrors the pinned-sighash tests on the rust side
// (deposits-core/tests/dep16_authorizer_test.rs::dep17_*_sighash_pinned)
// against the JS implementation in vendor/dep17.js. If any hash here
// disagrees with rust, the JS port has silently diverged — every signature
// the wallet produces would be rejected by the operator.
//
// Run with: `node --test deposits-web/wallet/tests/`
// (no install step; uses Node's built-in test runner. Requires Node ≥18.)

import { test } from 'node:test';
import { strict as assert } from 'node:assert';

import {
  buildInvoiceLockOp,
  buildReceiveOp,
  operationPreimage,
  operationSighash,
} from '../vendor/dep17.js';

function toHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// The canonical deposit_id used on both sides of the cross-impl pin.
const CANONICAL_DID = new Uint8Array([
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
  0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
]);

test('InvoiceLock sighash matches rust pin', () => {
  const op = buildInvoiceLockOp({
    deposit_id: CANONICAL_DID,
    amount_msats: 100_000,
    payment_id: new Uint8Array(32).fill(0xaa),
    nonce: 42,
    expiry: 0xFFFFFFFF,
  });
  const sighash = operationSighash(operationPreimage(op));
  // Rust pin: deposits-core/tests/dep16_authorizer_test.rs
  //          ::dep17_invoice_lock_sighash_pinned
  assert.equal(
    toHex(sighash),
    '60317ef178dce942d76273d3873c9f7a945906b31209d25db69c72fc4428251c',
    'dep-17 InvoiceLock sighash drifted from rust — update both sides together'
  );
});

test('receive_op sighash (no transfer_id) matches rust pin', () => {
  const op = buildReceiveOp({
    deposit_id: CANONICAL_DID,
    nonce: 42,
    expiry: 0xFFFFFFFF,
  });
  const sighash = operationSighash(operationPreimage(op));
  // Rust pin: deposits-core/tests/dep16_authorizer_test.rs
  //          ::dep17_receive_op_sighash_pinned (no_tx branch)
  assert.equal(
    toHex(sighash),
    'ea8dbd030cbe8b4734dbf277cac107c2db62e47883e02e58c58e4ed1e3b1072e',
    'receive_op (no transfer_id) sighash drifted from rust — update both sides together'
  );
});

test('receive_op sighash (with transfer_id) matches rust pin', () => {
  const op = buildReceiveOp({
    deposit_id: CANONICAL_DID,
    nonce: 42,
    expiry: 0xFFFFFFFF,
    transfer_id: new Uint8Array(32).fill(0xAB),
  });
  const sighash = operationSighash(operationPreimage(op));
  // Rust pin: deposits-core/tests/dep16_authorizer_test.rs
  //          ::dep17_receive_op_sighash_pinned (with_tx branch)
  assert.equal(
    toHex(sighash),
    '9f050992d374b517e322e5e0f62030e73ae71c7c43b20f771ffaa49feaec672a',
    'receive_op (with transfer_id) sighash drifted from rust — update both sides together'
  );
});
