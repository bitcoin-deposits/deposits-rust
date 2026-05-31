// Cross-implementation drift detector — browser flavor.
//
// Same pins as tests/sighash-pinned.test.mjs (Node side), but executed
// in real Chromium via the live import of vendor/dep17.js. Catches
// browser-specific regressions the Node tests would miss:
// - TextEncoder/Uint8Array semantics under different runtimes
// - noble-secp256k1's etc.hmacSha256Sync wiring under crypto.subtle
//   environments
// - ESM resolution / vendor chain assumptions
//
// Run with: `npm run test:browser` (from deposits-web/wallet/).

import { test, expect } from '@playwright/test';

const CANONICAL_DID_HEX = '0102030405060708090a0b0c0d0e0f10';

const PINS = {
  invoiceLock: '60317ef178dce942d76273d3873c9f7a945906b31209d25db69c72fc4428251c',
  receiveNoTransfer: 'ea8dbd030cbe8b4734dbf277cac107c2db62e47883e02e58c58e4ed1e3b1072e',
  receiveWithTransfer: '9f050992d374b517e322e5e0f62030e73ae71c7c43b20f771ffaa49feaec672a',
};

async function loadHarness(page) {
  await page.goto('/tests/browser/harness.html');
  await page.waitForFunction(() => window._loaded === true);
}

test.describe('dep17.js cross-impl pins (browser)', () => {
  test.beforeEach(async ({ page }) => {
    await loadHarness(page);
  });

  test('InvoiceLock sighash matches rust pin', async ({ page }) => {
    const sighashHex = await page.evaluate((didHex) => {
      const hexToBytes = (h) => new Uint8Array(
        h.match(/.{2}/g).map((b) => parseInt(b, 16))
      );
      const op = window.dep17.buildInvoiceLockOp({
        deposit_id: hexToBytes(didHex),
        amount_msats: 100_000,
        payment_id: new Uint8Array(32).fill(0xaa),
        nonce: 42,
        expiry: 0xFFFFFFFF,
      });
      const sighash = window.dep17.operationSighash(window.dep17.operationPreimage(op));
      return Array.from(sighash).map((b) => b.toString(16).padStart(2, '0')).join('');
    }, CANONICAL_DID_HEX);
    expect(sighashHex).toBe(PINS.invoiceLock);
  });

  test('receive_op sighash (no transfer_id) matches rust pin', async ({ page }) => {
    const sighashHex = await page.evaluate((didHex) => {
      const hexToBytes = (h) => new Uint8Array(
        h.match(/.{2}/g).map((b) => parseInt(b, 16))
      );
      const op = window.dep17.buildReceiveOp({
        deposit_id: hexToBytes(didHex),
        nonce: 42,
        expiry: 0xFFFFFFFF,
      });
      const sighash = window.dep17.operationSighash(window.dep17.operationPreimage(op));
      return Array.from(sighash).map((b) => b.toString(16).padStart(2, '0')).join('');
    }, CANONICAL_DID_HEX);
    expect(sighashHex).toBe(PINS.receiveNoTransfer);
  });

  test('receive_op sighash (with transfer_id) matches rust pin', async ({ page }) => {
    const sighashHex = await page.evaluate((didHex) => {
      const hexToBytes = (h) => new Uint8Array(
        h.match(/.{2}/g).map((b) => parseInt(b, 16))
      );
      const op = window.dep17.buildReceiveOp({
        deposit_id: hexToBytes(didHex),
        nonce: 42,
        expiry: 0xFFFFFFFF,
        transfer_id: new Uint8Array(32).fill(0xAB),
      });
      const sighash = window.dep17.operationSighash(window.dep17.operationPreimage(op));
      return Array.from(sighash).map((b) => b.toString(16).padStart(2, '0')).join('');
    }, CANONICAL_DID_HEX);
    expect(sighashHex).toBe(PINS.receiveWithTransfer);
  });

  test('signReceiveWitness produces verifiable signature shape', async ({ page }) => {
    const result = await page.evaluate(async (didHex) => {
      const hexToBytes = (h) => new Uint8Array(
        h.match(/.{2}/g).map((b) => parseInt(b, 16))
      );
      const secp = await import('/vendor/noble-secp256k1.js');
      const secretKey = new Uint8Array(32).fill(0x11);
      const publicKey = secp.getPublicKey(secretKey, true);
      const op = window.dep17.buildReceiveOp({
        deposit_id: hexToBytes(didHex),
        nonce: 1,
        expiry: 0xFFFFFFFF,
      });
      const witness = window.dep17.signReceiveWitness(op, [{ secretKey, publicKey }]);
      return {
        nonce: witness.nonce,
        expiry: witness.expiry,
        sigCount: Object.keys(witness.signatures).length,
        firstKeyLen: Object.keys(witness.signatures)[0].length,
        firstSigLen: Object.values(witness.signatures)[0].length,
      };
    }, CANONICAL_DID_HEX);
    expect(result.nonce).toBe(1);
    expect(result.expiry).toBe(0xFFFFFFFF);
    expect(result.sigCount).toBe(1);
    expect(result.firstKeyLen).toBe(66); // 33-byte compressed pk = 66 hex chars
    expect(result.firstSigLen).toBe(128); // 64-byte sig = 128 hex chars
  });
});
