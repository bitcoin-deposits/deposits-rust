// Wallet integration — exercises `maybeBuildReceiveWitness` and the
// deposit-state plumbing in the actual wallet runtime (index.html under
// real Chromium). Catches regressions in the wallet's binding between
// stored deposit records, seed-derived keys, and the dep17 surface that
// only manifest in browser-side execution.
//
// Uses the localhost-guarded `window._test` hook so it runs the same
// module-scoped helpers production callers do — no shim, no duplicated
// code path.

import { test, expect } from '@playwright/test';

async function loadWallet(page) {
  await page.goto('/index.html');
  // Wait for the module to install the localhost test hooks. If it never
  // does, the wallet's module init failed somewhere — surface fast.
  await page.waitForFunction(() => window._test !== undefined, { timeout: 5000 });
}

test.describe('wallet receive-side integration', () => {
  test.beforeEach(async ({ page }) => {
    await loadWallet(page);
  });

  test('maybeBuildReceiveWitness returns null when deposit does not require sig', async ({ page }) => {
    const result = await page.evaluate(() => {
      window._test.setState({
        seed: new Uint8Array(32).fill(0x11),
        keyIndex: 1,
      });
      const deposit = {
        alias: 'noreceive',
        descriptor: 'pk(02000000000000000000000000000000000000000000000000000000000000aaaa)',
        deposit_id: '00112233445566778899aabbccddeeff',
        deposit_pubkey: '02000000000000000000000000000000000000000000000000000000000000aaaa',
        key_index: 0,
        // no receive_requires_sig field — legacy / default
      };
      return window._test.maybeBuildReceiveWitness(deposit);
    });
    expect(result).toBeNull();
  });

  test('maybeBuildReceiveWitness builds a complete witness for a gated deposit', async ({ page }) => {
    const witness = await page.evaluate(() => {
      window._test.setState({
        seed: new Uint8Array(32).fill(0x42),
        keyIndex: 1,
      });
      // Derive what the wallet would: secret at index 0, pubkey, descriptor.
      const sk = window._test.deriveSecretKey(window._test.getState().seed, 0);
      const pk = window._test.getCompressedPubkey(sk);
      const pkHex = Array.from(pk).map((b) => b.toString(16).padStart(2, '0')).join('');
      // The wallet computes deposit_id from the descriptor as SHA256(descriptor)[..16].
      // For the test we just plug in a placeholder — maybeBuildReceiveWitness uses
      // it directly without re-checking it matches the descriptor.
      const deposit = {
        alias: 'gated',
        descriptor: `pk(${pkHex})`,
        deposit_id: '00112233445566778899aabbccddeeff',
        deposit_pubkey: pkHex,
        key_index: 0,
        receive_requires_sig: true,
      };
      return window._test.maybeBuildReceiveWitness(deposit);
    });

    expect(witness).not.toBeNull();
    expect(typeof witness.nonce).toBe('number');
    expect(witness.expiry).toBe(0xFFFFFFFF);
    expect(typeof witness.signatures).toBe('object');
    const keys = Object.keys(witness.signatures);
    expect(keys.length).toBe(1);
    expect(keys[0].length).toBe(66); // 33-byte compressed pubkey hex
    expect(witness.signatures[keys[0]].length).toBe(128); // 64-byte ECDSA hex
  });

  test('witness signature is over the actual receive_op preimage', async ({ page }) => {
    // End-to-end binding check: build a witness via the wallet, then independently
    // reconstruct the expected preimage and verify the produced signature against it.
    // If the wallet ever drifts from the spec'd preimage construction this fails
    // loud before signatures start being rejected by the operator.
    const result = await page.evaluate(async () => {
      const secp = await import('/vendor/noble-secp256k1.js');
      window._test.setState({ seed: new Uint8Array(32).fill(0x42), keyIndex: 1 });
      const sk = window._test.deriveSecretKey(window._test.getState().seed, 0);
      const pk = window._test.getCompressedPubkey(sk);
      const pkHex = Array.from(pk).map((b) => b.toString(16).padStart(2, '0')).join('');
      const did_hex = '00112233445566778899aabbccddeeff';
      const did = new Uint8Array(did_hex.match(/.{2}/g).map((b) => parseInt(b, 16)));
      const deposit = {
        alias: 'gated',
        descriptor: `pk(${pkHex})`,
        deposit_id: did_hex,
        deposit_pubkey: pkHex,
        key_index: 0,
        receive_requires_sig: true,
      };
      const witness = window._test.maybeBuildReceiveWitness(deposit);

      // Reconstruct the preimage WITH the same nonce the wallet chose.
      const op = window.dep17 ? null : null; // dep17 not exposed on index.html — use the spec's helper
      // Use the module's helper directly via dynamic import.
      const dep17 = await import('/vendor/dep17.js');
      const expectedOp = dep17.buildReceiveOp({
        deposit_id: did,
        nonce: witness.nonce,
        expiry: witness.expiry,
      });
      const preimage = dep17.operationPreimage(expectedOp);
      const sighash = dep17.operationSighash(preimage);

      // Verify the signature with the produced pubkey.
      const keyHex = Object.keys(witness.signatures)[0];
      const sigHex = witness.signatures[keyHex];
      const sigBytes = new Uint8Array(sigHex.match(/.{2}/g).map((b) => parseInt(b, 16)));
      // noble-secp256k1 sig.verify expects Signature instance; use the lower-level path.
      const sig = secp.Signature.fromCompact(sigBytes);
      const valid = secp.verify(sig, sighash, pk);
      return { valid, keyMatch: keyHex === pkHex };
    });

    expect(result.keyMatch).toBe(true);
    expect(result.valid).toBe(true);
  });
});
