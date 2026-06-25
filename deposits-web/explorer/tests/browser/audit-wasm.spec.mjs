// Browser end-to-end test for the explorer's solvency audit wasm.
//
// Loads the deposits-audit wasm module in real Chromium and runs it over a
// frozen fixture captured from the live relay (ledger 57f60e1d). The expected
// figures were cross-checked against the `replay-ledger` CLI and the native
// `deposits-audit` test on the same data, so this proves the wasm build —
// secp256k1 C compiled to wasm and all — loads and computes identically to the
// canonical Rust in the actual browser engine users run.

import { test, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';

// Fixture lives in the audit crate; read it node-side and inject.
const FIXTURE = new URL(
  '../../../../deposits-audit/tests/fixtures/ledger_57f60e1dbef339e2.json',
  import.meta.url,
);
const contents = JSON.parse(readFileSync(FIXTURE, 'utf8'));

async function loadHarness(page) {
  const errors = [];
  page.on('pageerror', (e) => errors.push(String(e)));
  await page.goto('/tests/browser/wasm-harness.html');
  await page.waitForFunction(
    () => window.__auditReady === true || window.__auditError,
    { timeout: 15_000 },
  );
  const err = await page.evaluate(() => window.__auditError);
  expect(err, `wasm init error: ${err} ${errors.join(';')}`).toBeFalsy();
}

test.describe('explorer solvency audit (wasm)', () => {
  test.beforeEach(async ({ page }) => loadHarness(page));

  test('reproduces the CLI audit figures in-browser', async ({ page }) => {
    const report = await page.evaluate((blobs) => {
      return JSON.parse(window.__audit(JSON.stringify(blobs)));
    }, contents);

    // Exact figures, identical to `replay-ledger` + the native audit test.
    expect(report.obligations_msats).toBe(132029);
    expect(report.locked_msats).toBe(0);
    expect(report.reserves_msats).toBe(15600000);
    expect(report.collateral_msats).toBe(23400000);
    expect(report.deposits).toBe(3);
    expect(report.solvent).toBe(true);
    expect(report.replay_errors).toBe(0);

    // Op tally: this snapshot reconciled (10 locks ↔ 10 fulfills, 0 fail).
    expect(report.op_counts.InvoiceLock).toBe(10);
    expect(report.op_counts.InvoiceFulfill).toBe(10);
    expect(report.op_counts.InvoiceCredit).toBe(11);
  });

  test('handles empty input gracefully', async ({ page }) => {
    const report = await page.evaluate(() => JSON.parse(window.__audit('[]')));
    expect(report.solvent).toBe(true);
    expect(report.obligations_msats).toBe(0);
    expect(report.deposits).toBe(0);
  });
});
