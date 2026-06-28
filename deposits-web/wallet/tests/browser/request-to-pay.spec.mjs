// /request-to-pay page: form validation + URL prefill. The invoice-creation
// fetch (/api/request-to-pay) needs the live LNURL service, so this only covers
// the client-side behaviour that doesn't touch the network.

import { test, expect } from '@playwright/test';

test.describe('request-to-pay page', () => {
  test('requires ledger and deposit before generating', async ({ page }) => {
    await page.goto('/request-to-pay.html');
    await page.click('#gen');
    await expect(page.locator('#err')).toHaveText(/Ledger and deposit are required/);
    // Form still shown, no result.
    await expect(page.locator('#result')).not.toHaveClass(/show/);
  });

  test('asks for an amount when ledger+deposit present but amount blank', async ({ page }) => {
    await page.goto('/request-to-pay.html');
    await page.fill('#ledger', 'a'.repeat(64));
    await page.fill('#deposit', '00112233445566778899aabbccddeeff');
    await page.click('#gen');
    await expect(page.locator('#err')).toHaveText(/amount in sats/);
  });

  test('prefills fields from the URL hash for shareable links', async ({ page }) => {
    const ledger = 'b'.repeat(64);
    // No amount → auto-generate stays off, so no network call.
    await page.goto(`/request-to-pay.html#ledger=${ledger}&deposit=dep123&message=coffee`);
    await expect(page.locator('#ledger')).toHaveValue(ledger);
    await expect(page.locator('#deposit')).toHaveValue('dep123');
    await expect(page.locator('#message')).toHaveValue('coffee');
  });
});
