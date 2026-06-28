// /request-payment page (explorer): ledger-from-context + form validation + URL
// prefill. The invoice fetch (/api/request-payment) needs the live LNURL service,
// so this only covers client-side behaviour that doesn't touch the network.

import { test, expect } from '@playwright/test';

const HEX = '57f60e1dbef339e25e53efe356b2291e2c10ebdeaf95069a9876172fdad6d610';

test.describe('request-payment page', () => {
  test('uses the ledger from #ledger= context instead of asking for it', async ({ page }) => {
    await page.goto(`/request-payment.html#ledger=${HEX}&deposit=dep123`);
    // Ledger shown as a read-only context chip; manual input row hidden.
    await expect(page.locator('#ledger-ctx')).toBeVisible();
    await expect(page.locator('#ledger-row')).toBeHidden();
    await expect(page.locator('#ledger')).toHaveValue(HEX);
    await expect(page.locator('#deposit')).toHaveValue('dep123');
    // "change" reveals the manual input.
    await page.click('#ledger-change');
    await expect(page.locator('#ledger-row')).toBeVisible();
  });

  test('falls back to a manual ledger field with no context', async ({ page }) => {
    await page.goto('/request-payment.html');
    await expect(page.locator('#ledger-row')).toBeVisible();
    await expect(page.locator('#ledger-ctx')).toBeHidden();
    await page.click('#gen');
    await expect(page.locator('#err')).toHaveText(/ledger is required/i);
  });

  test('validates deposit and amount before generating', async ({ page }) => {
    await page.goto(`/request-payment.html#ledger=${HEX}`);
    await page.click('#gen');
    await expect(page.locator('#err')).toHaveText(/deposit is required/i);
    await page.fill('#deposit', 'dep123');
    await page.click('#gen');
    await expect(page.locator('#err')).toHaveText(/amount in sats/i);
  });
});
