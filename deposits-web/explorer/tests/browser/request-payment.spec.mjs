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

  test('decodeCredit pulls payment_hash + amount from an InvoiceCredit op', async ({ page }) => {
    await page.goto(`/request-payment.html#ledger=${HEX}`);
    const ph = '11'.repeat(32);
    const content = buildCredit(ph, 50_000);
    const r = await page.evaluate((c) => window.__rp.decodeCredit(c), content);
    expect(r.ph).toBe(ph);   // exact payment_hash → precise paid detection
    expect(r.amt).toBe(50_000);
  });

  test('markPaid flips the UI to paid and hides the invoice/QR', async ({ page }) => {
    await page.goto(`/request-payment.html#ledger=${HEX}`);
    await page.evaluate(() => window.__rp.markPaid());
    await expect(page.locator('#status')).toHaveClass(/paid/);
    expect(await page.locator('#qr-wrap').evaluate(el => el.style.display)).toBe('none');
    expect(await page.locator('#copy').evaluate(el => el.style.display)).toBe('none');
  });
});

// Build an InvoiceCredit (op 30) content blob: disc(0)=30, payment_hash(14, 32B),
// amount(2, 8-byte big-endian). Single-byte varints suffice (tags/lens < 0xfd).
function buildCredit(paymentHashHex, amountMsats) {
  const ph = paymentHashHex.match(/.{2}/g).map(b => parseInt(b, 16));
  const amt = new Array(8); let n = amountMsats;
  for (let i = 7; i >= 0; i--) { amt[i] = n & 0xff; n = Math.floor(n / 256); }
  const tlv = (type, val) => [type, val.length, ...val];
  const inner = [...tlv(0, [30]), ...tlv(14, ph), ...tlv(2, amt)];
  const outer = [...tlv(8, inner)];
  return Buffer.from(outer).toString('base64');
}
