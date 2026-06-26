// Smoke test for the shared top-level section nav (installTopNav).
import { test, expect } from '@playwright/test';

async function load(page, query) {
  await page.goto(`/tests/browser/nav-harness.html${query}`);
  await page.waitForFunction(() => window.__navReady === true);
}

test.describe('top-nav section switcher', () => {
  test('renders nodes / ledgers / deposits with a ledger context', async ({ page }) => {
    await load(page, '?ledger=57f60e1dbef339e2&relay=wss%3A%2F%2Fr');
    const labels = await page.$$eval('nav.topnav .sections a', els => els.map(e => e.textContent));
    expect(labels).toEqual(['nodes', 'ledgers', 'deposits', 'live']);

    // deposits is a live link when a ledger is known.
    const deposits = page.locator('nav.topnav .sections a', { hasText: 'deposits' });
    await expect(deposits).not.toHaveClass(/disabled/);
    expect(await deposits.getAttribute('href')).toContain('/deposits#ledger=57f60e1dbef339e2');
  });

  test('deposits is inert without a ledger context', async ({ page }) => {
    await load(page, '');
    const deposits = page.locator('nav.topnav .sections a', { hasText: 'deposits' });
    await expect(deposits).toHaveClass(/disabled/);
  });
});
