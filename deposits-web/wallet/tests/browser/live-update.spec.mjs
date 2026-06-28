// Wallet live deposit-update handling. The wallet keeps a kind:9100 relay
// subscription filtered by its deposit ids; this verifies that an inbound update
// on one of our deposits promptly schedules a balance refresh — for ANY op, not
// only credits — while foreign / duplicate events are ignored. Uses the
// localhost-guarded window._test hook to drive the real handler.

import { test, expect } from '@playwright/test';

async function loadWallet(page) {
  await page.goto('/index.html');
  await page.waitForFunction(() => window._test !== undefined, { timeout: 5000 });
}

test.describe('wallet live deposit updates', () => {
  test.beforeEach(async ({ page }) => loadWallet(page));

  test('our deposit ops schedule a refresh; foreign and duplicate events do not', async ({ page }) => {
    const r = await page.evaluate(() => {
      const pkHex = '02' + 'ab'.repeat(32); // 33-byte compressed pubkey
      window._test.setState({
        seed: new Uint8Array(32).fill(0x11),
        deposits: [{ alias: 'mine', deposit_pubkey: pkHex }],
      });
      const ourId = window._test.getOurDepositIds()[0];
      const out = { start: window._test.liveSyncCount() };

      // A non-credit op on our deposit (content intentionally undecodable, to
      // prove the refresh is tag-driven and not gated on decoding a credit).
      window._test.handleLedgerUpdate({ id: 'ev-mine-1', kind: 9100, tags: [['i', ourId]], content: '' });
      out.afterOurs = window._test.liveSyncCount();

      // An update for someone else's deposit — must not refresh.
      window._test.handleLedgerUpdate({ id: 'ev-other', kind: 9100, tags: [['i', 'deadbeefdeadbeef']], content: '' });
      out.afterOther = window._test.liveSyncCount();

      // Same event id again — deduped, no extra refresh.
      window._test.handleLedgerUpdate({ id: 'ev-mine-1', kind: 9100, tags: [['i', ourId]], content: '' });
      out.afterDup = window._test.liveSyncCount();
      return out;
    });
    expect(r.afterOurs).toBe(r.start + 1);  // our op scheduled a sync
    expect(r.afterOther).toBe(r.afterOurs); // foreign op ignored
    expect(r.afterDup).toBe(r.afterOurs);   // duplicate event deduped
  });
});
