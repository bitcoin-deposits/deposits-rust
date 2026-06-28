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

  test('history sign: only credit (+) and fulfill/fee (−) move; lock follows fail', async ({ page }) => {
    const s = await page.evaluate(() => {
      const f = window._test.historyOpSign;
      return {
        credit: f('InvoiceCredit'),
        lock: f('InvoiceLock'),
        fulfill: f('InvoiceFulfill'),
        fee: f('FeeCollect'),
        fail: f('InvoiceFail'),
      };
    });
    // Value movements carry a sign; lifecycle markers don't.
    expect(s.credit.sign).toBe('+');  // inflow
    expect(s.fulfill.sign).toBe('-'); // settled outflow
    expect(s.fee.sign).toBe('-');     // settled debit
    // Lock (pending hold) and Fail (released hold) are both informative — same
    // neutral treatment, no sign.
    expect(s.lock.sign).toBe('');
    expect(s.fail.sign).toBe('');
    expect(s.lock).toEqual(s.fail);   // lock follows fail
  });

  test('history dedups (ledger,seq) re-signs, interleaves chronologically, attributes deposits', async ({ page }) => {
    const r = await page.evaluate(() => {
      const idToAlias = { aa: 'deposit-1', bb: 'deposit-2' };
      const decoded = [
        // two re-signs of the same (L1, seq 5) — must collapse to ONE row
        { id: 'e1', ts: 100, iTags: ['aa'], opName: 'DepositOpen', amount: 0, seq: 5, ledgerId: 'L1', ok: true },
        { id: 'e2', ts: 100, iTags: ['aa'], opName: 'DepositOpen', amount: 0, seq: 5, ledgerId: 'L1', ok: true },
        { id: 'e3', ts: 300, iTags: ['bb'], opName: 'InvoiceCredit', amount: 64000, seq: 9, ledgerId: 'L2', ok: true },
        { id: 'e4', ts: 200, iTags: ['aa'], opName: 'InvoiceCredit', amount: 10000, seq: 6, ledgerId: 'L1', ok: true },
        // undecodable — keyed by event id, must NOT collapse despite same seq 0
        { id: 'e5', ts: 50, iTags: ['bb'], opName: '?', amount: 0, seq: 0, ledgerId: '', ok: false },
        { id: 'e6', ts: 51, iTags: ['bb'], opName: '?', amount: 0, seq: 0, ledgerId: '', ok: false },
      ];
      return window._test.buildHistoryRows(decoded, idToAlias)
        .map(x => ({ op: x.opName, who: x.who, ts: x.ts }));
    });
    expect(r.filter(x => x.op === 'DepositOpen').length).toBe(1);   // re-sign collapsed
    expect(r.filter(x => x.op === '?').length).toBe(2);             // undecodable kept distinct
    expect(r.map(x => x.ts)).toEqual([300, 200, 100, 51, 50]);      // newest-first, interleaved
    expect(r.find(x => x.ts === 300).who).toBe('deposit-2');        // deposit attribution
    expect(r.find(x => x.ts === 200).who).toBe('deposit-1');
  });
});
