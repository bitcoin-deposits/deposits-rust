// Firehose decode/render smoke test. Loads the page (pointed at a dead relay so
// it doesn't hit the network) and drives the exposed decodeEvent/rowHtml against
// synthetic + real-fixture events. Verifies the tag-based decode (ledger / op /
// deposit / seq) and the amount-from-content path without needing a live stream.

import { test, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';

const FIXTURE = new URL(
  '../../../../deposits-audit/tests/fixtures/ledger_57f60e1dbef339e2.json',
  import.meta.url,
);
const contents = JSON.parse(readFileSync(FIXTURE, 'utf8'));

async function load(page) {
  // Dead relay → connect() fails fast, no real network; decode fns are set
  // first. Static server serves the .html (the extensionless /firehose route is
  // prod-only, in deposits-lnurl).
  await page.goto('/firehose.html#relay=ws://127.0.0.1:1');
  await page.waitForFunction(() => typeof window.__decodeEvent === 'function');
}

test.describe('firehose', () => {
  test.beforeEach(async ({ page }) => load(page));

  test('decodes ledger/op/deposit/seq from event tags', async ({ page }) => {
    const ev = {
      id: 'evt1',
      created_at: 1_700_000_000,
      tags: [['d', '57f60e1dbef339e2'], ['t', '30'], ['i', 'c3810cfd5269bb21d4b5099bb0635f85'], ['n', '42']],
      content: '',
    };
    const r = await page.evaluate((e) => window.__decodeEvent(e), ev);
    expect(r.ledger).toBe('57f60e1dbef339e2');
    expect(r.op).toBe('InvoiceCredit'); // disc 30
    expect(r.deposit).toBe('c3810cfd5269bb21d4b5099bb0635f85');
    expect(r.seq).toBe('42');

    const html = await page.evaluate((e) => window.__rowHtml(window.__decodeEvent(e)), ev);
    expect(html).toContain('InvoiceCredit');
    expect(html).toContain('/ledger#ledger=57f60e1dbef339e2');
    expect(html).toContain('/deposit#deposit=c3810cfd');
  });

  test('amount-from-content path: real fixture decodes without throwing', async ({ page }) => {
    // Pair a real SignedLedgerUpdate blob with minimal tags; amount comes from
    // the inner-op TLV. Assert it yields a non-negative number or null.
    const ev = { id: 'evt2', created_at: 1_700_000_000, tags: [['d', 'deadbeefdeadbeef']], content: contents[0] };
    const r = await page.evaluate((e) => window.__decodeEvent(e), ev);
    expect(r.amount === null || (Number.isInteger(r.amount) && r.amount >= 0)).toBe(true);
    expect(typeof r.op).toBe('string'); // decoded a discriminant from content
  });

  test('feed is newest-on-top regardless of arrival order', async ({ page }) => {
    // Feed events out of order (mimics the relay sending its backlog
    // newest-first, then live events). Rows must end up sorted newest-on-top.
    const mk = (id, ts) => ({ id, created_at: ts, tags: [['d', 'aa'.repeat(8)], ['t', '30']], content: '' });
    await page.evaluate(() => { /* ensure ready */ });
    await page.evaluate((evs) => evs.forEach((e) => window.__addEvent(e)), [
      mk('a', 1000), mk('b', 1002), mk('c', 1001), mk('d', 1003),
    ]);
    const order = await page.$$eval('#rows .row', els => els.map(e => Number(e.dataset.ts)));
    expect(order).toEqual([1003, 1002, 1001, 1000]); // strictly descending
  });

  test('missing tags degrade gracefully', async ({ page }) => {
    const r = await page.evaluate(() => window.__decodeEvent({ id: 'x', tags: [], content: '' }));
    expect(r.ledger).toBe('');
    expect(r.op).toBe('?');
    const html = await page.evaluate(() => window.__rowHtml(window.__decodeEvent({ id: 'x', tags: [], content: '' })));
    expect(html).toContain('—'); // em-dash placeholder for ledger/deposit
  });

  test('recovers the full 64-hex ledger id from event content', async ({ page }) => {
    // The relay `d` tag is only a 16-hex prefix; the full ledger_id (outer TLV
    // tag 2) is needed for a /ledger link that doesn't 400 as "not 64-hex".
    const ev = { id: 'evtL', created_at: 1_700_000_000, tags: [['d', '57f60e1dbef339e2']], content: contents[0] };
    const r = await page.evaluate((e) => window.__decodeEvent(e), ev);
    expect(r.ledger).toMatch(/^[0-9a-f]{64}$/);
    expect(r.ledger.startsWith('57f60e1dbef339e2')).toBe(true);
    const html = await page.evaluate((e) => window.__rowHtml(window.__decodeEvent(e)), ev);
    expect(html).toContain(`/ledger#ledger=${r.ledger}`); // full id, not the prefix
  });

  test('time and op both drill into the per-entry update view', async ({ page }) => {
    const ev = { id: 'evtE', created_at: 1_700_000_000, tags: [['d', '57f60e1dbef339e2'], ['t', '30']], content: '' };
    const html = await page.evaluate((e) => window.__rowHtml(window.__decodeEvent(e)), ev);
    const hits = (html.match(/\/update#event=evtE/g) || []).length;
    expect(hits).toBe(2); // the time cell and the op badge
    expect(html).toContain('class="op credit"'); // op badge is the link, still styled
  });

  test('lock holds, fulfill settles — op badge classes reflect balance effect', async ({ page }) => {
    const cls = async (disc) => page.evaluate((d) => {
      const ev = { id: 'c' + d, created_at: 1_700_000_000, tags: [['d', 'aa'.repeat(8)], ['t', String(d)]], content: '' };
      return window.__rowHtml(window.__decodeEvent(ev));
    }, disc);
    const credit = await cls(30);   // InvoiceCredit — inflow
    const lock = await cls(31);     // InvoiceLock — pending hold
    const fulfill = await cls(33);  // InvoiceFulfill — settled outflow
    expect(credit).toContain('class="op credit"');
    expect(lock).toContain('class="op lock"');
    expect(fulfill).toContain('class="op settle"');   // NOT credit
    expect(fulfill).not.toContain('class="op credit"');
  });

  test('only recent entries flash; the load-time backlog stays quiet', async ({ page }) => {
    const nowSec = Math.floor(Date.now() / 1000);
    await page.evaluate((ts) => {
      window.__addEvent({ id: 'old1', created_at: ts - 600, tags: [['d', 'bb'.repeat(8)], ['t', '30']], content: '' });
      window.__addEvent({ id: 'new1', created_at: ts,       tags: [['d', 'cc'.repeat(8)], ['t', '30']], content: '' });
    }, nowSec);
    const rows = await page.$$eval('#rows .row', els => els.map(e => ({ ts: Number(e.dataset.ts), fresh: e.classList.contains('fresh') })));
    expect(rows.find(r => r.ts === nowSec - 600).fresh).toBe(false);
    expect(rows.find(r => r.ts === nowSec).fresh).toBe(true);
  });
});
