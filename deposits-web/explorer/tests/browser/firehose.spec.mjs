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
});
