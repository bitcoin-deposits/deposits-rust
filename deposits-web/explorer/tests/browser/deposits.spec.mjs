// deposits.html is a directory of opened deposits — it REQs DepositOpen (op 20)
// events on a ledger and lists them, no balances/replay. This drives the
// exposed decodeDepositOpen against hand-built DepositOpen TLVs to verify the
// deposit_id (from the `i` tag, or inner tag 200) and descriptor (inner tag
// 202) extraction.

import { test, expect } from '@playwright/test';

async function load(page) {
  await page.goto('/deposits.html#ledger=' + 'ab'.repeat(32) + '&relay=ws://127.0.0.1:1');
  await page.waitForFunction(() => typeof window.__decodeDepositOpen === 'function');
}

// Build a SignedLedgerUpdate content blob carrying a DepositOpen inner op. Only
// single-byte varints are needed (all tags/lengths < 0xfd), matching shared.js
// parseTlv. Built in Node so the result can be passed into page.evaluate.
function buildContent(depositIdHex, descriptor) {
  const did = depositIdHex.match(/.{2}/g).map(b => parseInt(b, 16));
  const desc = [...Buffer.from(descriptor, 'utf8')];
  const tlv = (type, val) => [type, val.length, ...val];
  const inner = [...tlv(0, [20]), ...tlv(200, did), ...tlv(202, desc)];
  const outer = [...tlv(8, inner)]; // tag 8 = message (inner op)
  return Buffer.from(outer).toString('base64');
}

test.describe('deposits directory', () => {
  test.beforeEach(async ({ page }) => load(page));

  test('decodes deposit_id from the i tag and descriptor from the inner op', async ({ page }) => {
    const r = await page.evaluate((content) => {
      const ev = {
        id: 'd1', created_at: 1_700_000_000,
        tags: [['d', 'ab'.repeat(8)], ['t', '20'], ['i', '00112233445566778899aabbccddeeff']],
        content,
      };
      return window.__decodeDepositOpen(ev);
    }, buildContent('00112233445566778899aabbccddeeff', 'pk(02abababababababababababababababababababababababababababababababab)'));
    expect(r.deposit_id).toBe('00112233445566778899aabbccddeeff');
    expect(r.descriptor).toBe('pk(02abababababababababababababababababababababababababababababababab)');
    expect(r.ts).toBe(1_700_000_000);
  });

  test('falls back to inner tag 200 for deposit_id when no i tag', async ({ page }) => {
    const r = await page.evaluate((content) => {
      const ev = { id: 'd2', created_at: 1, tags: [['d', 'ab'.repeat(8)], ['t', '20']], content };
      return window.__decodeDepositOpen(ev);
    }, buildContent('aabbccddeeff00112233445566778899', 'wsh(multi(2,A,B))'));
    expect(r.deposit_id).toBe('aabbccddeeff00112233445566778899');
    expect(r.descriptor).toBe('wsh(multi(2,A,B))');
  });

  test('degrades gracefully on undecodable content', async ({ page }) => {
    const r = await page.evaluate(() => window.__decodeDepositOpen({
      id: 'd3', created_at: 5, tags: [['i', 'ff'.repeat(16)]], content: '',
    }));
    expect(r.deposit_id).toBe('ff'.repeat(16));
    expect(r.descriptor).toBe(''); // no crash, empty descriptor
  });
});

