// Unit tests for shared.js helpers that need a browser module context. Loads a
// served page (dead relay → no network), dynamically imports ./shared.js, and
// drives nostrFetchAll with a synthetic `_fetch` that mimics relay semantics
// (created_at-descending, inclusive `until`, capped at `limit`).

import { test, expect } from '@playwright/test';

async function load(page) {
  await page.goto('/live.html#relay=ws://127.0.0.1:1');
  await page.waitForFunction(() => typeof window.__decodeEvent === 'function');
}

test.describe('nostrFetchAll', () => {
  test.beforeEach(async ({ page }) => load(page));

  test('paginates past the per-REQ cap and dedupes the window overlap', async ({ page }) => {
    const r = await page.evaluate(async () => {
      const m = await import('./shared.js');
      // 1200 events, strictly-descending created_at, like a relay backlog.
      const all = Array.from({ length: 1200 }, (_, i) => ({ id: 'e' + i, created_at: 5000 - i }));
      const _fetch = async (_url, filter) => {
        let pool = all;
        if (filter.until != null) pool = all.filter(e => e.created_at <= filter.until);
        return pool.slice(0, filter.limit); // newest-first, capped
      };
      const got = await m.nostrFetchAll('ws://x', { kinds: [9100], limit: 500 }, { _fetch });
      return { count: got.length, unique: new Set(got.map(e => e.id)).size };
    });
    expect(r.count).toBe(1200);   // all pages, not just the first 500
    expect(r.unique).toBe(1200);  // inclusive `until` overlap deduped by id
  });

  test('a single short page returns everything without extra requests', async ({ page }) => {
    const r = await page.evaluate(async () => {
      const m = await import('./shared.js');
      const all = Array.from({ length: 42 }, (_, i) => ({ id: 'x' + i, created_at: 100 - i }));
      let calls = 0;
      const _fetch = async () => { calls++; return all; };
      const got = await m.nostrFetchAll('ws://x', { kinds: [9100], limit: 500 }, { _fetch });
      return { count: got.length, calls };
    });
    expect(r.count).toBe(42);
    expect(r.calls).toBe(1); // partial page → stop immediately
  });

  test('a full page of one shared timestamp terminates (no infinite loop)', async ({ page }) => {
    const r = await page.evaluate(async () => {
      const m = await import('./shared.js');
      // 500 distinct events all at the same created_at: `until` can't advance.
      const page0 = Array.from({ length: 500 }, (_, i) => ({ id: 's' + i, created_at: 7 }));
      let calls = 0;
      const _fetch = async () => { calls++; return page0; };
      const got = await m.nostrFetchAll('ws://x', { kinds: [9100], limit: 500 }, { _fetch });
      return { count: got.length, calls };
    });
    expect(r.count).toBe(500);
    expect(r.calls).toBe(2); // page 1 fills; page 2 is all dupes → break
  });
});
