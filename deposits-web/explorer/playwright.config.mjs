// Playwright config for the explorer's wasm audit test. Serves the explorer
// directory over python3 http.server so ES-module + wasm fetches resolve the
// same way they do in production (under Caddy/nginx). Chromium only.
//
// Run with: `npm run test:browser` (from deposits-web/explorer/).
// Requires the wasm artifact built first: `deposits-audit-wasm/build-wasm.sh`.

import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './tests/browser',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: 0,
  workers: 1,
  reporter: 'list',
  use: {
    baseURL: 'http://127.0.0.1:8124',
    trace: 'on-first-retry',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: 'python3 -m http.server 8124 --bind 127.0.0.1',
    url: 'http://127.0.0.1:8124',
    reuseExistingServer: !process.env.CI,
    timeout: 20_000,
    stdout: 'ignore',
    stderr: 'pipe',
  },
});
