// Playwright config — minimal. Tests run against a python3 -m http.server
// instance serving the wallet directory, so ES module imports of
// vendor/dep17.js and friends work the same way they do in production
// (under nginx). Chromium only — we test the same engine the wallet
// users are likely to run.
//
// Run with: `npm run test:browser` (from deposits-web/wallet/).

import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './tests/browser',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: 0,
  workers: 1,
  reporter: 'list',
  use: {
    baseURL: 'http://127.0.0.1:8123',
    trace: 'on-first-retry',
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
  ],
  webServer: {
    command: 'python3 -m http.server 8123 --bind 127.0.0.1',
    url: 'http://127.0.0.1:8123',
    reuseExistingServer: !process.env.CI,
    timeout: 20_000,
    stdout: 'ignore',
    stderr: 'pipe',
  },
});
