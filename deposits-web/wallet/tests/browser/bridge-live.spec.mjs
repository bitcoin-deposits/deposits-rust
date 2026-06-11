// LIVE drill — the web wallet's DEP-10 bridge flows against a real
// cluster + deposits-bridge daemon, in real Chromium. The browser is the
// wallet: it picks the preimage (receive) and verifies the proof of
// payment (pay); the CLI is only used for node-side setup (deposit open
// via the same seed/derivation, operator funding).
//
// Self-skips unless the drill stack is up:
//
//   BRIDGE_NPUB=$(cat /tmp/deposits-bridge-test/bridge.npub) \
//   BRIDGE_LEDGER=$(cat ../../deposits-tools/data/state/ledger_2_1) \
//   CLN_PAYER_SOCKET_PATH=/tmp/cln-payer-test/regtest/lightning-rpc \
//   DEPOSITS_WALLET=../../target/debug/deposits-wallet \
//   DEPOSITS_NODE=../../target/debug/deposits-node \
//     npx playwright test tests/browser/bridge-live.spec.mjs

import { test, expect } from '@playwright/test';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
import { createConnection } from 'node:net';
import { randomBytes } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, '../../../..');

const ENV = process.env;
const LIVE = !!(ENV.BRIDGE_NPUB && ENV.BRIDGE_LEDGER && ENV.CLN_PAYER_SOCKET_PATH);
const RELAY = ENV.RELAY_LEDGERS || 'ws://localhost:17779';
const WALLET_BIN = ENV.DEPOSITS_WALLET || join(REPO_ROOT, 'target/debug/deposits-wallet');
const NODE_BIN = ENV.DEPOSITS_NODE || join(REPO_ROOT, 'target/debug/deposits-node');
const OP2_SEED = '6f70320000000000000000000000000000000000000000000000000000000000';
const OP2_DATA = join(REPO_ROOT, 'deposits-tools/data/op2');

/// One-shot JSON-RPC against cln-payer's unix socket.
function payerRpc(method, params, timeoutMs = 120000) {
  return new Promise((resolve, reject) => {
    const sock = createConnection(ENV.CLN_PAYER_SOCKET_PATH);
    const timer = setTimeout(() => {
      sock.destroy();
      reject(new Error(`payer ${method} timeout`));
    }, timeoutMs);
    let buf = '';
    sock.on('connect', () => {
      sock.write(JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) + '\n');
    });
    sock.on('data', (d) => {
      buf += d.toString();
      if (buf.includes('\n')) {
        clearTimeout(timer);
        sock.end();
        try { resolve(JSON.parse(buf.slice(0, buf.indexOf('\n') + 1))); }
        catch (e) { reject(e); }
      }
    });
    sock.on('error', (e) => { clearTimeout(timer); reject(e); });
  });
}

// Shared wallet identity: CLI `open` and the browser derive the same key
// (BIP-84 m/84'/0'/0'/0/0) from this seed, so the browser drives a deposit
// the cluster already knows about.
let seedHex, depositEntry;

test.describe('web wallet ⇄ live bridge (DEP-10)', () => {
  test.skip(!LIVE, 'bridge drill stack not configured (BRIDGE_NPUB / BRIDGE_LEDGER / CLN_PAYER_SOCKET_PATH)');
  test.describe.configure({ mode: 'serial' });

  test.beforeAll(() => {
    seedHex = randomBytes(32).toString('hex');
    const dataDir = mkdtempSync(join(tmpdir(), 'web-bridge-'));

    // Open the deposit on the ledger via the CLI (same seed, same key).
    const open = spawnSync(WALLET_BIN, [
      'open', ENV.BRIDGE_LEDGER, '100000',
      '--alias', 'web',
      '--seed', seedHex,
      '--data-dir', dataDir,
      '--network', 'regtest',
      '--relay', RELAY,
    ], { encoding: 'utf8', timeout: 60000 });
    if (open.status !== 0) {
      throw new Error(`wallet open failed:\n${open.stdout}\n${open.stderr}`);
    }
    const deposits = JSON.parse(readFileSync(join(dataDir, 'deposits.json'), 'utf8'));
    depositEntry = deposits.find((d) => d.alias === 'web');
    if (!depositEntry) throw new Error('no deposit entry after open');

    // Fund it via the ledger's operator so the pay drill has a balance.
    const credit = spawnSync(NODE_BIN, [
      'deposit', 'credit', ENV.BRIDGE_LEDGER,
      depositEntry.deposit_id,
      String(30000 * 1000),
      `web-bridge-${seedHex.slice(0, 8)}`,
      '--seed', OP2_SEED,
      '--name', 'op2',
      '--network', 'regtest',
      '--data-dir', OP2_DATA,
      '--esplora', 'http://localhost:3102',
      '--relay', RELAY,
    ], { encoding: 'utf8', timeout: 60000 });
    if (!`${credit.stdout}${credit.stderr}`.includes('New balance')) {
      throw new Error(`operator credit failed:\n${credit.stdout}\n${credit.stderr}`);
    }
  });

  async function loadAndWire(page) {
    await page.goto('/index.html');
    await page.waitForFunction(() => window._test !== undefined, { timeout: 5000 });
    await page.evaluate(({ seedHex, ledger, dep, relay }) => {
      const seed = new Uint8Array(seedHex.match(/.{2}/g).map((b) => parseInt(b, 16)));
      window._test.setState({
        seed,
        network: 'regtest',
        relays: [relay],
        deposits: [{
          alias: 'web',
          ledger_id: ledger,
          descriptor: dep.descriptor,
          deposit_pubkey: dep.deposit_pubkey,
          deposit_id: dep.deposit_id,
          key_index: dep.key_index || 0,
        }],
      });
      window._test.connect();
    }, { seedHex, ledger: ENV.BRIDGE_LEDGER, dep: depositEntry, relay: RELAY });
    await page.waitForFunction(() => window._test.socketsConnected() > 0, { timeout: 10000 });
  }

  test('receive: browser preimage → bridge hold invoice → lock → reveal', async ({ page }) => {
    test.setTimeout(180000);
    await loadAndWire(page);

    // Kick off the flow; it parks waiting for the payer.
    await page.evaluate((ledger) => {
      window._recvResult = null;
      const dep = window._test.getState().deposits[0];
      window._test.discoverBridges(ledger)
        .then((bridges) => {
          if (!bridges.length) throw new Error('no bridge ads (Kind 39104) found');
          window._bridgeCount = bridges.length;
          return window._test.bridgeRecvLightning(dep, 5000, bridges[0]);
        })
        .then(() => { window._recvResult = 'ok'; })
        .catch((e) => { window._recvResult = 'ERR: ' + e.message; });
    }, ENV.BRIDGE_LEDGER);

    // The flow surfaces the BOLT-11 in the receive panel — scrape it.
    await page.waitForFunction(
      () => (document.getElementById('wallet-recv-text')?.textContent || '').startsWith('lnbcrt'),
      { timeout: 45000 },
    );
    const bolt11 = await page.evaluate(
      () => document.getElementById('wallet-recv-text').textContent.trim(),
    );

    // Pay it from cln-payer; the HTLC holds until the browser reveals.
    const payPromise = payerRpc('pay', { bolt11 });

    await page.waitForFunction(() => window._recvResult !== null, { timeout: 120000 });
    const result = await page.evaluate(() => window._recvResult);
    expect(result).toBe('ok');

    const pay = await payPromise;
    expect(pay.result?.status).toBe('complete');
    // The payer finished with the BROWSER's preimage — LN→ledger→LN.
  });

  test('pay: quote → lock on invoice hash → bridge claim is proof of payment', async ({ page }) => {
    test.setTimeout(180000);
    await loadAndWire(page);

    const label = `web-bridge-pay-${seedHex.slice(0, 8)}`;
    const inv = await payerRpc('invoice', {
      amount_msat: 1000 * 1000,
      label,
      description: 'web wallet bridge pay drill',
    });
    const bolt11 = inv.result?.bolt11;
    expect(bolt11, JSON.stringify(inv)).toBeTruthy();

    await page.evaluate(({ ledger, bolt11 }) => {
      window._payResult = null;
      const dep = window._test.getState().deposits[0];
      window._test.discoverBridges(ledger)
        .then((bridges) => {
          if (!bridges.length) throw new Error('no bridge ads (Kind 39104) found');
          return window._test.bridgePayInvoice(dep, bolt11, bridges[0]);
        })
        .then(() => { window._payResult = 'ok'; })
        .catch((e) => { window._payResult = 'ERR: ' + e.message; });
    }, { ledger: ENV.BRIDGE_LEDGER, bolt11 });

    await page.waitForFunction(() => window._payResult !== null, { timeout: 150000 });
    const result = await page.evaluate(() => window._payResult);
    expect(result).toBe('ok');

    // The invoice must be PAID upstream — bridgePayInvoice already verified
    // the on-ledger claim witness hashes to the invoice's payment_hash.
    const listed = await payerRpc('listinvoices', { label });
    expect(listed.result?.invoices?.[0]?.status).toBe('paid');
  });
});
