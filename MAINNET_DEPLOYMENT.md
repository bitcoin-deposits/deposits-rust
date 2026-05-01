# Mainnet Test Cluster Deployment

This document describes how to stand up a small **Bitcoin mainnet** test cluster running the deposits-node protocol. "Test" here means small balances and an operator group you control end-to-end — but the underlying chain, fees, and Lightning network are real, so failures cost real money. This is a deliberate sandbox for finding the things that only break under real conditions.

The existing [`OPERATIONS.md`](deposits-tools/OPERATIONS.md) covers regtest. This guide diffs against that — read it first if you haven't.

---

## What changes vs regtest

| Component | Regtest | Mainnet |
| --- | --- | --- |
| **Bitcoin node** | `bitcoind -regtest=1`, single container, mined on demand | Full node syncing real chain (~700 GB, days to IBD) |
| **Block timing** | On-demand via `miner` container | ~10 min real intervals, fee competition, reorgs |
| **Fees** | Negligible (`-fallbackfee=0.00001`) | Real estimates from mempool; size dispute/confiscation TXs accordingly |
| **Funds** | Faucet wallet with ~50 BTC of regtest coinbase | Manually funded operator wallets with real BTC |
| **Operator keys** | Hex pattern `op0` → `6f7030…00` | High-entropy generated keys, stored in a real KMS / hardware |
| **Relays** | `localhost:17779/17780`, native strfry process | Public domains, TLS, retention policies |
| **Lightning (optional)** | LDK regtest, single shared node | Real channels with peers; unrealistic to test in-cluster |
| **Mining** | `miner` container generates 1 block/sec | Removed entirely |
| **Access control** | None | Real authentication on operator daemon RPCs, firewalled UTXO node |

The protocol code is `--network bitcoin` instead of `--network regtest` — that's the only code-level switch. Everything else is operational.

---

## Pre-deployment checklist

**Pick the cluster size first.** The existing `setup.sh 3` uses 10 operators with Q=3 and 30 ledgers. For a mainnet sandbox, **start with 3 operators, Q=2, 1 ledger each (3 ledgers total)**. That's enough to exercise the dispute pipeline with actual on-chain confiscation TXs and is the smallest configuration that proves the protocol end-to-end. Scale up later.

**Decide who runs each operator.** The trust assumption is "no single operator can steal funds from a ledger they don't control" — so the 3 operators should be on different machines, ideally different networks, ideally different administrative control.

**Provision:**
- 1 Bitcoin full-node host (8 cores, 32 GB RAM, 1 TB SSD recommended for txindex). Initial sync takes 1–4 days depending on bandwidth.
- 3 operator hosts (1 each — modest; 4 cores, 8 GB RAM, 50 GB disk is plenty).
- 2 relay hosts (or one with two ports). Public IPs with TLS termination.
- Optionally: 1 monitoring host (Prometheus + Grafana).
- Domain names for the relays (e.g. `relay-ledgers.example.com`, `relay-msg.example.com`) — NIP-01 wallets and Lightning attestations expect WSS.

**Have ready:**
- A small amount of real BTC (enough to fund each operator's reserves UTXO + transaction fees + collateral). For a sandbox, ~0.01 BTC per operator is plenty.
- TLS certs for the relay domains (Let's Encrypt is fine; renewal needs to be set up before the cert expires or quorum members will silently lose connectivity).
- A KMS or HSM you trust for operator seeds. **Don't use the regtest hex-pattern seeds.**

---

## Step 1 — Bitcoin full node

Skip if you already have a synced node you can point everything at. Otherwise the slowest path-element by far.

```yaml
# docker-compose.mainnet.yml — bitcoin service
services:
  bitcoin:
    image: blockstream/bitcoind:27.2
    container_name: bitcoind-mainnet
    command:
      - bitcoind
      - -printtoconsole
      - -server=1
      - -rpcallowip=10.0.0.0/8        # restrict to your private network
      - -rpcbind=0.0.0.0
      - -rpcuser=${BITCOIN_RPC_USER}
      - -rpcpassword=${BITCOIN_RPC_PASSWORD}
      - -rest
      - -txindex                       # required for esplora/electrs
      - -dbcache=4096                  # speeds up IBD on this much RAM
    ports:
      - "8332:8332"                    # mainnet RPC
      - "8333:8333"                    # mainnet P2P
    volumes:
      - bitcoin_mainnet_data:/home/bitcoin/.bitcoin
    healthcheck:
      test: ["CMD", "bitcoin-cli", "-rpcuser=${BITCOIN_RPC_USER}", "-rpcpassword=${BITCOIN_RPC_PASSWORD}", "getblockchaininfo"]
      interval: 30s
      timeout: 10s
      retries: 5
volumes:
  bitcoin_mainnet_data:
```

Key removals from the regtest compose: drop `-regtest=1` and `-fallbackfee` (mainnet has real fee estimation). Keep `-rest` and `-txindex` — electrs needs both.

**Initial block download** runs as part of `docker compose up -d bitcoin`. Watch progress:

```sh
docker exec bitcoind-mainnet bitcoin-cli -rpcuser=$BITCOIN_RPC_USER -rpcpassword=$BITCOIN_RPC_PASSWORD getblockchaininfo
# verificationprogress: 0.0xxx → 1.0
```

Don't proceed until `verificationprogress > 0.999`. Until then, electrs's tip lags and operator daemons will see invalid block hashes when verifying fraud-proof anchors.

---

## Step 2 — Electrs

Same image as regtest, but `--network=bitcoin` and a different daemon-rpc-addr port.

```yaml
  electrs:
    image: mempool/electrs:v3.2.0
    container_name: electrs-mainnet
    depends_on:
      bitcoin:
        condition: service_healthy
    command:
      - -vvvv
      - --timestamp
      - --jsonrpc-import
      - --cookie=${BITCOIN_RPC_USER}:${BITCOIN_RPC_PASSWORD}
      - --network=bitcoin
      - --daemon-rpc-addr=bitcoind-mainnet:8332
      - --http-addr=0.0.0.0:3002
      - --monitoring-addr=0.0.0.0:4224
    ports:
      - "3002:3002"                    # external esplora HTTP
      - "4224:4224"                    # prometheus
    volumes:
      - electrs_mainnet_data:/data
volumes:
  electrs_mainnet_data:
```

Electrs's own initial index can take 2–4 hours after Bitcoin IBD finishes. `curl http://<host>:3002/blocks/tip/height` returns the current tip when it's caught up.

---

## Step 3 — Relays

The protocol uses two relays:
- **Ledgers relay** (durable, kind:9100/9103/39100, etc.) — sees every signed update; should retain forever.
- **Messaging relay** (ephemeral, cosign requests, balance queries) — can drop events older than a few minutes.

For a real deployment, run **strfry** behind nginx with TLS. Don't expose strfry's plaintext port to the internet.

```nginx
# /etc/nginx/sites-available/relay-ledgers
server {
    listen 443 ssl http2;
    server_name relay-ledgers.example.com;
    ssl_certificate     /etc/letsencrypt/live/relay-ledgers.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/relay-ledgers.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:7777;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 86400s;
    }
}
```

Strfry config (adapt from `deposits-tools/config/strfry.conf`):

```toml
db = "/var/lib/strfry/ledgers/"

relay {
    bind = "127.0.0.1"
    port = 7777
    info { name = "deposits ledgers"; description = "deposits-node durable relay" }
    maxWebsocketPayloadSize = 131072
    events {
        maxEventSize = 65536
        rejectEventsNewerThanSeconds = 900
        # Durable relay — DO NOT set ephemeralEventsLifetimeSeconds here.
    }
}
```

For the messaging relay, copy and override `ephemeralEventsLifetimeSeconds = 60` to expire kind:20101/20102 events.

**Disk for the ledgers relay:** ~2 KB per signed update. For a 10-operator cluster doing 100 deposits/second steady-state that's ~17 GB/day. For a 3-operator sandbox doing maybe 100 ops/day total, it's ~200 KB/day. Provision conservatively (10 GB+) to leave room for retention indexes.

**TLS renewal:** test once before going live. If certbot fails silently mid-month, the cluster goes opaque overnight.

---

## Step 4 — Operator keys and seeds

This is the part that matters most. Don't reuse the regtest pattern (`op0` → `6f7030...00`).

```sh
# On each operator host, generate a 32-byte seed from a high-entropy source.
deposits-node keygen --network bitcoin > /run/secrets/op-seed.hex
chmod 0400 /run/secrets/op-seed.hex
chown deposits:deposits /run/secrets/op-seed.hex
```

The seed deterministically derives:
- The operator's identity pubkey (BIP-32 path `m/86'/0'/0'/0/0`)
- The operator's reserves UTXO key
- The Nostr account key

**Lose the seed → lose access to the ledger.** With Q=2, the other operator can dispute and acquire custody, but their slashed collateral plus dispute-resolution time means it's still a multi-day painful event.

Storage options ranked by paranoia level:
1. Keep the file on the operator host with strict perms (sandbox-acceptable).
2. Encrypt with passphrase, decrypt at daemon startup.
3. KMS-backed secret pulled at startup; never written to disk.
4. Hardware wallet sign service (out of scope here).

For a mainnet sandbox, (1) or (2) is fine. Document which you chose so you can rotate if needed.

---

## Step 5 — Operator daemon

Each operator runs `deposits-node run` natively (matches regtest pattern) but with mainnet flags. Run as a systemd service so it restarts on crash; the existing regtest setup ran as a backgrounded shell process, which is a sandbox shortcut — don't carry that to mainnet.

```ini
# /etc/systemd/system/deposits-node.service
[Unit]
Description=deposits-node operator daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=deposits
Group=deposits
WorkingDirectory=/var/lib/deposits-node
EnvironmentFile=/etc/deposits-node/env
ExecStart=/usr/local/bin/deposits-node run \
    --seed-file /run/secrets/op-seed.hex \
    --name op-alpha \
    --network bitcoin \
    --data-dir /var/lib/deposits-node \
    --esplora https://esplora.example.com \
    --metrics-port 9100 \
    --relay wss://relay-ledgers.example.com \
    --relay wss://relay-messaging.example.com \
    --slow-relay wss://relay-ledgers.example.com
Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

Diff vs `setup.sh`'s regtest invocation:
- `--network bitcoin` (was `regtest`)
- `--esplora https://...` (HTTPS, not localhost HTTP)
- `--relay wss://...` (TLS, not plaintext ws://)
- **No `--fast-poll`**: the 60s default is the right cadence for mainnet. `--fast-poll` was added for regtest test speed; on mainnet it just churns CPU. (See `project_dispute_periodic_interval.md` in memory: structurally event-driven dispute drivers will deprecate this knob entirely.)
- `--metrics-port 9100`: bind to localhost only via firewall, never expose externally.
- `--seed-file` (not `--seed <hex>` from setup.sh) — never put the seed on the command line; ps shows it.

**First-run sequence per operator:**

```sh
# 1. Generate the keypair file (above).
# 2. Start the daemon — it'll discover other operators via Nostr but won't act yet.
sudo systemctl start deposits-node

# 3. Watch the log for "Wallet synced at height N" and "Connected to wss://...".
journalctl -u deposits-node -f

# 4. Operator funds their reserves UTXO with real BTC. Get the address:
deposits-node address --seed-file /run/secrets/op-seed.hex --network bitcoin

# 5. Send the chosen reserves amount (e.g. 0.005 BTC) from a separately-funded
#    wallet to that address. Wait for 6 confirmations.

# 6. Create the reserves UTXO via daemon RPC:
deposits-node reserves create --seed-file /run/secrets/op-seed.hex \
    --network bitcoin --amount-sats 500000

# 7. Open the operator's first ledger:
deposits-node ledger open --seed-file /run/secrets/op-seed.hex \
    --network bitcoin --reserves-amount 400000 --collateral-amount 100000

# 8. Out-of-band: each operator shares their pubkey with the other two.
#    Then each operator runs `quorum add` for the others' pubkeys.

# 9. Once quorums match, run `quorum begin` to activate Q=2 operation.
```

The `setup.sh` script automates steps 6–9 for regtest; for a mainnet sandbox, doing them manually is a feature — each step is a checkpoint where you confirm the on-chain state matches expectations.

---

## Step 6 — Lightning (optional)

The regtest cluster runs an embedded LDK node for invoice tests. **Don't replicate this on mainnet** — opening real channels requires capital and counterparty selection that's outside the scope of a deposits-node sandbox. Instead:

- Skip the `lightning` profile in `docker compose --profile`.
- Skip the `lnaddr-attest` and `lnurl` services (they depend on the LDK node).
- Operators can still process `OnchainOpen` / `OnchainCredit` flows. `InvoiceCredit` requires Lightning and won't work without a real LN node.

If you do want Lightning, use a hosted LSP integration — that's a separate document.

---

## Step 7 — Monitoring

The regtest compose runs Prometheus + Grafana on the same Docker network as bitcoind. For mainnet:

- Run Prometheus + Grafana on a separate host (or at least a separate Docker network).
- Each operator daemon's `--metrics-port 9100` should be firewalled to listen only on localhost; Prometheus reaches it via SSH tunnel or a private overlay network.
- Set up Grafana auth (the regtest compose has `GF_AUTH_ANONYMOUS_ENABLED=true` for convenience — REMOVE that for any non-localhost deployment).

Existing dashboards under `deposits-tools/grafana/dashboards/` cover request rates, cosign latency, ledger-update flow, and run-loop phase breakdowns. They work unchanged on mainnet — the metric names don't depend on network.

Alerting checklist:
- Operator daemon down (job_up == 0 for > 60s)
- Cosign timeout rate > 0
- Relay disconnect (nostr_connections_total flatlines)
- Block-height lag (current chain tip vs daemon's last seen) > 3 blocks
- Reserves UTXO unconfirmed (operator's view of its own UTXO out of mempool)

---

## Step 8 — Backup and recovery

Each operator's data dir contains:
- `wallet/ledgers/<ledger_id>.jsonl` — full append-only ledger history
- `wallet/ledgers/<ledger_id>.actor.log` — actor's shadow (best-effort, regenerable)
- `wallet/reserves.json` and `wallet/taproot_reserves.json` — UTXO references
- `confiscated_*.marker` — dispute outcomes

The JSONL files are the recovery substrate. With them + the operator seed, the daemon can rebuild state at startup. **Snapshot daily** to off-host storage:

```sh
# Operator-side cron, run daily at 03:00:
0 3 * * * tar czf /backup/$(date +%Y-%m-%d)-deposits.tgz /var/lib/deposits-node/wallet/
```

Test the restore path before you need it. Bring up a clone host, restore the tarball, point the daemon at the same seed, watch it sync from relays and reach the same chain_tip_hash as the live operator. If it doesn't, the gap is in your backup procedure.

---

## Step 9 — What to test

Once everything's up and quorums are active, exercise these in order:

1. **Open a deposit on each operator's ledger.** Fund it with real BTC via on-chain. Watch each operator's daemon credit it. Confirms the basic deposit flow works through a real esplora.

2. **Issue a `transfer_lock` between two deposits on the same ledger.** Watch cosignatures appear. Confirm `transfer_complete` clears the lock and updates balances.

3. **Run the cross-ledger HTLC route** (DEP-13). Stand up an htlc-agent (`./bin/setup-htlc-agent.sh` adapted for mainnet) with deposits on at least two of the three ledgers. Drive a wallet-side `route` from one ledger to another. Confirms cross-operator coordination works under real Nostr latency.

4. **Force a fraud-proof scenario.** Use the `dangerous-testing` build feature with the `forge-stale-cosig` CLI to publish an invalid cosignature on one operator's ledger. Watch the other operators detect it, arm for dispute, run the lottery, and confiscate. **Use a small reserves amount** (0.001 BTC) for the disputed ledger so the worst-case loss is bounded.

5. **Restart an operator daemon.** Verify it rejoins the cluster cleanly: chain tip syncs, cosign requests resume, no missed updates.

6. **Lose connectivity to one relay.** Verify the cluster remains functional through the other relay (the daemon broadcasts to all configured relays; consumers fan-in).

If any of these fail in a way regtest didn't catch, file a memory note in `~/.claude/projects/-home-claude-deposits-rust/memory/` so the regression test surface grows.

---

## Things to know that regtest hides

- **Mempool full / fee spike:** during a real fee event, confiscation TXs may sit unconfirmed for hours. Today's `initiate_confiscations` doesn't bump fees on its own — that's a known gap.
- **Reorgs:** mainnet has small reorgs (1–2 blocks) regularly. The protocol's block-anchor verification (used by `UncreditedOnchainPayment` and `DisputeDereliction` fraud proofs) requires the anchor block to be in the verifier's chain — a reorg can briefly invalidate a fraud proof. Quorum members should re-attempt verification after the new tip stabilizes.
- **NTP:** Nostr events have timestamps that relays validate within ±15 minutes (`rejectEventsNewerThanSeconds`). All operator and relay hosts must run an NTP client; clock drift silently breaks event ingest.
- **Public-relay abuse:** the ledgers relay accepts events from anyone. Strfry's default config doesn't rate-limit; for a public-facing deployment, add `dropEventsByPubkey` filtering or a write-side proxy that gates on operator pubkeys.

---

## Tear-down

To cleanly retire the cluster:

1. Each operator runs `deposits-node ledger close` on each of their ledgers (returns reserves UTXO to operator's wallet).
2. Each operator unwinds Lightning channels (if any).
3. Stop daemons (`systemctl stop deposits-node`).
4. Stop Bitcoin / electrs / relays via `docker compose down` (don't pass `-v` unless you actually want to delete the chain history).
5. Delete operator seeds **only after** confirming all reserves are returned to known wallets.

Do not just `docker compose down -v` — that wipes the bitcoind volume and you re-IBD from scratch next time.
