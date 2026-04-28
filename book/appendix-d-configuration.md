# Appendix D: Configuration Reference

> **Audience**: operators, developers, integrators
> **Prereqs**: [Chapter 19: Architecture Tour](19-architecture-tour.md), [Chapter 23: Operations and Mainnet](23-operations.md)
> **DEPs**: none

This appendix is a reference for every configuration knob a deposits process consumes: command-line flags, environment variables, on-disk files, and the Docker stack defaults. It does not teach concepts — those live in the protocol chapters and the operations chapter. Use it to look up "what does `--fast-poll` actually do?" or "where does the daemon write the allowlist?"

The three binaries covered here are `deposits-node` (the daemon and operator-side CLI), `deposits-wallet` (the depositor-side CLI), and `deposits-attest` (the optional Lightning-address attestation service). Source-of-truth definitions live in `deposits-node/src/node_cli/`, `deposits-wallet/src/wallet_cli/`, and `deposits-attestation/src/bin/deposits-attest.rs`.

## 1. Daemon (`deposits-node`)

### 1.1 Common flags

These flags are accepted by **every** subcommand of `deposits-node` (parsed by `parse_config` in `deposits-node/src/node_cli/mod.rs`). Any subcommand may also accept them, even when they look read-only (`info`, `address`).

| Flag | Type | Default | Description |
|---|---|---|---|
| `--seed <hex>` | 64-char hex | random + warning | The 32-byte master seed. The operator's signing key is derived as `m/86'/0'/0'/0/0` from this seed. Treat as the root secret. |
| `--name <s>` (alias `--operator-name`) | string | none | Operator's display name. Surfaced in logs and copied into `LedgerAdvertisement.operator_name` when `ledger advertise` runs. |
| `--network <net>` | `mainnet` \| `bitcoin` \| `testnet` \| `signet` \| `regtest` | `signet` | Bitcoin network. Affects address derivation, reserves script type, and which Esplora endpoint defaults make sense. |
| `--data-dir <path>` | filesystem path | `~/.deposits-node` | Where the daemon stores ledger files, BDK wallet state, the address index, processed-event sets, and lists. Created if absent. |
| `--esplora <url>` (alias `--electrum`) | URL | `https://mempool.space/signet/api` | Esplora REST endpoint (electrs-compatible). The wallet uses this for sync, broadcasting, and confirmation queries. |
| `--relay <url>` | WebSocket URL | none | Nostr relay URL. Pass once per relay; at least one is required for `run` and any subcommand that talks to the running daemon. |
| `--slow-relay <url>` | WebSocket URL | none | Secondary relay used only for low-priority traffic (advertisements, attestation cover events). Pass once per relay. |
| `--fast-poll` | flag | off | Tighter periodic-task intervals — meant for regtest and integration tests where you don't want to wait 30s between auto-task cycles. Do not enable in production. |
| `--skip-nostr-verify` | flag | off | Skip Nostr signature verification on inbound events. Test-only; subverts the protocol's authentication. |
| `--metrics-port <port>` | u16 | `9100` (test scripts use `9100 + op_idx`) | Prometheus exporter listener. `run` subcommand only. See section 4 for what the exporter exposes. |

### 1.2 Subcommands

The top-level dispatch is in `deposits-node/src/bin/deposits-node.rs`. Each subcommand has its own argument parser; what follows is a survey, not a per-flag enumeration.

**`run`** — daemon mode. Boots the `Node`, syncs the BDK wallet, opens relay subscriptions, refreshes ledger advertisements, and drives the actor pool indefinitely. The only `run`-specific flag is `--metrics-port`.

**`info`** — print Node ID, Nostr pubkey, on-chain wallet balance, reserves balance, and the next reserves address. Read-only short-lived process; does not require a running daemon.

**`address`** — derive and print the next BDK funding address. Increments `address_index.txt` in the data dir.

**`keygen`** — generate a fresh secp256k1 keypair, print as hex. No daemon, no data dir.

**`derive-deposit-key`** — derive a wallet-side deposit secret key from a seed at a given index. Used by collateral scripting flows.

**`reserves <create|list>`** — `create [amount_sats]` produces a reserves UTXO (default 100 000 000 sats / 1 BTC) by sending to a freshly-derived reserves address. `list` enumerates known reserves. Both go through the running daemon via gift-wrapped admin requests.

**`ledger <open|list|history|validate|export|advertise>`** — `open` creates a new ledger backed by a reserves UTXO. Fee-schedule flags set advertised minimums:
- `--annual-fee-bps <N>` — annual custody fee in basis points
- `--min-fee-sats <N>` — minimum fee per period
- `--fee-period-blocks <N>` — period length (default 2016)
- `--transfer-fee-fixed-msats <N>` — fixed per-transfer fee
- `--transfer-fee-rate-bps <N>` — proportional per-transfer fee

`advertise` republishes Kind 39100 ads with the latest chain tip and balances. `validate`, `history`, `export` are read-only inspection commands.

**`quorum <add|join|begin|request|list>`** — operator-side quorum management. `add <ledger_id> <member_pubkey> <member_ledger_id>` records `QuorumAddMember` on the operator's own ledger after collecting consent. `join` records that the local operator joined someone else's quorum. `begin [reserves_id]` rotates the reserves UTXO into the Q-of-Q multisig (the Phase 4 transition described in [Chapter 7](07-quorum-and-collateral.md)).

**`deposit <offer|list|open|ls|credit|check|complete>`** — deposit-side bookkeeping. `offer` writes a signed `DepositOffer` to the relay so a wallet can fund it. `credit` manually credits a deposit (Lightning-receive path). `complete` finalizes a confirmed on-chain offer.

**`withdraw <request|lock|complete|cancel|list>`** — on-chain withdrawal lifecycle. `request` is the one-shot wallet-or-operator-side path that signs and locks in a single step.

**`lightning` (alias `ln`)** — two groups: LDK sidecar wrappers (`invoice`, `pay`, `balance`, `info`, `channels`, `payments` — these shell out to `ldk-server-cli`) and ledger-operation wrappers (`lock`, `fail`, `fulfill`).

**`nostr <list|export|import|validate|request|watch|dispute>`** — relay-level operations. `export` and `import` move ledger updates between a local data dir and a relay. `dispute publish` opens a dispute against a non-conforming ledger. `dispute listen` subscribes to dispute events.

**`recovery`** — the dispute pipeline (see [Chapter 12](12-recovery-pipeline.md)). The full set:

- New protocol: `dispute`, `rebuild`, `arm`, `claim`, `continue`, `spend`, `status`
- Lottery pipeline: `confiscate`, `reveal`, `lottery-claim` (see [Chapter 13](13-custody-lottery.md))
- Helpers: `embed-hash`, `publish-fraud-broadcast`, `rotate-to-quorum`
- Legacy: `start`, `agree`, `prepare`, `release` (kept for back-compat tests)

**`admin`** — gift-wrapped admin requests dispatched to a running daemon (operator-authenticated administrative operations).

**`bootstrap`** — one-shot operator bootstrap helpers.

**`health`** — health-check probes for monitoring.

**`danger`** — testing-only, gated behind the `dangerous-testing` cargo feature. `publish-invalid <reserves_id> <violation_type>` deliberately publishes a malformed update to exercise dispute detection. Violation types: `invalid-hash`, `skip-sequence`, `double-spend`, `replay`. Never compile this into a production binary.

## 2. Wallet (`deposits-wallet`)

### 2.1 Common flags and env vars

Wallet config (parsed by `parse_config` in `deposits-wallet/src/wallet_cli/mod.rs`) accepts both flags and environment variables. Flags win when both are set.

| Flag | Env var | Default | Description |
|---|---|---|---|
| `--seed <hex>` | `WALLET_SEED` | autogen + write to `seed.hex` | 32-byte hex seed. If neither flag nor env nor on-disk seed file exists, a fresh seed is generated and saved. |
| `--network <net>` | `WALLET_NETWORK` | `regtest` | `bitcoin`/`mainnet`, `testnet`, `signet`, `regtest`. |
| `--data-dir <path>` | `WALLET_DATA_DIR` | `~/.deposits-wallet` | Where the wallet stores its seed, deposits.json, and per-deposit key index. |
| `--relay <url>` | `WALLET_RELAY` (single) | none | Nostr relay. Pass `--relay` multiple times for fallbacks; the env var takes only one. |
| `--alias <name>` | — | — | Local alias for the deposit. Used by `open`. |
| `--nsec-file <path>` | — | — | Override the Nostr identity. File contents must be `nsec1…` bech32 or 64-char hex. Files only — argv is visible in `ps`. |
| `--subkey-of <npub-or-hex>` | — | — | DEP-04 subkey delegation: act on behalf of this account. Must be paired with `--attestation-sig`. |
| `--attestation-sig <hex>` | — | — | 64-byte Schnorr attestation signature matching `--subkey-of`. |

The regtest helpers also read `BITCOIN_RPC_HOST`, `BITCOIN_RPC_PORT`, `BITCOIN_RPC_USER`, `BITCOIN_RPC_PASS`, and `BITCOIN_RPC_WALLET` to talk to a local bitcoind for `regtest-faucet`.

### 2.2 Subcommands

The dispatch is in `deposits-wallet/src/main.rs`. Categories follow the wallet's own usage banner:

- **Discovery**: `discover`, `info <ledger_id>`
- **Deposit lifecycle**: `open <ledger_id>`, `list`, `balance`, `sync`
- **Funding**: `offer <alias> <sats>`, `make_invoice <alias> <sats>`, `spread <total> [--count N]`
- **Outgoing payments**: `pay_invoice`, `send`, `transfer`, `transfer_complete`, `withdraw`, `route`
- **Swaps**: `swap-advertise`, `swap-list`, `swap-request`, `swap-listen`
- **Inspection**: `history <alias>`, `ledger list`, `ledger show`, `ledger validate`, `ledger custody`
- **Identity (DEP-04 subkey delegation)**: `attest`, `revoke`, `subkeys`
- **Escalation** (see [Chapter 15](15-delivery-escalation.md)): `escalate`
- **Regtest only**: `regtest-faucet <alias|addr> [sats]` — sends faucet sats and mines a block; relies on the `BITCOIN_RPC_*` env vars.

## 3. Attestation service (`deposits-attest`)

The Lightning-address verification service is configured entirely through environment variables — it has no command-line flags. Source: `deposits-attestation/src/bin/deposits-attest.rs`. Every variable below also accepts a `<NAME>_FILE` form pointing at a file (precedence: file over plain env), so secrets can be mounted as files in container deployments without leaking into argv.

| Variable | Default | Description |
|---|---|---|
| `VERIFY_NSEC` (or `VERIFY_NSEC_FILE`) | required | Nostr secret key; `nsec1…` bech32 or 64-char hex. The attestor's identity. |
| `VERIFY_RELAYS` | `wss://relay.damus.io` | Comma-separated relay URLs. The service subscribes here for Kind 25500/25502 requests. |
| `VERIFY_ATTESTATION_RELAYS` | falls back to `VERIFY_RELAYS` | Optional separate relay set for publishing durable Kind 55502 attestations. |
| `VERIFY_CHALLENGE_SATS` | `1000` | Total challenge amount, split across `VERIFY_NUM_PAYMENTS` payments. |
| `VERIFY_NUM_PAYMENTS` | `3` | Number of micro-payments the user must report back. Must be ≥ 2 and ≤ `VERIFY_CHALLENGE_SATS`. |
| `VERIFY_MAX_ATTEMPTS` | `3` | Maximum guess attempts per session before refusal. |
| `VERIFY_PREMIUM_SATS` | `0` | Optional premium charged on top of the challenge total. |
| `VERIFY_FEE_FALLBACK_SATS` | `10` | Per-payment fee assumption when the LDK fee probe fails or is stale. |
| `VERIFY_TIMEOUT_SECS` | `600` | Verification session timeout. |
| `VERIFY_FEE_CACHE_SECS` | `3600` | TTL for cached LNURL fee probes. |
| `VERIFY_NIP05_CACHE_SECS` | `3600` | TTL for cached NIP-05 lookups. |
| `VERIFY_CA_CERT` (or `_FILE`) | unset | Extra CA certificate to trust for self-signed NIP-05/LNURL servers in test environments. |
| `VERIFY_ALLOWLIST_FILE` | unset | Path to an allowlist consulted by the `proclaim` action (lets a trusted signer vouch for an arbitrary npub). |
| `VERIFY_COVER_ANCHOR` (or `_FILE`) | verifier's own xonly | The anchor whose Kind 3 contact list seeds the WoT cover ([Chapter 18](18-ring-signatures.md)). |
| `VERIFY_COVER_KMIN` | `5` | Minimum ring size in the published cover. |
| `VERIFY_COVER_PCT` | `100` | Ring size as a percentage of the anchor's follow set (clamped to 100). |
| `VERIFY_COVER_NUM_RINGS` | `1` | Number of rings in the cover. |
| `VERIFY_COVER_DTAG` | `default` | The `d` tag on the published cover event. |
| `VERIFY_COVER_REFRESH_SECS` | `3600` | How often the background task republishes the cover. |
| `LDK_CLI` | `ldk-server-cli` | Path to the LDK server CLI binary. |
| `LDK_HOST` | `localhost` | LDK server host. |
| `LDK_PORT` | `3000` | LDK server port. |
| `LDK_API_KEY` (or `_FILE`) | `test_api_key` | LDK API key. The `_FILE` form hex-encodes binary contents. |
| `LDK_TLS_CERT` | unset | TLS cert path passed to `ldk-server-cli -t`. |

## 4. Environment variables (daemon)

| Variable | Where | Description |
|---|---|---|
| `RUST_LOG` | all binaries | Logging filter — `error`, `warn`, `info`, `debug`, `trace`. Honors per-module syntax (e.g. `info,deposits_node::node::main_loop=debug`). |
| `TRACING_FLAME_PATH` | daemon | If set, span timing is recorded as a folded flamegraph at that path. Render with `inferno-flamegraph < tracing.folded > flamegraph.svg`. Spans come from `#[tracing::instrument]` attributes — `Node::new`, `commit_operation`, `sign_and_broadcast`, `request_cosign`, `handle_ledger_update`, `persist_ledger_to_disk`. |
| `DEPOSIT_ACCESS_CONTROL` | daemon | Set to `true` (or `1`) to enable the deposit allowlist — only npubs listed in `deposit_allowlist.txt` may open deposits, and the allowlist setting is published in the ledger advertisement. The denylist is always consulted regardless. |
| `MAX_DEPOSIT_BALANCE_MSATS` | daemon | If set to a positive integer, advertised as a per-deposit balance ceiling in the ledger advertisement. |

The daemon also exposes Prometheus metrics on `--metrics-port` (default 9100, but `bin/setup.sh` and `bin/start-operators.sh` use `9100 + op_idx` so a 10-operator regtest cluster ends up on 9100–9109). Histograms cover commit latency, cosign round-trip, persistence latency, and per-operation timings. See `deposits-node/src/metrics.rs`.

## 5. Data directory layout

The daemon's data directory holds wallet state, ledger files, and the various lists. Paths are relative to `--data-dir`.

```
data-dir/
├── daemon.pid                             # written by setup.sh / start-operators.sh, not the daemon itself
├── daemon.log                             # likewise — operator-script convention
├── address_index.txt                      # next BDK address index (incremented by `address`)
├── reserves.json                          # legacy reserves state (kept for migration)
├── taproot_reserves.json                  # current Taproot reserves state
├── deposit_allowlist.txt                  # one npub-or-xonly-hex per line; comments start with `#`
├── deposit_denylist.txt                   # same format, always enforced
├── deposit_domain_allowlist.txt           # one lowercase domain per line; advertised when DEPOSIT_ACCESS_CONTROL=true
├── seed.hex                               # only when seed was autogenerated (rare for operators; common for wallets)
└── wallet/
    └── ledgers/
        ├── <ledger_id>.jsonl              # authoritative chain — one SignedLedgerUpdate per line
        ├── <ledger_id>.actor.log          # actor pool's parallel mirror (8a/8b shadow); not loaded by handler
        └── <ledger_id>_<seq>_<pk16>.jsonl # fork-branch file written during a dispute, named with disputant's pubkey prefix
```

The `.actor.log` extension exists deliberately so the handler's `*.jsonl` glob doesn't pick up the actor's shadow files. See [Chapter 20](20-the-daemon.md) for what each file is for and how the actor migration uses them.

## 6. Docker stack ports

The compose file at `deposits-tools/docker-compose.yml` brings up infrastructure (bitcoind, electrs, optional Lightning, monitoring). Operator nodes themselves run **outside** Docker, against this stack. Default port mappings:

| Service | Container port → host port | Purpose |
|---|---|---|
| `bitcoind` (regtest) | 18443 → 18543 | RPC |
| `bitcoind` (regtest) | 18444 → 18544 | P2P |
| `electrs` | 3002 → 3102 | Esplora REST (`--esplora http://localhost:3102` from a host-side daemon) |
| `electrs` | 4224 → 4224 | Prometheus monitoring |
| `lightning` (LDK) | 9735 → 9835 | Lightning peer port |
| `lightning` (LDK) | 3000 → 3111 | LDK admin RPC |
| `lnaddr-attest` | 443 → 8805 | NIP-05 + LNURL test fixture, HTTPS |
| `lnurl` | 3000 → 3000 | Standalone LNURL-pay gateway |
| `wallet` (web) | 80 → 8888 | Static HTML wallet served by nginx |
| `prometheus` | 9090 → 9190 | Metrics scrape UI |
| `grafana` | 3000 → 3110 | Dashboards (anonymous-admin enabled) |

The Nostr relays (`strfry`) are **not** in Docker — `setup.sh` starts two natively on the host:

| Relay | Default port (env override) | Role |
|---|---|---|
| `ledgers` | `17779` (`RELAY_LEDGERS_PORT`) | Durable: ledger updates, advertisements, attestations |
| `messaging` | `17780` (`RELAY_MESSAGING_PORT`) | Ephemeral: gift-wrapped requests, cosign rounds |

The `lightning` and monitoring services live behind the `lightning` profile, so a baseline `docker-compose up -d` brings up only bitcoind, electrs, the Bitcoin Prometheus exporter, the miner, the wallet UI, and the metrics stack. Use `docker-compose --profile lightning up -d` to add the Lightning sidecar and attestor.

## 7. `setup.sh` walkthrough

`deposits-tools/bin/setup.sh <Q>` brings up a complete regtest cluster of operators, ledgers, and active quorums. Pass an integer `Q` for the quorum size; `setup.sh 3` produces 10 operators (`3*3+1`), `setup.sh 5` produces 16, `setup.sh 7` produces 22. The script reads three optional environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `DEPOSITS_NODE` | `$REPO_ROOT/target/release/deposits-node` | Path to the daemon binary. |
| `DATA_ROOT` | `$TOOLS_DIR/data` | Where per-operator state lives (one subdir per `op<i>`, plus `state/` and `relays/`). |
| `STRFRY_BIN` | `$SCRIPT_DIR/strfry` | The strfry binary used for the two relays. |
| `ELECTRS_URL` | `http://localhost:3102` | Esplora endpoint — must match the docker-compose mapping. |
| `RELAY_LEDGERS_PORT` | `17779` | Override the durable relay port (e.g. when running two clusters side by side). |
| `RELAY_MESSAGING_PORT` | `17780` | Override the ephemeral relay port. |

For `Q=3` the script:

1. **Phase 1**: stops any prior nodes/relays, wipes `DATA_ROOT`, starts the two strfry relays, ensures bitcoind has a `faucet` wallet with 101+ blocks of mature coinbase, and funds 10 operator addresses with `(reserves + collateral) * ledgers_per_op + 0.5` BTC each.
2. **Phase 1b**: starts 10 daemons (`op0`–`op9`), each with `--metrics-port 910N`, `--fast-poll`, `--data-dir data/opN`, both relays, and a deterministic 64-char seed (`hex("opN")` zero-padded).
3. **Phase 2**: for each operator, creates 3 reserves UTXOs and opens 3 ledgers — one per UTXO. Each ledger gets a `ledger advertise` against the durable relay so wallet `discover` finds it. State is recorded under `data/state/reserves_<i>_<l>` and `data/state/ledger_<i>_<l>`.
4. **Phase 3**: assigns `Q` quorum members per ledger using a stride-based dispersion across the operator pool, recording `QuorumAddMember` on each operator's own ledger.
5. **Phase 4**: invokes `quorum begin` on every ledger in parallel, mining periodically while the rotation transactions confirm and the staged-member cosign rounds run.

The cluster shape that results is `(3Q+1)` operators, each with 3 ledgers, each ledger backed by a 1 BTC UTXO (40 % reserves, 60 % collateral) sitting in a Q-of-Q Taproot multisig. Per-operator state lives at `data/op<i>/`, the consolidated ID lookup table at `data/state/`, and relay databases at `data/relays/{ledgers,messaging}/`. To resume after a partial failure without re-running from scratch, use `bin/setup-resume.sh`.
