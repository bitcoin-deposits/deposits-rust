# PACKAGING_PLAN — deposits-node for the self-custody bitcoin operator audience

## Who this is for

A self-custody Bitcoiner who already runs a Lightning node at home or on a VPS — Alby Hub, Umbrel (with LDK/LND/CLN), Start9, Citadel, MyNode, or just `bitcoind` + a Lightning daemon under systemd. They've already solved seed safety, channel management, uptime. They want to add "I'm a deposits operator serving public depositors" on top of "I run a Lightning node," and the install should be a small UX delta — not a parallel infrastructure setup.

This was the original product vision. The current deployment shape (`setup.sh 3` brings up 10 operators + bitcoind + relays + grafana on one box) targets a different audience (developer testing a cluster) and fights this one.

## Why this audience first

- They've already passed every prerequisite gate (seed discipline, channel management, full node operation, server uptime).
- "Become a deposits operator" is a strict UX delta of similar magnitude to "open my first Lightning channel," not a new mountain.
- The trust narrative — "collateralized multi-operator custody with on-chain slashing" — is a clean fit for bitcoin self-custody values. It's what people who already self-custody actually want for shared funds, not what they have today (personal multisig with no fraud-proof teeth).
- The Lightning bridge is natural: deposits-node already speaks LDK; operators already speak Lightning; integration is "wire the LN backend you already run into the deposits-node you're installing."

## Where today's deployment shape doesn't match

| Today | Audience expects |
|---|---|
| `deposits-tools/docker-compose.yml` bundles bitcoind + electrs + grafana + LDK | Slot in next to existing bitcoin + LN; depend on them via env |
| `ldk_cli.rs` hardcodes `ldk-server-cli` subprocess (no trait) | Pluggable backend: LDK, LND, CLN |
| `setup.sh N` creates a cluster of N operators on one box | "I'm one operator, here are 4 pubkeys to form a quorum with" |
| Quorum formation requires coordinated `setup.sh`-style bring-up | Public-discovery + handshake flow for forming quorums with strangers |
| Operator admin is `docker exec` + `node_cli/*` CLI | Web admin (Alby-Hub-shaped) for the operators who don't want to live in a terminal |
| No public image registry, no app-store manifests | Umbrel community app, Start9 `.s9pk`, plain `docker pull` |

## Distribution channels (priority order)

1. **Single-host docker-compose** — `deploy/operator.docker-compose.yml`. Two services (deposits-node, deposits-signer). External LN + bitcoin via env. Foundation for everything below.
2. **Umbrel community app** — wraps the single-host compose; depends on the bitcoin-core Umbrel app and one of the LN apps.
3. **Start9 `.s9pk`** — heavier manifest format with config schemas and action manifests; better operator UX once the work is done.
4. **Plain Linux + systemd units / .deb / AUR** — defer. Real ongoing maintenance burden; not a great first-audience fit.

Skipped: **Flatpak / Snap** — wrong fit for server daemons.

## Tier plan

### Tier 1a: `LightningBackend` trait + impls ✅ shipped

Extracted the surface `ldk_cli.rs` already implements into a `LightningBackend` trait. Three impls: `LdkBackend` (subprocess to `ldk-server-cli`), `LndBackend` (REST + macaroon), `ClnBackend` (Unix-socket JSON-RPC). Selected at runtime via `LIGHTNING_BACKEND=ldk|lnd|cln` env; single image supports all three.

Trait surface: `get_node_info`, `get_balances`, `create_invoice` (with + without description hash), `create_invoice_any_amount`, `pay_invoice` (with + without amount override), `list_channels`, `list_payments`, `get_payment_preimage`.

What landed (Sep 2026 commits):
- `223a440e`: LightningBackend trait + LdkBackend impl
- `f568d302`: migrate the ~11 production callers to `&dyn LightningBackend`
- `748a6e25`: rename LdkCli → LdkBackend for symmetry with sibling impls
- `<this>`: LndBackend + ClnBackend impls + env-driven dispatch

Compile-time conformance tests on all three impls; JSON-fixture parsers for the LND/CLN response shapes; trait-method-mapping unit tests.

Two known limitations:
- `LndBackend::get_node_info` returns no `current_best_block_hash` (LND's `/v1/getinfo` doesn't surface it). Display-only impact.
- `ClnBackend::create_invoice_with_desc_hash` returns `Err` because CLN's `invoice` command doesn't accept an explicit description hash. NIP-57 zap invoices need LDK or LND today; an upstream CLN improvement (or our `invoicerequest` adoption) fixes this later.

Outstanding for full audience coverage: end-to-end integration tests against a real LND / CLN (polar / docker — requires CI infrastructure investment). Compile-time conformance covers the "does this type satisfy the trait" question; real wire validation against live nodes lands when CI gets there.

**Why this was Tier 1**: without it, every Umbrel/Start9 user was bound to a specific LN backend and we only spoke one. With this landed, the operator picks `LIGHTNING_BACKEND=lnd` (Umbrel default) or `cln` and a single image works.

### Tier 1b: `ChainBackend` trait + impls ✅ shipped

Mirror of Tier 1a for bitcoin chain data. Three impls: `EsploraBackend`
(electrs/esplora HTTP), `BitcoindRpcBackend` (direct bitcoind JSON-RPC),
`ElectrumBackend` (electrum protocol over TCP). Selected at runtime via
`CHAIN_BACKEND=esplora|bitcoind|electrum` env; single image supports all three.

Trait surface: `get_tip_height`, `get_block_hash`, `get_block_height_if_in_best_chain`, `get_tx`, `get_tx_block_height`, `is_output_unspent`, `find_unspent_output_at`, `broadcast_tx`.

What landed:
- `e55dc3ac`: ChainBackend trait + EsploraBackend impl
- `3fb0da62`: migrate 14 wallet.rs + 4 ledger_wallet.rs + 11 recovery.rs callers to `&dyn ChainBackend`
- `<this>`: BitcoindRpcBackend + ElectrumBackend impls + env-driven dispatch + cluster integration

**Subtlety**: BDK has its own chain-source abstraction (`bdk_esplora`, `bdk_bitcoind_rpc`, `bdk_electrum`) for the wallet **sync** path. The ChainBackend trait sits *above* BDK for the operations BDK doesn't cover (broadcast, fetch-by-id, get-tip, output-status), and *parallel to* BDK's chain sources for the sync path (each backend impl wires the matching BDK source). BDK stays in-process; this trait isn't an attempt to replace it.

Compile-time conformance + fixture-parser tests on each impl. Cluster integration via `CHAIN_BACKEND=bitcoind|electrum ./bin/setup.sh N` — exercises the backends end-to-end through the existing tier-3 protocol tests.

**Why Tier 1b mattered at the same priority as 1a**: without it, the docker-compose in Tier 2 still had to bundle esplora or document "first set up electrs separately," which fought the "slot in next to your existing stack" framing. With it done, the Tier-2 single-operator compose can express `CHAIN_BACKEND=bitcoind` against an operator's existing `bitcoind` and not bundle anything extra.

One known limitation: `ElectrumBackend::get_block_height_if_in_best_chain` walks the last ~2016 blocks; lookups against deeper hashes return `Ok(None)`. Bitcoind / esplora callers needing deep cold-block confirmation should pick those backends.

### Tier 2: Single-operator docker-compose ✅ shipped

Lives under [`deploy/operator/`](deploy/operator/):
- `docker-compose.yml` — two services (deposits-signer, deposits-node).
  Internal-only `signer-net` between them; signer socket via a shared
  named volume. Same image runs both binaries (entrypoint overrides
  pick which). All external deps (bitcoin RPC, LN backend, relays)
  declared via env, none bundled.
- `.env.example` — every supported env var with comments + sensible
  defaults. Comprehensive enough that operators who don't want to use
  the wizard can edit by hand.
- `init.sh` — interactive wizard. Walks through network + LN backend +
  chain backend + relays + seed (generate or import). Runs
  `deposits-signer init`, extracts the daemon transport-pubkey via the
  `deposits-node transport-pubkey` subcommand, allowlists it on the
  signer, writes `SIGNER_PUBKEY` back into `.env`. Idempotent.
- `README.md` — 5-minute quickstart + per-backend bind-mount snippets
  (LND macaroon, CLN socket, bitcoind cookie) + operating cheatsheet +
  troubleshooting + backup checklist + a "what's bundled vs not" table
  that makes the minimalism explicit.

Acceptance unchanged: a clean Ubuntu VPS with bitcoind + LND already
running follows `README.md` and is operational in ~5 minutes.

What's NOT yet there:
- Pre-built images on a public registry. Operators build locally
  (`docker build -f deposits-node/Dockerfile .`) until CI ships images
  to `ghcr.io/bitcoin-deposits/deposits-node`. The compose's
  `${DEPOSITS_IMAGE:-deposits-node:latest}` env var is ready for the
  registry swap.
- Acceptance test against a real Ubuntu VPS. Shape is right; needs a
  live drive-through to surface anything the wizard's prompts don't
  cover.

### Tier 3: Quorum-formation wizard (private flow ✅ shipped; public flow pending)

**Private flow ✅** — operators who know each other's pubkeys out-of-band:

- `deposits-node quorum show-identity` — prints operator pubkey + owned
  ledger IDs in copy-paste form. Peers paste into a chat / email.
- `deposits-node quorum form-with --ledger-id <our> --member <pk>:<lid> [--member ...] [--begin --amount-sats N]`
  — orchestrator: validates inputs, calls quorum_add for each member
  sequentially, optionally runs quorum begin at the end.
- [`deploy/operator/QUORUM.md`](deploy/operator/QUORUM.md) — walkthrough
  covering show-identity → coordination → form-with → verify → operate.
  Includes Q sizing, membership expiry, troubleshooting.

Acceptance for private flow: 3 operators on 3 different boxes can
form a quorum following QUORUM.md without ever touching `setup.sh`.

**Public flow** — still pending. Operator advertises "seeking partners
for quorum" on the ledger relay; other operators discover via
`quorum list-seekers`, request to join, originator accepts. Touches the
advertisement protocol (new ad shape) + adds two CLI commands. Bigger
lift than the private flow; ships when there's enough operator density
that strangers-finding-strangers is the natural pattern. For now the
documented path is "use the project's announce channel out-of-band."

### Tier 4: Umbrel community app (manifest ready, submission blocked)

The Umbrel community-apps package lives in
[`deploy/umbrel/`](deploy/umbrel/):

- `umbrel-app.yml` — manifest (id, version, deps on `bitcoind` +
  `lightning`, repo + support URLs, port = metrics endpoint, gallery)
- `docker-compose.yml` — Umbrel-shaped: uses `APP_BITCOIN_NODE_IP` /
  `APP_LIGHTNING_NODE_*` / `APP_DATA_DIR` env vars; bakes in
  `CHAIN_BACKEND=bitcoind` + `LIGHTNING_BACKEND=lnd`
- `icon.svg` — vault motif in bitcoin orange
- `README.md` — submission steps + status (what blocks publication today)

**Three things block submission to getumbrel/umbrel-apps:**

1. **Published Docker images.** The compose pins
   `ghcr.io/bitcoin-deposits/deposits-node:0.1.0`. That tag needs to
   exist on a public registry. CI publish-on-tag needs to land first.
2. **Gallery screenshots** — three `.jpg`s referenced by name from the
   manifest. Trivial once the app is running for someone to capture.
3. **First-boot UX inside Umbrel.** The deploy/operator wizard is
   interactive; Umbrel users can't run an interactive shell against an
   app from the UI. Either ship an `exports.sh`-triggered first-boot
   script, a "first time setup" web page, or document the manual
   `docker exec` bootstrap (current README does the last).

Once those land the PR is small and mechanical.

Same shape adapts to Start9's `.s9pk`, Citadel community apps, MyNode
add-ons — each has its own packaging format. Per the recommendation
in this plan: Umbrel first (biggest user base), Start9 second
(polished UX), others as demand surfaces.

### Tier 5: Web operator admin UI

The polished-UX target — what Alby Hub does for Lightning, applied to the deposits operator surface. Static frontend (probably vanilla TS or React, served by the deposits-node directly so it's behind the same auth boundary as the admin RPCs). Pages:

- Dashboard: ledgers, quorums, collateral position, recent activity, sync status.
- Actions: rotate quorum, respond to dispute, lock for fulfillment, transfer between deposits.
- Settings: LN backend config, bitcoin RPC, relay URLs, signer status, network preferences.
- Audit log: every operator-initiated action with timestamp, op type, target, outcome.

Needs a new "admin API" surface on the daemon (today's `node_cli/*` flows are CLI-shaped, not HTTP-shaped). Auth via a generated bearer token written to disk on first run (operator copies it once); a future iteration can do proper user accounts.

Acceptance: an operator who has never used the deposits CLI can do a full day's operator work — open a quorum, watch payments flow, respond to a dispute, rotate keys — entirely in the browser.

### Tier 6 — REMOVED

Previously framed as "NWC speaker (depositor-side)." Removed because
NWC has no primitive for the depositor's wallet to produce a dep-17
receive-witness signature with the deposit's key — NWC's surface is
BOLT11 payments / invoice creation / balance queries, not arbitrary
preimage signing with a path-derived key.

NWC-compatible wallets (Alby Extension, Mutiny, etc.) can still pay
BOLT11 invoices an operator issues today — that path works without
any deposits-specific integration. The receive-witness flow that lets
depositors gate inbound credits (`receive_requires_sig = true`) needs
custody of the deposit's signing key, which NWC isn't built to grant.

If a real depositor-facing tier slots in here later, it'd be wallet
polish work (the receive-side flow we already shipped) or the
wallet-side advertisement-protocol update flagged in SIGNER.md §9.

## Sequencing rationale

- **Tier 1a and 1b in parallel** — both are structural unlocks; nothing else can ship without them. 1a is smaller and validated first; 1b is bigger (more call sites, BDK type-coupling) but blocks Tier 2 just as hard.
- **Tier 2 next** — packages Tier 1 for direct VPS install. Validates the single-operator deployment shape end-to-end.
- **Tier 3 in parallel with Tier 2** — independent code path; can be developed concurrently. Blocks "real first operator deploys to mainnet" because they need to form a quorum somehow.
- **Tier 4 after Tier 2** — mechanical wrap; ship once Tier 2 is solid.
- **Tier 5 is polish** — significant scope (probably weeks of work for a credible MVP), not blocking the install path. Worth starting in parallel with Tiers 2-4 if there's bandwidth.

## Open decisions

These need product input before too much code lands:

1. **LND-first vs CLN-first** for the second `LightningBackend` impl after LDK. Alby Hub uses LDK so the existing impl already covers that crowd. LND has the larger user base (Umbrel default, Start9 default); CLN is a smaller niche. Recommend LND.
2. **Bitcoind-first vs Electrum-first** for the second `ChainBackend` impl after Esplora. Direct bitcoind RPC fits the "I already have a full node" audience; electrum covers users who already run electrs (less common standalone, common as part of larger stacks). Recommend bitcoind.
3. **Single image vs per-backend image** — Single image with all backends compiled in + runtime selection is simpler distribution (one `docker pull`). Per-backend images are smaller but multiply CI artifacts. Recommend single image; runtime cost of dead backends is negligible.
4. **Umbrel first or Start9 first** — Umbrel has the larger user base, easier review (PR to a public repo). Start9 has a more polished package format (config schemas, action manifests) and better operator UX. Recommend Umbrel first to maximize reach; Start9 second to set the bar for polish.
5. **Operator admin UI: build or fork** — Alby Hub's frontend is open source. Fork-and-adapt could save weeks vs greenfield. Recommend fork-and-adapt for the initial cut; rewrite later if scope diverges enough to make the fork untenable.
6. **What's the "default cluster" for first-time operators?** — Tier 3's "private quorum with named pubkeys" assumes the operator knows other operators. For first deployments, do we run a "public matchmaking" service that lists operators looking for partners? Or do we punt that until there's enough operator density that they find each other organically? Recommend punt; document the manual flow in launch docs.

## Acceptance for "ready to recommend to the audience"

A self-custody Bitcoiner who already runs Alby Hub on Umbrel should be able to:

1. Click "Install" on the deposits app in Umbrel's community store.
2. Complete a setup wizard that auto-detects their LN node + bitcoind and configures everything.
3. Form a quorum with 2-4 other operators (whose pubkeys they found via the project's launch docs).
4. See their first depositor open a deposit, pay an invoice through their LN node, and credit the deposit balance.

Tiers 1a + 1b + 2 + 3 + 4 are sufficient to make that path work end-to-end. Tier 5 makes step 4 onward a pleasant operating experience instead of a CLI ordeal.
