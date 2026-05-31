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
| `ldk_cli.rs` hardcodes `ldk-server-cli` subprocess (no trait) | Pluggable backend: LDK, LND, CLN, NWC fallback |
| `setup.sh N` creates a cluster of N operators on one box | "I'm one operator, here are 4 pubkeys to form a quorum with" |
| Quorum formation requires coordinated `setup.sh`-style bring-up | Public-discovery + handshake flow for forming quorums with strangers |
| Operator admin is `docker exec` + `node_cli/*` CLI | Web admin (Alby-Hub-shaped) for the operators who don't want to live in a terminal |
| No public image registry, no app-store manifests | Umbrel community app, Start9 `.s9pk`, plain `docker pull` |

## Distribution channels (priority order)

1. **Single-host docker-compose** — `deploy/operator.docker-compose.yml`. Two services (deposits-node, deposits-signer). External LN + bitcoin via env. Foundation for everything below.
2. **Umbrel community app** — wraps the single-host compose; depends on the bitcoin-core Umbrel app and one of the LN apps.
3. **Start9 `.s9pk`** — heavier manifest format with config schemas and action manifests; better operator UX once the work is done.
4. **NWC speaker (depositor-side)** — separable workstream, not a packaging task per se. Lets Alby Extension / Mutiny / Coinos users pay-in/out without installing the deposits-web wallet.
5. **Plain Linux + systemd units / .deb / AUR** — defer. Real ongoing maintenance burden; not a great first-audience fit.

Skipped: **Flatpak / Snap** — wrong fit for server daemons.

## Tier plan

### Tier 1: `LightningBackend` trait + impls

Extract the surface `ldk_cli.rs` already implements into a `LightningBackend` trait. Make the existing `LdkCli` the LDK impl. Add `LndBackend` (macaroon + REST/gRPC) and `ClnBackend` (Unix socket / gRPC). Wire the choice from config (`LIGHTNING_BACKEND=ldk|lnd|cln` env var) so a single image supports all three.

The trait surface (extracted verbatim from current callers): `get_node_info`, `get_balances`, `create_invoice` (with + without description hash), `create_invoice_any_amount`, `pay_invoice` (with + without amount override), `list_channels`, `list_payments`, `get_payment_preimage`.

Acceptance: end-to-end integration test where deposits-node runs against a polar-spawned LND node (or a Docker LND in CI) and successfully makes/pays invoices.

**Why this is Tier 1**: without it, the audience can't install — every Umbrel/Start9 user is bound to a specific LN backend and we only speak one. Structural unlock for all of Tier 2-4.

### Tier 2: Single-operator docker-compose

New `deploy/operator/docker-compose.yml`. Two services: `deposits-node` and `deposits-signer`. Internal-only network between them; signer socket via a shared volume. External bitcoin RPC + LN backend configured via env (`BITCOIN_RPC_URL`, `LIGHTNING_BACKEND`, `LND_MACAROON_FILE`, etc.). No bundled bitcoind/electrs/grafana.

Plus `deploy/operator/init.sh` — a setup wizard that:
1. Generates or imports the operator seed (interactive confirmation)
2. Runs `deposits-signer init` against a fresh data dir
3. Runs `deposits-node transport-pubkey` to extract the daemon's transport key
4. Runs `deposits-signer trust add` to allowlist it
5. Writes `.env` with the resulting `SIGNER_PUBKEY`
6. Prints "you can now `docker compose up -d`"

Acceptance: a clean Ubuntu VPS with bitcoind + LND already running can install and bring up an operator in 5 minutes following a single docs page.

### Tier 3: Quorum-formation wizard

Today's quorum formation assumes `setup.sh`-style co-bring-up. The audience needs two flows:

- **Private (known peers)**: `deposits-node quorum form-with --members <pk1> <pk2> <pk3>`. The local operator publishes a `QuorumAddMember` for each named pubkey; peers see the requests via their existing inbound flow and accept via `deposits-node quorum accept-membership <ledger_id>`. When all members are in, the first `QuorumBegin` rotates reserves into the multisig.
- **Public (advertise + match)**: extension to the existing advertisement protocol (or a new ad type) — operator advertises "seeking partners for quorum, Q=N." Other operators see seekers via `deposits-node quorum list-seekers`, request to join, and the seeker accepts. Same `QuorumAddMember` → `QuorumBegin` underneath.

Acceptance: 3 operators on 3 different boxes form a quorum via documented commands. No `setup.sh`-style co-bring-up required.

### Tier 4: Umbrel community app

`umbrel/umbrel-app.yml` (metadata: name, version, port, dependencies on `bitcoin` and one of the LN apps), `umbrel/docker-compose.yml` (Umbrel-shaped: app-store-managed volumes, depends-on for bitcoin and the chosen LN app, env vars wired from Umbrel's standard variables), icon, screenshots. PR to `getumbrel/umbrel-apps`.

Once Tier 1 + 2 are solid, Tier 4 is mostly mechanical — the compose is already written; this wraps it in Umbrel's manifest format.

Same shape can be adapted to Start9's `.s9pk`, Citadel community apps, MyNode add-ons — but each has its own packaging format and review process. Pick one to ship through first; the rest are mechanical follow-ons.

Acceptance: app appears in the Umbrel community store, installs against a clean Umbrel instance, comes up green and lets the user complete the operator setup wizard from the Umbrel UI.

### Tier 5: Web operator admin UI

The polished-UX target — what Alby Hub does for Lightning, applied to the deposits operator surface. Static frontend (probably vanilla TS or React, served by the deposits-node directly so it's behind the same auth boundary as the admin RPCs). Pages:

- Dashboard: ledgers, quorums, collateral position, recent activity, sync status.
- Actions: rotate quorum, respond to dispute, lock for fulfillment, transfer between deposits.
- Settings: LN backend config, bitcoin RPC, relay URLs, signer status, network preferences.
- Audit log: every operator-initiated action with timestamp, op type, target, outcome.

Needs a new "admin API" surface on the daemon (today's `node_cli/*` flows are CLI-shaped, not HTTP-shaped). Auth via a generated bearer token written to disk on first run (operator copies it once); a future iteration can do proper user accounts.

Acceptance: an operator who has never used the deposits CLI can do a full day's operator work — open a quorum, watch payments flow, respond to a dispute, rotate keys — entirely in the browser.

### Tier 6: NWC speaker (depositor-side)

Lets any NWC-compatible wallet (Alby Extension, Alby Go, Mutiny, Coinos, etc.) connect to a deposits operator and pay-in/out against a deposit balance, without installing the `deposits-web` wallet.

Out of scope for "packaging the operator." Separate workstream targeting the depositor audience. Mentioned here for completeness; sequence independently.

## Sequencing rationale

- **Tier 1 first** — structural unlock; nothing else can ship without it.
- **Tier 2 next** — packages Tier 1 for direct VPS install. Validates the single-operator deployment shape end-to-end.
- **Tier 3 in parallel with Tier 2** — independent code path; can be developed concurrently. Blocks "real first operator deploys to mainnet" because they need to form a quorum somehow.
- **Tier 4 after Tier 2** — mechanical wrap; ship once Tier 2 is solid.
- **Tier 5 is polish** — significant scope (probably weeks of work for a credible MVP), not blocking the install path. Worth starting in parallel with Tiers 2-4 if there's bandwidth.
- **Tier 6 is parallel** — different audience, no dependency on the operator-packaging tiers.

## Open decisions

These need product input before too much code lands:

1. **LND-first vs CLN-first** for the second `LightningBackend` impl after LDK. Alby Hub uses LDK so the existing impl already covers that crowd. LND has the larger user base (Umbrel default, Start9 default); CLN is a smaller niche. Recommend LND.
2. **Single image vs per-backend image** — Single image with all backends compiled in + runtime selection is simpler distribution (one `docker pull`). Per-backend images are smaller but multiply CI artifacts. Recommend single image; runtime cost of dead backends is negligible.
3. **Umbrel first or Start9 first** — Umbrel has the larger user base, easier review (PR to a public repo). Start9 has a more polished package format (config schemas, action manifests) and better operator UX. Recommend Umbrel first to maximize reach; Start9 second to set the bar for polish.
4. **Operator admin UI: build or fork** — Alby Hub's frontend is open source. Fork-and-adapt could save weeks vs greenfield. Recommend fork-and-adapt for the initial cut; rewrite later if scope diverges enough to make the fork untenable.
5. **What's the "default cluster" for first-time operators?** — Tier 3's "private quorum with named pubkeys" assumes the operator knows other operators. For first deployments, do we run a "public matchmaking" service that lists operators looking for partners? Or do we punt that until there's enough operator density that they find each other organically? Recommend punt; document the manual flow in launch docs.

## Acceptance for "ready to recommend to the audience"

A self-custody Bitcoiner who already runs Alby Hub on Umbrel should be able to:

1. Click "Install" on the deposits app in Umbrel's community store.
2. Complete a setup wizard that auto-detects their LN node and configures everything.
3. Form a quorum with 2-4 other operators (whose pubkeys they found via the project's launch docs).
4. See their first depositor open a deposit, pay an invoice through their LN node, and credit the deposit balance.

Tiers 1 through 4 are sufficient to make that path work end-to-end. Tier 5 makes step 4 onward a pleasant operating experience instead of a CLI ordeal.
