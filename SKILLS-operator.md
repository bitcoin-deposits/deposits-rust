# SKILLS — operator (running a node)

How to bring up, configure, monitor, and operate a deposits node. For depositor flows see [SKILLS-wallet.md](SKILLS-wallet.md); for the protocol mechanics see [SKILLS-protocol.md](SKILLS-protocol.md).

For full runbooks, [OPERATIONS.md](deposits-tools/OPERATIONS.md) covers regtest cluster bring-up and [MAINNET_DEPLOYMENT.md](MAINNET_DEPLOYMENT.md) covers real-money deployment. This doc is the cheat-sheet that points you into both.

---

## 1. What an operator runs

An operator is the long-running daemon (`deposits-node run`) plus a few sidecars. Boxes of state behind it:

- **The seed.** The single non-reconstructible secret. Everything else can be rebuilt from `seed + relay`. In a production deployment the seed lives inside `deposits-signer` (see §6), not on the daemon's filesystem; in regtest / single-host setups it's on the daemon.
- **`data-dir/`.** Local cache: ledger state, BDK wallet, persisted indexes. Rebuildable from the seed + relay (slow), but worth backing up.
- **The LDK sidecar.** A separate container running `ldk-server-cli` for invoice creation and Lightning payments.
- **`deposits-signer` (optional, recommended for mainnet).** A separate process holding the operator seed. Daemon talks to it over a Unix socket; daemon's host never holds the operator-protocol secret. See §6 for operating it; full reference in [SIGNER.md](SIGNER.md).

Plus two relays the operator talks to: a **ledgers relay** (durable, port 17779 — the source of truth for ledger state) and a **messaging relay** (ephemeral, port 17780 — for wallet ↔ operator request/response). The Docker image bundles both via strfry so an operator can self-host.

The north-star direction (per memory: `project_nsec_only_state.md`) is to collapse all persistent state to the nsec only, with everything else as encrypted DMs to self. New on-disk state should go through a swappable backend so the eventual cutover is mechanical.

---

## 2. Bring up a regtest cluster

```bash
./deposits-tools/bin/setup.sh 3   # Q=3: 10 operators, 30 ledgers
./deposits-tools/bin/setup.sh 5   # Q=5: 16 operators, 48 ledgers
./deposits-tools/bin/setup.sh 7   # Q=7: 22 operators, 66 ledgers
```

`setup.sh Q` resets, starts both relays, funds BDK wallets, opens ledgers, starts daemons, forms quorums, and rotates each ledger's reserves into a Taproot multisig. It's safe to re-run; it wipes state.

Cluster CLI helpers live in `deposits-tools/docker/cluster-cli.sh` (`status`, `tail`, `restart-all`, etc.). Health checks: `deposits-tools/bin/health.sh`.

---

## 3. Bring up a mainnet operator

Read [MAINNET_DEPLOYMENT.md](MAINNET_DEPLOYMENT.md) end-to-end before doing anything. The smallest viable mainnet sandbox is **3 operators, Q=2, 1 ledger each.** Quick orientation:

- **`--network bitcoin`** is the only code-level switch; the rest is operational.
- **Bitcoin full node** with `txindex=1`, ~1 TB SSD, days to IBD.
- **Operator hosts** are modest (4 cores, 8 GB, 50 GB) but should be on different machines / networks / administrative control. The trust assumption is "no single operator can steal from a ledger they don't control."
- **Public relay domains with TLS.** NIP-01 wallets and Lightning attestations expect `wss://`.
- **Real BTC** for collateral. The collateral is part of the same UTXO as reserves — operator misbehaviour slashes it.

---

## 4. Daemon configuration

```bash
deposits-node run \
    --seed-file /run/secrets/seed \
    --name alice \
    --network bitcoin \
    --esplora https://esplora.example.com \
    --relay wss://relay-ledgers.example.com \
    --relay wss://relay-msg.example.com \
    --data-dir /var/lib/deposits/alice
```

**Seeds never go on argv.** Use `--seed-file` (0600) or `DEPOSITS_SEED` env. `ps` is visible to other processes and shell history; rotating a leaked seed is painful.

**`BOOTSTRAP=1` env gate.** The daemon refuses to bootstrap reserves on first run unless this is set. This is deliberate — a re-deploy that loses `data-dir` shouldn't accidentally create new ledgers and burn collateral. Set it once, intentionally, then unset.

**`NODE_NAME`** shows up in advertisements and the explorer. Pick a stable, recognisable string.

**`MAX_DEPOSIT_BALANCE_MSATS`** caps per-deposit balance. The lnurl gateway exposes this as `maxSendable` to lnurl-pay. Useful for "test-like" deployments where you don't want a single deposit holding meaningful value.

**Network ports & relays.** `--relay` can be passed multiple times. The daemon uses the first as the durable ledgers relay and the rest for messaging fallback. Override discovery with `RELAY_LEDGERS` / `RELAY_MESSAGING` env if needed.

---

## 5. The LDK sidecar

The daemon shells out to `ldk-server-cli` for invoice creation, Lightning payment, and channel management. A few sharp edges:

- **`gcompat` 1.1.0+** is required on Alpine/musl — earlier versions are missing `__res_init`. The Dockerfile builds a tiny stub library (`libres_init_stub.so`) and wires it via `LDK_LD_PRELOAD` in the entrypoint. If you see `Error relocating ... __res_init: symbol not found`, your gcompat is stale.
- **TLS cert refreshes on every container start.** `ldk-server` regenerates `/ldk/tls.crt`; the operator's cached `lightning.crt` goes stale and `make_invoice` silently breaks with "BadSignature." `setup.sh` now `docker cp`s the cert on every run; in production, automate the same.
- **Wrapper script preference.** The default is `/app/ldk-cli-wrapper.sh`; override to `/ldk/ldk-cli-wrapper.sh` only if you have a specific reason (e.g. running the wrapper from a sidecar's filesystem). Don't reverse this without intent.
- **`LDK_API_KEY`** comes from `/ldk/bitcoin/api_key`. Read it into env at container start, don't hard-code.

---

## 6. The signer (out-of-process)

`deposits-signer` is a separate process that holds the operator seed. The daemon talks to it over a Unix socket; the daemon's host filesystem never sees the operator-protocol secret. Anti-equivocation policy on the signer side refuses to sign two updates at the same `seq` — the safety net that makes hot-spare daemon configurations viable. Full reference: [SIGNER.md](SIGNER.md).

**Why use it:** if your daemon process gets compromised, the attacker walks away with a Nostr identity key (annoying, fixable) instead of the operator key (slashable, catastrophic). On regtest / single-host you can skip it; on mainnet you should always run it.

**Two seeds, structurally distinct:**

- **Operator key** at `m/86'/0'/0'/0/0` — protocol-level signs (operator_signature, cosignatures, invoice cosigns, attestations). Lives only in the signer.
- **Nostr identity** at `m/85'/0'/0'/0/0` — event signing, NIP-04 ECDH. Issued to the daemon at startup; daemon holds it locally.

**Bring-up:**

```bash
# Init signer with the seed; print the signer's transport pubkey.
deposits-signer init --data-dir /var/lib/dsigner --seed-file /run/seed
# → signer transport pubkey: dsig…

# Start the daemon, pin the signer's pubkey, point at the socket.
deposits-node run --signer-pubkey <dsig hex> \
                  --signer-socket /run/dsigner.sock \
                  ...
# Daemon prints its own transport pubkey on first connect.

# Allowlist the daemon on the signer side, then start the signer.
deposits-signer trust add --data-dir /var/lib/dsigner <node hex>
deposits-signer run --data-dir /var/lib/dsigner --socket /run/dsigner.sock
```

Pinning is mutual + explicit (no TOFU). The daemon's `--signer-pubkey` flag pins the signer's transport pubkey; the signer's allowlist names the daemon's. Either side rejecting the handshake means the wrong process is on the other end.

**Anti-equivocation policy.** The signer maintains a `(ledger_id, role) → max_seq` store at `<data-dir>/anti_equivocation.json`. Every operator-update or cosign-update sign request that would regress or repeat its `seq` is refused with `SignerError::PolicyRefused`. The daemon's logs will surface this; if you see it during normal operation, something is racing or duplicating sign work.

**Cluster bring-up shortcut.** `DEPOSITS_USE_SIGNER=1 ./bin/setup.sh 3` provisions a per-operator signer automatically — the `start_node` helper spawns one signer process per operator, allowlists the daemon's transport pubkey, and wires `--signer-pubkey`/`--signer-socket` into the daemon's run line. Existing tier-3 integration tests work unchanged with the flag set; they exercise the same protocol behaviour but with operator-protocol sigs flowing over the wire.

**Smoke test:** `./bin/test-signer.sh` exercises the spawn + handshake plumbing in ~5 seconds without needing bitcoin / relays / esplora. Useful for CI and iteration.

**Backups.** The signer's seed is the only non-reconstructible secret; back it up like the daemon's seed today (multiple media, multiple physical locations). The signer's `transport_secret` is fine to lose — `init` regenerates it; you re-pin the new pubkey at the daemon and re-add it to the allowlist.

---

## 7. Quorum lifecycle

The five-phase loop, in order:

1. **`LedgerOpen`.** Operator publishes the genesis update. UTXO contains reserves + collateral.
2. **`QuorumAddMember`.** For each prospective cosigner, operator publishes an add op carrying the member's pubkey *and* their member_ledger_id (the ledger where their collateral lives).
3. **`QuorumBegin`.** Once enough members are staged, operator rotates reserves into a Taproot multisig output and commits the new active set. The first `QuorumBegin` itself must carry cosignatures. `quorum_expiry` is the shortest member commitment (block height).
4. **Steady state.** Every subsequent update needs cosigs from a strict majority. Members verify against their own chain; the operator can't maintain parallel chains.
5. **Refresh before expiry.** Operator publishes a fresh `QuorumBegin` *before* `quorum_expiry`. Past the deadline, cosigners refuse to sign anything (including a fresh `QuorumBegin`) — see `QuorumExpired` fraud proof, DEP-06.

**Joining as a cosigner.** Wait for the operator's `QuorumAddMember` referencing your pubkey, then subscribe to their ledger relay. You'll start receiving cosign requests via Kind 20101.

**Leaving.** Either the operator publishes `QuorumRemoveMember` (graceful) or your collateral expires past `quorum_expiry` (forced).

---

## 8. Cosign duties and common failures

When you're a cosigner on someone else's ledger:

- Subscribe to their ledger relay continuously. Missed cosign requests delay the whole quorum.
- Verify the update's hash chain against your local copy before signing. Cosigning a backdated update produces a `StaleCosignature` fraud proof — slashable.
- Verify the on-chain UTXO matches `QuorumBegin` claims (existence, value, unspent, confs). The defaults: 6 mainnet, 3 testnet/signet, 1 regtest. Stricter is fine; don't go below.

**"Cosign timeout: 0/N cosigs in 5000ms"** hides three distinct bugs (per memory: `project_phase4_cosign_blockers`, `feedback_deposit_credit_unique_invoice`):

1. Members not subscribed to operator ledger after `QuorumJoin`.
2. Txid byte-order mismatch in `QuorumBegin` (writer used display order, verifier used internal).
3. Duplicate `invoice_id` → duplicate `payment_hash` → cosigners reject as `duplicate_credit`. In tests, use a per-call nonce.

If you see this in production, walk the three in order before assuming a deeper protocol bug.

**"Member consent failed."** The cosigner is online but rejecting — check their logs for the actual reason. Common: stale chain (subscribe issue), local reserves verification failed, or the cosigner ran past `quorum_expiry` on their own clock.

---

## 9. Dispute response

Disputes are automated end-to-end; an operator's job is to not trigger one. But you'll watch them happen on ledgers you cosign.

**Detection → DisputeArmed.** The fork-branch detector observes a fraud proof, publishes `DisputeArmed { commitment_hash }` carrying `HASH160(preimage)` where `LEN(preimage) - 16 ∈ 1..=N` is your contribution. The actor wakes via the `MaybeConfiscate` outbox event (per memory: `project_dispute_periodic_interval`, dispute "armed → confiscate" latency dropped from 5–60s periodic to ~ms event-driven in 8d).

**Confiscation tx.** Recovery quorum cosigns a tx spending the disputed reserves UTXO into the lottery output. Bifurcation depends on fraud-proof class:

- **Respectful (`QuorumExpired`):** `obligations` → lottery winner; `(reserves − obligations) + collateral` → operator change.
- **Punitive (everything else):** Full UTXO → confiscation. Reserves of `obligations` to lottery winner; the rest split equally among the `Q` cosigners. The lottery winner does **not** retain confiscated collateral as a windfall — they pay fresh collateral when claiming.

**Custody lottery.** Each disputant publishes their preimage as a `CustodyLotteryReveal` (Kind 9106). Winner is `(sum_of_contributions) mod N`; the script enforces it. Winner publishes `DisputeAcquire`; losers publish `DisputeYield`. See DEP-03 §Custody Lottery for the script tree.

**Cross-ledger contagion.** Punitive proofs propagate to the operator's *other* ledgers — same proof, same dispute. Respectful (`QuorumExpired`) does not propagate. The "Cross-ledger propagation gate + QuorumExpired in handle_fraud_proof" commit (e75ef3a) is where this gating lives.

**Q sizes.** Current policy: `VALID_QUORUM_SIZES = {3, 5, 7}` with `MAX_QUORUM_SIZE_POLICY = 7`. Disputants = `Q` (operator is barred from disputing their own ledger). Lifting the cap is a one-line constant change; the script supports up to N=15.

---

## 10. Monitoring

Per memory: `reference_perf_observability.md`.

- **Prometheus** on `:9100 + op_idx` (one port per operator). Steady-state histograms for the hot paths.
- **Flamegraphs** via `TRACING_FLAME_PATH=/path/output.folded` env var. Per-call sampling. `#[tracing::instrument]` is already on `Node::new`, `commit_operation`, `sign_and_broadcast`, `request_cosign`, `handle_ledger_update`, `persist_ledger_to_disk`.
- **Grafana dashboards** in `deposits-tools/grafana/`.
- **Strfry exporter** at `deposits-tools/bin/strfry-exporter.py` for relay-side metrics.

Watch:
- Cosign latency p99 and timeout rate.
- `quorum_expiry - current_height` per ledger; alert before you'd refuse to sign.
- Reserves UTXO balance vs. obligations sum (your local audit).
- Outbox depth (events queued for relay publish).

---

## 11. Recovery scenarios

**Lost `data-dir` but seed is safe.** Restart with the same seed; the daemon rebuilds state from the relay. Slow but complete.

**Lost seed.** Catastrophic. There's no operator-side recovery; collateral is forfeit, depositors will go through the dispute lottery. Back it up to multiple media in multiple physical locations. If you're running with a separate signer (§6), the seed lives in `<signer-data-dir>/seed`, not the daemon's data-dir — back up *that* file.

**Daemon process compromise (signer running separately).** Attacker gets the Nostr identity key (event signing, NIP-04 ECDH for inbound DMs to the Nostr pubkey). They can spam fake events from the daemon's Nostr pubkey and decrypt past inbound DMs. They cannot produce protocol-level operator signatures or cosignatures — those flow through the signer, which is a separate process they don't control. Mitigation: rotate the daemon's host, regenerate the Nostr identity (re-derive on a new seed if the daemon's filesystem leaked the cached Nostr key), restart against the same signer. The operator's collateral and ledgers are untouched.

**Daemon process compromise (no signer, single-host setup).** Attacker has the operator seed. Same blast radius as a stolen private key — they can sign protocol-level updates as the operator, drain reserves via co-signers if they can also subvert them, etc. There is no in-band recovery; you re-key by publishing a fresh `LedgerOpen` from a new seed, but every existing ledger backed by the compromised key is lost. **This is exactly why running the signer separately matters for mainnet.**

**Signer process compromise.** Catastrophic — same as "lost seed" above. The signer's host is the trust root; treat it accordingly (separate machine, hardened OS, restricted egress, ideally an HSM-adjacent host).

**Operator's UTXO node is compromised.** The operator can't unilaterally move funds — Tier 0 spending requires majority cosigners. But they can stall, denying cosign requests, until `quorum_expiry`. Cosigners then dispute via `QuorumExpired` (respectful path).

**A cosigner is permanently offline.** If it puts you below the cosign majority, publish `QuorumRemoveMember` and stage a replacement via `QuorumAddMember`, then `QuorumBegin` to rotate. Don't wait for expiry.

**A cosigner is misbehaving.** Present the fraud proof — the dispute pipeline does the rest. Their member_ledger gets confiscated, their collateral burns. Cross-ledger contagion handles the case where the same operator runs other quorums.

---

## 12. Code map for operators

| Concern | Path |
|---|---|
| Daemon main loop | `deposits-node/src/node/mod.rs` |
| Cosign actor + apply edge | `deposits-node/src/node/actor.rs` |
| Dispute pipeline (detection, confiscate, claim) | `deposits-node/src/node/dispute.rs`, `recovery.rs` |
| Outbound publish | `deposits-node/src/node/outbound.rs` |
| Inbound fan-in | `deposits-node/src/node/inbound.rs` |
| Wallet integration (BDK + UTXO ops) | `deposits-node/src/node/wallet.rs` |
| LDK glue | `deposits-node/src/lightning/`, `deposits-tools/bin/ldk-cli-wrapper.sh` |
| Signer client (RemoteSigner + connect/handshake) | `deposits-node/src/remote_signer.rs` |
| Signer trait + LocalSigner reference impl | `deposits-signer-api/src/` |
| Signer binary (init, trust, run, anti-equivocation) | `deposits-signer/src/` |
| Operator policies | `deposits-tools/permissive-write-policy.py`, `secrets/operator_policy.json` |
| Bring-up scripts | `deposits-tools/bin/setup.sh`, `start-operators.sh`, `redeploy.sh` |
| Mainnet runbook | [MAINNET_DEPLOYMENT.md](MAINNET_DEPLOYMENT.md) |
| Regtest runbook | [OPERATIONS.md](deposits-tools/OPERATIONS.md) |
| Out-of-process signer reference | [SIGNER.md](SIGNER.md) |

---

## 13. Useful one-liners

```bash
# Status across all containerised operators
deposits-tools/docker/cluster-cli.sh status

# Tail one operator's logs
docker logs -f alice

# Check reserves balance vs. obligations for one ledger
deposits-wallet ledger validate <ledger_id>

# Funds report across the whole cluster
deposits-tools/docker/funds-report.sh

# Mine N regtest blocks
docker exec miner sh -c 'btc -regtest -generate 6'

# Force a quorum refresh on a ledger
docker exec alice deposits-node quorum begin <ledger_id>

# Inspect the outbox of a stuck node
docker exec alice deposits-node debug outbox --ledger <ledger_id>

# Signer: print transport pubkey for paste into --signer-pubkey
deposits-signer pubkey --data-dir /var/lib/dsigner

# Signer: list allowlisted node pubkeys
deposits-signer trust list --data-dir /var/lib/dsigner

# Signer: dump anti-equivocation state (max seq per ledger/role)
cat /var/lib/dsigner/anti_equivocation.json | jq
```
