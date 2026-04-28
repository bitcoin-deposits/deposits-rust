# Chapter 20: The Daemon

> **Audience**: developers
> **Prereqs**: chapters 4, 6, 11, 12, 19
> **DEPs**: none directly (implements all of them)

`deposits-node` is the operator's daemon. It is the longest-running, most stateful, and most concurrent piece of the implementation. Every other component — the wallet, the courier, the test harness — eventually talks to one of these. This chapter takes the architecture-tour orientation from [Chapter 19](19-architecture-tour.md) and goes inside: the actor model, the main loop, the inbound dispatcher, the persistence layer, the dispute drivers, the Nostr and wallet wrappers, and how they fit together.

The single most consequential decision in this codebase is the per-ledger actor. Everything else makes more sense once you understand it, so we start there.

## The actor model

Every loaded ledger gets a dedicated tokio task — a `LedgerActor`. The actor owns the apply path for its ledger. Every other component that wants to mutate the ledger state goes through the actor's mpsc inbox; nothing else writes.

The actor's data is the same `Arc<RwLock<Ledger>>` that lives in `handler.ledgers`. This is important. There is one `Ledger` per ledger-id, and every reader sees it: the actor, the handler, the request handlers, the metrics emitter, the wallet's reserves-rotation builder. The actor is a *writer convention*, not a state silo. Single source of truth, single writer per ledger.

The shape, in `deposits-node/src/node/ledger_actor.rs`:

```rust
pub struct LedgerActor {
    pub inbox: mpsc::Receiver<LedgerEvent>,
    pub outbox: SharedOutbox,             // (ledger_id, LedgerOutbound) → coordinator
    pub ledger: Arc<RwLock<Ledger>>,      // shared with handler.ledgers
    pub ledger_id: String,
    pub persistence_path: PathBuf,         // <id>.actor.log
    pub forks_dir: PathBuf,
    pub fork_observations: HashMap<PublicKey, ForkObservation>,
    pub operator_secret: SecretKey,
}
```

Two events come in:

- `LedgerEvent::Inbound(SignedLedgerUpdate)` — a relay-delivered update to apply.
- `LedgerEvent::Commit { operation, block_height, block_hash, reply }` — an operator-initiated commit, with a oneshot reply for the caller.

Three outbound events go out, all of them tagged with the actor's `ledger_id` so the coordinator's drainer can dispatch:

- `LedgerOutbound::Broadcast { update, reply }` — publish to Nostr; `reply` is `Some` when the caller wants the event id.
- `LedgerOutbound::RequestCosig { update, members, threshold, reply }` — collect cosignatures from named members; reply blocks the actor's run loop. This is the only synchronous outbound path.
- `LedgerOutbound::MaybeConfiscate { ledger_id }` — apply-edge wakeup for the dispute pipeline (covered later in this chapter).

The single most important thing to internalize about the actor is the **lock discipline**. The ledger lock is `Arc<RwLock<Ledger>>`. The actor takes the write lock briefly, mutates, drops. It never holds the lock across an `.await`. Every async step in `handle_commit` is bracketed by lock acquisitions — read lock to stage, drop, await cosig round, write lock to apply, drop, await broadcast. Hold-across-await would deadlock the daemon because handlers running on other tasks routinely take read locks too.

### Why an actor model

The daemon was originally built around `Mutex<HashMap<String, Arc<RwLock<Ledger>>>>` with no per-ledger serialization. Two problems:

1. **Concurrent commits to the same ledger raced.** Two requests landing within milliseconds — say two `transfer_lock`s on the same source deposit — could both stage against the same tip, both produce sequence N+1, and one would lose at persist time. Worse, with cosig requests in flight, two threads could both have collected partial cosigs against different content_hashes and the conflict would only surface at the relay (where one would be a duplicate-seq and dropped).

2. **The hot path acquired the global ledgers map for every write.** Under load this dwarfed the per-ledger work and capped throughput.

The actor model fixes both. The mpsc inbox naturally serializes commits per ledger — only one `Commit` event is in flight in `handle_commit` at a time, because the actor is single-threaded. And the global map is touched only on inbox lookup; the lock is dropped before the inbox `send`, so two requests on different ledgers don't contend.

The shared `Arc<RwLock<Ledger>>` makes reads cheap. Anything that just wants to inspect state — metrics, query handlers, conformance checks — takes the read lock without round-tripping through the actor.

### `handle_commit` end to end

This is the most important function in the daemon. `deposits-node/src/node/ledger_actor.rs:497` walks through the full operator-driven commit:

1. **Stage.** Take the read lock briefly. Call `ledger.stage_operation(operation, block_height, block_hash)`, which validates against current state and produces a `StagedUpdate` (operation + unsigned `SignedLedgerUpdate` with `previous_hash`/`sequence_number`/`block_height` filled in). Snapshot whether the quorum is `Active` and the list of member pubkeys. Drop the lock before any `.await`.

2. **Cosign — if needed.** Cosig is required when `quorum_state == Active` *or* when this is the very first `QuorumBegin` (which transitions PreQuorum → Active and so needs the staged-but-not-yet-active members to attest). Threshold is `floor(N/2) + 1`. Build a oneshot, emit `LedgerOutbound::RequestCosig` to the outbox, await the reply. The collected `CosignEntry` list is sorted by pubkey (deterministic encoding), assigned to `staged.update.cosignatures`, and the legacy single-cosig fields are zeroed. Then `compute_hash()` is called to refresh the content hash now that the cosig vector has been finalized.

3. **Operator-sign.** Build the operator signing data via `staged.update.operator_signing_data()` — that helper hashes content + every cosignature, so the operator's signature commits to the assembled cosig set. Schnorr-sign with the operator secret captured at actor spawn.

4. **Apply.** Take the write lock briefly. `ledger.commit_staged(staged)` runs the state-machine transition (`LedgerState::apply`) and pushes the now-signed update to history. This is the authoritative write — every other reader will see the new tip on their next read-lock acquire. Drop the write lock.

5. **Persist to `.actor.log`.** Append a `{"type":"Update", ...}` row to `<id>.actor.log`. Failure here is logged, not fatal — the shadow file is a sanity check, the authoritative `<id>.jsonl` write happens later in the commit shim.

6. **Broadcast.** Emit `LedgerOutbound::Broadcast { update, reply: Some(tx) }` and await the resulting Nostr event id. If the publish fails the reply still resolves (with an empty event id) so the actor doesn't hang the caller — relay echo or peer gap-fill can deliver the update later.

7. **Reply.** Send `Ok(CommitResult { event_id, update })` back to the operator-side caller (whose `commit_operation` shim is awaiting on the oneshot).

`apply_inbound` (the `LedgerEvent::Inbound` path) is simpler. It runs against the same shared `Arc<RwLock<Ledger>>`. Steps:

1. Operator-key filter — if `update.operator_id != ledger.state.parent_pubkey`, this is a fork-branch update from a disputer. Hand it to `handle_fork_branch_update`, which observes per-disputer fork state and writes to `{ledger_id}_{last_valid_seq:06}_{disputer_pk_16}.actor.log` (matching the handler's compound-key fork file naming).
2. Dedup on `(seq, content_hash)`. Same content at same seq → no-op. Different content at same seq → equivocation evidence; logged loudly and refused.
3. Chain-continuity. Only apply if `update.sequence_number == state.sequence + 1` AND `update.previous_hash == state.chain_tip_hash`. Gaps and out-of-order updates are dropped on the floor; the gap-fill machinery in `inbound.rs` brings the chain up the rest of the way.
4. Decode the operation, run `LedgerState::apply`, advance `sequence` and `chain_tip_hash`, push to history. Drop the write lock.
5. Append to `.actor.log`.

Self-broadcasts echoed off the relay land here as a no-op via the dedup check. That property is what lets `inbound.rs` skip the historical "is this our own ledger?" guard — the actor handles it idempotently.

## The main loop

`Node::run(self: &Arc<Self>)` in `deposits-node/src/node/main_loop.rs:934` is the long-running async function that keeps everything ticking. Spawned at `cargo run -- run` time, it doesn't return until the process is shut down.

The loop has four spawned tasks plus the loop body itself:

**Dispute wakeup task.** Owns the `dispute_wakeup: Arc<Notify>`. It loops: `wakeup.notified().await; auto_confiscate().await;` Each call is wrapped in a 10s timeout so a stuck cosig fetch can't hang it. The actors signal this `Notify` (via the outbox drainer, below) when they observe a fork-branch `DisputeArmed`. This is the apply-edge dispute driver — events drive it, not a periodic timer.

**Actor outbox drainer.** Picks up the `actor_outbox_rx` parked on `Node` by `init.rs` (parking is necessary because the drainer needs `Arc<Node>` for callbacks like `request_cosign` that don't exist until `Self` is fully constructed). It loops on the receiver, dispatching:
- `MaybeConfiscate { ledger_id }` → `node.dispute_wakeup.notify_one()`. That's the apply-edge wakeup.
- `Broadcast { update, reply }` → spawn a sub-task that calls `nostr.broadcast_ledger_update`, sends the result back through `reply` if `Some`. Spawn so a slow relay can't stall the drainer.
- `RequestCosig { update, reply, .. }` → spawn a sub-task that calls `request_cosign(&lid, &update)`, sends the result through `reply`. Same reasoning — multi-second cosig RTTs can't serialize.

**Periodic-tasks tick.** Every `periodic_interval` (5s in fast-poll mode for tests, 60s in production), the loop spawns a background task that runs the auto-tasks: `auto_complete_deposits`, `auto_credit_received_payments`, `auto_complete_outbound_payments`, `auto_complete_withdrawals`, `auto_collect_fees`, `auto_timeout_transfers`, `auto_lottery_claim_or_yield`, `auto_confiscate`, `auto_reveal_on_confiscation`, `auto_post_win_cleanup`, `publish_price_oracle`, `remirror_advertisements`. Each call is wrapped in `timed_periodic!` — a 10s tokio timeout. A periodic task that hangs gets logged and the next periodic batch runs as scheduled.

`auto_confiscate` runs on this tick *and* on the apply-edge wakeup. Why both? The wakeup catches the common case (a `DisputeArmed` arrived, fire immediately), but on startup the actor hasn't observed the armed state yet — it loaded from disk. The periodic tick is a safety net that picks up `custody_armed_*.marker` files left over from before the daemon started.

**Wallet-sync tick.** Full wallet sync (~40 HTTP requests to Electrs) every 30s/60s. The cheaper `sync_block_height` runs on the periodic tick.

**Reload tick.** Every `reload_interval` (2s/5s), discover new ledger files in `wallet/ledgers/`, refresh the joined-ledger cache, refresh the per-ledger Nostr filters, auto-import any joined ledgers we don't yet have locally. The reload pre-checks `try_lock()` on `handler.ledgers` and skips the cycle if contended — orphaned tasks holding the lock can't be allowed to stall the loop.

**Poll tick.** Every 30s, fetch recent request events from the durable relay as a safety net for missed subscription events. Subscriptions handle real-time delivery; this is a backstop.

**Inbound event drain.** Every iteration, `process_events_with_timeout(events_timeout_ms)` pulls events off the Nostr subscription's internal queue. The timeout adapts: short (10ms) when the previous iteration had requests, longer (200ms) when idle. Each drained event is dispatched: requests → `handle_ledger_request` (which routes to the per-ledger request worker), updates → `handle_inbound` → `handle_ledger_update` (the inbound dispatcher), disputes → `handle_dispute`, fraud proofs → `handle_fraud_proof`.

The loop body is single-threaded by construction. Spawning is what gives concurrency — each spawned sub-task runs on the tokio worker pool, the loop itself returns to the next `process_events_with_timeout` quickly. The loop's job is to be a fair scheduler, not to do work.

## The inbound dispatcher

`Node::handle_ledger_update` in `deposits-node/src/node/inbound.rs:403` is what runs when a `Kind:9100` (ledger update) Nostr event arrives. Walking through:

1. **Membership filter.** `is_quorum_member_of_ledger(&inbound.ledger_id)` — drop updates for ledgers we have no business watching. (We're either an operator or a member; if we're neither, we don't care.)

2. **Event-store insert.** `handler.insert_event(&inbound.update)` content-addresses the update by its hash, runs format-level validation, and reports whether the entry is `Valid`/`Invalid`/`Unknown`. Duplicates short-circuit. Metrics get bumped here.

3. **Actor dispatch.** Look up the actor in `ledger_actors`, fire-and-forget `handle.try_send(LedgerEvent::Inbound(Box::new(update.clone())))`. The actor will run `apply_inbound` — its idempotent dedup means a double-delivery is fine, and it being on a separate task means inbound throughput isn't bounded by the main loop's drain cadence.

4. **Sender-role classification.** Take a read lock on the ledger and compute four booleans:
   - `is_from_operator` — `update.operator_id == ledger.state.parent_pubkey`?
   - `is_from_active_member` — operator id is in the active quorum?
   - `is_dispute_enter` — the operation TLV-decodes to `DisputeEnter`?
   - `in_dispute` — `dispute_state != Normal`?

5. **Branch on role.**
   - **Not operator, but active member sending DisputeEnter.** Member is starting a fork branch. The dispute lives on the fork, not on the main chain. Log and return — the actor's fork-branch handler will write the fork file, and the dispute pipeline will react.
   - **Not operator, ledger in dispute.** Custody may have transferred via `DisputeAcquire`. Re-import the ledger from Nostr to pick up the new `parent_pubkey`. Re-check; if still non-operator, drop.
   - **Not operator, not dispute, not member.** Random junk. Anyone can sign anything and tag it with a ledger_id. Drop.

6. **Gap detection.** Compare `update.sequence_number` to local `next_sequence()`. If we're behind, try `catch_up_ledger_from_event_store` (in-memory bridging from previously-seen events). If still behind, mark the ledger stale for background gap-fill from the relay.

7. **Hash-chain validation.** `validate_incoming_update_hash_chain(&inbound.update)`. If it fails — and the operator is the sender, and dispute_state is Normal — that is fraud-proof evidence. Call `auto_arm_for_dispute` (covered below). The `is_operator_of_ledger` guard prevents the operator from auto-arming its own ledger; that would self-fork against the on-chain UTXO.

8. **Apply.** If validation passed and the update is the exact next slot chaining from our tip, apply it via `apply_and_check` (state transition + conformance check), advance `sequence` and `chain_tip_hash`, push to history, persist to `<id>.jsonl`.

The actor's `apply_inbound` and the handler-side apply branch *both* target the same `Arc<RwLock<Ledger>>`. Whichever gets the write lock first does the mutation; the second-mover's chain-continuity check (or dedup, in the actor) finds the slot already filled and turns into a no-op. This is the key idempotency property — fully concurrent apply paths can race on the same update without producing inconsistent state.

## The cosig collector

`coordination.rs::request_cosign` is the multicast-and-await pattern (`deposits-node/src/node/coordination.rs:278`). The shape:

1. Acquire a permit from `cosign_semaphore`. The semaphore is `Arc<Semaphore::new(8)>`, capping concurrent cosig rounds. Why? Multiple in-flight rounds compete for shared response channels and can deadlock when every operator in the cluster is in batch-await simultaneously. Eight is empirical — high enough that single-operator throughput isn't bounded, low enough to avoid the cross-operator deadlock pattern.

2. Build the request: `cosign_data_hex`, `content_hash_hex`, `message_type`, plus a piggyback of up to 20 prior updates (base64'd TLV) so members can apply any updates they're missing inline before doing the freshness check. Without this piggyback, a member two updates behind would reject every cosign request with "stale by N" until the inbound subscription caught it up.

3. Threshold = `floor(n/2) + 1` over the active quorum members (or `next_quorum_members` for the first `QuorumBegin`).

4. Build a `CosignCollector` (capacity `threshold`) and store it in `pending_cosign_requests` keyed by request id.

5. Multicast the cosign request to the messaging relay via `nostr.send_ledger_request`. Track our own event id in `sent_events` so we filter our broadcast back out on inbound.

6. `tokio::select!` between `collector.notify.notified()` (threshold met) and `tokio::time::sleep(deadline)` (5s default, configurable via `COSIGN_TIMEOUT_MS`). On either branch, take the collected results.

7. Remove the entry from `pending_cosign_requests`. If `results.len() < threshold`, return a "Cosign timeout" error — the actor surfaces this as a commit failure, the staging lock is released, the operator-side caller sees the error.

8. Otherwise return the cosig entries to the actor.

The collector itself (`mod.rs:119`) deduplicates by pubkey (so a member that responds twice doesn't get counted twice) and uses `tokio::sync::Notify` for wakeup. `Notify::notify_one` is one of those primitives that's exactly the right shape for "wake the awaiter once when threshold is reached."

## The dispute drivers

The dispute pipeline (Chapter 12 covers the protocol view) has three drivers in `deposits-node/src/node/dispute.rs`.

**`auto_arm_for_dispute(ledger_id, last_valid_seq)`** (`dispute.rs:10`). Triggered from `inbound.rs` when we detect operator fraud. Steps:
1. `create_dispute_fork(ledger_id, last_valid_seq)` — produces a fork ledger keyed `{ledger_id}_{last_valid_seq:06}_{our_pk_16}` and persists it as a separate JSONL file.
2. Append `DisputeEnter { last_valid_sequence, reason }` on the fork.
3. Set `parent_pubkey` to our key on the fork (we now operate this fork branch).
4. Copy our existing collateral attestations from all our owned ledgers onto the fork (proves we have collateral backing).
5. Append `DisputeArmed { ... }` on the fork — we are now ready to settle the lottery.
6. Sign and broadcast.

The fork-vs-main split is critical: the operator's own main ledger stays in `Normal` state. The dispute lives on a separate continuation that members fork from the last conforming update.

**`auto_confiscate()`** (`dispute.rs:889`). Two phases:
1. `collect_confiscation_signatures()` — for each `pending_confiscations` entry, fetch recent response events from the relay, parse signatures from quorum members, accumulate into `pc.signatures`. Drop entries older than 120s so we re-initiate.
2. `initiate_confiscations()` — for each `custody_armed_*.marker` file in `data_dir`, check if all expected disputants are armed and confiscation hasn't already started. If so, build the confiscation TX, request signatures from quorum members, store in `pending_confiscations`. Once `signatures.len() >= required_sigs`, `broadcast_confiscation` builds the witness from the collected signatures and broadcasts the TX to the Bitcoin network.

`auto_confiscate` runs on two triggers: the periodic 5s/60s tick, and the apply-edge wakeup. The wakeup is the fast path — when an actor observes a fork-branch `DisputeArmed`, it sends `MaybeConfiscate` on the outbox, the drainer fires `dispute_wakeup.notify_one()`, and the wakeup task runs `auto_confiscate` immediately. Drops dispute armed→confiscate latency from `periodic_interval` (5–60s) to single-digit milliseconds.

**`auto_lottery_claim_or_yield()`** (`dispute.rs:364`). For each `lottery_revealed_*.marker` in `data_dir` without a matching `lottery_completed_*.marker`, find the fork ledger key, call `try_lottery_claim_or_yield`. That function fetches the lottery's revealed preimages from the relay, determines the winner deterministically, and either:
- **Winner**: calls `claim_lottery` to spend the lottery output on-chain and commits `DisputeAcquire { ... }` on the fork. The fork now becomes the canonical chain via `parent_pubkey` rotation.
- **Loser**: commits `DisputeYield` on the fork. The branch is tombstoned.

This driver runs only on the periodic tick today — its wakeup is gated on the Bitcoin reveal being confirmed, which the daemon doesn't currently push through the actor outbox. Making this fully event-driven is a follow-up tracked in the project memory.

## Persistence

Two parallel files per ledger in `wallet/ledgers/`:

- **`<id>.jsonl`** — the handler's authoritative file. JSONL: first line is a `Role` row, then a `State` row (snapshot), then `Update` rows for each entry. Loaded on startup. Compaction periodically rewrites with a bounded history tail (`HISTORY_RETAIN`).
- **`<id>.actor.log`** — the actor's parallel mirror. Same `{"type":"Update", ...}` row format as the `Update` rows in the `.jsonl`. Written on every accepted inbound and every committed outbound. Used as a regression check by the `actor_shadow_consistency` Tier-3 test: any divergence between `.actor.log` and the `Update` rows of `.jsonl` indicates the actor and handler disagreed about what entered the chain, which is the failure mode the actor migration was guarding against.

Fork-branch updates go to `<id>_<last_valid_seq:06>_<disputer_pk_16hex>.jsonl` (handler-side) and `.actor.log` (actor-side). Same compound key on both, so a diff stays straightforward.

The `.jsonl` compaction policy keeps the last `HISTORY_RETAIN` (~2000) updates plus the snapshot state. Older entries are pruned, but the snapshot guarantees the load path can reconstruct without them. Joined-ledger histories also get truncated on the periodic tick to bound memory.

## Lazy-spawn for new ledgers

`Node::new` spawns one actor per ledger present on disk at startup. Ledgers that come into existence at runtime — operator opens a new ledger via `ledger_open`, member imports via `QuorumJoin`, daemon receives an inbound update for a ledger-id we now want to track — need an actor too, or their inbound and commit events fall on the floor.

`Node::ensure_actor_for(ledger_id)` (`init.rs:306`) is the lazy-spawn path. It's called from:
- `ledger_queries::open_ledger` (when the operator creates a new ledger),
- `ledger_queries::import_ledger` (when we import a foreign ledger as a quorum member),
- `main_loop.rs::auto_import_joined_ledgers` (when a `QuorumJoin` brings us into a ledger we don't have locally yet),
- `request_handlers/quorum.rs::consent_collateral` (when we consent to back another operator's ledger and need to start tracking it).

`ensure_actor_for` is idempotent: it returns immediately if `ledger_actors` already has an entry for the id. The check + insert is under a `Mutex` so concurrent callers don't double-spawn.

The actor outbox `tx` is captured on `Node` precisely so this path doesn't need to restart the daemon to wire a new actor in — every actor sends to the same shared outbox.

## The Nostr layer

`deposits-node/src/nostr.rs` wraps `nostr-sdk`. The shape:

- **Two clients.** A "fast" client connected to the relays in `config.relays` for subscriptions and publishing, and a "slow" client connected to `config.slow_relays` for durable gap-fill `fetch_events` calls. The slow path is where you point at a long-retention relay like a self-hosted strfry; the fast path can be any low-latency relay. Both are constructed in `NostrTransport::new_with_slow`.

- **Subscription strategy.** `subscribe_global` (line 1163) opens five compacted filters: requests (`Kind:20100`), responses (`Kind:20101`), updates (`Kind:9100`), disputes (`Kind:9103`), fraud proofs (`Kind:9101`). Each filter has `since = now - 5s` so we don't re-deliver old events on reconnect. The `subscribe_to_ledger` path adds per-ledger interest tags but doesn't open new subscriptions; the global filters cover everything.

- **Publishing.** `broadcast_ledger_update(&update)` (line 1312) TLV-encodes the update, base64s it as the event content, builds a `Kind:9100` event with d-tag for the ledger and p-tag for the operator, signs with the operator's Nostr keypair, and publishes. Returns the Nostr event id.

- **Request multicast.** `send_ledger_request(ledger_id, action, params)` builds a `Kind:20100` ephemeral event tagged for the operator and broadcasts. Anyone subscribed sees it. The cosig and consent paths use this; the gift-wrap helpers (`send_gift_wrap_request`) are for admin requests that need the sender to be sealed — `Kind:1059`-wrapped `rumor` events.

- **Inbound delivery.** `process_events_with_timeout(timeout_ms)` is the main loop's drain function. It pulls events from the underlying client's notification stream, de-duplicates against a seen-events set (rotated each periodic cycle), and routes by kind into `InboundMessage` / `LedgerRequest` / `InboundLedgerUpdate` / `LedgerDispute` / `FraudProofEvent` channels.

The Nostr layer doesn't speak the protocol — it speaks events, kinds, and tags. The protocol layer (everything in `node/`) decodes the TLV payloads and routes by action.

## The wallet layer

`deposits-node/src/wallet.rs` wraps BDK. The wallet holds the operator's seed, manages the operator's on-chain coins, and constructs the protocol's reserves UTXOs.

What the daemon uses it for:

- **Block height + hash.** `get_block_height()`, `get_block_hash()`. Stamped into every committed update via `commit_operation` so the chain anchors to a recent Bitcoin tip.
- **Wallet sync.** `sync_wallet()` (full, periodic) and `sync_block_height()` (cheap, every periodic tick).
- **Reserves output construction.** `create_reserves_output(amount_sats, partners, threshold)` — builds the Taproot script tree for a new reserves UTXO with the quorum's public keys.
- **Reserves rotation.** Building the tx that moves coins from operator-only to quorum-controlled (or rotates between quorum sets).
- **Confiscation TX.** `broadcast_confiscation` in `dispute.rs` builds a Taproot witness from collected quorum signatures and submits the TX through the wallet's broadcast path.
- **Cooperative withdrawal.** When a depositor exits on-chain, the wallet builds a tx that spends a portion of the reserves to the wallet's external address, with operator and quorum signatures.

The wallet does not hold protocol state — that's exclusively the ledger's job. It's a stateless on-chain accountant from the protocol's perspective.

## Crash recovery

What happens when the daemon dies mid-commit?

The durable point is the **`<id>.jsonl` write** at the end of `commit_operation`. Before that write completes:
- The actor has staged, cosigned, signed, applied to the in-memory `Ledger`, persisted to `.actor.log`, and broadcast to Nostr.
- The handler's `<id>.jsonl` has not been updated.

If the daemon crashes between the in-memory apply and the `.jsonl` write:
- On restart, the `<id>.jsonl` loader reads the chain through the *previous* tip. The committed update is missing from the loaded state.
- The Nostr event has already been published (or is in flight).
- When the daemon re-subscribes and the broadcast event arrives back, the inbound dispatcher applies it normally — same chain-continuity check, same idempotency. The committed update is replayed onto the loaded chain.
- The `.actor.log` file has the row that the `.jsonl` doesn't. The next `actor_shadow_consistency` audit would flag this until the inbound replay catches up; the test expects this to be transient.

Two safety guards are critical here. The chain-continuity check in `apply_inbound` ensures the replayed update only applies if it extends the current tip — so we can't double-apply or skip updates. And `validate_chain_before_persist` (`init.rs:351`) is called before the `.jsonl` write to ensure the in-memory chain is internally consistent (sequence-monotonic, hash-linked); if not, the persist is skipped and the operator-side caller sees an error.

If the daemon dies *after* `<id>.jsonl` is updated but before the broadcast lands at the relay, the operator restarts with the committed tip on disk and the broadcast lost. The `seed_for_resync_request` machinery in `main_loop.rs::start` (lines 24–38) seeds every loaded ledger into `stale_joined_ledgers` so the background gap-fill loop will rebroadcast missing tail entries to the relay. Members who were online observed the original broadcast and are already up to date; members who came up after will pull the chain via `auto_import_joined_ledgers`.

## Metrics

Prometheus exporters listen on port `9100 + op_idx` (each operator in a cluster has a distinct index). Histograms for `commit_operation`, `request_cosign`, `sign_and_broadcast` come for free from the `#[tracing::instrument]` annotations on those functions plus the metrics shim in `metrics.rs`. Counters for `ledger_update_received` (broken down by validity), `cosign_stale_discarded`, `event_store_insert`, gauges for `pending_cosign_requests`, `processed_requests_current/_prev`, `stale_joined_ledgers`, `ledger_count`, `ledger_history_length`, `total_deposit_balance_sats`, `reserves_balance_sats`. The full catalog is in `deposits-node/src/metrics.rs`. There's also a tracing-flame integration: set `TRACING_FLAME_PATH=/tmp/flame.folded` and a flamegraph of the same instrumented functions gets written on shutdown.

## Worked example: a `transfer_lock` from arrival to response

Let's trace one request from Nostr arrival to wallet response, citing every file and function.

The wallet has published a `Kind:20100` event tagged with the operator's pubkey and the source ledger's id. The event content carries an action `"transfer_lock"`, a wallet signature, a source `deposit_id`, a destination `deposit_id`, an amount in millisats, a deadline, and a unique nonce.

1. **Nostr client receives the event.** `nostr.rs::process_events_with_timeout` — invoked by the main loop's drain phase (`main_loop.rs:1701`) — pulls the event off the notification queue, classifies it as a request, decodes into a `LedgerRequest`, and pushes onto the request channel.

2. **Main loop dispatches.** `main_loop.rs:1710` calls `self.handle_inbound(inbound)` for non-request inbound. For requests the path is the per-ledger request worker. Each owned ledger has a persistent `ledger_workers` task with its own mpsc; `main_loop` routes the request there. The worker calls `handle_ledger_request`.

3. **`handle_ledger_request` filters.** `inbound.rs:5`. Resolves the truncated d-tag back to a full 64-char ledger id; rejects if we already sent this event id (own-broadcast filter); rejects if we're not the operator (`transfer_lock` is in the `operator_only_actions` list); rejects if the request is older than 15s (stale-transfer guard). Otherwise, dispatches by action to the matching handler in `request_handlers/`.

4. **`process_transfer_lock_request`.** `request_handlers/transfer.rs:190`. Verifies the wallet signature against the deposit's wallet key, looks up the source deposit, checks balance availability and deadline, constructs `LedgerOperation::TransferLock { source_deposit, destination_deposit, amount_msat, lock_id, deadline_block, ... }`.

5. **`commit_operation`.** `operations.rs:130`. Acquire the per-ledger staging lock (so two concurrent transfers don't both try to commit at once). Snapshot block height + hash from the wallet. Look up the actor's inbox in `ledger_actors`. Send `LedgerEvent::Commit { operation, block_height, block_hash, reply: tx }`. Await the oneshot.

6. **Actor `handle_commit`.** `ledger_actor.rs:497`. Stage (read lock briefly), drop. Cosign request (`LedgerOutbound::RequestCosig`) → outbox. The drainer task in `main_loop.rs:1022` spawns a sub-task that calls `request_cosign(&ledger_id, &update)`.

7. **`request_cosign`.** `coordination.rs:278`. Acquire semaphore permit. Build cosign request with up-to-20-update piggyback. Multicast `Kind:20100` cosign_update request via `nostr.send_ledger_request`. Store collector keyed by request id. `tokio::select!` on threshold or 5s timeout.

8. **Quorum members.** Each member's daemon receives the cosign request in its own `process_events_with_timeout`, dispatches to its `cosign_workers` per-ledger task, runs `request_handlers/cosign.rs::process_cosign_update_request`. The member applies any piggybacked updates, runs `apply_and_check` against the staged update, and if it passes, signs and replies with a `Kind:20101` response carrying `cosign_signature_hex` and `member_ledger_hash_hex`.

9. **Operator receives cosign responses.** Back in operator land: `coordination.rs::handle_ledger_response` (or the cosign-only fast path in `handle_cosign_response_only`) pushes each response into the matching `CosignCollector`. Once `threshold` is reached, `collector.notify.notify_one()` wakes the awaiter. `request_cosign` collects results, returns them to the drainer task, drainer sends the `Vec<CosignEntry>` back via the actor's `RequestCosig` reply.

10. **Actor finishes the commit.** Operator-signs the staged update. Takes the write lock, runs `commit_staged` (which advances the state machine — `LedgerState::apply` consumes the `TransferLock` and locks `amount_msat` of the source deposit). Drops the write lock. Appends to `.actor.log`. Sends `LedgerOutbound::Broadcast { update, reply: Some(btx) }`. Drainer publishes via `nostr.broadcast_ledger_update`, sends event id back through `btx`. Actor sends `Ok(CommitResult { event_id, update })` back to the operator via the `Commit` reply.

11. **`commit_operation` finishes.** `operations.rs:173` calls `handler.persist_ledger_to_disk(ledger_id)` — the durable `<id>.jsonl` write. Logs the new sequence number. Returns the event id.

12. **Transfer handler finishes.** `process_transfer_lock_request` builds a response payload containing the lock id, the new sequence number, the locked deposit state. Calls `nostr.send_ledger_response` to publish a `Kind:20101` response tagged back to the wallet's original event id.

13. **Wallet receives the response.** Its own subscription delivers the response, the wallet decodes it, persists locally, and prints "lock complete" to stdout.

End-to-end, in fast-poll regtest mode with healthy cosig latencies, this is on the order of 100–500ms. The slow paths are step 7 (multicast + 5s timeout window — actually completes in tens of ms when members are responsive) and step 11 (file write). Everything else is in-process channel work.

If you can step through that flow in your debugger or your tracing flame chart, you understand the daemon. The other request types (`transfer_complete`, `make_invoice`, `pay_invoice`, `deposit_open`, `quorum_add`, `quorum_begin`, etc.) are variations on the same shape — different validation, different `LedgerOperation` variant, same actor-driven commit flow.

## What stays in your head

- **Per-ledger actor.** One tokio task per ledger. Owns the apply path. Shares `Arc<RwLock<Ledger>>` with `handler.ledgers`. Single source of truth, single writer per ledger, but readers don't round-trip through the actor.
- **Lock discipline.** Never hold the ledger lock across an `.await`. Take, mutate, drop.
- **Main loop.** Spawns the dispute wakeup task, the actor outbox drainer, runs periodic + reload + poll ticks, drains incoming Nostr events and dispatches per-ledger.
- **Inbound dispatcher.** Sender-role classification (operator / member / dispute / random) determines which apply path runs. The actor and handler both apply to the same `Arc<RwLock<Ledger>>`; first-mover wins, second-mover dedups.
- **Cosig collector.** Multicast a `Kind:20100` request, collect responses into a notify-backed collector, return when threshold or timeout. Bounded by `cosign_semaphore` to avoid distributed deadlock.
- **Dispute drivers.** `auto_arm` on detection, `auto_confiscate` on apply-edge wakeup or periodic safety-net, `auto_lottery_claim_or_yield` on observing the reveal. The wakeup path drops armed→confiscate latency from seconds-to-minutes to milliseconds.
- **Persistence.** `<id>.jsonl` is authoritative; `.actor.log` is the parallel mirror. Both sit under `wallet/ledgers/`.
- **Crash recovery.** The `<id>.jsonl` write is the durable point. Pre-write crashes lose the commit but the relay broadcast brings it back via inbound replay; post-write crashes recover via gap-fill.

## Where this leads

[Chapter 21](21-the-wallet.md) covers the depositor's CLI: how it discovers operators, builds and signs requests, awaits responses, and escalates when an operator goes silent. The wallet talks to the daemon you just walked through, but its concerns are different — offline tolerance, key management, and graceful degradation when the operator vanishes.
