// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Per-ledger actor.
//!
//! Each ledger gets a dedicated tokio task that owns its `Ledger`
//! state, persistence, and state-machine transitions. The coordinator
//! (the existing `Node`) routes events to the right actor by
//! `ledger_id` and consumes outbound events for broadcast / wallet /
//! spawning new actors.
//!
//! Design discipline:
//!   - The actor never touches any state outside its own `Ledger`.
//!   - Inbound is fully idempotent — dedup on `content_hash` so the
//!     skip-own-ledger guard becomes unnecessary (a self-broadcast
//!     echoed from the relay is just a duplicate the actor recognizes
//!     and drops).
//!   - Outbound is fire-and-forget for everything except cosignature
//!     collection. Cosig is the one synchronous exception: the actor
//!     emits `LedgerOutbound::RequestCosig { reply, .. }` and awaits
//!     the oneshot response before sealing the staged update.
//!
//! This file (Step 1 of the migration) defines the types only — the
//! actor isn't wired into any code path yet. Subsequent steps stand up
//! the actor pool, route inbound through it, route commits through it,
//! and finally drop the parallel `DepositsHandler::ledgers` map.
//! See `MEMORY.md` references for the migration plan.

use bitcoin::secp256k1::{PublicKey, SecretKey};
use deposits_core::messages::LedgerOperation;
use deposits_core::types::{CosignEntry, SignedLedgerUpdate};
use tokio::sync::{mpsc, oneshot};

/// Opaque identifier the coordinator assigns to a cosign request so
/// the actor can correlate the eventual reply with the request that
/// triggered it. Today the coordinator's existing `pending_cosign_requests`
/// uses `String` (Nostr request_id); we keep that shape.
pub type CosigRequestId = String;

/// Events the coordinator forwards into a ledger actor.
#[derive(Debug)]
pub enum LedgerEvent {
    /// A signed update arrived from the relay. The actor checks chain
    /// continuity, dedups on `content_hash`, and (if accepted) applies
    /// it and persists.
    Inbound(Box<SignedLedgerUpdate>),

    /// A peer asked us to cosign their proposed update (we're a quorum
    /// member of the source ledger). Actor validates against its
    /// replica and sends a `CosignReply` back via `LedgerOutbound`.
    Cosign {
        update: Box<SignedLedgerUpdate>,
        reply: oneshot::Sender<Option<CosignEntry>>,
    },

    /// The local operator just committed an update via the legacy
    /// `Node::commit_operation` path; mirror it onto the actor's
    /// shadow view and persist to `.actor.log`. This is 8b-shadow:
    /// the actor isn't authoritative for outbound commits yet, but
    /// it records every committed update so `actor.log` stays a
    /// faithful mirror of `handler`'s `<id>.jsonl` for both inbound
    /// AND outbound updates. A future commit ("true 8b") flips the
    /// flow so `Node::commit_operation` *requests* the commit via
    /// this event and the actor drives staging + cosig + broadcast.
    LocalCommit(Box<SignedLedgerUpdate>),

    /// True 8b — the actor drives a new commit end to end. Replaces
    /// the legacy `Node::commit_operation` body: actor stages, runs
    /// the cosig round (if quorum is active or this is a first
    /// `QuorumBegin`), operator-signs, applies, persists, and
    /// broadcasts. `Node::commit_operation` becomes a thin shim that
    /// emits this event and awaits `reply`; on success it mirrors
    /// the result onto `handler.ledgers` so legacy readers stay
    /// consistent until 8c migrates them.
    Commit {
        operation: LedgerOperation,
        block_height: u32,
        block_hash: [u8; 32],
        reply: oneshot::Sender<Result<CommitResult, String>>,
    },

    /// Drained from the run loop on shutdown.
    Shutdown,
}

/// Result the actor returns on a successful `Commit`. The drainer-
/// side `Node::commit_operation` shim mirrors `update` back into
/// `handler.ledgers` (until 8c removes that map) and returns
/// `event_id` to the caller.
#[derive(Debug)]
pub struct CommitResult {
    pub event_id: String,
    pub update: SignedLedgerUpdate,
}

/// Specification for an on-chain confiscation transaction the actor
/// needs the wallet (held by the coordinator) to build and broadcast.
/// This is the only "ask the wallet to do something" event because
/// every other on-chain action (reserves rotation, deposit funding) is
/// driven by the coordinator's own paths, not the per-ledger actor.
#[derive(Debug)]
pub struct ConfiscationSpec {
    pub ledger_id: String,
    pub last_valid_seq: u64,
    pub winner_pubkey: PublicKey,
    // Concrete UTXO + script-path details get added in step 4 when we
    // actually move dispute resolution into the actor — kept abstract
    // here so this type doesn't drag in the full lottery scaffolding.
}

/// Events an actor emits to the coordinator. Fire-and-forget for
/// everything except `RequestCosig`, which carries a oneshot reply
/// so the actor can await majority cosignatures before sealing.
#[derive(Debug)]
pub enum LedgerOutbound {
    /// Publish a fully-formed `SignedLedgerUpdate` over Nostr. The
    /// optional `reply` is set when the caller needs the resulting
    /// event id (e.g. the actor-driven commit path); fire-and-forget
    /// when `None` (legacy and disposable broadcasts).
    Broadcast {
        update: Box<SignedLedgerUpdate>,
        reply: Option<oneshot::Sender<Result<String, String>>>,
    },

    /// Publish a kind:9101 fraud broadcast.
    BroadcastFraud(Box<deposits_core::fraud::FraudBroadcast>),

    /// Coordinator: collect cosignatures from the listed members for
    /// this update. When threshold reached (or timeout), respond via
    /// the oneshot. The actor blocks its run loop on this — it's the
    /// only synchronous outbound path. Reply is `Result` so the actor
    /// can distinguish a real cosig failure (abort the commit) from
    /// "no quorum needed yet" (proceed with operator-only signature).
    RequestCosig {
        update: Box<SignedLedgerUpdate>,
        members: Vec<PublicKey>,
        threshold: usize,
        reply: oneshot::Sender<Result<Vec<CosignEntry>, String>>,
    },

    /// Coordinator + wallet: build, sign, and broadcast the on-chain
    /// confiscation transaction described by `spec`.
    NeedOnchainTx(ConfiscationSpec),

    /// Coordinator: a dispute-resolution event has produced a forked
    /// ledger; spawn a new actor to own it.
    SpawnFork {
        new_ledger_id: String,
        // Concrete spawn args (initial Ledger state, persistence path)
        // get added in step 5 when fork creation moves into the actor.
        // For now this is a marker; the migration introduces the field
        // shape progressively.
    },

    /// Step 8d — apply-edge wakeup: the actor just observed a
    /// fork-branch `DisputeArmed` for `ledger_id`. The coordinator
    /// should run `auto_confiscate` immediately rather than waiting
    /// for the next `periodic_interval` tick. The coordinator's
    /// existing logic is idempotent (skips ledgers without
    /// `custody_armed_*.marker`, skips ones with pending or already-
    /// landed confiscation), so firing aggressively on every armed
    /// observation is safe — extras are no-ops.
    MaybeConfiscate { ledger_id: String },
}

/// A handle the coordinator keeps to talk to the actor.
pub struct LedgerActorHandle {
    /// Coordinator pushes events here.
    pub inbox: mpsc::Sender<LedgerEvent>,
}

impl LedgerActorHandle {
    /// Try to send an event without awaiting; logs and drops on
    /// closed channel. Used for fire-and-forget routing from the
    /// coordinator's main loop where blocking the main loop on a
    /// per-actor backlog would be the wrong shape.
    pub fn try_send(&self, ev: LedgerEvent) {
        if let Err(e) = self.inbox.try_send(ev) {
            tracing::warn!("LedgerActor inbox send failed: {}", e);
        }
    }
}

/// Shared-shape outbox: each actor sends `(ledger_id, outbound_event)`
/// into a single coordinator-side receiver. Easier multiplexing than
/// per-actor channels and matches how the coordinator's main loop
/// already handles fan-in for Nostr / wallet operations.
pub type SharedOutbox = mpsc::UnboundedSender<(String, LedgerOutbound)>;

/// The actor itself. Step 1 leaves this as the type sketch; subsequent
/// steps fill in `run()` with the real state-machine driver, move
/// `Ledger` ownership in, and add persistence.
pub struct LedgerActor {
    /// Inbox the actor reads from. Owned here so dropping the actor
    /// closes the channel naturally on shutdown.
    pub inbox: mpsc::Receiver<LedgerEvent>,
    /// Shared outbox to the coordinator (tagged with this actor's
    /// `ledger_id` on every send).
    pub outbox: SharedOutbox,
    /// The shared ledger handle. Phase C/D of the 8b/8c migration
    /// changes this from an owned `Ledger` to the same
    /// `Arc<RwLock<Ledger>>` that lives in `handler.ledgers`. Single
    /// source of truth: the actor's writes (via `commit_staged` in
    /// `handle_commit`, or `apply` in `apply_inbound`) immediately
    /// become visible to every reader still going through
    /// `handler.ledgers`. No separate mirror step needed.
    ///
    /// Lock discipline:
    ///   - Take the write lock only for the apply-state slice.
    ///   - Never hold any lock across an `.await` (cosig + broadcast
    ///     in `handle_commit` complete with the lock dropped).
    ///   - Reads that need a snapshot clone the lock guard contents
    ///     and drop the guard before returning.
    pub ledger: std::sync::Arc<std::sync::RwLock<deposits_core::ledger::Ledger>>,
    /// Stable identifier for log lines and outbox tagging.
    pub ledger_id: String,
    /// Path to the actor's parallel JSONL (Step 5). Each accepted
    /// `Inbound` update is appended as a `{"type":"Update", ...}` row,
    /// matching the format `handler.rs` already uses for the
    /// authoritative file. The actor never writes a State row — its
    /// JSONL is "updates seen since this process started", so a diff
    /// against the handler's authoritative file validates that the
    /// actor's apply path agrees on what's in the chain.
    pub persistence_path: std::path::PathBuf,
    /// Step 8a: directory holding the fork files. The actor writes
    /// each observed fork branch to
    /// `{ledger_id}_{last_valid_seq:06}_{disputer_pk_16}.actor.log`
    /// in this directory, matching the handler's compound-key
    /// layout (handler emits `.jsonl` with the same name). The
    /// actor's job is to observe — it doesn't apply fork branches
    /// to a sub-state today; that's 8b territory.
    pub forks_dir: std::path::PathBuf,
    /// Step 8a: per-disputer mapping of disputer pubkey →
    /// (last_valid_seq, last_observed_seq_on_fork). Built up as
    /// `DisputeEnter` events arrive and consulted when subsequent
    /// fork-branch updates need to be routed to the right file.
    /// Cleared on `DisputeAcquire` (custody transferred — fork is
    /// now the canonical chain) or `DisputeYield` (branch
    /// tombstoned).
    pub fork_observations: std::collections::HashMap<
        bitcoin::secp256k1::PublicKey,
        ForkObservation,
    >,
    /// Operator's signing key, captured at actor spawn from the
    /// node's wallet. Used by `handle_commit` (true 8b) to sign new
    /// updates the actor produces. Stable for the daemon's lifetime
    /// — same key is used by the legacy `Node::commit_operation`
    /// path, so no risk of key drift between paths.
    pub operator_secret: SecretKey,
}

/// Step 8a — per-disputer fork-branch observation state.
#[derive(Clone, Debug)]
pub struct ForkObservation {
    /// Sequence on the *main* chain at which this fork diverges.
    /// Sourced from `DisputeEnter.last_valid_sequence`. Becomes part
    /// of the compound tracking key.
    pub last_valid_seq: u64,
    /// Highest sequence we've observed on this disputer's fork
    /// branch. Drives idempotent dedup on subsequent appends.
    pub last_observed_seq: u64,
}

impl LedgerActor {
    /// Convenience: send to the shared outbox tagged with this
    /// actor's ledger_id.
    #[allow(dead_code)] // becomes used in step 3+
    fn emit(&self, ev: LedgerOutbound) {
        if let Err(e) = self.outbox.send((self.ledger_id.clone(), ev)) {
            tracing::warn!(
                "LedgerActor[{}…] outbox send failed (coordinator gone?): {}",
                &self.ledger_id[..16.min(self.ledger_id.len())],
                e
            );
        }
    }

    /// Apply an inbound `SignedLedgerUpdate` to the actor's shadow
    /// `Ledger`. Step 4 implementation: idempotent dedup on
    /// `(sequence_number, content_hash)`, then chain-continuity check
    /// (next slot only — gaps and out-of-order are dropped), then
    /// `apply_state_changes` and tip advancement. Mirrors what the
    /// authoritative `handler.ledgers` path does for non-self updates.
    /// Self-broadcasts echoed back from the relay land here too and
    /// dedup correctly via content_hash.
    ///
    /// No persistence in step 4 — actor state is in-memory shadow only.
    /// Step 5 adds persistence and makes the actor authoritative.
    fn apply_inbound(&mut self, update: deposits_core::types::SignedLedgerUpdate) {
        use deposits_core::messages::LedgerOperation;
        use deposits_core::tlv::TlvDecode;

        // Phase C/D — `self.ledger` is now `Arc<RwLock<Ledger>>`
        // shared with `handler.ledgers`. Take the write lock for the
        // whole apply path (no awaits inside this function) so the
        // checks (parent_pubkey, dedup, chain-continuity) and the
        // mutation see a consistent view.
        let mut ledger = self.ledger.write().unwrap();

        // Operator-key filter: only accept updates whose operator_id
        // matches our current `parent_pubkey`. Fork-branch updates from
        // dispute initiators carry the disputer's pubkey as the operator
        // and would extend a different chain. The handler's
        // `handle_ledger_update` does the same gate (see
        // `is_from_operator` check in `inbound.rs`); without this the
        // actor's shadow drifts as soon as a dispute creates competing
        // seq-N+1 updates from multiple disputers' forks.
        // After DisputeAcquire, parent_pubkey is updated to the new
        // custodian — the filter naturally adapts.
        if update.operator_id != ledger.state.parent_pubkey {
            // Fork-branch update — Step 8a routes to a per-disputer
            // file matching the handler's compound-key layout. Drop
            // the lock first so the fork helper can take its own.
            drop(ledger);
            self.handle_fork_branch_update(&update);
            return;
        }

        // Dedup on (seq, content_hash). Same content at same seq → no-op.
        // Different content at same seq → equivocation evidence; log and
        // refuse to apply (keeps the actor consistent with whichever
        // arrived first).
        if let Some(existing) = ledger
            .history
            .iter()
            .find(|u| u.sequence_number == update.sequence_number)
        {
            if existing.content_hash != update.content_hash {
                tracing::warn!(
                    "LedgerActor[{}…] equivocation at seq {}: existing content {} vs new {}",
                    &self.ledger_id[..16.min(self.ledger_id.len())],
                    update.sequence_number,
                    hex::encode(&existing.content_hash[..8]),
                    hex::encode(&update.content_hash[..8])
                );
            }
            return;
        }

        // Chain-continuity: only apply if this is the exact next slot
        // AND the previous_hash matches our tip's chain_hash. Gaps and
        // out-of-order updates are dropped — the authoritative handler
        // path may have already accepted via event-store catch-up; the
        // actor's shadow stays slightly behind in that case (will be
        // reconciled when the actor takes over persistence in step 5).
        let expected_seq = ledger.state.sequence + 1;
        if update.sequence_number != expected_seq {
            tracing::trace!(
                "LedgerActor[{}…] dropping seq {} (expected {})",
                &self.ledger_id[..16.min(self.ledger_id.len())],
                update.sequence_number,
                expected_seq
            );
            return;
        }
        let expected_prev = ledger.state.chain_tip_hash;
        if update.previous_hash != expected_prev {
            tracing::warn!(
                "LedgerActor[{}…] chain-break at seq {}: previous_hash {} vs tip {}",
                &self.ledger_id[..16.min(self.ledger_id.len())],
                update.sequence_number,
                hex::encode(&update.previous_hash[..8]),
                hex::encode(&expected_prev[..8])
            );
            return;
        }

        let op = match LedgerOperation::tlv_decode(&update.message) {
            Ok(o) => o,
            Err(e) => {
                tracing::warn!(
                    "LedgerActor[{}…] decode failed at seq {}: {}",
                    &self.ledger_id[..16.min(self.ledger_id.len())],
                    update.sequence_number,
                    e
                );
                return;
            }
        };
        if let Err(e) = ledger.state.apply(&op) {
            tracing::warn!(
                "LedgerActor[{}…] apply failed at seq {}: {}",
                &self.ledger_id[..16.min(self.ledger_id.len())],
                update.sequence_number,
                e
            );
            return;
        }
        ledger.state.sequence = update.sequence_number;
        ledger.state.chain_tip_hash = update.chain_hash();
        ledger.history.push(update.clone());
        // Drop the write lock before doing disk I/O: persistence is a
        // sanity-check side channel, not on the critical path, and
        // the handler's persist_ledger_to_disk path can take its own
        // read lock at any time.
        drop(ledger);

        // Append to parallel JSONL (Step 5). Matches handler's
        // `LedgerLogRow::Update` wire shape — flatten the update with
        // a `"type":"Update"` key. Failure to persist is logged but
        // doesn't unwind the in-memory apply: the shadow file is for
        // sanity-checking, and a missed line is recoverable from the
        // authoritative handler file in step 6.
        if let Err(e) = self.append_update_row(&update) {
            tracing::warn!(
                "LedgerActor[{}…] persist seq {} failed: {}",
                &self.ledger_id[..16.min(self.ledger_id.len())],
                update.sequence_number,
                e
            );
        }
    }

    /// Append a single `Update` JSONL row to the actor's parallel file.
    /// Step 8a — observe a fork-branch update (operator_id !=
    /// parent_pubkey) and persist it to a per-disputer file matching
    /// the handler's compound-key layout.
    ///
    /// On `DisputeEnter` (the disputer's first fork-branch update),
    /// register a new `ForkObservation` keyed by the disputer's
    /// pubkey and persist the update under
    /// `{ledger_id}_{last_valid_seq:06}_{disputer_pk_16}.actor.log`.
    /// Subsequent fork-branch updates from the same disputer are
    /// routed to the same file as long as their sequence is strictly
    /// monotonic on the fork. On `DisputeAcquire` / `DisputeYield`,
    /// the observation is dropped — the fork either takes over the
    /// canonical chain or is tombstoned.
    ///
    /// This is observation-only: the actor does NOT apply the fork
    /// branches to a sub-state. That's 8b/8c territory. The files
    /// produced here let later migration steps (and audit tooling)
    /// read the actor's view of every fork it saw.
    fn handle_fork_branch_update(
        &mut self,
        update: &deposits_core::types::SignedLedgerUpdate,
    ) {
        use deposits_core::messages::LedgerOperation;
        use deposits_core::tlv::TlvDecode;

        let op = match LedgerOperation::tlv_decode(&update.message) {
            Ok(o) => o,
            Err(e) => {
                tracing::trace!(
                    "LedgerActor[{}…] fork update decode failed at seq {}: {}",
                    &self.ledger_id[..16.min(self.ledger_id.len())],
                    update.sequence_number,
                    e
                );
                return;
            }
        };

        // Pre-fork updates that snuck through (operator_id was the
        // old operator on a stale broadcast) get logged at trace
        // and dropped. Only updates ≥ our chain tip are interesting.
        let is_dispute_enter =
            matches!(op, LedgerOperation::DisputeEnter { .. });
        let main_chain_seq = self.ledger.read().unwrap().state.sequence;
        if update.sequence_number <= main_chain_seq && !is_dispute_enter {
            tracing::trace!(
                "LedgerActor[{}…] stale non-operator update seq {} from {}",
                &self.ledger_id[..16.min(self.ledger_id.len())],
                update.sequence_number,
                hex::encode(&update.operator_id.serialize()[..8])
            );
            return;
        }

        // Resolve which fork file this update belongs to. New
        // disputers register on `DisputeEnter`; subsequent updates
        // look up by `operator_id`.
        let last_valid_seq = match &op {
            LedgerOperation::DisputeEnter {
                last_valid_sequence,
                ..
            } => {
                let entry = self
                    .fork_observations
                    .entry(update.operator_id)
                    .or_insert(ForkObservation {
                        last_valid_seq: *last_valid_sequence,
                        last_observed_seq: 0,
                    });
                // Disputer can re-emit DisputeEnter with the same
                // last_valid_sequence (idempotent retry). Reject if
                // they shift the divergence point — that's protocol
                // confusion and we don't want fork files mutating
                // their compound key mid-life.
                if entry.last_valid_seq != *last_valid_sequence {
                    tracing::warn!(
                        "LedgerActor[{}…] disputer {} changed last_valid_seq {} → {}",
                        &self.ledger_id[..16.min(self.ledger_id.len())],
                        hex::encode(&update.operator_id.serialize()[..8]),
                        entry.last_valid_seq,
                        last_valid_sequence
                    );
                    return;
                }
                tracing::info!(
                    "LedgerActor[{}…] fork-branch DisputeEnter: disputer={} fork_seq={}",
                    &self.ledger_id[..16.min(self.ledger_id.len())],
                    hex::encode(&update.operator_id.serialize()[..8]),
                    last_valid_sequence
                );
                *last_valid_sequence
            }
            _ => match self.fork_observations.get(&update.operator_id) {
                Some(obs) => obs.last_valid_seq,
                None => {
                    // Subsequent fork-branch update without a prior
                    // DisputeEnter we observed. The disputer's
                    // DisputeEnter may have been published before our
                    // process started; without it we don't know the
                    // divergence point so we can't compute the
                    // compound key. Drop with a log so audit can
                    // notice.
                    tracing::trace!(
                        "LedgerActor[{}…] fork update from unobserved disputer {} (no DisputeEnter on record)",
                        &self.ledger_id[..16.min(self.ledger_id.len())],
                        hex::encode(&update.operator_id.serialize()[..8])
                    );
                    return;
                }
            },
        };

        // Idempotent dedup on the fork's chain. Anything ≤ what we've
        // already observed is a duplicate (or out-of-order replay)
        // and we don't write it twice.
        if let Some(obs) = self.fork_observations.get(&update.operator_id) {
            if update.sequence_number <= obs.last_observed_seq
                && obs.last_observed_seq > 0
            {
                tracing::trace!(
                    "LedgerActor[{}…] dedup fork update from {} at seq {} (last_observed={})",
                    &self.ledger_id[..16.min(self.ledger_id.len())],
                    hex::encode(&update.operator_id.serialize()[..8]),
                    update.sequence_number,
                    obs.last_observed_seq
                );
                return;
            }
        }

        // Compound key matches `DepositsHandler::fork_tracking_key`:
        //   {ledger_id}_{last_valid_seq:06}_{disputer_pk_first_16_hex}
        let disputer_prefix = hex::encode(update.operator_id.serialize());
        let compound_key = format!(
            "{}_{:06}_{}",
            self.ledger_id,
            last_valid_seq,
            &disputer_prefix[..16]
        );
        let path = self.forks_dir.join(format!("{}.actor.log", compound_key));

        if let Err(e) = append_update_to(&path, update) {
            tracing::warn!(
                "LedgerActor[{}…] persist fork seq {} from {} failed: {}",
                &self.ledger_id[..16.min(self.ledger_id.len())],
                update.sequence_number,
                hex::encode(&update.operator_id.serialize()[..8]),
                e
            );
            return;
        }

        // Update the observation's last_observed_seq.
        if let Some(obs) = self.fork_observations.get_mut(&update.operator_id) {
            obs.last_observed_seq = obs.last_observed_seq.max(update.sequence_number);
        }

        // Drop the observation when the fork resolves — DisputeAcquire
        // means this branch took custody (it'll become the new main
        // chain via parent_pubkey rotation); DisputeYield tombstones
        // the branch. Either way, we stop tracking it.
        if matches!(
            op,
            LedgerOperation::DisputeAcquire { .. } | LedgerOperation::DisputeYield
        ) {
            self.fork_observations.remove(&update.operator_id);
        }

        // Step 8d — apply-edge confiscation trigger. When we observe
        // a `DisputeArmed` from any disputer (ourselves or a peer),
        // wake the coordinator so it can re-check whether all
        // expected disputants are armed and the confiscation is now
        // ready to initiate. Without this signal, the coordinator
        // waits up to `periodic_interval` (5s with --fast-poll, else
        // 60s) before checking — most of the dispute pipeline's
        // wall-clock latency is here. Idempotent: the coordinator's
        // logic skips ledgers that don't qualify yet or that already
        // have a pending/landed confiscation.
        if matches!(op, LedgerOperation::DisputeArmed { .. }) {
            if let Err(e) = self.outbox.send((
                self.ledger_id.clone(),
                LedgerOutbound::MaybeConfiscate {
                    ledger_id: self.ledger_id.clone(),
                },
            )) {
                tracing::trace!(
                    "LedgerActor[{}…] MaybeConfiscate outbox send failed: {}",
                    &self.ledger_id[..16.min(self.ledger_id.len())],
                    e
                );
            }
        }
    }

    // 8b-shadow's `handle_local_commit_shadow` was removed in Phase
    // C/D — Phase B made the actor authoritative for commits, and
    // Phase C/D made `self.ledger` the same `Arc<RwLock<Ledger>>`
    // that `handler.ledgers` exposes. There's no separate handler
    // copy to mirror onto, and `Node::commit_operation` no longer
    // fires `LedgerEvent::LocalCommit`. The variant is kept on the
    // enum for binary-compat with any in-flight messages but the
    // run loop just drops it.

    /// Append the main-chain update to `self.persistence_path`. Thin
    /// wrapper around the free `append_update_to` so the fork path
    /// (8a) and main path share the same write logic.
    fn append_update_row(
        &self,
        update: &deposits_core::types::SignedLedgerUpdate,
    ) -> Result<(), std::io::Error> {
        append_update_to(&self.persistence_path, update)
    }

    /// True 8b — drive a new commit end to end on this ledger.
    ///
    /// Mirrors what `Node::commit_operation` used to do, but with the
    /// actor's owned `Ledger` as the authoritative state and the
    /// outbox as the only path back to the rest of the daemon
    /// (cosig collection, broadcast). The async work happens inline
    /// in the run loop because each actor is single-tasked — this
    /// blocks other events on this ledger but not on others, which
    /// matches the per-ledger staging-lock semantics the legacy
    /// path used.
    ///
    /// Returns the broadcast event id and the fully-signed update
    /// (so `Node::commit_operation`'s shim can mirror it onto
    /// `handler.ledgers` for legacy readers until 8c migrates them).
    async fn handle_commit(
        &mut self,
        operation: LedgerOperation,
        block_height: u32,
        block_hash: [u8; 32],
    ) -> Result<CommitResult, String> {
        use bitcoin::hashes::{sha256, Hash};
        use bitcoin::secp256k1::{Keypair, Message, Secp256k1};

        // 1. Stage on the actor's ledger. validate_operation runs
        //    inside; mirrors what Node used to do via handler.ledgers.
        //    Take the read lock for staging only — release before any
        //    .await to keep readers unblocked during the cosig round.
        let (mut staged, quorum_active, members) = {
            let ledger = self.ledger.read().unwrap();
            let staged = ledger
                .stage_operation(operation, block_height, block_hash)
                .map_err(|e| format!("stage failed: {}", e))?;
            let quorum_active =
                ledger.state.quorum_state == deposits_core::QuorumState::Active;
            let members: Vec<PublicKey> = ledger
                .state
                .quorum_members
                .iter()
                .map(|m| m.pubkey)
                .collect();
            (staged, quorum_active, members)
        };

        // 2. Cosign — required when the quorum is active OR when this
        //    is the very first QuorumBegin (which transitions the
        //    state machine PreQuorum -> Active and so needs member
        //    attestation even though the state is still PreQuorum at
        //    stage time). Same gate as the legacy path.
        let is_first_quorum_begin = !quorum_active
            && matches!(&staged.operation, LedgerOperation::QuorumBegin { .. });
        if quorum_active || is_first_quorum_begin {
            let threshold = members.len() / 2 + 1;
            let (tx, rx) = oneshot::channel::<Result<Vec<CosignEntry>, String>>();
            let send_res = self.outbox.send((
                self.ledger_id.clone(),
                LedgerOutbound::RequestCosig {
                    update: Box::new(staged.update.clone()),
                    members: members.clone(),
                    threshold,
                    reply: tx,
                },
            ));
            if let Err(e) = send_res {
                return Err(format!("RequestCosig outbox send failed: {}", e));
            }
            let entries = rx
                .await
                .map_err(|_| "RequestCosig reply dropped".to_string())??;
            let mut sorted = entries;
            sorted.sort_by(|a, b| {
                a.cosigner_pubkey
                    .serialize()
                    .cmp(&b.cosigner_pubkey.serialize())
            });
            staged.update.cosignatures = sorted;
            staged.update.cosigner_pubkey = None;
            staged.update.member_ledger_hash = None;
            staged.update.cosign_signature = [0u8; 64];
            staged.update.content_hash = staged.update.compute_hash();
        }

        // 3. Operator-sign with the actor's stored secret. The data
        //    we sign covers content + every cosignature, matching
        //    what `operator_signing_data()` builds — same shape as
        //    the legacy path so peers' verifiers don't notice.
        {
            let secp = Secp256k1::new();
            let data = staged.update.operator_signing_data();
            let hash = sha256::Hash::hash(&data);
            let msg = Message::from_digest(*hash.as_byte_array());
            let keypair = Keypair::from_secret_key(&secp, &self.operator_secret);
            staged.update.operator_signature = secp.sign_schnorr(&msg, &keypair).serialize();
        }

        // 4. Apply on the shared ledger. Phase C/D — `self.ledger`
        //    is the same `Arc<RwLock<Ledger>>` `handler.ledgers`
        //    holds, so `commit_staged` here is the authoritative
        //    write that every reader sees. Take the write lock
        //    briefly and drop before any subsequent .await.
        let update_for_return = staged.update.clone();
        {
            let mut ledger = self.ledger.write().unwrap();
            ledger
                .commit_staged(staged)
                .map_err(|e| format!("commit_staged failed: {}", e))?;
        }

        // 5. Persist to .actor.log so the on-disk shadow stays in
        //    sync with the in-memory tip even if the daemon dies
        //    before broadcast.
        if let Err(e) = self.append_update_row(&update_for_return) {
            tracing::warn!(
                "LedgerActor[{}…] handle_commit persist seq {} failed: {}",
                &self.ledger_id[..16.min(self.ledger_id.len())],
                update_for_return.sequence_number,
                e
            );
        }

        // 6. Broadcast over Nostr via the outbox. Wait for the
        //    event id so callers (whose API contract returns
        //    `String`) get the same answer they used to.
        let (btx, brx) = oneshot::channel::<Result<String, String>>();
        let send_res = self.outbox.send((
            self.ledger_id.clone(),
            LedgerOutbound::Broadcast {
                update: Box::new(update_for_return.clone()),
                reply: Some(btx),
            },
        ));
        if let Err(e) = send_res {
            return Err(format!("Broadcast outbox send failed: {}", e));
        }
        let event_id = brx
            .await
            .map_err(|_| "Broadcast reply dropped".to_string())?
            .unwrap_or_default(); // legacy path also tolerates broadcast failure (see operations.rs)

        Ok(CommitResult {
            event_id,
            update: update_for_return,
        })
    }

    /// Run loop. Step 4 implements `Inbound` to keep an in-memory
    /// shadow of the ledger; LocalCommit + Cosign are still stubs.
    pub async fn run(mut self) {
        tracing::info!(
            "LedgerActor[{}…] starting",
            &self.ledger_id[..16.min(self.ledger_id.len())]
        );
        while let Some(event) = self.inbox.recv().await {
            match event {
                LedgerEvent::Inbound(update) => {
                    self.apply_inbound(*update);
                }
                LedgerEvent::Cosign { reply, .. } => {
                    // Step 4: still refuse to cosign — handler path is
                    // authoritative until step 5.
                    let _ = reply.send(None);
                }
                LedgerEvent::LocalCommit(_update) => {
                    // Dead code post-Phase B: see the comment near
                    // where `handle_local_commit_shadow` used to live.
                    // The variant is kept for binary-compat; just drop.
                }
                LedgerEvent::Commit {
                    operation,
                    block_height,
                    block_hash,
                    reply,
                } => {
                    let res = self
                        .handle_commit(operation, block_height, block_hash)
                        .await;
                    let _ = reply.send(res);
                }
                LedgerEvent::Shutdown => {
                    tracing::info!(
                        "LedgerActor[{}…] shutting down",
                        &self.ledger_id[..16.min(self.ledger_id.len())]
                    );
                    break;
                }
            }
        }
        tracing::info!(
            "LedgerActor[{}…] inbox closed; exiting",
            &self.ledger_id[..16.min(self.ledger_id.len())]
        );
    }
}

/// Append a `SignedLedgerUpdate` row to the given path, matching the
/// "newline-then-row" `{"type":"Update", ...}` shape used by the
/// handler's authoritative ledger files. Used by both the main-chain
/// `append_update_row` and the fork-branch path in
/// `handle_fork_branch_update` (Step 8a).
fn append_update_to(
    path: &std::path::Path,
    update: &deposits_core::types::SignedLedgerUpdate,
) -> Result<(), std::io::Error> {
    use std::io::Write;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut value = match serde_json::to_value(update) {
        Ok(v) => v,
        Err(e) => return Err(std::io::Error::other(e)),
    };
    if let Some(obj) = value.as_object_mut() {
        obj.insert(
            "type".to_string(),
            serde_json::Value::String("Update".into()),
        );
    }
    let line = match serde_json::to_string(&value) {
        Ok(s) => s,
        Err(e) => return Err(std::io::Error::other(e)),
    };

    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)?;
    write!(file, "\n{}", line)?;
    Ok(())
}
