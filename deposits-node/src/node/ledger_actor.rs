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

use bitcoin::secp256k1::PublicKey;
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

    /// The local operator wants to commit a new operation. Actor stages,
    /// requests cosignatures (synchronously), commits, persists, and
    /// emits a `Broadcast`.
    LocalCommit(Box<deposits_core::messages::LedgerOperation>),

    /// Drained from the run loop on shutdown.
    Shutdown,
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
    /// Publish a fully-formed `SignedLedgerUpdate` over Nostr.
    Broadcast(Box<SignedLedgerUpdate>),

    /// Publish a kind:9101 fraud broadcast.
    BroadcastFraud(Box<deposits_core::fraud::FraudBroadcast>),

    /// Coordinator: collect cosignatures from the listed members for
    /// this update. When threshold reached (or timeout), respond via
    /// the oneshot. The actor blocks its run loop on this — it's the
    /// only synchronous outbound path.
    RequestCosig {
        update: Box<SignedLedgerUpdate>,
        members: Vec<PublicKey>,
        threshold: usize,
        reply: oneshot::Sender<Vec<CosignEntry>>,
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
    /// The owned ledger. Wrapped so steps 2-3 can move ownership in
    /// without forcing a full rewrite of every existing access site
    /// in one PR.
    pub ledger: deposits_core::ledger::Ledger,
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
        if update.operator_id != self.ledger.state.parent_pubkey {
            // Fork-branch update — Step 8a routes to a per-disputer
            // file matching the handler's compound-key layout.
            self.handle_fork_branch_update(&update);
            return;
        }

        // Dedup on (seq, content_hash). Same content at same seq → no-op.
        // Different content at same seq → equivocation evidence; log and
        // refuse to apply (keeps the actor consistent with whichever
        // arrived first).
        if let Some(existing) = self
            .ledger
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
        let expected_seq = self.ledger.state.sequence + 1;
        if update.sequence_number != expected_seq {
            tracing::trace!(
                "LedgerActor[{}…] dropping seq {} (expected {})",
                &self.ledger_id[..16.min(self.ledger_id.len())],
                update.sequence_number,
                expected_seq
            );
            return;
        }
        let expected_prev = self.ledger.state.chain_tip_hash;
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
        if let Err(e) = self.ledger.state.apply(&op) {
            tracing::warn!(
                "LedgerActor[{}…] apply failed at seq {}: {}",
                &self.ledger_id[..16.min(self.ledger_id.len())],
                update.sequence_number,
                e
            );
            return;
        }
        self.ledger.state.sequence = update.sequence_number;
        self.ledger.state.chain_tip_hash = update.chain_hash();
        self.ledger.history.push(update.clone());

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
        if update.sequence_number <= self.ledger.state.sequence
            && !is_dispute_enter
        {
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
    }

    /// Append the main-chain update to `self.persistence_path`. Thin
    /// wrapper around the free `append_update_to` so the fork path
    /// (8a) and main path share the same write logic.
    fn append_update_row(
        &self,
        update: &deposits_core::types::SignedLedgerUpdate,
    ) -> Result<(), std::io::Error> {
        append_update_to(&self.persistence_path, update)
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
                LedgerEvent::LocalCommit(_) => {
                    tracing::debug!(
                        "LedgerActor[{}…] received LocalCommit (stub: dropped)",
                        &self.ledger_id[..16.min(self.ledger_id.len())]
                    );
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
