// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Per-ledger actor.
//!
//! Each ledger gets a dedicated tokio task. `Node` routes events to
//! the right actor by `ledger_id` and consumes outbound events for
//! broadcast / cosig / dispute-pipeline wakeups.
//!
//! Design discipline:
//!   - The actor's `ledger` is `Arc<RwLock<Ledger>>` shared with
//!     `handler.ledgers` — single source of truth, single writer.
//!   - Inbound is fully idempotent: dedup on `(seq, content_hash)`,
//!     so a self-broadcast echoed off the relay is a no-op.
//!   - Outbound is fire-and-forget for `MaybeConfiscate`. `Broadcast`
//!     is fire-and-forget *unless* a reply oneshot is set.
//!     `RequestCosig` is the one fully-synchronous outbound path:
//!     the actor blocks its run loop awaiting majority cosignatures
//!     before sealing the staged update.
//!   - Never hold the ledger lock across an `.await`. Take read or
//!     write briefly, drop, do async work, take again if needed.

use bitcoin::secp256k1::{PublicKey, SecretKey};
use deposits_core::messages::LedgerOperation;
use deposits_core::types::{CosignEntry, SignedLedgerUpdate};
use tokio::sync::{mpsc, oneshot};

/// Events the coordinator forwards into a ledger actor.
#[derive(Debug)]
pub enum LedgerEvent {
    /// A signed update arrived from the relay. The actor checks chain
    /// continuity, dedups on `content_hash`, and (if accepted) applies
    /// it and persists.
    Inbound(Box<SignedLedgerUpdate>),

    /// Operator-driven commit. Actor stages, runs the cosig round (if
    /// quorum is active or this is a first `QuorumBegin`),
    /// operator-signs, applies, persists, and broadcasts.
    /// `Node::commit_operation` is a thin shim that emits this event
    /// and awaits `reply`.
    Commit {
        operation: LedgerOperation,
        block_height: u32,
        block_hash: [u8; 32],
        reply: oneshot::Sender<Result<CommitResult, String>>,
    },
}

/// Result the actor returns on a successful `Commit`.
#[derive(Debug)]
pub struct CommitResult {
    pub event_id: String,
    pub update: SignedLedgerUpdate,
}

/// Events an actor emits to the coordinator.
#[derive(Debug)]
pub enum LedgerOutbound {
    /// Publish a fully-formed `SignedLedgerUpdate` over Nostr. The
    /// optional `reply` is set when the caller needs the resulting
    /// event id (e.g. the actor-driven commit path); fire-and-forget
    /// when `None`.
    Broadcast {
        update: Box<SignedLedgerUpdate>,
        reply: Option<oneshot::Sender<Result<String, String>>>,
    },

    /// Coordinator: collect cosignatures from the listed members for
    /// this update. When threshold reached (or timeout), respond via
    /// the oneshot. The actor blocks its run loop on this — it's the
    /// only synchronous outbound path. Reply is `Result` so the actor
    /// can distinguish a real cosig failure (abort the commit) from
    /// "no quorum needed yet".
    RequestCosig {
        update: Box<SignedLedgerUpdate>,
        members: Vec<PublicKey>,
        threshold: usize,
        reply: oneshot::Sender<Result<Vec<CosignEntry>, String>>,
    },

    /// Apply-edge wakeup: the actor just observed a fork-branch
    /// `DisputeArmed` for `ledger_id`. `Node` runs `auto_confiscate`
    /// immediately instead of waiting for the next periodic tick.
    /// Idempotent (skips ledgers without a `custody_armed_*.marker`
    /// and ones with pending or already-landed confiscation), so
    /// firing on every armed observation is safe.
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
/// into a single coordinator-side receiver.
pub type SharedOutbox = mpsc::UnboundedSender<(String, LedgerOutbound)>;

pub struct LedgerActor {
    /// Inbox the actor reads from.
    pub inbox: mpsc::Receiver<LedgerEvent>,
    /// Shared outbox to the coordinator (tagged with this actor's
    /// `ledger_id` on every send).
    pub outbox: SharedOutbox,
    /// Shared ledger handle — the same `Arc<RwLock<Ledger>>` that
    /// lives in `handler.ledgers`. The actor's writes (via
    /// `commit_staged` in `handle_commit`, or `LedgerState::apply`
    /// in `apply_inbound`) are immediately visible to every reader.
    pub ledger: std::sync::Arc<std::sync::RwLock<deposits_core::ledger::Ledger>>,
    /// Stable identifier for log lines and outbox tagging.
    pub ledger_id: String,
    /// Parallel `<id>.actor.log` JSONL file. Each accepted update is
    /// appended as a `{"type":"Update", ...}` row, matching the
    /// shape of the handler's authoritative `<id>.jsonl`. Used as a
    /// regression check: a diff between the two files validates
    /// that the actor's apply path agrees on what's in the chain.
    pub persistence_path: std::path::PathBuf,
    /// Directory the actor writes fork-branch files into:
    /// `{ledger_id}_{last_valid_seq:06}_{disputer_pk_16}.actor.log`,
    /// matching the handler's compound-key layout (handler emits
    /// `.jsonl` files with the same name). Observation only — the
    /// actor doesn't apply fork branches to a sub-state.
    pub forks_dir: std::path::PathBuf,
    /// Per-disputer mapping of disputer pubkey →
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
    /// node's wallet. Stable for the daemon's lifetime.
    pub operator_secret: SecretKey,
}

/// Per-disputer fork-branch observation state.
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
    /// Apply an inbound `SignedLedgerUpdate` to the shared `Ledger`.
    /// Idempotent dedup on `(sequence_number, content_hash)`, then
    /// chain-continuity check (next slot only — gaps and out-of-order
    /// are dropped), then `LedgerState::apply` and tip advancement.
    /// Self-broadcasts echoed back from the relay land here too and
    /// dedup as no-ops.
    ///
    /// `self.ledger` is shared with `handler.ledgers`, so this is the
    /// authoritative apply path the rest of the daemon sees. The
    /// handler's `inbound.rs` apply path may race with us; whichever
    /// gets the lock first wins, the other's dedup check turns into
    /// a no-op.
    fn apply_inbound(&mut self, update: deposits_core::types::SignedLedgerUpdate) {
        use deposits_core::messages::LedgerOperation;
        use deposits_core::tlv::TlvDecode;

        // Take the write lock for the whole apply path (no awaits
        // inside this function) so the checks and the mutation see a
        // consistent view.
        let mut ledger = self.ledger.write().unwrap();

        // Operator-key filter: only accept updates whose operator_id
        // matches our current `parent_pubkey`. Fork-branch updates
        // from dispute initiators carry the disputer's pubkey as the
        // operator and would extend a different chain. After
        // DisputeAcquire, parent_pubkey updates to the new custodian
        // — the filter adapts naturally.
        if update.operator_id != ledger.state.parent_pubkey {
            // Drop the lock so the fork helper can take its own.
            drop(ledger);
            self.handle_fork_branch_update(&update);
            return;
        }

        // Dedup on (seq, content_hash). Same content at same seq →
        // no-op. Different content at same seq → equivocation
        // evidence; log and refuse to apply.
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
        // AND the previous_hash matches our tip's chain_hash. Gaps
        // and out-of-order updates are dropped.
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

        // Append to the parallel `<id>.actor.log`. Failure to persist
        // is logged but doesn't unwind the in-memory apply — the
        // shadow file is for sanity-checking, and a missed line is
        // recoverable from the authoritative `<id>.jsonl`.
        if let Err(e) = self.append_update_row(&update) {
            tracing::warn!(
                "LedgerActor[{}…] persist seq {} failed: {}",
                &self.ledger_id[..16.min(self.ledger_id.len())],
                update.sequence_number,
                e
            );
        }
    }

    /// Observe a fork-branch update (operator_id != parent_pubkey)
    /// and persist it to a per-disputer file matching the handler's
    /// compound-key layout.
    ///
    /// On `DisputeEnter` (the disputer's first fork-branch update),
    /// register a new `ForkObservation` keyed by the disputer's
    /// pubkey and persist the update under
    /// `{ledger_id}_{last_valid_seq:06}_{disputer_pk_16}.actor.log`.
    /// Subsequent fork-branch updates from the same disputer route
    /// to the same file as long as their sequence is strictly
    /// monotonic on the fork. On `DisputeAcquire` / `DisputeYield`,
    /// the observation is dropped — the fork either takes over the
    /// canonical chain or is tombstoned.
    ///
    /// Observation-only: fork branches do not apply to a sub-state.
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

        // Apply-edge confiscation trigger. On any `DisputeArmed`,
        // wake `Node` to re-check whether all expected disputants
        // are armed and confiscation is ready to initiate. Without
        // this signal, `Node` would wait up to `periodic_interval`
        // (5s/60s) before checking — most of the dispute pipeline's
        // wall-clock latency was here. Idempotent.
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

    /// Append a main-chain update to `self.persistence_path`. Thin
    /// wrapper around `append_update_to` so the fork-branch path and
    /// the main path share the same write logic.
    fn append_update_row(
        &self,
        update: &deposits_core::types::SignedLedgerUpdate,
    ) -> Result<(), std::io::Error> {
        append_update_to(&self.persistence_path, update)
    }

    /// Drive a new commit end-to-end: stage, cosig, sign, apply,
    /// persist, broadcast.
    ///
    /// The async work happens inline in the run loop because each
    /// actor is single-tasked — this blocks other events on this
    /// ledger but not on others. Returns the broadcast event id and
    /// the fully-signed update.
    async fn handle_commit(
        &mut self,
        operation: LedgerOperation,
        block_height: u32,
        block_hash: [u8; 32],
    ) -> Result<CommitResult, String> {
        use bitcoin::hashes::{sha256, Hash};
        use bitcoin::secp256k1::{Keypair, Message, Secp256k1};

        // 1. Stage. Take the read lock briefly and release it before
        //    any .await so the cosig round doesn't block readers.
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

        // 2. Cosign — required when the quorum is active OR when
        //    this is the very first QuorumBegin (which transitions
        //    the state machine PreQuorum -> Active and so needs
        //    member attestation even though state is still PreQuorum
        //    at stage time).
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

        // 3. Operator-sign. Data covers content + every cosignature
        //    (see `operator_signing_data`).
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
        // Tolerate broadcast failure — the relay echo or a peer's
        // gap-fill will deliver the update if our publish dropped.
        let event_id = brx
            .await
            .map_err(|_| "Broadcast reply dropped".to_string())?
            .unwrap_or_default();

        Ok(CommitResult {
            event_id,
            update: update_for_return,
        })
    }

    /// Run loop — drives `Inbound` and `Commit` events. The actor
    /// exits when its inbox channel closes (i.e. every sender has
    /// dropped).
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
            }
        }
        tracing::info!(
            "LedgerActor[{}…] inbox closed; exiting",
            &self.ledger_id[..16.min(self.ledger_id.len())]
        );
    }
}

/// Append a `SignedLedgerUpdate` row to the given path, matching the
/// `{"type":"Update", ...}` shape the handler's authoritative ledger
/// files use. Shared between the main-chain and fork-branch writers.
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
