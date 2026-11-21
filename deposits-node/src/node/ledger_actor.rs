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

use bitcoin::secp256k1::PublicKey;
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
        /// DEP-06 answer floor (keys, need): a rotating QuorumBegin also needs `need` valid
        /// cosignatures by `keys` (the spent tier's), or nothing is committed.
        tier_floor: Option<(Vec<bitcoin::secp256k1::XOnlyPublicKey>, usize)>,
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
        reply: oneshot::Sender<Result<Vec<CosignEntry>, super::cosign_restage::CosignFailure>>,
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
    /// Notified whenever the actor advances `ledger.state.sequence`
    /// (Inbound apply, Commit, or any future state-advancing event).
    /// Inbound dispatchers can wait on this for cosign requests whose
    /// referenced sequence hasn't landed yet — no busy-polling.
    pub apply_wakeup: std::sync::Arc<tokio::sync::Notify>,
}

impl LedgerActorHandle {
    /// Try to send an event without awaiting. Used for fire-and-forget
    /// routing from the coordinator's main loop where blocking the main
    /// loop on a per-actor backlog would be the wrong shape. `false` when
    /// the event was not delivered (inbox full or closed): a caller
    /// forwarding a ledger update marks the ledger stale, so the gap the
    /// dropped update leaves is filled from the relay instead of sitting
    /// until the next update exposes it (a member's replica three updates
    /// short at a rotation, signet soak 2026-10-21).
    #[must_use]
    pub fn try_send(&self, ev: LedgerEvent) -> bool {
        match self.inbox.try_send(ev) {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!("LedgerActor inbox send failed: {}", e);
                false
            }
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
    /// `commit_staged` in `handle_commit`, or `apply_and_check`
    /// in `apply_inbound`) are immediately visible to every reader.
    pub ledger: std::sync::Arc<std::sync::RwLock<deposits_core::ledger::Ledger>>,
    /// Stable identifier for log lines and outbox tagging.
    pub ledger_id: String,
    /// Operator-side signer, shared with the handler. The actor calls
    /// `bip340_sign` here to produce the operator signature on each
    /// committed update; the underlying secret never lives on the
    /// actor's stack.
    pub signer: std::sync::Arc<dyn deposits_signer_api::Signer>,
    /// Shared handler reference. The actor calls
    /// `handler.persist_ledger_to_disk` after each accepted apply
    /// (inbound or commit) so the authoritative `<id>.jsonl` matches
    /// the in-memory tip. The actor is the single writer for this
    /// ledger; the handler's persist function is its disk path.
    pub handler: std::sync::Arc<crate::handler::DepositsHandler>,
    /// Same `Notify` as in `LedgerActorHandle::apply_wakeup`. The actor
    /// calls `notify_waiters()` on this after every successful state
    /// advance, so external waiters (e.g. the inbound cosign dispatcher
    /// waiting for a prior update to land) get woken event-driven.
    pub apply_wakeup: std::sync::Arc<tokio::sync::Notify>,
    /// Our chain tip (height, block hash), read when a draft must be re-staged
    /// (`cosign_restage`). `None` when unknown.
    pub chain_tip: ChainTip,
}

/// Where a ledger actor reads our chain tip.
pub type ChainTip = std::sync::Arc<dyn Fn() -> Option<(u32, [u8; 32])> + Send + Sync>;

/// The wallet's cached tip, as `Node::commit_operation_floored` reads it.
pub fn wallet_chain_tip(wallet: std::sync::Arc<crate::wallet::Wallet>) -> ChainTip {
    std::sync::Arc::new(move || {
        let h = wallet.get_block_height().ok()?;
        let hash = wallet.get_block_hash().ok()?;
        (h != 0).then_some((h, hash))
    })
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
    /// handler's `apply_updates_to_ledger` (joined-ledger relay gap-fill,
    /// driven by `main_loop::reimport_joined_ledger`) may race with us;
    /// both are sync, hold the ledger write lock atomically, and recheck
    /// chain continuity under it, so whichever gets the lock first wins
    /// and the other backs off (Err / dedup no-op).
    fn apply_inbound(&mut self, update: deposits_core::types::SignedLedgerUpdate) {
        use deposits_core::messages::LedgerOperation;
        use deposits_core::tlv::TlvDecode;

        // Take the write lock for the whole apply path (no awaits
        // inside this function) so the checks and the mutation see a
        // consistent view.
        let mut ledger = self.ledger.write().unwrap();

        // A ledger already in dispute doesn't accept further main-chain
        // updates — recovery flows on the fork branch (different
        // operator_id) own the chain from here. The fork-branch filter
        // below routes those correctly; this guard catches the rare
        // case of a same-operator update arriving after dispute_state
        // moved.
        if ledger.state.dispute_state != deposits_core::types::DisputeState::Normal {
            return;
        }

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
                // Only an update the operator actually signed is evidence of
                // equivocation. Anyone can publish bytes under this ledger's tag
                // (a relabelled or altered copy fails the v2 signature), and
                // calling those "equivocation" sent us chasing a non-event.
                if update.verify_operator_signature().is_ok() {
                    tracing::warn!(
                        "LedgerActor[{}…] equivocation at seq {}: existing content {} vs new {}",
                        &self.ledger_id[..16.min(self.ledger_id.len())],
                        update.sequence_number,
                        hex::encode(&existing.content_hash[..8]),
                        hex::encode(&update.content_hash[..8])
                    );
                } else {
                    tracing::debug!(
                        "LedgerActor[{}…] dropping an update at seq {} whose operator signature does not verify",
                        &self.ledger_id[..16.min(self.ledger_id.len())],
                        update.sequence_number
                    );
                }
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
        // `apply_and_check` runs the state-machine + conformance
        // verifier (witness, reserve sufficiency, preimage match for
        // OnchainFulfill, etc.). Conformance violations are logged
        // and reported but don't abort the apply — they're the
        // dispute-trigger signal the watcher path needs to see.
        // The inbound update's `block_height` is the cosigned operator
        // view at the moment it was committed; use it as the chain_tip
        // for descriptor `after()` checks. Matches the on-chain
        // perspective that `apply_and_check` is replaying.
        // DEP-02 §Block height and hash: a height below its predecessor's, or no block.
        if let Some(v) = deposits_core::fraud::header_violation(
            ledger.history.last(),
            &update,
            deposits_core::fraud::signed_header_applies(Some(&ledger.state), &update),
        ) {
            tracing::warn!(
                ledger_id = %self.ledger_id,
                seq = update.sequence_number,
                "Header violation on inbound apply: {}",
                v
            );
            self.handler
                .note_non_conforming(&self.ledger_id, update.sequence_number);
        }
        match ledger.apply_and_check_at(
            &op,
            update.block_height,
            update.block_height,
            update.sequence_number,
        ) {
            Ok(violations) if !violations.is_empty() => {
                tracing::warn!(
                    ledger_id = %self.ledger_id,
                    seq = update.sequence_number,
                    "Conformance violations on inbound apply: {:?}",
                    violations
                );
                // The replica still applies it (and so follows the chain past
                // it); record where it went wrong so a dispute forks before
                // it, not at our tip. Only violations the signed evidence
                // proves (under v2 signing, all of them; see
                // `proves_non_conformance`).
                if violations
                    .iter()
                    .any(deposits_core::fraud::proves_non_conformance)
                {
                    self.handler
                        .note_non_conforming(&self.ledger_id, update.sequence_number);
                }
            }
            Err(e) => {
                tracing::warn!(
                    "LedgerActor[{}…] apply_and_check failed at seq {}: {}",
                    &self.ledger_id[..16.min(self.ledger_id.len())],
                    update.sequence_number,
                    e
                );
                return;
            }
            _ => {}
        }
        // The post-hook a replay runs (LedgerState::apply_update_in_place): without it a
        // replica's state differs from a replay of its own chain after every QuorumBegin.
        if matches!(op, LedgerOperation::QuorumBegin { .. }) {
            ledger.state.note_quorum_begin(
                update.block_height,
                update.sequence_number,
                update.content_hash,
            );
        }
        ledger.state.sequence = update.sequence_number;
        ledger.state.chain_tip_hash = update.chain_hash();
        ledger.history.push(update.clone());
        // Every CHECKPOINT_EVERY updates: replay the segment since the previous checkpoint and
        // compare it with the live state (Ledger::verify_checkpoint).
        let checkpoint = ledger.verify_checkpoint(deposits_core::ledger::CHECKPOINT_EVERY);
        let checkpoint_to_save = match &checkpoint {
            deposits_core::ledger::CheckpointOutcome::Taken
            | deposits_core::ledger::CheckpointOutcome::Mismatch
            | deposits_core::ledger::CheckpointOutcome::Bootstrapped(_) => {
                ledger.verified_checkpoint.clone()
            }
            _ => None,
        };
        // Drop the write lock before doing disk I/O: persist_ledger_to_disk
        // takes its own read lock through the same Arc.
        drop(ledger);
        self.handler
            .note_checkpoint(&self.ledger_id, &checkpoint, checkpoint_to_save.as_ref());

        // Wake any cosign dispatchers waiting for state to catch up to
        // this seq. notify_waiters fires once for every pending waiter;
        // newly-arrived waiters that missed this notification re-check
        // the seq immediately on next entry to their wait loop.
        self.apply_wakeup.notify_waiters();

        // Persist the authoritative `<id>.jsonl` to disk. This is what
        // the handler's load_ledgers_from_jsonl reads on next start;
        // missing the write would leave the on-disk view behind the
        // in-memory chain.
        if let Err(e) = self.handler.persist_ledger_to_disk(&self.ledger_id) {
            tracing::warn!(
                "LedgerActor[{}…] persist_ledger_to_disk seq {} failed: {}",
                &self.ledger_id[..16.min(self.ledger_id.len())],
                update.sequence_number,
                e
            );
        }
    }

    /// Observe a fork-branch update (operator_id != parent_pubkey).
    /// Fork-branch ledgers are stored separately under compound keys
    /// in `handler.ledgers`; the disputant who authors them is the
    /// single writer. The main-chain actor's responsibility on a
    /// fork-branch observation is just the apply-edge confiscation
    /// trigger: when any DisputeArmed lands on a fork, wake `Node`
    /// to check whether confiscation is ready, instead of waiting
    /// for the next periodic.
    fn handle_fork_branch_update(&mut self, update: &deposits_core::types::SignedLedgerUpdate) {
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
        tier_floor: Option<(Vec<bitcoin::secp256k1::XOnlyPublicKey>, usize)>,
    ) -> Result<CommitResult, String> {
        use bitcoin::hashes::{sha256, Hash};

        // 1+2. Stage, then cosign. A draft that falls behind the cosigners' window before its
        //      cosignatures are in comes back `CosignFailure::Stale` and is RE-STAGED at our
        //      tip, whole (balance commitments, conformance, tier), and asked for again, at most
        //      `MAX_RESTAGES` times. It is unsigned (step 3 signs), so re-dating it signs nothing
        //      twice; `write_ahead::check_restampable` checks that rather than assuming it.
        //      (cosign_restage: regtest 1121-101522, a post-expiry rotation lost to a draft every
        //      retry resent at the same stale height.)
        let operation_in = operation;
        let (mut block_height, mut block_hash) = (block_height, block_hash);
        let mut restages = 0usize;
        let mut staged = loop {
            // Take the read lock briefly and release it before any .await so the cosig round
            // doesn't block readers.
            let (mut staged, quorum_active, members) = {
                let ledger = self.ledger.read().unwrap();
                // Fill DEP-02 balance commitments before staging so the
                // operator declares the post-op (balance, locked_balance) it
                // computes; cosigners recompute and compare (verify-when-present,
                // intrinsic to every ruleset). Safe unconditionally per DEP-18.
                let operation = ledger
                    .state
                    .fill_balance_commitments_at(operation_in.clone(), block_height);
                // Speculative-apply conformance during stage uses the same
                // chain_tip the StagedUpdate carries — so descriptor
                // `after(N)` checks on the operator side match what
                // cosigners will see when they re-run conformance.
                let staged = ledger
                    .stage_operation(operation, block_height, block_hash)
                    .map_err(|e| format!("stage failed: {}", e))?;
                let quorum_active = ledger.state.quorum_state == deposits_core::QuorumState::Active;
                let members: Vec<PublicKey> = ledger
                    .state
                    .quorum_members
                    .iter()
                    .map(|m| m.pubkey)
                    .collect();
                (staged, quorum_active, members)
            };

            // Cosign — required when the quorum is active OR when
            // this is the very first QuorumBegin (which transitions
            // the state machine PreQuorum -> Active and so needs
            // member attestation even though state is still PreQuorum
            // at stage time).
            let is_first_quorum_begin =
                !quorum_active && matches!(&staged.operation, LedgerOperation::QuorumBegin { .. });
            if !(quorum_active || is_first_quorum_begin) {
                break staged;
            }
            let threshold = (members.len() / 2 + 1)
                .max(tier_floor.as_ref().map(|(_, n)| *n).unwrap_or(0));
            let (tx, rx) = oneshot::channel();
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
            match rx.await.map_err(|_| "RequestCosig reply dropped".to_string())? {
                Ok(entries) => {
                    let mut sorted = entries;
                    sorted.sort_by(|a, b| {
                        a.cosigner_pubkey
                            .serialize()
                            .cmp(&b.cosigner_pubkey.serialize())
                    });
                    staged.update.cosignatures = sorted;
                    staged.update.content_hash = staged.update.compute_hash();
                    break staged;
                }
                Err(super::cosign_restage::CosignFailure::Stale { draft_height, current_height, reason })
                    if restages < super::cosign_restage::MAX_RESTAGES =>
                {
                    {
                        let ledger = self.ledger.read().unwrap();
                        super::write_ahead::check_restampable(
                            &self.handler.data_dir,
                            &self.ledger_id,
                            &ledger.history,
                            &staged.update,
                        )?;
                    }
                    let (h, hash) = match (self.chain_tip)() {
                        Some((h, hash)) if h > draft_height => (h, hash),
                        other => {
                            return Err(format!(
                                "{} (our chain tip {:?} gives no later height to re-stage at)",
                                super::cosign_restage::CosignFailure::Stale { draft_height, current_height, reason },
                                other.map(|(h, _)| h)
                            ))
                        }
                    };
                    tracing::warn!(
                        "LedgerActor[{}…] re-staging seq {}: drafted at block_height {}, our tip is {} ({}); \
                         the draft is unsigned, so it is re-dated rather than resent",
                        &self.ledger_id[..16.min(self.ledger_id.len())],
                        staged.update.sequence_number,
                        draft_height,
                        h,
                        reason
                    );
                    restages += 1;
                    block_height = h;
                    block_hash = hash;
                }
                Err(e) => return Err(e.to_string()),
            }
        };
        // DEP-06: a rotating QuorumBegin answers a challenge of its rungs only at the spent tier's
        // floor; below it nothing is recorded (signet C, 2026-11-16). Mirrors cl-deposits'
        // APPEND-OPERATION :tier-floor.
        if let Some((keys, need)) = &tier_floor {
            let have = deposits_core::vault_spend::tier_cosignatures(&staged.update, keys);
            if have < *need {
                return Err(format!(
                    "QuorumBegin: {have} of the {need} cosignatures by the spent vault's tier that \
                     answer its rungs (DEP-06); not recording a rotation no judge could answer"
                ));
            }
        }

        // 3. Operator-sign. Uses the DEP-02 v2 operator digest
        //    (see `SignedLedgerUpdate::operator_digest`). Routed
        //    through the Signer so RemoteSigner / anti-equivocation
        //    policy can intercept.
        {
            use deposits_signer_api::SignContext;
            let digest = staged.update.operator_digest();
            let ledger_id_bytes = self.ledger.read().unwrap().ledger_id();
            let ctx = SignContext::operator_update(ledger_id_bytes, staged.update.sequence_number);
            staged.update.operator_signature = self
                .signer
                .bip340_sign(&ctx, &digest)
                .map_err(|e| format!("operator sign failed: {}", e))?;
        }

        // 4. Apply on the shared ledger. `self.ledger` is the same
        //    `Arc<RwLock<Ledger>>` `handler.ledgers` holds, so
        //    `commit_staged` here is the authoritative write that
        //    every reader sees. Take the write lock briefly and drop
        //    before any subsequent .await.
        let update_for_return = staged.update.clone();
        {
            let mut ledger = self.ledger.write().unwrap();
            ledger
                .commit_staged(staged)
                .map_err(|e| format!("commit_staged failed: {}", e))?;
        }
        // Wake any cosign dispatchers waiting for this seq (symmetric
        // with the inbound apply path above).
        self.apply_wakeup.notify_waiters();

        // 5. WRITE-AHEAD (node::write_ahead): the pending file, then the authoritative
        //    `<id>.jsonl`, durable before the broadcast. A failure is an error and the update
        //    is never published: published-but-not-saved is what let a retry sign a second
        //    update at this sequence.
        let sync = super::write_ahead::fsync_operator_updates();
        let pending = super::write_ahead::write_pending(
            &self.handler.data_dir,
            &self.ledger_id,
            &update_for_return,
            sync,
        )
        .and_then(|p| self.handler.persist_ledger_durable(&self.ledger_id, sync).map(|_| p))
        .map_err(|e| {
            format!(
                "LedgerActor[{}…] seq {} not persisted ({}); not publishing it",
                &self.ledger_id[..16.min(self.ledger_id.len())],
                update_for_return.sequence_number,
                e
            )
        })?;

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
        let sent = brx
            .await
            .map_err(|_| "Broadcast reply dropped".to_string())?;
        // Sent: the pending file has done its job. Not sent: it stays, and the next pass (or
        // start) publishes these bytes.
        if sent.is_ok() {
            let _ = std::fs::remove_file(&pending);
        }
        let event_id = sent.unwrap_or_default();

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
                    tier_floor,
                    reply,
                } => {
                    let res = self
                        .handle_commit(operation, block_height, block_hash, tier_floor)
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
