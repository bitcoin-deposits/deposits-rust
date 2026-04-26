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

    /// Stub run loop for Step 2 — drains the inbox and logs each event
    /// type. Real behavior moves in at Step 3 (Inbound), Step 4
    /// (LocalCommit, Cosign).
    pub async fn run(mut self) {
        tracing::info!(
            "LedgerActor[{}…] starting (stub run loop)",
            &self.ledger_id[..16.min(self.ledger_id.len())]
        );
        while let Some(event) = self.inbox.recv().await {
            match event {
                LedgerEvent::Inbound(_) => {
                    tracing::debug!(
                        "LedgerActor[{}…] received Inbound (stub: dropped)",
                        &self.ledger_id[..16.min(self.ledger_id.len())]
                    );
                }
                LedgerEvent::Cosign { reply, .. } => {
                    // Step 2: refuse to cosign — keeps existing daemon
                    // path authoritative until step 4.
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
