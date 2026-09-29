// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Handler implementation for deposits-node
//!
//! Implements `HandlerContext` from deposits-core using BDK wallet and Nostr transport.

use bitcoin::secp256k1::{PublicKey, SecretKey};
use deposits_core::error::HandlerError;
use deposits_core::event_store::EventStore;
use deposits_core::ledger::Ledger;
use deposits_core::ledger::LedgerRole;
use deposits_core::message_validation::ProtocolEvent;
use deposits_core::message_validation::{HandlerContext, ValidationContext};
use deposits_core::messages::DepositsMessage;
use deposits_core::types::{LedgerState, SignedLedgerUpdate};
use deposits_core::validation::{LedgerConformanceValidator, LedgerExport, ValidationReport};
use deposits_signer_api::{SignContext, Signer};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use tokio::sync::mpsc;

use crate::metrics;
use crate::wallet::Wallet;
use crate::Error;

/// Outbound message to be sent via Nostr
#[derive(Debug)]
pub struct OutboundMessage {
    pub peer: PublicKey,
    pub message: DepositsMessage,
}

/// Serializable ledger entry for persistence (legacy format)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
struct LedgerEntry {
    ledger_id: String,
    ledger: Ledger,
}

/// JSONL row for append-only ledger log format
/// - First line: Role variant (LedgerRole)
/// - Second line: State variant (current LedgerState)
/// - Subsequent lines: Update variant (each SignedLedgerUpdate)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
enum LedgerLogRow {
    Role {
        role: LedgerRole,
    },
    State(LedgerState),
    Update(SignedLedgerUpdate),
    /// Nostr `created_at` (unix-seconds) for the update whose `content_hash`
    /// (hex) is given. Lets a re-broadcast after restart reuse the original
    /// timestamp so the event id is stable and relays dedupe. Last-wins on
    /// load; written incrementally on record and snapshotted on compaction.
    /// Older binaries skip this unknown row (parse error → warn+continue).
    CreatedAt {
        content_hash: String,
        ts: u64,
    },
}

/// Request to persist ledgers (sent from handler to persistence thread)
#[derive(Debug, Clone)]
enum PersistRequest {
    /// Request to save all ledgers to disk
    SaveAll,
    /// Request to save a specific ledger
    SaveOne(String),
    /// Request to shut down persistence thread
    Shutdown,
}

/// The main handler for deposits-node
///
/// This implements `HandlerContext` to enable all core protocol logic.
pub struct DepositsHandler {
    /// Our node's public key (derived from Nostr keypair)
    our_node_id: PublicKey,

    /// Signer abstraction. `LocalSigner` today; `RemoteSigner` in v1.
    /// All operator-protocol signing flows through this — the daemon does
    /// not retain the operator secret as a separate field.
    pub(crate) signer: Arc<dyn Signer>,

    /// Shared secp256k1 context
    pub secp: bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>,

    /// Ledgers indexed by ledger_id (the unique hash identifier)
    pub ledgers: Mutex<HashMap<String, Arc<RwLock<Ledger>>>>,

    /// Pending events to be processed
    events: Mutex<Vec<ProtocolEvent>>,

    /// Outbound message queue (for async sending)
    outbound_tx: mpsc::UnboundedSender<OutboundMessage>,

    /// BDK wallet for on-chain operations
    wallet: Arc<Wallet>,

    /// Data directory for persistence
    data_dir: PathBuf,

    /// Enable periodic deposit metrics emission (every 60 seconds)
    /// Controlled by DEPOSITS_ENABLE_METRICS_EMITTER env var
    enable_metrics_emitter: bool,

    /// Per ledger, the sequence of the first update not yet written to its
    /// JSONL (absent: the file has not been written this session, so the next
    /// persist writes it whole). A SEQUENCE, not an index into the in-memory
    /// `history`: the old index cursor was re-based by compaction and
    /// overwritten by a persist that straddled one, and each of those counted
    /// updates as written that never were (see `compact_ledger`). Only ever
    /// raised, by the persist that wrote the updates below it.
    persisted_next_seq: Mutex<HashMap<String, u64>>,

    /// One persist at a time per ledger: two appends to the same file must
    /// not interleave their rows, nor an append race a full rewrite.
    persist_locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,

    /// Ledgers whose JSONL skips sequences, with the missing ones, found at
    /// load (see [`sequence_gaps`]). A replica replayed across a hole folds
    /// into wrong balances; `Node` repairs these from the relay at startup
    /// and does not judge (dispute) one it could not repair.
    damaged_ledgers: Mutex<HashMap<String, Vec<SequenceGap>>>,

    /// Per joined ledger, the lowest sequence whose operator update this
    /// replica flagged as non-conforming when applying it (the replica still
    /// applies it and follows the chain, so its tip can be past the fault).
    /// See [`Handler::first_non_conforming`].
    flagged_non_conforming: Mutex<HashMap<String, u64>>,

    /// Per ledger, the first non-conforming update found by scanning the
    /// history once (`find_non_conforming_update`), which covers what was
    /// applied before this process started (the JSONL loader applies without
    /// judging).
    scanned_non_conforming: Mutex<HashMap<String, Option<u64>>>,

    /// Tracks last-seen modification times for ledger JSONL files.
    /// Used to avoid re-parsing files that haven't changed.
    last_file_modtimes: Mutex<HashMap<String, std::time::SystemTime>>,

    /// Tracks appends since last compaction per ledger.
    /// Used to decide when to write a State line (every 100 appends)
    /// and when to do a full file rewrite (every 1000 appends).
    appends_since_compaction: Mutex<HashMap<String, usize>>,

    /// Content-addressed event store for ledger sync.
    /// Events are indexed by content_hash with memoized validation.
    pub event_store: Mutex<EventStore>,
}

/// A run of sequences a ledger's JSONL skips: `first..=last` are missing
/// between two updates it holds. The neighbours' hashes pin what belongs
/// there: the run must chain from `after` (the `chain_hash` of `first - 1`)
/// to `before` (the `previous_hash` of `last + 1`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SequenceGap {
    pub first: u64,
    pub last: u64,
    pub after: [u8; 32],
    pub before: [u8; 32],
    /// Operator of the update before the run: who must have signed it.
    pub operator: PublicKey,
}

/// The runs of sequences missing from `history` (sorted by sequence, one
/// update per sequence, as the loader leaves it) between its first and last.
pub(crate) fn sequence_gaps(history: &[SignedLedgerUpdate]) -> Vec<SequenceGap> {
    history
        .windows(2)
        .filter(|w| w[1].sequence_number > w[0].sequence_number + 1)
        .map(|w| SequenceGap {
            first: w[0].sequence_number + 1,
            last: w[1].sequence_number - 1,
            after: w[0].chain_hash(),
            before: w[1].previous_hash,
            operator: w[0].operator_id,
        })
        .collect()
}

/// `gaps` as a short list for a log line: "53330, 60353" or "121035-122035".
pub(crate) fn describe_gaps(gaps: &[SequenceGap]) -> String {
    let mut parts: Vec<String> = gaps
        .iter()
        .take(12)
        .map(|g| {
            if g.first == g.last {
                g.first.to_string()
            } else {
                format!("{}-{}", g.first, g.last)
            }
        })
        .collect();
    if gaps.len() > 12 {
        parts.push(format!("… ({} runs)", gaps.len()));
    }
    parts.join(", ")
}

/// One append persist, between reading what to write and recording it written.
struct PersistAppend {
    history_len: usize,
    updates: Vec<SignedLedgerUpdate>,
    state: Option<LedgerState>,
}

impl DepositsHandler {
    /// Create a new handler
    ///
    /// Returns the handler and a receiver for outbound messages that should
    /// be sent via Nostr transport asynchronously.
    pub fn new(
        signer: Arc<dyn Signer>,
        wallet: Arc<Wallet>,
        data_dir: PathBuf,
        enable_metrics_emitter: bool,
    ) -> (Self, mpsc::UnboundedReceiver<OutboundMessage>) {
        use bitcoin::secp256k1::Secp256k1;
        let secp = Secp256k1::new();
        let our_node_id = signer.pubkey();

        let (outbound_tx, outbound_rx) = mpsc::unbounded_channel();

        // Load existing ledgers from disk. `load_single_ledger_from_jsonl`
        // reads the FULL append-only JSONL (the durable log holds the whole
        // chain — genesis, QuorumBegin, everything), so `ledger.history` here
        // is the complete chain, potentially larger than the in-memory cap. We
        // populate the event store from that full history first, THEN apply the
        // RAM cap (below) so the daemon comes back up in the same steady state
        // it maintains after a compaction: full chain on disk, capped in RAM.
        let ledgers = Self::load_ledgers_from_disk(&data_dir);

        // Populate event store from the FULL loaded history (before capping RAM)
        // so the resync/heal live cache holds every event up to the store's own
        // FIFO cap, not just the retained in-memory tail.
        let max_events: usize = std::env::var("DEPOSITS_EVENT_STORE_MAX")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(50_000);
        let event_store = {
            let mut store = EventStore::with_max_events(max_events);
            tracing::info!(
                "Event store max capacity: {}",
                if max_events == 0 {
                    "unlimited".to_string()
                } else {
                    max_events.to_string()
                }
            );
            for arc in ledgers.values() {
                let ledger = arc.read().unwrap();
                for update in &ledger.history {
                    store.insert(update.clone());
                }
                // Restore the persisted Nostr created_at so a re-broadcast
                // after this restart reuses the original timestamp (stable
                // event id → relay dedupe) instead of minting a fresh now().
                for (hash, ts) in &ledger.created_at {
                    store.record_created_at(hash, *ts);
                }
            }
            if !store.is_empty() {
                tracing::info!(
                    "Event store initialized: {} events, {} unknown",
                    store.len(),
                    store.unknown_count(),
                );
            }
            Mutex::new(store)
        };

        // Apply the in-memory cap to each freshly-loaded ledger, and start the
        // append cursor past the loaded tip: everything loaded came from the
        // file, so it is all written. Capping here (rather than waiting for
        // the next compaction) re-establishes the durable-disk / capped-RAM
        // invariant immediately on restart.
        let damaged_ledgers = Mutex::new(Self::find_damaged_ledgers(&ledgers));
        let retain = Self::history_retain();
        let persisted_next_seq = {
            let mut next = HashMap::new();
            for (id, arc) in &ledgers {
                Self::truncate_history(arc, retain);
                next.insert(id.clone(), Self::next_seq_after(&arc.read().unwrap().history));
            }
            Mutex::new(next)
        };

        let handler = Self {
            our_node_id,
            signer,
            secp,
            ledgers: Mutex::new(ledgers),
            events: Mutex::new(Vec::new()),
            outbound_tx,
            wallet,
            data_dir,
            enable_metrics_emitter,
            persisted_next_seq,
            persist_locks: Mutex::new(HashMap::new()),
            damaged_ledgers,
            flagged_non_conforming: Mutex::new(HashMap::new()),
            scanned_non_conforming: Mutex::new(HashMap::new()),
            last_file_modtimes: Mutex::new(HashMap::new()),
            appends_since_compaction: Mutex::new(HashMap::new()),
            event_store,
        };

        (handler, outbound_rx)
    }

    /// Build a tracking key for a dispute fork.
    ///
    /// Format: `{ledger_id}_{fork_seq:06}_{operator_prefix_16hex}`
    /// where `fork_seq` is the last valid sequence (divergence point)
    /// and `operator_prefix` is the first 16 hex chars of the fork operator's pubkey.
    pub fn fork_tracking_key(
        ledger_id: &str,
        fork_seq: u64,
        operator_pubkey: &PublicKey,
    ) -> String {
        format!(
            "{}_{:06}_{}",
            ledger_id,
            fork_seq,
            &hex::encode(operator_pubkey.serialize())[..16]
        )
    }

    /// Find our dispute fork for a given ledger_id (if any).
    ///
    /// Returns the compound tracking key if we have a fork entry for this ledger.
    pub fn find_our_fork(&self, ledger_id: &str) -> Option<String> {
        let ledgers = self.ledgers.lock().unwrap();
        ledgers
            .keys()
            .find(|k| k.starts_with(ledger_id) && k.len() > ledger_id.len())
            .cloned()
    }

    /// After winning a confiscation lottery, make the resolved dispute fork the
    /// daemon's authoritative copy of the BASE ledger so we actually operate it
    /// as the new custodian.
    ///
    /// A winning cosigner holds two entries for the same on-chain ledger: the
    /// stale JOINED base entry (`ledger_id`, still keyed to the fraudulent
    /// operator) and the resolved FORK entry (`<ledger_id>_<seq>_<pk16>`, whose
    /// `DisputeAcquire` rotated `operator_key` to us and cleared the dispute).
    /// Deposit-open requests resolve by BASE `ledger_id`, so without this the
    /// daemon would keep serving `wallet open` off the stale entry (old
    /// operator, disputed) and the recovered ledger stays unserviceable.
    ///
    /// Promote by pointing the base key at the fork's `Arc<RwLock<Ledger>>`
    /// (same allocation, so a later actor + our own catch-up all see one
    /// state), persist under the base filename, and return `true`. The caller
    /// must `ensure_actor_for(ledger_id)` afterward so the base ledger has a
    /// writer. Idempotent: returns `false` if there's no eligible fork or the
    /// base entry already reflects us as operator.
    pub fn promote_dispute_fork_to_base(&self, ledger_id: &str) -> Result<bool, String> {
        let our_id = self.our_node_id;

        // Find our resolved fork: same base id, operator rotated to us,
        // dispute cleared to Normal, and role Operator (it's the authoritative
        // custody copy we built + signed).
        let fork_key = {
            let ledgers = self.ledgers.lock().unwrap();
            ledgers
                .keys()
                .filter(|k| k.starts_with(ledger_id) && k.len() > ledger_id.len())
                .find(|k| {
                    ledgers
                        .get(*k)
                        .map(|arc| {
                            let l = arc.read().unwrap();
                            l.state.operator_key == our_id
                                && l.state.dispute_state
                                    == deposits_core::types::DisputeState::Normal
                                && l.role == deposits_core::ledger::LedgerRole::Operator
                        })
                        .unwrap_or(false)
                })
                .cloned()
        };

        let Some(fork_key) = fork_key else {
            return Ok(false);
        };

        // Adopt the resolved fork as the base ledger. We must NOT early-return
        // merely because the base's `operator_key` is already us: a joined-member
        // base copy can converge to us as operator via `reimport_joined_ledger`
        // (which applies the winning fork's DisputeAcquire) yet keep
        // `role = Partner` AND a stale sequence cursor / truncated history — so
        // committing a fresh op picks an already-taken sequence and the quorum
        // refuses it as an equivocation. The fork copy has the clean, consistent
        // operator state, so adopt it.
        //
        // Copy the fork's role+state+history IN PLACE into the EXISTING base
        // `Arc<RwLock<Ledger>>` rather than swapping the map entry to a new Arc.
        // The base's live `LedgerActor` (the single writer) and every reader
        // hold clones of that specific Arc; swapping the map entry would leave
        // the actor writing a now-orphaned allocation (stale sequence), which is
        // exactly what produced the seq-collision on the first fresh open. An
        // in-place overwrite keeps the actor bound to the one shared allocation
        // that now carries the resolved custody state.
        {
            let ledgers = self.ledgers.lock().unwrap();
            let Some(fork_arc) = ledgers.get(&fork_key).cloned() else {
                return Ok(false);
            };
            match ledgers.get(ledger_id) {
                Some(base_arc) if !Arc::ptr_eq(base_arc, &fork_arc) => {
                    let base_arc = base_arc.clone();
                    let resolved = fork_arc.read().unwrap().clone();
                    // Idempotency guard: if the base already reflects the fork's
                    // resolved tip under us as Operator, nothing to do.
                    {
                        let b = base_arc.read().unwrap();
                        if b.role == deposits_core::ledger::LedgerRole::Operator
                            && b.state.operator_key == our_id
                            && b.next_sequence() == resolved.next_sequence()
                        {
                            return Ok(false);
                        }
                    }
                    *base_arc.write().unwrap() = resolved;
                }
                Some(_) => return Ok(false), // base IS the fork Arc — already promoted
                None => {
                    // No base entry yet — register the fork Arc under the base key.
                    drop(ledgers);
                    self.ledgers
                        .lock()
                        .unwrap()
                        .insert(ledger_id.to_string(), fork_arc);
                }
            }
        }

        // Force a FULL rewrite of the base JSONL. `persist_ledger_to_disk` is
        // append-only and only re-emits the State/Role lines every ~100
        // appends — but we just replaced the base's entire ledger (new Role,
        // new State, a different history tail), so an append would leave the
        // stale joined-copy State/Role on disk and the next daemon start would
        // reload the pre-promotion ledger. Reset the append cursor so the
        // persist does a clean rewrite from the promoted ledger.
        self.forget_persisted(ledger_id);
        self.persist_ledger_to_disk(ledger_id)?;
        tracing::info!(
            "Promoted resolved dispute fork {} to operate base ledger {} as new custodian",
            &fork_key[..32.min(fork_key.len())],
            &ledger_id[..16.min(ledger_id.len())],
        );
        Ok(true)
    }

    /// Find the original (non-fork) entry for a ledger_id.
    pub fn find_original(&self, ledger_id: &str) -> Option<String> {
        let ledgers = self.ledgers.lock().unwrap();
        if ledgers.contains_key(ledger_id) {
            Some(ledger_id.to_string())
        } else {
            None
        }
    }

    /// Emit deposit balance metrics for monitoring
    ///
    /// Computes and emits the following metrics:
    /// - Total reserves balance across all ledgers (satoshis)
    /// - Total deposit balance under management (satoshis)
    /// - Per-ledger balance (satoshis)
    pub fn emit_deposit_metrics(&self) {
        let mut reserves_total: u64 = 0;
        let mut deposits_total: u64 = 0;

        let ledgers = self.ledgers.lock().unwrap();

        for (ledger_id, ledger_arc) in ledgers.iter() {
            let ledger = ledger_arc.read().unwrap();

            // Get reserves amount from the ledger state (in millisatoshis)
            let reserves_msats = ledger.state.reserves_amount;
            // Convert to satoshis for display (divide by 1000)
            let reserves_sats = reserves_msats / 1000;
            reserves_total += reserves_sats; // reserves_total is in sats for display

            // Get deposits amount from the ledger state (HashMap<DepositId, Deposit>)
            let deposits_msats = ledger
                .state
                .deposits
                .values()
                .map(|d| d.balance)
                .sum::<u64>();
            // Convert to satoshis (divide by 1000)
            let deposits_sats = deposits_msats / 1000;
            deposits_total += deposits_sats;

            // Emit per-ledger balance metric
            let ledger_total = reserves_sats + deposits_sats;
            metrics::set_ledger_deposit_balance_sats(ledger_id, ledger_total);

            // Emit per-deposit balances
            for (deposit_id, deposit) in ledger.state.deposits.iter() {
                let deposit_id_str = hex::encode(deposit_id);
                let deposit_sats = deposit.balance / 1000;
                metrics::set_deposit_balance_sats(&deposit_id_str, deposit_sats);
            }
        }

        // Emit totals
        metrics::set_reserves_balance_sats(reserves_total);
        metrics::set_total_deposit_balance_sats(deposits_total);

        tracing::debug!(
            "Deposit metrics: reserves={} sats, deposits={} sats",
            reserves_total,
            deposits_total
        );
    }

    /// Start periodic deposit metrics emission (every 60 seconds)
    ///
    /// Only runs if `DEPOSITS_ENABLE_METRICS_EMITTER=1` is set.
    /// This is a background thread that emits metrics without blocking.
    pub fn start_metrics_emitter(self: &Arc<Self>) {
        if !self.enable_metrics_emitter {
            tracing::debug!("Deposit metrics emitter is disabled");
            return;
        }

        tracing::info!("Starting deposit metrics emitter (every 60s)");

        let handler = self.clone();

        std::thread::spawn(move || {
            loop {
                std::thread::sleep(std::time::Duration::from_secs(60));

                // Emit metrics
                handler.emit_deposit_metrics();
            }
        });
    }

    /// Save all ledgers to disk (full rewrite / compaction).
    /// Takes a snapshot under the mutex (fast), then writes synchronously.
    /// Records each ledger written through its snapshot's tip.
    fn save_ledgers_to_disk(&self) -> Result<(), String> {
        // Take a snapshot while holding the mutex (fast - just clones the data)
        let ledgers_snapshot = {
            let ledgers = self.ledgers.lock().unwrap();
            ledgers
                .iter()
                .map(|(id, arc)| {
                    let ledger = arc.read().unwrap();
                    (id.clone(), ledger.clone())
                })
                .collect::<Vec<_>>()
        };

        // Perform disk I/O synchronously after releasing the mutex.
        // This ensures the data is on disk before returning, which is critical
        // for CLI processes (the caller must not exit before the write completes).
        Self::save_ledgers_to_disk_impl(&ledgers_snapshot, &self.data_dir);

        // Record what we just wrote: each snapshot through its tip.
        let mut next = self.persisted_next_seq.lock().unwrap();
        let mut compaction = self.appends_since_compaction.lock().unwrap();
        for (id, ledger) in &ledgers_snapshot {
            next.insert(id.clone(), Self::next_seq_after(&ledger.history));
            compaction.insert(id.clone(), 0);
        }

        // Update modtimes so discover_new_ledgers() doesn't re-read our own writes
        let ledgers_dir = self.data_dir.join("ledgers");
        let mut modtimes = self.last_file_modtimes.lock().unwrap();
        for (id, _) in &ledgers_snapshot {
            let path = ledgers_dir.join(format!("{}.jsonl", id));
            if let Ok(mtime) = path.metadata().and_then(|m| m.modified()) {
                modtimes.insert(id.clone(), mtime);
            }
        }

        Ok(())
    }

    /// Implementation of save_ledgers_to_disk (full rewrite / compaction)
    fn save_ledgers_to_disk_impl(ledgers: &[(String, Ledger)], data_dir: &PathBuf) {
        // Ensure data directory exists
        if !data_dir.exists() {
            if let Err(e) = fs::create_dir_all(data_dir) {
                tracing::error!("Failed to create data dir: {}", e);
                return;
            }
        }

        // Create ledgers subdirectory for JSONL files
        let ledgers_dir = data_dir.join("ledgers");
        if !ledgers_dir.exists() {
            if let Err(e) = fs::create_dir_all(&ledgers_dir) {
                tracing::error!("Failed to create ledgers dir: {}", e);
                return;
            }
        }

        let mut saved_count = 0;

        for (ledger_id, ledger) in ledgers.iter() {
            // Serialize to JSONL: first line is role, second is state, rest are updates
            let mut lines = Vec::with_capacity(2 + ledger.history.len());

            // First line: role
            let role_row = LedgerLogRow::Role { role: ledger.role };
            if let Ok(line) = serde_json::to_string(&role_row) {
                lines.push(line);
            }

            // Second line: current state
            let state_row = LedgerLogRow::State(ledger.state.clone());
            if let Ok(line) = serde_json::to_string(&state_row) {
                lines.push(line);
            }

            // Subsequent lines: each update
            for update in &ledger.history {
                let update_row = LedgerLogRow::Update(update.clone());
                if let Ok(line) = serde_json::to_string(&update_row) {
                    lines.push(line);
                }
            }

            // Write to file
            let ledger_file = ledgers_dir.join(format!("{}.jsonl", ledger_id));
            let contents = lines.join("\n");
            if let Err(e) = fs::write(&ledger_file, contents) {
                tracing::error!("Failed to write ledger file {}: {}", ledger_id, e);
                continue;
            }

            saved_count += 1;
        }

        if saved_count > 0 {
            tracing::debug!("Persisted {} ledgers", saved_count);
        }
    }

    /// Load ledgers from disk (supports both legacy JSON and new JSONL format)
    fn load_ledgers_from_disk(data_dir: &PathBuf) -> HashMap<String, Arc<RwLock<Ledger>>> {
        // First, check for new JSONL format directory
        let ledgers_dir = data_dir.join("ledgers");

        if ledgers_dir.exists() && ledgers_dir.is_dir() {
            // Load from new JSONL format
            return Self::load_ledgers_from_jsonl(&ledgers_dir);
        }

        // Fall back to legacy JSON format
        let ledgers_file = data_dir.join("ledgers.json");
        if !ledgers_file.exists() {
            return HashMap::new();
        }

        let contents = match fs::read_to_string(&ledgers_file) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("Failed to read ledgers file: {}", e);
                return HashMap::new();
            }
        };

        let entries: Vec<LedgerEntry> = match serde_json::from_str(&contents) {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!("Failed to parse ledgers file: {}", e);
                return HashMap::new();
            }
        };

        let mut ledgers = HashMap::new();
        for entry in entries {
            ledgers.insert(entry.ledger_id, Arc::new(RwLock::new(entry.ledger)));
        }

        tracing::debug!("Loaded {} ledgers from legacy JSON", ledgers.len());
        ledgers
    }

    /// Load ledgers from new append-only JSONL format.
    ///
    /// File: `{ledger_id}.jsonl` where:
    ///  - First line: LedgerState (type: "State")
    ///  - Subsequent lines: SignedLedgerUpdate (type: "Update")
    ///
    /// Parse a single JSONL file into a Ledger.
    fn load_single_ledger_from_jsonl(ledger_id: &str, path: &std::path::Path) -> Option<Ledger> {
        let contents = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("Failed to read ledger {}: {}", ledger_id, e);
                return None;
            }
        };

        let mut role: Option<LedgerRole> = None;
        let mut state: Option<LedgerState> = None;
        let mut updates: Vec<SignedLedgerUpdate> = Vec::new();
        let mut created_at: HashMap<[u8; 32], u64> = HashMap::new();
        let mut seen_sequences = std::collections::HashSet::new();
        // Main-chain operator pubkey. Established from the first update
        // (or seq 0's LedgerOpen if present). Updates from a different
        // operator_id are fork-branch artifacts — earlier daemon
        // versions sometimes persisted them into the main jsonl, which
        // poisoned subsequent reimports with `wrong previous_hash`
        // errors. Heal at load time by dropping them; the next
        // persist_ledger_to_disk rewrites the file without them.
        //
        // Fork-branch jsonls (compound key `<ledger_id>_<seq>_<peer>`,
        // length > 64) legitimately contain TWO operators: the
        // original operator up to last_valid_sequence, then the
        // disputant from there on. The filter would mis-fire there and
        // strip every disputant update, so it's disabled for the
        // fork-branch file format.
        let is_fork_file = ledger_id.len() > 64;
        let mut main_operator: Option<bitcoin::secp256k1::PublicKey> = None;

        for line in contents.lines() {
            if line.trim().is_empty() {
                continue;
            }

            match serde_json::from_str::<LedgerLogRow>(line) {
                Ok(LedgerLogRow::Role { role: r }) => {
                    role = Some(r);
                }
                Ok(LedgerLogRow::State(s)) => {
                    state = Some(s);
                }
                Ok(LedgerLogRow::Update(u)) => {
                    if !is_fork_file {
                        if main_operator.is_none() {
                            main_operator = Some(u.operator_id);
                        }
                        if Some(u.operator_id) != main_operator {
                            tracing::warn!(
                                "Ledger {} seq {}: dropping foreign-operator update \
                                 {} (main operator {}). Likely fork-branch artifact \
                                 from an older binary; the main jsonl should only \
                                 contain main-chain updates.",
                                ledger_id,
                                u.sequence_number,
                                hex::encode(&u.operator_id.serialize()[..8]),
                                hex::encode(&main_operator.unwrap().serialize()[..8]),
                            );
                            continue;
                        }
                    }
                    if seen_sequences.insert(u.sequence_number) {
                        updates.push(u);
                    }
                }
                Ok(LedgerLogRow::CreatedAt { content_hash, ts }) => {
                    // Transport metadata (Nostr created_at). Last-wins so a
                    // later snapshot/append overrides an earlier value.
                    if let Ok(bytes) = hex::decode(&content_hash) {
                        if let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) {
                            created_at.insert(arr, ts);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to parse line in {}: {}", ledger_id, e);
                }
            }
        }

        let ledger_role = role.unwrap_or_else(|| {
            tracing::warn!(
                "Ledger {} missing role in JSONL, defaulting to Partner",
                ledger_id
            );
            LedgerRole::Partner
        });

        updates.sort_by_key(|u| u.sequence_number);

        // Trusting the persisted `State` row was the source of a real
        // bug: persist runs on every in-memory append, and an early
        // snapshot can be written *before* a late-arriving update at an
        // earlier sequence has been applied (e.g. op7's own
        // `QuorumAddMember` at seq 3 arriving after the snapshot was
        // written at seq 6). On load we'd then trust the stale snapshot
        // and only replay seq>state_sequence, which misses the late
        // update entirely and leaves quorum_members short — auto-dispute
        // and confiscation downstream silently exclude that member.
        //
        // Reconstruct from LedgerOpen (seq 0) instead. The State row is
        // informational only.
        use deposits_core::tlv::TlvDecode;
        let mut ledger_state = if let Some(seq0) = updates.iter().find(|u| u.sequence_number == 0) {
            match deposits_core::messages::LedgerOperation::tlv_decode(&seq0.message) {
                Ok(deposits_core::messages::LedgerOperation::LedgerOpen {
                    operator_id,
                    reserves_id,
                    genesis_block,
                    ..
                }) => LedgerState::new(operator_id, reserves_id, genesis_block),
                _ => {
                    tracing::warn!(
                        "Ledger {} seq 0 is not LedgerOpen — falling back to persisted State row",
                        ledger_id
                    );
                    state?
                }
            }
        } else {
            // No seq 0 in history (truncated). Fall back to the
            // persisted State row, with the same stale-snapshot caveat.
            match state {
                Some(s) => s,
                None => {
                    tracing::warn!("Ledger {} missing state and no LedgerOpen", ledger_id);
                    return None;
                }
            }
        };

        // Replay every update we have. For ledgers where seq 0 is
        // present we start with a fresh state and apply all updates;
        // for truncated histories we start from the persisted snapshot
        // and apply updates strictly past its sequence.
        let replay_after_seq: i64 = if updates.iter().any(|u| u.sequence_number == 0) {
            -1
        } else {
            ledger_state.sequence as i64
        };

        if let Some(last_update) = updates.last() {
            ledger_state.sequence = last_update.sequence_number;
            // Use chain_hash (SHA256(content_hash || operator_signature)) so the next
            // append_operation sets prev_hash = chain_hash, matching the protocol spec.
            ledger_state.chain_tip_hash = last_update.chain_hash();
        }

        let mut ledger = Ledger {
            state: ledger_state,
            protocol: Default::default(),
            role: ledger_role,
            history: updates,
            created_at,
        };

        let ops_to_replay: Vec<_> = ledger
            .history
            .iter()
            .filter(|u| (u.sequence_number as i64) > replay_after_seq)
            .filter_map(|u| {
                match deposits_core::messages::LedgerOperation::tlv_decode(&u.message) {
                    Ok(op) => Some((u.sequence_number, op)),
                    Err(e) => {
                        tracing::warn!(
                            "Ledger {} seq {}: failed to decode operation for replay: {}",
                            ledger_id,
                            u.sequence_number,
                            e
                        );
                        None
                    }
                }
            })
            .collect();

        let mut replayed = 0u64;
        for (seq, operation) in &ops_to_replay {
            if let Err(e) = ledger.apply_state_changes(operation) {
                tracing::warn!(
                    "Ledger {} seq {}: failed to replay state change: {}",
                    ledger_id,
                    seq,
                    e
                );
            } else {
                replayed += 1;
            }
        }

        // Restore fork-branch ownership after reload.
        //
        // `parent_pubkey` marks who OPERATES a dispute fork; the dispute
        // pipeline (`initiate_confiscations`, `auto_lottery_claim_or_yield`,
        // `auto_reveal_on_confiscation`) all gate on
        // `parent_pubkey == our_node_id` to decide "this is my fork."
        // But `parent_pubkey` is only ever set imperatively by
        // `auto_arm_for_dispute_with_anchor` (in-memory) — no `apply()`
        // sets it, so a plain replay from the JSONL leaves it at the
        // original operator's key (the LedgerOpen default). After a
        // daemon restart mid-dispute, every dispute stage would then skip
        // the disputer's own fork and the confiscation/lottery/continue
        // arc would silently stall.
        //
        // Heal it here: a fork-branch file (`ledger_id.len() > 64`)
        // carries the disputer's DisputeEnter/DisputeArmed past
        // `last_valid_sequence`, authored under their own `operator_id`
        // (patched at arm time). The author of the first fork-branch
        // DisputeEnter/DisputeArmed is the fork owner.
        if is_fork_file {
            use deposits_core::messages::LedgerOperation;
            let fork_owner = ledger
                .history
                .iter()
                .find_map(|u| match LedgerOperation::tlv_decode(&u.message) {
                    Ok(LedgerOperation::DisputeEnter { .. })
                    | Ok(LedgerOperation::DisputeArmed { .. }) => Some(u.operator_id),
                    _ => None,
                });
            if let Some(owner) = fork_owner {
                if ledger.state.parent_pubkey != owner {
                    tracing::debug!(
                        "Restored fork parent_pubkey for {} to {} (was {})",
                        ledger_id,
                        owner,
                        ledger.state.parent_pubkey
                    );
                    ledger.state.parent_pubkey = owner;
                }
            }
        }

        if replayed > 0 {
            tracing::debug!(
                "Loaded ledger {} with {} updates ({} state changes replayed)",
                ledger_id,
                ledger.history.len(),
                replayed
            );
        } else {
            tracing::debug!(
                "Loaded ledger {} with {} updates",
                ledger_id,
                ledger.history.len()
            );
        }

        Some(ledger)
    }

    fn load_ledgers_from_jsonl(ledgers_dir: &PathBuf) -> HashMap<String, Arc<RwLock<Ledger>>> {
        let t0 = std::time::Instant::now();
        let mut ledgers = HashMap::new();

        let entries = match fs::read_dir(ledgers_dir) {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!("Failed to read ledgers directory: {}", e);
                return ledgers;
            }
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("jsonl") {
                continue;
            }

            let Some(ledger_id) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };

            if let Some(ledger) = Self::load_single_ledger_from_jsonl(ledger_id, &path) {
                ledgers.insert(ledger_id.to_string(), Arc::new(RwLock::new(ledger)));
            }
        }

        let total_elapsed = t0.elapsed();
        if total_elapsed.as_millis() > 5 {
            tracing::info!(
                "[PROFILE] load_ledgers_from_jsonl: {} ledgers in {:?}",
                ledgers.len(),
                total_elapsed
            );
        } else {
            tracing::debug!("Loaded {} ledgers from JSONL", ledgers.len());
        }
        ledgers
    }

    /// Reload ledgers from disk, merging with in-memory state.
    ///
    /// This allows the daemon to pick up changes made by CLI processes.
    /// For each ledger:
    /// - If the disk version has more history entries, it wins
    /// - If the in-memory version has more, keep in-memory
    /// - New ledgers on disk are added to in-memory state
    ///
    /// Returns the number of ledgers that were updated.
    /// Discover new ledger files on disk that aren't already in memory.
    /// Does NOT re-parse existing ledgers — the daemon is the sole writer
    /// for ledgers it already knows about.
    pub fn discover_new_ledgers(&self) -> usize {
        let ledgers_dir = self.data_dir.join("ledgers");
        if !ledgers_dir.exists() {
            return 0;
        }

        // Collect only files whose modtime has changed (instead of all-or-nothing).
        // persist_ledger_to_disk() updates modtimes after writing, so our own writes
        // are excluded — only files modified by external processes (CLI) appear here.
        let changed_files: Vec<(String, PathBuf)> = {
            let modtimes = self.last_file_modtimes.lock().unwrap();
            let mut changed = Vec::new();
            if let Ok(entries) = fs::read_dir(&ledgers_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().and_then(|s| s.to_str()) != Some("jsonl") {
                        continue;
                    }
                    let stem = match path.file_stem().and_then(|s| s.to_str()) {
                        Some(s) => s.to_string(),
                        None => continue,
                    };
                    let current_mtime = path.metadata().ok().and_then(|m| m.modified().ok());
                    match (modtimes.get(&stem), current_mtime) {
                        (Some(prev), Some(curr)) if *prev == curr => {}
                        _ => {
                            changed.push((stem, path));
                        }
                    }
                }
            }
            changed
        };

        if changed_files.is_empty() {
            return 0;
        }

        // Collect current in-memory tip sequences for changed ledgers only.
        // Use next_sequence() instead of history.len() because in-memory history
        // may be truncated (history.len()=2000 but actual tip=50000).
        let known: std::collections::HashMap<String, u64> = {
            let ledgers = self.ledgers.lock().unwrap();
            changed_files
                .iter()
                .filter_map(|(stem, _)| {
                    ledgers.get(stem).map(|arc| {
                        let l = arc.read().unwrap();
                        (stem.clone(), l.next_sequence())
                    })
                })
                .collect()
        };

        let t0 = std::time::Instant::now();
        let mut changes = 0;
        let mut new_updates: Vec<SignedLedgerUpdate> = Vec::new();

        let mut ledgers = self.ledgers.lock().unwrap();
        let mut counts = self.persisted_next_seq.lock().unwrap();

        // Read and parse ONLY the changed files (not all files)
        for (ledger_id, path) in &changed_files {
            let disk_ledger = match Self::load_single_ledger_from_jsonl(ledger_id, path) {
                Some(l) => l,
                None => continue,
            };
            let disk_tip = disk_ledger.next_sequence();
            let disk_len = disk_ledger.history.len();

            if let Some(&mem_tip) = known.get(ledger_id) {
                // Existing ledger — update if disk has higher tip sequence
                if disk_tip > mem_tip {
                    tracing::debug!(
                        "Reloaded ledger {}... from disk (seq {} -> {}, {} entries)",
                        &ledger_id[..16.min(ledger_id.len())],
                        mem_tip,
                        disk_tip,
                        disk_len
                    );
                    // Add updates that are beyond our current tip
                    for update in disk_ledger.history.iter() {
                        if update.sequence_number >= mem_tip {
                            new_updates.push(update.clone());
                        }
                    }
                    let next = Self::next_seq_after(&disk_ledger.history);
                    ledgers.insert(ledger_id.clone(), Arc::new(RwLock::new(disk_ledger)));
                    counts.insert(ledger_id.clone(), next);
                    changes += 1;
                }
            } else {
                // New ledger — all updates are new
                tracing::debug!(
                    "Discovered new ledger {}... ({} entries)",
                    &ledger_id[..16.min(ledger_id.len())],
                    disk_len
                );
                for update in &disk_ledger.history {
                    new_updates.push(update.clone());
                }
                let next = Self::next_seq_after(&disk_ledger.history);
                ledgers.insert(ledger_id.clone(), Arc::new(RwLock::new(disk_ledger)));
                counts.insert(ledger_id.clone(), next);
                changes += 1;
            }
        }

        drop(counts);
        drop(ledgers);

        // Insert discovered updates into event store (outside ledgers lock)
        if !new_updates.is_empty() {
            let mut store = self.event_store.lock().unwrap();
            let mut inserted = 0usize;
            for update in new_updates {
                if store.insert(update) {
                    inserted += 1;
                }
            }
            if inserted > 0 {
                tracing::debug!(
                    "Event store: +{} events from disk (total {}, {} unknown)",
                    inserted,
                    store.len(),
                    store.unknown_count(),
                );
            }
        }

        // Update modification times for changed files
        {
            let mut modtimes = self.last_file_modtimes.lock().unwrap();
            for (stem, path) in &changed_files {
                if let Ok(mtime) = path.metadata().and_then(|m| m.modified()) {
                    modtimes.insert(stem.clone(), mtime);
                }
            }
        }

        let elapsed = t0.elapsed();
        if changes > 0 {
            tracing::debug!(
                "[PROFILE] discover_new_ledgers: {} changes in {:?} ({} files re-read)",
                changes,
                elapsed,
                changed_files.len()
            );
        } else if elapsed.as_millis() > 10 {
            tracing::debug!(
                "[PROFILE] discover_new_ledgers: no changes from {} files in {:?}",
                changed_files.len(),
                elapsed
            );
        }

        changes
    }

    /// Process an incoming message from a peer
    pub fn handle_message(
        &self,
        message: DepositsMessage,
        _sender: PublicKey,
    ) -> Result<(), Error> {
        // The legacy `DepositsMessage::LedgerUpdate(msg)` p2p dispatch
        // path has been deleted — production senders publish ledger
        // updates as Kind 9100 Nostr events, routed through
        // `LedgerActor`. Any DepositsMessage variant arriving here is
        // unhandled by design; log and drop.
        tracing::debug!("Unhandled message type: {:?}", message.message_type());
        Ok(())
    }

    /// Get pending events and clear the queue
    pub fn drain_events(&self) -> Vec<ProtocolEvent> {
        let mut events = self.events.lock().unwrap();
        std::mem::take(&mut *events)
    }

    /// Create or get a ledger for the given operator/reserves_id pair
    ///
    /// When creating a new ledger for our own operator, automatically adds
    /// LedgerOpen operation with the UTXO value as reserves_amount.
    pub fn get_or_create_ledger(
        &self,
        operator: PublicKey,
        reserves_address: String,
    ) -> Arc<RwLock<Ledger>> {
        self.get_or_create_ledger_with_outpoint(operator, reserves_address, None, None)
    }

    /// Get or create a ledger with a specific reserves balance and outpoint.
    ///
    /// If `reserves_balance` is Some, use that for the LedgerOpen reserves_amount
    /// instead of the total wallet reserves balance.
    ///
    /// If `outpoint` is Some, include it in the ledger_id computation so multiple
    /// reserves with the same address produce distinct ledger IDs.
    /// `split_msats` is `Some((reserves_msats, collateral_msats))`
    /// when the caller wants to override the LedgerOpen split. When
    /// `None`, the entire wallet reserves balance becomes
    /// `reserves_amount` and `collateral_amount = 0` (the legacy
    /// behaviour for partner-side ledger imports where no quorum
    /// will be activated).
    pub fn get_or_create_ledger_with_outpoint(
        &self,
        operator: PublicKey,
        reserves_address: String,
        split_msats: Option<(u64, u64)>,
        outpoint: Option<String>,
    ) -> Arc<RwLock<Ledger>> {
        use deposits_core::types::LedgerState;

        // Get current block height for genesis_block
        let genesis_block = self.wallet.get_block_height().unwrap_or(0);

        // Compute ledger_id from genesis parameters.
        // When an outpoint is provided, include it in the computation so that
        // multiple reserves with the same address produce distinct ledger IDs.
        let ledger_id = if let Some(ref op) = outpoint {
            let combined = format!("{}#{}", reserves_address, op);
            let id_bytes = LedgerState::compute_ledger_id(&operator, &combined, genesis_block);
            hex::encode(id_bytes)
        } else {
            let id_bytes =
                LedgerState::compute_ledger_id(&operator, &reserves_address, genesis_block);
            hex::encode(id_bytes)
        };

        let mut ledgers = self.ledgers.lock().unwrap();
        let is_new = !ledgers.contains_key(&ledger_id);
        let ledger = ledgers
            .entry(ledger_id.clone())
            .or_insert_with(|| {
                let role = if operator == self.our_node_id {
                    deposits_core::LedgerRole::Operator
                } else {
                    deposits_core::LedgerRole::Partner
                };
                Arc::new(RwLock::new(Ledger::new(
                    operator,
                    reserves_address.clone(),
                    role,
                    vec![],
                    genesis_block,
                )))
            })
            .clone();

        // If we created a new ledger for ourselves, add initial operations
        if is_new && operator == self.our_node_id {
            // Resolve the LedgerOpen split. Caller-provided value
            // takes precedence; otherwise this is genesis mode with
            // zero on-chain commitment yet (the first QuorumBegin will
            // populate the real amounts).
            let (reserves_msats, collateral_msats) = split_msats.unwrap_or((0, 0));

            // Add LedgerOpen operation
            {
                let mut ledger_guard = ledger.write().unwrap();
                let operation = deposits_core::messages::LedgerOperation::LedgerOpen {
                    operator_id: operator,
                    reserves_id: reserves_address.clone(),
                    genesis_block,
                    reserves_amount: reserves_msats,
                    collateral_amount: collateral_msats,
                };
                if let Err(e) = ledger_guard.append_operation(operation) {
                    tracing::error!("Failed to append LedgerOpen: {:?}", e);
                } else {
                    self.sign_ledger_update(&mut ledger_guard);
                }
            }

            // Save to disk
            drop(ledgers); // Release lock before saving
            if let Err(e) = self.persist_ledger_to_disk(&ledger_id) {
                tracing::error!("Failed to save ledgers after creation: {}", e);
            }
        } else if is_new {
            // New ledger for a partner, just save
            drop(ledgers);
            if let Err(e) = self.persist_ledger_to_disk(&ledger_id) {
                tracing::error!("Failed to save ledgers after creation: {}", e);
            }
        }

        ledger
    }

    /// Read the chain tip (last sequence_number and content_hash) from the JSONL file on disk.
    ///
    /// Returns None if the file doesn't exist or has no Update lines.
    pub fn read_disk_chain_tip(&self, ledger_id: &str) -> Option<(u64, [u8; 32])> {
        let ledger_file = self
            .data_dir
            .join("ledgers")
            .join(format!("{}.jsonl", ledger_id));
        let contents = fs::read_to_string(&ledger_file).ok()?;

        let mut best_seq: Option<u64> = None;
        let mut best_hash = [0u8; 32];

        for line in contents.lines() {
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(LedgerLogRow::Update(u)) = serde_json::from_str::<LedgerLogRow>(line) {
                match best_seq {
                    None => {
                        best_seq = Some(u.sequence_number);
                        best_hash = u.content_hash;
                    }
                    Some(s) if u.sequence_number > s => {
                        best_seq = Some(u.sequence_number);
                        best_hash = u.content_hash;
                    }
                    _ => {}
                }
            }
        }

        best_seq.map(|s| (s, best_hash))
    }

    /// Read the FULL persisted update chain for a ledger from its append-only
    /// JSONL log on disk, in sequence order.
    ///
    /// The in-memory `Ledger::history` is truncated to the most recent
    /// [`Self::history_retain`] entries (a RAM optimization). The JSONL on disk,
    /// however, holds the entire chain — including the genesis `LedgerOpen`
    /// (seq 0) and the early `QuorumBegin`. Callers that need the whole chain
    /// (e.g. ledger healing, which must re-publish the old span the relay
    /// dropped) read from here rather than from the truncated `Vec`.
    ///
    /// Returns the updates de-duplicated by `content_hash` (a compacted log may
    /// legitimately contain the same update in both a State-snapshot region and
    /// a later append region) and sorted ascending by `sequence_number` so the
    /// result is a clean, oldest-first chain. Returns `None` if the file is
    /// missing or unreadable (so callers can fall back to in-memory history);
    /// returns `Some(empty)` only if the file exists but has no `Update` rows.
    pub fn read_persisted_history(&self, ledger_id: &str) -> Option<Vec<SignedLedgerUpdate>> {
        Self::read_persisted_history_at(&self.data_dir, ledger_id)
    }

    /// Static core of [`Self::read_persisted_history`]: parse the ledger's
    /// `{data_dir}/ledgers/{ledger_id}.jsonl` into a de-duplicated,
    /// sequence-ordered chain. Split out so it can be unit-tested against a
    /// temp dir without constructing a full [`DepositsHandler`].
    pub fn read_persisted_history_at(
        data_dir: &std::path::Path,
        ledger_id: &str,
    ) -> Option<Vec<SignedLedgerUpdate>> {
        let ledger_file = data_dir
            .join("ledgers")
            .join(format!("{}.jsonl", ledger_id));
        let contents = fs::read_to_string(&ledger_file).ok()?;

        let mut by_hash: HashMap<[u8; 32], SignedLedgerUpdate> = HashMap::new();
        for line in contents.lines() {
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(LedgerLogRow::Update(u)) = serde_json::from_str::<LedgerLogRow>(line) {
                by_hash.entry(u.content_hash).or_insert(u);
            }
        }

        let mut updates: Vec<SignedLedgerUpdate> = by_hash.into_values().collect();
        updates.sort_by_key(|u| u.sequence_number);
        Some(updates)
    }

    /// The first `n` updates (sequence 0..n) of a ledger's persisted chain,
    /// in order, reading the JSONL only as far as it must.
    ///
    /// [`Self::read_persisted_history`] reads and parses the whole file, which
    /// for a busy ledger is gigabytes (2.1 GB for a 141k-update ledger on the
    /// cl-deposits devnet): 20 s and as much RAM per call. The genesis prefix
    /// sits at the top of an append-only log, so stream it, parse only
    /// `Update` rows, and stop once 0..n are all present. A log whose early
    /// updates are scattered (compaction) is read to the end, as before.
    pub fn read_persisted_history_prefix(&self, ledger_id: &str, n: u64) -> Option<Vec<SignedLedgerUpdate>> {
        Self::read_persisted_history_prefix_at(&self.data_dir, ledger_id, n)
    }

    /// Static core of [`Self::read_persisted_history_prefix`], for tests.
    pub fn read_persisted_history_prefix_at(
        data_dir: &std::path::Path,
        ledger_id: &str,
        n: u64,
    ) -> Option<Vec<SignedLedgerUpdate>> {
        use std::io::BufRead;
        let ledger_file = data_dir
            .join("ledgers")
            .join(format!("{}.jsonl", ledger_id));
        let reader = std::io::BufReader::new(fs::File::open(&ledger_file).ok()?);
        let mut by_seq: std::collections::BTreeMap<u64, SignedLedgerUpdate> = Default::default();
        for line in reader.lines() {
            let line = line.ok()?;
            if !line.starts_with("{\"type\":\"Update\"") {
                continue;
            }
            if let Ok(LedgerLogRow::Update(u)) = serde_json::from_str::<LedgerLogRow>(&line) {
                if u.sequence_number < n {
                    by_seq.entry(u.sequence_number).or_insert(u);
                    if by_seq.len() as u64 == n {
                        break;
                    }
                }
            }
        }
        Some(by_seq.into_values().collect())
    }

    /// Append accepted updates to `{data_dir}/ledgers/{ledger_id}.jsonl` in the
    /// same append-only `LedgerLogRow::Update` format the daemon persists —
    /// deduped by `content_hash` against what the file already holds, and NEVER
    /// truncating the file (a fork-branch key gets its own file). Returns the
    /// number of new rows written.
    ///
    /// This is the durable-write half of the `archive` subcommand's reuse of the
    /// daemon's persistence: the file it produces is byte-compatible with
    /// [`Self::read_persisted_history_at`], so a diff/backfill pass round-trips
    /// through the exact same reader the daemon's healer uses. The `Update`
    /// variant is private to this module, so the archivist writes through here
    /// rather than re-deriving the JSONL shape.
    ///
    /// Safety: only ever appends the rows handed to it. The archivist only hands
    /// it updates that have already passed [`crate::node_cli::archive`]'s
    /// quorum-cosig + hash-chain validation, so a compromised relay can never
    /// get uncosigned/forged bytes into the archive through this path.
    pub fn archive_append_updates_at(
        data_dir: &std::path::Path,
        ledger_id: &str,
        updates: &[SignedLedgerUpdate],
    ) -> std::io::Result<usize> {
        use std::io::Write;

        let ledgers_dir = data_dir.join("ledgers");
        fs::create_dir_all(&ledgers_dir)?;
        let ledger_file = ledgers_dir.join(format!("{}.jsonl", ledger_id));

        // Dedup against what's already on disk (append-only, so we never rewrite
        // or drop existing rows) — matches the daemon's content_hash dedup.
        let existing: std::collections::HashSet<[u8; 32]> =
            Self::read_persisted_history_at(data_dir, ledger_id)
                .unwrap_or_default()
                .iter()
                .map(|u| u.content_hash)
                .collect();

        let to_write: Vec<&SignedLedgerUpdate> = updates
            .iter()
            .filter(|u| !existing.contains(&u.content_hash))
            .collect();
        if to_write.is_empty() {
            return Ok(0);
        }

        let file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&ledger_file)?;
        let mut writer = std::io::BufWriter::new(file);
        let mut written = 0usize;
        for update in to_write {
            let row = LedgerLogRow::Update((*update).clone());
            let line = serde_json::to_string(&row)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            writeln!(writer, "{}", line)?;
            written += 1;
        }
        writer.flush()?;
        Ok(written)
    }

    /// Insert a signed ledger update into the event store.
    /// Returns true if the event was new (not a duplicate).
    pub fn insert_event(&self, update: &SignedLedgerUpdate) -> bool {
        let t0 = std::time::Instant::now();
        let mut store = self.event_store.lock().unwrap();
        let is_new = store.insert(update.clone());
        let elapsed = t0.elapsed();
        crate::metrics::record_insert_event_duration(elapsed);
        is_new
    }

    /// Record (and durably persist) the Nostr `created_at` of the kind:9100
    /// event for `content_hash` on `ledger_id`. Writes to three places:
    ///   1. the in-memory `EventStore` (live cache the resync path reads), and
    ///   2. the owning `Ledger`'s `created_at` map (the carrier that travels
    ///      with the ledger clone into the persist thread + full-write
    ///      snapshots), and
    ///   3. an incremental `CreatedAt` jsonl row on disk so the timestamp
    ///      survives an immediate restart, not just the next compaction.
    /// First-write-wins per hash, matching `EventStore::record_created_at`.
    pub fn record_created_at(&self, ledger_id: &str, content_hash: [u8; 32], ts: u64) {
        // 1. Live cache for resync.
        self.event_store
            .lock()
            .unwrap()
            .record_created_at(&content_hash, ts);

        // 2. Persistence carrier on the ledger. Skip the disk append if this
        //    hash was already recorded (idempotent re-broadcast).
        let newly_recorded = {
            let ledgers = self.ledgers.lock().unwrap();
            match ledgers.get(ledger_id) {
                Some(arc) => {
                    let mut ledger = arc.write().unwrap();
                    if let std::collections::hash_map::Entry::Vacant(e) =
                        ledger.created_at.entry(content_hash)
                    {
                        e.insert(ts);
                        true
                    } else {
                        false
                    }
                }
                None => false,
            }
        };

        // 3. Durable incremental row (outside the ledgers lock).
        if newly_recorded {
            Self::append_created_at_to_disk(ledger_id, &content_hash, ts, &self.data_dir);
        }
    }

    /// Persist a specific ledger to disk using append-only strategy.
    ///
    /// On first save (or when no tracking exists), does a full rewrite.
    /// On subsequent saves, only appends new Update lines to the JSONL file.
    /// State line is written every 100 appends (not every time) to reduce file bloat.
    /// Full compaction (rewrite) triggers every 1000 appends to cap file size.
    #[tracing::instrument(name = "persist_ledger_to_disk", skip(self), fields(ledger = &ledger_id[..16.min(ledger_id.len())]))]
    pub fn persist_ledger_to_disk(&self, ledger_id: &str) -> Result<(), String> {
        let t0 = std::time::Instant::now();

        // One persist at a time for this ledger, held across the I/O. Only
        // persists take it, and a persist takes no other lock while holding a
        // ledger lock, so it cannot deadlock with compaction or the actor.
        let persist_lock = self
            .persist_locks
            .lock()
            .unwrap()
            .entry(ledger_id.to_string())
            .or_default()
            .clone();
        let _persisting = persist_lock.lock().unwrap_or_else(|e| e.into_inner());

        let next_seq = self
            .persisted_next_seq
            .lock()
            .unwrap()
            .get(ledger_id)
            .copied();

        // Get Arc clone
        let ledger_arc = {
            let ledgers = self.ledgers.lock().unwrap();
            ledgers
                .get(ledger_id)
                .ok_or_else(|| format!("Ledger not found: {}", ledger_id))?
                .clone()
        };

        if next_seq.is_none() {
            // First save — write State + the FULL in-memory history to disk.
            //
            // DURABILITY: the on-disk JSONL must hold the complete chain. In
            // the common case first-save runs on a fresh, small ledger whose
            // in-memory `history` IS the full chain, so `retain=None` (write
            // everything) is exactly right. On the reload path the append
            // cursor is initialized past the loaded tip (see `Self::new`), so
            // this branch only fires when the file has never been written —
            // never after a truncating reload — or when a caller replaced the
            // chain and asked for a rewrite (`forget_persisted`). Writing the
            // untruncated history here is what keeps genesis/QuorumBegin
            // durable from the start.
            let ledger = ledger_arc.read().unwrap();
            let history_len = ledger.history.len();
            let written_next = Self::next_seq_after(&ledger.history);
            Self::save_ledger_to_disk_streaming(ledger_id, &ledger, &self.data_dir, None);
            drop(ledger);
            self.mark_persisted(ledger_id, written_next);

            // Cap ONLY RAM; the disk file above holds the full chain.
            let final_len = self.cap_history(ledger_id, &ledger_arc, Self::history_retain());
            self.appends_since_compaction
                .lock()
                .unwrap()
                .insert(ledger_id.to_string(), 0);

            let total_elapsed = t0.elapsed();
            if total_elapsed.as_millis() > 1 {
                tracing::info!(
                    "[PROFILE] persist_ledger_to_disk: disk={}, RAM={} entries, total={:?}, mode=full_write",
                    history_len,
                    final_len,
                    total_elapsed
                );
            }
        } else if let Some(append) =
            self.persist_append_snapshot(ledger_id, &ledger_arc, next_seq.unwrap_or(0))
        {
            Self::append_updates_to_disk(
                ledger_id,
                append.state.as_ref(),
                &append.updates,
                &self.data_dir,
            );
            self.persist_append_commit(ledger_id, &append);
            let total_elapsed = t0.elapsed();
            if total_elapsed.as_millis() > 1 {
                tracing::info!(
                    "[PROFILE] persist_ledger_to_disk: {} entries (+{}), total={:?}, mode=append{}",
                    append.history_len,
                    append.updates.len(),
                    total_elapsed,
                    if append.state.is_some() { " (with state)" } else { "" }
                );
            }
        }

        // Update modtime so discover_new_ledgers() doesn't re-read our own writes
        let ledger_file = self
            .data_dir
            .join("ledgers")
            .join(format!("{}.jsonl", ledger_id));
        if let Ok(mtime) = ledger_file.metadata().and_then(|m| m.modified()) {
            self.last_file_modtimes
                .lock()
                .unwrap()
                .insert(ledger_id.to_string(), mtime);
        }

        crate::metrics::record_persist_ledger_duration(t0.elapsed());
        Ok(())
    }

    /// Every loaded ledger whose JSONL skips sequences, logged loudly: its
    /// replay folded across the hole, so its balances are wrong from there.
    fn find_damaged_ledgers(
        ledgers: &HashMap<String, Arc<RwLock<Ledger>>>,
    ) -> HashMap<String, Vec<SequenceGap>> {
        let mut damaged = HashMap::new();
        for (id, arc) in ledgers {
            let gaps = sequence_gaps(&arc.read().unwrap().history);
            if gaps.is_empty() {
                continue;
            }
            let missing: u64 = gaps.iter().map(|g| g.last - g.first + 1).sum();
            tracing::error!(
                "Ledger {} JSONL is missing {} update(s): {}. Its state is replayed across \
                 the hole and is wrong from seq {}; repairing from the relay",
                id,
                missing,
                describe_gaps(&gaps),
                gaps[0].first
            );
            damaged.insert(id.clone(), gaps);
        }
        damaged
    }

    /// Ledgers whose JSONL skips sequences, as found at load (or left after
    /// a repair).
    pub(crate) fn damaged_ledgers(&self) -> Vec<(String, Vec<SequenceGap>)> {
        self.damaged_ledgers
            .lock()
            .unwrap()
            .iter()
            .map(|(id, gaps)| (id.clone(), gaps.clone()))
            .collect()
    }

    /// Record that the replica flagged the update at `seq` on `ledger_id` as
    /// non-conforming while applying it. Takes no ledger lock, so the ledger
    /// actor can call it while holding the ledger's write lock.
    pub(crate) fn note_non_conforming(&self, ledger_id: &str, seq: u64) {
        let mut flagged = self.flagged_non_conforming.lock().unwrap();
        let first = flagged.entry(ledger_id.to_string()).or_insert(seq);
        *first = (*first).min(seq);
    }

    /// The first sequence on `ledger_id`'s original operator chain known to be
    /// non-conforming: the lowest this replica flagged on apply, or found by a
    /// one-time scan of its history. A dispute must fork before it: the
    /// replica applies flagged updates and follows the fraudulent chain, so
    /// its tip is not a valid base.
    pub(crate) fn first_non_conforming(&self, ledger_id: &str) -> Option<u64> {
        let flagged = self
            .flagged_non_conforming
            .lock()
            .unwrap()
            .get(ledger_id)
            .copied();
        let cached = self
            .scanned_non_conforming
            .lock()
            .unwrap()
            .get(ledger_id)
            .copied();
        let scanned = match cached {
            Some(s) => s,
            None => {
                let arc = self.ledgers.lock().unwrap().get(ledger_id).cloned();
                let s = arc.and_then(|arc| {
                    let l = arc.read().unwrap();
                    let operator = l.history.first().filter(|g| g.sequence_number == 0)?.operator_id;
                    // The dep-16 descriptor verifier, as the replica's
                    // apply_and_check uses: a forged witness is a fault.
                    deposits_core::fraud::find_non_conforming_update(
                        &l.history,
                        &operator,
                        &deposits_core::dep16::Dep16Authorizer::new(),
                    )
                    .map(|(seq, _)| seq)
                });
                self.scanned_non_conforming
                    .lock()
                    .unwrap()
                    .insert(ledger_id.to_string(), s);
                s
            }
        };
        match (flagged, scanned) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// Whether `ledger_id`'s replica was replayed across a hole in its JSONL
    /// and is not repaired: its balances and quorum are not to be judged.
    pub(crate) fn is_damaged(&self, ledger_id: &str) -> bool {
        self.damaged_ledgers.lock().unwrap().contains_key(ledger_id)
    }

    /// Write `fills` (verified updates for `ledger_id`'s holes) into its JSONL
    /// and rebuild the ledger from the file in place, so its state is folded
    /// over the whole chain. The `Arc` is kept (the actor holds it). For
    /// startup, before anything is applied to the ledger: the rebuild takes
    /// the file as the truth. Returns the gaps still left.
    pub(crate) fn repair_ledger_gaps(
        &self,
        ledger_id: &str,
        fills: &[SignedLedgerUpdate],
    ) -> Result<Vec<SequenceGap>, String> {
        let persist_lock = self
            .persist_locks
            .lock()
            .unwrap()
            .entry(ledger_id.to_string())
            .or_default()
            .clone();
        let _persisting = persist_lock.lock().unwrap_or_else(|e| e.into_inner());

        // The daemon's own append (a leading newline per row): the file ends
        // without one, so a row-then-newline append would glue onto its last.
        Self::append_updates_to_disk(ledger_id, None, fills, &self.data_dir);
        let path = self
            .data_dir
            .join("ledgers")
            .join(format!("{}.jsonl", ledger_id));
        let mut fresh = Self::load_single_ledger_from_jsonl(ledger_id, &path)
            .ok_or_else(|| format!("reload {}", ledger_id))?;
        let gaps = sequence_gaps(&fresh.history);
        let next = Self::next_seq_after(&fresh.history);
        let retain = Self::history_retain();
        let len = fresh.history.len();
        if len > retain {
            fresh.history.drain(..len - retain);
        }
        let arc = self
            .ledgers
            .lock()
            .unwrap()
            .get(ledger_id)
            .cloned()
            .ok_or_else(|| format!("Ledger not found: {}", ledger_id))?;
        *arc.write().unwrap() = fresh;
        self.mark_persisted(ledger_id, next);
        let mut damaged = self.damaged_ledgers.lock().unwrap();
        if gaps.is_empty() {
            damaged.remove(ledger_id);
        } else {
            damaged.insert(ledger_id.to_string(), gaps.clone());
        }
        Ok(gaps)
    }

    /// The sequence after the last update in `history` (0 if empty): what an
    /// append cursor reads once `history` is all written.
    fn next_seq_after(history: &[SignedLedgerUpdate]) -> u64 {
        history.last().map_or(0, |u| u.sequence_number + 1)
    }

    /// Record `ledger_id`'s JSONL as written below `next_seq`. Never lowers
    /// the cursor: a persist that finishes after a later one has nothing to
    /// take back.
    fn mark_persisted(&self, ledger_id: &str, next_seq: u64) {
        let mut next = self.persisted_next_seq.lock().unwrap();
        let entry = next.entry(ledger_id.to_string()).or_insert(next_seq);
        *entry = (*entry).max(next_seq);
    }

    /// Forget what was written for `ledger_id`, so its next persist rewrites
    /// the whole file from memory: for a caller that replaced the chain (a
    /// promoted fork, a re-import from genesis) rather than extending it.
    pub(crate) fn forget_persisted(&self, ledger_id: &str) {
        self.persisted_next_seq.lock().unwrap().remove(ledger_id);
    }

    /// Step 1 of an append persist: the updates at or past `next_seq`, read
    /// under the ledger lock. Found from the tail, by sequence, so nothing
    /// that trims the front of `history` in the meantime can shift it.
    fn persist_append_snapshot(
        &self,
        ledger_id: &str,
        ledger_arc: &Arc<RwLock<Ledger>>,
        next_seq: u64,
    ) -> Option<PersistAppend> {
        let ledger = ledger_arc.read().unwrap();
        let history_len = ledger.history.len();
        let start = ledger
            .history
            .iter()
            .rposition(|u| u.sequence_number < next_seq)
            .map_or(0, |i| i + 1);
        if start == history_len {
            return None;
        }
        let appends = self
            .appends_since_compaction
            .lock()
            .unwrap()
            .get(ledger_id)
            .copied()
            .unwrap_or(0);
        let state = (appends % 100 == 0).then(|| ledger.state.clone());
        Some(PersistAppend {
            history_len,
            updates: ledger.history[start..].to_vec(),
            state,
        })
    }

    /// Step 3 of an append persist, after the rows are on disk: raise the
    /// cursor past what this persist wrote, whatever ran meanwhile.
    fn persist_append_commit(&self, ledger_id: &str, append: &PersistAppend) {
        self.mark_persisted(ledger_id, Self::next_seq_after(&append.updates));
        *self
            .appends_since_compaction
            .lock()
            .unwrap()
            .entry(ledger_id.to_string())
            .or_insert(0) += append.updates.len();
    }

    /// Full-compaction threshold (appends since last compaction). PROD DEFAULT:
    /// 1000. `DEPOSITS_COMPACT_THRESHOLD` overrides it ONLY for tests — paired
    /// with `DEPOSITS_HISTORY_RETAIN`, it lets a regtest reproduce the real
    /// deep-ledger condition (compaction fires → in-memory history truncated
    /// past seq 0 / QuorumBegin while the full chain stays on disk) on a shallow
    /// ledger, instead of having to build 1000+ real updates. Never set in prod.
    const COMPACT_THRESHOLD: usize = 1000;

    fn compact_threshold() -> usize {
        std::env::var("DEPOSITS_COMPACT_THRESHOLD")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|&n| n >= 1)
            .unwrap_or(Self::COMPACT_THRESHOLD)
    }

    /// Returns ledger IDs that need compaction (>= [`Self::compact_threshold`]
    /// appends since last compaction; prod default 1000).
    pub fn ledgers_needing_compaction(&self) -> Vec<String> {
        let threshold = Self::compact_threshold();
        let compaction = self.appends_since_compaction.lock().unwrap();
        compaction
            .iter()
            .filter(|(_, &count)| count >= threshold)
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Run compaction for a single ledger. Call from background task.
    ///
    /// DURABILITY INVARIANT: compaction caps ONLY the in-memory `history` Vec;
    /// it MUST NOT truncate the on-disk JSONL. The JSONL is append-only and
    /// [`persist_ledger_to_disk`] has already appended every update up to the
    /// current tip, so the full chain — genesis `LedgerOpen` (seq 0), early
    /// `QuorumBegin` and all — is already durable on disk. A custody ledger's
    /// full history is only a few MB; unbounded on-disk growth is acceptable
    /// and correct because depositors reconstruct from genesis and the daemon
    /// must be able to re-publish the whole chain (heal) after relay retention
    /// expires the old span. Truncating disk here (the old behavior) deleted
    /// seq 0 / QuorumBegin from the durable log once a ledger passed the retain
    /// window — the data-loss bug this closes.
    ///
    /// So compaction's job is purely to cap RAM, and it drops only updates
    /// already written ([`Self::cap_history`]). It no longer touches the
    /// append cursor. When the cursor was an index into the in-memory Vec,
    /// compaction re-based it to the capped length, and two things lost
    /// updates from replicas' JSONLs (whose applies come from the actor, the
    /// relay reimport and the event store, concurrently with this task):
    ///   - an update applied but not yet persisted when compaction ran was
    ///     re-based as written and never was (ref3's C: seqs 53330, 60353);
    ///   - a persist straddling the compaction stored its pre-compaction
    ///     length as the cursor afterwards, so the next ~1000 appends were
    ///     skipped (ref2's F: 121035-122035, after `compact_ledger: RAM
    ///     51001→50000` then `persist_ledger_to_disk: 51001 entries`).
    /// The cursor is now a sequence only persists raise.
    pub fn compact_ledger(&self, ledger_id: &str) -> Result<(), String> {
        let t0 = std::time::Instant::now();

        let ledger_arc = {
            let ledgers = self.ledgers.lock().unwrap();
            ledgers
                .get(ledger_id)
                .ok_or_else(|| format!("Ledger not found: {}", ledger_id))?
                .clone()
        };

        let history_len = ledger_arc.read().unwrap().history.len();

        // Cap ONLY RAM, and only what is written. Disk keeps the full
        // append-only chain untouched.
        let final_len = self.cap_history(ledger_id, &ledger_arc, Self::history_retain());

        self.appends_since_compaction
            .lock()
            .unwrap()
            .insert(ledger_id.to_string(), 0);
        crate::metrics::record_ledger_compaction();

        // NOTE: intentionally do NOT touch the JSONL modtime here. We didn't
        // write the file, so leaving the modtime as-is is correct; there is no
        // self-write for `discover_new_ledgers` to skip.

        tracing::info!(
            "[PROFILE] compact_ledger: RAM {}→{} entries (disk keeps full chain), total={:?}",
            history_len,
            final_len,
            t0.elapsed()
        );

        Ok(())
    }

    /// Truncate in-memory history to at most `retain` entries, all of which
    /// must be on disk (the load path: everything came from the file).
    /// Returns the new history length.
    fn truncate_history(ledger_arc: &Arc<RwLock<Ledger>>, retain: usize) -> usize {
        Self::truncate_history_below(ledger_arc, retain, u64::MAX)
    }

    /// Truncate in-memory history to at most `retain` entries, dropping only
    /// updates below sequence `written_below`: one not yet written stays in
    /// RAM until a persist has it on disk. Returns the new history length.
    fn truncate_history_below(
        ledger_arc: &Arc<RwLock<Ledger>>,
        retain: usize,
        written_below: u64,
    ) -> usize {
        let mut ledger = ledger_arc.write().unwrap();
        let len = ledger.history.len();
        if len > retain {
            let written = ledger
                .history
                .iter()
                .take(len - retain)
                .take_while(|u| u.sequence_number < written_below)
                .count();
            ledger.history.drain(..written);
        }
        ledger.history.len()
    }

    /// Cap `ledger_id`'s in-memory history at `retain`, keeping anything its
    /// JSONL does not yet hold. Every RAM trim of a live ledger goes through
    /// here. Returns the new history length.
    pub(crate) fn cap_history(
        &self,
        ledger_id: &str,
        ledger_arc: &Arc<RwLock<Ledger>>,
        retain: usize,
    ) -> usize {
        let written_below = self
            .persisted_next_seq
            .lock()
            .unwrap()
            .get(ledger_id)
            .copied()
            .unwrap_or(0);
        Self::truncate_history_below(ledger_arc, retain, written_below)
    }

    /// Maximum history entries to retain IN MEMORY. This caps ONLY the
    /// in-memory `Ledger::history` Vec — the on-disk JSONL is append-only and
    /// always holds the FULL chain (see [`Self::compact_ledger`]). The State
    /// snapshot captures all balances/deposits; the in-memory history tail is
    /// needed only for chain continuity and a recent audit trail. Any path that
    /// needs the whole chain (heal / reconstruction) sources it from disk via
    /// [`Self::read_persisted_history`].
    ///
    /// PROD DEFAULT: 50_000 — matches the EventStore FIFO cap and keeps even a
    /// ~12k-update ledger (e.g. mainnet `57f60e1d`) fully in memory, so only
    /// pathologically huge ledgers ever truncate in RAM. Raised from 2000,
    /// which truncated deep ledgers in RAM far too eagerly. The
    /// `DEPOSITS_HISTORY_RETAIN` env var overrides it ONLY for tests — it lets a
    /// regtest reproduce the deep/truncated-ledger case (in-memory history drops
    /// seq 0 / QuorumBegin while the full chain stays on disk) without building
    /// 50k+ real updates. Never set it in production; the default is what ships.
    const HISTORY_RETAIN: usize = 50_000;

    /// Effective in-memory history retention. Reads the
    /// `DEPOSITS_HISTORY_RETAIN` test override, falling back to the prod
    /// default [`Self::HISTORY_RETAIN`] (50_000). A value of 0 or an unparseable
    /// value falls back to the default (retain must be >= 1 for chain continuity).
    fn history_retain() -> usize {
        std::env::var("DEPOSITS_HISTORY_RETAIN")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|&n| n >= 1)
            .unwrap_or(Self::HISTORY_RETAIN)
    }

    fn save_ledger_to_disk_streaming(
        ledger_id: &str,
        ledger: &Ledger,
        data_dir: &PathBuf,
        retain: Option<usize>,
    ) {
        let t0 = std::time::Instant::now();
        let ledgers_dir = data_dir.join("ledgers");
        if !ledgers_dir.exists() {
            if let Err(e) = fs::create_dir_all(&ledgers_dir) {
                tracing::error!("Failed to create ledgers dir: {}", e);
                return;
            }
        }

        let history_len = ledger.history.len();
        let start = match retain {
            Some(k) => history_len.saturating_sub(k),
            None => 0,
        };
        let written = history_len - start;
        let ledger_file = ledgers_dir.join(format!("{}.jsonl", ledger_id));

        // Write to a temp file, then rename for atomicity
        let tmp_file = ledgers_dir.join(format!("{}.jsonl.tmp", ledger_id));
        let file = match fs::File::create(&tmp_file) {
            Ok(f) => f,
            Err(e) => {
                tracing::error!("Failed to create temp ledger file {}: {}", ledger_id, e);
                return;
            }
        };

        use std::io::Write;
        let mut writer = std::io::BufWriter::new(file);

        // Stream role + state + updates directly to file — no intermediate Vec<String>
        let role_row = LedgerLogRow::Role { role: ledger.role };
        if let Ok(line) = serde_json::to_string(&role_row) {
            let _ = writeln!(writer, "{}", line);
        }

        let state_row = LedgerLogRow::State(ledger.state.clone());
        if let Ok(line) = serde_json::to_string(&state_row) {
            let _ = writeln!(writer, "{}", line);
        }

        // Write only the retained tail of history (or all if retain is None)
        for update in &ledger.history[start..] {
            let update_row = LedgerLogRow::Update(update.clone());
            if let Ok(line) = serde_json::to_string(&update_row) {
                let _ = writeln!(writer, "{}", line);
            }
        }

        // Snapshot the Nostr created_at for each retained update so a
        // re-broadcast after restart reuses the original timestamp (stable
        // event id → relay dedupe). Only the retained tail is kept, which
        // also compacts the incremental CreatedAt rows appended since the
        // last full write. Hashes outside the tail are dropped as orphans.
        for update in &ledger.history[start..] {
            if let Some(ts) = ledger.created_at.get(&update.content_hash) {
                let row = LedgerLogRow::CreatedAt {
                    content_hash: hex::encode(update.content_hash),
                    ts: *ts,
                };
                if let Ok(line) = serde_json::to_string(&row) {
                    let _ = writeln!(writer, "{}", line);
                }
            }
        }

        if let Err(e) = writer.flush() {
            tracing::error!("Failed to flush ledger file {}: {}", ledger_id, e);
            let _ = fs::remove_file(&tmp_file);
            return;
        }
        drop(writer);

        // Atomic rename
        if let Err(e) = fs::rename(&tmp_file, &ledger_file) {
            tracing::error!("Failed to rename ledger file {}: {}", ledger_id, e);
            let _ = fs::remove_file(&tmp_file);
            return;
        }

        let total_elapsed = t0.elapsed();
        if total_elapsed.as_millis() > 1 {
            tracing::info!(
                "[PROFILE] save_ledger_to_disk_streaming: {}/{} entries, total={:?}",
                written,
                history_len,
                total_elapsed
            );
        }
    }

    // Keep old signature for callers that pass owned data
    fn save_single_ledger_to_disk((ledger_id, ledger): (String, Ledger), data_dir: &PathBuf) {
        Self::save_ledger_to_disk_streaming(&ledger_id, &ledger, data_dir, None);
    }

    /// Append new updates (and optionally a State snapshot) to an existing ledger JSONL file.
    ///
    /// When `current_state` is Some, writes a State line first so reloads see current state.
    /// The loader takes the last-seen State line and replays updates after it, so State lines
    /// only need to be written periodically (every ~100 appends) rather than on every persist.
    fn append_updates_to_disk(
        ledger_id: &str,
        current_state: Option<&LedgerState>,
        new_updates: &[SignedLedgerUpdate],
        data_dir: &PathBuf,
    ) {
        let ledgers_dir = data_dir.join("ledgers");
        let ledger_file = ledgers_dir.join(format!("{}.jsonl", ledger_id));

        let file = match fs::OpenOptions::new().append(true).open(&ledger_file) {
            Ok(f) => f,
            Err(e) => {
                tracing::error!("Failed to open ledger file for append {}: {}", ledger_id, e);
                return;
            }
        };

        use std::io::Write;
        let mut writer = std::io::BufWriter::new(file);

        // Optionally write State line (only every ~100 appends to reduce file bloat)
        if let Some(state) = current_state {
            let state_row = LedgerLogRow::State(state.clone());
            if let Ok(line) = serde_json::to_string(&state_row) {
                if let Err(e) = write!(writer, "\n{}", line) {
                    tracing::error!("Failed to append state to ledger {}: {}", ledger_id, e);
                    return;
                }
            }
        }

        for update in new_updates {
            let update_row = LedgerLogRow::Update(update.clone());
            if let Ok(line) = serde_json::to_string(&update_row) {
                if let Err(e) = write!(writer, "\n{}", line) {
                    tracing::error!("Failed to append to ledger {}: {}", ledger_id, e);
                    return;
                }
            }
        }

        if let Err(e) = writer.flush() {
            tracing::error!("Failed to flush ledger file {}: {}", ledger_id, e);
        }
    }

    /// Append a single Nostr `created_at` row to an existing ledger JSONL.
    /// Cheap (one line, append mode) so it can run every time we mint a fresh
    /// timestamp on first broadcast. Snapshotted/compacted on the next full
    /// write. No-op if the file doesn't exist yet (first persist writes it).
    fn append_created_at_to_disk(
        ledger_id: &str,
        content_hash: &[u8; 32],
        ts: u64,
        data_dir: &PathBuf,
    ) {
        let ledger_file = data_dir
            .join("ledgers")
            .join(format!("{}.jsonl", ledger_id));
        let file = match fs::OpenOptions::new().append(true).open(&ledger_file) {
            Ok(f) => f,
            // Not yet persisted — the first full write will snapshot it.
            Err(_) => return,
        };
        use std::io::Write;
        let mut writer = std::io::BufWriter::new(file);
        let row = LedgerLogRow::CreatedAt {
            content_hash: hex::encode(content_hash),
            ts,
        };
        if let Ok(line) = serde_json::to_string(&row) {
            let _ = write!(writer, "\n{}", line);
        }
        let _ = writer.flush();
    }

    /// Sign the last update in a ledger with our operator key.
    ///
    /// Signs `update.operator_digest()` — tagged BIP-340 hash
    /// with length-prefixed `message`. See `SignedLedgerUpdate::
    /// operator_digest` for the layout and the rationale
    /// (closes the `message ↔ cosignatures` boundary ambiguity and
    /// adds domain separation against cross-protocol sig replay).
    fn sign_ledger_update(&self, ledger: &mut Ledger) {
        let ledger_id = ledger.ledger_id();
        if let Some(update) = ledger.history.last_mut() {
            let digest = update.operator_digest();
            let ctx = SignContext::operator_update(ledger_id, update.sequence_number);
            let sig = self
                .signer
                .bip340_sign(&ctx, &digest)
                .expect("LocalSigner cannot fail; RemoteSigner errors propagate when wired");

            update.operator_signature = sig;
            tracing::debug!("Signed update seq={}", update.sequence_number);
        }

        // Finalize state.hash = chain_hash = SHA256(content_hash || operator_signature)
        // so the next append_operation uses chain_hash as prev_hash (per protocol spec).
        ledger.finalize_chain_hash();
    }

    /// Import a ledger from an export file (JSON or binary)
    ///
    /// This validates the ledger using LedgerConformanceValidator before storing it.
    /// The ledger will be stored with the Partner role since it's from another operator.
    ///
    /// If the ledger already exists locally, this will apply any newer updates
    /// from the export instead of failing. This is essential for custody recovery
    /// scenarios where a quorum member already has the ledger but needs the
    /// DisputeAcquire updates to become the new operator.
    pub fn import_ledger(
        &self,
        export: LedgerExport,
    ) -> Result<(ValidationReport, Arc<RwLock<Ledger>>), String> {
        // Check if this is our own ledger (not allowed to import our own)
        if export.operator_id == self.our_node_id {
            return Err("Cannot import your own ledger. Use 'ledger open' instead.".to_string());
        }

        // Compute the ledger_id from export parameters
        let ledger_id_bytes = LedgerState::compute_ledger_id(
            &export.operator_id,
            &export.reserves_id,
            export.genesis_block,
        );
        let ledger_id = hex::encode(ledger_id_bytes);

        // Check if ledger already exists
        let existing_ledger = {
            let ledgers = self.ledgers.lock().unwrap();
            ledgers.get(&ledger_id).cloned()
        };

        // Validate the export
        let report = LedgerConformanceValidator::validate(&export)
            .map_err(|e| format!("Validation failed: {}", e))?;

        // Log warnings if ledger has issues, but still allow import
        // This is important for recovery scenarios where we import a ledger
        // that may have been corrupted by a malicious operator
        if !report.is_valid {
            tracing::warn!(
                "Importing non-conforming ledger: {} warnings, {} invalid signatures",
                report.warnings.len(),
                report.signatures.invalid_signatures.len()
            );
        }

        // If ledger exists, apply newer updates instead of creating new
        if let Some(ledger_arc) = existing_ledger {
            let local_seq = {
                let ledger = ledger_arc.read().unwrap();
                ledger.sequence()
            };

            // Find updates that are newer than our local copy
            let new_updates: Vec<_> = export
                .updates
                .iter()
                .filter(|u| u.sequence_number > local_seq)
                .cloned()
                .collect();

            if new_updates.is_empty() {
                tracing::info!(
                    "Ledger {} already up to date (seq {})",
                    &ledger_id[..16],
                    local_seq
                );
                return Ok((report, ledger_arc));
            }

            // Sort by sequence number
            let mut sorted_updates = new_updates;
            sorted_updates.sort_by_key(|u| u.sequence_number);

            tracing::info!(
                "Ledger {} exists with {} entries, applying {} new updates",
                &ledger_id[..16],
                local_seq,
                sorted_updates.len()
            );

            // Apply each new update in order
            {
                let mut ledger = ledger_arc.write().unwrap();
                for update in sorted_updates {
                    // Verify chain continuity
                    if update.previous_hash != ledger.tail_hash() {
                        // This can happen if there are branches - skip non-matching updates
                        tracing::debug!(
                            "Skipping update {} with wrong previous_hash",
                            update.sequence_number
                        );
                        continue;
                    }
                    ledger.append_signed_update(update);
                }
            }

            // Persist only this ledger (append-only)
            self.persist_ledger_to_disk(&ledger_id)?;

            return Ok((report, ledger_arc));
        }

        // Create the ledger from the validated export
        let ledger = Ledger::from_export(export)
            .map_err(|e| format!("Failed to reconstruct ledger: {}", e))?;

        // Store the ledger
        let ledger_arc = Arc::new(RwLock::new(ledger));
        let ledger_id_for_persist = ledger_id.clone();
        {
            let mut ledgers = self.ledgers.lock().unwrap();
            ledgers.insert(ledger_id, ledger_arc.clone());
        }

        // Persist only this ledger (append-only)
        self.persist_ledger_to_disk(&ledger_id_for_persist)?;

        Ok((report, ledger_arc))
    }

    /// Apply new updates to an existing ledger.
    /// Returns the number of updates applied.
    pub fn apply_updates_to_ledger(
        &self,
        ledger_id: &str,
        updates: Vec<SignedLedgerUpdate>,
    ) -> Result<usize, String> {
        // Find the ledger by ledger_id
        let ledgers = self.ledgers.lock().unwrap();
        let ledger_arc = ledgers
            .get(ledger_id)
            .cloned()
            .ok_or_else(|| format!("Ledger not found: {}", ledger_id))?;
        drop(ledgers); // Release lock before modifying

        use deposits_core::tlv::TlvDecode;

        let mut ledger = ledger_arc.write().unwrap();
        let mut applied = 0;

        for update in updates {
            // Verify this update follows the current chain. Stop (don't error
            // out) at the first non-chaining update so the validated prefix
            // before it is still applied and persisted — a single broken/forked
            // update partway through a relay batch must not discard the real,
            // cosigned updates ahead of it (otherwise a node behind the relay
            // never catches up past the break).
            if update.previous_hash != ledger.tail_hash() {
                tracing::warn!(
                    "apply_updates_to_ledger {}: chain break at seq {} (expected prev {}, got {}) — \
                     applied {} so far, stopping",
                    ledger_id,
                    update.sequence_number,
                    hex::encode(&ledger.tail_hash()[..8]),
                    hex::encode(&update.previous_hash[..8]),
                    applied,
                );
                break;
            }

            // Run the state machine — don't just append. Appending to history
            // alone advanced the chain (sequence/tip) but left derived state
            // (deposits, balances, quorum) untouched, so a joined member's
            // re-imported replica sat at the right seq with an empty deposits
            // map — and a later dependent op (e.g. a drip InvoiceCredit against
            // the buffer's DepositOpen) was rejected DepositNotFound. Mirror
            // ledger_actor::apply_inbound: apply the op through the state
            // machine + conformance verifier, then advance chain + push.
            let op = match deposits_core::messages::LedgerOperation::tlv_decode(&update.message) {
                Ok(o) => o,
                Err(e) => {
                    return Err(format!(
                        "decode op at seq {}: {}",
                        update.sequence_number, e
                    ))
                }
            };
            match ledger.apply_and_check(&op, update.block_height) {
                Ok(violations) if !violations.is_empty() => {
                    tracing::warn!(
                        "apply_updates_to_ledger {}: conformance violations at seq {}: {:?}",
                        ledger_id,
                        update.sequence_number,
                        violations
                    );
                }
                Err(e) => {
                    // Stop at the first un-appliable update; keep prior progress.
                    tracing::warn!(
                        "apply_updates_to_ledger {}: apply failed at seq {}: {} — stopping",
                        ledger_id,
                        update.sequence_number,
                        e
                    );
                    break;
                }
                _ => {}
            }
            ledger.state.sequence = update.sequence_number;
            ledger.state.chain_tip_hash = update.chain_hash();
            ledger.history.push(update);
            applied += 1;
        }

        drop(ledger); // Release write lock

        // Persist only this ledger (append-only)
        self.persist_ledger_to_disk(ledger_id)?;

        Ok(applied)
    }

    /// Apply + persist an update we authored ourselves onto `ledger_id`,
    /// running the state machine so derived state (custody, dispute state,
    /// tip, sequence) advances, then flushing to disk.
    ///
    /// Unlike `apply_updates_to_ledger`, this does NOT re-verify chain
    /// continuity against `tail_hash()`. It exists for the winner's
    /// `DisputeAcquire` on its own dispute fork: that update chains off the
    /// fork's `DisputeArmed` using the SAME `previous_hash` we broadcast to
    /// the relay (see `dispute::claim_lottery`), so the local copy and the
    /// wire copy are byte-identical — but the fork's in-memory `tail_hash()`
    /// is the DisputeArmed's `chain_hash()`, which the broadcast update does
    /// not (by the existing dispute wire convention) reference. Re-deriving
    /// `previous_hash` here would fork the local copy away from the published
    /// one, so we take the authored update verbatim and only run the state
    /// machine + advance the tip.
    ///
    /// Safe against the fork's actor for the same reasons
    /// `apply_updates_to_ledger` is: it holds the ledger write lock
    /// atomically with no awaits mid-apply, and it's idempotent (a duplicate
    /// seq+content_hash is a no-op). Returns `Ok(true)` if it appended,
    /// `Ok(false)` if the update was already present.
    pub fn commit_self_authored_update(
        &self,
        ledger_id: &str,
        operation: &deposits_core::messages::LedgerOperation,
        update: SignedLedgerUpdate,
        block_height: u32,
    ) -> Result<bool, String> {
        let ledger_arc = {
            let ledgers = self.ledgers.lock().unwrap();
            ledgers
                .get(ledger_id)
                .cloned()
                .ok_or_else(|| format!("Ledger not found: {}", ledger_id))?
        };

        {
            let mut ledger = ledger_arc.write().unwrap();

            // Idempotent across periodic retries of the claim task.
            let already = ledger.history.iter().any(|u| {
                u.sequence_number == update.sequence_number && u.content_hash == update.content_hash
            });
            if already {
                return Ok(false);
            }

            // Run the state machine + conformance verifier so custody /
            // dispute state / balances advance (not just the chain tip).
            match ledger.apply_and_check(operation, block_height) {
                Ok(violations) if !violations.is_empty() => {
                    tracing::warn!(
                        "commit_self_authored_update {}: conformance violations at seq {}: {:?}",
                        ledger_id,
                        update.sequence_number,
                        violations
                    );
                }
                Err(e) => {
                    return Err(format!(
                        "apply failed at seq {}: {}",
                        update.sequence_number, e
                    ));
                }
                _ => {}
            }

            ledger.state.sequence = update.sequence_number;
            ledger.state.chain_tip_hash = update.chain_hash();
            ledger.history.push(update);
        }

        self.persist_ledger_to_disk(ledger_id)?;
        Ok(true)
    }

    /// Adopt the relay's newer cosigned updates for a ledger we operate, IN
    /// PLACE on the shared `Arc<RwLock<Ledger>>` (the same one the ledger's
    /// actor holds — so this advances the operator's writer view, never a second
    /// copy). `fetched` is the relay's chain for this ledger; we keep only the
    /// real operator's signed updates beyond our tip, require the first to chain
    /// onto our tip (else it's a fork at the tip → adopt nothing, never purge an
    /// operated ledger), and apply via `apply_updates_to_ledger` (prefix-safe).
    ///
    /// This is the load-bearing recovery for an operator that restarted behind
    /// its own already-cosigned chain (local state regressed). A cosigned update
    /// is authentic — only the operator could have signed it and the quorum
    /// cosigned it — so adopting it is correct, not a trust concession. Returns
    /// the number of updates applied. Split from the relay fetch (in
    /// `Node::catch_up_owned_ledger`) so the decision is unit-testable.
    pub fn adopt_owned_updates(&self, ledger_id: &str, fetched: Vec<SignedLedgerUpdate>) -> usize {
        let (local_next_seq, local_tip_hash, operator) = {
            let ledgers = self.ledgers.lock().unwrap();
            let Some(arc) = ledgers.get(ledger_id) else {
                return 0;
            };
            let l = arc.read().unwrap();
            (l.next_sequence(), l.tail_hash(), l.state.operator_key)
        };

        let mut new_updates: Vec<_> = fetched
            .into_iter()
            .filter(|u| u.sequence_number >= local_next_seq && u.operator_id == operator)
            .collect();
        new_updates.sort_by_key(|u| u.sequence_number);
        new_updates.dedup_by_key(|u| u.sequence_number);
        if new_updates.is_empty() {
            return 0; // already at or ahead of the relay — nothing to adopt
        }

        if new_updates[0].sequence_number == local_next_seq
            && new_updates[0].previous_hash != local_tip_hash
        {
            tracing::error!(
                "adopt_owned_updates {}…: relay diverges from our tip at seq {} — not adopting (manual reconciliation needed)",
                &ledger_id[..16.min(ledger_id.len())],
                local_next_seq,
            );
            return 0;
        }

        match self.apply_updates_to_ledger(ledger_id, new_updates) {
            Ok(applied) => {
                if applied > 0 {
                    let tip = self
                        .ledgers
                        .lock()
                        .unwrap()
                        .get(ledger_id)
                        .map(|a| a.read().unwrap().state.sequence)
                        .unwrap_or(0);
                    tracing::info!(
                        "adopt_owned_updates {}…: adopted {} cosigned update(s) from relay, tip now seq {}",
                        &ledger_id[..16.min(ledger_id.len())],
                        applied,
                        tip,
                    );
                }
                applied
            }
            Err(e) => {
                tracing::warn!(
                    "adopt_owned_updates {}…: apply failed: {}",
                    &ledger_id[..16.min(ledger_id.len())],
                    e
                );
                0
            }
        }
    }
}

// ============================================================================
// ValidationContext Implementation
// ============================================================================

impl ValidationContext for DepositsHandler {
    fn get_ledger(&self, operator: &PublicKey, reserves_id: &str) -> Option<Arc<RwLock<Ledger>>> {
        // Search ledgers by operator and reserves_key (reserves_id)
        let ledgers = self.ledgers.lock().unwrap();
        for (_ledger_id, ledger_arc) in ledgers.iter() {
            let ledger = ledger_arc.read().unwrap();
            if ledger.operator_key() == *operator && ledger.reserves_key() == reserves_id {
                return Some(ledger_arc.clone());
            }
        }
        None
    }

    fn our_node_id(&self) -> PublicKey {
        self.our_node_id
    }

    fn get_commitment_tx_reserves_amount(&self, _operator: PublicKey) -> Option<u64> {
        // Legacy P2WSH reserves are gone; the per-ledger Taproot vault carries
        // its own committed amount in `LedgerOpen.reserves_amount`. This hook
        // is no longer the authoritative source.
        None
    }
}

// ============================================================================
// HandlerContext Implementation
// ============================================================================

impl HandlerContext for DepositsHandler {
    fn queue_message(&self, peer: PublicKey, msg: DepositsMessage) -> Result<(), HandlerError> {
        // Queue the message for async sending
        self.outbound_tx
            .send(OutboundMessage { peer, message: msg })
            .map_err(|_| HandlerError::Internal("Outbound channel closed".to_string()))
    }

    fn emit_event(&self, event: ProtocolEvent) {
        let mut events = self.events.lock().unwrap();
        events.push(event);
    }

    fn our_secret_key(&self) -> Option<SecretKey> {
        // The daemon no longer retains the operator secret directly — all
        // signing flows through `self.signer`. The `HandlerContext` trait
        // method's default-impl callers (sign_message / sign_schnorr) will
        // see `None` and bail out; in deposits-rust those defaults are not
        // wired into any active daemon path.
        None
    }

    fn current_block_height(&self) -> u32 {
        self.wallet.get_block_height().unwrap_or(0)
    }

    fn persist_ledger(&self, operator: &PublicKey, reserves_id: &str) -> Result<(), String> {
        // Find the ledger_id for this operator/reserves_id pair
        let ledger_id = {
            let ledgers = self.ledgers.lock().unwrap();
            ledgers
                .iter()
                .find(|(_, arc)| {
                    let l = arc.read().unwrap();
                    l.operator_key() == *operator && l.reserves_key() == reserves_id
                })
                .map(|(id, _)| id.clone())
        };

        if let Some(id) = ledger_id {
            self.persist_ledger_to_disk(&id)
        } else {
            Err("Ledger not found for operator/reserves_id".to_string())
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Serializes tests that mutate the process-global `DEPOSITS_HISTORY_RETAIN`
    /// env var so a small override from one test can't leak into another's
    /// handler construction (which reads the var on load/persist).
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn test_secret_key() -> SecretKey {
        SecretKey::from_slice(&[1u8; 32]).unwrap()
    }

    fn test_pubkey() -> PublicKey {
        use bitcoin::secp256k1::Secp256k1;
        let secp = Secp256k1::new();
        PublicKey::from_secret_key(&secp, &test_secret_key())
    }

    fn test_local_signer() -> Arc<dyn Signer> {
        Arc::new(deposits_signer_api::LocalSigner::new(test_secret_key()))
    }

    fn create_mock_wallet(temp_dir: &TempDir) -> Arc<Wallet> {
        // Create a minimal wallet for testing
        Arc::new(Wallet::new_mock(temp_dir.path().to_path_buf()))
    }

    #[test]
    fn test_handler_creation() {
        let temp_dir = TempDir::new().unwrap();
        let wallet = create_mock_wallet(&temp_dir);
        let data_dir = temp_dir.path().to_path_buf();

        let (handler, _rx) = DepositsHandler::new(test_local_signer(), wallet, data_dir, false);

        assert_eq!(handler.our_node_id, test_pubkey());
        assert!(handler.ledgers.lock().unwrap().is_empty());
    }

    #[test]
    fn test_ledger_creation_and_persistence() {
        let temp_dir = TempDir::new().unwrap();
        let wallet = create_mock_wallet(&temp_dir);
        let data_dir = temp_dir.path().to_path_buf();

        let reserves_id = "tb1qtest".to_string();

        // Create handler and ledger
        {
            let (handler, _rx) =
                DepositsHandler::new(test_local_signer(), wallet.clone(), data_dir.clone(), false);

            // Create a ledger (as partner, so we control when it's created)
            let other_pk = {
                let sk = SecretKey::from_slice(&[2u8; 32]).unwrap();
                let secp = bitcoin::secp256k1::Secp256k1::new();
                PublicKey::from_secret_key(&secp, &sk)
            };

            let ledger = handler.get_or_create_ledger(other_pk, reserves_id.clone());
            assert!(ledger.read().unwrap().history.is_empty());

            // Save to disk
            handler.save_ledgers_to_disk().unwrap();
        }

        // Reload and verify
        {
            let (handler, _rx) = DepositsHandler::new(test_local_signer(), wallet, data_dir, false);

            let ledgers = handler.ledgers.lock().unwrap();
            assert_eq!(ledgers.len(), 1);
        }
    }

    /// Build a minimal SignedLedgerUpdate for a given operator/seq, with a
    /// deterministic content_hash. Mirrors event_store::tests::make_update.
    fn mk_update(operator_id: PublicKey, seq: u64, tag: u8) -> SignedLedgerUpdate {
        SignedLedgerUpdate {
            message: vec![tag],
            message_type: 0x0001,
            operator_id,
            ledger_id: [tag; 32],
            sequence_number: seq,
            previous_hash: [0u8; 32],
            content_hash: [tag; 32],
            block_height: 100 + seq as u32,
            block_hash: [0u8; 32],
            operator_signature: [0u8; 64],
            cosignatures: Vec::new(),
        }
    }

    /// Regression: the Nostr `created_at` recorded on first broadcast must
    /// survive a restart so a re-broadcast reuses the same timestamp (stable
    /// event id → relay dedupe). Before the fix it lived only in the in-memory
    /// EventStore and was lost on reload, so every post-redeploy republish
    /// minted a fresh now() and fanned out a duplicate.
    #[test]
    fn created_at_persists_across_restart() {
        let temp_dir = TempDir::new().unwrap();
        let wallet = create_mock_wallet(&temp_dir);
        let data_dir = temp_dir.path().to_path_buf();

        let op_pk = {
            let sk = SecretKey::from_slice(&[2u8; 32]).unwrap();
            let secp = bitcoin::secp256k1::Secp256k1::new();
            PublicKey::from_secret_key(&secp, &sk)
        };

        let update = mk_update(op_pk, 0, 0xAB);
        let pinned_ts = 1_700_000_000u64;

        // Session 1: create ledger, add an update, persist, then record the
        // Nostr created_at (as the broadcast path does after minting now()).
        {
            let (handler, _rx) =
                DepositsHandler::new(test_local_signer(), wallet.clone(), data_dir.clone(), false);
            let arc = handler.get_or_create_ledger(op_pk, "tb1qtest".to_string());
            let ledger_id = handler
                .ledgers
                .lock()
                .unwrap()
                .keys()
                .next()
                .unwrap()
                .clone();
            arc.write().unwrap().history.push(update.clone());
            // The commit path inserts into the EventStore before broadcasting;
            // mirror that so record_created_at's live-cache write lands.
            handler.insert_event(&update);
            handler.persist_ledger_to_disk(&ledger_id).unwrap();

            handler.record_created_at(&ledger_id, update.content_hash, pinned_ts);
            // Recorded in the live cache this session.
            assert_eq!(
                handler
                    .event_store
                    .lock()
                    .unwrap()
                    .get(&update.content_hash)
                    .and_then(|s| s.created_at),
                Some(pinned_ts),
            );
        }

        // Session 2: fresh handler over the same data dir — simulates the
        // `deposits-hub bootstrap` restart. The timestamp must come back.
        {
            let (handler, _rx) = DepositsHandler::new(test_local_signer(), wallet, data_dir, false);
            let restored = handler
                .event_store
                .lock()
                .unwrap()
                .get(&update.content_hash)
                .and_then(|s| s.created_at);
            assert_eq!(
                restored,
                Some(pinned_ts),
                "created_at should survive restart so re-broadcast reuses it"
            );
        }
    }

    /// Deep-ledger healing: the heal must diff+republish against the FULL
    /// on-disk chain, not the truncated in-memory `Vec`. This reproduces the
    /// `57f60e1d` failure shape in miniature — an in-memory history truncated
    /// past its genesis `LedgerOpen` (seq 0) and early `QuorumBegin` (seq 4),
    /// while the JSONL on disk still holds the whole chain — and asserts:
    ///   1. in-memory history really is truncated (seq 0/4 gone),
    ///   2. `read_persisted_history` returns the full chain (seq 0/4 present),
    ///   3. the heal's missing-set, computed from the DISK history against an
    ///      empty relay, INCLUDES the old genesis+QuorumBegin span,
    ///   4. contrast: the same diff over the truncated IN-MEMORY history omits
    ///      them — i.e. sourcing from disk is exactly what restores them.
    #[test]
    fn heal_sources_full_on_disk_history_including_genesis_and_quorumbegin() {
        use crate::node::heal::{missing_updates, HEAL_BATCH_LIMIT};

        let temp_dir = TempDir::new().unwrap();
        let wallet = create_mock_wallet(&temp_dir);
        let data_dir = temp_dir.path().to_path_buf();

        let op_pk = {
            let sk = SecretKey::from_slice(&[2u8; 32]).unwrap();
            let secp = bitcoin::secp256k1::Secp256k1::new();
            PublicKey::from_secret_key(&secp, &sk)
        };

        let (handler, _rx) =
            DepositsHandler::new(test_local_signer(), wallet, data_dir.clone(), false);
        let arc = handler.get_or_create_ledger(op_pk, "tb1qtest".to_string());
        let ledger_id = handler
            .ledgers
            .lock()
            .unwrap()
            .keys()
            .next()
            .unwrap()
            .clone();

        // Build a 10-deep chain. seq 0 stands in for the genesis LedgerOpen,
        // seq 4 for the early QuorumBegin; both use distinct content_hash tags.
        const CHAIN_LEN: u64 = 10;
        const GENESIS_TAG: u8 = 0x00; // seq 0 → LedgerOpen
        const QUORUM_TAG: u8 = 0x04; // seq 4 → QuorumBegin
        for seq in 0..CHAIN_LEN {
            let tag = seq as u8; // content_hash = [seq; 32], distinct per update
            let u = mk_update(op_pk, seq, tag);
            arc.write().unwrap().history.push(u.clone());
            handler.insert_event(&u);
        }
        // Persist the FULL chain to disk (first save writes State + history).
        handler.persist_ledger_to_disk(&ledger_id).unwrap();

        // Simulate the RAM truncation that a deep ledger undergoes: keep only
        // the most-recent 3 in memory, dropping seq 0..=6 (genesis + QuorumBegin).
        let retain = 3usize;
        let in_mem_len = DepositsHandler::truncate_history(&arc, retain);
        assert_eq!(in_mem_len, retain);

        // (1) In-memory history is truncated past genesis/QuorumBegin.
        let in_mem: Vec<SignedLedgerUpdate> = arc.read().unwrap().history.clone();
        let in_mem_seqs: Vec<u64> = in_mem.iter().map(|u| u.sequence_number).collect();
        assert_eq!(in_mem_seqs, vec![7, 8, 9], "RAM keeps only the recent tail");
        assert!(
            !in_mem.iter().any(|u| u.content_hash[0] == GENESIS_TAG),
            "genesis LedgerOpen dropped from RAM"
        );
        assert!(
            !in_mem.iter().any(|u| u.content_hash[0] == QUORUM_TAG),
            "early QuorumBegin dropped from RAM"
        );

        // (2) The JSONL on disk still has the whole chain, oldest-first.
        let disk = handler
            .read_persisted_history(&ledger_id)
            .expect("JSONL exists");
        let disk_seqs: Vec<u64> = disk.iter().map(|u| u.sequence_number).collect();
        assert_eq!(
            disk_seqs,
            (0..CHAIN_LEN).collect::<Vec<_>>(),
            "disk holds the full chain in sequence order"
        );
        assert!(disk.iter().any(|u| u.content_hash[0] == GENESIS_TAG));
        assert!(disk.iter().any(|u| u.content_hash[0] == QUORUM_TAG));

        // (3) Heal diff over the DISK history against an EMPTY relay (post-wipe):
        // the missing set is the whole chain, INCLUDING genesis + QuorumBegin.
        let empty_relay: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
        let missing_from_disk = missing_updates(&empty_relay, &disk, HEAL_BATCH_LIMIT);
        let missing_disk_seqs: Vec<u64> = missing_from_disk
            .iter()
            .map(|u| u.sequence_number)
            .collect();
        assert_eq!(
            missing_disk_seqs,
            (0..CHAIN_LEN).collect::<Vec<_>>(),
            "disk-sourced heal re-publishes the entire chain oldest-first"
        );
        assert!(
            missing_from_disk
                .iter()
                .any(|u| u.content_hash[0] == GENESIS_TAG),
            "disk-sourced heal INCLUDES genesis LedgerOpen (seq 0)"
        );
        assert!(
            missing_from_disk
                .iter()
                .any(|u| u.content_hash[0] == QUORUM_TAG),
            "disk-sourced heal INCLUDES early QuorumBegin (seq 4)"
        );

        // (4) Contrast — the pre-fix behavior. The same diff over the truncated
        // IN-MEMORY history can NEVER surface the old span: it isn't there.
        let missing_from_mem = missing_updates(&empty_relay, &in_mem, HEAL_BATCH_LIMIT);
        assert!(
            !missing_from_mem
                .iter()
                .any(|u| u.content_hash[0] == GENESIS_TAG),
            "in-memory-sourced heal MISSES genesis — the bug this fix closes"
        );
        assert!(
            !missing_from_mem
                .iter()
                .any(|u| u.content_hash[0] == QUORUM_TAG),
            "in-memory-sourced heal MISSES QuorumBegin — the bug this fix closes"
        );
    }

    /// Durability: compaction MUST keep the full chain on the on-disk JSONL
    /// (append-only) while capping ONLY the in-memory `history` Vec. This is the
    /// exact data-loss bug being closed — before the fix, `compact_ledger`
    /// rewrote the JSONL down to the retained tail, deleting genesis
    /// `LedgerOpen` (seq 0) and early `QuorumBegin` from the durable log once a
    /// ledger passed the retain window. Reproduces the shape cheaply with a
    /// tiny `DEPOSITS_HISTORY_RETAIN` and asserts:
    ///   1. after compaction the in-memory history is capped to the retain tail
    ///      (genesis/QuorumBegin gone from RAM), but
    ///   2. the on-disk JSONL STILL contains seq 0 + the whole chain, and
    ///   3. a subsequent append does not drop/duplicate — disk keeps growing.
    #[test]
    fn compaction_retains_full_disk_history_while_capping_ram() {
        // Scope the env override so it can't leak into sibling tests.
        struct RetainGuard;
        impl Drop for RetainGuard {
            fn drop(&mut self) {
                std::env::remove_var("DEPOSITS_HISTORY_RETAIN");
            }
        }
        let _env = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("DEPOSITS_HISTORY_RETAIN", "3");
        let _guard = RetainGuard;
        assert_eq!(DepositsHandler::history_retain(), 3);

        let temp_dir = TempDir::new().unwrap();
        let wallet = create_mock_wallet(&temp_dir);
        let data_dir = temp_dir.path().to_path_buf();

        let op_pk = {
            let sk = SecretKey::from_slice(&[2u8; 32]).unwrap();
            let secp = bitcoin::secp256k1::Secp256k1::new();
            PublicKey::from_secret_key(&secp, &sk)
        };

        let (handler, _rx) =
            DepositsHandler::new(test_local_signer(), wallet, data_dir.clone(), false);
        let arc = handler.get_or_create_ledger(op_pk, "tb1qtest".to_string());
        let ledger_id = handler
            .ledgers
            .lock()
            .unwrap()
            .keys()
            .next()
            .unwrap()
            .clone();

        const CHAIN_LEN: u64 = 10;
        const GENESIS_TAG: u8 = 0x00; // seq 0 → LedgerOpen
        const QUORUM_TAG: u8 = 0x04; // seq 4 → QuorumBegin

        // First update, then first persist (full write of the small chain).
        arc.write()
            .unwrap()
            .history
            .push(mk_update(op_pk, 0, GENESIS_TAG));
        handler.persist_ledger_to_disk(&ledger_id).unwrap();
        // Append the rest one at a time as the live path does.
        for seq in 1..CHAIN_LEN {
            arc.write()
                .unwrap()
                .history
                .push(mk_update(op_pk, seq, seq as u8));
            handler.persist_ledger_to_disk(&ledger_id).unwrap();
        }

        // Compact — caps RAM, must NOT touch the on-disk chain.
        handler.compact_ledger(&ledger_id).unwrap();

        // (1) In-memory history capped to the retain tail; genesis/QuorumBegin gone from RAM.
        let in_mem_seqs: Vec<u64> = arc
            .read()
            .unwrap()
            .history
            .iter()
            .map(|u| u.sequence_number)
            .collect();
        assert_eq!(in_mem_seqs, vec![7, 8, 9], "RAM capped to retain=3 tail");

        // (2) The on-disk JSONL still holds the FULL chain, seq 0 present.
        let disk = handler
            .read_persisted_history(&ledger_id)
            .expect("JSONL exists");
        let disk_seqs: Vec<u64> = disk.iter().map(|u| u.sequence_number).collect();
        assert_eq!(
            disk_seqs,
            (0..CHAIN_LEN).collect::<Vec<_>>(),
            "on-disk chain survives compaction intact, seq 0..9"
        );
        assert!(
            disk.iter().any(|u| u.content_hash[0] == GENESIS_TAG),
            "genesis LedgerOpen (seq 0) STILL on disk after compaction"
        );
        assert!(
            disk.iter().any(|u| u.content_hash[0] == QUORUM_TAG),
            "early QuorumBegin (seq 4) STILL on disk after compaction"
        );

        // (3) A post-compaction append grows the disk chain without dropping or
        // duplicating: seq 10 lands, seq 0 stays, no dupes.
        arc.write()
            .unwrap()
            .history
            .push(mk_update(op_pk, CHAIN_LEN, CHAIN_LEN as u8));
        handler.persist_ledger_to_disk(&ledger_id).unwrap();
        let disk2 = handler.read_persisted_history(&ledger_id).unwrap();
        let disk2_seqs: Vec<u64> = disk2.iter().map(|u| u.sequence_number).collect();
        assert_eq!(
            disk2_seqs,
            (0..=CHAIN_LEN).collect::<Vec<_>>(),
            "append after compaction extends the full on-disk chain (seq 0..10, no dupes/gaps)"
        );
    }

    /// A retain=3 handler holding one persisted ledger of seqs 0..10; the
    /// guard restores the env when dropped.
    fn compaction_race_fixture(
        temp_dir: &TempDir,
    ) -> (DepositsHandler, Arc<RwLock<Ledger>>, String, PublicKey) {
        let wallet = create_mock_wallet(temp_dir);
        let op_pk = {
            let sk = SecretKey::from_slice(&[2u8; 32]).unwrap();
            PublicKey::from_secret_key(&bitcoin::secp256k1::Secp256k1::new(), &sk)
        };
        let (handler, _rx) = DepositsHandler::new(
            test_local_signer(),
            wallet,
            temp_dir.path().to_path_buf(),
            false,
        );
        let arc = handler.get_or_create_ledger(op_pk, "tb1qtest".to_string());
        let ledger_id = handler.ledgers.lock().unwrap().keys().next().unwrap().clone();
        for seq in 0..10u64 {
            arc.write().unwrap().history.push(mk_update(op_pk, seq, seq as u8));
            handler.persist_ledger_to_disk(&ledger_id).unwrap();
        }
        (handler, arc, ledger_id, op_pk)
    }

    /// Ledger C in miniature, as a replica holds it after following the
    /// fraud: LedgerOpen (reserves 20e9, collateral 30e9), QuorumBegin,
    /// DepositOpen, a 480e6 credit, the 40e9 credit at seq 4, then two more
    /// updates on top (tip 6). Real operations, operator-signed.
    fn replica_past_a_fault() -> (PublicKey, Vec<SignedLedgerUpdate>) {
        use bitcoin::secp256k1::{Keypair, Message, Secp256k1};
        use deposits_core::messages::{LedgerOperation, QuorumMemberRef};
        use deposits_core::TlvEncode;
        use sha2::{Digest, Sha256};

        let secp = Secp256k1::new();
        let kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[7u8; 32]).unwrap());
        let op = kp.public_key();
        let member = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[2u8; 32]).unwrap());
        let ledger_id = deposits_core::types::LedgerState::compute_ledger_id(&op, "tb1qres", 0);
        let credit = |n: u8, amount: u64| LedgerOperation::OnchainCredit {
            txid: [n; 32],
            vout: 0,
            deposit_id: [0xAB; 16],
            amount,
            funding_address: "tb1qfund".to_string(),
            commitment: None,
        };
        let ops = vec![
            LedgerOperation::LedgerOpen {
                operator_id: op,
                reserves_id: "tb1qres".to_string(),
                genesis_block: 0,
                reserves_amount: 20_000_000_000,
                collateral_amount: 30_000_000_000,
            },
            LedgerOperation::QuorumBegin {
                reserves_id: "tb1qres".to_string(),
                spending_txid: [0; 32],
                new_outpoint_txid: [1; 32],
                new_outpoint_vout: 0,
                amount: 20_000_000_000,
                quorum_expiry: 1_000_000,
                ledger_hash: [0; 32],
                quorum_members: vec![QuorumMemberRef::pubkey_only(member)],
                collateral_amount: 30_000_000_000,
                protocol_version: None,
            },
            LedgerOperation::DepositOpen {
                deposit_id: [0xAB; 16],
                // A descriptor that parses: the scan judges with the dep-16
                // verifier, which reports an unparseable one (as it should).
                descriptor: format!("wsh(prove(pk({})))", bitcoin::PublicKey::new(member)),
                fees: None,
                transfer_fees: None,
                payment_hash: None,
                invoice: None,
                cosigner_guarantee_signature: None,
                receive_requires_sig: false,
                fee_change_after_blocks: None,
                fee_change_notice_blocks: None,
                fee_change_limit_bps: None,
                commitment: None,
            },
            credit(1, 480_000_000),
            credit(2, 40_000_000_000),
            credit(3, 1),
            credit(4, 1),
        ];
        let mut chain: Vec<SignedLedgerUpdate> = Vec::new();
        for (seq, o) in ops.iter().enumerate() {
            let mut u = mk_update(op, seq as u64, 0);
            u.message = o.tlv_encode();
            u.ledger_id = ledger_id;
            u.previous_hash = chain.last().map(|p| p.chain_hash()).unwrap_or([0u8; 32]);
            u.content_hash = u.compute_hash();
            let digest = u.operator_digest();
            u.operator_signature = secp
                .sign_schnorr_no_aux_rand(&Message::from_digest(digest), &kp)
                .serialize();
            chain.push(u);
        }
        (op, chain)
    }

    /// A dispute forks before the first non-conforming update the replica
    /// holds, not at its tip: found by scanning the history (what the JSONL
    /// loader applied without judging) and by what the actor flags on apply,
    /// whichever is lower.
    #[test]
    fn the_first_non_conforming_update_bounds_the_dispute_base() {
        let temp_dir = TempDir::new().unwrap();
        let wallet = create_mock_wallet(&temp_dir);
        let (handler, _rx) = DepositsHandler::new(
            test_local_signer(),
            wallet,
            temp_dir.path().to_path_buf(),
            false,
        );
        let (op, chain) = replica_past_a_fault();
        let arc = handler.get_or_create_ledger(op, "tb1qres".to_string());
        let ledger_key = handler.ledgers.lock().unwrap().keys().next().unwrap().clone();
        arc.write().unwrap().history = chain;

        assert_eq!(handler.first_non_conforming(&ledger_key), Some(4));
        // A later flag doesn't raise it; an earlier one lowers it.
        handler.note_non_conforming(&ledger_key, 6);
        assert_eq!(handler.first_non_conforming(&ledger_key), Some(4));
        // The replica's tip is 6; the dispute forks at 3.
        assert_eq!(
            crate::node::dispute::dispute_base(6, handler.first_non_conforming(&ledger_key)),
            3
        );
        handler.note_non_conforming(&ledger_key, 2);
        assert_eq!(handler.first_non_conforming(&ledger_key), Some(2));
        // A ledger with nothing flagged or found keeps the caller's base.
        assert_eq!(handler.first_non_conforming("00"), None);
    }

    struct RetainEnv;
    impl RetainEnv {
        fn set(n: &str) -> Self {
            std::env::set_var("DEPOSITS_HISTORY_RETAIN", n);
            RetainEnv
        }
    }
    impl Drop for RetainEnv {
        fn drop(&mut self) {
            std::env::remove_var("DEPOSITS_HISTORY_RETAIN");
        }
    }

    fn disk_seqs(handler: &DepositsHandler, ledger_id: &str) -> Vec<u64> {
        handler
            .read_persisted_history(ledger_id)
            .unwrap()
            .iter()
            .map(|u| u.sequence_number)
            .collect()
    }

    /// Compaction runs between an apply and its persist (the replica paths
    /// push under the ledger lock, drop it, then persist; a reimport batch
    /// pushes many). The updates applied but not yet written must still reach
    /// the JSONL. ref3's C lost seqs 53330 and 60353 this way.
    #[test]
    fn compaction_between_apply_and_persist_loses_nothing() {
        let _env = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _retain = RetainEnv::set("3");
        let temp_dir = TempDir::new().unwrap();
        let (handler, arc, ledger_id, op_pk) = compaction_race_fixture(&temp_dir);

        // A batch applied to memory (seqs 10..13), not yet persisted...
        for seq in 10..13u64 {
            arc.write().unwrap().history.push(mk_update(op_pk, seq, seq as u8));
        }
        // ...when the background compaction runs.
        handler.compact_ledger(&ledger_id).unwrap();
        // The apply path's persist, then the next update as usual.
        handler.persist_ledger_to_disk(&ledger_id).unwrap();
        arc.write().unwrap().history.push(mk_update(op_pk, 13, 13));
        handler.persist_ledger_to_disk(&ledger_id).unwrap();

        assert_eq!(disk_seqs(&handler, &ledger_id), (0..14).collect::<Vec<_>>());
    }

    /// Compaction runs while a persist is writing (it reads what to write,
    /// the compaction truncates RAM, then the persist records its cursor).
    /// ref2's replica of F logged exactly this at 2026-09-25 08:32:36:
    /// `compact_ledger: RAM 51001→50000`, then `persist_ledger_to_disk: 51001
    /// entries (+1)`, and lost the next 1,001 updates (121035-122035).
    #[test]
    fn compaction_during_a_persist_loses_nothing() {
        let _env = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _retain = RetainEnv::set("3");
        let temp_dir = TempDir::new().unwrap();
        let (handler, arc, ledger_id, op_pk) = compaction_race_fixture(&temp_dir);
        handler.compact_ledger(&ledger_id).unwrap();

        arc.write().unwrap().history.push(mk_update(op_pk, 10, 10));
        let cursor = *handler.persisted_next_seq.lock().unwrap().get(&ledger_id).unwrap();
        let append = handler
            .persist_append_snapshot(&ledger_id, &arc, cursor)
            .expect("seq 10 to write");
        DepositsHandler::append_updates_to_disk(
            &ledger_id,
            append.state.as_ref(),
            &append.updates,
            &handler.data_dir,
        );
        handler.compact_ledger(&ledger_id).unwrap();
        handler.persist_append_commit(&ledger_id, &append);

        for seq in 11..16u64 {
            arc.write().unwrap().history.push(mk_update(op_pk, seq, seq as u8));
            handler.persist_ledger_to_disk(&ledger_id).unwrap();
        }
        assert_eq!(disk_seqs(&handler, &ledger_id), (0..16).collect::<Vec<_>>());
    }

    /// No trim of RAM drops an update the JSONL does not hold yet: the
    /// periodic cap of a replica's history (a bare `drain` before) and
    /// compaction both go through `cap_history`.
    #[test]
    fn trimming_ram_keeps_unwritten_updates() {
        let _env = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _retain = RetainEnv::set("3");
        let temp_dir = TempDir::new().unwrap();
        let (handler, arc, ledger_id, op_pk) = compaction_race_fixture(&temp_dir);
        handler.compact_ledger(&ledger_id).unwrap();
        for seq in 10..16u64 {
            arc.write().unwrap().history.push(mk_update(op_pk, seq, seq as u8));
        }
        // Six unwritten on top of three written: only the written may go.
        assert_eq!(handler.cap_history(&ledger_id, &arc, 1), 6);
        handler.persist_ledger_to_disk(&ledger_id).unwrap();
        assert_eq!(handler.cap_history(&ledger_id, &arc, 1), 1);
        assert_eq!(disk_seqs(&handler, &ledger_id), (0..16).collect::<Vec<_>>());
    }

    /// A JSONL that skips sequences is found at load and the ledger marked
    /// damaged; writing the missing updates in rebuilds it from the whole file
    /// and clears the mark (the relay fetch and link check are in
    /// `node::ledger_repair`).
    #[test]
    fn a_jsonl_with_holes_is_found_at_load_and_repaired_in_place() {
        let _env = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let temp_dir = TempDir::new().unwrap();
        let wallet = create_mock_wallet(&temp_dir);
        let data_dir = temp_dir.path().to_path_buf();
        let op_pk = {
            let sk = SecretKey::from_slice(&[2u8; 32]).unwrap();
            PublicKey::from_secret_key(&bitcoin::secp256k1::Secp256k1::new(), &sk)
        };
        let all: Vec<SignedLedgerUpdate> =
            (0..12u64).map(|s| mk_update(op_pk, s, s as u8)).collect();
        let ledger_id = {
            let (handler, _rx) =
                DepositsHandler::new(test_local_signer(), wallet.clone(), data_dir.clone(), false);
            let arc = handler.get_or_create_ledger(op_pk, "tb1qtest".to_string());
            let ledger_id = handler.ledgers.lock().unwrap().keys().next().unwrap().clone();
            assert!(handler.damaged_ledgers().is_empty());
            // Written with 4 and 7-8 missing, as the race left replicas.
            for u in &all {
                if ![4, 7, 8].contains(&u.sequence_number) {
                    arc.write().unwrap().history.push(u.clone());
                }
            }
            handler.persist_ledger_to_disk(&ledger_id).unwrap();
            ledger_id
        };

        let (handler, _rx) = DepositsHandler::new(test_local_signer(), wallet, data_dir, false);
        let damaged = handler.damaged_ledgers();
        assert_eq!(damaged.len(), 1);
        assert_eq!(damaged[0].0, ledger_id);
        assert_eq!(
            damaged[0].1.iter().map(|g| (g.first, g.last)).collect::<Vec<_>>(),
            vec![(4, 4), (7, 8)]
        );
        assert_eq!(describe_gaps(&damaged[0].1), "4, 7-8");
        assert!(handler.is_damaged(&ledger_id));

        // One run filled: still damaged, the other remains.
        let left = handler
            .repair_ledger_gaps(&ledger_id, &[all[4].clone()])
            .unwrap();
        assert_eq!(left.iter().map(|g| (g.first, g.last)).collect::<Vec<_>>(), vec![(7, 8)]);
        assert!(handler.is_damaged(&ledger_id));
        let left = handler
            .repair_ledger_gaps(&ledger_id, &[all[7].clone(), all[8].clone()])
            .unwrap();
        assert!(left.is_empty());
        assert!(!handler.is_damaged(&ledger_id));
        assert_eq!(disk_seqs(&handler, &ledger_id), (0..12).collect::<Vec<_>>());
        let arc = handler.ledgers.lock().unwrap().get(&ledger_id).unwrap().clone();
        assert_eq!(
            arc.read().unwrap().history.iter().map(|u| u.sequence_number).collect::<Vec<_>>(),
            (0..12).collect::<Vec<_>>(),
            "rebuilt from the whole file"
        );
        // Appends continue past the tip.
        arc.write().unwrap().history.push(mk_update(op_pk, 12, 12));
        handler.persist_ledger_to_disk(&ledger_id).unwrap();
        assert_eq!(disk_seqs(&handler, &ledger_id), (0..13).collect::<Vec<_>>());
    }

    /// Restart survival: a full (untruncated) JSONL on disk reloads into a
    /// handler that (a) exposes the FULL chain via `read_persisted_history`
    /// (genesis present) and (b) caps the in-memory `history` to the retain
    /// window. Confirms the durable-disk / capped-RAM invariant survives a
    /// daemon restart and no load path assumes a pre-truncated JSONL.
    #[test]
    fn restart_reloads_full_chain_from_disk_and_recaps_ram() {
        struct RetainGuard;
        impl Drop for RetainGuard {
            fn drop(&mut self) {
                std::env::remove_var("DEPOSITS_HISTORY_RETAIN");
            }
        }
        let _env = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("DEPOSITS_HISTORY_RETAIN", "3");
        let _guard = RetainGuard;

        let temp_dir = TempDir::new().unwrap();
        let wallet = create_mock_wallet(&temp_dir);
        let data_dir = temp_dir.path().to_path_buf();

        let op_pk = {
            let sk = SecretKey::from_slice(&[2u8; 32]).unwrap();
            let secp = bitcoin::secp256k1::Secp256k1::new();
            PublicKey::from_secret_key(&secp, &sk)
        };

        const CHAIN_LEN: u64 = 10;
        const GENESIS_TAG: u8 = 0x00;

        // Session 1: build + persist the full chain, compact, then drop.
        let ledger_id = {
            let (handler, _rx) =
                DepositsHandler::new(test_local_signer(), wallet.clone(), data_dir.clone(), false);
            let arc = handler.get_or_create_ledger(op_pk, "tb1qtest".to_string());
            let ledger_id = handler
                .ledgers
                .lock()
                .unwrap()
                .keys()
                .next()
                .unwrap()
                .clone();
            arc.write()
                .unwrap()
                .history
                .push(mk_update(op_pk, 0, GENESIS_TAG));
            handler.persist_ledger_to_disk(&ledger_id).unwrap();
            for seq in 1..CHAIN_LEN {
                arc.write()
                    .unwrap()
                    .history
                    .push(mk_update(op_pk, seq, seq as u8));
                handler.persist_ledger_to_disk(&ledger_id).unwrap();
            }
            handler.compact_ledger(&ledger_id).unwrap();
            ledger_id
        };

        // Session 2: restart — construct a fresh handler over the same data_dir.
        let (handler2, _rx2) =
            DepositsHandler::new(test_local_signer(), wallet, data_dir.clone(), false);

        // Disk still holds the whole chain including genesis.
        let disk = handler2.read_persisted_history(&ledger_id).unwrap();
        let disk_seqs: Vec<u64> = disk.iter().map(|u| u.sequence_number).collect();
        assert_eq!(
            disk_seqs,
            (0..CHAIN_LEN).collect::<Vec<_>>(),
            "restart preserves the full on-disk chain (genesis present)"
        );

        // In-memory history is re-capped to the retain window on load.
        let arc2 = handler2
            .ledgers
            .lock()
            .unwrap()
            .get(&ledger_id)
            .unwrap()
            .clone();
        let in_mem_seqs: Vec<u64> = arc2
            .read()
            .unwrap()
            .history
            .iter()
            .map(|u| u.sequence_number)
            .collect();
        assert_eq!(
            in_mem_seqs,
            vec![7, 8, 9],
            "restart re-applies the in-memory cap (retain=3 tail)"
        );

        // The append cursor starts past the loaded tip: everything loaded is
        // on disk, and the next append writes seq 10 on.
        assert_eq!(
            *handler2
                .persisted_next_seq
                .lock()
                .unwrap()
                .get(&ledger_id)
                .unwrap(),
            CHAIN_LEN,
            "append cursor starts past the loaded tip on restart"
        );
    }

    #[test]
    fn test_validation_context_impl() {
        let temp_dir = TempDir::new().unwrap();
        let wallet = create_mock_wallet(&temp_dir);
        let data_dir = temp_dir.path().to_path_buf();

        let (handler, _rx) = DepositsHandler::new(test_local_signer(), wallet, data_dir, false);

        // our_node_id should return our pubkey
        assert_eq!(handler.our_node_id(), test_pubkey());

        // get_ledger should return None for non-existent ledger
        let other_pk = {
            let sk = SecretKey::from_slice(&[2u8; 32]).unwrap();
            let secp = bitcoin::secp256k1::Secp256k1::new();
            PublicKey::from_secret_key(&secp, &sk)
        };
        assert!(handler.get_ledger(&other_pk, "nonexistent").is_none());

        // Create a ledger and verify we can retrieve it
        let reserves_id = "tb1qtest".to_string();
        handler.get_or_create_ledger(other_pk, reserves_id.clone());
        assert!(handler.get_ledger(&other_pk, &reserves_id).is_some());
    }

    #[test]
    fn test_event_queue() {
        let temp_dir = TempDir::new().unwrap();
        let wallet = create_mock_wallet(&temp_dir);
        let data_dir = temp_dir.path().to_path_buf();

        let (handler, _rx) = DepositsHandler::new(test_local_signer(), wallet, data_dir, false);

        // Initially empty
        assert!(handler.drain_events().is_empty());

        // Emit some events
        handler.emit_event(ProtocolEvent::LedgerSynced {
            operator: test_pubkey(),
            reserves_id: "test".to_string(),
            sequence: 1,
            hash: [0u8; 32],
        });

        // Drain should return the event
        let events = handler.drain_events();
        assert_eq!(events.len(), 1);

        // Queue should be empty after drain
        assert!(handler.drain_events().is_empty());
    }

    /// The consent piggyback reads only the head of the persisted log: the
    /// first `n` updates from genesis, in order, even with RAM truncated —
    /// and the whole chain when it is shorter than `n`.
    #[test]
    fn persisted_history_prefix_reads_genesis_span_only() {
        let temp_dir = TempDir::new().unwrap();
        let wallet = create_mock_wallet(&temp_dir);
        let data_dir = temp_dir.path().to_path_buf();
        let op_pk = {
            let sk = SecretKey::from_slice(&[2u8; 32]).unwrap();
            let secp = bitcoin::secp256k1::Secp256k1::new();
            PublicKey::from_secret_key(&secp, &sk)
        };
        let (handler, _rx) =
            DepositsHandler::new(test_local_signer(), wallet, data_dir.clone(), false);
        let arc = handler.get_or_create_ledger(op_pk, "tb1qtest".to_string());
        let ledger_id = handler.ledgers.lock().unwrap().keys().next().unwrap().clone();
        for seq in 0..10u64 {
            let u = mk_update(op_pk, seq, seq as u8);
            arc.write().unwrap().history.push(u.clone());
            handler.insert_event(&u);
        }
        handler.persist_ledger_to_disk(&ledger_id).unwrap();
        DepositsHandler::truncate_history(&arc, 3);

        let seqs = |v: Vec<SignedLedgerUpdate>| v.iter().map(|u| u.sequence_number).collect::<Vec<_>>();
        let head = handler.read_persisted_history_prefix(&ledger_id, 4).expect("JSONL exists");
        assert_eq!(seqs(head.clone()), vec![0, 1, 2, 3]);
        assert_eq!(head[0].content_hash[0], 0x00, "starts at the genesis update");
        let full = handler.read_persisted_history(&ledger_id).unwrap();
        assert_eq!(head, full[..4].to_vec(), "same updates as the full reader");
        assert_eq!(
            seqs(handler.read_persisted_history_prefix(&ledger_id, 40).unwrap()),
            (0..10).collect::<Vec<_>>(),
            "a chain shorter than n comes back whole"
        );
        assert!(handler.read_persisted_history_prefix("00".repeat(32).as_str(), 4).is_none());
    }
}
