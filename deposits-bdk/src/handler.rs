// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Handler implementation for deposits-bdk
//!
//! Implements `HandlerContext` from deposits-core using BDK wallet and Nostr transport.

use bitcoin::secp256k1::{PublicKey, SecretKey};
use deposits_core::error::HandlerError;
use deposits_core::ledger::Ledger;
use deposits_core::types::{SignedLedgerUpdate, LedgerState};
use deposits_core::ledger::LedgerRole;
use deposits_core::message_validation::{HandlerContext, ValidationContext};
use deposits_core::validation::{LedgerConformanceValidator, LedgerExport, ValidationReport};
use deposits_core::messages::DepositsMessage;
use deposits_core::traits::ProtocolEvent;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use tokio::sync::mpsc;

use crate::wallet::Wallet;
use crate::metrics;
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
    Role { role: LedgerRole },
    State(LedgerState),
    Update(SignedLedgerUpdate),
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

/// The main handler for deposits-bdk
///
/// This implements `HandlerContext` to enable all core protocol logic.
pub struct DepositsHandler {
    /// Our node's public key (derived from Nostr keypair)
    our_node_id: PublicKey,

    /// Our secret key for signing
    secret_key: SecretKey,

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
}

impl DepositsHandler {
    /// Create a new handler
    ///
    /// Returns the handler and a receiver for outbound messages that should
    /// be sent via Nostr transport asynchronously.
    pub fn new(
        secret_key: SecretKey,
        wallet: Arc<Wallet>,
        data_dir: PathBuf,
        enable_metrics_emitter: bool,
    ) -> (Self, mpsc::UnboundedReceiver<OutboundMessage>) {
        use bitcoin::secp256k1::Secp256k1;
        let secp = Secp256k1::new();
        let our_node_id = PublicKey::from_secret_key(&secp, &secret_key);

        let (outbound_tx, outbound_rx) = mpsc::unbounded_channel();

        // Load existing ledgers from disk
        let ledgers = Self::load_ledgers_from_disk(&data_dir);

        let handler = Self {
            our_node_id,
            secret_key,
            ledgers: Mutex::new(ledgers),
            events: Mutex::new(Vec::new()),
            outbound_tx,
            wallet,
            data_dir,
            enable_metrics_emitter,
        };

        (handler, outbound_rx)
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
            let reserves_msats = ledger.state.reserves.amount;
            // Convert to satoshis (divide by 1000)
            let reserves_sats = reserves_msats / 1000;
            reserves_total += reserves_sats;

            // Get deposits amount from the ledger state (HashMap<DepositId, Deposit>)
            let deposits_msats = ledger.state.deposits.values()
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

    /// Save all ledgers to disk.
    /// Takes a snapshot under the mutex (fast), then writes synchronously.
    fn save_ledgers_to_disk(&self) -> Result<(), String> {
        // Take a snapshot while holding the mutex (fast - just clones the data)
        let ledgers_snapshot = {
            let ledgers = self.ledgers.lock().unwrap();
            ledgers.iter()
                .map(|(id, arc)| {
                    let ledger = arc.read().unwrap();
                    (id.clone(), ledger.clone())
                })
                .collect::<Vec<_>>()
        };

        // Perform disk I/O synchronously after releasing the mutex.
        // This ensures the data is on disk before returning, which is critical
        // for CLI processes (the caller must not exit before the write completes).
        Self::save_ledgers_to_disk_impl(ledgers_snapshot, &self.data_dir);

        Ok(())
    }

    /// Implementation of save_ledgers_to_disk (runs in blocking thread)
    fn save_ledgers_to_disk_impl(
        ledgers: Vec<(String, Ledger)>,
        data_dir: &PathBuf,
    ) {
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

    /// Load ledgers from new append-only JSONL format
    /// File: {ledger_id}.jsonl where:
    /// - First line: LedgerState (type: "State")
    /// - Subsequent lines: SignedLedgerUpdate (type: "Update")
    fn load_ledgers_from_jsonl(ledgers_dir: &PathBuf) -> HashMap<String, Arc<RwLock<Ledger>>> {
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
            
            // Read all lines from the JSONL file
            let contents = match fs::read_to_string(&path) {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!("Failed to read ledger {}: {}", ledger_id, e);
                    continue;
                }
            };
            
            let mut role: Option<LedgerRole> = None;
            let mut state: Option<LedgerState> = None;
            let mut updates: Vec<SignedLedgerUpdate> = Vec::new();
            
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
                        updates.push(u);
                    }
                    Err(e) => {
                        tracing::warn!("Failed to parse line in {}: {}", ledger_id, e);
                    }
                }
            }
            
            // Reconstruct the Ledger from role + state + updates
            // Handle backward compatibility: old JSONL files don't have Role line
            let ledger_role = role.unwrap_or_else(|| {
                tracing::warn!("Ledger {} missing role in JSONL, defaulting to Partner", ledger_id);
                LedgerRole::Partner
            });
            
            if let Some(ledger_state) = state {
                // Create Ledger directly from state (it's already the final state)
                // History is preserved for audit purposes
                let ledger = Ledger {
                    state: ledger_state,
                    role: ledger_role,
                    history: updates.clone(),
                };
                let update_count = updates.len();
                ledgers.insert(ledger_id.to_string(), Arc::new(RwLock::new(ledger)));
                tracing::debug!("Loaded ledger {} with {} updates", ledger_id, update_count);
            } else {
                tracing::warn!("Ledger {} missing state", ledger_id);
            }
        }
        
        tracing::debug!("Loaded {} ledgers from JSONL", ledgers.len());
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
    pub fn reload_ledgers(&self) -> usize {
        let disk_ledgers = Self::load_ledgers_from_disk(&self.data_dir);
        let mut updated = 0;

        let mut ledgers = self.ledgers.lock().unwrap();

        for (ledger_id, disk_arc) in disk_ledgers {
            let disk_ledger = disk_arc.read().unwrap();
            let disk_len = disk_ledger.history.len();

            if let Some(memory_arc) = ledgers.get(&ledger_id) {
                let memory_ledger = memory_arc.read().unwrap();
                let memory_len = memory_ledger.history.len();

                if disk_len > memory_len {
                    // Disk has newer state, update in-memory
                    drop(memory_ledger);
                    let mut memory_ledger = memory_arc.write().unwrap();
                    *memory_ledger = disk_ledger.clone();
                    updated += 1;
                    tracing::debug!(
                        "Reloaded ledger {}... ({} -> {} entries)",
                        &ledger_id[..16.min(ledger_id.len())],
                        memory_len,
                        disk_len
                    );
                }
            } else {
                // New ledger on disk, add to in-memory
                ledgers.insert(ledger_id.clone(), Arc::new(RwLock::new(disk_ledger.clone())));
                updated += 1;
                tracing::debug!(
                    "Loaded new ledger {}... ({} entries)",
                    &ledger_id[..16.min(ledger_id.len())],
                    disk_len
                );
            }
        }

        if updated > 0 {
            tracing::info!("Reloaded {} ledgers from disk", updated);
        }

        updated
    }

    /// Process an incoming message from a peer
    pub fn handle_message(
        &self,
        message: DepositsMessage,
        _sender: PublicKey,
    ) -> Result<(), Error> {
        // Dispatch to core handlers based on message type
        // The core handlers use the HandlerContext trait methods we implement below
        match &message {
            DepositsMessage::LedgerUpdate(msg) => {
                let result = deposits_core::handle_ledger_update(self, msg)?;
                tracing::info!("Ledger update result: {:?}", result);
            }
            // Add other message type handlers as needed
            _ => {
                tracing::debug!("Unhandled message type: {:?}", message.message_type());
            }
        }
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
    /// LedgerOpen and ReservesIncrease operations with the UTXO value.
    pub fn get_or_create_ledger(
        &self,
        operator: PublicKey,
        reserves_address: String,
    ) -> Arc<RwLock<Ledger>> {
        use deposits_core::types::LedgerState;

        // Get current block height for genesis_block
        let genesis_block = self.wallet.get_block_height().unwrap_or(0);

        // Compute ledger_id from genesis parameters
        let ledger_id_bytes = LedgerState::compute_ledger_id(&operator, &reserves_address, genesis_block);
        let ledger_id = hex::encode(ledger_id_bytes);

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
                    reserves_address.clone(), // Use reserves_address as ledger_address for BDK
                    genesis_block,
                )))
            })
            .clone();

        // If we created a new ledger for ourselves, add initial operations
        if is_new && operator == self.our_node_id {
            // Get reserves balance from wallet
            let reserves_balance = self.wallet.get_reserves_balance().unwrap_or(0);

            // Add LedgerOpen operation
            {
                let mut ledger_guard = ledger.write().unwrap();
                let operation = deposits_core::messages::LedgerOperation::LedgerOpen {
                    operator_id: operator,
                    reserves_id: reserves_address.clone(),
                    ledger_address: reserves_address.clone(),
                    genesis_block,
                    collateral_enforcement_block: 0, // Default to immediate enforcement
                };
                if let Err(e) = ledger_guard.append_operation(
                    operation,
                    deposits_core::messages::consts::LEDGER_OPEN_REQUEST,
                ) {
                    tracing::error!("Failed to append LedgerOpen: {:?}", e);
                } else {
                    self.sign_ledger_update(&mut ledger_guard);
                }
            }

            // Add ReservesIncrease operation with UTXO value
            if reserves_balance > 0 {
                let mut ledger_guard = ledger.write().unwrap();
                let operation = deposits_core::messages::LedgerOperation::ReservesIncrease {
                    reserves_id: reserves_address.clone(),
                    new_amount: reserves_balance,
                };
                if let Err(e) = ledger_guard.append_operation(
                    operation,
                    deposits_core::messages::consts::RESERVES_INCREASE,
                ) {
                    tracing::error!("Failed to append ReservesIncrease: {:?}", e);
                } else {
                    self.sign_ledger_update(&mut ledger_guard);
                }
            }

            // Save to disk
            drop(ledgers); // Release lock before saving
            if let Err(e) = self.save_ledgers_to_disk() {
                tracing::error!("Failed to save ledgers after creation: {}", e);
            }
        } else if is_new {
            // New ledger for a partner, just save
            drop(ledgers);
            if let Err(e) = self.save_ledgers_to_disk() {
                tracing::error!("Failed to save ledgers after creation: {}", e);
            }
        }

        ledger
    }

    /// Persist a specific ledger to disk
    pub fn persist_ledger(&self, ledger_id: &str) -> Result<(), String> {
        let ledger_clone = {
            let ledgers = self.ledgers.lock().unwrap();
            let ledger_arc = ledgers.get(ledger_id)
                .ok_or_else(|| format!("Ledger not found: {}", ledger_id))?;
            let ledger = ledger_arc.read().unwrap();
            (ledger_id.to_string(), ledger.clone())
        };

        Self::save_single_ledger_to_disk(ledger_clone, &self.data_dir);
        Ok(())
    }

    /// Save a single ledger to its JSONL file
    fn save_single_ledger_to_disk(
        (ledger_id, ledger): (String, Ledger),
        data_dir: &PathBuf,
    ) {
        let ledgers_dir = data_dir.join("ledgers");
        if !ledgers_dir.exists() {
            if let Err(e) = fs::create_dir_all(&ledgers_dir) {
                tracing::error!("Failed to create ledgers dir: {}", e);
                return;
            }
        }

        let mut lines = Vec::with_capacity(2 + ledger.history.len());

        let role_row = LedgerLogRow::Role { role: ledger.role };
        if let Ok(line) = serde_json::to_string(&role_row) {
            lines.push(line);
        }

        let state_row = LedgerLogRow::State(ledger.state.clone());
        if let Ok(line) = serde_json::to_string(&state_row) {
            lines.push(line);
        }

        for update in &ledger.history {
            let update_row = LedgerLogRow::Update(update.clone());
            if let Ok(line) = serde_json::to_string(&update_row) {
                lines.push(line);
            }
        }

        let ledger_file = ledgers_dir.join(format!("{}.jsonl", ledger_id));
        let contents = lines.join("\n");
        if let Err(e) = fs::write(&ledger_file, contents) {
            tracing::error!("Failed to write ledger file {}: {}", ledger_id, e);
        }
    }

    /// Sign the last update in a ledger with our operator key
    fn sign_ledger_update(&self, ledger: &mut Ledger) {
        use bitcoin::secp256k1::{Secp256k1, Message};
        use bitcoin::hashes::{Hash, sha256};

        if let Some(update) = ledger.history.last_mut() {
            // Compute signature over update content
            let mut sig_input = Vec::new();
            sig_input.extend_from_slice(&update.sequence_number.to_le_bytes());
            sig_input.extend_from_slice(&update.previous_hash);
            sig_input.extend_from_slice(&update.current_hash);
            sig_input.extend_from_slice(&update.message);

            let hash = sha256::Hash::hash(&sig_input);
            let secp = Secp256k1::new();
            let msg = Message::from_digest(*hash.as_byte_array());
            let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &self.secret_key);
            let sig = secp.sign_schnorr(&msg, &keypair);

            update.operator_signature = sig.serialize();
            tracing::debug!("Signed update seq={}", update.sequence_number);
        }
    }

    /// Import a ledger from an export file (JSON or binary)
    ///
    /// This validates the ledger using LedgerConformanceValidator before storing it.
    /// The ledger will be stored with the Partner role since it's from another operator.
    ///
    /// If the ledger already exists locally, this will apply any newer updates
    /// from the export instead of failing. This is essential for custody recovery
    /// scenarios where a quorum member already has the ledger but needs the
    /// CustodyAcquire updates to become the new operator.
    pub fn import_ledger(&self, export: LedgerExport) -> Result<(ValidationReport, Arc<RwLock<Ledger>>), String> {
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
            let new_updates: Vec<_> = export.updates.iter()
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

            // Persist to disk
            self.save_ledgers_to_disk()?;

            return Ok((report, ledger_arc));
        }

        // Create the ledger from the validated export
        let ledger = Ledger::from_export(export)
            .map_err(|e| format!("Failed to reconstruct ledger: {}", e))?;

        // Store the ledger
        let ledger_arc = Arc::new(RwLock::new(ledger));
        {
            let mut ledgers = self.ledgers.lock().unwrap();
            ledgers.insert(ledger_id, ledger_arc.clone());
        }

        // Persist to disk
        self.save_ledgers_to_disk()?;

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

        let mut ledger = ledger_arc.write().unwrap();
        let mut applied = 0;

        for update in updates {
            // Verify this update follows the current chain
            if update.previous_hash != ledger.tail_hash() {
                return Err(format!(
                    "Update {} has wrong previous_hash (expected {}, got {})",
                    update.sequence_number,
                    hex::encode(&ledger.tail_hash()[..8]),
                    hex::encode(&update.previous_hash[..8])
                ));
            }

            // Append the update
            ledger.append_signed_update(update);
            applied += 1;
        }

        drop(ledger); // Release write lock

        // Persist to disk
        self.save_ledgers_to_disk()?;

        Ok(applied)
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
        // In BDK implementation, reserves are on-chain UTXOs, not commitment tx outputs
        // Return the wallet balance for reserves
        self.wallet.get_reserves_balance().ok()
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

    fn recovery_manager(
        &self,
    ) -> Option<Arc<Mutex<deposits_core::recovery::RecoveryManager>>> {
        // TODO: Implement recovery manager
        None
    }

    fn our_secret_key(&self) -> Option<SecretKey> {
        Some(self.secret_key)
    }

    fn current_block_height(&self) -> u32 {
        self.wallet.get_block_height().unwrap_or(0)
    }

    fn persist_ledger(&self, _operator: &PublicKey, _reserves_id: &str) -> Result<(), String> {
        // Save all ledgers to disk (could optimize to save just the specific one)
        self.save_ledgers_to_disk()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_secret_key() -> SecretKey {
        SecretKey::from_slice(&[1u8; 32]).unwrap()
    }

    fn test_pubkey() -> PublicKey {
        use bitcoin::secp256k1::Secp256k1;
        let secp = Secp256k1::new();
        PublicKey::from_secret_key(&secp, &test_secret_key())
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

        let (handler, _rx) = DepositsHandler::new(test_secret_key(), wallet, data_dir, false);

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
            let (handler, _rx) = DepositsHandler::new(
                test_secret_key(),
                wallet.clone(),
                data_dir.clone(),
                false,
            );

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
            let (handler, _rx) = DepositsHandler::new(
                test_secret_key(),
                wallet,
                data_dir,
                false,
            );

            let ledgers = handler.ledgers.lock().unwrap();
            assert_eq!(ledgers.len(), 1);
        }
    }

    #[test]
    fn test_validation_context_impl() {
        let temp_dir = TempDir::new().unwrap();
        let wallet = create_mock_wallet(&temp_dir);
        let data_dir = temp_dir.path().to_path_buf();

        let (handler, _rx) = DepositsHandler::new(test_secret_key(), wallet, data_dir, false);

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

        let (handler, _rx) = DepositsHandler::new(test_secret_key(), wallet, data_dir, false);

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
}
