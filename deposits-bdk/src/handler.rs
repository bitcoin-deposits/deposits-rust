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
use crate::Error;

/// Outbound message to be sent via Nostr
#[derive(Debug)]
pub struct OutboundMessage {
    pub peer: PublicKey,
    pub message: DepositsMessage,
}

/// Serializable ledger entry for persistence
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LedgerEntry {
    operator: String,
    reserves_id: String,
    ledger: Ledger,
}

/// The main handler for deposits-bdk
///
/// This implements `HandlerContext` to enable all core protocol logic.
pub struct DepositsHandler {
    /// Our node's public key (derived from Nostr keypair)
    our_node_id: PublicKey,

    /// Our secret key for signing
    secret_key: SecretKey,

    /// Ledgers indexed by (operator, reserves_id)
    pub ledgers: Mutex<HashMap<(PublicKey, String), Arc<RwLock<Ledger>>>>,

    /// Pending events to be processed
    events: Mutex<Vec<ProtocolEvent>>,

    /// Outbound message queue (for async sending)
    outbound_tx: mpsc::UnboundedSender<OutboundMessage>,

    /// BDK wallet for on-chain operations
    wallet: Arc<Wallet>,

    /// Data directory for persistence
    data_dir: PathBuf,
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
        };

        (handler, outbound_rx)
    }

    /// Load ledgers from disk
    fn load_ledgers_from_disk(data_dir: &PathBuf) -> HashMap<(PublicKey, String), Arc<RwLock<Ledger>>> {
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
            let operator = match entry.operator.parse::<PublicKey>() {
                Ok(pk) => pk,
                Err(e) => {
                    tracing::warn!("Invalid operator pubkey in ledger: {}", e);
                    continue;
                }
            };
            // reserves_id is now a String, no parsing needed
            ledgers.insert((operator, entry.reserves_id), Arc::new(RwLock::new(entry.ledger)));
        }

        tracing::info!("Loaded {} ledgers from disk", ledgers.len());
        ledgers
    }

    /// Save all ledgers to disk
    fn save_ledgers_to_disk(&self) -> Result<(), String> {
        // Ensure data directory exists
        if !self.data_dir.exists() {
            fs::create_dir_all(&self.data_dir)
                .map_err(|e| format!("Failed to create data dir: {}", e))?;
        }

        let ledgers = self.ledgers.lock().unwrap();
        let entries: Vec<LedgerEntry> = ledgers
            .iter()
            .map(|((operator, reserves_id), ledger_arc)| {
                let ledger = ledger_arc.read().unwrap();
                LedgerEntry {
                    operator: operator.to_string(),
                    reserves_id: reserves_id.clone(),
                    ledger: ledger.clone(),
                }
            })
            .collect();

        let contents = serde_json::to_string_pretty(&entries)
            .map_err(|e| format!("Failed to serialize ledgers: {}", e))?;

        let ledgers_file = self.data_dir.join("ledgers.json");
        fs::write(&ledgers_file, contents)
            .map_err(|e| format!("Failed to write ledgers file: {}", e))?;

        tracing::info!("Saved {} ledgers to disk", entries.len());
        Ok(())
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
        reserves_id: String,
    ) -> Arc<RwLock<Ledger>> {
        // Get current block height for genesis_block
        let genesis_block = self.wallet.get_block_height().unwrap_or(0);

        let mut ledgers = self.ledgers.lock().unwrap();
        let key = (operator, reserves_id.clone());
        let is_new = !ledgers.contains_key(&key);
        let ledger = ledgers
            .entry(key)
            .or_insert_with(|| {
                let role = if operator == self.our_node_id {
                    deposits_core::LedgerRole::Operator
                } else {
                    deposits_core::LedgerRole::Partner
                };
                Arc::new(RwLock::new(Ledger::new(
                    operator,
                    reserves_id.clone(),
                    role,
                    vec![],
                    reserves_id.clone(), // Use reserves_id as ledger_address for BDK
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
                    reserves_id: reserves_id.clone(),
                    ledger_address: reserves_id.clone(),
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
                    reserves_id: reserves_id.clone(),
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
    pub fn persist_ledger(&self, _operator: &PublicKey, _reserves_id: &str) -> Result<(), String> {
        // Save all ledgers to disk (could optimize to save just the specific one)
        self.save_ledgers_to_disk()
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
    pub fn import_ledger(&self, export: LedgerExport) -> Result<(ValidationReport, Arc<RwLock<Ledger>>), String> {
        // Check if this is our own ledger (not allowed to import our own)
        if export.operator_id == self.our_node_id {
            return Err("Cannot import your own ledger. Use 'ledger open' instead.".to_string());
        }

        // Check if ledger already exists
        let key = (export.operator_id, export.reserves_id.clone());
        {
            let ledgers = self.ledgers.lock().unwrap();
            if ledgers.contains_key(&key) {
                return Err(format!(
                    "Ledger already exists for operator {} with reserves {}",
                    export.operator_id, export.reserves_id
                ));
            }
        }

        // Validate the export
        let report = LedgerConformanceValidator::validate(&export)
            .map_err(|e| format!("Validation failed: {}", e))?;

        if !report.is_valid {
            return Err(format!(
                "Ledger is not conforming: {} warnings, {} invalid signatures",
                report.warnings.len(),
                report.signatures.invalid_signatures.len()
            ));
        }

        // Create the ledger from the validated export
        let ledger = Ledger::from_export(export)
            .map_err(|e| format!("Failed to reconstruct ledger: {}", e))?;

        // Store the ledger
        let ledger_arc = Arc::new(RwLock::new(ledger));
        {
            let mut ledgers = self.ledgers.lock().unwrap();
            ledgers.insert(key, ledger_arc.clone());
        }

        // Persist to disk
        self.save_ledgers_to_disk()?;

        Ok((report, ledger_arc))
    }
}

// ============================================================================
// ValidationContext Implementation
// ============================================================================

impl ValidationContext for DepositsHandler {
    fn get_ledger(&self, operator: &PublicKey, reserves_id: &str) -> Option<Arc<RwLock<Ledger>>> {
        let ledgers = self.ledgers.lock().unwrap();
        ledgers.get(&(*operator, reserves_id.to_string())).cloned()
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
