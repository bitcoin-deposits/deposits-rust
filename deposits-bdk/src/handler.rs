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
    pub fn get_or_create_ledger(
        &self,
        operator: PublicKey,
        reserves_id: String,
    ) -> Arc<RwLock<Ledger>> {
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
                    String::new(),
                )))
            })
            .clone();

        // If we created a new ledger, save to disk
        if is_new {
            drop(ledgers); // Release lock before saving
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
