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
use std::collections::HashMap;
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

/// The main handler for deposits-bdk
///
/// This implements `HandlerContext` to enable all core protocol logic.
pub struct DepositsHandler {
    /// Our node's public key (derived from Nostr keypair)
    our_node_id: PublicKey,

    /// Our secret key for signing
    secret_key: SecretKey,

    /// Ledgers indexed by (operator, partner)
    ledgers: Mutex<HashMap<(PublicKey, PublicKey), Arc<RwLock<Ledger>>>>,

    /// Pending events to be processed
    events: Mutex<Vec<ProtocolEvent>>,

    /// Outbound message queue (for async sending)
    outbound_tx: mpsc::UnboundedSender<OutboundMessage>,

    /// BDK wallet for on-chain operations
    wallet: Arc<Wallet>,
}

impl DepositsHandler {
    /// Create a new handler
    ///
    /// Returns the handler and a receiver for outbound messages that should
    /// be sent via Nostr transport asynchronously.
    pub fn new(
        secret_key: SecretKey,
        wallet: Arc<Wallet>,
    ) -> (Self, mpsc::UnboundedReceiver<OutboundMessage>) {
        use bitcoin::secp256k1::Secp256k1;
        let secp = Secp256k1::new();
        let our_node_id = PublicKey::from_secret_key(&secp, &secret_key);

        let (outbound_tx, outbound_rx) = mpsc::unbounded_channel();

        let handler = Self {
            our_node_id,
            secret_key,
            ledgers: Mutex::new(HashMap::new()),
            events: Mutex::new(Vec::new()),
            outbound_tx,
            wallet,
        };

        (handler, outbound_rx)
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

    /// Create or get a ledger for the given operator/partner pair
    pub fn get_or_create_ledger(
        &self,
        operator: PublicKey,
        partner: PublicKey,
    ) -> Arc<RwLock<Ledger>> {
        let mut ledgers = self.ledgers.lock().unwrap();
        ledgers
            .entry((operator, partner))
            .or_insert_with(|| {
                let role = if operator == self.our_node_id {
                    deposits_core::LedgerRole::Operator
                } else {
                    deposits_core::LedgerRole::Partner
                };
                Arc::new(RwLock::new(Ledger::new(
                    operator,
                    partner,
                    role,
                    vec![],
                    String::new(),
                )))
            })
            .clone()
    }
}

// ============================================================================
// ValidationContext Implementation
// ============================================================================

impl ValidationContext for DepositsHandler {
    fn get_ledger(&self, operator: &PublicKey, partner: &PublicKey) -> Option<Arc<RwLock<Ledger>>> {
        let ledgers = self.ledgers.lock().unwrap();
        ledgers.get(&(*operator, *partner)).cloned()
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

    fn persist_ledger(&self, operator: &PublicKey, partner: &PublicKey) -> Result<(), String> {
        // TODO: Implement persistence
        let _ = (operator, partner);
        Ok(())
    }
}
