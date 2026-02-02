// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Bitcoin Deposits Protocol Handler
//!
//! The core protocol state machine, generic over Lightning implementation.
//!
//! This handler implements the deposits protocol logic using adapter traits,
//! allowing it to work with any Lightning implementation (LDK, CLN, etc.).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

use bitcoin::secp256k1::PublicKey;

use crate::ledger::Ledger;
use crate::traits::{
    Broadcaster, ChainSource, ChannelRegistry, EventEmitter, Logger, LogLevel,
    MessageHandler, PaymentTracker, PeerTransport, SignatureProvider, Storage,
    HandleError,
};

/// Information about a pending ACK
#[derive(Clone, Debug)]
pub struct PendingAck {
    /// The message type awaiting ACK
    pub message_type: u16,
    /// When the message was sent (unix timestamp)
    pub timestamp: u64,
    /// The peer we're waiting for ACK from
    pub peer: PublicKey,
}

/// The main protocol handler
///
/// This struct manages all protocol state and implements message handling.
/// It is generic over the adapter traits, allowing it to work with any
/// Lightning implementation.
pub struct Handler<S, T, P, C, B, H, G, E, L>
where
    S: Storage,
    T: PeerTransport,
    P: PaymentTracker,
    C: ChannelRegistry,
    B: Broadcaster,
    H: ChainSource,
    G: SignatureProvider,
    E: EventEmitter,
    L: Logger,
{
    /// Our node's public key (derived from signer)
    node_id: PublicKey,

    /// Ledgers indexed by (operator, partner)
    /// Uses Arc to enable sharing with external systems (e.g., DepositsHandler)
    ledgers: Arc<Mutex<HashMap<(PublicKey, String), Arc<RwLock<Ledger>>>>>,

    /// Pending ACKs: message_hash -> (message_type, timestamp, peer)
    /// Tracks which messages are waiting for acknowledgment
    /// Uses Arc to enable sharing with external systems (e.g., DepositsHandler)
    pending_acks: Arc<Mutex<HashMap<[u8; 32], PendingAck>>>,

    /// Storage
    storage: Arc<S>,

    /// Peer transport
    transport: Arc<T>,

    /// Payment tracker
    payments: Arc<P>,

    /// Channel registry
    channels: Arc<C>,

    /// Transaction broadcaster
    broadcaster: Arc<B>,

    /// Chain source
    chain: Arc<H>,

    /// Signature provider
    signer: Arc<G>,

    /// Event emitter
    events: Arc<E>,

    /// Logger
    logger: Arc<L>,
}

impl<S, T, P, C, B, H, G, E, L> Handler<S, T, P, C, B, H, G, E, L>
where
    S: Storage,
    T: PeerTransport,
    P: PaymentTracker,
    C: ChannelRegistry,
    B: Broadcaster,
    H: ChainSource,
    G: SignatureProvider,
    E: EventEmitter,
    L: Logger,
{
    /// Create a new handler with fresh state
    pub fn new(
        storage: Arc<S>,
        transport: Arc<T>,
        payments: Arc<P>,
        channels: Arc<C>,
        broadcaster: Arc<B>,
        chain: Arc<H>,
        signer: Arc<G>,
        events: Arc<E>,
        logger: Arc<L>,
    ) -> Self {
        Self::with_shared_state(
            Arc::new(Mutex::new(HashMap::new())),
            Arc::new(Mutex::new(HashMap::new())),
            storage,
            transport,
            payments,
            channels,
            broadcaster,
            chain,
            signer,
            events,
            logger,
        )
    }

    /// Create a new handler with shared ledger storage (backwards compatible)
    ///
    /// This constructor allows the handler to share ledger state with an external
    /// system (e.g., DepositsHandler in deposits-ldk). Operations on the handler
    /// will affect the shared ledgers.
    pub fn with_ledgers(
        ledgers: Arc<Mutex<HashMap<(PublicKey, String), Arc<RwLock<Ledger>>>>>,
        storage: Arc<S>,
        transport: Arc<T>,
        payments: Arc<P>,
        channels: Arc<C>,
        broadcaster: Arc<B>,
        chain: Arc<H>,
        signer: Arc<G>,
        events: Arc<E>,
        logger: Arc<L>,
    ) -> Self {
        Self::with_shared_state(
            ledgers,
            Arc::new(Mutex::new(HashMap::new())),
            storage,
            transport,
            payments,
            channels,
            broadcaster,
            chain,
            signer,
            events,
            logger,
        )
    }

    /// Create a new handler with fully shared state
    ///
    /// This constructor allows sharing both ledgers and pending_acks with an
    /// external system (e.g., DepositsHandler in deposits-ldk).
    pub fn with_shared_state(
        ledgers: Arc<Mutex<HashMap<(PublicKey, String), Arc<RwLock<Ledger>>>>>,
        pending_acks: Arc<Mutex<HashMap<[u8; 32], PendingAck>>>,
        storage: Arc<S>,
        transport: Arc<T>,
        payments: Arc<P>,
        channels: Arc<C>,
        broadcaster: Arc<B>,
        chain: Arc<H>,
        signer: Arc<G>,
        events: Arc<E>,
        logger: Arc<L>,
    ) -> Self {
        let node_id = signer.node_pubkey();
        Self {
            node_id,
            ledgers,
            pending_acks,
            storage,
            transport,
            payments,
            channels,
            broadcaster,
            chain,
            signer,
            events,
            logger,
        }
    }

    /// Get a reference to the shared ledgers
    ///
    /// This allows external systems to access the ledger storage for sharing.
    pub fn ledgers(&self) -> &Arc<Mutex<HashMap<(PublicKey, String), Arc<RwLock<Ledger>>>>> {
        &self.ledgers
    }

    /// Get a reference to the shared pending ACKs
    ///
    /// This allows external systems to access the pending ACK state for sharing.
    pub fn pending_acks(&self) -> &Arc<Mutex<HashMap<[u8; 32], PendingAck>>> {
        &self.pending_acks
    }

    // ========================================================================
    // ACK Management
    // ========================================================================

    /// Register a message as pending ACK
    ///
    /// Called when sending a message that requires acknowledgment.
    /// Returns the message hash for tracking.
    pub fn register_pending_ack(&self, hash: [u8; 32], message_type: u16, peer: PublicKey) {
        let ack = PendingAck {
            message_type,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            peer,
        };
        self.pending_acks.lock().unwrap().insert(hash, ack);
        self.logger.log(
            LogLevel::Debug,
            &format!("Registered pending ACK for hash {:02x?}... type={:#06x}", &hash[..4], message_type),
        );
    }

    /// Complete a pending ACK
    ///
    /// Called when an ACK is received for a previously sent message.
    /// Returns the pending ACK info if found.
    pub fn complete_pending_ack(&self, hash: &[u8; 32]) -> Option<PendingAck> {
        let result = self.pending_acks.lock().unwrap().remove(hash);
        if let Some(ref ack) = result {
            self.logger.log(
                LogLevel::Debug,
                &format!("Completed pending ACK for hash {:02x?}... type={:#06x}", &hash[..4], ack.message_type),
            );
        }
        result
    }

    /// Check if a message hash has a pending ACK
    pub fn has_pending_ack(&self, hash: &[u8; 32]) -> bool {
        self.pending_acks.lock().unwrap().contains_key(hash)
    }

    /// Get all pending ACKs (for cleanup/timeout handling)
    pub fn get_all_pending_acks(&self) -> Vec<([u8; 32], PendingAck)> {
        self.pending_acks.lock().unwrap()
            .iter()
            .map(|(h, a)| (*h, a.clone()))
            .collect()
    }

    /// Get our node ID
    pub fn node_id(&self) -> PublicKey {
        self.node_id
    }

    /// Get the current block height
    pub fn current_height(&self) -> u32 {
        self.chain.current_height()
    }

    /// Get a ledger by (operator, reserves_id)
    pub fn get_ledger(&self, operator: PublicKey, reserves_id: &str) -> Option<Arc<RwLock<Ledger>>> {
        let ledgers = self.ledgers.lock().unwrap();
        ledgers.get(&(operator, reserves_id.to_string())).cloned()
    }

    /// List all reserves_ids where we are the operator
    pub fn list_operator_ledgers(&self) -> Vec<String> {
        let ledgers = self.ledgers.lock().unwrap();
        ledgers.keys()
            .filter(|(op, _)| *op == self.node_id)
            .map(|(_, reserves_id)| reserves_id.clone())
            .collect()
    }

    /// List all operators where we are the reserves
    pub fn list_partner_ledgers(&self) -> Vec<PublicKey> {
        let ledgers = self.ledgers.lock().unwrap();
        let node_id_str = self.node_id.to_string();
        ledgers.keys()
            .filter(|(_, reserves_id)| *reserves_id == node_id_str)
            .map(|(op, _)| *op)
            .collect()
    }

    /// List all ledgers (both operator and partner roles)
    pub fn list_all_ledgers(&self) -> Vec<(PublicKey, String)> {
        let ledgers = self.ledgers.lock().unwrap();
        ledgers.keys().cloned().collect()
    }

    // ========================================================================
    // Ledger Management
    // ========================================================================

    /// Create a new ledger as operator with the given reserves_id
    pub fn create_operator_ledger(
        &self,
        reserves_id: String,
        ledger_address: String,
        genesis_block: u32,
    ) -> Result<(), HandleError> {
        let key = (self.node_id, reserves_id.clone());

        let mut ledgers = self.ledgers.lock().unwrap();
        if ledgers.contains_key(&key) {
            return Err(HandleError::ValidationFailed(
                "Ledger already exists".to_string(),
            ));
        }

        let ledger = Ledger::new_as_operator(self.node_id, reserves_id.clone(), ledger_address, genesis_block);
        ledgers.insert(key, Arc::new(RwLock::new(ledger)));

        self.logger.log(
            LogLevel::Info,
            &format!("Created operator ledger with reserves_id {}", reserves_id),
        );

        Ok(())
    }

    /// Create a new ledger as partner with the given operator
    /// Note: For LDK compatibility, reserves_id is our node_id as string
    pub fn create_partner_ledger(
        &self,
        operator: PublicKey,
        ledger_address: String,
        genesis_block: u32,
    ) -> Result<(), HandleError> {
        let reserves_id = self.node_id.to_string();
        let key = (operator, reserves_id.clone());

        let mut ledgers = self.ledgers.lock().unwrap();
        if ledgers.contains_key(&key) {
            return Err(HandleError::ValidationFailed(
                "Ledger already exists".to_string(),
            ));
        }

        let ledger = Ledger::new_as_partner(operator, reserves_id, ledger_address, genesis_block);
        ledgers.insert(key, Arc::new(RwLock::new(ledger)));

        self.logger.log(
            LogLevel::Info,
            &format!("Created partner ledger with operator {}", operator),
        );

        Ok(())
    }

    /// Remove a ledger (used for cleanup after close)
    pub fn remove_ledger(&self, operator: PublicKey, reserves_id: &str) -> bool {
        let mut ledgers = self.ledgers.lock().unwrap();
        ledgers.remove(&(operator, reserves_id.to_string())).is_some()
    }

    /// Check if we have a ledger with this reserves_id (as operator)
    pub fn has_ledger_with(&self, reserves_id: &str) -> bool {
        let ledgers = self.ledgers.lock().unwrap();
        ledgers.contains_key(&(self.node_id, reserves_id.to_string()))
    }

    /// Get our role with a reserves_id (Operator or None for BDK)
    pub fn role_with(&self, reserves_id: &str) -> Option<crate::ledger::LedgerRole> {
        let ledgers = self.ledgers.lock().unwrap();
        if ledgers.contains_key(&(self.node_id, reserves_id.to_string())) {
            Some(crate::ledger::LedgerRole::Operator)
        } else {
            None
        }
    }

    // ========================================================================
    // Ledger Query Operations
    // ========================================================================

    /// Get ledger hash for a specific ledger
    pub fn get_ledger_hash(&self, operator: PublicKey, reserves_id: &str) -> Option<[u8; 32]> {
        self.get_ledger(operator, reserves_id).map(|arc| {
            let ledger = arc.read().unwrap();
            ledger.hash()
        })
    }

    /// Get ledger sequence number
    pub fn get_ledger_sequence(&self, operator: PublicKey, reserves_id: &str) -> Option<u64> {
        self.get_ledger(operator, reserves_id).map(|arc| {
            let ledger = arc.read().unwrap();
            ledger.sequence()
        })
    }

    /// Get total deposit balance (msat) for a ledger
    pub fn get_ledger_deposit_balance(&self, operator: PublicKey, reserves_id: &str) -> Option<u64> {
        self.get_ledger(operator, reserves_id).map(|arc| {
            let ledger = arc.read().unwrap();
            ledger.total_deposit_balance()
        })
    }

    /// Get reserves amount (sats) for a ledger
    pub fn get_ledger_reserves(&self, operator: PublicKey, reserves_id: &str) -> Option<u64> {
        self.get_ledger(operator, reserves_id).map(|arc| {
            let ledger = arc.read().unwrap();
            ledger.reserves_amount()
        })
    }

    /// Check if a ledger has sufficient reserves
    pub fn ledger_has_sufficient_reserves(&self, operator: PublicKey, reserves_id: &str) -> bool {
        self.get_ledger(operator, reserves_id)
            .map(|arc| {
                let ledger = arc.read().unwrap();
                ledger.has_sufficient_reserves()
            })
            .unwrap_or(false)
    }

    // ========================================================================
    // Message Processing
    // ========================================================================

    /// Process a V2 protocol message
    pub fn process_message_v2(
        &self,
        sender: PublicKey,
        message: &crate::messages::DepositsMessage,
    ) -> Result<Option<crate::messages::DepositsMessage>, HandleError> {
        use crate::messages::DepositsMessage;

        self.logger.log(
            LogLevel::Debug,
            &format!(
                "Processing {} from {}",
                message.variant_name(),
                sender
            ),
        );

        match message {
            DepositsMessage::LedgerUpdate(msg) => {
                self.handle_ledger_update(sender, msg)
            }
            DepositsMessage::LedgerUpdateResponse(msg) => {
                self.handle_ledger_update_response(sender, msg)
            }
            DepositsMessage::Handshake(msg) => {
                self.handle_handshake(sender, msg)
            }
            DepositsMessage::HandshakeResponse(msg) => {
                self.handle_handshake_response(sender, msg)
            }
            DepositsMessage::Sync(msg) => {
                self.handle_sync(sender, msg)
            }
            DepositsMessage::SyncResponse(msg) => {
                self.handle_sync_response(sender, msg)
            }
            DepositsMessage::Recovery(msg) => {
                self.handle_recovery(sender, msg)
            }
            DepositsMessage::RecoveryResponse(msg) => {
                self.handle_recovery_response(sender, msg)
            }
            DepositsMessage::Coordination(msg) => {
                self.handle_coordination(sender, msg)
            }
            DepositsMessage::CoordinationResponse(msg) => {
                self.handle_coordination_response(sender, msg)
            }
            DepositsMessage::Relay(msg) => {
                self.handle_relay(sender, msg)
            }
            DepositsMessage::RelayResponse(msg) => {
                self.handle_relay_response(sender, msg)
            }
            DepositsMessage::ReservesAddOutput(msg) => {
                self.handle_reserves_add_output(sender, msg)
            }
            DepositsMessage::ReservesRemoveOutput(msg) => {
                self.handle_reserves_remove_output(sender, msg)
            }
        }
    }

    // ========================================================================
    // Message Handlers (stubs - to be implemented)
    // ========================================================================

    fn handle_ledger_update(
        &self,
        sender: PublicKey,
        msg: &crate::messages::LedgerUpdateMsg,
    ) -> Result<Option<crate::messages::DepositsMessage>, HandleError> {
        self.logger.log(
            LogLevel::Debug,
            &format!(
                "Ledger update from {} - seq={}, op={:?}",
                sender, msg.sequence_number, msg.operation
            ),
        );

        // Get the ledger
        let ledger_arc = self.get_ledger(msg.operator_id, &msg.reserves_id)
            .ok_or(HandleError::UnknownLedger {
                operator: msg.operator_id,
                reserves_id: msg.reserves_id.clone(),
            })?;

        // Validate and apply the update
        {
            let mut ledger = ledger_arc.write().unwrap();

            // Verify sequence number
            if msg.sequence_number != ledger.sequence() + 1 {
                return Err(HandleError::ValidationFailed(format!(
                    "Sequence mismatch: expected {}, got {}",
                    ledger.sequence() + 1,
                    msg.sequence_number
                )));
            }

            // Verify previous hash
            if msg.previous_hash != ledger.hash() {
                return Err(HandleError::ValidationFailed(
                    "Previous hash mismatch".to_string(),
                ));
            }

            // Verify operator signature
            if !self.signer.verify_schnorr(
                &msg.operator_id,
                msg.current_hash,
                &msg.operator_signature,
            ) {
                return Err(HandleError::ValidationFailed(
                    "Invalid operator signature".to_string(),
                ));
            }

            // Apply the operation
            let update = ledger.apply_operation(&msg.operation)
                .map_err(|e| HandleError::ValidationFailed(e.to_string()))?;

            // Verify computed hash matches
            if update.current_hash != msg.current_hash {
                return Err(HandleError::ValidationFailed(
                    "Hash mismatch after applying operation".to_string(),
                ));
            }
        }

        // Sign the response
        let partner_signature = self.signer.sign_schnorr(msg.current_hash)
            .map_err(|e| HandleError::Internal(e))?;

        // Create response
        let response = crate::messages::LedgerUpdateResponseMsg {
            operator_id: msg.operator_id,
            reserves_id: msg.reserves_id.clone(),
            request_hash: msg.current_hash,
            accepted: true,
            error: None,
            partner_signature: Some(partner_signature),
            confirmed_sequence: msg.sequence_number,
            confirmed_hash: msg.current_hash,
        };

        Ok(Some(crate::messages::DepositsMessage::LedgerUpdateResponse(response)))
    }

    fn handle_ledger_update_response(
        &self,
        sender: PublicKey,
        msg: &crate::messages::LedgerUpdateResponseMsg,
    ) -> Result<Option<crate::messages::DepositsMessage>, HandleError> {
        self.logger.log(
            LogLevel::Debug,
            &format!(
                "Ledger update response from {} - accepted={}, seq={}",
                sender, msg.accepted, msg.confirmed_sequence
            ),
        );

        if !msg.accepted {
            self.logger.log(
                LogLevel::Warn,
                &format!(
                    "Ledger update rejected: {:?}",
                    msg.error
                ),
            );
        }

        // Verify partner signature if accepted (only for LDK where reserves_id is a pubkey)
        if msg.accepted {
            if let Some(sig) = &msg.partner_signature {
                // Try to parse reserves_id as pubkey for signature verification
                if let Ok(partner_pubkey) = msg.reserves_id.parse::<PublicKey>() {
                    if !self.signer.verify_schnorr(&partner_pubkey, msg.confirmed_hash, sig) {
                        return Err(HandleError::ValidationFailed(
                            "Invalid partner signature".to_string(),
                        ));
                    }
                }
                // For BDK, reserves_id is an address, not a pubkey - skip signature verification
            }
        }

        Ok(None)
    }

    fn handle_handshake(
        &self,
        sender: PublicKey,
        msg: &crate::messages::HandshakeMsg,
    ) -> Result<Option<crate::messages::DepositsMessage>, HandleError> {
        self.logger.log(
            LogLevel::Info,
            &format!(
                "Handshake from {} - protocol v{}",
                sender, msg.protocol_version
            ),
        );

        // Create handshake response
        let response = crate::messages::HandshakeResponseMsg {
            request_hash: [0u8; 32], // TODO: Hash the request
            reserves_id: self.node_id.to_string(),
            accepted: true,
            protocol_version: crate::messages::PROTOCOL_VERSION,
            error: None,
        };

        Ok(Some(crate::messages::DepositsMessage::HandshakeResponse(response)))
    }

    fn handle_handshake_response(
        &self,
        sender: PublicKey,
        msg: &crate::messages::HandshakeResponseMsg,
    ) -> Result<Option<crate::messages::DepositsMessage>, HandleError> {
        self.logger.log(
            LogLevel::Info,
            &format!(
                "Handshake response from {} - accepted={}, v{}",
                sender, msg.accepted, msg.protocol_version
            ),
        );
        Ok(None)
    }

    fn handle_sync(
        &self,
        sender: PublicKey,
        msg: &crate::messages::SyncMsg,
    ) -> Result<Option<crate::messages::DepositsMessage>, HandleError> {
        self.logger.log(
            LogLevel::Debug,
            &format!("Sync request from {} - from_seq={}", sender, msg.last_known_sequence),
        );

        // Get ledger and prepare sync response
        let ledger_arc = self.get_ledger(msg.operator_id, &msg.reserves_id)
            .ok_or(HandleError::UnknownLedger {
                operator: msg.operator_id,
                reserves_id: msg.reserves_id.clone(),
            })?;

        let (current_hash, current_sequence) = {
            let ledger = ledger_arc.read().unwrap();
            (ledger.hash(), ledger.sequence())
        };

        let response = crate::messages::SyncResponseMsg {
            operator_id: msg.operator_id,
            reserves_id: msg.reserves_id.clone(),
            request_hash: msg.last_known_hash, // Use the known hash as request reference
            updates: Vec::new(), // Would be populated from history
            current_hash,
            current_sequence,
        };

        Ok(Some(crate::messages::DepositsMessage::SyncResponse(response)))
    }

    fn handle_sync_response(
        &self,
        sender: PublicKey,
        msg: &crate::messages::SyncResponseMsg,
    ) -> Result<Option<crate::messages::DepositsMessage>, HandleError> {
        self.logger.log(
            LogLevel::Debug,
            &format!(
                "Sync response from {} - {} updates, seq={}",
                sender, msg.updates.len(), msg.current_sequence
            ),
        );
        Ok(None)
    }

    fn handle_recovery(
        &self,
        sender: PublicKey,
        _msg: &crate::messages::RecoveryMsg,
    ) -> Result<Option<crate::messages::DepositsMessage>, HandleError> {
        self.logger.log(
            LogLevel::Info,
            &format!("Recovery message from {}", sender),
        );
        // Recovery handling is complex - stub for now
        Ok(None)
    }

    fn handle_recovery_response(
        &self,
        sender: PublicKey,
        _msg: &crate::messages::RecoveryResponseMsg,
    ) -> Result<Option<crate::messages::DepositsMessage>, HandleError> {
        self.logger.log(
            LogLevel::Info,
            &format!("Recovery response from {}", sender),
        );
        Ok(None)
    }

    fn handle_coordination(
        &self,
        sender: PublicKey,
        _msg: &crate::messages::CoordinationMsg,
    ) -> Result<Option<crate::messages::DepositsMessage>, HandleError> {
        self.logger.log(
            LogLevel::Debug,
            &format!("Coordination message from {}", sender),
        );
        // Coordination handling - stub for now
        Ok(None)
    }

    fn handle_coordination_response(
        &self,
        sender: PublicKey,
        _msg: &crate::messages::CoordinationResponseMsg,
    ) -> Result<Option<crate::messages::DepositsMessage>, HandleError> {
        self.logger.log(
            LogLevel::Debug,
            &format!("Coordination response from {}", sender),
        );
        Ok(None)
    }

    fn handle_relay(
        &self,
        sender: PublicKey,
        _msg: &crate::messages::RelayMsg,
    ) -> Result<Option<crate::messages::DepositsMessage>, HandleError> {
        self.logger.log(
            LogLevel::Debug,
            &format!("Relay message from {}", sender),
        );
        // Relay handling - stub for now
        Ok(None)
    }

    fn handle_relay_response(
        &self,
        sender: PublicKey,
        _msg: &crate::messages::RelayResponseMsg,
    ) -> Result<Option<crate::messages::DepositsMessage>, HandleError> {
        self.logger.log(
            LogLevel::Debug,
            &format!("Relay response from {}", sender),
        );
        Ok(None)
    }

    fn handle_reserves_add_output(
        &self,
        sender: PublicKey,
        msg: &crate::wire_messages::ReservesAddOutputMsg,
    ) -> Result<Option<crate::messages::DepositsMessage>, HandleError> {
        self.logger.log(
            LogLevel::Debug,
            &format!("Reserves add output from {}: reserves_id={}", sender, msg.reserves_id),
        );
        // This is a peer coordination message to add reserves output to commitment
        // Handler implementation will coordinate with ChannelManager
        Ok(None)
    }

    fn handle_reserves_remove_output(
        &self,
        sender: PublicKey,
        msg: &crate::wire_messages::ReservesRemoveOutputMsg,
    ) -> Result<Option<crate::messages::DepositsMessage>, HandleError> {
        self.logger.log(
            LogLevel::Debug,
            &format!("Reserves remove output from {}: reserves_id={}", sender, msg.reserves_id),
        );
        // This is a peer coordination message to remove reserves output from commitment
        // Handler implementation will coordinate with ChannelManager
        Ok(None)
    }

    // ========================================================================
    // Sending Messages
    // ========================================================================

    /// Send a message to a peer
    pub fn send_message(
        &self,
        peer: PublicKey,
        message: &crate::messages::DepositsMessage,
    ) -> Result<(), HandleError> {
        let bytes = message.encode();
        self.transport.send(peer, &bytes)
            .map_err(|e| HandleError::Internal(format!("Transport error: {}", e)))
    }
}

// ============================================================================
// Handler Trait Implementations
// ============================================================================

impl<S, T, P, C, B, H, G, E, L> crate::handler_traits::DepositOperations for Handler<S, T, P, C, B, H, G, E, L>
where
    S: Storage,
    T: PeerTransport,
    P: PaymentTracker,
    C: ChannelRegistry,
    B: Broadcaster,
    H: ChainSource,
    G: SignatureProvider,
    E: EventEmitter,
    L: Logger,
{
    fn list_deposits(&self) -> Result<Vec<PublicKey>, crate::DepositsError> {
        let mut all_deposits = Vec::new();
        let ledgers = self.ledgers.lock().unwrap();
        for ledger_arc in ledgers.values() {
            let ledger = ledger_arc.read().unwrap();
            for deposit in ledger.state.deposits.values() {
                all_deposits.push(deposit.pubkey);
            }
        }
        Ok(all_deposits)
    }

    fn list_deposits_for_depositor(
        &self,
        depositor_pubkey: PublicKey,
    ) -> Result<Vec<PublicKey>, crate::DepositsError> {
        let mut depositor_deposits = Vec::new();
        let ledgers = self.ledgers.lock().unwrap();
        for ledger_arc in ledgers.values() {
            let ledger = ledger_arc.read().unwrap();
            if let Some(deposit) = ledger.state.deposits.get(&depositor_pubkey) {
                depositor_deposits.push(deposit.pubkey);
            }
        }
        Ok(depositor_deposits)
    }

    fn list_deposits_for_pubkey(
        &self,
        deposit_pubkey: PublicKey,
    ) -> Result<Vec<PublicKey>, crate::DepositsError> {
        let mut matching_deposits = Vec::new();
        let ledgers = self.ledgers.lock().unwrap();
        for ledger_arc in ledgers.values() {
            let ledger = ledger_arc.read().unwrap();
            for deposit in ledger.state.deposits.values() {
                if deposit.pubkey == deposit_pubkey {
                    matching_deposits.push(deposit.pubkey);
                }
            }
        }
        Ok(matching_deposits)
    }

    fn get_deposit_balance(&self, deposit_pubkey: PublicKey) -> Result<u64, crate::DepositsError> {
        let ledgers = self.ledgers.lock().unwrap();
        for ledger_arc in ledgers.values() {
            let ledger = ledger_arc.read().unwrap();
            if let Some(deposit) = ledger.state.deposits.get(&deposit_pubkey) {
                return Ok(deposit.balance.saturating_sub(deposit.locked_balance));
            }
        }
        Err(crate::DepositsError::DepositNotFound)
    }

    fn find_deposit_by_payment_hash(&self, payment_hash: &[u8; 32]) -> Option<(String, PublicKey, u64)> {
        let ledgers = self.ledgers.lock().unwrap();
        for ((operator_id, reserves_id), ledger_arc) in ledgers.iter() {
            if *operator_id == self.node_id {
                let ledger = ledger_arc.read().unwrap();
                for (deposit_pubkey, deposit) in ledger.state.deposits.iter() {
                    for invoice in &deposit.invoices {
                        if &invoice.payment_hash == payment_hash {
                            return Some((reserves_id.clone(), *deposit_pubkey, invoice.amount));
                        }
                    }
                }
            }
        }
        None
    }

    fn get_active_depositors(&self) -> Vec<PublicKey> {
        let mut active_depositors = Vec::new();
        let ledgers = self.ledgers.lock().unwrap();
        for ledger_arc in ledgers.values() {
            let ledger = ledger_arc.read().unwrap();
            for (depositor_pubkey, deposit) in &ledger.state.deposits {
                if deposit.balance > 0 {
                    active_depositors.push(*depositor_pubkey);
                }
            }
        }
        active_depositors
    }

    fn get_total_deposit_balances(&self, partner_node_id: PublicKey) -> Option<u64> {
        let ledgers = self.ledgers.lock().unwrap();
        if let Some(ledger_arc) = ledgers.get(&(self.node_id, partner_node_id.to_string())) {
            let ledger = ledger_arc.read().unwrap();
            let total = ledger.state.deposits.values()
                .map(|deposit| deposit.balance)
                .sum();
            Some(total)
        } else {
            None
        }
    }

    fn get_deposits_for_partner(&self, partner_node_id: PublicKey) -> Option<Vec<(PublicKey, u64, u64)>> {
        let ledgers = self.ledgers.lock().unwrap();
        if let Some(ledger_arc) = ledgers.get(&(self.node_id, partner_node_id.to_string())) {
            let ledger = ledger_arc.read().unwrap();
            let deposits: Vec<(PublicKey, u64, u64)> = ledger.state.deposits.iter()
                .map(|(depositor_pubkey, deposit)| (*depositor_pubkey, deposit.balance, deposit.locked_balance))
                .collect();
            Some(deposits)
        } else {
            None
        }
    }

    fn get_max_outstanding_invoice_amount(&self, partner_node_id: PublicKey) -> Option<u64> {
        let ledgers = self.ledgers.lock().unwrap();
        if let Some(ledger_arc) = ledgers.get(&(self.node_id, partner_node_id.to_string())) {
            let ledger = ledger_arc.read().unwrap();
            let max_invoice = ledger.state.deposits.values()
                .flat_map(|d| d.invoices.iter())
                .map(|inv| inv.amount)
                .max()
                .unwrap_or(0);
            Some(max_invoice)
        } else {
            None
        }
    }
}

impl<S, T, P, C, B, H, G, E, L> crate::handler_traits::LedgerOperations for Handler<S, T, P, C, B, H, G, E, L>
where
    S: Storage,
    T: PeerTransport,
    P: PaymentTracker,
    C: ChannelRegistry,
    B: Broadcaster,
    H: ChainSource,
    G: SignatureProvider,
    E: EventEmitter,
    L: Logger,
{
    fn get_ledger_hash(&self, partner_node_id: PublicKey) -> Result<[u8; 32], crate::DepositsError> {
        let ledgers = self.ledgers.lock().unwrap();
        if let Some(ledger_arc) = ledgers.get(&(self.node_id, partner_node_id.to_string())) {
            let ledger = ledger_arc.read().unwrap();
            Ok(ledger.tail_hash())
        } else {
            Err(crate::DepositsError::LedgerNotFound)
        }
    }

    fn get_ledger_hashes(&self, partner_node_id: PublicKey) -> (Option<[u8; 32]>, Option<[u8; 32]>) {
        let ledgers = self.ledgers.lock().unwrap();

        // Local hash (where we are operator)
        let local_hash = ledgers.get(&(self.node_id, partner_node_id.to_string()))
            .map(|arc| {
                let ledger = arc.read().unwrap();
                ledger.state.channel_deepest_commitment_hash
            });

        // Remote hash (where they are operator)
        let remote_hash = ledgers.get(&(partner_node_id, self.node_id.to_string()))
            .map(|arc| {
                let ledger = arc.read().unwrap();
                ledger.state.channel_deepest_commitment_hash
            });

        (local_hash, remote_hash)
    }

    fn get_committed_ledger_hashes_from_channel(
        &self,
        _counterparty_node_id: PublicKey,
    ) -> (Option<[u8; 32]>, Option<[u8; 32]>) {
        // This requires channel manager access - return None for now
        // Implementations with channel access can override
        (None, None)
    }

    fn validate_ledger_hash_for_reserves(
        &self,
        counterparty_node_id: &PublicKey,
        ledger_hash: &[u8; 32],
    ) -> bool {
        // Zero hash is always valid
        if ledger_hash == &[0u8; 32] {
            return true;
        }

        let ledgers = self.ledgers.lock().unwrap();
        let ledger_key = (*counterparty_node_id, self.node_id.to_string());

        if let Some(ledger_arc) = ledgers.get(&ledger_key) {
            let ledger = ledger_arc.read().unwrap();
            // Delegate to deposits-core's pure hash lookup
            ledger.find_hash_sequence(ledger_hash).is_some()
        } else {
            false
        }
    }

    fn get_ledger_sequence(&self, partner_node_id: PublicKey) -> Result<u64, crate::DepositsError> {
        let ledgers = self.ledgers.lock().unwrap();
        if let Some(ledger_arc) = ledgers.get(&(self.node_id, partner_node_id.to_string())) {
            let ledger = ledger_arc.read().unwrap();
            Ok(ledger.sequence())
        } else {
            Err(crate::DepositsError::LedgerNotFound)
        }
    }

    fn has_ledger_with(&self, partner_node_id: PublicKey) -> bool {
        let ledgers = self.ledgers.lock().unwrap();
        ledgers.contains_key(&(self.node_id, partner_node_id.to_string()))
    }

    fn list_operator_ledgers(&self) -> Vec<String> {
        let ledgers = self.ledgers.lock().unwrap();
        ledgers.keys()
            .filter(|(op, _)| *op == self.node_id)
            .map(|(_, reserves_id)| reserves_id.clone())
            .collect()
    }

    fn list_partner_ledgers(&self) -> Vec<PublicKey> {
        let ledgers = self.ledgers.lock().unwrap();
        let node_id_str = self.node_id.to_string();
        ledgers.keys()
            .filter(|(_, reserves_id)| *reserves_id == node_id_str)
            .map(|(op, _)| *op)
            .collect()
    }
}

impl<S, T, P, C, B, H, G, E, L> MessageHandler for Handler<S, T, P, C, B, H, G, E, L>
where
    S: Storage,
    T: PeerTransport,
    P: PaymentTracker,
    C: ChannelRegistry,
    B: Broadcaster,
    H: ChainSource,
    G: SignatureProvider,
    E: EventEmitter,
    L: Logger,
{
    fn handle_message(
        &self,
        sender: PublicKey,
        message: &[u8],
    ) -> Result<Option<Vec<u8>>, HandleError> {
        use crate::messages::DepositsMessage;

        self.logger.log(LogLevel::Debug, &format!(
            "Received {} bytes from {}",
            message.len(),
            sender
        ));

        // Decode the message
        let decoded = DepositsMessage::decode(message)
            .map_err(|e| HandleError::InvalidMessage(format!("Decode error: {:?}", e)))?;

        self.logger.log(LogLevel::Debug, &format!(
            "Decoded message type {} from {}",
            decoded.variant_name(),
            sender
        ));

        // Process and get response
        let response = self.process_message_v2(sender, &decoded)?;

        // Encode response if any
        Ok(response.map(|r| r.encode()))
    }

    fn peer_connected(&self, peer: PublicKey) {
        self.logger.log(LogLevel::Info, &format!(
            "Peer connected: {}",
            peer
        ));

        // Notify transport
        // Note: In a real implementation, this would update the transport's connected peer list
    }

    fn peer_disconnected(&self, peer: PublicKey) {
        self.logger.log(LogLevel::Info, &format!(
            "Peer disconnected: {}",
            peer
        ));

        // Notify transport
        // Note: In a real implementation, this would update the transport's connected peer list
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    fn test_pubkey() -> PublicKey {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[1u8; 32]).unwrap();
        PublicKey::from_secret_key(&secp, &secret)
    }

    // Mock implementations for testing
    struct MockTransport;
    impl PeerTransport for MockTransport {
        fn send(&self, _peer: PublicKey, _message: &[u8]) -> Result<(), TransportError> { Ok(()) }
        fn is_connected(&self, _peer: &PublicKey) -> bool { true }
        fn connected_peers(&self) -> Vec<PublicKey> { vec![] }
    }

    struct MockStorage;
    impl Storage for MockStorage {
        fn get(&self, _key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> { Ok(None) }
        fn put(&self, _key: &[u8], _value: &[u8]) -> Result<(), StorageError> { Ok(()) }
        fn delete(&self, _key: &[u8]) -> Result<(), StorageError> { Ok(()) }
        fn scan_prefix(&self, _prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> { Ok(vec![]) }
    }

    struct MockChannels;
    impl ChannelRegistry for MockChannels {
        fn partner_for_channel(&self, _channel_id: [u8; 32]) -> Option<PublicKey> { None }
        fn channels_with_peer(&self, _peer: PublicKey) -> Vec<[u8; 32]> { vec![] }
        fn channel_is_usable(&self, _channel_id: [u8; 32]) -> bool { false }
        fn channel_balance_msat(&self, _channel_id: [u8; 32]) -> Option<u64> { None }
    }

    struct MockChain;
    impl ChainSource for MockChain {
        fn current_height(&self) -> u32 { 800000 }
        fn get_block_hash(&self, _height: u32) -> Option<[u8; 32]> { Some([0u8; 32]) }
        fn fee_rate(&self, _confirmation_target: u32) -> Option<u64> { Some(10) }
    }

    struct MockPayments;
    impl PaymentTracker for MockPayments {
        fn payment_received(&self, _payment_hash: [u8; 32], _amount_msat: u64) -> bool { false }
        fn payment_sent(&self, _payment_id: [u8; 32], _success: bool) {}
        fn get_payment_status(&self, _payment_id: [u8; 32]) -> PaymentStatus { PaymentStatus::Unknown }
        fn get_preimage(&self, _payment_hash: [u8; 32]) -> Option<[u8; 32]> { None }
    }

    struct MockBroadcaster;
    impl Broadcaster for MockBroadcaster {
        fn broadcast_transaction(&self, _tx: &bitcoin::Transaction) -> Result<(), BroadcastError> { Ok(()) }
    }

    struct MockSigner;
    impl SignatureProvider for MockSigner {
        fn node_pubkey(&self) -> PublicKey { test_pubkey() }
        fn sign_schnorr(&self, _message_hash: [u8; 32]) -> Result<[u8; 64], String> { Ok([0u8; 64]) }
        fn verify_schnorr(&self, _pubkey: &PublicKey, _message_hash: [u8; 32], _signature: &[u8; 64]) -> bool { true }
    }

    struct MockEvents;
    impl EventEmitter for MockEvents {
        fn emit(&self, _event: ProtocolEvent) {}
    }

    #[test]
    fn test_handler_creation() {
        let handler = Handler::new(
            Arc::new(MockStorage),
            Arc::new(MockTransport),
            Arc::new(MockPayments),
            Arc::new(MockChannels),
            Arc::new(MockBroadcaster),
            Arc::new(MockChain),
            Arc::new(MockSigner),
            Arc::new(MockEvents),
            Arc::new(NullLogger),
        );

        assert_eq!(handler.node_id(), test_pubkey());
        assert_eq!(handler.current_height(), 800000);
        assert!(handler.list_operator_ledgers().is_empty());
        assert!(handler.list_partner_ledgers().is_empty());
    }

    #[test]
    fn test_message_handler_impl() {
        let handler = Handler::new(
            Arc::new(MockStorage),
            Arc::new(MockTransport),
            Arc::new(MockPayments),
            Arc::new(MockChannels),
            Arc::new(MockBroadcaster),
            Arc::new(MockChain),
            Arc::new(MockSigner),
            Arc::new(MockEvents),
            Arc::new(NullLogger),
        );

        // Test handle_message with invalid bytes - should return an error
        let result = handler.handle_message(test_pubkey(), &[1, 2, 3]);
        assert!(result.is_err()); // Invalid message bytes should fail to decode

        // Test peer_connected/disconnected (just verify they don't panic)
        handler.peer_connected(test_pubkey());
        handler.peer_disconnected(test_pubkey());
    }

    #[test]
    fn test_ledger_management() {
        let handler = Handler::new(
            Arc::new(MockStorage),
            Arc::new(MockTransport),
            Arc::new(MockPayments),
            Arc::new(MockChannels),
            Arc::new(MockBroadcaster),
            Arc::new(MockChain),
            Arc::new(MockSigner),
            Arc::new(MockEvents),
            Arc::new(NullLogger),
        );

        let partner = {
            let secp = Secp256k1::new();
            let secret = SecretKey::from_slice(&[2u8; 32]).unwrap();
            PublicKey::from_secret_key(&secp, &secret)
        };

        // Initially no ledgers
        let partner_str = partner.to_string();
        assert!(!handler.has_ledger_with(&partner_str));
        assert!(handler.list_operator_ledgers().is_empty());

        // Create operator ledger
        let result = handler.create_operator_ledger(partner_str.clone(), "tb1q...".to_string(), 0);
        assert!(result.is_ok());
        assert!(handler.has_ledger_with(&partner_str));
        assert_eq!(handler.list_operator_ledgers(), vec![partner_str.clone()]);

        // Verify ledger properties
        assert_eq!(handler.get_ledger_sequence(test_pubkey(), &partner_str), Some(0));
        assert_eq!(handler.get_ledger_deposit_balance(test_pubkey(), &partner_str), Some(0));

        // Can't create duplicate
        let result = handler.create_operator_ledger(partner_str.clone(), "tb1q...".to_string(), 0);
        assert!(result.is_err());

        // Remove ledger
        assert!(handler.remove_ledger(test_pubkey(), &partner_str));
        assert!(!handler.has_ledger_with(&partner_str));
    }

    #[test]
    fn test_deposit_operations_trait() {
        use crate::handler_traits::DepositOperations;

        let handler = Handler::new(
            Arc::new(MockStorage),
            Arc::new(MockTransport),
            Arc::new(MockPayments),
            Arc::new(MockChannels),
            Arc::new(MockBroadcaster),
            Arc::new(MockChain),
            Arc::new(MockSigner),
            Arc::new(MockEvents),
            Arc::new(NullLogger),
        );

        let partner = {
            let secp = Secp256k1::new();
            let secret = SecretKey::from_slice(&[2u8; 32]).unwrap();
            PublicKey::from_secret_key(&secp, &secret)
        };

        // Create a ledger
        let partner_str = partner.to_string();
        handler.create_operator_ledger(partner_str.clone(), "tb1q...".to_string(), 0).unwrap();

        // Initially no deposits
        assert!(handler.list_deposits().unwrap().is_empty());
        assert!(handler.get_active_depositors().is_empty());
        assert_eq!(handler.get_total_deposit_balances(partner), Some(0));
        assert!(handler.get_deposits_for_partner(partner).unwrap().is_empty());

        // Add a deposit to the ledger
        let deposit_pubkey = {
            let secp = Secp256k1::new();
            let secret = SecretKey::from_slice(&[3u8; 32]).unwrap();
            PublicKey::from_secret_key(&secp, &secret)
        };

        {
            let ledger_arc = handler.get_ledger(test_pubkey(), &partner_str).unwrap();
            let mut ledger = ledger_arc.write().unwrap();
            let mut deposit = crate::types::Deposit::new(deposit_pubkey, None);
            deposit.balance = 100_000;
            deposit.locked_balance = 10_000;
            ledger.state.deposits.insert(deposit_pubkey, deposit);
        }

        // Now we should see the deposit
        let deposits = handler.list_deposits().unwrap();
        assert_eq!(deposits.len(), 1);
        assert_eq!(deposits[0], deposit_pubkey);

        // Check balance (balance - locked)
        let balance = handler.get_deposit_balance(deposit_pubkey).unwrap();
        assert_eq!(balance, 90_000);

        // Check total balances
        assert_eq!(handler.get_total_deposit_balances(partner), Some(100_000));

        // Check active depositors
        let active = handler.get_active_depositors();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0], deposit_pubkey);

        // Check deposits for partner
        let partner_deposits = handler.get_deposits_for_partner(partner).unwrap();
        assert_eq!(partner_deposits.len(), 1);
        assert_eq!(partner_deposits[0], (deposit_pubkey, 100_000, 10_000));
    }

    #[test]
    fn test_ledger_operations_trait() {
        use crate::handler_traits::LedgerOperations;

        let handler = Handler::new(
            Arc::new(MockStorage),
            Arc::new(MockTransport),
            Arc::new(MockPayments),
            Arc::new(MockChannels),
            Arc::new(MockBroadcaster),
            Arc::new(MockChain),
            Arc::new(MockSigner),
            Arc::new(MockEvents),
            Arc::new(NullLogger),
        );

        let partner = {
            let secp = Secp256k1::new();
            let secret = SecretKey::from_slice(&[2u8; 32]).unwrap();
            PublicKey::from_secret_key(&secp, &secret)
        };

        // No ledger yet - use trait methods which take partner_node_id
        assert!(!<_ as LedgerOperations>::has_ledger_with(&handler, partner));
        assert!(<_ as LedgerOperations>::get_ledger_hash(&handler, partner).is_err());
        assert!(<_ as LedgerOperations>::get_ledger_sequence(&handler, partner).is_err());

        // Create ledger
        let partner_str = partner.to_string();
        handler.create_operator_ledger(partner_str.clone(), "tb1q...".to_string(), 0).unwrap();

        // Now we have a ledger - use trait methods
        assert!(<_ as LedgerOperations>::has_ledger_with(&handler, partner));

        // Check hash (should be zeros for empty ledger)
        let hash = <_ as LedgerOperations>::get_ledger_hash(&handler, partner).unwrap();
        assert_eq!(hash, [0u8; 32]);

        // Check sequence
        let seq = <_ as LedgerOperations>::get_ledger_sequence(&handler, partner).unwrap();
        assert_eq!(seq, 0);

        // Check hashes
        let (local, remote) = <_ as LedgerOperations>::get_ledger_hashes(&handler, partner);
        assert_eq!(local, Some([0u8; 32])); // commitment hash starts at zero
        assert_eq!(remote, None); // no remote ledger

        // Validate hash for reserves
        assert!(<_ as LedgerOperations>::validate_ledger_hash_for_reserves(&handler, &partner, &[0u8; 32])); // zero is always valid

        // List ledgers - these are already trait methods
        assert_eq!(<_ as LedgerOperations>::list_operator_ledgers(&handler), vec![partner_str]);
        assert!(<_ as LedgerOperations>::list_partner_ledgers(&handler).is_empty());
    }
}
