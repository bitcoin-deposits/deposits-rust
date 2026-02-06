// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Node implementation that ties together wallet, nostr, and lightning

use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{PublicKey, Secp256k1};
use bitcoin::Network;
use deposits_core::ledger::Ledger;
use deposits_core::message_validation::HandlerContext;
use deposits_core::messages::LedgerOperation;
use deposits_core::TlvDecode;
use deposits_core::types::{
    Deposit, DepositOffer, DepositOfferStatus, FeeStructure,
    OnChainWithdrawal, OnChainWithdrawalStatus,
    WithdrawalLockResult, WithdrawalCompleteResult,
};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use tokio::sync::mpsc;

use crate::handler::{DepositsHandler, OutboundMessage};
use crate::lightning::LightningClient;
use crate::nostr::{InboundMessage, NostrTransport};
use crate::wallet::Wallet;
use crate::Error;

/// Configuration for the deposits-bdk node
#[derive(Clone)]
pub struct NodeConfig {
    /// Seed for wallet/identity (32 bytes)
    pub seed: [u8; 32],

    /// Bitcoin network
    pub network: Network,

    /// Electrum server URL
    pub electrum_url: String,

    /// Nostr relay URLs
    pub relays: Vec<String>,

    /// NWC connection string (optional - for Lightning operations)
    pub nwc_uri: Option<String>,

    /// Data directory
    pub data_dir: PathBuf,
}

/// Result of rotating reserves to quorum-based Taproot spending
#[derive(Debug, Clone)]
pub struct RotateReservesResult {
    /// The transaction ID of the rotation transaction
    pub txid: String,

    /// The new Taproot reserves address
    pub new_address: String,

    /// Amount in satoshis
    pub amount_sats: u64,

    /// Number of quorum members in the new output
    pub quorum_member_count: usize,

    /// Block height when first quorum member expires (operator-only unlock)
    pub first_expiry_block: u32,

    /// The ledger hash committed to in the new Taproot tree
    pub ledger_hash: [u8; 32],
}

/// A deposits-bdk node
pub struct Node {
    /// Our node ID (secp256k1 pubkey)
    pub node_id: PublicKey,

    /// The wallet for on-chain operations
    pub wallet: Arc<Wallet>,

    /// Nostr transport for peer messaging
    pub nostr: NostrTransport,

    /// Lightning client (optional)
    pub lightning: Option<LightningClient>,

    /// The protocol handler
    pub handler: Arc<DepositsHandler>,

    /// Outbound message receiver (for async sending via nostr)
    outbound_rx: mpsc::UnboundedReceiver<OutboundMessage>,

    /// Pending deposit offers indexed by offer_id
    deposit_offers: Mutex<HashMap<[u8; 32], (DepositOffer, DepositOfferStatus)>>,

    /// Pending withdrawals indexed by withdrawal_id
    withdrawals: Mutex<HashMap<[u8; 32], (OnChainWithdrawal, OnChainWithdrawalStatus)>>,

    /// Data directory for persistence
    data_dir: PathBuf,
}

impl Node {
    /// Create a new node
    pub async fn new(config: NodeConfig) -> Result<Self, Error> {
        let secp = Secp256k1::new();

        // Create wallet
        let wallet = Arc::new(Wallet::new(
            config.seed,
            config.network,
            config.data_dir.join("wallet"),
            config.electrum_url,
        )?);

        let secret_key = wallet.operator_secret();
        let node_id = PublicKey::from_secret_key(&secp, &secret_key);

        // Create nostr transport
        let nostr = NostrTransport::new(secret_key, config.relays).await?;

        // Create lightning client if NWC URI provided
        let lightning = if let Some(uri) = &config.nwc_uri {
            Some(LightningClient::new(uri).await?)
        } else {
            None
        };

        // Create handler with data_dir for ledger persistence
        let handler_data_dir = config.data_dir.join("wallet");
        let (handler, outbound_rx) = DepositsHandler::new(secret_key, wallet.clone(), handler_data_dir);

        // Load existing deposit offers from disk
        let deposit_offers = Self::load_deposit_offers(&config.data_dir)?;

        // Load existing withdrawals from disk
        let withdrawals = Self::load_withdrawals(&config.data_dir)?;

        tracing::info!("Node created with ID: {}", node_id);

        Ok(Self {
            node_id,
            wallet,
            nostr,
            lightning,
            handler: Arc::new(handler),
            outbound_rx,
            deposit_offers: Mutex::new(deposit_offers),
            withdrawals: Mutex::new(withdrawals),
            data_dir: config.data_dir,
        })
    }

    /// Sync the wallet with the blockchain
    pub fn sync_wallet(&self) -> Result<(), Error> {
        self.wallet.sync()
    }

    /// Sign the last update in a ledger with our operator key
    ///
    /// Call this after appending an operation to sign the update before broadcasting.
    pub fn sign_last_update(&self, reserves_id: &str) -> Result<(), Error> {
        use bitcoin::secp256k1::{Secp256k1, Message};
        use bitcoin::hashes::{Hash, sha256};

        // Get the ledger
        let ledger_arc = self.handler.ledgers.lock().unwrap()
            .iter()
            .find(|((_, rid), _)| rid == reserves_id)
            .map(|(_, arc)| arc.clone());

        let ledger_arc = ledger_arc
            .ok_or_else(|| Error::Protocol(format!("Ledger not found: {}", reserves_id)))?;

        let mut ledger = ledger_arc.write().unwrap();

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
            let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &self.wallet.operator_secret());
            let sig = secp.sign_schnorr(&msg, &keypair);

            update.operator_signature = sig.serialize();
            tracing::debug!("Signed update seq={} for ledger {}", update.sequence_number, reserves_id);
        }

        Ok(())
    }

    /// Broadcast the most recent ledger update to Nostr
    ///
    /// Call this after appending an operation to a ledger to ensure the update
    /// is published to the Nostr relay for other participants to see.
    pub async fn broadcast_last_update(&self, reserves_id: &str) -> Result<String, Error> {
        // Get the ledger
        let (_, ledger) = self.get_ledger_by_reserves_id(reserves_id)
            .ok_or_else(|| Error::Protocol(format!("Ledger not found: {}", reserves_id)))?;

        // Get the last update
        let update = ledger.history.last()
            .ok_or_else(|| Error::Protocol("Ledger has no updates".to_string()))?;

        // Broadcast to Nostr
        let event_id = self.nostr.broadcast_ledger_update(update).await?;
        tracing::info!("Broadcast update seq={} to Nostr: {}", update.sequence_number, &event_id[..16]);

        Ok(event_id)
    }

    /// Broadcast all ledger updates to Nostr
    ///
    /// Use this when initializing a ledger (e.g., after ledger_open) to broadcast
    /// all initial operations (LedgerOpen, ReservesIncrease, etc.)
    pub async fn broadcast_all_updates(&self, reserves_id: &str) -> Result<usize, Error> {
        // Get the ledger
        let (_, ledger) = self.get_ledger_by_reserves_id(reserves_id)
            .ok_or_else(|| Error::Protocol(format!("Ledger not found: {}", reserves_id)))?;

        let mut count = 0;
        for update in &ledger.history {
            match self.nostr.broadcast_ledger_update(update).await {
                Ok(event_id) => {
                    tracing::info!("Broadcast update seq={} to Nostr: {}", update.sequence_number, &event_id[..16]);
                    count += 1;
                }
                Err(e) => {
                    tracing::warn!("Failed to broadcast update seq={}: {}", update.sequence_number, e);
                }
            }
        }

        Ok(count)
    }

    /// Start listening for messages
    pub async fn start(&mut self) -> Result<(), Error> {
        self.nostr.start_listening().await?;

        // Auto-subscribe to ledger requests/disputes for all our ledgers
        let ledgers = self.handler.ledgers.lock().unwrap().clone();
        for ((operator, _reserves_id), ledger_arc) in ledgers.iter() {
            // Only subscribe to ledgers where we're the operator
            if *operator == self.node_id {
                let ledger = ledger_arc.read().unwrap();
                let ledger_id = ledger.ledger_id_hex();

                if let Err(e) = self.nostr.subscribe_to_requests(&ledger_id).await {
                    tracing::warn!("Failed to subscribe to requests for ledger {}: {}", &ledger_id[..16], e);
                } else {
                    tracing::info!("Subscribed to requests for ledger {}...", &ledger_id[..16]);
                }

                if let Err(e) = self.nostr.subscribe_to_disputes(&ledger_id).await {
                    tracing::warn!("Failed to subscribe to disputes for ledger {}: {}", &ledger_id[..16], e);
                } else {
                    tracing::info!("Subscribed to disputes for ledger {}...", &ledger_id[..16]);
                }
            }
        }

        // Also subscribe to joined ledgers (where we're a quorum member)
        let joined_ledgers = self.get_joined_ledger_ids();
        for ledger_id in joined_ledgers {
            if let Err(e) = self.nostr.subscribe_to_requests(&ledger_id).await {
                tracing::warn!("Failed to subscribe to requests for joined ledger {}: {}", &ledger_id[..16], e);
            }
            if let Err(e) = self.nostr.subscribe_to_disputes(&ledger_id).await {
                tracing::warn!("Failed to subscribe to disputes for joined ledger {}: {}", &ledger_id[..16], e);
            }
        }

        tracing::info!("Node started, listening for messages");
        Ok(())
    }

    /// Subscribe to requests and disputes for a specific ledger
    /// Call this after opening a new ledger to start watching it
    pub async fn subscribe_to_ledger(&self, ledger_id: &str) -> Result<(), Error> {
        if let Err(e) = self.nostr.subscribe_to_requests(ledger_id).await {
            tracing::warn!("Failed to subscribe to requests for ledger {}: {}", &ledger_id[..16.min(ledger_id.len())], e);
        } else {
            tracing::info!("Subscribed to requests for ledger {}...", &ledger_id[..16.min(ledger_id.len())]);
        }

        if let Err(e) = self.nostr.subscribe_to_disputes(ledger_id).await {
            tracing::warn!("Failed to subscribe to disputes for ledger {}: {}", &ledger_id[..16.min(ledger_id.len())], e);
        } else {
            tracing::info!("Subscribed to disputes for ledger {}...", &ledger_id[..16.min(ledger_id.len())]);
        }

        Ok(())
    }

    /// Get ledger IDs of ledgers we've joined as a quorum member
    fn get_joined_ledger_ids(&self) -> Vec<String> {
        let mut joined = Vec::new();
        let ledgers = self.handler.ledgers.lock().unwrap();

        for ((operator, _), ledger_arc) in ledgers.iter() {
            if *operator == self.node_id {
                let ledger = ledger_arc.read().unwrap();
                for update in &ledger.history {
                    if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                        if let LedgerOperation::QuorumJoin { reserves_id, .. } = op {
                            if !joined.contains(&reserves_id) {
                                joined.push(reserves_id);
                            }
                        }
                    }
                }
            }
        }

        joined
    }

    /// Run the main event loop
    pub async fn run(&mut self) -> Result<(), Error> {
        loop {
            tokio::select! {
                // Process inbound messages from nostr (P2P + ledger events)
                _ = self.nostr.process_events() => {
                    // Handle P2P messages
                    while let Some(inbound) = self.nostr.try_recv() {
                        self.handle_inbound(inbound);
                    }

                    // Handle ledger requests
                    while let Some(request) = self.nostr.try_recv_request() {
                        self.handle_ledger_request(request).await;
                    }

                    // Handle disputes
                    while let Some(dispute) = self.nostr.try_recv_dispute() {
                        self.handle_dispute(dispute).await;
                    }
                }

                // Send outbound messages via nostr
                Some(outbound) = self.outbound_rx.recv() => {
                    if let Err(e) = self.nostr.send_message(outbound.peer, outbound.message).await {
                        tracing::error!("Failed to send message: {}", e);
                    }
                }

                // Periodic tasks
                _ = tokio::time::sleep(tokio::time::Duration::from_secs(60)) => {
                    // Sync wallet periodically
                    if let Err(e) = self.sync_wallet() {
                        tracing::warn!("Wallet sync failed: {}", e);
                    }

                    // Auto-complete funded deposits
                    self.auto_complete_deposits().await;

                    // Drain and log events
                    let events = self.handler.drain_events();
                    for event in events {
                        tracing::info!("Protocol event: {:?}", event);
                    }
                }
            }
        }
    }

    /// Handle a ledger request from Nostr
    async fn handle_ledger_request(&self, request: crate::nostr::LedgerRequest) {
        tracing::info!(
            "Ledger request: action={}, ledger={}..., event={}...",
            request.action,
            &request.ledger_id[..16.min(request.ledger_id.len())],
            &request.event_id[..16.min(request.event_id.len())]
        );

        // Check if this request is for a ledger we own or have joined
        let is_our_ledger = self.get_ledger_by_ledger_id(&request.ledger_id).is_some()
            || self.get_ledger_by_reserves_id(&request.ledger_id).is_some();
        let is_cross_ledger_sign = request.action == "custody_transfer_sign"
            || request.action == "confiscation_sign";

        if !is_our_ledger && !is_cross_ledger_sign {
            tracing::debug!("Skipping request for unknown ledger: {}", &request.ledger_id[..16]);
            return;
        }

        // Process the request based on action
        let (success, result, error) = match request.action.as_str() {
            "deposit_open" => self.process_deposit_open_request(&request).await,
            "deposit_offer" => self.process_deposit_offer_request(&request).await,
            "collateral_lock" => self.process_collateral_lock_request(&request).await,
            "custody_transfer_sign" => self.process_custody_transfer_sign_request(&request).await,
            "confiscation_sign" => self.process_confiscation_sign_request(&request).await,
            "custodian_query" => self.process_custodian_query_request(&request).await,
            _ => {
                tracing::warn!("Unknown request action: {}", request.action);
                (false, None, Some(format!("Unknown action: {}", request.action)))
            }
        };

        // Send response - convert result String to serde_json::Value
        let result_json = result.map(|s| serde_json::Value::String(s));
        if let Err(e) = self.nostr.send_ledger_response(
            &request.event_id,
            &request.ledger_id,
            success,
            result_json,
            error.clone(),
        ).await {
            tracing::error!("Failed to send response: {}", e);
        } else if success {
            tracing::info!("Request {} processed successfully", &request.event_id[..16]);
        } else {
            tracing::warn!("Request {} failed: {}", &request.event_id[..16], error.unwrap_or_default());
        }
    }

    /// Handle a dispute notification from Nostr
    async fn handle_dispute(&self, dispute: crate::nostr::LedgerDispute) {
        tracing::warn!(
            "!!! DISPUTE RECEIVED for ledger {}...: {} (by {}...)",
            &dispute.ledger_id[..16.min(dispute.ledger_id.len())],
            dispute.reason,
            &dispute.disputer_pubkey[..16.min(dispute.disputer_pubkey.len())]
        );

        // TODO: Auto-validate and participate in dispute resolution
        // For now, just log it prominently
        tracing::warn!("  Last valid seq: {}", dispute.last_valid_sequence);
        if let Some(vs) = dispute.violation_sequence {
            tracing::warn!("  Violation seq: {}", vs);
        }
        tracing::warn!("  ACTION REQUIRED: Run 'recovery dispute' to participate");
    }

    // ========================================================================
    // Request Handlers (stubs - full implementation is in CLI's nostr watch)
    // These are placeholders for future Node-integrated handling.
    // ========================================================================

    async fn process_deposit_open_request(&self, _request: &crate::nostr::LedgerRequest) -> (bool, Option<String>, Option<String>) {
        // TODO: Implement - for now handled by CLI's nostr watch
        tracing::info!("deposit_open request received (not yet handled by Node)");
        (false, None, Some("deposit_open: use 'nostr watch' CLI for now".to_string()))
    }

    async fn process_deposit_offer_request(&self, _request: &crate::nostr::LedgerRequest) -> (bool, Option<String>, Option<String>) {
        // TODO: Implement - for now handled by CLI's nostr watch
        tracing::info!("deposit_offer request received (not yet handled by Node)");
        (false, None, Some("deposit_offer: use 'nostr watch' CLI for now".to_string()))
    }

    async fn process_collateral_lock_request(&self, _request: &crate::nostr::LedgerRequest) -> (bool, Option<String>, Option<String>) {
        // TODO: Implement - for now handled by CLI's nostr watch
        tracing::info!("collateral_lock request received (not yet handled by Node)");
        (false, None, Some("collateral_lock: use 'nostr watch' CLI for now".to_string()))
    }

    async fn process_custody_transfer_sign_request(&self, _request: &crate::nostr::LedgerRequest) -> (bool, Option<String>, Option<String>) {
        // TODO: Implement - for now handled by CLI's nostr watch
        tracing::info!("custody_transfer_sign request received (not yet handled by Node)");
        (false, None, Some("custody_transfer_sign: use 'nostr watch' CLI for now".to_string()))
    }

    async fn process_confiscation_sign_request(&self, _request: &crate::nostr::LedgerRequest) -> (bool, Option<String>, Option<String>) {
        // TODO: Implement - for now handled by CLI's nostr watch
        tracing::info!("confiscation_sign request received (not yet handled by Node)");
        (false, None, Some("confiscation_sign: use 'nostr watch' CLI for now".to_string()))
    }

    async fn process_custodian_query_request(&self, request: &crate::nostr::LedgerRequest) -> (bool, Option<String>, Option<String>) {
        // Get ledger
        let (reserves_id, ledger) = match self.get_ledger_by_ledger_id(&request.ledger_id)
            .or_else(|| self.get_ledger_by_reserves_id(&request.ledger_id))
        {
            Some(l) => l,
            None => return (false, None, Some("Ledger not found".to_string())),
        };

        let custodian_hex = hex::encode(ledger.operator_key().serialize());

        let result = serde_json::json!({
            "status": "SUCCESS",
            "custodian": custodian_hex,
            "reserves_id": reserves_id,
            "ledger_id": ledger.ledger_id_hex(),
        });
        (true, Some(result.to_string()), None)
    }

    // ========================================================================
    // Auto-Response Tasks
    // ========================================================================

    /// Auto-complete deposits that have been funded on-chain
    async fn auto_complete_deposits(&self) {
        use deposits_core::types::DepositOfferStatus;

        let offers = self.list_deposit_offers();
        let pending: Vec<_> = offers.iter()
            .filter(|(_, status)| matches!(status, DepositOfferStatus::Pending))
            .collect();

        if pending.is_empty() {
            return;
        }

        for (offer, _) in pending {
            let offer_id = offer.offer_id;

            // Check if funded
            match self.check_deposit_offer_funding(&offer_id) {
                Ok(Some((txid, amount_sats))) => {
                    tracing::info!(
                        "Auto-completing funded deposit: offer={}... txid={}... amount={} sats",
                        hex::encode(&offer_id[..8]),
                        &txid[..16.min(txid.len())],
                        amount_sats
                    );

                    // Complete the deposit
                    match self.complete_deposit_offer(&offer_id, txid.clone(), amount_sats) {
                        Ok(new_balance) => {
                            tracing::info!(
                                "Deposit completed! New balance: {} msats",
                                new_balance
                            );

                            // Broadcast the update to Nostr
                            if let Some(reserves_id) = self.find_ledger_for_offer(&offer_id) {
                                if let Err(e) = self.broadcast_last_update(&reserves_id).await {
                                    tracing::warn!("Failed to broadcast deposit complete: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            tracing::error!(
                                "Failed to complete deposit {}...: {}",
                                hex::encode(&offer_id[..8]),
                                e
                            );
                        }
                    }
                }
                Ok(None) => {
                    // Not funded yet, skip
                }
                Err(e) => {
                    tracing::debug!(
                        "Error checking deposit funding {}...: {}",
                        hex::encode(&offer_id[..8]),
                        e
                    );
                }
            }
        }
    }

    /// Find the ledger (reserves_id) for a specific deposit offer
    fn find_ledger_for_offer(&self, offer_id: &[u8; 32]) -> Option<String> {
        // Get the offer to find its ledger_id
        let (offer, _) = self.get_deposit_offer(offer_id)?;

        // Find the ledger by ledger_id
        let ledgers = self.handler.ledgers.lock().unwrap();
        for ((operator, reserves_id), ledger_arc) in ledgers.iter() {
            if *operator == self.node_id {
                let ledger = ledger_arc.read().unwrap();
                if ledger.ledger_id_hex() == offer.ledger_id {
                    return Some(reserves_id.clone());
                }
            }
        }
        None
    }

    /// Handle an inbound message
    fn handle_inbound(&self, inbound: InboundMessage) {
        tracing::debug!("Received message from {}", inbound.sender);
        if let Err(e) = self.handler.handle_message(inbound.message, inbound.sender) {
            tracing::error!("Failed to handle message: {}", e);
        }
    }

    /// Get the wallet balance
    pub fn wallet_balance(&self) -> Result<u64, Error> {
        self.wallet.get_wallet_balance()
    }

    /// Get the reserves balance
    pub fn reserves_balance(&self) -> Result<u64, Error> {
        self.wallet.get_reserves_balance()
    }

    /// Get a new address
    pub fn new_address(&self) -> Result<bitcoin::Address, Error> {
        self.wallet.get_new_address()
    }

    /// Create a reserves output
    pub fn create_reserves(
        &self,
        amount_sats: u64,
        partners: Vec<PublicKey>,
        threshold: usize,
    ) -> Result<crate::wallet::ReservesOutput, Error> {
        self.wallet.create_reserves_output(amount_sats, partners, threshold)
    }

    // ========================================================================
    // Ledger Management
    // ========================================================================

    /// Open a new ledger backed by our reserves UTXO
    ///
    /// This creates a self-ledger where we are the operator. The `enforcement_block`
    /// parameter controls when collateral size requirements are enforced:
    /// - 0: Immediate enforcement (joining an established network)
    /// - Future block: Bootstrap phase (allows cross-establishing collateral)
    ///
    /// For BDK, the ledger is identified by the reserves UTXO address (stored in
    /// ledger_address). The reserves_id field uses our own pubkey since there is
    /// no separate partner node.
    pub fn open_ledger(
        &self,
        enforcement_block: u64,
    ) -> Result<Ledger, Error> {
        // Get our reserves info
        let reserves_balance = self.wallet.get_reserves_balance()?;
        let reserves_outpoint = self.wallet.get_reserves_outpoint();

        if reserves_balance == 0 {
            return Err(Error::NoReserves);
        }

        // Get funding txid and vout from reserves outpoint
        let (funding_txid, funding_vout) = if let Some(outpoint) = reserves_outpoint {
            (outpoint.txid.to_byte_array(), outpoint.vout as u16)
        } else {
            ([0u8; 32], 0u16)
        };

        // Get the ledger address (reserves address) - this identifies the ledger
        let ledger_address = self.wallet.get_reserves_address()
            .map(|a| a.to_string())
            .unwrap_or_default();

        // Create the ledger state
        let enforcement = if enforcement_block > 0 {
            Some(enforcement_block)
        } else {
            None
        };

        // For BDK, use the ledger_address as the reserves_id (identifies the reserves UTXO)
        let reserves_id = ledger_address.clone();

        // Get or create the ledger - this automatically adds LedgerOpen and ReservesIncrease
        // if it's a new ledger for our own operator
        let ledger_arc = self.handler.get_or_create_ledger(self.node_id, reserves_id.clone());

        // Update enforcement block and other state
        {
            let mut ledger_guard = ledger_arc.write().unwrap();
            ledger_guard.state.collateral_enforcement_block = enforcement;
            ledger_guard.state.reserves.spend_to = self.node_id;
        }

        // Persist the ledger
        if let Err(e) = self.handler.persist_ledger(&self.node_id, &reserves_id) {
            tracing::error!("Failed to persist ledger: {}", e);
        }

        // Create handshake message to send to partner (wire protocol)
        // Note: For BDK self-ledger, this handshake may be sent to self or skipped
        let handshake_msg = deposits_core::messages::HandshakeMsg {
            protocol_version: deposits_core::messages::PROTOCOL_VERSION,
            min_protocol_version: deposits_core::messages::PROTOCOL_VERSION,
            features: 0,
            operator_id: self.node_id,
            reserves_id: reserves_id.clone(),
            funding_txid,
            funding_vout,
            collateral_enforcement_block: enforcement_block,
        };

        // Queue the handshake message (for BDK, sent to self as there's no remote partner)
        let _ = self.handler.queue_message(
            self.node_id,
            deposits_core::messages::DepositsMessage::Handshake(handshake_msg),
        );

        // Return the ledger
        let ledger_arc = self.handler.get_or_create_ledger(self.node_id, reserves_id.clone());
        let ledger = ledger_arc.read().unwrap().clone();
        Ok(ledger)
    }

    /// List all ledgers
    pub fn list_ledgers(&self) -> HashMap<(PublicKey, String), Arc<RwLock<Ledger>>> {
        let ledgers = self.handler.ledgers.lock().unwrap();
        ledgers.clone()
    }

    /// Import a ledger from an export (validates before storing)
    pub fn import_ledger(
        &self,
        export: deposits_core::validation::LedgerExport,
    ) -> Result<(deposits_core::validation::ValidationReport, Ledger), String> {
        let (report, ledger_arc) = self.handler.import_ledger(export)?;
        let ledger = ledger_arc.read().unwrap().clone();
        Ok((report, ledger))
    }

    // ========================================================================
    // Quorum Member Management
    // ========================================================================

    /// Request a peer to be a quorum member
    pub async fn request_partner(&self, peer: PublicKey) -> Result<(), Error> {
        // Create a coordination message for partnership request
        // For now, this is a simple handshake-like message
        let request_msg = deposits_core::messages::DepositsMessage::Handshake(
            deposits_core::messages::HandshakeMsg {
                protocol_version: deposits_core::messages::PROTOCOL_VERSION,
                min_protocol_version: deposits_core::messages::PROTOCOL_VERSION,
                features: 0x01, // Flag indicating partnership request
                operator_id: self.node_id,
                reserves_id: peer.to_string(),
                funding_txid: [0u8; 32],
                funding_vout: 0,
                collateral_enforcement_block: 0,
            },
        );

        // Send via Nostr
        self.nostr.send_message(peer, request_msg).await?;

        Ok(())
    }

    /// Add a quorum member to our ledger.
    ///
    /// This appends a QuorumAddMember operation to our ledger with the member's signature.
    /// For testing, we can generate a placeholder signature.
    ///
    /// # Arguments
    /// * `reserves_id` - Our ledger's reserves ID
    /// * `quorum_member` - The public key of the new quorum member
    /// * `signature` - The member's consent signature (or placeholder for testing)
    pub fn add_quorum_member(
        &self,
        reserves_id: &str,
        quorum_member: PublicKey,
        signature: [u8; 64],
    ) -> Result<(), Error> {
        {
            let ledgers = self.handler.ledgers.lock().unwrap();

            // Find our ledger (where we are the operator)
            let ledger_arc = ledgers
                .get(&(self.node_id, reserves_id.to_string()))
                .ok_or_else(|| Error::Protocol("Ledger not found".to_string()))?;

            let mut ledger = ledger_arc.write().unwrap();

            // Check if already a member
            if ledger.state.quorum_members.contains(&quorum_member) {
                return Err(Error::Protocol("Already a quorum member".to_string()));
            }

            // Get current block info
            let block_height = self.wallet.get_block_height().unwrap_or(0);
            let block_hash = self.wallet.get_block_hash().unwrap_or([0u8; 32]);

            // Create and append QuorumAddMember operation
            let operation = deposits_core::messages::LedgerOperation::QuorumAddMember {
                quorum_member,
                quorum_member_signature: signature,
            };

            ledger.append_operation_with_block(
                operation,
                deposits_core::messages::consts::QUORUM_ADD_MEMBER,
                block_height,
                block_hash,
            ).map_err(|e| Error::Protocol(format!("Failed to add quorum member: {:?}", e)))?;
        }

        // Sign the update
        self.sign_last_update(reserves_id)?;

        // Persist the ledger
        if let Err(e) = self.handler.persist_ledger(&self.node_id, reserves_id) {
            tracing::error!("Failed to persist ledger: {}", e);
        }

        Ok(())
    }

    /// Record that we have joined another operator's quorum.
    ///
    /// This appends a QuorumJoin operation to our own ledger, creating a two-sided audit trail.
    ///
    /// # Arguments
    /// * `our_reserves_id` - Our own ledger's reserves ID
    /// * `target_operator` - The operator whose quorum we're joining
    /// * `target_reserves_id` - The reserves ID of the ledger we're monitoring
    /// * `membership_expires` - Block height when our membership commitment expires
    /// * `signature` - Our consent signature
    pub fn record_quorum_join(
        &self,
        our_reserves_id: &str,
        target_operator: PublicKey,
        target_reserves_id: &str,
        membership_expires: u32,
        signature: [u8; 64],
    ) -> Result<(), Error> {
        {
            let ledgers = self.handler.ledgers.lock().unwrap();

            // Find our ledger (where we are the operator)
            let ledger_arc = ledgers
                .get(&(self.node_id, our_reserves_id.to_string()))
                .ok_or_else(|| Error::Protocol("Our ledger not found".to_string()))?;

            let mut ledger = ledger_arc.write().unwrap();

            // Get current block info
            let block_height = self.wallet.get_block_height().unwrap_or(0);
            let block_hash = self.wallet.get_block_hash().unwrap_or([0u8; 32]);

            // Create and append QuorumJoin operation
            let operation = deposits_core::messages::LedgerOperation::QuorumJoin {
                operator_id: target_operator,
                reserves_id: target_reserves_id.to_string(),
                membership_expires,
                our_signature: signature,
            };

            ledger.append_operation_with_block(
                operation,
                deposits_core::messages::consts::QUORUM_JOIN,
                block_height,
                block_hash,
            ).map_err(|e| Error::Protocol(format!("Failed to record quorum join: {:?}", e)))?;
        }

        // Sign the update
        self.sign_last_update(our_reserves_id)?;

        // Persist the ledger
        if let Err(e) = self.handler.persist_ledger(&self.node_id, our_reserves_id) {
            tracing::error!("Failed to persist ledger: {}", e);
        }

        Ok(())
    }

    /// List all quorum members across all ledgers
    /// Returns (identifier, role) tuples where identifier is pubkey or reserves_id string
    pub fn list_partners(&self) -> Vec<(String, String)> {
        let mut partners = Vec::new();
        let ledgers = self.handler.ledgers.lock().unwrap();

        for ((operator, reserves_id), ledger_arc) in ledgers.iter() {
            let ledger = ledger_arc.read().unwrap();
            let role = if *operator == self.node_id {
                "Partner on our ledger"
            } else {
                "We are partner on their ledger"
            };

            // Add the partner/operator
            if *operator == self.node_id {
                // reserves_id is now a String (could be pubkey string or address)
                partners.push((reserves_id.clone(), role.to_string()));
            } else {
                partners.push((operator.to_string(), role.to_string()));
            }

            // Add quorum members
            for cp in &ledger.state.quorum_members {
                partners.push((cp.to_string(), "Quorum member".to_string()));
            }
        }

        // Deduplicate
        partners.sort_by(|a, b| a.0.cmp(&b.0));
        partners.dedup_by(|a, b| a.0 == b.0);

        partners
    }

    /// Rotate reserves to use quorum-based Taproot spending
    ///
    /// This creates a new reserves output with tiered spending:
    /// - Tier 0: Majority of quorum + operator (immediate)
    /// - Tier 1: Operator only after first quorum member expires
    /// - Tier 2: Emergency recovery after extended timeout
    ///
    /// The rotation should be scheduled before the first quorum member expires
    /// to maintain quorum-based security.
    ///
    /// # Arguments
    /// * `reserves_id` - The reserves ID (ledger address) of the ledger to rotate for
    ///
    /// # Returns
    /// The new Taproot reserves address and txid, or error if rotation fails
    pub fn rotate_reserves_to_quorum(
        &self,
        reserves_id: &str,
    ) -> Result<RotateReservesResult, Error> {
        // Get the ledger
        let ledgers = self.handler.ledgers.lock().unwrap();
        let ledger_arc = ledgers
            .get(&(self.node_id, reserves_id.to_string()))
            .ok_or_else(|| Error::Protocol("Ledger not found".to_string()))?
            .clone();
        drop(ledgers);

        let (quorum_members, quorum_expiries, ledger_hash, _current_reserves) = {
            let ledger = ledger_arc.read().unwrap();

            // Get quorum members and their expiration times
            let members = ledger.state.quorum_members.clone();

            // For now, use a fixed expiration window per member
            // In a real implementation, these would come from QuorumAddMember operations
            let current_block = self.wallet.get_block_height().unwrap_or(0);
            let default_expiry = current_block + 1000; // ~1 week

            // TODO: Get actual expiries from quorum member info in ledger
            let expiries: Vec<u32> = members.iter().map(|_| default_expiry).collect();

            let hash = ledger.hash();
            let reserves = ledger.state.reserves.amount;

            (members, expiries, hash, reserves)
        };

        if quorum_members.is_empty() {
            return Err(Error::Protocol(
                "No quorum members to rotate to. Add quorum members first.".to_string()
            ));
        }

        // Rotate the existing P2WSH reserves to new Taproot output
        let result = self.wallet.rotate_reserves_to_taproot(
            quorum_members.clone(),
            quorum_expiries.clone(),
            ledger_hash,
        )?;

        // Broadcast the rotation transaction
        let txid = self.wallet.broadcast(&result.tx)?;

        tracing::info!(
            "Rotated reserves to Taproot quorum-based output: txid={}, address={}, {} members, first expiry at block {}",
            txid,
            result.address,
            quorum_members.len(),
            result.first_expiry_block
        );

        // Append ReservesRotate operation to the ledger for audit trail
        {
            let block_height = self.wallet.get_block_height().unwrap_or(0);
            let block_hash = [0u8; 32]; // We don't have the block hash yet since tx is just broadcast

            // Convert txid to bytes
            let txid_bytes: [u8; 32] = {
                let mut bytes = txid.to_byte_array();
                bytes.reverse(); // Bitcoin txids are displayed in reverse byte order
                bytes
            };

            // Calculate quorum parameters
            let quorum_size = (quorum_members.len() + 1) as u8; // +1 for operator
            let quorum_threshold = (quorum_size / 2) + 1; // Majority

            let operation = LedgerOperation::ReservesRotate {
                reserves_id: result.address.to_string(),
                spending_txid: txid_bytes,
                new_outpoint_txid: txid_bytes, // Same tx creates the new output
                new_outpoint_vout: result.outpoint.vout,
                amount: result.amount,
                quorum_threshold,
                quorum_size,
                first_expiry_block: result.first_expiry_block,
                ledger_hash,
            };

            let mut ledger = ledger_arc.write().unwrap();
            ledger.append_operation_with_block(
                operation,
                deposits_core::messages::consts::RESERVES_ROTATE,
                block_height,
                block_hash,
            ).map_err(|e| Error::Protocol(format!("Failed to record reserves rotation: {:?}", e)))?;

            tracing::info!(
                "Appended ReservesRotate operation to ledger: txid={}, quorum={}/{}",
                txid,
                quorum_threshold,
                quorum_size
            );
        }

        // Sign the update
        self.sign_last_update(&reserves_id)?;

        // Persist the ledger with the new operation
        if let Err(e) = self.handler.persist_ledger(&self.node_id, &reserves_id) {
            tracing::error!("Failed to persist ledger after rotation: {}", e);
        }

        Ok(RotateReservesResult {
            txid: txid.to_string(),
            new_address: result.address.to_string(),
            amount_sats: result.amount,
            quorum_member_count: quorum_members.len(),
            first_expiry_block: result.first_expiry_block,
            ledger_hash,
        })
    }

    /// Lock a deposit's balance as collateral backing for the operator.
    ///
    /// The locked amount cannot be withdrawn until the lock expires.
    /// Uses ratchet semantics: can only increase amount AND extend duration.
    ///
    /// # Arguments
    /// * `reserves_id` - The reserves ID (ledger address) where the deposit exists
    /// * `deposit_pubkey` - The deposit's public key
    /// * `deposit_secret` - The deposit holder's secret key for signing
    /// * `amount_msats` - Amount to lock as collateral (millisatoshis)
    /// * `lock_until_block` - Block height when the lock expires
    ///
    /// # Returns
    /// A signed CollateralAttestationMsg that the requesting operator can record on their own ledger
    pub fn lock_collateral(
        &self,
        reserves_id: &str,
        deposit_pubkey: PublicKey,
        deposit_secret: &bitcoin::secp256k1::SecretKey,
        amount_msats: u64,
        lock_until_block: u32,
        requesting_operator: PublicKey,
    ) -> Result<deposits_core::CollateralAttestationMsg, Error> {
        let ledger_arc = self.handler.get_or_create_ledger(self.node_id, reserves_id.to_string());

        let attestation = {
            let mut ledger = ledger_arc.write().unwrap();

            // Check if deposit exists
            if !ledger.state.deposits.contains_key(&deposit_pubkey) {
                return Err(Error::Protocol(format!(
                    "Deposit not found for pubkey {}",
                    deposit_pubkey
                )));
            }

            // Create the deposit holder's signature for the lock
            let lock_signature = deposits_core::signature_utils::create_collateral_lock_signature(
                deposit_secret,
                &deposit_pubkey,
                amount_msats,
                lock_until_block,
                &self.node_id,
            ).map_err(|e| Error::Protocol(format!("Failed to create signature: {:?}", e)))?;

            // Apply the CollateralLock operation
            let operation = LedgerOperation::CollateralLock {
                deposit_pubkey,
                amount: amount_msats,
                lock_until_block,
                operator_id: self.node_id,
                deposit_holder_signature: lock_signature,
            };

            let block_height = self.wallet.get_block_height().unwrap_or(0);
            let block_hash = self.wallet.get_block_hash().unwrap_or([0u8; 32]);
            ledger.append_operation_with_block(operation, deposits_core::messages::consts::COLLATERAL_LOCK, block_height, block_hash)
                .map_err(|e| Error::Protocol(format!("Failed to lock collateral: {:?}", e)))?;

            // Calculate total locked collateral from all deposits
            let total_locked: u64 = ledger.state.deposits.values()
                .filter(|d| d.collateral_lock_expires > block_height)
                .map(|d| d.collateral_lock_amount)
                .sum();

            // Find minimum lock expiry among active locks
            let min_lock_until: u32 = ledger.state.deposits.values()
                .filter(|d| d.collateral_lock_expires > block_height && d.collateral_lock_amount > 0)
                .map(|d| d.collateral_lock_expires)
                .min()
                .unwrap_or(lock_until_block);

            // Get current ledger hash for the attestation
            let ledger_hash = ledger.hash();

            // Create operator's attestation signature
            // Sign: operator || quorum_member || amount || block_height || lock_until_block || ledger_hash
            let attestation_signature = self.sign_collateral_attestation(
                requesting_operator,
                total_locked,
                block_height,
                min_lock_until,
                ledger_hash,
            )?;

            deposits_core::CollateralAttestationMsg {
                operator: self.node_id,
                quorum_member: requesting_operator,
                amount: total_locked,
                block_height,
                lock_until_block: min_lock_until,
                signature: attestation_signature,
                ledger_hash,
            }
        };

        // Sign the update
        self.sign_last_update(reserves_id)?;

        // Persist the ledger
        if let Err(e) = self.handler.persist_ledger(&self.node_id, reserves_id) {
            tracing::error!("Failed to persist ledger: {}", e);
        }

        tracing::info!(
            "Created collateral lock for deposit {}: {} msats until block {}, attestation for {}",
            deposit_pubkey,
            attestation.amount,
            attestation.lock_until_block,
            requesting_operator
        );

        Ok(attestation)
    }

    /// Sign a collateral attestation message
    fn sign_collateral_attestation(
        &self,
        quorum_member: PublicKey,
        amount: u64,
        block_height: u32,
        lock_until_block: u32,
        ledger_hash: [u8; 32],
    ) -> Result<[u8; 64], Error> {
        use bitcoin::hashes::{sha256, Hash};
        use bitcoin::secp256k1::{Secp256k1, Message};

        let mut sign_content = Vec::new();
        sign_content.extend_from_slice(b"COLLATERAL_ATTESTATION:");
        sign_content.extend_from_slice(&self.node_id.serialize());
        sign_content.extend_from_slice(&quorum_member.serialize());
        sign_content.extend_from_slice(&amount.to_le_bytes());
        sign_content.extend_from_slice(&block_height.to_le_bytes());
        sign_content.extend_from_slice(&lock_until_block.to_le_bytes());
        sign_content.extend_from_slice(&ledger_hash);

        let hash = sha256::Hash::hash(&sign_content);
        let msg = Message::from_digest(hash.to_byte_array());

        let secp = Secp256k1::new();
        let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &self.wallet.operator_secret());
        let sig = secp.sign_schnorr(&msg, &keypair);

        Ok(*sig.as_ref())
    }

    /// Record a received CollateralAttestation on our own ledger
    ///
    /// This is called by an operator who received an attestation from another operator
    /// after pledging collateral on their ledger. The attestation is recorded on the
    /// caller's own ledger so quorum members can see it.
    pub fn record_collateral_attestation(
        &self,
        reserves_id: &str,
        attestation: deposits_core::CollateralAttestationMsg,
    ) -> Result<(), Error> {
        // Verify we are the quorum_member in the attestation
        if attestation.quorum_member != self.node_id {
            return Err(Error::Protocol(format!(
                "Attestation is for {}, not us ({})",
                attestation.quorum_member, self.node_id
            )));
        }

        let ledger_arc = self.handler.get_or_create_ledger(self.node_id, reserves_id.to_string());

        {
            let mut ledger = ledger_arc.write().unwrap();

            // Create the CollateralAttestation operation
            let operation = LedgerOperation::CollateralAttestation {
                collateral_operator: attestation.operator,
                quorum_member: attestation.quorum_member,
                amount: attestation.amount,
                block_height: attestation.block_height,
                lock_until_block: attestation.lock_until_block,
                signature: attestation.signature,
                ledger_hash: attestation.ledger_hash,
            };

            let block_height = self.wallet.get_block_height().unwrap_or(0);
            let block_hash = self.wallet.get_block_hash().unwrap_or([0u8; 32]);
            ledger.append_operation_with_block(
                operation,
                deposits_core::messages::consts::COLLATERAL_ATTESTATION,
                block_height,
                block_hash,
            ).map_err(|e| Error::Protocol(format!("Failed to record attestation: {:?}", e)))?;
        }

        // Sign the update
        self.sign_last_update(reserves_id)?;

        // Persist the ledger
        if let Err(e) = self.handler.persist_ledger(&self.node_id, reserves_id) {
            tracing::error!("Failed to persist ledger: {}", e);
        }

        tracing::info!(
            "Recorded collateral attestation from {} for {} msats",
            attestation.operator,
            attestation.amount
        );

        Ok(())
    }

    // ========================================================================
    // Deposit Offer Management (On-Chain Funding)
    // ========================================================================

    /// Create a deposit offer for on-chain funding
    ///
    /// This creates a signed commitment from the operator to credit a deposit
    /// with funds sent to a specific address, up to a maximum amount, before
    /// a deadline block.
    ///
    /// The `ledger_id` should be the 64-char hex hash that identifies the ledger
    /// (stable across custody transfers).
    pub fn create_deposit_offer(
        &self,
        ledger_id: &str,
        deposit_pubkey: PublicKey,
        max_amount_sats: u64,
        min_amount_sats: u64,
        blocks_valid: u32,
    ) -> Result<DepositOffer, Error> {
        // Get current block height
        let current_block = self.wallet.get_block_height()?;
        let deadline_block = current_block + blocks_valid;

        // Generate a new funding address
        let funding_address = self.wallet.get_new_address()?;
        let funding_address_str = funding_address.to_string();

        // Get the signing message and compute offer ID
        let signing_message = DepositOffer::signing_message(
            &self.node_id,
            ledger_id,
            &deposit_pubkey,
            &funding_address_str,
            max_amount_sats,
            min_amount_sats,
            deadline_block,
        );
        let offer_id = DepositOffer::compute_offer_id(&signing_message);

        // Sign the offer
        let signature = deposits_core::create_deposit_offer_signature(
            &self.wallet.operator_secret(),
            &self.node_id,
            ledger_id,
            &deposit_pubkey,
            &funding_address_str,
            max_amount_sats,
            min_amount_sats,
            deadline_block,
        ).map_err(|e| Error::Protocol(format!("Failed to sign offer: {:?}", e)))?;

        // Create the offer
        let offer = DepositOffer {
            operator_id: self.node_id,
            ledger_id: ledger_id.to_string(),
            deposit_pubkey,
            funding_address: funding_address_str,
            max_amount_sats,
            min_amount_sats,
            deadline_block,
            created_at_block: current_block,
            offer_id,
            operator_signature: signature,
        };

        // Store the offer
        {
            let mut offers = self.deposit_offers.lock().unwrap();
            offers.insert(offer_id, (offer.clone(), DepositOfferStatus::Pending));
        }

        // Persist to disk
        self.save_deposit_offers()?;

        tracing::info!(
            "Created deposit offer {} for {} sats to {}",
            hex::encode(&offer_id[..8]),
            max_amount_sats,
            offer.funding_address
        );

        Ok(offer)
    }

    /// List all deposit offers
    pub fn list_deposit_offers(&self) -> Vec<(DepositOffer, DepositOfferStatus)> {
        let offers = self.deposit_offers.lock().unwrap();
        offers.values().cloned().collect()
    }

    /// Get a specific deposit offer by ID
    pub fn get_deposit_offer(&self, offer_id: &[u8; 32]) -> Option<(DepositOffer, DepositOfferStatus)> {
        let offers = self.deposit_offers.lock().unwrap();
        offers.get(offer_id).cloned()
    }

    /// Update the status of a deposit offer
    pub fn update_deposit_offer_status(
        &self,
        offer_id: &[u8; 32],
        status: DepositOfferStatus,
    ) -> Result<(), Error> {
        {
            let mut offers = self.deposit_offers.lock().unwrap();
            if let Some((_, ref mut current_status)) = offers.get_mut(offer_id) {
                *current_status = status;
            } else {
                return Err(Error::Protocol("Deposit offer not found".to_string()));
            }
        }
        self.save_deposit_offers()
    }

    /// Check for expired offers and update their status
    pub fn check_expired_offers(&self) -> Result<Vec<[u8; 32]>, Error> {
        let current_block = self.wallet.get_block_height()?;
        let mut expired = Vec::new();

        {
            let mut offers = self.deposit_offers.lock().unwrap();
            for (offer_id, (offer, status)) in offers.iter_mut() {
                if matches!(status, DepositOfferStatus::Pending) && offer.is_expired(current_block) {
                    *status = DepositOfferStatus::Expired {
                        expired_at_block: current_block,
                    };
                    expired.push(*offer_id);
                }
            }
        }

        if !expired.is_empty() {
            self.save_deposit_offers()?;
        }

        Ok(expired)
    }

    /// Load deposit offers from disk
    fn load_deposit_offers(
        data_dir: &PathBuf,
    ) -> Result<HashMap<[u8; 32], (DepositOffer, DepositOfferStatus)>, Error> {
        let offers_file = data_dir.join("wallet").join("deposit_offers.json");
        if !offers_file.exists() {
            return Ok(HashMap::new());
        }

        let contents = std::fs::read_to_string(&offers_file)
            .map_err(|e| Error::Wallet(format!("Failed to read deposit offers: {}", e)))?;

        let offers: Vec<(DepositOffer, DepositOfferStatus)> = serde_json::from_str(&contents)
            .map_err(|e| Error::Wallet(format!("Failed to parse deposit offers: {}", e)))?;

        let mut map = HashMap::new();
        for (offer, status) in offers {
            map.insert(offer.offer_id, (offer, status));
        }

        // Debug: print what we loaded
        println!("DEBUG: Loaded {} deposit offers from {:?}", map.len(), offers_file);
        for (offer_id, (offer, _status)) in &map {
            println!("DEBUG:   offer_id={} ledger={}", hex::encode(&offer_id[..8]), &offer.ledger_id[..20.min(offer.ledger_id.len())]);
        }

        tracing::info!("Loaded {} deposit offers from disk", map.len());
        Ok(map)
    }

    /// Save deposit offers to disk
    fn save_deposit_offers(&self) -> Result<(), Error> {
        let offers_file = self.data_dir.join("wallet").join("deposit_offers.json");

        let offers: Vec<(DepositOffer, DepositOfferStatus)> = {
            let offers = self.deposit_offers.lock().unwrap();
            offers.values().cloned().collect()
        };

        let contents = serde_json::to_string_pretty(&offers)
            .map_err(|e| Error::Wallet(format!("Failed to serialize deposit offers: {}", e)))?;

        // Debug: print what we're saving
        println!("DEBUG: Saving {} deposit offers to {:?}", offers.len(), offers_file);
        for (offer, status) in &offers {
            println!("DEBUG:   offer_id={} ledger={}", hex::encode(&offer.offer_id[..8]), &offer.ledger_id[..20.min(offer.ledger_id.len())]);
        }

        std::fs::write(&offers_file, contents)
            .map_err(|e| Error::Wallet(format!("Failed to write deposit offers: {}", e)))?;

        tracing::info!("Saved {} deposit offers to disk", offers.len());
        Ok(())
    }

    // ========================================================================
    // On-Chain Withdrawal Management
    // ========================================================================

    /// Lock funds for an on-chain withdrawal
    ///
    /// This creates a withdrawal request and locks the funds in the deposit.
    /// The depositor must sign the withdrawal to authorize it.
    /// The nonce must be provided by the depositor (who created the signature).
    pub fn lock_withdrawal(
        &self,
        reserves_id: &str,
        deposit_pubkey: PublicKey,
        destination_address: String,
        amount_sats: u64,
        fee_sats: u64,
        nonce: [u8; 32],
        depositor_signature: [u8; 64],
        memo: Option<String>,
    ) -> Result<WithdrawalLockResult, Error> {
        let current_block = self.wallet.get_block_height()?;

        // Compute withdrawal ID
        let signing_message = OnChainWithdrawal::signing_message(
            &nonce,
            &deposit_pubkey,
            &destination_address,
            amount_sats,
            fee_sats,
        );
        let withdrawal_id = OnChainWithdrawal::compute_withdrawal_id(&signing_message);

        // Create the withdrawal
        let withdrawal = OnChainWithdrawal {
            withdrawal_id,
            nonce,
            deposit_pubkey,
            destination_address: destination_address.clone(),
            amount_sats,
            fee_sats,
            requested_at_block: current_block,
            memo,
            depositor_signature,
        };

        // Verify the signature
        let sig_valid = deposits_core::verify_withdrawal_signature(&withdrawal)
            .map_err(|e| Error::Protocol(format!("Signature verification failed: {:?}", e)))?;

        if !sig_valid {
            return Err(Error::Protocol("Invalid withdrawal signature".to_string()));
        }

        // Get the ledger and apply OnchainLock operation
        let ledger_arc = self.handler.get_or_create_ledger(self.node_id, reserves_id.to_string());
        let (previous_balance, new_balance) = {
            let mut ledger = ledger_arc.write().unwrap();

            // Check if deposit exists and has sufficient balance
            let deposit = ledger.state.deposits.get(&deposit_pubkey)
                .ok_or_else(|| Error::Protocol(format!(
                    "Deposit not found for pubkey {}",
                    deposit_pubkey
                )))?;

            let total_debit_msats = (amount_sats + fee_sats) * 1000;
            if deposit.balance < total_debit_msats {
                return Err(Error::Protocol(format!(
                    "Insufficient balance: {} msats available, {} msats needed",
                    deposit.balance, total_debit_msats
                )));
            }

            let prev_balance = deposit.balance;

            // Apply the OnchainLock operation
            let operation = LedgerOperation::OnchainLock {
                deposit_pubkey,
                amount: total_debit_msats,
                destination_address: destination_address.clone(),
                withdrawal_id,
            };

            let block_height = self.wallet.get_block_height().unwrap_or(0);
            let block_hash = self.wallet.get_block_hash().unwrap_or([0u8; 32]);
            ledger.append_operation_with_block(operation, deposits_core::messages::consts::ONCHAIN_LOCK, block_height, block_hash)
                .map_err(|e| Error::Protocol(format!("Failed to lock withdrawal: {:?}", e)))?;

            // Get new balance
            let new_bal = ledger.state.deposits.get(&deposit_pubkey)
                .map(|d| d.balance)
                .unwrap_or(0);

            (prev_balance, new_bal)
        };

        // Sign the update
        self.sign_last_update(reserves_id)?;

        // Persist the ledger
        if let Err(e) = self.handler.persist_ledger(&self.node_id, reserves_id) {
            tracing::error!("Failed to persist ledger: {}", e);
        }

        // Store the withdrawal as locked
        let status = OnChainWithdrawalStatus::Locked {
            locked_at_block: current_block,
        };

        {
            let mut withdrawals = self.withdrawals.lock().unwrap();
            withdrawals.insert(withdrawal_id, (withdrawal.clone(), status));
        }

        // Persist to disk
        self.save_withdrawals()?;

        // Calculate balances (convert sats to msats for the result)
        let total_debit_msats = withdrawal.total_debit() * 1000;

        tracing::info!(
            "Locked withdrawal {} for {} sats + {} fee to {}, balance {} -> {} msats",
            hex::encode(&withdrawal_id[..8]),
            amount_sats,
            fee_sats,
            withdrawal.destination_address,
            previous_balance,
            new_balance
        );

        Ok(WithdrawalLockResult {
            withdrawal: withdrawal.clone(),
            previous_balance_msats: previous_balance,
            new_balance_msats: new_balance,
            locked_amount_msats: total_debit_msats,
        })
    }

    /// Complete a withdrawal by broadcasting the transaction
    ///
    /// This creates and broadcasts the on-chain transaction with the required
    /// OP_RETURN commitment, then marks the withdrawal as complete.
    pub fn complete_withdrawal(
        &self,
        reserves_id: &str,
        withdrawal_id: &[u8; 32],
    ) -> Result<WithdrawalCompleteResult, Error> {
        let current_block = self.wallet.get_block_height()?;

        // Get the withdrawal
        let withdrawal = {
            let withdrawals = self.withdrawals.lock().unwrap();
            match withdrawals.get(withdrawal_id) {
                Some((w, OnChainWithdrawalStatus::Locked { .. })) => w.clone(),
                Some((_, status)) => {
                    return Err(Error::Protocol(format!(
                        "Withdrawal not in Locked state: {:?}",
                        status
                    )));
                }
                None => return Err(Error::OfferNotFound),
            }
        };

        // Build and broadcast the transaction
        let txid = self.wallet.send_withdrawal(&withdrawal)?;

        // Convert txid string to bytes for the ledger operation
        let txid_bytes: [u8; 32] = hex::decode(&txid)
            .ok()
            .and_then(|v| {
                let mut arr = [0u8; 32];
                if v.len() == 32 {
                    arr.copy_from_slice(&v);
                    Some(arr)
                } else {
                    None
                }
            })
            .unwrap_or([0u8; 32]);

        // Apply OnchainFulfill operation to the ledger
        let final_balance = {
            let ledger_arc = self.handler.get_or_create_ledger(self.node_id, reserves_id.to_string());
            let mut ledger = ledger_arc.write().unwrap();

            let operation = LedgerOperation::OnchainFulfill {
                deposit_pubkey: withdrawal.deposit_pubkey,
                withdrawal_id: *withdrawal_id,
                amount: withdrawal.amount_sats * 1000, // Convert to msats
                txid: txid_bytes,
                destination_address: withdrawal.destination_address.clone(),
            };

            let block_height = self.wallet.get_block_height().unwrap_or(0);
            let block_hash = self.wallet.get_block_hash().unwrap_or([0u8; 32]);
            ledger.append_operation_with_block(operation, deposits_core::messages::consts::ONCHAIN_FULFILL, block_height, block_hash)
                .map_err(|e| Error::Protocol(format!("Failed to fulfill withdrawal: {:?}", e)))?;

            // Get final balance
            ledger.state.deposits.get(&withdrawal.deposit_pubkey)
                .map(|d| d.balance)
                .unwrap_or(0)
        };

        // Sign the update
        self.sign_last_update(reserves_id)?;

        // Persist the ledger
        if let Err(e) = self.handler.persist_ledger(&self.node_id, reserves_id) {
            tracing::error!("Failed to persist ledger: {}", e);
        }

        // Update status
        let new_status = OnChainWithdrawalStatus::Broadcast {
            txid: txid.clone(),
            broadcast_at_block: current_block,
        };

        {
            let mut withdrawals = self.withdrawals.lock().unwrap();
            if let Some((_, status)) = withdrawals.get_mut(withdrawal_id) {
                *status = new_status;
            }
        }

        // Persist
        self.save_withdrawals()?;

        tracing::info!(
            "Completed withdrawal {}: txid={}, final balance={} msats",
            hex::encode(&withdrawal_id[..8]),
            txid,
            final_balance
        );

        Ok(WithdrawalCompleteResult {
            withdrawal_id: *withdrawal_id,
            txid,
            amount_sats: withdrawal.amount_sats,
            fee_sats: withdrawal.fee_sats,
            final_balance_msats: final_balance,
        })
    }

    /// Cancel a withdrawal (only if not yet broadcast)
    pub fn cancel_withdrawal(
        &self,
        withdrawal_id: &[u8; 32],
        reason: String,
    ) -> Result<(), Error> {
        let current_block = self.wallet.get_block_height()?;

        {
            let mut withdrawals = self.withdrawals.lock().unwrap();
            match withdrawals.get_mut(withdrawal_id) {
                Some((_, status @ OnChainWithdrawalStatus::Locked { .. })) => {
                    *status = OnChainWithdrawalStatus::Cancelled {
                        cancelled_at_block: current_block,
                        reason,
                    };
                }
                Some((_, status)) => {
                    return Err(Error::Protocol(format!(
                        "Cannot cancel withdrawal in state: {:?}",
                        status
                    )));
                }
                None => return Err(Error::OfferNotFound),
            }
        }

        self.save_withdrawals()?;
        Ok(())
    }

    /// List all withdrawals
    pub fn list_withdrawals(&self) -> Vec<(OnChainWithdrawal, OnChainWithdrawalStatus)> {
        let withdrawals = self.withdrawals.lock().unwrap();
        withdrawals.values().cloned().collect()
    }

    /// Get a specific withdrawal by ID
    pub fn get_withdrawal(
        &self,
        withdrawal_id: &[u8; 32],
    ) -> Option<(OnChainWithdrawal, OnChainWithdrawalStatus)> {
        let withdrawals = self.withdrawals.lock().unwrap();
        withdrawals.get(withdrawal_id).cloned()
    }

    /// Generate a random nonce for withdrawal uniqueness
    fn generate_nonce() -> [u8; 32] {
        use std::time::{SystemTime, UNIX_EPOCH};
        let mut nonce = [0u8; 32];

        // Use timestamp + some pseudo-randomness
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        nonce[0..16].copy_from_slice(&now.to_le_bytes());

        // Hash it for better distribution
        use bitcoin::hashes::{sha256, Hash};
        let hash = sha256::Hash::hash(&nonce);
        hash.to_byte_array()
    }

    /// Load withdrawals from disk
    fn load_withdrawals(
        data_dir: &PathBuf,
    ) -> Result<HashMap<[u8; 32], (OnChainWithdrawal, OnChainWithdrawalStatus)>, Error> {
        let withdrawals_file = data_dir.join("wallet").join("withdrawals.json");
        if !withdrawals_file.exists() {
            return Ok(HashMap::new());
        }

        let contents = std::fs::read_to_string(&withdrawals_file)
            .map_err(|e| Error::Wallet(format!("Failed to read withdrawals: {}", e)))?;

        let withdrawals: Vec<(OnChainWithdrawal, OnChainWithdrawalStatus)> =
            serde_json::from_str(&contents)
                .map_err(|e| Error::Wallet(format!("Failed to parse withdrawals: {}", e)))?;

        let mut map = HashMap::new();
        for (withdrawal, status) in withdrawals {
            map.insert(withdrawal.withdrawal_id, (withdrawal, status));
        }

        tracing::info!("Loaded {} withdrawals from disk", map.len());
        Ok(map)
    }

    /// Save withdrawals to disk
    fn save_withdrawals(&self) -> Result<(), Error> {
        let withdrawals_file = self.data_dir.join("wallet").join("withdrawals.json");

        let withdrawals: Vec<(OnChainWithdrawal, OnChainWithdrawalStatus)> = {
            let withdrawals = self.withdrawals.lock().unwrap();
            withdrawals.values().cloned().collect()
        };

        let contents = serde_json::to_string_pretty(&withdrawals)
            .map_err(|e| Error::Wallet(format!("Failed to serialize withdrawals: {}", e)))?;

        std::fs::write(&withdrawals_file, contents)
            .map_err(|e| Error::Wallet(format!("Failed to write withdrawals: {}", e)))?;

        tracing::info!("Saved {} withdrawals to disk", withdrawals.len());
        Ok(())
    }

    // ========================================================================
    // Deposit Management
    // ========================================================================

    /// Open a new deposit in a ledger
    ///
    /// Creates a deposit for a given public key in the ledger with the reserves_id.
    /// This applies a DepositOpen operation to the ledger.
    pub fn open_deposit(
        &self,
        reserves_id: &str,
        deposit_pubkey: PublicKey,
        fees: Option<FeeStructure>,
    ) -> Result<Deposit, Error> {
        let ledger_arc = self.handler.get_or_create_ledger(self.node_id, reserves_id.to_string());

        let deposit = {
            let mut ledger = ledger_arc.write().unwrap();

            // Check if deposit already exists
            if ledger.state.deposits.contains_key(&deposit_pubkey) {
                return Err(Error::Protocol(format!(
                    "Deposit already exists for pubkey {}",
                    deposit_pubkey
                )));
            }

            // Apply the DepositOpen operation with history tracking
            let operation = LedgerOperation::DepositOpen {
                pubkey: deposit_pubkey,
                fees: fees.clone(),
                payment_hash: None,
                invoice: None,
                cosigner_guarantee_signature: None,
            };

            let block_height = self.wallet.get_block_height().unwrap_or(0);
            let block_hash = self.wallet.get_block_hash().unwrap_or([0u8; 32]);
            ledger.append_operation_with_block(operation, deposits_core::messages::consts::DEPOSIT_OPEN, block_height, block_hash)
                .map_err(|e| Error::Protocol(format!("Failed to open deposit: {:?}", e)))?;

            // Return the created deposit
            ledger.state.deposits.get(&deposit_pubkey)
                .cloned()
                .ok_or_else(|| Error::Protocol("Deposit not found after creation".to_string()))?
        };

        // Sign the update
        self.sign_last_update(reserves_id)?;

        // Persist the ledger
        if let Err(e) = self.handler.persist_ledger(&self.node_id, reserves_id) {
            tracing::error!("Failed to persist ledger: {}", e);
        }

        tracing::info!(
            "Opened deposit {} in ledger with reserves {}",
            deposit_pubkey,
            reserves_id
        );

        Ok(deposit)
    }

    /// Credit a deposit with on-chain funds
    ///
    /// This applies an OnchainCredit operation to add funds to a deposit.
    /// Used when on-chain funding is received for a deposit offer.
    pub fn credit_deposit_onchain(
        &self,
        reserves_id: &str,
        deposit_pubkey: PublicKey,
        amount_msats: u64,
        txid: [u8; 32],
        vout: u32,
        funding_address: String,
    ) -> Result<u64, Error> {
        let ledger_arc = self.handler.get_or_create_ledger(self.node_id, reserves_id.to_string());

        let new_balance = {
            let mut ledger = ledger_arc.write().unwrap();

            // Check if deposit exists
            if !ledger.state.deposits.contains_key(&deposit_pubkey) {
                return Err(Error::Protocol(format!(
                    "Deposit not found for pubkey {}",
                    deposit_pubkey
                )));
            }

            // Apply the OnchainCredit operation with history tracking
            let operation = LedgerOperation::OnchainCredit {
                txid,
                vout,
                deposit_pubkey,
                amount: amount_msats,
                funding_address,
            };

            let block_height = self.wallet.get_block_height().unwrap_or(0);
            let block_hash = self.wallet.get_block_hash().unwrap_or([0u8; 32]);
            ledger.append_operation_with_block(operation, deposits_core::messages::consts::ONCHAIN_CREDIT, block_height, block_hash)
                .map_err(|e| Error::Protocol(format!("Failed to credit deposit: {:?}", e)))?;

            // Return the new balance
            ledger.state.deposits.get(&deposit_pubkey)
                .map(|d| d.balance)
                .unwrap_or(0)
        };

        // Sign the update
        self.sign_last_update(reserves_id)?;

        // Persist the ledger
        if let Err(e) = self.handler.persist_ledger(&self.node_id, reserves_id) {
            tracing::error!("Failed to persist ledger: {}", e);
        }

        tracing::info!(
            "Credited deposit {} with {} msats (on-chain), new balance: {} msats",
            deposit_pubkey,
            amount_msats,
            new_balance
        );

        Ok(new_balance)
    }

    /// Credit a deposit with Lightning invoice payment
    ///
    /// This applies an InvoiceCredit operation to add funds to a deposit.
    /// Used when a Lightning invoice payment is received.
    pub fn credit_deposit(
        &self,
        reserves_id: &str,
        deposit_pubkey: PublicKey,
        amount_msats: u64,
        payment_hash: [u8; 32],
        invoice_id: String,
    ) -> Result<u64, Error> {
        let ledger_arc = self.handler.get_or_create_ledger(self.node_id, reserves_id.to_string());

        let new_balance = {
            let mut ledger = ledger_arc.write().unwrap();

            // Check if deposit exists
            if !ledger.state.deposits.contains_key(&deposit_pubkey) {
                return Err(Error::Protocol(format!(
                    "Deposit not found for pubkey {}",
                    deposit_pubkey
                )));
            }

            // Get the next sequence number for this deposit's operations
            let sequence_number = ledger.sequence() + 1;

            // Apply the InvoiceCredit operation with history tracking
            let operation = LedgerOperation::InvoiceCredit {
                payment_hash,
                deposit_pubkey,
                amount: amount_msats,
                invoice_id,
                sequence_number,
            };

            let block_height = self.wallet.get_block_height().unwrap_or(0);
            let block_hash = self.wallet.get_block_hash().unwrap_or([0u8; 32]);
            ledger.append_operation_with_block(operation, deposits_core::messages::consts::RECEIVING_CREDIT_PAYMENT, block_height, block_hash)
                .map_err(|e| Error::Protocol(format!("Failed to credit deposit: {:?}", e)))?;

            // Return the new balance
            ledger.state.deposits.get(&deposit_pubkey)
                .map(|d| d.balance)
                .unwrap_or(0)
        };

        // Sign the update
        self.sign_last_update(reserves_id)?;

        // Persist the ledger
        if let Err(e) = self.handler.persist_ledger(&self.node_id, reserves_id) {
            tracing::error!("Failed to persist ledger: {}", e);
        }

        tracing::info!(
            "Credited deposit {} with {} msats (invoice), new balance: {} msats",
            deposit_pubkey,
            amount_msats,
            new_balance
        );

        Ok(new_balance)
    }

    /// Get a deposit by pubkey from a ledger
    pub fn get_deposit(
        &self,
        reserves_id: &str,
        deposit_pubkey: PublicKey,
    ) -> Option<Deposit> {
        let ledgers = self.handler.ledgers.lock().unwrap();
        if let Some(ledger_arc) = ledgers.get(&(self.node_id, reserves_id.to_string())) {
            let ledger = ledger_arc.read().unwrap();
            return ledger.state.deposits.get(&deposit_pubkey).cloned();
        }
        None
    }

    /// List all deposits in a ledger
    pub fn list_deposits(&self, reserves_id: &str) -> Vec<(PublicKey, Deposit)> {
        let ledgers = self.handler.ledgers.lock().unwrap();
        if let Some(ledger_arc) = ledgers.get(&(self.node_id, reserves_id.to_string())) {
            let ledger = ledger_arc.read().unwrap();
            return ledger.state.deposits.iter()
                .map(|(k, v)| (*k, v.clone()))
                .collect();
        }
        Vec::new()
    }

    /// Complete a deposit offer by crediting the deposit
    ///
    /// This should be called when on-chain funding is detected for a deposit offer.
    /// It marks the offer as funded and credits the deposit.
    pub fn complete_deposit_offer(
        &self,
        offer_id: &[u8; 32],
        funding_txid: String,
        funding_amount_sats: u64,
    ) -> Result<u64, Error> {
        // Get the offer
        let (offer, status) = self.get_deposit_offer(offer_id)
            .ok_or(Error::OfferNotFound)?;

        // Check offer is in correct state
        if !matches!(status, DepositOfferStatus::Pending) {
            return Err(Error::Protocol(format!(
                "Deposit offer not in Pending state: {:?}",
                status
            )));
        }

        // Check amount is within bounds
        if funding_amount_sats < offer.min_amount_sats {
            return Err(Error::Protocol(format!(
                "Funding amount {} sats below minimum {} sats",
                funding_amount_sats, offer.min_amount_sats
            )));
        }
        let credited_amount = funding_amount_sats.min(offer.max_amount_sats);

        // Check deadline
        let current_block = self.wallet.get_block_height()?;
        if offer.is_expired(current_block) {
            return Err(Error::Protocol("Deposit offer has expired".to_string()));
        }

        // Credit the deposit (convert sats to msats)
        let amount_msats = credited_amount * 1000;

        // Parse txid from hex string to bytes (reversed for Bitcoin's internal byte order)
        let txid_bytes: [u8; 32] = hex::decode(&funding_txid)
            .map_err(|e| Error::Protocol(format!("Invalid txid hex: {}", e)))?
            .try_into()
            .map_err(|_| Error::Protocol("Invalid txid length".to_string()))?;

        // Look up the ledger by ledger_id to get the current reserves_id
        let (reserves_id, _) = self.get_ledger_by_ledger_id(&offer.ledger_id)
            .ok_or_else(|| Error::Protocol(format!(
                "Ledger not found for ledger_id: {}",
                &offer.ledger_id[..16.min(offer.ledger_id.len())]
            )))?;

        let new_balance = self.credit_deposit_onchain(
            &reserves_id,
            offer.deposit_pubkey,
            amount_msats,
            txid_bytes,
            0, // vout - typically 0 for deposit offers
            offer.funding_address.clone(),
        )?;

        // Update offer status
        {
            let mut offers = self.deposit_offers.lock().unwrap();
            if let Some((_, ref mut current_status)) = offers.get_mut(offer_id) {
                *current_status = DepositOfferStatus::Completed {
                    txid: funding_txid,
                    amount_sats: credited_amount,
                    confirmed_at_block: current_block,
                };
            }
        }
        self.save_deposit_offers()?;

        tracing::info!(
            "Completed deposit offer {}: credited {} msats to {}",
            hex::encode(&offer_id[..8]),
            amount_msats,
            offer.deposit_pubkey
        );

        Ok(new_balance)
    }

    /// Check if a deposit offer's funding address has received funds
    ///
    /// Returns Some((txid, amount_sats)) if funds are detected, None otherwise.
    pub fn check_deposit_offer_funding(&self, offer_id: &[u8; 32]) -> Result<Option<(String, u64)>, Error> {
        let (offer, status) = self.get_deposit_offer(offer_id)
            .ok_or(Error::OfferNotFound)?;

        // Only check pending offers
        if !matches!(status, DepositOfferStatus::Pending) {
            return Ok(None);
        }

        // Parse the funding address and check for received funds
        let address = offer.funding_address.parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()
            .map_err(|e| Error::Protocol(format!("Invalid funding address: {}", e)))?;

        // Check wallet for received funds to this address
        // This requires syncing the wallet first
        self.wallet.sync()?;

        // Check if any transactions have been received to this address
        if let Some((txid, amount)) = self.wallet.check_address_received(&address)? {
            return Ok(Some((txid, amount)));
        }

        Ok(None)
    }

    /// Get ledger history (for display purposes)
    ///
    /// Returns the list of signed updates in the ledger's history.
    pub fn get_ledger_history(
        &self,
        partner: PublicKey,
    ) -> Option<Vec<deposits_core::types::SignedLedgerUpdate>> {
        let ledgers = self.handler.ledgers.lock().unwrap();
        if let Some(ledger_arc) = ledgers.get(&(self.node_id, partner.to_string())) {
            let ledger = ledger_arc.read().unwrap();
            return Some(ledger.history.clone());
        }
        None
    }

    /// Get a specific ledger
    pub fn get_ledger(&self, partner: PublicKey) -> Option<Ledger> {
        let ledgers = self.handler.ledgers.lock().unwrap();
        if let Some(ledger_arc) = ledgers.get(&(self.node_id, partner.to_string())) {
            let ledger = ledger_arc.read().unwrap();
            return Some(ledger.clone());
        }
        None
    }

    /// Get the primary ledger (operator ledger backed by reserves)
    /// Returns (reserves_id, ledger) tuple
    /// Only returns ledgers with non-zero reserves (the actual reserves ledger)
    pub fn get_primary_ledger(&self) -> Option<(String, Ledger)> {
        let ledgers = self.handler.ledgers.lock().unwrap();
        for ((operator, reserves_id), ledger_arc) in ledgers.iter() {
            if *operator == self.node_id {
                let ledger = ledger_arc.read().unwrap();
                // Only return ledgers backed by reserves
                if ledger.reserves_amount() > 0 {
                    return Some((reserves_id.clone(), ledger.clone()));
                }
            }
        }
        None
    }

    /// Get a ledger by reserves_id (Bitcoin address string)
    /// Returns (reserves_id, ledger) tuple
    /// Searches all ledgers (both operator and partner roles)
    pub fn get_ledger_by_reserves_id(&self, reserves_id: &str) -> Option<(String, Ledger)> {
        let ledgers = self.handler.ledgers.lock().unwrap();
        for ((_operator, rid), ledger_arc) in ledgers.iter() {
            if rid == reserves_id {
                let ledger = ledger_arc.read().unwrap();
                return Some((rid.clone(), ledger.clone()));
            }
        }
        None
    }

    /// Get a ledger by ledger_id (64-char hex hash)
    /// Returns (reserves_id, ledger) tuple
    /// The ledger_id is stable across custody transfers
    pub fn get_ledger_by_ledger_id(&self, ledger_id_hex: &str) -> Option<(String, Ledger)> {
        let ledgers = self.handler.ledgers.lock().unwrap();
        for ((_operator, rid), ledger_arc) in ledgers.iter() {
            let ledger = ledger_arc.read().unwrap();
            if ledger.ledger_id_hex() == ledger_id_hex {
                return Some((rid.clone(), ledger.clone()));
            }
        }
        None
    }
}
