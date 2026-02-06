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

    /// Pending collateral lock requests (request_id -> our_reserves_id)
    /// Used to auto-record attestations when responses arrive
    pending_collateral_requests: Mutex<HashMap<String, String>>,

    /// Data directory for persistence
    data_dir: PathBuf,

    /// Primary relay URL for Nostr
    relay_url: String,
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
            config.electrum_url.clone(),
        )?);

        let secret_key = wallet.operator_secret();
        let node_id = PublicKey::from_secret_key(&secp, &secret_key);

        // Store relay URL for later use
        let relay_url = config.relays.first().cloned().unwrap_or_default();

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
            pending_collateral_requests: Mutex::new(HashMap::new()),
            data_dir: config.data_dir,
            relay_url,
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

                    // Handle responses (for auto-recording attestations)
                    while let Some(response) = self.nostr.try_recv_response() {
                        self.handle_ledger_response(response).await;
                    }

                    // Handle ledger updates (validate and auto-dispute on invalid)
                    while let Some(update) = self.nostr.try_recv_ledger_update() {
                        self.handle_ledger_update(update).await;
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

                    // Auto-claim/yield for any pending lottery disputes
                    self.auto_lottery_claim_or_yield().await;

                    // Auto-initiate confiscation when all participants are armed
                    self.auto_confiscate().await;

                    // Auto-reveal preimage when confiscation TX has 3+ confirmations
                    self.auto_reveal_on_confiscation().await;

                    // Auto-rotate and continue after winning
                    self.auto_post_win_cleanup().await;

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
            "withdraw" => self.process_withdraw_request(&request).await,
            "collateral_lock" => self.process_collateral_lock_request(&request).await,
            "custody_transfer_sign" => self.process_custody_transfer_sign_request(&request).await,
            "confiscation_sign" => self.process_confiscation_sign_request(&request).await,
            "custodian_query" => self.process_custodian_query_request(&request).await,
            "lottery_reveal" => {
                // When we see another participant's reveal, auto-reveal ours
                self.auto_reveal_preimage(&request.ledger_id).await;
                (true, None, None) // No response needed
            }
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

    /// Handle an incoming ledger update - validate and auto-dispute if invalid
    async fn handle_ledger_update(&self, inbound: crate::nostr::InboundLedgerUpdate) {
        // Check if we care about this ledger (we're a quorum member)
        if !self.is_quorum_member_of_ledger(&inbound.ledger_id) {
            return; // Not our concern
        }

        // Find the ledger
        let ledger_arc = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let mut found = None;
            for ((_operator, _reserves_id), arc) in ledgers.iter() {
                let ledger = arc.read().unwrap();
                if ledger.ledger_id_hex() == inbound.ledger_id {
                    found = Some(arc.clone());
                    break;
                }
            }
            found
        };

        let Some(ledger_arc) = ledger_arc else {
            return; // Ledger not found locally
        };

        // Validate the update
        let validation_result = {
            let ledger = ledger_arc.read().unwrap();

            // Skip if already in dispute state
            if ledger.state.dispute_state != deposits_core::types::DisputeState::Normal {
                return;
            }

            ledger.validate_incoming_update(&inbound.update, None)
        };

        if let Err(e) = validation_result {
            tracing::warn!(
                "!!! INVALID UPDATE DETECTED on ledger {}...: {:?}",
                &inbound.ledger_id[..16.min(inbound.ledger_id.len())],
                e
            );
            tracing::warn!("  From operator: {}...", hex::encode(inbound.update.operator_id.serialize())[..16].to_string());
            tracing::warn!("  Sequence: {}", inbound.update.sequence_number);

            // Get the last valid sequence number (the one before this invalid update)
            let last_valid_seq = if inbound.update.sequence_number > 0 {
                inbound.update.sequence_number - 1
            } else {
                0
            };

            // Auto-arm for the dispute
            tracing::info!("Auto-arming for dispute...");
            match self.auto_arm_for_dispute(&inbound.ledger_id, last_valid_seq).await {
                Ok(()) => {
                    tracing::info!("Successfully auto-armed for dispute on invalid update");
                }
                Err(e) => {
                    tracing::error!("Failed to auto-arm for dispute: {}", e);
                }
            }
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

        tracing::warn!("  Last valid seq: {}", dispute.last_valid_sequence);
        if let Some(vs) = dispute.violation_sequence {
            tracing::warn!("  Violation seq: {}", vs);
        }

        // Check if we're a quorum member of this ledger
        let is_member = self.is_quorum_member_of_ledger(&dispute.ledger_id);
        if !is_member {
            tracing::info!("Not a quorum member of this ledger, skipping auto-arm");
            return;
        }

        tracing::info!("We are a quorum member - auto-participating in dispute");

        // Auto-arm for the dispute
        match self.auto_arm_for_dispute(&dispute.ledger_id, dispute.last_valid_sequence).await {
            Ok(()) => {
                tracing::info!("Successfully auto-armed for dispute");
            }
            Err(e) => {
                tracing::error!("Failed to auto-arm for dispute: {}", e);
                tracing::warn!("Manual intervention required: Run 'recovery arm {}'", dispute.ledger_id);
            }
        }
    }

    /// Check if we're a quorum member of a ledger (by ledger_id hash)
    fn is_quorum_member_of_ledger(&self, ledger_id: &str) -> bool {
        // Check our joined ledgers
        let joined = self.get_joined_ledger_ids();

        // The ledger_id in disputes is the ledger hash, not the reserves_id
        // We need to check if we've joined this specific ledger or if it's our own
        let ledgers = self.handler.ledgers.lock().unwrap();
        for ((operator, _reserves_id), ledger_arc) in ledgers.iter() {
            let ledger = ledger_arc.read().unwrap();
            if ledger.ledger_id_hex() == ledger_id {
                // It's one of our ledgers (either we're operator or we've joined)
                if *operator == self.node_id {
                    return true;
                }
            }
        }

        // Also check if we have a QuorumJoin for this ledger
        for jid in joined {
            if jid == ledger_id || jid.contains(ledger_id) {
                return true;
            }
        }

        false
    }

    /// Auto-arm for a dispute by publishing CustodyDispute and CustodyArmed
    async fn auto_arm_for_dispute(&self, ledger_id: &str, last_valid_seq: u64) -> Result<(), Error> {
        use bitcoin::hashes::{Hash, hash160};
        use bitcoin::secp256k1::Secp256k1;
        use bitcoin::secp256k1::rand::rngs::OsRng;
        use bitcoin::secp256k1::rand::Rng;
        use deposits_core::TlvEncode;
        use deposits_core::messages::LedgerOperation;

        let secp = Secp256k1::new();

        // Get our operator keypair
        let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &self.wallet.operator_secret());
        let our_pubkey = keypair.public_key();

        // Find our reserves_id (our ledger where we'll record the dispute/arm)
        let our_reserves_id = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let mut found = None;
            for ((operator, reserves_id), _) in ledgers.iter() {
                if *operator == self.node_id {
                    found = Some(reserves_id.clone());
                    break;
                }
            }
            found.ok_or_else(|| Error::Protocol("No ledger found for our operator".to_string()))?
        };

        // Get our ledger's current state
        let ledger_arc = self.handler.get_or_create_ledger(self.node_id, our_reserves_id.clone());
        let current_block = self.wallet.get_block_height().unwrap_or(0);
        let block_hash = self.wallet.get_block_hash().unwrap_or([0u8; 32]);

        // 1. First publish CustodyDispute on our branch
        {
            let mut ledger = ledger_arc.write().unwrap();

            // Check if we've already published a CustodyDispute for this ledger
            let already_disputed = ledger.history.iter().any(|u| {
                if let Ok(op) = LedgerOperation::tlv_decode(&u.message) {
                    matches!(op, LedgerOperation::CustodyDispute { .. })
                } else {
                    false
                }
            });

            if already_disputed {
                tracing::info!("Already have CustodyDispute on our ledger");
            } else {
                let dispute_op = LedgerOperation::CustodyDispute {
                    last_valid_sequence: last_valid_seq,
                    reason: "auto_dispute".to_string(),
                };

                ledger.append_operation_with_block(
                    dispute_op,
                    deposits_core::messages::consts::CUSTODY_DISPUTE,
                    current_block,
                    block_hash,
                ).map_err(|e| Error::Protocol(format!("Failed to append CustodyDispute: {:?}", e)))?;

                tracing::info!("Published CustodyDispute on our ledger");
            }
        }

        // Sign the dispute update
        self.sign_last_update(&our_reserves_id)?;

        // 2. Copy our existing attestations from our own ledger history
        // These are attestations we received (proving we have collateral backing)
        {
            let ledger = ledger_arc.read().unwrap();

            // Find all CollateralAttestation operations in our history
            let mut attestations_to_copy: Vec<LedgerOperation> = Vec::new();
            let mut quorum_members_to_add: Vec<bitcoin::secp256k1::PublicKey> = Vec::new();

            for update in ledger.history.iter() {
                if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                    match &op {
                        LedgerOperation::CollateralAttestation { collateral_operator, quorum_member, .. } => {
                            // We want attestations where WE are the quorum_member
                            // (proving we locked collateral on other operators' ledgers)
                            if quorum_member == &our_pubkey {
                                attestations_to_copy.push(op.clone());
                                // Also need to add the collateral_operator as a quorum member
                                if !quorum_members_to_add.contains(collateral_operator) {
                                    quorum_members_to_add.push(*collateral_operator);
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }

            drop(ledger);

            // First add quorum members, then attestations
            for member in quorum_members_to_add {
                let mut ledger = ledger_arc.write().unwrap();

                // Check if already added
                if ledger.state.quorum_members.contains(&member) {
                    continue;
                }

                // Create QuorumAddMember operation
                // Note: The signature should come from the member, but for auto-arm
                // we use a placeholder since the member will broadcast their own version
                let add_op = LedgerOperation::QuorumAddMember {
                    quorum_member: member,
                    quorum_member_signature: [0u8; 64], // Placeholder
                };

                if let Err(e) = ledger.append_operation_with_block(
                    add_op,
                    deposits_core::messages::consts::QUORUM_ADD_MEMBER,
                    current_block,
                    block_hash,
                ) {
                    tracing::warn!("Failed to add quorum member: {:?}", e);
                } else {
                    tracing::info!("Added quorum member: {}...", &hex::encode(member.serialize())[..16]);
                }
            }

            // Now copy attestations
            for attestation in attestations_to_copy {
                let mut ledger = ledger_arc.write().unwrap();

                if let Err(e) = ledger.append_operation_with_block(
                    attestation,
                    deposits_core::messages::consts::COLLATERAL_ATTESTATION,
                    current_block,
                    block_hash,
                ) {
                    tracing::warn!("Failed to copy attestation: {:?}", e);
                } else {
                    tracing::info!("Copied existing attestation to dispute branch");
                }
            }

            // Sign after adding members and attestations
            self.sign_last_update(&our_reserves_id)?;
        }

        // 3. Now publish CustodyArmed with preimage commitment
        {
            let mut ledger = ledger_arc.write().unwrap();

            // Check if we've already armed
            let already_armed = ledger.history.iter().any(|u| {
                if let Ok(op) = LedgerOperation::tlv_decode(&u.message) {
                    matches!(op, LedgerOperation::CustodyArmed { .. })
                } else {
                    false
                }
            });

            if already_armed {
                tracing::info!("Already have CustodyArmed on our ledger");
            } else {
                // Generate random preimage (17-20 bytes for lottery entropy)
                let mut rng = OsRng;
                let preimage_len = rng.gen_range(17..=20);
                let mut preimage = vec![0u8; preimage_len];
                rng.fill(&mut preimage[..]);

                // Compute commitment_hash = HASH160(preimage)
                let commitment_hash: [u8; 20] = *hash160::Hash::hash(&preimage).as_byte_array();

                // Store preimage for later reveal
                let preimage_file = self.data_dir.join(format!("lottery_preimage_{}.hex",
                    &ledger_id[..16.min(ledger_id.len())]));
                if let Err(e) = std::fs::write(&preimage_file, hex::encode(&preimage)) {
                    tracing::warn!("Failed to store preimage: {}", e);
                } else {
                    tracing::info!("Stored lottery preimage in: {:?}", preimage_file);
                }

                // Use P2WPKH address derived from our operator pubkey for target_reserves
                let pubkey_bytes: [u8; 33] = our_pubkey.serialize();
                let compressed = bitcoin::CompressedPublicKey::from_slice(&pubkey_bytes)
                    .map_err(|e| Error::Protocol(format!("Invalid pubkey: {}", e)))?;
                let target_reserves = bitcoin::Address::p2wpkh(&compressed, self.wallet.network()).to_string();

                let armed_op = LedgerOperation::CustodyArmed {
                    armed_block: current_block,
                    commitment_hash,
                    target_reserves,
                };

                ledger.append_operation_with_block(
                    armed_op,
                    deposits_core::messages::consts::CUSTODY_ARMED,
                    current_block,
                    block_hash,
                ).map_err(|e| Error::Protocol(format!("Failed to append CustodyArmed: {:?}", e)))?;

                tracing::info!("Published CustodyArmed on our ledger");
            }
        }

        // Sign the armed update
        self.sign_last_update(&our_reserves_id)?;

        // Persist
        if let Err(e) = self.handler.persist_ledger(&self.node_id, &our_reserves_id) {
            tracing::error!("Failed to persist ledger: {}", e);
        }

        // Broadcast all updates
        if let Err(e) = self.broadcast_all_updates(&our_reserves_id).await {
            tracing::warn!("Failed to broadcast dispute updates: {}", e);
        }

        Ok(())
    }

    /// Auto-reveal our lottery preimage when we see another participant's reveal
    async fn auto_reveal_preimage(&self, ledger_id: &str) {
        // Check if we're a quorum member of this ledger
        if !self.is_quorum_member_of_ledger(ledger_id) {
            return;
        }

        // Check if we have a preimage file for this ledger
        let preimage_file = self.data_dir.join(format!("lottery_preimage_{}.hex",
            &ledger_id[..16.min(ledger_id.len())]));

        if !preimage_file.exists() {
            tracing::debug!("No preimage file for ledger {}", &ledger_id[..16]);
            return;
        }

        // Check if we already revealed (marker file)
        let revealed_marker = self.data_dir.join(format!("lottery_revealed_{}.marker",
            &ledger_id[..16.min(ledger_id.len())]));
        if revealed_marker.exists() {
            tracing::debug!("Already revealed preimage for ledger {}", &ledger_id[..16]);
            return;
        }

        // Load and reveal the preimage
        let preimage_hex = match std::fs::read_to_string(&preimage_file) {
            Ok(hex) => hex.trim().to_string(),
            Err(e) => {
                tracing::warn!("Failed to read preimage file: {}", e);
                return;
            }
        };

        let preimage = match hex::decode(&preimage_hex) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::warn!("Invalid preimage hex: {}", e);
                return;
            }
        };

        tracing::info!("Auto-revealing lottery preimage for ledger {}...", &ledger_id[..16]);
        tracing::info!("  Preimage length: {} bytes (contribution: {})", preimage.len(), preimage.len().saturating_sub(16));

        // Publish reveal via Nostr
        let reveal_params = serde_json::json!({
            "ledger_id": ledger_id,
            "preimage": preimage_hex,
        });

        match self.nostr.send_ledger_request(
            ledger_id,
            "lottery_reveal",
            reveal_params,
        ).await {
            Ok(request_id) => {
                tracing::info!("Lottery preimage revealed! Request ID: {}...", &request_id[..16.min(request_id.len())]);

                // Create marker file to prevent double-reveal
                if let Err(e) = std::fs::write(&revealed_marker, "revealed") {
                    tracing::warn!("Failed to write revealed marker: {}", e);
                }
            }
            Err(e) => {
                tracing::error!("Failed to send reveal: {:?}", e);
            }
        }
    }

    /// Auto-claim or yield for any pending lottery disputes
    ///
    /// For each ledger where we've revealed our preimage:
    /// 1. Check if all preimages are collected
    /// 2. Determine winner
    /// 3. Winner: claim lottery output + publish CustodyAcquire
    /// 4. Loser: publish CustodyYield
    async fn auto_lottery_claim_or_yield(&self) {
        use bitcoin::secp256k1::Secp256k1;

        let secp = Secp256k1::new();
        let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &self.wallet.operator_secret());

        // Find revealed marker files in data_dir
        let entries = match std::fs::read_dir(&self.data_dir) {
            Ok(e) => e,
            Err(_) => return,
        };

        let revealed_markers: Vec<_> = entries
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name().to_string_lossy().starts_with("lottery_revealed_")
                    && e.file_name().to_string_lossy().ends_with(".marker")
            })
            .collect();

        for entry in revealed_markers {
            let marker_path = entry.path();
            // Extract ledger_id prefix from filename
            let filename = match marker_path.file_name().and_then(|f| f.to_str()) {
                Some(f) => f,
                None => continue,
            };

            // lottery_revealed_<prefix>.marker
            let ledger_prefix = filename
                .strip_prefix("lottery_revealed_")
                .and_then(|s| s.strip_suffix(".marker"))
                .unwrap_or("");

            if ledger_prefix.is_empty() {
                continue;
            }

            // Check if we've already claimed/yielded (completed marker)
            let completed_marker = self.data_dir.join(format!("lottery_completed_{}.marker", ledger_prefix));
            if completed_marker.exists() {
                continue;
            }

            // Find the full ledger_id
            let ledger_id = {
                let ledgers = self.handler.ledgers.lock().unwrap();
                let mut found = None;
                for ((_operator, _reserves_id), arc) in ledgers.iter() {
                    let ledger = arc.read().unwrap();
                    let lid = ledger.ledger_id_hex();
                    if lid.starts_with(ledger_prefix) {
                        found = Some(lid);
                        break;
                    }
                }
                match found {
                    Some(id) => id,
                    None => continue,
                }
            };

            // Try to claim or yield
            match self.try_lottery_claim_or_yield(&ledger_id, &keypair).await {
                Ok(completed) => {
                    if completed {
                        // Create completed marker
                        if let Err(e) = std::fs::write(&completed_marker, "completed") {
                            tracing::warn!("Failed to write completed marker: {}", e);
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!("Lottery claim/yield not ready for {}: {}", ledger_prefix, e);
                }
            }
        }
    }

    /// Try to claim or yield for a specific ledger
    /// Returns Ok(true) if completed, Ok(false) if not ready, Err if failed
    async fn try_lottery_claim_or_yield(
        &self,
        ledger_id: &str,
        keypair: &bitcoin::secp256k1::Keypair,
    ) -> Result<bool, Error> {
        use bitcoin::hashes::{Hash, sha256, hash160};
        use bitcoin::secp256k1::{Secp256k1, PublicKey};
        use deposits_core::{TlvDecode, TlvEncode, SignedLedgerUpdate};
        use deposits_core::messages::LedgerOperation;
        use deposits_core::tapscript_reserves::{LotteryScriptBuilder, LotteryParticipant, LotteryOutput};
        use crate::nostr::{KIND_LEDGER_UPDATE, KIND_LEDGER_REQUEST};
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
        use nostr_sdk::{Client, Keys, Filter, Kind, TagKind};
        use nostr_sdk::prelude::{SingleLetterTag, Alphabet};

        let secp = Secp256k1::new();
        let our_pubkey = keypair.public_key();

        // Fetch updates and reveals from Nostr
        let keys = Keys::generate();
        let client = Client::new(keys);
        client.add_relay(&self.relay_url).await
            .map_err(|e| Error::Protocol(format!("Failed to add relay: {}", e)))?;
        client.connect().await;

        // Fetch ledger updates
        let filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_UPDATE))
            .custom_tag(SingleLetterTag::lowercase(Alphabet::D), [ledger_id])
            .limit(500);

        let update_events = client
            .fetch_events(vec![filter], None)
            .await
            .map_err(|e| Error::Protocol(format!("Failed to fetch updates: {}", e)))?;

        // Fetch lottery reveals
        let reveal_filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_REQUEST))
            .custom_tag(SingleLetterTag::lowercase(Alphabet::L), [ledger_id])
            .limit(100);

        let reveal_events = client
            .fetch_events(vec![reveal_filter], None)
            .await
            .map_err(|e| Error::Protocol(format!("Failed to fetch reveals: {}", e)))?;

        client.disconnect().await.ok();

        // Extract CustodyArmed participants
        let mut participants: Vec<(PublicKey, LotteryParticipant)> = Vec::new();
        let mut our_armed: Option<SignedLedgerUpdate> = None;

        for event in update_events.iter() {
            if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
                if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                    if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                        if let LedgerOperation::CustodyArmed { commitment_hash, target_reserves, .. } = op {
                            let x_only = update.operator_id.x_only_public_key().0;
                            participants.push((update.operator_id, LotteryParticipant::new(
                                x_only,
                                commitment_hash,
                                target_reserves,
                            )));
                            if update.operator_id == our_pubkey {
                                our_armed = Some(update);
                            }
                        }
                    }
                }
            }
        }

        if participants.is_empty() {
            return Err(Error::Protocol("No CustodyArmed participants found".to_string()));
        }

        let our_armed = our_armed.ok_or_else(||
            Error::Protocol("Could not find our CustodyArmed".to_string()))?;

        // Sort participants by x-only pubkey for deterministic order
        participants.sort_by(|a, b| a.1.pubkey.serialize().cmp(&b.1.pubkey.serialize()));

        // Collect revealed preimages
        let mut preimages: std::collections::HashMap<String, Vec<u8>> = std::collections::HashMap::new();

        for event in reveal_events.iter() {
            let is_lottery_reveal = event.tags.iter().any(|tag| {
                tag.kind() == TagKind::custom("action") &&
                tag.content().map(|c| c == "lottery_reveal").unwrap_or(false)
            });

            if is_lottery_reveal {
                if let Ok(content) = serde_json::from_str::<serde_json::Value>(&event.content) {
                    if let Some(preimage_hex) = content.get("preimage").and_then(|v| v.as_str()) {
                        if let Ok(preimage) = hex::decode(preimage_hex) {
                            preimages.insert(event.pubkey.to_string(), preimage);
                        }
                    }
                }
            }
        }

        // Not ready if not all preimages revealed
        if preimages.len() < participants.len() {
            return Ok(false);
        }

        // Match preimages to participants
        let mut ordered_preimages: Vec<Vec<u8>> = Vec::new();
        for (pubkey, _participant) in &participants {
            let x_only = pubkey.x_only_public_key().0;
            let pubkey_str = x_only.to_string();
            if let Some(preimage) = preimages.get(&pubkey_str) {
                ordered_preimages.push(preimage.clone());
            } else {
                return Err(Error::Protocol(format!("Missing preimage from participant")));
            }
        }

        // Determine winner
        let winner_index = LotteryOutput::calculate_winner(&ordered_preimages)
            .map_err(|e| Error::Protocol(format!("Failed to calculate winner: {:?}", e)))?;

        let (winner_pubkey, winner_participant) = &participants[winner_index];

        if *winner_pubkey == our_pubkey {
            // WE WON - claim the lottery
            tracing::info!("We won the lottery for ledger {}!", &ledger_id[..16]);
            self.claim_lottery(ledger_id, &participants, &ordered_preimages, winner_index, &our_armed, keypair).await?;
        } else {
            // We lost - yield
            tracing::info!("We lost the lottery for ledger {}. Publishing CustodyYield.", &ledger_id[..16]);
            self.publish_custody_yield(ledger_id, &our_armed, keypair).await?;
        }

        Ok(true)
    }

    /// Claim the lottery output as the winner
    async fn claim_lottery(
        &self,
        ledger_id: &str,
        participants: &[(bitcoin::secp256k1::PublicKey, deposits_core::tapscript_reserves::LotteryParticipant)],
        ordered_preimages: &[Vec<u8>],
        winner_index: usize,
        our_armed: &deposits_core::SignedLedgerUpdate,
        keypair: &bitcoin::secp256k1::Keypair,
    ) -> Result<(), Error> {
        use bitcoin::hashes::{Hash, sha256};
        use bitcoin::secp256k1::{Secp256k1, PublicKey, Message};
        use bitcoin::{Transaction, TxIn, TxOut, Witness, Amount, ScriptBuf};
        use bitcoin::sighash::{SighashCache, TapSighashType};
        use bitcoin::taproot::TapLeafHash;
        use deposits_core::{TlvDecode, TlvEncode, SignedLedgerUpdate};
        use deposits_core::messages::LedgerOperation;
        use deposits_core::tapscript_reserves::{LotteryScriptBuilder, LotteryParticipant, LotteryOutput};
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

        let secp = Secp256k1::new();
        let our_pubkey = keypair.public_key();
        let (_, winner_participant) = &participants[winner_index];

        // Build lottery participants list
        let lottery_participants: Vec<LotteryParticipant> = participants.iter()
            .map(|(_, p)| p.clone())
            .collect();

        // Get recovery voters (need to fetch from ledger)
        // For now, use participants as recovery voters
        let recovery_voters: Vec<bitcoin::secp256k1::XOnlyPublicKey> = participants.iter()
            .map(|(pk, _)| pk.x_only_public_key().0)
            .collect();

        let recovery_threshold = (recovery_voters.len() + 1) / 2;

        // Build the lottery output
        let lottery_builder = LotteryScriptBuilder::new(
            lottery_participants.clone(),
            recovery_voters.clone(),
            recovery_threshold,
            self.wallet.network(),
        );

        let lottery_output = lottery_builder.build()
            .map_err(|e| Error::Protocol(format!("Failed to build lottery output: {:?}", e)))?;

        // Find the lottery UTXO on-chain
        let lottery_script = lottery_output.address.script_pubkey();

        // Use wallet's esplora to find UTXO
        let lottery_utxo = self.wallet.find_utxo_for_script(&lottery_script)
            .map_err(|e| Error::Protocol(format!("Failed to find lottery UTXO: {:?}", e)))?;

        let (lottery_outpoint, lottery_amount) = lottery_utxo
            .ok_or_else(|| Error::Protocol("No unspent UTXO at lottery address".to_string()))?;

        tracing::info!("Found lottery UTXO: {} ({} sats)", lottery_outpoint, lottery_amount);

        // Parse winner's target address
        let target_address: bitcoin::Address<bitcoin::address::NetworkUnchecked> = winner_participant.target_reserves.parse()
            .map_err(|e| Error::Protocol(format!("Invalid target address: {}", e)))?;
        let target_address = target_address.require_network(self.wallet.network())
            .map_err(|e| Error::Protocol(format!("Address network mismatch: {}", e)))?;

        // Build claim transaction
        let claim_fee = 400u64;
        let output_amount = lottery_amount.saturating_sub(claim_fee);

        let claim_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: lottery_outpoint,
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(output_amount),
                script_pubkey: target_address.script_pubkey(),
            }],
        };

        // Compute sighash
        let prevouts = vec![TxOut {
            value: Amount::from_sat(lottery_amount),
            script_pubkey: lottery_script.clone(),
        }];

        let leaf_hash = TapLeafHash::from_script(&lottery_output.lottery_script, bitcoin::taproot::LeafVersion::TapScript);

        let mut sighash_cache = SighashCache::new(&claim_tx);
        let sighash = sighash_cache.taproot_script_spend_signature_hash(
            0,
            &bitcoin::sighash::Prevouts::All(&prevouts),
            leaf_hash,
            TapSighashType::Default,
        ).map_err(|e| Error::Protocol(format!("Failed to compute sighash: {}", e)))?;

        // Sign
        let msg = Message::from_digest(*sighash.as_ref());
        let signature = secp.sign_schnorr(&msg, keypair);
        let sig_bytes: [u8; 64] = *signature.as_ref();

        // Create witness
        let witness = lottery_output.create_claim_witness(&sig_bytes, ordered_preimages)
            .map_err(|e| Error::Protocol(format!("Failed to create witness: {:?}", e)))?;

        let mut claim_tx = claim_tx;
        claim_tx.input[0].witness = witness;

        // Broadcast
        tracing::info!("Broadcasting claim transaction...");
        self.wallet.broadcast(&claim_tx)?;

        let claim_txid = claim_tx.compute_txid();
        tracing::info!("Claim TX broadcast: {}", claim_txid);

        // Publish CustodyAcquire
        let current_block = self.wallet.get_block_height().unwrap_or(0);
        let current_block_hash = self.wallet.get_block_hash().unwrap_or([0u8; 32]);
        let spend_txid_bytes: [u8; 32] = *claim_txid.as_ref();

        let operation = LedgerOperation::CustodyAcquire {
            new_custodian: our_pubkey,
            entropy_block_height: current_block,
            entropy_block_hash: current_block_hash,
            spend_txid: spend_txid_bytes,
            new_reserves_address: winner_participant.target_reserves.clone(),
        };

        let message_bytes = operation.tlv_encode();

        // Build update continuing from our CustodyArmed
        let sequence = our_armed.sequence_number + 1;
        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(&sequence.to_le_bytes());
        hash_input.extend_from_slice(&our_armed.current_hash);
        hash_input.extend_from_slice(&message_bytes);
        let new_hash = *sha256::Hash::hash(&hash_input).as_byte_array();

        // Sign the update
        let update_msg = format!(
            "deposits:ledger:{}:{}:{}",
            hex::encode(our_armed.current_hash),
            sequence,
            hex::encode(&new_hash)
        );
        let msg_hash = sha256::Hash::hash(update_msg.as_bytes());
        let msg = Message::from_digest(*msg_hash.as_ref());
        let signature = secp.sign_schnorr(&msg, keypair);
        let operator_sig_bytes: [u8; 64] = *signature.as_ref();

        let ledger_id_bytes: [u8; 32] = hex::decode(ledger_id)
            .map_err(|e| Error::Protocol(format!("Invalid ledger_id: {}", e)))?
            .try_into()
            .map_err(|_| Error::Protocol("Ledger ID must be 32 bytes".to_string()))?;

        let signed_update = SignedLedgerUpdate {
            message: message_bytes,
            message_type: 0x8001,
            operator_signature: operator_sig_bytes,
            partner_signature: [0u8; 64],
            operator_id: our_pubkey,
            ledger_id: ledger_id_bytes,
            sequence_number: sequence,
            previous_hash: our_armed.current_hash,
            current_hash: new_hash,
            timestamp: deposits_core::now_unix_timestamp(),
            block_height: current_block,
            block_hash: current_block_hash,
        };

        // Broadcast to Nostr
        self.nostr.broadcast_ledger_update(&signed_update).await
            .map_err(|e| Error::Protocol(format!("Failed to broadcast CustodyAcquire: {:?}", e)))?;

        tracing::info!("CustodyAcquire published! We are now the operator.");
        Ok(())
    }

    /// Publish CustodyYield as a loser
    async fn publish_custody_yield(
        &self,
        ledger_id: &str,
        our_armed: &deposits_core::SignedLedgerUpdate,
        keypair: &bitcoin::secp256k1::Keypair,
    ) -> Result<(), Error> {
        use bitcoin::hashes::{Hash, sha256};
        use bitcoin::secp256k1::{Secp256k1, Message};
        use deposits_core::{TlvEncode, SignedLedgerUpdate};
        use deposits_core::messages::LedgerOperation;

        let secp = Secp256k1::new();
        let our_pubkey = keypair.public_key();

        let current_block = self.wallet.get_block_height().unwrap_or(0);
        let current_block_hash = self.wallet.get_block_hash().unwrap_or([0u8; 32]);

        // Create CustodyYield operation
        let operation = LedgerOperation::CustodyYield;
        let message_bytes = operation.tlv_encode();

        // Build update continuing from our CustodyArmed
        let sequence = our_armed.sequence_number + 1;
        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(&sequence.to_le_bytes());
        hash_input.extend_from_slice(&our_armed.current_hash);
        hash_input.extend_from_slice(&message_bytes);
        let new_hash = *sha256::Hash::hash(&hash_input).as_byte_array();

        // Sign the update
        let update_msg = format!(
            "deposits:ledger:{}:{}:{}",
            hex::encode(our_armed.current_hash),
            sequence,
            hex::encode(&new_hash)
        );
        let msg_hash = sha256::Hash::hash(update_msg.as_bytes());
        let msg = Message::from_digest(*msg_hash.as_ref());
        let signature = secp.sign_schnorr(&msg, keypair);
        let operator_sig_bytes: [u8; 64] = *signature.as_ref();

        let ledger_id_bytes: [u8; 32] = hex::decode(ledger_id)
            .map_err(|e| Error::Protocol(format!("Invalid ledger_id: {}", e)))?
            .try_into()
            .map_err(|_| Error::Protocol("Ledger ID must be 32 bytes".to_string()))?;

        let signed_update = SignedLedgerUpdate {
            message: message_bytes,
            message_type: 0x8001,
            operator_signature: operator_sig_bytes,
            partner_signature: [0u8; 64],
            operator_id: our_pubkey,
            ledger_id: ledger_id_bytes,
            sequence_number: sequence,
            previous_hash: our_armed.current_hash,
            current_hash: new_hash,
            timestamp: deposits_core::now_unix_timestamp(),
            block_height: current_block,
            block_hash: current_block_hash,
        };

        // Broadcast to Nostr
        self.nostr.broadcast_ledger_update(&signed_update).await
            .map_err(|e| Error::Protocol(format!("Failed to broadcast CustodyYield: {:?}", e)))?;

        tracing::info!("CustodyYield published. Branch terminated.");
        Ok(())
    }

    /// Auto-initiate confiscation when all participants are armed
    ///
    /// For each ledger where we're armed but confiscation hasn't happened yet,
    /// check if all participants have armed. If so, build the confiscation TX,
    /// request signatures from quorum members, and broadcast.
    async fn auto_confiscate(&self) {
        use bitcoin::secp256k1::{Secp256k1, Keypair, Message, PublicKey, XOnlyPublicKey};
        use deposits_core::{TlvDecode, TlvEncode, SignedLedgerUpdate, VoterSet, ThresholdConfig, TapscriptReservesBuilder};
        use deposits_core::messages::LedgerOperation;
        use deposits_core::tapscript_reserves::{LotteryScriptBuilder, LotteryParticipant};
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
        use nostr_sdk::{Client, Keys, Filter, Kind};
        use nostr_sdk::prelude::{SingleLetterTag, Alphabet};
        use bitcoin::{Transaction, TxIn, TxOut, Witness, Amount};
        use bitcoin::sighash::{SighashCache, TapSighashType};
        use std::collections::HashMap;

        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, &self.wallet.operator_secret());
        let our_pubkey = keypair.public_key();

        // Find armed markers (ledgers where we've armed)
        let entries = match std::fs::read_dir(&self.data_dir) {
            Ok(e) => e,
            Err(_) => return,
        };

        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.starts_with("custody_armed_") || !name.ends_with(".marker") {
                continue;
            }

            // Extract ledger prefix from marker name
            let ledger_prefix = name
                .trim_start_matches("custody_armed_")
                .trim_end_matches(".marker");

            // Skip if already confiscated or revealed
            let confiscated_marker = self.data_dir.join(format!("confiscated_{}.marker", ledger_prefix));
            let revealed_marker = self.data_dir.join(format!("lottery_revealed_{}.marker", ledger_prefix));
            if confiscated_marker.exists() || revealed_marker.exists() {
                continue;
            }

            tracing::debug!("Checking if confiscation ready for ledger {}...", ledger_prefix);

            // Find the full ledger_id by looking at our ledgers
            let ledger_id = {
                let ledgers = self.handler.ledgers.lock().unwrap();
                let mut found = None;
                for ((_op, _res), arc) in ledgers.iter() {
                    let ledger = arc.read().unwrap();
                    let lid = ledger.ledger_id_hex();
                    if lid.starts_with(ledger_prefix) {
                        found = Some(lid);
                        break;
                    }
                }
                match found {
                    Some(id) => id,
                    None => continue,
                }
            };

            // Fetch ledger updates from Nostr
            let keys = Keys::generate();
            let client = Client::new(keys);

            if client.add_relay(&self.relay_url).await.is_err() {
                continue;
            }
            client.connect().await;

            let filter = Filter::new()
                .kind(Kind::Custom(crate::nostr::KIND_LEDGER_UPDATE))
                .custom_tag(SingleLetterTag::lowercase(Alphabet::D), [ledger_id.as_str()])
                .limit(500);

            let events = match client.fetch_events(vec![filter], Some(std::time::Duration::from_secs(10))).await {
                Ok(e) => e,
                Err(_) => {
                    client.disconnect().await.ok();
                    continue;
                }
            };
            client.disconnect().await.ok();

            // Extract CustodyArmed participants, quorum members, and reserves info
            let mut participants: Vec<LotteryParticipant> = Vec::new();
            let mut quorum_members: Vec<PublicKey> = Vec::new();
            let mut reserves_address: Option<String> = None;
            let mut ledger_hash: Option<[u8; 32]> = None;
            let mut original_operator: Option<PublicKey> = None;

            for event in events.iter() {
                if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
                    if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                        if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                            match op {
                                LedgerOperation::LedgerOpen { operator_id, .. } => {
                                    original_operator = Some(operator_id);
                                }
                                LedgerOperation::QuorumAddMember { quorum_member, .. } => {
                                    if !quorum_members.contains(&quorum_member) {
                                        quorum_members.push(quorum_member);
                                    }
                                }
                                LedgerOperation::ReservesRotate { reserves_id, ledger_hash: lh, .. } => {
                                    reserves_address = Some(reserves_id);
                                    ledger_hash = Some(lh);
                                }
                                LedgerOperation::CustodyArmed { commitment_hash, target_reserves, .. } => {
                                    let x_only = update.operator_id.x_only_public_key().0;
                                    // Check if we already have this participant
                                    if !participants.iter().any(|p| p.pubkey == x_only) {
                                        participants.push(LotteryParticipant::new(
                                            x_only,
                                            commitment_hash,
                                            target_reserves,
                                        ));
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }

            // Need at least 2 participants to proceed
            if participants.len() < 2 {
                tracing::debug!("Not enough CustodyArmed participants yet ({}/2)", participants.len());
                continue;
            }

            let original_operator = match original_operator {
                Some(op) => op,
                None => continue,
            };
            let reserves_address_str = match reserves_address {
                Some(addr) => addr,
                None => continue,
            };
            let ledger_hash_val = match ledger_hash {
                Some(lh) => lh,
                None => continue,
            };

            tracing::info!("All {} participants armed for ledger {}..., initiating confiscation",
                participants.len(), ledger_prefix);

            // Sort participants by pubkey for deterministic order
            participants.sort_by(|a, b| a.pubkey.serialize().cmp(&b.pubkey.serialize()));

            // Build recovery voters (quorum minus original operator)
            let recovery_voters: Vec<XOnlyPublicKey> = quorum_members.iter()
                .filter(|pk| **pk != original_operator)
                .map(|pk| pk.x_only_public_key().0)
                .collect();

            let recovery_threshold = (recovery_voters.len() / 2) + 1;

            // Build the lottery output
            let lottery_builder = LotteryScriptBuilder::new(
                participants.clone(),
                recovery_voters,
                recovery_threshold,
                self.wallet.network(),
            );

            let lottery_output = match lottery_builder.build() {
                Ok(out) => out,
                Err(e) => {
                    tracing::error!("Failed to build lottery output: {:?}", e);
                    continue;
                }
            };

            tracing::info!("  Lottery address: {}", lottery_output.address);

            // Look up reserves UTXO
            let reserves_addr: bitcoin::Address<bitcoin::address::NetworkUnchecked> = match reserves_address_str.parse() {
                Ok(a) => a,
                Err(_) => continue,
            };
            let reserves_addr = match reserves_addr.require_network(self.wallet.network()) {
                Ok(a) => a,
                Err(_) => continue,
            };

            let script_pubkey = reserves_addr.script_pubkey();
            let utxo = match self.wallet.find_utxo_for_script(&script_pubkey) {
                Ok(Some(u)) => u,
                Ok(None) => {
                    tracing::debug!("No unspent reserves UTXO found");
                    continue;
                }
                Err(_) => continue,
            };

            let (reserves_outpoint, reserves_amount) = utxo;
            tracing::info!("  Found reserves: {} sats at {}", reserves_amount, reserves_outpoint);

            // Build confiscation transaction
            let fee_rate = 2u64;
            let estimated_vsize = 200u64;
            let fee = fee_rate * estimated_vsize;
            let output_amount = reserves_amount.saturating_sub(fee);

            let confiscation_tx = Transaction {
                version: bitcoin::transaction::Version::TWO,
                lock_time: bitcoin::absolute::LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: reserves_outpoint,
                    script_sig: bitcoin::ScriptBuf::new(),
                    sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::default(),
                }],
                output: vec![TxOut {
                    value: Amount::from_sat(output_amount),
                    script_pubkey: lottery_output.script_pubkey(),
                }],
            };

            // Build the Taproot reserves structure for signing
            let voter_set = VoterSet::new(original_operator, quorum_members.clone());
            let voter_count = voter_set.all_voters().len();
            let threshold_config = ThresholdConfig::default_for_voter_count(voter_count);

            let taproot_builder = TapscriptReservesBuilder::new(
                voter_set.clone(),
                threshold_config.clone(),
                self.wallet.network(),
                ledger_hash_val,
            );

            let taproot_output = match taproot_builder.build() {
                Ok(out) => out,
                Err(e) => {
                    tracing::error!("Failed to build Taproot output: {:?}", e);
                    continue;
                }
            };

            // Use quorum-override tier (threshold without tie-breaker)
            let (tier_index, tier) = match threshold_config.tiers.iter()
                .enumerate()
                .find(|(_, t)| !t.requires_tie_breaker && t.threshold > 1)
            {
                Some(t) => t,
                None => {
                    tracing::error!("No quorum-override tier found");
                    continue;
                }
            };

            tracing::info!("  Using Tier {} for confiscation (threshold={}/{})",
                tier_index, tier.threshold, voter_count);

            // Build leaf script and compute sighash
            let leaf_script = match taproot_builder.build_threshold_leaf(tier) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("Failed to build leaf script: {:?}", e);
                    continue;
                }
            };

            let leaf_hash = bitcoin::taproot::TapLeafHash::from_script(&leaf_script, bitcoin::taproot::LeafVersion::TapScript);

            let prevouts = vec![TxOut {
                value: Amount::from_sat(reserves_amount),
                script_pubkey: reserves_addr.script_pubkey(),
            }];

            let mut confiscation_tx = confiscation_tx;
            let mut sighash_cache = SighashCache::new(&confiscation_tx);
            let sighash = match sighash_cache.taproot_script_spend_signature_hash(
                0,
                &bitcoin::sighash::Prevouts::All(&prevouts),
                leaf_hash,
                TapSighashType::Default,
            ) {
                Ok(sh) => sh,
                Err(e) => {
                    tracing::error!("Failed to compute sighash: {}", e);
                    continue;
                }
            };

            let sighash_bytes: [u8; 32] = *sighash.as_ref();

            // Sign with our key
            let msg = Message::from_digest(sighash_bytes);
            let our_signature = secp.sign_schnorr(&msg, &keypair);

            let mut signatures: HashMap<PublicKey, [u8; 64]> = HashMap::new();
            signatures.insert(our_pubkey, our_signature.serialize());

            tracing::info!("  Signed with our key");

            // Request signatures from other quorum members via Nostr
            let required_sigs = tier.threshold;
            tracing::info!("  Need {}/{} signatures", required_sigs, voter_count);

            if signatures.len() < required_sigs {
                let unsigned_tx_bytes = bitcoin::consensus::encode::serialize(&confiscation_tx);
                let unsigned_tx_hex = hex::encode(&unsigned_tx_bytes);

                let request_params = serde_json::json!({
                    "ledger_id": ledger_id,
                    "sighash": hex::encode(sighash_bytes),
                    "unsigned_tx": unsigned_tx_hex,
                    "lottery_address": lottery_output.address.to_string(),
                    "violation_details": "Confiscation to lottery for dispute resolution",
                });

                let request_id = match self.nostr.send_ledger_request(
                    &ledger_id,
                    "confiscation_sign",
                    request_params,
                ).await {
                    Ok(id) => id,
                    Err(e) => {
                        tracing::error!("Failed to send sign request: {:?}", e);
                        continue;
                    }
                };

                tracing::info!("  Request ID: {}...", &request_id[..16.min(request_id.len())]);

                // Poll for signatures
                let max_attempts = 20;
                let poll_interval = std::time::Duration::from_secs(3);

                for attempt in 1..=max_attempts {
                    tokio::time::sleep(poll_interval).await;

                    let since = nostr_sdk::Timestamp::now() - 120;
                    let filter = Filter::new()
                        .kind(Kind::Custom(crate::nostr::KIND_LEDGER_RESPONSE))
                        .since(since);

                    let response_events = match self.nostr.client()
                        .fetch_events(vec![filter], Some(std::time::Duration::from_secs(5)))
                        .await
                    {
                        Ok(e) => e,
                        Err(_) => continue,
                    };

                    for event in response_events.iter() {
                        let mut is_our_request = false;
                        for tag in event.tags.iter() {
                            if tag.kind() == nostr_sdk::TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::E)) {
                                if let Some(val) = tag.content() {
                                    if val == request_id {
                                        is_our_request = true;
                                        break;
                                    }
                                }
                            }
                        }

                        if !is_our_request { continue; }

                        if let Ok(response) = serde_json::from_str::<crate::nostr::LedgerResponse>(&event.content) {
                            if response.success {
                                if let Some(result) = &response.result {
                                    if let (Some(signer_hex), Some(sig_hex)) = (
                                        result.get("signer").and_then(|v| v.as_str()),
                                        result.get("signature").and_then(|v| v.as_str())
                                    ) {
                                        if let (Ok(signer), Ok(sig_bytes)) = (
                                            signer_hex.parse::<PublicKey>(),
                                            hex::decode(sig_hex)
                                        ) {
                                            if sig_bytes.len() == 64 && !signatures.contains_key(&signer) {
                                                let mut sig_arr = [0u8; 64];
                                                sig_arr.copy_from_slice(&sig_bytes);
                                                signatures.insert(signer, sig_arr);
                                                tracing::info!("    Received signature from {}...", &signer.to_string()[..16]);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    tracing::debug!("    Poll {}/{}: {}/{} signatures", attempt, max_attempts, signatures.len(), required_sigs);

                    if signatures.len() >= required_sigs { break; }
                }
            }

            if signatures.len() < required_sigs {
                tracing::warn!("Could not collect enough signatures ({}/{}), will retry later",
                    signatures.len(), required_sigs);
                continue;
            }

            // Build witness
            tracing::info!("  Building witness with {} signatures...", signatures.len());

            let control_block = match taproot_output.control_block_for_tier(tier_index) {
                Some(cb) => cb,
                None => {
                    tracing::error!("Failed to get control block for tier");
                    continue;
                }
            };

            let mut witness = Witness::new();
            let sorted_keys = voter_set.sorted_x_only_pubkeys();

            for x_only in sorted_keys.iter().rev() {
                for voter in voter_set.all_voters() {
                    if voter.x_only_public_key().0 == *x_only {
                        if let Some(sig) = signatures.get(&voter) {
                            witness.push(sig);
                        } else {
                            witness.push(&[] as &[u8]);
                        }
                        break;
                    }
                }
            }

            witness.push(leaf_script.as_bytes());
            witness.push(control_block.serialize());

            confiscation_tx.input[0].witness = witness;

            // Broadcast
            tracing::info!("  Broadcasting confiscation transaction...");

            match self.wallet.broadcast(&confiscation_tx) {
                Ok(_) => {
                    let confiscation_txid = confiscation_tx.compute_txid();
                    tracing::info!("Confiscation transaction broadcast! Txid: {}", confiscation_txid);
                    tracing::info!("  Lottery address: {}", lottery_output.address);

                    // Write confiscated marker
                    if let Err(e) = std::fs::write(&confiscated_marker, confiscation_txid.to_string()) {
                        tracing::warn!("Failed to write confiscated marker: {}", e);
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to broadcast confiscation TX: {}", e);
                }
            }
        }
    }

    /// Auto-reveal preimage when confiscation TX has 3+ confirmations
    ///
    /// For each ledger where we're armed but haven't revealed yet,
    /// check if the lottery UTXO exists with 3+ confirmations.
    async fn auto_reveal_on_confiscation(&self) {
        use deposits_core::TlvDecode;
        use deposits_core::messages::LedgerOperation;
        use deposits_core::tapscript_reserves::{LotteryScriptBuilder, LotteryParticipant};

        // Find armed marker files (preimage exists but not revealed)
        let entries = match std::fs::read_dir(&self.data_dir) {
            Ok(e) => e,
            Err(_) => return,
        };

        let preimage_files: Vec<_> = entries
            .filter_map(|e| e.ok())
            .filter(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                name.starts_with("lottery_preimage_") && name.ends_with(".hex")
            })
            .collect();

        for entry in preimage_files {
            let filename = entry.file_name().to_string_lossy().to_string();
            let ledger_prefix = filename
                .strip_prefix("lottery_preimage_")
                .and_then(|s| s.strip_suffix(".hex"))
                .unwrap_or("");

            if ledger_prefix.is_empty() {
                continue;
            }

            // Skip if already revealed
            let revealed_marker = self.data_dir.join(format!("lottery_revealed_{}.marker", ledger_prefix));
            if revealed_marker.exists() {
                continue;
            }

            // Find the full ledger_id
            let ledger_id = {
                let ledgers = self.handler.ledgers.lock().unwrap();
                let mut found = None;
                for ((_operator, _reserves_id), arc) in ledgers.iter() {
                    let ledger = arc.read().unwrap();
                    let lid = ledger.ledger_id_hex();
                    if lid.starts_with(ledger_prefix) {
                        found = Some(lid);
                        break;
                    }
                }
                match found {
                    Some(id) => id,
                    None => continue,
                }
            };

            // Check if confiscation TX is confirmed with 3+ blocks
            match self.check_confiscation_confirmed(&ledger_id, 3).await {
                Ok(true) => {
                    tracing::info!("Confiscation TX confirmed +3 for ledger {}. Auto-revealing preimage.", &ledger_id[..16]);
                    self.auto_reveal_preimage(&ledger_id).await;
                }
                Ok(false) => {
                    // Not yet confirmed enough
                }
                Err(e) => {
                    tracing::debug!("Could not check confiscation for {}: {}", &ledger_id[..16], e);
                }
            }
        }
    }

    /// Check if the confiscation TX for a ledger has enough confirmations
    async fn check_confiscation_confirmed(&self, ledger_id: &str, min_confirmations: u32) -> Result<bool, Error> {
        use deposits_core::TlvDecode;
        use deposits_core::messages::LedgerOperation;
        use deposits_core::tapscript_reserves::{LotteryScriptBuilder, LotteryParticipant};
        use crate::nostr::KIND_LEDGER_UPDATE;
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
        use nostr_sdk::{Client, Keys, Filter, Kind};
        use nostr_sdk::prelude::{SingleLetterTag, Alphabet};

        // Fetch CustodyArmed participants from Nostr to build the lottery address
        let keys = Keys::generate();
        let client = Client::new(keys);
        client.add_relay(&self.relay_url).await
            .map_err(|e| Error::Protocol(format!("Failed to add relay: {}", e)))?;
        client.connect().await;

        let filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_UPDATE))
            .custom_tag(SingleLetterTag::lowercase(Alphabet::D), [ledger_id])
            .limit(500);

        let events = client
            .fetch_events(vec![filter], None)
            .await
            .map_err(|e| Error::Protocol(format!("Failed to fetch: {}", e)))?;

        client.disconnect().await.ok();

        // Extract CustodyArmed participants
        let mut participants: Vec<LotteryParticipant> = Vec::new();

        for event in events.iter() {
            if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
                if let Ok(update) = deposits_core::SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                    if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                        if let LedgerOperation::CustodyArmed { commitment_hash, target_reserves, .. } = op {
                            let x_only = update.operator_id.x_only_public_key().0;
                            participants.push(LotteryParticipant::new(x_only, commitment_hash, target_reserves));
                        }
                    }
                }
            }
        }

        if participants.len() < 2 {
            return Err(Error::Protocol("Not enough participants for lottery".to_string()));
        }

        // Sort by x-only pubkey for deterministic order
        participants.sort_by(|a, b| a.pubkey.serialize().cmp(&b.pubkey.serialize()));

        // Build lottery output to get the address
        let recovery_voters: Vec<bitcoin::secp256k1::XOnlyPublicKey> = participants.iter()
            .map(|p| p.pubkey)
            .collect();
        let recovery_threshold = (recovery_voters.len() + 1) / 2;

        let lottery_builder = LotteryScriptBuilder::new(
            participants,
            recovery_voters,
            recovery_threshold,
            self.wallet.network(),
        );

        let lottery_output = lottery_builder.build()
            .map_err(|e| Error::Protocol(format!("Failed to build lottery output: {:?}", e)))?;

        // Check if lottery address has a UTXO with enough confirmations
        let lottery_script = lottery_output.address.script_pubkey();

        let utxo_result = self.wallet.find_utxo_for_script(&lottery_script)?;

        if utxo_result.is_none() {
            return Ok(false); // No UTXO at lottery address yet
        }

        // Check confirmations
        let current_height = self.wallet.get_block_height().unwrap_or(0);

        // We need to find the TX and its confirmation height
        // For simplicity, if UTXO exists and we're 3+ blocks past our armed height, consider it confirmed
        // In practice, we'd check the TX's block height

        // For now, use a simple heuristic: if UTXO exists, check if we have an armed marker with block height
        let armed_height_file = self.data_dir.join(format!("lottery_armed_height_{}.txt", &ledger_id[..16.min(ledger_id.len())]));

        if let Ok(height_str) = std::fs::read_to_string(&armed_height_file) {
            if let Ok(armed_height) = height_str.trim().parse::<u32>() {
                // Check if current height is at least armed_height + 3 (confiscation happens after arming)
                if current_height >= armed_height + 3 {
                    return Ok(true);
                }
            }
        }

        // If no armed height file, create one
        if !armed_height_file.exists() {
            let _ = std::fs::write(&armed_height_file, current_height.to_string());
        }

        Ok(false)
    }

    /// Auto-rotate to quorum and continue ledger after winning
    async fn auto_post_win_cleanup(&self) {
        // Find completed marker files (lottery finished, we might have won)
        let entries = match std::fs::read_dir(&self.data_dir) {
            Ok(e) => e,
            Err(_) => return,
        };

        let completed_markers: Vec<_> = entries
            .filter_map(|e| e.ok())
            .filter(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                name.starts_with("lottery_completed_") && name.ends_with(".marker")
            })
            .collect();

        for entry in completed_markers {
            let filename = entry.file_name().to_string_lossy().to_string();
            let ledger_prefix = filename
                .strip_prefix("lottery_completed_")
                .and_then(|s| s.strip_suffix(".marker"))
                .unwrap_or("");

            if ledger_prefix.is_empty() {
                continue;
            }

            // Skip if already rotated
            let rotated_marker = self.data_dir.join(format!("lottery_rotated_{}.marker", ledger_prefix));
            if rotated_marker.exists() {
                continue;
            }

            // Find the full ledger_id
            let ledger_id = {
                let ledgers = self.handler.ledgers.lock().unwrap();
                let mut found = None;
                for ((_operator, _reserves_id), arc) in ledgers.iter() {
                    let ledger = arc.read().unwrap();
                    let lid = ledger.ledger_id_hex();
                    if lid.starts_with(ledger_prefix) {
                        found = Some(lid);
                        break;
                    }
                }
                match found {
                    Some(id) => id,
                    None => continue,
                }
            };

            // Check if we won (we published CustodyAcquire)
            match self.check_if_we_won(&ledger_id).await {
                Ok(true) => {
                    tracing::info!("We won lottery for {}. Auto-rotating to quorum...", &ledger_id[..16]);

                    // Auto-rotate
                    match self.auto_rotate_to_quorum(&ledger_id).await {
                        Ok(()) => {
                            // Mark as rotated
                            let _ = std::fs::write(&rotated_marker, "rotated");
                            tracing::info!("Rotation complete for {}", &ledger_id[..16]);

                            // Auto-continue
                            if let Err(e) = self.auto_continue_ledger(&ledger_id).await {
                                tracing::warn!("Auto-continue failed: {}", e);
                            }
                        }
                        Err(e) => {
                            tracing::warn!("Auto-rotate failed for {}: {}", &ledger_id[..16], e);
                        }
                    }
                }
                Ok(false) => {
                    // We didn't win, nothing to do
                    let _ = std::fs::write(&rotated_marker, "not_winner");
                }
                Err(e) => {
                    tracing::debug!("Could not check win status for {}: {}", &ledger_id[..16], e);
                }
            }
        }
    }

    /// Check if we won the lottery for a ledger (we published CustodyAcquire)
    async fn check_if_we_won(&self, ledger_id: &str) -> Result<bool, Error> {
        use deposits_core::TlvDecode;
        use deposits_core::messages::LedgerOperation;
        use crate::nostr::KIND_LEDGER_UPDATE;
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
        use nostr_sdk::{Client, Keys, Filter, Kind};
        use nostr_sdk::prelude::{SingleLetterTag, Alphabet};
        use bitcoin::secp256k1::Secp256k1;

        let secp = Secp256k1::new();
        let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &self.wallet.operator_secret());
        let our_pubkey = keypair.public_key();

        let keys = Keys::generate();
        let client = Client::new(keys);
        client.add_relay(&self.relay_url).await
            .map_err(|e| Error::Protocol(format!("Failed to add relay: {}", e)))?;
        client.connect().await;

        let filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_UPDATE))
            .custom_tag(SingleLetterTag::lowercase(Alphabet::D), [ledger_id])
            .limit(500);

        let events = client
            .fetch_events(vec![filter], None)
            .await
            .map_err(|e| Error::Protocol(format!("Failed to fetch: {}", e)))?;

        client.disconnect().await.ok();

        // Check if we have a CustodyAcquire
        for event in events.iter() {
            if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
                if let Ok(update) = deposits_core::SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                    if update.operator_id == our_pubkey {
                        if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                            if matches!(op, LedgerOperation::CustodyAcquire { .. }) {
                                return Ok(true);
                            }
                        }
                    }
                }
            }
        }

        Ok(false)
    }

    /// Auto-rotate winnings to quorum-controlled Taproot
    async fn auto_rotate_to_quorum(&self, ledger_id: &str) -> Result<(), Error> {
        use bitcoin::hashes::{Hash, sha256};
        use bitcoin::secp256k1::{Secp256k1, PublicKey, Message};
        use bitcoin::{Transaction, TxIn, TxOut, Witness, Amount, ScriptBuf};
        use deposits_core::{TlvDecode, TlvEncode, SignedLedgerUpdate, VoterSet, ThresholdConfig, TapscriptReservesBuilder};
        use deposits_core::messages::LedgerOperation;
        use crate::nostr::KIND_LEDGER_UPDATE;
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
        use nostr_sdk::{Client, Keys, Filter, Kind};
        use nostr_sdk::prelude::{SingleLetterTag, Alphabet};

        let secp = Secp256k1::new();
        let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &self.wallet.operator_secret());
        let our_pubkey = keypair.public_key();

        // Fetch updates from Nostr
        let keys = Keys::generate();
        let client = Client::new(keys);
        client.add_relay(&self.relay_url).await
            .map_err(|e| Error::Protocol(format!("Failed to add relay: {}", e)))?;
        client.connect().await;

        let filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_UPDATE))
            .custom_tag(SingleLetterTag::lowercase(Alphabet::D), [ledger_id])
            .limit(500);

        let events = client
            .fetch_events(vec![filter], None)
            .await
            .map_err(|e| Error::Protocol(format!("Failed to fetch: {}", e)))?;

        client.disconnect().await.ok();

        // Find our CustodyAcquire and quorum members
        let mut current_reserves_address: Option<String> = None;
        let mut our_latest: Option<SignedLedgerUpdate> = None;
        let mut quorum_members: Vec<PublicKey> = Vec::new();

        for event in events.iter() {
            if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
                if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                    if update.operator_id == our_pubkey {
                        if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                            if let LedgerOperation::CustodyAcquire { ref new_reserves_address, .. } = op {
                                current_reserves_address = Some(new_reserves_address.clone());
                            }
                            if let LedgerOperation::QuorumAddMember { quorum_member, .. } = op {
                                if !quorum_members.contains(&quorum_member) {
                                    quorum_members.push(quorum_member);
                                }
                            }
                        }
                        if our_latest.is_none() || update.sequence_number > our_latest.as_ref().unwrap().sequence_number {
                            our_latest = Some(update);
                        }
                    }
                }
            }
        }

        let current_reserves_address = current_reserves_address
            .ok_or_else(|| Error::Protocol("No CustodyAcquire found".to_string()))?;
        let our_latest = our_latest
            .ok_or_else(|| Error::Protocol("No latest update found".to_string()))?;

        if quorum_members.is_empty() {
            return Err(Error::Protocol("No quorum members found".to_string()));
        }

        tracing::info!("Rotating from {} with {} quorum members", &current_reserves_address[..20.min(current_reserves_address.len())], quorum_members.len());

        // Find UTXO at current reserves address
        let reserves_addr: bitcoin::Address<bitcoin::address::NetworkUnchecked> = current_reserves_address.parse()
            .map_err(|e| Error::Protocol(format!("Invalid address: {}", e)))?;
        let reserves_addr = reserves_addr.require_network(self.wallet.network())
            .map_err(|e| Error::Protocol(format!("Network mismatch: {}", e)))?;

        let script_pubkey = reserves_addr.script_pubkey();
        let utxo = self.wallet.find_utxo_for_script(&script_pubkey)?
            .ok_or_else(|| Error::Protocol("No UTXO at reserves address".to_string()))?;

        let (outpoint, amount) = utxo;

        // Build new Taproot reserves with quorum
        let current_block = self.wallet.get_block_height().unwrap_or(0);
        let expiry_block = current_block + 1000; // 1000 blocks expiry

        // Build voter set - we are tie-breaker, others are additional voters
        let other_voters: Vec<bitcoin::secp256k1::PublicKey> = quorum_members
            .iter()
            .filter(|m| **m != our_pubkey)
            .copied()
            .collect();
        let voter_set = VoterSet::new(our_pubkey, other_voters);

        // Compute quorum parameters for ReservesRotate
        let quorum_size = quorum_members.len() as u8;
        let quorum_threshold = ((quorum_members.len() + 1) / 2) as u8;
        let first_expiry_block = expiry_block;

        // Compute ledger hash
        let ledger_hash = our_latest.current_hash;

        // Build Taproot reserves with default config
        let tapscript_builder = TapscriptReservesBuilder::with_defaults(
            voter_set,
            self.wallet.network(),
            ledger_hash,
        );

        let taproot_output = tapscript_builder.build()
            .map_err(|e| Error::Protocol(format!("Failed to build taproot output: {:?}", e)))?;

        // Build rotation TX
        let fee = 300u64;
        let output_amount = amount.saturating_sub(fee);

        let rotate_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(output_amount),
                script_pubkey: taproot_output.address.script_pubkey(),
            }],
        };

        // Sign the transaction (P2WPKH spend from our target_reserves)
        let pubkey_bytes: [u8; 33] = our_pubkey.serialize();
        let compressed = bitcoin::CompressedPublicKey::from_slice(&pubkey_bytes)
            .map_err(|e| Error::Protocol(format!("Invalid pubkey: {}", e)))?;

        use bitcoin::sighash::{SighashCache, EcdsaSighashType};
        let prevouts = vec![TxOut {
            value: Amount::from_sat(amount),
            script_pubkey: script_pubkey.clone(),
        }];

        let mut sighash_cache = SighashCache::new(&rotate_tx);
        let sighash = sighash_cache.p2wpkh_signature_hash(
            0,
            &script_pubkey,
            Amount::from_sat(amount),
            EcdsaSighashType::All,
        ).map_err(|e| Error::Protocol(format!("Sighash error: {}", e)))?;

        let msg = Message::from_digest(*sighash.as_ref());
        let signature = secp.sign_ecdsa(&msg, &self.wallet.operator_secret());

        // Build witness
        let mut sig_bytes = signature.serialize_der().to_vec();
        sig_bytes.push(EcdsaSighashType::All as u8);

        let mut rotate_tx = rotate_tx;
        rotate_tx.input[0].witness.push(sig_bytes);
        rotate_tx.input[0].witness.push(compressed.to_bytes());

        // Broadcast
        let rotate_txid = self.wallet.broadcast(&rotate_tx)?;
        tracing::info!("Rotation TX broadcast: {}", rotate_txid);

        // Publish ReservesRotate operation
        let operation = LedgerOperation::ReservesRotate {
            reserves_id: taproot_output.address.to_string(),
            spending_txid: *outpoint.txid.as_ref(),
            new_outpoint_txid: *rotate_txid.as_ref(),
            new_outpoint_vout: 0,
            amount: output_amount,
            quorum_threshold,
            quorum_size,
            first_expiry_block,
            ledger_hash,
        };

        let message_bytes = operation.tlv_encode();

        let sequence = our_latest.sequence_number + 1;
        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(&sequence.to_le_bytes());
        hash_input.extend_from_slice(&our_latest.current_hash);
        hash_input.extend_from_slice(&message_bytes);
        let new_hash = *sha256::Hash::hash(&hash_input).as_byte_array();

        let update_msg = format!(
            "deposits:ledger:{}:{}:{}",
            hex::encode(our_latest.current_hash),
            sequence,
            hex::encode(&new_hash)
        );
        let msg_hash = sha256::Hash::hash(update_msg.as_bytes());
        let msg = Message::from_digest(*msg_hash.as_ref());
        let signature = secp.sign_schnorr(&msg, &keypair);
        let operator_sig_bytes: [u8; 64] = *signature.as_ref();

        let ledger_id_bytes: [u8; 32] = hex::decode(ledger_id)
            .map_err(|e| Error::Protocol(format!("Invalid ledger_id: {}", e)))?
            .try_into()
            .map_err(|_| Error::Protocol("Ledger ID must be 32 bytes".to_string()))?;

        let block_hash = self.wallet.get_block_hash().unwrap_or([0u8; 32]);
        let signed_update = SignedLedgerUpdate {
            message: message_bytes,
            message_type: deposits_core::messages::consts::RESERVES_ROTATE,
            operator_signature: operator_sig_bytes,
            partner_signature: [0u8; 64],
            operator_id: our_pubkey,
            ledger_id: ledger_id_bytes,
            sequence_number: sequence,
            previous_hash: our_latest.current_hash,
            current_hash: new_hash,
            timestamp: deposits_core::now_unix_timestamp(),
            block_height: current_block,
            block_hash,
        };

        self.nostr.broadcast_ledger_update(&signed_update).await
            .map_err(|e| Error::Protocol(format!("Failed to broadcast ReservesRotate: {:?}", e)))?;

        tracing::info!("ReservesRotate published. New reserves at: {}", taproot_output.address);
        Ok(())
    }

    /// Auto-continue ledger after rotation (re-open deposits)
    async fn auto_continue_ledger(&self, ledger_id: &str) -> Result<(), Error> {
        use bitcoin::hashes::{Hash, sha256};
        use bitcoin::secp256k1::{Secp256k1, PublicKey, Message};
        use deposits_core::{TlvDecode, TlvEncode, SignedLedgerUpdate};
        use deposits_core::messages::LedgerOperation;
        use crate::nostr::KIND_LEDGER_UPDATE;
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
        use nostr_sdk::{Client, Keys, Filter, Kind};
        use nostr_sdk::prelude::{SingleLetterTag, Alphabet};

        let secp = Secp256k1::new();
        let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &self.wallet.operator_secret());
        let our_pubkey = keypair.public_key();

        // Fetch updates
        let keys = Keys::generate();
        let client = Client::new(keys);
        client.add_relay(&self.relay_url).await
            .map_err(|e| Error::Protocol(format!("Failed to add relay: {}", e)))?;
        client.connect().await;

        let filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_UPDATE))
            .custom_tag(SingleLetterTag::lowercase(Alphabet::D), [ledger_id])
            .limit(500);

        let events = client
            .fetch_events(vec![filter], None)
            .await
            .map_err(|e| Error::Protocol(format!("Failed to fetch: {}", e)))?;

        client.disconnect().await.ok();

        // Find our latest update and collect original depositors
        let mut our_latest: Option<SignedLedgerUpdate> = None;
        let mut original_depositors: Vec<PublicKey> = Vec::new();

        for event in events.iter() {
            if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
                if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                    // Collect depositors
                    if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                        if let LedgerOperation::DepositOpen { pubkey, .. } = op {
                            if !original_depositors.contains(&pubkey) {
                                original_depositors.push(pubkey);
                            }
                        }
                    }

                    if update.operator_id == our_pubkey {
                        if our_latest.is_none() || update.sequence_number > our_latest.as_ref().unwrap().sequence_number {
                            our_latest = Some(update);
                        }
                    }
                }
            }
        }

        let mut our_latest = our_latest
            .ok_or_else(|| Error::Protocol("No latest update found".to_string()))?;

        if original_depositors.is_empty() {
            tracing::info!("No original depositors to re-open");
            return Ok(());
        }

        tracing::info!("Re-opening {} deposits", original_depositors.len());

        let current_block = self.wallet.get_block_height().unwrap_or(0);
        let block_hash = self.wallet.get_block_hash().unwrap_or([0u8; 32]);

        // Re-open each deposit
        for depositor in original_depositors {
            let operation = LedgerOperation::DepositOpen {
                pubkey: depositor,
                fees: None,
                payment_hash: None,
                invoice: None,
                cosigner_guarantee_signature: None,
            };

            let message_bytes = operation.tlv_encode();

            let sequence = our_latest.sequence_number + 1;
            let mut hash_input = Vec::new();
            hash_input.extend_from_slice(&sequence.to_le_bytes());
            hash_input.extend_from_slice(&our_latest.current_hash);
            hash_input.extend_from_slice(&message_bytes);
            let new_hash = *sha256::Hash::hash(&hash_input).as_byte_array();

            let update_msg = format!(
                "deposits:ledger:{}:{}:{}",
                hex::encode(our_latest.current_hash),
                sequence,
                hex::encode(&new_hash)
            );
            let msg_hash = sha256::Hash::hash(update_msg.as_bytes());
            let msg = Message::from_digest(*msg_hash.as_ref());
            let signature = secp.sign_schnorr(&msg, &keypair);
            let operator_sig_bytes: [u8; 64] = *signature.as_ref();

            let ledger_id_bytes: [u8; 32] = hex::decode(ledger_id)
                .map_err(|e| Error::Protocol(format!("Invalid ledger_id: {}", e)))?
                .try_into()
                .map_err(|_| Error::Protocol("Ledger ID must be 32 bytes".to_string()))?;

            let signed_update = SignedLedgerUpdate {
                message: message_bytes,
                message_type: deposits_core::messages::consts::DEPOSIT_OPEN,
                operator_signature: operator_sig_bytes,
                partner_signature: [0u8; 64],
                operator_id: our_pubkey,
                ledger_id: ledger_id_bytes,
                sequence_number: sequence,
                previous_hash: our_latest.current_hash,
                current_hash: new_hash,
                timestamp: deposits_core::now_unix_timestamp(),
                block_height: current_block,
                block_hash,
            };

            self.nostr.broadcast_ledger_update(&signed_update).await
                .map_err(|e| Error::Protocol(format!("Failed to broadcast DepositOpen: {:?}", e)))?;

            tracing::info!("Re-opened deposit for {}...", &depositor.to_string()[..16]);

            // Update our_latest for next iteration
            our_latest = signed_update;
        }

        tracing::info!("Ledger continue complete");
        Ok(())
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

    /// Process a withdrawal request from a depositor
    ///
    /// Params:
    /// - deposit_pubkey: hex-encoded depositor's pubkey
    /// - address: destination Bitcoin address
    /// - amount_sats: amount to withdraw
    /// - fee_sats: fee for the withdrawal transaction
    /// - nonce: hex-encoded 32-byte nonce
    /// - signature: hex-encoded Schnorr signature over withdrawal message
    async fn process_withdraw_request(&self, request: &crate::nostr::LedgerRequest) -> (bool, Option<String>, Option<String>) {
        use bitcoin::secp256k1::{Secp256k1, schnorr::Signature, Message};
        use bitcoin::hashes::{sha256, Hash};

        tracing::info!("Processing withdraw request for ledger {}...",
            &request.ledger_id[..16.min(request.ledger_id.len())]);

        // Extract parameters
        let deposit_pubkey_hex = match request.params.get("deposit_pubkey").and_then(|v| v.as_str()) {
            Some(p) => p,
            None => return (false, None, Some("Missing deposit_pubkey".to_string())),
        };
        let address = match request.params.get("address").and_then(|v| v.as_str()) {
            Some(a) => a,
            None => return (false, None, Some("Missing address".to_string())),
        };
        let amount_sats = match request.params.get("amount_sats").and_then(|v| v.as_u64()) {
            Some(a) => a,
            None => return (false, None, Some("Missing amount_sats".to_string())),
        };
        let fee_sats = match request.params.get("fee_sats").and_then(|v| v.as_u64()) {
            Some(f) => f,
            None => return (false, None, Some("Missing fee_sats".to_string())),
        };
        let nonce_hex = match request.params.get("nonce").and_then(|v| v.as_str()) {
            Some(n) => n,
            None => return (false, None, Some("Missing nonce".to_string())),
        };
        let signature_hex = match request.params.get("signature").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return (false, None, Some("Missing signature".to_string())),
        };

        // Parse deposit pubkey
        let deposit_pubkey = match hex::decode(deposit_pubkey_hex)
            .ok()
            .and_then(|bytes| bitcoin::secp256k1::PublicKey::from_slice(&bytes).ok())
        {
            Some(pk) => pk,
            None => return (false, None, Some("Invalid deposit_pubkey".to_string())),
        };

        // Parse nonce
        let nonce: [u8; 32] = match hex::decode(nonce_hex) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                arr
            }
            _ => return (false, None, Some("Invalid nonce (must be 32 bytes hex)".to_string())),
        };

        // Parse signature
        let signature = match hex::decode(signature_hex)
            .ok()
            .and_then(|bytes| Signature::from_slice(&bytes).ok())
        {
            Some(sig) => sig,
            None => return (false, None, Some("Invalid signature".to_string())),
        };

        // Verify signature
        // Message format: "withdraw:{address}:{amount_sats}:{fee_sats}:{nonce_hex}"
        let msg_str = format!("withdraw:{}:{}:{}:{}", address, amount_sats, fee_sats, nonce_hex);
        let msg_hash = sha256::Hash::hash(msg_str.as_bytes());
        let secp = Secp256k1::new();
        let msg = Message::from_digest(*msg_hash.as_byte_array());
        let x_only = deposit_pubkey.x_only_public_key().0;

        if secp.verify_schnorr(&signature, &msg, &x_only).is_err() {
            return (false, None, Some("Invalid signature".to_string()));
        }

        // Find the ledger
        let (reserves_id, _ledger) = match self.get_ledger_by_ledger_id(&request.ledger_id)
            .or_else(|| self.get_ledger_by_reserves_id(&request.ledger_id))
        {
            Some(l) => l,
            None => return (false, None, Some("Ledger not found".to_string())),
        };

        // Lock the withdrawal
        match self.lock_withdrawal(
            &reserves_id,
            deposit_pubkey,
            address.to_string(),
            amount_sats,
            fee_sats,
            nonce,
            signature.serialize(),
            None, // no memo
        ) {
            Ok(lock_result) => {
                let withdrawal_id = lock_result.withdrawal.withdrawal_id;
                let result = serde_json::json!({
                    "status": "locked",
                    "withdrawal_id": hex::encode(withdrawal_id),
                    "message": "Withdrawal locked. Will be broadcast after lock period.",
                });
                tracing::info!("Withdrawal locked: {}", hex::encode(&withdrawal_id[..8]));
                (true, Some(result.to_string()), None)
            }
            Err(e) => {
                tracing::warn!("Withdrawal failed: {}", e);
                (false, None, Some(format!("Withdrawal failed: {}", e)))
            }
        }
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

    async fn process_confiscation_sign_request(&self, request: &crate::nostr::LedgerRequest) -> (bool, Option<String>, Option<String>) {
        use bitcoin::secp256k1::{Secp256k1, Message};

        tracing::info!("Processing confiscation_sign request for ledger {}...",
            &request.ledger_id[..16.min(request.ledger_id.len())]);

        // Extract sighash from request params
        let sighash_hex = match request.params.get("sighash").and_then(|v| v.as_str()) {
            Some(h) => h,
            None => return (false, None, Some("Missing sighash parameter".to_string())),
        };

        let sighash_bytes: [u8; 32] = match hex::decode(sighash_hex) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                arr
            }
            _ => return (false, None, Some("Invalid sighash format".to_string())),
        };

        // Check if we have an armed marker for this ledger (meaning we're participating in the dispute)
        let ledger_prefix = &request.ledger_id[..16.min(request.ledger_id.len())];
        let armed_marker = self.data_dir.join(format!("custody_armed_{}.marker", ledger_prefix));

        if !armed_marker.exists() {
            return (false, None, Some("Not armed for this dispute".to_string()));
        }

        // Sign the sighash
        let secp = Secp256k1::new();
        let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &self.wallet.operator_secret());
        let msg = Message::from_digest(sighash_bytes);
        let signature = secp.sign_schnorr(&msg, &keypair);

        let our_pubkey = keypair.public_key();
        let result = serde_json::json!({
            "signer": our_pubkey.to_string(),
            "signature": hex::encode(signature.serialize()),
        });

        tracing::info!("Signed confiscation sighash for ledger {}...", ledger_prefix);
        (true, Some(result.to_string()), None)
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

    /// Handle a ledger response (for auto-recording attestations)
    async fn handle_ledger_response(&self, response: crate::nostr::LedgerResponse) {
        // Check if this is a response to one of our pending collateral_lock requests
        let our_reserves_id = {
            let pending = self.pending_collateral_requests.lock().unwrap();
            pending.get(&response.request_id).cloned()
        };

        let Some(reserves_id) = our_reserves_id else {
            // Not a tracked request, ignore
            return;
        };

        // Remove from pending
        {
            let mut pending = self.pending_collateral_requests.lock().unwrap();
            pending.remove(&response.request_id);
        }

        if !response.success {
            tracing::warn!(
                "Collateral lock request {} failed: {}",
                &response.request_id[..16.min(response.request_id.len())],
                response.error.unwrap_or_default()
            );
            return;
        }

        // Extract and decode attestation from response
        let Some(result) = response.result else {
            tracing::warn!("Collateral lock response has no result data");
            return;
        };

        let Some(attestation_b64) = result.get("attestation_b64").and_then(|v| v.as_str()) else {
            tracing::warn!("Collateral lock response missing attestation_b64");
            return;
        };

        // Decode base64 -> JSON -> CollateralAttestationMsg
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
        let attestation_json = match BASE64.decode(attestation_b64) {
            Ok(bytes) => match String::from_utf8(bytes) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("Failed to decode attestation as UTF-8: {}", e);
                    return;
                }
            },
            Err(e) => {
                tracing::error!("Failed to decode attestation base64: {}", e);
                return;
            }
        };

        let attestation: deposits_core::CollateralAttestationMsg = match serde_json::from_str(&attestation_json) {
            Ok(a) => a,
            Err(e) => {
                tracing::error!("Failed to parse attestation JSON: {}", e);
                return;
            }
        };

        tracing::info!(
            "Auto-recording attestation: amount={} msats, until_block={}, from operator {}...",
            attestation.amount,
            attestation.lock_until_block,
            &hex::encode(attestation.operator.serialize())[..16]
        );

        // Record the attestation on our ledger
        match self.record_collateral_attestation(&reserves_id, attestation) {
            Ok(()) => {
                tracing::info!("Attestation recorded successfully on ledger {}", &reserves_id[..16.min(reserves_id.len())]);

                // Broadcast the update
                if let Err(e) = self.broadcast_last_update(&reserves_id).await {
                    tracing::warn!("Failed to broadcast attestation: {}", e);
                }
            }
            Err(e) => {
                tracing::error!("Failed to record attestation: {}", e);
            }
        }
    }

    /// Send a collateral_lock request and track it for auto-recording the attestation response
    ///
    /// When the response arrives with an attestation, it will be automatically recorded
    /// on our ledger (specified by `our_reserves_id`).
    pub async fn send_collateral_lock_request(
        &self,
        target_ledger_id: &str,
        our_reserves_id: &str,
        deposit_secret: &bitcoin::secp256k1::SecretKey,
        amount_msats: u64,
        lock_blocks: u32,
    ) -> Result<String, Error> {
        let params = serde_json::json!({
            "deposit_secret": hex::encode(deposit_secret.secret_bytes()),
            "amount_msats": amount_msats,
            "lock_blocks": lock_blocks,
            "requesting_operator": hex::encode(self.node_id.serialize()),
        });

        // Send the request
        let request_id = self.nostr.send_ledger_request(target_ledger_id, "collateral_lock", params)
            .await
            .map_err(|e| Error::Protocol(format!("Failed to send collateral_lock request: {:?}", e)))?;

        // Track for auto-recording
        {
            let mut pending = self.pending_collateral_requests.lock().unwrap();
            pending.insert(request_id.clone(), our_reserves_id.to_string());
        }

        tracing::info!(
            "Sent collateral_lock request {} to ledger {}..., tracking for auto-record",
            &request_id[..16.min(request_id.len())],
            &target_ledger_id[..16.min(target_ledger_id.len())]
        );

        Ok(request_id)
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
