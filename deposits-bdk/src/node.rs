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

    /// Start listening for messages
    pub async fn start(&mut self) -> Result<(), Error> {
        self.nostr.start_listening().await?;
        tracing::info!("Node started, listening for messages");
        Ok(())
    }

    /// Run the main event loop
    pub async fn run(&mut self) -> Result<(), Error> {
        loop {
            tokio::select! {
                // Process inbound messages from nostr
                _ = self.nostr.process_events() => {
                    while let Some(inbound) = self.nostr.try_recv() {
                        self.handle_inbound(inbound);
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

                    // Drain and log events
                    let events = self.handler.drain_events();
                    for event in events {
                        tracing::info!("Protocol event: {:?}", event);
                    }
                }
            }
        }
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

    /// Open a new ledger with a partner
    ///
    /// This creates a ledger where we are the operator. The `enforcement_block`
    /// parameter controls when collateral size requirements are enforced:
    /// - 0: Immediate enforcement (joining an established network)
    /// - Future block: Bootstrap phase (allows cross-establishing collateral)
    pub fn open_ledger(
        &self,
        partner: PublicKey,
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

        // Get the ledger address (reserves address)
        let ledger_address = self.wallet.get_reserves_address()
            .map(|a| a.to_string())
            .unwrap_or_default();

        // Create the ledger state
        let enforcement = if enforcement_block > 0 {
            Some(enforcement_block)
        } else {
            None
        };

        let _ledger = Ledger::with_enforcement_block(
            self.node_id,
            partner,
            deposits_core::ledger::LedgerRole::Operator,
            Vec::new(), // No collateral partners initially
            ledger_address.clone(),
            enforcement,
        );

        // Store the ledger in the handler
        let ledger_arc = self.handler.get_or_create_ledger(self.node_id, partner);
        {
            let mut ledger_guard = ledger_arc.write().unwrap();
            // Update with our configuration
            ledger_guard.state.reserves = deposits_core::types::ReservesOutput {
                channel_id: [0u8; 32], // Not using channels in BDK
                spend_to: self.node_id,
                amount: reserves_balance,
            };
            ledger_guard.state.collateral_enforcement_block = enforcement;
        }

        // Persist the ledger after modification
        if let Err(e) = self.handler.persist_ledger(&self.node_id, &partner) {
            tracing::error!("Failed to persist ledger: {}", e);
        }

        // Add LedgerOpen operation to history
        {
            let operation = LedgerOperation::LedgerOpen {
                operator_id: self.node_id,
                reserves_id: partner,
                ledger_address: ledger_address.clone(),
                reserves_amount: reserves_balance,
                collateral_enforcement_block: enforcement_block,
            };

            let ledger_arc = self.handler.get_or_create_ledger(self.node_id, partner);
            let mut ledger_guard = ledger_arc.write().unwrap();
            ledger_guard.append_operation(operation, deposits_core::messages::consts::LEDGER_OPEN_REQUEST)
                .map_err(|e| Error::Protocol(format!("Failed to append LedgerOpen: {:?}", e)))?;
        }

        // Persist the ledger after adding history
        if let Err(e) = self.handler.persist_ledger(&self.node_id, &partner) {
            tracing::error!("Failed to persist ledger: {}", e);
        }

        // Create handshake message to send to partner (wire protocol)
        let handshake_msg = deposits_core::messages::HandshakeMsg {
            protocol_version: deposits_core::messages::PROTOCOL_VERSION,
            min_protocol_version: deposits_core::messages::PROTOCOL_VERSION,
            features: 0,
            operator_id: self.node_id,
            reserves_id: partner,
            ledger_address,
            funding_txid,
            funding_vout,
            reserves_amount: reserves_balance,
            collateral_enforcement_block: enforcement_block,
        };

        // Queue the handshake message to be sent via Nostr
        let _ = self.handler.queue_message(
            partner,
            deposits_core::messages::DepositsMessage::Handshake(handshake_msg),
        );

        // Return the ledger
        let ledger_arc = self.handler.get_or_create_ledger(self.node_id, partner);
        let ledger = ledger_arc.read().unwrap().clone();
        Ok(ledger)
    }

    /// List all ledgers
    pub fn list_ledgers(&self) -> HashMap<(PublicKey, PublicKey), Arc<RwLock<Ledger>>> {
        let ledgers = self.handler.ledgers.lock().unwrap();
        ledgers.clone()
    }

    // ========================================================================
    // Collateral Partner Management
    // ========================================================================

    /// Request a peer to be a collateral partner
    pub async fn request_partner(&self, peer: PublicKey) -> Result<(), Error> {
        // Create a coordination message for partnership request
        // For now, this is a simple handshake-like message
        let request_msg = deposits_core::messages::DepositsMessage::Handshake(
            deposits_core::messages::HandshakeMsg {
                protocol_version: deposits_core::messages::PROTOCOL_VERSION,
                min_protocol_version: deposits_core::messages::PROTOCOL_VERSION,
                features: 0x01, // Flag indicating partnership request
                operator_id: self.node_id,
                reserves_id: peer,
                ledger_address: String::new(), // Will be filled when ledger is established
                funding_txid: [0u8; 32],
                funding_vout: 0,
                reserves_amount: self.wallet.get_reserves_balance().unwrap_or(0),
                collateral_enforcement_block: 0,
            },
        );

        // Send via Nostr
        self.nostr.send_message(peer, request_msg).await?;

        Ok(())
    }

    /// List all collateral partners across all ledgers
    pub fn list_partners(&self) -> Vec<(PublicKey, String)> {
        let mut partners = Vec::new();
        let ledgers = self.handler.ledgers.lock().unwrap();

        for ((operator, partner), ledger_arc) in ledgers.iter() {
            let ledger = ledger_arc.read().unwrap();
            let role = if *operator == self.node_id {
                "Partner on our ledger"
            } else {
                "We are partner on their ledger"
            };

            // Add the partner/operator
            if *operator == self.node_id {
                partners.push((*partner, role.to_string()));
            } else {
                partners.push((*operator, role.to_string()));
            }

            // Add collateral partners
            for cp in &ledger.state.collateral_partners {
                partners.push((*cp, "Collateral partner".to_string()));
            }
        }

        // Deduplicate
        partners.sort_by(|a, b| a.0.to_string().cmp(&b.0.to_string()));
        partners.dedup_by(|a, b| a.0 == b.0);

        partners
    }

    // ========================================================================
    // Deposit Offer Management (On-Chain Funding)
    // ========================================================================

    /// Create a deposit offer for on-chain funding
    ///
    /// This creates a signed commitment from the operator to credit a deposit
    /// with funds sent to a specific address, up to a maximum amount, before
    /// a deadline block.
    pub fn create_deposit_offer(
        &self,
        partner: PublicKey,
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
            &partner,
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
            &partner,
            &deposit_pubkey,
            &funding_address_str,
            max_amount_sats,
            min_amount_sats,
            deadline_block,
        ).map_err(|e| Error::Protocol(format!("Failed to sign offer: {:?}", e)))?;

        // Create the offer
        let offer = DepositOffer {
            operator_id: self.node_id,
            reserves_id: partner,
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
    pub fn lock_withdrawal(
        &self,
        deposit_pubkey: PublicKey,
        destination_address: String,
        amount_sats: u64,
        fee_sats: u64,
        depositor_signature: [u8; 64],
        memo: Option<String>,
    ) -> Result<WithdrawalLockResult, Error> {
        let current_block = self.wallet.get_block_height()?;

        // Generate random nonce
        let nonce = Self::generate_nonce();

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
            destination_address,
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
            "Locked withdrawal {} for {} sats + {} fee to {}",
            hex::encode(&withdrawal_id[..8]),
            amount_sats,
            fee_sats,
            withdrawal.destination_address
        );

        Ok(WithdrawalLockResult {
            withdrawal: withdrawal.clone(),
            previous_balance_msats: 0, // Would need ledger access to get actual balance
            new_balance_msats: 0,
            locked_amount_msats: total_debit_msats,
        })
    }

    /// Complete a withdrawal by broadcasting the transaction
    ///
    /// This creates and broadcasts the on-chain transaction with the required
    /// OP_RETURN commitment, then marks the withdrawal as complete.
    pub fn complete_withdrawal(
        &self,
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
            "Completed withdrawal {}: txid={}",
            hex::encode(&withdrawal_id[..8]),
            txid
        );

        Ok(WithdrawalCompleteResult {
            withdrawal_id: *withdrawal_id,
            txid,
            amount_sats: withdrawal.amount_sats,
            fee_sats: withdrawal.fee_sats,
            final_balance_msats: 0, // Would need ledger access
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
    /// Creates a deposit for a given public key in the ledger with the partner.
    /// This applies a DepositOpen operation to the ledger.
    pub fn open_deposit(
        &self,
        partner: PublicKey,
        deposit_pubkey: PublicKey,
        fees: Option<FeeStructure>,
    ) -> Result<Deposit, Error> {
        let ledger_arc = self.handler.get_or_create_ledger(self.node_id, partner);

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

            ledger.append_operation(operation, deposits_core::messages::consts::DEPOSIT_OPEN)
                .map_err(|e| Error::Protocol(format!("Failed to open deposit: {:?}", e)))?;

            // Return the created deposit
            ledger.state.deposits.get(&deposit_pubkey)
                .cloned()
                .ok_or_else(|| Error::Protocol("Deposit not found after creation".to_string()))?
        };

        // Persist the ledger
        if let Err(e) = self.handler.persist_ledger(&self.node_id, &partner) {
            tracing::error!("Failed to persist ledger: {}", e);
        }

        tracing::info!(
            "Opened deposit {} in ledger with partner {}",
            deposit_pubkey,
            partner
        );

        Ok(deposit)
    }

    /// Credit a deposit with received funds
    ///
    /// This applies a PaymentCredit operation to add funds to a deposit.
    /// Used when on-chain funding is received for a deposit offer.
    pub fn credit_deposit(
        &self,
        partner: PublicKey,
        deposit_pubkey: PublicKey,
        amount_msats: u64,
        payment_hash: [u8; 32],
        invoice_id: String,
    ) -> Result<u64, Error> {
        let ledger_arc = self.handler.get_or_create_ledger(self.node_id, partner);

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

            // Apply the PaymentCredit operation with history tracking
            let operation = LedgerOperation::PaymentCredit {
                payment_hash,
                deposit_pubkey,
                amount: amount_msats,
                invoice_id,
                sequence_number,
            };

            ledger.append_operation(operation, deposits_core::messages::consts::RECEIVING_CREDIT_PAYMENT)
                .map_err(|e| Error::Protocol(format!("Failed to credit deposit: {:?}", e)))?;

            // Return the new balance
            ledger.state.deposits.get(&deposit_pubkey)
                .map(|d| d.balance)
                .unwrap_or(0)
        };

        // Persist the ledger
        if let Err(e) = self.handler.persist_ledger(&self.node_id, &partner) {
            tracing::error!("Failed to persist ledger: {}", e);
        }

        tracing::info!(
            "Credited deposit {} with {} msats, new balance: {} msats",
            deposit_pubkey,
            amount_msats,
            new_balance
        );

        Ok(new_balance)
    }

    /// Get a deposit by pubkey from a ledger
    pub fn get_deposit(
        &self,
        partner: PublicKey,
        deposit_pubkey: PublicKey,
    ) -> Option<Deposit> {
        let ledgers = self.handler.ledgers.lock().unwrap();
        if let Some(ledger_arc) = ledgers.get(&(self.node_id, partner)) {
            let ledger = ledger_arc.read().unwrap();
            return ledger.state.deposits.get(&deposit_pubkey).cloned();
        }
        None
    }

    /// List all deposits in a ledger
    pub fn list_deposits(&self, partner: PublicKey) -> Vec<(PublicKey, Deposit)> {
        let ledgers = self.handler.ledgers.lock().unwrap();
        if let Some(ledger_arc) = ledgers.get(&(self.node_id, partner)) {
            let ledger = ledger_arc.read().unwrap();
            return ledger.state.deposits.iter()
                .map(|(k, v)| (*k, v.clone()))
                .collect();
        }
        Vec::new()
    }

    /// Transfer funds between two deposits (internal transfer)
    ///
    /// Locks funds from source deposit and fulfills transfer to destination deposit.
    /// Both deposits must be in the same ledger.
    pub fn transfer_between_deposits(
        &self,
        partner: PublicKey,
        source_pubkey: PublicKey,
        dest_pubkey: PublicKey,
        amount_msats: u64,
    ) -> Result<([u8; 32], u64, u64), Error> {
        let ledger_arc = self.handler.get_or_create_ledger(self.node_id, partner);

        // Generate a unique transfer ID
        let transfer_id = Self::generate_nonce();

        let (source_balance, dest_balance) = {
            let mut ledger = ledger_arc.write().unwrap();

            // Check both deposits exist
            if !ledger.state.deposits.contains_key(&source_pubkey) {
                return Err(Error::Protocol(format!(
                    "Source deposit not found: {}",
                    source_pubkey
                )));
            }
            if !ledger.state.deposits.contains_key(&dest_pubkey) {
                return Err(Error::Protocol(format!(
                    "Destination deposit not found: {}",
                    dest_pubkey
                )));
            }

            // Check source has sufficient balance
            let source_balance = ledger.state.deposits.get(&source_pubkey)
                .map(|d| d.balance)
                .unwrap_or(0);
            if source_balance < amount_msats {
                return Err(Error::Protocol(format!(
                    "Insufficient balance: {} msats available, {} msats requested",
                    source_balance, amount_msats
                )));
            }

            // Lock funds from source (with history tracking)
            let lock_op = LedgerOperation::TransferLock {
                pubkey: source_pubkey,
                amount: amount_msats,
                transfer_id,
            };
            ledger.append_operation(lock_op, deposits_core::messages::consts::DEPOSIT_LOCK_TRANSFER)
                .map_err(|e| Error::Protocol(format!("Failed to lock transfer: {:?}", e)))?;

            // Fulfill transfer to destination (with history tracking)
            let fulfill_op = LedgerOperation::TransferFulfill {
                pubkey: dest_pubkey,
                amount: amount_msats,
                transfer_id,
            };
            ledger.append_operation(fulfill_op, deposits_core::messages::consts::DEPOSIT_FULFILL_TRANSFER)
                .map_err(|e| Error::Protocol(format!("Failed to fulfill transfer: {:?}", e)))?;

            // Get updated balances
            let new_source = ledger.state.deposits.get(&source_pubkey)
                .map(|d| d.balance)
                .unwrap_or(0);
            let new_dest = ledger.state.deposits.get(&dest_pubkey)
                .map(|d| d.balance)
                .unwrap_or(0);

            (new_source, new_dest)
        };

        // Persist the ledger
        if let Err(e) = self.handler.persist_ledger(&self.node_id, &partner) {
            tracing::error!("Failed to persist ledger: {}", e);
        }

        tracing::info!(
            "Transferred {} msats from {} to {}: new balances {} / {}",
            amount_msats,
            source_pubkey,
            dest_pubkey,
            source_balance,
            dest_balance
        );

        Ok((transfer_id, source_balance, dest_balance))
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
        let payment_hash = *offer_id; // Use offer_id as payment hash
        let invoice_id = format!("deposit_offer:{}", hex::encode(&offer_id[..8]));

        let new_balance = self.credit_deposit(
            offer.reserves_id,
            offer.deposit_pubkey,
            amount_msats,
            payment_hash,
            invoice_id,
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
        if let Some(ledger_arc) = ledgers.get(&(self.node_id, partner)) {
            let ledger = ledger_arc.read().unwrap();
            return Some(ledger.history.clone());
        }
        None
    }

    /// Get a specific ledger
    pub fn get_ledger(&self, partner: PublicKey) -> Option<Ledger> {
        let ledgers = self.handler.ledgers.lock().unwrap();
        if let Some(ledger_arc) = ledgers.get(&(self.node_id, partner)) {
            let ledger = ledger_arc.read().unwrap();
            return Some(ledger.clone());
        }
        None
    }

    /// Get the primary ledger (first ledger where we are operator)
    pub fn get_primary_ledger(&self) -> Option<(PublicKey, Ledger)> {
        let ledgers = self.handler.ledgers.lock().unwrap();
        for ((operator, reserves_id), ledger_arc) in ledgers.iter() {
            if *operator == self.node_id {
                let ledger = ledger_arc.read().unwrap();
                return Some((*reserves_id, ledger.clone()));
            }
        }
        None
    }
}
