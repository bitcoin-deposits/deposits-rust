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
    Deposit, DepositId, DepositOffer, DepositOfferStatus, DescriptorWitness, FeeStructure,
    OnChainWithdrawal, OnChainWithdrawalStatus,
    WithdrawalLockResult, WithdrawalCompleteResult, compute_deposit_id,
};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use tokio::sync::mpsc;

use crate::handler::{DepositsHandler, OutboundMessage};
use crate::lightning::LightningClient;
use crate::metrics;
use crate::nostr::{InboundMessage, NostrTransport};
use crate::wallet::Wallet;
use crate::Error;

/// Maximum number of quorum members a node will accept on its ledger.
/// Beyond this limit, add_quorum_member requests will be rejected.
pub const MAX_QUORUM_MEMBERS: usize = 8;

/// Maximum number of quorums a node will join (QuorumJoin operations).
/// Beyond this limit, quorum join requests will be rejected.
pub const MAX_QUORUMS_JOINED: usize = 12;

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

    /// Operator name for advertisements (optional)
    pub operator_name: Option<String>,

    /// Use fast polling intervals (for regtest/testing)
    /// When enabled: periodic=5s, poll=5s, reload=2s
    /// When disabled: periodic=60s, poll=30s, reload=5s
    pub fast_poll: bool,
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

/// Result of a co-sign request from a quorum member
#[derive(Debug, Clone)]
pub struct CoSignResult {
    /// The partner's ECDSA signature over (partner_signing_data || member_ledger_hash)
    pub partner_signature: [u8; 64],

    /// The public key of the quorum member who co-signed
    pub cosigner_pubkey: PublicKey,

    /// The current hash of the quorum member's own ledger at time of signing
    /// This binds the co-signature to the member's ledger state
    pub member_ledger_hash: [u8; 32],
}

/// Result of a deposit offer co-sign request from a quorum member
#[derive(Debug, Clone)]
pub struct OfferCoSignResult {
    /// The ECDSA signature over the offer signing data
    pub signature: [u8; 64],

    /// The public key of the quorum member who co-signed
    pub cosigner_pubkey: PublicKey,

    /// The current hash of the quorum member's own ledger at time of signing
    /// This binds the co-signature to the member's ledger state
    pub member_ledger_hash: [u8; 32],
}

/// A pending Lightning invoice waiting for payment
#[derive(Debug, Clone)]
pub struct PendingInvoice {
    /// The ledger this invoice belongs to
    pub ledger_id: String,
    /// The deposit_id to credit
    pub deposit_id: DepositId,
    /// The descriptor for this deposit
    pub descriptor: String,
    /// Amount in millisatoshis
    pub amount_msat: u64,
    /// The bolt11 invoice string
    pub invoice: String,
    /// When the invoice was created
    pub created_at: u64,
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

    /// Pending co-sign requests: request_id -> (ledger_id, oneshot sender for co-sign result)
    /// The result includes the partner signature and the member's ledger hash
    pending_cosign_requests: Arc<Mutex<HashMap<String, (String, tokio::sync::oneshot::Sender<CoSignResult>)>>>,

    /// Pending Lightning invoices: payment_hash -> (ledger_id, deposit_pubkey, amount_msat)
    /// Used to credit deposits when payments are received
    pending_invoices: Arc<Mutex<HashMap<[u8; 32], PendingInvoice>>>,

    /// Processed request event IDs (to avoid duplicate processing from polling)
    processed_requests: Mutex<std::collections::HashSet<String>>,

    /// Event IDs of requests sent by THIS daemon process.
    /// Used to filter out our own requests (Nostr broadcasts to all subscribers).
    sent_events: Mutex<std::collections::HashSet<String>>,

    /// Data directory for persistence
    data_dir: PathBuf,

    /// Primary relay URL for Nostr
    relay_url: String,

    /// Use fast polling intervals (for regtest/testing)
    fast_poll: bool,

    /// Cached joined ledger IDs (from QuorumJoin history scan).
    /// Populated on first access, invalidated when new ledgers are discovered.
    joined_ledger_cache: Mutex<Option<Vec<String>>>,
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
        let enable_metrics_emitter = std::env::var("DEPOSITS_ENABLE_METRICS_EMITTER").as_deref() == Ok("1");
        let (handler, outbound_rx) = DepositsHandler::new(
            secret_key,
            wallet.clone(),
            handler_data_dir,
            enable_metrics_emitter,
        );

        // Start periodic deposit metrics emitter if enabled
        let handler_arc = Arc::new(handler);
        handler_arc.start_metrics_emitter();

        // Load existing deposit offers from disk
        let deposit_offers = Self::load_deposit_offers(&config.data_dir)?;

        // Load existing withdrawals from disk
        let withdrawals = Self::load_withdrawals(&config.data_dir)?;

        // Set response filter for relay-side #l tag filtering (reduces fan-out ~75%)
        // Collect owned ledger IDs from already-loaded handler ledgers
        {
            let ledgers = handler_arc.ledgers.lock().unwrap();
            let owned_ids: Vec<String> = ledgers.iter()
                .filter(|(_, larc)| larc.read().unwrap().operator_key() == node_id)
                .map(|(_, larc)| larc.read().unwrap().ledger_id_hex())
                .collect();
            if !owned_ids.is_empty() {
                nostr.set_response_ledger_filter(owned_ids);
            }
        }

        // Subscribe to responses early (needed for co-sign response handling in CLI commands)
        // CLI commands don't call start(), so we need this here
        if let Err(e) = nostr.subscribe_to_response("").await {
            tracing::warn!("Failed to subscribe to responses during init: {}", e);
        }

        tracing::info!("Node created with ID: {}", node_id);

        Ok(Self {
            node_id,
            wallet,
            nostr,
            lightning,
            handler: handler_arc,
            outbound_rx,
            deposit_offers: Mutex::new(deposit_offers),
            withdrawals: Mutex::new(withdrawals),
            pending_collateral_requests: Mutex::new(HashMap::new()),
            pending_cosign_requests: Arc::new(Mutex::new(HashMap::new())),
            pending_invoices: Arc::new(Mutex::new(HashMap::new())),
            processed_requests: Mutex::new(std::collections::HashSet::new()),
            sent_events: Mutex::new(std::collections::HashSet::new()),
            data_dir: config.data_dir,
            relay_url,
            fast_poll: config.fast_poll,
            joined_ledger_cache: Mutex::new(None),
        })
    }

    /// Sync the wallet with the blockchain
    pub fn sync_wallet(&self) -> Result<(), Error> {
        self.wallet.sync()
    }

    /// Sign the last update in a ledger with our operator key
    ///
    /// Call this after appending an operation to sign the update before broadcasting.
    pub fn sign_last_update(&self, ledger_id: &str) -> Result<(), Error> {
        use bitcoin::secp256k1::{Secp256k1, Message};
        use bitcoin::hashes::{Hash, sha256};

        // Get the ledger by ledger_id
        let ledger_arc = self.handler.ledgers.lock().unwrap()
            .get(ledger_id)
            .cloned()
            .ok_or_else(|| Error::Protocol(format!("Ledger not found: {}", ledger_id)))?;

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
            tracing::debug!("Signed update seq={} for ledger {}", update.sequence_number, &ledger_id[..16.min(ledger_id.len())]);
        }

        Ok(())
    }

    /// Validate that the last in-memory update chains correctly from what's on disk.
    ///
    /// Call this after signing but before persisting + broadcasting. If the in-memory
    /// chain doesn't extend the disk state correctly (e.g., another process wrote a
    /// conflicting entry), returns an error to trigger rollback and retry.
    fn validate_chain_before_persist(&self, ledger_id: &str) -> Result<(), Error> {
        // The daemon is the sole writer — validate in-memory chain consistency
        // instead of re-reading the entire JSONL from disk.
        let ledgers = self.handler.ledgers.lock().unwrap();
        let ledger_arc = ledgers.get(ledger_id)
            .ok_or_else(|| Error::Protocol(format!("Ledger not found: {}", ledger_id)))?;
        let ledger = ledger_arc.read().unwrap();

        let len = ledger.history.len();
        if len < 2 {
            return Ok(());
        }

        // Check that the last entry chains from its predecessor
        let prev = &ledger.history[len - 2];
        let last = &ledger.history[len - 1];

        if last.sequence_number != prev.sequence_number + 1 {
            return Err(Error::Protocol(format!(
                "Sequence gap before persist: prev_seq={}, last_seq={}",
                prev.sequence_number, last.sequence_number,
            )));
        }

        if last.previous_hash != prev.current_hash {
            return Err(Error::Protocol(format!(
                "Hash chain break before persist: seq={} prev_hash={}... but seq={} hash={}...",
                last.sequence_number,
                hex::encode(&last.previous_hash[..8]),
                prev.sequence_number,
                hex::encode(&prev.current_hash[..8]),
            )));
        }

        Ok(())
    }

    /// Sign with operator-only signature, validate chain, persist, and broadcast.
    ///
    /// Convenience method for paths where no co-signing is needed (no quorum members).
    /// Performs the full validate → persist → broadcast sequence.
    async fn operator_sign_persist_broadcast(&self, ledger_id: &str) -> Result<String, Error> {
        self.sign_last_update(ledger_id)?;
        self.validate_chain_before_persist(ledger_id)?;
        if let Err(e) = self.handler.persist_ledger_to_disk(ledger_id) {
            tracing::warn!("Failed to persist ledger: {}", e);
        }
        self.broadcast_last_update(ledger_id).await
    }

    /// Broadcast the most recent ledger update to Nostr
    ///
    /// Call this after appending an operation to a ledger to ensure the update
    /// is published to the Nostr relay for other participants to see.
    pub async fn broadcast_last_update(&self, ledger_id: &str) -> Result<String, Error> {
        // Get the ledger by ledger_id
        let ledger_arc = self.handler.ledgers.lock().unwrap()
            .get(ledger_id)
            .cloned()
            .ok_or_else(|| Error::Protocol(format!("Ledger not found: {}", ledger_id)))?;

        let ledger = ledger_arc.read().unwrap();

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
    pub async fn broadcast_all_updates(&self, ledger_id: &str) -> Result<usize, Error> {
        // Get the ledger by ledger_id
        let ledger_arc = self.handler.ledgers.lock().unwrap()
            .get(ledger_id)
            .cloned()
            .ok_or_else(|| Error::Protocol(format!("Ledger not found: {}", ledger_id)))?;

        let ledger = ledger_arc.read().unwrap();

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
        // Collect all ledger IDs we care about (owned + joined)
        let mut ledger_ids: Vec<String> = Vec::new();

        let ledgers = self.handler.ledgers.lock().unwrap().clone();
        for (_ledger_id_key, ledger_arc) in ledgers.iter() {
            let ledger = ledger_arc.read().unwrap();
            if ledger.operator_key() == self.node_id {
                ledger_ids.push(ledger.ledger_id_hex());
            }
        }

        // Add joined ledgers
        ledger_ids.extend(self.get_joined_ledger_ids());

        // Subscribe to requests and disputes for all ledgers in one batched call
        if !ledger_ids.is_empty() {
            if let Err(e) = self.nostr.subscribe_to_ledgers_batch(&ledger_ids).await {
                tracing::warn!("Failed to subscribe to ledgers: {}", e);
            } else {
                tracing::info!("Subscribed to {} ledgers (requests + disputes)", ledger_ids.len());
            }
        }

        // Set up per-ledger filters for polling and response subscriptions
        if !ledger_ids.is_empty() {
            // Request poll filter uses all ledger IDs (owned + joined)
            self.nostr.set_request_ledger_filter(ledger_ids.clone());

            // Response filter uses only owned ledger IDs
            let owned_ids: Vec<String> = {
                let ledgers = self.handler.ledgers.lock().unwrap();
                ledgers.iter()
                    .filter(|(_, larc)| larc.read().unwrap().operator_key() == self.node_id)
                    .map(|(_, larc)| larc.read().unwrap().ledger_id_hex())
                    .collect()
            };
            if !owned_ids.is_empty() {
                self.nostr.clear_response_subscription();
                self.nostr.set_response_ledger_filter(owned_ids);
            }
        }
        if let Err(e) = self.nostr.subscribe_to_response("").await {
            tracing::warn!("Failed to subscribe to responses: {}", e);
        }

        tracing::info!("Node started, listening for messages");
        Ok(())
    }

    /// Subscribe to requests and disputes for a specific ledger
    /// Call this after opening a new ledger to start watching it
    pub async fn subscribe_to_ledger(&self, ledger_id: &str) -> Result<(), Error> {
        // Use batch subscribe for a single ledger (handles dedup internally)
        if let Err(e) = self.nostr.subscribe_to_ledgers_batch(&[ledger_id.to_string()]).await {
            tracing::warn!("Failed to subscribe to ledger {}: {}", &ledger_id[..16.min(ledger_id.len())], e);
        }

        Ok(())
    }

    /// Get ledger IDs of ledgers we've joined as a quorum member
    fn get_joined_ledger_ids(&self) -> Vec<String> {
        // Check cache first
        {
            let cache = self.joined_ledger_cache.lock().unwrap();
            if let Some(ref cached) = *cache {
                return cached.clone();
            }
        }

        // Cache miss — do the full scan
        let t0 = std::time::Instant::now();
        let mut joined = Vec::new();
        let ledgers = self.handler.ledgers.lock().unwrap();

        for (_ledger_id, ledger_arc) in ledgers.iter() {
            let ledger = ledger_arc.read().unwrap();
            if ledger.operator_key() == self.node_id {
                let history_len = ledger.history.len();
                for update in &ledger.history {
                    if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                        if let LedgerOperation::QuorumJoin { ledger_id, .. } = op {
                            if !joined.contains(&ledger_id) {
                                joined.push(ledger_id);
                            }
                        }
                    }
                }
                let elapsed = t0.elapsed();
                if elapsed.as_millis() > 1 {
                    tracing::info!("[PROFILE] get_joined_ledger_ids: scanned {} history entries in {:?} (cache miss)", history_len, elapsed);
                }
            }
        }
        drop(ledgers);

        // Store in cache
        let mut cache = self.joined_ledger_cache.lock().unwrap();
        *cache = Some(joined.clone());

        joined
    }

    /// Invalidate the joined ledger cache (call after discovering new ledgers)
    fn invalidate_joined_ledger_cache(&self) {
        let mut cache = self.joined_ledger_cache.lock().unwrap();
        *cache = None;
    }

    /// Run the main event loop
    pub async fn run(&mut self) -> Result<(), Error> {
        // Track last ledger reload time
        let mut last_reload = tokio::time::Instant::now();
        let reload_interval = if self.fast_poll {
            tokio::time::Duration::from_secs(2)
        } else {
            tokio::time::Duration::from_secs(5)
        };

        // Track last request poll time (fallback for missed subscription events)
        let mut last_poll = tokio::time::Instant::now();
        let poll_interval = if self.fast_poll {
            tokio::time::Duration::from_secs(5)  // Safety net only — subscriptions handle real-time delivery
        } else {
            tokio::time::Duration::from_secs(30)
        };

        // Track last periodic tasks time (wallet sync, auto-complete deposits, etc.)
        let mut last_periodic = tokio::time::Instant::now();
        let periodic_interval = if self.fast_poll {
            tokio::time::Duration::from_secs(5)
        } else {
            tokio::time::Duration::from_secs(60)
        };

        if self.fast_poll {
            tracing::info!("Fast poll mode enabled: periodic=5s, poll=5s, reload=2s");
        }

        loop {
            // Periodic tasks (every 60 seconds) - moved outside select! to avoid reset on each iteration
            if last_periodic.elapsed() >= periodic_interval {
                // Sync wallet periodically
                if let Err(e) = self.sync_wallet() {
                    tracing::warn!("Wallet sync failed: {}", e);
                }

                // Auto-complete funded deposits
                self.auto_complete_deposits().await;

                // Auto-credit received Lightning payments
                self.auto_credit_received_payments().await;

                // Auto-complete locked withdrawals (broadcast TXs)
                self.auto_complete_withdrawals().await;

                // Auto-collect fees from deposits when due
                self.auto_collect_fees().await;

                // Auto-timeout expired transfers
                self.auto_timeout_transfers().await;

                // Auto-expire old deposit offers
                if let Ok(expired) = self.check_expired_offers() {
                    if !expired.is_empty() {
                        tracing::info!("Expired {} deposit offers", expired.len());
                    }
                }

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

                last_periodic = tokio::time::Instant::now();
            }

            // Discover new/updated ledger files and refresh quorum membership cache
            if last_reload.elapsed() >= reload_interval {
                self.invalidate_joined_ledger_cache();
                let discovered = self.handler.discover_new_ledgers();

                // Collect all ledger IDs (owned + joined) for subscriptions and poll filter
                let mut all_ledger_ids = self.get_joined_ledger_ids();
                let mut owned_ids = Vec::new();
                {
                    let ledgers = self.handler.ledgers.lock().unwrap();
                    for (ledger_id, ledger_arc) in ledgers.iter() {
                        let ledger = ledger_arc.read().unwrap();
                        if ledger.operator_key() == self.node_id {
                            all_ledger_ids.push(ledger_id.clone());
                            owned_ids.push(ledger.ledger_id_hex());
                        }
                        metrics::set_ledger_history_length(ledger_id, ledger.history.len());
                    }
                }

                // Update poll filter (always, since joined ledgers change without new files)
                self.nostr.set_request_ledger_filter(all_ledger_ids.clone());

                if discovered > 0 {
                    // Subscribe to new ledgers' requests
                    for ledger_id in &all_ledger_ids {
                        if let Err(e) = self.nostr.subscribe_to_requests(ledger_id).await {
                            tracing::debug!("Subscribe to ledger {} failed: {}", &ledger_id[..16.min(ledger_id.len())], e);
                        }
                    }
                    // Refresh response subscription filter (owned ledgers only)
                    if !owned_ids.is_empty() {
                        self.nostr.clear_response_subscription();
                        self.nostr.set_response_ledger_filter(owned_ids);
                        if let Err(e) = self.nostr.subscribe_to_response("").await {
                            tracing::warn!("Failed to resubscribe to responses: {}", e);
                        }
                    }
                }

                last_reload = tokio::time::Instant::now();
            }

            // Poll for recent requests — safety net for missed subscription events
            if last_poll.elapsed() >= poll_interval {
                if let Ok(requests) = self.nostr.fetch_recent_requests(7).await {
                    for request in requests {
                        // Check if already processed
                        let already_processed = {
                            let processed = self.processed_requests.lock().unwrap();
                            processed.contains(&request.event_id)
                        };
                        if !already_processed {
                            tracing::debug!("Request via polling: action={}, event={}...",
                                request.action, &request.event_id[..16.min(request.event_id.len())]);
                            // Mark as processed before handling
                            self.processed_requests.lock().unwrap().insert(request.event_id.clone());
                            self.handle_ledger_request(request).await;
                        }
                    }
                }
                last_poll = tokio::time::Instant::now();
            }

            // Process subscription notifications - this has a 100ms internal timeout
            // so periodic tasks will still run frequently even if no notifications arrive
            let _ = self.nostr.process_events().await;

            // Handle P2P messages
            while let Some(inbound) = self.nostr.try_recv() {
                self.handle_inbound(inbound);
            }

            // Handle ledger requests from subscription
            while let Some(request) = self.nostr.try_recv_request() {
                // Check if already processed (from polling)
                let already_processed = {
                    let processed = self.processed_requests.lock().unwrap();
                    processed.contains(&request.event_id)
                };
                if !already_processed {
                    tracing::debug!("Request via subscription: action={}, event={}...",
                        request.action, &request.event_id[..16.min(request.event_id.len())]);
                    self.processed_requests.lock().unwrap().insert(request.event_id.clone());
                    self.handle_ledger_request(request).await;
                }
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

            // Check for outbound messages (non-blocking)
            while let Ok(outbound) = self.outbound_rx.try_recv() {
                if let Err(e) = self.nostr.send_message(outbound.peer, outbound.message).await {
                    tracing::error!("Failed to send message: {}", e);
                }
            }
        }
    }

    /// Handle a ledger request from Nostr
    async fn handle_ledger_request(&mut self, request: crate::nostr::LedgerRequest) {
        // Skip requests that THIS daemon process sent (Nostr broadcasts to all subscribers).
        // We track sent event IDs rather than filtering by pubkey, because CLI commands
        // use the same operator key and we want the daemon to process those.
        if self.sent_events.lock().unwrap().contains(&request.event_id) {
            tracing::debug!("Skipping our own request: {}", &request.event_id[..16.min(request.event_id.len())]);
            return;
        }

        // Check if this request is for a ledger we own or have joined
        let is_our_ledger = self.get_ledger_by_ledger_id(&request.ledger_id).is_some()
            || self.get_ledger_by_reserves_key(&request.ledger_id).is_some();
        let is_cross_ledger_sign = request.action == "custody_transfer_sign"
            || request.action == "confiscation_sign";
        // cosign requests can come from ledgers where we're a quorum member
        // (we may not have the full ledger locally, just a QuorumJoin record)
        let is_cosign_request = request.action == "cosign_update"
            || request.action == "cosign_offer";

        // Silently drop operator-only actions if we're not the operator
        // (these are broadcast but only the operator should respond)
        let operator_only_actions = ["deposit_open", "make_offer", "withdraw", "collateral_lock", "offer_status", "balance_query", "make_invoice", "pay_invoice", "transfer_lock", "transfer_complete", "bump"];
        if operator_only_actions.contains(&request.action.as_str()) && !self.is_operator_of_ledger(&request.ledger_id) {
            return; // Silent drop - the actual operator will respond
        }

        if !is_our_ledger && !is_cross_ledger_sign && !is_cosign_request {
            return; // Silent drop - not our concern
        }

        tracing::info!(
            "Ledger request: action={}, ledger={}..., event={}...",
            request.action,
            &request.ledger_id[..16.min(request.ledger_id.len())],
            &request.event_id[..16.min(request.event_id.len())]
        );

        // Record request received metric
        crate::metrics::record_request_received(&request.action);

        // Start timing request processing
        let start_time = std::time::Instant::now();

        // Process the request based on action
        let (success, result, error) = match request.action.as_str() {
            "deposit_open" => self.process_deposit_open_request(&request).await,
            "make_offer" => self.process_make_offer_request(&request).await,
            "withdraw" => self.process_withdraw_request(&request).await,
            "transfer_lock" => self.process_transfer_lock_request(&request).await,
            "transfer_complete" => self.process_transfer_complete_request(&request).await,
            "collateral_lock" => self.process_collateral_lock_request(&request).await,
            "custody_transfer_sign" => self.process_custody_transfer_sign_request(&request).await,
            "confiscation_sign" => self.process_confiscation_sign_request(&request).await,
            "custodian_query" => self.process_custodian_query_request(&request).await,
            "lottery_reveal" => {
                // When we see another participant's reveal, auto-reveal ours
                self.auto_reveal_preimage(&request.ledger_id).await;
                (true, None, None) // No response needed
            }
            "cosign_update" => {
                // Silently ignore if we're not a quorum member for this ledger
                // (co-sign requests are broadcast, only quorum members should respond)
                if !self.is_quorum_member_of_ledger(&request.ledger_id) {
                    tracing::debug!("Ignoring cosign_update for {} - not a quorum member",
                        &request.ledger_id[..16.min(request.ledger_id.len())]);
                    return;
                }

                self.process_cosign_request(&request).await
            }
            "cosign_offer" => {
                // Silently ignore if we're not a quorum member for this ledger
                if !self.is_quorum_member_of_ledger(&request.ledger_id) {
                    tracing::debug!("Ignoring cosign_offer for {} - not a quorum member",
                        &request.ledger_id[..16.min(request.ledger_id.len())]);
                    return;
                }

                self.process_cosign_offer_request(&request).await
            }
            "offer_status" => self.process_offer_status_request(&request).await,
            "balance_query" => self.process_balance_query_request(&request).await,
            "make_invoice" => self.process_make_invoice_request(&request).await,
            "pay_invoice" => self.process_pay_invoice_request(&request).await,
            "bump" => {
                tracing::info!("Bump requested - syncing wallet and checking deposits...");
                if let Err(e) = self.sync_wallet() {
                    (false, None, Some(format!("Wallet sync failed: {}", e)))
                } else {
                    self.auto_complete_deposits().await;
                    (true, Some(serde_json::json!({"message": "Wallet synced and deposits checked"}).to_string()), None)
                }
            }
            _ => {
                tracing::warn!("Unknown request action: {}", request.action);
                (false, None, Some(format!("Unknown action: {}", request.action)))
            }
        };

        // Record request processing time
        let processing_time = start_time.elapsed();
        if processing_time.as_millis() > 1 {
            tracing::info!("[PROFILE] handle_ledger_request action={} took {:?} (success={})",
                request.action, processing_time, success);
        }
        crate::metrics::record_request_processing(&request.action, success, processing_time);
        crate::metrics::record_response_sent(&request.action, success);

        // Send response - parse result String as JSON Value
        let result_json = result.and_then(|s| serde_json::from_str(&s).ok());
        if let Err(e) = self.nostr.send_ledger_response(
            &request.event_id,
            &request.ledger_id,
            &request.action,
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

        // Find the ledger by ledger_id
        let ledger_arc = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            ledgers.get(&inbound.ledger_id).cloned()
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
        let t0 = std::time::Instant::now();
        // Check if we have this ledger and are the operator
        let ledgers = self.handler.ledgers.lock().unwrap();
        if let Some(ledger_arc) = ledgers.get(ledger_id) {
            let ledger = ledger_arc.read().unwrap();
            if ledger.operator_key() == self.node_id {
                return true;
            }
        }
        drop(ledgers);

        // Check our joined ledgers (QuorumJoin records in our ledger history)
        let joined = self.get_joined_ledger_ids();
        for jid in joined {
            if jid == ledger_id {
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

        // Find our ledger_id (our ledger where we'll record the dispute/arm)
        let our_ledger_id = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let mut found = None;
            for (ledger_id, arc) in ledgers.iter() {
                let ledger = arc.read().unwrap();
                if ledger.operator_key() == self.node_id {
                    found = Some(ledger_id.clone());
                    break;
                }
            }
            found.ok_or_else(|| Error::Protocol("No ledger found for our operator".to_string()))?
        };

        // Get our ledger's current state
        let ledger_arc = self.handler.ledgers.lock().unwrap()
            .get(&our_ledger_id)
            .cloned()
            .ok_or_else(|| Error::Protocol("Ledger not found".to_string()))?;
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
        self.sign_last_update(&our_ledger_id)?;

        // 2. Copy our existing attestations from our own ledger history
        // These are attestations we received (proving we have collateral backing)
        {
            let ledger = ledger_arc.read().unwrap();

            // Find all CollateralAttestation operations in our history
            let mut attestations_to_copy: Vec<LedgerOperation> = Vec::new();
            // Track quorum members with their collateral ledger IDs
            let mut quorum_members_to_add: Vec<(bitcoin::secp256k1::PublicKey, String)> = Vec::new();

            for update in ledger.history.iter() {
                if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                    match &op {
                        LedgerOperation::CollateralAttestation { collateral_operator, quorum_member, collateral_ledger_id, .. } => {
                            // We want attestations where WE are the quorum_member
                            // (proving we locked collateral on other operators' ledgers)
                            if quorum_member == &our_pubkey {
                                attestations_to_copy.push(op.clone());
                                // Also need to add the collateral_operator as a quorum member with their ledger ID
                                if !quorum_members_to_add.iter().any(|(pk, _)| pk == collateral_operator) {
                                    quorum_members_to_add.push((*collateral_operator, collateral_ledger_id.clone()));
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }

            drop(ledger);

            // First add quorum members, then attestations
            for (member, member_ledger_id) in quorum_members_to_add {
                let mut ledger = ledger_arc.write().unwrap();

                // Check if already added
                if ledger.state.quorum_members.iter().any(|m| m.pubkey == member) {
                    continue;
                }

                // Create QuorumAddMember operation
                // Note: The signature should come from the member, but for auto-arm
                // we use a placeholder since the member will broadcast their own version
                let add_op = LedgerOperation::QuorumAddMember {
                    quorum_member: member,
                    quorum_member_signature: [0u8; 64], // Placeholder
                    member_ledger_id: member_ledger_id.clone(),
                };

                if let Err(e) = ledger.append_operation_with_block(
                    add_op,
                    deposits_core::messages::consts::QUORUM_ADD_MEMBER,
                    current_block,
                    block_hash,
                ) {
                    tracing::warn!("Failed to add quorum member: {:?}", e);
                } else {
                    tracing::info!("Added quorum member: {}... (ledger: {}...)", &hex::encode(member.serialize())[..16], &member_ledger_id[..16.min(member_ledger_id.len())]);
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
            self.sign_last_update(&our_ledger_id)?;
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
        self.sign_last_update(&our_ledger_id)?;

        // Persist
        if let Err(e) = self.handler.persist_ledger_to_disk(&our_ledger_id) {
            tracing::error!("Failed to persist ledger: {}", e);
        }

        // Broadcast all updates
        if let Err(e) = self.broadcast_all_updates(&our_ledger_id).await {
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
                self.track_sent_event(&request_id);
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
                for (lid, _arc) in ledgers.iter() {
                    if lid.starts_with(ledger_prefix) {
                        found = Some(lid.clone());
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
        use nostr_sdk::{Filter, Kind, TagKind};
        use nostr_sdk::prelude::{SingleLetterTag, Alphabet};

        let our_pubkey = keypair.public_key();

        // Use the existing nostr client
        let client = self.nostr.client();

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
            cosigner_pubkey: None,
            member_ledger_hash: None,
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
            cosigner_pubkey: None,
            member_ledger_hash: None,
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
                for (lid, _arc) in ledgers.iter() {
                    if lid.starts_with(ledger_prefix) {
                        found = Some(lid.clone());
                        break;
                    }
                }
                match found {
                    Some(id) => id,
                    None => continue,
                }
            };

            // Use the existing nostr client
            let client = self.nostr.client();

            let filter = Filter::new()
                .kind(Kind::Custom(crate::nostr::KIND_LEDGER_UPDATE))
                .custom_tag(SingleLetterTag::lowercase(Alphabet::D), [ledger_id.as_str()])
                .limit(500);

            let events = match client.fetch_events(vec![filter], Some(std::time::Duration::from_secs(10))).await {
                Ok(e) => e,
                Err(_) => continue,
            };

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
                self.track_sent_event(&request_id);

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
                for (lid, _arc) in ledgers.iter() {
                    if lid.starts_with(ledger_prefix) {
                        found = Some(lid.clone());
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
        use nostr_sdk::{Filter, Kind};
        use nostr_sdk::prelude::{SingleLetterTag, Alphabet};

        // Use the existing nostr client
        let client = self.nostr.client();

        let filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_UPDATE))
            .custom_tag(SingleLetterTag::lowercase(Alphabet::D), [ledger_id])
            .limit(500);

        let events = client
            .fetch_events(vec![filter], None)
            .await
            .map_err(|e| Error::Protocol(format!("Failed to fetch: {}", e)))?;

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
                for (lid, _arc) in ledgers.iter() {
                    if lid.starts_with(ledger_prefix) {
                        found = Some(lid.clone());
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

        // Use the existing nostr client
        let client = self.nostr.client();

        let filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_UPDATE))
            .custom_tag(SingleLetterTag::lowercase(Alphabet::D), [ledger_id])
            .limit(500);

        let events = client
            .fetch_events(vec![filter], None)
            .await
            .map_err(|e| Error::Protocol(format!("Failed to fetch: {}", e)))?;

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
        use nostr_sdk::{Filter, Kind};
        use nostr_sdk::prelude::{SingleLetterTag, Alphabet};

        let secp = Secp256k1::new();
        let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &self.wallet.operator_secret());
        let our_pubkey = keypair.public_key();

        // Use the existing nostr client
        let client = self.nostr.client();

        let filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_UPDATE))
            .custom_tag(SingleLetterTag::lowercase(Alphabet::D), [ledger_id])
            .limit(500);

        let events = client
            .fetch_events(vec![filter], None)
            .await
            .map_err(|e| Error::Protocol(format!("Failed to fetch: {}", e)))?;

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
            cosigner_pubkey: None,
            member_ledger_hash: None,
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

        // Use the existing nostr client
        let client = self.nostr.client();

        let filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_UPDATE))
            .custom_tag(SingleLetterTag::lowercase(Alphabet::D), [ledger_id])
            .limit(500);

        let events = client
            .fetch_events(vec![filter], None)
            .await
            .map_err(|e| Error::Protocol(format!("Failed to fetch: {}", e)))?;

        // Find our latest update and collect original depositors (deposit_id, descriptor)
        let mut our_latest: Option<SignedLedgerUpdate> = None;
        let mut original_depositors: Vec<(DepositId, String)> = Vec::new();

        for event in events.iter() {
            if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
                if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                    // Collect depositors
                    if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                        if let LedgerOperation::DepositOpen { deposit_id, descriptor, .. } = op {
                            if !original_depositors.iter().any(|(id, _)| *id == deposit_id) {
                                original_depositors.push((deposit_id, descriptor));
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
        for (deposit_id, descriptor) in original_depositors {
            let operation = LedgerOperation::DepositOpen {
                deposit_id,
                descriptor: descriptor.clone(),
                fees: None,
                transfer_fees: None,
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
                cosigner_pubkey: None,
                member_ledger_hash: None,
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

            tracing::info!("Re-opened deposit {}...", hex::encode(&deposit_id[..8]));

            // Update our_latest for next iteration
            our_latest = signed_update;
        }

        tracing::info!("Ledger continue complete");
        Ok(())
    }

    // ========================================================================
    // Request Handlers
    // These process incoming Nostr requests for ledger operations.
    // ========================================================================

    async fn process_deposit_open_request(&mut self, request: &crate::nostr::LedgerRequest) -> (bool, Option<String>, Option<String>) {
        use std::str::FromStr;

        tracing::info!("Processing deposit_open request for ledger {}...",
            &request.ledger_id[..16.min(request.ledger_id.len())]);

        // Resolve to ledger_id (handles both hash and reserves_key formats)
        let ledger_id = match self.resolve_to_ledger_id(&request.ledger_id) {
            Ok(lid) => lid,
            Err(e) => return (false, None, Some(e)),
        };

        // Extract deposit_pubkey from params
        let deposit_pubkey_str = match request.params.get("deposit_pubkey") {
            Some(serde_json::Value::String(s)) => s.clone(),
            _ => return (false, None, Some("Missing deposit_pubkey parameter".to_string())),
        };

        let deposit_pubkey = match PublicKey::from_str(&deposit_pubkey_str) {
            Ok(pk) => pk,
            Err(e) => return (false, None, Some(format!("Invalid deposit_pubkey: {}", e))),
        };

        // Fetch the advertisement to get fee minimums
        let advertisement = match self.nostr.fetch_ledger_advertisement(&request.ledger_id).await {
            Ok(Some(ad)) => ad,
            Ok(None) => {
                tracing::warn!("No advertisement found for ledger {}, using zero fee minimums", &request.ledger_id[..16]);
                crate::nostr::LedgerAdvertisement::new(
                    request.ledger_id.clone(),
                    String::new(),
                    String::new(),
                    String::new(),
                )
            }
            Err(e) => {
                tracing::warn!("Failed to fetch advertisement: {}, using zero fee minimums", e);
                crate::nostr::LedgerAdvertisement::new(
                    request.ledger_id.clone(),
                    String::new(),
                    String::new(),
                    String::new(),
                )
            }
        };

        let (min_annual_bps, min_fixed_per_period) = advertisement.minimum_fees();

        // Extract fee parameters from request OR use advertisement defaults
        let ad_period = if advertisement.fee_period_blocks > 0 { advertisement.fee_period_blocks } else { 2016 };
        let frequency_blocks = request.params.get("fee_frequency")
            .and_then(|v| v.as_u64())
            .map(|v| if v > 0 { v as u32 } else { 2016 })
            .unwrap_or(ad_period);

        let fees = if request.params.get("fee_fixed").is_some()
            || request.params.get("fee_bps").is_some()
        {
            FeeStructure {
                annualized_fixed: request.params.get("fee_fixed")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
                annualized_bps: request.params.get("fee_bps")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u16,
                frequency_blocks,
            }
        } else {
            // Use advertisement defaults if no fees specified
            advertisement.to_fee_structure()
        };

        // Validate proposed fees meet operator minimums
        if let Err(e) = deposits_core::operation_validation::validate_fee_minimum(
            &fees,
            min_annual_bps,
            min_fixed_per_period,
        ) {
            return (false, None, Some(format!("Fee validation failed: {}", e)));
        }

        // Extract per-transfer fee schedule (optional, defaults to 2 sats fixed + 20 bps)
        let transfer_fees = {
            let fixed = request.params.get("transfer_fee_fixed").and_then(|v| v.as_u64());
            let rate = request.params.get("transfer_fee_rate_bps").and_then(|v| v.as_u64());
            if fixed.is_some() || rate.is_some() {
                Some(deposits_core::TransferFeeSchedule::new(
                    fixed.unwrap_or(2),
                    rate.unwrap_or(20) as u16,
                ))
            } else {
                None // will use default (100 sats, 0 bps)
            }
        };

        // Create descriptor from pubkey (single-key deposit)
        let descriptor = format!("pk({})", deposit_pubkey_str);

        // Open the deposit with co-signing
        match self.open_deposit(&ledger_id, &descriptor, Some(fees), transfer_fees).await {
            Ok(deposit) => {
                let result = serde_json::json!({
                    "deposit_pubkey": deposit_pubkey_str,
                    "balance": deposit.balance,
                    "fees": {
                        "fixed": deposit.fees.annualized_fixed,
                        "bps": deposit.fees.annualized_bps,
                        "frequency": deposit.fees.frequency_blocks,
                    },
                    "transfer_fees": {
                        "fixed_sats": deposit.transfer_fees.fixed_sats,
                        "rate_bps": deposit.transfer_fees.rate_bps,
                    }
                });
                tracing::info!("Deposit opened for {}...", &deposit_pubkey_str[..16]);
                (true, Some(result.to_string()), None)
            }
            Err(e) => {
                tracing::warn!("Failed to open deposit: {}", e);
                (false, None, Some(e.to_string()))
            }
        }
    }

    async fn process_make_offer_request(&mut self, request: &crate::nostr::LedgerRequest) -> (bool, Option<String>, Option<String>) {
        use std::str::FromStr;

        tracing::info!("Processing make_offer request for ledger {}...",
            &request.ledger_id[..16.min(request.ledger_id.len())]);

        // Verify the ledger exists (ledger_id may be a hash or reserves_id)
        let resolved_ledger_id = if request.ledger_id.len() == 64 && request.ledger_id.chars().all(|c| c.is_ascii_hexdigit()) {
            // Already a 64-char hex ledger_id hash
            request.ledger_id.clone()
        } else {
            // It's a reserves_id, look up the ledger to get its ledger_id
            match self.get_ledger_by_reserves_key(&request.ledger_id) {
                Some((_, ledger)) => ledger.ledger_id_hex(),
                None => return (false, None, Some(format!("Ledger not found: {}", &request.ledger_id[..16]))),
            }
        };

        // Extract deposit_pubkey from params
        let deposit_pubkey_str = match request.params.get("deposit_pubkey") {
            Some(serde_json::Value::String(s)) => s.clone(),
            _ => return (false, None, Some("Missing deposit_pubkey parameter".to_string())),
        };

        let deposit_pubkey = match PublicKey::from_str(&deposit_pubkey_str) {
            Ok(pk) => pk,
            Err(e) => return (false, None, Some(format!("Invalid deposit_pubkey: {}", e))),
        };

        // Extract required parameters
        let max_sats = match request.params.get("max_sats").and_then(|v| v.as_u64()) {
            Some(v) => v,
            None => return (false, None, Some("Missing max_sats parameter".to_string())),
        };

        let min_sats = match request.params.get("min_sats").and_then(|v| v.as_u64()) {
            Some(v) => v,
            None => return (false, None, Some("Missing min_sats parameter".to_string())),
        };

        let blocks_valid = match request.params.get("blocks_valid").and_then(|v| v.as_u64()) {
            Some(v) => v as u32,
            None => return (false, None, Some("Missing blocks_valid parameter".to_string())),
        };

        if min_sats >= max_sats {
            return (false, None, Some("min_sats must be less than max_sats".to_string()));
        }

        // Fetch the advertisement to get fee minimums
        let advertisement = match self.nostr.fetch_ledger_advertisement(&resolved_ledger_id).await {
            Ok(Some(ad)) => ad,
            Ok(None) => {
                tracing::warn!("No advertisement found for ledger {}, using zero fee minimums", &resolved_ledger_id[..16]);
                crate::nostr::LedgerAdvertisement::new(
                    resolved_ledger_id.clone(),
                    String::new(),
                    String::new(),
                    String::new(),
                )
            }
            Err(e) => {
                tracing::warn!("Failed to fetch advertisement: {}, using zero fee minimums", e);
                crate::nostr::LedgerAdvertisement::new(
                    resolved_ledger_id.clone(),
                    String::new(),
                    String::new(),
                    String::new(),
                )
            }
        };

        let (min_annual_bps, min_fixed_per_period) = advertisement.minimum_fees();
        let ad_period = if advertisement.fee_period_blocks > 0 { advertisement.fee_period_blocks } else { 2016 };

        // Extract fee parameters from request if provided, or use advertisement defaults
        let fees = if request.params.get("fee_fixed").is_some()
            || request.params.get("fee_bps").is_some()
            || request.params.get("fee_frequency").is_some()
        {
            let frequency_blocks = request.params.get("fee_frequency")
                .and_then(|v| v.as_u64())
                .map(|v| if v > 0 { v as u32 } else { ad_period })
                .unwrap_or(ad_period);

            FeeStructure {
                annualized_fixed: request.params.get("fee_fixed")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
                annualized_bps: request.params.get("fee_bps")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u16,
                frequency_blocks,
            }
        } else {
            // Use advertisement defaults if no fees specified
            advertisement.to_fee_structure()
        };

        // Validate proposed fees meet operator minimums
        if let Err(e) = deposits_core::operation_validation::validate_fee_minimum(
            &fees,
            min_annual_bps,
            min_fixed_per_period,
        ) {
            return (false, None, Some(format!("Fee validation failed: {}", e)));
        }

        // Sync wallet to get current block height
        if let Err(e) = self.sync_wallet() {
            return (false, None, Some(format!("Failed to sync wallet: {}", e)));
        }

        // Create the offer using ledger_id (stable across custody transfers)
        match self.create_deposit_offer(&resolved_ledger_id, deposit_pubkey, max_sats, min_sats, blocks_valid, Some(fees)) {
            Ok(offer) => {
                // Check if we need a co-signature (post-rotation)
                let requires_cosign = self.has_quorum_reserves(&resolved_ledger_id);

                if requires_cosign {
                    // Request co-signature from quorum members (retry up to 3 times)
                    let max_attempts = 3;
                    let mut cosign_ok = None;
                    let mut last_err = String::new();
                    for attempt in 1..=max_attempts {
                        match self.request_offer_cosign(&resolved_ledger_id, &offer).await {
                            Ok(result) => { cosign_ok = Some(result); break; }
                            Err(e) => {
                                tracing::warn!("Offer cosign attempt {}/{} failed: {}", attempt, max_attempts, e);
                                last_err = e.to_string();
                                if attempt < max_attempts {
                                    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                                }
                            }
                        }
                    }
                    match cosign_ok {
                        Some(cosign_result) => {
                            let result = serde_json::json!({
                                "offer_id": hex::encode(&offer.offer_id),
                                "operator_id": offer.operator_id.to_string(),
                                "funding_address": offer.funding_address,
                                "deadline_block": offer.deadline_block,
                                "created_at_block": offer.created_at_block,
                                "max_sats": max_sats,
                                "min_sats": min_sats,
                                "cosign_required": true,
                                "cosigner_pubkey": cosign_result.cosigner_pubkey.to_string(),
                                "cosigner_ledger_hash": hex::encode(cosign_result.member_ledger_hash),
                                "cosign_signature": hex::encode(cosign_result.signature),
                            });
                            tracing::info!("Deposit offer created with co-signature: {}...", &hex::encode(&offer.offer_id[..8]));
                            (true, Some(result.to_string()), None)
                        }
                        None => {
                            tracing::warn!("Failed to get co-signature for offer after {} attempts: {}", max_attempts, last_err);
                            (false, None, Some(format!("Co-signature required but failed: {}", last_err)))
                        }
                    }
                } else {
                    // Pre-rotation: no co-signature required
                    let result = serde_json::json!({
                        "offer_id": hex::encode(&offer.offer_id),
                        "operator_id": offer.operator_id.to_string(),
                        "funding_address": offer.funding_address,
                        "deadline_block": offer.deadline_block,
                        "created_at_block": offer.created_at_block,
                        "max_sats": max_sats,
                        "min_sats": min_sats,
                        "cosign_required": false,
                    });
                    tracing::info!("Deposit offer created: {}...", &hex::encode(&offer.offer_id[..8]));
                    (true, Some(result.to_string()), None)
                }
            }
            Err(e) => {
                tracing::warn!("Failed to create deposit offer: {}", e);
                (false, None, Some(e.to_string()))
            }
        }
    }

    /// Process an offer status query request
    ///
    /// Params:
    /// - offer_id: hex-encoded 32-byte offer ID (optional)
    /// - deposit_pubkey: hex-encoded depositor pubkey (optional, used if offer_id not found)
    ///
    /// If offer_id is found, returns the offer status.
    /// If offer_id is not found but deposit_pubkey is provided, checks if the deposit
    /// exists in the ledger (meaning the offer was completed).
    async fn process_offer_status_request(&self, request: &crate::nostr::LedgerRequest) -> (bool, Option<String>, Option<String>) {
        use deposits_core::types::DepositOfferStatus;

        // Extract offer_id from params
        let offer_id_hex = match request.params.get("offer_id").and_then(|v| v.as_str()) {
            Some(id) => id,
            None => return (false, None, Some("Missing offer_id parameter".to_string())),
        };

        // Also extract deposit_pubkey if provided (for fallback lookup)
        let deposit_pubkey_hex = request.params.get("deposit_pubkey").and_then(|v| v.as_str());

        // Parse hex offer_id
        let offer_id_bytes = match hex::decode(offer_id_hex) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                arr
            }
            Ok(_) => return (false, None, Some("offer_id must be 32 bytes".to_string())),
            Err(e) => return (false, None, Some(format!("Invalid offer_id hex: {}", e))),
        };

        // Look up the offer
        match self.get_deposit_offer(&offer_id_bytes) {
            Some((offer, status)) => {
                let status_json = match status {
                    DepositOfferStatus::Pending => serde_json::json!({
                        "status": "pending",
                    }),
                    DepositOfferStatus::FundingReceived { txid, amount_sats, detected_at_block } => serde_json::json!({
                        "status": "funding_received",
                        "txid": txid,
                        "amount_sats": amount_sats,
                        "detected_at_block": detected_at_block,
                    }),
                    DepositOfferStatus::Completed { txid, amount_sats, confirmed_at_block } => serde_json::json!({
                        "status": "completed",
                        "txid": txid,
                        "amount_sats": amount_sats,
                        "confirmed_at_block": confirmed_at_block,
                    }),
                    DepositOfferStatus::Expired { expired_at_block } => serde_json::json!({
                        "status": "expired",
                        "expired_at_block": expired_at_block,
                    }),
                    DepositOfferStatus::Cancelled => serde_json::json!({
                        "status": "cancelled",
                    }),
                };

                let result = serde_json::json!({
                    "offer_id": offer_id_hex,
                    "funding_address": offer.funding_address,
                    "ledger_id": offer.ledger_id,
                    "max_sats": offer.max_amount_sats,
                    "min_sats": offer.min_amount_sats,
                    "deadline_block": offer.deadline_block,
                    "status": status_json,
                });

                tracing::debug!("Offer status query: {}... -> {:?}", &offer_id_hex[..16], status_json);
                (true, Some(result.to_string()), None)
            }
            None => {
                // Offer not in our tracking. If we have deposit_pubkey, check if the deposit
                // exists in the ledger (meaning it was funded and completed).
                if let Some(pubkey_hex) = deposit_pubkey_hex {
                    // Convert pubkey to deposit_id
                    let descriptor = format!("pk({})", pubkey_hex);
                    let deposit_id = compute_deposit_id(&descriptor);

                    // Check if deposit exists in the ledger
                    if let Some((_, ledger)) = self.get_ledger_by_ledger_id(&request.ledger_id)
                        .or_else(|| self.get_ledger_by_reserves_key(&request.ledger_id))
                    {
                        if let Some(deposit) = ledger.state.deposits.get(&deposit_id) {
                            // Deposit exists - offer must have completed
                            let result = serde_json::json!({
                                "offer_id": offer_id_hex,
                                "status": {
                                    "status": "completed",
                                    "amount_sats": deposit.balance / 1000,
                                },
                            });
                            tracing::debug!("Offer status query: {}... -> completed (from ledger)", &offer_id_hex[..16]);
                            return (true, Some(result.to_string()), None);
                        }
                    }
                }

                // No offer and no deposit found
                let result = serde_json::json!({
                    "offer_id": offer_id_hex,
                    "status": {
                        "status": "not_found",
                    },
                });
                tracing::debug!("Offer status query: {}... -> not found", &offer_id_hex[..16]);
                (true, Some(result.to_string()), None)
            }
        }
    }

    /// Process a balance query request
    ///
    /// Params:
    /// - deposit_pubkey: hex-encoded depositor's pubkey (legacy, converted to deposit_id)
    ///
    /// Returns the current balance in the ledger (in millisatoshis)
    async fn process_balance_query_request(&self, request: &crate::nostr::LedgerRequest) -> (bool, Option<String>, Option<String>) {
        // Extract deposit_pubkey from params
        let deposit_pubkey_hex = match request.params.get("deposit_pubkey").and_then(|v| v.as_str()) {
            Some(pk) => pk,
            None => return (false, None, Some("Missing deposit_pubkey parameter".to_string())),
        };

        // Convert pubkey hex to deposit_id via descriptor
        let descriptor = format!("pk({})", deposit_pubkey_hex);
        let deposit_id = compute_deposit_id(&descriptor);

        // Find the ledger
        let (_, ledger) = match self.get_ledger_by_ledger_id(&request.ledger_id)
            .or_else(|| self.get_ledger_by_reserves_key(&request.ledger_id))
        {
            Some(l) => l,
            None => return (false, None, Some("Ledger not found".to_string())),
        };

        // Look up the deposit balance
        match ledger.state.deposits.get(&deposit_id) {
            Some(deposit) => {
                let result = serde_json::json!({
                    "deposit_pubkey": deposit_pubkey_hex,
                    "deposit_id": hex::encode(deposit_id),
                    "balance_msats": deposit.balance,
                    "balance_sats": deposit.balance / 1000,
                    "locked_msats": deposit.locked_balance,
                    "collateral_lock_msats": deposit.collateral_lock_amount,
                    "collateral_lock_expires": deposit.collateral_lock_expires,
                });
                tracing::debug!("Balance query: {}... -> {} msats", &deposit_pubkey_hex[..16], deposit.balance);
                (true, Some(result.to_string()), None)
            }
            None => {
                (false, None, Some(format!("Deposit not found for pubkey: {}...", &deposit_pubkey_hex[..16])))
            }
        }
    }

    /// Process a make_invoice request - create Lightning invoice for deposit credit
    ///
    /// Uses LdkCli to talk to the ldk-server sidecar (same as `deposits-bdk lightning invoice`)
    ///
    /// Params:
    /// - deposit_pubkey: hex-encoded depositor's pubkey
    /// - amount_sats: amount for the invoice
    /// - description: optional invoice description
    async fn process_make_invoice_request(&self, request: &crate::nostr::LedgerRequest) -> (bool, Option<String>, Option<String>) {
        use crate::ldk_cli::LdkCli;
        use lightning_invoice::Bolt11Invoice;
        use std::str::FromStr;

        // Extract parameters
        let deposit_pubkey_hex = match request.params.get("deposit_pubkey").and_then(|v| v.as_str()) {
            Some(pk) => pk,
            None => return (false, None, Some("Missing deposit_pubkey parameter".to_string())),
        };

        // Convert pubkey hex to descriptor and deposit_id
        let descriptor = format!("pk({})", deposit_pubkey_hex);
        let deposit_id = compute_deposit_id(&descriptor);

        let amount_sats = match request.params.get("amount_sats").and_then(|v| v.as_u64()) {
            Some(a) => a,
            None => return (false, None, Some("Missing amount_sats parameter".to_string())),
        };

        let description = request.params.get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("Deposit credit");

        // Create invoice via LdkCli (same as `deposits-bdk lightning invoice`)
        let cli = LdkCli::from_env();
        let amount_msat = amount_sats * 1000;

        match cli.create_invoice(amount_msat, description) {
            Ok(invoice_str) => {
                // Parse the invoice to get the payment hash
                let payment_hash = match Bolt11Invoice::from_str(&invoice_str) {
                    Ok(inv) => {
                        let mut hash = [0u8; 32];
                        hash.copy_from_slice(inv.payment_hash().as_ref());
                        hash
                    }
                    Err(e) => {
                        tracing::warn!("Failed to parse created invoice: {}", e);
                        // Generate a hash from the invoice string as fallback
                        use bitcoin::hashes::{sha256, Hash};
                        let hash = sha256::Hash::hash(invoice_str.as_bytes());
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(hash.as_ref());
                        arr
                    }
                };

                // Track the pending invoice for crediting when paid
                let pending = PendingInvoice {
                    ledger_id: request.ledger_id.clone(),
                    deposit_id,
                    descriptor: descriptor.clone(),
                    amount_msat,
                    invoice: invoice_str.clone(),
                    created_at: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0),
                };

                self.pending_invoices.lock().unwrap().insert(payment_hash, pending);

                tracing::info!("Created invoice for {}... amount={} sats, hash={}",
                    &deposit_pubkey_hex[..16.min(deposit_pubkey_hex.len())],
                    amount_sats,
                    hex::encode(&payment_hash[..8]));

                let result = serde_json::json!({
                    "invoice": invoice_str,
                    "amount_sats": amount_sats,
                    "deposit_pubkey": deposit_pubkey_hex,
                    "deposit_id": hex::encode(deposit_id),
                    "payment_hash": hex::encode(payment_hash),
                });
                (true, Some(result.to_string()), None)
            }
            Err(e) => {
                tracing::error!("Failed to create invoice: {}", e);
                (false, None, Some(format!("Failed to create invoice: {}", e)))
            }
        }
    }

    /// Process a pay_invoice request - pay Lightning invoice from deposit
    ///
    /// Uses LdkCli to talk to the ldk-server sidecar (same as `deposits-bdk lightning pay`)
    ///
    /// Params:
    /// - deposit_pubkey: hex-encoded depositor's pubkey
    /// - invoice: bolt11 invoice string
    /// - nonce: hex-encoded 32-byte nonce
    /// - signature: hex-encoded Schnorr signature over payment message
    async fn process_pay_invoice_request(&mut self, request: &crate::nostr::LedgerRequest) -> (bool, Option<String>, Option<String>) {
        use crate::ldk_cli::LdkCli;
        use bitcoin::secp256k1::{Secp256k1, schnorr::Signature, Message};
        use deposits_core::messages::LedgerOperation;
        use lightning_invoice::Bolt11Invoice;
        use std::str::FromStr;

        // Extract parameters
        let deposit_pubkey_hex = match request.params.get("deposit_pubkey").and_then(|v| v.as_str()) {
            Some(pk) => pk,
            None => return (false, None, Some("Missing deposit_pubkey parameter".to_string())),
        };

        let invoice_str = match request.params.get("invoice").and_then(|v| v.as_str()) {
            Some(i) => i,
            None => return (false, None, Some("Missing invoice parameter".to_string())),
        };

        let payment_hash_hex = match request.params.get("payment_hash").and_then(|v| v.as_str()) {
            Some(h) => h,
            None => return (false, None, Some("Missing payment_hash parameter".to_string())),
        };

        let amount_msat = match request.params.get("amount_msats").and_then(|v| v.as_u64()) {
            Some(a) => a,
            None => return (false, None, Some("Missing amount_msats parameter".to_string())),
        };

        let signature_hex = match request.params.get("signature").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return (false, None, Some("Missing signature parameter".to_string())),
        };

        // Parse payment_hash from client
        let mut payment_id = [0u8; 32];
        match hex::decode(payment_hash_hex) {
            Ok(bytes) if bytes.len() == 32 => payment_id.copy_from_slice(&bytes),
            _ => return (false, None, Some("Invalid payment_hash".to_string())),
        }

        // Parse the BOLT11 invoice and verify it matches client's payment_hash and amount
        let invoice = match Bolt11Invoice::from_str(invoice_str) {
            Ok(inv) => inv,
            Err(e) => return (false, None, Some(format!("Invalid invoice: {}", e))),
        };

        let invoice_payment_hash = invoice.payment_hash();
        let invoice_hash_bytes: &[u8] = invoice_payment_hash.as_ref();
        if invoice_hash_bytes != &payment_id {
            return (false, None, Some("payment_hash does not match invoice".to_string()));
        }

        let invoice_amount = invoice.amount_milli_satoshis().unwrap_or(0);
        if invoice_amount != amount_msat {
            return (false, None, Some("amount_msats does not match invoice".to_string()));
        }

        // Convert pubkey hex to descriptor and deposit_id
        let descriptor = format!("pk({})", deposit_pubkey_hex);
        let deposit_id = compute_deposit_id(&descriptor);

        // Parse pubkey for signature verification
        let deposit_pubkey = match hex::decode(deposit_pubkey_hex)
            .ok()
            .and_then(|bytes| bitcoin::secp256k1::PublicKey::from_slice(&bytes).ok())
        {
            Some(pk) => pk,
            None => return (false, None, Some("Invalid deposit_pubkey".to_string())),
        };

        // Verify INVOICE signature (deposit_id, payment_hash, amount)
        let secp = Secp256k1::verification_only();
        let msg_hash = deposits_core::signature_utils::invoice_lock_signing_message(
            &deposit_id,
            &payment_id,
            amount_msat,
        );
        let msg = Message::from_digest(msg_hash);

        let sig_bytes = match hex::decode(signature_hex) {
            Ok(b) if b.len() == 64 => b,
            _ => return (false, None, Some("Invalid signature format".to_string())),
        };

        let signature = match Signature::from_slice(&sig_bytes) {
            Ok(s) => s,
            Err(_) => return (false, None, Some("Invalid signature".to_string())),
        };

        let xonly = bitcoin::secp256k1::XOnlyPublicKey::from(deposit_pubkey);
        if secp.verify_schnorr(&signature, &msg, &xonly).is_err() {
            return (false, None, Some("Signature verification failed".to_string()));
        }

        // Find the ledger and check deposit balance
        let ledger_id = &request.ledger_id;
        let ledger_arc = match self.handler.ledgers.lock().unwrap().get(ledger_id).cloned() {
            Some(l) => l,
            None => return (false, None, Some("Ledger not found".to_string())),
        };

        let sequence_number = {
            let ledger = ledger_arc.read().unwrap();

            let deposit = match ledger.state.deposits.get(&deposit_id) {
                Some(d) => d,
                None => return (false, None, Some("Deposit not found".to_string())),
            };

            if deposit.balance < amount_msat {
                return (false, None, Some(format!(
                    "Insufficient balance: {} msat available, {} msat needed",
                    deposit.balance, amount_msat
                )));
            }

            ledger.history.len() as u64
        };

        // Create witness from signature
        let witness = DescriptorWitness { stack: vec![sig_bytes.clone()] };

        let lock_operation = LedgerOperation::InvoiceLock {
            deposit_id,
            amount: amount_msat,
            payment_id,
            sequence_number,
            witness: witness.clone(),
        };

        // Append the lock operation
        {
            let mut ledger = ledger_arc.write().unwrap();
            let block_height = self.wallet.get_block_height().unwrap_or(0);
            let block_hash = self.wallet.get_block_hash().unwrap_or([0u8; 32]);

            if let Err(e) = ledger.append_operation_with_block(
                lock_operation,
                deposits_core::messages::consts::SENDING_LOCK_PAYMENT,
                block_height,
                block_hash,
            ) {
                return (false, None, Some(format!("Failed to lock funds: {:?}", e)));
            }
        }

        // Sign and broadcast the lock
        if let Err(e) = self.sign_and_broadcast(ledger_id).await {
            tracing::error!("Failed to broadcast lock: {}", e);
            // Note: funds are locked locally, but broadcast failed
        }

        tracing::info!("Locked {} msat for payment {}",
            amount_msat, hex::encode(&payment_id[..8]));

        // Pay invoice via LdkCli
        let cli = LdkCli::from_env();
        let pay_result = cli.pay_invoice(invoice_str);

        // Poll for payment completion (with timeout)
        let mut preimage: Option<[u8; 32]> = None;
        let mut payment_succeeded = false;

        if pay_result.is_ok() {
            // Wait for payment to complete
            for _ in 0..30 {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;

                if let Ok(payments) = cli.list_payments() {
                    for p in payments.payments {
                        if let Ok(p_hash) = hex::decode(&p.id) {
                            if p_hash.len() >= 32 && p_hash[..32] == payment_id[..] {
                                match p.status {
                                    1 => {
                                        // Succeeded
                                        payment_succeeded = true;
                                        if let Some(ref pre_hex) = p.preimage {
                                            if let Ok(pre_bytes) = hex::decode(pre_hex) {
                                                if pre_bytes.len() == 32 {
                                                    let mut pre = [0u8; 32];
                                                    pre.copy_from_slice(&pre_bytes);
                                                    preimage = Some(pre);
                                                }
                                            }
                                        }
                                        break;
                                    }
                                    2 => {
                                        // Failed
                                        break;
                                    }
                                    _ => continue, // Still pending
                                }
                            }
                        }
                    }
                    if payment_succeeded || preimage.is_some() {
                        break;
                    }
                }
            }
        }

        // Create fulfill or fail operation
        let final_sequence = {
            let ledger = ledger_arc.read().unwrap();
            ledger.history.len() as u64
        };

        if payment_succeeded {
            let pre = preimage.unwrap_or([0u8; 32]);
            let fulfill_operation = LedgerOperation::InvoiceFulfill {
                deposit_id,
                amount: amount_msat,
                payment_id,
                sequence_number: final_sequence,
                witness: witness.clone(),
                preimage: pre,
            };

            {
                let mut ledger = ledger_arc.write().unwrap();
                let block_height = self.wallet.get_block_height().unwrap_or(0);
                let block_hash = self.wallet.get_block_hash().unwrap_or([0u8; 32]);

                if let Err(e) = ledger.append_operation_with_block(
                    fulfill_operation,
                    deposits_core::messages::consts::SENDING_FULFILL_PAYMENT,
                    block_height,
                    block_hash,
                ) {
                    tracing::error!("Failed to record fulfill: {:?}", e);
                }
            }

            if let Err(e) = self.sign_and_broadcast(ledger_id).await {
                tracing::error!("Failed to broadcast fulfill: {}", e);
            }

            tracing::info!("Payment {} fulfilled, {} msat debited from {}",
                hex::encode(&payment_id[..8]), amount_msat,
                &deposit_pubkey_hex[..16]);

            let result = serde_json::json!({
                "payment_id": hex::encode(&payment_id),
                "deposit_pubkey": deposit_pubkey_hex,
                "amount_msat": amount_msat,
                "preimage": preimage.map(|p| hex::encode(p)),
                "status": "succeeded",
            });
            (true, Some(result.to_string()), None)
        } else {
            // Payment failed - unlock funds
            let fail_operation = LedgerOperation::InvoiceFail {
                deposit_id,
                amount: amount_msat,
                payment_id,
                sequence_number: final_sequence,
            };

            {
                let mut ledger = ledger_arc.write().unwrap();
                let block_height = self.wallet.get_block_height().unwrap_or(0);
                let block_hash = self.wallet.get_block_hash().unwrap_or([0u8; 32]);

                if let Err(e) = ledger.append_operation_with_block(
                    fail_operation,
                    deposits_core::messages::consts::SENDING_FAIL_PAYMENT,
                    block_height,
                    block_hash,
                ) {
                    tracing::error!("Failed to record fail: {:?}", e);
                }
            }

            if let Err(e) = self.sign_and_broadcast(ledger_id).await {
                tracing::error!("Failed to broadcast fail: {}", e);
            }

            tracing::warn!("Payment {} failed, {} msat unlocked for {}",
                hex::encode(&payment_id[..8]), amount_msat,
                &deposit_pubkey_hex[..16]);

            let error_msg = pay_result.err().map(|e| e.to_string()).unwrap_or_else(|| "Payment timed out".to_string());
            (false, None, Some(format!("Payment failed: {}", error_msg)))
        }
    }

    /// Process a withdrawal request from a depositor
    ///
    /// Params:
    /// - deposit_pubkey: hex-encoded depositor's pubkey
    /// - deposit_id: hex-encoded 16-byte deposit identifier
    /// - address: destination Bitcoin address
    /// - amount_sats: amount to withdraw
    /// - fee_sats: fee for the withdrawal transaction
    /// - nonce: hex-encoded 32-byte nonce
    /// - signature: hex-encoded Schnorr signature over WITHDRAWAL message
    async fn process_withdraw_request(&mut self, request: &crate::nostr::LedgerRequest) -> (bool, Option<String>, Option<String>) {
        use bitcoin::secp256k1::{Secp256k1, schnorr::Signature, Message};

        tracing::info!("Processing withdraw request for ledger {}...",
            &request.ledger_id[..16.min(request.ledger_id.len())]);

        // Extract parameters
        let deposit_pubkey_hex = match request.params.get("deposit_pubkey").and_then(|v| v.as_str()) {
            Some(p) => p,
            None => return (false, None, Some("Missing deposit_pubkey".to_string())),
        };
        let deposit_id_hex = match request.params.get("deposit_id").and_then(|v| v.as_str()) {
            Some(d) => d,
            None => return (false, None, Some("Missing deposit_id".to_string())),
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

        // Parse deposit_id
        let mut deposit_id = [0u8; 16];
        match hex::decode(deposit_id_hex) {
            Ok(bytes) if bytes.len() == 16 => deposit_id.copy_from_slice(&bytes),
            _ => return (false, None, Some("Invalid deposit_id (must be 16 bytes hex)".to_string())),
        }

        // Verify deposit_id matches pubkey
        let descriptor = format!("pk({})", deposit_pubkey_hex);
        let expected_deposit_id = compute_deposit_id(&descriptor);
        if deposit_id != expected_deposit_id {
            return (false, None, Some("deposit_id does not match deposit_pubkey".to_string()));
        }

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

        // Verify WITHDRAWAL signature (nonce, deposit_id, address, amount, fee)
        let msg_hash = deposits_core::signature_utils::withdrawal_signing_message(
            &nonce,
            &deposit_id,
            address,
            amount_sats,
            fee_sats,
        );
        let secp = Secp256k1::new();
        let msg = Message::from_digest(msg_hash);
        let x_only = deposit_pubkey.x_only_public_key().0;

        if secp.verify_schnorr(&signature, &msg, &x_only).is_err() {
            return (false, None, Some("Invalid withdrawal signature".to_string()));
        }

        // Find the ledger
        let (reserves_id, _ledger) = match self.get_ledger_by_ledger_id(&request.ledger_id)
            .or_else(|| self.get_ledger_by_reserves_key(&request.ledger_id))
        {
            Some(l) => l,
            None => return (false, None, Some("Ledger not found".to_string())),
        };

        // Compute deposit_id from pubkey
        let descriptor = format!("pk({})", deposit_pubkey_hex);
        let deposit_id = compute_deposit_id(&descriptor);

        // Create witness from signature
        let depositor_witness = DescriptorWitness {
            stack: vec![signature.serialize().to_vec()],
        };

        // Lock the withdrawal with co-signing
        match self.lock_withdrawal(
            &reserves_id,
            deposit_id,
            address.to_string(),
            amount_sats,
            fee_sats,
            nonce,
            depositor_witness,
            None, // no memo
        ).await {
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

    /// Process a transfer_lock request - lock funds for conditional transfer
    async fn process_transfer_lock_request(&mut self, request: &crate::nostr::LedgerRequest) -> (bool, Option<String>, Option<String>) {
        use bitcoin::secp256k1::{Secp256k1, schnorr::Signature, Message};
        use deposits_core::types::{compute_deposit_id, DescriptorWitness};
        use deposits_core::messages::LedgerOperation;

        tracing::info!("Processing transfer_lock request for ledger {}...",
            &request.ledger_id[..16.min(request.ledger_id.len())]);

        // Extract parameters
        let nonce_hex = match request.params.get("nonce").and_then(|v| v.as_str()) {
            Some(n) => n,
            None => return (false, None, Some("Missing nonce".to_string())),
        };
        let source_id_hex = match request.params.get("source_deposit_id").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return (false, None, Some("Missing source_deposit_id".to_string())),
        };
        let dest_id_hex = match request.params.get("destination_deposit_id").and_then(|v| v.as_str()) {
            Some(d) => d,
            None => return (false, None, Some("Missing destination_deposit_id".to_string())),
        };
        let amount = match request.params.get("amount").and_then(|v| v.as_u64()) {
            Some(a) => a,
            None => return (false, None, Some("Missing amount".to_string())),
        };
        let fee = match request.params.get("fee").and_then(|v| v.as_u64()) {
            Some(f) => f,
            None => return (false, None, Some("Missing fee".to_string())),
        };
        let completion_script = match request.params.get("completion_script").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return (false, None, Some("Missing completion_script".to_string())),
        };
        let timeout_height = match request.params.get("timeout_height").and_then(|v| v.as_u64()) {
            Some(t) => t as u32,
            None => return (false, None, Some("Missing timeout_height".to_string())),
        };
        let transfer_id_hex = match request.params.get("transfer_id").and_then(|v| v.as_str()) {
            Some(t) => t,
            None => return (false, None, Some("Missing transfer_id".to_string())),
        };
        let signature_hex = match request.params.get("signature").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return (false, None, Some("Missing signature".to_string())),
        };

        // Parse nonce
        let nonce: [u8; 32] = match hex::decode(nonce_hex) {
            Ok(bytes) if bytes.len() == 32 => bytes.try_into().unwrap(),
            _ => return (false, None, Some("Invalid nonce".to_string())),
        };

        // Parse deposit IDs
        let mut source_deposit_id = [0u8; 16];
        match hex::decode(source_id_hex) {
            Ok(bytes) if bytes.len() == 16 => source_deposit_id.copy_from_slice(&bytes),
            _ => return (false, None, Some("Invalid source_deposit_id".to_string())),
        }

        let mut destination_deposit_id = [0u8; 16];
        match hex::decode(dest_id_hex) {
            Ok(bytes) if bytes.len() == 16 => destination_deposit_id.copy_from_slice(&bytes),
            _ => return (false, None, Some("Invalid destination_deposit_id".to_string())),
        }

        // Parse transfer_id
        let transfer_id: [u8; 32] = match hex::decode(transfer_id_hex) {
            Ok(bytes) if bytes.len() == 32 => bytes.try_into().unwrap(),
            _ => return (false, None, Some("Invalid transfer_id".to_string())),
        };

        // Parse signature
        let signature = match hex::decode(signature_hex)
            .ok()
            .and_then(|bytes| Signature::from_slice(&bytes).ok())
        {
            Some(sig) => sig,
            None => return (false, None, Some("Invalid signature".to_string())),
        };

        // Get ledger and verify source deposit exists
        let ledger_id = &request.ledger_id;
        let (deposit_descriptor, deposit_pubkey) = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let ledger_arc = match ledgers.get(ledger_id) {
                Some(l) => l.clone(),
                None => return (false, None, Some(format!("Ledger not found: {}", ledger_id))),
            };
            let ledger = ledger_arc.read().unwrap();

            let deposit = match ledger.state.deposits.get(&source_deposit_id) {
                Some(d) => d,
                None => return (false, None, Some("Source deposit not found".to_string())),
            };

            // Validate fee against deposit's transfer fee schedule
            let expected_fee = deposit.transfer_fees.calculate_fee(amount);
            if fee != expected_fee {
                return (false, None, Some(format!(
                    "Fee mismatch: expected {} sats (fixed={} + {}bps on {}), got {}",
                    expected_fee, deposit.transfer_fees.fixed_sats,
                    deposit.transfer_fees.rate_bps, amount, fee
                )));
            }

            // Check sufficient balance
            let total = (amount + fee) * 1000; // Convert to msats
            if deposit.balance < total {
                let balance_json = format!("{{\"balance_msats\":{}}}", deposit.balance);
                return (false, Some(balance_json), Some(format!(
                    "Insufficient balance: {} msats available, {} msats needed",
                    deposit.balance, total
                )));
            }

            (deposit.descriptor.clone(), deposit.descriptor.clone())
        };

        // Verify signature
        let secp = Secp256k1::new();
        let msg_hash = deposits_core::signature_utils::transfer_lock_signing_message(
            &nonce,
            &source_deposit_id,
            &destination_deposit_id,
            amount,
            fee,
            completion_script,
            timeout_height,
        );

        // Extract pubkey from descriptor for verification
        let pubkey = if deposit_descriptor.starts_with("pk(") {
            let pk_hex = &deposit_descriptor[3..deposit_descriptor.len()-1];
            match hex::decode(pk_hex).ok().and_then(|b| bitcoin::secp256k1::PublicKey::from_slice(&b).ok()) {
                Some(pk) => pk.x_only_public_key().0,
                None => return (false, None, Some("Invalid pubkey in descriptor".to_string())),
            }
        } else {
            return (false, None, Some("Only pk() descriptors supported for transfers".to_string()));
        };

        let msg = Message::from_digest(msg_hash);
        if secp.verify_schnorr(&signature, &msg, &pubkey).is_err() {
            return (false, None, Some("Invalid signature".to_string()));
        }

        // Create and append the operation
        let amount_msats = amount * 1000;
        let fee_msats = fee * 1000;
        let witness = DescriptorWitness { stack: vec![signature.serialize().to_vec()] };
        let operation = LedgerOperation::TransferLock {
            nonce,
            source_deposit_id,
            destination_deposit_id,
            amount: amount_msats,
            fee: fee_msats,
            completion_script: completion_script.to_string(),
            timeout_height,
            transfer_id,
            witness,
        };

        // Append operation (applies state changes: deducts balance, adds to locked)
        let t_append = std::time::Instant::now();
        {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let ledger_arc = ledgers.get(ledger_id).unwrap().clone();
            let mut ledger = ledger_arc.write().unwrap();

            let block_height = self.wallet.get_block_height().unwrap_or(0);
            let block_hash = self.wallet.get_block_hash().unwrap_or([0u8; 32]);
            if let Err(e) = ledger.append_operation_with_block(
                operation,
                deposits_core::messages::consts::TRANSFER_LOCK,
                block_height,
                block_hash,
            ) {
                return (false, None, Some(format!("Failed to append operation: {:?}", e)));
            }
        }
        let append_elapsed = t_append.elapsed();

        // Sign (with co-signature if quorum active) and broadcast
        let t_sign = std::time::Instant::now();
        if let Err(e) = self.sign_and_broadcast(ledger_id).await {
            // Rollback: undo the state changes from the failed operation.
            // The operation was appended and state modified (balance deducted, locked increased)
            // but signing failed, so we must restore the previous state.
            tracing::warn!("sign_and_broadcast failed for transfer_lock, rolling back state: {}", e);
            {
                let ledgers = self.handler.ledgers.lock().unwrap();
                let ledger_arc = ledgers.get(ledger_id).unwrap().clone();
                let mut ledger = ledger_arc.write().unwrap();
                // Pop the unsigned operation from history
                ledger.history.pop();
                // Undo TransferLock state changes
                let total_msats = amount_msats + fee_msats;
                if let Some(deposit) = ledger.state.deposits.get_mut(&source_deposit_id) {
                    deposit.balance = deposit.balance.saturating_add(total_msats);
                    deposit.locked_balance = deposit.locked_balance.saturating_sub(total_msats);
                }
                ledger.state.pending_transfers.remove(&transfer_id);
                // Restore sequence and hash from the last remaining entry
                let (seq, hash) = ledger.history.last()
                    .map(|l| (l.sequence_number, l.current_hash))
                    .unwrap_or((0, [0u8; 32]));
                ledger.state.sequence = seq;
                ledger.state.hash = hash;
            }
            return (false, None, Some(format!("Failed to sign/broadcast: {:?}", e)));
        }

        let sign_elapsed = t_sign.elapsed();

        // Persist to disk
        let t_persist = std::time::Instant::now();
        if let Err(e) = self.handler.persist_ledger_to_disk(ledger_id) {
            tracing::warn!("Failed to persist ledger after transfer_lock: {}", e);
        }
        let persist_elapsed = t_persist.elapsed();

        tracing::info!("Transfer locked: {}", hex::encode(&transfer_id[..8]));
        tracing::info!("[PROFILE] transfer_lock breakdown: append={:?}, sign_broadcast={:?}, persist={:?}",
            append_elapsed, sign_elapsed, persist_elapsed);
        (true, Some(serde_json::json!({
            "transfer_id": transfer_id_hex,
            "amount": amount,
            "fee": fee,
            "message": "Transfer locked successfully"
        }).to_string()), None)
    }

    /// Process a transfer_complete request - complete a transfer by revealing preimage
    async fn process_transfer_complete_request(&mut self, request: &crate::nostr::LedgerRequest) -> (bool, Option<String>, Option<String>) {
        use deposits_core::types::DescriptorWitness;
        use deposits_core::messages::LedgerOperation;

        tracing::info!("Processing transfer_complete request for ledger {}...",
            &request.ledger_id[..16.min(request.ledger_id.len())]);

        // Extract parameters
        let transfer_id_hex = match request.params.get("transfer_id").and_then(|v| v.as_str()) {
            Some(t) => t,
            None => return (false, None, Some("Missing transfer_id".to_string())),
        };
        let preimage_hex = match request.params.get("preimage").and_then(|v| v.as_str()) {
            Some(p) => p,
            None => return (false, None, Some("Missing preimage".to_string())),
        };

        // Parse transfer_id
        let transfer_id: [u8; 32] = match hex::decode(transfer_id_hex) {
            Ok(bytes) if bytes.len() == 32 => bytes.try_into().unwrap(),
            _ => return (false, None, Some("Invalid transfer_id".to_string())),
        };

        // Parse preimage
        let preimage: Vec<u8> = match hex::decode(preimage_hex) {
            Ok(bytes) if bytes.len() == 32 => bytes,
            _ => return (false, None, Some("Invalid preimage (must be 32 bytes)".to_string())),
        };

        // Verify the preimage matches the hash in the pending transfer
        let ledger_id = &request.ledger_id;
        {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let ledger_arc = match ledgers.get(ledger_id) {
                Some(l) => l.clone(),
                None => return (false, None, Some(format!("Ledger not found: {}", ledger_id))),
            };
            let ledger = ledger_arc.read().unwrap();

            let pending = match ledger.state.pending_transfers.get(&transfer_id) {
                Some(p) => p,
                None => return (false, None, Some("Pending transfer not found".to_string())),
            };

            // Verify preimage: hash it and check against completion_script
            // completion_script is like "sha256(abc123...)"
            if pending.completion_script.starts_with("sha256(") {
                let expected_hash_hex = &pending.completion_script[7..pending.completion_script.len()-1];
                let expected_hash = match hex::decode(expected_hash_hex) {
                    Ok(h) => h,
                    Err(_) => return (false, None, Some("Invalid hash in completion_script".to_string())),
                };

                use bitcoin::hashes::{sha256, Hash};
                let actual_hash = sha256::Hash::hash(&preimage);
                if actual_hash.as_byte_array()[..] != expected_hash[..] {
                    return (false, None, Some("Preimage does not match hash".to_string()));
                }
            } else {
                return (false, None, Some("Only sha256() completion scripts supported".to_string()));
            }
        }

        // Capture pending transfer info before appending (needed for rollback)
        let pending_transfer_backup = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let ledger_arc = ledgers.get(ledger_id).unwrap().clone();
            let ledger = ledger_arc.read().unwrap();
            ledger.state.pending_transfers.get(&transfer_id).cloned()
        };

        // Create and append the operation
        let script_witness = DescriptorWitness { stack: vec![preimage] };
        let operation = LedgerOperation::TransferComplete {
            transfer_id,
            script_witness,
        };

        // Append operation (applies state changes: unlocks source, credits destination)
        {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let ledger_arc = ledgers.get(ledger_id).unwrap().clone();
            let mut ledger = ledger_arc.write().unwrap();

            let block_height = self.wallet.get_block_height().unwrap_or(0);
            let block_hash = self.wallet.get_block_hash().unwrap_or([0u8; 32]);
            if let Err(e) = ledger.append_operation_with_block(
                operation,
                deposits_core::messages::consts::TRANSFER_COMPLETE,
                block_height,
                block_hash,
            ) {
                return (false, None, Some(format!("Failed to append operation: {:?}", e)));
            }
        }

        // Sign (with co-signature if quorum active) and broadcast
        if let Err(e) = self.sign_and_broadcast(ledger_id).await {
            // Rollback: undo TransferComplete state changes
            tracing::warn!("sign_and_broadcast failed for transfer_complete, rolling back state: {}", e);
            if let Some(pending) = pending_transfer_backup {
                let ledgers = self.handler.ledgers.lock().unwrap();
                let ledger_arc = ledgers.get(ledger_id).unwrap().clone();
                let mut ledger = ledger_arc.write().unwrap();
                // Pop the unsigned operation from history
                ledger.history.pop();
                // Undo TransferComplete state changes: re-lock source, debit destination
                let total = pending.total_locked();
                if let Some(source) = ledger.state.deposits.get_mut(&pending.source_deposit_id) {
                    source.locked_balance = source.locked_balance.saturating_add(total);
                }
                if let Some(dest) = ledger.state.deposits.get_mut(&pending.destination_deposit_id) {
                    dest.balance = dest.balance.saturating_sub(pending.amount);
                }
                // Re-insert the pending transfer
                ledger.state.pending_transfers.insert(transfer_id, pending);
                // Restore sequence and hash
                let (seq, hash) = ledger.history.last()
                    .map(|l| (l.sequence_number, l.current_hash))
                    .unwrap_or((0, [0u8; 32]));
                ledger.state.sequence = seq;
                ledger.state.hash = hash;
            }
            return (false, None, Some(format!("Failed to sign/broadcast: {:?}", e)));
        }

        // Persist to disk
        if let Err(e) = self.handler.persist_ledger_to_disk(ledger_id) {
            tracing::warn!("Failed to persist ledger after transfer_complete: {}", e);
        }

        tracing::info!("Transfer completed: {}", hex::encode(&transfer_id[..8]));
        let (completed_amount, completed_fee) = pending_transfer_backup
            .as_ref()
            .map(|p| (p.amount, p.fee))
            .unwrap_or((0, 0));
        (true, Some(serde_json::json!({
            "transfer_id": transfer_id_hex,
            "amount": completed_amount,
            "fee": completed_fee,
            "message": "Transfer completed successfully"
        }).to_string()), None)
    }

    async fn process_collateral_lock_request(&mut self, request: &crate::nostr::LedgerRequest) -> (bool, Option<String>, Option<String>) {
        use bitcoin::secp256k1::SecretKey;
        use std::str::FromStr;

        tracing::info!("Processing collateral_lock request for ledger {}...",
            &request.ledger_id[..16.min(request.ledger_id.len())]);

        // Resolve to ledger_id (handles both hash and reserves_key formats)
        let ledger_id = match self.resolve_to_ledger_id(&request.ledger_id) {
            Ok(lid) => lid,
            Err(e) => return (false, None, Some(e)),
        };

        // Extract deposit_secret from params
        let deposit_secret_hex = match request.params.get("deposit_secret") {
            Some(serde_json::Value::String(s)) => s.clone(),
            _ => return (false, None, Some("Missing deposit_secret parameter".to_string())),
        };

        let secret_bytes = match hex::decode(&deposit_secret_hex) {
            Ok(b) => b,
            Err(e) => return (false, None, Some(format!("Invalid deposit_secret hex: {}", e))),
        };

        let deposit_secret = match SecretKey::from_slice(&secret_bytes) {
            Ok(s) => s,
            Err(e) => return (false, None, Some(format!("Invalid deposit_secret: {}", e))),
        };

        // Derive the deposit pubkey from the secret and create descriptor
        let secp = Secp256k1::new();
        let deposit_pubkey = PublicKey::from_secret_key(&secp, &deposit_secret);
        let descriptor = format!("pk({})", hex::encode(deposit_pubkey.serialize()));

        // Extract required parameters
        let amount_msats = match request.params.get("amount_msats").and_then(|v| v.as_u64()) {
            Some(v) => v,
            None => return (false, None, Some("Missing amount_msats parameter".to_string())),
        };

        let lock_blocks = match request.params.get("lock_blocks").and_then(|v| v.as_u64()) {
            Some(v) => v as u32,
            None => return (false, None, Some("Missing lock_blocks parameter".to_string())),
        };

        // Get current block height and compute lock_until_block
        let current_block = match self.wallet.get_block_height() {
            Ok(h) => h,
            Err(e) => return (false, None, Some(format!("Failed to get block height: {}", e))),
        };
        let lock_until_block = current_block + lock_blocks;

        // Parse requesting operator (defaults to our node_id for self-request)
        let requesting_operator = if let Some(serde_json::Value::String(hex)) = request.params.get("requesting_operator") {
            match PublicKey::from_str(hex) {
                Ok(pk) => pk,
                Err(e) => return (false, None, Some(format!("Invalid requesting_operator: {}", e))),
            }
        } else {
            // Default to our own node_id (self-request)
            self.node_id
        };

        // Lock the collateral (now includes co-signing and broadcast)
        match self.lock_collateral(
            &ledger_id,
            &descriptor,
            &deposit_secret,
            amount_msats,
            lock_until_block,
            requesting_operator,
        ).await {
            Ok(attestation) => {
                // Serialize attestation as JSON then base64 encode
                use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
                let attestation_json = serde_json::to_string(&attestation).unwrap_or_default();
                let attestation_b64 = BASE64.encode(attestation_json.as_bytes());
                let result = serde_json::json!({
                    "amount": attestation.amount,
                    "lock_until_block": attestation.lock_until_block,
                    "quorum_member": attestation.quorum_member.to_string(),
                    "attestation_b64": attestation_b64,
                });
                tracing::info!("Collateral locked: {} msats until block {}", amount_msats, lock_until_block);
                (true, Some(result.to_string()), None)
            }
            Err(e) => {
                tracing::warn!("Failed to lock collateral: {}", e);
                (false, None, Some(e.to_string()))
            }
        }
    }

    /// Process a co-sign request from an operator.
    ///
    /// When another operator wants to update their ledger where we are a quorum member,
    /// they send us a co-sign request. We validate the update and return our ECDSA signature.
    ///
    /// The signature covers: partner_signing_data || our_ledger_current_hash
    /// This binds the co-signature to the current state of our own ledger.
    async fn process_cosign_request(&self, request: &crate::nostr::LedgerRequest) -> (bool, Option<String>, Option<String>) {
        use bitcoin::hashes::{sha256, Hash};
        use bitcoin::secp256k1::{Message, Secp256k1};
        use std::str::FromStr;

        tracing::info!("Processing cosign_update request for ledger {}...",
            &request.ledger_id[..16.min(request.ledger_id.len())]);

        // Extract required parameters
        let sequence_number = match request.params.get("sequence_number").and_then(|v| v.as_u64()) {
            Some(seq) => seq,
            None => return (false, None, Some("Missing sequence_number parameter".to_string())),
        };

        let partner_signing_data_hex = match request.params.get("partner_signing_data_hex").and_then(|v| v.as_str()) {
            Some(hex) => hex.to_string(),
            None => return (false, None, Some("Missing partner_signing_data_hex parameter".to_string())),
        };

        let current_hash_hex = match request.params.get("current_hash_hex").and_then(|v| v.as_str()) {
            Some(hex) => hex.to_string(),
            None => return (false, None, Some("Missing current_hash_hex parameter".to_string())),
        };

        // Decode partner signing data
        let partner_signing_data = match hex::decode(&partner_signing_data_hex) {
            Ok(data) => data,
            Err(e) => return (false, None, Some(format!("Invalid partner_signing_data_hex: {}", e))),
        };

        // Decode current hash (used for validation logging)
        let _current_hash: [u8; 32] = match hex::decode(&current_hash_hex) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                arr
            }
            Ok(_) => return (false, None, Some("current_hash_hex must be 32 bytes".to_string())),
            Err(e) => return (false, None, Some(format!("Invalid current_hash_hex: {}", e))),
        };

        // Find the operator's ledger where we are a quorum member (for sequence validation)
        // Get the target ledger and extract operator/reserves for matching
        let (operator_ledger_arc, target_operator_id, target_reserves_key) = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            if let Some(arc) = ledgers.get(&request.ledger_id) {
                let ledger = arc.read().unwrap();
                (Some(arc.clone()), Some(ledger.operator_key()), Some(ledger.reserves_key().to_string()))
            } else {
                (None, None, None)
            }
        };

        // If we don't have the ledger locally, get the operator from the request sender
        // The sender of a cosign_update request IS the operator who needs the co-signature
        let target_operator_id = if target_operator_id.is_none() {
            // The request.sender is a Nostr x-only pubkey (32 bytes / 64 hex chars)
            // We need to convert to secp256k1 PublicKey (33 bytes with 02/03 prefix)
            match hex::decode(&request.sender) {
                Ok(x_only_bytes) if x_only_bytes.len() == 32 => {
                    // Convert x-only to compressed pubkey (assume even y-coordinate)
                    let mut compressed = [0u8; 33];
                    compressed[0] = 0x02;
                    compressed[1..].copy_from_slice(&x_only_bytes);
                    match PublicKey::from_slice(&compressed) {
                        Ok(sender_key) => {
                            tracing::debug!("Using request sender as target operator: {}...", &request.sender[..16]);
                            Some(sender_key)
                        }
                        Err(e) => {
                            tracing::warn!("Failed to parse sender as pubkey: {}", e);
                            None
                        }
                    }
                }
                _ => {
                    tracing::warn!("Invalid sender pubkey format: {}", &request.sender[..16.min(request.sender.len())]);
                    None
                }
            }
        } else {
            target_operator_id
        };

        // Note: We don't strictly need target_reserves_key for matching
        // We can match by operator_id alone since each operator has one ledger

        // Validate sequence number if we have local ledger state
        if let Some(ref arc) = operator_ledger_arc {
            let ledger = arc.read().unwrap();
            let expected_seq = ledger.history.len() as u64;
            if sequence_number != expected_seq {
                return (false, None, Some(format!(
                    "Sequence mismatch: expected {}, got {}",
                    expected_seq, sequence_number
                )));
            }

            if let Some(last_update) = ledger.history.last() {
                let prev_hash = last_update.current_hash;
                tracing::debug!("Validating co-sign for seq {} (prev_hash: {}...)",
                    sequence_number, &hex::encode(&prev_hash[..4]));
            }
        }

        // Auto-detect which of OUR ledgers is bound to the requesting ledger.
        // We look for a ledger where we are the operator AND we have a QuorumJoin
        // pointing to the target operator/reserves_key.
        let member_ledger_hash: [u8; 32] = {
            let t_scan = std::time::Instant::now();
            let ledgers = self.handler.ledgers.lock().unwrap();
            let mut found_hash = None;

            for (_ledger_id, arc) in ledgers.iter() {
                let ledger = arc.read().unwrap();

                // Only look at ledgers where we are the operator
                if ledger.operator_key() != self.node_id {
                    continue;
                }

                // Check if this ledger has a QuorumJoin pointing to the target operator
                // Scan history because state.joined_quorums may not be populated after deserialization
                // Compare x-coordinates only (Nostr uses x-only pubkeys, so we can't know the y parity)
                let history_len = ledger.history.len();
                let has_join = ledger.history.iter().any(|update| {
                    if update.message_type != deposits_core::messages::consts::QUORUM_JOIN {
                        return false;
                    }
                    if let Ok(LedgerOperation::QuorumJoin { operator_id, .. }) =
                        LedgerOperation::tlv_decode(&update.message)
                    {
                        if let Some(target_op) = &target_operator_id {
                            // Compare the x-coordinate (bytes 1-32 of compressed pubkey)
                            let jq_x = &operator_id.serialize()[1..];
                            let target_x = &target_op.serialize()[1..];
                            if jq_x == target_x {
                                tracing::debug!("Found QuorumJoin in history matching operator (x-only match)");
                                return true;
                            }
                        }
                    }
                    false
                });

                let scan_elapsed = t_scan.elapsed();
                if scan_elapsed.as_millis() > 0 {
                    tracing::info!("[PROFILE] cosign QuorumJoin scan: {} entries in {:?}", history_len, scan_elapsed);
                }

                if has_join {
                    // Get current hash from the last update, or all zeros if no updates
                    found_hash = Some(
                        ledger.history.last()
                            .map(|u| u.current_hash)
                            .unwrap_or([0u8; 32])
                    );
                    let ledger_id_hex = ledger.ledger_id_hex();
                    tracing::debug!("Auto-detected member ledger {} with hash {}...",
                        &ledger_id_hex[..16], &hex::encode(&found_hash.unwrap()[..4]));
                    break;
                }
            }

            match found_hash {
                Some(h) => h,
                None => return (false, None, Some(
                    "No ledger found with QuorumJoin to target - not a quorum member".to_string()
                )),
            }
        };

        // Build tagged hash following BIP-340 convention:
        // sha256(sha256(tag) || sha256(tag) || data)
        // This provides domain separation and prevents cross-protocol attacks
        let tag = b"deposits/cosign";
        let tag_hash = sha256::Hash::hash(tag);

        let mut tagged_input = Vec::new();
        tagged_input.extend_from_slice(tag_hash.as_byte_array());
        tagged_input.extend_from_slice(tag_hash.as_byte_array());
        tagged_input.extend_from_slice(&partner_signing_data);
        tagged_input.extend_from_slice(&member_ledger_hash);

        let hash = sha256::Hash::hash(&tagged_input);

        // Sign with ECDSA
        let secp = Secp256k1::new();
        let msg = Message::from_digest(hash.to_byte_array());
        let secret = self.wallet.operator_secret();
        let sig = secp.sign_ecdsa(&msg, &secret);
        let sig_bytes = sig.serialize_compact();

        tracing::info!("Co-signed update seq={} for ledger {}... (member_ledger_hash: {}...)",
            sequence_number, &request.ledger_id[..16], &hex::encode(&member_ledger_hash[..4]));

        // Return the signature, our pubkey, and our ledger hash
        let result = serde_json::json!({
            "partner_signature_hex": hex::encode(sig_bytes),
            "cosigner_pubkey": self.node_id.to_string(),
            "sequence_number": sequence_number,
            "member_ledger_hash_hex": hex::encode(member_ledger_hash),
        });

        (true, Some(result.to_string()), None)
    }

    /// Process a cosign_offer request from an operator.
    ///
    /// This is called by quorum members when an operator needs a co-signature
    /// on a deposit offer. The co-signature proves the operator has valid
    /// quorum backing, preventing rogue former operators from creating offers
    /// after custody recovery.
    ///
    /// Params:
    /// - offer_id: hex-encoded 32-byte offer ID
    /// - operator_id: hex-encoded compressed public key of the operator
    /// - funding_address: the Bitcoin address for the deposit
    /// - deadline_block: block height when offer expires
    async fn process_cosign_offer_request(&self, request: &crate::nostr::LedgerRequest) -> (bool, Option<String>, Option<String>) {
        use bitcoin::hashes::{sha256, Hash};
        use bitcoin::secp256k1::{Message, Secp256k1};
        use std::str::FromStr;

        tracing::info!("Processing cosign_offer request for ledger {}...",
            &request.ledger_id[..16.min(request.ledger_id.len())]);

        // Extract required parameters
        let offer_id_hex = match request.params.get("offer_id").and_then(|v| v.as_str()) {
            Some(id) => id.to_string(),
            None => return (false, None, Some("Missing offer_id parameter".to_string())),
        };

        let offer_id: [u8; 32] = match hex::decode(&offer_id_hex) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                arr
            }
            Ok(_) => return (false, None, Some("offer_id must be 32 bytes".to_string())),
            Err(e) => return (false, None, Some(format!("Invalid offer_id hex: {}", e))),
        };

        let operator_id_hex = match request.params.get("operator_id").and_then(|v| v.as_str()) {
            Some(id) => id.to_string(),
            None => return (false, None, Some("Missing operator_id parameter".to_string())),
        };

        let operator_id = match PublicKey::from_str(&operator_id_hex) {
            Ok(pk) => pk,
            Err(e) => return (false, None, Some(format!("Invalid operator_id: {}", e))),
        };

        let funding_address = match request.params.get("funding_address").and_then(|v| v.as_str()) {
            Some(addr) => addr.to_string(),
            None => return (false, None, Some("Missing funding_address parameter".to_string())),
        };

        let deadline_block = match request.params.get("deadline_block").and_then(|v| v.as_u64()) {
            Some(b) => b as u32,
            None => return (false, None, Some("Missing deadline_block parameter".to_string())),
        };

        // Get the target operator from the request sender
        let target_operator_id = match hex::decode(&request.sender) {
            Ok(x_only_bytes) if x_only_bytes.len() == 32 => {
                // Convert x-only to compressed pubkey (assume even y-coordinate)
                let mut compressed = [0u8; 33];
                compressed[0] = 0x02;
                compressed[1..].copy_from_slice(&x_only_bytes);
                match PublicKey::from_slice(&compressed) {
                    Ok(sender_key) => Some(sender_key),
                    Err(_) => None,
                }
            }
            _ => None,
        };

        // Auto-detect which of OUR ledgers is bound to the requesting ledger.
        // We look for a ledger where we are the operator AND we have a QuorumJoin
        // pointing to the target operator.
        let member_ledger_hash: [u8; 32] = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let mut found_hash = None;

            for (_ledger_id, arc) in ledgers.iter() {
                let ledger = arc.read().unwrap();

                // Only look at ledgers where we are the operator
                if ledger.operator_key() != self.node_id {
                    continue;
                }

                // Check if this ledger has a QuorumJoin pointing to the target operator
                let has_join = ledger.history.iter().any(|update| {
                    if update.message_type != deposits_core::messages::consts::QUORUM_JOIN {
                        return false;
                    }
                    if let Ok(LedgerOperation::QuorumJoin { operator_id: join_op, .. }) =
                        LedgerOperation::tlv_decode(&update.message)
                    {
                        if let Some(target_op) = &target_operator_id {
                            // Compare the x-coordinate (bytes 1-32 of compressed pubkey)
                            let jq_x = &join_op.serialize()[1..];
                            let target_x = &target_op.serialize()[1..];
                            if jq_x == target_x {
                                return true;
                            }
                        }
                    }
                    false
                });

                if has_join {
                    found_hash = Some(
                        ledger.history.last()
                            .map(|u| u.current_hash)
                            .unwrap_or([0u8; 32])
                    );
                    break;
                }
            }

            match found_hash {
                Some(h) => h,
                None => return (false, None, Some(
                    "No ledger found with QuorumJoin to target - not a quorum member".to_string()
                )),
            }
        };

        // Build the offer signing data
        let signing_data = Self::build_offer_signing_data(
            &request.ledger_id,
            &offer_id,
            &operator_id,
            &funding_address,
            deadline_block,
        );

        // Build tagged hash following BIP-340 convention
        let tag = b"deposits/offer_cosign";
        let tag_hash = sha256::Hash::hash(tag);

        let mut tagged_input = Vec::new();
        tagged_input.extend_from_slice(tag_hash.as_byte_array());
        tagged_input.extend_from_slice(tag_hash.as_byte_array());
        tagged_input.extend_from_slice(&signing_data);
        tagged_input.extend_from_slice(&member_ledger_hash);

        let hash = sha256::Hash::hash(&tagged_input);

        // Sign with ECDSA
        let secp = Secp256k1::new();
        let msg = Message::from_digest(hash.to_byte_array());
        let secret = self.wallet.operator_secret();
        let sig = secp.sign_ecdsa(&msg, &secret);
        let sig_bytes = sig.serialize_compact();

        tracing::info!("Co-signed offer {} for ledger {}... (member_ledger_hash: {}...)",
            &offer_id_hex[..16], &request.ledger_id[..16], &hex::encode(&member_ledger_hash[..4]));

        // Return the signature, our pubkey, and our ledger hash
        let result = serde_json::json!({
            "signature_hex": hex::encode(sig_bytes),
            "cosigner_pubkey": self.node_id.to_string(),
            "member_ledger_hash_hex": hex::encode(member_ledger_hash),
        });

        (true, Some(result.to_string()), None)
    }

    async fn process_custody_transfer_sign_request(&self, request: &crate::nostr::LedgerRequest) -> (bool, Option<String>, Option<String>) {
        use bitcoin::secp256k1::{Keypair, Message};
        use deposits_core::SignedLedgerUpdate;
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
        use nostr_sdk::prelude::*;
        use crate::nostr::KIND_LEDGER_UPDATE;

        tracing::info!("Processing custody_transfer_sign request...");

        // Extract required parameters
        let ledger_id = match request.params.get("ledger_id").and_then(|v| v.as_str()) {
            Some(id) => id.to_string(),
            None => return (false, None, Some("Missing ledger_id parameter".to_string())),
        };

        let sighash_hex = match request.params.get("sighash").and_then(|v| v.as_str()) {
            Some(h) => h.to_string(),
            None => return (false, None, Some("Missing sighash parameter".to_string())),
        };

        let _unsigned_tx_hex = match request.params.get("unsigned_tx").and_then(|v| v.as_str()) {
            Some(tx) => tx.to_string(),
            None => return (false, None, Some("Missing unsigned_tx parameter".to_string())),
        };

        let new_custodian_hex = match request.params.get("new_custodian").and_then(|v| v.as_str()) {
            Some(c) => c.to_string(),
            None => return (false, None, Some("Missing new_custodian parameter".to_string())),
        };

        let violation_details = match request.params.get("violation_details").and_then(|v| v.as_str()) {
            Some(d) => d.to_string(),
            None => return (false, None, Some("Missing violation_details parameter".to_string())),
        };

        let last_valid_sequence = match request.params.get("last_valid_sequence").and_then(|v| v.as_u64()) {
            Some(seq) => seq,
            None => return (false, None, Some("Missing last_valid_sequence parameter".to_string())),
        };

        // Parse sighash
        let sighash_bytes: [u8; 32] = match hex::decode(&sighash_hex) {
            Ok(b) if b.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b);
                arr
            }
            Ok(_) => return (false, None, Some("Invalid sighash length".to_string())),
            Err(e) => return (false, None, Some(format!("Invalid sighash hex: {}", e))),
        };

        // Parse new custodian (validated but not directly used in signing)
        let _new_custodian: PublicKey = match new_custodian_hex.parse() {
            Ok(pk) => pk,
            Err(e) => return (false, None, Some(format!("Invalid new_custodian: {}", e))),
        };

        tracing::info!("    Ledger: {}...", &ledger_id[..16.min(ledger_id.len())]);
        tracing::info!("    New custodian: {}...", &new_custodian_hex[..16.min(new_custodian_hex.len())]);
        tracing::info!("    Violation: {}", &violation_details[..50.min(violation_details.len())]);

        // Use the node's operator key
        let secp = Secp256k1::new();
        let secret_key = self.wallet.operator_secret();
        let keypair = Keypair::from_secret_key(&secp, &secret_key);
        let our_pubkey = self.node_id;

        tracing::info!("    Our key: {}...", &our_pubkey.to_string()[..16]);

        // Use the existing nostr client
        let client = self.nostr.client();

        let filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_UPDATE))
            .custom_tag(SingleLetterTag::lowercase(Alphabet::D), [ledger_id.as_str()])
            .limit(500);

        let events = match client.fetch_events(vec![filter], None).await {
            Ok(e) => e,
            Err(e) => {
                return (false, None, Some(format!("Failed to fetch ledger: {}", e)));
            }
        };

        // Decode and validate updates
        let mut updates: Vec<SignedLedgerUpdate> = Vec::new();
        for event in events.iter() {
            if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
                if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                    updates.push(update);
                }
            }
        }

        updates.sort_by_key(|u| (u.sequence_number, u.operator_id));
        updates.dedup_by(|a, b| a.sequence_number == b.sequence_number && a.operator_id == b.operator_id && a.current_hash == b.current_hash);

        // Find the original operator (the one who opened the ledger)
        let original_operator = updates.iter()
            .find(|u| u.sequence_number == 0)
            .map(|u| u.operator_id);

        let original_operator = match original_operator {
            Some(op) => op,
            None => return (false, None, Some("Could not find ledger genesis (sequence 0)".to_string())),
        };

        // Filter to only the original operator's updates for violation validation
        let original_updates: Vec<&SignedLedgerUpdate> = updates.iter()
            .filter(|u| u.operator_id == original_operator)
            .collect();

        // Verify the violation exists on the original operator's chain
        let mut last_valid_hash = [0u8; 32];
        let mut found_violation = false;
        let mut validated_sequence: i64 = -1;

        for update in &original_updates {
            let expected_seq = (validated_sequence + 1) as u64;
            if update.sequence_number != expected_seq && validated_sequence >= 0 {
                found_violation = true;
                break;
            }

            let expected_prev = if update.sequence_number == 0 {
                [0u8; 32]
            } else {
                last_valid_hash
            };

            if update.previous_hash != expected_prev {
                found_violation = true;
                break;
            }

            let computed_hash = update.compute_hash();
            if computed_hash != update.current_hash {
                found_violation = true;
                break;
            }

            last_valid_hash = update.current_hash;
            validated_sequence = update.sequence_number as i64;
        }

        if !found_violation {
            return (false, None, Some("Could not verify violation - ledger appears conforming".to_string()));
        }

        // Verify that the last_valid_sequence matches our validation
        if validated_sequence != last_valid_sequence as i64 {
            return (false, None, Some(format!(
                "Sequence mismatch: requester says {}, we validated {}",
                last_valid_sequence, validated_sequence
            )));
        }

        tracing::info!("    Violation verified at seq {}", validated_sequence + 1);

        // Verify we're a quorum member by checking the ledger operations
        let mut is_quorum_member = false;
        for update in updates.iter().take((validated_sequence + 1) as usize) {
            if let Ok(operation) = LedgerOperation::tlv_decode(&update.message) {
                match operation {
                    LedgerOperation::QuorumAddMember { quorum_member, .. } => {
                        if quorum_member == our_pubkey {
                            is_quorum_member = true;
                        }
                    }
                    _ => {}
                }
            }
        }

        if !is_quorum_member {
            return (false, None, Some("We are not a quorum member for this ledger".to_string()));
        }

        tracing::info!("    Verified: we are a quorum member");

        // Sign the sighash
        let msg = Message::from_digest(sighash_bytes);
        let signature = secp.sign_schnorr(&msg, &keypair);
        let signature_bytes = signature.serialize();

        tracing::info!("    Signed sighash: {}...", &hex::encode(&signature_bytes[..4]));

        // Return the signature
        let result = serde_json::json!({
            "signer": our_pubkey.to_string(),
            "signature": hex::encode(signature_bytes),
            "sighash": sighash_hex,
        });

        (true, Some(result.to_string()), None)
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
            .or_else(|| self.get_ledger_by_reserves_key(&request.ledger_id))
        {
            Some(l) => l,
            None => return (false, None, Some("Ledger not found".to_string())),
        };

        let custodian_hex = hex::encode(ledger.operator_key().serialize());
        let attester_hex = hex::encode(self.node_id.serialize());

        let result = serde_json::json!({
            "status": "SUCCESS",
            "custodian": custodian_hex,
            "attester": attester_hex,
            "reserves_id": reserves_id,
            "ledger_id": ledger.ledger_id_hex(),
        });
        (true, Some(result.to_string()), None)
    }

    // ========================================================================
    // Auto-Response Tasks
    // ========================================================================

    /// Auto-complete deposits that have been funded on-chain
    pub async fn auto_complete_deposits(&mut self) {
        use deposits_core::types::DepositOfferStatus;

        let offers = self.list_deposit_offers();
        let pending: Vec<_> = offers.iter()
            .filter(|(_, status)| matches!(status, DepositOfferStatus::Pending))
            .collect();

        if pending.is_empty() {
            return;
        }

        // Sync wallet ONCE before checking all offers (not per-offer)
        if let Err(e) = self.wallet.sync() {
            tracing::warn!("Wallet sync failed in auto_complete_deposits: {}", e);
            return;
        }

        for (offer, _) in pending {
            let offer_id = offer.offer_id;

            // Skip offers for ledgers we don't have (e.g., daemon seeing CLI watcher's offers
            // for imported ledgers in the shared data directory)
            if self.get_ledger_by_ledger_id(&offer.ledger_id).is_none() {
                tracing::debug!(
                    "Skipping offer {}... for unknown ledger {}...",
                    hex::encode(&offer_id[..8]),
                    &offer.ledger_id[..16.min(offer.ledger_id.len())]
                );
                continue;
            }

            // Check if funded (skip_sync=true since we synced above)
            match self.check_deposit_offer_funding_inner(&offer_id, true) {
                Ok(Some((txid, amount_sats))) => {
                    tracing::info!(
                        "Auto-completing funded deposit: offer={}... txid={}... amount={} sats",
                        hex::encode(&offer_id[..8]),
                        &txid[..16.min(txid.len())],
                        amount_sats
                    );

                    // Complete the deposit with co-signing
                    match self.complete_deposit_offer(&offer_id, txid.clone(), amount_sats).await {
                        Ok(new_balance) => {
                            tracing::info!(
                                "Deposit completed! New balance: {} msats",
                                new_balance
                            );
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

    /// Auto-complete locked withdrawals by broadcasting their transactions
    pub async fn auto_complete_withdrawals(&mut self) {
        // Get all locked withdrawals
        let locked_withdrawals: Vec<([u8; 32], OnChainWithdrawal)> = {
            let withdrawals = self.withdrawals.lock().unwrap();
            withdrawals.iter()
                .filter_map(|(id, (w, status))| {
                    if matches!(status, OnChainWithdrawalStatus::Locked { .. }) {
                        Some((*id, w.clone()))
                    } else {
                        None
                    }
                })
                .collect()
        };

        if locked_withdrawals.is_empty() {
            return;
        }

        for (withdrawal_id, withdrawal) in locked_withdrawals {
            // Find the ledger for this withdrawal
            let ledger_id = {
                let ledgers = self.handler.ledgers.lock().unwrap();
                let mut found_id = None;
                for (lid, arc) in ledgers.iter() {
                    let ledger = arc.read().unwrap();
                    // Check if this ledger is operated by us
                    if ledger.operator_key() != self.node_id {
                        continue;
                    }
                    // Check if this ledger has the withdrawal's deposit
                    if ledger.state.deposits.contains_key(&withdrawal.deposit_id) {
                        found_id = Some(lid.clone());
                        break;
                    }
                }
                found_id
            };

            let Some(ledger_id) = ledger_id else {
                tracing::debug!(
                    "Could not find ledger for withdrawal {}...",
                    hex::encode(&withdrawal_id[..8])
                );
                continue;
            };

            tracing::info!(
                "Auto-completing locked withdrawal: id={}... to {} for {} sats",
                hex::encode(&withdrawal_id[..8]),
                &withdrawal.destination_address[..20.min(withdrawal.destination_address.len())],
                withdrawal.amount_sats
            );

            match self.complete_withdrawal(&ledger_id, &withdrawal_id).await {
                Ok(result) => {
                    tracing::info!(
                        "Withdrawal completed! txid={}, final balance={} msats",
                        &result.txid[..16.min(result.txid.len())],
                        result.final_balance_msats
                    );
                    // Sync wallet after each successful broadcast to update UTXO set
                    // This prevents subsequent withdrawals from trying to spend already-used UTXOs
                    if let Err(e) = self.sync_wallet() {
                        tracing::warn!("Wallet sync after withdrawal failed: {}", e);
                    }
                }
                Err(e) => {
                    tracing::error!(
                        "Failed to complete withdrawal {}...: {}",
                        hex::encode(&withdrawal_id[..8]),
                        e
                    );
                }
            }
        }
    }

    /// Auto-collect fees from deposits when due
    ///
    /// This checks all operated ledgers for deposits that have fees due (based on
    /// block height and fee collection frequency) and applies FeeCollect operations.
    pub async fn auto_collect_fees(&self) {
        let current_block = match self.wallet.get_block_height() {
            Ok(h) => h,
            Err(e) => {
                tracing::debug!("Failed to get block height for fee collection: {}", e);
                return;
            }
        };

        let block_hash = self.wallet.get_block_hash().unwrap_or([0u8; 32]);

        // Get operated ledgers (where we are the operator)
        let ledgers = self.handler.ledgers.lock().unwrap().clone();
        let operated: Vec<_> = ledgers.into_iter()
            .filter(|(_, arc)| arc.read().unwrap().operator_key() == self.node_id)
            .collect();

        for (ledger_id, ledger_arc) in operated {
            // Collect fees that are due
            let fee_ops: Vec<(DepositId, u64)> = {
                let ledger = ledger_arc.read().unwrap();
                ledger.state.deposits.iter()
                    .filter_map(|(deposit_id, deposit)| {
                        let fee = deposit.calculate_fees_due(current_block);
                        let available = deposit.balance.saturating_sub(deposit.locked_balance);
                        if fee > 0 && fee <= available {
                            Some((*deposit_id, fee))
                        } else {
                            None
                        }
                    })
                    .collect()
            };

            if fee_ops.is_empty() {
                continue;
            }

            // Apply each FeeCollect operation
            for (deposit_id, amount) in fee_ops {
                tracing::info!(
                    "Collecting fee: deposit={}... amount={} sats",
                    hex::encode(&deposit_id[..8]),
                    amount / 1000 // Convert msats to sats for logging
                );

                let operation = LedgerOperation::FeeCollect {
                    deposit_id,
                    amount,
                    block_height: current_block,
                };

                {
                    let mut ledger = ledger_arc.write().unwrap();
                    if let Err(e) = ledger.append_operation_with_block(
                        operation,
                        deposits_core::messages::consts::MAINTENANCE_FEE_COLLECT,
                        current_block,
                        block_hash,
                    ) {
                        tracing::warn!(
                            "Failed to collect fee from deposit {}...: {:?}",
                            hex::encode(&deposit_id[..8]),
                            e
                        );
                        continue;
                    }
                }

                // Sign the update
                if let Err(e) = self.sign_last_update(&ledger_id) {
                    tracing::warn!("Failed to sign fee collection update: {}", e);
                    continue;
                }

                // Validate chain before persisting
                if let Err(e) = self.validate_chain_before_persist(&ledger_id) {
                    tracing::warn!("Chain validation failed for fee collection: {}", e);
                    continue;
                }

                // Save ledger to disk
                if let Err(e) = self.handler.persist_ledger_to_disk(&ledger_id) {
                    tracing::warn!("Failed to save ledger after fee collection: {}", e);
                }

                // Broadcast to Nostr
                if let Err(e) = self.broadcast_last_update(&ledger_id).await {
                    tracing::warn!("Failed to broadcast fee collection: {}", e);
                }
            }
        }
    }

    /// Automatically timeout expired transfers.
    ///
    /// Scans all operated ledgers for pending transfers that have passed their
    /// timeout_height and issues TransferTimeout operations to return funds
    /// to the source deposits.
    pub async fn auto_timeout_transfers(&self) {
        use deposits_core::messages::LedgerOperation;

        let current_block = match self.wallet.get_block_height() {
            Ok(h) => h,
            Err(e) => {
                tracing::debug!("Failed to get block height for transfer timeout: {}", e);
                return;
            }
        };

        let block_hash = self.wallet.get_block_hash().unwrap_or([0u8; 32]);

        // Get operated ledgers (where we are the operator)
        let ledgers = self.handler.ledgers.lock().unwrap().clone();
        let operated: Vec<_> = ledgers.into_iter()
            .filter(|(_, arc)| arc.read().unwrap().operator_key() == self.node_id)
            .collect();

        for (ledger_id, ledger_arc) in operated {
            // Find expired transfers
            let expired_transfers: Vec<[u8; 32]> = {
                let ledger = ledger_arc.read().unwrap();
                ledger.state.pending_transfers.iter()
                    .filter(|(_, pending)| current_block >= pending.timeout_height)
                    .map(|(id, _)| *id)
                    .collect()
            };

            if expired_transfers.is_empty() {
                continue;
            }

            // Process only ONE timeout per periodic cycle. Timeouts are low priority
            // and each is a full ledger operation (append + sign + persist + broadcast).
            // Processing them in a batch starves transfer_lock/transfer_complete handling.
            // The next periodic cycle (5s) will pick up more.
            if let Some(&transfer_id) = expired_transfers.first() {
                // Re-check that the transfer is still pending (a complete may
                // have arrived since we collected the list)
                {
                    let ledger = ledger_arc.read().unwrap();
                    if !ledger.state.pending_transfers.contains_key(&transfer_id) {
                        continue;
                    }
                }

                if expired_transfers.len() > 1 {
                    tracing::info!(
                        "Processing 1 of {} expired transfers (rest deferred to next cycle)",
                        expired_transfers.len()
                    );
                }

                tracing::info!(
                    "Timing out expired transfer: {}... (block {} >= timeout)",
                    hex::encode(&transfer_id[..8]),
                    current_block
                );

                let operation = LedgerOperation::TransferTimeout {
                    transfer_id,
                    block_hash,
                };

                {
                    let mut ledger = ledger_arc.write().unwrap();
                    if let Err(e) = ledger.append_operation_with_block(
                        operation,
                        deposits_core::messages::consts::TRANSFER_TIMEOUT,
                        current_block,
                        block_hash,
                    ) {
                        tracing::warn!(
                            "Failed to timeout transfer {}...: {:?}",
                            hex::encode(&transfer_id[..8]),
                            e
                        );
                        continue;
                    }
                }

                // Sign the update
                if let Err(e) = self.sign_last_update(&ledger_id) {
                    tracing::warn!("Failed to sign transfer timeout update: {}", e);
                    continue;
                }

                // Validate chain before persisting
                if let Err(e) = self.validate_chain_before_persist(&ledger_id) {
                    tracing::warn!("Chain validation failed for transfer timeout: {}", e);
                    continue;
                }

                // Save ledger to disk
                if let Err(e) = self.handler.persist_ledger_to_disk(&ledger_id) {
                    tracing::warn!("Failed to save ledger after transfer timeout: {}", e);
                }

                // Broadcast to Nostr
                if let Err(e) = self.broadcast_last_update(&ledger_id).await {
                    tracing::warn!("Failed to broadcast transfer timeout: {}", e);
                }

                tracing::info!(
                    "Transfer {} timed out, funds returned to source",
                    hex::encode(&transfer_id[..8])
                );
            }
        }
    }

    /// Automatically credit deposits when Lightning invoices are paid.
    ///
    /// This polls LDK for payment status and creates InvoiceCredit operations
    /// for any pending invoices that have been successfully paid.
    pub async fn auto_credit_received_payments(&mut self) {
        use crate::ldk_cli::LdkCli;

        // Get pending invoices
        let pending: Vec<([u8; 32], PendingInvoice)> = {
            self.pending_invoices.lock().unwrap()
                .iter()
                .map(|(h, p)| (*h, p.clone()))
                .collect()
        };

        if pending.is_empty() {
            return;
        }

        // Query LDK for payment status
        let cli = LdkCli::from_env();
        let payments = match cli.list_payments() {
            Ok(resp) => resp.payments,
            Err(e) => {
                tracing::debug!("Failed to list payments for invoice check: {}", e);
                return;
            }
        };

        // Check each pending invoice against payments
        for (payment_hash, invoice) in pending {
            let payment_hash_hex = hex::encode(payment_hash);

            // Find matching payment by ID (payment hash)
            let matching_payment = payments.iter()
                .find(|p| p.id == payment_hash_hex);

            if let Some(payment) = matching_payment {
                // status: 0 = pending, 1 = succeeded, 2 = failed
                match payment.status {
                    1 => {
                        // Payment succeeded - credit the deposit
                        tracing::info!(
                            "Invoice paid! Crediting deposit {}... with {} msat (hash: {}...)",
                            hex::encode(&invoice.deposit_id[..8]),
                            invoice.amount_msat,
                            &payment_hash_hex[..16]
                        );

                        // Generate invoice_id from the invoice string
                        let invoice_id = format!("bolt11:{}", &invoice.invoice[..32.min(invoice.invoice.len())]);

                        match self.credit_deposit(
                            &invoice.ledger_id,
                            invoice.deposit_id,
                            invoice.amount_msat,
                            payment_hash,
                            invoice_id,
                        ).await {
                            Ok(new_balance) => {
                                tracing::info!(
                                    "Deposit credited! New balance: {} msat",
                                    new_balance
                                );
                                // Remove from pending
                                self.pending_invoices.lock().unwrap().remove(&payment_hash);
                            }
                            Err(e) => {
                                tracing::error!(
                                    "Failed to credit deposit for invoice {}...: {}",
                                    &payment_hash_hex[..16],
                                    e
                                );
                            }
                        }
                    }
                    2 => {
                        // Payment failed - remove from pending (invoice expired or rejected)
                        tracing::warn!(
                            "Invoice {}... payment failed, removing from pending",
                            &payment_hash_hex[..16]
                        );
                        self.pending_invoices.lock().unwrap().remove(&payment_hash);
                    }
                    _ => {
                        // Still pending, do nothing
                    }
                }
            }

            // Clean up old invoices (older than 1 hour)
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            if now > invoice.created_at + 3600 {
                tracing::debug!(
                    "Removing expired pending invoice {}...",
                    &payment_hash_hex[..16]
                );
                self.pending_invoices.lock().unwrap().remove(&payment_hash);
            }
        }
    }

    /// Find the ledger_id for a specific deposit offer
    fn find_ledger_for_offer(&self, offer_id: &[u8; 32]) -> Option<String> {
        // Get the offer to find its ledger_id
        let (offer, _) = self.get_deposit_offer(offer_id)?;

        // The offer already contains the ledger_id, just verify it exists
        let ledgers = self.handler.ledgers.lock().unwrap();
        if ledgers.contains_key(&offer.ledger_id) {
            return Some(offer.ledger_id.clone());
        }
        None
    }

    /// Handle co-sign responses only (sync, to avoid recursion in request_cosign polling)
    ///
    /// This is a simplified version of handle_ledger_response that only processes
    /// co-sign responses. Used inside request_cosign to avoid the recursive call:
    /// request_cosign -> handle_ledger_response -> record_collateral_attestation -> sign_and_broadcast -> request_cosign
    fn handle_cosign_response_only(&self, response: crate::nostr::LedgerResponse) {
        use std::str::FromStr;
        // For error responses, don't remove the pending request - keep waiting for success.
        // This is important because co-sign requests are multicast and non-quorum-members
        // will respond with errors before the actual quorum member responds.
        if !response.success {
            let has_pending = {
                let pending = self.pending_cosign_requests.lock().unwrap();
                pending.contains_key(&response.request_id)
            };
            if has_pending {
                tracing::debug!(
                    "Ignoring error co-sign response for {}: {} (waiting for quorum member)",
                    &response.request_id[..16.min(response.request_id.len())],
                    response.error.as_deref().unwrap_or("unknown error")
                );
            }
            return;
        }

        // Only remove pending request on success
        let cosign_sender = {
            let mut pending = self.pending_cosign_requests.lock().unwrap();
            let result = pending.remove(&response.request_id);
            metrics::set_pending_cosign_requests(pending.len());
            result
        };

        if let Some((_ledger_id, tx)) = cosign_sender {
            // This is a successful co-sign response

            if let Some(result) = &response.result {
                let result_obj = if result.is_object() {
                    result.clone()
                } else if let Some(s) = result.as_str() {
                    serde_json::from_str(s).unwrap_or_default()
                } else {
                    tracing::warn!("Co-sign response result is not an object or string");
                    return;
                };

                let sig_hex = result_obj.get("partner_signature_hex").and_then(|v| v.as_str());
                let hash_hex = result_obj.get("member_ledger_hash_hex").and_then(|v| v.as_str());
                let cosigner_str = result_obj.get("cosigner_pubkey").and_then(|v| v.as_str());

                if let (Some(sig_hex), Some(hash_hex)) = (sig_hex, hash_hex) {
                    if let (Ok(sig_vec), Ok(hash_vec)) = (hex::decode(sig_hex), hex::decode(hash_hex)) {
                        if sig_vec.len() == 64 && hash_vec.len() == 32 {
                            let mut sig = [0u8; 64];
                            sig.copy_from_slice(&sig_vec);
                            let mut hash = [0u8; 32];
                            hash.copy_from_slice(&hash_vec);

                            let cosigner_pubkey = cosigner_str
                                .and_then(|s| PublicKey::from_str(s).ok())
                                .unwrap_or(self.node_id); // fallback for old responders

                            let cosign_result = CoSignResult {
                                partner_signature: sig,
                                cosigner_pubkey,
                                member_ledger_hash: hash,
                            };
                            let _ = tx.send(cosign_result);
                            return;
                        } else {
                            tracing::warn!("Co-sign response has wrong signature/hash lengths");
                        }
                    } else {
                        tracing::warn!("Co-sign response has invalid hex encoding");
                    }
                } else {
                    tracing::warn!("Co-sign response missing partner_signature_hex or member_ledger_hash_hex");
                }
            } else {
                tracing::warn!("Co-sign response has no result");
            }
            // tx dropped, receiver gets error
        }
        // Non-cosign responses are not handled here - they'll be processed later by handle_ledger_response
    }

    /// Handle a ledger response (for auto-recording attestations and co-sign responses)
    async fn handle_ledger_response(&mut self, response: crate::nostr::LedgerResponse) {
        // First, check if this is a response to a pending co-sign request
        // For error responses, don't remove - keep waiting for success from actual quorum member
        let is_cosign_request = {
            let pending = self.pending_cosign_requests.lock().unwrap();
            pending.contains_key(&response.request_id)
        };

        if is_cosign_request {
            if !response.success {
                // Ignore error responses - non-quorum-members respond with errors
                // but we need to wait for the actual quorum member's success response
                tracing::debug!(
                    "Ignoring error co-sign response for {}: {} (waiting for quorum member)",
                    &response.request_id[..16.min(response.request_id.len())],
                    response.error.clone().unwrap_or_default()
                );
                return;
            }

            // Only remove on success
            let cosign_sender = {
                let mut pending = self.pending_cosign_requests.lock().unwrap();
                let result = pending.remove(&response.request_id);
                metrics::set_pending_cosign_requests(pending.len());
                result
            };

            if let Some((_ledger_id, tx)) = cosign_sender {
                // This is a successful co-sign response
                if let Some(result) = &response.result {
                    // The result might be a JSON object or a string containing JSON
                    let result_obj = if result.is_object() {
                        result.clone()
                    } else if let Some(s) = result.as_str() {
                        serde_json::from_str(s).unwrap_or_default()
                    } else {
                        serde_json::Value::Null
                    };

                    // Extract partner_signature_hex
                    let sig_hex = result_obj.get("partner_signature_hex").and_then(|v| v.as_str());
                    // Extract member_ledger_hash_hex
                    let hash_hex = result_obj.get("member_ledger_hash_hex").and_then(|v| v.as_str());
                    // Extract cosigner_pubkey
                    let cosigner_str = result_obj.get("cosigner_pubkey").and_then(|v| v.as_str());

                    if let (Some(sig_hex), Some(hash_hex)) = (sig_hex, hash_hex) {
                        let sig_bytes = hex::decode(sig_hex);
                        let hash_bytes = hex::decode(hash_hex);

                        if let (Ok(sig_vec), Ok(hash_vec)) = (sig_bytes, hash_bytes) {
                            if sig_vec.len() == 64 && hash_vec.len() == 32 {
                                let mut sig = [0u8; 64];
                                sig.copy_from_slice(&sig_vec);
                                let mut hash = [0u8; 32];
                                hash.copy_from_slice(&hash_vec);

                                let cosigner_pubkey = cosigner_str
                                    .and_then(|s| {
                                        use std::str::FromStr;
                                        PublicKey::from_str(s).ok()
                                    })
                                    .unwrap_or(self.node_id); // fallback for old responders

                                let cosign_result = CoSignResult {
                                    partner_signature: sig,
                                    cosigner_pubkey,
                                    member_ledger_hash: hash,
                                };
                                let _ = tx.send(cosign_result);
                                tracing::debug!("Co-sign response received: sig + member_hash {}...",
                                    &hash_hex[..8.min(hash_hex.len())]);
                                return;
                            }
                        }
                    }
                    tracing::warn!("Co-sign response missing valid partner_signature_hex or member_ledger_hash_hex");
                }
            }
            // tx is dropped here if we didn't send, receiver will get an error
            return;
        }

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
            metrics::set_pending_collateral_requests(pending.len());
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

        // Record the attestation on our ledger (now includes co-signing and broadcast)
        match self.record_collateral_attestation(&reserves_id, attestation).await {
            Ok(event_id) => {
                tracing::info!("Attestation recorded and broadcast on ledger {}: event_id={}",
                    &reserves_id[..16.min(reserves_id.len())],
                    &event_id[..16.min(event_id.len())]);
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
        self.track_sent_event(&request_id);

        // Track for auto-recording
        {
            let mut pending = self.pending_collateral_requests.lock().unwrap();
            pending.insert(request_id.clone(), our_reserves_id.to_string());
            metrics::set_pending_collateral_requests(pending.len());
        }

        tracing::info!(
            "Sent collateral_lock request {} to ledger {}..., tracking for auto-record",
            &request_id[..16.min(request_id.len())],
            &target_ledger_id[..16.min(target_ledger_id.len())]
        );

        Ok(request_id)
    }

    /// Request a co-signature from a quorum member for an update.
    ///
    /// This sends a cosign_update request via Nostr and waits for the response.
    /// The quorum member will validate the update and return their ECDSA signature
    /// over (partner_signing_data || member_ledger_hash).
    ///
    /// This is a multicast request - it goes to all quorum members subscribed to the
    /// ledger, and the first valid response is used. Each responder auto-detects which
    /// of their ledgers is bound to this one via QuorumJoin.
    ///
    /// # Arguments
    /// * `ledger_id` - The 64-char hex ledger_id hash of the ledger being updated
    /// * `update` - The SignedLedgerUpdate that needs co-signing
    ///
    /// # Returns
    /// A CoSignResult containing the partner signature and the member's ledger hash
    pub async fn request_cosign(
        &mut self,
        ledger_id: &str,
        update: &deposits_core::SignedLedgerUpdate,
    ) -> Result<CoSignResult, Error> {
        use tokio::time::Duration;

        // Compute partner signing data
        let partner_signing_data = update.partner_signing_data();

        // Create request parameters - responders auto-detect their bound ledger
        let params = serde_json::json!({
            "sequence_number": update.sequence_number,
            "partner_signing_data_hex": hex::encode(&partner_signing_data),
            "current_hash_hex": hex::encode(update.current_hash),
            "message_type": update.message_type,
        });

        // Create notification receiver BEFORE sending the request so we don't miss
        // any early responses. Each call to create_notification_receiver() creates a
        // new broadcast::Receiver that only sees events from that point forward.
        let mut notification_rx = self.nostr.create_notification_receiver();

        // Create oneshot channel for response (first responder wins)
        let (tx, rx) = tokio::sync::oneshot::channel();

        // Send the multicast request to the ledger
        let request_id = self.nostr.send_ledger_request(ledger_id, "cosign_update", params)
            .await
            .map_err(|e| Error::Protocol(format!("Failed to send co_sign request: {:?}", e)))?;
        self.track_sent_event(&request_id);

        // Subscribe to response for this request
        if let Err(e) = self.nostr.subscribe_to_response(&request_id).await {
            tracing::warn!("Failed to subscribe to co-sign response: {}", e);
        }

        // Store in pending requests
        {
            let mut pending = self.pending_cosign_requests.lock().unwrap();
            pending.insert(request_id.clone(), (ledger_id.to_string(), tx));
            metrics::set_pending_cosign_requests(pending.len());
        }

        tracing::info!(
            "Sent multicast co_sign request {} for seq={} (waiting for first responder)",
            &request_id[..16.min(request_id.len())],
            update.sequence_number,
        );

        // Poll for response while processing Nostr events
        // We need to run a mini event loop to receive the response
        // Use 3 second timeout for fast operations (regtest/testing)
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        let mut rx = rx;

        loop {
            tokio::select! {
                // Check if we got a response (first responder wins)
                result = &mut rx => {
                    match result {
                        Ok(cosign_result) => {
                            tracing::info!("Received co-signature for seq={} with member_hash {}...",
                                update.sequence_number,
                                &hex::encode(&cosign_result.member_ledger_hash[..4]));
                            return Ok(cosign_result);
                        }
                        Err(_) => {
                            return Err(Error::Protocol(
                                "Co-sign response not received (quorum member may have returned an error or response was malformed)".to_string()
                            ));
                        }
                    }
                }

                // Await the next notification from nostr-sdk's background task.
                // This replaces the old sleep+drain_notifications approach which was broken:
                // each call to client.notifications() creates a NEW broadcast::Receiver
                // starting empty, so try_recv() always returned nothing.
                //
                // By creating notification_rx ONCE (before sending the request) and
                // awaiting recv() here, we properly receive events as they arrive.
                notif = notification_rx.recv() => {
                    // Route notification to internal channels
                    match notif {
                        Ok(notification) => {
                            self.nostr.dispatch_notification(notification);
                            // Drain any additional notifications that arrived
                            while let Ok(n) = notification_rx.try_recv() {
                                self.nostr.dispatch_notification(n);
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                            // Receiver lagged - some events missed, drain what's available
                            tracing::warn!("Cosign mini loop notification receiver lagged by {} events", n);
                            while let Ok(n) = notification_rx.try_recv() {
                                self.nostr.dispatch_notification(n);
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            tracing::warn!("Cosign mini loop notification channel closed");
                        }
                    }

                    // Process co-sign responses (for our pending request)
                    while let Some(response) = self.nostr.try_recv_response() {
                        self.handle_cosign_response_only(response);
                    }

                    // Also process incoming co-sign REQUESTS from others
                    // This prevents deadlock where A waits for B while B waits for A
                    // Safe because processing a co-sign request just signs and responds,
                    // it doesn't trigger another sign_and_broadcast
                    //
                    // Non-cosign requests (e.g. transfer_lock, transfer_complete) that
                    // arrive while we wait are collected and re-queued so the main loop
                    // processes them after cosign completes — not silently dropped.
                    let mut deferred_requests = Vec::new();
                    while let Some(request) = self.nostr.try_recv_request() {
                        if request.action == "cosign_update" {
                            // Skip our own requests
                            let our_x_only = hex::encode(&self.node_id.serialize()[1..]);
                            if request.sender != our_x_only {
                                // Silently ignore if we're not a quorum member
                                if !self.is_quorum_member_of_ledger(&request.ledger_id) {
                                    continue;
                                }

                                let (success, result, error) = self.process_cosign_request(&request).await;
                                let result_json = result.map(|s| serde_json::Value::String(s));
                                if let Err(e) = self.nostr.send_ledger_response(
                                    &request.event_id,
                                    &request.ledger_id,
                                    &request.action,
                                    success,
                                    result_json,
                                    error,
                                ).await {
                                    tracing::debug!("Failed to send co-sign response: {}", e);
                                }
                            }
                        } else {
                            // Defer non-cosign requests so the main loop can process them
                            deferred_requests.push(request);
                        }
                    }
                    // Re-queue deferred requests for the main run loop to process
                    for req in deferred_requests {
                        self.nostr.queue_request(req);
                    }
                }

                // Timeout check
                _ = tokio::time::sleep_until(deadline) => {
                    let mut pending = self.pending_cosign_requests.lock().unwrap();
                    pending.remove(&request_id);
                    metrics::set_pending_cosign_requests(pending.len());
                    return Err(Error::Protocol("Co-sign request timed out after 3 seconds".to_string()));
                }
            }
        }
    }

    /// Request a co-signature on a deposit offer from quorum members.
    ///
    /// This sends a cosign_offer request via Nostr and waits for the first valid response.
    /// The co-signature proves the operator has valid quorum backing, preventing rogue
    /// former operators from creating valid offers after custody recovery.
    ///
    /// # Arguments
    /// * `ledger_id` - The 64-char hex ledger_id hash
    /// * `offer` - The deposit offer that needs co-signing
    ///
    /// # Returns
    /// An OfferCoSignResult containing the signature, co-signer pubkey, and their ledger hash
    pub async fn request_offer_cosign(
        &mut self,
        ledger_id: &str,
        offer: &DepositOffer,
    ) -> Result<OfferCoSignResult, Error> {
        use tokio::time::Duration;
        use std::str::FromStr;

        // Create request parameters
        let params = serde_json::json!({
            "offer_id": hex::encode(&offer.offer_id),
            "operator_id": offer.operator_id.to_string(),
            "funding_address": offer.funding_address,
            "deadline_block": offer.deadline_block,
        });

        // Create notification receiver BEFORE sending the request so we don't miss
        // any early responses. Each call to create_notification_receiver() creates a
        // new broadcast::Receiver that only sees events from that point forward.
        let mut notification_rx = self.nostr.create_notification_receiver();

        // Send the multicast request to quorum members
        let request_id = self.nostr.send_ledger_request(ledger_id, "cosign_offer", params)
            .await
            .map_err(|e| Error::Protocol(format!("Failed to send cosign_offer request: {:?}", e)))?;
        self.track_sent_event(&request_id);

        // Subscribe to response for this request
        if let Err(e) = self.nostr.subscribe_to_response(&request_id).await {
            tracing::warn!("Failed to subscribe to cosign_offer response: {}", e);
        }

        tracing::info!(
            "Sent cosign_offer request {} for offer {}... (waiting for first responder)",
            &request_id[..16.min(request_id.len())],
            &hex::encode(&offer.offer_id[..4]),
        );

        // Poll for response - use 3 second timeout for fast operations
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);

        loop {
            tokio::select! {
                // Await the next notification from nostr-sdk's background task.
                // By creating notification_rx ONCE (before sending the request) and
                // awaiting recv() here, we properly receive events as they arrive,
                // unlike poll_events() which creates a new empty receiver each call.
                notif = notification_rx.recv() => {
                    match notif {
                        Ok(notification) => {
                            self.nostr.dispatch_notification(notification);
                            // Drain any additional notifications that arrived
                            while let Ok(n) = notification_rx.try_recv() {
                                self.nostr.dispatch_notification(n);
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                            tracing::warn!("Offer cosign mini loop notification receiver lagged by {} events", n);
                            while let Ok(n) = notification_rx.try_recv() {
                                self.nostr.dispatch_notification(n);
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            return Err(Error::Protocol("Notification channel closed during offer cosign".to_string()));
                        }
                    }

                    // Check for responses
                    while let Some(response) = self.nostr.try_recv_response() {
                        if response.request_id == request_id {
                            if response.success {
                                if let Some(result) = &response.result {
                                    // Parse response fields
                                    let sig_hex = result.get("signature_hex")
                                        .and_then(|v| v.as_str())
                                        .ok_or_else(|| Error::Protocol("Missing signature_hex".to_string()))?;

                                    let cosigner_pubkey_str = result.get("cosigner_pubkey")
                                        .and_then(|v| v.as_str())
                                        .ok_or_else(|| Error::Protocol("Missing cosigner_pubkey".to_string()))?;

                                    let member_hash_hex = result.get("member_ledger_hash_hex")
                                        .and_then(|v| v.as_str())
                                        .ok_or_else(|| Error::Protocol("Missing member_ledger_hash_hex".to_string()))?;

                                    // Decode signature
                                    let sig_bytes = hex::decode(sig_hex)
                                        .map_err(|e| Error::Protocol(format!("Invalid signature hex: {}", e)))?;
                                    if sig_bytes.len() != 64 {
                                        return Err(Error::Protocol("Signature must be 64 bytes".to_string()));
                                    }
                                    let mut signature = [0u8; 64];
                                    signature.copy_from_slice(&sig_bytes);

                                    // Decode cosigner pubkey
                                    let cosigner_pubkey = PublicKey::from_str(cosigner_pubkey_str)
                                        .map_err(|e| Error::Protocol(format!("Invalid cosigner_pubkey: {}", e)))?;

                                    // Decode member ledger hash
                                    let hash_bytes = hex::decode(member_hash_hex)
                                        .map_err(|e| Error::Protocol(format!("Invalid member_ledger_hash_hex: {}", e)))?;
                                    if hash_bytes.len() != 32 {
                                        return Err(Error::Protocol("member_ledger_hash must be 32 bytes".to_string()));
                                    }
                                    let mut member_ledger_hash = [0u8; 32];
                                    member_ledger_hash.copy_from_slice(&hash_bytes);

                                    tracing::info!("Received offer co-signature from {} (member_hash: {}...)",
                                        &cosigner_pubkey_str[..16.min(cosigner_pubkey_str.len())],
                                        &member_hash_hex[..8]);

                                    return Ok(OfferCoSignResult {
                                        signature,
                                        cosigner_pubkey,
                                        member_ledger_hash,
                                    });
                                }
                            } else {
                                let error = response.error.unwrap_or_else(|| "Unknown error".to_string());
                                tracing::warn!("Cosign_offer request failed: {}", error);
                                // Continue waiting for other responses
                            }
                        }
                    }

                    // Also handle incoming cosign_offer requests from others
                    // (in case we're also a quorum member of another ledger)
                    while let Some(request) = self.nostr.try_recv_request() {
                        if request.action == "cosign_offer" {
                            let our_x_only = hex::encode(&self.node_id.serialize()[1..]);
                            if request.sender != our_x_only {
                                if self.is_quorum_member_of_ledger(&request.ledger_id) {
                                    let (success, result, error) = self.process_cosign_offer_request(&request).await;
                                    let result_json = result.map(|s| serde_json::Value::String(s));
                                    if let Err(e) = self.nostr.send_ledger_response(
                                        &request.event_id,
                                        &request.ledger_id,
                                        &request.action,
                                        success,
                                        result_json,
                                        error,
                                    ).await {
                                        tracing::debug!("Failed to send cosign_offer response: {}", e);
                                    }
                                }
                            }
                        }
                        // Defer non-cosign_offer requests (will be processed after we exit)
                    }
                }

                // Timeout check
                _ = tokio::time::sleep_until(deadline) => {
                    return Err(Error::Protocol("Co-signature required but failed: timeout after 3 seconds".to_string()));
                }
            }
        }
    }

    /// Track a Nostr event sent by this daemon process so we can filter it
    /// when it comes back via the relay broadcast.
    fn track_sent_event(&self, event_id: &str) {
        let mut sent = self.sent_events.lock().unwrap();
        // Cap the set to prevent unbounded growth
        if sent.len() > 1000 {
            sent.clear();
        }
        sent.insert(event_id.to_string());
    }

    /// Check if this ledger has had a reserves rotation to quorum-based Taproot.
    ///
    /// After the first ReservesRotate operation, co-signatures are required for all updates.
    fn has_quorum_reserves(&self, ledger_id: &str) -> bool {
        use deposits_core::messages::consts;

        let ledgers = self.handler.ledgers.lock().unwrap();
        if let Some(ledger_arc) = ledgers.get(ledger_id) {
            let ledger = ledger_arc.read().unwrap();
            // Check if any ReservesRotate operation exists in history
            for update in &ledger.history {
                if update.message_type == consts::RESERVES_ROTATE {
                    return true;
                }
            }
        }
        false
    }

    /// Build canonical signing data for deposit offer co-signatures.
    ///
    /// The signing data format is:
    /// `ledger_id || offer_id || operator_id_x || len(funding_address) || funding_address || deadline_block`
    ///
    /// This data is then hashed using BIP-340 tagged hashing with tag "deposits/offer_cosign"
    /// and combined with the member's ledger hash before signing.
    fn build_offer_signing_data(
        ledger_id: &str,
        offer_id: &[u8; 32],
        operator_id: &PublicKey,
        funding_address: &str,
        deadline_block: u32,
    ) -> Vec<u8> {
        let mut data = Vec::new();

        // ledger_id (64 hex chars = 32 bytes when decoded, but we use raw hex bytes for simplicity)
        data.extend_from_slice(ledger_id.as_bytes());

        // offer_id (32 bytes)
        data.extend_from_slice(offer_id);

        // operator_id x-coordinate only (32 bytes - excludes the 02/03 prefix)
        data.extend_from_slice(&operator_id.serialize()[1..]);

        // funding_address length (1 byte) + address bytes
        let addr_bytes = funding_address.as_bytes();
        data.push(addr_bytes.len() as u8);
        data.extend_from_slice(addr_bytes);

        // deadline_block (4 bytes, little-endian)
        data.extend_from_slice(&deadline_block.to_le_bytes());

        data
    }

    /// Sign an update with co-signature from a quorum member, then broadcast.
    ///
    /// This implements the "Porcupine Dance" signing order:
    /// 1. Partner (quorum member) signs (update content || their_ledger_hash) with ECDSA
    /// 2. Operator signs (content + partner_signature) with Schnorr
    ///
    /// Co-signature behavior:
    /// - Before reserves rotation: Falls back to operator-only if no quorum members
    /// - After reserves rotation: Co-signatures are REQUIRED (fails if none available)
    ///
    /// # Arguments
    /// * `ledger_id` - The ledger_id (hash or reserves address) identifying our ledger
    ///
    /// # Returns
    /// The Nostr event ID of the broadcast update
    pub async fn sign_and_broadcast(&mut self, ledger_id: &str) -> Result<String, Error> {
        // Check if reserves have been rotated to quorum (co-signatures become required)
        let quorum_reserves = self.has_quorum_reserves(ledger_id);

        // Get the ledger info we need
        let (has_quorum_members, update_clone) = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let ledger_arc = ledgers
                .get(ledger_id)
                .ok_or_else(|| Error::Protocol("Ledger not found".to_string()))?;
            let ledger = ledger_arc.read().unwrap();

            let has_quorum_members = !ledger.state.quorum_members.is_empty();

            // Clone the last update for co-signing
            let update_clone = ledger.history.last()
                .ok_or_else(|| Error::Protocol("No update to sign".to_string()))?
                .clone();

            (has_quorum_members, update_clone)
        };

        // If no quorum members and no rotation yet, fall back to operator-only signature
        if !has_quorum_members {
            if quorum_reserves {
                // After rotation, we should have quorum members - this is an error state
                return Err(Error::Protocol(
                    "Reserves have been rotated but no quorum members available - cannot sign".to_string()
                ));
            }
            tracing::debug!("No quorum members yet, using operator-only signature");
            return self.operator_sign_persist_broadcast(ledger_id).await;
        }

        // Send multicast co-sign request - first responder wins
        // Retry up to 3 times since responses can be missed during polling gaps
        let max_attempts = 3;
        let mut last_error = None;

        for attempt in 1..=max_attempts {
            match self.request_cosign(ledger_id, &update_clone).await {
                Ok(result) => {
                    // Apply partner signature
                    let ledgers = self.handler.ledgers.lock().unwrap();
                    let ledger_arc = ledgers
                        .get(ledger_id)
                        .ok_or_else(|| Error::Protocol("Ledger not found".to_string()))?;
                    let mut ledger = ledger_arc.write().unwrap();

                    if let Some(last) = ledger.history.last_mut() {
                        last.partner_signature = result.partner_signature;
                        last.cosigner_pubkey = Some(result.cosigner_pubkey);
                        last.member_ledger_hash = Some(result.member_ledger_hash);
                    }

                    tracing::info!("Applied partner signature from {} (member_ledger_hash: {}...)",
                        &result.cosigner_pubkey.to_string()[..8],
                        &hex::encode(&result.member_ledger_hash[..4]));
                    last_error = None;
                    break;
                }
                Err(e) => {
                    tracing::warn!("Co-sign attempt {}/{} failed: {}", attempt, max_attempts, e);
                    last_error = Some(e);
                    if attempt < max_attempts {
                        // Brief delay before retry
                        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                    }
                }
            }
        }

        if let Some(e) = last_error {
            if quorum_reserves {
                // After rotation, co-signatures are required - fail instead of falling back
                return Err(Error::Protocol(format!(
                    "Co-signature required after reserves rotation, but all {} attempts failed: {}",
                    max_attempts, e
                )));
            }
            // Before rotation, allow fallback to operator-only
            tracing::warn!("Co-sign multicast failed after {} attempts, using operator-only signature", max_attempts);
        }

        // Sign as operator
        let t_sign_op = std::time::Instant::now();
        self.sign_last_update(ledger_id)?;
        let sign_op_elapsed = t_sign_op.elapsed();

        // Validate chain consistency before persisting
        let t_validate = std::time::Instant::now();
        self.validate_chain_before_persist(ledger_id)?;
        let validate_elapsed = t_validate.elapsed();

        // Persist the ledger
        let t_persist2 = std::time::Instant::now();
        if let Err(e) = self.handler.persist_ledger_to_disk(ledger_id) {
            tracing::warn!("Failed to persist ledger after signing: {}", e);
        }
        let persist2_elapsed = t_persist2.elapsed();

        // Broadcast
        let t_broadcast = std::time::Instant::now();
        let result = self.broadcast_last_update(ledger_id).await;
        let broadcast_elapsed = t_broadcast.elapsed();

        tracing::info!("[PROFILE] sign_and_broadcast inner: cosign_wait=included_above, sign_op={:?}, validate={:?}, persist={:?}, broadcast={:?}",
            sign_op_elapsed, validate_elapsed, persist2_elapsed, broadcast_elapsed);

        result
    }

    /// Add a quorum member with co-signing and broadcast.
    ///
    /// This is the async version that handles the full co-signing flow:
    /// 1. Appends the QuorumAddMember operation (unsigned)
    /// 2. Requests co-signature from existing quorum member (if any)
    /// 3. Signs as operator
    /// 4. Broadcasts to Nostr
    ///
    /// If there are no existing quorum members, falls back to operator-only signature.
    pub async fn add_quorum_member(
        &mut self,
        ledger_id: &str,
        quorum_member: PublicKey,
        member_ledger_id: &str,
        signature: [u8; 64],
    ) -> Result<String, Error> {
        // Check if there are existing quorum members BEFORE adding the new one
        let has_quorum = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let ledger_arc = ledgers
                .get(ledger_id)
                .ok_or_else(|| Error::Protocol("Ledger not found".to_string()))?;
            let ledger = ledger_arc.read().unwrap();
            !ledger.state.quorum_members.is_empty()
        };

        // Append the operation (but don't sign yet)
        {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let ledger_arc = ledgers
                .get(ledger_id)
                .ok_or_else(|| Error::Protocol("Ledger not found".to_string()))?;

            let mut ledger = ledger_arc.write().unwrap();

            // Check if already a member
            if ledger.state.quorum_members.iter().any(|m| m.pubkey == quorum_member) {
                return Err(Error::Protocol("Already a quorum member".to_string()));
            }

            // Check if we've reached the maximum quorum size
            if ledger.state.quorum_members.len() >= MAX_QUORUM_MEMBERS {
                return Err(Error::Protocol(format!(
                    "Maximum quorum size reached ({} members)",
                    MAX_QUORUM_MEMBERS
                )));
            }

            let block_height = self.wallet.get_block_height().unwrap_or(0);
            let block_hash = self.wallet.get_block_hash().unwrap_or([0u8; 32]);

            let operation = deposits_core::messages::LedgerOperation::QuorumAddMember {
                quorum_member,
                quorum_member_signature: signature,
                member_ledger_id: member_ledger_id.to_string(),
            };

            ledger.append_operation_with_block(
                operation,
                deposits_core::messages::consts::QUORUM_ADD_MEMBER,
                block_height,
                block_hash,
            ).map_err(|e| Error::Protocol(format!("Failed to add quorum member: {:?}", e)))?;
        }

        // Now sign and broadcast (with co-signing if we have quorum members)
        if has_quorum {
            self.sign_and_broadcast(ledger_id).await
        } else {
            self.operator_sign_persist_broadcast(ledger_id).await
        }
    }

    /// Record a quorum join with co-signing and broadcast.
    ///
    /// This is the async version that handles the full co-signing flow.
    pub async fn record_quorum_join(
        &mut self,
        our_ledger_id: &str,
        target_operator: PublicKey,
        target_ledger_id: &str,
        membership_expires: u32,
        signature: [u8; 64],
    ) -> Result<String, Error> {
        // Check if there are existing quorum members
        let has_quorum = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let ledger_arc = ledgers
                .get(our_ledger_id)
                .ok_or_else(|| Error::Protocol(format!("Ledger not found: {}", our_ledger_id)))?;
            let ledger = ledger_arc.read().unwrap();
            !ledger.state.quorum_members.is_empty()
        };

        // Append the operation
        {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let ledger_arc = ledgers
                .get(our_ledger_id)
                .ok_or_else(|| Error::Protocol(format!("Ledger not found: {}", our_ledger_id)))?;

            let mut ledger = ledger_arc.write().unwrap();

            let block_height = self.wallet.get_block_height().unwrap_or(0);

            // Count active (non-expired) QuorumJoin operations
            let active_quorums = ledger.history.iter().filter(|u| {
                if u.message_type != deposits_core::messages::consts::QUORUM_JOIN {
                    return false;
                }
                if let Ok(LedgerOperation::QuorumJoin { membership_expires, .. }) =
                    LedgerOperation::tlv_decode(&u.message)
                {
                    membership_expires > block_height
                } else {
                    false
                }
            }).count();

            if active_quorums >= MAX_QUORUMS_JOINED {
                return Err(Error::Protocol(format!(
                    "Maximum active quorums joined reached ({} quorums)",
                    MAX_QUORUMS_JOINED
                )));
            }
            let block_hash = self.wallet.get_block_hash().unwrap_or([0u8; 32]);

            let operation = deposits_core::messages::LedgerOperation::QuorumJoin {
                operator_id: target_operator,
                ledger_id: target_ledger_id.to_string(),
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

        // Subscribe to the target ledger's requests so we can receive co-sign requests
        // This is important for quorum members to respond to update co-signing
        if let Err(e) = self.subscribe_to_ledger(target_ledger_id).await {
            tracing::warn!("Failed to subscribe to target ledger {}: {}", &target_ledger_id[..16.min(target_ledger_id.len())], e);
        }

        // Sign and broadcast
        if has_quorum {
            self.sign_and_broadcast(our_ledger_id).await
        } else {
            self.operator_sign_persist_broadcast(our_ledger_id).await
        }
    }

    /// Lock collateral with co-signing and broadcast.
    ///
    /// This is the async version that handles the full co-signing flow.
    /// Takes a descriptor string (e.g., "pk(02abc...)" for single-key deposits).
    /// Returns the attestation after successfully broadcasting.
    pub async fn lock_collateral(
        &mut self,
        ledger_id: &str,
        descriptor: &str,
        deposit_secret: &bitcoin::secp256k1::SecretKey,
        amount_msats: u64,
        lock_until_block: u32,
        requesting_operator: PublicKey,
    ) -> Result<deposits_core::CollateralAttestationMsg, Error> {
        use bitcoin::hashes::{sha256, Hash};
        use bitcoin::secp256k1::{Secp256k1, Message};

        let deposit_id = compute_deposit_id(descriptor);

        // Check if there are existing quorum members
        let has_quorum = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let ledger_arc = ledgers
                .get(ledger_id)
                .ok_or_else(|| Error::Protocol(format!("Ledger not found: {}", ledger_id)))?;
            let ledger = ledger_arc.read().unwrap();
            !ledger.state.quorum_members.is_empty()
        };

        // Create the operation and attestation
        let attestation = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let ledger_arc = ledgers
                .get(ledger_id)
                .ok_or_else(|| Error::Protocol(format!("Ledger not found: {}", ledger_id)))?
                .clone();
            drop(ledgers);

            let mut ledger = ledger_arc.write().unwrap();

            // Check if deposit exists
            let deposit = ledger.state.deposits.get(&deposit_id)
                .ok_or_else(|| Error::Protocol(format!(
                    "Deposit not found for descriptor {}",
                    descriptor
                )))?;

            let block_height = self.wallet.get_block_height().unwrap_or(0);
            let block_hash = self.wallet.get_block_hash().unwrap_or([0u8; 32]);

            // Check if collateral is already locked with sufficient amount and duration
            // This makes the operation idempotent - safe to retry without error
            let already_locked = deposit.collateral_lock_amount >= amount_msats
                && deposit.collateral_lock_expires >= lock_until_block
                && deposit.collateral_lock_expires > block_height;

            if already_locked {
                tracing::info!(
                    "Collateral already locked for deposit {}: {} msats until block {} (requested {} until {})",
                    hex::encode(deposit_id),
                    deposit.collateral_lock_amount,
                    deposit.collateral_lock_expires,
                    amount_msats,
                    lock_until_block
                );
            } else {
                // Create the deposit holder's signature for the lock
                let secp = Secp256k1::signing_only();
                let deposit_pubkey = PublicKey::from_secret_key(&secp, deposit_secret);
                let msg_str = format!("COLLATERAL_LOCK:{}:{}:{}:{}",
                    hex::encode(deposit_id),
                    amount_msats,
                    lock_until_block,
                    hex::encode(self.node_id.serialize())
                );
                let msg_hash = sha256::Hash::hash(msg_str.as_bytes());
                let msg = Message::from_digest(*msg_hash.as_byte_array());
                let signature = secp.sign_ecdsa(&msg, deposit_secret);
                let lock_signature: [u8; 64] = signature.serialize_compact();

                // Create witness from signature
                let witness = DescriptorWitness { stack: vec![lock_signature.to_vec()] };

                // Apply the CollateralLock operation
                let operation = LedgerOperation::CollateralLock {
                    deposit_id,
                    amount: amount_msats,
                    lock_until_block,
                    operator_id: self.node_id,
                    witness,
                };

                ledger.append_operation_with_block(operation, deposits_core::messages::consts::COLLATERAL_LOCK, block_height, block_hash)
                    .map_err(|e| Error::Protocol(format!("Failed to lock collateral: {:?}", e)))?;
            }

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

            // Get ledger_id (hex-encoded) for the attestation
            let collateral_ledger_id = hex::encode(ledger.state.ledger_id);

            // Create operator's attestation signature
            let mut sign_content = Vec::new();
            sign_content.extend_from_slice(b"COLLATERAL_ATTESTATION:");
            sign_content.extend_from_slice(&self.node_id.serialize());
            sign_content.extend_from_slice(&requesting_operator.serialize());
            sign_content.extend_from_slice(&total_locked.to_le_bytes());
            sign_content.extend_from_slice(&block_height.to_le_bytes());
            sign_content.extend_from_slice(&min_lock_until.to_le_bytes());
            sign_content.extend_from_slice(&ledger_hash);

            let hash = sha256::Hash::hash(&sign_content);
            let msg = Message::from_digest(hash.to_byte_array());

            let secp = Secp256k1::new();
            let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &self.wallet.operator_secret());
            let sig = secp.sign_schnorr(&msg, &keypair);
            let attestation_signature: [u8; 64] = *sig.as_ref();

            deposits_core::CollateralAttestationMsg {
                operator: self.node_id,
                quorum_member: requesting_operator,
                collateral_ledger_id,
                amount: total_locked,
                block_height,
                lock_until_block: min_lock_until,
                signature: attestation_signature,
                ledger_hash,
            }
        };

        // Sign and broadcast
        if has_quorum {
            self.sign_and_broadcast(ledger_id).await?;
        } else {
            self.operator_sign_persist_broadcast(ledger_id).await?;
        }

        tracing::info!(
            "Created collateral lock for deposit {}: {} msats until block {}, attestation for {}",
            hex::encode(deposit_id),
            attestation.amount,
            attestation.lock_until_block,
            requesting_operator
        );

        Ok(attestation)
    }

    /// Record a collateral attestation with co-signing and broadcast.
    ///
    /// This is the async version that handles the full co-signing flow.
    pub async fn record_collateral_attestation(
        &mut self,
        ledger_id: &str,
        attestation: deposits_core::CollateralAttestationMsg,
    ) -> Result<String, Error> {
        // Check if there are existing quorum members
        let has_quorum = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let ledger_arc = ledgers
                .get(ledger_id)
                .ok_or_else(|| Error::Protocol(format!("Ledger not found: {}", ledger_id)))?;
            let ledger = ledger_arc.read().unwrap();
            !ledger.state.quorum_members.is_empty()
        };

        // Verify we are the quorum_member in the attestation
        if attestation.quorum_member != self.node_id {
            return Err(Error::Protocol(format!(
                "Attestation is for {}, not us ({})",
                attestation.quorum_member, self.node_id
            )));
        }

        // Append the operation
        {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let ledger_arc = ledgers
                .get(ledger_id)
                .ok_or_else(|| Error::Protocol(format!("Ledger not found: {}", ledger_id)))?;
            let mut ledger = ledger_arc.write().unwrap();

            let operation = deposits_core::messages::LedgerOperation::CollateralAttestation {
                collateral_operator: attestation.operator,
                quorum_member: attestation.quorum_member,
                collateral_ledger_id: attestation.collateral_ledger_id.clone(),
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

        // Sign and broadcast
        if has_quorum {
            self.sign_and_broadcast(ledger_id).await
        } else {
            self.operator_sign_persist_broadcast(ledger_id).await
        }
    }

    /// Open a deposit with co-signing and broadcast.
    ///
    /// Takes a descriptor string (e.g., "pk(02abc...)" for single-key deposits).
    pub async fn open_deposit(
        &mut self,
        ledger_id: &str,
        descriptor: &str,
        fees: Option<FeeStructure>,
        transfer_fees: Option<deposits_core::TransferFeeSchedule>,
    ) -> Result<Deposit, Error> {
        let deposit_id = compute_deposit_id(descriptor);

        // Check if there are existing quorum members
        let has_quorum = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let ledger_arc = ledgers
                .get(ledger_id)
                .ok_or_else(|| Error::Protocol(format!("Ledger not found: {}", ledger_id)))?;
            let ledger = ledger_arc.read().unwrap();
            !ledger.state.quorum_members.is_empty()
        };

        // Append the operation
        let deposit = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let ledger_arc = ledgers
                .get(ledger_id)
                .ok_or_else(|| Error::Protocol(format!("Ledger not found: {}", ledger_id)))?
                .clone();

            let mut ledger = ledger_arc.write().unwrap();

            // Check if deposit already exists
            if ledger.state.deposits.contains_key(&deposit_id) {
                return Err(Error::Protocol(format!(
                    "Deposit already exists for descriptor {}",
                    descriptor
                )));
            }

            let operation = LedgerOperation::DepositOpen {
                deposit_id,
                descriptor: descriptor.to_string(),
                fees: fees.clone(),
                transfer_fees: transfer_fees.clone(),
                payment_hash: None,
                invoice: None,
                cosigner_guarantee_signature: None,
            };

            let block_height = self.wallet.get_block_height().unwrap_or(0);
            let block_hash = self.wallet.get_block_hash().unwrap_or([0u8; 32]);
            ledger.append_operation_with_block(
                operation,
                deposits_core::messages::consts::DEPOSIT_OPEN,
                block_height,
                block_hash,
            ).map_err(|e| Error::Protocol(format!("Failed to open deposit: {:?}", e)))?;

            ledger.state.deposits.get(&deposit_id)
                .cloned()
                .ok_or_else(|| Error::Protocol("Deposit not found after creation".to_string()))?
        };

        // Sign and broadcast
        let sign_result = if has_quorum {
            self.sign_and_broadcast(ledger_id).await
        } else {
            self.operator_sign_persist_broadcast(ledger_id).await
        };

        if let Err(e) = sign_result {
            // Rollback: undo the DepositOpen state changes.
            tracing::warn!("sign_and_broadcast failed for open_deposit, rolling back state: {}", e);
            {
                let ledgers = self.handler.ledgers.lock().unwrap();
                let ledger_arc = ledgers.get(ledger_id).unwrap().clone();
                let mut ledger = ledger_arc.write().unwrap();
                // Pop the unsigned operation from history
                ledger.history.pop();
                // Undo DepositOpen state change: remove the deposit
                ledger.state.deposits.remove(&deposit_id);
                // Restore sequence and hash from the last remaining entry
                let (seq, hash) = ledger.history.last()
                    .map(|l| (l.sequence_number, l.current_hash))
                    .unwrap_or((0, [0u8; 32]));
                ledger.state.sequence = seq;
                ledger.state.hash = hash;
            }
            return Err(e);
        }

        tracing::info!("Opened deposit {} in ledger {}", hex::encode(deposit_id), ledger_id);
        Ok(deposit)
    }

    /// Credit a deposit with on-chain funds, with co-signing and broadcast.
    pub async fn credit_deposit_onchain(
        &mut self,
        ledger_id: &str,
        descriptor: &str,
        amount_msats: u64,
        txid: [u8; 32],
        vout: u32,
        funding_address: String,
    ) -> Result<u64, Error> {
        let deposit_id = compute_deposit_id(descriptor);

        // Check if there are existing quorum members
        let has_quorum = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let ledger_arc = ledgers
                .get(ledger_id)
                .ok_or_else(|| Error::Protocol(format!("Ledger not found: {}", ledger_id)))?;
            let ledger = ledger_arc.read().unwrap();
            !ledger.state.quorum_members.is_empty()
        };

        // Append the operation
        let new_balance = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let ledger_arc = ledgers
                .get(ledger_id)
                .ok_or_else(|| Error::Protocol(format!("Ledger not found: {}", ledger_id)))?
                .clone();

            let mut ledger = ledger_arc.write().unwrap();

            if !ledger.state.deposits.contains_key(&deposit_id) {
                return Err(Error::Protocol(format!(
                    "Deposit not found for descriptor {}",
                    descriptor
                )));
            }

            let operation = LedgerOperation::OnchainCredit {
                txid,
                vout,
                deposit_id,
                amount: amount_msats,
                funding_address,
            };

            let block_height = self.wallet.get_block_height().unwrap_or(0);
            let block_hash = self.wallet.get_block_hash().unwrap_or([0u8; 32]);
            ledger.append_operation_with_block(
                operation,
                deposits_core::messages::consts::ONCHAIN_CREDIT,
                block_height,
                block_hash,
            ).map_err(|e| Error::Protocol(format!("Failed to credit deposit: {:?}", e)))?;

            ledger.state.deposits.get(&deposit_id)
                .map(|d| d.balance)
                .unwrap_or(0)
        };

        // Sign and broadcast
        let sign_result = if has_quorum {
            self.sign_and_broadcast(ledger_id).await
        } else {
            self.operator_sign_persist_broadcast(ledger_id).await
        };

        if let Err(e) = sign_result {
            // Rollback: undo the OnchainCredit state changes.
            // The operation was appended and balance credited but signing failed,
            // so we must restore the previous state to prevent duplicate credits
            // on the next auto_complete_deposits cycle.
            tracing::warn!("sign_and_broadcast failed for credit_deposit_onchain, rolling back state: {}", e);
            {
                let ledgers = self.handler.ledgers.lock().unwrap();
                let ledger_arc = ledgers.get(ledger_id).unwrap().clone();
                let mut ledger = ledger_arc.write().unwrap();
                // Pop the unsigned operation from history
                ledger.history.pop();
                // Undo OnchainCredit state change: subtract the credited amount
                if let Some(deposit) = ledger.state.deposits.get_mut(&deposit_id) {
                    deposit.balance = deposit.balance.saturating_sub(amount_msats);
                }
                // Restore sequence and hash from the last remaining entry
                let (seq, hash) = ledger.history.last()
                    .map(|l| (l.sequence_number, l.current_hash))
                    .unwrap_or((0, [0u8; 32]));
                ledger.state.sequence = seq;
                ledger.state.hash = hash;
            }
            return Err(e);
        }

        tracing::info!(
            "Credited deposit {} with {} msats (on-chain), new balance: {} msats",
            hex::encode(deposit_id), amount_msats, new_balance
        );
        Ok(new_balance)
    }

    /// Credit a deposit with Lightning invoice payment, with co-signing and broadcast.
    pub async fn credit_deposit(
        &mut self,
        ledger_id: &str,
        deposit_id: DepositId,
        amount_msats: u64,
        payment_hash: [u8; 32],
        invoice_id: String,
    ) -> Result<u64, Error> {
        // Check if there are existing quorum members
        let has_quorum = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let ledger_arc = ledgers
                .get(ledger_id)
                .ok_or_else(|| Error::Protocol(format!("Ledger not found: {}", ledger_id)))?;
            let ledger = ledger_arc.read().unwrap();
            !ledger.state.quorum_members.is_empty()
        };

        // Append the operation
        let new_balance = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let ledger_arc = ledgers
                .get(ledger_id)
                .ok_or_else(|| Error::Protocol(format!("Ledger not found: {}", ledger_id)))?
                .clone();

            let mut ledger = ledger_arc.write().unwrap();

            if !ledger.state.deposits.contains_key(&deposit_id) {
                return Err(Error::Protocol(format!(
                    "Deposit not found for id {}",
                    hex::encode(deposit_id)
                )));
            }

            let sequence_number = ledger.sequence() + 1;

            let operation = LedgerOperation::InvoiceCredit {
                payment_hash,
                deposit_id,
                amount: amount_msats,
                invoice_id,
                sequence_number,
            };

            let block_height = self.wallet.get_block_height().unwrap_or(0);
            let block_hash = self.wallet.get_block_hash().unwrap_or([0u8; 32]);
            ledger.append_operation_with_block(
                operation,
                deposits_core::messages::consts::RECEIVING_CREDIT_PAYMENT,
                block_height,
                block_hash,
            ).map_err(|e| Error::Protocol(format!("Failed to credit deposit: {:?}", e)))?;

            ledger.state.deposits.get(&deposit_id)
                .map(|d| d.balance)
                .unwrap_or(0)
        };

        // Sign and broadcast
        if has_quorum {
            self.sign_and_broadcast(ledger_id).await?;
        } else {
            self.operator_sign_persist_broadcast(ledger_id).await?;
        }

        tracing::info!(
            "Credited deposit {} with {} msats (invoice), new balance: {} msats",
            hex::encode(deposit_id), amount_msats, new_balance
        );
        Ok(new_balance)
    }

    /// Lock funds for an outgoing Lightning invoice payment, with co-signing and broadcast.
    pub async fn lock_invoice_payment(
        &mut self,
        ledger_id: &str,
        deposit_id: DepositId,
        amount_msats: u64,
        payment_id: [u8; 32],
        witness: DescriptorWitness,
    ) -> Result<u64, Error> {
        // Check if there are existing quorum members
        let has_quorum = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let ledger_arc = ledgers
                .get(ledger_id)
                .ok_or_else(|| Error::Protocol(format!("Ledger not found: {}", ledger_id)))?;
            let ledger = ledger_arc.read().unwrap();
            !ledger.state.quorum_members.is_empty()
        };

        // Append the operation
        let new_locked = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let ledger_arc = ledgers
                .get(ledger_id)
                .ok_or_else(|| Error::Protocol(format!("Ledger not found: {}", ledger_id)))?
                .clone();

            let mut ledger = ledger_arc.write().unwrap();

            let deposit = ledger.state.deposits.get(&deposit_id)
                .ok_or_else(|| Error::Protocol(format!(
                    "Deposit not found for id {}",
                    hex::encode(deposit_id)
                )))?;

            if deposit.available_balance() < amount_msats {
                return Err(Error::Protocol(format!(
                    "Insufficient available balance: {} msats available, {} msats needed",
                    deposit.available_balance(), amount_msats
                )));
            }

            let sequence_number = ledger.sequence() + 1;

            let operation = LedgerOperation::InvoiceLock {
                deposit_id,
                amount: amount_msats,
                payment_id,
                sequence_number,
                witness,
            };

            let block_height = self.wallet.get_block_height().unwrap_or(0);
            let block_hash = self.wallet.get_block_hash().unwrap_or([0u8; 32]);
            ledger.append_operation_with_block(
                operation,
                deposits_core::messages::consts::SENDING_LOCK_PAYMENT,
                block_height,
                block_hash,
            ).map_err(|e| Error::Protocol(format!("Failed to lock payment: {:?}", e)))?;

            ledger.state.deposits.get(&deposit_id)
                .map(|d| d.locked_balance)
                .unwrap_or(0)
        };

        // Sign and broadcast
        if has_quorum {
            self.sign_and_broadcast(ledger_id).await?;
        } else {
            self.operator_sign_persist_broadcast(ledger_id).await?;
        }

        tracing::info!(
            "Locked {} msats for invoice payment {} on deposit {}",
            amount_msats, hex::encode(&payment_id[..8]), hex::encode(deposit_id)
        );
        Ok(new_locked)
    }

    /// Fail an outgoing Lightning invoice payment, with co-signing and broadcast.
    pub async fn fail_invoice_payment(
        &mut self,
        ledger_id: &str,
        deposit_id: DepositId,
        amount_msats: u64,
        payment_id: [u8; 32],
    ) -> Result<u64, Error> {
        // Check if there are existing quorum members
        let has_quorum = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let ledger_arc = ledgers
                .get(ledger_id)
                .ok_or_else(|| Error::Protocol(format!("Ledger not found: {}", ledger_id)))?;
            let ledger = ledger_arc.read().unwrap();
            !ledger.state.quorum_members.is_empty()
        };

        // Append the operation
        let new_balance = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let ledger_arc = ledgers
                .get(ledger_id)
                .ok_or_else(|| Error::Protocol(format!("Ledger not found: {}", ledger_id)))?
                .clone();

            let mut ledger = ledger_arc.write().unwrap();

            let deposit = ledger.state.deposits.get(&deposit_id)
                .ok_or_else(|| Error::Protocol(format!(
                    "Deposit not found for id {}",
                    hex::encode(deposit_id)
                )))?;

            if deposit.locked_balance < amount_msats {
                return Err(Error::Protocol(format!(
                    "Insufficient locked balance: {} msats locked, {} msats to fail",
                    deposit.locked_balance, amount_msats
                )));
            }

            let sequence_number = ledger.sequence() + 1;

            let operation = LedgerOperation::InvoiceFail {
                deposit_id,
                amount: amount_msats,
                payment_id,
                sequence_number,
            };

            let block_height = self.wallet.get_block_height().unwrap_or(0);
            let block_hash = self.wallet.get_block_hash().unwrap_or([0u8; 32]);
            ledger.append_operation_with_block(
                operation,
                deposits_core::messages::consts::SENDING_FAIL_PAYMENT,
                block_height,
                block_hash,
            ).map_err(|e| Error::Protocol(format!("Failed to fail payment: {:?}", e)))?;

            ledger.state.deposits.get(&deposit_id)
                .map(|d| d.balance)
                .unwrap_or(0)
        };

        // Sign and broadcast
        if has_quorum {
            self.sign_and_broadcast(ledger_id).await?;
        } else {
            self.operator_sign_persist_broadcast(ledger_id).await?;
        }

        tracing::info!(
            "Failed invoice payment {} for {} msats on deposit {}, new balance: {} msats",
            hex::encode(&payment_id[..8]), amount_msats, hex::encode(deposit_id), new_balance
        );
        Ok(new_balance)
    }

    /// Fulfill an outgoing Lightning invoice payment, with co-signing and broadcast.
    pub async fn fulfill_invoice_payment(
        &mut self,
        ledger_id: &str,
        deposit_id: DepositId,
        amount_msats: u64,
        payment_id: [u8; 32],
        preimage: [u8; 32],
        witness: DescriptorWitness,
    ) -> Result<u64, Error> {
        // Check if there are existing quorum members
        let has_quorum = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let ledger_arc = ledgers
                .get(ledger_id)
                .ok_or_else(|| Error::Protocol(format!("Ledger not found: {}", ledger_id)))?;
            let ledger = ledger_arc.read().unwrap();
            !ledger.state.quorum_members.is_empty()
        };

        // Append the operation
        let new_balance = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let ledger_arc = ledgers
                .get(ledger_id)
                .ok_or_else(|| Error::Protocol(format!("Ledger not found: {}", ledger_id)))?
                .clone();

            let mut ledger = ledger_arc.write().unwrap();

            let deposit = ledger.state.deposits.get(&deposit_id)
                .ok_or_else(|| Error::Protocol(format!(
                    "Deposit not found for id {}",
                    hex::encode(deposit_id)
                )))?;

            if deposit.locked_balance < amount_msats {
                return Err(Error::Protocol(format!(
                    "Insufficient locked balance: {} msats locked, {} msats to fulfill",
                    deposit.locked_balance, amount_msats
                )));
            }

            let sequence_number = ledger.sequence() + 1;

            let operation = LedgerOperation::InvoiceFulfill {
                deposit_id,
                amount: amount_msats,
                payment_id,
                preimage,
                sequence_number,
                witness,
            };

            let block_height = self.wallet.get_block_height().unwrap_or(0);
            let block_hash = self.wallet.get_block_hash().unwrap_or([0u8; 32]);
            ledger.append_operation_with_block(
                operation,
                deposits_core::messages::consts::SENDING_FULFILL_PAYMENT,
                block_height,
                block_hash,
            ).map_err(|e| Error::Protocol(format!("Failed to fulfill payment: {:?}", e)))?;

            ledger.state.deposits.get(&deposit_id)
                .map(|d| d.balance)
                .unwrap_or(0)
        };

        // Sign and broadcast
        if has_quorum {
            self.sign_and_broadcast(ledger_id).await?;
        } else {
            self.operator_sign_persist_broadcast(ledger_id).await?;
        }

        tracing::info!(
            "Fulfilled invoice payment {} for {} msats on deposit {}, new balance: {} msats",
            hex::encode(&payment_id[..8]), amount_msats, hex::encode(deposit_id), new_balance
        );
        Ok(new_balance)
    }

    /// Lock a withdrawal with co-signing and broadcast.
    pub async fn lock_withdrawal(
        &mut self,
        ledger_id: &str,
        deposit_id: DepositId,
        destination_address: String,
        amount_sats: u64,
        fee_sats: u64,
        nonce: [u8; 32],
        depositor_witness: DescriptorWitness,
        memo: Option<String>,
    ) -> Result<WithdrawalLockResult, Error> {
        // Check if there are existing quorum members
        let has_quorum = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let ledger_arc = ledgers
                .get(ledger_id)
                .ok_or_else(|| Error::Protocol(format!("Ledger not found: {}", ledger_id)))?;
            let ledger = ledger_arc.read().unwrap();
            !ledger.state.quorum_members.is_empty()
        };

        let current_block = self.wallet.get_block_height()?;

        // Compute withdrawal ID
        let signing_message = OnChainWithdrawal::signing_message(
            &nonce,
            &deposit_id,
            &destination_address,
            amount_sats,
            fee_sats,
        );
        let withdrawal_id = OnChainWithdrawal::compute_withdrawal_id(&signing_message);

        // Clone witness for use in OnchainLock operation
        let witness_for_lock = depositor_witness.clone();

        // Create the withdrawal
        let withdrawal = OnChainWithdrawal {
            withdrawal_id,
            nonce,
            deposit_id,
            destination_address: destination_address.clone(),
            amount_sats,
            fee_sats,
            requested_at_block: current_block,
            memo,
            depositor_witness,
        };

        // Note: Signature verification is skipped here because process_withdraw_request
        // already verified the Schnorr signature. The deposits_core verification expects
        // ECDSA with a different message format, which doesn't match the Nostr request flow.
        // TODO: Unify signature formats between Nostr requests and lock_withdrawal

        // Append the operation
        let (previous_balance, new_balance) = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let ledger_arc = ledgers
                .get(ledger_id)
                .ok_or_else(|| Error::Protocol(format!("Ledger not found: {}", ledger_id)))?
                .clone();

            let mut ledger = ledger_arc.write().unwrap();

            let deposit = ledger.state.deposits.get(&deposit_id)
                .ok_or_else(|| Error::Protocol(format!(
                    "Deposit not found for id {}",
                    hex::encode(deposit_id)
                )))?;

            let total_debit_msats = (amount_sats + fee_sats) * 1000;
            if deposit.balance < total_debit_msats {
                return Err(Error::Protocol(format!(
                    "Insufficient balance: {} msats available, {} msats needed",
                    deposit.balance, total_debit_msats
                )));
            }

            let prev_balance = deposit.balance;

            let operation = LedgerOperation::OnchainLock {
                deposit_id,
                amount: amount_sats * 1000, // Convert to msats
                fee_sats,
                destination_address: destination_address.clone(),
                withdrawal_id,
                witness: witness_for_lock,
            };

            let block_height = self.wallet.get_block_height().unwrap_or(0);
            let block_hash = self.wallet.get_block_hash().unwrap_or([0u8; 32]);
            ledger.append_operation_with_block(
                operation,
                deposits_core::messages::consts::ONCHAIN_LOCK,
                block_height,
                block_hash,
            ).map_err(|e| Error::Protocol(format!("Failed to lock withdrawal: {:?}", e)))?;

            let new_bal = ledger.state.deposits.get(&deposit_id)
                .map(|d| d.balance)
                .unwrap_or(0);

            (prev_balance, new_bal)
        };

        // Sign and broadcast
        if has_quorum {
            self.sign_and_broadcast(ledger_id).await?;
        } else {
            self.operator_sign_persist_broadcast(ledger_id).await?;
        }

        // Store the withdrawal as locked
        let status = OnChainWithdrawalStatus::Locked {
            locked_at_block: current_block,
        };

        {
            let mut withdrawals = self.withdrawals.lock().unwrap();
            withdrawals.insert(withdrawal_id, (withdrawal.clone(), status));
        }

        self.save_withdrawals()?;

        let total_debit_msats = withdrawal.total_debit() * 1000;

        tracing::info!(
            "Locked withdrawal {} for {} sats + {} fee to {}, balance {} -> {} msats",
            hex::encode(&withdrawal_id[..8]),
            amount_sats, fee_sats, withdrawal.destination_address,
            previous_balance, new_balance
        );

        Ok(WithdrawalLockResult {
            withdrawal: withdrawal.clone(),
            previous_balance_msats: previous_balance,
            new_balance_msats: new_balance,
            locked_amount_msats: total_debit_msats,
        })
    }

    /// Complete a withdrawal with co-signing and broadcast.
    pub async fn complete_withdrawal(
        &mut self,
        ledger_id: &str,
        withdrawal_id: &[u8; 32],
    ) -> Result<WithdrawalCompleteResult, Error> {
        // Check if there are existing quorum members
        let has_quorum = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let ledger_arc = ledgers
                .get(ledger_id)
                .ok_or_else(|| Error::Protocol(format!("Ledger not found: {}", ledger_id)))?;
            let ledger = ledger_arc.read().unwrap();
            !ledger.state.quorum_members.is_empty()
        };

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

        // Append the OnchainFulfill operation
        let final_balance = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let ledger_arc = ledgers
                .get(ledger_id)
                .ok_or_else(|| Error::Protocol(format!("Ledger not found: {}", ledger_id)))?
                .clone();

            let mut ledger = ledger_arc.write().unwrap();

            let operation = LedgerOperation::OnchainFulfill {
                deposit_id: withdrawal.deposit_id,
                withdrawal_id: *withdrawal_id,
                amount: withdrawal.amount_sats * 1000,
                txid: txid_bytes,
                destination_address: withdrawal.destination_address.clone(),
            };

            let block_height = self.wallet.get_block_height().unwrap_or(0);
            let block_hash = self.wallet.get_block_hash().unwrap_or([0u8; 32]);
            ledger.append_operation_with_block(
                operation,
                deposits_core::messages::consts::ONCHAIN_FULFILL,
                block_height,
                block_hash,
            ).map_err(|e| Error::Protocol(format!("Failed to fulfill withdrawal: {:?}", e)))?;

            ledger.state.deposits.get(&withdrawal.deposit_id)
                .map(|d| d.balance)
                .unwrap_or(0)
        };

        // Sign and broadcast
        if has_quorum {
            self.sign_and_broadcast(ledger_id).await?;
        } else {
            self.operator_sign_persist_broadcast(ledger_id).await?;
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

        self.save_withdrawals()?;

        tracing::info!(
            "Completed withdrawal {}: txid={}, final balance={} msats",
            hex::encode(&withdrawal_id[..8]), txid, final_balance
        );

        Ok(WithdrawalCompleteResult {
            withdrawal_id: *withdrawal_id,
            txid,
            amount_sats: withdrawal.amount_sats,
            fee_sats: withdrawal.fee_sats,
            final_balance_msats: final_balance,
        })
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

        // Update enforcement block and other state, get ledger_id
        let ledger_id = {
            let mut ledger_guard = ledger_arc.write().unwrap();
            ledger_guard.state.collateral_enforcement_block = enforcement;
            ledger_guard.state.reserves.spend_to = self.node_id;
            ledger_guard.ledger_id_hex()
        };

        // Persist the ledger
        if let Err(e) = self.handler.persist_ledger_to_disk(&ledger_id) {
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

        // Return the ledger (we already have ledger_arc from above)
        let ledger = ledger_arc.read().unwrap().clone();
        Ok(ledger)
    }

    /// List all ledgers
    pub fn list_ledgers(&self) -> HashMap<String, Arc<RwLock<Ledger>>> {
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

    /// List all quorum members across all ledgers
    /// Returns (identifier, role) tuples where identifier is pubkey or ledger_id string
    pub fn list_partners(&self) -> Vec<(String, String)> {
        let mut partners = Vec::new();
        let ledgers = self.handler.ledgers.lock().unwrap();

        for (ledger_id, ledger_arc) in ledgers.iter() {
            let ledger = ledger_arc.read().unwrap();
            let operator = ledger.operator_key();
            let role = if operator == self.node_id {
                "Partner on our ledger"
            } else {
                "We are partner on their ledger"
            };

            // Add the partner/operator
            if operator == self.node_id {
                // Use ledger_id as the identifier for our own ledgers
                partners.push((ledger_id.clone(), role.to_string()));
            } else {
                partners.push((operator.to_string(), role.to_string()));
            }

            // Add quorum members
            for member in &ledger.state.quorum_members {
                partners.push((member.pubkey.to_string(), "Quorum member".to_string()));
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
    /// * `ledger_id` - The ledger ID (hex-encoded hash)
    ///
    /// # Returns
    /// The new Taproot reserves address and txid, or error if rotation fails
    pub fn rotate_reserves_to_quorum(
        &self,
        ledger_id: &str,
    ) -> Result<RotateReservesResult, Error> {
        // Get the ledger
        let ledgers = self.handler.ledgers.lock().unwrap();
        let ledger_arc = ledgers
            .get(ledger_id)
            .ok_or_else(|| Error::Protocol(format!("Ledger not found: {}", ledger_id)))?
            .clone();
        drop(ledgers);

        let (quorum_members, quorum_expiries, ledger_hash, _current_reserves) = {
            let ledger = ledger_arc.read().unwrap();

            // Get quorum members' pubkeys
            let members: Vec<PublicKey> = ledger.state.quorum_members.iter().map(|m| m.pubkey).collect();

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
        self.sign_last_update(ledger_id)?;

        // Validate chain before persisting
        self.validate_chain_before_persist(ledger_id)?;

        // Persist the ledger with the new operation
        if let Err(e) = self.handler.persist_ledger_to_disk(ledger_id) {
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
        fees: Option<FeeStructure>,
    ) -> Result<DepositOffer, Error> {
        // Get current block height
        let current_block = self.wallet.get_block_height()?;
        let deadline_block = current_block + blocks_valid;

        // Generate a new funding address
        let funding_address = self.wallet.get_new_address()?;
        let funding_address_str = funding_address.to_string();

        // Create descriptor and compute deposit_id from pubkey
        let descriptor = format!("pk({})", hex::encode(deposit_pubkey.serialize()));
        let deposit_id = compute_deposit_id(&descriptor);

        // Get the signing message and compute offer ID
        let signing_message = DepositOffer::signing_message(
            &self.node_id,
            ledger_id,
            &deposit_id,
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
            &deposit_id,
            &funding_address_str,
            max_amount_sats,
            min_amount_sats,
            deadline_block,
        ).map_err(|e| Error::Protocol(format!("Failed to sign offer: {:?}", e)))?;

        // Create the offer
        let offer = DepositOffer {
            operator_id: self.node_id,
            ledger_id: ledger_id.to_string(),
            deposit_id,
            descriptor,
            funding_address: funding_address_str,
            max_amount_sats,
            min_amount_sats,
            deadline_block,
            created_at_block: current_block,
            offer_id,
            operator_signature: signature,
            fees,
            transfer_fees: None,
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

        tracing::debug!("Loaded {} deposit offers from disk", map.len());
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

        // Update metrics
        self.update_pending_offers_metric();

        Ok(())
    }

    /// Update the pending deposit offers metric
    fn update_pending_offers_metric(&self) {
        let offers = self.deposit_offers.lock().unwrap();
        let pending_count = offers.values()
            .filter(|(_, status)| matches!(status, DepositOfferStatus::Pending))
            .count();
        metrics::set_pending_deposit_offers(pending_count);
    }

    /// Reload deposit offers from disk (merges with in-memory state)
    ///
    /// This is needed when CLI commands modify the deposit_offers file
    /// outside of the running daemon.
    fn reload_deposit_offers(&self) {
        let disk_offers = match Self::load_deposit_offers(&self.data_dir) {
            Ok(offers) => offers,
            Err(e) => {
                tracing::warn!("Failed to reload deposit offers: {}", e);
                return;
            }
        };

        let mut memory_offers = self.deposit_offers.lock().unwrap();

        // Update in-memory state with any changes from disk
        for (offer_id, (disk_offer, disk_status)) in disk_offers {
            if let Some((_, ref mut memory_status)) = memory_offers.get_mut(&offer_id) {
                // If disk has a "more complete" status, use it
                // Pending < FundingReceived < Completed/Expired/Cancelled
                let should_update = match (&*memory_status, &disk_status) {
                    (DepositOfferStatus::Pending, DepositOfferStatus::FundingReceived { .. }) => true,
                    (DepositOfferStatus::Pending, DepositOfferStatus::Completed { .. }) => true,
                    (DepositOfferStatus::Pending, DepositOfferStatus::Expired { .. }) => true,
                    (DepositOfferStatus::Pending, DepositOfferStatus::Cancelled) => true,
                    (DepositOfferStatus::FundingReceived { .. }, DepositOfferStatus::Completed { .. }) => true,
                    _ => false,
                };

                if should_update {
                    tracing::debug!(
                        "Reloaded deposit offer {}...: {:?} -> {:?}",
                        hex::encode(&offer_id[..8]),
                        memory_status,
                        disk_status
                    );
                    *memory_status = disk_status;
                }
            } else {
                // New offer on disk, add to memory
                memory_offers.insert(offer_id, (disk_offer, disk_status));
            }
        }

        // Update metrics - need to count pending within the lock
        let pending_count = memory_offers.values()
            .filter(|(_, status)| matches!(status, DepositOfferStatus::Pending))
            .count();
        drop(memory_offers);
        metrics::set_pending_deposit_offers(pending_count);
    }

    // ========================================================================
    // On-Chain Withdrawal Management
    // ========================================================================

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

    /// Get a deposit by deposit_id from a ledger
    pub fn get_deposit(
        &self,
        ledger_id: &str,
        deposit_id: DepositId,
    ) -> Option<Deposit> {
        let ledgers = self.handler.ledgers.lock().unwrap();
        if let Some(ledger_arc) = ledgers.get(ledger_id) {
            let ledger = ledger_arc.read().unwrap();
            return ledger.state.deposits.get(&deposit_id).cloned();
        }
        None
    }

    /// List all deposits in a ledger
    pub fn list_deposits(&self, ledger_id: &str) -> Vec<(DepositId, Deposit)> {
        let ledgers = self.handler.ledgers.lock().unwrap();
        if let Some(ledger_arc) = ledgers.get(ledger_id) {
            let ledger = ledger_arc.read().unwrap();
            return ledger.state.deposits.iter()
                .map(|(k, v)| (*k, v.clone()))
                .collect();
        }
        Vec::new()
    }

    /// Complete a deposit offer with co-signing and broadcast.
    ///
    /// This is the async version that handles the full co-signing flow.
    /// Uses a per-offer lock file to prevent concurrent completion by daemon and CLI.
    pub async fn complete_deposit_offer(
        &mut self,
        offer_id: &[u8; 32],
        funding_txid: String,
        funding_amount_sats: u64,
    ) -> Result<u64, Error> {
        use deposits_core::types::DepositOfferStatus;

        // Per-offer lock to prevent concurrent completion by daemon and CLI.
        // O_CREAT | O_EXCL is atomic on POSIX filesystems - safe as cross-process advisory lock.
        let wallet_dir = self.data_dir.join("wallet");
        let lock_path = wallet_dir.join(format!("completing_{}.lock", hex::encode(offer_id)));

        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
        {
            Ok(_) => {},
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // Check if the lock is stale (process crashed while holding it)
                let is_stale = std::fs::metadata(&lock_path)
                    .and_then(|m| m.modified())
                    .map(|t| t.elapsed().unwrap_or_default().as_secs() > 20)
                    .unwrap_or(false);

                if is_stale {
                    // Remove stale lock and try again
                    tracing::warn!(
                        "Removing stale completion lock for deposit {}...",
                        &hex::encode(offer_id)[..16]
                    );
                    let _ = std::fs::remove_file(&lock_path);
                    match std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&lock_path)
                    {
                        Ok(_) => {},
                        Err(_) => {
                            return Err(Error::Protocol(format!(
                                "Could not acquire completion lock for deposit {}...",
                                &hex::encode(offer_id)[..16]
                            )));
                        }
                    }
                } else {
                    // Another process is actively completing this - wait for it to finish
                    tracing::info!(
                        "Deposit {}... completion already in progress, waiting up to 15s",
                        &hex::encode(offer_id)[..16]
                    );
                    for _ in 0..30 {
                        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                        if !lock_path.exists() {
                            break;
                        }
                    }
                    // Reload and check the other process's result
                    self.reload_deposit_offers();
                    let offers = self.deposit_offers.lock().unwrap();
                    match offers.get(offer_id) {
                        Some((_, DepositOfferStatus::Completed { amount_sats, .. })) => {
                            tracing::info!(
                                "Deposit completed by concurrent process: {} sats",
                                amount_sats
                            );
                            return Ok(*amount_sats * 1000);
                        }
                        _ => {
                            drop(offers);
                            if lock_path.exists() {
                                // Lock still held - other process is still running.
                                // Do NOT remove it or proceed - that would cause concurrent
                                // completion and hash chain breaks.
                                return Err(Error::Protocol(format!(
                                    "Deposit {}... completion still in progress by another process",
                                    &hex::encode(offer_id)[..16]
                                )));
                            }
                            // Lock was released but process failed - safe to retry ourselves
                            tracing::info!(
                                "Concurrent completion failed for {}..., retrying",
                                &hex::encode(offer_id)[..16]
                            );
                            match std::fs::OpenOptions::new()
                                .write(true)
                                .create_new(true)
                                .open(&lock_path)
                            {
                                Ok(_) => {},
                                Err(_) => {
                                    return Err(Error::Protocol(format!(
                                        "Could not acquire completion lock for deposit {}...",
                                        &hex::encode(offer_id)[..16]
                                    )));
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                // Lock creation failed for unexpected reason - don't proceed without lock
                return Err(Error::Protocol(format!(
                    "Failed to create deposit completion lock: {}",
                    e
                )));
            }
        };

        // Lock acquired. Reload offer status from disk to catch any completions
        // that happened just before we got the lock.
        self.reload_deposit_offers();

        // Run the actual completion logic
        let result = self.do_complete_deposit_offer(offer_id, funding_txid, funding_amount_sats).await;

        // Release lock
        let _ = std::fs::remove_file(&lock_path);

        result
    }

    /// Inner completion logic, called with the per-offer lock held.
    async fn do_complete_deposit_offer(
        &mut self,
        offer_id: &[u8; 32],
        funding_txid: String,
        funding_amount_sats: u64,
    ) -> Result<u64, Error> {
        use deposits_core::types::DepositOfferStatus;

        // Get the offer
        let (offer, status) = self.get_deposit_offer(offer_id)
            .ok_or(Error::OfferNotFound)?;

        // Check offer is in correct state.
        // If already Completed (another process finished just before we got the lock), return its result.
        if let DepositOfferStatus::Completed { amount_sats, .. } = &status {
            tracing::info!("Deposit already completed (detected after reload): {} sats", amount_sats);
            return Ok(*amount_sats * 1000);
        }
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

        // Parse txid from hex string to bytes
        let txid_bytes: [u8; 32] = hex::decode(&funding_txid)
            .map_err(|e| Error::Protocol(format!("Invalid txid hex: {}", e)))?
            .try_into()
            .map_err(|_| Error::Protocol("Invalid txid length".to_string()))?;

        // Look up the ledger by ledger_id hash
        let (reserves_id, _) = self.get_ledger_by_ledger_id(&offer.ledger_id)
            .ok_or_else(|| Error::Protocol(format!(
                "Ledger not found for ledger_id: {}",
                &offer.ledger_id[..16.min(offer.ledger_id.len())]
            )))?;

        // First, open the deposit if it doesn't already exist (with co-signing)
        match self.open_deposit(&reserves_id, &offer.descriptor, offer.fees.clone(), offer.transfer_fees.clone()).await {
            Ok(_) => {
                tracing::info!(
                    "Opened deposit for {} in ledger {}",
                    hex::encode(offer.deposit_id),
                    &reserves_id[..16.min(reserves_id.len())]
                );
            }
            Err(e) => {
                // If deposit already exists, that's fine - continue to credit
                let err_msg = format!("{}", e);
                if !err_msg.contains("already exists") {
                    return Err(e);
                }
                tracing::debug!("Deposit already exists, proceeding to credit");
            }
        }

        // Credit the deposit with co-signing
        let new_balance = self.credit_deposit_onchain(
            &reserves_id,
            &offer.descriptor,
            amount_msats,
            txid_bytes,
            0, // vout - typically 0 for deposit offers
            offer.funding_address.clone(),
        ).await?;

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
            hex::encode(offer.deposit_id)
        );

        Ok(new_balance)
    }

    /// Check if a deposit offer's funding address has received funds
    ///
    /// Returns Some((txid, amount_sats)) if funds are detected, None otherwise.
    /// This version syncs the wallet before checking - use for single-call CLI usage.
    pub fn check_deposit_offer_funding(&self, offer_id: &[u8; 32]) -> Result<Option<(String, u64)>, Error> {
        // Sync wallet first for CLI/single-call usage
        self.wallet.sync()?;
        self.check_deposit_offer_funding_inner(offer_id, true)
    }

    /// Inner implementation of check_deposit_offer_funding
    ///
    /// If skip_sync is true, assumes wallet is already synced (for batch operations).
    fn check_deposit_offer_funding_inner(&self, offer_id: &[u8; 32], skip_sync: bool) -> Result<Option<(String, u64)>, Error> {
        let (offer, status) = self.get_deposit_offer(offer_id)
            .ok_or(Error::OfferNotFound)?;

        tracing::debug!(
            "check_deposit_offer_funding: offer {} status {:?}",
            hex::encode(&offer_id[..8]),
            status
        );

        // If already completed, return the completed info
        if let DepositOfferStatus::Completed { txid, amount_sats, .. } = &status {
            tracing::debug!("check_deposit_offer_funding: already completed");
            return Ok(Some((txid.clone(), *amount_sats)));
        }

        // Only check pending offers
        if !matches!(status, DepositOfferStatus::Pending) {
            tracing::debug!("check_deposit_offer_funding: skipping non-pending offer");
            return Ok(None);
        }

        // Parse the funding address and check for received funds
        let address = offer.funding_address.parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()
            .map_err(|e| Error::Protocol(format!("Invalid funding address: {}", e)))?;

        // Sync wallet if not already synced
        if !skip_sync {
            self.wallet.sync()?;
        }

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
        ledger_id: &str,
    ) -> Option<Vec<deposits_core::types::SignedLedgerUpdate>> {
        let ledgers = self.handler.ledgers.lock().unwrap();
        if let Some(ledger_arc) = ledgers.get(ledger_id) {
            let ledger = ledger_arc.read().unwrap();
            return Some(ledger.history.clone());
        }
        None
    }

    /// Get a specific ledger by ledger_id
    pub fn get_ledger(&self, ledger_id: &str) -> Option<Ledger> {
        let ledgers = self.handler.ledgers.lock().unwrap();
        if let Some(ledger_arc) = ledgers.get(ledger_id) {
            let ledger = ledger_arc.read().unwrap();
            return Some(ledger.clone());
        }
        None
    }

    /// Get the primary ledger (operator ledger backed by reserves)
    /// Returns (ledger_id, ledger) tuple
    /// Only returns ledgers with non-zero reserves (the actual reserves ledger)
    pub fn get_primary_ledger(&self) -> Option<(String, Ledger)> {
        let ledgers = self.handler.ledgers.lock().unwrap();
        for (ledger_id, ledger_arc) in ledgers.iter() {
            let ledger = ledger_arc.read().unwrap();
            if ledger.operator_key() == self.node_id {
                // Only return ledgers backed by reserves
                if ledger.reserves_amount() > 0 {
                    return Some((ledger_id.clone(), ledger.clone()));
                }
            }
        }
        None
    }

    /// Get a ledger by reserves_key (Bitcoin address string)
    /// Returns (ledger_id, ledger) tuple
    /// Searches all ledgers (both operator and partner roles)
    pub fn get_ledger_by_reserves_key(&self, reserves_key: &str) -> Option<(String, Ledger)> {
        let ledgers = self.handler.ledgers.lock().unwrap();
        for (ledger_id, ledger_arc) in ledgers.iter() {
            let ledger = ledger_arc.read().unwrap();
            if ledger.reserves_key() == reserves_key {
                return Some((ledger_id.clone(), ledger.clone()));
            }
        }
        None
    }

    /// Get a ledger by ledger_id (64-char hex hash)
    /// Returns (ledger_id, ledger) tuple
    /// The ledger_id is stable across custody transfers
    pub fn get_ledger_by_ledger_id(&self, ledger_id_hex: &str) -> Option<(String, Ledger)> {
        let ledgers = self.handler.ledgers.lock().unwrap();
        // Direct lookup since ledger_id is now the key
        if let Some(ledger_arc) = ledgers.get(ledger_id_hex) {
            let ledger = ledger_arc.read().unwrap();
            return Some((ledger_id_hex.to_string(), ledger.clone()));
        }
        None
    }

    /// Get a ledger by either ledger_id (64-char hex hash) or reserves_key (Bitcoin address)
    /// Returns (ledger_id, ledger) tuple
    /// Tries ledger_id first, then falls back to reserves_key lookup
    pub fn get_ledger_with_id(&self, identifier: &str) -> Option<(String, Ledger)> {
        // First try by ledger_id (more common after rotation)
        if let Some(result) = self.get_ledger_by_ledger_id(identifier) {
            return Some(result);
        }
        // Fall back to reserves_key (Bitcoin address)
        self.get_ledger_by_reserves_key(identifier)
    }

    /// Resolve a ledger_id or reserves_key to ledger_id
    /// Returns error string if ledger is not found
    fn resolve_to_ledger_id(&self, identifier: &str) -> Result<String, String> {
        // First try direct lookup by ledger_id
        if let Some((lid, _)) = self.get_ledger_by_ledger_id(identifier) {
            return Ok(lid);
        }
        // Fall back to reserves_key lookup
        if let Some((lid, _)) = self.get_ledger_by_reserves_key(identifier) {
            return Ok(lid);
        }
        Err(format!("Ledger not found: {}", &identifier[..16.min(identifier.len())]))
    }

    /// Check if we are the operator of the given ledger
    /// Returns false if ledger not found or we're just a quorum member
    fn is_operator_of_ledger(&self, ledger_id: &str) -> bool {
        if let Some((_, ledger)) = self.get_ledger_by_ledger_id(ledger_id) {
            return ledger.operator_key() == self.node_id;
        }
        if let Some((_, ledger)) = self.get_ledger_by_reserves_key(ledger_id) {
            return ledger.operator_key() == self.node_id;
        }
        false
    }
}
