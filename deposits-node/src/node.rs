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

/// Fast hex encoding for PublicKey (avoids byte-by-byte fmt::LowerHex overhead).
#[inline]
fn pubkey_hex(pk: &PublicKey) -> String {
    hex::encode(pk.serialize())
}
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

/// Configuration for the deposits-node node
#[derive(Clone)]
pub struct NodeConfig {
    /// Seed for wallet/identity (32 bytes)
    pub seed: [u8; 32],

    /// Bitcoin network
    pub network: Network,

    /// Electrum server URL
    pub electrum_url: String,

    /// Nostr relay URLs (fast relays for subscriptions + publishing)
    pub relays: Vec<String>,

    /// Slow (durable) relay URLs for gap-fill fetch_events only
    pub slow_relays: Vec<String>,

    /// Data directory
    pub data_dir: PathBuf,

    /// Operator name for advertisements (optional)
    pub operator_name: Option<String>,

    /// Use fast polling intervals (for regtest/testing)
    /// When enabled: periodic=5s, poll=5s, reload=2s
    /// When disabled: periodic=60s, poll=30s, reload=5s
    pub fast_poll: bool,

    /// Skip Schnorr signature verification of incoming Nostr events.
    /// Only use with trusted relays (e.g., local/private relays).
    pub skip_nostr_verify: bool,
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
    /// The co-signer's ECDSA signature over (cosign_data || member_ledger_hash)
    pub cosign_signature: [u8; 64],

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

/// State for a non-blocking confiscation request awaiting co-signatures.
struct PendingConfiscation {
    /// Nostr event ID of our confiscation_sign request
    request_id: String,
    /// The unsigned confiscation transaction
    confiscation_tx: bitcoin::Transaction,
    /// Sighash bytes that all signers sign
    sighash_bytes: [u8; 32],
    /// Signatures collected so far (signer pubkey -> 64-byte Schnorr sig)
    signatures: std::collections::HashMap<bitcoin::secp256k1::PublicKey, [u8; 64]>,
    /// Number of signatures required
    required_sigs: usize,
    /// The VoterSet for building the witness
    voter_set: deposits_core::VoterSet,
    /// Tier index in threshold config for the control block
    tier_index: usize,
    /// The leaf script for the Taproot spend
    leaf_script: bitcoin::ScriptBuf,
    /// The TaprootReservesOutput (for control block)
    taproot_output: deposits_core::TaprootReservesOutput,
    /// Confiscated marker path
    confiscated_marker: PathBuf,
    /// Lottery address (for logging)
    lottery_address: String,
    /// Ledger prefix (for logging)
    ledger_prefix: String,
    /// When we sent the request (for timeout)
    created_at: std::time::Instant,
}

/// A deposits-node node
pub struct Node {
    /// Our node ID (secp256k1 pubkey)
    pub node_id: PublicKey,

    /// Pre-computed hex string of node_id (avoids repeated byte-by-byte formatting)
    node_id_hex: String,

    /// Shared secp256k1 context (expensive to create — ~1MB allocation + randomization)
    secp: Secp256k1<bitcoin::secp256k1::All>,

    /// The wallet for on-chain operations
    pub wallet: Arc<Wallet>,

    /// Nostr transport for peer messaging
    pub nostr: NostrTransport,

    /// The protocol handler
    pub handler: Arc<DepositsHandler>,

    /// Outbound message receiver (for async sending via nostr).
    /// Wrapped in Mutex so run loop can drain with &self.
    outbound_rx: Mutex<mpsc::UnboundedReceiver<OutboundMessage>>,

    /// Pending deposit offers indexed by offer_id
    deposit_offers: Mutex<HashMap<[u8; 32], (DepositOffer, DepositOfferStatus)>>,

    /// Pending withdrawals indexed by withdrawal_id
    withdrawals: Mutex<HashMap<[u8; 32], (OnChainWithdrawal, OnChainWithdrawalStatus)>>,

    /// Pending collateral lock requests (request_id -> our_reserves_id)
    /// Used to auto-record attestations when responses arrive
    pending_collateral_requests: Mutex<HashMap<String, String>>,

    /// Pending co-sign requests: request_id -> (ledger_id, oneshot sender for co-sign result)
    /// The result includes the co-signer's signature and the member's ledger hash
    pending_cosign_requests: Arc<Mutex<HashMap<String, (String, tokio::sync::oneshot::Sender<CoSignResult>)>>>,

    /// Semaphore to limit concurrent request_cosign calls.
    /// Multiple concurrent mini loops compete for shared channels (response_rx,
    /// ledger_rx) and can deadlock when all operators are in batch-await simultaneously.
    /// Serializing cosign requests prevents this while still allowing concurrent
    /// processing of non-cosign requests (cosign_update, partner_join, etc.).
    cosign_semaphore: Arc<tokio::sync::Semaphore>,

    /// Pending Lightning invoices: payment_hash -> (ledger_id, deposit_pubkey, amount_msat)
    /// Used to credit deposits when payments are received
    pending_invoices: Arc<Mutex<HashMap<[u8; 32], PendingInvoice>>>,

    /// Processed request event IDs (to avoid duplicate processing from polling).
    /// Two-generation design: on periodic cleanup, current is swapped to prev.
    /// Lookups check both; inserts go to current. This caps memory at ~2 periods
    /// while never losing entries within the last period (preventing re-processing
    /// of transfer_lock/transfer_complete which consume one-time nonces).
    processed_requests: Mutex<std::collections::HashSet<String>>,
    processed_requests_prev: Mutex<std::collections::HashSet<String>>,

    /// Event IDs of requests sent by THIS daemon process.
    /// Used to filter out our own requests (Nostr broadcasts to all subscribers).
    /// Two-generation design (same as processed_requests): current + prev.
    sent_events: Mutex<std::collections::HashSet<String>>,
    sent_events_prev: Mutex<std::collections::HashSet<String>>,

    /// Active per-ledger request processing tasks.
    /// Only one task runs per ledger at a time to maintain hash-chain serialization.
    /// The main loop checks for completion and spawns new tasks without blocking.
    active_ledger_tasks: Mutex<HashMap<String, tokio::task::JoinHandle<(String, usize, usize)>>>,

    /// Persistent per-ledger worker channels. Each owned ledger gets a dedicated
    /// mpsc channel. The main loop routes requests to the channel. A persistent
    /// tokio task reads and processes requests one at a time — no spawn/reap gaps.
    ledger_workers: Mutex<HashMap<String, tokio::sync::mpsc::UnboundedSender<crate::nostr::LedgerRequest>>>,

    /// Persistent per-ledger workers for cosign requests (where we're a quorum member).
    /// Separate from ledger_workers so cosign request processing never blocks the main
    /// loop — the main loop must stay free to pump process_events + drain_responses so
    /// our OWN cosign responses get routed to oneshot channels.
    cosign_workers: Mutex<HashMap<String, tokio::sync::mpsc::UnboundedSender<crate::nostr::LedgerRequest>>>,

    /// Optional allowlist of npubs (hex) that can open deposits.
    /// If empty, anyone can open deposits. Loaded from {data_dir}/deposit_allowlist.txt.
    deposit_allowlist: RwLock<std::collections::HashSet<String>>,

    /// Data directory for persistence
    data_dir: PathBuf,

    /// Primary relay URL for Nostr
    relay_url: String,

    /// Use fast polling intervals (for regtest/testing)
    fast_poll: bool,

    /// Cached joined ledger IDs (from QuorumJoin history scan).
    /// Self-validates by checking history lengths — only rescans when history grows.
    joined_ledger_cache: Mutex<Option<Vec<String>>>,
    /// History lengths at last cache fill. Used to detect when rescan is needed
    /// without doing the full O(history_len) scan every cycle.
    joined_ledger_cache_versions: Mutex<HashMap<String, usize>>,

    /// Joined ledger IDs that have been imported from Nostr (or attempted).
    /// Prevents re-importing on every reload cycle.
    imported_joined_ledgers: Mutex<std::collections::HashSet<String>>,

    /// Pending confiscation requests awaiting co-signatures from quorum members.
    /// Key is the ledger prefix (from custody_armed marker).
    pending_confiscations: Mutex<HashMap<String, PendingConfiscation>>,

    /// Joined ledger IDs detected as stale during cosign requests.
    /// Drained and re-imported in the run loop to avoid blocking request handlers.
    stale_joined_ledgers: Mutex<std::collections::HashSet<String>>,

    /// Rate-limiter for background relay fetches of stale joined ledgers.
    /// Tracks when each ledger was last fetched from relay (30s cooldown per ledger).
    last_relay_fetch_times: Mutex<HashMap<String, std::time::Instant>>,

    /// Cache mapping target_ledger_id → our member ledger key (in the ledgers HashMap).
    /// Populated on first cosign request per target, invalidated with joined_ledger_cache.
    /// Eliminates the O(N) full history TLV-decode scan in process_cosign_request.
    cosign_member_cache: Mutex<HashMap<String, String>>,

    /// Ledger IDs that have been modified but not yet persisted to disk.
    /// Flushed at the end of each request drain batch to reduce write syscalls.
    dirty_ledgers: Mutex<std::collections::HashSet<String>>,

    /// Cache for has_quorum_reserves: ledger_id → (result, history_len_when_scanned).
    /// Once a QuorumBegin is found, the result is permanently true (never reverts).
    /// For false results, the history_len is stored so we only rescan when history grows.
    quorum_reserves_cache: Mutex<HashMap<String, (bool, usize)>>,

    /// Cache for is_operator_of_ledger: ledger_id → (result, history_len_when_scanned).
    /// Once true (operator found), the result is permanent.
    /// For false results, we rescan when history grows.
    operator_of_cache: Mutex<HashMap<String, (bool, usize)>>,
}

impl Node {
    /// Clock-skew buffer (seconds) when computing `since` for relay fetches.
    const RELAY_FETCH_CLOCK_SKEW_SECS: u64 = 30;
    /// Events requested per relay page during joined-ledger reimport.
    const RELAY_FETCH_PAGE_LIMIT: usize = 5000;
    /// Stop paginating if a page returns fewer than this many events.
    const RELAY_FETCH_MIN_PAGE: usize = 1000;
    /// Maximum pages before giving up (safety cap).
    const RELAY_FETCH_MAX_PAGES: u32 = 50;
    /// Per-ledger cooldown between background relay fetches.
    const RELAY_FETCH_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(30);
    /// Maximum updates re-broadcast per resync request.
    const RESYNC_BATCH_CAP: usize = 500;

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

        // Create nostr transport (fast relays for subs/publish, slow relays for gap-fill)
        let nostr = NostrTransport::new_with_slow(secret_key, config.relays, config.slow_relays, config.skip_nostr_verify).await?;

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

        // Subscribe globally (4 compacted kind filters for all event types).
        // CLI commands don't call start(), so we do this here too.
        if let Err(e) = nostr.subscribe_global().await {
            tracing::warn!("Failed to subscribe globally during init: {}", e);
        }

        tracing::info!("Node created with ID: {}", node_id);

        let node_id_hex = hex::encode(node_id.serialize());

        Ok(Self {
            node_id,
            node_id_hex,
            secp,
            wallet,
            nostr,
            handler: handler_arc,
            outbound_rx: Mutex::new(outbound_rx),
            deposit_offers: Mutex::new(deposit_offers),
            withdrawals: Mutex::new(withdrawals),
            pending_collateral_requests: Mutex::new(HashMap::new()),
            pending_cosign_requests: Arc::new(Mutex::new(HashMap::new())),
            cosign_semaphore: Arc::new(tokio::sync::Semaphore::new(8)),
            pending_invoices: Arc::new(Mutex::new(HashMap::new())),
            processed_requests: Mutex::new(std::collections::HashSet::new()),
            processed_requests_prev: Mutex::new(std::collections::HashSet::new()),
            sent_events: Mutex::new(std::collections::HashSet::new()),
            sent_events_prev: Mutex::new(std::collections::HashSet::new()),
            active_ledger_tasks: Mutex::new(HashMap::new()),
            ledger_workers: Mutex::new(HashMap::new()),
            cosign_workers: Mutex::new(HashMap::new()),
            deposit_allowlist: RwLock::new(Self::load_allowlist(&config.data_dir)),
            data_dir: config.data_dir,
            relay_url,
            fast_poll: config.fast_poll,
            joined_ledger_cache: Mutex::new(None),
            joined_ledger_cache_versions: Mutex::new(HashMap::new()),
            imported_joined_ledgers: Mutex::new(std::collections::HashSet::new()),
            pending_confiscations: Mutex::new(HashMap::new()),
            stale_joined_ledgers: Mutex::new(std::collections::HashSet::new()),
            last_relay_fetch_times: Mutex::new(HashMap::new()),
            cosign_member_cache: Mutex::new(HashMap::new()),
            dirty_ledgers: Mutex::new(std::collections::HashSet::new()),
            quorum_reserves_cache: Mutex::new(HashMap::new()),
            operator_of_cache: Mutex::new(HashMap::new()),
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
            let secp = &self.secp;
            let msg = Message::from_digest(*hash.as_byte_array());
            let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &self.wallet.operator_secret());
            let sig = secp.sign_schnorr(&msg, &keypair);

            update.operator_signature = sig.serialize();
            tracing::debug!("Signed update seq={} for ledger {}", update.sequence_number, &ledger_id[..16.min(ledger_id.len())]);
        }

        // Finalize state.hash = chain_hash = SHA256(current_hash || operator_signature)
        ledger.finalize_chain_hash();

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

    /// Mark a ledger as dirty (modified but not yet persisted).
    /// Deferred persistence reduces write syscalls by batching multiple
    /// modifications into a single persist at the end of request processing.
    fn mark_ledger_dirty(&self, ledger_id: &str) {
        self.dirty_ledgers.lock().unwrap().insert(ledger_id.to_string());
    }

    /// Flush all dirty ledgers to disk.
    /// Called at the end of each request drain batch.
    fn flush_dirty_ledgers(&self) {
        let dirty: Vec<String> = self.dirty_ledgers.lock().unwrap().drain().collect();
        if dirty.is_empty() {
            return;
        }
        // Pre-check: if handler.ledgers is contended (orphaned JoinSet tasks),
        // defer ALL dirty ledgers to the next cycle rather than blocking the thread.
        if self.handler.ledgers.try_lock().is_err() {
            let mut d = self.dirty_ledgers.lock().unwrap();
            let count = dirty.len();
            for id in dirty { d.insert(id); }
            tracing::warn!("flush_dirty_ledgers: ledgers lock contended, deferring {} ledgers", count);
            return;
        }
        for ledger_id in &dirty {
            if let Err(e) = self.handler.persist_ledger_to_disk(ledger_id) {
                tracing::warn!("Failed to persist dirty ledger {}: {}", &ledger_id[..16.min(ledger_id.len())], e);
            }
        }
    }

    /// Broadcast the most recent ledger update to Nostr
    ///
    /// Call this after appending an operation to a ledger to ensure the update
    /// is published to the Nostr relay for other participants to see.
    pub async fn broadcast_last_update(&self, ledger_id: &str) -> Result<String, Error> {
        // Get the ledger by ledger_id and clone the update.
        // Clone before the await to avoid holding RwLockReadGuard across await (not Send).
        let (update, seq) = {
            let ledger_arc = self.handler.ledgers.lock().unwrap()
                .get(ledger_id)
                .cloned()
                .ok_or_else(|| Error::Protocol(format!("Ledger not found: {}", ledger_id)))?;
            let ledger = ledger_arc.read().unwrap();
            let update = ledger.history.last()
                .ok_or_else(|| Error::Protocol("Ledger has no updates".to_string()))?
                .clone();
            let seq = update.sequence_number;
            (update, seq)
        };

        // Broadcast to Nostr
        let event_id = self.nostr.broadcast_ledger_update(&update).await?;
        tracing::info!("Broadcast update seq={} to Nostr: {}", seq, &event_id[..16]);

        Ok(event_id)
    }

    /// Broadcast all ledger updates to Nostr
    ///
    /// Use this when initializing a ledger (e.g., after ledger_open) to broadcast
    /// all initial operations (LedgerOpen, LedgerOpen, etc.)
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
    pub async fn start(&self) -> Result<(), Error> {
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
        let joined_ids = self.get_joined_ledger_ids();
        ledger_ids.extend(joined_ids.clone());

        // Seed ALL locally-loaded ledgers (owned + joined) into stale_joined_ledgers
        // so the background gap-fill loop catches up from the relay after restart.
        // This recovers any updates that were deferred (mark_ledger_dirty) but not
        // flushed before the previous shutdown. Safe because reimport_joined_ledger()
        // already checks if fetched data is newer than local tip.
        {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let mut stale = self.stale_joined_ledgers.lock().unwrap();
            for lid in ledgers.keys() {
                stale.insert(lid.clone());
            }
            if !stale.is_empty() {
                tracing::info!("Seeded {} ledgers for background catch-up", stale.len());
            }
        }

        // Set up per-ledger filters for polling and interested ledger set
        if !ledger_ids.is_empty() {
            self.nostr.set_interested_ledgers(ledger_ids.iter().cloned());
            self.nostr.set_request_ledger_filter(ledger_ids.clone());
        }

        // Global subscription was already set up in new(), but ensure it's active
        if let Err(e) = self.nostr.subscribe_global().await {
            tracing::warn!("Failed to subscribe globally: {}", e);
        }

        tracing::info!("Node started, listening for messages");
        Ok(())
    }

    /// Register interest in a specific ledger for event routing.
    /// Call this after opening a new ledger to start watching it.
    /// Global subscription handles all kinds; this just adds to the interest set.
    pub async fn subscribe_to_ledger(&self, ledger_id: &str) -> Result<(), Error> {
        self.nostr.add_interested_ledger(ledger_id.to_string());
        Ok(())
    }

    /// Get ledger IDs of ledgers we've joined as a quorum member.
    ///
    /// Uses an incremental scan: on the first call, scans all history. On subsequent
    /// calls, only scans new entries since the last scan. This avoids the O(full_history)
    /// scan that was triggered every 2s reload when history grows during sustained load.
    fn get_joined_ledger_ids(&self) -> Vec<String> {
        // Fast path: check if cache is populated AND history hasn't grown.
        //
        // IMPORTANT: Clone cache data BEFORE acquiring handler.ledgers to avoid
        // ABBA deadlock. The cache-miss path below acquires handler.ledgers first,
        // then joined_ledger_cache. If we held joined_ledger_cache while waiting
        // for handler.ledgers here, a concurrent task in the cache-miss path
        // (holding handler.ledgers, waiting for joined_ledger_cache) would deadlock.
        {
            let (cached_data, cached_versions) = {
                let cache = self.joined_ledger_cache.lock().unwrap();
                let versions = self.joined_ledger_cache_versions.lock().unwrap();
                (cache.clone(), versions.clone())
            };
            // Cache locks released — safe to acquire handler.ledgers

            if let Some(ref cached) = cached_data {
                let ledgers = self.handler.ledgers.lock().unwrap();
                let mut stale = false;

                if ledgers.len() != cached_versions.len() {
                    stale = true;
                } else {
                    for (lid, arc) in ledgers.iter() {
                        let l = arc.read().unwrap();
                        if l.operator_key() == self.node_id {
                            match cached_versions.get(lid) {
                                Some(&v) if v == l.history.len() => {}
                                _ => { stale = true; break; }
                            }
                        }
                    }
                }

                if !stale {
                    return cached.clone();
                }
            }
        }

        // Cache miss — incremental scan: only check entries we haven't seen yet.
        // QuorumJoin entries are rare and only appear early in history, so after
        // the first full scan, incremental scans process near-zero new entries.
        let t0 = std::time::Instant::now();
        let mut new_versions = HashMap::new();
        let ledgers = self.handler.ledgers.lock().unwrap();

        // Start from previous cached result + scan offsets
        let prev_cache = self.joined_ledger_cache.lock().unwrap().clone();
        let prev_versions = self.joined_ledger_cache_versions.lock().unwrap().clone();
        let mut joined = prev_cache.unwrap_or_default();
        let mut scanned_new = 0usize;

        for (ledger_id, ledger_arc) in ledgers.iter() {
            let ledger = ledger_arc.read().unwrap();
            if ledger.operator_key() == self.node_id {
                let history_len = ledger.history.len();
                new_versions.insert(ledger_id.clone(), history_len);

                // Only scan entries beyond what we've already scanned.
                // Cap at history_len in case history was truncated.
                let prev_len = prev_versions.get(ledger_id).copied().unwrap_or(0)
                    .min(ledger.history.len());
                for update in ledger.history.iter().skip(prev_len) {
                    scanned_new += 1;
                    if update.message_type != deposits_core::messages::consts::QUORUM_JOIN {
                        continue;
                    }
                    if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                        if let LedgerOperation::QuorumJoin { ledger_id, .. } = op {
                            if !joined.contains(&ledger_id) {
                                joined.push(ledger_id);
                            }
                        }
                    }
                }
            }
        }
        drop(ledgers);

        let elapsed = t0.elapsed();
        if elapsed.as_millis() > 1 || scanned_new > 100 {
            let total: usize = new_versions.values().sum();
            tracing::info!("[PROFILE] get_joined_ledger_ids: scanned {} new entries ({} total) in {:?}",
                scanned_new, total, elapsed);
        }

        let mut cache = self.joined_ledger_cache.lock().unwrap();
        *cache = Some(joined.clone());
        *self.joined_ledger_cache_versions.lock().unwrap() = new_versions;

        joined
    }

    /// Force-invalidate the joined ledger cache.
    /// Only needed when ledger data changes externally (e.g., discover_new_ledgers).
    fn invalidate_joined_ledger_cache(&self) {
        let mut cache = self.joined_ledger_cache.lock().unwrap();
        *cache = None;
        self.joined_ledger_cache_versions.lock().unwrap().clear();
        // Also invalidate cosign member cache since QuorumJoin mappings may have changed
        self.cosign_member_cache.lock().unwrap().clear();
    }

    /// Auto-import joined ledgers from Nostr so we can validate their updates.
    /// Called from the reload cycle when we discover joined ledger IDs not in our local map.
    async fn auto_import_joined_ledgers(&self, joined_ids: &[String]) {
        use deposits_core::validation::LedgerExport;
        use deposits_core::messages::LedgerOperation;
        use deposits_core::TlvDecode;
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
        use nostr_sdk::{Filter, Kind};
        use nostr_sdk::prelude::{SingleLetterTag, Alphabet};

        for ledger_id in joined_ids {
            // Skip if already in local map
            {
                let ledgers = self.handler.ledgers.lock().unwrap();
                if ledgers.contains_key(ledger_id) {
                    // Mark as imported so we don't check again
                    self.imported_joined_ledgers.lock().unwrap().insert(ledger_id.clone());
                    continue;
                }
            }

            // Skip if already attempted import
            {
                let imported = self.imported_joined_ledgers.lock().unwrap();
                if imported.contains(ledger_id) {
                    continue;
                }
            }

            tracing::info!("Auto-importing joined ledger {}...", &ledger_id[..16.min(ledger_id.len())]);

            // Fetch ledger updates from Nostr
            let filter = Filter::new()
                .kind(Kind::Custom(crate::nostr::KIND_LEDGER_UPDATE))
                .custom_tag(SingleLetterTag::lowercase(Alphabet::D), [ledger_id.as_str()]);

            let events = match self.nostr.fetch_client().fetch_events(vec![filter], None).await {
                Ok(events) => events,
                Err(e) => {
                    tracing::warn!("Failed to fetch ledger {} from Nostr: {}", &ledger_id[..16], e);
                    // Mark as attempted so we don't retry every cycle
                    self.imported_joined_ledgers.lock().unwrap().insert(ledger_id.clone());
                    continue;
                }
            };

            if events.is_empty() {
                tracing::debug!("No updates found on Nostr for ledger {}", &ledger_id[..16]);
                // Don't mark as imported — operator may not have exported yet
                continue;
            }

            // Decode events into SignedLedgerUpdate
            let mut updates: Vec<deposits_core::SignedLedgerUpdate> = Vec::new();
            for event in events.iter() {
                if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
                    if let Ok(update) = deposits_core::SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                        updates.push(update);
                    }
                }
            }

            if updates.is_empty() {
                tracing::debug!("No valid updates decoded for ledger {}", &ledger_id[..16]);
                continue;
            }

            // Sort by sequence, dedup exact copies
            updates.sort_by_key(|u| (u.sequence_number, u.operator_id.serialize(), u.current_hash));
            updates.dedup_by(|a, b| {
                a.sequence_number == b.sequence_number
                    && a.operator_id == b.operator_id
                    && a.current_hash == b.current_hash
            });

            // Find LedgerOpen to get metadata
            let ledger_open = updates.iter().find_map(|u| {
                if let Ok(op) = LedgerOperation::tlv_decode(&u.message) {
                    if let LedgerOperation::LedgerOpen { operator_id, reserves_id, ledger_address, genesis_block, .. } = op {
                        return Some((operator_id, reserves_id, ledger_address, genesis_block));
                    }
                }
                None
            });

            let Some((operator_id, reserves_id, ledger_address, genesis_block)) = ledger_open else {
                tracing::warn!("No LedgerOpen found for ledger {} — cannot import", &ledger_id[..16]);
                self.imported_joined_ledgers.lock().unwrap().insert(ledger_id.clone());
                continue;
            };

            // Build best chain (handle branches: prefer chains with DisputeAcquire, then longest)
            let by_prev: std::collections::HashMap<[u8; 32], Vec<&deposits_core::SignedLedgerUpdate>> = {
                let mut map = std::collections::HashMap::new();
                for u in &updates {
                    map.entry(u.previous_hash).or_insert_with(Vec::new).push(u);
                }
                map
            };

            // Walk the chain iteratively from genesis. At forks, pick the
            // branch that contains DisputeAcquire (or the longest if tied).
            let best_chain = {
                let mut chain: Vec<&deposits_core::SignedLedgerUpdate> = Vec::new();
                let mut current_hash = [0u8; 32];
                loop {
                    let Some(children) = by_prev.get(&current_hash) else { break; };
                    // Single child (common case): just follow it
                    let next = if children.len() == 1 {
                        children[0]
                    } else {
                        // Fork: peek one step ahead and pick best branch
                        let mut best_child: Option<&deposits_core::SignedLedgerUpdate> = None;
                        let mut best_has_acquire = false;
                        let mut best_depth = 0usize;
                        for &child in children {
                            let has_acquire = LedgerOperation::tlv_decode(&child.message)
                                .map(|op| matches!(op, LedgerOperation::DisputeAcquire { .. }))
                                .unwrap_or(false);
                            // Count chain length from this child (iterative peek)
                            let mut depth = 1usize;
                            let mut h = child.current_hash;
                            while let Some(next_children) = by_prev.get(&h) {
                                if let Some(first) = next_children.first() {
                                    h = first.current_hash;
                                    depth += 1;
                                } else {
                                    break;
                                }
                            }
                            let is_better = best_child.is_none()
                                || (has_acquire && !best_has_acquire)
                                || (has_acquire == best_has_acquire && depth > best_depth);
                            if is_better {
                                best_child = Some(child);
                                best_has_acquire = has_acquire;
                                best_depth = depth;
                            }
                        }
                        match best_child {
                            Some(c) => c,
                            None => break,
                        }
                    };
                    current_hash = next.current_hash;
                    chain.push(next);
                }
                chain
            };
            let filtered: Vec<deposits_core::SignedLedgerUpdate> = best_chain.iter().map(|u| (*u).clone()).collect();

            if filtered.is_empty() {
                tracing::warn!("No valid chain found for ledger {}", &ledger_id[..16]);
                self.imported_joined_ledgers.lock().unwrap().insert(ledger_id.clone());
                continue;
            }

            // Parse ledger_id bytes
            let ledger_id_bytes: [u8; 32] = match hex::decode(ledger_id) {
                Ok(bytes) if bytes.len() == 32 => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    arr
                }
                _ => {
                    tracing::warn!("Invalid ledger_id hex: {}", &ledger_id[..16]);
                    self.imported_joined_ledgers.lock().unwrap().insert(ledger_id.clone());
                    continue;
                }
            };

            let block_height = self.wallet.get_block_height().unwrap_or(0);

            let export = LedgerExport::new(
                ledger_id_bytes,
                genesis_block,
                operator_id,
                reserves_id,
                ledger_address,
                filtered.clone(),
                block_height,
            );

            match self.handler.import_ledger(export) {
                Ok((_report, _ledger_arc)) => {
                    tracing::info!(
                        "Auto-imported joined ledger {} ({} updates)",
                        &ledger_id[..16],
                        filtered.len()
                    );
                }
                Err(e) => {
                    tracing::warn!("Failed to import ledger {}: {}", &ledger_id[..16], e);
                }
            }

            self.imported_joined_ledgers.lock().unwrap().insert(ledger_id.clone());
        }
    }

    /// Re-import a joined ledger from Nostr, replacing any stale local copy.
    ///
    /// Called when `handle_ledger_update` detects a gap between the local
    /// history and an incoming update sequence number.
    async fn reimport_joined_ledger(&self, ledger_id: &str) -> Result<(), Error> {
        use deposits_core::validation::LedgerExport;
        use deposits_core::messages::LedgerOperation;
        use deposits_core::TlvDecode;
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
        use nostr_sdk::{Filter, Kind, Timestamp};
        use nostr_sdk::prelude::{SingleLetterTag, Alphabet};

        let local_tip_seq = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            ledgers.get(ledger_id)
                .map(|arc| arc.read().unwrap().next_sequence())
                .unwrap_or(0)
        };

        // Paginate forward using Nostr event created_at timestamps.
        // The relay returns newest-first capped by maxFilterLimit per query,
        // so we advance `since` after each page to walk forward through history.
        let mut cursor_ts: u64 = 0;

        let mut all_fetched: Vec<deposits_core::SignedLedgerUpdate> = Vec::new();
        let mut pages = 0u32;
        let max_pages = Self::RELAY_FETCH_MAX_PAGES;

        loop {
            let mut filter = Filter::new()
                .kind(Kind::Custom(crate::nostr::KIND_LEDGER_UPDATE))
                .custom_tag(SingleLetterTag::lowercase(Alphabet::D), [ledger_id])
                .limit(Self::RELAY_FETCH_PAGE_LIMIT);

            if cursor_ts > 0 {
                filter = filter.since(Timestamp::from(cursor_ts));
            }

            let events = self.nostr.fetch_client()
                .fetch_events(vec![filter], Some(std::time::Duration::from_secs(15)))
                .await
                .map_err(|e| Error::Protocol(format!("Failed to fetch: {}", e)))?;

            if events.is_empty() {
                break;
            }

            let mut page_max_ts = cursor_ts;
            let mut page_count = 0usize;
            for event in events.iter() {
                let event_ts = event.created_at.as_u64();
                if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
                    if let Ok(update) = deposits_core::SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                        if event_ts > page_max_ts {
                            page_max_ts = event_ts;
                        }
                        all_fetched.push(update);
                        page_count += 1;
                    }
                }
            }

            pages += 1;
            tracing::debug!(
                "reimport_joined_ledger {}...: page {} fetched {} updates (cursor_ts={}, max_ts={})",
                &ledger_id[..16.min(ledger_id.len())], pages, page_count, cursor_ts, page_max_ts,
            );

            // If the max timestamp didn't advance or we got fewer events than
            // our page size, we've reached the end.
            if page_max_ts <= cursor_ts || page_count < Self::RELAY_FETCH_MIN_PAGE || pages >= max_pages {
                break;
            }

            // Advance cursor past the newest event in this page (no overlap buffer
            // needed — dedup below handles any duplicates from boundary events).
            cursor_ts = page_max_ts;
            tokio::task::yield_now().await;
        }

        if all_fetched.is_empty() {
            // If the ledger already exists locally, relay having no events is fine
            // (fast relay expires all events). Not an error — we're already caught up.
            let exists = self.handler.ledgers.lock().unwrap().contains_key(ledger_id);
            if exists {
                tracing::debug!(
                    "Relay has no events for {}... but ledger exists locally — already caught up",
                    &ledger_id[..16.min(ledger_id.len())],
                );
                return Ok(());
            }
            return Err(Error::Protocol("No events on Nostr".into()));
        }

        tracing::info!(
            "reimport_joined_ledger {}...: fetched {} updates in {} pages (local_tip_seq={})",
            &ledger_id[..16.min(ledger_id.len())], all_fetched.len(), pages, local_tip_seq,
        );

        // For existing ledgers (the common case — stale set only contains known
        // ledgers), skip the expensive LedgerOpen search and chain walk. After
        // history truncation, LedgerOpen (seq 0) is gone from memory, so the old
        // genesis-based chain walk always fails. Instead, filter the relay events
        // for updates beyond our tip and append directly.
        let existing = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            ledgers.get(ledger_id).cloned()
        };

        if let Some(ledger_arc) = existing {
            // --- Fast path: existing ledger, incremental update ---
            let (local_tip_hash, local_next_seq) = {
                let ledger = ledger_arc.read().unwrap();
                (ledger.tail_hash(), ledger.next_sequence())
            };

            // Filter, sort, dedup relay events to those beyond our tip
            let mut new_updates: Vec<_> = all_fetched.into_iter()
                .filter(|u| u.sequence_number >= local_next_seq)
                .collect();
            new_updates.sort_by_key(|u| u.sequence_number);
            new_updates.dedup_by_key(|u| u.sequence_number);

            if new_updates.is_empty() {
                tracing::debug!(
                    "Ledger {}... already up to date (tip seq={})",
                    &ledger_id[..16.min(ledger_id.len())], local_next_seq,
                );
                return Ok(()); // Already caught up — not an error
            }

            // Verify the first new update chains from our tip
            if new_updates[0].sequence_number == local_next_seq
                && new_updates[0].previous_hash != local_tip_hash
            {
                return Err(Error::Protocol(format!(
                    "Chain break: update {} previous_hash doesn't match local tip",
                    local_next_seq,
                )));
            }

            match self.handler.apply_updates_to_ledger(ledger_id, new_updates.clone()) {
                Ok(applied) => {
                    tracing::info!(
                        "Re-imported joined ledger {} (+{} updates from relay, tip_seq {})",
                        &ledger_id[..16], applied,
                        new_updates.last().map(|u| u.sequence_number).unwrap_or(0),
                    );
                    Ok(())
                }
                Err(e) => {
                    tracing::warn!("Failed to apply relay updates to ledger {}: {}", &ledger_id[..16], e);
                    Err(Error::Protocol(format!("Apply updates failed: {}", e)))
                }
            }
        } else {
            // --- Slow path: new ledger, full import from genesis ---
            let mut updates: Vec<deposits_core::SignedLedgerUpdate> = all_fetched;
            updates.sort_by_key(|u| (u.sequence_number, u.operator_id.serialize(), u.current_hash));
            updates.dedup_by(|a, b| {
                a.sequence_number == b.sequence_number
                    && a.operator_id == b.operator_id
                    && a.current_hash == b.current_hash
            });

            let ledger_open = updates.iter().find_map(|u| {
                if let Ok(op) = LedgerOperation::tlv_decode(&u.message) {
                    if let LedgerOperation::LedgerOpen { operator_id, reserves_id, ledger_address, genesis_block, .. } = op {
                        return Some((operator_id, reserves_id, ledger_address, genesis_block));
                    }
                }
                None
            });

            let Some((operator_id, reserves_id, ledger_address, genesis_block)) = ledger_open else {
                return Err(Error::Protocol("No LedgerOpen in fetched events".into()));
            };

            // Build best chain from genesis
            let by_prev: std::collections::HashMap<[u8; 32], Vec<&deposits_core::SignedLedgerUpdate>> = {
                let mut map = std::collections::HashMap::new();
                for u in &updates { map.entry(u.previous_hash).or_insert_with(Vec::new).push(u); }
                map
            };

            let best_chain = {
                let mut chain: Vec<&deposits_core::SignedLedgerUpdate> = Vec::new();
                let mut current_hash = [0u8; 32];
                loop {
                    let Some(children) = by_prev.get(&current_hash) else { break; };
                    let next = if children.len() == 1 {
                        children[0]
                    } else {
                        let mut best_child: Option<&deposits_core::SignedLedgerUpdate> = None;
                        let mut best_has_acquire = false;
                        let mut best_depth = 0usize;
                        for &child in children {
                            let has_acquire = LedgerOperation::tlv_decode(&child.message)
                                .map(|op| matches!(op, LedgerOperation::DisputeAcquire { .. }))
                                .unwrap_or(false);
                            let mut depth = 1usize;
                            let mut h = child.current_hash;
                            while let Some(next_children) = by_prev.get(&h) {
                                if let Some(first) = next_children.first() {
                                    h = first.current_hash;
                                    depth += 1;
                                } else {
                                    break;
                                }
                            }
                            let is_better = best_child.is_none()
                                || (has_acquire && !best_has_acquire)
                                || (has_acquire == best_has_acquire && depth > best_depth);
                            if is_better {
                                best_child = Some(child);
                                best_has_acquire = has_acquire;
                                best_depth = depth;
                            }
                        }
                        match best_child {
                            Some(c) => c,
                            None => break,
                        }
                    };
                    current_hash = next.current_hash;
                    chain.push(next);
                }
                chain
            };
            let filtered: Vec<deposits_core::SignedLedgerUpdate> = best_chain.iter().map(|u| (*u).clone()).collect();

            if filtered.is_empty() {
                return Err(Error::Protocol("No valid chain found".into()));
            }

            let ledger_id_bytes: [u8; 32] = hex::decode(ledger_id)
                .map_err(|e| Error::Protocol(format!("Bad hex: {}", e)))
                .and_then(|bytes| {
                    if bytes.len() == 32 {
                        let mut arr = [0u8; 32]; arr.copy_from_slice(&bytes); Ok(arr)
                    } else {
                        Err(Error::Protocol("Wrong length".into()))
                    }
                })?;

            let block_height = self.wallet.get_block_height().unwrap_or(0);

            let export = LedgerExport::new(
                ledger_id_bytes, genesis_block, operator_id,
                reserves_id, ledger_address, filtered.clone(), block_height,
            );

            match self.handler.import_ledger(export) {
                Ok(_) => {
                    tracing::info!("Imported new joined ledger {} ({} updates, tip_seq {} from relay)",
                        &ledger_id[..16], filtered.len(), filtered.last().map(|u| u.sequence_number).unwrap_or(0));
                    Ok(())
                }
                Err(e) => {
                    tracing::warn!("Failed to import ledger {}: {}", &ledger_id[..16], e);
                    Err(Error::Protocol(format!("Import failed: {}", e)))
                }
            }
        }
    }

    /// Catch up a joined ledger's history from the event store's validated chain.
    ///
    /// Pure in-memory operation — no relay I/O. Returns the number of events
    /// appended to the ledger history, or 0 if the event store doesn't have
    /// anything beyond the ledger's current history.
    fn catch_up_ledger_from_event_store(&self, ledger_id: &str) -> usize {
        let ledger_arc = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            match ledgers.get(ledger_id) {
                Some(arc) => arc.clone(),
                None => return 0,
            }
        };

        let (ledger_id_bytes, operator_id, local_next_seq) = {
            let ledger = ledger_arc.read().unwrap();
            (ledger.state.ledger_id, ledger.state.parent_pubkey, ledger.next_sequence())
        };

        let store = self.handler.event_store.lock().unwrap();
        let tip = match store.validated_tip(&ledger_id_bytes, &operator_id) {
            Some(t) => t,
            None => return 0,
        };

        // Event store has nothing beyond what the ledger already has
        if tip < local_next_seq {
            return 0;
        }

        // Collect updates from local_next_seq..=tip
        let mut to_append = Vec::new();
        for seq in local_next_seq..=tip {
            if let Some(stored) = store.get_by_seq(&ledger_id_bytes, &operator_id, seq) {
                if stored.validity == deposits_core::event_store::Validity::Valid {
                    to_append.push(stored.update.clone());
                } else {
                    break; // Chain broken
                }
            } else {
                break; // Gap — can't continue
            }
        }
        drop(store);

        if to_append.is_empty() {
            return 0;
        }

        let count = to_append.len();
        let mut ledger = ledger_arc.write().unwrap();

        // Re-check after acquiring write lock (another thread may have caught up)
        let next_seq = ledger.next_sequence();
        let mut appended = 0u64;
        for update in to_append {
            if update.sequence_number == next_seq + appended {
                ledger.history.push(update);
                appended += 1;
            } else {
                break;
            }
        }

        if appended > 0 {
            // Update state sequence/hash from last appended
            let last_seq = ledger.history.last().map(|u| u.sequence_number);
            let last_hash = ledger.history.last().map(|u| u.current_hash);
            if let (Some(seq), Some(hash)) = (last_seq, last_hash) {
                ledger.state.sequence = seq;
                ledger.state.hash = hash;
            }

            // Truncate joined ledger history to prevent unbounded memory growth.
            // Owned ledgers are truncated during persist_ledger_to_disk, but joined
            // ledgers are never persisted by this operator, so truncate here.
            const JOINED_HISTORY_RETAIN: usize = 2000;
            let len = ledger.history.len();
            if len > JOINED_HISTORY_RETAIN * 2 {
                ledger.history.drain(..len - JOINED_HISTORY_RETAIN);
            }

            tracing::info!(
                "Caught up ledger {}... from event store: seq {} -> {} (+{} entries)",
                &ledger_id[..16.min(ledger_id.len())],
                next_seq,
                next_seq + appended,
                appended,
            );
        }

        appended as usize
    }

    /// Send a resync request to the operator of a joined ledger asking them
    /// to re-broadcast updates from our local sequence onward. Fire-and-forget.
    async fn send_resync_request_if_needed(&self, ledger_id: &str) {
        // Find the operator pubkey for this ledger
        let operator_pubkey = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            match ledgers.get(ledger_id) {
                Some(arc) => {
                    let ledger = arc.read().unwrap();
                    hex::encode(ledger.operator_key().serialize())
                }
                None => return,
            }
        };

        // Get our local sequence
        let from_seq = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            match ledgers.get(ledger_id) {
                Some(arc) => arc.read().unwrap().next_sequence(),
                None => return,
            }
        };

        let params = serde_json::json!({
            "from_seq": from_seq,
            "requester": hex::encode(self.node_id.serialize()),
        });

        match self.nostr.send_ledger_request(ledger_id, "resync", params).await {
            Ok(event_id) => {
                tracing::info!(
                    "Sent resync request for ledger {}... from_seq={} to operator {}...",
                    &ledger_id[..16.min(ledger_id.len())],
                    from_seq,
                    &operator_pubkey[..16.min(operator_pubkey.len())],
                );
                self.sent_events.lock().unwrap().insert(event_id);
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to send resync request for ledger {}...: {}",
                    &ledger_id[..16.min(ledger_id.len())],
                    e,
                );
            }
        }
    }

    /// Run the main event loop.
    /// Takes `&Arc<Self>` to enable per-ledger parallel dispatch via `tokio::spawn`.
    pub async fn run(self: &Arc<Self>) -> Result<(), Error> {
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
            tokio::time::Duration::from_secs(30)  // Safety net only — subscriptions handle real-time delivery
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

        // Adaptive timeout: short when busy (more requests likely coming),
        // longer when idle (save CPU). Starts idle.
        let mut had_requests_last_iteration = false;

        let mut loop_iteration: u64 = 0;
        loop {
            let loop_start = std::time::Instant::now();
            loop_iteration += 1;

            // Watchdog: log every 100th iteration so we can see if the loop is running
            if loop_iteration % 100 == 0 {
                tracing::debug!("run loop iteration {}", loop_iteration);
            }

            // Periodic tasks (every 60 seconds) - moved outside select! to avoid reset on each iteration
            if last_periodic.elapsed() >= periodic_interval {
                let periodic_start = std::time::Instant::now();
                tracing::info!("[CANARY] entering periodic section (v2-timeout-all)");
                // Sync wallet periodically
                if let Err(e) = self.sync_wallet() {
                    tracing::warn!("Wallet sync failed: {}", e);
                }

                // Emit reserves balance after sync
                if let Ok(reserves) = self.reserves_balance() {
                    metrics::set_reserves_balance_sats(reserves);
                }

                // Spawn cosign-heavy periodic tasks as background work so the main
                // loop stays free to pump events and route cosign responses.
                // These tasks call sign_and_broadcast → request_cosign, which needs
                // the main loop to be running to route responses via process_events.
                {
                    let node = Arc::clone(self);
                    tokio::spawn(async move {
                        macro_rules! timed_periodic {
                            ($name:expr, $call:expr) => {
                                match tokio::time::timeout(std::time::Duration::from_secs(10), $call).await {
                                    Ok(()) => {},
                                    Err(_) => tracing::error!("Periodic task '{}' timed out after 10s", $name),
                                }
                            };
                        }
                        timed_periodic!("auto_complete_deposits", node.auto_complete_deposits());
                        timed_periodic!("auto_credit_received_payments", node.auto_credit_received_payments());
                        timed_periodic!("auto_complete_withdrawals", node.auto_complete_withdrawals());
                        timed_periodic!("auto_collect_fees", node.auto_collect_fees());
                        timed_periodic!("auto_timeout_transfers", node.auto_timeout_transfers());

                        // Auto-expire old deposit offers
                        if let Ok(expired) = node.check_expired_offers() {
                            if !expired.is_empty() {
                                tracing::info!("Expired {} deposit offers", expired.len());
                            }
                        }

                        // Dispute-related periodic tasks
                        timed_periodic!("auto_lottery_claim_or_yield", node.auto_lottery_claim_or_yield());
                        timed_periodic!("auto_confiscate", node.auto_confiscate());
                        timed_periodic!("auto_reveal_on_confiscation", node.auto_reveal_on_confiscation());
                        timed_periodic!("auto_post_win_cleanup", node.auto_post_win_cleanup());

                        // Reload allowlist (non-async, fast)
                        node.reload_allowlist();

                        // Publish price oracle (~every periodic cycle)
                        node.publish_price_oracle().await;
                    });
                }

                // Drain and log events
                let events = self.handler.drain_events();
                for event in events {
                    tracing::info!("Protocol event: {:?}", event);
                }

                // Two-generation cleanup for processed_requests.
                // Swap current → prev each period. Lookups check both generations,
                // so no entry is lost within the last period. This prevents
                // reprocessing of transfer_lock/transfer_complete (one-time nonces)
                // while capping memory at ~2 periods of entries.
                {
                    let mut current = self.processed_requests.lock().unwrap();
                    let mut prev = self.processed_requests_prev.lock().unwrap();
                    metrics::set_processed_requests_current(current.len());
                    metrics::set_processed_requests_prev(prev.len());
                    if current.len() > 1_000 {
                        let cur_len = current.len();
                        let prev_len = prev.len();
                        *prev = std::mem::take(&mut *current);
                        tracing::debug!("Rotated processed_requests: current={} -> prev (dropped {} old)", cur_len, prev_len);
                    }
                }

                // Two-generation cleanup for sent_events (same pattern as processed_requests).
                // Prevents the atomic clear() bug where wiping all entries at once creates
                // a window for reprocessing our own broadcast events.
                {
                    let mut current = self.sent_events.lock().unwrap();
                    let mut prev = self.sent_events_prev.lock().unwrap();
                    if current.len() > 1_000 {
                        *prev = std::mem::take(&mut *current);
                    }
                }

                // Rotate notification-level dedup set
                self.nostr.rotate_seen_events();

                // Truncate joined ledger histories to prevent unbounded memory growth.
                // Owned ledgers are truncated during persist_ledger_to_disk compaction,
                // but joined ledgers accumulate history from Nostr updates forever.
                if let Ok(ledgers) = self.handler.ledgers.try_lock() {
                    const JOINED_HISTORY_RETAIN: usize = 2000;
                    for (lid, arc) in ledgers.iter() {
                        let mut ledger = arc.write().unwrap();
                        let len = ledger.history.len();
                        if len > JOINED_HISTORY_RETAIN * 2 {
                            let before = len;
                            ledger.history.drain(..len - JOINED_HISTORY_RETAIN);
                            tracing::debug!("Truncated history for {}: {} -> {} entries",
                                &lid[..16.min(lid.len())], before, ledger.history.len());
                        }
                    }
                }

                metrics::record_run_loop_phase("periodic", periodic_start.elapsed());
                last_periodic = tokio::time::Instant::now();
            }

            // Discover new/updated ledger files and refresh quorum membership cache
            if last_reload.elapsed() >= reload_interval {
                tracing::info!("[CANARY] entering reload section (v2-timeout-all)");
                // Pre-check: skip entire reload if ledgers lock is contended
                // (orphaned JoinSet tasks may still hold it after abort_all+drain timeout).
                if self.handler.ledgers.try_lock().is_err() {
                    tracing::warn!("reload section: ledgers lock contended, skipping this cycle");
                    last_reload = tokio::time::Instant::now();
                } else {
                let reload_start = std::time::Instant::now();
                let discovered = self.handler.discover_new_ledgers();
                if discovered > 0 {
                    // Force-invalidate: external process changed ledger files
                    self.invalidate_joined_ledger_cache();
                }
                // Otherwise, get_joined_ledger_ids() self-validates via version check

                // Single pass over ledgers: collect IDs, emit metrics, gather event store keys.
                // This avoids two separate iterations and eliminates the nested
                // event_store + ledgers lock that risked deadlock with catch_up paths.
                let mut all_ledger_ids = self.get_joined_ledger_ids();
                let mut owned_ids = Vec::new();
                let mut tip_queries: Vec<(String, [u8; 32], bitcoin::secp256k1::PublicKey)> = Vec::new();
                {
                    let ledgers = match self.handler.ledgers.try_lock() {
                        Ok(l) => l,
                        Err(_) => {
                            tracing::warn!("reload section: ledgers lock contended, skipping this cycle");
                            last_reload = tokio::time::Instant::now();
                            continue;
                        }
                    };
                    metrics::set_ledger_count(ledgers.len());
                    let mut total_balance_sats: u64 = 0;
                    let mut total_history_bytes: u64 = 0;
                    for (ledger_id, ledger_arc) in ledgers.iter() {
                        let ledger = ledger_arc.read().unwrap();
                        if ledger.operator_key() == self.node_id {
                            all_ledger_ids.push(ledger_id.clone());
                            owned_ids.push(ledger.ledger_id_hex());
                        }
                        let hist_len = ledger.history.len();
                        metrics::set_ledger_history_length(ledger_id, hist_len);
                        // ~570 bytes per entry (370 struct + ~200 avg message Vec)
                        total_history_bytes += hist_len as u64 * 570;
                        // Emit per-ledger and per-deposit balance metrics
                        let mut ledger_balance_sats: u64 = 0;
                        for (dep_id_bytes, deposit) in &ledger.state.deposits {
                            let balance_sats = deposit.balance / 1000;
                            ledger_balance_sats += balance_sats;
                            let dep_id = hex::encode(dep_id_bytes);
                            metrics::set_deposit_balance_sats(&dep_id, balance_sats);
                        }
                        metrics::set_ledger_deposit_balance_sats(ledger_id, ledger_balance_sats);
                        total_balance_sats += ledger_balance_sats;
                        tip_queries.push((ledger_id.clone(), ledger.state.ledger_id, ledger.state.parent_pubkey));
                    }
                    metrics::set_total_deposit_balance_sats(total_balance_sats);
                    metrics::set_history_memory_estimate_bytes(total_history_bytes);
                }

                // Emit event store validated tips — separate lock, no nesting
                {
                    let store = self.handler.event_store.lock().unwrap();
                    for (ledger_id, ledger_id_bytes, parent_pubkey) in &tip_queries {
                        if let Some(tip) = store.validated_tip(ledger_id_bytes, parent_pubkey) {
                            metrics::set_event_store_validated_tip(ledger_id, tip);
                        }
                    }
                }

                // Update interested ledgers + poll filter
                self.nostr.set_interested_ledgers(all_ledger_ids.iter().cloned());
                self.nostr.set_request_ledger_filter(all_ledger_ids.clone());

                // Auto-import joined ledgers from Nostr (so we can validate their updates)
                let joined_ids = self.get_joined_ledger_ids();
                if !joined_ids.is_empty() {
                    match tokio::time::timeout(std::time::Duration::from_secs(10), self.auto_import_joined_ledgers(&joined_ids)).await {
                        Ok(()) => {},
                        Err(_) => tracing::error!("auto_import_joined_ledgers timed out after 10s"),
                    }
                }

                // Subscribe with compacted global filters (4 filters instead of 36+ per-ledger).
                // Per-ledger filtering happens in-process via interested_ledgers.
                match tokio::time::timeout(std::time::Duration::from_secs(5), self.nostr.subscribe_global()).await {
                    Ok(Err(e)) => tracing::debug!("Global subscribe failed: {}", e),
                    Err(_) => tracing::error!("subscribe_global timed out after 5s"),
                    _ => {},
                }

                // Background gap-fill for stale joined ledgers.
                // Try event store first (free, in-memory), then fall back to relay fetch
                // (one per cycle, 30s cooldown per ledger) for post-restart recovery.
                {
                    let stale_ids: Vec<String> = {
                        let mut stale = self.stale_joined_ledgers.lock().unwrap();
                        stale.drain().collect()
                    };

                    let mut relay_fetched_this_cycle = false;
                    let relay_cooldown = Self::RELAY_FETCH_COOLDOWN;

                    for stale_id in &stale_ids {
                        // Try event store first (free, in-memory)
                        let caught_up = self.catch_up_ledger_from_event_store(stale_id);
                        if caught_up > 0 {
                            tracing::info!(
                                "Background gap-fill: ledger {}... +{} events from event store",
                                &stale_id[..16.min(stale_id.len())], caught_up,
                            );
                            metrics::record_gap_fill("from_store");
                            continue; // Resolved — don't re-queue
                        }

                        // Event store empty (typical after restart). Try relay fetch
                        // — one per cycle to avoid blocking the run loop.
                        if !relay_fetched_this_cycle {
                            let should_fetch = {
                                let times = self.last_relay_fetch_times.lock().unwrap();
                                match times.get(stale_id) {
                                    Some(last) => last.elapsed() >= relay_cooldown,
                                    None => true,
                                }
                            };

                            if should_fetch {
                                relay_fetched_this_cycle = true;
                                self.last_relay_fetch_times.lock().unwrap()
                                    .insert(stale_id.clone(), std::time::Instant::now());

                                let local_seq = {
                                    let ledgers = self.handler.ledgers.lock().unwrap();
                                    ledgers.get(stale_id)
                                        .map(|arc| arc.read().unwrap().next_sequence())
                                        .unwrap_or(0)
                                };

                                tracing::info!(
                                    "Background gap-fill: fetching ledger {}... from relay (local_seq={})",
                                    &stale_id[..16.min(stale_id.len())], local_seq,
                                );

                                match tokio::time::timeout(std::time::Duration::from_secs(10), self.reimport_joined_ledger(stale_id)).await {
                                    Err(_) => {
                                        tracing::error!("reimport_joined_ledger timed out for {}...", &stale_id[..16.min(stale_id.len())]);
                                        // Re-queue for next cycle
                                        self.stale_joined_ledgers.lock().unwrap().insert(stale_id.clone());
                                    }
                                    Ok(Ok(())) => {
                                        let new_seq = {
                                            let ledgers = self.handler.ledgers.lock().unwrap();
                                            ledgers.get(stale_id)
                                                .map(|arc| arc.read().unwrap().next_sequence())
                                                .unwrap_or(0)
                                        };
                                        tracing::info!(
                                            "Background gap-fill: relay fetch succeeded for {}... (seq {} -> {})",
                                            &stale_id[..16.min(stale_id.len())], local_seq, new_seq,
                                        );
                                        if new_seq > local_seq {
                                            metrics::record_gap_fill("from_relay");
                                            // Persist the updated ledger
                                            self.dirty_ledgers.lock().unwrap().insert(stale_id.clone());
                                            continue; // Resolved — don't re-queue
                                        }
                                        // Relay had no new events — ask operator to re-broadcast
                                        tracing::warn!(
                                            "Background gap-fill: relay had no new events for {}..., requesting resync",
                                            &stale_id[..16.min(stale_id.len())],
                                        );
                                        metrics::record_gap_fill("relay_empty");
                                        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), self.send_resync_request_if_needed(stale_id)).await;
                                    }
                                    Ok(Err(e)) => {
                                        let err_str = format!("{}", e);
                                        // Chain break = unbridgeable gap (operator history truncated).
                                        // Don't resync — it will just repeat the same failure.
                                        if err_str.contains("wrong previous_hash") || err_str.contains("Chain break") {
                                            tracing::info!(
                                                "Background gap-fill: chain break for {}... — dropping from stale queue (gap is unbridgeable)",
                                                &stale_id[..16.min(stale_id.len())],
                                            );
                                            metrics::record_gap_fill("chain_break");
                                            continue; // Don't re-queue
                                        }
                                        tracing::warn!(
                                            "Background gap-fill: relay fetch failed for {}...: {}",
                                            &stale_id[..16.min(stale_id.len())], e,
                                        );
                                        metrics::record_gap_fill("relay_failed");
                                        // Relay doesn't have the events — ask operator to re-broadcast
                                        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), self.send_resync_request_if_needed(stale_id)).await;
                                    }
                                }
                            }
                        }

                        // Still behind — re-queue for next cycle
                        self.stale_joined_ledgers.lock().unwrap().insert(stale_id.clone());
                    }

                    let remaining = self.stale_joined_ledgers.lock().unwrap().len();
                    metrics::set_stale_joined_ledgers(remaining);
                }

                // Emit event store stats
                {
                    let store = self.handler.event_store.lock().unwrap();
                    metrics::set_event_store_total(store.len());
                    metrics::set_event_store_unknown(store.unknown_count());
                    metrics::set_event_store_by_parent_size(store.by_parent_len());
                    metrics::set_event_store_evictions(store.evicted_total());
                }

                // Emit process-level metrics (CPU, memory, I/O) + per-thread CPU
                metrics::emit_process_metrics();
                metrics::emit_thread_cpu_metrics();

                metrics::record_run_loop_phase("reload", reload_start.elapsed());
                last_reload = tokio::time::Instant::now();
            } // else (reload body)
            }

            // Poll for recent requests — safety net for missed subscription events.
            // Uses per-ledger parallel dispatch (same as drain_requests).
            if last_poll.elapsed() >= poll_interval {
                let poll_start = std::time::Instant::now();
                let mut poll_processed = 0usize;
                if let Ok(requests) = self.nostr.fetch_recent_requests(7).await {
                    let mut poll_by_ledger: std::collections::HashMap<String, Vec<crate::nostr::LedgerRequest>> = std::collections::HashMap::new();
                    for request in requests {
                        let already_processed = {
                            let processed = self.processed_requests.lock().unwrap();
                            if processed.contains(&request.event_id) { true }
                            else { self.processed_requests_prev.lock().unwrap().contains(&request.event_id) }
                        };
                        if !already_processed {
                            tracing::debug!("Request via polling: action={}, event={}...",
                                request.action, &request.event_id[..16.min(request.event_id.len())]);
                            self.processed_requests.lock().unwrap().insert(request.event_id.clone());
                            poll_by_ledger
                                .entry(request.ledger_id.clone())
                                .or_default()
                                .push(request);
                            poll_processed += 1;
                        }
                    }
                    if !poll_by_ledger.is_empty() {
                        // Dispatch poll requests to workers (non-blocking)
                        for (_lid, reqs) in poll_by_ledger {
                            for req in reqs {
                                if req.action == "cosign_update" || req.action == "cosign_offer" || req.action == "cosign_invoice" {
                                    // Dispatch to cosign worker
                                    let lid = req.ledger_id.clone();
                                    let mut workers = self.cosign_workers.lock().unwrap();
                                    let tx = workers.entry(lid.clone()).or_insert_with(|| {
                                        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<crate::nostr::LedgerRequest>();
                                        let node = Arc::clone(self);
                                        let lid_for_task = lid.clone();
                                        tokio::spawn(async move {
                                            while let Some(r) = rx.recv().await {
                                                let _ = tokio::time::timeout(
                                                    std::time::Duration::from_secs(3),
                                                    node.handle_ledger_request(r),
                                                ).await;
                                            }
                                            tracing::info!("Cosign worker (poll) exiting for {}...", &lid_for_task[..16.min(lid_for_task.len())]);
                                        });
                                        tx
                                    });
                                    let _ = tx.send(req);
                                } else {
                                    // Dispatch to ledger worker
                                    let lid = req.ledger_id.clone();
                                    let mut workers = self.ledger_workers.lock().unwrap();
                                    let tx = workers.entry(lid.clone()).or_insert_with(|| {
                                        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<crate::nostr::LedgerRequest>();
                                        let node = Arc::clone(self);
                                        let lid_for_task = lid.clone();
                                        tokio::spawn(async move {
                                            while let Some(r) = rx.recv().await {
                                                let _ = tokio::time::timeout(
                                                    std::time::Duration::from_secs(5),
                                                    node.handle_ledger_request(r),
                                                ).await;
                                            }
                                            tracing::info!("Per-ledger worker (poll) exiting for {}...", &lid_for_task[..16.min(lid_for_task.len())]);
                                        });
                                        tx
                                    });
                                    let _ = tx.send(req);
                                }
                            }
                        }
                    }
                }
                if poll_processed > 0 {
                    had_requests_last_iteration = true;
                }
                self.flush_dirty_ledgers();
                metrics::record_run_loop_phase("polling", poll_start.elapsed());
                last_poll = tokio::time::Instant::now();
            }

            // Process subscription notifications — adaptive timeout:
            // 1ms when busy (previous iteration processed requests, more likely coming)
            // 100ms when idle (save CPU, still responsive to new events)
            let events_timeout_ms: u64 = if had_requests_last_iteration { 1 } else { 100 };
            metrics::record_events_timeout_ms(events_timeout_ms);
            let process_events_start = std::time::Instant::now();
            let _ = self.nostr.process_events_with_timeout(events_timeout_ms).await;
            metrics::record_run_loop_phase("process_events", process_events_start.elapsed());

            // Handle P2P messages
            while let Some(inbound) = self.nostr.try_recv() {
                self.handle_inbound(inbound);
            }

            // Handle ledger requests — persistent per-ledger worker dispatch.
            //
            // Each ledger gets a dedicated mpsc channel and a persistent tokio task.
            // The main loop routes requests to channels. Workers process requests
            // one at a time with zero spawn/reap overhead. Cosign requests are
            // still processed inline (fast, time-critical).
            let subscription_batch_size = {
                let drain_start = std::time::Instant::now();

                // Drain requests from Nostr
                let drain_budget = std::time::Duration::from_millis(5);
                let mut total_drained = 0usize;
                let mut cosign_count = 0usize;

                while let Some(request) = self.nostr.try_recv_request() {
                    let already_processed = {
                        let processed = self.processed_requests.lock().unwrap();
                        if processed.contains(&request.event_id) { true }
                        else { self.processed_requests_prev.lock().unwrap().contains(&request.event_id) }
                    };
                    if already_processed {
                        if drain_start.elapsed() >= drain_budget { break; }
                        continue;
                    }

                    self.processed_requests.lock().unwrap().insert(request.event_id.clone());
                    tracing::debug!("Request via subscription: action={}, event={}...",
                        request.action, &request.event_id[..16.min(request.event_id.len())]);

                    // Cosign requests: dispatch to per-ledger cosign worker (non-blocking)
                    // These are requests from PARTNERS asking US to co-sign their updates.
                    // Must not block main loop — main loop needs to pump process_events +
                    // drain_responses so our OWN outbound cosign responses get routed.
                    if request.action == "cosign_update" || request.action == "cosign_offer" || request.action == "cosign_invoice" {
                        let lid = request.ledger_id.clone();
                        let mut workers = self.cosign_workers.lock().unwrap();
                        let tx = workers.entry(lid.clone()).or_insert_with(|| {
                            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<crate::nostr::LedgerRequest>();
                            let node = Arc::clone(self);
                            let lid_for_task = lid.clone();
                            tokio::spawn(async move {
                                while let Some(req) = rx.recv().await {
                                    let _ = tokio::time::timeout(
                                        std::time::Duration::from_secs(3),
                                        node.handle_ledger_request(req),
                                    ).await;
                                }
                                tracing::info!("Cosign worker exiting for {}...", &lid_for_task[..16.min(lid_for_task.len())]);
                            });
                            tx
                        });
                        let _ = tx.send(request);
                        cosign_count += 1;
                    } else {
                        // Route to persistent per-ledger worker
                        let lid = request.ledger_id.clone();
                        let mut workers = self.ledger_workers.lock().unwrap();
                        let tx = workers.entry(lid.clone()).or_insert_with(|| {
                            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<crate::nostr::LedgerRequest>();
                            let node = Arc::clone(self);
                            let lid_for_task = lid.clone();
                            tokio::spawn(async move {
                                while let Some(req) = rx.recv().await {
                                    let action = req.action.clone();
                                    let event_id = req.event_id.clone();
                                    match tokio::time::timeout(
                                        std::time::Duration::from_secs(5),
                                        node.handle_ledger_request(req),
                                    ).await {
                                        Ok(()) => {},
                                        Err(_) => {
                                            tracing::warn!(
                                                "Request timed out after 5s: ledger={}... action={}, event={}...",
                                                &lid_for_task[..16.min(lid_for_task.len())],
                                                action, &event_id[..16.min(event_id.len())]
                                            );
                                        }
                                    }
                                }
                                tracing::info!("Per-ledger worker exiting for {}...", &lid_for_task[..16.min(lid_for_task.len())]);
                            });
                            tx
                        });
                        if let Err(e) = tx.send(request) {
                            tracing::warn!("Per-ledger worker channel closed for {}...: {}", &lid[..16.min(lid.len())], e);
                            workers.remove(&lid);
                        }
                        total_drained += 1;
                    }

                    if drain_start.elapsed() >= drain_budget {
                        break;
                    }
                }

                if cosign_count > 0 {
                    tracing::debug!("Processed {} cosign requests (serial)", cosign_count);
                }
                if total_drained > 0 {
                    metrics::record_request_drain_batch_size(total_drained);
                }
                metrics::record_run_loop_phase("drain_requests", drain_start.elapsed());
                total_drained
            };

            // Flush any ledgers modified during request processing

            let flush_start = std::time::Instant::now();
            self.flush_dirty_ledgers();
            metrics::record_run_loop_phase("flush", flush_start.elapsed());

            // Background compaction: check if any ledgers need compaction and spawn
            // a blocking task so the run loop stays free to pump events and cosigns.
            {
                let needs_compaction = self.handler.ledgers_needing_compaction();
                if !needs_compaction.is_empty() {
                    let handler = self.handler.clone();
                    tokio::task::spawn_blocking(move || {
                        for ledger_id in &needs_compaction {
                            if let Err(e) = handler.compact_ledger(ledger_id) {
                                tracing::warn!("Background compaction failed for {}: {}", &ledger_id[..16.min(ledger_id.len())], e);
                            }
                        }
                    });
                }
            }

            // Handle disputes
            {
                let phase_start = std::time::Instant::now();
                while let Some(dispute) = self.nostr.try_recv_dispute() {
                    match tokio::time::timeout(std::time::Duration::from_secs(5), self.handle_dispute(dispute)).await {
                        Ok(()) => {},
                        Err(_) => { tracing::error!("handle_dispute timed out after 5s"); break; }
                    }
                }
                metrics::record_run_loop_phase("drain_disputes", phase_start.elapsed());
            }

            // Handle fraud proofs
            {
                let phase_start = std::time::Instant::now();
                while let Some(fp) = self.nostr.try_recv_fraud_proof() {
                    match tokio::time::timeout(std::time::Duration::from_secs(5), self.handle_fraud_proof(fp)).await {
                        Ok(()) => {},
                        Err(_) => { tracing::error!("handle_fraud_proof timed out after 5s"); break; }
                    }
                }
                metrics::record_run_loop_phase("drain_fraud_proofs", phase_start.elapsed());
            }

            // Handle responses (for auto-recording attestations)
            {
                let phase_start = std::time::Instant::now();
                while let Some(response) = self.nostr.try_recv_response() {
                    match tokio::time::timeout(std::time::Duration::from_secs(5), self.handle_ledger_response(response)).await {
                        Ok(()) => {},
                        Err(_) => { tracing::error!("handle_ledger_response timed out after 5s"); break; }
                    }
                }
                metrics::record_run_loop_phase("drain_responses", phase_start.elapsed());
            }

            // Handle ledger updates (validate and auto-dispute on invalid)
            {
                let phase_start = std::time::Instant::now();
                while let Some(update) = self.nostr.try_recv_ledger_update() {
                    self.handle_ledger_update(update).await;
                }
                metrics::record_run_loop_phase("drain_updates", phase_start.elapsed());
            }

            // Check for outbound messages (non-blocking)
            while let Ok(outbound) = self.outbound_rx.lock().unwrap().try_recv() {
                match tokio::time::timeout(std::time::Duration::from_secs(5), self.nostr.send_message(outbound.peer, outbound.message)).await {
                    Ok(Err(e)) => tracing::error!("Failed to send message: {}", e),
                    Err(_) => { tracing::error!("send_message timed out after 5s"); break; }
                    _ => {},
                }
            }

            // Update adaptive timeout: use short timeout next iteration if we
            // processed any requests OR have active spawned tasks (cosign responses
            // need process_events + drain_responses to route to the oneshot channel).
            // With persistent per-ledger workers, always use short timeout when
            // workers exist (they may have in-flight cosign requests needing event pump).
            let has_workers = {
                let workers = self.ledger_workers.lock().unwrap();
                !workers.is_empty()
            };
            had_requests_last_iteration = subscription_batch_size > 0 || has_workers;

            // Record run loop iteration duration
            let loop_elapsed = loop_start.elapsed();
            metrics::record_run_loop_iteration(loop_elapsed);
            if loop_elapsed.as_millis() > 500 {
                tracing::warn!("[SLOW_LOOP] Run loop iteration took {:?}", loop_elapsed);
            }
        }
    }

    /// Handle a ledger request from Nostr
    async fn handle_ledger_request(&self, request: crate::nostr::LedgerRequest) {
        // Skip requests that THIS daemon process sent (Nostr broadcasts to all subscribers).
        // We track sent event IDs rather than filtering by pubkey, because CLI commands
        // use the same operator key and we want the daemon to process those.
        let is_own_event = {
            let sent = self.sent_events.lock().unwrap();
            if sent.contains(&request.event_id) { true }
            else { self.sent_events_prev.lock().unwrap().contains(&request.event_id) }
        };
        if is_own_event {
            tracing::debug!("Skipping our own request: {}", &request.event_id[..16.min(request.event_id.len())]);
            return;
        }

        // Check if this request is for a ledger we own or have joined
        let is_our_ledger = self.has_ledger(&request.ledger_id)
            || self.has_ledger_by_reserves_key(&request.ledger_id);
        let is_cross_ledger_sign = request.action == "custody_transfer_sign"
            || request.action == "confiscation_sign";
        // cosign requests can come from ledgers where we're a quorum member
        // (we may not have the full ledger locally, just a QuorumJoin record)
        let is_cosign_request = request.action == "cosign_update"
            || request.action == "cosign_offer"
            || request.action == "cosign_invoice";

        // Silently drop operator-only actions if we're not the operator
        // (these are broadcast but only the operator should respond)
        let operator_only_actions = ["deposit_open", "make_offer", "withdraw", "collateral_lock", "offer_status", "balance_query", "make_invoice", "pay_invoice", "transfer_lock", "transfer_complete", "bump", "complete_offer", "partner_add", "partner_join", "collateral_record", "reserves_rotate", "resync"];
        if operator_only_actions.contains(&request.action.as_str()) && !self.is_operator_of_ledger(&request.ledger_id) {
            return; // Silent drop - the actual operator will respond
        }

        if !is_our_ledger && !is_cross_ledger_sign && !is_cosign_request {
            return; // Silent drop - not our concern
        }

        // Record request age (now - created_at) for all incoming requests.
        // Cosign requests older than 2 seconds are definitely past all retry
        // windows (3 × 500ms timeout + 200ms sleep = 1.9s max) and can be
        // discarded immediately. The 2s threshold accounts for second-precision
        // timestamps and network latency.
        let request_age_secs = {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            now.saturating_sub(request.timestamp) as f64
        };
        metrics::record_request_age(&request.action, request_age_secs);

        if is_cosign_request && request_age_secs >= 2.0 {
            metrics::record_cosign_stale_discarded();
            tracing::debug!(
                "Discarding stale cosign request: age={:.0}s, event={}...",
                request_age_secs,
                &request.event_id[..16.min(request.event_id.len())]
            );
            return;
        }

        // Discard stale transfer requests. The simulator retries on timeout,
        // so processing old requests wastes cycles and creates state conflicts.
        // 15s is well within the client's 30s lock_timeout.
        let is_transfer = request.action == "transfer_lock" || request.action == "transfer_complete";
        if is_transfer && request_age_secs >= 15.0 {
            tracing::debug!(
                "Discarding stale {} request: age={:.0}s, event={}...",
                request.action,
                request_age_secs,
                &request.event_id[..16.min(request.event_id.len())]
            );
            return;
        }

        // For cosign requests: drain any buffered ledger updates into the event store
        // BEFORE checking freshness.  Updates arrive through the same Nostr subscription
        // but are queued in a separate channel — they may already be buffered but not yet
        // processed because the run loop drains requests before updates.  This in-memory
        // drain closes the race where a cosign request arrives microseconds before its
        // prerequisite updates are drained from the channel.
        if is_cosign_request {
            let mut drained = 0usize;
            // Cap the drain to prevent unbounded sync work — this loop has no .await
            // points, so tokio task cancellation (from JoinSet::abort_all) cannot take
            // effect until the loop exits.  With thousands of queued updates this loop
            // previously ran for seconds, holding handler.ledgers.lock() intermittently
            // and preventing the main run loop from acquiring it.
            const MAX_PRE_COSIGN_DRAIN: usize = 50;
            while drained < MAX_PRE_COSIGN_DRAIN {
                let update = match self.nostr.try_recv_ledger_update() {
                    Some(u) => u,
                    None => break,
                };
                self.handler.insert_event(&update.update);
                // Also append to ledger history if consecutive
                let ledgers = self.handler.ledgers.lock().unwrap();
                if let Some(ledger_arc) = ledgers.get(&update.ledger_id) {
                    let mut ledger = ledger_arc.write().unwrap();
                    let expected = ledger.next_sequence();
                    if update.update.sequence_number == expected {
                        ledger.history.push(update.update);
                    }
                }
                drained += 1;
            }
            if drained > 0 {
                // Also try event store catch-up for this specific ledger
                self.catch_up_ledger_from_event_store(&request.ledger_id);
                tracing::debug!(
                    "Pre-cosign drain: processed {} buffered updates",
                    drained,
                );
            }
            metrics::record_pre_cosign_drain(drained, true);
        }

        tracing::info!(
            "Ledger request: action={}, ledger={}..., event={}..., age={:.1}ms",
            request.action,
            &request.ledger_id[..16.min(request.ledger_id.len())],
            &request.event_id[..16.min(request.event_id.len())],
            request_age_secs * 1000.0,
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

                let result = self.process_cosign_request(&request).await;
                if !result.0 { return; }  // Silent — don't send error response
                result
            }
            "cosign_offer" | "cosign_invoice" => {
                // Silently ignore if we're not a quorum member for this ledger
                if !self.is_quorum_member_of_ledger(&request.ledger_id) {
                    tracing::debug!("Ignoring {} for {} - not a quorum member",
                        request.action, &request.ledger_id[..16.min(request.ledger_id.len())]);
                    return;
                }

                let result = if request.action == "cosign_offer" {
                    self.process_cosign_offer_request(&request).await
                } else {
                    self.process_cosign_invoice_request(&request).await
                };
                if !result.0 { return; }  // Silent — don't send error response
                result
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
            "complete_offer" => self.process_complete_offer_request(&request).await,
            "partner_add" => self.process_partner_add_request(&request).await,
            "partner_join" => self.process_partner_join_request(&request).await,
            "collateral_record" => self.process_collateral_record_request(&request).await,
            "reserves_rotate" => self.process_reserves_rotate_request(&request).await,
            "resync" => self.process_resync_request(&request).await,
            _ => {
                tracing::warn!("Unknown request action: {}", request.action);
                (false, None, Some(format!("Unknown action: {}", request.action)))
            }
        };

        // Record request processing time
        let processing_time = start_time.elapsed();
        if is_transfer || processing_time.as_millis() > 1 {
            tracing::info!("[PROFILE] handle_ledger_request action={} took {:.1}ms, age={:.1}ms (success={})",
                request.action, processing_time.as_secs_f64() * 1000.0, request_age_secs * 1000.0, success);
        }
        crate::metrics::record_request_processing(&request.action, &request.ledger_id, success, processing_time);
        crate::metrics::record_response_sent_for_ledger(&request.action, &request.ledger_id, success);
        // Note: record_response_sent is called inside send_ledger_response (nostr.rs)

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

        // Index in event store (content-addressed, handles dedup + validation)
        let is_new = self.handler.insert_event(&inbound.update);
        if is_new {
            // Check validity after insert
            let validity_str = {
                let store = self.handler.event_store.lock().unwrap();
                match store.get(&inbound.update.current_hash) {
                    Some(stored) => match stored.validity {
                        deposits_core::event_store::Validity::Valid => "valid",
                        deposits_core::event_store::Validity::Invalid => "invalid",
                        deposits_core::event_store::Validity::Unknown => "unknown",
                    },
                    None => "missing",
                }
            };
            metrics::record_event_store_insert(validity_str);
            metrics::record_ledger_update_received(validity_str);
            tracing::debug!(
                "Event store: indexed seq {} on ledger {}... ({})",
                inbound.update.sequence_number,
                &inbound.ledger_id[..16.min(inbound.ledger_id.len())],
                validity_str,
            );
        } else {
            metrics::record_ledger_update_received("duplicate");
        }

        // Find the ledger by ledger_id
        let ledger_arc = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            ledgers.get(&inbound.ledger_id).cloned()
        };

        let Some(ledger_arc) = ledger_arc else {
            return; // Ledger not found locally
        };

        // Don't validate updates on our own ledger — we're the operator, not a monitor.
        // Without this, stale in-memory state causes the daemon to dispute itself.
        {
            let ledger = ledger_arc.read().unwrap();
            if ledger.operator_key() == self.node_id {
                return;
            }
        }

        // Drop updates from non-operators (except DisputeEnter, which any
        // quorum member may publish).  Non-operator writes are never legitimate
        // and must not trigger a dispute — they're just noise.
        //
        // Exception: if the ledger is in a non-Normal dispute state and we see
        // an update from a different key, the operator may have changed via
        // DisputeAcquire.  Re-import the ledger to pick up the custody transfer,
        // then re-check.
        {
            let ledger = ledger_arc.read().unwrap();
            let is_from_operator = inbound.update.operator_id == ledger.state.parent_pubkey;
            if !is_from_operator {
                use deposits_core::tlv::TlvDecode;
                let is_dispute = deposits_core::messages::LedgerOperation::tlv_decode(&inbound.update.message)
                    .map(|op| matches!(op, deposits_core::messages::LedgerOperation::DisputeEnter { .. }))
                    .unwrap_or(false);
                if !is_dispute {
                    // If the ledger is in a dispute state, the operator may have
                    // changed (DisputeAcquire).  Re-import and re-check.
                    let in_dispute = ledger.state.dispute_state
                        != deposits_core::types::DisputeState::Normal;
                    drop(ledger);

                    if in_dispute {
                        tracing::info!(
                            "Non-operator update on disputed ledger {}... — re-importing to check for custody transfer",
                            &inbound.ledger_id[..16.min(inbound.ledger_id.len())],
                        );
                        let _ = self.reimport_joined_ledger(&inbound.ledger_id).await;

                        // Re-check operator after reimport (re-fetch arc since import may replace it)
                        let ledgers = self.handler.ledgers.lock().unwrap();
                        let Some(fresh_arc) = ledgers.get(&inbound.ledger_id) else {
                            return;
                        };
                        let fresh_ledger = fresh_arc.read().unwrap();
                        let now_from_operator = inbound.update.operator_id == fresh_ledger.state.parent_pubkey;
                        drop(fresh_ledger);
                        drop(ledgers);
                        if !now_from_operator {
                            tracing::debug!(
                                "Still non-operator after reimport — dropping update seq {} on ledger {}...",
                                inbound.update.sequence_number,
                                &inbound.ledger_id[..16.min(inbound.ledger_id.len())],
                            );
                            return;
                        }
                        // Operator changed — fall through to continue processing
                    } else {
                        tracing::debug!(
                            "Dropping update seq {} on ledger {}... from non-operator {}...",
                            inbound.update.sequence_number,
                            &inbound.ledger_id[..16.min(inbound.ledger_id.len())],
                            hex::encode(&inbound.update.operator_id.serialize()[..8]),
                        );
                        return;
                    }
                }
            }
        }

        // If the incoming update is ahead of our local copy, try to catch up
        // from the event store first (pure in-memory, no relay I/O).  Only mark
        // as stale for background gap-fill if event store can't bridge the gap.
        {
            let ledger = ledger_arc.read().unwrap();
            let local_seq = ledger.next_sequence();
            if inbound.update.sequence_number > local_seq {
                tracing::info!(
                    "Ledger {}... has gap: local={}, incoming seq={}. Attempting event store catch-up.",
                    &inbound.ledger_id[..16.min(inbound.ledger_id.len())],
                    local_seq,
                    inbound.update.sequence_number,
                );
                drop(ledger); // release read lock before catch-up

                // Try to catch up from event store (no relay I/O)
                let caught_up = self.catch_up_ledger_from_event_store(&inbound.ledger_id);

                // Re-check if still behind after catch-up
                let still_behind = {
                    let ledgers = self.handler.ledgers.lock().unwrap();
                    ledgers.get(&inbound.ledger_id)
                        .map(|arc| {
                            let l = arc.read().unwrap();
                            l.next_sequence() < inbound.update.sequence_number
                        })
                        .unwrap_or(true)
                };

                if still_behind {
                    // Mark as stale for background gap-fill (non-blocking)
                    self.stale_joined_ledgers.lock().unwrap().insert(inbound.ledger_id.clone());
                    let stale_count = self.stale_joined_ledgers.lock().unwrap().len();
                    metrics::set_stale_joined_ledgers(stale_count);
                    if caught_up > 0 {
                        tracing::info!(
                            "Event store catch-up added {} events but still behind — queued for background fill",
                            caught_up,
                        );
                    } else {
                        tracing::debug!(
                            "Event store has no bridging events — queued for background fill",
                        );
                    }
                } else if caught_up > 0 {
                    tracing::info!(
                        "Event store catch-up bridged the gap (+{} events)",
                        caught_up,
                    );
                }
            }
        }

        // Validate the update (hash chain only — signature format is not yet
        // standardised across the codebase, so signature failures are dropped
        // rather than treated as disputes)
        let validation_result = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let Some(ledger_arc) = ledgers.get(&inbound.ledger_id).cloned() else {
                return;
            };
            drop(ledgers);

            let ledger = ledger_arc.read().unwrap();

            // Skip if already in dispute state
            if ledger.state.dispute_state != deposits_core::types::DisputeState::Normal {
                return;
            }

            ledger.validate_incoming_update_hash_chain(&inbound.update)
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
        } else {
            // Validation passed — append the update to our local copy so it stays
            // in sync for cosign sequence validation.  Only append if this is the
            // exact next entry (no gaps).
            let ledgers = self.handler.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&inbound.ledger_id) {
                let mut ledger = ledger_arc.write().unwrap();
                let expected_seq = ledger.next_sequence();
                if inbound.update.sequence_number == expected_seq {
                    ledger.history.push(inbound.update.clone());
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

    /// Handle an incoming fraud proof broadcast.
    ///
    /// Verifies the proof hash against the embedding, then checks if we're
    /// a quorum member. If so, initiates a custody dispute.
    async fn handle_fraud_proof(&self, fp: crate::nostr::FraudProofEvent) {
        use deposits_core::fraud::FraudProofType;
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

        let broadcast = &fp.broadcast;
        let ledger_id = &broadcast.proof.ledger_id;

        tracing::warn!(
            "Processing fraud proof: {:?} against {} on ledger {}...",
            broadcast.proof.proof_type,
            &broadcast.proof.accused[..16.min(broadcast.proof.accused.len())],
            &ledger_id[..16.min(ledger_id.len())]
        );

        // 1. Verify proof hash matches embedding
        let proof_hash = broadcast.proof.proof_hash();
        let proof_hash_hex = hex::encode(proof_hash);

        // 2. Fetch the embedding update and verify the hash is in the nonce
        let embedding = &broadcast.embedding;
        let embedding_verified = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            if let Some(arc) = ledgers.get(&embedding.ledger_id) {
                let ledger = arc.read().unwrap();
                ledger.history.iter().any(|u| {
                    if u.sequence_number != embedding.sequence { return false; }
                    // Decode the operation and check the nonce field
                    if let Ok(op) = deposits_core::messages::LedgerOperation::tlv_decode(&u.message) {
                        if let deposits_core::messages::LedgerOperation::TransferLock { nonce, .. } = op {
                            return nonce == proof_hash;
                        }
                    }
                    false
                })
            } else {
                false
            }
        };

        if !embedding_verified {
            tracing::warn!("Fraud proof embedding not verified — hash {} not found at seq {} on ledger {}",
                &proof_hash_hex[..16], embedding.sequence, &embedding.ledger_id[..16]);
            // Don't act on unverified proofs, but log for manual review
            return;
        }

        tracing::warn!("Fraud proof embedding VERIFIED: hash {} at seq {} on {}",
            &proof_hash_hex[..16], embedding.sequence, &embedding.ledger_id[..16]);

        // 3. Verify causal chain (if indirect embedding)
        if embedding.ledger_id != *ledger_id {
            // Verify each causal link exists
            let mut chain_verified = true;
            for link in &broadcast.causal_chain {
                let link_ok = {
                    let ledgers = self.handler.ledgers.lock().unwrap();
                    if let Some(arc) = ledgers.get(&link.ledger_id) {
                        let ledger = arc.read().unwrap();
                        ledger.history.iter().any(|u| {
                            u.sequence_number == link.sequence
                                && u.member_ledger_hash.map(|h| hex::encode(h)) == Some(link.member_ledger_hash.clone())
                        })
                    } else {
                        false
                    }
                };
                if !link_ok {
                    tracing::warn!("Causal link not verified: seq {} on ledger {}",
                        link.sequence, &link.ledger_id[..16]);
                    chain_verified = false;
                    break;
                }
            }
            if !chain_verified {
                tracing::warn!("Fraud proof causal chain not fully verified — skipping");
                return;
            }
            tracing::warn!("Fraud proof causal chain verified ({} links)", broadcast.causal_chain.len());
        }

        // 4. Check if we're a quorum member of the accused ledger
        if !self.is_quorum_member_of_ledger(ledger_id) {
            tracing::info!("Not a quorum member of accused ledger {}, skipping", &ledger_id[..16]);
            return;
        }

        // 5. Determine last valid sequence from the proof
        let last_valid_seq = match &broadcast.proof.evidence {
            deposits_core::fraud::FraudEvidence::UncreditedOnchain { proof_sequence, .. } => {
                proof_sequence.saturating_sub(1)
            }
            deposits_core::fraud::FraudEvidence::UncreditedLightning { proof_sequence, .. } => {
                proof_sequence.saturating_sub(1)
            }
            deposits_core::fraud::FraudEvidence::NonConforming { sequence, .. } => {
                sequence.saturating_sub(1)
            }
            _ => {
                // For stale cosign and inactive quorum, use the embedding sequence
                // as a reference point (the fraud happened before this)
                let ledgers = self.handler.ledgers.lock().unwrap();
                ledgers.get(ledger_id)
                    .map(|arc| arc.read().unwrap().next_sequence().saturating_sub(1))
                    .unwrap_or(0)
            }
        };

        tracing::warn!(
            "INITIATING DISPUTE based on fraud proof: ledger={}, last_valid_seq={}, type={:?}",
            &ledger_id[..16], last_valid_seq, broadcast.proof.proof_type
        );

        // 6. Auto-arm for dispute
        let reason = format!("fraud_proof:{:?}", broadcast.proof.proof_type);
        match self.auto_arm_for_dispute(ledger_id, last_valid_seq).await {
            Ok(()) => {
                tracing::warn!("Successfully armed for dispute based on fraud proof");

                // Also broadcast a dispute event referencing the fraud proof
                let secret = self.wallet.operator_secret();
                let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&self.secp, &secret);
                if let Err(e) = self.nostr.publish_dispute(
                    ledger_id,
                    &reason,
                    &format!("Fraud proof verified: {}", &fp.event_id[..16]),
                    proof_hash,
                    last_valid_seq,
                    None,
                    &keypair,
                ).await {
                    tracing::error!("Failed to broadcast dispute: {:?}", e);
                }
            }
            Err(e) => {
                tracing::error!("Failed to arm for fraud-proof dispute: {}", e);
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

        // Also check for dispute forks where we're the parent (dispute opener)
        for (key, arc) in ledgers.iter() {
            if key.starts_with(ledger_id) && key.len() > ledger_id.len() {
                let ledger = arc.read().unwrap();
                if ledger.state.parent_pubkey == self.node_id {
                    return true;
                }
            }
        }
        drop(ledgers);

        // Check our joined ledgers (QuorumJoin records in our ledger history)
        let joined = self.get_joined_ledger_ids();
        for jid in joined {
            if jid == ledger_id {
                let elapsed = t0.elapsed();
                if elapsed.as_millis() > 1 {
                    tracing::info!("[PROFILE] is_quorum_member_of_ledger (found via history scan): {:?}", elapsed);
                }
                return true;
            }
        }

        let elapsed = t0.elapsed();
        if elapsed.as_millis() > 1 {
            tracing::info!("[PROFILE] is_quorum_member_of_ledger (not found, full scan): {:?}", elapsed);
        }
        false
    }

    /// Find the tracking key for a ledger, preferring dispute forks over originals.
    ///
    /// When a dispute is active, we want to operate on the fork (compound key),
    /// not the original Partner copy. This scans ledgers by prefix and returns
    /// the fork key if one exists, otherwise the original key.
    fn find_fork_or_original_by_prefix(&self, ledger_prefix: &str) -> Option<String> {
        let ledgers = self.handler.ledgers.lock().unwrap();
        let mut original: Option<String> = None;
        let mut fork: Option<String> = None;

        for key in ledgers.keys() {
            if key.starts_with(ledger_prefix) {
                if key.len() > 64 {
                    // Fork key (compound format with seq + operator prefix)
                    fork = Some(key.clone());
                } else {
                    // Original key (plain ledger_id, 64 hex chars)
                    original = Some(key.clone());
                }
            }
        }

        // Prefer fork over original for dispute operations
        fork.or(original)
    }

    /// Create a dispute fork of a ledger at the given divergence point.
    ///
    /// Clones the Partner copy of the disputed ledger, truncates its history
    /// to `last_valid_seq`, rebuilds state by replaying operations, and stores
    /// the fork under a compound tracking key. The original Partner copy stays
    /// untouched for evidence/auditing.
    ///
    /// Returns the compound tracking key for the fork.
    fn create_dispute_fork(&self, ledger_id: &str, last_valid_seq: u64) -> Result<String, Error> {
        use deposits_core::TlvDecode;
        use deposits_core::messages::LedgerOperation;
        use crate::handler::DepositsHandler;

        let secp = &self.secp;
        let our_pubkey = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &self.wallet.operator_secret());

        // Check if we already have a fork for this ledger
        if let Some(existing_fork) = self.handler.find_our_fork(ledger_id) {
            tracing::info!("Already have fork for ledger {}: {}", &ledger_id[..16], &existing_fork[..32.min(existing_fork.len())]);
            return Ok(existing_fork);
        }

        // Clone the Partner copy of the disputed ledger
        let original_arc = self.handler.ledgers.lock().unwrap()
            .get(ledger_id)
            .cloned()
            .ok_or_else(|| Error::Protocol(format!("Don't have disputed ledger: {}", &ledger_id[..16])))?;
        let original = original_arc.read().unwrap();

        // Truncate history to last_valid_seq
        let truncated_history: Vec<_> = original.history.iter()
            .filter(|u| u.sequence_number <= last_valid_seq)
            .cloned()
            .collect();

        // Rebuild state from genesis by replaying truncated history.
        // Start with a fresh state based on the original's genesis parameters.
        let mut fork_state = original.state.clone();

        // Reset derived state fields that will be rebuilt by replay
        fork_state.deposits.clear();
        fork_state.quorum_members.clear();
        fork_state.collateral_attestations.clear();
        fork_state.joined_quorums.clear();
        fork_state.pending_transfers.clear();
        fork_state.quorum_at_fork.clear();
        fork_state.dispute_fork_sequence = 0;
        fork_state.dispute_state = deposits_core::types::DisputeState::Normal;
        fork_state.reserves.amount = 0;
        fork_state.sequence = 0;
        fork_state.hash = [0u8; 32];

        // Create a temporary ledger for replay
        let mut fork = Ledger {
            state: fork_state,
            role: deposits_core::ledger::LedgerRole::Operator, // We operate the fork
            history: truncated_history.clone(),
        };

        // Replay all truncated operations to rebuild state
        for update in &truncated_history {
            if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                if let Err(e) = fork.apply_state_changes(&op) {
                    tracing::warn!(
                        "Fork replay seq {}: failed to apply state change: {}",
                        update.sequence_number, e
                    );
                }
            }
        }

        // Update sequence/hash from last valid update
        if let Some(last) = truncated_history.last() {
            fork.state.sequence = last.sequence_number as u64;
            fork.state.hash = last.current_hash;
        }

        // Store under compound key
        let fork_key = DepositsHandler::fork_tracking_key(ledger_id, last_valid_seq, &our_pubkey);

        tracing::info!(
            "Created dispute fork: {} (diverged at seq {}, {} updates)",
            &fork_key[..32.min(fork_key.len())],
            last_valid_seq,
            fork.history.len(),
        );

        self.handler.ledgers.lock().unwrap()
            .insert(fork_key.clone(), Arc::new(RwLock::new(fork)));

        Ok(fork_key)
    }

    /// Auto-arm for a dispute by creating a fork of the disputed ledger,
    /// then publishing DisputeEnter and DisputeArmed on the fork.
    ///
    /// This ensures the operator's own ledger stays in Normal state and is
    /// not affected by the dispute. The fork is stored under a compound
    /// tracking key and persisted as a separate JSONL file.
    async fn auto_arm_for_dispute(&self, ledger_id: &str, last_valid_seq: u64) -> Result<(), Error> {
        use bitcoin::hashes::{Hash, hash160};
        use bitcoin::secp256k1::Secp256k1;
        use bitcoin::secp256k1::rand::rngs::OsRng;
        use bitcoin::secp256k1::rand::Rng;
        use deposits_core::TlvEncode;
        use deposits_core::messages::LedgerOperation;

        let secp = &self.secp;

        // Get our operator keypair
        let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &self.wallet.operator_secret());
        let our_pubkey = keypair.public_key();

        // 0. Create a fork of the disputed ledger (or reuse existing one)
        let fork_key = self.create_dispute_fork(ledger_id, last_valid_seq)?;

        // Get the fork ledger's arc
        let fork_arc = self.handler.ledgers.lock().unwrap()
            .get(&fork_key)
            .cloned()
            .ok_or_else(|| Error::Protocol("Fork ledger not found after creation".to_string()))?;
        let current_block = self.wallet.get_block_height().unwrap_or(0);
        let block_hash = self.wallet.get_block_hash().unwrap_or([0u8; 32]);

        // Track whether we actually added new operations (to avoid re-broadcast loops)
        let mut added_new_operations = false;

        // 1. Publish DisputeEnter on the fork
        {
            let mut fork_ledger = fork_arc.write().unwrap();

            // Check if we've already published a DisputeEnter on this fork
            let already_disputed = fork_ledger.history.iter().any(|u| {
                if let Ok(op) = LedgerOperation::tlv_decode(&u.message) {
                    matches!(op, LedgerOperation::DisputeEnter { .. })
                } else {
                    false
                }
            });

            if already_disputed {
                tracing::info!("Already have DisputeEnter on fork");
            } else {
                let dispute_op = LedgerOperation::DisputeEnter {
                    last_valid_sequence: last_valid_seq,
                    reason: "auto_dispute".to_string(),
                };

                fork_ledger.append_operation_with_block(
                    dispute_op,
                    deposits_core::messages::consts::LEDGER_UPDATE,
                    current_block,
                    block_hash,
                ).map_err(|e| Error::Protocol(format!("Failed to append DisputeEnter to fork: {:?}", e)))?;

                // Set parent_pubkey to our key (we now operate this fork branch)
                fork_ledger.state.parent_pubkey = our_pubkey;

                // Patch operator_id on the appended update to our pubkey
                if let Some(update) = fork_ledger.history.last_mut() {
                    update.operator_id = our_pubkey;
                }

                tracing::info!("Published DisputeEnter on fork (parent_pubkey set to us)");
                added_new_operations = true;
            }
        }

        // Sign the dispute update on the fork
        self.sign_last_update(&fork_key)?;

        // 2. Copy our existing attestations from ALL of our operator ledger histories
        // (not from the fork - those prove we have collateral backing).
        // With multi-ledger operators, attestations may be spread across any of our
        // ledgers, so we must scan all of them.
        {
            // Collect arcs for all our owned ledgers
            let our_ledger_arcs: Vec<_> = {
                let ledgers = self.handler.ledgers.lock().unwrap();
                ledgers.iter()
                    .filter(|(lid, arc)| {
                        let l = arc.read().unwrap();
                        l.operator_key() == self.node_id && lid.len() <= 64
                    })
                    .map(|(_, arc)| arc.clone())
                    .collect()
            };

            let mut attestations_to_copy: Vec<LedgerOperation> = Vec::new();
            let mut quorum_members_to_add: Vec<(bitcoin::secp256k1::PublicKey, String)> = Vec::new();

            for ledger_arc in &our_ledger_arcs {
                let ledger = ledger_arc.read().unwrap();
                for update in ledger.history.iter() {
                    if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                        if let LedgerOperation::CollateralAttestation { collateral_operator, quorum_member, collateral_ledger_id, .. } = &op {
                            // We want attestations where WE are the quorum_member
                            if quorum_member == &our_pubkey {
                                attestations_to_copy.push(op.clone());
                                if !quorum_members_to_add.iter().any(|(pk, _)| pk == collateral_operator) {
                                    quorum_members_to_add.push((*collateral_operator, collateral_ledger_id.clone()));
                                }
                            }
                        }
                    }
                }
            }

            if !attestations_to_copy.is_empty() {
                // Add quorum members to the fork
                for (member, member_ledger_id) in quorum_members_to_add {
                    let mut fork_ledger = fork_arc.write().unwrap();

                    if fork_ledger.state.quorum_members.iter().any(|m| m.pubkey == member) {
                        continue;
                    }

                    let add_op = LedgerOperation::QuorumAddMember {
                        quorum_member: member,
                        quorum_member_signature: [0u8; 64],
                        member_ledger_id: member_ledger_id.clone(),
                        min_fee_bps: None,
                        min_fee_fixed: None,
                        max_fee_period: None,
                        collateral_lock_amount: None,
                        collateral_lock_until: None,
                    };

                    if let Err(e) = fork_ledger.append_operation_with_block(
                        add_op,
                        deposits_core::messages::consts::QUORUM_ADD_MEMBER,
                        current_block,
                        block_hash,
                    ) {
                        tracing::warn!("Failed to add quorum member to fork: {:?}", e);
                    } else {
                        if let Some(update) = fork_ledger.history.last_mut() {
                            update.operator_id = our_pubkey;
                        }
                        tracing::info!("Added quorum member to fork: {}...", &hex::encode(member.serialize())[..16]);
                        added_new_operations = true;
                    }
                }

                // Copy attestations to the fork
                for attestation in attestations_to_copy {
                    let mut fork_ledger = fork_arc.write().unwrap();

                    if let Err(e) = fork_ledger.append_operation_with_block(
                        attestation,
                        deposits_core::messages::consts::COLLATERAL_ATTESTATION,
                        current_block,
                        block_hash,
                    ) {
                        tracing::warn!("Failed to copy attestation to fork: {:?}", e);
                    } else {
                        if let Some(update) = fork_ledger.history.last_mut() {
                            update.operator_id = our_pubkey;
                        }
                        tracing::info!("Copied attestation to dispute fork");
                        added_new_operations = true;
                    }
                }

                // Sign after adding members and attestations
                self.sign_last_update(&fork_key)?;
            }
        }

        // 3. Publish DisputeArmed with preimage commitment on the fork
        {
            let mut fork_ledger = fork_arc.write().unwrap();

            let already_armed = fork_ledger.history.iter().any(|u| {
                if let Ok(op) = LedgerOperation::tlv_decode(&u.message) {
                    matches!(op, LedgerOperation::DisputeArmed { .. })
                } else {
                    false
                }
            });

            if already_armed {
                tracing::info!("Already have DisputeArmed on fork");
            } else {
                // Generate random preimage (17-20 bytes for lottery entropy)
                let mut rng = OsRng;
                let preimage_len = rng.gen_range(17..=20);
                let mut preimage = vec![0u8; preimage_len];
                rng.fill(&mut preimage[..]);

                // Compute commitment_hash = HASH160(preimage)
                let commitment_hash: [u8; 20] = *hash160::Hash::hash(&preimage).as_byte_array();

                // Store preimage for later reveal (keyed by disputed ledger_id prefix)
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

                let armed_op = LedgerOperation::DisputeArmed {
                    armed_block: current_block,
                    commitment_hash,
                    target_reserves,
                };

                fork_ledger.append_operation_with_block(
                    armed_op,
                    deposits_core::messages::consts::LEDGER_UPDATE,
                    current_block,
                    block_hash,
                ).map_err(|e| Error::Protocol(format!("Failed to append DisputeArmed to fork: {:?}", e)))?;

                // Patch operator_id
                if let Some(update) = fork_ledger.history.last_mut() {
                    update.operator_id = our_pubkey;
                }

                tracing::info!("Published DisputeArmed on fork");
                added_new_operations = true;
            }
        }

        // Sign the armed update on the fork
        self.sign_last_update(&fork_key)?;

        // Persist the fork (new JSONL file with compound key as filename)
        if let Err(e) = self.handler.persist_ledger_to_disk(&fork_key) {
            tracing::error!("Failed to persist fork ledger: {}", e);
        }

        // Create custody_armed marker (needed by auto_confiscate)
        let armed_marker = self.data_dir.join(format!("custody_armed_{}.marker",
            &ledger_id[..16.min(ledger_id.len())]));
        if let Err(e) = std::fs::write(&armed_marker, "armed") {
            tracing::warn!("Failed to write armed marker: {}", e);
        } else {
            tracing::info!("Created custody_armed marker: {:?}", armed_marker);
        }

        // Only broadcast if we actually added new operations to the fork.
        // Without this guard, incoming fork events re-trigger auto_arm_for_dispute,
        // which re-broadcasts all updates, creating an infinite feedback loop.
        if added_new_operations {
            if let Err(e) = self.broadcast_all_updates(&fork_key).await {
                tracing::warn!("Failed to broadcast dispute fork updates: {}", e);
            }
        } else {
            tracing::debug!("Fork already fully armed, skipping re-broadcast");
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
    /// 3. Winner: claim lottery output + publish DisputeAcquire
    /// 4. Loser: publish DisputeYield
    async fn auto_lottery_claim_or_yield(&self) {
        use bitcoin::secp256k1::Secp256k1;

        let secp = &self.secp;
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

            // Find the fork or original ledger key (prefer fork for dispute operations)
            let ledger_key = match self.find_fork_or_original_by_prefix(ledger_prefix) {
                Some(key) => key,
                None => continue,
            };

            // Extract the base ledger_id (first 64 chars) for Nostr queries
            let ledger_id = if ledger_key.len() > 64 {
                ledger_key[..64].to_string()
            } else {
                ledger_key.clone()
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

        // Use the slow relay client for historical fetch
        let client = self.nostr.fetch_client();

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

        // Extract DisputeArmed participants
        let mut participants: Vec<(PublicKey, LotteryParticipant)> = Vec::new();
        let mut our_armed: Option<SignedLedgerUpdate> = None;

        for event in update_events.iter() {
            if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
                if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                    if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                        if let LedgerOperation::DisputeArmed { commitment_hash, target_reserves, .. } = op {
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
            return Err(Error::Protocol("No DisputeArmed participants found".to_string()));
        }

        let our_armed = our_armed.ok_or_else(||
            Error::Protocol("Could not find our DisputeArmed".to_string()))?;

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
            tracing::info!("We lost the lottery for ledger {}. Publishing DisputeYield.", &ledger_id[..16]);
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

        let secp = &self.secp;
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

        let recovery_threshold = (recovery_voters.len() / 2) + 1;

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

        // Publish DisputeAcquire
        let current_block = self.wallet.get_block_height().unwrap_or(0);
        let current_block_hash = self.wallet.get_block_hash().unwrap_or([0u8; 32]);
        let spend_txid_bytes: [u8; 32] = *claim_txid.as_ref();

        let operation = LedgerOperation::DisputeAcquire {
            new_custodian: our_pubkey,
            entropy_block_height: current_block,
            entropy_block_hash: current_block_hash,
            spend_txid: spend_txid_bytes,
            new_reserves_address: winner_participant.target_reserves.clone(),
        };

        let message_bytes = operation.tlv_encode();

        // Build update continuing from our DisputeArmed
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
            cosign_signature: [0u8; 64],
            operator_id: our_pubkey,
            ledger_id: ledger_id_bytes,
            sequence_number: sequence,
            previous_hash: our_armed.current_hash,
            current_hash: new_hash,
            block_height: current_block,
            block_hash: current_block_hash,
        };

        // Broadcast to Nostr
        self.nostr.broadcast_ledger_update(&signed_update).await
            .map_err(|e| Error::Protocol(format!("Failed to broadcast DisputeAcquire: {:?}", e)))?;

        tracing::info!("DisputeAcquire published! We are now the operator.");
        Ok(())
    }

    /// Publish DisputeYield as a loser
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

        let secp = &self.secp;
        let our_pubkey = keypair.public_key();

        let current_block = self.wallet.get_block_height().unwrap_or(0);
        let current_block_hash = self.wallet.get_block_hash().unwrap_or([0u8; 32]);

        // Create DisputeYield operation
        let operation = LedgerOperation::DisputeYield;
        let message_bytes = operation.tlv_encode();

        // Build update continuing from our DisputeArmed
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
            cosign_signature: [0u8; 64],
            operator_id: our_pubkey,
            ledger_id: ledger_id_bytes,
            sequence_number: sequence,
            previous_hash: our_armed.current_hash,
            current_hash: new_hash,
            block_height: current_block,
            block_hash: current_block_hash,
        };

        // Broadcast to Nostr
        self.nostr.broadcast_ledger_update(&signed_update).await
            .map_err(|e| Error::Protocol(format!("Failed to broadcast DisputeYield: {:?}", e)))?;

        tracing::info!("DisputeYield published. Branch terminated.");
        Ok(())
    }

    /// Auto-initiate confiscation when all participants are armed
    ///
    /// For each ledger where we're armed but confiscation hasn't happened yet,
    /// check if all participants have armed. If so, build the confiscation TX,
    /// request signatures from quorum members, and broadcast.
    async fn auto_confiscate(&self) {
        // Phase 1: Check for pending confiscations that need signature collection
        self.collect_confiscation_signatures().await;

        // Phase 2: Initiate new confiscations for armed ledgers that don't have one pending
        self.initiate_confiscations().await;
    }

    /// Non-blocking: collect signatures for pending confiscation requests and broadcast when ready.
    async fn collect_confiscation_signatures(&self) {
        use bitcoin::secp256k1::PublicKey;
        use nostr_sdk::{Filter, Kind};
        use nostr_sdk::prelude::{SingleLetterTag, Alphabet};
        use bitcoin::Witness;

        let prefixes: Vec<String> = {
            let pending = self.pending_confiscations.lock().unwrap();
            pending.keys().cloned().collect()
        };

        for prefix in prefixes {
            // Check timeout (120s) — drop stale requests so we can re-initiate
            {
                let pending = self.pending_confiscations.lock().unwrap();
                if let Some(pc) = pending.get(&prefix) {
                    if pc.created_at.elapsed() > std::time::Duration::from_secs(120) {
                        tracing::warn!("Confiscation request for {} timed out, will re-initiate", prefix);
                        drop(pending);
                        self.pending_confiscations.lock().unwrap().remove(&prefix);
                        continue;
                    }
                }
            }

            // Fetch recent response events (non-blocking, single fetch)
            let (request_id, required_sigs) = {
                let pending = self.pending_confiscations.lock().unwrap();
                match pending.get(&prefix) {
                    Some(pc) => (pc.request_id.clone(), pc.required_sigs),
                    None => continue,
                }
            };

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

            // Process responses and add signatures
            let mut ready_to_broadcast = false;
            {
                let mut pending = self.pending_confiscations.lock().unwrap();
                let pc = match pending.get_mut(&prefix) {
                    Some(pc) => pc,
                    None => continue,
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
                                        if sig_bytes.len() == 64 && !pc.signatures.contains_key(&signer) {
                                            let mut sig_arr = [0u8; 64];
                                            sig_arr.copy_from_slice(&sig_bytes);
                                            pc.signatures.insert(signer, sig_arr);
                                            tracing::info!("  Confiscation {}: received signature from {}... ({}/{})",
                                                &prefix, &signer.to_string()[..16], pc.signatures.len(), required_sigs);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                if pc.signatures.len() >= required_sigs {
                    ready_to_broadcast = true;
                }
            }

            if ready_to_broadcast {
                self.broadcast_confiscation(&prefix).await;
            }
        }
    }

    /// Build witness and broadcast a confiscation transaction that has enough signatures.
    async fn broadcast_confiscation(&self, prefix: &str) {
        use bitcoin::Witness;

        let pc = match self.pending_confiscations.lock().unwrap().remove(prefix) {
            Some(pc) => pc,
            None => return,
        };

        tracing::info!("  Building witness with {} signatures for {}...", pc.signatures.len(), prefix);

        let control_block = match pc.taproot_output.control_block_for_tier(pc.tier_index) {
            Some(cb) => cb,
            None => {
                tracing::error!("Failed to get control block for tier");
                return;
            }
        };

        let mut witness = Witness::new();
        let sorted_keys = pc.voter_set.sorted_x_only_pubkeys();

        for x_only in sorted_keys.iter().rev() {
            for voter in pc.voter_set.all_voters() {
                if voter.x_only_public_key().0 == *x_only {
                    if let Some(sig) = pc.signatures.get(&voter) {
                        witness.push(sig);
                    } else {
                        witness.push(&[] as &[u8]);
                    }
                    break;
                }
            }
        }

        witness.push(pc.leaf_script.as_bytes());
        witness.push(control_block.serialize());

        let mut confiscation_tx = pc.confiscation_tx;
        confiscation_tx.input[0].witness = witness;

        // Broadcast
        tracing::info!("  Broadcasting confiscation transaction...");

        match self.wallet.broadcast(&confiscation_tx) {
            Ok(_) => {
                let confiscation_txid = confiscation_tx.compute_txid();
                tracing::info!("Confiscation transaction broadcast! Txid: {}", confiscation_txid);
                tracing::info!("  Lottery address: {}", pc.lottery_address);

                // Write confiscated marker
                if let Err(e) = std::fs::write(&pc.confiscated_marker, confiscation_txid.to_string()) {
                    tracing::warn!("Failed to write confiscated marker: {}", e);
                }
            }
            Err(e) => {
                tracing::error!("Failed to broadcast confiscation TX: {}", e);
            }
        }
    }

    /// Non-blocking: initiate confiscation for armed ledgers that don't already have a pending request.
    async fn initiate_confiscations(&self) {
        use bitcoin::secp256k1::{Secp256k1, Keypair, Message, PublicKey, XOnlyPublicKey};
        use deposits_core::{TlvDecode, TlvEncode, SignedLedgerUpdate, VoterSet, ThresholdConfig, TapscriptReservesBuilder};
        use deposits_core::messages::LedgerOperation;
        use deposits_core::tapscript_reserves::{LotteryScriptBuilder, LotteryParticipant};
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
        use nostr_sdk::{Filter, Kind};
        use nostr_sdk::prelude::{SingleLetterTag, Alphabet};
        use bitcoin::{Transaction, TxIn, TxOut, Witness, Amount};
        use bitcoin::sighash::{SighashCache, TapSighashType};
        use std::collections::HashMap;

        let secp = &self.secp;
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

            // Skip if we already have a pending confiscation for this ledger
            {
                let pending = self.pending_confiscations.lock().unwrap();
                if pending.contains_key(ledger_prefix) {
                    continue;
                }
            }

            tracing::debug!("Checking if confiscation ready for ledger {}...", ledger_prefix);

            // Find the fork or original ledger key (prefer fork for dispute operations)
            let ledger_key = match self.find_fork_or_original_by_prefix(ledger_prefix) {
                Some(key) => key,
                None => continue,
            };

            // Extract the base ledger_id (first 64 chars) for Nostr queries
            let ledger_id = if ledger_key.len() > 64 {
                ledger_key[..64].to_string()
            } else {
                ledger_key.clone()
            };

            // Use the slow relay client for historical fetch
            let client = self.nostr.fetch_client();

            let filter = Filter::new()
                .kind(Kind::Custom(crate::nostr::KIND_LEDGER_UPDATE))
                .custom_tag(SingleLetterTag::lowercase(Alphabet::D), [ledger_id.as_str()])
                .limit(500);

            let events = match client.fetch_events(vec![filter], Some(std::time::Duration::from_secs(10))).await {
                Ok(e) => e,
                Err(_) => continue,
            };

            // Extract DisputeArmed participants, quorum members, and reserves info
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
                                LedgerOperation::LedgerOpen { operator_id, reserves_id, .. } => {
                                    original_operator = Some(operator_id);
                                    // Use LedgerOpen reserves_id as fallback if no QuorumBegin
                                    if reserves_address.is_none() {
                                        reserves_address = Some(reserves_id);
                                    }
                                }
                                LedgerOperation::QuorumAddMember { quorum_member, .. } => {
                                    // Only use QuorumAddMember from the original operator's updates
                                    // (fork updates also contain QuorumAddMember for dispute bookkeeping,
                                    // but those inflate the voter count and break Taproot address matching)
                                    let is_from_original = original_operator
                                        .map(|op| update.operator_id == op)
                                        .unwrap_or(true);
                                    if is_from_original && !quorum_members.contains(&quorum_member) {
                                        quorum_members.push(quorum_member);
                                    }
                                }
                                LedgerOperation::QuorumBegin { reserves_id, ledger_hash: lh, .. } => {
                                    reserves_address = Some(reserves_id);
                                    ledger_hash = Some(lh);
                                }
                                LedgerOperation::DisputeArmed { commitment_hash, target_reserves, .. } => {
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
                tracing::debug!("Not enough DisputeArmed participants yet ({}/2)", participants.len());
                continue;
            }

            let original_operator = match original_operator {
                Some(op) => op,
                None => {
                    tracing::debug!("Could not find original operator (LedgerOpen) for {}", ledger_prefix);
                    continue;
                }
            };
            let reserves_address_str = match reserves_address {
                Some(addr) => addr,
                None => {
                    tracing::debug!("Could not find reserves address for {}", ledger_prefix);
                    continue;
                }
            };
            // ledger_hash comes from QuorumBegin; fall back to fork's current hash
            let ledger_hash_val = match ledger_hash {
                Some(lh) => lh,
                None => {
                    // No QuorumBegin found — use the fork ledger's current hash
                    let ledgers = self.handler.ledgers.lock().unwrap();
                    if let Some(fork_arc) = ledgers.get(&ledger_key) {
                        let fork = fork_arc.read().unwrap();
                        fork.state.hash
                    } else {
                        tracing::debug!("Could not find ledger hash for {}", ledger_prefix);
                        continue;
                    }
                }
            };

            // Filter out original operator from quorum_members (VoterSet adds operator as tie_breaker)
            quorum_members.retain(|pk| *pk != original_operator);

            tracing::info!("All {} participants armed for ledger {}..., initiating confiscation ({} quorum members)",
                participants.len(), ledger_prefix, quorum_members.len());

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

            let confiscation_tx = confiscation_tx;
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
            tracing::info!("  Need {}/{} signatures, requesting co-signatures...", required_sigs, voter_count);

            // If we already have enough signatures (e.g., threshold=1), broadcast immediately
            if signatures.len() >= required_sigs {
                let control_block = match taproot_output.control_block_for_tier(tier_index) {
                    Some(cb) => cb,
                    None => {
                        tracing::error!("Failed to get control block for tier");
                        continue;
                    }
                };

                let mut witness = bitcoin::Witness::new();
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

                let mut confiscation_tx = confiscation_tx;
                confiscation_tx.input[0].witness = witness;

                tracing::info!("  Broadcasting confiscation transaction (enough sigs locally)...");
                match self.wallet.broadcast(&confiscation_tx) {
                    Ok(_) => {
                        let txid = confiscation_tx.compute_txid();
                        tracing::info!("Confiscation transaction broadcast! Txid: {}", txid);
                        if let Err(e) = std::fs::write(&confiscated_marker, txid.to_string()) {
                            tracing::warn!("Failed to write confiscated marker: {}", e);
                        }
                    }
                    Err(e) => tracing::error!("Failed to broadcast confiscation TX: {}", e),
                }
                continue;
            }

            // Send the request and store pending state (non-blocking)
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

            tracing::info!("  Sent confiscation_sign request {}..., will collect signatures on next cycle",
                &request_id[..16.min(request_id.len())]);

            // Store pending state — signatures will be collected on subsequent periodic cycles
            let pending = PendingConfiscation {
                request_id,
                confiscation_tx,
                sighash_bytes,
                signatures,
                required_sigs,
                voter_set,
                tier_index,
                leaf_script,
                taproot_output,
                confiscated_marker,
                lottery_address: lottery_output.address.to_string(),
                ledger_prefix: ledger_prefix.to_string(),
                created_at: std::time::Instant::now(),
            };

            self.pending_confiscations.lock().unwrap().insert(ledger_prefix.to_string(), pending);
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

            // Find the fork or original ledger key (prefer fork for dispute operations)
            let ledger_key = match self.find_fork_or_original_by_prefix(ledger_prefix) {
                Some(key) => key,
                None => continue,
            };

            // Extract the base ledger_id (first 64 chars) for Nostr queries
            let ledger_id = if ledger_key.len() > 64 {
                ledger_key[..64].to_string()
            } else {
                ledger_key.clone()
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
        use bitcoin::secp256k1::PublicKey;
        use deposits_core::TlvDecode;
        use deposits_core::messages::LedgerOperation;
        use deposits_core::tapscript_reserves::{LotteryScriptBuilder, LotteryParticipant};
        use crate::nostr::KIND_LEDGER_UPDATE;
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
        use nostr_sdk::{Filter, Kind};
        use nostr_sdk::prelude::{SingleLetterTag, Alphabet};

        // Use the slow relay client for historical fetch
        let client = self.nostr.fetch_client();

        let filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_UPDATE))
            .custom_tag(SingleLetterTag::lowercase(Alphabet::D), [ledger_id])
            .limit(500);

        let events = client
            .fetch_events(vec![filter], None)
            .await
            .map_err(|e| Error::Protocol(format!("Failed to fetch: {}", e)))?;

        // Extract DisputeArmed participants AND quorum members (must match auto_confiscate)
        let mut participants: Vec<LotteryParticipant> = Vec::new();
        let mut quorum_members: Vec<PublicKey> = Vec::new();
        let mut original_operator: Option<PublicKey> = None;

        for event in events.iter() {
            if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
                if let Ok(update) = deposits_core::SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                    if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                        match op {
                            LedgerOperation::LedgerOpen { operator_id, .. } => {
                                original_operator = Some(operator_id);
                            }
                            LedgerOperation::QuorumAddMember { quorum_member, .. } => {
                                // Only use QuorumAddMember from original operator's updates
                                // (must match auto_confiscate's filtering)
                                let is_from_original = original_operator
                                    .map(|op| update.operator_id == op)
                                    .unwrap_or(true);
                                if is_from_original && !quorum_members.contains(&quorum_member) {
                                    quorum_members.push(quorum_member);
                                }
                            }
                            LedgerOperation::DisputeArmed { commitment_hash, target_reserves, .. } => {
                                let x_only = update.operator_id.x_only_public_key().0;
                                if !participants.iter().any(|p| p.pubkey == x_only) {
                                    participants.push(LotteryParticipant::new(x_only, commitment_hash, target_reserves));
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        if participants.len() < 2 {
            return Err(Error::Protocol("Not enough participants for lottery".to_string()));
        }

        // Sort participants by x-only pubkey for deterministic order
        participants.sort_by(|a, b| a.pubkey.serialize().cmp(&b.pubkey.serialize()));

        // Build recovery voters from quorum_members (must match auto_confiscate)
        if let Some(orig_op) = original_operator {
            quorum_members.retain(|pk| *pk != orig_op);
        }

        let recovery_voters: Vec<bitcoin::secp256k1::XOnlyPublicKey> = quorum_members.iter()
            .filter(|pk| original_operator.map_or(true, |op| **pk != op))
            .map(|pk| pk.x_only_public_key().0)
            .collect();
        let recovery_threshold = (recovery_voters.len() / 2) + 1;

        let lottery_builder = LotteryScriptBuilder::new(
            participants,
            recovery_voters,
            recovery_threshold,
            self.wallet.network(),
        );

        let lottery_output = lottery_builder.build()
            .map_err(|e| Error::Protocol(format!("Failed to build lottery output: {:?}", e)))?;

        tracing::debug!("check_confiscation_confirmed: lottery address = {}", lottery_output.address);

        // Check if lottery address has a UTXO with enough confirmations
        let lottery_script = lottery_output.address.script_pubkey();

        let utxo_result = self.wallet.find_utxo_for_script(&lottery_script)?;

        if utxo_result.is_none() {
            return Ok(false); // No UTXO at lottery address yet
        }

        // Check confirmations
        let current_height = self.wallet.get_block_height().unwrap_or(0);

        // Use armed height heuristic: if UTXO exists and 3+ blocks since we first saw it, confirmed
        let armed_height_file = self.data_dir.join(format!("lottery_armed_height_{}.txt", &ledger_id[..16.min(ledger_id.len())]));

        if let Ok(height_str) = std::fs::read_to_string(&armed_height_file) {
            if let Ok(armed_height) = height_str.trim().parse::<u32>() {
                if current_height >= armed_height + min_confirmations {
                    return Ok(true);
                }
            }
        }

        // If no armed height file, create one (first time seeing the UTXO)
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

            // Find the fork or original ledger key (prefer fork for dispute operations)
            let ledger_key = match self.find_fork_or_original_by_prefix(ledger_prefix) {
                Some(key) => key,
                None => continue,
            };

            // Extract the base ledger_id (first 64 chars) for Nostr queries
            let ledger_id = if ledger_key.len() > 64 {
                ledger_key[..64].to_string()
            } else {
                ledger_key.clone()
            };

            // Check if we won (we published DisputeAcquire)
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

    /// Check if we won the lottery for a ledger (we published DisputeAcquire)
    async fn check_if_we_won(&self, ledger_id: &str) -> Result<bool, Error> {
        use deposits_core::TlvDecode;
        use deposits_core::messages::LedgerOperation;
        use crate::nostr::KIND_LEDGER_UPDATE;
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
        use nostr_sdk::{Client, Keys, Filter, Kind};
        use nostr_sdk::prelude::{SingleLetterTag, Alphabet};
        use bitcoin::secp256k1::Secp256k1;

        let secp = &self.secp;
        let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &self.wallet.operator_secret());
        let our_pubkey = keypair.public_key();

        // Use the slow relay client for historical fetch
        let client = self.nostr.fetch_client();

        let filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_UPDATE))
            .custom_tag(SingleLetterTag::lowercase(Alphabet::D), [ledger_id])
            .limit(500);

        let events = client
            .fetch_events(vec![filter], None)
            .await
            .map_err(|e| Error::Protocol(format!("Failed to fetch: {}", e)))?;

        // Check if we have a DisputeAcquire
        for event in events.iter() {
            if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
                if let Ok(update) = deposits_core::SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                    if update.operator_id == our_pubkey {
                        if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                            if matches!(op, LedgerOperation::DisputeAcquire { .. }) {
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

        let secp = &self.secp;
        let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &self.wallet.operator_secret());
        let our_pubkey = keypair.public_key();

        // Use the slow relay client for historical fetch
        let client = self.nostr.fetch_client();

        let filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_UPDATE))
            .custom_tag(SingleLetterTag::lowercase(Alphabet::D), [ledger_id])
            .limit(500);

        let events = client
            .fetch_events(vec![filter], None)
            .await
            .map_err(|e| Error::Protocol(format!("Failed to fetch: {}", e)))?;

        // Find our DisputeAcquire and quorum members
        let mut current_reserves_address: Option<String> = None;
        let mut our_latest: Option<SignedLedgerUpdate> = None;
        let mut quorum_members: Vec<PublicKey> = Vec::new();

        for event in events.iter() {
            if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
                if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                    if update.operator_id == our_pubkey {
                        if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                            if let LedgerOperation::DisputeAcquire { ref new_reserves_address, .. } = op {
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
            .ok_or_else(|| Error::Protocol("No DisputeAcquire found".to_string()))?;
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

        // Compute quorum parameters for QuorumBegin
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

        // Publish QuorumBegin operation (convert sats to msats at boundary)
        let operation = LedgerOperation::QuorumBegin {
            reserves_id: taproot_output.address.to_string(),
            spending_txid: *outpoint.txid.as_ref(),
            new_outpoint_txid: *rotate_txid.as_ref(),
            new_outpoint_vout: 0,
            amount: output_amount.saturating_mul(1000), // sats to msats
            first_expiry_block,
            ledger_hash,
            quorum_members: quorum_members.clone(),
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
            message_type: deposits_core::messages::consts::QUORUM_BEGIN,
            operator_signature: operator_sig_bytes,
            cosigner_pubkey: None,
            member_ledger_hash: None,
            cosign_signature: [0u8; 64],
            operator_id: our_pubkey,
            ledger_id: ledger_id_bytes,
            sequence_number: sequence,
            previous_hash: our_latest.current_hash,
            current_hash: new_hash,
            block_height: current_block,
            block_hash,
        };

        self.nostr.broadcast_ledger_update(&signed_update).await
            .map_err(|e| Error::Protocol(format!("Failed to broadcast QuorumBegin: {:?}", e)))?;

        tracing::info!("QuorumBegin published. New reserves at: {}", taproot_output.address);
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

        let secp = &self.secp;
        let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &self.wallet.operator_secret());
        let our_pubkey = keypair.public_key();

        // Use the slow relay client for historical fetch
        let client = self.nostr.fetch_client();

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
                is_collateral: false,
                receive_requires_sig: false,
                fee_change_after_blocks: None,
                fee_change_notice_blocks: None,
                fee_change_limit_bps: None,
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
                cosign_signature: [0u8; 64],
                operator_id: our_pubkey,
                ledger_id: ledger_id_bytes,
                sequence_number: sequence,
                previous_hash: our_latest.current_hash,
                current_hash: new_hash,
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

    async fn process_deposit_open_request(&self, request: &crate::nostr::LedgerRequest) -> (bool, Option<String>, Option<String>) {
        use std::str::FromStr;

        tracing::info!("Processing deposit_open request for ledger {}...",
            &request.ledger_id[..16.min(request.ledger_id.len())]);

        // Check deposit allowlist (if configured)
        {
            let allowlist = self.deposit_allowlist.read().unwrap();
            if !allowlist.is_empty() && !allowlist.contains(&request.sender) {
                tracing::warn!("Deposit open rejected: sender {} not on allowlist", &request.sender[..16.min(request.sender.len())]);
                return (false, None, Some("Not authorized to open deposits on this ledger".to_string()));
            }
        }

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

        // Check if this is a collateral deposit
        let is_collateral = request.params.get("is_collateral")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        // Check if receiving requires wallet signature
        let receive_requires_sig = request.params.get("receive_requires_sig")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

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
        match self.open_deposit(&ledger_id, &descriptor, Some(fees), transfer_fees, is_collateral, receive_requires_sig).await {
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

    async fn process_make_offer_request(&self, request: &crate::nostr::LedgerRequest) -> (bool, Option<String>, Option<String>) {
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

        // Check if the deposit (if it already exists) requires a receive signature
        {
            let descriptor = format!("pk({})", deposit_pubkey_str);
            let deposit_id = compute_deposit_id(&descriptor);
            let ledgers = self.handler.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&resolved_ledger_id) {
                let ledger = ledger_arc.read().unwrap();
                if let Some(deposit) = ledger.state.deposits.get(&deposit_id) {
                    if deposit.receive_requires_sig {
                        // Verify receive signature from deposit key
                        use bitcoin::secp256k1::{schnorr::Signature, Message};
                        let recv_sig_hex = match request.params.get("receive_signature").and_then(|v| v.as_str()) {
                            Some(s) => s,
                            None => return (false, None, Some("Deposit requires receive_signature for offers".to_string())),
                        };
                        let recv_sig = match hex::decode(recv_sig_hex)
                            .ok()
                            .and_then(|bytes| Signature::from_slice(&bytes).ok())
                        {
                            Some(sig) => sig,
                            None => return (false, None, Some("Invalid receive_signature".to_string())),
                        };
                        // Sign the deposit_id to authorize receiving
                        let recv_msg = Message::from_digest({
                            let mut h = [0u8; 32];
                            h[..16].copy_from_slice(&deposit_id);
                            h
                        });
                        let dest_pubkey = deposit_pubkey.x_only_public_key().0;
                        let secp = &self.secp;
                        if secp.verify_schnorr(&recv_sig, &recv_msg, &dest_pubkey).is_err() {
                            return (false, None, Some("Invalid receive_signature".to_string()));
                        }
                    }
                }
            }
        }

        // Sync wallet to get current block height
        if let Err(e) = self.sync_wallet() {
            return (false, None, Some(format!("Failed to sync wallet: {}", e)));
        }

        // Check collateral obligation limits before creating the offer
        if let Some(err) = self.check_collateral_obligation_limit(&resolved_ledger_id, max_sats * 1000) {
            return (false, None, Some(err));
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
                                "operator_id": pubkey_hex(&offer.operator_id),
                                "funding_address": offer.funding_address,
                                "deadline_block": offer.deadline_block,
                                "created_at_block": offer.created_at_block,
                                "max_sats": max_sats,
                                "min_sats": min_sats,
                                "cosign_required": true,
                                "cosigner_pubkey": pubkey_hex(&cosign_result.cosigner_pubkey),
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
                        "operator_id": pubkey_hex(&offer.operator_id),
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
                let block_height = self.wallet.get_block_height().unwrap_or(0);
                let result = serde_json::json!({
                    "deposit_pubkey": deposit_pubkey_hex,
                    "deposit_id": hex::encode(deposit_id),
                    "balance_msats": deposit.balance,
                    "balance_sats": deposit.balance / 1000,
                    "locked_msats": deposit.locked_balance,
                    "collateral_lock_msats": deposit.collateral_lock_amount,
                    "collateral_lock_expires": deposit.collateral_lock_expires,
                    "block_height": block_height,
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
    /// Uses LdkCli to talk to the ldk-server sidecar (same as `deposits-node lightning invoice`)
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

        // Check if deposit requires receive signature
        {
            let ledgers = self.handler.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&request.ledger_id) {
                let ledger = ledger_arc.read().unwrap();
                if let Some(deposit) = ledger.state.deposits.get(&deposit_id) {
                    if deposit.receive_requires_sig {
                        use bitcoin::secp256k1::{schnorr::Signature, Message};
                        let recv_sig_hex = match request.params.get("receive_signature").and_then(|v| v.as_str()) {
                            Some(s) => s,
                            None => return (false, None, Some("Deposit requires receive_signature for invoices".to_string())),
                        };
                        let recv_sig = match hex::decode(recv_sig_hex)
                            .ok()
                            .and_then(|bytes| Signature::from_slice(&bytes).ok())
                        {
                            Some(sig) => sig,
                            None => return (false, None, Some("Invalid receive_signature".to_string())),
                        };
                        // Sign the deposit_id to authorize receiving
                        let recv_msg = Message::from_digest({
                            let mut h = [0u8; 32];
                            h[..16].copy_from_slice(&deposit_id);
                            h
                        });
                        let dest_pubkey = match hex::decode(deposit_pubkey_hex)
                            .ok()
                            .and_then(|b| bitcoin::secp256k1::PublicKey::from_slice(&b).ok())
                        {
                            Some(pk) => pk.x_only_public_key().0,
                            None => return (false, None, Some("Invalid deposit_pubkey".to_string())),
                        };
                        let secp = &self.secp;
                        if secp.verify_schnorr(&recv_sig, &recv_msg, &dest_pubkey).is_err() {
                            return (false, None, Some("Invalid receive_signature".to_string()));
                        }
                    }
                }
            }
        }

        let amount_sats = match request.params.get("amount_sats").and_then(|v| v.as_u64()) {
            Some(a) => a,
            None => return (false, None, Some("Missing amount_sats parameter".to_string())),
        };

        let description = request.params.get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("Deposit credit");

        let amount_msat = amount_sats * 1000;

        // Check collateral obligation limits before creating the invoice
        if let Some(err) = self.check_collateral_obligation_limit(&request.ledger_id, amount_msat) {
            return (false, None, Some(err));
        }

        // Create invoice via LdkCli (same as `deposits-node lightning invoice`)
        let cli = LdkCli::from_env();

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

                // Request co-signature from quorum member (if post-rotation)
                let requires_cosign = self.has_quorum_reserves(&request.ledger_id);
                if requires_cosign {
                    let params = serde_json::json!({
                        "payment_hash": hex::encode(payment_hash),
                        "deposit_id": hex::encode(deposit_id),
                        "amount_msat": amount_msat,
                        "invoice": &invoice_str,
                    });

                    let mut notification_rx = self.nostr.create_notification_receiver();
                    let req_id = match self.nostr.send_ledger_request(&request.ledger_id, "cosign_invoice", params).await {
                        Ok(id) => id,
                        Err(e) => {
                            return (false, None, Some(format!("Failed to send cosign_invoice: {:?}", e)));
                        }
                    };
                    self.track_sent_event(&req_id);

                    // Poll for response (3s timeout)
                    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(3);
                    let mut cosign_result: Option<serde_json::Value> = None;
                    loop {
                        // Drain notifications to trigger response processing
                        match tokio::time::timeout(
                            tokio::time::Duration::from_millis(100),
                            notification_rx.recv(),
                        ).await {
                            Ok(Ok(n)) => { self.nostr.dispatch_or_extract_request(n, ""); }
                            Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => {}
                            _ => {}
                        }
                        // Check for our response
                        while let Some(response) = self.nostr.try_recv_response() {
                            if response.request_id == req_id && response.success {
                                cosign_result = response.result.clone();
                                break;
                            }
                        }
                        if cosign_result.is_some() || tokio::time::Instant::now() >= deadline { break; }
                    }

                    match cosign_result {
                        Some(r) => {
                            let result = serde_json::json!({
                                "invoice": invoice_str,
                                "amount_sats": amount_sats,
                                "deposit_pubkey": deposit_pubkey_hex,
                                "deposit_id": hex::encode(deposit_id),
                                "payment_hash": hex::encode(payment_hash),
                                "cosign_required": true,
                                "cosigner_pubkey": r.get("cosigner_pubkey").and_then(|v| v.as_str()).unwrap_or(""),
                                "cosigner_ledger_hash": r.get("cosigner_ledger_hash").and_then(|v| v.as_str()).unwrap_or(""),
                                "cosign_signature": r.get("cosign_signature").and_then(|v| v.as_str()).unwrap_or(""),
                            });
                            (true, Some(result.to_string()), None)
                        }
                        None => {
                            (false, None, Some("Invoice co-signature required but no quorum member responded".to_string()))
                        }
                    }
                } else {
                    let result = serde_json::json!({
                        "invoice": invoice_str,
                        "amount_sats": amount_sats,
                        "deposit_pubkey": deposit_pubkey_hex,
                        "deposit_id": hex::encode(deposit_id),
                        "payment_hash": hex::encode(payment_hash),
                    });
                    (true, Some(result.to_string()), None)
                }
            }
            Err(e) => {
                tracing::error!("Failed to create invoice: {}", e);
                (false, None, Some(format!("Failed to create invoice: {}", e)))
            }
        }
    }

    /// Process a pay_invoice request - pay Lightning invoice from deposit
    ///
    /// Uses LdkCli to talk to the ldk-server sidecar (same as `deposits-node lightning pay`)
    ///
    /// Params:
    /// - deposit_pubkey: hex-encoded depositor's pubkey
    /// - invoice: bolt11 invoice string
    /// - nonce: hex-encoded 32-byte nonce
    /// - signature: hex-encoded Schnorr signature over payment message
    async fn process_pay_invoice_request(&self, request: &crate::nostr::LedgerRequest) -> (bool, Option<String>, Option<String>) {
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

            ledger.next_sequence()
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

        // Check for self-pay: if this invoice was created by us (exists in pending_invoices),
        // settle internally without touching LDK. This handles the case where a depositor
        // pays an invoice created for another depositor on the same operator.
        let self_pay = self.pending_invoices.lock().unwrap().contains_key(&payment_id);

        if self_pay {
            tracing::info!("Self-pay detected for payment {}... — settling internally",
                hex::encode(&payment_id[..8]));

            // Look up the pending invoice to find the destination deposit
            let pending = self.pending_invoices.lock().unwrap().remove(&payment_id);
            if let Some(pending) = pending {
                // Fulfill the lock (debit sender)
                let fulfill_sequence = {
                    let ledger = ledger_arc.read().unwrap();
                    ledger.next_sequence()
                };

                let fulfill_operation = LedgerOperation::InvoiceFulfill {
                    deposit_id,
                    amount: amount_msat,
                    payment_id,
                    sequence_number: fulfill_sequence,
                    witness: witness.clone(),
                    preimage: [0u8; 32], // No real preimage needed for internal settlement
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
                        return (false, None, Some(format!("Failed to fulfill self-pay: {:?}", e)));
                    }
                }

                // Credit the destination deposit
                let credit_sequence = {
                    let ledger = ledger_arc.read().unwrap();
                    ledger.next_sequence()
                };

                let credit_operation = LedgerOperation::InvoiceCredit {
                    payment_hash: payment_id,
                    deposit_id: pending.deposit_id,
                    amount: amount_msat,
                    invoice_id: pending.invoice.clone(),
                    sequence_number: credit_sequence,
                };

                {
                    let mut ledger = ledger_arc.write().unwrap();
                    let block_height = self.wallet.get_block_height().unwrap_or(0);
                    let block_hash = self.wallet.get_block_hash().unwrap_or([0u8; 32]);

                    if let Err(e) = ledger.append_operation_with_block(
                        credit_operation,
                        deposits_core::messages::consts::RECEIVING_CREDIT_PAYMENT,
                        block_height,
                        block_hash,
                    ) {
                        tracing::error!("Failed to credit destination deposit: {:?}", e);
                    }
                }

                if let Err(e) = self.sign_and_broadcast(ledger_id).await {
                    tracing::error!("Failed to broadcast self-pay: {}", e);
                }

                tracing::info!("Self-pay settled: {} msat from {} to {}",
                    amount_msat,
                    hex::encode(&deposit_id[..4]),
                    hex::encode(&pending.deposit_id[..4]));

                let result = serde_json::json!({
                    "payment_id": hex::encode(&payment_id),
                    "deposit_pubkey": deposit_pubkey_hex,
                    "amount_msat": amount_msat,
                    "status": "succeeded",
                    "self_pay": true,
                });
                return (true, Some(result.to_string()), None);
            }
        }

        // Pay invoice via LdkCli (external payment)
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
            ledger.next_sequence()
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
    async fn process_withdraw_request(&self, request: &crate::nostr::LedgerRequest) -> (bool, Option<String>, Option<String>) {
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
        let secp = &self.secp;
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
    async fn process_transfer_lock_request(&self, request: &crate::nostr::LedgerRequest) -> (bool, Option<String>, Option<String>) {
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
        let secp = &self.secp;
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

        // Check if destination deposit requires a receive signature
        {
            let ledgers = self.handler.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(ledger_id) {
                let ledger = ledger_arc.read().unwrap();
                if let Some(dest_deposit) = ledger.state.deposits.get(&destination_deposit_id) {
                    if dest_deposit.receive_requires_sig {
                        // Verify receive signature from destination deposit key
                        let recv_sig_hex = match request.params.get("receive_signature").and_then(|v| v.as_str()) {
                            Some(s) => s,
                            None => return (false, None, Some("Destination deposit requires receive_signature".to_string())),
                        };
                        let recv_sig = match hex::decode(recv_sig_hex)
                            .ok()
                            .and_then(|bytes| Signature::from_slice(&bytes).ok())
                        {
                            Some(sig) => sig,
                            None => return (false, None, Some("Invalid receive_signature".to_string())),
                        };
                        // Destination key signs the transfer_id to authorize receiving
                        let recv_msg = Message::from_digest(transfer_id);
                        let dest_pubkey = if dest_deposit.descriptor.starts_with("pk(") {
                            let pk_hex = &dest_deposit.descriptor[3..dest_deposit.descriptor.len()-1];
                            match hex::decode(pk_hex).ok().and_then(|b| bitcoin::secp256k1::PublicKey::from_slice(&b).ok()) {
                                Some(pk) => pk.x_only_public_key().0,
                                None => return (false, None, Some("Invalid destination deposit pubkey".to_string())),
                            }
                        } else {
                            return (false, None, Some("Only pk() descriptors supported for receive_requires_sig".to_string()));
                        };
                        if secp.verify_schnorr(&recv_sig, &recv_msg, &dest_pubkey).is_err() {
                            return (false, None, Some("Invalid receive_signature: does not match destination deposit key".to_string()));
                        }
                    }
                }
            }
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

        // Persist immediately — transfer_lock creates pending_transfer state
        // that must survive bounces so transfer_complete can find it.
        if let Err(e) = self.handler.persist_ledger_to_disk(ledger_id) {
            tracing::warn!("Failed to persist after transfer_lock: {}", e);
        }

        tracing::info!("Transfer locked: {}", hex::encode(&transfer_id[..8]));
        tracing::info!("[PROFILE] transfer_lock breakdown: append={:?}, sign_broadcast={:?}",
            append_elapsed, sign_elapsed);
        (true, Some(serde_json::json!({
            "transfer_id": transfer_id_hex,
            "amount": amount,
            "fee": fee,
            "message": "Transfer locked successfully"
        }).to_string()), None)
    }

    /// Process a transfer_complete request - complete a transfer by revealing preimage
    async fn process_transfer_complete_request(&self, request: &crate::nostr::LedgerRequest) -> (bool, Option<String>, Option<String>) {
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

        // Persist immediately — transfer_complete consumes pending_transfer
        // and credits the destination; must survive bounces.
        if let Err(e) = self.handler.persist_ledger_to_disk(ledger_id) {
            tracing::warn!("Failed to persist after transfer_complete: {}", e);
        }

        crate::metrics::record_transfer_completed(&request.ledger_id);
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

    async fn process_collateral_lock_request(&self, request: &crate::nostr::LedgerRequest) -> (bool, Option<String>, Option<String>) {
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
        let secp = &self.secp;
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
                    "quorum_member": pubkey_hex(&attestation.quorum_member),
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
    /// The signature covers: cosign_data || our_ledger_current_hash
    /// This binds the co-signature to the current state of our own ledger.
    async fn process_cosign_request(&self, request: &crate::nostr::LedgerRequest) -> (bool, Option<String>, Option<String>) {
        use bitcoin::hashes::{sha256, Hash};
        use bitcoin::secp256k1::{Message, Secp256k1};
        use std::str::FromStr;

        tracing::info!("Processing cosign_update request for ledger {}...",
            &request.ledger_id[..16.min(request.ledger_id.len())]);

        // Extract sequence_number early — we need it for the freshness check.
        let sequence_number = match request.params.get("sequence_number").and_then(|v| v.as_u64()) {
            Some(seq) => seq,
            None => return (false, None, Some("Missing sequence_number parameter".to_string())),
        };

        // Apply piggybacked updates before freshness check.
        // The requester includes the previous signed update (seq N-1) so we can
        // catch up inline without waiting for relay delivery.
        if let Some(prev_arr) = request.params.get("previous_updates").and_then(|v| v.as_array()) {
            use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
            let mut applied = 0usize;
            for item in prev_arr {
                if let Some(b64) = item.as_str() {
                    if let Ok(tlv) = BASE64.decode(b64) {
                        if let Ok(update) = deposits_core::SignedLedgerUpdate::tlv_decode(&tlv) {
                            self.handler.insert_event(&update);
                            let ledgers = self.handler.ledgers.lock().unwrap();
                            if let Some(arc) = ledgers.get(&request.ledger_id) {
                                let mut ledger = arc.write().unwrap();
                                if update.sequence_number == ledger.next_sequence() {
                                    ledger.history.push(update);
                                    applied += 1;
                                }
                            }
                        }
                    }
                }
            }
            if applied > 0 {
                self.catch_up_ledger_from_event_store(&request.ledger_id);
                tracing::debug!("Applied {} piggybacked updates for {}...",
                    applied, &request.ledger_id[..16.min(request.ledger_id.len())]);
            }
        }

        // Freshness check with event-store recovery.
        //
        // If our ledger history is behind the requested sequence, try to catch up
        // from the event store (pure in-memory, no relay I/O) before giving up.
        // This avoids returning "stale" when the event store already has the events
        // but the ledger history hasn't been updated yet.
        {
            let ledgers = self.handler.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&request.ledger_id) {
                let ledger = ledger_arc.read().unwrap();
                if ledger.state.dispute_state != deposits_core::types::DisputeState::Normal {
                    return (false, None, Some(format!(
                        "Ledger {}... in dispute state {:?}",
                        &request.ledger_id[..16.min(request.ledger_id.len())],
                        ledger.state.dispute_state
                    )));
                }
                let local_seq = ledger.next_sequence();
                if local_seq < sequence_number {
                    // Release locks before attempting recovery
                    drop(ledger);
                    drop(ledgers);

                    // Try to catch up from event store (no relay I/O)
                    let caught_up = self.catch_up_ledger_from_event_store(&request.ledger_id);
                    if caught_up > 0 {
                        metrics::record_cosign_freshness_recovery("recovered");
                        tracing::info!(
                            "Cosign freshness: caught up {} events from event store for ledger {}...",
                            caught_up, &request.ledger_id[..16.min(request.ledger_id.len())],
                        );
                    }

                    // Re-check after catch-up
                    let still_stale = {
                        let ledgers = self.handler.ledgers.lock().unwrap();
                        ledgers.get(&request.ledger_id)
                            .map(|arc| {
                                let l = arc.read().unwrap();
                                l.next_sequence() < sequence_number
                            })
                            .unwrap_or(true)
                    };

                    if still_stale {
                        // Still behind after event store catch-up + pre-cosign channel drain.
                        // Queue for background relay fetch; clear the per-ledger cooldown so
                        // the next reload-loop iteration (2-3s) fires immediately instead of
                        // waiting up to 30s. The operator will retry (3 attempts × 500ms),
                        // giving the background fetch time to catch up.
                        metrics::record_cosign_freshness_recovery("stale");
                        metrics::record_pre_cosign_drain(0, false);
                        self.stale_joined_ledgers.lock().unwrap().insert(request.ledger_id.clone());
                        // Reset relay-fetch cooldown so next reload cycle fetches immediately.
                        self.last_relay_fetch_times.lock().unwrap().remove(&request.ledger_id);
                        let current_len = {
                            let ledgers = self.handler.ledgers.lock().unwrap();
                            ledgers.get(&request.ledger_id)
                                .map(|arc| arc.read().unwrap().next_sequence())
                                .unwrap_or(0)
                        };
                        tracing::debug!(
                            "Cosign stale: have {}, need {} for {}...",
                            current_len, sequence_number,
                            &request.ledger_id[..16.min(request.ledger_id.len())]
                        );
                        return (false, None, None);
                    }
                }
            }
        }

        let cosign_data_hex = match request.params.get("cosign_data_hex").and_then(|v| v.as_str()) {
            Some(hex) => hex.to_string(),
            None => return (false, None, Some("Missing cosign_data_hex parameter".to_string())),
        };

        let current_hash_hex = match request.params.get("current_hash_hex").and_then(|v| v.as_str()) {
            Some(hex) => hex.to_string(),
            None => return (false, None, Some("Missing current_hash_hex parameter".to_string())),
        };

        // Decode cosign data
        let cosign_data = match hex::decode(&cosign_data_hex) {
            Ok(data) => data,
            Err(e) => return (false, None, Some(format!("Invalid cosign_data_hex: {}", e))),
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

        // Validate sequence number if we have local ledger state.
        // sequence_number = operator's history.len() BEFORE pushing the new update
        // (0-indexed: first entry = seq 0).  Our local copy should have the same
        // number of entries as the operator had before appending.
        //
        // Only reject if we're BEHIND the operator (we're missing history they already
        // have). Being AHEAD is fine — Nostr broadcasts arrive at quorum members faster
        // than cosign requests, so at high TPS members are typically 1-2 seqs ahead.
        // The stale recovery block above handles the "we're behind" case; this block
        // is a safety net for exact-match validation only.
        if let Some(ref arc) = operator_ledger_arc {
            let ledger = arc.read().unwrap();
            let expected_seq = ledger.next_sequence();
            if sequence_number > expected_seq {
                tracing::debug!(
                    "Cosign seq mismatch: expected {}, got {} for {}...",
                    expected_seq, sequence_number,
                    &request.ledger_id[..16.min(request.ledger_id.len())]
                );
                return (false, None, None);
            }

            if let Some(last_update) = ledger.history.last() {
                let prev_hash = last_update.current_hash;
                tracing::debug!("Validating co-sign for seq {} (prev_hash: {}...)",
                    sequence_number, &hex::encode(&prev_hash[..4]));
            }
        }

        // Auto-detect which of OUR ledgers is bound to the requesting ledger.
        // Uses a cache (target_ledger_id → our_member_ledger_key) to avoid the
        // expensive O(N) history TLV-decode scan on every cosign request.
        let member_ledger_hash: [u8; 32] = {
            // Fast path: check cache
            let cached_key = self.cosign_member_cache.lock().unwrap()
                .get(&request.ledger_id).cloned();

            let member_key = if let Some(key) = cached_key {
                key
            } else {
                // Cache miss: do the full scan, then cache the result
                let t_scan = std::time::Instant::now();
                let ledgers = self.handler.ledgers.lock().unwrap();
                let mut found_key = None;

                for (ledger_key, arc) in ledgers.iter() {
                    let ledger = arc.read().unwrap();
                    if ledger.operator_key() != self.node_id {
                        continue;
                    }

                    let history_len = ledger.history.len();
                    let has_join = ledger.history.iter().any(|update| {
                        if update.message_type != deposits_core::messages::consts::QUORUM_JOIN {
                            return false;
                        }
                        if let Ok(LedgerOperation::QuorumJoin { operator_id, ledger_id, .. }) =
                            LedgerOperation::tlv_decode(&update.message)
                        {
                            if ledger_id == request.ledger_id {
                                return true;
                            }
                            if let Some(target_op) = &target_operator_id {
                                let jq_x = &operator_id.serialize()[1..];
                                let target_x = &target_op.serialize()[1..];
                                if jq_x == target_x {
                                    return true;
                                }
                            }
                        }
                        false
                    });

                    let scan_elapsed = t_scan.elapsed();
                    if scan_elapsed.as_millis() > 0 {
                        tracing::info!("[PROFILE] cosign QuorumJoin scan (cache miss): {} entries in {:?}", history_len, scan_elapsed);
                    }

                    if has_join {
                        found_key = Some(ledger_key.clone());
                        break;
                    }
                }
                drop(ledgers);

                match found_key {
                    Some(key) => {
                        self.cosign_member_cache.lock().unwrap()
                            .insert(request.ledger_id.clone(), key.clone());
                        key
                    }
                    None => return (false, None, Some(
                        "No ledger found with QuorumJoin to target - not a quorum member".to_string()
                    )),
                }
            };

            // O(1) hash lookup using the cached member ledger key
            let ledgers = self.handler.ledgers.lock().unwrap();
            match ledgers.get(&member_key) {
                Some(arc) => {
                    let ledger = arc.read().unwrap();
                    let hash = ledger.history.last()
                        .map(|u| u.current_hash)
                        .unwrap_or([0u8; 32]);
                    tracing::debug!("Member ledger {} hash {}...",
                        &member_key[..16.min(member_key.len())],
                        &hex::encode(&hash[..4]));
                    hash
                }
                None => {
                    // Ledger disappeared — invalidate cache entry and fail
                    self.cosign_member_cache.lock().unwrap().remove(&request.ledger_id);
                    return (false, None, Some(
                        "Member ledger no longer found".to_string()
                    ));
                }
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
        tagged_input.extend_from_slice(&cosign_data);
        tagged_input.extend_from_slice(&member_ledger_hash);

        let hash = sha256::Hash::hash(&tagged_input);

        // Sign with Schnorr (BIP-340)
        let secp = &self.secp;
        let msg = Message::from_digest(hash.to_byte_array());
        let secret = self.wallet.operator_secret();
        let keypair = bitcoin::secp256k1::Keypair::from_secret_key(secp, &secret);
        let sig = secp.sign_schnorr(&msg, &keypair);
        let sig_bytes = sig.serialize();

        tracing::info!("Co-signed update seq={} for ledger {}... (member_ledger_hash: {}...)",
            sequence_number, &request.ledger_id[..16], &hex::encode(&member_ledger_hash[..4]));

        // Return the signature, our pubkey, and our ledger hash
        let result = serde_json::json!({
            "cosign_signature_hex": hex::encode(sig_bytes),
            "cosigner_pubkey": self.node_id_hex.clone(),
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

        // Refuse to co-sign if the ledger is in a disputed state.
        // Don't block on reimport — the background sync will catch up.
        {
            let ledgers = self.handler.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&request.ledger_id) {
                let ledger = ledger_arc.read().unwrap();
                if ledger.state.dispute_state != deposits_core::types::DisputeState::Normal {
                    tracing::warn!("Refusing to cosign offer for ledger {} - dispute state: {:?}",
                        &request.ledger_id[..16.min(request.ledger_id.len())],
                        ledger.state.dispute_state);
                    return (false, None, Some(format!(
                        "Ledger is in {:?} state - cannot co-sign offers",
                        ledger.state.dispute_state
                    )));
                }
            }
        }

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
        // Match on ledger_id (stable across custody transfers) with fallback
        // to operator x-coord match.
        let member_ledger_hash: [u8; 32] = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let mut found_hash = None;

            for (_ledger_id, arc) in ledgers.iter() {
                let ledger = arc.read().unwrap();

                // Only look at ledgers where we are the operator
                if ledger.operator_key() != self.node_id {
                    continue;
                }

                // Check if this ledger has a QuorumJoin pointing to the target ledger
                let has_join = ledger.history.iter().any(|update| {
                    if update.message_type != deposits_core::messages::consts::QUORUM_JOIN {
                        return false;
                    }
                    if let Ok(LedgerOperation::QuorumJoin { operator_id: join_op, ledger_id: join_ledger, .. }) =
                        LedgerOperation::tlv_decode(&update.message)
                    {
                        // Primary match: ledger_id (stable across custody transfers)
                        if join_ledger == request.ledger_id {
                            return true;
                        }
                        // Fallback: operator x-coord match
                        if let Some(target_op) = &target_operator_id {
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

        // Sign with Schnorr (BIP-340)
        let secp = &self.secp;
        let msg = Message::from_digest(hash.to_byte_array());
        let secret = self.wallet.operator_secret();
        let keypair = bitcoin::secp256k1::Keypair::from_secret_key(secp, &secret);
        let sig = secp.sign_schnorr(&msg, &keypair);
        let sig_bytes = sig.serialize();

        tracing::info!("Co-signed offer {} for ledger {}... (member_ledger_hash: {}...)",
            &offer_id_hex[..16], &request.ledger_id[..16], &hex::encode(&member_ledger_hash[..4]));

        // Return the signature, our pubkey, and our ledger hash
        let result = serde_json::json!({
            "signature_hex": hex::encode(sig_bytes),
            "cosigner_pubkey": self.node_id_hex.clone(),
            "member_ledger_hash_hex": hex::encode(member_ledger_hash),
        });

        (true, Some(result.to_string()), None)
    }

    async fn process_cosign_invoice_request(&self, request: &crate::nostr::LedgerRequest) -> (bool, Option<String>, Option<String>) {
        use bitcoin::hashes::{sha256, Hash};
        use bitcoin::secp256k1::Message;

        tracing::info!("Processing cosign_invoice request for ledger {}...",
            &request.ledger_id[..16.min(request.ledger_id.len())]);

        // Extract parameters
        let payment_hash_hex = match request.params.get("payment_hash").and_then(|v| v.as_str()) {
            Some(h) => h.to_string(),
            None => return (false, None, Some("Missing payment_hash".to_string())),
        };
        let deposit_id_hex = match request.params.get("deposit_id").and_then(|v| v.as_str()) {
            Some(d) => d.to_string(),
            None => return (false, None, Some("Missing deposit_id".to_string())),
        };
        let amount_msat = match request.params.get("amount_msat").and_then(|v| v.as_u64()) {
            Some(a) => a,
            None => return (false, None, Some("Missing amount_msat".to_string())),
        };

        let payment_hash: [u8; 32] = match hex::decode(&payment_hash_hex) {
            Ok(b) if b.len() == 32 => { let mut a = [0u8; 32]; a.copy_from_slice(&b); a }
            _ => return (false, None, Some("Invalid payment_hash".to_string())),
        };
        let deposit_id: [u8; 16] = match hex::decode(&deposit_id_hex) {
            Ok(b) if b.len() == 16 => { let mut a = [0u8; 16]; a.copy_from_slice(&b); a }
            _ => return (false, None, Some("Invalid deposit_id".to_string())),
        };

        // Find our member ledger hash (same lookup as cosign_offer)
        let member_ledger_hash: [u8; 32] = {
            let cached_key = self.cosign_member_cache.lock().unwrap()
                .get(&request.ledger_id).cloned();
            let member_key = if let Some(key) = cached_key { key } else {
                let ledgers = self.handler.ledgers.lock().unwrap();
                let mut found_key = None;
                for (ledger_key, arc) in ledgers.iter() {
                    let ledger = arc.read().unwrap();
                    if ledger.operator_key() != self.node_id { continue; }
                    let has_join = ledger.history.iter().any(|update| {
                        if update.message_type != deposits_core::messages::consts::QUORUM_JOIN { return false; }
                        if let Ok(LedgerOperation::QuorumJoin { ledger_id: join_ledger, .. }) =
                            LedgerOperation::tlv_decode(&update.message)
                        { join_ledger == request.ledger_id } else { false }
                    });
                    if has_join { found_key = Some(ledger_key.clone()); break; }
                }
                drop(ledgers);
                match found_key {
                    Some(key) => {
                        self.cosign_member_cache.lock().unwrap()
                            .insert(request.ledger_id.clone(), key.clone());
                        key
                    }
                    None => return (false, None, Some("Not a quorum member".to_string())),
                }
            };
            let ledgers = self.handler.ledgers.lock().unwrap();
            match ledgers.get(&member_key) {
                Some(arc) => arc.read().unwrap().history.last()
                    .map(|u| u.current_hash).unwrap_or([0u8; 32]),
                None => return (false, None, Some("Member ledger not found".to_string())),
            }
        };

        // Build tagged hash: SHA256(tag || tag || signing_data || member_ledger_hash)
        let signing_data = Self::build_invoice_signing_data(
            &request.ledger_id, &payment_hash, &deposit_id, amount_msat,
        );
        let tag = b"deposits/invoice_cosign";
        let tag_hash = sha256::Hash::hash(tag);
        let mut tagged_input = Vec::new();
        tagged_input.extend_from_slice(tag_hash.as_byte_array());
        tagged_input.extend_from_slice(tag_hash.as_byte_array());
        tagged_input.extend_from_slice(&signing_data);
        tagged_input.extend_from_slice(&member_ledger_hash);
        let hash = sha256::Hash::hash(&tagged_input);

        let secp = &self.secp;
        let msg = Message::from_digest(hash.to_byte_array());
        let secret = self.wallet.operator_secret();
        let keypair = bitcoin::secp256k1::Keypair::from_secret_key(secp, &secret);
        let sig = secp.sign_schnorr(&msg, &keypair);

        tracing::info!("Co-signed invoice {} for ledger {}...",
            &payment_hash_hex[..16], &request.ledger_id[..16]);

        let result = serde_json::json!({
            "cosign_signature": hex::encode(sig.serialize()),
            "cosigner_pubkey": self.node_id_hex.clone(),
            "cosigner_ledger_hash": hex::encode(member_ledger_hash),
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
        let secp = &self.secp;
        let secret_key = self.wallet.operator_secret();
        let keypair = Keypair::from_secret_key(&secp, &secret_key);
        let our_pubkey = self.node_id;

        tracing::info!("    Our key: {}...", &our_pubkey.to_string()[..16]);

        // Use the slow relay client for historical fetch
        let client = self.nostr.fetch_client();

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
            "signer": self.node_id_hex.clone(),
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
        let secp = &self.secp;
        let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &self.wallet.operator_secret());
        let msg = Message::from_digest(sighash_bytes);
        let signature = secp.sign_schnorr(&msg, &keypair);

        let our_pubkey = keypair.public_key();
        let result = serde_json::json!({
            "signer": self.node_id_hex.clone(),
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
    // Daemon-mediated CLI request handlers
    // ========================================================================

    async fn process_complete_offer_request(&self, request: &crate::nostr::LedgerRequest) -> (bool, Option<String>, Option<String>) {
        tracing::info!("Processing complete_offer request for ledger {}...",
            &request.ledger_id[..16.min(request.ledger_id.len())]);

        let offer_id_hex = match request.params.get("offer_id").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return (false, None, Some("Missing offer_id parameter".to_string())),
        };
        let txid = match request.params.get("txid").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return (false, None, Some("Missing txid parameter".to_string())),
        };
        let amount_sats = match request.params.get("amount_sats").and_then(|v| v.as_u64()) {
            Some(v) => v,
            None => return (false, None, Some("Missing amount_sats parameter".to_string())),
        };

        let offer_id_bytes = match hex::decode(offer_id_hex) {
            Ok(bytes) if bytes.len() == 32 => bytes,
            _ => return (false, None, Some("Invalid offer_id (must be 64 hex chars)".to_string())),
        };
        let mut offer_id = [0u8; 32];
        offer_id.copy_from_slice(&offer_id_bytes);

        // Sync wallet to see on-chain funding
        if let Err(e) = self.wallet.sync() {
            tracing::warn!("Wallet sync failed before complete_offer: {}", e);
        }

        match self.complete_deposit_offer(&offer_id, txid, amount_sats).await {
            Ok(new_balance) => {
                let result = serde_json::json!({
                    "status": "SUCCESS",
                    "new_balance_msats": new_balance,
                    "new_balance_sats": new_balance / 1000,
                });
                (true, Some(result.to_string()), None)
            }
            Err(e) => {
                tracing::error!("complete_offer failed: {}", e);
                (false, None, Some(e.to_string()))
            }
        }
    }

    async fn process_partner_add_request(&self, request: &crate::nostr::LedgerRequest) -> (bool, Option<String>, Option<String>) {
        use std::str::FromStr;

        tracing::info!("Processing partner_add request for ledger {}...",
            &request.ledger_id[..16.min(request.ledger_id.len())]);

        let member_pubkey_hex = match request.params.get("member_pubkey").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return (false, None, Some("Missing member_pubkey parameter".to_string())),
        };
        let member_ledger_id = match request.params.get("member_ledger_id").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return (false, None, Some("Missing member_ledger_id parameter".to_string())),
        };

        let quorum_member = match PublicKey::from_str(member_pubkey_hex) {
            Ok(pk) => pk,
            Err(e) => return (false, None, Some(format!("Invalid member_pubkey: {}", e))),
        };

        if member_ledger_id.len() != 64 || !member_ledger_id.chars().all(|c| c.is_ascii_hexdigit()) {
            return (false, None, Some("member_ledger_id must be 64 hex chars".to_string()));
        }

        // Resolve ledger_id
        let ledger_id = if request.ledger_id.len() == 64 && request.ledger_id.chars().all(|c| c.is_ascii_hexdigit()) {
            request.ledger_id.clone()
        } else {
            match self.get_ledger_by_reserves_key(&request.ledger_id) {
                Some((_, ledger)) => ledger.ledger_id_hex(),
                None => return (false, None, Some(format!("Ledger not found: {}", &request.ledger_id[..16]))),
            }
        };

        let placeholder_sig = [0u8; 64];

        // Extract fee limits the member is imposing (from their advertisement)
        let min_fee_bps = request.params.get("min_fee_bps").and_then(|v| v.as_u64()).map(|v| v as u16);
        let min_fee_fixed = request.params.get("min_fee_fixed").and_then(|v| v.as_u64());
        let max_fee_period = request.params.get("max_fee_period").and_then(|v| v.as_u64()).map(|v| v as u32);

        // Extract collateral commitment from request
        let collateral_lock_amount = request.params.get("collateral_lock_amount").and_then(|v| v.as_u64());
        let collateral_lock_until = request.params.get("collateral_lock_until").and_then(|v| v.as_u64()).map(|v| v as u32);

        match self.add_quorum_member(&ledger_id, quorum_member, &member_ledger_id, placeholder_sig, min_fee_bps, min_fee_fixed, max_fee_period, collateral_lock_amount, collateral_lock_until).await {
            Ok(event_id) => {
                let result = serde_json::json!({
                    "status": "SUCCESS",
                    "event_id": event_id,
                    "member": member_pubkey_hex,
                    "member_ledger_id": member_ledger_id,
                });
                (true, Some(result.to_string()), None)
            }
            Err(e) => {
                tracing::error!("partner_add failed: {}", e);
                (false, None, Some(e.to_string()))
            }
        }
    }

    async fn process_partner_join_request(&self, request: &crate::nostr::LedgerRequest) -> (bool, Option<String>, Option<String>) {
        use std::str::FromStr;

        tracing::info!("Processing partner_join request for ledger {}...",
            &request.ledger_id[..16.min(request.ledger_id.len())]);

        let target_operator_hex = match request.params.get("target_operator").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return (false, None, Some("Missing target_operator parameter".to_string())),
        };
        let target_ledger_id = match request.params.get("target_ledger_id").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => return (false, None, Some("Missing target_ledger_id parameter".to_string())),
        };
        let membership_expires = match request.params.get("membership_expires").and_then(|v| v.as_u64()) {
            Some(v) => v as u32,
            None => return (false, None, Some("Missing membership_expires parameter".to_string())),
        };

        let target_operator = match PublicKey::from_str(target_operator_hex) {
            Ok(pk) => pk,
            Err(e) => return (false, None, Some(format!("Invalid target_operator: {}", e))),
        };

        if target_ledger_id.len() != 64 || !target_ledger_id.chars().all(|c| c.is_ascii_hexdigit()) {
            return (false, None, Some("target_ledger_id must be 64 hex chars".to_string()));
        }

        // Resolve our ledger_id
        let our_ledger_id = if request.ledger_id.len() == 64 && request.ledger_id.chars().all(|c| c.is_ascii_hexdigit()) {
            request.ledger_id.clone()
        } else {
            match self.get_ledger_by_reserves_key(&request.ledger_id) {
                Some((_, ledger)) => ledger.ledger_id_hex(),
                None => return (false, None, Some(format!("Ledger not found: {}", &request.ledger_id[..16]))),
            }
        };

        let placeholder_sig = [0u8; 64];

        match self.record_quorum_join(&our_ledger_id, target_operator, &target_ledger_id, membership_expires, placeholder_sig).await {
            Ok(event_id) => {
                let result = serde_json::json!({
                    "status": "SUCCESS",
                    "event_id": event_id,
                    "target_operator": target_operator_hex,
                    "target_ledger_id": target_ledger_id,
                    "membership_expires": membership_expires,
                });
                (true, Some(result.to_string()), None)
            }
            Err(e) => {
                tracing::error!("partner_join failed: {}", e);
                (false, None, Some(e.to_string()))
            }
        }
    }

    async fn process_collateral_record_request(&self, request: &crate::nostr::LedgerRequest) -> (bool, Option<String>, Option<String>) {
        tracing::info!("Processing collateral_record request for ledger {}...",
            &request.ledger_id[..16.min(request.ledger_id.len())]);

        let attestation_json = match request.params.get("attestation").and_then(|v| v.as_str()) {
            Some(s) => s.to_string(),
            None => {
                // Try the whole params object as the attestation (if passed as object)
                match request.params.get("attestation") {
                    Some(v) => v.to_string(),
                    None => return (false, None, Some("Missing attestation parameter".to_string())),
                }
            }
        };

        let attestation: deposits_core::CollateralAttestationMsg = match serde_json::from_str(&attestation_json) {
            Ok(a) => a,
            Err(e) => return (false, None, Some(format!("Invalid attestation JSON: {}", e))),
        };

        // Resolve ledger_id
        let ledger_id = if request.ledger_id.len() == 64 && request.ledger_id.chars().all(|c| c.is_ascii_hexdigit()) {
            request.ledger_id.clone()
        } else {
            match self.get_ledger_by_reserves_key(&request.ledger_id) {
                Some((_, ledger)) => ledger.ledger_id_hex(),
                None => return (false, None, Some(format!("Ledger not found: {}", &request.ledger_id[..16]))),
            }
        };

        match self.record_collateral_attestation(&ledger_id, attestation).await {
            Ok(event_id) => {
                let result = serde_json::json!({
                    "status": "SUCCESS",
                    "event_id": event_id,
                });
                (true, Some(result.to_string()), None)
            }
            Err(e) => {
                tracing::error!("collateral_record failed: {}", e);
                (false, None, Some(e.to_string()))
            }
        }
    }

    async fn process_reserves_rotate_request(&self, request: &crate::nostr::LedgerRequest) -> (bool, Option<String>, Option<String>) {
        tracing::info!("Processing reserves_rotate request for ledger {}...",
            &request.ledger_id[..16.min(request.ledger_id.len())]);

        // Resolve ledger_id
        let ledger_id = if request.ledger_id.len() == 64 && request.ledger_id.chars().all(|c| c.is_ascii_hexdigit()) {
            request.ledger_id.clone()
        } else {
            match self.get_ledger_by_reserves_key(&request.ledger_id) {
                Some((_, ledger)) => ledger.ledger_id_hex(),
                None => return (false, None, Some(format!("Ledger not found: {}", &request.ledger_id[..16]))),
            }
        };

        // Reload reserves from disk (CLI may have created them after daemon started)
        if let Err(e) = self.wallet.reload_reserves_from_disk() {
            tracing::warn!("Failed to reload reserves from disk: {}", e);
        }

        // Sync wallet to see current UTXOs
        if let Err(e) = self.wallet.sync() {
            tracing::warn!("Wallet sync failed before reserves_rotate: {}", e);
        }

        match self.rotate_reserves_to_quorum(&ledger_id) {
            Ok(result) => {
                // Broadcast the update to Nostr
                if let Err(e) = self.broadcast_last_update(&ledger_id).await {
                    tracing::warn!("Failed to broadcast reserves rotation: {}", e);
                }

                let response = serde_json::json!({
                    "status": "SUCCESS",
                    "txid": result.txid,
                    "new_address": result.new_address,
                    "amount_sats": result.amount_sats,
                    "quorum_member_count": result.quorum_member_count,
                    "first_expiry_block": result.first_expiry_block,
                    "ledger_hash": hex::encode(&result.ledger_hash[..8]),
                });
                (true, Some(response.to_string()), None)
            }
            Err(e) => {
                tracing::error!("reserves_rotate failed: {}", e);
                (false, None, Some(e.to_string()))
            }
        }
    }

    /// Process a resync request from a quorum member asking us to re-broadcast
    /// ledger updates from a given sequence number. This enables post-restart
    /// recovery when the relay has evicted old events.
    async fn process_resync_request(&self, request: &crate::nostr::LedgerRequest) -> (bool, Option<String>, Option<String>) {
        let from_seq = request.params.get("from_seq")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        tracing::info!(
            "Processing resync request for ledger {}... from_seq={}",
            &request.ledger_id[..16.min(request.ledger_id.len())],
            from_seq,
        );

        // Get the ledger history
        let updates: Vec<deposits_core::SignedLedgerUpdate> = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            match ledgers.get(&request.ledger_id) {
                Some(arc) => {
                    let ledger = arc.read().unwrap();
                    ledger.history.iter()
                        .filter(|u| u.sequence_number >= from_seq)
                        .cloned()
                        .collect()
                }
                None => {
                    return (false, None, Some(format!(
                        "Ledger not found: {}...",
                        &request.ledger_id[..16.min(request.ledger_id.len())]
                    )));
                }
            }
        };

        if updates.is_empty() {
            let response = serde_json::json!({
                "rebroadcast_count": 0,
                "from_seq": from_seq,
                "through_seq": from_seq,
                "total_available": 0,
                "has_more": false,
            });
            return (true, Some(response.to_string()), None);
        }

        let total_available = updates.len();
        let batch: Vec<_> = updates.into_iter().take(Self::RESYNC_BATCH_CAP).collect();
        let first_seq = batch.first().map(|u| u.sequence_number).unwrap_or(from_seq);
        let last_seq = batch.last().map(|u| u.sequence_number).unwrap_or(from_seq);

        let mut rebroadcast_count = 0usize;
        for (i, update) in batch.iter().enumerate() {
            match self.nostr.broadcast_ledger_update(update).await {
                Ok(_) => rebroadcast_count += 1,
                Err(e) => {
                    tracing::warn!(
                        "Resync broadcast failed at seq {}: {}",
                        update.sequence_number, e,
                    );
                    break;
                }
            }
            // Yield every 10 broadcasts to avoid starving other tasks
            if (i + 1) % 10 == 0 {
                tokio::task::yield_now().await;
            }
        }

        let has_more = total_available > Self::RESYNC_BATCH_CAP;
        tracing::info!(
            "Resync: re-broadcast {} updates (seq {}..{}) for ledger {}... ({} total available, has_more={})",
            rebroadcast_count, first_seq, last_seq,
            &request.ledger_id[..16.min(request.ledger_id.len())],
            total_available, has_more,
        );

        let response = serde_json::json!({
            "rebroadcast_count": rebroadcast_count,
            "from_seq": first_seq,
            "through_seq": last_seq,
            "total_available": total_available,
            "has_more": has_more,
        });
        (true, Some(response.to_string()), None)
    }

    // ========================================================================
    // Auto-Response Tasks
    // ========================================================================

    /// Auto-complete deposits that have been funded on-chain
    pub async fn auto_complete_deposits(&self) {
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

            // Skip offers for ledgers we don't operate.
            // Quorum members also load the ledger, but only the operator should
            // auto-complete deposits — otherwise multiple daemons race to write
            // the same sequence number and cause hash chain breaks.
            if !self.is_operator_of_ledger(&offer.ledger_id) {
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
    pub async fn auto_complete_withdrawals(&self) {
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
                let ledgers = match self.handler.ledgers.try_lock() {
                    Ok(l) => l,
                    Err(_) => {
                        tracing::warn!("auto_complete_withdrawals: ledgers lock contended, skipping");
                        return;
                    }
                };
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
        // Use try_lock to avoid blocking the tokio thread if a detached JoinSet task holds the mutex
        let ledgers = match self.handler.ledgers.try_lock() {
            Ok(l) => l.clone(),
            Err(_) => {
                tracing::warn!("auto_collect_fees: ledgers lock contended, skipping this cycle");
                return;
            }
        };
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
    /// timeout_height and issues TransferFail operations to return funds
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
        let ledgers = match self.handler.ledgers.try_lock() {
            Ok(l) => l.clone(),
            Err(_) => {
                tracing::warn!("auto_timeout_transfers: ledgers lock contended, skipping this cycle");
                return;
            }
        };
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

                let operation = LedgerOperation::TransferFail {
                    transfer_id,
                    block_hash,
                    reason: 1,
                };

                {
                    let mut ledger = ledger_arc.write().unwrap();
                    if let Err(e) = ledger.append_operation_with_block(
                        operation,
                        deposits_core::messages::consts::TRANSFER_FAIL,
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
    pub async fn auto_credit_received_payments(&self) {
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

                let sig_hex = result_obj.get("cosign_signature_hex").and_then(|v| v.as_str());
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
                                cosign_signature: sig,
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
                    tracing::warn!("Co-sign response missing cosign_signature_hex or member_ledger_hash_hex");
                }
            } else {
                tracing::warn!("Co-sign response has no result");
            }
            // tx dropped, receiver gets error
        }
        // Non-cosign responses are not handled here - they'll be processed later by handle_ledger_response
    }

    /// Handle a ledger response (for auto-recording attestations and co-sign responses)
    async fn handle_ledger_response(&self, response: crate::nostr::LedgerResponse) {
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

                    // Extract cosign_signature_hex
                    let sig_hex = result_obj.get("cosign_signature_hex").and_then(|v| v.as_str());
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
                                    cosign_signature: sig,
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
                    tracing::warn!("Co-sign response missing valid cosign_signature_hex or member_ledger_hash_hex");
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
    /// over (cosign_data || member_ledger_hash).
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
    /// A CoSignResult containing the co-signer's signature and the member's ledger hash
    pub async fn request_cosign(
        &self,
        ledger_id: &str,
        update: &deposits_core::SignedLedgerUpdate,
    ) -> Result<CoSignResult, Error> {
        use tokio::time::Duration;

        // Acquire semaphore to serialize cosign requests. Multiple concurrent
        // mini loops compete for shared channels and cause distributed deadlocks
        // when all operators are in batch-await simultaneously.
        let _permit = self.cosign_semaphore.acquire().await
            .map_err(|_| Error::Protocol("Cosign semaphore closed".to_string()))?;

        // Compute cosign data
        let cosign_data = update.cosign_data();

        // Create request parameters - responders auto-detect their bound ledger
        let mut params = serde_json::json!({
            "sequence_number": update.sequence_number,
            "cosign_data_hex": hex::encode(&cosign_data),
            "current_hash_hex": hex::encode(update.current_hash),
            "message_type": update.message_type,
        });

        // Piggyback previous updates so quorum members can apply them inline
        // before the freshness check — eliminates "stale by N" failures under
        // load where Nostr latency causes members to fall behind.  Each update
        // is ~200-500 bytes base64, so 100 × 400 ≈ 40 KB — well within the
        // relay's 131 KB max websocket payload.
        {
            use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
            use deposits_core::TlvEncode;

            const MAX_PIGGYBACK: usize = 20;

            let ledgers = self.handler.ledgers.lock().unwrap();
            if let Some(arc) = ledgers.get(ledger_id) {
                let ledger = arc.read().unwrap();
                let len = ledger.history.len();
                // history[len-1] is the new update; we piggyback the N entries before it
                if len >= 2 {
                    let num = (len - 1).min(MAX_PIGGYBACK);
                    let prev_updates: Vec<String> = ledger.history[len - 1 - num..len - 1]
                        .iter()
                        .map(|u| BASE64.encode(&u.tlv_encode()))
                        .collect();
                    params["previous_updates"] = serde_json::json!(prev_updates);
                }
            }
        }

        // Create oneshot channel for response (first responder wins)
        let (tx, rx) = tokio::sync::oneshot::channel();

        // Send the multicast request to the ledger
        let request_id = self.nostr.send_ledger_request(ledger_id, "cosign_update", params)
            .await
            .map_err(|e| Error::Protocol(format!("Failed to send co_sign request: {:?}", e)))?;
        self.track_sent_event(&request_id);

        // Store in pending requests — the main run loop's handle_ledger_response()
        // will route the cosign response to this oneshot when it arrives.
        {
            let mut pending = self.pending_cosign_requests.lock().unwrap();
            pending.insert(request_id.clone(), (ledger_id.to_string(), tx));
            metrics::set_pending_cosign_requests(pending.len());
        }

        let cosign_send_time = std::time::Instant::now();
        tracing::info!(
            "Sent multicast co_sign request {} for seq={} (waiting for first responder)",
            &request_id[..16.min(request_id.len())],
            update.sequence_number,
        );

        // Wait for response via oneshot channel with timeout.
        //
        // The main run loop pumps process_events() and routes responses via
        // drain_responses → handle_ledger_response → pending_cosign_requests oneshot.
        // Since request_cosign always runs in a spawned task (per-ledger worker or
        // spawned periodic task), the main loop is free to pump events concurrently.
        // No polling or response draining needed here — just await the oneshot.
        let deadline = Duration::from_millis(500);

        tokio::select! {
            result = rx => {
                let cosign_rtt = cosign_send_time.elapsed();
                match result {
                    Ok(cosign_result) => {
                        tracing::info!("[PROFILE] cosign_rtt={:.1}ms for seq={} member_hash={}...",
                            cosign_rtt.as_secs_f64() * 1000.0,
                            update.sequence_number,
                            &hex::encode(&cosign_result.member_ledger_hash[..4]));
                        return Ok(cosign_result);
                    }
                    Err(_) => {
                        return Err(Error::Protocol(
                            "Co-sign response channel dropped".to_string()
                        ));
                    }
                }
            }
            _ = tokio::time::sleep(deadline) => {
                let mut pending = self.pending_cosign_requests.lock().unwrap();
                pending.remove(&request_id);
                metrics::set_pending_cosign_requests(pending.len());
                return Err(Error::Protocol("Co-sign request timed out after 500ms".to_string()));
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
        &self,
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
                    // Inline extraction: intercept cosign_offer requests from the
                    // notification stream directly, never putting them in request_rx.
                    let our_x_only = hex::encode(&self.node_id.serialize()[1..]);
                    let mut inline_offer_requests: Vec<crate::nostr::LedgerRequest> = Vec::new();

                    match notif {
                        Ok(notification) => {
                            if let Some(req) = self.nostr.dispatch_or_extract_request(notification, "cosign_offer") {
                                inline_offer_requests.push(req);
                            }
                            loop {
                                match notification_rx.try_recv() {
                                    Ok(n) => {
                                        if let Some(req) = self.nostr.dispatch_or_extract_request(n, "cosign_offer") {
                                            inline_offer_requests.push(req);
                                        }
                                    }
                                    Err(tokio::sync::broadcast::error::TryRecvError::Lagged(n)) => {
                                        tracing::warn!("Offer cosign mini loop notification receiver lagged by {} events", n);
                                    }
                                    Err(_) => break,
                                }
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                            tracing::warn!("Offer cosign mini loop notification receiver lagged by {} events", n);
                            loop {
                                match notification_rx.try_recv() {
                                    Ok(n) => {
                                        if let Some(req) = self.nostr.dispatch_or_extract_request(n, "cosign_offer") {
                                            inline_offer_requests.push(req);
                                        }
                                    }
                                    Err(tokio::sync::broadcast::error::TryRecvError::Lagged(_)) => {}
                                    Err(_) => break,
                                }
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

                    // Process cosign_offer requests extracted inline from notifications.
                    for request in inline_offer_requests {
                        if request.sender != our_x_only {
                            if self.is_quorum_member_of_ledger(&request.ledger_id) {
                                // Mark as processed to prevent polling fallback from re-processing
                                self.processed_requests.lock().unwrap().insert(request.event_id.clone());
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
        self.sent_events.lock().unwrap().insert(event_id.to_string());
    }

    /// Check if this ledger has had a reserves rotation to quorum-based Taproot.
    ///
    /// After the first QuorumBegin operation, co-signatures are required for all updates.
    /// This persists through disputes and custody transfers — the quorum co-signing
    /// requirement is permanent once rotation occurs.
    fn has_quorum_reserves(&self, ledger_id: &str) -> bool {
        use deposits_core::messages::consts;

        // Fast path: check cache
        let current_len = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(ledger_id) {
                ledger_arc.read().unwrap().history.len()
            } else {
                return false;
            }
        };
        {
            let cache = self.quorum_reserves_cache.lock().unwrap();
            if let Some(&(cached_result, cached_len)) = cache.get(ledger_id) {
                // True is permanent (QuorumBegin never reverts)
                if cached_result {
                    return true;
                }
                // False is valid until history grows (or is truncated)
                if cached_len == current_len || cached_len > current_len {
                    return false;
                }
            }
        }

        // Cache miss or stale false: scan history
        let result = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(ledger_id) {
                let ledger = ledger_arc.read().unwrap();
                ledger.history.iter().any(|u| u.message_type == consts::QUORUM_BEGIN)
            } else {
                false
            }
        };

        self.quorum_reserves_cache.lock().unwrap()
            .insert(ledger_id.to_string(), (result, current_len));
        result
    }

    /// Check if adding `additional_msats` to a ledger's obligations would exceed
    /// either the reserves limit or 2x the smallest quorum member's collateral commitment.
    ///
    /// Returns None if OK, or Some(error_message) if either limit would be exceeded.
    fn check_collateral_obligation_limit(&self, ledger_id: &str, additional_msats: u64) -> Option<String> {
        let ledgers = self.handler.ledgers.lock().unwrap();
        let ledger_arc = match ledgers.get(ledger_id) {
            Some(l) => l.clone(),
            None => return None,
        };
        let ledger = ledger_arc.read().unwrap();

        let current_obligations: u64 = ledger.state.deposits.values()
            .map(|d| d.balance + d.locked_balance)
            .sum();
        let new_total = current_obligations.saturating_add(additional_msats);

        // Check reserves limit: obligations (msats) <= reserves (msats)
        let reserves_limit_msats = ledger.state.reserves.amount;
        if reserves_limit_msats > 0 && new_total > reserves_limit_msats {
            return Some(format!(
                "Would exceed reserves: {} + {} = {} msats > {} msats (reserves {} msats)",
                current_obligations, additional_msats, new_total,
                reserves_limit_msats, ledger.state.reserves.amount
            ));
        }

        // Check collateral limit: obligations <= 2 * min(member.collateral_lock_amount)
        let min_collateral = ledger.state.quorum_members.iter()
            .filter_map(|m| m.collateral_lock_amount)
            .min();

        if let Some(min_c) = min_collateral {
            let collateral_limit = min_c.saturating_mul(2);
            if new_total > collateral_limit {
                return Some(format!(
                    "Would exceed collateral limit: {} + {} = {} msats > {} msats (2x smallest member collateral {})",
                    current_obligations, additional_msats, new_total, collateral_limit, min_c
                ));
            }
        }

        None
    }

    /// Build canonical signing data for invoice co-signatures.
    ///
    /// The signing data format is:
    /// `ledger_id || payment_hash || deposit_id || amount_msat`
    ///
    /// This data is then hashed using BIP-340 tagged hashing with tag "deposits/invoice_cosign"
    /// and combined with the member's ledger hash before signing.
    fn build_invoice_signing_data(
        ledger_id: &str,
        payment_hash: &[u8; 32],
        deposit_id: &[u8; 16],
        amount_msat: u64,
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(ledger_id.as_bytes());
        data.extend_from_slice(payment_hash);
        data.extend_from_slice(deposit_id);
        data.extend_from_slice(&amount_msat.to_le_bytes());
        data
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
    /// 2. Operator signs (content + cosign_signature) with Schnorr
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
    pub async fn sign_and_broadcast(&self, ledger_id: &str) -> Result<String, Error> {
        let sab_start = std::time::Instant::now();

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
                metrics::record_sign_and_broadcast("error_no_quorum", sab_start.elapsed());
                return Err(Error::Protocol(
                    "Reserves have been rotated but no quorum members available - cannot sign".to_string()
                ));
            }
            tracing::debug!("No quorum members yet, using operator-only signature");
            let result = self.operator_sign_persist_broadcast(ledger_id).await;
            metrics::record_sign_and_broadcast("success_no_cosign", sab_start.elapsed());
            return result;
        }

        // Before reserves rotation, co-signatures are optional — skip the cosign
        // round-trip entirely to avoid blocking the event loop (each attempt holds
        // the run loop for 500ms, causing cascading timeouts under load).
        if !quorum_reserves {
            tracing::debug!("Pre-rotation: skipping optional co-sign, using operator-only signature");
            let result = self.operator_sign_persist_broadcast(ledger_id).await;
            metrics::record_sign_and_broadcast("success_skip_cosign", sab_start.elapsed());
            return result;
        }

        // Send multicast co-sign request - first responder wins
        // Retry up to 3 times since responses can be missed during polling gaps
        let max_attempts = 3;
        let mut last_error = None;
        let cosign_start = std::time::Instant::now();

        for attempt in 1..=max_attempts {
            let attempt_start = std::time::Instant::now();
            match self.request_cosign(ledger_id, &update_clone).await {
                Ok(result) => {
                    let label = format!("success_attempt_{}", attempt);
                    metrics::record_cosign_attempt(&label, attempt_start.elapsed());
                    // Apply co-signer info and recompute hash for causal ordering,
                    // then apply co-signer's signature
                    let ledgers = self.handler.ledgers.lock().unwrap();
                    let ledger_arc = ledgers
                        .get(ledger_id)
                        .ok_or_else(|| Error::Protocol("Ledger not found".to_string()))?;
                    let mut ledger = ledger_arc.write().unwrap();

                    // Apply cosigner data + co-signer's signature, recompute current_hash
                    ledger.apply_cosigner_hash(
                        result.member_ledger_hash,
                        result.cosigner_pubkey,
                        result.cosign_signature,
                    );

                    tracing::info!("Applied co-sign from {}... (member_hash: {}..., new chain_hash: {}...)",
                        &pubkey_hex(&result.cosigner_pubkey)[..8],
                        &hex::encode(&result.member_ledger_hash[..4]),
                        &hex::encode(&ledger.state.hash[..4]));
                    last_error = None;
                    break;
                }
                Err(e) => {
                    let label = format!("timeout_attempt_{}", attempt);
                    metrics::record_cosign_attempt(&label, attempt_start.elapsed());
                    tracing::warn!("Co-sign attempt {}/{} failed: {}", attempt, max_attempts, e);
                    last_error = Some(e);
                    if attempt < max_attempts {
                        // Brief delay before retry — keep short since success latency
                        // is 5-9ms; if the update hasn't arrived by now, a longer wait
                        // just blocks the run loop (which prevents processing OTHER
                        // operators' cosign requests, causing cascading timeouts).
                        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
                    }
                }
            }
        }

        metrics::record_cosign_duration(cosign_start.elapsed());

        if let Some(e) = last_error {
            if quorum_reserves {
                // After rotation, co-signatures are required - fail instead of falling back
                metrics::record_sign_and_broadcast("timeout", sab_start.elapsed());
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

        metrics::record_sign_and_broadcast("success", sab_start.elapsed());
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
        &self,
        ledger_id: &str,
        quorum_member: PublicKey,
        member_ledger_id: &str,
        signature: [u8; 64],
        min_fee_bps: Option<u16>,
        min_fee_fixed: Option<u64>,
        max_fee_period: Option<u32>,
        collateral_lock_amount: Option<u64>,
        collateral_lock_until: Option<u32>,
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
                min_fee_bps,
                min_fee_fixed,
                max_fee_period,
                collateral_lock_amount,
                collateral_lock_until,
            };

            ledger.append_operation_with_block(
                operation,
                deposits_core::messages::consts::QUORUM_ADD_MEMBER,
                block_height,
                block_hash,
            ).map_err(|e| Error::Protocol(format!("Failed to add quorum member: {:?}", e)))?;
        }

        // Now sign and broadcast.
        // Before reserves rotation, co-signatures are optional (the fallback is
        // operator-only anyway) and attempting cosign blocks the run loop for up
        // to 36 seconds per attempt — which cascades when multiple operators are
        // adding members simultaneously.  Skip cosign entirely pre-rotation.
        if has_quorum && self.has_quorum_reserves(ledger_id) {
            self.sign_and_broadcast(ledger_id).await
        } else {
            if has_quorum {
                tracing::debug!("Pre-rotation: skipping cosign for QuorumAddMember");
            }
            self.operator_sign_persist_broadcast(ledger_id).await
        }
    }

    /// Record a quorum join with co-signing and broadcast.
    ///
    /// This is the async version that handles the full co-signing flow.
    pub async fn record_quorum_join(
        &self,
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

        // Sign and broadcast — skip cosign pre-rotation (same reasoning as
        // add_quorum_member: avoids 36s blocking when all daemons are busy)
        if has_quorum && self.has_quorum_reserves(our_ledger_id) {
            self.sign_and_broadcast(our_ledger_id).await
        } else {
            if has_quorum {
                tracing::debug!("Pre-rotation: skipping cosign for QuorumJoin");
            }
            self.operator_sign_persist_broadcast(our_ledger_id).await
        }
    }

    /// Lock collateral with co-signing and broadcast.
    ///
    /// This is the async version that handles the full co-signing flow.
    /// Takes a descriptor string (e.g., "pk(02abc...)" for single-key deposits).
    /// Returns the attestation after successfully broadcasting.
    pub async fn lock_collateral(
        &self,
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
                let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, deposit_secret);
                let signature = secp.sign_schnorr_no_aux_rand(&msg, &keypair);
                let lock_signature: [u8; 64] = signature.serialize();

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

            let secp = &self.secp;
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
        &self,
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
        &self,
        ledger_id: &str,
        descriptor: &str,
        fees: Option<FeeStructure>,
        transfer_fees: Option<deposits_core::TransferFeeSchedule>,
        is_collateral: bool,
        receive_requires_sig: bool,
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
                is_collateral,
                receive_requires_sig,
                fee_change_after_blocks: None,
                fee_change_notice_blocks: None,
                fee_change_limit_bps: None,
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
        &self,
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
        &self,
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
        &self,
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
        &self,
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
        &self,
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
        &self,
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
        &self,
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

    /// Get the data directory path.
    pub fn data_dir(&self) -> &std::path::Path {
        &self.data_dir
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
        // Find an unused reserves output (not already backing a ledger)
        let all_reserves = self.wallet.get_reserves();
        if all_reserves.is_empty() {
            return Err(Error::NoReserves);
        }

        // Addresses of reserves already backing ledgers.
        // Each reserves has a unique P2WSH address (ensured by timeout_height offset
        // in create_reserves_output), so address-based matching is correct.
        let used_addresses: std::collections::HashSet<String> = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            ledgers.values().map(|l| l.read().unwrap().state.reserves_key.clone()).collect()
        };

        let unused = all_reserves.iter().find(|r| {
            let addr = bitcoin::Address::p2wsh(&r.redeem_script, self.wallet.network()).to_string();
            !used_addresses.contains(&addr)
        }).ok_or_else(|| {
            Error::Protocol(format!(
                "All {} reserves are already backing ledgers ({} used addresses)",
                all_reserves.len(), used_addresses.len()
            ))
        })?;

        let reserves_balance = unused.amount;
        let reserves_outpoint = Some(unused.outpoint);
        let ledger_address = bitcoin::Address::p2wsh(&unused.redeem_script, self.wallet.network()).to_string();

        if reserves_balance == 0 {
            return Err(Error::NoReserves);
        }

        // Get funding txid and vout from reserves outpoint
        let (funding_txid, funding_vout) = if let Some(outpoint) = reserves_outpoint {
            (outpoint.txid.to_byte_array(), outpoint.vout as u16)
        } else {
            ([0u8; 32], 0u16)
        };

        // Create the ledger state
        let enforcement = if enforcement_block > 0 {
            Some(enforcement_block)
        } else {
            None
        };

        // For BDK, use the ledger_address as the reserves_id (identifies the reserves UTXO)
        let reserves_id = ledger_address.clone();

        // Get or create the ledger - this automatically adds LedgerOpen (with reserves_amount)
        // if it's a new ledger for our own operator
        // Convert reserves_balance from sats to msats at the on-chain boundary
        let reserves_balance_msats = reserves_balance.saturating_mul(1000);
        let ledger_arc = self.handler.get_or_create_ledger_with_outpoint(
            self.node_id, reserves_id.clone(), Some(reserves_balance_msats), None,
        );

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

        // Append QuorumBegin operation to the ledger for audit trail
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
            let operation = LedgerOperation::QuorumBegin {
                reserves_id: result.address.to_string(),
                spending_txid: txid_bytes,
                new_outpoint_txid: txid_bytes, // Same tx creates the new output
                new_outpoint_vout: result.outpoint.vout,
                amount: result.amount.saturating_mul(1000), // sats to msats
                first_expiry_block: result.first_expiry_block,
                ledger_hash,
                quorum_members: quorum_members.clone(),
            };

            let mut ledger = ledger_arc.write().unwrap();
            ledger.append_operation_with_block(
                operation,
                deposits_core::messages::consts::QUORUM_BEGIN,
                block_height,
                block_hash,
            ).map_err(|e| Error::Protocol(format!("Failed to record reserves rotation: {:?}", e)))?;

            tracing::info!(
                "Appended QuorumBegin operation to ledger: txid={}, quorum={} members",
                txid,
                quorum_members.len()
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

    /// Fetch BTC/USD price and publish as a Nostr price oracle event.
    async fn publish_price_oracle(&self) {
        // Fetch from mempool.space (or esplora — operator has its own)
        let url = "https://mempool.space/api/v1/prices";
        let price = match reqwest::get(url).await {
            Ok(resp) => match resp.json::<serde_json::Value>().await {
                Ok(data) => data.get("USD").and_then(|v| v.as_f64()).unwrap_or(0.0),
                Err(_) => return,
            },
            Err(_) => return,
        };
        if price <= 0.0 { return; }
        if let Err(e) = self.nostr.publish_price(price).await {
            tracing::debug!("Failed to publish price: {}", e);
        }
    }

    /// Load deposit allowlist from {data_dir}/deposit_allowlist.txt.
    /// Returns empty set if file doesn't exist (all deposits allowed).
    fn load_allowlist(data_dir: &std::path::Path) -> std::collections::HashSet<String> {
        let path = data_dir.join("deposit_allowlist.txt");
        match std::fs::read_to_string(&path) {
            Ok(content) => {
                let list: std::collections::HashSet<String> = content
                    .lines()
                    .map(|l| l.trim().to_lowercase())
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                    .collect();
                if !list.is_empty() {
                    tracing::info!("Deposit allowlist loaded: {} entries from {}", list.len(), path.display());
                }
                list
            }
            Err(_) => std::collections::HashSet::new(),
        }
    }

    /// Reload the deposit allowlist from disk (only updates if changed).
    pub fn reload_allowlist(&self) {
        let new_list = Self::load_allowlist(&self.data_dir);
        let current = self.deposit_allowlist.read().unwrap();
        if *current != new_list {
            let count = new_list.len();
            drop(current);
            *self.deposit_allowlist.write().unwrap() = new_list;
            tracing::info!("Deposit allowlist updated: {} entries", count);
        }
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
        &self,
        offer_id: &[u8; 32],
        funding_txid: String,
        funding_amount_sats: u64,
    ) -> Result<u64, Error> {
        use deposits_core::types::DepositOfferStatus;

        // Get the offer
        let (offer, status) = self.get_deposit_offer(offer_id)
            .ok_or(Error::OfferNotFound)?;

        // Only the ledger operator may complete deposits
        if !self.is_operator_of_ledger(&offer.ledger_id) {
            return Err(Error::Protocol(
                "Cannot complete deposit: not the operator of this ledger".to_string()
            ));
        }

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
        match self.open_deposit(&reserves_id, &offer.descriptor, offer.fees.clone(), offer.transfer_fees.clone(), false, false).await {
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

    /// Check if a ledger exists by ledger_id (no clone).
    fn has_ledger(&self, ledger_id: &str) -> bool {
        self.handler.ledgers.lock().unwrap().contains_key(ledger_id)
    }

    /// Check if a ledger exists by reserves_key (no clone).
    fn has_ledger_by_reserves_key(&self, reserves_key: &str) -> bool {
        let ledgers = self.handler.ledgers.lock().unwrap();
        ledgers.values().any(|arc| arc.read().unwrap().reserves_key() == reserves_key)
    }

    /// Check if we are the operator of the given ledger.
    ///
    /// Returns true when either:
    /// - The ledger's original operator_key matches our node_id, OR
    /// - A DisputeAcquire operation transferred custody to our node_id.
    ///
    /// Results are cached by (ledger_id, history_len). Once true, the cache
    /// entry is permanent. False entries use incremental scanning — only new
    /// history entries since the last check are scanned for DisputeAcquire.
    fn is_operator_of_ledger(&self, ledger_id: &str) -> bool {
        // Single lock: resolve canonical_id + get Arc clone
        let (canonical_id, arc) = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            if let Some(arc) = ledgers.get(ledger_id) {
                (ledger_id.to_string(), arc.clone())
            } else {
                // Try reserves_key lookup
                match ledgers.iter().find(|(_, a)| a.read().unwrap().reserves_key() == ledger_id) {
                    Some((lid, arc)) => (lid.clone(), arc.clone()),
                    None => return false,
                }
            }
        };

        let ledger = arc.read().unwrap();
        let history_len = ledger.history.len();

        // Check cache — determine if we can return early or need incremental scan
        let scan_from = {
            let cache = self.operator_of_cache.lock().unwrap();
            if let Some(&(result, cached_len)) = cache.get(&canonical_id) {
                if result {
                    return true; // Permanent: we are the operator
                }
                if cached_len == history_len {
                    return false; // No new entries since last check
                }
                // Stale false — only scan new entries [cached_len..]
                // Cap at history_len in case history was truncated
                cached_len.min(history_len)
            } else {
                0 // First check — full scan needed
            }
        };

        // Compute result: full check on first call, incremental on subsequent
        let result = if scan_from == 0 {
            // First check: test operator_key, then scan entire history
            if ledger.operator_key() == self.node_id {
                true
            } else {
                ledger.history.iter().rev().any(|u| {
                    u.message_type == 55
                        && deposits_core::messages::LedgerOperation::tlv_decode(&u.message)
                            .map(|op| matches!(op, deposits_core::messages::LedgerOperation::DisputeAcquire { new_custodian, .. } if new_custodian == self.node_id))
                            .unwrap_or(false)
                })
            }
        } else {
            // Incremental: only scan entries [scan_from..] for DisputeAcquire
            ledger.history[scan_from..].iter().rev().any(|u| {
                u.message_type == 55
                    && deposits_core::messages::LedgerOperation::tlv_decode(&u.message)
                        .map(|op| matches!(op, deposits_core::messages::LedgerOperation::DisputeAcquire { new_custodian, .. } if new_custodian == self.node_id))
                        .unwrap_or(false)
            })
        };

        drop(ledger);

        // Store in cache
        self.operator_of_cache.lock().unwrap().insert(canonical_id, (result, history_len));
        result
    }
}
