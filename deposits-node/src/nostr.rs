// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Nostr transport for peer-to-peer messaging
//!
//! Uses Nostr encrypted direct messages (NIP-04) to send deposits protocol
//! messages between peers, and public events for ledger updates.
//!
//! # Ledger Addressing
//!
//! All ledger-related events are addressed by **ledger_id** (a 64-char hex hash),
//! NOT by operator pubkey. This allows custody to transfer between operators
//! while maintaining the same ledger identity.
//!
//! # Custom Kinds
//!
//! - **Kind 9100**: Ledger updates (regular event, not replaceable)
//!   - Tag `d`: ledger_id (64-char hex hash)
//!   - Tag `seq`: sequence number
//!   - Tag `prev`: previous hash (hex)
//!   - Tag `hash`: current hash (hex)
//!   - Content: base64-encoded TLV wire format of SignedLedgerUpdate
//!
//! - **Kind 20101** (ephemeral): Ledger requests (transfer_lock, cosign_update, balance_query, etc.)
//!   - Tag `l`: ledger_id (64-char hex hash)
//!   - Tag `action`: action name (e.g., "transfer_lock")
//!   - Content: JSON with action parameters
//!   - Ephemeral: relays auto-delete after short TTL
//!
//! - **Kind 20102** (ephemeral): Ledger responses (replies to requests)
//!   - Tag `e`: reference to request event ID
//!   - Tag `l`: ledger_id
//!   - Tag `status`: "ok" or "error"
//!   - Content: JSON with result or error message
//!   - Ephemeral: relays auto-delete after short TTL
//!
//! - **Kind 9103**: Ledger disputes (invalid ledger detected)
//!   - Tag `d`: ledger_id
//!   - Tag `reason`: dispute reason (e.g., "hash_chain_broken")
//!   - Tag `disputer`: disputer's pubkey (hex)
//!   - Content: JSON with LedgerDispute details

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use bitcoin::secp256k1::{PublicKey, SecretKey};
use deposits_core::messages::DepositsMessage;
use deposits_core::types::SignedLedgerUpdate;
use deposits_core::{TlvDecode, TlvEncode};
use nostr_sdk::prelude::*;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use tokio::sync::mpsc;

use crate::Error;
use crate::metrics;

/// A received fraud proof broadcast from a wallet.
#[derive(Clone, Debug)]
pub struct FraudProofEvent {
    /// The fraud broadcast (proof + embedding + causal chain).
    pub broadcast: deposits_core::fraud::FraudBroadcast,
    /// The Nostr event ID.
    pub event_id: String,
    /// Sender pubkey.
    pub sender: String,
}

/// Track last advertisement timestamp to ensure monotonic ordering.
/// NIP-33 replaceable events use created_at to determine which event is "latest".
static LAST_AD_TIMESTAMP: AtomicU64 = AtomicU64::new(0);

/// Custom Kind for ledger updates.
/// Uses range 1000-9999 (regular custom events) to ensure relay storage.
/// Each update is a separate event that relays should retain.
pub const KIND_LEDGER_UPDATE: u16 = 9100;

/// Custom Kind for ledger requests (transfer_lock, cosign_update, balance_query, etc.)
/// Uses ephemeral range 20000-29999 so relays auto-delete after a short TTL.
/// These are transient peer-to-peer messages, not durable records.
pub const KIND_LEDGER_REQUEST: u16 = 20101;

/// Custom Kind for ledger responses (replies to requests)
/// Uses ephemeral range 20000-29999 so relays auto-delete after a short TTL.
pub const KIND_LEDGER_RESPONSE: u16 = 20102;

/// Custom Kind for ledger disputes (invalid ledger detected)
/// Uses range 1000-9999 (regular custom events) for relay storage.
/// Published when a quorum member detects a non-conforming ledger.
pub const KIND_LEDGER_DISPUTE: u16 = 9103;

/// Custom Kind for recovery agreement (quorum member agrees to recovery)
/// Uses range 1000-9999 (regular custom events) for relay storage.
/// Published in response to a dispute, signaling agreement to recover.
pub const KIND_RECOVERY_AGREE: u16 = 9104;

/// Custom Kind for ledger advertisement (operator terms)
/// Uses NIP-33 parameterized replaceable events (30000-39999).
/// Tag `d` = ledger_id ensures only latest ad per ledger is kept.
/// Content: JSON with fees, limits, and metadata.
pub const KIND_LEDGER_ADVERTISE: u16 = 39100;

/// Custom Kind for agent service advertisement (HTLC routing, etc.)
/// Uses NIP-33 parameterized replaceable events (30000-39999).
/// Tag `d` = agent_pubkey ensures only latest ad per agent is kept.
/// Content: JSON with per-ledger directional fees and balances.
pub const KIND_AGENT_ADVERTISE: u16 = 39102;

/// Custom Kind for fraud proof broadcasts (wallet evidence of operator dishonesty)
/// Uses range 1000-9999 (regular custom events) for relay storage.
/// Published by wallets with evidence embedded in the causal chain.
pub const KIND_FRAUD_PROOF: u16 = 9101;

/// Custom Kind for price oracle (BTC/USD rate published by operators)
/// Uses NIP-33 parameterized replaceable events (30000-39999).
/// Tag `d` = "btcusd" ensures only the latest price per operator is kept.
/// Content: JSON with price, currency, and timestamp.
pub const KIND_PRICE_ORACLE: u16 = 39101;

/// Semantic Nostr tag constants (single-letter, relay-filterable per NIP-01).
/// `d` — NIP-01 identifier tag. Used as ledger ID on durable events.
pub const TAG_LEDGER_ID: SingleLetterTag = SingleLetterTag::lowercase(Alphabet::D);
/// `l` — ledger ID on ephemeral request/response events.
pub const TAG_LEDGER_REQ: SingleLetterTag = SingleLetterTag::lowercase(Alphabet::L);
/// `n` — sequence number within a ledger's hash chain.
pub const TAG_SEQUENCE: SingleLetterTag = SingleLetterTag::lowercase(Alphabet::N);
/// `t` — operation type discriminant (numeric).
pub const TAG_OP_TYPE: SingleLetterTag = SingleLetterTag::lowercase(Alphabet::T);
/// `i` — affected deposit ID(s).
pub const TAG_DEPOSIT_ID: SingleLetterTag = SingleLetterTag::lowercase(Alphabet::I);
/// `e` — NIP-01 event reference (e.g. dispute event being agreed to).
pub const TAG_EVENT_REF: SingleLetterTag = SingleLetterTag::lowercase(Alphabet::E);
/// `p` — NIP-01 pubkey reference (e.g. target of a DM or ping).
pub const TAG_PUBKEY: SingleLetterTag = SingleLetterTag::lowercase(Alphabet::P);

/// Truncated ledger ID prefix length for Nostr tags (16 hex chars = 8 bytes).
/// Full ledger IDs are 64 hex chars; we truncate for compact tags while
/// maintaining collision resistance (2^64 possible values).
const LEDGER_TAG_LEN: usize = 16;

/// Truncate a ledger_id hex string to the prefix length used in Nostr tags.
pub fn ledger_tag(ledger_id: &str) -> &str {
    &ledger_id[..LEDGER_TAG_LEN.min(ledger_id.len())]
}

/// Default relay URLs for the network
/// Empty by default - relays should be explicitly configured
pub const DEFAULT_RELAYS: &[&str] = &[];

/// Nostr transport for deposits protocol messages
pub struct NostrTransport {
    /// The nostr client (fast relay only — used for subscriptions and publishing)
    client: Client,

    /// Primary relay URL — used for publishing. When set, events are only sent
    /// to this relay, not broadcast to all connected relays. This distributes
    /// write load when operators connect to multiple peer relays for reads.
    primary_relay_url: Option<RelayUrl>,

    /// Separate client connected to the slow (durable) relay, used only for
    /// gap-fill `fetch_events` calls. None if no slow relay is configured.
    slow_client: Option<Client>,

    /// Work queue for mirroring events to the durable relay in the background.
    /// Events are sent here and a background task drains them to slow_client.
    mirror_tx: Option<mpsc::UnboundedSender<Event>>,

    /// Our keypair for signing/decryption
    keys: Keys,

    /// Our secp256k1 pubkey (same as deposits node ID)
    our_pubkey: PublicKey,

    /// Pending inbound messages (encrypted DMs).
    /// Wrapped in Mutex so try_recv can take &self (enables per-ledger parallel dispatch).
    inbound_rx: std::sync::Mutex<mpsc::UnboundedReceiver<InboundMessage>>,

    /// Sender for inbound messages (used by subscription task)
    inbound_tx: mpsc::UnboundedSender<InboundMessage>,

    /// Pending inbound ledger updates (broadcasts).
    /// Wrapped in Mutex so try_recv can take &self.
    ledger_rx: std::sync::Mutex<mpsc::UnboundedReceiver<InboundLedgerUpdate>>,

    /// Sender for ledger updates
    ledger_tx: mpsc::UnboundedSender<InboundLedgerUpdate>,

    /// Pending inbound ledger requests.
    /// Wrapped in Mutex so try_recv can take &self.
    request_rx: std::sync::Mutex<mpsc::UnboundedReceiver<LedgerRequest>>,

    /// Sender for ledger requests
    request_tx: mpsc::UnboundedSender<LedgerRequest>,

    /// Pending inbound ledger responses.
    /// Wrapped in Mutex so try_recv can take &self.
    response_rx: std::sync::Mutex<mpsc::UnboundedReceiver<LedgerResponse>>,

    /// Sender for ledger responses
    response_tx: mpsc::UnboundedSender<LedgerResponse>,

    /// Pending inbound ledger disputes.
    /// Wrapped in Mutex so try_recv can take &self.
    dispute_rx: std::sync::Mutex<mpsc::UnboundedReceiver<LedgerDispute>>,

    /// Sender for ledger disputes
    dispute_tx: mpsc::UnboundedSender<LedgerDispute>,

    /// Pending inbound fraud proofs.
    fraud_proof_rx: std::sync::Mutex<mpsc::UnboundedReceiver<FraudProofEvent>>,

    /// Sender for fraud proofs
    fraud_proof_tx: mpsc::UnboundedSender<FraudProofEvent>,

    /// Peer pubkey mapping (secp256k1 -> nostr)
    peer_keys: RwLock<HashMap<PublicKey, nostr_sdk::PublicKey>>,

    /// Active subscriptions to prevent duplicates
    /// Key format: "type:id" e.g. "requests:abc123" or "disputes:abc123"
    active_subscriptions: RwLock<std::collections::HashSet<String>>,

    /// Ledger IDs to filter response subscriptions by (relay-side #l tag filtering).
    /// If non-empty, subscribe_to_response uses these to reduce relay fan-out.
    /// Set via set_response_ledger_filter() before calling subscribe_to_response().
    response_ledger_filter: RwLock<Vec<String>>,

    /// Ledger IDs to filter polling requests by (relay-side #l tag filtering).
    /// If non-empty, fetch_recent_requests uses per-ledger filters.
    /// Set via set_request_ledger_filter().
    request_ledger_filter: RwLock<Vec<String>>,

    /// Persistent notification receiver for the daemon run loop.
    /// Created once at start_listening() and reused by process_events()
    /// to avoid missing events between calls (broadcast::Receiver is
    /// per-instance — each notifications() call creates a new empty receiver).
    /// Wrapped in Mutex for &self access (take/put-back pattern, not held across await).
    daemon_notification_rx: std::sync::Mutex<Option<tokio::sync::broadcast::Receiver<RelayPoolNotification>>>,

    /// Two-generation dedup set for notification event IDs.
    /// Checked before any parsing to avoid expensive tag extraction / JSON decode
    /// on events we've already routed to channels. Uses event.id bytes (32 bytes)
    /// for O(1) lookup without string allocation.
    /// Wrapped in Mutex for &self access.
    seen_events: std::sync::Mutex<std::collections::HashSet<[u8; 32]>>,
    seen_events_prev: std::sync::Mutex<std::collections::HashSet<[u8; 32]>>,

    /// Set of ledger IDs we're interested in. Events for ledgers NOT in this set
    /// are dropped in handle_notification() before channel insertion.
    /// Empty = accept all (backwards-compatible default for CLI callers).
    interested_ledgers: RwLock<std::collections::HashSet<String>>,

    /// Local cache of our own ledger advertisements.
    /// Populated by publish_ledger_advertisement(), read by fetch_ledger_advertisement()
    /// to avoid unnecessary relay round-trips when processing deposit requests.
    ad_cache: RwLock<HashMap<String, LedgerAdvertisement>>,
}

/// An inbound message from a peer
#[derive(Debug, Clone)]
pub struct InboundMessage {
    /// The deposits protocol message
    pub message: DepositsMessage,

    /// Sender's secp256k1 public key
    pub sender: PublicKey,

    /// Timestamp
    pub timestamp: u64,
}

/// An inbound ledger update from a broadcast
#[derive(Debug, Clone)]
pub struct InboundLedgerUpdate {
    /// The signed ledger update
    pub update: SignedLedgerUpdate,

    /// Ledger identifier (64-char hex hash)
    pub ledger_id: String,

    /// Nostr event timestamp
    pub timestamp: u64,

    /// Nostr event ID for reference
    pub event_id: String,
}

/// A ledger request (e.g., deposit_open)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LedgerRequest {
    /// Action to perform
    pub action: String,

    /// Ledger identifier (64-char hex hash)
    pub ledger_id: String,

    /// Action-specific parameters as JSON
    pub params: serde_json::Value,

    /// Nostr event ID of this request
    #[serde(skip)]
    pub event_id: String,

    /// Sender's nostr pubkey (for responses)
    #[serde(skip)]
    pub sender: String,

    /// Timestamp
    #[serde(skip)]
    pub timestamp: u64,
}

/// A ledger response (reply to a request)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LedgerResponse {
    /// Was the request successful?
    pub success: bool,

    /// Result data (if successful)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,

    /// Error message (if failed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    /// Reference to the request event ID
    #[serde(skip)]
    pub request_id: String,

    /// Ledger identifier
    #[serde(skip)]
    pub ledger_id: String,

    /// Nostr event ID of this response
    #[serde(skip)]
    pub event_id: String,

    /// Timestamp
    #[serde(skip)]
    pub timestamp: u64,
}

/// A ledger dispute (invalid ledger detected)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LedgerDispute {
    /// The disputer's secp256k1 pubkey (who detected the violation)
    pub disputer_pubkey: String,

    /// Ledger identifier (64-char hex hash)
    pub ledger_id: String,

    /// Reason for dispute (e.g., "hash_chain_broken", "invalid_signature", "business_rule_violation")
    pub reason: String,

    /// Detailed error message
    pub details: String,

    /// The last valid hash before the violation (hex)
    pub last_valid_hash: String,

    /// The last valid sequence number before the violation
    pub last_valid_sequence: u64,

    /// The sequence number where the violation was detected (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub violation_sequence: Option<u64>,

    /// Schnorr signature over the dispute (hex) for verification
    pub signature: String,

    /// Nostr event ID of this dispute
    #[serde(skip)]
    pub event_id: String,

    /// Timestamp
    #[serde(skip)]
    pub timestamp: u64,
}

/// A recovery agreement (quorum member agrees to recover a ledger)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RecoveryAgreement {
    /// The agreeing member's secp256k1 pubkey
    pub member_pubkey: String,

    /// Ledger identifier (the ledger being recovered)
    pub ledger_id: String,

    /// Reference to the dispute event ID we're agreeing with
    pub dispute_event_id: String,

    /// Our independently verified last valid sequence
    pub last_valid_sequence: u64,

    /// Our independently verified last valid hash (hex)
    pub last_valid_hash: String,

    /// Schnorr signature over the agreement (hex)
    pub signature: String,

    /// Nostr event ID of this agreement
    #[serde(skip)]
    pub event_id: String,

    /// Timestamp
    #[serde(skip)]
    pub timestamp: u64,
}

/// Information about a quorum member in a ledger advertisement
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct QuorumMemberInfo {
    /// Member's public key (hex)
    pub pubkey: String,

    /// Amount of collateral locked by this member (sats)
    pub collateral_sats: u64,

    /// Block height when the collateral lock expires
    pub lock_expires_block: u64,
}

/// A ledger advertisement (operator terms and limits)
/// Published as a NIP-33 parameterized replaceable event.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LedgerAdvertisement {
    /// Ledger identifier (64-char hex hash)
    pub ledger_id: String,

    /// Operator's secp256k1 pubkey (hex)
    pub operator_pubkey: String,

    /// Current reserves address (for verification)
    pub reserves_address: String,

    /// Human-readable name for the operator/custodian
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operator_name: Option<String>,

    /// Description of the operator's service
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    // === Fee Structure (all in basis points, 100 bps = 1%) ===

    /// Annual custody fee (e.g., 50 = 0.5% per year)
    pub annual_fee_bps: u32,

    /// One-time fee on deposits (e.g., 10 = 0.1%)
    pub deposit_fee_bps: u32,

    /// Fee on withdrawals (e.g., 10 = 0.1%)
    pub withdrawal_fee_bps: u32,

    /// Fee per Lightning invoice payment (e.g., 5 = 0.05%)
    pub invoice_fee_bps: u32,

    /// Minimum fee per transaction in sats (floor)
    #[serde(default)]
    pub min_fee_sats: u64,

    /// Fee collection period in blocks
    #[serde(default)]
    pub fee_period_blocks: u32,

    /// Fixed per-transfer fee in msats
    #[serde(default)]
    pub transfer_fee_fixed_msats: u64,

    /// Proportional per-transfer fee in basis points
    #[serde(default)]
    pub transfer_fee_rate_bps: u16,

    // === Deposit Limits ===

    /// Maximum single deposit size in sats
    pub max_deposit_msats: u64,

    /// Minimum deposit size in sats
    pub min_deposit_msats: u64,

    /// Maximum total balance per depositor in sats (0 = unlimited)
    #[serde(default)]
    pub max_balance_msats: u64,

    // === Trust Info ===

    // === Capacity ===

    /// Current total obligations (deposit balances) in sats
    #[serde(default)]
    pub total_obligations_msats: u64,

    /// Available headroom for new deposits in sats
    /// Calculated as: reserves_amount - total_obligations (or fraction thereof)
    #[serde(default)]
    pub available_headroom_msats: u64,

    // === Trust Info ===

    /// Current total reserves backing the ledger (sats)
    pub reserves_amount_msats: u64,

    /// Total received collateral from quorum members (msats)
    #[serde(default)]
    pub received_collateral_msats: u64,

    /// Total collateral attestations attached to this ledger (msats)
    #[serde(default)]
    pub attested_collateral_msats: u64,

    /// Total collateral held by other operators on this ledger (msats)
    /// Subtract from reserves to get effective reserves backing customer deposits
    #[serde(default)]
    pub held_collateral_msats: u64,

    // === Connectivity ===

    /// Relay URL where this operator publishes responses
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_url: Option<String>,

    // === Metadata ===

    /// Network (bitcoin, testnet, signet, regtest)
    pub network: String,

    /// Version of the advertisement format
    #[serde(default = "default_version")]
    pub version: u8,

    /// Nostr event ID of this advertisement
    #[serde(skip)]
    pub event_id: String,

    /// Timestamp when published
    #[serde(skip)]
    pub timestamp: u64,
}

fn default_version() -> u8 { 1 }

/// Agent service advertisement (Kind 39102)
/// Published by HTLC routing agents with per-ledger directional fees.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AgentAdvertisement {
    /// Agent's Nostr pubkey (hex)
    pub agent_pubkey: String,

    /// Service type (e.g. "htlc_routing")
    pub service: String,

    /// Network (bitcoin, testnet, signet, regtest)
    pub network: String,

    /// Per-ledger deposit info with directional fees
    pub ledgers: Vec<AgentLedgerEntry>,

    /// Nostr event ID
    #[serde(skip)]
    pub event_id: String,

    /// Timestamp when published
    #[serde(skip)]
    pub timestamp: u64,
}

/// Per-ledger entry in an agent advertisement
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AgentLedgerEntry {
    pub ledger_id: String,
    pub deposit_id: String,
    #[serde(default)]
    pub balance_msats: u64,
    #[serde(default)]
    pub fee_in_fixed_msats: u64,
    #[serde(default)]
    pub fee_in_rate_bps: u64,
    #[serde(default)]
    pub fee_out_fixed_msats: u64,
    #[serde(default)]
    pub fee_out_rate_bps: u64,
}

impl LedgerAdvertisement {
    /// Create a new advertisement with required fields
    pub fn new(
        ledger_id: String,
        operator_pubkey: String,
        reserves_address: String,
        network: String,
    ) -> Self {
        Self {
            ledger_id,
            operator_pubkey,
            reserves_address,
            operator_name: None,
            description: None,
            annual_fee_bps: 0,
            deposit_fee_bps: 0,
            withdrawal_fee_bps: 0,
            invoice_fee_bps: 0,
            min_fee_sats: 0,
            fee_period_blocks: 0,
            transfer_fee_fixed_msats: 0,
            transfer_fee_rate_bps: 0,
            max_deposit_msats: u64::MAX,
            min_deposit_msats: 0,
            max_balance_msats: 0,
            total_obligations_msats: 0,
            available_headroom_msats: 0,
            reserves_amount_msats: 0,
            received_collateral_msats: 0,
            attested_collateral_msats: 0,
            held_collateral_msats: 0,
            relay_url: None,
            network,
            version: 1,
            event_id: String::new(),
            timestamp: 0,
        }
    }

    /// Convert advertisement fees to FeeStructure for new deposits.
    ///
    /// Uses the advertisement's annual_fee_bps, min_fee_sats, and fee_period_blocks.
    /// If fee_period_blocks is 0, returns a FeeStructure with frequency_blocks=0
    /// (caller should handle this case or provide a fallback).
    pub fn to_fee_structure(&self) -> deposits_core::types::FeeStructure {
        const BLOCKS_PER_YEAR: u64 = 52560;
        let frequency = self.fee_period_blocks;
        let periods_per_year = if frequency > 0 { BLOCKS_PER_YEAR / frequency as u64 } else { 0 };
        deposits_core::types::FeeStructure {
            annualized_msats: self.min_fee_sats.saturating_mul(periods_per_year),
            annualized_bps: self.annual_fee_bps as u16,
            frequency_blocks: frequency,
        }
    }

    /// Get minimum acceptable fee parameters for deposit validation.
    ///
    /// Returns (min_annual_bps, min_fixed_per_period) where:
    /// - min_annual_bps: minimum annual fee in basis points
    /// - min_fixed_per_period: minimum fixed fee per collection period in sats
    pub fn minimum_fees(&self) -> (u16, u64) {
        (self.annual_fee_bps as u16, self.min_fee_sats)
    }
}

impl NostrTransport {
    /// Create a new Nostr transport.
    ///
    /// `relays` — fast relay URLs (used for subscriptions + publishing).
    /// `slow_relays` — durable relay URLs (used only for gap-fill `fetch_events`).
    pub async fn new(secret_key: SecretKey, relays: Vec<String>) -> Result<Self, Error> {
        Self::new_with_slow(secret_key, relays, Vec::new(), false).await
    }

    /// Create a new Nostr transport with explicit slow relay(s).
    pub async fn new_with_slow(secret_key: SecretKey, relays: Vec<String>, slow_relays: Vec<String>, skip_nostr_verify: bool) -> Result<Self, Error> {
        // Convert secp256k1 key to nostr keys
        let secret_bytes = secret_key.secret_bytes();
        let nostr_secret = nostr_sdk::SecretKey::from_slice(&secret_bytes)
            .map_err(|e| Error::Nostr(format!("Invalid secret key: {}", e)))?;
        let keys = Keys::new(nostr_secret);

        // Get our secp256k1 pubkey
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let our_pubkey = PublicKey::from_secret_key(&secp, &secret_key);

        // Create main nostr client (fast relay only) with explicit connection options
        let opts = Options::default()
            .connection_timeout(Some(std::time::Duration::from_secs(30)))
            .notification_channel_size(65536);
        let client = Client::builder()
            .signer(keys.clone())
            .opts(opts)
            .build();

        // Add fast relays only to main client
        let relay_list: Vec<String> = if relays.is_empty() {
            DEFAULT_RELAYS.iter().map(|s| s.to_string()).collect()
        } else {
            relays
        };

        // If multiple relays, the first is "primary" (used for publishing only).
        // Other relays are for subscriptions/reads (e.g., peer operator relays).
        let primary_relay_url = if relay_list.len() > 1 {
            RelayUrl::parse(&relay_list[0]).ok()
        } else {
            None // single relay: publish to all (same thing)
        };

        let relay_opts = RelayOptions::default()
            .skip_event_verification(skip_nostr_verify);
        for relay in &relay_list {
            client
                .pool()
                .add_relay(relay, relay_opts.clone())
                .await
                .map_err(|e| Error::Nostr(format!("Failed to add relay {}: {}", relay, e)))?;
        }

        // Connect main client to relays with explicit timeout
        client.connect_with_timeout(std::time::Duration::from_secs(30)).await;

        // Wait for at least one relay to be connected (max 10 seconds)
        let max_wait = std::time::Duration::from_secs(10);
        let start = std::time::Instant::now();
        loop {
            let relays = client.relays().await;
            let connected = relays.values().any(|r| {
                r.status() == nostr_sdk::RelayStatus::Connected
            });
            if connected {
                break;
            }
            if start.elapsed() > max_wait {
                tracing::warn!("Timeout waiting for relay connection, proceeding anyway");
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        // Record connection metrics
        let relays = client.relays().await;
        let connected_count = relays.values()
            .filter(|r| r.status() == nostr_sdk::RelayStatus::Connected)
            .count();
        metrics::set_active_connections(connected_count);
        for _ in 0..connected_count {
            metrics::record_connection();
        }

        // Create separate slow client for gap-fill (if slow relays configured)
        let slow_client = if !slow_relays.is_empty() {
            let slow_opts = Options::default()
                .connection_timeout(Some(std::time::Duration::from_secs(30)));
            let sc = Client::builder()
                .signer(keys.clone())
                .opts(slow_opts)
                .build();
            for relay in &slow_relays {
                sc.add_relay(relay)
                    .await
                    .map_err(|e| Error::Nostr(format!("Failed to add slow relay {}: {}", relay, e)))?;
            }
            sc.connect_with_timeout(std::time::Duration::from_secs(30)).await;
            tracing::info!("Slow relay client connected: {:?}", slow_relays);
            Some(sc)
        } else {
            None
        };

        // Create channels for inbound messages, ledger updates, requests, responses, and disputes
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
        let (ledger_tx, ledger_rx) = mpsc::unbounded_channel();
        let (request_tx, request_rx) = mpsc::unbounded_channel();
        let (response_tx, response_rx) = mpsc::unbounded_channel();
        let (dispute_tx, dispute_rx) = mpsc::unbounded_channel();
        let (fraud_proof_tx, fraud_proof_rx) = mpsc::unbounded_channel();

        // Spawn background mirror task if we have a durable relay
        let mirror_tx = if let Some(ref sc) = slow_client {
            let (tx, mut rx) = mpsc::unbounded_channel::<Event>();
            let sc = sc.clone();
            tokio::spawn(async move {
                while let Some(event) = rx.recv().await {
                    let seq_tag = event.tags.iter()
                        .find(|t| t.as_slice().first().map(|s| s.as_str()) == Some("n"))
                        .and_then(|t| t.as_slice().get(1))
                        .map(|s| s.to_string())
                        .unwrap_or_default();
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        sc.send_event(event),
                    ).await {
                        Ok(Ok(_)) => tracing::debug!("Mirrored seq {} to durable relay", seq_tag),
                        Ok(Err(e)) => tracing::warn!("Mirror to durable relay failed: {}", e),
                        Err(_) => tracing::warn!("Mirror to durable relay timed out (seq {})", seq_tag),
                    }
                }
            });
            Some(tx)
        } else {
            None
        };

        Ok(Self {
            client,
            primary_relay_url,
            slow_client,
            mirror_tx,
            keys,
            our_pubkey,
            inbound_rx: std::sync::Mutex::new(inbound_rx),
            inbound_tx,
            ledger_rx: std::sync::Mutex::new(ledger_rx),
            ledger_tx,
            request_rx: std::sync::Mutex::new(request_rx),
            request_tx,
            response_rx: std::sync::Mutex::new(response_rx),
            response_tx,
            dispute_rx: std::sync::Mutex::new(dispute_rx),
            dispute_tx,
            fraud_proof_rx: std::sync::Mutex::new(fraud_proof_rx),
            fraud_proof_tx,
            peer_keys: RwLock::new(HashMap::new()),
            active_subscriptions: RwLock::new(std::collections::HashSet::new()),
            response_ledger_filter: RwLock::new(Vec::new()),
            request_ledger_filter: RwLock::new(Vec::new()),
            daemon_notification_rx: std::sync::Mutex::new(None),
            seen_events: std::sync::Mutex::new(std::collections::HashSet::new()),
            seen_events_prev: std::sync::Mutex::new(std::collections::HashSet::new()),
            interested_ledgers: RwLock::new(std::collections::HashSet::new()),
            ad_cache: RwLock::new(HashMap::new()),
        })
    }

    /// Get our secp256k1 public key (node ID)
    pub fn our_pubkey(&self) -> PublicKey {
        self.our_pubkey
    }

    /// Set ledger IDs for response subscription filtering.
    /// When set, subscribe_to_response will use relay-side #l tag filtering
    /// to only receive responses for these ledgers, reducing fan-out.
    pub fn set_response_ledger_filter(&self, ledger_ids: Vec<String>) {
        tracing::info!("Response filter set for {} ledgers", ledger_ids.len());
        *self.response_ledger_filter.write().unwrap() = ledger_ids;
    }

    /// Set ledger IDs for request polling filter.
    /// When set, fetch_recent_requests uses per-ledger #l tag filters.
    pub fn set_request_ledger_filter(&self, ledger_ids: Vec<String>) {
        let old_len = self.request_ledger_filter.read().unwrap().len();
        if ledger_ids.len() != old_len {
            tracing::info!("Request poll filter set for {} ledgers (was {})", ledger_ids.len(), old_len);
        }
        *self.request_ledger_filter.write().unwrap() = ledger_ids;
    }

    /// Clear the response subscription tracking flag so the next subscribe_to_response
    /// call will create a new subscription (e.g. with updated ledger filter).
    pub fn clear_response_subscription(&self) {
        self.active_subscriptions.write().unwrap().remove("responses:all");
    }

    /// Get a reference to the underlying Nostr client (fast relay)
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// Get the client to use for gap-fill `fetch_events` calls.
    /// Returns the slow (durable) relay client if configured, otherwise the main client.
    pub fn fetch_client(&self) -> &Client {
        self.slow_client.as_ref().unwrap_or(&self.client)
    }

    /// Add a single ledger ID to the interested set.
    /// Stores the truncated prefix to match against tag values.
    pub fn add_interested_ledger(&self, ledger_id: String) {
        self.interested_ledgers.write().unwrap().insert(ledger_tag(&ledger_id).to_string());
    }

    /// Remove a ledger ID from the interested set.
    pub fn remove_interested_ledger(&self, ledger_id: &str) {
        self.interested_ledgers.write().unwrap().remove(ledger_tag(ledger_id));
    }

    /// Set the ledger IDs we're interested in receiving events for.
    /// Events for other ledgers are dropped in handle_notification().
    /// Empty set = accept all (the default).
    /// Stores truncated prefixes to match against tag values.
    pub fn set_interested_ledgers(&self, ledger_ids: impl IntoIterator<Item = String>) {
        let new_set: std::collections::HashSet<String> = ledger_ids.into_iter()
            .map(|id| ledger_tag(&id).to_string())
            .collect();
        let count = new_set.len();
        *self.interested_ledgers.write().unwrap() = new_set;
        tracing::info!("Interested ledgers set: {} ledgers", count);
    }

    /// Subscribe with compacted global filters (3 kind-based filters instead of per-ledger).
    /// Replaces subscribe_to_ledgers_batch for the daemon. Per-ledger filtering happens
    /// in-process via interested_ledgers, not at the relay level.
    pub async fn subscribe_global(&self) -> Result<(), Error> {
        let sub_key = "global_compacted".to_string();
        {
            let subs = self.active_subscriptions.read().unwrap();
            if subs.contains(&sub_key) {
                return Ok(());
            }
        }

        let since = nostr_sdk::Timestamp::now() - 5;

        let filters = vec![
            // Requests (ephemeral kind 20101)
            Filter::new()
                .kind(Kind::Custom(KIND_LEDGER_REQUEST))
                .since(since),
            // Responses (ephemeral kind 20102)
            Filter::new()
                .kind(Kind::Custom(KIND_LEDGER_RESPONSE))
                .since(since),
            // Updates (durable kind 9100)
            Filter::new()
                .kind(Kind::Custom(KIND_LEDGER_UPDATE))
                .since(since),
            // Disputes (durable kind 9103)
            Filter::new()
                .kind(Kind::Custom(KIND_LEDGER_DISPUTE))
                .since(since),
            // Fraud proofs (durable kind 9101)
            Filter::new()
                .kind(Kind::Custom(KIND_FRAUD_PROOF))
                .since(since),
        ];

        self.client
            .subscribe(filters, None)
            .await
            .map_err(|e| Error::Nostr(format!("Failed to subscribe (global): {}", e)))?;

        self.active_subscriptions.write().unwrap().insert(sub_key);
        tracing::info!("Subscribed with 4 global compacted filters (requests, responses, updates, disputes)");
        Ok(())
    }

    /// Get our nostr keys for signing
    pub fn keys(&self) -> &Keys {
        &self.keys
    }

    /// Get our nostr public key
    pub fn nostr_pubkey(&self) -> nostr_sdk::PublicKey {
        self.keys.public_key()
    }

    /// Convert a secp256k1 pubkey to nostr pubkey
    fn secp_to_nostr(pubkey: &PublicKey) -> Result<nostr_sdk::PublicKey, Error> {
        // secp256k1 pubkeys are 33 bytes compressed, nostr uses x-only (32 bytes)
        let serialized = pubkey.serialize();
        // Skip the first byte (0x02 or 0x03 prefix) to get x-only
        let x_only = &serialized[1..];
        nostr_sdk::PublicKey::from_slice(x_only)
            .map_err(|e| Error::Nostr(format!("Invalid pubkey conversion: {}", e)))
    }

    /// Send an event without waiting for relay acknowledgment.
    ///
    /// This is a "fire and forget" method that returns immediately after sending
    /// the message to the relay, without waiting for the OK response. This reduces
    /// latency by ~150ms per event (one full round-trip).
    ///
    /// Use this for high-throughput operations where you don't need confirmation
    /// that the relay accepted the event.
    /// Maximum time to wait for any Nostr send operation before giving up.
    /// Prevents a stuck relay WebSocket from freezing the entire node.
    const SEND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

    async fn send_event_nowait(&self, event: Event) -> Result<(), Error> {
        let urls: Vec<RelayUrl> = if let Some(ref primary) = self.primary_relay_url {
            // Multi-relay mode: publish only to primary relay
            vec![primary.clone()]
        } else {
            // Single-relay mode: publish to all
            let relays = self.client.relays().await;
            if relays.is_empty() {
                return Err(Error::Nostr("No relays connected".to_string()));
            }
            relays.keys().cloned().collect()
        };

        // Send using batch_msg which doesn't wait for OK
        let publish_start = std::time::Instant::now();
        tokio::time::timeout(Self::SEND_TIMEOUT,
            self.client.send_msg_to(urls, ClientMessage::event(event))
        )
            .await
            .map_err(|_| Error::Nostr("send_event_nowait timed out".to_string()))?
            .map_err(|e| Error::Nostr(format!("Failed to send event: {}", e)))?;
        crate::metrics::record_nostr_publish(publish_start.elapsed());

        Ok(())
    }

    /// Send an event with a timeout to prevent relay hangs from freezing the node.
    async fn send_event_with_timeout(&self, event: Event) -> Result<(), Error> {
        let urls: Vec<RelayUrl> = if let Some(ref primary) = self.primary_relay_url {
            vec![primary.clone()]
        } else {
            let relays = self.client.relays().await;
            relays.keys().cloned().collect()
        };
        tokio::time::timeout(Self::SEND_TIMEOUT,
            self.client.send_msg_to(urls, ClientMessage::event(event))
        )
            .await
            .map_err(|_| Error::Nostr("send_event timed out (relay may be stuck)".to_string()))?
            .map_err(|e| Error::Nostr(format!("Failed to send event: {}", e)))?;
        Ok(())
    }


    /// Send a message to a peer via encrypted DM (NIP-04)
    pub async fn send_message(&self, peer: PublicKey, msg: DepositsMessage) -> Result<(), Error> {
        // Convert peer pubkey to nostr pubkey
        let nostr_peer = Self::secp_to_nostr(&peer)?;

        // Serialize the message
        let bytes = msg.encode();

        // Encode as hex for transport
        let plaintext = hex::encode(&bytes);

        // Encrypt using NIP-04
        let encrypted = nip04::encrypt(self.keys.secret_key(), &nostr_peer, &plaintext)
            .map_err(|e| Error::Nostr(format!("Encryption failed: {}", e)))?;

        // Build the event (kind 4 = encrypted DM)
        let event = EventBuilder::new(Kind::EncryptedDirectMessage, encrypted)
            .tag(Tag::public_key(nostr_peer))
            .sign_with_keys(&self.keys)
            .map_err(|e| Error::Nostr(format!("Failed to sign event: {}", e)))?;

        // Send
        self.send_event_with_timeout(event)
            .await
            .map_err(|e| Error::Nostr(format!("Failed to send message: {}", e)))?;

        tracing::debug!("Sent message to {}", peer);
        Ok(())
    }

    /// Broadcast a ledger update to the network.
    ///
    /// Creates a parameterized replaceable event (Kind 30100) that can be
    /// subscribed to by anyone interested in this ledger.
    pub async fn broadcast_ledger_update(&self, update: &SignedLedgerUpdate) -> Result<String, Error> {
        // Use the hashed ledger_id as the identifier
        let ledger_id = update.ledger_id_hex();

        // Encode update as TLV, then base64
        let tlv_bytes = update.tlv_encode();
        let content = BASE64.encode(&tlv_bytes);

        // Build the event with appropriate tags
        // - `d`: ledger ID prefix (16 hex chars, relay-filterable)
        // - `n`: sequence number (single-letter, relay-filterable)
        // - `t`: operation type discriminant (single-letter, relay-filterable)
        // - `i`: affected deposit IDs (single-letter, relay-filterable)
        // Hash chain data (prev_hash, current_hash) is in the TLV content.
        let mut builder = EventBuilder::new(Kind::Custom(KIND_LEDGER_UPDATE), &content)
            .tag(Tag::custom(
                TagKind::SingleLetter(TAG_LEDGER_ID),
                [ledger_tag(&ledger_id)],
            ))
            .tag(Tag::custom(
                TagKind::SingleLetter(TAG_SEQUENCE),
                [update.sequence_number.to_string()],
            ));

        // Tag operation type and affected deposit IDs for relay-side filtering
        if let Ok(op) = deposits_core::messages::LedgerOperation::tlv_decode(&update.message) {
            // Operation type tag (e.g. "QuorumAddMember", "TransferLock")
            builder = builder.tag(Tag::custom(
                TagKind::SingleLetter(TAG_OP_TYPE),
                [op.discriminant().to_string()],
            ));

            for dep_id in op.affected_deposit_ids() {
                builder = builder.tag(Tag::custom(
                    TagKind::SingleLetter(TAG_DEPOSIT_ID),
                    [hex::encode(dep_id)],
                ));
            }
        }

        let event = builder
            .sign_with_keys(&self.keys)
            .map_err(|e| Error::Nostr(format!("Failed to sign event: {}", e)))?;

        let event_id = event.id.to_hex();

        // Broadcast to primary (fast) relay
        self.send_event_with_timeout(event.clone())
            .await
            .map_err(|e| Error::Nostr(format!("Failed to broadcast ledger update: {}", e)))?;

        // Enqueue mirror to durable relay (processed by background task)
        if let Some(ref tx) = self.mirror_tx {
            let _ = tx.send(event);
        }

        tracing::debug!(
            "Broadcast ledger update: ledger={}, seq={}, hash={}",
            ledger_id,
            update.sequence_number,
            &hex::encode(update.current_hash)[..16]
        );

        Ok(event_id)
    }

    /// Subscribe to ledger updates for a specific ledger.
    ///
    /// The ledger_id is a 64-char hex hash that uniquely identifies the ledger.
    pub async fn subscribe_to_ledger(&self, ledger_id: &str) -> Result<(), Error> {
        // Check if already subscribed to this ledger
        let sub_key = format!("ledger:{}", ledger_id);
        {
            let subs = self.active_subscriptions.read().unwrap();
            if subs.contains(&sub_key) {
                tracing::debug!("Already subscribed to ledger {}", ledger_id);
                return Ok(());
            }
        }

        let filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_UPDATE))
            .custom_tag(
                TAG_LEDGER_ID,
                [ledger_tag(ledger_id)],
            );

        self.client
            .subscribe(vec![filter], None)
            .await
            .map_err(|e| Error::Nostr(format!("Failed to subscribe to ledger: {}", e)))?;

        // Mark as subscribed
        self.active_subscriptions.write().unwrap().insert(sub_key);

        tracing::debug!("Subscribed to ledger updates: {}", ledger_id);
        Ok(())
    }

    /// Subscribe to all ledger updates from a specific operator.
    ///
    /// Uses prefix matching on the `d` tag to find all ledgers from this operator.
    pub async fn subscribe_to_operator(&self, operator_pubkey: &PublicKey) -> Result<(), Error> {
        // Check if already subscribed to all updates (global subscription)
        let sub_key = "updates:all".to_string();
        {
            let subs = self.active_subscriptions.read().unwrap();
            if subs.contains(&sub_key) {
                tracing::debug!("Already subscribed to all ledger updates");
                return Ok(());
            }
        }

        // We can't do prefix matching in Nostr filters, so we subscribe to all
        // ledger update events and filter locally. For now, subscribe to all.
        let filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_UPDATE));

        self.client
            .subscribe(vec![filter], None)
            .await
            .map_err(|e| Error::Nostr(format!("Failed to subscribe to operator: {}", e)))?;

        // Mark as subscribed
        self.active_subscriptions.write().unwrap().insert(sub_key);

        tracing::debug!("Subscribed to ledger updates from operator: {}", operator_pubkey);
        Ok(())
    }

    /// Send a ledger request (e.g., deposit_open)
    ///
    /// Returns the event ID for tracking the response.
    pub async fn send_ledger_request(
        &self,
        ledger_id: &str,
        action: &str,
        params: serde_json::Value,
    ) -> Result<String, Error> {
        let content = serde_json::to_string(&params)
            .map_err(|e| Error::Serialization(format!("Failed to serialize params: {}", e)))?;

        let event = EventBuilder::new(Kind::Custom(KIND_LEDGER_REQUEST), &content)
            .tag(Tag::custom(
                TagKind::SingleLetter(TAG_LEDGER_REQ),
                [ledger_id],
            ))
            .tag(Tag::custom(
                TagKind::custom("action"),
                [action],
            ))
            .sign_with_keys(&self.keys)
            .map_err(|e| Error::Nostr(format!("Failed to sign event: {}", e)))?;

        let event_id = event.id.to_hex();

        self.send_event_with_timeout(event)
            .await
            .map_err(|e| Error::Nostr(format!("Failed to send request: {}", e)))?;

        tracing::debug!(
            "Sent ledger request: ledger={}, action={}, event={}",
            ledger_id,
            action,
            &event_id[..16]
        );
        metrics::record_request_sent(action);

        Ok(event_id)
    }

    /// Add a relay and connect to it
    pub async fn add_relay(&self, url: &str) -> Result<(), Error> {
        self.client.add_relay(url).await
            .map_err(|e| Error::Nostr(format!("Failed to add relay {}: {}", url, e)))?;
        self.client.connect_with_timeout(std::time::Duration::from_secs(5)).await;
        Ok(())
    }

    /// Send a request addressed to a courier (Kind 20101 with #p tag)
    pub async fn send_agent_request(
        &self,
        agent_pubkey: &str,
        action: &str,
        params: serde_json::Value,
    ) -> Result<String, Error> {
        let content = serde_json::to_string(&params)
            .map_err(|e| Error::Serialization(format!("Failed to serialize params: {}", e)))?;

        let event = EventBuilder::new(Kind::Custom(KIND_LEDGER_REQUEST), &content)
            .tag(Tag::custom(
                TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::P)),
                [agent_pubkey],
            ))
            .tag(Tag::custom(
                TagKind::custom("action"),
                [action],
            ))
            .sign_with_keys(&self.keys)
            .map_err(|e| Error::Nostr(format!("Failed to sign event: {}", e)))?;

        let event_id = event.id.to_hex();

        self.send_event_with_timeout(event)
            .await
            .map_err(|e| Error::Nostr(format!("Failed to send request: {}", e)))?;

        Ok(event_id)
    }

    /// Send a ledger response (reply to a request)
    pub async fn send_ledger_response(
        &self,
        request_id: &str,
        ledger_id: &str,
        action: &str,
        success: bool,
        result: Option<serde_json::Value>,
        error: Option<String>,
    ) -> Result<String, Error> {
        let response = LedgerResponse {
            success,
            result,
            error,
            request_id: String::new(),
            ledger_id: String::new(),
            event_id: String::new(),
            timestamp: 0,
        };

        let content = serde_json::to_string(&response)
            .map_err(|e| Error::Serialization(format!("Failed to serialize response: {}", e)))?;

        let status = if success { "ok" } else { "error" };

        let event = EventBuilder::new(Kind::Custom(KIND_LEDGER_RESPONSE), &content)
            .tag(Tag::custom(
                TagKind::SingleLetter(TAG_EVENT_REF),
                [request_id],
            ))
            .tag(Tag::custom(
                TagKind::SingleLetter(TAG_LEDGER_REQ),
                [ledger_id],
            ))
            .tag(Tag::custom(
                TagKind::custom("status"),
                [status],
            ))
            .sign_with_keys(&self.keys)
            .map_err(|e| Error::Nostr(format!("Failed to sign event: {}", e)))?;

        let event_id = event.id.to_hex();

        self.send_event_with_timeout(event)
            .await
            .map_err(|e| Error::Nostr(format!("Failed to send response: {}", e)))?;

        tracing::debug!(
            "Sent ledger response: request={}, action={}, status={}, event={}",
            &request_id[..16],
            action,
            status,
            &event_id[..16]
        );
        metrics::record_response_sent(action, success);

        Ok(event_id)
    }

    /// Publish a ledger dispute (invalid ledger detected)
    ///
    /// This is broadcast when a quorum member detects a non-conforming ledger.
    /// Other quorum members listening will receive this and can initiate recovery.
    pub async fn publish_dispute(
        &self,
        ledger_id: &str,
        reason: &str,
        details: &str,
        last_valid_hash: [u8; 32],
        last_valid_sequence: u64,
        violation_sequence: Option<u64>,
        keypair: &bitcoin::secp256k1::Keypair,
    ) -> Result<String, Error> {
        use bitcoin::hashes::{Hash, sha256};
        use bitcoin::secp256k1::{Secp256k1, Message};

        // Build the message to sign
        let mut preimage = Vec::new();
        preimage.extend_from_slice(ledger_id.as_bytes());
        preimage.extend_from_slice(reason.as_bytes());
        preimage.extend_from_slice(&last_valid_hash);
        preimage.extend_from_slice(&last_valid_sequence.to_le_bytes());
        if let Some(vs) = violation_sequence {
            preimage.extend_from_slice(&vs.to_le_bytes());
        }

        let sighash = sha256::Hash::hash(&preimage);
        let secp = Secp256k1::new();
        let msg = Message::from_digest(sighash.to_byte_array());
        let signature = secp.sign_schnorr(&msg, keypair);

        let disputer_pubkey = hex::encode(keypair.public_key().serialize());

        let dispute = LedgerDispute {
            disputer_pubkey: disputer_pubkey.clone(),
            ledger_id: ledger_id.to_string(),
            reason: reason.to_string(),
            details: details.to_string(),
            last_valid_hash: hex::encode(last_valid_hash),
            last_valid_sequence,
            violation_sequence,
            signature: hex::encode(signature.serialize()),
            event_id: String::new(),
            timestamp: 0,
        };

        let content = serde_json::to_string(&dispute)
            .map_err(|e| Error::Serialization(format!("Failed to serialize dispute: {}", e)))?;

        let event = EventBuilder::new(Kind::Custom(KIND_LEDGER_DISPUTE), &content)
            .tag(Tag::custom(
                TagKind::SingleLetter(TAG_LEDGER_ID),
                [ledger_id],
            ))
            .tag(Tag::custom(
                TagKind::SingleLetter(TAG_LEDGER_REQ),
                [ledger_id],
            ))
            .tag(Tag::custom(
                TagKind::custom("reason"),
                [reason],
            ))
            .tag(Tag::custom(
                TagKind::custom("disputer"),
                [&disputer_pubkey],
            ))
            .sign_with_keys(&self.keys)
            .map_err(|e| Error::Nostr(format!("Failed to sign event: {}", e)))?;

        let event_id = event.id.to_hex();

        self.send_event_with_timeout(event)
            .await
            .map_err(|e| Error::Nostr(format!("Failed to send dispute: {}", e)))?;

        tracing::warn!(
            "Published ledger dispute: ledger={}, reason={}, event={}",
            ledger_id,
            reason,
            &event_id[..16]
        );

        Ok(event_id)
    }

    /// Subscribe to disputes for a specific ledger (for quorum members)
    pub async fn subscribe_to_disputes(&self, ledger_id: &str) -> Result<(), Error> {
        // Check if already subscribed to disputes for this ledger
        let sub_key = format!("disputes:{}", ledger_id);
        {
            let subs = self.active_subscriptions.read().unwrap();
            if subs.contains(&sub_key) {
                tracing::debug!("Already subscribed to disputes for ledger {}", ledger_id);
                return Ok(());
            }
        }

        // Include a 30-second lookback to catch any events sent before subscription was established
        let since = nostr_sdk::Timestamp::now() - 30;
        let filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_DISPUTE))
            .custom_tag(
                TAG_LEDGER_REQ,
                [ledger_id],
            )
            .since(since);

        self.client
            .subscribe(vec![filter], None)
            .await
            .map_err(|e| Error::Nostr(format!("Failed to subscribe to disputes: {}", e)))?;

        // Mark as subscribed
        self.active_subscriptions.write().unwrap().insert(sub_key);

        tracing::debug!("Subscribed to disputes for ledger: {}", ledger_id);
        Ok(())
    }

    /// Subscribe to all disputes (for monitoring)
    pub async fn subscribe_to_all_disputes(&self) -> Result<(), Error> {
        // Check if already subscribed to all disputes
        let sub_key = "disputes:all".to_string();
        {
            let subs = self.active_subscriptions.read().unwrap();
            if subs.contains(&sub_key) {
                tracing::debug!("Already subscribed to all disputes");
                return Ok(());
            }
        }

        // Include a 30-second lookback to catch any events sent before subscription was established
        let since = nostr_sdk::Timestamp::now() - 30;
        let filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_DISPUTE))
            .since(since);

        self.client
            .subscribe(vec![filter], None)
            .await
            .map_err(|e| Error::Nostr(format!("Failed to subscribe to all disputes: {}", e)))?;

        // Mark as subscribed
        self.active_subscriptions.write().unwrap().insert(sub_key);

        tracing::debug!("Subscribed to all ledger disputes (kind {})", KIND_LEDGER_DISPUTE);
        Ok(())
    }

    /// Subscribe to requests and disputes for multiple ledgers in a single batched call.
    ///
    /// This is more efficient than calling subscribe_to_requests + subscribe_to_disputes
    /// for each ledger individually, as it creates fewer subscription calls to the relay.
    pub async fn subscribe_to_ledgers_batch(&self, ledger_ids: &[String]) -> Result<(), Error> {
        if ledger_ids.is_empty() {
            return Ok(());
        }

        // Check which ledgers need new subscriptions (requests, disputes, and updates are per-ledger)
        let mut new_request_ledgers: Vec<&String> = Vec::new();
        let mut new_dispute_ledgers: Vec<&String> = Vec::new();
        let mut new_update_ledgers: Vec<&String> = Vec::new();
        {
            let subs = self.active_subscriptions.read().unwrap();
            for lid in ledger_ids {
                let prefix = &lid[..16.min(lid.len())];
                let req_key = format!("requests:{}", prefix);
                let dis_key = format!("disputes:{}", lid);
                let upd_key = format!("updates:{}", prefix);
                if !subs.contains(&req_key) {
                    new_request_ledgers.push(lid);
                }
                if !subs.contains(&dis_key) {
                    new_dispute_ledgers.push(lid);
                }
                if !subs.contains(&upd_key) {
                    new_update_ledgers.push(lid);
                }
            }
        }

        if new_request_ledgers.is_empty() && new_dispute_ledgers.is_empty() && new_update_ledgers.is_empty() {
            tracing::debug!("All {} ledgers already subscribed", ledger_ids.len());
            return Ok(());
        }

        // Build filters for new subscriptions
        // Short lookback to minimize historical dump on reconnect (reduces EAGAIN disconnects)
        let since = nostr_sdk::Timestamp::now() - 5;
        let mut filters = Vec::new();

        // Per-ledger request filters with #l tag for relay-side filtering
        for lid in &new_request_ledgers {
            filters.push(
                Filter::new()
                    .kind(Kind::Custom(KIND_LEDGER_REQUEST))
                    .custom_tag(
                        TAG_LEDGER_REQ,
                        [lid.as_str()],
                    )
                    .since(since)
            );
        }

        // Per-ledger dispute filters (relay filters by tag)
        for lid in &new_dispute_ledgers {
            filters.push(
                Filter::new()
                    .kind(Kind::Custom(KIND_LEDGER_DISPUTE))
                    .custom_tag(
                        TAG_LEDGER_REQ,
                        [lid.as_str()],
                    )
                    .since(since)
            );
        }

        // Per-ledger update filters with #d tag (for validating joined ledgers)
        for lid in &new_update_ledgers {
            filters.push(
                Filter::new()
                    .kind(Kind::Custom(KIND_LEDGER_UPDATE))
                    .custom_tag(
                        TAG_LEDGER_ID,
                        [ledger_tag(lid)],
                    )
                    .since(since)
            );
        }

        // Only subscribe if we have filters to add
        if filters.is_empty() {
            return Ok(());
        }

        let filter_count = filters.len();

        // Subscribe with all filters in one call
        self.client
            .subscribe(filters, None)
            .await
            .map_err(|e| Error::Nostr(format!("Failed to batch subscribe: {}", e)))?;

        // Mark all as subscribed
        {
            let mut subs = self.active_subscriptions.write().unwrap();
            for lid in &new_request_ledgers {
                subs.insert(format!("requests:{}", &lid[..16.min(lid.len())]));
            }
            for lid in &new_dispute_ledgers {
                subs.insert(format!("disputes:{}", lid));
            }
            for lid in &new_update_ledgers {
                subs.insert(format!("updates:{}", &lid[..16.min(lid.len())]));
            }
        }

        tracing::info!("Batch subscribed: {} request + {} dispute + {} update filters ({} total)",
            new_request_ledgers.len(), new_dispute_ledgers.len(), new_update_ledgers.len(), filter_count);
        Ok(())
    }

    /// Publish a recovery agreement (quorum member agreeing to recover)
    pub async fn publish_recovery_agreement(
        &self,
        ledger_id: &str,
        dispute_event_id: &str,
        last_valid_sequence: u64,
        last_valid_hash: [u8; 32],
        keypair: &bitcoin::secp256k1::Keypair,
    ) -> Result<String, Error> {
        use bitcoin::hashes::{Hash, sha256};
        use bitcoin::secp256k1::{Secp256k1, Message};

        // Build the message to sign
        let mut preimage = Vec::new();
        preimage.extend_from_slice(ledger_id.as_bytes());
        preimage.extend_from_slice(dispute_event_id.as_bytes());
        preimage.extend_from_slice(&last_valid_sequence.to_le_bytes());
        preimage.extend_from_slice(&last_valid_hash);

        let sighash = sha256::Hash::hash(&preimage);
        let secp = Secp256k1::new();
        let msg = Message::from_digest(sighash.to_byte_array());
        let signature = secp.sign_schnorr(&msg, keypair);

        let member_pubkey = hex::encode(keypair.public_key().serialize());

        let agreement = RecoveryAgreement {
            member_pubkey: member_pubkey.clone(),
            ledger_id: ledger_id.to_string(),
            dispute_event_id: dispute_event_id.to_string(),
            last_valid_sequence,
            last_valid_hash: hex::encode(last_valid_hash),
            signature: hex::encode(signature.serialize()),
            event_id: String::new(),
            timestamp: 0,
        };

        let content = serde_json::to_string(&agreement)
            .map_err(|e| Error::Serialization(format!("Failed to serialize agreement: {}", e)))?;

        let event = EventBuilder::new(Kind::Custom(KIND_RECOVERY_AGREE), &content)
            .tag(Tag::custom(
                TagKind::SingleLetter(TAG_LEDGER_ID),
                [ledger_id],
            ))
            .tag(Tag::custom(
                TagKind::SingleLetter(TAG_LEDGER_REQ),
                [ledger_id],
            ))
            .tag(Tag::custom(
                TagKind::SingleLetter(TAG_EVENT_REF),
                [dispute_event_id],
            ))
            .tag(Tag::custom(
                TagKind::custom("member"),
                [&member_pubkey],
            ))
            .sign_with_keys(&self.keys)
            .map_err(|e| Error::Nostr(format!("Failed to sign event: {}", e)))?;

        let event_id = event.id.to_hex();

        self.send_event_with_timeout(event)
            .await
            .map_err(|e| Error::Nostr(format!("Failed to send agreement: {}", e)))?;

        tracing::info!(
            "Published recovery agreement: ledger={}, dispute={}, event={}",
            &ledger_id[..16.min(ledger_id.len())],
            &dispute_event_id[..16],
            &event_id[..16]
        );

        Ok(event_id)
    }

    /// Fetch recovery agreements for a specific dispute
    pub async fn fetch_recovery_agreements(
        &self,
        dispute_event_id: &str,
    ) -> Result<Vec<RecoveryAgreement>, Error> {
        let filter = Filter::new()
            .kind(Kind::Custom(KIND_RECOVERY_AGREE))
            .custom_tag(
                TAG_EVENT_REF,
                [dispute_event_id],
            );

        let events = self.client
            .fetch_events(vec![filter], Some(std::time::Duration::from_secs(10)))
            .await
            .map_err(|e| Error::Nostr(format!("Failed to fetch agreements: {}", e)))?;

        let mut agreements = Vec::new();
        for event in events.iter() {
            if let Ok(mut agreement) = serde_json::from_str::<RecoveryAgreement>(&event.content) {
                agreement.event_id = event.id.to_hex();
                agreement.timestamp = event.created_at.as_u64();
                agreements.push(agreement);
            }
        }

        Ok(agreements)
    }

    /// Publish a ledger advertisement
    ///
    /// Uses NIP-33 parameterized replaceable events, so only the latest
    /// advertisement per ledger_id is retained by relays.
    /// Queries the relay for existing advertisement timestamp to ensure
    /// the new event has a strictly greater timestamp.
    pub async fn publish_ledger_advertisement(
        &self,
        ad: &LedgerAdvertisement,
    ) -> Result<String, Error> {
        // Cache locally so we don't need relay round-trips to read our own ads
        self.ad_cache.write().unwrap().insert(ad.ledger_id.clone(), ad.clone());

        let content = serde_json::to_string(ad)
            .map_err(|e| Error::Serialization(format!("Failed to serialize advertisement: {}", e)))?;

        // Query relay for existing advertisement's timestamp
        let existing_timestamp = self.get_advertisement_timestamp(&ad.ledger_id).await.unwrap_or(0);

        // Ensure new timestamp is strictly greater than existing
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let timestamp = std::cmp::max(now, existing_timestamp + 1);

        // Update the static counter too for same-process rapid updates
        LAST_AD_TIMESTAMP.fetch_max(timestamp, Ordering::SeqCst);

        let event = EventBuilder::new(Kind::Custom(KIND_LEDGER_ADVERTISE), &content)
            .custom_created_at(Timestamp::from(timestamp))
            .tag(Tag::custom(
                TagKind::SingleLetter(TAG_LEDGER_ID),
                [ad.ledger_id.as_str()],
            ))
            .tag(Tag::custom(
                TagKind::SingleLetter(TAG_SEQUENCE),
                [ad.network.as_str()],
            ))
            .tag(Tag::custom(
                TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::O)),
                [ad.operator_pubkey.as_str()],
            ))
            .sign_with_keys(&self.keys)
            .map_err(|e| Error::Nostr(format!("Failed to sign event: {}", e)))?;

        let event_id = event.id.to_hex();

        // Send the event and give the relay time to process it before the
        // connection drops.  nostr-sdk's send_event is fire-and-forget at the
        // WebSocket level, so a short-lived CLI process may disconnect before
        // strfry flushes the write.  The brief sleep is a pragmatic workaround.
        self.send_event_with_timeout(event.clone()).await
            .map_err(|e| Error::Nostr(format!("Failed to send advertisement: {}", e)))?;
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;

        // Enqueue mirror to durable relay (advertisements are NIP-33 replaceable, belong there)
        if let Some(ref tx) = self.mirror_tx {
            let _ = tx.send(event);
        }

        tracing::info!(
            "Published ledger advertisement: ledger={}, event={}",
            &ad.ledger_id[..16.min(ad.ledger_id.len())],
            &event_id[..16]
        );

        Ok(event_id)
    }

    /// Publish a price oracle event (BTC/USD rate)
    pub async fn publish_price(&self, price_usd: f64) -> Result<String, Error> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let content = serde_json::json!({
            "pair": "BTCUSD",
            "price": price_usd,
            "timestamp": now,
        }).to_string();

        let event = EventBuilder::new(Kind::Custom(KIND_PRICE_ORACLE), &content)
            .tag(Tag::custom(
                TagKind::SingleLetter(TAG_LEDGER_ID),
                ["btcusd"],
            ))
            .sign_with_keys(&self.keys)
            .map_err(|e| Error::Nostr(format!("Failed to sign price event: {}", e)))?;

        let event_id = event.id.to_hex();

        self.send_event_with_timeout(event.clone()).await
            .map_err(|e| Error::Nostr(format!("Failed to publish price: {}", e)))?;

        // Mirror to durable relay
        if let Some(ref tx) = self.mirror_tx {
            let _ = tx.send(event);
        }

        tracing::debug!("Published BTC/USD price: ${}", price_usd);
        Ok(event_id)
    }

    /// Get the timestamp of an existing advertisement for a ledger
    async fn get_advertisement_timestamp(&self, ledger_id: &str) -> Option<u64> {
        let filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_ADVERTISE))
            .custom_tag(
                TAG_LEDGER_ID,
                [ledger_id],
            )
            .limit(1);

        let events = self.client
            .fetch_events(vec![filter], Some(std::time::Duration::from_secs(5)))
            .await
            .ok()?;

        // Extract timestamp from first event
        let mut timestamp = None;
        for event in events.iter() {
            timestamp = Some(event.created_at.as_u64());
            break;
        }
        timestamp
    }

    /// Fetch all ledger advertisements for a network
    pub async fn fetch_ledger_advertisements(
        &self,
        network: &str,
    ) -> Result<Vec<LedgerAdvertisement>, Error> {
        let filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_ADVERTISE))
            .custom_tag(
                TAG_SEQUENCE,
                [network],
            );

        let events = self.client
            .fetch_events(vec![filter], Some(std::time::Duration::from_secs(10)))
            .await
            .map_err(|e| Error::Nostr(format!("Failed to fetch advertisements: {}", e)))?;

        let mut ads = Vec::new();
        for event in events.iter() {
            if let Ok(mut ad) = serde_json::from_str::<LedgerAdvertisement>(&event.content) {
                ad.event_id = event.id.to_hex();
                ad.timestamp = event.created_at.as_u64();
                ads.push(ad);
            }
        }

        // Sort by timestamp descending (newest first)
        ads.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        Ok(ads)
    }

    /// Fetch agent service advertisements (Kind 39102)
    pub async fn fetch_agent_advertisements(
        &self,
        network: &str,
    ) -> Result<Vec<AgentAdvertisement>, Error> {
        let filter = Filter::new()
            .kind(Kind::Custom(KIND_AGENT_ADVERTISE));

        let events = self.client
            .fetch_events(vec![filter], Some(std::time::Duration::from_secs(10)))
            .await
            .map_err(|e| Error::Nostr(format!("Failed to fetch agent advertisements: {}", e)))?;

        let mut ads = Vec::new();
        for event in events.iter() {
            if let Ok(mut ad) = serde_json::from_str::<AgentAdvertisement>(&event.content) {
                // Filter by network client-side
                if ad.network != network {
                    continue;
                }
                ad.event_id = event.id.to_hex();
                ad.timestamp = event.created_at.as_u64();
                ads.push(ad);
            }
        }

        ads.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        Ok(ads)
    }

    /// Re-mirror our own advertisements to the durable (slow) relay.
    ///
    /// Fetches Kind 39100 events authored by this node from the fast relay
    /// and sends them to the slow relay. This covers the case where the slow
    /// relay was restarted (losing its DB) after ads were originally published.
    pub async fn remirror_advertisements(&self) -> usize {
        let slow = match self.slow_client {
            Some(ref sc) => sc,
            None => return 0,
        };

        let filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_ADVERTISE))
            .author(self.keys.public_key());

        let events = match self.client
            .fetch_events(vec![filter], Some(std::time::Duration::from_secs(5)))
            .await
        {
            Ok(evts) => evts,
            Err(e) => {
                tracing::debug!("remirror_advertisements: fetch failed: {}", e);
                return 0;
            }
        };

        let mut mirrored = 0usize;
        for event in events.into_iter() {
            match tokio::time::timeout(
                std::time::Duration::from_secs(5),
                slow.send_event(event),
            ).await {
                Ok(Ok(_)) => mirrored += 1,
                Ok(Err(e)) => tracing::debug!("remirror ad failed: {}", e),
                Err(_) => tracing::debug!("remirror ad timed out"),
            }
        }

        if mirrored > 0 {
            tracing::info!("Re-mirrored {} advertisement(s) to durable relay", mirrored);
        }
        mirrored
    }

    /// Fetch a specific ledger's advertisement.
    /// Returns from local cache if available (our own ads), otherwise queries relay.
    pub async fn fetch_ledger_advertisement(
        &self,
        ledger_id: &str,
    ) -> Result<Option<LedgerAdvertisement>, Error> {
        // Check local cache first (populated by publish_ledger_advertisement)
        if let Some(ad) = self.ad_cache.read().unwrap().get(ledger_id) {
            return Ok(Some(ad.clone()));
        }

        let filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_ADVERTISE))
            .custom_tag(
                TAG_LEDGER_ID,
                [ledger_id],
            )
            .limit(1);

        let events = self.client
            .fetch_events(vec![filter], Some(std::time::Duration::from_secs(10)))
            .await
            .map_err(|e| Error::Nostr(format!("Failed to fetch advertisement: {}", e)))?;

        if let Some(event) = events.iter().next() {
            if let Ok(mut ad) = serde_json::from_str::<LedgerAdvertisement>(&event.content) {
                ad.event_id = event.id.to_hex();
                ad.timestamp = event.created_at.as_u64();
                return Ok(Some(ad));
            }
        }

        Ok(None)
    }

    /// Fetch disputes for a ledger
    pub async fn fetch_disputes(
        &self,
        ledger_id: &str,
    ) -> Result<Vec<LedgerDispute>, Error> {
        let filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_DISPUTE))
            .custom_tag(
                TAG_LEDGER_REQ,
                [ledger_id],
            );

        let events = self.client
            .fetch_events(vec![filter], Some(std::time::Duration::from_secs(10)))
            .await
            .map_err(|e| Error::Nostr(format!("Failed to fetch disputes: {}", e)))?;

        let mut disputes = Vec::new();
        for event in events.iter() {
            if let Ok(mut dispute) = serde_json::from_str::<LedgerDispute>(&event.content) {
                dispute.event_id = event.id.to_hex();
                dispute.timestamp = event.created_at.as_u64();
                disputes.push(dispute);
            }
        }

        // Sort by timestamp (oldest first)
        disputes.sort_by_key(|d| d.timestamp);

        Ok(disputes)
    }

    /// Fetch ledger updates for a specific ledger
    ///
    /// Used by clients to verify quorum membership by checking for QuorumAddMember operations.
    pub async fn fetch_ledger_updates(
        &self,
        ledger_id: &str,
    ) -> Result<Vec<deposits_core::SignedLedgerUpdate>, Error> {
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

        let filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_UPDATE))
            .custom_tag(
                TAG_LEDGER_REQ,
                [ledger_tag(ledger_id)],
            );

        let events = self.client
            .fetch_events(vec![filter], Some(std::time::Duration::from_secs(10)))
            .await
            .map_err(|e| Error::Nostr(format!("Failed to fetch ledger updates: {}", e)))?;

        let mut updates = Vec::new();
        for event in events.iter() {
            // Updates are base64-encoded SignedLedgerUpdate
            if let Ok(bytes) = BASE64.decode(&event.content) {
                if let Ok(update) = deposits_core::SignedLedgerUpdate::tlv_decode(&bytes) {
                    updates.push(update);
                }
            }
        }

        // Sort by sequence number
        updates.sort_by_key(|u| u.sequence_number);

        Ok(updates)
    }

    /// Fetch a single ledger update by sequence number from the relay.
    /// Filters by `#d` (ledger prefix) relay-side, then by seq client-side.
    pub async fn fetch_ledger_update_by_seq(
        &self,
        ledger_id: &str,
        seq: u64,
    ) -> Result<Option<deposits_core::SignedLedgerUpdate>, Error> {
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

        let filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_UPDATE))
            .custom_tag(
                TAG_LEDGER_ID,
                [ledger_tag(ledger_id)],
            );

        let events = self.client
            .fetch_events(vec![filter], Some(std::time::Duration::from_secs(5)))
            .await
            .map_err(|e| Error::Nostr(format!("Failed to fetch update seq {}: {}", seq, e)))?;

        for event in events.iter() {
            if let Ok(bytes) = BASE64.decode(&event.content) {
                if let Ok(update) = deposits_core::SignedLedgerUpdate::tlv_decode(&bytes) {
                    if update.sequence_number == seq {
                        return Ok(Some(update));
                    }
                }
            }
        }

        Ok(None)
    }

    /// Fetch a range of ledger updates [from_seq, to_seq] from the relay.
    /// Filters by `#d` (ledger_id) relay-side, then by seq range client-side.
    pub async fn fetch_ledger_updates_range(
        &self,
        ledger_id: &str,
        from_seq: u64,
        to_seq: u64,
    ) -> Result<Vec<deposits_core::SignedLedgerUpdate>, Error> {
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

        let filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_UPDATE))
            .custom_tag(
                TAG_LEDGER_ID,
                [ledger_tag(ledger_id)],
            );

        let events = self.client
            .fetch_events(vec![filter], Some(std::time::Duration::from_secs(10)))
            .await
            .map_err(|e| Error::Nostr(format!("Failed to fetch updates range: {}", e)))?;

        let mut updates = Vec::new();
        for event in events.iter() {
            if let Ok(bytes) = BASE64.decode(&event.content) {
                if let Ok(update) = deposits_core::SignedLedgerUpdate::tlv_decode(&bytes) {
                    if update.sequence_number >= from_seq && update.sequence_number <= to_seq {
                        updates.push(update);
                    }
                }
            }
        }

        updates.sort_by_key(|u| u.sequence_number);
        Ok(updates)
    }

    /// Subscribe to ledger requests for a specific ledger (for operators)
    /// Uses relay-side #l tag filtering to only receive events for this ledger,
    /// dramatically reducing bandwidth (from ALL requests to just ~25% per ledger).
    pub async fn subscribe_to_requests(&self, ledger_id: &str) -> Result<(), Error> {
        // Per-ledger subscription to leverage relay-side filtering
        let sub_key = format!("requests:{}", &ledger_id[..16.min(ledger_id.len())]);
        {
            let subs = self.active_subscriptions.read().unwrap();
            if subs.contains(&sub_key) {
                tracing::debug!("Already subscribed to requests for ledger {}", &ledger_id[..16.min(ledger_id.len())]);
                return Ok(());
            }
        }

        // Short lookback to minimize historical dump on reconnect (reduces EAGAIN disconnects)
        let since = nostr_sdk::Timestamp::now() - 5;
        let filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_REQUEST))
            .custom_tag(TAG_LEDGER_REQ, [ledger_id])
            .since(since);

        self.client
            .subscribe(vec![filter], None)
            .await
            .map_err(|e| Error::Nostr(format!("Failed to subscribe to requests: {}", e)))?;

        // Mark as subscribed
        self.active_subscriptions.write().unwrap().insert(sub_key);

        tracing::debug!("Subscribed to ledger requests (kind {}) for ledger: {}", KIND_LEDGER_REQUEST, &ledger_id[..16.min(ledger_id.len())]);
        Ok(())
    }

    /// Fetch recent ledger requests (polling fallback).
    /// Uses per-ledger #l tag filtering when request_ledger_filter is set.
    pub async fn fetch_recent_requests(&self, since_secs: u64) -> Result<Vec<LedgerRequest>, Error> {
        use nostr_sdk::Timestamp;

        let since = Timestamp::now() - since_secs;
        let ledger_ids = self.request_ledger_filter.read().unwrap().clone();
        let filters = if !ledger_ids.is_empty() {
            ledger_ids.iter().map(|lid| {
                Filter::new()
                    .kind(Kind::Custom(KIND_LEDGER_REQUEST))
                    .custom_tag(TAG_LEDGER_REQ, [lid.as_str()])
                    .since(since)
            }).collect::<Vec<_>>()
        } else {
            vec![Filter::new()
                .kind(Kind::Custom(KIND_LEDGER_REQUEST))
                .since(since)]
        };

        let events = self.client
            .fetch_events(filters, Some(tokio::time::Duration::from_secs(5)))
            .await
            .map_err(|e| Error::Nostr(format!("Failed to fetch events: {}", e)))?;

        let mut requests = Vec::new();
        for event in events.into_iter() {
            if let Ok(req) = self.process_ledger_request(&event) {
                requests.push(req);
            }
        }

        if !requests.is_empty() {
            tracing::debug!("Fetched {} recent requests", requests.len());
        }
        Ok(requests)
    }

    /// Subscribe to responses (for requesters).
    /// If response_ledger_filter is set, uses relay-side #l tag filtering
    /// to only receive responses for specific ledgers (reduces fan-out ~75%).
    /// Otherwise falls back to global subscription.
    pub async fn subscribe_to_response(&self, _request_id: &str) -> Result<(), Error> {
        let sub_key = "responses:all".to_string();
        {
            let subs = self.active_subscriptions.read().unwrap();
            if subs.contains(&sub_key) {
                return Ok(());
            }
        }

        // Short lookback to minimize historical dump on reconnect (reduces EAGAIN disconnects)
        let since = nostr_sdk::Timestamp::now() - 5;

        // Check if we have a ledger filter configured
        let ledger_ids = self.response_ledger_filter.read().unwrap().clone();

        let filters = if !ledger_ids.is_empty() {
            // Per-ledger response filters for relay-side filtering
            ledger_ids.iter().map(|lid| {
                Filter::new()
                    .kind(Kind::Custom(KIND_LEDGER_RESPONSE))
                    .custom_tag(TAG_LEDGER_REQ, [lid.as_str()])
                    .since(since)
            }).collect::<Vec<_>>()
        } else {
            // Global fallback (no filter configured)
            vec![Filter::new()
                .kind(Kind::Custom(KIND_LEDGER_RESPONSE))
                .since(since)]
        };

        let filter_count = filters.len();
        self.client
            .subscribe(filters, None)
            .await
            .map_err(|e| Error::Nostr(format!("Failed to subscribe to responses: {}", e)))?;

        // Mark as subscribed
        self.active_subscriptions.write().unwrap().insert(sub_key);

        if !ledger_ids.is_empty() {
            tracing::info!("Subscribed to ledger responses (kind {}) for {} ledgers", KIND_LEDGER_RESPONSE, filter_count);
        } else {
            tracing::info!("Subscribed to all ledger responses (kind {}) - no filter", KIND_LEDGER_RESPONSE);
        }
        Ok(())
    }

    /// Fetch response for a specific request (polling fallback)
    pub async fn fetch_response(&self, request_id: &str) -> Result<Option<LedgerResponse>, Error> {
        use nostr_sdk::Timestamp;

        // Look for responses from the last 120 seconds (wider window for clock drift)
        let since = Timestamp::now() - 120;

        // Fetch ALL responses and filter locally (custom_tag filters unreliable on some relays)
        let filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_RESPONSE))
            .since(since);

        // Use shorter timeout (1s) to allow more polling attempts within outer timeout
        let events = match self.client
            .fetch_events(vec![filter], Some(tokio::time::Duration::from_secs(1)))
            .await
        {
            Ok(e) => e,
            Err(e) => {
                tracing::debug!("fetch_events error (will retry): {}", e);
                return Ok(None);
            }
        };

        tracing::debug!("Fetched {} response events, looking for request {}",
            events.len(), &request_id[..16]);

        for event in events.into_iter() {
            if let Ok(response) = self.process_ledger_response(&event) {
                tracing::debug!("Found response for request {}, comparing with {}",
                    &response.request_id[..16.min(response.request_id.len())],
                    &request_id[..16]);
                if response.request_id == request_id {
                    tracing::info!("Matched response for request: {}", &request_id[..16]);
                    return Ok(Some(response));
                }
            }
        }

        Ok(None)
    }

    /// Stream responses for a request until timeout, allowing caller to accept/reject each one
    /// Returns responses one at a time via the callback. Return true to accept, false to keep waiting.
    pub async fn wait_for_valid_response<F>(
        &self,
        request_id: &str,
        timeout_ms: u64,
        mut validator: F,
    ) -> Result<LedgerResponse, Error>
    where
        F: FnMut(&LedgerResponse) -> bool,
    {
        // Subscribe to responses if not already
        self.subscribe_to_response(request_id).await?;

        let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_millis(timeout_ms);

        // First check if we already have a valid response
        while let Some(response) = self.try_recv_response() {
            if response.request_id == request_id && validator(&response) {
                return Ok(response);
            }
        }

        // Create notification receiver ONCE before the loop to avoid missing events
        // (each call to client.notifications() creates a new empty receiver)
        let mut notification_rx = self.client.notifications();

        // Wait for notifications until we get a valid response or timeout
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(Error::Nostr("Timeout waiting for valid response".to_string()));
            }

            match tokio::time::timeout(remaining, notification_rx.recv()).await {
                Ok(Ok(notification)) => {
                    self.handle_notification(notification);

                    while let Ok(notification) = notification_rx.try_recv() {
                        self.handle_notification(notification);
                    }

                    // Check all responses that arrived
                    while let Some(response) = self.try_recv_response() {
                        if response.request_id == request_id && validator(&response) {
                            return Ok(response);
                        }
                    }
                }
                Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(n))) => {
                    tracing::warn!("Notification receiver lagged by {} events", n);
                }
                Ok(Err(_)) => {
                    return Err(Error::Nostr("Notification channel closed".to_string()));
                }
                Err(_) => {
                    return Err(Error::Nostr("Timeout waiting for valid response".to_string()));
                }
            }
        }
    }

    /// Wait for a specific response using real-time subscription (low latency)
    /// This is much faster than polling - typically <5ms vs 100-200ms
    pub async fn wait_for_response(&self, request_id: &str, timeout_ms: u64) -> Result<LedgerResponse, Error> {
        // Subscribe to responses if not already
        self.subscribe_to_response(request_id).await?;

        let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_millis(timeout_ms);

        // First check if we already have the response (from a previous notification)
        while let Some(response) = self.try_recv_response() {
            if response.request_id == request_id {
                return Ok(response);
            }
        }

        // Create notification receiver ONCE before the loop to avoid missing events
        let mut notification_rx = self.client.notifications();

        // Wait for notifications until we get our response or timeout
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(Error::Nostr("Timeout waiting for response".to_string()));
            }

            // Wait for next notification with timeout
            match tokio::time::timeout(remaining, notification_rx.recv()).await {
                Ok(Ok(notification)) => {
                    self.handle_notification(notification);

                    // Drain any additional pending notifications
                    while let Ok(notification) = notification_rx.try_recv() {
                        self.handle_notification(notification);
                    }

                    // Check if our response arrived
                    while let Some(response) = self.try_recv_response() {
                        if response.request_id == request_id {
                            return Ok(response);
                        }
                    }
                }
                Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(n))) => {
                    tracing::warn!("Notification receiver lagged by {} events", n);
                }
                Ok(Err(_)) => {
                    // Channel closed
                    return Err(Error::Nostr("Notification channel closed".to_string()));
                }
                Err(_) => {
                    // Timeout
                    return Err(Error::Nostr("Timeout waiting for response".to_string()));
                }
            }
        }
    }

    /// Fetch all responses since a timestamp
    pub async fn fetch_responses_since(&self, _since: nostr_sdk::Timestamp) -> Result<Vec<LedgerResponse>, Error> {
        // Ignore 'since' and use a fixed 5-minute lookback to avoid timestamp sync issues
        // The strfry relay may have clock drift or event ordering issues with recent events
        let since = nostr_sdk::Timestamp::now() - 300;
        let filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_RESPONSE))
            .since(since);

        // Use 200ms timeout - relay should respond almost instantly with stored events
        let events = self.client
            .fetch_events(vec![filter], Some(tokio::time::Duration::from_millis(200)))
            .await
            .map_err(|e| Error::Nostr(format!("Failed to fetch events: {}", e)))?;

        tracing::debug!("fetch_responses_since: fetched {} KIND_LEDGER_RESPONSE events (5 min lookback)", events.len());

        let mut responses = Vec::new();
        for event in events.into_iter() {
            if let Ok(response) = self.process_ledger_response(&event) {
                tracing::debug!("  -> response for request: {}...", &response.request_id[..16.min(response.request_id.len())]);
                responses.push(response);
            }
        }

        Ok(responses)
    }

    /// Start listening for inbound messages
    pub async fn start_listening(&self) -> Result<(), Error> {
        // Subscribe to DMs addressed to us
        let filter = Filter::new()
            .kind(Kind::EncryptedDirectMessage)
            .pubkey(self.keys.public_key());

        self.client
            .subscribe(vec![filter], None)
            .await
            .map_err(|e| Error::Nostr(format!("Subscribe failed: {}", e)))?;

        // Create persistent notification receiver for the daemon run loop.
        // Must be created AFTER subscriptions are set up, BEFORE any events arrive.
        *self.daemon_notification_rx.lock().unwrap() = Some(self.client.notifications());

        Ok(())
    }

    /// Process incoming events (call this in a loop).
    /// Uses the persistent notification receiver created in start_listening()
    /// to avoid missing events between calls.
    ///
    /// `timeout_ms` controls how long to wait for the first notification.
    /// Use short timeouts (1ms) when under load, longer (100ms) when idle.
    pub async fn process_events_with_timeout(&self, timeout_ms: u64) -> Result<(), Error> {
        // Take the receiver out of the Mutex to avoid holding the lock across await.
        // Use a block to ensure the MutexGuard is dropped before any await point.
        let taken = self.daemon_notification_rx.lock().unwrap().take();
        let mut rx = match taken {
            Some(rx) => rx,
            None => {
                // Fallback: create ephemeral receiver (for non-daemon callers)
                let timeout = tokio::time::Duration::from_millis(timeout_ms);
                let mut rx = self.client.notifications();
                match tokio::time::timeout(timeout, rx.recv()).await {
                    Ok(Ok(notification)) => { self.handle_notification(notification); },
                    _ => {}
                }
                return Ok(());
            }
        };

        let mut recreate = false;

        // Drain all available notifications from the broadcast channel.
        // try_recv() is non-blocking, so this loop exits as soon as the buffer
        // is empty. A generous budget prevents broadcast::Lagged under sustained
        // load (500+ events/sec across 6 relays).
        let drain_budget = std::time::Duration::from_millis(100);
        let drain_start = std::time::Instant::now();
        let mut drain_count = 0u32;
        let mut dedup_count = 0u32;

        // Wait for first event with caller-specified timeout
        let timeout = tokio::time::Duration::from_millis(timeout_ms);
        match tokio::time::timeout(timeout, rx.recv()).await {
            Ok(Ok(notification)) => {
                if self.handle_notification(notification) { drain_count += 1; } else { dedup_count += 1; }
                // Drain pending notifications with time budget
                loop {
                    if drain_start.elapsed() >= drain_budget {
                        break;
                    }
                    match rx.try_recv() {
                        Ok(notification) => {
                            if self.handle_notification(notification) { drain_count += 1; } else { dedup_count += 1; }
                        }
                        Err(tokio::sync::broadcast::error::TryRecvError::Lagged(n)) => {
                            crate::metrics::record_broadcast_lag("daemon_drain", n);
                            tracing::warn!("Daemon notification receiver lagged by {} events", n);
                        }
                        Err(_) => break,
                    }
                }
            }
            Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(n))) => {
                crate::metrics::record_broadcast_lag("daemon_recv", n);
                tracing::warn!("Daemon notification receiver lagged by {} events, re-syncing", n);
                // After lag, drain what we can (with budget)
                loop {
                    if drain_start.elapsed() >= drain_budget {
                        break;
                    }
                    match rx.try_recv() {
                        Ok(notification) => {
                            if self.handle_notification(notification) { drain_count += 1; } else { dedup_count += 1; }
                        }
                        Err(_) => break,
                    }
                }
            }
            Ok(Err(_)) => {
                // Channel closed — re-create receiver
                tracing::warn!("Daemon notification channel closed, re-creating receiver");
                recreate = true;
            }
            Err(_) => {
                // Timeout - no notification received, that's ok
            }
        }

        if drain_count > 0 || dedup_count > 0 {
            crate::metrics::record_notification_drain_count(drain_count);
        }
        if dedup_count > 0 {
            crate::metrics::record_notification_dedup_skipped(dedup_count);
        }

        // Put the receiver back (or create a new one if channel was closed)
        *self.daemon_notification_rx.lock().unwrap() = Some(if recreate {
            self.client.notifications()
        } else {
            rx
        });
        Ok(())
    }

    /// Process incoming events with the default 100ms timeout.
    pub async fn process_events(&self) -> Result<(), Error> {
        self.process_events_with_timeout(100).await
    }

    /// Poll for events with a short wait
    /// Fetches recent responses and drains pending notifications
    pub async fn poll_events(&self) -> Result<(), Error> {
        // Fetch recent responses directly (subscriptions may not deliver reliably)
        // Use a short 5-second lookback to avoid fetching too many events
        let since = nostr_sdk::Timestamp::now() - 5;
        let filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_RESPONSE))
            .since(since);

        // Use short timeout to avoid blocking
        if let Ok(events) = self.client
            .fetch_events(vec![filter], Some(std::time::Duration::from_millis(500)))
            .await
        {
            for event in events.iter() {
                if let Ok(response) = self.process_ledger_response(event) {
                    let _ = self.response_tx.send(response);
                }
            }
        }

        // Also drain any pending notifications
        while let Ok(notification) = self.client.notifications().try_recv() {
            self.handle_notification(notification);
        }

        Ok(())
    }

    /// Create a new broadcast notification receiver.
    /// Call this BEFORE sending a request to ensure events aren't missed.
    /// Each call to client.notifications() creates a new receiver that only
    /// sees events from that point forward — so create once and reuse.
    pub fn create_notification_receiver(&self) -> tokio::sync::broadcast::Receiver<RelayPoolNotification> {
        self.client.notifications()
    }

    /// Route a notification to the appropriate internal channel.
    /// Use in the cosign mini loop after receiving from a notification_receiver.
    pub fn dispatch_notification(&self, notification: RelayPoolNotification) {
        self.handle_notification(notification);
    }

    /// Dispatch a notification but intercept Kind 20101 requests matching `extract_action`.
    ///
    /// If the notification is a request with the given action, it is parsed and
    /// returned directly (never enters request_rx). All other notifications —
    /// including non-matching requests — are dispatched to channels normally.
    ///
    /// This lets cosign mini loops handle requests inline from the notification
    /// stream, eliminating the re-queue amplification problem where cosign
    /// requests get buried behind non-cosign requests in request_rx.
    pub fn dispatch_or_extract_request(&self, notification: RelayPoolNotification, extract_action: &str) -> Option<LedgerRequest> {
        if let RelayPoolNotification::Event { ref event, .. } = &notification {
            let kind_num = event.kind.as_u16();
            if kind_num == KIND_LEDGER_REQUEST {
                if let Ok(request) = self.process_ledger_request(event) {
                    if request.action == extract_action {
                        // Return directly — never enters request_rx
                        return Some(request);
                    }
                    // Non-matching request: route to channel as normal
                    let _ = self.request_tx.send(request);
                }
                return None;
            }
        }
        // Everything else (updates, responses, disputes, DMs): normal dispatch
        self.handle_notification(notification);
        None
    }

    /// Handle a single notification.
    /// Returns true if the event was new (processed), false if skipped as duplicate.
    fn handle_notification(&self, notification: RelayPoolNotification) -> bool {
        if let RelayPoolNotification::Event { event, .. } = notification {
            // Early dedup: check event ID before any parsing.
            // event.id is already computed by nostr-sdk, so this is just a HashSet lookup
            // on 32 bytes — much cheaper than tag extraction + JSON decode.
            let event_id_bytes = event.id.to_bytes();
            {
                let seen = self.seen_events.lock().unwrap();
                if seen.contains(&event_id_bytes) || self.seen_events_prev.lock().unwrap().contains(&event_id_bytes) {
                    return false;
                }
            }
            self.seen_events.lock().unwrap().insert(event_id_bytes);

            // Use numeric kind value for comparison since Kind::Custom(n) and Kind::Regular(n)
            // are different enum variants but represent the same kind number
            let kind_num = event.kind.as_u16();

            // Per-ledger interest filter: extract ledger ID from tags and check
            // against the interested set. Empty set = accept all.
            let interested = self.interested_ledgers.read().unwrap();
            if !interested.is_empty() && kind_num != 4 /* EncryptedDirectMessage */ {
                let ledger_id = Self::extract_ledger_id_from_event(&event, kind_num);
                if let Some(lid) = &ledger_id {
                    if !interested.contains(lid) {
                        return false; // Not our ledger — drop
                    }
                }
                // If no ledger_id could be extracted, let it through (safety)
            }
            drop(interested);

            if event.kind == Kind::EncryptedDirectMessage {
                if let Ok(msg) = self.process_dm(&event) {
                    let _ = self.inbound_tx.send(msg);
                }
            } else if kind_num == KIND_LEDGER_UPDATE {
                if let Ok(update) = self.process_ledger_update(&event) {
                    let _ = self.ledger_tx.send(update);
                }
            } else if kind_num == KIND_LEDGER_REQUEST {
                if let Ok(request) = self.process_ledger_request(&event) {
                    let _ = self.request_tx.send(request);
                }
            } else if kind_num == KIND_LEDGER_RESPONSE {
                if let Ok(response) = self.process_ledger_response(&event) {
                    let _ = self.response_tx.send(response);
                }
            } else if kind_num == KIND_LEDGER_DISPUTE {
                if let Ok(dispute) = self.process_ledger_dispute(&event) {
                    let _ = self.dispute_tx.send(dispute);
                }
            } else if kind_num == KIND_FRAUD_PROOF {
                if let Ok(fp) = self.process_fraud_proof(&event) {
                    let _ = self.fraud_proof_tx.send(fp);
                }
            }
            return true;
        }
        false
    }

    /// Extract ledger ID prefix from an event's tags without full parsing.
    /// Updates use `#d` tag, requests/responses/disputes use `#l` tag.
    /// Returns a truncated prefix (for interest filtering, not routing).
    fn extract_ledger_id_from_event(event: &Event, kind_num: u16) -> Option<String> {
        let tag_letter = if kind_num == KIND_LEDGER_UPDATE {
            TAG_LEDGER_ID
        } else {
            TAG_LEDGER_REQ
        };
        event.tags.iter().find_map(|tag| {
            if tag.kind() == TagKind::SingleLetter(tag_letter) {
                tag.content().map(|s| ledger_tag(s).to_string())
            } else {
                None
            }
        })
    }

    /// Rotate the seen_events dedup set (two-generation cleanup).
    /// Call periodically from the run loop to cap memory.
    pub fn rotate_seen_events(&self) {
        let mut seen = self.seen_events.lock().unwrap();
        if seen.len() > 10_000 {
            *self.seen_events_prev.lock().unwrap() = std::mem::take(&mut *seen);
        }
    }

    /// Process an encrypted DM event
    fn process_dm(&self, event: &Event) -> Result<InboundMessage, Error> {
        // Decrypt the content using NIP-04
        let content = nip04::decrypt(self.keys.secret_key(), &event.pubkey, &event.content)
            .map_err(|e| Error::Nostr(format!("Failed to decrypt DM: {}", e)))?;

        // Decode from hex
        let bytes = hex::decode(&content)
            .map_err(|e| Error::Serialization(format!("Invalid hex in message: {}", e)))?;

        // Parse as DepositsMessage
        let msg = DepositsMessage::decode(&bytes)
            .map_err(|e| Error::Serialization(format!("Failed to parse message: {:?}", e)))?;

        // Convert sender nostr pubkey to secp256k1
        // Note: This is lossy - we lose the y-coordinate parity
        // In production, messages should include the full sender pubkey
        let sender_bytes = event.pubkey.to_bytes();
        let mut full_pubkey = [0u8; 33];
        full_pubkey[0] = 0x02; // Assume even y
        full_pubkey[1..].copy_from_slice(&sender_bytes);
        let sender = PublicKey::from_slice(&full_pubkey)
            .map_err(|e| Error::Nostr(format!("Invalid sender pubkey: {}", e)))?;

        Ok(InboundMessage {
            message: msg,
            sender,
            timestamp: event.created_at.as_u64(),
        })
    }

    /// Process a ledger update event
    fn process_ledger_update(&self, event: &Event) -> Result<InboundLedgerUpdate, Error> {
        // Decode content from base64
        let tlv_bytes = BASE64
            .decode(&event.content)
            .map_err(|e| Error::Serialization(format!("Invalid base64 in ledger update: {}", e)))?;

        // Decode TLV to SignedLedgerUpdate — full ledger_id is in the TLV content
        let update = SignedLedgerUpdate::tlv_decode(&tlv_bytes)
            .map_err(|e| Error::Serialization(format!("Failed to decode ledger update: {:?}", e)))?;

        let ledger_id = update.ledger_id_hex();

        tracing::trace!(
            "Received ledger update: ledger={}, seq={}, hash={}",
            &ledger_id[..16],
            update.sequence_number,
            &hex::encode(update.current_hash)[..16]
        );

        Ok(InboundLedgerUpdate {
            update,
            ledger_id,
            timestamp: event.created_at.as_u64(),
            event_id: event.id.to_hex(),
        })
    }

    /// Process a ledger request event
    fn process_ledger_request(&self, event: &Event) -> Result<LedgerRequest, Error> {
        // Extract ledger_id from the l tag
        let ledger_id = event
            .tags
            .iter()
            .find_map(|tag| {
                if tag.kind() == TagKind::SingleLetter(TAG_LEDGER_REQ) {
                    tag.content().map(|s| s.to_string())
                } else {
                    None
                }
            })
            .ok_or_else(|| Error::Nostr("Missing l tag in ledger request".to_string()))?;

        // Extract action from the action tag
        let action = event
            .tags
            .iter()
            .find_map(|tag| {
                if tag.kind() == TagKind::custom("action") {
                    tag.content().map(|s| s.to_string())
                } else {
                    None
                }
            })
            .ok_or_else(|| Error::Nostr("Missing action tag in ledger request".to_string()))?;

        // Parse params from content
        let params: serde_json::Value = serde_json::from_str(&event.content)
            .unwrap_or(serde_json::Value::Null);

        tracing::trace!(
            "Received ledger request: ledger={}, action={}, event={}",
            ledger_id,
            action,
            &event.id.to_hex()[..16]
        );

        Ok(LedgerRequest {
            action,
            ledger_id,
            params,
            event_id: event.id.to_hex(),
            sender: event.pubkey.to_hex(),
            timestamp: event.created_at.as_u64(),
        })
    }

    /// Process a ledger response event
    fn process_ledger_response(&self, event: &Event) -> Result<LedgerResponse, Error> {
        // Extract request_id from the e tag
        let request_id = event
            .tags
            .iter()
            .find_map(|tag| {
                if tag.kind() == TagKind::SingleLetter(TAG_EVENT_REF) {
                    tag.content().map(|s| s.to_string())
                } else {
                    None
                }
            })
            .ok_or_else(|| Error::Nostr("Missing e tag in ledger response".to_string()))?;

        // Extract ledger_id from the l tag
        let ledger_id = event
            .tags
            .iter()
            .find_map(|tag| {
                if tag.kind() == TagKind::SingleLetter(TAG_LEDGER_REQ) {
                    tag.content().map(|s| s.to_string())
                } else {
                    None
                }
            })
            .unwrap_or_default();

        // Extract status from the status tag
        let status = event
            .tags
            .iter()
            .find_map(|tag| {
                if tag.kind() == TagKind::custom("status") {
                    tag.content().map(|s| s.to_string())
                } else {
                    None
                }
            })
            .unwrap_or_else(|| "unknown".to_string());

        // Parse response from content
        let mut response: LedgerResponse = serde_json::from_str(&event.content)
            .unwrap_or(LedgerResponse {
                success: status == "ok",
                result: None,
                error: Some("Failed to parse response".to_string()),
                request_id: String::new(),
                ledger_id: String::new(),
                event_id: String::new(),
                timestamp: 0,
            });

        response.request_id = request_id.clone();
        response.ledger_id = ledger_id;
        response.event_id = event.id.to_hex();
        response.timestamp = event.created_at.as_u64();

        tracing::trace!(
            "Received ledger response: request={}, status={}, event={}",
            &request_id[..16.min(request_id.len())],
            status,
            &event.id.to_hex()[..16]
        );
        // Note: action not available in response, using "unknown"
        metrics::record_response_received("unknown", response.success);

        Ok(response)
    }

    /// Process a ledger dispute event
    fn process_ledger_dispute(&self, event: &Event) -> Result<LedgerDispute, Error> {
        // Parse dispute from content
        let mut dispute: LedgerDispute = serde_json::from_str(&event.content)
            .map_err(|e| Error::Serialization(format!("Failed to parse dispute: {}", e)))?;

        dispute.event_id = event.id.to_hex();
        dispute.timestamp = event.created_at.as_u64();

        tracing::warn!(
            "Received ledger dispute: ledger={}, reason={}, from={}, event={}",
            dispute.ledger_id,
            dispute.reason,
            &dispute.disputer_pubkey[..16],
            &event.id.to_hex()[..16]
        );

        Ok(dispute)
    }

    fn process_fraud_proof(&self, event: &Event) -> Result<FraudProofEvent, Error> {
        let broadcast: deposits_core::fraud::FraudBroadcast = serde_json::from_str(&event.content)
            .map_err(|e| Error::Serialization(format!("Failed to parse fraud proof: {}", e)))?;

        // Structural verification (chain links connect properly)
        if let Err(e) = broadcast.verify_chain_structure() {
            return Err(Error::Protocol(format!("Invalid fraud proof chain: {}", e)));
        }

        tracing::warn!(
            "Received fraud proof: type={:?}, accused={}, ledger={}, from={}",
            broadcast.proof.proof_type,
            &broadcast.proof.accused[..16.min(broadcast.proof.accused.len())],
            &broadcast.proof.ledger_id[..16.min(broadcast.proof.ledger_id.len())],
            &event.pubkey.to_hex()[..16]
        );

        Ok(FraudProofEvent {
            broadcast,
            event_id: event.id.to_hex(),
            sender: event.pubkey.to_hex(),
        })
    }

    /// Receive the next inbound message (non-blocking)
    pub fn try_recv(&self) -> Option<InboundMessage> {
        self.inbound_rx.lock().unwrap().try_recv().ok()
    }

    /// Receive the next ledger update (non-blocking)
    pub fn try_recv_ledger_update(&self) -> Option<InboundLedgerUpdate> {
        self.ledger_rx.lock().unwrap().try_recv().ok()
    }

    /// Receive the next ledger request (non-blocking)
    pub fn try_recv_request(&self) -> Option<LedgerRequest> {
        self.request_rx.lock().unwrap().try_recv().ok()
    }

    /// Queue a request for processing (used by polling fallback)
    pub fn queue_request(&self, request: LedgerRequest) {
        let _ = self.request_tx.send(request);
    }

    /// Receive the next ledger response (non-blocking)
    pub fn try_recv_response(&self) -> Option<LedgerResponse> {
        self.response_rx.lock().unwrap().try_recv().ok()
    }

    /// Receive the next ledger dispute (non-blocking)
    pub fn try_recv_dispute(&self) -> Option<LedgerDispute> {
        self.dispute_rx.lock().unwrap().try_recv().ok()
    }

    pub fn try_recv_fraud_proof(&self) -> Option<FraudProofEvent> {
        self.fraud_proof_rx.lock().unwrap().try_recv().ok()
    }

    /// Disconnect from all relays
    pub async fn disconnect(&self) {
        self.client.disconnect().await.ok();
    }

    /// Get relay connection status: (connected_count, total_count, details)
    pub async fn relay_status(&self) -> (usize, usize, Vec<(String, String)>) {
        let relays = self.client.relays().await;
        let total = relays.len();
        let connected = relays.values()
            .filter(|r| r.status() == nostr_sdk::RelayStatus::Connected)
            .count();
        let details: Vec<_> = relays.iter()
            .map(|(url, r)| (url.to_string(), format!("{:?}", r.status())))
            .collect();
        (connected, total, details)
    }
}

/// Builder for NostrTransport with configuration options
pub struct NostrTransportBuilder {
    secret_key: SecretKey,
    relays: Vec<String>,
    slow_relays: Vec<String>,
    skip_nostr_verify: bool,
}

impl NostrTransportBuilder {
    pub fn new(secret_key: SecretKey) -> Self {
        Self {
            secret_key,
            relays: Vec::new(),
            slow_relays: Vec::new(),
            skip_nostr_verify: false,
        }
    }

    pub fn relay(mut self, url: impl Into<String>) -> Self {
        self.relays.push(url.into());
        self
    }

    pub fn relays(mut self, urls: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.relays.extend(urls.into_iter().map(|s| s.into()));
        self
    }

    pub fn slow_relay(mut self, url: impl Into<String>) -> Self {
        self.slow_relays.push(url.into());
        self
    }

    pub fn skip_nostr_verify(mut self, skip: bool) -> Self {
        self.skip_nostr_verify = skip;
        self
    }

    pub async fn build(self) -> Result<NostrTransport, Error> {
        NostrTransport::new_with_slow(self.secret_key, self.relays, self.slow_relays, self.skip_nostr_verify).await
    }
}
