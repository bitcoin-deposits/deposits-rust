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
//! - **Kind 9101**: Ledger requests (deposit_open, etc.)
//!   - Tag `l`: ledger_id (64-char hex hash)
//!   - Tag `action`: action name (e.g., "deposit_open")
//!   - Content: JSON with action parameters
//!
//! - **Kind 9102**: Ledger responses (replies to requests)
//!   - Tag `e`: reference to request event ID
//!   - Tag `l`: ledger_id
//!   - Tag `status`: "ok" or "error"
//!   - Content: JSON with result or error message
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

/// Track last advertisement timestamp to ensure monotonic ordering.
/// NIP-33 replaceable events use created_at to determine which event is "latest".
static LAST_AD_TIMESTAMP: AtomicU64 = AtomicU64::new(0);

/// Custom Kind for ledger updates.
/// Uses range 1000-9999 (regular custom events) to ensure relay storage.
/// Each update is a separate event that relays should retain.
pub const KIND_LEDGER_UPDATE: u16 = 9100;

/// Custom Kind for ledger requests (deposit_open, etc.)
/// Uses range 1000-9999 (regular custom events) for relay storage.
pub const KIND_LEDGER_REQUEST: u16 = 9101;

/// Custom Kind for ledger responses (replies to requests)
/// Uses range 1000-9999 (regular custom events) for relay storage.
pub const KIND_LEDGER_RESPONSE: u16 = 9102;

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

/// Default relay URLs for the network
/// Empty by default - relays should be explicitly configured
pub const DEFAULT_RELAYS: &[&str] = &[];

/// Nostr transport for deposits protocol messages
pub struct NostrTransport {
    /// The nostr client
    client: Client,

    /// Our keypair for signing/decryption
    keys: Keys,

    /// Our secp256k1 pubkey (same as deposits node ID)
    our_pubkey: PublicKey,

    /// Pending inbound messages (encrypted DMs)
    inbound_rx: mpsc::UnboundedReceiver<InboundMessage>,

    /// Sender for inbound messages (used by subscription task)
    inbound_tx: mpsc::UnboundedSender<InboundMessage>,

    /// Pending inbound ledger updates (broadcasts)
    ledger_rx: mpsc::UnboundedReceiver<InboundLedgerUpdate>,

    /// Sender for ledger updates
    ledger_tx: mpsc::UnboundedSender<InboundLedgerUpdate>,

    /// Pending inbound ledger requests
    request_rx: mpsc::UnboundedReceiver<LedgerRequest>,

    /// Sender for ledger requests
    request_tx: mpsc::UnboundedSender<LedgerRequest>,

    /// Pending inbound ledger responses
    response_rx: mpsc::UnboundedReceiver<LedgerResponse>,

    /// Sender for ledger responses
    response_tx: mpsc::UnboundedSender<LedgerResponse>,

    /// Pending inbound ledger disputes
    dispute_rx: mpsc::UnboundedReceiver<LedgerDispute>,

    /// Sender for ledger disputes
    dispute_tx: mpsc::UnboundedSender<LedgerDispute>,

    /// Peer pubkey mapping (secp256k1 -> nostr)
    peer_keys: RwLock<HashMap<PublicKey, nostr_sdk::PublicKey>>,

    /// Active subscriptions to prevent duplicates
    /// Key format: "type:id" e.g. "requests:abc123" or "disputes:abc123"
    active_subscriptions: RwLock<std::collections::HashSet<String>>,
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

    // === Deposit Limits ===

    /// Maximum single deposit size in sats
    pub max_deposit_sats: u64,

    /// Minimum deposit size in sats
    pub min_deposit_sats: u64,

    /// Maximum total balance per depositor in sats (0 = unlimited)
    #[serde(default)]
    pub max_balance_sats: u64,

    // === Trust Info ===

    // === Capacity ===

    /// Current total obligations (deposit balances) in sats
    #[serde(default)]
    pub total_obligations_sats: u64,

    /// Available headroom for new deposits in sats
    /// Calculated as: reserves_amount - total_obligations (or fraction thereof)
    #[serde(default)]
    pub available_headroom_sats: u64,

    // === Trust Info ===

    /// Number of quorum members
    pub quorum_size: u8,

    /// Block height when collateral requirements are enforced
    pub collateral_enforcement_block: u64,

    /// Current total reserves backing the ledger (sats)
    pub reserves_amount_sats: u64,

    /// Total received collateral from quorum members (sats)
    #[serde(default)]
    pub received_collateral_sats: u64,

    /// Quorum member details (pubkey, collateral amount, expiry block)
    #[serde(default)]
    pub quorum_members: Vec<QuorumMemberInfo>,

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
            max_deposit_sats: u64::MAX,
            min_deposit_sats: 0,
            max_balance_sats: 0,
            total_obligations_sats: 0,
            available_headroom_sats: 0,
            quorum_size: 0,
            collateral_enforcement_block: 0,
            reserves_amount_sats: 0,
            received_collateral_sats: 0,
            quorum_members: Vec::new(),
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
            annualized_fixed: self.min_fee_sats.saturating_mul(periods_per_year),
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
    /// Create a new Nostr transport
    pub async fn new(secret_key: SecretKey, relays: Vec<String>) -> Result<Self, Error> {
        // Convert secp256k1 key to nostr keys
        let secret_bytes = secret_key.secret_bytes();
        let nostr_secret = nostr_sdk::SecretKey::from_slice(&secret_bytes)
            .map_err(|e| Error::Nostr(format!("Invalid secret key: {}", e)))?;
        let keys = Keys::new(nostr_secret);

        // Get our secp256k1 pubkey
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let our_pubkey = PublicKey::from_secret_key(&secp, &secret_key);

        // Create nostr client with explicit connection options
        let opts = Options::default()
            .connection_timeout(Some(std::time::Duration::from_secs(30)));
        let client = Client::builder()
            .signer(keys.clone())
            .opts(opts)
            .build();

        // Add relays
        let relay_list: Vec<String> = if relays.is_empty() {
            DEFAULT_RELAYS.iter().map(|s| s.to_string()).collect()
        } else {
            relays
        };

        for relay in &relay_list {
            client
                .add_relay(relay)
                .await
                .map_err(|e| Error::Nostr(format!("Failed to add relay {}: {}", relay, e)))?;
        }

        // Connect to relays with explicit timeout
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

        // Create channels for inbound messages, ledger updates, requests, responses, and disputes
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
        let (ledger_tx, ledger_rx) = mpsc::unbounded_channel();
        let (request_tx, request_rx) = mpsc::unbounded_channel();
        let (response_tx, response_rx) = mpsc::unbounded_channel();
        let (dispute_tx, dispute_rx) = mpsc::unbounded_channel();

        Ok(Self {
            client,
            keys,
            our_pubkey,
            inbound_rx,
            inbound_tx,
            ledger_rx,
            ledger_tx,
            request_rx,
            request_tx,
            response_rx,
            response_tx,
            dispute_rx,
            dispute_tx,
            peer_keys: RwLock::new(HashMap::new()),
            active_subscriptions: RwLock::new(std::collections::HashSet::new()),
        })
    }

    /// Get our secp256k1 public key (node ID)
    pub fn our_pubkey(&self) -> PublicKey {
        self.our_pubkey
    }

    /// Get a reference to the underlying Nostr client
    pub fn client(&self) -> &Client {
        &self.client
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
        self.client
            .send_event(event)
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
        let event = EventBuilder::new(Kind::Custom(KIND_LEDGER_UPDATE), &content)
            .tag(Tag::custom(
                TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::D)),
                [&ledger_id],
            ))
            .tag(Tag::custom(
                TagKind::custom("seq"),
                [update.sequence_number.to_string()],
            ))
            .tag(Tag::custom(
                TagKind::custom("prev"),
                [hex::encode(update.previous_hash)],
            ))
            .tag(Tag::custom(
                TagKind::custom("hash"),
                [hex::encode(update.current_hash)],
            ))
            .sign_with_keys(&self.keys)
            .map_err(|e| Error::Nostr(format!("Failed to sign event: {}", e)))?;

        let event_id = event.id.to_hex();

        // Broadcast
        self.client
            .send_event(event)
            .await
            .map_err(|e| Error::Nostr(format!("Failed to broadcast ledger update: {}", e)))?;

        tracing::info!(
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
                SingleLetterTag::lowercase(Alphabet::D),
                [ledger_id],
            );

        self.client
            .subscribe(vec![filter], None)
            .await
            .map_err(|e| Error::Nostr(format!("Failed to subscribe to ledger: {}", e)))?;

        // Mark as subscribed
        self.active_subscriptions.write().unwrap().insert(sub_key);

        tracing::info!("Subscribed to ledger updates: {}", ledger_id);
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

        tracing::info!("Subscribed to ledger updates from operator: {}", operator_pubkey);
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
                TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::L)),
                [ledger_id],
            ))
            .tag(Tag::custom(
                TagKind::custom("action"),
                [action],
            ))
            .sign_with_keys(&self.keys)
            .map_err(|e| Error::Nostr(format!("Failed to sign event: {}", e)))?;

        let event_id = event.id.to_hex();

        self.client
            .send_event(event)
            .await
            .map_err(|e| Error::Nostr(format!("Failed to send request: {}", e)))?;

        tracing::info!(
            "Sent ledger request: ledger={}, action={}, event={}",
            ledger_id,
            action,
            &event_id[..16]
        );

        Ok(event_id)
    }

    /// Send a ledger response (reply to a request)
    pub async fn send_ledger_response(
        &self,
        request_id: &str,
        ledger_id: &str,
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
                TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::E)),
                [request_id],
            ))
            .tag(Tag::custom(
                TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::L)),
                [ledger_id],
            ))
            .tag(Tag::custom(
                TagKind::custom("status"),
                [status],
            ))
            .sign_with_keys(&self.keys)
            .map_err(|e| Error::Nostr(format!("Failed to sign event: {}", e)))?;

        let event_id = event.id.to_hex();

        self.client
            .send_event(event)
            .await
            .map_err(|e| Error::Nostr(format!("Failed to send response: {}", e)))?;

        tracing::info!(
            "Sent ledger response: request={}, status={}, event={}",
            &request_id[..16],
            status,
            &event_id[..16]
        );

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
                TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::D)),
                [ledger_id],
            ))
            .tag(Tag::custom(
                TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::L)),
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

        self.client
            .send_event(event)
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
                SingleLetterTag::lowercase(Alphabet::L),
                [ledger_id],
            )
            .since(since);

        self.client
            .subscribe(vec![filter], None)
            .await
            .map_err(|e| Error::Nostr(format!("Failed to subscribe to disputes: {}", e)))?;

        // Mark as subscribed
        self.active_subscriptions.write().unwrap().insert(sub_key);

        tracing::info!("Subscribed to disputes for ledger: {}", ledger_id);
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

        tracing::info!("Subscribed to all ledger disputes (kind {})", KIND_LEDGER_DISPUTE);
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

        // Check which ledgers we haven't subscribed to disputes yet
        // (requests use a single global subscription, disputes are per-ledger)
        let mut new_dispute_ledgers: Vec<&String> = Vec::new();
        let needs_request_sub: bool;
        {
            let subs = self.active_subscriptions.read().unwrap();
            needs_request_sub = !subs.contains("requests:global");
            for lid in ledger_ids {
                let dis_key = format!("disputes:{}", lid);
                if !subs.contains(&dis_key) {
                    new_dispute_ledgers.push(lid);
                }
            }
        }

        if !needs_request_sub && new_dispute_ledgers.is_empty() {
            tracing::debug!("All {} ledgers already subscribed", ledger_ids.len());
            return Ok(());
        }

        // Build filters for new subscriptions
        let since = nostr_sdk::Timestamp::now() - 30;
        let mut filters = Vec::new();

        // Add global request filter if not already subscribed
        if needs_request_sub {
            filters.push(
                Filter::new()
                    .kind(Kind::Custom(KIND_LEDGER_REQUEST))
                    .since(since)
            );
        }

        // Per-ledger dispute filters (relay filters by tag)
        for lid in &new_dispute_ledgers {
            filters.push(
                Filter::new()
                    .kind(Kind::Custom(KIND_LEDGER_DISPUTE))
                    .custom_tag(
                        SingleLetterTag::lowercase(Alphabet::L),
                        [lid.as_str()],
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
            if needs_request_sub {
                subs.insert("requests:global".to_string());
            }
            for lid in &new_dispute_ledgers {
                subs.insert(format!("disputes:{}", lid));
            }
        }

        tracing::info!("Batch subscribed to {} ledgers ({} filters)", new_dispute_ledgers.len(), filter_count);
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
                TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::D)),
                [ledger_id],
            ))
            .tag(Tag::custom(
                TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::L)),
                [ledger_id],
            ))
            .tag(Tag::custom(
                TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::E)),
                [dispute_event_id],
            ))
            .tag(Tag::custom(
                TagKind::custom("member"),
                [&member_pubkey],
            ))
            .sign_with_keys(&self.keys)
            .map_err(|e| Error::Nostr(format!("Failed to sign event: {}", e)))?;

        let event_id = event.id.to_hex();

        self.client
            .send_event(event)
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
                SingleLetterTag::lowercase(Alphabet::E),
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
                TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::D)),
                [ad.ledger_id.as_str()],
            ))
            .tag(Tag::custom(
                TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::N)),
                [ad.network.as_str()],
            ))
            .tag(Tag::custom(
                TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::O)),
                [ad.operator_pubkey.as_str()],
            ))
            .sign_with_keys(&self.keys)
            .map_err(|e| Error::Nostr(format!("Failed to sign event: {}", e)))?;

        let event_id = event.id.to_hex();

        self.client
            .send_event(event)
            .await
            .map_err(|e| Error::Nostr(format!("Failed to send advertisement: {}", e)))?;

        tracing::info!(
            "Published ledger advertisement: ledger={}, event={}",
            &ad.ledger_id[..16.min(ad.ledger_id.len())],
            &event_id[..16]
        );

        Ok(event_id)
    }

    /// Get the timestamp of an existing advertisement for a ledger
    async fn get_advertisement_timestamp(&self, ledger_id: &str) -> Option<u64> {
        let filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_ADVERTISE))
            .custom_tag(
                SingleLetterTag::lowercase(Alphabet::D),
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
                SingleLetterTag::lowercase(Alphabet::N),
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

    /// Fetch a specific ledger's advertisement
    pub async fn fetch_ledger_advertisement(
        &self,
        ledger_id: &str,
    ) -> Result<Option<LedgerAdvertisement>, Error> {
        let filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_ADVERTISE))
            .custom_tag(
                SingleLetterTag::lowercase(Alphabet::D),
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
                SingleLetterTag::lowercase(Alphabet::L),
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

    /// Subscribe to ledger requests for a specific ledger (for operators)
    pub async fn subscribe_to_requests(&self, ledger_id: &str) -> Result<(), Error> {
        // Check if already subscribed to requests (global subscription, filter by ledger in handler)
        let sub_key = "requests:global".to_string();
        {
            let subs = self.active_subscriptions.read().unwrap();
            if subs.contains(&sub_key) {
                tracing::debug!("Already subscribed to requests, skipping (for ledger {})", ledger_id);
                return Ok(());
            }
        }

        // Subscribe to ALL requests of this kind (filter by ledger_id in handler)
        // This avoids potential issues with custom tag filters on some relays
        // Include a 30-second lookback to catch any events sent before subscription was established
        let since = nostr_sdk::Timestamp::now() - 30;
        let filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_REQUEST))
            .since(since);

        self.client
            .subscribe(vec![filter], None)
            .await
            .map_err(|e| Error::Nostr(format!("Failed to subscribe to requests: {}", e)))?;

        // Mark as subscribed
        self.active_subscriptions.write().unwrap().insert(sub_key);

        tracing::info!("Subscribed to ledger requests (kind {}), filtering for: {}", KIND_LEDGER_REQUEST, ledger_id);
        Ok(())
    }

    /// Fetch recent ledger requests (polling fallback)
    pub async fn fetch_recent_requests(&self, since_secs: u64) -> Result<Vec<LedgerRequest>, Error> {
        use nostr_sdk::Timestamp;

        let since = Timestamp::now() - since_secs;
        let filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_REQUEST))
            .since(since);

        let events = self.client
            .fetch_events(vec![filter], Some(tokio::time::Duration::from_secs(5)))
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

    /// Subscribe to responses for a specific request (for requesters)
    /// Note: strfry doesn't support #e tag filtering on custom kinds well,
    /// so we subscribe to ALL responses and filter locally in handle_notification
    pub async fn subscribe_to_response(&self, _request_id: &str) -> Result<(), Error> {
        // Use a single global subscription for all responses
        // (strfry has issues with custom tag filtering on non-standard kinds)
        let sub_key = "responses:all".to_string();
        {
            let subs = self.active_subscriptions.read().unwrap();
            if subs.contains(&sub_key) {
                return Ok(());
            }
        }

        // Include lookback to catch responses sent before subscription was active
        let since = nostr_sdk::Timestamp::now() - 30;

        let filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_RESPONSE))
            .since(since);

        self.client
            .subscribe(vec![filter], None)
            .await
            .map_err(|e| Error::Nostr(format!("Failed to subscribe to responses: {}", e)))?;

        // Mark as subscribed
        self.active_subscriptions.write().unwrap().insert(sub_key);

        tracing::info!("Subscribed to all ledger responses (kind {})", KIND_LEDGER_RESPONSE);
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

        let events = self.client
            .fetch_events(vec![filter], Some(tokio::time::Duration::from_secs(5)))
            .await
            .map_err(|e| Error::Nostr(format!("Failed to fetch events: {}", e)))?;

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

    /// Fetch all responses since a timestamp
    pub async fn fetch_responses_since(&self, _since: nostr_sdk::Timestamp) -> Result<Vec<LedgerResponse>, Error> {
        // Ignore 'since' and use a fixed 5-minute lookback to avoid timestamp sync issues
        // The strfry relay may have clock drift or event ordering issues with recent events
        let since = nostr_sdk::Timestamp::now() - 300;
        let filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_RESPONSE))
            .since(since);

        let events = self.client
            .fetch_events(vec![filter], Some(tokio::time::Duration::from_secs(5)))
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

        Ok(())
    }

    /// Process incoming events (call this in a loop)
    /// This awaits on the notification channel with a timeout
    pub async fn process_events(&mut self) -> Result<(), Error> {
        // Wait for a notification with timeout
        let timeout = tokio::time::Duration::from_millis(500);
        match tokio::time::timeout(timeout, self.client.notifications().recv()).await {
            Ok(Ok(notification)) => {
                tracing::debug!("Received notification: {:?}", notification);
                self.handle_notification(notification);
                // Drain any additional pending notifications without blocking
                while let Ok(notification) = self.client.notifications().try_recv() {
                    self.handle_notification(notification);
                }
            }
            Ok(Err(_)) => {
                // Channel closed or lagged
                tracing::debug!("Notification channel error");
            }
            Err(_) => {
                // Timeout - no notification received, that's ok
            }
        }
        Ok(())
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

    /// Handle a single notification
    fn handle_notification(&self, notification: RelayPoolNotification) {
        if let RelayPoolNotification::Event { event, .. } = notification {
            // Use numeric kind value for comparison since Kind::Custom(n) and Kind::Regular(n)
            // are different enum variants but represent the same kind number
            let kind_num = event.kind.as_u16();

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
            }
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
        // Extract ledger_id from the d tag
        let ledger_id = event
            .tags
            .iter()
            .find_map(|tag| {
                if tag.kind() == TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::D)) {
                    tag.content().map(|s| s.to_string())
                } else {
                    None
                }
            })
            .ok_or_else(|| Error::Nostr("Missing d tag in ledger update".to_string()))?;

        // Decode content from base64
        let tlv_bytes = BASE64
            .decode(&event.content)
            .map_err(|e| Error::Serialization(format!("Invalid base64 in ledger update: {}", e)))?;

        // Decode TLV to SignedLedgerUpdate
        let update = SignedLedgerUpdate::tlv_decode(&tlv_bytes)
            .map_err(|e| Error::Serialization(format!("Failed to decode ledger update: {:?}", e)))?;

        tracing::debug!(
            "Received ledger update: ledger={}, seq={}, hash={}",
            ledger_id,
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
                if tag.kind() == TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::L)) {
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

        tracing::debug!(
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
                if tag.kind() == TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::E)) {
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
                if tag.kind() == TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::L)) {
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

        tracing::debug!(
            "Received ledger response: request={}, status={}, event={}",
            &request_id[..16.min(request_id.len())],
            status,
            &event.id.to_hex()[..16]
        );

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

    /// Receive the next inbound message (non-blocking)
    pub fn try_recv(&mut self) -> Option<InboundMessage> {
        self.inbound_rx.try_recv().ok()
    }

    /// Receive the next inbound message (blocking)
    pub async fn recv(&mut self) -> Option<InboundMessage> {
        self.inbound_rx.recv().await
    }

    /// Receive the next ledger update (non-blocking)
    pub fn try_recv_ledger_update(&mut self) -> Option<InboundLedgerUpdate> {
        self.ledger_rx.try_recv().ok()
    }

    /// Receive the next ledger update (blocking)
    pub async fn recv_ledger_update(&mut self) -> Option<InboundLedgerUpdate> {
        self.ledger_rx.recv().await
    }

    /// Receive the next ledger request (non-blocking)
    pub fn try_recv_request(&mut self) -> Option<LedgerRequest> {
        self.request_rx.try_recv().ok()
    }

    /// Queue a request for processing (used by polling fallback)
    pub fn queue_request(&self, request: LedgerRequest) {
        let _ = self.request_tx.send(request);
    }

    /// Receive the next ledger request (blocking)
    pub async fn recv_request(&mut self) -> Option<LedgerRequest> {
        self.request_rx.recv().await
    }

    /// Receive the next ledger response (non-blocking)
    pub fn try_recv_response(&mut self) -> Option<LedgerResponse> {
        self.response_rx.try_recv().ok()
    }

    /// Receive the next ledger response (blocking)
    pub async fn recv_response(&mut self) -> Option<LedgerResponse> {
        self.response_rx.recv().await
    }

    /// Receive the next ledger dispute (non-blocking)
    pub fn try_recv_dispute(&mut self) -> Option<LedgerDispute> {
        self.dispute_rx.try_recv().ok()
    }

    /// Receive the next ledger dispute (blocking)
    pub async fn recv_dispute(&mut self) -> Option<LedgerDispute> {
        self.dispute_rx.recv().await
    }

    /// Disconnect from all relays
    pub async fn disconnect(&self) {
        self.client.disconnect().await.ok();
    }
}

/// Builder for NostrTransport with configuration options
pub struct NostrTransportBuilder {
    secret_key: SecretKey,
    relays: Vec<String>,
}

impl NostrTransportBuilder {
    pub fn new(secret_key: SecretKey) -> Self {
        Self {
            secret_key,
            relays: Vec::new(),
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

    pub async fn build(self) -> Result<NostrTransport, Error> {
        NostrTransport::new(self.secret_key, self.relays).await
    }
}
