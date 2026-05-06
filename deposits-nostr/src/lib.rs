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

use ::base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use bitcoin::secp256k1::{PublicKey, SecretKey};
use deposits_protocol::messages::DepositsMessage;
use deposits_protocol::tlv::{TlvDecode, TlvEncode};
use deposits_protocol::types::SignedLedgerUpdate;
use nostr_sdk::prelude::*;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use tokio::sync::mpsc;

/// Install `ring` as the process-wide rustls `CryptoProvider`.
/// rustls 0.23+ refuses to auto-pick a provider even with a single
/// feature enabled — the first TLS handshake panics with
/// "Could not automatically determine the process-level CryptoProvider".
/// Every binary that uses [`NostrTransport`] over `wss://` must call
/// this once at startup, before any relay connection. It's idempotent:
/// if a provider is already installed (by this call or by the
/// consumer), the second attempt is silently ignored.
pub fn install_default_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Errors surfaced by the Nostr transport. Kept narrow on purpose —
/// the daemon's catch-all `Error` type wraps this via `#[from]`, while
/// wallet-side callers match on these variants directly without
/// pulling in the rest of `deposits-node`.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Nostr error: {0}")]
    Nostr(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Protocol error: {0}")]
    Protocol(String),
}

/// Tiny in-crate metrics façade. Each call expands to one `metrics`
/// crate macro invocation; with no recorder registered they're cheap
/// no-ops so wallet-side consumers don't pay anything. The daemon
/// registers a `metrics-exporter-prometheus` recorder and these get
/// picked up automatically.
mod metrics {
    use std::time::Duration;

    pub fn record_broadcast_lag(receiver: &str, dropped: u64) {
        ::metrics::counter!(
            "broadcast_channel_lag_total",
            "receiver" => receiver.to_string()
        )
        .increment(1);
        ::metrics::counter!(
            "broadcast_channel_lag_events_total",
            "receiver" => receiver.to_string()
        )
        .increment(dropped);
    }

    pub fn record_notification_drain_count(count: u32) {
        ::metrics::histogram!("notification_drain_count").record(count as f64);
    }

    pub fn record_notification_dedup_skipped(count: u32) {
        ::metrics::counter!("notification_dedup_skipped_total").increment(count as u64);
    }

    pub fn record_nostr_publish(duration: Duration) {
        ::metrics::histogram!("nostr_publish_seconds").record(duration.as_secs_f64());
    }

    pub fn record_connection() {
        ::metrics::counter!("nostr_connections_total").increment(1);
        ::metrics::gauge!("nostr_connections_active").increment(1.0);
    }

    pub fn set_active_connections(count: usize) {
        ::metrics::gauge!("nostr_connections_active").set(count as f64);
    }

    pub fn record_request_sent(action: &str) {
        ::metrics::counter!(
            "nostr_requests_sent_total",
            "action" => action.to_string()
        )
        .increment(1);
    }

    pub fn record_response_sent(action: &str, success: bool) {
        let status = if success { "success" } else { "error" };
        ::metrics::counter!(
            "nostr_responses_sent_total",
            "action" => action.to_string(),
            "status" => status
        )
        .increment(1);
    }

    pub fn record_response_received(action: &str, success: bool) {
        let status = if success { "success" } else { "error" };
        ::metrics::counter!(
            "nostr_responses_received_total",
            "action" => action.to_string(),
            "status" => status
        )
        .increment(1);
    }
}

/// A received fraud proof broadcast from a wallet.
#[derive(Clone, Debug)]
pub struct FraudProofEvent {
    /// The fraud broadcast (proof + embedding + causal chain).
    pub broadcast: deposits_protocol::fraud::FraudBroadcast,
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

/// Custom Kind for custody-lottery preimage reveals.
/// Uses range 1000-9999 for relay storage — other disputants must be able
/// to fetch all reveals to compute the lottery winner. Published by each
/// disputant during the reveal phase after `recovery confiscate` lands the
/// lottery output on chain. The preimage is the secret committed via the
/// `commitment_hash` field of an earlier `DisputeArmed`.
pub const KIND_CUSTODY_LOTTERY_REVEAL: u16 = 9106;

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

/// Custom Kind for open swap advertisement (bilateral peer-swap bootstrap).
/// Uses NIP-33 parameterized replaceable events (30000-39999).
/// Tag `d` = source_deposit_id ensures one ad per deposit per author.
/// Content: JSON with source ledger/deposit, available amount, desired
/// destination ledgers (preference hint, not a whitelist), and swap fees.
pub const KIND_SWAP_ADVERTISE: u16 = 39103;

/// Ephemeral swap-request event: taker → maker, proposing a specific swap
/// against a published SwapAdvertisement. Addressed via #p = maker_pubkey.
pub const KIND_SWAP_REQUEST: u16 = 20103;

/// Ephemeral swap-response event: maker → taker, accepting or rejecting a
/// swap_request. Addressed via #p = taker_pubkey and #e = request event id.
pub const KIND_SWAP_RESPONSE: u16 = 20104;

/// Lightning-verify request: gift-wrapped ephemeral event addressed to the
/// `attestation_verifier` service. Content is JSON (lightning_address on
/// round one, `{action: "challenge", session_id}` / `{action: "verify",
/// session_id, amounts}` on later rounds).
pub const KIND_LIGHTNING_VERIFY_REQUEST: u16 = 25500;

/// Lightning-verify response: gift-wrapped reply addressed back to the
/// requester via #e tag on the outer wrap (matches the request's outer
/// event id, same convention as `send_admin_request`).
pub const KIND_LIGHTNING_VERIFY_RESPONSE: u16 = 25501;

/// Subkey-list event (DEP-04 §"Subkey Attestation"): replaceable event
/// authored by the root/account pubkey, listing currently-authorized
/// subkeys (`inbox_keys`) and revoked ones (`revoked_subkeys`). The
/// per-subkey attestation signature is carried by the subkey's own
/// events via `["va", "<sig>"]`; this event is the policy index that
/// verifiers consult to distinguish active from revoked delegations.
pub const KIND_SUBKEY_LIST: u16 = 10301;

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

    /// Daemon's *delegate* Nostr pubkey. Populated via `set_delegate_pubkey`
    /// at startup. Today: filled into `LedgerAdvertisement.delegate_pubkey`
    /// before publish, so wallets discover where to address messages.
    delegate_pubkey: std::sync::Mutex<Option<PublicKey>>,

    /// Operator's protocol-level Nostr pubkey (xonly form, derived from
    /// the operator secp256k1 pubkey). Populated via
    /// `set_operator_pubkey` at startup. Used for:
    ///  - The fallback NIP-04 decrypt path (when an inbound DM is
    ///    encrypted to operator and the daemon's `self.keys` is the
    ///    delegate, the daemon asks `self.signer` for a NIP-04 shared
    ///    key against this pubkey).
    ///  - Filters that target advertisements (always operator-authored).
    operator_pubkey: std::sync::Mutex<Option<nostr_sdk::PublicKey>>,

    /// Signer for operator-key signs/ECDH. Used to sign Kind 39100
    /// advertisements (which must stay operator-authored even when
    /// `self.keys` is the delegate) and to perform the fallback NIP-04
    /// decrypt against the operator key. None when the daemon was
    /// constructed without a Signer (legacy paths in tests). Only
    /// present when the `signer` feature is enabled.
    #[cfg(feature = "signer")]
    signer: std::sync::Mutex<Option<std::sync::Arc<dyn deposits_signer_api::Signer>>>,

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
    daemon_notification_rx:
        std::sync::Mutex<Option<tokio::sync::broadcast::Receiver<RelayPoolNotification>>>,

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

    /// If gift-wrapped: real sender pubkey (for encrypting response back)
    #[serde(skip)]
    pub gift_wrap_sender: Option<String>,

    /// DEP-04 subkey delegation — account pubkey (xonly hex) the sender
    /// is acting on behalf of. Sourced from the event's `["v", "<hex>"]`
    /// tag. When present alongside `subkey_attestation`, handlers resolve
    /// access-control checks against this pubkey rather than `sender`.
    #[serde(skip)]
    pub subkey_account: Option<String>,

    /// DEP-04 attestation signature — BIP-340 Schnorr over
    /// `SHA256("nostr301:" + sender)`, signed by `subkey_account`.
    /// Sourced from `["va", "<hex>"]`.
    #[serde(skip)]
    pub subkey_attestation: Option<String>,
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

/// A custody-lottery preimage reveal (one disputant publishing their
/// secret during the reveal phase). Other disputants fetch all reveals
/// for the same dispute to compute the lottery winner via
/// `LotteryOutput::calculate_winner`.
///
/// Published as a Nostr event of `KIND_CUSTODY_LOTTERY_REVEAL` (9106).
/// The event's pubkey identifies the revealing disputant; the
/// `member_pubkey` field in the content is included for ergonomic
/// JSON parsing without needing to cross-reference event metadata.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CustodyLotteryReveal {
    /// The revealing disputant's secp256k1 pubkey (hex).
    pub member_pubkey: String,

    /// Ledger identifier this reveal applies to.
    pub ledger_id: String,

    /// The preimage bytes, hex-encoded. Length must be 17..=(16+N)
    /// where N is the dispute's disputant count; HASH160 of these
    /// bytes equals the `commitment_hash` from the disputant's
    /// `DisputeArmed`.
    pub preimage_hex: String,

    /// Schnorr signature over the reveal (member binds the preimage
    /// to their identity, hex).
    pub signature: String,

    /// Nostr event ID of this reveal.
    #[serde(skip)]
    pub event_id: String,

    /// Timestamp.
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

/// AES-256-CBC decrypt with a precomputed NIP-04 shared key.
///
/// Mirrors `nostr/nips/nip04.rs::decrypt_to_bytes` but takes the shared
/// key as input rather than deriving it from a `SecretKey`. Used by the
/// NIP-04 fallback decrypt path on `NostrTransport` — when the daemon's
/// `self.keys` (delegate) can't decrypt an inbound DM, it asks the
/// `Signer` for an operator-key NIP-04 shared key, then routes the
/// AES-CBC half through this helper.
fn nip04_decrypt_with_shared_key(
    shared_key: &[u8; 32],
    ciphertext: &str,
) -> Result<String, &'static str> {
    use aes::cipher::block_padding::Pkcs7;
    use aes::cipher::{BlockDecryptMut, KeyIvInit};
    use ::base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

    let parts: Vec<&str> = ciphertext.split("?iv=").collect();
    if parts.len() != 2 {
        return Err("NIP-04: invalid ciphertext format (no `?iv=`)");
    }
    let ct = B64.decode(parts[0]).map_err(|_| "NIP-04: ciphertext not base64")?;
    let iv = B64.decode(parts[1]).map_err(|_| "NIP-04: iv not base64")?;
    if iv.len() != 16 {
        return Err("NIP-04: iv must be 16 bytes");
    }
    let cipher = Aes256CbcDec::new(shared_key.into(), iv.as_slice().into());
    let plaintext_bytes = cipher
        .decrypt_padded_vec_mut::<Pkcs7>(&ct)
        .map_err(|_| "NIP-04: AES-CBC decrypt / unpadding failed")?;
    String::from_utf8(plaintext_bytes).map_err(|_| "NIP-04: plaintext not UTF-8")
}

/// A ledger advertisement (operator terms and limits)
/// Published as a NIP-33 parameterized replaceable event.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LedgerAdvertisement {
    /// Ledger identifier (64-char hex hash)
    pub ledger_id: String,

    /// Operator's secp256k1 pubkey (hex). The trust anchor: wallets verify
    /// the advertisement's outer Nostr event signature against this key.
    /// Slashing and on-chain custody flow from this identity.
    pub operator_pubkey: String,

    /// **Delegate Nostr pubkey** (33-byte compressed secp256k1, hex). The
    /// daemon publishes this advertisement signed by `operator_pubkey`
    /// (the outer Nostr event author + sig), but every other Nostr-layer
    /// op — Kind 9100 ledger updates, NIP-04 DM recipient, gift-wrap
    /// envelopes — uses this delegate key. Wallets that follow the
    /// delegation address messages to `delegate_pubkey` while still
    /// trusting `operator_pubkey` as the protocol-level identity.
    ///
    /// Empty (`""`) on advertisements published by older daemons that
    /// haven't been moved off the "operator key for everything" model.
    /// Wallets seeing an empty `delegate_pubkey` should fall back to
    /// `operator_pubkey` for messaging — the key is always sound, just
    /// less leak-resistant on the daemon's host.
    #[serde(default)]
    pub delegate_pubkey: String,

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

    /// Annualized fixed periodic fee in msats. Combines with
    /// `annual_fee_bps` to form the protocol-level `FeeStructure`
    /// (`annualized_msats` half). The actual quorum-join floors
    /// live on `quorum add` (`--min-fee-bps`, `--min-fee-fixed`),
    /// not here — this field is the operator's *charged* fixed fee.
    ///
    /// Hard-broken from the old `min_fee_sats` field (per-period
    /// sats with implicit ×periods/year ×1000 conversion). Old
    /// JSON ads will deserialize with this field defaulted to 0.
    #[serde(default)]
    pub annualized_fixed_msats: u64,

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
    /// Maximum single deposit size in msats
    pub max_deposit_msats: u64,

    /// Minimum deposit size in msats
    pub min_deposit_msats: u64,

    /// Per-deposit balance cap (msats). 0 = unlimited. Operator-side
    /// enforcement of `MAX_DEPOSIT_BALANCE_MSATS`; surfaced here so
    /// wallets and lnurl gateways can clamp `maxSendable` (or refuse a
    /// credit that'd push the balance past the cap) before paying. The
    /// gateway in particular reflects this into the LNURL metadata
    /// response so a depositor sees the cap before constructing an
    /// invoice that'd be rejected.
    #[serde(default)]
    pub max_deposit_balance_msats: u64,

    // === Trust Info ===
    //
    // NOTE: historically carried `total_obligations_msats` and
    // `available_headroom_msats` too. Both were dropped — they're
    // trivially inflatable by the operator via self-paid Lightning
    // invoices (see the over-reserves bootstrap pattern), so they
    // aren't reliable trust signals. Wallets that need capacity
    // information should either (a) discover a courier who already
    // holds funds on this ledger, or (b) trust the protocol invariant
    // `reserves ≥ obligations` enforced by the quorum's co-signers.
    /// Current total reserves backing the ledger (msats). Mirrors the
    /// `reserves_amount_msats` declared on this ledger's most recent
    /// `LedgerOpen` / `QuorumBegin` (DEP-02).
    pub reserves_amount_msats: u64,

    /// Operator-declared collateral on this ledger (msats). The non-reserves
    /// portion of the operator's on-chain UTXO; forfeit on proven
    /// non-conformance (DEP-05). Mirrors `collateral_amount_msats` on the
    /// most recent `LedgerOpen` / `QuorumBegin`.
    #[serde(default)]
    pub collateral_amount_msats: u64,

    // === Connectivity ===
    /// Relay URL where this operator publishes responses
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_url: Option<String>,

    /// Whether deposit access control is enabled (deposits may require attestation).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub access_control: bool,

    /// Lightning address domains accepted for attestation-based deposit access.
    /// Empty = domain check not used (npub allowlist only).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_domains: Vec<String>,

    // === Metadata ===
    /// Network (bitcoin, testnet, signet, regtest)
    pub network: String,

    /// Operator's observed Bitcoin chain tip at publish time.
    /// Lets wallets pick timeouts without a separate `balance_query` round-trip.
    #[serde(default)]
    pub current_block: u32,

    /// Current quorum state. `"PreQuorum"` for ledgers that have a
    /// `LedgerOpen` but no `QuorumBegin` yet (provisional, no on-chain
    /// commitment yet — wallets should ignore these). `"Active"` once
    /// the genesis QuorumBegin lands. `"Expired"` if the active quorum
    /// passed its expiry without a re-rotation.
    #[serde(default)]
    pub quorum_state: String,

    /// Active quorum cosigners (operator NOT included). Hex-encoded
    /// 33-byte compressed secp256k1 pubkeys. Empty when
    /// `quorum_state == PreQuorum`. `Q == quorum_members.len()`.
    /// Wallets use this to verify which operators back this ledger
    /// — quorum membership is public chain state, not a secret.
    #[serde(default)]
    pub quorum_members: Vec<String>,

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

fn default_version() -> u8 {
    1
}

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

/// Open swap advertisement (Kind 39103).
///
/// Published by a wallet holding a deposit on one ledger, signaling openness
/// to bilateral peer-swaps into other ledgers. Unlike `AgentAdvertisement`
/// (which frames the publisher as routing infrastructure), a swap ad is a
/// one-shot availability signal — "I have funds on X, I'd like Y or Z."
///
/// `desired_ledgers` is a preference hint, not a whitelist: a taker may still
/// ask to swap into an unlisted ledger and the maker decides at negotiation
/// time.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SwapAdvertisement {
    /// Maker's Nostr pubkey (hex).
    pub maker_pubkey: String,

    /// Network (bitcoin, testnet, signet, regtest).
    pub network: String,

    /// Ledger where the maker holds the source funds.
    pub source_ledger: String,

    /// Source deposit ID (hex, 32 chars / 16 bytes).
    pub source_deposit_id: String,

    /// How much the maker is willing to swap out of `source_deposit_id` (msats).
    pub available_msats: u64,

    /// Ledgers the maker would prefer to receive on. Empty = no preference;
    /// taker can propose any destination and maker decides at negotiation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub desired_ledgers: Vec<String>,

    /// Flat swap fee in msats (charged by the maker on top of the amount).
    #[serde(default)]
    pub fee_fixed_msats: u64,

    /// Proportional swap fee in basis points.
    #[serde(default)]
    pub fee_rate_bps: u16,

    /// Per-swap minimum (msats).
    #[serde(default)]
    pub min_swap_msats: u64,

    /// Per-swap maximum (msats). 0 = no cap.
    #[serde(default)]
    pub max_swap_msats: u64,

    /// Relay where the maker listens for `swap_request` events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_url: Option<String>,

    /// Unix timestamp after which this ad should be ignored. 0 = no expiry.
    #[serde(default)]
    pub expires_at: u64,

    /// Optional human-readable note (e.g. "offline after 5pm UTC").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,

    /// Nostr event ID of this advertisement.
    #[serde(skip)]
    pub event_id: String,

    /// Timestamp when published.
    #[serde(skip)]
    pub timestamp: u64,
}

/// A taker's proposal to execute a specific swap against a SwapAdvertisement.
/// Published as Kind 20103 (ephemeral), signed by the taker, and addressed
/// to the maker via a #p tag.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SwapRequest {
    /// Event ID of the SwapAdvertisement this request references.
    pub swap_ad_event_id: String,
    /// Amount the taker wants to swap (msats out of the ad's source deposit).
    pub amount_msats: u64,
    /// sha256(preimage) — only the taker knows the preimage until reveal.
    pub hash_hex: String,
    /// Ledger the taker is offering on their side (the "right" leg).
    pub taker_source_ledger: String,
    /// Taker's deposit on `taker_source_ledger` that will fund the right leg.
    pub taker_source_deposit_id: String,
    /// Taker's deposit on the ad's source_ledger where they want to receive.
    pub taker_dest_deposit_id: String,
    /// Relay where the taker will listen for the response.
    pub relay_url: String,
    /// Nostr event ID of this request.
    #[serde(skip)]
    pub event_id: String,
    /// Event author (= taker pubkey, hex).
    #[serde(skip)]
    pub taker_pubkey: String,
    /// Timestamp when the request was published.
    #[serde(skip)]
    pub timestamp: u64,
}

/// A maker's response to a SwapRequest. Published as Kind 20104 (ephemeral),
/// signed by the maker, addressed via #p = taker_pubkey and #e = request id.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SwapResponse {
    /// Event ID of the SwapRequest this responds to.
    pub request_event_id: String,
    /// Whether the maker accepts the proposed swap.
    pub accepted: bool,
    /// Human-readable reject reason (present when `accepted == false`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Maker's deposit on the taker's source ledger (destination of the right
    /// leg). Present iff `accepted`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maker_dest_deposit_id: Option<String>,
    /// Maker's intended timeout for the left leg (blocks in the future).
    /// Maker locks on source_ledger with this timeout.
    #[serde(default)]
    pub timeout_left_blocks: u32,
    /// Suggested timeout for the right leg (taker's lock). Must exceed
    /// `timeout_left_blocks` by at least the maker's safety delta.
    #[serde(default)]
    pub timeout_right_blocks: u32,
    /// Fee the maker will charge (msats). Derived from the ad's fee terms
    /// and the requested amount.
    #[serde(default)]
    pub fee_msats: u64,
    /// Nostr event ID of this response.
    #[serde(skip)]
    pub event_id: String,
    /// Timestamp when the response was published.
    #[serde(skip)]
    pub timestamp: u64,
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
            delegate_pubkey: String::new(),
            reserves_address,
            operator_name: None,
            description: None,
            annual_fee_bps: 0,
            annualized_fixed_msats: 0,
            deposit_fee_bps: 0,
            withdrawal_fee_bps: 0,
            invoice_fee_bps: 0,
            fee_period_blocks: 0,
            transfer_fee_fixed_msats: 0,
            transfer_fee_rate_bps: 0,
            max_deposit_msats: u64::MAX,
            min_deposit_msats: 0,
            max_deposit_balance_msats: 0,
            reserves_amount_msats: 0,
            collateral_amount_msats: 0,
            relay_url: None,
            access_control: false,
            allowed_domains: Vec::new(),
            network,
            current_block: 0,
            quorum_state: String::new(),
            quorum_members: Vec::new(),
            version: 1,
            event_id: String::new(),
            timestamp: 0,
        }
    }

    /// Convert advertisement fees to FeeStructure for new deposits.
    /// Both halves of the result map directly: `annualized_fixed_msats`
    /// → `annualized_msats`, `annual_fee_bps` → `annualized_bps`.
    /// If `fee_period_blocks` is 0, the resulting FeeStructure has
    /// `frequency_blocks=0` and the caller should treat it as unset.
    pub fn to_fee_structure(&self) -> deposits_protocol::types::FeeStructure {
        deposits_protocol::types::FeeStructure {
            annualized_msats: self.annualized_fixed_msats,
            annualized_bps: self.annual_fee_bps as u16,
            frequency_blocks: self.fee_period_blocks,
        }
    }

    /// Operator-charged fee shape, returned for member-side fee-floor
    /// validation: `(annual_bps, fixed_per_period_msats)`.
    ///
    /// The fixed half is converted from annualized to per-period (matches
    /// `OperatorPolicy::minimum_fees`). `validate_fee_minimum` compares
    /// proposed per-period against this value, so returning the raw
    /// annualized number would inflate the floor by the periods-per-year
    /// factor (~26 for the default 2016-block period).
    pub fn minimum_fees(&self) -> (u16, u64) {
        const BLOCKS_PER_YEAR: u64 = 52560;
        let period = (self.fee_period_blocks as u64).max(1);
        let periods_per_year = (BLOCKS_PER_YEAR / period).max(1);
        let fixed_per_period = self.annualized_fixed_msats / periods_per_year;
        (self.annual_fee_bps as u16, fixed_per_period)
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
    pub async fn new_with_slow(
        secret_key: SecretKey,
        relays: Vec<String>,
        slow_relays: Vec<String>,
        skip_nostr_verify: bool,
    ) -> Result<Self, Error> {
        // Convert secp256k1 key to nostr keys
        let secret_bytes = secret_key.secret_bytes();
        let nostr_secret = nostr_sdk::SecretKey::from_slice(&secret_bytes)
            .map_err(|e| Error::Nostr(format!("Invalid secret key: {}", e)))?;
        let keys = Keys::new(nostr_secret);

        // Get our secp256k1 pubkey
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let our_pubkey = PublicKey::from_secret_key(&secp, &secret_key);

        // Create main nostr client (fast relay only) with explicit connection options
        let opts = Options::default().notification_channel_size(65536);
        let client = Client::builder().signer(keys.clone()).opts(opts).build();

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

        let relay_opts = RelayOptions::default();
        let _ = skip_nostr_verify; // reserved for future use
        for relay in &relay_list {
            client
                .pool()
                .add_relay(relay, relay_opts.clone())
                .await
                .map_err(|e| Error::Nostr(format!("Failed to add relay {}: {}", relay, e)))?;
        }

        // Also add slow relays to the main client pool so we receive
        // ephemeral requests from clients who connect to the public relay.
        for relay in &slow_relays {
            if !relay_list.contains(relay) {
                if let Err(e) = client.pool().add_relay(relay, relay_opts.clone()).await {
                    tracing::warn!("Failed to add slow relay {} to main client: {}", relay, e);
                } else {
                    tracing::info!("Added slow relay {} to main subscription pool", relay);
                }
            }
        }

        // Connect main client to relays with explicit timeout
        client
            .connect_with_timeout(std::time::Duration::from_secs(30))
            .await;

        // Wait for at least one relay to be connected (max 10 seconds)
        let max_wait = std::time::Duration::from_secs(10);
        let start = std::time::Instant::now();
        loop {
            let relays = client.relays().await;
            let connected = relays
                .values()
                .any(|r| r.status() == nostr_sdk::RelayStatus::Connected);
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
        let connected_count = relays
            .values()
            .filter(|r| r.status() == nostr_sdk::RelayStatus::Connected)
            .count();
        metrics::set_active_connections(connected_count);
        for _ in 0..connected_count {
            metrics::record_connection();
        }

        // Create separate slow client for gap-fill (if slow relays configured)
        let slow_client = if !slow_relays.is_empty() {
            let slow_opts = Options::default();
            let sc = Client::builder()
                .signer(keys.clone())
                .opts(slow_opts)
                .build();
            for relay in &slow_relays {
                sc.add_relay(relay).await.map_err(|e| {
                    Error::Nostr(format!("Failed to add slow relay {}: {}", relay, e))
                })?;
            }
            sc.connect_with_timeout(std::time::Duration::from_secs(30))
                .await;
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
                    let seq_tag = event
                        .tags
                        .iter()
                        .find(|t| t.as_slice().first().map(|s| s.as_str()) == Some("n"))
                        .and_then(|t| t.as_slice().get(1))
                        .map(|s| s.to_string())
                        .unwrap_or_default();
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        sc.send_event(event),
                    )
                    .await
                    {
                        Ok(Ok(_)) => tracing::debug!("Mirrored seq {} to durable relay", seq_tag),
                        Ok(Err(e)) => tracing::warn!("Mirror to durable relay failed: {}", e),
                        Err(_) => {
                            tracing::warn!("Mirror to durable relay timed out (seq {})", seq_tag)
                        }
                    }
                }
            });
            Some(tx)
        } else {
            None
        };

        Ok(Self {
            delegate_pubkey: std::sync::Mutex::new(None),
            operator_pubkey: std::sync::Mutex::new(None),
            #[cfg(feature = "signer")]
            signer: std::sync::Mutex::new(None),
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
            tracing::info!(
                "Request poll filter set for {} ledgers (was {})",
                ledger_ids.len(),
                old_len
            );
        }
        *self.request_ledger_filter.write().unwrap() = ledger_ids;
    }

    /// Clear the response subscription tracking flag so the next subscribe_to_response
    /// call will create a new subscription (e.g. with updated ledger filter).
    pub fn clear_response_subscription(&self) {
        self.active_subscriptions
            .write()
            .unwrap()
            .remove("responses:all");
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
        self.interested_ledgers
            .write()
            .unwrap()
            .insert(ledger_tag(&ledger_id).to_string());
    }

    /// Remove a ledger ID from the interested set.
    pub fn remove_interested_ledger(&self, ledger_id: &str) {
        self.interested_ledgers
            .write()
            .unwrap()
            .remove(ledger_tag(ledger_id));
    }

    /// Set the ledger IDs we're interested in receiving events for.
    /// Events for other ledgers are dropped in handle_notification().
    /// Empty set = accept all (the default).
    /// Stores truncated prefixes to match against tag values.
    pub fn set_interested_ledgers(&self, ledger_ids: impl IntoIterator<Item = String>) {
        let new_set: std::collections::HashSet<String> = ledger_ids
            .into_iter()
            .map(|id| ledger_tag(&id).to_string())
            .collect();
        let count = new_set.len();
        *self.interested_ledgers.write().unwrap() = new_set;
        tracing::debug!("Interested ledgers set: {} ledgers", count);
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
        tracing::info!(
            "Subscribed with 4 global compacted filters (requests, responses, updates, disputes)"
        );
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
        let urls: Vec<RelayUrl> = {
            let relays = self.client.relays().await;
            if relays.is_empty() {
                return Err(Error::Nostr("No relays connected".to_string()));
            }
            relays.keys().cloned().collect()
        };

        // Send using batch_msg which doesn't wait for OK
        let publish_start = std::time::Instant::now();
        tokio::time::timeout(
            Self::SEND_TIMEOUT,
            self.client.send_msg_to(urls, ClientMessage::event(event)),
        )
        .await
        .map_err(|_| Error::Nostr("send_event_nowait timed out".to_string()))?
        .map_err(|e| Error::Nostr(format!("Failed to send event: {}", e)))?;
        crate::metrics::record_nostr_publish(publish_start.elapsed());

        Ok(())
    }

    /// Send an event with a timeout to prevent relay hangs from freezing the node.
    async fn send_event_with_timeout(&self, event: Event) -> Result<(), Error> {
        let relays = self.client.relays().await;
        let urls: Vec<RelayUrl> = relays.keys().cloned().collect();
        tokio::time::timeout(
            Self::SEND_TIMEOUT,
            self.client.send_msg_to(urls, ClientMessage::event(event)),
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
    pub async fn broadcast_ledger_update(
        &self,
        update: &SignedLedgerUpdate,
    ) -> Result<String, Error> {
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
        // Hash chain data (prev_hash, content_hash) is in the TLV content.
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
        if let Ok(op) = deposits_protocol::messages::LedgerOperation::tlv_decode(&update.message) {
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

            // Payment-hash tag for InvoiceCredit. Lets clients (e.g. the
            // LNURL gateway publishing NIP-57 zap receipts, third-party
            // monitoring) match a credit back to the originating BOLT11
            // without TLV-decoding the body.
            if let deposits_protocol::messages::LedgerOperation::InvoiceCredit {
                payment_hash, ..
            } = &op
            {
                builder = builder.tag(Tag::custom(
                    TagKind::custom("payment_hash"),
                    [hex::encode(payment_hash)],
                ));
            }
        }

        let event = builder
            .sign_with_keys(&self.keys)
            .map_err(|e| Error::Nostr(format!("Failed to sign event: {}", e)))?;

        let event_id = event.id.to_hex();

        // Broadcast to ALL relays (fast + slow) so quorum members on any relay see it
        {
            let relays = self.client.relays().await;
            let urls: Vec<RelayUrl> = relays.keys().cloned().collect();
            tokio::time::timeout(
                Self::SEND_TIMEOUT,
                self.client
                    .send_msg_to(urls, ClientMessage::event(event.clone())),
            )
            .await
            .map_err(|_| Error::Nostr("broadcast ledger update timed out".to_string()))?
            .map_err(|e| Error::Nostr(format!("Failed to broadcast ledger update: {}", e)))?;
        }

        // Also enqueue mirror to durable relay (for relay-specific mirroring)
        if let Some(ref tx) = self.mirror_tx {
            let _ = tx.send(event);
        }

        tracing::debug!(
            "Broadcast ledger update: ledger={}, seq={}, hash={}",
            ledger_id,
            update.sequence_number,
            &hex::encode(update.content_hash)[..16]
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
            .custom_tag(TAG_LEDGER_ID, [ledger_tag(ledger_id)]);

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
        let filter = Filter::new().kind(Kind::Custom(KIND_LEDGER_UPDATE));

        self.client
            .subscribe(vec![filter], None)
            .await
            .map_err(|e| Error::Nostr(format!("Failed to subscribe to operator: {}", e)))?;

        // Mark as subscribed
        self.active_subscriptions.write().unwrap().insert(sub_key);

        tracing::debug!(
            "Subscribed to ledger updates from operator: {}",
            operator_pubkey
        );
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
        self.send_ledger_request_ext(ledger_id, action, params, None)
            .await
    }

    /// Like `send_ledger_request` but with a DEP-04 subkey delegation
    /// attached to the outgoing event. When `subkey_credential` is
    /// `Some((account_xonly_hex, attestation_sig_hex))` we add `["v",
    /// account]` and `["va", sig]` tags so the daemon's
    /// `resolve_attested_sender` can collapse the signer back to the
    /// account for ACL purposes. The event is still SIGNED by the
    /// current wallet key (the subkey) — that's the whole point of
    /// delegation.
    pub async fn send_ledger_request_ext(
        &self,
        ledger_id: &str,
        action: &str,
        params: serde_json::Value,
        subkey_credential: Option<(&str, &str)>,
    ) -> Result<String, Error> {
        let content = serde_json::to_string(&params)
            .map_err(|e| Error::Serialization(format!("Failed to serialize params: {}", e)))?;

        let mut builder = EventBuilder::new(Kind::Custom(KIND_LEDGER_REQUEST), &content)
            .tag(Tag::custom(
                TagKind::SingleLetter(TAG_LEDGER_REQ),
                [ledger_id],
            ))
            .tag(Tag::custom(TagKind::custom("action"), [action]));

        if let Some((account_xonly, attestation_sig)) = subkey_credential {
            builder = builder
                .tag(Tag::custom(
                    TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::V)),
                    [account_xonly],
                ))
                .tag(Tag::custom(TagKind::custom("va"), [attestation_sig]));
        }

        let event = builder
            .sign_with_keys(&self.keys)
            .map_err(|e| Error::Nostr(format!("Failed to sign event: {}", e)))?;

        let event_id = event.id.to_hex();

        // Ensure response subscription is active *before* publishing — operators
        // can respond within milliseconds, well before a post-publish subscribe
        // would complete setup. Without this the wallet would silently miss the
        // response and fall through to a timeout.
        self.subscribe_to_response(&event_id).await?;

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
        self.client
            .add_relay(url)
            .await
            .map_err(|e| Error::Nostr(format!("Failed to add relay {}: {}", url, e)))?;
        self.client
            .connect_with_timeout(std::time::Duration::from_secs(5))
            .await;
        Ok(())
    }

    /// Send a request addressed to a courier (Kind 20101 with #p tag)
    pub async fn send_agent_request(
        &self,
        agent_pubkey: &str,
        action: &str,
        params: serde_json::Value,
    ) -> Result<String, Error> {
        // Fallback shim for callers that don't have a ledger context — use a
        // zero placeholder. The daemon's request parser requires SOME #l tag,
        // but handlers addressed by action+#p (e.g. health_status) ignore it.
        self.send_agent_request_on_ledger(agent_pubkey, &"0".repeat(64), action, params)
            .await
    }

    /// Like `send_agent_request` but with an explicit ledger_id for the `#l`
    /// tag. Use this when you know which of the peer's ledgers to route
    /// against; `process_ledger_request` rejects requests missing `#l`.
    pub async fn send_agent_request_on_ledger(
        &self,
        agent_pubkey: &str,
        ledger_id: &str,
        action: &str,
        params: serde_json::Value,
    ) -> Result<String, Error> {
        let content = serde_json::to_string(&params)
            .map_err(|e| Error::Serialization(format!("Failed to serialize params: {}", e)))?;

        // Nostr p-tags require x-only pubkeys (BIP-340, 32 bytes / 64 hex).
        // Advertisements sometimes carry 33-byte compressed secp256k1 form
        // (0x02/0x03 prefix + x); strip the prefix so strfry accepts the tag.
        let p_tag_value: String = if agent_pubkey.len() == 66 {
            agent_pubkey[2..].to_string()
        } else {
            agent_pubkey.to_string()
        };

        let event = EventBuilder::new(Kind::Custom(KIND_LEDGER_REQUEST), &content)
            .tag(Tag::custom(
                TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::P)),
                [p_tag_value.as_str()],
            ))
            .tag(Tag::custom(
                TagKind::SingleLetter(TAG_LEDGER_REQ),
                [ledger_id],
            ))
            .tag(Tag::custom(TagKind::custom("action"), [action]))
            .sign_with_keys(&self.keys)
            .map_err(|e| Error::Nostr(format!("Failed to sign event: {}", e)))?;

        let event_id = event.id.to_hex();

        // Subscribe to the response BEFORE publishing so a fast reply isn't
        // missed — same race as send_ledger_request handles.
        self.subscribe_to_response(&event_id).await?;

        self.send_event_with_timeout(event)
            .await
            .map_err(|e| Error::Nostr(format!("Failed to send request: {}", e)))?;

        Ok(event_id)
    }

    /// Send an admin-class request as a *custom* gift-wrapped Kind 20101.
    ///
    /// ## Not NIP-17 — deliberate differences
    ///
    /// This envelope borrows the *shape* of NIP-59 gift-wrap (rumor → seal →
    /// outer wrap) but is **not** interoperable with standard NIP-17 DM
    /// clients. The divergences are intentional — they let admin requests
    /// ride the existing Kind 20101 request pipeline (subscription filter,
    /// `process_ledger_request` unwrap, action dispatch, response routing):
    ///
    /// | Field            | NIP-17      | This scheme                      |
    /// |------------------|-------------|----------------------------------|
    /// | Outer wrap kind  | 1059        | 20101 (KIND_LEDGER_REQUEST)      |
    /// | Rumor kind       | 14          | 20101 (reuses request handlers)  |
    /// | Seal kind        | 13          | 13 ✓                             |
    /// | Encryption       | NIP-44      | NIP-04 (matches existing path)   |
    ///
    /// If we ever want interop with external Nostr DM clients, migrate to
    /// real NIP-17 via `EventBuilder::private_msg` (already used for the
    /// admin-onboarding DM in `bootstrap init`).
    ///
    /// ## Intentional response-id convention
    ///
    /// The returned id is the **outer wrap's** event id, not the rumor's.
    /// The daemon's `process_ledger_request` already sets `event_id` from
    /// `event.id` (i.e. the wrap), and `send_ledger_response` tags its
    /// reply with that same id. Returning the rumor id would force a
    /// second lookup table on the daemon side with no benefit.
    ///
    /// The seal's signer pubkey is surfaced to handlers as
    /// `gift_wrap_sender`; `check_admin_authorized` uses it to confirm the
    /// request came from the operator key or the admin pubkey registered
    /// at bootstrap.
    pub async fn send_admin_request(
        &self,
        recipient_hex: &str,
        ledger_id: &str,
        action: &str,
        params: serde_json::Value,
    ) -> Result<String, Error> {
        let content = serde_json::to_string(&params)
            .map_err(|e| Error::Serialization(format!("Failed to serialize params: {}", e)))?;
        let recipient_pk = nostr_sdk::PublicKey::from_hex(recipient_hex)
            .map_err(|e| Error::Nostr(format!("Invalid recipient pubkey: {}", e)))?;

        // ── Rumor: the "real" Kind 20101 event, unsigned (NIP-59-style).
        //    Real NIP-17 would use Kind 14 here; see the doc comment above
        //    for why we keep it on 20101.
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let rumor_json = serde_json::json!({
            "kind": KIND_LEDGER_REQUEST,
            "content": content,
            "tags": [
                ["l", ledger_id],
                ["action", action],
            ],
            "pubkey": self.keys.public_key().to_hex(),
            "created_at": created_at,
        })
        .to_string();
        // Rumor id — the handler returns this as the "event_id" so responses
        // can be matched to our request.
        let rumor_id = {
            use sha2::{Digest, Sha256};
            // Canonical NIP-01 serialization for event id hashing.
            let canonical = serde_json::json!([
                0,
                self.keys.public_key().to_hex(),
                created_at,
                KIND_LEDGER_REQUEST,
                [["l", ledger_id], ["action", action]],
                content,
            ])
            .to_string();
            hex::encode(Sha256::digest(canonical.as_bytes()))
        };

        // ── Seal: NIP-04-encrypted rumor, Kind 13, signed by us ──
        let seal_content = nip04::encrypt(self.keys.secret_key(), &recipient_pk, &rumor_json)
            .map_err(|e| Error::Nostr(format!("admin seal encrypt failed: {}", e)))?;
        let seal_event = EventBuilder::new(Kind::Custom(13), &seal_content)
            .sign_with_keys(&self.keys)
            .map_err(|e| Error::Nostr(format!("admin seal sign failed: {}", e)))?;
        let seal_json = serde_json::json!({
            "id": seal_event.id.to_hex(),
            "pubkey": seal_event.pubkey.to_hex(),
            "created_at": seal_event.created_at.as_u64(),
            "kind": 13,
            "content": seal_event.content,
            "sig": seal_event.sig.to_string(),
        })
        .to_string();

        // ── Wrap: outer Kind 20101 with a throwaway key ──
        let throwaway = Keys::generate();
        let wrap_content = nip04::encrypt(throwaway.secret_key(), &recipient_pk, &seal_json)
            .map_err(|e| Error::Nostr(format!("admin wrap encrypt failed: {}", e)))?;
        let wrap = EventBuilder::new(Kind::Custom(KIND_LEDGER_REQUEST), &wrap_content)
            .tag(Tag::public_key(recipient_pk))
            .tag(Tag::custom(
                TagKind::SingleLetter(TAG_LEDGER_REQ),
                [ledger_id],
            ))
            .tag(Tag::custom(TagKind::custom("action"), [action]))
            .sign_with_keys(&throwaway)
            .map_err(|e| Error::Nostr(format!("admin wrap sign failed: {}", e)))?;

        // The daemon's response references the OUTER wrap event id in its
        // #e tag (that's what process_ledger_request returns as event_id),
        // so the caller must wait on that id — not the rumor id.
        let wrap_id = wrap.id.to_hex();
        let _ = rumor_id;

        // Subscribe BEFORE publishing so a fast response isn't missed.
        self.subscribe_to_response(&wrap_id).await?;

        self.send_event_with_timeout(wrap)
            .await
            .map_err(|e| Error::Nostr(format!("Failed to send admin request: {}", e)))?;

        Ok(wrap_id)
    }

    /// Send a request to a lightning-verify service (Kind 25500) using the
    /// same custom NIP-04 gift-wrap envelope as `send_admin_request`.
    /// Mirrors the web wallet's `giftWrap()` path so both clients talk to
    /// the verifier identically.
    ///
    /// Returns the outer wrap event id. The verifier's reply is a Kind
    /// 25501 event with `#e` pointing at that id — use
    /// `wait_for_verify_response` to collect it.
    pub async fn send_verify_request(
        &self,
        verifier_pubkey_hex: &str,
        params: serde_json::Value,
    ) -> Result<String, Error> {
        let content = serde_json::to_string(&params).map_err(|e| {
            Error::Serialization(format!("Failed to serialize verify params: {}", e))
        })?;
        // Verifier pubkeys are normally published as x-only (32 bytes /
        // 64 hex). Accept compressed (33 bytes / 66 hex) too — strip the
        // prefix for the recipient key and #p tag.
        let xonly_hex: String = if verifier_pubkey_hex.len() == 66 {
            verifier_pubkey_hex[2..].to_string()
        } else {
            verifier_pubkey_hex.to_string()
        };
        let recipient_pk = nostr_sdk::PublicKey::from_hex(&xonly_hex)
            .map_err(|e| Error::Nostr(format!("Invalid verifier pubkey: {}", e)))?;

        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let rumor_json = serde_json::json!({
            "kind": KIND_LIGHTNING_VERIFY_REQUEST,
            "content": content,
            "tags": [["p", xonly_hex]],
            "pubkey": self.keys.public_key().to_hex(),
            "created_at": created_at,
        })
        .to_string();

        let seal_content = nip04::encrypt(self.keys.secret_key(), &recipient_pk, &rumor_json)
            .map_err(|e| Error::Nostr(format!("verify seal encrypt failed: {}", e)))?;
        let seal_event = EventBuilder::new(Kind::Custom(13), &seal_content)
            .sign_with_keys(&self.keys)
            .map_err(|e| Error::Nostr(format!("verify seal sign failed: {}", e)))?;
        let seal_json = serde_json::json!({
            "id": seal_event.id.to_hex(),
            "pubkey": seal_event.pubkey.to_hex(),
            "created_at": seal_event.created_at.as_u64(),
            "kind": 13,
            "content": seal_event.content,
            "sig": seal_event.sig.to_string(),
        })
        .to_string();

        let throwaway = Keys::generate();
        let wrap_content = nip04::encrypt(throwaway.secret_key(), &recipient_pk, &seal_json)
            .map_err(|e| Error::Nostr(format!("verify wrap encrypt failed: {}", e)))?;
        let wrap = EventBuilder::new(Kind::Custom(KIND_LIGHTNING_VERIFY_REQUEST), &wrap_content)
            .tag(Tag::public_key(recipient_pk))
            .sign_with_keys(&throwaway)
            .map_err(|e| Error::Nostr(format!("verify wrap sign failed: {}", e)))?;

        let wrap_id = wrap.id.to_hex();

        // Subscribe BEFORE publishing — verifier can respond within ms.
        self.subscribe_verify_responses().await?;

        self.send_event_with_timeout(wrap)
            .await
            .map_err(|e| Error::Nostr(format!("Failed to send verify request: {}", e)))?;

        Ok(wrap_id)
    }

    /// Subscribe to Kind 25501 lightning-verify responses. Must be called
    /// before any `send_verify_request` or `wait_for_verify_response`.
    async fn subscribe_verify_responses(&self) -> Result<(), Error> {
        let sub_key = "verify_responses".to_string();
        {
            let subs = self.active_subscriptions.read().unwrap();
            if subs.contains(&sub_key) {
                return Ok(());
            }
        }
        let filter = Filter::new()
            .kind(Kind::Custom(KIND_LIGHTNING_VERIFY_RESPONSE))
            .since(Timestamp::now() - 5);
        self.client
            .subscribe(vec![filter], None)
            .await
            .map_err(|e| Error::Nostr(format!("subscribe verify: {}", e)))?;
        self.active_subscriptions.write().unwrap().insert(sub_key);
        Ok(())
    }

    /// Wait for a lightning-verify response (Kind 25501) whose `#e` tag
    /// points at the given request id. Unwraps the gift envelope
    /// (same NIP-04 shape as `send_verify_request`). Returns the
    /// verifier's JSON content.
    pub async fn wait_for_verify_response(
        &self,
        request_event_id: &str,
        timeout_ms: u64,
    ) -> Result<serde_json::Value, Error> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);
        let mut rx = self.client.notifications();
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Err(Error::Nostr("verify response timeout".into()));
            }
            let recv = tokio::time::timeout(remaining, rx.recv()).await;
            let notif = match recv {
                Ok(Ok(n)) => n,
                _ => return Err(Error::Nostr("verify response timeout".into())),
            };
            if let RelayPoolNotification::Event { event, .. } = notif {
                if event.kind.as_u16() != KIND_LIGHTNING_VERIFY_RESPONSE {
                    continue;
                }
                // Match #e tag against request id.
                let matches = event.tags.iter().any(|t| {
                    t.kind() == TagKind::SingleLetter(TAG_EVENT_REF)
                        && t.content() == Some(request_event_id)
                });
                if !matches {
                    continue;
                }
                // Unwrap — same NIP-04 gift envelope the wallet/verifier use.
                if let Ok(json) = self.unwrap_verify_payload(&event) {
                    return Ok(json);
                }
                // If unwrap fails, keep waiting (could be a response for
                // a different client that happened to match the e-tag by
                // coincidence — extremely unlikely, but cheap to skip).
            }
        }
    }

    fn unwrap_verify_payload(&self, event: &Event) -> Result<serde_json::Value, Error> {
        // Plaintext (unlikely but supported).
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&event.content) {
            if let Some(s) = v.get("content").and_then(|x| x.as_str()) {
                if let Ok(inner) = serde_json::from_str::<serde_json::Value>(s) {
                    return Ok(inner);
                }
            }
            return Ok(v);
        }
        // Gift-unwrap: outer → seal (kind 13) → rumor.
        let seal_json = self
            .nip04_decrypt_with_fallback(&event.pubkey, &event.content)
            .map_err(|e| Error::Nostr(format!("verify unwrap outer: {}", e)))?;
        let seal: serde_json::Value = serde_json::from_str(&seal_json)
            .map_err(|e| Error::Nostr(format!("verify seal parse: {}", e)))?;
        let seal_pubkey_hex = seal["pubkey"]
            .as_str()
            .ok_or_else(|| Error::Nostr("verify seal missing pubkey".into()))?;
        let seal_pubkey = nostr_sdk::PublicKey::from_hex(seal_pubkey_hex)
            .map_err(|e| Error::Nostr(format!("verify seal pubkey parse: {}", e)))?;
        let rumor_json = self
            .nip04_decrypt_with_fallback(&seal_pubkey, seal["content"].as_str().unwrap_or(""))
            .map_err(|e| Error::Nostr(format!("verify rumor decrypt: {}", e)))?;
        let rumor: serde_json::Value = serde_json::from_str(&rumor_json)
            .map_err(|e| Error::Nostr(format!("verify rumor parse: {}", e)))?;
        let content = rumor["content"].as_str().unwrap_or_default();
        serde_json::from_str(content)
            .map_err(|e| Error::Nostr(format!("verify payload parse: {}", e)))
    }

    /// Publish this wallet's Kind 10301 subkey list (DEP-04). The
    /// content is a JSON object with `inbox_keys` and `revoked_subkeys`
    /// arrays. Replaceable — relay keeps only the latest per author.
    pub async fn publish_subkey_list(
        &self,
        inbox_keys: &[String],
        revoked_subkeys: &[String],
    ) -> Result<String, Error> {
        let content = serde_json::json!({
            "inbox_keys": inbox_keys,
            "revoked_subkeys": revoked_subkeys,
        })
        .to_string();

        // Replaceable events are broken if two publishes land in the same
        // second — NIP-01 tie-breaks on event id, not on write order, so
        // the older state can win. Query the existing event's timestamp
        // and force ours strictly newer.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let prior = {
            let our_pk = self.keys.public_key();
            let filter = Filter::new()
                .kind(Kind::Custom(KIND_SUBKEY_LIST))
                .author(our_pk)
                .limit(1);
            let evs = self
                .client
                .fetch_events(vec![filter], Some(std::time::Duration::from_secs(3)))
                .await
                .ok();
            evs.and_then(|e| e.iter().map(|x| x.created_at.as_u64()).max())
                .unwrap_or(0)
        };
        let created_at = std::cmp::max(now, prior + 1);

        let event = EventBuilder::new(Kind::Custom(KIND_SUBKEY_LIST), &content)
            .custom_created_at(Timestamp::from(created_at))
            .sign_with_keys(&self.keys)
            .map_err(|e| Error::Nostr(format!("Failed to sign subkey list: {}", e)))?;
        let event_id = event.id.to_hex();
        self.send_event_with_timeout(event)
            .await
            .map_err(|e| Error::Nostr(format!("Failed to publish subkey list: {}", e)))?;
        // Give the relay a moment to persist before the CLI exits.
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        Ok(event_id)
    }

    /// Fetch the latest Kind 10301 subkey list authored by
    /// `author_xonly_hex`. Returns `(inbox_keys, revoked_subkeys)` or
    /// `(vec![], vec![])` if no list has been published yet.
    pub async fn fetch_subkey_list(
        &self,
        author_xonly_hex: &str,
    ) -> Result<(Vec<String>, Vec<String>), Error> {
        let author = nostr_sdk::PublicKey::from_hex(author_xonly_hex)
            .map_err(|e| Error::Nostr(format!("Invalid author pubkey: {}", e)))?;
        let filter = Filter::new()
            .kind(Kind::Custom(KIND_SUBKEY_LIST))
            .author(author)
            .limit(1);

        let events = self
            .client
            .fetch_events(vec![filter], Some(std::time::Duration::from_secs(5)))
            .await
            .map_err(|e| Error::Nostr(format!("Failed to fetch subkey list: {}", e)))?;

        let mut latest: Option<&Event> = None;
        for e in events.iter() {
            match latest {
                None => latest = Some(e),
                Some(prev) if e.created_at > prev.created_at => latest = Some(e),
                _ => {}
            }
        }
        let Some(evt) = latest else {
            return Ok((Vec::new(), Vec::new()));
        };

        let parsed: serde_json::Value = serde_json::from_str(&evt.content)
            .map_err(|e| Error::Serialization(format!("subkey list parse: {}", e)))?;
        let take_arr = |k: &str| -> Vec<String> {
            parsed
                .get(k)
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|s| s.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default()
        };
        Ok((take_arr("inbox_keys"), take_arr("revoked_subkeys")))
    }

    /// Send a ledger response (reply to a request).
    /// If `gift_wrap_to` is set, the response is gift-wrapped to that pubkey.
    pub async fn send_ledger_response(
        &self,
        request_id: &str,
        ledger_id: &str,
        action: &str,
        success: bool,
        result: Option<serde_json::Value>,
        error: Option<String>,
        gift_wrap_to: Option<&str>,
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

        let plaintext_content = serde_json::to_string(&response)
            .map_err(|e| Error::Serialization(format!("Failed to serialize response: {}", e)))?;

        let status = if success { "ok" } else { "error" };

        let event = if let Some(recipient_hex) = gift_wrap_to {
            // Gift-wrap response: rumor → seal (encrypted) → wrap (throwaway key)
            let recipient_pk = nostr_sdk::PublicKey::from_hex(recipient_hex)
                .map_err(|e| Error::Nostr(format!("Invalid gift_wrap_to pubkey: {}", e)))?;

            let rumor_json = serde_json::json!({
                "kind": KIND_LEDGER_RESPONSE,
                "content": plaintext_content,
                "tags": [["e", request_id]],
                "pubkey": self.keys.public_key().to_hex(),
                "created_at": std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs()).unwrap_or(0),
            })
            .to_string();

            let seal_content =
                nip04::encrypt(self.keys.secret_key(), &recipient_pk, &rumor_json)
                    .map_err(|e| Error::Nostr(format!("Gift wrap seal encrypt failed: {}", e)))?;
            let seal_event = EventBuilder::new(Kind::Custom(13), &seal_content)
                .sign_with_keys(&self.keys)
                .map_err(|e| Error::Nostr(format!("Gift wrap seal sign failed: {}", e)))?;
            let seal_json = serde_json::json!({
                "id": seal_event.id.to_hex(),
                "pubkey": seal_event.pubkey.to_hex(),
                "created_at": seal_event.created_at.as_u64(),
                "kind": 13,
                "content": seal_event.content,
                "sig": seal_event.sig.to_string(),
            })
            .to_string();

            let throwaway = Keys::generate();
            let wrap_content = nip04::encrypt(throwaway.secret_key(), &recipient_pk, &seal_json)
                .map_err(|e| Error::Nostr(format!("Gift wrap outer encrypt failed: {}", e)))?;
            EventBuilder::new(Kind::Custom(KIND_LEDGER_RESPONSE), &wrap_content)
                .tag(Tag::public_key(recipient_pk))
                .tag(Tag::custom(
                    TagKind::SingleLetter(TAG_EVENT_REF),
                    [request_id],
                ))
                .sign_with_keys(&throwaway)
                .map_err(|e| Error::Nostr(format!("Gift wrap sign failed: {}", e)))?
        } else {
            // Plaintext response (node-to-node)
            EventBuilder::new(Kind::Custom(KIND_LEDGER_RESPONSE), &plaintext_content)
                .tag(Tag::custom(
                    TagKind::SingleLetter(TAG_EVENT_REF),
                    [request_id],
                ))
                .tag(Tag::custom(
                    TagKind::SingleLetter(TAG_LEDGER_REQ),
                    [ledger_id],
                ))
                .tag(Tag::custom(TagKind::custom("status"), [status]))
                .sign_with_keys(&self.keys)
                .map_err(|e| Error::Nostr(format!("Failed to sign event: {}", e)))?
        };

        let event_id = event.id.to_hex();

        // Send response to ALL relays (not just primary) so the requesting
        // client receives it regardless of which relay they're connected to.
        {
            let relays = self.client.relays().await;
            let urls: Vec<RelayUrl> = relays.keys().cloned().collect();
            tokio::time::timeout(
                Self::SEND_TIMEOUT,
                self.client.send_msg_to(urls, ClientMessage::event(event)),
            )
            .await
            .map_err(|_| Error::Nostr("send response timed out".to_string()))?
            .map_err(|e| Error::Nostr(format!("Failed to send response: {}", e)))?;
        }

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
    /// Operator-side flow only — gated behind the `signer` feature.
    #[cfg(feature = "signer")]
    pub async fn publish_dispute(
        &self,
        ledger_id: &str,
        reason: &str,
        details: &str,
        last_valid_hash: [u8; 32],
        last_valid_sequence: u64,
        violation_sequence: Option<u64>,
        signer: &dyn deposits_signer_api::Signer,
    ) -> Result<String, Error> {
        use bitcoin::hashes::{sha256, Hash};

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
        let signature_bytes = signer
            .bip340_sign(
                &deposits_signer_api::SignContext::no_ledger(
                    deposits_signer_api::SigPurpose::Bip340Untagged,
                ),
                &sighash.to_byte_array(),
            )
            .map_err(|e| Error::Nostr(format!("publish_dispute sign: {}", e)))?;

        let disputer_pubkey = hex::encode(signer.pubkey().serialize());

        let dispute = LedgerDispute {
            disputer_pubkey: disputer_pubkey.clone(),
            ledger_id: ledger_id.to_string(),
            reason: reason.to_string(),
            details: details.to_string(),
            last_valid_hash: hex::encode(last_valid_hash),
            last_valid_sequence,
            violation_sequence,
            signature: hex::encode(signature_bytes),
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
            .tag(Tag::custom(TagKind::custom("reason"), [reason]))
            .tag(Tag::custom(TagKind::custom("disputer"), [&disputer_pubkey]))
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
            .custom_tag(TAG_LEDGER_REQ, [ledger_id])
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

        tracing::debug!(
            "Subscribed to all ledger disputes (kind {})",
            KIND_LEDGER_DISPUTE
        );
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

        if new_request_ledgers.is_empty()
            && new_dispute_ledgers.is_empty()
            && new_update_ledgers.is_empty()
        {
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
                    .custom_tag(TAG_LEDGER_REQ, [lid.as_str()])
                    .since(since),
            );
        }

        // Per-ledger dispute filters (relay filters by tag)
        for lid in &new_dispute_ledgers {
            filters.push(
                Filter::new()
                    .kind(Kind::Custom(KIND_LEDGER_DISPUTE))
                    .custom_tag(TAG_LEDGER_REQ, [lid.as_str()])
                    .since(since),
            );
        }

        // Per-ledger update filters with #d tag (for validating joined ledgers)
        for lid in &new_update_ledgers {
            filters.push(
                Filter::new()
                    .kind(Kind::Custom(KIND_LEDGER_UPDATE))
                    .custom_tag(TAG_LEDGER_ID, [ledger_tag(lid)])
                    .since(since),
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

        tracing::info!(
            "Batch subscribed: {} request + {} dispute + {} update filters ({} total)",
            new_request_ledgers.len(),
            new_dispute_ledgers.len(),
            new_update_ledgers.len(),
            filter_count
        );
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
        use bitcoin::hashes::{sha256, Hash};
        use bitcoin::secp256k1::{Message, Secp256k1};

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
            .tag(Tag::custom(TagKind::custom("member"), [&member_pubkey]))
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
            .custom_tag(TAG_EVENT_REF, [dispute_event_id]);

        let events = self
            .client
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

    /// Publish a custody-lottery preimage reveal.
    ///
    /// Called by each disputant during the reveal phase after the
    /// confiscation TX has confirmed on-chain. Other disputants fetch
    /// these events to compute the lottery winner.
    ///
    /// The signature binds `(ledger_id, preimage)` to the revealing
    /// disputant's identity, preventing a third party from re-publishing
    /// the same preimage under a different `member_pubkey`.
    pub async fn publish_custody_lottery_reveal(
        &self,
        ledger_id: &str,
        preimage: &[u8],
        keypair: &bitcoin::secp256k1::Keypair,
    ) -> Result<String, Error> {
        use bitcoin::hashes::{sha256, Hash};
        use bitcoin::secp256k1::{Message, Secp256k1};

        let mut sighash_input = Vec::new();
        sighash_input.extend_from_slice(b"CustodyLotteryReveal:");
        sighash_input.extend_from_slice(ledger_id.as_bytes());
        sighash_input.push(0x00);
        sighash_input.extend_from_slice(preimage);

        let sighash = sha256::Hash::hash(&sighash_input);
        let secp = Secp256k1::new();
        let msg = Message::from_digest(sighash.to_byte_array());
        let signature = secp.sign_schnorr(&msg, keypair);

        let member_pubkey = hex::encode(keypair.public_key().serialize());

        let reveal = CustodyLotteryReveal {
            member_pubkey: member_pubkey.clone(),
            ledger_id: ledger_id.to_string(),
            preimage_hex: hex::encode(preimage),
            signature: hex::encode(signature.serialize()),
            event_id: String::new(),
            timestamp: 0,
        };

        let content = serde_json::to_string(&reveal)
            .map_err(|e| Error::Serialization(format!("Failed to serialize reveal: {}", e)))?;

        let event = EventBuilder::new(Kind::Custom(KIND_CUSTODY_LOTTERY_REVEAL), &content)
            .tag(Tag::custom(
                TagKind::SingleLetter(TAG_LEDGER_ID),
                [ledger_id],
            ))
            .tag(Tag::custom(TagKind::custom("member"), [&member_pubkey]))
            .sign_with_keys(&self.keys)
            .map_err(|e| Error::Nostr(format!("Failed to sign reveal event: {}", e)))?;

        let event_id = event.id.to_hex();

        self.send_event_with_timeout(event)
            .await
            .map_err(|e| Error::Nostr(format!("Failed to send reveal: {}", e)))?;

        tracing::info!(
            "Published custody-lottery reveal: ledger={}, member={}, event={}, preimage_len={}",
            &ledger_id[..16.min(ledger_id.len())],
            &member_pubkey[..16],
            &event_id[..16],
            preimage.len()
        );

        Ok(event_id)
    }

    /// Fetch all custody-lottery reveals for a given ledger.
    ///
    /// The caller is expected to filter by the disputant set (membership
    /// in the original dispute) and verify each reveal's signature
    /// against its `member_pubkey` before passing the preimages to
    /// `LotteryOutput::calculate_winner`.
    pub async fn fetch_custody_lottery_reveals(
        &self,
        ledger_id: &str,
    ) -> Result<Vec<CustodyLotteryReveal>, Error> {
        let filter = Filter::new()
            .kind(Kind::Custom(KIND_CUSTODY_LOTTERY_REVEAL))
            .custom_tag(TAG_LEDGER_ID, [ledger_tag(ledger_id)]);

        let events = self
            .client
            .fetch_events(vec![filter], Some(std::time::Duration::from_secs(10)))
            .await
            .map_err(|e| Error::Nostr(format!("Failed to fetch reveals: {}", e)))?;

        let mut reveals = Vec::new();
        for event in events.iter() {
            if let Ok(mut reveal) = serde_json::from_str::<CustodyLotteryReveal>(&event.content) {
                reveal.event_id = event.id.to_hex();
                reveal.timestamp = event.created_at.as_u64();
                reveals.push(reveal);
            }
        }

        Ok(reveals)
    }

    /// Publish a ledger advertisement
    ///
    /// Uses NIP-33 parameterized replaceable events, so only the latest
    /// advertisement per ledger_id is retained by relays.
    /// Set the daemon's delegate Nostr pubkey. Once set, every
    /// subsequently-published Kind 39100 advertisement carries this
    /// pubkey in `LedgerAdvertisement.delegate_pubkey`. Wallets that
    /// follow the delegation address messages here while still
    /// trusting the operator's pubkey as the protocol-level identity.
    ///
    /// Idempotent. The same delegate pubkey is expected for the
    /// daemon's lifetime (it's persisted under `<data-dir>/delegate_secret`).
    pub fn set_delegate_pubkey(&self, pk: PublicKey) {
        if let Ok(mut guard) = self.delegate_pubkey.lock() {
            *guard = Some(pk);
        }
    }

    /// Set the operator's protocol-level pubkey. Used for advertisement
    /// signing (which stays operator-authored) and for the fallback
    /// NIP-04 decrypt path (operator-encrypted DMs from wallets that
    /// don't read advertisement.delegate_pubkey).
    pub fn set_operator_pubkey(&self, pk: bitcoin::secp256k1::PublicKey) {
        let xonly = pk.x_only_public_key().0;
        if let Ok(nostr_pk) = nostr_sdk::PublicKey::from_slice(&xonly.serialize()) {
            if let Ok(mut guard) = self.operator_pubkey.lock() {
                *guard = Some(nostr_pk);
            }
        }
    }

    /// Set the daemon's `Signer` so the transport can request operator-key
    /// signs/ECDH for the call sites that need them — Kind 39100
    /// advertisements (`bip340_sign` on the event id) and the fallback
    /// NIP-04 decrypt path (`nip04_shared_key`). Gated behind the
    /// `signer` feature; wallet-only consumers don't pull this in.
    #[cfg(feature = "signer")]
    pub fn set_signer(
        &self,
        signer: std::sync::Arc<dyn deposits_signer_api::Signer>,
    ) {
        if let Ok(mut guard) = self.signer.lock() {
            *guard = Some(signer);
        }
    }

    /// NIP-04 decrypt with delegate-first / operator-fallback semantics.
    ///
    /// The daemon's `self.keys` holds the delegate secret; most wallets
    /// (delegation-aware) encrypt to delegate, and this path returns
    /// after one synchronous in-process decrypt — fast.
    ///
    /// Wallets that pre-date the delegation still encrypt to the
    /// operator pubkey. Their messages fail the in-process decrypt;
    /// we then ask the configured `Signer` for the NIP-04 raw-X shared
    /// key against the operator key (one wire round-trip if RemoteSigner
    /// is in use), do the AES-CBC decrypt locally, and return the result.
    ///
    /// Either branch returning `Ok` succeeded; only when both fail do
    /// we surface the error. The error message is intentionally
    /// the operator-side one (more useful for diagnosis since the
    /// delegate-side failure on a legacy wallet is expected).
    fn nip04_decrypt_with_fallback(
        &self,
        sender: &nostr_sdk::PublicKey,
        ciphertext: &str,
    ) -> Result<String, Error> {
        // 1. Try delegate (in-process, fast).
        if let Ok(plaintext) = nip04::decrypt(self.keys.secret_key(), sender, ciphertext) {
            return Ok(plaintext);
        }

        // 2. Fall back to operator key via the Signer. Only available
        //    when the `signer` feature is enabled; wallet-only builds
        //    don't have an operator key to fall back to in the first
        //    place, so the delegate path is the only one.
        #[cfg(feature = "signer")]
        {
            let signer = match self.signer.lock().ok().and_then(|g| g.clone()) {
                Some(s) => s,
                None => {
                    return Err(Error::Nostr(
                        "NIP-04 decrypt failed (delegate) and no Signer configured for operator-key fallback"
                            .to_string(),
                    ));
                }
            };

            // Convert the nostr_sdk PublicKey (xonly) into a
            // bitcoin::secp256k1::PublicKey for the signer call. NIP-04 sender
            // is xonly; we lift it to compressed (with even-Y) since
            // shared_secret_point operates on full points and the convention
            // (matching nostr/util::generate_shared_key) is even-Y normalization.
            let sender_bytes = sender.to_bytes();
            let mut compressed = [0u8; 33];
            compressed[0] = 0x02; // even Y
            compressed[1..].copy_from_slice(&sender_bytes);
            let sender_full = bitcoin::secp256k1::PublicKey::from_slice(&compressed).map_err(|e| {
                Error::Nostr(format!("NIP-04 fallback: lift sender pubkey: {}", e))
            })?;

            let shared_key = signer.nip04_shared_key(&sender_full).map_err(|e| {
                Error::Nostr(format!("NIP-04 fallback ECDH via signer: {}", e))
            })?;

            // AES-256-CBC decrypt with the shared key. Mirrors what
            // nostr/nips/nip04.rs::decrypt_to_bytes does after
            // `util::generate_shared_key`.
            return nip04_decrypt_with_shared_key(&shared_key, ciphertext).map_err(|e| {
                Error::Nostr(format!("NIP-04 fallback AES-CBC: {}", e))
            });
        }

        #[cfg(not(feature = "signer"))]
        Err(Error::Nostr(
            "NIP-04 decrypt failed (delegate) and `signer` feature \
             is not enabled — wallet-only builds can't fall back to \
             operator-key decryption"
                .to_string(),
        ))
    }

    /// Queries the relay for existing advertisement timestamp to ensure
    /// the new event has a strictly greater timestamp.
    pub async fn publish_ledger_advertisement(
        &self,
        ad: &LedgerAdvertisement,
    ) -> Result<String, Error> {
        // Stamp the daemon's delegate pubkey into the ad if we know it.
        // Caller may have already set it; otherwise fill from our cached
        // value. Either way the on-wire ad carries delegate_pubkey for
        // wallets following the delegation pattern.
        let mut ad = ad.clone();
        if ad.delegate_pubkey.is_empty() {
            if let Ok(guard) = self.delegate_pubkey.lock() {
                if let Some(pk) = guard.as_ref() {
                    ad.delegate_pubkey = hex::encode(pk.serialize());
                }
            }
        }
        let ad = &ad;
        // Cache locally so we don't need relay round-trips to read our own ads
        self.ad_cache
            .write()
            .unwrap()
            .insert(ad.ledger_id.clone(), ad.clone());

        let content = serde_json::to_string(ad).map_err(|e| {
            Error::Serialization(format!("Failed to serialize advertisement: {}", e))
        })?;

        // Query relay for existing advertisement's timestamp
        let existing_timestamp = self
            .get_advertisement_timestamp(&ad.ledger_id)
            .await
            .unwrap_or(0);

        // Ensure new timestamp is strictly greater than existing
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let timestamp = std::cmp::max(now, existing_timestamp + 1);

        // Update the static counter too for same-process rapid updates
        LAST_AD_TIMESTAMP.fetch_max(timestamp, Ordering::SeqCst);

        let builder = EventBuilder::new(Kind::Custom(KIND_LEDGER_ADVERTISE), &content)
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
            ));

        // Sign Kind 39100 advertisements with the operator key (via Signer)
        // when one is configured. Wallets pin the *operator* pubkey from
        // their bech32 ledger id and verify the ad's signature against it
        // — when self.keys is the delegate (post-cutover) we'd produce ads
        // they reject, so we go back through the signer for this one.
        // Falls back to self.keys-signing when no signer is wired (test
        // builds, legacy single-key deployments, or builds without the
        // `signer` feature). The Signer-using branch is gated behind the
        // feature so wallet-only consumers don't pull deposits-signer-api.
        #[cfg(feature = "signer")]
        let event = if let Some(signer) =
            self.signer.lock().ok().and_then(|g| g.clone())
        {
            // Operator xonly → nostr_sdk::PublicKey (same 32-byte encoding).
            let xonly_secp = signer.xonly_pubkey();
            let xonly_bytes = xonly_secp.serialize();
            let operator_xonly = nostr_sdk::PublicKey::from_slice(&xonly_bytes).map_err(|e| {
                Error::Nostr(format!("operator xonly → nostr pubkey: {}", e))
            })?;

            let unsigned = builder.build(operator_xonly);
            let id = unsigned.id.ok_or_else(|| {
                Error::Nostr("UnsignedEvent::build did not populate id".to_string())
            })?;
            let id_bytes: [u8; 32] = id.to_bytes();

            let ctx = deposits_signer_api::SignContext::no_ledger(
                deposits_signer_api::SigPurpose::NostrEvent,
            );
            let sig_bytes = signer.bip340_sign(&ctx, &id_bytes).map_err(|e| {
                Error::Nostr(format!("signer bip340_sign for advertisement: {}", e))
            })?;
            let sig = bitcoin::secp256k1::schnorr::Signature::from_slice(&sig_bytes)
                .map_err(|e| {
                    Error::Nostr(format!("parse advertisement schnorr sig: {}", e))
                })?;
            unsigned.add_signature(sig).map_err(|e| {
                Error::Nostr(format!("attach signature to advertisement: {}", e))
            })?
        } else {
            builder
                .sign_with_keys(&self.keys)
                .map_err(|e| Error::Nostr(format!("Failed to sign event: {}", e)))?
        };
        #[cfg(not(feature = "signer"))]
        let event = builder
            .sign_with_keys(&self.keys)
            .map_err(|e| Error::Nostr(format!("Failed to sign event: {}", e)))?;

        let event_id = event.id.to_hex();

        // Send the event and give the relay time to process it before the
        // connection drops.  nostr-sdk's send_event is fire-and-forget at the
        // WebSocket level, so a short-lived CLI process may disconnect before
        // strfry flushes the write.  The brief sleep is a pragmatic workaround.
        self.send_event_with_timeout(event.clone())
            .await
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
        })
        .to_string();

        let event = EventBuilder::new(Kind::Custom(KIND_PRICE_ORACLE), &content)
            .tag(Tag::custom(
                TagKind::SingleLetter(TAG_LEDGER_ID),
                ["btcusd"],
            ))
            .sign_with_keys(&self.keys)
            .map_err(|e| Error::Nostr(format!("Failed to sign price event: {}", e)))?;

        let event_id = event.id.to_hex();

        self.send_event_with_timeout(event.clone())
            .await
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
            .custom_tag(TAG_LEDGER_ID, [ledger_id])
            .limit(1);

        let events = self
            .client
            .fetch_events(vec![filter], Some(std::time::Duration::from_secs(5)))
            .await
            .ok()?;

        // Extract timestamp from first event
        events.first().map(|event| event.created_at.as_u64())
    }

    /// Fetch all ledger advertisements for a network
    pub async fn fetch_ledger_advertisements(
        &self,
        network: &str,
    ) -> Result<Vec<LedgerAdvertisement>, Error> {
        let filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_ADVERTISE))
            .custom_tag(TAG_SEQUENCE, [network]);

        let events = self
            .client
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
        let filter = Filter::new().kind(Kind::Custom(KIND_AGENT_ADVERTISE));

        let events = self
            .client
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

    /// Publish a swap advertisement (Kind 39103). The d-tag is the source
    /// deposit_id so one author can advertise multiple open swaps.
    pub async fn publish_swap_advertisement(
        &self,
        ad: &SwapAdvertisement,
    ) -> Result<String, Error> {
        let content = serde_json::to_string(ad).map_err(|e| {
            Error::Serialization(format!("Failed to serialize swap advertisement: {}", e))
        })?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let event = EventBuilder::new(Kind::Custom(KIND_SWAP_ADVERTISE), &content)
            .custom_created_at(Timestamp::from(now))
            .tag(Tag::custom(
                TagKind::SingleLetter(TAG_LEDGER_ID),
                [ad.source_deposit_id.as_str()],
            ))
            .tag(Tag::custom(
                TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::L)),
                [ad.source_ledger.as_str()],
            ))
            .sign_with_keys(&self.keys)
            .map_err(|e| Error::Nostr(format!("Failed to sign swap ad: {}", e)))?;

        let event_id = event.id.to_hex();
        self.send_event_with_timeout(event)
            .await
            .map_err(|e| Error::Nostr(format!("Failed to send swap ad: {}", e)))?;
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        Ok(event_id)
    }

    /// Fetch open swap advertisements (Kind 39103) visible on the relays.
    /// Expired ads are filtered out.
    pub async fn fetch_swap_advertisements(
        &self,
        network: &str,
    ) -> Result<Vec<SwapAdvertisement>, Error> {
        let filter = Filter::new().kind(Kind::Custom(KIND_SWAP_ADVERTISE));

        let events = self
            .client
            .fetch_events(vec![filter], Some(std::time::Duration::from_secs(10)))
            .await
            .map_err(|e| Error::Nostr(format!("Failed to fetch swap advertisements: {}", e)))?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut ads = Vec::new();
        for event in events.iter() {
            if let Ok(mut ad) = serde_json::from_str::<SwapAdvertisement>(&event.content) {
                if ad.network != network {
                    continue;
                }
                if ad.expires_at != 0 && ad.expires_at < now {
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

    /// Publish a SwapRequest addressed to a maker (Kind 20103).
    pub async fn publish_swap_request(
        &self,
        maker_pubkey: &str,
        req: &SwapRequest,
    ) -> Result<String, Error> {
        let content = serde_json::to_string(req).map_err(|e| {
            Error::Serialization(format!("Failed to serialize swap request: {}", e))
        })?;

        let event = EventBuilder::new(Kind::Custom(KIND_SWAP_REQUEST), &content)
            .tag(Tag::custom(
                TagKind::SingleLetter(TAG_PUBKEY),
                [maker_pubkey],
            ))
            .sign_with_keys(&self.keys)
            .map_err(|e| Error::Nostr(format!("Failed to sign swap request: {}", e)))?;

        let event_id = event.id.to_hex();
        self.send_event_with_timeout(event)
            .await
            .map_err(|e| Error::Nostr(format!("Failed to send swap request: {}", e)))?;
        Ok(event_id)
    }

    /// Publish a SwapResponse to a taker (Kind 20104). `taker_pubkey` is the
    /// hex-serialized secp256k1 pubkey the response is addressed to.
    pub async fn publish_swap_response(
        &self,
        taker_pubkey: &str,
        resp: &SwapResponse,
    ) -> Result<String, Error> {
        let content = serde_json::to_string(resp).map_err(|e| {
            Error::Serialization(format!("Failed to serialize swap response: {}", e))
        })?;

        let event = EventBuilder::new(Kind::Custom(KIND_SWAP_RESPONSE), &content)
            .tag(Tag::custom(
                TagKind::SingleLetter(TAG_PUBKEY),
                [taker_pubkey],
            ))
            .tag(Tag::custom(
                TagKind::SingleLetter(TAG_EVENT_REF),
                [resp.request_event_id.as_str()],
            ))
            .sign_with_keys(&self.keys)
            .map_err(|e| Error::Nostr(format!("Failed to sign swap response: {}", e)))?;

        let event_id = event.id.to_hex();
        self.send_event_with_timeout(event)
            .await
            .map_err(|e| Error::Nostr(format!("Failed to send swap response: {}", e)))?;
        Ok(event_id)
    }

    /// Subscribe to SwapResponses on active relays. Must be called before
    /// `publish_swap_request` so the broadcast subscription is live when the
    /// maker responds. Ephemeral events (20000-29999) are not stored by relays;
    /// they are only delivered to subscribers active at publish time.
    pub async fn subscribe_swap_responses(&self) -> Result<(), Error> {
        let filter = Filter::new()
            .kind(Kind::Custom(KIND_SWAP_RESPONSE))
            .since(Timestamp::now() - 5);
        self.client
            .subscribe(vec![filter], None)
            .await
            .map_err(|e| Error::Nostr(format!("Failed to subscribe to swap responses: {}", e)))?;
        Ok(())
    }

    /// Wait for a SwapResponse to a specific request event id. The receiver
    /// MUST have been created before the request was published — broadcast
    /// receivers only see events sent after their creation.
    pub async fn wait_for_swap_response(
        &self,
        rx: &mut tokio::sync::broadcast::Receiver<RelayPoolNotification>,
        request_event_id: &str,
        timeout_ms: u64,
    ) -> Result<SwapResponse, Error> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);

        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Err(Error::Nostr("swap response timeout".into()));
            }
            let recv = tokio::time::timeout(remaining, rx.recv()).await;
            let notif = match recv {
                Ok(Ok(n)) => n,
                Ok(Err(_)) | Err(_) => {
                    return Err(Error::Nostr("swap response timeout".into()));
                }
            };
            if let RelayPoolNotification::Event { event, .. } = notif {
                if event.kind.as_u16() != KIND_SWAP_RESPONSE {
                    continue;
                }
                if let Ok(mut resp) = serde_json::from_str::<SwapResponse>(&event.content) {
                    if resp.request_event_id == request_event_id {
                        resp.event_id = event.id.to_hex();
                        resp.timestamp = event.created_at.as_u64();
                        return Ok(resp);
                    }
                }
            }
        }
    }

    /// Subscribe to inbound SwapRequests addressed to our pubkey. Must be
    /// called before any `next_swap_request` calls — ephemeral events are
    /// only delivered while a subscription is active.
    pub async fn subscribe_swap_requests(&self, our_pubkey: &str) -> Result<(), Error> {
        let filter = Filter::new()
            .kind(Kind::Custom(KIND_SWAP_REQUEST))
            .custom_tag(TAG_PUBKEY, [our_pubkey])
            .since(Timestamp::now() - 5);
        self.client
            .subscribe(vec![filter], None)
            .await
            .map_err(|e| Error::Nostr(format!("Failed to subscribe to swap requests: {}", e)))?;
        Ok(())
    }

    /// Wait for the next SwapRequest on the active subscription. Returns
    /// `None` if no request arrives within `timeout_ms`. The receiver MUST
    /// have been created before `subscribe_swap_requests` — see the note on
    /// `wait_for_swap_response`.
    pub async fn next_swap_request(
        &self,
        rx: &mut tokio::sync::broadcast::Receiver<RelayPoolNotification>,
        timeout_ms: u64,
    ) -> Result<Option<SwapRequest>, Error> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);

        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }
            let recv = tokio::time::timeout(remaining, rx.recv()).await;
            let notif = match recv {
                Ok(Ok(n)) => n,
                Ok(Err(_)) | Err(_) => return Ok(None),
            };
            if let RelayPoolNotification::Event { event, .. } = notif {
                if event.kind.as_u16() != KIND_SWAP_REQUEST {
                    continue;
                }
                if let Ok(mut req) = serde_json::from_str::<SwapRequest>(&event.content) {
                    req.event_id = event.id.to_hex();
                    req.taker_pubkey = event.pubkey.to_hex();
                    req.timestamp = event.created_at.as_u64();
                    return Ok(Some(req));
                }
            }
        }
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

        // Filter by the author who actually signs the ad. Post-cutover that's
        // the operator pubkey (signer-mediated); legacy single-key deployments
        // still sign with self.keys (the daemon-held identity), so fall back
        // to that when no operator pubkey was registered.
        let author = self
            .operator_pubkey
            .lock()
            .ok()
            .and_then(|g| *g)
            .unwrap_or_else(|| self.keys.public_key());

        let filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_ADVERTISE))
            .author(author);

        let events = match self
            .client
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
            match tokio::time::timeout(std::time::Duration::from_secs(5), slow.send_event(event))
                .await
            {
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
            .custom_tag(TAG_LEDGER_ID, [ledger_id])
            .limit(1);

        let events = self
            .client
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
    pub async fn fetch_disputes(&self, ledger_id: &str) -> Result<Vec<LedgerDispute>, Error> {
        let filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_DISPUTE))
            .custom_tag(TAG_LEDGER_REQ, [ledger_id]);

        let events = self
            .client
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
    ) -> Result<Vec<deposits_protocol::types::SignedLedgerUpdate>, Error> {
        use ::base64::{engine::general_purpose::STANDARD as BASE64, Engine};

        let filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_UPDATE))
            .custom_tag(TAG_LEDGER_ID, [ledger_tag(ledger_id)]);

        let events = self
            .client
            .fetch_events(vec![filter], Some(std::time::Duration::from_secs(10)))
            .await
            .map_err(|e| Error::Nostr(format!("Failed to fetch ledger updates: {}", e)))?;

        let mut updates = Vec::new();
        for event in events.iter() {
            // Updates are base64-encoded SignedLedgerUpdate
            if let Ok(bytes) = BASE64.decode(&event.content) {
                if let Ok(update) = deposits_protocol::types::SignedLedgerUpdate::tlv_decode(&bytes) {
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
    ) -> Result<Option<deposits_protocol::types::SignedLedgerUpdate>, Error> {
        use ::base64::{engine::general_purpose::STANDARD as BASE64, Engine};

        let filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_UPDATE))
            .custom_tag(TAG_LEDGER_ID, [ledger_tag(ledger_id)]);

        let events = self
            .client
            .fetch_events(vec![filter], Some(std::time::Duration::from_secs(5)))
            .await
            .map_err(|e| Error::Nostr(format!("Failed to fetch update seq {}: {}", seq, e)))?;

        for event in events.iter() {
            if let Ok(bytes) = BASE64.decode(&event.content) {
                if let Ok(update) = deposits_protocol::types::SignedLedgerUpdate::tlv_decode(&bytes) {
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
    ) -> Result<Vec<deposits_protocol::types::SignedLedgerUpdate>, Error> {
        use ::base64::{engine::general_purpose::STANDARD as BASE64, Engine};

        let filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_UPDATE))
            .custom_tag(TAG_LEDGER_ID, [ledger_tag(ledger_id)]);

        let events = self
            .client
            .fetch_events(vec![filter], Some(std::time::Duration::from_secs(10)))
            .await
            .map_err(|e| Error::Nostr(format!("Failed to fetch updates range: {}", e)))?;

        let mut updates = Vec::new();
        for event in events.iter() {
            if let Ok(bytes) = BASE64.decode(&event.content) {
                if let Ok(update) = deposits_protocol::types::SignedLedgerUpdate::tlv_decode(&bytes) {
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
                tracing::debug!(
                    "Already subscribed to requests for ledger {}",
                    &ledger_id[..16.min(ledger_id.len())]
                );
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

        tracing::debug!(
            "Subscribed to ledger requests (kind {}) for ledger: {}",
            KIND_LEDGER_REQUEST,
            &ledger_id[..16.min(ledger_id.len())]
        );
        Ok(())
    }

    /// Fetch recent ledger requests (polling fallback).
    /// Uses per-ledger #l tag filtering when request_ledger_filter is set.
    pub async fn fetch_recent_requests(
        &self,
        since_secs: u64,
    ) -> Result<Vec<LedgerRequest>, Error> {
        use nostr_sdk::Timestamp;

        let since = Timestamp::now() - since_secs;
        let ledger_ids = self.request_ledger_filter.read().unwrap().clone();
        let filters = if !ledger_ids.is_empty() {
            ledger_ids
                .iter()
                .map(|lid| {
                    Filter::new()
                        .kind(Kind::Custom(KIND_LEDGER_REQUEST))
                        .custom_tag(TAG_LEDGER_REQ, [lid.as_str()])
                        .since(since)
                })
                .collect::<Vec<_>>()
        } else {
            vec![Filter::new()
                .kind(Kind::Custom(KIND_LEDGER_REQUEST))
                .since(since)]
        };

        let events = self
            .client
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
            ledger_ids
                .iter()
                .map(|lid| {
                    Filter::new()
                        .kind(Kind::Custom(KIND_LEDGER_RESPONSE))
                        .custom_tag(TAG_LEDGER_REQ, [lid.as_str()])
                        .since(since)
                })
                .collect::<Vec<_>>()
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
            tracing::info!(
                "Subscribed to ledger responses (kind {}) for {} ledgers",
                KIND_LEDGER_RESPONSE,
                filter_count
            );
        } else {
            tracing::info!(
                "Subscribed to all ledger responses (kind {}) - no filter",
                KIND_LEDGER_RESPONSE
            );
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
        let events = match self
            .client
            .fetch_events(vec![filter], Some(tokio::time::Duration::from_secs(1)))
            .await
        {
            Ok(e) => e,
            Err(e) => {
                tracing::debug!("fetch_events error (will retry): {}", e);
                return Ok(None);
            }
        };

        tracing::debug!(
            "Fetched {} response events, looking for request {}",
            events.len(),
            &request_id[..16]
        );

        for event in events.into_iter() {
            if let Ok(response) = self.process_ledger_response(&event) {
                tracing::debug!(
                    "Found response for request {}, comparing with {}",
                    &response.request_id[..16.min(response.request_id.len())],
                    &request_id[..16]
                );
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
                return Err(Error::Nostr(
                    "Timeout waiting for valid response".to_string(),
                ));
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
                    return Err(Error::Nostr(
                        "Timeout waiting for valid response".to_string(),
                    ));
                }
            }
        }
    }

    /// Wait for a specific response using real-time subscription (low latency)
    /// This is much faster than polling - typically <5ms vs 100-200ms
    pub async fn wait_for_response(
        &self,
        request_id: &str,
        timeout_ms: u64,
    ) -> Result<LedgerResponse, Error> {
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
    pub async fn fetch_responses_since(
        &self,
        _since: nostr_sdk::Timestamp,
    ) -> Result<Vec<LedgerResponse>, Error> {
        // Ignore 'since' and use a fixed 5-minute lookback to avoid timestamp sync issues
        // The strfry relay may have clock drift or event ordering issues with recent events
        let since = nostr_sdk::Timestamp::now() - 300;
        let filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_RESPONSE))
            .since(since);

        // Use 200ms timeout - relay should respond almost instantly with stored events
        let events = self
            .client
            .fetch_events(vec![filter], Some(tokio::time::Duration::from_millis(200)))
            .await
            .map_err(|e| Error::Nostr(format!("Failed to fetch events: {}", e)))?;

        tracing::debug!(
            "fetch_responses_since: fetched {} KIND_LEDGER_RESPONSE events (5 min lookback)",
            events.len()
        );

        let mut responses = Vec::new();
        for event in events.into_iter() {
            if let Ok(response) = self.process_ledger_response(&event) {
                tracing::debug!(
                    "  -> response for request: {}...",
                    &response.request_id[..16.min(response.request_id.len())]
                );
                responses.push(response);
            }
        }

        Ok(responses)
    }

    /// Start listening for inbound messages
    pub async fn start_listening(&self) -> Result<(), Error> {
        // Subscribe to DMs addressed to us. Post-cutover `self.keys` is the
        // delegate, but legacy wallets still address by operator pubkey, so
        // when we have a registered operator pubkey we add a second filter
        // covering its `#p` tag too. The dual-decrypt path in
        // `nip04_decrypt_with_fallback` then unwraps either kind.
        let mut filters = vec![Filter::new()
            .kind(Kind::EncryptedDirectMessage)
            .pubkey(self.keys.public_key())];

        if let Some(op_pk) = self.operator_pubkey.lock().ok().and_then(|g| *g) {
            if op_pk != self.keys.public_key() {
                filters.push(
                    Filter::new()
                        .kind(Kind::EncryptedDirectMessage)
                        .pubkey(op_pk),
                );
            }
        }

        self.client
            .subscribe(filters, None)
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
                if let Ok(Ok(notification)) = tokio::time::timeout(timeout, rx.recv()).await {
                    self.handle_notification(notification);
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
                if self.handle_notification(notification) {
                    drain_count += 1;
                } else {
                    dedup_count += 1;
                }
                // Drain pending notifications with time budget
                loop {
                    if drain_start.elapsed() >= drain_budget {
                        break;
                    }
                    match rx.try_recv() {
                        Ok(notification) => {
                            if self.handle_notification(notification) {
                                drain_count += 1;
                            } else {
                                dedup_count += 1;
                            }
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
                tracing::warn!(
                    "Daemon notification receiver lagged by {} events, re-syncing",
                    n
                );
                // After lag, drain what we can (with budget)
                loop {
                    if drain_start.elapsed() >= drain_budget {
                        break;
                    }
                    match rx.try_recv() {
                        Ok(notification) => {
                            if self.handle_notification(notification) {
                                drain_count += 1;
                            } else {
                                dedup_count += 1;
                            }
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
        if let Ok(events) = self
            .client
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
    pub fn create_notification_receiver(
        &self,
    ) -> tokio::sync::broadcast::Receiver<RelayPoolNotification> {
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
    pub fn dispatch_or_extract_request(
        &self,
        notification: RelayPoolNotification,
        extract_action: &str,
    ) -> Option<LedgerRequest> {
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
            // Span the per-event processing tagged with event_id + kind so a
            // tracing-flame capture lets us see which events dominate
            // wall-clock time and how many times each is re-delivered. Kept
            // at debug level so production runs aren't swamped; enable with
            // RUST_LOG=deposits_node::nostr=debug.
            let event_id_short = event.id.to_hex();
            let kind_num_for_span = event.kind.as_u16();
            let _span = tracing::debug_span!(
                "handle_notification",
                event_id = &event_id_short[..16],
                kind = kind_num_for_span,
            )
            .entered();
            {
                let seen = self.seen_events.lock().unwrap();
                if seen.contains(&event_id_bytes)
                    || self
                        .seen_events_prev
                        .lock()
                        .unwrap()
                        .contains(&event_id_bytes)
                {
                    tracing::trace!(event_id = &event_id_short[..16], "dedup'd duplicate");
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
            if !interested.is_empty() && kind_num != 4
            /* EncryptedDirectMessage */
            {
                // Admin / peer-addressed events (#p = our pubkey) bypass the
                // ledger filter — they're meant for us regardless of which
                // ledger they reference. Without this, gift-wrapped admin
                // requests (ledger_open, reserves_create) get dropped as
                // soon as the daemon has any ledger in its interested set.
                // Two valid recipients: the daemon's Nostr-layer pubkey
                // (delegate post-cutover) and, when configured, the operator
                // pubkey itself — the dual-decrypt path handles either, but
                // we still need to *let the event through the gate* first.
                let our_xonly_hex = {
                    let (xo, _) = self.our_pubkey.x_only_public_key();
                    hex::encode(xo.serialize())
                };
                let operator_xonly_hex = self
                    .operator_pubkey
                    .lock()
                    .ok()
                    .and_then(|g| *g)
                    .map(|pk| pk.to_hex());
                let addressed_to_us = event.tags.iter().any(|tag| {
                    if tag.kind()
                        != TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::P))
                    {
                        return false;
                    }
                    let content = tag.content();
                    content == Some(our_xonly_hex.as_str())
                        || (operator_xonly_hex.is_some()
                            && content == operator_xonly_hex.as_deref())
                });

                if !addressed_to_us {
                    let ledger_id = Self::extract_ledger_id_from_event(&event, kind_num);
                    if let Some(lid) = &ledger_id {
                        if !interested.contains(lid) {
                            if kind_num == KIND_LEDGER_REQUEST {
                                tracing::debug!("Dropping kind {} request for ledger {} (not in interested set: {:?})",
                                    kind_num, lid, interested.iter().collect::<Vec<_>>());
                            }
                            return false; // Not our ledger — drop
                        }
                    }
                    // If no ledger_id could be extracted, let it through (safety)
                }
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
                match self.process_ledger_request(&event) {
                    Ok(request) => {
                        let _ = self.request_tx.send(request);
                    }
                    Err(e) => {
                        tracing::warn!(
                            "process_ledger_request failed for event {}: {}",
                            &event.id.to_hex()[..16],
                            e
                        );
                    }
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
        // Decrypt the content using NIP-04 — try delegate first, fall back
        // to operator key (via Signer) so legacy wallets still work.
        let content = self
            .nip04_decrypt_with_fallback(&event.pubkey, &event.content)
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
        let update = SignedLedgerUpdate::tlv_decode(&tlv_bytes).map_err(|e| {
            Error::Serialization(format!("Failed to decode ledger update: {:?}", e))
        })?;

        let ledger_id = update.ledger_id_hex();

        tracing::trace!(
            "Received ledger update: ledger={}, seq={}, hash={}",
            &ledger_id[..16],
            update.sequence_number,
            &hex::encode(update.content_hash)[..16]
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
        // Try gift-unwrap first: if content isn't valid JSON, try to decrypt
        let (tags, content_str, real_sender, is_wrapped) = match serde_json::from_str::<
            serde_json::Value,
        >(&event.content)
        {
            Ok(_) => {
                // Plaintext — use event directly
                (
                    event.tags.clone(),
                    event.content.clone(),
                    event.pubkey.to_hex(),
                    false,
                )
            }
            Err(_) => {
                // Not JSON — try gift-unwrap. This is a NIP-59-*shaped*
                // envelope but uses NIP-04 (not NIP-44) and Kind 20101
                // for the outer wrap; see `send_admin_request` for the
                // rationale and divergences from real NIP-17.
                let seal_json = self
                    .nip04_decrypt_with_fallback(&event.pubkey, &event.content)
                    .map_err(|e| {
                        Error::Nostr(format!("Gift unwrap outer decrypt failed: {}", e))
                    })?;
                let seal: serde_json::Value = serde_json::from_str(&seal_json)
                    .map_err(|e| Error::Nostr(format!("Gift unwrap seal parse failed: {}", e)))?;
                let seal_pubkey_hex = seal["pubkey"]
                    .as_str()
                    .ok_or_else(|| Error::Nostr("Gift unwrap: missing seal pubkey".to_string()))?;
                let seal_pubkey = nostr_sdk::PublicKey::from_hex(seal_pubkey_hex).map_err(|e| {
                    Error::Nostr(format!("Gift unwrap: invalid seal pubkey: {}", e))
                })?;
                let rumor_json = self
                    .nip04_decrypt_with_fallback(
                        &seal_pubkey,
                        seal["content"].as_str().unwrap_or(""),
                    )
                    .map_err(|e| {
                        Error::Nostr(format!("Gift unwrap seal decrypt failed: {}", e))
                    })?;
                let rumor: serde_json::Value = serde_json::from_str(&rumor_json)
                    .map_err(|e| Error::Nostr(format!("Gift unwrap rumor parse failed: {}", e)))?;

                // Extract tags from rumor
                let mut rumor_tags = nostr_sdk::event::tag::Tags::new(vec![]);
                if let Some(tags_arr) = rumor.get("tags").and_then(|t| t.as_array()) {
                    for tag_arr in tags_arr {
                        if let Some(strs) = tag_arr.as_array() {
                            let parts: Vec<String> = strs
                                .iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect();
                            if parts.len() >= 2 {
                                rumor_tags = nostr_sdk::event::tag::Tags::new(
                                    rumor_tags
                                        .iter()
                                        .cloned()
                                        .chain(std::iter::once(Tag::custom(
                                            TagKind::custom(&parts[0]),
                                            parts[1..].iter().map(|s| s.as_str()),
                                        )))
                                        .collect(),
                                );
                            }
                        }
                    }
                }
                let real_sender = rumor["pubkey"]
                    .as_str()
                    .unwrap_or(seal_pubkey_hex)
                    .to_string();
                let content = rumor["content"].as_str().unwrap_or("").to_string();
                tracing::debug!(
                    "Gift-unwrapped request from {}...",
                    &real_sender[..16.min(real_sender.len())]
                );
                (rumor_tags, content, real_sender, true)
            }
        };

        // Extract ledger_id from the l tag
        let ledger_id = tags
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
        let action = tags
            .iter()
            .find_map(|tag| {
                if tag.kind() == TagKind::custom("action") {
                    tag.content().map(|s| s.to_string())
                } else {
                    None
                }
            })
            .ok_or_else(|| Error::Nostr("Missing action tag in ledger request".to_string()))?;

        // Extract DEP-04 subkey delegation tags, if present:
        //   ["v",  "<account xonly hex>"]
        //   ["va", "<schnorr sig hex>"]
        // Signature verification + Kind 10301 policy check happen in the
        // handler — we just surface the raw values here.
        let subkey_account = tags.iter().find_map(|tag| {
            if tag.kind()
                == TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::V))
            {
                tag.content().map(|s| s.to_string())
            } else {
                None
            }
        });
        let subkey_attestation = tags.iter().find_map(|tag| {
            if tag.kind() == TagKind::custom("va") {
                tag.content().map(|s| s.to_string())
            } else {
                None
            }
        });

        // Parse params from content
        let params: serde_json::Value =
            serde_json::from_str(&content_str).unwrap_or(serde_json::Value::Null);

        tracing::trace!(
            "Received ledger request: ledger={}, action={}, event={} wrapped={}",
            ledger_id,
            action,
            &event.id.to_hex()[..16],
            is_wrapped,
        );

        Ok(LedgerRequest {
            action,
            ledger_id,
            params,
            event_id: event.id.to_hex(),
            sender: real_sender.clone(),
            timestamp: event.created_at.as_u64(),
            gift_wrap_sender: if is_wrapped { Some(real_sender) } else { None },
            subkey_account,
            subkey_attestation,
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

        // Parse response from content. If the content isn't valid JSON, the
        // response may be gift-wrapped (matches `send_ledger_response` with
        // gift_wrap_to set, e.g. replies to admin-class requests): decrypt
        // the outer layer, pull the rumor out of the seal, then parse the
        // rumor's content as LedgerResponse.
        let response_text: String = match serde_json::from_str::<LedgerResponse>(&event.content) {
            Ok(_) => event.content.clone(),
            Err(_) => {
                // Gift-unwrap
                let seal_json = self
                    .nip04_decrypt_with_fallback(&event.pubkey, &event.content)
                    .map_err(|e| {
                        Error::Nostr(format!("response gift unwrap outer failed: {}", e))
                    })?;
                let seal: serde_json::Value = serde_json::from_str(&seal_json).map_err(|e| {
                    Error::Nostr(format!("response gift unwrap seal parse failed: {}", e))
                })?;
                let seal_pubkey_hex = seal["pubkey"].as_str().ok_or_else(|| {
                    Error::Nostr("response gift unwrap: missing seal pubkey".to_string())
                })?;
                let seal_pubkey = nostr_sdk::PublicKey::from_hex(seal_pubkey_hex).map_err(|e| {
                    Error::Nostr(format!("response gift unwrap: invalid seal pubkey: {}", e))
                })?;
                let rumor_json = self
                    .nip04_decrypt_with_fallback(
                        &seal_pubkey,
                        seal["content"].as_str().unwrap_or(""),
                    )
                    .map_err(|e| {
                        Error::Nostr(format!("response gift unwrap seal decrypt failed: {}", e))
                    })?;
                let rumor: serde_json::Value = serde_json::from_str(&rumor_json).map_err(|e| {
                    Error::Nostr(format!("response gift unwrap rumor parse failed: {}", e))
                })?;
                // The rumor carries the response payload as `content` (see
                // send_ledger_response's gift-wrap branch).
                rumor["content"].as_str().unwrap_or_default().to_string()
            }
        };

        let mut response: LedgerResponse = serde_json::from_str(&response_text).unwrap_or_else(
            |_| LedgerResponse {
                success: status == "ok",
                result: None,
                error: Some("Failed to parse response".to_string()),
                request_id: String::new(),
                ledger_id: String::new(),
                event_id: String::new(),
                timestamp: 0,
            },
        );

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
        let broadcast: deposits_protocol::fraud::FraudBroadcast = serde_json::from_str(&event.content)
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
        let connected = relays
            .values()
            .filter(|r| r.status() == nostr_sdk::RelayStatus::Connected)
            .count();
        let details: Vec<_> = relays
            .iter()
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
        NostrTransport::new_with_slow(
            self.secret_key,
            self.relays,
            self.slow_relays,
            self.skip_nostr_verify,
        )
        .await
    }
}

#[cfg(test)]
mod custody_lottery_reveal_tests {
    use super::*;

    #[test]
    fn custody_lottery_reveal_json_roundtrip() {
        // Locks down the on-the-wire JSON shape of CustodyLotteryReveal —
        // any rename or field reorder would break wire compat with peers
        // running an older release. Skipped fields (event_id, timestamp)
        // must reset to defaults on parse.
        let r = CustodyLotteryReveal {
            member_pubkey: "02".to_string() + &"00".repeat(32),
            ledger_id: "abc123".into(),
            preimage_hex: "deadbeef".to_string() + &"00".repeat(15),
            signature: "ff".repeat(64),
            event_id: "should-not-serialize".into(),
            timestamp: 999,
        };

        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"member_pubkey\""));
        assert!(json.contains("\"ledger_id\""));
        assert!(json.contains("\"preimage_hex\""));
        assert!(json.contains("\"signature\""));
        assert!(!json.contains("\"event_id\""), "event_id must be #[serde(skip)]");
        assert!(!json.contains("\"timestamp\""), "timestamp must be #[serde(skip)]");

        let parsed: CustodyLotteryReveal = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.member_pubkey, r.member_pubkey);
        assert_eq!(parsed.ledger_id, r.ledger_id);
        assert_eq!(parsed.preimage_hex, r.preimage_hex);
        assert_eq!(parsed.signature, r.signature);
        assert_eq!(parsed.event_id, "");
        assert_eq!(parsed.timestamp, 0);
    }

    #[test]
    fn custody_lottery_reveal_kind_is_durable() {
        // KIND_CUSTODY_LOTTERY_REVEAL must be in the 1000-9999 range so
        // relays retain the events. Other disputants need to fetch
        // these reveals well after publish; ephemeral kinds (20000+)
        // would be auto-deleted by the relay.
        assert!(
            (1000..=9999).contains(&KIND_CUSTODY_LOTTERY_REVEAL),
            "KIND_CUSTODY_LOTTERY_REVEAL ({}) must be in the durable range",
            KIND_CUSTODY_LOTTERY_REVEAL
        );
        // Sits in the dispute-related cluster (9100-9106).
        assert_eq!(KIND_CUSTODY_LOTTERY_REVEAL, 9106);
    }
}

#[cfg(test)]
mod ledger_advertisement_tests {
    use super::*;

    #[test]
    fn minimum_fees_converts_annualized_to_per_period() {
        // The advertisement stores `annualized_fixed_msats` as msats/year,
        // but `validate_fee_minimum` compares against per-period — so this
        // accessor MUST do the division. Returning the raw annualized
        // number inflates the floor by the periods-per-year factor.
        // Regression-locks the wallet-deposit-open path for operators
        // who haven't written an `operator_policy.json` yet.
        let mut ad = LedgerAdvertisement::new(
            "0".repeat(64),
            "0".repeat(66),
            String::new(),
            "regtest".into(),
        );
        ad.annual_fee_bps = 50;
        ad.annualized_fixed_msats = 2_500_000;   // 2500 sats/year
        ad.fee_period_blocks = 2016;             // ≈ 2 weeks → 26 periods/year

        let (bps, fixed_per_period) = ad.minimum_fees();
        assert_eq!(bps, 50);
        // 52560 / 2016 = 26 periods/year; 2_500_000 / 26 = 96_153 msats/period
        assert_eq!(fixed_per_period, 96_153);
    }
}
