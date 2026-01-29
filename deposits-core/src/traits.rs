// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Adapter Traits for Bitcoin Deposits Protocol
//!
//! These traits abstract the Lightning implementation-specific functionality,
//! allowing the deposits protocol to work with LDK, CLN, or any other implementation.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                  deposits-core (this crate)                      │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  Protocol logic using these traits                              │
//! └─────────────────────────────────────────────────────────────────┘
//!                            │
//!                            ▼
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                     Adapter Traits                               │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  PeerTransport, PaymentTracker, ChannelRegistry, Storage, etc.  │
//! └─────────────────────────────────────────────────────────────────┘
//!                            │
//!             ┌──────────────┴──────────────┐
//!             ▼                             ▼
//! ┌─────────────────────────┐   ┌─────────────────────────┐
//! │  deposits-ldk           │   │  deposits-cln           │
//! │  (LDK adapter)          │   │  (CLN adapter)          │
//! └─────────────────────────┘   └─────────────────────────┘
//! ```

use bitcoin::secp256k1::PublicKey;
use std::fmt;
use std::sync::Arc;

// ============================================================================
// Error Types
// ============================================================================

/// Error from peer transport operations
#[derive(Debug, Clone)]
pub enum TransportError {
    /// Peer is not connected
    PeerNotConnected(PublicKey),
    /// Message encoding failed
    EncodingError(String),
    /// Send queue is full
    QueueFull,
    /// Transport is shutting down
    Shutdown,
    /// Other transport error
    Other(String),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PeerNotConnected(pk) => write!(f, "peer not connected: {}", pk),
            Self::EncodingError(e) => write!(f, "encoding error: {}", e),
            Self::QueueFull => write!(f, "send queue full"),
            Self::Shutdown => write!(f, "transport shutting down"),
            Self::Other(e) => write!(f, "transport error: {}", e),
        }
    }
}

impl std::error::Error for TransportError {}

/// Error from message handling
#[derive(Debug, Clone)]
pub enum HandleError {
    /// Message format is invalid
    InvalidMessage(String),
    /// Message references unknown ledger
    UnknownLedger { operator: PublicKey, partner: PublicKey },
    /// Validation failed
    ValidationFailed(String),
    /// Internal error
    Internal(String),
}

impl fmt::Display for HandleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMessage(e) => write!(f, "invalid message: {}", e),
            Self::UnknownLedger { operator, partner } => {
                write!(f, "unknown ledger: {} -> {}", operator, partner)
            }
            Self::ValidationFailed(e) => write!(f, "validation failed: {}", e),
            Self::Internal(e) => write!(f, "internal error: {}", e),
        }
    }
}

impl std::error::Error for HandleError {}

/// Error from storage operations
#[derive(Debug, Clone)]
pub enum StorageError {
    /// Key not found
    NotFound,
    /// Serialization error
    SerializationError(String),
    /// IO error
    IoError(String),
    /// Storage is read-only
    ReadOnly,
    /// Other storage error
    Other(String),
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => write!(f, "key not found"),
            Self::SerializationError(e) => write!(f, "serialization error: {}", e),
            Self::IoError(e) => write!(f, "IO error: {}", e),
            Self::ReadOnly => write!(f, "storage is read-only"),
            Self::Other(e) => write!(f, "storage error: {}", e),
        }
    }
}

impl std::error::Error for StorageError {}

/// Error from broadcast operations
#[derive(Debug, Clone)]
pub enum BroadcastError {
    /// Transaction is invalid
    InvalidTransaction(String),
    /// Network error
    NetworkError(String),
    /// Transaction was rejected
    Rejected(String),
    /// Other broadcast error
    Other(String),
}

impl fmt::Display for BroadcastError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTransaction(e) => write!(f, "invalid transaction: {}", e),
            Self::NetworkError(e) => write!(f, "network error: {}", e),
            Self::Rejected(e) => write!(f, "transaction rejected: {}", e),
            Self::Other(e) => write!(f, "broadcast error: {}", e),
        }
    }
}

impl std::error::Error for BroadcastError {}

// ============================================================================
// Peer Transport
// ============================================================================

/// Send protocol messages to peers over Lightning gossip
///
/// This trait abstracts the peer-to-peer messaging layer. In LDK, this is
/// implemented via `CustomMessageHandler`. Other implementations may use
/// different mechanisms (e.g., CLN's plugin messaging).
pub trait PeerTransport: Send + Sync {
    /// Send a message to a specific peer
    ///
    /// The message bytes should be the encoded V2 protocol message
    /// (including the 2-byte type prefix).
    fn send(&self, peer: PublicKey, message: &[u8]) -> Result<(), TransportError>;

    /// Broadcast a message to multiple peers
    ///
    /// Default implementation sends to each peer individually.
    fn broadcast(&self, peers: &[PublicKey], message: &[u8]) -> Result<(), TransportError> {
        for peer in peers {
            self.send(*peer, message)?;
        }
        Ok(())
    }

    /// Check if a peer is currently connected
    fn is_connected(&self, peer: &PublicKey) -> bool;

    /// Get list of currently connected peers
    fn connected_peers(&self) -> Vec<PublicKey>;
}

// ============================================================================
// Message Handler
// ============================================================================

/// Receive and process incoming protocol messages
///
/// This trait is implemented by the deposits handler and called by the
/// transport layer when messages arrive.
pub trait MessageHandler: Send + Sync {
    /// Handle an incoming message from a peer
    ///
    /// Returns an optional response message to send back.
    fn handle_message(
        &self,
        sender: PublicKey,
        message: &[u8],
    ) -> Result<Option<Vec<u8>>, HandleError>;

    /// Called when a peer connects
    fn peer_connected(&self, peer: PublicKey);

    /// Called when a peer disconnects
    fn peer_disconnected(&self, peer: PublicKey);
}

// ============================================================================
// Payment Tracking
// ============================================================================

/// Status of a Lightning payment
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymentStatus {
    /// Payment is pending (in-flight)
    Pending,
    /// Payment completed successfully
    Succeeded,
    /// Payment failed
    Failed,
    /// Payment status unknown
    Unknown,
}

/// Track Lightning payments for deposit crediting
///
/// This trait abstracts payment tracking. The deposits protocol needs to know
/// when payments succeed or fail to properly credit deposits and release locks.
pub trait PaymentTracker: Send + Sync {
    /// Check if a payment with this hash was received
    ///
    /// Returns true if payment was received and should be credited.
    /// The `amount_msat` is the expected amount.
    fn payment_received(&self, payment_hash: [u8; 32], amount_msat: u64) -> bool;

    /// Notify that a payment was sent
    ///
    /// Called when an outgoing payment completes (success or failure).
    fn payment_sent(&self, payment_id: [u8; 32], success: bool);

    /// Get the status of a payment by ID
    fn get_payment_status(&self, payment_id: [u8; 32]) -> PaymentStatus;

    /// Get the preimage for a completed payment
    ///
    /// Returns None if payment not found or preimage not available.
    fn get_preimage(&self, payment_hash: [u8; 32]) -> Option<[u8; 32]>;
}

// ============================================================================
// Channel Registry
// ============================================================================

/// Map channels to peers and vice versa
///
/// The deposits protocol needs to know which peer is associated with which
/// channel for routing messages and validating operations.
pub trait ChannelRegistry: Send + Sync {
    /// Get the partner node for a given channel ID
    fn partner_for_channel(&self, channel_id: [u8; 32]) -> Option<PublicKey>;

    /// Get all channel IDs with a specific peer
    fn channels_with_peer(&self, peer: PublicKey) -> Vec<[u8; 32]>;

    /// Check if a channel exists and is usable
    fn channel_is_usable(&self, channel_id: [u8; 32]) -> bool;

    /// Get the local balance in a channel (in millisatoshis)
    fn channel_balance_msat(&self, channel_id: [u8; 32]) -> Option<u64>;
}

// ============================================================================
// Channel Operations
// ============================================================================

/// Basic channel information needed by the deposits protocol
#[derive(Debug, Clone)]
pub struct ChannelInfo {
    /// The channel ID
    pub channel_id: [u8; 32],
    /// The counterparty's node ID
    pub counterparty_node_id: PublicKey,
    /// Funding transaction ID (if confirmed)
    pub funding_txid: Option<[u8; 32]>,
    /// Funding output index
    pub funding_vout: Option<u32>,
    /// Whether the channel is usable for payments
    pub is_usable: bool,
    /// Channel capacity in satoshis
    pub channel_value_satoshis: u64,
    /// Our balance in millisatoshis
    pub balance_msat: u64,
}

/// Extended channel operations needed by the deposits protocol
///
/// This trait provides the channel management operations that go beyond
/// simple registry lookups. It abstracts LDK's ChannelManager functionality.
pub trait ChannelOperations: Send + Sync {
    /// List all channels with a specific counterparty
    fn list_channels_with_counterparty(&self, counterparty: &PublicKey) -> Vec<ChannelInfo>;

    /// List all channels
    fn list_channels(&self) -> Vec<ChannelInfo>;

    /// Get the first channel with a counterparty (convenience method)
    fn get_channel_with_counterparty(&self, counterparty: &PublicKey) -> Option<ChannelInfo> {
        self.list_channels_with_counterparty(counterparty).into_iter().next()
    }

    /// Get channel IDs for all partners we have channels with
    fn get_all_channel_partners(&self) -> Vec<PublicKey> {
        let channels = self.list_channels();
        let mut partners: Vec<PublicKey> = channels
            .into_iter()
            .map(|ch| ch.counterparty_node_id)
            .collect();
        partners.sort_by_key(|pk| pk.serialize());
        partners.dedup();
        partners
    }

    /// Force-close a channel with an optional reason message
    fn force_close_channel(
        &self,
        channel_id: &[u8; 32],
        counterparty: &PublicKey,
        reason: &str,
    ) -> Result<(), String>;
}

// ============================================================================
// Reserves Operations (Bitcoin Deposits Protocol Specific)
// ============================================================================

/// Operations for managing reserves commitments on Lightning channels
///
/// These operations are specific to the Bitcoin Deposits protocol and
/// manage the reserves state that is committed in channel transactions.
pub trait ReservesOperations: Send + Sync {
    /// Update the local reserves commitment for a channel
    ///
    /// This sets the reserves amount and ledger hash that will be
    /// included in the next commitment transaction.
    fn update_local_reserves(
        &self,
        counterparty: &PublicKey,
        channel_id: &[u8; 32],
        reserves_sats: u64,
        ledger_hash: [u8; 32],
    ) -> Result<(), String>;

    /// Get the currently committed local reserves ledger hash
    ///
    /// Returns the ledger hash that is in the current commitment transaction.
    fn get_committed_reserves_hash(
        &self,
        counterparty: &PublicKey,
        channel_id: &[u8; 32],
    ) -> Option<[u8; 32]>;

    /// Check if there are pending (uncommitted) reserves updates
    fn has_pending_reserves(
        &self,
        counterparty: &PublicKey,
        channel_id: &[u8; 32],
    ) -> bool;

    /// Get both local and remote reserves hashes for a channel
    fn get_reserves_hashes(
        &self,
        counterparty: &PublicKey,
    ) -> (Option<[u8; 32]>, Option<[u8; 32]>);
}

// ============================================================================
// Storage
// ============================================================================

/// Persist protocol state
///
/// This trait abstracts the storage layer. Implementations may use
/// filesystem, database, or any other persistence mechanism.
pub trait Storage: Send + Sync {
    /// Get a value by key
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError>;

    /// Store a value
    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError>;

    /// Delete a value
    fn delete(&self, key: &[u8]) -> Result<(), StorageError>;

    /// Scan all keys with a given prefix
    ///
    /// Returns key-value pairs sorted by key.
    fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError>;

    /// Check if a key exists
    fn exists(&self, key: &[u8]) -> Result<bool, StorageError> {
        Ok(self.get(key)?.is_some())
    }
}

// ============================================================================
// Deposits Storage Provider
// ============================================================================

use crate::types::{LedgerState, Deposit, ReservesOutput, SignedLedgerUpdate};
use crate::tlv::{TlvEncode, TlvDecode};

/// High-level storage provider for Bitcoin Deposits protocol.
///
/// This trait provides typed access to protocol state, using TLV encoding
/// for serialization (same format as wire protocol). Implementations wrap
/// a low-level key-value store.
///
/// # Key Format
/// Keys are structured as: `{namespace}/{type}/{id}`
/// - namespace: "deposits"
/// - type: "ledger", "deposit", "reserves", "updates"
/// - id: hex-encoded identifier (pubkey or hash)
pub trait DepositsStorage: Send + Sync {
    // ========================================================================
    // Ledger State
    // ========================================================================

    /// Get ledger state for an operator-partner pair.
    fn get_ledger_state(
        &self,
        operator: &PublicKey,
        partner: &PublicKey,
    ) -> Result<Option<LedgerState>, StorageError>;

    /// Store ledger state.
    fn put_ledger_state(&self, state: &LedgerState) -> Result<(), StorageError>;

    /// Delete ledger state.
    fn delete_ledger_state(
        &self,
        operator: &PublicKey,
        partner: &PublicKey,
    ) -> Result<(), StorageError>;

    /// List all ledger states.
    fn list_ledger_states(&self) -> Result<Vec<LedgerState>, StorageError>;

    // ========================================================================
    // Deposits
    // ========================================================================

    /// Get a deposit by pubkey within a ledger.
    fn get_deposit(
        &self,
        operator: &PublicKey,
        partner: &PublicKey,
        deposit_pubkey: &PublicKey,
    ) -> Result<Option<Deposit>, StorageError>;

    /// Store a deposit.
    fn put_deposit(
        &self,
        operator: &PublicKey,
        partner: &PublicKey,
        deposit: &Deposit,
    ) -> Result<(), StorageError>;

    /// Delete a deposit.
    fn delete_deposit(
        &self,
        operator: &PublicKey,
        partner: &PublicKey,
        deposit_pubkey: &PublicKey,
    ) -> Result<(), StorageError>;

    /// List all deposits for a ledger.
    fn list_deposits(
        &self,
        operator: &PublicKey,
        partner: &PublicKey,
    ) -> Result<Vec<Deposit>, StorageError>;

    // ========================================================================
    // Reserves
    // ========================================================================

    /// Get reserves output for a ledger.
    fn get_reserves(
        &self,
        operator: &PublicKey,
        partner: &PublicKey,
    ) -> Result<Option<ReservesOutput>, StorageError>;

    /// Store reserves output.
    fn put_reserves(
        &self,
        operator: &PublicKey,
        partner: &PublicKey,
        reserves: &ReservesOutput,
    ) -> Result<(), StorageError>;

    // ========================================================================
    // Signed Updates (Audit Trail)
    // ========================================================================

    /// Append a signed update to the ledger's audit trail.
    fn append_signed_update(
        &self,
        operator: &PublicKey,
        partner: &PublicKey,
        update: &SignedLedgerUpdate,
    ) -> Result<(), StorageError>;

    /// Get signed updates for a ledger (optionally from a sequence number).
    fn get_signed_updates(
        &self,
        operator: &PublicKey,
        partner: &PublicKey,
        from_sequence: Option<u64>,
    ) -> Result<Vec<SignedLedgerUpdate>, StorageError>;
}

/// Default implementation using a low-level Storage backend.
///
/// Uses JSON for complex types (LedgerState) and TLV for simpler types
/// (Deposit, ReservesOutput, SignedLedgerUpdate).
pub struct DefaultStorageProvider<S: Storage> {
    storage: S,
}

impl<S: Storage> DefaultStorageProvider<S> {
    /// Create a new storage provider wrapping a low-level storage backend.
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    /// Build a key for ledger state.
    fn ledger_key(operator: &PublicKey, partner: &PublicKey) -> Vec<u8> {
        let mut key = b"deposits/ledger/".to_vec();
        key.extend_from_slice(&operator.serialize());
        key.push(b'/');
        key.extend_from_slice(&partner.serialize());
        key
    }

    /// Build a key for a deposit.
    fn deposit_key(operator: &PublicKey, partner: &PublicKey, deposit_pubkey: &PublicKey) -> Vec<u8> {
        let mut key = b"deposits/deposit/".to_vec();
        key.extend_from_slice(&operator.serialize());
        key.push(b'/');
        key.extend_from_slice(&partner.serialize());
        key.push(b'/');
        key.extend_from_slice(&deposit_pubkey.serialize());
        key
    }

    /// Build a key prefix for deposits in a ledger.
    fn deposits_prefix(operator: &PublicKey, partner: &PublicKey) -> Vec<u8> {
        let mut key = b"deposits/deposit/".to_vec();
        key.extend_from_slice(&operator.serialize());
        key.push(b'/');
        key.extend_from_slice(&partner.serialize());
        key.push(b'/');
        key
    }

    /// Build a key for reserves.
    fn reserves_key(operator: &PublicKey, partner: &PublicKey) -> Vec<u8> {
        let mut key = b"deposits/reserves/".to_vec();
        key.extend_from_slice(&operator.serialize());
        key.push(b'/');
        key.extend_from_slice(&partner.serialize());
        key
    }

    /// Build a key for a signed update.
    fn update_key(operator: &PublicKey, partner: &PublicKey, sequence: u64) -> Vec<u8> {
        let mut key = b"deposits/updates/".to_vec();
        key.extend_from_slice(&operator.serialize());
        key.push(b'/');
        key.extend_from_slice(&partner.serialize());
        key.push(b'/');
        key.extend_from_slice(&sequence.to_be_bytes());
        key
    }

    /// Build a key prefix for updates in a ledger.
    fn updates_prefix(operator: &PublicKey, partner: &PublicKey) -> Vec<u8> {
        let mut key = b"deposits/updates/".to_vec();
        key.extend_from_slice(&operator.serialize());
        key.push(b'/');
        key.extend_from_slice(&partner.serialize());
        key.push(b'/');
        key
    }

    /// Prefix for all ledgers
    fn ledgers_prefix() -> Vec<u8> {
        b"deposits/ledger/".to_vec()
    }
}

impl<S: Storage> DepositsStorage for DefaultStorageProvider<S> {
    fn get_ledger_state(
        &self,
        operator: &PublicKey,
        partner: &PublicKey,
    ) -> Result<Option<LedgerState>, StorageError> {
        let key = Self::ledger_key(operator, partner);
        match self.storage.get(&key)? {
            Some(bytes) => {
                let state: LedgerState = serde_json::from_slice(&bytes)
                    .map_err(|e| StorageError::SerializationError(e.to_string()))?;
                Ok(Some(state))
            }
            None => Ok(None),
        }
    }

    fn put_ledger_state(&self, state: &LedgerState) -> Result<(), StorageError> {
        let key = Self::ledger_key(&state.operator_key, &state.reserves_key);
        let bytes = serde_json::to_vec(state)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;
        self.storage.put(&key, &bytes)
    }

    fn delete_ledger_state(
        &self,
        operator: &PublicKey,
        partner: &PublicKey,
    ) -> Result<(), StorageError> {
        let key = Self::ledger_key(operator, partner);
        self.storage.delete(&key)
    }

    fn list_ledger_states(&self) -> Result<Vec<LedgerState>, StorageError> {
        let prefix = Self::ledgers_prefix();
        let items = self.storage.scan_prefix(&prefix)?;
        let mut states = Vec::new();
        for (_key, bytes) in items {
            let state: LedgerState = serde_json::from_slice(&bytes)
                .map_err(|e| StorageError::SerializationError(e.to_string()))?;
            states.push(state);
        }
        Ok(states)
    }

    fn get_deposit(
        &self,
        operator: &PublicKey,
        partner: &PublicKey,
        deposit_pubkey: &PublicKey,
    ) -> Result<Option<Deposit>, StorageError> {
        let key = Self::deposit_key(operator, partner, deposit_pubkey);
        match self.storage.get(&key)? {
            Some(bytes) => {
                let deposit = Deposit::tlv_decode(&bytes)
                    .map_err(|e| StorageError::SerializationError(e.to_string()))?;
                Ok(Some(deposit))
            }
            None => Ok(None),
        }
    }

    fn put_deposit(
        &self,
        operator: &PublicKey,
        partner: &PublicKey,
        deposit: &Deposit,
    ) -> Result<(), StorageError> {
        let key = Self::deposit_key(operator, partner, &deposit.pubkey);
        let bytes = deposit.tlv_encode();
        self.storage.put(&key, &bytes)
    }

    fn delete_deposit(
        &self,
        operator: &PublicKey,
        partner: &PublicKey,
        deposit_pubkey: &PublicKey,
    ) -> Result<(), StorageError> {
        let key = Self::deposit_key(operator, partner, deposit_pubkey);
        self.storage.delete(&key)
    }

    fn list_deposits(
        &self,
        operator: &PublicKey,
        partner: &PublicKey,
    ) -> Result<Vec<Deposit>, StorageError> {
        let prefix = Self::deposits_prefix(operator, partner);
        let items = self.storage.scan_prefix(&prefix)?;
        let mut deposits = Vec::new();
        for (_key, bytes) in items {
            let deposit = Deposit::tlv_decode(&bytes)
                .map_err(|e| StorageError::SerializationError(e.to_string()))?;
            deposits.push(deposit);
        }
        Ok(deposits)
    }

    fn get_reserves(
        &self,
        operator: &PublicKey,
        partner: &PublicKey,
    ) -> Result<Option<ReservesOutput>, StorageError> {
        let key = Self::reserves_key(operator, partner);
        match self.storage.get(&key)? {
            Some(bytes) => {
                let reserves = ReservesOutput::tlv_decode(&bytes)
                    .map_err(|e| StorageError::SerializationError(e.to_string()))?;
                Ok(Some(reserves))
            }
            None => Ok(None),
        }
    }

    fn put_reserves(
        &self,
        operator: &PublicKey,
        partner: &PublicKey,
        reserves: &ReservesOutput,
    ) -> Result<(), StorageError> {
        let key = Self::reserves_key(operator, partner);
        let bytes = reserves.tlv_encode();
        self.storage.put(&key, &bytes)
    }

    fn append_signed_update(
        &self,
        operator: &PublicKey,
        partner: &PublicKey,
        update: &SignedLedgerUpdate,
    ) -> Result<(), StorageError> {
        let key = Self::update_key(operator, partner, update.sequence_number);
        let bytes = update.tlv_encode();
        self.storage.put(&key, &bytes)
    }

    fn get_signed_updates(
        &self,
        operator: &PublicKey,
        partner: &PublicKey,
        from_sequence: Option<u64>,
    ) -> Result<Vec<SignedLedgerUpdate>, StorageError> {
        let prefix = Self::updates_prefix(operator, partner);
        let items = self.storage.scan_prefix(&prefix)?;
        let mut updates = Vec::new();
        for (key, bytes) in items {
            // Extract sequence number from key (last 8 bytes)
            if key.len() >= 8 {
                let seq_bytes: [u8; 8] = key[key.len() - 8..].try_into().unwrap_or([0; 8]);
                let seq = u64::from_be_bytes(seq_bytes);
                if let Some(from) = from_sequence {
                    if seq < from {
                        continue;
                    }
                }
            }
            let update = SignedLedgerUpdate::tlv_decode(&bytes)
                .map_err(|e| StorageError::SerializationError(e.to_string()))?;
            updates.push(update);
        }
        // Sort by sequence number
        updates.sort_by_key(|u| u.sequence_number);
        Ok(updates)
    }
}

// ============================================================================
// Transaction Broadcaster
// ============================================================================

/// Broadcast transactions to the Bitcoin network
///
/// Used for broadcasting claim transactions during recovery.
pub trait Broadcaster: Send + Sync {
    /// Broadcast a transaction
    fn broadcast_transaction(&self, tx: &bitcoin::Transaction) -> Result<(), BroadcastError>;
}

// ============================================================================
// Chain Source
// ============================================================================

/// Query blockchain state
///
/// The deposits protocol needs chain data for:
/// - Block heights (for timelocks, fee collection timing)
/// - Block hashes (for hash commitments)
pub trait ChainSource: Send + Sync {
    /// Get the current best block height
    fn current_height(&self) -> u32;

    /// Get the block hash at a specific height
    ///
    /// Returns None if the height is invalid or not yet known.
    fn get_block_hash(&self, height: u32) -> Option<[u8; 32]>;

    /// Get the current fee rate estimate (sat/vbyte)
    ///
    /// `confirmation_target` is the desired number of blocks for confirmation.
    fn fee_rate(&self, confirmation_target: u32) -> Option<u64>;
}

// ============================================================================
// Signature Provider
// ============================================================================

/// Sign messages and transactions
///
/// The deposits protocol needs to sign:
/// - Ledger updates (operator signature)
/// - Recovery votes
/// - Claim transactions
pub trait SignatureProvider: Send + Sync {
    /// Get the node's public key
    fn node_pubkey(&self) -> PublicKey;

    /// Sign a message hash with the node key (Schnorr signature)
    fn sign_schnorr(&self, message_hash: [u8; 32]) -> Result<[u8; 64], String>;

    /// Verify a Schnorr signature
    fn verify_schnorr(
        &self,
        pubkey: &PublicKey,
        message_hash: [u8; 32],
        signature: &[u8; 64],
    ) -> bool;
}

// ============================================================================
// Event Emitter
// ============================================================================

/// Emit protocol events for external consumers
///
/// Events are used to notify the application layer about important
/// protocol state changes.
pub trait EventEmitter: Send + Sync {
    /// Emit an event
    fn emit(&self, event: ProtocolEvent);
}

/// Protocol events
#[derive(Debug, Clone)]
pub enum ProtocolEvent {
    /// A deposit was opened
    DepositOpened {
        operator: PublicKey,
        partner: PublicKey,
        deposit_pubkey: PublicKey,
    },
    /// A deposit was closed
    DepositClosed {
        operator: PublicKey,
        partner: PublicKey,
        deposit_pubkey: PublicKey,
        final_balance: u64,
    },
    /// A payment was credited to a deposit
    PaymentCredited {
        operator: PublicKey,
        partner: PublicKey,
        deposit_pubkey: PublicKey,
        amount: u64,
        payment_hash: [u8; 32],
    },
    /// A payment was sent from a deposit
    PaymentSent {
        operator: PublicKey,
        partner: PublicKey,
        deposit_pubkey: PublicKey,
        amount: u64,
        payment_id: [u8; 32],
    },
    /// Ledger synchronization completed
    LedgerSynced {
        operator: PublicKey,
        partner: PublicKey,
        sequence: u64,
        hash: [u8; 32],
    },
    /// Recovery voting started
    RecoveryStarted {
        operator: PublicKey,
        partner: PublicKey,
    },
    /// Recovery claim succeeded
    RecoveryClaimed {
        operator: PublicKey,
        partner: PublicKey,
        new_operator: PublicKey,
        claim_txid: [u8; 32],
    },
    /// A protocol error occurred
    Error {
        operator: PublicKey,
        partner: PublicKey,
        error: String,
    },
    /// An uncredited payment accusation was received
    UncreditedPaymentReceived {
        operator: PublicKey,
        partner: PublicKey,
        payment_hash: [u8; 32],
        deposit_pubkey: PublicKey,
        amount_msat: u64,
        settlement_sequence: u64,
    },
    /// Fees were collected from a deposit
    FeeCollected {
        operator: PublicKey,
        partner: PublicKey,
        deposit_pubkey: PublicKey,
        amount: u64,
        block_height: u32,
    },
    /// A ledger was closed
    LedgerClosed {
        operator: PublicKey,
        partner: PublicKey,
    },
    /// An invoice cosign was requested
    InvoiceCosignRequested {
        operator: PublicKey,
        partner: PublicKey,
        deposit_pubkey: PublicKey,
        amount: u64,
        payment_hash: [u8; 32],
    },
    /// A recovery claim was requested
    RecoveryClaimRequested {
        operator: PublicKey,
        partner: PublicKey,
        claimant: PublicKey,
        tier_index: u8,
    },
    /// A recovery claim signature was received
    RecoveryClaimSignatureReceived {
        operator: PublicKey,
        partner: PublicKey,
        signer: PublicKey,
    },
    /// A recovery claim was completed
    RecoveryClaimCompleted {
        old_operator: PublicKey,
        partner: PublicKey,
        new_operator: PublicKey,
        claim_txid: [u8; 32],
        confirmation_block: u32,
    },
    /// A channel was closed (tombstone received)
    ChannelClosed {
        operator: PublicKey,
        partner: PublicKey,
        channel_id: [u8; 32],
        reason: Option<String>,
    },
    /// A quorum member joined
    QuorumMemberJoined {
        operator: PublicKey,
        partner: PublicKey,
        member: PublicKey,
    },
    /// Reserves spend ready after vote threshold reached
    ReservesSpendReady {
        vote_round_id: [u8; 32],
        operator: PublicKey,
        partner: PublicKey,
        signed_tx_bytes: Vec<u8>,
        conforming_votes: u32,
        threshold: u32,
    },
}

// ============================================================================
// Logging
// ============================================================================

/// Log level for the logger trait
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    /// Trace level (most verbose)
    Trace,
    /// Debug level
    Debug,
    /// Info level
    Info,
    /// Warning level
    Warn,
    /// Error level (least verbose)
    Error,
}

/// Logger trait for protocol logging
///
/// This trait allows the deposits protocol to log messages without
/// depending on a specific logging implementation.
pub trait Logger: Send + Sync {
    /// Log a message at the given level
    fn log(&self, level: LogLevel, message: &str);

    /// Log a debug message
    fn debug(&self, message: &str) {
        self.log(LogLevel::Debug, message);
    }

    /// Log an info message
    fn info(&self, message: &str) {
        self.log(LogLevel::Info, message);
    }

    /// Log a warning message
    fn warn(&self, message: &str) {
        self.log(LogLevel::Warn, message);
    }

    /// Log an error message
    fn error(&self, message: &str) {
        self.log(LogLevel::Error, message);
    }
}

/// A no-op logger that discards all messages
pub struct NullLogger;

impl Logger for NullLogger {
    fn log(&self, _level: LogLevel, _message: &str) {}
}

// ============================================================================
// Combined Handler Configuration
// ============================================================================

/// Configuration bundle for creating a deposits handler
///
/// Groups all the adapter trait implementations needed by the handler.
pub struct HandlerConfig<S, T, P, C, B, H, G, E>
where
    S: Storage,
    T: PeerTransport,
    P: PaymentTracker,
    C: ChannelRegistry,
    B: Broadcaster,
    H: ChainSource,
    G: SignatureProvider,
    E: EventEmitter,
{
    pub storage: Arc<S>,
    pub transport: Arc<T>,
    pub payments: Arc<P>,
    pub channels: Arc<C>,
    pub broadcaster: Arc<B>,
    pub chain: Arc<H>,
    pub signer: Arc<G>,
    pub events: Arc<E>,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // Ensure traits are object-safe
    fn _assert_object_safe() {
        fn _peer_transport(_: &dyn PeerTransport) {}
        fn _message_handler(_: &dyn MessageHandler) {}
        fn _payment_tracker(_: &dyn PaymentTracker) {}
        fn _channel_registry(_: &dyn ChannelRegistry) {}
        fn _channel_operations(_: &dyn ChannelOperations) {}
        fn _reserves_operations(_: &dyn ReservesOperations) {}
        fn _storage(_: &dyn Storage) {}
        fn _broadcaster(_: &dyn Broadcaster) {}
        fn _chain_source(_: &dyn ChainSource) {}
        fn _signature_provider(_: &dyn SignatureProvider) {}
        fn _event_emitter(_: &dyn EventEmitter) {}
    }

    #[test]
    fn test_transport_error_display() {
        let err = TransportError::PeerNotConnected(
            "02abc123".parse().unwrap_or_else(|_| {
                let secp = bitcoin::secp256k1::Secp256k1::new();
                let sk = bitcoin::secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap();
                PublicKey::from_secret_key(&secp, &sk)
            }),
        );
        assert!(err.to_string().contains("peer not connected"));
    }

    #[test]
    fn test_storage_error_display() {
        assert_eq!(StorageError::NotFound.to_string(), "key not found");
        assert_eq!(StorageError::ReadOnly.to_string(), "storage is read-only");
    }

    #[test]
    fn test_payment_status() {
        assert_ne!(PaymentStatus::Pending, PaymentStatus::Succeeded);
        assert_ne!(PaymentStatus::Failed, PaymentStatus::Unknown);
    }
}
