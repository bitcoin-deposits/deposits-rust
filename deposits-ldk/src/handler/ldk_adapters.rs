//! LDK Adapters for deposits-core traits
//!
//! This module provides adapter implementations that bridge LDK types to
//! the abstract traits defined in deposits-core. This allows the core
//! protocol logic to work with LDK's concrete types.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bitcoin::secp256k1::PublicKey;
use lightning::util::logger::Logger as LdkLogger;

use deposits_core::traits::{
    Storage, StorageError, PeerTransport, TransportError,
    Logger, LogLevel, ChainSource, EventEmitter, ProtocolEvent,
    SignatureProvider, PaymentTracker, PaymentStatus, ChannelRegistry,
    Broadcaster, BroadcastError,
};

use super::messages::DepositsMessage;

// ============================================================================
// Storage Adapter
// ============================================================================

/// Adapter that wraps LDK's KVStoreSync to implement deposits-core Storage trait
pub struct LdkStorageAdapter {
    store: Arc<crate::types::DynStore>,
}

impl LdkStorageAdapter {
    pub fn new(store: Arc<crate::types::DynStore>) -> Self {
        Self { store }
    }
}

impl Storage for LdkStorageAdapter {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        // Convert key to string path components
        let key_str = String::from_utf8_lossy(key);
        let parts: Vec<&str> = key_str.split('/').collect();

        if parts.len() < 2 {
            return Ok(None);
        }

        let primary = parts[0];
        let secondary = parts[1..].join("/");
        let key_name = parts.last().unwrap_or(&"");

        match self.store.read(primary, &secondary, key_name) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(_) => Ok(None), // Treat read errors as not found
        }
    }

    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        let key_str = String::from_utf8_lossy(key);
        let parts: Vec<&str> = key_str.split('/').collect();

        if parts.len() < 2 {
            return Err(StorageError::Other("Invalid key format".to_string()));
        }

        let primary = parts[0];
        let secondary = parts[1..].join("/");
        let key_name = parts.last().unwrap_or(&"");

        self.store.write(primary, &secondary, key_name, value.to_vec())
            .map_err(|e| StorageError::IoError(format!("{:?}", e)))
    }

    fn delete(&self, key: &[u8]) -> Result<(), StorageError> {
        let key_str = String::from_utf8_lossy(key);
        let parts: Vec<&str> = key_str.split('/').collect();

        if parts.len() < 2 {
            return Ok(()); // Nothing to delete
        }

        let primary = parts[0];
        let secondary = parts[1..].join("/");
        let key_name = parts.last().unwrap_or(&"");

        self.store.remove(primary, &secondary, key_name, false)
            .map_err(|e| StorageError::IoError(format!("{:?}", e)))
    }

    fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
        let prefix_str = String::from_utf8_lossy(prefix);
        let parts: Vec<&str> = prefix_str.split('/').collect();

        if parts.is_empty() {
            return Ok(vec![]);
        }

        let primary = parts[0];
        let secondary = if parts.len() > 1 { parts[1..].join("/") } else { String::new() };

        match self.store.list(primary, &secondary) {
            Ok(keys) => {
                let mut results = Vec::new();
                for key in keys {
                    let full_key = format!("{}/{}/{}", primary, secondary, key);
                    if let Ok(Some(value)) = self.get(full_key.as_bytes()) {
                        results.push((full_key.into_bytes(), value));
                    }
                }
                Ok(results)
            }
            Err(_) => Ok(vec![]),
        }
    }
}

// ============================================================================
// Transport Adapter
// ============================================================================

/// Adapter that wraps outbound message queue for peer transport
pub struct LdkTransportAdapter {
    outbound_messages: Arc<Mutex<HashMap<PublicKey, Vec<DepositsMessage>>>>,
    connected_peers: Arc<Mutex<std::collections::HashSet<PublicKey>>>,
}

impl LdkTransportAdapter {
    pub fn new(
        outbound_messages: Arc<Mutex<HashMap<PublicKey, Vec<DepositsMessage>>>>,
        connected_peers: Arc<Mutex<std::collections::HashSet<PublicKey>>>,
    ) -> Self {
        Self { outbound_messages, connected_peers }
    }
}

impl PeerTransport for LdkTransportAdapter {
    fn send(&self, peer: PublicKey, message: &[u8]) -> Result<(), TransportError> {
        // Decode the message bytes into DepositsMessage
        let msg = DepositsMessage::decode(message)
            .map_err(|e| TransportError::EncodingError(format!("{:?}", e)))?;

        let mut messages = self.outbound_messages.lock().unwrap();
        messages.entry(peer).or_default().push(msg);
        Ok(())
    }

    fn is_connected(&self, peer: &PublicKey) -> bool {
        let peers = self.connected_peers.lock().unwrap();
        peers.contains(peer)
    }

    fn connected_peers(&self) -> Vec<PublicKey> {
        let peers = self.connected_peers.lock().unwrap();
        peers.iter().cloned().collect()
    }
}

// ============================================================================
// Logger Adapter
// ============================================================================

/// Adapter that wraps LDK's Logger to implement deposits-core Logger trait
pub struct LdkLoggerAdapter<L: std::ops::Deref + Clone + Send + Sync>
where
    L::Target: LdkLogger,
{
    logger: L,
}

impl<L: std::ops::Deref + Clone + Send + Sync> LdkLoggerAdapter<L>
where
    L::Target: LdkLogger,
{
    pub fn new(logger: L) -> Self {
        Self { logger }
    }
}

impl<L: std::ops::Deref + Clone + Send + Sync> Logger for LdkLoggerAdapter<L>
where
    L::Target: LdkLogger,
{
    fn log(&self, level: LogLevel, message: &str) {
        use lightning::util::logger::Level;

        let ldk_level = match level {
            LogLevel::Trace => Level::Trace,
            LogLevel::Debug => Level::Debug,
            LogLevel::Info => Level::Info,
            LogLevel::Warn => Level::Warn,
            LogLevel::Error => Level::Error,
        };

        // Create the record and log in one expression to avoid lifetime issues with format_args!
        // Record::new(level, peer_id, channel_id, args, module_path, file, line, payment_hash)
        self.logger.log(lightning::util::logger::Record::new(
            ldk_level,
            None, // peer_id
            None, // channel_id
            format_args!("{}", message),
            "deposits",
            "",
            0,
            None, // payment_hash
        ));
    }
}

// ============================================================================
// Chain Source Adapter
// ============================================================================

/// Adapter that wraps channel manager for chain info
pub struct LdkChainAdapter {
    channel_manager: Option<Arc<dyn crate::channel_manager_ops::ChannelManagerOps>>,
}

impl LdkChainAdapter {
    pub fn new(channel_manager: Option<Arc<dyn crate::channel_manager_ops::ChannelManagerOps>>) -> Self {
        Self { channel_manager }
    }
}

impl ChainSource for LdkChainAdapter {
    fn current_height(&self) -> u32 {
        self.channel_manager
            .as_ref()
            .map(|cm| cm.current_best_block_height())
            .unwrap_or(0)
    }

    fn get_block_hash(&self, _height: u32) -> Option<[u8; 32]> {
        // LDK doesn't provide direct block hash access
        // Would need a chain source for this
        None
    }

    fn fee_rate(&self, _confirmation_target: u32) -> Option<u64> {
        // Would need fee estimator for this
        Some(10) // Default 10 sat/vB
    }
}

// ============================================================================
// Event Emitter Adapter
// ============================================================================

/// Adapter that wraps DepositsEventEmitter for core events
pub struct LdkEventAdapter {
    event_queue: Arc<dyn crate::DepositsEventEmitter>,
}

impl LdkEventAdapter {
    pub fn new(event_queue: Arc<dyn crate::DepositsEventEmitter>) -> Self {
        Self { event_queue }
    }
}

impl EventEmitter for LdkEventAdapter {
    fn emit(&self, event: ProtocolEvent) {
        use super::events::DepositsEvent;

        // Convert core ProtocolEvent to LDK DepositsEvent
        let ldk_event = match event {
            ProtocolEvent::DepositOpened { deposit_pubkey, .. } => {
                DepositsEvent::DepositAdded {
                    pubkey: deposit_pubkey,
                }
            }
            ProtocolEvent::DepositClosed { deposit_pubkey, .. } => {
                DepositsEvent::DepositRemoved {
                    pubkey: deposit_pubkey,
                }
            }
            ProtocolEvent::PaymentCredited { deposit_pubkey, amount, .. } => {
                DepositsEvent::PaymentCredited {
                    deposit_pubkey,
                    amount,
                }
            }
            ProtocolEvent::LedgerSynced { .. } => {
                // No direct mapping for LedgerSynced in DepositsEvent
                return;
            }
            ProtocolEvent::RecoveryStarted { .. } => {
                // RecoveryStarted doesn't have a direct mapping
                // Could emit RecoveryClaimReady but we don't have the right info
                return;
            }
            ProtocolEvent::RecoveryClaimed { operator, partner, new_operator, claim_txid } => {
                DepositsEvent::RecoveryClaimCompleted {
                    old_operator: operator,
                    reserves_id: partner,
                    new_operator,
                    claim_txid,
                    confirmation_block: 0,
                }
            }
            ProtocolEvent::Error { partner, error, .. } => {
                DepositsEvent::ProtocolViolation {
                    partner_node_id: partner,
                    violation_type: "Error".to_string(),
                    evidence: error.into_bytes(),
                }
            }
            _ => return, // Other events don't have direct mappings yet
        };

        let _ = self.event_queue.emit_deposits_event(ldk_event);
    }
}

// ============================================================================
// Signature Provider Adapter
// ============================================================================

/// Adapter for signing operations using the node's secret key
pub struct LdkSignerAdapter {
    node_pubkey: PublicKey,
    secret_key: Option<bitcoin::secp256k1::SecretKey>,
}

impl LdkSignerAdapter {
    pub fn new(node_pubkey: PublicKey, secret_key: Option<bitcoin::secp256k1::SecretKey>) -> Self {
        Self { node_pubkey, secret_key }
    }
}

impl SignatureProvider for LdkSignerAdapter {
    fn node_pubkey(&self) -> PublicKey {
        self.node_pubkey
    }

    fn sign_schnorr(&self, message_hash: [u8; 32]) -> Result<[u8; 64], String> {
        use bitcoin::secp256k1::{Secp256k1, Message};

        let secret = self.secret_key.ok_or("No secret key configured")?;
        let secp = Secp256k1::new();
        let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &secret);
        let msg = Message::from_digest(message_hash);
        let sig = secp.sign_schnorr(&msg, &keypair);
        Ok(sig.serialize())
    }

    fn verify_schnorr(
        &self,
        pubkey: &PublicKey,
        message_hash: [u8; 32],
        signature: &[u8; 64],
    ) -> bool {
        use bitcoin::secp256k1::{Secp256k1, Message};
        use bitcoin::secp256k1::schnorr::Signature;

        let secp = Secp256k1::verification_only();
        let msg = Message::from_digest(message_hash);

        let sig = match Signature::from_slice(signature) {
            Ok(s) => s,
            Err(_) => return false,
        };

        let (x_only, _parity) = pubkey.x_only_public_key();

        secp.verify_schnorr(&sig, &msg, &x_only).is_ok()
    }
}

// ============================================================================
// Payment Tracker Adapter
// ============================================================================

/// Adapter that wraps payment tracking state for the PaymentTracker trait
pub struct LdkPaymentAdapter {
    /// Payment index for looking up deposits by payment hash
    payment_index: Arc<deposits_core::DepositInvoiceIndex>,
    /// Track received payments (payment_hash -> amount_msat)
    received_payments: Arc<Mutex<HashMap<[u8; 32], u64>>>,
    /// Track payment preimages (payment_hash -> preimage)
    preimages: Arc<Mutex<HashMap<[u8; 32], [u8; 32]>>>,
}

impl LdkPaymentAdapter {
    pub fn new(payment_index: Arc<deposits_core::DepositInvoiceIndex>) -> Self {
        Self {
            payment_index,
            received_payments: Arc::new(Mutex::new(HashMap::new())),
            preimages: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Record a received payment with its preimage
    pub fn record_payment(&self, payment_hash: [u8; 32], amount_msat: u64, preimage: [u8; 32]) {
        self.received_payments.lock().unwrap().insert(payment_hash, amount_msat);
        self.preimages.lock().unwrap().insert(payment_hash, preimage);
    }
}

impl PaymentTracker for LdkPaymentAdapter {
    fn payment_received(&self, payment_hash: [u8; 32], amount_msat: u64) -> bool {
        // Check if we have a record of this payment being received
        if let Some(&received_amount) = self.received_payments.lock().unwrap().get(&payment_hash) {
            return received_amount >= amount_msat;
        }
        false
    }

    fn payment_sent(&self, _payment_id: [u8; 32], _success: bool) {
        // Track outgoing payments if needed
    }

    fn get_payment_status(&self, payment_id: [u8; 32]) -> PaymentStatus {
        if self.received_payments.lock().unwrap().contains_key(&payment_id) {
            PaymentStatus::Succeeded
        } else {
            PaymentStatus::Unknown
        }
    }

    fn get_preimage(&self, payment_hash: [u8; 32]) -> Option<[u8; 32]> {
        self.preimages.lock().unwrap().get(&payment_hash).copied()
    }
}

// ============================================================================
// Channel Registry Adapter
// ============================================================================

/// Adapter that wraps ChannelManagerOps for the ChannelRegistry trait
pub struct LdkChannelAdapter {
    channel_manager: Option<Arc<dyn crate::channel_manager_ops::ChannelManagerOps>>,
}

impl LdkChannelAdapter {
    pub fn new(channel_manager: Option<Arc<dyn crate::channel_manager_ops::ChannelManagerOps>>) -> Self {
        Self { channel_manager }
    }
}

impl ChannelRegistry for LdkChannelAdapter {
    fn partner_for_channel(&self, channel_id: [u8; 32]) -> Option<PublicKey> {
        let cm = self.channel_manager.as_ref()?;
        let channels = cm.list_channels();
        for ch in channels {
            if ch.channel_id.0 == channel_id {
                return Some(ch.counterparty_node_id);
            }
        }
        None
    }

    fn channels_with_peer(&self, peer: PublicKey) -> Vec<[u8; 32]> {
        self.channel_manager
            .as_ref()
            .map(|cm| {
                cm.list_channels()
                    .into_iter()
                    .filter(|ch| ch.counterparty_node_id == peer)
                    .map(|ch| ch.channel_id.0)
                    .collect()
            })
            .unwrap_or_default()
    }

    fn channel_is_usable(&self, channel_id: [u8; 32]) -> bool {
        self.channel_manager
            .as_ref()
            .map(|cm| {
                cm.list_channels()
                    .into_iter()
                    .any(|ch| ch.channel_id.0 == channel_id && ch.is_usable)
            })
            .unwrap_or(false)
    }

    fn channel_balance_msat(&self, channel_id: [u8; 32]) -> Option<u64> {
        let cm = self.channel_manager.as_ref()?;
        cm.list_channels()
            .into_iter()
            .find(|ch| ch.channel_id.0 == channel_id)
            .map(|ch| ch.balance_msat)
    }
}

// ============================================================================
// Broadcaster Adapter
// ============================================================================

/// Adapter for broadcasting Bitcoin transactions
///
/// This adapter wraps a BroadcasterInterface from LDK for broadcasting
/// claim transactions and other on-chain operations.
pub struct LdkBroadcasterAdapter {
    broadcaster: Option<Arc<dyn lightning::chain::chaininterface::BroadcasterInterface + Send + Sync>>,
}

impl LdkBroadcasterAdapter {
    pub fn new(broadcaster: Option<Arc<dyn lightning::chain::chaininterface::BroadcasterInterface + Send + Sync>>) -> Self {
        Self { broadcaster }
    }
}

impl Broadcaster for LdkBroadcasterAdapter {
    fn broadcast_transaction(&self, tx: &bitcoin::Transaction) -> Result<(), BroadcastError> {
        match &self.broadcaster {
            Some(b) => {
                b.broadcast_transactions(&[tx]);
                Ok(())
            }
            None => Err(BroadcastError::Other("No broadcaster configured".to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signer_adapter() {
        use bitcoin::secp256k1::{Secp256k1, SecretKey};

        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let pubkey = PublicKey::from_secret_key(&secp, &secret);

        let signer = LdkSignerAdapter::new(pubkey, Some(secret));

        assert_eq!(signer.node_pubkey(), pubkey);

        let message_hash = [42u8; 32];
        let sig = signer.sign_schnorr(message_hash).unwrap();
        assert!(signer.verify_schnorr(&pubkey, message_hash, &sig));
    }
}
