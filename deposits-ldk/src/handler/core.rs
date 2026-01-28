// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Bitcoin Deposits Custom Message Handler
//!
//! This module provides the Lightning Network message handling integration
//! for the Bitcoin Deposits protocol, enabling peer-to-peer communication
//! of protocol messages through LDK's CustomMessageHandler interface.

// Allow unused items in this large protocol handler - many variables are
// extracted for pattern matching or future use during protocol development
#![allow(unused_variables, unused_imports)]

use bitcoin::secp256k1::PublicKey;
use lightning::ln::peer_handler::CustomMessageHandler;
use deposits_core::{Invoice, ReservesStatus, SignedLedgerUpdate, DepositInvoiceIndex};
use deposits_core::{Ledger, LedgerRole, LedgerUpdate, LedgerManager, LedgerValidator};
use lightning::ln::wire::CustomMessageReader;
use lightning::ln::msgs::{DecodeError, LightningError, ErrorAction};
use lightning_types::features::{InitFeatures, NodeFeatures};
use lightning::util::logger::Logger;
use lightning::io;

use std::collections::HashMap;
use std::ops::Deref;
use std::sync::{Arc, Mutex, RwLock};
use tokio::sync::oneshot;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

use deposits_core::DepositsError;
use super::messages::DepositsMessage;
use super::messages::{HandshakeMsg, HandshakeResponseMsg, DepositsMessageReader};
use super::message_validation::MessageValidation;
use super::channel_locks::ChannelLocks;
use super::payment_tracking::PaymentTracking;
use super::recovery_ops::RecoveryOperations;
use super::ledger_ops::{LedgerOperations, LedgerOperationsExt};
use super::deposit_ops::DepositOperations;
use super::reserves_ops::ReservesOperations;
use super::collateral_ops::CollateralOperations;
use super::protocol_stub::DepositsProtocol;
use crate::channel_manager_ops::ChannelManagerOps;
use deposits_core::quorum::{QuorumManager, LedgerId};
use deposits_core::{TapscriptReservesBuilder, VoterSet};
use super::DepositsEvent;
use crate::DepositsEventEmitter;
use deposits_core::{log_debug, log_error, log_info, log_warn};
use lightning::util::logger::Logger as LdkLogger;
use bitcoin::{Network, ScriptBuf};

// Import LDK adapters for core handler integration
use super::ldk_adapters::{
    LdkStorageAdapter, LdkTransportAdapter, LdkLoggerAdapter,
    LdkChainAdapter, LdkEventAdapter, LdkSignerAdapter,
    LdkPaymentAdapter, LdkChannelAdapter, LdkBroadcasterAdapter,
};

/// Type alias for the core protocol handler with LDK adapters
pub type CoreHandler<L> = deposits_core::Handler<
    LdkStorageAdapter,
    LdkTransportAdapter,
    LdkPaymentAdapter,
    LdkChannelAdapter,
    LdkBroadcasterAdapter,
    LdkChainAdapter,
    LdkSignerAdapter,
    LdkEventAdapter,
    LdkLoggerAdapter<L>,
>;

// Re-export types from handler_types for backward compatibility
pub use super::handler_types::{
    CosignedInvoice,
    VoteRoundState,
    ProtocolStats,
    LedgerSummary,
    ReservesSummary,
    CollateralPartnerInfo,
    CollateralInfo,
};

// Re-export signature utilities for backward compatibility
pub use super::signature_utils::{
    create_deposit_guarantee_signature,
    verify_deposit_guarantee_signature,
    create_payment_authorization_signature,
};

// Re-export constants
pub(crate) use super::constants::{
    RESERVES_HEADROOM_SATS,
    COLLATERAL_HEADROOM_SATS,
    calculate_reserves_with_headroom,
    calculate_collateral_with_headroom,
};
pub(super) use super::constants::{
    STALE_ACK_THRESHOLD_SECS,
    STALE_BROADCAST_THRESHOLD_SECS,
    LAZY_SYNC_DELAY_SECS,
};

// Re-export build_taproot_reserves_script from deposits-core
pub(super) use deposits_core::build_taproot_reserves_script;

/// Bitcoin Deposits protocol message handler
pub struct DepositsHandler<L: Deref + Clone + Send + Sync>
where
    L::Target: LdkLogger,
{
    /// Unified ledger storage keyed by (operator_id, partner_id) tuple
    /// Each ledger has an `our_role` field indicating if we're Operator, Partner, or Auditor
    /// Uses Arc to enable sharing with core Handler
    pub(crate) ledgers: Arc<Mutex<HashMap<(PublicKey, PublicKey), Arc<RwLock<Ledger>>>>>,

    /// Legacy protocol implementations (will be removed in future phases)
    /// TODO: Remove this once full migration is complete
    pub(crate) protocols: Mutex<HashMap<PublicKey, Arc<DepositsProtocol<L>>>>,

    /// Event emitter for protocol events (allows different backends)
    pub(crate) event_queue: Arc<dyn DepositsEventEmitter>,

    /// Message reader for parsing incoming messages
    pub(crate) message_reader: DepositsMessageReader,

    /// Logger instance
    pub(crate) logger: L,

    /// Channel manager reference for querying channel counterparties
    pub(crate) channel_manager: Option<Arc<dyn ChannelManagerOps>>,

    /// Outbound message queue (messages to send to peers)
    pub(crate) outbound_messages: Mutex<HashMap<PublicKey, Vec<DepositsMessage>>>,

    /// Track individual payment locks (payment_id -> (deposit_pubkey, amount))
    pub(super) payment_locks: Mutex<HashMap<[u8; 32], (PublicKey, u64)>>,

    /// Store ledger private keys (partner_id -> secret_key) for operator-created ledgers
    /// Only the operator stores the private key for their ledgers
    pub(super) ledger_private_keys: Mutex<HashMap<PublicKey, bitcoin::secp256k1::SecretKey>>,

    /// Track pending oneshot acknowledgments (message_hash -> oneshot_sender)
    pub(super) pending_oneshot_acks: Mutex<HashMap<[u8; 32], oneshot::Sender<Result<(), String>>>>,

    /// Store partner signatures from ACKs (message_hash -> partner_signature)
    /// Used when operator broadcasts after receiving ACK (e.g., AddCollateralPartner)
    pub(super) received_partner_signatures: Mutex<HashMap<[u8; 32], [u8; 64]>>,

    /// Lightning Liquidity pattern: Track pending deposit creation requests
    pending_add_deposit_requests: Mutex<HashMap<u64, oneshot::Sender<Result<(), DepositsError>>>>,

    /// Lightning Liquidity pattern: Track pending remove deposit requests
    pending_remove_deposit_requests: Mutex<HashMap<u64, oneshot::Sender<Result<(), DepositsError>>>>,

    /// Lightning Liquidity pattern: Track pending cosign invoice requests
    pending_cosign_requests: Mutex<HashMap<u64, oneshot::Sender<Result<(), DepositsError>>>>,

    /// Track pending cosignature requests (message_hash -> oneshot_sender for signature)
    pub(super) pending_cosignature_requests: Mutex<HashMap<[u8; 32], oneshot::Sender<Result<Vec<u8>, String>>>>,

    /// Track pending collateral consent requests (message_hash -> oneshot_sender for signature)
    /// Used when operator requests consent from a collateral partner to back a ledger
    pub(crate) pending_consent_requests: Mutex<HashMap<[u8; 32], oneshot::Sender<Result<[u8; 64], String>>>>,

    /// Track undelivered consent requests for retry on reconnect (peer_id -> (message_hash, consent_message))
    /// When we send a consent request and the peer disconnects before responding, we resend on reconnect
    pub(super) undelivered_consent_requests: Mutex<HashMap<PublicKey, ([u8; 32], DepositsMessage)>>,

    /// Request ID counter for generating unique request IDs
    pub(super) next_request_id: std::sync::atomic::AtomicU64,

    /// Persistent storage for Bitcoin Deposits data
    pub(super) kv_store: Arc<crate::types::DynStore>,

    /// Timestamp of last message queue update (for triggering periodic processing)
    pub(super) last_msg_queued: std::sync::atomic::AtomicU64,

    /// Our Lightning node's public key
    pub(crate) our_node_id: PublicKey,

    /// Track sent messages for broadcasting after ack (message_hash -> (operator_id, partner_id, message, prev_hash, new_hash, chain_index))
    /// When we receive an ack from partner_id for this message, we broadcast to all other partners
    /// operator_id is always `our_node_id`, partner_id is the direct partner
    /// prev_hash is the ledger's hash BEFORE applying this update
    /// new_hash is the ledger's hash AFTER applying this update
    /// chain_index is the position of this update in the ledger's hash chain (like block height)
    pub(crate) sent_messages_for_broadcast: Mutex<HashMap<[u8; 32], (PublicKey, PublicKey, DepositsMessage, [u8; 32], [u8; 32], u64)>>,

    /// Track pending ACKs (message_hash -> PendingAck)
    /// Used by operators to track which messages are waiting for ACKs from partners
    /// Shared with core_handler for delegation
    pub(crate) pending_acks: Arc<Mutex<HashMap<[u8; 32], deposits_core::PendingAck>>>,

    /// Signed ledger update logs for third-party auditing
    /// Key: (operator_id, partner_id) -> log of signed updates
    /// Only contains ledgers where we are neither operator nor partner (third-party audit only)
    pub(crate) signed_update_logs: Mutex<HashMap<(PublicKey, PublicKey), deposits_core::SignedLedgerUpdateLog>>,

    /// For operators: track broadcast sequence numbers for our own ledgers
    /// Map of (operator_id, partner_id) -> next sequence number to use
    pub(super) broadcast_sequence_numbers: Mutex<HashMap<(PublicKey, PublicKey), u64>>,

    /// Node's secret key for signing ledger updates
    /// This is the Lightning node's identity key, used to sign audit messages
    /// NOTE: This should be wired from KeysManager in production
    pub(crate) node_secret_key: Option<bitcoin::secp256k1::SecretKey>,

    /// Track peers we've already refreshed commitments for after reconnection
    /// This prevents redundant refreshes on every message from the same peer
    pub(super) peers_refreshed_after_reconnect: Mutex<std::collections::HashSet<PublicKey>>,

    /// Track currently connected peers
    /// Used by get_and_clear_pending_msg to avoid draining messages for disconnected peers
    pub(crate) connected_peers: Mutex<std::collections::HashSet<PublicKey>>,

    /// Cosigned invoices storage (partner side only)
    /// Key: (operator_id, payment_hash) -> CosignedInvoice
    /// Stored durably until expiration + grace period, used for fraud proof validation
    /// NOT stored in the ledger to prevent spam attacks
    pub(crate) cosigned_invoices: Mutex<HashMap<(PublicKey, [u8; 32]), CosignedInvoice>>,

    /// O(1) index for payment-to-deposit lookups (from deposits-core)
    /// This is an index, not the source of truth - deposit.invoices in the ledger is the SOT.
    /// Populated when invoice is cosigned, cleaned up when payment is credited.
    /// CRITICAL: Must check this BEFORE calling claim_funds() to prevent uncredited payments
    pub(crate) payment_index: DepositInvoiceIndex,

    /// Per-channel operation locks to prevent commitment signature races
    /// Only one operation can be in-flight per channel at a time
    /// Key: (operator_id, partner_id) -> lock
    /// CRITICAL: Acquired before any operation that may trigger commitment updates
    pub(crate) channel_operation_locks: Mutex<HashMap<(PublicKey, PublicKey), Arc<std::sync::Mutex<()>>>>,

    /// Async-compatible per-channel operation locks for use in async contexts
    /// Uses tokio::sync::Mutex to allow holding across await points
    pub(crate) channel_operation_locks_async: tokio::sync::Mutex<HashMap<(PublicKey, PublicKey), Arc<tokio::sync::Mutex<()>>>>,

    /// Lazy sync tracking: ledgers with uncommitted ACKed updates
    /// Key: partner_id -> timestamp when lazy sync was requested
    /// After LAZY_SYNC_DELAY_SECS of quiet, the flush timer will commit
    /// This coalesces rapid updates into a single commitment
    pub(super) pending_lazy_syncs: Mutex<HashMap<PublicKey, u64>>,

    /// Pending vote rounds for cooperative reserve spending
    /// Key: vote_round_id -> VoteRoundState
    pub(crate) pending_vote_rounds: Mutex<HashMap<[u8; 32], VoteRoundState>>,

    /// Quorum manager for peer synchronization and conformance voting
    pub(crate) quorum_manager: QuorumManager,

    /// Recovery manager for tracking force-close recovery processes
    pub(crate) recovery_manager: Arc<Mutex<deposits_core::recovery::RecoveryManager>>,

    /// Claim manager for aggregating signatures and executing claims
    pub(crate) claim_manager: Arc<Mutex<deposits_core::recovery_claim::ClaimManager>>,

    /// Bitcoin network (mainnet, testnet, regtest, etc.)
    pub(super) network: Network,

    /// Track pending reserves commitments awaiting confirmation
    /// Key: partner_id -> (expected_script_pubkey, ledger_hash, reserves_sats, timestamp_sent)
    /// Set when propose_extra_outputs is called, cleared when outputs appear in channel
    pub(super) pending_reserves_commitments: Mutex<HashMap<PublicKey, (ScriptBuf, [u8; 32], u64, u64)>>,

    /// Core protocol handler from deposits-core
    /// This contains the pure protocol logic and will gradually take over
    /// operations from the LDK-specific code
    pub(crate) core_handler: Option<Arc<CoreHandler<L>>>,
}

impl<L: Deref + Clone + Send + Sync> DepositsHandler<L>
where
    L::Target: LdkLogger,
{
    // NOTE: set_channel_manager and set_node_secret_key are in setup_ops.rs

    // Channel lock methods - inherent for simpler trait bounds
    /// Execute a function while holding the channel operation lock
    pub fn with_channel_lock<F, R>(&self, operator_id: PublicKey, partner_id: PublicKey, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        let lock = {
            let mut locks = self.channel_operation_locks.lock().unwrap();
            locks.entry((operator_id, partner_id))
                .or_insert_with(|| Arc::new(std::sync::Mutex::new(())))
                .clone()
        };
        let _guard = lock.lock().unwrap();
        f()
    }

    /// Async version of with_channel_lock for use in async contexts
    pub async fn acquire_channel_lock_async(&self, operator_id: PublicKey, partner_id: PublicKey) -> tokio::sync::OwnedMutexGuard<()> {
        let lock = {
            let mut locks = self.channel_operation_locks_async.lock().await;
            locks.entry((operator_id, partner_id))
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                .clone()
        };
        lock.lock_owned().await
    }

    /// Get our node's public key
    pub fn our_node_id(&self) -> PublicKey {
        self.our_node_id
    }

    /// Acquire channel lock for a deposit (finds the partner and acquires the lock)
    pub async fn acquire_channel_lock_for_deposit(&self, deposit_pubkey: PublicKey) -> Option<tokio::sync::OwnedMutexGuard<()>> {
        let partner_id = self.find_partner_for_deposit(deposit_pubkey)?;
        Some(self.acquire_channel_lock_async(self.our_node_id, partner_id).await)
    }

    // NOTE: handle_channel_closed is in channel_close_handler.rs

    // NOTE: RecoveryOperations methods are in recovery_ops.rs

    /// Create a new Bitcoin Deposits message handler
    pub fn new(
        event_queue: Arc<dyn DepositsEventEmitter>,
        logger: L,
        kv_store: Arc<crate::types::DynStore>,
        our_node_id: PublicKey,
        network: Network,
    ) -> Result<Self, deposits_core::DepositsError> {
        let handler = Self {
            ledgers: Arc::new(Mutex::new(HashMap::new())),
            protocols: Mutex::new(HashMap::new()),
            event_queue,
            message_reader: DepositsMessageReader,
            logger: logger.clone(),
            channel_manager: None,
            outbound_messages: Mutex::new(HashMap::new()),
            payment_locks: Mutex::new(HashMap::new()),
            ledger_private_keys: Mutex::new(HashMap::new()),
            pending_oneshot_acks: Mutex::new(HashMap::new()),
            received_partner_signatures: Mutex::new(HashMap::new()),
            pending_add_deposit_requests: Mutex::new(HashMap::new()),
            pending_remove_deposit_requests: Mutex::new(HashMap::new()),
            pending_cosign_requests: Mutex::new(HashMap::new()),
            pending_cosignature_requests: Mutex::new(HashMap::new()),
            pending_consent_requests: Mutex::new(HashMap::new()),
            undelivered_consent_requests: Mutex::new(HashMap::new()),
            next_request_id: std::sync::atomic::AtomicU64::new(1),
            kv_store,
            last_msg_queued: std::sync::atomic::AtomicU64::new(0),
            our_node_id,
            sent_messages_for_broadcast: Mutex::new(HashMap::new()),
            pending_acks: Arc::new(Mutex::new(HashMap::new())),
            signed_update_logs: Mutex::new(HashMap::new()),
            broadcast_sequence_numbers: Mutex::new(HashMap::new()),
            node_secret_key: None, // Will be set via set_node_secret_key() if needed for signing
            peers_refreshed_after_reconnect: Mutex::new(std::collections::HashSet::new()),
            connected_peers: Mutex::new(std::collections::HashSet::new()),
            cosigned_invoices: Mutex::new(HashMap::new()),
            payment_index: DepositInvoiceIndex::new(),
            channel_operation_locks: Mutex::new(HashMap::new()),
            channel_operation_locks_async: tokio::sync::Mutex::new(HashMap::new()),
            pending_lazy_syncs: Mutex::new(HashMap::new()),
            pending_vote_rounds: Mutex::new(HashMap::new()),
            quorum_manager: QuorumManager::new(our_node_id),
            recovery_manager: Arc::new(Mutex::new(deposits_core::recovery::RecoveryManager::new(our_node_id))),
            claim_manager: Arc::new(Mutex::new(deposits_core::recovery_claim::ClaimManager::new(
                our_node_id,
                None, // Secret key set via set_node_secret_key() after construction
                deposits_core::recovery_claim::ClaimConfig::default(),
            ))),
            network,
            pending_reserves_commitments: Mutex::new(HashMap::new()),
            core_handler: None, // Initialized lazily when channel_manager is set
        };

        // Recover existing ledgers on startup - propagate errors
        handler.recover_persistent_state()?;

        Ok(handler)
    }

    // NOTE: persist_ledger_state and persist_audit_ledger_state are in persistence_ops.rs

    // NOTE: ensure_collateral_across_ledgers, ensure_collateral_for_invoice,
    // ensure_reserves_for_collateral, and increase_collateral_on_ledger are in collateral_async_ops.rs

    // NOTE: recover_persistent_state is in persistence_ops.rs

    // NOTE: Messaging infrastructure (send_message, has_pending_messages, send_message_with_oneshot_ack,
    //       request_collateral_consent, send_message_with_ack_async, wait_for_commitment_with_hash,
    //       wait_for_pending_reserves_clear) is in messaging_ops.rs

    // NOTE: handle_sending_fulfill_payment_async and handle_sending_fail_payment_async are in payment_handlers.rs

    // NOTE: process_message (~876 lines) is in message_dispatch.rs

    // NOTE: generate_protocol_event, peer_supports_protocol, list_active_partners,
    // store_ledger_private_key, get_ledger_private_key, and get_protocol_stats
    // are in event_info_ops.rs

    // NOTE: drop_all_ledgers is in testing_helpers.rs

    // NOTE: get_or_create_protocol is in protocol_management.rs

    // NOTE: handle_received_ack is in ack_handler.rs

    // NOTE: handle_third_party_audit_message is in audit_message_ops.rs

    // NOTE: broadcast_message_to_other_partners is in broadcast_ops.rs

    // NOTE: create_signed_update, sign_ledger_update, sign_as_partner, sign_attestation_content,
    // send_audit_update_to_new_collateral_partner, persist_signed_update, load_signed_update_log,
    // verify_signed_update, verify_and_store_signed_update, handle_audit_sync_request, and
    // handle_audit_sync_response are in signed_update_ops.rs

    // NOTE: trigger_commitment_transaction_update is in commitment_ops.rs

    // NOTE: send_acknowledgment is in messaging_ops.rs

    // Message validation methods are now in message_validation.rs
    // Use the MessageValidation trait (imported at top of file)

    // NOTE: flush_stale_updates, mark_for_lazy_sync, cancel_lazy_sync,
    // and start_background_flush_arc are in maintenance_ops.rs
}

// NOTE: ProtocolStats, LedgerSummary, ReservesSummary, CollateralPartnerInfo, CollateralInfo
// are in handler_types.rs (re-exported above for backward compatibility)

// NOTE: DepositsHandlerBuilder is in builder.rs

// NOTE: create_deposit_guarantee_signature, verify_deposit_guarantee_signature,
// create_payment_authorization_signature are in signature_utils.rs
// (re-exported from mod.rs for backward compatibility)
