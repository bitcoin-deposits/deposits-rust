// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Bitcoin Deposits Protocol Messages
//!
//! Consolidated message protocol with 12 message types (6 request/response pairs).
//! All message types use odd numbers per BOLT 1 "it's OK to be odd" rule for safe ignorability.
//!
//! ## Message Types
//!
//! | Request              | Response                  | Purpose                    |
//! |---------------------|---------------------------|----------------------------|
//! | LEDGER_UPDATE (0x8001) | LEDGER_UPDATE_RESPONSE (0x8003) | All ledger operations |
//! | HANDSHAKE (0x8005)     | HANDSHAKE_RESPONSE (0x8007)     | Protocol negotiation  |
//! | SYNC (0x8009)          | SYNC_RESPONSE (0x800B)          | State synchronization |
//! | RECOVERY (0x800D)      | RECOVERY_RESPONSE (0x800F)      | Recovery voting/claims|
//! | COORDINATION (0x8011)  | COORDINATION_RESPONSE (0x8013)  | Invoice cosigning etc |

use bitcoin::secp256k1::PublicKey;
use std::io::{self, Read, Write};

use crate::types::{DepositId, DescriptorWitness, FeeStructure, TransferFeeSchedule};
use crate::types::SignedLedgerUpdate;

// ============================================================================
// Protocol Version
// ============================================================================

/// Current protocol version (v2 = consolidated messages)
pub const PROTOCOL_VERSION: u16 = 2;

/// Minimum supported protocol version
pub const MIN_PROTOCOL_VERSION: u16 = 1;

// ============================================================================
// Message Type Constants (all odd for safe ignorability per BOLT 1)
// ============================================================================

pub mod consts {
    // Envelope Message Types (used for wire transmission)
    pub const LEDGER_UPDATE: u16 = 0x8001;
    pub const LEDGER_UPDATE_RESPONSE: u16 = 0x8003;
    pub const HANDSHAKE: u16 = 0x8005;
    pub const HANDSHAKE_RESPONSE: u16 = 0x8007;
    pub const SYNC: u16 = 0x8009;
    pub const SYNC_RESPONSE: u16 = 0x800B;
    pub const RECOVERY: u16 = 0x800D;
    pub const RECOVERY_RESPONSE: u16 = 0x800F;
    pub const COORDINATION: u16 = 0x8011;
    pub const COORDINATION_RESPONSE: u16 = 0x8013;

    // Operation Message Types (used in SignedLedgerUpdate.message_type)
    // Reserves operations
    pub const RESERVES_ADD_OUTPUT: u16 = 0x80C1;
    pub const RESERVES_REMOVE_OUTPUT: u16 = 0x80C3;
    pub const QUORUM_BEGIN: u16 = 0x80B5;
    pub const RESERVES_UPDATE_OUTPUT: u16 = 0x80C9;

    // Reserves commitment protocol
    pub const UPDATE_RESERVES: u16 = 0x80E1;
    pub const ACCEPT_RESERVES: u16 = 0x80E3;

    // Collateral operations
    pub const COLLATERAL_INCREASE: u16 = 0x80CB;
    pub const COLLATERAL_DECREASE: u16 = 0x80CD;
    pub const COLLATERAL_STATUS: u16 = 0x80CF;
    pub const COLLATERAL_ATTESTATION: u16 = 0x808D;
    pub const QUORUM_ADD_MEMBER: u16 = 0x8097;
    pub const QUORUM_REMOVE_MEMBER: u16 = 0x8099;
    pub const COLLATERAL_CONSENT_REQUEST: u16 = 0x809B;
    pub const COLLATERAL_CONSENT_RESPONSE: u16 = 0x809D;
    pub const COLLATERAL_LOCK: u16 = 0x809F;
    pub const QUORUM_JOIN: u16 = 0x80AB;

    // Deposit operations
    pub const DEPOSIT_OPEN: u16 = 0x80D1;
    pub const DEPOSIT_CLOSE: u16 = 0x80D3;
    pub const FEE_CHANGE: u16 = 0x80D5;
    pub const DEPOSIT_KEY_ROTATE: u16 = 0x80D7;

    // Onchain operations (Bitcoin layer credits/withdrawals)
    pub const ONCHAIN_CREDIT: u16 = 0x80E1;
    pub const ONCHAIN_LOCK: u16 = 0x80E3;
    pub const ONCHAIN_FAIL: u16 = 0x80E5;
    pub const ONCHAIN_FULFILL: u16 = 0x80E7;

    // Transfer operations (conditional transfers between deposits)
    pub const TRANSFER_LOCK: u16 = 0x80F1;
    pub const TRANSFER_COMPLETE: u16 = 0x80F3;
    pub const TRANSFER_FAIL: u16 = 0x80F5;

    // Ledger lifecycle
    pub const LEDGER_CLOSE: u16 = 0x801D;


    // Maintenance
    pub const MAINTENANCE_FEE_COLLECT: u16 = 0x8021;

    // Receiving (incoming payments)
    pub const RECEIVING_COSIGN_INVOICE: u16 = 0x8031;
    pub const RECEIVING_CREDIT_PAYMENT: u16 = 0x8033;
    pub const UNCREDITED_PAYMENT: u16 = 0x8035;

    // Sending (outgoing payments)
    pub const SENDING_LOCK_PAYMENT: u16 = 0x8041;
    pub const SENDING_FAIL_PAYMENT: u16 = 0x8043;
    pub const SENDING_FULFILL_PAYMENT: u16 = 0x8045;

    // Signed updates and sync
    pub const SIGNED_UPDATE: u16 = 0x8057;
    pub const SYNC_REQUEST: u16 = 0x8059;

    // Ledger export and validation
    pub const LEDGER_EXPORT_REQUEST: u16 = 0x805B;
    pub const LEDGER_EXPORT_RESPONSE: u16 = 0x805D;

    // Ledger establishment (aliases for Handshake)
    pub const LEDGER_OPEN_REQUEST: u16 = 0x8061;
    pub const LEDGER_OPEN_RESPONSE: u16 = 0x8063;

    // Acknowledgment
    pub const ACK: u16 = 0x8071;

    // Quorum operations
    pub const QUORUM_JOIN_REQUEST: u16 = 0x8081;
    pub const QUORUM_JOIN_RESPONSE: u16 = 0x8083;
    pub const QUORUM_STATE_SYNC: u16 = 0x8085;
    pub const QUORUM_VOTE_REQUEST: u16 = 0x8087;
    pub const QUORUM_VOTE: u16 = 0x8089;
    pub const QUORUM_MEMBERSHIP_CHANGE: u16 = 0x808B;

    // Recovery operations
    pub const RECOVERY_VOTE: u16 = 0x808F;
    pub const RECOVERY_CLAIM_REQUEST: u16 = 0x8091;
    pub const RECOVERY_CLAIM_SIGNATURE: u16 = 0x8093;
    pub const RECOVERY_CLAIM_COMPLETE: u16 = 0x8095;

}

pub use consts::*;

// ============================================================================
// Message Type Collections
// ============================================================================

/// Envelope message types - the outer wire message types
pub const ALL_ENVELOPE_MESSAGE_TYPES: &[u16] = &[
    LEDGER_UPDATE, LEDGER_UPDATE_RESPONSE,
    HANDSHAKE, HANDSHAKE_RESPONSE,
    SYNC, SYNC_RESPONSE,
    RECOVERY, RECOVERY_RESPONSE,
    COORDINATION, COORDINATION_RESPONSE,
];

/// Operation message types - stored in SignedLedgerUpdate.message_type field
pub const ALL_OPERATION_MESSAGE_TYPES: &[u16] = &[
    RESERVES_ADD_OUTPUT, RESERVES_REMOVE_OUTPUT,
    RESERVES_UPDATE_OUTPUT, UPDATE_RESERVES, ACCEPT_RESERVES,
    COLLATERAL_INCREASE, COLLATERAL_DECREASE, COLLATERAL_STATUS,
    COLLATERAL_ATTESTATION, QUORUM_ADD_MEMBER, QUORUM_REMOVE_MEMBER,
    COLLATERAL_CONSENT_REQUEST, COLLATERAL_CONSENT_RESPONSE,
    DEPOSIT_OPEN, DEPOSIT_CLOSE, FEE_CHANGE,
    ONCHAIN_CREDIT, ONCHAIN_LOCK, ONCHAIN_FAIL, ONCHAIN_FULFILL,
    LEDGER_CLOSE,
    MAINTENANCE_FEE_COLLECT,
    RECEIVING_COSIGN_INVOICE, RECEIVING_CREDIT_PAYMENT, UNCREDITED_PAYMENT,
    SENDING_LOCK_PAYMENT, SENDING_FAIL_PAYMENT, SENDING_FULFILL_PAYMENT,
    SIGNED_UPDATE, SYNC_REQUEST,
    LEDGER_EXPORT_REQUEST, LEDGER_EXPORT_RESPONSE,
    LEDGER_OPEN_REQUEST, LEDGER_OPEN_RESPONSE,
    ACK,
    QUORUM_JOIN_REQUEST, QUORUM_JOIN_RESPONSE, QUORUM_STATE_SYNC,
    QUORUM_VOTE_REQUEST, QUORUM_VOTE, QUORUM_MEMBERSHIP_CHANGE,
    RECOVERY_VOTE, RECOVERY_CLAIM_REQUEST, RECOVERY_CLAIM_SIGNATURE, RECOVERY_CLAIM_COMPLETE,
];

/// Messages that require acknowledgment
pub const MESSAGES_REQUIRING_ACK: &[u16] = &[
    RESERVES_ADD_OUTPUT, RESERVES_REMOVE_OUTPUT,
    RESERVES_UPDATE_OUTPUT,
    DEPOSIT_OPEN, DEPOSIT_CLOSE, FEE_CHANGE,
    ONCHAIN_CREDIT, ONCHAIN_LOCK, ONCHAIN_FAIL, ONCHAIN_FULFILL,
    RECEIVING_CREDIT_PAYMENT, RECEIVING_COSIGN_INVOICE,
    SENDING_LOCK_PAYMENT, SENDING_FAIL_PAYMENT, SENDING_FULFILL_PAYMENT,
    COLLATERAL_INCREASE, COLLATERAL_DECREASE,
    QUORUM_ADD_MEMBER, QUORUM_REMOVE_MEMBER,
    COLLATERAL_CONSENT_REQUEST, COLLATERAL_CONSENT_RESPONSE,
    MAINTENANCE_FEE_COLLECT,
    LEDGER_CLOSE,
    LEDGER_OPEN_REQUEST,
    LEDGER_UPDATE,
    HANDSHAKE,
];

// ============================================================================
// Message Type Utilities
// ============================================================================

/// Check if a message type is a Bitcoin Deposits protocol message
pub fn is_deposits_message_type(message_type: u16) -> bool {
    ALL_ENVELOPE_MESSAGE_TYPES.contains(&message_type) || ALL_OPERATION_MESSAGE_TYPES.contains(&message_type)
}

/// Check if a message type requires acknowledgment
pub fn requires_acknowledgment(message_type: u16) -> bool {
    MESSAGES_REQUIRING_ACK.contains(&message_type)
}

/// Get the message category for a message type
pub fn get_message_category(message_type: u16) -> Option<&'static str> {
    match message_type {
        RESERVES_ADD_OUTPUT | RESERVES_REMOVE_OUTPUT |
        RESERVES_UPDATE_OUTPUT => Some("reserves"),

        COLLATERAL_INCREASE | COLLATERAL_DECREASE | COLLATERAL_STATUS |
        COLLATERAL_ATTESTATION | QUORUM_ADD_MEMBER | QUORUM_REMOVE_MEMBER |
        COLLATERAL_CONSENT_REQUEST | COLLATERAL_CONSENT_RESPONSE => Some("collateral"),

        DEPOSIT_OPEN | DEPOSIT_CLOSE | FEE_CHANGE => Some("deposit"),

        ONCHAIN_CREDIT | ONCHAIN_LOCK | ONCHAIN_FAIL | ONCHAIN_FULFILL => Some("onchain"),

        LEDGER_CLOSE => Some("lifecycle"),

        MAINTENANCE_FEE_COLLECT => Some("maintenance"),

        RECEIVING_COSIGN_INVOICE | RECEIVING_CREDIT_PAYMENT | UNCREDITED_PAYMENT => Some("receiving"),

        SENDING_LOCK_PAYMENT | SENDING_FAIL_PAYMENT | SENDING_FULFILL_PAYMENT => Some("sending"),

        SIGNED_UPDATE | SYNC_REQUEST | LEDGER_OPEN_REQUEST | LEDGER_OPEN_RESPONSE | ACK |
        LEDGER_EXPORT_REQUEST | LEDGER_EXPORT_RESPONSE => Some("control"),

        QUORUM_JOIN_REQUEST | QUORUM_JOIN_RESPONSE | QUORUM_STATE_SYNC |
        QUORUM_VOTE_REQUEST | QUORUM_VOTE | QUORUM_MEMBERSHIP_CHANGE => Some("quorum"),

        RECOVERY_VOTE | RECOVERY_CLAIM_REQUEST | RECOVERY_CLAIM_SIGNATURE |
        RECOVERY_CLAIM_COMPLETE => Some("recovery"),

        // V2 types
        LEDGER_UPDATE | LEDGER_UPDATE_RESPONSE => Some("ledger"),
        HANDSHAKE | HANDSHAKE_RESPONSE => Some("handshake"),
        SYNC | SYNC_RESPONSE => Some("sync"),
        RECOVERY | RECOVERY_RESPONSE => Some("recovery"),
        COORDINATION | COORDINATION_RESPONSE => Some("coordination"),

        _ => None,
    }
}

/// Convert a message type ID to its constant name (V2 messages only)
pub fn type_id_to_const_name(type_id: u16) -> &'static str {
    match type_id {
        LEDGER_UPDATE => "LEDGER_UPDATE",
        LEDGER_UPDATE_RESPONSE => "LEDGER_UPDATE_RESPONSE",
        HANDSHAKE => "HANDSHAKE",
        HANDSHAKE_RESPONSE => "HANDSHAKE_RESPONSE",
        SYNC => "SYNC",
        SYNC_RESPONSE => "SYNC_RESPONSE",
        RECOVERY => "RECOVERY",
        RECOVERY_RESPONSE => "RECOVERY_RESPONSE",
        COORDINATION => "COORDINATION",
        COORDINATION_RESPONSE => "COORDINATION_RESPONSE",
        _ => "UNKNOWN",
    }
}

/// Convert a message type ID to its variant name (V2 messages only)
pub fn type_id_to_variant_name(type_id: u16) -> Option<&'static str> {
    match type_id {
        LEDGER_UPDATE => Some("LedgerUpdate"),
        LEDGER_UPDATE_RESPONSE => Some("LedgerUpdateResponse"),
        HANDSHAKE => Some("Handshake"),
        HANDSHAKE_RESPONSE => Some("HandshakeResponse"),
        SYNC => Some("Sync"),
        SYNC_RESPONSE => Some("SyncResponse"),
        RECOVERY => Some("Recovery"),
        RECOVERY_RESPONSE => Some("RecoveryResponse"),
        COORDINATION => Some("Coordination"),
        COORDINATION_RESPONSE => Some("CoordinationResponse"),
        _ => None,
    }
}

// ============================================================================
// Hash Strategy
// ============================================================================

/// HashStrategy determines how to calculate the expected consensus hash
/// for message types that require commitment transaction synchronization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HashStrategy {
    /// Use the current committed hash (after the operation is applied).
    /// Used for amount-changing operations (ReservesAdd, ReservesToReserves, etc.)
    /// where the reserves amount in the commitment must match ledger state.
    CurrentCommitted,

    /// Predict the hash that will result from the operation being applied.
    /// Used for operations where the commitment must contain the post-op state.
    /// Example: ReceivingCreditPayment - commit predicted hash, then apply credit.
    PredictedAfterOp,

    /// No synchronization needed. The hash will catch up on next sync operation.
    /// Used for operations that don't immediately affect reserves (e.g., LedgerAddDeposit).
    None,
}

impl HashStrategy {
    /// Determine the hash strategy for a given message type.
    /// Returns (needs_reserves_update, strategy)
    pub fn for_message_type(msg_type: u16) -> (bool, HashStrategy) {
        match msg_type {
            // Amount-changing operations - sync after applying
            RESERVES_ADD_OUTPUT | COLLATERAL_INCREASE => {
                (true, HashStrategy::CurrentCommitted)
            },
            // Credit must be in committed hash - predict before applying
            RECEIVING_CREDIT_PAYMENT => {
                (true, HashStrategy::PredictedAfterOp)
            },
            // Everything else - no sync needed (catches up lazily)
            _ => (false, HashStrategy::None),
        }
    }

    /// Check if this strategy requires synchronization
    pub fn requires_sync(&self) -> bool {
        !matches!(self, HashStrategy::None)
    }
}

// ============================================================================
// Main Message Enum
// ============================================================================

/// V2 Protocol Messages - 14 types total
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DepositsMessage {
    LedgerUpdate(LedgerUpdateMsg),
    LedgerUpdateResponse(LedgerUpdateResponseMsg),
    Handshake(HandshakeMsg),
    HandshakeResponse(HandshakeResponseMsg),
    Sync(SyncMsg),
    SyncResponse(SyncResponseMsg),
    Recovery(RecoveryMsg),
    RecoveryResponse(RecoveryResponseMsg),
    Coordination(CoordinationMsg),
    CoordinationResponse(CoordinationResponseMsg),
    /// Reserves add output - peer message to add reserves to commitment (not a ledger operation)
    ReservesAddOutput(crate::wire_messages::ReservesAddOutputMsg),
    /// Reserves remove output - peer message to remove reserves from commitment (not a ledger operation)
    ReservesRemoveOutput(crate::wire_messages::ReservesRemoveOutputMsg),
}

impl DepositsMessage {
    pub fn message_type(&self) -> u16 {
        match self {
            Self::LedgerUpdate(_) => LEDGER_UPDATE,
            Self::LedgerUpdateResponse(_) => LEDGER_UPDATE_RESPONSE,
            Self::Handshake(_) => HANDSHAKE,
            Self::HandshakeResponse(_) => HANDSHAKE_RESPONSE,
            Self::Sync(_) => SYNC,
            Self::SyncResponse(_) => SYNC_RESPONSE,
            Self::Recovery(_) => RECOVERY,
            Self::RecoveryResponse(_) => RECOVERY_RESPONSE,
            Self::Coordination(_) => COORDINATION,
            Self::CoordinationResponse(_) => COORDINATION_RESPONSE,
            Self::ReservesAddOutput(_) => RESERVES_ADD_OUTPUT,
            Self::ReservesRemoveOutput(_) => RESERVES_REMOVE_OUTPUT,
        }
    }

    pub fn variant_name(&self) -> &'static str {
        match self {
            Self::LedgerUpdate(_) => "LedgerUpdate",
            Self::LedgerUpdateResponse(_) => "LedgerUpdateResponse",
            Self::Handshake(_) => "Handshake",
            Self::HandshakeResponse(_) => "HandshakeResponse",
            Self::Sync(_) => "Sync",
            Self::SyncResponse(_) => "SyncResponse",
            Self::Recovery(_) => "Recovery",
            Self::RecoveryResponse(_) => "RecoveryResponse",
            Self::Coordination(_) => "Coordination",
            Self::CoordinationResponse(_) => "CoordinationResponse",
            Self::ReservesAddOutput(_) => "ReservesAddOutput",
            Self::ReservesRemoveOutput(_) => "ReservesRemoveOutput",
        }
    }

    /// Get the reserves_id if present in the message
    pub fn reserves_id(&self) -> Option<String> {
        match self {
            Self::LedgerUpdate(m) => Some(m.reserves_id.clone()),
            Self::LedgerUpdateResponse(m) => Some(m.reserves_id.clone()),
            Self::Handshake(m) => Some(m.reserves_id.clone()),
            Self::HandshakeResponse(m) => Some(m.reserves_id.clone()),
            Self::Sync(_) => None, // Uses ledger_id now
            Self::SyncResponse(_) => None, // Uses ledger_id now
            Self::Recovery(m) => m.reserves_id(),
            Self::RecoveryResponse(m) => m.reserves_id(),
            Self::Coordination(m) => m.reserves_id(),
            Self::CoordinationResponse(m) => m.reserves_id(),
            Self::ReservesAddOutput(m) => Some(m.reserves_id.clone()),
            Self::ReservesRemoveOutput(m) => Some(m.reserves_id.clone()),
        }
    }

    /// Extract the LedgerOperation from this message, if it contains one.
    /// Returns Some(operation) for LedgerUpdate messages, None otherwise.
    pub fn to_operation(&self) -> Option<LedgerOperation> {
        match self {
            Self::LedgerUpdate(m) => Some(m.operation.clone()),
            _ => None,
        }
    }

    /// Encode message to bytes (type prefix + payload)
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.message_type().to_be_bytes());
        self.write_payload(&mut bytes).expect("encoding to vec should not fail");
        bytes
    }

    /// Decode message from bytes
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        if bytes.len() < 2 {
            return Err(CodecError::TooShort);
        }
        let message_type = u16::from_be_bytes([bytes[0], bytes[1]]);
        let mut reader = &bytes[2..];
        Self::read_payload(message_type, &mut reader)
    }
}

// ============================================================================
// Ledger Update Messages (0x8001 / 0x8003)
// ============================================================================

/// All ledger-modifying operations in a single message type
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerUpdateMsg {
    /// Operator's public key
    pub operator_id: PublicKey,
    /// Reserves identifier (UTXO address for BDK, partner pubkey string for LDK)
    pub reserves_id: String,
    /// The operation to perform
    pub operation: LedgerOperation,
    /// Sequence number in the ledger chain
    pub sequence_number: u64,
    /// Hash of the previous ledger state
    pub previous_hash: [u8; 32],
    /// Hash after applying this operation
    pub current_hash: [u8; 32],
    /// Operator's signature over the update
    pub operator_signature: [u8; 64],
}

/// Response to a ledger update (replaces ACK + porcupine dance)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerUpdateResponseMsg {
    /// Operator's public key
    pub operator_id: PublicKey,
    /// Reserves identifier (UTXO address for BDK, partner pubkey string for LDK)
    pub reserves_id: String,
    /// Hash of the request being responded to
    pub request_hash: [u8; 32],
    /// Whether the update was accepted
    pub accepted: bool,
    /// Error message if rejected
    pub error: Option<String>,
    /// Co-signer's signature if accepted
    pub cosign_signature: Option<[u8; 64]>,
    /// Confirmed sequence number
    pub confirmed_sequence: u64,
    /// Confirmed ledger hash
    pub confirmed_hash: [u8; 32],
}

/// All possible ledger operations (29 variants)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LedgerOperation {
    // ========== Ledger Establishment (1) ==========
    /// Open/establish a new ledger (first operation, sequence 0)
    LedgerOpen {
        /// Operator's node ID
        operator_id: PublicKey,
        /// Reserves identifier (UTXO address for BDK, partner pubkey string for LDK)
        reserves_id: String,
        /// Block height when this ledger was opened (used in ledger_id computation)
        genesis_block: u32,
        /// Initial reserves amount in millisatoshis (from on-chain UTXO balance)
        reserves_amount: u64,
    },

    // ========== Reserves Operations (1) ==========
    // Note: ReservesAdd/Remove/UpdateSpendTo are peer messages, not ledger operations.
    // The initial reserves state is set via LedgerOpen.
    // Reserves amount is updated at QuorumBegin (formerly ReservesRotate).
    /// Establish/refresh the quorum and rotate reserves UTXO into a new multisig
    ///
    /// Records the rotation of reserves from P2WSH to P2TR with tiered spending:
    /// - Immediate: quorum_threshold-of-quorum_size multisig
    /// - After quorum_expiry: operator can spend alone
    ///
    /// The quorum member pubkeys are derived from QuorumAddMember operations on this ledger.
    QuorumBegin {
        /// New reserves identifier (the new Taproot address)
        reserves_id: String,
        /// Transaction that spent the old reserves UTXO
        spending_txid: [u8; 32],
        /// New reserves UTXO txid
        new_outpoint_txid: [u8; 32],
        /// New reserves UTXO vout
        new_outpoint_vout: u32,
        /// Amount in millisatoshis (should match previous reserves)
        amount: u64,
        /// Block height when the quorum expires (shortest member's collateral_lock_until).
        /// A new QuorumBegin MUST be appended before this block (see DEP-11).
        /// The reserves tapscript uses this for tiered spending:
        ///   - Full quorum (k-of-n): no timelock
        ///   - Degraded quorum (k-1 of n): available before quorum_expiry (rotation window)
        ///   - Operator solo: available well after quorum_expiry (last resort)
        quorum_expiry: u32,
        /// Ledger hash committed in the Taproot script
        ledger_hash: [u8; 32],
        /// Quorum member pubkeys included in this rotation
        quorum_members: Vec<bitcoin::secp256k1::PublicKey>,
        /// Total attested collateral across all quorum members (msats).
        /// Wallets use this to verify obligation limits without scanning attestations.
        total_collateral: u64,
    },

    // ========== Deposit Operations (6) ==========
    /// Open a new deposit
    DepositOpen {
        /// Unique identifier (hash of descriptor)
        deposit_id: DepositId,
        /// Miniscript descriptor controlling this deposit
        descriptor: String,
        fees: Option<FeeStructure>,
        /// Per-transfer fee schedule (fixed + proportional)
        transfer_fees: Option<TransferFeeSchedule>,
        payment_hash: Option<[u8; 32]>,
        invoice: Option<String>,
        cosigner_guarantee_signature: Option<[u8; 64]>,
        /// If true, this deposit is collateral — subject to collateral rules,
        /// not regular deposit obligations. Collateral deposits cannot be
        /// transferred or withdrawn normally.
        is_collateral: bool,
        /// If true, incoming funds (transfers, offers, invoices) require a
        /// signature from the deposit key. Prevents unsolicited crediting.
        receive_requires_sig: bool,
        /// Blocks after deposit open before fees can be changed (relative).
        fee_change_after_blocks: Option<u32>,
        /// Blocks of notice required before a fee change takes effect.
        fee_change_notice_blocks: Option<u32>,
        /// Maximum fee change per adjustment in basis points of current fee (default 1000 = 10%).
        fee_change_limit_bps: Option<u16>,
    },
    /// Close a deposit
    DepositClose { deposit_id: DepositId },
    /// Announce a fee change. Takes effect after the notice period.
    /// The new fees must be within fee_change_limit_bps of the current fees.
    FeeChange {
        deposit_id: DepositId,
        new_fees: FeeStructure,
        /// Block height at which this change takes effect.
        /// Must be >= current_block + fee_change_notice_blocks.
        effective_block: u32,
    },
    /// Rotate the deposit's spending key/descriptor
    /// The deposit_id stays the same (derived from original descriptor)
    /// but the current descriptor changes to new_descriptor.
    /// Requires witness proving authorization from the current descriptor.
    DepositKeyRotate {
        deposit_id: DepositId,
        new_descriptor: String,
        /// Witness satisfying the CURRENT descriptor (proves ownership)
        witness: DescriptorWitness,
    },
    // ========== Invoice Operations (4) ==========
    /// Credit a received invoice payment to a deposit
    InvoiceCredit {
        payment_hash: [u8; 32],
        deposit_id: DepositId,
        amount: u64,
        invoice_id: String,
        sequence_number: u64,
    },
    /// Lock funds for an outgoing invoice payment
    InvoiceLock {
        deposit_id: DepositId,
        amount: u64,
        payment_id: [u8; 32],
        sequence_number: u64,
        /// Witness satisfying the deposit descriptor
        witness: DescriptorWitness,
    },
    /// Fail a pending invoice payment
    InvoiceFail {
        deposit_id: DepositId,
        amount: u64,
        payment_id: [u8; 32],
        sequence_number: u64,
    },
    /// Fulfill a pending invoice payment
    InvoiceFulfill {
        deposit_id: DepositId,
        amount: u64,
        payment_id: [u8; 32],
        sequence_number: u64,
        /// Witness satisfying the deposit descriptor
        witness: DescriptorWitness,
        preimage: [u8; 32],
    },

    // ========== Onchain Operations ==========
    /// Credit received on-chain funds to a deposit (incoming, fast)
    OnchainCredit {
        txid: [u8; 32],
        vout: u32,
        deposit_id: DepositId,
        amount: u64,
        funding_address: String,
    },
    /// Lock funds for an on-chain withdrawal (outgoing, debits balance)
    OnchainLock {
        deposit_id: DepositId,
        amount: u64,
        fee_sats: u64,
        destination_address: String,
        withdrawal_id: [u8; 32],
        witness: DescriptorWitness,
    },
    /// Fail a pending on-chain withdrawal (returns funds to deposit)
    OnchainFail {
        deposit_id: DepositId,
        withdrawal_id: [u8; 32],
    },
    /// Fulfill an on-chain withdrawal (confirmed on-chain)
    OnchainFulfill {
        deposit_id: DepositId,
        withdrawal_id: [u8; 32],
        amount: u64,
        txid: [u8; 32],
        destination_address: String,
    },

    // ========== Transfer Operations (3) ==========
    /// Lock funds for a conditional transfer between deposits
    /// The transfer completes if completion_script is satisfied, or times out after timeout_height
    TransferLock {
        nonce: [u8; 32],
        source_deposit_id: DepositId,
        destination_deposit_id: DepositId,
        amount: u64,
        fee: u64,
        completion_script: String,
        timeout_height: u32,
        transfer_id: [u8; 32],
        witness: DescriptorWitness,
    },
    /// Complete a transfer by satisfying the completion_script
    TransferComplete {
        transfer_id: [u8; 32],
        script_witness: DescriptorWitness,
    },
    /// Fail a transfer and return funds to source.
    /// Reason 1 = timeout (deadline reached without completion).
    /// Reason 0 is reserved/invalid.
    TransferFail {
        transfer_id: [u8; 32],
        block_hash: [u8; 32],
        /// Failure reason: 1 = timeout. 0 is reserved.
        reason: u8,
    },

    // ========== Collateral Operations ==========
    /// Record a collateral attestation from another quorum member
    CollateralAttestation {
        collateral_operator: PublicKey,
        quorum_member: PublicKey,
        /// The ledger ID where collateral is locked (must match member_ledger_id from QuorumAddMember)
        collateral_ledger_id: String,
        amount: u64,
        block_height: u32,
        /// Block height when the collateral lock expires
        lock_until_block: u32,
        signature: [u8; 64],
        ledger_hash: [u8; 32],
    },

    // ========== Quorum Membership (2) ==========
    /// Add a quorum member to the VoterSet.
    /// Fee limits are the member's terms — minimum fees they require.
    /// DepositOpen fees must meet or exceed the strictest quorum member minimums.
    /// This protects members from inheriting low-fee obligations after custody transfer.
    QuorumAddMember {
        quorum_member: PublicKey,
        quorum_member_signature: [u8; 64],
        /// The ledger ID where this member will lock collateral
        member_ledger_id: String,
        /// Minimum annualized fee rate (basis points) the member requires
        min_fee_bps: Option<u16>,
        /// Minimum annualized fixed fee (msats/year) the member requires
        min_fee_fixed: Option<u64>,
        /// Maximum fee collection period (blocks) the member allows
        max_fee_period: Option<u32>,
        /// Minimum collateral (msats) the member commits to maintain on their ledger.
        /// Obligations are limited to 2x the smallest member's commitment.
        collateral_lock_amount: Option<u64>,
        /// Block height until which the member's collateral must remain locked.
        /// Membership duration is limited to the shortest lock time.
        collateral_lock_until: Option<u32>,
        /// Per-quorum timing: blocks before member must respond to fraud evidence
        dispute_response_blocks: Option<u32>,
        /// Per-quorum timing: blocks after DisputeEnter to arm for lottery
        dispute_arm_blocks: Option<u32>,
        /// Per-quorum timing: blocks before unprocessed request = censorship
        service_response_blocks: Option<u32>,
        /// Per-quorum timing: max timeout_height distance for TransferLock
        max_transfer_timeout_blocks: Option<u32>,
        /// Maximum descriptor size (bytes) member will accept on deposits
        max_descriptor_bytes: Option<u32>,
    },
    /// Remove a quorum member from the VoterSet
    QuorumRemoveMember {
        quorum_member: PublicKey,
        operator_signature: [u8; 64],
    },
    /// Lock deposit balance as collateral backing for the operator.
    /// The locked amount cannot be withdrawn until lock expires.
    /// Uses ratchet semantics: can only increase amount AND extend duration.
    CollateralLock {
        /// Which deposit is locking collateral
        deposit_id: DepositId,
        /// Amount locked as collateral (millisatoshis)
        amount: u64,
        /// Block height when the lock expires
        lock_until_block: u32,
        /// Operator being backed
        operator_id: PublicKey,
        /// Witness satisfying the deposit descriptor to authorize the lock
        witness: DescriptorWitness,
    },
    /// Record that we have joined another operator's quorum as a monitoring member.
    /// This is appended to the consenting party's own ledger when they grant consent.
    /// Creates a two-sided auditable trail alongside QuorumAddMember on the operator's ledger.
    /// Uses ratchet semantics: can only extend membership duration.
    QuorumJoin {
        /// The operator whose quorum we're joining
        operator_id: PublicKey,
        /// The ledger_id (64-char hex hash) of the ledger we're monitoring
        ledger_id: String,
        /// Block height when our membership commitment expires
        membership_expires: u32,
        /// Our consent signature (matches quorum_member_signature in QuorumAddMember)
        our_signature: [u8; 64],
    },

    // ========== Maintenance (1) ==========
    /// Collect maintenance fees from a deposit
    FeeCollect {
        deposit_id: DepositId,
        amount: u64,
        block_height: u32,
    },

    // ========== Custody Dispute and Recovery (4) ==========
    /// Open a custody dispute. Can ONLY be signed by a quorum member (verified
    /// against the quorum at the fork point).
    ///
    /// Effects:
    /// - Disbands the quorum (all memberships voided)
    /// - Voids all collateral attestations
    /// - The signer becomes the "parent pubkey" for this branch
    /// - Transitions ledger to DISPUTED state
    ///
    /// Signature rule: This is the ONE EXCEPTION to the rule that updates must be
    /// signed by the same pubkey as the previous update. DisputeEnter can be
    /// signed by any pubkey that was a quorum member at the fork point.
    DisputeEnter {
        /// Sequence number of the last valid update before the dispute.
        last_valid_sequence: u64,
        /// Human-readable description of why the dispute was opened.
        reason: String,
    },

    /// Signal readiness for custody competition. This is a PRE-COMMITMENT that
    /// locks in the candidate for entropy-based selection.
    ///
    /// Effects:
    /// - Locks in the current quorum - no more changes allowed
    /// - Registers this candidate for entropy-based selection
    /// - Only candidates with DisputeArmed before the entropy block are eligible
    ///
    /// Validation:
    /// - Must be in DISPUTED state
    /// - Must have at least N quorum members added
    /// - Must have collateral attestations from quorum members
    DisputeArmed {
        /// Block height when this candidate is ready (used for eligibility cutoff).
        armed_block: u32,
        /// HASH160 of secret preimage (32 bytes) for lottery entropy.
        commitment_hash: [u8; 20],
        /// Bitcoin address where winner wants reserves sent.
        target_reserves: String,
    },

    /// Acquire custody after winning entropy selection.
    ///
    /// Effects:
    /// - Spends the reserves to the new custodian's address
    /// - Transitions ledger back to NORMAL state
    /// - This candidate is now the operator
    ///
    /// Validation:
    /// - Must be in READY state
    /// - Must be the entropy-selected winner among all READY candidates
    DisputeAcquire {
        /// The new custodian (this candidate's pubkey).
        /// Validators verify this matches the entropy-selected winner.
        new_custodian: PublicKey,
        /// Block height used for entropy (e.g., initiation_block + 6).
        entropy_block_height: u32,
        /// Hash of the entropy block.
        entropy_block_hash: [u8; 32],
        /// Transaction ID of the on-chain confiscation spend (proves control).
        spend_txid: [u8; 32],
        /// New reserves address (where the confiscated funds now reside).
        new_reserves_address: String,
    },

    /// Yield custody claim after not being selected. Tombstones this branch.
    ///
    /// Effects:
    /// - Terminates this branch permanently
    /// - No further updates allowed on this branch
    ///
    /// Validation:
    /// - Must be in READY state
    /// - Must NOT be the entropy-selected winner
    ///
    /// Note: This is NOT "invalid" - it's simply a terminated branch.
    DisputeYield,

    // ========== Delivery (1) ==========
    /// Embed a wallet's request hash for certified delivery (see DEP-12).
    /// Appended by a quorum member to their own ledger when a wallet escalates
    /// an unprocessed request. Starts the service_response_blocks clock.
    DeliveryEmbed {
        /// SHA256 of the wallet's signed request payload
        request_hash: [u8; 32],
        /// Ledger ID where the request should be processed
        target_ledger_id: [u8; 32],
        /// Operator pubkey of the target ledger
        target_operator: PublicKey,
    },

    // ========== Lifecycle (1) ==========
    /// Close the ledger
    LedgerClose,
}

impl LedgerOperation {
    /// Get the operation type as a discriminant byte
    pub fn discriminant(&self) -> u8 {
        match self {
            Self::LedgerOpen { .. } => 1,  // First operation
            Self::QuorumBegin { .. } => 12,
            Self::DepositOpen { .. } => 20,
            Self::DepositClose { .. } => 21,
            Self::FeeChange { .. } => 22,
            Self::DepositKeyRotate { .. } => 23,
            Self::InvoiceCredit { .. } => 30,
            Self::InvoiceLock { .. } => 31,
            Self::InvoiceFail { .. } => 32,
            Self::InvoiceFulfill { .. } => 33,
            Self::OnchainCredit { .. } => 35,
            Self::OnchainLock { .. } => 36,
            Self::OnchainFail { .. } => 37,
            Self::OnchainFulfill { .. } => 38,
            Self::TransferLock { .. } => 70,
            Self::TransferComplete { .. } => 71,
            Self::TransferFail { .. } => 72,
            Self::CollateralAttestation { .. } => 42,
            Self::QuorumAddMember { .. } => 43,
            Self::QuorumRemoveMember { .. } => 44,
            Self::CollateralLock { .. } => 45,
            Self::QuorumJoin { .. } => 46,
            Self::FeeCollect { .. } => 50,
            // Custody dispute operations
            Self::DisputeEnter { .. } => 54,  // Opens dispute, transitions to DISPUTED
            Self::DisputeAcquire { .. } => 55,  // Winner acquires custody
            Self::DisputeYield => 56,           // Loser yields, branch tombstoned
            Self::DisputeArmed { .. } => 57,    // Pre-commitment, transitions to READY
            Self::DeliveryEmbed { .. } => 80,
            Self::LedgerClose => 60,
        }
    }

    /// Get the wire message type constant for this operation.
    /// Derived from the discriminant — this is the canonical mapping.
    pub fn message_type(&self) -> u16 {
        match self {
            Self::LedgerOpen { .. } => consts::LEDGER_OPEN_REQUEST,
            Self::QuorumBegin { .. } => consts::QUORUM_BEGIN,
            Self::DepositOpen { .. } => consts::DEPOSIT_OPEN,
            Self::DepositClose { .. } => consts::DEPOSIT_CLOSE,
            Self::FeeChange { .. } => consts::FEE_CHANGE,
            Self::DepositKeyRotate { .. } => consts::DEPOSIT_KEY_ROTATE,
            Self::InvoiceCredit { .. } => consts::RECEIVING_CREDIT_PAYMENT,
            Self::InvoiceLock { .. } => consts::SENDING_LOCK_PAYMENT,
            Self::InvoiceFail { .. } => consts::SENDING_FAIL_PAYMENT,
            Self::InvoiceFulfill { .. } => consts::SENDING_FULFILL_PAYMENT,
            Self::OnchainCredit { .. } => consts::ONCHAIN_CREDIT,
            Self::OnchainLock { .. } => consts::ONCHAIN_LOCK,
            Self::OnchainFail { .. } => consts::ONCHAIN_FAIL,
            Self::OnchainFulfill { .. } => consts::ONCHAIN_FULFILL,
            Self::TransferLock { .. } => consts::TRANSFER_LOCK,
            Self::TransferComplete { .. } => consts::TRANSFER_COMPLETE,
            Self::TransferFail { .. } => consts::TRANSFER_FAIL,
            Self::CollateralAttestation { .. } => consts::COLLATERAL_ATTESTATION,
            Self::QuorumAddMember { .. } => consts::QUORUM_ADD_MEMBER,
            Self::QuorumRemoveMember { .. } => consts::QUORUM_REMOVE_MEMBER,
            Self::CollateralLock { .. } => consts::COLLATERAL_LOCK,
            Self::QuorumJoin { .. } => consts::QUORUM_JOIN,
            Self::FeeCollect { .. } => consts::MAINTENANCE_FEE_COLLECT,
            Self::DisputeEnter { .. } => consts::LEDGER_UPDATE,
            Self::DisputeAcquire { .. } => consts::LEDGER_UPDATE,
            Self::DisputeYield => consts::LEDGER_UPDATE,
            Self::DisputeArmed { .. } => consts::LEDGER_UPDATE,
            Self::DeliveryEmbed { .. } => consts::LEDGER_UPDATE,
            Self::LedgerClose => consts::LEDGER_CLOSE,
        }
    }

    /// Derive the message_type u16 from TLV-encoded message bytes
    /// by reading the discriminant from the first TLV field.
    pub fn message_type_from_bytes(message: &[u8]) -> u16 {
        // The discriminant is the first TLV field (tag=0).
        // TLV format: varint(tag) varint(len) bytes...
        // For tag=0: 0x00, then varint(1), then the u8 discriminant
        if message.len() >= 3 && message[0] == 0 && message[1] == 1 {
            Self::message_type_from_discriminant(message[2])
        } else {
            0
        }
    }

    /// Map a discriminant byte to the wire message type constant.
    pub fn message_type_from_discriminant(disc: u8) -> u16 {
        match disc {
            1 => consts::LEDGER_OPEN_REQUEST,
            12 => consts::QUORUM_BEGIN,
            20 => consts::DEPOSIT_OPEN,
            21 => consts::DEPOSIT_CLOSE,
            22 => consts::FEE_CHANGE,
            23 => consts::DEPOSIT_KEY_ROTATE,
            30 => consts::RECEIVING_CREDIT_PAYMENT,
            31 => consts::SENDING_LOCK_PAYMENT,
            32 => consts::SENDING_FAIL_PAYMENT,
            33 => consts::SENDING_FULFILL_PAYMENT,
            35 => consts::ONCHAIN_CREDIT,
            36 => consts::ONCHAIN_LOCK,
            37 => consts::ONCHAIN_FAIL,
            38 => consts::ONCHAIN_FULFILL,
            42 => consts::COLLATERAL_ATTESTATION,
            43 => consts::QUORUM_ADD_MEMBER,
            44 => consts::QUORUM_REMOVE_MEMBER,
            45 => consts::COLLATERAL_LOCK,
            46 => consts::QUORUM_JOIN,
            50 => consts::MAINTENANCE_FEE_COLLECT,
            54 | 55 | 56 | 57 | 80 => consts::LEDGER_UPDATE,
            60 => consts::LEDGER_CLOSE,
            70 => consts::TRANSFER_LOCK,
            71 => consts::TRANSFER_COMPLETE,
            72 => consts::TRANSFER_FAIL,
            _ => 0,
        }
    }

    /// Return deposit IDs affected by this operation (for Nostr event tagging).
    pub fn affected_deposit_ids(&self) -> Vec<&crate::types::DepositId> {
        match self {
            Self::DepositOpen { deposit_id, .. }
            | Self::DepositClose { deposit_id }
            | Self::FeeChange { deposit_id, .. }
            | Self::DepositKeyRotate { deposit_id, .. }
            | Self::InvoiceCredit { deposit_id, .. }
            | Self::InvoiceLock { deposit_id, .. }
            | Self::InvoiceFail { deposit_id, .. }
            | Self::InvoiceFulfill { deposit_id, .. }
            | Self::OnchainCredit { deposit_id, .. }
            | Self::OnchainLock { deposit_id, .. }
            | Self::OnchainFail { deposit_id, .. }
            | Self::OnchainFulfill { deposit_id, .. }
            | Self::FeeCollect { deposit_id, .. } => vec![deposit_id],

            Self::TransferLock { source_deposit_id, destination_deposit_id, .. } => {
                vec![source_deposit_id, destination_deposit_id]
            }

            // These don't reference deposits
            _ => vec![],
        }
    }
}

// ============================================================================
// Handshake Messages (0x8005 / 0x8007)
// ============================================================================

/// Protocol handshake to establish a ledger connection
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandshakeMsg {
    /// Protocol version
    pub protocol_version: u16,
    /// Minimum supported version
    pub min_protocol_version: u16,
    /// Feature flags
    pub features: u32,
    /// Operator's public key
    pub operator_id: PublicKey,
    /// Reserves identifier (UTXO address for BDK, partner pubkey string for LDK)
    pub reserves_id: String,
    /// Funding transaction ID (reserves UTXO)
    pub funding_txid: [u8; 32],
    /// Funding output index
    pub funding_vout: u16,
}

/// Response to handshake
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandshakeResponseMsg {
    /// Hash of the request being responded to
    pub request_hash: [u8; 32],
    /// Negotiated protocol version
    pub protocol_version: u16,
    /// Whether handshake was accepted
    pub accepted: bool,
    /// Error reason if rejected
    pub error: Option<String>,
    /// Reserves identifier
    pub reserves_id: String,
}

// ============================================================================
// Sync Messages (0x8009 / 0x800B)
// ============================================================================

/// Request to synchronize ledger state
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncMsg {
    pub ledger_id: [u8; 32],
    pub last_known_sequence: u64,
    pub last_known_hash: [u8; 32],
}

/// Response with missing updates
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncResponseMsg {
    pub ledger_id: [u8; 32],
    pub request_hash: [u8; 32],
    /// Signed updates since last_known_sequence
    pub updates: Vec<SignedLedgerUpdate>,
    pub current_sequence: u64,
    pub current_hash: [u8; 32],
}

// ============================================================================
// Recovery Messages (0x800D / 0x800F)
// ============================================================================

/// Recovery-related messages (nested enum)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecoveryMsg {
    /// Vote on whether operator is conforming
    Vote {
        operator: PublicKey,
        partner: PublicKey,
        voter: PublicKey,
        is_conforming: bool,
        validated_hash: [u8; 32],
        validated_sequence: u64,
        substitute_nomination: Option<PublicKey>,
        discovered_violation: bool,
        signature: [u8; 64],
    },
    /// Request signatures for a claim transaction
    ClaimRequest {
        operator: PublicKey,
        partner: PublicKey,
        claimant: PublicKey,
        tier_index: u8,
        unsigned_tx: Vec<u8>,
        sighash: [u8; 32],
        destination_script: Vec<u8>,
        block_height: u32,
    },
    /// Announce completion of a claim
    ClaimComplete {
        operator: PublicKey,
        partner: PublicKey,
        new_operator: PublicKey,
        claim_txid: [u8; 32],
        confirmation_block: u32,
        reason_code: u8,
    },
    /// Report an uncredited payment (fraud evidence)
    UncreditedPayment {
        operator: PublicKey,
        partner: PublicKey,
        payment_hash: [u8; 32],
        preimage: [u8; 32],
        deposit_pubkey: PublicKey,
        amount_msat: u64,
        invoice_cosignature: [u8; 64],
        settlement_sequence: u64,
        settlement_ledger_hash: [u8; 32],
        settlement_block_height: u32,
        accuser_signature: [u8; 64],
    },
}

impl RecoveryMsg {
    pub fn reserves_id(&self) -> Option<String> {
        match self {
            Self::Vote { partner, .. } => Some(partner.to_string()),
            Self::ClaimRequest { partner, .. } => Some(partner.to_string()),
            Self::ClaimComplete { partner, .. } => Some(partner.to_string()),
            Self::UncreditedPayment { partner, .. } => Some(partner.to_string()),
        }
    }
}

/// Response to recovery messages
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecoveryResponseMsg {
    /// Acknowledge a vote
    VoteAck {
        request_hash: [u8; 32],
        recorded: bool,
    },
    /// Provide a claim signature
    ClaimSignature {
        request_hash: [u8; 32],
        signer: PublicKey,
        sighash: [u8; 32],
        signature: [u8; 64],
    },
    /// Acknowledge claim completion
    ClaimAck {
        request_hash: [u8; 32],
    },
    /// Acknowledge uncredited payment report
    UncreditedPaymentAck {
        request_hash: [u8; 32],
    },
}

impl RecoveryResponseMsg {
    pub fn reserves_id(&self) -> Option<String> {
        None // Recovery responses don't have a specific partner
    }
}

// ============================================================================
// Coordination Messages (0x8011 / 0x8013)
// ============================================================================

/// Coordination messages for non-ledger-modifying operations
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CoordinationMsg {
    /// Request partner to cosign an invoice
    CosignInvoice {
        operator_id: PublicKey,
        reserves_id: String,
        /// Invoice details for cosigning
        amount: u64,
        payment_hash: [u8; 32],
        expires: u64,
        assigned_deposit: PublicKey,
        invoice_id: String,
        bolt11_invoice: String,
    },
    /// Request consent for collateral registration
    CollateralConsentRequest {
        operator_id: PublicKey,
        reserves_id: String,
        operator_signature: [u8; 64],
    },
    /// Quorum join request
    QuorumJoinRequest {
        requester_pubkey: PublicKey,
        operator_id: PublicKey,
        reserves_id: String,
        protocol_version: u16,
        timestamp: u64,
        signature: [u8; 64],
    },
    /// Quorum vote request
    QuorumVoteRequest {
        vote_round_id: [u8; 32],
        operator_id: PublicKey,
        reserves_id: String,
        sequence_number: u64,
        state_hash: [u8; 32],
        claimed_reserves: u64,
        collateral_amounts: Vec<u64>,
        reserves_outpoint: Vec<u8>,
        destination_script: Vec<u8>,
        fee_rate_sat_vbyte: u64,
        timestamp: u64,
    },
    /// Quorum vote submission
    QuorumVote {
        vote_round_id: [u8; 32],
        voter_pubkey: PublicKey,
        vote: bool,
        voter_sequence: u64,
        voter_state_hash: [u8; 32],
        evidence: Option<Vec<u8>>,
        signature: [u8; 64],
        spend_signature: Option<[u8; 64]>,
    },
    /// Propose extra outputs for reserves commitment
    UpdateReserves {
        channel_id: [u8; 32],
        reserves_sats: u64,
        script_pubkey: Vec<u8>,
        ledger_hash: [u8; 32],
        remote_ledger_hash: [u8; 32],
    },
}

impl CoordinationMsg {
    pub fn reserves_id(&self) -> Option<String> {
        match self {
            Self::CosignInvoice { reserves_id, .. } => Some(reserves_id.clone()),
            Self::CollateralConsentRequest { reserves_id, .. } => Some(reserves_id.clone()),
            Self::QuorumJoinRequest { reserves_id, .. } => Some(reserves_id.clone()),
            Self::QuorumVoteRequest { reserves_id, .. } => Some(reserves_id.clone()),
            Self::QuorumVote { .. } => None,
            Self::UpdateReserves { .. } => None, // Channel-level, not ledger-level
        }
    }
}

/// Response to coordination messages
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CoordinationResponseMsg {
    /// Invoice cosigned
    InvoiceCosigned {
        request_hash: [u8; 32],
        cosignature: [u8; 64],
    },
    /// Collateral consent granted/denied
    CollateralConsentResponse {
        request_hash: [u8; 32],
        operator_id: PublicKey,
        reserves_id: String,
        consent_granted: bool,
        quorum_member_signature: [u8; 64],
    },
    /// Quorum join accepted/rejected
    QuorumJoinResponse {
        request_hash: [u8; 32],
        accepted: bool,
        members: Vec<PublicKey>,
        threshold: u16,
        last_sequence: u64,
        current_hash: [u8; 32],
        rejection_reason: Option<String>,
    },
    /// Quorum state sync
    QuorumStateSync {
        request_hash: [u8; 32],
        operator_id: PublicKey,
        reserves_id: String,
        updates: Vec<SignedLedgerUpdate>,
        start_sequence: u64,
        is_final: bool,
    },
    /// Quorum membership change announcement
    QuorumMembershipChange {
        request_hash: [u8; 32],
        operator_id: PublicKey,
        reserves_id: String,
        change_type: String,
        member_pubkey: PublicKey,
        new_members: Vec<PublicKey>,
        new_threshold: u16,
        timestamp: u64,
        operator_signature: [u8; 64],
    },
    /// Accept proposed reserves commitment
    AcceptReserves {
        channel_id: [u8; 32],
    },
}

impl CoordinationResponseMsg {
    pub fn reserves_id(&self) -> Option<String> {
        match self {
            Self::InvoiceCosigned { .. } => None,
            Self::CollateralConsentResponse { reserves_id, .. } => Some(reserves_id.clone()),
            Self::QuorumJoinResponse { .. } => None,
            Self::QuorumStateSync { reserves_id, .. } => Some(reserves_id.clone()),
            Self::QuorumMembershipChange { reserves_id, .. } => Some(reserves_id.clone()),
            Self::AcceptReserves { .. } => None, // Channel-level, not ledger-level
        }
    }
}

// ============================================================================
// Binary Codec (no LDK dependencies)
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    TooShort,
    InvalidMessageType(u16),
    InvalidDiscriminant(u8),
    InvalidData(String),
    Io(String),
}

impl std::fmt::Display for CodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort => write!(f, "buffer too short"),
            Self::InvalidMessageType(t) => write!(f, "invalid message type: 0x{:04X}", t),
            Self::InvalidDiscriminant(d) => write!(f, "invalid discriminant: {}", d),
            Self::InvalidData(s) => write!(f, "invalid data: {}", s),
            Self::Io(s) => write!(f, "IO error: {}", s),
        }
    }
}

impl std::error::Error for CodecError {}

impl From<io::Error> for CodecError {
    fn from(e: io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

/// Binary codec trait for V2 messages
pub trait BinaryCodec: Sized {
    fn write_to<W: Write>(&self, writer: &mut W) -> Result<(), CodecError>;
    fn read_from<R: Read>(reader: &mut R) -> Result<Self, CodecError>;
}

// Helper functions for binary encoding
fn write_u8<W: Write>(w: &mut W, v: u8) -> Result<(), CodecError> {
    w.write_all(&[v])?;
    Ok(())
}

fn write_u16<W: Write>(w: &mut W, v: u16) -> Result<(), CodecError> {
    w.write_all(&v.to_be_bytes())?;
    Ok(())
}

fn write_u32<W: Write>(w: &mut W, v: u32) -> Result<(), CodecError> {
    w.write_all(&v.to_be_bytes())?;
    Ok(())
}

fn write_u64<W: Write>(w: &mut W, v: u64) -> Result<(), CodecError> {
    w.write_all(&v.to_be_bytes())?;
    Ok(())
}

fn write_bool<W: Write>(w: &mut W, v: bool) -> Result<(), CodecError> {
    write_u8(w, if v { 1 } else { 0 })
}

fn write_bytes<W: Write>(w: &mut W, v: &[u8]) -> Result<(), CodecError> {
    write_u32(w, v.len() as u32)?;
    w.write_all(v)?;
    Ok(())
}

fn write_string<W: Write>(w: &mut W, v: &str) -> Result<(), CodecError> {
    write_bytes(w, v.as_bytes())
}

fn write_pubkey<W: Write>(w: &mut W, pk: &PublicKey) -> Result<(), CodecError> {
    w.write_all(&pk.serialize())?;
    Ok(())
}

fn write_20<W: Write>(w: &mut W, v: &[u8; 20]) -> Result<(), CodecError> {
    w.write_all(v)?;
    Ok(())
}

fn write_32<W: Write>(w: &mut W, v: &[u8; 32]) -> Result<(), CodecError> {
    w.write_all(v)?;
    Ok(())
}

fn write_64<W: Write>(w: &mut W, v: &[u8; 64]) -> Result<(), CodecError> {
    w.write_all(v)?;
    Ok(())
}

fn write_option<W: Write, T, F>(w: &mut W, v: &Option<T>, f: F) -> Result<(), CodecError>
where
    F: FnOnce(&mut W, &T) -> Result<(), CodecError>,
{
    match v {
        Some(val) => {
            write_bool(w, true)?;
            f(w, val)?;
        }
        None => write_bool(w, false)?,
    }
    Ok(())
}

fn write_vec<W: Write, T, F>(w: &mut W, v: &[T], f: F) -> Result<(), CodecError>
where
    F: Fn(&mut W, &T) -> Result<(), CodecError>,
{
    write_u32(w, v.len() as u32)?;
    for item in v {
        f(w, item)?;
    }
    Ok(())
}

fn read_u8<R: Read>(r: &mut R) -> Result<u8, CodecError> {
    let mut buf = [0u8; 1];
    r.read_exact(&mut buf)?;
    Ok(buf[0])
}

fn read_u16<R: Read>(r: &mut R) -> Result<u16, CodecError> {
    let mut buf = [0u8; 2];
    r.read_exact(&mut buf)?;
    Ok(u16::from_be_bytes(buf))
}

fn read_u32<R: Read>(r: &mut R) -> Result<u32, CodecError> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf)?;
    Ok(u32::from_be_bytes(buf))
}

fn read_u64<R: Read>(r: &mut R) -> Result<u64, CodecError> {
    let mut buf = [0u8; 8];
    r.read_exact(&mut buf)?;
    Ok(u64::from_be_bytes(buf))
}

fn read_bool<R: Read>(r: &mut R) -> Result<bool, CodecError> {
    Ok(read_u8(r)? != 0)
}

fn read_bytes<R: Read>(r: &mut R) -> Result<Vec<u8>, CodecError> {
    let len = read_u32(r)? as usize;
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

fn read_string<R: Read>(r: &mut R) -> Result<String, CodecError> {
    let bytes = read_bytes(r)?;
    String::from_utf8(bytes).map_err(|e| CodecError::InvalidData(e.to_string()))
}

fn read_pubkey<R: Read>(r: &mut R) -> Result<PublicKey, CodecError> {
    let mut buf = [0u8; 33];
    r.read_exact(&mut buf)?;
    PublicKey::from_slice(&buf).map_err(|e| CodecError::InvalidData(e.to_string()))
}

fn read_20<R: Read>(r: &mut R) -> Result<[u8; 20], CodecError> {
    let mut buf = [0u8; 20];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

fn read_32<R: Read>(r: &mut R) -> Result<[u8; 32], CodecError> {
    let mut buf = [0u8; 32];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

fn read_33<R: Read>(r: &mut R) -> Result<[u8; 33], CodecError> {
    let mut buf = [0u8; 33];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

fn read_64<R: Read>(r: &mut R) -> Result<[u8; 64], CodecError> {
    let mut buf = [0u8; 64];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

fn read_option<R: Read, T, F>(r: &mut R, f: F) -> Result<Option<T>, CodecError>
where
    F: FnOnce(&mut R) -> Result<T, CodecError>,
{
    if read_bool(r)? {
        Ok(Some(f(r)?))
    } else {
        Ok(None)
    }
}

fn read_vec<R: Read, T, F>(r: &mut R, f: F) -> Result<Vec<T>, CodecError>
where
    F: Fn(&mut R) -> Result<T, CodecError>,
{
    let len = read_u32(r)? as usize;
    let mut result = Vec::with_capacity(len);
    for _ in 0..len {
        result.push(f(r)?);
    }
    Ok(result)
}

// FeeStructure codec
impl BinaryCodec for FeeStructure {
    fn write_to<W: Write>(&self, w: &mut W) -> Result<(), CodecError> {
        write_u64(w, self.annualized_msats)?;
        write_u16(w, self.annualized_bps)?;
        write_u32(w, self.frequency_blocks)?;
        Ok(())
    }

    fn read_from<R: Read>(r: &mut R) -> Result<Self, CodecError> {
        Ok(Self {
            annualized_msats: read_u64(r)?,
            annualized_bps: read_u16(r)?,
            frequency_blocks: read_u32(r)?,
        })
    }
}

// LedgerOperation codec
impl BinaryCodec for LedgerOperation {
    fn write_to<W: Write>(&self, w: &mut W) -> Result<(), CodecError> {
        write_u8(w, self.discriminant())?;
        match self {
            Self::LedgerOpen { operator_id, reserves_id, genesis_block, reserves_amount } => {
                write_pubkey(w, operator_id)?;
                write_string(w, reserves_id)?;
                write_u32(w, *genesis_block)?;
                write_u32(w, 0)?; // reserved (was collateral_enforcement_block)
                write_u64(w, *reserves_amount)?;
            }
            Self::QuorumBegin { reserves_id, spending_txid, new_outpoint_txid, new_outpoint_vout, amount, quorum_expiry, ledger_hash, quorum_members, total_collateral } => {
                write_string(w, reserves_id)?;
                write_32(w, spending_txid)?;
                write_32(w, new_outpoint_txid)?;
                write_u32(w, *new_outpoint_vout)?;
                write_u64(w, *amount)?;
                write_u8(w, quorum_members.len() as u8)?;
                write_u8(w, quorum_members.len() as u8)?;
                write_u32(w, *quorum_expiry)?;
                write_32(w, ledger_hash)?;
                write_u64(w, *total_collateral)?;
            }
            // Legacy encoding - deposit operations now use deposit_id/descriptor, but we encode
            // the deposit_id bytes as a placeholder for legacy compatibility
            Self::DepositOpen { deposit_id, fees, payment_hash, invoice, cosigner_guarantee_signature, .. } => {
                // Write deposit_id padded to 33 bytes (legacy pubkey size)
                let mut legacy_bytes = [0u8; 33];
                legacy_bytes[0] = 0x02; // Valid compressed pubkey prefix
                legacy_bytes[1..17].copy_from_slice(deposit_id);
                w.write_all(&legacy_bytes)?;
                write_option(w, fees, |w, f| f.write_to(w))?;
                write_option(w, payment_hash, |w, h| write_32(w, h))?;
                write_option(w, invoice, |w, s| write_string(w, s))?;
                write_option(w, cosigner_guarantee_signature, |w, s| write_64(w, s))?;
            }
            Self::DepositClose { deposit_id } => {
                let mut legacy_bytes = [0u8; 33];
                legacy_bytes[0] = 0x02;
                legacy_bytes[1..17].copy_from_slice(deposit_id);
                w.write_all(&legacy_bytes)?;
            }
            Self::FeeChange { deposit_id, new_fees, .. } => {
                let mut legacy_bytes = [0u8; 33];
                legacy_bytes[0] = 0x02;
                legacy_bytes[1..17].copy_from_slice(deposit_id);
                w.write_all(&legacy_bytes)?;
                new_fees.write_to(w)?;
            }
            Self::DepositKeyRotate { deposit_id, new_descriptor, witness } => {
                let mut legacy_bytes = [0u8; 33];
                legacy_bytes[0] = 0x02;
                legacy_bytes[1..17].copy_from_slice(deposit_id);
                w.write_all(&legacy_bytes)?;
                write_string(w, new_descriptor)?;
                // Write first stack element (signature) as 64 bytes or zeros
                let sig_bytes: [u8; 64] = witness.stack.first()
                    .and_then(|s| if s.len() >= 64 { s[..64].try_into().ok() } else { None })
                    .unwrap_or([0u8; 64]);
                w.write_all(&sig_bytes)?;
            }
            Self::InvoiceCredit { payment_hash, deposit_id, amount, invoice_id, sequence_number } => {
                write_32(w, payment_hash)?;
                let mut legacy_bytes = [0u8; 33];
                legacy_bytes[0] = 0x02;
                legacy_bytes[1..17].copy_from_slice(deposit_id);
                w.write_all(&legacy_bytes)?;
                write_u64(w, *amount)?;
                write_string(w, invoice_id)?;
                write_u64(w, *sequence_number)?;
            }
            Self::InvoiceLock { deposit_id, amount, payment_id, sequence_number, witness } => {
                let mut legacy_bytes = [0u8; 33];
                legacy_bytes[0] = 0x02;
                legacy_bytes[1..17].copy_from_slice(deposit_id);
                w.write_all(&legacy_bytes)?;
                write_u64(w, *amount)?;
                write_32(w, payment_id)?;
                write_u64(w, *sequence_number)?;
                // Write first stack element (signature) as 64 bytes or zeros
                let sig_bytes: [u8; 64] = witness.stack.first()
                    .and_then(|s| if s.len() >= 64 { s[..64].try_into().ok() } else { None })
                    .unwrap_or([0u8; 64]);
                w.write_all(&sig_bytes)?;
            }
            Self::InvoiceFail { deposit_id, amount, payment_id, sequence_number } => {
                let mut legacy_bytes = [0u8; 33];
                legacy_bytes[0] = 0x02;
                legacy_bytes[1..17].copy_from_slice(deposit_id);
                w.write_all(&legacy_bytes)?;
                write_u64(w, *amount)?;
                write_32(w, payment_id)?;
                write_u64(w, *sequence_number)?;
            }
            Self::InvoiceFulfill { deposit_id, amount, payment_id, sequence_number, witness, preimage } => {
                let mut legacy_bytes = [0u8; 33];
                legacy_bytes[0] = 0x02;
                legacy_bytes[1..17].copy_from_slice(deposit_id);
                w.write_all(&legacy_bytes)?;
                write_u64(w, *amount)?;
                write_32(w, payment_id)?;
                write_u64(w, *sequence_number)?;
                let sig_bytes: [u8; 64] = witness.stack.first()
                    .and_then(|s| if s.len() >= 64 { s[..64].try_into().ok() } else { None })
                    .unwrap_or([0u8; 64]);
                w.write_all(&sig_bytes)?;
                write_32(w, preimage)?;
            }
            Self::OnchainCredit { txid, vout, deposit_id, amount, funding_address } => {
                write_32(w, txid)?;
                write_u32(w, *vout)?;
                let mut legacy_bytes = [0u8; 33];
                legacy_bytes[0] = 0x02;
                legacy_bytes[1..17].copy_from_slice(deposit_id);
                w.write_all(&legacy_bytes)?;
                write_u64(w, *amount)?;
                write_string(w, funding_address)?;
            }
            Self::OnchainLock { deposit_id, amount, fee_sats, destination_address, withdrawal_id, witness } => {
                let mut legacy_bytes = [0u8; 33];
                legacy_bytes[0] = 0x02;
                legacy_bytes[1..17].copy_from_slice(deposit_id);
                w.write_all(&legacy_bytes)?;
                write_u64(w, *amount)?;
                write_u64(w, *fee_sats)?;
                write_string(w, destination_address)?;
                write_32(w, withdrawal_id)?;
                // Write first stack element (signature) as 64 bytes or zeros
                let sig_bytes: [u8; 64] = witness.stack.first()
                    .and_then(|s| if s.len() >= 64 { s[..64].try_into().ok() } else { None })
                    .unwrap_or([0u8; 64]);
                w.write_all(&sig_bytes)?;
            }
            Self::OnchainFail { deposit_id, withdrawal_id } => {
                let mut legacy_bytes = [0u8; 33];
                legacy_bytes[0] = 0x02;
                legacy_bytes[1..17].copy_from_slice(deposit_id);
                w.write_all(&legacy_bytes)?;
                write_32(w, withdrawal_id)?;
            }
            Self::OnchainFulfill { deposit_id, withdrawal_id, amount, txid, destination_address } => {
                let mut legacy_bytes = [0u8; 33];
                legacy_bytes[0] = 0x02;
                legacy_bytes[1..17].copy_from_slice(deposit_id);
                w.write_all(&legacy_bytes)?;
                write_32(w, withdrawal_id)?;
                write_u64(w, *amount)?;
                write_32(w, txid)?;
                write_string(w, destination_address)?;
            }
            Self::TransferLock { nonce, source_deposit_id, destination_deposit_id, amount, fee, completion_script, timeout_height, transfer_id, witness } => {
                write_32(w, nonce)?;
                let mut src_bytes = [0u8; 33];
                src_bytes[0] = 0x02;
                src_bytes[1..17].copy_from_slice(source_deposit_id);
                w.write_all(&src_bytes)?;
                let mut dst_bytes = [0u8; 33];
                dst_bytes[0] = 0x02;
                dst_bytes[1..17].copy_from_slice(destination_deposit_id);
                w.write_all(&dst_bytes)?;
                write_u64(w, *amount)?;
                write_u64(w, *fee)?;
                write_string(w, completion_script)?;
                write_u32(w, *timeout_height)?;
                write_32(w, transfer_id)?;
                let sig_bytes: [u8; 64] = witness.stack.first()
                    .and_then(|s| if s.len() >= 64 { s[..64].try_into().ok() } else { None })
                    .unwrap_or([0u8; 64]);
                w.write_all(&sig_bytes)?;
            }
            Self::TransferComplete { transfer_id, script_witness } => {
                write_32(w, transfer_id)?;
                // Write witness stack length and elements
                write_u16(w, script_witness.stack.len() as u16)?;
                for element in &script_witness.stack {
                    write_u16(w, element.len() as u16)?;
                    w.write_all(element)?;
                }
            }
            Self::TransferFail { transfer_id, block_hash, reason } => {
                write_32(w, transfer_id)?;
                write_32(w, block_hash)?;
                write_u8(w, *reason)?;
            }
            Self::CollateralAttestation { collateral_operator, quorum_member, collateral_ledger_id, amount, block_height, lock_until_block, signature, ledger_hash } => {
                write_pubkey(w, collateral_operator)?;
                write_pubkey(w, quorum_member)?;
                write_string(w, collateral_ledger_id)?;
                write_u64(w, *amount)?;
                write_u32(w, *block_height)?;
                write_u32(w, *lock_until_block)?;
                write_64(w, signature)?;
                write_32(w, ledger_hash)?;
            }
            Self::QuorumAddMember { quorum_member, quorum_member_signature, member_ledger_id, .. } => {
                write_pubkey(w, quorum_member)?;
                write_64(w, quorum_member_signature)?;
                write_string(w, member_ledger_id)?;
            }
            Self::QuorumRemoveMember { quorum_member, operator_signature } => {
                write_pubkey(w, quorum_member)?;
                write_64(w, operator_signature)?;
            }
            Self::CollateralLock { deposit_id, amount, lock_until_block, operator_id, witness } => {
                let mut legacy_bytes = [0u8; 33];
                legacy_bytes[0] = 0x02;
                legacy_bytes[1..17].copy_from_slice(deposit_id);
                w.write_all(&legacy_bytes)?;
                write_u64(w, *amount)?;
                write_u32(w, *lock_until_block)?;
                write_pubkey(w, operator_id)?;
                let sig_bytes: [u8; 64] = witness.stack.first()
                    .and_then(|s| if s.len() >= 64 { s[..64].try_into().ok() } else { None })
                    .unwrap_or([0u8; 64]);
                w.write_all(&sig_bytes)?;
            }
            Self::QuorumJoin { operator_id, ledger_id, membership_expires, our_signature } => {
                write_pubkey(w, operator_id)?;
                write_string(w, ledger_id)?;
                write_u32(w, *membership_expires)?;
                write_64(w, our_signature)?;
            }
            Self::FeeCollect { deposit_id, amount, block_height } => {
                let mut legacy_bytes = [0u8; 33];
                legacy_bytes[0] = 0x02;
                legacy_bytes[1..17].copy_from_slice(deposit_id);
                w.write_all(&legacy_bytes)?;
                write_u64(w, *amount)?;
                write_u32(w, *block_height)?;
            }
            Self::DisputeEnter { last_valid_sequence, reason } => {
                write_u64(w, *last_valid_sequence)?;
                write_string(w, reason)?;
            }
            Self::DisputeArmed { armed_block, commitment_hash, target_reserves } => {
                write_u32(w, *armed_block)?;
                write_20(w, commitment_hash)?;
                write_string(w, target_reserves)?;
            }
            Self::DisputeAcquire { new_custodian, entropy_block_height, entropy_block_hash, spend_txid, new_reserves_address } => {
                write_pubkey(w, new_custodian)?;
                write_u32(w, *entropy_block_height)?;
                write_32(w, entropy_block_hash)?;
                write_32(w, spend_txid)?;
                write_string(w, new_reserves_address)?;
            }
            Self::DeliveryEmbed { request_hash, target_ledger_id, target_operator } => {
                write_32(w, request_hash)?;
                write_32(w, target_ledger_id)?;
                write_pubkey(w, target_operator)?;
            }
            Self::DisputeYield => {}
            Self::LedgerClose => {}
        }
        Ok(())
    }

    fn read_from<R: Read>(r: &mut R) -> Result<Self, CodecError> {
        let discriminant = read_u8(r)?;
        match discriminant {
            // LedgerOpen (1)
            1 => {
                let operator_id = read_pubkey(r)?;
                let reserves_id = read_string(r)?;
                let genesis_block = read_u32(r)?;
                let _reserved = read_u32(r)?; // was collateral_enforcement_block
                // reserves_amount added later; default to 0 for legacy data
                let reserves_amount = read_u64(r).unwrap_or(0);
                Ok(Self::LedgerOpen {
                    operator_id, reserves_id, genesis_block,
                    reserves_amount,
                })
            }
            // QuorumBegin (12) — formerly ReservesRotate
            12 => {
                let reserves_id = read_string(r)?;
                let spending_txid = read_32(r)?;
                let new_outpoint_txid = read_32(r)?;
                let new_outpoint_vout = read_u32(r)?;
                let amount = read_u64(r)?;
                let _threshold = read_u8(r)?; // legacy: skip
                let _size = read_u8(r)?; // legacy: skip
                let quorum_expiry = read_u32(r)?;
                let ledger_hash = read_32(r)?;
                let total_collateral = read_u64(r).unwrap_or(0);
                Ok(Self::QuorumBegin {
                    reserves_id, spending_txid, new_outpoint_txid, new_outpoint_vout,
                    amount, quorum_expiry, ledger_hash, quorum_members: Vec::new(),
                    total_collateral,
                })
            }
            // Deposit operations (20-25) - legacy decoding extracts deposit_id from embedded bytes
            20 => {
                let legacy_bytes = read_33(r)?;
                let mut deposit_id = [0u8; 16];
                deposit_id.copy_from_slice(&legacy_bytes[1..17]);
                Ok(Self::DepositOpen {
                    deposit_id,
                    descriptor: format!("legacy({})", hex::encode(&deposit_id)),
                    fees: read_option(r, FeeStructure::read_from)?,
                    transfer_fees: None,
                    payment_hash: read_option(r, read_32)?,
                    invoice: read_option(r, read_string)?,
                    cosigner_guarantee_signature: read_option(r, read_64)?,
                    is_collateral: false,
                    receive_requires_sig: false,
                    fee_change_after_blocks: None,
                    fee_change_notice_blocks: None,
                    fee_change_limit_bps: None,
                })
            }
            21 => {
                let legacy_bytes = read_33(r)?;
                let mut deposit_id = [0u8; 16];
                deposit_id.copy_from_slice(&legacy_bytes[1..17]);
                Ok(Self::DepositClose { deposit_id })
            }
            22 => {
                let legacy_bytes = read_33(r)?;
                let mut deposit_id = [0u8; 16];
                deposit_id.copy_from_slice(&legacy_bytes[1..17]);
                Ok(Self::FeeChange {
                    deposit_id,
                    new_fees: FeeStructure::read_from(r)?,
                    effective_block: 0,
                })
            }
            23 => {
                let legacy_bytes = read_33(r)?;
                let mut deposit_id = [0u8; 16];
                deposit_id.copy_from_slice(&legacy_bytes[1..17]);
                let new_descriptor = read_string(r)?;
                let sig_bytes = read_64(r)?;
                let witness = DescriptorWitness {
                    stack: vec![sig_bytes.to_vec()],
                };
                Ok(Self::DepositKeyRotate {
                    deposit_id,
                    new_descriptor,
                    witness,
                })
            }
            // Invoice operations (30-33)
            30 => {
                let payment_hash = read_32(r)?;
                let legacy_bytes = read_33(r)?;
                let mut deposit_id = [0u8; 16];
                deposit_id.copy_from_slice(&legacy_bytes[1..17]);
                Ok(Self::InvoiceCredit {
                    payment_hash,
                    deposit_id,
                    amount: read_u64(r)?,
                    invoice_id: read_string(r)?,
                    sequence_number: read_u64(r)?,
                })
            }
            31 => {
                let legacy_bytes = read_33(r)?;
                let mut deposit_id = [0u8; 16];
                deposit_id.copy_from_slice(&legacy_bytes[1..17]);
                let amount = read_u64(r)?;
                let payment_id = read_32(r)?;
                let sequence_number = read_u64(r)?;
                let sig = read_64(r)?;
                Ok(Self::InvoiceLock {
                    deposit_id,
                    amount,
                    payment_id,
                    sequence_number,
                    witness: crate::types::DescriptorWitness { stack: vec![sig.to_vec()] },
                })
            }
            32 => {
                let legacy_bytes = read_33(r)?;
                let mut deposit_id = [0u8; 16];
                deposit_id.copy_from_slice(&legacy_bytes[1..17]);
                Ok(Self::InvoiceFail {
                    deposit_id,
                    amount: read_u64(r)?,
                    payment_id: read_32(r)?,
                    sequence_number: read_u64(r)?,
                })
            }
            33 => {
                let legacy_bytes = read_33(r)?;
                let mut deposit_id = [0u8; 16];
                deposit_id.copy_from_slice(&legacy_bytes[1..17]);
                let amount = read_u64(r)?;
                let payment_id = read_32(r)?;
                let sequence_number = read_u64(r)?;
                let sig = read_64(r)?;
                let preimage = read_32(r)?;
                Ok(Self::InvoiceFulfill {
                    deposit_id,
                    amount,
                    payment_id,
                    sequence_number,
                    witness: crate::types::DescriptorWitness { stack: vec![sig.to_vec()] },
                    preimage,
                })
            }
            // Onchain operations (35-38)
            35 => {
                let txid = read_32(r)?;
                let vout = read_u32(r)?;
                let legacy_bytes = read_33(r)?;
                let mut deposit_id = [0u8; 16];
                deposit_id.copy_from_slice(&legacy_bytes[1..17]);
                Ok(Self::OnchainCredit {
                    txid,
                    vout,
                    deposit_id,
                    amount: read_u64(r)?,
                    funding_address: read_string(r)?,
                })
            }
            36 => {
                let legacy_bytes = read_33(r)?;
                let mut deposit_id = [0u8; 16];
                deposit_id.copy_from_slice(&legacy_bytes[1..17]);
                let amount = read_u64(r)?;
                let fee_sats = read_u64(r)?;
                let destination_address = read_string(r)?;
                let withdrawal_id = read_32(r)?;
                let sig_bytes = read_64(r)?;
                Ok(Self::OnchainLock {
                    deposit_id,
                    amount,
                    fee_sats,
                    destination_address,
                    withdrawal_id,
                    witness: DescriptorWitness { stack: vec![sig_bytes.to_vec()] },
                })
            }
            37 => {
                let legacy_bytes = read_33(r)?;
                let mut deposit_id = [0u8; 16];
                deposit_id.copy_from_slice(&legacy_bytes[1..17]);
                Ok(Self::OnchainFail {
                    deposit_id,
                    withdrawal_id: read_32(r)?,
                })
            }
            38 => {
                let legacy_bytes = read_33(r)?;
                let mut deposit_id = [0u8; 16];
                deposit_id.copy_from_slice(&legacy_bytes[1..17]);
                Ok(Self::OnchainFulfill {
                    deposit_id,
                    withdrawal_id: read_32(r)?,
                    amount: read_u64(r)?,
                    txid: read_32(r)?,
                    destination_address: read_string(r)?,
                })
            }
            // Transfer operations (70-72)
            70 => {
                let nonce = read_32(r)?;
                let src_bytes = read_33(r)?;
                let mut source_deposit_id = [0u8; 16];
                source_deposit_id.copy_from_slice(&src_bytes[1..17]);
                let dst_bytes = read_33(r)?;
                let mut destination_deposit_id = [0u8; 16];
                destination_deposit_id.copy_from_slice(&dst_bytes[1..17]);
                let amount = read_u64(r)?;
                let fee = read_u64(r)?;
                let completion_script = read_string(r)?;
                let timeout_height = read_u32(r)?;
                let transfer_id = read_32(r)?;
                let sig_bytes = read_64(r)?;
                Ok(Self::TransferLock {
                    nonce,
                    source_deposit_id,
                    destination_deposit_id,
                    amount,
                    fee,
                    completion_script,
                    timeout_height,
                    transfer_id,
                    witness: DescriptorWitness { stack: vec![sig_bytes.to_vec()] },
                })
            }
            71 => {
                let transfer_id = read_32(r)?;
                let stack_len = read_u16(r)? as usize;
                let mut stack = Vec::with_capacity(stack_len);
                for _ in 0..stack_len {
                    let elem_len = read_u16(r)? as usize;
                    let mut elem = vec![0u8; elem_len];
                    r.read_exact(&mut elem)?;
                    stack.push(elem);
                }
                Ok(Self::TransferComplete {
                    transfer_id,
                    script_witness: DescriptorWitness { stack },
                })
            }
            72 => Ok(Self::TransferFail {
                transfer_id: read_32(r)?,
                block_hash: read_32(r)?,
                reason: read_u8(r).unwrap_or(1),
            }),
            // Collateral operations (40-44)
            42 => Ok(Self::CollateralAttestation {
                collateral_operator: read_pubkey(r)?,
                quorum_member: read_pubkey(r)?,
                collateral_ledger_id: read_string(r)?,
                amount: read_u64(r)?,
                block_height: read_u32(r)?,
                lock_until_block: read_u32(r)?,
                signature: read_64(r)?,
                ledger_hash: read_32(r)?,
            }),
            43 => Ok(Self::QuorumAddMember {
                quorum_member: read_pubkey(r)?,
                quorum_member_signature: read_64(r)?,
                member_ledger_id: read_string(r)?,
                min_fee_bps: None,
                min_fee_fixed: None,
                max_fee_period: None,
                collateral_lock_amount: None,
                collateral_lock_until: None,
                dispute_response_blocks: None,
                dispute_arm_blocks: None,
                service_response_blocks: None,
                max_transfer_timeout_blocks: None,
                max_descriptor_bytes: None,
            }),
            44 => Ok(Self::QuorumRemoveMember {
                quorum_member: read_pubkey(r)?,
                operator_signature: read_64(r)?,
            }),
            45 => {
                let legacy_bytes = read_33(r)?;
                let mut deposit_id = [0u8; 16];
                deposit_id.copy_from_slice(&legacy_bytes[1..17]);
                let amount = read_u64(r)?;
                let lock_until_block = read_u32(r)?;
                let operator_id = read_pubkey(r)?;
                let sig = read_64(r)?;
                Ok(Self::CollateralLock {
                    deposit_id,
                    amount,
                    lock_until_block,
                    operator_id,
                    witness: crate::types::DescriptorWitness { stack: vec![sig.to_vec()] },
                })
            }
            46 => Ok(Self::QuorumJoin {
                operator_id: read_pubkey(r)?,
                ledger_id: read_string(r)?,
                membership_expires: read_u32(r)?,
                our_signature: read_64(r)?,
            }),
            // Fee operations (50)
            50 => {
                let legacy_bytes = read_33(r)?;
                let mut deposit_id = [0u8; 16];
                deposit_id.copy_from_slice(&legacy_bytes[1..17]);
                Ok(Self::FeeCollect {
                    deposit_id,
                    amount: read_u64(r)?,
                    block_height: read_u32(r)?,
                })
            }
            // DisputeEnter (54)
            54 => Ok(Self::DisputeEnter {
                last_valid_sequence: read_u64(r)?,
                reason: read_string(r)?,
            }),
            // DisputeAcquire (55)
            55 => Ok(Self::DisputeAcquire {
                new_custodian: read_pubkey(r)?,
                entropy_block_height: read_u32(r)?,
                entropy_block_hash: read_32(r)?,
                spend_txid: read_32(r)?,
                new_reserves_address: read_string(r)?,
            }),
            // DisputeYield (56)
            56 => Ok(Self::DisputeYield),
            // DisputeArmed (57)
            57 => Ok(Self::DisputeArmed {
                armed_block: read_u32(r)?,
                commitment_hash: read_20(r)?,
                target_reserves: read_string(r)?,
            }),
            // DeliveryEmbed (80)
            80 => Ok(Self::DeliveryEmbed {
                request_hash: read_32(r)?,
                target_ledger_id: read_32(r)?,
                target_operator: read_pubkey(r)?,
            }),
            // Close operations (60)
            60 => Ok(Self::LedgerClose),
            _ => Err(CodecError::InvalidDiscriminant(discriminant)),
        }
    }
}

// LedgerUpdateMsg codec (for computing message hash in handlers)
impl BinaryCodec for LedgerUpdateMsg {
    fn write_to<W: Write>(&self, w: &mut W) -> Result<(), CodecError> {
        write_pubkey(w, &self.operator_id)?;
        write_string(w, &self.reserves_id)?;
        self.operation.write_to(w)?;
        write_u64(w, self.sequence_number)?;
        write_32(w, &self.previous_hash)?;
        write_32(w, &self.current_hash)?;
        write_64(w, &self.operator_signature)?;
        Ok(())
    }

    fn read_from<R: Read>(r: &mut R) -> Result<Self, CodecError> {
        Ok(Self {
            operator_id: read_pubkey(r)?,
            reserves_id: read_string(r)?,
            operation: LedgerOperation::read_from(r)?,
            sequence_number: read_u64(r)?,
            previous_hash: read_32(r)?,
            current_hash: read_32(r)?,
            operator_signature: read_64(r)?,
        })
    }
}

impl BinaryCodec for SignedLedgerUpdate {
    fn write_to<W: Write>(&self, w: &mut W) -> Result<(), CodecError> {
        write_bytes(w, &self.message)?;
        write_u16(w, self.message_type)?;
        write_pubkey(w, &self.operator_id)?;
        write_32(w, &self.ledger_id)?;
        write_u64(w, self.sequence_number)?;
        write_32(w, &self.previous_hash)?;
        write_u32(w, self.block_height)?;
        write_32(w, &self.block_hash)?;
        write_64(w, &self.cosign_signature)?;
        write_64(w, &self.operator_signature)?;
        write_option(w, &self.cosigner_pubkey, |w, pk| write_pubkey(w, pk))?;
        write_option(w, &self.member_ledger_hash, |w, h| write_32(w, h))?;
        Ok(())
    }

    fn read_from<R: Read>(r: &mut R) -> Result<Self, CodecError> {
        let message = read_bytes(r)?;
        let message_type = read_u16(r)?;
        let operator_id = read_pubkey(r)?;
        let ledger_id = read_32(r)?;
        let sequence_number = read_u64(r)?;
        let previous_hash = read_32(r)?;
        let block_height = read_u32(r)?;
        let block_hash = read_32(r)?;
        let cosign_signature = read_64(r)?;
        let operator_signature = read_64(r)?;
        // Optional fields (backward compatible - not present in old format)
        let cosigner_pubkey = read_option(r, read_pubkey).unwrap_or(None);
        let member_ledger_hash = read_option(r, |r| Ok(read_32(r)?)).unwrap_or(None);
        let mut update = Self {
            message,
            message_type,
            operator_id,
            ledger_id,
            sequence_number,
            previous_hash,
            current_hash: [0u8; 32],
            block_height,
            block_hash,
            cosign_signature,
            operator_signature,
            cosigner_pubkey,
            member_ledger_hash,
        };
        update.current_hash = update.compute_hash();
        Ok(update)
    }
}

// Implement write_payload and read_payload for DepositsMessage
impl DepositsMessage {
    fn write_payload<W: Write>(&self, w: &mut W) -> Result<(), CodecError> {
        match self {
            Self::LedgerUpdate(m) => {
                write_pubkey(w, &m.operator_id)?;
                write_string(w, &m.reserves_id)?;
                m.operation.write_to(w)?;
                write_u64(w, m.sequence_number)?;
                write_32(w, &m.previous_hash)?;
                write_32(w, &m.current_hash)?;
                write_64(w, &m.operator_signature)?;
            }
            Self::LedgerUpdateResponse(m) => {
                write_pubkey(w, &m.operator_id)?;
                write_string(w, &m.reserves_id)?;
                write_32(w, &m.request_hash)?;
                write_bool(w, m.accepted)?;
                write_option(w, &m.error, |w, s| write_string(w, s))?;
                write_option(w, &m.cosign_signature, |w, s| write_64(w, s))?;
                write_u64(w, m.confirmed_sequence)?;
                write_32(w, &m.confirmed_hash)?;
            }
            Self::Handshake(m) => {
                write_u16(w, m.protocol_version)?;
                write_u16(w, m.min_protocol_version)?;
                write_u32(w, m.features)?;
                write_pubkey(w, &m.operator_id)?;
                write_string(w, &m.reserves_id)?;
                write_32(w, &m.funding_txid)?;
                write_u16(w, m.funding_vout)?;
                write_u32(w, 0)?; // reserved (was collateral_enforcement_block)
            }
            Self::HandshakeResponse(m) => {
                write_32(w, &m.request_hash)?;
                write_u16(w, m.protocol_version)?;
                write_bool(w, m.accepted)?;
                write_option(w, &m.error, |w, s| write_string(w, s))?;
                write_string(w, &m.reserves_id)?;
            }
            Self::Sync(m) => {
                write_32(w, &m.ledger_id)?;
                write_u64(w, m.last_known_sequence)?;
                write_32(w, &m.last_known_hash)?;
            }
            Self::SyncResponse(m) => {
                write_32(w, &m.ledger_id)?;
                write_32(w, &m.request_hash)?;
                write_vec(w, &m.updates, |w, u| u.write_to(w))?;
                write_u64(w, m.current_sequence)?;
                write_32(w, &m.current_hash)?;
            }
            Self::Recovery(m) => m.write_to(w)?,
            Self::RecoveryResponse(m) => m.write_to(w)?,
            Self::Coordination(m) => m.write_to(w)?,
            Self::CoordinationResponse(m) => m.write_to(w)?,
            Self::ReservesAddOutput(m) => {
                write_u64(w, m.initial_amount)?;
                write_pubkey(w, &m.spend_to)?;
                write_string(w, &m.reserves_id)?;
                write_u16(w, m.quorum_members.len() as u16)?;
                for pk in &m.quorum_members {
                    write_pubkey(w, pk)?;
                }
            }
            Self::ReservesRemoveOutput(m) => {
                write_string(w, &m.reserves_id)?;
                write_bool(w, m.remove_all)?;
            }
        }
        Ok(())
    }

    fn read_payload<R: Read>(message_type: u16, r: &mut R) -> Result<Self, CodecError> {
        match message_type {
            LEDGER_UPDATE => Ok(Self::LedgerUpdate(LedgerUpdateMsg {
                operator_id: read_pubkey(r)?,
                reserves_id: read_string(r)?,
                operation: LedgerOperation::read_from(r)?,
                sequence_number: read_u64(r)?,
                previous_hash: read_32(r)?,
                current_hash: read_32(r)?,
                operator_signature: read_64(r)?,
            })),
            LEDGER_UPDATE_RESPONSE => Ok(Self::LedgerUpdateResponse(LedgerUpdateResponseMsg {
                operator_id: read_pubkey(r)?,
                reserves_id: read_string(r)?,
                request_hash: read_32(r)?,
                accepted: read_bool(r)?,
                error: read_option(r, read_string)?,
                cosign_signature: read_option(r, read_64)?,
                confirmed_sequence: read_u64(r)?,
                confirmed_hash: read_32(r)?,
            })),
            HANDSHAKE => {
                let protocol_version = read_u16(r)?;
                let min_protocol_version = read_u16(r)?;
                let features = read_u32(r)?;
                let operator_id = read_pubkey(r)?;
                let reserves_id = read_string(r)?;
                let funding_txid = read_32(r)?;
                let funding_vout = read_u16(r)?;
                let _reserved = read_u32(r)?; // was collateral_enforcement_block
                Ok(Self::Handshake(HandshakeMsg {
                    protocol_version, min_protocol_version, features,
                    operator_id, reserves_id, funding_txid, funding_vout,
                }))
            }
            HANDSHAKE_RESPONSE => Ok(Self::HandshakeResponse(HandshakeResponseMsg {
                request_hash: read_32(r)?,
                protocol_version: read_u16(r)?,
                accepted: read_bool(r)?,
                error: read_option(r, read_string)?,
                reserves_id: read_string(r)?,
            })),
            SYNC => Ok(Self::Sync(SyncMsg {
                ledger_id: read_32(r)?,
                last_known_sequence: read_u64(r)?,
                last_known_hash: read_32(r)?,
            })),
            SYNC_RESPONSE => Ok(Self::SyncResponse(SyncResponseMsg {
                ledger_id: read_32(r)?,
                request_hash: read_32(r)?,
                updates: read_vec(r, SignedLedgerUpdate::read_from)?,
                current_sequence: read_u64(r)?,
                current_hash: read_32(r)?,
            })),
            RECOVERY => Ok(Self::Recovery(RecoveryMsg::read_from(r)?)),
            RECOVERY_RESPONSE => Ok(Self::RecoveryResponse(RecoveryResponseMsg::read_from(r)?)),
            COORDINATION => Ok(Self::Coordination(CoordinationMsg::read_from(r)?)),
            COORDINATION_RESPONSE => Ok(Self::CoordinationResponse(CoordinationResponseMsg::read_from(r)?)),
            RESERVES_ADD_OUTPUT => {
                let initial_amount = read_u64(r)?;
                let spend_to = read_pubkey(r)?;
                let reserves_id = read_string(r)?;
                let count = read_u16(r)? as usize;
                let mut quorum_members = Vec::with_capacity(count);
                for _ in 0..count {
                    quorum_members.push(read_pubkey(r)?);
                }
                Ok(Self::ReservesAddOutput(crate::wire_messages::ReservesAddOutputMsg {
                    initial_amount,
                    spend_to,
                    reserves_id,
                    quorum_members,
                }))
            }
            RESERVES_REMOVE_OUTPUT => {
                let reserves_id = read_string(r)?;
                let remove_all = read_bool(r)?;
                Ok(Self::ReservesRemoveOutput(crate::wire_messages::ReservesRemoveOutputMsg {
                    reserves_id,
                    remove_all,
                }))
            }
            _ => Err(CodecError::InvalidMessageType(message_type)),
        }
    }
}

// RecoveryMsg codec
impl BinaryCodec for RecoveryMsg {
    fn write_to<W: Write>(&self, w: &mut W) -> Result<(), CodecError> {
        match self {
            Self::Vote { operator, partner, voter, is_conforming, validated_hash, validated_sequence, substitute_nomination, discovered_violation, signature } => {
                write_u8(w, 0)?;
                write_pubkey(w, operator)?;
                write_pubkey(w, partner)?;
                write_pubkey(w, voter)?;
                write_bool(w, *is_conforming)?;
                write_32(w, validated_hash)?;
                write_u64(w, *validated_sequence)?;
                write_option(w, substitute_nomination, |w, pk| write_pubkey(w, pk))?;
                write_bool(w, *discovered_violation)?;
                write_64(w, signature)?;
            }
            Self::ClaimRequest { operator, partner, claimant, tier_index, unsigned_tx, sighash, destination_script, block_height } => {
                write_u8(w, 1)?;
                write_pubkey(w, operator)?;
                write_pubkey(w, partner)?;
                write_pubkey(w, claimant)?;
                write_u8(w, *tier_index)?;
                write_bytes(w, unsigned_tx)?;
                write_32(w, sighash)?;
                write_bytes(w, destination_script)?;
                write_u32(w, *block_height)?;
            }
            Self::ClaimComplete { operator, partner, new_operator, claim_txid, confirmation_block, reason_code } => {
                write_u8(w, 2)?;
                write_pubkey(w, operator)?;
                write_pubkey(w, partner)?;
                write_pubkey(w, new_operator)?;
                write_32(w, claim_txid)?;
                write_u32(w, *confirmation_block)?;
                write_u8(w, *reason_code)?;
            }
            Self::UncreditedPayment { operator, partner, payment_hash, preimage, deposit_pubkey, amount_msat, invoice_cosignature, settlement_sequence, settlement_ledger_hash, settlement_block_height, accuser_signature } => {
                write_u8(w, 3)?;
                write_pubkey(w, operator)?;
                write_pubkey(w, partner)?;
                write_32(w, payment_hash)?;
                write_32(w, preimage)?;
                write_pubkey(w, deposit_pubkey)?;
                write_u64(w, *amount_msat)?;
                write_64(w, invoice_cosignature)?;
                write_u64(w, *settlement_sequence)?;
                write_32(w, settlement_ledger_hash)?;
                write_u32(w, *settlement_block_height)?;
                write_64(w, accuser_signature)?;
            }
        }
        Ok(())
    }

    fn read_from<R: Read>(r: &mut R) -> Result<Self, CodecError> {
        match read_u8(r)? {
            0 => Ok(Self::Vote {
                operator: read_pubkey(r)?,
                partner: read_pubkey(r)?,
                voter: read_pubkey(r)?,
                is_conforming: read_bool(r)?,
                validated_hash: read_32(r)?,
                validated_sequence: read_u64(r)?,
                substitute_nomination: read_option(r, read_pubkey)?,
                discovered_violation: read_bool(r)?,
                signature: read_64(r)?,
            }),
            1 => Ok(Self::ClaimRequest {
                operator: read_pubkey(r)?,
                partner: read_pubkey(r)?,
                claimant: read_pubkey(r)?,
                tier_index: read_u8(r)?,
                unsigned_tx: read_bytes(r)?,
                sighash: read_32(r)?,
                destination_script: read_bytes(r)?,
                block_height: read_u32(r)?,
            }),
            2 => Ok(Self::ClaimComplete {
                operator: read_pubkey(r)?,
                partner: read_pubkey(r)?,
                new_operator: read_pubkey(r)?,
                claim_txid: read_32(r)?,
                confirmation_block: read_u32(r)?,
                reason_code: read_u8(r)?,
            }),
            3 => Ok(Self::UncreditedPayment {
                operator: read_pubkey(r)?,
                partner: read_pubkey(r)?,
                payment_hash: read_32(r)?,
                preimage: read_32(r)?,
                deposit_pubkey: read_pubkey(r)?,
                amount_msat: read_u64(r)?,
                invoice_cosignature: read_64(r)?,
                settlement_sequence: read_u64(r)?,
                settlement_ledger_hash: read_32(r)?,
                settlement_block_height: read_u32(r)?,
                accuser_signature: read_64(r)?,
            }),
            d => Err(CodecError::InvalidDiscriminant(d)),
        }
    }
}

// RecoveryResponseMsg codec
impl BinaryCodec for RecoveryResponseMsg {
    fn write_to<W: Write>(&self, w: &mut W) -> Result<(), CodecError> {
        match self {
            Self::VoteAck { request_hash, recorded } => {
                write_u8(w, 0)?;
                write_32(w, request_hash)?;
                write_bool(w, *recorded)?;
            }
            Self::ClaimSignature { request_hash, signer, sighash, signature } => {
                write_u8(w, 1)?;
                write_32(w, request_hash)?;
                write_pubkey(w, signer)?;
                write_32(w, sighash)?;
                write_64(w, signature)?;
            }
            Self::ClaimAck { request_hash } => {
                write_u8(w, 2)?;
                write_32(w, request_hash)?;
            }
            Self::UncreditedPaymentAck { request_hash } => {
                write_u8(w, 3)?;
                write_32(w, request_hash)?;
            }
        }
        Ok(())
    }

    fn read_from<R: Read>(r: &mut R) -> Result<Self, CodecError> {
        match read_u8(r)? {
            0 => Ok(Self::VoteAck {
                request_hash: read_32(r)?,
                recorded: read_bool(r)?,
            }),
            1 => Ok(Self::ClaimSignature {
                request_hash: read_32(r)?,
                signer: read_pubkey(r)?,
                sighash: read_32(r)?,
                signature: read_64(r)?,
            }),
            2 => Ok(Self::ClaimAck { request_hash: read_32(r)? }),
            3 => Ok(Self::UncreditedPaymentAck { request_hash: read_32(r)? }),
            d => Err(CodecError::InvalidDiscriminant(d)),
        }
    }
}

// CoordinationMsg codec
impl BinaryCodec for CoordinationMsg {
    fn write_to<W: Write>(&self, w: &mut W) -> Result<(), CodecError> {
        match self {
            Self::CosignInvoice { operator_id, reserves_id, amount, payment_hash, expires, assigned_deposit, invoice_id, bolt11_invoice } => {
                write_u8(w, 0)?;
                write_pubkey(w, operator_id)?;
                write_string(w, reserves_id)?;
                write_u64(w, *amount)?;
                write_32(w, payment_hash)?;
                write_u64(w, *expires)?;
                write_pubkey(w, assigned_deposit)?;
                write_string(w, invoice_id)?;
                write_string(w, bolt11_invoice)?;
            }
            Self::CollateralConsentRequest { operator_id, reserves_id, operator_signature } => {
                write_u8(w, 1)?;
                write_pubkey(w, operator_id)?;
                write_string(w, reserves_id)?;
                write_64(w, operator_signature)?;
            }
            Self::QuorumJoinRequest { requester_pubkey, operator_id, reserves_id, protocol_version, timestamp, signature } => {
                write_u8(w, 2)?;
                write_pubkey(w, requester_pubkey)?;
                write_pubkey(w, operator_id)?;
                write_string(w, reserves_id)?;
                write_u16(w, *protocol_version)?;
                write_u64(w, *timestamp)?;
                write_64(w, signature)?;
            }
            Self::QuorumVoteRequest { vote_round_id, operator_id, reserves_id, sequence_number, state_hash, claimed_reserves, collateral_amounts, reserves_outpoint, destination_script, fee_rate_sat_vbyte, timestamp } => {
                write_u8(w, 3)?;
                write_32(w, vote_round_id)?;
                write_pubkey(w, operator_id)?;
                write_string(w, reserves_id)?;
                write_u64(w, *sequence_number)?;
                write_32(w, state_hash)?;
                write_u64(w, *claimed_reserves)?;
                write_vec(w, collateral_amounts, |w, a| write_u64(w, *a))?;
                write_bytes(w, reserves_outpoint)?;
                write_bytes(w, destination_script)?;
                write_u64(w, *fee_rate_sat_vbyte)?;
                write_u64(w, *timestamp)?;
            }
            Self::QuorumVote { vote_round_id, voter_pubkey, vote, voter_sequence, voter_state_hash, evidence, signature, spend_signature } => {
                write_u8(w, 4)?;
                write_32(w, vote_round_id)?;
                write_pubkey(w, voter_pubkey)?;
                write_bool(w, *vote)?;
                write_u64(w, *voter_sequence)?;
                write_32(w, voter_state_hash)?;
                write_option(w, evidence, |w, e| write_bytes(w, e))?;
                write_64(w, signature)?;
                write_option(w, spend_signature, |w, s| write_64(w, s))?;
            }
            Self::UpdateReserves { channel_id, reserves_sats, script_pubkey, ledger_hash, remote_ledger_hash } => {
                write_u8(w, 5)?;
                write_32(w, channel_id)?;
                write_u64(w, *reserves_sats)?;
                write_bytes(w, script_pubkey)?;
                write_32(w, ledger_hash)?;
                write_32(w, remote_ledger_hash)?;
            }
        }
        Ok(())
    }

    fn read_from<R: Read>(r: &mut R) -> Result<Self, CodecError> {
        match read_u8(r)? {
            0 => Ok(Self::CosignInvoice {
                operator_id: read_pubkey(r)?,
                reserves_id: read_string(r)?,
                amount: read_u64(r)?,
                payment_hash: read_32(r)?,
                expires: read_u64(r)?,
                assigned_deposit: read_pubkey(r)?,
                invoice_id: read_string(r)?,
                bolt11_invoice: read_string(r)?,
            }),
            1 => Ok(Self::CollateralConsentRequest {
                operator_id: read_pubkey(r)?,
                reserves_id: read_string(r)?,
                operator_signature: read_64(r)?,
            }),
            2 => Ok(Self::QuorumJoinRequest {
                requester_pubkey: read_pubkey(r)?,
                operator_id: read_pubkey(r)?,
                reserves_id: read_string(r)?,
                protocol_version: read_u16(r)?,
                timestamp: read_u64(r)?,
                signature: read_64(r)?,
            }),
            3 => Ok(Self::QuorumVoteRequest {
                vote_round_id: read_32(r)?,
                operator_id: read_pubkey(r)?,
                reserves_id: read_string(r)?,
                sequence_number: read_u64(r)?,
                state_hash: read_32(r)?,
                claimed_reserves: read_u64(r)?,
                collateral_amounts: read_vec(r, read_u64)?,
                reserves_outpoint: read_bytes(r)?,
                destination_script: read_bytes(r)?,
                fee_rate_sat_vbyte: read_u64(r)?,
                timestamp: read_u64(r)?,
            }),
            4 => Ok(Self::QuorumVote {
                vote_round_id: read_32(r)?,
                voter_pubkey: read_pubkey(r)?,
                vote: read_bool(r)?,
                voter_sequence: read_u64(r)?,
                voter_state_hash: read_32(r)?,
                evidence: read_option(r, read_bytes)?,
                signature: read_64(r)?,
                spend_signature: read_option(r, read_64)?,
            }),
            5 => Ok(Self::UpdateReserves {
                channel_id: read_32(r)?,
                reserves_sats: read_u64(r)?,
                script_pubkey: read_bytes(r)?,
                ledger_hash: read_32(r)?,
                remote_ledger_hash: read_32(r)?,
            }),
            d => Err(CodecError::InvalidDiscriminant(d)),
        }
    }
}

// CoordinationResponseMsg codec
impl BinaryCodec for CoordinationResponseMsg {
    fn write_to<W: Write>(&self, w: &mut W) -> Result<(), CodecError> {
        match self {
            Self::InvoiceCosigned { request_hash, cosignature } => {
                write_u8(w, 0)?;
                write_32(w, request_hash)?;
                write_64(w, cosignature)?;
            }
            Self::CollateralConsentResponse { request_hash, operator_id, reserves_id, consent_granted, quorum_member_signature } => {
                write_u8(w, 1)?;
                write_32(w, request_hash)?;
                write_pubkey(w, operator_id)?;
                write_string(w, reserves_id)?;
                write_bool(w, *consent_granted)?;
                write_64(w, quorum_member_signature)?;
            }
            Self::QuorumJoinResponse { request_hash, accepted, members, threshold, last_sequence, current_hash, rejection_reason } => {
                write_u8(w, 2)?;
                write_32(w, request_hash)?;
                write_bool(w, *accepted)?;
                write_vec(w, members, |w, pk| write_pubkey(w, pk))?;
                write_u16(w, *threshold)?;
                write_u64(w, *last_sequence)?;
                write_32(w, current_hash)?;
                write_option(w, rejection_reason, |w, s| write_string(w, s))?;
            }
            Self::QuorumStateSync { request_hash, operator_id, reserves_id, updates, start_sequence, is_final } => {
                write_u8(w, 3)?;
                write_32(w, request_hash)?;
                write_pubkey(w, operator_id)?;
                write_string(w, reserves_id)?;
                write_vec(w, updates, |w, u| u.write_to(w))?;
                write_u64(w, *start_sequence)?;
                write_bool(w, *is_final)?;
            }
            Self::QuorumMembershipChange { request_hash, operator_id, reserves_id, change_type, member_pubkey, new_members, new_threshold, timestamp, operator_signature } => {
                write_u8(w, 4)?;
                write_32(w, request_hash)?;
                write_pubkey(w, operator_id)?;
                write_string(w, reserves_id)?;
                write_string(w, change_type)?;
                write_pubkey(w, member_pubkey)?;
                write_vec(w, new_members, |w, pk| write_pubkey(w, pk))?;
                write_u16(w, *new_threshold)?;
                write_u64(w, *timestamp)?;
                write_64(w, operator_signature)?;
            }
            Self::AcceptReserves { channel_id } => {
                write_u8(w, 5)?;
                write_32(w, channel_id)?;
            }
        }
        Ok(())
    }

    fn read_from<R: Read>(r: &mut R) -> Result<Self, CodecError> {
        match read_u8(r)? {
            0 => Ok(Self::InvoiceCosigned {
                request_hash: read_32(r)?,
                cosignature: read_64(r)?,
            }),
            1 => Ok(Self::CollateralConsentResponse {
                request_hash: read_32(r)?,
                operator_id: read_pubkey(r)?,
                reserves_id: read_string(r)?,
                consent_granted: read_bool(r)?,
                quorum_member_signature: read_64(r)?,
            }),
            2 => Ok(Self::QuorumJoinResponse {
                request_hash: read_32(r)?,
                accepted: read_bool(r)?,
                members: read_vec(r, read_pubkey)?,
                threshold: read_u16(r)?,
                last_sequence: read_u64(r)?,
                current_hash: read_32(r)?,
                rejection_reason: read_option(r, read_string)?,
            }),
            3 => Ok(Self::QuorumStateSync {
                request_hash: read_32(r)?,
                operator_id: read_pubkey(r)?,
                reserves_id: read_string(r)?,
                updates: read_vec(r, SignedLedgerUpdate::read_from)?,
                start_sequence: read_u64(r)?,
                is_final: read_bool(r)?,
            }),
            4 => Ok(Self::QuorumMembershipChange {
                request_hash: read_32(r)?,
                operator_id: read_pubkey(r)?,
                reserves_id: read_string(r)?,
                change_type: read_string(r)?,
                member_pubkey: read_pubkey(r)?,
                new_members: read_vec(r, read_pubkey)?,
                new_threshold: read_u16(r)?,
                timestamp: read_u64(r)?,
                operator_signature: read_64(r)?,
            }),
            5 => Ok(Self::AcceptReserves {
                channel_id: read_32(r)?,
            }),
            d => Err(CodecError::InvalidDiscriminant(d)),
        }
    }
}

// ============================================================================
// TLV Encoding for V2 Messages
// ============================================================================

use crate::tlv::{TlvEncode, TlvDecode, TlvBuilder, TlvReader, TlvResult, TlvError};

/// TLV field type constants for LedgerOperation
mod ledger_op_tlv {
    pub const DISCRIMINANT: u64 = 0;
    pub const AMOUNT: u64 = 2;
    pub const SPEND_TO: u64 = 4;
    pub const QUORUM_MEMBERS: u64 = 6;
    pub const FEES: u64 = 12;
    pub const PAYMENT_HASH: u64 = 14;
    pub const INVOICE: u64 = 16;
    pub const COSIGNER_SIG: u64 = 18;
    pub const NEW_FEES: u64 = 20;
    pub const DEPOSIT_PUBKEY: u64 = 24;
    pub const INVOICE_ID: u64 = 26;
    pub const SEQUENCE_NUMBER: u64 = 28;
    pub const PAYMENT_ID: u64 = 30;
    pub const PREIMAGE: u64 = 34;
    pub const BLOCK_HEIGHT: u64 = 36;
    pub const COLLATERAL_OPERATOR: u64 = 38;
    pub const SIGNATURE: u64 = 40;
    pub const LEDGER_HASH: u64 = 42;
    pub const QUORUM_MEMBER: u64 = 44;
    pub const QUORUM_MEMBER_SIG: u64 = 46;
    pub const OPERATOR_SIG: u64 = 48;
    // LedgerOpen fields
    pub const OPERATOR_ID: u64 = 56;
    pub const RESERVES_ID: u64 = 58;
    pub const RESERVES_AMOUNT: u64 = 62;
    // 64 was collateral_enforcement_block (removed)
    pub const GENESIS_BLOCK: u64 = 96;
    // Onchain operation fields
    pub const TXID: u64 = 66;
    pub const VOUT: u64 = 68;
    pub const DESTINATION_ADDRESS: u64 = 70;
    pub const WITHDRAWAL_ID: u64 = 72;
    pub const FUNDING_ADDRESS: u64 = 74;
    // CollateralLock fields
    pub const LOCK_UNTIL_BLOCK: u64 = 76;
    // QuorumJoin fields
    pub const OUR_SIGNATURE: u64 = 80;
    pub const MEMBERSHIP_EXPIRES: u64 = 82;
    // QuorumBegin fields
    pub const SPENDING_TXID: u64 = 90;
    pub const NEW_OUTPOINT_TXID: u64 = 84;
    pub const NEW_OUTPOINT_VOUT: u64 = 92;
    pub const QUORUM_EXPIRY: u64 = 86;
    pub const TOTAL_COLLATERAL: u64 = 88;
    // Dispute fields
    pub const REASON: u64 = 100;
    pub const LAST_VALID_SEQUENCE: u64 = 102;
    pub const ENTROPY_BLOCK_HEIGHT: u64 = 116;
    pub const ENTROPY_BLOCK_HASH: u64 = 106;
    pub const NEW_CUSTODIAN: u64 = 108;
    pub const ARMED_BLOCK: u64 = 118;
    pub const SPEND_TXID: u64 = 110;
    pub const NEW_RESERVES_ADDRESS: u64 = 120;
    // DisputeArmed lottery fields
    pub const COMMITMENT_HASH: u64 = 112;
    pub const TARGET_RESERVES: u64 = 122;
    // Quorum/Collateral ledger binding fields
    pub const MEMBER_LEDGER_ID: u64 = 114;
    pub const COLLATERAL_LEDGER_ID: u64 = 124;
    // Descriptor-based deposit fields
    pub const DEPOSIT_ID: u64 = 200;      // 16-byte deposit identifier
    pub const DESCRIPTOR: u64 = 202;       // Variable-length string
    pub const WITNESS: u64 = 204;          // Nested TLV with stack elements
    pub const WITNESS_ELEMENT: u64 = 206;  // Single stack element (bytes)
    pub const NEW_DESCRIPTOR: u64 = 208;   // New descriptor for key rotation

    // Transfer operation fields
    pub const NONCE: u64 = 210;
    pub const SOURCE_DEPOSIT_ID: u64 = 212;
    pub const DESTINATION_DEPOSIT_ID: u64 = 214;
    pub const COMPLETION_SCRIPT: u64 = 216;
    pub const TIMEOUT_HEIGHT: u64 = 218;
    pub const TRANSFER_ID: u64 = 220;
    pub const BLOCK_HASH: u64 = 222;
    pub const SCRIPT_WITNESS: u64 = 224;
    pub const TRANSFER_FEES: u64 = 226;
    pub const FAIL_REASON: u64 = 228;   // u8 (0 = timeout)
    pub const IS_COLLATERAL: u64 = 230; // u8 (0 or 1)
    pub const RECEIVE_REQUIRES_SIG: u64 = 232; // u8 (0 or 1)
    // Quorum member fee limits (on QuorumAddMember)
    pub const MIN_FEE_BPS: u64 = 234;     // u16
    pub const MIN_FEE_FIXED: u64 = 236;   // u64 (msats/year)
    pub const MAX_FEE_PERIOD: u64 = 238;   // u32 (blocks)
    pub const FEE_CHANGE_AFTER: u64 = 244;  // u32 (blocks after open)
    pub const FEE_CHANGE_NOTICE: u64 = 246; // u32 (notice blocks)
    pub const FEE_CHANGE_LIMIT_BPS: u64 = 248; // u16 (default 1000 = 10%)
    pub const EFFECTIVE_BLOCK: u64 = 250;   // u32 (on FeeChange)
    pub const COLLATERAL_LOCK_AMOUNT: u64 = 240; // u64 (msats)
    pub const COLLATERAL_LOCK_UNTIL: u64 = 242; // u32 (block height)

    // Per-quorum timing parameters (on QuorumAddMember)
    pub const DISPUTE_RESPONSE_BLOCKS: u64 = 252; // u32
    pub const DISPUTE_ARM_BLOCKS: u64 = 254;       // u32
    pub const SERVICE_RESPONSE_BLOCKS: u64 = 256;  // u32
    pub const MAX_TRANSFER_TIMEOUT_BLOCKS: u64 = 258; // u32
    pub const MAX_DESCRIPTOR_BYTES: u64 = 262;     // u32

    // Delivery operation fields
    pub const REQUEST_HASH: u64 = 270;       // [u8; 32]
    pub const TARGET_LEDGER_ID: u64 = 272;   // [u8; 32]
    pub const TARGET_OPERATOR: u64 = 274;    // pubkey (33 bytes)
}

impl TlvEncode for LedgerOperation {
    fn tlv_encode(&self) -> Vec<u8> {
        use ledger_op_tlv::*;

        let mut builder = TlvBuilder::new().u8_field(DISCRIMINANT, self.discriminant());

        match self {
            Self::LedgerOpen { operator_id, reserves_id, genesis_block, reserves_amount } => {
                builder = builder
                    .pubkey_field(OPERATOR_ID, operator_id)
                    .string_field(RESERVES_ID, reserves_id)
                    .u32_field(GENESIS_BLOCK, *genesis_block)
                    .u64_field(RESERVES_AMOUNT, *reserves_amount);
            }
            Self::QuorumBegin { reserves_id, spending_txid, new_outpoint_txid, new_outpoint_vout, amount, quorum_expiry, ledger_hash, quorum_members, total_collateral } => {
                let mut members_bytes = Vec::new();
                for pk in quorum_members {
                    members_bytes.extend_from_slice(&pk.serialize());
                }
                builder = builder
                    .string_field(RESERVES_ID, reserves_id)
                    .bytes_field(SPENDING_TXID, spending_txid)
                    .bytes_field(NEW_OUTPOINT_TXID, new_outpoint_txid)
                    .u32_field(NEW_OUTPOINT_VOUT, *new_outpoint_vout)
                    .u64_field(AMOUNT, *amount)
                    .u32_field(QUORUM_EXPIRY, *quorum_expiry)
                    .bytes_field(LEDGER_HASH, ledger_hash)
                    .bytes_field(QUORUM_MEMBERS, &members_bytes)
                    .u64_field(TOTAL_COLLATERAL, *total_collateral);
            }
            Self::DepositOpen { deposit_id, descriptor, fees, transfer_fees, payment_hash, invoice, cosigner_guarantee_signature, is_collateral, receive_requires_sig, fee_change_after_blocks, fee_change_notice_blocks, fee_change_limit_bps } => {
                builder = builder
                    .deposit_id_field(DEPOSIT_ID, deposit_id)
                    .string_field(DESCRIPTOR, descriptor);
                if let Some(f) = fees {
                    builder = builder.nested(FEES, f);
                }
                if let Some(tf) = transfer_fees {
                    builder = builder.nested(TRANSFER_FEES, tf);
                }
                if let Some(h) = payment_hash {
                    builder = builder.bytes_field(PAYMENT_HASH, h);
                }
                if let Some(inv) = invoice {
                    builder = builder.string_field(INVOICE, inv);
                }
                if let Some(sig) = cosigner_guarantee_signature {
                    builder = builder.bytes_field(COSIGNER_SIG, sig);
                }
                if *is_collateral {
                    builder = builder.u8_field(IS_COLLATERAL, 1);
                }
                if *receive_requires_sig {
                    builder = builder.u8_field(RECEIVE_REQUIRES_SIG, 1);
                }
                if let Some(v) = fee_change_after_blocks {
                    builder = builder.u32_field(FEE_CHANGE_AFTER, *v);
                }
                if let Some(v) = fee_change_notice_blocks {
                    builder = builder.u32_field(FEE_CHANGE_NOTICE, *v);
                }
                if let Some(v) = fee_change_limit_bps {
                    builder = builder.u16_field(FEE_CHANGE_LIMIT_BPS, *v);
                }
            }
            Self::DepositClose { deposit_id } => {
                builder = builder.deposit_id_field(DEPOSIT_ID, deposit_id);
            }
            Self::FeeChange { deposit_id, new_fees, effective_block } => {
                builder = builder
                    .deposit_id_field(DEPOSIT_ID, deposit_id)
                    .nested(NEW_FEES, new_fees)
                    .u32_field(EFFECTIVE_BLOCK, *effective_block);
            }
            Self::DepositKeyRotate { deposit_id, new_descriptor, witness } => {
                builder = builder
                    .deposit_id_field(DEPOSIT_ID, deposit_id)
                    .string_field(NEW_DESCRIPTOR, new_descriptor)
                    .witness_field(WITNESS, witness);
            }
            Self::InvoiceCredit { payment_hash, deposit_id, amount, invoice_id, sequence_number } => {
                builder = builder
                    .bytes_field(PAYMENT_HASH, payment_hash)
                    .deposit_id_field(DEPOSIT_ID, deposit_id)
                    .u64_field(AMOUNT, *amount)
                    .string_field(INVOICE_ID, invoice_id)
                    .u64_field(SEQUENCE_NUMBER, *sequence_number);
            }
            Self::InvoiceLock { deposit_id, amount, payment_id, sequence_number, witness } => {
                builder = builder
                    .deposit_id_field(DEPOSIT_ID, deposit_id)
                    .u64_field(AMOUNT, *amount)
                    .bytes_field(PAYMENT_ID, payment_id)
                    .u64_field(SEQUENCE_NUMBER, *sequence_number)
                    .witness_field(WITNESS, witness);
            }
            Self::InvoiceFail { deposit_id, amount, payment_id, sequence_number } => {
                builder = builder
                    .deposit_id_field(DEPOSIT_ID, deposit_id)
                    .u64_field(AMOUNT, *amount)
                    .bytes_field(PAYMENT_ID, payment_id)
                    .u64_field(SEQUENCE_NUMBER, *sequence_number);
            }
            Self::InvoiceFulfill { deposit_id, amount, payment_id, sequence_number, witness, preimage } => {
                builder = builder
                    .deposit_id_field(DEPOSIT_ID, deposit_id)
                    .u64_field(AMOUNT, *amount)
                    .bytes_field(PAYMENT_ID, payment_id)
                    .u64_field(SEQUENCE_NUMBER, *sequence_number)
                    .witness_field(WITNESS, witness)
                    .bytes_field(PREIMAGE, preimage);
            }
            Self::OnchainCredit { txid, vout, deposit_id, amount, funding_address } => {
                builder = builder
                    .bytes_field(TXID, txid)
                    .u32_field(VOUT, *vout)
                    .deposit_id_field(DEPOSIT_ID, deposit_id)
                    .u64_field(AMOUNT, *amount)
                    .string_field(FUNDING_ADDRESS, funding_address);
            }
            Self::OnchainLock { deposit_id, amount, fee_sats, destination_address, withdrawal_id, witness } => {
                builder = builder
                    .deposit_id_field(DEPOSIT_ID, deposit_id)
                    .u64_field(AMOUNT, *amount)
                    .u64_field(FEES, *fee_sats)
                    .string_field(DESTINATION_ADDRESS, destination_address)
                    .bytes_field(WITHDRAWAL_ID, withdrawal_id)
                    .witness_field(WITNESS, witness);
            }
            Self::OnchainFail { deposit_id, withdrawal_id } => {
                builder = builder
                    .deposit_id_field(DEPOSIT_ID, deposit_id)
                    .bytes_field(WITHDRAWAL_ID, withdrawal_id);
            }
            Self::OnchainFulfill { deposit_id, withdrawal_id, amount, txid, destination_address } => {
                builder = builder
                    .deposit_id_field(DEPOSIT_ID, deposit_id)
                    .bytes_field(WITHDRAWAL_ID, withdrawal_id)
                    .u64_field(AMOUNT, *amount)
                    .bytes_field(TXID, txid)
                    .string_field(DESTINATION_ADDRESS, destination_address);
            }
            Self::TransferLock { nonce, source_deposit_id, destination_deposit_id, amount, fee, completion_script, timeout_height, transfer_id, witness } => {
                builder = builder
                    .bytes_field(NONCE, nonce)
                    .deposit_id_field(SOURCE_DEPOSIT_ID, source_deposit_id)
                    .deposit_id_field(DESTINATION_DEPOSIT_ID, destination_deposit_id)
                    .u64_field(AMOUNT, *amount)
                    .u64_field(FEES, *fee)
                    .string_field(COMPLETION_SCRIPT, completion_script)
                    .u32_field(TIMEOUT_HEIGHT, *timeout_height)
                    .bytes_field(TRANSFER_ID, transfer_id)
                    .witness_field(WITNESS, witness);
            }
            Self::TransferComplete { transfer_id, script_witness } => {
                builder = builder
                    .bytes_field(TRANSFER_ID, transfer_id)
                    .witness_field(SCRIPT_WITNESS, script_witness);
            }
            Self::TransferFail { transfer_id, block_hash, reason } => {
                builder = builder
                    .bytes_field(TRANSFER_ID, transfer_id)
                    .bytes_field(BLOCK_HASH, block_hash)
                    .u8_field(FAIL_REASON, *reason);
            }
            Self::CollateralAttestation { collateral_operator, quorum_member, collateral_ledger_id, amount, block_height, lock_until_block, signature, ledger_hash } => {
                builder = builder
                    .pubkey_field(COLLATERAL_OPERATOR, collateral_operator)
                    .pubkey_field(QUORUM_MEMBER, quorum_member)
                    .string_field(COLLATERAL_LEDGER_ID, collateral_ledger_id)
                    .u64_field(AMOUNT, *amount)
                    .u32_field(BLOCK_HEIGHT, *block_height)
                    .u32_field(LOCK_UNTIL_BLOCK, *lock_until_block)
                    .bytes_field(SIGNATURE, signature)
                    .bytes_field(LEDGER_HASH, ledger_hash);
            }
            Self::QuorumAddMember { quorum_member, quorum_member_signature, member_ledger_id, min_fee_bps, min_fee_fixed, max_fee_period, collateral_lock_amount, collateral_lock_until, dispute_response_blocks, dispute_arm_blocks, service_response_blocks, max_transfer_timeout_blocks, max_descriptor_bytes } => {
                builder = builder
                    .pubkey_field(QUORUM_MEMBER, quorum_member)
                    .bytes_field(QUORUM_MEMBER_SIG, quorum_member_signature)
                    .string_field(MEMBER_LEDGER_ID, member_ledger_id);
                if let Some(bps) = min_fee_bps {
                    builder = builder.u16_field(MIN_FEE_BPS, *bps);
                }
                if let Some(fixed) = min_fee_fixed {
                    builder = builder.u64_field(MIN_FEE_FIXED, *fixed);
                }
                if let Some(period) = max_fee_period {
                    builder = builder.u32_field(MAX_FEE_PERIOD, *period);
                }
                if let Some(amt) = collateral_lock_amount {
                    builder = builder.u64_field(COLLATERAL_LOCK_AMOUNT, *amt);
                }
                if let Some(lock) = collateral_lock_until {
                    builder = builder.u32_field(COLLATERAL_LOCK_UNTIL, *lock);
                }
                if let Some(v) = dispute_response_blocks {
                    builder = builder.u32_field(DISPUTE_RESPONSE_BLOCKS, *v);
                }
                if let Some(v) = dispute_arm_blocks {
                    builder = builder.u32_field(DISPUTE_ARM_BLOCKS, *v);
                }
                if let Some(v) = service_response_blocks {
                    builder = builder.u32_field(SERVICE_RESPONSE_BLOCKS, *v);
                }
                if let Some(v) = max_transfer_timeout_blocks {
                    builder = builder.u32_field(MAX_TRANSFER_TIMEOUT_BLOCKS, *v);
                }
                if let Some(v) = max_descriptor_bytes {
                    builder = builder.u32_field(MAX_DESCRIPTOR_BYTES, *v);
                }
            }
            Self::QuorumRemoveMember { quorum_member, operator_signature } => {
                builder = builder
                    .pubkey_field(QUORUM_MEMBER, quorum_member)
                    .bytes_field(OPERATOR_SIG, operator_signature);
            }
            Self::CollateralLock { deposit_id, amount, lock_until_block, operator_id, witness } => {
                builder = builder
                    .deposit_id_field(DEPOSIT_ID, deposit_id)
                    .u64_field(AMOUNT, *amount)
                    .u32_field(LOCK_UNTIL_BLOCK, *lock_until_block)
                    .pubkey_field(OPERATOR_ID, operator_id)
                    .witness_field(WITNESS, witness);
            }
            Self::QuorumJoin { operator_id, ledger_id, membership_expires, our_signature } => {
                // Note: TLV field ID is RESERVES_ID (58) for wire compatibility,
                // even though the Rust field is now named ledger_id
                builder = builder
                    .pubkey_field(OPERATOR_ID, operator_id)
                    .string_field(RESERVES_ID, ledger_id)
                    .u32_field(MEMBERSHIP_EXPIRES, *membership_expires)
                    .bytes_field(OUR_SIGNATURE, our_signature);
            }
            Self::FeeCollect { deposit_id, amount, block_height } => {
                builder = builder
                    .deposit_id_field(DEPOSIT_ID, deposit_id)
                    .u64_field(AMOUNT, *amount)
                    .u32_field(BLOCK_HEIGHT, *block_height);
            }
            Self::DisputeEnter { last_valid_sequence, reason } => {
                builder = builder
                    .u64_field(LAST_VALID_SEQUENCE, *last_valid_sequence)
                    .string_field(REASON, reason);
            }
            Self::DisputeArmed { armed_block, commitment_hash, target_reserves } => {
                builder = builder
                    .u32_field(ARMED_BLOCK, *armed_block)
                    .bytes_field(COMMITMENT_HASH, commitment_hash)
                    .string_field(TARGET_RESERVES, target_reserves);
            }
            Self::DisputeAcquire { new_custodian, entropy_block_height, entropy_block_hash, spend_txid, new_reserves_address } => {
                builder = builder
                    .pubkey_field(NEW_CUSTODIAN, new_custodian)
                    .u32_field(ENTROPY_BLOCK_HEIGHT, *entropy_block_height)
                    .bytes_field(ENTROPY_BLOCK_HASH, entropy_block_hash)
                    .bytes_field(SPEND_TXID, spend_txid)
                    .string_field(NEW_RESERVES_ADDRESS, new_reserves_address);
            }
            Self::DeliveryEmbed { request_hash, target_ledger_id, target_operator } => {
                builder = builder
                    .bytes_field(REQUEST_HASH, request_hash)
                    .bytes_field(TARGET_LEDGER_ID, target_ledger_id)
                    .pubkey_field(TARGET_OPERATOR, target_operator);
            }
            Self::DisputeYield => {}
            Self::LedgerClose => {}
        }

        builder.build()
    }
}

impl TlvDecode for LedgerOperation {
    fn tlv_decode(data: &[u8]) -> TlvResult<Self> {
        use ledger_op_tlv::*;

        let reader = TlvReader::new(data)?;
        let discriminant = reader.read_u8(DISCRIMINANT)?;

        match discriminant {
            1 => Ok(Self::LedgerOpen {
                operator_id: reader.read_pubkey(OPERATOR_ID)?,
                reserves_id: reader.read_string(RESERVES_ID)?,
                genesis_block: reader.read_u32_opt(GENESIS_BLOCK)?.unwrap_or(0),
                reserves_amount: reader.read_u64_opt(RESERVES_AMOUNT)?.unwrap_or(0),
            }),
            12 => {
                let members_bytes = reader.read_raw_opt(QUORUM_MEMBERS).unwrap_or(&[]);
                let mut quorum_members = Vec::new();
                let mut off = 0;
                while off + 33 <= members_bytes.len() {
                    if let Ok(pk) = bitcoin::secp256k1::PublicKey::from_slice(&members_bytes[off..off+33]) {
                        quorum_members.push(pk);
                    }
                    off += 33;
                }
                Ok(Self::QuorumBegin {
                    reserves_id: reader.read_string(RESERVES_ID)?,
                    spending_txid: reader.read_bytes(SPENDING_TXID)?,
                    new_outpoint_txid: reader.read_bytes(NEW_OUTPOINT_TXID)?,
                    new_outpoint_vout: reader.read_u32(NEW_OUTPOINT_VOUT)?,
                    amount: reader.read_u64(AMOUNT)?,
                    quorum_expiry: reader.read_u32(QUORUM_EXPIRY)?,
                    ledger_hash: reader.read_bytes(LEDGER_HASH)?,
                    quorum_members,
                    total_collateral: reader.read_u64(TOTAL_COLLATERAL)?,
                })
            }
            20 => Ok(Self::DepositOpen {
                deposit_id: reader.read_deposit_id(DEPOSIT_ID)?,
                descriptor: reader.read_string(DESCRIPTOR)?,
                fees: reader.read_nested_opt(FEES)?,
                transfer_fees: reader.read_nested_opt(TRANSFER_FEES)?,
                payment_hash: reader.read_bytes_opt(PAYMENT_HASH)?,
                invoice: reader.read_string_opt(INVOICE)?,
                cosigner_guarantee_signature: reader.read_bytes_opt(COSIGNER_SIG)?,
                is_collateral: reader.read_u8(IS_COLLATERAL).unwrap_or(0) != 0,
                receive_requires_sig: reader.read_u8(RECEIVE_REQUIRES_SIG).unwrap_or(0) != 0,
                fee_change_after_blocks: reader.read_u32_opt(FEE_CHANGE_AFTER)?,
                fee_change_notice_blocks: reader.read_u32_opt(FEE_CHANGE_NOTICE)?,
                fee_change_limit_bps: reader.read_u16_opt(FEE_CHANGE_LIMIT_BPS)?,
            }),
            21 => Ok(Self::DepositClose { deposit_id: reader.read_deposit_id(DEPOSIT_ID)? }),
            22 => Ok(Self::FeeChange {
                deposit_id: reader.read_deposit_id(DEPOSIT_ID)?,
                new_fees: reader.read_nested(NEW_FEES)?,
                effective_block: reader.read_u32_opt(EFFECTIVE_BLOCK)?.unwrap_or(0),
            }),
            23 => Ok(Self::DepositKeyRotate {
                deposit_id: reader.read_deposit_id(DEPOSIT_ID)?,
                new_descriptor: reader.read_string(NEW_DESCRIPTOR)?,
                witness: reader.read_witness(WITNESS)?,
            }),
            30 => Ok(Self::InvoiceCredit {
                payment_hash: reader.read_bytes(PAYMENT_HASH)?,
                deposit_id: reader.read_deposit_id(DEPOSIT_ID)?,
                amount: reader.read_u64(AMOUNT)?,
                invoice_id: reader.read_string(INVOICE_ID)?,
                sequence_number: reader.read_u64(SEQUENCE_NUMBER)?,
            }),
            31 => Ok(Self::InvoiceLock {
                deposit_id: reader.read_deposit_id(DEPOSIT_ID)?,
                amount: reader.read_u64(AMOUNT)?,
                payment_id: reader.read_bytes(PAYMENT_ID)?,
                sequence_number: reader.read_u64(SEQUENCE_NUMBER)?,
                witness: reader.read_witness(WITNESS)?,
            }),
            32 => Ok(Self::InvoiceFail {
                deposit_id: reader.read_deposit_id(DEPOSIT_ID)?,
                amount: reader.read_u64(AMOUNT)?,
                payment_id: reader.read_bytes(PAYMENT_ID)?,
                sequence_number: reader.read_u64(SEQUENCE_NUMBER)?,
            }),
            33 => Ok(Self::InvoiceFulfill {
                deposit_id: reader.read_deposit_id(DEPOSIT_ID)?,
                amount: reader.read_u64(AMOUNT)?,
                payment_id: reader.read_bytes(PAYMENT_ID)?,
                sequence_number: reader.read_u64(SEQUENCE_NUMBER)?,
                witness: reader.read_witness(WITNESS)?,
                preimage: reader.read_bytes(PREIMAGE)?,
            }),
            35 => Ok(Self::OnchainCredit {
                txid: reader.read_bytes(TXID)?,
                vout: reader.read_u32(VOUT)?,
                deposit_id: reader.read_deposit_id(DEPOSIT_ID)?,
                amount: reader.read_u64(AMOUNT)?,
                funding_address: reader.read_string(FUNDING_ADDRESS)?,
            }),
            36 => Ok(Self::OnchainLock {
                deposit_id: reader.read_deposit_id(DEPOSIT_ID)?,
                amount: reader.read_u64(AMOUNT)?,
                fee_sats: reader.read_u64(FEES)?,
                destination_address: reader.read_string(DESTINATION_ADDRESS)?,
                withdrawal_id: reader.read_bytes(WITHDRAWAL_ID)?,
                witness: reader.read_witness(WITNESS)?,
            }),
            37 => Ok(Self::OnchainFail {
                deposit_id: reader.read_deposit_id(DEPOSIT_ID)?,
                withdrawal_id: reader.read_bytes(WITHDRAWAL_ID)?,
            }),
            38 => Ok(Self::OnchainFulfill {
                deposit_id: reader.read_deposit_id(DEPOSIT_ID)?,
                withdrawal_id: reader.read_bytes(WITHDRAWAL_ID)?,
                amount: reader.read_u64(AMOUNT)?,
                txid: reader.read_bytes(TXID)?,
                destination_address: reader.read_string(DESTINATION_ADDRESS)?,
            }),
            70 => Ok(Self::TransferLock {
                nonce: reader.read_bytes(NONCE)?,
                source_deposit_id: reader.read_deposit_id(SOURCE_DEPOSIT_ID)?,
                destination_deposit_id: reader.read_deposit_id(DESTINATION_DEPOSIT_ID)?,
                amount: reader.read_u64(AMOUNT)?,
                fee: reader.read_u64(FEES)?,
                completion_script: reader.read_string(COMPLETION_SCRIPT)?,
                timeout_height: reader.read_u32(TIMEOUT_HEIGHT)?,
                transfer_id: reader.read_bytes(TRANSFER_ID)?,
                witness: reader.read_witness(WITNESS)?,
            }),
            71 => Ok(Self::TransferComplete {
                transfer_id: reader.read_bytes(TRANSFER_ID)?,
                script_witness: reader.read_witness(SCRIPT_WITNESS)?,
            }),
            72 => Ok(Self::TransferFail {
                transfer_id: reader.read_bytes(TRANSFER_ID)?,
                block_hash: reader.read_bytes(BLOCK_HASH)?,
                reason: reader.read_u8(FAIL_REASON).unwrap_or(1),
            }),
            42 => Ok(Self::CollateralAttestation {
                collateral_operator: reader.read_pubkey(COLLATERAL_OPERATOR)?,
                quorum_member: reader.read_pubkey(QUORUM_MEMBER)?,
                collateral_ledger_id: reader.read_string(COLLATERAL_LEDGER_ID)?,
                amount: reader.read_u64(AMOUNT)?,
                block_height: reader.read_u32(BLOCK_HEIGHT)?,
                lock_until_block: reader.read_u32(LOCK_UNTIL_BLOCK)?,
                signature: reader.read_bytes(SIGNATURE)?,
                ledger_hash: reader.read_bytes(LEDGER_HASH)?,
            }),
            43 => Ok(Self::QuorumAddMember {
                quorum_member: reader.read_pubkey(QUORUM_MEMBER)?,
                quorum_member_signature: reader.read_bytes(QUORUM_MEMBER_SIG)?,
                member_ledger_id: reader.read_string(MEMBER_LEDGER_ID)?,
                min_fee_bps: reader.read_u16_opt(MIN_FEE_BPS)?,
                min_fee_fixed: reader.read_u64_opt(MIN_FEE_FIXED)?,
                max_fee_period: reader.read_u32_opt(MAX_FEE_PERIOD)?,
                collateral_lock_amount: reader.read_u64_opt(COLLATERAL_LOCK_AMOUNT)?,
                collateral_lock_until: reader.read_u32_opt(COLLATERAL_LOCK_UNTIL)?,
                dispute_response_blocks: reader.read_u32_opt(DISPUTE_RESPONSE_BLOCKS)?,
                dispute_arm_blocks: reader.read_u32_opt(DISPUTE_ARM_BLOCKS)?,
                service_response_blocks: reader.read_u32_opt(SERVICE_RESPONSE_BLOCKS)?,
                max_transfer_timeout_blocks: reader.read_u32_opt(MAX_TRANSFER_TIMEOUT_BLOCKS)?,
                max_descriptor_bytes: reader.read_u32_opt(MAX_DESCRIPTOR_BYTES)?,
            }),
            44 => Ok(Self::QuorumRemoveMember {
                quorum_member: reader.read_pubkey(QUORUM_MEMBER)?,
                operator_signature: reader.read_bytes(OPERATOR_SIG)?,
            }),
            45 => Ok(Self::CollateralLock {
                deposit_id: reader.read_deposit_id(DEPOSIT_ID)?,
                amount: reader.read_u64(AMOUNT)?,
                lock_until_block: reader.read_u32(LOCK_UNTIL_BLOCK)?,
                operator_id: reader.read_pubkey(OPERATOR_ID)?,
                witness: reader.read_witness(WITNESS)?,
            }),
            46 => Ok(Self::QuorumJoin {
                operator_id: reader.read_pubkey(OPERATOR_ID)?,
                // Note: TLV field ID is RESERVES_ID (58) for wire compatibility
                ledger_id: reader.read_string(RESERVES_ID)?,
                membership_expires: reader.read_u32(MEMBERSHIP_EXPIRES)?,
                our_signature: reader.read_bytes(OUR_SIGNATURE)?,
            }),
            50 => Ok(Self::FeeCollect {
                deposit_id: reader.read_deposit_id(DEPOSIT_ID)?,
                amount: reader.read_u64(AMOUNT)?,
                block_height: reader.read_u32(BLOCK_HEIGHT)?,
            }),
            54 => Ok(Self::DisputeEnter {
                last_valid_sequence: reader.read_u64(LAST_VALID_SEQUENCE)?,
                reason: reader.read_string(REASON)?,
            }),
            55 => Ok(Self::DisputeAcquire {
                new_custodian: reader.read_pubkey(NEW_CUSTODIAN)?,
                entropy_block_height: reader.read_u32(ENTROPY_BLOCK_HEIGHT)?,
                entropy_block_hash: reader.read_bytes(ENTROPY_BLOCK_HASH)?,
                spend_txid: reader.read_bytes(SPEND_TXID)?,
                new_reserves_address: reader.read_string(NEW_RESERVES_ADDRESS)?,
            }),
            56 => Ok(Self::DisputeYield),
            57 => Ok(Self::DisputeArmed {
                armed_block: reader.read_u32(ARMED_BLOCK)?,
                commitment_hash: reader.read_bytes(COMMITMENT_HASH)?,
                target_reserves: reader.read_string(TARGET_RESERVES)?,
            }),
            80 => Ok(Self::DeliveryEmbed {
                request_hash: reader.read_bytes(REQUEST_HASH)?,
                target_ledger_id: reader.read_bytes(TARGET_LEDGER_ID)?,
                target_operator: reader.read_pubkey(TARGET_OPERATOR)?,
            }),
            60 => Ok(Self::LedgerClose),
            d => Err(TlvError::InvalidFieldValue {
                field_type: DISCRIMINANT,
                reason: format!("unknown LedgerOperation discriminant: {}", d),
            }),
        }
    }
}

/// TLV field type constants for LedgerUpdateMsg
mod ledger_update_tlv {
    pub const OPERATOR_ID: u64 = 0;
    pub const RESERVES_ID: u64 = 2;
    pub const OPERATION: u64 = 4;
    pub const SEQUENCE_NUMBER: u64 = 6;
    pub const PREVIOUS_HASH: u64 = 8;
    pub const CURRENT_HASH: u64 = 10;
    pub const OPERATOR_SIGNATURE: u64 = 12;
}

impl TlvEncode for LedgerUpdateMsg {
    fn tlv_encode(&self) -> Vec<u8> {
        use ledger_update_tlv::*;
        TlvBuilder::new()
            .pubkey_field(OPERATOR_ID, &self.operator_id)
            .string_field(RESERVES_ID, &self.reserves_id)
            .nested(OPERATION, &self.operation)
            .u64_field(SEQUENCE_NUMBER, self.sequence_number)
            .bytes_field(PREVIOUS_HASH, &self.previous_hash)
            .bytes_field(CURRENT_HASH, &self.current_hash)
            .bytes_field(OPERATOR_SIGNATURE, &self.operator_signature)
            .build()
    }
}

impl TlvDecode for LedgerUpdateMsg {
    fn tlv_decode(data: &[u8]) -> TlvResult<Self> {
        use ledger_update_tlv::*;
        let reader = TlvReader::new(data)?;
        Ok(Self {
            operator_id: reader.read_pubkey(OPERATOR_ID)?,
            reserves_id: reader.read_string(RESERVES_ID)?,
            operation: reader.read_nested(OPERATION)?,
            sequence_number: reader.read_u64(SEQUENCE_NUMBER)?,
            previous_hash: reader.read_bytes(PREVIOUS_HASH)?,
            current_hash: reader.read_bytes(CURRENT_HASH)?,
            operator_signature: reader.read_bytes(OPERATOR_SIGNATURE)?,
        })
    }
}

/// TLV field type constants for LedgerUpdateResponseMsg
mod ledger_response_tlv {
    pub const OPERATOR_ID: u64 = 0;
    pub const RESERVES_ID: u64 = 2;
    pub const REQUEST_HASH: u64 = 4;
    pub const ACCEPTED: u64 = 6;
    pub const ERROR: u64 = 8;
    pub const COSIGN_SIGNATURE: u64 = 10;
    pub const CONFIRMED_SEQUENCE: u64 = 12;
    pub const CONFIRMED_HASH: u64 = 14;
}

impl TlvEncode for LedgerUpdateResponseMsg {
    fn tlv_encode(&self) -> Vec<u8> {
        use ledger_response_tlv::*;
        let mut builder = TlvBuilder::new()
            .pubkey_field(OPERATOR_ID, &self.operator_id)
            .string_field(RESERVES_ID, &self.reserves_id)
            .bytes_field(REQUEST_HASH, &self.request_hash)
            .u8_field(ACCEPTED, if self.accepted { 1 } else { 0 });

        if let Some(ref err) = self.error {
            builder = builder.string_field(ERROR, err);
        }
        if let Some(ref sig) = self.cosign_signature {
            builder = builder.bytes_field(COSIGN_SIGNATURE, sig);
        }

        builder
            .u64_field(CONFIRMED_SEQUENCE, self.confirmed_sequence)
            .bytes_field(CONFIRMED_HASH, &self.confirmed_hash)
            .build()
    }
}

impl TlvDecode for LedgerUpdateResponseMsg {
    fn tlv_decode(data: &[u8]) -> TlvResult<Self> {
        use ledger_response_tlv::*;
        let reader = TlvReader::new(data)?;
        Ok(Self {
            operator_id: reader.read_pubkey(OPERATOR_ID)?,
            reserves_id: reader.read_string(RESERVES_ID)?,
            request_hash: reader.read_bytes(REQUEST_HASH)?,
            accepted: reader.read_u8(ACCEPTED)? != 0,
            error: reader.read_string_opt(ERROR)?,
            cosign_signature: reader.read_bytes_opt(COSIGN_SIGNATURE)?,
            confirmed_sequence: reader.read_u64(CONFIRMED_SEQUENCE)?,
            confirmed_hash: reader.read_bytes(CONFIRMED_HASH)?,
        })
    }
}

/// TLV field type constants for HandshakeMsg
mod handshake_tlv {
    pub const PROTOCOL_VERSION: u64 = 0;
    pub const MIN_PROTOCOL_VERSION: u64 = 2;
    pub const FEATURES: u64 = 4;
    pub const OPERATOR_PUBKEY: u64 = 6;
    pub const PARTNER_PUBKEY: u64 = 8;
    pub const FUNDING_TXID: u64 = 10;
    pub const FUNDING_VOUT: u64 = 12;
    // 14 was COLLATERAL_ENFORCEMENT_BLOCK (removed)
}

impl TlvEncode for HandshakeMsg {
    fn tlv_encode(&self) -> Vec<u8> {
        use handshake_tlv::*;
        TlvBuilder::new()
            .u16_field(PROTOCOL_VERSION, self.protocol_version)
            .u16_field(MIN_PROTOCOL_VERSION, self.min_protocol_version)
            .u32_field(FEATURES, self.features)
            .pubkey_field(OPERATOR_PUBKEY, &self.operator_id)
            .string_field(PARTNER_PUBKEY, &self.reserves_id)
            .bytes_field(FUNDING_TXID, &self.funding_txid)
            .u16_field(FUNDING_VOUT, self.funding_vout)
            .build()
    }
}

impl TlvDecode for HandshakeMsg {
    fn tlv_decode(data: &[u8]) -> TlvResult<Self> {
        use handshake_tlv::*;
        let reader = TlvReader::new(data)?;
        Ok(Self {
            protocol_version: reader.read_u16(PROTOCOL_VERSION)?,
            min_protocol_version: reader.read_u16(MIN_PROTOCOL_VERSION)?,
            features: reader.read_u32(FEATURES)?,
            operator_id: reader.read_pubkey(OPERATOR_PUBKEY)?,
            reserves_id: reader.read_string(PARTNER_PUBKEY)?,
            funding_txid: reader.read_bytes(FUNDING_TXID)?,
            funding_vout: reader.read_u16(FUNDING_VOUT)?,
        })
    }
}

/// TLV field type constants for HandshakeResponseMsg
mod handshake_response_tlv {
    pub const REQUEST_HASH: u64 = 0;
    pub const PROTOCOL_VERSION: u64 = 2;
    pub const ACCEPTED: u64 = 4;
    pub const ERROR: u64 = 6;
    pub const PARTNER_PUBKEY: u64 = 8;
}

impl TlvEncode for HandshakeResponseMsg {
    fn tlv_encode(&self) -> Vec<u8> {
        use handshake_response_tlv::*;
        let mut builder = TlvBuilder::new()
            .bytes_field(REQUEST_HASH, &self.request_hash)
            .u16_field(PROTOCOL_VERSION, self.protocol_version)
            .u8_field(ACCEPTED, if self.accepted { 1 } else { 0 });

        if let Some(ref err) = self.error {
            builder = builder.string_field(ERROR, err);
        }

        builder.string_field(PARTNER_PUBKEY, &self.reserves_id).build()
    }
}

impl TlvDecode for HandshakeResponseMsg {
    fn tlv_decode(data: &[u8]) -> TlvResult<Self> {
        use handshake_response_tlv::*;
        let reader = TlvReader::new(data)?;
        Ok(Self {
            request_hash: reader.read_bytes(REQUEST_HASH)?,
            protocol_version: reader.read_u16(PROTOCOL_VERSION)?,
            accepted: reader.read_u8(ACCEPTED)? != 0,
            error: reader.read_string_opt(ERROR)?,
            reserves_id: reader.read_string(PARTNER_PUBKEY)?,
        })
    }
}

// NOTE: TlvEncode/TlvDecode for SignedLedgerUpdate are implemented in types.rs

/// TLV for SyncMsg
mod sync_msg_tlv {
    pub const LEDGER_ID: u64 = 0;
    pub const LAST_KNOWN_SEQUENCE: u64 = 2;
    pub const LAST_KNOWN_HASH: u64 = 4;
}

impl TlvEncode for SyncMsg {
    fn tlv_encode(&self) -> Vec<u8> {
        use sync_msg_tlv::*;
        TlvBuilder::new()
            .bytes_field(LEDGER_ID, &self.ledger_id)
            .u64_field(LAST_KNOWN_SEQUENCE, self.last_known_sequence)
            .bytes_field(LAST_KNOWN_HASH, &self.last_known_hash)
            .build()
    }
}

impl TlvDecode for SyncMsg {
    fn tlv_decode(data: &[u8]) -> TlvResult<Self> {
        use sync_msg_tlv::*;
        let reader = TlvReader::new(data)?;
        Ok(Self {
            ledger_id: reader.read_bytes(LEDGER_ID)?,
            last_known_sequence: reader.read_u64(LAST_KNOWN_SEQUENCE)?,
            last_known_hash: reader.read_bytes(LAST_KNOWN_HASH)?,
        })
    }
}

/// TLV for SyncResponseMsg
mod sync_response_tlv {
    pub const LEDGER_ID: u64 = 0;
    pub const REQUEST_HASH: u64 = 2;
    pub const UPDATES: u64 = 4;
    pub const CURRENT_SEQUENCE: u64 = 6;
    pub const CURRENT_HASH: u64 = 8;
}

impl TlvEncode for SyncResponseMsg {
    fn tlv_encode(&self) -> Vec<u8> {
        use sync_response_tlv::*;
        TlvBuilder::new()
            .bytes_field(LEDGER_ID, &self.ledger_id)
            .bytes_field(REQUEST_HASH, &self.request_hash)
            .vec_field(UPDATES, &self.updates)
            .u64_field(CURRENT_SEQUENCE, self.current_sequence)
            .bytes_field(CURRENT_HASH, &self.current_hash)
            .build()
    }
}

impl TlvDecode for SyncResponseMsg {
    fn tlv_decode(data: &[u8]) -> TlvResult<Self> {
        use sync_response_tlv::*;
        let reader = TlvReader::new(data)?;
        Ok(Self {
            ledger_id: reader.read_bytes(LEDGER_ID)?,
            request_hash: reader.read_bytes(REQUEST_HASH)?,
            updates: reader.read_vec(UPDATES)?,
            current_sequence: reader.read_u64(CURRENT_SEQUENCE)?,
            current_hash: reader.read_bytes(CURRENT_HASH)?,
        })
    }
}

/// TLV for RecoveryMsg
mod recovery_msg_tlv {
    pub const DISCRIMINANT: u64 = 0;
    pub const OPERATOR: u64 = 2;
    pub const PARTNER: u64 = 4;
    pub const VOTER: u64 = 6;
    pub const IS_CONFORMING: u64 = 8;
    pub const VALIDATED_HASH: u64 = 10;
    pub const VALIDATED_SEQUENCE: u64 = 12;
    pub const SUBSTITUTE_NOMINATION: u64 = 14;
    pub const DISCOVERED_VIOLATION: u64 = 16;
    pub const SIGNATURE: u64 = 18;
    pub const CLAIMANT: u64 = 20;
    pub const TIER_INDEX: u64 = 22;
    pub const UNSIGNED_TX: u64 = 24;
    pub const SIGHASH: u64 = 26;
    pub const DESTINATION_SCRIPT: u64 = 28;
    pub const BLOCK_HEIGHT: u64 = 30;
    pub const NEW_OPERATOR: u64 = 32;
    pub const CLAIM_TXID: u64 = 34;
    pub const CONFIRMATION_BLOCK: u64 = 36;
    pub const REASON_CODE: u64 = 38;
    pub const PAYMENT_HASH: u64 = 40;
    pub const PREIMAGE: u64 = 42;
    pub const DEPOSIT_PUBKEY: u64 = 44;
    pub const AMOUNT_MSAT: u64 = 46;
    pub const INVOICE_COSIGNATURE: u64 = 48;
    pub const SETTLEMENT_SEQUENCE: u64 = 50;
    pub const SETTLEMENT_LEDGER_HASH: u64 = 52;
    pub const SETTLEMENT_BLOCK_HEIGHT: u64 = 54;
    pub const ACCUSER_SIGNATURE: u64 = 56;
}

impl TlvEncode for RecoveryMsg {
    fn tlv_encode(&self) -> Vec<u8> {
        use recovery_msg_tlv::*;
        match self {
            Self::Vote { operator, partner, voter, is_conforming, validated_hash, validated_sequence, substitute_nomination, discovered_violation, signature } => {
                let mut builder = TlvBuilder::new()
                    .u8_field(DISCRIMINANT, 0)
                    .pubkey_field(OPERATOR, operator)
                    .pubkey_field(PARTNER, partner)
                    .pubkey_field(VOTER, voter)
                    .u8_field(IS_CONFORMING, if *is_conforming { 1 } else { 0 })
                    .bytes_field(VALIDATED_HASH, validated_hash)
                    .u64_field(VALIDATED_SEQUENCE, *validated_sequence);
                if let Some(sub) = substitute_nomination {
                    builder = builder.pubkey_field(SUBSTITUTE_NOMINATION, sub);
                }
                builder
                    .u8_field(DISCOVERED_VIOLATION, if *discovered_violation { 1 } else { 0 })
                    .bytes_field(SIGNATURE, signature)
                    .build()
            }
            Self::ClaimRequest { operator, partner, claimant, tier_index, unsigned_tx, sighash, destination_script, block_height } => {
                TlvBuilder::new()
                    .u8_field(DISCRIMINANT, 1)
                    .pubkey_field(OPERATOR, operator)
                    .pubkey_field(PARTNER, partner)
                    .pubkey_field(CLAIMANT, claimant)
                    .u8_field(TIER_INDEX, *tier_index)
                    .bytes_field(UNSIGNED_TX, unsigned_tx)
                    .bytes_field(SIGHASH, sighash)
                    .bytes_field(DESTINATION_SCRIPT, destination_script)
                    .u32_field(BLOCK_HEIGHT, *block_height)
                    .build()
            }
            Self::ClaimComplete { operator, partner, new_operator, claim_txid, confirmation_block, reason_code } => {
                TlvBuilder::new()
                    .u8_field(DISCRIMINANT, 2)
                    .pubkey_field(OPERATOR, operator)
                    .pubkey_field(PARTNER, partner)
                    .pubkey_field(NEW_OPERATOR, new_operator)
                    .bytes_field(CLAIM_TXID, claim_txid)
                    .u32_field(CONFIRMATION_BLOCK, *confirmation_block)
                    .u8_field(REASON_CODE, *reason_code)
                    .build()
            }
            Self::UncreditedPayment { operator, partner, payment_hash, preimage, deposit_pubkey, amount_msat, invoice_cosignature, settlement_sequence, settlement_ledger_hash, settlement_block_height, accuser_signature } => {
                TlvBuilder::new()
                    .u8_field(DISCRIMINANT, 3)
                    .pubkey_field(OPERATOR, operator)
                    .pubkey_field(PARTNER, partner)
                    .bytes_field(PAYMENT_HASH, payment_hash)
                    .bytes_field(PREIMAGE, preimage)
                    .pubkey_field(DEPOSIT_PUBKEY, deposit_pubkey)
                    .u64_field(AMOUNT_MSAT, *amount_msat)
                    .bytes_field(INVOICE_COSIGNATURE, invoice_cosignature)
                    .u64_field(SETTLEMENT_SEQUENCE, *settlement_sequence)
                    .bytes_field(SETTLEMENT_LEDGER_HASH, settlement_ledger_hash)
                    .u32_field(SETTLEMENT_BLOCK_HEIGHT, *settlement_block_height)
                    .bytes_field(ACCUSER_SIGNATURE, accuser_signature)
                    .build()
            }
        }
    }
}

impl TlvDecode for RecoveryMsg {
    fn tlv_decode(data: &[u8]) -> TlvResult<Self> {
        use recovery_msg_tlv::*;
        let reader = TlvReader::new(data)?;
        let discriminant = reader.read_u8(DISCRIMINANT)?;
        match discriminant {
            0 => Ok(Self::Vote {
                operator: reader.read_pubkey(OPERATOR)?,
                partner: reader.read_pubkey(PARTNER)?,
                voter: reader.read_pubkey(VOTER)?,
                is_conforming: reader.read_u8(IS_CONFORMING)? != 0,
                validated_hash: reader.read_bytes(VALIDATED_HASH)?,
                validated_sequence: reader.read_u64(VALIDATED_SEQUENCE)?,
                substitute_nomination: reader.read_pubkey_opt(SUBSTITUTE_NOMINATION)?,
                discovered_violation: reader.read_u8(DISCOVERED_VIOLATION)? != 0,
                signature: reader.read_bytes(SIGNATURE)?,
            }),
            1 => Ok(Self::ClaimRequest {
                operator: reader.read_pubkey(OPERATOR)?,
                partner: reader.read_pubkey(PARTNER)?,
                claimant: reader.read_pubkey(CLAIMANT)?,
                tier_index: reader.read_u8(TIER_INDEX)?,
                unsigned_tx: reader.read_raw(UNSIGNED_TX)?.to_vec(),
                sighash: reader.read_bytes(SIGHASH)?,
                destination_script: reader.read_raw(DESTINATION_SCRIPT)?.to_vec(),
                block_height: reader.read_u32(BLOCK_HEIGHT)?,
            }),
            2 => Ok(Self::ClaimComplete {
                operator: reader.read_pubkey(OPERATOR)?,
                partner: reader.read_pubkey(PARTNER)?,
                new_operator: reader.read_pubkey(NEW_OPERATOR)?,
                claim_txid: reader.read_bytes(CLAIM_TXID)?,
                confirmation_block: reader.read_u32(CONFIRMATION_BLOCK)?,
                reason_code: reader.read_u8(REASON_CODE)?,
            }),
            3 => Ok(Self::UncreditedPayment {
                operator: reader.read_pubkey(OPERATOR)?,
                partner: reader.read_pubkey(PARTNER)?,
                payment_hash: reader.read_bytes(PAYMENT_HASH)?,
                preimage: reader.read_bytes(PREIMAGE)?,
                deposit_pubkey: reader.read_pubkey(DEPOSIT_PUBKEY)?,
                amount_msat: reader.read_u64(AMOUNT_MSAT)?,
                invoice_cosignature: reader.read_bytes(INVOICE_COSIGNATURE)?,
                settlement_sequence: reader.read_u64(SETTLEMENT_SEQUENCE)?,
                settlement_ledger_hash: reader.read_bytes(SETTLEMENT_LEDGER_HASH)?,
                settlement_block_height: reader.read_u32(SETTLEMENT_BLOCK_HEIGHT)?,
                accuser_signature: reader.read_bytes(ACCUSER_SIGNATURE)?,
            }),
            d => Err(TlvError::InvalidFieldValue {
                field_type: DISCRIMINANT,
                reason: format!("unknown RecoveryMsg discriminant: {}", d),
            }),
        }
    }
}

/// TLV for RecoveryResponseMsg
mod recovery_response_tlv {
    pub const DISCRIMINANT: u64 = 0;
    pub const REQUEST_HASH: u64 = 2;
    pub const RECORDED: u64 = 4;
    pub const SIGNER: u64 = 6;
    pub const SIGHASH: u64 = 8;
    pub const SIGNATURE: u64 = 10;
}

impl TlvEncode for RecoveryResponseMsg {
    fn tlv_encode(&self) -> Vec<u8> {
        use recovery_response_tlv::*;
        match self {
            Self::VoteAck { request_hash, recorded } => {
                TlvBuilder::new()
                    .u8_field(DISCRIMINANT, 0)
                    .bytes_field(REQUEST_HASH, request_hash)
                    .u8_field(RECORDED, if *recorded { 1 } else { 0 })
                    .build()
            }
            Self::ClaimSignature { request_hash, signer, sighash, signature } => {
                TlvBuilder::new()
                    .u8_field(DISCRIMINANT, 1)
                    .bytes_field(REQUEST_HASH, request_hash)
                    .pubkey_field(SIGNER, signer)
                    .bytes_field(SIGHASH, sighash)
                    .bytes_field(SIGNATURE, signature)
                    .build()
            }
            Self::ClaimAck { request_hash } => {
                TlvBuilder::new()
                    .u8_field(DISCRIMINANT, 2)
                    .bytes_field(REQUEST_HASH, request_hash)
                    .build()
            }
            Self::UncreditedPaymentAck { request_hash } => {
                TlvBuilder::new()
                    .u8_field(DISCRIMINANT, 3)
                    .bytes_field(REQUEST_HASH, request_hash)
                    .build()
            }
        }
    }
}

impl TlvDecode for RecoveryResponseMsg {
    fn tlv_decode(data: &[u8]) -> TlvResult<Self> {
        use recovery_response_tlv::*;
        let reader = TlvReader::new(data)?;
        let discriminant = reader.read_u8(DISCRIMINANT)?;
        match discriminant {
            0 => Ok(Self::VoteAck {
                request_hash: reader.read_bytes(REQUEST_HASH)?,
                recorded: reader.read_u8(RECORDED)? != 0,
            }),
            1 => Ok(Self::ClaimSignature {
                request_hash: reader.read_bytes(REQUEST_HASH)?,
                signer: reader.read_pubkey(SIGNER)?,
                sighash: reader.read_bytes(SIGHASH)?,
                signature: reader.read_bytes(SIGNATURE)?,
            }),
            2 => Ok(Self::ClaimAck {
                request_hash: reader.read_bytes(REQUEST_HASH)?,
            }),
            3 => Ok(Self::UncreditedPaymentAck {
                request_hash: reader.read_bytes(REQUEST_HASH)?,
            }),
            d => Err(TlvError::InvalidFieldValue {
                field_type: DISCRIMINANT,
                reason: format!("unknown RecoveryResponseMsg discriminant: {}", d),
            }),
        }
    }
}

// ============================================================================
// TLV Encoding for Coordination Messages
// ============================================================================

mod coordination_tlv {
    pub const DISCRIMINANT: u64 = 0;
    pub const OPERATOR_ID: u64 = 2;
    pub const RESERVES_ID: u64 = 4;
    pub const AMOUNT: u64 = 6;
    pub const PAYMENT_HASH: u64 = 8;
    pub const EXPIRES: u64 = 10;
    pub const ASSIGNED_DEPOSIT: u64 = 12;
    pub const INVOICE_ID: u64 = 14;
    pub const BOLT11_INVOICE: u64 = 16;
    pub const OPERATOR_SIGNATURE: u64 = 18;
    pub const REQUESTER_PUBKEY: u64 = 20;
    pub const PROTOCOL_VERSION: u64 = 22;
    pub const TIMESTAMP: u64 = 24;
    pub const SIGNATURE: u64 = 26;
    pub const VOTE_ROUND_ID: u64 = 28;
    pub const SEQUENCE_NUMBER: u64 = 30;
    pub const STATE_HASH: u64 = 32;
    pub const CLAIMED_RESERVES: u64 = 34;
    pub const COLLATERAL_AMOUNTS: u64 = 36;
    pub const RESERVES_OUTPOINT: u64 = 38;
    pub const DESTINATION_SCRIPT: u64 = 40;
    pub const FEE_RATE_SAT_VBYTE: u64 = 42;
    pub const VOTER_PUBKEY: u64 = 44;
    pub const VOTE: u64 = 46;
    pub const VOTER_SEQUENCE: u64 = 48;
    pub const VOTER_STATE_HASH: u64 = 50;
    pub const EVIDENCE: u64 = 52;
    pub const SPEND_SIGNATURE: u64 = 54;
    // UpdateReserves fields
    pub const CHANNEL_ID: u64 = 56;
    pub const RESERVES_SATS: u64 = 58;
    pub const SCRIPT_PUBKEY: u64 = 60;
    pub const LEDGER_HASH: u64 = 62;
    pub const REMOTE_LEDGER_HASH: u64 = 64;
}

impl TlvEncode for CoordinationMsg {
    fn tlv_encode(&self) -> Vec<u8> {
        use coordination_tlv::*;
        match self {
            Self::CosignInvoice {
                operator_id, reserves_id, amount, payment_hash, expires,
                assigned_deposit, invoice_id, bolt11_invoice,
            } => {
                TlvBuilder::new()
                    .u8_field(DISCRIMINANT, 0)
                    .pubkey_field(OPERATOR_ID, operator_id)
                    .string_field(RESERVES_ID, reserves_id)
                    .u64_field(AMOUNT, *amount)
                    .bytes_field(PAYMENT_HASH, payment_hash)
                    .u64_field(EXPIRES, *expires)
                    .pubkey_field(ASSIGNED_DEPOSIT, assigned_deposit)
                    .string_field(INVOICE_ID, invoice_id)
                    .string_field(BOLT11_INVOICE, bolt11_invoice)
                    .build()
            }
            Self::CollateralConsentRequest {
                operator_id, reserves_id, operator_signature,
            } => {
                TlvBuilder::new()
                    .u8_field(DISCRIMINANT, 1)
                    .pubkey_field(OPERATOR_ID, operator_id)
                    .string_field(RESERVES_ID, reserves_id)
                    .bytes_field(OPERATOR_SIGNATURE, operator_signature)
                    .build()
            }
            Self::QuorumJoinRequest {
                requester_pubkey, operator_id, reserves_id, protocol_version,
                timestamp, signature,
            } => {
                TlvBuilder::new()
                    .u8_field(DISCRIMINANT, 2)
                    .pubkey_field(REQUESTER_PUBKEY, requester_pubkey)
                    .pubkey_field(OPERATOR_ID, operator_id)
                    .string_field(RESERVES_ID, reserves_id)
                    .u16_field(PROTOCOL_VERSION, *protocol_version)
                    .u64_field(TIMESTAMP, *timestamp)
                    .bytes_field(SIGNATURE, signature)
                    .build()
            }
            Self::QuorumVoteRequest {
                vote_round_id, operator_id, reserves_id, sequence_number, state_hash,
                claimed_reserves, collateral_amounts, reserves_outpoint,
                destination_script, fee_rate_sat_vbyte, timestamp,
            } => {
                // Encode Vec<u64> as concatenated big-endian bytes
                let collateral_bytes: Vec<u8> = collateral_amounts.iter()
                    .flat_map(|v| v.to_be_bytes())
                    .collect();
                TlvBuilder::new()
                    .u8_field(DISCRIMINANT, 3)
                    .bytes_field(VOTE_ROUND_ID, vote_round_id)
                    .pubkey_field(OPERATOR_ID, operator_id)
                    .string_field(RESERVES_ID, reserves_id)
                    .u64_field(SEQUENCE_NUMBER, *sequence_number)
                    .bytes_field(STATE_HASH, state_hash)
                    .u64_field(CLAIMED_RESERVES, *claimed_reserves)
                    .bytes_field(COLLATERAL_AMOUNTS, &collateral_bytes)
                    .bytes_field(RESERVES_OUTPOINT, reserves_outpoint)
                    .bytes_field(DESTINATION_SCRIPT, destination_script)
                    .u64_field(FEE_RATE_SAT_VBYTE, *fee_rate_sat_vbyte)
                    .u64_field(TIMESTAMP, *timestamp)
                    .build()
            }
            Self::QuorumVote {
                vote_round_id, voter_pubkey, vote, voter_sequence, voter_state_hash,
                evidence, signature, spend_signature,
            } => {
                let mut builder = TlvBuilder::new()
                    .u8_field(DISCRIMINANT, 4)
                    .bytes_field(VOTE_ROUND_ID, vote_round_id)
                    .pubkey_field(VOTER_PUBKEY, voter_pubkey)
                    .u8_field(VOTE, if *vote { 1 } else { 0 })
                    .u64_field(VOTER_SEQUENCE, *voter_sequence)
                    .bytes_field(VOTER_STATE_HASH, voter_state_hash);
                if let Some(ev) = evidence {
                    builder = builder.bytes_field(EVIDENCE, ev);
                }
                builder = builder.bytes_field(SIGNATURE, signature);
                if let Some(spend_sig) = spend_signature {
                    builder = builder.bytes_field(SPEND_SIGNATURE, spend_sig);
                }
                builder.build()
            }
            Self::UpdateReserves {
                channel_id, reserves_sats, script_pubkey, ledger_hash, remote_ledger_hash,
            } => {
                TlvBuilder::new()
                    .u8_field(DISCRIMINANT, 5)
                    .bytes_field(CHANNEL_ID, channel_id)
                    .u64_field(RESERVES_SATS, *reserves_sats)
                    .bytes_field(SCRIPT_PUBKEY, script_pubkey)
                    .bytes_field(LEDGER_HASH, ledger_hash)
                    .bytes_field(REMOTE_LEDGER_HASH, remote_ledger_hash)
                    .build()
            }
        }
    }
}

impl TlvDecode for CoordinationMsg {
    fn tlv_decode(data: &[u8]) -> TlvResult<Self> {
        use coordination_tlv::*;
        let reader = TlvReader::new(data)?;
        let discriminant = reader.read_u8(DISCRIMINANT)?;
        match discriminant {
            0 => Ok(Self::CosignInvoice {
                operator_id: reader.read_pubkey(OPERATOR_ID)?,
                reserves_id: reader.read_string(RESERVES_ID)?,
                amount: reader.read_u64(AMOUNT)?,
                payment_hash: reader.read_bytes(PAYMENT_HASH)?,
                expires: reader.read_u64(EXPIRES)?,
                assigned_deposit: reader.read_pubkey(ASSIGNED_DEPOSIT)?,
                invoice_id: reader.read_string(INVOICE_ID)?,
                bolt11_invoice: reader.read_string(BOLT11_INVOICE)?,
            }),
            1 => Ok(Self::CollateralConsentRequest {
                operator_id: reader.read_pubkey(OPERATOR_ID)?,
                reserves_id: reader.read_string(RESERVES_ID)?,
                operator_signature: reader.read_bytes(OPERATOR_SIGNATURE)?,
            }),
            2 => Ok(Self::QuorumJoinRequest {
                requester_pubkey: reader.read_pubkey(REQUESTER_PUBKEY)?,
                operator_id: reader.read_pubkey(OPERATOR_ID)?,
                reserves_id: reader.read_string(RESERVES_ID)?,
                protocol_version: reader.read_u16(PROTOCOL_VERSION)?,
                timestamp: reader.read_u64(TIMESTAMP)?,
                signature: reader.read_bytes(SIGNATURE)?,
            }),
            3 => {
                // Decode Vec<u64> from concatenated big-endian bytes
                let collateral_raw = reader.read_raw(COLLATERAL_AMOUNTS)?;
                let collateral_amounts: Vec<u64> = collateral_raw
                    .chunks_exact(8)
                    .map(|chunk| u64::from_be_bytes(chunk.try_into().unwrap()))
                    .collect();
                Ok(Self::QuorumVoteRequest {
                    vote_round_id: reader.read_bytes(VOTE_ROUND_ID)?,
                    operator_id: reader.read_pubkey(OPERATOR_ID)?,
                    reserves_id: reader.read_string(RESERVES_ID)?,
                    sequence_number: reader.read_u64(SEQUENCE_NUMBER)?,
                    state_hash: reader.read_bytes(STATE_HASH)?,
                    claimed_reserves: reader.read_u64(CLAIMED_RESERVES)?,
                    collateral_amounts,
                    reserves_outpoint: reader.read_raw(RESERVES_OUTPOINT)?.to_vec(),
                    destination_script: reader.read_raw(DESTINATION_SCRIPT)?.to_vec(),
                    fee_rate_sat_vbyte: reader.read_u64(FEE_RATE_SAT_VBYTE)?,
                    timestamp: reader.read_u64(TIMESTAMP)?,
                })
            },
            4 => Ok(Self::QuorumVote {
                vote_round_id: reader.read_bytes(VOTE_ROUND_ID)?,
                voter_pubkey: reader.read_pubkey(VOTER_PUBKEY)?,
                vote: reader.read_u8(VOTE)? != 0,
                voter_sequence: reader.read_u64(VOTER_SEQUENCE)?,
                voter_state_hash: reader.read_bytes(VOTER_STATE_HASH)?,
                evidence: reader.read_raw_opt(EVIDENCE).map(|b| b.to_vec()),
                signature: reader.read_bytes(SIGNATURE)?,
                spend_signature: reader.read_bytes_opt(SPEND_SIGNATURE)?,
            }),
            5 => Ok(Self::UpdateReserves {
                channel_id: reader.read_bytes(CHANNEL_ID)?,
                reserves_sats: reader.read_u64(RESERVES_SATS)?,
                script_pubkey: reader.read_raw(SCRIPT_PUBKEY)?.to_vec(),
                ledger_hash: reader.read_bytes(LEDGER_HASH)?,
                remote_ledger_hash: reader.read_bytes(REMOTE_LEDGER_HASH)?,
            }),
            d => Err(TlvError::InvalidFieldValue {
                field_type: DISCRIMINANT,
                reason: format!("unknown CoordinationMsg discriminant: {}", d),
            }),
        }
    }
}

mod coordination_response_tlv {
    pub const DISCRIMINANT: u64 = 0;
    pub const REQUEST_HASH: u64 = 2;
    pub const COSIGNATURE: u64 = 4;
    pub const OPERATOR_ID: u64 = 6;
    pub const RESERVES_ID: u64 = 8;
    pub const CONSENT_GRANTED: u64 = 10;
    pub const QUORUM_MEMBER_SIGNATURE: u64 = 12;
    pub const ACCEPTED: u64 = 14;
    pub const MEMBERS: u64 = 16;
    pub const THRESHOLD: u64 = 18;
    pub const LAST_SEQUENCE: u64 = 20;
    pub const CURRENT_STATE_HASH: u64 = 22;
    pub const REJECTION_REASON: u64 = 24;
    pub const UPDATES: u64 = 26;
    pub const START_SEQUENCE: u64 = 28;
    pub const IS_FINAL: u64 = 30;
    pub const CHANGE_TYPE: u64 = 32;
    pub const MEMBER_PUBKEY: u64 = 34;
    pub const NEW_MEMBERS: u64 = 36;
    pub const NEW_THRESHOLD: u64 = 38;
    pub const TIMESTAMP: u64 = 40;
    pub const OPERATOR_SIGNATURE: u64 = 42;
    // AcceptReserves fields
    pub const CHANNEL_ID: u64 = 44;
}

impl TlvEncode for CoordinationResponseMsg {
    fn tlv_encode(&self) -> Vec<u8> {
        use coordination_response_tlv::*;
        match self {
            Self::InvoiceCosigned { request_hash, cosignature } => {
                TlvBuilder::new()
                    .u8_field(DISCRIMINANT, 0)
                    .bytes_field(REQUEST_HASH, request_hash)
                    .bytes_field(COSIGNATURE, cosignature)
                    .build()
            }
            Self::CollateralConsentResponse {
                request_hash, operator_id, reserves_id, consent_granted,
                quorum_member_signature,
            } => {
                TlvBuilder::new()
                    .u8_field(DISCRIMINANT, 1)
                    .bytes_field(REQUEST_HASH, request_hash)
                    .pubkey_field(OPERATOR_ID, operator_id)
                    .string_field(RESERVES_ID, reserves_id)
                    .u8_field(CONSENT_GRANTED, if *consent_granted { 1 } else { 0 })
                    .bytes_field(QUORUM_MEMBER_SIGNATURE, quorum_member_signature)
                    .build()
            }
            Self::QuorumJoinResponse {
                request_hash, accepted, members, threshold, last_sequence,
                current_hash, rejection_reason,
            } => {
                // Encode Vec<PublicKey> as concatenated compressed pubkey bytes (33 bytes each)
                let members_bytes: Vec<u8> = members.iter()
                    .flat_map(|pk| pk.serialize())
                    .collect();
                let mut builder = TlvBuilder::new()
                    .u8_field(DISCRIMINANT, 2)
                    .bytes_field(REQUEST_HASH, request_hash)
                    .u8_field(ACCEPTED, if *accepted { 1 } else { 0 })
                    .bytes_field(MEMBERS, &members_bytes)
                    .u16_field(THRESHOLD, *threshold)
                    .u64_field(LAST_SEQUENCE, *last_sequence)
                    .bytes_field(CURRENT_STATE_HASH, current_hash);
                if let Some(reason) = rejection_reason {
                    builder = builder.string_field(REJECTION_REASON, reason);
                }
                builder.build()
            }
            Self::QuorumStateSync {
                request_hash, operator_id, reserves_id, updates, start_sequence, is_final,
            } => {
                TlvBuilder::new()
                    .u8_field(DISCRIMINANT, 3)
                    .bytes_field(REQUEST_HASH, request_hash)
                    .pubkey_field(OPERATOR_ID, operator_id)
                    .string_field(RESERVES_ID, reserves_id)
                    .vec_field(UPDATES, updates)
                    .u64_field(START_SEQUENCE, *start_sequence)
                    .u8_field(IS_FINAL, if *is_final { 1 } else { 0 })
                    .build()
            }
            Self::QuorumMembershipChange {
                request_hash, operator_id, reserves_id, change_type, member_pubkey,
                new_members, new_threshold, timestamp, operator_signature,
            } => {
                // Encode Vec<PublicKey> as concatenated compressed pubkey bytes (33 bytes each)
                let new_members_bytes: Vec<u8> = new_members.iter()
                    .flat_map(|pk| pk.serialize())
                    .collect();
                TlvBuilder::new()
                    .u8_field(DISCRIMINANT, 4)
                    .bytes_field(REQUEST_HASH, request_hash)
                    .pubkey_field(OPERATOR_ID, operator_id)
                    .string_field(RESERVES_ID, reserves_id)
                    .string_field(CHANGE_TYPE, change_type)
                    .pubkey_field(MEMBER_PUBKEY, member_pubkey)
                    .bytes_field(NEW_MEMBERS, &new_members_bytes)
                    .u16_field(NEW_THRESHOLD, *new_threshold)
                    .u64_field(TIMESTAMP, *timestamp)
                    .bytes_field(OPERATOR_SIGNATURE, operator_signature)
                    .build()
            }
            Self::AcceptReserves { channel_id } => {
                TlvBuilder::new()
                    .u8_field(DISCRIMINANT, 5)
                    .bytes_field(CHANNEL_ID, channel_id)
                    .build()
            }
        }
    }
}

impl TlvDecode for CoordinationResponseMsg {
    fn tlv_decode(data: &[u8]) -> TlvResult<Self> {
        use coordination_response_tlv::*;
        let reader = TlvReader::new(data)?;
        let discriminant = reader.read_u8(DISCRIMINANT)?;
        match discriminant {
            0 => Ok(Self::InvoiceCosigned {
                request_hash: reader.read_bytes(REQUEST_HASH)?,
                cosignature: reader.read_bytes(COSIGNATURE)?,
            }),
            1 => Ok(Self::CollateralConsentResponse {
                request_hash: reader.read_bytes(REQUEST_HASH)?,
                operator_id: reader.read_pubkey(OPERATOR_ID)?,
                reserves_id: reader.read_string(RESERVES_ID)?,
                consent_granted: reader.read_u8(CONSENT_GRANTED)? != 0,
                quorum_member_signature: reader.read_bytes(QUORUM_MEMBER_SIGNATURE)?,
            }),
            2 => {
                // Decode Vec<PublicKey> from concatenated 33-byte compressed pubkeys
                let members_raw = reader.read_raw(MEMBERS)?;
                let members: Result<Vec<PublicKey>, _> = members_raw
                    .chunks_exact(33)
                    .map(|chunk| PublicKey::from_slice(chunk))
                    .collect();
                let members = members.map_err(|e| TlvError::InvalidFieldValue {
                    field_type: MEMBERS,
                    reason: format!("invalid pubkey: {}", e),
                })?;
                Ok(Self::QuorumJoinResponse {
                    request_hash: reader.read_bytes(REQUEST_HASH)?,
                    accepted: reader.read_u8(ACCEPTED)? != 0,
                    members,
                    threshold: reader.read_u16(THRESHOLD)?,
                    last_sequence: reader.read_u64(LAST_SEQUENCE)?,
                    current_hash: reader.read_bytes(CURRENT_STATE_HASH)?,
                    rejection_reason: reader.read_string_opt(REJECTION_REASON)?,
                })
            },
            3 => Ok(Self::QuorumStateSync {
                request_hash: reader.read_bytes(REQUEST_HASH)?,
                operator_id: reader.read_pubkey(OPERATOR_ID)?,
                reserves_id: reader.read_string(RESERVES_ID)?,
                updates: reader.read_vec(UPDATES)?,
                start_sequence: reader.read_u64(START_SEQUENCE)?,
                is_final: reader.read_u8(IS_FINAL)? != 0,
            }),
            4 => {
                // Decode Vec<PublicKey> from concatenated 33-byte compressed pubkeys
                let new_members_raw = reader.read_raw(NEW_MEMBERS)?;
                let new_members: Result<Vec<PublicKey>, _> = new_members_raw
                    .chunks_exact(33)
                    .map(|chunk| PublicKey::from_slice(chunk))
                    .collect();
                let new_members = new_members.map_err(|e| TlvError::InvalidFieldValue {
                    field_type: NEW_MEMBERS,
                    reason: format!("invalid pubkey: {}", e),
                })?;
                Ok(Self::QuorumMembershipChange {
                    request_hash: reader.read_bytes(REQUEST_HASH)?,
                    operator_id: reader.read_pubkey(OPERATOR_ID)?,
                    reserves_id: reader.read_string(RESERVES_ID)?,
                    change_type: reader.read_string(CHANGE_TYPE)?,
                    member_pubkey: reader.read_pubkey(MEMBER_PUBKEY)?,
                    new_members,
                    new_threshold: reader.read_u16(NEW_THRESHOLD)?,
                    timestamp: reader.read_u64(TIMESTAMP)?,
                    operator_signature: reader.read_bytes(OPERATOR_SIGNATURE)?,
                })
            },
            5 => Ok(Self::AcceptReserves {
                channel_id: reader.read_bytes(CHANNEL_ID)?,
            }),
            d => Err(TlvError::InvalidFieldValue {
                field_type: DISCRIMINANT,
                reason: format!("unknown CoordinationResponseMsg discriminant: {}", d),
            }),
        }
    }
}

// ============================================================================
// TLV Encoding for ReservesAddOutputMsg
// ============================================================================

mod reserves_add_output_tlv {
    pub const INITIAL_AMOUNT: u64 = 0;
    pub const SPEND_TO: u64 = 2;
    pub const RESERVES_ID: u64 = 4;
    pub const QUORUM_MEMBERS: u64 = 6;
}

impl TlvEncode for crate::wire_messages::ReservesAddOutputMsg {
    fn tlv_encode(&self) -> Vec<u8> {
        use reserves_add_output_tlv::*;
        // Encode Vec<PublicKey> as concatenated compressed pubkey bytes (33 bytes each)
        let partners_bytes: Vec<u8> = self.quorum_members.iter()
            .flat_map(|pk| pk.serialize())
            .collect();
        TlvBuilder::new()
            .u64_field(INITIAL_AMOUNT, self.initial_amount)
            .pubkey_field(SPEND_TO, &self.spend_to)
            .string_field(RESERVES_ID, &self.reserves_id)
            .bytes_field(QUORUM_MEMBERS, &partners_bytes)
            .build()
    }
}

impl TlvDecode for crate::wire_messages::ReservesAddOutputMsg {
    fn tlv_decode(data: &[u8]) -> TlvResult<Self> {
        use reserves_add_output_tlv::*;
        let reader = TlvReader::new(data)?;
        // Decode Vec<PublicKey> from concatenated 33-byte compressed pubkeys
        let partners_raw = reader.read_raw(QUORUM_MEMBERS)?;
        let quorum_members: Result<Vec<bitcoin::secp256k1::PublicKey>, _> = partners_raw
            .chunks(33)
            .map(|chunk| bitcoin::secp256k1::PublicKey::from_slice(chunk))
            .collect();
        let quorum_members = quorum_members.map_err(|e| TlvError::InvalidFieldValue {
            field_type: QUORUM_MEMBERS,
            reason: format!("invalid pubkey: {}", e),
        })?;
        Ok(Self {
            initial_amount: reader.read_u64(INITIAL_AMOUNT)?,
            spend_to: reader.read_pubkey(SPEND_TO)?,
            reserves_id: reader.read_string(RESERVES_ID)?,
            quorum_members,
        })
    }
}

// ============================================================================
// TLV Encoding for ReservesRemoveOutputMsg
// ============================================================================

mod reserves_remove_output_tlv {
    pub const RESERVES_ID: u64 = 0;
    pub const REMOVE_ALL: u64 = 2;
}

impl TlvEncode for crate::wire_messages::ReservesRemoveOutputMsg {
    fn tlv_encode(&self) -> Vec<u8> {
        use reserves_remove_output_tlv::*;
        TlvBuilder::new()
            .string_field(RESERVES_ID, &self.reserves_id)
            .u8_field(REMOVE_ALL, if self.remove_all { 1 } else { 0 })
            .build()
    }
}

impl TlvDecode for crate::wire_messages::ReservesRemoveOutputMsg {
    fn tlv_decode(data: &[u8]) -> TlvResult<Self> {
        use reserves_remove_output_tlv::*;
        let reader = TlvReader::new(data)?;
        Ok(Self {
            reserves_id: reader.read_string(RESERVES_ID)?,
            remove_all: reader.read_u8(REMOVE_ALL)? != 0,
        })
    }
}

// ============================================================================
// TLV Encoding for DepositsMessage (main enum)
// ============================================================================

mod message_v2_tlv {
    pub const MESSAGE_TYPE: u64 = 0;
    pub const MESSAGE_BODY: u64 = 2;
}

impl DepositsMessage {
    /// Encode this message to TLV wire format
    pub fn tlv_encode(&self) -> Vec<u8> {
        use message_v2_tlv::*;
        let (msg_type, body) = match self {
            Self::LedgerUpdate(msg) => (LEDGER_UPDATE, msg.tlv_encode()),
            Self::LedgerUpdateResponse(msg) => (LEDGER_UPDATE_RESPONSE, msg.tlv_encode()),
            Self::Handshake(msg) => (HANDSHAKE, msg.tlv_encode()),
            Self::HandshakeResponse(msg) => (HANDSHAKE_RESPONSE, msg.tlv_encode()),
            Self::Sync(msg) => (SYNC, msg.tlv_encode()),
            Self::SyncResponse(msg) => (SYNC_RESPONSE, msg.tlv_encode()),
            Self::Recovery(msg) => (RECOVERY, msg.tlv_encode()),
            Self::RecoveryResponse(msg) => (RECOVERY_RESPONSE, msg.tlv_encode()),
            Self::Coordination(msg) => (COORDINATION, msg.tlv_encode()),
            Self::CoordinationResponse(msg) => (COORDINATION_RESPONSE, msg.tlv_encode()),
            Self::ReservesAddOutput(msg) => (RESERVES_ADD_OUTPUT, msg.tlv_encode()),
            Self::ReservesRemoveOutput(msg) => (RESERVES_REMOVE_OUTPUT, msg.tlv_encode()),
        };
        TlvBuilder::new()
            .u16_field(MESSAGE_TYPE, msg_type)
            .bytes_field(MESSAGE_BODY, &body)
            .build()
    }

    /// Decode this message from TLV wire format
    pub fn tlv_decode(data: &[u8]) -> TlvResult<Self> {
        use message_v2_tlv::*;
        let reader = TlvReader::new(data)?;
        let msg_type = reader.read_u16(MESSAGE_TYPE)?;
        let body = reader.read_raw(MESSAGE_BODY)?;
        match msg_type {
            LEDGER_UPDATE => Ok(Self::LedgerUpdate(LedgerUpdateMsg::tlv_decode(&body)?)),
            LEDGER_UPDATE_RESPONSE => Ok(Self::LedgerUpdateResponse(LedgerUpdateResponseMsg::tlv_decode(&body)?)),
            HANDSHAKE => Ok(Self::Handshake(HandshakeMsg::tlv_decode(&body)?)),
            HANDSHAKE_RESPONSE => Ok(Self::HandshakeResponse(HandshakeResponseMsg::tlv_decode(&body)?)),
            SYNC => Ok(Self::Sync(SyncMsg::tlv_decode(&body)?)),
            SYNC_RESPONSE => Ok(Self::SyncResponse(SyncResponseMsg::tlv_decode(&body)?)),
            RECOVERY => Ok(Self::Recovery(RecoveryMsg::tlv_decode(&body)?)),
            RECOVERY_RESPONSE => Ok(Self::RecoveryResponse(RecoveryResponseMsg::tlv_decode(&body)?)),
            COORDINATION => Ok(Self::Coordination(CoordinationMsg::tlv_decode(&body)?)),
            COORDINATION_RESPONSE => Ok(Self::CoordinationResponse(CoordinationResponseMsg::tlv_decode(&body)?)),
            RESERVES_ADD_OUTPUT => Ok(Self::ReservesAddOutput(crate::wire_messages::ReservesAddOutputMsg::tlv_decode(&body)?)),
            RESERVES_REMOVE_OUTPUT => Ok(Self::ReservesRemoveOutput(crate::wire_messages::ReservesRemoveOutputMsg::tlv_decode(&body)?)),
            _ => Err(TlvError::InvalidFieldValue {
                field_type: MESSAGE_TYPE,
                reason: format!("unknown message type: 0x{:04X}", msg_type),
            }),
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pubkey() -> PublicKey {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let sk = bitcoin::secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap();
        PublicKey::from_secret_key(&secp, &sk)
    }

    #[test]
    fn test_message_type_constants() {
        // All message types should be odd per BOLT 1
        assert_eq!(LEDGER_UPDATE & 1, 1);
        assert_eq!(LEDGER_UPDATE_RESPONSE & 1, 1);
        assert_eq!(HANDSHAKE & 1, 1);
        assert_eq!(HANDSHAKE_RESPONSE & 1, 1);
        assert_eq!(SYNC & 1, 1);
        assert_eq!(SYNC_RESPONSE & 1, 1);
        assert_eq!(RECOVERY & 1, 1);
        assert_eq!(RECOVERY_RESPONSE & 1, 1);
        assert_eq!(COORDINATION & 1, 1);
        assert_eq!(COORDINATION_RESPONSE & 1, 1);
    }

    #[test]
    fn test_ledger_operation_roundtrip() {
        // Test non-deposit operations that fully round-trip with BinaryCodec
        let ops = vec![
            LedgerOperation::FeeCollect {
                deposit_id: crate::types::compute_deposit_id("pk(test)"),
                amount: 500,
                block_height: 800000,
            },
        ];

        for op in ops {
            let mut bytes = Vec::new();
            op.write_to(&mut bytes).unwrap();
            let decoded = LedgerOperation::read_from(&mut &bytes[..]).unwrap();
            assert_eq!(op, decoded);
        }

        // Test DepositOpen separately - BinaryCodec is a legacy format that uses 33-byte
        // legacy pubkey encoding for deposit_id and doesn't preserve the descriptor.
        // The descriptor becomes "legacy(<hex_deposit_id>)" on decode.
        let deposit_id = crate::types::compute_deposit_id("pk(test)");
        let deposit_open = LedgerOperation::DepositOpen {
            deposit_id,
            descriptor: "pk(test)".to_string(),
            fees: Some(FeeStructure {
                annualized_msats: 1000,
                annualized_bps: 50,
                frequency_blocks: 144,
            }),
            transfer_fees: None,
            payment_hash: Some([0xAB; 32]),
            invoice: Some("lnbc...".to_string()),
            cosigner_guarantee_signature: None,
            is_collateral: false,
            receive_requires_sig: false,
            fee_change_after_blocks: None,
            fee_change_notice_blocks: None,
            fee_change_limit_bps: None,
        };

        let mut bytes = Vec::new();
        deposit_open.write_to(&mut bytes).unwrap();
        let decoded = LedgerOperation::read_from(&mut &bytes[..]).unwrap();

        // Verify deposit_id is preserved, descriptor becomes legacy format
        if let LedgerOperation::DepositOpen { deposit_id: decoded_id, descriptor, .. } = decoded {
            assert_eq!(decoded_id, deposit_id);
            assert_eq!(descriptor, format!("legacy({})", hex::encode(&deposit_id)));
        } else {
            panic!("Expected DepositOpen");
        }
    }

    #[test]
    fn test_ledger_update_message_roundtrip() {
        let msg = DepositsMessage::LedgerUpdate(LedgerUpdateMsg {
            operator_id: test_pubkey(),
            reserves_id: test_pubkey().to_string(),
            operation: LedgerOperation::FeeCollect {
                deposit_id: crate::types::compute_deposit_id("pk(test)"),
                amount: 500,
                block_height: 800000,
            },
            sequence_number: 1,
            previous_hash: [0u8; 32],
            current_hash: [0xAB; 32],
            operator_signature: [0xCD; 64],
        });

        let encoded = msg.encode();
        let decoded = DepositsMessage::decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
        assert_eq!(decoded.message_type(), LEDGER_UPDATE);
    }

    #[test]
    fn test_handshake_roundtrip() {
        let msg = DepositsMessage::Handshake(HandshakeMsg {
            protocol_version: PROTOCOL_VERSION,
            min_protocol_version: MIN_PROTOCOL_VERSION,
            features: 0,
            operator_id: test_pubkey(),
            reserves_id: test_pubkey().to_string(),
            funding_txid: [0x11; 32],
            funding_vout: 0,
        });

        let encoded = msg.encode();
        let decoded = DepositsMessage::decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_recovery_message_roundtrip() {
        let msg = DepositsMessage::Recovery(RecoveryMsg::Vote {
            operator: test_pubkey(),
            partner: test_pubkey(),
            voter: test_pubkey(),
            is_conforming: true,
            validated_hash: [0xAB; 32],
            validated_sequence: 100,
            substitute_nomination: Some(test_pubkey()),
            discovered_violation: false,
            signature: [0xCD; 64],
        });

        let encoded = msg.encode();
        let decoded = DepositsMessage::decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_coordination_message_roundtrip() {
        let msg = DepositsMessage::Coordination(CoordinationMsg::CosignInvoice {
            operator_id: test_pubkey(),
            reserves_id: test_pubkey().to_string(),
            amount: 50000,
            payment_hash: [0x11; 32],
            expires: 1234567890,
            assigned_deposit: test_pubkey(),
            invoice_id: "inv123".to_string(),
            bolt11_invoice: "lnbc...".to_string(),
        });

        let encoded = msg.encode();
        let decoded = DepositsMessage::decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_all_message_types_are_odd() {
        // Per BOLT 1: odd types MAY be ignored if not understood
        let types = [
            LEDGER_UPDATE, LEDGER_UPDATE_RESPONSE,
            HANDSHAKE, HANDSHAKE_RESPONSE,
            SYNC, SYNC_RESPONSE,
            RECOVERY, RECOVERY_RESPONSE,
            COORDINATION, COORDINATION_RESPONSE,
        ];
        for t in types {
            assert!(t & 1 == 1, "Message type 0x{:04X} is not odd", t);
        }
    }

    // ========================================================================
    // TLV Roundtrip Tests
    // ========================================================================

    #[test]
    fn test_ledger_operation_tlv_roundtrip() {
        use crate::tlv::{TlvEncode, TlvDecode};

        let ops = vec![
            LedgerOperation::DepositOpen {
                deposit_id: crate::types::compute_deposit_id("pk(test)"),
                descriptor: "pk(test)".to_string(),
                fees: Some(FeeStructure::new(100, 10, 144)),
                transfer_fees: None,
                payment_hash: Some([0xAA; 32]),
                invoice: Some("lnbc...".to_string()),
                cosigner_guarantee_signature: None,
                is_collateral: false,
                receive_requires_sig: false,
                fee_change_after_blocks: Some(52560),
                fee_change_notice_blocks: Some(2016),
                fee_change_limit_bps: Some(1000),
            },
            LedgerOperation::DepositClose { deposit_id: crate::types::compute_deposit_id("pk(test)") },
            LedgerOperation::InvoiceCredit {
                payment_hash: [0xBB; 32],
                deposit_id: crate::types::compute_deposit_id("pk(test)"),
                amount: 50000,
                invoice_id: "inv123".to_string(),
                sequence_number: 1,
            },
            LedgerOperation::LedgerClose,
        ];

        for op in ops {
            let encoded = op.tlv_encode();
            let decoded = LedgerOperation::tlv_decode(&encoded).unwrap();
            assert_eq!(op, decoded, "TLV roundtrip failed for {:?}", op);
        }
    }

    #[test]
    fn test_ledger_update_msg_tlv_roundtrip() {
        use crate::tlv::{TlvEncode, TlvDecode};

        let msg = LedgerUpdateMsg {
            operator_id: test_pubkey(),
            reserves_id: test_pubkey().to_string(),
            operation: LedgerOperation::FeeCollect {
                deposit_id: crate::types::compute_deposit_id("pk(test)"),
                amount: 500,
                block_height: 800000,
            },
            sequence_number: 1,
            previous_hash: [0u8; 32],
            current_hash: [0xAB; 32],
            operator_signature: [0xCD; 64],
        };

        let encoded = msg.tlv_encode();
        let decoded = LedgerUpdateMsg::tlv_decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_ledger_update_response_msg_tlv_roundtrip() {
        use crate::tlv::{TlvEncode, TlvDecode};

        let msg = LedgerUpdateResponseMsg {
            operator_id: test_pubkey(),
            reserves_id: test_pubkey().to_string(),
            request_hash: [0xAA; 32],
            accepted: true,
            error: None,
            cosign_signature: Some([0xBB; 64]),
            confirmed_sequence: 5,
            confirmed_hash: [0xCC; 32],
        };

        let encoded = msg.tlv_encode();
        let decoded = LedgerUpdateResponseMsg::tlv_decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_handshake_msg_tlv_roundtrip() {
        use crate::tlv::{TlvEncode, TlvDecode};

        let msg = HandshakeMsg {
            protocol_version: PROTOCOL_VERSION,
            min_protocol_version: MIN_PROTOCOL_VERSION,
            features: 0,
            operator_id: test_pubkey(),
            reserves_id: test_pubkey().to_string(),
            funding_txid: [0x11; 32],
            funding_vout: 0,
        };

        let encoded = msg.tlv_encode();
        let decoded = HandshakeMsg::tlv_decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_handshake_response_msg_tlv_roundtrip() {
        use crate::tlv::{TlvEncode, TlvDecode};

        let msg = HandshakeResponseMsg {
            request_hash: [0xAA; 32],
            protocol_version: PROTOCOL_VERSION,
            accepted: true,
            error: None,
            reserves_id: test_pubkey().to_string(),
        };

        let encoded = msg.tlv_encode();
        let decoded = HandshakeResponseMsg::tlv_decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_sync_msg_tlv_roundtrip() {
        use crate::tlv::{TlvEncode, TlvDecode};

        let msg = SyncMsg {
            ledger_id: [0x12; 32],
            last_known_sequence: 5,
            last_known_hash: [0xAA; 32],
        };

        let encoded = msg.tlv_encode();
        let decoded = SyncMsg::tlv_decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_sync_response_msg_tlv_roundtrip() {
        use crate::tlv::{TlvEncode, TlvDecode};

        let mut update = SignedLedgerUpdate {
            // Valid TLV: tag=0 (discriminant), len=1, value=60 (LedgerClose)
            message: vec![0x00, 0x01, 60],
            message_type: LEDGER_CLOSE,
            operator_id: test_pubkey(),
            ledger_id: [0x12; 32],
            sequence_number: 1,
            previous_hash: [0xCC; 32],
            current_hash: [0u8; 32], // will be computed
            block_height: 12345,
            block_hash: [0x11; 32],
            cosign_signature: [0xFF; 64],
            operator_signature: [0xEE; 64],
            cosigner_pubkey: None,
            member_ledger_hash: None,
        };
        update.current_hash = update.compute_hash();

        let msg = SyncResponseMsg {
            ledger_id: [0x12; 32],
            request_hash: [0xAA; 32],
            updates: vec![update],
            current_sequence: 10,
            current_hash: [0xBB; 32],
        };

        let encoded = msg.tlv_encode();
        let decoded = SyncResponseMsg::tlv_decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_recovery_msg_tlv_roundtrip() {
        use crate::tlv::{TlvEncode, TlvDecode};

        let msgs = vec![
            RecoveryMsg::Vote {
                operator: test_pubkey(),
                partner: test_pubkey(),
                voter: test_pubkey(),
                is_conforming: true,
                validated_hash: [0xAA; 32],
                validated_sequence: 100,
                substitute_nomination: None,
                discovered_violation: false,
                signature: [0xBB; 64],
            },
            RecoveryMsg::ClaimRequest {
                operator: test_pubkey(),
                partner: test_pubkey(),
                claimant: test_pubkey(),
                tier_index: 1,
                unsigned_tx: vec![0xCC; 200],
                sighash: [0xDD; 32],
                destination_script: vec![0xEE; 25],
                block_height: 850000,
            },
        ];

        for msg in msgs {
            let encoded = msg.tlv_encode();
            let decoded = RecoveryMsg::tlv_decode(&encoded).unwrap();
            assert_eq!(msg, decoded);
        }
    }

    #[test]
    fn test_coordination_msg_tlv_roundtrip() {
        use crate::tlv::{TlvEncode, TlvDecode};

        let msgs = vec![
            CoordinationMsg::CosignInvoice {
                operator_id: test_pubkey(),
                reserves_id: test_pubkey().to_string(),
                amount: 100000,
                payment_hash: [0xAA; 32],
                expires: 1234567890,
                assigned_deposit: test_pubkey(),
                invoice_id: "inv123".to_string(),
                bolt11_invoice: "lnbc100...".to_string(),
            },
            CoordinationMsg::CollateralConsentRequest {
                operator_id: test_pubkey(),
                reserves_id: test_pubkey().to_string(),
                operator_signature: [0xBB; 64],
            },
            CoordinationMsg::QuorumVoteRequest {
                vote_round_id: [0xCC; 32],
                operator_id: test_pubkey(),
                reserves_id: test_pubkey().to_string(),
                sequence_number: 50,
                state_hash: [0xDD; 32],
                claimed_reserves: 500000,
                collateral_amounts: vec![100000, 200000, 150000],
                reserves_outpoint: vec![0xEE; 36],
                destination_script: vec![0xFF; 25],
                fee_rate_sat_vbyte: 5,
                timestamp: 1234567890,
            },
        ];

        for msg in msgs {
            let encoded = msg.tlv_encode();
            let decoded = CoordinationMsg::tlv_decode(&encoded).unwrap();
            assert_eq!(msg, decoded);
        }
    }

    #[test]
    fn test_coordination_response_msg_tlv_roundtrip() {
        use crate::tlv::{TlvEncode, TlvDecode};

        let msgs = vec![
            CoordinationResponseMsg::InvoiceCosigned {
                request_hash: [0xAA; 32],
                cosignature: [0xBB; 64],
            },
            CoordinationResponseMsg::QuorumJoinResponse {
                request_hash: [0xCC; 32],
                accepted: true,
                members: vec![test_pubkey(), test_pubkey()],
                threshold: 2,
                last_sequence: 100,
                current_hash: [0xDD; 32],
                rejection_reason: None,
            },
        ];

        for msg in msgs {
            let encoded = msg.tlv_encode();
            let decoded = CoordinationResponseMsg::tlv_decode(&encoded).unwrap();
            assert_eq!(msg, decoded);
        }
    }

    #[test]
    fn test_deposits_message_v2_tlv_roundtrip() {
        let messages = vec![
            DepositsMessage::LedgerUpdate(LedgerUpdateMsg {
                operator_id: test_pubkey(),
                reserves_id: test_pubkey().to_string(),
                operation: LedgerOperation::InvoiceCredit {
                    payment_hash: [0xAA; 32],
                    deposit_id: crate::types::compute_deposit_id("pk(test)"),
                    amount: 100000,
                    invoice_id: "inv123".to_string(),
                    sequence_number: 1,
                },
                sequence_number: 1,
                previous_hash: [0xBB; 32],
                current_hash: [0xCC; 32],
                operator_signature: [0xDD; 64],
            }),
            DepositsMessage::Handshake(HandshakeMsg {
                protocol_version: PROTOCOL_VERSION,
                min_protocol_version: 1,
                features: 0,
                operator_id: test_pubkey(),
                reserves_id: test_pubkey().to_string(),
                funding_txid: [0xEE; 32],
                funding_vout: 0,
            }),
            DepositsMessage::Sync(SyncMsg {
                ledger_id: [0x12; 32],
                last_known_sequence: 5,
                last_known_hash: [0xFF; 32],
            }),
        ];

        for msg in messages {
            let encoded = msg.tlv_encode();
            let decoded = DepositsMessage::tlv_decode(&encoded).unwrap();
            assert_eq!(msg, decoded);
        }
    }

    #[test]
    fn test_transfer_lock_wire_roundtrip() {
        let source_id = crate::types::compute_deposit_id("pk(alice)");
        let dest_id = crate::types::compute_deposit_id("pk(bob)");

        let op = LedgerOperation::TransferLock {
            nonce: [0x42u8; 32],
            source_deposit_id: source_id,
            destination_deposit_id: dest_id,
            amount: 100_000,
            fee: 1_000,
            completion_script: "sha256(deadbeef0123456789abcdef0123456789abcdef0123456789abcdef01234567)".to_string(),
            timeout_height: 850_000,
            transfer_id: [0xABu8; 32],
            witness: DescriptorWitness { stack: vec![[0x11u8; 64].to_vec()] },
        };

        let mut bytes = Vec::new();
        op.write_to(&mut bytes).unwrap();
        let decoded = LedgerOperation::read_from(&mut &bytes[..]).unwrap();

        // Wire encoding preserves source and dest deposit IDs
        if let LedgerOperation::TransferLock {
            nonce, source_deposit_id, destination_deposit_id, amount, fee,
            completion_script, timeout_height, transfer_id, witness
        } = decoded {
            assert_eq!(nonce, [0x42u8; 32]);
            assert_eq!(source_deposit_id, source_id);
            assert_eq!(destination_deposit_id, dest_id);
            assert_eq!(amount, 100_000);
            assert_eq!(fee, 1_000);
            assert_eq!(completion_script, "sha256(deadbeef0123456789abcdef0123456789abcdef0123456789abcdef01234567)");
            assert_eq!(timeout_height, 850_000);
            assert_eq!(transfer_id, [0xABu8; 32]);
            assert_eq!(witness.stack.len(), 1);
            assert_eq!(witness.stack[0].len(), 64);
        } else {
            panic!("Expected TransferLock");
        }
    }

    #[test]
    fn test_transfer_complete_wire_roundtrip() {
        let op = LedgerOperation::TransferComplete {
            transfer_id: [0xCDu8; 32],
            script_witness: DescriptorWitness {
                stack: vec![
                    [0x11u8; 32].to_vec(),  // preimage
                ],
            },
        };

        let mut bytes = Vec::new();
        op.write_to(&mut bytes).unwrap();
        let decoded = LedgerOperation::read_from(&mut &bytes[..]).unwrap();

        if let LedgerOperation::TransferComplete { transfer_id, script_witness } = decoded {
            assert_eq!(transfer_id, [0xCDu8; 32]);
            assert_eq!(script_witness.stack.len(), 1);
            assert_eq!(script_witness.stack[0], [0x11u8; 32].to_vec());
        } else {
            panic!("Expected TransferComplete");
        }
    }

    #[test]
    fn test_transfer_fail_wire_roundtrip() {
        let op = LedgerOperation::TransferFail {
            transfer_id: [0xEFu8; 32],
            block_hash: [0x99u8; 32],
            reason: 1,
        };

        let mut bytes = Vec::new();
        op.write_to(&mut bytes).unwrap();
        let decoded = LedgerOperation::read_from(&mut &bytes[..]).unwrap();

        assert_eq!(op, decoded);
    }

    #[test]
    fn test_transfer_lock_tlv_roundtrip() {
        let source_id = crate::types::compute_deposit_id("pk(source_key)");
        let dest_id = crate::types::compute_deposit_id("pk(dest_key)");

        let op = LedgerOperation::TransferLock {
            nonce: [0x55u8; 32],
            source_deposit_id: source_id,
            destination_deposit_id: dest_id,
            amount: 250_000,
            fee: 2_500,
            completion_script: "sha256(cafebabe)".to_string(),
            timeout_height: 900_000,
            transfer_id: [0x77u8; 32],
            witness: DescriptorWitness { stack: vec![[0x88u8; 64].to_vec()] },
        };

        let encoded = op.tlv_encode();
        let decoded = LedgerOperation::tlv_decode(&encoded).unwrap();

        if let LedgerOperation::TransferLock {
            nonce, source_deposit_id, destination_deposit_id, amount, fee,
            completion_script, timeout_height, transfer_id, witness
        } = decoded {
            assert_eq!(nonce, [0x55u8; 32]);
            assert_eq!(source_deposit_id, source_id);
            assert_eq!(destination_deposit_id, dest_id);
            assert_eq!(amount, 250_000);
            assert_eq!(fee, 2_500);
            assert_eq!(completion_script, "sha256(cafebabe)");
            assert_eq!(timeout_height, 900_000);
            assert_eq!(transfer_id, [0x77u8; 32]);
            assert_eq!(witness.stack.len(), 1);
        } else {
            panic!("Expected TransferLock");
        }
    }

    #[test]
    fn test_transfer_complete_tlv_roundtrip() {
        let op = LedgerOperation::TransferComplete {
            transfer_id: [0xAAu8; 32],
            script_witness: DescriptorWitness {
                stack: vec![
                    vec![1, 2, 3, 4],  // arbitrary witness data
                    vec![5, 6, 7, 8],
                ],
            },
        };

        let encoded = op.tlv_encode();
        let decoded = LedgerOperation::tlv_decode(&encoded).unwrap();

        if let LedgerOperation::TransferComplete { transfer_id, script_witness } = decoded {
            assert_eq!(transfer_id, [0xAAu8; 32]);
            assert_eq!(script_witness.stack.len(), 2);
            assert_eq!(script_witness.stack[0], vec![1, 2, 3, 4]);
            assert_eq!(script_witness.stack[1], vec![5, 6, 7, 8]);
        } else {
            panic!("Expected TransferComplete");
        }
    }

    #[test]
    fn test_transfer_fail_tlv_roundtrip() {
        let op = LedgerOperation::TransferFail {
            transfer_id: [0xBBu8; 32],
            block_hash: [0xCCu8; 32],
            reason: 1,
        };

        let encoded = op.tlv_encode();
        let decoded = LedgerOperation::tlv_decode(&encoded).unwrap();

        assert_eq!(op, decoded);
    }

    #[test]
    fn test_transfer_discriminants() {
        let source_id = crate::types::compute_deposit_id("pk(test)");
        let dest_id = crate::types::compute_deposit_id("pk(test2)");

        let lock = LedgerOperation::TransferLock {
            nonce: [0u8; 32],
            source_deposit_id: source_id,
            destination_deposit_id: dest_id,
            amount: 1000,
            fee: 10,
            completion_script: "sha256(00)".to_string(),
            timeout_height: 100,
            transfer_id: [0u8; 32],
            witness: DescriptorWitness { stack: vec![] },
        };

        let complete = LedgerOperation::TransferComplete {
            transfer_id: [0u8; 32],
            script_witness: DescriptorWitness { stack: vec![] },
        };

        let timeout = LedgerOperation::TransferFail {
            transfer_id: [0u8; 32],
            block_hash: [0u8; 32],
            reason: 1,
        };

        assert_eq!(lock.discriminant(), 70);
        assert_eq!(complete.discriminant(), 71);
        assert_eq!(timeout.discriminant(), 72);
    }
}
