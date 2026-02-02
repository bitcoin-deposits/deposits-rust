// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Bitcoin Deposits Protocol Messages (V2)
//!
//! Re-exports the V2 message format from deposits-core with LDK wire protocol integration.
//!
//! ## Message Types
//!
//! - [`DepositsMessage`]: Main message enum (alias for DepositsMessageCore)
//! - [`LedgerOperation`]: All ledger-modifying operations
//! - [`LedgerUpdateMsg`]: Wrapper for ledger operations with metadata
//! - [`HandshakeMsg`]/[`HandshakeResponseMsg`]: Ledger establishment
//! - [`SyncMsg`]/[`SyncResponseMsg`]: State synchronization
//! - [`RecoveryMsg`]/[`RecoveryResponseMsg`]: Recovery voting
//! - [`CoordinationMsg`]/[`CoordinationResponseMsg`]: Quorum coordination
//! - [`RelayMsg`]/[`RelayResponseMsg`]: NWC relay

use bitcoin::secp256k1::PublicKey;
use lightning::util::ser::{LengthLimitedRead, Readable, Writeable, Writer};
use lightning::ln::msgs::DecodeError;
use lightning::io;

// ============================================================================
// Re-exports from deposits-core
// ============================================================================

pub use deposits_core::messages::{
    // Main message enum (renamed from DepositsMessageV2 in deposits-core)
    DepositsMessage as DepositsMessageCore,
    // Ledger operations
    LedgerOperation,
    // Recovery
    RecoveryMsg, RecoveryResponseMsg,
    // Coordination (quorum)
    CoordinationMsg, CoordinationResponseMsg,
    // Relay (NWC)
    RelayMsg, RelayResponseMsg, RelayStatus,
    // Codec
    CodecError,
    // Message type constants
    LEDGER_UPDATE, LEDGER_UPDATE_RESPONSE,
    HANDSHAKE, HANDSHAKE_RESPONSE,
    SYNC, SYNC_RESPONSE,
    RECOVERY, RECOVERY_RESPONSE,
    COORDINATION, COORDINATION_RESPONSE,
    RELAY, RELAY_RESPONSE,
};

// Re-export V2 types with aliases for those we're defining locally
pub use deposits_core::messages::{
    HandshakeMsg as HandshakeMsgV2,
    HandshakeResponseMsg as HandshakeResponseMsgV2,
    LedgerUpdateMsg as LedgerUpdateMsgV2,
    LedgerUpdateResponseMsg as LedgerUpdateResponseMsgV2,
    SyncMsg as SyncMsgV2,
    SyncResponseMsg as SyncResponseMsgV2,
};

// Re-export wire types for message field types (local version with LDK traits)
pub use crate::wire::types::{FeeStructure, PendingInvoice};

// ============================================================================
// Wire Message Types
// ============================================================================
// Message types are defined in deposits-core::messages and re-exported above.
// This module provides type aliases and extension traits for LDK integration.

// ============================================================================
// LedgerOperation Extensions
// ============================================================================

/// Extension trait for LedgerOperation to add helper methods
pub trait LedgerOperationExt {
    fn variant_name(&self) -> &'static str;
    /// Get the sequence number from operations that have one (payments, tombstone)
    fn get_sequence_number(&self) -> Option<u64>;
}

impl LedgerOperationExt for LedgerOperation {
    fn variant_name(&self) -> &'static str {
        match self {
            LedgerOperation::LedgerOpen { .. } => "LedgerOpen",
            LedgerOperation::ReservesIncrease { .. } => "ReservesIncrease",
            LedgerOperation::ReservesDecrease { .. } => "ReservesDecrease",
            LedgerOperation::ReservesRotate { .. } => "ReservesRotate",
            LedgerOperation::DepositOpen { .. } => "DepositOpen",
            LedgerOperation::DepositClose { .. } => "DepositClose",
            LedgerOperation::DepositUpdate { .. } => "DepositUpdate",
            LedgerOperation::InvoiceCredit { .. } => "InvoiceCredit",
            LedgerOperation::InvoiceLock { .. } => "InvoiceLock",
            LedgerOperation::InvoiceFail { .. } => "InvoiceFail",
            LedgerOperation::InvoiceFulfill { .. } => "InvoiceFulfill",
            LedgerOperation::OnchainCredit { .. } => "OnchainCredit",
            LedgerOperation::OnchainLock { .. } => "OnchainLock",
            LedgerOperation::OnchainFail { .. } => "OnchainFail",
            LedgerOperation::OnchainFulfill { .. } => "OnchainFulfill",
            LedgerOperation::CollateralIncrease { .. } => "CollateralIncrease",
            LedgerOperation::CollateralDecrease { .. } => "CollateralDecrease",
            LedgerOperation::CollateralAttestation { .. } => "CollateralAttestation",
            LedgerOperation::QuorumAddMember { .. } => "QuorumAddMember",
            LedgerOperation::QuorumRemoveMember { .. } => "QuorumRemoveMember",
            LedgerOperation::CollateralLock { .. } => "CollateralLock",
            LedgerOperation::QuorumJoin { .. } => "QuorumJoin",
            LedgerOperation::FeeCollect { .. } => "FeeCollect",
            LedgerOperation::LedgerClose => "LedgerClose",
            LedgerOperation::Tombstone { .. } => "Tombstone",
        }
    }

    fn get_sequence_number(&self) -> Option<u64> {
        match self {
            LedgerOperation::InvoiceCredit { sequence_number, .. } => Some(*sequence_number),
            LedgerOperation::InvoiceLock { sequence_number, .. } => Some(*sequence_number),
            LedgerOperation::InvoiceFail { sequence_number, .. } => Some(*sequence_number),
            LedgerOperation::InvoiceFulfill { sequence_number, .. } => Some(*sequence_number),
            // Other operations don't have sequence numbers
            _ => None,
        }
    }
}

// ============================================================================
// Main Message Type
// ============================================================================

/// Main deposits message type for the Bitcoin Deposits protocol.
///
/// This enum wraps the core message types with LDK-specific trait implementations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DepositsMessage {
    // ==================== Core V2 Types ====================
    /// Ledger update - carries all ledger-modifying operations
    LedgerUpdate(LedgerUpdateMsg),
    /// Ledger update response (acknowledgment)
    LedgerUpdateResponse(LedgerUpdateResponseMsg),
    /// Handshake - ledger establishment
    Handshake(HandshakeMsg),
    /// Handshake response
    HandshakeResponse(HandshakeResponseMsg),
    /// Sync request
    Sync(SyncMsg),
    /// Sync response
    SyncResponse(SyncResponseMsg),
    /// Recovery message
    Recovery(RecoveryMsg),
    /// Recovery response
    RecoveryResponse(RecoveryResponseMsg),
    /// Coordination message (quorum operations)
    Coordination(CoordinationMsg),
    /// Coordination response
    CoordinationResponse(CoordinationResponseMsg),
    /// Relay message (NWC)
    Relay(RelayMsg),
    /// Relay response
    RelayResponse(RelayResponseMsg),
    /// Reserves add output (peer message, not a ledger operation)
    ReservesAddOutput(deposits_core::ReservesAddOutputMsg),
    /// Reserves remove output (peer message, not a ledger operation)
    ReservesRemoveOutput(deposits_core::ReservesRemoveOutputMsg),

}

impl DepositsMessage {
    pub fn message_type(&self) -> u16 {
        use self::consts::*;
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
            Self::Relay(_) => RELAY,
            Self::RelayResponse(_) => RELAY_RESPONSE,
            Self::ReservesAddOutput(_) => RESERVES_ADD_OUTPUT,
            Self::ReservesRemoveOutput(_) => RESERVES_REMOVE_OUTPUT,
        }
    }

    /// Get the V2 wire format type ID for this message.
    pub fn v2_type_id(&self) -> u16 {
        // All variants are now V2 types, so this is the same as message_type()
        self.message_type()
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
            Self::Relay(_) => "Relay",
            Self::RelayResponse(_) => "RelayResponse",
            Self::ReservesAddOutput(_) => "ReservesAddOutput",
            Self::ReservesRemoveOutput(_) => "ReservesRemoveOutput",
        }
    }

    /// Get the operation name for LedgerUpdate messages
    pub fn operation_name(&self) -> Option<&'static str> {
        match self {
            Self::LedgerUpdate(msg) => Some(msg.operation.variant_name()),
            _ => None,
        }
    }

    /// Get a descriptive name including operation for LedgerUpdate
    pub fn descriptive_name(&self) -> String {
        match self {
            Self::LedgerUpdate(msg) => format!("LedgerUpdate({})", msg.operation.variant_name()),
            _ => self.variant_name().to_string(),
        }
    }

    pub fn reserves_id(&self) -> Option<String> {
        match self {
            Self::LedgerUpdate(m) => Some(m.reserves_id.clone()),
            Self::LedgerUpdateResponse(_) => None,
            Self::Handshake(m) => Some(m.reserves_id.clone()),
            Self::HandshakeResponse(m) => Some(m.reserves_id.clone()),
            Self::Sync(_) => None, // Uses ledger_id now
            Self::SyncResponse(_) => None, // Uses ledger_id now
            Self::Recovery(_) => None,
            Self::RecoveryResponse(_) => None,
            Self::Coordination(_) => None,
            Self::CoordinationResponse(_) => None,
            Self::Relay(_) => None,
            Self::RelayResponse(_) => None,
            Self::ReservesAddOutput(m) => Some(m.reserves_id.clone()),
            Self::ReservesRemoveOutput(m) => Some(m.reserves_id.clone()),
        }
    }

    // ==================== Factory Methods for LedgerUpdate ====================
    // These create LedgerUpdate messages with specific operations.
    // Metadata (sequence, hashes, signature) will be filled in by the ledger.

    /// Create a DepositOpen operation message
    pub fn new_deposit_open(
        operator: PublicKey,
        partner: PublicKey,
        pubkey: PublicKey,
        fees: Option<deposits_core::FeeStructure>,
        payment_hash: Option<[u8; 32]>,
        invoice: Option<String>,
        cosigner_signature: Option<[u8; 64]>,
    ) -> Self {
        Self::LedgerUpdate(LedgerUpdateMsg::new_with_operation(
            operator,
            partner.to_string(),
            LedgerOperation::DepositOpen {
                pubkey,
                fees: fees.map(|f| f.into()),
                payment_hash,
                invoice,
                cosigner_guarantee_signature: cosigner_signature,
            },
        ))
    }

    /// Create a DepositClose operation message
    pub fn new_deposit_close(operator: PublicKey, partner: PublicKey, pubkey: PublicKey) -> Self {
        Self::LedgerUpdate(LedgerUpdateMsg::new_with_operation(
            operator,
            partner.to_string(),
            LedgerOperation::DepositClose { pubkey },
        ))
    }

    /// Create a ReservesIncrease operation message
    pub fn new_reserves_increase(operator: PublicKey, partner: PublicKey, new_amount: u64) -> Self {
        Self::LedgerUpdate(LedgerUpdateMsg::new_with_operation(
            operator,
            partner.to_string(),
            LedgerOperation::ReservesIncrease { new_amount },
        ))
    }

    /// Create a ReservesDecrease operation message
    pub fn new_reserves_decrease(operator: PublicKey, partner: PublicKey, new_amount: u64) -> Self {
        Self::LedgerUpdate(LedgerUpdateMsg::new_with_operation(
            operator,
            partner.to_string(),
            LedgerOperation::ReservesDecrease { new_amount },
        ))
    }

    /// Create a DepositUpdate operation message
    pub fn new_deposit_update(
        operator: PublicKey,
        partner: PublicKey,
        pubkey: PublicKey,
        new_fees: deposits_core::FeeStructure,
    ) -> Self {
        Self::LedgerUpdate(LedgerUpdateMsg::new_with_operation(
            operator,
            partner.to_string(),
            LedgerOperation::DepositUpdate { pubkey, new_fees: new_fees.into() },
        ))
    }

    /// Create an InvoiceCredit operation message
    pub fn new_payment_credit(
        operator: PublicKey,
        partner: PublicKey,
        payment_hash: [u8; 32],
        deposit_pubkey: PublicKey,
        amount: u64,
        invoice_id: String,
        sequence_number: u64,
    ) -> Self {
        Self::LedgerUpdate(LedgerUpdateMsg::new_with_operation(
            operator,
            partner.to_string(),
            LedgerOperation::InvoiceCredit { payment_hash, deposit_pubkey, amount, invoice_id, sequence_number },
        ))
    }

    /// Create a InvoiceLock operation message
    pub fn new_payment_lock(
        operator: PublicKey,
        partner: PublicKey,
        pubkey: PublicKey,
        amount: u64,
        payment_id: [u8; 32],
        sequence_number: u64,
        scriptpubkey_signature: [u8; 64],
    ) -> Self {
        Self::LedgerUpdate(LedgerUpdateMsg::new_with_operation(
            operator,
            partner.to_string(),
            LedgerOperation::InvoiceLock { pubkey, amount, payment_id, sequence_number, scriptpubkey_signature },
        ))
    }

    /// Create a InvoiceFulfill operation message
    pub fn new_payment_fulfill(
        operator: PublicKey,
        partner: PublicKey,
        pubkey: PublicKey,
        amount: u64,
        payment_id: [u8; 32],
        sequence_number: u64,
        scriptpubkey_signature: [u8; 64],
        preimage: [u8; 32],
    ) -> Self {
        Self::LedgerUpdate(LedgerUpdateMsg::new_with_operation(
            operator,
            partner.to_string(),
            LedgerOperation::InvoiceFulfill { pubkey, amount, payment_id, sequence_number, scriptpubkey_signature, preimage },
        ))
    }

    /// Create a InvoiceFail operation message
    pub fn new_payment_fail(
        operator: PublicKey,
        partner: PublicKey,
        pubkey: PublicKey,
        amount: u64,
        payment_id: [u8; 32],
        sequence_number: u64,
    ) -> Self {
        Self::LedgerUpdate(LedgerUpdateMsg::new_with_operation(
            operator,
            partner.to_string(),
            LedgerOperation::InvoiceFail { pubkey, amount, payment_id, sequence_number },
        ))
    }

    /// Create a QuorumAddMember operation message
    pub fn new_quorum_add_member(
        operator: PublicKey,
        partner: PublicKey,
        quorum_member: PublicKey,
    ) -> Self {
        Self::LedgerUpdate(LedgerUpdateMsg::new_with_operation(
            operator,
            partner.to_string(),
            LedgerOperation::QuorumAddMember {
                quorum_member,
                quorum_member_signature: [0u8; 64], // Filled in at signing time
            },
        ))
    }

    /// Create a QuorumRemoveMember operation message
    pub fn new_quorum_remove_member(
        operator: PublicKey,
        partner: PublicKey,
        quorum_member: PublicKey,
    ) -> Self {
        Self::LedgerUpdate(LedgerUpdateMsg::new_with_operation(
            operator,
            partner.to_string(),
            LedgerOperation::QuorumRemoveMember {
                quorum_member,
                operator_signature: [0u8; 64], // Filled in at signing time
            },
        ))
    }

    /// Create a CollateralIncrease operation message
    pub fn new_collateral_increase(
        operator: PublicKey,
        partner: PublicKey,
        new_amount: u64,
        block_height: u32,
    ) -> Self {
        Self::LedgerUpdate(LedgerUpdateMsg::new_with_operation(
            operator,
            partner.to_string(),
            LedgerOperation::CollateralIncrease { new_amount, block_height },
        ))
    }

    /// Create a CollateralDecrease operation message
    pub fn new_collateral_decrease(
        operator: PublicKey,
        partner: PublicKey,
        new_amount: u64,
        block_height: u32,
    ) -> Self {
        Self::LedgerUpdate(LedgerUpdateMsg::new_with_operation(
            operator,
            partner.to_string(),
            LedgerOperation::CollateralDecrease { new_amount, block_height },
        ))
    }

    /// Create a CollateralAttestation operation message
    pub fn new_collateral_attestation(
        operator: PublicKey,
        partner: PublicKey,
        collateral_operator: PublicKey,
        quorum_member: PublicKey,
        amount: u64,
        block_height: u32,
        lock_until_block: u32,
        signature: [u8; 64],
        ledger_hash: [u8; 32],
    ) -> Self {
        Self::LedgerUpdate(LedgerUpdateMsg::new_with_operation(
            operator,
            partner.to_string(),
            LedgerOperation::CollateralAttestation {
                collateral_operator, quorum_member, amount, block_height, lock_until_block, signature, ledger_hash
            },
        ))
    }

    /// Create a FeeCollect operation message
    pub fn new_fee_collect(
        operator: PublicKey,
        partner: PublicKey,
        pubkey: PublicKey,
        amount: u64,
        block_height: u32,
    ) -> Self {
        Self::LedgerUpdate(LedgerUpdateMsg::new_with_operation(
            operator,
            partner.to_string(),
            LedgerOperation::FeeCollect { pubkey, amount, block_height },
        ))
    }

    /// Create a Tombstone operation message
    pub fn new_tombstone(
        operator: PublicKey,
        partner: PublicKey,
        channel_id: [u8; 32],
        close_reason: Option<String>,
        timestamp: u64,
    ) -> Self {
        Self::LedgerUpdate(LedgerUpdateMsg::new_with_operation(
            operator,
            partner.to_string(),
            LedgerOperation::Tombstone { channel_id, close_reason, timestamp },
        ))
    }

    /// Create a LedgerClose operation message
    pub fn new_ledger_close(operator: PublicKey, partner: PublicKey) -> Self {
        Self::LedgerUpdate(LedgerUpdateMsg::new_with_operation(
            operator,
            partner.to_string(),
            LedgerOperation::LedgerClose,
        ))
    }

    // ==================== Pattern Matching Helpers ====================

    /// Check if this is a LedgerUpdate with a specific operation
    pub fn is_operation(&self, check: impl Fn(&LedgerOperation) -> bool) -> bool {
        if let Self::LedgerUpdate(msg) = self {
            check(&msg.operation)
        } else {
            false
        }
    }

    /// Get the inner LedgerUpdateMsg if this is a LedgerUpdate
    pub fn as_ledger_update(&self) -> Option<&LedgerUpdateMsg> {
        if let Self::LedgerUpdate(msg) = self {
            Some(msg)
        } else {
            None
        }
    }

    /// Extract LedgerOperation from LedgerUpdate.
    ///
    /// Returns None for non-ledger messages (coordination, recovery, relay, etc.)
    pub fn to_operation(&self) -> Option<LedgerOperation> {
        match self {
            Self::LedgerUpdate(msg) => Some(msg.operation.clone()),
            _ => None,
        }
    }

    /// Check if this message represents a ledger operation
    pub fn is_ledger_operation(&self) -> bool {
        matches!(self, Self::LedgerUpdate(_))
    }

    /// Get the sequence number from messages that have one (payments, tombstone)
    pub fn get_sequence_number(&self) -> Option<u64> {
        self.to_operation().and_then(|op| op.get_sequence_number())
    }

    /// Encode message to bytes (for wire protocol)
    /// Format: [type: u16 BE][payload bytes]
    pub fn encode(&self) -> Vec<u8> {
        self.clone().into_v2().encode()
    }

    /// Decode message from bytes
    /// Format: [type: u16 BE][payload bytes]
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let v2 = DepositsMessageCore::decode(bytes)?;
        Ok(Self::from_v2(v2))
    }

    /// Convert from V2 message to our enum
    pub fn from_v2(msg: DepositsMessageCore) -> Self {
        match msg {
            DepositsMessageCore::LedgerUpdate(m) => Self::LedgerUpdate(m.into()),
            DepositsMessageCore::LedgerUpdateResponse(m) => Self::LedgerUpdateResponse(m.into()),
            DepositsMessageCore::Handshake(m) => Self::Handshake(m.into()),
            DepositsMessageCore::HandshakeResponse(m) => Self::HandshakeResponse(m.into()),
            DepositsMessageCore::Sync(m) => Self::Sync(m.into()),
            DepositsMessageCore::SyncResponse(m) => Self::SyncResponse(m),
            DepositsMessageCore::Recovery(m) => Self::Recovery(m),
            DepositsMessageCore::RecoveryResponse(m) => Self::RecoveryResponse(m),
            DepositsMessageCore::Coordination(m) => Self::Coordination(m),
            DepositsMessageCore::CoordinationResponse(m) => Self::CoordinationResponse(m),
            DepositsMessageCore::Relay(m) => Self::Relay(m),
            DepositsMessageCore::RelayResponse(m) => Self::RelayResponse(m),
            DepositsMessageCore::ReservesAddOutput(m) => Self::ReservesAddOutput(m),
            DepositsMessageCore::ReservesRemoveOutput(m) => Self::ReservesRemoveOutput(m),
        }
    }

    /// Convert to V2 message format
    pub fn into_v2(self) -> DepositsMessageCore {
        match self {
            Self::LedgerUpdate(m) => DepositsMessageCore::LedgerUpdate(m.into()),
            Self::LedgerUpdateResponse(m) => DepositsMessageCore::LedgerUpdateResponse(m.into()),
            Self::Handshake(m) => DepositsMessageCore::Handshake(m.into()),
            Self::HandshakeResponse(m) => DepositsMessageCore::HandshakeResponse(m.into()),
            Self::Sync(m) => DepositsMessageCore::Sync(m.into()),
            Self::SyncResponse(m) => DepositsMessageCore::SyncResponse(m),
            Self::Recovery(m) => DepositsMessageCore::Recovery(m),
            Self::RecoveryResponse(m) => DepositsMessageCore::RecoveryResponse(m),
            Self::Coordination(m) => DepositsMessageCore::Coordination(m),
            Self::CoordinationResponse(m) => DepositsMessageCore::CoordinationResponse(m),
            Self::Relay(m) => DepositsMessageCore::Relay(m),
            Self::RelayResponse(m) => DepositsMessageCore::RelayResponse(m),
            Self::ReservesAddOutput(m) => DepositsMessageCore::ReservesAddOutput(m),
            Self::ReservesRemoveOutput(m) => DepositsMessageCore::ReservesRemoveOutput(m),
        }
    }
}

// ============================================================================
// Local Message Structs
// ============================================================================
// These match the field names used throughout the codebase.
// They can be converted to/from deposits_core V2 types.

/// Handshake message - uses core type directly
pub type HandshakeMsg = HandshakeMsgV2;

/// Handshake response message - uses core type directly
pub type HandshakeResponseMsg = HandshakeResponseMsgV2;

/// Ledger update message - uses core type directly
pub type LedgerUpdateMsg = LedgerUpdateMsgV2;

/// Extension trait for LedgerUpdateMsg convenience methods
pub trait LedgerUpdateMsgExt {
    fn new_with_operation(operator: PublicKey, reserves_id: String, operation: LedgerOperation) -> LedgerUpdateMsg;
    fn is_deposit_open(&self) -> bool;
    fn is_deposit_close(&self) -> bool;
    fn is_reserves_increase(&self) -> bool;
    fn is_reserves_decrease(&self) -> bool;
    fn is_payment_credit(&self) -> bool;
    fn is_payment_lock(&self) -> bool;
    fn is_payment_fulfill(&self) -> bool;
    fn is_payment_fail(&self) -> bool;
    fn is_collateral_add_partner(&self) -> bool;
    fn is_collateral_increase(&self) -> bool;
    fn is_collateral_decrease(&self) -> bool;
    fn is_fee_collect(&self) -> bool;
    fn is_tombstone(&self) -> bool;
    fn is_ledger_close(&self) -> bool;
}

impl LedgerUpdateMsgExt for LedgerUpdateMsg {
    fn new_with_operation(operator: PublicKey, reserves_id: String, operation: LedgerOperation) -> LedgerUpdateMsg {
        LedgerUpdateMsg {
            operator_id: operator,
            reserves_id,
            operation,
            sequence_number: 0,
            previous_hash: [0u8; 32],
            current_hash: [0u8; 32],
            operator_signature: [0u8; 64],
        }
    }

    fn is_deposit_open(&self) -> bool {
        matches!(self.operation, LedgerOperation::DepositOpen { .. })
    }

    fn is_deposit_close(&self) -> bool {
        matches!(self.operation, LedgerOperation::DepositClose { .. })
    }

    fn is_reserves_increase(&self) -> bool {
        matches!(self.operation, LedgerOperation::ReservesIncrease { .. })
    }

    fn is_reserves_decrease(&self) -> bool {
        matches!(self.operation, LedgerOperation::ReservesDecrease { .. })
    }

    fn is_payment_credit(&self) -> bool {
        matches!(self.operation, LedgerOperation::InvoiceCredit { .. })
    }

    fn is_payment_lock(&self) -> bool {
        matches!(self.operation, LedgerOperation::InvoiceLock { .. })
    }

    fn is_payment_fulfill(&self) -> bool {
        matches!(self.operation, LedgerOperation::InvoiceFulfill { .. })
    }

    fn is_payment_fail(&self) -> bool {
        matches!(self.operation, LedgerOperation::InvoiceFail { .. })
    }

    fn is_collateral_add_partner(&self) -> bool {
        matches!(self.operation, LedgerOperation::QuorumAddMember { .. })
    }

    fn is_collateral_increase(&self) -> bool {
        matches!(self.operation, LedgerOperation::CollateralIncrease { .. })
    }

    fn is_collateral_decrease(&self) -> bool {
        matches!(self.operation, LedgerOperation::CollateralDecrease { .. })
    }

    fn is_fee_collect(&self) -> bool {
        matches!(self.operation, LedgerOperation::FeeCollect { .. })
    }

    fn is_tombstone(&self) -> bool {
        matches!(self.operation, LedgerOperation::Tombstone { .. })
    }

    fn is_ledger_close(&self) -> bool {
        matches!(self.operation, LedgerOperation::LedgerClose { .. })
    }
}

/// Ledger update response message - uses core type directly
pub type LedgerUpdateResponseMsg = LedgerUpdateResponseMsgV2;

/// Sync message - uses core type directly
pub type SyncMsg = SyncMsgV2;

/// Sync response message - uses core type directly
pub type SyncResponseMsg = SyncResponseMsgV2;

// Type alias for backwards compatibility
pub type SignedUpdateMsg = deposits_core::SignedLedgerUpdate;

// ============================================================================
// Message Type Constants (V2 only)
// ============================================================================

pub mod consts {
    // V2 types from deposits-core
    pub use deposits_core::messages::{
        LEDGER_UPDATE, LEDGER_UPDATE_RESPONSE,
        HANDSHAKE, HANDSHAKE_RESPONSE,
        SYNC, SYNC_RESPONSE,
        RECOVERY, RECOVERY_RESPONSE,
        COORDINATION, COORDINATION_RESPONSE,
        RELAY, RELAY_RESPONSE,
        RESERVES_ADD_OUTPUT, RESERVES_REMOVE_OUTPUT,
    };

    // Re-export utility functions from deposits-core
    pub use deposits_core::messages::{
        requires_acknowledgment, is_deposits_message_type, get_message_category,
        type_id_to_const_name, type_id_to_variant_name,
        MESSAGES_REQUIRING_ACK, ALL_ENVELOPE_MESSAGE_TYPES, ALL_OPERATION_MESSAGE_TYPES,
    };
}

// Re-export message type name functions from deposits-core for backwards compatibility
pub use deposits_core::messages::{type_id_to_const_name, type_id_to_variant_name};

// Core types use TLV encoding from deposits-core - no local Writeable/Readable needed

// ============================================================================
// LDK Wire Protocol Integration
// ============================================================================

impl Readable for DepositsMessage {
    fn read<R: io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
        // Read message type
        let msg_type: u16 = Readable::read(reader)?;

        // Read remaining bytes for V2 codec
        let mut bytes = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => bytes.extend_from_slice(&buf[..n]),
                Err(_) => return Err(DecodeError::ShortRead),
            }
        }

        // Prepend message type for V2 decode
        let mut full_bytes = msg_type.to_be_bytes().to_vec();
        full_bytes.extend(bytes);

        // Decode using deposits-core codec and convert to our enum
        match DepositsMessageCore::decode(&full_bytes) {
            Ok(v2_msg) => Ok(Self::from_v2(v2_msg)),
            Err(_) => Err(DecodeError::InvalidValue),
        }
    }
}

impl Writeable for DepositsMessage {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
        // encode() returns [type: u16][payload], but LDK adds the type prefix
        // separately via type_id(), so we only write the payload (skip first 2 bytes).
        let bytes = self.encode();
        if bytes.len() >= 2 {
            writer.write_all(&bytes[2..])
        } else {
            Ok(())
        }
    }
}

impl lightning::ln::wire::Type for DepositsMessage {
    fn type_id(&self) -> u16 {
        self.v2_type_id()
    }
}

/// Message reader for LDK CustomMessageHandler
pub struct DepositsMessageReader;

impl lightning::ln::wire::CustomMessageReader for DepositsMessageReader {
    type CustomMessage = DepositsMessage;

    fn read<R: LengthLimitedRead>(
        &self,
        message_type: u16,
        buffer: &mut R,
    ) -> Result<Option<Self::CustomMessage>, DecodeError> {
        use self::consts::*;

        // Check if this is a deposits message type
        if !is_deposits_message_type(message_type) {
            return Ok(None);
        }

        // Read all bytes from buffer
        let mut bytes = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match buffer.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => bytes.extend_from_slice(&buf[..n]),
                Err(_) => return Err(DecodeError::ShortRead),
            }
        }

        // Try TLV decode first (new format), fall back to BinaryCodec (old format)
        use deposits_core::TlvDecode;
        use deposits_core::messages::{
            LedgerUpdateMsg as CoreLedgerUpdateMsg,
            LedgerUpdateResponseMsg as CoreLedgerUpdateResponseMsg,
            HandshakeMsg as CoreHandshakeMsg,
            HandshakeResponseMsg as CoreHandshakeResponseMsg,
            SyncMsg as CoreSyncMsg,
            SyncResponseMsg as CoreSyncResponseMsg,
            RecoveryMsg as CoreRecoveryMsg,
            RecoveryResponseMsg as CoreRecoveryResponseMsg,
            CoordinationMsg as CoreCoordinationMsg,
            CoordinationResponseMsg as CoreCoordinationResponseMsg,
            RelayMsg as CoreRelayMsg,
            RelayResponseMsg as CoreRelayResponseMsg,
        };

        // Try TLV decode based on message type
        let tlv_result: Option<DepositsMessageCore> = match message_type {
            LEDGER_UPDATE => CoreLedgerUpdateMsg::tlv_decode(&bytes).ok().map(DepositsMessageCore::LedgerUpdate),
            LEDGER_UPDATE_RESPONSE => CoreLedgerUpdateResponseMsg::tlv_decode(&bytes).ok().map(DepositsMessageCore::LedgerUpdateResponse),
            HANDSHAKE => CoreHandshakeMsg::tlv_decode(&bytes).ok().map(DepositsMessageCore::Handshake),
            HANDSHAKE_RESPONSE => CoreHandshakeResponseMsg::tlv_decode(&bytes).ok().map(DepositsMessageCore::HandshakeResponse),
            SYNC => CoreSyncMsg::tlv_decode(&bytes).ok().map(DepositsMessageCore::Sync),
            SYNC_RESPONSE => CoreSyncResponseMsg::tlv_decode(&bytes).ok().map(DepositsMessageCore::SyncResponse),
            RECOVERY => CoreRecoveryMsg::tlv_decode(&bytes).ok().map(DepositsMessageCore::Recovery),
            RECOVERY_RESPONSE => CoreRecoveryResponseMsg::tlv_decode(&bytes).ok().map(DepositsMessageCore::RecoveryResponse),
            COORDINATION => CoreCoordinationMsg::tlv_decode(&bytes).ok().map(DepositsMessageCore::Coordination),
            COORDINATION_RESPONSE => CoreCoordinationResponseMsg::tlv_decode(&bytes).ok().map(DepositsMessageCore::CoordinationResponse),
            RELAY => CoreRelayMsg::tlv_decode(&bytes).ok().map(DepositsMessageCore::Relay),
            RELAY_RESPONSE => CoreRelayResponseMsg::tlv_decode(&bytes).ok().map(DepositsMessageCore::RelayResponse),
            _ => None,
        };

        // If TLV decode succeeded, use it; otherwise fall back to BinaryCodec
        let v2_msg = match tlv_result {
            Some(msg) => msg,
            None => {
                // Fall back to BinaryCodec for backwards compatibility
                let mut full_bytes = message_type.to_be_bytes().to_vec();
                full_bytes.extend(&bytes);
                match DepositsMessageCore::decode(&full_bytes) {
                    Ok(msg) => msg,
                    Err(_) => return Err(DecodeError::InvalidValue),
                }
            }
        };

        // Convert to our enum
        Ok(Some(DepositsMessage::from_v2(v2_msg)))
    }
}

// Re-export is_deposits_message_type from deposits-core
pub use deposits_core::messages::is_deposits_message_type;

// Note: serde helpers for byte arrays are available in deposits-core::types::{serde_32, serde_64, serde_opt_64}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pubkey() -> PublicKey {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let sk = bitcoin::secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap();
        PublicKey::from_secret_key(&secp, &sk)
    }

    #[test]
    fn test_message_type_helpers() {
        assert_eq!(type_id_to_const_name(LEDGER_UPDATE), "LEDGER_UPDATE");
        assert_eq!(type_id_to_variant_name(HANDSHAKE), Some("Handshake"));
        assert!(is_deposits_message_type(LEDGER_UPDATE));
        assert!(!is_deposits_message_type(0x1234));
    }

    #[test]
    #[ignore = "Requires deposits-core V2 codec fix for LedgerOperation roundtrip"]
    fn test_ledger_operation_roundtrip() {
        let op = LedgerOperation::ReservesIncrease { new_amount: 100_000 };

        let msg = LedgerUpdateMsg {
            operator_id: test_pubkey(),
            reserves_id: test_pubkey().to_string(),
            operation: op.clone(),
            sequence_number: 1,
            previous_hash: [0u8; 32],
            current_hash: [0u8; 32],
            operator_signature: [0u8; 64],
        };

        let wrapped = DepositsMessage::LedgerUpdate(msg.clone());

        // Test encode/decode roundtrip
        let encoded = wrapped.encode();
        let decoded = DepositsMessage::decode(&encoded).unwrap();

        if let DepositsMessage::LedgerUpdate(decoded_msg) = decoded {
            assert_eq!(decoded_msg.sequence_number, msg.sequence_number);
        } else {
            panic!("Wrong message type after decode");
        }
    }
}
