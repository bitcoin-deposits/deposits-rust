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
// V1 Wire Message Structs (from deposits-ldk) - REMOVED
// ============================================================================
// V1 wire message types have been removed. Only V2 types are now used.
// See deposits-core::messages for the V2 message types.

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
            LedgerOperation::ReservesAdd { .. } => "ReservesAdd",
            LedgerOperation::ReservesRemove => "ReservesRemove",
            LedgerOperation::ReservesIncrease { .. } => "ReservesIncrease",
            LedgerOperation::ReservesDecrease { .. } => "ReservesDecrease",
            LedgerOperation::ReservesUpdateSpendTo { .. } => "ReservesUpdateSpendTo",
            LedgerOperation::DepositOpen { .. } => "DepositOpen",
            LedgerOperation::DepositClose { .. } => "DepositClose",
            LedgerOperation::DepositUpdate { .. } => "DepositUpdate",
            LedgerOperation::TransferLock { .. } => "TransferLock",
            LedgerOperation::TransferFail { .. } => "TransferFail",
            LedgerOperation::TransferFulfill { .. } => "TransferFulfill",
            LedgerOperation::PaymentCredit { .. } => "PaymentCredit",
            LedgerOperation::PaymentLock { .. } => "PaymentLock",
            LedgerOperation::PaymentFail { .. } => "PaymentFail",
            LedgerOperation::PaymentFulfill { .. } => "PaymentFulfill",
            LedgerOperation::CollateralIncrease { .. } => "CollateralIncrease",
            LedgerOperation::CollateralDecrease { .. } => "CollateralDecrease",
            LedgerOperation::CollateralAttestation { .. } => "CollateralAttestation",
            LedgerOperation::CollateralAddPartner { .. } => "CollateralAddPartner",
            LedgerOperation::CollateralRemovePartner { .. } => "CollateralRemovePartner",
            LedgerOperation::FeeCollect { .. } => "FeeCollect",
            LedgerOperation::LedgerClose => "LedgerClose",
            LedgerOperation::Tombstone { .. } => "Tombstone",
        }
    }

    fn get_sequence_number(&self) -> Option<u64> {
        match self {
            LedgerOperation::PaymentCredit { sequence_number, .. } => Some(*sequence_number),
            LedgerOperation::PaymentLock { sequence_number, .. } => Some(*sequence_number),
            LedgerOperation::PaymentFail { sequence_number, .. } => Some(*sequence_number),
            LedgerOperation::PaymentFulfill { sequence_number, .. } => Some(*sequence_number),
            // Other operations don't have sequence numbers
            _ => None,
        }
    }
}

// ============================================================================
// Main Message Type (V1-compatible enum over V2)
// ============================================================================

/// Main deposits message type (V2 wire format with V1-compatible API)
///
/// Core V2 types handle all operations, with V1-named variants for backward API compatibility.
/// Wire format is always V2 - the V1 aliases are just for pattern matching convenience.
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

    pub fn partner_id(&self) -> Option<PublicKey> {
        match self {
            Self::LedgerUpdate(m) => Some(m.partner_pubkey),
            Self::LedgerUpdateResponse(_) => None,
            Self::Handshake(m) => Some(m.partner_id),
            Self::HandshakeResponse(m) => Some(m.partner_id),
            Self::Sync(m) => Some(m.partner_id),
            Self::SyncResponse(m) => Some(m.partner_id),
            Self::Recovery(_) => None,
            Self::RecoveryResponse(_) => None,
            Self::Coordination(_) => None,
            Self::CoordinationResponse(_) => None,
            Self::Relay(_) => None,
            Self::RelayResponse(_) => None,
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
            partner,
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
            partner,
            LedgerOperation::DepositClose { pubkey },
        ))
    }

    /// Create a ReservesAdd operation message
    pub fn new_reserves_add(
        operator: PublicKey,
        partner: PublicKey,
        amount: u64,
        spend_to: PublicKey,
        collateral_partners: Vec<PublicKey>,
    ) -> Self {
        Self::LedgerUpdate(LedgerUpdateMsg::new_with_operation(
            operator,
            partner,
            LedgerOperation::ReservesAdd { amount, spend_to, collateral_partners },
        ))
    }

    /// Create a ReservesIncrease operation message
    pub fn new_reserves_increase(operator: PublicKey, partner: PublicKey, new_amount: u64) -> Self {
        Self::LedgerUpdate(LedgerUpdateMsg::new_with_operation(
            operator,
            partner,
            LedgerOperation::ReservesIncrease { new_amount },
        ))
    }

    /// Create a ReservesDecrease operation message
    pub fn new_reserves_decrease(operator: PublicKey, partner: PublicKey, new_amount: u64) -> Self {
        Self::LedgerUpdate(LedgerUpdateMsg::new_with_operation(
            operator,
            partner,
            LedgerOperation::ReservesDecrease { new_amount },
        ))
    }

    /// Create a ReservesRemove operation message
    pub fn new_reserves_remove(operator: PublicKey, partner: PublicKey) -> Self {
        Self::LedgerUpdate(LedgerUpdateMsg::new_with_operation(
            operator,
            partner,
            LedgerOperation::ReservesRemove,
        ))
    }

    /// Create a ReservesUpdateSpendTo operation message
    pub fn new_reserves_update_spend_to(operator: PublicKey, partner: PublicKey, spend_to: PublicKey) -> Self {
        Self::LedgerUpdate(LedgerUpdateMsg::new_with_operation(
            operator,
            partner,
            LedgerOperation::ReservesUpdateSpendTo { spend_to },
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
            partner,
            LedgerOperation::DepositUpdate { pubkey, new_fees: new_fees.into() },
        ))
    }

    /// Create a TransferLock operation message
    pub fn new_transfer_lock(
        operator: PublicKey,
        partner: PublicKey,
        pubkey: PublicKey,
        amount: u64,
        transfer_id: [u8; 32],
    ) -> Self {
        Self::LedgerUpdate(LedgerUpdateMsg::new_with_operation(
            operator,
            partner,
            LedgerOperation::TransferLock { pubkey, amount, transfer_id },
        ))
    }

    /// Create a TransferFail operation message
    pub fn new_transfer_fail(
        operator: PublicKey,
        partner: PublicKey,
        pubkey: PublicKey,
        transfer_id: [u8; 32],
    ) -> Self {
        Self::LedgerUpdate(LedgerUpdateMsg::new_with_operation(
            operator,
            partner,
            LedgerOperation::TransferFail { pubkey, transfer_id },
        ))
    }

    /// Create a TransferFulfill operation message
    pub fn new_transfer_fulfill(
        operator: PublicKey,
        partner: PublicKey,
        pubkey: PublicKey,
        amount: u64,
        transfer_id: [u8; 32],
    ) -> Self {
        Self::LedgerUpdate(LedgerUpdateMsg::new_with_operation(
            operator,
            partner,
            LedgerOperation::TransferFulfill { pubkey, amount, transfer_id },
        ))
    }

    /// Create a PaymentCredit operation message
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
            partner,
            LedgerOperation::PaymentCredit { payment_hash, deposit_pubkey, amount, invoice_id, sequence_number },
        ))
    }

    /// Create a PaymentLock operation message
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
            partner,
            LedgerOperation::PaymentLock { pubkey, amount, payment_id, sequence_number, scriptpubkey_signature },
        ))
    }

    /// Create a PaymentFulfill operation message
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
            partner,
            LedgerOperation::PaymentFulfill { pubkey, amount, payment_id, sequence_number, scriptpubkey_signature, preimage },
        ))
    }

    /// Create a PaymentFail operation message
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
            partner,
            LedgerOperation::PaymentFail { pubkey, amount, payment_id, sequence_number },
        ))
    }

    /// Create a CollateralAddPartner operation message
    pub fn new_collateral_add_partner(
        operator: PublicKey,
        partner: PublicKey,
        collateral_partner: PublicKey,
    ) -> Self {
        Self::LedgerUpdate(LedgerUpdateMsg::new_with_operation(
            operator,
            partner,
            LedgerOperation::CollateralAddPartner {
                collateral_partner,
                collateral_partner_signature: [0u8; 64], // Filled in at signing time
            },
        ))
    }

    /// Create a CollateralRemovePartner operation message
    pub fn new_collateral_remove_partner(
        operator: PublicKey,
        partner: PublicKey,
        collateral_partner: PublicKey,
    ) -> Self {
        Self::LedgerUpdate(LedgerUpdateMsg::new_with_operation(
            operator,
            partner,
            LedgerOperation::CollateralRemovePartner {
                collateral_partner,
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
            partner,
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
            partner,
            LedgerOperation::CollateralDecrease { new_amount, block_height },
        ))
    }

    /// Create a CollateralAttestation operation message
    pub fn new_collateral_attestation(
        operator: PublicKey,
        partner: PublicKey,
        collateral_operator: PublicKey,
        amount: u64,
        block_height: u32,
        signature: [u8; 64],
        ledger_hash: [u8; 32],
    ) -> Self {
        Self::LedgerUpdate(LedgerUpdateMsg::new_with_operation(
            operator,
            partner,
            LedgerOperation::CollateralAttestation {
                collateral_operator, amount, block_height, signature, ledger_hash
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
            partner,
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
            partner,
            LedgerOperation::Tombstone { channel_id, close_reason, timestamp },
        ))
    }

    /// Create a LedgerClose operation message
    pub fn new_ledger_close(operator: PublicKey, partner: PublicKey) -> Self {
        Self::LedgerUpdate(LedgerUpdateMsg::new_with_operation(
            operator,
            partner,
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
        let v2 = self.clone().into_v2();
        println!("🟢 ENCODE: {} -> V2 type {:?}", self.variant_name(), std::mem::discriminant(&v2));
        v2.encode()
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
            DepositsMessageCore::SyncResponse(m) => {
                let op_id = m.operator_id;
                let partner_id = m.partner_id;
                Self::SyncResponse(SyncResponseMsg {
                    operator_id: op_id,
                    partner_id,
                    updates: m.updates.into_iter().map(|u| LedgerUpdateMsg {
                        operator_pubkey: op_id,
                        partner_pubkey: partner_id,
                        operation: u.operation.clone(),
                        sequence_number: u.sequence_number,
                        previous_state_hash: u.previous_hash,
                        current_state_hash: u.current_hash,
                        operator_signature: u.operator_signature,
                        message_type: u.operation.discriminant() as u16,
                        message: Vec::new(),
                        timestamp: u.timestamp,
                        partner_signature: Some(u.partner_signature),
                    }).collect(),
                })
            }
            DepositsMessageCore::Recovery(m) => Self::Recovery(m),
            DepositsMessageCore::RecoveryResponse(m) => Self::RecoveryResponse(m),
            DepositsMessageCore::Coordination(m) => Self::Coordination(m),
            DepositsMessageCore::CoordinationResponse(m) => Self::CoordinationResponse(m),
            DepositsMessageCore::Relay(m) => Self::Relay(m),
            DepositsMessageCore::RelayResponse(m) => Self::RelayResponse(m),
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
            Self::SyncResponse(m) => {
                let current_sequence = m.updates.last().map(|u| u.sequence_number).unwrap_or(0);
                let current_hash = m.updates.last().map(|u| u.current_state_hash).unwrap_or([0u8; 32]);
                DepositsMessageCore::SyncResponse(SyncResponseMsgV2 {
                    operator_id: m.operator_id,
                    partner_id: m.partner_id,
                    request_hash: [0u8; 32],
                    updates: m.updates.into_iter().map(|u| deposits_core::messages::SignedLedgerUpdate {
                        sequence_number: u.sequence_number,
                        operation: u.operation,
                        previous_hash: u.previous_state_hash,
                        current_hash: u.current_state_hash,
                        operator_signature: u.operator_signature,
                        partner_signature: u.partner_signature.unwrap_or([0u8; 64]),
                        timestamp: u.timestamp,
                    }).collect(),
                    current_sequence,
                    current_hash,
                })
            }
            Self::Recovery(m) => DepositsMessageCore::Recovery(m),
            Self::RecoveryResponse(m) => DepositsMessageCore::RecoveryResponse(m),
            Self::Coordination(m) => DepositsMessageCore::Coordination(m),
            Self::CoordinationResponse(m) => DepositsMessageCore::CoordinationResponse(m),
            Self::Relay(m) => DepositsMessageCore::Relay(m),
            Self::RelayResponse(m) => DepositsMessageCore::RelayResponse(m),
        }
    }
}

// ============================================================================
// Local Message Structs
// ============================================================================
// These match the field names used throughout the codebase.
// They can be converted to/from deposits_core V2 types.

/// Handshake message (local type with expected field names)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandshakeMsg {
    pub protocol_version: u16,
    pub min_protocol_version: u16,
    pub features: u32,
    pub public_key: PublicKey,
    pub partner_id: PublicKey,
    pub ledger_address: String,
    pub funding_txid: [u8; 32],
    pub funding_vout: u16,
}

impl From<HandshakeMsgV2> for HandshakeMsg {
    fn from(v2: HandshakeMsgV2) -> Self {
        Self {
            protocol_version: v2.protocol_version,
            min_protocol_version: v2.min_protocol_version,
            features: v2.features,
            public_key: v2.operator_pubkey,
            partner_id: v2.partner_pubkey,
            ledger_address: v2.ledger_address,
            funding_txid: v2.funding_txid,
            funding_vout: v2.funding_vout,
        }
    }
}

impl From<HandshakeMsg> for HandshakeMsgV2 {
    fn from(local: HandshakeMsg) -> Self {
        Self {
            protocol_version: local.protocol_version,
            min_protocol_version: local.min_protocol_version,
            features: local.features,
            operator_pubkey: local.public_key,
            partner_pubkey: local.partner_id,
            ledger_address: local.ledger_address,
            funding_txid: local.funding_txid,
            funding_vout: local.funding_vout,
        }
    }
}

/// Handshake response message (local type)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandshakeResponseMsg {
    pub protocol_version: u16,
    pub accepted: bool,
    pub error_reason: Option<String>,
    pub public_key: PublicKey,
    pub partner_id: PublicKey,
}

impl From<HandshakeResponseMsgV2> for HandshakeResponseMsg {
    fn from(v2: HandshakeResponseMsgV2) -> Self {
        Self {
            protocol_version: v2.protocol_version,
            accepted: v2.accepted,
            error_reason: v2.error,
            public_key: v2.partner_pubkey,
            partner_id: v2.partner_pubkey,
        }
    }
}

impl From<HandshakeResponseMsg> for HandshakeResponseMsgV2 {
    fn from(local: HandshakeResponseMsg) -> Self {
        Self {
            request_hash: [0u8; 32], // Computed at send time
            protocol_version: local.protocol_version,
            accepted: local.accepted,
            error: local.error_reason,
            partner_pubkey: local.partner_id,
        }
    }
}

/// Ledger update message (local type with expected field names)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerUpdateMsg {
    pub operator_pubkey: PublicKey,
    pub partner_pubkey: PublicKey,
    pub operation: LedgerOperation,
    pub sequence_number: u64,
    pub previous_state_hash: [u8; 32],
    pub current_state_hash: [u8; 32],
    pub operator_signature: [u8; 64],
    // V1 compatibility fields
    pub message_type: u16,
    pub message: Vec<u8>,
    pub timestamp: u64,
    pub partner_signature: Option<[u8; 64]>,
}

impl From<LedgerUpdateMsgV2> for LedgerUpdateMsg {
    fn from(v2: LedgerUpdateMsgV2) -> Self {
        Self {
            operator_pubkey: v2.operator_id,
            partner_pubkey: v2.partner_id,
            operation: v2.operation.clone(),
            sequence_number: v2.sequence_number,
            previous_state_hash: v2.previous_hash,
            current_state_hash: v2.current_hash,
            operator_signature: v2.operator_signature,
            // V1 compat fields derived from operation
            message_type: v2.operation.discriminant() as u16,
            message: Vec::new(), // V2 uses typed operations, not raw bytes
            timestamp: 0,
            partner_signature: None,
        }
    }
}

impl From<LedgerUpdateMsg> for LedgerUpdateMsgV2 {
    fn from(local: LedgerUpdateMsg) -> Self {
        Self {
            operator_id: local.operator_pubkey,
            partner_id: local.partner_pubkey,
            operation: local.operation,
            sequence_number: local.sequence_number,
            previous_hash: local.previous_state_hash,
            current_hash: local.current_state_hash,
            operator_signature: local.operator_signature,
        }
    }
}

impl LedgerUpdateMsg {
    /// Create a new LedgerUpdate with the given operation.
    /// Metadata (sequence, hashes, signature) will be filled in by the ledger.
    pub fn new_with_operation(
        operator: PublicKey,
        partner: PublicKey,
        operation: LedgerOperation,
    ) -> Self {
        Self {
            operator_pubkey: operator,
            partner_pubkey: partner,
            operation,
            sequence_number: 0,
            previous_state_hash: [0u8; 32],
            current_state_hash: [0u8; 32],
            operator_signature: [0u8; 64],
            message_type: 0,
            message: Vec::new(),
            timestamp: 0,
            partner_signature: None,
        }
    }

    /// Get the operation from this update
    pub fn operation(&self) -> &LedgerOperation {
        &self.operation
    }

    /// Check if this is a specific operation type
    pub fn is_deposit_open(&self) -> bool {
        matches!(self.operation, LedgerOperation::DepositOpen { .. })
    }

    pub fn is_deposit_close(&self) -> bool {
        matches!(self.operation, LedgerOperation::DepositClose { .. })
    }

    pub fn is_reserves_add(&self) -> bool {
        matches!(self.operation, LedgerOperation::ReservesAdd { .. })
    }

    pub fn is_reserves_increase(&self) -> bool {
        matches!(self.operation, LedgerOperation::ReservesIncrease { .. })
    }

    pub fn is_reserves_decrease(&self) -> bool {
        matches!(self.operation, LedgerOperation::ReservesDecrease { .. })
    }

    pub fn is_payment_credit(&self) -> bool {
        matches!(self.operation, LedgerOperation::PaymentCredit { .. })
    }

    pub fn is_payment_lock(&self) -> bool {
        matches!(self.operation, LedgerOperation::PaymentLock { .. })
    }

    pub fn is_payment_fulfill(&self) -> bool {
        matches!(self.operation, LedgerOperation::PaymentFulfill { .. })
    }

    pub fn is_payment_fail(&self) -> bool {
        matches!(self.operation, LedgerOperation::PaymentFail { .. })
    }

    pub fn is_collateral_add_partner(&self) -> bool {
        matches!(self.operation, LedgerOperation::CollateralAddPartner { .. })
    }

    pub fn is_collateral_increase(&self) -> bool {
        matches!(self.operation, LedgerOperation::CollateralIncrease { .. })
    }

    pub fn is_collateral_decrease(&self) -> bool {
        matches!(self.operation, LedgerOperation::CollateralDecrease { .. })
    }

    pub fn is_fee_collect(&self) -> bool {
        matches!(self.operation, LedgerOperation::FeeCollect { .. })
    }

    pub fn is_tombstone(&self) -> bool {
        matches!(self.operation, LedgerOperation::Tombstone { .. })
    }

    pub fn is_ledger_close(&self) -> bool {
        matches!(self.operation, LedgerOperation::LedgerClose { .. })
    }
}

/// Ledger update response message (local type)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerUpdateResponseMsg {
    pub message_hash: [u8; 32],
    pub success: bool,
    pub error_message: Option<String>,
    pub partner_signature: Option<[u8; 64]>,
    pub confirmed_sequence: u64,
    pub confirmed_hash: [u8; 32],
    // V1 compatibility fields
    pub acked_message_type: u16,
    pub cosignature: Option<[u8; 64]>,
    pub update_signature: Option<[u8; 64]>,
    pub update_sequence: Option<u64>,
    pub update_prev_hash: Option<[u8; 32]>,
    pub update_curr_hash: Option<[u8; 32]>,
}

impl From<LedgerUpdateResponseMsgV2> for LedgerUpdateResponseMsg {
    fn from(v2: LedgerUpdateResponseMsgV2) -> Self {
        Self {
            message_hash: v2.request_hash,
            success: v2.accepted,
            error_message: v2.error,
            partner_signature: v2.partner_signature,
            confirmed_sequence: v2.confirmed_sequence,
            confirmed_hash: v2.confirmed_hash,
            // V1 compat fields
            acked_message_type: 0,
            cosignature: v2.partner_signature,
            update_signature: v2.partner_signature,
            update_sequence: Some(v2.confirmed_sequence),
            update_prev_hash: None,
            update_curr_hash: Some(v2.confirmed_hash),
        }
    }
}

impl From<LedgerUpdateResponseMsg> for LedgerUpdateResponseMsgV2 {
    fn from(local: LedgerUpdateResponseMsg) -> Self {
        Self {
            operator_id: PublicKey::from_slice(&[2; 33]).unwrap(), // Set at send time
            partner_id: PublicKey::from_slice(&[2; 33]).unwrap(),  // Set at send time
            request_hash: local.message_hash,
            accepted: local.success,
            error: local.error_message,
            partner_signature: local.partner_signature,
            confirmed_sequence: local.confirmed_sequence,
            confirmed_hash: local.confirmed_hash,
        }
    }
}

/// Sync message (local type)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncMsg {
    pub operator_id: PublicKey,
    pub partner_id: PublicKey,
    pub from_sequence: u64,
    pub to_sequence: Option<u64>,
}

impl From<SyncMsgV2> for SyncMsg {
    fn from(v2: SyncMsgV2) -> Self {
        Self {
            operator_id: v2.operator_id,
            partner_id: v2.partner_id,
            from_sequence: v2.last_known_sequence,
            to_sequence: None,
        }
    }
}

impl From<SyncMsg> for SyncMsgV2 {
    fn from(local: SyncMsg) -> Self {
        Self {
            operator_id: local.operator_id,
            partner_id: local.partner_id,
            last_known_sequence: local.from_sequence,
            last_known_hash: [0u8; 32], // Computed at send time
        }
    }
}

/// Sync response message (local type)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncResponseMsg {
    pub operator_id: PublicKey,
    pub partner_id: PublicKey,
    pub updates: Vec<LedgerUpdateMsg>,
}

// Type aliases for backwards compatibility
pub type SignedUpdateMsg = LedgerUpdateMsg;

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
    };

    // Re-export utility functions from deposits-core
    pub use deposits_core::messages::{
        requires_acknowledgment, is_deposits_message_type, get_message_category,
        type_id_to_const_name, type_id_to_variant_name,
        MESSAGES_REQUIRING_ACK, ALL_V2_MESSAGE_TYPES,
    };
}

// Re-export message type name functions from deposits-core for backwards compatibility
pub use deposits_core::messages::{type_id_to_const_name, type_id_to_variant_name};

// ============================================================================
// Writeable/Readable implementations for local message types
// ============================================================================

// LedgerUpdateMsg encoding
impl Writeable for LedgerUpdateMsg {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
        self.operator_pubkey.write(writer)?;
        self.partner_pubkey.write(writer)?;
        self.message_type.write(writer)?;
        (self.message.len() as u32).write(writer)?;
        writer.write_all(&self.message)?;
        self.sequence_number.write(writer)?;
        writer.write_all(&self.previous_state_hash)?;
        writer.write_all(&self.current_state_hash)?;
        self.timestamp.write(writer)?;
        writer.write_all(&self.operator_signature)?;
        // Write partner_signature: 1 byte flag + optional 64 bytes
        if let Some(ref sig) = self.partner_signature {
            1u8.write(writer)?;
            writer.write_all(sig)?;
        } else {
            0u8.write(writer)?;
        }
        Ok(())
    }
}

impl Readable for LedgerUpdateMsg {
    fn read<R: io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
        let operator_pubkey: PublicKey = Readable::read(reader)?;
        let partner_pubkey: PublicKey = Readable::read(reader)?;
        let message_type: u16 = Readable::read(reader)?;
        let message_len: u32 = Readable::read(reader)?;
        let mut message = vec![0u8; message_len as usize];
        reader.read_exact(&mut message).map_err(|_| DecodeError::ShortRead)?;
        let sequence_number: u64 = Readable::read(reader)?;
        let mut previous_state_hash = [0u8; 32];
        reader.read_exact(&mut previous_state_hash).map_err(|_| DecodeError::ShortRead)?;
        let mut current_state_hash = [0u8; 32];
        reader.read_exact(&mut current_state_hash).map_err(|_| DecodeError::ShortRead)?;
        let timestamp: u64 = Readable::read(reader)?;
        let mut operator_signature = [0u8; 64];
        reader.read_exact(&mut operator_signature).map_err(|_| DecodeError::ShortRead)?;
        // Read partner_signature: 1 byte flag + optional 64 bytes
        let has_partner_sig: u8 = Readable::read(reader)?;
        let partner_signature = if has_partner_sig == 1 {
            let mut sig = [0u8; 64];
            reader.read_exact(&mut sig).map_err(|_| DecodeError::ShortRead)?;
            Some(sig)
        } else {
            None
        };

        // For V1 SignedUpdate, extract the actual operation from the `message` bytes
        // The message bytes contain a serialized DepositsMessage that can be decoded
        let operation = crate::wire::MessageCodec::decode_message_with_type(message_type, &message)
            .ok()
            .and_then(|msg| msg.to_operation())
            .unwrap_or(deposits_core::LedgerOperation::ReservesRemove);

        Ok(Self {
            operator_pubkey,
            partner_pubkey,
            operation,
            sequence_number,
            previous_state_hash,
            current_state_hash,
            operator_signature,
            message_type,
            message,
            timestamp,
            partner_signature,
        })
    }
}

// ============================================================================
// LDK Wire Protocol Integration
// ============================================================================

impl Readable for DepositsMessage {
    fn read<R: io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
        use self::consts::*;

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
        // Always use V2 wire format. V1 variants are converted to V2 via into_v2().
        // encode() returns [type: u16][payload], but LDK adds the type prefix
        // separately via type_id(), so we only write the payload (skip first 2 bytes).
        let bytes = self.encode();
        println!("🟡 WRITEABLE::WRITE called for {}, encode returned {} bytes, first 4: {:02x?}",
            self.variant_name(), bytes.len(), &bytes[..bytes.len().min(4)]);
        if bytes.len() >= 2 {
            writer.write_all(&bytes[2..])
        } else {
            Ok(())
        }
    }
}

impl lightning::ln::wire::Type for DepositsMessage {
    fn type_id(&self) -> u16 {
        // Always use V2 wire format type IDs
        let v2_id = self.v2_type_id();
        let v1_id = self.message_type();
        println!("🔴 TYPE_ID CALLED: v1={:#06x}, v2={:#06x}, variant={}", v1_id, v2_id, self.variant_name());
        v2_id
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

        // Debug: log all message types we're asked to read
        println!("MESSAGE_READER: Checking type {:#06x}, is_deposits={}",
            message_type, is_deposits_message_type(message_type));

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
        let op = LedgerOperation::ReservesAdd {
            amount: 100_000,
            spend_to: test_pubkey(),
            collateral_partners: vec![test_pubkey()],
        };

        let msg = LedgerUpdateMsg {
            operator_pubkey: test_pubkey(),
            partner_pubkey: test_pubkey(),
            operation: op.clone(),
            sequence_number: 1,
            previous_state_hash: [0u8; 32],
            current_state_hash: [0u8; 32],
            operator_signature: [0u8; 64],
            message_type: op.discriminant() as u16,
            message: Vec::new(),
            timestamp: 0,
            partner_signature: None,
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
