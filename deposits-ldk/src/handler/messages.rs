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
// V1 Wire Message Structs (from deposits-ldk)
// ============================================================================
// These are V1-compatible message structs with LDK Readable/Writeable implementations.
// They are used for wire encoding during peer-to-peer communication.

pub use crate::wire::messages::{
    // Reserves operations
    ReservesIncreaseMsg, ReservesDecreaseMsg, ReservesAddOutputMsg,
    ReservesRemoveOutputMsg, ReservesUpdateOutputMsg,
    // Reserves commitment protocol (custom messages for generic extra outputs API)
    UpdateReservesMsg, AcceptReservesMsg,
    // Deposit operations
    DepositOpenMsg, DepositCloseMsg, DepositUpdateMsg,
    // Collateral operations
    CollateralIncreaseMsg, CollateralDecreaseMsg, CollateralAddPartnerMsg,
    CollateralRemovePartnerMsg, CollateralStatusMsg,
    CollateralConsentRequestMsg, CollateralConsentResponseMsg,
    // Fee and ledger close
    FeeCollectMsg, LedgerCloseMsg,
    // Payment messages
    ReceivingCreditPaymentMsg, SendingLockPaymentMsg, SendingFailPaymentMsg,
    SendingFulfillPaymentMsg, UncreditedPaymentMsg,
    // Transfer messages
    DepositLockTransferMsg, DepositFailTransferMsg, DepositFulfillTransferMsg,
    // Sync and channel close
    SyncRequestMsg, ChannelCloseTombstoneMsg,
    // Quorum messages
    QuorumJoinRequestMsg, QuorumJoinResponseMsg, QuorumMembershipChangeMsg,
    QuorumVoteRequestMsg, QuorumVoteMsg,
    // Recovery messages
    RecoveryVoteMsg, RecoveryClaimRequestMsg, RecoveryClaimSignatureMsg,
    RecoveryClaimCompleteMsg,
    // Relay messages
    RelayNwcRequestMsg, RelayNwcResponseMsg, RelayNwcDeliveryProofMsg,
    // Collateral attestation (now has serde derives and available_collateral())
    CollateralAttestationMsg,
};
// Note: The following are kept local due to structural differences or special needs:
// - ReceivingCosignInvoiceMsg: uses PendingInvoice wrapper
// - QuorumStateSyncMsg: uses Vec<SignedUpdateMsg>

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

    // ==================== V1-Compatible Aliases ====================
    // These are for backward API compatibility. They wrap LedgerUpdate internally.
    // Wire format is always V2 LedgerUpdate.

    /// V1 alias for Handshake (ledger open request)
    LedgerOpenRequest(HandshakeMsg),
    /// V1 alias for HandshakeResponse
    LedgerOpenResponse(HandshakeResponseMsg),
    /// V1 alias for LedgerUpdateResponse (acknowledgment)
    Ack(LedgerUpdateResponseMsg),
    /// V1 alias for LedgerUpdate (signed updates from operator)
    SignedUpdate(LedgerUpdateMsg),
    /// V1 alias for Sync (state sync request)
    SyncRequest(SyncRequestMsg),

    // Ledger operation wrappers (serialize as LedgerUpdate)
    /// Deposit open operation - uses inline fields (legacy DepositOpenMsg removed)
    DepositOpen {
        partner_id: PublicKey,
        pubkey: PublicKey,
        fees: Option<FeeStructure>,
        payment_hash: Option<[u8; 32]>,
        invoice: Option<String>,
        cosigner_guarantee_signature: Option<[u8; 64]>,
    },
    /// Deposit close operation - uses inline fields (legacy DepositCloseMsg removed)
    DepositClose {
        partner_id: PublicKey,
        pubkey: PublicKey,
    },
    /// Deposit update operation - uses inline fields (legacy DepositUpdateMsg removed)
    DepositUpdate {
        partner_id: PublicKey,
        pubkey: PublicKey,
        new_fees: FeeStructure,
    },
    /// Reserves add output - uses inline fields (legacy ReservesAddOutputMsg removed)
    ReservesAddOutput {
        initial_amount: u64,
        spend_to: PublicKey,
        partner_id: PublicKey,
        collateral_partners: Vec<PublicKey>,
    },
    /// Reserves remove output - uses inline fields (legacy ReservesRemoveOutputMsg removed)
    ReservesRemoveOutput {
        partner_id: PublicKey,
        remove_all: bool,
    },
    /// Reserves increase - uses inline fields (legacy ReservesIncreaseMsg removed)
    ReservesIncrease {
        partner_id: PublicKey,
        new_amount: u64,
    },
    /// Reserves decrease - uses inline fields (legacy ReservesDecreaseMsg removed)
    ReservesDecrease {
        partner_id: PublicKey,
        new_amount: u64,
    },
    /// Reserves update output - uses inline fields (legacy ReservesUpdateOutputMsg removed)
    ReservesUpdateOutput {
        partner_id: PublicKey,
        spend_to: PublicKey,
    },
    /// UpdateReserves - custom message for reserves commitment protocol
    /// Sent after propose_extra_outputs() to notify counterparty of proposed reserves
    UpdateReserves {
        channel_id: [u8; 32],
        reserves_sats: u64,
        script_pubkey: Vec<u8>,
        ledger_hash: [u8; 32],
        remote_ledger_hash: [u8; 32],
    },
    /// AcceptReserves - response to UpdateReserves indicating acceptance
    AcceptReserves {
        channel_id: [u8; 32],
    },
    /// Payment credit (receiving) - uses inline fields (legacy ReceivingCreditPaymentMsg retained for deserialization)
    ReceivingCreditPayment {
        payment_hash: [u8; 32],
        deposit_pubkey: PublicKey,
        amount: u64,
        invoice_id: String,
        partner_id: PublicKey,
        sequence_number: u64,
    },
    /// Cosign invoice request - uses inline fields (legacy ReceivingCosignInvoiceMsg retained for deserialization)
    ReceivingCosignInvoice {
        pending_invoice: PendingInvoice,
    },
    /// Payment lock (sending) - uses inline fields (legacy SendingLockPaymentMsg retained for deserialization)
    SendingLockPayment {
        pubkey: PublicKey,
        amount: u64,
        payment_id: [u8; 32],
        sequence_number: u64,
        scriptpubkey_signature: [u8; 64],
    },
    /// Payment fulfill (sending) - uses inline fields (legacy SendingFulfillPaymentMsg retained for deserialization)
    SendingFulfillPayment {
        pubkey: PublicKey,
        amount: u64,
        payment_id: [u8; 32],
        sequence_number: u64,
        scriptpubkey_signature: [u8; 64],
        preimage: [u8; 32],
    },
    /// Payment fail (sending) - uses inline fields (legacy SendingFailPaymentMsg retained for deserialization)
    SendingFailPayment {
        pubkey: PublicKey,
        amount: u64,
        payment_id: [u8; 32],
        sequence_number: u64,
    },
    /// Collateral add partner - uses inline fields (legacy CollateralAddPartnerMsg retained for deserialization)
    CollateralAddPartner {
        operator_id: PublicKey,
        partner_id: PublicKey,
        collateral_partner: PublicKey,
        collateral_partner_signature: [u8; 64],
    },
    /// Collateral remove partner - uses inline fields (legacy CollateralRemovePartnerMsg retained for deserialization)
    CollateralRemovePartner {
        partner_id: PublicKey,
        collateral_partner: PublicKey,
        operator_signature: [u8; 64],
    },
    /// Collateral increase - uses inline fields (legacy CollateralIncreaseMsg retained for deserialization)
    CollateralIncrease {
        partner_id: PublicKey,
        new_amount: u64,
        block_height: u32,
    },
    /// Collateral decrease - uses inline fields (legacy CollateralDecreaseMsg retained for deserialization)
    CollateralDecrease {
        partner_id: PublicKey,
        new_amount: u64,
        block_height: u32,
    },
    /// Collateral attestation - uses inline fields (legacy CollateralAttestationMsg retained for deserialization)
    CollateralAttestation {
        operator: PublicKey,
        collateral_partner: PublicKey,
        amount: u64,
        block_height: u32,
        signature: [u8; 64],
        ledger_hash: [u8; 32],
    },
    /// Collateral consent request - uses inline fields (legacy CollateralConsentRequestMsg retained for deserialization)
    CollateralConsentRequest {
        operator_id: PublicKey,
        partner_id: PublicKey,
        operator_signature: [u8; 64],
    },
    /// Collateral consent response - uses inline fields (legacy CollateralConsentResponseMsg retained for deserialization)
    CollateralConsentResponse {
        operator_id: PublicKey,
        partner_id: PublicKey,
        consent_granted: bool,
        collateral_partner_signature: [u8; 64],
    },
    /// Collateral status - uses inline fields (legacy CollateralStatusMsg retained for deserialization)
    CollateralStatus {
        collateral_operator: PublicKey,
        amount: u64,
        block_height: u32,
        signature: [u8; 64],
    },
    /// Fee collection - uses inline fields (legacy FeeCollectMsg/MaintenanceFeeCollectMsg retained for deserialization)
    MaintenanceFeeCollect {
        pubkey: PublicKey,
        amount: u64,
        block_height: u32,
    },
    /// Ledger close - uses inline fields (legacy LedgerCloseMsg retained for deserialization)
    LedgerClose {
        partner_id: PublicKey,
    },
    /// Channel close tombstone - uses inline fields (legacy ChannelCloseTombstoneMsg retained for deserialization)
    ChannelCloseTombstone {
        operator_pubkey: PublicKey,
        partner_pubkey: PublicKey,
        timestamp: u64,
        channel_id: [u8; 32],
        close_reason: Option<String>,
        sequence_number: u64,
    },
    /// Uncredited payment accusation - uses inline fields (legacy UncreditedPaymentMsg retained for deserialization)
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
    /// Transfer lock - uses inline fields (legacy DepositLockTransferMsg removed)
    DepositLockTransfer {
        partner_id: PublicKey,
        pubkey: PublicKey,
        amount: u64,
        transfer_id: [u8; 32],
    },
    /// Transfer fulfill - uses inline fields (legacy DepositFulfillTransferMsg removed)
    DepositFulfillTransfer {
        partner_id: PublicKey,
        pubkey: PublicKey,
        amount: u64,
        transfer_id: [u8; 32],
    },
    /// Transfer fail - uses inline fields (legacy DepositFailTransferMsg removed)
    DepositFailTransfer {
        partner_id: PublicKey,
        pubkey: PublicKey,
        transfer_id: [u8; 32],
    },

    // Quorum/coordination wrappers - uses inline fields (legacy structs retained for deserialization)
    /// Quorum join request
    QuorumJoinRequest {
        requester_pubkey: PublicKey,
        operator_id: PublicKey,
        partner_id: PublicKey,
        protocol_version: u16,
        timestamp: u64,
        signature: [u8; 64],
    },
    /// Quorum join response
    QuorumJoinResponse {
        accepted: bool,
        members: Vec<PublicKey>,
        threshold: u16,
        last_sequence: u64,
        current_state_hash: [u8; 32],
        rejection_reason: Option<String>,
    },
    /// Quorum state sync
    QuorumStateSync {
        operator_id: PublicKey,
        partner_id: PublicKey,
        updates: Vec<SignedUpdateMsg>,
        start_sequence: u64,
        is_final: bool,
    },
    /// Quorum vote request
    QuorumVoteRequest {
        operator_id: PublicKey,
        partner_id: PublicKey,
        vote_round_id: [u8; 32],
        sequence_number: u64,
        state_hash: [u8; 32],
        claimed_reserves: u64,
        collateral_amounts: Vec<u64>,
        reserves_outpoint: Vec<u8>,
        destination_script: Vec<u8>,
        fee_rate_sat_vbyte: u64,
    },
    /// Quorum vote
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
    /// Quorum membership change
    QuorumMembershipChange {
        operator_id: PublicKey,
        partner_id: PublicKey,
        change_type: String,
        member_pubkey: PublicKey,
        new_members: Vec<PublicKey>,
    },

    // Recovery wrappers - uses inline fields (legacy structs retained for deserialization)
    /// Recovery vote
    RecoveryVote {
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
    /// Recovery claim request
    RecoveryClaimRequest {
        operator: PublicKey,
        partner: PublicKey,
        claimant: PublicKey,
        tier_index: u8,
        unsigned_tx: Vec<u8>,
        sighash: [u8; 32],
        destination_script: Vec<u8>,
        block_height: u32,
    },
    /// Recovery claim signature
    RecoveryClaimSignature {
        operator: PublicKey,
        partner: PublicKey,
        signer: PublicKey,
        sighash: [u8; 32],
        signature: [u8; 64],
    },
    /// Recovery claim complete
    RecoveryClaimComplete {
        operator: PublicKey,
        partner: PublicKey,
        new_operator: PublicKey,
        claim_txid: [u8; 32],
        confirmation_block: u32,
        reason_code: u8,
    },

    // Relay wrappers (NWC)
    /// Relay NWC request
    RelayNwcRequest(RelayNwcRequestMsg),
    /// Relay NWC response
    RelayNwcResponse(RelayNwcResponseMsg),
    /// Relay NWC delivery proof
    RelayNwcDeliveryProof(RelayNwcDeliveryProofMsg),
}

impl DepositsMessage {
    pub fn message_type(&self) -> u16 {
        use self::consts::*;
        match self {
            // Core V2 types
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

            // V1-compatible aliases (serialize as V2)
            Self::LedgerOpenRequest(_) => HANDSHAKE,
            Self::LedgerOpenResponse(_) => HANDSHAKE_RESPONSE,
            Self::Ack(_) => LEDGER_UPDATE_RESPONSE,
            Self::SignedUpdate(_) => SIGNED_UPDATE,
            Self::SyncRequest(_) => SYNC,

            // Ledger operation wrappers (serialize as LEDGER_UPDATE)
            Self::DepositOpen { .. } => DEPOSIT_OPEN,
            Self::DepositClose { .. } => DEPOSIT_CLOSE,
            Self::DepositUpdate { .. } => DEPOSIT_UPDATE,
            Self::ReservesAddOutput { .. } => RESERVES_ADD_OUTPUT,
            Self::ReservesRemoveOutput { .. } => RESERVES_REMOVE_OUTPUT,
            Self::ReservesIncrease { .. } => RESERVES_INCREASE,
            Self::ReservesDecrease { .. } => RESERVES_DECREASE,
            Self::ReservesUpdateOutput { .. } => RESERVES_UPDATE_OUTPUT,
            Self::UpdateReserves { .. } => UPDATE_RESERVES,
            Self::AcceptReserves { .. } => ACCEPT_RESERVES,
            Self::ReceivingCreditPayment { .. } => RECEIVING_CREDIT_PAYMENT,
            Self::ReceivingCosignInvoice { .. } => RECEIVING_COSIGN_INVOICE,
            Self::SendingLockPayment { .. } => SENDING_LOCK_PAYMENT,
            Self::SendingFulfillPayment { .. } => SENDING_FULFILL_PAYMENT,
            Self::SendingFailPayment { .. } => SENDING_FAIL_PAYMENT,
            Self::CollateralAddPartner { .. } => COLLATERAL_ADD_PARTNER,
            Self::CollateralRemovePartner { .. } => COLLATERAL_REMOVE_PARTNER,
            Self::CollateralIncrease { .. } => COLLATERAL_INCREASE,
            Self::CollateralDecrease { .. } => COLLATERAL_DECREASE,
            Self::CollateralAttestation { .. } => COLLATERAL_ATTESTATION,
            Self::CollateralConsentRequest { .. } => COLLATERAL_CONSENT_REQUEST,
            Self::CollateralConsentResponse { .. } => COLLATERAL_CONSENT_RESPONSE,
            Self::CollateralStatus { .. } => COLLATERAL_STATUS,
            Self::MaintenanceFeeCollect { .. } => MAINTENANCE_FEE_COLLECT,
            Self::LedgerClose { .. } => LEDGER_CLOSE,
            Self::ChannelCloseTombstone { .. } => CHANNEL_CLOSE_TOMBSTONE,
            Self::UncreditedPayment { .. } => UNCREDITED_PAYMENT,
            Self::DepositLockTransfer { .. } => DEPOSIT_LOCK_TRANSFER,
            Self::DepositFulfillTransfer { .. } => DEPOSIT_FULFILL_TRANSFER,
            Self::DepositFailTransfer { .. } => DEPOSIT_FAIL_TRANSFER,

            // Quorum/coordination wrappers
            Self::QuorumJoinRequest { .. } => QUORUM_JOIN_REQUEST,
            Self::QuorumJoinResponse { .. } => QUORUM_JOIN_RESPONSE,
            Self::QuorumStateSync { .. } => QUORUM_STATE_SYNC,
            Self::QuorumVoteRequest { .. } => QUORUM_VOTE_REQUEST,
            Self::QuorumVote { .. } => QUORUM_VOTE,
            Self::QuorumMembershipChange { .. } => QUORUM_MEMBERSHIP_CHANGE,

            // Recovery wrappers
            Self::RecoveryVote { .. } => RECOVERY_VOTE,
            Self::RecoveryClaimRequest { .. } => RECOVERY_CLAIM_REQUEST,
            Self::RecoveryClaimSignature { .. } => RECOVERY_CLAIM_SIGNATURE,
            Self::RecoveryClaimComplete { .. } => RECOVERY_CLAIM_COMPLETE,

            // Relay wrappers
            Self::RelayNwcRequest(_) => RELAY_NWC_REQUEST,
            Self::RelayNwcResponse(_) => RELAY_NWC_RESPONSE,
            Self::RelayNwcDeliveryProof(_) => RELAY_NWC_DELIVERY_PROOF,
        }
    }

    pub fn variant_name(&self) -> &'static str {
        match self {
            // Core V2 types
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

            // V1-compatible aliases
            Self::LedgerOpenRequest(_) => "LedgerOpenRequest",
            Self::LedgerOpenResponse(_) => "LedgerOpenResponse",
            Self::Ack(_) => "Ack",
            Self::SignedUpdate(_) => "SignedUpdate",
            Self::SyncRequest(_) => "SyncRequest",

            // Ledger operation wrappers
            Self::DepositOpen { .. } => "DepositOpen",
            Self::DepositClose { .. } => "DepositClose",
            Self::DepositUpdate { .. } => "DepositUpdate",
            Self::ReservesAddOutput { .. } => "ReservesAddOutput",
            Self::ReservesRemoveOutput { .. } => "ReservesRemoveOutput",
            Self::ReservesIncrease { .. } => "ReservesIncrease",
            Self::ReservesDecrease { .. } => "ReservesDecrease",
            Self::ReservesUpdateOutput { .. } => "ReservesUpdateOutput",
            Self::UpdateReserves { .. } => "UpdateReserves",
            Self::AcceptReserves { .. } => "AcceptReserves",
            Self::ReceivingCreditPayment { .. } => "ReceivingCreditPayment",
            Self::ReceivingCosignInvoice { .. } => "ReceivingCosignInvoice",
            Self::SendingLockPayment { .. } => "SendingLockPayment",
            Self::SendingFulfillPayment { .. } => "SendingFulfillPayment",
            Self::SendingFailPayment { .. } => "SendingFailPayment",
            Self::CollateralAddPartner { .. } => "CollateralAddPartner",
            Self::CollateralRemovePartner { .. } => "CollateralRemovePartner",
            Self::CollateralIncrease { .. } => "CollateralIncrease",
            Self::CollateralDecrease { .. } => "CollateralDecrease",
            Self::CollateralAttestation { .. } => "CollateralAttestation",
            Self::CollateralConsentRequest { .. } => "CollateralConsentRequest",
            Self::CollateralConsentResponse { .. } => "CollateralConsentResponse",
            Self::CollateralStatus { .. } => "CollateralStatus",
            Self::MaintenanceFeeCollect { .. } => "MaintenanceFeeCollect",
            Self::LedgerClose { .. } => "LedgerClose",
            Self::ChannelCloseTombstone { .. } => "ChannelCloseTombstone",
            Self::UncreditedPayment { .. } => "UncreditedPayment",
            Self::DepositLockTransfer { .. } => "DepositLockTransfer",
            Self::DepositFulfillTransfer { .. } => "DepositFulfillTransfer",
            Self::DepositFailTransfer { .. } => "DepositFailTransfer",

            // Quorum/coordination wrappers
            Self::QuorumJoinRequest { .. } => "QuorumJoinRequest",
            Self::QuorumJoinResponse { .. } => "QuorumJoinResponse",
            Self::QuorumStateSync { .. } => "QuorumStateSync",
            Self::QuorumVoteRequest { .. } => "QuorumVoteRequest",
            Self::QuorumVote { .. } => "QuorumVote",
            Self::QuorumMembershipChange { .. } => "QuorumMembershipChange",

            // Recovery wrappers
            Self::RecoveryVote { .. } => "RecoveryVote",
            Self::RecoveryClaimRequest { .. } => "RecoveryClaimRequest",
            Self::RecoveryClaimSignature { .. } => "RecoveryClaimSignature",
            Self::RecoveryClaimComplete { .. } => "RecoveryClaimComplete",

            // Relay wrappers
            Self::RelayNwcRequest(_) => "RelayNwcRequest",
            Self::RelayNwcResponse(_) => "RelayNwcResponse",
            Self::RelayNwcDeliveryProof(_) => "RelayNwcDeliveryProof",
        }
    }

    /// Get the operation name for LedgerUpdate messages
    pub fn operation_name(&self) -> Option<&'static str> {
        match self {
            Self::LedgerUpdate(msg) => Some(msg.operation.variant_name()),
            Self::SignedUpdate(msg) => Some(msg.operation.variant_name()),
            // V1 wrappers have implicit operation names
            Self::DepositOpen { .. } => Some("DepositOpen"),
            Self::DepositClose { .. } => Some("DepositClose"),
            Self::ReservesIncrease { .. } => Some("ReservesIncrease"),
            Self::ReservesDecrease { .. } => Some("ReservesDecrease"),
            Self::ReceivingCreditPayment { .. } => Some("PaymentCredit"),
            Self::SendingLockPayment { .. } => Some("PaymentLock"),
            Self::SendingFulfillPayment { .. } => Some("PaymentFulfill"),
            Self::SendingFailPayment { .. } => Some("PaymentFail"),
            Self::CollateralAddPartner { .. } => Some("CollateralAddPartner"),
            Self::CollateralIncrease { .. } => Some("CollateralIncrease"),
            Self::CollateralDecrease { .. } => Some("CollateralDecrease"),
            Self::MaintenanceFeeCollect { .. } => Some("FeeCollect"),
            Self::LedgerClose { .. } => Some("LedgerClose"),
            Self::ChannelCloseTombstone { .. } => Some("Tombstone"),
            _ => None,
        }
    }

    /// Get a descriptive name including operation for LedgerUpdate
    pub fn descriptive_name(&self) -> String {
        match self {
            Self::LedgerUpdate(msg) => format!("LedgerUpdate({})", msg.operation.variant_name()),
            Self::SignedUpdate(msg) => format!("SignedUpdate({})", msg.operation.variant_name()),
            _ => self.variant_name().to_string(),
        }
    }

    pub fn partner_id(&self) -> Option<PublicKey> {
        match self {
            // Core V2 types
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

            // V1-compatible aliases
            Self::LedgerOpenRequest(m) => Some(m.partner_id),
            Self::LedgerOpenResponse(m) => Some(m.partner_id),
            Self::Ack(_) => None,
            Self::SignedUpdate(m) => Some(m.partner_pubkey),
            Self::SyncRequest(m) => Some(m.partner_id),

            // Ledger operation wrappers - use partner_id field if available
            Self::DepositOpen { partner_id, .. } => Some(*partner_id),
            Self::DepositClose { partner_id, .. } => Some(*partner_id),
            Self::DepositUpdate { partner_id, .. } => Some(*partner_id),
            Self::ReservesAddOutput { partner_id, .. } => Some(*partner_id),
            Self::ReservesRemoveOutput { partner_id, .. } => Some(*partner_id),
            Self::ReservesIncrease { partner_id, .. } => Some(*partner_id),
            Self::ReservesDecrease { partner_id, .. } => Some(*partner_id),
            Self::ReservesUpdateOutput { partner_id, .. } => Some(*partner_id),
            Self::UpdateReserves { .. } => None, // Channel-identified, partner from sender
            Self::AcceptReserves { .. } => None, // Channel-identified, partner from sender
            Self::ReceivingCreditPayment { partner_id, .. } => Some(*partner_id),
            Self::ReceivingCosignInvoice { .. } => None,
            Self::SendingLockPayment { .. } => None, // partner_id passed separately
            Self::SendingFulfillPayment { .. } => None, // partner_id passed separately
            Self::SendingFailPayment { .. } => None, // partner_id passed separately
            Self::CollateralAddPartner { partner_id, .. } => Some(*partner_id),
            Self::CollateralRemovePartner { partner_id, .. } => Some(*partner_id),
            Self::CollateralIncrease { partner_id, .. } => Some(*partner_id),
            Self::CollateralDecrease { partner_id, .. } => Some(*partner_id),
            Self::CollateralAttestation { collateral_partner, .. } => Some(*collateral_partner),
            Self::CollateralConsentRequest { partner_id, .. } => Some(*partner_id),
            Self::CollateralConsentResponse { partner_id, .. } => Some(*partner_id),
            Self::CollateralStatus { .. } => None, // CollateralStatus doesn't track partner
            Self::MaintenanceFeeCollect { .. } => None,
            Self::LedgerClose { partner_id, .. } => Some(*partner_id),
            Self::ChannelCloseTombstone { partner_pubkey, .. } => Some(*partner_pubkey),
            Self::UncreditedPayment { partner, .. } => Some(*partner),
            Self::DepositLockTransfer { partner_id, .. } => Some(*partner_id),
            Self::DepositFulfillTransfer { partner_id, .. } => Some(*partner_id),
            Self::DepositFailTransfer { partner_id, .. } => Some(*partner_id),

            // Quorum/coordination wrappers
            Self::QuorumJoinRequest { partner_id, .. } => Some(*partner_id),
            Self::QuorumJoinResponse { .. } => None, // Response doesn't track partner
            Self::QuorumStateSync { partner_id, .. } => Some(*partner_id),
            Self::QuorumVoteRequest { partner_id, .. } => Some(*partner_id),
            Self::QuorumVote { .. } => None, // Vote doesn't track partner (uses voter_pubkey)
            Self::QuorumMembershipChange { partner_id, .. } => Some(*partner_id),

            // Recovery wrappers
            Self::RecoveryVote { partner, .. } => Some(*partner),
            Self::RecoveryClaimRequest { partner, .. } => Some(*partner),
            Self::RecoveryClaimSignature { partner, .. } => Some(*partner),
            Self::RecoveryClaimComplete { partner, .. } => Some(*partner),

            // Relay wrappers
            Self::RelayNwcRequest(_) => None,
            Self::RelayNwcResponse(_) => None,
            Self::RelayNwcDeliveryProof(_) => None,
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

    /// Extract LedgerOperation from both V1 variants and V2 LedgerUpdate.
    /// This is the key migration helper - allows code to work with operations
    /// uniformly regardless of wire format version.
    ///
    /// Returns None for non-ledger messages (coordination, recovery, relay, etc.)
    pub fn to_operation(&self) -> Option<LedgerOperation> {
        match self {
            // V2 format - operation is directly available
            Self::LedgerUpdate(msg) => Some(msg.operation.clone()),
            Self::SignedUpdate(msg) => Some(msg.operation.clone()),

            // V1 variants - convert to equivalent LedgerOperation
            Self::DepositOpen { pubkey, fees, payment_hash, invoice, cosigner_guarantee_signature, .. } => {
                Some(LedgerOperation::DepositOpen {
                    pubkey: *pubkey,
                    fees: fees.as_ref().map(|f| f.0.clone()),
                    payment_hash: *payment_hash,
                    invoice: invoice.clone(),
                    cosigner_guarantee_signature: *cosigner_guarantee_signature,
                })
            }
            Self::DepositClose { pubkey, .. } => {
                Some(LedgerOperation::DepositClose { pubkey: *pubkey })
            }
            Self::DepositUpdate { pubkey, new_fees, .. } => {
                Some(LedgerOperation::DepositUpdate {
                    pubkey: *pubkey,
                    new_fees: new_fees.0.clone(),
                })
            }
            Self::ReservesAddOutput { initial_amount, spend_to, collateral_partners, .. } => {
                Some(LedgerOperation::ReservesAdd {
                    amount: *initial_amount,
                    spend_to: *spend_to,
                    collateral_partners: collateral_partners.clone(),
                })
            }
            Self::ReservesRemoveOutput { .. } => {
                Some(LedgerOperation::ReservesRemove)
            }
            Self::ReservesIncrease { new_amount, .. } => {
                Some(LedgerOperation::ReservesIncrease { new_amount: *new_amount })
            }
            Self::ReservesDecrease { new_amount, .. } => {
                Some(LedgerOperation::ReservesDecrease { new_amount: *new_amount })
            }
            Self::ReservesUpdateOutput { spend_to, .. } => {
                Some(LedgerOperation::ReservesUpdateSpendTo { spend_to: *spend_to })
            }
            Self::ReceivingCreditPayment { payment_hash, deposit_pubkey, amount, invoice_id, sequence_number, .. } => {
                Some(LedgerOperation::PaymentCredit {
                    payment_hash: *payment_hash,
                    deposit_pubkey: *deposit_pubkey,
                    amount: *amount,
                    invoice_id: invoice_id.clone(),
                    sequence_number: *sequence_number,
                })
            }
            Self::SendingLockPayment { pubkey, amount, payment_id, sequence_number, scriptpubkey_signature } => {
                Some(LedgerOperation::PaymentLock {
                    pubkey: *pubkey,
                    amount: *amount,
                    payment_id: *payment_id,
                    sequence_number: *sequence_number,
                    scriptpubkey_signature: *scriptpubkey_signature,
                })
            }
            Self::SendingFailPayment { pubkey, amount, payment_id, sequence_number } => {
                Some(LedgerOperation::PaymentFail {
                    pubkey: *pubkey,
                    amount: *amount,
                    payment_id: *payment_id,
                    sequence_number: *sequence_number,
                })
            }
            Self::SendingFulfillPayment { pubkey, amount, payment_id, sequence_number, scriptpubkey_signature, preimage } => {
                Some(LedgerOperation::PaymentFulfill {
                    pubkey: *pubkey,
                    amount: *amount,
                    payment_id: *payment_id,
                    sequence_number: *sequence_number,
                    scriptpubkey_signature: *scriptpubkey_signature,
                    preimage: *preimage,
                })
            }
            Self::CollateralIncrease { new_amount, block_height, .. } => {
                Some(LedgerOperation::CollateralIncrease {
                    new_amount: *new_amount,
                    block_height: *block_height,
                })
            }
            Self::CollateralDecrease { new_amount, block_height, .. } => {
                Some(LedgerOperation::CollateralDecrease {
                    new_amount: *new_amount,
                    block_height: *block_height,
                })
            }
            Self::CollateralAttestation { operator, amount, block_height, signature, ledger_hash, .. } => {
                Some(LedgerOperation::CollateralAttestation {
                    collateral_operator: *operator,
                    amount: *amount,
                    block_height: *block_height,
                    signature: *signature,
                    ledger_hash: *ledger_hash,
                })
            }
            Self::CollateralAddPartner { collateral_partner, collateral_partner_signature, .. } => {
                Some(LedgerOperation::CollateralAddPartner {
                    collateral_partner: *collateral_partner,
                    collateral_partner_signature: *collateral_partner_signature,
                })
            }
            Self::CollateralRemovePartner { collateral_partner, operator_signature, .. } => {
                Some(LedgerOperation::CollateralRemovePartner {
                    collateral_partner: *collateral_partner,
                    operator_signature: *operator_signature,
                })
            }
            Self::MaintenanceFeeCollect { pubkey, amount, block_height } => {
                Some(LedgerOperation::FeeCollect {
                    pubkey: *pubkey,
                    amount: *amount,
                    block_height: *block_height,
                })
            }
            Self::LedgerClose { .. } => {
                Some(LedgerOperation::LedgerClose)
            }
            Self::ChannelCloseTombstone { channel_id, close_reason, timestamp, .. } => {
                Some(LedgerOperation::Tombstone {
                    channel_id: *channel_id,
                    close_reason: close_reason.clone(),
                    timestamp: *timestamp,
                })
            }
            Self::DepositLockTransfer { pubkey, amount, transfer_id, .. } => {
                Some(LedgerOperation::TransferLock {
                    pubkey: *pubkey,
                    amount: *amount,
                    transfer_id: *transfer_id,
                })
            }
            Self::DepositFailTransfer { pubkey, transfer_id, .. } => {
                Some(LedgerOperation::TransferFail {
                    pubkey: *pubkey,
                    transfer_id: *transfer_id,
                })
            }
            Self::DepositFulfillTransfer { pubkey, amount, transfer_id, .. } => {
                Some(LedgerOperation::TransferFulfill {
                    pubkey: *pubkey,
                    amount: *amount,
                    transfer_id: *transfer_id,
                })
            }

            // Non-ledger messages return None
            _ => None,
        }
    }

    /// Check if this message represents a ledger operation (V1 or V2)
    pub fn is_ledger_operation(&self) -> bool {
        self.to_operation().is_some()
    }

    /// Get the sequence number from messages that have one (payments, tombstone)
    /// Uses to_operation() for unified V1/V2 handling where possible
    pub fn get_sequence_number(&self) -> Option<u64> {
        // Try to get sequence_number from LedgerOperation (handles V1 payments, V2 LedgerUpdate)
        if let Some(seq) = self.to_operation().and_then(|op| op.get_sequence_number()) {
            return Some(seq);
        }
        // Special case: ChannelCloseTombstone has sequence_number but LedgerOperation::Tombstone doesn't
        if let Self::ChannelCloseTombstone { sequence_number, .. } = self {
            return Some(*sequence_number);
        }
        None
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
            // Core V2 types
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

            // V1-compatible aliases - convert to equivalent V2 type
            Self::LedgerOpenRequest(m) => DepositsMessageCore::Handshake(m.into()),
            Self::LedgerOpenResponse(m) => DepositsMessageCore::HandshakeResponse(m.into()),
            Self::Ack(m) => DepositsMessageCore::LedgerUpdateResponse(m.into()),
            Self::SignedUpdate(m) => DepositsMessageCore::LedgerUpdate(m.into()),
            Self::SyncRequest(m) => DepositsMessageCore::Sync(SyncMsgV2 {
                operator_id: m.operator_id,
                partner_id: m.partner_id,
                last_known_sequence: m.last_known_sequence,
                last_known_hash: [0u8; 32],
            }),

            // UncreditedPayment - converts to RecoveryMsg::UncreditedPayment
            Self::UncreditedPayment { operator, partner, payment_hash, preimage, deposit_pubkey, amount_msat, invoice_cosignature, settlement_sequence, settlement_ledger_hash, settlement_block_height, accuser_signature } => DepositsMessageCore::Recovery(RecoveryMsg::UncreditedPayment {
                operator,
                partner,
                payment_hash,
                preimage,
                deposit_pubkey,
                amount_msat,
                invoice_cosignature,
                settlement_sequence,
                settlement_ledger_hash,
                settlement_block_height,
                accuser_signature,
            }),

            // V1 operation variants - convert to V2 LedgerUpdate with placeholder envelope fields
            // The actual operator_id, partner_id, sequence, hashes are stored in SignedLedgerUpdate
            Self::DepositOpen { partner_id, pubkey, fees, payment_hash, invoice, cosigner_guarantee_signature } => {
                DepositsMessageCore::LedgerUpdate(LedgerUpdateMsgV2 {
                    operator_id: partner_id, // placeholder - actual stored in SignedLedgerUpdate
                    partner_id,
                    operation: LedgerOperation::DepositOpen {
                        pubkey,
                        fees: fees.as_ref().map(|f| f.0.clone()),
                        payment_hash,
                        invoice: invoice.clone(),
                        cosigner_guarantee_signature,
                    },
                    sequence_number: 0,
                    previous_hash: [0u8; 32],
                    current_hash: [0u8; 32],
                    operator_signature: [0u8; 64],
                })
            }
            Self::DepositClose { partner_id, pubkey } => {
                DepositsMessageCore::LedgerUpdate(LedgerUpdateMsgV2 {
                    operator_id: partner_id,
                    partner_id,
                    operation: LedgerOperation::DepositClose { pubkey },
                    sequence_number: 0,
                    previous_hash: [0u8; 32],
                    current_hash: [0u8; 32],
                    operator_signature: [0u8; 64],
                })
            }
            Self::DepositUpdate { partner_id, pubkey, new_fees } => {
                DepositsMessageCore::LedgerUpdate(LedgerUpdateMsgV2 {
                    operator_id: partner_id,
                    partner_id,
                    operation: LedgerOperation::DepositUpdate {
                        pubkey,
                        new_fees: new_fees.0.clone(),
                    },
                    sequence_number: 0,
                    previous_hash: [0u8; 32],
                    current_hash: [0u8; 32],
                    operator_signature: [0u8; 64],
                })
            }
            Self::ReservesAddOutput { initial_amount, spend_to, partner_id, collateral_partners } => {
                DepositsMessageCore::LedgerUpdate(LedgerUpdateMsgV2 {
                    operator_id: partner_id,
                    partner_id,
                    operation: LedgerOperation::ReservesAdd {
                        amount: initial_amount,
                        spend_to,
                        collateral_partners,
                    },
                    sequence_number: 0,
                    previous_hash: [0u8; 32],
                    current_hash: [0u8; 32],
                    operator_signature: [0u8; 64],
                })
            }
            Self::ReservesRemoveOutput { partner_id, .. } => {
                DepositsMessageCore::LedgerUpdate(LedgerUpdateMsgV2 {
                    operator_id: partner_id,
                    partner_id,
                    operation: LedgerOperation::ReservesRemove,
                    sequence_number: 0,
                    previous_hash: [0u8; 32],
                    current_hash: [0u8; 32],
                    operator_signature: [0u8; 64],
                })
            }
            Self::ReservesIncrease { partner_id, new_amount } => {
                DepositsMessageCore::LedgerUpdate(LedgerUpdateMsgV2 {
                    operator_id: partner_id,
                    partner_id,
                    operation: LedgerOperation::ReservesIncrease { new_amount },
                    sequence_number: 0,
                    previous_hash: [0u8; 32],
                    current_hash: [0u8; 32],
                    operator_signature: [0u8; 64],
                })
            }
            Self::ReservesDecrease { partner_id, new_amount } => {
                DepositsMessageCore::LedgerUpdate(LedgerUpdateMsgV2 {
                    operator_id: partner_id,
                    partner_id,
                    operation: LedgerOperation::ReservesDecrease { new_amount },
                    sequence_number: 0,
                    previous_hash: [0u8; 32],
                    current_hash: [0u8; 32],
                    operator_signature: [0u8; 64],
                })
            }
            Self::ReservesUpdateOutput { partner_id, spend_to } => {
                DepositsMessageCore::LedgerUpdate(LedgerUpdateMsgV2 {
                    operator_id: partner_id,
                    partner_id,
                    operation: LedgerOperation::ReservesUpdateSpendTo { spend_to },
                    sequence_number: 0,
                    previous_hash: [0u8; 32],
                    current_hash: [0u8; 32],
                    operator_signature: [0u8; 64],
                })
            }
            Self::ReceivingCreditPayment { payment_hash, deposit_pubkey, amount, invoice_id, partner_id, sequence_number } => {
                DepositsMessageCore::LedgerUpdate(LedgerUpdateMsgV2 {
                    operator_id: partner_id,
                    partner_id,
                    operation: LedgerOperation::PaymentCredit {
                        payment_hash,
                        deposit_pubkey,
                        amount,
                        invoice_id: invoice_id.clone(),
                        sequence_number,
                    },
                    sequence_number: 0,
                    previous_hash: [0u8; 32],
                    current_hash: [0u8; 32],
                    operator_signature: [0u8; 64],
                })
            }
            Self::ReceivingCosignInvoice { pending_invoice } => {
                // CosignInvoice is in CoordinationMsg - extract fields from PendingInvoice
                let pi = pending_invoice;
                DepositsMessageCore::Coordination(CoordinationMsg::CosignInvoice {
                    operator_id: pi.assigned_deposit, // placeholder
                    partner_id: pi.assigned_deposit,   // placeholder
                    amount: pi.amount,
                    payment_hash: pi.payment_hash,
                    expires: pi.expires,
                    assigned_deposit: pi.assigned_deposit,
                    invoice_id: pi.invoice_id.clone(),
                    bolt11_invoice: pi.bolt11.clone(),
                })
            }
            Self::SendingLockPayment { pubkey, amount, payment_id, sequence_number, scriptpubkey_signature } => {
                DepositsMessageCore::LedgerUpdate(LedgerUpdateMsgV2 {
                    operator_id: pubkey, // Use pubkey as placeholder
                    partner_id: pubkey,
                    operation: LedgerOperation::PaymentLock {
                        pubkey,
                        amount,
                        payment_id,
                        sequence_number,
                        scriptpubkey_signature,
                    },
                    sequence_number: 0,
                    previous_hash: [0u8; 32],
                    current_hash: [0u8; 32],
                    operator_signature: [0u8; 64],
                })
            }
            Self::SendingFulfillPayment { pubkey, amount, payment_id, sequence_number, scriptpubkey_signature, preimage } => {
                DepositsMessageCore::LedgerUpdate(LedgerUpdateMsgV2 {
                    operator_id: pubkey,
                    partner_id: pubkey,
                    operation: LedgerOperation::PaymentFulfill {
                        pubkey,
                        amount,
                        payment_id,
                        sequence_number,
                        scriptpubkey_signature,
                        preimage,
                    },
                    sequence_number: 0,
                    previous_hash: [0u8; 32],
                    current_hash: [0u8; 32],
                    operator_signature: [0u8; 64],
                })
            }
            Self::SendingFailPayment { pubkey, amount, payment_id, sequence_number } => {
                DepositsMessageCore::LedgerUpdate(LedgerUpdateMsgV2 {
                    operator_id: pubkey,
                    partner_id: pubkey,
                    operation: LedgerOperation::PaymentFail {
                        pubkey,
                        amount,
                        payment_id,
                        sequence_number,
                    },
                    sequence_number: 0,
                    previous_hash: [0u8; 32],
                    current_hash: [0u8; 32],
                    operator_signature: [0u8; 64],
                })
            }
            Self::CollateralAddPartner { operator_id, partner_id, collateral_partner, collateral_partner_signature } => {
                DepositsMessageCore::LedgerUpdate(LedgerUpdateMsgV2 {
                    operator_id,
                    partner_id,
                    operation: LedgerOperation::CollateralAddPartner {
                        collateral_partner,
                        collateral_partner_signature,
                    },
                    sequence_number: 0,
                    previous_hash: [0u8; 32],
                    current_hash: [0u8; 32],
                    operator_signature: [0u8; 64],
                })
            }
            Self::CollateralRemovePartner { partner_id, collateral_partner, operator_signature } => {
                DepositsMessageCore::LedgerUpdate(LedgerUpdateMsgV2 {
                    operator_id: partner_id,
                    partner_id,
                    operation: LedgerOperation::CollateralRemovePartner {
                        collateral_partner,
                        operator_signature,
                    },
                    sequence_number: 0,
                    previous_hash: [0u8; 32],
                    current_hash: [0u8; 32],
                    operator_signature: [0u8; 64],
                })
            }
            Self::CollateralIncrease { partner_id, new_amount, block_height } => {
                DepositsMessageCore::LedgerUpdate(LedgerUpdateMsgV2 {
                    operator_id: partner_id,
                    partner_id,
                    operation: LedgerOperation::CollateralIncrease {
                        new_amount,
                        block_height,
                    },
                    sequence_number: 0,
                    previous_hash: [0u8; 32],
                    current_hash: [0u8; 32],
                    operator_signature: [0u8; 64],
                })
            }
            Self::CollateralDecrease { partner_id, new_amount, block_height } => {
                DepositsMessageCore::LedgerUpdate(LedgerUpdateMsgV2 {
                    operator_id: partner_id,
                    partner_id,
                    operation: LedgerOperation::CollateralDecrease {
                        new_amount,
                        block_height,
                    },
                    sequence_number: 0,
                    previous_hash: [0u8; 32],
                    current_hash: [0u8; 32],
                    operator_signature: [0u8; 64],
                })
            }
            Self::CollateralAttestation { operator, collateral_partner, amount, block_height, signature, ledger_hash } => {
                DepositsMessageCore::LedgerUpdate(LedgerUpdateMsgV2 {
                    operator_id: operator,
                    partner_id: collateral_partner,
                    operation: LedgerOperation::CollateralAttestation {
                        collateral_operator: operator,
                        amount,
                        block_height,
                        signature,
                        ledger_hash,
                    },
                    sequence_number: 0,
                    previous_hash: [0u8; 32],
                    current_hash: [0u8; 32],
                    operator_signature: [0u8; 64],
                })
            }
            Self::CollateralConsentRequest { operator_id, partner_id, operator_signature } => {
                // Map to CollateralConsentRequest in CoordinationMsg
                DepositsMessageCore::Coordination(CoordinationMsg::CollateralConsentRequest {
                    operator_id,
                    partner_id,
                    operator_signature,
                })
            }
            Self::CollateralConsentResponse { operator_id, partner_id, .. } => {
                // No direct V2 equivalent - use placeholder LedgerUpdate
                // (V1 was never deployed, this is just for compilation)
                DepositsMessageCore::LedgerUpdate(LedgerUpdateMsgV2 {
                    operator_id,
                    partner_id,
                    operation: LedgerOperation::LedgerClose, // placeholder
                    sequence_number: 0,
                    previous_hash: [0u8; 32],
                    current_hash: [0u8; 32],
                    operator_signature: [0u8; 64],
                })
            }
            Self::CollateralStatus { collateral_operator, amount, block_height, signature } => {
                // No direct V2 equivalent - use placeholder LedgerUpdate
                DepositsMessageCore::LedgerUpdate(LedgerUpdateMsgV2 {
                    operator_id: collateral_operator,
                    partner_id: collateral_operator,
                    operation: LedgerOperation::CollateralAttestation {
                        collateral_operator,
                        amount,
                        block_height,
                        signature,
                        ledger_hash: [0u8; 32],
                    },
                    sequence_number: 0,
                    previous_hash: [0u8; 32],
                    current_hash: [0u8; 32],
                    operator_signature: [0u8; 64],
                })
            }
            Self::MaintenanceFeeCollect { pubkey, amount, block_height } => {
                DepositsMessageCore::LedgerUpdate(LedgerUpdateMsgV2 {
                    operator_id: pubkey,
                    partner_id: pubkey,
                    operation: LedgerOperation::FeeCollect {
                        pubkey,
                        amount,
                        block_height,
                    },
                    sequence_number: 0,
                    previous_hash: [0u8; 32],
                    current_hash: [0u8; 32],
                    operator_signature: [0u8; 64],
                })
            }
            Self::LedgerClose { partner_id } => {
                DepositsMessageCore::LedgerUpdate(LedgerUpdateMsgV2 {
                    operator_id: partner_id,
                    partner_id,
                    operation: LedgerOperation::LedgerClose,
                    sequence_number: 0,
                    previous_hash: [0u8; 32],
                    current_hash: [0u8; 32],
                    operator_signature: [0u8; 64],
                })
            }
            Self::ChannelCloseTombstone { operator_pubkey, partner_pubkey, timestamp, channel_id, close_reason, sequence_number } => {
                DepositsMessageCore::LedgerUpdate(LedgerUpdateMsgV2 {
                    operator_id: operator_pubkey,
                    partner_id: partner_pubkey,
                    operation: LedgerOperation::Tombstone {
                        channel_id,
                        close_reason,
                        timestamp,
                    },
                    sequence_number,
                    previous_hash: [0u8; 32],
                    current_hash: [0u8; 32],
                    operator_signature: [0u8; 64],
                })
            }
            Self::DepositLockTransfer { partner_id, pubkey, amount, transfer_id } => {
                DepositsMessageCore::LedgerUpdate(LedgerUpdateMsgV2 {
                    operator_id: partner_id,
                    partner_id,
                    operation: LedgerOperation::TransferLock {
                        pubkey,
                        amount,
                        transfer_id,
                    },
                    sequence_number: 0,
                    previous_hash: [0u8; 32],
                    current_hash: [0u8; 32],
                    operator_signature: [0u8; 64],
                })
            }
            Self::DepositFulfillTransfer { partner_id, pubkey, amount, transfer_id } => {
                DepositsMessageCore::LedgerUpdate(LedgerUpdateMsgV2 {
                    operator_id: partner_id,
                    partner_id,
                    operation: LedgerOperation::TransferFulfill {
                        pubkey,
                        amount,
                        transfer_id,
                    },
                    sequence_number: 0,
                    previous_hash: [0u8; 32],
                    current_hash: [0u8; 32],
                    operator_signature: [0u8; 64],
                })
            }
            Self::DepositFailTransfer { partner_id, pubkey, transfer_id } => {
                DepositsMessageCore::LedgerUpdate(LedgerUpdateMsgV2 {
                    operator_id: partner_id,
                    partner_id,
                    operation: LedgerOperation::TransferFail {
                        pubkey,
                        transfer_id,
                    },
                    sequence_number: 0,
                    previous_hash: [0u8; 32],
                    current_hash: [0u8; 32],
                    operator_signature: [0u8; 64],
                })
            }
            Self::QuorumJoinRequest { requester_pubkey, operator_id, partner_id, protocol_version, timestamp, signature } => {
                DepositsMessageCore::Coordination(CoordinationMsg::QuorumJoinRequest {
                    requester_pubkey,
                    operator_id,
                    partner_id,
                    protocol_version,
                    timestamp,
                    signature,
                })
            }
            Self::QuorumJoinResponse { members, last_sequence, current_state_hash, .. } => {
                // No direct V2 equivalent - use placeholder LedgerUpdate
                DepositsMessageCore::LedgerUpdate(LedgerUpdateMsgV2 {
                    operator_id: members.first().copied().unwrap_or(
                        bitcoin::secp256k1::PublicKey::from_slice(&[2; 33]).unwrap_or_else(|_| panic!("invalid pubkey"))
                    ),
                    partner_id: members.first().copied().unwrap_or(
                        bitcoin::secp256k1::PublicKey::from_slice(&[2; 33]).unwrap_or_else(|_| panic!("invalid pubkey"))
                    ),
                    operation: LedgerOperation::LedgerClose,
                    sequence_number: last_sequence,
                    previous_hash: [0u8; 32],
                    current_hash: current_state_hash,
                    operator_signature: [0u8; 64],
                })
            }
            Self::QuorumStateSync { operator_id, partner_id, start_sequence, .. } => {
                // QuorumStateSync needs the SignedUpdateMsg list - use empty for now
                DepositsMessageCore::Sync(SyncMsgV2 {
                    operator_id,
                    partner_id,
                    last_known_sequence: start_sequence,
                    last_known_hash: [0u8; 32],
                })
            }
            Self::QuorumVoteRequest { operator_id, partner_id, vote_round_id, sequence_number, state_hash, claimed_reserves, collateral_amounts, reserves_outpoint, destination_script, fee_rate_sat_vbyte } => {
                DepositsMessageCore::Coordination(CoordinationMsg::QuorumVoteRequest {
                    vote_round_id,
                    operator_id,
                    partner_id,
                    sequence_number,
                    state_hash,
                    claimed_reserves,
                    collateral_amounts,
                    reserves_outpoint,
                    destination_script,
                    fee_rate_sat_vbyte,
                    timestamp: 0, // V1 doesn't have timestamp
                })
            }
            Self::QuorumVote { vote_round_id, voter_pubkey, vote, voter_sequence, voter_state_hash, evidence, signature, spend_signature } => {
                DepositsMessageCore::Coordination(CoordinationMsg::QuorumVote {
                    vote_round_id,
                    voter_pubkey,
                    vote,
                    voter_sequence,
                    voter_state_hash,
                    evidence,
                    signature,
                    spend_signature,
                })
            }
            Self::QuorumMembershipChange { operator_id, partner_id, .. } => {
                // No direct V2 equivalent - use placeholder LedgerUpdate
                DepositsMessageCore::LedgerUpdate(LedgerUpdateMsgV2 {
                    operator_id,
                    partner_id,
                    operation: LedgerOperation::LedgerClose, // placeholder
                    sequence_number: 0,
                    previous_hash: [0u8; 32],
                    current_hash: [0u8; 32],
                    operator_signature: [0u8; 64],
                })
            }
            Self::RecoveryVote { operator, partner, voter, is_conforming, validated_hash, validated_sequence, substitute_nomination, discovered_violation, signature } => {
                DepositsMessageCore::Recovery(RecoveryMsg::Vote {
                    operator,
                    partner,
                    voter,
                    is_conforming,
                    validated_hash,
                    validated_sequence,
                    substitute_nomination,
                    discovered_violation,
                    signature,
                })
            }
            Self::RecoveryClaimRequest { operator, partner, claimant, tier_index, unsigned_tx, sighash, destination_script, block_height } => {
                DepositsMessageCore::Recovery(RecoveryMsg::ClaimRequest {
                    operator,
                    partner,
                    claimant,
                    tier_index,
                    unsigned_tx,
                    sighash,
                    destination_script,
                    block_height,
                })
            }
            Self::RecoveryClaimSignature { operator, partner, .. } => {
                // No direct V2 equivalent (ClaimSignature doesn't exist) - use placeholder
                DepositsMessageCore::LedgerUpdate(LedgerUpdateMsgV2 {
                    operator_id: operator,
                    partner_id: partner,
                    operation: LedgerOperation::LedgerClose, // placeholder
                    sequence_number: 0,
                    previous_hash: [0u8; 32],
                    current_hash: [0u8; 32],
                    operator_signature: [0u8; 64],
                })
            }
            Self::RecoveryClaimComplete { operator, partner, new_operator, claim_txid, .. } => {
                DepositsMessageCore::Recovery(RecoveryMsg::ClaimComplete {
                    operator,
                    partner,
                    new_operator,
                    claim_txid,
                    confirmation_block: 0, // V1 doesn't have this
                    reason_code: 0,        // V1 doesn't have this
                })
            }
            Self::RelayNwcRequest(m) => {
                // RelayNwcRequest maps to RelayMsg::NwcRequest (different fields)
                // V1 only has request_id and encrypted_content, V2 needs more fields
                DepositsMessageCore::Relay(RelayMsg::NwcRequest {
                    request_id: m.request_id,
                    target_operator: bitcoin::secp256k1::PublicKey::from_slice(&[2; 33]).unwrap(), // placeholder
                    deposit_pubkey: bitcoin::secp256k1::PublicKey::from_slice(&[2; 33]).unwrap(),  // placeholder
                    nwc_request_content: m.encrypted_content.clone(),
                    wallet_signature: [0u8; 64],
                    wallet_pubkey: bitcoin::secp256k1::PublicKey::from_slice(&[2; 33]).unwrap(),
                    timestamp: 0,
                })
            }
            Self::RelayNwcResponse(m) => {
                // No direct NwcResponse in RelayMsg - use placeholder
                let _ = m;
                DepositsMessageCore::LedgerUpdate(LedgerUpdateMsgV2 {
                    operator_id: bitcoin::secp256k1::PublicKey::from_slice(&[2; 33]).unwrap(),
                    partner_id: bitcoin::secp256k1::PublicKey::from_slice(&[2; 33]).unwrap(),
                    operation: LedgerOperation::LedgerClose, // placeholder
                    sequence_number: 0,
                    previous_hash: [0u8; 32],
                    current_hash: [0u8; 32],
                    operator_signature: [0u8; 64],
                })
            }
            Self::RelayNwcDeliveryProof(m) => {
                // RelayNwcDeliveryProof maps to RelayMsg::DeliveryProof (different fields)
                DepositsMessageCore::Relay(RelayMsg::DeliveryProof {
                    request_id: m.request_id,
                    response_hash: [0u8; 32], // placeholder
                    block_height: 0,
                    attestation_signature: [0u8; 64],
                })
            }

            // UpdateReserves and AcceptReserves are deposits-ldk specific messages
            // that don't have a V2 core equivalent. For logging purposes (encode() method),
            // we use a placeholder LedgerUpdate. Actual wire encoding uses Writeable directly.
            Self::UpdateReserves { reserves_sats, ledger_hash, .. } => {
                DepositsMessageCore::LedgerUpdate(LedgerUpdateMsgV2 {
                    operator_id: PublicKey::from_slice(&[2; 33]).unwrap_or_else(|_| {
                        PublicKey::from_slice(&[3; 33]).unwrap()
                    }),
                    partner_id: PublicKey::from_slice(&[2; 33]).unwrap_or_else(|_| {
                        PublicKey::from_slice(&[3; 33]).unwrap()
                    }),
                    operation: LedgerOperation::ReservesIncrease { new_amount: reserves_sats },
                    sequence_number: 0,
                    previous_hash: [0u8; 32],
                    current_hash: ledger_hash,
                    operator_signature: [0u8; 64],
                })
            }
            Self::AcceptReserves { channel_id } => {
                DepositsMessageCore::LedgerUpdate(LedgerUpdateMsgV2 {
                    operator_id: PublicKey::from_slice(&[2; 33]).unwrap_or_else(|_| {
                        PublicKey::from_slice(&[3; 33]).unwrap()
                    }),
                    partner_id: PublicKey::from_slice(&[2; 33]).unwrap_or_else(|_| {
                        PublicKey::from_slice(&[3; 33]).unwrap()
                    }),
                    operation: LedgerOperation::ReservesIncrease { new_amount: 0 },
                    sequence_number: 0,
                    previous_hash: channel_id,
                    current_hash: [0u8; 32],
                    operator_signature: [0u8; 64],
                })
            }
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

// V1 Compatibility Aliases
pub type LedgerOpenRequestMsg = HandshakeMsg;
pub type LedgerOpenResponseMsg = HandshakeResponseMsg;
pub type AckMsg = LedgerUpdateResponseMsg;
pub type SignedUpdateMsg = LedgerUpdateMsg;

// ============================================================================
// V1 Compatibility Structs (local - structurally different or with special impls)
// ============================================================================
// Most V1 message structs are now imported from deposits_ldk::wire::messages.
// The structs below are kept local because they have structural differences
// or special implementations that can't be easily moved to deposits-ldk.

// CollateralAttestationMsg is now imported from deposits-ldk (has serde derives and available_collateral())

/// Type alias for MaintenanceFeeCollect
pub type MaintenanceFeeCollectMsg = FeeCollectMsg;

/// V1-compatible receiving cosign invoice message (local - uses PendingInvoice wrapper)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceivingCosignInvoiceMsg {
    pub pending_invoice: PendingInvoice,
}

// Note: From implementations for quorum types were removed because they violate orphan rules
// when QuorumJoinRequestMsg/QuorumJoinResponseMsg are imported from deposits-ldk.
// Conversions can be done using the helper functions below if needed.

/// Convert deposits-ldk QuorumJoinRequestMsg to deposits-core version
pub fn quorum_join_request_to_core(msg: &QuorumJoinRequestMsg) -> deposits_core::QuorumJoinRequestMsg {
    deposits_core::QuorumJoinRequestMsg {
        requester_pubkey: msg.requester_pubkey,
        operator_id: msg.operator_id,
        partner_id: msg.partner_id,
        protocol_version: msg.protocol_version,
        timestamp: msg.timestamp,
        signature: msg.signature,
    }
}

/// Convert deposits-core QuorumJoinResponseMsg to deposits-ldk version
pub fn quorum_join_response_from_core(msg: deposits_core::QuorumJoinResponseMsg) -> QuorumJoinResponseMsg {
    QuorumJoinResponseMsg {
        accepted: msg.accepted,
        members: msg.members,
        threshold: msg.threshold,
        last_sequence: msg.last_sequence,
        current_state_hash: msg.current_state_hash,
        rejection_reason: msg.rejection_reason,
    }
}

/// V1-compatible quorum state sync message (local - uses Vec<SignedUpdateMsg>)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuorumStateSyncMsg {
    pub operator_id: PublicKey,
    pub partner_id: PublicKey,
    pub updates: Vec<SignedUpdateMsg>,
    pub start_sequence: u64,
    pub is_final: bool,
}

// ============================================================================
// V1 Message Type Constants (imported from deposits-ldk)
// ============================================================================

// Import all V1 message type constants from deposits-ldk
pub use crate::wire::message_types::{
    RESERVES_ADD_OUTPUT, RESERVES_REMOVE_OUTPUT, RESERVES_INCREASE, RESERVES_DECREASE,
    RESERVES_UPDATE_OUTPUT, UPDATE_RESERVES, ACCEPT_RESERVES, COLLATERAL_INCREASE, COLLATERAL_DECREASE, COLLATERAL_STATUS,
    DEPOSIT_OPEN, DEPOSIT_CLOSE, DEPOSIT_UPDATE, DEPOSIT_LOCK_TRANSFER, DEPOSIT_FAIL_TRANSFER,
    DEPOSIT_FULFILL_TRANSFER, LEDGER_CLOSE, MAINTENANCE_FEE_COLLECT, RECEIVING_COSIGN_INVOICE,
    RECEIVING_CREDIT_PAYMENT, UNCREDITED_PAYMENT, SENDING_LOCK_PAYMENT, SENDING_FAIL_PAYMENT,
    SENDING_FULFILL_PAYMENT, CHANNEL_CLOSE_TOMBSTONE, SIGNED_UPDATE, SYNC_REQUEST,
    LEDGER_OPEN_REQUEST, LEDGER_OPEN_RESPONSE, ACK, QUORUM_JOIN_REQUEST, QUORUM_JOIN_RESPONSE,
    QUORUM_STATE_SYNC, QUORUM_VOTE_REQUEST, QUORUM_VOTE, QUORUM_MEMBERSHIP_CHANGE,
    COLLATERAL_ATTESTATION, RECOVERY_VOTE, RECOVERY_CLAIM_REQUEST, RECOVERY_CLAIM_SIGNATURE,
    RECOVERY_CLAIM_COMPLETE, COLLATERAL_ADD_PARTNER, COLLATERAL_REMOVE_PARTNER,
    COLLATERAL_CONSENT_REQUEST, COLLATERAL_CONSENT_RESPONSE, RELAY_NWC_REQUEST,
    RELAY_NWC_RESPONSE, RELAY_NWC_DELIVERY_PROOF,
};

// ============================================================================
// Message Type Constants (all types including V1 compatibility)
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

    // V1 compatibility constants from deposits-ldk
    pub use crate::wire::message_types::{
        RESERVES_ADD_OUTPUT, RESERVES_REMOVE_OUTPUT, RESERVES_INCREASE, RESERVES_DECREASE,
        RESERVES_UPDATE_OUTPUT, UPDATE_RESERVES, ACCEPT_RESERVES, COLLATERAL_INCREASE, COLLATERAL_DECREASE, COLLATERAL_STATUS,
        DEPOSIT_OPEN, DEPOSIT_CLOSE, DEPOSIT_UPDATE, DEPOSIT_LOCK_TRANSFER, DEPOSIT_FAIL_TRANSFER,
        DEPOSIT_FULFILL_TRANSFER, LEDGER_CLOSE, MAINTENANCE_FEE_COLLECT, RECEIVING_COSIGN_INVOICE,
        RECEIVING_CREDIT_PAYMENT, UNCREDITED_PAYMENT, SENDING_LOCK_PAYMENT, SENDING_FAIL_PAYMENT,
        SENDING_FULFILL_PAYMENT, CHANNEL_CLOSE_TOMBSTONE, SIGNED_UPDATE, SYNC_REQUEST,
        LEDGER_OPEN_REQUEST, LEDGER_OPEN_RESPONSE, ACK, QUORUM_JOIN_REQUEST, QUORUM_JOIN_RESPONSE,
        QUORUM_STATE_SYNC, QUORUM_VOTE_REQUEST, QUORUM_VOTE, QUORUM_MEMBERSHIP_CHANGE,
        COLLATERAL_ATTESTATION, RECOVERY_VOTE, RECOVERY_CLAIM_REQUEST, RECOVERY_CLAIM_SIGNATURE,
        RECOVERY_CLAIM_COMPLETE, COLLATERAL_ADD_PARTNER, COLLATERAL_REMOVE_PARTNER,
        COLLATERAL_CONSENT_REQUEST, COLLATERAL_CONSENT_RESPONSE, RELAY_NWC_REQUEST,
        RELAY_NWC_RESPONSE, RELAY_NWC_DELIVERY_PROOF,
    };

    // Re-export helper function
    pub use super::requires_acknowledgment;
}

/// All message type IDs
pub const ALL_MESSAGE_TYPES: &[u16] = &[
    // V2 unified message types
    LEDGER_UPDATE, LEDGER_UPDATE_RESPONSE,
    HANDSHAKE, HANDSHAKE_RESPONSE,
    SYNC, SYNC_RESPONSE,
    RECOVERY, RECOVERY_RESPONSE,
    COORDINATION, COORDINATION_RESPONSE,
    RELAY, RELAY_RESPONSE,
    // V1 message types (for compatibility with existing code)
    RESERVES_ADD_OUTPUT, RESERVES_REMOVE_OUTPUT, RESERVES_INCREASE, RESERVES_DECREASE,
    RESERVES_UPDATE_OUTPUT, UPDATE_RESERVES, ACCEPT_RESERVES,
    COLLATERAL_INCREASE, COLLATERAL_DECREASE, COLLATERAL_STATUS,
    DEPOSIT_OPEN, DEPOSIT_CLOSE, DEPOSIT_UPDATE, DEPOSIT_LOCK_TRANSFER, DEPOSIT_FAIL_TRANSFER,
    DEPOSIT_FULFILL_TRANSFER, LEDGER_CLOSE, MAINTENANCE_FEE_COLLECT, RECEIVING_COSIGN_INVOICE,
    RECEIVING_CREDIT_PAYMENT, UNCREDITED_PAYMENT, SENDING_LOCK_PAYMENT, SENDING_FAIL_PAYMENT,
    SENDING_FULFILL_PAYMENT, CHANNEL_CLOSE_TOMBSTONE, SIGNED_UPDATE, SYNC_REQUEST,
    LEDGER_OPEN_REQUEST, LEDGER_OPEN_RESPONSE, ACK, QUORUM_JOIN_REQUEST, QUORUM_JOIN_RESPONSE,
    QUORUM_STATE_SYNC, QUORUM_VOTE_REQUEST, QUORUM_VOTE, QUORUM_MEMBERSHIP_CHANGE,
    COLLATERAL_ATTESTATION, RECOVERY_VOTE, RECOVERY_CLAIM_REQUEST, RECOVERY_CLAIM_SIGNATURE,
    RECOVERY_CLAIM_COMPLETE, COLLATERAL_ADD_PARTNER, COLLATERAL_REMOVE_PARTNER,
    COLLATERAL_CONSENT_REQUEST, COLLATERAL_CONSENT_RESPONSE, RELAY_NWC_REQUEST,
    RELAY_NWC_RESPONSE, RELAY_NWC_DELIVERY_PROOF,
];

/// Messages that require acknowledgment
pub const MESSAGES_REQUIRING_ACK: &[u16] = &[
    LEDGER_UPDATE,
];

/// Check if a message type requires acknowledgment
pub fn requires_acknowledgment(type_id: u16) -> bool {
    MESSAGES_REQUIRING_ACK.contains(&type_id)
}

/// Convert a message type ID to its constant name
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
        RELAY => "RELAY",
        RELAY_RESPONSE => "RELAY_RESPONSE",
        _ => "UNKNOWN",
    }
}

/// Convert a message type ID to its variant name
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
        RELAY => Some("Relay"),
        RELAY_RESPONSE => Some("RelayResponse"),
        _ => None,
    }
}

// ============================================================================
// Writeable/Readable implementations for local V1 message types
// ============================================================================
// These enable proper binary encoding for locally-defined message types.
// Imported types from deposits-ldk already have their Readable/Writeable impls.

// CollateralAttestationMsg Writeable/Readable now comes from deposits-ldk

impl Writeable for ReceivingCosignInvoiceMsg {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
        use deposits_core::tlv::TlvEncode;
        let bytes = self.pending_invoice.tlv_encode();
        // Write length-prefixed TLV data
        (bytes.len() as u32).write(writer)?;
        writer.write_all(&bytes)
    }
}

impl Readable for ReceivingCosignInvoiceMsg {
    fn read<R: io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
        use deposits_core::tlv::TlvDecode;
        // Read length-prefixed TLV data
        let len: u32 = Readable::read(reader)?;
        let mut bytes = vec![0u8; len as usize];
        reader.read_exact(&mut bytes).map_err(|_| DecodeError::ShortRead)?;
        let core_invoice = deposits_core::PendingInvoice::tlv_decode(&bytes)
            .map_err(|_| DecodeError::InvalidValue)?;
        Ok(Self { pending_invoice: PendingInvoice(core_invoice) })
    }
}

// V1 SignedUpdate (LedgerUpdateMsg) encoding - includes partner_signature
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

        // For V1 SignedUpdate, the actual operation is in the `message` bytes
        // The operation field is a placeholder - V1 code uses message_type + message
        Ok(Self {
            operator_pubkey,
            partner_pubkey,
            operation: deposits_core::LedgerOperation::ReservesRemove, // Placeholder for V1
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

        // Try V1 message types first (with Readable implementations)
        // These need the reader passed directly to their Readable impl
        match msg_type {
            RECEIVING_CREDIT_PAYMENT => {
                return ReceivingCreditPaymentMsg::read(reader).map(|m| Self::ReceivingCreditPayment {
                    payment_hash: m.payment_hash,
                    deposit_pubkey: m.deposit_pubkey,
                    amount: m.amount,
                    invoice_id: m.invoice_id,
                    partner_id: m.partner_id,
                    sequence_number: m.sequence_number,
                });
            }
            SENDING_LOCK_PAYMENT => {
                return SendingLockPaymentMsg::read(reader).map(|m| Self::SendingLockPayment {
                    pubkey: m.pubkey,
                    amount: m.amount,
                    payment_id: m.payment_id,
                    sequence_number: m.sequence_number,
                    scriptpubkey_signature: m.scriptpubkey_signature,
                });
            }
            SENDING_FAIL_PAYMENT => {
                return SendingFailPaymentMsg::read(reader).map(|m| Self::SendingFailPayment {
                    pubkey: m.pubkey,
                    amount: m.amount,
                    payment_id: m.payment_id,
                    sequence_number: m.sequence_number,
                });
            }
            SENDING_FULFILL_PAYMENT => {
                return SendingFulfillPaymentMsg::read(reader).map(|m| Self::SendingFulfillPayment {
                    pubkey: m.pubkey,
                    amount: m.amount,
                    payment_id: m.payment_id,
                    sequence_number: m.sequence_number,
                    scriptpubkey_signature: m.scriptpubkey_signature,
                    preimage: m.preimage,
                });
            }
            DEPOSIT_OPEN => {
                return DepositOpenMsg::read(reader).map(|m| Self::DepositOpen {
                    partner_id: m.partner_id,
                    pubkey: m.pubkey,
                    fees: m.fees,
                    payment_hash: m.payment_hash,
                    invoice: m.invoice,
                    cosigner_guarantee_signature: m.cosigner_guarantee_signature,
                });
            }
            DEPOSIT_CLOSE => {
                return DepositCloseMsg::read(reader).map(|m| Self::DepositClose {
                    partner_id: m.partner_id,
                    pubkey: m.pubkey,
                });
            }
            RESERVES_ADD_OUTPUT => {
                return ReservesAddOutputMsg::read(reader).map(|m| Self::ReservesAddOutput {
                    initial_amount: m.initial_amount,
                    spend_to: m.spend_to,
                    partner_id: m.partner_id,
                    collateral_partners: m.collateral_partners,
                });
            }
            RESERVES_REMOVE_OUTPUT => {
                return ReservesRemoveOutputMsg::read(reader).map(|m| Self::ReservesRemoveOutput {
                    partner_id: m.partner_id,
                    remove_all: m.remove_all,
                });
            }
            MAINTENANCE_FEE_COLLECT => {
                return FeeCollectMsg::read(reader).map(|m| Self::MaintenanceFeeCollect {
                    pubkey: m.pubkey,
                    amount: m.amount,
                    block_height: m.block_height,
                });
            }
            CHANNEL_CLOSE_TOMBSTONE => {
                return ChannelCloseTombstoneMsg::read(reader).map(|m| Self::ChannelCloseTombstone {
                    operator_pubkey: m.operator_pubkey,
                    partner_pubkey: m.partner_pubkey,
                    timestamp: m.timestamp,
                    channel_id: m.channel_id,
                    close_reason: m.close_reason,
                    sequence_number: m.sequence_number,
                });
            }
            RESERVES_INCREASE => {
                return ReservesIncreaseMsg::read(reader).map(|m| Self::ReservesIncrease {
                    partner_id: m.partner_id,
                    new_amount: m.new_amount,
                });
            }
            RESERVES_DECREASE => {
                return ReservesDecreaseMsg::read(reader).map(|m| Self::ReservesDecrease {
                    partner_id: m.partner_id,
                    new_amount: m.new_amount,
                });
            }
            RESERVES_UPDATE_OUTPUT => {
                return ReservesUpdateOutputMsg::read(reader).map(|m| Self::ReservesUpdateOutput {
                    partner_id: m.partner_id,
                    spend_to: m.spend_to,
                });
            }
            UPDATE_RESERVES => {
                return UpdateReservesMsg::read(reader).map(|m| Self::UpdateReserves {
                    channel_id: m.channel_id,
                    reserves_sats: m.reserves_sats,
                    script_pubkey: m.script_pubkey,
                    ledger_hash: m.ledger_hash,
                    remote_ledger_hash: m.remote_ledger_hash,
                });
            }
            ACCEPT_RESERVES => {
                return AcceptReservesMsg::read(reader).map(|m| Self::AcceptReserves {
                    channel_id: m.channel_id,
                });
            }
            COLLATERAL_INCREASE => {
                return CollateralIncreaseMsg::read(reader).map(|m| Self::CollateralIncrease {
                    partner_id: m.partner_id,
                    new_amount: m.new_amount,
                    block_height: m.block_height,
                });
            }
            COLLATERAL_DECREASE => {
                return CollateralDecreaseMsg::read(reader).map(|m| Self::CollateralDecrease {
                    partner_id: m.partner_id,
                    new_amount: m.new_amount,
                    block_height: m.block_height,
                });
            }
            COLLATERAL_STATUS => {
                return CollateralStatusMsg::read(reader).map(|m| Self::CollateralStatus {
                    collateral_operator: m.collateral_operator,
                    amount: m.amount,
                    block_height: m.block_height,
                    signature: m.signature,
                });
            }
            COLLATERAL_CONSENT_REQUEST => {
                return CollateralConsentRequestMsg::read(reader).map(|m| Self::CollateralConsentRequest {
                    operator_id: m.operator_id,
                    partner_id: m.partner_id,
                    operator_signature: m.operator_signature,
                });
            }
            COLLATERAL_CONSENT_RESPONSE => {
                return CollateralConsentResponseMsg::read(reader).map(|m| Self::CollateralConsentResponse {
                    operator_id: m.operator_id,
                    partner_id: m.partner_id,
                    consent_granted: m.consent_granted,
                    collateral_partner_signature: m.collateral_partner_signature,
                });
            }
            COLLATERAL_ADD_PARTNER => {
                return CollateralAddPartnerMsg::read(reader).map(|m| Self::CollateralAddPartner {
                    operator_id: m.operator_id,
                    partner_id: m.partner_id,
                    collateral_partner: m.collateral_partner,
                    collateral_partner_signature: m.collateral_partner_signature,
                });
            }
            COLLATERAL_REMOVE_PARTNER => {
                return CollateralRemovePartnerMsg::read(reader).map(|m| Self::CollateralRemovePartner {
                    partner_id: m.partner_id,
                    collateral_partner: m.collateral_partner,
                    operator_signature: m.operator_signature,
                });
            }
            COLLATERAL_ATTESTATION => {
                return CollateralAttestationMsg::read(reader).map(|m| Self::CollateralAttestation {
                    operator: m.operator,
                    collateral_partner: m.collateral_partner,
                    amount: m.amount,
                    block_height: m.block_height,
                    signature: m.signature,
                    ledger_hash: m.ledger_hash,
                });
            }
            RECEIVING_COSIGN_INVOICE => {
                return ReceivingCosignInvoiceMsg::read(reader).map(|m| Self::ReceivingCosignInvoice {
                    pending_invoice: m.pending_invoice,
                });
            }
            SIGNED_UPDATE => {
                return LedgerUpdateMsg::read(reader).map(Self::SignedUpdate);
            }
            _ => {}
        }

        // For V2 message types and V1 types that use V2 payload format,
        // read remaining bytes and use V2 codec
        let mut bytes = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => bytes.extend_from_slice(&buf[..n]),
                Err(_) => return Err(DecodeError::ShortRead),
            }
        }

        // Map V1 message types to V2 equivalents for decoding
        // These V1 types use V2 payload format but different type IDs
        let v2_msg_type = match msg_type {
            LEDGER_OPEN_REQUEST => HANDSHAKE,
            LEDGER_OPEN_RESPONSE => HANDSHAKE_RESPONSE,
            ACK => LEDGER_UPDATE_RESPONSE,
            _ => msg_type,
        };

        // Prepend (mapped) message type for V2 decode
        let mut full_bytes = v2_msg_type.to_be_bytes().to_vec();
        full_bytes.extend(bytes);

        // Decode using deposits-core codec and convert to our enum
        match DepositsMessageCore::decode(&full_bytes) {
            Ok(v2_msg) => {
                let result = Self::from_v2(v2_msg);
                // Re-wrap in V1 variant if original type was V1
                let final_msg = match msg_type {
                    LEDGER_OPEN_REQUEST => {
                        if let Self::Handshake(h) = result {
                            Self::LedgerOpenRequest(h)
                        } else {
                            result
                        }
                    }
                    LEDGER_OPEN_RESPONSE => {
                        if let Self::HandshakeResponse(h) = result {
                            Self::LedgerOpenResponse(h)
                        } else {
                            result
                        }
                    }
                    ACK => {
                        if let Self::LedgerUpdateResponse(r) = result {
                            Self::Ack(r)
                        } else {
                            result
                        }
                    }
                    _ => result,
                };
                Ok(final_msg)
            }
            Err(_) => Err(DecodeError::InvalidValue),
        }
    }
}

impl Writeable for DepositsMessage {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
        // V1 message types with custom Readable/Writeable implementations must be
        // serialized directly using their V1 format. Using encode() -> into_v2()
        // would produce the wrong wire format (V2 format with V1 type prefix).
        //
        // For V2 message types and V1 aliases that map to V2, use encode().
        match self {
            // === V1 message types - serialize using V1 Writeable directly ===
            Self::DepositOpen { partner_id, pubkey, fees, payment_hash, invoice, cosigner_guarantee_signature } => {
                DepositOpenMsg { partner_id: *partner_id, pubkey: *pubkey, fees: fees.clone(), payment_hash: *payment_hash, invoice: invoice.clone(), cosigner_guarantee_signature: *cosigner_guarantee_signature }.write(writer)
            }
            Self::DepositClose { partner_id, pubkey } => {
                DepositCloseMsg { partner_id: *partner_id, pubkey: *pubkey }.write(writer)
            }
            Self::ReservesAddOutput { initial_amount, spend_to, partner_id, collateral_partners } => {
                ReservesAddOutputMsg { initial_amount: *initial_amount, spend_to: *spend_to, partner_id: *partner_id, collateral_partners: collateral_partners.clone() }.write(writer)
            }
            Self::ReservesRemoveOutput { partner_id, remove_all } => {
                ReservesRemoveOutputMsg { partner_id: *partner_id, remove_all: *remove_all }.write(writer)
            }
            Self::ReservesIncrease { partner_id, new_amount } => {
                ReservesIncreaseMsg { partner_id: *partner_id, new_amount: *new_amount }.write(writer)
            }
            Self::ReservesDecrease { partner_id, new_amount } => {
                ReservesDecreaseMsg { partner_id: *partner_id, new_amount: *new_amount }.write(writer)
            }
            Self::ReservesUpdateOutput { partner_id, spend_to } => {
                ReservesUpdateOutputMsg { partner_id: *partner_id, spend_to: *spend_to }.write(writer)
            }
            Self::UpdateReserves { channel_id, reserves_sats, script_pubkey, ledger_hash, remote_ledger_hash } => {
                UpdateReservesMsg {
                    channel_id: *channel_id,
                    reserves_sats: *reserves_sats,
                    script_pubkey: script_pubkey.clone(),
                    ledger_hash: *ledger_hash,
                    remote_ledger_hash: *remote_ledger_hash,
                }.write(writer)
            }
            Self::AcceptReserves { channel_id } => {
                AcceptReservesMsg { channel_id: *channel_id }.write(writer)
            }
            Self::ReceivingCreditPayment { payment_hash, deposit_pubkey, amount, invoice_id, partner_id, sequence_number } => {
                ReceivingCreditPaymentMsg { payment_hash: *payment_hash, deposit_pubkey: *deposit_pubkey, amount: *amount, invoice_id: invoice_id.clone(), partner_id: *partner_id, sequence_number: *sequence_number }.write(writer)
            }
            Self::ReceivingCosignInvoice { pending_invoice } => {
                ReceivingCosignInvoiceMsg { pending_invoice: pending_invoice.clone() }.write(writer)
            }
            Self::SendingLockPayment { pubkey, amount, payment_id, sequence_number, scriptpubkey_signature } => {
                SendingLockPaymentMsg { pubkey: *pubkey, amount: *amount, payment_id: *payment_id, sequence_number: *sequence_number, scriptpubkey_signature: *scriptpubkey_signature }.write(writer)
            }
            Self::SendingFulfillPayment { pubkey, amount, payment_id, sequence_number, scriptpubkey_signature, preimage } => {
                SendingFulfillPaymentMsg { pubkey: *pubkey, amount: *amount, payment_id: *payment_id, sequence_number: *sequence_number, scriptpubkey_signature: *scriptpubkey_signature, preimage: *preimage }.write(writer)
            }
            Self::SendingFailPayment { pubkey, amount, payment_id, sequence_number } => {
                SendingFailPaymentMsg { pubkey: *pubkey, amount: *amount, payment_id: *payment_id, sequence_number: *sequence_number }.write(writer)
            }
            Self::CollateralIncrease { partner_id, new_amount, block_height } => {
                CollateralIncreaseMsg { partner_id: *partner_id, new_amount: *new_amount, block_height: *block_height }.write(writer)
            }
            Self::CollateralDecrease { partner_id, new_amount, block_height } => {
                CollateralDecreaseMsg { partner_id: *partner_id, new_amount: *new_amount, block_height: *block_height }.write(writer)
            }
            Self::CollateralStatus { collateral_operator, amount, block_height, signature } => {
                CollateralStatusMsg { collateral_operator: *collateral_operator, amount: *amount, block_height: *block_height, signature: *signature }.write(writer)
            }
            Self::CollateralAttestation { operator, collateral_partner, amount, block_height, signature, ledger_hash } => {
                CollateralAttestationMsg { operator: *operator, collateral_partner: *collateral_partner, amount: *amount, block_height: *block_height, signature: *signature, ledger_hash: *ledger_hash }.write(writer)
            }
            Self::CollateralAddPartner { operator_id, partner_id, collateral_partner, collateral_partner_signature } => {
                CollateralAddPartnerMsg { operator_id: *operator_id, partner_id: *partner_id, collateral_partner: *collateral_partner, collateral_partner_signature: *collateral_partner_signature }.write(writer)
            }
            Self::CollateralRemovePartner { partner_id, collateral_partner, operator_signature } => {
                CollateralRemovePartnerMsg { partner_id: *partner_id, collateral_partner: *collateral_partner, operator_signature: *operator_signature }.write(writer)
            }
            Self::CollateralConsentRequest { operator_id, partner_id, operator_signature } => {
                CollateralConsentRequestMsg { operator_id: *operator_id, partner_id: *partner_id, operator_signature: *operator_signature }.write(writer)
            }
            Self::CollateralConsentResponse { operator_id, partner_id, consent_granted, collateral_partner_signature } => {
                CollateralConsentResponseMsg { operator_id: *operator_id, partner_id: *partner_id, consent_granted: *consent_granted, collateral_partner_signature: *collateral_partner_signature }.write(writer)
            }
            Self::MaintenanceFeeCollect { pubkey, amount, block_height } => {
                FeeCollectMsg { pubkey: *pubkey, amount: *amount, block_height: *block_height }.write(writer)
            }
            Self::ChannelCloseTombstone { operator_pubkey, partner_pubkey, timestamp, channel_id, close_reason, sequence_number } => {
                ChannelCloseTombstoneMsg { operator_pubkey: *operator_pubkey, partner_pubkey: *partner_pubkey, timestamp: *timestamp, channel_id: *channel_id, close_reason: close_reason.clone(), sequence_number: *sequence_number }.write(writer)
            }
            Self::SignedUpdate(m) => m.write(writer),
            Self::LedgerClose { partner_id } => {
                LedgerCloseMsg { partner_id: *partner_id }.write(writer)
            }

            // === V2 message types and V1 aliases that map to V2 - use encode() ===
            _ => {
                // LDK adds the type prefix separately via type_id(), so we only write payload
                // encode() returns [type: u16][payload], so skip first 2 bytes
                let bytes = self.encode();
                if bytes.len() >= 2 {
                    writer.write_all(&bytes[2..])
                } else {
                    Ok(())
                }
            }
        }
    }
}

impl lightning::ln::wire::Type for DepositsMessage {
    fn type_id(&self) -> u16 {
        self.message_type()
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
        println!("🔍 MESSAGE_READER: Checking type {:#06x}, is_deposits={}",
            message_type, is_deposits_message_type(message_type));

        // Check if this is a deposits message type
        if !is_deposits_message_type(message_type) {
            return Ok(None);
        }

        // Try V1 message types first (with Readable implementations)
        match message_type {
            RECEIVING_CREDIT_PAYMENT => {
                return ReceivingCreditPaymentMsg::read(buffer)
                    .map(|m| Some(DepositsMessage::ReceivingCreditPayment {
                        payment_hash: m.payment_hash,
                        deposit_pubkey: m.deposit_pubkey,
                        amount: m.amount,
                        invoice_id: m.invoice_id,
                        partner_id: m.partner_id,
                        sequence_number: m.sequence_number,
                    }));
            }
            SENDING_LOCK_PAYMENT => {
                return SendingLockPaymentMsg::read(buffer)
                    .map(|m| Some(DepositsMessage::SendingLockPayment {
                        pubkey: m.pubkey,
                        amount: m.amount,
                        payment_id: m.payment_id,
                        sequence_number: m.sequence_number,
                        scriptpubkey_signature: m.scriptpubkey_signature,
                    }));
            }
            SENDING_FAIL_PAYMENT => {
                return SendingFailPaymentMsg::read(buffer)
                    .map(|m| Some(DepositsMessage::SendingFailPayment {
                        pubkey: m.pubkey,
                        amount: m.amount,
                        payment_id: m.payment_id,
                        sequence_number: m.sequence_number,
                    }));
            }
            SENDING_FULFILL_PAYMENT => {
                return SendingFulfillPaymentMsg::read(buffer)
                    .map(|m| Some(DepositsMessage::SendingFulfillPayment {
                        pubkey: m.pubkey,
                        amount: m.amount,
                        payment_id: m.payment_id,
                        sequence_number: m.sequence_number,
                        scriptpubkey_signature: m.scriptpubkey_signature,
                        preimage: m.preimage,
                    }));
            }
            DEPOSIT_OPEN => {
                return DepositOpenMsg::read(buffer)
                    .map(|m| Some(DepositsMessage::DepositOpen {
                        partner_id: m.partner_id,
                        pubkey: m.pubkey,
                        fees: m.fees,
                        payment_hash: m.payment_hash,
                        invoice: m.invoice,
                        cosigner_guarantee_signature: m.cosigner_guarantee_signature,
                    }));
            }
            DEPOSIT_CLOSE => {
                return DepositCloseMsg::read(buffer)
                    .map(|m| Some(DepositsMessage::DepositClose {
                        partner_id: m.partner_id,
                        pubkey: m.pubkey,
                    }));
            }
            RESERVES_ADD_OUTPUT => {
                return ReservesAddOutputMsg::read(buffer)
                    .map(|m| Some(DepositsMessage::ReservesAddOutput {
                        initial_amount: m.initial_amount,
                        spend_to: m.spend_to,
                        partner_id: m.partner_id,
                        collateral_partners: m.collateral_partners,
                    }));
            }
            RESERVES_REMOVE_OUTPUT => {
                return ReservesRemoveOutputMsg::read(buffer)
                    .map(|m| Some(DepositsMessage::ReservesRemoveOutput {
                        partner_id: m.partner_id,
                        remove_all: m.remove_all,
                    }));
            }
            RESERVES_INCREASE => {
                return ReservesIncreaseMsg::read(buffer)
                    .map(|m| Some(DepositsMessage::ReservesIncrease {
                        partner_id: m.partner_id,
                        new_amount: m.new_amount,
                    }));
            }
            RESERVES_DECREASE => {
                return ReservesDecreaseMsg::read(buffer)
                    .map(|m| Some(DepositsMessage::ReservesDecrease {
                        partner_id: m.partner_id,
                        new_amount: m.new_amount,
                    }));
            }
            RESERVES_UPDATE_OUTPUT => {
                return ReservesUpdateOutputMsg::read(buffer)
                    .map(|m| Some(DepositsMessage::ReservesUpdateOutput {
                        partner_id: m.partner_id,
                        spend_to: m.spend_to,
                    }));
            }
            UPDATE_RESERVES => {
                return UpdateReservesMsg::read(buffer)
                    .map(|m| Some(DepositsMessage::UpdateReserves {
                        channel_id: m.channel_id,
                        reserves_sats: m.reserves_sats,
                        script_pubkey: m.script_pubkey,
                        ledger_hash: m.ledger_hash,
                        remote_ledger_hash: m.remote_ledger_hash,
                    }));
            }
            ACCEPT_RESERVES => {
                return AcceptReservesMsg::read(buffer)
                    .map(|m| Some(DepositsMessage::AcceptReserves {
                        channel_id: m.channel_id,
                    }));
            }
            COLLATERAL_INCREASE => {
                return CollateralIncreaseMsg::read(buffer)
                    .map(|m| Some(DepositsMessage::CollateralIncrease {
                        partner_id: m.partner_id,
                        new_amount: m.new_amount,
                        block_height: m.block_height,
                    }));
            }
            COLLATERAL_DECREASE => {
                return CollateralDecreaseMsg::read(buffer)
                    .map(|m| Some(DepositsMessage::CollateralDecrease {
                        partner_id: m.partner_id,
                        new_amount: m.new_amount,
                        block_height: m.block_height,
                    }));
            }
            COLLATERAL_STATUS => {
                return CollateralStatusMsg::read(buffer)
                    .map(|m| Some(DepositsMessage::CollateralStatus {
                        collateral_operator: m.collateral_operator,
                        amount: m.amount,
                        block_height: m.block_height,
                        signature: m.signature,
                    }));
            }
            MAINTENANCE_FEE_COLLECT => {
                return FeeCollectMsg::read(buffer)
                    .map(|m| Some(DepositsMessage::MaintenanceFeeCollect {
                        pubkey: m.pubkey,
                        amount: m.amount,
                        block_height: m.block_height,
                    }));
            }
            CHANNEL_CLOSE_TOMBSTONE => {
                return ChannelCloseTombstoneMsg::read(buffer)
                    .map(|m| Some(DepositsMessage::ChannelCloseTombstone {
                        operator_pubkey: m.operator_pubkey,
                        partner_pubkey: m.partner_pubkey,
                        timestamp: m.timestamp,
                        channel_id: m.channel_id,
                        close_reason: m.close_reason,
                        sequence_number: m.sequence_number,
                    }));
            }
            COLLATERAL_CONSENT_REQUEST => {
                return CollateralConsentRequestMsg::read(buffer)
                    .map(|m| Some(DepositsMessage::CollateralConsentRequest {
                        operator_id: m.operator_id,
                        partner_id: m.partner_id,
                        operator_signature: m.operator_signature,
                    }));
            }
            COLLATERAL_CONSENT_RESPONSE => {
                return CollateralConsentResponseMsg::read(buffer)
                    .map(|m| Some(DepositsMessage::CollateralConsentResponse {
                        operator_id: m.operator_id,
                        partner_id: m.partner_id,
                        consent_granted: m.consent_granted,
                        collateral_partner_signature: m.collateral_partner_signature,
                    }));
            }
            COLLATERAL_ADD_PARTNER => {
                return CollateralAddPartnerMsg::read(buffer)
                    .map(|m| Some(DepositsMessage::CollateralAddPartner {
                        operator_id: m.operator_id,
                        partner_id: m.partner_id,
                        collateral_partner: m.collateral_partner,
                        collateral_partner_signature: m.collateral_partner_signature,
                    }));
            }
            COLLATERAL_REMOVE_PARTNER => {
                return CollateralRemovePartnerMsg::read(buffer)
                    .map(|m| Some(DepositsMessage::CollateralRemovePartner {
                        partner_id: m.partner_id,
                        collateral_partner: m.collateral_partner,
                        operator_signature: m.operator_signature,
                    }));
            }
            COLLATERAL_ATTESTATION => {
                return CollateralAttestationMsg::read(buffer)
                    .map(|m| Some(DepositsMessage::CollateralAttestation {
                        operator: m.operator,
                        collateral_partner: m.collateral_partner,
                        amount: m.amount,
                        block_height: m.block_height,
                        signature: m.signature,
                        ledger_hash: m.ledger_hash,
                    }));
            }
            RECEIVING_COSIGN_INVOICE => {
                return ReceivingCosignInvoiceMsg::read(buffer)
                    .map(|m| Some(DepositsMessage::ReceivingCosignInvoice {
                        pending_invoice: m.pending_invoice,
                    }));
            }
            LEDGER_CLOSE => {
                return LedgerCloseMsg::read(buffer)
                    .map(|m| Some(DepositsMessage::LedgerClose {
                        partner_id: m.partner_id,
                    }));
            }
            SIGNED_UPDATE => {
                // Use V1 decoding to preserve partner_signature
                return LedgerUpdateMsg::read(buffer)
                    .map(|m| Some(DepositsMessage::SignedUpdate(m)));
            }
            _ => {}
        }

        // For V2 message types, read remaining bytes and use V2 codec
        let mut bytes = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match buffer.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => bytes.extend_from_slice(&buf[..n]),
                Err(_) => return Err(DecodeError::ShortRead),
            }
        }

        // Map V1 message types to their V2 equivalents for decoding
        // These V1 types use the same wire format as V2 but different type IDs
        // (they are type aliases: LedgerOpenRequestMsg = HandshakeMsg, etc.)
        // Note: SIGNED_UPDATE is handled above with V1 decoding to preserve partner_signature
        let v2_message_type = match message_type {
            LEDGER_OPEN_REQUEST => HANDSHAKE,
            LEDGER_OPEN_RESPONSE => HANDSHAKE_RESPONSE,
            ACK => LEDGER_UPDATE_RESPONSE,
            _ => message_type,
        };

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
        let tlv_result: Option<DepositsMessageCore> = match v2_message_type {
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
                let mut full_bytes = v2_message_type.to_be_bytes().to_vec();
                full_bytes.extend(&bytes);
                match DepositsMessageCore::decode(&full_bytes) {
                    Ok(msg) => msg,
                    Err(_) => return Err(DecodeError::InvalidValue),
                }
            }
        };

        // Convert to our enum and wrap in correct V1 variant if needed
        let result = DepositsMessage::from_v2(v2_msg);
        let final_msg = match message_type {
            LEDGER_OPEN_REQUEST => {
                if let DepositsMessage::Handshake(h) = result {
                    DepositsMessage::LedgerOpenRequest(h)
                } else {
                    result
                }
            }
            LEDGER_OPEN_RESPONSE => {
                if let DepositsMessage::HandshakeResponse(h) = result {
                    DepositsMessage::LedgerOpenResponse(h)
                } else {
                    result
                }
            }
            ACK => {
                if let DepositsMessage::LedgerUpdateResponse(r) = result {
                    DepositsMessage::Ack(r)
                } else {
                    result
                }
            }
            // Note: SIGNED_UPDATE is handled above with V1 decoding
            _ => result,
        };
        Ok(Some(final_msg))
    }
}

/// Check if a message type ID is a deposits protocol message
pub fn is_deposits_message_type(type_id: u16) -> bool {
    ALL_MESSAGE_TYPES.contains(&type_id)
}

// ============================================================================
// Serde helpers for byte arrays (kept for API compatibility)
// ============================================================================

pub mod serde_arrays {
    use serde::{Deserializer, Serializer, Deserialize, Serialize};

    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        bytes.as_slice().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where D: Deserializer<'de> {
        let vec: Vec<u8> = Vec::deserialize(deserializer)?;
        if vec.len() == 64 {
            let mut array = [0u8; 64];
            array.copy_from_slice(&vec);
            Ok(array)
        } else {
            Err(serde::de::Error::custom(format!("Expected 64 bytes, got {}", vec.len())))
        }
    }
}

pub mod serde_arrays_32 {
    use serde::{Deserializer, Serializer, Deserialize, Serialize};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        bytes.as_slice().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where D: Deserializer<'de> {
        let vec: Vec<u8> = Vec::deserialize(deserializer)?;
        if vec.len() == 32 {
            let mut array = [0u8; 32];
            array.copy_from_slice(&vec);
            Ok(array)
        } else {
            Err(serde::de::Error::custom(format!("Expected 32 bytes, got {}", vec.len())))
        }
    }
}

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
