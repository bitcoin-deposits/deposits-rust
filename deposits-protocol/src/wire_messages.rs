// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Wire Protocol Message Structs
//!
//! This module contains message structs used as parameter types by message handlers.
//! Serialization uses TLV encoding provided separately in deposits-ldk.

use bitcoin::secp256k1::PublicKey;

use crate::types::FeeStructure;

// ============================================================================
// Reserves Messages
// ============================================================================

/// reserves add output message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReservesAddOutputMsg {
    pub initial_amount: u64,
    pub spend_to: PublicKey,
    pub reserves_id: String,
    pub quorum_members: Vec<PublicKey>,
}

/// reserves remove output message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReservesRemoveOutputMsg {
    pub reserves_id: String,
    pub remove_all: bool,
}

/// reserves update output message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReservesUpdateOutputMsg {
    pub reserves_id: String,
    pub spend_to: PublicKey,
}

// ============================================================================
// Reserves Commitment Protocol Messages
// ============================================================================

/// UpdateReserves message - sent to propose reserves commitment to counterparty
///
/// This custom message is sent after calling propose_extra_outputs() on the
/// ChannelManager to notify the counterparty of the proposed extra outputs.
/// The counterparty should respond with AcceptReserves after validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateReservesMsg {
    /// The Lightning channel ID
    pub channel_id: [u8; 32],
    /// Reserves amount in satoshis
    pub reserves_sats: u64,
    /// The script pubkey for the reserves output
    pub script_pubkey: Vec<u8>,
    /// Our ledger hash being committed
    pub ledger_hash: [u8; 32],
    /// Remote ledger hash for bidirectional verification
    pub remote_ledger_hash: [u8; 32],
}

/// AcceptReserves message - response to UpdateReserves indicating acceptance
///
/// Sent by the counterparty after validating and accepting the proposed
/// reserves commitment via accept_extra_outputs_proposal().
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptReservesMsg {
    /// The Lightning channel ID
    pub channel_id: [u8; 32],
}

// ============================================================================
// Deposit Messages
// ============================================================================

/// deposit open message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DepositOpenMsg {
    pub reserves_id: String,
    pub pubkey: PublicKey,
    pub fees: Option<FeeStructure>,
    pub payment_hash: Option<[u8; 32]>,
    pub invoice: Option<String>,
    pub cosigner_guarantee_signature: Option<[u8; 64]>,
}

/// deposit close message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DepositCloseMsg {
    pub reserves_id: String,
    pub pubkey: PublicKey,
}

/// fee change message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeeChangeMsg {
    pub reserves_id: String,
    pub pubkey: PublicKey,
    pub new_fees: FeeStructure,
}

// ============================================================================
// Fee and Ledger Close Messages
// ============================================================================

/// fee collect message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeeCollectMsg {
    pub pubkey: PublicKey,
    pub amount: u64,
    pub block_height: u32,
}

/// ledger close message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerCloseMsg {
    pub reserves_id: String,
}

// ============================================================================
// Payment Messages
// ============================================================================

/// receiving credit payment message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceivingCreditPaymentMsg {
    pub payment_hash: [u8; 32],
    pub deposit_pubkey: PublicKey,
    pub amount: u64,
    pub invoice_id: String,
    pub reserves_id: String,
    pub sequence_number: u64,
}

/// sending lock payment message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendingLockPaymentMsg {
    pub pubkey: PublicKey,
    pub amount: u64,
    pub payment_id: [u8; 32],
    pub sequence_number: u64,
    pub scriptpubkey_signature: [u8; 64],
}

/// sending fail payment message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendingFailPaymentMsg {
    pub pubkey: PublicKey,
    pub amount: u64,
    pub payment_id: [u8; 32],
    pub sequence_number: u64,
}

/// sending fulfill payment message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendingFulfillPaymentMsg {
    pub pubkey: PublicKey,
    pub amount: u64,
    pub payment_id: [u8; 32],
    pub sequence_number: u64,
    pub scriptpubkey_signature: [u8; 64],
    pub preimage: [u8; 32],
}

/// receiving cosign invoice message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceivingCosignInvoiceMsg {
    pub amount: u64,
    pub payment_hash: [u8; 32],
    pub expires: u64,
    pub assigned_deposit: PublicKey,
    pub invoice_id: String,
    pub bolt11: String,
}

// ============================================================================
// Collateral Messages
// ============================================================================

/// quorum add member message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuorumAddMemberMsg {
    pub operator_id: PublicKey,
    pub reserves_id: String,
    pub quorum_member: PublicKey,
    pub quorum_member_signature: [u8; 64],
    /// The ledger ID where this member will lock collateral
    pub member_ledger_id: String,
}

/// quorum remove member message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuorumRemoveMemberMsg {
    pub reserves_id: String,
    pub quorum_member: PublicKey,
    pub operator_signature: [u8; 64],
}

/// collateral consent request message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollateralConsentRequestMsg {
    pub operator_id: PublicKey,
    pub reserves_id: String,
    pub operator_signature: [u8; 64],
}

/// collateral consent response message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollateralConsentResponseMsg {
    pub operator_id: PublicKey,
    pub reserves_id: String,
    pub consent_granted: bool,
    pub quorum_member_signature: [u8; 64],
}

// ============================================================================
// Sync Messages
// ============================================================================

/// sync request message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncRequestMsg {
    pub ledger_id: [u8; 32],
    pub last_known_sequence: u64,
}

// ============================================================================
// Quorum Messages
// ============================================================================

/// quorum join request message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuorumJoinRequestMsgWire {
    pub requester_pubkey: PublicKey,
    pub operator_id: PublicKey,
    pub reserves_id: String,
    pub protocol_version: u16,
    pub timestamp: u64,
    pub signature: [u8; 64],
    /// Member's proposed compensation rate (bips of collected fees). See
    /// `DEFAULT_COMPENSATION_BPS` and `CoordinationMsg::QuorumJoinRequest`.
    pub compensation_bps: Option<u16>,
    pub compensation_deposit_id: Option<[u8; 16]>,
    pub compensation_frequency_blocks: Option<u32>,
}

/// quorum join response message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuorumJoinResponseMsgWire {
    pub accepted: bool,
    pub members: Vec<PublicKey>,
    pub threshold: u16,
    pub last_sequence: u64,
    pub content_hash: [u8; 32],
    pub rejection_reason: Option<String>,
}

/// quorum membership change message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuorumMembershipChangeMsg {
    pub operator_id: PublicKey,
    pub reserves_id: String,
    pub change_type: String,
    pub member_pubkey: PublicKey,
    pub new_members: Vec<PublicKey>,
}

/// quorum state sync message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuorumStateSyncMsg {
    pub operator_id: PublicKey,
    pub reserves_id: String,
    pub updates: Vec<Vec<u8>>,
    pub start_sequence: u64,
    pub is_final: bool,
}

/// quorum vote request message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuorumVoteRequestMsg {
    pub operator_id: PublicKey,
    pub reserves_id: String,
    pub vote_round_id: [u8; 32],
    pub sequence_number: u64,
    pub state_hash: [u8; 32],
    pub claimed_reserves: u64,
    pub collateral_amounts: Vec<u64>,
    pub reserves_outpoint: Vec<u8>,
    pub destination_script: Vec<u8>,
    pub fee_rate_sat_vbyte: u64,
}

/// quorum vote message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuorumVoteMsgWire {
    pub vote_round_id: [u8; 32],
    pub voter_pubkey: PublicKey,
    pub vote: bool,
    pub voter_sequence: u64,
    pub voter_state_hash: [u8; 32],
    pub evidence: Option<Vec<u8>>,
    pub signature: [u8; 64],
    pub spend_signature: Option<[u8; 64]>,
}

// ============================================================================
// Ledger Export Messages
// ============================================================================

/// Request to export a ledger for validation.
///
/// Sent by a partner or quorum member to request the complete ledger
/// history from the operator for conformance validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerExportRequestMsg {
    /// Operator's public key.
    pub operator_id: PublicKey,
    /// Reserves identifier for the ledger.
    pub reserves_id: String,
    /// Optional: only return updates after this sequence number.
    pub from_sequence: Option<u64>,
    /// Current block height (for export timestamp).
    pub block_height: u32,
}

/// Response containing the ledger export data.
///
/// Contains the complete ledger history for validation, including
/// all signed updates and current state information.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerExportResponseMsg {
    /// Operator's public key.
    pub operator_id: PublicKey,
    /// Reserves identifier for the ledger.
    pub reserves_id: String,
    /// Protocol version.
    pub version: u32,
    /// Export timestamp.
    pub exported_at: u64,
    /// Block height at export time.
    pub block_height: u32,
    /// Number of updates included.
    pub update_count: u32,
    /// Serialized updates (each update is length-prefixed).
    pub updates_data: Vec<u8>,
    /// Whether export was successful.
    pub success: bool,
    /// Error message if export failed.
    pub error_message: Option<String>,
}
