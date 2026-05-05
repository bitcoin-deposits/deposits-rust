//! Bitcoin Deposits Protocol — wire format, types, and encoding
//!
//! Pure protocol definitions with no state machine or handler logic.
//! Depends only on bitcoin, serde, and crypto primitives.

#![allow(missing_docs)]

pub mod constants;
pub mod error;
pub mod fraud;
pub mod messages;
pub mod signature_utils;
pub mod tlv;
pub mod types;
pub mod wire_messages;

/// Kaitai Struct generated parser (for reading raw TLV bytes)
#[cfg(feature = "kaitai-parser")]
#[allow(clippy::all, unused_parens)]
#[path = "../generated/deposits_protocol.rs"]
pub mod kaitai_parser;

// Re-exports
pub use constants::{
    COLLATERAL_REPORTING_PERIOD_BLOCKS, DEFAULT_EMERGENCY_TIMEOUT_BLOCKS,
    DEPOSITS_PROTOCOL_VERSION, MAX_EMERGENCY_TIMEOUT_BLOCKS, MAX_RESERVES_OUTPUT_SATS,
    MIN_EMERGENCY_TIMEOUT_BLOCKS, MIN_RESERVES_OUTPUT_SATS, MIN_RESERVES_RATIO_PERCENT,
};
pub use error::{DepositsError, DepositsResult, HandlerError};
pub use messages::{DepositsMessage, HashStrategy, LedgerOperation, ReplacementCollateral};
pub use signature_utils::{
    compute_transfer_id, invoice_cosign_signing_message, invoice_lock_signing_message,
    offer_cosign_signing_message, transfer_lock_signing_message, withdrawal_signing_message,
};
pub use tlv::{TlvBuilder, TlvDecode, TlvEncode, TlvError, TlvReader, TlvResult, TlvStream};
pub use types::{
    compute_deposit_id, entropy_selection_score, is_entropy_winner, select_entropy_winner,
    serde_32, serde_64, serde_opt_64, serde_pubkey, serde_pubkey_map, serde_pubkey_vec,
    AuditResult, ChannelId, CommitmentExtraOutput, ConformanceViolation, CrossLedgerViolation,
    Deposit, DepositId, DepositInfo, DepositOffer, DepositOfferStatus, DescriptorWitness,
    DisputeState, FeeStructure, Invoice, InvoiceInfo, LedgerState, LedgerStateUpdate, LedgerUpdate,
    NoVerify, OnChainWithdrawal, OnChainWithdrawalStatus, PendingInvoice, PendingTransfer,
    QuorumJoinRequestMsg, QuorumJoinResponseMsg, QuorumState, QuorumVoteMsg, ReservesOutput,
    ReservesStatus, SignedLedgerUpdate, SignedLedgerUpdateLog, TransferFeeSchedule, Violation,
    WithdrawalCompleteResult, WithdrawalLockResult, WitnessVerifier,
};
