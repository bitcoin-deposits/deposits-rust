//! Bitcoin Deposits Protocol — wire format, types, and encoding
//!
//! Pure protocol definitions with no state machine or handler logic.
//! Depends only on bitcoin, serde, and crypto primitives.

#![allow(missing_docs)]

pub mod constants;
pub mod error;
pub mod tlv;
pub mod types;
pub mod messages;
pub mod signature_utils;
pub mod wire_messages;
pub mod fraud;

/// Kaitai Struct generated parser (for reading raw TLV bytes)
#[cfg(feature = "kaitai-parser")]
#[path = "../generated/deposits_protocol.rs"]
pub mod kaitai_parser;

// Re-exports
pub use constants::{
    MIN_RESERVES_OUTPUT_SATS, MAX_RESERVES_OUTPUT_SATS, DEFAULT_EMERGENCY_TIMEOUT_BLOCKS,
    MIN_EMERGENCY_TIMEOUT_BLOCKS, MAX_EMERGENCY_TIMEOUT_BLOCKS, MIN_RESERVES_RATIO_PERCENT,
    COLLATERAL_REPORTING_PERIOD_BLOCKS, DEPOSITS_PROTOCOL_VERSION,
};
pub use error::{DepositsError, DepositsResult, HandlerError};
pub use messages::{DepositsMessage, LedgerOperation, HashStrategy};
pub use tlv::{TlvEncode, TlvDecode, TlvStream, TlvBuilder, TlvReader, TlvError, TlvResult};
pub use types::{
    Deposit, FeeStructure, TransferFeeSchedule, PendingInvoice, ReservesOutput, Invoice,
    LedgerState, LedgerUpdate, SignedLedgerUpdate, SignedLedgerUpdateLog,
    DepositId, DescriptorWitness, compute_deposit_id,
    DisputeState, entropy_selection_score, select_entropy_winner, is_entropy_winner,
    DepositInfo, InvoiceInfo, ReservesStatus, CollateralAttestation,
    AuditResult, Violation, CrossLedgerViolation, LedgerStateUpdate,
    QuorumJoinRequestMsg, QuorumJoinResponseMsg, QuorumVoteMsg,
    DepositOffer, DepositOfferStatus,
    OnChainWithdrawal, OnChainWithdrawalStatus,
    WithdrawalLockResult, WithdrawalCompleteResult,
    CommitmentExtraOutput, ChannelId,
    serde_pubkey, serde_32, serde_64, serde_opt_64, serde_pubkey_map, serde_pubkey_vec,
    PendingTransfer,
};
pub use signature_utils::{
    create_deposit_guarantee_signature, verify_deposit_guarantee_signature,
    create_payment_authorization_signature, verify_payment_signature,
    create_payment_signature,
    create_deposit_offer_signature, verify_deposit_offer_signature,
    withdrawal_signing_message, verify_withdrawal_witness,
    verify_descriptor_witness, verify_collateral_lock_witness,
    create_withdrawal_signature, create_collateral_lock_signature,
    invoice_lock_signing_message, verify_invoice_lock_witness,
};
