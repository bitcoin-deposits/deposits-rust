// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! # Bitcoin Deposits Protocol - Core Library
//!
//! Trust-minimized custody for Lightning. This crate contains the core protocol
//! logic with zero Lightning implementation dependencies.
//!
//! ## Architecture
//!
//! The deposits protocol is split into two crates:
//!
//! - **deposits-core** (this crate): Core protocol logic, types, validation
//! - **deposits-node**: BDK wallet + Nostr transport implementation
//!
//! This separation allows the protocol to work with any Lightning implementation
//! (LDK, CLN, Eclair, etc.) through adapter traits.
//!
//! ## Key Components
//!
//! - [`messages`]: Wire protocol messages (12 consolidated types)
//! - [`traits`]: Adapter traits for Lightning integration
//! - [`types`]: Core data types (Deposit, FeeStructure, etc.)
//! - [`error`]: Error types
//! - [`ledger`]: Hash-chained ledger operations
//! - [`validation`]: Conformance checking rules
//!
//! ## Example
//!
//! ```ignore
//! use deposits_core::messages::{DepositsMessage, LedgerOperation};
//! use deposits_core::types::FeeStructure;
//!
//! // Create a deposit open operation
//! let op = LedgerOperation::DepositOpen {
//!     pubkey: user_pubkey,
//!     fees: Some(FeeStructure {
//!         annualized_msats: 1000,
//!         annualized_bps: 50,
//!         frequency_blocks: 144,
//!     }),
//!     payment_hash: None,
//!     invoice: None,
//!     cosigner_guarantee_signature: None,
//! };
//! ```

// TODO: Add comprehensive documentation
#![allow(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

// Protocol definitions (re-exported from deposits-protocol for backward compatibility)
pub use deposits_protocol::constants;
pub use deposits_protocol::error;
pub use deposits_protocol::fraud;
pub use deposits_protocol::messages;
pub use deposits_protocol::signature_utils;
pub use deposits_protocol::tlv;
pub use deposits_protocol::types;
pub use deposits_protocol::wire_messages;

// Core modules (state machine, handlers, validation)
pub mod descriptor;
pub mod event_store;
pub mod ledger;
pub mod signing;
#[macro_use]
pub mod logging;
pub mod message_handlers;
pub mod message_validation;
pub mod operation_validation;
pub mod quorum_policy;
pub mod tapscript_reserves;
pub mod time_utils;
pub mod validation;

// Re-exports for convenience
pub use constants::{
    COLLATERAL_REPORTING_PERIOD_BLOCKS, DEFAULT_EMERGENCY_TIMEOUT_BLOCKS,
    DEPOSITS_PROTOCOL_VERSION, MAX_DISPUTANTS, MAX_EMERGENCY_TIMEOUT_BLOCKS,
    MAX_QUORUM_SIZE_POLICY, MAX_RESERVES_OUTPUT_SATS, MIN_EMERGENCY_TIMEOUT_BLOCKS,
    MIN_RESERVES_OUTPUT_SATS, MIN_RESERVES_RATIO_PERCENT, TIMEOUT_RECOVERY_CSV_BLOCKS,
    VALID_QUORUM_SIZES,
};
pub use error::{DepositsError, DepositsResult, HandlerError};
pub use ledger::{
    Ledger, LedgerManager, LedgerProtocolState, LedgerRole, LedgerValidator, StagedUpdate,
};
pub use messages::{DepositsMessage, HashStrategy, LedgerOperation};
pub use tapscript_reserves::{
    build_taproot_reserves_script, verify_taproot_reserves, ReservesSpendBuilder, SpendTxParams,
    TaprootReservesOutput, TapscriptReservesBuilder, ThresholdConfig, ThresholdTier, Voter,
    VoterSet,
};
pub use time_utils::{is_expired, now_unix_timestamp};
pub use types::{
    compute_deposit_id,
    entropy_selection_score,
    is_entropy_winner,
    select_entropy_winner,
    serde_32,
    serde_64,
    serde_opt_64,
    // Serde helper modules for serializing/deserializing Bitcoin types
    serde_pubkey,
    serde_pubkey_map,
    serde_pubkey_vec,
    AuditResult,
    ChannelId,
    // Channel types
    CommitmentExtraOutput,
    CosignEntry,
    CrossLedgerViolation,
    Deposit,
    // Deposit identifier types
    DepositId,
    DepositInfo,
    // On-chain deposit funding
    DepositOffer,
    DepositOfferStatus,
    DescriptorWitness,
    DisputeState,
    FeeStructure,
    Invoice,
    InvoiceInfo,
    LedgerState,
    LedgerStateUpdate,
    LedgerUpdate,
    // On-chain withdrawal
    OnChainWithdrawal,
    OnChainWithdrawalStatus,
    PendingInvoice,
    QuorumJoinRequestMsg,
    QuorumJoinResponseMsg,
    // Quorum and dispute protocol types
    QuorumState,
    QuorumVoteMsg,
    ReservesOutput,
    ReservesStatus,
    SignedLedgerUpdate,
    SignedLedgerUpdateLog,
    TransferFeeSchedule,
    Violation,
    WithdrawalCompleteResult,
    WithdrawalLockResult,
};
pub use validation::{
    ChainStatus,
    ConformanceResult,
    ConformanceViolation,
    LedgerConformanceValidator,
    // Export and validation API types
    LedgerExport,
    LedgerStateSnapshot,
    OperationValidator,
    RuleCheck,
    SignatureReport,
    ValidationError,
    ValidationReport,
    ValidationRules,
};
// Re-export signing message builders from signature_utils (pure data construction)
pub use signature_utils::{
    compute_transfer_id, invoice_lock_signing_message, transfer_lock_signing_message,
    withdrawal_signing_message,
};
// Re-export crypto operations from signing module
pub use message_handlers::{handle_ledger_update, HandlerResult, ResponseData};
pub use message_validation::{
    // Message validation functions (with _msg suffix to distinguish from operation_validation)
    validate_add_deposit_msg,
    validate_fee_collect_msg,
    validate_ledger_close_msg,
    // LedgerOperation validation
    validate_ledger_operation,
    validate_receiving_cosign_invoice_msg,
    validate_receiving_credit_payment_msg,
    validate_remove_deposit_msg,
    validate_reserves_add_output_msg,
    validate_reserves_remove_msg,
    validate_sending_fail_payment_msg,
    validate_sending_fulfill_payment_msg,
    validate_sending_lock_payment_msg,
    validate_update_deposit_msg,
    // HandlerContext trait for implementing message handlers (extends ValidationContext)
    HandlerContext,
    // ValidationContext trait for implementing message validation
    ValidationContext,
};
pub use operation_validation::{
    // Invoice validations
    validate_cosign_invoice,
    // Payment validations
    validate_credit_payment,
    // Deposit validations
    validate_deposit_add,
    validate_deposit_close,
    validate_deposit_fee_change,
    validate_fee_change,
    // Fee validations
    validate_fee_collect,
    // Ledger validations
    validate_ledger_close,
    validate_payment_fail,
    validate_payment_fulfill,
    validate_payment_lock,
    // Reserves validations
    validate_reserves_add,
    // Result type
    ValidationResult,
    // Constants
    MAX_FEE_RATE_BPS,
};
pub use signing::{
    create_deposit_guarantee_signature, create_deposit_offer_signature,
    create_payment_authorization_signature, create_payment_signature, create_withdrawal_signature,
    verify_deposit_guarantee_signature, verify_deposit_offer_signature,
    verify_invoice_lock_witness, verify_payment_signature, verify_transfer_complete_witness,
    verify_transfer_lock_witness, verify_withdrawal_witness,
};
pub use tlv::{TlvBuilder, TlvDecode, TlvEncode, TlvError, TlvReader, TlvResult, TlvStream};
pub use wire_messages::{
    AcceptReservesMsg,
    CollateralConsentRequestMsg,
    CollateralConsentResponseMsg,
    DepositCloseMsg,
    // Deposit messages
    DepositOpenMsg,
    FeeChangeMsg,
    // Fee and lifecycle messages
    FeeCollectMsg,
    LedgerCloseMsg,
    // Ledger export messages
    LedgerExportRequestMsg,
    LedgerExportResponseMsg,
    // Collateral messages
    QuorumAddMemberMsg,
    // Quorum messages (wire-specific versions with Wire suffix)
    QuorumJoinRequestMsgWire,
    QuorumJoinResponseMsgWire,
    QuorumMembershipChangeMsg,
    QuorumRemoveMemberMsg,
    QuorumStateSyncMsg,
    QuorumVoteMsgWire,
    QuorumVoteRequestMsg,
    ReceivingCosignInvoiceMsg,
    // Payment messages
    ReceivingCreditPaymentMsg,
    // Reserves messages
    ReservesAddOutputMsg,
    ReservesRemoveOutputMsg,
    ReservesUpdateOutputMsg,
    SendingFailPaymentMsg,
    SendingFulfillPaymentMsg,
    SendingLockPaymentMsg,
    // Sync messages
    SyncRequestMsg,
    UpdateReservesMsg,
};
