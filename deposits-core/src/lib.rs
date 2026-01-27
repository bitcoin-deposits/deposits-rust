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
//! - **deposits-ldk** (or other adapters): Lightning implementation bindings
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
//!         annualized_fixed: 1000,
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

pub mod channel_manager_ops;
pub mod constants;
pub mod error;
pub mod handler;
pub mod handler_traits;
pub mod handler_types;
pub mod ledger;
#[macro_use]
pub mod logging;
pub mod message_processor;
pub mod messages;
pub mod operation_validation;
pub mod payment_tracker;
pub mod quorum;
pub mod recovery;
pub mod recovery_claim;
pub mod reserves_proposal;
pub mod signature_utils;
pub mod tapscript_reserves;
pub mod time_utils;
pub mod tlv;
pub mod traits;
pub mod types;
pub mod validation;
pub mod wire_messages;
pub mod message_validation;
pub mod message_handlers;

// Re-exports for convenience
pub use constants::{
    MIN_RESERVES_OUTPUT_SATS, MAX_RESERVES_OUTPUT_SATS, DEFAULT_EMERGENCY_TIMEOUT_BLOCKS,
    MIN_EMERGENCY_TIMEOUT_BLOCKS, MAX_EMERGENCY_TIMEOUT_BLOCKS, MIN_RESERVES_RATIO_PERCENT,
    COLLATERAL_REPORTING_PERIOD_BLOCKS, DEPOSITS_PROTOCOL_VERSION,
};
pub use error::{DepositsError, DepositsResult, HandlerError};
pub use messages::{DepositsMessage, LedgerOperation, HashStrategy};
pub use recovery::{
    RecoveryManager, RecoveryPhase, RecoveryVote, RecoveryOutcome, RecoveryError,
    ClaimEligibility, RecoveryPool, RecoveryCandidate, select_recovery_partner,
};
pub use time_utils::{now_unix_timestamp, is_expired};
pub use traits::{
    Broadcaster, ChainSource, ChannelRegistry, EventEmitter, MessageHandler,
    PaymentTracker, PeerTransport, SignatureProvider, Storage, StorageError,
    Logger, LogLevel, NullLogger,
    // Channel operations traits
    ChannelInfo, ChannelOperations, ReservesOperations,
    // Storage provider
    DepositsStorage, DefaultStorageProvider,
};
pub use tapscript_reserves::{
    TapscriptReservesBuilder, TaprootReservesOutput, VoterSet, Voter,
    ThresholdConfig, ThresholdTier, verify_taproot_reserves, build_taproot_reserves_script,
};
pub use types::{
    Deposit, FeeStructure, PendingInvoice, ReservesOutput, Invoice,
    LedgerState, LedgerUpdate, SignedLedgerUpdate, SignedLedgerUpdateLog,
    DepositInfo, InvoiceInfo, ReservesStatus, CollateralAttestation,
    AuditResult, Violation, CrossLedgerViolation, LedgerStateUpdate,
    QuorumJoinRequestMsg, QuorumJoinResponseMsg, QuorumVoteMsg,
    // Channel types
    CommitmentExtraOutput, ChannelId,
    // Serde helper modules for serializing/deserializing Bitcoin types
    serde_pubkey, serde_32, serde_64, serde_opt_64, serde_pubkey_map, serde_pubkey_vec,
};
pub use channel_manager_ops::{
    ChannelManagerOps, ChannelDetails, NullChannelManager,
};
pub use validation::{
    ValidationRules, OperationValidator, LedgerConformanceValidator,
    ConformanceResult, ConformanceViolation,
};
pub use ledger::{
    Ledger, LedgerRole, LedgerValidator, LedgerManager,
    // Note: LedgerUpdate is exported from types module
};
pub use handler::{Handler, PendingAck};
pub use message_processor::{
    QuorumProcessor, QuorumMessageResult, QuorumResponse,
    QuorumJoinRequest, QuorumStateSync, QuorumVote,
    CollateralProcessor, CollateralMessageResult,
    RecoveryProcessor, RecoveryMessageResult,
};
pub use handler_types::{
    // Pending operation tracking
    PendingTransfer, PendingPayment,
    // Protocol state types
    CosignedInvoice, VoteRoundState, ProtocolStats,
    LedgerSummary, ReservesSummary, CollateralPartnerInfo, CollateralInfo,
};
pub use handler_traits::{
    // Pure protocol traits (no LDK dependencies)
    CollateralOperations, DepositOperations, PaymentTracking, ReservesQueryOps,
    // Note: LedgerOperations and RecoveryOperations stay in ldk-node
    // as they have LDK-specific types (Arc<RwLock<Ledger>>, BroadcasterInterface)
};
pub use payment_tracker::DepositInvoiceIndex;
pub use reserves_proposal::{
    ReservesOutputProposal, SpendingPolicy, EmergencyRecovery, ProposalStatus,
    serde_arrays,
};
pub use signature_utils::{
    create_deposit_guarantee_signature, verify_deposit_guarantee_signature,
    create_payment_authorization_signature, verify_payment_signature,
};
pub use tlv::{
    TlvEncode, TlvDecode, TlvStream, TlvBuilder, TlvReader,
    TlvError, TlvResult,
};
pub use operation_validation::{
    // Reserves validations
    validate_reserves_add, validate_reserves_increase, validate_reserves_decrease,
    // Payment validations
    validate_credit_payment, validate_payment_lock, validate_payment_fulfill, validate_payment_fail,
    // Fee validations
    validate_fee_collect,
    // Deposit validations
    validate_deposit_add, validate_deposit_close, validate_deposit_update,
    // Collateral validations
    validate_collateral_increase, validate_collateral_decrease,
    // Invoice validations
    validate_cosign_invoice,
    // Ledger validations
    validate_ledger_close,
    // Constants
    MAX_FEE_RATE_BPS,
    // Result type
    ValidationResult,
};
pub use wire_messages::{
    // Traits
    WireEncode, WireDecode, WireError,
    // Reserves messages
    ReservesIncreaseMsg, ReservesDecreaseMsg, ReservesAddOutputMsg,
    ReservesRemoveOutputMsg, ReservesUpdateOutputMsg,
    UpdateReservesMsg, AcceptReservesMsg,
    // Deposit messages
    DepositOpenMsg, DepositCloseMsg, DepositUpdateMsg,
    // Collateral messages
    CollateralIncreaseMsg, CollateralDecreaseMsg,
    CollateralAddPartnerMsg, CollateralRemovePartnerMsg,
    CollateralAttestationMsg,
    CollateralConsentRequestMsg, CollateralConsentResponseMsg,
    // Fee and lifecycle messages
    FeeCollectMsg, LedgerCloseMsg,
    // Payment messages
    ReceivingCreditPaymentMsg, SendingLockPaymentMsg,
    SendingFailPaymentMsg, SendingFulfillPaymentMsg,
    ReceivingCosignInvoiceMsg, UncreditedPaymentMsg,
    // Transfer messages
    DepositLockTransferMsg, DepositFailTransferMsg, DepositFulfillTransferMsg,
    // Sync messages
    SyncRequestMsg, ChannelCloseTombstoneMsg,
    // Quorum messages (wire-specific versions with Wire suffix)
    QuorumJoinRequestMsgWire, QuorumJoinResponseMsgWire, QuorumVoteMsgWire,
    QuorumMembershipChangeMsg, QuorumStateSyncMsg, QuorumVoteRequestMsg,
    // Recovery messages
    RecoveryVoteMsg, RecoveryClaimRequestMsg, RecoveryClaimSignatureMsg, RecoveryClaimCompleteMsg,
    // Relay messages
    RelayNwcRequestMsg, RelayNwcResponseMsg, RelayNwcDeliveryProofMsg,
};
pub use message_validation::{
    // ValidationContext trait for implementing message validation
    ValidationContext,
    // HandlerContext trait for implementing message handlers (extends ValidationContext)
    HandlerContext,
    // LedgerOperation validation
    validate_ledger_operation,
    // Message validation functions (with _msg suffix to distinguish from operation_validation)
    validate_add_deposit_msg, validate_remove_deposit_msg, validate_update_deposit_msg,
    validate_sending_lock_payment_msg, validate_sending_fulfill_payment_msg, validate_sending_fail_payment_msg,
    validate_receiving_credit_payment_msg, validate_reserves_add_output_msg, validate_reserves_remove_msg,
    validate_reserves_increase_msg, validate_reserves_decrease_msg,
    validate_fee_collect_msg, validate_collateral_increase_msg, validate_collateral_decrease_msg,
    validate_receiving_cosign_invoice_msg, validate_ledger_close_msg,
};
pub use message_handlers::{
    // Handler result types
    HandlerResult, ResponseData,
    // Core handler functions
    handle_quorum_join_request, handle_quorum_vote_request,
    handle_recovery_vote,
    handle_collateral_consent_request, handle_collateral_consent_response,
    handle_collateral_add_partner, handle_collateral_remove_partner,
    handle_collateral_attestation, handle_uncredited_payment,
    // Payment handler functions
    handle_receiving_credit_payment, handle_sending_lock_payment,
    handle_sending_fulfill_payment, handle_sending_fail_payment,
    // Fee and lifecycle handler functions
    handle_fee_collect, handle_ledger_close, handle_receiving_cosign_invoice,
    // Generic ledger update handler
    handle_ledger_update,
    // Helper functions
    make_ledger_id,
};
