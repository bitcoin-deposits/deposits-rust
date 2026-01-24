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

pub mod constants;
pub mod error;
pub mod handler;
pub mod ledger;
pub mod message_processor;
pub mod messages;
pub mod quorum;
pub mod recovery;
pub mod recovery_claim;
pub mod tapscript_reserves;
pub mod time_utils;
pub mod tlv;
pub mod traits;
pub mod types;
pub mod validation;
pub mod handler_types;
pub mod handler_traits;
pub mod payment_tracker;
pub mod reserves_proposal;
pub mod signature_utils;

// Re-exports for convenience
pub use constants::{
    MIN_RESERVES_OUTPUT_SATS, MAX_RESERVES_OUTPUT_SATS, DEFAULT_EMERGENCY_TIMEOUT_BLOCKS,
    MIN_EMERGENCY_TIMEOUT_BLOCKS, MAX_EMERGENCY_TIMEOUT_BLOCKS, MIN_RESERVES_RATIO_PERCENT,
    COLLATERAL_REPORTING_PERIOD_BLOCKS, DEPOSITS_PROTOCOL_VERSION,
};
pub use error::{DepositsError, DepositsResult};
pub use messages::{DepositsMessage, LedgerOperation};
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
    ThresholdConfig, ThresholdTier, verify_taproot_reserves,
};
pub use types::{
    Deposit, FeeStructure, PendingInvoice, ReservesOutput, Invoice,
    LedgerState, LedgerUpdate, SignedLedgerUpdate, SignedLedgerUpdateLog,
    DepositInfo, InvoiceInfo, ReservesStatus, CollateralAttestation,
    AuditResult, Violation, CrossLedgerViolation, LedgerStateUpdate,
    QuorumJoinRequestMsg, QuorumJoinResponseMsg, QuorumVoteMsg,
    // Serde helper modules for serializing/deserializing Bitcoin types
    serde_pubkey, serde_32, serde_64, serde_opt_64, serde_pubkey_map, serde_pubkey_vec,
};
pub use validation::{
    ValidationRules, OperationValidator, LedgerConformanceValidator,
    ConformanceResult, ConformanceViolation,
};
pub use ledger::{
    Ledger, LedgerRole, LedgerValidator, LedgerManager,
    // Note: LedgerUpdate is exported from types module
};
pub use handler::Handler;
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
    create_payment_authorization_signature,
};
pub use tlv::{
    TlvEncode, TlvDecode, TlvStream, TlvBuilder, TlvReader,
    TlvError, TlvResult,
};
