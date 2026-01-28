//! Bitcoin Deposits Handler Module
//!
//! This module provides the main DepositsHandler and related functionality,
//! organized into focused sub-modules for better maintainability and testability.
//!
//! # Module Organization
//!
//! - `core` - Main DepositsHandler struct and implementation
//! - `payment_tracking` - Invoice payment registration and lookup
//! - `channel_locks` - Per-channel operation locks for commitment safety
//! - `recovery_ops` - Force-close recovery tracking and fraud proofs
//!
//! # Usage
//!
//! The DepositsHandler is the main entry point. Extension traits from sub-modules
//! are automatically available when the sub-modules are in scope.
//!
//! ```ignore
//! use crate::deposits::handler::{DepositsHandler, PaymentTracking, ChannelLocks, RecoveryOperations};
//!
//! let handler = DepositsHandler::new(...);
//! handler.register_deposit_invoice(...);  // From PaymentTracking
//! handler.with_channel_lock(...);         // From ChannelLocks
//! handler.start_recovery_tracking(...);   // From RecoveryOperations
//! ```

// Prelude with common imports for all handler modules
pub mod prelude;

// Macros for handler delegation patterns
mod macros;

// Message types for handlers (DepositsMessage enum with LDK traits)
pub mod messages;

// Event types for handlers
pub mod events;

// Ledger extension traits
pub mod ledger_ext;

// Protocol stubs for legacy types (temporary)
pub mod protocol_stub;

// Core module containing DepositsHandler struct and main implementation
mod core;

// Sub-modules with focused functionality (extension traits)
pub mod payment_tracking;
pub mod channel_locks;
pub mod recovery_ops;
pub mod ledger_ops;
pub mod deposit_ops;
pub mod reserves_ops;
pub mod collateral_ops;
pub mod message_validation;
mod message_handlers;
mod reserves_handlers;
mod ack_handler;
mod persistence_ops;
mod payment_handlers;
mod channel_close_handler;
mod signed_update_ops;
mod commitment_ops;
mod maintenance_ops;
mod message_dispatch;
mod broadcast_ops;
mod handshake_async_ops;
mod credit_async_ops;
mod deposit_add_async;
mod collateral_async_ops;
mod reserves_commitment_ops;
mod ledger_init_ops;
mod custom_message_handler;
mod deposit_sync_ops;
mod collateral_sync_ops;
mod transfer_ops;
mod ledger_close_ops;
pub mod testing_helpers;
mod protocol_management;
mod messaging_ops;
mod audit_message_ops;
mod event_info_ops;
mod builder;
mod setup_ops;
mod signature_utils;
mod handler_types;
mod constants;
pub mod validation_ext;
mod handler_context_impl;
pub mod ldk_adapters;

// Test module
#[cfg(test)]
mod tests;

// Re-export everything from core for backwards compatibility
pub use core::*;

// Re-export builder
pub use builder::DepositsHandlerBuilder;

// Re-export extension traits for convenience
pub use payment_tracking::PaymentTracking;
pub use channel_locks::ChannelLocks;
pub use recovery_ops::RecoveryOperations;
pub use ledger_ops::{LedgerOperations, LedgerOperationsExt};
pub use deposit_ops::DepositOperations;
pub use reserves_ops::ReservesOperations;
pub use collateral_ops::CollateralOperations;
pub use message_validation::MessageValidation;

// Re-export signature utilities
pub use signature_utils::{
    create_deposit_guarantee_signature,
    verify_deposit_guarantee_signature,
    create_payment_authorization_signature,
};

// Re-export handler types
pub use handler_types::{
    CosignedInvoice,
    VoteRoundState,
    ProtocolStats,
    LedgerSummary,
    ReservesSummary,
    CollateralPartnerInfo,
    CollateralInfo,
};

// Re-export events
pub use events::DepositsEvent;

// Re-export ledger extension traits
pub use ledger_ext::{LedgerExt, SignedLedgerUpdateExt, SignedLedgerUpdateLogExt};

// Re-export validation extension trait
pub use validation_ext::LedgerConformanceValidatorExt;

// Re-export core handler extension trait
pub use handler_context_impl::CoreHandlerExt;

// Re-export constants (internal use)
