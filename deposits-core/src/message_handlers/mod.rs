// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Core message handler logic for the Bitcoin Deposits protocol.
//!
//! This module provides Lightning-agnostic handler functions that can be used
//! by any Lightning implementation (LDK, CLN, etc.).
//!
//! ## Design
//!
//! Each handler function:
//! - Takes a reference to a `HandlerContext` for access to ledgers, messaging, etc.
//! - Takes the message and sender information
//! - Returns `Result<HandlerResult, HandlerError>`
//! - Performs validation and state updates
//! - Queues response messages via the context
//!
//! The LDK adapter (deposits-ldk) implements `HandlerContext` and calls these
//! core functions, converting `HandlerError` to `LightningError` at the boundary.

use bitcoin::secp256k1::PublicKey;

use crate::error::HandlerError;
use crate::message_validation::HandlerContext;
use crate::messages::{
    CoordinationMsg, CoordinationResponseMsg, DepositsMessage, RecoveryResponseMsg, SyncMsg,
};
use crate::operation_validation::{
    validate_cosign_invoice,
    validate_credit_payment,
    validate_credit_payment_by_id,
    // DepositId-based validation functions
    validate_deposit_add_by_id,
    validate_deposit_close_by_id,
    validate_deposit_fee_change,
    validate_deposit_key_rotate,
    validate_fee_change_by_id,
    validate_fee_collect,
    validate_fee_collect_by_id,
    validate_ledger_close,
    validate_payment_fail,
    validate_payment_fulfill,
    validate_payment_fulfill_by_id,
    validate_payment_lock,
    validate_payment_lock_by_id,
    validate_reserves_add,
};
use crate::quorum::LedgerId;
use crate::recovery::RecoveryVote;
use crate::traits::ProtocolEvent;
use crate::wire_messages::{
    CollateralAttestationMsg, CollateralConsentRequestMsg, CollateralConsentResponseMsg,
    DepositCloseMsg, DepositOpenMsg, FeeChangeMsg, FeeCollectMsg, LedgerCloseMsg,
    QuorumAddMemberMsg, QuorumJoinRequestMsgWire, QuorumRemoveMemberMsg, QuorumVoteRequestMsg,
    ReceivingCosignInvoiceMsg, ReceivingCreditPaymentMsg, RecoveryClaimCompleteMsg,
    RecoveryClaimRequestMsg, RecoveryClaimSignatureMsg, RecoveryVoteMsg, ReservesAddOutputMsg,
    ReservesRemoveOutputMsg, SendingFailPaymentMsg, SendingFulfillPaymentMsg,
    SendingLockPaymentMsg, UncreditedPaymentMsg,
};

mod admin;
mod collateral;
mod deposits;
mod ledger;
mod payments;
mod quorum;
mod recovery;
mod reserves;
mod types;

pub use admin::*;
pub use collateral::*;
pub use deposits::*;
pub use ledger::*;
pub use payments::*;
pub use quorum::*;
pub use recovery::*;
pub use reserves::*;
pub use types::*;

// ============================================================================
// Helper Functions
// ============================================================================

/// Create a ledger ID from operator and reserves_id
pub fn make_ledger_id(operator: PublicKey, reserves_id: String) -> LedgerId {
    LedgerId::new(operator, reserves_id)
}
