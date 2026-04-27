// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Error types for the Bitcoin Deposits Protocol.

use bitcoin::secp256k1::PublicKey;
use thiserror::Error;

/// Result type for deposits operations.
pub type DepositsResult<T> = Result<T, DepositsError>;

/// Error type for protocol message handlers.
/// Replaces LDK's LightningError for Lightning-agnostic handling.
#[derive(Debug, Clone)]
pub enum HandlerError {
    /// Validation failed
    ValidationFailed(String),
    /// Ledger not found
    LedgerNotFound {
        operator: PublicKey,
        reserves_id: String,
    },
    /// Invalid state for operation
    InvalidState(String),
    /// Internal error
    Internal(String),
}

impl std::fmt::Display for HandlerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ValidationFailed(msg) => write!(f, "validation failed: {}", msg),
            Self::LedgerNotFound {
                operator,
                reserves_id,
            } => {
                write!(
                    f,
                    "ledger not found: operator={}, reserves_id={}",
                    operator, reserves_id
                )
            }
            Self::InvalidState(msg) => write!(f, "invalid state: {}", msg),
            Self::Internal(msg) => write!(f, "internal error: {}", msg),
        }
    }
}

impl std::error::Error for HandlerError {}

/// Errors that can occur in the deposits protocol.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DepositsError {
    // ========== Reserves Errors ==========
    /// Insufficient reserves to cover deposits
    #[error("Insufficient reserves: required {required}, available {available}")]
    InsufficientReserves {
        /// Amount of reserves required
        required: u64,
        /// Amount of reserves available
        available: u64,
    },

    /// Cannot remove reserves - output not found
    #[error("Reserves output not found: {0}")]
    ReservesOutputNotFound(String),

    /// Invalid reserves decrease
    #[error("Invalid reserves decrease: {0}")]
    InvalidReservesDecrease(String),

    /// Invalid reserve amount
    #[error("Invalid reserve amount")]
    InvalidReserveAmount,

    // ========== Deposit Errors ==========
    /// Deposit has non-zero balance
    #[error("Deposit has non-zero balance: {balance}")]
    NonZeroBalance {
        /// Current balance
        balance: u64,
    },

    /// Deposit has outstanding invoices
    #[error("Deposit has {count} outstanding invoices")]
    OutstandingInvoices {
        /// Number of outstanding invoices
        count: usize,
    },

    /// Insufficient deposit balance for operation
    #[error("Insufficient deposit balance: available {available}, required {required}")]
    InsufficientDepositBalance {
        /// Available balance
        available: u64,
        /// Required balance
        required: u64,
    },

    /// Deposit not found
    #[error("Deposit not found")]
    DepositNotFound,

    /// Deposit already exists
    #[error("Deposit already exists")]
    DepositAlreadyExists,

    /// Insufficient balance (generic)
    #[error("Insufficient balance")]
    InsufficientBalance,

    // ========== Payment Errors ==========
    /// Unknown payment
    #[error("Unknown payment")]
    UnknownPayment,

    /// Payment amount mismatch
    #[error("Payment amount mismatch")]
    PaymentAmountMismatch,

    /// Payment not locked
    #[error("Payment not locked")]
    PaymentNotLocked,

    // ========== Ledger Errors ==========
    /// Ledger already exists
    #[error("Ledger already exists")]
    LedgerAlreadyExists,

    /// Ledger not found
    #[error("Ledger not found")]
    LedgerNotFound,

    /// Ledger not initialized
    #[error("Ledger not initialized")]
    LedgerNotInitialized,

    /// Ledger ID mismatch
    #[error("Ledger ID mismatch")]
    LedgerIdMismatch,

    // ========== Handshake Errors ==========
    /// Handshake in progress
    #[error("Handshake in progress")]
    HandshakeInProgress,

    /// No active handshake
    #[error("No active handshake")]
    NoActiveHandshake,

    /// Handshake rejected
    #[error("Handshake rejected")]
    HandshakeRejected,

    // ========== Partner/Collateral Errors ==========
    /// Partner not found
    #[error("Partner not found")]
    PartnerNotFound,

    /// Invalid partner
    #[error("Invalid partner")]
    InvalidPartner,

    /// Quorum member already exists
    #[error("Quorum member already exists")]
    QuorumMemberAlreadyExists,

    /// Insufficient collateral
    #[error("Insufficient collateral: required {required}, available {available}")]
    InsufficientCollateral {
        /// Amount required
        required: u64,
        /// Amount available
        available: u64,
        /// Partners missing attestations
        missing_attestations: Vec<PublicKey>,
    },

    /// Insufficient quorum members
    #[error("Insufficient quorum members: operator ledgers {operator_ledgers}, partner ledgers {partner_ledgers}")]
    InsufficientQuorumMembers {
        /// Number of operator ledgers
        operator_ledgers: usize,
        /// Number of partner ledgers
        partner_ledgers: usize,
    },

    // ========== Channel Errors ==========
    /// Invalid channel state
    #[error("Invalid channel state")]
    InvalidChannelState,

    // ========== Cryptographic Errors ==========
    /// Invalid secret key
    #[error("Invalid secret key")]
    InvalidSecretKey,

    /// Invalid public key
    #[error("Invalid public key")]
    InvalidPublicKey,

    /// Invalid signature
    #[error("Invalid signature")]
    InvalidSignature,

    // ========== Message Errors ==========
    /// Invalid message
    #[error("Invalid message: {reason}")]
    InvalidMessage {
        /// Reason for invalidity
        reason: String,
    },

    /// Protocol violation
    #[error("Protocol violation: {violation_type} - {details}")]
    ProtocolViolation {
        /// Type of violation
        violation_type: String,
        /// Details
        details: String,
    },

    // ========== Storage Errors ==========
    /// Persistence failed
    #[error("Persistence failed: {reason}")]
    PersistenceFailed {
        /// Reason for failure
        reason: String,
    },

    /// Audit queue full
    #[error("Audit queue full")]
    AuditQueueFull,

    /// Serialization error
    #[error("Serialization error")]
    SerializationError,

    // ========== Validation Errors ==========
    /// Fee assessment failed
    #[error("Fee assessment failed: {reason}")]
    FeeAssessmentFailed {
        /// Reason for failure
        reason: String,
    },

    /// Audit failed
    #[error("Audit failed: {reason}")]
    AuditFailed {
        /// Reason for failure
        reason: String,
    },

    /// Cosigning failed
    #[error("Cosigning failed: {reason}")]
    CosigningFailed {
        /// Reason for failure
        reason: String,
    },

    // ========== Parsing Errors ==========
    /// Invalid address
    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    /// Invalid amount
    #[error("Invalid amount: {0}")]
    InvalidAmount(String),

    /// Invalid timeout
    #[error("Invalid timeout: {0}")]
    InvalidTimeout(String),

    // ========== State Errors ==========
    /// Proposal not found
    #[error("Proposal not found: {0}")]
    ProposalNotFound(String),

    /// Invalid state
    #[error("Invalid state: {0}")]
    InvalidState(String),

    /// Insufficient funds
    #[error("Insufficient funds: {0}")]
    InsufficientFunds(String),

    // ========== Codec Errors ==========
    /// Codec error
    #[error("Codec error: {0}")]
    CodecError(String),

    /// Hash mismatch
    #[error("Hash mismatch: expected {expected}, got {actual}")]
    HashMismatch {
        /// Expected hash (hex)
        expected: String,
        /// Actual hash (hex)
        actual: String,
    },

    /// Sequence mismatch
    #[error("Sequence mismatch: expected {expected}, got {actual}")]
    SequenceMismatch {
        /// Expected sequence
        expected: u64,
        /// Actual sequence
        actual: u64,
    },

    // ========== Broadcast Errors ==========
    /// Transaction broadcast failed
    #[error("Broadcast failed: {0}")]
    BroadcastFailed(String),

    // ========== Lottery / Confiscation Preconditions ==========
    /// Recovery quorum is too small to ever sign the long-tail recovery
    /// script. Without this minimum, a stalled lottery is unrecoverable.
    #[error(
        "Recovery quorum unreachable: {n_quorum} quorum members, {n_disputants} disputants, \
         need at least {t_emergency} non-disputing signers"
    )]
    RecoveryQuorumUnreachable {
        n_quorum: usize,
        n_disputants: usize,
        t_emergency: usize,
    },

    /// Disputed value is too small relative to the on-chain claim fee for
    /// the lottery to be economically rational.
    #[error(
        "Lottery not economically rational: disputed value {disputed_value} sats < \
         {min_required} sats (5x estimated claim fee)"
    )]
    LotteryNotEconomical {
        disputed_value: u64,
        min_required: u64,
    },

    /// A disputant's bond is below the per-regime ratio required to keep
    /// defection irrational at this disputant count.
    #[error(
        "Insufficient bond at N={n}: bond {actual} sats < required {required} sats \
         ({numerator}/{denominator} of disputed value)"
    )]
    InsufficientBondRatio {
        n: usize,
        actual: u64,
        required: u64,
        numerator: u64,
        denominator: u64,
    },
}

impl From<crate::messages::CodecError> for DepositsError {
    fn from(e: crate::messages::CodecError) -> Self {
        DepositsError::CodecError(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = DepositsError::InsufficientReserves {
            required: 100000,
            available: 50000,
        };
        assert!(err.to_string().contains("100000"));
        assert!(err.to_string().contains("50000"));
    }

    #[test]
    #[allow(clippy::unnecessary_literal_unwrap)]
    fn test_result_type() {
        let ok: DepositsResult<u64> = Ok(42);
        assert_eq!(ok.unwrap(), 42);

        let err: DepositsResult<u64> = Err(DepositsError::DepositNotFound);
        assert!(err.is_err());
    }
}
