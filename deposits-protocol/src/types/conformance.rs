// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Conformance checking types and traits.

use bitcoin::secp256k1::PublicKey;

use super::core::DescriptorWitness;

// ============================================================================
// Conformance Checking
// ============================================================================

/// A violation of protocol conformance rules detected in a ledger state.
///
/// Conformance violations indicate the operator has produced a valid state
/// transition (the operation was applied) but the resulting state violates
/// protocol rules. Quorum members use these to detect misbehavior.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConformanceViolation {
    /// Total deposit balances exceed declared reserves.
    InsufficientReserves { reserves: u64, obligations: u64 },

    /// A witness or signature failed verification.
    InvalidWitness {
        operation: &'static str,
        detail: String,
    },

    /// Lock-class operation (InvoiceLock/OnchainLock/TransferLock) had
    /// `amount == 0`. Zero-amount locks have no semantic purpose and
    /// would silently succeed against the state-machine apply, so
    /// conformance treats them as a hard refusal.
    ZeroAmount { operation: &'static str },

    /// OnchainLock's `destination_address` was empty.
    EmptyDestination,

    /// TransferLock's declared `transfer_id` field disagrees with the
    /// id derived from the operation's signing message. Without this
    /// check, a writer could craft a transfer whose authoritative id
    /// (used for later TransferComplete lookup) differs from the id
    /// the depositor signed over.
    MismatchedTransferId {
        expected: [u8; 32],
        actual: [u8; 32],
    },

    /// DepositKeyRotate's `new_descriptor` failed to parse as a
    /// miniscript descriptor. Without rejecting at rotation time the
    /// resulting deposit becomes unspendable through normal paths.
    UnparseableDescriptor {
        operation: &'static str,
        detail: String,
    },

    /// Credit-class operation (InvoiceCredit/OnchainCredit/
    /// TransferComplete) would push total credited balances above the
    /// active quorum's collateral envelope. Separate from
    /// InsufficientReserves: reserves cap absolute custody, collateral
    /// caps the share an under-collateralised operator can route.
    ExceedsCollateral { credit: u64, collateral: u64 },

    /// FeeCollect fired before the deposit's fee window elapsed.
    /// Operators can't accelerate fee assessment past the
    /// `frequency_blocks` cadence the depositor accepted at open.
    FeeWindowNotElapsed {
        current_block: u32,
        next_allowed_block: u32,
    },

    /// DepositOpen's `descriptor` exceeded the active quorum's
    /// `max_descriptor_bytes` policy. Without this, an outsized
    /// descriptor could bloat every cosigner's signing path.
    DescriptorTooLarge { actual: usize, max: u32 },

    /// A signature-bearing op (InvoiceLock / OnchainLock / TransferLock /
    /// DepositKeyRotate) supplied a `nonce` that does not strictly increase
    /// past the deposit's `last_op_nonce`. Replay protection for the dep-16
    /// operation preimage; without this, a signed op could be replayed at
    /// any later moment against the same deposit. See PLAN-dep16-integration.md
    /// phase 3.
    NonceNotIncreasing {
        operation: &'static str,
        last_op_nonce: u64,
        actual: u64,
    },

    /// A signature-bearing op supplied an `expiry` block height that the
    /// chain has already buried. Signatures over the dep-16 operation
    /// preimage bind to a specific expiry; the protocol rejects after that
    /// height regardless of any other signal. See PLAN-dep16-integration.md
    /// phase 3.
    ExpiryPassed {
        operation: &'static str,
        expiry: u32,
        current_height: u32,
    },

    /// A protocol rule was violated.
    ProtocolRule { rule: &'static str, detail: String },

    /// The state machine itself refused the transition (invariant
    /// failure, unknown deposit id, etc.) — surfaced through the
    /// conformance API by `check_speculative` so callers don't have
    /// to branch on `apply` errors separately. Carries the inner
    /// error's debug rendering.
    StateMachineRejected { detail: String },
}

impl std::fmt::Display for ConformanceViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InsufficientReserves {
                reserves,
                obligations,
            } => write!(f, "reserves ({}) < obligations ({})", reserves, obligations),
            Self::InvalidWitness { operation, detail } => {
                write!(f, "invalid witness in {}: {}", operation, detail)
            }
            Self::ZeroAmount { operation } => {
                write!(f, "zero amount in {}", operation)
            }
            Self::EmptyDestination => write!(f, "empty destination address"),
            Self::MismatchedTransferId { expected, actual } => write!(
                f,
                "transfer_id mismatch: declared {} but signing message yields {}",
                hex::encode(actual),
                hex::encode(expected),
            ),
            Self::UnparseableDescriptor { operation, detail } => write!(
                f,
                "unparseable descriptor in {}: {}",
                operation, detail
            ),
            Self::ExceedsCollateral { credit, collateral } => write!(
                f,
                "credit ({}) would exceed quorum collateral ({})",
                credit, collateral
            ),
            Self::FeeWindowNotElapsed {
                current_block,
                next_allowed_block,
            } => write!(
                f,
                "fee_collect at block {} fires before next allowed assessment at block {}",
                current_block, next_allowed_block,
            ),
            Self::DescriptorTooLarge { actual, max } => write!(
                f,
                "descriptor size {} bytes exceeds quorum max of {} bytes",
                actual, max
            ),
            Self::NonceNotIncreasing {
                operation,
                last_op_nonce,
                actual,
            } => write!(
                f,
                "{}: nonce {} ≤ deposit.last_op_nonce {}",
                operation, actual, last_op_nonce,
            ),
            Self::ExpiryPassed {
                operation,
                expiry,
                current_height,
            } => write!(
                f,
                "{}: expiry block {} ≤ current height {}",
                operation, expiry, current_height,
            ),
            Self::ProtocolRule { rule, detail } => {
                write!(f, "protocol rule '{}' violated: {}", rule, detail)
            }
            Self::StateMachineRejected { detail } => {
                write!(f, "state machine refused transition: {}", detail)
            }
        }
    }
}

/// Trait for verifying witnesses and signatures during ledger state application.
///
/// deposits-protocol defines the interface; deposits-core provides the real
/// implementation using miniscript descriptors and secp256k1 verification.
pub trait WitnessVerifier {
    /// Verify a descriptor witness against a message hash.
    fn verify_witness(
        &self,
        descriptor: &str,
        witness: &DescriptorWitness,
        message_hash: &[u8; 32],
    ) -> bool;

    /// Verify a 64-byte Schnorr/ECDSA signature.
    fn verify_signature(
        &self,
        pubkey: &PublicKey,
        message: &[u8; 32],
        signature: &[u8; 64],
    ) -> bool;

    /// Check that a descriptor string parses as miniscript. Returns
    /// `None` if parseable; `Some(detail)` with a human-readable
    /// error otherwise. Used by `check_conformance` to surface
    /// `UnparseableDescriptor` on `DepositOpen`/`DepositKeyRotate`
    /// without pulling the `miniscript` crate into `deposits-protocol`.
    fn validate_descriptor(&self, descriptor: &str) -> Option<String> {
        // Default: accept everything. The protocol-layer NoVerify
        // ships this; deposits-core overrides with a real check.
        let _ = descriptor;
        None
    }
}

/// No-op verifier that accepts all witnesses and signatures.
/// Used when conformance checking without cryptographic verification
/// (e.g., in protocol-layer tests or lightweight replay).
pub struct NoVerify;

impl WitnessVerifier for NoVerify {
    fn verify_witness(&self, _: &str, _: &DescriptorWitness, _: &[u8; 32]) -> bool {
        true
    }
    fn verify_signature(&self, _: &PublicKey, _: &[u8; 32], _: &[u8; 64]) -> bool {
        true
    }
}
