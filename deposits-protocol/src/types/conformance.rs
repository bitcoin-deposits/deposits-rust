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

    /// A protocol rule was violated.
    ProtocolRule { rule: &'static str, detail: String },
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
            Self::ProtocolRule { rule, detail } => {
                write!(f, "protocol rule '{}' violated: {}", rule, detail)
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
