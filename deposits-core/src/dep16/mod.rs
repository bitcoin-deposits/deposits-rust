// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Glue between the dep-16 calculus and the deposits protocol.
//!
//! The calculus itself lives in our fork of rust-miniscript (under the `dep16` feature, in
//! `third_party/rust-miniscript/src/calculus/`). This module is the deposits-core side of the
//! integration: it re-exports the calculus's surface under a name callers can spell without
//! reaching into the miniscript crate's submodules, and provides the [`ProtocolLedgerState`]
//! adapter that future phases will populate with real protocol bookkeeping.
//!
//! See `PLAN-dep16-integration.md` for the broader integration plan. Phase 1 was the wiring
//! (this module's re-exports + the [`ProtocolLedgerState`] adapter); phase 2 ([`operations`])
//! defines the per-operation translation. Phases 3 onward fill in the per-deposit nonce/expiry
//! plumbing, the `Authorizer` trait, and the call-site switchover.

pub mod authorizer;
pub mod operations;

pub use authorizer::{Dep16Authorizer, ReceiveWitness};

/// The calculus's surface, re-exported. Callers can spell
/// `deposits_core::dep16::Descriptor` instead of
/// `miniscript::calculus::Descriptor`, etc. Kept narrow on purpose — names not exported here are
/// still reachable via `miniscript::calculus::*` for cases that need them.
pub use miniscript::calculus::{
    evaluate, parse, Descriptor, EvalError, HashValue, LedgerState, Obligation, Operation,
    OperationData, Symbol, Value, Witness,
};

/// The fraud-proof bundle and replay primitive — used by phase-7 work but kept exported here so
/// callers reach for it via the same path as everything else.
pub use miniscript::calculus::{replay, FraudProof, ReplayOutcome};

/// Admission and capability surface. A descriptor that hasn't passed [`admit`] should never reach
/// the evaluator; the protocol runs admission at deposit-open and re-runs it on every candidate
/// produced by a modification (see PLAN phases 4 and 5).
pub use miniscript::calculus::{admit, AdmissionError, CapabilitySet};

/// Real-crypto verifiers — both ECDSA (33-byte compressed secp keys) and BIP-340 Schnorr (32-byte
/// x-only keys). The evaluator is generic over [`Verifier`], so an integration test that doesn't
/// want real crypto can substitute a mock.
pub use miniscript::calculus::{EcdsaVerifier, SchnorrVerifier, Signature, Verifier};

/// Adapter that exposes a snapshot of protocol-side ledger state to the dep-16 evaluator.
///
/// v1 (this phase) panics on every reading: the wiring exists, but the actual fields the
/// evaluator queries are not yet plumbed through. Phase 2 (operation-mapping translation) and
/// phase 3 (per-deposit nonce/expiry + bookkeeping) populate the readings the descriptor
/// templates we ship actually use: `balance`, `current_height`, and the three `blocks_since_*`
/// readings. `rolling_window` and `cumulative_spent_via` are a second slice, deferred until a
/// template needs them.
///
/// Constructed empty by [`ProtocolLedgerState::empty`]; takes a borrow on the protocol state once
/// the real fields land.
pub struct ProtocolLedgerState<'a> {
    // Phantom for now; phase 2 swaps this for a borrow on `deposits_protocol::types::LedgerState`
    // (or whichever shape the operation-mapping layer ends up wanting).
    _phantom: std::marker::PhantomData<&'a ()>,
}

impl<'a> Default for ProtocolLedgerState<'a> {
    fn default() -> Self {
        Self::empty()
    }
}

impl<'a> ProtocolLedgerState<'a> {
    /// An empty adapter — every reading panics. Suitable only for descriptors that don't touch
    /// ledger state at all (e.g., a bare `pk(K)` policy). Useful for phase-1 smoke tests and for
    /// any future code path that should be inert against ledger reads.
    pub fn empty() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<'a> LedgerState for ProtocolLedgerState<'a> {
    fn blocks_since_activity(&self) -> i128 {
        unimplemented!("ProtocolLedgerState::blocks_since_activity — wired in phase 2/3")
    }
    fn blocks_since_open(&self) -> i128 {
        unimplemented!("ProtocolLedgerState::blocks_since_open — wired in phase 2/3")
    }
    fn blocks_since_received(&self) -> i128 {
        unimplemented!("ProtocolLedgerState::blocks_since_received — wired in phase 2/3")
    }
    fn balance(&self) -> i128 {
        unimplemented!("ProtocolLedgerState::balance — wired in phase 2/3")
    }
    fn rolling_window(&self, _field: &str, _period: i128) -> i128 {
        unimplemented!("ProtocolLedgerState::rolling_window — deferred, see PLAN phase 3")
    }
    fn cumulative_spent_via(&self, _path: &[usize]) -> i128 {
        unimplemented!("ProtocolLedgerState::cumulative_spent_via — deferred, see PLAN phase 3")
    }
    fn current_height(&self) -> i128 {
        unimplemented!("ProtocolLedgerState::current_height — wired in phase 2/3")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use bitcoin::PublicKey;
    use std::collections::BTreeMap;

    /// Phase-1 smoke test. Exercises the full wire-up:
    /// - the calculus re-exports compile (`Descriptor`, `Witness`, `Operation`, `evaluate`)
    /// - a bitcoin secp keypair flows through the dep-17 operation preimage construction
    /// - the real ECDSA verifier authorizes a real signature
    /// - the [`ProtocolLedgerState`] adapter satisfies [`LedgerState`] (un-read for this
    ///   trivial descriptor, so its panicking readings never fire)
    ///
    /// The descriptor is the minimum-meaningful dep-16 policy: `wsh(pk(K))` — K signs anything.
    /// No `match(operation_type(), …)`, no ledger reads, no modification. Just "did K sign?"
    #[test]
    fn smoke_test_evaluates_a_trivial_descriptor() {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x42; 32]).expect("valid secret key");
        let pk = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk));

        let descriptor_src = format!("wsh(pk({}))", pk);
        let d = parse::<PublicKey>(&descriptor_src).expect("descriptor parses");

        // A minimal operation: type "spend", no args, deposit_id zeroed, nonce 0, expiry MAX.
        // The operation-mapping translation layer (phase 2) is what eventually builds these from
        // `LedgerOperation` variants; for this smoke test we synthesize one directly.
        let op = OperationData::<PublicKey> {
            op_type: miniscript::calculus::Symbol::new("spend"),
            args: BTreeMap::new(),
            deposit_id: [0u8; 32],
            nonce: 0,
            expiry: u32::MAX,
        };

        let verifier = EcdsaVerifier::new();
        let message = miniscript::calculus::operation_preimage(&op);
        let sig = verifier.sign(&sk, &message);
        let witness = Witness::empty().with_signature(pk, sig);
        let state = ProtocolLedgerState::empty();

        let verdict = evaluate(&d, &op, &state, &witness, &verifier).expect("evaluate");
        assert!(verdict, "K signed the operation preimage; the descriptor accepts");
    }

    /// Negative case: a different message under the same key produces a different operation
    /// preimage, so the signature won't verify. Confirms the wire-up actually checks
    /// signatures (rather than silently accepting anything).
    #[test]
    fn smoke_test_rejects_a_signature_over_the_wrong_message() {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x42; 32]).expect("valid secret key");
        let pk = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk));

        let descriptor_src = format!("wsh(pk({}))", pk);
        let d = parse::<PublicKey>(&descriptor_src).expect("descriptor parses");

        // Two operations differing only in nonce — distinct preimages, distinct sighashes.
        let op_signed = OperationData::<PublicKey> {
            op_type: miniscript::calculus::Symbol::new("spend"),
            args: BTreeMap::new(),
            deposit_id: [0u8; 32],
            nonce: 1,
            expiry: u32::MAX,
        };
        let op_evaluated = OperationData::<PublicKey> {
            nonce: 2,
            ..op_signed.clone()
        };

        let verifier = EcdsaVerifier::new();
        let sig = verifier.sign(&sk, &miniscript::calculus::operation_preimage(&op_signed));
        let witness = Witness::empty().with_signature(pk, sig);
        let state = ProtocolLedgerState::empty();

        assert!(
            !evaluate(&d, &op_evaluated, &state, &witness, &verifier).expect("evaluate"),
            "signature over a different operation must not authorize this one",
        );
    }
}
