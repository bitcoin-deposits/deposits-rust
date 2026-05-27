// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! [`Dep16Authorizer`] — the real `Authorizer` impl for the deposits protocol.
//!
//! Wires the dep-16 evaluator into [`deposits_protocol::Authorizer`]: takes a descriptor
//! string + a [`LedgerOperation`], parses the descriptor as dep-16 source, translates the
//! operation via [`super::operations::to_dep16`], converts the byte-stack witness into the
//! dep-16 keyed `Witness` shape (by trying each stack signature against each key the
//! descriptor mentions), and evaluates. Currently used by `DepositKeyRotate`'s conformance
//! check — phases 5 and 6 of `PLAN-dep16-integration.md` extend it to the lock-side
//! variants and remove the old `WitnessVerifier` path.
//!
//! v1 scope: the descriptor's keys are read as 33-byte compressed secp256k1 pubkeys
//! (bitcoin::PublicKey). x-only (BIP-340) and tr key-path support land in a later phase
//! when the descriptor catalogue introduces tr deposits.

use bitcoin::PublicKey;
use deposits_protocol::messages::LedgerOperation;
use deposits_protocol::types::DescriptorWitness;
use deposits_protocol::Authorizer;

use super::{
    operations, EcdsaVerifier, Obligation, Verifier as Dep16Verifier, Witness as Dep16Witness,
};
use miniscript::calculus::ast::BTerm;
use miniscript::calculus::Signature as Dep16Signature;

/// dep-16-backed `Authorizer`. Holds a single ECDSA verifier; produces verdicts by
/// evaluating the calculus on the operation's translated form.
pub struct Dep16Authorizer {
    verifier: EcdsaVerifier,
}

impl Default for Dep16Authorizer {
    fn default() -> Self {
        Self::new()
    }
}

impl Dep16Authorizer {
    pub fn new() -> Self {
        Self {
            verifier: EcdsaVerifier::new(),
        }
    }
}

impl Authorizer for Dep16Authorizer {
    fn authorize(&self, descriptor: &str, operation: &LedgerOperation) -> bool {
        authorize_inner(&self.verifier, descriptor, operation).unwrap_or(false)
    }

    fn validate_descriptor(&self, descriptor: &str) -> Option<String> {
        match miniscript::calculus::parse::<PublicKey>(descriptor) {
            Ok(_) => None,
            Err(e) => Some(format!("{}", e)),
        }
    }
}

/// The actual authorization logic, factored out so the trait method can `unwrap_or(false)`
/// on any error (parse failure, missing witness, ledger-state read on an op that doesn't
/// have one). Phase 4 keeps the "unauthorized on any error" stance from the legacy
/// `verify_witness` path; phase 5 may surface specific errors as conformance violations.
fn authorize_inner(
    verifier: &EcdsaVerifier,
    descriptor: &str,
    operation: &LedgerOperation,
) -> Option<bool> {
    // 1. Parse descriptor as dep-16 source.
    let d = miniscript::calculus::parse::<PublicKey>(descriptor).ok()?;

    // 2. Translate the protocol op into the dep-16 Operation form. None for variants
    //    that don't go through descriptor evaluation (fulfill, administrative ops).
    let dep16_op = operations::to_dep16(operation)?;

    // 3. The signing preimage the witness signatures must verify against.
    let preimage = miniscript::calculus::operation_preimage(&dep16_op);

    // 4. Convert the byte-stack witness to the dep-16 keyed shape. Walks the descriptor
    //    for pk(K) leaves; for each (signature, key) pair, tests verification; binds
    //    matches into the dep-16 witness.
    let byte_witness = extract_witness(operation)?;
    let dep16_witness = stack_to_keyed(verifier, &d, &byte_witness.stack, &preimage);

    // 5. Evaluate. ProtocolLedgerState::empty() is fine for now: DepositKeyRotate
    //    (the only variant currently routed here) doesn't read ledger state. Phase 5
    //    will plumb a real adapter when the spend-side variants start needing it.
    let state = super::ProtocolLedgerState::empty();
    miniscript::calculus::evaluate(&d, &dep16_op, &state, &dep16_witness, verifier).ok()
}

/// Pull the `witness` (or `script_witness`) field out of a `LedgerOperation` variant.
/// Returns `None` for variants that don't carry a witness or aren't routed through the
/// dep-16 path.
fn extract_witness(op: &LedgerOperation) -> Option<&DescriptorWitness> {
    match op {
        LedgerOperation::InvoiceLock { witness, .. } => Some(witness),
        LedgerOperation::OnchainLock { witness, .. } => Some(witness),
        LedgerOperation::TransferLock { witness, .. } => Some(witness),
        LedgerOperation::DepositKeyRotate { witness, .. } => Some(witness),
        // TransferComplete's script_witness is the lock's release-descriptor witness;
        // the caller routes this through Authorizer against the lock's completion_script.
        LedgerOperation::TransferComplete { script_witness, .. } => Some(script_witness),
        _ => None,
    }
}

/// Convert a positional byte-stack witness (the legacy `DescriptorWitness` shape) into
/// the dep-16 keyed `Witness`. Walks the descriptor's body for every `pk(K)` obligation;
/// for each (stack signature, descriptor key) pair, tries ECDSA verification against the
/// operation preimage; on match, binds the signature to the key in the dep-16 witness.
///
/// A signature that matches multiple keys (theoretically impossible with secp256k1
/// uniqueness, but defensively) is bound to whichever key the descriptor walk encountered
/// first — the dep-16 evaluator only cares whether each obligation's key has *some*
/// satisfying entry, so duplicate bindings don't change the verdict.
fn stack_to_keyed(
    verifier: &EcdsaVerifier,
    descriptor: &miniscript::calculus::Descriptor<PublicKey>,
    stack: &[Vec<u8>],
    preimage: &[u8],
) -> Dep16Witness<PublicKey> {
    let mut witness = Dep16Witness::empty();
    let body = match descriptor.body() {
        Some(b) => b,
        None => return witness, // tr(K) with no body
    };
    let keys = collect_pk_keys(body);
    for stack_bytes in stack {
        if stack_bytes.len() != 64 {
            // dep-16 ECDSA verifier expects 64-byte compact signatures. Anything else
            // (Bitcoin Script witness elements that aren't sigs, ridiculous lengths)
            // is skipped — the witness simply lacks a matching entry for whichever
            // key needed this sig.
            continue;
        }
        let sig = Dep16Signature(stack_bytes.clone());
        for key in &keys {
            if witness.signatures.contains_key(key) {
                continue;
            }
            if verifier.verify_signature(key, &sig, preimage) {
                witness = witness.with_signature(*key, sig.clone());
                break;
            }
        }
    }
    witness
}

/// Recursively walk a body term and collect every key referenced by a signature-bearing
/// obligation (`pk(K)`, `pk_any([K, ...])`, `pk_threshold(k, [K, ...])`). The collected
/// keys are the universe of candidates for stack-to-keyed witness binding.
///
/// Other obligation kinds (`pk_h`, `hashlock`, `attest`) carry a different witness
/// shape (key-hash, preimage, attestation) and aren't fed by stack signatures —
/// supporting them would require parallel walks of the witness for preimages / attestor
/// references. Phase 5 / 6 will add those as the lock-side descriptors start using them.
fn collect_pk_keys(t: &BTerm<PublicKey>) -> Vec<PublicKey> {
    let mut keys = Vec::new();
    collect_pk_keys_into(t, &mut keys);
    keys
}

fn collect_pk_keys_into(t: &BTerm<PublicKey>, out: &mut Vec<PublicKey>) {
    use miniscript::calculus::ast::VTerm;
    use miniscript::calculus::Value;
    // Helper: pull a single literal key out of a VTerm if it is one.
    fn lit_key(v: &VTerm<PublicKey>) -> Option<PublicKey> {
        match v {
            VTerm::Lit(Value::Key(k)) => Some(*k),
            _ => None,
        }
    }
    // Helper: pull a literal list of keys out of a VTerm if it is one.
    fn lit_key_list(v: &VTerm<PublicKey>) -> Vec<PublicKey> {
        match v {
            VTerm::Lit(Value::List(items)) => items
                .iter()
                .filter_map(|item| match item {
                    Value::Key(k) => Some(*k),
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        }
    }
    fn push_unique(out: &mut Vec<PublicKey>, k: PublicKey) {
        if !out.contains(&k) {
            out.push(k);
        }
    }
    match t {
        BTerm::Prove(Obligation::Pk(v)) => {
            if let Some(k) = lit_key(v) {
                push_unique(out, k);
            }
        }
        BTerm::Prove(Obligation::PkAny(v)) | BTerm::Prove(Obligation::Multi(_, v)) => {
            for k in lit_key_list(v) {
                push_unique(out, k);
            }
        }
        BTerm::Prove(_) => {} // pk_h / hashlock / attest — see fn doc.
        BTerm::And(bs) | BTerm::Or(bs) | BTerm::Thresh(_, bs) => {
            for b in bs {
                collect_pk_keys_into(b, out);
            }
        }
        BTerm::Not(b) => collect_pk_keys_into(b, out),
        BTerm::If(c, t, e) => {
            collect_pk_keys_into(c, out);
            collect_pk_keys_into(t, out);
            collect_pk_keys_into(e, out);
        }
        BTerm::Match { arms, default, .. } => {
            for (_, body) in arms {
                collect_pk_keys_into(body, out);
            }
            collect_pk_keys_into(default, out);
        }
        BTerm::Const(_) | BTerm::Cmp(..) | BTerm::State(..) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use deposits_protocol::types::DescriptorWitness;

    fn keypair(seed: u8) -> (SecretKey, PublicKey) {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[seed; 32]).unwrap();
        let pk = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk));
        (sk, pk)
    }

    fn dummy_deposit_id() -> [u8; 16] {
        let mut id = [0u8; 16];
        id[0] = 0xde;
        id[1] = 0xad;
        id
    }

    /// A real keypair signs a DepositKeyRotate against a wsh(pk(K)) deposit; the
    /// Dep16Authorizer accepts. Exercises: descriptor parse, operation translation,
    /// preimage construction, key-collection walk, witness conversion, evaluation.
    #[test]
    fn authorizes_deposit_key_rotate_when_owner_signs() {
        let (sk, pk) = keypair(0x11);
        let descriptor = format!("wsh(prove(pk({})))", pk);
        let auth = Dep16Authorizer::new();

        let op = LedgerOperation::DepositKeyRotate {
            deposit_id: dummy_deposit_id(),
            new_descriptor: format!("wsh(prove(pk({})))", keypair(0x22).1),
            nonce: 1,
            expiry: u32::MAX,
            witness: DescriptorWitness::new(), // filled below
        };

        // Sign the operation preimage with the deposit's owner key.
        let dep16_op = operations::to_dep16(&op).unwrap();
        let preimage = miniscript::calculus::operation_preimage(&dep16_op);
        let verifier = EcdsaVerifier::new();
        let sig = verifier.sign(&sk, &preimage);

        // Re-build the op with the signature in its witness stack.
        let op_signed = LedgerOperation::DepositKeyRotate {
            deposit_id: dummy_deposit_id(),
            new_descriptor: format!("wsh(prove(pk({})))", keypair(0x22).1),
            nonce: 1,
            expiry: u32::MAX,
            witness: DescriptorWitness {
                stack: vec![sig.0],
            },
        };

        assert!(
            auth.authorize(&descriptor, &op_signed),
            "owner-signed rotation must be authorized"
        );
    }

    /// A signature by a different key does not authorize. Confirms the Dep16Authorizer
    /// actually verifies signatures rather than accepting blindly.
    #[test]
    fn rejects_deposit_key_rotate_signed_by_wrong_key() {
        let (_, owner_pk) = keypair(0x11);
        let (impostor_sk, _) = keypair(0x99);
        let descriptor = format!("wsh(prove(pk({})))", owner_pk);
        let auth = Dep16Authorizer::new();

        let op = LedgerOperation::DepositKeyRotate {
            deposit_id: dummy_deposit_id(),
            new_descriptor: format!("wsh(prove(pk({})))", keypair(0x22).1),
            nonce: 1,
            expiry: u32::MAX,
            witness: DescriptorWitness::new(),
        };
        let dep16_op = operations::to_dep16(&op).unwrap();
        let preimage = miniscript::calculus::operation_preimage(&dep16_op);
        let verifier = EcdsaVerifier::new();
        let sig = verifier.sign(&impostor_sk, &preimage);

        let op_signed = LedgerOperation::DepositKeyRotate {
            deposit_id: dummy_deposit_id(),
            new_descriptor: format!("wsh(prove(pk({})))", keypair(0x22).1),
            nonce: 1,
            expiry: u32::MAX,
            witness: DescriptorWitness {
                stack: vec![sig.0],
            },
        };
        assert!(
            !auth.authorize(&descriptor, &op_signed),
            "impostor-signed rotation must be rejected",
        );
    }

    /// A signature over a *different* operation does not authorize this one. The
    /// dep-17 operation preimage embeds nonce, expiry, deposit_id, op_type and args;
    /// a signature over op_a's preimage cannot replay against op_b. This is the
    /// concrete replay-protection property dep-17 was designed for.
    #[test]
    fn signature_over_different_operation_is_rejected() {
        let (sk, pk) = keypair(0x11);
        let descriptor = format!("wsh(prove(pk({})))", pk);
        let auth = Dep16Authorizer::new();

        // Sign op_a's preimage.
        let op_a = LedgerOperation::DepositKeyRotate {
            deposit_id: dummy_deposit_id(),
            new_descriptor: "wsh(prove(pk(_a)))".to_string(),
            nonce: 1,
            expiry: u32::MAX,
            witness: DescriptorWitness::new(),
        };
        let preimage_a = miniscript::calculus::operation_preimage(&operations::to_dep16(&op_a).unwrap());
        let verifier = EcdsaVerifier::new();
        let sig_a = verifier.sign(&sk, &preimage_a);

        // Attach sig_a to op_b (different new_descriptor — different preimage).
        let op_b = LedgerOperation::DepositKeyRotate {
            deposit_id: dummy_deposit_id(),
            new_descriptor: "wsh(prove(pk(_b)))".to_string(),
            nonce: 1,
            expiry: u32::MAX,
            witness: DescriptorWitness {
                stack: vec![sig_a.0],
            },
        };
        assert!(
            !auth.authorize(&descriptor, &op_b),
            "signature over a different op must not authorize this one",
        );
    }

    /// A 2-of-3 multisig descriptor authorizes when any two of three sign. The
    /// stack_to_keyed helper has to bind two distinct signatures to two of the
    /// three keys; the dep-16 evaluator's pk_threshold sees two valid sigs and
    /// the threshold is met.
    #[test]
    fn authorizes_threshold_with_two_of_three() {
        let (sk_a, pk_a) = keypair(0x01);
        let (sk_b, pk_b) = keypair(0x02);
        let (_, pk_c) = keypair(0x03);
        let descriptor = format!(
            "wsh(prove(pk_threshold(2, [{}, {}, {}])))",
            pk_a, pk_b, pk_c
        );
        let auth = Dep16Authorizer::new();

        let op = LedgerOperation::DepositKeyRotate {
            deposit_id: dummy_deposit_id(),
            new_descriptor: format!("wsh(prove(pk({})))", keypair(0xee).1),
            nonce: 1,
            expiry: u32::MAX,
            witness: DescriptorWitness::new(),
        };
        let preimage = miniscript::calculus::operation_preimage(&operations::to_dep16(&op).unwrap());
        let verifier = EcdsaVerifier::new();
        let sig_a = verifier.sign(&sk_a, &preimage);
        let sig_b = verifier.sign(&sk_b, &preimage);

        let op_signed = LedgerOperation::DepositKeyRotate {
            deposit_id: dummy_deposit_id(),
            new_descriptor: format!("wsh(prove(pk({})))", keypair(0xee).1),
            nonce: 1,
            expiry: u32::MAX,
            witness: DescriptorWitness {
                stack: vec![sig_a.0, sig_b.0],
            },
        };
        assert!(
            auth.authorize(&descriptor, &op_signed),
            "2-of-3 with two sigs must satisfy the threshold",
        );

        // Same descriptor, only one signature → under-threshold, rejected.
        let only_a = LedgerOperation::DepositKeyRotate {
            deposit_id: dummy_deposit_id(),
            new_descriptor: format!("wsh(prove(pk({})))", keypair(0xee).1),
            nonce: 1,
            expiry: u32::MAX,
            witness: DescriptorWitness {
                stack: vec![verifier.sign(&sk_a, &preimage).0],
            },
        };
        assert!(
            !auth.authorize(&descriptor, &only_a),
            "2-of-3 with one sig must NOT satisfy the threshold",
        );
    }

    /// validate_descriptor rejects unparseable strings, accepts parseable ones.
    #[test]
    fn validate_descriptor_round_trips() {
        let auth = Dep16Authorizer::new();
        let (_, pk) = keypair(0x11);
        let valid = format!("wsh(prove(pk({})))", pk);
        assert!(auth.validate_descriptor(&valid).is_none());
        assert!(auth.validate_descriptor("not a descriptor").is_some());
    }

    /// Operations that don't go through descriptor evaluation (fulfills,
    /// administrative ops) return false — the Authorizer has nothing to evaluate
    /// against. The caller decides what that means (typically: don't run the check
    /// for these variants at all).
    #[test]
    fn unevaluable_operations_return_false() {
        let (_, pk) = keypair(0x11);
        let descriptor = format!("wsh(prove(pk({})))", pk);
        let auth = Dep16Authorizer::new();

        let fulfill = LedgerOperation::InvoiceFulfill {
            deposit_id: dummy_deposit_id(),
            amount: 50,
            payment_id: [0xab; 32],
            sequence_number: 1,
            preimage: [0xee; 32],
            witness: DescriptorWitness::new(),
        };
        assert!(!auth.authorize(&descriptor, &fulfill));

        let close = LedgerOperation::DepositClose {
            deposit_id: dummy_deposit_id(),
        };
        assert!(!auth.authorize(&descriptor, &close));
    }
}
