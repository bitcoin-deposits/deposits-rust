// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! End-to-end integration: a real keypair signs a `DepositKeyRotate` over the dep-17
//! operation preimage; the protocol's conformance check routes it through the new
//! `Dep16Authorizer` and accepts (or rejects for adversarial inputs).
//!
//! This exercises the full path through `apply_with_verifier`: state-machine apply,
//! conformance check, dep-16 authorization, integration with the existing
//! `WitnessVerifier`-routed checks for the other variants. The `Dep16Authorizer`
//! has its own focused unit tests in `deposits-core/src/dep16/authorizer.rs`; this file
//! is about the protocol-level integration.

use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::PublicKey;
use deposits_core::dep16::Dep16Authorizer;
use deposits_core::dep16::{operations, EcdsaVerifier, Verifier};
use deposits_protocol::messages::LedgerOperation;
use deposits_protocol::types::{ConformanceViolation, DenyAll, DescriptorWitness, NoVerify};
use deposits_protocol::{Deposit, LedgerState};

fn keypair(seed: u8) -> (SecretKey, PublicKey) {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[seed; 32]).unwrap();
    let pk = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk));
    (sk, pk)
}

/// Build a state with one deposit whose descriptor is `wsh(prove(pk(K)))`. Returns
/// (state, deposit_id, K).
fn state_with_pk_deposit(seed: u8) -> (LedgerState, [u8; 16], PublicKey) {
    let (_, pk) = keypair(seed);
    let descriptor = format!("wsh(prove(pk({})))", pk);
    let operator_key = bitcoin::secp256k1::PublicKey::from_slice(&[
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
    ])
    .unwrap();
    let mut state = LedgerState::new(operator_key, "test_reserves".to_string(), 0);
    let deposit = Deposit::new(descriptor.clone(), None);
    let did = deposit.deposit_id;
    state.deposits.insert(did, deposit);
    (state, did, pk)
}

/// Build a `DepositKeyRotate` op signed by `sk` over the dep-17 operation preimage.
/// The op rotates to a new arbitrary descriptor; the signature binds to the full op
/// (including the new descriptor, nonce, expiry, deposit_id).
fn signed_rotate(
    deposit_id: [u8; 16],
    new_descriptor: &str,
    nonce: u64,
    sk: &SecretKey,
) -> LedgerOperation {
    // Build the op with an empty witness first to derive the operation preimage.
    let op = LedgerOperation::DepositKeyRotate {
        deposit_id,
        new_descriptor: new_descriptor.to_string(),
        nonce,
        expiry: u32::MAX,
        witness: DescriptorWitness::new(),
    };
    let dep16_op = operations::to_dep16(&op).expect("descriptor-evaluated variant");
    let preimage = miniscript::calculus::operation_preimage(&dep16_op);
    let verifier = EcdsaVerifier::new();
    let sig = verifier.sign(sk, &preimage);
    // Rebuild with the signature in the witness stack.
    LedgerOperation::DepositKeyRotate {
        deposit_id,
        new_descriptor: new_descriptor.to_string(),
        nonce,
        expiry: u32::MAX,
        witness: DescriptorWitness {
            stack: vec![sig.0],
        },
    }
}

/// The happy path: owner-signed rotation with a strictly-increasing nonce and a real
/// signature over the dep-17 operation preimage produces zero conformance violations
/// when routed through `Dep16Authorizer`. Confirms the full integration:
///   - apply_with_verifier threads the Authorizer through to check_conformance
///   - DepositKeyRotate's check_conformance arm calls authorizer.authorize(...)
///   - Dep16Authorizer parses the OLD descriptor, translates the op, builds the
///     keyed witness from the byte-stack, evaluates via the dep-16 evaluator,
///     returns accept.
#[test]
fn deposit_key_rotate_authorized_by_owner_signature() {
    let (sk, _pk) = keypair(0x11);
    let (state, did, _) = state_with_pk_deposit(0x11);
    let new_desc = format!("wsh(prove(pk({})))", keypair(0x22).1);
    let op = signed_rotate(did, &new_desc, 1, &sk);

    let authorizer = Dep16Authorizer::new();
    let (next, violations) = state
        .apply_with_verifier(&op, &NoVerify, &authorizer, 0)
        .expect("apply must succeed");

    // No InvalidWitness for DepositKeyRotate. (Other violations — replay protection,
    // unparseable descriptor — could theoretically fire, but with this setup they
    // shouldn't.)
    let invalid_witness = violations.iter().any(|v| {
        matches!(
            v,
            ConformanceViolation::InvalidWitness {
                operation: "DepositKeyRotate",
                ..
            }
        )
    });
    assert!(
        !invalid_witness,
        "owner-signed rotation must not produce InvalidWitness: {:?}",
        violations,
    );
    // And the deposit's descriptor was actually updated.
    assert_eq!(next.deposits[&did].descriptor, new_desc);
}

/// Negative case: a rotation signed by some other key — not the deposit owner —
/// produces an `InvalidWitness` violation. The Dep16Authorizer rejected the witness;
/// the protocol layer surfaces the violation.
#[test]
fn deposit_key_rotate_rejected_when_signed_by_wrong_key() {
    let (_, _pk_owner) = keypair(0x11);
    let (sk_impostor, _) = keypair(0x99);
    let (state, did, _) = state_with_pk_deposit(0x11);
    let new_desc = format!("wsh(prove(pk({})))", keypair(0x22).1);
    let op = signed_rotate(did, &new_desc, 1, &sk_impostor);

    let authorizer = Dep16Authorizer::new();
    let (_, violations) = state
        .apply_with_verifier(&op, &NoVerify, &authorizer, 0)
        .expect("apply succeeds; the violation is in conformance");

    assert!(
        violations.iter().any(|v| matches!(
            v,
            ConformanceViolation::InvalidWitness {
                operation: "DepositKeyRotate",
                ..
            }
        )),
        "impostor-signed rotation must produce InvalidWitness: {:?}",
        violations,
    );
}

/// The dep-17 operation preimage binds nonce: a signature over op_a doesn't authorize
/// op_b that differs only in nonce. This is the protocol-level replay protection
/// property the dep-17 spec was designed for.
#[test]
fn signature_for_one_nonce_doesnt_authorize_another() {
    let (sk, _) = keypair(0x11);
    let (state, did, _) = state_with_pk_deposit(0x11);
    let new_desc = format!("wsh(prove(pk({})))", keypair(0x22).1);

    // Sign nonce=1, then swap in the signature for an otherwise-identical nonce=2 op.
    let op_signed = signed_rotate(did, &new_desc, 1, &sk);
    let sig_for_nonce_1 = match &op_signed {
        LedgerOperation::DepositKeyRotate { witness, .. } => witness.stack[0].clone(),
        _ => unreachable!(),
    };
    let op_replay = LedgerOperation::DepositKeyRotate {
        deposit_id: did,
        new_descriptor: new_desc.clone(),
        nonce: 2, // different nonce — different preimage
        expiry: u32::MAX,
        witness: DescriptorWitness {
            stack: vec![sig_for_nonce_1],
        },
    };

    let authorizer = Dep16Authorizer::new();
    let (_, violations) = state
        .apply_with_verifier(&op_replay, &NoVerify, &authorizer, 0)
        .expect("apply succeeds; the violation is in conformance");

    assert!(
        violations.iter().any(|v| matches!(
            v,
            ConformanceViolation::InvalidWitness {
                operation: "DepositKeyRotate",
                ..
            }
        )),
        "signature for a different nonce must not authorize: {:?}",
        violations,
    );
}

/// Explicit `AllowAll` opt-out: a caller that doesn't want descriptor
/// authorization (e.g. a unit test focused on a different invariant) can plug
/// in `AllowAll` and the rotation passes regardless of the witness. Companion
/// to `deposit_key_rotate_authorized_by_owner_signature` (which uses a real
/// `Dep16Authorizer`) — together they confirm that the authorization decision
/// is fully delegated to whatever `Authorizer` the caller supplies.
#[test]
fn allow_all_opt_out_accepts_rotation() {
    use deposits_protocol::types::AllowAll;
    let (sk, _) = keypair(0x11);
    let (state, did, _) = state_with_pk_deposit(0x11);
    let new_desc = format!("wsh(prove(pk({})))", keypair(0x22).1);
    let op = signed_rotate(did, &new_desc, 1, &sk);

    let (_, violations) = state
        .apply_with_verifier(&op, &NoVerify, &AllowAll, 0)
        .expect("apply succeeds");
    assert!(
        !violations.iter().any(|v| matches!(
            v,
            ConformanceViolation::InvalidWitness {
                operation: "DepositKeyRotate",
                ..
            }
        )),
        "AllowAll authorizer must not raise InvalidWitness: {:?}",
        violations,
    );
}

/// A 2-of-3 multisig descriptor: any two of three sign and the rotation is authorized;
/// one signature alone is rejected. Confirms the Dep16Authorizer's threshold support
/// works through the full protocol path.
#[test]
fn threshold_rotation_two_of_three() {
    let (sk_a, pk_a) = keypair(0x01);
    let (sk_b, pk_b) = keypair(0x02);
    let (_, pk_c) = keypair(0x03);
    let descriptor = format!(
        "wsh(prove(pk_threshold(2, [{}, {}, {}])))",
        pk_a, pk_b, pk_c
    );

    let operator_key = bitcoin::secp256k1::PublicKey::from_slice(&[
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
    ])
    .unwrap();
    let mut state = LedgerState::new(operator_key, "test_reserves".to_string(), 0);
    let deposit = Deposit::new(descriptor.clone(), None);
    let did = deposit.deposit_id;
    state.deposits.insert(did, deposit);

    let new_desc = format!("wsh(prove(pk({})))", keypair(0xee).1);
    // Compute the preimage once (same op shape for both sub-cases).
    let op_template = LedgerOperation::DepositKeyRotate {
        deposit_id: did,
        new_descriptor: new_desc.clone(),
        nonce: 1,
        expiry: u32::MAX,
        witness: DescriptorWitness::new(),
    };
    let preimage = miniscript::calculus::operation_preimage(
        &operations::to_dep16(&op_template).unwrap(),
    );
    let verifier = EcdsaVerifier::new();
    let sig_a = verifier.sign(&sk_a, &preimage);
    let sig_b = verifier.sign(&sk_b, &preimage);

    let authorizer = Dep16Authorizer::new();

    // A+B sign: authorized (threshold met).
    let op_ab = LedgerOperation::DepositKeyRotate {
        deposit_id: did,
        new_descriptor: new_desc.clone(),
        nonce: 1,
        expiry: u32::MAX,
        witness: DescriptorWitness {
            stack: vec![sig_a.0.clone(), sig_b.0.clone()],
        },
    };
    let (_, violations_ab) = state
        .apply_with_verifier(&op_ab, &NoVerify, &authorizer, 0)
        .expect("apply must succeed");
    assert!(
        !violations_ab.iter().any(|v| matches!(
            v,
            ConformanceViolation::InvalidWitness {
                operation: "DepositKeyRotate",
                ..
            }
        )),
        "2-of-3 with two sigs must satisfy threshold: {:?}",
        violations_ab,
    );

    // Only A: under-threshold (must produce InvalidWitness).
    let op_a_only = LedgerOperation::DepositKeyRotate {
        deposit_id: did,
        new_descriptor: new_desc,
        nonce: 1,
        expiry: u32::MAX,
        witness: DescriptorWitness {
            stack: vec![sig_a.0],
        },
    };
    let (_, violations_a) = state
        .apply_with_verifier(&op_a_only, &NoVerify, &authorizer, 0)
        .expect("apply succeeds; the violation is in conformance");
    assert!(
        violations_a.iter().any(|v| matches!(
            v,
            ConformanceViolation::InvalidWitness {
                operation: "DepositKeyRotate",
                ..
            }
        )),
        "2-of-3 with one sig must produce InvalidWitness: {:?}",
        violations_a,
    );
}
