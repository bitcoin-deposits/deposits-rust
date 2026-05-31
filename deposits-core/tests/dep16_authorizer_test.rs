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
use deposits_protocol::types::{ConformanceViolation, DenyAll, DescriptorWitness};
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
        .apply_with_verifier(&op, &authorizer, 0)
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
        .apply_with_verifier(&op, &authorizer, 0)
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
        .apply_with_verifier(&op_replay, &authorizer, 0)
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
        .apply_with_verifier(&op, &AllowAll, 0)
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
        .apply_with_verifier(&op_ab, &authorizer, 0)
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
        .apply_with_verifier(&op_a_only, &authorizer, 0)
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

// =========================================================================
// End-to-end via sign_op: the production wallet path
//
// The DepositKeyRotate tests above use a raw EcdsaVerifier::sign path that
// confirms the authorizer accepts a well-formed dep-16 signature. The tests
// below confirm the *production* wallet signing path (`sign_op`) produces a
// witness shape `Dep16Authorizer` accepts for each lock-side variant. If the
// signing algorithm ever drifts from what the authorizer verifies against
// (e.g. Schnorr vs. ECDSA), these tests fail.
// =========================================================================

fn state_with_descriptor(seed: u8) -> (LedgerState, [u8; 16], bitcoin::secp256k1::SecretKey) {
    let (sk, pk) = keypair(seed);
    let descriptor = format!("wsh(prove(pk({})))", pk);
    let operator_key = bitcoin::secp256k1::PublicKey::from_slice(&[
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
    ])
    .unwrap();
    let mut state = LedgerState::new(operator_key, "test_reserves".to_string(), 0);
    state.reserves_amount = 10_000_000;
    let deposit = Deposit::new(descriptor.clone(), None);
    let did = deposit.deposit_id;
    state.deposits.insert(did, deposit);
    // Credit so locks have balance to work with.
    state = state
        .apply(&LedgerOperation::InvoiceCredit {
            payment_hash: [0xee; 32],
            deposit_id: did,
            amount: 1_000_000,
            invoice_id: "seed".into(),
            sequence_number: 1,
        })
        .unwrap();
    (state, did, sk)
}

fn assert_authorizer_accepts(state: &LedgerState, op: &LedgerOperation, op_label: &str) {
    let authorizer = Dep16Authorizer::new();
    let (_, violations) = state
        .apply_with_verifier(op, &authorizer, 0)
        .expect("apply succeeds; failure would be in conformance");
    let invalid_witness = violations.iter().any(|v| {
        matches!(
            v,
            ConformanceViolation::InvalidWitness { .. }
        )
    });
    assert!(
        !invalid_witness,
        "{} signed via sign_op must satisfy Dep16Authorizer; violations: {:?}",
        op_label, violations,
    );
}

#[test]
fn sign_op_invoice_lock_authorized_by_dep16() {
    let (state, did, sk) = state_with_descriptor(0x21);
    let proto = LedgerOperation::InvoiceLock {
        deposit_id: did,
        amount: 100_000,
        payment_id: [0xaa; 32],
        sequence_number: 2,
        nonce: deposits_core::signing::fresh_op_nonce(),
        expiry: u32::MAX,
        witness: DescriptorWitness::new(),
    };
    let op = deposits_core::signing::sign_op(proto, &sk).expect("InvoiceLock is signable");
    assert_authorizer_accepts(&state, &op, "InvoiceLock");
}

#[test]
fn sign_op_onchain_lock_authorized_by_dep16() {
    let (state, did, sk) = state_with_descriptor(0x22);
    let proto = LedgerOperation::OnchainLock {
        deposit_id: did,
        amount: 50_000,
        fee_sats: 500,
        destination_address: "bcrt1qsink".into(),
        withdrawal_id: [0xbb; 32],
        nonce: deposits_core::signing::fresh_op_nonce(),
        expiry: u32::MAX,
        witness: DescriptorWitness::new(),
    };
    let op = deposits_core::signing::sign_op(proto, &sk).expect("OnchainLock is signable");
    assert_authorizer_accepts(&state, &op, "OnchainLock");
}

#[test]
fn sign_op_transfer_lock_authorized_by_dep16() {
    let (state, did, sk) = state_with_descriptor(0x23);
    // Need a destination deposit for state-machine apply to succeed.
    let dst_descriptor = format!("wsh(prove(pk({})))", keypair(0x24).1);
    let dst = deposits_protocol::types::compute_deposit_id(&dst_descriptor);
    let mut state = state;
    state.deposits.insert(dst, Deposit::new(dst_descriptor, None));

    let proto = LedgerOperation::TransferLock {
        transfer_nonce: [0x77; 32],
        source_deposit_id: did,
        destination_deposit_id: dst,
        amount: 30_000,
        fee: 500,
        completion_script: "sha256(cafe)".into(),
        timeout_height: 900_000,
        transfer_id: [0x88; 32],
        nonce: deposits_core::signing::fresh_op_nonce(),
        expiry: u32::MAX,
        witness: DescriptorWitness::new(),
    };
    let op = deposits_core::signing::sign_op(proto, &sk).expect("TransferLock is signable");
    assert_authorizer_accepts(&state, &op, "TransferLock");
}

#[test]
fn sign_op_deposit_key_rotate_authorized_by_dep16() {
    let (state, did, sk) = state_with_descriptor(0x25);
    let new_desc = format!("wsh(prove(pk({})))", keypair(0x26).1);
    let proto = LedgerOperation::DepositKeyRotate {
        deposit_id: did,
        new_descriptor: new_desc,
        nonce: deposits_core::signing::fresh_op_nonce(),
        expiry: u32::MAX,
        witness: DescriptorWitness::new(),
    };
    let op = deposits_core::signing::sign_op(proto, &sk).expect("DepositKeyRotate is signable");
    assert_authorizer_accepts(&state, &op, "DepositKeyRotate");
}

/// Pinned dep-17 sighash for a fixed InvoiceLock. Cross-language parity
/// fixture: the same op shape must produce exactly this hash in the JS port
/// at `deposits-web/wallet/vendor/dep17.js`. If you change preimage
/// construction (encode.rs / to_dep16) and this hash moves, the JS port
/// breaks silently until you mirror the change there.
#[test]
fn dep17_invoice_lock_sighash_pinned() {
    let did = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10,
    ];
    let op = LedgerOperation::InvoiceLock {
        deposit_id: did,
        amount: 100_000_u64,
        payment_id: [0xaa; 32],
        sequence_number: 7,
        nonce: 42_u64,
        expiry: u32::MAX,
        witness: DescriptorWitness::new(),
    };
    let sighash = deposits_core::dep16::operations::operation_sighash(&op).unwrap();
    assert_eq!(
        hex::encode(sighash),
        "60317ef178dce942d76273d3873c9f7a945906b31209d25db69c72fc4428251c",
        "dep-17 sighash drifted — update deposits-web/wallet/vendor/dep17.js too",
    );
}
