//! Conformance tests for DEP-02 §Balance Commitments.
//!
//! Two rules:
//!   - verify-when-present (intrinsic to EVERY ruleset): a declared post-op
//!     `(balance, locked_balance)` must equal the replayed state.
//!   - require-presence (only under `balance-commit-v4`): every balance-touching
//!     op must carry its commitment.

use deposits_protocol::messages::{BalanceCommitment, LedgerOperation};
use deposits_protocol::types::{
    compute_deposit_id, AllowAll, ConformanceViolation, FeeStructure, LedgerState,
    TransferFeeSchedule,
};

fn test_pubkey() -> bitcoin::secp256k1::PublicKey {
    use std::str::FromStr;
    bitcoin::secp256k1::PublicKey::from_str(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    )
    .unwrap()
}

fn make_state() -> LedgerState {
    let mut state = LedgerState::new(test_pubkey(), "bcrt1qtest".to_string(), 0);
    state.reserves_amount = 1_000_000;
    state
}

fn open_deposit(state: &LedgerState, descriptor: &str) -> LedgerState {
    let deposit_id = compute_deposit_id(descriptor);
    state
        .apply(&LedgerOperation::DepositOpen {
            deposit_id,
            descriptor: descriptor.to_string(),
            fees: Some(FeeStructure::default()),
            transfer_fees: Some(TransferFeeSchedule::default()),
            payment_hash: None,
            invoice: None,
            cosigner_guarantee_signature: None,
            receive_requires_sig: false,
            fee_change_after_blocks: None,
            fee_change_notice_blocks: None,
            fee_change_limit_bps: None,
            commitment: None,
        })
        .unwrap()
}

/// A credit of `amount` to `deposit_id`, carrying `commitment`.
fn credit(
    deposit_id: [u8; 16],
    amount: u64,
    commitment: Option<BalanceCommitment>,
) -> LedgerOperation {
    LedgerOperation::InvoiceCredit {
        payment_hash: [0xaa; 32],
        deposit_id,
        amount,
        invoice_id: "test".to_string(),
        sequence_number: 1,
        wallet_authorization: None,
        commitment,
    }
}

fn has_mismatch(violations: &[ConformanceViolation]) -> bool {
    violations
        .iter()
        .any(|v| matches!(v, ConformanceViolation::BalanceCommitmentMismatch { .. }))
}

fn has_missing(violations: &[ConformanceViolation]) -> bool {
    violations
        .iter()
        .any(|v| matches!(v, ConformanceViolation::MissingBalanceCommitment { .. }))
}

#[test]
fn correct_commitment_passes() {
    let state = open_deposit(&make_state(), "pk(aabbcc)");
    let did = compute_deposit_id("pk(aabbcc)");
    // Fresh deposit at (0, 0); a 500k credit → (500_000, 0).
    let op = credit(
        did,
        500_000,
        Some(BalanceCommitment {
            balance_after: 500_000,
            locked_after: 0,
        }),
    );
    let (_next, violations) = state.apply_with_verifier(&op, &AllowAll, 0).unwrap();
    assert!(
        !has_mismatch(&violations),
        "correct commitment must not fault: {:?}",
        violations
    );
}

#[test]
fn wrong_balance_faults_on_every_ruleset() {
    // active_ruleset_name defaults to "legacy" — verify-when-present is intrinsic.
    let state = open_deposit(&make_state(), "pk(aabbcc)");
    let did = compute_deposit_id("pk(aabbcc)");
    let op = credit(
        did,
        500_000,
        Some(BalanceCommitment {
            balance_after: 499_999, // lie
            locked_after: 0,
        }),
    );
    let (_next, violations) = state.apply_with_verifier(&op, &AllowAll, 0).unwrap();
    assert!(
        has_mismatch(&violations),
        "a wrong declared balance must fault even under legacy"
    );
}

#[test]
fn wrong_locked_faults() {
    let state = open_deposit(&make_state(), "pk(aabbcc)");
    let did = compute_deposit_id("pk(aabbcc)");
    let op = credit(
        did,
        500_000,
        Some(BalanceCommitment {
            balance_after: 500_000,
            locked_after: 7, // a credit locks nothing
        }),
    );
    let (_next, violations) = state.apply_with_verifier(&op, &AllowAll, 0).unwrap();
    assert!(
        has_mismatch(&violations),
        "a wrong declared locked_balance must fault"
    );
}

#[test]
fn missing_commitment_ok_on_legacy() {
    let state = open_deposit(&make_state(), "pk(aabbcc)");
    let did = compute_deposit_id("pk(aabbcc)");
    let op = credit(did, 500_000, None);
    let (_next, violations) = state.apply_with_verifier(&op, &AllowAll, 0).unwrap();
    assert!(
        !has_missing(&violations),
        "legacy ledgers must accept commitment-less ops"
    );
    assert!(!has_mismatch(&violations));
}

#[test]
fn missing_commitment_faults_under_v4() {
    let mut state = make_state();
    state.active_ruleset_name = "balance-commit-v4".to_string();
    let state = open_deposit(&state, "pk(aabbcc)");
    let did = compute_deposit_id("pk(aabbcc)");
    let op = credit(did, 500_000, None);
    let (_next, violations) = state.apply_with_verifier(&op, &AllowAll, 0).unwrap();
    assert!(
        has_missing(&violations),
        "balance-commit-v4 must require a commitment on a balance-touching op"
    );
}

#[test]
fn correct_commitment_ok_under_v4() {
    let mut state = make_state();
    state.active_ruleset_name = "balance-commit-v4".to_string();
    let state = open_deposit(&state, "pk(aabbcc)");
    let did = compute_deposit_id("pk(aabbcc)");
    let op = credit(
        did,
        500_000,
        Some(BalanceCommitment {
            balance_after: 500_000,
            locked_after: 0,
        }),
    );
    let (_next, violations) = state.apply_with_verifier(&op, &AllowAll, 0).unwrap();
    assert!(
        !has_mismatch(&violations) && !has_missing(&violations),
        "a correct commitment under v4 must pass clean: {:?}",
        violations
    );
}

#[test]
fn lock_commitment_tracks_locked_balance() {
    // Credit 500k, then lock 100k: balance stays 500k, locked becomes 100k.
    // The commitment must reflect the *pair* — this is the locking-clarity case.
    let state = open_deposit(&make_state(), "pk(aabbcc)");
    let did = compute_deposit_id("pk(aabbcc)");
    let funded = state.apply(&credit(did, 500_000, None)).unwrap();

    let lock = LedgerOperation::InvoiceLock {
        deposit_id: did,
        amount: 100_000,
        payment_id: [0xcd; 32],
        sequence_number: 2,
        nonce: 1,
        expiry: u32::MAX,
        timeout_height: None,
        fee: None,
        witness: Default::default(),
        commitment: Some(BalanceCommitment {
            balance_after: 500_000, // lock doesn't move balance
            locked_after: 100_000,  // it locks it
        }),
    };
    let (_next, violations) = funded.apply_with_verifier(&lock, &AllowAll, 0).unwrap();
    assert!(
        !has_mismatch(&violations),
        "a correct lock commitment (balance unchanged, locked raised) must pass: {:?}",
        violations
    );

    // And a lie about the locked side faults.
    let bad_lock = LedgerOperation::InvoiceLock {
        deposit_id: did,
        amount: 100_000,
        payment_id: [0xce; 32],
        sequence_number: 2,
        nonce: 2,
        expiry: u32::MAX,
        timeout_height: None,
        fee: None,
        witness: Default::default(),
        commitment: Some(BalanceCommitment {
            balance_after: 500_000,
            locked_after: 0, // lie: it did lock 100k
        }),
    };
    let (_n, v2) = funded.apply_with_verifier(&bad_lock, &AllowAll, 0).unwrap();
    assert!(
        has_mismatch(&v2),
        "a lock that under-declares locked_balance must fault"
    );
}

#[test]
fn fill_then_verify_roundtrips() {
    // The operator's `fill_balance_commitments` must produce a commitment the
    // cosigner's `check_conformance` accepts — for credit AND lock.
    let state = open_deposit(&make_state(), "pk(aabbcc)");
    let did = compute_deposit_id("pk(aabbcc)");

    let filled_credit = state.fill_balance_commitments(credit(did, 500_000, None));
    match &filled_credit {
        LedgerOperation::InvoiceCredit { commitment, .. } => assert_eq!(
            *commitment,
            Some(BalanceCommitment {
                balance_after: 500_000,
                locked_after: 0
            })
        ),
        _ => panic!("wrong op"),
    }
    let (funded, v) = state
        .apply_with_verifier(&filled_credit, &AllowAll, 0)
        .unwrap();
    assert!(
        !has_mismatch(&v),
        "filled credit must verify clean: {:?}",
        v
    );

    let lock = LedgerOperation::InvoiceLock {
        deposit_id: did,
        amount: 100_000,
        payment_id: [0xcd; 32],
        sequence_number: 2,
        nonce: 1,
        expiry: u32::MAX,
        timeout_height: None,
        fee: None,
        witness: Default::default(),
        commitment: None,
    };
    let filled_lock = funded.fill_balance_commitments(lock);
    match &filled_lock {
        LedgerOperation::InvoiceLock { commitment, .. } => assert_eq!(
            *commitment,
            Some(BalanceCommitment {
                balance_after: 500_000,
                locked_after: 100_000
            })
        ),
        _ => panic!("wrong op"),
    }
    let (_n, v2) = funded
        .apply_with_verifier(&filled_lock, &AllowAll, 0)
        .unwrap();
    assert!(
        !has_mismatch(&v2),
        "filled lock must verify clean: {:?}",
        v2
    );
}

#[test]
fn fill_satisfies_v4_requirement() {
    // On a balance-commit-v4 ledger, a filled op must NOT trip
    // MissingBalanceCommitment.
    let mut state = make_state();
    state.active_ruleset_name = "balance-commit-v4".to_string();
    let state = open_deposit(&state, "pk(aabbcc)");
    let did = compute_deposit_id("pk(aabbcc)");
    let filled = state.fill_balance_commitments(credit(did, 500_000, None));
    let (_n, v) = state.apply_with_verifier(&filled, &AllowAll, 0).unwrap();
    assert!(
        !has_missing(&v) && !has_mismatch(&v),
        "a filled op must satisfy balance-commit-v4 cleanly: {:?}",
        v
    );
}

#[test]
fn fill_leaves_non_balance_ops_untouched() {
    // DepositKeyRotate touches no (balance, locked) pair → returned unchanged.
    let state = open_deposit(&make_state(), "pk(aabbcc)");
    let did = compute_deposit_id("pk(aabbcc)");
    let rotate = LedgerOperation::DepositKeyRotate {
        deposit_id: did,
        new_descriptor: "pk(ddeeff)".to_string(),
        witness: Default::default(),
        nonce: 1,
        expiry: u32::MAX,
    };
    let out = state.fill_balance_commitments(rotate.clone());
    assert_eq!(
        out, rotate,
        "non-balance-touching ops are returned unchanged"
    );
}
