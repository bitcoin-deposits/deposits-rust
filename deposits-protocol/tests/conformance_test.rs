//! Tests for LedgerState conformance tracking.
//!
//! Verifies that apply_with_verifier detects violations (reserve backing,
//! witness verification) and that check_and_apply refuses non-conforming state.

use deposits_protocol::messages::LedgerOperation;
use deposits_protocol::types::{
    compute_deposit_id, ConformanceViolation, FeeStructure, LedgerState, NoVerify,
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
    // Set reserves to 1 BTC (100_000_000 msats in protocol terms, but reserves_amount is sats)
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
        })
        .unwrap()
}

// ==========================================================================
// Reserve sufficiency
// ==========================================================================

#[test]
fn credit_within_reserves_is_conforming() {
    let state = make_state();
    let state = open_deposit(&state, "pk(aabbcc)");
    let deposit_id = compute_deposit_id("pk(aabbcc)");

    let (next, violations) = state
        .apply_with_verifier(
            &LedgerOperation::InvoiceCredit {
                payment_hash: [0xaa; 32],
                deposit_id,
                amount: 500_000, // half of reserves
                invoice_id: "test".to_string(),
                sequence_number: 1,
            },
            &NoVerify,
        )
        .unwrap();

    assert!(
        violations.is_empty(),
        "should be conforming: {:?}",
        violations
    );
    assert_eq!(next.deposits.get(&deposit_id).unwrap().balance, 500_000);
}

#[test]
fn credit_exceeding_reserves_is_non_conforming() {
    let state = make_state();
    let state = open_deposit(&state, "pk(aabbcc)");
    let deposit_id = compute_deposit_id("pk(aabbcc)");

    let (next, violations) = state
        .apply_with_verifier(
            &LedgerOperation::InvoiceCredit {
                payment_hash: [0xaa; 32],
                deposit_id,
                amount: 2_000_000, // double the reserves
                invoice_id: "test".to_string(),
                sequence_number: 1,
            },
            &NoVerify,
        )
        .unwrap();

    assert_eq!(violations.len(), 1);
    assert!(matches!(
        &violations[0],
        ConformanceViolation::InsufficientReserves {
            reserves: 1_000_000,
            obligations: 2_000_000
        }
    ));
    // State was still applied (for watchers)
    assert_eq!(next.deposits.get(&deposit_id).unwrap().balance, 2_000_000);
}

#[test]
fn check_and_apply_refuses_non_conforming() {
    let state = make_state();
    let state = open_deposit(&state, "pk(aabbcc)");
    let deposit_id = compute_deposit_id("pk(aabbcc)");

    let result = state.check_and_apply(
        &LedgerOperation::InvoiceCredit {
            payment_hash: [0xaa; 32],
            deposit_id,
            amount: 2_000_000, // exceeds reserves
            invoice_id: "test".to_string(),
            sequence_number: 1,
        },
        &NoVerify,
    );

    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("conformance"),
        "error should mention conformance: {}",
        err
    );
}

#[test]
fn onchain_credit_exceeding_reserves_is_non_conforming() {
    let state = make_state();
    let state = open_deposit(&state, "pk(aabbcc)");
    let deposit_id = compute_deposit_id("pk(aabbcc)");

    let (_next, violations) = state
        .apply_with_verifier(
            &LedgerOperation::OnchainCredit {
                txid: [0x11; 32],
                vout: 0,
                deposit_id,
                amount: 5_000_000,
                funding_address: "bcrt1qfund".to_string(),
            },
            &NoVerify,
        )
        .unwrap();

    assert_eq!(violations.len(), 1);
    assert!(matches!(
        &violations[0],
        ConformanceViolation::InsufficientReserves { .. }
    ));
}

#[test]
fn multiple_credits_accumulate_correctly() {
    let state = make_state();
    let state = open_deposit(&state, "pk(aabbcc)");
    let deposit_id = compute_deposit_id("pk(aabbcc)");

    // First credit: 600k (within 1M reserves)
    let (state, violations) = state
        .apply_with_verifier(
            &LedgerOperation::InvoiceCredit {
                payment_hash: [0x01; 32],
                deposit_id,
                amount: 600_000,
                invoice_id: "inv1".to_string(),
                sequence_number: 1,
            },
            &NoVerify,
        )
        .unwrap();
    assert!(violations.is_empty());

    // Second credit: 600k (total 1.2M > 1M reserves)
    let (_state, violations) = state
        .apply_with_verifier(
            &LedgerOperation::InvoiceCredit {
                payment_hash: [0x02; 32],
                deposit_id,
                amount: 600_000,
                invoice_id: "inv2".to_string(),
                sequence_number: 2,
            },
            &NoVerify,
        )
        .unwrap();
    assert_eq!(violations.len(), 1);
    assert!(matches!(
        &violations[0],
        ConformanceViolation::InsufficientReserves {
            reserves: 1_000_000,
            obligations: 1_200_000,
        }
    ));
}

// ==========================================================================
// Operations that don't affect reserves are always conforming
// ==========================================================================

#[test]
fn deposit_open_is_conforming() {
    let state = make_state();
    let deposit_id = compute_deposit_id("pk(newdeposit)");

    let (_next, violations) = state
        .apply_with_verifier(
            &LedgerOperation::DepositOpen {
                deposit_id,
                descriptor: "pk(newdeposit)".to_string(),
                fees: Some(FeeStructure::default()),
                transfer_fees: None,
                payment_hash: None,
                invoice: None,
                cosigner_guarantee_signature: None,

                receive_requires_sig: false,
                fee_change_after_blocks: None,
                fee_change_notice_blocks: None,
                fee_change_limit_bps: None,
            },
            &NoVerify,
        )
        .unwrap();

    assert!(violations.is_empty());
}

#[test]
fn fee_collect_is_conforming() {
    let state = make_state();
    let state = open_deposit(&state, "pk(aabbcc)");
    let deposit_id = compute_deposit_id("pk(aabbcc)");

    // Credit some balance first
    let state = state
        .apply(&LedgerOperation::InvoiceCredit {
            payment_hash: [0xaa; 32],
            deposit_id,
            amount: 100_000,
            invoice_id: "test".to_string(),
            sequence_number: 1,
        })
        .unwrap();

    let (_next, violations) = state
        .apply_with_verifier(
            &LedgerOperation::FeeCollect {
                deposit_id,
                amount: 1_000,
                block_height: 100,
            },
            &NoVerify,
        )
        .unwrap();

    assert!(violations.is_empty());
}
