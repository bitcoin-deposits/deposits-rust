//! Tests for fee change validation with block notice and change limits.

use deposits_core::ledger::{Ledger, LedgerRole};
use deposits_core::messages::LedgerOperation;
use deposits_core::operation_validation::validate_deposit_fee_change;
use deposits_core::types::{compute_deposit_id, FeeStructure, LedgerState};

fn test_pubkey() -> bitcoin::secp256k1::PublicKey {
    use std::str::FromStr;
    bitcoin::secp256k1::PublicKey::from_str(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    )
    .unwrap()
}

fn make_ledger() -> Ledger {
    let state = LedgerState::new(test_pubkey(), "bcrt1qtest".to_string(), 0);
    Ledger {
        state,
        protocol: Default::default(),
        role: LedgerRole::Operator,
        history: Vec::new(),
    }
}

fn open_deposit_with_change_params(
    ledger: &mut Ledger,
    descriptor: &str,
    fees: FeeStructure,
    after_blocks: Option<u32>,
    notice_blocks: Option<u32>,
    limit_bps: Option<u16>,
    block_height: u32,
) -> [u8; 16] {
    let deposit_id = compute_deposit_id(descriptor);
    ledger
        .append_operation_with_block(
            LedgerOperation::DepositOpen {
                deposit_id,
                descriptor: descriptor.to_string(),
                fees: Some(fees),
                transfer_fees: None,
                payment_hash: None,
                invoice: None,
                cosigner_guarantee_signature: None,
                receive_requires_sig: false,
                fee_change_after_blocks: after_blocks,
                fee_change_notice_blocks: notice_blocks,
                fee_change_limit_bps: limit_bps,
            },
            block_height,
            [0u8; 32],
        )
        .unwrap();
    deposit_id
}

// =========================================================================
// No constraints: fee changes always allowed
// =========================================================================

#[test]
fn fee_change_no_constraints_passes() {
    let mut ledger = make_ledger();
    let did = open_deposit_with_change_params(
        &mut ledger,
        "pk(test1)",
        FeeStructure::new(1000, 100, 2016),
        None,
        None,
        None,
        100,
    );

    let new_fees = FeeStructure::new(5000, 500, 2016);
    // With current_block=0, skip timing checks (legacy)
    assert!(validate_deposit_fee_change(&ledger, &did, &new_fees, 0, 0).is_ok());
    // With real block, still passes since no constraints
    assert!(validate_deposit_fee_change(&ledger, &did, &new_fees, 200, 200).is_ok());
}

// =========================================================================
// fee_change_after_blocks
// =========================================================================

#[test]
fn fee_change_too_early_rejected() {
    let mut ledger = make_ledger();
    let did = open_deposit_with_change_params(
        &mut ledger,
        "pk(test2)",
        FeeStructure::new(1000, 100, 2016),
        Some(1000), // can't change until block 1100 (opened at 100)
        None,
        None,
        100,
    );

    let new_fees = FeeStructure::new(1100, 110, 2016);
    // At block 500: too early (need block 1100)
    let err = validate_deposit_fee_change(&ledger, &did, &new_fees, 600, 500).unwrap_err();
    assert!(err.contains("too early"), "{}", err);
}

#[test]
fn fee_change_after_waiting_period_passes() {
    let mut ledger = make_ledger();
    let did = open_deposit_with_change_params(
        &mut ledger,
        "pk(test3)",
        FeeStructure::new(1000, 100, 2016),
        Some(1000),
        None,
        None,
        100,
    );

    let new_fees = FeeStructure::new(1100, 110, 2016);
    // At block 1200: past block 1100, allowed
    assert!(validate_deposit_fee_change(&ledger, &did, &new_fees, 1300, 1200).is_ok());
}

// =========================================================================
// fee_change_notice_blocks
// =========================================================================

#[test]
fn fee_change_insufficient_notice_rejected() {
    let mut ledger = make_ledger();
    let did = open_deposit_with_change_params(
        &mut ledger,
        "pk(test4)",
        FeeStructure::new(1000, 100, 2016),
        None,
        Some(144), // 144 blocks notice required
        None,
        100,
    );

    let new_fees = FeeStructure::new(1100, 110, 2016);
    // current=500, effective=600: only 100 blocks notice, need 144
    let err = validate_deposit_fee_change(&ledger, &did, &new_fees, 600, 500).unwrap_err();
    assert!(err.contains("notice"), "{}", err);
}

#[test]
fn fee_change_sufficient_notice_passes() {
    let mut ledger = make_ledger();
    let did = open_deposit_with_change_params(
        &mut ledger,
        "pk(test5)",
        FeeStructure::new(1000, 100, 2016),
        None,
        Some(144),
        None,
        100,
    );

    let new_fees = FeeStructure::new(1100, 110, 2016);
    // current=500, effective=700: 200 blocks notice >= 144
    assert!(validate_deposit_fee_change(&ledger, &did, &new_fees, 700, 500).is_ok());
}

// =========================================================================
// fee_change_limit_bps (10% = 1000 bps)
// =========================================================================

#[test]
fn fee_change_within_limit_passes() {
    let mut ledger = make_ledger();
    let did = open_deposit_with_change_params(
        &mut ledger,
        "pk(test6)",
        FeeStructure::new(10000, 1000, 2016),
        None,
        None,
        Some(1000), // 10% limit
        100,
    );

    // 10% of 1000 bps = 100 bps change allowed
    let new_fees = FeeStructure::new(11000, 1100, 2016); // exactly 10% increase
    assert!(validate_deposit_fee_change(&ledger, &did, &new_fees, 200, 200).is_ok());
}

#[test]
fn fee_change_exceeding_bps_limit_rejected() {
    let mut ledger = make_ledger();
    let did = open_deposit_with_change_params(
        &mut ledger,
        "pk(test7)",
        FeeStructure::new(10000, 1000, 2016),
        None,
        None,
        Some(1000), // 10% limit
        100,
    );

    // 15% increase in bps: 1000 -> 1150 = 150 bps change, max is 100
    let new_fees = FeeStructure::new(10000, 1150, 2016);
    let err = validate_deposit_fee_change(&ledger, &did, &new_fees, 200, 200).unwrap_err();
    assert!(err.contains("rate change too large"), "{}", err);
}

#[test]
fn fee_change_exceeding_fixed_limit_rejected() {
    let mut ledger = make_ledger();
    let did = open_deposit_with_change_params(
        &mut ledger,
        "pk(test8)",
        FeeStructure::new(10000, 100, 2016),
        None,
        None,
        Some(1000), // 10% limit
        100,
    );

    // 15% increase in fixed: 10000 -> 11500 = 1500 change, max is 1000
    let new_fees = FeeStructure::new(11501, 100, 2016);
    let err = validate_deposit_fee_change(&ledger, &did, &new_fees, 200, 200).unwrap_err();
    assert!(err.contains("Fixed fee change too large"), "{}", err);
}

#[test]
fn fee_decrease_within_limit_passes() {
    let mut ledger = make_ledger();
    let did = open_deposit_with_change_params(
        &mut ledger,
        "pk(test9)",
        FeeStructure::new(10000, 1000, 2016),
        None,
        None,
        Some(1000), // 10% limit
        100,
    );

    // 10% decrease
    let new_fees = FeeStructure::new(9000, 900, 2016);
    assert!(validate_deposit_fee_change(&ledger, &did, &new_fees, 200, 200).is_ok());
}

// =========================================================================
// Combined constraints
// =========================================================================

#[test]
fn all_constraints_satisfied_passes() {
    let mut ledger = make_ledger();
    let did = open_deposit_with_change_params(
        &mut ledger,
        "pk(test10)",
        FeeStructure::new(10000, 1000, 2016),
        Some(1000), // can't change until block 1100
        Some(144),  // 144 blocks notice
        Some(1000), // 10% limit
        100,
    );

    // At block 1200 (past 1100), effective at 1400 (200 blocks > 144), 5% change
    let new_fees = FeeStructure::new(10500, 1050, 2016);
    assert!(validate_deposit_fee_change(&ledger, &did, &new_fees, 1400, 1200).is_ok());
}

#[test]
fn all_constraints_first_failure_reported() {
    let mut ledger = make_ledger();
    let did = open_deposit_with_change_params(
        &mut ledger,
        "pk(test11)",
        FeeStructure::new(10000, 1000, 2016),
        Some(1000),
        Some(144),
        Some(1000),
        100,
    );

    // Too early AND too large — should fail on "too early" first
    let new_fees = FeeStructure::new(20000, 2000, 2016);
    let err = validate_deposit_fee_change(&ledger, &did, &new_fees, 300, 200).unwrap_err();
    assert!(err.contains("too early"), "{}", err);
}

// =========================================================================
// State machine: FeeChange stored as pending, applied at FeeCollect
// =========================================================================

#[test]
fn deposit_update_creates_pending_fee_change() {
    let mut ledger = make_ledger();
    let did = open_deposit_with_change_params(
        &mut ledger,
        "pk(test12)",
        FeeStructure::new(1000, 100, 2016),
        None,
        None,
        None,
        100,
    );

    // Apply FeeChange
    ledger
        .apply_state_changes(&LedgerOperation::FeeChange {
            deposit_id: did,
            new_fees: FeeStructure::new(2000, 200, 2016),
            effective_block: 500,
        })
        .unwrap();

    let deposit = ledger.state.deposits.get(&did).unwrap();
    // Current fees unchanged
    assert_eq!(deposit.fees.annualized_bps, 100);
    // Pending change stored
    assert!(deposit.pending_fee_change.is_some());
    let (pending_fees, effective) = deposit.pending_fee_change.as_ref().unwrap();
    assert_eq!(pending_fees.annualized_bps, 200);
    assert_eq!(*effective, 500);
}

#[test]
fn fee_collect_applies_pending_change_at_effective_block() {
    let mut ledger = make_ledger();
    let did = open_deposit_with_change_params(
        &mut ledger,
        "pk(test13)",
        FeeStructure::new(1000, 100, 2016),
        None,
        None,
        None,
        100,
    );

    // Credit some balance
    ledger
        .apply_state_changes(&LedgerOperation::InvoiceCredit {
            payment_hash: [0xaa; 32],
            deposit_id: did,
            amount: 1_000_000,
            invoice_id: "fund".to_string(),
            sequence_number: 1,
        })
        .unwrap();

    // Schedule fee change for block 500
    ledger
        .apply_state_changes(&LedgerOperation::FeeChange {
            deposit_id: did,
            new_fees: FeeStructure::new(2000, 200, 2016),
            effective_block: 500,
        })
        .unwrap();

    // FeeCollect before effective block: old fees still apply
    ledger
        .apply_state_changes(&LedgerOperation::FeeCollect {
            deposit_id: did,
            amount: 10,
            block_height: 400,
        })
        .unwrap();
    let deposit = ledger.state.deposits.get(&did).unwrap();
    assert_eq!(deposit.fees.annualized_bps, 100); // still old
    assert!(deposit.pending_fee_change.is_some()); // still pending

    // FeeCollect at effective block: new fees applied
    ledger
        .apply_state_changes(&LedgerOperation::FeeCollect {
            deposit_id: did,
            amount: 10,
            block_height: 500,
        })
        .unwrap();
    let deposit = ledger.state.deposits.get(&did).unwrap();
    assert_eq!(deposit.fees.annualized_bps, 200); // new!
    assert_eq!(deposit.fees.annualized_msats, 2000);
    assert!(deposit.pending_fee_change.is_none()); // consumed
}

// =========================================================================
// append_operation_with_block enforces constraints
// =========================================================================

#[test]
fn append_fee_change_too_early_rejected() {
    let mut ledger = make_ledger();
    let did = open_deposit_with_change_params(
        &mut ledger,
        "pk(test14)",
        FeeStructure::new(1000, 100, 2016),
        Some(1000), // can't change until block 1100
        None,
        None,
        100,
    );

    // Try to append at block 500 — too early
    let result = ledger.append_operation_with_block(
        LedgerOperation::FeeChange {
            deposit_id: did,
            new_fees: FeeStructure::new(1100, 110, 2016),
            effective_block: 600,
        },
        500,
        [0u8; 32],
    );
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("too early") || err.contains("fee_change"),
        "{}",
        err
    );
}

#[test]
fn append_fee_change_exceeding_limit_rejected() {
    let mut ledger = make_ledger();
    let did = open_deposit_with_change_params(
        &mut ledger,
        "pk(test15)",
        FeeStructure::new(10000, 1000, 2016),
        None,
        None,
        Some(1000), // 10% limit
        100,
    );

    // Try 50% increase
    let result = ledger.append_operation_with_block(
        LedgerOperation::FeeChange {
            deposit_id: did,
            new_fees: FeeStructure::new(15000, 1500, 2016),
            effective_block: 300,
        },
        200,
        [0u8; 32],
    );
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("change too large") || err.contains("fee_change"),
        "{}",
        err
    );
}

// =========================================================================
// Edge cases
// =========================================================================

#[test]
fn fee_change_from_zero_fees_allowed() {
    let mut ledger = make_ledger();
    let did = open_deposit_with_change_params(
        &mut ledger,
        "pk(zero_fees)",
        FeeStructure::new(0, 0, 2016), // start at zero
        None,
        None,
        Some(1000), // 10% limit — but 10% of zero is zero, needs special handling
        100,
    );

    // Setting fees from zero should be allowed (limit_bps acts as absolute max when current is zero)
    let new_fees = FeeStructure::new(500, 500, 2016);
    assert!(validate_deposit_fee_change(&ledger, &did, &new_fees, 200, 200).is_ok());
}

#[test]
fn fee_change_to_zero_within_limit() {
    let mut ledger = make_ledger();
    let did = open_deposit_with_change_params(
        &mut ledger,
        "pk(to_zero)",
        FeeStructure::new(100, 100, 2016),
        None,
        None,
        Some(10000), // 100% limit — allows going to zero
        100,
    );

    let new_fees = FeeStructure::new(0, 0, 2016);
    assert!(validate_deposit_fee_change(&ledger, &did, &new_fees, 200, 200).is_ok());
}

#[test]
fn fee_change_frequency_not_constrained_by_limit() {
    let mut ledger = make_ledger();
    let did = open_deposit_with_change_params(
        &mut ledger,
        "pk(freq_change)",
        FeeStructure::new(1000, 100, 2016),
        None,
        None,
        Some(1000), // 10% limit on bps/fixed
        100,
    );

    // Changing only frequency (not bps or fixed) should pass
    let new_fees = FeeStructure::new(1000, 100, 4032); // doubled period
    assert!(validate_deposit_fee_change(&ledger, &did, &new_fees, 200, 200).is_ok());
}

#[test]
fn opened_at_block_recorded_correctly() {
    let mut ledger = make_ledger();
    let did = open_deposit_with_change_params(
        &mut ledger,
        "pk(block_track)",
        FeeStructure::new(1000, 100, 2016),
        Some(500),
        None,
        None,
        750, // opened at block 750
    );

    let deposit = ledger.state.deposits.get(&did).unwrap();
    assert_eq!(deposit.opened_at_block, 750);
    assert_eq!(deposit.fee_change_after_blocks, Some(500));
}

#[test]
fn pending_fee_change_survives_multiple_fee_collects_before_effective() {
    let mut ledger = make_ledger();
    let did = open_deposit_with_change_params(
        &mut ledger,
        "pk(multi_collect)",
        FeeStructure::new(1000, 100, 2016),
        None,
        None,
        None,
        100,
    );

    // Credit balance
    ledger
        .apply_state_changes(&LedgerOperation::InvoiceCredit {
            payment_hash: [0xaa; 32],
            deposit_id: did,
            amount: 1_000_000,
            invoice_id: "fund".to_string(),
            sequence_number: 1,
        })
        .unwrap();

    // Schedule change for block 500
    ledger
        .apply_state_changes(&LedgerOperation::FeeChange {
            deposit_id: did,
            new_fees: FeeStructure::new(2000, 200, 2016),
            effective_block: 500,
        })
        .unwrap();

    // Multiple fee collects before effective block
    for block in [300, 350, 400, 450] {
        ledger
            .apply_state_changes(&LedgerOperation::FeeCollect {
                deposit_id: did,
                amount: 1,
                block_height: block,
            })
            .unwrap();
        let d = ledger.state.deposits.get(&did).unwrap();
        assert_eq!(
            d.fees.annualized_bps, 100,
            "should still be old fees at block {}",
            block
        );
        assert!(
            d.pending_fee_change.is_some(),
            "pending should survive at block {}",
            block
        );
    }

    // Finally at block 500
    ledger
        .apply_state_changes(&LedgerOperation::FeeCollect {
            deposit_id: did,
            amount: 1,
            block_height: 500,
        })
        .unwrap();
    let d = ledger.state.deposits.get(&did).unwrap();
    assert_eq!(
        d.fees.annualized_bps, 200,
        "new fees should apply at effective block"
    );
    assert!(d.pending_fee_change.is_none());
}

#[test]
fn second_fee_change_replaces_pending() {
    let mut ledger = make_ledger();
    let did = open_deposit_with_change_params(
        &mut ledger,
        "pk(replace)",
        FeeStructure::new(1000, 100, 2016),
        None,
        None,
        None,
        100,
    );

    // First change
    ledger
        .apply_state_changes(&LedgerOperation::FeeChange {
            deposit_id: did,
            new_fees: FeeStructure::new(2000, 200, 2016),
            effective_block: 500,
        })
        .unwrap();

    // Second change replaces the first
    ledger
        .apply_state_changes(&LedgerOperation::FeeChange {
            deposit_id: did,
            new_fees: FeeStructure::new(3000, 300, 2016),
            effective_block: 600,
        })
        .unwrap();

    let d = ledger.state.deposits.get(&did).unwrap();
    let (pending_fees, effective) = d.pending_fee_change.as_ref().unwrap();
    assert_eq!(pending_fees.annualized_bps, 300);
    assert_eq!(*effective, 600);
}
