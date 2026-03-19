//! Tests for is_collateral flag on DepositOpen and CollateralLock validation

use deposits_core::ledger::{Ledger, LedgerRole};
use deposits_core::messages::LedgerOperation;
use deposits_core::types::{FeeStructure, LedgerState, DescriptorWitness, compute_deposit_id};

fn test_pubkey() -> bitcoin::secp256k1::PublicKey {
    use std::str::FromStr;
    bitcoin::secp256k1::PublicKey::from_str(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    ).unwrap()
}

fn make_ledger() -> Ledger {
    let state = LedgerState::new(test_pubkey(), "bcrt1qtest".to_string(), 0);
    Ledger { state, role: LedgerRole::Operator, history: Vec::new() }
}

fn open_deposit(ledger: &mut Ledger, descriptor: &str, is_collateral: bool) -> [u8; 16] {
    let deposit_id = compute_deposit_id(descriptor);
    ledger.apply_state_changes(&LedgerOperation::DepositOpen {
        deposit_id,
        descriptor: descriptor.to_string(),
        fees: Some(FeeStructure::default()),
        transfer_fees: None,
        payment_hash: None,
        invoice: None,
        cosigner_guarantee_signature: None,
        is_collateral,
        receive_requires_sig: false,
        fee_change_after_blocks: None,
        fee_change_notice_blocks: None,
        fee_change_limit_bps: None,
    }).unwrap();
    deposit_id
}

#[test]
fn collateral_deposit_flag_is_set() {
    let mut ledger = make_ledger();
    let did = open_deposit(&mut ledger, "pk(collateral_key)", true);
    let deposit = ledger.state.deposits.get(&did).unwrap();
    assert!(deposit.is_collateral, "deposit should be marked as collateral");
}

#[test]
fn regular_deposit_flag_is_not_set() {
    let mut ledger = make_ledger();
    let did = open_deposit(&mut ledger, "pk(regular_key)", false);
    let deposit = ledger.state.deposits.get(&did).unwrap();
    assert!(!deposit.is_collateral, "deposit should not be collateral");
}

#[test]
fn collateral_lock_on_collateral_deposit_succeeds() {
    let mut ledger = make_ledger();
    let did = open_deposit(&mut ledger, "pk(collateral_key)", true);

    // Credit some balance first
    ledger.apply_state_changes(&LedgerOperation::InvoiceCredit {
        payment_hash: [0xaa; 32],
        deposit_id: did,
        amount: 1_000_000,
        invoice_id: "test".to_string(),
        sequence_number: 1,
    }).unwrap();

    // CollateralLock should succeed on collateral deposit
    let result = ledger.apply_state_changes(&LedgerOperation::CollateralLock {
        deposit_id: did,
        amount: 500_000,
        lock_until_block: 1000,
        operator_id: test_pubkey(),
        witness: DescriptorWitness { stack: vec![vec![0x30; 64]] },
    });
    assert!(result.is_ok(), "CollateralLock should succeed on collateral deposit");

    let deposit = ledger.state.deposits.get(&did).unwrap();
    assert_eq!(deposit.collateral_lock_amount, 500_000);
    assert_eq!(deposit.collateral_lock_expires, 1000);
}

#[test]
fn collateral_lock_on_regular_deposit_fails() {
    let mut ledger = make_ledger();
    let did = open_deposit(&mut ledger, "pk(regular_key)", false);

    // Credit some balance
    ledger.apply_state_changes(&LedgerOperation::InvoiceCredit {
        payment_hash: [0xbb; 32],
        deposit_id: did,
        amount: 1_000_000,
        invoice_id: "test".to_string(),
        sequence_number: 1,
    }).unwrap();

    // CollateralLock should fail on regular deposit
    let result = ledger.apply_state_changes(&LedgerOperation::CollateralLock {
        deposit_id: did,
        amount: 500_000,
        lock_until_block: 1000,
        operator_id: test_pubkey(),
        witness: DescriptorWitness { stack: vec![vec![0x30; 64]] },
    });
    assert!(result.is_err(), "CollateralLock should fail on regular deposit");
    let err = result.unwrap_err().to_string();
    assert!(err.contains("collateral"), "error should mention collateral: {}", err);
}

#[test]
fn collateral_and_regular_deposits_coexist() {
    let mut ledger = make_ledger();
    let regular_did = open_deposit(&mut ledger, "pk(regular)", false);
    let collateral_did = open_deposit(&mut ledger, "pk(collateral)", true);

    assert_eq!(ledger.state.deposits.len(), 2);
    assert!(!ledger.state.deposits.get(&regular_did).unwrap().is_collateral);
    assert!(ledger.state.deposits.get(&collateral_did).unwrap().is_collateral);
}
