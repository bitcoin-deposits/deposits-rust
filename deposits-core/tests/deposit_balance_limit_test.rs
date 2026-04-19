//! Tests for per-deposit balance limits.
//!
//! MAX_DEPOSIT_BALANCE_MSATS caps the balance of any single deposit.
//! Enforced at make_offer, make_invoice, and transfer_lock.

use deposits_core::ledger::{Ledger, LedgerRole};
use deposits_core::messages::LedgerOperation;
use deposits_core::types::{compute_deposit_id, FeeStructure, LedgerState};

fn test_pubkey() -> bitcoin::secp256k1::PublicKey {
    use std::str::FromStr;
    bitcoin::secp256k1::PublicKey::from_str(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    )
    .unwrap()
}

fn make_ledger() -> Ledger {
    let mut state = LedgerState::new(test_pubkey(), "bcrt1qtest".to_string(), 0);
    state.reserves_amount = 100_000_000_000; // 100M msats = 100k sats
    Ledger {
        state,
        protocol: Default::default(),
        role: LedgerRole::Operator,
        history: Vec::new(),
    }
}

fn open_deposit(ledger: &mut Ledger, descriptor: &str) -> [u8; 16] {
    let deposit_id = compute_deposit_id(descriptor);
    ledger
        .apply_state_changes(&LedgerOperation::DepositOpen {
            deposit_id,
            descriptor: descriptor.to_string(),
            fees: Some(FeeStructure::default()),
            transfer_fees: None,
            payment_hash: None,
            invoice: None,
            cosigner_guarantee_signature: None,
            receive_requires_sig: false,
            fee_change_after_blocks: None,
            fee_change_notice_blocks: None,
            fee_change_limit_bps: None,
        })
        .unwrap();
    deposit_id
}

fn credit_deposit(ledger: &mut Ledger, deposit_id: [u8; 16], amount_msats: u64) {
    ledger
        .apply_state_changes(&LedgerOperation::InvoiceCredit {
            deposit_id,
            amount: amount_msats,
            payment_hash: [0u8; 32],
            invoice_id: "test".to_string(),
            sequence_number: ledger.state.sequence + 1,
        })
        .unwrap();
}

/// Simulates the check_deposit_balance_limit logic from Node.
/// Returns Some(error) if limit exceeded, None if ok.
fn check_limit(
    ledger: &Ledger,
    deposit_id: &[u8; 16],
    additional_msats: u64,
    limit_msats: u64,
) -> Option<String> {
    if limit_msats == 0 {
        return None;
    }
    let current = ledger
        .state
        .deposits
        .get(deposit_id)
        .map(|d| d.balance + d.locked_balance)
        .unwrap_or(0);
    let new_balance = current.saturating_add(additional_msats);
    if new_balance > limit_msats {
        Some(format!(
            "Would exceed deposit balance limit: {} + {} = {} msats > {} msats",
            current, additional_msats, new_balance, limit_msats
        ))
    } else {
        None
    }
}

// -- Tests --

#[test]
fn zero_limit_allows_anything() {
    let mut ledger = make_ledger();
    let did = open_deposit(&mut ledger, "pk(alice)");
    credit_deposit(&mut ledger, did, 50_000_000_000); // 50k sats

    assert!(check_limit(&ledger, &did, 999_999_999_999, 0).is_none());
}

#[test]
fn under_limit_allowed() {
    let mut ledger = make_ledger();
    let did = open_deposit(&mut ledger, "pk(alice)");

    let limit = 10_000_000; // 10k sats in msats
    assert!(check_limit(&ledger, &did, 5_000_000, limit).is_none());
}

#[test]
fn at_limit_allowed() {
    let mut ledger = make_ledger();
    let did = open_deposit(&mut ledger, "pk(alice)");

    let limit = 10_000_000;
    assert!(check_limit(&ledger, &did, 10_000_000, limit).is_none());
}

#[test]
fn over_limit_rejected() {
    let mut ledger = make_ledger();
    let did = open_deposit(&mut ledger, "pk(alice)");

    let limit = 10_000_000;
    let err = check_limit(&ledger, &did, 10_000_001, limit);
    assert!(err.is_some());
    assert!(err.unwrap().contains("Would exceed deposit balance limit"));
}

#[test]
fn existing_balance_counted() {
    let mut ledger = make_ledger();
    let did = open_deposit(&mut ledger, "pk(alice)");
    credit_deposit(&mut ledger, did, 7_000_000); // 7k sats

    let limit = 10_000_000; // 10k sats
                            // 7k + 4k = 11k > 10k limit
    assert!(check_limit(&ledger, &did, 4_000_000, limit).is_some());
    // 7k + 3k = 10k = limit, ok
    assert!(check_limit(&ledger, &did, 3_000_000, limit).is_none());
}

#[test]
fn different_deposits_independent() {
    let mut ledger = make_ledger();
    let did1 = open_deposit(&mut ledger, "pk(alice)");
    let did2 = open_deposit(&mut ledger, "pk(bob)");
    credit_deposit(&mut ledger, did1, 9_000_000); // alice at 9k

    let limit = 10_000_000;
    // alice can only add 1k more
    assert!(check_limit(&ledger, &did1, 2_000_000, limit).is_some());
    // bob is at 0, can add up to 10k
    assert!(check_limit(&ledger, &did2, 10_000_000, limit).is_none());
}

#[test]
fn nonexistent_deposit_checked_from_zero() {
    let ledger = make_ledger();
    let fake_id = [0xAB; 16];

    let limit = 5_000_000;
    assert!(check_limit(&ledger, &fake_id, 5_000_000, limit).is_none());
    assert!(check_limit(&ledger, &fake_id, 5_000_001, limit).is_some());
}

#[test]
fn limit_message_includes_amounts() {
    let mut ledger = make_ledger();
    let did = open_deposit(&mut ledger, "pk(alice)");
    credit_deposit(&mut ledger, did, 8_000_000);

    let err = check_limit(&ledger, &did, 5_000_000, 10_000_000).unwrap();
    assert!(err.contains("8000000"), "should contain current balance");
    assert!(err.contains("5000000"), "should contain additional amount");
    assert!(err.contains("13000000"), "should contain new total");
    assert!(err.contains("10000000"), "should contain limit");
}
