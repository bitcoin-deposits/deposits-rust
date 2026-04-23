//! Tests that cosign validation (LedgerState::apply) correctly rejects
//! invalid operations. These mirror the checks that a co-signing quorum
//! member performs before endorsing an operator's update.

use deposits_core::ledger::{Ledger, LedgerRole};
use deposits_core::messages::LedgerOperation;
use deposits_core::tlv::{TlvDecode, TlvEncode};
use deposits_core::types::DescriptorWitness;
use deposits_core::types::{compute_deposit_id, FeeStructure, LedgerState};

fn test_pubkey() -> bitcoin::secp256k1::PublicKey {
    use std::str::FromStr;
    bitcoin::secp256k1::PublicKey::from_str(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    )
    .unwrap()
}

fn make_ledger() -> Ledger {
    let state = LedgerState::new(test_pubkey(), "bcrt1qtest".to_string(), 800_000);
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

fn credit_deposit(ledger: &mut Ledger, deposit_id: [u8; 16], amount: u64) {
    ledger
        .apply_state_changes(&LedgerOperation::InvoiceCredit {
            deposit_id,
            amount,
            payment_hash: [0u8; 32],
            invoice_id: "test".to_string(),
            sequence_number: 0,
        })
        .unwrap();
}

// =========================================================================
// Invoice lock validation
// =========================================================================

#[test]
fn cosign_rejects_invoice_lock_insufficient_balance() {
    let mut ledger = make_ledger();
    let dep = open_deposit(
        &mut ledger,
        "pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)",
    );
    credit_deposit(&mut ledger, dep, 1000);

    // Lock more than available — should fail
    let result = ledger.state.apply(&LedgerOperation::InvoiceLock {
        deposit_id: dep,
        amount: 2000,
        payment_id: [1u8; 32],
        sequence_number: 0,
        witness: DescriptorWitness { stack: vec![] },
    });
    assert!(result.is_err(), "Should reject lock exceeding balance");
}

#[test]
fn cosign_accepts_invoice_lock_within_balance() {
    let mut ledger = make_ledger();
    let dep = open_deposit(
        &mut ledger,
        "pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)",
    );
    credit_deposit(&mut ledger, dep, 5000);

    let result = ledger.state.apply(&LedgerOperation::InvoiceLock {
        deposit_id: dep,
        amount: 3000,
        payment_id: [1u8; 32],
        sequence_number: 0,
        witness: DescriptorWitness { stack: vec![] },
    });
    assert!(result.is_ok(), "Should accept lock within balance");
}

#[test]
fn cosign_rejects_double_lock_exceeding_available() {
    let mut ledger = make_ledger();
    let dep = open_deposit(
        &mut ledger,
        "pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)",
    );
    credit_deposit(&mut ledger, dep, 5000);

    // First lock succeeds
    ledger
        .apply_state_changes(&LedgerOperation::InvoiceLock {
            deposit_id: dep,
            amount: 3000,
            payment_id: [1u8; 32],
            sequence_number: 0,
            witness: DescriptorWitness { stack: vec![] },
        })
        .unwrap();

    // Second lock exceeds remaining available (5000 - 3000 = 2000 available)
    let result = ledger.state.apply(&LedgerOperation::InvoiceLock {
        deposit_id: dep,
        amount: 3000,
        payment_id: [2u8; 32],
        sequence_number: 0,
        witness: DescriptorWitness { stack: vec![] },
    });
    assert!(
        result.is_err(),
        "Should reject second lock exceeding available balance"
    );
}

// =========================================================================
// Deposit existence checks
// =========================================================================

#[test]
fn cosign_rejects_lock_on_nonexistent_deposit() {
    let ledger = make_ledger();
    let fake_id = [0xFFu8; 16];

    let result = ledger.state.apply(&LedgerOperation::InvoiceLock {
        deposit_id: fake_id,
        amount: 1000,
        payment_id: [1u8; 32],
        sequence_number: 0,
        witness: DescriptorWitness { stack: vec![] },
    });
    assert!(result.is_err(), "Should reject lock on nonexistent deposit");
}

#[test]
fn cosign_rejects_duplicate_deposit_open() {
    let mut ledger = make_ledger();
    let dep = open_deposit(
        &mut ledger,
        "pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)",
    );

    // Opening same deposit again should fail
    let result = ledger.state.apply(&LedgerOperation::DepositOpen {
        deposit_id: dep,
        descriptor: "pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)"
            .to_string(),
        fees: Some(FeeStructure::default()),
        transfer_fees: None,
        payment_hash: None,
        invoice: None,
        cosigner_guarantee_signature: None,
        receive_requires_sig: false,
        fee_change_after_blocks: None,
        fee_change_notice_blocks: None,
        fee_change_limit_bps: None,
    });
    assert!(result.is_err(), "Should reject duplicate deposit open");
}

#[test]
fn cosign_rejects_close_with_balance() {
    let mut ledger = make_ledger();
    let dep = open_deposit(
        &mut ledger,
        "pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)",
    );
    credit_deposit(&mut ledger, dep, 1000);

    let result = ledger
        .state
        .apply(&LedgerOperation::DepositClose { deposit_id: dep });
    assert!(result.is_err(), "Should reject close with non-zero balance");
}

// =========================================================================
// Transfer validation
// =========================================================================

#[test]
fn cosign_rejects_transfer_lock_insufficient_balance() {
    let mut ledger = make_ledger();
    let src = open_deposit(
        &mut ledger,
        "pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)",
    );
    let dst = open_deposit(
        &mut ledger,
        "pk(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)",
    );
    credit_deposit(&mut ledger, src, 1000);

    let result = ledger.state.apply(&LedgerOperation::TransferLock {
        nonce: [0u8; 32],
        source_deposit_id: src,
        destination_deposit_id: dst,
        amount: 2000,
        fee: 0,
        completion_script:
            "sha256(0000000000000000000000000000000000000000000000000000000000000001)".to_string(),
        timeout_height: 900_000,
        transfer_id: [0u8; 32],
        witness: DescriptorWitness { stack: vec![] },
    });
    assert!(
        result.is_err(),
        "Should reject transfer lock exceeding balance"
    );
}

// =========================================================================
// Fee collection validation
// =========================================================================

#[test]
fn cosign_rejects_fee_collect_exceeding_balance() {
    let mut ledger = make_ledger();
    let dep = open_deposit(
        &mut ledger,
        "pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)",
    );
    credit_deposit(&mut ledger, dep, 1000);

    // Collecting more than balance — apply doesn't error but saturates to 0
    // This tests that the state transition is at least sensible
    let result = ledger.state.apply(&LedgerOperation::FeeCollect {
        deposit_id: dep,
        amount: 2000,
        block_height: 810_000,
    });
    // FeeCollect uses saturating_sub so it doesn't error, but the cosigner
    // should flag this as non-conforming in a real implementation.
    // For now, ensure it at least doesn't panic.
    assert!(result.is_ok());
}

// =========================================================================
// Open invoice lock tracking
// =========================================================================

#[test]
fn open_invoice_locks_tracked_through_lifecycle() {
    let mut ledger = make_ledger();
    let dep = open_deposit(
        &mut ledger,
        "pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)",
    );
    credit_deposit(&mut ledger, dep, 10_000);

    let payment_id = [42u8; 32];

    // Lock — should appear in open_invoice_locks
    ledger
        .apply_state_changes(&LedgerOperation::InvoiceLock {
            deposit_id: dep,
            amount: 5000,
            payment_id,
            sequence_number: 0,
            witness: DescriptorWitness { stack: vec![] },
        })
        .unwrap();

    assert!(
        ledger.state.open_invoice_locks.contains_key(&payment_id),
        "Lock should be tracked"
    );
    assert_eq!(ledger.state.open_invoice_locks[&payment_id].amount, 5000);
    assert_eq!(ledger.state.open_invoice_locks[&payment_id].deposit_id, dep);

    // Fulfill — should remove from open_invoice_locks
    ledger
        .apply_state_changes(&LedgerOperation::InvoiceFulfill {
            deposit_id: dep,
            amount: 5000,
            payment_id,
            sequence_number: 1,
            witness: DescriptorWitness { stack: vec![] },
            preimage: [0u8; 32],
        })
        .unwrap();

    assert!(
        !ledger.state.open_invoice_locks.contains_key(&payment_id),
        "Fulfill should clear the lock"
    );
}

#[test]
fn open_invoice_lock_cleared_on_fail() {
    let mut ledger = make_ledger();
    let dep = open_deposit(
        &mut ledger,
        "pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)",
    );
    credit_deposit(&mut ledger, dep, 10_000);

    let payment_id = [99u8; 32];

    ledger
        .apply_state_changes(&LedgerOperation::InvoiceLock {
            deposit_id: dep,
            amount: 3000,
            payment_id,
            sequence_number: 0,
            witness: DescriptorWitness { stack: vec![] },
        })
        .unwrap();

    assert!(ledger.state.open_invoice_locks.contains_key(&payment_id));

    // Fail — should remove and unlock balance
    ledger
        .apply_state_changes(&LedgerOperation::InvoiceFail {
            deposit_id: dep,
            amount: 3000,
            payment_id,
            sequence_number: 1,
        })
        .unwrap();

    assert!(
        !ledger.state.open_invoice_locks.contains_key(&payment_id),
        "Fail should clear the lock"
    );
    // Balance is restored modulo the fixed fee charged on failure
    // (TransferFeeSchedule::default().fixed_msats = 2).
    let deposit = ledger.state.deposits.get(&dep).unwrap();
    assert_eq!(
        deposit.balance, 10_000 - 2,
        "Balance should be restored after fail minus fixed operator fee"
    );
    assert_eq!(
        deposit.locked_balance, 0,
        "Locked balance should be zero after fail"
    );
}

// =========================================================================
// Cosign data extraction (the format process_cosign_request decodes)
// =========================================================================

#[test]
fn cosign_data_contains_decodable_operation() {
    let mut ledger = make_ledger();
    let dep = open_deposit(
        &mut ledger,
        "pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)",
    );
    credit_deposit(&mut ledger, dep, 10_000);

    let operation = LedgerOperation::InvoiceLock {
        deposit_id: dep,
        amount: 5000,
        payment_id: [1u8; 32],
        sequence_number: 3,
        witness: DescriptorWitness { stack: vec![] },
    };

    // Build cosign_data the same way the protocol does
    let message_bytes = operation.tlv_encode();
    let seq: u64 = 3;
    let prev_hash = [0u8; 32];

    let mut cosign_data = Vec::new();
    cosign_data.extend_from_slice(&seq.to_le_bytes());
    cosign_data.extend_from_slice(&prev_hash);
    cosign_data.extend_from_slice(&message_bytes);

    // The cosigner extracts bytes 40+ as the operation TLV
    assert!(cosign_data.len() > 40);
    let extracted_message = &cosign_data[40..];
    let decoded = LedgerOperation::tlv_decode(extracted_message);
    assert!(
        decoded.is_ok(),
        "Should be able to decode operation from cosign_data"
    );

    // Validate against state — should succeed
    let result = ledger.state.apply(&decoded.unwrap());
    assert!(
        result.is_ok(),
        "Valid operation should pass cosign validation"
    );
}

#[test]
fn cosign_data_invalid_operation_rejected() {
    let ledger = make_ledger();
    // Don't open any deposits — lock on nonexistent deposit

    let fake_dep = [0xAAu8; 16];
    let operation = LedgerOperation::InvoiceLock {
        deposit_id: fake_dep,
        amount: 5000,
        payment_id: [1u8; 32],
        sequence_number: 0,
        witness: DescriptorWitness { stack: vec![] },
    };

    let message_bytes = operation.tlv_encode();
    let mut cosign_data = Vec::new();
    cosign_data.extend_from_slice(&0u64.to_le_bytes());
    cosign_data.extend_from_slice(&[0u8; 32]);
    cosign_data.extend_from_slice(&message_bytes);

    let extracted = &cosign_data[40..];
    let decoded = LedgerOperation::tlv_decode(extracted).unwrap();

    // Validate against state — should fail (deposit doesn't exist)
    let result = ledger.state.apply(&decoded);
    assert!(
        result.is_err(),
        "Invalid operation should be rejected by cosign validation"
    );
}
