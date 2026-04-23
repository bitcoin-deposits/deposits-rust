//! Tests for the operator fee accumulator on `LedgerState.fees_accumulated`.
//!
//! Contributions to the accumulator:
//!   - `FeeCollect`            — maintenance fee charged against a deposit
//!   - `TransferComplete`      — the `fee` field on the matching pending transfer
//!   - `TransferFail`          — the fixed portion of the transfer fee
//!                                (proportional portion is zero since nothing moved)
//!   - `InvoiceFail`           — the fixed portion of the transfer fee
//!   - `OnchainFail`           — the fixed portion of the transfer fee
//!
//! Fixed-portion fees on failures are read from the deposit's current
//! `transfer_fees.fixed_msats`. Miner fees (`OnchainLock.fee_sats`) are
//! never accrued to the operator.

use deposits_core::ledger::{Ledger, LedgerRole};
use deposits_core::messages::LedgerOperation;
use deposits_core::types::{
    compute_deposit_id, DescriptorWitness, FeeStructure, LedgerState, TransferFeeSchedule,
};

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

/// Open a deposit with a specific fixed transfer fee (msats). Rate is 20 bps.
fn open_deposit_fixed_fee(ledger: &mut Ledger, descriptor: &str, fixed_msats: u64) -> [u8; 16] {
    let deposit_id = compute_deposit_id(descriptor);
    ledger
        .apply_state_changes(&LedgerOperation::DepositOpen {
            deposit_id,
            descriptor: descriptor.to_string(),
            fees: Some(FeeStructure::default()),
            transfer_fees: Some(TransferFeeSchedule {
                fixed_msats,
                rate_bps: 20,
            }),
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

fn open_deposit(ledger: &mut Ledger, descriptor: &str) -> [u8; 16] {
    open_deposit_fixed_fee(ledger, descriptor, 2)
}

fn credit(ledger: &mut Ledger, deposit_id: [u8; 16], amount: u64, seq: u64) {
    let hash_seed = seq as u8;
    ledger
        .apply_state_changes(&LedgerOperation::InvoiceCredit {
            payment_hash: [hash_seed; 32],
            deposit_id,
            amount,
            invoice_id: format!("inv-{}", seq),
            sequence_number: seq,
        })
        .unwrap();
}

#[test]
fn fresh_ledger_has_zero_accumulated_fees() {
    let ledger = make_ledger();
    assert_eq!(ledger.state.fees_accumulated, 0);
}

#[test]
fn fee_collect_adds_to_accumulator() {
    let mut ledger = make_ledger();
    let did = open_deposit(&mut ledger, "pk(alice)");
    credit(&mut ledger, did, 1_000_000, 1);

    ledger
        .apply_state_changes(&LedgerOperation::FeeCollect {
            deposit_id: did,
            amount: 12_345,
            block_height: 2016,
        })
        .unwrap();

    assert_eq!(ledger.state.fees_accumulated, 12_345);

    // A second FeeCollect stacks.
    ledger
        .apply_state_changes(&LedgerOperation::FeeCollect {
            deposit_id: did,
            amount: 500,
            block_height: 4032,
        })
        .unwrap();
    assert_eq!(ledger.state.fees_accumulated, 12_845);
}

#[test]
fn transfer_complete_adds_fee_to_accumulator() {
    let mut ledger = make_ledger();
    let source = open_deposit(&mut ledger, "pk(alice)");
    let dest = open_deposit(&mut ledger, "pk(bob)");
    credit(&mut ledger, source, 1_000_000, 1);

    let transfer_id = [0xBB; 32];
    let amount = 100_000u64;
    let fee = 777u64;

    ledger
        .apply_state_changes(&LedgerOperation::TransferLock {
            nonce: [0x42; 32],
            source_deposit_id: source,
            destination_deposit_id: dest,
            amount,
            fee,
            completion_script: "sha256(deadbeef)".to_string(),
            timeout_height: 900_000,
            transfer_id,
            witness: DescriptorWitness {
                stack: vec![[0x11u8; 64].to_vec()],
            },
        })
        .unwrap();

    // Lock alone doesn't book the fee — it's still refundable.
    assert_eq!(ledger.state.fees_accumulated, 0);

    ledger
        .apply_state_changes(&LedgerOperation::TransferComplete {
            transfer_id,
            script_witness: DescriptorWitness {
                stack: vec![[0x22u8; 64].to_vec()],
            },
        })
        .unwrap();

    assert_eq!(ledger.state.fees_accumulated, fee);
}

#[test]
fn transfer_fail_accumulates_fixed_fee() {
    let mut ledger = make_ledger();
    let source = open_deposit_fixed_fee(&mut ledger, "pk(alice)", 500);
    let dest = open_deposit(&mut ledger, "pk(bob)");
    credit(&mut ledger, source, 1_000_000, 1);

    let transfer_id = [0xCC; 32];
    ledger
        .apply_state_changes(&LedgerOperation::TransferLock {
            nonce: [0x42; 32],
            source_deposit_id: source,
            destination_deposit_id: dest,
            amount: 50_000,
            // Caller pre-computed fee = fixed(500) + proportional(50_000 * 20bps = 100) = 600.
            fee: 600,
            completion_script: "sha256(deadbeef)".to_string(),
            timeout_height: 900_000,
            transfer_id,
            witness: DescriptorWitness {
                stack: vec![[0x11u8; 64].to_vec()],
            },
        })
        .unwrap();
    ledger
        .apply_state_changes(&LedgerOperation::TransferFail {
            transfer_id,
            block_hash: [0; 32],
            reason: 1,
        })
        .unwrap();

    // Fixed portion (500) accrues to operator; proportional portion (100)
    // is refunded to depositor. Lock is fully released.
    assert_eq!(ledger.state.fees_accumulated, 500);
    let src = ledger.state.deposits.get(&source).unwrap();
    assert_eq!(src.locked_balance, 0);
    assert_eq!(src.balance, 1_000_000 - 500);
}

#[test]
fn invoice_fail_accumulates_fixed_fee() {
    let mut ledger = make_ledger();
    let did = open_deposit_fixed_fee(&mut ledger, "pk(alice)", 300);
    credit(&mut ledger, did, 1_000_000, 1);

    let payment_id = [0xEE; 32];
    ledger
        .apply_state_changes(&LedgerOperation::InvoiceLock {
            deposit_id: did,
            amount: 10_000,
            payment_id,
            sequence_number: 2,
            witness: DescriptorWitness {
                stack: vec![[0x11u8; 64].to_vec()],
            },
        })
        .unwrap();
    ledger
        .apply_state_changes(&LedgerOperation::InvoiceFail {
            deposit_id: did,
            amount: 10_000,
            payment_id,
            sequence_number: 3,
        })
        .unwrap();

    assert_eq!(ledger.state.fees_accumulated, 300);
    let d = ledger.state.deposits.get(&did).unwrap();
    assert_eq!(d.locked_balance, 0);
    assert_eq!(d.balance, 1_000_000 - 300);
}

#[test]
fn onchain_fail_accumulates_fixed_fee() {
    // Miner fees don't accrue, but the fixed operator fee does.
    let mut ledger = make_ledger();
    let did = open_deposit_fixed_fee(&mut ledger, "pk(alice)", 400);
    credit(&mut ledger, did, 1_000_000, 1);

    let withdrawal_id = [0xDD; 32];
    ledger
        .apply_state_changes(&LedgerOperation::OnchainLock {
            deposit_id: did,
            amount: 100_000,
            fee_sats: 2_000,
            destination_address: "bcrt1qsomewhere".to_string(),
            withdrawal_id,
            witness: DescriptorWitness {
                stack: vec![[0x11u8; 64].to_vec()],
            },
        })
        .unwrap();
    ledger
        .apply_state_changes(&LedgerOperation::OnchainFail {
            deposit_id: did,
            withdrawal_id,
        })
        .unwrap();

    assert_eq!(ledger.state.fees_accumulated, 400);
    let d = ledger.state.deposits.get(&did).unwrap();
    assert_eq!(d.locked_balance, 0);
    assert_eq!(d.balance, 1_000_000 - 400);
}

#[test]
fn onchain_fulfill_does_not_accumulate() {
    // Success path: miner fee leaves to miners, no operator fee model for
    // on-chain withdrawals today. Fulfill stays at 0 on the accumulator.
    let mut ledger = make_ledger();
    let did = open_deposit(&mut ledger, "pk(alice)");
    credit(&mut ledger, did, 1_000_000, 1);

    let withdrawal_id = [0xDD; 32];
    ledger
        .apply_state_changes(&LedgerOperation::OnchainLock {
            deposit_id: did,
            amount: 100_000,
            fee_sats: 2_000,
            destination_address: "bcrt1qsomewhere".to_string(),
            withdrawal_id,
            witness: DescriptorWitness {
                stack: vec![[0x11u8; 64].to_vec()],
            },
        })
        .unwrap();
    ledger
        .apply_state_changes(&LedgerOperation::OnchainFulfill {
            deposit_id: did,
            withdrawal_id,
            amount: 100_000,
            txid: [0xAA; 32],
            destination_address: "bcrt1qsomewhere".to_string(),
        })
        .unwrap();

    assert_eq!(ledger.state.fees_accumulated, 0);
}

#[test]
fn accumulator_survives_json_roundtrip() {
    let mut ledger = make_ledger();
    let did = open_deposit(&mut ledger, "pk(alice)");
    credit(&mut ledger, did, 1_000_000, 1);
    ledger
        .apply_state_changes(&LedgerOperation::FeeCollect {
            deposit_id: did,
            amount: 9_999,
            block_height: 2016,
        })
        .unwrap();
    assert_eq!(ledger.state.fees_accumulated, 9_999);

    let json = serde_json::to_string(&ledger.state).unwrap();
    let restored: LedgerState = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.fees_accumulated, 9_999);
}

#[test]
fn old_ledger_json_defaults_accumulator_to_zero() {
    // Serde default lets us load a pre-accumulator ledger cleanly.
    let ledger = make_ledger();
    let mut json: serde_json::Value = serde_json::to_value(&ledger.state).unwrap();
    json.as_object_mut().unwrap().remove("fees_accumulated");
    let restored: LedgerState = serde_json::from_value(json).unwrap();
    assert_eq!(restored.fees_accumulated, 0);
}
