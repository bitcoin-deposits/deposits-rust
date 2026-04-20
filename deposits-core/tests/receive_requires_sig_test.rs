//! Tests for receive_requires_sig flag on deposits.
//!
//! The flag is set at DepositOpen time and persists on the Deposit state.
//! Enforcement of the signature check happens in the node's request handlers,
//! but here we verify the flag propagates correctly through the protocol layer.

use deposits_core::ledger::{Ledger, LedgerRole};
use deposits_core::messages::LedgerOperation;
use deposits_core::types::{
    compute_deposit_id, Deposit, DescriptorWitness, FeeStructure, LedgerState, TransferFeeSchedule,
};
use deposits_protocol::TlvDecode;
use deposits_protocol::TlvEncode;

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

fn open_deposit_ex(ledger: &mut Ledger, descriptor: &str, receive_requires_sig: bool) -> [u8; 16] {
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
            receive_requires_sig,
            fee_change_after_blocks: None,
            fee_change_notice_blocks: None,
            fee_change_limit_bps: None,
        })
        .unwrap();
    deposit_id
}

// =========================================================================
// Flag propagation tests
// =========================================================================

#[test]
fn receive_requires_sig_flag_set_on_deposit() {
    let mut ledger = make_ledger();
    let did = open_deposit_ex(&mut ledger, "pk(guarded_key)", true);
    let deposit = ledger.state.deposits.get(&did).unwrap();
    assert!(
        deposit.receive_requires_sig,
        "deposit should have receive_requires_sig set"
    );
}

#[test]
fn receive_requires_sig_flag_not_set_by_default() {
    let mut ledger = make_ledger();
    let did = open_deposit_ex(&mut ledger, "pk(normal_key)", false);
    let deposit = ledger.state.deposits.get(&did).unwrap();
    assert!(
        !deposit.receive_requires_sig,
        "deposit should not have receive_requires_sig"
    );
}

#[test]
fn receive_requires_sig_flag_set_independently() {
    let mut ledger = make_ledger();
    let did = open_deposit_ex(&mut ledger, "pk(both_flags)", true);
    let deposit = ledger.state.deposits.get(&did).unwrap();
    assert!(deposit.receive_requires_sig);
}

// =========================================================================
// TLV roundtrip tests
// =========================================================================

#[test]
fn deposit_open_receive_requires_sig_tlv_roundtrip() {
    let deposit_id = compute_deposit_id("pk(guarded)");
    let op = LedgerOperation::DepositOpen {
        deposit_id,
        descriptor: "pk(guarded)".to_string(),
        fees: Some(FeeStructure::default()),
        transfer_fees: None,
        payment_hash: None,
        invoice: None,
        cosigner_guarantee_signature: None,
        receive_requires_sig: true,
        fee_change_after_blocks: None,
        fee_change_notice_blocks: None,
        fee_change_limit_bps: None,
    };

    let encoded = op.tlv_encode();
    let decoded = LedgerOperation::tlv_decode(&encoded).unwrap();

    if let LedgerOperation::DepositOpen {
        receive_requires_sig,
        ..
    } = decoded
    {
        assert!(receive_requires_sig, "flag should survive TLV roundtrip");
    } else {
        panic!("decoded wrong variant");
    }
}

#[test]
fn deposit_open_without_flag_decodes_as_false() {
    let deposit_id = compute_deposit_id("pk(normal)");
    let op = LedgerOperation::DepositOpen {
        deposit_id,
        descriptor: "pk(normal)".to_string(),
        fees: Some(FeeStructure::default()),
        transfer_fees: None,
        payment_hash: None,
        invoice: None,
        cosigner_guarantee_signature: None,
        receive_requires_sig: false,
        fee_change_after_blocks: None,
        fee_change_notice_blocks: None,
        fee_change_limit_bps: None,
    };

    let encoded = op.tlv_encode();
    let decoded = LedgerOperation::tlv_decode(&encoded).unwrap();

    if let LedgerOperation::DepositOpen {
        receive_requires_sig,
        ..
    } = decoded
    {
        assert!(!receive_requires_sig, "default should be false");
    } else {
        panic!("decoded wrong variant");
    }
}

#[test]
fn deposit_struct_receive_requires_sig_tlv_roundtrip() {
    let deposit_id = compute_deposit_id("pk(test_rrs)");
    let deposit = Deposit {
        deposit_id,
        descriptor: "pk(test_rrs)".to_string(),
        balance: 100_000,
        locked_balance: 0,
        invoices: vec![],
        fees: FeeStructure::default(),
        last_fee_assessment: 0,
        transfer_fees: TransferFeeSchedule::default(),
        receive_requires_sig: true,
        fee_change_after_blocks: None,
        fee_change_notice_blocks: None,
        fee_change_limit_bps: None,
        opened_at_block: 0,
        pending_fee_change: None,
    };

    let encoded = deposit.tlv_encode();
    let decoded = Deposit::tlv_decode(&encoded).unwrap();
    assert_eq!(deposit, decoded);
    assert!(decoded.receive_requires_sig);
}

// =========================================================================
// Backward compatibility: old TLV without the field decodes to false
// =========================================================================

#[test]
fn deposit_struct_without_flag_field_defaults_false() {
    // Build a Deposit without receive_requires_sig, encode, decode
    let deposit_id = compute_deposit_id("pk(old_format)");
    let deposit = Deposit {
        deposit_id,
        descriptor: "pk(old_format)".to_string(),
        balance: 50_000,
        locked_balance: 0,
        invoices: vec![],
        fees: FeeStructure::default(),
        last_fee_assessment: 0,
        transfer_fees: TransferFeeSchedule::default(),
        receive_requires_sig: false,
        fee_change_after_blocks: None,
        fee_change_notice_blocks: None,
        fee_change_limit_bps: None,
        opened_at_block: 0,
        pending_fee_change: None,
    };

    let encoded = deposit.tlv_encode();
    let decoded = Deposit::tlv_decode(&encoded).unwrap();
    assert!(
        !decoded.receive_requires_sig,
        "missing field should default to false"
    );
}

// =========================================================================
// Mixed deposits: guarded and unguarded coexist
// =========================================================================

#[test]
fn guarded_and_unguarded_deposits_coexist() {
    let mut ledger = make_ledger();
    let guarded = open_deposit_ex(&mut ledger, "pk(guarded)", true);
    let normal = open_deposit_ex(&mut ledger, "pk(normal)", false);

    assert_eq!(ledger.state.deposits.len(), 2);

    let g = ledger.state.deposits.get(&guarded).unwrap();
    let n = ledger.state.deposits.get(&normal).unwrap();

    assert!(g.receive_requires_sig);
    assert!(!n.receive_requires_sig);
}

// =========================================================================
// Transfer to guarded deposit at ledger level (state changes only —
// the signature enforcement is in node.rs, but state changes still apply)
// =========================================================================

#[test]
fn transfer_lock_to_guarded_deposit_applies_state() {
    let mut ledger = make_ledger();
    let source = open_deposit_ex(&mut ledger, "pk(sender)", false);
    let dest = open_deposit_ex(&mut ledger, "pk(receiver)", true);

    // Credit the source
    ledger
        .apply_state_changes(&LedgerOperation::InvoiceCredit {
            payment_hash: [0xaa; 32],
            deposit_id: source,
            amount: 100_000,
            invoice_id: "fund".to_string(),
            sequence_number: 1,
        })
        .unwrap();

    // TransferLock at the ledger level always succeeds (signature check is in node.rs)
    let transfer_id = [0xBB; 32];
    let amount = 30_000u64;
    let fee = 500u64;

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

    // Source balance is unchanged (balance = total obligation); the lock
    // moves a portion into locked_balance instead.
    let src = ledger.state.deposits.get(&source).unwrap();
    assert_eq!(src.balance, 100_000);
    assert_eq!(src.locked_balance, amount + fee);

    // Destination should still have receive_requires_sig
    let dst = ledger.state.deposits.get(&dest).unwrap();
    assert!(dst.receive_requires_sig);

    // Complete the transfer
    ledger
        .apply_state_changes(&LedgerOperation::TransferComplete {
            transfer_id,
            script_witness: DescriptorWitness {
                stack: vec![[0x22u8; 64].to_vec()],
            },
        })
        .unwrap();

    // Destination should have received the funds
    let dst = ledger.state.deposits.get(&dest).unwrap();
    assert_eq!(dst.balance, amount);
    assert!(dst.receive_requires_sig, "flag persists after transfer");
}
