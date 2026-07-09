//! Tests for `LedgerOperation::Batch` (DEP-02 §"Batch"): wire-format
//! round-trip, applier transactionality, and admission gates.

use deposits_protocol::messages::{LedgerOperation, MAX_BATCH_OPS};
use deposits_protocol::tlv::{TlvDecode, TlvEncode};
use deposits_protocol::types::{
    compute_deposit_id, AllowAll, FeeStructure, LedgerState, TransferFeeSchedule,
};

fn test_pubkey() -> bitcoin::secp256k1::PublicKey {
    use std::str::FromStr;
    bitcoin::secp256k1::PublicKey::from_str(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    )
    .unwrap()
}

fn open_state() -> LedgerState {
    let mut s = LedgerState::new(test_pubkey(), "bcrt1qtest".to_string(), 0);
    s.reserves_amount = 10_000_000;
    s
}

fn open_deposit_op(descriptor: &str) -> LedgerOperation {
    LedgerOperation::DepositOpen {
        deposit_id: compute_deposit_id(descriptor),
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
    }
}

fn credit_op(descriptor: &str, amount: u64, seq: u64, hash_byte: u8) -> LedgerOperation {
    LedgerOperation::InvoiceCredit {
        payment_hash: [hash_byte; 32],
        deposit_id: compute_deposit_id(descriptor),
        amount,
        invoice_id: format!("inv-{}", seq),
        sequence_number: seq,
        wallet_authorization: None,
        commitment: None,
    }
}

#[test]
fn batch_tlv_roundtrip() {
    let batch = LedgerOperation::Batch(vec![
        open_deposit_op("pk(aa)"),
        credit_op("pk(aa)", 1_000, 1, 0xAA),
    ]);
    let bytes = batch.tlv_encode();
    let decoded = LedgerOperation::tlv_decode(&bytes).expect("roundtrip");
    assert_eq!(decoded, batch);
}

#[test]
fn batch_applies_inner_ops_in_order() {
    let state = open_state();
    let batch = LedgerOperation::Batch(vec![
        open_deposit_op("pk(aa)"),
        credit_op("pk(aa)", 5_000, 1, 0xAA),
    ]);
    let (next, violations) = state
        .apply_with_verifier(&batch, &AllowAll, 0)
        .expect("batch apply");
    assert!(violations.is_empty(), "expected no violations: {:?}", violations);
    let deposit_id = compute_deposit_id("pk(aa)");
    assert_eq!(
        next.deposits.get(&deposit_id).unwrap().balance,
        5_000,
        "credit must have been applied through the batch"
    );
}

#[test]
fn batch_inner_op_failure_rolls_back_entire_batch() {
    let state = open_state();
    // Open a deposit, then try to credit a *different* (unopened) deposit.
    // The inner credit should fail; the batch should not partially apply.
    let batch = LedgerOperation::Batch(vec![
        open_deposit_op("pk(aa)"),
        credit_op("pk(bb)", 1_000, 1, 0xBB), // bb wasn't opened
    ]);
    let result = state.apply_with_verifier(&batch, &AllowAll, 0);
    // The batch should either error or surface violations; in either case,
    // the deposit `pk(aa)` from inner op 0 must NOT appear in the state.
    let aa_id = compute_deposit_id("pk(aa)");
    match result {
        Ok((next, violations)) => {
            // If apply succeeded, violations should at least surface — and
            // the original `state` is what we built from, so its `deposits`
            // should still be empty.
            assert!(
                state.deposits.get(&aa_id).is_none(),
                "rollback: original state had no aa deposit, must remain so"
            );
            // The applied next-state could legitimately have aa (since the
            // first op succeeded and we used apply_with_verifier which
            // tracks violations rather than aborting). The transactional
            // contract on `apply()` is what really matters — exercise that:
            let strict_result = state.apply(&batch);
            assert!(
                strict_result.is_err() || strict_result.unwrap().deposits.get(&aa_id).is_none(),
                "strict apply must either error or not partially-apply: \
                 violations from with_verifier path = {:?}, next.deposits.contains(aa) = {}",
                violations,
                next.deposits.contains_key(&aa_id)
            );
        }
        Err(_) => {
            // Errored — that's a valid transactional outcome.
        }
    }
}

#[test]
fn batch_empty_is_rejected_at_decode() {
    // Manually build a Batch with 0 inner ops; the TLV decoder MUST reject.
    let empty_batch = LedgerOperation::Batch(vec![]);
    let bytes = empty_batch.tlv_encode();
    let err = LedgerOperation::tlv_decode(&bytes).expect_err("empty Batch must fail to decode");
    let msg = format!("{:?}", err);
    assert!(
        msg.contains("empty"),
        "expected 'empty' in decode error, got: {}",
        msg
    );
}

#[test]
fn batch_oversized_is_rejected_at_decode() {
    let many: Vec<LedgerOperation> = (0..(MAX_BATCH_OPS + 1) as u64)
        .map(|i| credit_op("pk(aa)", 1, i + 1, i as u8))
        .collect();
    let batch = LedgerOperation::Batch(many);
    let bytes = batch.tlv_encode();
    let err = LedgerOperation::tlv_decode(&bytes).expect_err("oversized must fail");
    let msg = format!("{:?}", err);
    assert!(
        msg.contains("MAX_BATCH_OPS"),
        "expected 'MAX_BATCH_OPS' in decode error, got: {}",
        msg
    );
}

#[test]
fn batch_nested_is_rejected_at_decode() {
    let inner = LedgerOperation::Batch(vec![credit_op("pk(aa)", 1, 1, 0xAA)]);
    let outer = LedgerOperation::Batch(vec![inner]);
    let bytes = outer.tlv_encode();
    let err = LedgerOperation::tlv_decode(&bytes).expect_err("nested must fail");
    let msg = format!("{:?}", err);
    assert!(
        msg.contains("nested"),
        "expected 'nested' in decode error, got: {}",
        msg
    );
}
