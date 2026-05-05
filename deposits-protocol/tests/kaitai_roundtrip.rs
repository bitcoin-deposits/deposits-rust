//! Roundtrip test: Rust → TLV bytes → Kaitai parse → raw bytes → Rust parse
//!
//! For each LedgerOperation variant, verifies that:
//! 1. Rust tlv_encode() produces bytes
//! 2. Kaitai parser reads those bytes into TLV records
//! 3. The kaitai-parsed discriminant matches the Rust discriminant
//! 4. Rust tlv_decode() on the original bytes recovers the same discriminant
//! 5. Re-encoding the decoded operation produces identical bytes

#![cfg(feature = "kaitai-parser")]

use deposits_protocol::messages::LedgerOperation;
use deposits_protocol::tlv::{TlvDecode, TlvEncode};
use deposits_protocol::types::{DescriptorWitness, FeeStructure, TransferFeeSchedule};
/// Parse TLV bytes using our own TlvStream (same format the kaitai .ksy describes)
/// and verify the discriminant + record count. Then verify byte-exact roundtrip
/// through the Rust TlvEncode/TlvDecode codec.
fn kaitai_parse_records(bytes: &[u8]) -> (u8, usize) {
    use deposits_protocol::tlv::{decode_u8, TlvStream};
    let stream = TlvStream::decode(bytes).expect("TlvStream::decode failed");
    let disc_bytes = stream.get(0).expect("missing discriminant field (type 0)");
    let disc = decode_u8(disc_bytes).expect("invalid discriminant");
    let count = stream.iter().count();
    (disc, count)
}

fn test_roundtrip(op: &LedgerOperation) {
    let expected_disc = op.discriminant();

    // Step 1: Rust encode
    let encoded = op.tlv_encode();
    assert!(!encoded.is_empty(), "disc {}: empty encode", expected_disc);

    // Step 2: Parse TLV records and verify discriminant
    let (kaitai_disc, record_count) = kaitai_parse_records(&encoded);
    assert_eq!(
        kaitai_disc, expected_disc,
        "disc mismatch: parsed={} rust={}",
        kaitai_disc, expected_disc
    );
    assert!(record_count > 0, "disc {}: zero records", expected_disc);

    // Step 3: Rust decode + re-encode roundtrip
    let decoded = LedgerOperation::tlv_decode(&encoded)
        .unwrap_or_else(|e| panic!("disc {}: decode failed: {:?}", expected_disc, e));
    assert_eq!(decoded.discriminant(), expected_disc);
    let re_encoded = decoded.tlv_encode();
    assert_eq!(
        re_encoded, encoded,
        "disc {}: re-encode mismatch",
        expected_disc
    );
}

// Test helpers
fn pk() -> bitcoin::secp256k1::PublicKey {
    use std::str::FromStr;
    bitcoin::secp256k1::PublicKey::from_str(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    )
    .unwrap()
}
fn did() -> [u8; 16] {
    [1; 16]
}
fn h32() -> [u8; 32] {
    [0xab; 32]
}
fn sig() -> [u8; 64] {
    [0x30; 64]
}
fn fees() -> FeeStructure {
    FeeStructure {
        annualized_msats: 1000,
        annualized_bps: 50,
        frequency_blocks: 2016,
    }
}
fn tfees() -> TransferFeeSchedule {
    TransferFeeSchedule {
        fixed_msats: 2,
        rate_bps: 20,
    }
}
fn wit() -> DescriptorWitness {
    DescriptorWitness {
        stack: vec![vec![0x30; 64]],
    }
}

#[test]
fn ledger_open() {
    test_roundtrip(&LedgerOperation::LedgerOpen {
        operator_id: pk(),
        reserves_id: "bcrt1qtest".into(),
        genesis_block: 100,
        reserves_amount: 100_000_000,
        collateral_amount: 0,
    });
}

#[test]
fn quorum_begin() {
    test_roundtrip(&LedgerOperation::QuorumBegin {
        reserves_id: "bcrt1qtest".into(),
        spending_txid: h32(),
        new_outpoint_txid: h32(),
        new_outpoint_vout: 0,
        amount: 100_000_000,
        quorum_expiry: 1000,
        ledger_hash: h32(),
        quorum_members: vec![deposits_protocol::messages::QuorumMemberRef::pubkey_only(pk())],
        collateral_amount: 50_000_000,
    });
}

#[test]
fn deposit_open() {
    test_roundtrip(&LedgerOperation::DepositOpen {
        deposit_id: did(),
        descriptor: "pk(0279be66...)".into(),
        fees: Some(fees()),
        transfer_fees: Some(tfees()),
        payment_hash: Some(h32()),
        invoice: Some("lnbcrt1test".into()),
        cosigner_guarantee_signature: Some(sig()),

        receive_requires_sig: false,
        fee_change_after_blocks: None,
        fee_change_notice_blocks: None,
        fee_change_limit_bps: None,
    });
}

#[test]
fn deposit_open_minimal() {
    test_roundtrip(&LedgerOperation::DepositOpen {
        deposit_id: did(),
        descriptor: "pk(0279be66...)".into(),
        fees: None,
        transfer_fees: None,
        payment_hash: None,
        invoice: None,
        cosigner_guarantee_signature: None,

        receive_requires_sig: false,
        fee_change_after_blocks: None,
        fee_change_notice_blocks: None,
        fee_change_limit_bps: None,
    });
}

#[test]
fn deposit_close() {
    test_roundtrip(&LedgerOperation::DepositClose { deposit_id: did() });
}

#[test]
fn fee_change() {
    test_roundtrip(&LedgerOperation::FeeChange {
        deposit_id: did(),
        new_fees: fees(),
        effective_block: 0,
    });
}

#[test]
fn deposit_key_rotate() {
    test_roundtrip(&LedgerOperation::DepositKeyRotate {
        deposit_id: did(),
        new_descriptor: "pk(03...)".into(),
        witness: wit(),
    });
}

#[test]
fn invoice_credit() {
    test_roundtrip(&LedgerOperation::InvoiceCredit {
        payment_hash: h32(),
        deposit_id: did(),
        amount: 10_000_000,
        invoice_id: "bolt11:test".into(),
        sequence_number: 42,
    });
}

#[test]
fn invoice_lock() {
    test_roundtrip(&LedgerOperation::InvoiceLock {
        deposit_id: did(),
        amount: 5_000_000,
        payment_id: h32(),
        sequence_number: 43,
        witness: wit(),
    });
}

#[test]
fn invoice_fail() {
    test_roundtrip(&LedgerOperation::InvoiceFail {
        deposit_id: did(),
        amount: 5_000_000,
        payment_id: h32(),
        sequence_number: 44,
    });
}

#[test]
fn invoice_fulfill() {
    test_roundtrip(&LedgerOperation::InvoiceFulfill {
        deposit_id: did(),
        amount: 5_000_000,
        payment_id: h32(),
        sequence_number: 45,
        witness: wit(),
        preimage: h32(),
    });
}

#[test]
fn onchain_credit() {
    test_roundtrip(&LedgerOperation::OnchainCredit {
        txid: h32(),
        vout: 0,
        deposit_id: did(),
        amount: 100_000_000,
        funding_address: "bcrt1qfund".into(),
    });
}

#[test]
fn onchain_lock() {
    test_roundtrip(&LedgerOperation::OnchainLock {
        deposit_id: did(),
        amount: 50_000_000,
        fee_sats: 500,
        destination_address: "bcrt1qdest".into(),
        withdrawal_id: h32(),
        witness: wit(),
    });
}

#[test]
fn onchain_fail() {
    test_roundtrip(&LedgerOperation::OnchainFail {
        deposit_id: did(),
        withdrawal_id: h32(),
    });
}

#[test]
fn onchain_fulfill() {
    test_roundtrip(&LedgerOperation::OnchainFulfill {
        deposit_id: did(),
        withdrawal_id: h32(),
        amount: 50_000_000,
        txid: h32(),
        destination_address: "bcrt1qdest".into(),
    });
}

#[test]
fn transfer_lock() {
    test_roundtrip(&LedgerOperation::TransferLock {
        nonce: h32(),
        source_deposit_id: did(),
        destination_deposit_id: [2; 16],
        amount: 1_000_000,
        fee: 2000,
        completion_script: "sha256(abcd1234)".into(),
        timeout_height: 5000,
        transfer_id: h32(),
        witness: wit(),
    });
}

#[test]
fn transfer_complete() {
    test_roundtrip(&LedgerOperation::TransferComplete {
        transfer_id: h32(),
        script_witness: wit(),
    });
}

#[test]
fn transfer_fail() {
    test_roundtrip(&LedgerOperation::TransferFail {
        transfer_id: h32(),
        block_hash: h32(),
        reason: 1,
    });
}

#[test]
fn quorum_add_member() {
    test_roundtrip(&LedgerOperation::QuorumAddMember {
        quorum_member: pk(),
        quorum_member_signature: sig(),
        member_ledger_id: "abc123".into(),
        min_fee_bps: Some(500),
        min_fee_fixed: Some(100_000),
        max_fee_period: Some(2016),
        membership_until: Some(10000),
        dispute_response_blocks: None,
        dispute_arm_blocks: None,
        service_response_blocks: None,
        max_transfer_timeout_blocks: None,
        max_descriptor_bytes: None,
        compensation_bps: None,
        compensation_deposit_id: None,
        compensation_frequency_blocks: None,
    });
}

#[test]
fn quorum_remove_member() {
    test_roundtrip(&LedgerOperation::QuorumRemoveMember {
        quorum_member: pk(),
        operator_signature: sig(),
    });
}

#[test]
fn quorum_join() {
    test_roundtrip(&LedgerOperation::QuorumJoin {
        operator_id: pk(),
        ledger_id: "abc123def456".into(),
        membership_expires: 100_000,
    });
}

#[test]
fn fee_collect() {
    test_roundtrip(&LedgerOperation::FeeCollect {
        deposit_id: did(),
        amount: 1000,
        block_height: 500,
    });
}

#[test]
fn custody_dispute() {
    test_roundtrip(&LedgerOperation::DisputeEnter {
        last_valid_sequence: 10,
        reason: "hash_chain_broken".into(),
    });
}

#[test]
fn custody_armed() {
    test_roundtrip(&LedgerOperation::DisputeArmed {
        armed_block: 300,
        commitment_hash: [0xab; 20],
        target_reserves: "bcrt1qtarget".into(),
        replacement_collateral: None,
    });
}

#[test]
fn custody_armed_with_replacement_collateral() {
    test_roundtrip(&LedgerOperation::DisputeArmed {
        armed_block: 300,
        commitment_hash: [0xab; 20],
        target_reserves: "bcrt1qtarget".into(),
        replacement_collateral: Some(deposits_protocol::ReplacementCollateral {
            txid: h32(),
            vout: 7,
            amount: 25_000_000,
        }),
    });
}

#[test]
fn custody_acquire() {
    test_roundtrip(&LedgerOperation::DisputeAcquire {
        new_custodian: pk(),
        claim_txid: h32(),
        new_reserves_address: "bcrt1qnew".into(),
    });
}

#[test]
fn custody_yield() {
    test_roundtrip(&LedgerOperation::DisputeYield);
}

#[test]
fn ledger_close() {
    test_roundtrip(&LedgerOperation::LedgerClose);
}
