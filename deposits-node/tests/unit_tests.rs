//! Unit tests for deposits-node covering critical testable functions.
//!
//! Focuses on pure computation that doesn't require Nostr relay connections,
//! wallet instances, or network access.

use deposits_node::nostr::{
    ledger_tag, LedgerAdvertisement, LedgerDispute, LedgerResponse, KIND_LEDGER_ADVERTISE,
    KIND_LEDGER_DISPUTE, KIND_LEDGER_REQUEST, KIND_LEDGER_RESPONSE, KIND_LEDGER_UPDATE,
};

// ============================================================================
// 1. ledger_tag() — prefix truncation
// ============================================================================

#[test]
fn ledger_tag_truncates_to_16_chars() {
    let full_id = "a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718";
    assert_eq!(ledger_tag(full_id), "a1b2c3d4e5f60718");
}

#[test]
fn ledger_tag_short_input_returns_as_is() {
    // If input is shorter than 16, should return the full input (min logic)
    let short = "abcdef";
    assert_eq!(ledger_tag(short), "abcdef");
}

#[test]
fn ledger_tag_exact_16_returns_unchanged() {
    let exact = "0123456789abcdef";
    assert_eq!(ledger_tag(exact), "0123456789abcdef");
}

// ============================================================================
// 2. LedgerAdvertisement::new() defaults
// ============================================================================

#[test]
fn advertisement_new_sets_required_fields() {
    let ad = LedgerAdvertisement::new(
        "abc123".to_string(),
        "02deadbeef".to_string(),
        "bc1q...".to_string(),
        "regtest".to_string(),
    );
    assert_eq!(ad.ledger_id, "abc123");
    assert_eq!(ad.operator_pubkey, "02deadbeef");
    assert_eq!(ad.reserves_address, "bc1q...");
    assert_eq!(ad.network, "regtest");
    assert_eq!(ad.version, 1);
}

#[test]
fn advertisement_new_defaults_fees_to_zero() {
    let ad = LedgerAdvertisement::new(
        String::new(),
        String::new(),
        String::new(),
        "regtest".to_string(),
    );
    assert_eq!(ad.annual_fee_bps, 0);
    assert_eq!(ad.deposit_fee_bps, 0);
    assert_eq!(ad.withdrawal_fee_bps, 0);
    assert_eq!(ad.invoice_fee_bps, 0);
    assert_eq!(ad.annualized_fixed_msats, 0);
    assert_eq!(ad.fee_period_blocks, 0);
    assert_eq!(ad.transfer_fee_fixed_msats, 0);
    assert_eq!(ad.transfer_fee_rate_bps, 0);
}

#[test]
fn advertisement_new_defaults_limits() {
    let ad = LedgerAdvertisement::new(
        String::new(),
        String::new(),
        String::new(),
        "bitcoin".to_string(),
    );
    assert_eq!(ad.max_deposit_msats, u64::MAX);
    assert_eq!(ad.min_deposit_msats, 0);
    assert_eq!(ad.reserves_amount_msats, 0);
}

#[test]
fn advertisement_new_optional_fields_are_none() {
    let ad = LedgerAdvertisement::new(
        String::new(),
        String::new(),
        String::new(),
        "bitcoin".to_string(),
    );
    assert!(ad.operator_name.is_none());
    assert!(ad.description.is_none());
    assert!(ad.relay_url.is_none());
    assert!(!ad.access_control);
    assert!(ad.allowed_domains.is_empty());
}

// ============================================================================
// 3. LedgerAdvertisement::to_fee_structure()
// ============================================================================

#[test]
fn to_fee_structure_zero_period_returns_zero_annualized() {
    let ad = LedgerAdvertisement::new(
        String::new(),
        String::new(),
        String::new(),
        "regtest".to_string(),
    );
    let fs = ad.to_fee_structure();
    assert_eq!(fs.frequency_blocks, 0);
    assert_eq!(fs.annualized_msats, 0);
    assert_eq!(fs.annualized_bps, 0);
}

#[test]
fn to_fee_structure_computes_periods_per_year() {
    let mut ad = LedgerAdvertisement::new(
        String::new(),
        String::new(),
        String::new(),
        "regtest".to_string(),
    );
    // After the rename, both halves of FeeStructure pass through
    // directly — no per-period × periods-per-year × 1000 conversion.
    ad.fee_period_blocks = 4380;
    ad.annualized_fixed_msats = 1_200_000;
    ad.annual_fee_bps = 50;

    let fs = ad.to_fee_structure();
    assert_eq!(fs.frequency_blocks, 4380);
    assert_eq!(fs.annualized_bps, 50);
    assert_eq!(fs.annualized_msats, 1_200_000);
}

#[test]
fn to_fee_structure_passes_through_unchanged() {
    let mut ad = LedgerAdvertisement::new(
        String::new(),
        String::new(),
        String::new(),
        "regtest".to_string(),
    );
    ad.fee_period_blocks = 1;
    ad.annualized_fixed_msats = 52_560_000;

    let fs = ad.to_fee_structure();
    assert_eq!(fs.annualized_msats, 52_560_000);
    assert_eq!(fs.frequency_blocks, 1);
}

#[test]
fn to_fee_structure_max_value_unchanged() {
    let mut ad = LedgerAdvertisement::new(
        String::new(),
        String::new(),
        String::new(),
        "regtest".to_string(),
    );
    ad.fee_period_blocks = 1;
    ad.annualized_fixed_msats = u64::MAX;

    let fs = ad.to_fee_structure();
    assert_eq!(fs.annualized_msats, u64::MAX);
}

#[test]
fn to_fee_structure_long_period_keeps_value() {
    let mut ad = LedgerAdvertisement::new(
        String::new(),
        String::new(),
        String::new(),
        "regtest".to_string(),
    );
    // Period > blocks/year is a valid configuration (annual fee
    // collected on a multi-year cadence). The pass-through means
    // the annualized msats stay as set rather than truncating to 0.
    ad.fee_period_blocks = 100_000;
    ad.annualized_fixed_msats = 500;

    let fs = ad.to_fee_structure();
    assert_eq!(fs.annualized_msats, 500);
    assert_eq!(fs.frequency_blocks, 100_000);
}

// ============================================================================
// 4. LedgerAdvertisement::minimum_fees()
// ============================================================================

#[test]
fn minimum_fees_converts_annualized_to_per_period() {
    // `minimum_fees` returns annualized_fixed_msats divided by the
    // periods-per-year derived from `fee_period_blocks`. Use a
    // pretty-divisible annual amount so the per-period floor is
    // checkable without integer truncation noise.
    let mut ad = LedgerAdvertisement::new(
        String::new(),
        String::new(),
        String::new(),
        "regtest".to_string(),
    );
    ad.annual_fee_bps = 100; // 1% — passes through as-is
    ad.annualized_fixed_msats = 52_560_000;

    const BLOCKS_PER_YEAR: u64 = 52560;
    let period = (ad.fee_period_blocks as u64).max(1);
    let periods_per_year = (BLOCKS_PER_YEAR / period).max(1);

    let (bps, fixed_msats) = ad.minimum_fees();
    assert_eq!(bps, 100);
    assert_eq!(fixed_msats, 52_560_000 / periods_per_year);
}

#[test]
fn minimum_fees_zero_values() {
    let ad = LedgerAdvertisement::new(
        String::new(),
        String::new(),
        String::new(),
        "regtest".to_string(),
    );

    let (bps, fixed_msats) = ad.minimum_fees();
    assert_eq!(bps, 0);
    assert_eq!(fixed_msats, 0);
}

#[test]
fn minimum_fees_max_msats_divides_by_periods_per_year() {
    // `minimum_fees` converts annualized → per-period; saturating
    // arithmetic isn't used, so u64::MAX as the annualized input
    // yields `u64::MAX / periods_per_year` for the per-period floor.
    let mut ad = LedgerAdvertisement::new(
        String::new(),
        String::new(),
        String::new(),
        "regtest".to_string(),
    );
    ad.annualized_fixed_msats = u64::MAX;

    const BLOCKS_PER_YEAR: u64 = 52560;
    let period = (ad.fee_period_blocks as u64).max(1);
    let periods_per_year = (BLOCKS_PER_YEAR / period).max(1);

    let (_, fixed_msats) = ad.minimum_fees();
    assert_eq!(fixed_msats, u64::MAX / periods_per_year);
}

#[test]
fn minimum_fees_bps_truncation() {
    let mut ad = LedgerAdvertisement::new(
        String::new(),
        String::new(),
        String::new(),
        "regtest".to_string(),
    );
    // annual_fee_bps is u32 but minimum_fees returns u16
    ad.annual_fee_bps = 65535; // max u16

    let (bps, _) = ad.minimum_fees();
    assert_eq!(bps, u16::MAX);
}

// ============================================================================
// 5. LedgerAdvertisement serialization round-trip
// ============================================================================

#[test]
fn advertisement_json_round_trip() {
    let mut ad = LedgerAdvertisement::new(
        "aabbccdd".repeat(8),
        "02".to_string() + &"ab".repeat(32),
        "bc1qtest".to_string(),
        "signet".to_string(),
    );
    ad.annual_fee_bps = 50;
    ad.deposit_fee_bps = 10;
    ad.annualized_fixed_msats = 100;
    ad.fee_period_blocks = 4380;
    ad.max_deposit_msats = 1_000_000_000;
    ad.min_deposit_msats = 1_000;
    ad.operator_name = Some("TestOp".to_string());

    let json = serde_json::to_string(&ad).unwrap();
    let parsed: LedgerAdvertisement = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed.ledger_id, ad.ledger_id);
    assert_eq!(parsed.operator_pubkey, ad.operator_pubkey);
    assert_eq!(parsed.annual_fee_bps, 50);
    assert_eq!(parsed.deposit_fee_bps, 10);
    assert_eq!(parsed.annualized_fixed_msats, 100);
    assert_eq!(parsed.fee_period_blocks, 4380);
    assert_eq!(parsed.max_deposit_msats, 1_000_000_000);
    assert_eq!(parsed.min_deposit_msats, 1_000);
    assert_eq!(parsed.operator_name, Some("TestOp".to_string()));
    assert_eq!(parsed.network, "signet");
}

#[test]
fn advertisement_json_missing_optional_fields() {
    // Minimal JSON (only required fields + mandatory defaults)
    let json = r#"{
        "ledger_id": "abc",
        "operator_pubkey": "02dead",
        "reserves_address": "bc1q",
        "annual_fee_bps": 0,
        "deposit_fee_bps": 0,
        "withdrawal_fee_bps": 0,
        "invoice_fee_bps": 0,
        "max_deposit_msats": 100000,
        "min_deposit_msats": 0,
        "reserves_amount_msats": 0,
        "network": "regtest"
    }"#;
    let parsed: LedgerAdvertisement = serde_json::from_str(json).unwrap();
    assert_eq!(parsed.ledger_id, "abc");
    assert!(parsed.operator_name.is_none());
    assert!(parsed.description.is_none());
    assert_eq!(parsed.fee_period_blocks, 0); // serde(default)
    assert_eq!(parsed.annualized_fixed_msats, 0); // serde(default)
    assert_eq!(parsed.transfer_fee_fixed_msats, 0);
    assert_eq!(parsed.transfer_fee_rate_bps, 0);
}

// ============================================================================
// 6. LedgerResponse serialization
// ============================================================================

#[test]
fn ledger_response_success_round_trip() {
    let resp = LedgerResponse {
        success: true,
        result: Some(serde_json::json!({"balance": 1000})),
        error: None,
        request_id: String::new(),
        ledger_id: String::new(),
        event_id: String::new(),
        timestamp: 0,
        responder_pubkey: None,
    };
    let json = serde_json::to_string(&resp).unwrap();
    let parsed: LedgerResponse = serde_json::from_str(&json).unwrap();
    assert!(parsed.success);
    assert_eq!(parsed.result, Some(serde_json::json!({"balance": 1000})));
    assert!(parsed.error.is_none());
}

#[test]
fn ledger_response_error_round_trip() {
    let resp = LedgerResponse {
        success: false,
        result: None,
        error: Some("insufficient funds".to_string()),
        request_id: String::new(),
        ledger_id: String::new(),
        event_id: String::new(),
        timestamp: 0,
        responder_pubkey: None,
    };
    let json = serde_json::to_string(&resp).unwrap();
    let parsed: LedgerResponse = serde_json::from_str(&json).unwrap();
    assert!(!parsed.success);
    assert!(parsed.result.is_none());
    assert_eq!(parsed.error.as_deref(), Some("insufficient funds"));
}

// ============================================================================
// 7. LedgerDispute serialization
// ============================================================================

#[test]
fn ledger_dispute_round_trip() {
    let dispute = LedgerDispute {
        disputer_pubkey: "02".to_string() + &"aa".repeat(32),
        ledger_id: "bb".repeat(32),
        reason: "hash_chain_broken".to_string(),
        details: "Mismatch at seq 42".to_string(),
        last_valid_hash: "cc".repeat(32),
        last_valid_sequence: 41,
        violation_sequence: Some(42),
        signature: "dd".repeat(32),
        event_id: String::new(),
        timestamp: 0,
    };
    let json = serde_json::to_string(&dispute).unwrap();
    let parsed: LedgerDispute = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.reason, "hash_chain_broken");
    assert_eq!(parsed.last_valid_sequence, 41);
    assert_eq!(parsed.violation_sequence, Some(42));
}

#[test]
fn ledger_dispute_without_violation_sequence() {
    let json = r#"{
        "disputer_pubkey": "02aa",
        "ledger_id": "bb",
        "reason": "business_rule_violation",
        "details": "bad",
        "last_valid_hash": "cc",
        "last_valid_sequence": 10,
        "signature": "dd"
    }"#;
    let parsed: LedgerDispute = serde_json::from_str(json).unwrap();
    assert!(parsed.violation_sequence.is_none());
}

// ============================================================================
// 8. Custom Nostr kind constants
// ============================================================================

#[test]
fn kind_constants_are_in_correct_ranges() {
    // Ledger updates: regular custom (1000-9999)
    assert!(KIND_LEDGER_UPDATE >= 1000 && KIND_LEDGER_UPDATE <= 9999);
    // Requests: ephemeral (20000-29999)
    assert!(KIND_LEDGER_REQUEST >= 20000 && KIND_LEDGER_REQUEST <= 29999);
    // Responses: ephemeral (20000-29999)
    assert!(KIND_LEDGER_RESPONSE >= 20000 && KIND_LEDGER_RESPONSE <= 29999);
    // Disputes: regular custom (1000-9999)
    assert!(KIND_LEDGER_DISPUTE >= 1000 && KIND_LEDGER_DISPUTE <= 9999);
    // Advertisements: NIP-33 replaceable (30000-39999)
    assert!(KIND_LEDGER_ADVERTISE >= 30000 && KIND_LEDGER_ADVERTISE <= 39999);
}

#[test]
fn kind_constants_have_expected_values() {
    assert_eq!(KIND_LEDGER_UPDATE, 9100);
    assert_eq!(KIND_LEDGER_REQUEST, 20101);
    assert_eq!(KIND_LEDGER_RESPONSE, 20102);
    assert_eq!(KIND_LEDGER_DISPUTE, 9103);
    assert_eq!(KIND_LEDGER_ADVERTISE, 39100);
}

// ============================================================================
// 9. SignedLedgerUpdate hash chain (via deposits-core)
// ============================================================================

#[test]
fn signed_ledger_update_compute_hash_deterministic() {
    use deposits_core::types::SignedLedgerUpdate;

    let update = SignedLedgerUpdate {
        message: vec![1, 2, 3],
        message_type: 1,
        operator_id: test_pubkey(),
        ledger_id: [0xaa; 32],
        sequence_number: 0,
        previous_hash: [0u8; 32],
        content_hash: [0u8; 32], // will be computed
        block_height: 0,
        block_hash: [0u8; 32],
        cosign_signature: [0u8; 64],
        operator_signature: [0u8; 64],
        cosigner_pubkey: None,
        member_ledger_hash: None,
        cosignatures: vec![],
    };

    let hash1 = update.compute_hash();
    let hash2 = update.compute_hash();
    assert_eq!(hash1, hash2, "compute_hash must be deterministic");
    assert_ne!(hash1, [0u8; 32], "hash should not be all zeros");
}

#[test]
fn signed_ledger_update_hash_changes_with_sequence() {
    use deposits_core::types::SignedLedgerUpdate;

    let mut update = SignedLedgerUpdate {
        message: vec![1, 2, 3],
        message_type: 1,
        operator_id: test_pubkey(),
        ledger_id: [0xaa; 32],
        sequence_number: 0,
        previous_hash: [0u8; 32],
        content_hash: [0u8; 32],
        block_height: 0,
        block_hash: [0u8; 32],
        cosign_signature: [0u8; 64],
        operator_signature: [0u8; 64],
        cosigner_pubkey: None,
        member_ledger_hash: None,
        cosignatures: vec![],
    };

    let hash_seq0 = update.compute_hash();
    update.sequence_number = 1;
    let hash_seq1 = update.compute_hash();
    assert_ne!(
        hash_seq0, hash_seq1,
        "different sequence should produce different hash"
    );
}

#[test]
fn signed_ledger_update_hash_changes_with_previous_hash() {
    use deposits_core::types::SignedLedgerUpdate;

    let mut update = SignedLedgerUpdate {
        message: vec![1, 2, 3],
        message_type: 1,
        operator_id: test_pubkey(),
        ledger_id: [0xaa; 32],
        sequence_number: 5,
        previous_hash: [0u8; 32],
        content_hash: [0u8; 32],
        block_height: 0,
        block_hash: [0u8; 32],
        cosign_signature: [0u8; 64],
        operator_signature: [0u8; 64],
        cosigner_pubkey: None,
        member_ledger_hash: None,
        cosignatures: vec![],
    };

    let hash_a = update.compute_hash();
    update.previous_hash = [0xff; 32];
    let hash_b = update.compute_hash();
    assert_ne!(
        hash_a, hash_b,
        "different previous_hash should produce different hash"
    );
}

#[test]
fn signed_ledger_update_hash_changes_with_message() {
    use deposits_core::types::SignedLedgerUpdate;

    let mut update = SignedLedgerUpdate {
        message: vec![1, 2, 3],
        message_type: 1,
        operator_id: test_pubkey(),
        ledger_id: [0xaa; 32],
        sequence_number: 0,
        previous_hash: [0u8; 32],
        content_hash: [0u8; 32],
        block_height: 0,
        block_hash: [0u8; 32],
        cosign_signature: [0u8; 64],
        operator_signature: [0u8; 64],
        cosigner_pubkey: None,
        member_ledger_hash: None,
        cosignatures: vec![],
    };

    let hash_a = update.compute_hash();
    update.message = vec![4, 5, 6];
    let hash_b = update.compute_hash();
    assert_ne!(
        hash_a, hash_b,
        "different message should produce different hash"
    );
}

// ============================================================================
// 10. SignedLedgerUpdate TLV round-trip
// ============================================================================

#[test]
fn signed_ledger_update_tlv_round_trip() {
    use deposits_core::types::SignedLedgerUpdate;
    use deposits_core::{TlvDecode, TlvEncode};

    let mut update = SignedLedgerUpdate {
        message: vec![0xde, 0xad, 0xbe, 0xef],
        message_type: 42,
        operator_id: test_pubkey(),
        ledger_id: [0xbb; 32],
        sequence_number: 7,
        previous_hash: [0x11; 32],
        content_hash: [0u8; 32],
        block_height: 800_000,
        block_hash: [0x22; 32],
        cosign_signature: [0x33; 64],
        operator_signature: [0x44; 64],
        cosigner_pubkey: None,
        member_ledger_hash: None,
        cosignatures: vec![],
    };
    update.content_hash = update.compute_hash();

    let encoded = update.tlv_encode();
    assert!(!encoded.is_empty());

    let decoded = SignedLedgerUpdate::tlv_decode(&encoded).expect("TLV decode should succeed");
    assert_eq!(decoded.message, update.message);
    // message_type is derived from message bytes on TLV decode, not stored separately
    assert_eq!(decoded.ledger_id, update.ledger_id);
    assert_eq!(decoded.sequence_number, update.sequence_number);
    assert_eq!(decoded.previous_hash, update.previous_hash);
    assert_eq!(decoded.content_hash, update.content_hash);
    assert_eq!(decoded.block_height, update.block_height);
    assert_eq!(decoded.operator_signature, update.operator_signature);
    assert_eq!(decoded.cosign_signature, update.cosign_signature);
}

#[test]
fn signed_ledger_update_tlv_decode_invalid_bytes() {
    use deposits_core::types::SignedLedgerUpdate;
    use deposits_core::TlvDecode;

    let garbage = vec![0xff, 0x00, 0x01, 0x02];
    let result = SignedLedgerUpdate::tlv_decode(&garbage);
    assert!(result.is_err(), "garbage bytes should fail TLV decode");
}

#[test]
fn signed_ledger_update_tlv_decode_empty() {
    use deposits_core::types::SignedLedgerUpdate;
    use deposits_core::TlvDecode;

    let result = SignedLedgerUpdate::tlv_decode(&[]);
    assert!(result.is_err(), "empty bytes should fail TLV decode");
}

// ============================================================================
// 11. dep-17 operation preimage (per-op authorization sighash)
// ============================================================================
//
// The dep-17 operation preimage is what signature-bearing ops are signed
// over. Determinism + field sensitivity here is the binding property: a
// signature for one op shape can't authorize a different op shape, so a
// replay or substitution attack can't reuse signatures across contexts.

fn invoice_lock_preimage(deposit_id: [u8; 16], payment_id: [u8; 32], amount: u64) -> [u8; 32] {
    let op = deposits_core::messages::LedgerOperation::InvoiceLock {
        deposit_id,
        amount,
        payment_id,
        sequence_number: 1,
        nonce: 0,
        expiry: u32::MAX,
        witness: deposits_core::types::DescriptorWitness::new(),
    };
    deposits_core::dep16::operations::operation_sighash(&op)
        .expect("InvoiceLock has a dep-17 preimage")
}

fn transfer_lock_preimage(
    transfer_nonce: [u8; 32],
    src: [u8; 16],
    dst: [u8; 16],
    amount: u64,
    fee: u64,
    completion_script: &str,
    timeout: u32,
) -> [u8; 32] {
    let op = deposits_core::messages::LedgerOperation::TransferLock {
        transfer_nonce,
        source_deposit_id: src,
        destination_deposit_id: dst,
        amount,
        fee,
        completion_script: completion_script.into(),
        timeout_height: timeout,
        transfer_id: [0; 32],
        nonce: 0,
        expiry: u32::MAX,
        witness: deposits_core::types::DescriptorWitness::new(),
    };
    deposits_core::dep16::operations::operation_sighash(&op)
        .expect("TransferLock has a dep-17 preimage")
}

fn withdrawal_preimage(
    withdrawal_id: [u8; 32],
    deposit_id: [u8; 16],
    address: &str,
    amount: u64,
    fee: u64,
) -> [u8; 32] {
    let op = deposits_core::messages::LedgerOperation::OnchainLock {
        deposit_id,
        amount,
        fee_sats: fee,
        destination_address: address.into(),
        withdrawal_id,
        nonce: 0,
        expiry: u32::MAX,
        witness: deposits_core::types::DescriptorWitness::new(),
    };
    deposits_core::dep16::operations::operation_sighash(&op)
        .expect("OnchainLock has a dep-17 preimage")
}

#[test]
fn invoice_lock_preimage_deterministic() {
    let msg1 = invoice_lock_preimage([0xaa; 16], [0xbb; 32], 50_000);
    let msg2 = invoice_lock_preimage([0xaa; 16], [0xbb; 32], 50_000);
    assert_eq!(msg1, msg2);
    assert_ne!(msg1, [0u8; 32]);
}

#[test]
fn invoice_lock_preimage_changes_with_amount() {
    let msg_a = invoice_lock_preimage([0xaa; 16], [0xbb; 32], 1000);
    let msg_b = invoice_lock_preimage([0xaa; 16], [0xbb; 32], 2000);
    assert_ne!(msg_a, msg_b);
}

#[test]
fn invoice_lock_preimage_changes_with_payment_hash() {
    let msg_a = invoice_lock_preimage([0xaa; 16], [0x11; 32], 1000);
    let msg_b = invoice_lock_preimage([0xaa; 16], [0x22; 32], 1000);
    assert_ne!(msg_a, msg_b);
}

#[test]
fn transfer_lock_preimage_deterministic() {
    let msg1 = transfer_lock_preimage(
        [0x01; 32], [0xaa; 16], [0xbb; 16], 1000, 10, "preimage(abc)", 850000,
    );
    let msg2 = transfer_lock_preimage(
        [0x01; 32], [0xaa; 16], [0xbb; 16], 1000, 10, "preimage(abc)", 850000,
    );
    assert_eq!(msg1, msg2);
}

#[test]
fn transfer_lock_preimage_changes_with_script() {
    let msg_a = transfer_lock_preimage(
        [0x01; 32], [0xaa; 16], [0xbb; 16], 1000, 10, "preimage(abc)", 850000,
    );
    let msg_b = transfer_lock_preimage(
        [0x01; 32], [0xaa; 16], [0xbb; 16], 1000, 10, "preimage(xyz)", 850000,
    );
    assert_ne!(msg_a, msg_b);
}

#[test]
fn withdrawal_preimage_deterministic() {
    let address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    let msg1 = withdrawal_preimage([0x42; 32], [0xaa; 16], address, 50_000, 500);
    let msg2 = withdrawal_preimage([0x42; 32], [0xaa; 16], address, 50_000, 500);
    assert_eq!(msg1, msg2);
}

#[test]
fn withdrawal_preimage_changes_with_address() {
    let msg_a = withdrawal_preimage([0x42; 32], [0xaa; 16], "bc1qaddr1", 50_000, 500);
    let msg_b = withdrawal_preimage([0x42; 32], [0xaa; 16], "bc1qaddr2", 50_000, 500);
    assert_ne!(msg_a, msg_b);
}

// ============================================================================
// 12. SignedLedgerUpdate hash chain simulation
// ============================================================================

#[test]
fn hash_chain_links_correctly() {
    use deposits_core::types::SignedLedgerUpdate;

    // Build a chain of 3 updates
    let mut updates = Vec::new();
    let mut prev_hash = [0u8; 32]; // genesis

    for seq in 0..3u64 {
        let mut update = SignedLedgerUpdate {
            message: vec![seq as u8],
            message_type: 1,
            operator_id: test_pubkey(),
            ledger_id: [0xaa; 32],
            sequence_number: seq,
            previous_hash: prev_hash,
            content_hash: [0u8; 32],
            block_height: 0,
            block_hash: [0u8; 32],
            cosign_signature: [0u8; 64],
            operator_signature: [0u8; 64],
            cosigner_pubkey: None,
            member_ledger_hash: None,
            cosignatures: vec![],
        };
        update.content_hash = update.compute_hash();
        prev_hash = update.content_hash;
        updates.push(update);
    }

    // Verify chain linkage
    assert_eq!(updates[0].previous_hash, [0u8; 32]); // genesis
    assert_eq!(updates[1].previous_hash, updates[0].content_hash);
    assert_eq!(updates[2].previous_hash, updates[1].content_hash);

    // All hashes are unique
    let hashes: Vec<_> = updates.iter().map(|u| u.content_hash).collect();
    assert_ne!(hashes[0], hashes[1]);
    assert_ne!(hashes[1], hashes[2]);
    assert_ne!(hashes[0], hashes[2]);
}

#[test]
fn hash_chain_detects_tampering() {
    use deposits_core::types::SignedLedgerUpdate;

    let mut update0 = SignedLedgerUpdate {
        message: vec![0],
        message_type: 1,
        operator_id: test_pubkey(),
        ledger_id: [0xaa; 32],
        sequence_number: 0,
        previous_hash: [0u8; 32],
        content_hash: [0u8; 32],
        block_height: 0,
        block_hash: [0u8; 32],
        cosign_signature: [0u8; 64],
        operator_signature: [0u8; 64],
        cosigner_pubkey: None,
        member_ledger_hash: None,
        cosignatures: vec![],
    };
    update0.content_hash = update0.compute_hash();

    let mut update1 = SignedLedgerUpdate {
        message: vec![1],
        message_type: 1,
        operator_id: test_pubkey(),
        ledger_id: [0xaa; 32],
        sequence_number: 1,
        previous_hash: update0.content_hash,
        content_hash: [0u8; 32],
        block_height: 0,
        block_hash: [0u8; 32],
        cosign_signature: [0u8; 64],
        operator_signature: [0u8; 64],
        cosigner_pubkey: None,
        member_ledger_hash: None,
        cosignatures: vec![],
    };
    update1.content_hash = update1.compute_hash();

    // Tamper with update0's message after the fact
    let tampered_message = vec![99];
    let mut tampered_update0 = update0.clone();
    tampered_update0.message = tampered_message;

    // The recomputed hash won't match the stored content_hash
    let recomputed = tampered_update0.compute_hash();
    assert_ne!(
        recomputed, tampered_update0.content_hash,
        "tampered update should have mismatched hash"
    );

    // And update1's previous_hash won't match the tampered update0's recomputed hash
    assert_ne!(
        update1.previous_hash, recomputed,
        "chain link broken by tampering"
    );
}

// ============================================================================
// 13. LedgerAdvertisement edge cases
// ============================================================================

#[test]
fn to_fee_structure_with_max_u32_period() {
    let mut ad = LedgerAdvertisement::new(
        String::new(),
        String::new(),
        String::new(),
        "regtest".to_string(),
    );
    ad.fee_period_blocks = u32::MAX;
    ad.annualized_fixed_msats = 1000;

    let fs = ad.to_fee_structure();
    // Both halves pass through unchanged regardless of period.
    assert_eq!(fs.annualized_msats, 1000);
    assert_eq!(fs.frequency_blocks, u32::MAX);
}

// ============================================================================
// Helpers
// ============================================================================

/// Create a valid secp256k1 public key for testing.
fn test_pubkey() -> bitcoin::secp256k1::PublicKey {
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[0x01; 32]).unwrap();
    sk.public_key(&secp)
}
