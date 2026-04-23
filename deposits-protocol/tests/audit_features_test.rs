use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use deposits_protocol::messages::{BinaryCodec, LedgerOperation};
use deposits_protocol::tlv::{TlvDecode, TlvEncode};
use std::io::Cursor;

fn test_pubkey() -> PublicKey {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[1u8; 32]).unwrap();
    PublicKey::from_secret_key(&secp, &sk)
}

fn test_pubkey_2() -> PublicKey {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[2u8; 32]).unwrap();
    PublicKey::from_secret_key(&secp, &sk)
}

// =========================================================================
// DeliveryEmbed TLV roundtrip
// =========================================================================

#[test]
fn delivery_embed_tlv_roundtrip() {
    let original = LedgerOperation::DeliveryEmbed {
        request_hash: [0xAB; 32],
        target_ledger_id: [0xCD; 32],
        target_operator: test_pubkey(),
    };

    assert_eq!(original.discriminant(), 80);

    let encoded = original.tlv_encode();
    let decoded = LedgerOperation::tlv_decode(&encoded).unwrap();

    match decoded {
        LedgerOperation::DeliveryEmbed {
            request_hash,
            target_ledger_id,
            target_operator,
        } => {
            assert_eq!(request_hash, [0xAB; 32]);
            assert_eq!(target_ledger_id, [0xCD; 32]);
            assert_eq!(target_operator, test_pubkey());
        }
        other => panic!(
            "Expected DeliveryEmbed, got discriminant {}",
            other.discriminant()
        ),
    }
}

// =========================================================================
// DeliveryEmbed binary roundtrip
// =========================================================================

#[test]
fn delivery_embed_binary_roundtrip() {
    let original = LedgerOperation::DeliveryEmbed {
        request_hash: [0x11; 32],
        target_ledger_id: [0x22; 32],
        target_operator: test_pubkey_2(),
    };

    let mut bytes = Vec::new();
    original.write_to(&mut bytes).unwrap();
    let decoded = LedgerOperation::read_from(&mut Cursor::new(&bytes)).unwrap();

    match decoded {
        LedgerOperation::DeliveryEmbed {
            request_hash,
            target_ledger_id,
            target_operator,
        } => {
            assert_eq!(request_hash, [0x11; 32]);
            assert_eq!(target_ledger_id, [0x22; 32]);
            assert_eq!(target_operator, test_pubkey_2());
        }
        other => panic!(
            "Expected DeliveryEmbed, got discriminant {}",
            other.discriminant()
        ),
    }
}

// =========================================================================
// QuorumAddMember with timing params TLV roundtrip
// =========================================================================

#[test]
fn quorum_add_member_with_timing_params_tlv_roundtrip() {
    let original = LedgerOperation::QuorumAddMember {
        quorum_member: test_pubkey(),
        quorum_member_signature: [0xAA; 64],
        member_ledger_id: "test-ledger-id-123".to_string(),
        min_fee_bps: Some(50),
        min_fee_fixed: Some(1000),
        max_fee_period: Some(2016),
        membership_until: Some(900_000),
        dispute_response_blocks: Some(144),
        dispute_arm_blocks: Some(144),
        service_response_blocks: Some(72),
        max_transfer_timeout_blocks: Some(1008),
        max_descriptor_bytes: Some(500),
        compensation_bps: Some(300),
        compensation_deposit_id: Some([0x11; 16]),
        compensation_frequency_blocks: Some(2016),
    };

    let encoded = original.tlv_encode();
    let decoded = LedgerOperation::tlv_decode(&encoded).unwrap();

    match decoded {
        LedgerOperation::QuorumAddMember {
            quorum_member,
            quorum_member_signature,
            member_ledger_id,
            min_fee_bps,
            min_fee_fixed,
            max_fee_period,
            membership_until,
            dispute_response_blocks,
            dispute_arm_blocks,
            service_response_blocks,
            max_transfer_timeout_blocks,
            max_descriptor_bytes,
            compensation_bps,
            compensation_deposit_id,
            compensation_frequency_blocks,
        } => {
            assert_eq!(quorum_member, test_pubkey());
            assert_eq!(quorum_member_signature, [0xAA; 64]);
            assert_eq!(member_ledger_id, "test-ledger-id-123");
            assert_eq!(min_fee_bps, Some(50));
            assert_eq!(min_fee_fixed, Some(1000));
            assert_eq!(max_fee_period, Some(2016));
            assert_eq!(membership_until, Some(900_000));
            assert_eq!(dispute_response_blocks, Some(144));
            assert_eq!(dispute_arm_blocks, Some(144));
            assert_eq!(service_response_blocks, Some(72));
            assert_eq!(max_transfer_timeout_blocks, Some(1008));
            assert_eq!(max_descriptor_bytes, Some(500));
            assert_eq!(compensation_bps, Some(300));
            assert_eq!(compensation_deposit_id, Some([0x11; 16]));
            assert_eq!(compensation_frequency_blocks, Some(2016));
        }
        other => panic!(
            "Expected QuorumAddMember, got discriminant {}",
            other.discriminant()
        ),
    }
}

// =========================================================================
// QuorumAddMember with None timing params - backward compat
// =========================================================================

#[test]
fn quorum_add_member_none_timing_params_tlv_roundtrip() {
    let original = LedgerOperation::QuorumAddMember {
        quorum_member: test_pubkey_2(),
        quorum_member_signature: [0xBB; 64],
        member_ledger_id: "legacy-ledger".to_string(),
        min_fee_bps: None,
        min_fee_fixed: None,
        max_fee_period: None,
        membership_until: None,
        dispute_response_blocks: None,
        dispute_arm_blocks: None,
        service_response_blocks: None,
        max_transfer_timeout_blocks: None,
        max_descriptor_bytes: None,
        compensation_bps: None,
        compensation_deposit_id: None,
        compensation_frequency_blocks: None,
    };

    let encoded = original.tlv_encode();
    let decoded = LedgerOperation::tlv_decode(&encoded).unwrap();

    match decoded {
        LedgerOperation::QuorumAddMember {
            quorum_member,
            quorum_member_signature,
            member_ledger_id,
            min_fee_bps,
            min_fee_fixed,
            max_fee_period,
            membership_until,
            dispute_response_blocks,
            dispute_arm_blocks,
            service_response_blocks,
            max_transfer_timeout_blocks,
            max_descriptor_bytes,
            compensation_bps,
            compensation_deposit_id,
            compensation_frequency_blocks,
        } => {
            assert_eq!(quorum_member, test_pubkey_2());
            assert_eq!(quorum_member_signature, [0xBB; 64]);
            assert_eq!(member_ledger_id, "legacy-ledger");
            assert_eq!(min_fee_bps, None);
            assert_eq!(min_fee_fixed, None);
            assert_eq!(max_fee_period, None);
            assert_eq!(membership_until, None);
            assert_eq!(dispute_response_blocks, None);
            assert_eq!(dispute_arm_blocks, None);
            assert_eq!(service_response_blocks, None);
            assert_eq!(max_transfer_timeout_blocks, None);
            assert_eq!(max_descriptor_bytes, None);
            assert_eq!(compensation_bps, None);
            assert_eq!(compensation_deposit_id, None);
            assert_eq!(compensation_frequency_blocks, None);
        }
        other => panic!(
            "Expected QuorumAddMember, got discriminant {}",
            other.discriminant()
        ),
    }
}

// =========================================================================
// QuorumAddMember binary roundtrip with timing params
// =========================================================================

#[test]
fn quorum_add_member_binary_roundtrip_with_timing_params() {
    // Note: The legacy binary format only encodes quorum_member, signature, and
    // member_ledger_id. Optional timing/fee fields are NOT carried in the binary
    // wire format -- they are only preserved in the TLV format. The binary decode
    // sets all optional fields to None. This test verifies the core fields survive
    // the roundtrip and that the optional fields degrade gracefully.
    let original = LedgerOperation::QuorumAddMember {
        quorum_member: test_pubkey(),
        quorum_member_signature: [0xCC; 64],
        member_ledger_id: "binary-test-ledger".to_string(),
        min_fee_bps: Some(100),
        min_fee_fixed: Some(2000),
        max_fee_period: Some(4032),
        membership_until: Some(950_000),
        dispute_response_blocks: Some(144),
        dispute_arm_blocks: Some(144),
        service_response_blocks: Some(72),
        max_transfer_timeout_blocks: Some(1008),
        max_descriptor_bytes: Some(500),
        compensation_bps: Some(300),
        compensation_deposit_id: Some([0x22; 16]),
        compensation_frequency_blocks: Some(2016),
    };

    let mut bytes = Vec::new();
    original.write_to(&mut bytes).unwrap();
    let decoded = LedgerOperation::read_from(&mut Cursor::new(&bytes)).unwrap();

    match decoded {
        LedgerOperation::QuorumAddMember {
            quorum_member,
            quorum_member_signature,
            member_ledger_id,
            min_fee_bps,
            min_fee_fixed,
            max_fee_period,
            membership_until,
            dispute_response_blocks,
            dispute_arm_blocks,
            service_response_blocks,
            max_transfer_timeout_blocks,
            max_descriptor_bytes,
            compensation_bps,
            compensation_deposit_id,
            compensation_frequency_blocks,
        } => {
            // Core fields survive the binary roundtrip
            assert_eq!(quorum_member, test_pubkey());
            assert_eq!(quorum_member_signature, [0xCC; 64]);
            assert_eq!(member_ledger_id, "binary-test-ledger");
            // Optional fields are not encoded in legacy binary format
            assert_eq!(min_fee_bps, None);
            assert_eq!(min_fee_fixed, None);
            assert_eq!(max_fee_period, None);
            assert_eq!(membership_until, None);
            assert_eq!(dispute_response_blocks, None);
            assert_eq!(dispute_arm_blocks, None);
            assert_eq!(service_response_blocks, None);
            assert_eq!(max_transfer_timeout_blocks, None);
            assert_eq!(max_descriptor_bytes, None);
            assert_eq!(compensation_bps, None);
            assert_eq!(compensation_deposit_id, None);
            assert_eq!(compensation_frequency_blocks, None);
        }
        other => panic!(
            "Expected QuorumAddMember, got discriminant {}",
            other.discriminant()
        ),
    }
}
