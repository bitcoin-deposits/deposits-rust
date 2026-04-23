//! Tests for obligation limits and state changes from audit-related operations.
//!
//! Covers:
//! - QuorumBegin storing total_collateral and quorum_expiry on LedgerState
//! - DeliveryEmbed applying without side effects
//! - QuorumMember timing field serialization/deserialization

use deposits_core::ledger::{Ledger, LedgerRole};
use deposits_core::messages::LedgerOperation;
use deposits_core::types::{LedgerState, QuorumMember};

fn test_pubkey() -> bitcoin::secp256k1::PublicKey {
    use std::str::FromStr;
    bitcoin::secp256k1::PublicKey::from_str(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    )
    .unwrap()
}

fn test_pubkey_2() -> bitcoin::secp256k1::PublicKey {
    use std::str::FromStr;
    bitcoin::secp256k1::PublicKey::from_str(
        "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
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

// =========================================================================
// total_collateral() returns collateral_amount from state
// =========================================================================

#[test]
fn total_collateral_returns_collateral_amount() {
    let ledger = make_ledger();
    // Default collateral_amount is 0
    assert_eq!(ledger.state.total_collateral(), 0);
}

// =========================================================================
// QuorumBegin stores quorum_expiry on state
// =========================================================================

#[test]
fn quorum_begin_stores_quorum_expiry() {
    let mut ledger = make_ledger();

    ledger
        .apply_state_changes(&LedgerOperation::QuorumBegin {
            reserves_id: "tb1qtest_taproot".to_string(),
            spending_txid: [0u8; 32],
            new_outpoint_txid: [0u8; 32],
            new_outpoint_vout: 0,
            amount: 1_000_000,
            quorum_expiry: 100_000,
            ledger_hash: [0u8; 32],
            quorum_members: vec![],
            collateral_amount: 500_000,
        })
        .unwrap();

    assert_eq!(ledger.state.quorum_expiry, Some(100_000));
}

#[test]
fn quorum_begin_updates_reserves_key_and_amount() {
    let mut ledger = make_ledger();

    ledger
        .apply_state_changes(&LedgerOperation::QuorumBegin {
            reserves_id: "tb1p_new_taproot_addr".to_string(),
            spending_txid: [0u8; 32],
            new_outpoint_txid: [0u8; 32],
            new_outpoint_vout: 0,
            amount: 2_000_000,
            quorum_expiry: 100_000,
            ledger_hash: [0u8; 32],
            quorum_members: vec![],
            collateral_amount: 500_000,
        })
        .unwrap();

    assert_eq!(ledger.state.reserves_key, "tb1p_new_taproot_addr");
    assert_eq!(ledger.state.reserves_amount, 2_000_000);
}

#[test]
fn quorum_begin_overwrites_previous_values() {
    let mut ledger = make_ledger();

    // First QuorumBegin
    ledger
        .apply_state_changes(&LedgerOperation::QuorumBegin {
            reserves_id: "tb1p_first".to_string(),
            spending_txid: [0u8; 32],
            new_outpoint_txid: [0u8; 32],
            new_outpoint_vout: 0,
            amount: 1_000_000,
            quorum_expiry: 100_000,
            ledger_hash: [0u8; 32],
            quorum_members: vec![],
            collateral_amount: 500_000,
        })
        .unwrap();

    assert_eq!(ledger.state.quorum_expiry, Some(100_000));

    // Second QuorumBegin overwrites
    ledger
        .apply_state_changes(&LedgerOperation::QuorumBegin {
            reserves_id: "tb1p_second".to_string(),
            spending_txid: [1u8; 32],
            new_outpoint_txid: [1u8; 32],
            new_outpoint_vout: 1,
            amount: 3_000_000,
            quorum_expiry: 200_000,
            ledger_hash: [1u8; 32],
            quorum_members: vec![],
            collateral_amount: 750_000,
        })
        .unwrap();

    assert_eq!(ledger.state.quorum_expiry, Some(200_000));
    assert_eq!(ledger.state.reserves_key, "tb1p_second");
    assert_eq!(ledger.state.reserves_amount, 3_000_000);
}

// =========================================================================
// DeliveryEmbed applies without state changes
// =========================================================================

#[test]
fn delivery_embed_no_state_changes() {
    let mut ledger = make_ledger();

    // Open a deposit so we have some state to verify doesn't change
    let deposit_id = deposits_core::types::compute_deposit_id("pk(test_deposit)");
    ledger
        .apply_state_changes(&LedgerOperation::DepositOpen {
            deposit_id,
            descriptor: "pk(test_deposit)".to_string(),
            fees: None,
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

    let deposit_count = ledger.state.deposits.len();
    let reserves_amount = ledger.state.reserves_amount;
    let total_collateral = ledger.state.total_collateral();
    let quorum_expiry = ledger.state.quorum_expiry;
    let reserves_key = ledger.state.reserves_key.clone();

    // Apply DeliveryEmbed
    ledger
        .apply_state_changes(&LedgerOperation::DeliveryEmbed {
            request_hash: [0xABu8; 32],
            target_ledger_id: [0xCDu8; 32],
            target_operator: test_pubkey_2(),
        })
        .unwrap();

    // Verify nothing changed
    assert_eq!(ledger.state.deposits.len(), deposit_count);
    assert_eq!(ledger.state.reserves_amount, reserves_amount);
    assert_eq!(ledger.state.total_collateral(), total_collateral);
    assert_eq!(ledger.state.quorum_expiry, quorum_expiry);
    assert_eq!(ledger.state.reserves_key, reserves_key);
}

#[test]
fn delivery_embed_on_empty_ledger() {
    let mut ledger = make_ledger();

    // DeliveryEmbed should succeed even with no deposits
    ledger
        .apply_state_changes(&LedgerOperation::DeliveryEmbed {
            request_hash: [0x11u8; 32],
            target_ledger_id: [0x22u8; 32],
            target_operator: test_pubkey_2(),
        })
        .unwrap();

    assert!(ledger.state.deposits.is_empty());
}

// =========================================================================
// QuorumMember timing fields serialize/deserialize
// =========================================================================

#[test]
fn quorum_member_timing_fields_roundtrip() {
    let member = QuorumMember {
        pubkey: test_pubkey_2(),
        ledger_id: "test_ledger_id".to_string(),
        min_fee_bps: None,
        min_fee_fixed: None,
        max_fee_period: None,
        membership_until: Some(50_000),
        dispute_response_blocks: Some(144),
        dispute_arm_blocks: Some(288),
        service_response_blocks: Some(72),
        max_transfer_timeout_blocks: Some(1008),
        max_descriptor_bytes: Some(256),
        compensation_bps: None,
        compensation_deposit_id: None,
        compensation_frequency_blocks: None,
    };

    let json = serde_json::to_string(&member).unwrap();
    let decoded: QuorumMember = serde_json::from_str(&json).unwrap();

    assert_eq!(member, decoded);
    assert_eq!(decoded.dispute_response_blocks, Some(144));
    assert_eq!(decoded.dispute_arm_blocks, Some(288));
    assert_eq!(decoded.service_response_blocks, Some(72));
    assert_eq!(decoded.max_transfer_timeout_blocks, Some(1008));
    assert_eq!(decoded.max_descriptor_bytes, Some(256));
    assert_eq!(decoded.membership_until, Some(50_000));
}

// =========================================================================
// QuorumMember timing fields default to None (skip_serializing_if)
// =========================================================================

#[test]
fn quorum_member_timing_fields_default_to_none() {
    let member = QuorumMember {
        pubkey: test_pubkey_2(),
        ledger_id: "test_ledger_id".to_string(),
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

    let json = serde_json::to_string(&member).unwrap();

    // Verify skip_serializing_if = "Option::is_none" is working:
    // None fields should NOT appear in the serialized JSON
    assert!(
        !json.contains("dispute_response_blocks"),
        "None field should be skipped: {}",
        json
    );
    assert!(
        !json.contains("dispute_arm_blocks"),
        "None field should be skipped: {}",
        json
    );
    assert!(
        !json.contains("service_response_blocks"),
        "None field should be skipped: {}",
        json
    );
    assert!(
        !json.contains("max_transfer_timeout_blocks"),
        "None field should be skipped: {}",
        json
    );
    assert!(
        !json.contains("max_descriptor_bytes"),
        "None field should be skipped: {}",
        json
    );
    assert!(
        !json.contains("membership_until"),
        "None field should be skipped: {}",
        json
    );

    // Deserialize back and verify all None
    let decoded: QuorumMember = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.dispute_response_blocks, None);
    assert_eq!(decoded.dispute_arm_blocks, None);
    assert_eq!(decoded.service_response_blocks, None);
    assert_eq!(decoded.max_transfer_timeout_blocks, None);
    assert_eq!(decoded.max_descriptor_bytes, None);
    assert_eq!(decoded.membership_until, None);
}

#[test]
fn quorum_member_missing_timing_fields_deserialize_as_none() {
    // Serialize a minimal QuorumMember, then strip optional fields to simulate
    // JSON from an older version that doesn't include timing fields.
    let member = QuorumMember {
        pubkey: test_pubkey_2(),
        ledger_id: "old_format".to_string(),
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

    // Serialize to JSON (skip_serializing_if removes None fields)
    let json = serde_json::to_string(&member).unwrap();

    // Verify the JSON only has pubkey and ledger_id
    assert!(!json.contains("dispute_response_blocks"));

    // Deserialize back — all optional fields should default to None
    let decoded: QuorumMember = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.ledger_id, "old_format");
    assert_eq!(decoded.dispute_response_blocks, None);
    assert_eq!(decoded.dispute_arm_blocks, None);
    assert_eq!(decoded.service_response_blocks, None);
    assert_eq!(decoded.max_transfer_timeout_blocks, None);
    assert_eq!(decoded.max_descriptor_bytes, None);
    assert_eq!(decoded.min_fee_bps, None);
    assert_eq!(decoded.min_fee_fixed, None);
    assert_eq!(decoded.max_fee_period, None);
    assert_eq!(decoded.membership_until, None);
}
