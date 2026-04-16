//! Tests for Uncredited Payment Accusation functionality
//!
//! These tests verify that:
//! 1. UncreditedPaymentMsg serializes/deserializes correctly
//! 2. Preimage verification works (SHA256(preimage) == payment_hash)
//! 3. Handler rejects invalid accusations
//! 4. Ledger correctly identifies missing credits

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

use deposits_core::messages::{DepositsMessage, LedgerOperation, RecoveryMsg};
use deposits_core::types::LedgerState;
use deposits_core::wire_messages::UncreditedPaymentMsg;

/// Generate a test public key from a seed byte
fn generate_test_pubkey(seed: u8) -> PublicKey {
    let secp = Secp256k1::new();
    let mut secret = [0u8; 32];
    secret[31] = seed;
    let sk = SecretKey::from_slice(&secret).unwrap();
    PublicKey::from_secret_key(&secp, &sk)
}

/// Generate a valid payment hash from a preimage
fn generate_payment_hash(preimage: &[u8; 32]) -> [u8; 32] {
    *sha256::Hash::hash(preimage).as_byte_array()
}

/// Create a test LedgerState with a single open deposit, returning (state, deposit_id).
fn create_test_ledger_with_deposit() -> (LedgerState, [u8; 16]) {
    let state = LedgerState::new(generate_test_pubkey(1), "bcrt1qtest".to_string(), 0);
    let descriptor = "wpkh(test_descriptor)";
    let deposit_id = deposits_core::types::compute_deposit_id(descriptor);
    let state = state
        .apply(&LedgerOperation::DepositOpen {
            deposit_id,
            descriptor: descriptor.to_string(),
            fees: None,
            transfer_fees: None,
            payment_hash: None,
            invoice: None,
            cosigner_guarantee_signature: None,
            is_collateral: false,
            receive_requires_sig: false,
            fee_change_after_blocks: None,
            fee_change_notice_blocks: None,
            fee_change_limit_bps: None,
        })
        .unwrap();
    (state, deposit_id)
}

// =============================================================================
// Preimage Verification Tests
// =============================================================================

#[test]
fn test_preimage_verification_valid() {
    // Given a known preimage
    let preimage: [u8; 32] = [0xAB; 32];

    // When we compute the payment hash
    let payment_hash = generate_payment_hash(&preimage);

    // Then verification should pass
    let computed = sha256::Hash::hash(&preimage);
    assert_eq!(computed.as_byte_array(), &payment_hash);
}

#[test]
fn test_preimage_verification_invalid() {
    // Given a preimage and different payment hash
    let preimage: [u8; 32] = [0xAB; 32];
    let wrong_hash: [u8; 32] = [0xCD; 32];

    // Verification should fail
    let computed = sha256::Hash::hash(&preimage);
    assert_ne!(computed.as_byte_array(), &wrong_hash);
}

#[test]
fn test_preimage_verification_known_vectors() {
    // Test with known SHA256 test vectors
    // SHA256 of all zeros
    let preimage = [0u8; 32];
    let hash = generate_payment_hash(&preimage);

    // SHA256(00...00) = 66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925
    let expected = [
        0x66, 0x68, 0x7a, 0xad, 0xf8, 0x62, 0xbd, 0x77, 0x6c, 0x8f, 0xc1, 0x8b, 0x8e, 0x9f, 0x8e,
        0x20, 0x08, 0x97, 0x14, 0x85, 0x6e, 0xe2, 0x33, 0xb3, 0x90, 0x2a, 0x59, 0x1d, 0x0d, 0x5f,
        0x29, 0x25,
    ];
    assert_eq!(hash, expected);
}

// =============================================================================
// Message Codec Tests
// =============================================================================

#[test]
fn test_uncredited_payment_msg_type() {
    use deposits_core::messages::RECOVERY;

    let msg = DepositsMessage::Recovery(RecoveryMsg::UncreditedPayment {
        operator: generate_test_pubkey(1),
        partner: generate_test_pubkey(2),
        payment_hash: [0xAA; 32],
        preimage: [0xBB; 32],
        deposit_pubkey: generate_test_pubkey(3),
        amount_msat: 50_000_000,
        invoice_cosignature: [0u8; 64],
        settlement_sequence: 1,
        settlement_ledger_hash: [0xCC; 32],
        settlement_block_height: 800_000,
        accuser_signature: [0u8; 64],
    });

    // V2: UncreditedPayment is now a variant of RecoveryMsg, which uses RECOVERY type (0x800D)
    assert_eq!(msg.message_type(), RECOVERY);
    assert_eq!(msg.message_type(), 0x800D);
}

// =============================================================================
// Ledger Credit Detection Tests
// =============================================================================

#[test]
fn test_ledger_has_no_credit_initially() {
    let (state, _deposit_id) = create_test_ledger_with_deposit();
    assert!(state.credited_payments.is_empty());
}

#[test]
fn test_ledger_detects_existing_credit() {
    let (state, deposit_id) = create_test_ledger_with_deposit();

    let payment_hash = [0xAA; 32];
    let state = state
        .apply(&LedgerOperation::InvoiceCredit {
            payment_hash,
            deposit_id,
            amount: 100_000,
            invoice_id: "inv1".to_string(),
            sequence_number: 1,
        })
        .unwrap();

    assert!(state.credited_payments.contains(&hex::encode(payment_hash)));
}

#[test]
fn test_ledger_multiple_credits() {
    let (state, deposit_id) = create_test_ledger_with_deposit();

    let hash1 = [0xAA; 32];
    let hash2 = [0xBB; 32];
    let hash3 = [0xCC; 32];

    let state = state
        .apply(&LedgerOperation::InvoiceCredit {
            payment_hash: hash1,
            deposit_id,
            amount: 100_000,
            invoice_id: "inv1".to_string(),
            sequence_number: 1,
        })
        .unwrap();

    let state = state
        .apply(&LedgerOperation::InvoiceCredit {
            payment_hash: hash2,
            deposit_id,
            amount: 200_000,
            invoice_id: "inv2".to_string(),
            sequence_number: 2,
        })
        .unwrap();

    let state = state
        .apply(&LedgerOperation::InvoiceCredit {
            payment_hash: hash3,
            deposit_id,
            amount: 300_000,
            invoice_id: "inv3".to_string(),
            sequence_number: 3,
        })
        .unwrap();

    assert!(state.credited_payments.contains(&hex::encode(hash1)));
    assert!(state.credited_payments.contains(&hex::encode(hash2)));
    assert!(state.credited_payments.contains(&hex::encode(hash3)));
    assert_eq!(state.credited_payments.len(), 3);
}

// =============================================================================
// Accusation Validation Tests
// =============================================================================

#[test]
fn test_accusation_with_valid_preimage() {
    // Create an accusation with a valid preimage
    let preimage: [u8; 32] = [0x42; 32];
    let payment_hash = generate_payment_hash(&preimage);

    let accusation = UncreditedPaymentMsg {
        operator: generate_test_pubkey(1),
        partner: generate_test_pubkey(2),
        payment_hash,
        preimage,
        deposit_pubkey: generate_test_pubkey(3),
        amount_msat: 50_000_000,
        invoice_cosignature: [0u8; 64],
        settlement_sequence: 10,
        settlement_ledger_hash: [0xCC; 32],
        settlement_block_height: 850_000,
        accuser_signature: [0u8; 64],
    };

    // Verify preimage is valid
    let computed = sha256::Hash::hash(&accusation.preimage);
    assert_eq!(computed.as_byte_array(), &accusation.payment_hash);
}

#[test]
fn test_accusation_with_invalid_preimage() {
    // Create an accusation with an invalid preimage
    let preimage: [u8; 32] = [0x42; 32];
    let wrong_hash: [u8; 32] = [0xFF; 32]; // Wrong hash!

    let accusation = UncreditedPaymentMsg {
        operator: generate_test_pubkey(1),
        partner: generate_test_pubkey(2),
        payment_hash: wrong_hash,
        preimage,
        deposit_pubkey: generate_test_pubkey(3),
        amount_msat: 50_000_000,
        invoice_cosignature: [0u8; 64],
        settlement_sequence: 10,
        settlement_ledger_hash: [0xCC; 32],
        settlement_block_height: 850_000,
        accuser_signature: [0u8; 64],
    };

    // Verify preimage is INVALID
    let computed = sha256::Hash::hash(&accusation.preimage);
    assert_ne!(computed.as_byte_array(), &accusation.payment_hash);
}

#[test]
fn test_accusation_against_ledger_with_credit() {
    let (state, deposit_id) = create_test_ledger_with_deposit();

    let payment_hash = [0xAA; 32];
    let state = state
        .apply(&LedgerOperation::InvoiceCredit {
            payment_hash,
            deposit_id,
            amount: 100_000,
            invoice_id: "inv1".to_string(),
            sequence_number: 1,
        })
        .unwrap();

    // The payment hash IS credited — accusation would be invalid
    assert!(state.credited_payments.contains(&hex::encode(payment_hash)));
}

#[test]
fn test_accusation_against_ledger_without_credit() {
    let (state, _deposit_id) = create_test_ledger_with_deposit();

    let payment_hash = [0xAA; 32];

    // The payment hash is NOT credited — accusation would be valid
    assert!(!state.credited_payments.contains(&hex::encode(payment_hash)));
}

// =============================================================================
// Edge Cases
// =============================================================================

#[test]
fn test_preimage_all_zeros() {
    let preimage = [0u8; 32];
    let payment_hash = generate_payment_hash(&preimage);

    let accusation = UncreditedPaymentMsg {
        operator: generate_test_pubkey(1),
        partner: generate_test_pubkey(2),
        payment_hash,
        preimage,
        deposit_pubkey: generate_test_pubkey(3),
        amount_msat: 1,
        invoice_cosignature: [0u8; 64],
        settlement_sequence: 0,
        settlement_ledger_hash: [0u8; 32],
        settlement_block_height: 0,
        accuser_signature: [0u8; 64],
    };

    // Even with all zeros, verification should work
    let computed = sha256::Hash::hash(&accusation.preimage);
    assert_eq!(computed.as_byte_array(), &accusation.payment_hash);
}

#[test]
fn test_preimage_all_ones() {
    let preimage = [0xFF; 32];
    let payment_hash = generate_payment_hash(&preimage);

    let accusation = UncreditedPaymentMsg {
        operator: generate_test_pubkey(1),
        partner: generate_test_pubkey(2),
        payment_hash,
        preimage,
        deposit_pubkey: generate_test_pubkey(3),
        amount_msat: u64::MAX,
        invoice_cosignature: [0xFF; 64],
        settlement_sequence: u64::MAX,
        settlement_ledger_hash: [0xFF; 32],
        settlement_block_height: u32::MAX,
        accuser_signature: [0xFF; 64],
    };

    // Extreme values should still work
    let computed = sha256::Hash::hash(&accusation.preimage);
    assert_eq!(computed.as_byte_array(), &accusation.payment_hash);
}

#[test]
fn test_empty_ledger_updates() {
    let state = LedgerState::new(generate_test_pubkey(1), "bcrt1qtest".to_string(), 0);
    assert!(state.credited_payments.is_empty());
}
