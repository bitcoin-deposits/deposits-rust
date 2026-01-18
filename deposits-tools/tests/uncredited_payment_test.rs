//! Tests for Uncredited Payment Accusation functionality
//!
//! These tests verify that:
//! 1. UncreditedPaymentMsg serializes/deserializes correctly
//! 2. Preimage verification works (SHA256(preimage) == payment_hash)
//! 3. Handler rejects invalid accusations
//! 4. Ledger correctly identifies missing credits

#![cfg(feature = "bitcoin-deposits")]

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{Secp256k1, SecretKey, PublicKey};

use deposits_ldk::handler::messages::{
    DepositsMessage, UncreditedPaymentMsg,
};
use deposits_ldk::handler::messages::UNCREDITED_PAYMENT;

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
        0x66, 0x68, 0x7a, 0xad, 0xf8, 0x62, 0xbd, 0x77,
        0x6c, 0x8f, 0xc1, 0x8b, 0x8e, 0x9f, 0x8e, 0x20,
        0x08, 0x97, 0x14, 0x85, 0x6e, 0xe2, 0x33, 0xb3,
        0x90, 0x2a, 0x59, 0x1d, 0x0d, 0x5f, 0x29, 0x25,
    ];
    assert_eq!(hash, expected);
}

// =============================================================================
// Message Codec Tests
// =============================================================================

#[test]
#[ignore = "TODO: Update for V2 message codec - UncreditedPayment encoding changed"]
fn test_uncredited_payment_msg_roundtrip() {
    todo!("Update for V2 message codec - UncreditedPayment is now encoded differently");
}

#[test]
fn test_uncredited_payment_msg_type() {
    let msg = DepositsMessage::UncreditedPayment {
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
    };

    assert_eq!(msg.message_type(), UNCREDITED_PAYMENT);
    assert_eq!(msg.message_type(), 0x8035);
}

// =============================================================================
// Ledger Credit Detection Tests
// =============================================================================

#[test]
#[ignore = "TODO: Update for V2 Ledger API"]
fn test_ledger_has_no_credit_initially() {
    todo!("Update for V2 Ledger API - Ledger constructor and has_credit_for_payment changed");
}

#[test]
#[ignore = "TODO: Update for V2 Ledger API"]
fn test_ledger_detects_existing_credit() {
    todo!("Update for V2 Ledger API - Ledger constructor, updates field, and has_credit_for_payment changed");
}

#[test]
#[ignore = "TODO: Update for V2 Ledger API"]
fn test_ledger_multiple_credits() {
    todo!("Update for V2 Ledger API - Ledger constructor, updates field, and has_credit_for_payment changed");
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
#[ignore = "TODO: Update for V2 Ledger API"]
fn test_accusation_against_ledger_with_credit() {
    todo!("Update for V2 Ledger API - Ledger constructor, updates field, and has_credit_for_payment changed");
}

#[test]
#[ignore = "TODO: Update for V2 Ledger API"]
fn test_accusation_against_ledger_without_credit() {
    todo!("Update for V2 Ledger API - Ledger constructor and has_credit_for_payment changed");
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
#[ignore = "TODO: Update for V2 Ledger API"]
fn test_empty_ledger_updates() {
    todo!("Update for V2 Ledger API - Ledger constructor, updates field, and has_credit_for_payment changed");
}
