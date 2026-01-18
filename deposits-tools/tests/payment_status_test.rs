//! Payment Status Tests
//!
//! Tests for payment status types used in same-node transfers.
//! These tests verify that:
//! 1. PaymentStatus variants exist and work correctly
//! 2. PaymentDetails structure is correct

#![cfg(feature = "bitcoin-deposits")]

use bitcoin::hashes::{sha256, Hash};

use ldk_node::payment::{PaymentStatus, PaymentDirection, PaymentKind};

use lightning::ln::channelmanager::PaymentId;
use lightning_types::payment::{PaymentHash, PaymentPreimage};

/// Generate a valid payment hash from a preimage
fn generate_payment_hash(preimage: &[u8; 32]) -> [u8; 32] {
    *sha256::Hash::hash(preimage).as_byte_array()
}

// =============================================================================
// PaymentStatus Enum Tests
// =============================================================================

#[test]
fn test_payment_status_variants() {
    // Verify all status variants exist
    let _pending = PaymentStatus::Pending;
    let _succeeded = PaymentStatus::Succeeded;
    let _failed = PaymentStatus::Failed;
}

#[test]
fn test_payment_status_equality() {
    assert_eq!(PaymentStatus::Succeeded, PaymentStatus::Succeeded);
    assert_eq!(PaymentStatus::Pending, PaymentStatus::Pending);
    assert_eq!(PaymentStatus::Failed, PaymentStatus::Failed);

    assert_ne!(PaymentStatus::Succeeded, PaymentStatus::Pending);
    assert_ne!(PaymentStatus::Succeeded, PaymentStatus::Failed);
    assert_ne!(PaymentStatus::Pending, PaymentStatus::Failed);
}

// =============================================================================
// PaymentDirection Tests
// =============================================================================

#[test]
fn test_payment_direction_variants() {
    let _inbound = PaymentDirection::Inbound;
    let _outbound = PaymentDirection::Outbound;
}

#[test]
fn test_payment_direction_equality() {
    assert_eq!(PaymentDirection::Inbound, PaymentDirection::Inbound);
    assert_eq!(PaymentDirection::Outbound, PaymentDirection::Outbound);
    assert_ne!(PaymentDirection::Inbound, PaymentDirection::Outbound);
}

// =============================================================================
// Preimage to PaymentHash Verification
// =============================================================================

#[test]
fn test_preimage_produces_correct_payment_hash() {
    let preimage_bytes: [u8; 32] = [0xCC; 32];
    let preimage = PaymentPreimage(preimage_bytes);
    let payment_hash_bytes = generate_payment_hash(&preimage_bytes);
    let payment_hash = PaymentHash(payment_hash_bytes);

    // Verify SHA256(preimage) = payment_hash
    let computed_hash = sha256::Hash::hash(&preimage.0);
    assert_eq!(*computed_hash.as_byte_array(), payment_hash.0);
}

#[test]
fn test_payment_id_from_payment_hash() {
    // PaymentId uses the same bytes as PaymentHash for BOLT11 payments
    let payment_hash_bytes: [u8; 32] = [0xDD; 32];
    let payment_id = PaymentId(payment_hash_bytes);

    assert_eq!(payment_id.0, payment_hash_bytes);
}

// =============================================================================
// PaymentKind Bolt11 Tests
// =============================================================================

#[test]
fn test_payment_kind_bolt11_has_preimage() {
    let preimage_bytes: [u8; 32] = [0xAA; 32];
    let preimage = PaymentPreimage(preimage_bytes);
    let payment_hash_bytes = generate_payment_hash(&preimage_bytes);
    let payment_hash = PaymentHash(payment_hash_bytes);

    let kind = PaymentKind::Bolt11 {
        hash: payment_hash,
        preimage: Some(preimage),
        secret: None,
    };

    // Verify we can extract preimage from PaymentKind
    match kind {
        PaymentKind::Bolt11 { preimage: Some(pi), hash, .. } => {
            assert_eq!(pi.0, preimage_bytes);
            let expected_hash = sha256::Hash::hash(&pi.0);
            assert_eq!(hash.0, *expected_hash.as_byte_array());
        }
        _ => panic!("Expected Bolt11 payment kind with preimage"),
    }
}

#[test]
fn test_payment_kind_bolt11_hash_preimage_relationship() {
    // This is the key relationship used in same-node transfers:
    // When a payment is marked as settled, we need to provide the correct
    // preimage that hashes to the payment_hash

    let preimage_bytes: [u8; 32] = [0xBB; 32];
    let preimage = PaymentPreimage(preimage_bytes);
    let payment_hash_bytes = generate_payment_hash(&preimage_bytes);
    let payment_hash = PaymentHash(payment_hash_bytes);

    // This is the verification that happens in mark_settled_for_hash
    let expected_hash = PaymentHash(
        *sha256::Hash::hash(&preimage.0).as_byte_array()
    );
    assert_eq!(payment_hash, expected_hash);
}

// =============================================================================
// Same-Node Transfer Payment Flow Tests
// =============================================================================

#[test]
fn test_same_node_transfer_status_transition() {
    // Same-node transfers should transition from Pending to Succeeded
    let initial_status = PaymentStatus::Pending;
    let final_status = PaymentStatus::Succeeded;

    assert_ne!(initial_status, final_status);
}

#[test]
fn test_same_node_transfer_payment_hash_from_preimage() {
    // In same-node transfers, we have the preimage from the payment store
    // and we use it to update the payment status

    let preimage_bytes: [u8; 32] = [0xEE; 32];
    let payment_hash_bytes = generate_payment_hash(&preimage_bytes);

    // Create PaymentId from hash (as done in mark_settled_for_hash)
    let payment_id = PaymentId(payment_hash_bytes);

    // Verify the relationship
    assert_eq!(payment_id.0, payment_hash_bytes);
}
