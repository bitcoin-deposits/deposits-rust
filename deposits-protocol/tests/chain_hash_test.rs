//! Tests for the hash chain structure:
//!   current_hash = SHA256(seq || prev_hash || message [|| member_ledger_hash] [|| partner_signature])
//!   chain_hash   = SHA256(current_hash || operator_signature)
//!   next update's previous_hash = chain_hash

use deposits_protocol::types::SignedLedgerUpdate;
use sha2::{Digest, Sha256};

fn test_pubkey() -> bitcoin::secp256k1::PublicKey {
    use std::str::FromStr;
    bitcoin::secp256k1::PublicKey::from_str(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    )
    .unwrap()
}

fn make_update(seq: u64, prev_hash: [u8; 32], message: &[u8]) -> SignedLedgerUpdate {
    let mut u = SignedLedgerUpdate {
        message: message.to_vec(),
        message_type: 1,
        operator_id: test_pubkey(),
        ledger_id: [0x12; 32],
        sequence_number: seq,
        previous_hash: prev_hash,
        current_hash: [0u8; 32],
        block_height: 0,
        block_hash: [0u8; 32],
        partner_signature: [0u8; 64],
        operator_signature: [0u8; 64],
        cosigner_pubkey: None,
        member_ledger_hash: None,
    };
    u.current_hash = u.compute_hash();
    u
}

// =========================================================================
// current_hash structure
// =========================================================================

#[test]
fn current_hash_without_signatures_is_content_only() {
    let u = make_update(0, [0u8; 32], &[1, 2, 3]);

    let mut h = Sha256::new();
    h.update(&0u64.to_le_bytes());
    h.update(&[0u8; 32]);
    h.update(&[1u8, 2, 3]);
    let expected: [u8; 32] = h.finalize().into();

    assert_eq!(u.current_hash, expected);
}

#[test]
fn current_hash_with_partner_signature() {
    let mut u = make_update(0, [0u8; 32], &[1, 2, 3]);
    let hash_before = u.current_hash;

    u.partner_signature = [0xAA; 64];
    u.current_hash = u.compute_hash();

    assert_ne!(u.current_hash, hash_before);

    // Verify manually
    let mut h = Sha256::new();
    h.update(&0u64.to_le_bytes());
    h.update(&[0u8; 32]);
    h.update(&[1u8, 2, 3]);
    h.update(&[0xAA; 64]);
    let expected: [u8; 32] = h.finalize().into();

    assert_eq!(u.current_hash, expected);
}

#[test]
fn current_hash_with_member_ledger_hash_and_partner_signature() {
    let mut u = make_update(0, [0u8; 32], &[1, 2, 3]);

    u.member_ledger_hash = Some([0xBB; 32]);
    u.partner_signature = [0xCC; 64];
    u.current_hash = u.compute_hash();

    let mut h = Sha256::new();
    h.update(&0u64.to_le_bytes());
    h.update(&[0u8; 32]);
    h.update(&[1u8, 2, 3]);
    h.update(&[0xBB; 32]);
    h.update(&[0xCC; 64]);
    let expected: [u8; 32] = h.finalize().into();

    assert_eq!(u.current_hash, expected);
}

// =========================================================================
// chain_hash structure
// =========================================================================

#[test]
fn chain_hash_is_sha256_current_hash_plus_operator_sig() {
    let mut u = make_update(0, [0u8; 32], &[1, 2, 3]);
    u.operator_signature = [0xDD; 64];

    let mut h = Sha256::new();
    h.update(&u.current_hash);
    h.update(&[0xDD; 64]);
    let expected: [u8; 32] = h.finalize().into();

    assert_eq!(u.chain_hash(), expected);
}

#[test]
fn chain_hash_differs_from_current_hash() {
    let mut u = make_update(0, [0u8; 32], &[1, 2, 3]);
    u.operator_signature = [0xEE; 64];
    assert_ne!(u.chain_hash(), u.current_hash);
}

#[test]
fn chain_hash_with_zero_operator_sig_still_differs() {
    let u = make_update(0, [0u8; 32], &[1, 2, 3]);
    // Even with zero sig, chain_hash wraps current_hash
    assert_ne!(u.chain_hash(), u.current_hash);
}

// =========================================================================
// Multi-update chain linkage
// =========================================================================

#[test]
fn two_update_chain_links_via_chain_hash() {
    let mut u0 = make_update(0, [0u8; 32], &[10, 20]);
    u0.operator_signature = [0x11; 64];

    // Next update's previous_hash = u0.chain_hash()
    let u1 = make_update(1, u0.chain_hash(), &[30, 40]);

    assert_eq!(u1.previous_hash, u0.chain_hash());
    assert_ne!(u1.previous_hash, u0.current_hash); // not current_hash!
}

#[test]
fn three_update_chain_with_signatures() {
    // Build a 3-update chain with distinct signatures
    let mut u0 = make_update(0, [0u8; 32], &[1]);
    u0.partner_signature = [0xA1; 64];
    u0.current_hash = u0.compute_hash();
    u0.operator_signature = [0xA2; 64];

    let mut u1 = make_update(1, u0.chain_hash(), &[2]);
    u1.partner_signature = [0xB1; 64];
    u1.current_hash = u1.compute_hash();
    u1.operator_signature = [0xB2; 64];

    let mut u2 = make_update(2, u1.chain_hash(), &[3]);
    u2.partner_signature = [0xC1; 64];
    u2.current_hash = u2.compute_hash();
    u2.operator_signature = [0xC2; 64];

    // Verify chain linkage
    assert_eq!(u1.previous_hash, u0.chain_hash());
    assert_eq!(u2.previous_hash, u1.chain_hash());

    // Verify each current_hash includes partner_signature
    assert!(u0.verify_hash());
    assert!(u1.verify_hash());
    assert!(u2.verify_hash());

    // All hashes are distinct
    assert_ne!(u0.current_hash, u1.current_hash);
    assert_ne!(u1.current_hash, u2.current_hash);
    assert_ne!(u0.chain_hash(), u1.chain_hash());
    assert_ne!(u1.chain_hash(), u2.chain_hash());
}

#[test]
fn chain_with_cosigned_and_unsigned_updates() {
    // u0: unsigned (no partner sig, no member hash)
    let mut u0 = make_update(0, [0u8; 32], &[1]);
    u0.operator_signature = [0x01; 64];

    // u1: co-signed (has member_ledger_hash + partner_signature)
    let mut u1 = make_update(1, u0.chain_hash(), &[2]);
    u1.member_ledger_hash = Some([0xAA; 32]);
    u1.partner_signature = [0xBB; 64];
    u1.current_hash = u1.compute_hash();
    u1.operator_signature = [0x02; 64];

    // u2: unsigned again
    let mut u2 = make_update(2, u1.chain_hash(), &[3]);
    u2.operator_signature = [0x03; 64];

    // Chain links correctly through both types
    assert_eq!(u1.previous_hash, u0.chain_hash());
    assert_eq!(u2.previous_hash, u1.chain_hash());

    // u1's current_hash includes member_ledger_hash + partner_signature
    let mut h = Sha256::new();
    h.update(&1u64.to_le_bytes());
    h.update(&u0.chain_hash());
    h.update(&[2u8]);
    h.update(&[0xAA; 32]);
    h.update(&[0xBB; 64]);
    let expected: [u8; 32] = h.finalize().into();
    assert_eq!(u1.current_hash, expected);

    // u1's chain_hash folds in operator sig
    let mut h2 = Sha256::new();
    h2.update(&u1.current_hash);
    h2.update(&[0x02; 64]);
    let expected_chain: [u8; 32] = h2.finalize().into();
    assert_eq!(u1.chain_hash(), expected_chain);
    assert_eq!(u2.previous_hash, expected_chain);
}

// =========================================================================
// Tampering detection
// =========================================================================

#[test]
fn changing_operator_signature_changes_chain_hash() {
    let mut u = make_update(0, [0u8; 32], &[1, 2, 3]);
    u.operator_signature = [0x11; 64];
    let h1 = u.chain_hash();

    u.operator_signature = [0x22; 64];
    let h2 = u.chain_hash();

    assert_ne!(h1, h2);
}

#[test]
fn changing_partner_signature_changes_current_hash() {
    let mut u = make_update(0, [0u8; 32], &[1, 2, 3]);
    u.partner_signature = [0x11; 64];
    u.current_hash = u.compute_hash();
    let h1 = u.current_hash;

    u.partner_signature = [0x22; 64];
    u.current_hash = u.compute_hash();
    let h2 = u.current_hash;

    assert_ne!(h1, h2);
}

#[test]
fn swapping_cosigner_breaks_chain() {
    // Build u0 → u1 chain
    let mut u0 = make_update(0, [0u8; 32], &[1]);
    u0.partner_signature = [0xAA; 64];
    u0.current_hash = u0.compute_hash();
    u0.operator_signature = [0x01; 64];

    let u1 = make_update(1, u0.chain_hash(), &[2]);

    // Now swap the cosigner on u0
    u0.partner_signature = [0xFF; 64];
    u0.current_hash = u0.compute_hash();
    // u0.chain_hash() has changed, so u1.previous_hash no longer matches
    assert_ne!(u1.previous_hash, u0.chain_hash());
}

#[test]
fn swapping_operator_sig_breaks_chain() {
    let mut u0 = make_update(0, [0u8; 32], &[1]);
    u0.operator_signature = [0x01; 64];

    let u1 = make_update(1, u0.chain_hash(), &[2]);

    // Swap operator sig on u0
    u0.operator_signature = [0xFF; 64];
    assert_ne!(u1.previous_hash, u0.chain_hash());
}
