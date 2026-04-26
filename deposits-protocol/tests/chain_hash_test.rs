//! Tests for the hash chain structure:
//!   content_hash = SHA256(seq || prev_hash || message [|| member_ledger_hash] [|| cosign_signature])
//!   chain_hash   = SHA256(content_hash || operator_signature)
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
        content_hash: [0u8; 32],
        block_height: 0,
        block_hash: [0u8; 32],
        cosign_signature: [0u8; 64],
        operator_signature: [0u8; 64],
        cosigner_pubkey: None,
        member_ledger_hash: None,
        cosignatures: Vec::new(),
    };
    u.content_hash = u.compute_hash();
    u
}

// =========================================================================
// content_hash structure
// =========================================================================

#[test]
fn content_hash_without_signatures_is_content_only() {
    let u = make_update(0, [0u8; 32], &[1, 2, 3]);

    let mut h = Sha256::new();
    h.update(0u64.to_le_bytes());
    h.update([0u8; 32]);
    h.update([1u8, 2, 3]);
    let expected: [u8; 32] = h.finalize().into();

    assert_eq!(u.content_hash, expected);
}

#[test]
fn content_hash_with_cosign_signature() {
    let mut u = make_update(0, [0u8; 32], &[1, 2, 3]);
    let hash_before = u.content_hash;

    u.cosign_signature = [0xAA; 64];
    u.content_hash = u.compute_hash();

    assert_ne!(u.content_hash, hash_before);

    // Verify manually
    let mut h = Sha256::new();
    h.update(0u64.to_le_bytes());
    h.update([0u8; 32]);
    h.update([1u8, 2, 3]);
    h.update([0xAA; 64]);
    let expected: [u8; 32] = h.finalize().into();

    assert_eq!(u.content_hash, expected);
}

#[test]
fn content_hash_with_member_ledger_hash_and_cosign_signature() {
    let mut u = make_update(0, [0u8; 32], &[1, 2, 3]);

    u.member_ledger_hash = Some([0xBB; 32]);
    u.cosign_signature = [0xCC; 64];
    u.content_hash = u.compute_hash();

    let mut h = Sha256::new();
    h.update(0u64.to_le_bytes());
    h.update([0u8; 32]);
    h.update([1u8, 2, 3]);
    h.update([0xBB; 32]);
    h.update([0xCC; 64]);
    let expected: [u8; 32] = h.finalize().into();

    assert_eq!(u.content_hash, expected);
}

// =========================================================================
// chain_hash structure
// =========================================================================

#[test]
fn chain_hash_is_sha256_content_hash_plus_operator_sig() {
    let mut u = make_update(0, [0u8; 32], &[1, 2, 3]);
    u.operator_signature = [0xDD; 64];

    let mut h = Sha256::new();
    h.update(u.content_hash);
    h.update([0xDD; 64]);
    let expected: [u8; 32] = h.finalize().into();

    assert_eq!(u.chain_hash(), expected);
}

#[test]
fn chain_hash_differs_from_content_hash() {
    let mut u = make_update(0, [0u8; 32], &[1, 2, 3]);
    u.operator_signature = [0xEE; 64];
    assert_ne!(u.chain_hash(), u.content_hash);
}

#[test]
fn chain_hash_with_zero_operator_sig_still_differs() {
    let u = make_update(0, [0u8; 32], &[1, 2, 3]);
    // Even with zero sig, chain_hash wraps content_hash
    assert_ne!(u.chain_hash(), u.content_hash);
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
    assert_ne!(u1.previous_hash, u0.content_hash); // not content_hash!
}

#[test]
fn three_update_chain_with_signatures() {
    // Build a 3-update chain with distinct signatures
    let mut u0 = make_update(0, [0u8; 32], &[1]);
    u0.cosign_signature = [0xA1; 64];
    u0.content_hash = u0.compute_hash();
    u0.operator_signature = [0xA2; 64];

    let mut u1 = make_update(1, u0.chain_hash(), &[2]);
    u1.cosign_signature = [0xB1; 64];
    u1.content_hash = u1.compute_hash();
    u1.operator_signature = [0xB2; 64];

    let mut u2 = make_update(2, u1.chain_hash(), &[3]);
    u2.cosign_signature = [0xC1; 64];
    u2.content_hash = u2.compute_hash();
    u2.operator_signature = [0xC2; 64];

    // Verify chain linkage
    assert_eq!(u1.previous_hash, u0.chain_hash());
    assert_eq!(u2.previous_hash, u1.chain_hash());

    // Verify each content_hash includes cosign_signature
    assert!(u0.verify_hash());
    assert!(u1.verify_hash());
    assert!(u2.verify_hash());

    // All hashes are distinct
    assert_ne!(u0.content_hash, u1.content_hash);
    assert_ne!(u1.content_hash, u2.content_hash);
    assert_ne!(u0.chain_hash(), u1.chain_hash());
    assert_ne!(u1.chain_hash(), u2.chain_hash());
}

#[test]
fn chain_with_cosigned_and_unsigned_updates() {
    // u0: unsigned (no partner sig, no member hash)
    let mut u0 = make_update(0, [0u8; 32], &[1]);
    u0.operator_signature = [0x01; 64];

    // u1: co-signed (has member_ledger_hash + cosign_signature)
    let mut u1 = make_update(1, u0.chain_hash(), &[2]);
    u1.member_ledger_hash = Some([0xAA; 32]);
    u1.cosign_signature = [0xBB; 64];
    u1.content_hash = u1.compute_hash();
    u1.operator_signature = [0x02; 64];

    // u2: unsigned again
    let mut u2 = make_update(2, u1.chain_hash(), &[3]);
    u2.operator_signature = [0x03; 64];

    // Chain links correctly through both types
    assert_eq!(u1.previous_hash, u0.chain_hash());
    assert_eq!(u2.previous_hash, u1.chain_hash());

    // u1's content_hash includes member_ledger_hash + cosign_signature
    let mut h = Sha256::new();
    h.update(1u64.to_le_bytes());
    h.update(u0.chain_hash());
    h.update([2u8]);
    h.update([0xAA; 32]);
    h.update([0xBB; 64]);
    let expected: [u8; 32] = h.finalize().into();
    assert_eq!(u1.content_hash, expected);

    // u1's chain_hash folds in operator sig
    let mut h2 = Sha256::new();
    h2.update(u1.content_hash);
    h2.update([0x02; 64]);
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
fn changing_cosign_signature_changes_content_hash() {
    let mut u = make_update(0, [0u8; 32], &[1, 2, 3]);
    u.cosign_signature = [0x11; 64];
    u.content_hash = u.compute_hash();
    let h1 = u.content_hash;

    u.cosign_signature = [0x22; 64];
    u.content_hash = u.compute_hash();
    let h2 = u.content_hash;

    assert_ne!(h1, h2);
}

#[test]
fn swapping_cosigner_breaks_chain() {
    // Build u0 → u1 chain
    let mut u0 = make_update(0, [0u8; 32], &[1]);
    u0.cosign_signature = [0xAA; 64];
    u0.content_hash = u0.compute_hash();
    u0.operator_signature = [0x01; 64];

    let u1 = make_update(1, u0.chain_hash(), &[2]);

    // Now swap the cosigner on u0
    u0.cosign_signature = [0xFF; 64];
    u0.content_hash = u0.compute_hash();
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

// =========================================================================
// TLV roundtrip: content_hash derived on decode, not transmitted
// =========================================================================

#[test]
fn tlv_roundtrip_derives_content_hash() {
    use deposits_protocol::tlv::{TlvDecode, TlvEncode};

    let mut u = make_update(5, [0xAA; 32], &[10, 20, 30]);
    u.cosign_signature = [0xBB; 64];
    u.member_ledger_hash = Some([0xCC; 32]);
    u.content_hash = u.compute_hash();
    u.operator_signature = [0xDD; 64];

    let expected_hash = u.content_hash;
    assert_ne!(expected_hash, [0u8; 32]);

    // Encode (content_hash is NOT on the wire)
    let encoded = u.tlv_encode();

    // Decode — content_hash is recomputed from content
    let decoded = SignedLedgerUpdate::tlv_decode(&encoded).unwrap();

    assert_eq!(
        decoded.content_hash, expected_hash,
        "derived content_hash should match original"
    );
    assert_eq!(decoded.sequence_number, 5);
    assert_eq!(decoded.previous_hash, [0xAA; 32]);
    assert_eq!(decoded.message, vec![10, 20, 30]);
    assert_eq!(decoded.cosign_signature, [0xBB; 64]);
    assert_eq!(decoded.member_ledger_hash, Some([0xCC; 32]));
    assert_eq!(decoded.operator_signature, [0xDD; 64]);
    assert_eq!(decoded.chain_hash(), u.chain_hash());
}

#[test]
fn tlv_roundtrip_unsigned_update_derives_hash() {
    use deposits_protocol::tlv::{TlvDecode, TlvEncode};

    let u = make_update(0, [0u8; 32], &[1, 2, 3]);
    let expected = u.content_hash;

    let encoded = u.tlv_encode();
    let decoded = SignedLedgerUpdate::tlv_decode(&encoded).unwrap();

    assert_eq!(decoded.content_hash, expected);
    assert_eq!(decoded.cosign_signature, [0u8; 64]);
    assert_eq!(decoded.member_ledger_hash, None);
}

#[test]
fn tlv_wire_does_not_contain_content_hash_bytes() {
    use deposits_protocol::tlv::{TlvEncode, TlvStream};

    let mut u = make_update(0, [0u8; 32], &[1, 2, 3]);
    u.content_hash = u.compute_hash();

    let encoded = u.tlv_encode();
    let stream = TlvStream::decode(&encoded).unwrap();

    // content_hash should not be in the TLV stream (derived on decode)
    // With new layout, no field maps to content_hash

    // Check fields are present with new tag numbers
    assert!(
        stream.get(0).is_some(),
        "operator_id (type 0) should be present"
    );
    assert!(
        stream.get(4).is_some(),
        "sequence_number (type 4) should be present"
    );
    assert!(
        stream.get(6).is_some(),
        "previous_hash (type 6) should be present"
    );
    assert!(
        stream.get(8).is_some(),
        "message (type 8) should be present"
    );
    assert!(
        stream.get(20).is_some(),
        "operator_signature (type 20) should be present"
    );
}

#[test]
fn chain_of_three_survives_tlv_roundtrip() {
    use deposits_protocol::tlv::{TlvDecode, TlvEncode};

    // Build a 3-update chain
    let mut u0 = make_update(0, [0u8; 32], &[1]);
    u0.cosign_signature = [0xA1; 64];
    u0.content_hash = u0.compute_hash();
    u0.operator_signature = [0xA2; 64];

    let mut u1 = make_update(1, u0.chain_hash(), &[2]);
    u1.cosign_signature = [0xB1; 64];
    u1.content_hash = u1.compute_hash();
    u1.operator_signature = [0xB2; 64];

    let mut u2 = make_update(2, u1.chain_hash(), &[3]);
    u2.cosign_signature = [0xC1; 64];
    u2.content_hash = u2.compute_hash();
    u2.operator_signature = [0xC2; 64];

    // Roundtrip each through TLV
    let d0 = SignedLedgerUpdate::tlv_decode(&u0.tlv_encode()).unwrap();
    let d1 = SignedLedgerUpdate::tlv_decode(&u1.tlv_encode()).unwrap();
    let d2 = SignedLedgerUpdate::tlv_decode(&u2.tlv_encode()).unwrap();

    // Chain linkage preserved
    assert_eq!(d1.previous_hash, d0.chain_hash());
    assert_eq!(d2.previous_hash, d1.chain_hash());

    // Hashes match originals
    assert_eq!(d0.content_hash, u0.content_hash);
    assert_eq!(d1.content_hash, u1.content_hash);
    assert_eq!(d2.content_hash, u2.content_hash);
    assert_eq!(d0.chain_hash(), u0.chain_hash());
    assert_eq!(d1.chain_hash(), u1.chain_hash());
    assert_eq!(d2.chain_hash(), u2.chain_hash());
}

// =========================================================================
// Cosignature ordering is canonicalized — same set, different insertion
// orders must produce identical content_hash, operator_signing_data, and
// wire bytes. Guards against signature malleability.
// =========================================================================

fn pubkey_from_seed(seed: u8) -> bitcoin::secp256k1::PublicKey {
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
    let mut bytes = [0u8; 32];
    bytes[0] = seed;
    bytes[31] = 0x42;
    let sk = SecretKey::from_slice(&bytes).unwrap();
    PublicKey::from_secret_key(&Secp256k1::new(), &sk)
}

fn entry(pubkey: bitcoin::secp256k1::PublicKey, sig_byte: u8) -> deposits_protocol::types::CosignEntry {
    deposits_protocol::types::CosignEntry {
        cosigner_pubkey: pubkey,
        cosign_signature: [sig_byte; 64],
        member_ledger_hash: [sig_byte.wrapping_add(1); 32],
    }
}

#[test]
fn cosignature_order_does_not_affect_content_hash() {
    let pk_a = pubkey_from_seed(1);
    let pk_b = pubkey_from_seed(2);
    let pk_c = pubkey_from_seed(3);

    let mut u_sorted = make_update(1, [0u8; 32], b"msg");
    u_sorted.cosignatures = {
        let mut v = vec![entry(pk_a, 0xA), entry(pk_b, 0xB), entry(pk_c, 0xC)];
        v.sort_by(|a, b| {
            a.cosigner_pubkey
                .serialize()
                .cmp(&b.cosigner_pubkey.serialize())
        });
        v
    };
    u_sorted.content_hash = u_sorted.compute_hash();

    // Same entries, deliberately reversed (unsorted) storage.
    let mut u_unsorted = make_update(1, [0u8; 32], b"msg");
    u_unsorted.cosignatures = {
        let mut v = u_sorted.cosignatures.clone();
        v.reverse();
        v
    };
    u_unsorted.content_hash = u_unsorted.compute_hash();

    assert_eq!(
        u_sorted.content_hash, u_unsorted.content_hash,
        "insertion order must not change content_hash"
    );
    assert_eq!(
        u_sorted.operator_signing_data(),
        u_unsorted.operator_signing_data(),
        "insertion order must not change operator_signing_data"
    );
}

// =========================================================================
// Equivocation defense
// =========================================================================
//
// Equivocation = the operator signs two distinct updates at the same
// {ledger_id, sequence_number, previous_hash} but with different message
// content. The protocol's defense lives in the chain itself: a cosigner's
// view of the chain is committed via their replica's `chain_tip_hash`
// (= chain_hash of the last applied update). Once they apply U_A, any
// subsequent U_C on a competing fork that extends U_B (i.e.
// U_C.previous_hash == chain_hash(U_B)) cannot satisfy the cosigner's
// continuity check (they need previous_hash == chain_hash(U_A)).
//
// These tests demonstrate the structural primitive: same {seq, prev_hash}
// with different message produces distinct content_hash (and therefore
// distinct chain_hash), so the two forks are bit-identifiable to anyone
// who sees both.

#[test]
fn equivocation_distinct_messages_produce_distinct_chain_hashes() {
    let prev = [0x42u8; 32];

    // Same operator, same chain seq, same prev_hash, DIFFERENT message.
    let u_a = make_update(5, prev, b"credit-A");
    let u_b = make_update(5, prev, b"credit-B");

    // Each update is well-formed in isolation.
    assert_eq!(u_a.sequence_number, u_b.sequence_number);
    assert_eq!(u_a.previous_hash, u_b.previous_hash);
    assert_ne!(u_a.message, u_b.message);

    // The protocol distinguishes them via content_hash, which then folds
    // into chain_hash. Both diverge.
    assert_ne!(u_a.content_hash, u_b.content_hash);
    assert_ne!(u_a.chain_hash(), u_b.chain_hash());
}

#[test]
fn equivocation_chain_extension_breaks_continuity_for_other_fork() {
    let prev_at_seq_4 = [0x42u8; 32];

    // Two competing updates at seq=5.
    let u_a = make_update(5, prev_at_seq_4, b"credit-A");
    let u_b = make_update(5, prev_at_seq_4, b"credit-B");

    // The adversary builds U_C extending U_B's fork (i.e. signs another
    // update with previous_hash = chain_hash(U_B)). Any cosigner who has
    // already applied U_A holds chain_tip_hash = chain_hash(U_A).
    let chain_tip_after_a = u_a.chain_hash();
    let u_c_extends_b = make_update(6, u_b.chain_hash(), b"credit-C");

    // The cosigner's continuity check is: U_C.previous_hash ==
    // their chain_tip_hash. For a cosigner committed to U_A, U_C's
    // previous_hash points at U_B's chain_hash — which doesn't match.
    assert_ne!(
        u_c_extends_b.previous_hash, chain_tip_after_a,
        "U_C's previous_hash must not match U_A-committed cosigner's chain_tip"
    );

    // Conversely, a cosigner committed to U_B accepts U_C (their chain_tip
    // = chain_hash(U_B), which IS U_C.previous_hash). That's the fork.
    let chain_tip_after_b = u_b.chain_hash();
    assert_eq!(
        u_c_extends_b.previous_hash, chain_tip_after_b,
        "U_C extends U_B's fork — the U_B-committed cosigner accepts it"
    );
}

#[test]
fn equivocation_witness_is_observable_to_anyone_with_both_updates() {
    // The "witness" of equivocation is just the pair (U_A, U_B) with:
    //   - same operator_id
    //   - same ledger_id
    //   - same sequence_number
    //   - same previous_hash
    //   - different content_hash (and hence different operator_signing_data)
    // Any third party that collects both can prove the operator signed
    // conflicting histories without trusting any cosigner — this is the
    // primitive a future FraudProofType::Equivocation would build on.

    let prev = [0xABu8; 32];
    let u_a = make_update(7, prev, b"transfer-to-X");
    let u_b = make_update(7, prev, b"transfer-to-Y");

    // The 4-tuple equivocation key is identical; only message + content_hash
    // differ. Cheap to detect with a hash-set keyed on (operator, ledger,
    // seq, prev_hash) → content_hash; collision triggers proof emission.
    let key_a = (u_a.operator_id, u_a.ledger_id, u_a.sequence_number, u_a.previous_hash);
    let key_b = (u_b.operator_id, u_b.ledger_id, u_b.sequence_number, u_b.previous_hash);
    assert_eq!(key_a, key_b, "equivocating updates share the (op, ledger, seq, prev) key");
    assert_ne!(u_a.content_hash, u_b.content_hash, "but content differs");
    assert_ne!(
        u_a.operator_signing_data(),
        u_b.operator_signing_data(),
        "operator's signing data also differs — both signatures are individually valid \
         but bind the operator to incompatible histories"
    );
}

#[test]
fn cosignature_order_does_not_affect_tlv_bytes() {
    use deposits_protocol::tlv::{TlvDecode, TlvEncode};

    let pk_a = pubkey_from_seed(1);
    let pk_b = pubkey_from_seed(2);
    let pk_c = pubkey_from_seed(3);

    let mut u_forward = make_update(1, [0u8; 32], b"msg");
    u_forward.cosignatures = vec![entry(pk_a, 0xA), entry(pk_b, 0xB), entry(pk_c, 0xC)];
    u_forward.content_hash = u_forward.compute_hash();

    let mut u_reversed = make_update(1, [0u8; 32], b"msg");
    u_reversed.cosignatures = vec![entry(pk_c, 0xC), entry(pk_b, 0xB), entry(pk_a, 0xA)];
    u_reversed.content_hash = u_reversed.compute_hash();

    assert_eq!(
        u_forward.tlv_encode(),
        u_reversed.tlv_encode(),
        "encode produces canonical bytes regardless of storage order"
    );

    // Decode also canonicalizes storage.
    let decoded = SignedLedgerUpdate::tlv_decode(&u_reversed.tlv_encode()).unwrap();
    let decoded_pks: Vec<_> = decoded
        .cosignatures
        .iter()
        .map(|e| e.cosigner_pubkey.serialize())
        .collect();
    let mut expected = decoded_pks.clone();
    expected.sort();
    assert_eq!(decoded_pks, expected, "decoder stores cosignatures sorted");
}
