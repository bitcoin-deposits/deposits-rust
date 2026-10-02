//! DEP-02 v2: `ledger_id`, `block_height` and `block_hash` are signed.
//!
//! - Relabelling (changing `ledger_id`) or re-dating (changing `block_height`
//!   or `block_hash`) a signed update breaks the operator signature, every
//!   cosignature and `content_hash`.
//! - Every update has exactly one encoding: the decoder rejects an explicit
//!   zero `block_height` / `block_hash` and the retired tags 14, 16 and 18.

use bitcoin::secp256k1::{Keypair, Message, PublicKey, Secp256k1, SecretKey};
use deposits_protocol::tlv::{TlvDecode, TlvEncode, TlvStream};
use deposits_protocol::types::{CosignEntry, SignedLedgerUpdate};

fn keypair(byte: u8) -> Keypair {
    Keypair::from_secret_key(
        &Secp256k1::new(),
        &SecretKey::from_slice(&[byte; 32]).unwrap(),
    )
}

const COSIGNERS: [u8; 3] = [0x22, 0x33, 0x44];

fn members() -> Vec<PublicKey> {
    COSIGNERS.iter().map(|&b| keypair(b).public_key()).collect()
}

/// A fully signed, cosigned update.
fn signed_update() -> SignedLedgerUpdate {
    let secp = Secp256k1::new();
    let op = keypair(0x11);
    let mut u = SignedLedgerUpdate {
        message: vec![0x00, 0x01, 0x2a],
        message_type: deposits_protocol::messages::LedgerOperation::message_type_from_bytes(&[
            0x00, 0x01, 0x2a,
        ]),
        operator_id: op.public_key(),
        ledger_id: [0xaa; 32],
        sequence_number: 7,
        previous_hash: [0xcc; 32],
        content_hash: [0u8; 32],
        block_height: 850_000,
        block_hash: [0xbb; 32],
        operator_signature: [0u8; 64],
        cosignatures: Vec::new(),
    };
    for (i, &b) in COSIGNERS.iter().enumerate() {
        let kp = keypair(b);
        let mlh = [i as u8 + 1; 32];
        let digest = u.cosign_digest(&mlh);
        u.cosignatures.push(CosignEntry {
            cosigner_pubkey: kp.public_key(),
            cosign_signature: secp
                .sign_schnorr_no_aux_rand(&Message::from_digest(digest), &kp)
                .serialize(),
            member_ledger_hash: mlh,
        });
    }
    u.cosignatures
        .sort_by_key(|e| e.cosigner_pubkey.serialize());
    u.content_hash = u.compute_hash();
    u.operator_signature = secp
        .sign_schnorr_no_aux_rand(&Message::from_digest(u.operator_digest()), &op)
        .serialize();
    u
}

/// Every cosignature entry, verified alone.
fn each_cosignature_verifies(u: &SignedLedgerUpdate) -> Vec<bool> {
    u.cosignatures
        .iter()
        .map(|e| {
            let mut one = u.clone();
            one.cosignatures = vec![e.clone()];
            one.verify_cosign_signatures(&[e.cosigner_pubkey], 1)
                .is_ok()
        })
        .collect()
}

fn assert_all_signatures_broken(original: &SignedLedgerUpdate, tampered: &SignedLedgerUpdate) {
    assert!(
        tampered.verify_operator_signature().is_err(),
        "operator signature must not survive"
    );
    assert_eq!(
        each_cosignature_verifies(tampered),
        vec![false; COSIGNERS.len()],
        "no cosignature may survive"
    );
    assert!(tampered.verify_cosign_signatures(&members(), 2).is_err());
    assert_ne!(tampered.compute_hash(), original.content_hash);
    assert!(
        !tampered.verify_hash(),
        "stale content_hash must not verify"
    );
}

#[test]
fn baseline_verifies() {
    let u = signed_update();
    u.verify_operator_signature().unwrap();
    u.verify_cosign_signatures(&members(), 3).unwrap();
    assert!(u.verify_hash());
    assert_eq!(each_cosignature_verifies(&u), vec![true; COSIGNERS.len()]);
}

#[test]
fn relabelling_breaks_every_signature_and_the_hash() {
    let u = signed_update();
    let mut relabelled = u.clone();
    relabelled.ledger_id = [0xab; 32];
    assert_all_signatures_broken(&u, &relabelled);

    // Also after a wire round trip, where content_hash is re-derived.
    let decoded = SignedLedgerUpdate::tlv_decode(&relabelled.tlv_encode()).unwrap();
    assert!(decoded.verify_operator_signature().is_err());
    assert_ne!(decoded.content_hash, u.content_hash);
    assert_ne!(decoded.chain_hash(), u.chain_hash());
}

#[test]
fn redating_block_height_breaks_every_signature_and_the_hash() {
    let u = signed_update();
    for h in [850_001, 849_999, 1] {
        let mut redated = u.clone();
        redated.block_height = h;
        assert_all_signatures_broken(&u, &redated);
    }
    // Dropping the height (absent = zero) is re-dating too.
    let mut undated = u.clone();
    undated.block_height = 0;
    assert_all_signatures_broken(&u, &undated);
}

#[test]
fn redating_block_hash_breaks_every_signature_and_the_hash() {
    let u = signed_update();
    let mut redated = u.clone();
    redated.block_hash[31] ^= 1;
    assert_all_signatures_broken(&u, &redated);

    let mut undated = u.clone();
    undated.block_hash = [0u8; 32];
    assert_all_signatures_broken(&u, &undated);
}

// -------------------------------------------------------------------------
// Decoding: one encoding per update
// -------------------------------------------------------------------------

/// Re-encode `u` with `tag` set to `value`.
fn with_field(u: &SignedLedgerUpdate, tag: u64, value: Vec<u8>) -> Vec<u8> {
    let mut stream = TlvStream::decode(&u.tlv_encode()).unwrap();
    stream.insert(tag, value);
    stream.encode()
}

#[test]
fn encoder_omits_zero_block_fields() {
    let mut u = signed_update();
    u.block_height = 0;
    u.block_hash = [0u8; 32];
    let stream = TlvStream::decode(&u.tlv_encode()).unwrap();
    assert!(stream.get(10).is_none());
    assert!(stream.get(12).is_none());
    // And the absent fields decode (and hash) as zero.
    let decoded = SignedLedgerUpdate::tlv_decode(&u.tlv_encode()).unwrap();
    assert_eq!(decoded.block_height, 0);
    assert_eq!(decoded.block_hash, [0u8; 32]);
    assert_eq!(decoded.content_hash, u.compute_hash());
}

#[test]
fn decoder_rejects_explicit_zero_block_height() {
    let u = signed_update();
    let bytes = with_field(&u, 10, 0u32.to_be_bytes().to_vec());
    assert!(SignedLedgerUpdate::tlv_decode(&bytes).is_err());
    // Sanity: the same stream with a nonzero value decodes.
    let ok = with_field(&u, 10, 850_000u32.to_be_bytes().to_vec());
    assert_eq!(SignedLedgerUpdate::tlv_decode(&ok).unwrap(), u);
}

#[test]
fn decoder_rejects_explicit_zero_block_hash() {
    let u = signed_update();
    let bytes = with_field(&u, 12, vec![0u8; 32]);
    assert!(SignedLedgerUpdate::tlv_decode(&bytes).is_err());
}

#[test]
fn decoder_rejects_retired_single_cosig_tags() {
    let u = signed_update();
    let values: [(u64, Vec<u8>); 3] = [
        (14, u.cosignatures[0].cosigner_pubkey.serialize().to_vec()),
        (16, u.cosignatures[0].member_ledger_hash.to_vec()),
        (18, u.cosignatures[0].cosign_signature.to_vec()),
    ];
    for (tag, value) in values {
        let bytes = with_field(&u, tag, value);
        assert!(
            SignedLedgerUpdate::tlv_decode(&bytes).is_err(),
            "tag {} must be rejected",
            tag
        );
    }
    // Also on an update without tag 22.
    let mut bare = u.clone();
    bare.cosignatures.clear();
    let bytes = with_field(&bare, 18, [0x55; 64].to_vec());
    assert!(SignedLedgerUpdate::tlv_decode(&bytes).is_err());
}

#[test]
fn signed_update_round_trips() {
    let u = signed_update();
    let decoded = SignedLedgerUpdate::tlv_decode(&u.tlv_encode()).unwrap();
    assert_eq!(decoded, u);
    decoded.verify_operator_signature().unwrap();
    decoded.verify_cosign_signatures(&members(), 2).unwrap();
}
