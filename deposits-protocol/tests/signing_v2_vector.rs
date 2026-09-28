//! DEP-02 v2 signing test vector.
//!
//! Builds a fixed update, signs it with fixed keys (BIP-340, aux_rand = 32
//! zero bytes) and prints every intermediate value as JSON, for byte-for-byte
//! comparison with other implementations:
//!
//! ```text
//! cargo test -p deposits-protocol --test signing_v2_vector -- --nocapture
//! ```
//!
//! The test also checks the values against an independent, byte-by-byte
//! computation of the spec formulas and against the verifiers.

use bitcoin::secp256k1::{Keypair, Message, PublicKey, Secp256k1, SecretKey};
use deposits_protocol::messages::LedgerOperation;
use deposits_protocol::tlv::{TlvDecode, TlvEncode};
use deposits_protocol::types::{CosignData, CosignEntry, SignedLedgerUpdate};
use sha2::{Digest, Sha256};

const AUX: [u8; 32] = [0u8; 32];

fn tagged_hash(tag: &[u8], data: &[u8]) -> [u8; 32] {
    let t: [u8; 32] = Sha256::digest(tag).into();
    let mut h = Sha256::new();
    h.update(t);
    h.update(t);
    h.update(data);
    h.finalize().into()
}

fn keypair(byte: u8) -> Keypair {
    Keypair::from_secret_key(
        &Secp256k1::new(),
        &SecretKey::from_slice(&[byte; 32]).unwrap(),
    )
}

fn sign(digest: [u8; 32], kp: &Keypair) -> [u8; 64] {
    Secp256k1::new()
        .sign_schnorr_with_aux_rand(&Message::from_digest(digest), kp, &AUX)
        .serialize()
}

#[test]
fn dep02_signing_v2_vector() {
    let operator = keypair(0x11);
    let operator_id: PublicKey = operator.public_key();
    // (secret key byte, member_ledger_hash byte)
    let cosigners = [(0x22u8, 0x01u8), (0x33u8, 0x02u8)];

    let message = hex::decode("00012a").unwrap();
    let mut update = SignedLedgerUpdate {
        message_type: LedgerOperation::message_type_from_bytes(&message),
        message,
        operator_id,
        ledger_id: [0xaa; 32],
        sequence_number: 7,
        previous_hash: [0xcc; 32],
        content_hash: [0u8; 32],
        block_height: 850_000,
        block_hash: [0xbb; 32],
        operator_signature: [0u8; 64],
        cosignatures: Vec::new(),
    };

    // cosign_data, and an independent construction of it.
    let cosign_data = update.cosign_data();
    let mut expected = Vec::new();
    expected.extend_from_slice(&7u64.to_le_bytes());
    expected.extend_from_slice(&[0xaa; 32]);
    expected.extend_from_slice(&850_000u32.to_le_bytes());
    expected.extend_from_slice(&[0xbb; 32]);
    expected.extend_from_slice(&[0xcc; 32]);
    expected.extend_from_slice(&3u32.to_le_bytes());
    expected.extend_from_slice(&[0x00, 0x01, 0x2a]);
    assert_eq!(cosign_data, expected);
    assert_eq!(CosignData::parse(&cosign_data).unwrap(), update.cosign_fields());

    // Cosignatures, sorted by cosigner pubkey.
    let mut entries: Vec<(CosignEntry, [u8; 32])> = cosigners
        .iter()
        .map(|&(sk, mlh)| {
            let kp = keypair(sk);
            let member_ledger_hash = [mlh; 32];
            let digest = update.cosign_digest(&member_ledger_hash);
            let mut data = cosign_data.clone();
            data.extend_from_slice(&member_ledger_hash);
            assert_eq!(digest, tagged_hash(b"deposits/cosign/v2", &data));
            (
                CosignEntry {
                    cosigner_pubkey: kp.public_key(),
                    cosign_signature: sign(digest, &kp),
                    member_ledger_hash,
                },
                digest,
            )
        })
        .collect();
    entries.sort_by_key(|(e, _)| e.cosigner_pubkey.serialize());
    update.cosignatures = entries.iter().map(|(e, _)| e.clone()).collect();

    // current_hash
    update.content_hash = update.compute_hash();
    let mut data = cosign_data.clone();
    data.extend_from_slice(&2u16.to_le_bytes());
    for (e, _) in &entries {
        data.extend_from_slice(&e.member_ledger_hash);
        data.extend_from_slice(&e.cosign_signature);
    }
    assert_eq!(update.content_hash, tagged_hash(b"deposits/update/v2", &data));

    // Operator signature
    let operator_digest = update.operator_digest();
    let mut data = cosign_data.clone();
    data.extend_from_slice(&2u16.to_le_bytes());
    for (e, _) in &entries {
        data.extend_from_slice(&e.cosign_signature);
    }
    assert_eq!(
        operator_digest,
        tagged_hash(b"deposits/operator-update/v2", &data)
    );
    update.operator_signature = sign(operator_digest, &operator);

    let chain_hash = update.chain_hash();
    let mut h = Sha256::new();
    h.update(update.content_hash);
    h.update(update.operator_signature);
    assert_eq!(chain_hash, <[u8; 32]>::from(h.finalize()));

    // Everything verifies, and the encoding round-trips.
    update.verify_operator_signature().unwrap();
    let members: Vec<PublicKey> = entries.iter().map(|(e, _)| e.cosigner_pubkey).collect();
    update.verify_cosign_signatures(&members, 2).unwrap();
    let tlv = update.tlv_encode();
    assert_eq!(SignedLedgerUpdate::tlv_decode(&tlv).unwrap(), update);

    let json = serde_json::json!({
        "cosign_data": hex::encode(&cosign_data),
        "cosigners": entries.iter().map(|(e, digest)| serde_json::json!({
            "pubkey": hex::encode(e.cosigner_pubkey.serialize()),
            "member_ledger_hash": hex::encode(e.member_ledger_hash),
            "digest": hex::encode(digest),
            "signature": hex::encode(e.cosign_signature),
        })).collect::<Vec<_>>(),
        "operator_digest": hex::encode(operator_digest),
        "operator_signature": hex::encode(update.operator_signature),
        "current_hash": hex::encode(update.content_hash),
        "chain_hash": hex::encode(chain_hash),
        "update_tlv": hex::encode(&tlv),
    });
    println!("{}", serde_json::to_string_pretty(&json).unwrap());
}
