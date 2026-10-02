//! Unauthorised vault spend (DEP-06, discriminant 10): a proof and spend that
//! cl-deposits built and signed (3-of-4 on tier 0 of its reserves), checked
//! here. The proof hash must match cl's byte for byte, and the witness must
//! verify against the reserves tree this crate builds from the same keys.
//! The vector is cl-deposits' `inspect/rotation-test.lisp` setup: keys
//! `1000000007 + i * 987654321`, ledger hash sha256(0xaa), expiry 5000.

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use deposits_core::vault_spend::verify_unauthorized_vault_spend;
use deposits_protocol::fraud::{
    verify_fraud_evidence, FraudEvidence, FraudProof, FraudProofType, LedgerProvider,
};
use deposits_protocol::messages::{LedgerOperation, QuorumMemberRef};
use deposits_protocol::tlv::TlvEncode;
use deposits_protocol::types::SignedLedgerUpdate;

const CL_PROOF_HASH: &str = "53b34dbf1df8701b5ce43b0216ec4c2967a7cf989bfadfbed950df5978bb2485";

fn pubkey(i: u64) -> PublicKey {
    let k = 1_000_000_007u64 + i * 987_654_321;
    let mut b = [0u8; 32];
    b[24..].copy_from_slice(&k.to_be_bytes());
    PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&b).unwrap())
}

fn sha(b: &[u8]) -> [u8; 32] {
    sha256::Hash::hash(b).to_byte_array()
}

fn proof() -> FraudProof {
    serde_json::from_str(include_str!("vectors/vault_spend_cl.json")).unwrap()
}

fn update(seq: u64, op: &LedgerOperation) -> SignedLedgerUpdate {
    SignedLedgerUpdate {
        message: op.tlv_encode(),
        message_type: op.message_type(),
        operator_id: pubkey(1),
        ledger_id: sha(&[2]),
        sequence_number: seq,
        previous_hash: [0; 32],
        content_hash: [0; 32],
        block_height: 100,
        block_hash: [0; 32],
        operator_signature: [0; 64],
        cosignatures: Vec::new(),
    }
}

fn qb(spending_txid: [u8; 32], expiry: u32, version: &str) -> LedgerOperation {
    LedgerOperation::QuorumBegin {
        reserves_id: String::new(),
        spending_txid,
        new_outpoint_txid: sha(&[0xf0, 0x0d]),
        new_outpoint_vout: 0,
        amount: 39_000_000_000,
        quorum_expiry: expiry,
        ledger_hash: sha(&[0xaa]),
        quorum_members: (2..=4)
            .map(|i| QuorumMemberRef {
                pubkey: pubkey(i),
                member_ledger_id: String::new(),
            })
            .collect(),
        collateral_amount: 0,
        protocol_version: Some(version.into()),
    }
}

fn history(spending_txid: [u8; 32]) -> Vec<SignedLedgerUpdate> {
    vec![
        update(
            0,
            &LedgerOperation::LedgerOpen {
                operator_id: pubkey(1),
                reserves_id: String::new(),
                genesis_block: 0,
                reserves_amount: 0,
                collateral_amount: 0,
            },
        ),
        update(1, &qb(spending_txid, 5000, "cltv-offset-v2")),
    ]
}

#[test]
fn proof_hash_matches_cl() {
    let p = proof();
    assert_eq!(p.proof_type.discriminant(), 10);
    assert!(!p.proof_type.requires_embedding());
    assert_eq!(hex::encode(p.proof_hash()), CL_PROOF_HASH);
}

#[test]
fn cl_signed_theft_verifies() {
    verify_unauthorized_vault_spend(&proof(), &history([9; 32]), &[]).unwrap();
}

#[test]
fn the_non_signer_is_not_accused() {
    let mut p = proof();
    p.accused = hex::encode(pubkey(4).serialize());
    let err = verify_unauthorized_vault_spend(&p, &history([9; 32]), &[]).unwrap_err();
    assert!(err.contains("not among the verified signers"), "{err}");
}

#[test]
fn a_recorded_rotation_is_not_theft() {
    let p = proof();
    let FraudEvidence::UnauthorizedVaultSpend { spend_tx_hex, .. } = &p.evidence else {
        panic!()
    };
    let tx: bitcoin::Transaction =
        bitcoin::consensus::deserialize(&hex::decode(spend_tx_hex).unwrap()).unwrap();
    let txid = tx.compute_txid().to_byte_array();
    // Excused by a recorded QuorumBegin (as its spending txid) or by the caller.
    let err = verify_unauthorized_vault_spend(&p, &history(txid), &[]).unwrap_err();
    assert!(err.contains("recorded rotation"), "{err}");
    let err = verify_unauthorized_vault_spend(&p, &history([9; 32]), &[txid]).unwrap_err();
    assert!(err.contains("recorded rotation"), "{err}");
}

#[test]
fn reserves_must_match_the_governing_quorum_begin() {
    let mut h = history([9; 32]);
    h[1] = update(1, &qb([9; 32], 5001, "cltv-offset-v2"));
    assert!(verify_unauthorized_vault_spend(&proof(), &h, &[]).is_err());
    let mut p = proof();
    let FraudEvidence::UnauthorizedVaultSpend {
        governing_quorumbegin_seq,
        ..
    } = &mut p.evidence
    else {
        panic!()
    };
    *governing_quorumbegin_seq = 5;
    let err = verify_unauthorized_vault_spend(&p, &history([9; 32]), &[]).unwrap_err();
    assert!(err.contains("no such QuorumBegin"), "{err}");
}

#[test]
fn a_tampered_spend_does_not_verify() {
    let mut p = proof();
    let FraudEvidence::UnauthorizedVaultSpend { spend_tx_hex, .. } = &mut p.evidence else {
        panic!()
    };
    // Flip a bit in the last output's script: the signatures no longer cover it.
    let mut bytes = hex::decode(&*spend_tx_hex).unwrap();
    let at = bytes.len() - 20;
    bytes[at] ^= 1;
    *spend_tx_hex = hex::encode(bytes);
    assert!(verify_unauthorized_vault_spend(&p, &history([9; 32]), &[]).is_err());
}

struct Ledgers(Vec<SignedLedgerUpdate>);
impl LedgerProvider for Ledgers {
    fn ledger_history(&self, id: &str) -> Option<Vec<SignedLedgerUpdate>> {
        (id == hex::encode(sha(&[2])) && !self.0.is_empty()).then(|| self.0.clone())
    }
}

#[test]
fn dispatch_needs_the_spent_ledger_and_the_block() {
    let p = proof();
    assert!(matches!(
        p.proof_type,
        FraudProofType::UnauthorizedVaultSpend
    ));
    let auth = deposits_core::dep16::Dep16Authorizer::new();
    let known = |_: &[u8; 32]| Some(1u32);
    let unknown = |_: &[u8; 32]| None;
    verify_fraud_evidence(&p, &Ledgers(history([9; 32])), &known, &auth).unwrap();
    assert!(verify_fraud_evidence(&p, &Ledgers(history([9; 32])), &unknown, &auth).is_err());
    assert!(verify_fraud_evidence(&p, &Ledgers(vec![]), &known, &auth).is_err());
}
