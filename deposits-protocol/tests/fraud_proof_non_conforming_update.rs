//! Unit coverage for `verify_non_conforming_update` — the verifier that
//! grounds a `NonConformingUpdate` confiscation. The accusation: the operator
//! BIP-340-signed an update on their own ledger that fails to chain onto the
//! canonical tip (wrong `previous_hash`) or carries a bad `content_hash`.
//!
//! Only the operator's key can produce the signature, and an honest operator
//! never signs an update that doesn't extend its canonical chain — so this is
//! unilateral operator fraud with no false-positive surface against honest
//! operators. These tests pin: the positive verdict (chain break + bad hash),
//! and every fail-closed guard (conforming update, bad signature, accused
//! mismatch, seq redundancy, missing predecessor).

use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use deposits_protocol::fraud::{
    verify_non_conforming_update, FraudEvidence, FraudProof, FraudProofType,
};
use deposits_protocol::tlv::TlvEncode;
use deposits_protocol::types::SignedLedgerUpdate;
use sha2::{Digest, Sha256};

/// Build an operator-signed update at `seq` with `previous_hash = prev`,
/// signed by the key derived from `op_seed`. `content_hash` is set to the
/// correct `compute_hash()` unless `break_content_hash` is true.
fn signed_update(
    seq: u64,
    ledger_id: [u8; 32],
    prev: [u8; 32],
    op_seed: u8,
    msg: &[u8],
    break_content_hash: bool,
) -> SignedLedgerUpdate {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(&[op_seed; 32]).unwrap();
    let kp = Keypair::from_secret_key(&secp, &secret);

    let mut u = SignedLedgerUpdate {
        message: msg.to_vec(),
        message_type: 1,
        operator_id: kp.public_key(),
        ledger_id,
        sequence_number: seq,
        previous_hash: prev,
        content_hash: [0u8; 32],
        block_height: 0,
        block_hash: [0u8; 32],
        cosign_signature: [0u8; 64],
        operator_signature: [0u8; 64],
        cosigner_pubkey: None,
        member_ledger_hash: None,
        cosignatures: Vec::new(),
    };
    u.content_hash = if break_content_hash {
        [0x77; 32] // deliberately not compute_hash()
    } else {
        u.compute_hash()
    };
    // Sign the legacy raw digest — verify_operator_signature accepts it.
    let digest: [u8; 32] = Sha256::digest(u.operator_signing_data()).into();
    u.operator_signature = secp
        .sign_schnorr_no_aux_rand(&Message::from_digest(digest), &kp)
        .serialize();
    u
}

const LEDGER: [u8; 32] = [0xA1; 32];
const OP: u8 = 7;

/// A clean 3-update canonical chain by operator `OP`.
fn canonical_chain() -> Vec<SignedLedgerUpdate> {
    let g = signed_update(0, LEDGER, [0u8; 32], OP, b"genesis", false);
    let one = signed_update(1, LEDGER, g.chain_hash(), OP, b"one", false);
    let two = signed_update(2, LEDGER, one.chain_hash(), OP, b"two", false);
    vec![g, one, two]
}

fn proof_for(update: &SignedLedgerUpdate) -> FraudProof {
    FraudProof {
        proof_type: FraudProofType::NonConformingUpdate,
        accused: hex::encode(update.operator_id.serialize()),
        ledger_id: hex::encode(update.ledger_id),
        evidence: FraudEvidence::NonConformingUpdate {
            fault_sequence: update.sequence_number,
            fault_update_hex: hex::encode(update.tlv_encode()),
        },
    }
}

#[test]
fn broken_previous_hash_is_non_conforming() {
    let history = canonical_chain();
    // Operator signs a seq-2 update that does NOT chain onto seq 1.
    let bad = signed_update(2, LEDGER, [0xFF; 32], OP, b"orphan", false);
    let proof = proof_for(&bad);
    assert!(
        verify_non_conforming_update(&proof, &history).is_ok(),
        "an operator-signed update with a wrong previous_hash must verify as fraud"
    );
}

// NOTE: a content_hash break is deliberately NOT tested end-to-end because it
// is unrepresentable over the wire — the TLV format re-derives content_hash on
// decode (SignedLedgerUpdate::tlv_decode), so a hand-corrupted content_hash is
// normalized away by the encode→decode round-trip every FraudProof performs.
// The verifier keeps a defensive content_hash check, but the load-bearing
// structural signal for an over-the-wire fault is the previous_hash link,
// covered by `broken_previous_hash_is_non_conforming`.

#[test]
fn conforming_update_is_rejected() {
    let history = canonical_chain();
    // history[2] is a perfectly good seq-2 update — NOT fraud.
    let proof = proof_for(&history[2]);
    assert!(
        verify_non_conforming_update(&proof, &history).is_err(),
        "a conforming update must NOT be judged fraudulent (fail closed)"
    );
}

#[test]
fn same_seq_fork_with_valid_prev_is_not_this_fault() {
    // An update at seq 2 that DOES chain onto seq 1 but differs in content
    // from the canonical seq 2 is an Equivocation, not a NonConformingUpdate.
    // verify_non_conforming_update must decline it (fail closed).
    let history = canonical_chain();
    let fork = signed_update(2, LEDGER, history[1].chain_hash(), OP, b"different", false);
    let proof = proof_for(&fork);
    assert!(
        verify_non_conforming_update(&proof, &history).is_err(),
        "a valid-prev same-seq fork is Equivocation's domain, not NonConformingUpdate"
    );
}

#[test]
fn tampered_operator_signature_is_rejected() {
    let history = canonical_chain();
    let mut bad = signed_update(2, LEDGER, [0xFF; 32], OP, b"orphan", false);
    bad.operator_signature = [0x00; 64]; // invalidate
    let proof = proof_for(&bad);
    assert!(
        verify_non_conforming_update(&proof, &history).is_err(),
        "an update whose operator_signature doesn't verify must be rejected"
    );
}

#[test]
fn accused_mismatch_is_rejected() {
    let history = canonical_chain();
    let bad = signed_update(2, LEDGER, [0xFF; 32], OP, b"orphan", false);
    let mut proof = proof_for(&bad);
    // Point the accusation at a different pubkey than the signer.
    let other = {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[9u8; 32]).unwrap();
        Keypair::from_secret_key(&secp, &sk).public_key()
    };
    proof.accused = hex::encode(other.serialize());
    assert!(
        verify_non_conforming_update(&proof, &history).is_err(),
        "accused must be the operator that signed the fault update"
    );
}

#[test]
fn sequence_redundancy_mismatch_is_rejected() {
    let history = canonical_chain();
    let bad = signed_update(2, LEDGER, [0xFF; 32], OP, b"orphan", false);
    let mut proof = proof_for(&bad);
    if let FraudEvidence::NonConformingUpdate { fault_sequence, .. } = &mut proof.evidence {
        *fault_sequence = 5; // lie about the sequence
    }
    assert!(
        verify_non_conforming_update(&proof, &history).is_err(),
        "evidence.fault_sequence must match the inline update's sequence_number"
    );
}

#[test]
fn missing_predecessor_is_inconclusive() {
    // Only genesis is in history; a bad seq-2 update's predecessor (seq 1)
    // can't be reconstructed → fail closed rather than guess.
    let full = canonical_chain();
    let history = vec![full[0].clone()];
    let bad = signed_update(2, LEDGER, [0xFF; 32], OP, b"orphan", false);
    let proof = proof_for(&bad);
    assert!(
        verify_non_conforming_update(&proof, &history).is_err(),
        "absent a reconstructable canonical predecessor, the verifier must fail closed"
    );
}

#[test]
fn seq_zero_with_nonzero_prev_is_non_conforming() {
    // A seq-0 open must link to the all-zero hash; anything else is fraud.
    let bad = signed_update(0, LEDGER, [0x11; 32], OP, b"bad-genesis", false);
    let proof = proof_for(&bad);
    assert!(
        verify_non_conforming_update(&proof, &[]).is_ok(),
        "a seq-0 update not linking to the zero hash must verify as fraud"
    );
}

// ---------------------------------------------------------------------------
// Broadcast-level: NonConformingUpdate is self-evident (DEP-06), so the
// broadcast verifies on its evidence alone, with no embedding or causal
// chain. The evidence check is never skipped.
// ---------------------------------------------------------------------------

use deposits_protocol::fraud::{verify_fraud_broadcast, FraudBroadcast, ProofEmbedding};

fn accused_history(id: &str) -> Option<Vec<SignedLedgerUpdate>> {
    (id == hex::encode(LEDGER)).then(canonical_chain)
}

fn no_blocks(_: &[u8; 32]) -> Option<u32> {
    None
}

/// cl-deposits' transitional placeholder embedding (fraud.lisp
/// `broadcast->json`): the accused ledger, seq 0, empty hash, "inline".
fn cl_placeholder(ledger_id: &str) -> ProofEmbedding {
    ProofEmbedding {
        ledger_id: ledger_id.to_string(),
        sequence: 0,
        update_hash: String::new(),
        field: "inline".into(),
    }
}

#[test]
fn ncu_broadcast_without_embedding_verifies() {
    let bad = signed_update(2, LEDGER, [0xFF; 32], OP, b"orphan", false);
    let b = FraudBroadcast {
        proof: proof_for(&bad),
        embedding: None,
        causal_chain: vec![],
    };
    b.verify_chain_structure().unwrap();
    verify_fraud_broadcast(&b, &accused_history, &no_blocks).unwrap();
}

#[test]
fn ncu_broadcast_with_cl_placeholder_verifies() {
    let bad = signed_update(2, LEDGER, [0xFF; 32], OP, b"orphan", false);
    let proof = proof_for(&bad);
    let b = FraudBroadcast {
        embedding: Some(cl_placeholder(&proof.ledger_id)),
        proof,
        causal_chain: vec![],
    };
    verify_fraud_broadcast(&b, &accused_history, &no_blocks).unwrap();
}

#[test]
fn ncu_broadcast_with_bogus_evidence_still_rejected() {
    // A conforming update dressed up as fraud: no embedding needed, but the
    // evidence check still runs and refuses it.
    let honest = canonical_chain()[2].clone();
    let b = FraudBroadcast {
        proof: proof_for(&honest),
        embedding: None,
        causal_chain: vec![],
    };
    let err = verify_fraud_broadcast(&b, &accused_history, &no_blocks).unwrap_err();
    assert!(err.contains("conforming"), "wrong error: {}", err);

    // A non-conforming update not signed by the accused: impersonation.
    let bad = signed_update(2, LEDGER, [0xFF; 32], OP, b"orphan", false);
    let mut proof = proof_for(&bad);
    proof.accused = hex::encode(
        Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[9; 32]).unwrap())
            .public_key()
            .serialize(),
    );
    let b = FraudBroadcast {
        embedding: Some(cl_placeholder(&proof.ledger_id)),
        proof,
        causal_chain: vec![],
    };
    assert!(verify_fraud_broadcast(&b, &accused_history, &no_blocks).is_err());

    // The accused ledger unavailable: fail closed, not skip.
    let bad = signed_update(2, LEDGER, [0xFF; 32], OP, b"orphan", false);
    let b = FraudBroadcast {
        proof: proof_for(&bad),
        embedding: None,
        causal_chain: vec![],
    };
    let nothing = |_: &str| -> Option<Vec<SignedLedgerUpdate>> { None };
    assert!(verify_fraud_broadcast(&b, &nothing, &no_blocks).is_err());
}

/// cl's JSON, as `broadcast->json` / `proof->json` emit it today (with the
/// placeholder), and the embedding-less shapes it can move to.
#[test]
fn cl_shaped_json_round_trip() {
    let bad = signed_update(2, LEDGER, [0xFF; 32], OP, b"orphan", false);
    let accused = hex::encode(bad.operator_id.serialize());
    let ledger = hex::encode(LEDGER);
    let fault_hex = hex::encode(bad.tlv_encode());
    let proof_json = format!(
        r#"{{"proof_type":"NonConformingUpdate","accused":"{accused}","ledger_id":"{ledger}","evidence":{{"NonConformingUpdate":{{"fault_sequence":2,"fault_update_hex":"{fault_hex}"}}}}}}"#
    );
    let with_placeholder = format!(
        r#"{{"proof":{proof_json},"embedding":{{"ledger_id":"{ledger}","sequence":0,"update_hash":"","field":"inline"}},"causal_chain":[]}}"#
    );
    let key_absent = format!(r#"{{"proof":{proof_json},"causal_chain":[]}}"#);
    let null_embedding = format!(r#"{{"proof":{proof_json},"embedding":null,"causal_chain":[]}}"#);
    let bare = format!(r#"{{"proof":{proof_json}}}"#);

    let expected_hash = proof_for(&bad).proof_hash();
    for (name, json) in [
        ("placeholder", &with_placeholder),
        ("key absent", &key_absent),
        ("null", &null_embedding),
        ("no causal_chain", &bare),
    ] {
        let b: FraudBroadcast =
            serde_json::from_str(json).unwrap_or_else(|e| panic!("{name}: parse: {e}"));
        assert_eq!(b.proof.proof_hash(), expected_hash, "{name}: proof hash");
        verify_fraud_broadcast(&b, &accused_history, &no_blocks)
            .unwrap_or_else(|e| panic!("{name}: verify: {e}"));
        // Round trip through the reference's serializer.
        let again: FraudBroadcast = serde_json::from_str(&serde_json::to_string(&b).unwrap()).unwrap();
        assert_eq!(again.proof.proof_hash(), expected_hash, "{name}: round trip");
        assert_eq!(again.embedding.is_some(), b.embedding.is_some(), "{name}: embedding");
    }

    // The reference omits the key (not `null`) when it has no embedding.
    let b: FraudBroadcast = serde_json::from_str(&key_absent).unwrap();
    let out: serde_json::Value = serde_json::to_value(&b).unwrap();
    assert!(out.get("embedding").is_none(), "embedding key must be omitted: {out}");
    assert_eq!(out["causal_chain"], serde_json::json!([]));
}
