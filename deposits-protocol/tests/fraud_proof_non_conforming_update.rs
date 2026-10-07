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
use deposits_protocol::messages::{LedgerOperation, QuorumMemberRef};
use deposits_protocol::tlv::TlvEncode;
// This crate has no descriptor evaluator, so these verifier calls pass
// `AllowAll`: witnesses are not judged here. Nodes pass deposits-core's
// `Dep16Authorizer`; the witness cases are tested in
// deposits-core/tests/fraud_proof_witness.rs.
use deposits_protocol::types::{AllowAll, SignedLedgerUpdate};
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
        operator_signature: [0u8; 64],
        cosignatures: Vec::new(),
    };
    u.content_hash = if break_content_hash {
        [0x77; 32] // deliberately not compute_hash()
    } else {
        u.compute_hash()
    };
    let digest = u.operator_digest();
    u.operator_signature = secp
        .sign_schnorr_no_aux_rand(&Message::from_digest(digest), &kp)
        .serialize();
    u
}

/// The ledger's id as its genesis derives it: the verifier only accepts a
/// history whose seq 0 opens the ledger the proof names.
fn ledger() -> [u8; 32] {
    deposits_protocol::types::LedgerState::compute_ledger_id(&pubkey(OP), "bcrt1qreserves", 0)
}

fn genesis_op() -> LedgerOperation {
    LedgerOperation::LedgerOpen {
        operator_id: pubkey(OP),
        reserves_id: "bcrt1qreserves".to_string(),
        genesis_block: 0,
        reserves_amount: RESERVES,
        collateral_amount: COLLATERAL,
    }
}
const OP: u8 = 7;

/// A clean 3-update canonical chain by operator `OP`: a real LedgerOpen, then
/// two byte-string "operations" (enough for the structural checks, which
/// never replay; a verdict that needs a replay fails closed on them).
fn canonical_chain() -> Vec<SignedLedgerUpdate> {
    let g = signed_update(
        0,
        ledger(),
        [0u8; 32],
        OP,
        &genesis_op().tlv_encode(),
        false,
    );
    let one = signed_update(1, ledger(), g.chain_hash(), OP, b"one", false);
    let two = signed_update(2, ledger(), one.chain_hash(), OP, b"two", false);
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
    let bad = signed_update(
        2,
        ledger(),
        canonical_chain()[0].chain_hash(),
        OP,
        b"orphan",
        false,
    );
    let proof = proof_for(&bad);
    assert!(
        verify_non_conforming_update(&proof, &history, &AllowAll).is_ok(),
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
    // history[2] is a perfectly good seq-2 update — NOT fraud. (It chains, so
    // the verifier replays; these byte-string "operations" do not decode, so
    // it fails closed. `chained_conforming_update_is_rejected` covers the
    // same verdict on real operations.)
    let proof = proof_for(&history[2]);
    assert!(
        verify_non_conforming_update(&proof, &history, &AllowAll).is_err(),
        "a conforming update must NOT be judged fraudulent (fail closed)"
    );
}

#[test]
fn same_seq_fork_with_valid_prev_is_not_this_fault() {
    // An update at seq 2 that DOES chain onto seq 1 but differs in content
    // from the canonical seq 2 is an Equivocation, not a NonConformingUpdate.
    // verify_non_conforming_update must decline it (fail closed).
    let history = canonical_chain();
    let fork = signed_update(
        2,
        ledger(),
        history[1].chain_hash(),
        OP,
        b"different",
        false,
    );
    let proof = proof_for(&fork);
    assert!(
        verify_non_conforming_update(&proof, &history, &AllowAll).is_err(),
        "a valid-prev same-seq fork is Equivocation's domain, not NonConformingUpdate"
    );
}

#[test]
fn tampered_operator_signature_is_rejected() {
    let history = canonical_chain();
    let mut bad = signed_update(
        2,
        ledger(),
        canonical_chain()[0].chain_hash(),
        OP,
        b"orphan",
        false,
    );
    bad.operator_signature = [0x00; 64]; // invalidate
    let proof = proof_for(&bad);
    assert!(
        verify_non_conforming_update(&proof, &history, &AllowAll).is_err(),
        "an update whose operator_signature doesn't verify must be rejected"
    );
}

#[test]
fn accused_mismatch_is_rejected() {
    let history = canonical_chain();
    let bad = signed_update(
        2,
        ledger(),
        canonical_chain()[0].chain_hash(),
        OP,
        b"orphan",
        false,
    );
    let mut proof = proof_for(&bad);
    // Point the accusation at a different pubkey than the signer.
    let other = {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[9u8; 32]).unwrap();
        Keypair::from_secret_key(&secp, &sk).public_key()
    };
    proof.accused = hex::encode(other.serialize());
    assert!(
        verify_non_conforming_update(&proof, &history, &AllowAll).is_err(),
        "accused must be the operator that signed the fault update"
    );
}

#[test]
fn sequence_redundancy_mismatch_is_rejected() {
    let history = canonical_chain();
    let bad = signed_update(
        2,
        ledger(),
        canonical_chain()[0].chain_hash(),
        OP,
        b"orphan",
        false,
    );
    let mut proof = proof_for(&bad);
    if let FraudEvidence::NonConformingUpdate { fault_sequence, .. } = &mut proof.evidence {
        *fault_sequence = 5; // lie about the sequence
    }
    assert!(
        verify_non_conforming_update(&proof, &history, &AllowAll).is_err(),
        "evidence.fault_sequence must match the inline update's sequence_number"
    );
}

#[test]
fn missing_predecessor_is_inconclusive() {
    // Only genesis is in history; the seq-2 update follows seq 1, which isn't,
    // so it can't be judged (or even bound to this ledger) → fail closed.
    let full = canonical_chain();
    let history = vec![full[0].clone()];
    let bad = signed_update(2, ledger(), full[1].chain_hash(), OP, b"orphan", false);
    let proof = proof_for(&bad);
    assert!(
        verify_non_conforming_update(&proof, &history, &AllowAll).is_err(),
        "absent a reconstructable canonical predecessor, the verifier must fail closed"
    );
}

#[test]
fn seq_zero_with_nonzero_prev_is_non_conforming() {
    // A seq-0 open must link to the all-zero hash; anything else is fraud.
    let bad = signed_update(
        0,
        ledger(),
        [0x11; 32],
        OP,
        &genesis_op().tlv_encode(),
        false,
    );
    let proof = proof_for(&bad);
    assert!(
        verify_non_conforming_update(&proof, &[], &AllowAll).is_ok(),
        "a seq-0 update not linking to the zero hash must verify as fraud"
    );
    // A seq-0 update that doesn't open this ledger isn't bound to it.
    let other = signed_update(0, ledger(), [0x11; 32], OP, b"bad-genesis", false);
    assert!(verify_non_conforming_update(&proof_for(&other), &[], &AllowAll).is_err());
}

// ---------------------------------------------------------------------------
// Broadcast-level: NonConformingUpdate is self-evident (DEP-06), so the
// broadcast verifies on its evidence alone, with no embedding or causal
// chain. The evidence check is never skipped.
// ---------------------------------------------------------------------------

use deposits_protocol::fraud::{verify_fraud_broadcast, FraudBroadcast, ProofEmbedding};

fn accused_history(id: &str) -> Option<Vec<SignedLedgerUpdate>> {
    (id == hex::encode(ledger())).then(canonical_chain)
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
    let bad = signed_update(
        2,
        ledger(),
        canonical_chain()[0].chain_hash(),
        OP,
        b"orphan",
        false,
    );
    let b = FraudBroadcast {
        proof: proof_for(&bad),
        embedding: None,
        causal_chain: vec![],
    };
    b.verify_chain_structure().unwrap();
    verify_fraud_broadcast(&b, &accused_history, &no_blocks, &AllowAll).unwrap();
}

#[test]
fn ncu_broadcast_with_cl_placeholder_verifies() {
    let bad = signed_update(
        2,
        ledger(),
        canonical_chain()[0].chain_hash(),
        OP,
        b"orphan",
        false,
    );
    let proof = proof_for(&bad);
    let b = FraudBroadcast {
        embedding: Some(cl_placeholder(&proof.ledger_id)),
        proof,
        causal_chain: vec![],
    };
    verify_fraud_broadcast(&b, &accused_history, &no_blocks, &AllowAll).unwrap();
}

#[test]
fn ncu_broadcast_with_bogus_evidence_still_rejected() {
    // A conforming update dressed up as fraud: no embedding needed, but the
    // evidence check still runs and refuses it.
    // (Ledger C's honest credit: real operations, so the verifier replays
    // them and finds the credit applies cleanly.)
    let honest = ledger_c_prefix()[3].clone();
    let b = FraudBroadcast {
        proof: proof_for(&honest),
        embedding: None,
        causal_chain: vec![],
    };
    let ledger_c = |id: &str| (id == hex::encode(ledger())).then(ledger_c_prefix);
    let err = verify_fraud_broadcast(&b, &ledger_c, &no_blocks, &AllowAll).unwrap_err();
    assert!(err.contains("conforming"), "wrong error: {}", err);

    // A non-conforming update not signed by the accused: impersonation.
    let bad = signed_update(
        2,
        ledger(),
        canonical_chain()[0].chain_hash(),
        OP,
        b"orphan",
        false,
    );
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
    assert!(verify_fraud_broadcast(&b, &accused_history, &no_blocks, &AllowAll).is_err());

    // The accused ledger unavailable: fail closed, not skip.
    let bad = signed_update(
        2,
        ledger(),
        canonical_chain()[0].chain_hash(),
        OP,
        b"orphan",
        false,
    );
    let b = FraudBroadcast {
        proof: proof_for(&bad),
        embedding: None,
        causal_chain: vec![],
    };
    let nothing = |_: &str| -> Option<Vec<SignedLedgerUpdate>> { None };
    assert!(verify_fraud_broadcast(&b, &nothing, &no_blocks, &AllowAll).is_err());
}

/// cl's JSON, as `broadcast->json` / `proof->json` emit it today (with the
/// placeholder), and the embedding-less shapes it can move to.
#[test]
fn cl_shaped_json_round_trip() {
    let bad = signed_update(
        2,
        ledger(),
        canonical_chain()[0].chain_hash(),
        OP,
        b"orphan",
        false,
    );
    let accused = hex::encode(bad.operator_id.serialize());
    let ledger = hex::encode(ledger());
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
        verify_fraud_broadcast(&b, &accused_history, &no_blocks, &AllowAll)
            .unwrap_or_else(|e| panic!("{name}: verify: {e}"));
        // Round trip through the reference's serializer.
        let again: FraudBroadcast =
            serde_json::from_str(&serde_json::to_string(&b).unwrap()).unwrap();
        assert_eq!(
            again.proof.proof_hash(),
            expected_hash,
            "{name}: round trip"
        );
        assert_eq!(
            again.embedding.is_some(),
            b.embedding.is_some(),
            "{name}: embedding"
        );
    }

    // The reference omits the key (not `null`) when it has no embedding.
    let b: FraudBroadcast = serde_json::from_str(&key_absent).unwrap();
    let out: serde_json::Value = serde_json::to_value(&b).unwrap();
    assert!(
        out.get("embedding").is_none(),
        "embedding key must be omitted: {out}"
    );
    assert_eq!(out["causal_chain"], serde_json::json!([]));
}

// ---------------------------------------------------------------------------
// A fault that chains but breaks a rule: the verifier replays the canonical
// history to the fault's predecessor and applies the fault. Modelled on the
// devnet's ledger C (2026-09-28): reserves 20,000,000,000 msat, collateral
// 30,000,000,000, obligations 480,000,000, then a 40,000,000,000 credit
// signed by the operator onto the canonical tip (seq 17,840 there, 4 here).
// ---------------------------------------------------------------------------

use deposits_protocol::fraud::find_non_conforming_update;

const RESERVES: u64 = 20_000_000_000;
const COLLATERAL: u64 = 30_000_000_000;
const HONEST: u64 = 480_000_000;
const FRAUD: u64 = 40_000_000_000;
const DEPOSIT: [u8; 16] = [0xAB; 16];

fn pubkey(seed: u8) -> bitcoin::secp256k1::PublicKey {
    let secp = Secp256k1::new();
    Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[seed; 32]).unwrap()).public_key()
}

fn credit(n: u8, amount: u64) -> LedgerOperation {
    LedgerOperation::OnchainCredit {
        txid: [n; 32],
        vout: 0,
        deposit_id: DEPOSIT,
        amount,
        funding_address: "bcrt1qfund".to_string(),
        commitment: None,
    }
}

/// seq 0 LedgerOpen, 1 QuorumBegin, 2 DepositOpen, 3 the honest credit. Each
/// update is a real operation, signed by `OP`, chained onto the one before.
fn ledger_c_prefix() -> Vec<SignedLedgerUpdate> {
    let ops = [
        genesis_op(),
        LedgerOperation::QuorumBegin {
            exit_cutoff_height: None,
            exit_outputs: Vec::new(),
            reserves_id: "bcrt1qreserves".to_string(),
            spending_txid: [0; 32],
            new_outpoint_txid: [1; 32],
            new_outpoint_vout: 0,
            amount: RESERVES,
            quorum_expiry: 1_000_000,
            ledger_hash: [0; 32],
            quorum_members: vec![QuorumMemberRef::pubkey_only(pubkey(2))],
            collateral_amount: COLLATERAL,
            protocol_version: Some("cltv-offset-v2".to_string()),
        },
        LedgerOperation::DepositOpen {
            deposit_id: DEPOSIT,
            descriptor: "wpkh(deadbeef)".to_string(),
            fees: None,
            transfer_fees: None,
            payment_hash: None,
            invoice: None,
            cosigner_guarantee_signature: None,
            receive_requires_sig: false,
            fee_change_after_blocks: None,
            fee_change_notice_blocks: None,
            fee_change_limit_bps: None,
            commitment: None,
        },
        credit(1, HONEST),
    ];
    let mut chain: Vec<SignedLedgerUpdate> = Vec::new();
    for (seq, op) in ops.iter().enumerate() {
        let prev = chain.last().map(|u| u.chain_hash()).unwrap_or([0u8; 32]);
        chain.push(signed_update(
            seq as u64,
            ledger(),
            prev,
            OP,
            &op.tlv_encode(),
            false,
        ));
    }
    chain
}

/// The fraudulent 40,000,000,000 credit at seq 4, chained onto seq 3.
fn ledger_c_fraud(prefix: &[SignedLedgerUpdate], seed: u8) -> SignedLedgerUpdate {
    signed_update(
        4,
        ledger(),
        prefix[3].chain_hash(),
        seed,
        &credit(2, FRAUD).tlv_encode(),
        false,
    )
}

#[test]
fn chained_credit_over_reserves_verifies() {
    let prefix = ledger_c_prefix();
    let fraud = ledger_c_fraud(&prefix, OP);
    assert_eq!(fraud.previous_hash, prefix[3].chain_hash(), "it chains");
    // With and without the fault itself in the history (on the devnet it is
    // on the relay; a reporter may also send it only inline).
    let mut with_fault = prefix.clone();
    with_fault.push(fraud.clone());
    for history in [&prefix, &with_fault] {
        verify_non_conforming_update(&proof_for(&fraud), history, &AllowAll)
            .expect("a chained credit past reserves and collateral is non-conforming");
    }
}

#[test]
fn chained_credit_over_reserves_verifies_as_a_broadcast() {
    let prefix = ledger_c_prefix();
    let fraud = ledger_c_fraud(&prefix, OP);
    let mut history = prefix.clone();
    history.push(fraud.clone());
    let provider = move |id: &str| (id == hex::encode(ledger())).then(|| history.clone());
    let b = FraudBroadcast {
        proof: proof_for(&fraud),
        embedding: None,
        causal_chain: vec![],
    };
    verify_fraud_broadcast(&b, &provider, &no_blocks, &AllowAll).unwrap();
}

#[test]
fn chained_conforming_update_is_rejected() {
    let prefix = ledger_c_prefix();
    // The honest 480,000,000 credit: chains, applies, no violation.
    let err = verify_non_conforming_update(&proof_for(&prefix[3]), &prefix, &AllowAll).unwrap_err();
    assert!(err.contains("applies cleanly"), "{}", err);
    // And a second honest credit that stays under reserves and collateral.
    let ok_credit = signed_update(
        4,
        ledger(),
        prefix[3].chain_hash(),
        OP,
        &credit(3, 1_000_000_000).tlv_encode(),
        false,
    );
    let err = verify_non_conforming_update(&proof_for(&ok_credit), &prefix, &AllowAll).unwrap_err();
    assert!(err.contains("applies cleanly"), "{}", err);
}

#[test]
fn chained_fault_signed_by_someone_else_is_rejected() {
    let prefix = ledger_c_prefix();
    // Signed and claimed by another key, accused as the operator.
    let foreign = ledger_c_fraud(&prefix, 9);
    let mut proof = proof_for(&foreign);
    proof.accused = hex::encode(pubkey(OP).serialize());
    assert!(verify_non_conforming_update(&proof, &prefix, &AllowAll).is_err());
    // Claims the operator's key, but the signature is another key's.
    let mut forged = ledger_c_fraud(&prefix, OP);
    forged.operator_signature = foreign.operator_signature;
    assert!(verify_non_conforming_update(&proof_for(&forged), &prefix, &AllowAll).is_err());
}

#[test]
fn chain_break_on_a_real_ledger_still_verifies() {
    let prefix = ledger_c_prefix();
    // A perfectly conforming credit at seq 4 that follows seq 1: a rewind.
    let orphan = signed_update(
        4,
        ledger(),
        prefix[1].chain_hash(),
        OP,
        &credit(3, 1_000_000_000).tlv_encode(),
        false,
    );
    verify_non_conforming_update(&proof_for(&orphan), &prefix, &AllowAll).unwrap();
}

#[test]
fn a_forged_predecessor_does_not_frame_an_honest_update() {
    // A history with an unsigned impostor at seq 3 ahead of the real one: the
    // canonical chain adopts only signed links, so the honest seq-3 credit
    // stays canonical and the honest seq-4 credit chains onto it.
    let prefix = ledger_c_prefix();
    let mut impostor = prefix[3].clone();
    impostor.message = credit(7, 5).tlv_encode();
    impostor.content_hash = impostor.compute_hash();
    let honest4 = signed_update(
        4,
        ledger(),
        prefix[3].chain_hash(),
        OP,
        &credit(3, 1_000_000_000).tlv_encode(),
        false,
    );
    let history = vec![
        prefix[0].clone(),
        prefix[1].clone(),
        prefix[2].clone(),
        impostor,
        prefix[3].clone(),
        honest4.clone(),
    ];
    assert!(verify_non_conforming_update(&proof_for(&honest4), &history, &AllowAll).is_err());
    assert_eq!(
        find_non_conforming_update(&history, &pubkey(OP), &AllowAll),
        None
    );
}

#[test]
fn find_locates_the_chained_fault_once() {
    let prefix = ledger_c_prefix();
    assert_eq!(
        find_non_conforming_update(&prefix, &pubkey(OP), &AllowAll),
        None
    );
    let mut history = prefix.clone();
    history.push(ledger_c_fraud(&prefix, OP));
    let (seq, reason) = find_non_conforming_update(&history, &pubkey(OP), &AllowAll).unwrap();
    assert_eq!(seq, 4);
    assert!(reason.contains("InsufficientReserves"), "{}", reason);
}

#[test]
fn find_locates_a_chain_break() {
    let mut history = ledger_c_prefix();
    let skip_from = history[2].chain_hash();
    history.push(signed_update(
        4,
        ledger(),
        skip_from,
        OP,
        &credit(3, 1).tlv_encode(),
        false,
    ));
    assert_eq!(
        find_non_conforming_update(&history, &pubkey(OP), &AllowAll).map(|f| f.0),
        Some(4)
    );
}

fn lock(amount: u64, expiry: u32) -> LedgerOperation {
    LedgerOperation::OnchainLock {
        deposit_id: DEPOSIT,
        amount,
        fee_sats: 0,
        destination_address: "bcrt1qdest".to_string(),
        withdrawal_id: [5; 32],
        nonce: 1,
        expiry,
        witness: deposits_protocol::types::DescriptorWitness { stack: vec![] },
        commitment: None,
    }
}

#[test]
fn a_rewritten_block_height_does_not_frame_an_honest_update() {
    // Anyone relaying an honest lock can raise its block_height past the
    // lock's expiry. block_height is signed (DEP-02 v2), so the re-dated copy
    // no longer carries the operator's signature and is not proof.
    let prefix = ledger_c_prefix();
    let mut honest = signed_update(
        4,
        ledger(),
        prefix[3].chain_hash(),
        OP,
        &lock(1_000, 500).tlv_encode(),
        false,
    );
    assert!(verify_non_conforming_update(&proof_for(&honest), &prefix, &AllowAll).is_err());
    honest.block_height = 10_000;
    assert!(honest.verify_operator_signature().is_err());
    assert!(verify_non_conforming_update(&proof_for(&honest), &prefix, &AllowAll).is_err());

    // A rule that does not depend on heights still proves: a zero-amount lock.
    let zero = signed_update(
        4,
        ledger(),
        prefix[3].chain_hash(),
        OP,
        &lock(0, 500).tlv_encode(),
        false,
    );
    verify_non_conforming_update(&proof_for(&zero), &prefix, &AllowAll).unwrap();
}

// ---------------------------------------------------------------------------
// Binding to the ledger. One operator key runs several ledgers (cl-deposits
// nodes open their own ledger and operate another with the node key).
// ledger_id is signed (DEP-02 v2), so a relabelled copy carries no valid
// operator signature; the verifiers also bind a chain break to the named
// ledger through the previous_hash, walked back to this ledger's genesis.
// ---------------------------------------------------------------------------

/// Ledger X: another ledger by the same operator key, with its own reserves.
fn ledger_x() -> Vec<SignedLedgerUpdate> {
    let id =
        deposits_protocol::types::LedgerState::compute_ledger_id(&pubkey(OP), "bcrt1qreservesX", 0);
    let ops = [
        LedgerOperation::LedgerOpen {
            operator_id: pubkey(OP),
            reserves_id: "bcrt1qreservesX".to_string(),
            genesis_block: 0,
            reserves_amount: RESERVES,
            collateral_amount: COLLATERAL,
        },
        LedgerOperation::DepositOpen {
            deposit_id: DEPOSIT,
            descriptor: "wpkh(deadbeef)".to_string(),
            fees: None,
            transfer_fees: None,
            payment_hash: None,
            invoice: None,
            cosigner_guarantee_signature: None,
            receive_requires_sig: false,
            fee_change_after_blocks: None,
            fee_change_notice_blocks: None,
            fee_change_limit_bps: None,
            commitment: None,
        },
        credit(9, 1_000),
        credit(10, 2_000),
        credit(11, 3_000),
    ];
    let mut chain: Vec<SignedLedgerUpdate> = Vec::new();
    for (seq, op) in ops.iter().enumerate() {
        let prev = chain.last().map(|u| u.chain_hash()).unwrap_or([0u8; 32]);
        chain.push(signed_update(
            seq as u64,
            id,
            prev,
            OP,
            &op.tlv_encode(),
            false,
        ));
    }
    chain
}

#[test]
fn an_honest_update_of_another_ledger_relabelled_is_not_proof() {
    let y = ledger_c_prefix();
    let x = ledger_x();
    // X's honest seq-4 credit, relabelled as ledger Y (C). ledger_id is
    // signed, so the operator's signature no longer verifies.
    let mut relabelled = x[4].clone();
    relabelled.ledger_id = ledger();
    assert!(relabelled.verify_operator_signature().is_err());
    assert_ne!(relabelled.previous_hash, y[3].chain_hash());

    assert!(verify_non_conforming_update(&proof_for(&relabelled), &y, &AllowAll).is_err());
    // Even with X's history mixed into what the relay returns for Y (a
    // relabelled copy of all of it): X's genesis opens X, not Y.
    let mut mixed = y.clone();
    mixed.extend(x.iter().cloned().map(|mut u| {
        u.ledger_id = ledger();
        u
    }));
    assert!(verify_non_conforming_update(&proof_for(&relabelled), &mixed, &AllowAll).is_err());
    assert_eq!(
        find_non_conforming_update(&mixed, &pubkey(OP), &AllowAll),
        None
    );
    // And on X, where it belongs, it is an honest update.
    assert!(verify_non_conforming_update(&proof_for(&x[4]), &x, &AllowAll).is_err());
}

#[test]
fn an_update_following_nothing_in_the_history_is_not_proof() {
    let prefix = ledger_c_prefix();
    let orphan = signed_update(
        4,
        ledger(),
        [0xFF; 32],
        OP,
        &credit(3, 1).tlv_encode(),
        false,
    );
    let err = verify_non_conforming_update(&proof_for(&orphan), &prefix, &AllowAll).unwrap_err();
    assert!(err.contains("nothing binds it to this ledger"), "{}", err);
}

fn equivocation(a: &SignedLedgerUpdate, b: &SignedLedgerUpdate) -> FraudProof {
    FraudProof {
        proof_type: FraudProofType::Equivocation,
        accused: hex::encode(a.operator_id.serialize()),
        ledger_id: hex::encode(a.ledger_id),
        evidence: FraudEvidence::Equivocation {
            sequence: a.sequence_number,
            update_a_hex: hex::encode(a.tlv_encode()),
            update_b_hex: hex::encode(b.tlv_encode()),
        },
    }
}

#[test]
fn two_ledgers_updates_at_one_sequence_are_not_equivocation() {
    use deposits_protocol::fraud::{find_equivocation, verify_equivocation};
    let y = ledger_c_prefix();
    let x = ledger_x();
    // Seq 3 on both ledgers, same operator key. X's relabelled as Y no longer
    // carries the operator's signature: ledger_id is signed.
    let mut relabelled = x[3].clone();
    relabelled.ledger_id = ledger();
    assert!(relabelled.verify_operator_signature().is_err());
    let proof = equivocation(&y[3], &relabelled);
    assert!(verify_equivocation(&proof, &y).is_err());

    let mut mixed = y.clone();
    mixed.extend(x.iter().cloned().map(|mut u| {
        u.ledger_id = ledger();
        u
    }));
    assert!(verify_equivocation(&proof, &mixed).is_err());
    assert_eq!(find_equivocation(&mixed, &pubkey(OP)), None);
}

#[test]
fn a_genuine_equivocation_still_verifies() {
    use deposits_protocol::fraud::{find_equivocation, verify_equivocation};
    let y = ledger_c_prefix();
    let a = signed_update(
        4,
        ledger(),
        y[3].chain_hash(),
        OP,
        &credit(3, 1).tlv_encode(),
        false,
    );
    let b = signed_update(
        4,
        ledger(),
        y[3].chain_hash(),
        OP,
        &credit(4, 2).tlv_encode(),
        false,
    );
    verify_equivocation(&equivocation(&a, &b), &y).unwrap();
    let mut history = y.clone();
    history.extend([a.clone(), b.clone()]);
    assert_eq!(find_equivocation(&history, &pubkey(OP)), Some(4));

    // As a broadcast, with the accused ledger's history.
    let provider = move |id: &str| (id == hex::encode(ledger())).then(|| history.clone());
    let bc = FraudBroadcast {
        proof: equivocation(&a, &b),
        embedding: None,
        causal_chain: vec![],
    };
    verify_fraud_broadcast(&bc, &provider, &no_blocks, &AllowAll).unwrap();
    // Without the history, nothing binds the pair: fail closed.
    let nothing = |_: &str| -> Option<Vec<SignedLedgerUpdate>> { None };
    assert!(verify_fraud_broadcast(&bc, &nothing, &no_blocks, &AllowAll).is_err());
}

// ---------------------------------------------------------------------------
// Only the ledger's operator at the fault's sequence can be accused.
// ---------------------------------------------------------------------------

const MEMBER: u8 = 2; // ledger C's quorum member

/// A quorum member signs two different updates at the next sequence, chained
/// onto the operator's tip, and accuses itself. Neither is the ledger's
/// update: the operator at seq 4 is `OP`. Refused explicitly, not only
/// because an index happens to hold just the accused's own updates.
#[test]
fn a_member_accusing_itself_is_refused() {
    use deposits_protocol::fraud::verify_equivocation;
    let y = ledger_c_prefix();
    let a = signed_update(
        4,
        ledger(),
        y[3].chain_hash(),
        MEMBER,
        &credit(3, 1).tlv_encode(),
        false,
    );
    let b = signed_update(
        4,
        ledger(),
        y[3].chain_hash(),
        MEMBER,
        &credit(4, 2).tlv_encode(),
        false,
    );
    let mut history = y.clone();
    history.extend([a.clone(), b.clone()]);
    for h in [&y, &history] {
        let err = verify_equivocation(&equivocation(&a, &b), h).unwrap_err();
        assert!(
            err.contains("the accused does not operate the ledger at that sequence"),
            "wrong error: {}",
            err
        );
    }

    // The same as a NonConformingUpdate: a credit past reserves, by the member.
    let fraud = ledger_c_fraud(&y, MEMBER);
    let err = verify_non_conforming_update(&proof_for(&fraud), &y, &AllowAll).unwrap_err();
    assert!(
        err.contains("the accused does not operate the ledger at that sequence"),
        "wrong error: {}",
        err
    );
    // The operator's own is proof.
    verify_non_conforming_update(&proof_for(&ledger_c_fraud(&y, OP)), &y, &AllowAll).unwrap();
}

const SUCCESSOR: u8 = 9;

/// Ledger C taken over: DisputeEnter, DisputeArmed and DisputeAcquire (seq 4
/// to 6) move custody to `SUCCESSOR`, which signs from there.
fn taken_over() -> Vec<SignedLedgerUpdate> {
    let mut chain = ledger_c_prefix();
    let ops = [
        LedgerOperation::DisputeEnter {
            last_valid_sequence: 3,
            reason: "fraud_proof".into(),
            anchor_block_hash: None,
            anchor_block_height: None,
        },
        LedgerOperation::DisputeArmed {
            armed_block: 100,
            commitment_hash: [0; 20],
            target_reserves: "bcrt1qnew".into(),
            replacement_collateral: None,
        },
        LedgerOperation::DisputeAcquire {
            new_custodian: pubkey(SUCCESSOR),
            claim_txid: [9; 32],
            new_reserves_address: "bcrt1qnew".into(),
        },
    ];
    for op in ops {
        let prev = chain.last().unwrap().chain_hash();
        let seq = chain.len() as u64;
        chain.push(signed_update(
            seq,
            ledger(),
            prev,
            SUCCESSOR,
            &op.tlv_encode(),
            false,
        ));
    }
    chain
}

/// After a DisputeAcquire the operator is the new custodian, by the replayed
/// prefix: its faults are proof (they could not be proved before: the index
/// held only its updates, which do not reach the genesis), and the former
/// operator's updates onto the successor's chain are not its fault.
#[test]
fn custody_follows_dispute_acquire() {
    use deposits_protocol::fraud::verify_equivocation;
    let chain = taken_over();
    let tip = chain[6].chain_hash();
    let over_reserves = credit(2, FRAUD).tlv_encode();

    let by_successor = signed_update(7, ledger(), tip, SUCCESSOR, &over_reserves, false);
    verify_non_conforming_update(&proof_for(&by_successor), &chain, &AllowAll)
        .expect("the new custodian's fault is proof");

    let by_former = signed_update(7, ledger(), tip, OP, &over_reserves, false);
    let err = verify_non_conforming_update(&proof_for(&by_former), &chain, &AllowAll).unwrap_err();
    assert!(
        err.contains("does not operate the ledger"),
        "wrong error: {}",
        err
    );

    let a = signed_update(7, ledger(), tip, OP, &credit(3, 1).tlv_encode(), false);
    let b = signed_update(7, ledger(), tip, OP, &credit(4, 2).tlv_encode(), false);
    let err = verify_equivocation(&equivocation(&a, &b), &chain).unwrap_err();
    assert!(
        err.contains("does not operate the ledger"),
        "wrong error: {}",
        err
    );
    let a = signed_update(
        7,
        ledger(),
        tip,
        SUCCESSOR,
        &credit(3, 1).tlv_encode(),
        false,
    );
    let b = signed_update(
        7,
        ledger(),
        tip,
        SUCCESSOR,
        &credit(4, 2).tlv_encode(),
        false,
    );
    verify_equivocation(&equivocation(&a, &b), &chain).unwrap();

    // The former operator's fault from before the takeover still verifies:
    // it did operate the ledger at seq 4. Whether to act on it is the node's
    // call (a proof against a former operator disputes nothing).
    verify_non_conforming_update(&proof_for(&ledger_c_fraud(&chain, OP)), &chain, &AllowAll)
        .unwrap();
}
