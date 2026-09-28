//! Integration test: a verified `DisputeDereliction` fraud proof
//! drives the dispute pipeline end-to-end.
//!
//! In this proof type, the accused is a quorum member who *was online*
//! (their own ledger advanced past the required response window) but
//! failed to act on a prior fraud proof. The "accused" and "member" are
//! the same entity. `proof.ledger_id` is the member's collateral
//! ledger — the one that gets confiscated for the inaction.
//!
//! `verify_inactive_quorum_member` checks:
//!   1. `original_fraud_block_hash` is in the verifier's chain
//!   2. member's ledger has update at `member_active_sequence`; that
//!      update's `block_hash` is also in the verifier's chain
//!   3. `member_height - original_height >= required_response_blocks`
//!   4. update at `member_active_sequence` is signed by `member_pubkey`
//!
//! Flow:
//!   1. Pick op1's L3 ledger (untouched by other fraud tests).
//!   2. Find a peer (= quorum member of op1's L3 other than op1) so we
//!      can read accused history and so the auto-arm path triggers.
//!   3. From op1's own view of L3, pick two updates with non-zero
//!      block_hashes for original-fraud and member-active anchors.
//!   4. Build FraudProof. Embed proof_hash via `recovery embed-hash`
//!      from op1 (only the operator can extend its own ledger).
//!   5. Publish kind:9101. Poll for marker.

use deposits_protocol::fraud::{
    CausalLink, FraudBroadcast, FraudEvidence, FraudProof, FraudProofType, ProofEmbedding,
};
use deposits_test::regtest::*;
use std::time::Duration;

#[test]
#[ignore]
fn fraud_proof_inactive_quorum_triggers_confiscation() {
    if !cluster_available() {
        eprintln!("skipping: cluster not running — start with ./bin/setup.sh 3");
        return;
    }

    let node = build_node_with_danger();

    // ── 0. Fund op-key P2WPKHs for RC declarations. ──
    for op_idx in 0..16 {
        let _ = fund_operator_key_address(op_idx, 100_000);
    }
    mine_blocks(2);

    // ── 1. Pick op1's L3 ledger — accused = op1, ledger = ledger_1_3 ──
    let accused_op_idx: usize = 1;
    let accused_ledger = read_setup_state("ledger_1_3");
    let peer_op_idx = find_peer_with_ledger(&accused_ledger, accused_op_idx)
        .expect("no peer has op1's L3 ledger imported — quorum activation may have failed");

    // Extend the chain past QB. The LVS dispatch for
    // DisputeDereliction falls through to `next_sequence-1` on the
    // accused ledger, which on fresh setup equals the QB seq. The
    // cosigner check wants a QB at-or-before LVS; since LVS=QB-1,
    // that fails. A few `DepositOpen` updates push the chain forward
    // so LVS ends up past QB.
    let _tip = extend_chain_past_qb(&accused_ledger, peer_op_idx, 3);

    // Read from op1's own data dir — op1 is the operator and has full
    // history. We could read from peer too, but op1's view is canonical.
    let history = read_ledger_history(&op_data_dir(accused_op_idx), &accused_ledger);
    let active_update = history
        .iter()
        .rfind(|u| u.block_hash != [0u8; 32])
        .expect("accused ledger has no update with a confirmed block_hash");
    let member_active_sequence = active_update.sequence_number;
    let member_pubkey = active_update.operator_id;

    // The accused L3 ledger only has Phase-4 quorum-activation updates,
    // all in one block, so we can't pick an "earlier" anchor from the
    // ledger itself. Take the earliest confirmed block we know about
    // anywhere in the cluster instead — `original_fraud_block_hash`
    // just needs to be a block the verifier's chain knows.
    let original_fraud_block_hash = earliest_anchored_block_hash(accused_op_idx)
        .expect("no anchored block found anywhere in op1's ledgers");
    assert_ne!(
        original_fraud_block_hash, active_update.block_hash,
        "earliest cluster block_hash matches active update — would yield zero elapsed blocks"
    );
    eprintln!(
        "[setup]    accused=op{}  ledger={}…  peer=op{}  active_seq={}",
        accused_op_idx,
        &accused_ledger[..16],
        peer_op_idx,
        member_active_sequence
    );
    eprintln!(
        "[anchors]  original_fraud_block={}…  active_block={}…",
        &hex::encode(original_fraud_block_hash)[..16],
        &hex::encode(active_update.block_hash)[..16]
    );

    // ── 2. Build the FraudProof ──
    // `original_fraud_hash` is just a marker (verifier doesn't link it
    // back to a real prior proof — that's the embedding's job for
    // proving knowability). Random bytes are fine.
    let original_fraud_hash: [u8; 32] = {
        use bitcoin::secp256k1::rand::{rngs::OsRng, RngCore};
        let mut buf = [0u8; 32];
        OsRng.fill_bytes(&mut buf);
        buf
    };
    let proof = FraudProof {
        proof_type: FraudProofType::DisputeDereliction,
        accused: hex::encode(member_pubkey.serialize()),
        ledger_id: accused_ledger.clone(),
        evidence: FraudEvidence::DisputeDereliction {
            original_fraud_hash: hex::encode(original_fraud_hash),
            original_fraud_block_hash,
            required_response_blocks: 1,
            member_ledger_id: accused_ledger.clone(),
            member_active_sequence,
            member_pubkey: hex::encode(member_pubkey.serialize()),
        },
    };
    let proof_hash = proof.proof_hash();
    eprintln!("[proof]    hash={}…", &hex::encode(proof_hash)[..16]);

    // ── 3. Embed proof_hash on op1's own ledger ──
    // Only the operator (op1) can extend their own ledger, so embed
    // runs from op1's CLI. Read it back from peer's view since op1's
    // daemon skips inbound on its own ledger (see
    // project_own_ledger_inbound_skip).
    let embed_update = embed_proof_hash(
        &node,
        accused_op_idx,
        peer_op_idx,
        &accused_ledger,
        proof_hash,
    );
    let embed_seq = embed_update.sequence_number;
    let embed_content = embed_update.content_hash;
    eprintln!(
        "[embed]    seq={} content={}…",
        embed_seq,
        &hex::encode(embed_content)[..16]
    );

    // ── 4. Publish kind:9101 — anyone can publish. Use op1. ──
    let broadcast = FraudBroadcast {
        proof,
        embedding: Some(ProofEmbedding {
            ledger_id: accused_ledger.clone(),
            sequence: embed_seq,
            update_hash: hex::encode(embed_content),
            field: "delivery_request_hash".into(),
        }),
        causal_chain: Vec::<CausalLink>::new(),
    };
    eprintln!("[publish]  kind:9101 from op{}", accused_op_idx);
    publish_fraud_broadcast(&node, accused_op_idx, &broadcast);

    let op_idx = poll_confiscation_marker(&accused_ledger, Duration::from_secs(180));
    eprintln!(
        "[ok] verified fraud-proof drove confiscation: marker at op{}/confiscated_{}.marker",
        op_idx,
        &accused_ledger[..16]
    );
}
