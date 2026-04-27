//! Step-6 regression test for the per-ledger-actor migration.
//!
//! After a fraud-proof flow runs (StaleCosig: forge → embed → publish →
//! quorum-arm → confiscation), every quorum member's `LedgerActor` for
//! the accused ledger should have shadowed the operator's main-chain
//! updates byte-for-byte. This locks in the step-4/5 invariant:
//! actor.log content_hash == handler.jsonl content_hash for every
//! sequence the actor tracked.
//!
//! What we DON'T assert here:
//!   - Total counts match. Actor.log only contains updates seen by
//!     this process via Inbound; the handler.jsonl includes the
//!     pre-existing setup history (seq 0..QuorumBegin) loaded at boot.
//!   - Fork updates. Step-5's actor uses an operator-key filter that
//!     refuses fork-branch updates from disputers; handler routes
//!     those to per-fork files. We only compare main-chain seqs that
//!     appear in BOTH files.
//!
//! Drives StaleCosig as the workload because it produces a clean
//! 2-update inbound stream on the accused ledger (forge + embed)
//! across multiple quorum members.

use deposits_protocol::fraud::{
    CausalLink, FraudBroadcast, FraudEvidence, FraudProof, FraudProofType, ProofEmbedding,
};
use deposits_test::regtest::*;
use std::process::Command;
use std::time::Duration;

#[test]
#[ignore]
fn actor_shadow_matches_handler_for_main_chain() {
    if !cluster_available() {
        eprintln!("skipping: cluster not running — start with ./bin/setup.sh 3");
        return;
    }

    let node = build_node_with_danger();

    // ── Drive a StaleCosig forge + embed on a fresh op0 ledger ──
    // (Same flow as fraud_proof_stale_cosig.rs but trimmed: we only
    // need the inbound traffic, not the full dispute pipeline.)
    let accused_ledger = discover_op0_ledger();
    let member_ledger = read_setup_state("ledger_1_1");
    eprintln!(
        "[setup] accused={}…  member={}…",
        &accused_ledger[..16],
        &member_ledger[..16]
    );

    let member_history = read_ledger_history(&op_data_dir(1), &member_ledger);
    assert!(member_history.len() >= 3, "member ledger needs >= 3 updates");
    let stale_hash = member_history[0].chain_hash();
    let later_update = member_history.last().unwrap().clone();
    let forge_block = later_update.block_height + 50;

    eprintln!("[forge] danger forge-stale-cosig at block_height={}", forge_block);
    let out = Command::new(&node)
        .args([
            "danger",
            "forge-stale-cosig",
            &accused_ledger,
            &hex::encode(stale_hash),
            &forge_block.to_string(),
        ])
        .args(["--seed", OP0_SEED])
        .args(["--name", "op0"])
        .args(["--network", "regtest"])
        .args(["--data-dir", op0_data_dir().to_str().unwrap()])
        .args(["--esplora", ELECTRS_URL])
        .args(["--relay", relay_ledgers()])
        .output()
        .expect("invoke forge");
    assert!(out.status.success(), "forge failed:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr));
    std::thread::sleep(Duration::from_secs(3));

    // Build a proof_hash and embed it (same protocol primitives the
    // fraud-proof tests use). This puts a second update on the chain
    // that the actor should also shadow.
    let accused_history = read_ledger_history(&op_data_dir(1), &accused_ledger);
    let forged = accused_history
        .iter()
        .rev()
        .find(|u| !u.cosignatures.is_empty()
            && u.cosignatures.iter().any(|c| c.member_ledger_hash == stale_hash))
        .expect("forged update should be visible from peer");
    let proof = FraudProof {
        proof_type: FraudProofType::StaleCosignature,
        accused: hex::encode(accused_history[0].operator_id.serialize()),
        ledger_id: accused_ledger.clone(),
        evidence: FraudEvidence::StaleCosign {
            stale_update_sequence: forged.sequence_number,
            stale_update_hash: hex::encode(forged.content_hash),
            declared_member_hash: hex::encode(stale_hash),
            member_later_sequence: later_update.sequence_number,
            member_later_hash: hex::encode(later_update.chain_hash()),
            member_ledger_id: member_ledger.clone(),
        },
    };
    let proof_hash = proof.proof_hash();
    let embed_update = embed_proof_hash(&node, 0, 1, &accused_ledger, proof_hash);
    let embed_seq = embed_update.sequence_number;
    let embed_content_hash = embed_update.content_hash;

    // Optionally publish the broadcast — not strictly needed for the
    // shadow assertion (forge + embed already exercise the inbound
    // path) but produces a passing dispute pipeline so the test runs
    // in a realistic state.
    let broadcast = FraudBroadcast {
        proof,
        embedding: ProofEmbedding {
            ledger_id: accused_ledger.clone(),
            sequence: embed_seq,
            update_hash: hex::encode(embed_content_hash),
            field: "delivery_request_hash".into(),
        },
        causal_chain: Vec::<CausalLink>::new(),
    };
    publish_fraud_broadcast(&node, 0, &broadcast);
    let _ = poll_confiscation_marker(&accused_ledger, Duration::from_secs(180));

    // ── Compare actor.log vs handler.jsonl across all quorum members ──
    // For every (op_idx) that has a handler.jsonl for this ledger, also
    // expect an actor.log; for every overlapping seq, content_hash must
    // match exactly.
    let mut compared_pairs = 0u32;
    let mut compared_seqs = 0u32;
    for op_idx in 0..10 {
        let dd = op_data_dir(op_idx);
        let handler_path = dd
            .join("wallet/ledgers")
            .join(format!("{}.jsonl", accused_ledger));
        if !handler_path.exists() {
            continue;
        }
        let actor_path = dd
            .join("wallet/ledgers")
            .join(format!("{}.actor.log", accused_ledger));
        if !actor_path.exists() {
            // The actor only writes when it accepts inbound. Empty
            // actor.log is valid if the daemon was started after the
            // last inbound on this ledger; nothing to compare.
            continue;
        }

        let handler = read_ledger_history(&dd, &accused_ledger);
        let actor = read_actor_log(&dd, &accused_ledger);
        let handler_by_seq: std::collections::HashMap<u64, [u8; 32]> = handler
            .iter()
            .map(|u| (u.sequence_number, u.content_hash))
            .collect();

        let mut overlap_seqs = 0u32;
        for u in &actor {
            if let Some(handler_ch) = handler_by_seq.get(&u.sequence_number) {
                assert_eq!(
                    *handler_ch, u.content_hash,
                    "op{} ledger {}… seq {}: actor content_hash {} != handler {}",
                    op_idx,
                    &accused_ledger[..16],
                    u.sequence_number,
                    hex::encode(&u.content_hash[..8]),
                    hex::encode(&handler_ch[..8])
                );
                overlap_seqs += 1;
            }
            // Updates only-in-actor on the main file are tolerated:
            // step 8a now routes fork-branch updates to per-disputer
            // `{compound_key}.actor.log` files matching the handler's
            // layout, so the main `<id>.actor.log` should only carry
            // operator-key matches. Anything still in main-only here
            // is either a stale envelope from an earlier session or
            // the actor's view of an update the handler hasn't yet
            // persisted (race we don't pin in this test).
        }

        eprintln!(
            "[ok] op{}: actor={}  handler={}  overlap_seqs={}",
            op_idx,
            actor.len(),
            handler.len(),
            overlap_seqs
        );
        compared_pairs += 1;
        compared_seqs += overlap_seqs;
    }

    assert!(
        compared_pairs >= 2,
        "expected >= 2 ops with both actor.log and handler.jsonl; got {}",
        compared_pairs
    );
    assert!(
        compared_seqs >= 2,
        "expected >= 2 overlapping seqs (forge + embed at minimum); got {}",
        compared_seqs
    );
    eprintln!(
        "[ok] {} op-pairs compared, {} overlapping seqs validated",
        compared_pairs, compared_seqs
    );
}
