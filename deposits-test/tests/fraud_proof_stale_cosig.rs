//! Integration test: a verified `StaleCosignature` fraud proof must
//! drive the dispute pipeline end-to-end.
//!
//! Flow:
//!   1. Q=3 cluster from `./bin/setup.sh 3`. Op0 is the accused; op1 is
//!      a quorum member of op0's L1 whose collateral ledger op0 has
//!      imported via the consent piggyback.
//!   2. Read op1's ledger history. Pick the chain_hash at an early
//!      sequence S as the "stale" hash a backdated cosignature could
//!      have referenced. Pick a later block_height (op1 had advanced
//!      past S) for the comparison.
//!   3. `danger forge-stale-cosig` on op0: publish a SignedLedgerUpdate
//!      on op0's ledger that carries a CosignEntry with that stale
//!      member_ledger_hash, at a block_height *after* op1 had moved
//!      past it. This is the "evidence" the StaleCosignature verifier
//!      inspects.
//!   4. `recovery embed-hash` on op0: publish a `DeliveryEmbed` whose
//!      `request_hash` is the proof_hash of the FraudProof we're about
//!      to construct. Same-ledger embedding (no causal chain).
//!   5. Construct a `FraudBroadcast { proof, embedding, causal_chain }`
//!      and `recovery publish-fraud-broadcast` it as a kind:9101.
//!   6. Quorum members receive the broadcast, run
//!      `verify_fraud_broadcast` (composed dispatcher → per-type
//!      verifier), accept, auto-arm, run the lottery, broadcast the
//!      confiscation TX, write `confiscated_<prefix>.marker`.
//!   7. Test polls operator data dirs for that marker; pass on first
//!      sighting, fail on timeout.
//!
//! Requires: `./bin/setup.sh 3` cluster.

use deposits_protocol::fraud::{
    CausalLink, FraudBroadcast, FraudEvidence, FraudProof, FraudProofType, ProofEmbedding,
};
use deposits_test::regtest::*;
use std::process::Command;
use std::time::Duration;

#[test]
#[ignore]
fn fraud_proof_stale_cosig_triggers_confiscation() {
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

    // ── 1. Open a fresh victim ledger on op0 + add 3 cosigners ──
    //
    // Previously this test discovered op0's first setup ledger
    // (`discover_op0_ledger`) and used `ledger_1_1` as the member
    // collateral. That worked on a freshly-bootstrapped cluster but
    // broke once cluster-aging tests (auto_dispute_on_expiry,
    // candidate_queue_swap) mined past expiry: peers fork-disputed
    // op0's ledgers, the forged update stopped propagating to their
    // canonical chains, and the read at step 4 timed out.
    //
    // Long expiry (10_000 blocks) keeps the victim healthy through
    // the whole forge → broadcast → confiscation pipeline (~30s).
    let victim = match open_victim_quorum_ledger(&node, 0, 10_000, 3) {
        Some(v) => v,
        None => {
            eprintln!(
                "skipping: couldn't open a fresh victim — Q=3 healthy \
                 members not available on this cluster. Rerun against \
                 `setup.sh --fresh 3`."
            );
            return;
        }
    };
    let accused_ledger = victim.victim_ledger.clone();
    // Use the first cosigner as the "member" whose chain we cite as
    // staler than op0's cosignature claim.
    let (member_op_idx, _member_pk, member_ledger) = victim.members[0].clone();
    eprintln!(
        "[setup] accused={}…  member={}… (op{})",
        &accused_ledger[..16],
        &member_ledger[..16],
        member_op_idx,
    );

    // ── 2. Pick a stale member_ledger_hash from member's history ──
    // The member's collateral ledger lives in its own data dir.
    let member_history = read_ledger_history(&op_data_dir(member_op_idx), &member_ledger);
    assert!(
        member_history.len() >= 3,
        "member ledger needs at least 3 updates to find a 'stale' hash + evidence of advancement (got {})",
        member_history.len()
    );

    // The member's chain_hash at sequence index 0 (= LedgerOpen) is the
    // "stale" hash. The cosignature claim is that op0 declared *this*
    // hash, but by the time op0 cosigned, op1 had already advanced.
    let stale_idx = 0usize;
    let stale_hash = member_history[stale_idx].chain_hash();
    let stale_seq = member_history[stale_idx].sequence_number;

    // Pick the *latest* member update as the "later" reference. Its
    // block_height is what we compare against the forged cosig's
    // block_height to prove staleness.
    let later_update = member_history.last().unwrap().clone();
    let member_later_seq = later_update.sequence_number;
    let member_later_chain = later_update.chain_hash();
    let member_later_block = later_update.block_height;

    eprintln!(
        "[evidence] stale_seq={} stale_hash={}…  later_seq={} later_block={}",
        stale_seq,
        &hex::encode(stale_hash)[..16],
        member_later_seq,
        member_later_block
    );

    // ── 3. Forge a stale cosignature on op0's ledger ──
    // block_height for the forged update must be > member_later_block
    // so the verifier accepts "member had already advanced past
    // stale_hash before op0 cosigned".
    let forge_block = member_later_block + 50;
    eprintln!(
        "[forge] danger forge-stale-cosig at block_height={}",
        forge_block
    );
    let out = Command::new(&node)
        .args([
            "danger",
            "forge-stale-cosig",
            &accused_ledger,
            &hex::encode(stale_hash),
            &forge_block.to_string(),
        ])
        .args(["--seed", op0_seed()])
        .args(["--name", &op_name(0)])
        .args(["--network", "regtest"])
        .args(["--data-dir", op0_data_dir().to_str().unwrap()])
        .args(["--esplora", ELECTRS_URL])
        .args(["--relay", relay_ledgers()])
        .output()
        .expect("invoke danger forge-stale-cosig");
    assert!(
        out.status.success(),
        "forge-stale-cosig failed:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    // Op0's own daemon needs to ingest the broadcast back from the relay
    // before the forged update lands in its persisted history.
    std::thread::sleep(Duration::from_secs(3));

    // ── 4. Read op0's ledger from a quorum member's view ──
    // Op0's own daemon deliberately skips inbound updates for its own
    // ledger (`handle_ledger_update` returns early when
    // operator_key == self.node_id). Quorum members process the forged
    // update normally; the cosigner we just enrolled has it via the
    // consent-piggyback import that fires during `quorum add`.
    let accused_history = read_ledger_history(&op_data_dir(member_op_idx), &accused_ledger);
    let forged = accused_history
        .iter()
        .rev()
        .find(|u| {
            !u.cosignatures.is_empty()
                && u.cosignatures
                    .iter()
                    .any(|c| c.member_ledger_hash == stale_hash)
        })
        .expect("forged stale-cosig update should be in op0's history");
    let stale_update_seq = forged.sequence_number;
    let stale_update_content = forged.content_hash;
    eprintln!(
        "[forged] seq={} content={}…",
        stale_update_seq,
        &hex::encode(stale_update_content)[..16]
    );

    // ── 5. Build the FraudProof so we know its proof_hash ──
    let op0_pubkey_hex = {
        // Operator pubkey = the operator_id of any update on op0's ledger.
        hex::encode(accused_history[0].operator_id.serialize())
    };
    let proof = FraudProof {
        proof_type: FraudProofType::StaleCosignature,
        accused: op0_pubkey_hex.clone(),
        ledger_id: accused_ledger.clone(),
        evidence: FraudEvidence::StaleCosign {
            stale_update_sequence: stale_update_seq,
            stale_update_hash: hex::encode(stale_update_content),
            declared_member_hash: hex::encode(stale_hash),
            member_later_sequence: member_later_seq,
            member_later_hash: hex::encode(member_later_chain),
            member_ledger_id: member_ledger.clone(),
        },
    };
    let proof_hash = proof.proof_hash();
    eprintln!("[proof] hash={}…", &hex::encode(proof_hash)[..16]);

    // ── 6. Embed the proof_hash via DeliveryEmbed on op0's ledger ──
    let embed_update = embed_proof_hash(&node, 0, member_op_idx, &accused_ledger, proof_hash);
    let embed_seq = embed_update.sequence_number;
    let embed_content = embed_update.content_hash;
    eprintln!(
        "[embed] seq={} content={}…",
        embed_seq,
        &hex::encode(embed_content)[..16]
    );

    // ── 7. Build the FraudBroadcast and publish kind:9101 ──
    let broadcast = FraudBroadcast {
        proof,
        embedding: ProofEmbedding {
            ledger_id: accused_ledger.clone(),
            sequence: embed_seq,
            update_hash: hex::encode(embed_content),
            field: "delivery_request_hash".into(),
        },
        causal_chain: Vec::<CausalLink>::new(), // same-ledger
    };
    eprintln!("[publish] kind:9101 from op0");
    publish_fraud_broadcast(&node, 0, &broadcast);

    // ── 8. Poll for confiscation marker on any quorum member ──
    let op_idx = poll_confiscation_marker(&accused_ledger, Duration::from_secs(180));
    eprintln!(
        "[ok] verified fraud-proof drove confiscation: marker at op{}/confiscated_{}.marker",
        op_idx,
        &accused_ledger[..16]
    );
}
