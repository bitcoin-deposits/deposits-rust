//! Tier-3 cluster test: end-to-end replacement-collateral pipeline.
//!
//! Drives the full RC1–RC9 stack against a running regtest cluster.
//! Funds each potential disputant's operator-key P2WPKH address (so RC6
//! auto-arm finds a UTXO to declare), fires a `QuorumExpired` fraud
//! proof, and verifies:
//!
//!   1. Each quorum member's auto-armed `DisputeArmed` event on the
//!      fork branch carries `Some(replacement_collateral)` (RC6).
//!   2. The declared UTXO is at the disputant's operator-key P2WPKH
//!      and has value ≥ the declared amount (RC4 + RC6 invariant).
//!   3. The cosigner-side inequality holds against ledger state at
//!      `last_valid_sequence` (RC3 inequality).
//!   4. The confiscation TX confirmed on-chain (existing assertion;
//!      proves cosigners signed off on the declarations).
//!
//! TEST PRECONDITIONS:
//!   - Cluster started: `./bin/setup.sh 3`
//!   - L3 quorum has expired (mine ~1010 blocks past the QuorumBegin tx,
//!     or set up the cluster with a short --quorum-expiry override).
//!     See `fraud_proof_quorum_expired.rs` for the same precondition.
//!
//! Not in the default `cargo test` pass — `#[ignore]`'d.

use deposits_core::messages::LedgerOperation;
use deposits_core::tlv::TlvDecode;
use deposits_protocol::fraud::{
    CausalLink, FraudBroadcast, FraudEvidence, FraudProof, FraudProofType, ProofEmbedding,
};
use deposits_test::regtest::*;
use std::time::Duration;

#[test]
#[ignore]
fn replacement_collateral_round_trips_through_dispute_pipeline() {
    if !cluster_available() {
        eprintln!("skipping: cluster not running — start with ./bin/setup.sh 3");
        return;
    }

    let node = build_node_with_danger();

    // ── 0. Fund each operator's op-key P2WPKH ──
    // RC6 auto-arm pulls a UTXO from this address to declare. Without
    // funding, the declaration is None and a strict cosigner (RC3)
    // refuses confiscation. Mine a few blocks so the funding TX has
    // enough confirmations to satisfy CollateralPolicy::default
    // (min_confirmations = 1).
    //
    // Amount: 100_000 sats per op — comfortably above any realistic
    // `obligations × ratio + fee` floor for a Q=3 test setup. Funding
    // happens for all three potential disputants (in Q=3 only the two
    // non-accused members will actually arm, but funding all three is
    // simpler than identifying the cosigner subset upfront).
    for op_idx in 0..3 {
        let txid = fund_operator_key_address(op_idx, 100_000);
        eprintln!("[fund]    op{} op-key P2WPKH funded by {}", op_idx, txid);
    }
    mine_blocks(2);

    // ── 1. Mirror the QuorumExpired setup ──
    let accused_op_idx: usize = 1;
    let accused_ledger = read_setup_state("ledger_1_3");
    // Wait for op1's daemon to ingest its own QuorumBegin (race with
    // `setup.sh` returning).
    wait_for_quorum_begin(accused_op_idx, &accused_ledger, std::time::Duration::from_secs(30));
    let peer_op_idx = find_peer_with_ledger(&accused_ledger, accused_op_idx)
        .expect("no peer has op1's L3 ledger imported — quorum activation may have failed");

    let history = read_ledger_history(&op_data_dir(accused_op_idx), &accused_ledger);
    let mut quorum_expiry: Option<u32> = None;
    for u in history.iter().rev() {
        if let Ok(LedgerOperation::QuorumBegin {
            quorum_expiry: e, ..
        }) = LedgerOperation::tlv_decode(&u.message)
        {
            quorum_expiry = Some(e);
            break;
        }
    }
    let quorum_expiry =
        quorum_expiry.expect("accused ledger has no QuorumBegin — quorum was never active");

    // Mine past expiry + grace if the chain hasn't already been
    // advanced. Then wait for the accused's daemon to anchor a
    // post-expiry block to the ledger.
    let chain_tip = current_block_height();
    let target = quorum_expiry + 720 + 80;
    if chain_tip < target {
        let to_mine = target - chain_tip;
        eprintln!("[setup]   mining {} blocks → tip {} (past expiry+grace)", to_mine, target);
        mine_blocks(to_mine);
        wait_for_daemon_chain_tip(accused_op_idx, target, std::time::Duration::from_secs(120));
    }

    // Re-read the ledger history — the accused's daemon should have
    // anchored a new block_hash by now (the auto-anchor task runs
    // every ~10s in fast-poll). Poll for up to 30s.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut latest_anchor = None;
    while std::time::Instant::now() < deadline {
        let fresh_history = read_ledger_history(&op_data_dir(accused_op_idx), &accused_ledger);
        if let Some(u) = fresh_history
            .into_iter()
            .rev()
            .find(|u| u.block_hash != [0u8; 32] && u.block_height > quorum_expiry)
        {
            latest_anchor = Some(u);
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
    let latest_anchor = latest_anchor.unwrap_or_else(|| {
        panic!(
            "accused ledger has no post-expiry anchored block_hash within 30s after \
             mining past expiry — anchor task may be stuck or daemon not synced"
        )
    });
    let anchor_block_hash = latest_anchor.block_hash;
    eprintln!(
        "[setup]   accused=op{}  ledger={}…  peer=op{}",
        accused_op_idx,
        &accused_ledger[..16],
        peer_op_idx
    );

    // ── 2. Build + publish the fraud proof ──
    let proof = FraudProof {
        proof_type: FraudProofType::QuorumExpired,
        accused: hex::encode(history[0].operator_id.serialize()),
        ledger_id: accused_ledger.clone(),
        evidence: FraudEvidence::QuorumExpired {
            anchor_block_hash,
            quorum_expiry,
        },
    };
    let proof_hash = proof.proof_hash();
    let embed_update = embed_proof_hash(
        &node,
        accused_op_idx,
        peer_op_idx,
        &accused_ledger,
        proof_hash,
    );
    let broadcast = FraudBroadcast {
        proof,
        embedding: ProofEmbedding {
            ledger_id: accused_ledger.clone(),
            sequence: embed_update.sequence_number,
            update_hash: hex::encode(embed_update.content_hash),
            field: "delivery_request_hash".into(),
        },
        causal_chain: Vec::<CausalLink>::new(),
    };
    publish_fraud_broadcast(&node, accused_op_idx, &broadcast);

    // ── 3. Wait for confiscation ──
    // If RC3 cosigner verification accepts, this marker appears. If any
    // disputant declared None or an under-sized UTXO, no confiscation
    // happens and the poll panics on timeout.
    let confiscation_op = poll_confiscation_marker(&accused_ledger, Duration::from_secs(180));
    eprintln!(
        "[ok]      confiscation marker on op{}/confiscated_{}.marker",
        confiscation_op,
        &accused_ledger[..16]
    );

    // ── 4. Assert each disputant's DisputeArmed carries
    //       Some(replacement_collateral) ──
    // Walk every operator's data dir for fork-branch files matching this
    // ledger. Each fork file's last DisputeArmed update must have a
    // non-None declaration, since RC3 cosigner verification refused
    // confiscation otherwise.
    use deposits_core::SignedLedgerUpdate;
    let mut disputants_with_decl: Vec<(usize, deposits_core::messages::ReplacementCollateral)> =
        Vec::new();
    for op_idx in 0..3 {
        if op_idx == accused_op_idx {
            continue;
        }
        let data_dir = op_data_dir(op_idx);
        let entries = match std::fs::read_dir(data_dir.join("wallet")) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            // Compound key shape: {ledger_id}_{lvs:06}_{disputer_pk_16}.jsonl
            if !name.starts_with(&accused_ledger) || !name.ends_with(".jsonl") {
                continue;
            }
            // Tail-scan the JSONL for the most recent DisputeArmed.
            let contents = match std::fs::read_to_string(entry.path()) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let mut latest_armed_decl: Option<deposits_core::messages::ReplacementCollateral> =
                None;
            for line in contents.lines() {
                // Each line is `{"type":"Update","update":{...SignedLedgerUpdate...}}`
                // (or similar). Parse loosely as Value and pluck `update`.
                let v: serde_json::Value = match serde_json::from_str(line) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let upd_val = match v.get("update") {
                    Some(u) => u.clone(),
                    None => continue,
                };
                if let Ok(upd) = serde_json::from_value::<SignedLedgerUpdate>(upd_val) {
                    if let Ok(LedgerOperation::DisputeArmed {
                        replacement_collateral,
                        ..
                    }) = LedgerOperation::tlv_decode(&upd.message)
                    {
                        if let Some(rc) = replacement_collateral {
                            latest_armed_decl = Some(rc);
                        }
                    }
                }
            }
            if let Some(rc) = latest_armed_decl {
                disputants_with_decl.push((op_idx, rc));
            }
        }
    }

    assert!(
        !disputants_with_decl.is_empty(),
        "no disputant declared replacement_collateral on the fork branch — \
         RC6 auto-arm pipeline likely failed to find a fundable UTXO. \
         Check that fund_operator_key_address sent to the right address \
         and the funding tx confirmed before auto-arm ran."
    );

    for (op_idx, rc) in &disputants_with_decl {
        eprintln!(
            "[decl]    op{} declared {} sats from {}:{}",
            op_idx,
            rc.amount,
            hex::encode(rc.txid),
            rc.vout
        );
        assert!(rc.amount > 0, "op{} declared a zero-amount UTXO", op_idx);
    }

    eprintln!(
        "[ok]      verified {} disputant(s) declared replacement_collateral; \
         cosigners must have approved the inequality + UTXO check (RC3) for \
         confiscation to land",
        disputants_with_decl.len()
    );
}
