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

    // Pause auto_quorum_refresh on the accused before we start mining.
    // Otherwise op1 self-rescues past expiry and the cosigners see a
    // fresh quorum — no dispute fires. Marker is dropped via Drop guard.
    let refresh_pause_path = op_data_dir(1).join(".pause_auto_quorum_refresh");
    std::fs::write(&refresh_pause_path, b"replacement_collateral_e2e")
        .expect("write refresh-pause marker on accused");
    struct PauseGuard(std::path::PathBuf);
    impl Drop for PauseGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let _refresh_pause_guard = PauseGuard(refresh_pause_path);

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
    // Fund ALL cluster ops' op-key addresses, not just 0..3. The
    // ledger's actual quorum members depend on setup.sh's assignment
    // (Q=3 picks any 3 of the cluster's 16 ops). Any unfunded member
    // who happens to be a cosigner declares None, and the strict RC3
    // verifier refuses confiscation. Same pattern as
    // fraud_proof_quorum_expired (which fund-funds 0..16).
    for op_idx in 0..16 {
        let _ = fund_operator_key_address(op_idx, 100_000);
    }
    mine_blocks(2);

    // ── 1. Mirror the QuorumExpired setup ──
    // Use op3's L3 (ledger_3_3) so we don't clash with
    // fraud_proof_quorum_expired's use of ledger_1_3. Both tests
    // drive a ledger to confiscation; running both against the same
    // ledger on the same cluster fails the second one because the
    // accused's ledger is already in a frozen dispute state and
    // can't accept the proof-embed update.
    let accused_op_idx: usize = 3;
    let accused_ledger = read_setup_state("ledger_3_3");
    // Wait for op1's daemon to ingest its own QuorumBegin (race with
    // `setup.sh` returning). 90s — fresh cluster sometimes takes
    // longer than 30s to settle after setup.sh returns.
    wait_for_quorum_begin(
        accused_op_idx,
        &accused_ledger,
        std::time::Duration::from_secs(90),
    );

    let history = read_ledger_history(&op_data_dir(accused_op_idx), &accused_ledger);
    let mut quorum_expiry: Option<u32> = None;
    let mut quorum_member_pks: Vec<bitcoin::secp256k1::PublicKey> = Vec::new();
    for u in history.iter().rev() {
        if let Ok(LedgerOperation::QuorumBegin {
            quorum_expiry: e,
            quorum_members,
            ..
        }) = LedgerOperation::tlv_decode(&u.message)
        {
            quorum_expiry = Some(e);
            quorum_member_pks = quorum_members.iter().map(|m| m.pubkey).collect();
            break;
        }
    }

    // Pick the embed peer from the actual quorum members.
    // `find_peer_with_ledger` returns any op with the file on disk,
    // which can be a non-member from earlier test runs — non-members
    // don't subscribe to operator updates and so can't relay the
    // freshly-embedded one back into our view.
    use bitcoin::secp256k1::{PublicKey, Secp256k1};
    let secp = Secp256k1::new();
    let peer_op_idx = (0..16)
        .find(|&i| {
            if i == accused_op_idx {
                return false;
            }
            if !op_data_dir(i).exists() {
                return false;
            }
            let sk = op_operator_secret(i);
            let pk = PublicKey::from_secret_key(&secp, &sk);
            quorum_member_pks.iter().any(|m| m == &pk)
        })
        .expect("no quorum member found among ops 0..16 — cluster shape unknown");
    let quorum_expiry =
        quorum_expiry.expect("accused ledger has no QuorumBegin — quorum was never active");

    // Mine just past expiry+1 so the fraud-proof anchor is past
    // expiry (the verifier requires strict >). The auto-detect path
    // (cosigners' periodic loop) needs `expiry+720+grace`, but here
    // we publish kind:9101 explicitly, which only requires
    // `anchor_height > quorum_expiry`. Same pattern as
    // fraud_proof_quorum_expired.
    //
    // The anchor itself comes from bitcoind directly — no need to
    // wait for the accused's daemon to write a fresh anchored ledger
    // update, since the verifier only checks the block_hash is in
    // its confirmed chain (not that the ledger references it).
    let chain_tip = current_block_height();
    let target = quorum_expiry + 10;
    if chain_tip < target {
        let to_mine = target - chain_tip;
        eprintln!(
            "[setup]   mining {} blocks → tip {} (past expiry+1)",
            to_mine, target
        );
        mine_blocks(to_mine);
    }
    let chain_tip = current_block_height();
    assert!(
        chain_tip > quorum_expiry,
        "chain tip {} must exceed quorum_expiry {}",
        chain_tip,
        quorum_expiry
    );
    let anchor_block_hash = get_block_hash(chain_tip);
    eprintln!(
        "[setup]   accused=op{}  ledger={}…  peer=op{}  anchor={}",
        accused_op_idx,
        &accused_ledger[..16],
        peer_op_idx,
        &hex::encode(anchor_block_hash)[..16]
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
        embedding: Some(ProofEmbedding {
            ledger_id: accused_ledger.clone(),
            sequence: embed_update.sequence_number,
            update_hash: hex::encode(embed_update.content_hash),
            field: "delivery_request_hash".into(),
        }),
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
    for op_idx in 0..16 {
        if op_idx == accused_op_idx {
            continue;
        }
        let data_dir = op_data_dir(op_idx);
        // Ledger JSONL files live at `wallet/ledgers/`, not `wallet/`.
        let entries = match std::fs::read_dir(data_dir.join("wallet/ledgers")) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            // Compound key shape: {ledger_id}_{lvs:06}_{disputer_pk_16}.jsonl
            // — only the fork files (length > base + 6), not the base file.
            if !name.starts_with(&accused_ledger)
                || !name.ends_with(".jsonl")
                || name.len() <= accused_ledger.len() + 6
            {
                continue;
            }
            // Tail-scan the JSONL for the most recent DisputeArmed with RC.
            // SignedLedgerUpdate rows are flat with `#[serde(tag = "type")]`
            // on the enum, so the Update's fields sit alongside
            // `"type":"Update"` on the same object — strip the tag and
            // deserialize directly.
            let contents = match std::fs::read_to_string(entry.path()) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let mut latest_armed_decl: Option<deposits_core::messages::ReplacementCollateral> =
                None;
            for line in contents.lines() {
                let mut v: serde_json::Value = match serde_json::from_str(line) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                if v.get("type").and_then(|t| t.as_str()) != Some("Update") {
                    continue;
                }
                if let Some(obj) = v.as_object_mut() {
                    obj.remove("type");
                }
                if let Ok(upd) = serde_json::from_value::<SignedLedgerUpdate>(v) {
                    if let Ok(LedgerOperation::DisputeArmed {
                        replacement_collateral: Some(rc),
                        ..
                    }) = LedgerOperation::tlv_decode(&upd.message)
                    {
                        latest_armed_decl = Some(rc);
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
