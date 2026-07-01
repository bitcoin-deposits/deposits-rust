//! Integration test: `FraudProofType::Equivocation` end-to-end.
//!
//! The accusation: the operator double-signed — two distinct
//! `SignedLedgerUpdate`s at the same `(ledger_id, sequence_number)`,
//! both bearing the operator's BIP-340 signature. A canonical chain
//! can only have one update per seq, so two operator signatures at
//! the same seq is unrecoverable proof of misbehavior.
//!
//! Verification is fully self-contained: the two equivocating updates
//! travel inside the `FraudEvidence::Equivocation` variant, so the
//! verifier doesn't need any relay/oracle/cosigner-ledger lookup
//! beyond the proof itself. That's why this test bypasses the
//! `recovery start` → `kind:9103` path that `dispute_initiation` uses
//! (and that's fragile to relay-side duplicate-seq quirks): we publish
//! a kind:9101 `FraudBroadcast` directly.
//!
//! Flow:
//!   1. Fund every op's op-key P2WPKH (RC declaration precondition,
//!      identical recipe to fraud_proof_quorum_expired).
//!   2. Discover op0's active ledger; resolve its current quorum
//!      members.
//!   3. Run `deposits-node danger fork-update <ledger_id>
//!      --cosigner-seed <hex>+` — mints two cosigned updates at the
//!      same `{sequence, previous_hash}` with different message
//!      content, both signed by the operator, both cosigned by the
//!      quorum majority. Broadcasts U_A, waits, broadcasts U_B.
//!   4. Pull both updates back off the relay by filtering on the
//!      ledger_id and picking the two with matching sequence_number
//!      and operator_id but differing content_hash.
//!   5. Embed the proof_hash on a cosigner's ledger via DEP-12
//!      delivery_embed.
//!   6. Publish the `FraudBroadcast` (kind:9101).
//!   7. Poll for confiscation on-chain — the cosigners must arm and
//!      drive the confiscation TX through to broadcast.
//!
//! TEST PRECONDITIONS:
//!   - Cluster started: `./bin/setup.sh 3`
//!   - L1 quorum active on op0's ledger (setup.sh does this).
//!
//! Not in the default `cargo test` pass — `#[ignore]`'d.

use deposits_core::messages::LedgerOperation;
use deposits_core::tlv::{TlvDecode, TlvEncode};
use deposits_core::SignedLedgerUpdate;
use deposits_protocol::fraud::{
    CausalLink, FraudBroadcast, FraudEvidence, FraudProof, FraudProofType, ProofEmbedding,
};
use deposits_test::regtest::*;
use std::process::Command;
use std::time::Duration;

#[test]
#[ignore]
fn fraud_proof_equivocation_drives_confiscation() {
    if !cluster_available() {
        eprintln!("skipping: cluster not running — start with ./bin/setup.sh 3");
        return;
    }

    let node = build_node_with_danger();

    // ── 0. Fund every operator's op-key P2WPKH ──
    // RC6 auto-arm needs a UTXO at each disputant's op-key address;
    // unfunded → DisputeArmed declares None → cosigners refuse to
    // sign confiscation. Same recipe as fraud_proof_quorum_expired.
    for op_idx in 0..16 {
        let _ = fund_operator_key_address(op_idx, 100_000);
    }
    mine_blocks(2);

    // ── 1. Open a fresh victim ledger on op0 + 3 healthy cosigners ──
    //
    // Why not reuse a setup.sh ledger: by the time this test runs
    // (alphabetically after auto_dispute_on_expiry / candidate_queue_swap),
    // peers have auto-disputed every setup ledger and the forged
    // equivocation never reaches their canonical chain.
    let accused_op_idx: usize = 0;
    let victim = match open_victim_quorum_ledger(&node, accused_op_idx, 10_000, 3) {
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
    let history = read_ledger_history(&op_data_dir(accused_op_idx), &accused_ledger);
    let accused_pubkey_hex = hex::encode(history[0].operator_id.serialize());

    // `danger fork-update` needs every cosigner's seed. The victim
    // helper already enrolled the cosigners we picked, so use those
    // op indices directly.
    let cosigner_op_indices: Vec<usize> =
        victim.members.iter().map(|(op_idx, _, _)| *op_idx).collect();
    eprintln!("[setup] accused=op{}  ledger={}…", accused_op_idx, &accused_ledger[..16]);
    eprintln!("[setup] cosigner ops: {:?}", cosigner_op_indices);

    // ── 2. Run `danger fork-update` with all cosigner seeds ──
    let mut fork_args: Vec<String> = vec![
        "danger".to_string(),
        "fork-update".to_string(),
        accused_ledger.clone(),
    ];
    for op_idx in &cosigner_op_indices {
        fork_args.push("--cosigner-seed".to_string());
        fork_args.push(op_seed(*op_idx));
    }
    let out = Command::new(&node)
        .args(&fork_args)
        .args(["--seed", &op_seed(accused_op_idx)])
        .args(["--name", &format!("op{}", accused_op_idx)])
        .args(["--network", "regtest"])
        .args([
            "--data-dir",
            op_data_dir(accused_op_idx).to_str().unwrap(),
        ])
        .args(["--esplora", ELECTRS_URL])
        .args(["--relay", relay_ledgers()])
        .output()
        .expect("invoke danger fork-update");
    if !out.status.success() {
        panic!(
            "danger fork-update failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let fork_stdout = String::from_utf8_lossy(&out.stdout);
    eprintln!("[fork-update]\n{}", fork_stdout);
    let peer_op = cosigner_op_indices[0];

    // ── 3. Parse the two updates' TLV bytes straight from stdout ──
    // Cosigners only persist the update that applies cleanly (U_A);
    // U_B is rejected at the ledger_actor edge and never reaches
    // disk. The relay does carry both events, but fetching back is
    // racy and adds a Nostr dependency to the test. `danger
    // fork-update` already has both updates in memory — it prints
    // their TLV bytes as `U_A tlv_hex=...` / `U_B tlv_hex=...` lines
    // for exactly this consumer.
    let pluck = |needle: &str| -> Option<Vec<u8>> {
        fork_stdout
            .lines()
            .find(|l| l.trim().starts_with(needle))
            .and_then(|l| l.split('=').nth(1))
            .and_then(|s| hex::decode(s.trim()).ok())
    };
    let bytes_a = pluck("U_A tlv_hex").expect(
        "danger fork-update stdout missing `U_A tlv_hex=...` line — \
         older build of deposits-node?",
    );
    let bytes_b = pluck("U_B tlv_hex").expect("missing `U_B tlv_hex=...` line");
    let update_a = SignedLedgerUpdate::tlv_decode(&bytes_a)
        .expect("decode U_A from danger stdout");
    let update_b = SignedLedgerUpdate::tlv_decode(&bytes_b)
        .expect("decode U_B from danger stdout");
    assert_eq!(
        update_a.sequence_number, update_b.sequence_number,
        "fork-update produced two updates at different seqs — danger bug"
    );
    assert_ne!(
        update_a.content_hash, update_b.content_hash,
        "fork-update produced two identical content_hashes — not an equivocation"
    );
    let equiv_seq = update_a.sequence_number;
    eprintln!(
        "[evidence] equivocation at seq {}: content_a={}… content_b={}…",
        equiv_seq,
        hex::encode(&update_a.content_hash[..8]),
        hex::encode(&update_b.content_hash[..8])
    );

    // ── 4. Build the FraudProof ──
    let proof = FraudProof {
        proof_type: FraudProofType::Equivocation,
        accused: accused_pubkey_hex.clone(),
        ledger_id: accused_ledger.clone(),
        evidence: FraudEvidence::Equivocation {
            sequence: equiv_seq,
            update_a_hex: hex::encode(update_a.tlv_encode()),
            update_b_hex: hex::encode(update_b.tlv_encode()),
        },
    };
    let proof_hash = proof.proof_hash();
    eprintln!("[proof] hash={}…", &hex::encode(proof_hash)[..16]);

    // Sanity: classify punitive (operator provably misbehaved).
    assert!(
        !proof.proof_type.is_respectful(),
        "Equivocation must be classified punitive"
    );

    // ── 5. Embed proof_hash via DEP-12 delivery_embed on a peer ──
    let embed_update = embed_proof_hash(
        &node,
        accused_op_idx,
        peer_op,
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
    eprintln!("[publish] kind:9101 Equivocation from op{}", accused_op_idx);
    publish_fraud_broadcast(&node, accused_op_idx, &broadcast);

    // ── 6. Poll for confiscation TX on-chain ──
    let (op_idx, txid) = poll_confiscation_txid(&accused_ledger, Duration::from_secs(180));
    eprintln!(
        "[ok] Equivocation drove confiscation: tx {} (observed via op{})",
        txid, op_idx
    );
}

/// End-to-end of the AUTO-emit path (the lifecycle trigger). Unlike the test
/// above — which hand-builds, embeds, and publishes the kind:9101 broadcast —
/// here we publish NOTHING by hand. The operator double-signs a sequence and
/// the cosigners' daemons must, on their own: detect the equivocation on
/// inbound ingest (`handle_ledger_update` → `updates_equivocate`), build the
/// `Equivocation` FraudProof, anchor it via a cosigned DEP-12 embed on one of
/// their own ledgers, broadcast it (kind:9101), and the confiscation cascade
/// must fire. This proves the dormant machinery is actually wired to a trigger.
#[test]
#[ignore]
fn equivocation_auto_emits_and_confiscates() {
    if !cluster_available() {
        eprintln!("skipping: cluster not running — start with ./bin/setup.sh 3");
        return;
    }

    let node = build_node_with_danger();

    // Fund every op-key P2WPKH (RC6 auto-arm needs a UTXO per disputant).
    for op_idx in 0..16 {
        let _ = fund_operator_key_address(op_idx, 100_000);
    }
    mine_blocks(2);

    // Fresh victim ledger on op0 + 3 healthy cosigners.
    let accused_op_idx: usize = 0;
    let victim = match open_victim_quorum_ledger(&node, accused_op_idx, 10_000, 3) {
        Some(v) => v,
        None => {
            eprintln!(
                "skipping: couldn't open a fresh Q=3 victim — rerun against `setup.sh --fresh 3`."
            );
            return;
        }
    };
    let accused_ledger = victim.victim_ledger.clone();
    let cosigner_op_indices: Vec<usize> =
        victim.members.iter().map(|(op_idx, _, _)| *op_idx).collect();
    eprintln!(
        "[setup] accused=op{} ledger={}… cosigners={:?}",
        accused_op_idx,
        &accused_ledger[..16],
        cosigner_op_indices
    );

    // Operator double-signs seq N. `danger fork-update` broadcasts U_A, waits
    // 4s, then broadcasts the conflicting U_B — so cosigners ingest U_A and
    // advance, then see U_B at the same seq. That second ingest is exactly
    // what the detector keys on. We intentionally ignore the printed TLV here.
    let mut fork_args: Vec<String> =
        vec!["danger".into(), "fork-update".into(), accused_ledger.clone()];
    for op_idx in &cosigner_op_indices {
        fork_args.push("--cosigner-seed".into());
        fork_args.push(op_seed(*op_idx));
    }
    let out = Command::new(&node)
        .args(&fork_args)
        .args(["--seed", &op_seed(accused_op_idx)])
        .args(["--name", &format!("op{}", accused_op_idx)])
        .args(["--network", "regtest"])
        .args(["--data-dir", op_data_dir(accused_op_idx).to_str().unwrap()])
        .args(["--esplora", ELECTRS_URL])
        .args(["--relay", relay_ledgers()])
        .output()
        .expect("invoke danger fork-update");
    assert!(
        out.status.success(),
        "danger fork-update failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    eprintln!("[fork-update]\n{}", String::from_utf8_lossy(&out.stdout));

    // NO hand-built proof, NO embed, NO publish. The cosigner daemons must do
    // all of it autonomously. Poll for the resulting confiscation TX.
    let (op_idx, txid) = poll_confiscation_txid(&accused_ledger, Duration::from_secs(300));
    eprintln!(
        "[ok] AUTO-emitted equivocation proof drove confiscation: tx {} (observed via op{})",
        txid, op_idx
    );
}

/// Serviceability bar (DEP-06 blocker fix): the confiscation cascade must
/// carry all the way through winner-selection to a *serviceable* recovered
/// ledger — not merely land the confiscation TX.
///
/// This is the regression guard for the fixed-length lottery-preimage bug:
/// `derive_dispute_lottery_preimage` used to return a 32-byte preimage, so
/// the fast lottery-claim leaf's `OP_SIZE` bound (`17..=16+N`, = `17..=19`
/// at Q=3) rejected it and the claim was unspendable — the pipeline died
/// at winner-selection and the forked ledger never got a `DisputeAcquire`,
/// staying `DISPUTED` forever. With the length-shaping fix, an honest
/// cosigner wins, publishes `DisputeAcquire`, and the ledger becomes
/// depositable again under the new custodian.
///
/// Assertions past the confiscation TX:
///   1. a `DisputeAcquire` appears (winner selected → custody transferred),
///   2. `dispute status` reports `RESOLVED` (not `DISPUTED`),
///   3. the new custodian is one of the honest cosigners (not the accused),
///   4. a depositor can `deposits-wallet open` a deposit on the ledger.
#[test]
#[ignore]
fn equivocation_recovers_to_serviceable_ledger() {
    if !cluster_available() {
        eprintln!("skipping: cluster not running — start with ./bin/setup.sh 3 --fresh");
        return;
    }

    let node = build_node_with_danger();
    for op_idx in 0..16 {
        let _ = fund_operator_key_address(op_idx, 100_000);
    }
    mine_blocks(2);

    let accused_op_idx: usize = 0;
    let victim = match open_victim_quorum_ledger(&node, accused_op_idx, 10_000, 3) {
        Some(v) => v,
        None => {
            eprintln!("skipping: couldn't open a fresh Q=3 victim — rerun against `setup.sh --fresh 3`.");
            return;
        }
    };
    let accused_ledger = victim.victim_ledger.clone();
    let cosigner_op_indices: Vec<usize> =
        victim.members.iter().map(|(op_idx, _, _)| *op_idx).collect();
    let (_accused_full, accused_pk) = op_identity_pubkey(accused_op_idx);
    eprintln!(
        "[setup] accused=op{} ({}…) ledger={}… cosigners={:?}",
        accused_op_idx,
        &accused_pk[..12],
        &accused_ledger[..16],
        cosigner_op_indices
    );

    // Equivocate: double-sign the same sequence to both branches.
    let mut fork_args: Vec<String> =
        vec!["danger".into(), "fork-update".into(), accused_ledger.clone()];
    for op_idx in &cosigner_op_indices {
        fork_args.push("--cosigner-seed".into());
        fork_args.push(op_seed(*op_idx));
    }
    let out = Command::new(&node)
        .args(&fork_args)
        .args(["--seed", &op_seed(accused_op_idx)])
        .args(["--name", &format!("op{}", accused_op_idx)])
        .args(["--network", "regtest"])
        .args(["--data-dir", op_data_dir(accused_op_idx).to_str().unwrap()])
        .args(["--esplora", ELECTRS_URL])
        .args(["--relay", relay_ledgers()])
        .output()
        .expect("invoke danger fork-update");
    assert!(
        out.status.success(),
        "danger fork-update failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // 1. Confiscation TX must land (arm → confiscate).
    let (obs_op, txid) = poll_confiscation_txid(&accused_ledger, Duration::from_secs(300));
    eprintln!("[ok] confiscation TX {} (via op{})", txid, obs_op);

    // 2a. On-chain lottery claim — the DEFINITIVE proof of the fix. The
    //     confiscation TX paid a single P2TR lottery output; the fast
    //     lottery-claim leaf (unspendable since inception under the 32-byte
    //     preimage bug) must now be spent by the winner, revealing preimages
    //     whose lengths sit in `[17, 16+N]` (= [17,19] at Q=3). We assert
    //     both that the leaf was spent AND that the revealed preimages carry
    //     valid lengths — the exact regression the fix closes.
    let lottery_addr = lottery_output_address(&txid)
        .expect("confiscation TX must have a P2TR lottery output");
    eprintln!("[info] lottery output address: {}", lottery_addr);
    let (claim_txid, witness_lens) =
        poll_lottery_claim_witness(&lottery_addr, Duration::from_secs(300)).unwrap_or_else(|| {
            panic!(
                "lottery-claim leaf never spent for {} — the fast claim path is still \
                 unspendable (fixed-length preimage regression)",
                &accused_ledger[..16]
            )
        });
    eprintln!(
        "[ok] lottery-claim leaf SPENT: tx {} witness item lens {:?}",
        claim_txid, witness_lens
    );
    // Witness = [winner_sig(64), preimage_0, .., preimage_{N-1}, leaf, control].
    // The preimages are the middle items; every one must be in [17, 16+N]=[17,19].
    let preimage_lens: Vec<usize> = witness_lens
        .iter()
        .copied()
        .filter(|&l| (17..=19).contains(&l))
        .collect();
    assert!(
        preimage_lens.len() >= 3,
        "expected ≥3 length-valid preimages (17..=19) in the claim witness, got lens {:?}",
        witness_lens
    );
    eprintln!(
        "[ok] winner selected on-chain from length-carrying preimages {:?}",
        preimage_lens
    );

    // 2b. Reveal → winner-selection → DisputeAcquire. This is the step the
    //    fixed-length preimage bug used to kill: the claim leaf was
    //    unspendable so no DisputeAcquire ever appeared.
    let new_custodian = poll_dispute_acquire(&accused_ledger, Duration::from_secs(420))
        .unwrap_or_else(|| {
            panic!(
                "no DisputeAcquire within timeout for ledger {} — winner-selection stalled \
                 (the fixed-length preimage regression, or claim leaf unspendable)",
                &accused_ledger[..16]
            )
        });
    let custodian_hex = hex::encode(new_custodian.serialize());
    eprintln!("[ok] DisputeAcquire → new custodian {}…", &custodian_hex[..16]);

    // 3. New custodian must be an honest cosigner, never the accused.
    let custodian_xonly = hex::encode(new_custodian.x_only_public_key().0.serialize());
    assert_ne!(
        custodian_xonly, accused_pk,
        "winner must not be the accused equivocator"
    );
    let honest: Vec<String> = cosigner_op_indices
        .iter()
        .map(|i| op_identity_pubkey(*i).1)
        .collect();
    assert!(
        honest.contains(&custodian_xonly),
        "new custodian {} not among honest cosigners {:?}",
        &custodian_xonly[..16],
        honest
    );

    // 4. `dispute status` must report RESOLVED (not DISPUTED).
    let mut resolved = false;
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    let mut last_status = String::new();
    while std::time::Instant::now() < deadline {
        last_status = dispute_status(cosigner_op_indices[0], &accused_ledger);
        if last_status.contains("DISPUTE_STATUS: RESOLVED") {
            resolved = true;
            break;
        }
        std::thread::sleep(Duration::from_secs(3));
    }
    assert!(
        resolved,
        "dispute status never became RESOLVED; last:\n{}",
        last_status
    );
    assert!(
        !last_status.contains("DISPUTE_STATUS: DISPUTED"),
        "ledger still reports DISPUTED after recovery"
    );
    eprintln!("[ok] dispute status = RESOLVED");

    // 5. Serviceability: a depositor can open a deposit on the recovered
    //    ledger. Give the new custodian a moment to auto-continue and
    //    begin cosigning, then open.
    mine_blocks(2);
    std::thread::sleep(Duration::from_secs(5));
    let wdir = tempdir();
    let (sec_hex, _xonly) = keygen();
    let nsec = wdir.join("wallet.nsec");
    std::fs::write(&nsec, &sec_hex).expect("write wallet nsec");

    let mut opened = false;
    let mut last_open = String::new();
    for attempt in 0..6 {
        let (ok, msg) = wallet_open(
            &accused_ledger,
            &format!("post-recovery-{}", attempt),
            &nsec,
            &wdir,
            &[],
        );
        last_open = msg;
        if ok {
            opened = true;
            break;
        }
        mine_blocks(1);
        std::thread::sleep(Duration::from_secs(5));
    }
    assert!(
        opened,
        "deposit could not be opened on the recovered ledger; last wallet output:\n{}",
        last_open
    );
    eprintln!("[ok] SERVICEABLE: a deposit opened on the recovered ledger under the new custodian");
}
