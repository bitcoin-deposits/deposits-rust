//! Integration test: `FraudProofType::NonConformingCosignature` end-to-end.
//!
//! The accusation: a cosigner put their BIP-340 key on a
//! non-conforming update on someone else's ledger. With majority-
//! cosign enforced, an operator can't unilaterally land a bad
//! update — cosigners are expected to refuse anything that fires a
//! `ConformanceViolation` under the active ruleset. If a non-
//! conforming update does land, every signer (operator + cosigners)
//! is on the hook.
//!
//! Disputed ledger ≠ fault ledger. The accused is slashed via
//! one of their OWN ledgers (cross-ledger punitive contagion),
//! distinct from the ledger where the bad update sits.
//!
//! Flow:
//!   1. Fund every op's op-key P2WPKH (RC declaration precondition).
//!   2. Pick op0's L1 as the fault ledger; resolve its quorum members.
//!   3. Run `deposits-node danger forge-non-conforming-cosig` —
//!      operator-signed plus forged cosignatures from passed-in
//!      seeds, message body is `InvoiceLock { amount=0, deposit_id
//!      = dummy, … }`. Either path lands as fraud: apply fails
//!      (dummy deposit_id) or conformance fires `ZeroAmount`.
//!   4. Parse the forged update's TLV bytes from danger stdout.
//!      Pick one of the cosigners as the accused.
//!   5. Build `FraudProof::NonConformingCosignature { fault_ledger_id,
//!      fault_sequence, governing_quorumbegin_seq }` — outer
//!      `ledger_id` is one of the accused's own ledgers (the
//!      disputed one).
//!   6. Embed the proof_hash on a peer of the disputed ledger via
//!      DEP-12 delivery_embed.
//!   7. Publish kind:9101 FraudBroadcast.
//!   8. Poll for confiscation on the *disputed* ledger (the
//!      accused's own, not the fault ledger).
//!
//! TEST PRECONDITIONS:
//!   - Cluster started: `./bin/setup.sh 3`
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
fn fraud_proof_non_conforming_cosignature_drives_cross_ledger_confiscation() {
    if !cluster_available() {
        eprintln!("skipping: cluster not running — start with ./bin/setup.sh 3");
        return;
    }

    let node = build_node_with_danger();

    // ── 0. Fund every op's op-key P2WPKH ──
    for op_idx in 0..16 {
        let _ = fund_operator_key_address(op_idx, 100_000);
    }
    mine_blocks(2);

    // ── 1. Open a fresh FAULT ledger on op0 + 3 healthy cosigners ──
    //
    // Why fresh: same cluster-poisoning issue as the rest of the
    // fraud_proof_* family — by the time this test runs, peers have
    // auto-disputed every setup ledger and the forged update can't
    // reach their canonical view.
    let fault_op_idx: usize = 0;
    let fault_victim = match open_victim_quorum_ledger(&node, fault_op_idx, 10_000, 3) {
        Some(v) => v,
        None => {
            eprintln!(
                "skipping: couldn't open a fresh fault victim — Q=3 healthy \
                 members not available. Rerun against `setup.sh --fresh 3`."
            );
            return;
        }
    };
    let fault_ledger_id = fault_victim.victim_ledger.clone();
    let fault_history = read_ledger_history(&op_data_dir(fault_op_idx), &fault_ledger_id);

    // The most-recent QuorumBegin's sequence = governing_qb_seq.
    let mut governing_qb_seq: u64 = 0;
    for u in fault_history.iter().rev() {
        if let Ok(LedgerOperation::QuorumBegin { .. }) = LedgerOperation::tlv_decode(&u.message) {
            governing_qb_seq = u.sequence_number;
            break;
        }
    }
    assert!(
        governing_qb_seq > 0,
        "fault victim ledger has no QuorumBegin",
    );

    let cosigner_op_indices: Vec<usize> = fault_victim
        .members
        .iter()
        .map(|(op_idx, _, _)| *op_idx)
        .collect();
    use bitcoin::secp256k1::{PublicKey, Secp256k1};
    let secp = Secp256k1::new();
    eprintln!(
        "[setup]  fault_op=op{}  fault_ledger={}…  cosigners={:?}",
        fault_op_idx,
        &fault_ledger_id[..16],
        cosigner_op_indices
    );

    // ── 2. Open a fresh DISPUTED ledger on the accused cosigner ──
    //
    // The accused (one of the fault ledger's cosigners) gets a
    // separate own-ledger that the fraud broadcast targets for
    // confiscation. Pick the first cosigner; open a fresh victim
    // ledger on them so it's also undisputed.
    let accused_op_idx = cosigner_op_indices[0];
    let disputed_victim = match open_victim_quorum_ledger(&node, accused_op_idx, 10_000, 3) {
        Some(v) => v,
        None => {
            eprintln!(
                "skipping: couldn't open a fresh disputed victim on op{} — \
                 Q=3 healthy members not available.",
                accused_op_idx
            );
            return;
        }
    };
    let disputed_ledger_id = disputed_victim.victim_ledger.clone();
    let accused_pubkey_hex = hex::encode(
        op_operator_secret(accused_op_idx)
            .public_key(&secp)
            .serialize(),
    );
    eprintln!(
        "[setup]  accused=op{} ({}…)  disputed={}…",
        accused_op_idx,
        &accused_pubkey_hex[..16],
        &disputed_ledger_id[..16]
    );

    // ── 3. Forge the non-conforming update ──
    let mut forge_args: Vec<String> = vec![
        "danger".into(),
        "forge-non-conforming-cosig".into(),
        fault_ledger_id.clone(),
    ];
    for op_idx in &cosigner_op_indices {
        forge_args.push("--cosigner-seed".into());
        forge_args.push(op_seed(*op_idx));
    }
    let out = Command::new(&node)
        .args(&forge_args)
        .args(["--seed", &op_seed(fault_op_idx)])
        .args(["--name", &op_name(fault_op_idx)])
        .args(["--network", "regtest"])
        .args(["--data-dir", op_data_dir(fault_op_idx).to_str().unwrap()])
        .args(["--esplora", ELECTRS_URL])
        .args(["--relay", relay_ledgers()])
        .output()
        .expect("spawn danger forge-non-conforming-cosig");
    if !out.status.success() {
        panic!(
            "danger forge-non-conforming-cosig failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let forge_stdout = String::from_utf8_lossy(&out.stdout);
    eprintln!("[forge]\n{}", forge_stdout);

    // ── 4. Parse the forged update from stdout ──
    let pluck = |needle: &str| -> Option<String> {
        forge_stdout
            .lines()
            .find(|l| l.trim().starts_with(needle))
            .and_then(|l| l.split('=').nth(1))
            .map(|s| s.trim().to_string())
    };
    let tlv_hex = pluck("U tlv_hex").expect(
        "danger forge-non-conforming-cosig stdout missing `U tlv_hex=...` — \
         older deposits-node build?",
    );
    let forged_bytes = hex::decode(&tlv_hex).expect("decode U tlv_hex");
    let forged_update =
        SignedLedgerUpdate::tlv_decode(&forged_bytes).expect("decode forged update");
    let fault_sequence = forged_update.sequence_number;
    eprintln!(
        "[evidence] fault_sequence={} forged content_hash={}…",
        fault_sequence,
        hex::encode(&forged_update.content_hash[..8])
    );

    // Wait for the cosigners' daemons to ingest the forged update
    // into their relay-fetched view of the fault ledger. Verification
    // gap-fills from the relay, so the forged update needs to be
    // discoverable there — it should be, since danger broadcast it.
    std::thread::sleep(Duration::from_secs(3));

    // ── 5. Build the FraudProof ──
    let proof = FraudProof {
        proof_type: FraudProofType::NonConformingCosignature,
        accused: accused_pubkey_hex.clone(),
        ledger_id: disputed_ledger_id.clone(), // accused's OWN ledger
        evidence: FraudEvidence::NonConformingCosignature {
            fault_ledger_id: fault_ledger_id.clone(),
            fault_sequence,
            governing_quorumbegin_seq: governing_qb_seq,
            fault_update_hex: hex::encode(forged_update.tlv_encode()),
        },
    };
    let proof_hash = proof.proof_hash();
    eprintln!("[proof] hash={}…", &hex::encode(proof_hash)[..16]);
    assert!(
        !proof.proof_type.is_respectful(),
        "NonConformingCosignature must be classified punitive"
    );

    // ── 6. Embed proof_hash on a peer of the DISPUTED ledger ──
    // Peer-of-disputed (a cosigner of the accused's ledger), not
    // peer-of-fault — embedding must live on the same ledger we're
    // disputing. We just enrolled disputed_victim.members[0] as a
    // cosigner of the disputed ledger, so use them directly.
    let peer_op = disputed_victim.members[0].0;
    eprintln!("[embed]  peer=op{} (cosigner of disputed ledger)", peer_op);

    let embed_update = embed_proof_hash(
        &node,
        accused_op_idx,
        peer_op,
        &disputed_ledger_id,
        proof_hash,
    );
    let broadcast = FraudBroadcast {
        proof,
        embedding: ProofEmbedding {
            ledger_id: disputed_ledger_id.clone(),
            sequence: embed_update.sequence_number,
            update_hash: hex::encode(embed_update.content_hash),
            field: "delivery_request_hash".into(),
        },
        causal_chain: Vec::<CausalLink>::new(),
    };

    // ── 7. Publish kind:9101 from the accused (anyone may publish) ──
    eprintln!(
        "[publish] kind:9101 NonConformingCosignature from op{}",
        accused_op_idx
    );
    publish_fraud_broadcast(&node, accused_op_idx, &broadcast);

    // ── 8. Poll for confiscation on the DISPUTED ledger ──
    let (observed_op, txid) = poll_confiscation_txid(&disputed_ledger_id, Duration::from_secs(180));
    eprintln!(
        "[ok] NonConformingCosignature drove cross-ledger confiscation: \
         disputed_ledger={}… tx={} (observed via op{})",
        &disputed_ledger_id[..16],
        txid,
        observed_op
    );
}

/// AUTO-detect variant: the daemons must drive the whole thing. We forge a
/// quorum-cosigned NON-CONFORMING update on the fault ledger and broadcast it
/// (no hand-built FraudProof, no embed, no publish). The fault ledger's
/// cosigners must detect it on ingest (`check_speculative` fails on a cosigned
/// update → the collusion signal), arm a dispute, ground the confiscation via
/// `fetch_non_conforming_cosig_inline_evidence`, and confiscate the fault
/// ledger. Same-ledger confiscation (the operator landed bad cosigned work),
/// the simpler counterpart to the cross-ledger contagion test above.
#[test]
#[ignore]
fn non_conforming_cosignature_auto_detects_and_confiscates() {
    if !cluster_available() {
        eprintln!("skipping: cluster not running — start with ./bin/setup.sh 3");
        return;
    }

    let node = build_node_with_danger();

    for op_idx in 0..16 {
        let _ = fund_operator_key_address(op_idx, 100_000);
    }
    mine_blocks(2);

    let fault_op_idx: usize = 0;
    let fault_victim = match open_victim_quorum_ledger(&node, fault_op_idx, 10_000, 3) {
        Some(v) => v,
        None => {
            eprintln!("skipping: couldn't open a fresh Q=3 fault victim — rerun against setup.sh --fresh 3");
            return;
        }
    };
    let fault_ledger_id = fault_victim.victim_ledger.clone();
    let cosigner_op_indices: Vec<usize> = fault_victim
        .members
        .iter()
        .map(|(op_idx, _, _)| *op_idx)
        .collect();
    eprintln!(
        "[setup] fault_op=op{} ledger={}… cosigners={:?}",
        fault_op_idx,
        &fault_ledger_id[..16],
        cosigner_op_indices
    );

    // Forge + broadcast a quorum-cosigned non-conforming update. We publish
    // NOTHING else — the cosigners' daemons must detect, arm, and confiscate.
    let mut forge_args: Vec<String> = vec![
        "danger".into(),
        "forge-non-conforming-cosig".into(),
        fault_ledger_id.clone(),
    ];
    for op_idx in &cosigner_op_indices {
        forge_args.push("--cosigner-seed".into());
        forge_args.push(op_seed(*op_idx));
    }
    let out = Command::new(&node)
        .args(&forge_args)
        .args(["--seed", &op_seed(fault_op_idx)])
        .args(["--name", &op_name(fault_op_idx)])
        .args(["--network", "regtest"])
        .args(["--data-dir", op_data_dir(fault_op_idx).to_str().unwrap()])
        .args(["--esplora", ELECTRS_URL])
        .args(["--relay", relay_ledgers()])
        .output()
        .expect("spawn danger forge-non-conforming-cosig");
    assert!(
        out.status.success(),
        "danger forge-non-conforming-cosig failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    eprintln!("[forge]\n{}", String::from_utf8_lossy(&out.stdout));

    // Poll for confiscation on the FAULT ledger, driven entirely by the
    // daemons' auto-detection.
    let (op_idx, txid) = poll_confiscation_txid(&fault_ledger_id, Duration::from_secs(300));
    eprintln!(
        "[ok] AUTO-detected non-conforming cosignature drove confiscation: tx {} (via op{})",
        txid, op_idx
    );
}

/// Walk `op_idx`'s view of `ledger_id` for the most recent
/// `QuorumBegin`, return its declared `quorum_members` pubkeys.
fn read_quorum_members_of(ledger_id: &str, op_idx: usize) -> Vec<bitcoin::secp256k1::PublicKey> {
    let history = read_ledger_history(&op_data_dir(op_idx), ledger_id);
    for u in history.iter().rev() {
        if let Ok(LedgerOperation::QuorumBegin { quorum_members, .. }) =
            LedgerOperation::tlv_decode(&u.message)
        {
            return quorum_members.iter().map(|m| m.pubkey).collect();
        }
    }
    Vec::new()
}
