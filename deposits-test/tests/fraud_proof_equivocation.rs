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

    // ── 1. Pick op0's active ledger and resolve its quorum ──
    let accused_op_idx: usize = 0;
    let accused_ledger = discover_op0_ledger();
    eprintln!("[setup] accused=op{}  ledger={}…", accused_op_idx, &accused_ledger[..16]);

    let history = read_ledger_history(&op_data_dir(accused_op_idx), &accused_ledger);
    let accused_pubkey_hex = hex::encode(history[0].operator_id.serialize());

    // Read the current quorum's members. We need every cosigner's
    // seed to drive `danger fork-update` (it builds the multi-cosig
    // entries itself).
    let mut quorum_member_pks: Vec<bitcoin::secp256k1::PublicKey> = Vec::new();
    for u in history.iter().rev() {
        if let Ok(LedgerOperation::QuorumBegin { quorum_members, .. }) =
            LedgerOperation::tlv_decode(&u.message)
        {
            quorum_member_pks = quorum_members.iter().map(|m| m.pubkey).collect();
            break;
        }
    }
    assert!(
        !quorum_member_pks.is_empty(),
        "accused ledger has no QuorumBegin — setup didn't activate the quorum"
    );

    // Map quorum-member pubkeys → op indices so we can pull their
    // seeds. setup.sh's seeds are deterministic.
    use bitcoin::secp256k1::{PublicKey, Secp256k1};
    let secp = Secp256k1::new();
    let mut cosigner_op_indices: Vec<usize> = Vec::new();
    for member_pk in &quorum_member_pks {
        for i in 0..16 {
            if !op_data_dir(i).exists() {
                break;
            }
            let sk = op_operator_secret(i);
            let pk = PublicKey::from_secret_key(&secp, &sk);
            if &pk == member_pk {
                cosigner_op_indices.push(i);
                break;
            }
        }
    }
    assert_eq!(
        cosigner_op_indices.len(),
        quorum_member_pks.len(),
        "couldn't map every quorum member pubkey back to an op index — \
         cluster shape mismatch"
    );
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
