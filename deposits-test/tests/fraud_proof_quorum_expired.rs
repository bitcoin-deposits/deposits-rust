//! Integration test: a verified `QuorumExpired` fraud proof drives the
//! dispute pipeline end-to-end with the *respectful* confiscation shape.
//!
//! The accused is the operator. The accusation: they failed to rotate
//! the quorum before `quorum_expiry`. Cosigners refuse to cosign past
//! that block (`Ledger::validate_for_cosign`), so a missed deadline is
//! fatal to the current quorum. The respectful confiscation tx
//! bifurcates: `obligations` worth of reserves go to the lottery
//! winner (who inherits the deposit obligations), and the change
//! (excess reserves + full collateral) returns to the operator's
//! pubkey. Respectful proofs do NOT propagate cross-ledger.
//!
//! `verify_quorum_expired` checks:
//!   1. `anchor_block_hash` is in the verifier's confirmed chain
//!   2. anchor_height > evidence.quorum_expiry (strictly past;
//!      the expiry block itself is still cosignable)
//!   3. evidence.quorum_expiry matches the ledger's most recent
//!      QuorumBegin's declared `quorum_expiry`
//!
//! Flow:
//!   1. Pick op1's L3 ledger.
//!   2. Find a peer (= quorum member of op1's L3) so the auto-arm path
//!      triggers from a node with full ledger view.
//!   3. Read the most recent QuorumBegin's `quorum_expiry` from history.
//!   4. Pick a confirmed anchor block whose height > quorum_expiry.
//!      (Cluster setup defaults the expiry to current_block + 1000,
//!      so this test needs either a fast-forwarded regtest or a
//!      short-expiry test setup. See `// TEST PRECONDITIONS` below.)
//!   5. Build FraudProof. Embed proof_hash via `recovery embed-hash`
//!      from op1 (the accused operator embeds the proof on their own
//!      ledger — same pattern as dispute_dereliction).
//!   6. Publish kind:9101. Poll for marker.
//!
//! TEST PRECONDITIONS (not yet automated by setup.sh):
//!   - The cluster's L3 quorum has expired. Either:
//!     (a) Run setup.sh with a short --quorum-expiry-blocks override
//!         (e.g., 10 blocks), then mine ~12 blocks before running this
//!         test — not yet supported by setup.sh, see TODO.
//!     (b) Mine 1000+ blocks past the QuorumBegin tx (regtest can do
//!         this fast via `bitcoin-cli generatetoaddress 1000 ...`).
//!
//! TODO (gated on the confiscation-tx bifurcation commit):
//!   - Add an assertion that the on-chain confiscation tx has the
//!     bifurcated shape: 2 outputs (lottery + change to operator),
//!     where the lottery output's value equals the ledger's
//!     `obligations` and the change goes to the operator's pubkey.
//!     Currently the test only verifies the dispute pipeline reaches
//!     confiscation — the output shape is still the punitive default
//!     (full UTXO to lottery) until bifurcation lands.

use deposits_core::messages::LedgerOperation;
use deposits_core::tlv::TlvDecode;
use deposits_protocol::fraud::{
    CausalLink, FraudBroadcast, FraudEvidence, FraudProof, FraudProofType, ProofEmbedding,
};
use deposits_test::regtest::*;
use std::time::Duration;

#[test]
#[ignore]
fn fraud_proof_quorum_expired_triggers_respectful_confiscation() {
    if !cluster_available() {
        eprintln!("skipping: cluster not running — start with ./bin/setup.sh 3");
        return;
    }

    let node = build_node_with_danger();

    // ── 1. Pick op1's L3 ledger — accused = op1, ledger = ledger_1_3 ──
    let accused_op_idx: usize = 1;
    let accused_ledger = read_setup_state("ledger_1_3");
    let peer_op_idx = find_peer_with_ledger(&accused_ledger, accused_op_idx)
        .expect("no peer has op1's L3 ledger imported — quorum activation may have failed");

    // Read from op1's own data dir — op1 is the operator and has full
    // history.
    let history = read_ledger_history(&op_data_dir(accused_op_idx), &accused_ledger);

    // ── 2. Find the most recent QuorumBegin's declared quorum_expiry ──
    // Iterate the history backwards; the verifier reads the same value.
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

    // ── 3. Pick a confirmed anchor block past the expiry ──
    // The verifier requires `anchor_height > quorum_expiry`. Find the
    // latest-anchored block in the ledger and fail loudly if it isn't
    // past expiry — that's the test precondition not being met.
    let latest_anchor = history
        .iter()
        .rev()
        .find(|u| u.block_hash != [0u8; 32])
        .expect("accused ledger has no anchored block_hash");
    if latest_anchor.block_height <= quorum_expiry {
        panic!(
            "TEST PRECONDITION not met: latest anchor at block {}, but quorum_expiry is {}. \
             This test requires the cluster's quorum to have expired — either set up the \
             cluster with a short --quorum-expiry override or mine enough regtest blocks \
             past the QuorumBegin to push the chain past expiry. See module docs.",
            latest_anchor.block_height, quorum_expiry
        );
    }
    let anchor_block_hash = latest_anchor.block_hash;
    eprintln!(
        "[setup]    accused=op{}  ledger={}…  peer=op{}",
        accused_op_idx,
        &accused_ledger[..16],
        peer_op_idx
    );
    eprintln!(
        "[anchors]  anchor_block_hash={}…  anchor_height={}  quorum_expiry={}",
        &hex::encode(anchor_block_hash)[..16],
        latest_anchor.block_height,
        quorum_expiry
    );

    // ── 4. Build the FraudProof ──
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
    eprintln!("[proof]    hash={}…", &hex::encode(proof_hash)[..16]);

    // Sanity-check the classification — QuorumExpired is the only
    // respectful type today. If this regresses, the bifurcation logic
    // gates on the wrong predicate.
    assert!(
        proof.proof_type.is_respectful(),
        "QuorumExpired must be classified respectful"
    );

    // ── 5. Embed proof_hash on op1's own ledger ──
    // For QuorumExpired the accused IS the operator, so they're the
    // ones with authority to extend the ledger. In a real scenario the
    // operator may not cooperate (they're the one being disputed), so
    // production embedding goes through DEP-12 delivery_embed on a
    // cosigner's ledger. For this test we use the operator's CLI for
    // simplicity — the verifier doesn't care which ledger the embed
    // lives on, only that it's reachable via causal chain.
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

    // ── 6. Publish kind:9101 — anyone can publish. Use op1. ──
    let broadcast = FraudBroadcast {
        proof,
        embedding: ProofEmbedding {
            ledger_id: accused_ledger.clone(),
            sequence: embed_seq,
            update_hash: hex::encode(embed_content),
            field: "delivery_request_hash".into(),
        },
        causal_chain: Vec::<CausalLink>::new(),
    };
    eprintln!("[publish]  kind:9101 from op{}", accused_op_idx);
    publish_fraud_broadcast(&node, accused_op_idx, &broadcast);

    let op_idx = poll_confiscation_marker(&accused_ledger, Duration::from_secs(180));
    eprintln!(
        "[ok] verified QuorumExpired drove confiscation: marker at op{}/confiscated_{}.marker",
        op_idx,
        &accused_ledger[..16]
    );

    // ── 7. Assert the on-chain confiscation tx is bifurcated ──
    // Read the txid the operator wrote into the marker file, fetch the
    // tx from esplora, and verify the output shape:
    //   • exactly 2 outputs (single output = punitive, would be wrong here)
    //   • output[0].value ≥ P2WSH_DUST_LIMIT_SATS (lottery output)
    //   • output[1].script_pubkey is the original operator's P2WPKH (change)
    // For QuorumExpired with no deposits in the cluster, obligations = 0
    // so the lottery output should equal the dust floor (330 sats).
    let marker_path = op_data_dir(op_idx).join(format!(
        "confiscated_{}.marker",
        &accused_ledger[..16]
    ));
    let txid_str = std::fs::read_to_string(&marker_path)
        .expect("read marker")
        .trim()
        .to_string();
    eprintln!("[onchain]  fetching confiscation tx {}", &txid_str);

    let tx_url = format!("{}/tx/{}", ELECTRS_URL, txid_str);
    let tx_json: serde_json::Value = reqwest::blocking::get(&tx_url)
        .expect("esplora /tx fetch")
        .json()
        .expect("parse tx json");
    let outputs = tx_json["vout"]
        .as_array()
        .expect("tx.vout is an array")
        .clone();

    assert_eq!(
        outputs.len(),
        2,
        "expected 2 outputs (bifurcated respectful shape), got {} — this is the \
         pre-bifurcation single-output punitive shape",
        outputs.len()
    );

    let lottery_value = outputs[0]["value"].as_u64().expect("output[0].value");
    let change_value = outputs[1]["value"].as_u64().expect("output[1].value");
    assert!(
        lottery_value >= 330,
        "lottery output value {} below P2WSH_DUST_LIMIT_SATS",
        lottery_value
    );
    assert_eq!(
        lottery_value, 330,
        "with no deposits in cluster the lottery output should equal the dust floor"
    );

    // Verify the change goes to the original operator's P2WPKH. Original
    // operator pubkey is the LedgerOpen seq-0 operator_id we already have
    // in `history[0].operator_id`.
    let original_op_pk = history[0].operator_id;
    let pubkey_bytes: [u8; 33] = original_op_pk.serialize();
    let compressed = bitcoin::CompressedPublicKey::from_slice(&pubkey_bytes).unwrap();
    let expected_change_addr =
        bitcoin::Address::p2wpkh(&compressed, bitcoin::Network::Regtest).to_string();
    let change_addr = outputs[1]["scriptpubkey_address"]
        .as_str()
        .expect("output[1].scriptpubkey_address");
    assert_eq!(
        change_addr, expected_change_addr,
        "change output address {} ≠ original operator P2WPKH {}",
        change_addr, expected_change_addr
    );

    eprintln!(
        "[bifurcated] lottery={} sats, operator change={} sats, total_out={} sats",
        lottery_value,
        change_value,
        lottery_value + change_value
    );
}
