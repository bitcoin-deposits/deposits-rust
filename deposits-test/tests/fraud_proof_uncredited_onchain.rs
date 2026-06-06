//! Integration test: a verified `UncreditedOnchainPayment` fraud proof
//! drives the dispute pipeline end-to-end.
//!
//! Like UncreditedLightning, no forge is needed — the evidence is
//! constructed entirely off-chain. The two block-hash fields the
//! verifier checks against its own chain (`confirmed_at_block_hash` and
//! `proof_sequence`'s update.block_hash) come from real updates in
//! op0's accused history: those block hashes are already in the
//! daemon's confirmed chain because the daemon itself committed them
//! during Phase 4 of `setup.sh`.
//!
//! `verify_uncredited_onchain` checks:
//!   1. BIP-340 schnorr sig on the canonical offer signing message
//!   2. `confirmed_at_block_hash` is in the verifier's chain
//!   3. accused has update at `proof_sequence`; its block_hash is
//!      also in the chain
//!   4. `proof_height - confirmed_height >= required_confirmations`
//!   5. no OnchainCredit for `(txid, vout)` at seq ≤ proof_sequence
//!
//! Random `txid`/`vout` automatically satisfy (5).

use deposits_protocol::fraud::{
    CausalLink, FraudBroadcast, FraudEvidence, FraudProof, FraudProofType, ProofEmbedding,
};
use deposits_test::regtest::*;
use std::time::Duration;

#[test]
#[ignore]
fn fraud_proof_uncredited_onchain_triggers_confiscation() {
    if !cluster_available() {
        eprintln!("skipping: cluster not running — start with ./bin/setup.sh 3");
        return;
    }

    let node = build_node_with_danger();

    // ── 0. Fund every op's op-key P2WPKH — auto-arm pulls RC from
    //       there; unfunded → DisputeArmed declares None → cosigners
    //       refuse confiscation. Same recipe as fraud_proof_quorum_
    //       expired + replacement_collateral_e2e.
    for op_idx in 0..16 {
        let _ = fund_operator_key_address(op_idx, 100_000);
    }
    mine_blocks(2);

    // ── 1. Pick op0's L3 ledger (untouched by other fraud tests) ──
    let accused_ledger = read_setup_state("ledger_0_3");
    let peer_op_idx = find_peer_with_ledger(&accused_ledger, 0)
        .expect("no peer has op0's L3 ledger imported — quorum activation may have failed");

    // Extend the chain past QuorumBegin. Fresh-setup ledgers have QB
    // at the tip (seq 4 with Q=3), so an anchor picked from the
    // visible chain lands AT QB and the daemon's
    // `LVS = proof_sequence - 1` falls BEFORE QB → cosigners refuse
    // "no QuorumBegin observed at or before last_valid_sequence".
    // Drop a few `DepositOpen` updates past QB so the proof can cite
    // something post-rotation.
    let tip_seq = extend_chain_past_qb(&accused_ledger, peer_op_idx, 3);
    eprintln!("[extend]  chain extended to tip seq {}", tip_seq);

    let accused_history = read_ledger_history(&op_data_dir(peer_op_idx), &accused_ledger);
    assert!(
        accused_history.len() >= 3,
        "accused ledger needs at least 3 updates so we can pick distinct funding + proof anchors (got {})",
        accused_history.len()
    );

    // Pick two updates with distinct, *real* block_hashes. The very
    // first update (LedgerOpen) is committed before the daemon has
    // anchored to any block, so its block_hash is all-zero — skip
    // anything with a zero hash. We need an earlier one as the
    // "funding confirmed at" anchor and a later one as the "operator
    // was alive" anchor.
    let real_anchored: Vec<&deposits_protocol::types::SignedLedgerUpdate> = accused_history
        .iter()
        .filter(|u| u.block_hash != [0u8; 32])
        .collect();
    assert!(
        real_anchored.len() >= 2,
        "need >= 2 updates with non-zero block_hash; got {}",
        real_anchored.len()
    );
    let funding_update = real_anchored.first().unwrap();
    let proof_update = *real_anchored.last().unwrap();
    assert_ne!(
        funding_update.block_hash, proof_update.block_hash,
        "need distinct block_hashes between funding and proof anchors; got identical {}",
        hex::encode(funding_update.block_hash)
    );
    let confirmed_at_block_hash = funding_update.block_hash;
    let proof_sequence = proof_update.sequence_number;
    eprintln!(
        "[setup]    accused={}…  peer=op{}  proof_sequence={}",
        &accused_ledger[..16],
        peer_op_idx,
        proof_sequence
    );
    eprintln!(
        "[anchors]  confirmed_at={}…  proof_block={}…",
        &hex::encode(confirmed_at_block_hash)[..16],
        &hex::encode(proof_update.block_hash)[..16]
    );

    // ── 2. Random (txid, vout) + arbitrary offer/funding fields ──
    let (txid, vout) = {
        use bitcoin::secp256k1::rand::{rngs::OsRng, RngCore};
        let mut buf = [0u8; 32];
        OsRng.fill_bytes(&mut buf);
        (buf, 0u32)
    };
    let offer_id: [u8; 32] = [0xCC; 32];
    let cosigner_ledger_hash: [u8; 32] = [0xDD; 32];
    // The funding address is plaintext bytes signed into the cosig
    // message; verifier doesn't validate it as a real Bitcoin address.
    let funding_address = "bcrt1qfakeaddrforfraudprooftest0000000000".to_string();
    let amount_sats: u64 = 50_000;
    // deadline_block goes into the offer cosig message; pick something
    // well past current chain tip so it's "live" in flavour.
    let deadline_block: u32 = 999_999;
    let required_confirmations: u32 = 1;

    // ── 3. BIP-340 sign the offer message with peer's operator key ──
    let cosigner_secret = derive_operator_secret_for_op(peer_op_idx);
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let cosigner_keypair =
        bitcoin::secp256k1::Keypair::from_secret_key(&secp, &cosigner_secret);
    let cosigner_pubkey = cosigner_keypair.public_key();
    // Accused operator pubkey = the operator who issued the offer (op0).
    // Read from any update on op0's accused ledger — operator_id is
    // stable across the ledger's lifetime.
    let accused_operator_pubkey = accused_history[0].operator_id;
    let accused_operator_pubkey_hex = hex::encode(accused_operator_pubkey.serialize());

    let msg_hash = deposits_protocol::signature_utils::offer_cosign_signing_message(
        &accused_ledger,
        &offer_id,
        &accused_operator_pubkey,
        &funding_address,
        deadline_block,
        &cosigner_ledger_hash,
    );
    let msg = bitcoin::secp256k1::Message::from_digest(msg_hash);
    let cosign_signature = secp.sign_schnorr_no_aux_rand(&msg, &cosigner_keypair).serialize();
    eprintln!(
        "[cosig]    cosigner={}…  sig={}…",
        &hex::encode(cosigner_pubkey.serialize())[..16],
        &hex::encode(cosign_signature)[..16]
    );

    // ── 4. Build the FraudProof ──
    let proof = FraudProof {
        proof_type: FraudProofType::UncreditedOnchainPayment,
        accused: accused_operator_pubkey_hex,
        ledger_id: accused_ledger.clone(),
        evidence: FraudEvidence::UncreditedOnchain {
            offer_id: hex::encode(offer_id),
            funding_address,
            accused_operator_pubkey: hex::encode(accused_operator_pubkey.serialize()),
            deadline_block,
            cosigner_pubkey: hex::encode(cosigner_pubkey.serialize()),
            cosigner_ledger_hash: hex::encode(cosigner_ledger_hash),
            cosign_signature: hex::encode(cosign_signature),
            txid: hex::encode(txid),
            vout,
            amount_sats,
            confirmed_at_block_hash,
            required_confirmations,
            proof_sequence,
        },
    };
    let proof_hash = proof.proof_hash();
    eprintln!("[proof]    hash={}…", &hex::encode(proof_hash)[..16]);

    // ── 5. Embed + publish + poll for marker ──
    let embed_update = embed_proof_hash(&node, 0, peer_op_idx, &accused_ledger, proof_hash);
    let embed_seq = embed_update.sequence_number;
    let embed_content = embed_update.content_hash;
    eprintln!(
        "[embed]    seq={} content={}…",
        embed_seq,
        &hex::encode(embed_content)[..16]
    );

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
    eprintln!("[publish]  kind:9101 from op0");
    publish_fraud_broadcast(&node, 0, &broadcast);

    let op_idx = poll_confiscation_marker(&accused_ledger, Duration::from_secs(180));
    eprintln!(
        "[ok] verified fraud-proof drove confiscation: marker at op{}/confiscated_{}.marker",
        op_idx,
        &accused_ledger[..16]
    );
}

fn derive_operator_secret_for_op(op_idx: usize) -> bitcoin::secp256k1::SecretKey {
    use bitcoin::bip32::{DerivationPath, Xpriv};
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::Network;
    use std::str::FromStr;

    let seed_hex = op_seed(op_idx);
    let seed_bytes: [u8; 32] = hex::decode(&seed_hex)
        .expect("op_seed is valid hex")
        .try_into()
        .expect("op_seed is 32 bytes");

    let secp = Secp256k1::new();
    let xpriv = Xpriv::new_master(Network::Regtest, &seed_bytes).expect("master key");
    let path = DerivationPath::from_str("m/86'/0'/0'/0/0").expect("bip-86 path");
    let derived = xpriv.derive_priv(&secp, &path).expect("derive");
    derived.private_key
}
