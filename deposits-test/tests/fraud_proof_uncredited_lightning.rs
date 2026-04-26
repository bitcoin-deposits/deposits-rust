//! Integration test: a verified `UncreditedLightningPayment` fraud proof
//! drives the dispute pipeline end-to-end.
//!
//! Unlike StaleCosignature, this proof type doesn't require forging
//! anything onto the accused ledger. The "evidence" is constructed
//! purely off-chain: a fake invoice cosigned by a real operator key,
//! a preimage matching the invoice's payment_hash, and a reference to
//! any existing update on the accused ledger as the "operator was alive
//! after preimage was knowable" anchor.
//!
//! The verifier (`verify_uncredited_lightning`) checks:
//!   1. `sha256(preimage) == payment_hash`
//!   2. BIP-340 schnorr sig from `cosigner_pubkey` over the canonical
//!      invoice signing message
//!   3. accused has an update at `proof_sequence` (operator was alive)
//!   4. no `InvoiceCredit` / `InvoiceFulfill` for that payment_hash in
//!      accused history at seq ≤ `proof_sequence`
//!
//! Since payment_hash is random, (4) is automatically satisfied. We
//! sign the invoice with op1's operator secret to satisfy (2) — op1 is
//! a quorum member of op0's first ledger in the standard cluster, but
//! the verifier doesn't enforce that, so any keypair would work.
//!
//! Flow:
//!   1. Read op0's accused-ledger history from op1's view (op1 has it
//!      via consent piggyback). Pick the last seq as proof_sequence.
//!   2. Construct random (preimage, payment_hash). Pick arbitrary
//!      deposit_id, amount_msat, cosigner_ledger_hash.
//!   3. BIP-340 sign the canonical signing message with op1's key.
//!   4. Build FraudProof + same-ledger ProofEmbedding via embed-hash.
//!   5. Publish the FraudBroadcast (kind:9101) from op0.
//!   6. Poll quorum members for `confiscated_<prefix>.marker`.

use deposits_protocol::fraud::{
    CausalLink, FraudBroadcast, FraudEvidence, FraudProof, FraudProofType, ProofEmbedding,
};
use deposits_test::regtest::*;
use std::time::Duration;

#[test]
#[ignore]
fn fraud_proof_uncredited_lightning_triggers_confiscation() {
    if !cluster_available() {
        eprintln!("skipping: cluster not running — start with ./bin/setup.sh 3");
        return;
    }

    let node = build_node_with_danger();

    // ── 1. Pick op0's L2 ledger and read it from a quorum member's view ──
    // L1 (`ledger_0_1`) may already be disputed by a previous fraud-test
    // run on the same cluster; using L2 keeps tests independent so they
    // can run back-to-back without re-setting up the cluster. The peer
    // is discovered dynamically (setup.sh assigns quorums randomly).
    let accused_ledger = read_setup_state("ledger_0_2");
    let peer_op_idx = find_peer_with_ledger(&accused_ledger, 0)
        .expect("no peer has op0's L2 ledger imported — quorum activation may have failed");
    let accused_history = read_ledger_history(&op_data_dir(peer_op_idx), &accused_ledger);
    assert!(
        accused_history.len() >= 2,
        "accused ledger needs at least 2 updates for proof_sequence (got {})",
        accused_history.len()
    );
    let proof_sequence = accused_history.last().unwrap().sequence_number;
    eprintln!(
        "[setup] accused={}…  peer=op{}  proof_sequence={}",
        &accused_ledger[..16],
        peer_op_idx,
        proof_sequence
    );

    // ── 2. Random preimage → payment_hash + arbitrary scalar fields ──
    let preimage: [u8; 32] = {
        use bitcoin::secp256k1::rand::{rngs::OsRng, RngCore};
        let mut buf = [0u8; 32];
        OsRng.fill_bytes(&mut buf);
        buf
    };
    let payment_hash: [u8; 32] = {
        use bitcoin::hashes::Hash;
        bitcoin::hashes::sha256::Hash::hash(&preimage).to_byte_array()
    };
    // deposit_id and cosigner_ledger_hash aren't verified against the
    // ledger — they're inputs to the BIP-340 signing message only. Pick
    // recognizable byte patterns so debugging is easy.
    let deposit_id: deposits_protocol::types::DepositId = [0xAA; 16];
    let cosigner_ledger_hash: [u8; 32] = [0xBB; 32];
    let amount_msat: u64 = 123_000;
    eprintln!(
        "[evidence] preimage={}…  payment_hash={}…",
        &hex::encode(preimage)[..16],
        &hex::encode(payment_hash)[..16]
    );

    // ── 3. BIP-340 sign with the peer op's operator secret ──
    // The peer is a quorum member of the accused ledger and its key is
    // already imported on op0's view, but the verifier doesn't enforce
    // quorum-membership for the cosigner — any keypair would pass.
    let cosigner_secret = derive_operator_secret_for_op(peer_op_idx);
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let cosigner_keypair =
        bitcoin::secp256k1::Keypair::from_secret_key(&secp, &cosigner_secret);
    let cosigner_pubkey = cosigner_keypair.public_key();
    let cosigner_pubkey_hex = hex::encode(cosigner_pubkey.serialize());

    let msg_hash = deposits_protocol::signature_utils::invoice_cosign_signing_message(
        &accused_ledger,
        &payment_hash,
        &deposit_id,
        amount_msat,
        &cosigner_ledger_hash,
    );
    let msg = bitcoin::secp256k1::Message::from_digest(msg_hash);
    let cosign_signature = secp.sign_schnorr_no_aux_rand(&msg, &cosigner_keypair).serialize();
    eprintln!(
        "[cosig]    cosigner={}…  sig={}…",
        &cosigner_pubkey_hex[..16],
        &hex::encode(cosign_signature)[..16]
    );

    // ── 4. Build the FraudProof ──
    let op0_pubkey_hex = hex::encode(accused_history[0].operator_id.serialize());
    let proof = FraudProof {
        proof_type: FraudProofType::UncreditedLightningPayment,
        accused: op0_pubkey_hex,
        ledger_id: accused_ledger.clone(),
        evidence: FraudEvidence::UncreditedLightning {
            // BOLT11 string isn't parsed by the verifier — only its hash
            // links matter, which come through dedicated fields.
            invoice: "lnbcrt-fake-test-invoice".into(),
            payment_hash: hex::encode(payment_hash),
            deposit_id,
            amount_msat,
            cosigner_pubkey: cosigner_pubkey_hex,
            cosigner_ledger_hash: hex::encode(cosigner_ledger_hash),
            cosign_signature: hex::encode(cosign_signature),
            preimage: hex::encode(preimage),
            proof_sequence,
        },
    };
    let proof_hash = proof.proof_hash();
    eprintln!("[proof]    hash={}…", &hex::encode(proof_hash)[..16]);

    // ── 5. Embed proof_hash via DeliveryEmbed on op0's ledger ──
    let embed_update = embed_proof_hash(&node, 0, peer_op_idx, &accused_ledger, proof_hash);
    let embed_seq = embed_update.sequence_number;
    let embed_content = embed_update.content_hash;
    eprintln!(
        "[embed]    seq={} content={}…",
        embed_seq,
        &hex::encode(embed_content)[..16]
    );

    // ── 6. Publish the FraudBroadcast (same-ledger) ──
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

    // ── 7. Poll for confiscation marker on any quorum member ──
    let op_idx = poll_confiscation_marker(&accused_ledger, Duration::from_secs(180));
    eprintln!(
        "[ok] verified fraud-proof drove confiscation: marker at op{}/confiscated_{}.marker",
        op_idx,
        &accused_ledger[..16]
    );
}

/// Replicate `node_cli::derive_operator_secret` for op_idx using the
/// same BIP-86 path the daemon does. Lifted into the test rather than
/// re-exporting from `deposits-node`, since the test only needs the
/// secret derivation, not the full CLI surface.
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
