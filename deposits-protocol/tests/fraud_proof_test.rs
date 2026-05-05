//! Tests for fraud proof hashing, causal chains, and evidence types.

use deposits_protocol::fraud::*;

fn make_accused() -> String {
    "02".to_string() + &"ab".repeat(32)
}
fn make_ledger_id() -> String {
    "aa".repeat(32)
}

fn make_onchain_proof() -> FraudProof {
    FraudProof {
        proof_type: FraudProofType::UncreditedOnchainPayment,
        accused: make_accused(),
        ledger_id: make_ledger_id(),
        evidence: FraudEvidence::UncreditedOnchain {
            offer_id: "bb".repeat(16),
            funding_address: "bcrt1qtest".to_string(),
            accused_operator_pubkey: "02".to_string() + &"ab".repeat(32),
            deadline_block: 600,
            cosigner_pubkey: "02".to_string() + &"cc".repeat(32),
            cosigner_ledger_hash: "00".repeat(32),
            cosign_signature: "dd".repeat(32),
            txid: "ee".repeat(32),
            vout: 0,
            amount_sats: 100_000,
            confirmed_at_block_hash: [0xAA; 32],
            required_confirmations: 6,
            proof_sequence: 42,
        },
    }
}

fn make_lightning_proof() -> FraudProof {
    FraudProof {
        proof_type: FraudProofType::UncreditedLightningPayment,
        accused: make_accused(),
        ledger_id: make_ledger_id(),
        evidence: FraudEvidence::UncreditedLightning {
            invoice: "lnbcrt1test".to_string(),
            payment_hash: "ff".repeat(32),
            deposit_id: deposits_protocol::DepositId::default(),
            amount_msat: 1_000_000,
            cosigner_pubkey: "02".to_string() + &"cc".repeat(32),
            cosigner_ledger_hash: "00".repeat(32),
            cosign_signature: "dd".repeat(32),
            preimage: "11".repeat(32),
            proof_sequence: 50,
        },
    }
}

fn make_stale_cosign_proof() -> FraudProof {
    FraudProof {
        proof_type: FraudProofType::StaleCosignature,
        accused: make_accused(),
        ledger_id: make_ledger_id(),
        evidence: FraudEvidence::StaleCosign {
            stale_update_sequence: 100,
            stale_update_hash: "22".repeat(32),
            declared_member_hash: "33".repeat(32),
            member_later_sequence: 105,
            member_later_hash: "44".repeat(32),
            member_ledger_id: "55".repeat(32),
        },
    }
}

fn make_inactive_proof() -> FraudProof {
    FraudProof {
        proof_type: FraudProofType::DisputeDereliction,
        accused: make_accused(),
        ledger_id: make_ledger_id(),
        evidence: FraudEvidence::DisputeDereliction {
            original_fraud_hash: "66".repeat(32),
            original_fraud_block_hash: [0xAA; 32],
            member_ledger_id: hex::encode([0xBB; 32]),
            required_response_blocks: 144,
            member_active_sequence: 200,
            member_pubkey: "02".to_string() + &"77".repeat(32),
        },
    }
}

fn make_nonconforming_proof() -> FraudProof {
    FraudProof {
        proof_type: FraudProofType::NonConformingUpdate,
        accused: make_accused(),
        ledger_id: make_ledger_id(),
        evidence: FraudEvidence::NonConforming {
            sequence: 99,
            update_b64: "AQID".to_string(), // base64 of [1,2,3]
            violation: "balance underflow".to_string(),
        },
    }
}

fn make_quorum_expired_proof() -> FraudProof {
    FraudProof {
        proof_type: FraudProofType::QuorumExpired,
        accused: make_accused(),
        ledger_id: make_ledger_id(),
        evidence: FraudEvidence::QuorumExpired {
            anchor_block_hash: [0xCC; 32],
            quorum_expiry: 800_000,
        },
    }
}

// =========================================================================
// Hash determinism and uniqueness
// =========================================================================

#[test]
fn proof_hash_deterministic() {
    let p = make_onchain_proof();
    assert_eq!(p.proof_hash(), p.proof_hash());
}

#[test]
fn proof_hash_nonzero() {
    let p = make_onchain_proof();
    assert_ne!(p.proof_hash(), [0u8; 32]);
}

#[test]
fn each_proof_type_has_distinct_hash() {
    let hashes: Vec<[u8; 32]> = vec![
        make_onchain_proof().proof_hash(),
        make_lightning_proof().proof_hash(),
        make_stale_cosign_proof().proof_hash(),
        make_inactive_proof().proof_hash(),
        make_nonconforming_proof().proof_hash(),
        make_quorum_expired_proof().proof_hash(),
    ];
    // All pairwise distinct
    for i in 0..hashes.len() {
        for j in (i + 1)..hashes.len() {
            assert_ne!(
                hashes[i], hashes[j],
                "proof types {} and {} have same hash",
                i, j
            );
        }
    }
}

#[test]
fn changing_accused_changes_hash() {
    let mut p = make_onchain_proof();
    let h1 = p.proof_hash();
    p.accused = "02".to_string() + &"ff".repeat(32);
    assert_ne!(p.proof_hash(), h1);
}

#[test]
fn changing_ledger_id_changes_hash() {
    let mut p = make_onchain_proof();
    let h1 = p.proof_hash();
    p.ledger_id = "bb".repeat(32);
    assert_ne!(p.proof_hash(), h1);
}

#[test]
fn changing_evidence_amount_changes_hash() {
    let mut p = make_onchain_proof();
    let h1 = p.proof_hash();
    if let FraudEvidence::UncreditedOnchain {
        ref mut amount_sats,
        ..
    } = p.evidence
    {
        *amount_sats = 200_000;
    }
    assert_ne!(p.proof_hash(), h1);
}

#[test]
fn changing_evidence_txid_changes_hash() {
    let mut p = make_onchain_proof();
    let h1 = p.proof_hash();
    if let FraudEvidence::UncreditedOnchain { ref mut txid, .. } = p.evidence {
        *txid = "ff".repeat(32);
    }
    assert_ne!(p.proof_hash(), h1);
}

#[test]
fn changing_preimage_changes_hash() {
    let mut p = make_lightning_proof();
    let h1 = p.proof_hash();
    if let FraudEvidence::UncreditedLightning {
        ref mut preimage, ..
    } = p.evidence
    {
        *preimage = "22".repeat(32);
    }
    assert_ne!(p.proof_hash(), h1);
}

#[test]
fn verify_embedding_matches_hash() {
    let p = make_onchain_proof();
    let hash = p.proof_hash();
    assert!(p.verify_embedding(&hash));
    assert!(!p.verify_embedding(&[0u8; 32]));
}

// =========================================================================
// Discriminant coverage
// =========================================================================

#[test]
fn discriminants_are_unique() {
    let types = [
        FraudProofType::UncreditedOnchainPayment,
        FraudProofType::UncreditedLightningPayment,
        FraudProofType::StaleCosignature,
        FraudProofType::DisputeDereliction,
        FraudProofType::NonConformingUpdate,
    ];
    let discs: Vec<u8> = types.iter().map(|t| t.discriminant()).collect();
    for i in 0..discs.len() {
        for j in (i + 1)..discs.len() {
            assert_ne!(discs[i], discs[j]);
        }
    }
}

// =========================================================================
// Causal chain verification
// =========================================================================

#[test]
fn direct_embedding_valid() {
    let proof = make_onchain_proof();
    let b = FraudBroadcast {
        embedding: ProofEmbedding {
            ledger_id: proof.ledger_id.clone(),
            sequence: 50,
            update_hash: "ff".repeat(32),
            field: "transfer_nonce".to_string(),
        },
        causal_chain: vec![],
        proof,
    };
    assert!(b.verify_chain_structure().is_ok());
}

#[test]
fn direct_embedding_with_chain_rejected() {
    let proof = make_onchain_proof();
    let b = FraudBroadcast {
        embedding: ProofEmbedding {
            ledger_id: proof.ledger_id.clone(),
            sequence: 50,
            update_hash: "ff".repeat(32),
            field: "transfer_nonce".to_string(),
        },
        causal_chain: vec![CausalLink {
            ledger_id: proof.ledger_id.clone(),
            sequence: 55,
            update_hash: "ee".repeat(32),
            member_ledger_hash: "dd".repeat(32),
            source_ledger_id: "11".repeat(32),
        }],
        proof,
    };
    assert!(b.verify_chain_structure().is_err());
}

#[test]
fn indirect_missing_chain_rejected() {
    let proof = make_onchain_proof();
    let b = FraudBroadcast {
        embedding: ProofEmbedding {
            ledger_id: "11".repeat(32), // different from accused
            sequence: 10,
            update_hash: "22".repeat(32),
            field: "transfer_nonce".to_string(),
        },
        causal_chain: vec![],
        proof,
    };
    assert!(b.verify_chain_structure().is_err());
}

#[test]
fn one_hop_valid() {
    let proof = make_onchain_proof();
    let member = "11".repeat(32);
    let b = FraudBroadcast {
        embedding: ProofEmbedding {
            ledger_id: member.clone(),
            sequence: 10,
            update_hash: "22".repeat(32),
            field: "transfer_nonce".to_string(),
        },
        causal_chain: vec![CausalLink {
            ledger_id: proof.ledger_id.clone(),
            sequence: 55,
            update_hash: "33".repeat(32),
            member_ledger_hash: "44".repeat(32),
            source_ledger_id: member,
        }],
        proof,
    };
    assert!(b.verify_chain_structure().is_ok());
}

#[test]
fn one_hop_wrong_source_rejected() {
    let proof = make_onchain_proof();
    let b = FraudBroadcast {
        embedding: ProofEmbedding {
            ledger_id: "11".repeat(32),
            sequence: 10,
            update_hash: "22".repeat(32),
            field: "transfer_nonce".to_string(),
        },
        causal_chain: vec![CausalLink {
            ledger_id: proof.ledger_id.clone(),
            sequence: 55,
            update_hash: "33".repeat(32),
            member_ledger_hash: "44".repeat(32),
            source_ledger_id: "99".repeat(32), // wrong — doesn't match embedding
        }],
        proof,
    };
    assert!(b.verify_chain_structure().is_err());
}

#[test]
fn two_hop_valid() {
    let proof = make_onchain_proof();
    let a = "11".repeat(32);
    let b_ledger = "22".repeat(32);
    let b = FraudBroadcast {
        embedding: ProofEmbedding {
            ledger_id: a.clone(),
            sequence: 10,
            update_hash: "ff".repeat(32),
            field: "transfer_nonce".to_string(),
        },
        causal_chain: vec![
            CausalLink {
                ledger_id: b_ledger.clone(),
                sequence: 20,
                update_hash: "ee".repeat(32),
                member_ledger_hash: "dd".repeat(32),
                source_ledger_id: a,
            },
            CausalLink {
                ledger_id: proof.ledger_id.clone(),
                sequence: 30,
                update_hash: "cc".repeat(32),
                member_ledger_hash: "bb".repeat(32),
                source_ledger_id: b_ledger,
            },
        ],
        proof,
    };
    assert!(b.verify_chain_structure().is_ok());
}

#[test]
fn two_hop_broken_middle_rejected() {
    let proof = make_onchain_proof();
    let a = "11".repeat(32);
    let b_ledger = "22".repeat(32);
    let b = FraudBroadcast {
        embedding: ProofEmbedding {
            ledger_id: a.clone(),
            sequence: 10,
            update_hash: "ff".repeat(32),
            field: "transfer_nonce".to_string(),
        },
        causal_chain: vec![
            CausalLink {
                ledger_id: b_ledger.clone(),
                sequence: 20,
                update_hash: "ee".repeat(32),
                member_ledger_hash: "dd".repeat(32),
                source_ledger_id: a,
            },
            CausalLink {
                ledger_id: proof.ledger_id.clone(),
                sequence: 30,
                update_hash: "cc".repeat(32),
                member_ledger_hash: "bb".repeat(32),
                source_ledger_id: "99".repeat(32), // broken — doesn't match b_ledger
            },
        ],
        proof,
    };
    assert!(b.verify_chain_structure().is_err());
}

#[test]
fn chain_not_reaching_accused_rejected() {
    let proof = make_onchain_proof();
    let b = FraudBroadcast {
        embedding: ProofEmbedding {
            ledger_id: "11".repeat(32),
            sequence: 10,
            update_hash: "22".repeat(32),
            field: "transfer_nonce".to_string(),
        },
        causal_chain: vec![CausalLink {
            ledger_id: "99".repeat(32), // wrong destination
            sequence: 55,
            update_hash: "33".repeat(32),
            member_ledger_hash: "44".repeat(32),
            source_ledger_id: "11".repeat(32),
        }],
        proof,
    };
    assert!(b.verify_chain_structure().is_err());
}

// =========================================================================
// Causal hash in compute_hash
// =========================================================================

#[test]
fn compute_hash_changes_with_member_ledger_hash() {
    use deposits_protocol::types::SignedLedgerUpdate;

    let pk = {
        use std::str::FromStr;
        bitcoin::secp256k1::PublicKey::from_str(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .unwrap()
    };

    let mut update = SignedLedgerUpdate {
        message: vec![1, 2, 3],
        message_type: 1,
        operator_id: pk,
        ledger_id: [0x12; 32],
        sequence_number: 1,
        previous_hash: [0u8; 32],
        content_hash: [0u8; 32],
        block_height: 0,
        block_hash: [0u8; 32],
        cosign_signature: [0u8; 64],
        operator_signature: [0u8; 64],
        cosigner_pubkey: None,
        member_ledger_hash: None,
        cosignatures: Vec::new(),
    };

    let hash_without = update.compute_hash();

    update.member_ledger_hash = Some([0xAA; 32]);
    let hash_with = update.compute_hash();

    assert_ne!(
        hash_without, hash_with,
        "member_ledger_hash should change the hash"
    );

    update.member_ledger_hash = Some([0xBB; 32]);
    let hash_with_different = update.compute_hash();

    assert_ne!(
        hash_with, hash_with_different,
        "different member_ledger_hash should produce different hash"
    );
}

#[test]
fn compute_hash_without_member_hash_is_backward_compatible() {
    use deposits_protocol::types::SignedLedgerUpdate;

    let pk = {
        use std::str::FromStr;
        bitcoin::secp256k1::PublicKey::from_str(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .unwrap()
    };

    let update = SignedLedgerUpdate {
        message: vec![1, 2, 3],
        message_type: 1,
        operator_id: pk,
        ledger_id: [0x12; 32],
        sequence_number: 1,
        previous_hash: [0u8; 32],
        content_hash: [0u8; 32],
        block_height: 0,
        block_hash: [0u8; 32],
        cosign_signature: [0u8; 64],
        operator_signature: [0u8; 64],
        cosigner_pubkey: None,
        member_ledger_hash: None,
        cosignatures: Vec::new(),
    };

    // Without member_ledger_hash, hash is just SHA256(seq || prev_hash || message)
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(1u64.to_le_bytes());
    hasher.update([0u8; 32]);
    hasher.update([1u8, 2, 3]);
    let expected: [u8; 32] = hasher.finalize().into();

    assert_eq!(update.compute_hash(), expected);
}

#[test]
fn compute_hash_includes_cosign_signature() {
    use deposits_protocol::types::SignedLedgerUpdate;

    let pk = {
        use std::str::FromStr;
        bitcoin::secp256k1::PublicKey::from_str(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .unwrap()
    };

    let mut update = SignedLedgerUpdate {
        message: vec![1, 2, 3],
        message_type: 1,
        operator_id: pk,
        ledger_id: [0x12; 32],
        sequence_number: 1,
        previous_hash: [0u8; 32],
        content_hash: [0u8; 32],
        block_height: 0,
        block_hash: [0u8; 32],
        cosign_signature: [0u8; 64],
        operator_signature: [0u8; 64],
        cosigner_pubkey: None,
        member_ledger_hash: None,
        cosignatures: Vec::new(),
    };

    let hash_no_sig = update.compute_hash();

    update.cosign_signature = [0xAA; 64];
    let hash_with_sig = update.compute_hash();

    assert_ne!(
        hash_no_sig, hash_with_sig,
        "cosign_signature should change compute_hash"
    );

    update.cosign_signature = [0xBB; 64];
    let hash_different_sig = update.compute_hash();

    assert_ne!(
        hash_with_sig, hash_different_sig,
        "different cosign_signature = different hash"
    );
}

#[test]
fn chain_hash_includes_operator_signature() {
    use deposits_protocol::types::SignedLedgerUpdate;

    let pk = {
        use std::str::FromStr;
        bitcoin::secp256k1::PublicKey::from_str(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .unwrap()
    };

    let mut update = SignedLedgerUpdate {
        message: vec![1, 2, 3],
        message_type: 1,
        operator_id: pk,
        ledger_id: [0x12; 32],
        sequence_number: 1,
        previous_hash: [0u8; 32],
        content_hash: [0u8; 32],
        block_height: 0,
        block_hash: [0u8; 32],
        cosign_signature: [0u8; 64],
        operator_signature: [0u8; 64],
        cosigner_pubkey: None,
        member_ledger_hash: None,
        cosignatures: Vec::new(),
    };
    update.content_hash = update.compute_hash();

    let chain_no_sig = update.chain_hash();

    update.operator_signature = [0xCC; 64];
    let chain_with_sig = update.chain_hash();

    assert_ne!(
        chain_no_sig, chain_with_sig,
        "operator_signature should change chain_hash"
    );
    // chain_hash != content_hash
    assert_ne!(
        update.chain_hash(),
        update.content_hash,
        "chain_hash should differ from content_hash"
    );
}

// =========================================================================
// Receiver-level dispatch (verify_fraud_broadcast)
// =========================================================================
//
// `verify_fraud_broadcast` is the entry point the daemon calls. It composes:
//
//   1. structural sanity (`verify_chain_structure`)
//   2. embedding present in claimed ledger
//   3. causal-link presence per chain hop
//   4. per-type evidence verifier
//
// The tests below construct the smallest valid setup per fraud type and
// confirm the full pipeline accepts the genuine case + rejects each
// individual component being broken. The per-type verifiers themselves
// are unit-tested separately in `mod stale_cosignature` etc. above —
// these tests cover the *composition* of structural + embedding +
// chain + evidence checks.

mod dispatch {
    use deposits_protocol::fraud::*;
    use deposits_protocol::messages::LedgerOperation;
    use deposits_protocol::tlv::TlvEncode;
    use deposits_protocol::types::{CosignEntry, SignedLedgerUpdate};
    use sha2::{Digest, Sha256};
    use std::collections::HashMap;

    fn pk_from_seed(seed: u8) -> bitcoin::secp256k1::PublicKey {
        use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[seed; 32]).unwrap();
        Keypair::from_secret_key(&secp, &secret).public_key()
    }

    fn sign_invoice_cosig(
        cosigner_seed: u8,
        ledger_id: &str,
        payment_hash: &[u8; 32],
        deposit_id: &deposits_protocol::DepositId,
        amount_msat: u64,
        cosigner_ledger_hash: &[u8; 32],
    ) -> ([u8; 64], bitcoin::secp256k1::PublicKey) {
        use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[cosigner_seed; 32]).unwrap();
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let msg_hash = deposits_protocol::invoice_cosign_signing_message(
            ledger_id,
            payment_hash,
            deposit_id,
            amount_msat,
            cosigner_ledger_hash,
        );
        let msg = Message::from_digest(msg_hash);
        let sig = secp.sign_schnorr_no_aux_rand(&msg, &keypair);
        (sig.serialize(), keypair.public_key())
    }

    fn sign_offer_cosig(
        cosigner_seed: u8,
        ledger_id: &str,
        offer_id: &[u8; 32],
        accused_op: &bitcoin::secp256k1::PublicKey,
        funding_address: &str,
        deadline_block: u32,
        cosigner_ledger_hash: &[u8; 32],
    ) -> ([u8; 64], bitcoin::secp256k1::PublicKey) {
        use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[cosigner_seed; 32]).unwrap();
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let msg_hash = deposits_protocol::offer_cosign_signing_message(
            ledger_id,
            offer_id,
            accused_op,
            funding_address,
            deadline_block,
            cosigner_ledger_hash,
        );
        let msg = Message::from_digest(msg_hash);
        let sig = secp.sign_schnorr_no_aux_rand(&msg, &keypair);
        (sig.serialize(), keypair.public_key())
    }

    /// LedgerProvider backed by a HashMap<String, Vec<SignedLedgerUpdate>>.
    fn provider_from(
        m: HashMap<String, Vec<SignedLedgerUpdate>>,
    ) -> impl LedgerProvider {
        move |id: &str| m.get(id).cloned()
    }

    /// BlockOracle backed by a static map. Tests that don't need block
    /// confirmations just pass an empty map.
    struct MockOracle(HashMap<[u8; 32], u32>);
    impl BlockOracle for MockOracle {
        fn confirms(&self, h: &[u8; 32]) -> Option<u32> {
            self.0.get(h).copied()
        }
    }

    /// Build a SignedLedgerUpdate carrying `op` at `seq`. Stale-cosig and
    /// embedding tests need control over `block_height`, `cosignatures`,
    /// and `content_hash`; we accept overrides for those.
    fn update_with(
        seq: u64,
        ledger_id: [u8; 32],
        op: LedgerOperation,
        cosigs_with_member_hashes: &[[u8; 32]],
        block_height: u32,
        member_ledger_hash: Option<[u8; 32]>,
    ) -> SignedLedgerUpdate {
        SignedLedgerUpdate {
            message: op.tlv_encode(),
            message_type: op.message_type(),
            operator_id: pk_from_seed(0xAB),
            ledger_id,
            sequence_number: seq,
            previous_hash: [0u8; 32],
            content_hash: [0u8; 32],
            block_height,
            block_hash: [0u8; 32],
            cosign_signature: [0u8; 64],
            operator_signature: [0u8; 64],
            cosigner_pubkey: None,
            member_ledger_hash,
            cosignatures: cosigs_with_member_hashes
                .iter()
                .map(|h| CosignEntry {
                    cosigner_pubkey: pk_from_seed(0xCD),
                    cosign_signature: [0u8; 64],
                    member_ledger_hash: *h,
                })
                .collect(),
        }
    }

    fn dummy_transfer_lock(nonce: [u8; 32]) -> LedgerOperation {
        LedgerOperation::TransferLock {
            nonce,
            source_deposit_id: deposits_protocol::DepositId::default(),
            destination_deposit_id: deposits_protocol::DepositId::default(),
            amount: 1,
            fee: 0,
            completion_script: String::new(),
            timeout_height: 0,
            transfer_id: [0u8; 32],
            witness: Default::default(),
        }
    }

    // ---------------- StaleCosignature -----------------

    /// Build a verified stale-cosig scenario:
    ///   - Member ledger M has chain_hash H_old at seq 5 (block 90),
    ///     advances at blocks 95/100.
    ///   - Accused operator A cosigns at seq 30 (block 110) declaring H_old.
    ///   - Embedding: a TransferLock at seq 50 on A whose nonce = proof_hash.
    fn stale_cosig_scenario() -> (
        FraudBroadcast,
        HashMap<String, Vec<SignedLedgerUpdate>>,
    ) {
        let accused_ledger = [0xAA; 32];
        let member_ledger = [0xBB; 32];

        // Member history.
        let member_history = vec![
            update_with(5, member_ledger, dummy_transfer_lock([0; 32]), &[], 90, None),
            update_with(6, member_ledger, dummy_transfer_lock([1; 32]), &[], 95, None),
            update_with(7, member_ledger, dummy_transfer_lock([2; 32]), &[], 100, None),
        ];
        let h_old = member_history[0].chain_hash();
        let later_hash = member_history[2].chain_hash();

        // Build the proof to compute proof_hash; embedding nonce = proof_hash.
        let stale_content = [0x33; 32];
        let proof_template = FraudProof {
            proof_type: FraudProofType::StaleCosignature,
            accused: hex::encode(pk_from_seed(0xAB).serialize()),
            ledger_id: hex::encode(accused_ledger),
            evidence: FraudEvidence::StaleCosign {
                stale_update_sequence: 30,
                stale_update_hash: hex::encode(stale_content),
                declared_member_hash: hex::encode(h_old),
                member_later_sequence: 7,
                member_later_hash: hex::encode(later_hash),
                member_ledger_id: hex::encode(member_ledger),
            },
        };
        let proof_hash = proof_template.proof_hash();

        // Accused history: seq 30 = stale cosign update; seq 50 = embedding TL.
        let mut stale_update = update_with(
            30,
            accused_ledger,
            dummy_transfer_lock([0; 32]),
            &[h_old],
            110,
            None,
        );
        stale_update.content_hash = stale_content;
        let embedding_update = update_with(
            50,
            accused_ledger,
            dummy_transfer_lock(proof_hash),
            &[],
            120,
            None,
        );
        let accused_history = vec![stale_update, embedding_update];

        let broadcast = FraudBroadcast {
            embedding: ProofEmbedding {
                ledger_id: hex::encode(accused_ledger),
                sequence: 50,
                update_hash: hex::encode([0u8; 32]),
                field: "transfer_nonce".into(),
            },
            causal_chain: vec![],
            proof: proof_template,
        };

        let mut histories = HashMap::new();
        histories.insert(hex::encode(accused_ledger), accused_history);
        histories.insert(hex::encode(member_ledger), member_history);
        (broadcast, histories)
    }

    #[test]
    fn dispatch_accepts_genuine_stale_cosignature() {
        let (broadcast, histories) = stale_cosig_scenario();
        let provider = provider_from(histories);
        let oracle = MockOracle(HashMap::new());
        verify_fraud_broadcast(&broadcast, &provider, &oracle).unwrap();
    }

    #[test]
    fn dispatch_rejects_stale_cosig_with_missing_embedding() {
        let (mut broadcast, histories) = stale_cosig_scenario();
        broadcast.embedding.sequence = 999; // no update at this seq
        let provider = provider_from(histories);
        let oracle = MockOracle(HashMap::new());
        let err = verify_fraud_broadcast(&broadcast, &provider, &oracle).unwrap_err();
        assert!(err.contains("not embedded"), "wrong error: {}", err);
    }

    #[test]
    fn dispatch_rejects_stale_cosig_when_evidence_lies() {
        // Genuine setup, but flip the evidence to claim a later_sequence
        // that doesn't show member advancing past declared_member_hash.
        let (mut broadcast, histories) = stale_cosig_scenario();
        if let FraudEvidence::StaleCosign {
            member_later_sequence,
            ..
        } = &mut broadcast.proof.evidence
        {
            *member_later_sequence = 5; // = the declared hash itself, no advancement
        }
        // proof_hash changes when evidence changes — re-embed.
        let proof_hash = broadcast.proof.proof_hash();
        let mut histories = histories;
        let accused_id = broadcast.embedding.ledger_id.clone();
        let accused_history = histories.get_mut(&accused_id).unwrap();
        accused_history[1] = update_with(
            50,
            [0xAA; 32],
            dummy_transfer_lock(proof_hash),
            &[],
            120,
            None,
        );
        let provider = provider_from(histories);
        let oracle = MockOracle(HashMap::new());
        let err = verify_fraud_broadcast(&broadcast, &provider, &oracle).unwrap_err();
        assert!(
            err.contains("did not advance past")
                || err.contains("doesn't appear in member history"),
            "wrong error: {}",
            err
        );
    }

    // ---------------- UncreditedLightning -----------------

    fn uncredited_lightning_scenario() -> (
        FraudBroadcast,
        HashMap<String, Vec<SignedLedgerUpdate>>,
    ) {
        let accused_ledger = [0xAA; 32];
        let preimage = [0xBE; 32];
        let payment_hash: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(preimage);
            h.finalize().into()
        };
        let deposit_id = deposits_protocol::DepositId::default();
        let amount_msat = 1_000_000u64;
        let cosigner_ledger_hash = [0xCC; 32];

        let ledger_id_hex = hex::encode(accused_ledger);
        let (sig, cosigner_pk) = sign_invoice_cosig(
            0xAA,
            &ledger_id_hex,
            &payment_hash,
            &deposit_id,
            amount_msat,
            &cosigner_ledger_hash,
        );

        let proof_template = FraudProof {
            proof_type: FraudProofType::UncreditedLightningPayment,
            accused: hex::encode(pk_from_seed(0xAB).serialize()),
            ledger_id: ledger_id_hex.clone(),
            evidence: FraudEvidence::UncreditedLightning {
                invoice: "lnbcrt1ptest".into(),
                payment_hash: hex::encode(payment_hash),
                deposit_id,
                amount_msat,
                cosigner_pubkey: hex::encode(cosigner_pk.serialize()),
                cosigner_ledger_hash: hex::encode(cosigner_ledger_hash),
                cosign_signature: hex::encode(sig),
                preimage: hex::encode(preimage),
                proof_sequence: 50,
            },
        };
        let proof_hash = proof_template.proof_hash();

        let accused_history = vec![update_with(
            50,
            accused_ledger,
            dummy_transfer_lock(proof_hash),
            &[],
            0,
            None,
        )];

        let broadcast = FraudBroadcast {
            embedding: ProofEmbedding {
                ledger_id: ledger_id_hex.clone(),
                sequence: 50,
                update_hash: hex::encode([0u8; 32]),
                field: "transfer_nonce".into(),
            },
            causal_chain: vec![],
            proof: proof_template,
        };

        let mut histories = HashMap::new();
        histories.insert(ledger_id_hex, accused_history);
        (broadcast, histories)
    }

    #[test]
    fn dispatch_accepts_genuine_uncredited_lightning() {
        let (broadcast, histories) = uncredited_lightning_scenario();
        verify_fraud_broadcast(
            &broadcast,
            &provider_from(histories),
            &MockOracle(HashMap::new()),
        )
        .unwrap();
    }

    #[test]
    fn dispatch_rejects_uncredited_lightning_with_credit_present() {
        let (broadcast, mut histories) = uncredited_lightning_scenario();
        let payment_hash_bytes = match &broadcast.proof.evidence {
            FraudEvidence::UncreditedLightning { payment_hash, .. } => {
                let v = hex::decode(payment_hash).unwrap();
                let mut a = [0u8; 32];
                a.copy_from_slice(&v);
                a
            }
            _ => unreachable!(),
        };
        // Add an InvoiceCredit for this payment_hash before proof_sequence.
        let credit_op = LedgerOperation::InvoiceCredit {
            payment_hash: payment_hash_bytes,
            deposit_id: deposits_protocol::DepositId::default(),
            amount: 1000,
            invoice_id: "x".into(),
            sequence_number: 30,
        };
        let id = broadcast.embedding.ledger_id.clone();
        let v = histories.get_mut(&id).unwrap();
        v.insert(0, update_with(30, [0xAA; 32], credit_op, &[], 0, None));
        let err = verify_fraud_broadcast(
            &broadcast,
            &provider_from(histories),
            &MockOracle(HashMap::new()),
        )
        .unwrap_err();
        assert!(
            err.contains("InvoiceCredit found"),
            "wrong error: {}",
            err
        );
    }

    // ---------------- DisputeDereliction -----------------

    fn inactive_quorum_scenario(
        elapsed: u32,
        required: u32,
    ) -> (
        FraudBroadcast,
        HashMap<String, Vec<SignedLedgerUpdate>>,
        HashMap<[u8; 32], u32>,
    ) {
        let accused_ledger = [0xAA; 32];
        let member_ledger = [0xBB; 32];
        let original_block = [0xDD; 32];
        let member_block = [0xEE; 32];

        let mut blocks = HashMap::new();
        blocks.insert(original_block, 1000);
        blocks.insert(member_block, 1000 + elapsed);

        let member_pk = pk_from_seed(0xEF);
        let mut member_active_update =
            update_with(200, member_ledger, dummy_transfer_lock([0; 32]), &[], 0, None);
        member_active_update.operator_id = member_pk;
        member_active_update.block_hash = member_block;

        let proof_template = FraudProof {
            proof_type: FraudProofType::DisputeDereliction,
            accused: hex::encode(pk_from_seed(0xAB).serialize()),
            ledger_id: hex::encode(accused_ledger),
            evidence: FraudEvidence::DisputeDereliction {
                original_fraud_hash: "66".repeat(32),
                original_fraud_block_hash: original_block,
                required_response_blocks: required,
                member_ledger_id: hex::encode(member_ledger),
                member_active_sequence: 200,
                member_pubkey: hex::encode(member_pk.serialize()),
            },
        };
        let proof_hash = proof_template.proof_hash();

        // Embedding lives on the accused's ledger.
        let embedding_update =
            update_with(50, accused_ledger, dummy_transfer_lock(proof_hash), &[], 0, None);

        let mut histories = HashMap::new();
        histories.insert(hex::encode(accused_ledger), vec![embedding_update]);
        histories.insert(hex::encode(member_ledger), vec![member_active_update]);

        let broadcast = FraudBroadcast {
            embedding: ProofEmbedding {
                ledger_id: hex::encode(accused_ledger),
                sequence: 50,
                update_hash: hex::encode([0u8; 32]),
                field: "transfer_nonce".into(),
            },
            causal_chain: vec![],
            proof: proof_template,
        };
        (broadcast, histories, blocks)
    }

    #[test]
    fn dispatch_accepts_genuine_inactive_quorum_member() {
        let (broadcast, histories, blocks) = inactive_quorum_scenario(200, 144);
        verify_fraud_broadcast(
            &broadcast,
            &provider_from(histories),
            &MockOracle(blocks),
        )
        .unwrap();
    }

    #[test]
    fn dispatch_rejects_inactive_quorum_within_window() {
        let (broadcast, histories, blocks) = inactive_quorum_scenario(100, 144);
        let err = verify_fraud_broadcast(
            &broadcast,
            &provider_from(histories),
            &MockOracle(blocks),
        )
        .unwrap_err();
        assert!(err.contains("only 100 blocks past"), "wrong error: {}", err);
    }

    #[test]
    fn dispatch_rejects_inactive_quorum_with_unconfirmed_block() {
        // Empty oracle → original_fraud_block_hash isn't in the chain.
        let (broadcast, histories, _) = inactive_quorum_scenario(200, 144);
        let err = verify_fraud_broadcast(
            &broadcast,
            &provider_from(histories),
            &MockOracle(HashMap::new()),
        )
        .unwrap_err();
        assert!(
            err.contains("not in verifier's confirmed chain"),
            "wrong error: {}",
            err
        );
    }

    // ---------------- UncreditedOnchain -----------------

    fn uncredited_onchain_scenario(
        elapsed: u32,
        required: u32,
    ) -> (
        FraudBroadcast,
        HashMap<String, Vec<SignedLedgerUpdate>>,
        HashMap<[u8; 32], u32>,
    ) {
        let accused_ledger = [0xAA; 32];
        let funding_block = [0xDD; 32];
        let proof_block = [0xEE; 32];
        let txid = [0xCC; 32];
        let offer_id = [0x33; 32];
        let funding_address = "bcrt1qtest";
        let deadline_block = 600u32;

        let mut blocks = HashMap::new();
        blocks.insert(funding_block, 1000);
        blocks.insert(proof_block, 1000 + elapsed);

        let accused_op = pk_from_seed(0xAB);
        let cosigner_ledger_hash = [0x44; 32];
        let ledger_id_hex = hex::encode(accused_ledger);
        let (sig, cosigner_pk) = sign_offer_cosig(
            0xAA,
            &ledger_id_hex,
            &offer_id,
            &accused_op,
            funding_address,
            deadline_block,
            &cosigner_ledger_hash,
        );

        let proof_template = FraudProof {
            proof_type: FraudProofType::UncreditedOnchainPayment,
            accused: hex::encode(accused_op.serialize()),
            ledger_id: ledger_id_hex.clone(),
            evidence: FraudEvidence::UncreditedOnchain {
                offer_id: hex::encode(offer_id),
                funding_address: funding_address.into(),
                accused_operator_pubkey: hex::encode(accused_op.serialize()),
                deadline_block,
                cosigner_pubkey: hex::encode(cosigner_pk.serialize()),
                cosigner_ledger_hash: hex::encode(cosigner_ledger_hash),
                cosign_signature: hex::encode(sig),
                txid: hex::encode(txid),
                vout: 0,
                amount_sats: 100_000,
                confirmed_at_block_hash: funding_block,
                required_confirmations: required,
                proof_sequence: 50,
            },
        };
        let proof_hash = proof_template.proof_hash();

        let mut proof_update = update_with(
            50,
            accused_ledger,
            dummy_transfer_lock(proof_hash),
            &[],
            0,
            None,
        );
        proof_update.block_hash = proof_block;

        let mut histories = HashMap::new();
        histories.insert(ledger_id_hex.clone(), vec![proof_update]);

        let broadcast = FraudBroadcast {
            embedding: ProofEmbedding {
                ledger_id: ledger_id_hex,
                sequence: 50,
                update_hash: hex::encode([0u8; 32]),
                field: "transfer_nonce".into(),
            },
            causal_chain: vec![],
            proof: proof_template,
        };
        (broadcast, histories, blocks)
    }

    #[test]
    fn dispatch_accepts_genuine_uncredited_onchain() {
        let (broadcast, histories, blocks) = uncredited_onchain_scenario(10, 6);
        verify_fraud_broadcast(
            &broadcast,
            &provider_from(histories),
            &MockOracle(blocks),
        )
        .unwrap();
    }

    #[test]
    fn dispatch_rejects_uncredited_onchain_with_insufficient_confs() {
        let (broadcast, histories, blocks) = uncredited_onchain_scenario(3, 6);
        let err = verify_fraud_broadcast(
            &broadcast,
            &provider_from(histories),
            &MockOracle(blocks),
        )
        .unwrap_err();
        assert!(err.contains("only 3 blocks past"), "wrong error: {}", err);
    }

    #[test]
    fn dispatch_rejects_uncredited_onchain_with_tampered_offer() {
        let (mut broadcast, histories, blocks) = uncredited_onchain_scenario(10, 6);
        // Tamper with deadline_block — invalidates cosig.
        if let FraudEvidence::UncreditedOnchain { deadline_block, .. } = &mut broadcast.proof.evidence {
            *deadline_block = 9999;
        }
        // Re-anchor embedding since proof_hash changed.
        let new_hash = broadcast.proof.proof_hash();
        let id = broadcast.embedding.ledger_id.clone();
        let mut histories = histories;
        let v = histories.get_mut(&id).unwrap();
        v[0] = {
            let mut u = update_with(50, [0xAA; 32], dummy_transfer_lock(new_hash), &[], 0, None);
            u.block_hash = [0xEE; 32];
            u
        };
        let err = verify_fraud_broadcast(
            &broadcast,
            &provider_from(histories),
            &MockOracle(blocks),
        )
        .unwrap_err();
        assert!(
            err.contains("offer cosignature failed BIP-340"),
            "wrong error: {}",
            err
        );
    }
}

// =========================================================================
// Per-type evidence verifiers
// =========================================================================

mod stale_cosignature {
    use deposits_protocol::fraud::*;
    use deposits_protocol::types::{CosignEntry, SignedLedgerUpdate};

    fn dummy_pk() -> bitcoin::secp256k1::PublicKey {
        use std::str::FromStr;
        bitcoin::secp256k1::PublicKey::from_str(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .unwrap()
    }

    fn member_pk() -> bitcoin::secp256k1::PublicKey {
        use std::str::FromStr;
        bitcoin::secp256k1::PublicKey::from_str(
            "022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4",
        )
        .unwrap()
    }

    /// Build a SignedLedgerUpdate with controllable hash + block_height
    /// + cosignatures. Other fields are dummies — staleness verification
    /// only cares about the named ones.
    fn member_update(seq: u64, content_hash: [u8; 32], block_height: u32) -> SignedLedgerUpdate {
        SignedLedgerUpdate {
            message: vec![],
            message_type: 1,
            operator_id: member_pk(),
            ledger_id: [0xBB; 32],
            sequence_number: seq,
            previous_hash: [0u8; 32],
            content_hash,
            block_height,
            block_hash: [0u8; 32],
            cosign_signature: [0u8; 64],
            operator_signature: [0u8; 64],
            cosigner_pubkey: None,
            member_ledger_hash: None,
            cosignatures: Vec::new(),
        }
    }

    fn accused_update(
        seq: u64,
        content_hash: [u8; 32],
        block_height: u32,
        cosigs_with_member_hashes: &[[u8; 32]],
    ) -> SignedLedgerUpdate {
        SignedLedgerUpdate {
            message: vec![],
            message_type: 1,
            operator_id: dummy_pk(),
            ledger_id: [0xAA; 32],
            sequence_number: seq,
            previous_hash: [0u8; 32],
            content_hash,
            block_height,
            block_hash: [0u8; 32],
            cosign_signature: [0u8; 64],
            operator_signature: [0u8; 64],
            cosigner_pubkey: None,
            member_ledger_hash: None,
            cosignatures: cosigs_with_member_hashes
                .iter()
                .map(|h| CosignEntry {
                    cosigner_pubkey: member_pk(),
                    cosign_signature: [0u8; 64],
                    member_ledger_hash: *h,
                })
                .collect(),
        }
    }

    /// Build a `StaleCosignature` proof + the matching ledger histories.
    /// The "genuine fraud" scenario: at member seq 5, member's chain_hash
    /// is H_old; member advances to seq 6/7 at blocks 95/100; accused
    /// operator cosigns at seq 30 at block 110 declaring H_old.
    ///
    /// `cosign_block_height` controls when the accused cosigned — set
    /// > 100 for fraud (member already advanced) or < 100 for not-fraud.
    fn build_fixture(
        cosign_block_height: u32,
    ) -> (FraudProof, Vec<SignedLedgerUpdate>, Vec<SignedLedgerUpdate>) {
        // Member history. content_hashes are arbitrary; what matters is
        // chain_hash() of each entry (= sha256(content_hash || op_sig)).
        // With op_sig = [0; 64], chain_hash() is deterministic from
        // content_hash, so we just compute it after-the-fact and use it
        // as the declared_member_hash.
        let member_history = vec![
            member_update(5, [0x11; 32], 90),
            member_update(6, [0xAB; 32], 95),
            member_update(7, [0x22; 32], 100),
        ];
        let h_old = member_history[0].chain_hash(); // member's chain at seq 5

        let stale_content_hash = [0x33; 32];
        let accused_history = vec![accused_update(
            30,
            stale_content_hash,
            cosign_block_height,
            &[h_old],
        )];

        let later_chain_hash = member_history[2].chain_hash();

        let proof = FraudProof {
            proof_type: FraudProofType::StaleCosignature,
            accused: "02".to_string() + &"ab".repeat(32),
            ledger_id: hex::encode([0xAA; 32]),
            evidence: FraudEvidence::StaleCosign {
                stale_update_sequence: 30,
                stale_update_hash: hex::encode(stale_content_hash),
                declared_member_hash: hex::encode(h_old),
                member_later_sequence: 7,
                member_later_hash: hex::encode(later_chain_hash),
                member_ledger_id: hex::encode([0xBB; 32]),
            },
        };

        (proof, accused_history, member_history)
    }

    fn genuine_fraud_fixture() -> (FraudProof, Vec<SignedLedgerUpdate>, Vec<SignedLedgerUpdate>)
    {
        // Cosign at block 110 — AFTER member advanced at block 100. Stale.
        build_fixture(110)
    }

    #[test]
    fn accepts_genuine_stale_cosignature() {
        let (proof, accused, member) = genuine_fraud_fixture();
        verify_stale_cosignature(&proof, &accused, &member).unwrap();
    }

    #[test]
    fn rejects_when_member_didnt_advance_before_cosign() {
        // Cosign at block 80 — BEFORE member's seq 6/7 (blocks 95/100).
        // Member only had seq 5 = declared_member_hash at the cosign moment,
        // hadn't advanced past it yet → not stale.
        let (proof, accused, member) = build_fixture(80);
        let err = verify_stale_cosignature(&proof, &accused, &member).unwrap_err();
        assert!(
            err.contains("did not advance past"),
            "wrong error: {}",
            err
        );
    }

    #[test]
    fn rejects_when_declared_hash_never_appears_in_member_history() {
        let (mut proof, accused, member) = genuine_fraud_fixture();
        if let FraudEvidence::StaleCosign {
            declared_member_hash,
            ..
        } = &mut proof.evidence
        {
            *declared_member_hash = "ff".repeat(32);
        }
        let err = verify_stale_cosignature(&proof, &accused, &member).unwrap_err();
        // The declared hash isn't among the cosignatures on the stale update,
        // so we fail at that earlier check.
        assert!(
            err.contains("not found among CosignEntries"),
            "wrong error: {}",
            err
        );
    }

    #[test]
    fn rejects_when_stale_update_seq_missing() {
        let (mut proof, accused, member) = genuine_fraud_fixture();
        if let FraudEvidence::StaleCosign {
            stale_update_sequence,
            ..
        } = &mut proof.evidence
        {
            *stale_update_sequence = 999;
        }
        let err = verify_stale_cosignature(&proof, &accused, &member).unwrap_err();
        assert!(err.contains("not in accused history"), "wrong error: {}", err);
    }

    #[test]
    fn rejects_when_member_later_seq_missing() {
        let (mut proof, accused, member) = genuine_fraud_fixture();
        if let FraudEvidence::StaleCosign {
            member_later_sequence,
            ..
        } = &mut proof.evidence
        {
            *member_later_sequence = 999;
        }
        let err = verify_stale_cosignature(&proof, &accused, &member).unwrap_err();
        assert!(err.contains("not in member history"), "wrong error: {}", err);
    }

    #[test]
    fn rejects_when_stale_update_hash_doesnt_match() {
        let (mut proof, accused, member) = genuine_fraud_fixture();
        if let FraudEvidence::StaleCosign {
            stale_update_hash, ..
        } = &mut proof.evidence
        {
            *stale_update_hash = "ff".repeat(32);
        }
        let err = verify_stale_cosignature(&proof, &accused, &member).unwrap_err();
        assert!(err.contains("stale_update_hash mismatch"), "wrong error: {}", err);
    }

    #[test]
    fn rejects_wrong_evidence_type() {
        let (mut proof, accused, member) = genuine_fraud_fixture();
        proof.evidence = FraudEvidence::NonConforming {
            sequence: 1,
            update_b64: "AA==".to_string(),
            violation: "x".to_string(),
        };
        let err = verify_stale_cosignature(&proof, &accused, &member).unwrap_err();
        assert!(err.contains("wrong evidence type"), "wrong error: {}", err);
    }
}

mod uncredited_lightning {
    use deposits_protocol::fraud::*;
    use deposits_protocol::messages::LedgerOperation;
    use deposits_protocol::tlv::TlvEncode;
    use deposits_protocol::types::SignedLedgerUpdate;
    use sha2::{Digest, Sha256};

    fn dummy_pk() -> bitcoin::secp256k1::PublicKey {
        use std::str::FromStr;
        bitcoin::secp256k1::PublicKey::from_str(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .unwrap()
    }

    /// Build a real BIP-340 schnorr cosignature over the canonical
    /// invoice signing message. Returns (cosigner_pubkey, sig_hex,
    /// cosigner_ledger_hash).
    fn cosign_invoice(
        ledger_id: &str,
        payment_hash: &[u8; 32],
        deposit_id: &deposits_protocol::DepositId,
        amount_msat: u64,
        cosigner_seed: u8,
    ) -> (bitcoin::secp256k1::PublicKey, String, [u8; 32]) {
        use bitcoin::secp256k1::{Keypair, Message, Secp256k1};

        let cosigner_ledger_hash = [0xCC; 32];
        let secp = Secp256k1::new();
        let secret = bitcoin::secp256k1::SecretKey::from_slice(&[cosigner_seed; 32]).unwrap();
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let cosigner_pubkey = keypair.public_key();

        let msg_hash = deposits_protocol::invoice_cosign_signing_message(
            ledger_id,
            payment_hash,
            deposit_id,
            amount_msat,
            &cosigner_ledger_hash,
        );
        let msg = Message::from_digest(msg_hash);
        let sig = secp.sign_schnorr_no_aux_rand(&msg, &keypair);

        (cosigner_pubkey, hex::encode(sig.serialize()), cosigner_ledger_hash)
    }

    fn fixture_update(seq: u64, op: LedgerOperation) -> SignedLedgerUpdate {
        SignedLedgerUpdate {
            message: op.tlv_encode(),
            message_type: op.message_type(),
            operator_id: dummy_pk(),
            ledger_id: [0xAA; 32],
            sequence_number: seq,
            previous_hash: [0u8; 32],
            content_hash: [0u8; 32],
            block_height: 0,
            block_hash: [0u8; 32],
            cosign_signature: [0u8; 64],
            operator_signature: [0u8; 64],
            cosigner_pubkey: None,
            member_ledger_hash: None,
            cosignatures: Vec::new(),
        }
    }

    /// Tiny placeholder TransferLock used as "an update at this seq" when
    /// the test only cares about the seq (not the op contents).
    fn dummy_op() -> LedgerOperation {
        LedgerOperation::TransferLock {
            nonce: [0u8; 32],
            source_deposit_id: deposits_protocol::DepositId::default(),
            destination_deposit_id: deposits_protocol::DepositId::default(),
            amount: 1,
            fee: 0,
            completion_script: String::new(),
            timeout_height: 0,
            transfer_id: [0u8; 32],
            witness: Default::default(),
        }
    }

    fn proof_for(preimage: [u8; 32], proof_sequence: u64) -> FraudProof {
        let payment_hash: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(preimage);
            h.finalize().into()
        };
        let ledger_id = hex::encode([0xAA; 32]);
        let deposit_id = deposits_protocol::DepositId::default();
        let amount_msat = 1_000_000u64;
        let (cosigner_pk, sig_hex, cosigner_ledger_hash) =
            cosign_invoice(&ledger_id, &payment_hash, &deposit_id, amount_msat, 0xAA);

        FraudProof {
            proof_type: FraudProofType::UncreditedLightningPayment,
            accused: "02".to_string() + &"ab".repeat(32),
            ledger_id,
            evidence: FraudEvidence::UncreditedLightning {
                invoice: "lnbcrt1ptest".to_string(),
                payment_hash: hex::encode(payment_hash),
                deposit_id,
                amount_msat,
                cosigner_pubkey: hex::encode(cosigner_pk.serialize()),
                cosigner_ledger_hash: hex::encode(cosigner_ledger_hash),
                cosign_signature: sig_hex,
                preimage: hex::encode(preimage),
                proof_sequence,
            },
        }
    }

    #[test]
    fn accepts_genuine_uncredited_payment() {
        let preimage = [0xBE; 32];
        let proof = proof_for(preimage, 50);
        // Accused's history has unrelated updates, none crediting this payment.
        let history = vec![fixture_update(50, dummy_op())];
        verify_uncredited_lightning(&proof, &history).unwrap();
    }

    #[test]
    fn rejects_when_preimage_doesnt_match_payment_hash() {
        let preimage = [0xBE; 32];
        let mut proof = proof_for(preimage, 50);
        if let FraudEvidence::UncreditedLightning {
            payment_hash, ..
        } = &mut proof.evidence
        {
            *payment_hash = "ff".repeat(32); // doesn't match hash(preimage)
        }
        let history = vec![fixture_update(50, dummy_op())];
        let err = verify_uncredited_lightning(&proof, &history).unwrap_err();
        assert!(
            err.contains("preimage doesn't hash to payment_hash"),
            "wrong error: {}",
            err
        );
    }

    #[test]
    fn rejects_when_invoice_credit_present() {
        let preimage = [0xBE; 32];
        let proof = proof_for(preimage, 50);
        let payment_hash: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(preimage);
            h.finalize().into()
        };
        // Accused DID credit the deposit at seq 30 (before proof_sequence=50).
        let credit_op = LedgerOperation::InvoiceCredit {
            payment_hash,
            deposit_id: deposits_protocol::DepositId::default(),
            amount: 1000,
            invoice_id: "test".to_string(),
            sequence_number: 30,
        };
        let history = vec![
            fixture_update(30, credit_op),
            fixture_update(50, dummy_op()),
        ];
        let err = verify_uncredited_lightning(&proof, &history).unwrap_err();
        assert!(
            err.contains("InvoiceCredit found"),
            "wrong error: {}",
            err
        );
    }

    #[test]
    fn rejects_when_invoice_fulfill_present() {
        let preimage = [0xBE; 32];
        let proof = proof_for(preimage, 50);
        // Accused fulfilled the invoice (preimage in InvoiceFulfill).
        let fulfill_op = LedgerOperation::InvoiceFulfill {
            deposit_id: deposits_protocol::DepositId::default(),
            amount: 1000,
            payment_id: [0u8; 32],
            sequence_number: 30,
            witness: Default::default(),
            preimage,
        };
        let history = vec![
            fixture_update(30, fulfill_op),
            fixture_update(50, dummy_op()),
        ];
        let err = verify_uncredited_lightning(&proof, &history).unwrap_err();
        assert!(
            err.contains("InvoiceFulfill found"),
            "wrong error: {}",
            err
        );
    }

    #[test]
    fn rejects_when_proof_sequence_missing() {
        let preimage = [0xBE; 32];
        let proof = proof_for(preimage, 50);
        let history = vec![fixture_update(49, dummy_op())]; // 50 missing
        let err = verify_uncredited_lightning(&proof, &history).unwrap_err();
        assert!(err.contains("not in accused history"), "wrong error: {}", err);
    }

    #[test]
    fn ignores_credit_after_proof_sequence() {
        // If operator credits AFTER proof_sequence, that's irrelevant — by
        // proof_sequence they should already have credited. Still fraud.
        let preimage = [0xBE; 32];
        let proof = proof_for(preimage, 50);
        let payment_hash: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(preimage);
            h.finalize().into()
        };
        let credit_op = LedgerOperation::InvoiceCredit {
            payment_hash,
            deposit_id: deposits_protocol::DepositId::default(),
            amount: 1000,
            invoice_id: "test".to_string(),
            sequence_number: 60,
        };
        let history = vec![
            fixture_update(50, dummy_op()),
            fixture_update(60, credit_op), // after proof_sequence
        ];
        verify_uncredited_lightning(&proof, &history).unwrap();
    }

    #[test]
    fn rejects_wrong_evidence_type() {
        let mut proof = proof_for([0xBE; 32], 50);
        proof.evidence = FraudEvidence::NonConforming {
            sequence: 1,
            update_b64: "AA==".to_string(),
            violation: "x".to_string(),
        };
        let history = vec![fixture_update(50, dummy_op())];
        let err = verify_uncredited_lightning(&proof, &history).unwrap_err();
        assert!(err.contains("wrong evidence type"), "wrong error: {}", err);
    }

    #[test]
    fn rejects_invalid_cosignature() {
        // Signature that's syntactically a 64-byte schnorr but doesn't
        // verify against the canonical signing message. We swap in a
        // signature from a different message so structure passes but
        // verification fails.
        let other_proof = proof_for([0xCC; 32], 99); // signs a different message
        let other_sig = match &other_proof.evidence {
            FraudEvidence::UncreditedLightning { cosign_signature, .. } => {
                cosign_signature.clone()
            }
            _ => unreachable!(),
        };

        let mut proof = proof_for([0xBE; 32], 50);
        if let FraudEvidence::UncreditedLightning {
            cosign_signature, ..
        } = &mut proof.evidence
        {
            *cosign_signature = other_sig;
        }
        let history = vec![fixture_update(50, dummy_op())];
        let err = verify_uncredited_lightning(&proof, &history).unwrap_err();
        assert!(
            err.contains("invoice cosignature failed BIP-340 verification"),
            "wrong error: {}",
            err
        );
    }

    #[test]
    fn rejects_signature_over_wrong_message() {
        // Cosignature is over a DIFFERENT amount_msat than what evidence claims.
        // Anyone tampering with the amount field after the cosig was made
        // should be detected.
        let mut proof = proof_for([0xBE; 32], 50);
        if let FraudEvidence::UncreditedLightning {
            amount_msat, ..
        } = &mut proof.evidence
        {
            *amount_msat = 9_999_999; // tampered
        }
        let history = vec![fixture_update(50, dummy_op())];
        let err = verify_uncredited_lightning(&proof, &history).unwrap_err();
        assert!(
            err.contains("invoice cosignature failed BIP-340 verification"),
            "wrong error: {}",
            err
        );
    }
}

mod inactive_quorum_member {
    use deposits_protocol::fraud::*;
    use deposits_protocol::types::SignedLedgerUpdate;
    use std::collections::HashMap;

    fn member_pk() -> bitcoin::secp256k1::PublicKey {
        use std::str::FromStr;
        bitcoin::secp256k1::PublicKey::from_str(
            "022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4",
        )
        .unwrap()
    }

    fn other_pk() -> bitcoin::secp256k1::PublicKey {
        use std::str::FromStr;
        bitcoin::secp256k1::PublicKey::from_str(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .unwrap()
    }

    fn member_update_at(seq: u64, block_hash: [u8; 32], signer: bitcoin::secp256k1::PublicKey) -> SignedLedgerUpdate {
        SignedLedgerUpdate {
            message: vec![],
            message_type: 1,
            operator_id: signer,
            ledger_id: [0xBB; 32],
            sequence_number: seq,
            previous_hash: [0u8; 32],
            content_hash: [0u8; 32],
            block_height: 0,
            block_hash,
            cosign_signature: [0u8; 64],
            operator_signature: [0u8; 64],
            cosigner_pubkey: None,
            member_ledger_hash: None,
            cosignatures: Vec::new(),
        }
    }

    /// Mock oracle backed by a HashMap.
    struct MockOracle(HashMap<[u8; 32], u32>);
    impl BlockOracle for MockOracle {
        fn confirms(&self, hash: &[u8; 32]) -> Option<u32> {
            self.0.get(hash).copied()
        }
    }

    fn fixture(
        elapsed_blocks: u32,
        required_blocks: u32,
        signer: bitcoin::secp256k1::PublicKey,
    ) -> (FraudProof, Vec<SignedLedgerUpdate>, MockOracle) {
        let original_fraud_block_hash = [0xAA; 32];
        let member_block_hash = [0xCC; 32];

        let mut oracle = HashMap::new();
        oracle.insert(original_fraud_block_hash, 1000u32);
        oracle.insert(member_block_hash, 1000 + elapsed_blocks);

        let history = vec![member_update_at(200, member_block_hash, signer)];

        let proof = FraudProof {
            proof_type: FraudProofType::DisputeDereliction,
            accused: "02".to_string() + &"ab".repeat(32),
            ledger_id: hex::encode([0xAA; 32]),
            evidence: FraudEvidence::DisputeDereliction {
                original_fraud_hash: "66".repeat(32),
                original_fraud_block_hash,
                required_response_blocks: required_blocks,
                member_ledger_id: hex::encode([0xBB; 32]),
                member_active_sequence: 200,
                member_pubkey: hex::encode(member_pk().serialize()),
            },
        };

        (proof, history, MockOracle(oracle))
    }

    #[test]
    fn accepts_genuine_inactive_member() {
        // Member published 200 blocks after the fraud, deadline was 144.
        let (proof, history, oracle) = fixture(200, 144, member_pk());
        verify_inactive_quorum_member(&proof, &history, &oracle).unwrap();
    }

    #[test]
    fn rejects_when_window_not_yet_elapsed() {
        // Member published only 100 blocks after fraud — within the 144 window.
        let (proof, history, oracle) = fixture(100, 144, member_pk());
        let err = verify_inactive_quorum_member(&proof, &history, &oracle).unwrap_err();
        assert!(
            err.contains("only 100 blocks past"),
            "wrong error: {}",
            err
        );
    }

    #[test]
    fn rejects_unconfirmed_original_fraud_block() {
        // Oracle returns None for the original-fraud block hash.
        let (mut proof, history, _) = fixture(200, 144, member_pk());
        if let FraudEvidence::DisputeDereliction {
            original_fraud_block_hash,
            ..
        } = &mut proof.evidence
        {
            *original_fraud_block_hash = [0xFF; 32]; // unknown
        }
        let oracle = MockOracle(HashMap::new());
        let err = verify_inactive_quorum_member(&proof, &history, &oracle).unwrap_err();
        assert!(
            err.contains("original_fraud_block_hash") && err.contains("not in verifier"),
            "wrong error: {}",
            err
        );
    }

    #[test]
    fn rejects_unconfirmed_member_active_block() {
        // Member's update has a block_hash unknown to the oracle.
        let original_fraud_block_hash = [0xAA; 32];
        let mut oracle_map = HashMap::new();
        oracle_map.insert(original_fraud_block_hash, 1000u32);
        // Note: we deliberately do NOT insert the member's block hash.
        let oracle = MockOracle(oracle_map);

        let history = vec![member_update_at(200, [0xCC; 32], member_pk())];
        let proof = FraudProof {
            proof_type: FraudProofType::DisputeDereliction,
            accused: "02".to_string() + &"ab".repeat(32),
            ledger_id: hex::encode([0xAA; 32]),
            evidence: FraudEvidence::DisputeDereliction {
                original_fraud_hash: "66".repeat(32),
                original_fraud_block_hash,
                required_response_blocks: 144,
                member_ledger_id: hex::encode([0xBB; 32]),
                member_active_sequence: 200,
                member_pubkey: hex::encode(member_pk().serialize()),
            },
        };
        let err = verify_inactive_quorum_member(&proof, &history, &oracle).unwrap_err();
        assert!(
            err.contains("member-active update's block_hash") && err.contains("not in verifier"),
            "wrong error: {}",
            err
        );
    }

    #[test]
    fn rejects_when_member_active_seq_missing() {
        let (proof, _history, oracle) = fixture(200, 144, member_pk());
        let history: Vec<SignedLedgerUpdate> = vec![]; // no update at seq 200
        let err = verify_inactive_quorum_member(&proof, &history, &oracle).unwrap_err();
        assert!(err.contains("not in member history"), "wrong error: {}", err);
    }

    #[test]
    fn rejects_when_member_active_signed_by_someone_else() {
        // Update at the right sequence but signed by a different operator.
        // Prevents framing a member by planting an update with their seq
        // number on someone else's ledger.
        let (proof, _, oracle) = fixture(200, 144, other_pk());
        let history = vec![member_update_at(200, [0xCC; 32], other_pk())];
        let err = verify_inactive_quorum_member(&proof, &history, &oracle).unwrap_err();
        assert!(
            err.contains("signed by") && err.contains("not member_pubkey"),
            "wrong error: {}",
            err
        );
    }

    #[test]
    fn rejects_wrong_evidence_type() {
        let (mut proof, history, oracle) = fixture(200, 144, member_pk());
        proof.evidence = FraudEvidence::NonConforming {
            sequence: 1,
            update_b64: "AA==".to_string(),
            violation: "x".to_string(),
        };
        let err = verify_inactive_quorum_member(&proof, &history, &oracle).unwrap_err();
        assert!(err.contains("wrong evidence type"), "wrong error: {}", err);
    }
}

mod uncredited_onchain {
    use deposits_protocol::fraud::*;
    use deposits_protocol::messages::LedgerOperation;
    use deposits_protocol::tlv::TlvEncode;
    use deposits_protocol::types::SignedLedgerUpdate;
    use std::collections::HashMap;

    fn dummy_pk() -> bitcoin::secp256k1::PublicKey {
        use std::str::FromStr;
        bitcoin::secp256k1::PublicKey::from_str(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .unwrap()
    }

    struct MockOracle(HashMap<[u8; 32], u32>);
    impl BlockOracle for MockOracle {
        fn confirms(&self, hash: &[u8; 32]) -> Option<u32> {
            self.0.get(hash).copied()
        }
    }

    fn fixture_update(seq: u64, block_hash: [u8; 32], op: LedgerOperation) -> SignedLedgerUpdate {
        SignedLedgerUpdate {
            message: op.tlv_encode(),
            message_type: op.message_type(),
            operator_id: dummy_pk(),
            ledger_id: [0xAA; 32],
            sequence_number: seq,
            previous_hash: [0u8; 32],
            content_hash: [0u8; 32],
            block_height: 0,
            block_hash,
            cosign_signature: [0u8; 64],
            operator_signature: [0u8; 64],
            cosigner_pubkey: None,
            member_ledger_hash: None,
            cosignatures: Vec::new(),
        }
    }

    fn dummy_op() -> LedgerOperation {
        LedgerOperation::TransferLock {
            nonce: [0u8; 32],
            source_deposit_id: deposits_protocol::DepositId::default(),
            destination_deposit_id: deposits_protocol::DepositId::default(),
            amount: 1,
            fee: 0,
            completion_script: String::new(),
            timeout_height: 0,
            transfer_id: [0u8; 32],
            witness: Default::default(),
        }
    }

    /// Build a deterministic accused operator keypair so the offer-cosig
    /// signing message can be reproduced (operator pubkey is part of the
    /// hash). Returns (accused_pubkey, accused_pubkey_hex).
    fn accused_op() -> (bitcoin::secp256k1::PublicKey, String) {
        use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[0xAB; 32]).unwrap();
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let pk = keypair.public_key();
        (pk, hex::encode(pk.serialize()))
    }

    /// Sign an offer cosig with a deterministic cosigner key. Returns
    /// (cosigner_pubkey_hex, sig_hex, cosigner_ledger_hash).
    fn cosign_offer(
        ledger_id: &str,
        offer_id: &[u8; 32],
        accused_pk: &bitcoin::secp256k1::PublicKey,
        funding_address: &str,
        deadline_block: u32,
    ) -> (String, String, [u8; 32]) {
        use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
        let cosigner_ledger_hash = [0xDD; 32];
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[0xCD; 32]).unwrap();
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let cosigner_pk = keypair.public_key();
        let msg_hash = deposits_protocol::offer_cosign_signing_message(
            ledger_id,
            offer_id,
            accused_pk,
            funding_address,
            deadline_block,
            &cosigner_ledger_hash,
        );
        let msg = Message::from_digest(msg_hash);
        let sig = secp.sign_schnorr_no_aux_rand(&msg, &keypair);
        (
            hex::encode(cosigner_pk.serialize()),
            hex::encode(sig.serialize()),
            cosigner_ledger_hash,
        )
    }

    fn fixture(
        elapsed_blocks: u32,
        required_confs: u32,
    ) -> (FraudProof, Vec<SignedLedgerUpdate>, MockOracle, [u8; 32]) {
        let funding_block_hash = [0xBB; 32];
        let proof_block_hash = [0xCC; 32];
        let txid_bytes = [0xEE; 32];
        let offer_id = [0xBB; 32];
        let funding_address = "bcrt1qtest";
        let deadline_block = 600u32;

        let mut oracle = HashMap::new();
        oracle.insert(funding_block_hash, 1000u32);
        oracle.insert(proof_block_hash, 1000 + elapsed_blocks);

        let history = vec![fixture_update(50, proof_block_hash, dummy_op())];

        let (accused_pk, accused_hex) = accused_op();
        let ledger_id = hex::encode([0xAA; 32]);
        let (cosigner_pk_hex, sig_hex, cosigner_ledger_hash) = cosign_offer(
            &ledger_id,
            &offer_id,
            &accused_pk,
            funding_address,
            deadline_block,
        );

        let proof = FraudProof {
            proof_type: FraudProofType::UncreditedOnchainPayment,
            accused: accused_hex.clone(),
            ledger_id,
            evidence: FraudEvidence::UncreditedOnchain {
                offer_id: hex::encode(offer_id),
                funding_address: funding_address.to_string(),
                accused_operator_pubkey: accused_hex,
                deadline_block,
                cosigner_pubkey: cosigner_pk_hex,
                cosigner_ledger_hash: hex::encode(cosigner_ledger_hash),
                cosign_signature: sig_hex,
                txid: hex::encode(txid_bytes),
                vout: 0,
                amount_sats: 100_000,
                confirmed_at_block_hash: funding_block_hash,
                required_confirmations: required_confs,
                proof_sequence: 50,
            },
        };

        (proof, history, MockOracle(oracle), txid_bytes)
    }

    #[test]
    fn accepts_genuine_uncredited_onchain() {
        // Operator's update is 10 blocks past funding; required = 6.
        let (proof, history, oracle, _) = fixture(10, 6);
        verify_uncredited_onchain(&proof, &history, &oracle).unwrap();
    }

    #[test]
    fn rejects_when_not_enough_confirmations() {
        // Operator's update only 3 blocks past funding; required = 6.
        let (proof, history, oracle, _) = fixture(3, 6);
        let err = verify_uncredited_onchain(&proof, &history, &oracle).unwrap_err();
        assert!(
            err.contains("only 3 blocks past funding"),
            "wrong error: {}",
            err
        );
    }

    #[test]
    fn rejects_unconfirmed_funding_block() {
        let (mut proof, history, _, _) = fixture(10, 6);
        if let FraudEvidence::UncreditedOnchain {
            confirmed_at_block_hash,
            ..
        } = &mut proof.evidence
        {
            *confirmed_at_block_hash = [0xFF; 32];
        }
        let err = verify_uncredited_onchain(&proof, &history, &MockOracle(HashMap::new()))
            .unwrap_err();
        assert!(
            err.contains("confirmed_at_block_hash") && err.contains("not in verifier"),
            "wrong error: {}",
            err
        );
    }

    #[test]
    fn rejects_unconfirmed_proof_sequence_block() {
        // Build the genuine fixture, then drop the proof-block entry
        // from the oracle so only the funding block is confirmed.
        let (proof, history, oracle, _) = fixture(10, 6);
        let funding_block_hash =
            if let FraudEvidence::UncreditedOnchain { confirmed_at_block_hash, .. } =
                &proof.evidence
            {
                *confirmed_at_block_hash
            } else {
                unreachable!()
            };
        let mut oracle_map = HashMap::new();
        oracle_map.insert(funding_block_hash, oracle.0[&funding_block_hash]);
        let oracle = MockOracle(oracle_map);
        let err = verify_uncredited_onchain(&proof, &history, &oracle).unwrap_err();
        assert!(
            err.contains("proof_sequence update's block_hash") && err.contains("not in verifier"),
            "wrong error: {}",
            err
        );
    }

    #[test]
    fn rejects_when_onchain_credit_present() {
        let (proof, _hist, oracle, txid_bytes) = fixture(10, 6);
        let credit_op = LedgerOperation::OnchainCredit {
            txid: txid_bytes,
            vout: 0,
            deposit_id: deposits_protocol::DepositId::default(),
            amount: 100_000,
            funding_address: "bcrt1qtest".to_string(),
        };
        let history = vec![
            fixture_update(40, [0xCC; 32], credit_op),
            fixture_update(50, [0xCC; 32], dummy_op()),
        ];
        let err = verify_uncredited_onchain(&proof, &history, &oracle).unwrap_err();
        assert!(
            err.contains("OnchainCredit found"),
            "wrong error: {}",
            err
        );
    }

    #[test]
    fn ignores_credit_for_different_outpoint() {
        let (proof, _hist, oracle, _) = fixture(10, 6);
        // OnchainCredit exists but for a different (txid, vout).
        let credit_op = LedgerOperation::OnchainCredit {
            txid: [0x00; 32],
            vout: 99,
            deposit_id: deposits_protocol::DepositId::default(),
            amount: 100_000,
            funding_address: "bcrt1qother".to_string(),
        };
        let history = vec![
            fixture_update(40, [0xCC; 32], credit_op),
            fixture_update(50, [0xCC; 32], dummy_op()),
        ];
        verify_uncredited_onchain(&proof, &history, &oracle).unwrap();
    }

    #[test]
    fn rejects_when_proof_sequence_missing() {
        let (proof, _, oracle, _) = fixture(10, 6);
        let history: Vec<SignedLedgerUpdate> = vec![]; // no update at seq 50
        let err = verify_uncredited_onchain(&proof, &history, &oracle).unwrap_err();
        assert!(err.contains("not in accused history"), "wrong error: {}", err);
    }

    #[test]
    fn rejects_wrong_evidence_type() {
        let (mut proof, history, oracle, _) = fixture(10, 6);
        proof.evidence = FraudEvidence::NonConforming {
            sequence: 1,
            update_b64: "AA==".to_string(),
            violation: "x".to_string(),
        };
        let err = verify_uncredited_onchain(&proof, &history, &oracle).unwrap_err();
        assert!(err.contains("wrong evidence type"), "wrong error: {}", err);
    }

    #[test]
    fn rejects_offer_signature_over_wrong_message() {
        // Tamper with deadline_block after the cosig was made.
        let (mut proof, history, oracle, _) = fixture(10, 6);
        if let FraudEvidence::UncreditedOnchain {
            deadline_block, ..
        } = &mut proof.evidence
        {
            *deadline_block = 999_999;
        }
        let err = verify_uncredited_onchain(&proof, &history, &oracle).unwrap_err();
        assert!(
            err.contains("offer cosignature failed BIP-340 verification"),
            "wrong error: {}",
            err
        );
    }

    #[test]
    fn rejects_offer_signature_with_swapped_funding_address() {
        let (mut proof, history, oracle, _) = fixture(10, 6);
        if let FraudEvidence::UncreditedOnchain {
            funding_address, ..
        } = &mut proof.evidence
        {
            *funding_address = "bcrt1qother".to_string();
        }
        let err = verify_uncredited_onchain(&proof, &history, &oracle).unwrap_err();
        assert!(
            err.contains("offer cosignature failed BIP-340 verification"),
            "wrong error: {}",
            err
        );
    }
}

// =========================================================================
// Embedding source verification
// =========================================================================
//
// Two source types for the embedded hash:
//   - TransferLock.nonce        (wallet-controlled embed via a transfer)
//   - DeliveryEmbed.request_hash (operator-recorded embed of a request)
//
// Two paths the verifier walks to reach the embedding:
//   - Same ledger as the accused (no chain hops; chain is empty)
//   - A quorum member's ledger reached via the operator's `member_ledger_hash`
//     cosign field (one or more chain hops)
//
// `LedgerOperation::embedded_hash` extracts the hash regardless of source,
// and `ProofEmbedding::verify_in_history` finds the right update in a
// ledger's history. The chain-walking piece is `verify_chain_structure`,
// which is independent of source type.

mod embedding {
    use deposits_protocol::fraud::*;
    use deposits_protocol::messages::LedgerOperation;
    use deposits_protocol::tlv::TlvEncode;
    use deposits_protocol::types::SignedLedgerUpdate;

    fn dummy_pk() -> bitcoin::secp256k1::PublicKey {
        use std::str::FromStr;
        bitcoin::secp256k1::PublicKey::from_str(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .unwrap()
    }

    /// Build a SignedLedgerUpdate carrying `op` at `seq` on `ledger_id`. Hash
    /// chain fields aren't computed — the embedding lookup only cares about
    /// `sequence_number` + decoded `message`.
    fn fixture(seq: u64, ledger_id: [u8; 32], op: LedgerOperation) -> SignedLedgerUpdate {
        SignedLedgerUpdate {
            message: op.tlv_encode(),
            message_type: op.message_type(),
            operator_id: dummy_pk(),
            ledger_id,
            sequence_number: seq,
            previous_hash: [0u8; 32],
            content_hash: [0u8; 32],
            block_height: 0,
            block_hash: [0u8; 32],
            cosign_signature: [0u8; 64],
            operator_signature: [0u8; 64],
            cosigner_pubkey: None,
            member_ledger_hash: None,
            cosignatures: Vec::new(),
        }
    }

    fn transfer_lock(nonce: [u8; 32]) -> LedgerOperation {
        LedgerOperation::TransferLock {
            nonce,
            source_deposit_id: deposits_protocol::DepositId::default(),
            destination_deposit_id: deposits_protocol::DepositId::default(),
            amount: 1,
            fee: 0,
            completion_script: String::new(),
            timeout_height: 0,
            transfer_id: [0u8; 32],
            witness: Default::default(),
        }
    }

    fn delivery_embed(request_hash: [u8; 32]) -> LedgerOperation {
        LedgerOperation::DeliveryEmbed {
            request_hash,
            target_ledger_id: [0u8; 32],
            target_operator: dummy_pk(),
        }
    }

    // ---- LedgerOperation::embedded_hash returns the right field ----

    #[test]
    fn embedded_hash_extracts_transfer_lock_nonce() {
        let nonce = [0xAB; 32];
        assert_eq!(transfer_lock(nonce).embedded_hash(), Some(&nonce));
    }

    #[test]
    fn embedded_hash_extracts_delivery_embed_request_hash() {
        let h = [0xCD; 32];
        assert_eq!(delivery_embed(h).embedded_hash(), Some(&h));
    }

    #[test]
    fn embedded_hash_returns_none_for_unsupported_ops() {
        assert!(LedgerOperation::DisputeYield.embedded_hash().is_none());
        assert!(LedgerOperation::LedgerClose.embedded_hash().is_none());
    }

    // ---- ProofEmbedding::verify_in_history covers the source × path matrix ----
    //
    // `verify_in_history` operates on a single ledger's history. The "path"
    // distinction (same ledger vs. cross-ledger via cosign hash) is the
    // caller's job: same-ledger lookups query the operator's history, cross-
    // ledger lookups query the source ledger's history. This pair of tests
    // exercises both source types over both call patterns.

    fn proof_for(ledger_id: [u8; 32]) -> FraudProof {
        FraudProof {
            proof_type: FraudProofType::NonConformingUpdate,
            accused: "02".to_string() + &"ab".repeat(32),
            ledger_id: hex::encode(ledger_id),
            evidence: FraudEvidence::NonConforming {
                sequence: 99,
                update_b64: "AAA=".to_string(),
                violation: "test".to_string(),
            },
        }
    }

    #[test]
    fn verify_in_history_same_ledger_transfer_lock() {
        let accused_ledger = [0x11u8; 32];
        let proof = proof_for(accused_ledger);
        let ph = proof.proof_hash();

        let history = vec![fixture(50, accused_ledger, transfer_lock(ph))];
        let embedding = ProofEmbedding {
            ledger_id: hex::encode(accused_ledger),
            sequence: 50,
            update_hash: hex::encode([0xAA; 32]),
            field: "transfer_nonce".to_string(),
        };
        assert!(embedding.verify_in_history(&history, &ph));
    }

    #[test]
    fn verify_in_history_same_ledger_delivery_embed() {
        let accused_ledger = [0x22u8; 32];
        let proof = proof_for(accused_ledger);
        let ph = proof.proof_hash();

        let history = vec![fixture(7, accused_ledger, delivery_embed(ph))];
        let embedding = ProofEmbedding {
            ledger_id: hex::encode(accused_ledger),
            sequence: 7,
            update_hash: hex::encode([0xAA; 32]),
            field: "delivery_request_hash".to_string(),
        };
        assert!(embedding.verify_in_history(&history, &ph));
    }

    #[test]
    fn verify_in_history_cross_ledger_transfer_lock() {
        // Embedding lives on a member's ledger. Caller fetches the member's
        // history (this pure helper doesn't know about the chain hop) and
        // passes it in. The chain-walking is independently verified by
        // `verify_chain_structure` on the FraudBroadcast.
        let member_ledger = [0x33u8; 32];
        let proof = proof_for([0x44u8; 32]); // accused != member
        let ph = proof.proof_hash();

        let history = vec![fixture(10, member_ledger, transfer_lock(ph))];
        let embedding = ProofEmbedding {
            ledger_id: hex::encode(member_ledger),
            sequence: 10,
            update_hash: hex::encode([0xAA; 32]),
            field: "transfer_nonce".to_string(),
        };
        assert!(embedding.verify_in_history(&history, &ph));
    }

    #[test]
    fn verify_in_history_cross_ledger_delivery_embed() {
        let member_ledger = [0x55u8; 32];
        let proof = proof_for([0x66u8; 32]);
        let ph = proof.proof_hash();

        let history = vec![fixture(3, member_ledger, delivery_embed(ph))];
        let embedding = ProofEmbedding {
            ledger_id: hex::encode(member_ledger),
            sequence: 3,
            update_hash: hex::encode([0xAA; 32]),
            field: "delivery_request_hash".to_string(),
        };
        assert!(embedding.verify_in_history(&history, &ph));
    }

    // ---- Negative cases ----

    #[test]
    fn verify_in_history_rejects_wrong_hash() {
        let accused_ledger = [0x77u8; 32];
        let proof = proof_for(accused_ledger);
        let ph = proof.proof_hash();
        let wrong = [0xFFu8; 32];

        let history = vec![fixture(1, accused_ledger, transfer_lock(ph))];
        let embedding = ProofEmbedding {
            ledger_id: hex::encode(accused_ledger),
            sequence: 1,
            update_hash: hex::encode([0xAA; 32]),
            field: "transfer_nonce".to_string(),
        };
        assert!(!embedding.verify_in_history(&history, &wrong));
    }

    #[test]
    fn verify_in_history_rejects_wrong_sequence() {
        let accused_ledger = [0x88u8; 32];
        let proof = proof_for(accused_ledger);
        let ph = proof.proof_hash();

        let history = vec![fixture(1, accused_ledger, delivery_embed(ph))];
        let embedding = ProofEmbedding {
            ledger_id: hex::encode(accused_ledger),
            sequence: 99, // wrong
            update_hash: hex::encode([0xAA; 32]),
            field: "delivery_request_hash".to_string(),
        };
        assert!(!embedding.verify_in_history(&history, &ph));
    }

    #[test]
    fn verify_in_history_rejects_unsupported_op() {
        // Even if some random op happens to contain bytes equal to the
        // proof_hash somewhere in its TLV, an op type not listed in
        // `embedded_hash` cannot serve as an embedding source.
        let ledger = [0x99u8; 32];
        let proof = proof_for(ledger);
        let ph = proof.proof_hash();

        let history = vec![fixture(1, ledger, LedgerOperation::DisputeYield)];
        let embedding = ProofEmbedding {
            ledger_id: hex::encode(ledger),
            sequence: 1,
            update_hash: hex::encode([0xAA; 32]),
            field: "any".to_string(),
        };
        assert!(!embedding.verify_in_history(&history, &ph));
    }

    #[test]
    fn verify_in_history_rejects_empty_history() {
        let ledger = [0xAAu8; 32];
        let proof = proof_for(ledger);
        let embedding = ProofEmbedding {
            ledger_id: hex::encode(ledger),
            sequence: 0,
            update_hash: hex::encode([0xAA; 32]),
            field: "any".to_string(),
        };
        assert!(!embedding.verify_in_history(&[], &proof.proof_hash()));
    }
}

#[test]
fn chain_hash_is_sha256_of_content_hash_and_operator_sig() {
    use deposits_protocol::types::SignedLedgerUpdate;
    use sha2::{Digest, Sha256};

    let pk = {
        use std::str::FromStr;
        bitcoin::secp256k1::PublicKey::from_str(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .unwrap()
    };

    let mut update = SignedLedgerUpdate {
        message: vec![1, 2, 3],
        message_type: 1,
        operator_id: pk,
        ledger_id: [0x12; 32],
        sequence_number: 1,
        previous_hash: [0u8; 32],
        content_hash: [0u8; 32],
        block_height: 0,
        block_hash: [0u8; 32],
        cosign_signature: [0xAA; 64],
        operator_signature: [0xBB; 64],
        cosigner_pubkey: None,
        member_ledger_hash: Some([0xCC; 32]),
        cosignatures: Vec::new(),
    };
    update.content_hash = update.compute_hash();

    // Manual chain_hash computation
    let mut hasher = Sha256::new();
    hasher.update(update.content_hash);
    hasher.update(update.operator_signature);
    let expected: [u8; 32] = hasher.finalize().into();

    assert_eq!(update.chain_hash(), expected);
}

#[cfg(test)]
mod quorum_expired_verifier {
    use super::*;
    use deposits_protocol::fraud::verify_quorum_expired;
    use deposits_protocol::messages::LedgerOperation;
    use deposits_protocol::tlv::TlvEncode;
    use deposits_protocol::types::SignedLedgerUpdate;
    use std::collections::HashMap;

    struct MockOracle(HashMap<[u8; 32], u32>);
    impl BlockOracle for MockOracle {
        fn confirms(&self, h: &[u8; 32]) -> Option<u32> {
            self.0.get(h).copied()
        }
    }

    /// Build a minimal SignedLedgerUpdate carrying a QuorumBegin at the
    /// given expiry. Other fields are zeroed since the verifier only
    /// reads the message bytes.
    fn quorum_begin_update(seq: u64, quorum_expiry: u32) -> SignedLedgerUpdate {
        let op = LedgerOperation::QuorumBegin {
            reserves_id: "rid".into(),
            spending_txid: [0; 32],
            new_outpoint_txid: [0x11; 32],
            new_outpoint_vout: 0,
            amount: 1_000_000,
            quorum_expiry,
            ledger_hash: [0; 32],
            quorum_members: vec![],
            collateral_amount: 50_000,
        };
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let sk = bitcoin::secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap();
        let operator_id = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk);
        SignedLedgerUpdate {
            message: op.tlv_encode(),
            message_type: 0,
            operator_id,
            ledger_id: [0xAA; 32],
            sequence_number: seq,
            previous_hash: [0; 32],
            content_hash: [0; 32],
            block_height: 0,
            block_hash: [0; 32],
            cosign_signature: [0; 64],
            operator_signature: [0; 64],
            cosigner_pubkey: None,
            member_ledger_hash: None,
            cosignatures: vec![],
        }
    }

    fn make_proof(anchor: [u8; 32], claimed_expiry: u32) -> FraudProof {
        FraudProof {
            proof_type: FraudProofType::QuorumExpired,
            accused: "02".to_string() + &"ab".repeat(32),
            ledger_id: hex::encode([0xAA; 32]),
            evidence: FraudEvidence::QuorumExpired {
                anchor_block_hash: anchor,
                quorum_expiry: claimed_expiry,
            },
        }
    }

    #[test]
    fn accepts_genuine_expiry() {
        // QuorumBegin recorded expiry=500; anchor confirmed at height 600.
        let history = vec![quorum_begin_update(1, 500)];
        let anchor = [0xCC; 32];
        let mut oracle_map = HashMap::new();
        oracle_map.insert(anchor, 600);
        let oracle = MockOracle(oracle_map);
        verify_quorum_expired(&make_proof(anchor, 500), &history, &oracle).unwrap();
    }

    #[test]
    fn rejects_anchor_at_expiry_block() {
        // Anchor at the expiry block itself is NOT past — that block is
        // still cosignable per the cosigner-edge rule. Need anchor > expiry.
        let history = vec![quorum_begin_update(1, 500)];
        let anchor = [0xCC; 32];
        let mut oracle_map = HashMap::new();
        oracle_map.insert(anchor, 500);
        let oracle = MockOracle(oracle_map);
        let err =
            verify_quorum_expired(&make_proof(anchor, 500), &history, &oracle).unwrap_err();
        assert!(
            err.contains("not past quorum_expiry"),
            "expected expiry guard error, got: {}",
            err
        );
    }

    #[test]
    fn rejects_anchor_before_expiry() {
        let history = vec![quorum_begin_update(1, 500)];
        let anchor = [0xCC; 32];
        let mut oracle_map = HashMap::new();
        oracle_map.insert(anchor, 400);
        let oracle = MockOracle(oracle_map);
        let err =
            verify_quorum_expired(&make_proof(anchor, 500), &history, &oracle).unwrap_err();
        assert!(err.contains("not past quorum_expiry"));
    }

    #[test]
    fn rejects_unknown_anchor() {
        let history = vec![quorum_begin_update(1, 500)];
        let anchor = [0xCC; 32];
        let oracle = MockOracle(HashMap::new()); // empty
        let err =
            verify_quorum_expired(&make_proof(anchor, 500), &history, &oracle).unwrap_err();
        assert!(err.contains("not in verifier's confirmed chain"));
    }

    #[test]
    fn rejects_mismatched_expiry() {
        // Ledger recorded expiry=500; proof claims expiry=400. The
        // verifier reads the actual expiry from history and refuses
        // the binding — without this, a forged proof could fabricate
        // any expiry.
        let history = vec![quorum_begin_update(1, 500)];
        let anchor = [0xCC; 32];
        let mut oracle_map = HashMap::new();
        oracle_map.insert(anchor, 600);
        let oracle = MockOracle(oracle_map);
        let err =
            verify_quorum_expired(&make_proof(anchor, 400), &history, &oracle).unwrap_err();
        assert!(
            err.contains("doesn't match the ledger's most"),
            "expected mismatch error, got: {}",
            err
        );
    }

    #[test]
    fn rejects_no_quorum_begin_in_history() {
        // Ledger never had a QuorumBegin (PreQuorum forever). Can't be
        // "expired."
        let history = vec![];
        let anchor = [0xCC; 32];
        let mut oracle_map = HashMap::new();
        oracle_map.insert(anchor, 600);
        let oracle = MockOracle(oracle_map);
        let err =
            verify_quorum_expired(&make_proof(anchor, 500), &history, &oracle).unwrap_err();
        assert!(err.contains("no QuorumBegin"));
    }

    #[test]
    fn uses_most_recent_quorum_begin() {
        // Two QuorumBegins: re-rotation case. The verifier should bind
        // to the most recent one (current quorum), not the earliest.
        let history = vec![
            quorum_begin_update(1, 200), // old, already expired
            quorum_begin_update(2, 500), // current
        ];
        let anchor = [0xCC; 32];
        let mut oracle_map = HashMap::new();
        oracle_map.insert(anchor, 600);
        let oracle = MockOracle(oracle_map);
        verify_quorum_expired(&make_proof(anchor, 500), &history, &oracle).unwrap();
        // And the old expiry is rejected (matches a stale QuorumBegin):
        let err =
            verify_quorum_expired(&make_proof(anchor, 200), &history, &oracle).unwrap_err();
        assert!(err.contains("doesn't match the ledger's most"));
    }
}

#[cfg(test)]
mod winner_collateral_deviation_tests {
    use super::*;
    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Witness};
    use deposits_protocol::messages::{LedgerOperation, ReplacementCollateral};
    use deposits_protocol::tlv::TlvEncode;
    use deposits_protocol::types::SignedLedgerUpdate;
    use std::collections::HashMap;

    struct MockOracle(HashMap<[u8; 32], u32>);
    impl BlockOracle for MockOracle {
        fn confirms(&self, h: &[u8; 32]) -> Option<u32> {
            self.0.get(h).copied()
        }
    }

    fn winner_keypair() -> (Keypair, bitcoin::secp256k1::PublicKey) {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x77; 32]).unwrap();
        let kp = Keypair::from_secret_key(&secp, &sk);
        let pk = bitcoin::secp256k1::PublicKey::from_keypair(&kp);
        (kp, pk)
    }

    /// Build a `DisputeArmed` SignedLedgerUpdate with the given declaration,
    /// signed by the winner. Returns `(hex_bytes, target_script)`.
    fn make_armed_update(
        rc: Option<ReplacementCollateral>,
        target_address: &str,
    ) -> (String, ScriptBuf) {
        let (_kp, pk) = winner_keypair();
        let op = LedgerOperation::DisputeArmed {
            armed_block: 800_100,
            commitment_hash: [0xAB; 20],
            target_reserves: target_address.into(),
            replacement_collateral: rc,
        };
        let message = op.tlv_encode();
        let update = SignedLedgerUpdate {
            message,
            message_type: 9, // LEDGER_UPDATE
            operator_id: pk,
            ledger_id: [0xAA; 32],
            sequence_number: 5,
            previous_hash: [0; 32],
            content_hash: [0; 32],
            block_height: 800_000,
            block_hash: [0xBB; 32],
            cosign_signature: [0; 64],
            operator_signature: [0; 64],
            cosigner_pubkey: None,
            member_ledger_hash: None,
            cosignatures: vec![],
        };
        // The fraud verifier doesn't check this signature — it relies on
        // the fact that the proof itself was published, and on cross-ledger
        // attribution at broadcast verification time. Manual TLV here is
        // sufficient for the deviation evidence path.
        let bytes = update.tlv_encode();
        let script = bitcoin::Address::from_str(target_address)
            .unwrap()
            .assume_checked()
            .script_pubkey();
        (hex::encode(&bytes), script)
    }

    fn make_claim_tx(
        lottery_outpoint: OutPoint,
        lottery_amount: u64,
        rc_input: Option<(OutPoint, u64)>,
        out_script: ScriptBuf,
        out_amount: u64,
    ) -> bitcoin::Transaction {
        let mut input = vec![TxIn {
            previous_output: lottery_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }];
        if let Some((rc_outpoint, _amount)) = rc_input {
            input.push(TxIn {
                previous_output: rc_outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            });
        }
        let _ = lottery_amount;
        bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input,
            output: vec![TxOut {
                value: Amount::from_sat(out_amount),
                script_pubkey: out_script,
            }],
        }
    }

    fn make_proof(armed_hex: String, claim_txid: String, anchor: [u8; 32]) -> FraudProof {
        FraudProof {
            proof_type: FraudProofType::WinnerCollateralDeviation,
            accused: make_accused(),
            ledger_id: make_ledger_id(),
            evidence: FraudEvidence::WinnerCollateralDeviation {
                winner_armed_update_hex: armed_hex,
                claim_txid,
                claim_block_hash: anchor,
            },
        }
    }

    use std::str::FromStr;

    const REGTEST_TARGET: &str =
        "bcrt1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qzf4jry";

    #[test]
    fn winner_did_not_deviate_returns_err() {
        let (armed_hex, target_script) = make_armed_update(
            Some(ReplacementCollateral {
                txid: [0x11; 32],
                vout: 3,
                amount: 30_000,
            }),
            REGTEST_TARGET,
        );
        let lottery_outpoint = OutPoint::new(
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([0x22; 32])),
            0,
        );
        let lottery_amount = 100_000;
        let rc_outpoint = OutPoint::new(
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([0x11; 32])),
            3,
        );
        let claim_tx = make_claim_tx(
            lottery_outpoint,
            lottery_amount,
            Some((rc_outpoint, 30_000)),
            target_script,
            // lottery + declared - small fee, well above 10_000 budget floor
            lottery_amount + 30_000 - 1_200,
        );
        let claim_txid = claim_tx.compute_txid().to_string();
        let anchor = [0xCC; 32];
        let mut oracle_map = HashMap::new();
        oracle_map.insert(anchor, 800_500);
        let oracle = MockOracle(oracle_map);
        let proof = make_proof(armed_hex, claim_txid, anchor);
        let err = verify_winner_collateral_deviation(&proof, &claim_tx, lottery_amount, &oracle)
            .unwrap_err();
        assert!(err.contains("matches the declared"), "got: {}", err);
    }

    #[test]
    fn winner_skipped_declared_input_proves_deviation() {
        let (armed_hex, target_script) = make_armed_update(
            Some(ReplacementCollateral {
                txid: [0x11; 32],
                vout: 3,
                amount: 30_000,
            }),
            REGTEST_TARGET,
        );
        let lottery_outpoint = OutPoint::new(
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([0x22; 32])),
            0,
        );
        let lottery_amount = 100_000;
        // Single-input claim TX — declared collateral skipped.
        let claim_tx = make_claim_tx(
            lottery_outpoint,
            lottery_amount,
            None,
            target_script,
            lottery_amount - 400,
        );
        let claim_txid = claim_tx.compute_txid().to_string();
        let anchor = [0xCC; 32];
        let mut oracle_map = HashMap::new();
        oracle_map.insert(anchor, 800_500);
        let oracle = MockOracle(oracle_map);
        let proof = make_proof(armed_hex, claim_txid, anchor);
        verify_winner_collateral_deviation(&proof, &claim_tx, lottery_amount, &oracle).unwrap();
    }

    #[test]
    fn winner_used_different_outpoint_proves_deviation() {
        let (armed_hex, target_script) = make_armed_update(
            Some(ReplacementCollateral {
                txid: [0x11; 32],
                vout: 3,
                amount: 30_000,
            }),
            REGTEST_TARGET,
        );
        let lottery_outpoint = OutPoint::new(
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([0x22; 32])),
            0,
        );
        // Different outpoint than declared — deviation.
        let wrong_outpoint = OutPoint::new(
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([0x99; 32])),
            7,
        );
        let lottery_amount = 100_000;
        let claim_tx = make_claim_tx(
            lottery_outpoint,
            lottery_amount,
            Some((wrong_outpoint, 30_000)),
            target_script,
            lottery_amount + 30_000 - 1_200,
        );
        let claim_txid = claim_tx.compute_txid().to_string();
        let anchor = [0xCC; 32];
        let mut oracle_map = HashMap::new();
        oracle_map.insert(anchor, 800_500);
        let oracle = MockOracle(oracle_map);
        let proof = make_proof(armed_hex, claim_txid, anchor);
        verify_winner_collateral_deviation(&proof, &claim_tx, lottery_amount, &oracle).unwrap();
    }

    #[test]
    fn winner_routed_value_away_proves_deviation() {
        let (armed_hex, target_script) = make_armed_update(
            Some(ReplacementCollateral {
                txid: [0x11; 32],
                vout: 3,
                amount: 30_000,
            }),
            REGTEST_TARGET,
        );
        let lottery_outpoint = OutPoint::new(
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([0x22; 32])),
            0,
        );
        let rc_outpoint = OutPoint::new(
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([0x11; 32])),
            3,
        );
        let lottery_amount = 100_000;
        // Output is materially short — value siphoned to change.
        let claim_tx = make_claim_tx(
            lottery_outpoint,
            lottery_amount,
            Some((rc_outpoint, 30_000)),
            target_script,
            // Way short of expected lottery + declared - fee.
            50_000,
        );
        let claim_txid = claim_tx.compute_txid().to_string();
        let anchor = [0xCC; 32];
        let mut oracle_map = HashMap::new();
        oracle_map.insert(anchor, 800_500);
        let oracle = MockOracle(oracle_map);
        let proof = make_proof(armed_hex, claim_txid, anchor);
        verify_winner_collateral_deviation(&proof, &claim_tx, lottery_amount, &oracle).unwrap();
    }

    #[test]
    fn unconfirmed_anchor_block_rejects_proof() {
        let (armed_hex, _target_script) = make_armed_update(
            Some(ReplacementCollateral {
                txid: [0x11; 32],
                vout: 3,
                amount: 30_000,
            }),
            REGTEST_TARGET,
        );
        let lottery_outpoint = OutPoint::new(
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([0x22; 32])),
            0,
        );
        let lottery_amount = 100_000;
        let claim_tx = make_claim_tx(
            lottery_outpoint,
            lottery_amount,
            None,
            ScriptBuf::new(),
            10_000,
        );
        let claim_txid = claim_tx.compute_txid().to_string();
        // Oracle doesn't know about the anchor — verifier rejects.
        let anchor = [0xCC; 32];
        let oracle = MockOracle(HashMap::new());
        let proof = make_proof(armed_hex, claim_txid, anchor);
        let err = verify_winner_collateral_deviation(&proof, &claim_tx, lottery_amount, &oracle)
            .unwrap_err();
        assert!(err.contains("not in verifier's confirmed chain"), "got: {}", err);
    }

    #[test]
    fn no_declaration_means_nothing_to_deviate_from() {
        let (armed_hex, target_script) = make_armed_update(None, REGTEST_TARGET);
        let lottery_outpoint = OutPoint::new(
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([0x22; 32])),
            0,
        );
        let lottery_amount = 100_000;
        let claim_tx = make_claim_tx(
            lottery_outpoint,
            lottery_amount,
            None,
            target_script,
            lottery_amount - 400,
        );
        let claim_txid = claim_tx.compute_txid().to_string();
        let anchor = [0xCC; 32];
        let mut oracle_map = HashMap::new();
        oracle_map.insert(anchor, 800_500);
        let oracle = MockOracle(oracle_map);
        let proof = make_proof(armed_hex, claim_txid, anchor);
        let err = verify_winner_collateral_deviation(&proof, &claim_tx, lottery_amount, &oracle)
            .unwrap_err();
        assert!(err.contains("nothing for the claim TX to deviate from"), "got: {}", err);
    }
}
