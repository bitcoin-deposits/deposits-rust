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
            cosigner_pubkey: "02".to_string() + &"cc".repeat(32),
            cosign_signature: "dd".repeat(32),
            txid: "ee".repeat(32),
            amount_sats: 100_000,
            confirmed_at_block: 500,
            required_confirmations: 6,
            proof_sequence: 42,
            proof_block_height: 510,
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
            cosigner_pubkey: "02".to_string() + &"cc".repeat(32),
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
        proof_type: FraudProofType::InactiveQuorumMember,
        accused: make_accused(),
        ledger_id: make_ledger_id(),
        evidence: FraudEvidence::InactiveQuorum {
            original_fraud_hash: "66".repeat(32),
            evidence_available_at_block: 1000,
            required_response_blocks: 144,
            member_active_sequence: 200,
            member_active_block: 1200,
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
        FraudProofType::InactiveQuorumMember,
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
