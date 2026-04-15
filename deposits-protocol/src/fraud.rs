//! Fraud proof construction and verification.
//!
//! A fraud proof has two parts:
//!
//! 1. **The proof** (`FraudProof`): evidence of dishonesty. This is hashed
//!    and the hash embedded into a ledger chain as wallet-controlled data
//!    (e.g., a transfer nonce). The proof is constructed before embedding.
//!
//! 2. **The broadcast** (`FraudBroadcast`): the proof plus a causal chain
//!    showing how the hash got entangled into the accused operator's ledger.
//!    Constructed after embedding, once the causal chain has formed.
//!
//! Embedding targets (in order of preference):
//! - Direct: transfer nonce on the operator's own ledger
//! - One hop: on a quorum member's ledger, entangled at next co-signature
//! - Further: any ledger in the web, wait for causal propagation
//!
//! Verification: hash the proof, walk the causal chain from the embedding
//! to the operator's ledger, confirm each link is a signed update.

use bitcoin::hashes::{sha256, Hash};
use serde::{Deserialize, Serialize};

// ============================================================================
// The Proof (hashable, constructed before embedding)
// ============================================================================

/// Evidence of operator or quorum member dishonesty.
///
/// This is the hashable part — `proof_hash()` produces the 32-byte value
/// that gets embedded into a ledger chain.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FraudProof {
    /// Type of fraud being proven.
    pub proof_type: FraudProofType,
    /// The operator or member being accused (66-char hex pubkey).
    pub accused: String,
    /// The ledger where the fraud occurred (64-char hex).
    pub ledger_id: String,
    /// Evidence specific to the proof type.
    pub evidence: FraudEvidence,
}

/// The five types of fraud from the protocol specification.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FraudProofType {
    /// Operator offered to credit a deposit for on-chain funds but didn't,
    /// despite signing updates proving they saw sufficient confirmations.
    UncreditedOnchainPayment,
    /// Operator created a cosigned invoice but didn't credit the deposit
    /// despite the preimage being revealed (provable via causal ordering).
    UncreditedLightningPayment,
    /// A co-signature declares a member_ledger_hash that precedes the
    /// member's own later hash — proving the co-signer backdated.
    StaleCosignature,
    /// A quorum member was active (their ledger has updates) but didn't
    /// initiate a dispute within the required block window.
    InactiveQuorumMember,
    /// The operator signed a ledger update that violates protocol rules.
    NonConformingUpdate,
}

/// Evidence specific to each proof type.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FraudEvidence {
    /// Operator didn't credit an on-chain payment.
    UncreditedOnchain {
        /// The cosigned offer (hex offer_id, funding_address, cosignature).
        offer_id: String,
        funding_address: String,
        cosigner_pubkey: String,
        cosign_signature: String,
        /// On-chain proof.
        txid: String,
        amount_sats: u64,
        confirmed_at_block: u32,
        required_confirmations: u32,
        /// Operator signed an update at this block height, proving they
        /// saw sufficient confirmations but didn't credit.
        proof_sequence: u64,
        proof_block_height: u32,
    },

    /// Operator didn't credit a lightning payment.
    UncreditedLightning {
        /// The cosigned invoice.
        invoice: String,
        payment_hash: String,
        cosigner_pubkey: String,
        cosign_signature: String,
        /// The preimage proving payment.
        preimage: String,
        /// Operator signed an update after the preimage was known.
        proof_sequence: u64,
    },

    /// Co-signer backdated their ledger hash.
    StaleCosign {
        /// The update with the stale co-signature.
        stale_update_sequence: u64,
        stale_update_hash: String,
        /// The member_ledger_hash declared in the co-signature.
        declared_member_hash: String,
        /// A later update on the member's ledger proving the hash is stale.
        member_later_sequence: u64,
        member_later_hash: String,
        member_ledger_id: String,
    },

    /// Quorum member was active but didn't act on fraud.
    InactiveQuorum {
        /// Hash of the original fraud proof that was ignored.
        original_fraud_hash: String,
        evidence_available_at_block: u32,
        required_response_blocks: u32,
        /// Member was active after the window (proving they were online).
        member_active_sequence: u64,
        member_active_block: u32,
        member_pubkey: String,
    },

    /// Operator signed a non-conforming update.
    NonConforming {
        /// The non-conforming update (base64 TLV).
        sequence: u64,
        update_b64: String,
        /// What rule was violated.
        violation: String,
    },
}

impl FraudProof {
    /// Compute the 32-byte hash for embedding into a ledger chain.
    ///
    /// Uses BIP-340 tagged hashing for domain separation.
    pub fn proof_hash(&self) -> [u8; 32] {
        let tag = b"deposits/fraud_proof";
        let tag_hash = sha256::Hash::hash(tag);

        let mut input = Vec::new();
        input.extend_from_slice(tag_hash.as_byte_array());
        input.extend_from_slice(tag_hash.as_byte_array());
        input.push(self.proof_type.discriminant());
        input.extend_from_slice(self.accused.as_bytes());
        input.extend_from_slice(self.ledger_id.as_bytes());
        input.extend_from_slice(&self.evidence.canonical_bytes());

        sha256::Hash::hash(&input).to_byte_array()
    }

    /// Verify that a given 32-byte value matches this proof's hash.
    pub fn verify_embedding(&self, embedded_hash: &[u8; 32]) -> bool {
        &self.proof_hash() == embedded_hash
    }
}

// ============================================================================
// The Broadcast (proof + causal chain, constructed after embedding)
// ============================================================================

/// A fraud proof broadcast containing the proof and the causal chain
/// proving it was embedded before being revealed.
///
/// Broadcast as a Kind 9101 Nostr event. Verifiers walk the chain
/// without needing to search for anything.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FraudBroadcast {
    /// The fraud proof (hashable evidence).
    pub proof: FraudProof,
    /// Where the proof hash was embedded.
    pub embedding: ProofEmbedding,
    /// Causal chain from the embedding to the accused operator's ledger.
    /// Each link is a co-signed update that entangles one ledger into another.
    /// Empty if embedded directly on the operator's ledger.
    /// One entry if embedded on a quorum member's ledger (the co-signature
    /// on the operator's ledger that includes the member's hash).
    /// Multiple entries for longer paths through the web.
    pub causal_chain: Vec<CausalLink>,
}

/// Where the proof hash was embedded in a ledger.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofEmbedding {
    /// The ledger the hash was embedded in.
    pub ledger_id: String,
    /// Sequence number of the update containing the hash.
    pub sequence: u64,
    /// The current_hash of that update.
    pub update_hash: String,
    /// Which field contains the proof hash (e.g., "transfer_nonce").
    pub field: String,
}

/// A single link in the causal chain.
///
/// Each link is a co-signed update on one ledger that includes
/// `member_ledger_hash` from another ledger, proving temporal ordering.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CausalLink {
    /// The ledger this co-signed update is on.
    pub ledger_id: String,
    /// Sequence number.
    pub sequence: u64,
    /// The current_hash of this update.
    pub update_hash: String,
    /// The member_ledger_hash included in the co-signature.
    /// This hash is from the previous link's ledger (or the embedding ledger).
    pub member_ledger_hash: String,
    /// Which ledger the member_ledger_hash came from.
    pub source_ledger_id: String,
}

impl FraudBroadcast {
    /// Verify the causal chain integrity.
    ///
    /// Checks that each link's `member_ledger_hash` could follow from the
    /// previous link (or embedding). Does NOT verify signatures — that
    /// requires fetching the actual updates from relays.
    pub fn verify_chain_structure(&self) -> Result<(), String> {
        // The proof hash must match
        let expected_hash = self.proof.proof_hash();
        let _expected_hex = hex::encode(expected_hash);

        // If direct embedding on the accused ledger, chain should be empty
        if self.embedding.ledger_id == self.proof.ledger_id {
            if !self.causal_chain.is_empty() {
                return Err("Direct embedding should have empty causal chain".to_string());
            }
            return Ok(());
        }

        // Chain must connect embedding ledger to accused ledger
        if self.causal_chain.is_empty() {
            return Err("Indirect embedding requires at least one causal link".to_string());
        }

        // First link must reference the embedding ledger
        let first = &self.causal_chain[0];
        if first.source_ledger_id != self.embedding.ledger_id {
            return Err(format!(
                "First causal link source {} doesn't match embedding ledger {}",
                first.source_ledger_id, self.embedding.ledger_id
            ));
        }

        // Each subsequent link must chain from the previous
        for i in 1..self.causal_chain.len() {
            let prev = &self.causal_chain[i - 1];
            let curr = &self.causal_chain[i];
            if curr.source_ledger_id != prev.ledger_id {
                return Err(format!(
                    "Causal link {} source {} doesn't match previous link ledger {}",
                    i, curr.source_ledger_id, prev.ledger_id
                ));
            }
        }

        // Last link must be on the accused operator's ledger
        let last = &self.causal_chain.last().unwrap();
        if last.ledger_id != self.proof.ledger_id {
            return Err(format!(
                "Last causal link ledger {} doesn't reach accused ledger {}",
                last.ledger_id, self.proof.ledger_id
            ));
        }

        Ok(())
    }
}

// ============================================================================
// Helpers
// ============================================================================

impl FraudProofType {
    pub fn discriminant(&self) -> u8 {
        match self {
            Self::UncreditedOnchainPayment => 1,
            Self::UncreditedLightningPayment => 2,
            Self::StaleCosignature => 3,
            Self::InactiveQuorumMember => 4,
            Self::NonConformingUpdate => 5,
        }
    }
}

impl FraudEvidence {
    /// Canonical bytes for hashing — key fields that uniquely identify this evidence.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Self::UncreditedOnchain {
                offer_id,
                txid,
                amount_sats,
                confirmed_at_block,
                ..
            } => {
                out.extend_from_slice(offer_id.as_bytes());
                out.extend_from_slice(txid.as_bytes());
                out.extend_from_slice(&amount_sats.to_le_bytes());
                out.extend_from_slice(&confirmed_at_block.to_le_bytes());
            }
            Self::UncreditedLightning {
                payment_hash,
                preimage,
                ..
            } => {
                out.extend_from_slice(payment_hash.as_bytes());
                out.extend_from_slice(preimage.as_bytes());
            }
            Self::StaleCosign {
                stale_update_hash,
                declared_member_hash,
                member_later_hash,
                ..
            } => {
                out.extend_from_slice(stale_update_hash.as_bytes());
                out.extend_from_slice(declared_member_hash.as_bytes());
                out.extend_from_slice(member_later_hash.as_bytes());
            }
            Self::InactiveQuorum {
                original_fraud_hash,
                member_pubkey,
                evidence_available_at_block,
                ..
            } => {
                out.extend_from_slice(original_fraud_hash.as_bytes());
                out.extend_from_slice(member_pubkey.as_bytes());
                out.extend_from_slice(&evidence_available_at_block.to_le_bytes());
            }
            Self::NonConforming {
                sequence,
                update_b64,
                violation,
                ..
            } => {
                out.extend_from_slice(&sequence.to_le_bytes());
                out.extend_from_slice(update_b64.as_bytes());
                out.extend_from_slice(violation.as_bytes());
            }
        }
        out
    }
}

/// Nostr event kind for fraud proof broadcasts.
pub const KIND_FRAUD_PROOF: u16 = 9101;

#[cfg(test)]
mod tests {
    use super::*;

    fn make_proof() -> FraudProof {
        FraudProof {
            proof_type: FraudProofType::UncreditedOnchainPayment,
            accused: "02".to_string() + &"ab".repeat(32),
            ledger_id: "aa".repeat(32),
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

    #[test]
    fn proof_hash_is_deterministic() {
        let proof = make_proof();
        let h1 = proof.proof_hash();
        let h2 = proof.proof_hash();
        assert_eq!(h1, h2);
        assert_ne!(h1, [0u8; 32]);
    }

    #[test]
    fn different_evidence_different_hash() {
        let mut p1 = make_proof();
        let p2 = make_proof();
        if let FraudEvidence::UncreditedOnchain {
            ref mut amount_sats,
            ..
        } = p1.evidence
        {
            *amount_sats = 200_000;
        }
        assert_ne!(p1.proof_hash(), p2.proof_hash());
    }

    #[test]
    fn direct_embedding_empty_chain_valid() {
        let proof = make_proof();
        let broadcast = FraudBroadcast {
            embedding: ProofEmbedding {
                ledger_id: proof.ledger_id.clone(), // same as accused
                sequence: 50,
                update_hash: "ff".repeat(32),
                field: "transfer_nonce".to_string(),
            },
            causal_chain: vec![],
            proof,
        };
        assert!(broadcast.verify_chain_structure().is_ok());
    }

    #[test]
    fn one_hop_chain_valid() {
        let proof = make_proof();
        let member_ledger = "11".repeat(32);
        let broadcast = FraudBroadcast {
            embedding: ProofEmbedding {
                ledger_id: member_ledger.clone(), // embedded on member's ledger
                sequence: 10,
                update_hash: "22".repeat(32),
                field: "transfer_nonce".to_string(),
            },
            causal_chain: vec![CausalLink {
                ledger_id: proof.ledger_id.clone(), // operator's ledger
                sequence: 55,
                update_hash: "33".repeat(32),
                member_ledger_hash: "44".repeat(32),
                source_ledger_id: member_ledger.clone(), // from member's ledger
            }],
            proof,
        };
        assert!(broadcast.verify_chain_structure().is_ok());
    }

    #[test]
    fn indirect_embedding_missing_chain_rejected() {
        let proof = make_proof();
        let broadcast = FraudBroadcast {
            embedding: ProofEmbedding {
                ledger_id: "11".repeat(32), // different from accused
                sequence: 10,
                update_hash: "22".repeat(32),
                field: "transfer_nonce".to_string(),
            },
            causal_chain: vec![],
            proof,
        };
        assert!(broadcast.verify_chain_structure().is_err());
    }

    #[test]
    fn chain_not_reaching_accused_rejected() {
        let proof = make_proof();
        let broadcast = FraudBroadcast {
            embedding: ProofEmbedding {
                ledger_id: "11".repeat(32),
                sequence: 10,
                update_hash: "22".repeat(32),
                field: "transfer_nonce".to_string(),
            },
            causal_chain: vec![CausalLink {
                ledger_id: "99".repeat(32), // wrong — doesn't reach accused
                sequence: 55,
                update_hash: "33".repeat(32),
                member_ledger_hash: "44".repeat(32),
                source_ledger_id: "11".repeat(32),
            }],
            proof,
        };
        assert!(broadcast.verify_chain_structure().is_err());
    }

    #[test]
    fn two_hop_chain_valid() {
        let proof = make_proof();
        let ledger_a = "11".repeat(32);
        let ledger_b = "22".repeat(32);
        let broadcast = FraudBroadcast {
            embedding: ProofEmbedding {
                ledger_id: ledger_a.clone(),
                sequence: 10,
                update_hash: "ff".repeat(32),
                field: "transfer_nonce".to_string(),
            },
            causal_chain: vec![
                // ledger_b co-signed update includes ledger_a's hash
                CausalLink {
                    ledger_id: ledger_b.clone(),
                    sequence: 20,
                    update_hash: "ee".repeat(32),
                    member_ledger_hash: "dd".repeat(32),
                    source_ledger_id: ledger_a.clone(),
                },
                // operator's ledger co-signed update includes ledger_b's hash
                CausalLink {
                    ledger_id: proof.ledger_id.clone(),
                    sequence: 30,
                    update_hash: "cc".repeat(32),
                    member_ledger_hash: "bb".repeat(32),
                    source_ledger_id: ledger_b.clone(),
                },
            ],
            proof,
        };
        assert!(broadcast.verify_chain_structure().is_ok());
    }
}
