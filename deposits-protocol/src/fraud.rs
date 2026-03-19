//! Fraud proof construction and verification.
//!
//! A fraud proof demonstrates that an operator or quorum member has acted
//! dishonestly. The proof is hashed and embedded into a ledger chain as
//! wallet-controlled data (e.g., a transfer nonce). Once the operator signs
//! an update containing the hash, the evidence is causally ordered. The full
//! proof is then broadcast as a Nostr event, and anyone can verify the hash
//! was in the chain before the reveal.
//!
//! Embedding targets (in order of preference):
//! - Direct: transfer nonce on the operator's own ledger
//! - One hop: on a quorum member's ledger, entangled at next co-signature
//! - Further: any ledger in the web, wait for causal propagation

use bitcoin::hashes::{sha256, Hash};
use serde::{Serialize, Deserialize};

/// A fraud proof that can be hashed, embedded, and later revealed.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FraudProof {
    /// Type of fraud being proven.
    pub proof_type: FraudProofType,
    /// The operator or member being accused.
    pub accused: String, // 66-char hex pubkey
    /// The ledger where the fraud occurred.
    pub ledger_id: String, // 64-char hex
    /// Evidence specific to the proof type.
    pub evidence: FraudEvidence,
    /// Where the proof hash was embedded in the chain.
    pub embedding: Option<ProofEmbedding>,
}

/// The type of fraud being proven.
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
    /// initiate a dispute within the required block window after evidence
    /// of fraud was available.
    InactiveQuorumMember,
    /// The operator signed a ledger update that violates protocol rules
    /// (e.g., spending more than balance, invalid fee, double-spend).
    NonConformingUpdate,
}

/// Evidence specific to each proof type.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FraudEvidence {
    /// Evidence for uncredited on-chain payment.
    UncreditedOnchain {
        /// The cosigned offer (operator committed to credit on-chain funds).
        offer_id: String,
        funding_address: String,
        cosigner_pubkey: String,
        cosign_signature: String,
        /// The on-chain transaction proving funds were sent.
        txid: String,
        /// The amount sent (sats).
        amount_sats: u64,
        /// Block height at which the tx was confirmed.
        confirmed_at_block: u32,
        /// Number of confirmations required before credit.
        required_confirmations: u32,
        /// Sequence number of a signed update on the operator's ledger
        /// whose block_height exceeds confirmed_at_block + required_confirmations,
        /// proving the operator saw sufficient confirmations.
        proof_sequence: u64,
        proof_block_height: u32,
    },

    /// Evidence for uncredited lightning payment.
    UncreditedLightning {
        /// The cosigned invoice.
        invoice: String,
        payment_hash: String,
        cosigner_pubkey: String,
        cosign_signature: String,
        /// The preimage proving payment was received.
        preimage: String,
        /// Sequence number of a signed update after the preimage was known
        /// (proved via causal chain — the preimage hash was embedded before
        /// this update, and the operator signed after).
        proof_sequence: u64,
    },

    /// Evidence for stale co-signature.
    StaleCosign {
        /// The update with the stale co-signature.
        stale_update_sequence: u64,
        stale_update_hash: String,
        /// The member_ledger_hash declared in the co-signature.
        declared_member_hash: String,
        /// A later update on the member's own ledger that proves the
        /// declared hash is stale (this update's previous_hash chains
        /// to a point AFTER the declared hash).
        member_later_sequence: u64,
        member_later_hash: String,
        /// The member's ledger ID.
        member_ledger_id: String,
    },

    /// Evidence for inactive quorum member.
    InactiveQuorum {
        /// The fraud evidence that was available.
        original_fraud_hash: String,
        /// Block height when evidence was embedded in the chain.
        evidence_available_at_block: u32,
        /// Required response window (blocks).
        required_response_blocks: u32,
        /// The member's ledger showing activity after the window
        /// (proving they were online but didn't act).
        member_active_sequence: u64,
        member_active_block: u32,
        /// The member's pubkey.
        member_pubkey: String,
    },

    /// Evidence for non-conforming update.
    NonConforming {
        /// The sequence number of the non-conforming update.
        sequence: u64,
        /// The full TLV-encoded update (base64).
        update_b64: String,
        /// Description of the violation.
        violation: String,
    },
}

/// Where the proof hash was embedded in the chain.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofEmbedding {
    /// Which ledger the hash was embedded in.
    pub ledger_id: String,
    /// The sequence number of the update containing the hash.
    pub sequence: u64,
    /// Which field contains the hash (e.g., "transfer_nonce").
    pub field: String,
    /// The hash that was embedded (SHA256 of the serialized proof).
    pub proof_hash: String,
}

/// A causal chain link showing how the embedding connects to the target.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CausalLink {
    /// Ledger ID.
    pub ledger_id: String,
    /// Sequence number.
    pub sequence: u64,
    /// The current_hash of this update.
    pub hash: String,
    /// If this is a co-signed update, the member_ledger_hash it includes.
    pub member_ledger_hash: Option<String>,
    /// The cosigner's ledger ID (if co-signed).
    pub cosigner_ledger_id: Option<String>,
}

impl FraudProof {
    /// Compute the hash of this proof for embedding in a ledger chain.
    ///
    /// Uses BIP-340 tagged hashing for domain separation:
    /// `SHA256(SHA256("deposits/fraud_proof") || SHA256("deposits/fraud_proof") || type || accused || ledger_id || evidence_discriminant)`
    ///
    /// This hash is used as the transfer nonce (or other wallet-controlled
    /// 32-byte field) when creating a transaction on a ledger.
    pub fn proof_hash(&self) -> [u8; 32] {
        let tag = b"deposits/fraud_proof";
        let tag_hash = sha256::Hash::hash(tag);

        let mut input = Vec::new();
        input.extend_from_slice(tag_hash.as_byte_array());
        input.extend_from_slice(tag_hash.as_byte_array());
        // Include proof type discriminant
        input.push(self.proof_type.discriminant());
        // Include accused pubkey bytes
        input.extend_from_slice(self.accused.as_bytes());
        // Include ledger ID
        input.extend_from_slice(self.ledger_id.as_bytes());
        // Include evidence-specific data
        input.extend_from_slice(&self.evidence.canonical_bytes());

        sha256::Hash::hash(&input).to_byte_array()
    }

    /// Verify that a given 32-byte value matches this proof's hash.
    pub fn verify_embedding(&self, embedded_hash: &[u8; 32]) -> bool {
        &self.proof_hash() == embedded_hash
    }
}

impl FraudProofType {
    /// Discriminant byte for hashing.
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
    /// Canonical byte representation for hashing.
    /// Includes the key fields that uniquely identify this evidence.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Self::UncreditedOnchain { offer_id, txid, amount_sats, confirmed_at_block, .. } => {
                out.extend_from_slice(offer_id.as_bytes());
                out.extend_from_slice(txid.as_bytes());
                out.extend_from_slice(&amount_sats.to_le_bytes());
                out.extend_from_slice(&confirmed_at_block.to_le_bytes());
            }
            Self::UncreditedLightning { payment_hash, preimage, .. } => {
                out.extend_from_slice(payment_hash.as_bytes());
                out.extend_from_slice(preimage.as_bytes());
            }
            Self::StaleCosign { stale_update_hash, declared_member_hash, member_later_hash, .. } => {
                out.extend_from_slice(stale_update_hash.as_bytes());
                out.extend_from_slice(declared_member_hash.as_bytes());
                out.extend_from_slice(member_later_hash.as_bytes());
            }
            Self::InactiveQuorum { original_fraud_hash, member_pubkey, evidence_available_at_block, .. } => {
                out.extend_from_slice(original_fraud_hash.as_bytes());
                out.extend_from_slice(member_pubkey.as_bytes());
                out.extend_from_slice(&evidence_available_at_block.to_le_bytes());
            }
            Self::NonConforming { sequence, update_b64, violation, .. } => {
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
