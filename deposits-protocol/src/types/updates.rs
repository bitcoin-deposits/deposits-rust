// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Signed ledger updates, audit types, and TLV encoding implementations.

use bitcoin::secp256k1::PublicKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::core::*;
use super::serde_helpers::*;

use crate::tlv::{TlvBuilder, TlvDecode, TlvEncode, TlvReader, TlvResult};

// ============================================================================
// Signed Ledger Update
// ============================================================================

/// A single cosignature entry from a quorum member.
/// Each entry binds the member's signature to the update content and their own ledger tip.
/// Entries are stored sorted by cosigner_pubkey for deterministic hashing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CosignEntry {
    /// The quorum member who co-signed.
    #[serde(with = "serde_pubkey")]
    pub cosigner_pubkey: PublicKey,
    /// Schnorr signature over SHA256(tag||tag||cosign_data||member_ledger_hash).
    #[serde(with = "serde_64")]
    pub cosign_signature: [u8; 64],
    /// Hash of the cosigner's own ledger at time of signing (causal ordering).
    #[serde(with = "serde_32")]
    pub member_ledger_hash: [u8; 32],
}

/// A signed update to the ledger state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedLedgerUpdate {
    /// The ledger operation (serialized DepositsMessage).
    pub message: Vec<u8>,
    /// Type of the message (for quick filtering without deserializing).
    pub message_type: u16,
    /// Operator's public key (for signature verification).
    #[serde(with = "serde_pubkey")]
    pub operator_id: PublicKey,
    /// Unique ledger identifier: SHA256(genesis_operator || reserves_id || genesis_block).
    #[serde(with = "serde_32")]
    pub ledger_id: [u8; 32],
    /// Deterministic sequence number (starts at 0 for LedgerOpened).
    pub sequence_number: u64,
    /// Hash of previous ledger state (creates cryptographic chain).
    #[serde(with = "serde_32")]
    pub previous_hash: [u8; 32],
    /// Hash of current ledger state after this update.
    #[serde(with = "serde_32")]
    pub content_hash: [u8; 32],
    /// Block height when this update was created.
    #[serde(default)]
    pub block_height: u32,
    /// Block hash at the time this update was created.
    #[serde(default, with = "serde_32")]
    pub block_hash: [u8; 32],
    /// Co-signer's signature over update content.
    #[serde(with = "serde_64")]
    pub cosign_signature: [u8; 64],
    /// Operator's final signature covering co-signer's signature.
    #[serde(with = "serde_64")]
    pub operator_signature: [u8; 64],
    /// Public key of the quorum member who co-signed this update (if co-signed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cosigner_pubkey: Option<PublicKey>,
    /// Current hash of the cosigner's own ledger at time of co-signing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_ledger_hash: Option<[u8; 32]>,
    /// Majority cosignatures (post-QuorumBegin). Sorted by cosigner_pubkey.
    /// When non-empty, the deprecated single-cosig fields above are ignored.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cosignatures: Vec<CosignEntry>,
}

impl SignedLedgerUpdate {
    /// Return cosignature entries sorted by cosigner_pubkey, for use anywhere
    /// a byte-canonical view is required (hashing, signing, wire encoding).
    ///
    /// The hash and signing paths must always iterate this view — never
    /// `&self.cosignatures` directly — otherwise a writer that leaves the
    /// Vec unsorted produces a different-but-otherwise-valid content_hash
    /// for the same logical content. That's signature malleability.
    fn sorted_cosignatures(&self) -> Vec<&CosignEntry> {
        let mut refs: Vec<&CosignEntry> = self.cosignatures.iter().collect();
        refs.sort_by(|a, b| {
            a.cosigner_pubkey
                .serialize()
                .cmp(&b.cosigner_pubkey.serialize())
        });
        refs
    }

    /// Compute content_hash: commits to content, causal ordering, and co-signatures.
    ///
    /// Multi-cosig format (cosignatures non-empty):
    ///   `SHA256(seq || prev_hash || message || for each sorted entry: member_hash || cosig)`
    ///
    /// Legacy single-cosig format (cosignatures empty):
    ///   `SHA256(seq || prev_hash || message [|| member_hash] [|| cosig])`
    pub fn compute_hash(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(self.sequence_number.to_le_bytes());
        hasher.update(self.previous_hash);
        hasher.update(&self.message);

        if !self.cosignatures.is_empty() {
            // Multi-cosig: include all entries sorted by pubkey (canonical
            // ordering — see sorted_cosignatures).
            for entry in self.sorted_cosignatures() {
                hasher.update(entry.member_ledger_hash);
                hasher.update(entry.cosign_signature);
            }
        } else {
            // Legacy single-cosig
            if let Some(ref mlh) = self.member_ledger_hash {
                hasher.update(mlh);
            }
            if self.cosign_signature != [0u8; 64] {
                hasher.update(self.cosign_signature);
            }
        }

        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Compute the chain hash: the value used as previous_hash for the next update.
    ///
    /// `SHA256(content_hash || operator_signature)`
    ///
    /// This folds the operator's signature into the chain without circularity.
    /// The next update's previous_hash = this update's chain_hash().
    pub fn chain_hash(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(self.content_hash);
        hasher.update(self.operator_signature);

        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Verify content_hash matches the computed value.
    pub fn verify_hash(&self) -> bool {
        self.compute_hash() == self.content_hash
    }

    /// Get the ledger ID as a hex string.
    pub fn ledger_id_hex(&self) -> String {
        hex::encode(self.ledger_id)
    }

    // ========================================================================
    // Signature Methods
    // ========================================================================

    /// Compute the data that the co-signer signs (update content only, no operator signature).
    ///
    /// Co-signer signs: sequence || prev_hash || message
    /// Matches TLV field order: identity → chain → payload.
    /// Does NOT include content_hash — the hash is finalized after co-signing
    /// (it incorporates member_ledger_hash for causal ordering).
    /// Co-signer signs ONLY the content, NOT any operator signature.
    /// This prevents operator from tricking co-signer into endorsing invalid state.
    pub fn cosign_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.sequence_number.to_le_bytes());
        data.extend_from_slice(&self.previous_hash);
        data.extend_from_slice(&self.message);
        data
    }

    /// Compute the data that the operator signs (content + all co-signatures).
    ///
    /// Multi-cosig: cosign_data || for each sorted entry: cosign_signature
    /// Legacy: cosign_data || cosign_signature
    pub fn operator_signing_data(&self) -> Vec<u8> {
        let mut data = self.cosign_data();
        if !self.cosignatures.is_empty() {
            for entry in self.sorted_cosignatures() {
                data.extend_from_slice(&entry.cosign_signature);
            }
        } else {
            data.extend_from_slice(&self.cosign_signature);
        }
        data
    }

    /// Verify the co-signer's signature over the update content.
    ///
    /// The co-signer uses BIP-340 tagged hashing:
    /// `SHA256(SHA256("deposits/cosign") || SHA256("deposits/cosign") || cosign_data || member_ledger_hash)`
    ///
    /// The co-signer pubkey must be provided by the caller (from the Ledger).
    /// For BDK ledgers without a co-signer, pass None and this returns Ok.
    pub fn verify_cosign_signature(
        &self,
        partner_pubkey: Option<&PublicKey>,
    ) -> Result<(), String> {
        use bitcoin::hashes::{sha256, Hash};
        use bitcoin::secp256k1::{schnorr::Signature, Message, Secp256k1};

        // If no co-signer pubkey provided (BDK ledger), skip verification
        let partner_pubkey = match partner_pubkey {
            Some(pk) => pk,
            None => return Ok(()),
        };

        // If no co-signer signature, skip
        if self.cosign_signature == [0u8; 64] {
            return Ok(());
        }

        let secp = Secp256k1::new();
        let data = self.cosign_data();
        let member_hash = self.member_ledger_hash.unwrap_or([0u8; 32]);

        // BIP-340 tagged hash: SHA256(tag_hash || tag_hash || data || member_ledger_hash)
        let tag = b"deposits/cosign";
        let tag_hash = sha256::Hash::hash(tag);
        let mut tagged_input = Vec::new();
        tagged_input.extend_from_slice(tag_hash.as_byte_array());
        tagged_input.extend_from_slice(tag_hash.as_byte_array());
        tagged_input.extend_from_slice(&data);
        tagged_input.extend_from_slice(&member_hash);

        let hash = sha256::Hash::hash(&tagged_input);
        let msg = Message::from_digest(hash.to_byte_array());

        let sig = Signature::from_slice(&self.cosign_signature)
            .map_err(|e| format!("Invalid co-signer signature format: {}", e))?;

        let (xonly, _parity) = partner_pubkey.x_only_public_key();
        secp.verify_schnorr(&sig, &msg, &xonly)
            .map_err(|e| format!("Co-signer signature verification failed: {}", e))
    }

    /// Verify the operator's signature over content + co-signer's signature.
    pub fn verify_operator_signature(&self) -> Result<(), String> {
        use bitcoin::hashes::{sha256, Hash};
        use bitcoin::secp256k1::{schnorr::Signature, Message, Secp256k1};

        let secp = Secp256k1::new();
        let data = self.operator_signing_data();
        let hash = sha256::Hash::hash(&data);
        let msg = Message::from_digest(hash.to_byte_array());

        let sig = Signature::from_slice(&self.operator_signature)
            .map_err(|e| format!("Invalid operator signature format: {}", e))?;

        let (xonly, _parity) = self.operator_id.x_only_public_key();
        secp.verify_schnorr(&sig, &msg, &xonly)
            .map_err(|e| format!("Operator signature verification failed: {}", e))
    }

    /// Verify majority cosignatures.
    ///
    /// Checks that each entry's signature is valid, each pubkey is in the quorum,
    /// no duplicate pubkeys, and the count meets the threshold.
    pub fn verify_cosign_signatures(
        &self,
        quorum_members: &[PublicKey],
        threshold: usize,
    ) -> Result<(), String> {
        use bitcoin::hashes::{sha256, Hash};
        use bitcoin::secp256k1::{schnorr::Signature, Message, Secp256k1};

        if self.cosignatures.is_empty() {
            return Err("No cosignatures present".to_string());
        }
        if self.cosignatures.len() < threshold {
            return Err(format!(
                "Insufficient cosignatures: {} of {} required",
                self.cosignatures.len(),
                threshold
            ));
        }

        let secp = Secp256k1::new();
        let cosign_data = self.cosign_data();
        let tag = b"deposits/cosign";
        let tag_hash = sha256::Hash::hash(tag);

        let mut seen = std::collections::HashSet::new();
        for entry in &self.cosignatures {
            // Check for duplicate pubkeys
            let pk_bytes = entry.cosigner_pubkey.serialize();
            if !seen.insert(pk_bytes) {
                return Err(format!(
                    "Duplicate cosigner: {}",
                    hex::encode(&pk_bytes[..8])
                ));
            }

            // Check member is in quorum
            if !quorum_members.contains(&entry.cosigner_pubkey) {
                return Err(format!(
                    "Cosigner {} not in quorum",
                    hex::encode(&pk_bytes[..8])
                ));
            }

            // Verify BIP-340 tagged hash signature
            let mut tagged_input = Vec::new();
            tagged_input.extend_from_slice(tag_hash.as_byte_array());
            tagged_input.extend_from_slice(tag_hash.as_byte_array());
            tagged_input.extend_from_slice(&cosign_data);
            tagged_input.extend_from_slice(&entry.member_ledger_hash);

            let hash = sha256::Hash::hash(&tagged_input);
            let msg = Message::from_digest(hash.to_byte_array());

            let sig = Signature::from_slice(&entry.cosign_signature).map_err(|e| {
                format!(
                    "Invalid cosig format from {}: {}",
                    hex::encode(&pk_bytes[..8]),
                    e
                )
            })?;

            let (xonly, _) = entry.cosigner_pubkey.x_only_public_key();
            secp.verify_schnorr(&sig, &msg, &xonly).map_err(|e| {
                format!(
                    "Cosig verification failed for {}: {}",
                    hex::encode(&pk_bytes[..8]),
                    e
                )
            })?;
        }

        Ok(())
    }

    /// Verify both signatures on this update.
    ///
    /// For multi-cosig updates, pass quorum_members and threshold.
    /// For legacy single-cosig, pass partner_pubkey.
    /// For BDK ledgers without co-signers, pass None/empty.
    pub fn verify_signatures(&self, partner_pubkey: Option<&PublicKey>) -> Result<(), String> {
        self.verify_cosign_signature(partner_pubkey)?;
        self.verify_operator_signature()
    }

    /// Check if this update has valid (non-zero) signatures.
    pub fn is_fully_signed(&self) -> bool {
        let has_cosig = !self.cosignatures.is_empty() || self.cosign_signature != [0u8; 64];
        has_cosig && self.operator_signature != [0u8; 64]
    }

    /// Check if co-signer(s) have signed.
    pub fn has_cosign_signature(&self) -> bool {
        !self.cosignatures.is_empty() || self.cosign_signature != [0u8; 64]
    }

    /// Check if operator has signed (non-zero signature).
    pub fn has_operator_signature(&self) -> bool {
        self.operator_signature != [0u8; 64]
    }
}

// ============================================================================
// Deposit Info (API Response)
// ============================================================================

/// Deposit information for API responses.
///
/// Spendable funds are always computed as `balance - locked_balance`; they
/// are not stored separately because `locked_balance` is a subset of `balance`,
/// not an additional quantity.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DepositInfo {
    /// Deposit identifier (hex).
    pub deposit_id: String,
    /// Miniscript descriptor.
    pub descriptor: String,
    /// Total obligation owed on this deposit (millisatoshis).
    pub balance: u64,
    /// Portion of `balance` earmarked for in-flight operations (millisatoshis).
    /// Subset of `balance`, not a separate bucket.
    pub locked_balance: u64,
    /// Number of active invoices.
    pub invoice_count: usize,
    /// Fee structure.
    pub fees: FeeStructure,
}

impl From<&Deposit> for DepositInfo {
    fn from(d: &Deposit) -> Self {
        Self {
            deposit_id: hex::encode(d.deposit_id),
            descriptor: d.descriptor.clone(),
            balance: d.balance,
            locked_balance: d.locked_balance,
            invoice_count: d.invoices.len(),
            fees: d.fees.clone(),
        }
    }
}

// ============================================================================
// Quorum Message Types
// ============================================================================

/// Request to join a ledger's quorum.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumJoinRequestMsg {
    /// Requester's public key.
    #[serde(with = "serde_pubkey")]
    pub requester_pubkey: PublicKey,
    /// Operator of the ledger.
    #[serde(with = "serde_pubkey")]
    pub operator_id: PublicKey,
    /// Reserves identifier (UTXO address for BDK, partner pubkey string for LDK).
    pub reserves_id: String,
    /// Protocol version.
    pub protocol_version: u16,
    /// Timestamp.
    pub timestamp: u64,
    /// Signature.
    #[serde(with = "serde_64")]
    pub signature: [u8; 64],
}

/// Response to a quorum join request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumJoinResponseMsg {
    /// Whether the request was accepted.
    pub accepted: bool,
    /// Current quorum members.
    #[serde(with = "serde_pubkey_vec")]
    pub members: Vec<PublicKey>,
    /// Voting threshold.
    pub threshold: u16,
    /// Last sequence number.
    pub last_sequence: u64,
    /// Current state hash.
    #[serde(with = "serde_32")]
    pub content_hash: [u8; 32],
    /// Rejection reason (if rejected).
    pub rejection_reason: Option<String>,
}

/// A vote in a quorum voting round.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumVoteMsg {
    /// Vote round ID.
    #[serde(with = "serde_32")]
    pub vote_round_id: [u8; 32],
    /// Voter's public key.
    #[serde(with = "serde_pubkey")]
    pub voter_pubkey: PublicKey,
    /// Vote value (true = conforming, false = non-conforming).
    pub vote: bool,
    /// Voter's sequence number.
    pub voter_sequence: u64,
    /// Voter's state hash.
    #[serde(with = "serde_32")]
    pub voter_state_hash: [u8; 32],
    /// Evidence (for non-conforming votes).
    pub evidence: Option<Vec<u8>>,
    /// Signature over the vote.
    #[serde(with = "serde_64")]
    pub signature: [u8; 64],
    /// Optional spend signature for recovery.
    #[serde(with = "serde_opt_64")]
    pub spend_signature: Option<[u8; 64]>,
}

// ============================================================================
// Ledger Update (Hash Chain Entry)
// ============================================================================

/// A single ledger update entry - the atomic unit of ledger state transition.
/// The ledger state is derived by applying updates in sequence from genesis.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerUpdate {
    /// Sequential update number (0 for first update, 1 for second, etc.)
    pub sequence_number: u64,
    /// The protocol message that represents this state transition (serialized)
    pub message: Vec<u8>,
    /// Hash of the previous update in the chain (0x0 for genesis/first update)
    #[serde(with = "serde_32")]
    pub previous_hash: [u8; 32],
    /// Hash of this update (computed from sequence_number, message, and previous_hash)
    #[serde(with = "serde_32")]
    pub consensus_hash: [u8; 32],
}

impl LedgerUpdate {
    /// Calculate the hash of this update based on its contents.
    pub fn calculate_hash(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(self.sequence_number.to_le_bytes());
        hasher.update(self.previous_hash);
        hasher.update(&self.message);

        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
}

// ============================================================================
// Invoice Info (API Response)
// ============================================================================

/// Invoice information for API responses.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvoiceInfo {
    /// Invoice ID.
    pub id: String,
    /// Amount in satoshis.
    pub amount: u64,
    /// Expiration time (Unix timestamp).
    pub expires: u64,
    /// Payment hash.
    #[serde(with = "serde_32")]
    pub payment_hash: [u8; 32],
}

// ============================================================================
// Reserves Status (API Response)
// ============================================================================

/// Current reserves status.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReservesStatus {
    /// Current reserves amount.
    pub current_amount: u64,
    /// Required reserves amount (100% of deposits + max invoice).
    pub required_amount: u64,
    /// Excess reserves that can be removed.
    pub excess_amount: u64,
    /// Total of all deposit balances.
    pub total_deposit_balances: u64,
    /// Largest outstanding invoice amount.
    pub max_outstanding_invoice: u64,
    /// Number of deposits.
    pub deposit_count: usize,
    /// Total locked balances.
    pub total_locked_balances: u64,
}

// ============================================================================
// Signed Ledger Update Log (Audit Trail)
// ============================================================================

/// Cryptographically signed ledger update log for audit trail.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedLedgerUpdateLog {
    /// Unique ledger identifier: SHA256(genesis_operator || reserves_id || genesis_block).
    #[serde(with = "serde_32")]
    pub ledger_id: [u8; 32],
    /// Chain of signed updates (ordered by sequence number).
    pub updates: Vec<SignedLedgerUpdate>,
    /// Next expected sequence number.
    pub next_sequence: u64,
    /// Buffer for out-of-order updates (keyed by sequence number).
    #[serde(default)]
    pub pending_updates: HashMap<u64, SignedLedgerUpdate>,
}

impl SignedLedgerUpdateLog {
    /// Create a new empty log.
    pub fn new(ledger_id: [u8; 32]) -> Self {
        Self {
            ledger_id,
            updates: Vec::new(),
            next_sequence: 0,
            pending_updates: HashMap::new(),
        }
    }

    /// Get the ledger ID as a hex string.
    pub fn ledger_id_hex(&self) -> String {
        hex::encode(self.ledger_id)
    }

    /// Add an update to the log with sequence and hash chain validation.
    ///
    /// Validates that:
    /// - The sequence number matches the expected next sequence
    /// - The previous hash matches the last update's current hash (or zeros if first)
    pub fn add_update(&mut self, update: SignedLedgerUpdate) -> Result<(), crate::DepositsError> {
        // Verify sequence number
        if update.sequence_number != self.next_sequence {
            return Err(crate::DepositsError::InvalidState(format!(
                "Sequence mismatch: expected {}, got {}",
                self.next_sequence, update.sequence_number
            )));
        }

        // Verify chain continuity. The chain links via `chain_hash()`,
        // not `content_hash` — see docstring on `SignedLedgerUpdate::chain_hash`
        // and the canonical setter in `ledger::commit_staged`.
        let expected_prev = if let Some(last) = self.updates.last() {
            last.chain_hash()
        } else {
            [0u8; 32]
        };
        if update.previous_hash != expected_prev {
            return Err(crate::DepositsError::InvalidState(format!(
                "Hash chain broken: expected {}, got {}",
                hex::encode(expected_prev),
                hex::encode(update.previous_hash)
            )));
        }

        // Add to log
        self.updates.push(update);
        self.next_sequence += 1;
        Ok(())
    }

    /// Verify the hash chain integrity of all updates.
    ///
    /// Checks that:
    /// - Sequence numbers are contiguous starting from 0
    /// - Each update's previous_hash matches the prior update's chain_hash
    ///   (which folds the operator signature into content_hash; see
    ///   `SignedLedgerUpdate::chain_hash`)
    pub fn verify_chain(&self) -> Result<(), crate::DepositsError> {
        let mut expected_prev = [0u8; 32];
        for (i, update) in self.updates.iter().enumerate() {
            if update.sequence_number != i as u64 {
                return Err(crate::DepositsError::InvalidState(format!(
                    "Sequence mismatch at index {}: expected {}, got {}",
                    i, i, update.sequence_number
                )));
            }
            if update.previous_hash != expected_prev {
                return Err(crate::DepositsError::InvalidState(format!(
                    "Hash chain broken at index {}",
                    i
                )));
            }
            expected_prev = update.chain_hash();
        }
        Ok(())
    }

    /// Get all updates with sequence numbers greater than the given value.
    pub fn get_updates_since(&self, since_sequence: u64) -> Vec<SignedLedgerUpdate> {
        self.updates
            .iter()
            .filter(|u| u.sequence_number > since_sequence)
            .cloned()
            .collect()
    }

    /// Get the tail (most recent) hash from the update chain.
    ///
    /// Returns zeros if there are no updates yet.
    pub fn tail_hash(&self) -> [u8; 32] {
        self.updates
            .last()
            .map(|u| u.content_hash)
            .unwrap_or([0u8; 32])
    }

    /// Get the number of updates in this log.
    pub fn len(&self) -> usize {
        self.updates.len()
    }

    /// Check if this log is empty.
    pub fn is_empty(&self) -> bool {
        self.updates.is_empty()
    }
}

// ============================================================================
// Audit Types
// ============================================================================

/// Result of a ledger audit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditResult {
    /// Detected violations.
    pub violations: Vec<Violation>,
    /// Cross-ledger inconsistencies.
    pub cross_ledger_violations: Vec<CrossLedgerViolation>,
    /// Overall compliance score (0-100).
    pub compliance_score: u8,
    /// Audit timestamp (Unix timestamp).
    pub audit_timestamp: u64,
}

/// Types of protocol violations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Violation {
    /// Insufficient reserves for operation.
    InsufficientReserves {
        required: u64,
        actual: u64,
        timestamp: u64,
    },
    /// Unauthorized operation without proper signatures.
    UnauthorizedOperation {
        operation_type: String,
        timestamp: u64,
    },
    /// Payment received but not credited to deposit.
    PaymentNotCredited {
        #[serde(with = "serde_32")]
        payment_hash: [u8; 32],
        amount: u64,
        timestamp: u64,
    },
    /// Invalid reserve calculation.
    InvalidReserveCalculation {
        expected: u64,
        actual: u64,
        timestamp: u64,
    },
    /// Fee assessment violation.
    InvalidFeeAssessment {
        #[serde(with = "serde_deposit_id")]
        deposit_id: DepositId,
        timestamp: u64,
    },
}

/// Cross-ledger violations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CrossLedgerViolation {
    /// Inconsistent operator behavior across ledgers.
    InconsistentBehavior {
        #[serde(with = "serde_32")]
        ledger1: [u8; 32],
        #[serde(with = "serde_32")]
        ledger2: [u8; 32],
        discrepancy: String,
    },
    /// Reserve manipulation across ledgers.
    ReserveManipulation {
        affected_ledgers: Vec<[u8; 32]>,
        details: String,
    },
}

// ============================================================================
// Ledger State Updates
// ============================================================================

/// Updates that can be applied to ledger state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LedgerStateUpdate {
    /// Add a new deposit.
    AddDeposit(Deposit),
    /// Remove a deposit.
    RemoveDeposit(#[serde(with = "serde_pubkey")] PublicKey),
    /// Update deposit balance.
    UpdateDepositBalance {
        #[serde(with = "serde_pubkey")]
        pubkey: PublicKey,
        new_balance: u64,
    },
    /// Update reserves amount.
    UpdateReserves(u64),
    /// Set pending invoice.
    SetPendingInvoice(Option<PendingInvoice>),
    /// Lock deposit balance for payment.
    LockDepositBalance {
        #[serde(with = "serde_pubkey")]
        pubkey: PublicKey,
        amount: u64,
    },
    /// Unlock deposit balance (payment failed).
    UnlockDepositBalance {
        #[serde(with = "serde_pubkey")]
        pubkey: PublicKey,
        amount: u64,
    },
    /// Add invoice to deposit.
    AddInvoiceToDeposit {
        #[serde(with = "serde_pubkey")]
        pubkey: PublicKey,
        invoice: Invoice,
    },
    /// Remove invoice from deposit.
    RemoveInvoiceFromDeposit {
        #[serde(with = "serde_pubkey")]
        pubkey: PublicKey,
        invoice_id: String,
    },
}

// ============================================================================
// TLV Encoding Implementations
// ============================================================================

// Field type constants for FeeStructure
mod fee_structure_fields {
    pub const ANNUALIZED_MSATS: u64 = 0;
    pub const ANNUALIZED_BPS: u64 = 2;
    pub const FREQUENCY_BLOCKS: u64 = 4;
}

impl TlvEncode for FeeStructure {
    fn tlv_encode(&self) -> Vec<u8> {
        TlvBuilder::new()
            .u64_field(
                fee_structure_fields::ANNUALIZED_MSATS,
                self.annualized_msats,
            )
            .u16_field(fee_structure_fields::ANNUALIZED_BPS, self.annualized_bps)
            .u32_field(
                fee_structure_fields::FREQUENCY_BLOCKS,
                self.frequency_blocks,
            )
            .build()
    }
}

impl TlvDecode for FeeStructure {
    fn tlv_decode(data: &[u8]) -> TlvResult<Self> {
        let reader = TlvReader::new(data)?;
        Ok(Self {
            annualized_msats: reader.read_u64(fee_structure_fields::ANNUALIZED_MSATS)?,
            annualized_bps: reader.read_u16(fee_structure_fields::ANNUALIZED_BPS)?,
            frequency_blocks: reader.read_u32(fee_structure_fields::FREQUENCY_BLOCKS)?,
        })
    }
}

// Field type constants for TransferFeeSchedule
mod transfer_fee_fields {
    pub const FIXED_MSATS: u64 = 0;
    pub const RATE_BPS: u64 = 2;
}

impl TlvEncode for TransferFeeSchedule {
    fn tlv_encode(&self) -> Vec<u8> {
        TlvBuilder::new()
            .u64_field(transfer_fee_fields::FIXED_MSATS, self.fixed_msats)
            .u16_field(transfer_fee_fields::RATE_BPS, self.rate_bps)
            .build()
    }
}

impl TlvDecode for TransferFeeSchedule {
    fn tlv_decode(data: &[u8]) -> TlvResult<Self> {
        let reader = TlvReader::new(data)?;
        Ok(Self {
            fixed_msats: reader.read_u64(transfer_fee_fields::FIXED_MSATS)?,
            rate_bps: reader.read_u16(transfer_fee_fields::RATE_BPS)?,
        })
    }
}

// Field type constants for Invoice
mod invoice_fields {
    pub const ID: u64 = 0;
    pub const PAYMENT_HASH: u64 = 2;
    pub const AMOUNT: u64 = 4;
    pub const EXPIRES: u64 = 6;
    pub const ASSIGNED_DEPOSIT: u64 = 8;
    pub const BOLT11: u64 = 10;
}

impl TlvEncode for Invoice {
    fn tlv_encode(&self) -> Vec<u8> {
        TlvBuilder::new()
            .string_field(invoice_fields::ID, &self.id)
            .bytes_field(invoice_fields::PAYMENT_HASH, &self.payment_hash)
            .u64_field(invoice_fields::AMOUNT, self.amount)
            .u64_field(invoice_fields::EXPIRES, self.expires)
            .deposit_id_field(invoice_fields::ASSIGNED_DEPOSIT, &self.assigned_deposit)
            .string_field(invoice_fields::BOLT11, &self.bolt11)
            .build()
    }
}

impl TlvDecode for Invoice {
    fn tlv_decode(data: &[u8]) -> TlvResult<Self> {
        let reader = TlvReader::new(data)?;
        Ok(Self {
            id: reader.read_string(invoice_fields::ID)?,
            payment_hash: reader.read_bytes(invoice_fields::PAYMENT_HASH)?,
            amount: reader.read_u64(invoice_fields::AMOUNT)?,
            expires: reader.read_u64(invoice_fields::EXPIRES)?,
            assigned_deposit: reader.read_deposit_id(invoice_fields::ASSIGNED_DEPOSIT)?,
            bolt11: reader.read_string(invoice_fields::BOLT11)?,
        })
    }
}

// Field type constants for PendingInvoice
mod pending_invoice_fields {
    pub const AMOUNT: u64 = 0;
    pub const PAYMENT_HASH: u64 = 2;
    pub const EXPIRES: u64 = 4;
    pub const ASSIGNED_DEPOSIT: u64 = 6;
    pub const INVOICE_ID: u64 = 8;
    pub const BOLT11: u64 = 10;
}

impl TlvEncode for PendingInvoice {
    fn tlv_encode(&self) -> Vec<u8> {
        TlvBuilder::new()
            .u64_field(pending_invoice_fields::AMOUNT, self.amount)
            .bytes_field(pending_invoice_fields::PAYMENT_HASH, &self.payment_hash)
            .u64_field(pending_invoice_fields::EXPIRES, self.expires)
            .deposit_id_field(
                pending_invoice_fields::ASSIGNED_DEPOSIT,
                &self.assigned_deposit,
            )
            .string_field(pending_invoice_fields::INVOICE_ID, &self.invoice_id)
            .string_field(pending_invoice_fields::BOLT11, &self.bolt11)
            .build()
    }
}

impl TlvDecode for PendingInvoice {
    fn tlv_decode(data: &[u8]) -> TlvResult<Self> {
        let reader = TlvReader::new(data)?;
        Ok(Self {
            amount: reader.read_u64(pending_invoice_fields::AMOUNT)?,
            payment_hash: reader.read_bytes(pending_invoice_fields::PAYMENT_HASH)?,
            expires: reader.read_u64(pending_invoice_fields::EXPIRES)?,
            assigned_deposit: reader.read_deposit_id(pending_invoice_fields::ASSIGNED_DEPOSIT)?,
            invoice_id: reader.read_string(pending_invoice_fields::INVOICE_ID)?,
            bolt11: reader.read_string(pending_invoice_fields::BOLT11)?,
        })
    }
}

// Field type constants for Deposit
mod deposit_fields {
    pub const DEPOSIT_ID: u64 = 0;
    pub const DESCRIPTOR: u64 = 1;
    pub const BALANCE: u64 = 2;
    pub const LOCKED_BALANCE: u64 = 4;
    pub const COLLATERAL_PLEDGE_AMOUNT: u64 = 12;
    pub const COLLATERAL_PLEDGE_EXPIRES: u64 = 14;
    pub const INVOICES: u64 = 6;
    pub const FEES: u64 = 8;
    pub const LAST_FEE_ASSESSMENT: u64 = 10;
    pub const TRANSFER_FEES: u64 = 16;
    pub const RECEIVE_REQUIRES_SIG: u64 = 22; // u8 (0 or 1)
    pub const FEE_CHANGE_AFTER: u64 = 24; // u32
    pub const FEE_CHANGE_NOTICE: u64 = 26; // u32
    pub const FEE_CHANGE_LIMIT_BPS: u64 = 28; // u16
    pub const OPENED_AT_BLOCK: u64 = 18; // u32
    pub const PENDING_FEE_CHANGE: u64 = 30; // nested
}

impl TlvEncode for Deposit {
    fn tlv_encode(&self) -> Vec<u8> {
        let mut builder = TlvBuilder::new()
            .deposit_id_field(deposit_fields::DEPOSIT_ID, &self.deposit_id)
            .string_field(deposit_fields::DESCRIPTOR, &self.descriptor)
            .u64_field(deposit_fields::BALANCE, self.balance)
            .u64_field(deposit_fields::LOCKED_BALANCE, self.locked_balance)
            .vec_field(deposit_fields::INVOICES, &self.invoices)
            .nested(deposit_fields::FEES, &self.fees)
            .u32_field(
                deposit_fields::LAST_FEE_ASSESSMENT,
                self.last_fee_assessment,
            )
            .nested(deposit_fields::TRANSFER_FEES, &self.transfer_fees)
            .u8_field(
                deposit_fields::RECEIVE_REQUIRES_SIG,
                if self.receive_requires_sig { 1 } else { 0 },
            )
            .u32_field(deposit_fields::OPENED_AT_BLOCK, self.opened_at_block);
        if let Some(v) = self.fee_change_after_blocks {
            builder = builder.u32_field(deposit_fields::FEE_CHANGE_AFTER, v);
        }
        if let Some(v) = self.fee_change_notice_blocks {
            builder = builder.u32_field(deposit_fields::FEE_CHANGE_NOTICE, v);
        }
        if let Some(v) = self.fee_change_limit_bps {
            builder = builder.u16_field(deposit_fields::FEE_CHANGE_LIMIT_BPS, v);
        }
        builder.build()
    }
}

impl TlvDecode for Deposit {
    fn tlv_decode(data: &[u8]) -> TlvResult<Self> {
        let reader = TlvReader::new(data)?;
        Ok(Self {
            deposit_id: reader.read_deposit_id(deposit_fields::DEPOSIT_ID)?,
            descriptor: reader.read_string(deposit_fields::DESCRIPTOR)?,
            balance: reader.read_u64(deposit_fields::BALANCE)?,
            locked_balance: reader.read_u64(deposit_fields::LOCKED_BALANCE)?,
            invoices: reader.read_vec(deposit_fields::INVOICES)?,
            fees: reader.read_nested(deposit_fields::FEES)?,
            last_fee_assessment: reader.read_u32(deposit_fields::LAST_FEE_ASSESSMENT)?,
            transfer_fees: reader
                .read_nested_opt(deposit_fields::TRANSFER_FEES)?
                .unwrap_or_default(),
            receive_requires_sig: reader
                .read_u8(deposit_fields::RECEIVE_REQUIRES_SIG)
                .unwrap_or(0)
                != 0,
            fee_change_after_blocks: reader.read_u32_opt(deposit_fields::FEE_CHANGE_AFTER)?,
            fee_change_notice_blocks: reader.read_u32_opt(deposit_fields::FEE_CHANGE_NOTICE)?,
            fee_change_limit_bps: reader.read_u16_opt(deposit_fields::FEE_CHANGE_LIMIT_BPS)?,
            opened_at_block: reader
                .read_u32_opt(deposit_fields::OPENED_AT_BLOCK)?
                .unwrap_or(0),
            pending_fee_change: None, // transient state, not serialized in TLV
        })
    }
}

// Field type constants for ReservesOutput
mod reserves_output_fields {
    pub const CHANNEL_ID: u64 = 0;
    pub const AMOUNT: u64 = 2;
    pub const SPEND_TO: u64 = 4;
}

impl TlvEncode for ReservesOutput {
    fn tlv_encode(&self) -> Vec<u8> {
        TlvBuilder::new()
            .bytes_field(reserves_output_fields::CHANNEL_ID, &self.channel_id)
            .u64_field(reserves_output_fields::AMOUNT, self.amount)
            .pubkey_field(reserves_output_fields::SPEND_TO, &self.spend_to)
            .build()
    }
}

impl TlvDecode for ReservesOutput {
    fn tlv_decode(data: &[u8]) -> TlvResult<Self> {
        let reader = TlvReader::new(data)?;
        Ok(Self {
            channel_id: reader.read_bytes(reserves_output_fields::CHANNEL_ID)?,
            amount: reader.read_u64(reserves_output_fields::AMOUNT)?,
            spend_to: reader.read_pubkey(reserves_output_fields::SPEND_TO)?,
        })
    }
}

// Field type constants for SignedLedgerUpdate
//
// Layout: identity → chain → payload → context → cosign → signatures
//   tag=0  operator_id        (33B)
//   tag=2  ledger_id          (32B)
//   tag=4  sequence_number    (varint)
//   tag=6  previous_hash      (32B)
//   tag=8  message            (variable)       ← signed by both parties
//   tag=10 block_height       (4B, optional)
//   tag=12 block_hash         (32B, optional)
//   tag=14 cosigner_pubkey    (33B, optional)
//   tag=16 member_ledger_hash (32B, optional)
//   tag=18 cosign_signature   (64B)
//   tag=20 operator_signature (64B)
mod signed_update_fields {
    pub const OPERATOR_ID: u64 = 0;
    pub const LEDGER_ID: u64 = 2;
    pub const SEQUENCE_NUMBER: u64 = 4;
    pub const PREVIOUS_HASH: u64 = 6;
    pub const MESSAGE: u64 = 8;
    pub const BLOCK_HEIGHT: u64 = 10;
    pub const BLOCK_HASH: u64 = 12;
    pub const COSIGNER_PUBKEY: u64 = 14;
    pub const MEMBER_LEDGER_HASH: u64 = 16;
    pub const COSIGN_SIGNATURE: u64 = 18;
    pub const OPERATOR_SIGNATURE: u64 = 20;
    pub const COSIGNATURES: u64 = 22;
}

impl TlvEncode for SignedLedgerUpdate {
    fn tlv_encode(&self) -> Vec<u8> {
        let mut builder = TlvBuilder::new()
            .pubkey_field(signed_update_fields::OPERATOR_ID, &self.operator_id)
            .bytes_field(signed_update_fields::LEDGER_ID, &self.ledger_id)
            .u64_field(signed_update_fields::SEQUENCE_NUMBER, self.sequence_number)
            .bytes_field(signed_update_fields::PREVIOUS_HASH, &self.previous_hash)
            .bytes_field(signed_update_fields::MESSAGE, &self.message);
        if self.block_height != 0 {
            builder = builder.u32_field(signed_update_fields::BLOCK_HEIGHT, self.block_height);
        }
        if self.block_hash != [0u8; 32] {
            builder = builder.bytes_field(signed_update_fields::BLOCK_HASH, &self.block_hash);
        }
        if !self.cosignatures.is_empty() {
            // Multi-cosig: encode as tag 22 (length-prefixed entries),
            // sorted by pubkey so the wire bytes are canonical.
            let mut cosig_bytes = Vec::new();
            for entry in self.sorted_cosignatures() {
                let entry_len: u16 = 129; // 33 + 64 + 32
                cosig_bytes.extend_from_slice(&entry_len.to_be_bytes());
                cosig_bytes.extend_from_slice(&entry.cosigner_pubkey.serialize());
                cosig_bytes.extend_from_slice(&entry.cosign_signature);
                cosig_bytes.extend_from_slice(&entry.member_ledger_hash);
            }
            builder = builder.bytes_field(signed_update_fields::COSIGNATURES, &cosig_bytes);
        } else {
            // Legacy single-cosig: encode tags 14/16/18
            if let Some(ref pk) = self.cosigner_pubkey {
                builder = builder.pubkey_field(signed_update_fields::COSIGNER_PUBKEY, pk);
            }
            if let Some(ref hash) = self.member_ledger_hash {
                builder = builder.bytes_field(signed_update_fields::MEMBER_LEDGER_HASH, hash);
            }
            if self.cosign_signature != [0u8; 64] {
                builder = builder.bytes_field(
                    signed_update_fields::COSIGN_SIGNATURE,
                    &self.cosign_signature,
                );
            }
        }
        // Note: TLV is sorted by tag number, so operator_signature (tag 20) appears
        // before cosignatures (tag 22) on wire. This is cosmetic — the operator signs
        // over operator_signing_data() which includes cosignatures in the hash input,
        // and content_hash also incorporates all cosignatures. The tag ordering doesn't
        // affect signature validity.
        builder = builder.bytes_field(
            signed_update_fields::OPERATOR_SIGNATURE,
            &self.operator_signature,
        );
        builder.build()
    }
}

impl TlvDecode for SignedLedgerUpdate {
    fn tlv_decode(data: &[u8]) -> TlvResult<Self> {
        let reader = TlvReader::new(data)?;
        let message = reader.read_raw(signed_update_fields::MESSAGE)?.to_vec();
        // Derive message_type from the operation discriminant in message bytes
        let message_type = crate::messages::LedgerOperation::message_type_from_bytes(&message);
        // Try multi-cosig tag 22 first, fall back to legacy tags 14/16/18
        let cosignatures = if let Ok(raw) = reader.read_raw(signed_update_fields::COSIGNATURES) {
            let mut entries = Vec::new();
            let mut off = 0;
            while off + 2 <= raw.len() {
                let entry_len = u16::from_be_bytes([raw[off], raw[off + 1]]) as usize;
                off += 2;
                if off + entry_len > raw.len() || entry_len < 129 {
                    break;
                }
                let pk = PublicKey::from_slice(&raw[off..off + 33]).map_err(|e| {
                    crate::tlv::TlvError::InvalidFieldValue {
                        field_type: signed_update_fields::COSIGNATURES,
                        reason: format!("cosig pubkey: {}", e),
                    }
                })?;
                let mut sig = [0u8; 64];
                sig.copy_from_slice(&raw[off + 33..off + 97]);
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&raw[off + 97..off + 129]);
                entries.push(CosignEntry {
                    cosigner_pubkey: pk,
                    cosign_signature: sig,
                    member_ledger_hash: hash,
                });
                off += entry_len;
            }
            // Canonicalize storage: even if the wire bytes arrived out of
            // order (from a buggy or malicious sender), keep the in-memory
            // Vec sorted by pubkey so any downstream consumer that iterates
            // `.cosignatures` directly still sees the canonical order.
            entries.sort_by(|a, b| {
                a.cosigner_pubkey
                    .serialize()
                    .cmp(&b.cosigner_pubkey.serialize())
            });
            entries
        } else {
            Vec::new()
        };

        let mut update = Self {
            message,
            message_type,
            operator_id: reader.read_pubkey(signed_update_fields::OPERATOR_ID)?,
            ledger_id: reader.read_bytes(signed_update_fields::LEDGER_ID)?,
            sequence_number: reader.read_u64(signed_update_fields::SEQUENCE_NUMBER)?,
            previous_hash: reader.read_bytes(signed_update_fields::PREVIOUS_HASH)?,
            content_hash: [0u8; 32],
            block_height: reader
                .read_u32_opt(signed_update_fields::BLOCK_HEIGHT)?
                .unwrap_or(0),
            block_hash: reader
                .read_bytes_opt(signed_update_fields::BLOCK_HASH)?
                .unwrap_or([0u8; 32]),
            cosign_signature: reader
                .read_bytes_opt(signed_update_fields::COSIGN_SIGNATURE)?
                .unwrap_or([0u8; 64]),
            operator_signature: reader.read_bytes(signed_update_fields::OPERATOR_SIGNATURE)?,
            cosigner_pubkey: reader.read_pubkey_opt(signed_update_fields::COSIGNER_PUBKEY)?,
            member_ledger_hash: reader.read_bytes_opt(signed_update_fields::MEMBER_LEDGER_HASH)?,
            cosignatures,
        };
        // Derive content_hash from content (not stored on wire)
        update.content_hash = update.compute_hash();
        Ok(update)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pubkey() -> PublicKey {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let sk = bitcoin::secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap();
        PublicKey::from_secret_key(&secp, &sk)
    }

    #[test]
    fn test_fee_calculation() {
        let fees = FeeStructure::new(52560, 100, 144); // 1 sat/block fixed, 1% annual

        // One year of blocks
        let fee = fees.calculate_fee(1_000_000, 52560);
        // Should be ~52560 (fixed) + ~10000 (1% of 1M)
        assert!(fee > 60000 && fee < 65000);
    }

    #[test]
    fn test_deposit_operations() {
        let pk = test_pubkey();
        let mut deposit = Deposit::from_pubkey(&pk, None);

        // Credit
        deposit.credit(100_000);
        assert_eq!(deposit.balance, 100_000);

        // Lock
        deposit.lock(30_000).unwrap();
        assert_eq!(deposit.locked_balance, 30_000);
        assert_eq!(deposit.available_balance(), 70_000);

        // Can't lock more than available
        assert!(deposit.lock(80_000).is_err());

        // Unlock
        deposit.unlock(30_000);
        assert_eq!(deposit.locked_balance, 0);

        // Debit
        deposit.debit(50_000).unwrap();
        assert_eq!(deposit.balance, 50_000);
    }

    #[test]
    fn test_ledger_state() {
        let op = test_pubkey();
        let partner = test_pubkey();
        let mut state = super::super::ledger_state::LedgerState::new(op, partner.to_string(), 0);

        assert_eq!(state.total_deposit_balance(), 0);
        assert_eq!(state.reserves_amount, 0);
        assert!(state.has_sufficient_reserves()); // No deposits means 0 reserves is sufficient

        // Add reserves
        state.reserves_amount = 100_000;
        assert_eq!(state.reserves_amount, 100_000);
    }

    #[test]
    fn test_signed_update_hash() {
        let pk = test_pubkey();
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

        let hash = update.compute_hash();
        assert_ne!(hash, [0u8; 32]); // Hash should be computed
    }

    #[test]
    fn test_signed_update_signature_methods() {
        let pk = test_pubkey();
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

        // Test signing data generation
        let cosign_data = update.cosign_data();
        assert!(!cosign_data.is_empty());

        let operator_data = update.operator_signing_data();
        // Operator data includes cosign_signature
        assert!(operator_data.len() > cosign_data.len());
        assert_eq!(operator_data.len(), cosign_data.len() + 64);

        // Test signature status checks
        assert!(!update.is_fully_signed());
        assert!(!update.has_cosign_signature());
        assert!(!update.has_operator_signature());

        // Set non-zero signatures and check
        update.cosign_signature = [0xaa; 64];
        assert!(update.has_cosign_signature());
        assert!(!update.is_fully_signed());

        update.operator_signature = [0xbb; 64];
        assert!(update.has_operator_signature());
        assert!(update.is_fully_signed());
    }

    #[test]
    fn test_serde_roundtrip() {
        let fees = FeeStructure::new(1000, 50, 144);
        let json = serde_json::to_string(&fees).unwrap();
        let decoded: FeeStructure = serde_json::from_str(&json).unwrap();
        assert_eq!(fees, decoded);
    }

    // TLV roundtrip tests
    #[test]
    fn test_fee_structure_tlv_roundtrip() {
        let original = FeeStructure::new(1000, 50, 144);
        let encoded = original.tlv_encode();
        let decoded = FeeStructure::tlv_decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_invoice_tlv_roundtrip() {
        let pk = test_pubkey();
        let descriptor = format!("pk({})", hex::encode(pk.serialize()));
        let deposit_id = compute_deposit_id(&descriptor);
        let original = Invoice {
            id: "test-invoice-123".to_string(),
            payment_hash: [0xab; 32],
            amount: 100_000,
            expires: 1700000000,
            assigned_deposit: deposit_id,
            bolt11: "lnbc100n1...".to_string(),
        };
        let encoded = original.tlv_encode();
        let decoded = Invoice::tlv_decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_pending_invoice_tlv_roundtrip() {
        let pk = test_pubkey();
        let descriptor = format!("pk({})", hex::encode(pk.serialize()));
        let deposit_id = compute_deposit_id(&descriptor);
        let original = PendingInvoice {
            amount: 50_000,
            payment_hash: [0xcd; 32],
            expires: 1700001000,
            assigned_deposit: deposit_id,
            invoice_id: "pending-456".to_string(),
            bolt11: "lnbc1...".to_string(),
        };
        let encoded = original.tlv_encode();
        let decoded = PendingInvoice::tlv_decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_deposit_tlv_roundtrip() {
        let pk = test_pubkey();
        let descriptor = format!("pk({})", hex::encode(pk.serialize()));
        let deposit_id = compute_deposit_id(&descriptor);
        let original = Deposit {
            deposit_id,
            descriptor,
            balance: 1_000_000,
            locked_balance: 50_000,
            invoices: vec![Invoice {
                id: "inv1".to_string(),
                payment_hash: [0x11; 32],
                amount: 10_000,
                expires: 1700000000,
                assigned_deposit: deposit_id,
                bolt11: "lnbc10n1...".to_string(),
            }],
            fees: FeeStructure::new(100, 25, 2016),
            last_fee_assessment: 800_000,
            transfer_fees: TransferFeeSchedule::default(),
            receive_requires_sig: false,
            fee_change_after_blocks: Some(52560),
            fee_change_notice_blocks: Some(2016),
            fee_change_limit_bps: Some(1000),
            opened_at_block: 100,
            pending_fee_change: None,
        };
        let encoded = original.tlv_encode();
        let decoded = Deposit::tlv_decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_reserves_output_tlv_roundtrip() {
        let pk = test_pubkey();
        let original = ReservesOutput {
            channel_id: [0x42; 32],
            amount: 5_000_000,
            spend_to: pk,
        };
        let encoded = original.tlv_encode();
        let decoded = ReservesOutput::tlv_decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    // ========================================================================
    // Dispute State Tests
    // ========================================================================

    #[test]
    fn test_dispute_state_allows_operations() {
        // Normal state
        assert!(DisputeState::Normal.allows_operations());
        assert!(DisputeState::Normal.allows_operation(10)); // Some random op
        assert!(!DisputeState::Normal.allows_operation(55)); // DisputeAcquire
        assert!(!DisputeState::Normal.allows_operation(56)); // DisputeYield
        assert!(!DisputeState::Normal.allows_operation(57)); // DisputeArmed

        // Disputed state - only QuorumAddMember(43) and DisputeArmed(57)
        assert!(DisputeState::Disputed.allows_operations());
        assert!(DisputeState::Disputed.allows_operation(43)); // QuorumAddMember
        assert!(DisputeState::Disputed.allows_operation(57)); // DisputeArmed
        assert!(!DisputeState::Disputed.allows_operation(10)); // Random op blocked
        assert!(!DisputeState::Disputed.allows_operation(55)); // DisputeAcquire

        // Armed state - only DisputeAcquire(55) or DisputeYield(56)
        assert!(DisputeState::Armed.allows_operations());
        assert!(DisputeState::Armed.allows_operation(55)); // DisputeAcquire
        assert!(DisputeState::Armed.allows_operation(56)); // DisputeYield
        assert!(!DisputeState::Armed.allows_operation(43)); // QuorumAddMember blocked
        assert!(!DisputeState::Armed.allows_operation(57)); // DisputeArmed blocked

        // Tombstoned - nothing allowed
        assert!(!DisputeState::Tombstoned.allows_operations());
        assert!(!DisputeState::Tombstoned.allows_operation(55));
        assert!(!DisputeState::Tombstoned.allows_operation(56));
    }

    #[test]
    fn test_entropy_selection_deterministic() {
        let entropy_hash = [0x42u8; 32];

        let secp = bitcoin::secp256k1::Secp256k1::new();
        let pk1 = PublicKey::from_secret_key(
            &secp,
            &bitcoin::secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap(),
        );
        let pk2 = PublicKey::from_secret_key(
            &secp,
            &bitcoin::secp256k1::SecretKey::from_slice(&[2u8; 32]).unwrap(),
        );
        let pk3 = PublicKey::from_secret_key(
            &secp,
            &bitcoin::secp256k1::SecretKey::from_slice(&[3u8; 32]).unwrap(),
        );

        let candidates = vec![pk1, pk2, pk3];

        // Selection should be deterministic
        let winner1 = select_entropy_winner(&entropy_hash, &candidates);
        let winner2 = select_entropy_winner(&entropy_hash, &candidates);
        assert_eq!(winner1, winner2);

        // Order shouldn't matter
        let reversed = vec![pk3, pk2, pk1];
        let winner3 = select_entropy_winner(&entropy_hash, &reversed);
        assert_eq!(winner1, winner3);
    }

    #[test]
    fn test_entropy_selection_different_hashes() {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let pk1 = PublicKey::from_secret_key(
            &secp,
            &bitcoin::secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap(),
        );
        let pk2 = PublicKey::from_secret_key(
            &secp,
            &bitcoin::secp256k1::SecretKey::from_slice(&[2u8; 32]).unwrap(),
        );

        let candidates = vec![pk1, pk2];

        // Different entropy hashes should (usually) produce different winners
        let hash1 = [0x01u8; 32];
        let hash2 = [0x02u8; 32];

        // Note: It's possible both produce the same winner, but unlikely
        // Just verify both return Some
        assert!(select_entropy_winner(&hash1, &candidates).is_some());
        assert!(select_entropy_winner(&hash2, &candidates).is_some());
    }

    #[test]
    fn test_is_entropy_winner() {
        let entropy_hash = [0x42u8; 32];

        let secp = bitcoin::secp256k1::Secp256k1::new();
        let pk1 = PublicKey::from_secret_key(
            &secp,
            &bitcoin::secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap(),
        );
        let pk2 = PublicKey::from_secret_key(
            &secp,
            &bitcoin::secp256k1::SecretKey::from_slice(&[2u8; 32]).unwrap(),
        );

        let candidates = vec![pk1, pk2];
        let winner = select_entropy_winner(&entropy_hash, &candidates).unwrap();

        // Winner should report as winner
        assert!(is_entropy_winner(&entropy_hash, &winner, &candidates));

        // Loser should not report as winner
        let loser = if winner == pk1 { pk2 } else { pk1 };
        assert!(!is_entropy_winner(&entropy_hash, &loser, &candidates));
    }

    #[test]
    fn test_entropy_selection_empty() {
        let entropy_hash = [0x42u8; 32];
        let candidates: Vec<PublicKey> = vec![];

        assert!(select_entropy_winner(&entropy_hash, &candidates).is_none());
    }
}
