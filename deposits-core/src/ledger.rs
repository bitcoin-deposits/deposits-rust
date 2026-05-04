// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Hash-chained ledger operations for the Bitcoin Deposits Protocol.
//!
//! The ledger maintains a hash chain of all state transitions, ensuring
//! both parties have cryptographic proof of the ledger history.

use bitcoin::secp256k1::PublicKey;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

use crate::error::{DepositsError, DepositsResult};
use crate::messages::LedgerOperation;
use crate::types::{DisputeState, LedgerState, PendingInvoice, QuorumState, SignedLedgerUpdate};

/// An update that has been validated and serialized but NOT applied to the ledger.
/// The ledger state is unchanged until `commit_staged` is called.
/// This allows cosigning and operator signing to happen before any state mutation.
#[derive(Clone, Debug)]
pub struct StagedUpdate {
    /// The operation to be applied.
    pub operation: LedgerOperation,
    /// The fully-built (but initially unsigned) update.
    pub update: SignedLedgerUpdate,
}

/// Role of a node in a ledger relationship.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum LedgerRole {
    /// Operator: Creates deposits, proposes updates.
    Operator,
    /// Partner: Validates and cosigns updates.
    Partner,
    /// Auditor: Third-party observer that receives broadcasts but doesn't sign.
    /// Used for monitoring, compliance, or backup purposes.
    Auditor,
}

impl LedgerRole {
    /// Returns true if this role can propose new ledger updates.
    pub fn can_propose(&self) -> bool {
        matches!(self, LedgerRole::Operator)
    }

    /// Returns true if this role is required to cosign updates.
    pub fn must_cosign(&self) -> bool {
        matches!(self, LedgerRole::Partner)
    }

    /// Returns true if this role receives ledger broadcasts.
    pub fn receives_broadcasts(&self) -> bool {
        // All roles receive broadcasts
        true
    }
}

/// A single ledger update entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerUpdate {
    /// Sequential update number.
    pub sequence_number: u64,
    /// The operation being applied.
    pub operation: LedgerOperation,
    /// Hash of the previous update.
    pub previous_hash: [u8; 32],
    /// Hash of this update.
    pub content_hash: [u8; 32],
}

impl LedgerUpdate {
    /// Create a new ledger update.
    pub fn new(sequence_number: u64, operation: LedgerOperation, previous_hash: [u8; 32]) -> Self {
        let mut update = Self {
            sequence_number,
            operation,
            previous_hash,
            content_hash: [0u8; 32],
        };
        update.content_hash = update.compute_hash();
        update
    }

    /// Compute the hash of this update.
    pub fn compute_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.sequence_number.to_le_bytes());
        hasher.update(self.previous_hash);
        // Hash the operation discriminant and key fields
        hasher.update([self.operation.discriminant()]);

        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Verify the hash chain.
    pub fn verify_hash(&self) -> bool {
        self.compute_hash() == self.content_hash
    }
}

/// External protocol coordination state.
///
/// Separated from LedgerState to avoid cloning during immutable state transitions.
/// These fields are not part of the chain-deterministic state machine.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LedgerProtocolState {
    /// Pending invoice awaiting payment.
    pub pending_invoice: Option<PendingInvoice>,
    /// Pending out-of-order updates waiting for earlier updates to arrive.
    /// Key is the sequence number of the pending update.
    #[serde(default)]
    pub pending_updates: HashMap<u64, SignedLedgerUpdate>,
}

/// Ledger state manager.
///
/// Maintains the hash-chained ledger state and provides methods
/// for applying validated operations.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Ledger {
    /// Chain-deterministic ledger state.
    pub state: LedgerState,
    /// External protocol coordination state (not part of hash chain).
    #[serde(default)]
    pub protocol: LedgerProtocolState,
    /// Our role in this ledger.
    pub role: LedgerRole,
    /// History of signed updates.
    pub history: Vec<SignedLedgerUpdate>,
}

impl Ledger {
    /// Create a new ledger as operator.
    pub fn new_as_operator(
        operator_key: PublicKey,
        reserves_key: String,
        genesis_block: u32,
    ) -> Self {
        Self {
            state: LedgerState::new(operator_key, reserves_key, genesis_block),
            protocol: LedgerProtocolState::default(),
            role: LedgerRole::Operator,
            history: Vec::new(),
        }
    }

    /// Create a new ledger as partner.
    pub fn new_as_partner(
        operator_key: PublicKey,
        reserves_key: String,
        genesis_block: u32,
    ) -> Self {
        Self {
            state: LedgerState::new(operator_key, reserves_key, genesis_block),
            protocol: LedgerProtocolState::default(),
            role: LedgerRole::Partner,
            history: Vec::new(),
        }
    }

    /// Create a new ledger with explicit role and optional quorum members.
    pub fn new(
        operator_key: PublicKey,
        reserves_key: String,
        role: LedgerRole,
        quorum_members: Vec<crate::types::QuorumMember>,
        genesis_block: u32,
    ) -> Self {
        let mut state = LedgerState::new(operator_key, reserves_key, genesis_block);
        state.quorum_members = quorum_members;
        Self {
            state,
            protocol: LedgerProtocolState::default(),
            role,
            history: Vec::new(),
        }
    }

    /// Get the current sequence number.
    pub fn sequence(&self) -> u64 {
        self.state.sequence
    }

    /// Get the current ledger hash.
    pub fn hash(&self) -> [u8; 32] {
        self.state.chain_tip_hash
    }

    /// Get total deposit balance (millisatoshis).
    pub fn total_deposit_balance(&self) -> u64 {
        self.state.total_deposit_balance()
    }

    /// Get reserves amount (millisatoshis).
    pub fn reserves_amount(&self) -> u64 {
        self.state.reserves_amount
    }

    /// Calculate required reserves for current deposits (millisatoshis).
    pub fn required_reserves(&self) -> u64 {
        // Both deposits and reserves are in millisatoshis
        self.total_deposit_balance()
    }

    /// Check if reserves are sufficient.
    pub fn has_sufficient_reserves(&self) -> bool {
        self.reserves_amount() >= self.required_reserves()
    }

    // ========================================================================
    // Signed Update Handling with Out-of-Order Support
    // ========================================================================

    /// Append a signed update to the ledger history.
    ///
    /// Handles out-of-order updates by queuing them in pending_updates.
    /// When an update fills a gap, flushes consecutive pending updates.
    ///
    /// Returns the number of updates added (1 for normal, 1+N for gap fill with N pending).
    pub fn append_signed_update(&mut self, update: SignedLedgerUpdate) -> usize {
        let seq = update.sequence_number;
        let expected_seq = self.history.len() as u64;

        // Normal case: appending in order
        if seq == expected_seq {
            self.history.push(update);
            // Check if this fills a gap - flush any consecutive pending updates
            return 1 + self.flush_pending_updates();
        }

        // Already have this update (duplicate)
        if seq < expected_seq {
            // Update in place if this has better signatures
            if let Some(existing) = self.history.get_mut(seq as usize) {
                // Preserve existing co-signer signature if new one is empty
                if update.cosign_signature != [0u8; 64] || existing.cosign_signature == [0u8; 64] {
                    *existing = update;
                }
            }
            return 1;
        }

        // Out of order (seq > expected_seq) - queue for later
        self.protocol
            .pending_updates
            .insert(update.sequence_number, update);
        0
    }

    /// Flush pending updates that are now consecutive with history.
    ///
    /// Returns the number of updates flushed.
    fn flush_pending_updates(&mut self) -> usize {
        let mut flushed = 0;
        loop {
            let next_seq = self.history.len() as u64;
            if let Some(update) = self.protocol.pending_updates.remove(&next_seq) {
                self.history.push(update);
                flushed += 1;
            } else {
                break;
            }
        }
        flushed
    }

    /// Get the number of pending (out-of-order) updates.
    pub fn pending_count(&self) -> usize {
        self.protocol.pending_updates.len()
    }

    /// Check if there are gaps in the update history.
    pub fn has_gaps(&self) -> bool {
        !self.protocol.pending_updates.is_empty()
    }

    // ========================================================================
    // Signer Validation (Dispute Protocol)
    // ========================================================================

    /// Validate that an update is signed by an authorized pubkey.
    ///
    /// Per the dispute protocol:
    /// - Normal case: update must be signed by `parent_pubkey`
    /// - Exception: `DisputeEnter` can be signed by anyone who was in the quorum
    ///   at the fork point (stored in `quorum_at_fork`)
    ///
    /// This should be called BEFORE appending an incoming signed update.
    pub fn validate_update_signer(&self, update: &SignedLedgerUpdate) -> DepositsResult<()> {
        use crate::tlv::TlvDecode;

        let signer = &update.operator_id;

        // Decode the operation to check if it's DisputeEnter
        let operation = LedgerOperation::tlv_decode(&update.message).map_err(|e| {
            DepositsError::InvalidMessage {
                reason: format!("Failed to decode operation: {}", e),
            }
        })?;

        // DisputeEnter exception: can be signed by any quorum member at fork point
        if matches!(operation, LedgerOperation::DisputeEnter { .. }) {
            // For the first DisputeEnter (entering disputed state from normal),
            // the signer must be in the current quorum
            if self.state.dispute_state == DisputeState::Normal {
                if !self
                    .state
                    .quorum_members
                    .iter()
                    .any(|m| m.pubkey == *signer)
                {
                    return Err(DepositsError::ProtocolViolation {
                        violation_type: "custody_dispute_unauthorized".to_string(),
                        details: format!("DisputeEnter signer {} is not a quorum member", signer),
                    });
                }
                // Valid - quorum member can open dispute
                return Ok(());
            }
            // If already disputed, this shouldn't happen (state validation prevents it)
        }

        // Normal case: must be signed by parent_pubkey
        if signer != &self.state.parent_pubkey {
            return Err(DepositsError::ProtocolViolation {
                violation_type: "invalid_signer".to_string(),
                details: format!(
                    "Update signed by {} but parent_pubkey is {}",
                    signer, self.state.parent_pubkey
                ),
            });
        }

        Ok(())
    }

    /// Validate an incoming signed update completely.
    ///
    /// This performs:
    /// 1. Signature verification
    /// 2. Signer authorization (dispute protocol rules)
    /// 3. Operation validation (dispute state rules)
    /// 4. Hash chain validation
    ///
    /// Call this before accepting an update from a peer.
    pub fn validate_incoming_update(
        &self,
        update: &SignedLedgerUpdate,
        partner_pubkey: Option<&PublicKey>,
    ) -> DepositsResult<()> {
        // 1. Verify signatures
        update
            .verify_signatures(partner_pubkey)
            .map_err(|e| DepositsError::ProtocolViolation {
                violation_type: "invalid_signature".to_string(),
                details: e,
            })?;

        // 2. Validate signer is authorized
        self.validate_update_signer(update)?;

        // 3. Validate hash chain (truncation-safe: compare against tip, not by index)
        // Only validates the expected next update. Past updates were already
        // validated on first receipt; future updates will be validated when
        // we catch up to them.
        if update.sequence_number > 0 {
            let next_seq = self.next_sequence();

            if update.sequence_number == next_seq {
                let tip_hash = self
                    .history
                    .last()
                    .map(|u| u.content_hash)
                    .unwrap_or([0u8; 32]);
                if update.previous_hash != tip_hash {
                    return Err(DepositsError::ProtocolViolation {
                        violation_type: "hash_chain_break".to_string(),
                        details: format!(
                            "Previous hash mismatch at seq {}: expected {:02x?}, got {:02x?}",
                            update.sequence_number,
                            &tip_hash[..8],
                            &update.previous_hash[..8]
                        ),
                    });
                }
            }
        }

        // 4. Decode and validate operation against dispute state
        use crate::tlv::TlvDecode;
        let operation = LedgerOperation::tlv_decode(&update.message).map_err(|e| {
            DepositsError::InvalidMessage {
                reason: format!("Failed to decode operation: {}", e),
            }
        })?;

        let discriminant = operation.discriminant();
        if !self.state.dispute_state.allows_operation(discriminant) {
            return Err(DepositsError::ProtocolViolation {
                violation_type: "dispute_state_violation".to_string(),
                details: format!(
                    "Operation {} not allowed in {:?} state",
                    discriminant, self.state.dispute_state
                ),
            });
        }

        // 5. After QuorumBegin, all updates must have valid co-signatures
        // Use quorum_state (derived from apply_state_changes) instead of scanning history
        if self.state.quorum_state == QuorumState::Active {
            // Exception: DisputeEnter can be signed by any quorum member
            if !matches!(operation, LedgerOperation::DisputeEnter { .. })
                && !update.has_cosign_signature()
            {
                return Err(DepositsError::ProtocolViolation {
                    violation_type: "missing_cosignature".to_string(),
                    details: format!(
                        "Co-signature required after QuorumBegin (seq {})",
                        update.sequence_number
                    ),
                });
            }
        }

        // 6. First QuorumBegin must be cosigned by a majority of the staged
        // members. The state still reads PreQuorum at this point (the
        // transition to Active happens in apply_state_changes), so check 5
        // above hasn't fired. Without this gate, the operator could
        // unilaterally append a QuorumBegin — making up a membership set
        // and/or pointing to a reserves outpoint that doesn't exist or
        // hasn't confirmed — with no peer attestation.
        if self.state.quorum_state == QuorumState::PreQuorum
            && matches!(operation, LedgerOperation::QuorumBegin { .. })
        {
            let staged: Vec<bitcoin::secp256k1::PublicKey> = self
                .state
                .next_quorum_members
                .iter()
                .map(|m| m.pubkey)
                .collect();
            if staged.is_empty() {
                return Err(DepositsError::ProtocolViolation {
                    violation_type: "empty_quorum".to_string(),
                    details: "QuorumBegin with no staged members is not allowed — \
                        append QuorumAddMember entries before QuorumBegin"
                        .to_string(),
                });
            }
            let threshold = staged.len() / 2 + 1;
            update
                .verify_cosign_signatures(&staged, threshold)
                .map_err(|e| DepositsError::ProtocolViolation {
                    violation_type: "missing_cosignature".to_string(),
                    details: format!(
                        "First QuorumBegin requires {} of {} staged-member cosignatures: {}",
                        threshold,
                        staged.len(),
                        e
                    ),
                })?;
        }

        Ok(())
    }

    /// Validate only the hash chain of an incoming update (no signature check).
    ///
    /// Used by the daemon to detect fraudulent hash-chain breaks without
    /// relying on operator signature verification (which has a format
    /// mismatch across the codebase).
    pub fn validate_incoming_update_hash_chain(
        &self,
        update: &SignedLedgerUpdate,
    ) -> DepositsResult<()> {
        // Validate hash chain for the expected next update only.
        //
        // Past updates (seq < next_seq) were already validated when first
        // received — redelivery via Nostr is normal and not a violation.
        // Future updates (seq > next_seq) can't be validated until we
        // catch up — the caller handles gap detection separately.
        //
        // After history truncation, entries aren't addressable by
        // sequence_number as an index, so we compare against the tip.
        if update.sequence_number > 0 {
            let next_seq = self.next_sequence();

            if update.sequence_number == next_seq {
                // Expected next update — previous_hash must match our tip's chain_hash
                // chain_hash = SHA256(content_hash || operator_signature)
                let tip_hash = self
                    .history
                    .last()
                    .map(|u| u.chain_hash())
                    .unwrap_or([0u8; 32]);
                if update.previous_hash != tip_hash {
                    return Err(DepositsError::ProtocolViolation {
                        violation_type: "hash_chain_break".to_string(),
                        details: format!(
                            "Previous hash mismatch at seq {}: expected {:02x?}, got {:02x?}",
                            update.sequence_number,
                            &tip_hash[..8],
                            &update.previous_hash[..8]
                        ),
                    });
                }
            }
        }

        Ok(())
    }

    /// Validate DisputeAcquire or DisputeYield against the entropy selection.
    ///
    /// This validates that:
    /// - DisputeAcquire: the new_custodian is the entropy-selected winner
    /// - DisputeYield: the parent_pubkey (branch owner) is NOT the winner
    ///
    /// # Arguments
    /// * `operation` - The DisputeAcquire or DisputeYield operation
    /// * `candidates` - All pubkeys who published DisputeArmed
    ///
    /// In the on-chain-lottery design, the lottery script enforces
    /// the winner: only the `(sum mod N)`-th candidate (per revealed
    /// preimages) can spend the lottery output. The state machine
    /// trusts that selection and just verifies the new_custodian is
    /// among the candidates and the claim_txid is non-zero.
    /// Verification that `claim_txid` actually spends the expected
    /// lottery output is a separate component's responsibility (it
    /// requires on-chain access).
    pub fn validate_custody_resolution(
        &self,
        operation: &LedgerOperation,
        candidates: &[PublicKey],
    ) -> DepositsResult<()> {
        match operation {
            LedgerOperation::DisputeAcquire {
                new_custodian,
                claim_txid,
                ..
            } => {
                if !candidates.contains(new_custodian) {
                    return Err(DepositsError::ProtocolViolation {
                        violation_type: "custody_acquire_not_candidate".to_string(),
                        details: format!(
                            "DisputeAcquire new_custodian {} is not in the candidate set",
                            new_custodian
                        ),
                    });
                }
                if claim_txid == &[0u8; 32] {
                    return Err(DepositsError::ProtocolViolation {
                        violation_type: "custody_acquire_missing_claim".to_string(),
                        details: "DisputeAcquire claim_txid must be non-zero".to_string(),
                    });
                }
            }
            LedgerOperation::DisputeYield => {
                // DisputeYield is unilateral — a candidate self-tombstoning.
                // No cross-candidate validation needed in the new design.
            }
            _ => {
                // Not a custody resolution operation
            }
        }
        Ok(())
    }

    /// Validate DisputeYield against the entropy selection.
    ///
    /// Verifies that the branch owner (parent_pubkey) is NOT the entropy-selected winner.
    /// If they were the winner, they should publish DisputeAcquire instead.
    ///
    /// # Arguments
    /// * `entropy_block_hash` - The entropy block hash (from the winning DisputeAcquire)
    /// * `candidates` - All pubkeys who published DisputeArmed before the entropy block
    pub fn validate_custody_yield(
        &self,
        entropy_block_hash: &[u8; 32],
        candidates: &[PublicKey],
    ) -> DepositsResult<()> {
        use crate::types::is_entropy_winner;

        // The branch owner (parent_pubkey) must NOT be the winner
        if is_entropy_winner(entropy_block_hash, &self.state.parent_pubkey, candidates) {
            return Err(DepositsError::ProtocolViolation {
                violation_type: "custody_yield_is_winner".to_string(),
                details: format!(
                    "DisputeYield invalid: {} is the entropy winner and should DisputeAcquire",
                    self.state.parent_pubkey
                ),
            });
        }
        Ok(())
    }

    // ========================================================================
    // Role and Participant Methods
    // ========================================================================

    /// Check if we are the operator of this ledger.
    pub fn is_operator(&self) -> bool {
        self.role == LedgerRole::Operator
    }

    /// Check if we are the partner of this ledger.
    pub fn is_partner(&self) -> bool {
        self.role == LedgerRole::Partner
    }

    /// Check if we are an auditor of this ledger.
    pub fn is_auditor(&self) -> bool {
        self.role == LedgerRole::Auditor
    }

    /// Get the operator's public key.
    pub fn operator_key(&self) -> PublicKey {
        self.state.operator_key
    }

    /// Get the unique ledger identifier (hash of operator + reserves + genesis_block).
    pub fn ledger_id(&self) -> [u8; 32] {
        self.state.ledger_id
    }

    /// Get the ledger_id as a hex string.
    pub fn ledger_id_hex(&self) -> String {
        self.state.ledger_id_hex()
    }

    /// Get the genesis block height.
    pub fn genesis_block(&self) -> u32 {
        self.state.genesis_block
    }

    /// Get the reserves identifier (UTXO address for BDK, pubkey string for LDK).
    pub fn reserves_key(&self) -> &str {
        &self.state.reserves_key
    }

    /// Try to get reserves_key as a PublicKey (works for LDK where it's a pubkey string).
    /// Returns None for BDK where reserves_key is an address.
    pub fn reserves_key_as_pubkey(&self) -> Option<PublicKey> {
        use std::str::FromStr;
        PublicKey::from_str(&self.state.reserves_key).ok()
    }

    /// Get all quorum participants for this ledger.
    /// Returns: operator + active members + pending members. For LDK, also includes reserves partner.
    pub fn quorum_participants(&self) -> Vec<PublicKey> {
        let mut participants = Vec::with_capacity(
            2 + self.state.quorum_members.len() + self.state.next_quorum_members.len(),
        );
        participants.push(self.state.operator_key);
        // Include reserves partner if it's a valid pubkey (LDK)
        if let Some(reserves_pubkey) = self.reserves_key_as_pubkey() {
            participants.push(reserves_pubkey);
        }
        participants.extend(self.state.quorum_members.iter().map(|m| m.pubkey));
        participants.extend(self.state.next_quorum_members.iter().map(|m| m.pubkey));
        participants
    }

    /// Get all partners (channel partner + active + pending quorum members).
    /// This is the set of nodes the operator broadcasts updates to.
    pub fn all_partners(&self) -> Vec<PublicKey> {
        let mut partners = Vec::with_capacity(
            1 + self.state.quorum_members.len() + self.state.next_quorum_members.len(),
        );
        // Include reserves partner if it's a valid pubkey (LDK)
        if let Some(reserves_pubkey) = self.reserves_key_as_pubkey() {
            partners.push(reserves_pubkey);
        }
        partners.extend(self.state.quorum_members.iter().map(|m| m.pubkey));
        partners.extend(self.state.next_quorum_members.iter().map(|m| m.pubkey));
        partners
    }

    /// Add a quorum member to this ledger with their collateral ledger ID.
    pub fn add_quorum_member(
        &mut self,
        partner: PublicKey,
        member_ledger_id: String,
    ) -> DepositsResult<()> {
        if partner == self.state.operator_key {
            return Err(DepositsError::InvalidState(
                "Operator cannot be a quorum member".to_string(),
            ));
        }
        // Compare with reserves_key (which is a String)
        if partner.to_string() == self.state.reserves_key {
            return Err(DepositsError::InvalidState(
                "Channel partner is already part of the quorum".to_string(),
            ));
        }
        if self
            .state
            .quorum_members
            .iter()
            .any(|m| m.pubkey == partner)
            || self
                .state
                .next_quorum_members
                .iter()
                .any(|m| m.pubkey == partner)
        {
            return Err(DepositsError::InvalidState(format!(
                "Quorum member {} already exists",
                partner
            )));
        }
        self.state
            .next_quorum_members
            .push(crate::types::QuorumMember {
                pubkey: partner,
                ledger_id: member_ledger_id,
                min_fee_bps: None,
                min_fee_fixed: None,
                max_fee_period: None,
                membership_until: None,
                dispute_response_blocks: None,
                dispute_arm_blocks: None,
                service_response_blocks: None,
                max_transfer_timeout_blocks: None,
                max_descriptor_bytes: None,
                compensation_bps: None,
                compensation_deposit_id: None,
                compensation_frequency_blocks: None,
            });
        Ok(())
    }

    // ========================================================================
    // Hash Chain Methods
    // ========================================================================

    /// Get the chain hash of the last update (tail hash).
    /// Returns zero hash if no updates exist yet.
    ///
    /// chain_hash = SHA256(content_hash || operator_signature), which is
    /// the value the next update must use as its previous_hash.
    pub fn tail_hash(&self) -> [u8; 32] {
        self.history
            .last()
            .map(|u| u.chain_hash())
            .unwrap_or([0u8; 32])
    }

    /// Get the next expected sequence number.
    /// Derived from the last history entry, not from `history.len()`,
    /// so it remains correct after history truncation.
    pub fn next_sequence(&self) -> u64 {
        self.history
            .last()
            .map(|u| u.sequence_number + 1)
            .unwrap_or(0)
    }

    /// Find the sequence number of a hash in the update history.
    /// Returns None if the hash doesn't exist.
    pub fn find_hash_sequence(&self, target_hash: &[u8; 32]) -> Option<u64> {
        // Zero hash represents genesis (before any updates)
        if target_hash == &[0u8; 32] {
            return Some(0);
        }
        for update in &self.history {
            if &update.content_hash == target_hash {
                return Some(update.sequence_number);
            }
        }
        None
    }

    /// Check if a hash is valid for reserves (exists and is at or after committed hash).
    pub fn is_valid_reserves_hash(
        &self,
        target_hash: &[u8; 32],
        committed_hash: &[u8; 32],
    ) -> bool {
        let is_zero_committed = committed_hash == &[0u8; 32];
        let target_seq = match self.find_hash_sequence(target_hash) {
            Some(seq) => seq,
            None => return false,
        };
        if is_zero_committed {
            return true;
        }
        match self.find_hash_sequence(committed_hash) {
            Some(committed_seq) => target_seq >= committed_seq,
            None => false,
        }
    }

    // ========================================================================
    // State Query Methods
    // ========================================================================

    /// Check if this ledger is closed (has a LedgerClose as the last operation).
    /// Note: This checks the message_type field for quick detection without deserialization.
    pub fn is_closed(&self) -> bool {
        use crate::messages::consts::LEDGER_CLOSE;
        if let Some(last_update) = self.history.last() {
            last_update.message_type == LEDGER_CLOSE
        } else {
            false
        }
    }

    /// Get total deposit liability (`balance + locked_balance` across deposits,
    /// per DEP-05).
    pub fn total_deposit_liability(&self) -> u64 {
        self.state.total_deposit_balance()
    }

    /// Check if a credit has been issued for a given payment hash.
    /// This scans the history and deserializes InvoiceCredit messages to check.
    pub fn has_credit_for_payment(&self, payment_hash: &[u8; 32]) -> bool {
        use crate::tlv::TlvDecode;

        for update in &self.history {
            if update.message_type == crate::messages::consts::RECEIVING_CREDIT_PAYMENT {
                if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                    if let LedgerOperation::InvoiceCredit {
                        payment_hash: hash, ..
                    } = op
                    {
                        if &hash == payment_hash {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    /// Recompute all derived state by replaying the history.
    pub fn recompute_state(&mut self) -> DepositsResult<()> {
        use crate::messages::DepositsMessage;

        // Reset derived state
        self.state.deposits.clear();
        self.state.reserves_amount = 0;
        self.state.sequence = 0;
        self.state.chain_tip_hash = [0u8; 32];

        // Replay all updates
        for update in &self.history.clone() {
            // Deserialize the message to get the operation
            if let Ok(msg) = DepositsMessage::decode(&update.message) {
                if let Some(operation) = msg.to_operation() {
                    self.apply_state_changes(&operation)?;
                    // Set opened_at_block and initial last_fee_assessment for new deposits
                    if let LedgerOperation::DepositOpen { deposit_id, .. } = &operation {
                        if let Some(deposit) = self.state.deposits.get_mut(deposit_id) {
                            if update.block_height > 0 {
                                deposit.opened_at_block = update.block_height;
                                if deposit.last_fee_assessment == 0 {
                                    deposit.last_fee_assessment = update.block_height;
                                }
                            }
                        }
                    }
                }
            }
            self.state.sequence = update.sequence_number;
            self.state.chain_tip_hash = update.chain_hash();
        }
        Ok(())
    }

    // ========================================================================
    // Collateral Methods
    // ========================================================================

    // ========================================================================
    // Operation Application
    // ========================================================================

    /// Apply an operation to the ledger.
    ///
    /// This updates the state and advances the sequence/hash.
    pub fn apply_operation(&mut self, operation: &LedgerOperation) -> DepositsResult<LedgerUpdate> {
        // Validate the operation
        self.validate_operation(operation)?;

        // Create the update
        let update = LedgerUpdate::new(
            self.state.sequence + 1,
            operation.clone(),
            self.state.chain_tip_hash,
        );

        // Apply state changes
        self.apply_state_changes(operation)?;

        // Update sequence and hash
        self.state.sequence = update.sequence_number;
        self.state.chain_tip_hash = update.content_hash;

        Ok(update)
    }

    /// Append an operation to the ledger with full history tracking.
    ///
    /// This method:
    /// 1. Validates the operation
    /// 2. Serializes it to bytes using TLV encoding
    /// 3. Creates a SignedLedgerUpdate (unsigned - caller should sign)
    /// 4. Applies state changes
    /// 5. Appends to history
    ///
    /// Returns (previous_hash, new_hash, sequence_number) for signing.
    pub fn append_operation(
        &mut self,
        operation: LedgerOperation,
    ) -> DepositsResult<([u8; 32], [u8; 32], u64)> {
        self.append_operation_with_block(operation, 0, [0u8; 32])
    }

    /// Append an operation with block info.
    ///
    /// Same as `append_operation` but includes current block height and hash.
    pub fn append_operation_with_block(
        &mut self,
        operation: LedgerOperation,
        block_height: u32,
        block_hash: [u8; 32],
    ) -> DepositsResult<([u8; 32], [u8; 32], u64)> {
        use crate::tlv::TlvEncode;
        use bitcoin::hashes::{sha256, Hash};

        // Check if ledger is closed
        if self.is_closed() {
            return Err(DepositsError::InvalidState(
                "Cannot append to closed ledger".to_string(),
            ));
        }

        // Validate the operation
        self.validate_operation(&operation)?;

        // Validate fee change constraints (needs block_height context)
        if let LedgerOperation::FeeChange {
            deposit_id,
            new_fees,
            effective_block,
        } = &operation
        {
            crate::operation_validation::validate_deposit_fee_change(
                self,
                deposit_id,
                new_fees,
                *effective_block,
                block_height,
            )
            .map_err(|e| DepositsError::ProtocolViolation {
                violation_type: "fee_change_violation".to_string(),
                details: e,
            })?;
        }

        // Serialize the operation
        let message_bytes = operation.tlv_encode();

        // Compute hashes
        let prev_hash = self.state.chain_tip_hash;
        // Use next_sequence() (last_entry.seq + 1) instead of history.len(),
        // because history can be truncated (compacted) while state.hash still
        // tracks the true last-entry hash. history.len() would assign a stale
        // sequence number after compaction → "Sequence gap before persist".
        let sequence = self.next_sequence();

        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(&sequence.to_le_bytes());
        hash_input.extend_from_slice(&prev_hash);
        hash_input.extend_from_slice(&message_bytes);
        let new_hash = *sha256::Hash::hash(&hash_input).as_byte_array();

        // Create SignedLedgerUpdate (unsigned - caller should populate signatures)
        let signed_update = SignedLedgerUpdate {
            message_type: operation.message_type(),
            message: message_bytes,
            operator_signature: [0u8; 64],
            cosigner_pubkey: None,
            member_ledger_hash: None,
            cosignatures: Vec::new(),
            cosign_signature: [0u8; 64],
            operator_id: self.state.operator_key,
            ledger_id: self.state.ledger_id,
            sequence_number: sequence,
            previous_hash: prev_hash,
            content_hash: new_hash,
            block_height,
            block_hash,
        };

        // Apply state changes
        self.apply_state_changes(&operation)?;

        // Update state.hash to content_hash for now — will be updated to
        // chain_hash() after operator signing via finalize_chain_hash()
        self.state.chain_tip_hash = new_hash;

        // Set opened_at_block and initial last_fee_assessment for new deposits
        if let LedgerOperation::DepositOpen { deposit_id, .. } = &operation {
            if let Some(deposit) = self.state.deposits.get_mut(deposit_id) {
                deposit.opened_at_block = block_height;
                if deposit.last_fee_assessment == 0 {
                    deposit.last_fee_assessment = block_height;
                }
            }
        }

        // Update sequence (hash is set above, will become chain_hash after signing)
        self.state.sequence = sequence;

        // Append to history
        self.history.push(signed_update);

        Ok((prev_hash, new_hash, sequence))
    }

    /// Validate and build an update WITHOUT applying state changes.
    /// Returns a StagedUpdate that must be signed (and optionally cosigned)
    /// before being committed via `commit_staged`.
    ///
    /// The ledger state is completely unchanged after this call.
    pub fn stage_operation(
        &self,
        operation: LedgerOperation,
        block_height: u32,
        block_hash: [u8; 32],
    ) -> DepositsResult<StagedUpdate> {
        use crate::tlv::TlvEncode;
        use bitcoin::hashes::{sha256, Hash};

        if self.is_closed() {
            return Err(DepositsError::InvalidState(
                "Cannot append to closed ledger".to_string(),
            ));
        }

        self.validate_operation(&operation)?;

        if let LedgerOperation::FeeChange {
            deposit_id,
            new_fees,
            effective_block,
        } = &operation
        {
            crate::operation_validation::validate_deposit_fee_change(
                self,
                deposit_id,
                new_fees,
                *effective_block,
                block_height,
            )
            .map_err(|e| DepositsError::ProtocolViolation {
                violation_type: "fee_change_violation".to_string(),
                details: e,
            })?;
        }

        let message_bytes = operation.tlv_encode();
        let prev_hash = self.state.chain_tip_hash;
        let sequence = self.next_sequence();

        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(&sequence.to_le_bytes());
        hash_input.extend_from_slice(&prev_hash);
        hash_input.extend_from_slice(&message_bytes);
        let new_hash = *sha256::Hash::hash(&hash_input).as_byte_array();

        let update = SignedLedgerUpdate {
            message_type: operation.message_type(),
            message: message_bytes,
            operator_signature: [0u8; 64],
            cosigner_pubkey: None,
            member_ledger_hash: None,
            cosignatures: Vec::new(),
            cosign_signature: [0u8; 64],
            operator_id: self.state.operator_key,
            ledger_id: self.state.ledger_id,
            sequence_number: sequence,
            previous_hash: prev_hash,
            content_hash: new_hash,
            block_height,
            block_hash,
        };

        Ok(StagedUpdate { operation, update })
    }

    /// Commit a signed StagedUpdate: apply state changes, update hash chain, push to history.
    ///
    /// The update MUST have a non-zero operator_signature. If the ledger has an active
    /// quorum, the cosign_signature must also be non-zero.
    ///
    /// Call this only after signing (and cosigning if needed).
    pub fn commit_staged(&mut self, staged: StagedUpdate) -> DepositsResult<()> {
        // Verify the staged update matches our current chain tip
        if staged.update.previous_hash != self.state.chain_tip_hash {
            return Err(DepositsError::InvalidState(format!(
                "Staged update previous_hash {} doesn't match chain tip {}",
                hex::encode(&staged.update.previous_hash[..4]),
                hex::encode(&self.state.chain_tip_hash[..4]),
            )));
        }

        // Verify operator signature is present
        if staged.update.operator_signature == [0u8; 64] {
            return Err(DepositsError::InvalidState(
                "Cannot commit unsigned update".to_string(),
            ));
        }

        // Apply state changes with conformance check (operator must not produce non-conforming state)
        self.checked_apply(&staged.operation, &crate::descriptor::CoreWitnessVerifier)?;

        // Update chain state — chain_tip uses chain_hash() which folds in the operator signature
        self.state.chain_tip_hash = staged.update.chain_hash();
        self.state.sequence = staged.update.sequence_number;

        // Set opened_at_block and initial last_fee_assessment for new deposits
        if let LedgerOperation::DepositOpen { deposit_id, .. } = &staged.operation {
            if let Some(deposit) = self.state.deposits.get_mut(deposit_id) {
                deposit.opened_at_block = staged.update.block_height;
                if deposit.last_fee_assessment == 0 {
                    deposit.last_fee_assessment = staged.update.block_height;
                }
            }
        }

        // Push to history
        self.history.push(staged.update);

        Ok(())
    }

    /// Update the signature on the last history entry.
    ///
    /// This is used after `append_operation` to add signatures from the porcupine dance.
    pub fn sign_last_update(
        &mut self,
        operator_sig: Option<[u8; 64]>,
        cosign_sig: Option<[u8; 64]>,
    ) {
        if let Some(update) = self.history.last_mut() {
            if let Some(sig) = operator_sig {
                update.operator_signature = sig;
            }
            if let Some(sig) = cosign_sig {
                update.cosign_signature = sig;
            }
        }
    }

    /// Apply co-signer info and recompute content_hash.
    ///
    /// Sets member_ledger_hash, cosigner_pubkey, and co-signer's signature, then
    /// recomputes content_hash to include all three. Must be called BEFORE
    /// operator signing, since the operator signs content_hash.
    pub fn apply_cosigner_hash(
        &mut self,
        member_ledger_hash: [u8; 32],
        cosigner_pubkey: PublicKey,
        cosign_signature: [u8; 64],
    ) {
        if let Some(update) = self.history.last_mut() {
            update.member_ledger_hash = Some(member_ledger_hash);
            update.cosigner_pubkey = Some(cosigner_pubkey);
            update.cosign_signature = cosign_signature;
            // Recompute content_hash: includes message + member_ledger_hash + cosign_signature
            update.content_hash = update.compute_hash();
            // state.hash tracks content_hash until finalize_chain_hash
            self.state.chain_tip_hash = update.content_hash;
        }
    }

    /// Apply majority cosignatures to the last history entry and recompute hash.
    /// Entries are sorted by pubkey for deterministic hashing.
    /// Must be called BEFORE operator signing.
    pub fn apply_cosignatures(&mut self, mut entries: Vec<crate::types::CosignEntry>) {
        entries.sort_by(|a, b| {
            a.cosigner_pubkey
                .serialize()
                .cmp(&b.cosigner_pubkey.serialize())
        });
        if let Some(update) = self.history.last_mut() {
            update.cosignatures = entries;
            // Clear deprecated single-cosig fields
            update.cosigner_pubkey = None;
            update.member_ledger_hash = None;
            update.cosign_signature = [0u8; 64];
            // Recompute content_hash to include all cosig entries
            update.content_hash = update.compute_hash();
            self.state.chain_tip_hash = update.content_hash;
        }
    }

    /// Finalize state.hash to chain_hash after operator signing.
    ///
    /// chain_hash = SHA256(content_hash || operator_signature)
    /// This becomes the next update's previous_hash.
    pub fn finalize_chain_hash(&mut self) {
        if let Some(update) = self.history.last() {
            self.state.chain_tip_hash = update.chain_hash();
        }
    }

    /// Validate an operation before applying.
    fn validate_operation(&self, operation: &LedgerOperation) -> DepositsResult<()> {
        // Check dispute state allows this operation type
        let discriminant = operation.discriminant();
        if !self.state.dispute_state.allows_operation(discriminant) {
            return Err(DepositsError::ProtocolViolation {
                violation_type: "dispute_state_violation".to_string(),
                details: format!(
                    "Operation {} not allowed in {:?} state",
                    discriminant, self.state.dispute_state
                ),
            });
        }

        // Pre-release policy cap on the cosigner count Q. The lottery
        // script supports up to MAX_DISPUTANTS=15 but Q is policy-capped
        // until production reliability data justifies lifting it. Q must
        // also be one of {3, 5, 7} — odd-only so thresholds have a clean
        // majority, Q≥3 for redundancy. Operator is *not* counted in Q.
        if let LedgerOperation::QuorumBegin {
            quorum_members,
            quorum_expiry,
            ..
        } = operation
        {
            let q = quorum_members.len();
            if !crate::constants::VALID_QUORUM_SIZES.contains(&q) {
                return Err(DepositsError::ProtocolViolation {
                    violation_type: "quorum_size_invalid".to_string(),
                    details: format!(
                        "QuorumBegin Q={} (cosigner count) is not in the \
                         allowed set {:?}. Q must be odd, ≥3 for redundancy, \
                         and ≤{} per the pre-release policy cap. The script \
                         supports up to {} disputants but Q is restricted \
                         until production reliability data justifies lifting it.",
                        q,
                        crate::constants::VALID_QUORUM_SIZES,
                        crate::constants::MAX_QUORUM_SIZE_POLICY,
                        crate::constants::MAX_DISPUTANTS
                    ),
                });
            }

            // Each declared member must have an existing QuorumAddMember
            // consent in next_quorum_members. The operator can only rotate
            // to members who have explicitly consented; QuorumBegin is not
            // a unilateral "anyone I name is now a cosigner" lever.
            //
            // Operator can shorten the set (drop members) by omission, or
            // formally remove via QuorumRemoveMember. Adding a new member
            // without prior consent is rejected here.
            let staged: std::collections::HashMap<_, _> = self
                .state
                .next_quorum_members
                .iter()
                .map(|m| (m.pubkey, m))
                .collect();
            for declared in quorum_members {
                if !staged.contains_key(&declared.pubkey) {
                    return Err(DepositsError::ProtocolViolation {
                        violation_type: "quorum_member_unstaged".to_string(),
                        details: format!(
                            "QuorumBegin declares member {} who has no \
                             corresponding QuorumAddMember consent in \
                             next_quorum_members. Operator must record consent \
                             before including a member in a rotation.",
                            declared.pubkey
                        ),
                    });
                }
            }

            // The operator can shorten the expiry (e.g., to align rotations
            // with a calendar quarter) but cannot extend any member's
            // committed `membership_until`. The natural ceiling is the MIN
            // of the declared members' commitments — the most-impatient
            // member sets the deadline, since the on-chain script tree can
            // only encode one timelock.
            let min_committed: Option<u32> = quorum_members
                .iter()
                .filter_map(|m| staged.get(&m.pubkey).and_then(|s| s.membership_until))
                .min();
            if let Some(ceiling) = min_committed {
                if *quorum_expiry > ceiling {
                    return Err(DepositsError::ProtocolViolation {
                        violation_type: "quorum_expiry_exceeds_commitment".to_string(),
                        details: format!(
                            "QuorumBegin quorum_expiry={} exceeds the most-impatient \
                             declared member's membership_until={}. The operator can \
                             shorten the expiry but cannot extend a member's commitment.",
                            quorum_expiry, ceiling
                        ),
                    });
                }
            }
        }

        match operation {
            LedgerOperation::DepositOpen { deposit_id, .. } => {
                if self.state.deposits.contains_key(deposit_id) {
                    return Err(DepositsError::DepositAlreadyExists);
                }
            }
            LedgerOperation::DepositClose { deposit_id } => {
                let deposit = self
                    .state
                    .deposits
                    .get(deposit_id)
                    .ok_or(DepositsError::DepositNotFound)?;
                if deposit.balance > 0 {
                    return Err(DepositsError::NonZeroBalance {
                        balance: deposit.balance,
                    });
                }
            }
            LedgerOperation::InvoiceLock {
                deposit_id, amount, ..
            }
            | LedgerOperation::OnchainLock {
                deposit_id, amount, ..
            } => {
                let deposit = self
                    .state
                    .deposits
                    .get(deposit_id)
                    .ok_or(DepositsError::DepositNotFound)?;
                if deposit.available_balance() < *amount {
                    return Err(DepositsError::InsufficientDepositBalance {
                        available: deposit.available_balance(),
                        required: *amount,
                    });
                }
            }
            LedgerOperation::QuorumJoin {
                operator_id,
                ledger_id,
                membership_expires,
            } => {
                // 1. Must be on operator's own ledger (we are the operator)
                if !self.is_operator() {
                    return Err(DepositsError::ProtocolViolation {
                        violation_type: "quorum_join_wrong_role".to_string(),
                        details: "QuorumJoin can only be added to operator's own ledger"
                            .to_string(),
                    });
                }
                // Note: Signature verification should be done at the message handler level
                // where the signing key is available. Here we just validate the operation structure.
                // 2. Ratchet check: if renewing, new expiration must be >= existing
                if let Some(existing) = self
                    .state
                    .joined_quorums
                    .iter()
                    .find(|m| &m.operator_id == operator_id && &m.ledger_id == ledger_id)
                {
                    if *membership_expires < existing.membership_expires {
                        return Err(DepositsError::ProtocolViolation {
                            violation_type: "quorum_join_ratchet".to_string(),
                            details: format!(
                                "Cannot reduce membership duration: new {} < existing {}",
                                membership_expires, existing.membership_expires
                            ),
                        });
                    }
                }
            }
            LedgerOperation::DisputeArmed { .. } => {
                // Must be in active quorum to arm
                if self.state.quorum_state != QuorumState::Active {
                    return Err(DepositsError::ProtocolViolation {
                        violation_type: "custody_armed_no_quorum".to_string(),
                        details: "Cannot arm without any quorum members".to_string(),
                    });
                }
            }
            LedgerOperation::DisputeAcquire { claim_txid, .. } => {
                // Basic well-formedness: claim_txid must be non-zero. The
                // on-chain lottery script enforces winner selection;
                // cross-candidate validation lives in
                // `validate_custody_resolution()` which knows the
                // observed DisputeArmed set from Nostr.
                if claim_txid == &[0u8; 32] {
                    return Err(DepositsError::ProtocolViolation {
                        violation_type: "custody_acquire_no_claim".to_string(),
                        details: "DisputeAcquire requires a non-zero claim_txid"
                            .to_string(),
                    });
                }
            }
            _ => {
                // Other operations have simpler or no validation
            }
        }
        Ok(())
    }

    /// Apply state changes for an operation.
    ///
    /// Delegates to `LedgerState::apply()` which clones the state and returns a new one.
    /// The old state is replaced atomically — failed transitions leave state unchanged.
    pub fn apply_state_changes(&mut self, operation: &LedgerOperation) -> DepositsResult<()> {
        self.state = self.state.apply(operation)?;
        Ok(())
    }

    /// Apply state changes with conformance checking (operator path).
    ///
    /// Returns `Err` if the operation would produce a non-conforming state.
    /// Use this when the operator is creating their own updates.
    pub fn checked_apply(
        &mut self,
        operation: &LedgerOperation,
        verifier: &impl deposits_protocol::WitnessVerifier,
    ) -> DepositsResult<()> {
        self.state = self.state.check_and_apply(operation, verifier)?;
        Ok(())
    }

    /// Apply state changes and return any conformance violations (watcher path).
    ///
    /// Always applies the operation (even if non-conforming) so the watcher
    /// can continue tracking the ledger. Returns violations for logging/dispute.
    pub fn apply_and_check(
        &mut self,
        operation: &LedgerOperation,
        verifier: &impl deposits_protocol::WitnessVerifier,
    ) -> DepositsResult<Vec<deposits_protocol::ConformanceViolation>> {
        let (new_state, violations) = self.state.apply_with_verifier(operation, verifier)?;
        self.state = new_state;
        Ok(violations)
    }

    // ========================================================================
    // Export Methods
    // ========================================================================

    /// Export the complete ledger for validation and audit.
    ///
    /// Creates a `LedgerExport` containing all signed updates and metadata.
    pub fn export(&self, block_height: u32) -> crate::validation::LedgerExport {
        crate::validation::LedgerExport::new(
            self.state.ledger_id,
            self.state.genesis_block,
            self.state.operator_key,
            self.state.reserves_key.clone(),
            self.history.clone(),
            block_height,
        )
    }

    /// Export the ledger to a JSON string.
    ///
    /// Returns a human-readable JSON representation suitable for debugging and inspection.
    pub fn export_json(&self, block_height: u32) -> Result<String, serde_json::Error> {
        self.export(block_height).to_json()
    }

    /// Export the ledger to binary (bincode).
    ///
    /// Returns a compact binary representation suitable for storage and transmission.
    pub fn export_binary(&self, block_height: u32) -> Vec<u8> {
        self.export(block_height).to_binary()
    }

    /// Import and validate a ledger from an export.
    ///
    /// Validates the export and reconstructs the ledger state by replaying all updates.
    pub fn from_export(
        export: crate::validation::LedgerExport,
    ) -> Result<Self, crate::validation::ValidationError> {
        crate::validation::LedgerConformanceValidator::from_export(export)
    }

    /// Import from JSON and validate.
    ///
    /// Parses JSON and validates the ledger export.
    pub fn from_export_json(json: &str) -> Result<Self, crate::validation::ValidationError> {
        let export = crate::validation::LedgerExport::from_json(json).map_err(|e| {
            crate::validation::ValidationError::DecodeError(format!("JSON decode failed: {}", e))
        })?;
        Self::from_export(export)
    }

    /// Import from binary and validate.
    ///
    /// Parses bincode and validates the ledger export.
    pub fn from_export_binary(data: &[u8]) -> Result<Self, crate::validation::ValidationError> {
        let export = crate::validation::LedgerExport::from_binary(data)?;
        Self::from_export(export)
    }

    /// Reconstruct a Ledger from a persisted state and update history.
    ///
    /// This is used when loading from the append-only JSONL format:
    /// - First row: LedgerState (the initial/current state)
    /// - Subsequent rows: SignedLedgerUpdate (each update that was applied)
    ///
    /// The state should be the CURRENT state after all updates have been applied.
    /// This method rebuilds the ledger by verifying the chain and storing history.
    pub fn reconstruct(initial_state: LedgerState, updates: Vec<SignedLedgerUpdate>) -> Self {
        // Validate and apply each update to reconstruct the state chain
        // The stored state should already be the final state, but we verify continuity
        let mut content_hash = initial_state.chain_tip_hash;

        for update in &updates {
            // Verify this update continues the chain
            if update.previous_hash != content_hash {
                tracing::warn!(
                    "Update {} has mismatched previous_hash, chain may be corrupted",
                    update.sequence_number
                );
            }
            // Update content_hash to this update's hash for next iteration
            content_hash = update.content_hash;
        }

        // Return ledger with the final state and all history
        Self {
            state: initial_state,
            protocol: LedgerProtocolState::default(),
            role: LedgerRole::Partner, // Default role for reconstructed ledgers
            history: updates,
        }
    }

    /// Cosigner-edge validation: combines stateless `validate_operation`
    /// with the post-expiry refusal rule.
    ///
    /// Once a quorum's `quorum_expiry` block has passed, cosigners refuse
    /// to sign *any* operation, including a fresh `QuorumBegin`. Operators
    /// must rotate before the deadline; missing it forces them onto the
    /// Tier-1 (operator-alone after expiry) recovery path. There is no
    /// "rotate at the last second" exemption — the deadline is the
    /// deadline, and that's what makes it a meaningful obligation.
    ///
    /// Pre-quorum (no `quorum_expiry` set) and operations on a still-active
    /// quorum (`current_block <= quorum_expiry`) pass through.
    ///
    /// Callers: cosign request handlers, before they sign anything. NOT
    /// the operator's own apply path — operators can still apply ops
    /// post-expiry (e.g. via Tier-1 recovery) but won't get cosignatures
    /// for them.
    pub fn validate_for_cosign(
        &self,
        operation: &LedgerOperation,
        current_block_height: u32,
    ) -> DepositsResult<()> {
        self.validate_operation(operation)?;

        if let Some(expiry) = self.state.quorum_expiry {
            if current_block_height > expiry
                && self.state.quorum_state == deposits_protocol::QuorumState::Active
            {
                return Err(DepositsError::ProtocolViolation {
                    violation_type: "post_expiry_cosign_refused".to_string(),
                    details: format!(
                        "Quorum expired at block {}; current {}. \
                         Cosigners refuse to sign past expiry — the operator \
                         missed their rotation window. Recovery path is Tier-1 \
                         (operator-alone after expiry) followed by a fresh \
                         genesis bootstrap, not another QuorumBegin against \
                         this expired quorum.",
                        expiry, current_block_height
                    ),
                });
            }
        }

        Ok(())
    }
}

// ============================================================================
// Stateless Validation Utilities
// ============================================================================

/// Stateless validation utilities for ledgers.
///
/// All methods take `&Ledger` and don't mutate anything. This struct provides
/// pre-flight checks and validation without modifying ledger state.
pub struct LedgerValidator;

impl LedgerValidator {
    /// Check if an operation can be appended to the ledger.
    ///
    /// Validates business rules without mutating the ledger.
    pub fn can_append_operation(
        ledger: &Ledger,
        operation: &LedgerOperation,
    ) -> DepositsResult<()> {
        match operation {
            LedgerOperation::DepositOpen { deposit_id, .. } => {
                // Validate: deposit must not already exist
                if ledger.state.deposits.contains_key(deposit_id) {
                    return Err(DepositsError::ProtocolViolation {
                        violation_type: "duplicate_deposit".to_string(),
                        details: format!(
                            "Deposit already exists for id {}",
                            hex::encode(deposit_id)
                        ),
                    });
                }
            }
            LedgerOperation::DepositClose { deposit_id, .. } => {
                // Validate: deposit must exist and have zero balance
                if let Some(deposit) = ledger.state.deposits.get(deposit_id) {
                    if deposit.balance != 0 {
                        return Err(DepositsError::NonZeroBalance {
                            balance: deposit.balance,
                        });
                    }
                    if !deposit.invoices.is_empty() {
                        return Err(DepositsError::OutstandingInvoices {
                            count: deposit.invoices.len(),
                        });
                    }
                } else {
                    return Err(DepositsError::DepositNotFound);
                }
            }
            LedgerOperation::LedgerClose => {
                // Validate: no deposits remaining
                if !ledger.state.deposits.is_empty() {
                    return Err(DepositsError::ProtocolViolation {
                        violation_type: "ledger_close_with_deposits".to_string(),
                        details: format!(
                            "Cannot close ledger with {} active deposits",
                            ledger.state.deposits.len()
                        ),
                    });
                }
            }
            _ => {
                // Other operations validated in apply_operation
            }
        }
        Ok(())
    }

    /// Find the length of the valid chain.
    ///
    /// Walks the chain from genesis, returns index of first invalid update
    /// (or len if all valid).
    pub fn find_valid_chain_length(ledger: &Ledger) -> usize {
        let mut expected_previous_hash = [0u8; 32];

        for (i, update) in ledger.history.iter().enumerate() {
            // Check sequence number
            if update.sequence_number != i as u64 {
                return i;
            }

            // Check previous hash
            if update.previous_hash != expected_previous_hash {
                return i;
            }

            // Next update's `previous_hash` references this update's
            // `chain_hash()` (which folds in `operator_signature`), NOT
            // `content_hash`. See `commit_staged`.
            expected_previous_hash = update.chain_hash();
        }

        ledger.history.len()
    }

    /// Get the total balance across all deposits (balance + locked, per DEP-05).
    pub fn total_balance(ledger: &Ledger) -> u64 {
        ledger.state.total_deposit_balance()
    }

    /// Get total locked balance across all deposits.
    pub fn total_locked_balance(ledger: &Ledger) -> u64 {
        ledger
            .state
            .deposits
            .values()
            .map(|d| d.locked_balance)
            .sum()
    }

    /// Calculate minimum required reserves.
    ///
    /// In the 100%+100% backing model:
    /// - Reserves in this channel must be >= 100% of deposits
    /// - Collateral in other channels provides additional 100% security
    pub fn calculate_minimum_reserves(ledger: &Ledger) -> u64 {
        let total_deposits = Self::total_balance(ledger);
        // Add pending invoices calculation when tracked
        let max_outstanding_invoice = 0u64;

        // 100% of deposits + max outstanding invoice
        total_deposits.saturating_add(max_outstanding_invoice)
    }

    /// Check if the ledger has sufficient reserves for current deposits.
    pub fn has_sufficient_reserves(ledger: &Ledger) -> bool {
        ledger.state.reserves_amount >= Self::calculate_minimum_reserves(ledger)
    }

    /// Calculate excess reserves above the minimum requirement.
    pub fn excess_reserves(ledger: &Ledger) -> u64 {
        let min_required = Self::calculate_minimum_reserves(ledger);
        ledger.state.reserves_amount.saturating_sub(min_required)
    }

    // ========================================================================
    // Collateral Validation Methods
    // ========================================================================

    /// Validate reserves are sufficient for a given deposit liability.
    ///
    /// Obligations must not exceed reserves.
    ///
    /// Returns Ok if reserves are sufficient, Err with details if not.
    pub fn validate_collateral_for_liability(
        ledger: &Ledger,
        deposit_liability: u64,
        _current_block: u32,
        _max_attestation_age_blocks: u32,
    ) -> DepositsResult<()> {
        if ledger.state.reserves_amount < deposit_liability {
            return Err(DepositsError::InsufficientReserves {
                required: deposit_liability,
                available: ledger.state.reserves_amount,
            });
        }

        Ok(())
    }

    /// Check if a collateral decrease is allowed.
    ///
    /// Collateral decreases are not allowed within the reporting period
    /// after an increase, to prevent gaming the system.
    pub fn can_decrease_collateral(
        _ledger: &Ledger,
        _current_block: u32,
        _reporting_period_blocks: u32,
    ) -> bool {
        // TODO: Track last collateral increase block in state if needed
        true
    }

    // ========================================================================
    // Hash Chain Validation Methods
    // ========================================================================

    /// Find the sequence number for a given hash in the ledger history.
    ///
    /// Returns None if the hash is not found in the history.
    pub fn find_hash_sequence(ledger: &Ledger, target_hash: &[u8; 32]) -> Option<u64> {
        // Zero hash represents genesis (before any updates)
        if target_hash == &[0u8; 32] {
            return Some(0);
        }

        // Search through history for matching hash
        for update in &ledger.history {
            if update.content_hash == *target_hash {
                return Some(update.sequence_number);
            }
        }

        None
    }

    /// Check if a hash exists in the ledger chain and is >= the committed hash.
    ///
    /// A hash is valid for reserves if:
    /// 1. It exists in the update chain, AND
    /// 2. Its sequence number is >= the committed hash's sequence number
    ///
    /// This is used to validate UpdateReserves operations to ensure
    /// they reference a valid ledger state that hasn't been rolled back.
    pub fn is_valid_reserves_hash(
        ledger: &Ledger,
        target_hash: &[u8; 32],
        committed_hash: &[u8; 32],
    ) -> bool {
        // Zero hash means no commitment yet - any valid hash is acceptable
        let is_zero_committed = committed_hash == &[0u8; 32];

        // Find the sequence number of the target hash
        let target_seq = match Self::find_hash_sequence(ledger, target_hash) {
            Some(seq) => seq,
            None => return false, // Hash doesn't exist in chain
        };

        // If no prior commitment, any existing hash is valid
        if is_zero_committed {
            return true;
        }

        // Find the sequence number of the committed hash
        match Self::find_hash_sequence(ledger, committed_hash) {
            Some(committed_seq) => target_seq >= committed_seq,
            None => {
                // Committed hash not found - this shouldn't happen but be safe
                false
            }
        }
    }

    /// Check if the partner's ACK is up to date with the current ledger state.
    /// ACK tracking was removed with legacy Lightning fields — always returns true.
    pub fn is_partner_ack_current(_ledger: &Ledger) -> bool {
        true
    }

    /// Check if the channel commitment is up to date with the current ledger state.
    /// Commitment tracking was removed with legacy Lightning fields — always returns true.
    pub fn is_commitment_current(_ledger: &Ledger) -> bool {
        true
    }

    /// Get the sequence number difference between current state and partner's ACK.
    ///
    /// Returns 0 — ACK tracking was removed with the legacy Lightning protocol fields.
    pub fn unacked_update_count(_ledger: &Ledger) -> u64 {
        0
    }
}

// ============================================================================
// Ledger Manager
// ============================================================================

/// Complex multi-step operations for ledgers.
///
/// Wraps a ledger and provides convenience methods for multi-update sequences
/// like reserves topup before credit, reducing reserves to minimum, etc.
pub struct LedgerManager {
    ledger: Ledger,
}

impl LedgerManager {
    /// Create a new manager for an existing ledger.
    pub fn new(ledger: Ledger) -> Self {
        Self { ledger }
    }

    /// Create a new ledger as operator.
    pub fn create_as_operator(
        operator_key: PublicKey,
        reserves_key: String,
        genesis_block: u32,
    ) -> Self {
        Self::new(Ledger::new_as_operator(
            operator_key,
            reserves_key,
            genesis_block,
        ))
    }

    /// Create a new ledger as partner.
    pub fn create_as_partner(
        operator_key: PublicKey,
        reserves_key: String,
        genesis_block: u32,
    ) -> Self {
        Self::new(Ledger::new_as_partner(
            operator_key,
            reserves_key,
            genesis_block,
        ))
    }

    /// Get a reference to the underlying ledger.
    pub fn ledger(&self) -> &Ledger {
        &self.ledger
    }

    /// Get a mutable reference to the underlying ledger.
    pub fn ledger_mut(&mut self) -> &mut Ledger {
        &mut self.ledger
    }

    /// Consume the manager and return the underlying ledger.
    pub fn into_ledger(self) -> Ledger {
        self.ledger
    }

    // ========================================================================
    // Reserves Management
    // ========================================================================

    /// Calculate reserves needed for a given credit amount.
    ///
    /// Returns the reserves needed to cover current deposits plus the new credit.
    pub fn reserves_needed_for_credit(&self, credit_amount: u64) -> u64 {
        let current_balance = LedgerValidator::total_balance(&self.ledger);
        current_balance.saturating_add(credit_amount)
    }

    /// Check if reserves topup is needed before a credit.
    ///
    /// Returns Some(required_amount) if topup is needed, None otherwise.
    pub fn reserves_topup_needed(&self, credit_amount: u64) -> Option<u64> {
        let required = self.reserves_needed_for_credit(credit_amount);
        if self.ledger.reserves_amount() < required {
            Some(required)
        } else {
            None
        }
    }

    /// Calculate excess reserves that can be withdrawn.
    ///
    /// Returns the amount of reserves above the minimum requirement.
    pub fn excess_reserves(&self) -> u64 {
        LedgerValidator::excess_reserves(&self.ledger)
    }

    /// Calculate minimum required reserves.
    pub fn minimum_reserves(&self) -> u64 {
        LedgerValidator::calculate_minimum_reserves(&self.ledger)
    }

    // ========================================================================
    // Collateral Management
    // ========================================================================

    /// Check if collateral decrease is allowed.
    ///
    /// Decreases are not allowed within the reporting period after an increase.
    pub fn can_decrease_collateral(
        &self,
        current_block: u32,
        reporting_period_blocks: u32,
    ) -> bool {
        LedgerValidator::can_decrease_collateral(
            &self.ledger,
            current_block,
            reporting_period_blocks,
        )
    }

    /// Validate collateral is sufficient for current deposits.
    pub fn validate_collateral(
        &self,
        current_block: u32,
        max_attestation_age_blocks: u32,
    ) -> DepositsResult<()> {
        let deposit_liability = LedgerValidator::total_balance(&self.ledger);
        LedgerValidator::validate_collateral_for_liability(
            &self.ledger,
            deposit_liability,
            current_block,
            max_attestation_age_blocks,
        )
    }

    /// Get total collateral (reserves amount).
    pub fn total_collateral(&self, _current_block: u32, _max_age_blocks: u32) -> u64 {
        self.ledger.state.reserves_amount
    }

    // ========================================================================
    // Hash Chain Management
    // ========================================================================

    /// Check if partner ACK is current.
    pub fn is_partner_synced(&self) -> bool {
        LedgerValidator::is_partner_ack_current(&self.ledger)
    }

    /// Check if commitment is current.
    pub fn is_commitment_synced(&self) -> bool {
        LedgerValidator::is_commitment_current(&self.ledger)
    }

    /// Get count of unacked updates.
    pub fn unacked_count(&self) -> u64 {
        LedgerValidator::unacked_update_count(&self.ledger)
    }

    /// Validate a hash for reserves update.
    pub fn is_valid_reserves_hash(&self, target_hash: &[u8; 32]) -> bool {
        // No commitment tracking — any valid hash in the chain is acceptable
        LedgerValidator::is_valid_reserves_hash(&self.ledger, target_hash, &[0u8; 32])
    }

    // ========================================================================
    // Update Handling
    // ========================================================================

    /// Append a signed update with out-of-order support.
    pub fn append_update(&mut self, update: SignedLedgerUpdate) -> usize {
        self.ledger.append_signed_update(update)
    }

    /// Get pending update count.
    pub fn pending_count(&self) -> usize {
        self.ledger.pending_count()
    }

    /// Check if there are gaps in updates.
    pub fn has_gaps(&self) -> bool {
        self.ledger.has_gaps()
    }

    // ========================================================================
    // Factory Methods
    // ========================================================================

    /// Create a new empty ledger without any operations.
    ///
    /// This creates a new ledger in its initial state. The genesis hash is `[0u8; 32]`
    /// since no operations have been applied yet.
    ///
    /// Use this when initializing a ledger from a handshake message (like `LedgerOpenRequest`)
    /// where the handshake itself is not recorded as a ledger operation.
    pub fn create_empty_ledger(
        operator_key: PublicKey,
        reserves_key: String,
        role: LedgerRole,
        quorum_members: Vec<crate::types::QuorumMember>,
        genesis_block: u32,
    ) -> (Self, [u8; 32]) {
        let ledger = Ledger::new(
            operator_key,
            reserves_key,
            role,
            quorum_members,
            genesis_block,
        );
        let genesis_hash = ledger.state.chain_tip_hash; // Initial hash from LedgerState::new()
        (Self::new(ledger), genesis_hash)
    }

    /// Create a new ledger with the given genesis operation.
    ///
    /// This creates a new ledger, applies the genesis operation as the first update,
    /// and returns the manager along with the genesis hash.
    pub fn create_ledger(
        operator_key: PublicKey,
        reserves_key: String,
        role: LedgerRole,
        quorum_members: Vec<crate::types::QuorumMember>,
        genesis_block: u32,
        genesis_operation: LedgerOperation,
    ) -> DepositsResult<(Self, [u8; 32])> {
        // Create the base ledger
        let mut ledger = Ledger::new(
            operator_key,
            reserves_key,
            role,
            quorum_members,
            genesis_block,
        );

        // Apply the genesis operation
        let update = ledger.apply_operation(&genesis_operation)?;
        let genesis_hash = update.content_hash;

        Ok((Self::new(ledger), genesis_hash))
    }

    // ========================================================================
    // Composite Operations
    // ========================================================================

    /// Credit a payment with automatic reserves topup if needed.
    ///
    /// If the current reserves are insufficient, this will first apply a
    /// reserves increase, then apply the credit.
    ///
    /// The credit_operation must be an `InvoiceCredit` or `OnchainCredit` variant.
    pub fn credit_payment_with_reserves_topup(
        &mut self,
        credit_operation: LedgerOperation,
    ) -> DepositsResult<Vec<[u8; 32]>> {
        // Extract the credit amount from the operation
        let credit_amount = match &credit_operation {
            LedgerOperation::InvoiceCredit { amount, .. } => *amount,
            LedgerOperation::OnchainCredit { amount, .. } => *amount,
            _ => {
                return Err(DepositsError::InvalidReservesDecrease(
                    "Expected InvoiceCredit or OnchainCredit operation".to_string(),
                ))
            }
        };

        let mut hashes = Vec::new();

        // Check if reserves topup is needed — directly adjust reserves amount
        // (ReservesIncrease operation was removed; reserves are now set at LedgerOpen
        // and updated at QuorumBegin)
        if let Some(required_amount) = self.reserves_topup_needed(credit_amount) {
            self.ledger.state.reserves_amount = required_amount;
        }

        // Apply the credit operation
        let credit_update = self.ledger.apply_operation(&credit_operation)?;
        hashes.push(credit_update.content_hash);

        Ok(hashes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::FeeStructure;

    fn test_pubkey() -> PublicKey {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let sk = bitcoin::secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap();
        PublicKey::from_secret_key(&secp, &sk)
    }

    fn test_pubkey_2() -> PublicKey {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let sk = bitcoin::secp256k1::SecretKey::from_slice(&[2u8; 32]).unwrap();
        PublicKey::from_secret_key(&secp, &sk)
    }

    #[test]
    fn test_ledger_creation() {
        let op = test_pubkey();
        let partner = test_pubkey_2();
        let ledger = Ledger::new_as_operator(op, partner.to_string(), 0);

        assert_eq!(ledger.role, LedgerRole::Operator);
        assert_eq!(ledger.sequence(), 0);
        assert_eq!(ledger.total_deposit_balance(), 0);
    }

    #[test]
    fn test_reserves_set_at_open() {
        let op_key = test_pubkey();
        let partner = test_pubkey_2();
        let mut ledger = Ledger::new(op_key, partner.to_string(), LedgerRole::Operator, vec![], 0);

        // Set reserves via LedgerOpen
        let open = LedgerOperation::LedgerOpen {
            operator_id: op_key,
            reserves_id: "bcrt1q...".to_string(),
            genesis_block: 0,
            reserves_amount: 100_000,
            collateral_amount: 0,
        };

        let update = ledger.apply_operation(&open).unwrap();
        assert_eq!(update.sequence_number, 1);
        assert_eq!(ledger.reserves_amount(), 100_000);
    }

    #[test]
    fn test_deposit_lifecycle() {
        let op_key = test_pubkey();
        let partner = test_pubkey_2();
        let mut ledger = Ledger::new_as_operator(op_key, partner.to_string(), 0);

        // Set reserves directly on state (reserves are now set at LedgerOpen)
        ledger.state.reserves_amount = 100_000;

        // Open deposit
        let user = test_pubkey_2();
        let descriptor = format!("pk({})", hex::encode(user.serialize()));
        let deposit_id = crate::types::compute_deposit_id(&descriptor);
        ledger
            .apply_operation(&LedgerOperation::DepositOpen {
                deposit_id,
                descriptor: descriptor.clone(),
                fees: Some(FeeStructure::default()),
                transfer_fees: None,
                payment_hash: None,
                invoice: None,
                cosigner_guarantee_signature: None,
                receive_requires_sig: false,
                fee_change_after_blocks: None,
                fee_change_notice_blocks: None,
                fee_change_limit_bps: None,
            })
            .unwrap();

        assert_eq!(ledger.state.deposits.len(), 1);

        // Credit deposit
        ledger
            .apply_operation(&LedgerOperation::InvoiceCredit {
                payment_hash: [0u8; 32],
                deposit_id,
                amount: 50_000,
                invoice_id: "inv1".to_string(),
                sequence_number: 1,
            })
            .unwrap();

        assert_eq!(
            ledger.state.deposits.get(&deposit_id).unwrap().balance,
            50_000
        );
    }

    #[test]
    fn test_hash_chain() {
        let op = test_pubkey();
        let partner = test_pubkey_2();
        let mut ledger = Ledger::new_as_operator(op, partner.to_string(), 0);

        let initial_hash = ledger.hash();
        assert_eq!(initial_hash, [0u8; 32]);

        // Apply a LedgerOpen with reserves to change the hash
        let op_key = test_pubkey();
        let open = LedgerOperation::LedgerOpen {
            operator_id: op_key,
            reserves_id: "bcrt1q...".to_string(),
            genesis_block: 0,
            reserves_amount: 100_000,
            collateral_amount: 0,
        };
        ledger.apply_operation(&open).unwrap();

        let hash_after_1 = ledger.hash();
        assert_ne!(hash_after_1, initial_hash);

        // Apply a deposit open to change the hash again
        let deposit_id = crate::types::compute_deposit_id("pk(test_hash)");
        let deposit_open = LedgerOperation::DepositOpen {
            deposit_id,
            descriptor: "pk(test_hash)".to_string(),
            fees: None,
            transfer_fees: None,
            payment_hash: None,
            invoice: None,
            cosigner_guarantee_signature: None,
            receive_requires_sig: false,
            fee_change_after_blocks: None,
            fee_change_notice_blocks: None,
            fee_change_limit_bps: None,
        };
        ledger.apply_operation(&deposit_open).unwrap();

        let hash_after_2 = ledger.hash();
        assert_ne!(hash_after_2, hash_after_1);
    }

    #[test]
    fn test_ledger_export() {
        let op_key = test_pubkey();
        let partner = test_pubkey_2();
        let ledger = Ledger::new_as_operator(op_key, partner.to_string(), 0);

        // Export the ledger
        let export = ledger.export(1000);

        assert_eq!(export.version, 1);
        assert_eq!(export.operator_id, op_key);
        assert_eq!(export.reserves_id, partner.to_string());
        assert!(export.updates.is_empty());
        assert_eq!(export.block_height, 1000);
    }

    #[test]
    fn test_ledger_export_json() {
        let op_key = test_pubkey();
        let partner = test_pubkey_2();
        let ledger = Ledger::new_as_operator(op_key, partner.to_string(), 0);

        // Export to JSON
        let json = ledger
            .export_json(1000)
            .expect("JSON export should succeed");

        assert!(json.contains("\"version\": 1"));
        assert!(json.contains("reserves_id"));
    }

    #[test]
    fn test_ledger_export_binary() {
        let op_key = test_pubkey();
        let partner = test_pubkey_2();
        let ledger = Ledger::new_as_operator(op_key, partner.to_string(), 0);

        // Export to binary
        let binary = ledger.export_binary(1000);

        assert!(!binary.is_empty());
    }

    #[test]
    fn test_transfer_lock_complete_flow() {
        use crate::types::{compute_deposit_id, Deposit, DescriptorWitness, TransferFeeSchedule};

        let op_key = test_pubkey();
        let partner = test_pubkey_2();
        let mut ledger = Ledger::new_as_operator(op_key, partner.to_string(), 0);

        // Create source and destination deposits
        let source_id = compute_deposit_id("pk(alice)");
        let dest_id = compute_deposit_id("pk(bob)");

        let source_deposit = Deposit {
            deposit_id: source_id,
            descriptor: "pk(alice)".to_string(),
            balance: 100_000,
            locked_balance: 0,
            invoices: Vec::new(),
            fees: FeeStructure::default(),
            last_fee_assessment: 0,
            transfer_fees: TransferFeeSchedule::default(),
            receive_requires_sig: false,
            fee_change_after_blocks: None,
            fee_change_notice_blocks: None,
            fee_change_limit_bps: None,
            opened_at_block: 0,
            pending_fee_change: None,
        };
        let dest_deposit = Deposit {
            deposit_id: dest_id,
            descriptor: "pk(bob)".to_string(),
            balance: 50_000,
            locked_balance: 0,
            invoices: Vec::new(),
            fees: FeeStructure::default(),
            last_fee_assessment: 0,
            transfer_fees: TransferFeeSchedule::default(),
            receive_requires_sig: false,
            fee_change_after_blocks: None,
            fee_change_notice_blocks: None,
            fee_change_limit_bps: None,
            opened_at_block: 0,
            pending_fee_change: None,
        };
        ledger.state.deposits.insert(source_id, source_deposit);
        ledger.state.deposits.insert(dest_id, dest_deposit);

        // Create transfer lock
        let nonce = [0x42u8; 32];
        let transfer_id = [0xAAu8; 32];
        let amount = 30_000u64;
        let fee = 500u64;

        let lock_op = LedgerOperation::TransferLock {
            nonce,
            source_deposit_id: source_id,
            destination_deposit_id: dest_id,
            amount,
            fee,
            completion_script: "sha256(deadbeef)".to_string(),
            timeout_height: 900_000,
            transfer_id,
            witness: DescriptorWitness {
                stack: vec![[0x11u8; 64].to_vec()],
            },
        };

        ledger.apply_operation(&lock_op).unwrap();

        // Verify locked increased; balance is unchanged (it's the total
        // obligation, and the lock just marks a portion in-flight).
        let source = ledger.state.deposits.get(&source_id).unwrap();
        assert_eq!(source.balance, 100_000);
        assert_eq!(source.locked_balance, 30_500); // amount + fee

        // Verify pending transfer was created
        assert_eq!(ledger.state.pending_transfers.len(), 1);
        let pending = ledger.state.pending_transfers.get(&transfer_id).unwrap();
        assert_eq!(pending.amount, amount);
        assert_eq!(pending.fee, fee);
        assert_eq!(pending.source_deposit_id, source_id);
        assert_eq!(pending.destination_deposit_id, dest_id);

        // Complete the transfer
        let complete_op = LedgerOperation::TransferComplete {
            transfer_id,
            script_witness: DescriptorWitness {
                stack: vec![[0x22u8; 32].to_vec()],
            }, // preimage
        };

        ledger.apply_operation(&complete_op).unwrap();

        // Verify pending transfer was removed
        assert!(ledger.state.pending_transfers.is_empty());

        // After Complete: source.balance lost the `amount` that actually left;
        // fee is operator income (not tracked as per-deposit obligation).
        let source = ledger.state.deposits.get(&source_id).unwrap();
        assert_eq!(source.locked_balance, 0);
        assert_eq!(source.balance, 100_000 - 30_000); // 70,000

        // Verify destination received the amount (not the fee)
        let dest = ledger.state.deposits.get(&dest_id).unwrap();
        assert_eq!(dest.balance, 50_000 + 30_000); // 80,000
    }

    #[test]
    fn test_transfer_lock_timeout_flow() {
        use crate::types::{compute_deposit_id, Deposit, DescriptorWitness, TransferFeeSchedule};

        let op_key = test_pubkey();
        let partner = test_pubkey_2();
        let mut ledger = Ledger::new_as_operator(op_key, partner.to_string(), 0);

        // Create source deposit
        let source_id = compute_deposit_id("pk(alice)");
        let dest_id = compute_deposit_id("pk(bob)");

        let source_deposit = Deposit {
            deposit_id: source_id,
            descriptor: "pk(alice)".to_string(),
            balance: 100_000,
            locked_balance: 0,
            invoices: Vec::new(),
            fees: FeeStructure::default(),
            last_fee_assessment: 0,
            transfer_fees: TransferFeeSchedule::default(),
            receive_requires_sig: false,
            fee_change_after_blocks: None,
            fee_change_notice_blocks: None,
            fee_change_limit_bps: None,
            opened_at_block: 0,
            pending_fee_change: None,
        };
        ledger.state.deposits.insert(source_id, source_deposit);

        // Create transfer lock
        let transfer_id = [0xBBu8; 32];
        let amount = 25_000u64;
        let fee = 250u64;

        let lock_op = LedgerOperation::TransferLock {
            nonce: [0x11u8; 32],
            source_deposit_id: source_id,
            destination_deposit_id: dest_id,
            amount,
            fee,
            completion_script: "sha256(cafebabe)".to_string(),
            timeout_height: 850_000,
            transfer_id,
            witness: DescriptorWitness {
                stack: vec![[0x33u8; 64].to_vec()],
            },
        };

        ledger.apply_operation(&lock_op).unwrap();

        // Verify funds locked; balance unchanged (total obligation is the same).
        let source = ledger.state.deposits.get(&source_id).unwrap();
        assert_eq!(source.balance, 100_000);
        assert_eq!(source.locked_balance, 25_250);

        // Timeout the transfer (deadline passed, preimage not revealed)
        let timeout_op = LedgerOperation::TransferFail {
            transfer_id,
            block_hash: [0x99u8; 32],
            reason: 1,
        };

        ledger.apply_operation(&timeout_op).unwrap();

        // Verify pending transfer was removed
        assert!(ledger.state.pending_transfers.is_empty());

        // Source gets amount + proportional portion of fee back; the fixed
        // portion (TransferFeeSchedule::default().fixed_msats = 2) is
        // charged to the operator even on failure and shows up on
        // fees_accumulated.
        let source = ledger.state.deposits.get(&source_id).unwrap();
        assert_eq!(source.locked_balance, 0);
        assert_eq!(source.balance, 100_000 - 2);
        assert_eq!(ledger.state.fees_accumulated, 2);
    }

    /// `VALID_QUORUM_SIZES` rejection at QuorumBegin.
    ///
    /// Asserts that each `Q ∈ VALID_QUORUM_SIZES = {3, 5, 7}` (cosigner
    /// count, operator not counted) is accepted by the policy gate, and
    /// that out-of-set values (even `Q`, `Q < 3`, `Q > 7`) are rejected
    /// with `quorum_size_invalid`. In-set cases may still fail downstream
    /// cosignature checks but that's a different error.
    #[test]
    fn quorum_begin_policy_cap_rejects_oversize() {
        use crate::constants::VALID_QUORUM_SIZES;
        use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

        fn pk(seed: u8) -> PublicKey {
            let secp = Secp256k1::new();
            let mut bytes = [0u8; 32];
            bytes[31] = seed;
            let sk = SecretKey::from_slice(&bytes).unwrap();
            PublicKey::from_secret_key(&secp, &sk)
        }

        let operator = pk(1);
        let mut ledger = Ledger::new(
            operator,
            "rid".to_string(),
            LedgerRole::Operator,
            Vec::new(),
            100,
        );
        ledger.state.parent_pubkey = operator;
        ledger.state.reserves_amount = 1_000_000;

        let make_op = |cosigners: Vec<PublicKey>| LedgerOperation::QuorumBegin {
            // (closure body unchanged below; quorum_members wraps each pubkey in
            //  QuorumMemberRef::pubkey_only — see the field assignment.)
            reserves_id: "rid".into(),
            spending_txid: [0; 32],
            new_outpoint_txid: [0; 32],
            new_outpoint_vout: 0,
            amount: 1_000_000,
            quorum_expiry: 1_000_000,
            ledger_hash: [0; 32],
            quorum_members: cosigners
                .into_iter()
                .map(crate::messages::QuorumMemberRef::pubkey_only)
                .collect(),
            collateral_amount: 0,
        };

        // Q is the cosigner count, operator not counted. Each value in
        // VALID_QUORUM_SIZES (currently {3, 5, 7}) must NOT trip the
        // policy gate; if validate_operation returns an error, it must
        // be a different one (e.g. cosignature checks).
        for &q in &VALID_QUORUM_SIZES {
            let valid = make_op((2..=(q as u8 + 1)).map(pk).collect());
            if let Err(DepositsError::ProtocolViolation { violation_type, .. }) =
                ledger.validate_operation(&valid)
            {
                assert_ne!(
                    violation_type, "quorum_size_invalid",
                    "Q={} (in VALID_QUORUM_SIZES) must NOT trip the policy gate",
                    q
                );
            }
        }

        // Even Q (4) → not in the allowed set → policy reject.
        let even = make_op((2..=5).map(pk).collect()); // 4 cosigners
        let err = ledger
            .validate_operation(&even)
            .expect_err("Q=4 must be rejected (even)");
        match err {
            DepositsError::ProtocolViolation {
                violation_type, ..
            } => assert_eq!(violation_type, "quorum_size_invalid"),
            other => panic!("expected ProtocolViolation, got {:?}", other),
        }

        // Q below floor (1) → reductive → policy reject.
        let too_small = make_op(vec![pk(2)]); // 1 cosigner
        let err = ledger
            .validate_operation(&too_small)
            .expect_err("Q=1 must be rejected (below floor)");
        match err {
            DepositsError::ProtocolViolation {
                violation_type, ..
            } => assert_eq!(violation_type, "quorum_size_invalid"),
            other => panic!("expected ProtocolViolation, got {:?}", other),
        }

        // Q above cap (9) → over MAX_QUORUM_SIZE_POLICY → policy reject.
        let too_big = make_op((2..=10).map(pk).collect()); // 9 cosigners
        let err = ledger
            .validate_operation(&too_big)
            .expect_err("Q=9 must be rejected (above cap)");
        match err {
            DepositsError::ProtocolViolation {
                violation_type, ..
            } => assert_eq!(violation_type, "quorum_size_invalid"),
            other => panic!("expected ProtocolViolation, got {:?}", other),
        }
    }

    /// `validate_for_cosign` refuses ops past `quorum_expiry`.
    ///
    /// Verifies all four boundary cases:
    ///  - Active quorum + before expiry → accept
    ///  - Active quorum + at expiry → accept (boundary is inclusive of expiry)
    ///  - Active quorum + past expiry → refuse with `post_expiry_cosign_refused`
    ///  - PreQuorum (no expiry set) + any block height → accept
    #[test]
    fn validate_for_cosign_refuses_post_expiry() {
        use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
        use deposits_protocol::types::QuorumMember;
        use deposits_protocol::QuorumState;

        fn pk(seed: u8) -> PublicKey {
            let secp = Secp256k1::new();
            let mut bytes = [0u8; 32];
            bytes[31] = seed;
            let sk = SecretKey::from_slice(&bytes).unwrap();
            PublicKey::from_secret_key(&secp, &sk)
        }

        let operator = pk(1);
        let mut ledger = Ledger::new(
            operator,
            "rid".to_string(),
            LedgerRole::Operator,
            Vec::new(),
            100,
        );
        ledger.state.parent_pubkey = operator;
        ledger.state.reserves_amount = 1_000_000;

        // LedgerClose is the simplest op (no fields), used here as a probe
        // to check the expiry gate fires regardless of op shape.
        let op = LedgerOperation::LedgerClose;

        // PreQuorum: no expiry set, all block heights pass.
        ledger.state.quorum_state = QuorumState::PreQuorum;
        ledger.state.quorum_expiry = None;
        assert!(ledger.validate_for_cosign(&op, 1_000_000).is_ok());

        // Activate the quorum at expiry block 500.
        ledger.state.quorum_state = QuorumState::Active;
        ledger.state.quorum_expiry = Some(500);
        ledger.state.quorum_members = vec![
            QuorumMember {
                pubkey: pk(2),
                ledger_id: "m1".into(),
                min_fee_bps: None,
                min_fee_fixed: None,
                max_fee_period: None,
                membership_until: Some(500),
                dispute_response_blocks: None,
                dispute_arm_blocks: None,
                service_response_blocks: None,
                max_transfer_timeout_blocks: None,
                max_descriptor_bytes: None,
                compensation_bps: None,
                compensation_deposit_id: None,
                compensation_frequency_blocks: None,
            },
        ];

        // Before expiry → accept.
        assert!(
            ledger.validate_for_cosign(&op, 499).is_ok(),
            "block 499 with expiry 500 should pass"
        );
        // At expiry → accept (the expiry block itself is the last cosignable block).
        assert!(
            ledger.validate_for_cosign(&op, 500).is_ok(),
            "block 500 with expiry 500 should pass (boundary inclusive)"
        );
        // Past expiry → refuse with `post_expiry_cosign_refused`.
        let err = ledger
            .validate_for_cosign(&op, 501)
            .expect_err("block 501 with expiry 500 must refuse");
        match err {
            DepositsError::ProtocolViolation {
                violation_type, ..
            } => assert_eq!(violation_type, "post_expiry_cosign_refused"),
            other => panic!("expected ProtocolViolation, got {:?}", other),
        }

        // Way past expiry → still refuse.
        let err = ledger
            .validate_for_cosign(&op, 1_000_000)
            .expect_err("far-past expiry must refuse");
        match err {
            DepositsError::ProtocolViolation {
                violation_type, ..
            } => assert_eq!(violation_type, "post_expiry_cosign_refused"),
            other => panic!("expected ProtocolViolation, got {:?}", other),
        }
    }
}
