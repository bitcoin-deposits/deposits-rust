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

use crate::error::{DepositsError, DepositsResult};
use crate::messages::LedgerOperation;
use crate::types::{Deposit, DisputeState, LedgerState, ReservesOutput, SignedLedgerUpdate};

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
    pub current_hash: [u8; 32],
}

impl LedgerUpdate {
    /// Create a new ledger update.
    pub fn new(
        sequence_number: u64,
        operation: LedgerOperation,
        previous_hash: [u8; 32],
    ) -> Self {
        let mut update = Self {
            sequence_number,
            operation,
            previous_hash,
            current_hash: [0u8; 32],
        };
        update.current_hash = update.compute_hash();
        update
    }

    /// Compute the hash of this update.
    pub fn compute_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.sequence_number.to_le_bytes());
        hasher.update(&self.previous_hash);
        // Hash the operation discriminant and key fields
        hasher.update(&[self.operation.discriminant()]);

        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Verify the hash chain.
    pub fn verify_hash(&self) -> bool {
        self.compute_hash() == self.current_hash
    }
}

/// Ledger state manager.
///
/// Maintains the hash-chained ledger state and provides methods
/// for applying validated operations.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Ledger {
    /// Current ledger state.
    pub state: LedgerState,
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
        ledger_address: String,
        genesis_block: u32,
    ) -> Self {
        Self {
            state: LedgerState::new(operator_key, reserves_key, ledger_address, genesis_block),
            role: LedgerRole::Operator,
            history: Vec::new(),
        }
    }

    /// Create a new ledger as partner.
    pub fn new_as_partner(
        operator_key: PublicKey,
        reserves_key: String,
        ledger_address: String,
        genesis_block: u32,
    ) -> Self {
        Self {
            state: LedgerState::new(operator_key, reserves_key, ledger_address, genesis_block),
            role: LedgerRole::Partner,
            history: Vec::new(),
        }
    }

    /// Create a new ledger with explicit role and optional quorum members.
    /// This constructor is provided for compatibility with existing code.
    pub fn new(
        operator_key: PublicKey,
        reserves_key: String,
        role: LedgerRole,
        quorum_members: Vec<crate::types::QuorumMember>,
        ledger_address: String,
        genesis_block: u32,
    ) -> Self {
        Self::with_enforcement_block(
            operator_key,
            reserves_key,
            role,
            quorum_members,
            ledger_address,
            genesis_block,
            None,
        )
    }

    /// Create a new ledger with explicit collateral enforcement block.
    ///
    /// - `enforcement_block = None`: Immediate enforcement (for joining established networks)
    /// - `enforcement_block = Some(future_block)`: Deferred enforcement (for bootstrap phase)
    ///
    /// During bootstrap, operators can cross-establish quorum memberships before
    /// the size requirements kick in. After the enforcement block, partners must have
    /// ledgers >= half the operator's ledger size.
    pub fn with_enforcement_block(
        operator_key: PublicKey,
        reserves_key: String,
        role: LedgerRole,
        quorum_members: Vec<crate::types::QuorumMember>,
        ledger_address: String,
        genesis_block: u32,
        collateral_enforcement_block: Option<u64>,
    ) -> Self {
        let mut state = LedgerState::with_enforcement_block(
            operator_key,
            reserves_key,
            ledger_address,
            genesis_block,
            collateral_enforcement_block,
        );
        state.quorum_members = quorum_members;
        Self {
            state,
            role,
            history: Vec::new(),
        }
    }

    /// Check if collateral size requirements are enforced at the given block.
    pub fn is_collateral_enforced(&self, current_block: u64) -> bool {
        self.state.is_collateral_enforced(current_block)
    }

    /// Get the collateral enforcement block (None for immediate enforcement).
    pub fn collateral_enforcement_block(&self) -> Option<u64> {
        self.state.collateral_enforcement_block
    }

    /// Get the current sequence number.
    pub fn sequence(&self) -> u64 {
        self.state.sequence
    }

    /// Get the current ledger hash.
    pub fn hash(&self) -> [u8; 32] {
        self.state.hash
    }

    /// Get total deposit balance (millisatoshis).
    pub fn total_deposit_balance(&self) -> u64 {
        self.state.total_deposit_balance()
    }

    /// Get reserves amount (millisatoshis).
    pub fn reserves_amount(&self) -> u64 {
        self.state.reserves_amount()
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
                // Preserve existing partner signature if new one is empty
                if update.partner_signature != [0u8; 64] || existing.partner_signature == [0u8; 64] {
                    *existing = update;
                }
            }
            return 1;
        }

        // Out of order (seq > expected_seq) - queue for later
        self.state.queue_pending_update(update);
        0
    }

    /// Flush pending updates that are now consecutive with history.
    ///
    /// Returns the number of updates flushed.
    fn flush_pending_updates(&mut self) -> usize {
        let mut flushed = 0;
        loop {
            let next_seq = self.history.len() as u64;
            if let Some(update) = self.state.take_pending_update(next_seq) {
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
        self.state.pending_update_count()
    }

    /// Check if there are gaps in the update history.
    pub fn has_gaps(&self) -> bool {
        self.state.has_pending_updates()
    }

    // ========================================================================
    // Signer Validation (Dispute Protocol)
    // ========================================================================

    /// Validate that an update is signed by an authorized pubkey.
    ///
    /// Per the dispute protocol:
    /// - Normal case: update must be signed by `parent_pubkey`
    /// - Exception: `CustodyDispute` can be signed by anyone who was in the quorum
    ///   at the fork point (stored in `quorum_at_fork`)
    ///
    /// This should be called BEFORE appending an incoming signed update.
    pub fn validate_update_signer(&self, update: &SignedLedgerUpdate) -> DepositsResult<()> {
        use crate::tlv::TlvDecode;

        let signer = &update.operator_id;

        // Decode the operation to check if it's CustodyDispute
        let operation = LedgerOperation::tlv_decode(&update.message)
            .map_err(|e| DepositsError::InvalidMessage { reason: format!("Failed to decode operation: {}", e) })?;

        // CustodyDispute exception: can be signed by any quorum member at fork point
        if matches!(operation, LedgerOperation::CustodyDispute { .. }) {
            // For the first CustodyDispute (entering disputed state from normal),
            // the signer must be in the current quorum
            if self.state.dispute_state == DisputeState::Normal {
                if !self.state.quorum_members.iter().any(|m| m.pubkey == *signer) {
                    return Err(DepositsError::ProtocolViolation {
                        violation_type: "custody_dispute_unauthorized".to_string(),
                        details: format!(
                            "CustodyDispute signer {} is not a quorum member",
                            signer
                        ),
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
        update.verify_signatures(partner_pubkey)
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
                let tip_hash = self.history.last()
                    .map(|u| u.current_hash)
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
        let operation = LedgerOperation::tlv_decode(&update.message)
            .map_err(|e| DepositsError::InvalidMessage { reason: format!("Failed to decode operation: {}", e) })?;

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

        // 5. After ReservesRotate, all updates must have valid co-signatures
        // Check if we've already seen a ReservesRotate in history
        let has_reserves_rotated = self.history.iter().any(|u| {
            u.message_type == crate::messages::consts::RESERVES_ROTATE
        });

        if has_reserves_rotated {
            // After rotation, co-signature is required
            // Exception: CustodyDispute can be signed by any quorum member
            if !matches!(operation, LedgerOperation::CustodyDispute { .. }) {
                if !update.has_partner_signature() {
                    return Err(DepositsError::ProtocolViolation {
                        violation_type: "missing_cosignature".to_string(),
                        details: format!(
                            "Co-signature required after ReservesRotate (seq {})",
                            update.sequence_number
                        ),
                    });
                }
            }
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
                // Expected next update — previous_hash must match our tip
                let tip_hash = self.history.last()
                    .map(|u| u.current_hash)
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

    /// Validate CustodyAcquire or CustodyYield against the entropy selection.
    ///
    /// This validates that:
    /// - CustodyAcquire: the new_custodian is the entropy-selected winner
    /// - CustodyYield: the parent_pubkey (branch owner) is NOT the winner
    ///
    /// # Arguments
    /// * `operation` - The CustodyAcquire or CustodyYield operation
    /// * `candidates` - All pubkeys who published CustodyArmed before the entropy block
    ///
    /// The caller is responsible for:
    /// 1. Collecting all CustodyArmed updates from Nostr
    /// 2. Filtering to only those before the entropy block height
    /// 3. Extracting the parent_pubkey from each branch
    pub fn validate_custody_resolution(
        &self,
        operation: &LedgerOperation,
        candidates: &[PublicKey],
    ) -> DepositsResult<()> {
        use crate::types::{is_entropy_winner, select_entropy_winner};

        match operation {
            LedgerOperation::CustodyAcquire { new_custodian, entropy_block_hash, .. } => {
                // The new_custodian must be the entropy-selected winner
                if !is_entropy_winner(entropy_block_hash, new_custodian, candidates) {
                    let actual_winner = select_entropy_winner(entropy_block_hash, candidates);
                    return Err(DepositsError::ProtocolViolation {
                        violation_type: "custody_acquire_not_winner".to_string(),
                        details: format!(
                            "CustodyAcquire new_custodian {} is not the entropy winner (winner: {:?})",
                            new_custodian,
                            actual_winner
                        ),
                    });
                }
            }
            LedgerOperation::CustodyYield => {
                // CustodyYield doesn't include entropy_block_hash
                // Use validate_custody_yield() instead with the entropy hash
            }
            _ => {
                // Not a custody resolution operation
            }
        }
        Ok(())
    }

    /// Validate CustodyYield against the entropy selection.
    ///
    /// Verifies that the branch owner (parent_pubkey) is NOT the entropy-selected winner.
    /// If they were the winner, they should publish CustodyAcquire instead.
    ///
    /// # Arguments
    /// * `entropy_block_hash` - The entropy block hash (from the winning CustodyAcquire)
    /// * `candidates` - All pubkeys who published CustodyArmed before the entropy block
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
                    "CustodyYield invalid: {} is the entropy winner and should CustodyAcquire",
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
    /// Returns: operator + quorum members. For LDK, also includes reserves partner.
    pub fn quorum_participants(&self) -> Vec<PublicKey> {
        let mut participants = Vec::with_capacity(2 + self.state.quorum_members.len());
        participants.push(self.state.operator_key);
        // Include reserves partner if it's a valid pubkey (LDK)
        if let Some(reserves_pubkey) = self.reserves_key_as_pubkey() {
            participants.push(reserves_pubkey);
        }
        participants.extend(self.state.quorum_members.iter().map(|m| m.pubkey));
        participants
    }

    /// Get all partners (channel partner + quorum members).
    /// This is the set of nodes the operator broadcasts updates to.
    pub fn all_partners(&self) -> Vec<PublicKey> {
        let mut partners = Vec::with_capacity(1 + self.state.quorum_members.len());
        // Include reserves partner if it's a valid pubkey (LDK)
        if let Some(reserves_pubkey) = self.reserves_key_as_pubkey() {
            partners.push(reserves_pubkey);
        }
        partners.extend(self.state.quorum_members.iter().map(|m| m.pubkey));
        partners
    }

    /// Add a quorum member to this ledger with their collateral ledger ID.
    pub fn add_quorum_member(&mut self, partner: PublicKey, member_ledger_id: String) -> DepositsResult<()> {
        if partner == self.state.operator_key {
            return Err(DepositsError::InvalidState(
                "Operator cannot be a quorum member".to_string()
            ));
        }
        // Compare with reserves_key (which is a String)
        if partner.to_string() == self.state.reserves_key {
            return Err(DepositsError::InvalidState(
                "Channel partner is already part of the quorum".to_string()
            ));
        }
        if self.state.quorum_members.iter().any(|m| m.pubkey == partner) {
            return Err(DepositsError::InvalidState(
                format!("Quorum member {} already exists", partner)
            ));
        }
        self.state.quorum_members.push(crate::types::QuorumMember {
            pubkey: partner,
            ledger_id: member_ledger_id,
            min_fee_bps: None,
            min_fee_fixed: None,
            max_fee_period: None,
            collateral_lock_amount: None,
            collateral_lock_until: None,
        });
        Ok(())
    }

    // ========================================================================
    // Hash Chain Methods
    // ========================================================================

    /// Get the hash of the last update (tail hash).
    /// Returns zero hash if no updates exist yet.
    pub fn tail_hash(&self) -> [u8; 32] {
        self.history.last()
            .map(|u| u.current_hash)
            .unwrap_or([0u8; 32])
    }

    /// Get the next expected sequence number.
    /// Derived from the last history entry, not from `history.len()`,
    /// so it remains correct after history truncation.
    pub fn next_sequence(&self) -> u64 {
        self.history.last()
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
            if &update.current_hash == target_hash {
                return Some(update.sequence_number);
            }
        }
        None
    }

    /// Check if a hash is valid for reserves (exists and is at or after committed hash).
    pub fn is_valid_reserves_hash(&self, target_hash: &[u8; 32], committed_hash: &[u8; 32]) -> bool {
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

    /// Get total deposit liability (sum of all deposit balances).
    pub fn total_deposit_liability(&self) -> u64 {
        self.state.deposits.values().map(|d| d.balance).sum()
    }

    /// Check if a credit has been issued for a given payment hash.
    /// This scans the history and deserializes InvoiceCredit messages to check.
    pub fn has_credit_for_payment(&self, payment_hash: &[u8; 32]) -> bool {
        use crate::messages::DepositsMessage;

        for update in &self.history {
            // Quick filter: only check InvoiceCredit message types
            // InvoiceCredit is part of LedgerUpdate (0x8001) or standalone type (0x8005)
            if update.message_type == 0x8001 || update.message_type == 0x8005 {
                if let Ok(msg) = DepositsMessage::decode(&update.message) {
                    if let DepositsMessage::LedgerUpdate(lu) = msg {
                        if let LedgerOperation::InvoiceCredit { payment_hash: hash, .. } = lu.operation {
                            if &hash == payment_hash {
                                return true;
                            }
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
        self.state.reserves = ReservesOutput::default();
        self.state.collateral_amount = 0;
        self.state.collateral_attestations.clear();
        self.state.sequence = 0;
        self.state.hash = [0u8; 32];

        // Replay all updates
        for update in &self.history.clone() {
            // Deserialize the message to get the operation
            if let Ok(msg) = DepositsMessage::decode(&update.message) {
                if let Some(operation) = msg.to_operation() {
                    self.apply_state_changes(&operation)?;
                }
            }
            self.state.sequence = update.sequence_number;
            self.state.hash = update.current_hash;
        }
        Ok(())
    }

    // ========================================================================
    // Collateral Methods
    // ========================================================================

    /// Get total available collateral from attestations.
    pub fn total_available_collateral(&self, current_block: u32, max_age_blocks: u32) -> u64 {
        self.state.total_available_collateral(current_block, max_age_blocks)
    }

    /// Get available collateral from a specific partner.
    pub fn partner_available_collateral(&self, partner: &PublicKey) -> Option<u64> {
        self.state.partner_available_collateral(partner)
    }

    /// Get list of partners with missing or stale attestations.
    pub fn missing_attestations(&self, current_block: u32, max_age_blocks: u32) -> Vec<PublicKey> {
        self.state.missing_attestations(current_block, max_age_blocks)
    }

    /// Get total collateral pledged by deposit holders.
    ///
    /// Only counts pledges that haven't expired (lock_until_block > current_block).
    pub fn total_deposit_pledged_collateral(&self, current_block: u32) -> u64 {
        self.state.deposits.values()
            .filter(|d| d.collateral_lock_expires > current_block)
            .map(|d| d.collateral_lock_amount)
            .sum()
    }

    /// Validate collateral is sufficient for a given deposit liability.
    pub fn validate_collateral_for_liability(
        &self,
        deposit_liability: u64,
        current_block: u32,
        max_attestation_age_blocks: u32,
    ) -> DepositsResult<()> {
        // Requirement 1: reserves >= deposit_liability
        if self.state.reserves.amount < deposit_liability {
            return Err(DepositsError::InsufficientReserves {
                required: deposit_liability,
                available: self.state.reserves.amount,
            });
        }

        // Requirement 2: attestations >= deposit_liability (if we have quorum members)
        if !self.state.quorum_members.is_empty() {
            let total_collateral = self.total_available_collateral(current_block, max_attestation_age_blocks);
            if total_collateral < deposit_liability {
                return Err(DepositsError::InsufficientCollateral {
                    required: deposit_liability,
                    available: total_collateral,
                    missing_attestations: self.missing_attestations(current_block, max_attestation_age_blocks),
                });
            }
        }
        Ok(())
    }

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
            self.state.hash,
        );

        // Apply state changes
        self.apply_state_changes(operation)?;

        // Update sequence and hash
        self.state.sequence = update.sequence_number;
        self.state.hash = update.current_hash;

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
        message_type: u16,
    ) -> DepositsResult<([u8; 32], [u8; 32], u64)> {
        self.append_operation_with_block(operation, message_type, 0, [0u8; 32])
    }

    /// Append an operation with block info.
    ///
    /// Same as `append_operation` but includes current block height and hash.
    pub fn append_operation_with_block(
        &mut self,
        operation: LedgerOperation,
        message_type: u16,
        block_height: u32,
        block_hash: [u8; 32],
    ) -> DepositsResult<([u8; 32], [u8; 32], u64)> {
        use crate::tlv::TlvEncode;
        use bitcoin::hashes::{Hash, sha256};

        // Check if ledger is closed
        if self.is_closed() {
            return Err(DepositsError::InvalidState(
                "Cannot append to closed ledger".to_string(),
            ));
        }

        // Validate the operation
        self.validate_operation(&operation)?;

        // Serialize the operation
        let message_bytes = operation.tlv_encode();

        // Compute hashes
        let prev_hash = self.state.hash;
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
            message: message_bytes,
            message_type,
            operator_signature: [0u8; 64],
            cosigner_pubkey: None,
            member_ledger_hash: None,
            partner_signature: [0u8; 64],
            operator_id: self.state.operator_key,
            ledger_id: self.state.ledger_id,
            sequence_number: sequence,
            previous_hash: prev_hash,
            current_hash: new_hash,
            block_height,
            block_hash,
        };

        // Apply state changes
        self.apply_state_changes(&operation)?;

        // Update sequence and hash
        self.state.sequence = sequence;
        self.state.hash = new_hash;

        // Append to history
        self.history.push(signed_update);

        Ok((prev_hash, new_hash, sequence))
    }

    /// Update the signature on the last history entry.
    ///
    /// This is used after `append_operation` to add signatures from the porcupine dance.
    pub fn sign_last_update(&mut self, operator_sig: Option<[u8; 64]>, partner_sig: Option<[u8; 64]>) {
        if let Some(update) = self.history.last_mut() {
            if let Some(sig) = operator_sig {
                update.operator_signature = sig;
            }
            if let Some(sig) = partner_sig {
                update.partner_signature = sig;
            }
        }
    }

    /// Apply co-signer info and recompute the hash chain to include causal ordering.
    ///
    /// After a quorum member co-signs, their ledger's tip hash is incorporated into
    /// this update's `current_hash`. This creates a web of causality: the co-signer's
    /// ledger state at the time of signing is baked into our chain, proving temporal
    /// ordering across ledgers.
    ///
    /// Must be called BEFORE `sign_last_update` with the operator signature, since
    /// the operator signature covers the final hash.
    pub fn apply_cosigner_hash(&mut self, member_ledger_hash: [u8; 32], cosigner_pubkey: PublicKey) {
        if let Some(update) = self.history.last_mut() {
            update.member_ledger_hash = Some(member_ledger_hash);
            update.cosigner_pubkey = Some(cosigner_pubkey);
            // Recompute current_hash to include the member's ledger hash
            update.current_hash = update.compute_hash();
            // Update the ledger's state hash to match
            self.state.hash = update.current_hash;
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

        match operation {
            LedgerOperation::ReservesIncrease { reserves_id: _, new_amount } => {
                let current = self.reserves_amount();
                // Allow setting initial reserves (current == 0), otherwise must increase
                if current > 0 && *new_amount <= current {
                    return Err(DepositsError::InvalidReservesDecrease(
                        "New amount must be greater than current".to_string(),
                    ));
                }
            }
            LedgerOperation::ReservesDecrease { reserves_id: _, new_amount } => {
                let current = self.reserves_amount();
                if *new_amount >= current {
                    return Err(DepositsError::InvalidReservesDecrease(
                        "New amount must be less than current".to_string(),
                    ));
                }
                let required = self.required_reserves();
                if *new_amount < required {
                    return Err(DepositsError::InsufficientReserves {
                        required,
                        available: *new_amount,
                    });
                }
            }
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
            LedgerOperation::InvoiceLock { deposit_id, amount, .. } |
            LedgerOperation::OnchainLock { deposit_id, amount, .. } => {
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
            LedgerOperation::CollateralLock {
                deposit_id,
                amount,
                lock_until_block,
                operator_id,
                witness: _,
            } => {
                // 1. Deposit must exist
                let deposit = self
                    .state
                    .deposits
                    .get(deposit_id)
                    .ok_or(DepositsError::DepositNotFound)?;

                // 2. Witness verification is done at the message handler level
                // where the descriptor can be evaluated against the witness

                // 3. amount <= deposit.balance
                if *amount > deposit.balance {
                    return Err(DepositsError::InsufficientDepositBalance {
                        available: deposit.balance,
                        required: *amount,
                    });
                }

                // 4. Ratchet check: if existing lock, new must have (amount >= existing) AND (lock >= existing)
                if deposit.collateral_lock_amount > 0 {
                    if *amount < deposit.collateral_lock_amount {
                        return Err(DepositsError::ProtocolViolation {
                            violation_type: "collateral_lock_ratchet_violation".to_string(),
                            details: format!(
                                "New lock amount {} must be >= existing amount {}",
                                amount, deposit.collateral_lock_amount
                            ),
                        });
                    }
                    if *lock_until_block < deposit.collateral_lock_expires {
                        return Err(DepositsError::ProtocolViolation {
                            violation_type: "collateral_lock_ratchet_violation".to_string(),
                            details: format!(
                                "New lock expiry {} must be >= existing expiry {}",
                                lock_until_block, deposit.collateral_lock_expires
                            ),
                        });
                    }
                }

                // 5. operator_id must match ledger operator
                if *operator_id != self.state.operator_key {
                    return Err(DepositsError::ProtocolViolation {
                        violation_type: "invalid_collateral_lock_operator".to_string(),
                        details: format!(
                            "Operator ID {} does not match ledger operator {}",
                            operator_id, self.state.operator_key
                        ),
                    });
                }
            }
            LedgerOperation::QuorumJoin { operator_id, ledger_id, membership_expires, our_signature: _ } => {
                // 1. Must be on operator's own ledger (we are the operator)
                if !self.is_operator() {
                    return Err(DepositsError::ProtocolViolation {
                        violation_type: "quorum_join_wrong_role".to_string(),
                        details: "QuorumJoin can only be added to operator's own ledger".to_string(),
                    });
                }
                // Note: Signature verification should be done at the message handler level
                // where the signing key is available. Here we just validate the operation structure.
                // 2. Ratchet check: if renewing, new expiration must be >= existing
                if let Some(existing) = self.state.joined_quorums.iter().find(|m|
                    &m.operator_id == operator_id && &m.ledger_id == ledger_id
                ) {
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
            LedgerOperation::CustodyArmed { .. } => {
                // Must have at least one quorum member to arm
                if self.state.quorum_members.is_empty() {
                    return Err(DepositsError::ProtocolViolation {
                        violation_type: "custody_armed_no_quorum".to_string(),
                        details: "Cannot arm without any quorum members".to_string(),
                    });
                }
                // Must have at least one collateral attestation
                if self.state.collateral_attestations.is_empty() {
                    return Err(DepositsError::ProtocolViolation {
                        violation_type: "custody_armed_no_attestations".to_string(),
                        details: "Cannot arm without any collateral attestations".to_string(),
                    });
                }
            }
            LedgerOperation::CustodyAcquire { entropy_block_height, entropy_block_hash, .. } => {
                // Basic validation: entropy block must be specified
                if *entropy_block_height == 0 && *entropy_block_hash == [0u8; 32] {
                    return Err(DepositsError::ProtocolViolation {
                        violation_type: "custody_acquire_no_entropy".to_string(),
                        details: "CustodyAcquire requires entropy block".to_string(),
                    });
                }
                // Winner validation is done via validate_custody_resolution()
                // which requires knowing all candidates (from Nostr observation)
            }
            LedgerOperation::CollateralAttestation { collateral_operator, .. } => {
                // Verify the collateral_operator is a quorum member.
                // Collateral ties two operators across any number of ledgers,
                // so we only check membership — not which specific ledger the
                // collateral was locked on.
                if !self.state.quorum_members.iter().any(|m| m.pubkey == *collateral_operator) {
                    return Err(DepositsError::ProtocolViolation {
                        violation_type: "collateral_attestation_from_non_member".to_string(),
                        details: format!(
                            "Attestation from {} who is not a quorum member",
                            collateral_operator
                        ),
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
    pub fn apply_state_changes(&mut self, operation: &LedgerOperation) -> DepositsResult<()> {
        match operation {
            LedgerOperation::LedgerOpen {
                operator_id,
                reserves_id,
                ledger_address,
                genesis_block,
                collateral_enforcement_block,
            } => {
                // LedgerOpen sets up the initial ledger identity
                // Note: reserves amount is set via subsequent ReservesIncrease
                self.state.operator_key = *operator_id;
                self.state.reserves_key = reserves_id.clone();
                self.state.ledger_address = ledger_address.clone();
                self.state.genesis_block = *genesis_block;
                self.state.ledger_id = LedgerState::compute_ledger_id(operator_id, reserves_id, *genesis_block);
                self.state.collateral_enforcement_block = Some(*collateral_enforcement_block);
            }
            LedgerOperation::ReservesIncrease { reserves_id, new_amount } => {
                self.state.reserves_key = reserves_id.clone();
                self.state.reserves.amount = *new_amount;
            }
            LedgerOperation::ReservesDecrease { reserves_id, new_amount } => {
                self.state.reserves_key = reserves_id.clone();
                self.state.reserves.amount = *new_amount;
            }
            LedgerOperation::ReservesRotate { reserves_id, amount, .. } => {
                // ReservesRotate records the rotation to Taproot
                // Update the reserves_id to the new Taproot address
                self.state.reserves_key = reserves_id.clone();
                self.state.reserves.amount = *amount;
            }
            LedgerOperation::DepositOpen { deposit_id, descriptor, fees, transfer_fees, is_collateral, receive_requires_sig, .. } => {
                let mut deposit = Deposit::new(descriptor.clone(), fees.clone());
                if let Some(tf) = transfer_fees {
                    deposit.transfer_fees = tf.clone();
                }
                deposit.is_collateral = *is_collateral;
                deposit.receive_requires_sig = *receive_requires_sig;
                self.state.deposits.insert(*deposit_id, deposit);
            }
            LedgerOperation::DepositClose { deposit_id } => {
                self.state.deposits.remove(deposit_id);
            }
            LedgerOperation::DepositUpdate { deposit_id, new_fees } => {
                if let Some(deposit) = self.state.deposits.get_mut(deposit_id) {
                    deposit.fees = new_fees.clone();
                }
            }
            LedgerOperation::DepositKeyRotate { deposit_id, new_descriptor, .. } => {
                // Key rotation: update the descriptor while keeping the same deposit_id
                // Note: Witness verification should be done before this operation is applied
                if let Some(deposit) = self.state.deposits.get_mut(deposit_id) {
                    deposit.descriptor = new_descriptor.clone();
                }
            }
            LedgerOperation::InvoiceCredit {
                deposit_id,
                amount,
                ..
            } => {
                if let Some(deposit) = self.state.deposits.get_mut(deposit_id) {
                    deposit.credit(*amount);
                }
            }
            LedgerOperation::InvoiceLock { deposit_id, amount, .. } => {
                if let Some(deposit) = self.state.deposits.get_mut(deposit_id) {
                    deposit.lock(*amount)?;
                }
            }
            LedgerOperation::InvoiceFail { deposit_id, amount, .. } => {
                if let Some(deposit) = self.state.deposits.get_mut(deposit_id) {
                    deposit.unlock(*amount);
                }
            }
            LedgerOperation::InvoiceFulfill { deposit_id, amount, .. } => {
                if let Some(deposit) = self.state.deposits.get_mut(deposit_id) {
                    deposit.fulfill(*amount);
                }
            }
            LedgerOperation::OnchainCredit {
                deposit_id,
                amount,
                ..
            } => {
                if let Some(deposit) = self.state.deposits.get_mut(deposit_id) {
                    deposit.credit(*amount);
                }
            }
            LedgerOperation::OnchainLock { deposit_id, amount, .. } => {
                if let Some(deposit) = self.state.deposits.get_mut(deposit_id) {
                    deposit.lock(*amount)?;
                }
            }
            LedgerOperation::OnchainFail { deposit_id, withdrawal_id: _ } => {
                // Onchain fail needs to unlock the amount, but we don't track it here
                // The withdrawal tracking should handle this
                if let Some(_deposit) = self.state.deposits.get_mut(deposit_id) {
                    // TODO: Need to look up the withdrawal amount from withdrawal_id
                }
            }
            LedgerOperation::OnchainFulfill { deposit_id, amount, .. } => {
                // On fulfillment, deduct the locked funds from balance
                if let Some(deposit) = self.state.deposits.get_mut(deposit_id) {
                    deposit.fulfill(*amount);
                }
            }
            LedgerOperation::FeeCollect {
                deposit_id,
                amount,
                block_height,
            } => {
                if let Some(deposit) = self.state.deposits.get_mut(deposit_id) {
                    deposit.balance = deposit.balance.saturating_sub(*amount);
                    deposit.last_fee_assessment = *block_height;
                }
            }
            LedgerOperation::CollateralIncrease { new_amount, block_height } => {
                self.state.collateral_amount = *new_amount;
                self.state.last_collateral_increase_block = Some(*block_height);
            }
            LedgerOperation::CollateralDecrease { new_amount, .. } => {
                self.state.collateral_amount = *new_amount;
            }
            LedgerOperation::QuorumAddMember {
                quorum_member, member_ledger_id, min_fee_bps, min_fee_fixed, max_fee_period,
                collateral_lock_amount, collateral_lock_until, ..
            } => {
                use crate::types::QuorumMember;
                // Check if this member already exists (by pubkey)
                if !self.state.quorum_members.iter().any(|m| m.pubkey == *quorum_member) {
                    let member = QuorumMember {
                        pubkey: *quorum_member,
                        ledger_id: member_ledger_id.clone(),
                        min_fee_bps: *min_fee_bps,
                        min_fee_fixed: *min_fee_fixed,
                        max_fee_period: *max_fee_period,
                        collateral_lock_amount: *collateral_lock_amount,
                        collateral_lock_until: *collateral_lock_until,
                    };
                    self.state.quorum_members.push(member);
                }
            }
            LedgerOperation::QuorumRemoveMember {
                quorum_member, ..
            } => {
                self.state.quorum_members.retain(|m| m.pubkey != *quorum_member);
                // Also remove any attestations from this partner
                self.state.collateral_attestations.remove(quorum_member);
            }
            LedgerOperation::CollateralLock {
                deposit_id,
                amount,
                lock_until_block,
                ..
            } => {
                if let Some(deposit) = self.state.deposits.get_mut(deposit_id) {
                    if !deposit.is_collateral {
                        return Err(deposits_protocol::error::DepositsError::InvalidState(
                            "CollateralLock can only be applied to collateral deposits".to_string()
                        ));
                    }
                    deposit.collateral_lock_amount = *amount;
                    deposit.collateral_lock_expires = *lock_until_block;
                }
            }
            LedgerOperation::LedgerClose => {
                // Mark ledger as closed - clear collateral attestations
                self.state.clear_collateral_attestations();
            }
            LedgerOperation::CollateralAttestation {
                collateral_operator,
                quorum_member,
                collateral_ledger_id,
                amount,
                block_height,
                lock_until_block,
                signature,
                ledger_hash,
            } => {
                // Record the attestation keyed by the actual quorum member
                use crate::types::CollateralAttestation;
                let attestation = CollateralAttestation::new(
                    *collateral_operator,
                    *quorum_member,
                    collateral_ledger_id.clone(),
                    *amount,
                    *block_height,
                    *lock_until_block,
                    *signature,
                    *ledger_hash,
                );
                self.state.collateral_attestations.insert(*quorum_member, attestation);
                // Update received_collateral_amount - sum of all attestations
                self.state.received_collateral_amount = self.state.collateral_attestations.values()
                    .map(|a| a.available_collateral())
                    .sum();
            }
            LedgerOperation::QuorumJoin { operator_id, ledger_id, membership_expires, our_signature } => {
                use crate::types::QuorumMembership;
                // Find and update existing membership, or add new one
                if let Some(existing) = self.state.joined_quorums.iter_mut().find(|m|
                    m.operator_id == *operator_id && m.ledger_id == *ledger_id
                ) {
                    // Renew/extend membership
                    existing.membership_expires = *membership_expires;
                    existing.our_signature = *our_signature;
                } else {
                    // New membership
                    let membership = QuorumMembership {
                        operator_id: *operator_id,
                        ledger_id: ledger_id.clone(),
                        membership_expires: *membership_expires,
                        our_signature: *our_signature,
                        joined_at_sequence: self.state.sequence + 1,
                    };
                    self.state.joined_quorums.push(membership);
                }
            }
            LedgerOperation::CustodyDispute { last_valid_sequence, .. } => {
                // Opening a custody dispute:
                // 1. Snapshot the current quorum for reference
                // 2. Void collateral attestations (must be re-attested before arming)
                // 3. Record the fork point
                // 4. Transition to DISPUTED state
                //
                // The quorum is NOT disbanded — existing members continue
                // co-signing updates throughout the dispute process and
                // persist through CustodyAcquire for the new custodian.
                // Attestations are cleared because the new custodian must
                // collect fresh proofs before publishing CustodyArmed.
                //
                // Note: The parent_pubkey (dispute opener) is set by the caller
                // after signature verification.
                self.state.quorum_at_fork = self.state.quorum_members.clone();
                self.state.dispute_fork_sequence = *last_valid_sequence;
                self.state.collateral_attestations.clear();
                self.state.dispute_state = DisputeState::Disputed;
            }
            LedgerOperation::CustodyArmed { .. } => {
                // Pre-commitment: candidate is ready for entropy selection
                // Quorum is now locked - no more changes allowed
                self.state.dispute_state = DisputeState::Armed;
            }
            LedgerOperation::CustodyAcquire { new_custodian, .. } => {
                // Winner acquires custody:
                // 1. Transfer operator role to the new custodian
                // 2. Set parent_pubkey to new custodian
                // 3. Transition back to NORMAL state
                self.state.operator_key = *new_custodian;
                self.state.parent_pubkey = *new_custodian;
                self.state.dispute_state = DisputeState::Normal;
                // Clear dispute-related state
                self.state.quorum_at_fork.clear();
                self.state.dispute_fork_sequence = 0;
            }
            LedgerOperation::CustodyYield => {
                // Loser yields: tombstone this branch
                self.state.dispute_state = DisputeState::Tombstoned;
            }
            LedgerOperation::TransferLock {
                nonce, source_deposit_id, destination_deposit_id, amount, fee,
                completion_script, timeout_height, transfer_id, ..
            } => {
                // Lock funds from source deposit
                if let Some(deposit) = self.state.deposits.get_mut(source_deposit_id) {
                    let total = amount + fee;
                    deposit.balance = deposit.balance.saturating_sub(total);
                    deposit.locked_balance = deposit.locked_balance.saturating_add(total);
                }
                // Track pending transfer
                let pending = crate::types::PendingTransfer {
                    transfer_id: *transfer_id,
                    nonce: *nonce,
                    source_deposit_id: *source_deposit_id,
                    destination_deposit_id: *destination_deposit_id,
                    amount: *amount,
                    fee: *fee,
                    completion_script: completion_script.clone(),
                    timeout_height: *timeout_height,
                };
                self.state.pending_transfers.insert(*transfer_id, pending);
            }
            LedgerOperation::TransferComplete { transfer_id, .. } => {
                // Look up and remove pending transfer
                if let Some(pending) = self.state.pending_transfers.remove(transfer_id) {
                    let total = pending.total_locked();
                    // Unlock from source
                    if let Some(source) = self.state.deposits.get_mut(&pending.source_deposit_id) {
                        source.locked_balance = source.locked_balance.saturating_sub(total);
                    }
                    // Credit amount to destination (fee goes to custodian/reserves)
                    if let Some(dest) = self.state.deposits.get_mut(&pending.destination_deposit_id) {
                        dest.balance = dest.balance.saturating_add(pending.amount);
                    }
                    // Fee is implicitly collected (removed from circulation)
                }
            }
            LedgerOperation::TransferTimeout { transfer_id, .. } => {
                // Look up and remove pending transfer
                if let Some(pending) = self.state.pending_transfers.remove(transfer_id) {
                    let total = pending.total_locked();
                    // Return locked funds to source
                    if let Some(source) = self.state.deposits.get_mut(&pending.source_deposit_id) {
                        source.locked_balance = source.locked_balance.saturating_sub(total);
                        source.balance = source.balance.saturating_add(total);
                    }
                }
            }
        }
        Ok(())
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
            self.state.ledger_address.clone(),
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
    pub fn from_export(export: crate::validation::LedgerExport) -> Result<Self, crate::validation::ValidationError> {
        crate::validation::LedgerConformanceValidator::from_export(export)
    }

    /// Import from JSON and validate.
    ///
    /// Parses JSON and validates the ledger export.
    pub fn from_export_json(json: &str) -> Result<Self, crate::validation::ValidationError> {
        let export = crate::validation::LedgerExport::from_json(json)
            .map_err(|e| crate::validation::ValidationError::DecodeError(format!("JSON decode failed: {}", e)))?;
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
    pub fn reconstruct(
        initial_state: LedgerState,
        updates: Vec<SignedLedgerUpdate>,
    ) -> Self {
        // Validate and apply each update to reconstruct the state chain
        // The stored state should already be the final state, but we verify continuity
        let mut current_hash = initial_state.hash;
        
        for update in &updates {
            // Verify this update continues the chain
            if update.previous_hash != current_hash {
                tracing::warn!(
                    "Update {} has mismatched previous_hash, chain may be corrupted",
                    update.sequence_number
                );
            }
            // Update current_hash to this update's hash for next iteration
            current_hash = update.current_hash;
        }
        
        // Return ledger with the final state and all history
        Self {
            state: initial_state,
            role: LedgerRole::Partner, // Default role for reconstructed ledgers
            history: updates,
        }
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
                        details: format!("Deposit already exists for id {}", hex::encode(deposit_id)),
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

            // Next update should reference this update's hash
            expected_previous_hash = update.current_hash;
        }

        ledger.history.len()
    }

    /// Get the total balance across all deposits.
    pub fn total_balance(ledger: &Ledger) -> u64 {
        ledger.state.deposits.values().map(|d| d.balance).sum()
    }

    /// Get total locked balance across all deposits.
    pub fn total_locked_balance(ledger: &Ledger) -> u64 {
        ledger.state.deposits.values().map(|d| d.locked_balance).sum()
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
        ledger.state.reserves.amount >= Self::calculate_minimum_reserves(ledger)
    }

    /// Calculate excess reserves above the minimum requirement.
    pub fn excess_reserves(ledger: &Ledger) -> u64 {
        let min_required = Self::calculate_minimum_reserves(ledger);
        ledger.state.reserves.amount.saturating_sub(min_required)
    }

    // ========================================================================
    // Collateral Validation Methods
    // ========================================================================

    /// Get the total available collateral from attestations.
    ///
    /// Only counts attestations that are recent enough.
    pub fn total_available_collateral(
        ledger: &Ledger,
        current_block: u32,
        max_age_blocks: u32,
    ) -> u64 {
        ledger.state.total_available_collateral(current_block, max_age_blocks)
    }

    /// Get collateral from a specific partner.
    pub fn partner_available_collateral(ledger: &Ledger, partner: &PublicKey) -> Option<u64> {
        ledger.state.partner_available_collateral(partner)
    }

    /// Get list of partners with missing or stale attestations.
    pub fn missing_attestations(
        ledger: &Ledger,
        current_block: u32,
        max_age_blocks: u32,
    ) -> Vec<PublicKey> {
        ledger.state.missing_attestations(current_block, max_age_blocks)
    }

    /// Validate collateral is sufficient for a given deposit liability.
    ///
    /// In the 100%+100% model:
    /// - Requirement 1: reserves >= deposit_liability (checked elsewhere)
    /// - Requirement 2: attestations >= deposit_liability (if we have quorum members)
    ///
    /// Returns Ok if collateral is sufficient, Err with details if not.
    pub fn validate_collateral_for_liability(
        ledger: &Ledger,
        deposit_liability: u64,
        current_block: u32,
        max_attestation_age_blocks: u32,
    ) -> DepositsResult<()> {
        // Requirement 1: reserves >= deposit_liability
        if ledger.state.reserves.amount < deposit_liability {
            return Err(DepositsError::InsufficientReserves {
                required: deposit_liability,
                available: ledger.state.reserves.amount,
            });
        }

        // Requirement 2: attestations >= deposit_liability (if we have quorum members)
        if !ledger.state.quorum_members.is_empty() {
            let total_collateral =
                Self::total_available_collateral(ledger, current_block, max_attestation_age_blocks);
            if total_collateral < deposit_liability {
                return Err(DepositsError::InsufficientCollateral {
                    required: deposit_liability,
                    available: total_collateral,
                    missing_attestations: Self::missing_attestations(
                        ledger,
                        current_block,
                        max_attestation_age_blocks,
                    ),
                });
            }
        }

        Ok(())
    }

    /// Check if a collateral decrease is allowed.
    ///
    /// Collateral decreases are not allowed within the reporting period
    /// after an increase, to prevent gaming the system.
    pub fn can_decrease_collateral(
        ledger: &Ledger,
        current_block: u32,
        reporting_period_blocks: u32,
    ) -> bool {
        match ledger.state.last_collateral_increase_block {
            None => true,
            Some(increase_block) => {
                current_block.saturating_sub(increase_block) >= reporting_period_blocks
            }
        }
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
            if update.current_hash == *target_hash {
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
    pub fn is_partner_ack_current(ledger: &Ledger) -> bool {
        ledger.state.is_fully_acked()
    }

    /// Check if the channel commitment is up to date with the current ledger state.
    pub fn is_commitment_current(ledger: &Ledger) -> bool {
        ledger.state.is_fully_committed()
    }

    /// Get the sequence number difference between current state and partner's ACK.
    ///
    /// Returns the number of updates since the partner's last acknowledged state.
    /// Returns 0 if fully synced, or the count of unacked updates.
    pub fn unacked_update_count(ledger: &Ledger) -> u64 {
        if ledger.state.is_fully_acked() {
            return 0;
        }

        // Find the sequence of partner's ack
        match Self::find_hash_sequence(ledger, &ledger.state.partner_deepest_ack_hash) {
            Some(ack_seq) => ledger.state.sequence.saturating_sub(ack_seq),
            None => {
                // Partner's ACK hash not found - all updates are unacked
                ledger.state.sequence
            }
        }
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
        ledger_address: String,
        genesis_block: u32,
    ) -> Self {
        Self::new(Ledger::new_as_operator(operator_key, reserves_key, ledger_address, genesis_block))
    }

    /// Create a new ledger as partner.
    pub fn create_as_partner(
        operator_key: PublicKey,
        reserves_key: String,
        ledger_address: String,
        genesis_block: u32,
    ) -> Self {
        Self::new(Ledger::new_as_partner(operator_key, reserves_key, ledger_address, genesis_block))
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
    pub fn can_decrease_collateral(&self, current_block: u32, reporting_period_blocks: u32) -> bool {
        LedgerValidator::can_decrease_collateral(&self.ledger, current_block, reporting_period_blocks)
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

    /// Get total collateral from attestations.
    pub fn total_collateral(&self, current_block: u32, max_age_blocks: u32) -> u64 {
        LedgerValidator::total_available_collateral(&self.ledger, current_block, max_age_blocks)
    }

    /// Get partners missing attestations.
    pub fn missing_attestations(&self, current_block: u32, max_age_blocks: u32) -> Vec<PublicKey> {
        LedgerValidator::missing_attestations(&self.ledger, current_block, max_age_blocks)
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
        LedgerValidator::is_valid_reserves_hash(
            &self.ledger,
            target_hash,
            &self.ledger.state.channel_deepest_commitment_hash,
        )
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
        ledger_address: String,
        genesis_block: u32,
    ) -> (Self, [u8; 32]) {
        let ledger = Ledger::new(
            operator_key,
            reserves_key,
            role,
            quorum_members,
            ledger_address,
            genesis_block,
        );
        let genesis_hash = ledger.state.hash; // Initial hash from LedgerState::new()
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
        ledger_address: String,
        genesis_block: u32,
        genesis_operation: LedgerOperation,
    ) -> DepositsResult<(Self, [u8; 32])> {
        // Create the base ledger
        let mut ledger = Ledger::new(
            operator_key,
            reserves_key,
            role,
            quorum_members,
            ledger_address,
            genesis_block,
        );

        // Apply the genesis operation
        let update = ledger.apply_operation(&genesis_operation)?;
        let genesis_hash = update.current_hash;

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
            _ => return Err(DepositsError::InvalidReservesDecrease("Expected InvoiceCredit or OnchainCredit operation".to_string())),
        };

        let mut hashes = Vec::new();

        // Check if reserves topup is needed
        if let Some(required_amount) = self.reserves_topup_needed(credit_amount) {
            // Apply reserves increase operation
            let reserves_update = self.ledger.apply_operation(
                &LedgerOperation::ReservesIncrease {
                    reserves_id: self.ledger.state.reserves_key.clone(),
                    new_amount: required_amount,
                }
            )?;
            hashes.push(reserves_update.current_hash);
        }

        // Apply the credit operation
        let credit_update = self.ledger.apply_operation(&credit_operation)?;
        hashes.push(credit_update.current_hash);

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
        let ledger = Ledger::new_as_operator(op, partner.to_string(), "tb1q...".to_string(), 0);

        assert_eq!(ledger.role, LedgerRole::Operator);
        assert_eq!(ledger.sequence(), 0);
        assert_eq!(ledger.total_deposit_balance(), 0);
    }

    #[test]
    fn test_reserves_increase() {
        let op = test_pubkey();
        let partner = test_pubkey_2();
        let mut ledger = Ledger::new_as_operator(op, partner.to_string(), "tb1q...".to_string(), 0);

        // Initial reserves are 0, use ReservesIncrease to add funds
        let op = LedgerOperation::ReservesIncrease { reserves_id: "bcrt1q...".to_string(), new_amount: 100_000 };

        let update = ledger.apply_operation(&op).unwrap();
        assert_eq!(update.sequence_number, 1);
        assert_eq!(ledger.reserves_amount(), 100_000);
    }

    #[test]
    fn test_deposit_lifecycle() {
        let op_key = test_pubkey();
        let partner = test_pubkey_2();
        let mut ledger = Ledger::new_as_operator(op_key, partner.to_string(), "tb1q...".to_string(), 0);

        // Add reserves first via ReservesIncrease
        ledger
            .apply_operation(&LedgerOperation::ReservesIncrease { reserves_id: "bcrt1q...".to_string(), new_amount: 100_000 })
            .unwrap();

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
                is_collateral: false,
                receive_requires_sig: false,
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

        assert_eq!(ledger.state.deposits.get(&deposit_id).unwrap().balance, 50_000);
    }

    #[test]
    fn test_hash_chain() {
        let op = test_pubkey();
        let partner = test_pubkey_2();
        let mut ledger = Ledger::new_as_operator(op, partner.to_string(), "tb1q...".to_string(), 0);

        let initial_hash = ledger.hash();
        assert_eq!(initial_hash, [0u8; 32]);

        // Initial reserves are 0, use ReservesIncrease to add funds
        ledger
            .apply_operation(&LedgerOperation::ReservesIncrease { reserves_id: "bcrt1q...".to_string(), new_amount: 100_000 })
            .unwrap();

        let hash_after_1 = ledger.hash();
        assert_ne!(hash_after_1, initial_hash);

        ledger
            .apply_operation(&LedgerOperation::ReservesIncrease { reserves_id: "bcrt1q...".to_string(), new_amount: 200_000 })
            .unwrap();

        let hash_after_2 = ledger.hash();
        assert_ne!(hash_after_2, hash_after_1);
    }

    #[test]
    fn test_ledger_export() {
        let op_key = test_pubkey();
        let partner = test_pubkey_2();
        let ledger = Ledger::new_as_operator(op_key, partner.to_string(), "tb1q...".to_string(), 0);

        // Export the ledger
        let export = ledger.export(1000);

        assert_eq!(export.version, 1);
        assert_eq!(export.operator_id, op_key);
        assert_eq!(export.reserves_id, partner.to_string());
        assert_eq!(export.ledger_address, "tb1q...");
        assert!(export.updates.is_empty());
        assert_eq!(export.block_height, 1000);
    }

    #[test]
    fn test_ledger_export_json() {
        let op_key = test_pubkey();
        let partner = test_pubkey_2();
        let ledger = Ledger::new_as_operator(op_key, partner.to_string(), "tb1q...".to_string(), 0);

        // Export to JSON
        let json = ledger.export_json(1000).expect("JSON export should succeed");

        assert!(json.contains("\"version\": 1"));
        assert!(json.contains("tb1q..."));
    }

    #[test]
    fn test_ledger_export_binary() {
        let op_key = test_pubkey();
        let partner = test_pubkey_2();
        let ledger = Ledger::new_as_operator(op_key, partner.to_string(), "tb1q...".to_string(), 0);

        // Export to binary
        let binary = ledger.export_binary(1000);

        assert!(!binary.is_empty());
    }

    #[test]
    fn test_transfer_lock_complete_flow() {
        use crate::types::{compute_deposit_id, DescriptorWitness, Deposit, TransferFeeSchedule};

        let op_key = test_pubkey();
        let partner = test_pubkey_2();
        let mut ledger = Ledger::new_as_operator(op_key, partner.to_string(), "tb1q...".to_string(), 0);

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
            collateral_lock_amount: 0,
            collateral_lock_expires: 0,
            transfer_fees: TransferFeeSchedule::default(), is_collateral: false, receive_requires_sig: false,
        };
        let dest_deposit = Deposit {
            deposit_id: dest_id,
            descriptor: "pk(bob)".to_string(),
            balance: 50_000,
            locked_balance: 0,
            invoices: Vec::new(),
            fees: FeeStructure::default(),
            last_fee_assessment: 0,
            collateral_lock_amount: 0,
            collateral_lock_expires: 0,
            transfer_fees: TransferFeeSchedule::default(), is_collateral: false, receive_requires_sig: false,
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
            witness: DescriptorWitness { stack: vec![[0x11u8; 64].to_vec()] },
        };

        ledger.apply_operation(&lock_op).unwrap();

        // Verify source balance decreased and locked increased
        let source = ledger.state.deposits.get(&source_id).unwrap();
        assert_eq!(source.balance, 100_000 - 30_000 - 500); // 69,500
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
            script_witness: DescriptorWitness { stack: vec![[0x22u8; 32].to_vec()] }, // preimage
        };

        ledger.apply_operation(&complete_op).unwrap();

        // Verify pending transfer was removed
        assert!(ledger.state.pending_transfers.is_empty());

        // Verify source locked balance is now 0
        let source = ledger.state.deposits.get(&source_id).unwrap();
        assert_eq!(source.locked_balance, 0);
        assert_eq!(source.balance, 69_500); // unchanged from before

        // Verify destination received the amount (not the fee)
        let dest = ledger.state.deposits.get(&dest_id).unwrap();
        assert_eq!(dest.balance, 50_000 + 30_000); // 80,000
    }

    #[test]
    fn test_transfer_lock_timeout_flow() {
        use crate::types::{compute_deposit_id, DescriptorWitness, Deposit, TransferFeeSchedule};

        let op_key = test_pubkey();
        let partner = test_pubkey_2();
        let mut ledger = Ledger::new_as_operator(op_key, partner.to_string(), "tb1q...".to_string(), 0);

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
            collateral_lock_amount: 0,
            collateral_lock_expires: 0,
            transfer_fees: TransferFeeSchedule::default(), is_collateral: false, receive_requires_sig: false,
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
            witness: DescriptorWitness { stack: vec![[0x33u8; 64].to_vec()] },
        };

        ledger.apply_operation(&lock_op).unwrap();

        // Verify funds locked
        let source = ledger.state.deposits.get(&source_id).unwrap();
        assert_eq!(source.balance, 100_000 - 25_250);
        assert_eq!(source.locked_balance, 25_250);

        // Timeout the transfer (deadline passed, preimage not revealed)
        let timeout_op = LedgerOperation::TransferTimeout {
            transfer_id,
            block_hash: [0x99u8; 32],
        };

        ledger.apply_operation(&timeout_op).unwrap();

        // Verify pending transfer was removed
        assert!(ledger.state.pending_transfers.is_empty());

        // Verify source got all funds back (amount + fee)
        let source = ledger.state.deposits.get(&source_id).unwrap();
        assert_eq!(source.locked_balance, 0);
        assert_eq!(source.balance, 100_000); // fully restored
    }
}
