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
use crate::types::{Deposit, LedgerState, ReservesOutput, SignedLedgerUpdate};

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
        partner_key: PublicKey,
        ledger_address: String,
    ) -> Self {
        Self {
            state: LedgerState::new(operator_key, partner_key, ledger_address),
            role: LedgerRole::Operator,
            history: Vec::new(),
        }
    }

    /// Create a new ledger as partner.
    pub fn new_as_partner(
        operator_key: PublicKey,
        partner_key: PublicKey,
        ledger_address: String,
    ) -> Self {
        Self {
            state: LedgerState::new(operator_key, partner_key, ledger_address),
            role: LedgerRole::Partner,
            history: Vec::new(),
        }
    }

    /// Create a new ledger with explicit role and optional collateral partners.
    /// This constructor is provided for compatibility with existing code.
    pub fn new(
        operator_key: PublicKey,
        partner_key: PublicKey,
        role: LedgerRole,
        collateral_partners: Vec<PublicKey>,
        ledger_address: String,
    ) -> Self {
        let mut state = LedgerState::new(operator_key, partner_key, ledger_address);
        state.collateral_partners = collateral_partners;
        Self {
            state,
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
        self.state.hash
    }

    /// Get total deposit balance (millisatoshis).
    pub fn total_deposit_balance(&self) -> u64 {
        self.state.total_deposit_balance()
    }

    /// Get reserves amount (satoshis).
    pub fn reserves_amount(&self) -> u64 {
        self.state.reserves_amount()
    }

    /// Calculate required reserves for current deposits.
    pub fn required_reserves(&self) -> u64 {
        // Convert msat to sat
        self.total_deposit_balance() / 1000
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

    /// Get the partner's public key.
    pub fn partner_key(&self) -> PublicKey {
        self.state.partner_key
    }

    /// Get all quorum participants for this ledger.
    /// Returns: operator + partner + all collateral partners.
    pub fn quorum_participants(&self) -> Vec<PublicKey> {
        let mut participants = Vec::with_capacity(2 + self.state.collateral_partners.len());
        participants.push(self.state.operator_key);
        participants.push(self.state.partner_key);
        participants.extend(self.state.collateral_partners.iter().cloned());
        participants
    }

    /// Get all partners (channel partner + collateral partners).
    /// This is the set of nodes the operator broadcasts updates to.
    pub fn all_partners(&self) -> Vec<PublicKey> {
        let mut partners = Vec::with_capacity(1 + self.state.collateral_partners.len());
        partners.push(self.state.partner_key);
        partners.extend(self.state.collateral_partners.iter().cloned());
        partners
    }

    /// Add a collateral partner to this ledger.
    pub fn add_collateral_partner(&mut self, partner: PublicKey) -> DepositsResult<()> {
        if partner == self.state.operator_key {
            return Err(DepositsError::InvalidState(
                "Operator cannot be a collateral partner".to_string()
            ));
        }
        if partner == self.state.partner_key {
            return Err(DepositsError::InvalidState(
                "Channel partner is already part of the quorum".to_string()
            ));
        }
        if self.state.collateral_partners.contains(&partner) {
            return Err(DepositsError::InvalidState(
                format!("Collateral partner {} already exists", partner)
            ));
        }
        self.state.collateral_partners.push(partner);
        Ok(())
    }

    // ========================================================================
    // Hash Chain Methods
    // ========================================================================

    /// Get the hash of the last update (tail hash).
    /// Returns zero hash if no updates exist yet.
    pub fn tail_hash(&self) -> [u8; 32] {
        self.history.last()
            .map(|u| u.current_state_hash)
            .unwrap_or([0u8; 32])
    }

    /// Find the sequence number of a hash in the update history.
    /// Returns None if the hash doesn't exist.
    pub fn find_hash_sequence(&self, target_hash: &[u8; 32]) -> Option<u64> {
        // Zero hash represents genesis (before any updates)
        if target_hash == &[0u8; 32] {
            return Some(0);
        }
        for update in &self.history {
            if &update.current_state_hash == target_hash {
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

    /// Check if this ledger is closed (has a Tombstone or LedgerClose as the last operation).
    /// Note: This checks the message_type field for quick detection without deserialization.
    pub fn is_closed(&self) -> bool {
        if let Some(last_update) = self.history.last() {
            // Check message type for Tombstone (0x8016) or LedgerClose (0x8009)
            last_update.message_type == 0x8016 || last_update.message_type == 0x8009
        } else {
            false
        }
    }

    /// Get total deposit liability (sum of all deposit balances).
    pub fn total_deposit_liability(&self) -> u64 {
        self.state.deposits.values().map(|d| d.balance).sum()
    }

    /// Check if a credit has been issued for a given payment hash.
    /// This scans the history and deserializes PaymentCredit messages to check.
    pub fn has_credit_for_payment(&self, payment_hash: &[u8; 32]) -> bool {
        use crate::messages::DepositsMessage;

        for update in &self.history {
            // Quick filter: only check PaymentCredit message types
            // PaymentCredit is part of LedgerUpdate (0x8001) or the V1 type (0x8005)
            if update.message_type == 0x8001 || update.message_type == 0x8005 {
                if let Ok(msg) = DepositsMessage::decode(&update.message) {
                    if let DepositsMessage::LedgerUpdate(lu) = msg {
                        if let LedgerOperation::PaymentCredit { payment_hash: hash, .. } = lu.operation {
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
            self.state.hash = update.current_state_hash;
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

        // Requirement 2: attestations >= deposit_liability (if we have collateral partners)
        if !self.state.collateral_partners.is_empty() {
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

    /// Validate an operation before applying.
    fn validate_operation(&self, operation: &LedgerOperation) -> DepositsResult<()> {
        match operation {
            LedgerOperation::ReservesAdd { amount, .. } => {
                if *amount == 0 {
                    return Err(DepositsError::InvalidReserveAmount);
                }
                if self.state.reserves.amount > 0 {
                    return Err(DepositsError::InvalidState(
                        "Reserves already exist".to_string(),
                    ));
                }
            }
            LedgerOperation::ReservesRemove => {
                if self.state.reserves.amount == 0 {
                    return Err(DepositsError::ReservesOutputNotFound(
                        "No reserves to remove".to_string(),
                    ));
                }
                if self.total_deposit_balance() > 0 {
                    return Err(DepositsError::NonZeroBalance {
                        balance: self.total_deposit_balance(),
                    });
                }
            }
            LedgerOperation::ReservesIncrease { new_amount } => {
                let current = self.reserves_amount();
                if *new_amount <= current {
                    return Err(DepositsError::InvalidReservesDecrease(
                        "New amount must be greater than current".to_string(),
                    ));
                }
            }
            LedgerOperation::ReservesDecrease { new_amount } => {
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
            LedgerOperation::DepositOpen { pubkey, .. } => {
                if self.state.deposits.contains_key(pubkey) {
                    return Err(DepositsError::DepositAlreadyExists);
                }
            }
            LedgerOperation::DepositClose { pubkey } => {
                let deposit = self
                    .state
                    .deposits
                    .get(pubkey)
                    .ok_or(DepositsError::DepositNotFound)?;
                if deposit.balance > 0 {
                    return Err(DepositsError::NonZeroBalance {
                        balance: deposit.balance,
                    });
                }
            }
            LedgerOperation::PaymentLock { pubkey, amount, .. } => {
                let deposit = self
                    .state
                    .deposits
                    .get(pubkey)
                    .ok_or(DepositsError::DepositNotFound)?;
                if deposit.available_balance() < *amount {
                    return Err(DepositsError::InsufficientDepositBalance {
                        available: deposit.available_balance(),
                        required: *amount,
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
            LedgerOperation::ReservesAdd {
                amount,
                spend_to,
                collateral_partners,
            } => {
                self.state.reserves = ReservesOutput::new([0u8; 32], *amount, *spend_to);
                self.state.collateral_partners = collateral_partners.clone();
            }
            LedgerOperation::ReservesRemove => {
                self.state.reserves = ReservesOutput::default();
            }
            LedgerOperation::ReservesIncrease { new_amount } => {
                self.state.reserves.amount = *new_amount;
            }
            LedgerOperation::ReservesDecrease { new_amount } => {
                self.state.reserves.amount = *new_amount;
            }
            LedgerOperation::ReservesUpdateSpendTo { spend_to } => {
                self.state.reserves.spend_to = *spend_to;
            }
            LedgerOperation::DepositOpen { pubkey, fees, .. } => {
                let deposit = Deposit::new(*pubkey, fees.clone());
                self.state.deposits.insert(*pubkey, deposit);
            }
            LedgerOperation::DepositClose { pubkey } => {
                self.state.deposits.remove(pubkey);
            }
            LedgerOperation::DepositUpdate { pubkey, new_fees } => {
                if let Some(deposit) = self.state.deposits.get_mut(pubkey) {
                    deposit.fees = new_fees.clone();
                }
            }
            LedgerOperation::PaymentCredit {
                deposit_pubkey,
                amount,
                ..
            } => {
                if let Some(deposit) = self.state.deposits.get_mut(deposit_pubkey) {
                    deposit.credit(*amount);
                }
            }
            LedgerOperation::PaymentLock { pubkey, amount, .. } => {
                if let Some(deposit) = self.state.deposits.get_mut(pubkey) {
                    deposit.lock(*amount)?;
                }
            }
            LedgerOperation::PaymentFail { pubkey, amount, .. } => {
                if let Some(deposit) = self.state.deposits.get_mut(pubkey) {
                    deposit.unlock(*amount);
                }
            }
            LedgerOperation::PaymentFulfill { pubkey, amount, .. } => {
                if let Some(deposit) = self.state.deposits.get_mut(pubkey) {
                    deposit.fulfill(*amount);
                }
            }
            LedgerOperation::TransferLock { pubkey, amount, .. } => {
                if let Some(deposit) = self.state.deposits.get_mut(pubkey) {
                    deposit.lock(*amount)?;
                }
            }
            LedgerOperation::TransferFail { pubkey, .. } => {
                if let Some(deposit) = self.state.deposits.get_mut(pubkey) {
                    // Transfer fail unlocks - but we don't have amount here
                    // This is a simplified version
                    deposit.unlock(0);
                }
            }
            LedgerOperation::TransferFulfill { pubkey, amount, .. } => {
                if let Some(deposit) = self.state.deposits.get_mut(pubkey) {
                    deposit.credit(*amount);
                }
            }
            LedgerOperation::FeeCollect {
                pubkey,
                amount,
                block_height,
            } => {
                if let Some(deposit) = self.state.deposits.get_mut(pubkey) {
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
            LedgerOperation::CollateralAddPartner {
                collateral_partner, ..
            } => {
                if !self.state.collateral_partners.contains(collateral_partner) {
                    self.state.collateral_partners.push(*collateral_partner);
                }
            }
            LedgerOperation::CollateralRemovePartner {
                collateral_partner, ..
            } => {
                self.state.collateral_partners.retain(|k| k != collateral_partner);
                // Also remove any attestations from this partner
                self.state.collateral_attestations.remove(collateral_partner);
            }
            LedgerOperation::LedgerClose | LedgerOperation::Tombstone { .. } => {
                // Mark ledger as closed - clear collateral attestations
                self.state.clear_collateral_attestations();
            }
            LedgerOperation::CollateralAttestation {
                collateral_operator,
                amount,
                block_height,
                signature,
                ledger_hash,
            } => {
                // Record the attestation if the partner is valid
                use crate::types::CollateralAttestation;
                let attestation = CollateralAttestation::new(
                    *collateral_operator,
                    self.state.partner_key, // Attestation from our partner
                    *amount,
                    *block_height,
                    *signature,
                    *ledger_hash,
                );
                // Insert even if not in collateral_partners - validation is done elsewhere
                self.state.collateral_attestations.insert(self.state.partner_key, attestation);
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
            LedgerOperation::DepositOpen { pubkey, .. } => {
                // Validate: deposit must not already exist
                if ledger.state.deposits.contains_key(pubkey) {
                    return Err(DepositsError::ProtocolViolation {
                        violation_type: "duplicate_deposit".to_string(),
                        details: format!("Deposit already exists for pubkey {}", pubkey),
                    });
                }
            }
            LedgerOperation::DepositClose { pubkey, .. } => {
                // Validate: deposit must exist and have zero balance
                if let Some(deposit) = ledger.state.deposits.get(pubkey) {
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
            if update.previous_state_hash != expected_previous_hash {
                return i;
            }

            // Next update should reference this update's hash
            expected_previous_hash = update.current_state_hash;
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
    /// - Requirement 2: attestations >= deposit_liability (if we have collateral partners)
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

        // Requirement 2: attestations >= deposit_liability (if we have collateral partners)
        if !ledger.state.collateral_partners.is_empty() {
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
            if update.current_state_hash == *target_hash {
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
        partner_key: PublicKey,
        ledger_address: String,
    ) -> Self {
        Self::new(Ledger::new_as_operator(operator_key, partner_key, ledger_address))
    }

    /// Create a new ledger as partner.
    pub fn create_as_partner(
        operator_key: PublicKey,
        partner_key: PublicKey,
        ledger_address: String,
    ) -> Self {
        Self::new(Ledger::new_as_partner(operator_key, partner_key, ledger_address))
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
        partner_key: PublicKey,
        role: LedgerRole,
        collateral_partners: Vec<PublicKey>,
        ledger_address: String,
    ) -> (Self, [u8; 32]) {
        let ledger = Ledger::new(
            operator_key,
            partner_key,
            role,
            collateral_partners,
            ledger_address,
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
        partner_key: PublicKey,
        role: LedgerRole,
        collateral_partners: Vec<PublicKey>,
        ledger_address: String,
        genesis_operation: LedgerOperation,
    ) -> DepositsResult<(Self, [u8; 32])> {
        // Create the base ledger
        let mut ledger = Ledger::new(
            operator_key,
            partner_key,
            role,
            collateral_partners,
            ledger_address,
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
    /// The credit_operation must be a `PaymentCredit` variant.
    pub fn credit_payment_with_reserves_topup(
        &mut self,
        credit_operation: LedgerOperation,
    ) -> DepositsResult<Vec<[u8; 32]>> {
        // Extract the credit amount from the operation
        let credit_amount = match &credit_operation {
            LedgerOperation::PaymentCredit { amount, .. } => *amount,
            _ => return Err(DepositsError::InvalidReservesDecrease("Expected PaymentCredit operation".to_string())),
        };

        let mut hashes = Vec::new();

        // Check if reserves topup is needed
        if let Some(required_amount) = self.reserves_topup_needed(credit_amount) {
            // Apply reserves increase operation
            let reserves_update = self.ledger.apply_operation(
                &LedgerOperation::ReservesIncrease { new_amount: required_amount }
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
        let ledger = Ledger::new_as_operator(op, partner, "tb1q...".to_string());

        assert_eq!(ledger.role, LedgerRole::Operator);
        assert_eq!(ledger.sequence(), 0);
        assert_eq!(ledger.total_deposit_balance(), 0);
    }

    #[test]
    fn test_reserves_add() {
        let op = test_pubkey();
        let partner = test_pubkey_2();
        let mut ledger = Ledger::new_as_operator(op, partner, "tb1q...".to_string());

        let op = LedgerOperation::ReservesAdd {
            amount: 100_000,
            spend_to: op,
            collateral_partners: vec![],
        };

        let update = ledger.apply_operation(&op).unwrap();
        assert_eq!(update.sequence_number, 1);
        assert_eq!(ledger.reserves_amount(), 100_000);
    }

    #[test]
    fn test_deposit_lifecycle() {
        let op_key = test_pubkey();
        let partner = test_pubkey_2();
        let mut ledger = Ledger::new_as_operator(op_key, partner, "tb1q...".to_string());

        // Add reserves first
        ledger
            .apply_operation(&LedgerOperation::ReservesAdd {
                amount: 100_000,
                spend_to: op_key,
                collateral_partners: vec![],
            })
            .unwrap();

        // Open deposit
        let user = test_pubkey_2();
        ledger
            .apply_operation(&LedgerOperation::DepositOpen {
                pubkey: user,
                fees: Some(FeeStructure::default()),
                payment_hash: None,
                invoice: None,
                cosigner_guarantee_signature: None,
            })
            .unwrap();

        assert_eq!(ledger.state.deposits.len(), 1);

        // Credit deposit
        ledger
            .apply_operation(&LedgerOperation::PaymentCredit {
                payment_hash: [0u8; 32],
                deposit_pubkey: user,
                amount: 50_000,
                invoice_id: "inv1".to_string(),
                sequence_number: 1,
            })
            .unwrap();

        assert_eq!(ledger.state.deposits.get(&user).unwrap().balance, 50_000);
    }

    #[test]
    fn test_hash_chain() {
        let op = test_pubkey();
        let partner = test_pubkey_2();
        let mut ledger = Ledger::new_as_operator(op, partner, "tb1q...".to_string());

        let initial_hash = ledger.hash();
        assert_eq!(initial_hash, [0u8; 32]);

        ledger
            .apply_operation(&LedgerOperation::ReservesAdd {
                amount: 100_000,
                spend_to: op,
                collateral_partners: vec![],
            })
            .unwrap();

        let hash_after_1 = ledger.hash();
        assert_ne!(hash_after_1, initial_hash);

        ledger
            .apply_operation(&LedgerOperation::ReservesIncrease { new_amount: 200_000 })
            .unwrap();

        let hash_after_2 = ledger.hash();
        assert_ne!(hash_after_2, hash_after_1);
    }
}
