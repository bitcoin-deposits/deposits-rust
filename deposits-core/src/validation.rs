// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Bitcoin Deposits Protocol Validation Rules
//!
//! This module implements the core economic validation rules that enforce
//! the trust-minimized properties of the Bitcoin Deposits protocol.
//!
//! ## Key Validation Rules
//!
//! - **100% Reserves**: Reserves in the channel must cover 100% of deposits
//! - **100% Collateral**: Collateral from other channels provides additional 100% backing
//! - **Invoice Reserves**: Outstanding invoices increase reserve requirements
//! - **Fee Assessment**: Fees can only be collected when sufficient balance exists

use bitcoin::secp256k1::PublicKey;

use crate::error::{DepositsError, DepositsResult};
use crate::types::{Deposit, Invoice, LedgerState, PendingInvoice};

/// Core validation rules for Bitcoin Deposits protocol operations
pub struct ValidationRules;

impl ValidationRules {
    /// Validate that reserves meet the 100% requirement
    ///
    /// In the 100%+100% backing model:
    /// - Reserves in this channel must be >= 100% of deposits + max outstanding invoice
    /// - Collateral in other channels provides additional 100% security
    pub fn validate_reserves_requirement(state: &LedgerState) -> DepositsResult<()> {
        Self::validate_reserves_requirement_with_invoice(state, None)
    }

    /// Validate reserves requirement, accounting for a pending invoice if present.
    pub fn validate_reserves_requirement_with_invoice(
        state: &LedgerState,
        pending_invoice: Option<&PendingInvoice>,
    ) -> DepositsResult<()> {
        let total_deposit_balances = state.total_deposit_balance();

        let max_outstanding_invoice = Self::get_max_outstanding_invoice_amount(state, 0);

        // Add pending invoice if it exists
        let max_invoice_amount = if let Some(pending) = pending_invoice {
            std::cmp::max(max_outstanding_invoice, pending.amount)
        } else {
            max_outstanding_invoice
        };

        let required_reserves =
            Self::calculate_required_reserves(total_deposit_balances, max_invoice_amount);

        if state.reserves_amount < required_reserves {
            return Err(DepositsError::InsufficientReserves {
                required: required_reserves,
                available: state.reserves_amount,
            });
        }

        Ok(())
    }

    /// Calculate required reserves amount (100% of deposits + max invoice)
    ///
    /// In the 100%+100% backing model, reserves must cover 100% of deposits
    /// plus any outstanding invoice that could be claimed.
    pub fn calculate_required_reserves(total_deposits: u64, max_invoice: u64) -> u64 {
        // 100% of deposits + max outstanding invoice
        total_deposits.saturating_add(max_invoice)
    }

    /// Validate reserves requirement including a pending invoice
    pub fn validate_reserves_with_pending(
        state: &LedgerState,
        pending_invoice: &PendingInvoice,
    ) -> DepositsResult<()> {
        let total_deposit_balances = state.total_deposit_balance();

        let current_max_invoice = Self::get_max_outstanding_invoice_amount(state, 0);
        let max_with_pending = std::cmp::max(current_max_invoice, pending_invoice.amount);

        let required_reserves =
            Self::calculate_required_reserves(total_deposit_balances, max_with_pending);

        if state.reserves_amount < required_reserves {
            return Err(DepositsError::InsufficientReserves {
                required: required_reserves,
                available: state.reserves_amount,
            });
        }

        Ok(())
    }

    /// Validate deposit removal conditions
    pub fn validate_deposit_removal(deposit: &Deposit, current_time: u64) -> DepositsResult<()> {
        // Check for non-zero balance
        if deposit.balance > 0 {
            return Err(DepositsError::NonZeroBalance {
                balance: deposit.balance,
            });
        }

        // Check for locked balance
        if deposit.locked_balance > 0 {
            return Err(DepositsError::NonZeroBalance {
                balance: deposit.locked_balance,
            });
        }

        // Check for outstanding invoices
        let active_invoices: Vec<&Invoice> = deposit
            .invoices
            .iter()
            .filter(|inv| !inv.is_expired(current_time))
            .collect();

        if !active_invoices.is_empty() {
            return Err(DepositsError::OutstandingInvoices {
                count: active_invoices.len(),
            });
        }

        Ok(())
    }

    /// Validate outgoing payment from deposit
    pub fn validate_outgoing_payment(deposit: &Deposit, amount: u64) -> DepositsResult<()> {
        let available_balance = deposit.available_balance();

        if available_balance < amount {
            return Err(DepositsError::InsufficientDepositBalance {
                available: available_balance,
                required: amount,
            });
        }

        Ok(())
    }

    /// Validate that deposit exists and is in correct state
    pub fn validate_deposit_exists<'a>(
        state: &'a LedgerState,
        deposit_id: &crate::types::DepositId,
    ) -> DepositsResult<&'a Deposit> {
        state
            .deposits
            .get(deposit_id)
            .ok_or(DepositsError::DepositNotFound)
    }

    /// Validate that deposit does not already exist
    pub fn validate_deposit_not_exists(
        state: &LedgerState,
        deposit_id: &crate::types::DepositId,
    ) -> DepositsResult<()> {
        if state.deposits.contains_key(deposit_id) {
            return Err(DepositsError::DepositAlreadyExists);
        }
        Ok(())
    }

    /// Validate reserve amount is positive
    pub fn validate_reserve_amount(amount: u64) -> DepositsResult<()> {
        if amount == 0 {
            return Err(DepositsError::InvalidReserveAmount);
        }
        Ok(())
    }

    /// Validate invoice expiration
    pub fn validate_invoice_not_expired(
        invoice: &Invoice,
        current_time: u64,
    ) -> DepositsResult<()> {
        if invoice.is_expired(current_time) {
            return Err(DepositsError::InvalidMessage {
                reason: "Invoice has expired".to_string(),
            });
        }
        Ok(())
    }

    /// Validate pending invoice expiration
    pub fn validate_pending_invoice_not_expired(
        pending: &PendingInvoice,
        current_time: u64,
    ) -> DepositsResult<()> {
        if pending.is_expired(current_time) {
            return Err(DepositsError::InvalidMessage {
                reason: "Pending invoice has expired".to_string(),
            });
        }
        Ok(())
    }

    /// Calculate excess reserves that can be safely removed
    pub fn calculate_excess_reserves(state: &LedgerState) -> u64 {
        let total_deposit_balances = state.total_deposit_balance();

        let max_outstanding_invoice = Self::get_max_outstanding_invoice_amount(state, 0);

        let required_reserves =
            Self::calculate_required_reserves(total_deposit_balances, max_outstanding_invoice);

        state.reserves_amount.saturating_sub(required_reserves)
    }

    /// Validate fee assessment for deposit
    pub fn validate_fee_assessment(deposit: &Deposit, blocks_elapsed: u32) -> DepositsResult<u64> {
        // Calculate fee amount based on fee structure
        let fee_amount = Self::calculate_fee_amount(deposit, blocks_elapsed);

        // Ensure deposit has sufficient balance for fees
        let available_balance = deposit.available_balance();
        if available_balance < fee_amount {
            return Err(DepositsError::InsufficientDepositBalance {
                available: available_balance,
                required: fee_amount,
            });
        }

        Ok(fee_amount)
    }

    /// Calculate fee amount for a deposit over elapsed blocks
    pub fn calculate_fee_amount(deposit: &Deposit, blocks_elapsed: u32) -> u64 {
        deposit.fees.calculate_fee(deposit.balance, blocks_elapsed)
    }

    // ========================================================================
    // HELPER FUNCTIONS
    // ========================================================================

    /// Get maximum outstanding invoice amount across all deposits
    pub fn get_max_outstanding_invoice_amount(state: &LedgerState, current_time: u64) -> u64 {
        state
            .deposits
            .values()
            .flat_map(|deposit| &deposit.invoices)
            .filter(|invoice| !invoice.is_expired(current_time))
            .map(|invoice| invoice.amount)
            .max()
            .unwrap_or(0)
    }
}

/// Comprehensive operation validator
pub struct OperationValidator;

impl OperationValidator {
    /// Validate complete add deposit operation
    pub fn validate_add_deposit(
        state: &LedgerState,
        deposit_id: &crate::types::DepositId,
    ) -> DepositsResult<()> {
        // Check deposit doesn't already exist
        ValidationRules::validate_deposit_not_exists(state, deposit_id)?;

        // Note: Adding deposit with zero balance doesn't require reserve validation
        // since deposits start at zero and only increase from external payments

        Ok(())
    }

    /// Validate complete remove deposit operation
    pub fn validate_remove_deposit(
        state: &LedgerState,
        deposit_id: &crate::types::DepositId,
        current_time: u64,
    ) -> DepositsResult<()> {
        // Check deposit exists
        let deposit = ValidationRules::validate_deposit_exists(state, deposit_id)?;

        // Check removal conditions
        ValidationRules::validate_deposit_removal(deposit, current_time)?;

        Ok(())
    }

    /// Validate invoice cosigning operation
    pub fn validate_cosign_invoice(
        state: &LedgerState,
        pending_invoice: &PendingInvoice,
        current_time: u64,
    ) -> DepositsResult<()> {
        // Check pending invoice hasn't expired
        ValidationRules::validate_pending_invoice_not_expired(pending_invoice, current_time)?;

        // Check assigned deposit exists (assigned_deposit is now DepositId)
        ValidationRules::validate_deposit_exists(state, &pending_invoice.assigned_deposit)?;

        // Check reserves are sufficient for this invoice
        ValidationRules::validate_reserves_with_pending(state, pending_invoice)?;

        Ok(())
    }

    /// Validate payment locking operation
    pub fn validate_lock_payment(
        state: &LedgerState,
        deposit_id: &crate::types::DepositId,
        amount: u64,
    ) -> DepositsResult<()> {
        // Check deposit exists
        let deposit = ValidationRules::validate_deposit_exists(state, deposit_id)?;

        // Check sufficient balance for payment
        ValidationRules::validate_outgoing_payment(deposit, amount)?;

        Ok(())
    }

    /// Validate reserves addition operation
    pub fn validate_add_reserves(_state: &LedgerState, amount: u64) -> DepositsResult<()> {
        // Validate amount is positive
        ValidationRules::validate_reserve_amount(amount)?;

        // Note: Adding reserves always improves the reserve ratio, so no additional
        // validation needed beyond amount > 0

        Ok(())
    }

    /// Validate reserves removal operation
    pub fn validate_remove_reserves(state: &LedgerState, amount: u64) -> DepositsResult<()> {
        // Calculate what reserves would be after removal
        let remaining_reserves = state.reserves_amount.saturating_sub(amount);

        // Create temporary state to validate
        let mut temp_state = state.clone();
        temp_state.reserves_amount = remaining_reserves;

        // Ensure reserves requirement still met
        ValidationRules::validate_reserves_requirement(&temp_state)?;

        Ok(())
    }

    /// Validate credit payment operation
    pub fn validate_credit_payment(
        state: &LedgerState,
        pending_invoice: Option<&PendingInvoice>,
        deposit_id: &crate::types::DepositId,
        payment_hash: &[u8; 32],
        amount: u64,
        current_time: u64,
    ) -> DepositsResult<()> {
        // Check deposit exists
        ValidationRules::validate_deposit_exists(state, deposit_id)?;

        // Verify there's a pending invoice matching this payment
        if let Some(pending) = pending_invoice {
            if pending.payment_hash == *payment_hash
                && pending.assigned_deposit == *deposit_id
                && pending.amount == amount
            {
                return Ok(());
            }
        }

        // Check if there's a matching outstanding invoice in the deposit
        let deposit = ValidationRules::validate_deposit_exists(state, deposit_id)?;
        for invoice in &deposit.invoices {
            if invoice.payment_hash == *payment_hash
                && invoice.amount == amount
                && !invoice.is_expired(current_time)
            {
                return Ok(());
            }
        }

        Err(DepositsError::UnknownPayment)
    }
}

// ============================================================================
// LEDGER CONFORMANCE VALIDATION
// ============================================================================

/// Result of conformance validation
#[derive(Debug, Clone)]
pub struct ConformanceResult {
    /// Whether the ledger conforms to all rules
    pub is_conforming: bool,
    /// Final sequence number after replaying all updates
    pub final_sequence: u64,
    /// Final state hash after replaying all updates
    pub final_state_hash: [u8; 32],
    /// Computed reserves amount from ledger state
    pub computed_reserves: u64,
    /// Sum of all deposit balances
    pub total_deposits: u64,
    /// Violations found during validation (empty if conforming)
    pub violations: Vec<ConformanceViolation>,
}

/// Types of conformance violations
#[derive(Debug, Clone)]
pub enum ConformanceViolation {
    /// Hash chain is broken at the given sequence
    BrokenHashChain {
        sequence: u64,
        expected: [u8; 32],
        actual: [u8; 32],
    },
    /// Invalid operator signature at the given sequence
    InvalidSignature { sequence: u64 },
    /// Sequence number is out of order
    SequenceOutOfOrder { expected: u64, actual: u64 },
    /// Operation failed to apply
    OperationFailed { sequence: u64, reason: String },
    /// Reserves in channel insufficient to back deposits at 100%
    InsufficientReserves {
        reserves: u64,
        deposits: u64,
        reserves_ratio_percent: u64,
    },
    /// Collateral in other channels insufficient to back deposits at 100%
    InsufficientCollateral {
        total_collateral: u64,
        deposits: u64,
        collateral_ratio_percent: u64,
    },
    /// Final state hash doesn't match claimed
    StateHashMismatch {
        computed: [u8; 32],
        claimed: [u8; 32],
    },
    /// Operator pubkey mismatch
    OperatorMismatch {
        expected: PublicKey,
        actual: PublicKey,
    },
    /// Payment was settled (preimage revealed) but no credit was issued
    UncreditedPayment {
        payment_hash: [u8; 32],
        deposit_pubkey: PublicKey,
        amount_msat: u64,
        settlement_sequence: u64,
    },
}

/// Validates ledger conformance by replaying signed updates
pub struct LedgerConformanceValidator;

impl LedgerConformanceValidator {
    /// Create a new conformance validator
    pub fn new() -> Self {
        Self
    }

    /// Check if a ledger conforms based on state
    pub fn validate_state(
        &self,
        state: &LedgerState,
        claimed_reserves: u64,
        collateral_amounts: &[u64],
    ) -> ConformanceResult {
        let mut violations = Vec::new();

        // Check reserves backing (100% requirement)
        let total_deposits = state.total_deposit_balance();

        let reserves_ratio_percent = if total_deposits > 0 {
            (claimed_reserves * 100) / total_deposits
        } else {
            100
        };

        if claimed_reserves < total_deposits {
            violations.push(ConformanceViolation::InsufficientReserves {
                reserves: claimed_reserves,
                deposits: total_deposits,
                reserves_ratio_percent,
            });
        }

        // Check collateral backing (100% requirement)
        let total_collateral: u64 = collateral_amounts.iter().sum();

        let collateral_ratio_percent = if total_deposits > 0 {
            (total_collateral * 100) / total_deposits
        } else {
            100
        };

        if total_collateral < total_deposits {
            violations.push(ConformanceViolation::InsufficientCollateral {
                total_collateral,
                deposits: total_deposits,
                collateral_ratio_percent,
            });
        }

        ConformanceResult {
            is_conforming: violations.is_empty(),
            final_sequence: state.sequence,
            final_state_hash: state.chain_tip_hash,
            computed_reserves: state.reserves_amount,
            total_deposits,
            violations,
        }
    }

    /// Quick check if a ledger conforms
    pub fn is_conforming(
        &self,
        state: &LedgerState,
        claimed_reserves: u64,
        collateral_amounts: &[u64],
    ) -> bool {
        self.validate_state(state, claimed_reserves, collateral_amounts)
            .is_conforming
    }
}

impl Default for LedgerConformanceValidator {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// LEDGER EXPORT AND VALIDATION API
// ============================================================================

/// Complete ledger export for validation and audit.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct LedgerExport {
    /// Protocol version for compatibility checking.
    pub version: u32,
    /// Unique ledger identifier (hash of operator + reserves + genesis_block).
    #[serde(with = "crate::types::serde_32")]
    pub ledger_id: [u8; 32],
    /// Block height when this ledger was opened.
    pub genesis_block: u32,
    /// Operator's public key.
    #[serde(with = "crate::types::serde_pubkey")]
    pub operator_id: PublicKey,
    /// Reserves identifier (UTXO address for BDK, partner pubkey for LDK).
    pub reserves_id: String,
    /// Complete update history (chronologically ordered).
    pub updates: Vec<crate::types::SignedLedgerUpdate>,
    /// Export timestamp.
    pub exported_at: u64,
    /// Current block height at export time.
    pub block_height: u32,
}

impl LedgerExport {
    /// Create a new ledger export.
    pub fn new(
        ledger_id: [u8; 32],
        genesis_block: u32,
        operator_id: PublicKey,
        reserves_id: String,
        updates: Vec<crate::types::SignedLedgerUpdate>,
        block_height: u32,
    ) -> Self {
        Self {
            version: 1,
            ledger_id,
            genesis_block,
            operator_id,
            reserves_id,
            updates,
            exported_at: crate::now_unix_timestamp(),
            block_height,
        }
    }

    /// Get the ledger_id as a hex string.
    pub fn ledger_id_hex(&self) -> String {
        hex::encode(self.ledger_id)
    }

    /// Export to JSON string.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Import from JSON string.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Export to binary (bincode).
    pub fn to_binary(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }

    /// Import from binary (bincode).
    pub fn from_binary(data: &[u8]) -> Result<Self, ValidationError> {
        bincode::deserialize(data)
            .map_err(|e| ValidationError::DecodeError(format!("Bincode decode failed: {}", e)))
    }

    /// Get the genesis hash (first update's previous_hash, which should be [0u8; 32]).
    pub fn genesis_hash(&self) -> [u8; 32] {
        self.updates
            .first()
            .map(|u| u.previous_hash)
            .unwrap_or([0u8; 32])
    }

    /// Get the tail hash (last update's content_hash).
    pub fn tail_hash(&self) -> [u8; 32] {
        self.updates
            .last()
            .map(|u| u.content_hash)
            .unwrap_or([0u8; 32])
    }
}

/// Validation report for a ledger export.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ValidationReport {
    /// Is the ledger fully conforming?
    pub is_valid: bool,
    /// Final ledger state after replay.
    pub final_state: LedgerStateSnapshot,
    /// Hash chain status.
    pub hash_chain: ChainStatus,
    /// Signature verification results.
    pub signatures: SignatureReport,
    /// Business rule compliance.
    pub business_rules: Vec<RuleCheck>,
    /// Warnings (non-fatal issues).
    pub warnings: Vec<String>,
    /// Reconstructed ledger (only present if validation succeeded).
    #[serde(skip)]
    pub reconstructed_ledger: Option<crate::ledger::Ledger>,
}

/// Snapshot of ledger state for serialization in validation report.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct LedgerStateSnapshot {
    /// Final sequence number.
    pub sequence: u64,
    /// Final hash.
    #[serde(with = "crate::types::serde_32")]
    pub hash: [u8; 32],
    /// Total deposit balance (millisatoshis).
    pub total_deposits: u64,
    /// Reserves amount (millisatoshis).
    pub reserves_amount: u64,
    /// Number of active deposits.
    pub deposit_count: usize,
}

/// Hash chain validation status.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ChainStatus {
    /// Length of the valid chain (may be less than total if broken).
    pub valid_length: usize,
    /// Total number of updates.
    pub total_length: usize,
    /// Genesis hash (first update's previous_hash).
    #[serde(with = "crate::types::serde_32")]
    pub genesis_hash: [u8; 32],
    /// Tail hash (last valid update's content_hash).
    #[serde(with = "crate::types::serde_32")]
    pub tail_hash: [u8; 32],
}

/// Signature verification results.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct SignatureReport {
    /// Total number of updates.
    pub total_updates: usize,
    /// Updates with both operator and partner signatures.
    pub fully_signed: usize,
    /// Updates with only operator signature.
    pub operator_only: usize,
    /// Updates without any signatures.
    pub unsigned: usize,
    /// Invalid signatures with their sequence numbers and error messages.
    pub invalid_signatures: Vec<(u64, String)>,
}

/// Business rule check result.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct RuleCheck {
    /// Rule identifier.
    pub rule: String,
    /// Whether the rule passed.
    pub passed: bool,
    /// Additional details about the check.
    pub details: Option<String>,
}

/// Validation error for ledger conformance checking.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ValidationError {
    /// Hash chain is broken at the given sequence.
    #[error("Hash chain broken at sequence {sequence}: {reason}")]
    HashChainBroken { sequence: u64, reason: String },

    /// Signature verification failed.
    #[error("Signature verification failed at sequence {sequence}: {reason}")]
    SignatureInvalid { sequence: u64, reason: String },

    /// State transition failed to apply.
    #[error("State transition failed at sequence {sequence}: {reason}")]
    StateTransitionFailed { sequence: u64, reason: String },

    /// Business rule violation.
    #[error("Business rule violation: {rule}: {details}")]
    BusinessRuleViolation { rule: String, details: String },

    /// Decode error.
    #[error("Decode error: {0}")]
    DecodeError(String),

    /// Empty ledger (no updates).
    #[error("Empty ledger: no updates to validate")]
    EmptyLedger,
}

impl LedgerConformanceValidator {
    /// Validate a complete ledger export.
    ///
    /// Returns Ok(ValidationReport) on success, Err with first critical failure.
    pub fn validate(export: &LedgerExport) -> Result<ValidationReport, ValidationError> {
        // Check for empty ledger
        if export.updates.is_empty() {
            return Err(ValidationError::EmptyLedger);
        }

        // Validate hash chain
        Self::validate_hash_chain(&export.updates)?;

        // Validate signatures
        let signatures = Self::validate_signatures(export)?;

        // Validate state transitions and reconstruct ledger
        let ledger = Self::validate_state_transitions(export)?;

        // Validate business rules
        let business_rules = Self::validate_business_rules(&ledger);

        // Check if any critical business rule failed
        let critical_failure = business_rules
            .iter()
            .find(|r| !r.passed && r.rule == "reserves_coverage");

        // Collect warnings
        let mut warnings = Vec::new();
        if signatures.unsigned > 0 {
            warnings.push(format!("{} updates are unsigned", signatures.unsigned));
        }
        if signatures.operator_only > 0 {
            warnings.push(format!(
                "{} updates have only operator signature",
                signatures.operator_only
            ));
        }
        if !signatures.invalid_signatures.is_empty() {
            warnings.push(format!(
                "{} updates have invalid signatures",
                signatures.invalid_signatures.len()
            ));
        }

        // Build chain status
        let hash_chain = ChainStatus {
            valid_length: export.updates.len(),
            total_length: export.updates.len(),
            genesis_hash: export.genesis_hash(),
            tail_hash: export.tail_hash(),
        };

        // Build final state snapshot
        let final_state = LedgerStateSnapshot {
            sequence: ledger.sequence(),
            hash: ledger.hash(),
            total_deposits: ledger.total_deposit_balance(),
            reserves_amount: ledger.reserves_amount(),
            deposit_count: ledger.state.deposits.len(),
        };

        let is_valid = critical_failure.is_none()
            && signatures.invalid_signatures.is_empty()
            && business_rules
                .iter()
                .all(|r| r.passed || r.rule != "reserves_coverage");

        Ok(ValidationReport {
            is_valid,
            final_state,
            hash_chain,
            signatures,
            business_rules,
            warnings,
            reconstructed_ledger: Some(ledger),
        })
    }

    /// Validate just the hash chain (fast check).
    pub fn validate_hash_chain(
        updates: &[crate::types::SignedLedgerUpdate],
    ) -> Result<(), ValidationError> {
        let mut expected_prev = [0u8; 32];

        for (i, update) in updates.iter().enumerate() {
            // Check sequence number
            if update.sequence_number != i as u64 {
                return Err(ValidationError::HashChainBroken {
                    sequence: i as u64,
                    reason: format!(
                        "sequence gap: update at position {} claims sequence {}",
                        i, update.sequence_number
                    ),
                });
            }

            // Check previous hash linkage
            if update.previous_hash != expected_prev {
                return Err(ValidationError::HashChainBroken {
                    sequence: update.sequence_number,
                    reason: format!(
                        "prev_hash mismatch: update claims prev_hash {}..., but preceding entry has hash {}...",
                        &hex::encode(update.previous_hash)[..16],
                        &hex::encode(expected_prev)[..16]
                    ),
                });
            }

            // Verify computed hash matches stored hash
            let computed = update.compute_hash();
            if computed != update.content_hash {
                return Err(ValidationError::HashChainBroken {
                    sequence: update.sequence_number,
                    reason: format!(
                        "hash mismatch: update claims hash {}..., but recomputed hash is {}... (message content may have been altered)",
                        &hex::encode(update.content_hash)[..16],
                        &hex::encode(computed)[..16]
                    ),
                });
            }

            // The chain links via `chain_hash()`, not `content_hash`.
            // `chain_hash() = SHA256(content_hash || operator_signature)` —
            // see `commit_staged` in `ledger.rs`, which sets
            // `state.chain_tip_hash = staged.update.chain_hash()`. The next
            // update reads chain_tip_hash as its `previous_hash`, so the
            // validator MUST compare against the same folded hash.
            expected_prev = update.chain_hash();
        }

        Ok(())
    }

    /// Validate signatures on all updates.
    pub fn validate_signatures(export: &LedgerExport) -> Result<SignatureReport, ValidationError> {
        let mut report = SignatureReport {
            total_updates: export.updates.len(),
            ..Default::default()
        };

        for update in &export.updates {
            let has_operator = update.operator_signature != [0u8; 64];
            let has_partner = update.cosign_signature != [0u8; 64];

            if has_operator && has_partner {
                // Verify signatures if we have the keys
                // For now, we just count them as fully signed
                // Full verification would require access to secp256k1 context
                report.fully_signed += 1;
            } else if has_operator {
                report.operator_only += 1;
            } else {
                report.unsigned += 1;
            }
        }

        Ok(report)
    }

    /// Replay updates and verify state conformance.
    pub fn validate_state_transitions(
        export: &LedgerExport,
    ) -> Result<crate::ledger::Ledger, ValidationError> {
        use crate::ledger::{Ledger, LedgerRole};
        use crate::tlv::TlvDecode;

        // Create empty ledger as partner (for validation purposes)
        let mut ledger = Ledger::new(
            export.operator_id,
            export.reserves_id.clone(),
            LedgerRole::Partner,
            Vec::new(),
            export.genesis_block,
        );

        // Replay each update
        for update in &export.updates {
            // Decode the operation from TLV-encoded bytes
            let operation = crate::messages::LedgerOperation::tlv_decode(&update.message)
                .map_err(|e| ValidationError::DecodeError(format!("{:?}", e)))?;

            // Apply state changes (skip validation for replay - we trust the history)
            ledger.apply_state_changes(&operation).map_err(|e| {
                ValidationError::StateTransitionFailed {
                    sequence: update.sequence_number,
                    reason: format!("{}", e),
                }
            })?;

            // Update sequence/hash to match the update (use chain_hash for signed entries
            // so state.hash reflects the full hash chain including operator signature)
            ledger.state.sequence = update.sequence_number;
            ledger.state.chain_tip_hash = update.chain_hash();

            // Add to history
            ledger.history.push(update.clone());
        }

        Ok(ledger)
    }

    /// Check business rules (reserves >= deposits, etc).
    pub fn validate_business_rules(ledger: &crate::ledger::Ledger) -> Vec<RuleCheck> {
        let mut checks = Vec::new();

        // Rule 1: reserves >= deposits (both in millisatoshis)
        let total_deposits_msats = ledger.total_deposit_balance();
        let reserves_msats = ledger.reserves_amount();
        checks.push(RuleCheck {
            rule: "reserves_coverage".to_string(),
            passed: reserves_msats >= total_deposits_msats,
            details: Some(format!(
                "reserves: {} sats, deposits: {} sats ({}%)",
                reserves_msats / 1000,
                total_deposits_msats / 1000,
                if total_deposits_msats > 0 {
                    (reserves_msats * 100) / total_deposits_msats
                } else {
                    100
                }
            )),
        });

        // Rule 2: no negative balances (locked > balance is invalid)
        let has_invalid_balance = ledger
            .state
            .deposits
            .values()
            .any(|d| d.locked_balance > d.balance);
        checks.push(RuleCheck {
            rule: "non_negative_available_balance".to_string(),
            passed: !has_invalid_balance,
            details: if has_invalid_balance {
                Some("Some deposits have locked_balance > balance".to_string())
            } else {
                None
            },
        });

        // Rule 3: sequence numbers match history length
        let history_len = ledger.history.len() as u64;
        let current_seq = ledger.state.sequence;
        // After replaying N updates, sequence should be N-1 (0-indexed) or N depending on logic
        // The last update's sequence_number should be history.len() - 1
        let sequence_matches = if history_len > 0 {
            current_seq == history_len - 1
        } else {
            current_seq == 0
        };
        checks.push(RuleCheck {
            rule: "contiguous_sequences".to_string(),
            passed: sequence_matches,
            details: Some(format!(
                "history length: {}, current sequence: {}",
                history_len, current_seq
            )),
        });

        // Rule 4: hash matches computed hash (final state)
        let final_hash_valid = if let Some(last_update) = ledger.history.last() {
            last_update.content_hash == ledger.state.chain_tip_hash
        } else {
            ledger.state.chain_tip_hash == [0u8; 32]
        };
        checks.push(RuleCheck {
            rule: "final_hash_consistency".to_string(),
            passed: final_hash_valid,
            details: Some(format!(
                "final hash: {}",
                hex::encode(ledger.state.chain_tip_hash)
            )),
        });

        checks
    }

    /// Validate and reconstruct a ledger from an export.
    ///
    /// This is a convenience method that validates and returns the reconstructed ledger.
    pub fn from_export(export: LedgerExport) -> Result<crate::ledger::Ledger, ValidationError> {
        let report = Self::validate(&export)?;
        report
            .reconstructed_ledger
            .ok_or_else(|| ValidationError::StateTransitionFailed {
                sequence: 0,
                reason: "Failed to reconstruct ledger".to_string(),
            })
    }
}

// ============================================================================
// Tests
// ============================================================================

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

    fn create_test_deposit(balance: u64) -> Deposit {
        let mut deposit = Deposit::from_pubkey(&test_pubkey(), None);
        deposit.balance = balance;
        deposit
    }

    fn create_test_state(deposit_balance: u64, reserves: u64) -> LedgerState {
        let mut state = LedgerState::new(test_pubkey(), test_pubkey_2().to_string(), 0);

        let deposit = create_test_deposit(deposit_balance);
        let deposit_id = deposit.deposit_id;
        state.deposits.insert(deposit_id, deposit);

        state.reserves_amount = reserves;

        state
    }

    #[test]
    fn test_reserves_requirement_validation() {
        // Test insufficient reserves (100% requirement)
        let state = create_test_state(1000, 500); // Need 1000, have 500
        let result = ValidationRules::validate_reserves_requirement(&state);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DepositsError::InsufficientReserves { .. }
        ));

        // Test exactly sufficient reserves (100%)
        let state = create_test_state(1000, 1000); // Need 1000, have 1000
        let result = ValidationRules::validate_reserves_requirement(&state);
        assert!(result.is_ok());

        // Test more than sufficient reserves
        let state = create_test_state(1000, 1500); // Need 1000, have 1500
        let result = ValidationRules::validate_reserves_requirement(&state);
        assert!(result.is_ok());
    }

    #[test]
    fn test_deposit_removal_validation() {
        // Test deposit with balance - should fail
        let deposit = create_test_deposit(100);
        let result = ValidationRules::validate_deposit_removal(&deposit, 0);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DepositsError::NonZeroBalance { .. }
        ));

        // Test deposit with zero balance - should succeed
        let deposit = create_test_deposit(0);
        let result = ValidationRules::validate_deposit_removal(&deposit, 0);
        assert!(result.is_ok());
    }

    #[test]
    fn test_outgoing_payment_validation() {
        let deposit = create_test_deposit(1000);

        // Test sufficient balance
        let result = ValidationRules::validate_outgoing_payment(&deposit, 500);
        assert!(result.is_ok());

        // Test insufficient balance
        let result = ValidationRules::validate_outgoing_payment(&deposit, 1500);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DepositsError::InsufficientDepositBalance { .. }
        ));
    }

    #[test]
    fn test_excess_reserves_calculation() {
        // With 100% requirement: 1000 deposits needs 1000 reserves
        let state = create_test_state(1000, 2000); // Need 1000, have 2000
        let excess = ValidationRules::calculate_excess_reserves(&state);
        assert_eq!(excess, 1000); // 2000 - 1000 = 1000

        // Test case where reserves exactly meet requirement
        let state = create_test_state(1000, 1000); // Need 1000, have 1000
        let excess = ValidationRules::calculate_excess_reserves(&state);
        assert_eq!(excess, 0);

        // Test case where reserves are insufficient (should return 0)
        let state = create_test_state(1000, 500); // Need 1000, have 500
        let excess = ValidationRules::calculate_excess_reserves(&state);
        assert_eq!(excess, 0);
    }

    #[test]
    fn test_required_reserves_calculation() {
        // Test basic calculation: 100% of deposits (100%+100% model)
        let required = ValidationRules::calculate_required_reserves(1000, 0);
        assert_eq!(required, 1000);

        // Test with max invoice
        let required = ValidationRules::calculate_required_reserves(1000, 500);
        assert_eq!(required, 1500); // 1000 + 500

        // Test with large invoice
        let required = ValidationRules::calculate_required_reserves(1000, 2000);
        assert_eq!(required, 3000); // 1000 + 2000
    }

    #[test]
    fn test_fee_calculation() {
        let mut deposit = create_test_deposit(10000);
        deposit.fees = FeeStructure::new(1000, 100, 2016); // 1000 sat/year fixed, 1% annual

        // Test fee for about 2 weeks (2016 blocks)
        let fee = ValidationRules::calculate_fee_amount(&deposit, 2016);

        // Expected: some portion of annual fee for ~2 weeks
        // 2016 blocks is ~2 weeks out of ~52560 blocks/year
        assert!(fee > 0);
        assert!(fee < 200); // Should be a reasonable fraction
    }

    #[test]
    fn test_validate_deposit_exists() {
        use crate::types::compute_deposit_id;
        let state = create_test_state(1000, 1000);
        let pk = test_pubkey();
        let descriptor = format!("pk({})", hex::encode(pk.serialize()));
        let existing_id = compute_deposit_id(&descriptor);

        // Should find existing deposit
        let result = ValidationRules::validate_deposit_exists(&state, &existing_id);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().balance, 1000);

        // Should fail for non-existent deposit (different pubkey)
        let other_pk = test_pubkey_2();
        let other_descriptor = format!("pk({})", hex::encode(other_pk.serialize()));
        let other_id = compute_deposit_id(&other_descriptor);
        let result = ValidationRules::validate_deposit_exists(&state, &other_id);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DepositsError::DepositNotFound
        ));
    }

    #[test]
    fn test_validate_deposit_not_exists() {
        use crate::types::compute_deposit_id;
        let state = create_test_state(1000, 1000);
        let pk = test_pubkey();
        let descriptor = format!("pk({})", hex::encode(pk.serialize()));
        let existing_id = compute_deposit_id(&descriptor);

        // Should fail for existing deposit
        let result = ValidationRules::validate_deposit_not_exists(&state, &existing_id);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DepositsError::DepositAlreadyExists
        ));

        // Should succeed for non-existent deposit
        let other_pk = test_pubkey_2();
        let other_descriptor = format!("pk({})", hex::encode(other_pk.serialize()));
        let other_id = compute_deposit_id(&other_descriptor);
        let result = ValidationRules::validate_deposit_not_exists(&state, &other_id);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_reserve_amount() {
        // Zero amount should fail
        let result = ValidationRules::validate_reserve_amount(0);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DepositsError::InvalidReserveAmount
        ));

        // Non-zero amount should succeed
        let result = ValidationRules::validate_reserve_amount(1);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_remove_reserves_success() {
        // Create state with deposits=1000, reserves=2000 (excess of 1000)
        let state = create_test_state(1000, 2000);

        // Removing 500 leaves 1500, still above 1000 required
        let result = OperationValidator::validate_remove_reserves(&state, 500);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_remove_reserves_below_requirement_fails() {
        // Create state with deposits=1000, reserves=1500
        let state = create_test_state(1000, 1500);

        // Trying to remove 600 would leave 900, below 1000 required
        let result = OperationValidator::validate_remove_reserves(&state, 600);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DepositsError::InsufficientReserves { .. }
        ));
    }

    #[test]
    fn test_validate_remove_reserves_all_with_no_deposits() {
        // Create empty state with no deposits, reserves=5000
        let mut state = create_test_state(0, 5000);
        state.deposits.clear(); // Ensure no deposits

        // With no deposits, can remove all reserves
        let result = OperationValidator::validate_remove_reserves(&state, 5000);
        assert!(result.is_ok());
    }

    #[test]
    fn test_conformance_result_structure() {
        let result = ConformanceResult {
            is_conforming: true,
            final_sequence: 42,
            final_state_hash: [1u8; 32],
            computed_reserves: 10000,
            total_deposits: 5000,
            violations: Vec::new(),
        };

        assert!(result.is_conforming);
        assert_eq!(result.final_sequence, 42);
        assert!(result.violations.is_empty());
    }

    #[test]
    fn test_conformance_violation_types() {
        let pubkey = test_pubkey();

        // Test each violation type can be constructed
        let v1 = ConformanceViolation::BrokenHashChain {
            sequence: 1,
            expected: [0u8; 32],
            actual: [1u8; 32],
        };
        assert!(matches!(v1, ConformanceViolation::BrokenHashChain { .. }));

        let v2 = ConformanceViolation::InvalidSignature { sequence: 2 };
        assert!(matches!(v2, ConformanceViolation::InvalidSignature { .. }));

        let v3 = ConformanceViolation::SequenceOutOfOrder {
            expected: 3,
            actual: 5,
        };
        assert!(matches!(
            v3,
            ConformanceViolation::SequenceOutOfOrder { .. }
        ));

        let v4 = ConformanceViolation::OperationFailed {
            sequence: 4,
            reason: "Test failure".to_string(),
        };
        assert!(matches!(v4, ConformanceViolation::OperationFailed { .. }));

        let v5 = ConformanceViolation::InsufficientReserves {
            reserves: 500,
            deposits: 1000,
            reserves_ratio_percent: 50,
        };
        assert!(matches!(
            v5,
            ConformanceViolation::InsufficientReserves { .. }
        ));

        let v6 = ConformanceViolation::InsufficientCollateral {
            total_collateral: 300,
            deposits: 1000,
            collateral_ratio_percent: 30,
        };
        assert!(matches!(
            v6,
            ConformanceViolation::InsufficientCollateral { .. }
        ));

        let v7 = ConformanceViolation::StateHashMismatch {
            computed: [0u8; 32],
            claimed: [1u8; 32],
        };
        assert!(matches!(v7, ConformanceViolation::StateHashMismatch { .. }));

        let v8 = ConformanceViolation::OperatorMismatch {
            expected: pubkey,
            actual: pubkey,
        };
        assert!(matches!(v8, ConformanceViolation::OperatorMismatch { .. }));

        let v9 = ConformanceViolation::UncreditedPayment {
            payment_hash: [0u8; 32],
            deposit_pubkey: pubkey,
            amount_msat: 1000,
            settlement_sequence: 5,
        };
        assert!(matches!(v9, ConformanceViolation::UncreditedPayment { .. }));
    }

    // ========================================================================
    // Ledger Export Tests
    // ========================================================================

    #[test]
    fn test_ledger_export_creation() {
        let op = test_pubkey();
        let genesis_block = 1000u32;
        let ledger_id =
            crate::types::LedgerState::compute_ledger_id(&op, "reserves_id", genesis_block);
        let export = LedgerExport::new(
            ledger_id,
            genesis_block,
            op,
            "reserves_id".to_string(),
            Vec::new(),
            100,
        );

        assert_eq!(export.version, 1);
        assert_eq!(export.ledger_id, ledger_id);
        assert_eq!(export.genesis_block, genesis_block);
        assert_eq!(export.operator_id, op);
        assert_eq!(export.reserves_id, "reserves_id");
        assert!(export.updates.is_empty());
        assert_eq!(export.block_height, 100);
        assert!(export.exported_at > 0);
    }

    #[test]
    fn test_ledger_export_json_roundtrip() {
        let op = test_pubkey();
        let genesis_block = 1000u32;
        let ledger_id =
            crate::types::LedgerState::compute_ledger_id(&op, "reserves_id", genesis_block);
        let export = LedgerExport::new(
            ledger_id,
            genesis_block,
            op,
            "reserves_id".to_string(),
            Vec::new(),
            100,
        );

        // Serialize to JSON
        let json = export.to_json().expect("JSON serialization should succeed");
        assert!(json.contains("\"version\": 1"));
        assert!(json.contains("\"reserves_id\": \"reserves_id\""));

        // Deserialize from JSON
        let imported = LedgerExport::from_json(&json).expect("JSON deserialization should succeed");
        assert_eq!(imported.version, export.version);
        assert_eq!(imported.ledger_id, export.ledger_id);
        assert_eq!(imported.genesis_block, export.genesis_block);
        assert_eq!(imported.operator_id, export.operator_id);
        assert_eq!(imported.reserves_id, export.reserves_id);
    }

    #[test]
    fn test_ledger_export_binary_roundtrip() {
        let op = test_pubkey();
        let genesis_block = 1000u32;
        let ledger_id =
            crate::types::LedgerState::compute_ledger_id(&op, "reserves_id", genesis_block);
        let export = LedgerExport::new(
            ledger_id,
            genesis_block,
            op,
            "reserves_id".to_string(),
            Vec::new(),
            100,
        );

        // Serialize to binary
        let binary = export.to_binary();
        assert!(!binary.is_empty());

        // Deserialize from binary
        let imported =
            LedgerExport::from_binary(&binary).expect("Binary deserialization should succeed");
        assert_eq!(imported.version, export.version);
        assert_eq!(imported.ledger_id, export.ledger_id);
        assert_eq!(imported.genesis_block, export.genesis_block);
        assert_eq!(imported.operator_id, export.operator_id);
        assert_eq!(imported.reserves_id, export.reserves_id);
    }

    #[test]
    fn test_validation_error_display() {
        let e1 = ValidationError::HashChainBroken {
            sequence: 5,
            reason: "prev_hash mismatch".to_string(),
        };
        assert!(e1.to_string().contains("sequence 5"));

        let e2 = ValidationError::SignatureInvalid {
            sequence: 10,
            reason: "bad sig".to_string(),
        };
        assert!(e2.to_string().contains("sequence 10"));

        let e3 = ValidationError::StateTransitionFailed {
            sequence: 15,
            reason: "failed".to_string(),
        };
        assert!(e3.to_string().contains("sequence 15"));

        let e4 = ValidationError::BusinessRuleViolation {
            rule: "reserves".to_string(),
            details: "not enough".to_string(),
        };
        assert!(e4.to_string().contains("reserves"));

        let e5 = ValidationError::DecodeError("parse error".to_string());
        assert!(e5.to_string().contains("parse error"));

        let e6 = ValidationError::EmptyLedger;
        assert!(e6.to_string().contains("Empty ledger"));
    }

    #[test]
    fn test_chain_status_structure() {
        let status = ChainStatus {
            valid_length: 10,
            total_length: 10,
            genesis_hash: [0u8; 32],
            tail_hash: [1u8; 32],
        };

        assert_eq!(status.valid_length, 10);
        assert_eq!(status.total_length, 10);
        assert_eq!(status.genesis_hash, [0u8; 32]);
    }

    #[test]
    fn test_signature_report_default() {
        let report = SignatureReport::default();

        assert_eq!(report.total_updates, 0);
        assert_eq!(report.fully_signed, 0);
        assert_eq!(report.operator_only, 0);
        assert_eq!(report.unsigned, 0);
        assert!(report.invalid_signatures.is_empty());
    }

    #[test]
    fn test_rule_check_structure() {
        let check = RuleCheck {
            rule: "reserves_coverage".to_string(),
            passed: true,
            details: Some("100%".to_string()),
        };

        assert_eq!(check.rule, "reserves_coverage");
        assert!(check.passed);
        assert_eq!(check.details, Some("100%".to_string()));
    }

    #[test]
    fn test_validate_empty_ledger_fails() {
        let op = test_pubkey();
        let genesis_block = 1000u32;
        let ledger_id =
            crate::types::LedgerState::compute_ledger_id(&op, "reserves_id", genesis_block);
        let export = LedgerExport::new(
            ledger_id,
            genesis_block,
            op,
            "reserves_id".to_string(),
            Vec::new(),
            100,
        );

        let result = LedgerConformanceValidator::validate(&export);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ValidationError::EmptyLedger));
    }
}
