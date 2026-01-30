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
use crate::types::{LedgerState, Deposit, PendingInvoice, Invoice};

/// Core validation rules for Bitcoin Deposits protocol operations
pub struct ValidationRules;

impl ValidationRules {
    /// Validate that reserves meet the 100% requirement
    ///
    /// In the 100%+100% backing model:
    /// - Reserves in this channel must be >= 100% of deposits + max outstanding invoice
    /// - Collateral in other channels provides additional 100% security
    pub fn validate_reserves_requirement(state: &LedgerState) -> DepositsResult<()> {
        let total_deposit_balances = state.total_deposit_balance();

        let max_outstanding_invoice = Self::get_max_outstanding_invoice_amount(state, 0);

        // Add pending invoice if it exists
        let max_invoice_amount = if let Some(ref pending) = state.pending_invoice {
            std::cmp::max(max_outstanding_invoice, pending.amount)
        } else {
            max_outstanding_invoice
        };

        let required_reserves =
            Self::calculate_required_reserves(total_deposit_balances, max_invoice_amount);

        if state.reserves_amount() < required_reserves {
            return Err(DepositsError::InsufficientReserves {
                required: required_reserves,
                available: state.reserves_amount(),
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

        if state.reserves_amount() < required_reserves {
            return Err(DepositsError::InsufficientReserves {
                required: required_reserves,
                available: state.reserves_amount(),
            });
        }

        Ok(())
    }

    /// Validate deposit removal conditions
    pub fn validate_deposit_removal(
        deposit: &Deposit,
        current_time: u64,
    ) -> DepositsResult<()> {
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
        pubkey: &PublicKey,
    ) -> DepositsResult<&'a Deposit> {
        state.deposits.get(pubkey).ok_or(DepositsError::DepositNotFound)
    }

    /// Validate that deposit does not already exist
    pub fn validate_deposit_not_exists(state: &LedgerState, pubkey: &PublicKey) -> DepositsResult<()> {
        if state.deposits.contains_key(pubkey) {
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
    pub fn validate_invoice_not_expired(invoice: &Invoice, current_time: u64) -> DepositsResult<()> {
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

        state.reserves_amount().saturating_sub(required_reserves)
    }

    /// Validate fee assessment for deposit
    pub fn validate_fee_assessment(
        deposit: &Deposit,
        blocks_elapsed: u32,
    ) -> DepositsResult<u64> {
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
    pub fn validate_add_deposit(state: &LedgerState, pubkey: &PublicKey) -> DepositsResult<()> {
        // Check deposit doesn't already exist
        ValidationRules::validate_deposit_not_exists(state, pubkey)?;

        // Note: Adding deposit with zero balance doesn't require reserve validation
        // since deposits start at zero and only increase from external payments

        Ok(())
    }

    /// Validate complete remove deposit operation
    pub fn validate_remove_deposit(
        state: &LedgerState,
        pubkey: &PublicKey,
        current_time: u64,
    ) -> DepositsResult<()> {
        // Check deposit exists
        let deposit = ValidationRules::validate_deposit_exists(state, pubkey)?;

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

        // Check assigned deposit exists
        ValidationRules::validate_deposit_exists(state, &pending_invoice.assigned_deposit)?;

        // Check reserves are sufficient for this invoice
        ValidationRules::validate_reserves_with_pending(state, pending_invoice)?;

        Ok(())
    }

    /// Validate payment locking operation
    pub fn validate_lock_payment(
        state: &LedgerState,
        pubkey: &PublicKey,
        amount: u64,
    ) -> DepositsResult<()> {
        // Check deposit exists
        let deposit = ValidationRules::validate_deposit_exists(state, pubkey)?;

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
        let remaining_reserves = state.reserves_amount().saturating_sub(amount);

        // Create temporary state to validate
        let mut temp_state = state.clone();
        temp_state.reserves.amount = remaining_reserves;

        // Ensure reserves requirement still met
        ValidationRules::validate_reserves_requirement(&temp_state)?;

        Ok(())
    }

    /// Validate credit payment operation
    pub fn validate_credit_payment(
        state: &LedgerState,
        deposit_pubkey: &PublicKey,
        payment_hash: &[u8; 32],
        amount: u64,
        current_time: u64,
    ) -> DepositsResult<()> {
        // Check deposit exists
        ValidationRules::validate_deposit_exists(state, deposit_pubkey)?;

        // Verify there's a pending invoice matching this payment
        if let Some(ref pending) = state.pending_invoice {
            if pending.payment_hash == *payment_hash
                && pending.assigned_deposit == *deposit_pubkey
                && pending.amount == amount
            {
                return Ok(());
            }
        }

        // Check if there's a matching outstanding invoice in the deposit
        let deposit = ValidationRules::validate_deposit_exists(state, deposit_pubkey)?;
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
            final_state_hash: state.hash,
            computed_reserves: state.reserves_amount(),
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
        self.validate_state(state, claimed_reserves, collateral_amounts).is_conforming
    }
}

impl Default for LedgerConformanceValidator {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{FeeStructure, ReservesOutput};

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
        let mut deposit = Deposit::new(test_pubkey(), None);
        deposit.balance = balance;
        deposit
    }

    fn create_test_state(deposit_balance: u64, reserves: u64) -> LedgerState {
        let mut state = LedgerState::new(test_pubkey(), test_pubkey_2().to_string(), "tb1q...".to_string());

        let deposit = create_test_deposit(deposit_balance);
        let pubkey = deposit.pubkey;
        state.deposits.insert(pubkey, deposit);

        state.reserves = ReservesOutput::new([0u8; 32], reserves, test_pubkey());

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
        let state = create_test_state(1000, 1000);
        let existing_pubkey = test_pubkey();

        // Should find existing deposit
        let result = ValidationRules::validate_deposit_exists(&state, &existing_pubkey);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().balance, 1000);

        // Should fail for non-existent deposit (different pubkey)
        let other_pubkey = test_pubkey_2();
        let result = ValidationRules::validate_deposit_exists(&state, &other_pubkey);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), DepositsError::DepositNotFound));
    }

    #[test]
    fn test_validate_deposit_not_exists() {
        let state = create_test_state(1000, 1000);
        let existing_pubkey = test_pubkey();

        // Should fail for existing deposit
        let result = ValidationRules::validate_deposit_not_exists(&state, &existing_pubkey);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DepositsError::DepositAlreadyExists
        ));

        // Should succeed for non-existent deposit
        let other_pubkey = test_pubkey_2();
        let result = ValidationRules::validate_deposit_not_exists(&state, &other_pubkey);
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
}
