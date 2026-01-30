// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Operation-level validation for Bitcoin Deposits Protocol
//!
//! This module contains pure validation functions for ledger operations.
//! These functions take ledger state and operation data, returning validation results.
//!
//! ## Design
//!
//! Functions in this module are designed to be called from any context:
//! - LDK message handlers
//! - CLN plugins
//! - Direct API calls
//! - Test harnesses
//!
//! They do NOT:
//! - Access any storage/database
//! - Use any logging (caller can log based on result)
//! - Depend on any Lightning implementation

use bitcoin::secp256k1::PublicKey;
use bitcoin::hashes::{sha256, Hash};

use crate::constants::{MIN_RESERVES_OUTPUT_SATS, MAX_RESERVES_OUTPUT_SATS};
use crate::ledger::Ledger;
use crate::types::FeeStructure;
use crate::signature_utils::verify_payment_signature;

/// Result type for validation operations
pub type ValidationResult = Result<(), String>;

// ============================================================================
// Reserves Validations
// ============================================================================

/// Validate a reserves add operation
///
/// Checks:
/// - Amount is at least MIN_RESERVES_OUTPUT_SATS (economically spendable)
/// - Amount does not exceed MAX_RESERVES_OUTPUT_SATS
pub fn validate_reserves_add(initial_amount: u64) -> ValidationResult {
    if initial_amount < MIN_RESERVES_OUTPUT_SATS {
        return Err(format!(
            "Initial reserves amount {} sats is below minimum {} sats required for economic spendability",
            initial_amount, MIN_RESERVES_OUTPUT_SATS
        ));
    }

    if initial_amount > MAX_RESERVES_OUTPUT_SATS {
        return Err(format!(
            "Initial reserves amount {} sats exceeds maximum {} sats allowed",
            initial_amount, MAX_RESERVES_OUTPUT_SATS
        ));
    }

    Ok(())
}

/// Validate a reserves increase operation
///
/// Checks:
/// - New amount is greater than current reserves
/// - Optional: channel balance check (caller must provide)
pub fn validate_reserves_increase(
    current_reserves: u64,
    new_amount: u64,
    channel_balance: Option<u64>,
) -> ValidationResult {
    if new_amount <= current_reserves {
        return Err(format!(
            "New reserves amount {} must be greater than current {}",
            new_amount, current_reserves
        ));
    }

    if let Some(balance) = channel_balance {
        if new_amount > balance {
            return Err(format!(
                "Cannot increase reserves to {} sats: exceeds channel balance {} sats",
                new_amount, balance
            ));
        }
    }

    Ok(())
}

/// Validate a reserves decrease operation
///
/// Checks:
/// - New amount is less than current reserves
/// - New amount still covers required reserves (deposits + max invoice)
pub fn validate_reserves_decrease(
    ledger: &Ledger,
    new_amount: u64,
) -> ValidationResult {
    let current = ledger.reserves_amount();

    if new_amount >= current {
        return Err(format!(
            "New reserves amount {} must be less than current {}",
            new_amount, current
        ));
    }

    // Calculate minimum required reserves
    let total_deposits: u64 = ledger.state.deposits.values().map(|d| d.balance).sum();
    let max_invoice = ledger.state.deposits.values()
        .flat_map(|d| d.invoices.iter())
        .map(|i| i.amount)
        .max()
        .unwrap_or(0);

    let required = total_deposits.saturating_add(max_invoice);

    if new_amount < required {
        return Err(format!(
            "Cannot decrease reserves to {} sats: must maintain at least {} sats (deposits {} + max invoice {})",
            new_amount, required, total_deposits, max_invoice
        ));
    }

    Ok(())
}

// ============================================================================
// Payment Validations
// ============================================================================

/// Validate a payment credit operation
///
/// Checks:
/// - Deposit exists
/// - Amount is positive
/// - Amount is reasonable (< 1 BTC limit)
/// - Credit doesn't exceed reserves backing
/// - Credit doesn't exceed collateral backing
pub fn validate_credit_payment(
    ledger: &Ledger,
    deposit_pubkey: PublicKey,
    amount: u64,
    payment_hash: &[u8; 32],
) -> ValidationResult {
    // Check deposit exists
    if !ledger.state.deposits.contains_key(&deposit_pubkey) {
        return Err(format!("Deposit with pubkey {} does not exist", deposit_pubkey));
    }

    // Check amount is positive
    if amount == 0 {
        return Err("Credit amount must be greater than zero".to_string());
    }

    // Check payment hash is not obviously fake (all same bytes)
    if payment_hash.iter().all(|&b| b == payment_hash[0]) {
        return Err("Invalid payment hash: appears to be fake".to_string());
    }

    // Check amount is reasonable (not too large for a single payment)
    const MAX_CREDIT_SATS: u64 = 100_000_000; // 1 BTC limit per credit
    if amount > MAX_CREDIT_SATS {
        return Err(format!("Credit amount too large: {} sats (max {})", amount, MAX_CREDIT_SATS));
    }

    // Check that credit doesn't exceed reserves backing
    let current_deposits: u64 = ledger.state.deposits.values().map(|d| d.balance).sum();
    let new_total_deposits = current_deposits.saturating_add(amount);

    if new_total_deposits > ledger.reserves_amount() {
        return Err(format!(
            "Credit would exceed reserves: new deposits {} sats > reserves {} sats",
            new_total_deposits, ledger.reserves_amount()
        ));
    }

    // Check that credit doesn't exceed declared collateral
    if new_total_deposits > ledger.state.received_collateral_amount {
        return Err(format!(
            "Credit would exceed declared collateral: new deposits {} sats > received collateral {} sats",
            new_total_deposits, ledger.state.received_collateral_amount
        ));
    }

    Ok(())
}

/// Validate a payment lock operation (outbound payment)
///
/// Checks:
/// - Deposit exists
/// - Sufficient available balance
/// - Amount is positive
/// - Signature is valid
pub fn validate_payment_lock(
    ledger: &Ledger,
    deposit_pubkey: PublicKey,
    amount: u64,
    payment_id: &[u8; 32],
    signature: &[u8; 64],
) -> ValidationResult {
    // Check deposit exists
    let deposit = ledger.state.deposits.get(&deposit_pubkey)
        .ok_or_else(|| format!("Deposit with pubkey {} does not exist", deposit_pubkey))?;

    // Calculate available balance
    let available_balance = deposit.balance.saturating_sub(deposit.locked_balance);

    // Check sufficient balance
    if available_balance < amount {
        return Err(format!(
            "Insufficient available balance: {} < {}",
            available_balance, amount
        ));
    }

    // Check amount is positive
    if amount == 0 {
        return Err("Payment amount must be greater than zero".to_string());
    }

    // Verify scriptpubkey signature
    if !verify_payment_signature(&deposit_pubkey, payment_id, amount, signature) {
        return Err("Invalid scriptpubkey signature for payment lock".to_string());
    }

    Ok(())
}

/// Validate a payment fulfill operation
///
/// Checks:
/// - Amount is positive
/// - Signature is valid
/// - Preimage matches payment hash
pub fn validate_payment_fulfill(
    deposit_pubkey: &PublicKey,
    amount: u64,
    payment_id: &[u8; 32],
    signature: &[u8; 64],
    preimage: &[u8; 32],
) -> ValidationResult {
    // Check amount is positive
    if amount == 0 {
        return Err("Payment amount must be greater than zero".to_string());
    }

    // Verify scriptpubkey signature
    if !verify_payment_signature(deposit_pubkey, payment_id, amount, signature) {
        return Err("Invalid scriptpubkey signature for payment fulfill".to_string());
    }

    // Verify preimage matches payment_id (which is the payment_hash)
    let computed_hash = sha256::Hash::hash(preimage);
    if computed_hash.as_byte_array() != payment_id {
        return Err("Preimage does not match payment hash".to_string());
    }

    Ok(())
}

/// Validate a payment fail operation
///
/// Checks:
/// - Amount is positive
pub fn validate_payment_fail(amount: u64) -> ValidationResult {
    if amount == 0 {
        return Err("Payment amount must be greater than zero".to_string());
    }
    Ok(())
}

// ============================================================================
// Fee Validations
// ============================================================================

/// Validate a fee collection operation
///
/// Checks:
/// - Deposit exists
/// - Sufficient available balance
/// - Collection is on or after schedule
pub fn validate_fee_collect(
    ledger: &Ledger,
    deposit_pubkey: PublicKey,
    amount: u64,
    block_height: u32,
) -> ValidationResult {
    // Check deposit exists and get it
    let deposit = ledger.state.deposits.get(&deposit_pubkey)
        .ok_or_else(|| format!("Deposit with pubkey {} does not exist", deposit_pubkey))?;

    // Check sufficient balance
    let available = deposit.balance.saturating_sub(deposit.locked_balance);
    if available < amount {
        return Err(format!(
            "Insufficient balance for fees: {} available < {} requested",
            available, amount
        ));
    }

    // Check that fee collection happens on or after schedule
    let earliest_allowed_block = deposit.last_fee_assessment.saturating_add(deposit.fees.frequency_blocks);
    if block_height < earliest_allowed_block {
        return Err(format!(
            "Fee collection too early: block {} < earliest allowed {} (last assessment {} + frequency {})",
            block_height, earliest_allowed_block, deposit.last_fee_assessment, deposit.fees.frequency_blocks
        ));
    }

    Ok(())
}

// ============================================================================
// Deposit Validations
// ============================================================================

/// Maximum fee rate in basis points (100% = 10000 bps)
pub const MAX_FEE_RATE_BPS: u16 = 10000;

/// Validate a deposit add operation
///
/// Checks:
/// - Deposit doesn't already exist
/// - Pubkey is not all zeros
/// - Fee structure is valid (if provided)
pub fn validate_deposit_add(
    ledger: &Ledger,
    deposit_pubkey: PublicKey,
    fees: Option<&FeeStructure>,
) -> ValidationResult {
    // Check deposit doesn't already exist
    if ledger.state.deposits.contains_key(&deposit_pubkey) {
        return Err(format!("Deposit with pubkey {} already exists", deposit_pubkey));
    }

    // Validate pubkey is not all zeros
    if deposit_pubkey.serialize().iter().all(|&b| b == 0) {
        return Err("Invalid pubkey: all zeros".to_string());
    }

    // Validate fee structure if provided
    if let Some(fee_struct) = fees {
        if fee_struct.frequency_blocks == 0 {
            return Err("Fee frequency must be greater than zero".to_string());
        }
        if fee_struct.annualized_bps > MAX_FEE_RATE_BPS {
            return Err(format!(
                "Fee rate too high: {} bps exceeds maximum of {} bps",
                fee_struct.annualized_bps, MAX_FEE_RATE_BPS
            ));
        }
    }

    Ok(())
}

/// Validate a deposit close operation
///
/// Checks:
/// - Deposit exists
/// - Balance is zero
/// - No locked balance
pub fn validate_deposit_close(
    ledger: &Ledger,
    deposit_pubkey: PublicKey,
) -> ValidationResult {
    // Check deposit exists
    let deposit = ledger.state.deposits.get(&deposit_pubkey)
        .ok_or_else(|| format!("Deposit with pubkey {} does not exist", deposit_pubkey))?;

    // Check balance is zero
    if deposit.balance > 0 {
        return Err(format!(
            "Cannot close deposit with non-zero balance: {} sats",
            deposit.balance
        ));
    }

    // Check no locked balance
    if deposit.locked_balance > 0 {
        return Err(format!(
            "Cannot close deposit with locked balance: {} sats",
            deposit.locked_balance
        ));
    }

    Ok(())
}

/// Validate a deposit update operation
///
/// Checks:
/// - Deposit exists
/// - New fee structure is valid
pub fn validate_deposit_update(
    ledger: &Ledger,
    deposit_pubkey: PublicKey,
    new_fees: &FeeStructure,
) -> ValidationResult {
    if !ledger.state.deposits.contains_key(&deposit_pubkey) {
        return Err(format!("Deposit with pubkey {} does not exist", deposit_pubkey));
    }

    // Validate new fee structure
    if new_fees.frequency_blocks == 0 {
        return Err("Fee frequency must be greater than zero".to_string());
    }
    if new_fees.annualized_bps > MAX_FEE_RATE_BPS {
        return Err(format!(
            "Fee rate too high: {} bps exceeds maximum of {} bps",
            new_fees.annualized_bps, MAX_FEE_RATE_BPS
        ));
    }

    Ok(())
}

// ============================================================================
// Collateral Validations
// ============================================================================

/// Validate a collateral increase operation
///
/// Checks:
/// - New amount is greater than current
/// - New amount doesn't exceed reserves backing
pub fn validate_collateral_increase(
    current_collateral: u64,
    new_amount: u64,
    reserves_amount: u64,
) -> ValidationResult {
    // Allow idempotent case: if already at target, return Ok (no-op)
    // This handles state sync issues where operator thinks collateral is 0
    // but partner has it at the target value from a previous interaction
    if new_amount == current_collateral {
        return Ok(()); // Idempotent - already at target
    }

    if new_amount < current_collateral {
        return Err(format!(
            "CollateralIncrease must increase collateral: {} is less than current {}",
            new_amount, current_collateral
        ));
    }

    if new_amount > reserves_amount {
        return Err(format!(
            "Collateral increase exceeds reserves: {} sats committed > {} sats reserves",
            new_amount, reserves_amount
        ));
    }

    Ok(())
}

/// Collateral reporting period in blocks (used to prevent decrease right after increase)
pub use crate::constants::COLLATERAL_REPORTING_PERIOD_BLOCKS;

/// Validate a collateral decrease operation
///
/// Checks:
/// - New amount is less than current
/// - Not in same reporting period as increase
pub fn validate_collateral_decrease(
    current_collateral: u64,
    new_amount: u64,
    block_height: u32,
    last_increase_block: Option<u32>,
) -> ValidationResult {
    if new_amount >= current_collateral {
        return Err(format!(
            "CollateralDecrease must decrease collateral: {} is not less than current {}",
            new_amount, current_collateral
        ));
    }

    // Check timing constraint
    if let Some(last_increase) = last_increase_block {
        let earliest_allowed = last_increase.saturating_add(COLLATERAL_REPORTING_PERIOD_BLOCKS);
        if block_height < earliest_allowed {
            return Err(format!(
                "CollateralDecrease too soon after increase: block {} < earliest allowed {} (last increase {} + period {})",
                block_height, earliest_allowed, last_increase, COLLATERAL_REPORTING_PERIOD_BLOCKS
            ));
        }
    }

    Ok(())
}

// ============================================================================
// Invoice Validations
// ============================================================================

/// Validate a cosign invoice operation
///
/// Checks:
/// - Deposit exists
/// - Amount is positive
/// - Amount is reasonable (< 1 BTC in msat)
/// - Invoice ID is not empty
/// - Payment hash is not obviously fake
/// - Cosigning wouldn't exceed reserves backing
/// - Cosigning wouldn't exceed collateral backing
pub fn validate_cosign_invoice(
    ledger: &Ledger,
    assigned_deposit: PublicKey,
    amount: u64,
    invoice_id: &str,
    payment_hash: &[u8; 32],
) -> ValidationResult {
    // Check if the assigned deposit exists
    if !ledger.state.deposits.contains_key(&assigned_deposit) {
        return Err(format!("Deposit with pubkey {} does not exist", assigned_deposit));
    }

    // Check amount is positive
    if amount == 0 {
        return Err("Invoice amount must be greater than zero".to_string());
    }

    // Check amount is reasonable (not too large)
    const MAX_INVOICE_MSAT: u64 = 100_000_000_000; // 1 BTC in msat
    if amount > MAX_INVOICE_MSAT {
        return Err(format!("Invoice amount too large: {} msat (max {})", amount, MAX_INVOICE_MSAT));
    }

    // Check invoice ID is not empty
    if invoice_id.is_empty() {
        return Err("Invoice ID cannot be empty".to_string());
    }

    // Check payment hash is not obviously fake (all same bytes)
    if payment_hash.iter().all(|&b| b == payment_hash[0]) {
        return Err("Invalid payment hash: appears to be fake".to_string());
    }

    // CRITICAL: Check that cosigning this invoice wouldn't exceed reserves capacity
    // Total deposits + this new invoice amount must not exceed reserves
    let current_deposits: u64 = ledger.state.deposits.values().map(|d| d.balance).sum();
    let new_total_deposits = current_deposits.saturating_add(amount);

    if new_total_deposits > ledger.reserves_amount() {
        return Err(format!(
            "Cosigning would exceed reserves: potential deposits {} msat > reserves {} msat",
            new_total_deposits, ledger.reserves_amount()
        ));
    }

    // CRITICAL: Check that cosigning wouldn't exceed declared collateral
    if new_total_deposits > ledger.state.received_collateral_amount {
        return Err(format!(
            "Cosigning would exceed collateral: potential deposits {} msat > collateral {} msat",
            new_total_deposits, ledger.state.received_collateral_amount
        ));
    }

    Ok(())
}

// ============================================================================
// Ledger Validations
// ============================================================================

/// Validate a ledger close operation
///
/// Checks:
/// - Total deposit balance is zero
/// - No locked balances (pending payments)
///
/// Note: The caller must separately verify that the reserves_id matches the expected value.
pub fn validate_ledger_close(ledger: &Ledger) -> ValidationResult {
    // Check for outstanding balances - deposits should be empty or zero-balance
    let total_balance: u64 = ledger.state.deposits.values().map(|d| d.balance).sum();
    if total_balance > 0 {
        return Err(format!(
            "Cannot close ledger with outstanding deposit balance: {} msat",
            total_balance
        ));
    }

    // Check for locked balances (pending payments)
    let total_locked: u64 = ledger.state.deposits.values().map(|d| d.locked_balance).sum();
    if total_locked > 0 {
        return Err(format!(
            "Cannot close ledger with locked payments: {} msat",
            total_locked
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::{LedgerRole};
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    fn test_pubkey() -> PublicKey {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[1u8; 32]).unwrap();
        PublicKey::from_secret_key(&secp, &secret)
    }

    fn test_pubkey_2() -> PublicKey {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[2u8; 32]).unwrap();
        PublicKey::from_secret_key(&secp, &secret)
    }

    fn create_test_ledger() -> Ledger {
        Ledger::new(
            test_pubkey(),
            test_pubkey_2().to_string(),
            LedgerRole::Operator,
            vec![],
            "test_ledger".to_string(),
        )
    }

    #[test]
    fn test_validate_reserves_add() {
        // Valid amount
        assert!(validate_reserves_add(100_000).is_ok());

        // Too small
        assert!(validate_reserves_add(100).is_err());

        // Too large
        assert!(validate_reserves_add(1_000_000_000_000).is_err());
    }

    #[test]
    fn test_validate_reserves_increase() {
        // Valid increase
        assert!(validate_reserves_increase(1000, 2000, None).is_ok());

        // Not actually increasing
        assert!(validate_reserves_increase(1000, 1000, None).is_err());
        assert!(validate_reserves_increase(1000, 500, None).is_err());

        // Exceeds channel balance
        assert!(validate_reserves_increase(1000, 2000, Some(1500)).is_err());
    }

    #[test]
    fn test_validate_payment_fail() {
        assert!(validate_payment_fail(1000).is_ok());
        assert!(validate_payment_fail(0).is_err());
    }

    #[test]
    fn test_validate_deposit_add() {
        let ledger = create_test_ledger();
        let new_pubkey = test_pubkey_2();

        // Valid add to empty ledger
        assert!(validate_deposit_add(&ledger, new_pubkey, None).is_ok());

        // Invalid fee structure
        let bad_fees = FeeStructure {
            annualized_fixed: 0,
            annualized_bps: 0,
            frequency_blocks: 0, // Invalid
        };
        assert!(validate_deposit_add(&ledger, new_pubkey, Some(&bad_fees)).is_err());
    }

    #[test]
    fn test_validate_collateral_increase() {
        // Valid increase within reserves
        assert!(validate_collateral_increase(1000, 2000, 5000).is_ok());

        // Idempotent: same amount is OK (handles state sync issues)
        assert!(validate_collateral_increase(1000, 1000, 5000).is_ok());

        // Decrease is not allowed via CollateralIncrease
        assert!(validate_collateral_increase(1000, 500, 5000).is_err());

        // Exceeds reserves
        assert!(validate_collateral_increase(1000, 6000, 5000).is_err());
    }

    #[test]
    fn test_validate_collateral_decrease() {
        // Valid decrease, no timing constraint
        assert!(validate_collateral_decrease(2000, 1000, 1000, None).is_ok());

        // Not actually decreasing
        assert!(validate_collateral_decrease(1000, 1000, 1000, None).is_err());
        assert!(validate_collateral_decrease(1000, 1500, 1000, None).is_err());

        // Timing constraint: too soon after increase
        // COLLATERAL_REPORTING_PERIOD_BLOCKS is typically 144 blocks
        assert!(validate_collateral_decrease(2000, 1000, 100, Some(50)).is_err());

        // Timing constraint: after reporting period
        assert!(validate_collateral_decrease(2000, 1000, 1000, Some(50)).is_ok());
    }
}
