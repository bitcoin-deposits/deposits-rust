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

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::PublicKey;

use crate::constants::{MAX_RESERVES_OUTPUT_SATS, MIN_RESERVES_OUTPUT_SATS};
use crate::ledger::Ledger;
use crate::signing::verify_payment_signature;
use crate::types::FeeStructure;

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
    // Convert pubkey to deposit_id and check deposit exists
    let descriptor = format!("pk({})", hex::encode(deposit_pubkey.serialize()));
    let deposit_id = crate::types::compute_deposit_id(&descriptor);
    if !ledger.state.deposits.contains_key(&deposit_id) {
        return Err(format!(
            "Deposit with pubkey {} does not exist",
            deposit_pubkey
        ));
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
        return Err(format!(
            "Credit amount too large: {} sats (max {})",
            amount, MAX_CREDIT_SATS
        ));
    }

    // Check that credit doesn't exceed reserves backing. Per DEP-05, "total
    // obligations" = balance + locked across all deposits.
    let current_deposits = ledger.state.total_deposit_balance();
    let new_total_deposits = current_deposits.saturating_add(amount);

    if new_total_deposits > ledger.reserves_amount() {
        return Err(format!(
            "Credit would exceed reserves: new deposits {} msats > reserves {} msats",
            new_total_deposits,
            ledger.reserves_amount()
        ));
    }

    // Check that credit doesn't exceed declared collateral (only when quorum is active)
    if ledger.state.quorum_state == crate::types::QuorumState::Active
        && new_total_deposits > ledger.state.total_collateral()
    {
        return Err(format!(
            "Credit would exceed declared collateral: new deposits {} sats > received collateral {} sats",
            new_total_deposits, ledger.state.total_collateral()
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
    // Convert pubkey to deposit_id and check deposit exists
    let descriptor = format!("pk({})", hex::encode(deposit_pubkey.serialize()));
    let deposit_id = crate::types::compute_deposit_id(&descriptor);
    let deposit = ledger
        .state
        .deposits
        .get(&deposit_id)
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

/// Validate that a proposed fee structure meets operator terms.
///
/// Used when a wallet proposes fees during deposit opening. The operator
/// dictates the assessment period; the wallet may only choose annual rates.
///
/// Checks:
/// - `frequency_blocks` exactly equals the operator's period.
///   Without this, a wallet can propose `frequency_blocks > 1 year`
///   (no fees ever collected within a deposit lifetime), or
///   `frequency_blocks ≤ 1` (every block emits a fee-collect update,
///   bloating the ledger). Both bypass economic enforcement that the
///   per-period comparison alone can't catch.
/// - Proposed annual bps >= operator's minimum annual bps
/// - Proposed fixed fee per period >= operator's minimum fixed fee per period
pub fn validate_fee_minimum(
    proposed: &FeeStructure,
    min_annual_bps: u16,
    min_fixed_per_period: u64,
    expected_period_blocks: u32,
) -> ValidationResult {
    // The period is operator-dictated. Wallets that disagree must take
    // their business elsewhere — not silently re-shape the contract.
    if proposed.frequency_blocks != expected_period_blocks {
        return Err(format!(
            "Proposed fee period {} blocks doesn't match operator period {} blocks",
            proposed.frequency_blocks, expected_period_blocks
        ));
    }

    // Check annual bps meets minimum
    if proposed.annualized_bps < min_annual_bps {
        return Err(format!(
            "Proposed annual fee {} bps is below operator minimum {} bps",
            proposed.annualized_bps, min_annual_bps
        ));
    }

    // Calculate the proposed fixed fee per period from annualized fixed.
    // Period is now guaranteed equal to expected_period_blocks > 0, so
    // the divide-by-zero case is impossible.
    const BLOCKS_PER_YEAR: u64 = 52560;
    let periods_per_year = (BLOCKS_PER_YEAR / proposed.frequency_blocks.max(1) as u64).max(1);
    let proposed_fixed_per_period = proposed.annualized_msats / periods_per_year;

    // Check fixed fee meets minimum per period (both in msats)
    if proposed_fixed_per_period < min_fixed_per_period {
        return Err(format!(
            "Proposed fixed fee {} msats/period is below operator minimum {} msats/period",
            proposed_fixed_per_period, min_fixed_per_period
        ));
    }

    Ok(())
}

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
    // Convert pubkey to deposit_id and check deposit exists
    let descriptor = format!("pk({})", hex::encode(deposit_pubkey.serialize()));
    let deposit_id = crate::types::compute_deposit_id(&descriptor);
    let deposit = ledger
        .state
        .deposits
        .get(&deposit_id)
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
    let earliest_allowed_block = deposit
        .last_fee_assessment
        .saturating_add(deposit.fees.frequency_blocks);
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
    // Convert pubkey to deposit_id and check deposit doesn't already exist
    let descriptor = format!("pk({})", hex::encode(deposit_pubkey.serialize()));
    let deposit_id = crate::types::compute_deposit_id(&descriptor);
    if ledger.state.deposits.contains_key(&deposit_id) {
        return Err(format!(
            "Deposit with pubkey {} already exists",
            deposit_pubkey
        ));
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
pub fn validate_deposit_close(ledger: &Ledger, deposit_pubkey: PublicKey) -> ValidationResult {
    // Convert pubkey to deposit_id and check deposit exists
    let descriptor = format!("pk({})", hex::encode(deposit_pubkey.serialize()));
    let deposit_id = crate::types::compute_deposit_id(&descriptor);
    let deposit = ledger
        .state
        .deposits
        .get(&deposit_id)
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

/// Validate a fee change operation
///
/// Checks:
/// - Deposit exists
/// - New fee structure is valid
pub fn validate_fee_change(
    ledger: &Ledger,
    deposit_pubkey: PublicKey,
    new_fees: &FeeStructure,
) -> ValidationResult {
    // Convert pubkey to deposit_id and check deposit exists
    let descriptor = format!("pk({})", hex::encode(deposit_pubkey.serialize()));
    let deposit_id = crate::types::compute_deposit_id(&descriptor);
    if !ledger.state.deposits.contains_key(&deposit_id) {
        return Err(format!(
            "Deposit with pubkey {} does not exist",
            deposit_pubkey
        ));
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
    // Convert pubkey to deposit_id and check if the assigned deposit exists
    let descriptor = format!("pk({})", hex::encode(assigned_deposit.serialize()));
    let deposit_id = crate::types::compute_deposit_id(&descriptor);
    if !ledger.state.deposits.contains_key(&deposit_id) {
        return Err(format!(
            "Deposit with pubkey {} does not exist",
            assigned_deposit
        ));
    }

    // Check amount is positive
    if amount == 0 {
        return Err("Invoice amount must be greater than zero".to_string());
    }

    // Check amount is reasonable (not too large)
    const MAX_INVOICE_MSAT: u64 = 100_000_000_000; // 1 BTC in msat
    if amount > MAX_INVOICE_MSAT {
        return Err(format!(
            "Invoice amount too large: {} msat (max {})",
            amount, MAX_INVOICE_MSAT
        ));
    }

    // Check invoice ID is not empty
    if invoice_id.is_empty() {
        return Err("Invoice ID cannot be empty".to_string());
    }

    // Check payment hash is not obviously fake (all same bytes)
    if payment_hash.iter().all(|&b| b == payment_hash[0]) {
        return Err("Invalid payment hash: appears to be fake".to_string());
    }

    // CRITICAL: Check that cosigning this invoice wouldn't exceed reserves capacity.
    // Per DEP-05, total obligations = balance + locked across all deposits.
    let current_deposits = ledger.state.total_deposit_balance();
    let new_total_deposits = current_deposits.saturating_add(amount);

    if new_total_deposits > ledger.reserves_amount() {
        return Err(format!(
            "Cosigning would exceed reserves: potential deposits {} msat > reserves {} msat",
            new_total_deposits,
            ledger.reserves_amount()
        ));
    }

    // CRITICAL: Check that cosigning wouldn't exceed declared collateral (only when quorum is active)
    if ledger.state.quorum_state == crate::types::QuorumState::Active
        && new_total_deposits > ledger.state.total_collateral()
    {
        return Err(format!(
            "Cosigning would exceed collateral: potential deposits {} msat > collateral {} msat",
            new_total_deposits,
            ledger.state.total_collateral()
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
    // Check for outstanding balances — deposits should be empty or zero-balance,
    // including any locked funds (in-flight transfers/invoices) per DEP-05.
    let total_balance = ledger.state.total_deposit_balance();
    if total_balance > 0 {
        return Err(format!(
            "Cannot close ledger with outstanding deposit balance: {} msat",
            total_balance
        ));
    }

    // Check for locked balances (pending payments)
    let total_locked: u64 = ledger
        .state
        .deposits
        .values()
        .map(|d| d.locked_balance)
        .sum();
    if total_locked > 0 {
        return Err(format!(
            "Cannot close ledger with locked payments: {} msat",
            total_locked
        ));
    }

    Ok(())
}

// ============================================================================
// DepositId-based Validations
// ============================================================================

use crate::types::{DepositId, DescriptorWitness};

/// Validate a deposit add operation by deposit_id
///
/// Checks:
/// - Deposit doesn't already exist
/// - Fee structure is valid (if provided)
pub fn validate_deposit_add_by_id(
    ledger: &Ledger,
    deposit_id: &DepositId,
    fees: Option<&FeeStructure>,
) -> ValidationResult {
    // Check deposit doesn't already exist
    if ledger.state.deposits.contains_key(deposit_id) {
        return Err(format!(
            "Deposit with id {} already exists",
            hex::encode(deposit_id)
        ));
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

/// Validate a deposit close operation by deposit_id
///
/// Checks:
/// - Deposit exists
/// - Balance is zero
/// - No locked balance
pub fn validate_deposit_close_by_id(ledger: &Ledger, deposit_id: &DepositId) -> ValidationResult {
    // Check deposit exists
    let deposit = ledger
        .state
        .deposits
        .get(deposit_id)
        .ok_or_else(|| format!("Deposit with id {} does not exist", hex::encode(deposit_id)))?;

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

/// Validate a fee change operation by deposit_id
///
/// Checks:
/// - Deposit exists
/// - New fee structure is valid
pub fn validate_fee_change_by_id(
    ledger: &Ledger,
    deposit_id: &DepositId,
    new_fees: &FeeStructure,
) -> ValidationResult {
    validate_deposit_fee_change(ledger, deposit_id, new_fees, 0, 0)
}

/// Validate a fee change with full constraint checking.
///
/// Checks:
/// - Deposit exists
/// - New fee structure is valid
/// - Enough blocks since deposit open (fee_change_after_blocks)
/// - Effective block is far enough in future (fee_change_notice_blocks)
/// - Fee change is within limit (fee_change_limit_bps)
pub fn validate_deposit_fee_change(
    ledger: &Ledger,
    deposit_id: &DepositId,
    new_fees: &FeeStructure,
    effective_block: u32,
    current_block: u32,
) -> ValidationResult {
    let deposit = match ledger.state.deposits.get(deposit_id) {
        Some(d) => d,
        None => {
            return Err(format!(
                "Deposit with id {} does not exist",
                hex::encode(deposit_id)
            ))
        }
    };

    // Validate new fee structure basics
    if new_fees.frequency_blocks == 0 {
        return Err("Fee frequency must be greater than zero".to_string());
    }
    if new_fees.annualized_bps > MAX_FEE_RATE_BPS {
        return Err(format!(
            "Fee rate too high: {} bps exceeds maximum of {} bps",
            new_fees.annualized_bps, MAX_FEE_RATE_BPS
        ));
    }

    // Skip timing/limit checks if no change parameters were negotiated
    // or if current_block is 0 (legacy validation without block context)
    if current_block == 0 {
        return Ok(());
    }

    // Check: enough blocks since deposit open
    if let Some(after) = deposit.fee_change_after_blocks {
        let earliest = deposit.opened_at_block.saturating_add(after);
        if current_block < earliest {
            return Err(format!(
                "Fee change too early: {} blocks since open, {} required (earliest block {})",
                current_block.saturating_sub(deposit.opened_at_block),
                after,
                earliest
            ));
        }
    }

    // Check: effective_block far enough in future
    if let Some(notice) = deposit.fee_change_notice_blocks {
        let min_effective = current_block.saturating_add(notice);
        if effective_block < min_effective {
            return Err(format!(
                "Insufficient notice: effective_block {} < current {} + notice {} = {}",
                effective_block, current_block, notice, min_effective
            ));
        }
    }

    // Check: fee change within limit
    if let Some(limit_bps) = deposit.fee_change_limit_bps {
        // Check annualized_bps change
        let old_bps = deposit.fees.annualized_bps as i64;
        let new_bps = new_fees.annualized_bps as i64;
        let bps_change = (new_bps - old_bps).unsigned_abs();
        let max_bps_change = if old_bps > 0 {
            (old_bps as u64 * limit_bps as u64) / 10000
        } else {
            limit_bps as u64 // allow setting from zero
        };
        if bps_change > max_bps_change {
            return Err(format!(
                "Fee rate change too large: {} -> {} ({} bps change, max {} at {}% limit)",
                old_bps,
                new_bps,
                bps_change,
                max_bps_change,
                limit_bps as f64 / 100.0
            ));
        }

        // Check annualized_msats change
        let old_fixed = deposit.fees.annualized_msats as i64;
        let new_fixed = new_fees.annualized_msats as i64;
        let fixed_change = (new_fixed - old_fixed).unsigned_abs();
        let max_fixed_change = if old_fixed > 0 {
            (old_fixed as u64 * limit_bps as u64) / 10000
        } else {
            limit_bps as u64 // allow setting from zero
        };
        if fixed_change > max_fixed_change {
            return Err(format!(
                "Fixed fee change too large: {} -> {} ({} change, max {} at {}% limit)",
                old_fixed,
                new_fixed,
                fixed_change,
                max_fixed_change,
                limit_bps as f64 / 100.0
            ));
        }
    }

    Ok(())
}

/// Validate a credit payment operation by deposit_id
///
/// Checks:
/// - Deposit exists
/// - Amount is positive
/// - Credit wouldn't exceed reserves
/// - Credit wouldn't exceed collateral (if quorum present)
pub fn validate_credit_payment_by_id(
    ledger: &Ledger,
    deposit_id: &DepositId,
    amount: u64,
    payment_hash: &[u8; 32],
    _invoice_id: &str,
) -> ValidationResult {
    // Check deposit exists
    if !ledger.state.deposits.contains_key(deposit_id) {
        return Err(format!(
            "Deposit with id {} does not exist",
            hex::encode(deposit_id)
        ));
    }

    // Check amount is positive
    if amount == 0 {
        return Err("Credit amount must be greater than zero".to_string());
    }

    // Check that credit wouldn't exceed reserves capacity (obligations =
    // balance + locked across all deposits per DEP-05).
    let current_deposits = ledger.state.total_deposit_balance();
    let new_total_deposits = current_deposits.saturating_add(amount);

    if new_total_deposits > ledger.reserves_amount() {
        return Err(format!(
            "Credit would exceed reserves: new deposits {} msat > reserves {} msat",
            new_total_deposits,
            ledger.reserves_amount()
        ));
    }

    // Check payment hash is not obviously fake
    if payment_hash.iter().all(|&b| b == payment_hash[0]) {
        return Err("Invalid payment hash: appears to be fake".to_string());
    }

    // Check that credit doesn't exceed declared collateral (only when quorum is active)
    if ledger.state.quorum_state == crate::types::QuorumState::Active
        && new_total_deposits > ledger.state.total_collateral()
    {
        return Err(format!(
            "Credit would exceed declared collateral: new deposits {} sats > received collateral {} sats",
            new_total_deposits, ledger.state.total_collateral()
        ));
    }

    Ok(())
}

/// Validate a fee collection operation by deposit_id
///
/// Checks:
/// - Deposit exists
/// - Sufficient available balance
/// - Collection is on or after schedule
pub fn validate_fee_collect_by_id(
    ledger: &Ledger,
    deposit_id: &DepositId,
    amount: u64,
    block_height: u32,
) -> ValidationResult {
    // Check deposit exists and get it
    let deposit = ledger
        .state
        .deposits
        .get(deposit_id)
        .ok_or_else(|| format!("Deposit with id {} does not exist", hex::encode(deposit_id)))?;

    // Check sufficient balance
    let available = deposit.balance.saturating_sub(deposit.locked_balance);
    if available < amount {
        return Err(format!(
            "Insufficient balance for fees: {} available < {} requested",
            available, amount
        ));
    }

    // Check that fee collection happens on or after schedule
    let earliest_allowed_block = deposit
        .last_fee_assessment
        .saturating_add(deposit.fees.frequency_blocks);
    if block_height < earliest_allowed_block {
        return Err(format!(
            "Fee collection too early: block {} < earliest allowed {} (last assessment {} + frequency {})",
            block_height, earliest_allowed_block, deposit.last_fee_assessment, deposit.fees.frequency_blocks
        ));
    }

    Ok(())
}

// ============================================================================
// Transfer Validation
// ============================================================================

// validate_transfer_lock / validate_transfer_complete deleted —
// rolled into LedgerState::apply (balance/existence) and
// check_conformance (witness, zero-amount, transfer_id-match).

/// Validate a TransferFail operation.
///
/// Checks:
/// - Pending transfer exists
/// - Current block height is >= timeout_height
pub fn validate_transfer_timeout(
    ledger: &Ledger,
    transfer_id: &[u8; 32],
    current_block_height: u32,
) -> ValidationResult {
    // Check pending transfer exists
    let pending = ledger
        .state
        .pending_transfers
        .get(transfer_id)
        .ok_or_else(|| {
            format!(
                "Pending transfer {} does not exist",
                hex::encode(transfer_id)
            )
        })?;

    // Check we're past the timeout height
    if current_block_height < pending.timeout_height {
        return Err(format!(
            "Transfer timeout not reached: current block {} < timeout {}",
            current_block_height, pending.timeout_height
        ));
    }

    Ok(())
}

// ============================================================================
// QuorumAddMember signed-response validation (Q1)
// ============================================================================

/// Validate the optional `member_response` blob carried in `QuorumAddMember`.
///
/// When `response` is `None`, this is a legacy event — accept it (the operator
/// is still recording terms, just without a member-attested blob). When
/// `response` is `Some`, decode it and check:
///
/// 1. `signature` is `Some` (paired field).
/// 2. `signature` is a valid BIP-340 signature by `member_pubkey` (decoded
///    from the blob) over `quorum_member_response_digest(response)`.
/// 3. The decoded `member_pubkey` matches the loose `quorum_member` field.
/// 4. Every loose field on `QuorumAddMember` matches the corresponding
///    decoded field exactly. This is the rule that makes the blob
///    authoritative: an operator cannot rewrite the terms after the member
///    signed them.
pub fn validate_quorum_add_member_blob(
    quorum_member: &PublicKey,
    member_ledger_id: &str,
    response: Option<&[u8]>,
    signature: Option<&[u8; 64]>,
    loose_min_fee_bps: Option<u16>,
    loose_min_fee_fixed: Option<u64>,
    loose_max_fee_period: Option<u32>,
    loose_membership_until: Option<u32>,
    loose_dispute_response_blocks: Option<u32>,
    loose_dispute_arm_blocks: Option<u32>,
    loose_service_response_blocks: Option<u32>,
    loose_max_transfer_timeout_blocks: Option<u32>,
    loose_max_descriptor_bytes: Option<u32>,
    loose_compensation_bps: Option<u16>,
    loose_compensation_deposit_id: Option<crate::types::DepositId>,
    loose_compensation_frequency_blocks: Option<u32>,
) -> ValidationResult {
    let response_bytes = match response {
        None => return Ok(()),
        Some(b) => b,
    };
    let signature = signature.ok_or_else(|| {
        "QuorumAddMember.member_response is set but member_signature is missing".to_string()
    })?;

    use crate::types::{quorum_member_response_digest, QuorumMemberResponse};
    use crate::TlvDecode;

    let decoded = QuorumMemberResponse::tlv_decode(response_bytes)
        .map_err(|e| format!("QuorumAddMember.member_response failed to decode: {:?}", e))?;

    if decoded.member_pubkey != *quorum_member {
        return Err(format!(
            "QuorumAddMember.member_response.member_pubkey {} does not match outer quorum_member {}",
            decoded.member_pubkey, quorum_member
        ));
    }
    if decoded.member_ledger_id != member_ledger_id {
        return Err(format!(
            "QuorumAddMember.member_response.member_ledger_id {} does not match outer member_ledger_id {}",
            decoded.member_ledger_id, member_ledger_id
        ));
    }

    let digest = quorum_member_response_digest(response_bytes);
    use bitcoin::secp256k1::schnorr::Signature;
    use bitcoin::secp256k1::{Message, Secp256k1};
    let sig = Signature::from_slice(signature).map_err(|_| {
        "QuorumAddMember.member_signature: invalid 64-byte schnorr signature".to_string()
    })?;
    let msg = Message::from_digest(digest);
    let secp = Secp256k1::verification_only();
    let (xonly, _) = decoded.member_pubkey.x_only_public_key();
    secp.verify_schnorr(&sig, &msg, &xonly).map_err(|_| {
        "QuorumAddMember.member_signature: BIP-340 verify failed against member_pubkey".to_string()
    })?;

    fn check<T: PartialEq + std::fmt::Debug>(name: &str, loose: T, blob: T) -> ValidationResult {
        if loose != blob {
            return Err(format!(
                "QuorumAddMember.{} mismatch: loose={:?}, signed-blob={:?}",
                name, loose, blob
            ));
        }
        Ok(())
    }
    check("min_fee_bps", loose_min_fee_bps, decoded.min_fee_bps)?;
    check("min_fee_fixed", loose_min_fee_fixed, decoded.min_fee_fixed)?;
    check(
        "max_fee_period",
        loose_max_fee_period,
        decoded.max_fee_period,
    )?;
    check(
        "membership_until",
        loose_membership_until,
        decoded.membership_until,
    )?;
    check(
        "dispute_response_blocks",
        loose_dispute_response_blocks,
        decoded.dispute_response_blocks,
    )?;
    check(
        "dispute_arm_blocks",
        loose_dispute_arm_blocks,
        decoded.dispute_arm_blocks,
    )?;
    check(
        "service_response_blocks",
        loose_service_response_blocks,
        decoded.service_response_blocks,
    )?;
    check(
        "max_transfer_timeout_blocks",
        loose_max_transfer_timeout_blocks,
        decoded.max_transfer_timeout_blocks,
    )?;
    check(
        "max_descriptor_bytes",
        loose_max_descriptor_bytes,
        decoded.max_descriptor_bytes,
    )?;
    check(
        "compensation_bps",
        loose_compensation_bps,
        decoded.compensation_bps,
    )?;
    check(
        "compensation_deposit_id",
        loose_compensation_deposit_id,
        decoded.compensation_deposit_id,
    )?;
    check(
        "compensation_frequency_blocks",
        loose_compensation_frequency_blocks,
        decoded.compensation_frequency_blocks,
    )?;

    Ok(())
}

// ============================================================================
// Fork-branch DisputeEnter verifier (QuorumExpired path)
// ============================================================================

/// Validate a fork-branch `DisputeEnter` operation that cites QuorumExpired
/// evidence inline (`anchor_block_hash` + `anchor_block_height`).
///
/// A member daemon calls this on every fork-branch `DisputeEnter` it sees
/// before auto-arming. The verifier:
///
/// 1. **Anchor block exists.** `oracle.confirms(anchor_block_hash)` returns
///    `Some(observed_height)`; that height must equal `anchor_block_height`.
///    Together these prove the cited block is in the verifier's canonical
///    chain at the asserted height.
/// 2. **Anchor exceeds expiry.** `anchor_block_height > ledger.quorum_expiry`.
///    This is the "deadline missed" predicate — the disputer is asserting
///    the chain has progressed past the rotation deadline.
/// 3. **Fork point is the current tip.** `last_valid_sequence ==
///    main_chain_tip_seq`. A majority of members cosigned every update
///    on the main chain, so a majority knows the tip's sequence number.
///    Forking from an earlier point is provably forking from stale state
///    — a majority of receivers will reject it.
///
/// Returns `Ok(())` only when all three pass. Per-check error messages
/// distinguish the failure mode so the rejecting daemon's log makes
/// clear which invariant was broken.
///
/// **What this is NOT.** This verifier is QuorumExpired-specific: it
/// assumes the `DisputeEnter` is justified by deadline-miss evidence.
/// Other dispute paths (e.g., bad witness, uncredited payment) carry
/// their evidence via the kind:9101 fraud-broadcast pipeline and don't
/// populate `anchor_block_hash` / `anchor_block_height`. Callers should
/// route to this verifier only when both anchor fields are `Some`.
pub fn validate_dispute_enter_quorum_expired<O: deposits_protocol::fraud::BlockOracle>(
    anchor_block_hash: &[u8; 32],
    anchor_block_height: u32,
    last_valid_sequence: u64,
    ledger_quorum_expiry: u32,
    main_chain_tip_seq: u64,
    oracle: &O,
) -> ValidationResult {
    // 1. Oracle check
    let observed = oracle.confirms(anchor_block_hash).ok_or_else(|| {
        format!(
            "anchor_block_hash {} not in canonical chain (oracle unknown / not best chain)",
            hex::encode(anchor_block_hash)
        )
    })?;
    if observed != anchor_block_height {
        return Err(format!(
            "anchor_block_hash {} is at oracle height {}, not the asserted {}",
            hex::encode(anchor_block_hash),
            observed,
            anchor_block_height
        ));
    }

    // 2. Past expiry
    if anchor_block_height <= ledger_quorum_expiry {
        return Err(format!(
            "anchor_block_height {} does not exceed ledger quorum_expiry {} \
             (deadline-miss predicate not satisfied)",
            anchor_block_height, ledger_quorum_expiry
        ));
    }

    // 3. Fork point matches main-chain tip
    if last_valid_sequence != main_chain_tip_seq {
        return Err(format!(
            "last_valid_sequence {} does not equal main-chain tip {}: fork \
             attempted from stale state (the disputer's local chain has lagged \
             behind the cosigned canonical chain)",
            last_valid_sequence, main_chain_tip_seq
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::LedgerRole;
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
            0,
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

    mod quorum_member_response_validation {
        use super::*;
        use crate::types::{
            quorum_member_response_digest, QuorumMemberResponse, QUORUM_MEMBER_RESPONSE_VERSION,
        };
        use crate::TlvEncode;
        use bitcoin::hashes::Hash;
        use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};

        fn build(
            secp: &Secp256k1<bitcoin::secp256k1::All>,
            member_sk: &[u8; 32],
        ) -> (Vec<u8>, [u8; 64], PublicKey) {
            let kp = Keypair::from_seckey_slice(secp, member_sk).unwrap();
            let member_pk = PublicKey::from_keypair(&kp);
            let op_pk =
                PublicKey::from_secret_key(secp, &SecretKey::from_slice(&[7u8; 32]).unwrap());
            let r = QuorumMemberResponse {
                response_version: QUORUM_MEMBER_RESPONSE_VERSION,
                member_pubkey: member_pk,
                operator_pubkey: op_pk,
                operator_ledger_id: "ab".repeat(32),
                chosen_ruleset: "legacy".to_string(),
                supported_rulesets: vec!["legacy".to_string()],
                member_ledger_id: "cd".repeat(32),
                min_fee_bps: Some(100),
                min_fee_fixed: None,
                max_fee_period: Some(2016),
                membership_until: Some(900_000),
                dispute_response_blocks: None,
                dispute_arm_blocks: None,
                service_response_blocks: None,
                max_transfer_timeout_blocks: None,
                max_descriptor_bytes: None,
                compensation_bps: Some(300),
                compensation_deposit_id: None,
                compensation_frequency_blocks: None,
            };
            let bytes = r.tlv_encode();
            let digest = quorum_member_response_digest(&bytes);
            let msg = bitcoin::secp256k1::Message::from_digest(digest);
            let sig = secp.sign_schnorr_no_aux_rand(&msg, &kp);
            let mut sigb = [0u8; 64];
            sigb.copy_from_slice(sig.as_ref());
            (bytes, sigb, member_pk)
        }

        #[test]
        fn legacy_event_with_no_blob_is_ok() {
            assert!(validate_quorum_add_member_blob(
                &test_pubkey(),
                "ab".repeat(32).as_str(),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .is_ok());
        }

        #[test]
        fn missing_signature_when_blob_present_rejects() {
            let secp = Secp256k1::new();
            let (bytes, _sig, member_pk) = build(&secp, &[1u8; 32]);
            let err = validate_quorum_add_member_blob(
                &member_pk,
                "cd".repeat(32).as_str(),
                Some(&bytes),
                None,
                Some(100),
                None,
                Some(2016),
                Some(900_000),
                None,
                None,
                None,
                None,
                None,
                Some(300),
                None,
                None,
            )
            .unwrap_err();
            assert!(err.contains("member_signature is missing"), "{}", err);
        }

        #[test]
        fn matching_blob_and_loose_fields_accepts() {
            let secp = Secp256k1::new();
            let (bytes, sig, member_pk) = build(&secp, &[1u8; 32]);
            let r = validate_quorum_add_member_blob(
                &member_pk,
                "cd".repeat(32).as_str(),
                Some(&bytes),
                Some(&sig),
                Some(100),
                None,
                Some(2016),
                Some(900_000),
                None,
                None,
                None,
                None,
                None,
                Some(300),
                None,
                None,
            );
            assert!(r.is_ok(), "{:?}", r);
        }

        #[test]
        fn mismatched_loose_field_rejects() {
            let secp = Secp256k1::new();
            let (bytes, sig, member_pk) = build(&secp, &[1u8; 32]);
            let err = validate_quorum_add_member_blob(
                &member_pk,
                "cd".repeat(32).as_str(),
                Some(&bytes),
                Some(&sig),
                Some(101), // operator-rewritten
                None,
                Some(2016),
                Some(900_000),
                None,
                None,
                None,
                None,
                None,
                Some(300),
                None,
                None,
            )
            .unwrap_err();
            assert!(err.contains("min_fee_bps mismatch"), "{}", err);
        }

        #[test]
        fn signature_under_wrong_key_rejects() {
            let secp = Secp256k1::new();
            let (bytes, _good_sig, member_pk) = build(&secp, &[1u8; 32]);
            // Sign with a different key.
            let (_bytes2, bad_sig, _other_pk) = build(&secp, &[2u8; 32]);
            let err = validate_quorum_add_member_blob(
                &member_pk,
                "cd".repeat(32).as_str(),
                Some(&bytes),
                Some(&bad_sig),
                Some(100),
                None,
                Some(2016),
                Some(900_000),
                None,
                None,
                None,
                None,
                None,
                Some(300),
                None,
                None,
            )
            .unwrap_err();
            assert!(err.contains("BIP-340 verify failed"), "{}", err);
        }

        #[test]
        fn pubkey_in_blob_must_match_outer_quorum_member() {
            let secp = Secp256k1::new();
            let (bytes, sig, _member_pk) = build(&secp, &[1u8; 32]);
            let other =
                PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[9u8; 32]).unwrap());
            let err = validate_quorum_add_member_blob(
                &other,
                "cd".repeat(32).as_str(),
                Some(&bytes),
                Some(&sig),
                Some(100),
                None,
                Some(2016),
                Some(900_000),
                None,
                None,
                None,
                None,
                None,
                Some(300),
                None,
                None,
            )
            .unwrap_err();
            assert!(
                err.contains("does not match outer quorum_member"),
                "{}",
                err
            );
        }

        #[test]
        fn member_ledger_id_in_blob_must_match_outer() {
            let secp = Secp256k1::new();
            let (bytes, sig, member_pk) = build(&secp, &[1u8; 32]);
            let err = validate_quorum_add_member_blob(
                &member_pk,
                "ee".repeat(32).as_str(), // different ledger
                Some(&bytes),
                Some(&sig),
                Some(100),
                None,
                Some(2016),
                Some(900_000),
                None,
                None,
                None,
                None,
                None,
                Some(300),
                None,
                None,
            )
            .unwrap_err();
            assert!(
                err.contains("does not match outer member_ledger_id"),
                "{}",
                err
            );

            // Reference Hash to silence unused-import warning under all
            // feature combos.
            let _ = bitcoin::hashes::sha256::Hash::hash(b"x").to_byte_array();
        }
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
            annualized_msats: 0,
            annualized_bps: 0,
            frequency_blocks: 0, // Invalid
        };
        assert!(validate_deposit_add(&ledger, new_pubkey, Some(&bad_fees)).is_err());
    }

    // test_validate_transfer_lock_* and test_validate_transfer_complete_*
    // deleted along with the validators they exercised. The same
    // failure cases are covered by `LedgerState::apply` (insufficient
    // balance, nonexistent deposit) and `check_conformance`
    // (ZeroAmount, MismatchedTransferId, InvalidWitness).

    #[test]
    fn test_validate_transfer_timeout_not_reached() {
        use crate::types::{compute_deposit_id, PendingTransfer};

        let mut ledger = create_test_ledger();

        let source_id = compute_deposit_id("pk(alice)");
        let dest_id = compute_deposit_id("pk(bob)");
        let transfer_id = [0xBBu8; 32];

        // Create pending transfer with high timeout
        let pending = PendingTransfer {
            transfer_id,
            nonce: [0x11u8; 32],
            source_deposit_id: source_id,
            destination_deposit_id: dest_id,
            amount: 10_000,
            fee: 100,
            completion_script: "sha256(cc)".to_string(),
            timeout_height: 1_000_000, // Very high timeout
        };
        ledger.state.pending_transfers.insert(transfer_id, pending);

        // Try to timeout at a lower block
        let result = validate_transfer_timeout(&ledger, &transfer_id, 500_000);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not reached"));
    }

    #[test]
    fn test_validate_transfer_timeout_reached() {
        use crate::types::{compute_deposit_id, PendingTransfer};

        let mut ledger = create_test_ledger();

        let source_id = compute_deposit_id("pk(alice)");
        let dest_id = compute_deposit_id("pk(bob)");
        let transfer_id = [0xCCu8; 32];

        // Create pending transfer
        let pending = PendingTransfer {
            transfer_id,
            nonce: [0x22u8; 32],
            source_deposit_id: source_id,
            destination_deposit_id: dest_id,
            amount: 10_000,
            fee: 100,
            completion_script: "sha256(dd)".to_string(),
            timeout_height: 800_000,
        };
        ledger.state.pending_transfers.insert(transfer_id, pending);

        // Timeout at or after the timeout height should succeed
        let result = validate_transfer_timeout(&ledger, &transfer_id, 800_000);
        assert!(result.is_ok());

        let result = validate_transfer_timeout(&ledger, &transfer_id, 900_000);
        assert!(result.is_ok());
    }

    // ─── validate_fee_minimum ──────────────────────────────────────────

    fn fee(annualized_msats: u64, bps: u16, period: u32) -> FeeStructure {
        FeeStructure {
            annualized_msats,
            annualized_bps: bps,
            frequency_blocks: period,
        }
    }

    #[test]
    fn fee_minimum_accepts_matching_period_above_floor() {
        // Operator: 50 bps + 2_500_000 msats/year, period=2016 blocks.
        // 52560/2016 = 26 periods/year → min_per_period = 96_153 msats.
        let result = validate_fee_minimum(&fee(2_500_000, 50, 2016), 50, 96_153, 2016);
        assert!(result.is_ok(), "{:?}", result);
    }

    #[test]
    fn fee_minimum_rejects_too_long_period() {
        // Period > 1 year would make periods_per_year=0 in the divisor
        // and (without the period check) zero-out the per-period floor.
        // Has to be rejected even when annualized_msats matches the
        // operator's expectation.
        let result = validate_fee_minimum(&fee(2_500_000, 50, 100_000), 50, 96_153, 2016);
        let err = result.unwrap_err();
        assert!(
            err.contains("period") && err.contains("doesn't match"),
            "want period mismatch, got: {}",
            err
        );
    }

    #[test]
    fn fee_minimum_rejects_too_short_period() {
        // period=1 → fees assessable every block → ledger growth attack.
        // Reject regardless of whether the per-period number happens to
        // pass the floor.
        let result = validate_fee_minimum(&fee(u64::MAX, 50, 1), 50, 96_153, 2016);
        assert!(result.unwrap_err().contains("doesn't match"));
    }

    #[test]
    fn fee_minimum_rejects_zero_period() {
        // Same idea — zero would divide-by-zero in the per-period math
        // before this commit; now caught by the period check.
        let result = validate_fee_minimum(&fee(2_500_000, 50, 0), 50, 96_153, 2016);
        assert!(result.unwrap_err().contains("doesn't match"));
    }

    #[test]
    fn fee_minimum_rejects_below_bps_floor() {
        let result = validate_fee_minimum(&fee(2_500_000, 10, 2016), 50, 96_153, 2016);
        assert!(result.unwrap_err().contains("annual fee"));
    }

    #[test]
    fn fee_minimum_rejects_below_fixed_floor() {
        // annualized 100_000 msats / 26 = 3_846 — below floor.
        let result = validate_fee_minimum(&fee(100_000, 50, 2016), 50, 96_153, 2016);
        assert!(result.unwrap_err().contains("fixed fee"));
    }

    mod dispute_enter_quorum_expired {
        use super::*;
        use std::collections::HashMap;

        /// Mock oracle backed by a hash → height map.
        struct MockOracle(HashMap<[u8; 32], u32>);
        impl deposits_protocol::fraud::BlockOracle for MockOracle {
            fn confirms(&self, h: &[u8; 32]) -> Option<u32> {
                self.0.get(h).copied()
            }
        }

        fn oracle_with(entries: &[([u8; 32], u32)]) -> MockOracle {
            MockOracle(entries.iter().copied().collect())
        }

        const HASH_A: [u8; 32] = [0xAA; 32];
        const HASH_B: [u8; 32] = [0xBB; 32];

        #[test]
        fn happy_path_passes() {
            let oracle = oracle_with(&[(HASH_A, 949_000)]);
            assert!(validate_dispute_enter_quorum_expired(
                &HASH_A, 949_000, 146, 948_254, 146, &oracle
            )
            .is_ok());
        }

        #[test]
        fn oracle_doesnt_know_the_hash() {
            let oracle = oracle_with(&[(HASH_A, 949_000)]);
            let err =
                validate_dispute_enter_quorum_expired(&HASH_B, 949_000, 146, 948_254, 146, &oracle)
                    .unwrap_err();
            assert!(err.contains("not in canonical chain"), "{}", err);
        }

        #[test]
        fn oracle_disagrees_with_asserted_height() {
            let oracle = oracle_with(&[(HASH_A, 949_000)]);
            let err =
                validate_dispute_enter_quorum_expired(&HASH_A, 949_999, 146, 948_254, 146, &oracle)
                    .unwrap_err();
            assert!(err.contains("oracle height 949000"), "{}", err);
            assert!(err.contains("asserted 949999"), "{}", err);
        }

        #[test]
        fn anchor_at_expiry_is_not_yet_past_deadline() {
            // anchor_block_height must STRICTLY exceed quorum_expiry.
            let oracle = oracle_with(&[(HASH_A, 948_254)]);
            let err =
                validate_dispute_enter_quorum_expired(&HASH_A, 948_254, 146, 948_254, 146, &oracle)
                    .unwrap_err();
            assert!(err.contains("does not exceed"), "{}", err);
        }

        #[test]
        fn anchor_before_expiry_rejected() {
            let oracle = oracle_with(&[(HASH_A, 948_000)]);
            let err =
                validate_dispute_enter_quorum_expired(&HASH_A, 948_000, 146, 948_254, 146, &oracle)
                    .unwrap_err();
            assert!(err.contains("does not exceed"), "{}", err);
        }

        #[test]
        fn stale_fork_point_rejected() {
            // last_valid_sequence < tip → forking from stale state.
            let oracle = oracle_with(&[(HASH_A, 949_000)]);
            let err =
                validate_dispute_enter_quorum_expired(&HASH_A, 949_000, 145, 948_254, 146, &oracle)
                    .unwrap_err();
            assert!(err.contains("stale state"), "{}", err);
            assert!(err.contains("145"), "{}", err);
            assert!(err.contains("146"), "{}", err);
        }

        #[test]
        fn future_fork_point_rejected_too() {
            // last_valid_sequence > tip is also nonsensical (can't fork
            // from an update we haven't seen).
            let oracle = oracle_with(&[(HASH_A, 949_000)]);
            let err =
                validate_dispute_enter_quorum_expired(&HASH_A, 949_000, 200, 948_254, 146, &oracle)
                    .unwrap_err();
            assert!(err.contains("stale state"), "{}", err);
        }
    }
}
