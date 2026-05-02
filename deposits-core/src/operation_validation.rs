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

/// Validate a deposit key rotation operation
///
/// Checks:
/// - Deposit exists
/// - Witness satisfies the current descriptor (proves ownership)
/// - New descriptor is valid
pub fn validate_deposit_key_rotate(
    ledger: &Ledger,
    deposit_id: &DepositId,
    new_descriptor: &str,
    witness: &DescriptorWitness,
) -> ValidationResult {
    // Check deposit exists
    let deposit = ledger
        .state
        .deposits
        .get(deposit_id)
        .ok_or_else(|| format!("Deposit with id {} does not exist", hex::encode(deposit_id)))?;

    // Verify witness satisfies the current descriptor
    // The message being signed is the new_descriptor hash (proving intent to rotate to it)
    let message_hash =
        bitcoin::hashes::sha256::Hash::hash(new_descriptor.as_bytes()).to_byte_array();

    match crate::descriptor::verify_witness(&deposit.descriptor, witness, &message_hash) {
        Ok(true) => {}
        Ok(false) => return Err("Witness does not satisfy current descriptor".to_string()),
        Err(e) => return Err(format!("Failed to verify witness: {:?}", e)),
    }

    // Basic validation of new descriptor (at minimum, should be non-empty)
    if new_descriptor.is_empty() {
        return Err("New descriptor cannot be empty".to_string());
    }

    Ok(())
}

/// Validate a payment lock operation by deposit_id with descriptor witness
///
/// Checks:
/// - Deposit exists
/// - Sufficient available balance
/// - Amount is positive
/// - Witness satisfies the deposit's descriptor
pub fn validate_payment_lock_by_id(
    ledger: &Ledger,
    deposit_id: &DepositId,
    amount: u64,
    payment_id: &[u8; 32],
    witness: &DescriptorWitness,
) -> ValidationResult {
    // Check deposit exists
    let deposit = ledger
        .state
        .deposits
        .get(deposit_id)
        .ok_or_else(|| format!("Deposit with id {} does not exist", hex::encode(deposit_id)))?;

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

    // Verify witness satisfies the deposit's descriptor
    match crate::signing::verify_invoice_lock_witness(
        &deposit.descriptor,
        deposit_id,
        payment_id,
        amount,
        witness,
    ) {
        Ok(true) => {}
        Ok(false) => return Err("Witness does not satisfy deposit descriptor".to_string()),
        Err(e) => return Err(format!("Failed to verify witness: {:?}", e)),
    }

    Ok(())
}

/// Validate an on-chain withdrawal lock operation with descriptor witness
///
/// Checks:
/// - Deposit exists
/// - Sufficient available balance (amount + fees)
/// - Amount is positive
/// - Witness satisfies the deposit's descriptor
pub fn validate_onchain_lock_by_id(
    ledger: &Ledger,
    deposit_id: &DepositId,
    amount: u64,
    fee_sats: u64,
    destination_address: &str,
    withdrawal_id: &[u8; 32],
    witness: &DescriptorWitness,
) -> ValidationResult {
    // Check deposit exists
    let deposit = ledger
        .state
        .deposits
        .get(deposit_id)
        .ok_or_else(|| format!("Deposit with id {} does not exist", hex::encode(deposit_id)))?;

    // Calculate total debit (amount + fees)
    let total_debit = amount.saturating_add(fee_sats);

    // Calculate available balance
    let available_balance = deposit.balance.saturating_sub(deposit.locked_balance);

    // Check sufficient balance
    if available_balance < total_debit {
        return Err(format!(
            "Insufficient available balance: {} < {} (amount) + {} (fee)",
            available_balance, amount, fee_sats
        ));
    }

    // Check amount is positive
    if amount == 0 {
        return Err("Withdrawal amount must be greater than zero".to_string());
    }

    // Check destination address is non-empty
    if destination_address.is_empty() {
        return Err("Destination address cannot be empty".to_string());
    }

    // Verify witness satisfies the deposit's descriptor
    // The signing message is: WITHDRAWAL:{withdrawal_id}:{deposit_id}:{address}:{amount}:{fee}
    let message_hash = crate::signature_utils::withdrawal_signing_message(
        withdrawal_id,
        deposit_id,
        destination_address,
        amount,
        fee_sats,
    );

    match crate::descriptor::verify_witness(&deposit.descriptor, witness, &message_hash) {
        Ok(true) => {}
        Ok(false) => return Err("Witness does not satisfy deposit descriptor".to_string()),
        Err(e) => return Err(format!("Failed to verify witness: {:?}", e)),
    }

    Ok(())
}

/// Validate a payment fulfill operation by deposit_id with descriptor witness
///
/// Checks:
/// - Amount is positive
/// - Preimage matches payment hash
pub fn validate_payment_fulfill_by_id(
    _deposit_id: &DepositId,
    amount: u64,
    payment_id: &[u8; 32],
    _witness: &DescriptorWitness,
    preimage: &[u8; 32],
) -> ValidationResult {
    // Check amount is positive
    if amount == 0 {
        return Err("Payment amount must be greater than zero".to_string());
    }

    // Verify preimage matches payment_id (which is the payment_hash)
    let computed_hash = sha256::Hash::hash(preimage);
    if computed_hash.as_byte_array() != payment_id {
        return Err("Preimage does not match payment hash".to_string());
    }

    // Note: Witness verification against descriptor is done at higher level

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

/// Validate a TransferLock operation.
///
/// Checks:
/// - Source deposit exists
/// - Source deposit has sufficient available balance
/// - Destination deposit exists (optional - could be created later)
/// - Witness satisfies source deposit's descriptor
/// - Amount and fee are positive
pub fn validate_transfer_lock(
    ledger: &Ledger,
    source_deposit_id: &DepositId,
    destination_deposit_id: &DepositId,
    nonce: &[u8; 32],
    amount: u64,
    fee: u64,
    completion_script: &str,
    timeout_height: u32,
    transfer_id: &[u8; 32],
    witness: &DescriptorWitness,
) -> ValidationResult {
    // Check source deposit exists
    let source_deposit = ledger
        .state
        .deposits
        .get(source_deposit_id)
        .ok_or_else(|| {
            format!(
                "Source deposit {} does not exist",
                hex::encode(source_deposit_id)
            )
        })?;

    // Check amount is positive
    if amount == 0 {
        return Err("Transfer amount must be greater than zero".to_string());
    }

    // Calculate total to lock (amount + fee)
    let total = amount.saturating_add(fee);

    // Check sufficient available balance
    let available = source_deposit
        .balance
        .saturating_sub(source_deposit.locked_balance);
    if available < total {
        return Err(format!(
            "Insufficient available balance: {} < {} (amount {} + fee {})",
            available, total, amount, fee
        ));
    }

    // Verify transfer_id matches the signing message
    let signing_message = crate::signature_utils::transfer_lock_signing_message(
        nonce,
        source_deposit_id,
        destination_deposit_id,
        amount,
        fee,
        completion_script,
        timeout_height,
    );
    let computed_id = crate::signature_utils::compute_transfer_id(&signing_message);
    if computed_id != *transfer_id {
        return Err("Transfer ID does not match signing message parameters".to_string());
    }

    // Verify witness satisfies source deposit's descriptor
    match crate::signing::verify_transfer_lock_witness(
        &source_deposit.descriptor,
        source_deposit_id,
        destination_deposit_id,
        nonce,
        amount,
        fee,
        completion_script,
        timeout_height,
        witness,
    ) {
        Ok(true) => {}
        Ok(false) => return Err("Witness does not satisfy source deposit descriptor".to_string()),
        Err(e) => return Err(format!("Failed to verify witness: {:?}", e)),
    }

    Ok(())
}

/// Validate a TransferComplete operation.
///
/// Checks:
/// - Pending transfer exists
/// - Script witness satisfies the completion_script
pub fn validate_transfer_complete(
    ledger: &Ledger,
    transfer_id: &[u8; 32],
    script_witness: &DescriptorWitness,
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

    // Verify script_witness satisfies completion_script
    match crate::signing::verify_transfer_complete_witness(
        &pending.completion_script,
        transfer_id,
        &pending.nonce,
        &pending.source_deposit_id,
        &pending.destination_deposit_id,
        pending.amount,
        pending.fee,
        pending.timeout_height,
        script_witness,
    ) {
        Ok(true) => {}
        Ok(false) => return Err("Witness does not satisfy completion script".to_string()),
        Err(e) => return Err(format!("Failed to verify completion witness: {:?}", e)),
    }

    Ok(())
}

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

    #[test]
    fn test_validate_transfer_lock_insufficient_balance() {
        use crate::types::{
            compute_deposit_id, Deposit, FeeStructure, PendingTransfer, TransferFeeSchedule,
        };

        let mut ledger = create_test_ledger();

        // Create source deposit with limited balance
        let source_id = compute_deposit_id("pk(alice)");
        let dest_id = compute_deposit_id("pk(bob)");

        let source_deposit = Deposit {
            deposit_id: source_id,
            descriptor: "pk(alice)".to_string(),
            balance: 10_000, // Only 10k
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

        let nonce = [0x42u8; 32];
        let amount = 50_000u64; // 50k - more than balance
        let fee = 500u64;
        let completion_script = "sha256(deadbeef)";
        let timeout_height = 900_000u32;

        let signing_msg = crate::signature_utils::transfer_lock_signing_message(
            &nonce,
            &source_id,
            &dest_id,
            amount,
            fee,
            completion_script,
            timeout_height,
        );
        let transfer_id = crate::signature_utils::compute_transfer_id(&signing_msg);

        let result = validate_transfer_lock(
            &ledger,
            &source_id,
            &dest_id,
            &nonce,
            amount,
            fee,
            completion_script,
            timeout_height,
            &transfer_id,
            &DescriptorWitness { stack: vec![] },
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Insufficient"));
    }

    #[test]
    fn test_validate_transfer_lock_nonexistent_source() {
        use crate::types::compute_deposit_id;

        let ledger = create_test_ledger();

        let source_id = compute_deposit_id("pk(nonexistent)");
        let dest_id = compute_deposit_id("pk(bob)");
        let nonce = [0x42u8; 32];

        let signing_msg = crate::signature_utils::transfer_lock_signing_message(
            &nonce,
            &source_id,
            &dest_id,
            1000,
            10,
            "sha256(aa)",
            100,
        );
        let transfer_id = crate::signature_utils::compute_transfer_id(&signing_msg);

        let result = validate_transfer_lock(
            &ledger,
            &source_id,
            &dest_id,
            &nonce,
            1000,
            10,
            "sha256(aa)",
            100,
            &transfer_id,
            &DescriptorWitness { stack: vec![] },
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("does not exist"));
    }

    #[test]
    fn test_validate_transfer_lock_zero_amount() {
        use crate::types::{compute_deposit_id, Deposit, FeeStructure, TransferFeeSchedule};

        let mut ledger = create_test_ledger();

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

        let nonce = [0x42u8; 32];
        let signing_msg = crate::signature_utils::transfer_lock_signing_message(
            &nonce,
            &source_id,
            &dest_id,
            0,
            100,
            "sha256(aa)",
            100,
        );
        let transfer_id = crate::signature_utils::compute_transfer_id(&signing_msg);

        let result = validate_transfer_lock(
            &ledger,
            &source_id,
            &dest_id,
            &nonce,
            0, // Zero amount
            100,
            "sha256(aa)",
            100,
            &transfer_id,
            &DescriptorWitness { stack: vec![] },
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("greater than zero"));
    }

    #[test]
    fn test_validate_transfer_complete_nonexistent() {
        let ledger = create_test_ledger();

        let transfer_id = [0xAAu8; 32];

        let result =
            validate_transfer_complete(&ledger, &transfer_id, &DescriptorWitness { stack: vec![] });

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("does not exist"));
    }

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
        FeeStructure { annualized_msats, annualized_bps: bps, frequency_blocks: period }
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
}
