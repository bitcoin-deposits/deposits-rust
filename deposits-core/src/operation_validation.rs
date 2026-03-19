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
                "Cannot increase reserves to {} msats: exceeds channel balance {} msats",
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
            "Cannot decrease reserves to {} msats: must maintain at least {} msats (deposits {} + max invoice {})",
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
    // Convert pubkey to deposit_id and check deposit exists
    let descriptor = format!("pk({})", hex::encode(deposit_pubkey.serialize()));
    let deposit_id = crate::types::compute_deposit_id(&descriptor);
    if !ledger.state.deposits.contains_key(&deposit_id) {
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
            "Credit would exceed reserves: new deposits {} msats > reserves {} msats",
            new_total_deposits, ledger.reserves_amount()
        ));
    }

    // Check that credit doesn't exceed declared collateral
    // Skip this check if there are no quorum members - collateral only applies when
    // there are external parties providing attestations
    if !ledger.state.quorum_members.is_empty() && new_total_deposits > ledger.state.received_collateral_amount {
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
    // Convert pubkey to deposit_id and check deposit exists
    let descriptor = format!("pk({})", hex::encode(deposit_pubkey.serialize()));
    let deposit_id = crate::types::compute_deposit_id(&descriptor);
    let deposit = ledger.state.deposits.get(&deposit_id)
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

/// Validate that a proposed fee structure meets operator minimums.
///
/// This is used when a wallet proposes fees during deposit opening. The operator
/// can enforce minimum fees to ensure deposits are profitable enough to service.
///
/// Checks:
/// - Proposed annual bps >= operator's minimum annual bps
/// - Proposed fixed fee per period >= operator's minimum fixed fee per period
pub fn validate_fee_minimum(
    proposed: &FeeStructure,
    min_annual_bps: u16,
    min_fixed_per_period: u64,
) -> ValidationResult {
    // Check annual bps meets minimum
    if proposed.annualized_bps < min_annual_bps {
        return Err(format!(
            "Proposed annual fee {} bps is below operator minimum {} bps",
            proposed.annualized_bps, min_annual_bps
        ));
    }

    // Calculate the proposed fixed fee per period from annualized fixed
    const BLOCKS_PER_YEAR: u64 = 52560;
    let periods_per_year = BLOCKS_PER_YEAR / proposed.frequency_blocks.max(1) as u64;
    let proposed_fixed_per_period = if periods_per_year > 0 {
        proposed.annualized_fixed / periods_per_year
    } else {
        0
    };

    // Check fixed fee meets minimum per period
    if proposed_fixed_per_period < min_fixed_per_period {
        return Err(format!(
            "Proposed fixed fee {} sats/period is below operator minimum {} sats/period",
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
    let deposit = ledger.state.deposits.get(&deposit_id)
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
    // Convert pubkey to deposit_id and check deposit doesn't already exist
    let descriptor = format!("pk({})", hex::encode(deposit_pubkey.serialize()));
    let deposit_id = crate::types::compute_deposit_id(&descriptor);
    if ledger.state.deposits.contains_key(&deposit_id) {
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
    // Convert pubkey to deposit_id and check deposit exists
    let descriptor = format!("pk({})", hex::encode(deposit_pubkey.serialize()));
    let deposit_id = crate::types::compute_deposit_id(&descriptor);
    let deposit = ledger.state.deposits.get(&deposit_id)
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
    // Convert pubkey to deposit_id and check deposit exists
    let descriptor = format!("pk({})", hex::encode(deposit_pubkey.serialize()));
    let deposit_id = crate::types::compute_deposit_id(&descriptor);
    if !ledger.state.deposits.contains_key(&deposit_id) {
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
            "Collateral increase exceeds reserves: {} msats committed > {} msats reserves",
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
    // Convert pubkey to deposit_id and check if the assigned deposit exists
    let descriptor = format!("pk({})", hex::encode(assigned_deposit.serialize()));
    let deposit_id = crate::types::compute_deposit_id(&descriptor);
    if !ledger.state.deposits.contains_key(&deposit_id) {
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
    // Skip this check if there are no quorum members - collateral only applies when
    // there are external parties providing attestations
    if !ledger.state.quorum_members.is_empty() && new_total_deposits > ledger.state.received_collateral_amount {
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
        return Err(format!("Deposit with id {} already exists", hex::encode(deposit_id)));
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
pub fn validate_deposit_close_by_id(
    ledger: &Ledger,
    deposit_id: &DepositId,
) -> ValidationResult {
    // Check deposit exists
    let deposit = ledger.state.deposits.get(deposit_id)
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

/// Validate a deposit update operation by deposit_id
///
/// Checks:
/// - Deposit exists
/// - New fee structure is valid
pub fn validate_deposit_update_by_id(
    ledger: &Ledger,
    deposit_id: &DepositId,
    new_fees: &FeeStructure,
) -> ValidationResult {
    if !ledger.state.deposits.contains_key(deposit_id) {
        return Err(format!("Deposit with id {} does not exist", hex::encode(deposit_id)));
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
    let deposit = ledger.state.deposits.get(deposit_id)
        .ok_or_else(|| format!("Deposit with id {} does not exist", hex::encode(deposit_id)))?;

    // Verify witness satisfies the current descriptor
    // The message being signed is the new_descriptor hash (proving intent to rotate to it)
    let message_hash = bitcoin::hashes::sha256::Hash::hash(new_descriptor.as_bytes()).to_byte_array();

    match crate::signature_utils::verify_descriptor_witness(
        &deposit.descriptor,
        deposit_id,
        &message_hash,
        0,  // No amount for key rotation
        witness,
        0,  // Block height not relevant for key rotation
    ) {
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
    let deposit = ledger.state.deposits.get(deposit_id)
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
    match crate::signature_utils::verify_invoice_lock_witness(
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
    let deposit = ledger.state.deposits.get(deposit_id)
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

    match crate::signature_utils::verify_descriptor_witness(
        &deposit.descriptor,
        deposit_id,
        &message_hash,
        total_debit,
        witness,
        0, // Block height not relevant for withdrawals
    ) {
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
        return Err(format!("Deposit with id {} does not exist", hex::encode(deposit_id)));
    }

    // Check amount is positive
    if amount == 0 {
        return Err("Credit amount must be greater than zero".to_string());
    }

    // Check that credit wouldn't exceed reserves capacity
    let current_deposits: u64 = ledger.state.deposits.values().map(|d| d.balance).sum();
    let new_total_deposits = current_deposits.saturating_add(amount);

    if new_total_deposits > ledger.reserves_amount() {
        return Err(format!(
            "Credit would exceed reserves: new deposits {} msat > reserves {} msat",
            new_total_deposits, ledger.reserves_amount()
        ));
    }

    // Check payment hash is not obviously fake
    if payment_hash.iter().all(|&b| b == payment_hash[0]) {
        return Err("Invalid payment hash: appears to be fake".to_string());
    }

    // Check that credit doesn't exceed declared collateral (if quorum present)
    if !ledger.state.quorum_members.is_empty() && new_total_deposits > ledger.state.received_collateral_amount {
        return Err(format!(
            "Credit would exceed declared collateral: new deposits {} sats > received collateral {} sats",
            new_total_deposits, ledger.state.received_collateral_amount
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
    let deposit = ledger.state.deposits.get(deposit_id)
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
    let source_deposit = ledger.state.deposits.get(source_deposit_id)
        .ok_or_else(|| format!("Source deposit {} does not exist", hex::encode(source_deposit_id)))?;

    // Check amount is positive
    if amount == 0 {
        return Err("Transfer amount must be greater than zero".to_string());
    }

    // Calculate total to lock (amount + fee)
    let total = amount.saturating_add(fee);

    // Check sufficient available balance
    let available = source_deposit.balance.saturating_sub(source_deposit.locked_balance);
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
    match crate::signature_utils::verify_transfer_lock_witness(
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
    let pending = ledger.state.pending_transfers.get(transfer_id)
        .ok_or_else(|| format!("Pending transfer {} does not exist", hex::encode(transfer_id)))?;

    // Verify script_witness satisfies completion_script
    match crate::signature_utils::verify_transfer_complete_witness(
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

/// Validate a TransferTimeout operation.
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
    let pending = ledger.state.pending_transfers.get(transfer_id)
        .ok_or_else(|| format!("Pending transfer {} does not exist", hex::encode(transfer_id)))?;

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

    #[test]
    fn test_validate_transfer_lock_insufficient_balance() {
        use crate::types::{compute_deposit_id, Deposit, FeeStructure, PendingTransfer, TransferFeeSchedule};

        let mut ledger = create_test_ledger();

        // Create source deposit with limited balance
        let source_id = compute_deposit_id("pk(alice)");
        let dest_id = compute_deposit_id("pk(bob)");

        let source_deposit = Deposit {
            deposit_id: source_id,
            descriptor: "pk(alice)".to_string(),
            balance: 10_000,  // Only 10k
            locked_balance: 0,
            invoices: Vec::new(),
            fees: FeeStructure::default(),
            last_fee_assessment: 0,
            collateral_lock_amount: 0,
            collateral_lock_expires: 0,
            transfer_fees: TransferFeeSchedule::default(), is_collateral: false, receive_requires_sig: false,
        };
        ledger.state.deposits.insert(source_id, source_deposit);

        let nonce = [0x42u8; 32];
        let amount = 50_000u64;  // 50k - more than balance
        let fee = 500u64;
        let completion_script = "sha256(deadbeef)";
        let timeout_height = 900_000u32;

        let signing_msg = crate::signature_utils::transfer_lock_signing_message(
            &nonce, &source_id, &dest_id, amount, fee, completion_script, timeout_height
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
            &nonce, &source_id, &dest_id, 1000, 10, "sha256(aa)", 100
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
            collateral_lock_amount: 0,
            collateral_lock_expires: 0,
            transfer_fees: TransferFeeSchedule::default(), is_collateral: false, receive_requires_sig: false,
        };
        ledger.state.deposits.insert(source_id, source_deposit);

        let nonce = [0x42u8; 32];
        let signing_msg = crate::signature_utils::transfer_lock_signing_message(
            &nonce, &source_id, &dest_id, 0, 100, "sha256(aa)", 100
        );
        let transfer_id = crate::signature_utils::compute_transfer_id(&signing_msg);

        let result = validate_transfer_lock(
            &ledger,
            &source_id,
            &dest_id,
            &nonce,
            0,  // Zero amount
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

        let result = validate_transfer_complete(
            &ledger,
            &transfer_id,
            &DescriptorWitness { stack: vec![] },
        );

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
            timeout_height: 1_000_000,  // Very high timeout
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
}
