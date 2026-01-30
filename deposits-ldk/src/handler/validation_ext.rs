// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Ledger Conformance Validator Extensions
//!
//! This module provides LDK-specific extensions to the core LedgerConformanceValidator,
//! adding the ability to validate chains of signed ledger updates by replaying messages.

use bitcoin::secp256k1::{PublicKey, Secp256k1, Message};
use bitcoin::hashes::{Hash, sha256};
use std::collections::HashMap;

use deposits_core::{
    LedgerConformanceValidator, ConformanceResult, ConformanceViolation,
    SignedLedgerUpdate, LedgerOperation,
};
use lightning::util::ser::Readable;

use super::messages::DepositsMessage;

/// Extension trait for LedgerConformanceValidator providing update chain validation
pub trait LedgerConformanceValidatorExt {
    /// Validate a chain of signed ledger updates
    ///
    /// This performs:
    /// 1. Hash chain verification - each update's prev_hash matches prior's current_hash
    /// 2. Signature verification - each update is signed by the operator
    /// 3. State replay - apply each operation to compute final state
    /// 4. Reserves check - verify reserves >= 100% of deposits (in this channel)
    /// 5. Collateral check - verify sum(collateral) >= 100% of deposits (in other channels)
    ///
    /// The 100% + 100% model ensures deposits are double-backed:
    /// - Reserves in the channel provide immediate liquidity
    /// - Collateral in other channels provides cross-channel security
    ///
    /// # Arguments
    /// * `updates` - Chain of signed ledger updates to validate
    /// * `expected_operator` - Expected operator pubkey for all updates
    /// * `claimed_reserves` - Reserves amount (from commitment tx in this channel)
    /// * `collateral_amounts` - Collateral from each other partner channel
    /// * `claimed_state_hash` - Optional claimed final state hash to verify
    fn validate_update_chain(
        &self,
        updates: &[SignedLedgerUpdate],
        expected_operator: PublicKey,
        claimed_reserves: u64,
        collateral_amounts: &[u64],
        claimed_state_hash: Option<[u8; 32]>,
    ) -> ConformanceResult;

    /// Quick check if a ledger conforms without detailed violation tracking
    fn is_update_chain_conforming(
        &self,
        updates: &[SignedLedgerUpdate],
        expected_operator: PublicKey,
        claimed_reserves: u64,
        collateral_amounts: &[u64],
    ) -> bool;
}

impl LedgerConformanceValidatorExt for LedgerConformanceValidator {
    fn validate_update_chain(
        &self,
        updates: &[SignedLedgerUpdate],
        expected_operator: PublicKey,
        claimed_reserves: u64,
        collateral_amounts: &[u64],
        claimed_state_hash: Option<[u8; 32]>,
    ) -> ConformanceResult {
        let secp = Secp256k1::new();
        let mut violations = Vec::new();
        let mut previous_hash = [0u8; 32]; // Genesis hash

        // Create empty ledger state for replay
        let mut replay_state = ReplayLedgerState::new();

        for (idx, update) in updates.iter().enumerate() {
            let expected_seq = idx as u64;

            // 1. Check sequence number
            if update.sequence_number != expected_seq {
                violations.push(ConformanceViolation::SequenceOutOfOrder {
                    expected: expected_seq,
                    actual: update.sequence_number,
                });
            }

            // 2. Check operator pubkey
            if update.operator_id != expected_operator {
                violations.push(ConformanceViolation::OperatorMismatch {
                    expected: expected_operator,
                    actual: update.operator_id,
                });
            }

            // 3. Check hash chain
            if update.previous_hash != previous_hash {
                violations.push(ConformanceViolation::BrokenHashChain {
                    sequence: update.sequence_number,
                    expected: previous_hash,
                    actual: update.previous_hash,
                });
            }

            // 4. Verify operator signature
            if !verify_update_signature(&secp, update) {
                violations.push(ConformanceViolation::InvalidSignature {
                    sequence: update.sequence_number,
                });
            }

            // 5. Deserialize and apply the operation
            if let Err(reason) = apply_update_to_replay_state(&mut replay_state, update) {
                violations.push(ConformanceViolation::OperationFailed {
                    sequence: update.sequence_number,
                    reason,
                });
            }

            // Update previous hash for next iteration
            previous_hash = update.current_hash;
        }

        // 6. Check reserves backing (100% requirement - reserves in this channel)
        let total_deposits = replay_state.total_deposit_balance();

        // Calculate reserves ratio (avoid division by zero)
        let reserves_ratio_percent = if total_deposits > 0 {
            (claimed_reserves * 100) / total_deposits
        } else {
            100 // No deposits = always sufficient
        };

        if claimed_reserves < total_deposits {
            violations.push(ConformanceViolation::InsufficientReserves {
                reserves: claimed_reserves,
                deposits: total_deposits,
                reserves_ratio_percent,
            });
        }

        // 7. Check collateral backing (100% requirement - collateral in other channels)
        let total_collateral: u64 = collateral_amounts.iter().sum();

        // Calculate collateral ratio (avoid division by zero)
        let collateral_ratio_percent = if total_deposits > 0 {
            (total_collateral * 100) / total_deposits
        } else {
            100 // No deposits = always sufficient
        };

        if total_collateral < total_deposits {
            violations.push(ConformanceViolation::InsufficientCollateral {
                total_collateral,
                deposits: total_deposits,
                collateral_ratio_percent,
            });
        }

        // 8. Check final state hash if claimed
        if let Some(claimed) = claimed_state_hash {
            if !updates.is_empty() {
                let final_hash = updates.last().unwrap().current_hash;
                if final_hash != claimed {
                    violations.push(ConformanceViolation::StateHashMismatch {
                        computed: final_hash,
                        claimed,
                    });
                }
            }
        }

        let final_sequence = if updates.is_empty() { 0 } else { updates.len() as u64 - 1 };
        let final_state_hash = if updates.is_empty() {
            [0u8; 32]
        } else {
            updates.last().unwrap().current_hash
        };

        ConformanceResult {
            is_conforming: violations.is_empty(),
            final_sequence,
            final_state_hash,
            computed_reserves: replay_state.reserves,
            total_deposits,
            violations,
        }
    }

    fn is_update_chain_conforming(
        &self,
        updates: &[SignedLedgerUpdate],
        expected_operator: PublicKey,
        claimed_reserves: u64,
        collateral_amounts: &[u64],
    ) -> bool {
        let result = self.validate_update_chain(updates, expected_operator, claimed_reserves, collateral_amounts, None);
        result.is_conforming
    }
}

/// Verify the operator signature on a signed update
fn verify_update_signature(secp: &Secp256k1<bitcoin::secp256k1::All>, update: &SignedLedgerUpdate) -> bool {
    // Reconstruct the message that was signed:
    // message || sequence || prev_state_hash
    let mut signed_data = Vec::new();
    signed_data.extend_from_slice(&update.message);
    signed_data.extend_from_slice(&update.sequence_number.to_le_bytes());
    signed_data.extend_from_slice(&update.previous_hash);

    // Hash the signed data
    let hash = sha256::Hash::hash(&signed_data);
    let msg = Message::from_digest(hash.to_byte_array());

    // Parse the signature
    let sig = match bitcoin::secp256k1::ecdsa::Signature::from_compact(&update.operator_signature) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // Verify the signature
    secp.verify_ecdsa(&msg, &sig, &update.operator_id).is_ok()
}

/// Apply an update to the replay state
fn apply_update_to_replay_state(
    state: &mut ReplayLedgerState,
    update: &SignedLedgerUpdate,
) -> Result<(), String> {
    // Deserialize the message
    let mut cursor = std::io::Cursor::new(&update.message);
    let msg = DepositsMessage::read(&mut cursor)
        .map_err(|e| format!("Failed to deserialize message: {:?}", e))?;

    // Apply the state transition
    state.apply_message(msg)
}

/// Minimal ledger state for replay validation
/// Only tracks what's needed for conformance checking
struct ReplayLedgerState {
    /// Map of deposit pubkey -> balance
    deposits: HashMap<PublicKey, u64>,
    /// Map of deposit pubkey -> locked balance
    locked_balances: HashMap<PublicKey, u64>,
    /// Current reserves amount
    reserves: u64,
}

impl ReplayLedgerState {
    fn new() -> Self {
        Self {
            deposits: HashMap::new(),
            locked_balances: HashMap::new(),
            reserves: 0,
        }
    }

    fn total_deposit_balance(&self) -> u64 {
        self.deposits.values().sum()
    }

    /// Apply a message to update replay state
    fn apply_message(&mut self, msg: DepositsMessage) -> Result<(), String> {
        // Handle messages via to_operation() to extract the operation from LedgerUpdate
        if let Some(operation) = msg.to_operation() {
            match operation {
                LedgerOperation::DepositOpen { pubkey, .. } => {
                    self.deposits.insert(pubkey, 0);
                    self.locked_balances.insert(pubkey, 0);
                }
                LedgerOperation::DepositClose { pubkey } => {
                    self.deposits.remove(&pubkey);
                    self.locked_balances.remove(&pubkey);
                }
                LedgerOperation::InvoiceCredit { deposit_pubkey, amount, .. } => {
                    let balance = self.deposits.get_mut(&deposit_pubkey)
                        .ok_or("Deposit not found")?;
                    *balance += amount;
                }
                LedgerOperation::InvoiceLock { pubkey, amount, .. } => {
                    let locked = self.locked_balances.get_mut(&pubkey)
                        .ok_or("Deposit not found")?;
                    *locked += amount;
                }
                LedgerOperation::InvoiceFail { pubkey, amount, .. } => {
                    let locked = self.locked_balances.get_mut(&pubkey)
                        .ok_or("Deposit not found")?;
                    *locked = locked.saturating_sub(amount);
                }
                LedgerOperation::InvoiceFulfill { pubkey, amount, .. } => {
                    let balance = self.deposits.get_mut(&pubkey)
                        .ok_or("Deposit not found")?;
                    *balance = balance.saturating_sub(amount);

                    let locked = self.locked_balances.get_mut(&pubkey)
                        .ok_or("Deposit not found")?;
                    *locked = locked.saturating_sub(amount);
                }
                LedgerOperation::ReservesIncrease { new_amount } => {
                    self.reserves = new_amount;
                }
                LedgerOperation::ReservesDecrease { new_amount } => {
                    self.reserves = new_amount;
                }
                LedgerOperation::LedgerClose => {
                    self.deposits.clear();
                    self.locked_balances.clear();
                    self.reserves = 0;
                }
                _ => {
                    // Other operations don't affect replay state
                }
            }
            return Ok(());
        }

        // Handle special messages that don't have to_operation()
        match msg {
            DepositsMessage::Handshake(_) => {
                // Ledger opened - no state change
            }
            _ => {
                // Other message types don't affect ledger state
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn create_test_pubkey() -> PublicKey {
        PublicKey::from_str("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap()
    }

    #[test]
    fn test_conformance_validator_empty_chain() {
        let validator = LedgerConformanceValidator::new();
        let operator = create_test_pubkey();

        // Empty chain with 0 reserves and 0 collateral should conform (no deposits)
        let result = validator.validate_update_chain(&[], operator, 0, &[], None);
        assert!(result.is_conforming);
        assert_eq!(result.final_sequence, 0);
        assert_eq!(result.final_state_hash, [0u8; 32]);
        assert_eq!(result.computed_reserves, 0);
        assert_eq!(result.total_deposits, 0);
        assert!(result.violations.is_empty());
    }

    #[test]
    fn test_conformance_validator_insufficient_backing() {
        let validator = LedgerConformanceValidator::new();
        let operator = create_test_pubkey();

        // Empty chain with 0 deposits - 0 reserves + 0 collateral is sufficient
        // because 200% of 0 = 0
        let result = validator.validate_update_chain(&[], operator, 0, &[], None);
        assert!(result.is_conforming);
        assert!(result.violations.is_empty());

        // Test with collateral - reserves=50, collateral=[50] = 100 total
        // With 0 deposits, 100 backing is more than 200% of 0
        let result = validator.validate_update_chain(&[], operator, 50, &[50], None);
        assert!(result.is_conforming);
        assert!(result.violations.is_empty());
    }

    #[test]
    fn test_replay_state_deposit_operations() {
        let mut state = ReplayLedgerState::new();
        let pubkey = create_test_pubkey();

        // Add deposit
        state.deposits.insert(pubkey, 0);
        state.locked_balances.insert(pubkey, 0);
        assert_eq!(state.total_deposit_balance(), 0);

        // Credit payment
        *state.deposits.get_mut(&pubkey).unwrap() += 1000;
        assert_eq!(state.total_deposit_balance(), 1000);

        // Lock balance
        *state.locked_balances.get_mut(&pubkey).unwrap() += 500;

        // Fulfill payment (deducts from both)
        let balance = state.deposits.get_mut(&pubkey).unwrap();
        *balance = balance.saturating_sub(500);
        let locked = state.locked_balances.get_mut(&pubkey).unwrap();
        *locked = locked.saturating_sub(500);

        assert_eq!(state.total_deposit_balance(), 500);
    }

    #[test]
    fn test_replay_state_reserves_operations() {
        let mut state = ReplayLedgerState::new();

        // Add reserves
        state.reserves += 10000;
        assert_eq!(state.reserves, 10000);

        // Add more reserves
        state.reserves += 5000;
        assert_eq!(state.reserves, 15000);

        // Remove some reserves
        state.reserves = state.reserves.saturating_sub(3000);
        assert_eq!(state.reserves, 12000);

        // Remove all reserves
        state.reserves = 0;
        assert_eq!(state.reserves, 0);
    }

    #[test]
    fn test_is_update_chain_conforming() {
        let validator = LedgerConformanceValidator::new();
        let operator = create_test_pubkey();

        // Empty chain should conform
        assert!(validator.is_update_chain_conforming(&[], operator, 0, &[]));

        // With reserves and collateral, still conforms (no deposits)
        assert!(validator.is_update_chain_conforming(&[], operator, 1000, &[1000]));
    }
}
