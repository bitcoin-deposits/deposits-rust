//! Message Validation for Bitcoin Deposits
//!
//! This module provides validation functions for all deposit protocol messages.
//! Each validation function checks message-specific constraints before the message
//! is accepted and applied to the ledger.
//!
//! The validation is split between:
//! - **deposits-core**: Pure validation logic via `ValidationContext` trait
//! - **deposits-ldk**: LDK-specific `MessageValidation` trait and context implementation
//!
//! `DepositsHandler` implements both `ValidationContext` (for core validation) and
//! `MessageValidation` (for message dispatch and LDK-specific checks).

use bitcoin::secp256k1::PublicKey;
use std::ops::Deref;
use std::sync::{Arc, RwLock};

use super::messages::DepositsMessage;
use lightning::util::logger::Logger as LdkLogger;
use deposits_core::{Ledger, ValidationContext};
use crate::wire::messages::ReservesRemoveOutputMsg;

use super::core::DepositsHandler;
use super::reserves_ops::ReservesOperations;

// ============================================================================
// ValidationContext Implementation
// ============================================================================

/// Implement ValidationContext from deposits-core for DepositsHandler
///
/// This allows the core validation functions to access ledger state and
/// channel information through a generic interface.
impl<L: Deref + Clone + Send + Sync> ValidationContext for DepositsHandler<L>
where
    L::Target: LdkLogger,
{
    fn get_ledger(&self, operator: &PublicKey, partner: &str) -> Option<Arc<RwLock<Ledger>>> {
        let ledgers = self.ledgers.lock().unwrap();
        ledgers.get(&(*operator, partner.to_string())).cloned()
    }

    fn our_node_id(&self) -> PublicKey {
        self.our_node_id
    }

    fn get_commitment_tx_reserves_amount(&self, operator: PublicKey) -> Option<u64> {
        // Use the ReservesOperations trait method
        ReservesOperations::get_commitment_tx_reserves_amount(self, operator)
    }
}

// ============================================================================
// MessageValidation Trait (LDK-specific)
// ============================================================================

/// Extension trait for message validation operations on DepositsHandler
pub trait MessageValidation {
    /// Validate a received ledger-modifying message and determine if it should be accepted or rejected
    fn validate_message(&self, message: &DepositsMessage, sender: PublicKey) -> Result<(), String>;

    /// Validate DepositOpen (add deposit) message
    fn validate_add_deposit(&self, msg: &crate::wire::messages::DepositOpenMsg, sender: PublicKey) -> Result<(), String>;

    /// Validate DepositClose (remove deposit) message
    fn validate_remove_deposit(&self, msg: &crate::wire::messages::DepositCloseMsg, sender: PublicKey) -> Result<(), String>;

    /// Validate DepositUpdate message
    fn validate_update_deposit(&self, msg: &crate::wire::messages::DepositUpdateMsg, sender: PublicKey) -> Result<(), String>;

    /// Validate SendingLockPayment message
    fn validate_sending_lock_payment(&self, msg: &crate::wire::messages::SendingLockPaymentMsg, sender: PublicKey) -> Result<(), String>;

    /// Validate SendingFulfillPayment message
    fn validate_sending_fulfill_payment(&self, msg: &crate::wire::messages::SendingFulfillPaymentMsg, sender: PublicKey) -> Result<(), String>;

    /// Validate SendingFailPayment message
    fn validate_sending_fail_payment(&self, msg: &crate::wire::messages::SendingFailPaymentMsg, sender: PublicKey) -> Result<(), String>;

    /// Validate ReceivingCreditPayment message
    fn validate_receiving_credit_payment(&self, msg: &crate::wire::messages::ReceivingCreditPaymentMsg, sender: PublicKey) -> Result<(), String>;

    /// Validate ReservesAddOutput message
    fn validate_reserves_add(&self, msg: &crate::wire::messages::ReservesAddOutputMsg, sender: PublicKey) -> Result<(), String>;

    /// Validate ReservesRemoveOutput message
    fn validate_reserves_remove(&self, msg: &ReservesRemoveOutputMsg, sender: PublicKey) -> Result<(), String>;

    /// Validate FeeCollect message
    fn validate_fee_collect(&self, msg: &crate::wire::messages::FeeCollectMsg, sender: PublicKey) -> Result<(), String>;

    /// Validate CollateralIncrease message
    fn validate_collateral_increase(&self, msg: &crate::wire::messages::CollateralIncreaseMsg, sender: PublicKey) -> Result<(), String>;

    /// Validate CollateralDecrease message
    /// CONSTRAINT: collateraldecrease doesn't happen in the same reporting period as collateralincrease
    fn validate_collateral_decrease(&self, msg: &crate::wire::messages::CollateralDecreaseMsg, sender: PublicKey) -> Result<(), String>;

    /// Validate ReservesIncrease message
    /// CONSTRAINT: reservesincrease doesn't increase reserves past channel balance
    fn validate_reserves_increase(&self, msg: &crate::wire::messages::ReservesIncreaseMsg, sender: PublicKey) -> Result<(), String>;

    /// Validate ReservesDecrease message
    /// CONSTRAINT: reservesdecrease doesn't fall below ledger requirement
    fn validate_reserves_decrease(&self, msg: &crate::wire::messages::ReservesDecreaseMsg, sender: PublicKey) -> Result<(), String>;

    /// Validate ReceivingCosignInvoice message
    /// Partner must verify the invoice amount doesn't exceed reserves/collateral BEFORE cosigning
    fn validate_receiving_cosign_invoice(&self, msg: &crate::wire::messages::ReceivingCosignInvoiceMsg, sender: PublicKey) -> Result<(), String>;

    /// Validate LedgerClose message
    /// Partner must verify the ledger exists and can be closed
    fn validate_ledger_close(&self, msg: &crate::wire::messages::LedgerCloseMsg, sender: PublicKey) -> Result<(), String>;
}

// NOTE: validate_operation function removed - LedgerUpdate validation now happens in the
// generic core handler (handle_ledger_update) which validates during append_operation.

impl<L: Deref + Clone + Send + Sync> MessageValidation for DepositsHandler<L>
where
    L::Target: LdkLogger,
{
    fn validate_message(&self, message: &DepositsMessage, sender: PublicKey) -> Result<(), String> {
        // Skip validation for LedgerUpdate messages - the generic handler validates during append
        // This avoids redundant validation since handle_ledger_update does full validation
        if matches!(message, DepositsMessage::LedgerUpdate(_)) {
            return Ok(());
        }

        // Handle special message types that need validation
        match message {
            // Invoice Cosigning Validation (V2: Coordination(CoordinationMsg::CosignInvoice))
            DepositsMessage::Coordination(deposits_core::messages::CoordinationMsg::CosignInvoice {
                amount, payment_hash, expires, assigned_deposit, ref invoice_id, ref bolt11_invoice, ..
            }) => {
                use crate::wire::messages::ReceivingCosignInvoiceMsg;
                self.validate_receiving_cosign_invoice(&ReceivingCosignInvoiceMsg {
                    amount: *amount,
                    payment_hash: *payment_hash,
                    expires: *expires,
                    assigned_deposit: *assigned_deposit,
                    invoice_id: invoice_id.clone(),
                    bolt11: bolt11_invoice.clone(),
                }, sender)
            },

            // Messages that don't require validation (non-ledger-modifying)
            // Note: LedgerUpdate is handled at the start of this function
            _ => Ok(()),
        }
    }

    fn validate_add_deposit(&self, msg: &crate::wire::messages::DepositOpenMsg, sender: PublicKey) -> Result<(), String> {
        deposits_core::validate_add_deposit_msg(self, msg, sender)
    }

    fn validate_remove_deposit(&self, msg: &crate::wire::messages::DepositCloseMsg, sender: PublicKey) -> Result<(), String> {
        deposits_core::validate_remove_deposit_msg(self, msg, sender)
    }

    fn validate_update_deposit(&self, msg: &crate::wire::messages::DepositUpdateMsg, sender: PublicKey) -> Result<(), String> {
        deposits_core::validate_update_deposit_msg(self, msg, sender)
    }

    fn validate_sending_lock_payment(&self, msg: &crate::wire::messages::SendingLockPaymentMsg, sender: PublicKey) -> Result<(), String> {
        deposits_core::validate_sending_lock_payment_msg(self, msg, sender)
    }

    fn validate_sending_fulfill_payment(&self, msg: &crate::wire::messages::SendingFulfillPaymentMsg, _sender: PublicKey) -> Result<(), String> {
        deposits_core::validate_sending_fulfill_payment_msg(msg)
    }

    fn validate_sending_fail_payment(&self, msg: &crate::wire::messages::SendingFailPaymentMsg, _sender: PublicKey) -> Result<(), String> {
        deposits_core::validate_sending_fail_payment_msg(msg)
    }

    fn validate_receiving_credit_payment(&self, msg: &crate::wire::messages::ReceivingCreditPaymentMsg, sender: PublicKey) -> Result<(), String> {
        deposits_core::validate_receiving_credit_payment_msg(self, msg, sender)
    }

    fn validate_reserves_add(&self, msg: &crate::wire::messages::ReservesAddOutputMsg, _sender: PublicKey) -> Result<(), String> {
        deposits_core::validate_reserves_add_output_msg(msg)
    }

    fn validate_reserves_remove(&self, msg: &ReservesRemoveOutputMsg, sender: PublicKey) -> Result<(), String> {
        deposits_core::validate_reserves_remove_msg(self, msg, sender)
    }

    fn validate_fee_collect(&self, msg: &crate::wire::messages::FeeCollectMsg, sender: PublicKey) -> Result<(), String> {
        deposits_core::validate_fee_collect_msg(self, msg, sender)
    }

    fn validate_collateral_increase(&self, msg: &crate::wire::messages::CollateralIncreaseMsg, sender: PublicKey) -> Result<(), String> {
        deposits_core::validate_collateral_increase_msg(self, msg, sender)
    }

    fn validate_collateral_decrease(&self, msg: &crate::wire::messages::CollateralDecreaseMsg, sender: PublicKey) -> Result<(), String> {
        deposits_core::validate_collateral_decrease_msg(self, msg, sender)
    }

    fn validate_reserves_increase(&self, msg: &crate::wire::messages::ReservesIncreaseMsg, sender: PublicKey) -> Result<(), String> {
        deposits_core::validate_reserves_increase_msg(self, msg, sender)
    }

    fn validate_reserves_decrease(&self, msg: &crate::wire::messages::ReservesDecreaseMsg, sender: PublicKey) -> Result<(), String> {
        deposits_core::validate_reserves_decrease_msg(self, msg, sender)
    }

    fn validate_receiving_cosign_invoice(&self, msg: &crate::wire::messages::ReceivingCosignInvoiceMsg, sender: PublicKey) -> Result<(), String> {
        deposits_core::validate_receiving_cosign_invoice_msg(self, msg, sender)
    }

    fn validate_ledger_close(&self, msg: &crate::wire::messages::LedgerCloseMsg, sender: PublicKey) -> Result<(), String> {
        deposits_core::validate_ledger_close_msg(self, msg, sender)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use std::sync::Arc;
    use lightning::util::test_utils::TestLogger;
    use crate::handler::messages as handler_messages;

    fn create_test_handler() -> DepositsHandler<Arc<TestLogger>> {
        let logger = Arc::new(TestLogger::new());
        DepositsHandler::new_for_testing(logger)
    }

    fn create_test_pubkey(seed: u8) -> PublicKey {
        let secp = Secp256k1::new();
        let mut bytes = [seed; 32];
        if seed == 0 { bytes[0] = 1; }
        let secret = SecretKey::from_slice(&bytes).unwrap();
        PublicKey::from_secret_key(&secp, &secret)
    }

    #[test]
    fn test_validate_add_deposit_no_ledger() {
        let handler = create_test_handler();
        let sender = create_test_pubkey(1);
        let msg = crate::wire::messages::DepositOpenMsg {
            pubkey: create_test_pubkey(2),
            fees: None,
            payment_hash: None,
            invoice: None,
            cosigner_guarantee_signature: None,
            reserves_id: create_test_pubkey(3).to_string(),
        };

        let result = handler.validate_add_deposit(&msg, sender);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No channel ledger found"));
    }

    #[test]
    fn test_validate_remove_deposit_no_ledger() {
        let handler = create_test_handler();
        let sender = create_test_pubkey(3);
        let msg = crate::wire::messages::DepositCloseMsg {
            pubkey: create_test_pubkey(4),
            reserves_id: create_test_pubkey(5).to_string(),
        };

        let result = handler.validate_remove_deposit(&msg, sender);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No channel ledger found"));
    }

    #[test]
    fn test_validate_update_deposit_no_ledger() {
        let handler = create_test_handler();
        let sender = create_test_pubkey(5);
        let msg = crate::wire::messages::DepositUpdateMsg {
            pubkey: create_test_pubkey(6),
            new_fees: deposits_core::FeeStructure::default(),
            reserves_id: create_test_pubkey(7).to_string(),
        };

        let result = handler.validate_update_deposit(&msg, sender);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No channel ledger found"));
    }

    #[test]
    fn test_validate_sending_lock_payment_no_ledger() {
        let handler = create_test_handler();
        let sender = create_test_pubkey(7);
        let msg = crate::wire::messages::SendingLockPaymentMsg {
            pubkey: create_test_pubkey(8),
            amount: 1000,
            payment_id: [0xAB; 32],
            sequence_number: 0,
            scriptpubkey_signature: [0; 64],
        };

        let result = handler.validate_sending_lock_payment(&msg, sender);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No channel ledger found"));
    }

    #[test]
    fn test_validate_sending_fulfill_payment_zero_amount() {
        let handler = create_test_handler();
        let sender = create_test_pubkey(9);
        let msg = crate::wire::messages::SendingFulfillPaymentMsg {
            pubkey: create_test_pubkey(10),
            amount: 0,
            payment_id: [0xAB; 32],
            sequence_number: 0,
            scriptpubkey_signature: [0; 64],
            preimage: [0; 32],
        };

        let result = handler.validate_sending_fulfill_payment(&msg, sender);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must be greater than zero"));
    }

    #[test]
    fn test_validate_sending_fail_payment_zero_amount() {
        let handler = create_test_handler();
        let sender = create_test_pubkey(11);
        let msg = crate::wire::messages::SendingFailPaymentMsg {
            pubkey: create_test_pubkey(12),
            amount: 0,
            payment_id: [0xAB; 32],
            sequence_number: 0,
        };

        let result = handler.validate_sending_fail_payment(&msg, sender);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must be greater than zero"));
    }

    #[test]
    fn test_validate_receiving_credit_payment_no_ledger() {
        let handler = create_test_handler();
        let sender = create_test_pubkey(13);
        let msg = crate::wire::messages::ReceivingCreditPaymentMsg {
            deposit_pubkey: create_test_pubkey(14),
            amount: 1000,
            payment_hash: [0xAB; 32],
            invoice_id: "test_invoice".to_string(),
            reserves_id: create_test_pubkey(15).to_string(),
            sequence_number: 0,
        };

        let result = handler.validate_receiving_credit_payment(&msg, sender);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No channel ledger found"));
    }

    #[test]
    fn test_validate_reserves_add_too_small() {
        let handler = create_test_handler();
        let sender = create_test_pubkey(16);
        let msg = crate::wire::messages::ReservesAddOutputMsg {
            initial_amount: 100, // Below minimum
            spend_to: create_test_pubkey(17),
            reserves_id: create_test_pubkey(18).to_string(),
            quorum_members: vec![],
        };

        let result = handler.validate_reserves_add(&msg, sender);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("below minimum"));
    }

    #[test]
    fn test_validate_reserves_add_too_large() {
        let handler = create_test_handler();
        let sender = create_test_pubkey(17);
        let msg = crate::wire::messages::ReservesAddOutputMsg {
            initial_amount: 1_000_000_000_000, // Above maximum
            spend_to: create_test_pubkey(18),
            reserves_id: create_test_pubkey(19).to_string(),
            quorum_members: vec![],
        };

        let result = handler.validate_reserves_add(&msg, sender);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("exceeds maximum"));
    }

    #[test]
    fn test_validate_reserves_remove_no_ledger() {
        let handler = create_test_handler();
        let sender = create_test_pubkey(18);
        let msg = crate::wire::messages::ReservesRemoveOutputMsg {
            remove_all: false,
            reserves_id: create_test_pubkey(19).to_string(),
        };

        let result = handler.validate_reserves_remove(&msg, sender);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No channel ledger found"));
    }

    #[test]
    fn test_validate_fee_collect_no_ledger() {
        let handler = create_test_handler();
        let sender = create_test_pubkey(19);
        let msg = crate::wire::messages::FeeCollectMsg {
            pubkey: create_test_pubkey(20),
            amount: 100,
            block_height: 100,
        };

        let result = handler.validate_fee_collect(&msg, sender);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No channel ledger found"));
    }

    #[test]
    fn test_validate_collateral_increase_no_ledger() {
        let handler = create_test_handler();
        let sender = create_test_pubkey(21);
        let msg = crate::wire::messages::CollateralIncreaseMsg {
            new_amount: 1000,
            reserves_id: create_test_pubkey(22).to_string(),
            block_height: 100,
        };

        let result = handler.validate_collateral_increase(&msg, sender);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No channel ledger found"));
    }

    // ========================================================================
    // CONSTRAINT: reservesincrease doesn't increase reserves past channel balance
    // ========================================================================

    #[test]
    fn test_validate_reserves_increase_must_actually_increase() {
        let handler = create_test_handler();
        let operator = create_test_pubkey(30);
        let partner = handler.our_node_id;

        // Set up ledger with operator having 5000 reserves
        {
            let mut ledgers = handler.ledgers.lock().unwrap();
            let mut ledger = deposits_core::Ledger::new(
                operator,
                partner.to_string(),
                deposits_core::LedgerRole::Partner,
                vec![],
                "tb1qtest".to_string(),
                0,
            );
            ledger.state.reserves.amount =5000;
            ledgers.insert((operator, partner.to_string()), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
        }

        // Try to "increase" to a lower amount - should fail
        let msg = crate::wire::messages::ReservesIncreaseMsg {
            new_amount: 4000, // Less than current 5000
            reserves_id: partner.to_string(),
        };

        let result = handler.validate_reserves_increase(&msg, operator);
        assert!(result.is_err(), "ReservesIncrease to lower amount should fail");
        assert!(result.unwrap_err().contains("must be greater than current"));
    }

    #[test]
    fn test_validate_reserves_increase_same_amount_fails() {
        let handler = create_test_handler();
        let operator = create_test_pubkey(31);
        let partner = handler.our_node_id;

        // Set up ledger with operator having 5000 reserves
        {
            let mut ledgers = handler.ledgers.lock().unwrap();
            let mut ledger = deposits_core::Ledger::new(
                operator,
                partner.to_string(),
                deposits_core::LedgerRole::Partner,
                vec![],
                "tb1qtest".to_string(),
                0,
            );
            ledger.state.reserves.amount =5000;
            ledgers.insert((operator, partner.to_string()), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
        }

        // Try to "increase" to the same amount - should fail
        let msg = crate::wire::messages::ReservesIncreaseMsg {
            new_amount: 5000, // Same as current
            reserves_id: partner.to_string(),
        };

        let result = handler.validate_reserves_increase(&msg, operator);
        assert!(result.is_err(), "ReservesIncrease to same amount should fail");
        assert!(result.unwrap_err().contains("must be greater than current"));
    }

    #[test]
    fn test_validate_reserves_increase_valid_increase() {
        let handler = create_test_handler();
        let operator = create_test_pubkey(32);
        let partner = handler.our_node_id;

        // Set up ledger with operator having 5000 reserves
        {
            let mut ledgers = handler.ledgers.lock().unwrap();
            let mut ledger = deposits_core::Ledger::new(
                operator,
                partner.to_string(),
                deposits_core::LedgerRole::Partner,
                vec![],
                "tb1qtest".to_string(),
                0,
            );
            ledger.state.reserves.amount =5000;
            ledgers.insert((operator, partner.to_string()), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
        }

        // Increase to higher amount - should succeed
        // (without channel_manager, the channel balance check is skipped)
        let msg = crate::wire::messages::ReservesIncreaseMsg {
            new_amount: 10000, // More than current 5000
            reserves_id: partner.to_string(),
        };

        let result = handler.validate_reserves_increase(&msg, operator);
        assert!(result.is_ok(), "Valid reserves increase should succeed: {:?}", result);
    }

    #[test]
    fn test_validate_reserves_increase_no_ledger_succeeds() {
        // Without a ledger, the "must increase" check is skipped
        // This is acceptable because we'd reject the message later when trying to apply it
        let handler = create_test_handler();
        let operator = create_test_pubkey(33);

        let msg = crate::wire::messages::ReservesIncreaseMsg {
            new_amount: 10000,
            reserves_id: create_test_pubkey(34).to_string(),
        };

        // Without a ledger, the validation passes (channel balance check also skipped)
        let result = handler.validate_reserves_increase(&msg, operator);
        assert!(result.is_ok(), "Without ledger, reserves increase validation passes");
    }

    // NOTE: Testing the channel balance constraint (msg.new_amount > channel_reserves)
    // requires a real ChannelManager, which is not available in unit tests.
    // The constraint is enforced in validate_reserves_increase() when channel_manager is set.
    // Integration tests should verify this constraint.

    // ========================================================================
    // Preimage Validation Tests (CONSTRAINT: sendingfulfillpayment includes preimage)
    // ========================================================================

    #[test]
    fn test_validate_sending_fulfill_payment_valid_preimage() {
        use bitcoin::hashes::{sha256, Hash};

        let handler = create_test_handler();
        let sender = create_test_pubkey(40);

        // Create a valid preimage and compute its hash
        let preimage = [42u8; 32];
        let payment_hash = sha256::Hash::hash(&preimage);

        let msg = crate::wire::messages::SendingFulfillPaymentMsg {
            pubkey: create_test_pubkey(41),
            amount: 1000,
            payment_id: *payment_hash.as_byte_array(),
            sequence_number: 0,
            scriptpubkey_signature: [0; 64], // Placeholder accepted during development
            preimage,
        };

        // Should succeed because preimage matches payment_id
        let result = handler.validate_sending_fulfill_payment(&msg, sender);
        assert!(result.is_ok(), "Valid preimage should pass validation: {:?}", result);
    }

    #[test]
    fn test_validate_sending_fulfill_payment_invalid_preimage() {
        use bitcoin::hashes::{sha256, Hash};

        let handler = create_test_handler();
        let sender = create_test_pubkey(42);

        // Create a preimage that doesn't match the payment_id
        let preimage = [42u8; 32];
        let wrong_payment_id = [0xAB; 32]; // Doesn't match SHA256(preimage)

        let msg = crate::wire::messages::SendingFulfillPaymentMsg {
            pubkey: create_test_pubkey(43),
            amount: 1000,
            payment_id: wrong_payment_id,
            sequence_number: 0,
            scriptpubkey_signature: [0; 64],
            preimage,
        };

        // Should fail because preimage doesn't match payment_id
        let result = handler.validate_sending_fulfill_payment(&msg, sender);
        assert!(result.is_err(), "Invalid preimage should fail validation");
        assert!(result.unwrap_err().contains("Preimage does not match payment hash"));
    }

    // ========================================================================
    // Signature Verification Helper Tests
    // ========================================================================
    // NOTE: These tests are commented out because verify_payment_signature
    // function was removed during V2 migration. Signature verification is now
    // handled via deposits_core::signature_utils.

    // #[test]
    // fn test_verify_payment_signature_placeholder_accepted() {
    //     // During development, placeholder signatures (all zeros) are accepted
    //     let pubkey = create_test_pubkey(50);
    //     let payment_id = [0xAB; 32];
    //     let amount = 1000u64;
    //     let placeholder_sig = [0u8; 64];
    //
    //     let result = super::DepositsHandler::<std::sync::Arc<lightning::util::test_utils::TestLogger>>::verify_payment_signature(
    //         &pubkey,
    //         &payment_id,
    //         amount,
    //         &placeholder_sig,
    //     );
    //     assert!(result, "Placeholder signature should be accepted during development");
    // }

    // #[test]
    // fn test_verify_payment_signature_invalid_rejected() {
    //     // Non-zero invalid signatures should be rejected
    //     let pubkey = create_test_pubkey(51);
    //     let payment_id = [0xAB; 32];
    //     let amount = 1000u64;
    //     let invalid_sig = [0xFF; 64]; // Invalid signature (not all zeros)
    //
    //     let result = super::DepositsHandler::<std::sync::Arc<lightning::util::test_utils::TestLogger>>::verify_payment_signature(
    //         &pubkey,
    //         &payment_id,
    //         amount,
    //         &invalid_sig,
    //     );
    //     assert!(!result, "Invalid signature should be rejected");
    // }

    // ========================================================================
    // CONSTRAINT: collateraldecrease doesn't happen in same period as collateralincrease
    // ========================================================================

    #[test]
    fn test_validate_collateral_decrease_too_soon_after_increase() {
        let handler = create_test_handler();
        let operator = create_test_pubkey(60);
        let partner = handler.our_node_id;

        // Set up ledger with collateral and a recent increase at block 100
        {
            let mut ledgers = handler.ledgers.lock().unwrap();
            let mut ledger = deposits_core::Ledger::new(
                operator,
                partner.to_string(),
                deposits_core::LedgerRole::Partner,
                vec![],
                "tb1qtest".to_string(),
                0,
            );
            ledger.state.collateral_amount = 5000;
            ledger.state.last_collateral_increase_block = Some(100);
            ledgers.insert((operator, partner.to_string()), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
        }

        // Try to decrease at block 150 (within 144-block period)
        let msg = crate::wire::messages::CollateralDecreaseMsg {
            new_amount: 3000,
            reserves_id: partner.to_string(),
            block_height: 150,
        };

        let result = handler.validate_collateral_decrease(&msg, operator);
        assert!(result.is_err(), "Decrease too soon after increase should fail");
        assert!(result.unwrap_err().contains("too soon after increase"));
    }

    #[test]
    fn test_validate_collateral_decrease_after_reporting_period() {
        let handler = create_test_handler();
        let operator = create_test_pubkey(61);
        let partner = handler.our_node_id;

        // Set up ledger with collateral and an increase at block 100
        {
            let mut ledgers = handler.ledgers.lock().unwrap();
            let mut ledger = deposits_core::Ledger::new(
                operator,
                partner.to_string(),
                deposits_core::LedgerRole::Partner,
                vec![],
                "tb1qtest".to_string(),
                0,
            );
            ledger.state.collateral_amount = 5000;
            ledger.state.last_collateral_increase_block = Some(100);
            ledgers.insert((operator, partner.to_string()), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
        }

        // Decrease at block 250 (after 144-block period: 100 + 144 = 244)
        let msg = crate::wire::messages::CollateralDecreaseMsg {
            new_amount: 3000,
            reserves_id: partner.to_string(),
            block_height: 250,
        };

        let result = handler.validate_collateral_decrease(&msg, operator);
        assert!(result.is_ok(), "Decrease after reporting period should succeed: {:?}", result);
    }

    #[test]
    fn test_validate_collateral_decrease_no_prior_increase() {
        let handler = create_test_handler();
        let operator = create_test_pubkey(62);
        let partner = handler.our_node_id;

        // Set up ledger with collateral but no prior increase recorded
        {
            let mut ledgers = handler.ledgers.lock().unwrap();
            let mut ledger = deposits_core::Ledger::new(
                operator,
                partner.to_string(),
                deposits_core::LedgerRole::Partner,
                vec![],
                "tb1qtest".to_string(),
                0,
            );
            ledger.state.collateral_amount = 5000;
            ledger.state.last_collateral_increase_block = None; // No prior increase
            ledgers.insert((operator, partner.to_string()), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
        }

        // Decrease should work since no prior increase to wait for
        let msg = crate::wire::messages::CollateralDecreaseMsg {
            new_amount: 3000,
            reserves_id: partner.to_string(),
            block_height: 100,
        };

        let result = handler.validate_collateral_decrease(&msg, operator);
        assert!(result.is_ok(), "Decrease with no prior increase should succeed: {:?}", result);
    }

    #[test]
    fn test_validate_collateral_decrease_must_decrease() {
        let handler = create_test_handler();
        let operator = create_test_pubkey(63);
        let partner = handler.our_node_id;

        // Set up ledger with collateral
        {
            let mut ledgers = handler.ledgers.lock().unwrap();
            let mut ledger = deposits_core::Ledger::new(
                operator,
                partner.to_string(),
                deposits_core::LedgerRole::Partner,
                vec![],
                "tb1qtest".to_string(),
                0,
            );
            ledger.state.collateral_amount = 5000;
            ledger.state.last_collateral_increase_block = None;
            ledgers.insert((operator, partner.to_string()), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
        }

        // Try to "decrease" to a higher value
        let msg = crate::wire::messages::CollateralDecreaseMsg {
            new_amount: 6000,
            reserves_id: partner.to_string(),
            block_height: 100,
        };

        let result = handler.validate_collateral_decrease(&msg, operator);
        assert!(result.is_err(), "Decrease to higher value should fail");
        assert!(result.unwrap_err().contains("is not less than current"));
    }

    // ==================== ReservesDecrease Validation Tests ====================

    #[test]
    fn test_validate_reserves_decrease_no_ledger() {
        let handler = create_test_handler();
        let sender = create_test_pubkey(200);
        let partner = create_test_pubkey(201);

        let msg = crate::wire::messages::ReservesDecreaseMsg {
            new_amount: 50_000,
            reserves_id: partner.to_string(),
        };

        let result = handler.validate_reserves_decrease(&msg, sender);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No channel ledger"));
    }

    #[test]
    fn test_validate_reserves_decrease_must_decrease() {
        let handler = create_test_handler();
        let operator = create_test_pubkey(210);
        let partner = handler.our_node_id;

        // Set up ledger with 100k reserves
        {
            let mut ledgers = handler.ledgers.lock().unwrap();
            let mut ledger = deposits_core::Ledger::new(
                operator,
                partner.to_string(),
                deposits_core::LedgerRole::Partner,
                vec![],
                "tb1qtest".to_string(),
                0,
            );
            ledger.state.reserves.amount =100_000;
            ledgers.insert((operator, partner.to_string()), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
        }

        // Try to "decrease" to same value
        let msg = crate::wire::messages::ReservesDecreaseMsg {
            new_amount: 100_000,
            reserves_id: partner.to_string(),
        };

        let result = handler.validate_reserves_decrease(&msg, operator);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must be less than current"));
    }

    #[test]
    fn test_validate_reserves_decrease_to_higher_fails() {
        let handler = create_test_handler();
        let operator = create_test_pubkey(220);
        let partner = handler.our_node_id;

        // Set up ledger with 100k reserves
        {
            let mut ledgers = handler.ledgers.lock().unwrap();
            let mut ledger = deposits_core::Ledger::new(
                operator,
                partner.to_string(),
                deposits_core::LedgerRole::Partner,
                vec![],
                "tb1qtest".to_string(),
                0,
            );
            ledger.state.reserves.amount =100_000;
            ledgers.insert((operator, partner.to_string()), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
        }

        // Try to "decrease" to higher value
        let msg = crate::wire::messages::ReservesDecreaseMsg {
            new_amount: 150_000,
            reserves_id: partner.to_string(),
        };

        let result = handler.validate_reserves_decrease(&msg, operator);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must be less than current"));
    }

    #[test]
    fn test_validate_reserves_decrease_below_requirement_fails() {
        let handler = create_test_handler();
        let operator = create_test_pubkey(230);
        let partner = handler.our_node_id;
        let deposit_pubkey = create_test_pubkey(231);

        // Set up ledger with deposits requiring reserves
        {
            let mut ledgers = handler.ledgers.lock().unwrap();
            let mut ledger = deposits_core::Ledger::new(
                operator,
                partner.to_string(),
                deposits_core::LedgerRole::Partner,
                vec![],
                "tb1qtest".to_string(),
                0,
            );
            ledger.state.reserves.amount =100_000;

            // Add a deposit with 80k balance - this requires reserves backing
            let mut deposit = deposits_core::Deposit::new(deposit_pubkey, None);
            deposit.balance = 80_000;
            ledger.state.deposits.insert(deposit_pubkey, deposit);

            ledgers.insert((operator, partner.to_string()), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
        }

        // Try to decrease reserves below what's required to back deposits
        let msg = crate::wire::messages::ReservesDecreaseMsg {
            new_amount: 50_000, // Less than the 80k deposit balance
            reserves_id: partner.to_string(),
        };

        let result = handler.validate_reserves_decrease(&msg, operator);
        assert!(result.is_err(), "Should fail when decrease falls below requirement");
        assert!(result.unwrap_err().contains("must maintain at least"));
    }

    #[test]
    fn test_validate_reserves_decrease_valid() {
        let handler = create_test_handler();
        let operator = create_test_pubkey(240);
        let partner = handler.our_node_id;
        let deposit_pubkey = create_test_pubkey(241);

        // Set up ledger with deposits
        {
            let mut ledgers = handler.ledgers.lock().unwrap();
            let mut ledger = deposits_core::Ledger::new(
                operator,
                partner.to_string(),
                deposits_core::LedgerRole::Partner,
                vec![],
                "tb1qtest".to_string(),
                0,
            );
            ledger.state.reserves.amount =100_000;

            // Add a deposit with 50k balance
            let mut deposit = deposits_core::Deposit::new(deposit_pubkey, None);
            deposit.balance = 50_000;
            ledger.state.deposits.insert(deposit_pubkey, deposit);

            ledgers.insert((operator, partner.to_string()), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
        }

        // Decrease reserves to 60k - still above the 50k deposit requirement
        let msg = crate::wire::messages::ReservesDecreaseMsg {
            new_amount: 60_000,
            reserves_id: partner.to_string(),
        };

        let result = handler.validate_reserves_decrease(&msg, operator);
        assert!(result.is_ok(), "Valid decrease should succeed: {:?}", result);
    }

    #[test]
    fn test_validate_reserves_decrease_to_exact_requirement() {
        let handler = create_test_handler();
        let operator = create_test_pubkey(250);
        let partner = handler.our_node_id;
        let deposit_pubkey = create_test_pubkey(251);

        // Set up ledger with deposits
        {
            let mut ledgers = handler.ledgers.lock().unwrap();
            let mut ledger = deposits_core::Ledger::new(
                operator,
                partner.to_string(),
                deposits_core::LedgerRole::Partner,
                vec![],
                "tb1qtest".to_string(),
                0,
            );
            ledger.state.reserves.amount =100_000;

            // Add a deposit with 50k balance
            let mut deposit = deposits_core::Deposit::new(deposit_pubkey, None);
            deposit.balance = 50_000;
            ledger.state.deposits.insert(deposit_pubkey, deposit);

            ledgers.insert((operator, partner.to_string()), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
        }

        // Decrease reserves to exactly the requirement (50k)
        let msg = crate::wire::messages::ReservesDecreaseMsg {
            new_amount: 50_000,
            reserves_id: partner.to_string(),
        };

        let result = handler.validate_reserves_decrease(&msg, operator);
        assert!(result.is_ok(), "Decrease to exact requirement should succeed: {:?}", result);
    }

    #[test]
    fn test_validate_reserves_decrease_no_deposits() {
        let handler = create_test_handler();
        let operator = create_test_pubkey(160); // Keep in u8 range
        let partner = handler.our_node_id;

        // Set up ledger with reserves but no deposits
        {
            let mut ledgers = handler.ledgers.lock().unwrap();
            let mut ledger = deposits_core::Ledger::new(
                operator,
                partner.to_string(),
                deposits_core::LedgerRole::Partner,
                vec![],
                "tb1qtest".to_string(),
                0,
            );
            ledger.state.reserves.amount =100_000;
            // No deposits added

            ledgers.insert((operator, partner.to_string()), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
        }

        // Decrease reserves to very low amount - should work since no deposits
        let msg = crate::wire::messages::ReservesDecreaseMsg {
            new_amount: 1_000,
            reserves_id: partner.to_string(),
        };

        let result = handler.validate_reserves_decrease(&msg, operator);
        assert!(result.is_ok(), "Decrease with no deposits should succeed: {:?}", result);
    }

    // ==================== ReceivingCosignInvoice Validation Tests ====================

    #[test]
    fn test_validate_cosign_invoice_no_ledger() {
        let handler = create_test_handler();
        let sender = create_test_pubkey(170);

        let msg = crate::wire::messages::ReceivingCosignInvoiceMsg {
            amount: 10_000,
            payment_hash: [0xAB; 32],
            expires: 1000000,
            assigned_deposit: create_test_pubkey(171),
            invoice_id: "test_invoice".to_string(),
            bolt11: "lnbc1...".to_string(),
        };

        let result = handler.validate_receiving_cosign_invoice(&msg, sender);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No channel ledger"));
    }

    #[test]
    fn test_validate_cosign_invoice_deposit_not_found() {
        let handler = create_test_handler();
        let operator = create_test_pubkey(172);
        let partner = handler.our_node_id;

        // Set up ledger without the deposit
        {
            let mut ledgers = handler.ledgers.lock().unwrap();
            let ledger = deposits_core::Ledger::new(
                operator,
                partner.to_string(),
                deposits_core::LedgerRole::Partner,
                vec![],
                "tb1qtest".to_string(),
                0,
            );
            ledgers.insert((operator, partner.to_string()), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
        }

        let msg = crate::wire::messages::ReceivingCosignInvoiceMsg {
            amount: 10_000,
            payment_hash: [0xAB; 32],
            expires: 1000000,
            assigned_deposit: create_test_pubkey(173), // Doesn't exist
            invoice_id: "test_invoice".to_string(),
            bolt11: "lnbc1...".to_string(),
        };

        let result = handler.validate_receiving_cosign_invoice(&msg, operator);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("does not exist"));
    }

    #[test]
    fn test_validate_cosign_invoice_zero_amount() {
        let handler = create_test_handler();
        let operator = create_test_pubkey(174);
        let partner = handler.our_node_id;
        let deposit_pubkey = create_test_pubkey(175);

        // Set up ledger with deposit
        {
            let mut ledgers = handler.ledgers.lock().unwrap();
            let mut ledger = deposits_core::Ledger::new(
                operator,
                partner.to_string(),
                deposits_core::LedgerRole::Partner,
                vec![],
                "tb1qtest".to_string(),
                0,
            );
            ledger.state.reserves.amount =100_000;
            ledger.state.received_collateral_amount = 100_000;
            let deposit = deposits_core::Deposit::new(deposit_pubkey, None);
            ledger.state.deposits.insert(deposit_pubkey, deposit);
            ledgers.insert((operator, partner.to_string()), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
        }

        let msg = crate::wire::messages::ReceivingCosignInvoiceMsg {
            amount: 0, // Zero amount
            payment_hash: [0xAB; 32],
            expires: 1000000,
            assigned_deposit: deposit_pubkey,
            invoice_id: "test_invoice".to_string(),
            bolt11: "lnbc1...".to_string(),
        };

        let result = handler.validate_receiving_cosign_invoice(&msg, operator);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must be greater than zero"));
    }

    #[test]
    fn test_validate_cosign_invoice_exceeds_reserves() {
        let handler = create_test_handler();
        let operator = create_test_pubkey(176);
        let partner = handler.our_node_id;
        let deposit_pubkey = create_test_pubkey(177);

        // Set up ledger with limited reserves
        {
            let mut ledgers = handler.ledgers.lock().unwrap();
            let mut ledger = deposits_core::Ledger::new(
                operator,
                partner.to_string(),
                deposits_core::LedgerRole::Partner,
                vec![],
                "tb1qtest".to_string(),
                0,
            );
            ledger.state.reserves.amount =50_000; // Only 50k reserves
            ledger.state.received_collateral_amount = 100_000; // Plenty of collateral
            let mut deposit = deposits_core::Deposit::new(deposit_pubkey, None);
            deposit.balance = 30_000; // Already has 30k
            ledger.state.deposits.insert(deposit_pubkey, deposit);
            ledgers.insert((operator, partner.to_string()), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
        }

        // Try to cosign invoice for 25k - would push total to 55k, exceeding 50k reserves
        // Use a payment hash that doesn't look fake (not all same bytes)
        let mut payment_hash = [0u8; 32];
        for i in 0..32 {
            payment_hash[i] = (i as u8).wrapping_add(0xAB);
        }
        let msg = crate::wire::messages::ReceivingCosignInvoiceMsg {
            amount: 25_000,
            payment_hash,
            expires: 1000000,
            assigned_deposit: deposit_pubkey,
            invoice_id: "test_invoice".to_string(),
            bolt11: "lnbc1...".to_string(),
        };

        let result = handler.validate_receiving_cosign_invoice(&msg, operator);
        assert!(result.is_err(), "Should reject when cosigning would exceed reserves");
        assert!(result.unwrap_err().contains("would exceed reserves"));
    }

    #[test]
    fn test_validate_cosign_invoice_exceeds_collateral() {
        let handler = create_test_handler();
        let operator = create_test_pubkey(178);
        let partner = handler.our_node_id;
        let deposit_pubkey = create_test_pubkey(179);

        // Set up ledger with plenty of reserves but limited collateral
        {
            let mut ledgers = handler.ledgers.lock().unwrap();
            let mut ledger = deposits_core::Ledger::new(
                operator,
                partner.to_string(),
                deposits_core::LedgerRole::Partner,
                vec![],
                "tb1qtest".to_string(),
                0,
            );
            ledger.state.reserves.amount =100_000; // Plenty of reserves
            ledger.state.received_collateral_amount = 50_000; // Only 50k collateral
            let mut deposit = deposits_core::Deposit::new(deposit_pubkey, None);
            deposit.balance = 30_000;
            ledger.state.deposits.insert(deposit_pubkey, deposit);
            ledgers.insert((operator, partner.to_string()), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
        }

        // Try to cosign invoice for 25k - would push total to 55k, exceeding 50k collateral
        // Use a payment hash that doesn't look fake (not all same bytes)
        let mut payment_hash = [0u8; 32];
        for i in 0..32 {
            payment_hash[i] = (i as u8).wrapping_add(0xCD);
        }
        let msg = crate::wire::messages::ReceivingCosignInvoiceMsg {
            amount: 25_000,
            payment_hash,
            expires: 1000000,
            assigned_deposit: deposit_pubkey,
            invoice_id: "test_invoice".to_string(),
            bolt11: "lnbc1...".to_string(),
        };

        let result = handler.validate_receiving_cosign_invoice(&msg, operator);
        assert!(result.is_err(), "Should reject when cosigning would exceed collateral");
        assert!(result.unwrap_err().contains("would exceed collateral"));
    }

    #[test]
    fn test_validate_cosign_invoice_empty_invoice_id() {
        let handler = create_test_handler();
        let operator = create_test_pubkey(180);
        let partner = handler.our_node_id;
        let deposit_pubkey = create_test_pubkey(181);

        // Set up ledger with deposit
        {
            let mut ledgers = handler.ledgers.lock().unwrap();
            let mut ledger = deposits_core::Ledger::new(
                operator,
                partner.to_string(),
                deposits_core::LedgerRole::Partner,
                vec![],
                "tb1qtest".to_string(),
                0,
            );
            ledger.state.reserves.amount =100_000;
            ledger.state.received_collateral_amount = 100_000;
            let deposit = deposits_core::Deposit::new(deposit_pubkey, None);
            ledger.state.deposits.insert(deposit_pubkey, deposit);
            ledgers.insert((operator, partner.to_string()), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
        }

        let msg = crate::wire::messages::ReceivingCosignInvoiceMsg {
            amount: 10_000,
            payment_hash: [0xAB; 32],
            expires: 1000000,
            assigned_deposit: deposit_pubkey,
            invoice_id: "".to_string(), // Empty ID
            bolt11: "lnbc1...".to_string(),
        };

        let result = handler.validate_receiving_cosign_invoice(&msg, operator);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("cannot be empty"));
    }

    #[test]
    fn test_validate_cosign_invoice_fake_payment_hash() {
        let handler = create_test_handler();
        let operator = create_test_pubkey(182);
        let partner = handler.our_node_id;
        let deposit_pubkey = create_test_pubkey(183);

        // Set up ledger with deposit
        {
            let mut ledgers = handler.ledgers.lock().unwrap();
            let mut ledger = deposits_core::Ledger::new(
                operator,
                partner.to_string(),
                deposits_core::LedgerRole::Partner,
                vec![],
                "tb1qtest".to_string(),
                0,
            );
            ledger.state.reserves.amount =100_000;
            ledger.state.received_collateral_amount = 100_000;
            let deposit = deposits_core::Deposit::new(deposit_pubkey, None);
            ledger.state.deposits.insert(deposit_pubkey, deposit);
            ledgers.insert((operator, partner.to_string()), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
        }

        let msg = crate::wire::messages::ReceivingCosignInvoiceMsg {
            amount: 10_000,
            payment_hash: [0x00; 32], // All zeros - fake
            expires: 1000000,
            assigned_deposit: deposit_pubkey,
            invoice_id: "test_invoice".to_string(),
            bolt11: "lnbc1...".to_string(),
        };

        let result = handler.validate_receiving_cosign_invoice(&msg, operator);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("appears to be fake"));
    }

    #[test]
    fn test_validate_cosign_invoice_valid() {
        let handler = create_test_handler();
        let operator = create_test_pubkey(184);
        let partner = handler.our_node_id;
        let deposit_pubkey = create_test_pubkey(185);

        // Set up ledger with sufficient capacity
        {
            let mut ledgers = handler.ledgers.lock().unwrap();
            let mut ledger = deposits_core::Ledger::new(
                operator,
                partner.to_string(),
                deposits_core::LedgerRole::Partner,
                vec![],
                "tb1qtest".to_string(),
                0,
            );
            ledger.state.reserves.amount =100_000;
            ledger.state.received_collateral_amount = 100_000;
            let mut deposit = deposits_core::Deposit::new(deposit_pubkey, None);
            deposit.balance = 20_000;
            ledger.state.deposits.insert(deposit_pubkey, deposit);
            ledgers.insert((operator, partner.to_string()), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
        }

        // Cosign invoice for 50k - total would be 70k, under 100k capacity
        // Use a realistic payment hash (not all same bytes)
        let mut payment_hash = [0u8; 32];
        for i in 0..32 { payment_hash[i] = i as u8; }

        let msg = crate::wire::messages::ReceivingCosignInvoiceMsg {
            amount: 50_000,
            payment_hash,
            expires: 1000000,
            assigned_deposit: deposit_pubkey,
            invoice_id: "test_invoice".to_string(),
            bolt11: "lnbc1...".to_string(),
        };

        let result = handler.validate_receiving_cosign_invoice(&msg, operator);
        assert!(result.is_ok(), "Valid cosign request should succeed: {:?}", result);
    }

    // ==================== LedgerClose Validation Tests ====================

    #[test]
    fn test_validate_ledger_close_no_ledger() {
        let handler = create_test_handler();
        let sender = create_test_pubkey(186);

        let msg = crate::wire::messages::LedgerCloseMsg {
            reserves_id: handler.our_node_id.to_string(),
        };

        let result = handler.validate_ledger_close(&msg, sender);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No channel ledger"));
    }

    #[test]
    fn test_validate_ledger_close_wrong_partner() {
        let handler = create_test_handler();
        let operator = create_test_pubkey(187);
        let partner = handler.our_node_id;

        // Set up empty ledger
        {
            let mut ledgers = handler.ledgers.lock().unwrap();
            let ledger = deposits_core::Ledger::new(
                operator,
                partner.to_string(),
                deposits_core::LedgerRole::Partner,
                vec![],
                "tb1qtest".to_string(),
                0,
            );
            ledgers.insert((operator, partner.to_string()), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
        }

        // Close message with wrong reserves_id
        let msg = crate::wire::messages::LedgerCloseMsg {
            reserves_id: create_test_pubkey(188).to_string(), // Wrong partner
        };

        let result = handler.validate_ledger_close(&msg, operator);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("does not match our node"));
    }

    #[test]
    fn test_validate_ledger_close_outstanding_balance() {
        let handler = create_test_handler();
        let operator = create_test_pubkey(189);
        let partner = handler.our_node_id;
        let deposit_pubkey = create_test_pubkey(190);

        // Set up ledger with deposit that has balance
        {
            let mut ledgers = handler.ledgers.lock().unwrap();
            let mut ledger = deposits_core::Ledger::new(
                operator,
                partner.to_string(),
                deposits_core::LedgerRole::Partner,
                vec![],
                "tb1qtest".to_string(),
                0,
            );
            let mut deposit = deposits_core::Deposit::new(deposit_pubkey, None);
            deposit.balance = 50_000; // Has balance
            ledger.state.deposits.insert(deposit_pubkey, deposit);
            ledgers.insert((operator, partner.to_string()), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
        }

        let msg = crate::wire::messages::LedgerCloseMsg {
            reserves_id: partner.to_string(),
        };

        let result = handler.validate_ledger_close(&msg, operator);
        assert!(result.is_err(), "Should reject close with outstanding balance");
        assert!(result.unwrap_err().contains("outstanding deposit balance"));
    }

    #[test]
    fn test_validate_ledger_close_locked_payments() {
        let handler = create_test_handler();
        let operator = create_test_pubkey(191);
        let partner = handler.our_node_id;
        let deposit_pubkey = create_test_pubkey(192);

        // Set up ledger with deposit that has locked balance
        {
            let mut ledgers = handler.ledgers.lock().unwrap();
            let mut ledger = deposits_core::Ledger::new(
                operator,
                partner.to_string(),
                deposits_core::LedgerRole::Partner,
                vec![],
                "tb1qtest".to_string(),
                0,
            );
            let mut deposit = deposits_core::Deposit::new(deposit_pubkey, None);
            deposit.locked_balance = 10_000; // Has locked payments
            ledger.state.deposits.insert(deposit_pubkey, deposit);
            ledgers.insert((operator, partner.to_string()), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
        }

        let msg = crate::wire::messages::LedgerCloseMsg {
            reserves_id: partner.to_string(),
        };

        let result = handler.validate_ledger_close(&msg, operator);
        assert!(result.is_err(), "Should reject close with locked payments");
        assert!(result.unwrap_err().contains("locked payments"));
    }

    #[test]
    fn test_validate_ledger_close_valid_empty() {
        let handler = create_test_handler();
        let operator = create_test_pubkey(193);
        let partner = handler.our_node_id;

        // Set up empty ledger (no deposits)
        {
            let mut ledgers = handler.ledgers.lock().unwrap();
            let ledger = deposits_core::Ledger::new(
                operator,
                partner.to_string(),
                deposits_core::LedgerRole::Partner,
                vec![],
                "tb1qtest".to_string(),
                0,
            );
            ledgers.insert((operator, partner.to_string()), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
        }

        let msg = crate::wire::messages::LedgerCloseMsg {
            reserves_id: partner.to_string(),
        };

        let result = handler.validate_ledger_close(&msg, operator);
        assert!(result.is_ok(), "Valid close of empty ledger should succeed: {:?}", result);
    }

    #[test]
    fn test_validate_ledger_close_valid_zero_balance_deposits() {
        let handler = create_test_handler();
        let operator = create_test_pubkey(194);
        let partner = handler.our_node_id;
        let deposit_pubkey = create_test_pubkey(195);

        // Set up ledger with deposit that has zero balance
        {
            let mut ledgers = handler.ledgers.lock().unwrap();
            let mut ledger = deposits_core::Ledger::new(
                operator,
                partner.to_string(),
                deposits_core::LedgerRole::Partner,
                vec![],
                "tb1qtest".to_string(),
                0,
            );
            let deposit = deposits_core::Deposit::new(deposit_pubkey, None);
            ledger.state.deposits.insert(deposit_pubkey, deposit);
            ledgers.insert((operator, partner.to_string()), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
        }

        let msg = crate::wire::messages::LedgerCloseMsg {
            reserves_id: partner.to_string(),
        };

        let result = handler.validate_ledger_close(&msg, operator);
        assert!(result.is_ok(), "Valid close with zero-balance deposits should succeed: {:?}", result);
    }
}
