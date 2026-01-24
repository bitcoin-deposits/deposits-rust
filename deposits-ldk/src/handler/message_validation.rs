//! Message Validation for Bitcoin Deposits
//!
//! This module provides validation functions for all deposit protocol messages.
//! Each validation function checks message-specific constraints before the message
//! is accepted and applied to the ledger.

use bitcoin::secp256k1::PublicKey;
use std::ops::Deref;

use super::messages::{
    DepositsMessage,
    ReceivingCreditPaymentMsg,
    SendingFailPaymentMsg,
    SendingFulfillPaymentMsg,
    SendingLockPaymentMsg,
};
use lightning::util::logger::Logger as LdkLogger;

use super::core::DepositsHandler;
use super::reserves_ops::ReservesOperations;

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
    fn validate_reserves_remove(&self, msg: &super::messages::ReservesRemoveOutputMsg, sender: PublicKey) -> Result<(), String>;

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

// verify_payment_signature is now called internally by deposits_core validation functions

/// Unified validation of LedgerOperation (handles both V1 converted to operation and V2 native)
fn validate_operation<L: Deref + Clone>(
    handler: &DepositsHandler<L>,
    operation: &deposits_core::messages::LedgerOperation,
    partner_pubkey: PublicKey,
    sender: PublicKey,
) -> Result<(), String>
where
    L::Target: LdkLogger,
{
    use deposits_core::messages::LedgerOperation;

    match operation {
        LedgerOperation::DepositOpen { pubkey, fees, payment_hash, invoice, cosigner_guarantee_signature } => {
            use crate::wire::messages::DepositOpenMsg;
            use crate::wire::types::FeeStructure as WireFeeStructure;
            handler.validate_add_deposit(&DepositOpenMsg {
                partner_id: partner_pubkey,
                pubkey: *pubkey,
                fees: fees.clone().map(WireFeeStructure::from),
                payment_hash: *payment_hash,
                invoice: invoice.clone(),
                cosigner_guarantee_signature: *cosigner_guarantee_signature,
            }, sender)
        }
        LedgerOperation::DepositClose { pubkey } => {
            use crate::wire::messages::DepositCloseMsg;
            handler.validate_remove_deposit(&DepositCloseMsg {
                partner_id: partner_pubkey,
                pubkey: *pubkey,
            }, sender)
        }
        LedgerOperation::DepositUpdate { pubkey, new_fees } => {
            use crate::wire::messages::DepositUpdateMsg;
            use crate::wire::types::FeeStructure as WireFeeStructure;
            handler.validate_update_deposit(&DepositUpdateMsg {
                partner_id: partner_pubkey,
                pubkey: *pubkey,
                new_fees: WireFeeStructure::from(new_fees.clone()),
            }, sender)
        }
        LedgerOperation::PaymentLock { pubkey, amount, payment_id, sequence_number, scriptpubkey_signature } => {
            handler.validate_sending_lock_payment(&SendingLockPaymentMsg {
                pubkey: *pubkey,
                amount: *amount,
                payment_id: *payment_id,
                sequence_number: *sequence_number,
                scriptpubkey_signature: *scriptpubkey_signature,
            }, sender)
        }
        LedgerOperation::PaymentFulfill { pubkey, amount, payment_id, sequence_number, scriptpubkey_signature, preimage } => {
            handler.validate_sending_fulfill_payment(&SendingFulfillPaymentMsg {
                pubkey: *pubkey,
                amount: *amount,
                payment_id: *payment_id,
                sequence_number: *sequence_number,
                scriptpubkey_signature: *scriptpubkey_signature,
                preimage: *preimage,
            }, sender)
        }
        LedgerOperation::PaymentFail { pubkey, amount, payment_id, sequence_number } => {
            handler.validate_sending_fail_payment(&SendingFailPaymentMsg {
                pubkey: *pubkey,
                amount: *amount,
                payment_id: *payment_id,
                sequence_number: *sequence_number,
            }, sender)
        }
        LedgerOperation::PaymentCredit { payment_hash, deposit_pubkey, amount, invoice_id, sequence_number } => {
            handler.validate_receiving_credit_payment(&ReceivingCreditPaymentMsg {
                payment_hash: *payment_hash,
                deposit_pubkey: *deposit_pubkey,
                amount: *amount,
                invoice_id: invoice_id.clone(),
                partner_id: partner_pubkey,
                sequence_number: *sequence_number,
            }, sender)
        }
        LedgerOperation::ReservesAdd { amount, spend_to, collateral_partners } => {
            use crate::wire::messages::ReservesAddOutputMsg;
            handler.validate_reserves_add(&ReservesAddOutputMsg {
                initial_amount: *amount,
                spend_to: *spend_to,
                partner_id: partner_pubkey,
                collateral_partners: collateral_partners.clone(),
            }, sender)
        }
        LedgerOperation::ReservesRemove => {
            use super::messages::ReservesRemoveOutputMsg;
            handler.validate_reserves_remove(&ReservesRemoveOutputMsg {
                partner_id: partner_pubkey,
                remove_all: true,
            }, sender)
        }
        LedgerOperation::ReservesIncrease { new_amount } => {
            use crate::wire::messages::ReservesIncreaseMsg;
            handler.validate_reserves_increase(&ReservesIncreaseMsg {
                new_amount: *new_amount,
                partner_id: partner_pubkey,
            }, sender)
        }
        LedgerOperation::ReservesDecrease { new_amount } => {
            use crate::wire::messages::ReservesDecreaseMsg;
            handler.validate_reserves_decrease(&ReservesDecreaseMsg {
                new_amount: *new_amount,
                partner_id: partner_pubkey,
            }, sender)
        }
        LedgerOperation::CollateralIncrease { new_amount, block_height } => {
            handler.validate_collateral_increase(&crate::wire::messages::CollateralIncreaseMsg {
                partner_id: partner_pubkey,
                new_amount: *new_amount,
                block_height: *block_height,
            }, sender)
        }
        LedgerOperation::CollateralDecrease { new_amount, block_height } => {
            handler.validate_collateral_decrease(&crate::wire::messages::CollateralDecreaseMsg {
                partner_id: partner_pubkey,
                new_amount: *new_amount,
                block_height: *block_height,
            }, sender)
        }
        LedgerOperation::FeeCollect { pubkey, amount, block_height } => {
            handler.validate_fee_collect(&crate::wire::messages::FeeCollectMsg {
                pubkey: *pubkey,
                amount: *amount,
                block_height: *block_height,
            }, sender)
        }
        LedgerOperation::LedgerClose => {
            handler.validate_ledger_close(&crate::wire::messages::LedgerCloseMsg {
                partner_id: partner_pubkey,
            }, sender)
        }
        // Operations without specific validation
        LedgerOperation::ReservesUpdateSpendTo { .. } |
        LedgerOperation::TransferLock { .. } |
        LedgerOperation::TransferFail { .. } |
        LedgerOperation::TransferFulfill { .. } |
        LedgerOperation::CollateralAttestation { .. } |
        LedgerOperation::CollateralAddPartner { .. } |
        LedgerOperation::CollateralRemovePartner { .. } |
        LedgerOperation::Tombstone { .. } => Ok(()),
    }
}

impl<L: Deref + Clone> MessageValidation for DepositsHandler<L>
where
    L::Target: LdkLogger,
{
    fn validate_message(&self, message: &DepositsMessage, sender: PublicKey) -> Result<(), String> {
        // Handle messages that convert to LedgerOperation uniformly (V1 and V2)
        if let Some(operation) = message.to_operation() {
            if let Some(partner_pubkey) = message.partner_id() {
                return validate_operation(self, &operation, partner_pubkey, sender);
            }
        }

        // Handle special cases that don't convert to LedgerOperation
        match message {
            // Invoice Cosigning Validation
            DepositsMessage::ReceivingCosignInvoice { ref pending_invoice } => {
                use crate::wire::messages::ReceivingCosignInvoiceMsg as WireReceivingCosignInvoiceMsg;
                self.validate_receiving_cosign_invoice(&WireReceivingCosignInvoiceMsg {
                    amount: pending_invoice.amount,
                    payment_hash: pending_invoice.payment_hash,
                    expires: pending_invoice.expires,
                    assigned_deposit: pending_invoice.assigned_deposit,
                    invoice_id: pending_invoice.invoice_id.clone(),
                    bolt11: pending_invoice.bolt11.clone(),
                }, sender)
            },

            // SignedUpdate - delegate to operation validation
            DepositsMessage::SignedUpdate(update_msg) => {
                validate_operation(self, &update_msg.operation, update_msg.partner_pubkey, sender)
            },

            // Messages that don't require validation (non-ledger-modifying)
            _ => Ok(()),
        }
    }

    fn validate_add_deposit(&self, msg: &crate::wire::messages::DepositOpenMsg, sender: PublicKey) -> Result<(), String> {
        let ledgers = self.ledgers.lock().unwrap();

        if let Some(ledger_arc) = ledgers.get(&(sender, self.our_node_id)) {
            let ledger = ledger_arc.read().unwrap();
            // Convert wire FeeStructure to core FeeStructure if present
            let core_fees = msg.fees.as_ref().map(|f| deposits_core::types::FeeStructure {
                annualized_fixed: f.annualized_fixed,
                annualized_bps: f.annualized_bps,
                frequency_blocks: f.frequency_blocks,
            });
            deposits_core::validate_deposit_add(&ledger, msg.pubkey, core_fees.as_ref())
        } else {
            Err(format!("No channel ledger found for sender {}", sender))
        }
    }

    fn validate_remove_deposit(&self, msg: &crate::wire::messages::DepositCloseMsg, sender: PublicKey) -> Result<(), String> {
        let ledgers = self.ledgers.lock().unwrap();

        if let Some(ledger_arc) = ledgers.get(&(sender, self.our_node_id)) {
            let ledger = ledger_arc.read().unwrap();
            deposits_core::validate_deposit_close(&ledger, msg.pubkey)
        } else {
            Err(format!("No channel ledger found for sender {}", sender))
        }
    }

    fn validate_update_deposit(&self, msg: &crate::wire::messages::DepositUpdateMsg, sender: PublicKey) -> Result<(), String> {
        let ledgers = self.ledgers.lock().unwrap();

        if let Some(ledger_arc) = ledgers.get(&(sender, self.our_node_id)) {
            let ledger = ledger_arc.read().unwrap();
            // Convert wire FeeStructure to core FeeStructure
            let core_fees = deposits_core::types::FeeStructure {
                annualized_fixed: msg.new_fees.annualized_fixed,
                annualized_bps: msg.new_fees.annualized_bps,
                frequency_blocks: msg.new_fees.frequency_blocks,
            };
            deposits_core::validate_deposit_update(&ledger, msg.pubkey, &core_fees)
        } else {
            Err(format!("No channel ledger found for sender {}", sender))
        }
    }

    fn validate_sending_lock_payment(&self, msg: &crate::wire::messages::SendingLockPaymentMsg, sender: PublicKey) -> Result<(), String> {
        let ledgers = self.ledgers.lock().unwrap();

        if let Some(ledger_arc) = ledgers.get(&(sender, self.our_node_id)) {
            let ledger = ledger_arc.read().unwrap();
            deposits_core::validate_payment_lock(
                &ledger,
                msg.pubkey,
                msg.amount,
                &msg.payment_id,
                &msg.scriptpubkey_signature,
            )
        } else {
            Err(format!("No channel ledger found for sender {}", sender))
        }
    }

    fn validate_sending_fulfill_payment(&self, msg: &crate::wire::messages::SendingFulfillPaymentMsg, _sender: PublicKey) -> Result<(), String> {
        deposits_core::validate_payment_fulfill(
            &msg.pubkey,
            msg.amount,
            &msg.payment_id,
            &msg.scriptpubkey_signature,
            &msg.preimage,
        )
    }

    fn validate_sending_fail_payment(&self, msg: &crate::wire::messages::SendingFailPaymentMsg, _sender: PublicKey) -> Result<(), String> {
        deposits_core::validate_payment_fail(msg.amount)
    }

    fn validate_receiving_credit_payment(&self, msg: &crate::wire::messages::ReceivingCreditPaymentMsg, sender: PublicKey) -> Result<(), String> {
        // Demo-specific fake invoice check (TODO: move to separate layer)
        if msg.invoice_id.contains("fake") || msg.invoice_id.contains("424242") {
            return Err(format!("Invalid invoice ID: {}", msg.invoice_id));
        }

        let ledgers = self.ledgers.lock().unwrap();

        if let Some(ledger_arc) = ledgers.get(&(sender, self.our_node_id)) {
            let ledger = ledger_arc.read().unwrap();
            deposits_core::validate_credit_payment(
                &ledger,
                msg.deposit_pubkey,
                msg.amount,
                &msg.payment_hash,
            )
        } else {
            Err(format!("No channel ledger found for sender {}", sender))
        }
    }

    fn validate_reserves_add(&self, msg: &crate::wire::messages::ReservesAddOutputMsg, _sender: PublicKey) -> Result<(), String> {
        deposits_core::validate_reserves_add(msg.initial_amount)
    }

    fn validate_reserves_remove(&self, msg: &super::messages::ReservesRemoveOutputMsg, sender: PublicKey) -> Result<(), String> {
        // First check if we have a ledger for this sender
        let has_ledger = {
            let ledgers = self.ledgers.lock().unwrap();
            ledgers.get(&(sender, self.our_node_id)).is_some()
        };

        if has_ledger {
            // As the partner, use commitment tx reserves amount (not ledger's declared amount)
            // This is the source of truth for what the operator has actually committed
            let commitment_reserves = self.get_commitment_tx_reserves_amount(sender).unwrap_or(0);

            // If remove_all is false, this is a partial removal - validate reserves exist in commitment tx
            if !msg.remove_all && commitment_reserves == 0 {
                return Err("Cannot remove reserves: no reserves committed in channel".to_string());
            }

            Ok(())
        } else {
            Err(format!("No channel ledger found for sender {}", sender))
        }
    }

    fn validate_fee_collect(&self, msg: &crate::wire::messages::FeeCollectMsg, sender: PublicKey) -> Result<(), String> {
        let ledgers = self.ledgers.lock().unwrap();

        if let Some(ledger_arc) = ledgers.get(&(sender, self.our_node_id)) {
            let ledger = ledger_arc.read().unwrap();
            deposits_core::validate_fee_collect(&ledger, msg.pubkey, msg.amount, msg.block_height)
        } else {
            Err(format!("No channel ledger found for sender {}", sender))
        }
    }

    fn validate_collateral_increase(&self, msg: &crate::wire::messages::CollateralIncreaseMsg, sender: PublicKey) -> Result<(), String> {
        let ledgers = self.ledgers.lock().unwrap();

        if let Some(ledger_arc) = ledgers.get(&(sender, self.our_node_id)) {
            let ledger = ledger_arc.read().unwrap();
            deposits_core::validate_collateral_increase(
                ledger.state.collateral_amount,
                msg.new_amount,
                ledger.reserves_amount(),
            )
        } else {
            Err(format!("No channel ledger found for sender {}", sender))
        }
    }

    fn validate_collateral_decrease(&self, msg: &crate::wire::messages::CollateralDecreaseMsg, sender: PublicKey) -> Result<(), String> {
        let ledgers = self.ledgers.lock().unwrap();

        if let Some(ledger_arc) = ledgers.get(&(sender, self.our_node_id)) {
            let ledger = ledger_arc.read().unwrap();
            deposits_core::validate_collateral_decrease(
                ledger.state.collateral_amount,
                msg.new_amount,
                msg.block_height,
                ledger.state.last_collateral_increase_block,
            )
        } else {
            Err(format!("No channel ledger found for sender {}", sender))
        }
    }

    fn validate_reserves_increase(&self, msg: &crate::wire::messages::ReservesIncreaseMsg, sender: PublicKey) -> Result<(), String> {
        use super::reserves_ops::ReservesOperations;

        // Get channel balance for optional constraint check (LDK-specific)
        let channel_balance = self.get_commitment_tx_reserves_amount(sender);

        // Get current reserves
        let ledgers = self.ledgers.lock().unwrap();
        if let Some(ledger_arc) = ledgers.get(&(sender, self.our_node_id)) {
            let ledger = ledger_arc.read().unwrap();
            deposits_core::validate_reserves_increase(
                ledger.reserves_amount(),
                msg.new_amount,
                channel_balance,
            )
        } else {
            // No ledger - just do basic validation without current reserves check
            deposits_core::validate_reserves_increase(0, msg.new_amount, channel_balance)
        }
    }

    fn validate_reserves_decrease(&self, msg: &crate::wire::messages::ReservesDecreaseMsg, sender: PublicKey) -> Result<(), String> {
        let ledgers = self.ledgers.lock().unwrap();

        if let Some(ledger_arc) = ledgers.get(&(sender, self.our_node_id)) {
            let ledger = ledger_arc.read().unwrap();
            deposits_core::validate_reserves_decrease(&ledger, msg.new_amount)
        } else {
            Err(format!("No channel ledger found for sender {}", sender))
        }
    }

    fn validate_receiving_cosign_invoice(&self, msg: &crate::wire::messages::ReceivingCosignInvoiceMsg, sender: PublicKey) -> Result<(), String> {
        let ledgers = self.ledgers.lock().unwrap();

        // Sender is the operator, we are the partner being asked to cosign
        if let Some(ledger_arc) = ledgers.get(&(sender, self.our_node_id)) {
            let ledger = ledger_arc.read().unwrap();
            deposits_core::validate_cosign_invoice(
                &ledger,
                msg.assigned_deposit,
                msg.amount,
                &msg.invoice_id,
                &msg.payment_hash,
            )
        } else {
            Err(format!("No channel ledger found for sender {}", sender))
        }
    }

    fn validate_ledger_close(&self, msg: &crate::wire::messages::LedgerCloseMsg, sender: PublicKey) -> Result<(), String> {
        let ledgers = self.ledgers.lock().unwrap();

        // Sender is the operator, we are the partner
        if let Some(ledger_arc) = ledgers.get(&(sender, self.our_node_id)) {
            let ledger = ledger_arc.read().unwrap();

            // Check that the partner_id matches us (context-specific check)
            if msg.partner_id != self.our_node_id {
                return Err(format!(
                    "LedgerClose partner_id {} does not match our node {}",
                    msg.partner_id, self.our_node_id
                ));
            }

            // Delegate balance checks to core
            deposits_core::validate_ledger_close(&ledger)
        } else {
            Err(format!("No channel ledger found for sender {}", sender))
        }
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
            partner_id: create_test_pubkey(3),
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
            partner_id: create_test_pubkey(5),
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
            new_fees: crate::wire::types::FeeStructure::default(),
            partner_id: create_test_pubkey(7),
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
            partner_id: create_test_pubkey(15),
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
            partner_id: create_test_pubkey(18),
            collateral_partners: vec![],
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
            partner_id: create_test_pubkey(19),
            collateral_partners: vec![],
        };

        let result = handler.validate_reserves_add(&msg, sender);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("exceeds maximum"));
    }

    #[test]
    fn test_validate_reserves_remove_no_ledger() {
        let handler = create_test_handler();
        let sender = create_test_pubkey(18);
        let msg = handler_messages::ReservesRemoveOutputMsg {
            remove_all: false,
            partner_id: create_test_pubkey(19),
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
            partner_id: create_test_pubkey(22),
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
                partner,
                deposits_core::LedgerRole::Partner,
                vec![],
                "tb1qtest".to_string(),
            );
            ledger.state.reserves.amount =5000;
            ledgers.insert((operator, partner), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
        }

        // Try to "increase" to a lower amount - should fail
        let msg = crate::wire::messages::ReservesIncreaseMsg {
            new_amount: 4000, // Less than current 5000
            partner_id: partner,
        };

        let result = handler.validate_reserves_increase(&msg, operator);
        assert!(result.is_err(), "ReservesIncrease to lower amount should fail");
        assert!(result.unwrap_err().contains("not greater than current"));
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
                partner,
                deposits_core::LedgerRole::Partner,
                vec![],
                "tb1qtest".to_string(),
            );
            ledger.state.reserves.amount =5000;
            ledgers.insert((operator, partner), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
        }

        // Try to "increase" to the same amount - should fail
        let msg = crate::wire::messages::ReservesIncreaseMsg {
            new_amount: 5000, // Same as current
            partner_id: partner,
        };

        let result = handler.validate_reserves_increase(&msg, operator);
        assert!(result.is_err(), "ReservesIncrease to same amount should fail");
        assert!(result.unwrap_err().contains("not greater than current"));
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
                partner,
                deposits_core::LedgerRole::Partner,
                vec![],
                "tb1qtest".to_string(),
            );
            ledger.state.reserves.amount =5000;
            ledgers.insert((operator, partner), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
        }

        // Increase to higher amount - should succeed
        // (without channel_manager, the channel balance check is skipped)
        let msg = crate::wire::messages::ReservesIncreaseMsg {
            new_amount: 10000, // More than current 5000
            partner_id: partner,
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
            partner_id: create_test_pubkey(34),
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

    #[test]
    fn test_verify_payment_signature_placeholder_accepted() {
        // During development, placeholder signatures (all zeros) are accepted
        let pubkey = create_test_pubkey(50);
        let payment_id = [0xAB; 32];
        let amount = 1000u64;
        let placeholder_sig = [0u8; 64];

        let result = super::DepositsHandler::<std::sync::Arc<lightning::util::test_utils::TestLogger>>::verify_payment_signature(
            &pubkey,
            &payment_id,
            amount,
            &placeholder_sig,
        );
        assert!(result, "Placeholder signature should be accepted during development");
    }

    #[test]
    fn test_verify_payment_signature_invalid_rejected() {
        // Non-zero invalid signatures should be rejected
        let pubkey = create_test_pubkey(51);
        let payment_id = [0xAB; 32];
        let amount = 1000u64;
        let invalid_sig = [0xFF; 64]; // Invalid signature (not all zeros)

        let result = super::DepositsHandler::<std::sync::Arc<lightning::util::test_utils::TestLogger>>::verify_payment_signature(
            &pubkey,
            &payment_id,
            amount,
            &invalid_sig,
        );
        assert!(!result, "Invalid signature should be rejected");
    }

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
                partner,
                deposits_core::LedgerRole::Partner,
                vec![],
                "tb1qtest".to_string(),
            );
            ledger.state.collateral_amount = 5000;
            ledger.state.last_collateral_increase_block = Some(100);
            ledgers.insert((operator, partner), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
        }

        // Try to decrease at block 150 (within 144-block period)
        let msg = crate::wire::messages::CollateralDecreaseMsg {
            new_amount: 3000,
            partner_id: partner,
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
                partner,
                deposits_core::LedgerRole::Partner,
                vec![],
                "tb1qtest".to_string(),
            );
            ledger.state.collateral_amount = 5000;
            ledger.state.last_collateral_increase_block = Some(100);
            ledgers.insert((operator, partner), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
        }

        // Decrease at block 250 (after 144-block period: 100 + 144 = 244)
        let msg = crate::wire::messages::CollateralDecreaseMsg {
            new_amount: 3000,
            partner_id: partner,
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
                partner,
                deposits_core::LedgerRole::Partner,
                vec![],
                "tb1qtest".to_string(),
            );
            ledger.state.collateral_amount = 5000;
            ledger.state.last_collateral_increase_block = None; // No prior increase
            ledgers.insert((operator, partner), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
        }

        // Decrease should work since no prior increase to wait for
        let msg = crate::wire::messages::CollateralDecreaseMsg {
            new_amount: 3000,
            partner_id: partner,
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
                partner,
                deposits_core::LedgerRole::Partner,
                vec![],
                "tb1qtest".to_string(),
            );
            ledger.state.collateral_amount = 5000;
            ledger.state.last_collateral_increase_block = None;
            ledgers.insert((operator, partner), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
        }

        // Try to "decrease" to a higher value
        let msg = crate::wire::messages::CollateralDecreaseMsg {
            new_amount: 6000,
            partner_id: partner,
            block_height: 100,
        };

        let result = handler.validate_collateral_decrease(&msg, operator);
        assert!(result.is_err(), "Decrease to higher value should fail");
        assert!(result.unwrap_err().contains("must decrease"));
    }

    // ==================== ReservesDecrease Validation Tests ====================

    #[test]
    fn test_validate_reserves_decrease_no_ledger() {
        let handler = create_test_handler();
        let sender = create_test_pubkey(200);
        let partner = create_test_pubkey(201);

        let msg = crate::wire::messages::ReservesDecreaseMsg {
            new_amount: 50_000,
            partner_id: partner,
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
                partner,
                deposits_core::LedgerRole::Partner,
                vec![],
                "tb1qtest".to_string(),
            );
            ledger.state.reserves.amount =100_000;
            ledgers.insert((operator, partner), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
        }

        // Try to "decrease" to same value
        let msg = crate::wire::messages::ReservesDecreaseMsg {
            new_amount: 100_000,
            partner_id: partner,
        };

        let result = handler.validate_reserves_decrease(&msg, operator);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must decrease"));
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
                partner,
                deposits_core::LedgerRole::Partner,
                vec![],
                "tb1qtest".to_string(),
            );
            ledger.state.reserves.amount =100_000;
            ledgers.insert((operator, partner), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
        }

        // Try to "decrease" to higher value
        let msg = crate::wire::messages::ReservesDecreaseMsg {
            new_amount: 150_000,
            partner_id: partner,
        };

        let result = handler.validate_reserves_decrease(&msg, operator);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must decrease"));
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
                partner,
                deposits_core::LedgerRole::Partner,
                vec![],
                "tb1qtest".to_string(),
            );
            ledger.state.reserves.amount =100_000;

            // Add a deposit with 80k balance - this requires reserves backing
            let mut deposit = deposits_core::Deposit::new(deposit_pubkey, None);
            deposit.balance = 80_000;
            ledger.state.deposits.insert(deposit_pubkey, deposit);

            ledgers.insert((operator, partner), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
        }

        // Try to decrease reserves below what's required to back deposits
        let msg = crate::wire::messages::ReservesDecreaseMsg {
            new_amount: 50_000, // Less than the 80k deposit balance
            partner_id: partner,
        };

        let result = handler.validate_reserves_decrease(&msg, operator);
        assert!(result.is_err(), "Should fail when decrease falls below requirement");
        assert!(result.unwrap_err().contains("below requirement"));
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
                partner,
                deposits_core::LedgerRole::Partner,
                vec![],
                "tb1qtest".to_string(),
            );
            ledger.state.reserves.amount =100_000;

            // Add a deposit with 50k balance
            let mut deposit = deposits_core::Deposit::new(deposit_pubkey, None);
            deposit.balance = 50_000;
            ledger.state.deposits.insert(deposit_pubkey, deposit);

            ledgers.insert((operator, partner), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
        }

        // Decrease reserves to 60k - still above the 50k deposit requirement
        let msg = crate::wire::messages::ReservesDecreaseMsg {
            new_amount: 60_000,
            partner_id: partner,
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
                partner,
                deposits_core::LedgerRole::Partner,
                vec![],
                "tb1qtest".to_string(),
            );
            ledger.state.reserves.amount =100_000;

            // Add a deposit with 50k balance
            let mut deposit = deposits_core::Deposit::new(deposit_pubkey, None);
            deposit.balance = 50_000;
            ledger.state.deposits.insert(deposit_pubkey, deposit);

            ledgers.insert((operator, partner), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
        }

        // Decrease reserves to exactly the requirement (50k)
        let msg = crate::wire::messages::ReservesDecreaseMsg {
            new_amount: 50_000,
            partner_id: partner,
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
                partner,
                deposits_core::LedgerRole::Partner,
                vec![],
                "tb1qtest".to_string(),
            );
            ledger.state.reserves.amount =100_000;
            // No deposits added

            ledgers.insert((operator, partner), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
        }

        // Decrease reserves to very low amount - should work since no deposits
        let msg = crate::wire::messages::ReservesDecreaseMsg {
            new_amount: 1_000,
            partner_id: partner,
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
                partner,
                deposits_core::LedgerRole::Partner,
                vec![],
                "tb1qtest".to_string(),
            );
            ledgers.insert((operator, partner), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
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
                partner,
                deposits_core::LedgerRole::Partner,
                vec![],
                "tb1qtest".to_string(),
            );
            ledger.state.reserves.amount =100_000;
            ledger.state.received_collateral_amount = 100_000;
            let deposit = deposits_core::Deposit::new(deposit_pubkey, None);
            ledger.state.deposits.insert(deposit_pubkey, deposit);
            ledgers.insert((operator, partner), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
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
                partner,
                deposits_core::LedgerRole::Partner,
                vec![],
                "tb1qtest".to_string(),
            );
            ledger.state.reserves.amount =50_000; // Only 50k reserves
            ledger.state.received_collateral_amount = 100_000; // Plenty of collateral
            let mut deposit = deposits_core::Deposit::new(deposit_pubkey, None);
            deposit.balance = 30_000; // Already has 30k
            ledger.state.deposits.insert(deposit_pubkey, deposit);
            ledgers.insert((operator, partner), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
        }

        // Try to cosign invoice for 25k - would push total to 55k, exceeding 50k reserves
        let msg = crate::wire::messages::ReceivingCosignInvoiceMsg {
            amount: 25_000,
            payment_hash: [0xAB; 32],
            expires: 1000000,
            assigned_deposit: deposit_pubkey,
            invoice_id: "test_invoice".to_string(),
            bolt11: "lnbc1...".to_string(),
        };

        let result = handler.validate_receiving_cosign_invoice(&msg, operator);
        assert!(result.is_err(), "Should reject when cosigning would exceed reserves");
        assert!(result.unwrap_err().contains("exceed reserves"));
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
                partner,
                deposits_core::LedgerRole::Partner,
                vec![],
                "tb1qtest".to_string(),
            );
            ledger.state.reserves.amount =100_000; // Plenty of reserves
            ledger.state.received_collateral_amount = 50_000; // Only 50k collateral
            let mut deposit = deposits_core::Deposit::new(deposit_pubkey, None);
            deposit.balance = 30_000;
            ledger.state.deposits.insert(deposit_pubkey, deposit);
            ledgers.insert((operator, partner), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
        }

        // Try to cosign invoice for 25k - would push total to 55k, exceeding 50k collateral
        let msg = crate::wire::messages::ReceivingCosignInvoiceMsg {
            amount: 25_000,
            payment_hash: [0xAB; 32],
            expires: 1000000,
            assigned_deposit: deposit_pubkey,
            invoice_id: "test_invoice".to_string(),
            bolt11: "lnbc1...".to_string(),
        };

        let result = handler.validate_receiving_cosign_invoice(&msg, operator);
        assert!(result.is_err(), "Should reject when cosigning would exceed collateral");
        assert!(result.unwrap_err().contains("exceed collateral"));
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
                partner,
                deposits_core::LedgerRole::Partner,
                vec![],
                "tb1qtest".to_string(),
            );
            ledger.state.reserves.amount =100_000;
            ledger.state.received_collateral_amount = 100_000;
            let deposit = deposits_core::Deposit::new(deposit_pubkey, None);
            ledger.state.deposits.insert(deposit_pubkey, deposit);
            ledgers.insert((operator, partner), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
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
                partner,
                deposits_core::LedgerRole::Partner,
                vec![],
                "tb1qtest".to_string(),
            );
            ledger.state.reserves.amount =100_000;
            ledger.state.received_collateral_amount = 100_000;
            let deposit = deposits_core::Deposit::new(deposit_pubkey, None);
            ledger.state.deposits.insert(deposit_pubkey, deposit);
            ledgers.insert((operator, partner), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
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
                partner,
                deposits_core::LedgerRole::Partner,
                vec![],
                "tb1qtest".to_string(),
            );
            ledger.state.reserves.amount =100_000;
            ledger.state.received_collateral_amount = 100_000;
            let mut deposit = deposits_core::Deposit::new(deposit_pubkey, None);
            deposit.balance = 20_000;
            ledger.state.deposits.insert(deposit_pubkey, deposit);
            ledgers.insert((operator, partner), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
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
            partner_id: handler.our_node_id,
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
                partner,
                deposits_core::LedgerRole::Partner,
                vec![],
                "tb1qtest".to_string(),
            );
            ledgers.insert((operator, partner), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
        }

        // Close message with wrong partner_id
        let msg = crate::wire::messages::LedgerCloseMsg {
            partner_id: create_test_pubkey(188), // Wrong partner
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
                partner,
                deposits_core::LedgerRole::Partner,
                vec![],
                "tb1qtest".to_string(),
            );
            let mut deposit = deposits_core::Deposit::new(deposit_pubkey, None);
            deposit.balance = 50_000; // Has balance
            ledger.state.deposits.insert(deposit_pubkey, deposit);
            ledgers.insert((operator, partner), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
        }

        let msg = crate::wire::messages::LedgerCloseMsg {
            partner_id: partner,
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
                partner,
                deposits_core::LedgerRole::Partner,
                vec![],
                "tb1qtest".to_string(),
            );
            let mut deposit = deposits_core::Deposit::new(deposit_pubkey, None);
            deposit.locked_balance = 10_000; // Has locked payments
            ledger.state.deposits.insert(deposit_pubkey, deposit);
            ledgers.insert((operator, partner), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
        }

        let msg = crate::wire::messages::LedgerCloseMsg {
            partner_id: partner,
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
                partner,
                deposits_core::LedgerRole::Partner,
                vec![],
                "tb1qtest".to_string(),
            );
            ledgers.insert((operator, partner), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
        }

        let msg = crate::wire::messages::LedgerCloseMsg {
            partner_id: partner,
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
                partner,
                deposits_core::LedgerRole::Partner,
                vec![],
                "tb1qtest".to_string(),
            );
            let deposit = deposits_core::Deposit::new(deposit_pubkey, None);
            ledger.state.deposits.insert(deposit_pubkey, deposit);
            ledgers.insert((operator, partner), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
        }

        let msg = crate::wire::messages::LedgerCloseMsg {
            partner_id: partner,
        };

        let result = handler.validate_ledger_close(&msg, operator);
        assert!(result.is_ok(), "Valid close with zero-balance deposits should succeed: {:?}", result);
    }
}
