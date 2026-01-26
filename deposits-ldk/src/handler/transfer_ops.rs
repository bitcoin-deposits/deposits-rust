// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Transfer operations for the Bitcoin Deposits protocol.
//!
//! This module contains operations for same-node transfers between deposits
//! and payment authorization verification.

use bitcoin::secp256k1::PublicKey;

use super::core::DepositsHandler;
use deposits_core::DepositsError;
use deposits_core::log_info;
use lightning::util::logger::Logger as LdkLogger;

use std::ops::Deref;

impl<L: Deref + Clone + Send + Sync> DepositsHandler<L>
where
    L::Target: LdkLogger,
{
    /// Execute an internal transfer when sender and receiver are on the same node
    /// This is an optimization for when both deposits are managed by the same operator
    /// Returns Ok(()) on success
    pub fn execute_same_node_transfer(
        &self,
        partner_node_id: PublicKey,
        sender_deposit: PublicKey,
        receiver_deposit: PublicKey,
        amount_msat: u64,
        payment_hash: [u8; 32],
    ) -> Result<(), DepositsError> {
        let ledgers = self.ledgers.lock().unwrap();

        if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id)) {
            let mut ledger = ledger_arc.write().unwrap();

            // Check if ledger is closed (tombstoned) - no operations allowed
            if ledger.is_closed() {
                return Err(DepositsError::InvalidState(
                    "Cannot transfer on closed ledger (channel force-closed)".to_string()
                ));
            }

            // Verify sender has sufficient balance (both in millisatoshis)
            {
                let sender = ledger.state.deposits.get(&sender_deposit)
                    .ok_or(DepositsError::DepositNotFound)?;
                let available = sender.balance.saturating_sub(sender.locked_balance);
                if available < amount_msat {
                    return Err(DepositsError::InsufficientBalance);
                }
            }

            // Verify receiver deposit exists
            if !ledger.state.deposits.contains_key(&receiver_deposit) {
                return Err(DepositsError::DepositNotFound);
            }

            // Debit sender (in millisatoshis)
            if let Some(sender) = ledger.state.deposits.get_mut(&sender_deposit) {
                sender.balance = sender.balance.saturating_sub(amount_msat);
            }

            // Credit receiver and remove the invoice (in millisatoshis)
            if let Some(receiver) = ledger.state.deposits.get_mut(&receiver_deposit) {
                receiver.balance += amount_msat;
                // Remove the invoice that was paid
                receiver.invoices.retain(|inv| inv.payment_hash != payment_hash);
            }

            // Update timestamp
            ledger.state.last_updated = deposits_core::time_utils::now_unix_timestamp();

            log_info!(self.logger, "✅ Same-node transfer: {} msat from {} to {} (payment_hash: {:02x?})",
                     amount_msat, sender_deposit, receiver_deposit, &payment_hash[0..4]);

            Ok(())
        } else {
            Err(DepositsError::LedgerNotFound)
        }
    }

    /// Verify cryptographic authorization and payment proof
    /// The deposit owner must sign a message authorizing the payment AND provide payment pre-image
    pub(super) fn verify_payment_authorization(
        &self,
        deposit_pubkey: PublicKey,
        amount: u64,
        invoice_to_pay: &str,
        payment_preimage: &[u8; 32],
        signature: &[u8]
    ) -> Result<(), DepositsError> {
        use bitcoin::secp256k1::{Message, Secp256k1, ecdsa::Signature};
        use bitcoin::hashes::{Hash, sha256};
        use lightning_invoice::Bolt11Invoice;
        use std::str::FromStr;

        // Step 1: Verify pre-image proves payment was completed
        // Extract payment hash from invoice and verify it matches sha256(preimage)
        let invoice = Bolt11Invoice::from_str(invoice_to_pay)
            .map_err(|_| DepositsError::ProtocolViolation {
                violation_type: "invalid_invoice".to_string(),
                details: "Failed to parse Lightning invoice".to_string(),
            })?;

        let expected_payment_hash = invoice.payment_hash();
        let preimage_hash = sha256::Hash::hash(payment_preimage);

        // Verify the pre-image is correct for this payment
        if preimage_hash.as_ref() as &[u8] != expected_payment_hash.as_ref() as &[u8] {
            return Err(DepositsError::ProtocolViolation {
                violation_type: "invalid_payment_preimage".to_string(),
                details: format!(
                    "Pre-image hash {:02x?} does not match payment hash {:02x?}",
                    preimage_hash.as_ref() as &[u8],
                    expected_payment_hash.as_ref() as &[u8]
                ),
            });
        }

        // Step 2: Verify authorization signature
        // Create the message that should have been signed
        // Format: "PAY:{amount}:{invoice}:{preimage_hex}"
        let preimage_hex = hex::encode(payment_preimage);
        let authorization_message = format!("PAY:{}:{}:{}", amount, invoice_to_pay, preimage_hex);

        // Hash the message
        let message_hash = sha256::Hash::hash(authorization_message.as_bytes());
        let secp_message = Message::from_digest_slice(message_hash.as_ref())
            .map_err(|_| DepositsError::ProtocolViolation {
                violation_type: "invalid_message_hash".to_string(),
                details: "Failed to create secp256k1 message from hash".to_string(),
            })?;

        // Parse the signature
        if signature.len() != 64 {
            return Err(DepositsError::ProtocolViolation {
                violation_type: "invalid_signature_length".to_string(),
                details: format!("Expected 64 bytes, got {}", signature.len()),
            });
        }

        let secp_signature = Signature::from_compact(signature)
            .map_err(|_| DepositsError::ProtocolViolation {
                violation_type: "invalid_signature_format".to_string(),
                details: "Failed to parse signature".to_string(),
            })?;

        // Verify the signature
        let secp = Secp256k1::verification_only();
        secp.verify_ecdsa(&secp_message, &secp_signature, &deposit_pubkey)
            .map_err(|_| DepositsError::ProtocolViolation {
                violation_type: "signature_verification_failed".to_string(),
                details: format!("Signature verification failed for deposit {}", deposit_pubkey),
            })?;

        log_info!(
            self.logger,
            "✅ Payment authorization and pre-image verified for deposit {}: amount={}, invoice={}, preimage_hash={:02x?}",
            deposit_pubkey, amount, invoice_to_pay.chars().take(50).collect::<String>(), preimage_hash.as_ref() as &[u8]
        );

        Ok(())
    }
}
