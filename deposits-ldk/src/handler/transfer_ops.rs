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

        if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id.to_string())) {
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

}
