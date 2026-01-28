// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Payment handlers for the Bitcoin Deposits protocol.
//!
//! This module contains handlers for payment operations (lock, fulfill, fail),
//! extracted from core.rs to improve maintainability.

use super::core::DepositsHandler;
use deposits_core::DepositsError;
use super::messages::{DepositsMessage, LedgerUpdateMsg, LedgerUpdateMsgExt, LedgerOperation};
use super::ledger_ext::LedgerExt;
use deposits_core::{log_error, log_info};
use lightning::util::logger::Logger as LdkLogger;

use std::ops::Deref;

impl<L: Deref + Clone + Send + Sync> DepositsHandler<L>
where
    L::Target: LdkLogger,
{
    /// Handle sending payment fulfillment (fire-and-forget version)
    /// Payment is already complete (preimage received), this just updates the ledger
    pub async fn handle_sending_fulfill_payment_async(
        &self,
        msg: crate::wire::messages::SendingFulfillPaymentMsg,
    ) -> Result<(), DepositsError> {
        log_info!(self.logger, "🔵 FULFILL: payment_id={:02x?}, pubkey={}, amount={}",
                 &msg.payment_id[0..4], msg.pubkey, msg.amount);

        // STAGE 1: Validate and apply locally (optimistic - payment already succeeded)
        let (partner_node_id, prev_hash, new_hash, fulfill_message, broadcast_seq) = {
            let mut payment_locks = self.payment_locks.lock().unwrap();
            let ledgers = self.ledgers.lock().unwrap();

            // Validate payment lock
            let (locked_pubkey, locked_amount) = payment_locks.get(&msg.payment_id)
                .ok_or(DepositsError::PaymentNotLocked)?;

            if *locked_pubkey != msg.pubkey || *locked_amount != msg.amount {
                return Err(DepositsError::PaymentAmountMismatch);
            }

            // Find ledger containing this deposit by searching all ledgers
            let mut found_result = None;
            for ((op, partner), ledger_arc) in ledgers.iter() {
                if *op != self.our_node_id {
                    continue;
                }
                let mut ledger = ledger_arc.write().unwrap();
                if !ledger.state.deposits.contains_key(&msg.pubkey) {
                    continue; // Deposit not in this ledger, check next one
                }

                // Found the ledger with this deposit - process it
                payment_locks.remove(&msg.payment_id);
                ledger.state.last_updated = deposits_core::time_utils::now_unix_timestamp();

                // Compute sequence number BEFORE building the message (for validation in append)
                // The message's sequence_number must match ledger.history.len() at append time
                let expected_sequence = ledger.history.len() as u64;

                // Build V2 LedgerUpdate message with PaymentFulfill operation
                let update_msg = LedgerUpdateMsg::new_with_operation(
                    ledger.operator_key(),
                    ledger.partner_key(),
                    LedgerOperation::PaymentFulfill {
                        pubkey: msg.pubkey,
                        amount: msg.amount,
                        payment_id: msg.payment_id,
                        sequence_number: expected_sequence,
                        scriptpubkey_signature: msg.scriptpubkey_signature,
                        preimage: msg.preimage,
                    },
                );
                let fulfill_message = DepositsMessage::LedgerUpdate(update_msg);

                // Use append_mut_with_metadata to atomically get prev_hash, new_hash, and sequence_number
                // This prevents race conditions where another thread could append between operations
                // Returns 0-based sequence number for broadcasting
                let (prev_hash, new_hash, broadcast_seq) = ledger.append_v1_mut_with_metadata(fulfill_message.clone())?;

                found_result = Some((*partner, prev_hash, new_hash, fulfill_message, broadcast_seq));
                break;
            }
            found_result.ok_or(DepositsError::DepositNotFound)?
        };

        // STAGE 2: Send message fire-and-forget (no ACK wait needed)
        let message_hash = self.calculate_message_hash(&fulfill_message);
        let message_for_broadcast = fulfill_message.clone();

        // IMPORTANT: Insert into sent_messages_for_broadcast BEFORE send_message
        // to avoid race condition where ACK arrives before we set new_hash.
        // send_message inserts with [0u8; 32] placeholder, but we need the real hash.
        {
            let mut sent_messages = self.sent_messages_for_broadcast.lock().unwrap();
            sent_messages.insert(message_hash, (self.our_node_id, partner_node_id, message_for_broadcast.clone(), prev_hash, new_hash, broadcast_seq));
        }

        if let Err(e) = self.send_message(partner_node_id, fulfill_message) {
            log_error!(self.logger, "Failed to send fulfill message: {}", e);
        }

        // STAGE 3: Persist ledger
        {
            let ledgers = self.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id)) {
                let ledger = ledger_arc.read().unwrap();
                self.persist_ledger_state(&*ledger)?;
            }
        }

        // NOTE: Do NOT broadcast here. The entry in sent_messages_for_broadcast must remain
        // until handle_received_ack updates partner_deepest_ack_hash. The ACK handler will
        // broadcast after updating the ack hash, which allows flush_stale_updates to trigger
        // the commitment update.

        log_info!(self.logger, "✅ FULFILL complete: {} msat from deposit {} (payment {:02x?})",
                 msg.amount, msg.pubkey, &msg.payment_id[0..4]);

        Ok(())
    }

    /// Handle sending payment failure (fire-and-forget version)
    /// Payment failed, this just unlocks the balance in the ledger
    pub async fn handle_sending_fail_payment_async(
        &self,
        msg: crate::wire::messages::SendingFailPaymentMsg,
    ) -> Result<(), DepositsError> {
        log_info!(self.logger, "🔵 FAIL: payment_id={:02x?}, pubkey={}, amount={}",
                 &msg.payment_id[0..4], msg.pubkey, msg.amount);

        // STAGE 1: Validate and apply locally (optimistic - unlock balance immediately)
        let (partner_node_id, prev_hash, new_hash, msg, broadcast_seq) = {
            let mut payment_locks = self.payment_locks.lock().unwrap();
            let ledgers = self.ledgers.lock().unwrap();

            // Validate payment lock
            let (locked_pubkey, _) = payment_locks.get(&msg.payment_id)
                .ok_or(DepositsError::PaymentNotLocked)?;

            if *locked_pubkey != msg.pubkey {
                return Err(DepositsError::PaymentAmountMismatch);
            }

            // Find ledger containing this deposit by searching all ledgers
            let mut found_result = None;
            for ((op, partner), ledger_arc) in ledgers.iter() {
                if *op != self.our_node_id {
                    continue;
                }
                let mut ledger = ledger_arc.write().unwrap();
                if !ledger.state.deposits.contains_key(&msg.pubkey) {
                    continue; // Deposit not in this ledger, check next one
                }

                // Found the ledger with this deposit - process it
                payment_locks.remove(&msg.payment_id);
                ledger.state.last_updated = deposits_core::time_utils::now_unix_timestamp();

                // Compute sequence number BEFORE building the message (for validation in append)
                // The message's sequence_number must match ledger.history.len() at append time
                let expected_sequence = ledger.history.len() as u64;

                // Build the message with the correct sequence number
                let msg = crate::wire::messages::SendingFailPaymentMsg {
                    pubkey: msg.pubkey,
                    amount: msg.amount,
                    payment_id: msg.payment_id,
                    sequence_number: expected_sequence,
                };

                // Use append_mut_with_metadata to atomically get prev_hash, new_hash, and sequence_number
                // This prevents race conditions where another thread could append between operations
                // Returns 0-based sequence number for broadcasting
                let update_msg = LedgerUpdateMsg::new_with_operation(
                    ledger.operator_key(),
                    ledger.partner_key(),
                    LedgerOperation::PaymentFail {
                        pubkey: msg.pubkey,
                        amount: msg.amount,
                        payment_id: msg.payment_id,
                        sequence_number: msg.sequence_number,
                    },
                );
                let (prev_hash, new_hash, broadcast_seq) = ledger.append_v1_mut_with_metadata(DepositsMessage::LedgerUpdate(update_msg))?;

                found_result = Some((*partner, prev_hash, new_hash, msg, broadcast_seq));
                break;
            }
            found_result.ok_or(DepositsError::DepositNotFound)?
        };

        // STAGE 2: Send message fire-and-forget (no ACK wait needed)
        let fail_update_msg = LedgerUpdateMsg::new_with_operation(
            self.our_node_id,
            partner_node_id,
            LedgerOperation::PaymentFail {
                pubkey: msg.pubkey,
                amount: msg.amount,
                payment_id: msg.payment_id,
                sequence_number: msg.sequence_number,
            },
        );
        let message = DepositsMessage::LedgerUpdate(fail_update_msg);
        let message_hash = self.calculate_message_hash(&message);
        let message_for_broadcast = message.clone();

        // IMPORTANT: Insert into sent_messages_for_broadcast BEFORE send_message
        // to avoid race condition where ACK arrives before we set new_hash.
        // send_message inserts with [0u8; 32] placeholder, but we need the real hash.
        {
            let mut sent_messages = self.sent_messages_for_broadcast.lock().unwrap();
            sent_messages.insert(message_hash, (self.our_node_id, partner_node_id, message_for_broadcast.clone(), prev_hash, new_hash, broadcast_seq));
        }

        if let Err(e) = self.send_message(partner_node_id, message) {
            log_error!(self.logger, "Failed to send fail message: {}", e);
        }

        // STAGE 3: Persist ledger
        {
            let ledgers = self.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id)) {
                let ledger = ledger_arc.read().unwrap();
                self.persist_ledger_state(&*ledger)?;
            }
        }

        // NOTE: Do NOT broadcast here. The entry in sent_messages_for_broadcast must remain
        // until handle_received_ack updates partner_deepest_ack_hash. The ACK handler will
        // broadcast after updating the ack hash, which allows flush_stale_updates to trigger
        // the commitment update.

        log_info!(self.logger, "✅ FAIL complete: {} msat unlocked for deposit {} (payment {:02x?})",
                 msg.amount, msg.pubkey, &msg.payment_id[0..4]);

        Ok(())
    }

    /// Handle sending payment lock message - locks balance to prevent double spending
    /// Note: The sequence_number in msg is ignored - it's assigned atomically from the ledger
    pub fn handle_sending_lock_payment(&self, msg: crate::wire::messages::SendingLockPaymentMsg) -> Result<(), DepositsError> {
        // LOCK ORDERING: Always acquire payment_locks BEFORE ledgers to prevent deadlock
        let mut payment_locks = self.payment_locks.lock().unwrap();
        let ledgers = self.ledgers.lock().unwrap();

        // Find the deposit and lock the balance
        for ledger_arc in ledgers.values() {
            let mut ledger = ledger_arc.write().unwrap();

            // Validate sufficient balance (scoped to release borrow)
            // Continue to next ledger if deposit not found in this one
            {
                if let Some(deposit) = ledger.state.deposits.get(&msg.pubkey) {
                    let available_balance = deposit.balance.saturating_sub(deposit.locked_balance);
                    if available_balance < msg.amount {
                        return Err(DepositsError::InsufficientBalance);
                    }
                } else {
                    continue; // Deposit not in this ledger, check next one
                }
            } // deposit borrow ends here

            // Compute sequence number BEFORE building the message (for validation in append)
            // The message's sequence_number must match ledger.history.len() at append time
            let expected_sequence = ledger.history.len() as u64;

            // Track this specific payment lock
            payment_locks.insert(msg.payment_id, (msg.pubkey, msg.amount));

            // Update timestamp to current time
            ledger.state.last_updated = deposits_core::time_utils::now_unix_timestamp();

            // Build V2 LedgerUpdate message with PaymentLock operation
            let update_msg = LedgerUpdateMsg::new_with_operation(
                ledger.operator_key(),
                ledger.partner_key(),
                LedgerOperation::PaymentLock {
                    pubkey: msg.pubkey,
                    amount: msg.amount,
                    payment_id: msg.payment_id,
                    sequence_number: expected_sequence,
                    scriptpubkey_signature: msg.scriptpubkey_signature,
                },
            );
            let lock_message = DepositsMessage::LedgerUpdate(update_msg);

            // Use append_mut_with_metadata to atomically get prev_hash, new_hash, and sequence_number
            // This prevents race conditions where another thread could append between operations
            let (prev_hash, new_hash, sequence_number) = ledger.append_v1_mut_with_metadata(lock_message.clone()).map_err(|e| {
                log_error!(self.logger, "Failed to append PaymentLock update: {}", e);
                e
            })?;

            log_info!(self.logger, "Locked {} msat from deposit {} for payment {:?}",
                     msg.amount, msg.pubkey, &msg.payment_id[0..8]);

            // Notify partner about the lock
            let partner_node_id = ledger.partner_key();
            let operator_id = ledger.operator_key();
            drop(ledger); // Release write lock before sending message
            drop(ledgers); // Release ledgers lock
            drop(payment_locks); // Release payment_locks

            let message_hash = self.calculate_message_hash(&lock_message);
            let lock_message_for_broadcast = lock_message.clone();

            // IMPORTANT: Insert into sent_messages_for_broadcast BEFORE send_message
            // to avoid race condition where ACK arrives before we set new_hash.
            // send_message inserts with [0u8; 32] placeholder, but we need the real hash.
            {
                println!("🟣 PRE-INSERT SENT_MESSAGES: hash={:02x?}, type={:#06x}, prev_hash={:02x?}, new_hash={:02x?}, seq={}",
                    &message_hash[0..4], lock_message_for_broadcast.message_type(), &prev_hash[0..8], &new_hash[0..8], sequence_number);
                let mut sent_messages = self.sent_messages_for_broadcast.lock().unwrap();
                sent_messages.insert(message_hash, (operator_id, partner_node_id, lock_message_for_broadcast.clone(), prev_hash, new_hash, sequence_number));
            }

            // Fire-and-forget: Send message without waiting for ACK
            // Lock is enforced locally, partner will ACK asynchronously
            // This doesn't stall the pipeline - other operations can proceed
            if let Err(e) = self.send_message(partner_node_id, lock_message) {
                log_error!(self.logger, "Failed to send payment lock message: {}", e);
            }

            // NOTE: Do NOT broadcast here. The entry in sent_messages_for_broadcast must remain
            // until handle_received_ack updates partner_deepest_ack_hash. The ACK handler will
            // broadcast after updating the ack hash, which allows flush_stale_updates to trigger
            // the commitment update.

            return Ok(());
        }

        Err(DepositsError::DepositNotFound)
    }

    /// Handle sending payment fulfillment - permanently deducts locked balance
    /// DEPRECATED: This sync version commits changes BEFORE receiving ACK and doesn't broadcast to auditors.
    /// Use handle_sending_fulfill_payment_async() instead for proper ACK handling and audit broadcasts.
    #[deprecated(note = "Use handle_sending_fulfill_payment_async() - this version commits before ACK")]
    pub fn handle_sending_fulfill_payment(&self, _msg: crate::wire::messages::SendingFulfillPaymentMsg) -> Result<(), DepositsError> {
        Err(DepositsError::InvalidState(
            "handle_sending_fulfill_payment is deprecated - use handle_sending_fulfill_payment_async instead".to_string()
        ))
    }

    /// Handle sending payment failure - releases locked balance back to available
    pub fn handle_sending_fail_payment(&self, msg: crate::wire::messages::SendingFailPaymentMsg) -> Result<(), DepositsError> {
        // LOCK ORDERING: Always acquire payment_locks BEFORE ledgers to prevent deadlock
        let mut payment_locks = self.payment_locks.lock().unwrap();
        let ledgers = self.ledgers.lock().unwrap();

        // Check if payment was locked
        if let Some((locked_pubkey, locked_amount)) = payment_locks.remove(&msg.payment_id) {
            // Verify locked pubkey matches
            if locked_pubkey != msg.pubkey {
                log_error!(self.logger, "Payment pubkey mismatch: locked={}, fail={}",
                          locked_pubkey, msg.pubkey);
                return Err(DepositsError::PaymentAmountMismatch);
            }

            // Find the deposit and reduce locked balance
            for ledger_arc in ledgers.values() {
                let mut ledger = ledger_arc.write().unwrap();
                if ledger.state.deposits.contains_key(&msg.pubkey) {
                    // Update timestamp to current time
                    ledger.state.last_updated = deposits_core::time_utils::now_unix_timestamp();

                    // Capture prev_hash before applying update
                    let prev_hash = ledger.tail_hash();

                    // Create V2 LedgerUpdate message
                    let update_msg = LedgerUpdateMsg::new_with_operation(
                        ledger.operator_key(),
                        ledger.partner_key(),
                        LedgerOperation::PaymentFail {
                            pubkey: msg.pubkey,
                            amount: msg.amount,
                            payment_id: msg.payment_id,
                            sequence_number: msg.sequence_number,
                        },
                    );
                    let fail_message = DepositsMessage::LedgerUpdate(update_msg);

                    // Apply the update (this modifies state and records in history) and capture new_hash
                    let new_hash = ledger.append_v1_mut(fail_message.clone()).map_err(|e| {
                        log_error!(self.logger, "Failed to apply PaymentFail update: {}", e);
                        e
                    })?;
                    let chain_index = (ledger.history.len() - 1) as u64; // 0-based (index of just-appended entry)

                    log_info!(self.logger, "Payment failed: {} msat unlocked for deposit {} (payment {:?})",
                             locked_amount, msg.pubkey, &msg.payment_id[0..8]);

                    // Notify partner about the failure
                    let partner_node_id = ledger.partner_key();
                    let operator_id = ledger.operator_key();
                    drop(ledger); // Release write lock before sending message
                    drop(ledgers); // Release ledgers lock
                    drop(payment_locks); // Release payment_locks

                    let message_hash = self.calculate_message_hash(&fail_message);
                    let fail_message_for_broadcast = fail_message.clone();

                    // Insert into sent_messages_for_broadcast BEFORE send_message
                    {
                        let mut sent_messages = self.sent_messages_for_broadcast.lock().unwrap();
                        sent_messages.insert(message_hash, (operator_id, partner_node_id, fail_message_for_broadcast, prev_hash, new_hash, chain_index));
                    }

                    if let Err(e) = self.send_message(partner_node_id, fail_message) {
                        log_error!(self.logger, "Failed to notify partner about payment failure: {}", e);
                    }

                    // Broadcast SignedAuditUpdate to other partners/auditors
                    if let Err(e) = self.broadcast_message_to_other_partners(message_hash, partner_node_id, None) {
                        log_error!(self.logger, "Failed to broadcast PaymentFail: {:?}", e);
                    }

                    return Ok(());
                }
            }
        }

        Err(DepositsError::PaymentNotLocked)
    }
}
