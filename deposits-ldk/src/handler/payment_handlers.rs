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
use deposits_core::types::{DepositId, DescriptorWitness, compute_deposit_id};
use lightning::util::logger::Logger as LdkLogger;
use bitcoin::secp256k1::PublicKey;
use std::str::FromStr;

use std::ops::Deref;

/// Helper to convert a PublicKey to a descriptor and compute deposit_id
fn pubkey_to_deposit_id(pubkey: &PublicKey) -> (DepositId, String) {
    let descriptor = format!("pk({})", hex::encode(pubkey.serialize()));
    let deposit_id = compute_deposit_id(&descriptor);
    (deposit_id, descriptor)
}

/// Helper to convert a 64-byte signature to a DescriptorWitness
fn sig_to_witness(signature: [u8; 64]) -> DescriptorWitness {
    DescriptorWitness {
        stack: vec![signature.to_vec()],
    }
}

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
        let (deposit_id, _descriptor) = pubkey_to_deposit_id(&msg.pubkey);
        log_info!(self.logger, "🔵 FULFILL: payment_id={:02x?}, deposit_id={:02x?}, amount={}",
                 &msg.payment_id[0..4], &deposit_id[0..4], msg.amount);

        // STAGE 1: Validate and apply locally (optimistic - payment already succeeded)
        let (partner_node_id, reserves_id_str, prev_hash, new_hash, fulfill_message, broadcast_seq) = {
            let mut payment_locks = self.payment_locks.lock().unwrap();
            let ledgers = self.ledgers.lock().unwrap();

            // Validate payment lock
            let (locked_deposit_id, locked_amount) = payment_locks.get(&msg.payment_id)
                .ok_or(DepositsError::PaymentNotLocked)?;

            if *locked_deposit_id != deposit_id || *locked_amount != msg.amount {
                return Err(DepositsError::PaymentAmountMismatch);
            }

            // Find ledger containing this deposit by searching all ledgers
            let mut found_result = None;
            for ((op, reserves_id), ledger_arc) in ledgers.iter() {
                if *op != self.our_node_id {
                    continue;
                }
                let mut ledger = ledger_arc.write().unwrap();
                if !ledger.state.deposits.contains_key(&deposit_id) {
                    continue; // Deposit not in this ledger, check next one
                }

                // Parse reserves_id (partner pubkey string for LDK)
                let partner_pubkey = PublicKey::from_str(reserves_id)
                    .map_err(|_| DepositsError::InvalidPublicKey)?;

                // Found the ledger with this deposit - process it
                payment_locks.remove(&msg.payment_id);
                ledger.state.last_updated = deposits_core::time_utils::now_unix_timestamp();

                // Compute sequence number BEFORE building the message (for validation in append)
                // The message's sequence_number must match ledger.history.len() at append time
                let expected_sequence = ledger.history.len() as u64;

                // Build V2 LedgerUpdate message with InvoiceFulfill operation
                let update_msg = LedgerUpdateMsg::new_with_operation(
                    ledger.operator_key(),
                    ledger.reserves_key().to_string(),
                    LedgerOperation::InvoiceFulfill {
                        deposit_id,
                        amount: msg.amount,
                        payment_id: msg.payment_id,
                        sequence_number: expected_sequence,
                        witness: sig_to_witness(msg.scriptpubkey_signature),
                        preimage: msg.preimage,
                    },
                );
                let fulfill_message = DepositsMessage::LedgerUpdate(update_msg);

                // Use append_mut_with_metadata to atomically get prev_hash, new_hash, and sequence_number
                // This prevents race conditions where another thread could append between operations
                // Returns 0-based sequence number for broadcasting
                let (prev_hash, new_hash, broadcast_seq) = ledger.append_mut_with_metadata(fulfill_message.clone())?;

                found_result = Some((partner_pubkey, reserves_id.clone(), prev_hash, new_hash, fulfill_message, broadcast_seq));
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
            sent_messages.insert(message_hash, (self.our_node_id, partner_node_id.to_string(), message_for_broadcast.clone(), prev_hash, new_hash, broadcast_seq));
        }

        if let Err(e) = self.send_message(partner_node_id, fulfill_message) {
            log_error!(self.logger, "Failed to send fulfill message: {}", e);
        }

        // STAGE 3: Persist ledger
        {
            let ledgers = self.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, reserves_id_str)) {
                let ledger = ledger_arc.read().unwrap();
                self.persist_ledger_state(&*ledger)?;
            }
        }

        // NOTE: Do NOT broadcast here. The entry in sent_messages_for_broadcast must remain
        // until handle_received_ack updates partner_deepest_ack_hash. The ACK handler will
        // broadcast after updating the ack hash, which allows flush_stale_updates to trigger
        // the commitment update.

        log_info!(self.logger, "✅ FULFILL complete: {} msat from deposit {:02x?} (payment {:02x?})",
                 msg.amount, &deposit_id[0..4], &msg.payment_id[0..4]);

        Ok(())
    }

    /// Handle sending payment failure (fire-and-forget version)
    /// Payment failed, this just unlocks the balance in the ledger
    pub async fn handle_sending_fail_payment_async(
        &self,
        msg: crate::wire::messages::SendingFailPaymentMsg,
    ) -> Result<(), DepositsError> {
        let (deposit_id, _descriptor) = pubkey_to_deposit_id(&msg.pubkey);
        log_info!(self.logger, "🔵 FAIL: payment_id={:02x?}, deposit_id={:02x?}, amount={}",
                 &msg.payment_id[0..4], &deposit_id[0..4], msg.amount);

        // STAGE 1: Validate and apply locally (optimistic - unlock balance immediately)
        let (partner_pubkey, reserves_id_str, prev_hash, new_hash, expected_sequence, broadcast_seq) = {
            let mut payment_locks = self.payment_locks.lock().unwrap();
            let ledgers = self.ledgers.lock().unwrap();

            // Validate payment lock
            let (locked_deposit_id, _) = payment_locks.get(&msg.payment_id)
                .ok_or(DepositsError::PaymentNotLocked)?;

            if *locked_deposit_id != deposit_id {
                return Err(DepositsError::PaymentAmountMismatch);
            }

            // Find ledger containing this deposit by searching all ledgers
            let mut found_result = None;
            for ((op, reserves_id), ledger_arc) in ledgers.iter() {
                if *op != self.our_node_id {
                    continue;
                }
                let mut ledger = ledger_arc.write().unwrap();
                if !ledger.state.deposits.contains_key(&deposit_id) {
                    continue; // Deposit not in this ledger, check next one
                }

                // Parse reserves_id (partner pubkey string for LDK)
                let partner_pk = PublicKey::from_str(reserves_id)
                    .map_err(|_| DepositsError::InvalidPublicKey)?;

                // Found the ledger with this deposit - process it
                payment_locks.remove(&msg.payment_id);
                ledger.state.last_updated = deposits_core::time_utils::now_unix_timestamp();

                // Compute sequence number BEFORE building the message (for validation in append)
                // The message's sequence_number must match ledger.history.len() at append time
                let expected_sequence = ledger.history.len() as u64;

                // Use append_mut_with_metadata to atomically get prev_hash, new_hash, and sequence_number
                // This prevents race conditions where another thread could append between operations
                // Returns 0-based sequence number for broadcasting
                let update_msg = LedgerUpdateMsg::new_with_operation(
                    ledger.operator_key(),
                    ledger.reserves_key().to_string(),
                    LedgerOperation::InvoiceFail {
                        deposit_id,
                        amount: msg.amount,
                        payment_id: msg.payment_id,
                        sequence_number: expected_sequence,
                    },
                );
                let (prev_hash, new_hash, broadcast_seq) = ledger.append_mut_with_metadata(DepositsMessage::LedgerUpdate(update_msg))?;

                found_result = Some((partner_pk, reserves_id.clone(), prev_hash, new_hash, expected_sequence, broadcast_seq));
                break;
            }
            found_result.ok_or(DepositsError::DepositNotFound)?
        };

        // STAGE 2: Send message fire-and-forget (no ACK wait needed)
        let fail_update_msg = LedgerUpdateMsg::new_with_operation(
            self.our_node_id,
            reserves_id_str.clone(),
            LedgerOperation::InvoiceFail {
                deposit_id,
                amount: msg.amount,
                payment_id: msg.payment_id,
                sequence_number: expected_sequence,
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
            sent_messages.insert(message_hash, (self.our_node_id, partner_pubkey.to_string(), message_for_broadcast.clone(), prev_hash, new_hash, broadcast_seq));
        }

        if let Err(e) = self.send_message(partner_pubkey, message) {
            log_error!(self.logger, "Failed to send fail message: {}", e);
        }

        // STAGE 3: Persist ledger
        {
            let ledgers = self.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, reserves_id_str)) {
                let ledger = ledger_arc.read().unwrap();
                self.persist_ledger_state(&*ledger)?;
            }
        }

        // NOTE: Do NOT broadcast here. The entry in sent_messages_for_broadcast must remain
        // until handle_received_ack updates partner_deepest_ack_hash. The ACK handler will
        // broadcast after updating the ack hash, which allows flush_stale_updates to trigger
        // the commitment update.

        log_info!(self.logger, "✅ FAIL complete: {} msat unlocked for deposit {:02x?} (payment {:02x?})",
                 msg.amount, &deposit_id[0..4], &msg.payment_id[0..4]);

        Ok(())
    }

    /// Handle sending payment lock message - locks balance to prevent double spending
    /// Note: The sequence_number in msg is ignored - it's assigned atomically from the ledger
    pub fn handle_sending_lock_payment(&self, msg: crate::wire::messages::SendingLockPaymentMsg) -> Result<(), DepositsError> {
        let (deposit_id, _descriptor) = pubkey_to_deposit_id(&msg.pubkey);

        // LOCK ORDERING: Always acquire payment_locks BEFORE ledgers to prevent deadlock
        let mut payment_locks = self.payment_locks.lock().unwrap();
        let ledgers = self.ledgers.lock().unwrap();

        // Find the deposit and lock the balance
        for ledger_arc in ledgers.values() {
            let mut ledger = ledger_arc.write().unwrap();

            // Validate sufficient balance (scoped to release borrow)
            // Continue to next ledger if deposit not found in this one
            {
                if let Some(deposit) = ledger.state.deposits.get(&deposit_id) {
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

            // Track this specific payment lock using deposit_id
            payment_locks.insert(msg.payment_id, (deposit_id, msg.amount));

            // Update timestamp to current time
            ledger.state.last_updated = deposits_core::time_utils::now_unix_timestamp();

            // Build V2 LedgerUpdate message with InvoiceLock operation
            let update_msg = LedgerUpdateMsg::new_with_operation(
                ledger.operator_key(),
                ledger.reserves_key().to_string(),
                LedgerOperation::InvoiceLock {
                    deposit_id,
                    amount: msg.amount,
                    payment_id: msg.payment_id,
                    sequence_number: expected_sequence,
                    witness: sig_to_witness(msg.scriptpubkey_signature),
                },
            );
            let lock_message = DepositsMessage::LedgerUpdate(update_msg);

            // Use append_mut_with_metadata to atomically get prev_hash, new_hash, and sequence_number
            // This prevents race conditions where another thread could append between operations
            let (prev_hash, new_hash, sequence_number) = ledger.append_mut_with_metadata(lock_message.clone()).map_err(|e| {
                log_error!(self.logger, "Failed to append InvoiceLock update: {}", e);
                e
            })?;

            log_info!(self.logger, "Locked {} msat from deposit {:02x?} for payment {:?}",
                     msg.amount, &deposit_id[0..4], &msg.payment_id[0..8]);

            // Notify partner about the lock
            let partner_node_id_str = ledger.reserves_key().to_string();
            let operator_id = ledger.operator_key();
            drop(ledger); // Release write lock before sending message
            drop(ledgers); // Release ledgers lock
            drop(payment_locks); // Release payment_locks

            // Parse partner pubkey for send_message
            let partner_pubkey = PublicKey::from_str(&partner_node_id_str)
                .map_err(|_| DepositsError::InvalidPublicKey)?;

            let message_hash = self.calculate_message_hash(&lock_message);
            let lock_message_for_broadcast = lock_message.clone();

            // IMPORTANT: Insert into sent_messages_for_broadcast BEFORE send_message
            // to avoid race condition where ACK arrives before we set new_hash.
            // send_message inserts with [0u8; 32] placeholder, but we need the real hash.
            {
                let mut sent_messages = self.sent_messages_for_broadcast.lock().unwrap();
                sent_messages.insert(message_hash, ( operator_id, partner_node_id_str, lock_message_for_broadcast.clone(), prev_hash, new_hash, sequence_number));
            }

            // Fire-and-forget: Send message without waiting for ACK
            // Lock is enforced locally, partner will ACK asynchronously
            // This doesn't stall the pipeline - other operations can proceed
            if let Err(e) = self.send_message(partner_pubkey, lock_message) {
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
        let (deposit_id, _descriptor) = pubkey_to_deposit_id(&msg.pubkey);

        // LOCK ORDERING: Always acquire payment_locks BEFORE ledgers to prevent deadlock
        let mut payment_locks = self.payment_locks.lock().unwrap();
        let ledgers = self.ledgers.lock().unwrap();

        // Check if payment was locked
        if let Some((locked_deposit_id, locked_amount)) = payment_locks.remove(&msg.payment_id) {
            // Verify locked deposit_id matches
            if locked_deposit_id != deposit_id {
                log_error!(self.logger, "Payment deposit_id mismatch: locked={:02x?}, fail={:02x?}",
                          &locked_deposit_id[0..4], &deposit_id[0..4]);
                return Err(DepositsError::PaymentAmountMismatch);
            }

            // Find the deposit and reduce locked balance
            for ledger_arc in ledgers.values() {
                let mut ledger = ledger_arc.write().unwrap();
                if ledger.state.deposits.contains_key(&deposit_id) {
                    // Update timestamp to current time
                    ledger.state.last_updated = deposits_core::time_utils::now_unix_timestamp();

                    // Capture prev_hash before applying update
                    let prev_hash = ledger.tail_hash();

                    // Create V2 LedgerUpdate message
                    let update_msg = LedgerUpdateMsg::new_with_operation(
                        ledger.operator_key(),
                        ledger.reserves_key().to_string(),
                        LedgerOperation::InvoiceFail {
                            deposit_id,
                            amount: msg.amount,
                            payment_id: msg.payment_id,
                            sequence_number: msg.sequence_number,
                        },
                    );
                    let fail_message = DepositsMessage::LedgerUpdate(update_msg);

                    // Apply the update (this modifies state and records in history) and capture new_hash
                    let new_hash = ledger.append_mut(fail_message.clone()).map_err(|e| {
                        log_error!(self.logger, "Failed to apply InvoiceFail update: {}", e);
                        e
                    })?;
                    let chain_index = (ledger.history.len() - 1) as u64; // 0-based (index of just-appended entry)

                    log_info!(self.logger, "Payment failed: {} msat unlocked for deposit {:02x?} (payment {:?})",
                             locked_amount, &deposit_id[0..4], &msg.payment_id[0..8]);

                    // Notify partner about the failure
                    let partner_node_id_str = ledger.reserves_key().to_string();
                    let operator_id = ledger.operator_key();
                    drop(ledger); // Release write lock before sending message
                    drop(ledgers); // Release ledgers lock
                    drop(payment_locks); // Release payment_locks

                    // Parse partner pubkey for send_message
                    let partner_pubkey = PublicKey::from_str(&partner_node_id_str)
                        .map_err(|_| DepositsError::InvalidPublicKey)?;

                    let message_hash = self.calculate_message_hash(&fail_message);
                    let fail_message_for_broadcast = fail_message.clone();

                    // Insert into sent_messages_for_broadcast BEFORE send_message
                    {
                        let mut sent_messages = self.sent_messages_for_broadcast.lock().unwrap();
                        sent_messages.insert(message_hash, ( operator_id, partner_node_id_str, fail_message_for_broadcast, prev_hash, new_hash, chain_index));
                    }

                    if let Err(e) = self.send_message(partner_pubkey, fail_message) {
                        log_error!(self.logger, "Failed to notify partner about payment failure: {}", e);
                    }

                    // Broadcast SignedAuditUpdate to other partners/auditors
                    if let Err(e) = self.broadcast_message_to_other_partners(message_hash, partner_pubkey, None) {
                        log_error!(self.logger, "Failed to broadcast InvoiceFail: {:?}", e);
                    }

                    return Ok(());
                }
            }
        }

        Err(DepositsError::PaymentNotLocked)
    }
}
