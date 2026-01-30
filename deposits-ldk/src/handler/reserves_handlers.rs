// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Reserves handlers for the Bitcoin Deposits protocol.
//!
//! This module contains handlers for reserves operations, extracted from core.rs
//! to improve maintainability.

use bitcoin::secp256k1::PublicKey;

use super::core::DepositsHandler;
use deposits_core::DepositsError;
use super::messages::{DepositsMessage, LedgerUpdateMsg, LedgerUpdateMsgExt, LedgerOperation};
use super::ledger_ext::LedgerExt;
use deposits_core::{log_debug, log_error, log_info};
use lightning::util::logger::Logger as LdkLogger;

use std::ops::Deref;

impl<L: Deref + Clone + Send + Sync> DepositsHandler<L>
where
    L::Target: LdkLogger,
{
    /// Add reserves to a channel via proper protocol (sends ReservesIncrease message)
    pub fn add_reserves_to_channel(&self, partner_node_id: PublicKey, additional_reserves: u64) -> Result<(), DepositsError> {
        // Calculate absolute new_amount = current + additional_reserves
        let new_amount = {
            let ledgers = self.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id.to_string())) {
                let ledger = ledger_arc.read().unwrap();
                ledger.reserves_amount().saturating_add(additional_reserves)
            } else {
                return Err(DepositsError::LedgerNotFound);
            }
        };

        log_info!(
            self.logger,
            "Increasing reserves to {} sats (adding {}) for channel with {} via protocol",
            new_amount, additional_reserves, partner_node_id
        );

        // NOTE: prev_hash will be captured atomically at append time to avoid race conditions
        // Send ReservesIncrease message to partner (V2 format)
        let update_msg = LedgerUpdateMsg::new_with_operation(
            self.our_node_id,    // operator
            partner_node_id.to_string(),     // partner
            LedgerOperation::ReservesIncrease { new_amount },
        );
        let message = DepositsMessage::LedgerUpdate(update_msg);

        let message_hash = self.calculate_message_hash(&message);
        let message_type = message.message_type();
        let message_for_broadcast = message.clone();

        // Track pending ACK in ledger BEFORE sending (so handle_ack can find it)
        {
            let ledgers = self.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id.to_string())) {
                let _ledger = ledger_arc.write().unwrap();
                // Track pending ACK
                {
                    let mut pending_acks = self.pending_acks.lock().unwrap();
                    let timestamp = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    pending_acks.insert(message_hash, deposits_core::PendingAck {
                        message_type,
                        timestamp,
                        peer: partner_node_id,
                    });
                }
            }
        }

        // Send and wait for ACK
        self.send_message_with_oneshot_ack(partner_node_id, message, 30000)?;

        // After ACK, apply the update to our ledger - use append_mut_with_metadata to get
        // consistent prev_hash, new_hash, and sequence_number atomically (avoids race condition)
        let (prev_hash, new_hash, chain_index) = {
            let ledgers = self.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id.to_string())) {
                let mut ledger = ledger_arc.write().unwrap();
                let (prev, hash, seq) = ledger.append_mut_with_metadata(message_for_broadcast.clone())?;

                // CRITICAL: Retrieve partner signature from ACK and store it on the ledger update
                // This is needed for PORCUPINE validation - without it, partner_signature is [0u8; 64]
                {
                    let mut sigs = self.received_partner_signatures.lock().unwrap();
                    if let Some(partner_sig) = sigs.remove(&message_hash) {
                        if let Some(last_update) = ledger.history.last_mut() {
                            last_update.partner_signature = partner_sig;
                        }
                    }
                }

                // Update partner_deepest_ack_hash since partner just ACKed this update
                // This is needed BEFORE refresh_reserves_commitment can commit this hash
                ledger.state.partner_deepest_ack_hash = hash;

                self.persist_ledger_state(&*ledger)?;
                (prev, hash, seq)
            } else {
                return Err(DepositsError::DepositNotFound);
            }
        };

        // Update sent_messages_for_broadcast with correct new_hash
        // (entry should already exist from send_message pre-insert)
        {
            let mut sent_messages = self.sent_messages_for_broadcast.lock().unwrap();
            // Always insert/update - insert will replace if key exists
            sent_messages.insert(message_hash, (self.our_node_id, partner_node_id.to_string(), message_for_broadcast.clone(), prev_hash, new_hash, chain_index));
        }

        // Now broadcast with correct hashes
        if let Err(e) = self.broadcast_message_to_other_partners(message_hash, partner_node_id, None) {
            log_error!(self.logger, "Failed to broadcast after update: {}", e);
        }

        // ReservesIncrease is an amount-changing operation - sync commitment immediately
        // Cancel any pending lazy sync since we're syncing now
        self.cancel_lazy_sync(partner_node_id);
        if let Err(e) = self.refresh_reserves_commitment(partner_node_id) {
            log_error!(
                self.logger,
                "❌ HASH_STRATEGY: Failed to sync commitment after ReservesIncrease: {}",
                e
            );
        } else {
            log_debug!(
                self.logger,
                "✅ HASH_STRATEGY: Commitment synced after ReservesIncrease"
            );
        }

        log_info!(self.logger, "Successfully added {} sats to reserves via protocol", additional_reserves);
        Ok(())
    }

    /// Reduce reserves from a channel via proper protocol (sends ReservesDecrease message)
    pub fn reduce_reserves_from_channel(&self, partner_node_id: PublicKey, reduction_amount: u64) -> Result<(), DepositsError> {
        // Calculate absolute new_amount = current - reduction_amount
        let new_amount = {
            let ledgers = self.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id.to_string())) {
                let ledger = ledger_arc.read().unwrap();
                ledger.reserves_amount().saturating_sub(reduction_amount)
            } else {
                return Err(DepositsError::LedgerNotFound);
            }
        };

        log_info!(
            self.logger,
            "Reducing reserves to {} sats (removing {}) for channel with {} via protocol",
            new_amount, reduction_amount, partner_node_id
        );

        // NOTE: prev_hash will be captured atomically at append time to avoid race conditions
        // Send ReservesDecrease message to partner (V2 format)
        let update_msg = LedgerUpdateMsg::new_with_operation(
            self.our_node_id,    // operator
            partner_node_id.to_string(),     // partner
            LedgerOperation::ReservesDecrease { new_amount },
        );
        let message = DepositsMessage::LedgerUpdate(update_msg);

        let message_hash = self.calculate_message_hash(&message);
        let message_type = message.message_type();
        let message_for_broadcast = message.clone();

        // Track pending ACK in ledger BEFORE sending (so handle_ack can find it)
        {
            let ledgers = self.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id.to_string())) {
                let _ledger = ledger_arc.write().unwrap();
                // Track pending ACK
                {
                    let mut pending_acks = self.pending_acks.lock().unwrap();
                    let timestamp = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    pending_acks.insert(message_hash, deposits_core::PendingAck {
                        message_type,
                        timestamp,
                        peer: partner_node_id,
                    });
                }
            }
        }

        // Send and wait for ACK
        self.send_message_with_oneshot_ack(partner_node_id, message, 30000)?;

        // After ACK, apply the update to our ledger - use append_mut_with_metadata to get
        // consistent prev_hash, new_hash, and sequence_number atomically (avoids race condition)
        let (prev_hash, new_hash, chain_index) = {
            let ledgers = self.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id.to_string())) {
                let mut ledger = ledger_arc.write().unwrap();
                let (prev, hash, seq) = ledger.append_mut_with_metadata(message_for_broadcast.clone())?;

                // CRITICAL: Retrieve partner signature from ACK and store it on the ledger update
                {
                    let mut sigs = self.received_partner_signatures.lock().unwrap();
                    if let Some(partner_sig) = sigs.remove(&message_hash) {
                        if let Some(last_update) = ledger.history.last_mut() {
                            last_update.partner_signature = partner_sig;
                        }
                    }
                }

                // Update partner_deepest_ack_hash since partner just ACKed this update
                ledger.state.partner_deepest_ack_hash = hash;

                self.persist_ledger_state(&*ledger)?;
                (prev, hash, seq)
            } else {
                return Err(DepositsError::DepositNotFound);
            }
        };

        // Update sent_messages_for_broadcast with correct new_hash
        // (entry should already exist from send_message pre-insert)
        {
            let mut sent_messages = self.sent_messages_for_broadcast.lock().unwrap();
            // Always insert/update - insert will replace if key exists
            sent_messages.insert(message_hash, (self.our_node_id, partner_node_id.to_string(), message_for_broadcast.clone(), prev_hash, new_hash, chain_index));
        }

        // Now broadcast with correct hashes
        if let Err(e) = self.broadcast_message_to_other_partners(message_hash, partner_node_id, None) {
            log_error!(self.logger, "Failed to broadcast after update: {}", e);
        }

        // ReservesDecrease is an amount-changing operation - sync commitment immediately
        // Cancel any pending lazy sync since we're syncing now
        self.cancel_lazy_sync(partner_node_id);
        if let Err(e) = self.refresh_reserves_commitment(partner_node_id) {
            log_error!(
                self.logger,
                "❌ HASH_STRATEGY: Failed to sync commitment after ReservesDecrease: {}",
                e
            );
        } else {
            log_debug!(
                self.logger,
                "✅ HASH_STRATEGY: Commitment synced after ReservesDecrease"
            );
        }

        log_info!(self.logger, "Successfully reduced {} sats from reserves via protocol", reduction_amount);
        Ok(())
    }
}
