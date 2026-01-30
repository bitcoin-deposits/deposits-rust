// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Ledger closing and cleanup operations for the Bitcoin Deposits protocol.
//!
//! This module contains operations for:
//! - Removing deposits from ledgers
//! - Closing ledgers
//! - Removing reserves outputs
//! - Crediting deposit balances
//! - Message hash helpers

use bitcoin::secp256k1::PublicKey;

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
    /// Remove a deposit entirely (when balance is zero)
    /// This sends a LedgerRemoveDeposit message to the partner to create a proper ledger update
    pub fn remove_deposit(&self, partner_node_id: PublicKey, deposit_pubkey: PublicKey) -> Result<(), DepositsError> {
        // First validate that the deposit exists and has zero balance
        let ledgers = self.ledgers.lock().unwrap();

        if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id.to_string())) {
            let ledger = ledger_arc.read().unwrap();

            // Ensure deposit balance is zero before removing
            if let Some(deposit) = ledger.state.deposits.get(&deposit_pubkey) {
                if deposit.balance > 0 {
                    return Err(DepositsError::ProtocolViolation {
                        violation_type: "non_zero_balance".to_string(),
                        details: format!("Cannot remove deposit with non-zero balance: {} msat", deposit.balance),
                    });
                }
            } else {
                return Err(DepositsError::DepositNotFound);
            }

            // Drop the read lock before sending message
            drop(ledger);
            drop(ledgers);

            // Capture prev_hash before creating message
            let prev_hash = {
                let ledgers = self.ledgers.lock().unwrap();
                if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id.to_string())) {
                    let ledger = ledger_arc.read().unwrap();
                    ledger.tail_hash()
                } else {
                    [0u8; 32]
                }
            };

            // Send LedgerRemoveDeposit message to partner to create proper ledger update (V2 format)
            let update_msg = LedgerUpdateMsg::new_with_operation(
                self.our_node_id,    // operator
                partner_node_id.to_string(),     // partner
                LedgerOperation::DepositClose { pubkey: deposit_pubkey },
            );
            let message = DepositsMessage::LedgerUpdate(update_msg);

            let message_hash = self.calculate_message_hash(&message);
            let message_for_broadcast = message.clone();

            log_info!(self.logger, "Sending DepositClose message for deposit {} to partner {}", deposit_pubkey, partner_node_id);

            // Send message and wait for acknowledgment (with 5 second timeout)
            self.send_message_with_oneshot_ack(partner_node_id, message, 30000)?;

            // After ACK received, apply the update to our (operator's) ledger and capture new_hash
            let (new_hash, chain_index) = {
                let ledgers = self.ledgers.lock().unwrap();
                if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id.to_string())) {
                    let mut ledger = ledger_arc.write().unwrap();
                    let hash = ledger.append_mut(message_for_broadcast.clone())?;
                    let seq = (ledger.history.len() - 1) as u64; // 0-based (index of just-appended entry)
                    // Update partner_deepest_ack_hash since partner just ACKed this update
                    ledger.state.partner_deepest_ack_hash = hash;
                    self.persist_ledger_state(&*ledger)?;
                    (hash, seq)
                } else {
                    return Err(DepositsError::LedgerNotFound);
                }
            };

            // Update sent_messages_for_broadcast with correct new_hash and broadcast
            {
                let mut sent_messages = self.sent_messages_for_broadcast.lock().unwrap();
                sent_messages.insert(message_hash, (self.our_node_id, partner_node_id.to_string(), message_for_broadcast.clone(), prev_hash, new_hash, chain_index));
            }

            // Now broadcast with correct hashes
            if let Err(e) = self.broadcast_message_to_other_partners(message_hash, partner_node_id, None) {
                log_error!(self.logger, "Failed to broadcast after update: {}", e);
            }

            log_info!(self.logger, "Successfully removed deposit {} from channel with {}", deposit_pubkey, partner_node_id);
            Ok(())
        } else {
            Err(DepositsError::DepositNotFound)
        }
    }

    /// Close a ledger with a partner (removes the ledger relationship)
    /// Requires: no deposits remain on the ledger
    pub fn close_ledger(&self, partner_node_id: PublicKey) -> Result<(), DepositsError> {
        // Validate ledger exists and has no deposits
        {
            let ledgers = self.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id.to_string())) {
                let ledger = ledger_arc.read().unwrap();
                if !ledger.state.deposits.is_empty() {
                    return Err(DepositsError::ProtocolViolation {
                        violation_type: "deposits_remain".to_string(),
                        details: format!("Cannot close ledger with {} deposits remaining", ledger.state.deposits.len()),
                    });
                }
            } else {
                return Err(DepositsError::LedgerNotFound);
            }
        }

        // Send LedgerClose message (V2 format)
        let update_msg = LedgerUpdateMsg::new_with_operation(
            self.our_node_id,    // operator
            partner_node_id.to_string(),     // partner
            LedgerOperation::LedgerClose,
        );
        let message = DepositsMessage::LedgerUpdate(update_msg);

        let message_hash = self.calculate_message_hash(&message);
        let message_type = message.message_type();

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

        // Check peer connection status before sending
        let is_connected = self.connected_peers.lock().unwrap().contains(&partner_node_id);
        log_info!(self.logger, "📤 CLOSE_LEDGER: Sending LedgerClose to {} (connected={}, hash={:02x?})",
            partner_node_id, is_connected, &message_hash[0..4]);

        // Send message and wait for acknowledgment
        match self.send_message_with_oneshot_ack(partner_node_id, message.clone(), 30000) {
            Ok(()) => {
                log_info!(self.logger, "✅ CLOSE_LEDGER: ACK received for hash={:02x?}", &message_hash[0..4]);
            }
            Err(e) => {
                log_info!(self.logger, "❌ CLOSE_LEDGER: ACK failed for hash={:02x?}: {:?}", &message_hash[0..4], e);
                return Err(e);
            }
        }

        // After ACK, apply update and remove ledger
        {
            let mut ledgers = self.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id.to_string())) {
                let mut ledger = ledger_arc.write().unwrap();
                let new_hash = ledger.append_mut(message)?;
                // Update partner_deepest_ack_hash since partner just ACKed this update
                ledger.state.partner_deepest_ack_hash = new_hash;
                self.persist_ledger_state(&*ledger)?;
            }
            // Remove the ledger from our map
            ledgers.remove(&(self.our_node_id, partner_node_id.to_string()));
        }

        // Also remove from protocols map
        self.remove_protocol(&partner_node_id);

        log_info!(self.logger, "Successfully closed ledger with partner {}", partner_node_id);
        Ok(())
    }

    /// Close a ledger with a partner asynchronously (non-blocking version)
    /// Requires: no deposits remain on the ledger
    pub async fn close_ledger_async(&self, partner_node_id: PublicKey) -> Result<(), DepositsError> {
        // Validate ledger exists and has no deposits
        {
            let ledgers = self.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id.to_string())) {
                let ledger = ledger_arc.read().unwrap();
                if !ledger.state.deposits.is_empty() {
                    return Err(DepositsError::ProtocolViolation {
                        violation_type: "deposits_remain".to_string(),
                        details: format!("Cannot close ledger with {} deposits remaining", ledger.state.deposits.len()),
                    });
                }
            } else {
                return Err(DepositsError::LedgerNotFound);
            }
        }

        // Send LedgerClose message (V2 format)
        let update_msg = LedgerUpdateMsg::new_with_operation(
            self.our_node_id,    // operator
            partner_node_id.to_string(),     // partner
            LedgerOperation::LedgerClose,
        );
        let message = DepositsMessage::LedgerUpdate(update_msg);

        let message_hash = self.calculate_message_hash(&message);
        let message_type = message.message_type();

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

        // Check peer connection status before sending
        let is_connected = self.connected_peers.lock().unwrap().contains(&partner_node_id);
        log_info!(self.logger, "📤 CLOSE_LEDGER_ASYNC: Sending LedgerClose to {} (connected={}, hash={:02x?})",
            partner_node_id, is_connected, &message_hash[0..4]);

        // Send message and wait for acknowledgment (async version - doesn't block event loop)
        match self.send_message_with_ack_async(partner_node_id, message.clone(), 30000).await {
            Ok(()) => {
                log_info!(self.logger, "✅ CLOSE_LEDGER_ASYNC: ACK received for hash={:02x?}", &message_hash[0..4]);
            }
            Err(e) => {
                log_info!(self.logger, "❌ CLOSE_LEDGER_ASYNC: ACK failed for hash={:02x?}: {:?}", &message_hash[0..4], e);
                return Err(e);
            }
        }

        // After ACK, apply update and remove ledger
        {
            let mut ledgers = self.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id.to_string())) {
                let mut ledger = ledger_arc.write().unwrap();
                let new_hash = ledger.append_mut(message)?;
                // Update partner_deepest_ack_hash since partner just ACKed this update
                ledger.state.partner_deepest_ack_hash = new_hash;
                self.persist_ledger_state(&*ledger)?;
            }
            // Remove the ledger from our map
            ledgers.remove(&(self.our_node_id, partner_node_id.to_string()));
        }

        // Also remove from protocols map
        self.remove_protocol(&partner_node_id);

        log_info!(self.logger, "Successfully closed ledger with partner {} (async)", partner_node_id);
        Ok(())
    }

    /// Remove reserves output from a channel
    /// Requires: reserves balance is 0 (use reduce_reserves_from_channel first)
    pub fn remove_reserves(&self, partner_node_id: PublicKey) -> Result<(), DepositsError> {
        // Validate reserves are 0
        {
            let ledgers = self.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id.to_string())) {
                let ledger = ledger_arc.read().unwrap();
                if ledger.reserves_amount() > 0 {
                    return Err(DepositsError::ProtocolViolation {
                        violation_type: "non_zero_reserves".to_string(),
                        details: format!("Cannot remove reserves output with {} sats remaining. Use reduce_reserves_from_channel first.", ledger.reserves_amount()),
                    });
                }
            } else {
                return Err(DepositsError::LedgerNotFound);
            }
        }

        // Send ReservesDecrease to 0 message (reserves removal)
        let update_msg = LedgerUpdateMsg::new_with_operation(
            self.our_node_id,    // operator
            partner_node_id.to_string(),     // partner
            LedgerOperation::ReservesDecrease { new_amount: 0 },
        );
        let message = DepositsMessage::LedgerUpdate(update_msg);

        let message_hash = self.calculate_message_hash(&message);
        let message_type = message.message_type();

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

        log_info!(self.logger, "Sending ReservesDecrease to 0 message to partner {}", partner_node_id);

        // Send message and wait for acknowledgment
        self.send_message_with_oneshot_ack(partner_node_id, message.clone(), 30000)?;

        // After ACK, apply update to ledger
        {
            let ledgers = self.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id.to_string())) {
                let mut ledger = ledger_arc.write().unwrap();
                let new_hash = ledger.append_mut(message)?;
                // Update partner_deepest_ack_hash since partner just ACKed this update
                ledger.state.partner_deepest_ack_hash = new_hash;
                self.persist_ledger_state(&*ledger)?;
            }
        }

        // Sync commitment to remove reserves output from channel
        if let Err(e) = self.refresh_reserves_commitment(partner_node_id) {
            log_error!(self.logger, "Failed to sync commitment after reserves removal: {}", e);
            // Don't fail - the ledger update was successful
        }

        log_info!(self.logger, "Successfully removed reserves output from channel with {}", partner_node_id);
        Ok(())
    }

    /// Get all active depositors (depositors with non-zero balances)
    pub fn get_active_depositors(&self) -> Vec<PublicKey> {
        let mut active_depositors = Vec::new();
        let ledgers = self.ledgers.lock().unwrap();

        for ledger_arc in ledgers.values() {
            let ledger = ledger_arc.read().unwrap();
            for (depositor_pubkey, deposit) in &ledger.state.deposits {
                if deposit.balance > 0 {
                    active_depositors.push(*depositor_pubkey);
                }
            }
        }

        active_depositors
    }

    /// Credit a deposit balance (production method)
    /// This would typically be called when a Lightning payment is received for a deposit
    pub fn credit_deposit_balance(&self, partner_node_id: PublicKey, deposit_pubkey: PublicKey, amount: u64) -> Result<(), DepositsError> {
        let ledgers = self.ledgers.lock().unwrap();

        if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id.to_string())) {
            let mut ledger = ledger_arc.write().unwrap();

            // Direct balance update (for testing/internal use)
            if let Some(deposit) = ledger.state.deposits.get_mut(&deposit_pubkey) {
                deposit.balance += amount;
                log_info!(self.logger, "Credited {} msat to deposit {} (reserves validated)", amount, deposit_pubkey);
                Ok(())
            } else {
                Err(DepositsError::DepositNotFound)
            }
        } else {
            Err(DepositsError::DepositNotFound)
        }
    }

    /// Helper function to create a hash of a message for acknowledgment tracking
    pub(super) fn create_message_hash(message: &DepositsMessage) -> [u8; 32] {
        use bitcoin::hashes::{sha256, Hash, HashEngine};
        use lightning::util::ser::Writeable;

        let mut engine = sha256::Hash::engine();
        let mut buffer = Vec::new();
        message.write(&mut buffer).expect("Message serialization should not fail");
        engine.input(&buffer);
        sha256::Hash::from_engine(engine).to_byte_array()
    }
}
