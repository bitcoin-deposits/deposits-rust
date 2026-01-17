// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! ACK handling for the Bitcoin Deposits protocol.
//!
//! This module contains the handler for acknowledgment messages, extracted from core.rs
//! to improve maintainability.

use bitcoin::secp256k1::PublicKey;

use super::core::DepositsHandler;
use deposits_core::DepositsError;
use lightning::{log_debug, log_error};
use lightning::util::logger::Logger as LdkLogger;

use std::ops::Deref;

impl<L: Deref + Clone> DepositsHandler<L>
where
    L::Target: LdkLogger,
{
    /// Handle received acknowledgment message
    pub(super) fn handle_received_ack(&self, ack_msg: super::messages::AckMsg, sender: PublicKey) -> Result<(), DepositsError> {
        // First, notify any waiting threads
        let result = if ack_msg.success {
            Ok(())
        } else {
            Err(ack_msg.error_message.clone().unwrap_or_else(|| "Message rejected by peer".to_string()))
        };

        // Check if we have a pending oneshot ACK waiting for this message hash
        let oneshot_sender = {
            let mut pending_oneshot_acks = self.pending_oneshot_acks.lock().unwrap();
            pending_oneshot_acks.remove(&ack_msg.message_hash)
        };

        if let Some(oneshot_tx) = oneshot_sender {
            // Send result to oneshot channel
            let _ = oneshot_tx.send(result.clone());
        }

        // Check if we have a pending cosignature request waiting for this message hash
        let cosignature_sender = {
            let mut pending_cosignature_requests = self.pending_cosignature_requests.lock().unwrap();
            pending_cosignature_requests.remove(&ack_msg.message_hash)
        };

        if let Some(cosig_tx) = cosignature_sender {
            // Send cosignature if present and ACK is successful
            let cosig_result: Result<Vec<u8>, String> = if ack_msg.success {
                if let Some(ref signature) = ack_msg.cosignature {
                    Ok(signature.to_vec())
                } else {
                    Err("ACK succeeded but no cosignature provided".to_string())
                }
            } else {
                Err(ack_msg.error_message.clone().unwrap_or_else(|| "Cosigning rejected by peer".to_string()))
            };

            let _ = cosig_tx.send(cosig_result);

            log_debug!(
                self.logger,
                "Notified cosignature waiting thread for ACK from {} with hash {:02x?}: success={}",
                sender,
                &ack_msg.message_hash[0..8],
                ack_msg.success
            );
        }

        // Also handle through the ledger system (existing functionality)
        let ledgers = self.ledgers.lock().unwrap();

        // ACK can be for either:
        // 1. A ledger where sender is operator: (sender, self.our_node_id)
        // 2. A ledger where we are operator: (self.our_node_id, sender)
        let ledger_arc = ledgers.get(&(sender, self.our_node_id))
            .or_else(|| ledgers.get(&(self.our_node_id, sender)));

        if let Some(ledger_arc) = ledger_arc {
            let ledger = ledger_arc.read().unwrap();

            println!("🟢 HANDLE_ACK: Checking ledger for hash {:02x?} from {}", &ack_msg.message_hash[0..4], sender);

            // Check and remove pending ACK
            // Try both original message_hash and partner-specific hash (for messages like CollateralStatus
            // that are sent to multiple partners with the same content)
            let partner_specific_hash = Self::create_partner_specific_hash(&ack_msg.message_hash, &sender);
            let (original_message_type, lookup_hash) = {
                let mut pending_acks = self.pending_acks.lock().unwrap();
                // Try original hash first
                if let Some((msg_type, _timestamp)) = pending_acks.remove(&ack_msg.message_hash) {
                    (Some(msg_type), ack_msg.message_hash)
                } else if let Some((msg_type, _timestamp)) = pending_acks.remove(&partner_specific_hash) {
                    // Fallback to partner-specific hash
                    println!("🟡 HANDLE_ACK: Found pending ACK using partner-specific hash {:02x?}", &partner_specific_hash[0..4]);
                    (Some(msg_type), partner_specific_hash)
                } else {
                    (None, ack_msg.message_hash)
                }
            };

            if let Some(original_message_type) = original_message_type {
                println!("🟢 HANDLE_ACK: Found pending ACK, type={}, success={}", original_message_type, ack_msg.success);

                if ack_msg.success {
                    // NOTE: We do NOT mark the ledger as Committed here!
                    // The async caller (e.g., add_deposit_async) will apply the actual change
                    // and THEN mark it as committed. Marking it committed here would create
                    // a race condition where the ledger is committed with the OLD state
                    // before the change is applied.

                    // Get the current ledger hash for logging
                    let _ledger_hash = ledger.tail_hash();

                    log_debug!(self.logger, "Received successful ACK for message type {} from {} - caller will apply change and commit",
                              original_message_type, sender);

                    // BROADCAST TO ALL OTHER PARTNERS: Now that the message is acknowledged,
                    // broadcast it to all other partners as a third-party audit copy
                    drop(ledger); // Release ledger lock
                    drop(ledgers); // Release ledgers lock

                    // Get new_hash BEFORE broadcasting (broadcast removes the entry)
                    // For some message types (AddCollateralPartner, etc.), the operator appends AFTER
                    // receiving ACK, so new_hash won't be set yet. Skip in that case.
                    // Use lookup_hash which may be partner-specific for CollateralStatus messages.
                    let new_hash_opt = {
                        let sent_messages = self.sent_messages_for_broadcast.lock().unwrap();
                        sent_messages.get(&lookup_hash).map(|(_, _, _, _, new_hash, _)| *new_hash)
                    };

                    // Update partner_deepest_ack_hash BEFORE broadcasting
                    // (broadcast_message_to_other_partners removes entry from sent_messages_for_broadcast)
                    if let Some(new_hash) = new_hash_opt {
                        if new_hash != [0u8; 32] {
                            // Re-acquire ledger lock to update partner_deepest_ack_hash
                            let ledgers = self.ledgers.lock().unwrap();
                            // Check both ledger orientations - we might be operator or partner
                            let ledger_key = if ledgers.contains_key(&(self.our_node_id, sender)) {
                                Some((self.our_node_id, sender))
                            } else if ledgers.contains_key(&(sender, self.our_node_id)) {
                                Some((sender, self.our_node_id))
                            } else {
                                None
                            };

                            if let Some(key) = ledger_key {
                                if let Some(ledger_arc) = ledgers.get(&key) {
                                    let mut ledger = ledger_arc.write().unwrap();
                                    // Only update if this ACK advances the ack_hash
                                    if ledger.state.partner_deepest_ack_hash != new_hash {
                                        println!("[ACK] partner_deepest_ack_hash {:02x?} -> {:02x?}",
                                            &ledger.state.partner_deepest_ack_hash[0..4], &new_hash[0..4]);
                                        ledger.state.partner_deepest_ack_hash = new_hash;
                                        // Persist the updated ledger
                                        if let Err(e) = self.persist_ledger_state(&*ledger) {
                                            log_error!(self.logger, "Failed to persist ledger after ACK: {}", e);
                                        }

                                        // Mark for lazy sync if we're the operator
                                        // (Only operators send UpdateReserves)
                                        if key.0 == self.our_node_id {
                                            self.mark_for_lazy_sync(key.1);
                                        }
                                    }
                                }
                            }
                        } else {
                            println!("[ACK] skipping - new_hash is zeros (pending_acks path)");
                        }
                    }

                    // Now broadcast (this removes entry from sent_messages_for_broadcast)
                    // Use lookup_hash which may be partner-specific for CollateralStatus messages.
                    let should_broadcast = new_hash_opt.map(|h| h != [0u8; 32]).unwrap_or(false);
                    if should_broadcast {
                        println!("[ACK] broadcast hash={:02x?} sender={} has_sig={}",
                            &lookup_hash[0..4], sender, ack_msg.update_signature.is_some());
                        if let Err(e) = self.broadcast_message_to_other_partners(
                            lookup_hash,
                            sender,
                            ack_msg.update_signature,
                        ) {
                            log_error!(self.logger, "Failed to broadcast message to other partners: {}", e);
                            println!("[ACK] BROADCAST FAILED: {}", e);
                        } else {
                            println!("[ACK] BROADCAST OK hash={:02x?}", &lookup_hash[0..4]);
                        }
                    } else {
                        println!("[ACK] skip broadcast hash={:02x?} - new_hash not yet available", &lookup_hash[0..4]);
                        // Store partner signature so operator can use it when manually broadcasting
                        if let Some(sig) = ack_msg.update_signature {
                            let mut sigs = self.received_partner_signatures.lock().unwrap();
                            sigs.insert(lookup_hash, sig);
                            println!("[ACK] stored partner signature for later");
                        }
                    }
                } else {
                    log_error!(self.logger, "Received failed ACK for message type {} from {}: {}",
                              original_message_type, sender,
                              ack_msg.error_message.unwrap_or_else(|| "No error message provided".to_string()));
                }
            } else {
                // No pending ACK found - this could be a fire-and-forget message
                // (SendingLockPayment, SendingFulfillPayment, CollateralAttestation, etc.)
                // These don't add to pending_acks but DO add to sent_messages_for_broadcast
                println!("[ACK] no pending ACK, checking sent_messages hash={:02x?}", &ack_msg.message_hash[0..4]);

                if ack_msg.success {
                    // For fire-and-forget operations, we need to update partner_deepest_ack_hash
                    // when the ACK is received, so the background flush task will commit it.
                    let new_hash_opt = {
                        let sent_messages = self.sent_messages_for_broadcast.lock().unwrap();
                        sent_messages.get(&ack_msg.message_hash).map(|(_, _, _, _, new_hash, _)| *new_hash)
                    };

                    if let Some(new_hash) = new_hash_opt {
                        println!("[ACK] found in sent_messages new_hash={:02x?}", &new_hash[0..4]);

                        // Skip if new_hash is placeholder zeros - the update hasn't been applied yet
                        // The flush timer will retry later when the hash is properly set
                        if new_hash == [0u8; 32] {
                            println!("[ACK] skipping - new_hash is zeros (update not applied)");
                            // Don't clean up the entry - we'll need it when the update is applied
                        } else {
                            // Release existing locks before re-acquiring
                            drop(ledger);
                            drop(ledgers);

                            // Re-acquire ledger lock to update partner_deepest_ack_hash
                            let ledgers = self.ledgers.lock().unwrap();
                            // Check both ledger orientations - we might be operator or partner
                            let ledger_key = if ledgers.contains_key(&(self.our_node_id, sender)) {
                                Some((self.our_node_id, sender))
                            } else if ledgers.contains_key(&(sender, self.our_node_id)) {
                                Some((sender, self.our_node_id))
                            } else {
                                None
                            };

                            if let Some(key) = ledger_key {
                                if let Some(ledger_arc) = ledgers.get(&key) {
                                    let mut ledger = ledger_arc.write().unwrap();
                                    // Only update if this ACK advances the ack_hash
                                    if ledger.state.partner_deepest_ack_hash != new_hash {
                                        println!("[ACK] partner_deepest_ack_hash {:02x?} -> {:02x?} (fire-and-forget)",
                                            &ledger.state.partner_deepest_ack_hash[0..4], &new_hash[0..4]);
                                        ledger.state.partner_deepest_ack_hash = new_hash;
                                        // Persist the updated ledger
                                        if let Err(e) = self.persist_ledger_state(&*ledger) {
                                            log_error!(self.logger, "Failed to persist ledger after fire-and-forget ACK: {}", e);
                                        }

                                        // Mark for lazy sync if we're the operator
                                        // (Only operators send UpdateReserves)
                                        if key.0 == self.our_node_id {
                                            self.mark_for_lazy_sync(key.1);
                                        }
                                    }
                                }
                            }

                            // Broadcast SignedAuditUpdate to channel partner and quorum members
                            // IMPORTANT: Must happen BEFORE cleanup (broadcast reads from sent_messages_for_broadcast)
                            println!("[ACK] broadcast (fire-and-forget) hash={:02x?} sender={} has_sig={}",
                                &ack_msg.message_hash[0..4], sender, ack_msg.update_signature.is_some());
                            if let Err(e) = self.broadcast_message_to_other_partners(
                                ack_msg.message_hash,
                                sender,
                                ack_msg.update_signature,
                            ) {
                                log_error!(self.logger, "Failed to broadcast fire-and-forget message to partners: {}", e);
                                println!("[ACK] BROADCAST FAILED (fire-and-forget): {}", e);
                            } else {
                                println!("[ACK] BROADCAST OK (fire-and-forget) hash={:02x?}", &ack_msg.message_hash[0..4]);
                            }

                            // Clean up the entry from sent_messages_for_broadcast now that ACK is processed
                            // NOTE: broadcast_message_to_other_partners may have already removed it
                            {
                                let mut sent_messages = self.sent_messages_for_broadcast.lock().unwrap();
                                sent_messages.remove(&ack_msg.message_hash);
                            }
                        }
                    } else {
                        println!("[ACK] not found in sent_messages hash={:02x?}", &ack_msg.message_hash[0..4]);
                        log_debug!(self.logger, "Received ACK for message hash {:02x?} from {} (no ledger tracking)",
                                  &ack_msg.message_hash[0..8], sender);
                    }
                }
            }
        } else {
            println!("[ACK] NO LEDGER for sender {}", sender);
        }

        Ok(())
    }
}
