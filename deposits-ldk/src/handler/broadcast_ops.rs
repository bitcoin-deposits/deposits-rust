// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Broadcast operations for the Bitcoin Deposits protocol.
//!
//! This module contains operations for broadcasting signed updates to auditors
//! and other channel partners.

use bitcoin::secp256k1::PublicKey;

use super::core::DepositsHandler;
use super::ledger_ext::SignedLedgerUpdateLogExt;
use deposits_core::DepositsError;
use super::messages::{DepositsMessage, LedgerUpdateMsg, LedgerOperation};
use deposits_core::quorum::LedgerId;
use deposits_core::{log_debug, log_error, log_info};
use lightning::util::logger::Logger as LdkLogger;

use std::ops::Deref;

impl<L: Deref + Clone> DepositsHandler<L>
where
    L::Target: LdkLogger,
{
    /// This is used to send third-party audit copies after receiving an acknowledgment
    ///
    /// The partner_signature is included in ACKs (porcupine dance) and will be used
    /// to create the fully-signed update for broadcast.
    pub(super) fn broadcast_message_to_other_partners(
        &self,
        message_hash: [u8; 32],
        original_partner: PublicKey,
        partner_signature: Option<[u8; 64]>,
    ) -> Result<(), DepositsError> {

        // Check the message first (don't remove yet)
        let (operator_id, partner_id, original_message, stored_prev_hash, stored_new_hash, chain_index) = {
            let sent_messages = self.sent_messages_for_broadcast.lock().unwrap();

            match sent_messages.get(&message_hash) {
                Some((op, partner, msg, prev_hash, new_hash, idx)) => {
                    println!("🟡 BROADCAST: Retrieved from sent_messages_for_broadcast:");
                    println!("   Message type: {:#06x}", msg.message_type());
                    println!("   prev_hash: {:02x?}", &prev_hash[0..8]);
                    println!("   new_hash: {:02x?}", &new_hash[0..8]);
                    println!("   chain_index: {}", idx);

                    // Clone the data - we'll remove the entry at the end of this function
                    // after successfully broadcasting to all partners
                    (*op, *partner, msg.clone(), *prev_hash, *new_hash, *idx)
                }
                None => {
                    println!("🔴 BROADCAST: No message found in sent_messages_for_broadcast for hash {:02x?}", &message_hash[0..8]);
                    log_debug!(
                        self.logger,
                        "No message found for hash {:02x?} - may have been already broadcast or not tracked",
                        &message_hash[0..8]
                    );
                    return Ok(());
                }
            }
        };

        // Verify partner matches
        if partner_id != original_partner {
            log_error!(
                self.logger,
                "Message hash {:02x?} has mismatched partner: expected {}, got {}",
                &message_hash[0..8],
                partner_id,
                original_partner
            );
            return Err(DepositsError::InvalidState(
                "Mismatched partner for message hash".to_string()
            ));
        }

        // Get list of all broadcast recipients: channel counterparties + quorum members
        // This ensures signed updates reach all auditors who have joined the quorum
        let all_partners: Vec<PublicKey> = {
            use std::collections::HashSet;
            let mut recipients: HashSet<PublicKey> = HashSet::new();

            // IMPORTANT: Always include the original_partner (channel partner) in broadcast.
            // Partners no longer maintain their own hash chain - they receive authoritative
            // SignedAuditUpdate from operator and store it in their signed_update_logs.
            // This is critical for preventing hash chain divergence.
            recipients.insert(original_partner);

            // Add channel counterparties (traditional broadcast recipients)
            if let Some(ref cm) = self.channel_manager {
                let channels = cm.list_channels();
                for ch in channels.iter() {
                    let partner_id = ch.counterparty_node_id;
                    if partner_id != self.our_node_id {
                        recipients.insert(partner_id);
                    }
                }
            } else {
                // Fallback: use channel ledgers if channel manager not available
                let ledgers = self.ledgers.lock().unwrap();
                for (op_id, partner_id) in ledgers.keys() {
                    if *op_id == self.our_node_id {
                        recipients.insert(*partner_id);
                    }
                }
            }

            // Add quorum members for this specific ledger
            // Quorum members may be nodes without direct channels to us (third-party auditors)
            let ledger_id = LedgerId::new(operator_id, partner_id);
            if let Some(quorum_members) = self.quorum_manager.get_quorum(&ledger_id) {
                let member_count = quorum_members.len();
                for member in quorum_members {
                    // Skip ourselves, operator, and partner (partner is added above)
                    if member != self.our_node_id &&
                       member != operator_id &&
                       member != partner_id {
                        recipients.insert(member);
                    }
                }
                log_debug!(
                    self.logger,
                    "📋 QUORUM: Including {} quorum members in broadcast for ledger ({}, {})",
                    member_count,
                    operator_id,
                    partner_id
                );
            }

            recipients.into_iter().collect()
        };

        let partner_count = all_partners.len();

        // Create signed update for this message before broadcasting
        // Use chain_index stored at insert time - it's the position in the ledger's hash chain
        // Pass partner_signature if available from ACK (porcupine dance)
        let signed_update_result = self.create_signed_update(
            &original_message,
            partner_id,
            chain_index,
            stored_prev_hash,
            stored_new_hash,
            partner_signature,
        );

        // Create the signed update for broadcasting
        // IMPORTANT: Operators MUST persist their own SignedAuditUpdates so they can be
        // resent/synced to partners who miss the initial broadcast (e.g., due to disconnect).
        let signed_update = match signed_update_result {
            Ok(update) => {
                println!("🟢 BROADCAST: Created signed update seq={} for type {:#06x}",
                    update.sequence_number, original_message.message_type());
                log_debug!(
                    self.logger,
                    "✍️ Created signed update seq={} for operator {} -> partner {}",
                    update.sequence_number,
                    operator_id,
                    partner_id
                );

                // Store the signed update in operator's own log for potential resync
                {
                    let mut logs = self.signed_update_logs.lock().unwrap();
                    let log = logs.entry((operator_id, partner_id))
                        .or_insert_with(|| {
                            deposits_core::SignedLedgerUpdateLog::new(
                                operator_id,
                                partner_id
                            )
                        });

                    // Only add if this sequence number isn't already present
                    if log.updates.iter().all(|u| u.sequence_number != update.sequence_number) {
                        if let Err(e) = log.add_update(update.clone()) {
                            log_error!(
                                self.logger,
                                "Failed to store operator's own SignedAuditUpdate seq={}: {}",
                                update.sequence_number,
                                e
                            );
                        } else {
                            println!("🟢 BROADCAST: Stored operator's SignedAuditUpdate seq={} for potential resync",
                                update.sequence_number);
                        }
                    }
                }

                // Also persist to disk
                if let Err(e) = self.persist_signed_update(operator_id, partner_id, update.clone()) {
                    log_error!(
                        self.logger,
                        "Failed to persist operator's SignedAuditUpdate: {}",
                        e
                    );
                }

                Some(update)
            }
            Err(e) => {
                println!("🔴 BROADCAST: Could not create signed update for type {:#06x}: {}, sending raw message instead",
                    original_message.message_type(), e);
                log_debug!(
                    self.logger,
                    "Could not create signed update: {}, sending raw message instead",
                    e
                );
                None
            }
        };

        log_info!(
            self.logger,
            "🌐 Broadcasting message type {:#06x} from {} to {} other partners (signed={})",
            original_message.message_type(),
            original_partner,
            partner_count,
            signed_update.is_some()
        );

        // Send the message to each partner
        for &audit_recipient_id in &all_partners {
            // Skip sending raw messages to the original_partner - they already have the message
            // and sending a raw message would confuse them. Only send SignedAuditUpdate to
            // original_partner so they can get the authoritative hash chain.
            if audit_recipient_id == original_partner && signed_update.is_none() {
                println!("🟡 BROADCAST: Skipping {} (original_partner) - no signed update available",
                    audit_recipient_id);
                continue;
            }

            log_debug!(
                self.logger,
                "  → Sending audit copy to {} (ledger operator={}, partner={})",
                audit_recipient_id,
                operator_id,
                partner_id
            );

            // If we have a signed update, wrap it in SignedAuditUpdate message
            // Otherwise, send the raw message for backward compatibility
            let message_to_send = if let Some(ref signed_update) = signed_update {
                println!("🟢 BROADCAST: Wrapping in SignedAuditUpdate for recipient {}", audit_recipient_id);
                use super::messages::SignedUpdateMsg;
                // Extract actual operation from original message to avoid placeholder issues
                // Use to_operation() which handles all message types (LedgerUpdate, Handshake, etc.)
                let operation = original_message.to_operation().unwrap_or_else(|| {
                    // Fallback for non-ledger messages (Handshake, coordination, etc.)
                    // Use LedgerClose which is a benign no-op that doesn't modify reserves
                    println!("🟡 BROADCAST_OP: No operation found for variant {}, using LedgerClose placeholder", original_message.variant_name());
                    LedgerOperation::LedgerClose
                });
                println!("🟢 BROADCAST_OP: Using operation {:?} for variant {}", operation, original_message.variant_name());
                DepositsMessage::SignedUpdate(SignedUpdateMsg {
                    message: signed_update.message.clone(),
                    message_type: signed_update.message_type,
                    operator_signature: signed_update.operator_signature,
                    partner_signature: Some(signed_update.partner_signature),
                    operator_pubkey: signed_update.operator_pubkey,
                    partner_pubkey: signed_update.partner_pubkey,
                    sequence_number: signed_update.sequence_number,
                    previous_state_hash: signed_update.previous_state_hash,
                    current_state_hash: signed_update.current_state_hash,
                    timestamp: signed_update.timestamp,
                    operation,
                })
            } else {
                println!("🔴 BROADCAST: Sending raw message type {:#06x} to {} (no signature)",
                    original_message.message_type(), audit_recipient_id);
                original_message.clone()
            };

            // Send without waiting for ack - these are audit copies
            println!("🔵 BROADCAST: Calling send_message for recipient {}", audit_recipient_id);
            match self.send_message(audit_recipient_id, message_to_send.clone()) {
                Ok(()) => {
                    println!("🟢 BROADCAST: send_message succeeded for {}", audit_recipient_id);
                }
                Err(e) => {
                    println!("🔴 BROADCAST: send_message failed for {}: {}", audit_recipient_id, e);
                    log_error!(
                        self.logger,
                        "Failed to send audit copy to {}: {}",
                        audit_recipient_id,
                        e
                    );
                    // Continue broadcasting to other partners even if one fails
                }
            }
        }

        // Remove the message from sent_messages_for_broadcast now that we've broadcast it
        // This prevents the flush task from retrying the same message infinitely
        {
            let mut sent_messages = self.sent_messages_for_broadcast.lock().unwrap();
            if sent_messages.remove(&message_hash).is_some() {
                println!("🧹 BROADCAST: Removed message {:02x?} from sent_messages_for_broadcast after broadcast", &message_hash[0..8]);
            }
        }

        Ok(())
    }
    /// Broadcast SendingFulfillPayment state change to auditors
    /// This broadcasts the same protocol message to auditors that was exchanged between operator and partner
    fn broadcast_sending_fulfill_to_auditors(
        &self,
        partner_id: PublicKey,
        fulfill_msg: crate::wire::messages::SendingFulfillPaymentMsg,
        current_state_hash: [u8; 32],
    ) -> Result<(), DepositsError> {
        

        println!("🟣 SENDING_FULFILL_BROADCAST: Starting for deposit {}, amount {}", fulfill_msg.pubkey, fulfill_msg.amount);

        // Get the list of all channel partners (potential auditors)
        let all_partners: Vec<PublicKey> = {
            if let Some(ref cm) = self.channel_manager {
                let channels = cm.list_channels();
                channels
                    .iter()
                    .map(|ch| ch.counterparty_node_id)
                    .filter(|&p| p != partner_id && p != self.our_node_id)
                    .collect()
            } else {
                let ledgers = self.ledgers.lock().unwrap();
                ledgers
                    .keys()
                    .filter(|&(op, p)| *op == self.our_node_id && *p != partner_id)
                    .map(|(_, p)| *p)
                    .collect()
            }
        };

        if all_partners.is_empty() {
            println!("🟡 SENDING_FULFILL_BROADCAST: No auditors to broadcast to");
            return Ok(());
        }

        println!("🟣 SENDING_FULFILL_BROADCAST: Broadcasting to {} auditors", all_partners.len());

        // Get sequence number and previous hash from audit log
        let ledger_key = (self.our_node_id, partner_id);
        let (sequence_number, previous_state_hash) = {
            let logs = self.signed_update_logs.lock().unwrap();
            if let Some(log) = logs.get(&ledger_key) {
                let seq = log.next_sequence;
                let prev_hash = log.updates.last()
                    .map(|u| u.current_state_hash)
                    .unwrap_or([0u8; 32]);
                (seq, prev_hash)
            } else {
                println!("🔴 SENDING_FULFILL_BROADCAST: No audit log found for ledger");
                return Err(DepositsError::InvalidState("No audit log found".to_string()));
            }
        };

        println!("🟣 SENDING_FULFILL_BROADCAST: Creating signed update seq={}", sequence_number);

        // Use V2 LedgerUpdate for the broadcast message
        // This ensures audit ledgers match the operator's ledger exactly
        let update_msg = LedgerUpdateMsg::new_with_operation(
            self.our_node_id,
            partner_id,
            LedgerOperation::PaymentFulfill {
                pubkey: fulfill_msg.pubkey,
                amount: fulfill_msg.amount,
                payment_id: fulfill_msg.payment_id,
                sequence_number: fulfill_msg.sequence_number,
                scriptpubkey_signature: fulfill_msg.scriptpubkey_signature,
                preimage: fulfill_msg.preimage,
            },
        );
        let message = DepositsMessage::LedgerUpdate(update_msg);

        // Create signed update (no partner signature for internal broadcast)
        let signed_update = self.create_signed_update(
            &message,
            partner_id,
            sequence_number,
            previous_state_hash,
            current_state_hash,
            None, // Internal broadcast path - no partner signature
        )?;

        println!("🟢 BALANCE_WITHDRAWN_BROADCAST: Created signed update seq={} for type {:#06x}",
                 sequence_number, signed_update.message_type);

        // Store the signed update in our log
        {
            let mut logs = self.signed_update_logs.lock().unwrap();
            if let Some(log) = logs.get_mut(&ledger_key) {
                log.updates.push(signed_update.clone());
                log.next_sequence += 1;
                println!("🟢 BALANCE_WITHDRAWN_BROADCAST: Stored in log, next_seq={}", log.next_sequence);
            }
        }

        // Broadcast to all auditors - use the actual PaymentFulfill operation
        let audit_message = DepositsMessage::SignedUpdate(
            super::messages::SignedUpdateMsg {
                message: signed_update.message.clone(),
                message_type: signed_update.message_type,
                operator_signature: signed_update.operator_signature,
                partner_signature: Some(signed_update.partner_signature),
                operator_pubkey: signed_update.operator_pubkey,
                partner_pubkey: signed_update.partner_pubkey,
                sequence_number: signed_update.sequence_number,
                previous_state_hash: signed_update.previous_state_hash,
                current_state_hash: signed_update.current_state_hash,
                timestamp: signed_update.timestamp,
                operation: LedgerOperation::PaymentFulfill {
                    pubkey: fulfill_msg.pubkey,
                    amount: fulfill_msg.amount,
                    payment_id: fulfill_msg.payment_id,
                    sequence_number: fulfill_msg.sequence_number,
                    scriptpubkey_signature: fulfill_msg.scriptpubkey_signature,
                    preimage: fulfill_msg.preimage,
                },
            }
        );

        for audit_recipient_id in all_partners {
            println!("🔵 BALANCE_WITHDRAWN_BROADCAST: Sending to auditor {}", audit_recipient_id);
            if let Err(e) = self.send_message(audit_recipient_id, audit_message.clone()) {
                log_error!(self.logger, "Failed to send SendingFulfill audit to {}: {}", audit_recipient_id, e);
                println!("🔴 BALANCE_WITHDRAWN_BROADCAST: Failed to send to {}: {}", audit_recipient_id, e);
            } else {
                println!("🟢 BALANCE_WITHDRAWN_BROADCAST: Sent successfully to {}", audit_recipient_id);
            }
        }

        println!("🟢 BALANCE_WITHDRAWN_BROADCAST: Broadcast complete");
        Ok(())
    }
}
