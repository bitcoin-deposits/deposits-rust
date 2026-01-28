// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Broadcast operations for the Bitcoin Deposits protocol.

use bitcoin::secp256k1::PublicKey;
use super::core::DepositsHandler;
use deposits_core::DepositsError;
use super::messages::{DepositsMessage, LedgerUpdateMsg, LedgerUpdateMsgExt, LedgerOperation};
use deposits_core::quorum::LedgerId;
use deposits_core::{log_debug, log_error, log_info};
use lightning::util::logger::Logger as LdkLogger;
use std::ops::Deref;

impl<L: Deref + Clone + Send + Sync> DepositsHandler<L>
where
    L::Target: LdkLogger,
{
    /// Broadcast signed update to partners after receiving ACK
    pub(super) fn broadcast_message_to_other_partners(
        &self,
        message_hash: [u8; 32],
        original_partner: PublicKey,
        partner_signature: Option<[u8; 64]>,
    ) -> Result<(), DepositsError> {
        // Get stored message data
        let (operator_id, partner_id, original_message, stored_prev_hash, stored_new_hash, chain_index) =
            self.get_stored_broadcast_message(&message_hash)?;

        if partner_id != original_partner {
            return Err(DepositsError::InvalidState("Mismatched partner for message hash".to_string()));
        }

        // Get all recipients and create signed update
        let recipients = self.get_broadcast_recipients_internal(operator_id, partner_id, original_partner);
        let signed_update = self.create_and_store_signed_update(
            &original_message, operator_id, partner_id, chain_index,
            stored_prev_hash, stored_new_hash, partner_signature,
        );

        log_info!(self.logger, "🌐 Broadcasting type {:#06x} to {} partners (signed={})",
            original_message.message_type(), recipients.len(), signed_update.is_some());

        // Broadcast to all recipients
        self.send_to_recipients(&recipients, &original_message, &signed_update, original_partner);

        // Cleanup
        self.sent_messages_for_broadcast.lock().unwrap().remove(&message_hash);
        Ok(())
    }

    /// Get stored message for broadcast
    fn get_stored_broadcast_message(&self, hash: &[u8; 32]) -> Result<(PublicKey, PublicKey, DepositsMessage, [u8; 32], [u8; 32], u64), DepositsError> {
        let sent_messages = self.sent_messages_for_broadcast.lock().unwrap();
        sent_messages.get(hash)
            .map(|(op, partner, msg, prev, new, idx)| (*op, *partner, msg.clone(), *prev, *new, *idx))
            .ok_or_else(|| {
                log_debug!(self.logger, "No message found for hash {:02x?}", &hash[0..8]);
                DepositsError::InvalidState("No message found for broadcast".to_string())
            })
    }

    /// Get all broadcast recipients including quorum members
    fn get_broadcast_recipients_internal(&self, operator: PublicKey, partner: PublicKey, original_partner: PublicKey) -> Vec<PublicKey> {
        use std::collections::HashSet;
        let mut recipients: HashSet<PublicKey> = HashSet::new();
        recipients.insert(original_partner);

        // Add channel counterparties
        if let Some(ref cm) = self.channel_manager {
            for ch in cm.list_channels() {
                if ch.counterparty_node_id != self.our_node_id {
                    recipients.insert(ch.counterparty_node_id);
                }
            }
        } else {
            let ledgers = self.ledgers.lock().unwrap();
            for (op, p) in ledgers.keys() {
                if *op == self.our_node_id { recipients.insert(*p); }
            }
        }

        // Add quorum members
        if let Some(members) = self.quorum_manager.get_quorum(&LedgerId::new(operator, partner)) {
            for member in members {
                if member != self.our_node_id && member != operator && member != partner {
                    recipients.insert(member);
                }
            }
        }

        recipients.into_iter().collect()
    }

    /// Create signed update and store in logs
    fn create_and_store_signed_update(
        &self,
        message: &DepositsMessage,
        operator: PublicKey,
        partner: PublicKey,
        seq: u64,
        prev_hash: [u8; 32],
        new_hash: [u8; 32],
        partner_sig: Option<[u8; 64]>,
    ) -> Option<deposits_core::SignedLedgerUpdate> {
        let update = self.create_signed_update(message, partner, seq, prev_hash, new_hash, partner_sig).ok()?;

        // Store in memory
        {
            let mut logs = self.signed_update_logs.lock().unwrap();
            let log = logs.entry((operator, partner))
                .or_insert_with(|| deposits_core::SignedLedgerUpdateLog::new(operator, partner));
            if log.updates.iter().all(|u| u.sequence_number != update.sequence_number) {
                let _ = log.add_update(update.clone());
            }
        }

        // Persist to disk
        let _ = self.persist_signed_update(operator, partner, update.clone());
        Some(update)
    }

    /// Send message to all recipients
    fn send_to_recipients(
        &self,
        recipients: &[PublicKey],
        original: &DepositsMessage,
        signed: &Option<deposits_core::SignedLedgerUpdate>,
        original_partner: PublicKey,
    ) {
        for &recipient in recipients {
            if recipient == original_partner && signed.is_none() { continue; }

            let msg = if let Some(ref update) = signed {
                DepositsMessage::SyncResponse(super::messages::SyncResponseMsg {
                    operator_id: update.operator_id, partner_id: update.partner_id,
                    request_hash: [0u8; 32], updates: vec![update.clone()],
                    current_sequence: update.sequence_number, current_hash: update.current_hash,
                })
            } else {
                original.clone()
            };

            if let Err(e) = self.send_message(recipient, msg) {
                log_error!(self.logger, "Failed to send audit copy to {}: {}", recipient, e);
            }
        }
    }

    /// Broadcast SendingFulfillPayment to auditors
    fn broadcast_sending_fulfill_to_auditors(
        &self,
        partner_id: PublicKey,
        fulfill_msg: crate::wire::messages::SendingFulfillPaymentMsg,
        current_hash: [u8; 32],
    ) -> Result<(), DepositsError> {
        let auditors = self.get_auditors_except(partner_id);
        if auditors.is_empty() { return Ok(()); }

        let ledger_key = (self.our_node_id, partner_id);
        let (seq, prev_hash) = {
            let logs = self.signed_update_logs.lock().unwrap();
            let log = logs.get(&ledger_key).ok_or_else(|| DepositsError::InvalidState("No audit log".to_string()))?;
            (log.next_sequence, log.updates.last().map(|u| u.current_hash).unwrap_or([0u8; 32]))
        };

        let message = DepositsMessage::LedgerUpdate(LedgerUpdateMsg::new_with_operation(
            self.our_node_id, partner_id,
            LedgerOperation::PaymentFulfill {
                pubkey: fulfill_msg.pubkey, amount: fulfill_msg.amount, payment_id: fulfill_msg.payment_id,
                sequence_number: fulfill_msg.sequence_number, scriptpubkey_signature: fulfill_msg.scriptpubkey_signature,
                preimage: fulfill_msg.preimage,
            },
        ));

        let signed = self.create_signed_update(&message, partner_id, seq, prev_hash, current_hash, None)?;

        // Store and broadcast
        {
            let mut logs = self.signed_update_logs.lock().unwrap();
            if let Some(log) = logs.get_mut(&ledger_key) {
                log.updates.push(signed.clone());
                log.next_sequence += 1;
            }
        }

        let audit_msg = DepositsMessage::SyncResponse(super::messages::SyncResponseMsg {
            operator_id: signed.operator_id, partner_id: signed.partner_id,
            request_hash: [0u8; 32], updates: vec![signed.clone()],
            current_sequence: signed.sequence_number, current_hash: signed.current_hash,
        });

        for recipient in auditors {
            if let Err(e) = self.send_message(recipient, audit_msg.clone()) {
                log_error!(self.logger, "Failed to send audit to {}: {}", recipient, e);
            }
        }
        Ok(())
    }

    /// Get auditors excluding a specific partner
    fn get_auditors_except(&self, exclude: PublicKey) -> Vec<PublicKey> {
        if let Some(ref cm) = self.channel_manager {
            cm.list_channels().iter()
                .map(|ch| ch.counterparty_node_id)
                .filter(|&p| p != exclude && p != self.our_node_id)
                .collect()
        } else {
            let ledgers = self.ledgers.lock().unwrap();
            ledgers.keys()
                .filter(|&(op, p)| *op == self.our_node_id && *p != exclude)
                .map(|(_, p)| *p)
                .collect()
        }
    }
}
