// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! ACK handling for the Bitcoin Deposits protocol.

use bitcoin::secp256k1::PublicKey;
use super::core::DepositsHandler;
use super::messages::LedgerUpdateResponseMsg;
use deposits_core::DepositsError;
use deposits_core::{log_debug, log_error};
use lightning::util::logger::Logger as LdkLogger;
use std::ops::Deref;

impl<L: Deref + Clone + Send + Sync> DepositsHandler<L>
where
    L::Target: LdkLogger,
{
    /// Handle received acknowledgment message
    pub(super) fn handle_received_ack(&self, ack_msg: LedgerUpdateResponseMsg, sender: PublicKey) -> Result<(), DepositsError> {
        let result = if ack_msg.accepted { Ok(()) }
            else { Err(ack_msg.error.clone().unwrap_or_else(|| "Message rejected".to_string())) };

        // Notify oneshot waiters
        if let Some(tx) = self.pending_oneshot_acks.lock().unwrap().remove(&ack_msg.request_hash) {
            let _ = tx.send(result.clone());
        }

        // Notify cosignature waiters
        self.notify_cosignature_waiter(&ack_msg);

        // Process through ledger system
        if !self.has_ledger_for_peer(sender) { return Ok(()); }

        let (lookup_hash, msg_type) = self.find_pending_ack(&ack_msg.request_hash, &sender);

        if ack_msg.accepted {
            self.process_accepted_ack(&ack_msg, sender, lookup_hash, msg_type);
        } else if let Some(mt) = msg_type {
            log_error!(self.logger, "ACK failed for type {} from {}: {:?}", mt, sender, ack_msg.error);
        }

        Ok(())
    }

    /// Notify cosignature waiter if present
    fn notify_cosignature_waiter(&self, ack_msg: &LedgerUpdateResponseMsg) {
        if let Some(tx) = self.pending_cosignature_requests.lock().unwrap().remove(&ack_msg.request_hash) {
            let result = if ack_msg.accepted {
                ack_msg.partner_signature.as_ref()
                    .map(|s| s.to_vec())
                    .ok_or_else(|| "No cosignature provided".to_string())
            } else {
                Err(ack_msg.error.clone().unwrap_or_else(|| "Cosigning rejected".to_string()))
            };
            let _ = tx.send(result);
        }
    }

    /// Check if we have a ledger for this peer
    fn has_ledger_for_peer(&self, peer: PublicKey) -> bool {
        let ledgers = self.ledgers.lock().unwrap();
        ledgers.contains_key(&(peer, self.our_node_id)) || ledgers.contains_key(&(self.our_node_id, peer))
    }

    /// Find pending ACK entry, trying both original and partner-specific hash
    fn find_pending_ack(&self, hash: &[u8; 32], sender: &PublicKey) -> ([u8; 32], Option<u16>) {
        let partner_hash = Self::create_partner_specific_hash(hash, sender);
        let mut pending = self.pending_acks.lock().unwrap();

        if let Some(ack) = pending.remove(hash) {
            (*hash, Some(ack.message_type))
        } else if let Some(ack) = pending.remove(&partner_hash) {
            (partner_hash, Some(ack.message_type))
        } else {
            (*hash, None)
        }
    }

    /// Process an accepted ACK
    fn process_accepted_ack(&self, ack_msg: &LedgerUpdateResponseMsg, sender: PublicKey, lookup_hash: [u8; 32], _msg_type: Option<u16>) {
        let (new_hash, is_attestation) = self.get_broadcast_info(&lookup_hash);

        // Update partner_deepest_ack_hash if we have a valid hash
        if let Some(hash) = new_hash {
            if hash != [0u8; 32] {
                self.update_partner_ack_hash(sender, hash);
            }
        }

        // Broadcast or cleanup
        if is_attestation {
            self.sent_messages_for_broadcast.lock().unwrap().remove(&lookup_hash);
        } else if new_hash.map(|h| h != [0u8; 32]).unwrap_or(false) {
            if let Err(e) = self.broadcast_message_to_other_partners(lookup_hash, sender, ack_msg.partner_signature) {
                log_error!(self.logger, "Broadcast failed: {}", e);
            }
        } else if let Some(sig) = ack_msg.partner_signature {
            self.received_partner_signatures.lock().unwrap().insert(lookup_hash, sig);
        }
    }

    /// Get broadcast info from sent_messages
    fn get_broadcast_info(&self, hash: &[u8; 32]) -> (Option<[u8; 32]>, bool) {
        let sent = self.sent_messages_for_broadcast.lock().unwrap();
        sent.get(hash).map(|(_, _, msg, _, new_hash, _)| {
            let is_attestation = msg.to_operation().map_or(false, |op| {
                matches!(op, super::messages::LedgerOperation::CollateralAttestation { .. })
            });
            (Some(*new_hash), is_attestation)
        }).unwrap_or((None, false))
    }

    /// Update partner_deepest_ack_hash on ledger
    fn update_partner_ack_hash(&self, sender: PublicKey, new_hash: [u8; 32]) {
        let ledgers = self.ledgers.lock().unwrap();
        let key = if ledgers.contains_key(&(self.our_node_id, sender)) {
            Some((self.our_node_id, sender))
        } else if ledgers.contains_key(&(sender, self.our_node_id)) {
            Some((sender, self.our_node_id))
        } else { None };

        if let Some(k) = key {
            if let Some(arc) = ledgers.get(&k) {
                let mut ledger = arc.write().unwrap();
                if ledger.state.partner_deepest_ack_hash != new_hash {
                    ledger.state.partner_deepest_ack_hash = new_hash;
                    let _ = self.persist_ledger_state(&*ledger);
                    if k.0 == self.our_node_id { self.mark_for_lazy_sync(k.1); }
                }
            }
        }
    }
}
