// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Synchronous quorum member operations for the Bitcoin Deposits protocol.
//!
//! This module contains blocking/synchronous operations for quorum members:
//! - Adding quorum members (with consent request)
//! - Removing quorum members

use bitcoin::secp256k1::PublicKey;

use super::core::DepositsHandler;
use super::messages::{LedgerUpdateMsg, LedgerUpdateMsgExt, LedgerOperation};
use deposits_core::DepositsError;
use deposits_core::messages::CoordinationMsg;
use super::ledger_ext::LedgerExt;
use deposits_core::quorum::LedgerId;
use deposits_core::{log_info, log_warn};
use lightning::util::logger::Logger as LdkLogger;

use std::ops::Deref;

impl<L: Deref + Clone + Send + Sync> DepositsHandler<L>
where
    L::Target: LdkLogger,
{
    /// Add a quorum member to a ledger
    /// This first requests consent from the quorum member, then sends the QuorumAddMember
    /// message to the channel partner with both signatures proving consent.
    ///
    /// # Arguments
    /// * `partner_node_id` - The channel partner's node ID
    /// * `quorum_member` - The quorum member's public key
    /// * `member_ledger_id` - The ledger ID where the member will lock collateral (64-char hex)
    pub fn add_quorum_member(
        &self,
        partner_node_id: PublicKey,
        quorum_member: PublicKey,
        member_ledger_id: String,
    ) -> Result<(), DepositsError> {
        use super::messages::DepositsMessage;

        // Verify ledger exists
        {
            let ledgers = self.ledgers.lock().unwrap();
            if !ledgers.contains_key(&(self.our_node_id, partner_node_id.to_string())) {
                return Err(DepositsError::ProtocolViolation {
                    violation_type: "No ledger found".to_string(),
                    details: format!("No ledger exists for partner {}", partner_node_id),
                });
            }
            // Check the actual ledger state for duplicate quorum member
            if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id.to_string())) {
                let ledger = ledger_arc.read().unwrap();
                if ledger.state.quorum_members.iter().any(|m| m.pubkey == quorum_member) {
                    log_info!(
                        self.logger,
                        "📋 OPERATOR: Quorum member {} already exists in ledger, skipping",
                        quorum_member
                    );
                    return Err(DepositsError::QuorumMemberAlreadyExists);
                }
            }
        }

        // Also check quorum_manager for redundancy
        {
            let ledger_id = LedgerId::new(self.our_node_id, partner_node_id.to_string());
            if let Some(members) = self.quorum_manager.get_quorum(&ledger_id) {
                if members.contains(&quorum_member) {
                    return Err(DepositsError::QuorumMemberAlreadyExists);
                }
            }
        }

        // Step 1: Request consent from the quorum member
        log_info!(self.logger, "📨 Requesting consent from quorum member {} to back ledger with partner {}",
            quorum_member, partner_node_id);

        let consent_request = DepositsMessage::Coordination(CoordinationMsg::CollateralConsentRequest {
            operator_id: self.our_node_id,
            reserves_id: partner_node_id.to_string(),
            operator_signature: [0u8; 64],
        });

        // Send consent request and wait for response
        let quorum_member_signature = self.request_collateral_consent(
            quorum_member,
            consent_request,
        )?;

        log_info!(self.logger, "✅ Received consent signature from quorum member {}", quorum_member);

        // Step 2: Create the QuorumAddMember message with both signatures (V2 format)
        let message = DepositsMessage::LedgerUpdate(LedgerUpdateMsg::new_with_operation(
            self.our_node_id,
            partner_node_id.to_string(),
            LedgerOperation::QuorumAddMember {
                quorum_member,
                quorum_member_signature,
                member_ledger_id: member_ledger_id.clone(),
            },
        ));

        let message_hash = self.calculate_message_hash(&message);
        let message_type = message.message_type();
        let message_for_broadcast = message.clone();

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

        // Send and wait for ACK
        match self.send_message_with_oneshot_ack(partner_node_id, message, 30000) {
            Ok(()) => {
                log_info!(self.logger, "✅ QuorumAddMember ACK received from {}", partner_node_id);
            }
            Err(e) => {
                log_info!(self.logger, "❌ Failed to get QuorumAddMember ACK from {}: {}", partner_node_id, e);
                return Err(e);
            }
        }

        // Apply the change locally
        {
            let ledgers = self.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id.to_string())) {
                let mut ledger = ledger_arc.write().unwrap();

                // Capture prev_hash BEFORE appending
                let prev_hash = ledger.tail_hash();

                // Clone message_for_broadcast because we need it later to send to the quorum member
                let new_hash = ledger.append_mut(message_for_broadcast.clone())?;
                let chain_index = (ledger.history.len() - 1) as u64; // 0-based (index of just-appended entry)

                // Update partner_deepest_ack_hash since partner just ACKed this update
                // This is needed BEFORE refresh_reserves_commitment can commit this hash
                ledger.state.partner_deepest_ack_hash = new_hash;

                // Persist the updated ledger
                if let Err(e) = self.persist_ledger_state(&*ledger) {
                    log_warn!(self.logger, "Failed to persist ledger after adding quorum member: {:?}", e);
                }

                drop(ledger);
                drop(ledgers);

                // Update sent_messages_for_broadcast with correct new_hash
                {
                    let mut sent_messages = self.sent_messages_for_broadcast.lock().unwrap();
                    sent_messages.insert(message_hash, (self.our_node_id, partner_node_id.to_string(), message_for_broadcast.clone(), prev_hash, new_hash, chain_index));
                }

                // Now that new_hash is set, trigger the broadcast to other quorum members
                // The ACK handler skipped this because new_hash was zeros at that point
                // Retrieve the partner signature that was stored when ACK was received
                let partner_sig = {
                    let mut sigs = self.received_partner_signatures.lock().unwrap();
                    sigs.remove(&message_hash)
                };
                if let Err(e) = self.broadcast_message_to_other_partners(message_hash, partner_node_id, partner_sig) {
                    log_warn!(self.logger, "Failed to broadcast QuorumAddMember to other partners: {:?}", e);
                }
            }
        }

        // Sync with QuorumManager - add quorum member to quorum membership
        let ledger_id = LedgerId::new(self.our_node_id, partner_node_id.to_string());
        if let Err(e) = self.quorum_manager.add_member(&ledger_id, quorum_member) {
            log_warn!(
                self.logger,
                "Failed to add quorum member {} to quorum: {:?}",
                quorum_member,
                e
            );
        } else {
            log_info!(
                self.logger,
                "✅ Added quorum member {} to quorum for ledger ({}, {})",
                quorum_member,
                self.our_node_id,
                partner_node_id
            );
        }

        // Send SignedAuditUpdate to the new quorum member
        // This is critical: the ACK handler's broadcast_message_to_other_partners ran BEFORE
        // the quorum member was added to the quorum, so they didn't receive the update.
        // We need to send it now, directly to them.
        self.send_audit_update_to_new_quorum_member(
            partner_node_id,
            quorum_member,
            &message_for_broadcast,
        )?;

        Ok(())
    }

    pub fn remove_quorum_member(
        &self,
        partner_node_id: PublicKey,
        quorum_member: PublicKey,
    ) -> Result<(), DepositsError> {
        use super::messages::DepositsMessage;

        // Verify ledger exists
        {
            let ledgers = self.ledgers.lock().unwrap();
            if !ledgers.contains_key(&(self.our_node_id, partner_node_id.to_string())) {
                return Err(DepositsError::ProtocolViolation {
                    violation_type: "No ledger found".to_string(),
                    details: format!("No ledger exists for partner {}", partner_node_id),
                });
            }
        }

        // Create the message (signature is placeholder for now) (V2 format)
        let message = DepositsMessage::LedgerUpdate(LedgerUpdateMsg::new_with_operation(
            self.our_node_id,  // operator
            partner_node_id.to_string(),
            LedgerOperation::QuorumRemoveMember {
                quorum_member,
                operator_signature: [0u8; 64],
            },
        ));

        let message_hash = self.calculate_message_hash(&message);
        let message_type = message.message_type();
        let message_for_broadcast = message.clone();

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

        // Send and wait for ACK
        match self.send_message_with_oneshot_ack(partner_node_id, message, 30000) {
            Ok(()) => {
                log_info!(self.logger, "✅ QuorumRemoveMember ACK received from {}", partner_node_id);
            }
            Err(e) => {
                log_info!(self.logger, "❌ Failed to get QuorumRemoveMember ACK from {}: {}", partner_node_id, e);
                return Err(e);
            }
        }

        // Apply the change locally
        {
            let ledgers = self.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id.to_string())) {
                let mut ledger = ledger_arc.write().unwrap();

                // Capture prev_hash BEFORE appending
                let prev_hash = ledger.tail_hash();

                let new_hash = ledger.append_mut(message_for_broadcast.clone())?;
                let chain_index = (ledger.history.len() - 1) as u64; // 0-based (index of just-appended entry)

                // Update partner_deepest_ack_hash since partner just ACKed this update
                ledger.state.partner_deepest_ack_hash = new_hash;

                // Persist the updated ledger
                if let Err(e) = self.persist_ledger_state(&*ledger) {
                    log_warn!(self.logger, "Failed to persist ledger after removing quorum member: {:?}", e);
                }

                drop(ledger);
                drop(ledgers);

                // Update sent_messages_for_broadcast with correct new_hash
                {
                    let mut sent_messages = self.sent_messages_for_broadcast.lock().unwrap();
                    sent_messages.insert(message_hash, (self.our_node_id, partner_node_id.to_string(), message_for_broadcast.clone(), prev_hash, new_hash, chain_index));
                }

                // Now that new_hash is set, trigger the broadcast to other quorum members
                // Retrieve the partner signature that was stored when ACK was received
                let partner_sig = {
                    let mut sigs = self.received_partner_signatures.lock().unwrap();
                    sigs.remove(&message_hash)
                };
                if let Err(e) = self.broadcast_message_to_other_partners(message_hash, partner_node_id, partner_sig) {
                    log_warn!(self.logger, "Failed to broadcast QuorumRemoveMember to other partners: {:?}", e);
                }
            }
        }

        // Sync with QuorumManager - remove quorum member from quorum membership
        let ledger_id = LedgerId::new(self.our_node_id, partner_node_id.to_string());
        if let Err(e) = self.quorum_manager.remove_member(&ledger_id, &quorum_member) {
            log_warn!(
                self.logger,
                "Failed to remove quorum member {} from quorum: {:?}",
                quorum_member,
                e
            );
        } else {
            log_info!(
                self.logger,
                "✅ Removed quorum member {} from quorum for ledger ({}, {})",
                quorum_member,
                self.our_node_id,
                partner_node_id
            );
        }

        Ok(())
    }
}
