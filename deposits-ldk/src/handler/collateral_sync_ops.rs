// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Synchronous collateral partner operations for the Bitcoin Deposits protocol.
//!
//! This module contains blocking/synchronous operations for collateral partners:
//! - Adding collateral partners (with consent request)
//! - Removing collateral partners

use bitcoin::secp256k1::PublicKey;

use super::core::DepositsHandler;
use deposits_core::DepositsError;
use super::ledger_ext::LedgerExt;
use deposits_core::quorum::LedgerId;
use lightning::{log_info, log_warn};
use lightning::util::logger::Logger as LdkLogger;

use std::ops::Deref;

impl<L: Deref + Clone> DepositsHandler<L>
where
    L::Target: LdkLogger,
{
    /// Add a collateral partner to a ledger
    /// This first requests consent from the collateral partner, then sends the AddCollateralPartner
    /// message to the channel partner with both signatures proving consent.
    pub fn add_collateral_partner(
        &self,
        partner_node_id: PublicKey,
        collateral_partner: PublicKey,
    ) -> Result<(), DepositsError> {
        use super::messages::DepositsMessage;

        // Verify ledger exists
        {
            let ledgers = self.ledgers.lock().unwrap();
            if !ledgers.contains_key(&(self.our_node_id, partner_node_id)) {
                return Err(DepositsError::ProtocolViolation {
                    violation_type: "No ledger found".to_string(),
                    details: format!("No ledger exists for partner {}", partner_node_id),
                });
            }
            // Check the actual ledger state for duplicate collateral partner
            if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id)) {
                let ledger = ledger_arc.read().unwrap();
                if ledger.state.collateral_partners.contains(&collateral_partner) {
                    log_info!(
                        self.logger,
                        "📋 OPERATOR: Collateral partner {} already exists in ledger, skipping",
                        collateral_partner
                    );
                    return Err(DepositsError::CollateralPartnerAlreadyExists);
                }
            }
        }

        // Also check quorum_manager for redundancy
        {
            let ledger_id = LedgerId::new(self.our_node_id, partner_node_id);
            if let Some(members) = self.quorum_manager.get_quorum(&ledger_id) {
                if members.contains(&collateral_partner) {
                    return Err(DepositsError::CollateralPartnerAlreadyExists);
                }
            }
        }

        // Step 1: Request consent from the collateral partner
        log_info!(self.logger, "📨 Requesting consent from collateral partner {} to back ledger with partner {}",
            collateral_partner, partner_node_id);

        let consent_request = DepositsMessage::CollateralConsentRequest {
            operator_id: self.our_node_id,
            partner_id: partner_node_id,
            operator_signature: [0u8; 64],
        };

        // Send consent request and wait for response
        let collateral_partner_signature = self.request_collateral_consent(
            collateral_partner,
            consent_request,
        )?;

        log_info!(self.logger, "✅ Received consent signature from collateral partner {}", collateral_partner);

        // Step 2: Create the AddCollateralPartner message with both signatures
        let message = DepositsMessage::CollateralAddPartner {
            operator_id: self.our_node_id,
            partner_id: partner_node_id,
            collateral_partner,
            collateral_partner_signature,
        };

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
            pending_acks.insert(message_hash, (message_type, timestamp));
        }

        // Send and wait for ACK
        match self.send_message_with_oneshot_ack(partner_node_id, message, 30000) {
            Ok(()) => {
                log_info!(self.logger, "✅ AddCollateralPartner ACK received from {}", partner_node_id);
            }
            Err(e) => {
                log_info!(self.logger, "❌ Failed to get AddCollateralPartner ACK from {}: {}", partner_node_id, e);
                return Err(e);
            }
        }

        // Apply the change locally
        {
            let ledgers = self.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id)) {
                let mut ledger = ledger_arc.write().unwrap();

                // Capture prev_hash BEFORE appending
                let prev_hash = ledger.tail_hash();

                // Clone message_for_broadcast because we need it later to send to the collateral partner
                let new_hash = ledger.append_v1_mut(message_for_broadcast.clone())?;
                let chain_index = (ledger.history.len() - 1) as u64; // 0-based (index of just-appended entry)

                // Update partner_deepest_ack_hash since partner just ACKed this update
                // This is needed BEFORE refresh_reserves_commitment can commit this hash
                ledger.state.partner_deepest_ack_hash = new_hash;

                // Persist the updated ledger
                if let Err(e) = self.persist_ledger_state(&*ledger) {
                    log_warn!(self.logger, "Failed to persist ledger after adding collateral partner: {:?}", e);
                }

                drop(ledger);
                drop(ledgers);

                // Update sent_messages_for_broadcast with correct new_hash
                println!("🟣 UPDATE SENT_MESSAGES (AddCollateralPartner): hash={:02x?}, type={:#06x}, prev_hash={:02x?}, new_hash={:02x?}, seq={}",
                    &message_hash[0..4], message_type, &prev_hash[0..8], &new_hash[0..8], chain_index);
                {
                    let mut sent_messages = self.sent_messages_for_broadcast.lock().unwrap();
                    sent_messages.insert(message_hash, (self.our_node_id, partner_node_id, message_for_broadcast.clone(), prev_hash, new_hash, chain_index));
                }

                // Now that new_hash is set, trigger the broadcast to other collateral partners
                // The ACK handler skipped this because new_hash was zeros at that point
                // Retrieve the partner signature that was stored when ACK was received
                let partner_sig = {
                    let mut sigs = self.received_partner_signatures.lock().unwrap();
                    sigs.remove(&message_hash)
                };
                println!("🟢 TRIGGERING broadcast after AddCollateralPartner append (has_partner_sig={})", partner_sig.is_some());
                if let Err(e) = self.broadcast_message_to_other_partners(message_hash, partner_node_id, partner_sig) {
                    log_warn!(self.logger, "Failed to broadcast AddCollateralPartner to other partners: {:?}", e);
                }
            }
        }

        // Sync with QuorumManager - add collateral partner to quorum membership
        let ledger_id = LedgerId::new(self.our_node_id, partner_node_id);
        if let Err(e) = self.quorum_manager.add_member(&ledger_id, collateral_partner) {
            log_warn!(
                self.logger,
                "Failed to add collateral partner {} to quorum: {:?}",
                collateral_partner,
                e
            );
        } else {
            log_info!(
                self.logger,
                "✅ Added collateral partner {} to quorum for ledger ({}, {})",
                collateral_partner,
                self.our_node_id,
                partner_node_id
            );
        }

        // Send SignedAuditUpdate to the new collateral partner
        // This is critical: the ACK handler's broadcast_message_to_other_partners ran BEFORE
        // the collateral partner was added to the quorum, so they didn't receive the update.
        // We need to send it now, directly to them.
        self.send_audit_update_to_new_collateral_partner(
            partner_node_id,
            collateral_partner,
            &message_for_broadcast,
        )?;

        Ok(())
    }

    pub fn remove_collateral_partner(
        &self,
        partner_node_id: PublicKey,
        collateral_partner: PublicKey,
    ) -> Result<(), DepositsError> {
        use super::messages::DepositsMessage;

        // Verify ledger exists
        {
            let ledgers = self.ledgers.lock().unwrap();
            if !ledgers.contains_key(&(self.our_node_id, partner_node_id)) {
                return Err(DepositsError::ProtocolViolation {
                    violation_type: "No ledger found".to_string(),
                    details: format!("No ledger exists for partner {}", partner_node_id),
                });
            }
        }

        // Create the message (signature is placeholder for now)
        let message = DepositsMessage::CollateralRemovePartner {
            partner_id: partner_node_id,
            collateral_partner,
            operator_signature: [0u8; 64],
        };

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
            pending_acks.insert(message_hash, (message_type, timestamp));
        }

        // Send and wait for ACK
        match self.send_message_with_oneshot_ack(partner_node_id, message, 30000) {
            Ok(()) => {
                log_info!(self.logger, "✅ RemoveCollateralPartner ACK received from {}", partner_node_id);
            }
            Err(e) => {
                log_info!(self.logger, "❌ Failed to get RemoveCollateralPartner ACK from {}: {}", partner_node_id, e);
                return Err(e);
            }
        }

        // Apply the change locally
        {
            let ledgers = self.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner_node_id)) {
                let mut ledger = ledger_arc.write().unwrap();

                // Capture prev_hash BEFORE appending
                let prev_hash = ledger.tail_hash();

                let new_hash = ledger.append_v1_mut(message_for_broadcast.clone())?;
                let chain_index = (ledger.history.len() - 1) as u64; // 0-based (index of just-appended entry)

                // Persist the updated ledger
                if let Err(e) = self.persist_ledger_state(&*ledger) {
                    log_warn!(self.logger, "Failed to persist ledger after removing collateral partner: {:?}", e);
                }

                drop(ledger);
                drop(ledgers);

                // Update sent_messages_for_broadcast with correct new_hash
                println!("🟣 UPDATE SENT_MESSAGES (RemoveCollateralPartner): hash={:02x?}, type={:#06x}, prev_hash={:02x?}, new_hash={:02x?}, seq={}",
                    &message_hash[0..4], message_type, &prev_hash[0..8], &new_hash[0..8], chain_index);
                {
                    let mut sent_messages = self.sent_messages_for_broadcast.lock().unwrap();
                    sent_messages.insert(message_hash, (self.our_node_id, partner_node_id, message_for_broadcast.clone(), prev_hash, new_hash, chain_index));
                }

                // Now that new_hash is set, trigger the broadcast to other collateral partners
                // Retrieve the partner signature that was stored when ACK was received
                let partner_sig = {
                    let mut sigs = self.received_partner_signatures.lock().unwrap();
                    sigs.remove(&message_hash)
                };
                println!("🟢 TRIGGERING broadcast after RemoveCollateralPartner append (has_partner_sig={})", partner_sig.is_some());
                if let Err(e) = self.broadcast_message_to_other_partners(message_hash, partner_node_id, partner_sig) {
                    log_warn!(self.logger, "Failed to broadcast RemoveCollateralPartner to other partners: {:?}", e);
                }
            }
        }

        // Sync with QuorumManager - remove collateral partner from quorum membership
        let ledger_id = LedgerId::new(self.our_node_id, partner_node_id);
        if let Err(e) = self.quorum_manager.remove_member(&ledger_id, &collateral_partner) {
            log_warn!(
                self.logger,
                "Failed to remove collateral partner {} from quorum: {:?}",
                collateral_partner,
                e
            );
        } else {
            log_info!(
                self.logger,
                "✅ Removed collateral partner {} from quorum for ledger ({}, {})",
                collateral_partner,
                self.our_node_id,
                partner_node_id
            );
        }

        Ok(())
    }
}
