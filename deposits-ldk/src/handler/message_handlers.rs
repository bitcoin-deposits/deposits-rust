// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Message handlers for the Bitcoin Deposits protocol.
//!
//! This module contains handlers for specific message types, extracted from core.rs
//! to improve maintainability.

use bitcoin::secp256k1::PublicKey;
use lightning::ln::msgs::{LightningError, ErrorAction};

use super::core::DepositsHandler;
use super::ledger_ext::LedgerExt;
use super::messages::*;
use deposits_core::messages::{CoordinationMsg, CoordinationResponseMsg};
use deposits_core::message_handlers::{self as core_handlers, HandlerResult, ResponseData};
use deposits_core::{log_debug, log_error, log_info, log_warn};
use lightning::util::logger::Logger as LdkLogger;
use crate::wire::messages::ChannelCloseTombstoneMsg;

use std::ops::Deref;

impl<L: Deref + Clone + Send + Sync> DepositsHandler<L>
where
    L::Target: LdkLogger,
{
    // ========================================================================
    // Quorum Message Handlers
    // ========================================================================

    // NOTE: handle_quorum_join_request removed - dispatch calls core directly via send_quorum_state_sync provider
    // NOTE: handle_quorum_join_response removed - inlined in dispatch (just logging)
    // NOTE: handle_quorum_state_sync removed - dispatch calls core directly via verify_and_store_signed_update and update_quorum_member_state providers
    // NOTE: handle_quorum_vote_request removed - dispatch calls core directly via init_vote_round and sign_quorum_vote providers
    // NOTE: handle_quorum_vote removed - dispatch calls core directly via add_quorum_vote provider
    // NOTE: handle_quorum_membership_change removed - inlined in dispatch (just logging)

    // ========================================================================
    // Recovery Message Handlers
    // ========================================================================

    // NOTE: handle_recovery_vote removed - dispatch calls core directly

    // NOTE: handle_recovery_claim_request removed - dispatch calls core directly via sign_schnorr provider
    // NOTE: handle_recovery_claim_signature removed - dispatch calls core directly via add_claim_signature provider
    // NOTE: handle_recovery_claim_complete removed - dispatch calls core directly via remove_claim provider

    // ========================================================================
    // Collateral/Voter Message Handlers
    // ========================================================================

    // NOTE: send_collateral_nack, send_collateral_ack, finalize_collateral_add, finalize_collateral_remove
    // have been removed - all that logic is now in core handlers via HandlerContext provider methods.

    // NOTE: handle_collateral_consent_request removed - dispatch calls core directly via providers

    // NOTE: handle_collateral_consent_response removed - dispatch calls core directly via providers

    /// Handle CollateralAttestation message
    /// Handle CollateralAttestation message.
    ///
    /// Received from collateral partner after CollateralIncrease. Stores attestation
    /// and forwards to channel partners.
    pub(super) fn handle_collateral_attestation(
        &self,
        msg: &crate::wire::messages::CollateralAttestationMsg,
        sender_node_id: PublicKey,
    ) -> Result<(), LightningError> {
        log_info!(self.logger, "💰 COLLATERAL: Received attestation from {} - amount={}", sender_node_id, msg.amount);

        let is_direct = sender_node_id == msg.collateral_partner;
        let mut partners_to_forward: Vec<PublicKey> = Vec::new();

        // Process attestation based on our role
        {
            let ledgers = self.ledgers.lock().unwrap();
            for ((op, part), ledger_arc) in ledgers.iter() {
                if *op == self.our_node_id && *part == sender_node_id {
                    // Operator receiving from channel partner - store attestation
                    self.store_attestation(&mut ledger_arc.write().unwrap(), msg, sender_node_id);
                } else if *op == self.our_node_id && *part != sender_node_id && is_direct {
                    // Operator receiving directly - forward to other partners
                    partners_to_forward.push(*part);
                } else if *part == self.our_node_id && *op == sender_node_id {
                    // Partner receiving from operator
                    self.store_attestation_as_partner(&mut ledger_arc.write().unwrap(), msg);
                }
            }
        }

        // Forward to other channel partners
        if !partners_to_forward.is_empty() {
            self.forward_attestation_to_partners(msg, &partners_to_forward);
        }

        // Send ACK
        let ack_msg = self.create_attestation_message(msg);
        if let Err(e) = self.send_acknowledgment(&ack_msg, true, None, None, sender_node_id) {
            log_warn!(self.logger, "💰 COLLATERAL: Failed to send ACK: {:?}", e);
        }

        Ok(())
    }

    fn store_attestation(&self, ledger: &mut deposits_core::Ledger, msg: &crate::wire::messages::CollateralAttestationMsg, sender: PublicKey) {
        let attestation = deposits_core::types::CollateralAttestation::new(
            msg.operator, msg.collateral_partner, msg.amount, msg.block_height, msg.signature, msg.ledger_hash,
        );
        ledger.state.collateral_attestations.insert(sender, attestation);
        log_info!(self.logger, "💰 COLLATERAL: Stored attestation from {}", sender);
    }

    fn store_attestation_as_partner(&self, ledger: &mut deposits_core::Ledger, msg: &crate::wire::messages::CollateralAttestationMsg) {
        let attestation = deposits_core::types::CollateralAttestation::new(
            msg.operator, msg.collateral_partner, msg.amount, msg.block_height, msg.signature, msg.ledger_hash,
        );
        ledger.state.collateral_attestations.insert(msg.collateral_partner, attestation);
        ledger.state.received_collateral_amount = ledger.state.received_collateral_amount.saturating_add(msg.amount);
        if let Err(e) = self.persist_ledger_state(ledger) {
            log_error!(self.logger, "Failed to persist ledger: {}", e);
        }
        log_info!(self.logger, "💰 COLLATERAL: Partner stored attestation, received_collateral={}", ledger.state.received_collateral_amount);
    }

    fn create_attestation_message(&self, msg: &crate::wire::messages::CollateralAttestationMsg) -> DepositsMessage {
        DepositsMessage::LedgerUpdate(LedgerUpdateMsg::new_with_operation(
            msg.operator, msg.collateral_partner,
            LedgerOperation::CollateralAttestation {
                collateral_operator: msg.operator, amount: msg.amount, block_height: msg.block_height,
                signature: msg.signature, ledger_hash: msg.ledger_hash,
            },
        ))
    }

    fn forward_attestation_to_partners(&self, msg: &crate::wire::messages::CollateralAttestationMsg, partners: &[PublicKey]) {
        let forward_msg = self.create_attestation_message(msg);
        let ledgers = self.ledgers.lock().unwrap();

        for &partner in partners {
            if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, partner)) {
                let mut ledger = ledger_arc.write().unwrap();
                match ledger.append_mut_with_metadata(forward_msg.clone()) {
                    Ok((prev_hash, new_hash, seq)) => {
                        ledger.state.received_collateral_amount = ledger.state.received_collateral_amount.saturating_add(msg.amount);
                        let _ = self.persist_ledger_state(&*ledger);

                        // Track for broadcast
                        let hash = self.calculate_message_hash(&forward_msg);
                        let key = Self::create_partner_specific_hash(&hash, &partner);
                        self.sent_messages_for_broadcast.lock().unwrap()
                            .insert(key, (self.our_node_id, partner, forward_msg.clone(), prev_hash, new_hash, seq));
                        deposits_core::message_validation::HandlerContext::register_pending_ack(self, key, forward_msg.message_type(), partner);

                        // Send to partner
                        if let Err(e) = self.send_message(partner, forward_msg.clone()) {
                            log_error!(self.logger, "💰 COLLATERAL: Failed to send to {}: {:?}", partner, e);
                        } else {
                            log_info!(self.logger, "💰 COLLATERAL: Forwarded to {}", partner);
                        }
                    }
                    Err(e) => log_error!(self.logger, "❌ COLLATERAL: Failed to append: {}", e),
                }
            }
        }
    }

    // NOTE: handle_uncredited_payment and handle_accusation_followup removed
    // - Dispatch calls core directly
    // - Core emits event via emit_event() provider
    // - Core calls handle_fraud_proof_followup() provider for force-close and rebroadcast

    // ==================== Tombstone Message Handlers ====================

    /// Handle ChannelCloseTombstone message
    /// Append to ledger and mark as closed
    /// Handle ChannelCloseTombstone message.
    ///
    /// Core handler validates role and emits event, LDK layer handles ledger updates.
    pub(super) fn handle_channel_close_tombstone(
        &self,
        tombstone_msg: &ChannelCloseTombstoneMsg,
        message: &DepositsMessage,
        sender_node_id: PublicKey,
    ) -> Result<(), LightningError> {
        log_info!(
            self.logger,
            "₿ Received ChannelCloseTombstone from {} for channel {}",
            sender_node_id,
            crate::hex_utils::to_string(&tombstone_msg.channel_id)
        );

        // Delegate to core handler for validation
        match core_handlers::handle_channel_close_tombstone(self, tombstone_msg, sender_node_id) {
            Ok(HandlerResult::Rejected(reason)) => {
                log_warn!(self.logger, "₿ Tombstone rejected: {}", reason);
                return Ok(());
            }
            Err(e) => {
                log_error!(self.logger, "₿ Tombstone handler error: {:?}", e);
                return Ok(());
            }
            Ok(HandlerResult::Response(ResponseData::ChannelCloseTombstoneValidated {
                operator, partner, ..
            })) => {
                // Apply tombstone to ledger
                let we_are_operator = operator == self.our_node_id;
                let ledger_key = (operator, partner);

                if we_are_operator {
                    self.apply_tombstone_as_operator(&ledger_key, message);
                } else {
                    self.apply_tombstone_as_partner(&ledger_key, tombstone_msg, message);
                }
            }
            _ => {}
        }

        Ok(())
    }

    /// Apply tombstone to operator ledger
    fn apply_tombstone_as_operator(&self, ledger_key: &(PublicKey, PublicKey), message: &DepositsMessage) {
        let mut ledgers = self.ledgers.lock().unwrap();
        if let Some(ledger_arc) = ledgers.get_mut(ledger_key) {
            let mut ledger_guard = ledger_arc.write().unwrap();

            let operator_node_id = ledger_guard.operator_key();
            let partner_node_id = ledger_guard.reserves_key();
            let our_role = ledger_guard.role;
            let collateral_partners = ledger_guard.state.collateral_partners.clone();
            let ledger_address = ledger_guard.state.ledger_address.clone();

            let ledger_owned = std::mem::replace(
                &mut *ledger_guard,
                deposits_core::Ledger::new(operator_node_id, partner_node_id, our_role, collateral_partners, ledger_address)
            );

            match ledger_owned.append(message.clone()) {
                Ok((updated_ledger, _)) => {
                    *ledger_guard = updated_ledger;
                    log_info!(self.logger, "✅ Tombstone appended to operator ledger. Ledger is now closed.");
                }
                Err(e) => {
                    log_error!(self.logger, "Failed to append tombstone: {:?}", e);
                }
            }
        } else {
            log_warn!(self.logger, "₿ Tombstone for non-existent operator ledger: {:?}", ledger_key);
        }
    }

    /// Apply tombstone to partner ledger
    fn apply_tombstone_as_partner(
        &self,
        ledger_key: &(PublicKey, PublicKey),
        tombstone_msg: &ChannelCloseTombstoneMsg,
        message: &DepositsMessage,
    ) {
        use deposits_core::{Ledger, LedgerRole};
        use std::sync::{Arc, RwLock};

        let mut ledgers = self.ledgers.lock().unwrap();
        let ledger = ledgers.entry(*ledger_key).or_insert_with(|| {
            log_info!(self.logger, "📋 PARTNER: Creating partner ledger for tombstone");
            Arc::new(RwLock::new(Ledger::new(
                tombstone_msg.operator_id, self.our_node_id, LedgerRole::Partner, vec![], String::new()
            )))
        });

        let mut ledger_guard = ledger.write().unwrap();
        let signed_update = deposits_core::SignedLedgerUpdate {
            message: {
                use lightning::util::ser::Writeable;
                let mut buf = Vec::new();
                message.write(&mut buf).unwrap();
                buf
            },
            message_type: message.message_type(),
            operator_signature: [0u8; 64],
            partner_signature: [0u8; 64],
            operator_id: tombstone_msg.operator_id,
            reserves_id: tombstone_msg.reserves_id,
            sequence_number: tombstone_msg.sequence_number,
            previous_hash: [0u8; 32],
            current_hash: [0u8; 32],
            timestamp: tombstone_msg.timestamp,
        };

        let count = ledger_guard.insert_signed_unchecked(signed_update);
        log_info!(self.logger, "✅ Tombstone inserted (seq={}, added {}). Ledger closed.", tombstone_msg.sequence_number, count);
    }


    // ==================== Handshake Message Handlers ====================

    /// Handle LedgerOpenRequest message - respond to ledger creation handshake
    pub(super) fn handle_ledger_open_request(
        &self,
        init_msg: &HandshakeMsg,
        message: &DepositsMessage,
        sender_node_id: PublicKey,
    ) -> Result<(), LightningError> {
        // Check if ledger already exists
        if self.ledgers.lock().unwrap().contains_key(&(sender_node_id, self.our_node_id)) {
            self.send_handshake_rejection(init_msg, sender_node_id, "Ledger already exists");
            return Ok(());
        }

        // Validate and initialize ledger
        let ledger_address = match self.validate_ledger_address(&init_msg.ledger_address) {
            Ok(addr) => addr,
            Err(e) => {
                self.send_handshake_rejection(init_msg, sender_node_id, &e);
                return Ok(());
            }
        };

        if let Err(e) = self.initialize_ledger_as_partner_with_message(sender_node_id, ledger_address, init_msg.clone()) {
            log_error!(self.logger, "Failed to initialize ledger as partner: {}", e);
            self.send_handshake_rejection(init_msg, sender_node_id, &format!("Failed to initialize ledger: {}", e));
            return Ok(());
        }

        // Send acceptance and ACK
        self.send_handshake_acceptance(init_msg, sender_node_id);
        log_info!(self.logger, "RESPONDER: Ledger initialized, waiting for initiator to send UpdateReserves");

        if let Err(e) = self.send_acknowledgment(message, true, None, None, sender_node_id) {
            log_error!(self.logger, "Failed to send LedgerOpenRequest ACK: {}", e);
        }

        Ok(())
    }

    /// Validate ledger address from handshake
    fn validate_ledger_address(&self, addr_str: &str) -> Result<bitcoin::Address, String> {
        let addr = addr_str.parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()
            .map_err(|e| format!("Invalid address: {}", e))?;
        addr.require_network(bitcoin::Network::Regtest)
            .map_err(|e| format!("Invalid network: {}", e))
    }

    /// Send handshake rejection response
    fn send_handshake_rejection(&self, init_msg: &HandshakeMsg, peer: PublicKey, error: &str) {
        log_error!(self.logger, "Handshake rejected: {}", error);
        let response = DepositsMessage::HandshakeResponse(HandshakeResponseMsg {
            request_hash: [0u8; 32], protocol_version: init_msg.protocol_version, accepted: false,
            error: Some(error.to_string()), reserves_id: self.our_node_id,
        });
        let _ = self.send_message(peer, response);
    }

    /// Send handshake acceptance response
    fn send_handshake_acceptance(&self, init_msg: &HandshakeMsg, peer: PublicKey) {
        let response = DepositsMessage::HandshakeResponse(HandshakeResponseMsg {
            request_hash: [0u8; 32], protocol_version: init_msg.protocol_version, accepted: true,
            error: None, reserves_id: self.our_node_id,
        });
        if let Err(e) = self.send_message(peer, response) {
            log_error!(self.logger, "Failed to send LedgerOpenRequestResponse: {}", e);
        }
    }

    // ==================== Third-Party Audit Handlers ====================

    /// Handle third-party audit messages (messages where we are neither operator nor partner)
    /// Returns true if this message was handled as a third-party audit message
    pub(super) fn handle_third_party_audit(
        &self,
        message: &DepositsMessage,
        sender_node_id: PublicKey,
    ) -> Result<bool, LightningError> {
        // Check if this is a third-party audit message (we are neither operator nor partner)
        // A message is FOR US if:
        // 1. We have a ledger with the sender (existing relationship), OR
        // 2. The message's reserves_id field matches our own node ID (we are the intended partner)
        let is_for_us = if let Some(reserves_id) = message.reserves_id() {
            // If reserves_id matches our node ID, this message is intended for us
            reserves_id == self.our_node_id
        } else {
            // No reserves_id - check if we have existing ledger where sender is operator
            self.ledgers.lock().unwrap().contains_key(&(sender_node_id, self.our_node_id))
        };

        if is_for_us {
            return Ok(false); // Not a third-party audit, continue regular processing
        }

        // Handle AuditSyncRequest messages specially - they're requests for us to send updates
        if let DepositsMessage::Sync(ref request) = message {
            log_info!(
                self.logger,
                "📋 SYNC: Received sync request from {}",
                sender_node_id
            );

            if let Err(e) = self.handle_audit_sync_request(request, sender_node_id) {
                log_error!(
                    self.logger,
                    "Failed to handle audit sync request: {}",
                    e
                );
            }
            return Ok(true);
        }

        // Handle AuditSyncResponse messages - responses to our sync requests
        if let DepositsMessage::SyncResponse(ref response) = message {
            log_info!(
                self.logger,
                "📋 SYNC: Received sync response from {}",
                sender_node_id
            );

            // SyncResponseMsg is now the same type as core, just pass it through
            if let Err(e) = self.handle_audit_sync_response(response, sender_node_id) {
                log_error!(
                    self.logger,
                    "Failed to handle audit sync response: {}",
                    e
                );
            }
            return Ok(true);
        }

        // This is a third-party audit copy - store it separately
        if let Err(e) = self.handle_third_party_audit_message(message, sender_node_id) {
            log_error!(
                self.logger,
                "Failed to handle third-party audit message: {}",
                e
            );
        }

        // Don't send acknowledgment for audit messages - they're informational only
        Ok(true)
    }

    // ========================================================================
    // Reserves Commitment Protocol Handlers (UpdateReserves/AcceptReserves)
    // ========================================================================

    /// Handle incoming UpdateReserves custom message
    pub(super) fn handle_update_reserves(
        &self,
        channel_id: &[u8; 32],
        reserves_sats: u64,
        script_pubkey: &[u8],
        ledger_hash: &[u8; 32],
        remote_ledger_hash: &[u8; 32],
        sender_node_id: PublicKey,
    ) -> Result<(), LightningError> {
        log_info!(self.logger, "📥 Received UpdateReserves from {} - reserves={} sats", sender_node_id, reserves_sats);

        // Receive and accept the proposal
        self.receive_and_accept_extra_outputs(channel_id, reserves_sats, script_pubkey, ledger_hash, remote_ledger_hash, sender_node_id)?;

        // Update partner ledger state
        self.update_partner_ledger_state(sender_node_id, ledger_hash, reserves_sats);

        // Send AcceptReserves response
        let accept_msg = DepositsMessage::CoordinationResponse(CoordinationResponseMsg::AcceptReserves { channel_id: *channel_id });
        if let Err(e) = self.send_message(sender_node_id, accept_msg) {
            log_error!(self.logger, "Failed to send AcceptReserves: {:?}", e);
        } else {
            log_info!(self.logger, "📤 Sent AcceptReserves to {}", sender_node_id);
        }

        Ok(())
    }

    /// Receive and accept extra outputs proposal on channel manager
    fn receive_and_accept_extra_outputs(
        &self,
        channel_id: &[u8; 32],
        reserves_sats: u64,
        script_pubkey: &[u8],
        ledger_hash: &[u8; 32],
        remote_ledger_hash: &[u8; 32],
        sender: PublicKey,
    ) -> Result<(), LightningError> {
        use deposits_core::{ChannelId, CommitmentExtraOutput};

        let cm = self.channel_manager.as_ref().ok_or_else(|| LightningError {
            err: "Channel manager not available".to_string(), action: ErrorAction::IgnoreError,
        })?;

        let channel_id_typed = ChannelId::new(*channel_id);
        let output = CommitmentExtraOutput {
            amount_satoshis: reserves_sats,
            script_pubkey: bitcoin::ScriptBuf::from_bytes(script_pubkey.to_vec()),
        };

        let mut user_data = Vec::with_capacity(64);
        user_data.extend_from_slice(ledger_hash);
        user_data.extend_from_slice(remote_ledger_hash);

        cm.receive_extra_outputs_proposal(&sender, &channel_id_typed, vec![output], user_data)
            .map_err(|e| LightningError { err: format!("Failed to receive proposal: {}", e), action: ErrorAction::IgnoreError })?;

        cm.accept_extra_outputs_proposal(&sender, &channel_id_typed)
            .map_err(|e| LightningError { err: format!("Failed to accept proposal: {}", e), action: ErrorAction::IgnoreError })?;

        log_info!(self.logger, "✅ Accepted UpdateReserves from {}", sender);
        Ok(())
    }

    /// Update partner ledger commitment hash and reserves
    fn update_partner_ledger_state(&self, sender: PublicKey, ledger_hash: &[u8; 32], reserves_sats: u64) {
        let partner_ledger_key = (sender, self.our_node_id);
        let ledgers = self.ledgers.lock().unwrap();

        if let Some(ledger_arc) = ledgers.get(&partner_ledger_key) {
            let mut ledger = ledger_arc.write().unwrap();
            ledger.state.channel_deepest_commitment_hash = *ledger_hash;
            ledger.state.reserves.amount = reserves_sats;
            log_info!(self.logger, "🔒 Updated partner ledger: commitment_hash={:02x?}, reserves={} sats", &ledger_hash[0..8], reserves_sats);
            if let Err(e) = self.persist_ledger_state(&ledger) {
                log_error!(self.logger, "Failed to persist partner ledger state: {}", e);
            }
        } else {
            log_debug!(self.logger, "No partner ledger found for {}, skipping commitment hash update", sender);
        }
    }

    /// Handle incoming AcceptReserves custom message
    pub(super) fn handle_accept_reserves(
        &self,
        channel_id: &[u8; 32],
        sender_node_id: PublicKey,
    ) -> Result<(), LightningError> {
        use deposits_core::ChannelId;

        log_info!(self.logger, "📥 Received AcceptReserves from {} for channel {}", sender_node_id, hex::encode(&channel_id[..8]));

        let cm = self.channel_manager.as_ref().ok_or_else(|| LightningError {
            err: "Channel manager not available".to_string(), action: ErrorAction::IgnoreError,
        })?;

        cm.extra_outputs_accepted(&sender_node_id, &ChannelId::new(*channel_id))
            .map_err(|e| LightningError { err: format!("Failed to process acceptance: {}", e), action: ErrorAction::IgnoreError })?;

        log_info!(self.logger, "✅ Extra outputs accepted by {} - commitment will be updated", sender_node_id);
        Ok(())
    }
}

// Message struct conversions are handled in messages.rs
