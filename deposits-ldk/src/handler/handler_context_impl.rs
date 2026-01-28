// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Implementation of deposits-core's HandlerContext trait for DepositsHandler.
//!
//! This module bridges the LDK-specific DepositsHandler with the Lightning-agnostic
//! handler logic in deposits-core.
//!
//! Note: ValidationContext is implemented in message_validation.rs. This file
//! only implements the HandlerContext extension trait.

use bitcoin::secp256k1::{PublicKey, SecretKey};
use std::ops::Deref;
use std::sync::{Arc, Mutex};
use lightning::util::logger::Logger as LdkLogger;

use deposits_core::error::HandlerError;
use deposits_core::messages::DepositsMessage as CoreDepositsMessage;
use deposits_core::message_validation::HandlerContext;
use deposits_core::recovery::RecoveryManager;
use deposits_core::traits::ProtocolEvent;

use super::core::DepositsHandler;
use super::events::DepositsEvent;
use deposits_core::{log_info, log_warn};

impl<L: Deref + Clone + Send + Sync> HandlerContext for DepositsHandler<L>
where
    L::Target: LdkLogger,
{
    fn queue_message(&self, peer: PublicKey, msg: CoreDepositsMessage) -> Result<(), HandlerError> {
        use super::messages::{DepositsMessage, LedgerUpdateResponseMsg};
        use deposits_core::messages::{
            DepositsMessage as CoreMsg,
            LedgerUpdateResponseMsg as CoreLedgerUpdateResponseMsg,
        };

        // Convert core DepositsMessage to local DepositsMessage
        let local_msg = match msg {
            CoreMsg::LedgerUpdateResponse(v2_resp) => {
                // Convert V2 response to local format
                let local_resp: LedgerUpdateResponseMsg = v2_resp.into();
                DepositsMessage::LedgerUpdateResponse(local_resp)
            }
            CoreMsg::LedgerUpdate(v2_update) => {
                use super::messages::LedgerUpdateMsg;
                let local_update: LedgerUpdateMsg = v2_update.into();
                DepositsMessage::LedgerUpdate(local_update)
            }
            // Other message types pass through (they use the same core types)
            CoreMsg::Handshake(m) => {
                use super::messages::HandshakeMsg;
                DepositsMessage::Handshake(m.into())
            }
            CoreMsg::HandshakeResponse(m) => {
                use super::messages::HandshakeResponseMsg;
                DepositsMessage::HandshakeResponse(m.into())
            }
            CoreMsg::Sync(m) => {
                use super::messages::SyncMsg;
                DepositsMessage::Sync(m.into())
            }
            CoreMsg::SyncResponse(m) => {
                use super::messages::SyncResponseMsg;
                DepositsMessage::SyncResponse(m.into())
            }
            CoreMsg::Recovery(m) => DepositsMessage::Recovery(m),
            CoreMsg::RecoveryResponse(m) => DepositsMessage::RecoveryResponse(m),
            CoreMsg::Coordination(m) => DepositsMessage::Coordination(m),
            CoreMsg::CoordinationResponse(m) => DepositsMessage::CoordinationResponse(m),
            CoreMsg::Relay(m) => DepositsMessage::Relay(m),
            CoreMsg::RelayResponse(m) => DepositsMessage::RelayResponse(m),
        };

        // Queue the message for sending
        {
            let mut outbound = self.outbound_messages.lock().unwrap();
            outbound.entry(peer).or_default().push(local_msg.clone());
        }

        // Trigger immediate send
        self.trigger_immediate_send(peer, local_msg.message_type());

        Ok(())
    }

    fn emit_event(&self, event: ProtocolEvent) {
        // Convert core ProtocolEvent to LDK DepositsEvent
        match event {
            ProtocolEvent::DepositOpened { operator, partner, deposit_pubkey } => {
                // The DepositsEvent doesn't have a direct mapping, log it
                log_info!(
                    self.logger,
                    "Protocol event: DepositOpened - operator={}, partner={}, deposit={}",
                    operator, partner, deposit_pubkey
                );
            }
            ProtocolEvent::DepositClosed { operator, partner, deposit_pubkey, final_balance } => {
                log_info!(
                    self.logger,
                    "Protocol event: DepositClosed - operator={}, partner={}, deposit={}",
                    operator, partner, deposit_pubkey
                );
            }
            ProtocolEvent::PaymentCredited { operator, partner, deposit_pubkey, amount, payment_hash } => {
                log_info!(
                    self.logger,
                    "Protocol event: PaymentCredited - operator={}, partner={}, deposit={}, amount={}",
                    operator, partner, deposit_pubkey, amount
                );
            }
            ProtocolEvent::PaymentSent { operator, partner, deposit_pubkey, amount, payment_id } => {
                log_info!(
                    self.logger,
                    "Protocol event: PaymentSent - operator={}, partner={}, deposit={}, amount={}",
                    operator, partner, deposit_pubkey, amount
                );
            }
            ProtocolEvent::LedgerSynced { operator, partner, sequence, hash } => {
                log_info!(
                    self.logger,
                    "Protocol event: LedgerSynced - operator={}, partner={}, seq={}",
                    operator, partner, sequence
                );
            }
            ProtocolEvent::RecoveryStarted { operator, partner } => {
                log_info!(
                    self.logger,
                    "Protocol event: RecoveryStarted - operator={}, partner={}",
                    operator, partner
                );
                // Emit the LDK event
                let _ = self.event_queue.emit_deposits_event(
                    DepositsEvent::RecoveryNonCompliant {
                        operator_id: operator,
                        partner_id: partner,
                        non_conforming_votes: 0, // Filled in by caller
                        total_votes: 0,
                    }
                );
            }
            ProtocolEvent::RecoveryClaimed { operator, partner, new_operator, claim_txid } => {
                log_info!(
                    self.logger,
                    "Protocol event: RecoveryClaimed - operator={}, partner={}, new_operator={}",
                    operator, partner, new_operator
                );
                let _ = self.event_queue.emit_deposits_event(
                    DepositsEvent::RecoveryClaimCompleted {
                        old_operator: operator,
                        partner_id: partner,
                        new_operator,
                        claim_txid,
                        confirmation_block: 0, // Filled in by caller
                    }
                );
            }
            ProtocolEvent::Error { operator, partner, error } => {
                log_warn!(
                    self.logger,
                    "Protocol error: operator={}, partner={}: {}",
                    operator, partner, error
                );
            }
            ProtocolEvent::UncreditedPaymentReceived { operator, partner, payment_hash, amount_msat } => {
                log_warn!(
                    self.logger,
                    "Protocol event: UncreditedPaymentReceived (fraud proof) - operator={}, partner={}, amount={}",
                    operator, partner, amount_msat
                );
            }
            ProtocolEvent::FeeCollected { operator, partner, deposit_pubkey, amount, block_height } => {
                log_info!(
                    self.logger,
                    "Protocol event: FeeCollected - operator={}, partner={}, deposit={}, amount={}, block={}",
                    operator, partner, deposit_pubkey, amount, block_height
                );
            }
            ProtocolEvent::LedgerClosed { operator, partner } => {
                log_info!(
                    self.logger,
                    "Protocol event: LedgerClosed - operator={}, partner={}",
                    operator, partner
                );
            }
            ProtocolEvent::InvoiceCosignRequested { operator, partner, deposit_pubkey, amount, payment_hash } => {
                log_info!(
                    self.logger,
                    "Protocol event: InvoiceCosignRequested - operator={}, partner={}, deposit={}, amount={}",
                    operator, partner, deposit_pubkey, amount
                );
            }
            ProtocolEvent::RecoveryClaimRequested { operator, partner, claimant, tier_index } => {
                log_info!(
                    self.logger,
                    "Protocol event: RecoveryClaimRequested - operator={}, partner={}, claimant={}, tier={}",
                    operator, partner, claimant, tier_index
                );
            }
            ProtocolEvent::RecoveryClaimSignatureReceived { operator, partner, signer } => {
                log_info!(
                    self.logger,
                    "Protocol event: RecoveryClaimSignatureReceived - operator={}, partner={}, signer={}",
                    operator, partner, signer
                );
            }
            ProtocolEvent::RecoveryClaimCompleted { old_operator, partner, new_operator, claim_txid, confirmation_block } => {
                log_info!(
                    self.logger,
                    "Protocol event: RecoveryClaimCompleted - old_operator={}, partner={}, new_operator={}",
                    old_operator, partner, new_operator
                );
            }
            ProtocolEvent::ChannelClosed { operator, partner, channel_id, reason } => {
                log_info!(
                    self.logger,
                    "Protocol event: ChannelClosed - operator={}, partner={}, reason={:?}",
                    operator, partner, reason
                );
            }
            ProtocolEvent::QuorumMemberJoined { operator, partner, member } => {
                log_info!(
                    self.logger,
                    "Protocol event: QuorumMemberJoined - operator={}, partner={}, member={}",
                    operator, partner, member
                );
            }
        }
    }

    fn recovery_manager(&self) -> Option<Arc<Mutex<RecoveryManager>>> {
        Some(Arc::clone(&self.recovery_manager))
    }

    fn claim_manager(&self) -> Option<Arc<Mutex<deposits_core::recovery_claim::ClaimManager>>> {
        Some(Arc::clone(&self.claim_manager))
    }

    fn quorum_manager(&self) -> Option<&deposits_core::quorum::QuorumManager> {
        // Return a reference to our quorum manager
        Some(&self.quorum_manager)
    }

    fn our_secret_key(&self) -> Option<SecretKey> {
        self.node_secret_key
    }

    fn current_block_height(&self) -> u32 {
        self.channel_manager
            .as_ref()
            .map(|cm| cm.current_best_block_height())
            .unwrap_or(0)
    }

    fn sign_ledger_update(
        &self,
        message_bytes: &[u8],
        message_type: u16,
        sequence: u64,
        prev_hash: &[u8; 32],
        new_hash: &[u8; 32],
    ) -> Option<[u8; 64]> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        match self.sign_as_partner(message_bytes, message_type, sequence, prev_hash, new_hash, timestamp) {
            Ok(sig) => Some(sig),
            Err(e) => {
                log_warn!(self.logger, "Failed to sign ledger update: {:?}", e);
                None
            }
        }
    }

    fn persist_ledger(&self, operator: &PublicKey, partner: &PublicKey) -> Result<(), String> {
        let ledgers = self.ledgers.lock().unwrap();
        if let Some(ledger_arc) = ledgers.get(&(*operator, *partner)) {
            let ledger = ledger_arc.read().map_err(|e| format!("Lock error: {:?}", e))?;
            self.persist_ledger_state(&*ledger)
                .map_err(|e| format!("Persist error: {:?}", e))
        } else {
            Err(format!("Ledger not found for ({}, {})", operator, partner))
        }
    }

    fn sync_quorum_member(&self, operator: PublicKey, partner: PublicKey, collateral_partner: PublicKey, add: bool) {
        use deposits_core::quorum::LedgerId;

        let ledger_id = LedgerId::new(operator, partner);
        if add {
            if let Err(e) = self.quorum_manager.add_member(&ledger_id, collateral_partner) {
                log_info!(self.logger, "Quorum add_member (expected to fail for partners): {:?}", e);
            }
        } else {
            if let Err(e) = self.quorum_manager.remove_member(&ledger_id, &collateral_partner) {
                log_info!(self.logger, "Quorum remove_member (expected to fail for partners): {:?}", e);
            }
        }
    }

    fn send_ledger_update_ack(
        &self,
        peer: PublicKey,
        message_hash: [u8; 32],
        message_type: u16,
        success: bool,
        error_message: Option<String>,
        sequence: u64,
        prev_hash: [u8; 32],
        new_hash: [u8; 32],
        partner_signature: Option<[u8; 64]>,
    ) -> Result<(), HandlerError> {
        use super::messages::{DepositsMessage, LedgerUpdateResponseMsg};

        let ack = DepositsMessage::LedgerUpdateResponse(LedgerUpdateResponseMsg {
            operator_id: peer, // Responding to the operator who sent the update
            partner_id: self.our_node_id,
            request_hash: message_hash,
            accepted: success,
            error: error_message,
            partner_signature,
            confirmed_sequence: sequence,
            confirmed_hash: new_hash,
        });

        log_info!(
            self.logger,
            "📤 Sending ledger update ACK to {} (seq={}, success={}, hash={:02x?})",
            peer, sequence, success, &new_hash[0..8]
        );

        // Queue and trigger immediate send
        {
            let mut outbound = self.outbound_messages.lock().unwrap();
            outbound.entry(peer).or_default().push(ack.clone());
        }
        self.trigger_immediate_send(peer, ack.message_type());

        Ok(())
    }

    fn register_pending_ack(&self, hash: [u8; 32], msg_type: u16, peer: PublicKey) {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut pending_acks = self.pending_acks.lock().unwrap();
        pending_acks.insert(hash, deposits_core::PendingAck {
            message_type: msg_type,
            timestamp,
            peer,
        });
    }

    fn complete_pending_ack(&self, hash: &[u8; 32]) -> Option<deposits_core::PendingAck> {
        let mut pending_acks = self.pending_acks.lock().unwrap();
        pending_acks.remove(hash)
    }

    fn get_timed_out_acks(&self, threshold_secs: u64) -> Vec<([u8; 32], deposits_core::PendingAck)> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let pending_acks = self.pending_acks.lock().unwrap();
        pending_acks
            .iter()
            .filter(|(_, ack)| now.saturating_sub(ack.timestamp) > threshold_secs)
            .map(|(hash, ack)| (*hash, ack.clone()))
            .collect()
    }

    fn store_signed_update(
        &self,
        operator: &PublicKey,
        partner: &PublicKey,
        update: deposits_core::SignedLedgerUpdate,
    ) -> Result<(), String> {
        let mut logs = self.signed_update_logs.lock().unwrap();
        let log = logs.entry((*operator, *partner)).or_insert_with(|| {
            deposits_core::SignedLedgerUpdateLog {
                operator_id: *operator,
                partner_id: *partner,
                updates: Vec::new(),
                next_sequence: 0,
                pending_updates: std::collections::HashMap::new(),
            }
        });
        log.updates.push(update);
        log.next_sequence = log.updates.len() as u64;
        Ok(())
    }

    fn get_signed_updates(
        &self,
        operator: &PublicKey,
        partner: &PublicKey,
    ) -> Option<Vec<deposits_core::SignedLedgerUpdate>> {
        let logs = self.signed_update_logs.lock().unwrap();
        logs.get(&(*operator, *partner)).map(|log| log.updates.clone())
    }

    fn verify_and_store_signed_update(&self, update: deposits_core::SignedLedgerUpdate) -> Result<(), String> {
        // Store in signed_update_logs
        let operator = update.operator_id;
        let partner = update.partner_id;
        self.store_signed_update(&operator, &partner, update)
    }

    fn track_for_broadcast(
        &self,
        msg_hash: [u8; 32],
        operator: PublicKey,
        partner: PublicKey,
        msg: deposits_core::messages::DepositsMessage,
        prev_hash: [u8; 32],
        new_hash: [u8; 32],
        seq: u64,
    ) {
        // Convert core message to local message type
        use super::messages::DepositsMessage as LocalMessage;
        let local_msg: LocalMessage = LocalMessage::from_v2(msg);

        let mut sent_messages = self.sent_messages_for_broadcast.lock().unwrap();
        sent_messages.insert(msg_hash, (operator, partner, local_msg, prev_hash, new_hash, seq));
    }

    fn complete_broadcast(&self, msg_hash: [u8; 32], partner_sig: Option<[u8; 64]>) -> Result<(), String> {
        // Get the tracked message
        let info = {
            let sent_messages = self.sent_messages_for_broadcast.lock().unwrap();
            sent_messages.get(&msg_hash).cloned()
        };

        if let Some((operator, partner, _msg, _prev_hash, _new_hash, _seq)) = info {
            // Broadcast to other partners
            if let Err(e) = self.broadcast_message_to_other_partners(msg_hash, partner, partner_sig) {
                return Err(format!("Broadcast failed: {:?}", e));
            }
            // Remove from tracking
            let mut sent_messages = self.sent_messages_for_broadcast.lock().unwrap();
            sent_messages.remove(&msg_hash);
        }

        Ok(())
    }

    fn get_broadcast_recipients(&self, operator: &PublicKey, partner: &PublicKey) -> Vec<PublicKey> {
        use deposits_core::quorum::LedgerId;
        let ledger_id = LedgerId::new(*operator, *partner);
        self.quorum_manager
            .get_quorum(&ledger_id)
            .map(|members| members.into_iter().filter(|m| m != partner).collect())
            .unwrap_or_default()
    }
}

/// Extension trait for using core handlers with LDK
pub trait CoreHandlerExt<L: Deref + Clone + Send + Sync>
where
    L::Target: LdkLogger,
{
    /// Handle a collateral consent request using core logic
    fn handle_collateral_consent_request_core(
        &self,
        msg: &deposits_core::wire_messages::CollateralConsentRequestMsg,
        sender: PublicKey,
    ) -> Result<deposits_core::message_handlers::HandlerResult, HandlerError>;

    /// Handle a collateral consent response using core logic
    fn handle_collateral_consent_response_core(
        &self,
        msg: &deposits_core::wire_messages::CollateralConsentResponseMsg,
        sender: PublicKey,
    ) -> Result<deposits_core::message_handlers::HandlerResult, HandlerError>;

    /// Handle a recovery vote using core logic
    fn handle_recovery_vote_core(
        &self,
        msg: &deposits_core::wire_messages::RecoveryVoteMsg,
        sender: PublicKey,
    ) -> Result<deposits_core::message_handlers::HandlerResult, HandlerError>;
}

impl<L: Deref + Clone + Send + Sync> CoreHandlerExt<L> for DepositsHandler<L>
where
    L::Target: LdkLogger,
{
    fn handle_collateral_consent_request_core(
        &self,
        msg: &deposits_core::wire_messages::CollateralConsentRequestMsg,
        sender: PublicKey,
    ) -> Result<deposits_core::message_handlers::HandlerResult, HandlerError> {
        deposits_core::handle_collateral_consent_request(self, msg, sender)
    }

    fn handle_collateral_consent_response_core(
        &self,
        msg: &deposits_core::wire_messages::CollateralConsentResponseMsg,
        sender: PublicKey,
    ) -> Result<deposits_core::message_handlers::HandlerResult, HandlerError> {
        deposits_core::handle_collateral_consent_response(self, msg, sender)
    }

    fn handle_recovery_vote_core(
        &self,
        msg: &deposits_core::wire_messages::RecoveryVoteMsg,
        sender: PublicKey,
    ) -> Result<deposits_core::message_handlers::HandlerResult, HandlerError> {
        deposits_core::handle_recovery_vote(self, msg, sender)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests would go here
    // For now, we rely on the integration tests in deposits-ldk
}
