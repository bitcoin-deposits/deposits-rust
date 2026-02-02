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
use std::str::FromStr;
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
        use deposits_core::messages::DepositsMessage as CoreMsg;

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
            CoreMsg::Handshake(m) => DepositsMessage::Handshake(m.into()),
            CoreMsg::HandshakeResponse(m) => DepositsMessage::HandshakeResponse(m.into()),
            CoreMsg::Sync(m) => DepositsMessage::Sync(m.into()),
            CoreMsg::SyncResponse(m) => DepositsMessage::SyncResponse(m.into()),
            CoreMsg::Recovery(m) => DepositsMessage::Recovery(m),
            CoreMsg::RecoveryResponse(m) => DepositsMessage::RecoveryResponse(m),
            CoreMsg::Coordination(m) => DepositsMessage::Coordination(m),
            CoreMsg::CoordinationResponse(m) => DepositsMessage::CoordinationResponse(m),
            CoreMsg::Relay(m) => DepositsMessage::Relay(m),
            CoreMsg::RelayResponse(m) => DepositsMessage::RelayResponse(m),
            CoreMsg::ReservesAddOutput(m) => DepositsMessage::ReservesAddOutput(m),
            CoreMsg::ReservesRemoveOutput(m) => DepositsMessage::ReservesRemoveOutput(m),
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
            ProtocolEvent::DepositOpened { operator, reserves_id, deposit_pubkey } => {
                // The DepositsEvent doesn't have a direct mapping, log it
                log_info!(
                    self.logger,
                    "Protocol event: DepositOpened - operator={}, partner={}, deposit={}",
                    operator, reserves_id, deposit_pubkey
                );
            }
            ProtocolEvent::DepositClosed { operator, reserves_id, deposit_pubkey, .. } => {
                log_info!(
                    self.logger,
                    "Protocol event: DepositClosed - operator={}, partner={}, deposit={}",
                    operator, reserves_id, deposit_pubkey
                );
            }
            ProtocolEvent::InvoiceCredited { operator, reserves_id, deposit_pubkey, amount, .. } => {
                log_info!(
                    self.logger,
                    "Protocol event: InvoiceCredited - operator={}, partner={}, deposit={}, amount={}",
                    operator, reserves_id, deposit_pubkey, amount
                );
            }
            ProtocolEvent::InvoiceSent { operator, reserves_id, deposit_pubkey, amount, .. } => {
                log_info!(
                    self.logger,
                    "Protocol event: InvoiceSent - operator={}, partner={}, deposit={}, amount={}",
                    operator, reserves_id, deposit_pubkey, amount
                );
            }
            ProtocolEvent::LedgerSynced { operator, reserves_id, sequence, .. } => {
                log_info!(
                    self.logger,
                    "Protocol event: LedgerSynced - operator={}, partner={}, seq={}",
                    operator, reserves_id, sequence
                );
            }
            ProtocolEvent::RecoveryStarted { operator, reserves_id } => {
                log_info!(
                    self.logger,
                    "Protocol event: RecoveryStarted - operator={}, partner={}",
                    operator, reserves_id
                );
                // Emit the LDK event
                // Parse reserves_id back to PublicKey (in LDK it's always a pubkey string)
                if let Ok(reserves_pubkey) = PublicKey::from_str(&reserves_id) {
                    let _ = self.event_queue.emit_deposits_event(
                        DepositsEvent::RecoveryNonCompliant {
                            operator_id: operator,
                            reserves_id: reserves_pubkey,
                            non_conforming_votes: 0, // Filled in by caller
                            total_votes: 0,
                        }
                    );
                }
            }
            ProtocolEvent::RecoveryClaimed { operator, reserves_id, new_operator, claim_txid } => {
                log_info!(
                    self.logger,
                    "Protocol event: RecoveryClaimed - operator={}, partner={}, new_operator={}",
                    operator, reserves_id, new_operator
                );
                if let Ok(reserves_pubkey) = PublicKey::from_str(&reserves_id) {
                    let _ = self.event_queue.emit_deposits_event(
                        DepositsEvent::RecoveryClaimCompleted {
                            old_operator: operator,
                            reserves_id: reserves_pubkey,
                            new_operator,
                            claim_txid,
                            confirmation_block: 0, // Filled in by caller
                        }
                    );
                }
            }
            ProtocolEvent::Error { operator, reserves_id, error } => {
                log_warn!(
                    self.logger,
                    "Protocol error: operator={}, partner={}: {}",
                    operator, reserves_id, error
                );
            }
            ProtocolEvent::UncreditedPaymentReceived { operator, reserves_id, payment_hash, deposit_pubkey, amount_msat, settlement_sequence } => {
                log_warn!(
                    self.logger,
                    "Protocol event: UncreditedPaymentReceived (fraud proof) - operator={}, partner={}, amount={}",
                    operator, reserves_id, amount_msat
                );
                // Emit the LDK event (field is named 'partner' in the event)
                if let Ok(partner) = PublicKey::from_str(&reserves_id) {
                    let _ = self.event_queue.emit_deposits_event(
                        DepositsEvent::UncreditedPaymentAccusation {
                            operator,
                            partner,
                            payment_hash,
                            deposit_pubkey,
                            amount_msat,
                            settlement_sequence,
                        }
                    );
                }
            }
            ProtocolEvent::FeeCollected { operator, reserves_id, deposit_pubkey, amount, block_height } => {
                log_info!(
                    self.logger,
                    "Protocol event: FeeCollected - operator={}, partner={}, deposit={}, amount={}, block={}",
                    operator, reserves_id, deposit_pubkey, amount, block_height
                );
            }
            ProtocolEvent::LedgerClosed { operator, reserves_id } => {
                log_info!(
                    self.logger,
                    "Protocol event: LedgerClosed - operator={}, partner={}",
                    operator, reserves_id
                );
            }
            ProtocolEvent::InvoiceCosignRequested { operator, reserves_id, deposit_pubkey, amount, .. } => {
                log_info!(
                    self.logger,
                    "Protocol event: InvoiceCosignRequested - operator={}, partner={}, deposit={}, amount={}",
                    operator, reserves_id, deposit_pubkey, amount
                );
            }
            ProtocolEvent::RecoveryClaimRequested { operator, reserves_id, claimant, tier_index } => {
                log_info!(
                    self.logger,
                    "Protocol event: RecoveryClaimRequested - operator={}, partner={}, claimant={}, tier={}",
                    operator, reserves_id, claimant, tier_index
                );
            }
            ProtocolEvent::RecoveryClaimSignatureReceived { operator, reserves_id, signer } => {
                log_info!(
                    self.logger,
                    "Protocol event: RecoveryClaimSignatureReceived - operator={}, partner={}, signer={}",
                    operator, reserves_id, signer
                );
            }
            ProtocolEvent::RecoveryClaimCompleted { old_operator, reserves_id, new_operator, claim_txid, confirmation_block } => {
                log_info!(
                    self.logger,
                    "Protocol event: RecoveryClaimCompleted - old_operator={}, partner={}, new_operator={}",
                    old_operator, reserves_id, new_operator
                );
                if let Ok(reserves_pubkey) = PublicKey::from_str(&reserves_id) {
                    let _ = self.event_queue.emit_deposits_event(
                        DepositsEvent::RecoveryClaimCompleted {
                            old_operator,
                            reserves_id: reserves_pubkey,
                            new_operator,
                            claim_txid,
                            confirmation_block,
                        }
                    );
                }
            }
            ProtocolEvent::ChannelClosed { operator, reserves_id, reason, .. } => {
                log_info!(
                    self.logger,
                    "Protocol event: ChannelClosed - operator={}, partner={}, reason={:?}",
                    operator, reserves_id, reason
                );
            }
            ProtocolEvent::QuorumMemberJoined { operator, reserves_id, member } => {
                log_info!(
                    self.logger,
                    "Protocol event: QuorumMemberJoined - operator={}, partner={}, member={}",
                    operator, reserves_id, member
                );
            }
            ProtocolEvent::ReservesSpendReady { vote_round_id, operator, reserves_id, signed_tx_bytes, conforming_votes, threshold } => {
                log_info!(
                    self.logger,
                    "Protocol event: ReservesSpendReady - operator={}, partner={}, votes={}/{}",
                    operator, reserves_id, conforming_votes, threshold
                );
                if let Ok(reserves_pubkey) = PublicKey::from_str(&reserves_id) {
                    let _ = self.event_queue.emit_deposits_event(
                        DepositsEvent::ReservesSpendReady {
                            vote_round_id,
                            operator_id: operator,
                            reserves_id: reserves_pubkey,
                            signed_tx_bytes,
                            conforming_votes,
                            threshold,
                        }
                    );
                }
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

    fn persist_ledger(&self, operator: &PublicKey, partner: &str) -> Result<(), String> {
        let ledgers = self.ledgers.lock().unwrap();
        if let Some(ledger_arc) = ledgers.get(&(*operator, partner.to_string())) {
            let ledger = ledger_arc.read().map_err(|e| format!("Lock error: {:?}", e))?;
            self.persist_ledger_state(&*ledger)
                .map_err(|e| format!("Persist error: {:?}", e))
        } else {
            Err(format!("Ledger not found for ({}, {})", operator, partner))
        }
    }

    fn sync_quorum_member(&self, operator: PublicKey, partner: &str, quorum_member: PublicKey, add: bool) {
        use deposits_core::quorum::LedgerId;

        let ledger_id = LedgerId::new(operator, partner.to_string());
        if add {
            if let Err(e) = self.quorum_manager.add_member(&ledger_id, quorum_member) {
                log_info!(self.logger, "Quorum add_member (expected to fail for partners): {:?}", e);
            }
        } else {
            if let Err(e) = self.quorum_manager.remove_member(&ledger_id, &quorum_member) {
                log_info!(self.logger, "Quorum remove_member (expected to fail for partners): {:?}", e);
            }
        }
    }

    #[allow(unused_variables)]
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
            reserves_id: self.our_node_id.to_string(),
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
        // Get ledger_id from the ledger
        let ledger_id = {
            let ledgers = self.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&(*operator, partner.to_string())) {
                let ledger = ledger_arc.read().map_err(|e| format!("Lock error: {:?}", e))?;
                ledger.ledger_id()
            } else {
                // Fall back to the update's ledger_id
                update.ledger_id
            }
        };

        let mut logs = self.signed_update_logs.lock().unwrap();
        let log = logs.entry(ledger_id).or_insert_with(|| {
            deposits_core::SignedLedgerUpdateLog {
                ledger_id,
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
        // Get ledger_id from the ledger
        let ledger_id = {
            let ledgers = self.ledgers.lock().unwrap();
            let ledger_arc = ledgers.get(&(*operator, partner.to_string()))?;
            let ledger = ledger_arc.read().ok()?;
            ledger.ledger_id()
        };

        let logs = self.signed_update_logs.lock().unwrap();
        logs.get(&ledger_id).map(|log| log.updates.clone())
    }

    fn verify_and_store_signed_update(&self, update: deposits_core::SignedLedgerUpdate) -> Result<(), String> {
        // Store directly by ledger_id
        let ledger_id = update.ledger_id;

        let mut logs = self.signed_update_logs.lock().unwrap();
        let log = logs.entry(ledger_id).or_insert_with(|| {
            deposits_core::SignedLedgerUpdateLog {
                ledger_id,
                updates: Vec::new(),
                next_sequence: 0,
                pending_updates: std::collections::HashMap::new(),
            }
        });
        log.updates.push(update);
        log.next_sequence = log.updates.len() as u64;
        Ok(())
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
        sent_messages.insert(msg_hash, (operator, partner.to_string(), local_msg, prev_hash, new_hash, seq));
    }

    fn complete_broadcast(&self, msg_hash: [u8; 32], partner_sig: Option<[u8; 64]>) -> Result<(), String> {
        // Get the tracked message
        let info = {
            let sent_messages = self.sent_messages_for_broadcast.lock().unwrap();
            sent_messages.get(&msg_hash).cloned()
        };

        if let Some((_operator, reserves_id, _msg, _prev_hash, _new_hash, _seq)) = info {
            // Broadcast to other partners - parse reserves_id to PublicKey
            let partner_pubkey = PublicKey::from_str(&reserves_id)
                .map_err(|e| format!("Invalid partner pubkey: {}", e))?;
            if let Err(e) = self.broadcast_message_to_other_partners(msg_hash, partner_pubkey, partner_sig) {
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
        let ledger_id = LedgerId::new(*operator, partner.to_string());
        self.quorum_manager
            .get_quorum(&ledger_id)
            .map(|members| members.into_iter().filter(|m| m != partner).collect())
            .unwrap_or_default()
    }

    fn handle_fraud_proof_followup(
        &self,
        accused_operator: PublicKey,
        accusation_msg: deposits_core::messages::DepositsMessage,
    ) {
        // Skip if we're the accused operator
        if accused_operator == self.our_node_id {
            return;
        }

        // Check if we have a channel with the accused operator
        let our_ledger_key = (accused_operator, self.our_node_id.to_string());
        let have_channel = {
            let ledgers = self.ledgers.lock().unwrap();
            ledgers.contains_key(&our_ledger_key)
        };

        if !have_channel {
            return;
        }

        log_warn!(
            self.logger,
            "⚠️ FRAUD: We have channel with accused operator {} - force-closing",
            accused_operator
        );

        // Force-close our channel with the accused operator
        if let Some(ref cm) = self.channel_manager {
            let channels = cm.list_channels();
            if let Some(channel) = channels.iter().find(|c| c.counterparty_node_id == accused_operator) {
                let reason = format!("Fraud proof: operator {} accused of uncredited payment", accused_operator);
                if let Err(e) = cm.force_close_broadcasting_latest_txn(&channel.channel_id, &accused_operator, reason) {
                    log_warn!(self.logger, "⚠️ FRAUD: Force-close failed: {:?}", e);
                } else {
                    log_warn!(self.logger, "⚠️ FRAUD: Force-closed channel with {}", accused_operator);
                }
            }
        }

        // Rebroadcast to our quorum members
        let partners = {
            let ledgers = self.ledgers.lock().unwrap();
            ledgers.get(&(accused_operator, self.our_node_id.to_string()))
                .map(|l| l.read().unwrap().state.quorum_members.clone())
                .unwrap_or_default()
        };

        // Convert core message to local message type
        let local_msg = super::messages::DepositsMessage::from_v2(accusation_msg);

        for partner in partners {
            if partner != self.our_node_id {
                if let Err(e) = self.send_message(partner, local_msg.clone()) {
                    log_warn!(self.logger, "⚠️ FRAUD: Failed to rebroadcast to {}: {:?}", partner, e);
                } else {
                    log_info!(self.logger, "⚠️ FRAUD: Rebroadcast accusation to {}", partner);
                }
            }
        }
    }

    fn add_claim_signature(
        &self,
        operator: PublicKey,
        partner: PublicKey,
        signer: PublicKey,
        signature: [u8; 64],
    ) -> Result<bool, String> {
        let ledger_id = (operator, partner);
        let mut claim_manager = self.claim_manager.lock().unwrap();

        match claim_manager.add_peer_signature(&ledger_id, &signer, signature) {
            Ok(has_sufficient) => {
                log_info!(self.logger, "🔄 RECOVERY: Signature stored (threshold_met={})", has_sufficient);
                if has_sufficient {
                    // Emit event when threshold is reached - reserves_id is PublicKey in LDK events
                    let _ = self.event_queue.emit_deposits_event(
                        super::events::DepositsEvent::RecoveryClaimReady {
                            operator_id: operator,
                            reserves_id: partner, // partner is PublicKey
                        },
                    );
                }
                Ok(has_sufficient)
            }
            Err(e) => {
                log_warn!(self.logger, "🔄 RECOVERY: Failed to add signature: {:?}", e);
                Err(format!("{:?}", e))
            }
        }
    }

    fn remove_claim(&self, operator: PublicKey, partner: PublicKey) {
        let ledger_id = (operator, partner);
        let mut claim_manager = self.claim_manager.lock().unwrap();
        claim_manager.remove_claim(&ledger_id);
        log_info!(self.logger, "🔄 RECOVERY: Removed claim for ({}, {})", operator, partner);
    }

    fn send_quorum_state_sync(&self, member: PublicKey, operator: PublicKey, partner: &str) {
        // Parse partner to PublicKey for send_state_sync_to_member
        if let Ok(partner_pubkey) = PublicKey::from_str(partner) {
            self.send_state_sync_to_member(member, operator, partner_pubkey);
        }
    }

    fn add_quorum_vote(
        &self,
        vote_round_id: [u8; 32],
        voter: PublicKey,
        vote: bool,
        spend_signature: Option<[u8; 64]>,
    ) -> std::option::Option<(bitcoin::secp256k1::PublicKey, std::string::String, Vec<u8>, u32, u32)> {
        let mut rounds = self.pending_vote_rounds.lock().unwrap();
        let round = rounds.get_mut(&vote_round_id)?;

        round.votes.insert(voter, (vote, spend_signature));
        log_info!(self.logger, "📋 QUORUM: Vote round now has {}/{} conforming votes",
            round.conforming_vote_count(), round.threshold);

        if round.threshold_reached() && !round.tx_broadcast {
            round.tx_broadcast = true;

            // Prepare spend data
            let signatures = round.collect_spend_signatures();
            let mut data = Vec::new();
            data.extend_from_slice(&round.reserves_outpoint);
            data.extend_from_slice(&(round.destination_script.len() as u32).to_le_bytes());
            data.extend_from_slice(&round.destination_script);
            data.extend_from_slice(&round.claimed_reserves.to_le_bytes());
            data.extend_from_slice(&round.fee_rate_sat_vbyte.to_le_bytes());
            data.extend_from_slice(&(signatures.len() as u32).to_le_bytes());
            for (pubkey, sig) in &signatures {
                data.extend_from_slice(&pubkey.serialize());
                data.extend_from_slice(sig);
            }

            Some((
                round.operator_id,
                round.reserves_id.to_string(),
                data,
                round.conforming_vote_count() as u32,
                round.threshold as u32,
            ))
        } else {
            None
        }
    }

    fn complete_consent_request(
        &self,
        operator: PublicKey,
        partner: &str,
        granted: bool,
        signature: [u8; 64],
    ) -> bool {
        use super::messages::{DepositsMessage, CoordinationMsg};

        // Calculate the hash for the original consent request
        let original = DepositsMessage::Coordination(CoordinationMsg::CollateralConsentRequest {
            operator_id: operator,
            reserves_id: partner.to_string(),
            operator_signature: [0u8; 64],
        });
        let hash = self.calculate_message_hash(&original);

        let mut pending = self.pending_consent_requests.lock().unwrap();
        if let Some(tx) = pending.remove(&hash) {
            if granted {
                let _ = tx.send(Ok(signature));
            } else {
                let _ = tx.send(Err("Quorum member denied consent".to_string()));
            }
            log_info!(self.logger, "📋 CONSENT: Completed pending request (granted={})", granted);
            true
        } else {
            log_warn!(self.logger, "📋 CONSENT: No pending request for hash {:02x?}", &hash[..8]);
            false
        }
    }

    fn send_audit_to_quorum_member(
        &self,
        operator: PublicKey,
        partner: &str,
        new_quorum_member: PublicKey,
        signature: [u8; 64],
    ) {
        use super::messages::{DepositsMessage, CoordinationResponseMsg};

        log_info!(self.logger, "📋 SYNC: Sending audit history to new quorum member {}", new_quorum_member);

        let response = DepositsMessage::CoordinationResponse(CoordinationResponseMsg::CollateralConsentResponse {
            request_hash: [0u8; 32],
            operator_id: operator,
            reserves_id: partner.to_string(),
            consent_granted: true,
            quorum_member_signature: signature,
        });

        // Parse partner to PublicKey for send_audit_update_to_new_quorum_member
        let partner_pubkey = match PublicKey::from_str(partner) {
            Ok(pk) => pk,
            Err(e) => {
                log_warn!(self.logger, "📋 SYNC: Invalid partner pubkey: {:?}", e);
                return;
            }
        };
        if let Err(e) = self.send_audit_update_to_new_quorum_member(partner_pubkey, new_quorum_member, &response) {
            log_warn!(self.logger, "📋 SYNC: Failed to send audit history: {:?}", e);
        }
    }

    fn verify_consent_signature(
        &self,
        operator: PublicKey,
        partner: &str,
        signature: [u8; 64],
        signer: PublicKey,
    ) -> bool {
        use bitcoin::hashes::{Hash, sha256};
        use bitcoin::secp256k1::{Secp256k1, Message, ecdsa::Signature};

        let mut preimage = Vec::new();
        preimage.extend_from_slice(b"COLLATERAL_CONSENT");
        preimage.extend_from_slice(&operator.serialize());
        preimage.extend_from_slice(partner.as_bytes());

        let hash = sha256::Hash::hash(&preimage);
        let secp_msg = Message::from_digest(hash.to_byte_array());
        let secp = Secp256k1::new();

        match Signature::from_compact(&signature) {
            Ok(sig) => {
                if secp.verify_ecdsa(&secp_msg, &sig, &signer).is_ok() {
                    log_info!(self.logger, "📋 CONSENT: Verified signature from {}", signer);
                    true
                } else {
                    log_warn!(self.logger, "📋 CONSENT: Invalid signature from {}", signer);
                    false
                }
            }
            Err(e) => {
                log_warn!(self.logger, "📋 CONSENT: Malformed signature from {}: {}", signer, e);
                false
            }
        }
    }

    // ========================================================================
    // Quorum State Sync Methods
    // ========================================================================

    fn get_signed_update_log_state(
        &self,
        operator: &PublicKey,
        partner: &str,
    ) -> Option<(u64, [u8; 32])> {
        // Get ledger_id from the ledger
        let ledger_id = {
            let ledgers = self.ledgers.lock().unwrap();
            let ledger_arc = ledgers.get(&(*operator, partner.to_string()))?;
            let ledger = ledger_arc.read().ok()?;
            ledger.ledger_id()
        };

        let logs = self.signed_update_logs.lock().unwrap();
        logs.get(&ledger_id).map(|log| {
            let sequence = log.next_sequence.saturating_sub(1);
            let state_hash = log.updates.last()
                .map(|u| u.current_hash)
                .unwrap_or([0u8; 32]);
            (sequence, state_hash)
        })
    }

    fn update_quorum_member_state(
        &self,
        operator: PublicKey,
        partner: &str,
        sequence: u64,
        state_hash: [u8; 32],
    ) -> Result<(), String> {
        use deposits_core::quorum::LedgerId;

        let ledger_id = LedgerId::new(operator, partner.to_string());
        self.quorum_manager.update_member_state(
            &ledger_id,
            &self.our_node_id,
            sequence,
            state_hash,
        ).map_err(|e| format!("{:?}", e))
    }

    // ========================================================================
    // Vote Request Methods
    // ========================================================================

    fn init_vote_round(
        &self,
        vote_round_id: [u8; 32],
        operator: PublicKey,
        partner: &str,
        sequence_number: u64,
        state_hash: [u8; 32],
        claimed_reserves: u64,
        reserves_outpoint: Vec<u8>,
        destination_script: Vec<u8>,
        fee_rate_sat_vbyte: u64,
        threshold: usize,
    ) -> bool {
        use super::core::VoteRoundState;
        use std::collections::HashMap;
        use std::time::{SystemTime, UNIX_EPOCH};

        // Parse partner string to PublicKey for VoteRoundState
        let partner_pubkey = match PublicKey::from_str(partner) {
            Ok(pk) => pk,
            Err(_) => return false, // Invalid partner pubkey
        };

        let mut rounds = self.pending_vote_rounds.lock().unwrap();
        rounds.entry(vote_round_id).or_insert_with(|| {
            VoteRoundState {
                operator_id: operator,
                reserves_id: partner_pubkey,
                sequence_number,
                state_hash,
                claimed_reserves,
                reserves_outpoint,
                destination_script,
                fee_rate_sat_vbyte,
                threshold,
                votes: HashMap::new(),
                tx_broadcast: false,
                created_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
            }
        });
        true
    }

    fn sign_quorum_vote(
        &self,
        vote_round_id: &[u8; 32],
        vote: bool,
        sequence: u64,
        state_hash: &[u8; 32],
    ) -> Option<[u8; 64]> {
        use bitcoin::hashes::{Hash, sha256};
        use bitcoin::secp256k1::{Secp256k1, Message};

        let secret = self.node_secret_key.as_ref()?;

        let mut data = Vec::new();
        data.extend_from_slice(vote_round_id);
        data.push(if vote { 1 } else { 0 });
        data.extend_from_slice(&sequence.to_le_bytes());
        data.extend_from_slice(state_hash);

        let secp = Secp256k1::new();
        let msg_hash = Message::from_digest(sha256::Hash::hash(&data).to_byte_array());
        let sig = secp.sign_ecdsa(&msg_hash, secret);
        let mut bytes = [0u8; 64];
        bytes.copy_from_slice(&sig.serialize_compact());
        Some(bytes)
    }
}

// NOTE: CoreHandlerExt trait removed - dispatch calls core handlers directly via providers

#[cfg(test)]
mod tests {
    use super::*;

    // Tests would go here
    // For now, we rely on the integration tests in deposits-ldk
}
