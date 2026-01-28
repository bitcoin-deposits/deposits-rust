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
use deposits_core::messages::{CoordinationMsg, CoordinationResponseMsg, RecoveryMsg, RecoveryResponseMsg};
use deposits_core::message_handlers::{self as core_handlers, HandlerResult, ResponseData};
use deposits_core::{log_debug, log_error, log_info, log_warn};
use lightning::util::logger::Logger as LdkLogger;
use crate::wire::messages::{
    QuorumJoinRequestMsg, QuorumJoinResponseMsg, QuorumStateSyncMsg,
    QuorumVoteRequestMsg, QuorumVoteMsg, QuorumMembershipChangeMsg,
    CollateralAddPartnerMsg, CollateralRemovePartnerMsg,
    CollateralConsentRequestMsg, CollateralConsentResponseMsg,
    RecoveryVoteMsg, RecoveryClaimRequestMsg, RecoveryClaimSignatureMsg, RecoveryClaimCompleteMsg,
    UncreditedPaymentMsg, ChannelCloseTombstoneMsg,
};

use std::ops::Deref;

impl<L: Deref + Clone + Send + Sync> DepositsHandler<L>
where
    L::Target: LdkLogger,
{
    // ========================================================================
    // Quorum Message Handlers
    // ========================================================================

    /// Handle QuorumJoinRequest message
    pub(super) fn handle_quorum_join_request(
        &self,
        msg: &QuorumJoinRequestMsg,
        sender_node_id: PublicKey,
    ) -> Result<(), LightningError> {
        log_info!(
            self.logger,
            "📋 QUORUM: Received join request from {} for ledger ({}, {})",
            msg.requester_pubkey, msg.operator_id, msg.partner_id
        );

        // Delegate to core handler
        match core_handlers::handle_quorum_join_request(self, msg, sender_node_id) {
            Ok(deposits_core::HandlerResult::Response(
                deposits_core::ResponseData::QuorumJoinResponse { accepted, members, .. }
            )) => {
                if accepted {
                    log_info!(self.logger, "📋 QUORUM: Accepted {} (now {} members)",
                        msg.requester_pubkey, members.len());
                    // Send state sync to new member
                    self.send_state_sync_to_member(msg.requester_pubkey, msg.operator_id, msg.partner_id);
                }
            }
            Ok(deposits_core::HandlerResult::Rejected(reason)) => {
                log_info!(self.logger, "📋 QUORUM: Rejected: {}", reason);
            }
            Err(e) => {
                log_error!(self.logger, "📋 QUORUM: Handler failed: {:?}", e);
            }
            _ => {}
        }

        Ok(())
    }

    /// Handle QuorumJoinResponse message
    pub(super) fn handle_quorum_join_response(
        &self,
        msg: &QuorumJoinResponseMsg,
        _sender: PublicKey,
    ) -> Result<(), LightningError> {
        log_info!(
            self.logger,
            "📋 QUORUM: Received join response (accepted={}, members={})",
            msg.accepted,
            msg.members.len()
        );

        if msg.accepted {
            log_info!(
                self.logger,
                "📋 QUORUM: Successfully joined quorum, awaiting state sync"
            );
            // State sync will follow via QuorumStateSync message
        } else {
            log_info!(
                self.logger,
                "📋 QUORUM: Join request rejected: {:?}",
                msg.rejection_reason
            );
        }
        Ok(())
    }

    /// Handle QuorumStateSync message
    pub(super) fn handle_quorum_state_sync(
        &self,
        msg: &QuorumStateSyncMsg,
        _sender: PublicKey,
    ) -> Result<(), LightningError> {
        use deposits_core::quorum::LedgerId;
        use deposits_core::log_warn;

        log_info!(
            self.logger,
            "📋 QUORUM: Received state sync for ledger ({}, {}) - {} updates from seq {}",
            msg.operator_id,
            msg.partner_id,
            msg.updates.len(),
            msg.start_sequence
        );

        // Process each update in the batch
        // msg.updates is Vec<Vec<u8>> (raw bytes) - need to decode each
        let mut applied_count = 0;
        let mut error_count = 0;

        for update_bytes in &msg.updates {
            // Decode the raw bytes into a SignedLedgerUpdate (unified storage format)
            use deposits_core::messages::BinaryCodec;
            let mut cursor = std::io::Cursor::new(update_bytes);
            match deposits_core::types::SignedLedgerUpdate::read_from(&mut cursor) {
                Ok(signed_update) => {
                    let seq = signed_update.sequence_number;
                    // Verify and store the update (already in correct format)
                    match self.verify_and_store_signed_update(signed_update) {
                        Ok(()) => applied_count += 1,
                        Err(e) => {
                            log_warn!(
                                self.logger,
                                "📋 QUORUM: Failed to apply update seq={}: {:?}",
                                seq,
                                e
                            );
                            error_count += 1;
                        }
                    }
                }
                Err(e) => {
                    log_warn!(
                        self.logger,
                        "📋 QUORUM: Failed to decode update: {:?}",
                        e
                    );
                    error_count += 1;
                }
            }
        }

        log_info!(
            self.logger,
            "📋 QUORUM: Applied {}/{} updates ({} errors)",
            applied_count,
            msg.updates.len(),
            error_count
        );

        // Update quorum manager with our synced state after final batch
        if msg.is_final {
            log_info!(
                self.logger,
                "📋 QUORUM: State sync complete - received final batch"
            );

            // Get our current state from the signed update log
            let logs = self.signed_update_logs.lock().unwrap();
            if let Some(log) = logs.get(&(msg.operator_id, msg.partner_id)) {
                let ledger_id = LedgerId::new(msg.operator_id, msg.partner_id);
                let sequence = log.next_sequence.saturating_sub(1);
                let state_hash = if let Some(last_update) = log.updates.last() {
                    last_update.current_hash
                } else {
                    [0u8; 32]
                };

                // Update our member state in the quorum
                if let Err(e) = self.quorum_manager.update_member_state(
                    &ledger_id,
                    &self.our_node_id,
                    sequence,
                    state_hash,
                ) {
                    log_warn!(
                        self.logger,
                        "📋 QUORUM: Failed to update quorum member state: {:?}",
                        e
                    );
                } else {
                    log_info!(
                        self.logger,
                        "📋 QUORUM: Updated member state to seq={}, hash={:02x?}",
                        sequence,
                        &state_hash[0..4]
                    );
                }
            }
        }

        Ok(())
    }

    /// Handle QuorumVoteRequest message
    /// Handle QuorumVoteRequest message.
    pub(super) fn handle_quorum_vote_request(
        &self,
        msg: &QuorumVoteRequestMsg,
        sender_node_id: PublicKey,
    ) -> Result<(), LightningError> {
        log_info!(self.logger, "📋 QUORUM: Vote request for ({}, {}) seq={}", msg.operator_id, msg.partner_id, msg.sequence_number);

        // Get our local state
        let (our_seq, our_hash) = match self.get_local_ledger_state(&msg.operator_id, &msg.partner_id) {
            Some(state) => state,
            None => {
                log_info!(self.logger, "📋 QUORUM: No local state, abstaining");
                return Ok(());
            }
        };

        // Initialize vote round
        self.init_vote_round(msg);

        // Validate and create vote
        let is_conforming = true; // TODO: implement full conformance validation
        let vote = is_conforming && our_hash == msg.state_hash;
        let evidence = if !vote { Some(b"state_mismatch".to_vec()) } else { None };

        // Sign the vote
        let signature = match self.sign_vote(&msg.vote_round_id, vote, our_seq, &our_hash) {
            Some(sig) => sig,
            None => {
                log_warn!(self.logger, "📋 QUORUM: Cannot sign vote - no secret key");
                return Ok(());
            }
        };

        // Send vote
        let vote_msg = DepositsMessage::Coordination(CoordinationMsg::QuorumVote {
            vote_round_id: msg.vote_round_id, voter_pubkey: self.our_node_id, vote,
            voter_sequence: our_seq, voter_state_hash: our_hash, evidence, signature,
            spend_signature: None, // TODO: implement spend signing
        });

        log_info!(self.logger, "📋 QUORUM: Sending vote (conforming={})", vote);
        if let Err(e) = self.send_message(sender_node_id, vote_msg) {
            log_warn!(self.logger, "📋 QUORUM: Failed to send vote: {:?}", e);
        }

        Ok(())
    }

    fn get_local_ledger_state(&self, operator: &PublicKey, partner: &PublicKey) -> Option<(u64, [u8; 32])> {
        let logs = self.signed_update_logs.lock().unwrap();
        logs.get(&(*operator, *partner)).map(|log| {
            let seq = if log.updates.is_empty() { 0 } else { log.updates.len() as u64 - 1 };
            let hash = log.updates.last().map(|u| u.current_hash).unwrap_or([0u8; 32]);
            (seq, hash)
        })
    }

    fn init_vote_round(&self, msg: &QuorumVoteRequestMsg) {
        use super::core::VoteRoundState;
        use std::collections::HashMap;
        use std::time::{SystemTime, UNIX_EPOCH};

        let mut rounds = self.pending_vote_rounds.lock().unwrap();
        rounds.entry(msg.vote_round_id).or_insert_with(|| {
            VoteRoundState {
                operator_id: msg.operator_id, partner_id: msg.partner_id,
                sequence_number: msg.sequence_number, state_hash: msg.state_hash,
                claimed_reserves: msg.claimed_reserves, reserves_outpoint: msg.reserves_outpoint.clone(),
                destination_script: msg.destination_script.clone(), fee_rate_sat_vbyte: msg.fee_rate_sat_vbyte,
                threshold: 2, votes: HashMap::new(), tx_broadcast: false,
                created_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
            }
        });
    }

    fn sign_vote(&self, round_id: &[u8; 32], vote: bool, seq: u64, hash: &[u8; 32]) -> Option<[u8; 64]> {
        use bitcoin::hashes::{Hash, sha256};
        use bitcoin::secp256k1::{Secp256k1, Message};

        let secret = self.node_secret_key.as_ref()?;

        let mut data = Vec::new();
        data.extend_from_slice(round_id);
        data.push(if vote { 1 } else { 0 });
        data.extend_from_slice(&seq.to_le_bytes());
        data.extend_from_slice(hash);

        let secp = Secp256k1::new();
        let msg_hash = Message::from_digest(sha256::Hash::hash(&data).to_byte_array());
        let sig = secp.sign_ecdsa(&msg_hash, secret);
        let mut bytes = [0u8; 64];
        bytes.copy_from_slice(&sig.serialize_compact());
        Some(bytes)
    }

    /// Handle QuorumVote message
    pub(super) fn handle_quorum_vote(
        &self,
        msg: &QuorumVoteMsg,
        _sender: PublicKey,
    ) -> Result<(), LightningError> {
        log_info!(self.logger, "📋 QUORUM: Received vote from {} (conforming={}, has_spend_sig={})",
            msg.voter_pubkey, msg.vote, msg.spend_signature.is_some());

        // Add vote to round and check if threshold reached
        if let Some(round) = self.add_vote_to_round(msg) {
            log_info!(self.logger, "📋 QUORUM: Threshold reached for round {:?}!", hex::encode(&msg.vote_round_id[..8]));
            self.emit_spend_ready(&msg.vote_round_id, &round);
        }

        Ok(())
    }

    /// Add vote to round and return round if threshold reached
    fn add_vote_to_round(&self, msg: &QuorumVoteMsg) -> Option<super::core::VoteRoundState> {
        let mut rounds = self.pending_vote_rounds.lock().unwrap();
        let round = rounds.get_mut(&msg.vote_round_id)?;

        round.votes.insert(msg.voter_pubkey, (msg.vote, msg.spend_signature));
        log_info!(self.logger, "📋 QUORUM: Vote round now has {}/{} conforming votes",
            round.conforming_vote_count(), round.threshold);

        if round.threshold_reached() && !round.tx_broadcast {
            round.tx_broadcast = true;
            Some(round.clone())
        } else {
            None
        }
    }

    /// Prepare spend data from vote round
    fn prepare_spend_data(&self, round: &super::core::VoteRoundState) -> Vec<u8> {
        let signatures = round.collect_spend_signatures();
        log_info!(self.logger, "📋 QUORUM: Collected {} spend signatures", signatures.len());

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
        data
    }

    /// Emit spend ready event when threshold reached
    fn emit_spend_ready(&self, round_id: &[u8; 32], round: &super::core::VoteRoundState) {
        let spend_data = self.prepare_spend_data(round);
        log_info!(self.logger, "📋 QUORUM: Prepared {} bytes of spend data", spend_data.len());

        let _ = self.event_queue.emit_deposits_event(
            super::events::DepositsEvent::ReservesSpendReady {
                vote_round_id: *round_id, operator_id: round.operator_id, partner_id: round.partner_id,
                signed_tx_bytes: spend_data, conforming_votes: round.conforming_vote_count() as u32,
                threshold: round.threshold as u32,
            },
        );
        log_info!(self.logger, "📋 QUORUM: Emitted ReservesSpendReady event for round {:?}", hex::encode(&round_id[..8]));
    }

    /// Handle QuorumMembershipChange message
    pub(super) fn handle_quorum_membership_change(
        &self,
        msg: &QuorumMembershipChangeMsg,
        _sender: PublicKey,
    ) -> Result<(), LightningError> {
        log_info!(
            self.logger,
            "📋 QUORUM: Membership change for ({}, {}): {} {} (now {} members)",
            msg.operator_id,
            msg.partner_id,
            msg.change_type,
            msg.member_pubkey,
            msg.new_members.len()
        );
        Ok(())
    }

    // ========================================================================
    // Recovery Message Handlers
    // ========================================================================

    /// Handle RecoveryVote message
    pub(super) fn handle_recovery_vote(
        &self,
        msg: &RecoveryVoteMsg,
        sender: PublicKey,
    ) -> Result<(), LightningError> {
        log_info!(
            self.logger,
            "🔄 RECOVERY: Received vote from {} for operator {} (conforming={})",
            msg.voter, msg.operator, msg.is_conforming
        );

        // Delegate to core handler
        match core_handlers::handle_recovery_vote(self, msg, sender) {
            Ok(_) => {
                log_info!(self.logger, "🔄 RECOVERY: Vote processed successfully");
            }
            Err(e) => {
                log_warn!(self.logger, "🔄 RECOVERY: Vote handler failed: {:?}", e);
            }
        }

        Ok(())
    }

    /// Handle RecoveryClaimRequest message
    ///
    /// Core handler validates the request and emits events.
    /// LDK layer handles signing and queueing the response.
    pub(super) fn handle_recovery_claim_request(
        &self,
        msg: &RecoveryClaimRequestMsg,
        sender: PublicKey,
    ) -> Result<(), LightningError> {
        use bitcoin::secp256k1::{Secp256k1, Message, Keypair};

        log_info!(
            self.logger,
            "🔄 RECOVERY: Received claim request from {} for operator {} tier {}",
            msg.claimant, msg.operator, msg.tier_index
        );

        // Delegate to core handler for validation
        match core_handlers::handle_recovery_claim_request(self, msg, sender) {
            Ok(HandlerResult::Response(ResponseData::RecoveryClaimRequestValidated {
                claimant, sighash, ..
            })) => {
                // Core validated - now sign the claim transaction
                let secp = Secp256k1::new();
                let secret_key = match self.node_secret_key {
                    Some(sk) => sk,
                    None => {
                        log_warn!(self.logger, "🔄 RECOVERY: No signing key available");
                        return Ok(());
                    }
                };
                let keypair = Keypair::from_secret_key(&secp, &secret_key);

                // Sign the sighash
                let sighash_msg = Message::from_digest(sighash);
                let signature = secp.sign_schnorr_no_aux_rand(&sighash_msg, &keypair);

                log_info!(self.logger, "🔄 RECOVERY: Sending claim signature to {}", claimant);

                // Queue the response
                self.outbound_messages
                    .lock()
                    .unwrap()
                    .entry(claimant)
                    .or_default()
                    .push(DepositsMessage::RecoveryResponse(RecoveryResponseMsg::ClaimSignature {
                        request_hash: sighash,
                        signer: self.our_node_id,
                        sighash,
                        signature: signature.serialize(),
                    }));
            }
            Ok(HandlerResult::Rejected(reason)) => {
                log_warn!(self.logger, "🔄 RECOVERY: Claim request rejected: {}", reason);
            }
            Err(e) => {
                log_warn!(self.logger, "🔄 RECOVERY: Claim request handler failed: {:?}", e);
            }
            _ => {}
        }

        Ok(())
    }

    /// Handle RecoveryClaimSignature message
    ///
    /// Core handler validates and emits events.
    /// LDK layer handles claim_manager operations and threshold checking.
    pub(super) fn handle_recovery_claim_signature(
        &self,
        msg: &RecoveryClaimSignatureMsg,
        sender: PublicKey,
    ) -> Result<(), LightningError> {
        log_info!(
            self.logger,
            "🔄 RECOVERY: Received claim signature from {} for sighash {}",
            msg.signer, hex::encode(&msg.sighash[..8])
        );

        // Delegate to core handler for validation
        match core_handlers::handle_recovery_claim_signature(self, msg, sender) {
            Ok(HandlerResult::Response(ResponseData::RecoveryClaimSignatureReceived { .. })) => {
                // Core validated - now add to claim manager
                let ledger_id = (msg.operator, msg.partner);
                let add_result = {
                    let mut claim_manager = self.claim_manager.lock().unwrap();
                    claim_manager.add_peer_signature(&ledger_id, &msg.signer, msg.signature)
                };

                match add_result {
                    Ok(has_sufficient) => {
                        log_info!(self.logger, "🔄 RECOVERY: Signature stored (threshold_met={})", has_sufficient);
                        if has_sufficient {
                            let _ = self.event_queue.emit_deposits_event(
                                super::events::DepositsEvent::RecoveryClaimReady {
                                    operator_id: msg.operator,
                                    partner_id: msg.partner,
                                },
                            );
                        }
                    }
                    Err(e) => {
                        log_warn!(self.logger, "🔄 RECOVERY: Failed to add signature: {:?}", e);
                    }
                }
            }
            Ok(HandlerResult::Rejected(reason)) => {
                log_warn!(self.logger, "🔄 RECOVERY: Signature rejected: {}", reason);
            }
            Err(e) => {
                log_warn!(self.logger, "🔄 RECOVERY: Signature handler failed: {:?}", e);
            }
            _ => {}
        }

        Ok(())
    }

    /// Handle RecoveryClaimComplete message
    /// Handle RecoveryClaimComplete message
    ///
    /// Core handler emits protocol events.
    /// LDK layer handles claim_manager cleanup and LDK-specific events.
    pub(super) fn handle_recovery_claim_complete(
        &self,
        msg: &RecoveryClaimCompleteMsg,
        sender: PublicKey,
    ) -> Result<(), LightningError> {
        log_info!(
            self.logger,
            "🔄 RECOVERY: Claim complete for operator {} - new operator {}",
            msg.operator, msg.new_operator
        );

        // Delegate to core handler
        match core_handlers::handle_recovery_claim_complete(self, msg, sender) {
            Ok(HandlerResult::Response(ResponseData::RecoveryClaimCompleted { .. })) => {
                // Core validated and emitted events - now clean up claim_manager
                let ledger_id = (msg.operator, msg.partner);
                {
                    let mut claim_manager = self.claim_manager.lock().unwrap();
                    claim_manager.remove_claim(&ledger_id);
                }

                // Emit LDK-specific event
                let _ = self.event_queue.emit_deposits_event(
                    super::events::DepositsEvent::RecoveryClaimCompleted {
                        old_operator: msg.operator,
                        partner_id: msg.partner,
                        new_operator: msg.new_operator,
                        claim_txid: msg.claim_txid,
                        confirmation_block: msg.confirmation_block,
                    },
                );
            }
            Err(e) => {
                log_warn!(self.logger, "🔄 RECOVERY: Claim complete handler failed: {:?}", e);
            }
            _ => {}
        }

        Ok(())
    }

    // ========================================================================
    // Collateral/Voter Message Handlers
    // ========================================================================

    /// Handle CollateralAddPartner message
    ///
    /// Core handler does validation and ledger mutation.
    /// LDK layer handles signing, persistence, quorum sync, and ACK sending.
    /// Handle CollateralAddPartner message
    ///
    /// Core handler does the complete flow: validate, mutate, sign, persist, sync, ACK.
    /// LDK layer is just a thin wrapper that logs results.
    pub(super) fn handle_collateral_add_partner(
        &self,
        msg: &CollateralAddPartnerMsg,
        sender_node_id: PublicKey,
    ) -> Result<(), LightningError> {
        log_info!(
            self.logger,
            "📋 VOTER: Received AddCollateralPartner from {} - adding {}",
            sender_node_id, msg.collateral_partner
        );

        // Core handler does the complete flow: validate, mutate, sign, persist, sync quorum, send ACK
        match core_handlers::handle_collateral_add_partner(self, msg, sender_node_id) {
            Err(e) => {
                log_warn!(self.logger, "📋 VOTER: Handler failed: {:?}", e);
            }
            Ok(HandlerResult::Rejected(reason)) => {
                log_warn!(self.logger, "📋 VOTER: Rejected: {}", reason);
            }
            Ok(HandlerResult::Ok) => {
                log_info!(self.logger, "📋 VOTER: Added collateral partner {}", msg.collateral_partner);
            }
            Ok(_) => {}
        }

        Ok(())
    }

    /// Handle CollateralRemovePartner message
    ///
    /// Core handler does the complete flow: validate, mutate, sign, persist, sync, ACK.
    /// LDK layer is just a thin wrapper that logs results.
    pub(super) fn handle_collateral_remove_partner(
        &self,
        msg: &CollateralRemovePartnerMsg,
        sender_node_id: PublicKey,
    ) -> Result<(), LightningError> {
        log_info!(
            self.logger,
            "📋 VOTER: Received RemoveCollateralPartner from {} - removing {}",
            sender_node_id, msg.collateral_partner
        );

        // Core handler does the complete flow: validate, mutate, sign, persist, sync quorum, send ACK
        match core_handlers::handle_collateral_remove_partner(self, msg, sender_node_id) {
            Err(e) => {
                log_warn!(self.logger, "📋 VOTER: Handler failed: {:?}", e);
            }
            Ok(HandlerResult::Rejected(reason)) => {
                log_warn!(self.logger, "📋 VOTER: Rejected: {}", reason);
            }
            Ok(HandlerResult::Ok) => {
                log_info!(self.logger, "📋 VOTER: Removed collateral partner {}", msg.collateral_partner);
            }
            Ok(_) => {}
        }

        Ok(())
    }

    // NOTE: send_collateral_nack, send_collateral_ack, finalize_collateral_add, finalize_collateral_remove
    // have been removed - all that logic is now in core handlers via HandlerContext provider methods.

    /// Handle CollateralConsentRequest message
    /// Handle CollateralConsentRequest message.
    ///
    /// Core handler validates the request, LDK layer handles signing and sending.
    pub(super) fn handle_collateral_consent_request(
        &self,
        msg: &CollateralConsentRequestMsg,
        sender_node_id: PublicKey,
    ) -> Result<(), LightningError> {
        log_info!(
            self.logger,
            "📋 CONSENT: Received request from {} for ledger ({}, {})",
            sender_node_id, msg.operator_id, msg.partner_id
        );

        // Delegate to core handler for validation and decision
        match core_handlers::handle_collateral_consent_request(self, msg, sender_node_id) {
            Ok(HandlerResult::Response(ResponseData::CollateralConsent {
                operator_id, partner_id, consent_granted
            })) => {
                // Sign consent if granting
                let signature = if consent_granted {
                    self.sign_collateral_consent(&operator_id, &partner_id)
                } else {
                    [0u8; 64]
                };

                // Send response
                let response = DepositsMessage::CoordinationResponse(
                    CoordinationResponseMsg::CollateralConsentResponse {
                        request_hash: [0u8; 32],
                        operator_id,
                        partner_id,
                        consent_granted,
                        collateral_partner_signature: signature,
                    }
                );

                if let Err(e) = self.send_message(sender_node_id, response) {
                    log_warn!(self.logger, "📋 CONSENT: Failed to send response: {:?}", e);
                }

                // If consent granted, request sync of the ledger state
                if consent_granted {
                    log_info!(self.logger, "📋 CONSENT: Granted, requesting state sync");
                    let sync_request = DepositsMessage::Sync(SyncMsg {
                        operator_id,
                        partner_id,
                        last_known_sequence: 0,
                        last_known_hash: [0u8; 32],
                    });
                    if let Err(e) = self.send_message(operator_id, sync_request) {
                        log_warn!(self.logger, "📋 CONSENT: Failed to send SyncRequest: {:?}", e);
                    }
                } else {
                    log_info!(self.logger, "📋 CONSENT: Denied");
                }
            }
            Ok(HandlerResult::Rejected(reason)) => {
                log_warn!(self.logger, "📋 CONSENT: Rejected: {}", reason);
            }
            Err(e) => {
                log_error!(self.logger, "📋 CONSENT: Handler failed: {:?}", e);
            }
            _ => {}
        }

        Ok(())
    }

    /// Handle CollateralConsentResponse message
    /// Handle CollateralConsentResponse message.
    ///
    /// Received when a collateral partner responds to our consent request.
    pub(super) fn handle_collateral_consent_response(
        &self,
        msg: &CollateralConsentResponseMsg,
        sender_node_id: PublicKey,
    ) -> Result<(), LightningError> {
        log_info!(self.logger, "📋 CONSENT: Received response from {} - granted={}", sender_node_id, msg.consent_granted);

        // Verify signature if consent granted
        if msg.consent_granted && !self.verify_consent_signature(msg, sender_node_id) {
            return Ok(());
        }

        // Complete pending consent request
        self.complete_pending_consent(msg);

        // Send audit history to new collateral partner
        if msg.consent_granted {
            self.send_audit_to_collateral_partner(msg, sender_node_id);
        }

        Ok(())
    }

    /// Verify the collateral consent signature
    fn verify_consent_signature(&self, msg: &CollateralConsentResponseMsg, sender: PublicKey) -> bool {
        use bitcoin::hashes::{Hash, sha256};
        use bitcoin::secp256k1::{Secp256k1, Message, ecdsa::Signature};

        let mut preimage = Vec::new();
        preimage.extend_from_slice(b"COLLATERAL_CONSENT");
        preimage.extend_from_slice(&msg.operator_id.serialize());
        preimage.extend_from_slice(&msg.partner_id.serialize());

        let hash = sha256::Hash::hash(&preimage);
        let secp_msg = Message::from_digest(hash.to_byte_array());
        let secp = Secp256k1::new();

        match Signature::from_compact(&msg.collateral_partner_signature) {
            Ok(sig) => {
                if secp.verify_ecdsa(&secp_msg, &sig, &sender).is_ok() {
                    log_info!(self.logger, "📋 CONSENT: Verified signature from {}", sender);
                    true
                } else {
                    log_warn!(self.logger, "📋 CONSENT: Invalid signature from {}", sender);
                    false
                }
            }
            Err(e) => {
                log_warn!(self.logger, "📋 CONSENT: Malformed signature from {}: {}", sender, e);
                false
            }
        }
    }

    /// Complete a pending consent request
    fn complete_pending_consent(&self, msg: &CollateralConsentResponseMsg) {
        let original = DepositsMessage::Coordination(CoordinationMsg::CollateralConsentRequest {
            operator_id: msg.operator_id, partner_id: msg.partner_id, operator_signature: [0u8; 64],
        });
        let hash = self.calculate_message_hash(&original);

        let mut pending = self.pending_consent_requests.lock().unwrap();
        if let Some(tx) = pending.remove(&hash) {
            if msg.consent_granted {
                let _ = tx.send(Ok(msg.collateral_partner_signature));
            } else {
                let _ = tx.send(Err("Collateral partner denied consent".to_string()));
            }
        } else {
            log_warn!(self.logger, "📋 CONSENT: No pending request for hash {:02x?}", &hash[..8]);
        }
    }

    /// Send audit history to new collateral partner
    fn send_audit_to_collateral_partner(&self, msg: &CollateralConsentResponseMsg, sender: PublicKey) {
        log_info!(self.logger, "📋 SYNC: Sending audit history to new collateral partner {}", sender);

        let response = DepositsMessage::CoordinationResponse(CoordinationResponseMsg::CollateralConsentResponse {
            request_hash: [0u8; 32], operator_id: msg.operator_id, partner_id: msg.partner_id,
            consent_granted: msg.consent_granted, collateral_partner_signature: msg.collateral_partner_signature,
        });

        if let Err(e) = self.send_audit_update_to_new_collateral_partner(msg.partner_id, sender, &response) {
            log_warn!(self.logger, "📋 SYNC: Failed to send audit history: {:?}", e);
        }
    }

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

    // ==================== Accusation Message Handlers ====================

    /// Handle UncreditedPayment accusation message (0x8035)
    /// Partner broadcasting proof of unpaid settlement
    /// Handle UncreditedPayment accusation message.
    ///
    /// Core handler validates preimage and partner, LDK layer handles force-close and rebroadcast.
    pub(super) fn handle_uncredited_payment(
        &self,
        msg: &UncreditedPaymentMsg,
        sender_node_id: PublicKey,
    ) -> Result<(), LightningError> {
        log_info!(
            self.logger,
            "⚠️ ACCUSATION: Received UncreditedPayment from {} - operator={}, payment_hash={}, amount={}",
            sender_node_id, msg.operator, hex::encode(&msg.payment_hash[..8]), msg.amount_msat
        );

        // Delegate to core handler for validation
        match core_handlers::handle_uncredited_payment(self, msg, sender_node_id) {
            Ok(HandlerResult::Rejected(reason)) => {
                log_warn!(self.logger, "⚠️ ACCUSATION: Rejected: {}", reason);
                return Ok(());
            }
            Err(e) => {
                log_error!(self.logger, "⚠️ ACCUSATION: Handler error: {:?}", e);
                return Ok(());
            }
            Ok(HandlerResult::Response(ResponseData::UncreditedPaymentAccusation {
                operator, partner, payment_hash, deposit_pubkey, amount_msat, settlement_sequence
            })) => {
                // Emit event for node layer
                let _ = self.event_queue.emit_deposits_event(
                    super::events::DepositsEvent::UncreditedPaymentAccusation {
                        operator, partner, payment_hash, deposit_pubkey, amount_msat, settlement_sequence,
                    },
                );

                // If we have our own channel with this operator, force-close and rebroadcast
                self.handle_accusation_followup(msg, sender_node_id, operator);
            }
            _ => {}
        }

        Ok(())
    }

    /// Handle force-close and rebroadcast after valid accusation
    fn handle_accusation_followup(
        &self,
        msg: &UncreditedPaymentMsg,
        sender_node_id: PublicKey,
        operator: PublicKey,
    ) {
        if operator == self.our_node_id {
            return;
        }

        let our_ledger_key = (operator, self.our_node_id);
        let have_channel = {
            let ledgers = self.ledgers.lock().unwrap();
            ledgers.contains_key(&our_ledger_key)
        };

        if !have_channel {
            return;
        }

        log_warn!(self.logger, "⚠️ ACCUSATION: We have channel with accused operator {} - force-closing", operator);

        // Force-close our channel
        if let Some(ref cm) = self.channel_manager {
            let channels = cm.list_channels();
            if let Some(channel) = channels.iter().find(|c| c.counterparty_node_id == operator) {
                let reason = format!("Fraud proof: operator {} accused of uncredited payment", operator);
                if let Err(e) = cm.force_close_broadcasting_latest_txn(&channel.channel_id, &operator, reason) {
                    log_error!(self.logger, "⚠️ ACCUSATION: Force-close failed: {:?}", e);
                } else {
                    log_warn!(self.logger, "⚠️ ACCUSATION: Force-closed channel with {}", operator);
                }
            }
        }

        // Rebroadcast to our collateral partners
        let partners = {
            let ledgers = self.ledgers.lock().unwrap();
            ledgers.get(&our_ledger_key)
                .map(|l| l.read().unwrap().state.collateral_partners.clone())
                .unwrap_or_default()
        };

        let accusation_msg = DepositsMessage::Recovery(RecoveryMsg::UncreditedPayment {
            operator: msg.operator, partner: msg.partner, payment_hash: msg.payment_hash,
            preimage: msg.preimage, deposit_pubkey: msg.deposit_pubkey, amount_msat: msg.amount_msat,
            invoice_cosignature: msg.invoice_cosignature, settlement_sequence: msg.settlement_sequence,
            settlement_ledger_hash: msg.settlement_ledger_hash, settlement_block_height: msg.settlement_block_height,
            accuser_signature: msg.accuser_signature,
        });

        for partner in partners {
            if partner != sender_node_id {
                log_info!(self.logger, "⚠️ ACCUSATION: Forwarding to collateral partner {}", partner);
                let _ = self.send_message(partner, accusation_msg.clone());
            }
        }
    }

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
            let partner_node_id = ledger_guard.partner_key();
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
            partner_id: tombstone_msg.partner_id,
            sequence_number: tombstone_msg.sequence_number,
            previous_hash: [0u8; 32],
            current_hash: [0u8; 32],
            timestamp: tombstone_msg.timestamp,
        };

        let count = ledger_guard.insert_signed_unchecked(signed_update);
        log_info!(self.logger, "✅ Tombstone inserted (seq={}, added {}). Ledger closed.", tombstone_msg.sequence_number, count);
    }

    // ==================== SignedUpdate Message Handlers ====================

    /// Handle SignedAuditUpdate when we're the PARTNER
    /// The partner receives authoritative updates from operator and stores them in ledgers
    /// Returns true if this message was handled, false if it should continue to regular processing
    pub(super) fn handle_signed_update_as_partner(
        &self,
        signed_msg: &SignedUpdateMsg,
        sender_node_id: PublicKey,
    ) -> Result<bool, LightningError> {
        use deposits_core::{Ledger, LedgerRole};
        use std::sync::{Arc, RwLock};

        // Only handle if we're the partner (operator_id is sender, partner_id is us)
        if signed_msg.partner_id != self.our_node_id || signed_msg.operator_id != sender_node_id {
            return Ok(false); // Not for us as partner, continue regular processing
        }

        log_info!(
            self.logger,
            "📋 PARTNER: Receiving SignedAuditUpdate seq={} from operator {} (storing in ledgers)",
            signed_msg.sequence_number,
            sender_node_id
        );

        // SignedUpdateMsg is already SignedLedgerUpdate, just clone it
        let signed_update = signed_msg.clone();

        // Store in partner ledger using unified Ledger type
        let mut ledgers = self.ledgers.lock().unwrap();
        let key = (signed_msg.operator_id, self.our_node_id);

        // Get or create the partner ledger
        let ledger = ledgers.entry(key).or_insert_with(|| {
            // Create new Ledger for this partner relationship
            log_info!(
                self.logger,
                "📋 PARTNER: Creating new partner ledger for operator {}",
                signed_msg.operator_id
            );
            let new_ledger = Ledger::new(
                signed_msg.operator_id,
                self.our_node_id,
                LedgerRole::Partner,
                vec![], // collateral partners - will be populated from updates
                String::new(), // ledger address - will be set from first update
            );
            Arc::new(RwLock::new(new_ledger))
        });

        // Insert the signed update to the ledger (unchecked - we trust operator signature)
        // Partners receive SignedAuditUpdate broadcasts that may start mid-sequence,
        // so we can't use append_signed() which requires strict hash chain continuity
        let mut ledger_guard = ledger.write().unwrap();
        ledger_guard.insert_signed_unchecked(signed_update.clone());
        log_info!(
            self.logger,
            "📋 PARTNER: Inserted signed update seq={} to partner ledger (unchecked)",
            signed_msg.sequence_number
        );

        drop(ledger_guard);
        drop(ledgers);

        // Also store in signed_update_logs for backward compatibility
        if let Err(e) = self.verify_and_store_signed_update(signed_update) {
            log_error!(
                self.logger,
                "📋 PARTNER: Failed to store SignedAuditUpdate seq={} in signed_update_logs: {}",
                signed_msg.sequence_number,
                e
            );
        }

        Ok(true) // Message handled, don't continue processing
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
            error: Some(error.to_string()), partner_id: self.our_node_id,
        });
        let _ = self.send_message(peer, response);
    }

    /// Send handshake acceptance response
    fn send_handshake_acceptance(&self, init_msg: &HandshakeMsg, peer: PublicKey) {
        let response = DepositsMessage::HandshakeResponse(HandshakeResponseMsg {
            request_hash: [0u8; 32], protocol_version: init_msg.protocol_version, accepted: true,
            error: None, partner_id: self.our_node_id,
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
        // 2. The message's partner_id field matches our own node ID (we are the intended partner)
        let is_for_us = if let Some(partner_id) = message.partner_id() {
            // If partner_id matches our node ID, this message is intended for us
            partner_id == self.our_node_id
        } else {
            // No partner_id - check if we have existing ledger where sender is operator
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
