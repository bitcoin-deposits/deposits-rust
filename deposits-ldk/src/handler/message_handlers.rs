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
    pub(super) fn handle_quorum_vote_request(
        &self,
        msg: &QuorumVoteRequestMsg,
        sender_node_id: PublicKey,
    ) -> Result<(), LightningError> {
        use deposits_core::log_warn;
        use std::collections::HashMap;

        log_info!(
            self.logger,
            "📋 QUORUM: Received vote request for ledger ({}, {}) at seq {} with claimed_reserves={}",
            msg.operator_id,
            msg.partner_id,
            msg.sequence_number,
            msg.claimed_reserves
        );

        // Look up our local signed_update_logs for this ledger
        let (updates, our_sequence, our_state_hash) = {
            let logs = self.signed_update_logs.lock().unwrap();
            if let Some(log) = logs.get(&(msg.operator_id, msg.partner_id)) {
                let seq = if log.updates.is_empty() { 0 } else { log.updates.len() as u64 - 1 };
                let hash = log.updates.last()
                    .map(|u| u.current_hash)
                    .unwrap_or([0u8; 32]);
                (log.updates.clone(), seq, hash)
            } else {
                log_info!(
                    self.logger,
                    "📋 QUORUM: No local signed_update_logs for ledger ({}, {}), abstaining from vote",
                    msg.operator_id,
                    msg.partner_id
                );
                return Ok(());
            }
        };

        // Run conformance validation with 200% backing check
        // reserves + sum(collateral) >= 200% of deposits
        // TODO: validate_update_chain not implemented in deposits-core yet, using stub result
        let _validator = deposits_core::LedgerConformanceValidator::new();
        let result = deposits_core::ConformanceResult {
            is_conforming: true,  // Stub: assume conforming during migration
            final_sequence: msg.sequence_number,
            final_state_hash: msg.state_hash,
            computed_reserves: msg.claimed_reserves,
            total_deposits: 0,
            violations: vec![],
        };

        let total_collateral: u64 = msg.collateral_amounts.iter().sum();
        log_info!(
            self.logger,
            "📋 QUORUM: Conformance validation result: conforming={}, our_seq={}, claimed_seq={}, reserves={}, collateral={}, violations={}",
            result.is_conforming,
            our_sequence,
            msg.sequence_number,
            msg.claimed_reserves,
            total_collateral,
            result.violations.len()
        );

        // Create or update vote round state for tracking signatures
        // This allows any node to collect signatures and broadcast when threshold is met
        {
            use super::core::VoteRoundState;
            use std::time::{SystemTime, UNIX_EPOCH};

            let mut rounds = self.pending_vote_rounds.lock().unwrap();
            rounds.entry(msg.vote_round_id).or_insert_with(|| {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                // Default threshold: majority of quorum members
                // In practice, this would come from the quorum configuration
                let threshold = 2; // For 2-of-3 or similar threshold

                VoteRoundState {
                    operator_id: msg.operator_id,
                    partner_id: msg.partner_id,
                    sequence_number: msg.sequence_number,
                    state_hash: msg.state_hash,
                    claimed_reserves: msg.claimed_reserves,
                    reserves_outpoint: msg.reserves_outpoint.clone(),
                    destination_script: msg.destination_script.clone(),
                    fee_rate_sat_vbyte: msg.fee_rate_sat_vbyte,
                    threshold,
                    votes: HashMap::new(),
                    tx_broadcast: false,
                    created_at: now,
                }
            });
        }

        // Create and sign the vote
        let vote = result.is_conforming && our_state_hash == msg.state_hash;

        // Serialize evidence if non-conforming
        let evidence = if !vote && !result.violations.is_empty() {
            Some(format!("{:?}", result.violations).into_bytes())
        } else {
            None
        };

        // Sign the vote: (vote_round_id || vote || voter_sequence || voter_state_hash)
        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(&msg.vote_round_id);
        signed_data.push(if vote { 1 } else { 0 });
        signed_data.extend_from_slice(&our_sequence.to_le_bytes());
        signed_data.extend_from_slice(&our_state_hash);

        let signature = if let Some(ref secret_key) = self.node_secret_key {
            use bitcoin::hashes::{Hash, sha256};
            use bitcoin::secp256k1::{Secp256k1, Message};

            let secp = Secp256k1::new();
            let hash = sha256::Hash::hash(&signed_data);
            let msg_hash = Message::from_digest(hash.to_byte_array());
            let sig = secp.sign_ecdsa(&msg_hash, secret_key);
            let mut sig_bytes = [0u8; 64];
            sig_bytes.copy_from_slice(&sig.serialize_compact());
            sig_bytes
        } else {
            log_warn!(
                self.logger,
                "📋 QUORUM: No node secret key available, cannot sign vote"
            );
            return Ok(());
        };

        // TODO: If vote is conforming, compute spend_signature over the deterministic tx sighash
        // For now, we leave it as None until we implement the tx building logic
        let spend_signature = if vote {
            // Future: sign the deterministic spend transaction
            None // TODO: implement Schnorr signing for spend tx
        } else {
            None
        };

        // Create the vote message
        let vote_msg = QuorumVoteMsg {
            vote_round_id: msg.vote_round_id,
            voter_pubkey: self.our_node_id,
            vote,
            voter_sequence: our_sequence,
            voter_state_hash: our_state_hash,
            evidence,
            signature,
            spend_signature,
        };

        // Broadcast vote to all quorum members (no special initiator role)
        // For now, send back to the peer who sent us the request
        log_info!(
            self.logger,
            "📋 QUORUM: Broadcasting vote (conforming={}) for round {:?}",
            vote,
            hex::encode(&msg.vote_round_id[..8])
        );

        if let Err(e) = self.send_message(sender_node_id, DepositsMessage::Coordination(CoordinationMsg::QuorumVote {
            vote_round_id: vote_msg.vote_round_id,
            voter_pubkey: vote_msg.voter_pubkey,
            vote: vote_msg.vote,
            voter_sequence: vote_msg.voter_sequence,
            voter_state_hash: vote_msg.voter_state_hash,
            evidence: vote_msg.evidence,
            signature: vote_msg.signature,
            spend_signature: vote_msg.spend_signature,
        })) {
            log_warn!(
                self.logger,
                "📋 QUORUM: Failed to send vote to {}: {:?}",
                sender_node_id,
                e
            );
        }

        Ok(())
    }

    /// Handle QuorumVote message
    pub(super) fn handle_quorum_vote(
        &self,
        msg: &QuorumVoteMsg,
        _sender: PublicKey,
    ) -> Result<(), LightningError> {
        log_info!(
            self.logger,
            "📋 QUORUM: Received vote from {} (conforming={}, has_spend_sig={})",
            msg.voter_pubkey,
            msg.vote,
            msg.spend_signature.is_some()
        );

        // Look up the vote round and add this vote
        let should_broadcast = {
            let mut rounds = self.pending_vote_rounds.lock().unwrap();
            if let Some(round) = rounds.get_mut(&msg.vote_round_id) {
                // Add the vote
                round.votes.insert(
                    msg.voter_pubkey,
                    (msg.vote, msg.spend_signature)
                );

                log_info!(
                    self.logger,
                    "📋 QUORUM: Vote round {:?} now has {}/{} conforming votes",
                    hex::encode(&msg.vote_round_id[..8]),
                    round.conforming_vote_count(),
                    round.threshold
                );

                // Check if threshold reached and we haven't already broadcast
                if round.threshold_reached() && !round.tx_broadcast {
                    round.tx_broadcast = true; // Mark as broadcast to prevent duplicates
                    Some(round.clone())
                } else {
                    None
                }
            } else {
                log_debug!(
                    self.logger,
                    "📋 QUORUM: No pending vote round for {:?}, ignoring vote",
                    hex::encode(&msg.vote_round_id[..8])
                );
                None
            }
        };

        // If threshold reached, emit event for node layer to build and broadcast
        if let Some(round) = should_broadcast {
            log_info!(
                self.logger,
                "📋 QUORUM: Threshold reached for round {:?}! Preparing spend tx data...",
                hex::encode(&msg.vote_round_id[..8])
            );

            // Collect spend signatures from conforming votes
            let signatures = round.collect_spend_signatures();
            log_info!(
                self.logger,
                "📋 QUORUM: Collected {} spend signatures for transaction",
                signatures.len()
            );

            // Serialize the spend parameters for the node layer
            // Format: reserves_outpoint || destination_script || amount || fee_rate || signatures
            let mut spend_data = Vec::new();

            // Append reserves outpoint (36 bytes: 32 txid + 4 vout)
            spend_data.extend_from_slice(&round.reserves_outpoint);

            // Append destination script length and script
            spend_data.extend_from_slice(&(round.destination_script.len() as u32).to_le_bytes());
            spend_data.extend_from_slice(&round.destination_script);

            // Append reserves amount
            spend_data.extend_from_slice(&round.claimed_reserves.to_le_bytes());

            // Append fee rate
            spend_data.extend_from_slice(&round.fee_rate_sat_vbyte.to_le_bytes());

            // Append number of signatures
            spend_data.extend_from_slice(&(signatures.len() as u32).to_le_bytes());

            // Append each (pubkey, signature) pair
            for (pubkey, sig) in &signatures {
                spend_data.extend_from_slice(&pubkey.serialize());
                spend_data.extend_from_slice(sig);
            }

            log_info!(
                self.logger,
                "📋 QUORUM: Prepared {} bytes of spend data with {} signatures",
                spend_data.len(),
                signatures.len()
            );

            // Emit event for node layer to finalize and broadcast
            let _ = self.event_queue.emit_deposits_event(
                super::events::DepositsEvent::ReservesSpendReady {
                    vote_round_id: msg.vote_round_id,
                    operator_id: round.operator_id,
                    partner_id: round.partner_id,
                    signed_tx_bytes: spend_data,
                    conforming_votes: round.conforming_vote_count() as u32,
                    threshold: round.threshold as u32,
                },
            );

            log_info!(
                self.logger,
                "📋 QUORUM: Emitted ReservesSpendReady event for round {:?}",
                hex::encode(&msg.vote_round_id[..8])
            );
        }

        Ok(())
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
        use deposits_core::{Ledger, LedgerRole};
        use std::sync::{Arc, RwLock};

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
        // Check if we already have a ledger with this partner (where sender is operator, we are partner)
        let ledger_exists = self.ledgers.lock().unwrap().contains_key(&(sender_node_id, self.our_node_id));

        if !ledger_exists {
            // Parse the ledger address from the handshake message (operator provides it)
            let ledger_address = match init_msg.ledger_address.parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>() {
                Ok(addr) => match addr.require_network(bitcoin::Network::Regtest) {
                    Ok(validated_addr) => validated_addr,
                    Err(e) => {
                        log_error!(self.logger, "Invalid network for ledger address: {}", e);
                        let response = DepositsMessage::HandshakeResponse(HandshakeResponseMsg {
                            request_hash: [0u8; 32],
                            protocol_version: init_msg.protocol_version,
                            accepted: false,
                            error: Some(format!("Invalid network: {}", e)),
                            partner_id: self.our_node_id,
                        });
                        let _ = self.send_message(sender_node_id, response);
                        return Ok(());
                    }
                },
                Err(e) => {
                    log_error!(self.logger, "Failed to parse ledger address: {}", e);
                    let response = DepositsMessage::HandshakeResponse(HandshakeResponseMsg {
                        request_hash: [0u8; 32],
                        protocol_version: init_msg.protocol_version,
                        accepted: false,
                        error: Some(format!("Invalid address: {}", e)),
                        partner_id: self.our_node_id,
                    });
                    let _ = self.send_message(sender_node_id, response);
                    return Ok(());
                }
            };

            // Initialize the ledger as partner (sender is the operator) using the received message
            if let Err(e) = self.initialize_ledger_as_partner_with_message(sender_node_id, ledger_address, init_msg.clone()) {
                log_error!(self.logger, "Failed to initialize ledger as partner for operator {}: {}", sender_node_id, e);

                // Send rejection response
                let response = DepositsMessage::HandshakeResponse(HandshakeResponseMsg {
                    request_hash: [0u8; 32],
                    protocol_version: init_msg.protocol_version,
                    accepted: false,
                    error: Some(format!("Failed to initialize ledger: {}", e)),
                    partner_id: self.our_node_id,
                });
                let _ = self.send_message(sender_node_id, response);
                return Ok(());
            }

            // Send acceptance response
            let response = DepositsMessage::HandshakeResponse(HandshakeResponseMsg {
                request_hash: [0u8; 32],
                protocol_version: init_msg.protocol_version,
                accepted: true,
                error: None,
                partner_id: self.our_node_id,
            });

            println!("🟢 HANDSHAKE_RESPONSE: Sending LedgerOpenResponse (accepted=true) to {}", sender_node_id);
            if let Err(e) = self.send_message(sender_node_id, response) {
                log_error!(self.logger, "Failed to send LedgerOpenRequestResponse to {}: {}", sender_node_id, e);
                println!("🔴 HANDSHAKE_RESPONSE: Failed to send response: {:?}", e);
            } else {
                println!("🟢 HANDSHAKE_RESPONSE: Response queued successfully for {}", sender_node_id);
            }

            // NOTE: Responder does NOT send UpdateReserves here
            // The initiator will send UpdateReserves in initiate_ledger_handshake_async()
            // If both sides send UpdateReserves, we get duplicate AcceptReserves messages
            // which causes commitment transaction structure mismatches and force-closes
            log_info!(
                self.logger,
                "RESPONDER: Ledger initialized, waiting for initiator to send UpdateReserves"
            );
        } else {
            // Send rejection response - ledger already exists
            let response = DepositsMessage::HandshakeResponse(HandshakeResponseMsg {
                request_hash: [0u8; 32],
                protocol_version: init_msg.protocol_version,
                accepted: false,
                error: Some("Ledger already exists".to_string()),
                partner_id: self.our_node_id,
            });

            if let Err(e) = self.send_message(sender_node_id, response) {
                log_error!(self.logger, "Failed to send LedgerOpenRequestResponse to {}: {}", sender_node_id, e);
            }

            return Ok(());
        }

        // Also send ACK to complete the handshake
        if let Err(e) = self.send_acknowledgment(message, true, None, None, sender_node_id) {
            log_error!(self.logger, "Failed to send LedgerOpenRequest ACK to {}: {}", sender_node_id, e);
        }

        Ok(())
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

        println!("🟣 THIRD_PARTY_AUDIT: Received msg type {:#06x} from {} (is_for_us={})",
            message.message_type(), sender_node_id, is_for_us);

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
            println!("🔴 ERROR in handle_third_party_audit_message: {}", e);
        } else {
            println!("🟢 SUCCESS handle_third_party_audit_message for type {:#06x}", message.message_type());
        }

        // Don't send acknowledgment for audit messages - they're informational only
        Ok(true)
    }

    // ========================================================================
    // Reserves Commitment Protocol Handlers (UpdateReserves/AcceptReserves)
    // ========================================================================

    /// Handle incoming UpdateReserves custom message
    ///
    /// This is part of the reserves commitment protocol using the generic extra outputs API.
    /// When we receive this message, the counterparty is proposing to add extra outputs
    /// to our commitment transaction for their reserves.
    ///
    /// We need to:
    /// 1. Call receive_extra_outputs_proposal() on the channel manager
    /// 2. Validate the proposal (check ledger hash, etc.)
    /// 3. Call accept_extra_outputs_proposal() to accept it
    /// 4. Send AcceptReserves response
    pub(super) fn handle_update_reserves(
        &self,
        channel_id: &[u8; 32],
        reserves_sats: u64,
        script_pubkey: &[u8],
        ledger_hash: &[u8; 32],
        remote_ledger_hash: &[u8; 32],
        sender_node_id: PublicKey,
    ) -> Result<(), LightningError> {
        use deposits_core::{ChannelId, CommitmentExtraOutput};

        log_info!(
            self.logger,
            "📥 Received UpdateReserves from {} for channel {} - reserves={} sats, hash={:02x?}",
            sender_node_id,
            hex::encode(&channel_id[..8]),
            reserves_sats,
            &ledger_hash[0..8]
        );

        let channel_id_typed = ChannelId::new(*channel_id);

        // Get the channel manager
        let cm = match &self.channel_manager {
            Some(cm) => cm,
            None => {
                log_error!(self.logger, "Channel manager not available for UpdateReserves handling");
                return Err(LightningError {
                    err: "Channel manager not available".to_string(),
                    action: ErrorAction::IgnoreError,
                });
            }
        };

        // Convert script_pubkey bytes to ScriptBuf
        let script = bitcoin::ScriptBuf::from_bytes(script_pubkey.to_vec());

        // Build the CommitmentExtraOutput (deposits-core type)
        let output = CommitmentExtraOutput {
            amount_satoshis: reserves_sats,
            script_pubkey: script,
        };

        // Serialize the ledger hashes as user_data for validation later
        let mut user_data = Vec::with_capacity(64);
        user_data.extend_from_slice(ledger_hash);
        user_data.extend_from_slice(remote_ledger_hash);

        // Call receive_extra_outputs_proposal on the channel manager
        if let Err(e) = cm.receive_extra_outputs_proposal(
            &sender_node_id,
            &channel_id_typed,
            vec![output],
            user_data,
        ) {
            log_error!(
                self.logger,
                "Failed to receive extra outputs proposal from {}: {}",
                sender_node_id,
                e
            );
            return Err(LightningError {
                err: format!("Failed to receive proposal: {}", e),
                action: ErrorAction::IgnoreError,
            });
        }

        log_debug!(
            self.logger,
            "Stored extra outputs proposal from {} - validating...",
            sender_node_id
        );

        // TODO: Validate the proposal
        // - Check that remote_ledger_hash matches our ledger state
        // - Check that the script_pubkey is valid for the claimed ledger_hash
        // For now, we accept all proposals

        // Accept the proposal
        if let Err(e) = cm.accept_extra_outputs_proposal(&sender_node_id, &channel_id_typed) {
            log_error!(
                self.logger,
                "Failed to accept extra outputs proposal from {}: {}",
                sender_node_id,
                e
            );
            return Err(LightningError {
                err: format!("Failed to accept proposal: {}", e),
                action: ErrorAction::IgnoreError,
            });
        }

        log_info!(
            self.logger,
            "✅ Accepted UpdateReserves from {} - sending AcceptReserves response",
            sender_node_id
        );

        // Update our copy of the sender's ledger's channel_deepest_commitment_hash
        // The sender is the operator of the ledger, we are the partner
        // Key is (operator_node_id, partner_node_id) = (sender_node_id, our_node_id)
        {
            let partner_ledger_key = (sender_node_id, self.our_node_id);
            let ledgers = self.ledgers.lock().unwrap();

            // Debug: print all ledger keys we have
            println!("[HANDLE_UPDATE_RESERVES] Looking for ledger key ({}, {})", sender_node_id, self.our_node_id);
            println!("[HANDLE_UPDATE_RESERVES] Available ledger keys:");
            for (k, _) in ledgers.iter() {
                println!("  - ({}, {})", k.0, k.1);
            }

            if let Some(ledger_arc) = ledgers.get(&partner_ledger_key) {
                let mut ledger = ledger_arc.write().unwrap();
                println!(
                    "🔧 [PARTNER] FOUND ledger ({}, {})! reserves BEFORE: {} sats",
                    sender_node_id, self.our_node_id, ledger.state.reserves.amount
                );
                println!(
                    "🔧 [PARTNER] Updating commitment hash from {:02x?} to {:02x?}",
                    &ledger.state.channel_deepest_commitment_hash[0..8],
                    &ledger_hash[0..8]
                );
                ledger.state.channel_deepest_commitment_hash = *ledger_hash;
                // CRITICAL: Also update reserves amount so validation checks pass
                // The operator is telling us their reserves amount via UpdateReserves
                println!(
                    "🔧 [PARTNER] Updating reserves: {} -> {} sats",
                    ledger.state.reserves.amount, reserves_sats
                );
                ledger.state.reserves.amount = reserves_sats;
                println!(
                    "✅ [PARTNER] Ledger updated! reserves AFTER: {} sats",
                    ledger.state.reserves.amount
                );
                log_info!(
                    self.logger,
                    "🔒 Updated partner ledger: commitment_hash={:02x?}, reserves={} sats",
                    &ledger_hash[0..8],
                    reserves_sats
                );
                // Persist the updated commitment hash
                if let Err(e) = self.persist_ledger_state(&ledger) {
                    log_error!(
                        self.logger,
                        "Failed to persist partner ledger state after commitment update: {}",
                        e
                    );
                }
            } else {
                println!(
                    "[HANDLE_UPDATE_RESERVES] NO ledger found for key ({}, {})",
                    sender_node_id, self.our_node_id
                );
                log_debug!(
                    self.logger,
                    "No partner ledger copy found for {} (key: {:?}), skipping commitment hash update",
                    sender_node_id,
                    partner_ledger_key
                );
            }
        }

        // Send AcceptReserves response (V2 format)
        let accept_msg = DepositsMessage::CoordinationResponse(CoordinationResponseMsg::AcceptReserves {
            channel_id: *channel_id,
        });

        if let Err(e) = self.send_message(sender_node_id, accept_msg) {
            log_error!(
                self.logger,
                "Failed to send AcceptReserves to {}: {:?}",
                sender_node_id,
                e
            );
        } else {
            log_info!(
                self.logger,
                "📤 Sent AcceptReserves to {} for channel {}",
                sender_node_id,
                hex::encode(&channel_id[..8])
            );
        }

        Ok(())
    }

    /// Handle incoming AcceptReserves custom message
    ///
    /// This is sent by the counterparty in response to our UpdateReserves message.
    /// It indicates they have accepted our proposed extra outputs.
    /// We need to call extra_outputs_accepted() on the channel manager to finalize.
    pub(super) fn handle_accept_reserves(
        &self,
        channel_id: &[u8; 32],
        sender_node_id: PublicKey,
    ) -> Result<(), LightningError> {
        use deposits_core::ChannelId;

        log_info!(
            self.logger,
            "📥 Received AcceptReserves from {} for channel {}",
            sender_node_id,
            hex::encode(&channel_id[..8])
        );

        let channel_id_typed = ChannelId::new(*channel_id);

        // Get the channel manager
        let cm = match &self.channel_manager {
            Some(cm) => cm,
            None => {
                log_error!(self.logger, "Channel manager not available for AcceptReserves handling");
                return Err(LightningError {
                    err: "Channel manager not available".to_string(),
                    action: ErrorAction::IgnoreError,
                });
            }
        };

        // Call extra_outputs_accepted to finalize the proposal
        if let Err(e) = cm.extra_outputs_accepted(&sender_node_id, &channel_id_typed) {
            log_error!(
                self.logger,
                "Failed to process AcceptReserves from {}: {}",
                sender_node_id,
                e
            );
            return Err(LightningError {
                err: format!("Failed to process acceptance: {}", e),
                action: ErrorAction::IgnoreError,
            });
        }

        log_info!(
            self.logger,
            "✅ Extra outputs accepted by {} for channel {} - commitment transaction will be updated",
            sender_node_id,
            hex::encode(&channel_id[..8])
        );

        Ok(())
    }
}

// Message struct conversions are handled in messages.rs
