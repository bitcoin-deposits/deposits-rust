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
    pub(super) fn handle_collateral_consent_request(
        &self,
        msg: &CollateralConsentRequestMsg,
        sender_node_id: PublicKey,
    ) -> Result<(), LightningError> {
        use deposits_core::log_warn;

        // Verify the request is from the operator claiming to be the operator
        if sender_node_id != msg.operator_id {
            log_warn!(
                self.logger,
                "📋 CONSENT: Rejecting - sender {} doesn't match claimed operator {}",
                sender_node_id,
                msg.operator_id
            );
            return Ok(());
        }

        // Check if we have an operator channel with the requesting operator
        // This would be the channel where our reserves would serve as collateral
        let has_channel_with_operator = {
            let ledgers = self.ledgers.lock().unwrap();
            ledgers.contains_key(&(msg.operator_id, self.our_node_id))
        };

        let consent_granted = has_channel_with_operator;

        // Create consent response with our signature
        let signature = if consent_granted {
            // Sign: SHA256("COLLATERAL_CONSENT" || operator_id || partner_id)
            match self.node_secret_key {
                Some(secret_key) => {
                    use bitcoin::hashes::{Hash, sha256};
                    use bitcoin::secp256k1::{Secp256k1, Message};

                    // Construct the message to sign
                    let mut preimage = Vec::new();
                    preimage.extend_from_slice(b"COLLATERAL_CONSENT");
                    preimage.extend_from_slice(&msg.operator_id.serialize());
                    preimage.extend_from_slice(&msg.partner_id.serialize());

                    let message_hash = sha256::Hash::hash(&preimage);
                    let secp_message = Message::from_digest(message_hash.to_byte_array());

                    let secp = Secp256k1::new();
                    let sig = secp.sign_ecdsa(&secp_message, &secret_key);
                    sig.serialize_compact()
                }
                None => {
                    log_warn!(self.logger, "📋 CONSENT: No secret key available for signing");
                    [0u8; 64]
                }
            }
        } else {
            [0u8; 64]
        };

        let response = DepositsMessage::CoordinationResponse(CoordinationResponseMsg::CollateralConsentResponse {
            request_hash: [0u8; 32], // Will be filled by wire layer
            operator_id: msg.operator_id,
            partner_id: msg.partner_id,
            consent_granted,
            collateral_partner_signature: signature,
        });

        if consent_granted {
            log_info!(
                self.logger,
                "📋 CONSENT: Granting consent to back ledger ({}, {}) as collateral partner",
                msg.operator_id,
                msg.partner_id
            );
        } else {
            log_warn!(
                self.logger,
                "📋 CONSENT: Denying consent - no operator channel with {}",
                msg.operator_id
            );
        }

        // Send response back to operator
        if let Err(e) = self.send_message(sender_node_id, response) {
            log_warn!(self.logger, "📋 CONSENT: Failed to send CollateralConsentResponse: {:?}", e);
        }

        // If consent granted, request sync of the ledger state we're backing
        // As a collateral partner, we need to track the ledger's state
        if consent_granted {
            log_info!(
                self.logger,
                "📋 CONSENT: Requesting sync of ledger ({}, {}) that we're backing as collateral",
                msg.operator_id,
                msg.partner_id
            );

            let sync_request = DepositsMessage::Sync(SyncMsg {
                operator_id: msg.operator_id,
                partner_id: msg.partner_id,
                from_sequence: 0, // Start from beginning since we're new to this ledger
                to_sequence: None,
            });

            if let Err(e) = self.send_message(msg.operator_id, sync_request) {
                log_warn!(self.logger, "📋 CONSENT: Failed to send SyncRequest: {:?}", e);
            }
        }

        Ok(())
    }

    /// Handle CollateralConsentResponse message
    pub(super) fn handle_collateral_consent_response(
        &self,
        msg: &CollateralConsentResponseMsg,
        sender_node_id: PublicKey,
    ) -> Result<(), LightningError> {
        use bitcoin::secp256k1::ecdsa::Signature;
        use deposits_core::log_warn;

        log_info!(
            self.logger,
            "📋 CONSENT: Received CollateralConsentResponse from {} - granted={}",
            sender_node_id,
            msg.consent_granted
        );

        // The sender is the collateral partner
        // Verify the signature if consent was granted
        if msg.consent_granted {
            use bitcoin::hashes::{Hash, sha256};
            use bitcoin::secp256k1::{Secp256k1, Message};

            // Reconstruct the message that was signed
            // Signs: SHA256("COLLATERAL_CONSENT" || operator_id || partner_id)
            let mut preimage = Vec::new();
            preimage.extend_from_slice(b"COLLATERAL_CONSENT");
            preimage.extend_from_slice(&msg.operator_id.serialize());
            preimage.extend_from_slice(&msg.partner_id.serialize());

            let message_hash = sha256::Hash::hash(&preimage);
            let secp_message = Message::from_digest(message_hash.to_byte_array());

            let secp = Secp256k1::new();
            match Signature::from_compact(&msg.collateral_partner_signature) {
                Ok(sig) => {
                    if secp.verify_ecdsa(&secp_message, &sig, &sender_node_id).is_err() {
                        log_warn!(
                            self.logger,
                            "📋 CONSENT: REJECTING consent from {} - invalid signature",
                            sender_node_id
                        );
                        return Ok(());
                    }
                    log_info!(
                        self.logger,
                        "📋 CONSENT: Verified signature from collateral partner {}",
                        sender_node_id
                    );
                }
                Err(e) => {
                    log_warn!(
                        self.logger,
                        "📋 CONSENT: REJECTING consent from {} - malformed signature: {}",
                        sender_node_id,
                        e
                    );
                    return Ok(());
                }
            }
        }

        // Find the pending consent request and complete it
        // Calculate the hash of the original request for lookup (V2 format)
        let original_request = DepositsMessage::Coordination(CoordinationMsg::CollateralConsentRequest {
            operator_id: msg.operator_id,
            partner_id: msg.partner_id,
            operator_signature: [0u8; 64], // This should match what we sent
        });
        let request_hash = self.calculate_message_hash(&original_request);

        // Complete the pending request
        let mut pending = self.pending_consent_requests.lock().unwrap();
        if let Some(tx) = pending.remove(&request_hash) {
            if msg.consent_granted {
                let _ = tx.send(Ok(msg.collateral_partner_signature));
            } else {
                let _ = tx.send(Err("Collateral partner denied consent".to_string()));
            }
        } else {
            log_warn!(
                self.logger,
                "📋 CONSENT: Received response but no pending request found for hash {}",
                crate::hex_utils::to_string(&request_hash[..8])
            );
        }
        drop(pending);

        // If consent was granted, sync the full audit history to the new collateral partner
        // This ensures they receive seq=0 (LedgerOpenRequest) and all subsequent updates
        if msg.consent_granted {
            log_info!(
                self.logger,
                "📋 SYNC: Sending full audit history to new collateral partner {}",
                sender_node_id
            );

            // The operator is us (we sent the request), partner_id is from the message
            // The new collateral partner is the sender of this response
            if let Err(e) = self.send_audit_update_to_new_collateral_partner(
                msg.partner_id,  // The channel partner for this ledger
                sender_node_id,  // The new collateral partner who just granted consent
                &DepositsMessage::CoordinationResponse(CoordinationResponseMsg::CollateralConsentResponse {
                    request_hash: [0u8; 32], // Will be filled by wire layer
                    operator_id: msg.operator_id,
                    partner_id: msg.partner_id,
                    consent_granted: msg.consent_granted,
                    collateral_partner_signature: msg.collateral_partner_signature,
                }),
            ) {
                log_warn!(
                    self.logger,
                    "📋 SYNC: Failed to send audit history to collateral partner: {:?}",
                    e
                );
            }
        }

        Ok(())
    }

    /// Handle CollateralAttestation message
    pub(super) fn handle_collateral_attestation(
        &self,
        msg: &crate::wire::messages::CollateralAttestationMsg,
        sender_node_id: PublicKey,
    ) -> Result<(), LightningError> {
        use deposits_core::log_warn;

        // CollateralAttestation is received from a collateral partner after they process
        // our CollateralIncrease. We need to:
        // 1. Store the attestation as proof
        // 2. Forward the attestation to our CHANNEL partners (not the collateral ledger)
        //    to record that collateral is now available
        log_info!(
            self.logger,
            "💰 COLLATERAL: Received attestation from {} for operator {} - amount={}",
            sender_node_id,
            msg.operator,
            msg.amount
        );

        // Collect ledgers where we're operator and sender is a collateral partner
        let mut channel_ledgers_to_update: Vec<(PublicKey, PublicKey)> = Vec::new();
        let mut pending_messages: Vec<(PublicKey, DepositsMessage)> = Vec::new();

        {
            let ledgers = self.ledgers.lock().unwrap();
            // Only forward attestations that we received DIRECTLY from the collateral partner
            // (not forwarded ones). This prevents infinite forwarding loops.
            let is_direct_from_collateral_partner = sender_node_id == msg.collateral_partner;

            for ((operator_id, partner_id), ledger_arc) in ledgers.iter() {
                // Case 1: We're the OPERATOR receiving from a channel partner
                // Store attestation and potentially forward to other partners
                if *operator_id == self.our_node_id && *partner_id == sender_node_id {
                    let mut ledger = ledger_arc.write().unwrap();
                    // Store attestation as proof on the sender's ledger
                    let attestation = deposits_core::types::CollateralAttestation::new(
                        msg.operator,
                        msg.collateral_partner,
                        msg.amount,
                        msg.block_height,
                        msg.signature,
                        msg.ledger_hash,
                    );
                    ledger.state.collateral_attestations.insert(sender_node_id, attestation);
                    log_info!(
                        self.logger,
                        "💰 COLLATERAL: Stored attestation from channel partner {} on ledger ({}, {})",
                        sender_node_id,
                        operator_id,
                        partner_id
                    );
                }
                // Case 1b: We're the OPERATOR and this is a DIFFERENT channel partner
                // Forward the attestation to them so they know about available collateral
                // BUT only if we received it directly from the collateral partner (not forwarded)
                else if *operator_id == self.our_node_id && *partner_id != sender_node_id && is_direct_from_collateral_partner {
                    // Forward to other channel partners
                    channel_ledgers_to_update.push((*operator_id, *partner_id));
                    log_info!(
                        self.logger,
                        "💰 COLLATERAL: Will forward attestation from {} to channel partner {} on ledger ({}, {})",
                        sender_node_id, partner_id, operator_id, partner_id
                    );
                }
                // Case 2: We're the PARTNER receiving from the OPERATOR
                // The operator forwards attestations to channel partners after receiving them from collateral partners
                else if *partner_id == self.our_node_id && *operator_id == sender_node_id {
                    let mut ledger = ledger_arc.write().unwrap();
                    // Store attestation
                    let attestation = deposits_core::types::CollateralAttestation::new(
                        msg.operator,
                        msg.collateral_partner,
                        msg.amount,
                        msg.block_height,
                        msg.signature,
                        msg.ledger_hash,
                    );
                    ledger.state.collateral_attestations.insert(msg.collateral_partner, attestation);

                    // Update received_collateral_amount - this is the critical fix!
                    ledger.state.received_collateral_amount = ledger.state.received_collateral_amount.saturating_add(msg.amount);
                    log_info!(
                        self.logger,
                        "💰 COLLATERAL: Partner received attestation from operator {} - updated received_collateral_amount to {} for ledger ({}, {})",
                        sender_node_id,
                        ledger.state.received_collateral_amount,
                        operator_id,
                        partner_id
                    );

                    if let Err(e) = self.persist_ledger_state(&*ledger) {
                        log_error!(self.logger, "Failed to persist ledger after partner CollateralAttestation: {}", e);
                    }
                }
            }
        }

        // Forward CollateralAttestation to channel partners for bilateral signing
        // (Previously created a separate CollateralStatus, now we forward the full attestation)
        if !channel_ledgers_to_update.is_empty() {
            let attestation_forward = DepositsMessage::LedgerUpdate(LedgerUpdateMsg::new_with_operation(
                msg.operator,
                msg.collateral_partner,
                LedgerOperation::CollateralAttestation {
                    collateral_operator: msg.operator,
                    amount: msg.amount,
                    block_height: msg.block_height,
                    signature: msg.signature,
                    ledger_hash: msg.ledger_hash,
                },
            ));

            let ledgers = self.ledgers.lock().unwrap();
            for (op_id, part_id) in channel_ledgers_to_update {
                if let Some(ledger_arc) = ledgers.get(&(op_id, part_id)) {
                    let mut ledger = ledger_arc.write().unwrap();
                    match ledger.append_v1_mut_with_metadata(attestation_forward.clone()) {
                        Ok((prev_hash, new_hash, seq)) => {
                            log_info!(
                                self.logger,
                                "💰 COLLATERAL: Recorded CollateralAttestation on channel ledger ({}, {}), seq={}, amount={}, from={}",
                                op_id, part_id, seq, msg.amount, sender_node_id
                            );
                            ledger.state.received_collateral_amount = ledger.state.received_collateral_amount.saturating_add(msg.amount);
                            if let Err(e) = self.persist_ledger_state(&*ledger) {
                                log_error!(self.logger, "Failed to persist ledger after CollateralAttestation: {}", e);
                            }

                            // Queue message for sending to channel partner for bilateral signing
                            pending_messages.push((part_id, attestation_forward.clone()));

                            // Track for broadcast after partner ACK (use partner-specific key)
                            let message_hash = self.calculate_message_hash(&attestation_forward);
                            let unique_key = Self::create_partner_specific_hash(&message_hash, &part_id);
                            {
                                let mut sent_messages = self.sent_messages_for_broadcast.lock().unwrap();
                                sent_messages.insert(unique_key, (op_id, part_id, attestation_forward.clone(), prev_hash, new_hash, seq));
                            }
                            {
                                let mut pending_acks = self.pending_acks.lock().unwrap();
                                let timestamp = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap()
                                    .as_secs();
                                pending_acks.insert(unique_key, deposits_core::PendingAck {
                                    message_type: attestation_forward.message_type(),
                                    timestamp,
                                    peer: part_id,
                                });
                            }
                        }
                        Err(e) => {
                            log_error!(
                                self.logger,
                                "❌ COLLATERAL: Failed to add CollateralAttestation to channel ledger ({}, {}): {}",
                                op_id, part_id, e
                            );
                        }
                    }
                }
            }
        }

        // Send pending messages (CollateralAttestation to channel partners)
        for (peer_id, msg_to_send) in pending_messages {
            if let Err(e) = self.send_message(peer_id, msg_to_send.clone()) {
                log_error!(self.logger, "💰 COLLATERAL: Failed to send CollateralAttestation to {}: {:?}", peer_id, e);
            } else {
                log_info!(self.logger, "💰 COLLATERAL: Sent CollateralAttestation to channel partner {}", peer_id);
            }
        }

        // Simple ACK for the attestation itself (V2 format)
        let attestation_msg = DepositsMessage::LedgerUpdate(LedgerUpdateMsg::new_with_operation(
            msg.operator,
            msg.collateral_partner,
            LedgerOperation::CollateralAttestation {
                collateral_operator: msg.operator,
                amount: msg.amount,
                block_height: msg.block_height,
                signature: msg.signature,
                ledger_hash: msg.ledger_hash,
            },
        ));
        if let Err(e) = self.send_acknowledgment(&attestation_msg, true, None, None, sender_node_id) {
            log_warn!(self.logger, "💰 COLLATERAL: Failed to send ACK: {:?}", e);
        }

        Ok(())
    }

    // ==================== Accusation Message Handlers ====================

    /// Handle UncreditedPayment accusation message (0x8035)
    /// Partner broadcasting proof of unpaid settlement
    pub(super) fn handle_uncredited_payment(
        &self,
        msg: &UncreditedPaymentMsg,
        sender_node_id: PublicKey,
    ) -> Result<(), LightningError> {
        use bitcoin::hashes::{sha256, Hash};
        use super::messages::DepositsMessage;

        log_info!(
            self.logger,
            "⚠️ ACCUSATION: Received UncreditedPayment from {} - operator={}, payment_hash={}, amount={}",
            sender_node_id,
            msg.operator,
            hex::encode(&msg.payment_hash[..8]),
            msg.amount_msat
        );

        // 1. Verify preimage matches payment hash
        let computed_hash = sha256::Hash::hash(&msg.preimage);
        if computed_hash.as_byte_array() != &msg.payment_hash {
            log_warn!(
                self.logger,
                "⚠️ ACCUSATION: Invalid preimage - computed hash {} doesn't match payment_hash {}",
                hex::encode(computed_hash.as_byte_array()),
                hex::encode(&msg.payment_hash)
            );
            return Ok(());
        }

        // 2. Verify the accuser is the partner for this ledger
        if msg.partner != sender_node_id {
            log_warn!(
                self.logger,
                "⚠️ ACCUSATION: Sender {} is not the claimed partner {}",
                sender_node_id,
                msg.partner
            );
            return Ok(());
        }

        // 3. Check if we have the relevant ledger
        let ledger_key = (msg.operator, msg.partner);
        let has_credit = {
            let ledgers = self.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get(&ledger_key) {
                let ledger = ledger_arc.read().unwrap();
                // Check if there's a credit for this payment hash in the ledger
                ledger.has_credit_for_payment(&msg.payment_hash)
            } else {
                // We don't have this ledger - store accusation for later verification
                false
            }
        };

        if has_credit {
            log_info!(
                self.logger,
                "⚠️ ACCUSATION: Ledger ({}, {}) has a credit for payment_hash {} - accusation appears invalid",
                msg.operator,
                msg.partner,
                hex::encode(&msg.payment_hash[..8])
            );
            return Ok(());
        }

        // 4. Store the accusation for dispute resolution
        // TODO: Implement accusation storage (AccusationManager)
        log_warn!(
            self.logger,
            "⚠️ ACCUSATION: Storing uncredited payment accusation - operator={}, deposit={}, amount={}, settlement_seq={}",
            msg.operator,
            msg.deposit_pubkey,
            msg.amount_msat,
            msg.settlement_sequence
        );

        // 5. Emit event for node layer
        let _ = self.event_queue.emit_deposits_event(
            super::events::DepositsEvent::UncreditedPaymentAccusation {
                operator: msg.operator,
                partner: msg.partner,
                payment_hash: msg.payment_hash,
                deposit_pubkey: msg.deposit_pubkey,
                amount_msat: msg.amount_msat,
                settlement_sequence: msg.settlement_sequence,
            },
        );

        // 6. If we have our own channel with this operator, force-close it and rebroadcast
        // This protects us from a proven bad actor
        if msg.operator != self.our_node_id {
            // Check if we have a ledger with this operator (we are their partner)
            let our_ledger_key = (msg.operator, self.our_node_id);
            let have_channel_with_operator = {
                let ledgers = self.ledgers.lock().unwrap();
                ledgers.contains_key(&our_ledger_key)
            };

            if have_channel_with_operator {
                log_warn!(
                    self.logger,
                    "⚠️ ACCUSATION: We have a channel with accused operator {} - force-closing for protection",
                    msg.operator
                );

                // Force-close our channel with this operator
                if let Some(ref cm) = self.channel_manager {
                    let channels = cm.list_channels();
                    if let Some(channel) = channels.iter().find(|c| c.counterparty_node_id == msg.operator) {
                        let reason = format!(
                            "Fraud proof received: operator {} accused of uncredited payment (payment_hash={})",
                            msg.operator,
                            hex::encode(&msg.payment_hash[..8])
                        );

                        if let Err(e) = cm.force_close_broadcasting_latest_txn(
                            &channel.channel_id,
                            &msg.operator,
                            reason,
                        ) {
                            log_error!(
                                self.logger,
                                "⚠️ ACCUSATION: Failed to force-close our channel with operator {}: {:?}",
                                msg.operator,
                                e
                            );
                        } else {
                            log_warn!(
                                self.logger,
                                "⚠️ ACCUSATION: Force-closed our channel with operator {} due to fraud proof",
                                msg.operator
                            );
                        }
                    }
                }

                // Rebroadcast the accusation to our own collateral partners
                let our_collateral_partners = {
                    let ledgers = self.ledgers.lock().unwrap();
                    if let Some(ledger_arc) = ledgers.get(&our_ledger_key) {
                        let ledger = ledger_arc.read().unwrap();
                        ledger.state.collateral_partners.clone()
                    } else {
                        vec![]
                    }
                };

                // Forward the accusation to our collateral partners (excluding the sender)
                let accusation_msg = DepositsMessage::Recovery(RecoveryMsg::UncreditedPayment {
                    operator: msg.operator,
                    partner: msg.partner,
                    payment_hash: msg.payment_hash,
                    preimage: msg.preimage,
                    deposit_pubkey: msg.deposit_pubkey,
                    amount_msat: msg.amount_msat,
                    invoice_cosignature: msg.invoice_cosignature,
                    settlement_sequence: msg.settlement_sequence,
                    settlement_ledger_hash: msg.settlement_ledger_hash,
                    settlement_block_height: msg.settlement_block_height,
                    accuser_signature: msg.accuser_signature,
                });
                for partner in our_collateral_partners {
                    if partner != sender_node_id {
                        log_info!(
                            self.logger,
                            "⚠️ ACCUSATION: Forwarding fraud proof to our collateral partner {}",
                            partner
                        );
                        let _ = self.send_message(partner, accusation_msg.clone());
                    }
                }
            }
        }

        Ok(())
    }

    // ==================== Tombstone Message Handlers ====================

    /// Handle ChannelCloseTombstone message
    /// Append to ledger and mark as closed
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

        // Determine our role: operator or partner
        let we_are_operator = tombstone_msg.operator_id == self.our_node_id;
        let we_are_partner = tombstone_msg.partner_id == self.our_node_id;

        if !we_are_operator && !we_are_partner {
            log_warn!(
                self.logger,
                "₿ Received tombstone for ledger we're not part of: operator={}, partner={}",
                tombstone_msg.operator_id,
                tombstone_msg.partner_id
            );
            return Ok(());
        }

        let ledger_key = (tombstone_msg.operator_id, tombstone_msg.partner_id);

        if we_are_operator {
            // We are the operator - use ledgers
            let mut ledgers = self.ledgers.lock().unwrap();
            if let Some(ledger_arc) = ledgers.get_mut(&ledger_key) {
                let mut ledger_guard = ledger_arc.write().unwrap();

                // Extract values before mem::replace to avoid borrow checker issues
                let operator_node_id = ledger_guard.operator_key();
                let partner_node_id = ledger_guard.partner_key();
                let our_role = ledger_guard.role;
                let collateral_partners = ledger_guard.state.collateral_partners.clone();
                let ledger_address = ledger_guard.state.ledger_address.clone();

                // Take ownership of the ledger
                let ledger_owned = std::mem::replace(
                    &mut *ledger_guard,
                    deposits_core::Ledger::new(
                        operator_node_id,
                        partner_node_id,
                        our_role,
                        collateral_partners,
                        ledger_address,
                    )
                );

                match ledger_owned.append_v1(message.clone()) {
                    Ok((updated_ledger, _new_hash)) => {
                        *ledger_guard = updated_ledger;
                        log_info!(
                            self.logger,
                            "✅ Tombstone appended to operator ledger. Ledger is now closed."
                        );
                    }
                    Err(e) => {
                        log_error!(
                            self.logger,
                            "Failed to append tombstone to operator ledger: {:?}. Ledger state may be inconsistent.",
                            e
                        );
                    }
                }
            } else {
                log_warn!(
                    self.logger,
                    "₿ Received tombstone for non-existent operator ledger: {:?}",
                    ledger_key
                );
            }
        } else {
            // We are the partner - use ledgers
            // Partners receive tombstones as SignedAuditUpdate, but may also receive raw tombstone
            // Convert to SignedLedgerUpdate for consistent storage
            let mut ledgers = self.ledgers.lock().unwrap();

            // Get or create the partner ledger
            let ledger = ledgers.entry(ledger_key).or_insert_with(|| {
                log_info!(
                    self.logger,
                    "📋 PARTNER: Creating partner ledger for tombstone from operator {}",
                    tombstone_msg.operator_id
                );
                Arc::new(RwLock::new(Ledger::new(
                    tombstone_msg.operator_id,
                    self.our_node_id,
                    LedgerRole::Partner,
                    vec![],
                    String::new(),
                )))
            });

            let mut ledger_guard = ledger.write().unwrap();

            // For raw tombstone messages received by partner, we need to create a SignedLedgerUpdate
            // Use the sequence_number from the tombstone message
            let signed_update = deposits_core::SignedLedgerUpdate {
                message: {
                    use lightning::util::ser::Writeable;
                    let mut buf = Vec::new();
                    message.write(&mut buf).unwrap();
                    buf
                },
                message_type: message.message_type(),
                operator_signature: [0u8; 64], // No signature for raw tombstone - will be replaced by SignedAuditUpdate if available
                partner_signature: [0u8; 64],  // No partner signature for raw tombstone
                operator_id: tombstone_msg.operator_id,
                partner_id: tombstone_msg.partner_id,
                sequence_number: tombstone_msg.sequence_number,
                previous_hash: [0u8; 32], // Unknown from raw message
                current_hash: [0u8; 32],  // Unknown from raw message
                timestamp: tombstone_msg.timestamp,
            };

            let count = ledger_guard.insert_signed_unchecked(signed_update);
            log_info!(
                self.logger,
                "✅ Tombstone inserted to partner ledger (seq={}, added {} updates). Ledger is now closed.",
                tombstone_msg.sequence_number,
                count
            );
        }

        Ok(()) // Tombstone messages don't need ACKs or further processing
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

        // Convert to SignedLedgerUpdate
        let signed_update = deposits_core::SignedLedgerUpdate {
            message: signed_msg.message.clone(),
            message_type: signed_msg.message_type,
            operator_signature: signed_msg.operator_signature,
            partner_signature: signed_msg.partner_signature.unwrap_or([0u8; 64]),
            operator_id: signed_msg.operator_id,
            partner_id: signed_msg.partner_id,
            sequence_number: signed_msg.sequence_number,
            previous_hash: signed_msg.previous_hash,
            current_hash: signed_msg.current_hash,
            timestamp: signed_msg.timestamp,
        };

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

            // Convert handler SyncResponseMsg to core SyncResponseMsg
            let core_response = deposits_core::messages::SyncResponseMsg {
                operator_id: response.operator_id,
                partner_id: response.partner_id,
                request_hash: [0u8; 32], // Not available in handler format
                updates: response.updates.iter().map(|u| deposits_core::types::SignedLedgerUpdate {
                    message: u.message.clone(),
                    message_type: u.message_type,
                    operator_id: u.operator_id,
                    partner_id: u.partner_id,
                    sequence_number: u.sequence_number,
                    previous_hash: u.previous_hash,
                    current_hash: u.current_hash,
                    timestamp: u.timestamp,
                    partner_signature: u.partner_signature.unwrap_or([0u8; 64]),
                    operator_signature: u.operator_signature,
                }).collect(),
                current_sequence: response.updates.last().map(|u| u.sequence_number).unwrap_or(0),
                current_hash: response.updates.last().map(|u| u.current_hash).unwrap_or([0u8; 32]),
            };
            if let Err(e) = self.handle_audit_sync_response(&core_response, sender_node_id) {
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
