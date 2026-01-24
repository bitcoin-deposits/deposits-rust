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
use lightning::util::logger::Logger;

use super::core::DepositsHandler;
use super::ledger_ext::LedgerExt;
use super::messages::*;
use deposits_core::{log_debug, log_error, log_info, log_warn};
use lightning::util::logger::Logger as LdkLogger;

use std::ops::Deref;

impl<L: Deref + Clone> DepositsHandler<L>
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
            msg.requester_pubkey,
            msg.operator_id,
            msg.partner_id
        );

        // Delegate to QuorumManager (convert to core type using helper function)
        match self.quorum_manager.handle_join_request(&quorum_join_request_to_core(&msg)) {
            Ok(response) => {
                let accepted = response.accepted;

                if accepted {
                    log_info!(
                        self.logger,
                        "📋 QUORUM: Accepted {} into quorum (now {} members)",
                        msg.requester_pubkey,
                        response.members.len()
                    );
                } else {
                    log_info!(
                        self.logger,
                        "📋 QUORUM: Rejected join request from {}: {:?}",
                        msg.requester_pubkey,
                        response.rejection_reason
                    );
                }

                // Queue response (convert from core type using helper function)
                let response_into = quorum_join_response_from_core(response);
                let response_msg = DepositsMessage::QuorumJoinResponse {
                    accepted: response_into.accepted,
                    members: response_into.members,
                    threshold: response_into.threshold,
                    last_sequence: response_into.last_sequence,
                    current_state_hash: response_into.current_state_hash,
                    rejection_reason: response_into.rejection_reason,
                };
                self.outbound_messages
                    .lock()
                    .unwrap()
                    .entry(sender_node_id)
                    .or_insert_with(Vec::new)
                    .push(response_msg);

                // If accepted, send state sync to new member
                if accepted {
                    self.send_state_sync_to_member(
                        msg.requester_pubkey,
                        msg.operator_id,
                        msg.partner_id,
                    );
                }
            }
            Err(e) => {
                log_error!(
                    self.logger,
                    "📋 QUORUM: Failed to handle join request: {:?}",
                    e
                );
            }
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
        let mut applied_count = 0;
        let mut error_count = 0;

        for signed_msg in &msg.updates {
            // Convert SignedAuditUpdateMsg to SignedLedgerUpdate
            let signed_update = deposits_core::SignedLedgerUpdate {
                message: signed_msg.message.clone(),
                message_type: signed_msg.message_type,
                operator_signature: signed_msg.operator_signature,
                partner_signature: signed_msg.partner_signature.unwrap_or([0u8; 64]),
                operator_pubkey: signed_msg.operator_pubkey,
                partner_pubkey: signed_msg.partner_pubkey,
                sequence_number: signed_msg.sequence_number,
                previous_state_hash: signed_msg.previous_state_hash,
                current_state_hash: signed_msg.current_state_hash,
                timestamp: signed_msg.timestamp,
            };

            // Verify and store the update
            match self.verify_and_store_signed_update(signed_update) {
                Ok(()) => applied_count += 1,
                Err(e) => {
                    log_warn!(
                        self.logger,
                        "📋 QUORUM: Failed to apply update seq={}: {:?}",
                        signed_msg.sequence_number,
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
                    last_update.current_state_hash
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
                    .map(|u| u.current_state_hash)
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

        if let Err(e) = self.send_message(sender_node_id, DepositsMessage::QuorumVote {
            vote_round_id: vote_msg.vote_round_id,
            voter_pubkey: vote_msg.voter_pubkey,
            vote: vote_msg.vote,
            voter_sequence: vote_msg.voter_sequence,
            voter_state_hash: vote_msg.voter_state_hash,
            evidence: vote_msg.evidence,
            signature: vote_msg.signature,
            spend_signature: vote_msg.spend_signature,
        }) {
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
        _sender: PublicKey,
    ) -> Result<(), LightningError> {
        use deposits_core::log_warn;

        log_info!(
            self.logger,
            "🔄 RECOVERY: Received vote from {} for operator {} (conforming={})",
            msg.voter,
            msg.operator,
            msg.is_conforming
        );

        // Convert message to RecoveryVote struct
        let vote = deposits_core::recovery::RecoveryVote {
            voter: msg.voter,
            is_conforming: msg.is_conforming,
            validated_hash: msg.validated_hash,
            validated_sequence: msg.validated_sequence,
            substitute_nomination: msg.substitute_nomination,
            discovered_violation: msg.discovered_violation,
            signature: msg.signature,
        };

        // Submit vote to recovery manager (it handles signature verification)
        let ledger_id = (msg.operator, msg.partner);
        let vote_result = {
            let mut recovery_manager = self.recovery_manager.lock().unwrap();
            recovery_manager.submit_vote(ledger_id, vote)
        };

        match vote_result {
            Ok(result) => {
                log_info!(
                    self.logger,
                    "🔄 RECOVERY: Vote recorded - operator {} partner {} voter {} conforming={} (total={}, conforming={}, non-conforming={})",
                    msg.operator,
                    msg.partner,
                    msg.voter,
                    msg.is_conforming,
                    result.total_votes,
                    result.conforming_votes,
                    result.non_conforming_votes
                );

                // Check for non-compliance determination
                let non_conforming_threshold = if result.total_votes <= 2 {
                    1  // For 2-of-2 ledgers
                } else {
                    (result.total_votes / 2) + 1  // Strict majority
                };

                if result.non_conforming_votes >= non_conforming_threshold {
                    log_info!(
                        self.logger,
                        "🔄 RECOVERY: NON-COMPLIANCE DETERMINED! operator {} partner {} ({}/{} non-conforming votes)",
                        msg.operator,
                        msg.partner,
                        result.non_conforming_votes,
                        result.total_votes
                    );

                    // Emit RecoveryNonCompliant event
                    let _ = self.event_queue.emit_deposits_event(
                        super::events::DepositsEvent::RecoveryNonCompliant {
                            operator_id: msg.operator,
                            partner_id: msg.partner,
                            non_conforming_votes: result.non_conforming_votes as u32,
                            total_votes: result.total_votes as u32,
                        },
                    );
                }
            }
            Err(e) => {
                log_warn!(
                    self.logger,
                    "🔄 RECOVERY: Failed to submit vote from {} for operator {}: {:?}",
                    msg.voter,
                    msg.operator,
                    e
                );
            }
        }

        Ok(())
    }

    /// Handle RecoveryClaimRequest message
    pub(super) fn handle_recovery_claim_request(
        &self,
        msg: &RecoveryClaimRequestMsg,
        _sender: PublicKey,
    ) -> Result<(), LightningError> {
        use bitcoin::secp256k1::{Secp256k1, Message, Keypair};
        use deposits_core::log_warn;

        log_info!(
            self.logger,
            "🔄 RECOVERY: Received claim request from {} for operator {} tier {}",
            msg.claimant,
            msg.operator,
            msg.tier_index
        );

        // Verify the operator is in non-compliant recovery phase
        let ledger_id = (msg.operator, msg.partner);
        let is_non_compliant = {
            let recovery_manager = self.recovery_manager.lock().unwrap();
            match recovery_manager.get_recovery(&ledger_id) {
                Some(state) => {
                    matches!(state.phase, deposits_core::recovery::RecoveryPhase::NonCompliantRecovery { .. })
                }
                None => {
                    log_warn!(
                        self.logger,
                        "🔄 RECOVERY: No recovery state found for operator {} partner {} - proceeding anyway",
                        msg.operator, msg.partner
                    );
                    true
                }
            }
        };

        if !is_non_compliant {
            log_warn!(
                self.logger,
                "🔄 RECOVERY: Operator {} is not in non-compliant recovery phase - ignoring claim request",
                msg.operator
            );
            return Ok(());
        }

        // Sign the claim transaction if we have the key
        let secp = Secp256k1::new();
        let secret_key = match self.node_secret_key {
            Some(sk) => sk,
            None => {
                log_warn!(
                    self.logger,
                    "🔄 RECOVERY: No signing key available for claim request"
                );
                return Ok(());
            }
        };
        let keypair = Keypair::from_secret_key(&secp, &secret_key);

        // Sign the sighash
        let sighash_msg = Message::from_digest(msg.sighash);
        let signature = secp.sign_schnorr_no_aux_rand(&sighash_msg, &keypair);

        // Send signature response
        let response = RecoveryClaimSignatureMsg {
            operator: msg.operator,
            partner: msg.partner,
            signer: self.our_node_id,
            sighash: msg.sighash,
            signature: signature.serialize(),
        };

        log_info!(
            self.logger,
            "🔄 RECOVERY: Sending claim signature to {} for sighash {}",
            msg.claimant,
            hex::encode(&msg.sighash[..8])
        );

        self.outbound_messages
            .lock()
            .unwrap()
            .entry(msg.claimant)
            .or_insert_with(Vec::new)
            .push(DepositsMessage::RecoveryClaimSignature {
                operator: response.operator,
                partner: response.partner,
                signer: response.signer,
                sighash: response.sighash,
                signature: response.signature,
            });

        Ok(())
    }

    /// Handle RecoveryClaimSignature message
    pub(super) fn handle_recovery_claim_signature(
        &self,
        msg: &RecoveryClaimSignatureMsg,
        _sender: PublicKey,
    ) -> Result<(), LightningError> {
        use deposits_core::log_warn;

        log_info!(
            self.logger,
            "🔄 RECOVERY: Received claim signature from {} for sighash {}",
            msg.signer,
            hex::encode(&msg.sighash[..8])
        );

        // Add signature to claim manager (it handles verification)
        let ledger_id = (msg.operator, msg.partner);
        let add_result = {
            let mut claim_manager = self.claim_manager.lock().unwrap();
            claim_manager.add_peer_signature(&ledger_id, &msg.signer, msg.signature)
        };

        match add_result {
            Ok(has_sufficient) => {
                log_info!(
                    self.logger,
                    "🔄 RECOVERY: Claim signature stored - operator {} partner {} signer {} (threshold_met={})",
                    msg.operator,
                    msg.partner,
                    msg.signer,
                    has_sufficient
                );

                // Emit RecoveryClaimReady event when threshold is met
                if has_sufficient {
                    log_info!(
                        self.logger,
                        "🔄 RECOVERY: Signature threshold reached for operator {} partner {} - claim ready!",
                        msg.operator,
                        msg.partner
                    );

                    let _ = self.event_queue.emit_deposits_event(
                        super::events::DepositsEvent::RecoveryClaimReady {
                            operator_id: msg.operator,
                            partner_id: msg.partner,
                        },
                    );
                }
            }
            Err(e) => {
                log_warn!(
                    self.logger,
                    "🔄 RECOVERY: Failed to add signature from {} for operator {}: {:?}",
                    msg.signer,
                    msg.operator,
                    e
                );
            }
        }

        Ok(())
    }

    /// Handle RecoveryClaimComplete message
    pub(super) fn handle_recovery_claim_complete(
        &self,
        msg: &RecoveryClaimCompleteMsg,
        _sender: PublicKey,
    ) -> Result<(), LightningError> {
        log_info!(
            self.logger,
            "🔄 RECOVERY: Claim complete for operator {} - new operator {} (txid: {}, block: {})",
            msg.operator,
            msg.new_operator,
            hex::encode(&msg.claim_txid[..8]),
            msg.confirmation_block
        );

        // Clean up the completed claim from ClaimManager
        let ledger_id = (msg.operator, msg.partner);
        {
            let mut claim_manager = self.claim_manager.lock().unwrap();
            if let Some(_removed) = claim_manager.remove_claim(&ledger_id) {
                log_info!(
                    self.logger,
                    "🔄 RECOVERY: Removed completed claim for operator {} partner {}",
                    msg.operator, msg.partner
                );
            }
        }

        // Emit event for node layer
        let _ = self.event_queue.emit_deposits_event(
            super::events::DepositsEvent::RecoveryClaimCompleted {
                old_operator: msg.operator,
                partner_id: msg.partner,
                new_operator: msg.new_operator,
                claim_txid: msg.claim_txid,
                confirmation_block: msg.confirmation_block,
            },
        );

        Ok(())
    }

    // ========================================================================
    // Collateral/Voter Message Handlers
    // ========================================================================

    /// Handle CollateralAddPartner message
    pub(super) fn handle_collateral_add_partner(
        &self,
        msg: &super::messages::CollateralAddPartnerMsg,
        sender_node_id: PublicKey,
    ) -> Result<(), LightningError> {
        use deposits_core::quorum::LedgerId;
        use deposits_core::log_warn;

        log_info!(
            self.logger,
            "📋 VOTER: Received AddCollateralPartner from {} - adding {} to ledger with partner {}",
            sender_node_id,
            msg.collateral_partner,
            msg.partner_id
        );

        // Verify that the message is from the operator of a ledger we're the partner of
        let ledger_key = (sender_node_id, msg.partner_id);

        // We must be the partner_id to process this message
        if msg.partner_id != self.our_node_id {
            log_warn!(
                self.logger,
                "📋 VOTER: Rejecting AddCollateralPartner - we ({}) are not the target partner ({})",
                self.our_node_id,
                msg.partner_id
            );
            return Ok(());
        }

        // Update the ledger's collateral_partners via apply_state_only (NO hash chain entry)
        // Partners don't maintain their own hash chain - they receive SignedAuditUpdate from operator
        let mut ledgers = self.ledgers.lock().unwrap();
        if let Some(ledger_arc) = ledgers.get_mut(&ledger_key) {
            let mut ledger_guard = ledger_arc.write().unwrap();

            // Idempotency check: reject if collateral partner already exists in ledger
            if ledger_guard.state.collateral_partners.contains(&msg.collateral_partner) {
                log_info!(
                    self.logger,
                    "📋 PARTNER: Collateral partner {} already exists in ledger, sending ACK (idempotent)",
                    msg.collateral_partner
                );
                drop(ledger_guard);
                drop(ledgers);
                // Send ACK even though already exists - this is idempotent behavior
                let add_partner_msg = DepositsMessage::CollateralAddPartner {
                    operator_id: msg.operator_id,
                    partner_id: msg.partner_id,
                    collateral_partner: msg.collateral_partner,
                    collateral_partner_signature: msg.collateral_partner_signature,
                };
                if let Err(e) = self.send_acknowledgment(&add_partner_msg, true, None, None, sender_node_id) {
                    log_warn!(self.logger, "📋 PARTNER: Failed to send ACK for duplicate AddCollateralPartner: {:?}", e);
                }
                return Ok(());
            }

            // Append to hash chain with proper porcupine dance signing
            // Partner creates their own hash entry, signs it, and sends signature in ACK
            let add_partner_msg = DepositsMessage::CollateralAddPartner {
                operator_id: msg.operator_id,
                partner_id: msg.partner_id,
                collateral_partner: msg.collateral_partner,
                collateral_partner_signature: msg.collateral_partner_signature,
            };
            match ledger_guard.append_v1_mut_with_metadata(add_partner_msg.clone()) {
                Ok((prev_hash, new_hash, seq)) => {
                    log_info!(
                        self.logger,
                        "📋 VOTER: Appended collateral partner {} to ledger ({}, {}), seq={}, hash={:02x?}",
                        msg.collateral_partner,
                        sender_node_id,
                        msg.partner_id,
                        seq,
                        &new_hash[0..8]
                    );

                    // Get message bytes for signing
                    let message_bytes = ledger_guard.history.last()
                        .map(|u| u.message.clone())
                        .unwrap_or_default();

                    let timestamp = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();

                    // Partner signs content (porcupine dance)
                    let partner_sig = match self.sign_as_partner(
                        &message_bytes,
                        add_partner_msg.message_type(),
                        seq,
                        &prev_hash,
                        &new_hash,
                        timestamp,
                    ) {
                        Ok(sig) => Some(sig),
                        Err(e) => {
                            log_warn!(self.logger, "📋 VOTER: Failed to sign AddCollateralPartner: {:?}", e);
                            None
                        }
                    };

                    // Save updated ledger state (must do before dropping guard)
                    if let Err(e) = self.persist_ledger_state(&*ledger_guard) {
                        log_warn!(
                            self.logger,
                            "📋 VOTER: Failed to persist ledger after adding collateral partner: {:?}",
                            e
                        );
                    }

                    drop(ledger_guard);
                    drop(ledgers);

                    // Sync with QuorumManager - add collateral partner to quorum membership
                    // Note: Quorums only exist on the operator side, so this will fail for partners
                    // which is expected behavior - partners just store the ledger update, they don't manage quorums
                    let ledger_id = LedgerId::new(sender_node_id, msg.partner_id);
                    if let Err(e) = self.quorum_manager.add_member(&ledger_id, msg.collateral_partner) {
                        // This is expected for partners - quorums only exist on operator side
                        log_debug!(
                            self.logger,
                            "📋 PARTNER: Quorum sync skipped (quorum only exists on operator): {:?}",
                            e
                        );
                    } else {
                        log_info!(
                            self.logger,
                            "📋 VOTER: Added collateral partner {} to quorum for ledger ({}, {})",
                            msg.collateral_partner,
                            sender_node_id,
                            msg.partner_id
                        );
                    }

                    // Send ACK with porcupine dance signature
                    let message_hash = Self::create_message_hash(&add_partner_msg);
                    let ack = DepositsMessage::Ack(super::messages::AckMsg {
                        acked_message_type: add_partner_msg.message_type(),
                        message_hash,
                        success: true,
                        error_message: None,
                        cosignature: None,
                        update_signature: partner_sig,
                        update_sequence: Some(seq),
                        update_prev_hash: Some(prev_hash),
                        update_curr_hash: Some(new_hash),
                        // V2 required fields
                        partner_signature: partner_sig,
                        confirmed_sequence: seq,
                        confirmed_hash: new_hash,
                    });

                    {
                        let mut outbound_messages = self.outbound_messages.lock().unwrap();
                        outbound_messages.entry(sender_node_id).or_insert_with(Vec::new).push(ack.clone());
                    }
                    self.trigger_immediate_send(sender_node_id, ack.message_type());
                    log_info!(self.logger, "📋 VOTER: Sent ACK with porcupine signature for AddCollateralPartner");
                }
                Err(e) => {
                    log_warn!(
                        self.logger,
                        "📋 VOTER: Failed to add collateral partner {}: {:?}",
                        msg.collateral_partner,
                        e
                    );

                    // Send NACK back to operator using helper
                    drop(ledger_guard);
                    drop(ledgers);

                    if let Err(ack_err) = self.send_acknowledgment(&add_partner_msg, false, Some(format!("{:?}", e)), None, sender_node_id) {
                        log_warn!(self.logger, "📋 VOTER: Failed to send NACK for AddCollateralPartner: {:?}", ack_err);
                    }
                }
            }
        } else {
            log_warn!(
                self.logger,
                "📋 VOTER: No ledger found for operator {} partner {} to add collateral partner",
                sender_node_id,
                msg.partner_id
            );

            // Send NACK so operator knows the ledger wasn't found
            let add_partner_msg = DepositsMessage::CollateralAddPartner {
                operator_id: msg.operator_id,
                partner_id: msg.partner_id,
                collateral_partner: msg.collateral_partner,
                collateral_partner_signature: msg.collateral_partner_signature,
            };
            if let Err(e) = self.send_acknowledgment(
                &add_partner_msg,
                false,
                Some(format!("No ledger found for operator {} partner {}", sender_node_id, msg.partner_id)),
                None,
                sender_node_id
            ) {
                log_warn!(self.logger, "📋 VOTER: Failed to send NACK for AddCollateralPartner (no ledger): {:?}", e);
            }
        }

        Ok(())
    }

    /// Handle CollateralRemovePartner message
    pub(super) fn handle_collateral_remove_partner(
        &self,
        msg: &super::messages::CollateralRemovePartnerMsg,
        sender_node_id: PublicKey,
    ) -> Result<(), LightningError> {
        use deposits_core::quorum::LedgerId;
        use deposits_core::log_warn;

        log_info!(
            self.logger,
            "📋 VOTER: Received RemoveCollateralPartner from {} - removing {} from ledger with partner {}",
            sender_node_id,
            msg.collateral_partner,
            msg.partner_id
        );

        // Verify that the message is from the operator of a ledger we're the partner of
        let ledger_key = (sender_node_id, msg.partner_id);

        // We must be the partner_id to process this message
        if msg.partner_id != self.our_node_id {
            log_warn!(
                self.logger,
                "📋 VOTER: Rejecting RemoveCollateralPartner - we ({}) are not the target partner ({})",
                self.our_node_id,
                msg.partner_id
            );
            return Ok(());
        }

        // Append to hash chain with proper porcupine dance signing
        let mut ledgers = self.ledgers.lock().unwrap();
        if let Some(ledger_arc) = ledgers.get_mut(&ledger_key) {
            let mut ledger_guard = ledger_arc.write().unwrap();

            // Append to hash chain with proper porcupine dance signing
            let remove_partner_msg = DepositsMessage::CollateralRemovePartner {
                partner_id: msg.partner_id,
                collateral_partner: msg.collateral_partner,
                operator_signature: msg.operator_signature,
            };
            match ledger_guard.append_v1_mut_with_metadata(remove_partner_msg.clone()) {
                Ok((prev_hash, new_hash, seq)) => {
                    log_info!(
                        self.logger,
                        "📋 VOTER: Appended remove collateral partner {} to ledger ({}, {}), seq={}, hash={:02x?}",
                        msg.collateral_partner,
                        sender_node_id,
                        msg.partner_id,
                        seq,
                        &new_hash[0..8]
                    );

                    // Get message bytes for signing
                    let message_bytes = ledger_guard.history.last()
                        .map(|u| u.message.clone())
                        .unwrap_or_default();

                    let timestamp = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();

                    // Partner signs content (porcupine dance)
                    let partner_sig = match self.sign_as_partner(
                        &message_bytes,
                        remove_partner_msg.message_type(),
                        seq,
                        &prev_hash,
                        &new_hash,
                        timestamp,
                    ) {
                        Ok(sig) => Some(sig),
                        Err(e) => {
                            log_warn!(self.logger, "📋 VOTER: Failed to sign RemoveCollateralPartner: {:?}", e);
                            None
                        }
                    };

                    // Save updated ledger state (must do before dropping guard)
                    if let Err(e) = self.persist_ledger_state(&*ledger_guard) {
                        log_warn!(
                            self.logger,
                            "📋 VOTER: Failed to persist ledger after removing collateral partner: {:?}",
                            e
                        );
                    }

                    drop(ledger_guard);
                    drop(ledgers);

                    // Sync with QuorumManager - remove collateral partner from quorum membership
                    let ledger_id = LedgerId::new(sender_node_id, msg.partner_id);
                    if let Err(e) = self.quorum_manager.remove_member(&ledger_id, &msg.collateral_partner) {
                        log_warn!(
                            self.logger,
                            "📋 VOTER: Failed to remove collateral partner {} from quorum: {:?}",
                            msg.collateral_partner,
                            e
                        );
                    } else {
                        log_info!(
                            self.logger,
                            "📋 VOTER: Removed collateral partner {} from quorum for ledger ({}, {})",
                            msg.collateral_partner,
                            sender_node_id,
                            msg.partner_id
                        );
                    }

                    // Send ACK with porcupine dance signature
                    let message_hash = Self::create_message_hash(&remove_partner_msg);
                    let ack = DepositsMessage::Ack(super::messages::AckMsg {
                        acked_message_type: remove_partner_msg.message_type(),
                        message_hash,
                        success: true,
                        error_message: None,
                        cosignature: None,
                        update_signature: partner_sig,
                        update_sequence: Some(seq),
                        update_prev_hash: Some(prev_hash),
                        update_curr_hash: Some(new_hash),
                        // V2 required fields
                        partner_signature: partner_sig,
                        confirmed_sequence: seq,
                        confirmed_hash: new_hash,
                    });

                    {
                        let mut outbound_messages = self.outbound_messages.lock().unwrap();
                        outbound_messages.entry(sender_node_id).or_insert_with(Vec::new).push(ack.clone());
                    }
                    self.trigger_immediate_send(sender_node_id, ack.message_type());
                    log_info!(self.logger, "📋 VOTER: Sent ACK with porcupine signature for RemoveCollateralPartner");
                }
                Err(e) => {
                    log_warn!(
                        self.logger,
                        "📋 VOTER: Failed to remove collateral partner {}: {:?}",
                        msg.collateral_partner,
                        e
                    );

                    // Send NACK back to operator using helper
                    drop(ledger_guard);
                    drop(ledgers);

                    if let Err(ack_err) = self.send_acknowledgment(&remove_partner_msg, false, Some(format!("{:?}", e)), None, sender_node_id) {
                        log_warn!(self.logger, "📋 VOTER: Failed to send NACK for RemoveCollateralPartner: {:?}", ack_err);
                    }
                }
            }
        } else {
            log_warn!(
                self.logger,
                "📋 VOTER: No ledger found for operator {} partner {} to remove collateral partner",
                sender_node_id,
                msg.partner_id
            );

            // Send NACK so operator knows the ledger wasn't found
            let remove_partner_msg = DepositsMessage::CollateralRemovePartner {
                partner_id: msg.partner_id,
                collateral_partner: msg.collateral_partner,
                operator_signature: msg.operator_signature,
            };
            if let Err(e) = self.send_acknowledgment(
                &remove_partner_msg,
                false,
                Some(format!("No ledger found for operator {} partner {}", sender_node_id, msg.partner_id)),
                None,
                sender_node_id
            ) {
                log_warn!(self.logger, "📋 VOTER: Failed to send NACK for RemoveCollateralPartner (no ledger): {:?}", e);
            }
        }

        Ok(())
    }

    /// Handle CollateralConsentRequest message
    pub(super) fn handle_collateral_consent_request(
        &self,
        msg: &super::messages::CollateralConsentRequestMsg,
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

        let response = DepositsMessage::CollateralConsentResponse {
            operator_id: msg.operator_id,
            partner_id: msg.partner_id,
            consent_granted,
            collateral_partner_signature: signature,
        };

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

            let sync_request = DepositsMessage::SyncRequest(super::messages::SyncRequestMsg {
                operator_id: msg.operator_id,
                partner_id: msg.partner_id,
                last_known_sequence: 0, // Start from beginning since we're new to this ledger
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
        msg: &super::messages::CollateralConsentResponseMsg,
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
        // Calculate the hash of the original request for lookup
        let original_request = DepositsMessage::CollateralConsentRequest {
            operator_id: msg.operator_id,
            partner_id: msg.partner_id,
            operator_signature: [0u8; 64], // This should match what we sent
        };
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
                &DepositsMessage::CollateralConsentResponse {
                    operator_id: msg.operator_id,
                    partner_id: msg.partner_id,
                    consent_granted: msg.consent_granted,
                    collateral_partner_signature: msg.collateral_partner_signature,
                },
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
            for ((operator_id, partner_id), ledger_arc) in ledgers.iter() {
                // Only process ledgers where we're the operator
                if *operator_id == self.our_node_id {
                    let ledger = ledger_arc.read().unwrap();
                    if ledger.state.collateral_partners.contains(&sender_node_id) {
                        // Store attestation as proof
                        drop(ledger);
                        let mut ledger = ledger_arc.write().unwrap();
                        // Convert V1 message type to core attestation type
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
                            "💰 COLLATERAL: Stored attestation from {} on ledger ({}, {})",
                            sender_node_id,
                            operator_id,
                            partner_id
                        );

                        // If the sender is NOT the channel partner, this is a collateral partner
                        // We should forward CollateralAttestation to our CHANNEL ledgers (where sender != partner)
                        if *partner_id != sender_node_id {
                            channel_ledgers_to_update.push((*operator_id, *partner_id));
                        }
                    }
                }
            }
        }

        // Forward CollateralAttestation to channel partners for bilateral signing
        // (Previously created a separate CollateralStatus, now we forward the full attestation)
        if !channel_ledgers_to_update.is_empty() {
            let attestation_forward = DepositsMessage::CollateralAttestation {
                operator: msg.operator,
                collateral_partner: msg.collateral_partner,
                amount: msg.amount,
                block_height: msg.block_height,
                signature: msg.signature,
                ledger_hash: msg.ledger_hash,
            };

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
                                pending_acks.insert(unique_key, (attestation_forward.message_type(), timestamp));
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

        // Simple ACK for the attestation itself
        let attestation_msg = DepositsMessage::CollateralAttestation {
            operator: msg.operator,
            collateral_partner: msg.collateral_partner,
            amount: msg.amount,
            block_height: msg.block_height,
            signature: msg.signature,
            ledger_hash: msg.ledger_hash,
        };
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
        msg: &super::messages::UncreditedPaymentMsg,
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
                let accusation_msg = DepositsMessage::UncreditedPayment {
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
                };
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
        tombstone_msg: &super::messages::ChannelCloseTombstoneMsg,
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
        let we_are_operator = tombstone_msg.operator_pubkey == self.our_node_id;
        let we_are_partner = tombstone_msg.partner_pubkey == self.our_node_id;

        if !we_are_operator && !we_are_partner {
            log_warn!(
                self.logger,
                "₿ Received tombstone for ledger we're not part of: operator={}, partner={}",
                tombstone_msg.operator_pubkey,
                tombstone_msg.partner_pubkey
            );
            return Ok(());
        }

        let ledger_key = (tombstone_msg.operator_pubkey, tombstone_msg.partner_pubkey);

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
                    tombstone_msg.operator_pubkey
                );
                Arc::new(RwLock::new(Ledger::new(
                    tombstone_msg.operator_pubkey,
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
                operator_pubkey: tombstone_msg.operator_pubkey,
                partner_pubkey: tombstone_msg.partner_pubkey,
                sequence_number: tombstone_msg.sequence_number,
                previous_state_hash: [0u8; 32], // Unknown from raw message
                current_state_hash: [0u8; 32],  // Unknown from raw message
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

        // Only handle if we're the partner (operator_pubkey is sender, partner_pubkey is us)
        if signed_msg.partner_pubkey != self.our_node_id || signed_msg.operator_pubkey != sender_node_id {
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
            operator_pubkey: signed_msg.operator_pubkey,
            partner_pubkey: signed_msg.partner_pubkey,
            sequence_number: signed_msg.sequence_number,
            previous_state_hash: signed_msg.previous_state_hash,
            current_state_hash: signed_msg.current_state_hash,
            timestamp: signed_msg.timestamp,
        };

        // Store in partner ledger using unified Ledger type
        let mut ledgers = self.ledgers.lock().unwrap();
        let key = (signed_msg.operator_pubkey, self.our_node_id);

        // Get or create the partner ledger
        let ledger = ledgers.entry(key).or_insert_with(|| {
            // Create new Ledger for this partner relationship
            log_info!(
                self.logger,
                "📋 PARTNER: Creating new partner ledger for operator {}",
                signed_msg.operator_pubkey
            );
            let new_ledger = Ledger::new(
                signed_msg.operator_pubkey,
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
        init_msg: &LedgerOpenRequestMsg,
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
                        let response = DepositsMessage::LedgerOpenResponse(LedgerOpenResponseMsg {
                            protocol_version: init_msg.protocol_version,
                            accepted: false,
                            error_reason: Some(format!("Invalid network: {}", e)),
                            public_key: self.our_node_id,
                            partner_id: sender_node_id,
                        });
                        let _ = self.send_message(sender_node_id, response);
                        return Ok(());
                    }
                },
                Err(e) => {
                    log_error!(self.logger, "Failed to parse ledger address: {}", e);
                    let response = DepositsMessage::LedgerOpenResponse(LedgerOpenResponseMsg {
                        protocol_version: init_msg.protocol_version,
                        accepted: false,
                        error_reason: Some(format!("Invalid address: {}", e)),
                        public_key: self.our_node_id,
                        partner_id: sender_node_id,
                    });
                    let _ = self.send_message(sender_node_id, response);
                    return Ok(());
                }
            };

            // Initialize the ledger as partner (sender is the operator) using the received message
            if let Err(e) = self.initialize_ledger_as_partner_with_message(sender_node_id, ledger_address, init_msg.clone()) {
                log_error!(self.logger, "Failed to initialize ledger as partner for operator {}: {}", sender_node_id, e);

                // Send rejection response
                let response = DepositsMessage::LedgerOpenResponse(LedgerOpenResponseMsg {
                    protocol_version: init_msg.protocol_version,
                    accepted: false,
                    error_reason: Some(format!("Failed to initialize ledger: {}", e)),
                    public_key: self.our_node_id,
                    partner_id: sender_node_id,
                });
                let _ = self.send_message(sender_node_id, response);
                return Ok(());
            }

            // Send acceptance response
            let response = DepositsMessage::LedgerOpenResponse(LedgerOpenResponseMsg {
                protocol_version: init_msg.protocol_version,
                accepted: true,
                error_reason: None,
                public_key: self.our_node_id,
                partner_id: sender_node_id,
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
            let response = DepositsMessage::LedgerOpenResponse(LedgerOpenResponseMsg {
                protocol_version: init_msg.protocol_version,
                accepted: false,
                error_reason: Some("Ledger already exists".to_string()),
                public_key: self.our_node_id,
                partner_id: sender_node_id,
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
        if let DepositsMessage::SyncRequest(ref request) = message {
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
                updates: response.updates.iter().map(|u| deposits_core::messages::SignedLedgerUpdate {
                    sequence_number: u.sequence_number,
                    operation: u.operation.clone(),
                    previous_hash: u.previous_state_hash,
                    current_hash: u.current_state_hash,
                    operator_signature: u.operator_signature,
                    partner_signature: u.partner_signature.unwrap_or([0u8; 64]),
                    timestamp: deposits_core::now_unix_timestamp(),
                }).collect(),
                current_sequence: response.updates.last().map(|u| u.sequence_number).unwrap_or(0),
                current_hash: response.updates.last().map(|u| u.current_state_hash).unwrap_or([0u8; 32]),
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
                    "[HANDLE_UPDATE_RESERVES] FOUND ledger! Updating commitment hash from {:02x?} to {:02x?}",
                    &ledger.state.channel_deepest_commitment_hash[0..8],
                    &ledger_hash[0..8]
                );
                ledger.state.channel_deepest_commitment_hash = *ledger_hash;
                log_info!(
                    self.logger,
                    "🔒 Updated partner copy channel_deepest_commitment_hash to {:02x?}",
                    &ledger_hash[0..8]
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

        // Send AcceptReserves response
        let accept_msg = DepositsMessage::AcceptReserves {
            channel_id: *channel_id,
        };

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
