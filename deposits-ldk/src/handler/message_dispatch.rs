// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Message dispatch for the Bitcoin Deposits protocol.
//!
//! This module contains the main process_message function that routes
//! incoming protocol messages to appropriate handlers.

use bitcoin::secp256k1::PublicKey;
use lightning::ln::msgs::{LightningError, ErrorAction};

use super::core::{DepositsHandler, CosignedInvoice};
use super::message_validation::MessageValidation;
use super::messages::DepositsMessage;
use super::ledger_ext::LedgerExt;
// use deposits_core::Invoice; // Currently unused
use deposits_core::{log_debug, log_error, log_info, log_warn};
use lightning::util::logger::Logger as LdkLogger;

use std::ops::Deref;

impl<L: Deref + Clone> DepositsHandler<L>
where
    L::Target: LdkLogger,
{
    /// Process a protocol message and generate appropriate events
    pub(super) fn process_message(
        &self,
        message: DepositsMessage,
        sender_node_id: PublicKey,
    ) -> Result<(), LightningError> {
        log_debug!(
            self.logger,
            "Received Bitcoin Deposits message type {:#06x} from peer {}",
            message.message_type(),
            sender_node_id
        );

        // Debug: trace all incoming messages
        println!("[RECV] type={:#06x} name={} from={}",
            message.message_type(),
            message.descriptive_name(),
            sender_node_id
        );

        // Deferred oneshot notification for CollateralAttestation
        // We need to notify the waiter AFTER handle_collateral_attestation completes,
        // so that CollateralAttestation is in pending_acks before the waiter continues.
        // This fixes a race condition where the waiter would check pending_acks before
        // CollateralAttestation was added.
        let mut deferred_collateral_oneshot: Option<tokio::sync::oneshot::Sender<Result<(), String>>> = None;

        // Handle ACK messages specially - they don't need validation or further ACKs
        // Both Ack (V1) and LedgerUpdateResponse (V2) are ACK messages
        let ack_msg = match &message {
            DepositsMessage::Ack(msg) => Some(msg.clone()),
            DepositsMessage::LedgerUpdateResponse(msg) => Some(msg.clone()),
            _ => None,
        };
        if let Some(ack_msg) = ack_msg {
            if let Err(e) = self.handle_received_ack(ack_msg, sender_node_id) {
                log_error!(
                    self.logger,
                    "Failed to handle ACK message from {}: {}",
                    sender_node_id,
                    e
                );
            }
            return Ok(()); // ACK messages don't need further processing
        }

        // Handle CollateralAttestation as ACK when received from channel partner
        // Partner sends attestation instead of regular ACK for CollateralIncrease/CollateralDecrease
        if let DepositsMessage::CollateralAttestation { operator, collateral_partner, amount, block_height, signature, ledger_hash } = &message {
            // Check if we're the operator for a ledger with this sender as partner
            // and have a pending CollateralIncrease/CollateralDecrease
            let is_from_channel_partner = {
                let ledgers = self.ledgers.lock().unwrap();
                ledgers.contains_key(&(self.our_node_id, sender_node_id))
            };

            if is_from_channel_partner && *operator == self.our_node_id {
                log_info!(
                    self.logger,
                    "💰 OPERATOR: Received CollateralAttestation from channel partner {} - amount={}",
                    sender_node_id,
                    amount
                );

                // Find and complete any pending collateral message to this partner
                let pending_collateral_hash = {
                    let pending_acks = self.pending_acks.lock().unwrap();
                    // Look for pending collateral messages - both V1 format (COLLATERAL_INCREASE/COLLATERAL_DECREASE)
                    // and V2 format (LEDGER_UPDATE which wraps CollateralIncrease/CollateralDecrease operations)
                    pending_acks.iter()
                        .find(|(_, (msg_type, _))| {
                            *msg_type == super::messages::consts::COLLATERAL_INCREASE ||
                            *msg_type == super::messages::consts::COLLATERAL_DECREASE ||
                            *msg_type == super::messages::consts::LEDGER_UPDATE
                        })
                        .map(|(hash, _)| *hash)
                };

                if let Some(hash) = pending_collateral_hash {
                    // Remove from pending ACKs
                    {
                        let mut pending_acks = self.pending_acks.lock().unwrap();
                        pending_acks.remove(&hash);
                    }

                    // Construct the legacy struct for storage
                    let attestation_msg = crate::wire::messages::CollateralAttestationMsg {
                        operator: *operator,
                        collateral_partner: *collateral_partner,
                        amount: *amount,
                        block_height: *block_height,
                        signature: *signature,
                        ledger_hash: *ledger_hash,
                    };

                    // Store the attestation in the ledger BEFORE notifying the oneshot
                    // This ensures the attestation (with ledger_hash) is available when
                    // increase_collateral_on_ledger resumes and needs to verify the hash
                    {
                        let ledgers = self.ledgers.lock().unwrap();
                        if let Some(ledger_arc) = ledgers.get(&(self.our_node_id, sender_node_id)) {
                            let mut ledger = ledger_arc.write().unwrap();
                            // Convert V1 message type to core attestation type
                            let attestation = deposits_core::types::CollateralAttestation::new(
                                attestation_msg.operator,
                                attestation_msg.collateral_partner,
                                attestation_msg.amount,
                                attestation_msg.block_height,
                                attestation_msg.signature,
                                attestation_msg.ledger_hash,
                            );
                            ledger.state.collateral_attestations.insert(sender_node_id, attestation);
                            log_info!(
                                self.logger,
                                "💰 OPERATOR: Stored attestation from channel partner {} in ledger (hash={:02x?})",
                                sender_node_id,
                                &attestation_msg.ledger_hash[0..8]
                            );
                        }
                    }

                    // DEFER oneshot notification until AFTER handle_collateral_attestation completes
                    // This ensures CollateralAttestation is in pending_acks before the waiter continues
                    deferred_collateral_oneshot = {
                        let mut pending_oneshot_acks = self.pending_oneshot_acks.lock().unwrap();
                        pending_oneshot_acks.remove(&hash)
                    };

                    log_info!(
                        self.logger,
                        "💰 OPERATOR: CollateralAttestation treated as ACK for pending collateral message"
                    );
                }

                // Continue to process the attestation normally (for broadcasting, etc.)
            }
        }

        // Handle quorum messages - infrastructure-level peer coordination
        match &message {
            DepositsMessage::QuorumJoinRequest { requester_pubkey, operator_id, partner_id, protocol_version, timestamp, signature } => {
                // Delegate to extracted handler in message_handlers.rs
                let msg = crate::wire::messages::QuorumJoinRequestMsg {
                    requester_pubkey: *requester_pubkey,
                    operator_id: *operator_id,
                    partner_id: *partner_id,
                    protocol_version: *protocol_version,
                    timestamp: *timestamp,
                    signature: *signature,
                };
                return self.handle_quorum_join_request(&msg, sender_node_id);
            }

            DepositsMessage::QuorumJoinResponse { accepted, ref members, threshold, last_sequence, current_state_hash, ref rejection_reason } => {
                // Delegate to extracted handler in message_handlers.rs
                let msg = super::messages::QuorumJoinResponseMsg {
                    accepted: *accepted,
                    members: members.clone(),
                    threshold: *threshold,
                    last_sequence: *last_sequence,
                    current_state_hash: *current_state_hash,
                    rejection_reason: rejection_reason.clone(),
                };
                return self.handle_quorum_join_response(&msg, sender_node_id);
            }

            DepositsMessage::QuorumStateSync { operator_id, partner_id, ref updates, start_sequence, is_final } => {
                // Delegate to extracted handler in message_handlers.rs
                let msg = super::messages::QuorumStateSyncMsg {
                    operator_id: *operator_id,
                    partner_id: *partner_id,
                    updates: updates.clone(),
                    start_sequence: *start_sequence,
                    is_final: *is_final,
                };
                return self.handle_quorum_state_sync(&msg, sender_node_id);
            }

            DepositsMessage::QuorumVoteRequest { operator_id, partner_id, vote_round_id, sequence_number, state_hash, claimed_reserves, ref collateral_amounts, ref reserves_outpoint, ref destination_script, fee_rate_sat_vbyte } => {
                // Delegate to extracted handler in message_handlers.rs
                let msg = super::messages::QuorumVoteRequestMsg {
                    operator_id: *operator_id,
                    partner_id: *partner_id,
                    vote_round_id: *vote_round_id,
                    sequence_number: *sequence_number,
                    state_hash: *state_hash,
                    claimed_reserves: *claimed_reserves,
                    collateral_amounts: collateral_amounts.clone(),
                    reserves_outpoint: reserves_outpoint.clone(),
                    destination_script: destination_script.clone(),
                    fee_rate_sat_vbyte: *fee_rate_sat_vbyte,
                };
                return self.handle_quorum_vote_request(&msg, sender_node_id);
            }

            DepositsMessage::QuorumVote { vote_round_id, voter_pubkey, vote, voter_sequence, voter_state_hash, ref evidence, signature, spend_signature } => {
                // Delegate to extracted handler in message_handlers.rs
                let msg = super::messages::QuorumVoteMsg {
                    vote_round_id: *vote_round_id,
                    voter_pubkey: *voter_pubkey,
                    vote: *vote,
                    voter_sequence: *voter_sequence,
                    voter_state_hash: *voter_state_hash,
                    evidence: evidence.clone(),
                    signature: *signature,
                    spend_signature: *spend_signature,
                };
                return self.handle_quorum_vote(&msg, sender_node_id);
            }

            DepositsMessage::QuorumMembershipChange { operator_id, partner_id, ref change_type, member_pubkey, ref new_members } => {
                // Delegate to extracted handler in message_handlers.rs
                let msg = super::messages::QuorumMembershipChangeMsg {
                    operator_id: *operator_id,
                    partner_id: *partner_id,
                    change_type: change_type.clone(),
                    member_pubkey: *member_pubkey,
                    new_members: new_members.clone(),
                };
                return self.handle_quorum_membership_change(&msg, sender_node_id);
            }

            // Recovery Messages (0x808F-0x8095)
            DepositsMessage::RecoveryVote { operator, partner, voter, is_conforming, validated_hash, validated_sequence, substitute_nomination, discovered_violation, signature } => {
                // Delegate to extracted handler in message_handlers.rs
                let msg = super::messages::RecoveryVoteMsg {
                    operator: *operator,
                    partner: *partner,
                    voter: *voter,
                    is_conforming: *is_conforming,
                    validated_hash: *validated_hash,
                    validated_sequence: *validated_sequence,
                    substitute_nomination: *substitute_nomination,
                    discovered_violation: *discovered_violation,
                    signature: *signature,
                };
                return self.handle_recovery_vote(&msg, sender_node_id);
            }

            DepositsMessage::RecoveryClaimRequest { operator, partner, claimant, tier_index, ref unsigned_tx, sighash, ref destination_script, block_height } => {
                // Delegate to extracted handler in message_handlers.rs
                let msg = super::messages::RecoveryClaimRequestMsg {
                    operator: *operator,
                    partner: *partner,
                    claimant: *claimant,
                    tier_index: *tier_index,
                    unsigned_tx: unsigned_tx.clone(),
                    sighash: *sighash,
                    destination_script: destination_script.clone(),
                    block_height: *block_height,
                };
                return self.handle_recovery_claim_request(&msg, sender_node_id);
            }

            DepositsMessage::RecoveryClaimSignature { operator, partner, signer, sighash, signature } => {
                // Delegate to extracted handler in message_handlers.rs
                let msg = super::messages::RecoveryClaimSignatureMsg {
                    operator: *operator,
                    partner: *partner,
                    signer: *signer,
                    sighash: *sighash,
                    signature: *signature,
                };
                return self.handle_recovery_claim_signature(&msg, sender_node_id);
            }

            DepositsMessage::RecoveryClaimComplete { operator, partner, new_operator, claim_txid, confirmation_block, reason_code } => {
                // Delegate to extracted handler in message_handlers.rs
                let msg = super::messages::RecoveryClaimCompleteMsg {
                    operator: *operator,
                    partner: *partner,
                    new_operator: *new_operator,
                    claim_txid: *claim_txid,
                    confirmation_block: *confirmation_block,
                    reason_code: *reason_code,
                };
                return self.handle_recovery_claim_complete(&msg, sender_node_id);
            }

            // Voter Registration Messages (0x8097)
            DepositsMessage::CollateralAddPartner { operator_id, partner_id, collateral_partner, collateral_partner_signature } => {
                // Delegate to extracted handler in message_handlers.rs
                let msg = super::messages::CollateralAddPartnerMsg {
                    operator_id: *operator_id,
                    partner_id: *partner_id,
                    collateral_partner: *collateral_partner,
                    collateral_partner_signature: *collateral_partner_signature,
                };
                return self.handle_collateral_add_partner(&msg, sender_node_id);
            }

            // Voter Registration Messages (0x8099) - Remove collateral partner
            DepositsMessage::CollateralRemovePartner { partner_id, collateral_partner, operator_signature } => {
                // Delegate to extracted handler in message_handlers.rs
                let msg = super::messages::CollateralRemovePartnerMsg {
                    partner_id: *partner_id,
                    collateral_partner: *collateral_partner,
                    operator_signature: *operator_signature,
                };
                return self.handle_collateral_remove_partner(&msg, sender_node_id);
            }

            // Collateral Consent Request (0x809B) - Operator asking us to be a collateral partner
            DepositsMessage::CollateralConsentRequest { operator_id, partner_id, operator_signature } => {
                // Delegate to extracted handler in message_handlers.rs
                let msg = super::messages::CollateralConsentRequestMsg {
                    operator_id: *operator_id,
                    partner_id: *partner_id,
                    operator_signature: *operator_signature,
                };
                return self.handle_collateral_consent_request(&msg, sender_node_id);
            }

            // Collateral Consent Response (0x809D) - Response from potential collateral partner
            DepositsMessage::CollateralConsentResponse { operator_id, partner_id, consent_granted, collateral_partner_signature } => {
                // Delegate to extracted handler in message_handlers.rs
                let msg = super::messages::CollateralConsentResponseMsg {
                    operator_id: *operator_id,
                    partner_id: *partner_id,
                    consent_granted: *consent_granted,
                    collateral_partner_signature: *collateral_partner_signature,
                };
                return self.handle_collateral_consent_response(&msg, sender_node_id);
            }

            // Collateral Attestation Messages (0x808D)
            DepositsMessage::CollateralAttestation { operator, collateral_partner, amount, block_height, signature, ledger_hash } => {
                // Delegate to extracted handler in message_handlers.rs
                let msg = crate::wire::messages::CollateralAttestationMsg {
                    operator: *operator,
                    collateral_partner: *collateral_partner,
                    amount: *amount,
                    block_height: *block_height,
                    signature: *signature,
                    ledger_hash: *ledger_hash,
                };
                // Call handler FIRST to add CollateralAttestation to pending_acks
                let result = self.handle_collateral_attestation(&msg, sender_node_id);

                // NOW send the deferred oneshot notification
                // This ensures CollateralAttestation is in pending_acks before the waiter continues
                if let Some(oneshot_tx) = deferred_collateral_oneshot.take() {
                    log_info!(self.logger, "💰 OPERATOR: Sending deferred oneshot after handle_collateral_attestation");
                    let _ = oneshot_tx.send(Ok(()));
                }

                return result;
            }

            // Uncredited Payment Accusation (0x8035) - Partner broadcasting proof of unpaid settlement
            DepositsMessage::UncreditedPayment { operator, partner, payment_hash, preimage, deposit_pubkey, amount_msat, invoice_cosignature, settlement_sequence, settlement_ledger_hash, settlement_block_height, accuser_signature } => {
                // Delegate to extracted handler in message_handlers.rs
                let msg = super::messages::UncreditedPaymentMsg {
                    operator: *operator,
                    partner: *partner,
                    payment_hash: *payment_hash,
                    preimage: *preimage,
                    deposit_pubkey: *deposit_pubkey,
                    amount_msat: *amount_msat,
                    invoice_cosignature: *invoice_cosignature,
                    settlement_sequence: *settlement_sequence,
                    settlement_ledger_hash: *settlement_ledger_hash,
                    settlement_block_height: *settlement_block_height,
                    accuser_signature: *accuser_signature,
                };
                return self.handle_uncredited_payment(&msg, sender_node_id);
            }

            // UpdateReserves custom message (0x80E1) - Reserves commitment protocol
            // Counterparty is proposing extra outputs for the commitment transaction
            DepositsMessage::UpdateReserves { ref channel_id, reserves_sats, ref script_pubkey, ref ledger_hash, ref remote_ledger_hash } => {
                return self.handle_update_reserves(
                    channel_id,
                    *reserves_sats,
                    script_pubkey,
                    ledger_hash,
                    remote_ledger_hash,
                    sender_node_id,
                );
            }

            // AcceptReserves custom message (0x80E3) - Reserves commitment protocol
            // Counterparty has accepted our proposed extra outputs
            DepositsMessage::AcceptReserves { ref channel_id } => {
                return self.handle_accept_reserves(channel_id, sender_node_id);
            }

            _ => {} // Not a quorum/recovery/voter/collateral/accusation message, continue processing
        }

        // Handle ChannelCloseTombstone messages specially - append to ledger and mark as closed
        if let DepositsMessage::ChannelCloseTombstone { ref operator_pubkey, ref partner_pubkey, timestamp, ref channel_id, ref close_reason, sequence_number } = message {
            // Delegate to extracted handler in message_handlers.rs
            let tombstone_msg = super::messages::ChannelCloseTombstoneMsg {
                operator_pubkey: *operator_pubkey,
                partner_pubkey: *partner_pubkey,
                timestamp,
                channel_id: *channel_id,
                close_reason: close_reason.clone(),
                sequence_number,
            };
            return self.handle_channel_close_tombstone(&tombstone_msg, &message, sender_node_id);
        }

        // Check if this is a third-party audit message (we are neither operator nor partner)
        // Delegate to extracted handler in message_handlers.rs
        if self.handle_third_party_audit(&message, sender_node_id)? {
            return Ok(());
        }

        // Handle SignedAuditUpdate specially when we're the PARTNER
        // The partner should receive authoritative updates from operator and store in ledgers
        // NOT process through apply_state_only() which is for ledger update messages
        if let DepositsMessage::SignedUpdate(ref signed_msg) = message {
            // Delegate to extracted handler in message_handlers.rs
            if self.handle_signed_update_as_partner(signed_msg, sender_node_id)? {
                return Ok(());
            }
        }

        // For non-ACK messages from direct partners, validate and send acknowledgment
        let validation_result = self.validate_message(&message, sender_node_id);

        match validation_result {
            Ok(()) => {
                log_debug!(
                    self.logger,
                    "Message validation passed for type {:#06x} from {}",
                    message.message_type(),
                    sender_node_id
                );

                // Skip early ACK for messages that need special responses
                // Uses to_operation() to handle both V1 and V2 formats uniformly
                use deposits_core::messages::LedgerOperation;
                let is_collateral_op = message.to_operation().map_or(false, |op|
                    matches!(op, LedgerOperation::CollateralIncrease { .. } | LedgerOperation::CollateralDecrease { .. })
                );
                let needs_special_response = matches!(message, DepositsMessage::ReceivingCosignInvoice { .. })
                    || is_collateral_op;

                if !needs_special_response {
                    // IMPORTANT: Don't send simple ACK for messages that will get porcupine ACK later
                    // Ledger-modifying messages get their ACK after append_mut_with_metadata
                    // Uses is_ledger_operation() which handles both V1 variants and V2 LedgerUpdate
                    let will_get_porcupine_ack = message.is_ledger_operation();

                    if !will_get_porcupine_ack {
                        // Send success acknowledgment for non-ledger messages
                        if let Err(e) = self.send_acknowledgment(&message, true, None, None, sender_node_id) {
                            log_error!(
                                self.logger,
                                "Failed to send success acknowledgment to {}: {}",
                                sender_node_id,
                                e
                            );
                        }
                    }
                    // Ledger-modifying messages get their ACK after append_mut_with_metadata
                }
            }
            Err(error_msg) => {
                log_info!(
                    self.logger,
                    "Message validation failed for type {:#06x} from {}: {}",
                    message.message_type(),
                    sender_node_id,
                    error_msg
                );

                // Send failure acknowledgment
                if let Err(e) = self.send_acknowledgment(&message, false, Some(error_msg.clone()), None, sender_node_id) {
                    log_error!(
                        self.logger,
                        "Failed to send failure acknowledgment to {}: {}",
                        sender_node_id,
                        e
                    );
                }

                // Return error to prevent further processing of invalid message
                return Err(LightningError {
                    err: format!("Message validation failed: {}", error_msg),
                    action: ErrorAction::IgnoreError,
                });
            }
        }

        // HANDSHAKE: Handle ledger creation handshake messages
        // Match both V2 Handshake and V1 alias LedgerOpenRequest
        match &message {
            DepositsMessage::LedgerOpenRequest(init_msg) | DepositsMessage::Handshake(init_msg) => {
                println!("🟢 HANDSHAKE: Received Handshake/LedgerOpenRequest from {} (version {}, partner_id: {})",
                    sender_node_id, init_msg.protocol_version, init_msg.partner_id);
                // Delegate to extracted handler in message_handlers.rs
                return self.handle_ledger_open_request(init_msg, &message, sender_node_id);
            }
            _ => {}
        }

        // HANDSHAKE RESPONSE: Treat HandshakeResponse as ACK for pending Handshake
        // Match both V2 HandshakeResponse and V1 alias LedgerOpenResponse
        match &message {
            DepositsMessage::LedgerOpenResponse(resp_msg) | DepositsMessage::HandshakeResponse(resp_msg) => {
                log_info!(self.logger, "📨 Received HandshakeResponse from {} (accepted={})", sender_node_id, resp_msg.accepted);

                // Find and remove any pending ACK for HANDSHAKE type from this sender
                // We don't have the exact message hash, but we can match by type and peer
                let pending_ack_info = {
                    let mut pending_acks = self.pending_acks.lock().unwrap();
                    // Find any pending ACK with HANDSHAKE type (0x8005)
                    let mut found_hash = None;
                    for (hash, (msg_type, _timestamp)) in pending_acks.iter() {
                        // HANDSHAKE type is 0x8005 = 32773
                        if *msg_type == 0x8005 {
                            found_hash = Some(*hash);
                            break;
                        }
                    }
                    if let Some(hash) = found_hash {
                        println!("🟢 HANDSHAKE_RESPONSE: Clearing pending ACK for hash {:02x?}", &hash[0..4]);
                        pending_acks.remove(&hash);
                        Some(hash)
                    } else {
                        None
                    }
                };

                // Notify waiting oneshot channels
                if let Some(hash) = pending_ack_info {
                    let mut pending_oneshot_acks = self.pending_oneshot_acks.lock().unwrap();
                    if let Some(oneshot_tx) = pending_oneshot_acks.remove(&hash) {
                        let result = if resp_msg.accepted {
                            Ok(())
                        } else {
                            Err(resp_msg.error_reason.clone().unwrap_or_else(|| "Handshake rejected".to_string()))
                        };
                        let _ = oneshot_tx.send(result);
                        log_info!(self.logger, "🟢 Notified handshake waiting task (accepted={})", resp_msg.accepted);
                    }
                }

                // If accepted, initialize the ledger on our side as operator
                if resp_msg.accepted {
                    // The ledger should already be created when we sent the Handshake
                    // Just log success
                    log_info!(self.logger, "✅ Ledger handshake accepted by partner {}", sender_node_id);
                } else {
                    log_warn!(self.logger, "❌ Ledger handshake rejected by partner {}: {:?}",
                        sender_node_id, resp_msg.error_reason);
                }

                return Ok(());
            }
            _ => {}
        }

        // PHASE 3: Process message through new ChannelLedger architecture (parallel processing)
        // Note: For cosigning messages, we need to process first to get the signature,
        // then send ACK with the signature included

        // Skip automatic ACK sending for ledger open messages and ACK messages themselves
        // - Ledger open messages have their own response semantics
        // - ACK messages should never be ACKed (would create infinite loop)
        let should_skip_auto_ack = matches!(message,
            DepositsMessage::LedgerOpenRequest(_) |
            DepositsMessage::LedgerOpenResponse(_) |
            DepositsMessage::Handshake(_) |
            DepositsMessage::HandshakeResponse(_) |
            DepositsMessage::Ack(_) |
            DepositsMessage::LedgerUpdateResponse(_)
        );

        if should_skip_auto_ack {
            log_debug!(self.logger, "Skipping automatic ACK for message type {:#06x}", message.message_type());
            return Ok(());
        }

        let mut should_persist = false;
        let mut ledger_not_found = false;
        // Collect messages to send AFTER releasing locks to avoid deadlock
        // (send_message() acquires ledgers lock internally)
        let mut pending_messages: Vec<(PublicKey, DepositsMessage)> = Vec::new();

        {
            let ledgers = self.ledgers.lock().unwrap();
            // For received messages, sender is typically the operator, we are the partner
            // So ledger key is (sender=operator, us=partner)
            if let Some(ledger_arc) = ledgers.get(&(sender_node_id, self.our_node_id)) {
                let mut ledger = ledger_arc.write().unwrap();

                // Partner uses declared reserves from ledger state (from most recent ReservesUpdated message)

                log_info!(self.logger, "🟢 PARTNER: Processing message type {} from {} (operator), current history length: {}",
                         message.message_type(), sender_node_id, ledger.history.len());

                // Debug V2 LedgerUpdate processing
                if let DepositsMessage::LedgerUpdate(ref update_msg) = message {
                    println!("[PARTNER] V2 LedgerUpdate op={:?}", update_msg.operation);
                }

                // Check if this is a coordination message that doesn't modify ledger state
                let is_coordination_message = matches!(message, DepositsMessage::ReceivingCosignInvoice { .. });

                // Check if this is a collateral commitment message that needs attestation response
                // Uses to_operation() to handle both V1 format and V2 LedgerUpdate format uniformly
                let is_collateral_message = message.to_operation().map_or(false, |op|
                    matches!(op,
                        deposits_core::messages::LedgerOperation::CollateralIncrease { .. }
                        | deposits_core::messages::LedgerOperation::CollateralDecrease { .. }
                    )
                );

                if is_collateral_message {
                    // Collateral messages modify ledger state AND respond with CollateralAttestation
                    log_info!(self.logger, "💰 PARTNER: Processing collateral commitment message type {} from operator",
                             message.message_type());

                    // Append to ledger first
                    match ledger.append_v1_mut_with_metadata(message.clone()) {
                        Ok((prev_hash, new_hash, seq)) => {
                            log_info!(
                                self.logger,
                                "✅ PARTNER: Appended collateral message to local chain, seq={}, hash={:02x?}",
                                seq,
                                &new_hash[0..8]
                            );

                            // PORCUPINE DANCE: Partner must sign collateral updates just like regular messages
                            // This is required for reserves validation to pass
                            let message_bytes = ledger.history.last()
                                .map(|u| u.message.clone())
                                .unwrap_or_default();

                            let timestamp = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs();

                            if let Ok(sig) = self.sign_as_partner(
                                &message_bytes,
                                message.message_type(),
                                seq,
                                &prev_hash,
                                &new_hash,
                                timestamp,
                            ) {
                                if let Some(last_update) = ledger.history.last_mut() {
                                    last_update.partner_signature = sig;
                                    println!("🔏 PARTNER: Stored porcupine signature for collateral message seq={}", seq);
                                }
                            }

                            // Get the new collateral amount from the ledger
                            let new_collateral_amount = ledger.state.collateral_amount;

                            // Get current block height from channel manager
                            let block_height = self.channel_manager.as_ref()
                                .map(|cm| cm.current_best_block_height())
                                .unwrap_or(0);

                            // Generate CollateralAttestation as the response
                            use crate::wire::messages::CollateralAttestationMsg;

                            // Sign the attestation
                            // Content: operator + amount + block_height
                            let mut sign_bytes = Vec::new();
                            sign_bytes.extend_from_slice(&sender_node_id.serialize());
                            sign_bytes.extend_from_slice(&new_collateral_amount.to_le_bytes());
                            sign_bytes.extend_from_slice(&block_height.to_le_bytes());

                            let signature = match self.sign_attestation_content(&sign_bytes) {
                                Ok(sig) => sig,
                                Err(e) => {
                                    log_error!(self.logger, "💰 PARTNER: Failed to sign attestation: {:?}", e);
                                    [0u8; 64]
                                }
                            };

                            let attestation = CollateralAttestationMsg {
                                operator: sender_node_id,
                                collateral_partner: self.our_node_id,
                                amount: new_collateral_amount,
                                block_height,
                                signature,
                                ledger_hash: new_hash, // Include hash so operator can verify sync
                            };

                            log_info!(
                                self.logger,
                                "💰 PARTNER: Generated CollateralAttestation for operator {} - amount={}, block={}, hash={:02x?}",
                                sender_node_id,
                                new_collateral_amount,
                                block_height,
                                &new_hash[0..8]
                            );

                            // Send attestation as the response (serves as ACK)
                            let attestation_msg = DepositsMessage::CollateralAttestation {
                                operator: attestation.operator,
                                collateral_partner: attestation.collateral_partner,
                                amount: attestation.amount,
                                block_height: attestation.block_height,
                                signature: attestation.signature,
                                ledger_hash: attestation.ledger_hash,
                            };
                            pending_messages.push((sender_node_id, attestation_msg.clone()));

                            // Also broadcast attestation to other partners/auditors
                            // They need to know the current collateral level
                            // NOTE: We're already holding the ledgers lock from the outer scope,
                            // so we use the existing `ledgers` variable instead of re-locking
                            for ((op_id, part_id), _) in ledgers.iter() {
                                // Broadcast to all partners except:
                                // - the operator we just responded to
                                // - ourselves (if we are the partner in another ledger)
                                if *part_id != sender_node_id && *op_id != sender_node_id && *part_id != self.our_node_id {
                                    pending_messages.push((*part_id, attestation_msg.clone()));
                                }
                            }

                            // NOTE: Partner does NOT forward CollateralAttestation entries here.
                            // Only the OPERATOR forwards CollateralAttestation to their channel ledgers
                            // after receiving it. The partner's role is to:
                            // 1. Append CollateralIncrease to the shared ledger
                            // 2. Send CollateralAttestation back as proof

                            // Mark that we should persist
                            should_persist = true;
                        }
                        Err(e) => {
                            log_error!(
                                self.logger,
                                "❌ PARTNER: Failed to append collateral message: {}",
                                e
                            );
                            // Send failure ACK
                            let error_message = format!("{}", e);
                            if let Err(ack_err) = self.send_acknowledgment(&message, false, Some(error_message), None, sender_node_id) {
                                log_error!(self.logger, "❌ PARTNER: Failed to send NACK: {}", ack_err);
                            }
                        }
                    }
                } else if is_coordination_message {
                    // Coordination messages don't modify ledger state - validate but don't append
                    log_info!(self.logger, "🔵 PARTNER: Processing coordination message type {} (no ledger update)",
                             message.message_type());

                    // Generate cosignature for ReceivingCosignInvoice
                    let cosignature = if let DepositsMessage::ReceivingCosignInvoice { amount, payment_hash, expires, assigned_deposit, ref invoice_id, ref bolt11 } = message {
                        println!("🔐 PARTNER: Generating cosignature for invoice (payment_hash: {:02x?})", &payment_hash[0..4]);
                        // Generate proper 64-byte Schnorr signature over invoice data
                        let mut sig_input = Vec::new();
                        sig_input.extend_from_slice(&payment_hash);
                        sig_input.extend_from_slice(&amount.to_le_bytes());
                        sig_input.extend_from_slice(&expires.to_le_bytes());
                        sig_input.extend_from_slice(&assigned_deposit.serialize());

                        let sig_bytes = match self.sign_attestation_content(&sig_input) {
                            Ok(sig) => sig.to_vec(),
                            Err(e) => {
                                log_error!(self.logger, "🔐 PARTNER: Failed to sign cosignature: {:?}", e);
                                return Ok(());
                            }
                        };
                        println!("✅ PARTNER: Generated cosignature: {} bytes", sig_bytes.len());

                        // Store cosigned invoice for fraud proof validation
                        // Key: (operator, payment_hash)
                        let cosigned_invoice = CosignedInvoice {
                            deposit_pubkey: assigned_deposit,
                            payment_hash,
                            amount,
                            expires,
                            cosignature: sig_bytes.clone(),
                        };
                        {
                            let mut invoices = self.cosigned_invoices.lock().unwrap();
                            let key = (sender_node_id, payment_hash);
                            invoices.insert(key, cosigned_invoice);
                            println!("📋 PARTNER: Stored cosigned invoice for fraud proof validation (operator: {}, payment_hash: {:02x?})",
                                     sender_node_id, &payment_hash[0..4]);
                        }

                        // Add invoice to partner's ledger (deposit.invoices)
                        if let Some(deposit) = ledger.state.deposits.get_mut(&assigned_deposit) {
                            // Create invoice directly as core type for storage
                            let invoice = deposits_core::Invoice {
                                id: invoice_id.clone(),
                                payment_hash,
                                amount,
                                expires,
                                assigned_deposit,
                                bolt11: bolt11.clone(),
                            };
                            deposit.invoices.push(invoice);
                            log_info!(self.logger, "📋 PARTNER: Added invoice to deposit {} (payment_hash: {:02x?})",
                                     assigned_deposit, &payment_hash[0..4]);
                        }

                        Some(sig_bytes)
                    } else {
                        None
                    };

                    // Send ACK with cosignature (no ledger update needed)
                    use super::messages::{DepositsMessage, AckMsg};
                    let message_hash = self.calculate_message_hash(&message);
                    // Convert Vec<u8> cosignature to [u8; 64] - now properly 64 bytes from Schnorr signature
                    let cosig_array: Option<[u8; 64]> = cosignature.as_ref().and_then(|v| {
                        if v.len() == 64 {
                            let mut arr = [0u8; 64];
                            arr.copy_from_slice(v);
                            Some(arr)
                        } else {
                            println!("⚠️ PARTNER: Unexpected cosignature length: {} bytes (expected 64)", v.len());
                            None
                        }
                    });
                    let ack = DepositsMessage::Ack(AckMsg {
                        acked_message_type: message.message_type(),
                        message_hash,
                        success: true,
                        error_message: None,
                        cosignature: cosig_array,
                        update_signature: None,
                        update_sequence: None,
                        update_prev_hash: None,
                        update_curr_hash: None,
                        // V2 required fields (no ledger update, so use defaults)
                        partner_signature: cosig_array,
                        confirmed_sequence: 0,
                        confirmed_hash: message_hash,
                    });

                    println!("📤 PARTNER: Queueing ACK with cosignature for coordination message type {}, hash: {:02x?}",
                             message.message_type(), &message_hash[0..4]);

                    // Defer sending until after lock is released to avoid deadlock
                    pending_messages.push((sender_node_id, ack));
                } else {
                    // Regular ledger update - append to partner's hash chain with porcupine signing
                    // NOTE: Partner's sequence numbers may diverge from operator's (due to CollateralAttestation
                    // entries on operator's chain that partner doesn't have). This is expected.
                    // The operator's SignedAuditUpdate uses operator's values, with partner's signature
                    // included as proof of partner participation.
                    match ledger.append_v1_mut_with_metadata(message.clone()) {
                        Ok((prev_hash, new_hash, seq)) => {
                            log_info!(
                                self.logger,
                                "✅ PARTNER: Appended message type {:#06x} to local chain, seq={}, hash={:02x?}",
                                message.message_type(),
                                seq,
                                &new_hash[0..8]
                            );

                            // All ledger updates (including ReservesToReserves) use porcupine dance
                            // Partner's signature on the message IS their attestation
                            {
                                // Porcupine dance: Partner signs update content with their local chain values
                                // Get message bytes for signing
                                let message_bytes = ledger.history.last()
                                    .map(|u| u.message.clone())
                                    .unwrap_or_default();

                                let timestamp = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs();

                                // Partner signs content (porcupine dance)
                                let partner_sig = match self.sign_as_partner(
                                    &message_bytes,
                                    message.message_type(),
                                    seq,
                                    &prev_hash,
                                    &new_hash,
                                    timestamp,
                                ) {
                                    Ok(sig) => {
                                        // CRITICAL: Update the ledger entry with our signature
                                        // This is needed for reserves validation when operator commits
                                        if let Some(last_update) = ledger.history.last_mut() {
                                            last_update.partner_signature = sig;
                                            println!("🔏 PARTNER: Stored porcupine signature in ledger entry seq={}", seq);
                                        }
                                        Some(sig)
                                    },
                                    Err(e) => {
                                        log_warn!(self.logger, "📋 PARTNER: Failed to sign update: {:?}", e);
                                        None
                                    }
                                };

                                // Send ACK with porcupine dance signature
                                use super::messages::AckMsg;
                                let message_hash = self.calculate_message_hash(&message);

                                let ack = DepositsMessage::Ack(AckMsg {
                                    acked_message_type: message.message_type(),
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

                                println!("📤 PARTNER: Queueing ACK with porcupine signature for message type {}, seq={}, hash={:02x?}",
                                         message.message_type(), seq, &new_hash[0..4]);

                                // Defer sending until after lock is released to avoid deadlock
                                pending_messages.push((sender_node_id, ack));
                            }

                            // Special handling for CollateralAttestation: update received_collateral_amount
                            // This allows partners to track collateral received from operators
                            if let DepositsMessage::CollateralAttestation { operator, amount, .. } = message {
                                ledger.state.received_collateral_amount = ledger.state.received_collateral_amount.saturating_add(amount);
                                log_info!(self.logger, "💰 PARTNER: Updated received_collateral_amount to {} (added {} from {})",
                                    ledger.state.received_collateral_amount, amount, operator);
                            }

                            // Mark that we should persist the ledger after releasing locks (only on success)
                            should_persist = true;
                        }
                        Err(e) => {
                            log_error!(
                                self.logger,
                                "❌ PARTNER: Ledger failed to append message type {} from {}: {}",
                                message.message_type(),
                                sender_node_id,
                                e
                            );

                            // Send NACK since append failed
                            let error_message = format!("{}", e);
                            if let Err(ack_err) = self.send_acknowledgment(&message, false, Some(error_message), None, sender_node_id) {
                                log_error!(
                                    self.logger,
                                    "❌ PARTNER: Failed to send NACK for failed append: {}",
                                    ack_err
                                );
                            }
                        }
                    }
                }
            } else {
                // No ledger found - this is an error
                // Ledgers must be explicitly initialized via /bitcoin-deposits/ledger/init before messages can be exchanged
                ledger_not_found = true;
                log_error!(
                    self.logger,
                    "❌ PARTNER: No ledger found for message type {} from {} (looking for ledger key ({}, {})). Ledger must be initialized first.",
                    message.message_type(),
                    sender_node_id,
                    sender_node_id,
                    self.our_node_id
                );
            }
        } // Locks released here

        // Send pending messages now that locks are released (prevents deadlock)
        for (peer_id, msg) in pending_messages {
            log_info!(self.logger, "📤 PARTNER: Sending deferred message type {} to {}", msg.message_type(), peer_id);
            if let Err(e) = self.send_message(peer_id, msg) {
                log_error!(self.logger, "Failed to send deferred message: {}", e);
            }
        }

        // Persist the updated ledger state after successful processing (outside of locks)
        if should_persist {
            let ledgers = self.ledgers.lock().unwrap();
            // Same ledger key as above: (sender=operator, us=partner)
            if let Some(ledger_arc) = ledgers.get(&(sender_node_id, self.our_node_id)) {
                let ledger = ledger_arc.read().unwrap();
                if let Err(e) = self.persist_ledger_state(&*ledger) {
                    log_error!(self.logger, "Failed to persist ledger state after processing message: {}", e);
                }
            }
            // NOTE: Partners do NOT call refresh_reserves_commitment.
            // Only the operator sends UpdateReserves, and with HashStrategy,
            // sync is triggered by the operation type (amount-changing ops only).
        }

        // Send NACK if ledger was not found
        // (Success ACKs/NACKs are sent immediately in the processing logic above)
        if ledger_not_found {
            // Send NACK for ledger not found
            let error_msg = format!("No ledger found with {} as operator and {} as partner", sender_node_id, self.our_node_id);
            if let Err(e) = self.send_acknowledgment(&message, false, Some(error_msg), None, sender_node_id) {
                log_error!(
                    self.logger,
                    "Failed to send NACK for ledger not found: {}",
                    e
                );
            }
        }

        // TODO: Handle cosignatures properly in the immediate ACK sending above
        // For invoice cosigning, we need to include the cosignature in the ACK

        // All message types skip legacy protocol processing since:
        // 1. Handler-level processing is complete by this point
        // 2. Partners don't initialize legacy protocol ledger_state
        // 3. The legacy protocol is being phased out
        // Generate protocol event and return - no legacy processing needed
        self.generate_protocol_event(&message, sender_node_id);
        Ok(())
    }
}
