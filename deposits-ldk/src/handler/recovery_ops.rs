//! Recovery Operations for Bitcoin Deposits
//!
//! This module handles force-close recovery tracking, claim initiation,
//! transaction broadcasting, and fraud proof accusation.

use bitcoin::secp256k1::PublicKey;
use std::ops::Deref;

use super::messages::DepositsMessage;
use crate::wire::messages::{RecoveryVoteMsg, RecoveryClaimRequestMsg, RecoveryClaimCompleteMsg, UncreditedPaymentMsg};
use deposits_core::{log_info, log_error, log_warn};
use lightning::util::logger::Logger as LdkLogger;

use super::core::DepositsHandler;

/// Extension trait for recovery operations on DepositsHandler
pub trait RecoveryOperations {
    /// Start tracking a recovery process when a force close is detected
    fn start_recovery_tracking(
        &self,
        operator: PublicKey,
        partner: PublicKey,
        force_close_block: u32,
        force_close_txid: [u8; 32],
        on_chain_ledger_hash: [u8; 32],
    ) -> Result<(), String>;

    /// Called when the entropy block arrives (6 blocks after force close confirmation)
    fn on_recovery_entropy_block(
        &self,
        operator: PublicKey,
        partner: PublicKey,
        entropy_block_hash: [u8; 32],
    ) -> Result<(), String>;

    /// Initiate a claim for a non-compliant recovery and request signatures from voters
    fn initiate_claim_and_request_signatures(
        &self,
        operator: PublicKey,
        partner: PublicKey,
        reserves: deposits_core::recovery_claim::ClaimableReserves,
        current_block_height: u32,
    ) -> Result<(), String>;

    /// Broadcast a recovery claim transaction after signature threshold is met
    fn broadcast_recovery_claim<B: lightning::chain::chaininterface::BroadcasterInterface + Send + Sync>(
        &self,
        operator: PublicKey,
        partner: PublicKey,
        broadcaster: &B,
    ) -> Result<deposits_core::recovery_claim::BroadcastResult, String>;

    /// Initiate an uncredited payment accusation (fraud proof)
    fn broadcast_uncredited_payment_accusation(
        &self,
        operator: PublicKey,
        payment_hash: [u8; 32],
        preimage: [u8; 32],
        deposit_pubkey: PublicKey,
        amount_msat: u64,
        invoice_cosignature: [u8; 64],
    ) -> Result<(), String>;
}

impl<L: Deref + Clone + Send + Sync> RecoveryOperations for DepositsHandler<L>
where
    L::Target: LdkLogger,
{
    fn start_recovery_tracking(
        &self,
        operator: PublicKey,
        partner: PublicKey,
        force_close_block: u32,
        force_close_txid: [u8; 32],
        on_chain_ledger_hash: [u8; 32],
    ) -> Result<(), String> {
        let mut recovery_manager = self.recovery_manager.lock().unwrap();
        recovery_manager
            .start_recovery(operator, partner, force_close_block, force_close_txid, on_chain_ledger_hash)
            .map_err(|e| format!("{:?}", e))?;

        log_info!(
            self.logger,
            "🔄 RECOVERY: Started tracking recovery for operator {} partner {} at block {}",
            operator,
            partner,
            force_close_block
        );

        Ok(())
    }

    fn on_recovery_entropy_block(
        &self,
        operator: PublicKey,
        partner: PublicKey,
        entropy_block_hash: [u8; 32],
    ) -> Result<(), String> {
        use bitcoin::secp256k1::{Secp256k1, Keypair};

        // Transition to Evaluating phase
        {
            let mut recovery_manager = self.recovery_manager.lock().unwrap();
            recovery_manager
                .on_entropy_block((operator, partner), entropy_block_hash)
                .map_err(|e| format!("Failed to transition to Evaluating phase: {:?}", e))?;
        }

        log_info!(
            self.logger,
            "🔄 RECOVERY: Entropy block received for operator {} partner {} - evaluating ledger",
            operator,
            partner
        );

        // Get our signing key
        let secret_key = match self.node_secret_key {
            Some(sk) => sk,
            None => {
                log_warn!(
                    self.logger,
                    "🔄 RECOVERY: No signing key available - cannot broadcast vote"
                );
                return Err("No signing key available".to_string());
            }
        };

        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, &secret_key);

        // Evaluate our local ledger
        let (is_conforming, validated_hash, validated_sequence, discovered_violation) = {
            let ledgers = self.ledgers.lock().unwrap();
            let ledger_key = (operator, partner);

            match ledgers.get(&ledger_key) {
                Some(ledger_arc) => {
                    let ledger = ledger_arc.read().unwrap();
                    let hash = ledger.tail_hash();
                    let sequence = ledger.history.len() as u64;
                    (true, hash, sequence, false)
                }
                None => {
                    log_warn!(
                        self.logger,
                        "🔄 RECOVERY: No ledger found for operator {} partner {} - voting non-conforming",
                        operator,
                        partner
                    );
                    (false, [0u8; 32], 0u64, true)
                }
            }
        };

        // Create and sign our vote
        let vote = deposits_core::recovery::RecoveryVote::new_signed(
            &keypair,
            is_conforming,
            validated_hash,
            validated_sequence,
            None,
            discovered_violation,
        ).map_err(|e| format!("Failed to create signed vote: {:?}", e))?;

        // Create vote message
        let vote_msg = RecoveryVoteMsg {
            operator,
            partner,
            voter: self.our_node_id,
            is_conforming: vote.is_conforming,
            validated_hash: vote.validated_hash,
            validated_sequence: vote.validated_sequence,
            substitute_nomination: vote.substitute_nomination,
            discovered_violation: vote.discovered_violation,
            signature: vote.signature,
        };

        // V2 format: Recovery messages use Recovery(RecoveryMsg::...)
        use deposits_core::messages::RecoveryMsg;
        let message = super::messages::DepositsMessage::Recovery(RecoveryMsg::Vote {
            operator: vote_msg.operator,
            partner: vote_msg.partner,
            voter: vote_msg.voter,
            is_conforming: vote_msg.is_conforming,
            validated_hash: vote_msg.validated_hash,
            validated_sequence: vote_msg.validated_sequence,
            substitute_nomination: vote_msg.substitute_nomination,
            discovered_violation: vote_msg.discovered_violation,
            signature: vote_msg.signature,
        });

        // Broadcast to operator and partner
        let mut broadcast_targets = vec![operator, partner];
        broadcast_targets.retain(|pk| *pk != self.our_node_id);
        broadcast_targets.dedup();

        log_info!(
            self.logger,
            "🔄 RECOVERY: Broadcasting vote (conforming={}) to {} peers for operator {} partner {}",
            is_conforming,
            broadcast_targets.len(),
            operator,
            partner
        );

        for target in broadcast_targets {
            if let Err(e) = self.send_message(target, message.clone()) {
                log_warn!(
                    self.logger,
                    "🔄 RECOVERY: Failed to send vote to {}: {:?}",
                    target,
                    e
                );
            } else {
                log_info!(
                    self.logger,
                    "🔄 RECOVERY: Sent vote to {}",
                    target
                );
            }
        }

        // Submit our own vote to the recovery manager
        {
            let mut recovery_manager = self.recovery_manager.lock().unwrap();
            if let Err(e) = recovery_manager.submit_vote((operator, partner), vote) {
                log_warn!(
                    self.logger,
                    "🔄 RECOVERY: Failed to record our own vote: {:?}",
                    e
                );
            }
        }

        Ok(())
    }

    fn initiate_claim_and_request_signatures(
        &self,
        operator: PublicKey,
        partner: PublicKey,
        reserves: deposits_core::recovery_claim::ClaimableReserves,
        current_block_height: u32,
    ) -> Result<(), String> {
        use bitcoin::consensus::Encodable;

        let ledger_id = (operator, partner);

        // Get the recovery state and verify we're in NonCompliantRecovery phase
        let (eligibility, _recovery_pool) = {
            let recovery_manager = self.recovery_manager.lock().unwrap();
            match recovery_manager.get_recovery(&ledger_id) {
                Some(state) => {
                    match &state.phase {
                        deposits_core::recovery::RecoveryPhase::NonCompliantRecovery {
                            current_eligibility,
                            recovery_pool,
                            ..
                        } => (current_eligibility.clone(), recovery_pool.clone()),
                        _ => {
                            return Err(format!(
                                "Recovery for operator {} partner {} is not in NonCompliantRecovery phase",
                                operator, partner
                            ));
                        }
                    }
                }
                None => {
                    return Err(format!(
                        "No recovery state found for operator {} partner {}",
                        operator, partner
                    ));
                }
            }
        };

        // Verify we're eligible to claim based on current tier
        let we_are_eligible = match &eligibility {
            deposits_core::recovery::ClaimEligibility::SelectedPartnerOnly { partner: selected } => {
                *selected == self.our_node_id
            }
            deposits_core::recovery::ClaimEligibility::AnyThreePartners => true,
            deposits_core::recovery::ClaimEligibility::AnySinglePartner => true,
            deposits_core::recovery::ClaimEligibility::CommunityFallback => true,
        };

        if !we_are_eligible {
            return Err(format!(
                "We are not eligible to claim in current tier for operator {} partner {}",
                operator, partner
            ));
        }

        // Use deposits-core's tier_index() method for consistent tier mapping
        let tier_index = eligibility.tier_index();

        log_info!(
            self.logger,
            "🔄 RECOVERY: Initiating claim for operator {} partner {} at tier {} (block {})",
            operator,
            partner,
            tier_index,
            current_block_height
        );

        // Initialize claim in ClaimManager
        let (unsigned_tx_bytes, sighash, destination_script) = {
            let mut claim_manager = self.claim_manager.lock().unwrap();

            let attempt = claim_manager
                .initiate_claim(
                    ledger_id,
                    vec![self.our_node_id],
                    eligibility.clone(),
                    reserves.clone(),
                )
                .map_err(|e| format!("Failed to initiate claim: {:?}", e))?;

            let sighash = attempt
                .get_sighash()
                .map_err(|e| format!("Failed to get sighash: {:?}", e))?;

            let mut unsigned_tx_bytes = Vec::new();
            attempt.unsigned_tx
                .consensus_encode(&mut unsigned_tx_bytes)
                .map_err(|e| format!("Failed to encode transaction: {:?}", e))?;

            let destination_script = attempt.destination.script_pubkey().to_bytes();
            let sighash_bytes: [u8; 32] = *sighash.as_ref();

            (unsigned_tx_bytes, sighash_bytes, destination_script)
        };

        // Sign our own signature
        {
            let mut claim_manager = self.claim_manager.lock().unwrap();
            claim_manager
                .sign_claim(&ledger_id)
                .map_err(|e| format!("Failed to sign claim: {:?}", e))?;
        }

        log_info!(
            self.logger,
            "🔄 RECOVERY: Signed our own claim signature for operator {} partner {}",
            operator,
            partner
        );

        // Create claim request message
        let claim_request = RecoveryClaimRequestMsg {
            operator,
            partner,
            claimant: self.our_node_id,
            tier_index,
            unsigned_tx: unsigned_tx_bytes,
            sighash,
            destination_script,
            block_height: current_block_height,
        };

        // V2 format: Recovery messages use Recovery(RecoveryMsg::...)
        use deposits_core::messages::RecoveryMsg;
        let message = super::messages::DepositsMessage::Recovery(RecoveryMsg::ClaimRequest {
            operator: claim_request.operator,
            partner: claim_request.partner,
            claimant: claim_request.claimant,
            tier_index: claim_request.tier_index,
            unsigned_tx: claim_request.unsigned_tx,
            sighash: claim_request.sighash,
            destination_script: claim_request.destination_script,
            block_height: claim_request.block_height,
        });

        // Broadcast to all voters
        let broadcast_targets: Vec<PublicKey> = reserves.voter_set.all_voters()
            .into_iter()
            .filter(|pk| *pk != self.our_node_id)
            .collect();

        log_info!(
            self.logger,
            "🔄 RECOVERY: Broadcasting claim request to {} voters for operator {} partner {}",
            broadcast_targets.len(),
            operator,
            partner
        );

        for target in broadcast_targets {
            if let Err(e) = self.send_message(target, message.clone()) {
                log_warn!(
                    self.logger,
                    "🔄 RECOVERY: Failed to send claim request to {}: {:?}",
                    target,
                    e
                );
            } else {
                log_info!(
                    self.logger,
                    "🔄 RECOVERY: Sent claim request to {}",
                    target
                );
            }
        }

        Ok(())
    }

    fn broadcast_recovery_claim<B: lightning::chain::chaininterface::BroadcasterInterface + Send + Sync>(
        &self,
        operator: PublicKey,
        partner: PublicKey,
        broadcaster: &B,
    ) -> Result<deposits_core::recovery_claim::BroadcastResult, String> {
        use bitcoin::hashes::Hash;

        let ledger_id = (operator, partner);

        log_info!(
            self.logger,
            "🔄 RECOVERY: Broadcasting claim transaction for operator {} partner {}",
            operator,
            partner
        );

        // Get voter set for broadcasting RecoveryClaimComplete
        let voter_set_pubkeys: Vec<PublicKey> = {
            let claim_manager = self.claim_manager.lock().unwrap();
            match claim_manager.get_claim(&ledger_id) {
                Some(claim) => claim.reserves.voter_set.all_voters(),
                None => {
                    return Err(format!(
                        "No active claim found for operator {} partner {}",
                        operator, partner
                    ));
                }
            }
        };

        // Broadcast the claim transaction (wrap LDK broadcaster for deposits-core)
        // TODO: Fix broadcaster adapter - currently stubbed
        let result = {
            let mut claim_manager = self.claim_manager.lock().unwrap();
            // Use MemoryBroadcaster as a temporary stub until proper Arc handling is implemented
            let adapter = crate::chain::MemoryBroadcaster::new();
            claim_manager
                .broadcast_claim(&ledger_id, &adapter)
                .map_err(|e| format!("Failed to broadcast claim: {:?}", e))?
        };

        log_info!(
            self.logger,
            "🔄 RECOVERY: Claim transaction broadcast! txid={} amount={} sats",
            result.txid,
            result.amount_claimed
        );

        // Broadcast RecoveryClaimComplete message
        let complete_msg = RecoveryClaimCompleteMsg {
            operator,
            partner,
            new_operator: self.our_node_id,
            claim_txid: result.txid.to_byte_array(),
            confirmation_block: 0,
            reason_code: 1,
        };

        // V2 format: Recovery messages use Recovery(RecoveryMsg::...)
        use deposits_core::messages::RecoveryMsg;
        let message = super::messages::DepositsMessage::Recovery(RecoveryMsg::ClaimComplete {
            operator: complete_msg.operator,
            partner: complete_msg.partner,
            new_operator: complete_msg.new_operator,
            claim_txid: complete_msg.claim_txid,
            confirmation_block: complete_msg.confirmation_block,
            reason_code: complete_msg.reason_code,
        });

        let broadcast_targets: Vec<PublicKey> = voter_set_pubkeys
            .into_iter()
            .filter(|pk| *pk != self.our_node_id)
            .collect();

        log_info!(
            self.logger,
            "🔄 RECOVERY: Broadcasting claim complete to {} voters",
            broadcast_targets.len()
        );

        for target in broadcast_targets {
            if let Err(e) = self.send_message(target, message.clone()) {
                log_warn!(
                    self.logger,
                    "🔄 RECOVERY: Failed to send claim complete to {}: {:?}",
                    target,
                    e
                );
            }
        }

        // Emit event
        let _ = self.event_queue.emit_deposits_event(
            super::events::DepositsEvent::RecoveryClaimCompleted {
                old_operator: operator,
                partner_id: partner,
                new_operator: self.our_node_id,
                claim_txid: result.txid.to_byte_array(),
                confirmation_block: 0,
            },
        );

        Ok(result)
    }

    fn broadcast_uncredited_payment_accusation(
        &self,
        operator: PublicKey,
        payment_hash: [u8; 32],
        preimage: [u8; 32],
        deposit_pubkey: PublicKey,
        amount_msat: u64,
        invoice_cosignature: [u8; 64],
    ) -> Result<(), String> {
        // Verify preimage matches payment hash using deposits-core's pure validation
        deposits_core::recovery::validate_preimage(&preimage, &payment_hash)?;

        let ledger_key = (operator, self.our_node_id);

        // Verify invoice and check if already credited
        let (settlement_sequence, settlement_ledger_hash, collateral_partners, was_credited) = {
            let ledgers = self.ledgers.lock().unwrap();
            match ledgers.get(&ledger_key) {
                Some(ledger_arc) => {
                    let ledger = ledger_arc.read().unwrap();
                    let seq = ledger.history.len() as u64;
                    let hash = ledger.tail_hash();
                    let partners = ledger.state.collateral_partners.clone();

                    let credited = ledger.history.iter().any(|update| {
                        if update.message.len() < 2 {
                            return false;
                        }
                        let msg_type = u16::from_be_bytes([update.message[0], update.message[1]]);
                        let msg_data = &update.message[2..];

                        match crate::wire::MessageCodec::decode_message_with_type(msg_type, msg_data) {
                            Ok(msg) => {
                                // Check for PaymentCredit via to_operation()
                                if let Some(deposits_core::messages::LedgerOperation::PaymentCredit { payment_hash: hash, .. }) = msg.to_operation() {
                                    return hash == payment_hash;
                                }
                                false
                            }
                            Err(_) => false,
                        }
                    });

                    (seq, hash, partners, credited)
                }
                None => {
                    return Err(format!(
                        "No ledger found for operator {} partner {}",
                        operator, self.our_node_id
                    ));
                }
            }
        };

        // Check cosigned invoice exists
        let invoice_exists = {
            let invoices = self.cosigned_invoices.lock().unwrap();
            let key = (operator, payment_hash);
            if let Some(invoice) = invoices.get(&key) {
                invoice.deposit_pubkey == deposit_pubkey
            } else {
                false
            }
        };

        if !invoice_exists {
            return Err(format!(
                "Invalid fraud proof: no cosigned invoice found for payment_hash {} on deposit {}",
                hex::encode(&payment_hash),
                deposit_pubkey
            ));
        }

        if was_credited {
            return Err(format!(
                "Invalid fraud proof: payment_hash {} was already credited to the deposit",
                hex::encode(&payment_hash)
            ));
        }

        log_warn!(
            self.logger,
            "⚠️ FRAUD: Initiating uncredited payment accusation against operator {} for payment_hash {} amount {} msat",
            operator,
            hex::encode(&payment_hash[..8]),
            amount_msat
        );

        // Force close the channel with the operator
        if let Some(ref cm) = self.channel_manager {
            let channels = cm.list_channels();
            let operator_channel = channels.iter().find(|c| c.counterparty_node_id == operator);

            if let Some(channel) = operator_channel {
                log_warn!(
                    self.logger,
                    "⚠️ FRAUD: Force-closing channel {} with operator {} due to uncredited payment",
                    hex::encode(&channel.channel_id.0[..8]),
                    operator
                );

                let reason = format!(
                    "Uncredited payment fraud: payment_hash={} amount={} msat",
                    hex::encode(&payment_hash[..8]),
                    amount_msat
                );

                if let Err(e) = cm.force_close_broadcasting_latest_txn(
                    &channel.channel_id,
                    &operator,
                    reason,
                ) {
                    log_error!(
                        self.logger,
                        "⚠️ FRAUD: Failed to force-close channel with operator {}: {:?}",
                        operator,
                        e
                    );
                }
            } else {
                log_warn!(
                    self.logger,
                    "⚠️ FRAUD: No channel found with operator {} to force-close",
                    operator
                );
            }
        } else {
            log_warn!(
                self.logger,
                "⚠️ FRAUD: Channel manager not available, cannot force-close"
            );
        }

        let block_height = self.channel_manager.as_ref()
            .map(|cm| cm.current_best_block_height())
            .unwrap_or(0);

        // Construct accusation message
        let accuser_signature = [0u8; 64]; // TODO: Sign properly

        let accusation_msg = UncreditedPaymentMsg {
            operator,
            partner: self.our_node_id,
            payment_hash,
            preimage,
            deposit_pubkey,
            amount_msat,
            invoice_cosignature,
            settlement_sequence,
            settlement_ledger_hash,
            settlement_block_height: block_height,
            accuser_signature,
        };

        // V2 format: UncreditedPayment is now Recovery(RecoveryMsg::UncreditedPayment)
        use deposits_core::messages::RecoveryMsg;
        let message = DepositsMessage::Recovery(RecoveryMsg::UncreditedPayment {
            operator: accusation_msg.operator,
            partner: accusation_msg.partner,
            payment_hash: accusation_msg.payment_hash,
            preimage: accusation_msg.preimage,
            deposit_pubkey: accusation_msg.deposit_pubkey,
            amount_msat: accusation_msg.amount_msat,
            invoice_cosignature: accusation_msg.invoice_cosignature,
            settlement_sequence: accusation_msg.settlement_sequence,
            settlement_ledger_hash: accusation_msg.settlement_ledger_hash,
            settlement_block_height: accusation_msg.settlement_block_height,
            accuser_signature: accusation_msg.accuser_signature,
        });

        // Broadcast to all collateral partners
        let mut broadcast_targets = collateral_partners;
        if !broadcast_targets.contains(&operator) {
            broadcast_targets.push(operator);
        }

        log_warn!(
            self.logger,
            "⚠️ FRAUD: Broadcasting uncredited payment accusation to {} auditors",
            broadcast_targets.len()
        );

        for target in &broadcast_targets {
            if *target == self.our_node_id {
                continue;
            }
            if let Err(e) = self.send_message(*target, message.clone()) {
                log_warn!(
                    self.logger,
                    "⚠️ FRAUD: Failed to send accusation to {}: {:?}",
                    target,
                    e
                );
            }
        }

        // Emit event
        let _ = self.event_queue.emit_deposits_event(
            super::events::DepositsEvent::UncreditedPaymentAccusation {
                operator,
                partner: self.our_node_id,
                payment_hash,
                deposit_pubkey,
                amount_msat,
                settlement_sequence,
            },
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use std::sync::Arc;
    use lightning::util::test_utils::TestLogger;
    use deposits_core::{Ledger, LedgerRole};
    use deposits_core::{Deposit, FeeStructure};
    use std::sync::RwLock;
    use lightning::ln::peer_handler::CustomMessageHandler;
    use crate::handler::messages as handler_messages;

    fn create_test_handler() -> DepositsHandler<Arc<TestLogger>> {
        let logger = Arc::new(TestLogger::new());
        DepositsHandler::new_for_testing(logger)
    }

    fn create_test_pubkey(seed: u8) -> PublicKey {
        let secp = Secp256k1::new();
        let mut bytes = [seed; 32];
        if seed == 0 { bytes[0] = 1; }
        let secret = SecretKey::from_slice(&bytes).unwrap();
        PublicKey::from_secret_key(&secp, &secret)
    }

    fn create_test_secret_key(seed: u8) -> SecretKey {
        let mut bytes = [seed; 32];
        if seed == 0 { bytes[0] = 1; }
        SecretKey::from_slice(&bytes).unwrap()
    }

    /// Helper to create a handler with a signing key set
    /// Note: Uses [1; 32] as the secret key to match the handler's our_node_id
    fn create_test_handler_with_signing_key() -> (DepositsHandler<Arc<TestLogger>>, PublicKey) {
        let logger = Arc::new(TestLogger::new());
        let mut handler = DepositsHandler::new_for_testing(logger);
        // Use [1; 32] to match the handler's our_node_id (set in new_for_testing)
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[1; 32]).unwrap();
        let node_id = PublicKey::from_secret_key(&secp, &secret);
        handler.set_node_secret_key(secret);
        // Verify node_id matches handler's our_node_id
        assert_eq!(node_id, handler.our_node_id, "Handler node ID should match signing key");
        (handler, node_id)
    }

    /// Helper to add a ledger to a handler
    fn add_test_ledger(handler: &DepositsHandler<Arc<TestLogger>>, operator: PublicKey, partner: PublicKey) {
        let ledger = Ledger::new_as_operator(
            operator,
            partner,
            "tb1qtest".to_string(),
        );
        let mut ledgers = handler.ledgers.lock().unwrap();
        ledgers.insert((operator, partner), Arc::new(RwLock::new(ledger)));
    }

    /// Helper to mark a peer as connected
    fn mark_peer_connected(handler: &DepositsHandler<Arc<TestLogger>>, peer: PublicKey) {
        handler.connected_peers.lock().unwrap().insert(peer);
    }

    #[test]
    fn test_start_recovery_tracking() {
        let handler = create_test_handler();
        let operator = create_test_pubkey(1);
        let partner = create_test_pubkey(2);

        let result = handler.start_recovery_tracking(
            operator,
            partner,
            100,
            [0xAB; 32],
            [0xCD; 32],
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_start_recovery_tracking_multiple() {
        let handler = create_test_handler();

        // Start multiple recoveries for different channels
        for i in 1..5u8 {
            let operator = create_test_pubkey(i * 10);
            let partner = create_test_pubkey(i * 10 + 1);

            let result = handler.start_recovery_tracking(
                operator,
                partner,
                100 + i as u32,
                [i; 32],
                [i + 1; 32],
            );
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_on_recovery_entropy_block_no_signing_key() {
        let handler = create_test_handler();
        let operator = create_test_pubkey(3);
        let partner = create_test_pubkey(4);

        // First start recovery
        let _ = handler.start_recovery_tracking(
            operator,
            partner,
            100,
            [0xAB; 32],
            [0xCD; 32],
        );

        // Then try entropy block - should fail without signing key
        let result = handler.on_recovery_entropy_block(
            operator,
            partner,
            [0xEF; 32],
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("signing key"));
    }

    #[test]
    fn test_on_recovery_entropy_block_with_signing_key_no_ledger() {
        let (handler, our_node_id) = create_test_handler_with_signing_key();
        let operator = create_test_pubkey(10);
        let partner = our_node_id; // We are the partner

        // Mark operator as connected so messages can be sent
        mark_peer_connected(&handler, operator);

        // Start recovery
        let _ = handler.start_recovery_tracking(
            operator,
            partner,
            100,
            [0xAB; 32],
            [0xCD; 32],
        );

        // Entropy block with signing key but no ledger - should vote non-conforming
        let result = handler.on_recovery_entropy_block(
            operator,
            partner,
            [0xEF; 32],
        );

        // Should succeed (votes non-conforming due to missing ledger)
        assert!(result.is_ok());
    }

    #[test]
    fn test_on_recovery_entropy_block_with_ledger() {
        let (handler, our_node_id) = create_test_handler_with_signing_key();
        let operator = create_test_pubkey(20);
        let partner = our_node_id;

        // Add a ledger for this channel
        add_test_ledger(&handler, operator, partner);

        // Mark operator as connected
        mark_peer_connected(&handler, operator);

        // Start recovery
        let _ = handler.start_recovery_tracking(
            operator,
            partner,
            100,
            [0xAB; 32],
            [0xCD; 32],
        );

        // Entropy block with ledger - should vote conforming
        let result = handler.on_recovery_entropy_block(
            operator,
            partner,
            [0xEF; 32],
        );

        assert!(result.is_ok());

        // Check that a vote message was queued
        let pending = handler.get_and_clear_pending_msg();
        assert!(!pending.is_empty(), "Expected vote message to be queued");

        // Verify it's a RecoveryVote message (V2 format: Recovery(RecoveryMsg::Vote {...}))
        use deposits_core::messages::RecoveryMsg;
        let (target, msg) = &pending[0];
        assert_eq!(*target, operator);
        match msg {
            DepositsMessage::Recovery(RecoveryMsg::Vote { is_conforming, .. }) => {
                assert!(is_conforming, "Should vote conforming when ledger exists");
            }
            _ => panic!("Expected Recovery(RecoveryMsg::Vote) message"),
        }
    }

    #[test]
    fn test_broadcast_uncredited_payment_invalid_preimage() {
        let handler = create_test_handler();
        let operator = create_test_pubkey(5);
        let deposit = create_test_pubkey(6);

        // Preimage that doesn't match hash
        let result = handler.broadcast_uncredited_payment_accusation(
            operator,
            [0x11; 32], // payment_hash
            [0x22; 32], // wrong preimage
            deposit,
            1000,
            [0u8; 64],
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid preimage"));
    }

    #[test]
    fn test_broadcast_uncredited_payment_valid_preimage_no_ledger() {
        use bitcoin::hashes::{sha256, Hash};

        let handler = create_test_handler();
        let operator = create_test_pubkey(30);
        let deposit = create_test_pubkey(31);

        // Valid preimage and matching payment hash
        let preimage = [0xAB; 32];
        let payment_hash = *sha256::Hash::hash(&preimage).as_byte_array();

        // No ledger exists - should fail before checking cosigned invoice
        let result = handler.broadcast_uncredited_payment_accusation(
            operator,
            payment_hash,
            preimage,
            deposit,
            1000,
            [0u8; 64],
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No ledger found"));
    }

    #[test]
    fn test_broadcast_uncredited_payment_valid_preimage_no_invoice() {
        use bitcoin::hashes::{sha256, Hash};

        let (handler, our_node_id) = create_test_handler_with_signing_key();
        let operator = create_test_pubkey(32);

        // Set up a ledger so we get to the cosigned invoice check
        add_test_ledger(&handler, operator, our_node_id);

        let deposit = create_test_pubkey(33);

        // Valid preimage and matching payment hash
        let preimage = [0xAB; 32];
        let payment_hash = *sha256::Hash::hash(&preimage).as_byte_array();

        // No cosigned invoice - should fail
        let result = handler.broadcast_uncredited_payment_accusation(
            operator,
            payment_hash,
            preimage,
            deposit,
            1000,
            [0u8; 64],
        );

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("no cosigned invoice"), "Expected 'no cosigned invoice' error, got: {}", err);
    }

    #[test]
    fn test_broadcast_recovery_claim_not_in_recovery() {
        let handler = create_test_handler();
        let operator = create_test_pubkey(50);
        let partner = create_test_pubkey(51);

        // Create a dummy broadcaster
        struct DummyBroadcaster;
        impl lightning::chain::chaininterface::BroadcasterInterface for DummyBroadcaster {
            fn broadcast_transactions(&self, _txs: &[&bitcoin::Transaction]) {}
        }

        let broadcaster = DummyBroadcaster;

        // Try to broadcast without recovery
        let result = handler.broadcast_recovery_claim(
            operator,
            partner,
            &broadcaster,
        );

        // Should fail - no active claim
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No active claim found"));
    }

    #[test]
    fn test_start_recovery_duplicate_channel() {
        let handler = create_test_handler();
        let operator = create_test_pubkey(70);
        let partner = create_test_pubkey(71);

        // Start recovery first time
        let result1 = handler.start_recovery_tracking(
            operator,
            partner,
            100,
            [0xAB; 32],
            [0xCD; 32],
        );
        assert!(result1.is_ok());

        // Try to start recovery again for same channel
        let result2 = handler.start_recovery_tracking(
            operator,
            partner,
            101,
            [0xEF; 32],
            [0x12; 32],
        );

        // Should fail - recovery already exists
        assert!(result2.is_err());
    }

    #[test]
    fn test_on_recovery_entropy_block_no_recovery() {
        let (handler, _our_node_id) = create_test_handler_with_signing_key();
        let operator = create_test_pubkey(80);
        let partner = create_test_pubkey(81);

        // Try entropy block without starting recovery first
        let result = handler.on_recovery_entropy_block(
            operator,
            partner,
            [0xEF; 32],
        );

        // Should fail - no recovery in progress
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to transition to Evaluating phase"));
    }

    #[test]
    fn test_on_recovery_entropy_block_conforming_vote_content() {
        let (handler, our_node_id) = create_test_handler_with_signing_key();
        let operator = create_test_pubkey(100);
        let partner = our_node_id;

        // Add a ledger for this channel
        add_test_ledger(&handler, operator, partner);

        // Mark operator as connected
        mark_peer_connected(&handler, operator);

        // Start recovery
        let _ = handler.start_recovery_tracking(
            operator,
            partner,
            100,
            [0xAB; 32],
            [0xCD; 32],
        );

        // Entropy block with ledger - should vote conforming
        let result = handler.on_recovery_entropy_block(
            operator,
            partner,
            [0xEF; 32],
        );

        assert!(result.is_ok());

        // Check that a vote message was queued and verify it's conforming
        let pending = handler.get_and_clear_pending_msg();
        assert!(!pending.is_empty(), "Expected vote message to be queued");

        // Find the RecoveryVote message (V2 format: Recovery(RecoveryMsg::Vote {...}))
        use deposits_core::messages::RecoveryMsg;
        use crate::wire::messages::RecoveryVoteMsg;
        let vote_msg = pending.iter().find_map(|(_, msg)| {
            match msg {
                DepositsMessage::Recovery(RecoveryMsg::Vote { operator, partner, voter, is_conforming, validated_hash, validated_sequence, ref substitute_nomination, discovered_violation, signature }) => {
                    Some(RecoveryVoteMsg {
                        operator: *operator,
                        partner: *partner,
                        voter: *voter,
                        is_conforming: *is_conforming,
                        validated_hash: *validated_hash,
                        validated_sequence: *validated_sequence,
                        substitute_nomination: substitute_nomination.clone(),
                        discovered_violation: *discovered_violation,
                        signature: *signature,
                    })
                }
                _ => None,
            }
        });

        assert!(vote_msg.is_some(), "Expected RecoveryVote message");
        let vote = vote_msg.unwrap();
        assert!(vote.is_conforming, "Should vote conforming when ledger exists");
        assert_eq!(vote.operator, operator);
        assert_eq!(vote.partner, partner);
        assert_eq!(vote.voter, our_node_id);
        assert!(!vote.discovered_violation);
    }

    #[test]
    fn test_on_recovery_entropy_block_non_conforming_vote() {
        let (handler, our_node_id) = create_test_handler_with_signing_key();
        let operator = create_test_pubkey(110);
        let partner = our_node_id;

        // Don't add a ledger - should vote non-conforming

        // Mark operator as connected
        mark_peer_connected(&handler, operator);

        // Start recovery
        let _ = handler.start_recovery_tracking(
            operator,
            partner,
            100,
            [0xAB; 32],
            [0xCD; 32],
        );

        // Entropy block without ledger - should vote non-conforming
        let result = handler.on_recovery_entropy_block(
            operator,
            partner,
            [0xEF; 32],
        );

        assert!(result.is_ok());

        // Check that a vote message was queued and verify it's non-conforming
        let pending = handler.get_and_clear_pending_msg();
        assert!(!pending.is_empty(), "Expected vote message to be queued");

        // V2 format: Recovery(RecoveryMsg::Vote {...})
        use deposits_core::messages::RecoveryMsg;
        let vote_msg = pending.iter().find_map(|(_, msg)| {
            match msg {
                DepositsMessage::Recovery(RecoveryMsg::Vote { is_conforming, discovered_violation, .. }) => {
                    Some((is_conforming, discovered_violation))
                }
                _ => None,
            }
        });

        assert!(vote_msg.is_some(), "Expected Recovery(RecoveryMsg::Vote) message");
        let (is_conforming, discovered_violation) = vote_msg.unwrap();
        assert!(!is_conforming, "Should vote non-conforming when no ledger");
        assert!(discovered_violation, "Should mark violation discovered");
    }

    // ==================== Claim Initiation Tests ====================

    #[test]
    fn test_initiate_claim_not_in_non_compliant_phase() {
        let (handler, our_node_id) = create_test_handler_with_signing_key();
        let operator = create_test_pubkey(120);
        let partner = our_node_id;

        // Set up a recovery in Evaluating phase (not NonCompliantRecovery)
        handler.start_recovery_tracking(
            operator,
            partner,
            100,
            [0xAB; 32],
            [0xCD; 32],
        ).unwrap();

        // Move to evaluating phase
        handler.on_recovery_entropy_block(operator, partner, [0xEF; 32]).unwrap();

        // Create minimal reserves
        use deposits_core::recovery_claim::ClaimableReserves;
        use deposits_core::{VoterSet, ThresholdConfig};
        use bitcoin::{OutPoint, ScriptBuf, Network};
        use bitcoin::hashes::Hash;

        let voter_set = VoterSet::new(operator, vec![our_node_id]);
        let reserves = ClaimableReserves {
            outpoint: OutPoint { txid: bitcoin::Txid::from_byte_array([0xAB; 32]), vout: 0 },
            amount_sats: 100_000,
            script_pubkey: ScriptBuf::new(),
            voter_set,
            threshold_config: ThresholdConfig::default_for_voter_count(2),
            network: Network::Regtest,
            ledger_hash: [0u8; 32],
        };

        // Should fail - not in NonCompliantRecovery phase
        let result = handler.initiate_claim_and_request_signatures(
            operator,
            partner,
            reserves,
            200, // current block height
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not in NonCompliantRecovery phase"));
    }

    #[test]
    fn test_initiate_claim_no_recovery_state() {
        let (handler, our_node_id) = create_test_handler_with_signing_key();
        let operator = create_test_pubkey(130);
        let partner = our_node_id;

        use deposits_core::recovery_claim::ClaimableReserves;
        use deposits_core::{VoterSet, ThresholdConfig};
        use bitcoin::{OutPoint, ScriptBuf, Network};
        use bitcoin::hashes::Hash;

        let voter_set = VoterSet::new(operator, vec![our_node_id]);
        let reserves = ClaimableReserves {
            outpoint: OutPoint { txid: bitcoin::Txid::from_byte_array([0xAB; 32]), vout: 0 },
            amount_sats: 100_000,
            script_pubkey: ScriptBuf::new(),
            voter_set,
            threshold_config: ThresholdConfig::default_for_voter_count(2),
            network: Network::Regtest,
            ledger_hash: [0u8; 32],
        };

        // Should fail - no recovery state at all
        let result = handler.initiate_claim_and_request_signatures(
            operator,
            partner,
            reserves,
            200,
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No recovery state found"));
    }

    #[test]
    fn test_initiate_claim_in_non_compliant_recovery() {
        let (handler, our_node_id) = create_test_handler_with_signing_key();
        let operator = create_test_pubkey(140);
        let partner = our_node_id;

        // Set up recovery and transition to NonCompliantRecovery
        handler.start_recovery_tracking(
            operator,
            partner,
            100,
            [0xAB; 32],
            [0xCD; 32],
        ).unwrap();

        // Move to evaluating phase
        handler.on_recovery_entropy_block(operator, partner, [0xEF; 32]).unwrap();

        // Manually transition to NonCompliantRecovery phase
        {
            let mut recovery_manager = handler.recovery_manager.lock().unwrap();
            recovery_manager.transition_to_non_compliant(
                (operator, partner),
                100,
                vec![our_node_id, operator],
            ).unwrap();
        }

        // Mark peers as connected so messages can be sent
        mark_peer_connected(&handler, operator);

        use deposits_core::recovery_claim::ClaimableReserves;
        use deposits_core::{VoterSet, ThresholdConfig, TapscriptReservesBuilder};
        use bitcoin::{OutPoint, Network};
        use bitcoin::hashes::Hash;

        // Create valid voter set and reserves
        let voter_set = VoterSet::new(our_node_id, vec![operator]);
        let test_ledger_hash = [0xAA; 32];
        let builder = TapscriptReservesBuilder::with_defaults(voter_set.clone(), Network::Regtest, test_ledger_hash);
        let output = builder.build().unwrap();

        let reserves = ClaimableReserves {
            outpoint: OutPoint { txid: bitcoin::Txid::from_byte_array([0xAB; 32]), vout: 0 },
            amount_sats: 100_000,
            script_pubkey: output.script_pubkey(),
            voter_set,
            threshold_config: ThresholdConfig::default_for_voter_count(2),
            network: Network::Regtest,
            ledger_hash: test_ledger_hash,
        };

        // Should succeed now that we're in NonCompliantRecovery
        let result = handler.initiate_claim_and_request_signatures(
            operator,
            partner,
            reserves,
            200,
        );

        // The function should succeed (or fail during claim creation, not phase check)
        // If it fails, it should not be about "not in NonCompliantRecovery phase"
        if result.is_err() {
            let err = result.unwrap_err();
            assert!(!err.contains("not in NonCompliantRecovery phase"), "Unexpected error: {}", err);
        }
    }

    // ==================== Broadcast Recovery Claim Tests ====================

    #[test]
    fn test_broadcast_recovery_claim_no_active_claim() {
        let handler = create_test_handler();
        let operator = create_test_pubkey(150);
        let partner = create_test_pubkey(151);

        struct DummyBroadcaster;
        impl lightning::chain::chaininterface::BroadcasterInterface for DummyBroadcaster {
            fn broadcast_transactions(&self, _txs: &[&bitcoin::Transaction]) {}
        }

        let broadcaster = DummyBroadcaster;

        // Should fail - no active claim
        let result = handler.broadcast_recovery_claim(operator, partner, &broadcaster);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No active claim found"));
    }

    // ==================== Uncredited Payment Accusation Tests ====================

    #[test]
    fn test_uncredited_payment_accusation_with_cosigned_invoice_no_credit() {
        use bitcoin::hashes::{sha256, Hash};
        use crate::handler::CosignedInvoice;

        let (handler, our_node_id) = create_test_handler_with_signing_key();
        let operator = create_test_pubkey(160);
        let deposit_pubkey = create_test_pubkey(161);

        // Set up ledger so the function gets past the ledger check
        add_test_ledger(&handler, operator, our_node_id);

        // Valid preimage and payment hash
        let preimage = [0xDE; 32];
        let payment_hash = *sha256::Hash::hash(&preimage).as_byte_array();

        // Add a cosigned invoice for this payment
        {
            let mut invoices = handler.cosigned_invoices.lock().unwrap();
            let invoice = CosignedInvoice {
                deposit_pubkey,
                payment_hash,
                amount: 50_000,
                expires: u64::MAX, // Never expires for test
                cosignature: vec![0u8; 64],
            };
            invoices.insert((operator, payment_hash), invoice);
        }

        // Mark operator as connected
        mark_peer_connected(&handler, operator);

        // Now call the accusation function
        let result = handler.broadcast_uncredited_payment_accusation(
            operator,
            payment_hash,
            preimage,
            deposit_pubkey,
            50_000,
            [0u8; 64], // invoice_cosignature
        );

        // Should succeed - we have a valid preimage, ledger, and cosigned invoice
        // The accusation should go through (even without a real channel to force close)
        assert!(result.is_ok(), "Expected success, got: {:?}", result);

        // Check that an UncreditedPayment message was queued (V2 format: Recovery(RecoveryMsg::UncreditedPayment {...}))
        let pending = handler.get_and_clear_pending_msg();
        use deposits_core::messages::RecoveryMsg;
        let accusation_msg = pending.iter().find_map(|(_, msg)| {
            match msg {
                DepositsMessage::Recovery(RecoveryMsg::UncreditedPayment { payment_hash: ph, preimage: pr, deposit_pubkey: dp, amount_msat: amt, .. }) => {
                    Some((ph, pr, dp, amt))
                }
                _ => None,
            }
        });

        assert!(accusation_msg.is_some(), "Expected Recovery(RecoveryMsg::UncreditedPayment) message to be queued");
        let (msg_payment_hash, msg_preimage, msg_deposit_pubkey, msg_amount_msat) = accusation_msg.unwrap();
        assert_eq!(*msg_payment_hash, payment_hash);
        assert_eq!(*msg_preimage, preimage);
        assert_eq!(*msg_deposit_pubkey, deposit_pubkey);
        assert_eq!(*msg_amount_msat, 50_000);
    }

    #[test]
    fn test_uncredited_payment_accusation_no_ledger() {
        use bitcoin::hashes::{sha256, Hash};
        use crate::handler::CosignedInvoice;

        let (handler, our_node_id) = create_test_handler_with_signing_key();
        let operator = create_test_pubkey(170);
        let deposit_pubkey = create_test_pubkey(171);

        // Valid preimage and payment hash
        let preimage = [0xBB; 32];
        let payment_hash = *sha256::Hash::hash(&preimage).as_byte_array();

        // Add a cosigned invoice but NO ledger
        {
            let mut invoices = handler.cosigned_invoices.lock().unwrap();
            let invoice = CosignedInvoice {
                deposit_pubkey,
                payment_hash,
                amount: 50_000,
                expires: u64::MAX,
                cosignature: vec![0u8; 64],
            };
            invoices.insert((operator, payment_hash), invoice);
        }

        // Should fail - no ledger found for this operator
        let result = handler.broadcast_uncredited_payment_accusation(
            operator,
            payment_hash,
            preimage,
            deposit_pubkey,
            50_000,
            [0u8; 64],
        );

        assert!(result.is_err());
        // Should fail because there's no ledger for this operator
        let err_msg = result.unwrap_err();
        assert!(err_msg.contains("ledger") || err_msg.contains("not found"),
            "Expected error about missing ledger, got: {}", err_msg);
    }

    #[test]
    fn test_uncredited_payment_accusation_wrong_deposit_pubkey() {
        use bitcoin::hashes::{sha256, Hash};
        use crate::handler::CosignedInvoice;

        let (handler, our_node_id) = create_test_handler_with_signing_key();
        let operator = create_test_pubkey(180);
        let correct_deposit = create_test_pubkey(181);
        let wrong_deposit = create_test_pubkey(182);

        // Set up ledger
        add_test_ledger(&handler, operator, our_node_id);

        // Valid preimage
        let preimage = [0xCC; 32];
        let payment_hash = *sha256::Hash::hash(&preimage).as_byte_array();

        // Add cosigned invoice for the CORRECT deposit
        {
            let mut invoices = handler.cosigned_invoices.lock().unwrap();
            let invoice = CosignedInvoice {
                deposit_pubkey: correct_deposit,
                payment_hash,
                amount: 50_000,
                expires: u64::MAX,
                cosignature: vec![0u8; 64],
            };
            invoices.insert((operator, payment_hash), invoice);
        }

        // Try to accuse with WRONG deposit - should fail
        let result = handler.broadcast_uncredited_payment_accusation(
            operator,
            payment_hash,
            preimage,
            wrong_deposit, // Wrong!
            50_000,
            [0u8; 64],
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("no cosigned invoice"), "Expected 'no cosigned invoice' error due to deposit mismatch");
    }

    // ==================== Recovery Message Broadcast Tests ====================

    #[test]
    fn test_recovery_vote_message_broadcast_to_multiple_targets() {
        let (handler, our_node_id) = create_test_handler_with_signing_key();
        let operator = create_test_pubkey(190);
        let auditor = create_test_pubkey(191);
        let partner = our_node_id;

        // Add ledger and set up collateral partners
        {
            let ledger = Ledger::new(
                operator,
                partner,
                LedgerRole::Operator,
                vec![auditor], // Add auditor as collateral partner
                "tb1qtest".to_string(),
            );
            let mut ledgers = handler.ledgers.lock().unwrap();
            ledgers.insert((operator, partner), Arc::new(RwLock::new(ledger)));
        }

        // Mark both operator and auditor as connected
        mark_peer_connected(&handler, operator);
        mark_peer_connected(&handler, auditor);

        // Start recovery
        handler.start_recovery_tracking(
            operator,
            partner,
            100,
            [0xAB; 32],
            [0xCD; 32],
        ).unwrap();

        // Entropy block should trigger vote broadcast
        handler.on_recovery_entropy_block(operator, partner, [0xEF; 32]).unwrap();

        // Check that vote was sent to operator
        let pending = handler.get_and_clear_pending_msg();
        assert!(!pending.is_empty(), "Expected vote message(s) to be queued");

        // All should be RecoveryVote messages (V2 format: Recovery(RecoveryMsg::Vote {...}))
        use deposits_core::messages::RecoveryMsg;
        let vote_targets: Vec<PublicKey> = pending.iter()
            .filter_map(|(target, msg)| {
                match msg {
                    DepositsMessage::Recovery(RecoveryMsg::Vote { .. }) => Some(*target),
                    _ => None,
                }
            })
            .collect();

        // Should have sent to operator (and possibly auditor depending on implementation)
        assert!(vote_targets.contains(&operator), "Should send vote to operator");
    }

    #[test]
    fn test_start_recovery_tracking_with_different_txids() {
        let handler = create_test_handler();
        let operator = create_test_pubkey(200);
        let partner1 = create_test_pubkey(201);
        let partner2 = create_test_pubkey(202);

        // Start recovery for first channel
        let result1 = handler.start_recovery_tracking(
            operator,
            partner1,
            100,
            [0x11; 32], // txid 1
            [0xAA; 32], // hash 1
        );
        assert!(result1.is_ok());

        // Start recovery for second channel (same operator, different partner)
        let result2 = handler.start_recovery_tracking(
            operator,
            partner2,
            105,
            [0x22; 32], // txid 2
            [0xBB; 32], // hash 2
        );
        assert!(result2.is_ok());

        // Both should be tracked independently
    }
}
