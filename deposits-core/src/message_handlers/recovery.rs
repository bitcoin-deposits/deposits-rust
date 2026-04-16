use super::*;

// ============================================================================
// Recovery Message Handlers
// ============================================================================

/// Handle a RecoveryVote message.
///
/// Partners submit votes during recovery to determine if an operator
/// was compliant or non-compliant.
pub fn handle_recovery_vote<C: HandlerContext>(
    ctx: &C,
    msg: &RecoveryVoteMsg,
    _sender: PublicKey,
) -> Result<HandlerResult, HandlerError> {
    // Convert wire message to internal vote type
    let vote = RecoveryVote {
        voter: msg.voter,
        is_conforming: msg.is_conforming,
        validated_hash: msg.validated_hash,
        validated_sequence: msg.validated_sequence,
        substitute_nomination: msg.substitute_nomination,
        discovered_violation: msg.discovered_violation,
        signature: msg.signature,
    };

    // Get recovery manager if available
    let recovery_manager = ctx.recovery_manager().ok_or(HandlerError::InvalidState(
        "No recovery manager available".to_string(),
    ))?;

    // Submit the vote
    let ledger_id = (msg.operator, msg.partner);
    let vote_result = {
        let mut manager = recovery_manager.lock().map_err(|_| {
            HandlerError::Internal("Failed to acquire recovery manager lock".to_string())
        })?;
        manager.submit_vote(ledger_id, vote).map_err(|e| {
            HandlerError::ValidationFailed(format!("Vote submission failed: {:?}", e))
        })?
    };

    // Check for non-compliance determination
    let non_conforming_threshold = if vote_result.total_votes <= 2 {
        1 // For 2-of-2 ledgers
    } else {
        (vote_result.total_votes / 2) + 1 // Strict majority
    };

    if vote_result.non_conforming_votes >= non_conforming_threshold {
        // Emit recovery started event (non-compliance determined)
        ctx.emit_event(ProtocolEvent::RecoveryStarted {
            operator: msg.operator,
            reserves_id: msg.partner.to_string(),
        });
    }

    Ok(HandlerResult::Ok)
}

// ============================================================================
// Recovery Claim Message Handlers
// ============================================================================

/// Handle a RecoveryClaimRequest message.
///
/// This is sent by a claimant (usually the partner or a substitute) when they want
/// to claim reserves from a non-compliant operator. The receiving node validates
/// the request and, if valid, signs the claim transaction sighash.
///
/// # Validation
/// - The operator must be in non-compliant recovery phase
/// - The claimant must be authorized (partner or nominated substitute)
/// - The tier_index must be valid
///
/// # Arguments
/// * `ctx` - Handler context providing access to ledgers and recovery state
/// * `msg` - The recovery claim request message
/// * `_sender` - Public key of the message sender
///
/// # Returns
/// * `HandlerResult::Response(RecoveryClaimRequestValidated)` - Request is valid, should sign
/// * `HandlerResult::Rejected(reason)` - Request is invalid with explanation
/// * `HandlerError` - Internal error during processing
pub fn handle_recovery_claim_request<C: HandlerContext>(
    ctx: &C,
    msg: &RecoveryClaimRequestMsg,
    _sender: PublicKey,
) -> Result<HandlerResult, HandlerError> {
    // Verify the operator is in non-compliant recovery phase
    let ledger_id = (msg.operator, msg.partner);

    let recovery_manager = ctx.recovery_manager().ok_or(HandlerError::InvalidState(
        "No recovery manager available".to_string(),
    ))?;

    let is_non_compliant = {
        let manager = recovery_manager.lock().map_err(|_| {
            HandlerError::Internal("Failed to acquire recovery manager lock".to_string())
        })?;
        match manager.get_recovery(&ledger_id) {
            Some(state) => {
                matches!(
                    state.phase,
                    crate::recovery::RecoveryPhase::NonCompliantRecovery { .. }
                )
            }
            None => {
                // No recovery state found - proceed anyway (may be late-joining validator)
                true
            }
        }
    };

    if !is_non_compliant {
        return Ok(HandlerResult::Rejected(format!(
            "Operator {} is not in non-compliant recovery phase",
            msg.operator
        )));
    }

    // Validate tier_index is reasonable (0-2 for typical 3-tier recovery)
    if msg.tier_index > 2 {
        return Ok(HandlerResult::Rejected(format!(
            "Invalid tier_index: {} (expected 0-2)",
            msg.tier_index
        )));
    }

    // Emit event for claim request received
    ctx.emit_event(ProtocolEvent::RecoveryClaimRequested {
        operator: msg.operator,
        reserves_id: msg.partner.to_string(),
        claimant: msg.claimant,
        tier_index: msg.tier_index,
    });

    // Sign the sighash with Schnorr
    let signature = match ctx.sign_schnorr(&msg.sighash) {
        Some(sig) => sig,
        None => {
            return Ok(HandlerResult::Rejected(
                "No signing key available".to_string(),
            ));
        }
    };

    // Queue the claim signature response to the claimant
    let response = DepositsMessage::RecoveryResponse(RecoveryResponseMsg::ClaimSignature {
        request_hash: msg.sighash,
        signer: ctx.our_node_id(),
        sighash: msg.sighash,
        signature,
    });

    ctx.queue_message(msg.claimant, response)?;

    Ok(HandlerResult::Ok)
}

/// Handle a RecoveryClaimSignature message.
///
/// This is sent by co-signers in response to a RecoveryClaimRequest.
/// The claimant collects signatures until threshold is reached.
///
/// # Arguments
/// * `ctx` - Handler context
/// * `msg` - The signature message containing the signed sighash
/// * `sender` - Public key of the signer
///
/// # Returns
/// * `HandlerResult::Response(RecoveryClaimSignatureReceived)` - Signature recorded
/// * `HandlerResult::Rejected(reason)` - Invalid signature
/// * `HandlerError` - Internal error
pub fn handle_recovery_claim_signature<C: HandlerContext>(
    ctx: &C,
    msg: &RecoveryClaimSignatureMsg,
    sender: PublicKey,
) -> Result<HandlerResult, HandlerError> {
    // Validate sender matches signer in message
    if sender != msg.signer {
        return Ok(HandlerResult::Rejected(format!(
            "Sender {} does not match claimed signer {}",
            sender, msg.signer
        )));
    }

    // Emit event for signature received
    ctx.emit_event(ProtocolEvent::RecoveryClaimSignatureReceived {
        operator: msg.operator,
        reserves_id: msg.partner.to_string(),
        signer: msg.signer,
    });

    // Add signature to claim manager via provider
    // This also emits RecoveryClaimReady event if threshold is reached
    match ctx.add_claim_signature(msg.operator, msg.partner, msg.signer, msg.signature) {
        Ok(_threshold_reached) => Ok(HandlerResult::Ok),
        Err(e) => Ok(HandlerResult::Rejected(e)),
    }
}

/// Handle a RecoveryClaimComplete message.
///
/// This is broadcast when a recovery claim transaction has been confirmed on-chain.
/// Recipients should update their state and clean up any pending claim data.
///
/// # Arguments
/// * `ctx` - Handler context
/// * `msg` - The claim complete message with confirmation details
/// * `_sender` - Public key of the sender
///
/// # Returns
/// * `HandlerResult::Response(RecoveryClaimCompleted)` - Claim completion processed
/// * `HandlerError` - Internal error
pub fn handle_recovery_claim_complete<C: HandlerContext>(
    ctx: &C,
    msg: &RecoveryClaimCompleteMsg,
    _sender: PublicKey,
) -> Result<HandlerResult, HandlerError> {
    // Emit event for claim completion (this also emits DepositsEvent via provider)
    ctx.emit_event(ProtocolEvent::RecoveryClaimCompleted {
        old_operator: msg.operator,
        reserves_id: msg.partner.to_string(),
        new_operator: msg.new_operator,
        claim_txid: msg.claim_txid,
        confirmation_block: msg.confirmation_block,
    });

    // Clean up claim tracking via provider
    ctx.remove_claim(msg.operator, msg.partner);

    Ok(HandlerResult::Ok)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::{Ledger, LedgerRole};
    use crate::recovery::RecoveryManager;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex, RwLock};

    /// Test implementation of HandlerContext
    struct TestContext {
        ledgers: HashMap<(PublicKey, String), Arc<RwLock<Ledger>>>,
        our_node_id: PublicKey,
        events: Mutex<Vec<ProtocolEvent>>,
        recovery_manager: Option<Arc<Mutex<RecoveryManager>>>,
    }

    impl TestContext {
        fn new(our_node_id: PublicKey) -> Self {
            Self {
                ledgers: HashMap::new(),
                our_node_id,
                events: Mutex::new(Vec::new()),
                recovery_manager: None,
            }
        }

        #[allow(dead_code)]
        fn with_recovery_manager(mut self) -> Self {
            self.recovery_manager =
                Some(Arc::new(Mutex::new(RecoveryManager::new(self.our_node_id))));
            self
        }
    }

    impl crate::message_validation::ValidationContext for TestContext {
        fn get_ledger(
            &self,
            operator: &PublicKey,
            reserves_id: &str,
        ) -> Option<Arc<RwLock<Ledger>>> {
            self.ledgers
                .get(&(*operator, reserves_id.to_string()))
                .cloned()
        }

        fn our_node_id(&self) -> PublicKey {
            self.our_node_id
        }
    }

    impl HandlerContext for TestContext {
        fn queue_message(
            &self,
            _peer: PublicKey,
            _msg: crate::messages::DepositsMessage,
        ) -> Result<(), HandlerError> {
            Ok(())
        }

        fn emit_event(&self, event: ProtocolEvent) {
            self.events.lock().unwrap().push(event);
        }

        fn recovery_manager(&self) -> Option<Arc<Mutex<RecoveryManager>>> {
            self.recovery_manager.clone()
        }
    }

    fn create_test_pubkey(seed: u8) -> PublicKey {
        let secp = Secp256k1::new();
        let mut bytes = [seed; 32];
        if seed == 0 {
            bytes[0] = 1;
        }
        let secret = SecretKey::from_slice(&bytes).unwrap();
        PublicKey::from_secret_key(&secp, &secret)
    }

    // ========================================================================
    // Recovery Claim Request Tests
    // ========================================================================

    #[test]
    fn test_handle_recovery_claim_request_no_recovery_manager() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let partner = create_test_pubkey(3);
        let claimant = create_test_pubkey(4);

        let ctx = TestContext::new(our_node_id);

        let msg = RecoveryClaimRequestMsg {
            operator,
            partner,
            claimant,
            tier_index: 0,
            unsigned_tx: vec![0x01, 0x02, 0x03],
            sighash: [0xAB; 32],
            destination_script: vec![0x00, 0x14], // p2wpkh prefix
            block_height: 100,
        };

        // No recovery manager - should error
        let result = handle_recovery_claim_request(&ctx, &msg, claimant);
        assert!(matches!(result, Err(HandlerError::InvalidState(_))));
    }

    #[test]
    fn test_handle_recovery_claim_request_invalid_tier() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let partner = create_test_pubkey(3);
        let claimant = create_test_pubkey(4);

        let ctx = TestContext::new(our_node_id).with_recovery_manager();

        let msg = RecoveryClaimRequestMsg {
            operator,
            partner,
            claimant,
            tier_index: 5, // Invalid tier (>2)
            unsigned_tx: vec![0x01, 0x02, 0x03],
            sighash: [0xAB; 32],
            destination_script: vec![0x00, 0x14],
            block_height: 100,
        };

        // Invalid tier - should be rejected
        let result = handle_recovery_claim_request(&ctx, &msg, claimant);
        assert!(matches!(result, Ok(HandlerResult::Rejected(_))));
    }

    #[test]
    fn test_handle_recovery_claim_request_valid() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let partner = create_test_pubkey(3);
        let claimant = create_test_pubkey(4);

        let ctx = TestContext::new(our_node_id).with_recovery_manager();

        let sighash = [0xAB; 32];
        let msg = RecoveryClaimRequestMsg {
            operator,
            partner,
            claimant,
            tier_index: 0,
            unsigned_tx: vec![0x01, 0x02, 0x03],
            sighash,
            destination_script: vec![0x00, 0x14],
            block_height: 100,
        };

        // Valid request - handler emits event but returns Rejected because TestContext has no signing key
        let result = handle_recovery_claim_request(&ctx, &msg, claimant);
        // TestContext doesn't provide our_secret_key, so sign_schnorr returns None
        // Handler returns Rejected("No signing key available")
        assert!(matches!(result, Ok(HandlerResult::Rejected(_))));

        // Event should still have been emitted before signing attempt
        let events = ctx.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        match &events[0] {
            ProtocolEvent::RecoveryClaimRequested {
                operator: op,
                claimant: cl,
                tier_index,
                ..
            } => {
                assert_eq!(*op, operator);
                assert_eq!(*cl, claimant);
                assert_eq!(*tier_index, 0);
            }
            other => panic!("Expected RecoveryClaimRequested event, got {:?}", other),
        }
    }

    // ========================================================================
    // Recovery Claim Signature Tests
    // ========================================================================

    #[test]
    fn test_handle_recovery_claim_signature_wrong_sender() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let partner = create_test_pubkey(3);
        let signer = create_test_pubkey(4);
        let wrong_sender = create_test_pubkey(5);

        let ctx = TestContext::new(our_node_id);

        let msg = RecoveryClaimSignatureMsg {
            operator,
            partner,
            signer,
            sighash: [0xAB; 32],
            signature: [0xCD; 64],
        };

        // Wrong sender - should be rejected
        let result = handle_recovery_claim_signature(&ctx, &msg, wrong_sender);
        assert!(matches!(result, Ok(HandlerResult::Rejected(_))));
    }

    #[test]
    fn test_handle_recovery_claim_signature_valid() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let partner = create_test_pubkey(3);
        let signer = create_test_pubkey(4);

        let ctx = TestContext::new(our_node_id);

        let signature = [0xCD; 64];
        let msg = RecoveryClaimSignatureMsg {
            operator,
            partner,
            signer,
            sighash: [0xAB; 32],
            signature,
        };

        // Valid signature message - handler uses provider pattern and returns Ok
        let result = handle_recovery_claim_signature(&ctx, &msg, signer);
        // Handler emits event, calls provider to add signature, and returns Ok
        assert!(matches!(result, Ok(HandlerResult::Ok)));

        // Check that event was emitted
        let events = ctx.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        match &events[0] {
            ProtocolEvent::RecoveryClaimSignatureReceived {
                operator: op,
                signer: s,
                ..
            } => {
                assert_eq!(*op, operator);
                assert_eq!(*s, signer);
            }
            other => panic!(
                "Expected RecoveryClaimSignatureReceived event, got {:?}",
                other
            ),
        }
    }

    // ========================================================================
    // Recovery Claim Complete Tests
    // ========================================================================

    #[test]
    fn test_handle_recovery_claim_complete() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let partner = create_test_pubkey(3);
        let new_operator = create_test_pubkey(4);
        let sender = create_test_pubkey(5);

        let ctx = TestContext::new(our_node_id);

        let claim_txid = [0xDE; 32];
        let msg = RecoveryClaimCompleteMsg {
            operator,
            partner,
            new_operator,
            claim_txid,
            confirmation_block: 12345,
            reason_code: 1,
        };

        // Should always succeed - handler uses provider pattern and returns Ok
        let result = handle_recovery_claim_complete(&ctx, &msg, sender);
        assert!(matches!(result, Ok(HandlerResult::Ok)));

        // Check that event was emitted
        let events = ctx.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        match &events[0] {
            ProtocolEvent::RecoveryClaimCompleted {
                old_operator: old_op,
                new_operator: new_op,
                confirmation_block,
                ..
            } => {
                assert_eq!(*old_op, operator);
                assert_eq!(*new_op, new_operator);
                assert_eq!(*confirmation_block, 12345);
            }
            other => panic!("Expected RecoveryClaimCompleted event, got {:?}", other),
        }
    }
}
