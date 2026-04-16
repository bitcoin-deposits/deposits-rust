use super::*;

// ============================================================================
// Collateral Message Handlers
// ============================================================================

/// Handle a CollateralConsentRequest message.
///
/// Sent by operators requesting consent from potential quorum members.
/// Uses providers to sign and send responses directly.
pub fn handle_collateral_consent_request<C: HandlerContext>(
    ctx: &C,
    msg: &CollateralConsentRequestMsg,
    sender: PublicKey,
) -> Result<HandlerResult, HandlerError> {
    let our_node_id = ctx.our_node_id();

    // Verify the request is from the operator claiming to be the operator
    if sender != msg.operator_id {
        return Ok(HandlerResult::Rejected(
            "Sender doesn't match claimed operator".to_string(),
        ));
    }

    // Check if we have an operator channel with the requesting operator
    // This would be the channel where our reserves would serve as collateral
    let has_channel_with_operator = ctx
        .get_ledger(&msg.operator_id, &our_node_id.to_string())
        .is_some();
    let consent_granted = has_channel_with_operator;

    // Sign the consent (content: "COLLATERAL_CONSENT" + operator + reserves_id)
    let signature = if consent_granted {
        let mut sign_content = Vec::new();
        sign_content.extend_from_slice(b"COLLATERAL_CONSENT");
        sign_content.extend_from_slice(&msg.operator_id.serialize());
        sign_content.extend_from_slice(msg.reserves_id.as_bytes());
        ctx.sign_message(&sign_content).unwrap_or([0u8; 64])
    } else {
        [0u8; 64]
    };

    // If consent granted, append QuorumJoin to our own ledger
    // This creates a two-sided auditable trail
    if consent_granted {
        // Calculate membership expiration (~1 week at 10 min/block)
        let current_block = ctx.current_block_height();
        let membership_duration = 1000; // ~1 week
        let membership_expires = current_block + membership_duration;

        // Append QuorumJoin to our operator ledger
        ctx.append_quorum_join_to_own_ledger(
            msg.operator_id,
            &msg.reserves_id,
            membership_expires,
        )?;
    }

    // Queue the response message
    let response =
        DepositsMessage::CoordinationResponse(CoordinationResponseMsg::CollateralConsentResponse {
            request_hash: [0u8; 32],
            operator_id: msg.operator_id,
            reserves_id: msg.reserves_id.clone(),
            consent_granted,
            quorum_member_signature: signature,
        });
    ctx.queue_message(sender, response)?;

    // If consent granted, request state sync from the operator
    if consent_granted {
        // Get the ledger_id from our ledger with the operator
        if let Some(ledger_arc) = ctx.get_ledger(&msg.operator_id, &our_node_id.to_string()) {
            let ledger_id = {
                let ledger = ledger_arc.read().unwrap();
                ledger.ledger_id()
            };
            let sync_request = DepositsMessage::Sync(SyncMsg {
                ledger_id,
                last_known_sequence: 0,
                last_known_hash: [0u8; 32],
            });
            ctx.queue_message(msg.operator_id, sync_request)?;
        }
    }

    Ok(HandlerResult::Ok)
}

/// Handle a CollateralConsentResponse message.
///
/// Received by operators after requesting consent from quorum members.
pub fn handle_collateral_consent_response<C: HandlerContext>(
    ctx: &C,
    msg: &CollateralConsentResponseMsg,
    sender: PublicKey,
) -> Result<HandlerResult, HandlerError> {
    // Verify signature if consent granted
    if msg.consent_granted
        && !ctx.verify_consent_signature(
            msg.operator_id,
            &msg.reserves_id,
            msg.quorum_member_signature,
            sender,
        )
    {
        return Ok(HandlerResult::Rejected(
            "Invalid consent signature".to_string(),
        ));
    }

    // Complete pending consent request via provider
    ctx.complete_consent_request(
        msg.operator_id,
        &msg.reserves_id,
        msg.consent_granted,
        msg.quorum_member_signature,
    );

    // Send audit to new quorum member if granted
    if msg.consent_granted {
        ctx.send_audit_to_quorum_member(
            msg.operator_id,
            &msg.reserves_id,
            sender,
            msg.quorum_member_signature,
        );
    }

    Ok(HandlerResult::Ok)
}

/// Handle a QuorumAddMember message.
///
/// Received by partners when an operator adds a quorum member to a ledger.
/// This handler does the complete flow: validate, mutate, sign, persist, sync, send ACK.
pub fn handle_collateral_add_partner<C: HandlerContext>(
    ctx: &C,
    msg: &QuorumAddMemberMsg,
    sender: PublicKey,
) -> Result<HandlerResult, HandlerError> {
    use crate::messages::{LedgerOperation, LEDGER_UPDATE};

    let our_node_id = ctx.our_node_id();

    // We must be the reserves_id to process this message
    if msg.reserves_id != our_node_id.to_string() {
        return Ok(HandlerResult::Rejected(format!(
            "We ({}) are not the target partner ({})",
            our_node_id, msg.reserves_id
        )));
    }

    // Get the ledger - sender (operator) and us (partner)
    let ledger_arc =
        ctx.get_ledger(&sender, &msg.reserves_id)
            .ok_or(HandlerError::LedgerNotFound {
                operator: sender,
                reserves_id: msg.reserves_id.clone(),
            })?;

    let operation = LedgerOperation::QuorumAddMember {
        quorum_member: msg.quorum_member,
        quorum_member_signature: msg.quorum_member_signature,
        member_ledger_id: msg.member_ledger_id.clone(),
        min_fee_bps: None,
        min_fee_fixed: None,
        max_fee_period: None,
        collateral_lock_amount: None,
        collateral_lock_until: None,
        dispute_response_blocks: None,
        dispute_arm_blocks: None,
        service_response_blocks: None,
        max_transfer_timeout_blocks: None,
        max_descriptor_bytes: None,
    };

    // Check for idempotency and append (single write lock scope)
    let (prev_hash, new_hash, sequence, message_bytes, is_idempotent) = {
        let mut ledger = ledger_arc.write().map_err(|_| {
            HandlerError::Internal("Failed to acquire ledger write lock".to_string())
        })?;

        // Idempotency check: member already active or pending
        if ledger
            .state
            .quorum_members
            .iter()
            .any(|m| m.pubkey == msg.quorum_member)
            || ledger
                .state
                .next_quorum_members
                .iter()
                .any(|m| m.pubkey == msg.quorum_member)
        {
            let seq = ledger.sequence();
            let hash = ledger.hash();
            (hash, hash, seq, Vec::new(), true)
        } else {
            // Append operation
            let (prev, new, seq) = ledger
                .append_operation(operation.clone())
                .map_err(|e| HandlerError::ValidationFailed(e.to_string()))?;

            // Get message bytes for signing
            let bytes = ledger
                .history
                .last()
                .map(|u| u.message.clone())
                .unwrap_or_default();

            (prev, new, seq, bytes, false)
        }
    };

    // Sign the update (if not idempotent)
    let partner_sig = if !is_idempotent && !message_bytes.is_empty() {
        ctx.sign_ledger_update(
            &message_bytes,
            LEDGER_UPDATE,
            sequence,
            &prev_hash,
            &new_hash,
        )
    } else {
        None
    };

    // Update signature in ledger and persist (if not idempotent)
    if !is_idempotent {
        if let Some(sig) = partner_sig {
            let mut ledger = ledger_arc.write().map_err(|_| {
                HandlerError::Internal("Failed to acquire ledger write lock".to_string())
            })?;
            ledger.sign_last_update(None, Some(sig));
        }
        let _ = ctx.persist_ledger(&sender, &msg.reserves_id);
        ctx.sync_quorum_member(sender, &msg.reserves_id, msg.quorum_member, true);
    }

    // NOTE: ACK is sent by LDK dispatch code which has access to the correct message hash
    Ok(HandlerResult::Ok)
}

/// Handle a QuorumRemoveMember message.
///
/// Received by partners when an operator removes a quorum member from a ledger.
/// This handler does the complete flow: validate, mutate, sign, persist, sync, send ACK.
pub fn handle_collateral_remove_partner<C: HandlerContext>(
    ctx: &C,
    msg: &QuorumRemoveMemberMsg,
    sender: PublicKey,
) -> Result<HandlerResult, HandlerError> {
    use crate::messages::{LedgerOperation, LEDGER_UPDATE};

    let our_node_id = ctx.our_node_id();

    // We must be the reserves_id to process this message
    if msg.reserves_id != our_node_id.to_string() {
        return Ok(HandlerResult::Rejected(format!(
            "We ({}) are not the target partner ({})",
            our_node_id, msg.reserves_id
        )));
    }

    // Get the ledger - sender (operator) and us (partner)
    let ledger_arc =
        ctx.get_ledger(&sender, &msg.reserves_id)
            .ok_or(HandlerError::LedgerNotFound {
                operator: sender,
                reserves_id: msg.reserves_id.clone(),
            })?;

    let operation = LedgerOperation::QuorumRemoveMember {
        quorum_member: msg.quorum_member,
        operator_signature: msg.operator_signature,
    };

    // Check for idempotency and append (single write lock scope)
    let (prev_hash, new_hash, sequence, message_bytes, is_idempotent) = {
        let mut ledger = ledger_arc.write().map_err(|_| {
            HandlerError::Internal("Failed to acquire ledger write lock".to_string())
        })?;

        // Idempotency check - if already removed from both lists, return success
        if !ledger
            .state
            .quorum_members
            .iter()
            .any(|m| m.pubkey == msg.quorum_member)
            && !ledger
                .state
                .next_quorum_members
                .iter()
                .any(|m| m.pubkey == msg.quorum_member)
        {
            let seq = ledger.sequence();
            let hash = ledger.hash();
            (hash, hash, seq, Vec::new(), true)
        } else {
            // Append operation
            let (prev, new, seq) = ledger
                .append_operation(operation.clone())
                .map_err(|e| HandlerError::ValidationFailed(e.to_string()))?;

            // Get message bytes for signing
            let bytes = ledger
                .history
                .last()
                .map(|u| u.message.clone())
                .unwrap_or_default();

            (prev, new, seq, bytes, false)
        }
    };

    // Sign the update (if not idempotent)
    let partner_sig = if !is_idempotent && !message_bytes.is_empty() {
        ctx.sign_ledger_update(
            &message_bytes,
            LEDGER_UPDATE,
            sequence,
            &prev_hash,
            &new_hash,
        )
    } else {
        None
    };

    // Update signature in ledger and persist (if not idempotent)
    if !is_idempotent {
        if let Some(sig) = partner_sig {
            let mut ledger = ledger_arc.write().map_err(|_| {
                HandlerError::Internal("Failed to acquire ledger write lock".to_string())
            })?;
            ledger.sign_last_update(None, Some(sig));
        }
        let _ = ctx.persist_ledger(&sender, &msg.reserves_id);
        ctx.sync_quorum_member(sender, &msg.reserves_id, msg.quorum_member, false);
    }

    // NOTE: ACK is sent by LDK dispatch code which has access to the correct message hash
    Ok(HandlerResult::Ok)
}

/// Handle a CollateralAttestation message.
///
/// Received by operators from quorum members after they process a collateral lock.
/// The operator stores the attestation as proof and forwards it to channel partners.
pub fn handle_collateral_attestation<C: HandlerContext>(
    ctx: &C,
    msg: &CollateralAttestationMsg,
    sender: PublicKey,
) -> Result<HandlerResult, HandlerError> {
    let our_node_id = ctx.our_node_id();

    // The sender should be the quorum member
    if sender != msg.quorum_member {
        return Ok(HandlerResult::Rejected(format!(
            "Sender {} doesn't match quorum_member {}",
            sender, msg.quorum_member
        )));
    }

    // We should be the operator
    if msg.operator != our_node_id {
        return Ok(HandlerResult::Rejected(format!(
            "We ({}) are not the operator ({})",
            our_node_id, msg.operator
        )));
    }

    // Verify the attestation makes sense
    // - Amount should be positive
    if msg.amount == 0 {
        return Ok(HandlerResult::Rejected(
            "Attestation amount must be positive".to_string(),
        ));
    }

    // Return response data for the LDK layer to:
    // 1. Store the attestation in ledger state
    // 2. Forward CollateralAttestation to channel ledgers
    // 3. Send to channel partners for bilateral signing
    Ok(HandlerResult::Response(
        ResponseData::CollateralAttestationProcessed {
            operator: msg.operator,
            quorum_member: msg.quorum_member,
            amount: msg.amount,
        },
    ))
}

/// Handle an UncreditedPayment accusation message.
///
/// This is a fraud proof broadcast by a partner claiming the operator
/// failed to credit a payment they received. Quorum members must:
/// 1. Verify the preimage matches the payment hash
/// 2. Check if the ledger has a credit for this payment
/// 3. Store the accusation for dispute resolution
/// 4. Consider force-closing their own channel with the operator
pub fn handle_uncredited_payment<C: HandlerContext>(
    ctx: &C,
    msg: &UncreditedPaymentMsg,
    sender: PublicKey,
) -> Result<HandlerResult, HandlerError> {
    use bitcoin::hashes::{sha256, Hash};

    // 1. Verify preimage matches payment hash
    let computed_hash = sha256::Hash::hash(&msg.preimage);
    if computed_hash.as_byte_array() != &msg.payment_hash {
        return Ok(HandlerResult::Rejected(
            "Invalid preimage - computed hash doesn't match payment_hash".to_string(),
        ));
    }

    // 2. Verify the accuser is the partner for this ledger
    if msg.partner != sender {
        return Ok(HandlerResult::Rejected(format!(
            "Sender {} is not the claimed partner {}",
            sender, msg.partner
        )));
    }

    // 3. Check if we have the relevant ledger and if there's a credit
    if let Some(ledger_arc) = ctx.get_ledger(&msg.operator, &msg.partner.to_string()) {
        let ledger = ledger_arc
            .read()
            .map_err(|_| HandlerError::Internal("Failed to acquire ledger lock".to_string()))?;

        // Check if there's a credit for this payment hash in the ledger
        if ledger.has_credit_for_payment(&msg.payment_hash) {
            // The ledger has a credit - accusation appears invalid
            return Ok(HandlerResult::Rejected(
                "Ledger has a credit for this payment - accusation appears invalid".to_string(),
            ));
        }
    }
    // If we don't have the ledger, we can still process the accusation

    // 4. Emit event for node layer to store the accusation
    ctx.emit_event(ProtocolEvent::UncreditedPaymentReceived {
        operator: msg.operator,
        reserves_id: msg.partner.to_string(),
        payment_hash: msg.payment_hash,
        deposit_pubkey: msg.deposit_pubkey,
        amount_msat: msg.amount_msat,
        settlement_sequence: msg.settlement_sequence,
    });

    // 5. Handle followup: force-close and rebroadcast
    use crate::messages::RecoveryMsg;
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
    ctx.handle_fraud_proof_followup(msg.operator, accusation_msg);

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

        fn add_ledger(&mut self, operator: PublicKey, reserves_id: PublicKey, ledger: Ledger) {
            self.ledgers.insert(
                (operator, reserves_id.to_string()),
                Arc::new(RwLock::new(ledger)),
            );
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

    #[test]
    fn test_handle_collateral_consent_request_wrong_sender() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let partner = create_test_pubkey(3);
        let wrong_sender = create_test_pubkey(4);

        let ctx = TestContext::new(our_node_id);

        let msg = CollateralConsentRequestMsg {
            operator_id: operator,
            reserves_id: partner.to_string(),
            operator_signature: [0u8; 64],
        };

        // Wrong sender - should be rejected
        let result = handle_collateral_consent_request(&ctx, &msg, wrong_sender);
        assert!(matches!(result, Ok(HandlerResult::Rejected(_))));
    }

    #[test]
    fn test_handle_collateral_consent_request_no_channel() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let partner = create_test_pubkey(3);

        let ctx = TestContext::new(our_node_id);

        let msg = CollateralConsentRequestMsg {
            operator_id: operator,
            reserves_id: partner.to_string(),
            operator_signature: [0u8; 64],
        };

        // Correct sender but no channel - handler queues response message and returns Ok
        let result = handle_collateral_consent_request(&ctx, &msg, operator);
        // Handler now uses provider pattern - returns Ok after queueing response message
        assert!(matches!(result, Ok(HandlerResult::Ok)));
    }

    #[test]
    fn test_handle_collateral_consent_request_with_channel() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let partner = create_test_pubkey(3);

        let mut ctx = TestContext::new(our_node_id);

        // Create a ledger where operator is the operator and we are the partner
        let ledger = Ledger::new(
            operator,
            our_node_id.to_string(),
            LedgerRole::Partner,
            vec![],
            0,
        );
        ctx.add_ledger(operator, our_node_id, ledger);

        let msg = CollateralConsentRequestMsg {
            operator_id: operator,
            reserves_id: partner.to_string(),
            operator_signature: [0u8; 64],
        };

        // Correct sender and we have a channel - handler queues response message and returns Ok
        let result = handle_collateral_consent_request(&ctx, &msg, operator);
        // Handler now uses provider pattern - returns Ok after queueing response message
        assert!(matches!(result, Ok(HandlerResult::Ok)));
    }

    // ========================================================================
    // Collateral Add/Remove Partner Tests
    // ========================================================================

    #[test]
    fn test_handle_collateral_add_partner_wrong_partner() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let other_partner = create_test_pubkey(3);
        let quorum_member = create_test_pubkey(4);

        let ctx = TestContext::new(our_node_id);

        let msg = QuorumAddMemberMsg {
            operator_id: operator,
            reserves_id: other_partner.to_string(), // Not us
            quorum_member,
            quorum_member_signature: [0u8; 64],
            member_ledger_id: String::new(),
        };

        // We're not the target partner - should be rejected
        let result = handle_collateral_add_partner(&ctx, &msg, operator);
        assert!(matches!(result, Ok(HandlerResult::Rejected(_))));
    }

    #[test]
    fn test_handle_collateral_add_partner_no_ledger() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let quorum_member = create_test_pubkey(3);

        let ctx = TestContext::new(our_node_id);

        let msg = QuorumAddMemberMsg {
            operator_id: operator,
            reserves_id: our_node_id.to_string(),
            quorum_member,
            quorum_member_signature: [0u8; 64],
            member_ledger_id: String::new(),
        };

        // No ledger exists - should error
        let result = handle_collateral_add_partner(&ctx, &msg, operator);
        assert!(matches!(result, Err(HandlerError::LedgerNotFound { .. })));
    }

    #[test]
    fn test_handle_collateral_add_partner_valid() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let quorum_member = create_test_pubkey(3);

        let mut ctx = TestContext::new(our_node_id);

        // Create a ledger where operator is the operator and we are the partner
        let ledger = Ledger::new(
            operator,
            our_node_id.to_string(),
            LedgerRole::Partner,
            vec![],
            0,
        );
        ctx.add_ledger(operator, our_node_id, ledger);

        let msg = QuorumAddMemberMsg {
            operator_id: operator,
            reserves_id: our_node_id.to_string(),
            quorum_member,
            quorum_member_signature: [0u8; 64],
            member_ledger_id: String::new(),
        };

        // Valid request - should return Ok (actual mutation happens in LDK layer)
        let result = handle_collateral_add_partner(&ctx, &msg, operator);
        assert!(matches!(result, Ok(HandlerResult::Ok)));
    }

    #[test]
    fn test_handle_collateral_add_reserves_idempotent() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let quorum_member = create_test_pubkey(3);

        let mut ctx = TestContext::new(our_node_id);

        // Create a ledger with the quorum member already added
        let mut ledger = Ledger::new(
            operator,
            our_node_id.to_string(),
            LedgerRole::Partner,
            vec![],
            0,
        );
        ledger
            .state
            .quorum_members
            .push(crate::types::QuorumMember {
                pubkey: quorum_member,
                ledger_id: String::new(),
                min_fee_bps: None,
                min_fee_fixed: None,
                max_fee_period: None,
                collateral_lock_amount: None,
                collateral_lock_until: None,
                dispute_response_blocks: None,
                dispute_arm_blocks: None,
                service_response_blocks: None,
                max_transfer_timeout_blocks: None,
                max_descriptor_bytes: None,
            });
        ctx.add_ledger(operator, our_node_id, ledger);

        let msg = QuorumAddMemberMsg {
            operator_id: operator,
            reserves_id: our_node_id.to_string(),
            quorum_member,
            quorum_member_signature: [0u8; 64],
            member_ledger_id: String::new(),
        };

        // Already exists - should return Ok (idempotent success)
        let result = handle_collateral_add_partner(&ctx, &msg, operator);
        assert!(matches!(result, Ok(HandlerResult::Ok)));
    }

    #[test]
    fn test_handle_collateral_remove_partner_wrong_partner() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let other_partner = create_test_pubkey(3);
        let quorum_member = create_test_pubkey(4);

        let ctx = TestContext::new(our_node_id);

        let msg = QuorumRemoveMemberMsg {
            reserves_id: other_partner.to_string(), // Not us
            quorum_member,
            operator_signature: [0u8; 64],
        };

        // We're not the target partner - should be rejected
        let result = handle_collateral_remove_partner(&ctx, &msg, operator);
        assert!(matches!(result, Ok(HandlerResult::Rejected(_))));
    }

    #[test]
    fn test_handle_collateral_remove_partner_not_found() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let quorum_member = create_test_pubkey(3);

        let mut ctx = TestContext::new(our_node_id);

        // Create a ledger without the quorum member
        let ledger = Ledger::new(
            operator,
            our_node_id.to_string(),
            LedgerRole::Partner,
            vec![],
            0,
        );
        ctx.add_ledger(operator, our_node_id, ledger);

        let msg = QuorumRemoveMemberMsg {
            reserves_id: our_node_id.to_string(),
            quorum_member,
            operator_signature: [0u8; 64],
        };

        // Quorum member doesn't exist - should return Ok (idempotent, already removed)
        let result = handle_collateral_remove_partner(&ctx, &msg, operator);
        assert!(matches!(result, Ok(HandlerResult::Ok)));
    }

    #[test]
    fn test_handle_collateral_remove_partner_valid() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let quorum_member = create_test_pubkey(3);

        let mut ctx = TestContext::new(our_node_id);

        // Create a ledger with the quorum member
        let mut ledger = Ledger::new(
            operator,
            our_node_id.to_string(),
            LedgerRole::Partner,
            vec![],
            0,
        );
        ledger
            .state
            .quorum_members
            .push(crate::types::QuorumMember {
                pubkey: quorum_member,
                ledger_id: String::new(),
                min_fee_bps: None,
                min_fee_fixed: None,
                max_fee_period: None,
                collateral_lock_amount: None,
                collateral_lock_until: None,
                dispute_response_blocks: None,
                dispute_arm_blocks: None,
                service_response_blocks: None,
                max_transfer_timeout_blocks: None,
                max_descriptor_bytes: None,
            });
        ctx.add_ledger(operator, our_node_id, ledger);

        let msg = QuorumRemoveMemberMsg {
            reserves_id: our_node_id.to_string(),
            quorum_member,
            operator_signature: [0u8; 64],
        };

        // Valid request - should return Ok
        let result = handle_collateral_remove_partner(&ctx, &msg, operator);
        assert!(matches!(result, Ok(HandlerResult::Ok)));
    }

    // ========================================================================
    // Collateral Attestation Tests
    // ========================================================================

    #[test]
    fn test_handle_collateral_attestation_wrong_sender() {
        let our_node_id = create_test_pubkey(1);
        let quorum_member = create_test_pubkey(2);
        let wrong_sender = create_test_pubkey(3);

        let ctx = TestContext::new(our_node_id);

        let msg = CollateralAttestationMsg {
            operator: our_node_id,
            quorum_member,
            collateral_ledger_id: String::new(),
            amount: 100_000,
            block_height: 100,
            lock_until_block: 0,
            signature: [0u8; 64],
            ledger_hash: [0u8; 32],
        };

        // Wrong sender - should be rejected
        let result = handle_collateral_attestation(&ctx, &msg, wrong_sender);
        assert!(matches!(result, Ok(HandlerResult::Rejected(_))));
    }

    #[test]
    fn test_handle_collateral_attestation_not_operator() {
        let our_node_id = create_test_pubkey(1);
        let other_operator = create_test_pubkey(2);
        let quorum_member = create_test_pubkey(3);

        let ctx = TestContext::new(our_node_id);

        let msg = CollateralAttestationMsg {
            operator: other_operator, // Not us
            quorum_member,
            collateral_ledger_id: String::new(),
            amount: 100_000,
            block_height: 100,
            lock_until_block: 0,
            signature: [0u8; 64],
            ledger_hash: [0u8; 32],
        };

        // We're not the operator - should be rejected
        let result = handle_collateral_attestation(&ctx, &msg, quorum_member);
        assert!(matches!(result, Ok(HandlerResult::Rejected(_))));
    }

    #[test]
    fn test_handle_collateral_attestation_zero_amount() {
        let our_node_id = create_test_pubkey(1);
        let quorum_member = create_test_pubkey(2);

        let ctx = TestContext::new(our_node_id);

        let msg = CollateralAttestationMsg {
            operator: our_node_id,
            quorum_member,
            collateral_ledger_id: String::new(),
            amount: 0, // Zero
            block_height: 100,
            lock_until_block: 0,
            signature: [0u8; 64],
            ledger_hash: [0u8; 32],
        };

        // Zero amount - should be rejected
        let result = handle_collateral_attestation(&ctx, &msg, quorum_member);
        assert!(matches!(result, Ok(HandlerResult::Rejected(_))));
    }

    #[test]
    fn test_handle_collateral_attestation_valid() {
        let our_node_id = create_test_pubkey(1);
        let quorum_member = create_test_pubkey(2);

        let ctx = TestContext::new(our_node_id);

        let msg = CollateralAttestationMsg {
            operator: our_node_id,
            quorum_member,
            collateral_ledger_id: String::new(),
            amount: 100_000,
            block_height: 100,
            lock_until_block: 0,
            signature: [0u8; 64],
            ledger_hash: [0u8; 32],
        };

        // Valid attestation
        let result = handle_collateral_attestation(&ctx, &msg, quorum_member);
        match result {
            Ok(HandlerResult::Response(ResponseData::CollateralAttestationProcessed {
                amount,
                ..
            })) => {
                assert_eq!(amount, 100_000);
            }
            other => panic!(
                "Expected Response(CollateralAttestationProcessed), got {:?}",
                other
            ),
        }
    }

    // ========================================================================
    // Uncredited Payment Tests
    // ========================================================================

    #[test]
    fn test_handle_uncredited_payment_invalid_preimage() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let partner = create_test_pubkey(3);
        let deposit_pubkey = create_test_pubkey(4);

        let ctx = TestContext::new(our_node_id);

        // Create a preimage - we'll use the wrong hash to trigger rejection
        let preimage = [42u8; 32];
        // Don't use the correct hash - use a wrong one

        let msg = UncreditedPaymentMsg {
            operator,
            partner,
            payment_hash: [0u8; 32], // Wrong hash
            preimage,
            deposit_pubkey,
            amount_msat: 1_000_000,
            invoice_cosignature: [0u8; 64],
            settlement_sequence: 10,
            settlement_ledger_hash: [0u8; 32],
            settlement_block_height: 100,
            accuser_signature: [0u8; 64],
        };

        // Invalid preimage - should be rejected
        let result = handle_uncredited_payment(&ctx, &msg, partner);
        assert!(matches!(result, Ok(HandlerResult::Rejected(_))));
    }

    #[test]
    fn test_handle_uncredited_payment_wrong_sender() {
        use bitcoin::hashes::{sha256, Hash};

        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let partner = create_test_pubkey(3);
        let wrong_sender = create_test_pubkey(4);
        let deposit_pubkey = create_test_pubkey(5);

        let ctx = TestContext::new(our_node_id);

        // Create a preimage and compute its hash
        let preimage = [42u8; 32];
        let correct_hash = sha256::Hash::hash(&preimage);

        let msg = UncreditedPaymentMsg {
            operator,
            partner,
            payment_hash: *correct_hash.as_byte_array(),
            preimage,
            deposit_pubkey,
            amount_msat: 1_000_000,
            invoice_cosignature: [0u8; 64],
            settlement_sequence: 10,
            settlement_ledger_hash: [0u8; 32],
            settlement_block_height: 100,
            accuser_signature: [0u8; 64],
        };

        // Wrong sender - should be rejected
        let result = handle_uncredited_payment(&ctx, &msg, wrong_sender);
        assert!(matches!(result, Ok(HandlerResult::Rejected(_))));
    }

    #[test]
    fn test_handle_uncredited_payment_valid() {
        use bitcoin::hashes::{sha256, Hash};

        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let partner = create_test_pubkey(3);
        let deposit_pubkey = create_test_pubkey(4);

        let ctx = TestContext::new(our_node_id);

        // Create a preimage and compute its hash
        let preimage = [42u8; 32];
        let correct_hash = sha256::Hash::hash(&preimage);

        let msg = UncreditedPaymentMsg {
            operator,
            partner,
            payment_hash: *correct_hash.as_byte_array(),
            preimage,
            deposit_pubkey,
            amount_msat: 1_000_000,
            invoice_cosignature: [0u8; 64],
            settlement_sequence: 10,
            settlement_ledger_hash: [0u8; 32],
            settlement_block_height: 100,
            accuser_signature: [0u8; 64],
        };

        // Valid accusation (no ledger to check for credit)
        let result = handle_uncredited_payment(&ctx, &msg, partner);
        assert!(
            matches!(result, Ok(HandlerResult::Ok)),
            "Expected Ok(HandlerResult::Ok), got {:?}",
            result
        );

        // Check that event was emitted
        let events = ctx.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        match &events[0] {
            ProtocolEvent::UncreditedPaymentReceived {
                operator: op,
                reserves_id,
                amount_msat: amt,
                ..
            } => {
                assert_eq!(*op, operator);
                assert_eq!(*reserves_id, partner.to_string());
                assert_eq!(*amt, 1_000_000);
            }
            other => panic!("Expected UncreditedPaymentReceived event, got {:?}", other),
        }
    }
}
