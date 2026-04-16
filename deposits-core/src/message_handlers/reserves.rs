use super::*;

// ============================================================================
// Reserves Message Handlers
// ============================================================================

/// Handle a ReservesAddOutput message.
///
/// Received by partners when an operator adds a reserves output to the ledger.
/// This establishes the initial reserves backing for the ledger.
/// The partner validates the message and signs the ledger update (porcupine dance).
///
/// # Arguments
/// * `ctx` - Handler context providing access to ledgers and messaging
/// * `msg` - The reserves add output message
/// * `sender` - Public key of the message sender (should be the operator)
///
/// # Returns
/// * `HandlerResult::Response(ReservesAddOutputValidated)` - Valid, partner should sign and ACK
/// * `HandlerResult::Rejected(reason)` - Invalid with explanation
/// * `HandlerError` - Internal error during processing
pub fn handle_reserves_add_output<C: HandlerContext>(
    ctx: &C,
    msg: &ReservesAddOutputMsg,
    sender: PublicKey,
) -> Result<HandlerResult, HandlerError> {
    let our_node_id = ctx.our_node_id();

    // We must be the partner to process this message
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

    // Validate and get current state
    let (sequence, prev_hash, new_hash) = {
        let ledger = ledger_arc.read().map_err(|_| {
            HandlerError::Internal("Failed to acquire ledger read lock".to_string())
        })?;

        // Check for idempotency - if reserves output already exists with same amount
        if ledger.state.reserves_amount > 0 {
            return Ok(HandlerResult::Response(
                ResponseData::ReservesAddOutputValidated {
                    operator: sender,
                    reserves_id: msg.reserves_id.clone(),
                    initial_amount: msg.initial_amount,
                    spend_to: msg.spend_to,
                    quorum_members: msg.quorum_members.clone(),
                    sequence: ledger.sequence(),
                    prev_hash: ledger.hash(),
                    new_hash: ledger.hash(),
                },
            ));
        }

        // Validate the reserves add operation
        validate_reserves_add(msg.initial_amount).map_err(HandlerError::ValidationFailed)?;

        // Return current state for response
        (ledger.sequence(), ledger.hash(), ledger.hash())
    };

    // Return validated data for LDK layer to record to ledger and sign
    Ok(HandlerResult::Response(
        ResponseData::ReservesAddOutputValidated {
            operator: sender,
            reserves_id: msg.reserves_id.clone(),
            initial_amount: msg.initial_amount,
            spend_to: msg.spend_to,
            quorum_members: msg.quorum_members.clone(),
            sequence,
            prev_hash,
            new_hash,
        },
    ))
}

/// Handle a ReservesRemoveOutput message.
///
/// Received by partners when an operator removes the reserves output from the ledger.
/// This is typically done when closing the ledger or transitioning to a new reserves setup.
/// The partner validates the message and signs the ledger update (porcupine dance).
///
/// # Arguments
/// * `ctx` - Handler context providing access to ledgers and messaging
/// * `msg` - The reserves remove output message
/// * `sender` - Public key of the message sender (should be the operator)
///
/// # Returns
/// * `HandlerResult::Response(ReservesRemoveOutputValidated)` - Valid, partner should sign and ACK
/// * `HandlerResult::Rejected(reason)` - Invalid with explanation
/// * `HandlerError` - Internal error during processing
pub fn handle_reserves_remove_output<C: HandlerContext>(
    ctx: &C,
    msg: &ReservesRemoveOutputMsg,
    sender: PublicKey,
) -> Result<HandlerResult, HandlerError> {
    let our_node_id = ctx.our_node_id();

    // We must be the partner to process this message
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

    // Validate and get current state
    let (sequence, prev_hash, new_hash) = {
        let ledger = ledger_arc.read().map_err(|_| {
            HandlerError::Internal("Failed to acquire ledger read lock".to_string())
        })?;

        // Check for idempotency - if reserves output already removed
        if ledger.state.reserves_amount == 0 {
            return Ok(HandlerResult::Response(
                ResponseData::ReservesRemoveOutputValidated {
                    operator: sender,
                    reserves_id: msg.reserves_id.clone(),
                    sequence: ledger.sequence(),
                    prev_hash: ledger.hash(),
                    new_hash: ledger.hash(),
                },
            ));
        }

        // Validate: cannot remove reserves if there are active deposits
        let total_deposits: u64 = ledger.state.deposits.values().map(|d| d.balance).sum();
        if total_deposits > 0 {
            return Ok(HandlerResult::Rejected(format!(
                "Cannot remove reserves output with {} sats in active deposits",
                total_deposits
            )));
        }

        // Return current state for response
        (ledger.sequence(), ledger.hash(), ledger.hash())
    };

    // Return validated data for LDK layer to record to ledger and sign
    Ok(HandlerResult::Response(
        ResponseData::ReservesRemoveOutputValidated {
            operator: sender,
            reserves_id: msg.reserves_id.clone(),
            sequence,
            prev_hash,
            new_hash,
        },
    ))
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

    // ========================================================================
    // Reserves Add Output Tests
    // ========================================================================

    #[test]
    fn test_handle_reserves_add_output_wrong_partner() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let other_partner = create_test_pubkey(3);
        let spend_to = create_test_pubkey(4);

        let ctx = TestContext::new(our_node_id);

        let msg = ReservesAddOutputMsg {
            initial_amount: 100_000,
            spend_to,
            reserves_id: other_partner.to_string(), // Not us
            quorum_members: vec![],
        };

        // We're not the target partner - should be rejected
        let result = handle_reserves_add_output(&ctx, &msg, operator);
        assert!(matches!(result, Ok(HandlerResult::Rejected(_))));
    }

    #[test]
    fn test_handle_reserves_add_output_no_ledger() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let spend_to = create_test_pubkey(3);

        let ctx = TestContext::new(our_node_id);

        let msg = ReservesAddOutputMsg {
            initial_amount: 100_000,
            spend_to,
            reserves_id: our_node_id.to_string(),
            quorum_members: vec![],
        };

        // No ledger - should error
        let result = handle_reserves_add_output(&ctx, &msg, operator);
        assert!(matches!(result, Err(HandlerError::LedgerNotFound { .. })));
    }

    #[test]
    fn test_handle_reserves_add_output_valid() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let spend_to = create_test_pubkey(3);

        let mut ctx = TestContext::new(our_node_id);

        // Create a ledger with no reserves
        let ledger = Ledger::new(
            operator,
            our_node_id.to_string(),
            LedgerRole::Partner,
            vec![],
            0,
        );
        ctx.add_ledger(operator, our_node_id, ledger);

        let msg = ReservesAddOutputMsg {
            initial_amount: 100_000,
            spend_to,
            reserves_id: our_node_id.to_string(),
            quorum_members: vec![],
        };

        // Valid request - should return response
        let result = handle_reserves_add_output(&ctx, &msg, operator);
        match result {
            Ok(HandlerResult::Response(ResponseData::ReservesAddOutputValidated {
                initial_amount,
                ..
            })) => {
                assert_eq!(initial_amount, 100_000);
            }
            other => panic!(
                "Expected Response(ReservesAddOutputValidated), got {:?}",
                other
            ),
        }
    }

    #[test]
    fn test_handle_reserves_add_output_amount_too_small() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let spend_to = create_test_pubkey(3);

        let mut ctx = TestContext::new(our_node_id);

        // Create a ledger with no reserves
        let ledger = Ledger::new(
            operator,
            our_node_id.to_string(),
            LedgerRole::Partner,
            vec![],
            0,
        );
        ctx.add_ledger(operator, our_node_id, ledger);

        let msg = ReservesAddOutputMsg {
            initial_amount: 100, // Too small
            spend_to,
            reserves_id: our_node_id.to_string(),
            quorum_members: vec![],
        };

        // Amount too small - should fail validation
        let result = handle_reserves_add_output(&ctx, &msg, operator);
        assert!(matches!(result, Err(HandlerError::ValidationFailed(_))));
    }

    #[test]
    fn test_handle_reserves_add_output_idempotent() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let spend_to = create_test_pubkey(3);

        let mut ctx = TestContext::new(our_node_id);

        // Create a ledger that already has reserves
        let mut ledger = Ledger::new(
            operator,
            our_node_id.to_string(),
            LedgerRole::Partner,
            vec![],
            0,
        );
        ledger.state.reserves_amount = 100_000;
        ctx.add_ledger(operator, our_node_id, ledger);

        let msg = ReservesAddOutputMsg {
            initial_amount: 100_000,
            spend_to,
            reserves_id: our_node_id.to_string(),
            quorum_members: vec![],
        };

        // Already exists - should return success (idempotent)
        let result = handle_reserves_add_output(&ctx, &msg, operator);
        match result {
            Ok(HandlerResult::Response(ResponseData::ReservesAddOutputValidated { .. })) => {}
            other => panic!(
                "Expected Response(ReservesAddOutputValidated), got {:?}",
                other
            ),
        }
    }

    // ========================================================================
    // Reserves Remove Output Tests
    // ========================================================================

    #[test]
    fn test_handle_reserves_remove_output_wrong_partner() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let other_partner = create_test_pubkey(3);

        let ctx = TestContext::new(our_node_id);

        let msg = ReservesRemoveOutputMsg {
            reserves_id: other_partner.to_string(), // Not us
            remove_all: true,
        };

        // We're not the target partner - should be rejected
        let result = handle_reserves_remove_output(&ctx, &msg, operator);
        assert!(matches!(result, Ok(HandlerResult::Rejected(_))));
    }

    #[test]
    fn test_handle_reserves_remove_output_no_ledger() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);

        let ctx = TestContext::new(our_node_id);

        let msg = ReservesRemoveOutputMsg {
            reserves_id: our_node_id.to_string(),
            remove_all: true,
        };

        // No ledger - should error
        let result = handle_reserves_remove_output(&ctx, &msg, operator);
        assert!(matches!(result, Err(HandlerError::LedgerNotFound { .. })));
    }

    #[test]
    fn test_handle_reserves_remove_output_valid() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let _spend_to = create_test_pubkey(3);

        let mut ctx = TestContext::new(our_node_id);

        // Create a ledger with reserves but no deposits
        let mut ledger = Ledger::new(
            operator,
            our_node_id.to_string(),
            LedgerRole::Partner,
            vec![],
            0,
        );
        ledger.state.reserves_amount = 100_000;
        ctx.add_ledger(operator, our_node_id, ledger);

        let msg = ReservesRemoveOutputMsg {
            reserves_id: our_node_id.to_string(),
            remove_all: true,
        };

        // Valid request - should return response
        let result = handle_reserves_remove_output(&ctx, &msg, operator);
        match result {
            Ok(HandlerResult::Response(ResponseData::ReservesRemoveOutputValidated { .. })) => {}
            other => panic!(
                "Expected Response(ReservesRemoveOutputValidated), got {:?}",
                other
            ),
        }
    }

    #[test]
    fn test_handle_reserves_remove_output_has_active_deposits() {
        use crate::types::Deposit;

        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let _spend_to = create_test_pubkey(3);
        let deposit_pubkey = create_test_pubkey(4);

        let mut ctx = TestContext::new(our_node_id);

        // Create a ledger with reserves and active deposits
        let mut ledger = Ledger::new(
            operator,
            our_node_id.to_string(),
            LedgerRole::Partner,
            vec![],
            0,
        );
        ledger.state.reserves_amount = 100_000;
        let mut deposit = Deposit::from_pubkey(&deposit_pubkey, None);
        deposit.balance = 50_000;
        ledger.state.deposits.insert(deposit.deposit_id, deposit);
        ctx.add_ledger(operator, our_node_id, ledger);

        let msg = ReservesRemoveOutputMsg {
            reserves_id: our_node_id.to_string(),
            remove_all: true,
        };

        // Has active deposits - should be rejected
        let result = handle_reserves_remove_output(&ctx, &msg, operator);
        assert!(matches!(result, Ok(HandlerResult::Rejected(_))));
    }

    #[test]
    fn test_handle_reserves_remove_output_idempotent() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);

        let mut ctx = TestContext::new(our_node_id);

        // Create a ledger with no reserves (already removed)
        let ledger = Ledger::new(
            operator,
            our_node_id.to_string(),
            LedgerRole::Partner,
            vec![],
            0,
        );
        ctx.add_ledger(operator, our_node_id, ledger);

        let msg = ReservesRemoveOutputMsg {
            reserves_id: our_node_id.to_string(),
            remove_all: true,
        };

        // Already removed - should return success (idempotent)
        let result = handle_reserves_remove_output(&ctx, &msg, operator);
        match result {
            Ok(HandlerResult::Response(ResponseData::ReservesRemoveOutputValidated { .. })) => {}
            other => panic!(
                "Expected Response(ReservesRemoveOutputValidated), got {:?}",
                other
            ),
        }
    }
}
