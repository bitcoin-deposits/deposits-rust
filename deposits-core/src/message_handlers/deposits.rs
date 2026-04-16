use super::*;

// ============================================================================
// Deposit Message Handlers
// ============================================================================

/// Handle a DepositOpen message.
///
/// Received by partners when an operator opens a new deposit.
/// The partner validates the deposit and signs the ledger update (porcupine dance).
///
/// # Arguments
/// * `ctx` - Handler context providing access to ledgers and messaging
/// * `msg` - The deposit open message
/// * `sender` - Public key of the message sender (should be the operator)
///
/// # Returns
/// * `HandlerResult::Response(DepositOpenValidated)` - Deposit is valid, partner should sign and ACK
/// * `HandlerResult::Rejected(reason)` - Deposit is invalid with explanation
/// * `HandlerError` - Internal error during processing
pub fn handle_deposit_open<C: HandlerContext>(
    ctx: &C,
    msg: &DepositOpenMsg,
    sender: PublicKey,
) -> Result<HandlerResult, HandlerError> {
    use crate::messages::{LedgerOperation, LEDGER_UPDATE};

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

    // Convert pubkey to descriptor and compute deposit_id
    let descriptor = format!("pk({})", hex::encode(msg.pubkey.serialize()));
    let deposit_id = crate::types::compute_deposit_id(&descriptor);

    let operation = LedgerOperation::DepositOpen {
        deposit_id,
        descriptor: descriptor.clone(),
        fees: msg.fees.clone(),
        transfer_fees: None,
        payment_hash: msg.payment_hash,
        invoice: msg.invoice.clone(),
        cosigner_guarantee_signature: msg.cosigner_guarantee_signature,
        is_collateral: false,
        receive_requires_sig: false,
        fee_change_after_blocks: None,
        fee_change_notice_blocks: None,
        fee_change_limit_bps: None,
    };

    // Check for idempotency and append (single write lock scope)
    let (prev_hash, new_hash, sequence, message_bytes, is_idempotent) = {
        let mut ledger = ledger_arc.write().map_err(|_| {
            HandlerError::Internal("Failed to acquire ledger write lock".to_string())
        })?;

        // Idempotency check
        if ledger.state.deposits.contains_key(&deposit_id) {
            let seq = ledger.sequence();
            let hash = ledger.hash();
            (hash, hash, seq, Vec::new(), true)
        } else {
            // Validate first
            validate_deposit_add_by_id(&ledger, &deposit_id, msg.fees.as_ref())
                .map_err(HandlerError::ValidationFailed)?;

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
    }

    // NOTE: ACK is sent by LDK dispatch code which has access to the correct message hash

    // Emit event
    ctx.emit_event(crate::traits::ProtocolEvent::DepositOpened {
        operator: sender,
        reserves_id: msg.reserves_id.clone(),
        deposit_pubkey: msg.pubkey,
    });

    Ok(HandlerResult::Ok)
}

/// Handle a DepositClose message.
///
/// Received by partners when an operator closes a deposit.
/// This handler does the complete flow: validate, mutate, sign, persist, send ACK.
pub fn handle_deposit_close<C: HandlerContext>(
    ctx: &C,
    msg: &DepositCloseMsg,
    sender: PublicKey,
) -> Result<HandlerResult, HandlerError> {
    use crate::messages::{LedgerOperation, LEDGER_UPDATE};

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

    // Convert pubkey to descriptor and compute deposit_id
    let descriptor = format!("pk({})", hex::encode(msg.pubkey.serialize()));
    let deposit_id = crate::types::compute_deposit_id(&descriptor);

    let operation = LedgerOperation::DepositClose { deposit_id };

    // Check for idempotency and append (single write lock scope)
    let (prev_hash, new_hash, sequence, message_bytes, is_idempotent, final_balance) = {
        let mut ledger = ledger_arc.write().map_err(|_| {
            HandlerError::Internal("Failed to acquire ledger write lock".to_string())
        })?;

        // Idempotency check - if deposit doesn't exist, already closed
        if !ledger.state.deposits.contains_key(&deposit_id) {
            let seq = ledger.sequence();
            let hash = ledger.hash();
            (hash, hash, seq, Vec::new(), true, 0u64)
        } else {
            // Get final balance before close
            let final_balance = ledger
                .state
                .deposits
                .get(&deposit_id)
                .map(|d| d.balance)
                .unwrap_or(0);

            // Validate first
            validate_deposit_close_by_id(&ledger, &deposit_id)
                .map_err(HandlerError::ValidationFailed)?;

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

            (prev, new, seq, bytes, false, final_balance)
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
    }

    // NOTE: ACK is sent by LDK dispatch code which has access to the correct message hash

    // Emit event
    if !is_idempotent {
        ctx.emit_event(crate::traits::ProtocolEvent::DepositClosed {
            operator: sender,
            reserves_id: msg.reserves_id.clone(),
            deposit_pubkey: msg.pubkey,
            final_balance,
        });
    }

    Ok(HandlerResult::Ok)
}

/// Handle a fee change message.
///
/// Received by partners when an operator updates a deposit's fee structure.
/// This handler does the complete flow: validate, mutate, sign, persist, send ACK.
pub fn handle_fee_change<C: HandlerContext>(
    ctx: &C,
    msg: &FeeChangeMsg,
    sender: PublicKey,
) -> Result<HandlerResult, HandlerError> {
    use crate::messages::{LedgerOperation, LEDGER_UPDATE};

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

    // Convert pubkey to descriptor and compute deposit_id
    let descriptor = format!("pk({})", hex::encode(msg.pubkey.serialize()));
    let deposit_id = crate::types::compute_deposit_id(&descriptor);

    let operation = LedgerOperation::FeeChange {
        deposit_id,
        new_fees: msg.new_fees.clone(),
        effective_block: 0,
    };

    // Validate and append (single write lock scope)
    let (prev_hash, new_hash, sequence, message_bytes) = {
        let mut ledger = ledger_arc.write().map_err(|_| {
            HandlerError::Internal("Failed to acquire ledger write lock".to_string())
        })?;

        // Validate first
        validate_fee_change_by_id(&ledger, &deposit_id, &msg.new_fees)
            .map_err(HandlerError::ValidationFailed)?;

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

        (prev, new, seq, bytes)
    };

    // Sign the update
    let partner_sig = if !message_bytes.is_empty() {
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

    // Update signature in ledger and persist
    if let Some(sig) = partner_sig {
        let mut ledger = ledger_arc.write().map_err(|_| {
            HandlerError::Internal("Failed to acquire ledger write lock".to_string())
        })?;
        ledger.sign_last_update(None, Some(sig));
    }
    let _ = ctx.persist_ledger(&sender, &msg.reserves_id);

    // NOTE: ACK is sent by LDK dispatch code which has access to the correct message hash

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

    // ========================================================================
    // Deposit Open Tests
    // ========================================================================

    #[test]
    fn test_handle_deposit_open_wrong_partner() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let other_partner = create_test_pubkey(3);
        let deposit_pubkey = create_test_pubkey(4);

        let ctx = TestContext::new(our_node_id);

        let msg = DepositOpenMsg {
            reserves_id: other_partner.to_string(), // Not us
            pubkey: deposit_pubkey,
            fees: None,
            payment_hash: None,
            invoice: None,
            cosigner_guarantee_signature: None,
        };

        // We're not the target partner - should be rejected
        let result = handle_deposit_open(&ctx, &msg, operator);
        assert!(matches!(result, Ok(HandlerResult::Rejected(_))));
    }

    #[test]
    fn test_handle_deposit_open_no_ledger() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let deposit_pubkey = create_test_pubkey(3);

        let ctx = TestContext::new(our_node_id);

        let msg = DepositOpenMsg {
            reserves_id: our_node_id.to_string(),
            pubkey: deposit_pubkey,
            fees: None,
            payment_hash: None,
            invoice: None,
            cosigner_guarantee_signature: None,
        };

        // No ledger exists - should error
        let result = handle_deposit_open(&ctx, &msg, operator);
        assert!(matches!(result, Err(HandlerError::LedgerNotFound { .. })));
    }

    #[test]
    fn test_handle_deposit_open_valid() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let deposit_pubkey = create_test_pubkey(3);

        let mut ctx = TestContext::new(our_node_id);

        // Create a ledger
        let ledger = Ledger::new(
            operator,
            our_node_id.to_string(),
            LedgerRole::Partner,
            vec![],
            0,
        );
        ctx.add_ledger(operator, our_node_id, ledger);

        let msg = DepositOpenMsg {
            reserves_id: our_node_id.to_string(),
            pubkey: deposit_pubkey,
            fees: None,
            payment_hash: None,
            invoice: None,
            cosigner_guarantee_signature: None,
        };

        // Valid deposit open - should return Ok (handler does complete flow)
        let result = handle_deposit_open(&ctx, &msg, operator);
        assert!(matches!(result, Ok(HandlerResult::Ok)));
    }

    #[test]
    fn test_handle_deposit_open_idempotent() {
        use crate::types::Deposit;

        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let deposit_pubkey = create_test_pubkey(3);

        let mut ctx = TestContext::new(our_node_id);

        // Create a ledger with the deposit already added
        let mut ledger = Ledger::new(
            operator,
            our_node_id.to_string(),
            LedgerRole::Partner,
            vec![],
            0,
        );
        let deposit = Deposit::from_pubkey(&deposit_pubkey, None);
        ledger.state.deposits.insert(deposit.deposit_id, deposit);
        ctx.add_ledger(operator, our_node_id, ledger);

        let msg = DepositOpenMsg {
            reserves_id: our_node_id.to_string(),
            pubkey: deposit_pubkey,
            fees: None,
            payment_hash: None,
            invoice: None,
            cosigner_guarantee_signature: None,
        };

        // Already exists - should return Ok (idempotent success)
        let result = handle_deposit_open(&ctx, &msg, operator);
        assert!(matches!(result, Ok(HandlerResult::Ok)));
    }

    #[test]
    fn test_handle_deposit_open_with_fees() {
        use crate::types::FeeStructure;

        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let deposit_pubkey = create_test_pubkey(3);

        let mut ctx = TestContext::new(our_node_id);

        // Create a ledger
        let ledger = Ledger::new(
            operator,
            our_node_id.to_string(),
            LedgerRole::Partner,
            vec![],
            0,
        );
        ctx.add_ledger(operator, our_node_id, ledger);

        let fees = FeeStructure {
            annualized_msats: 1000,
            annualized_bps: 50,
            frequency_blocks: 144,
        };

        let msg = DepositOpenMsg {
            reserves_id: our_node_id.to_string(),
            pubkey: deposit_pubkey,
            fees: Some(fees),
            payment_hash: None,
            invoice: None,
            cosigner_guarantee_signature: None,
        };

        // Valid deposit open with fees - should succeed
        let result = handle_deposit_open(&ctx, &msg, operator);
        assert!(matches!(result, Ok(HandlerResult::Ok)));
    }

    #[test]
    fn test_handle_deposit_open_invalid_fees() {
        use crate::types::FeeStructure;

        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let deposit_pubkey = create_test_pubkey(3);

        let mut ctx = TestContext::new(our_node_id);

        // Create a ledger
        let ledger = Ledger::new(
            operator,
            our_node_id.to_string(),
            LedgerRole::Partner,
            vec![],
            0,
        );
        ctx.add_ledger(operator, our_node_id, ledger);

        // Invalid fee structure with zero frequency
        let invalid_fees = FeeStructure {
            annualized_msats: 1000,
            annualized_bps: 50,
            frequency_blocks: 0, // Invalid
        };

        let msg = DepositOpenMsg {
            reserves_id: our_node_id.to_string(),
            pubkey: deposit_pubkey,
            fees: Some(invalid_fees),
            payment_hash: None,
            invoice: None,
            cosigner_guarantee_signature: None,
        };

        // Invalid fees - should fail validation
        let result = handle_deposit_open(&ctx, &msg, operator);
        assert!(matches!(result, Err(HandlerError::ValidationFailed(_))));
    }

    // ========================================================================
    // Deposit Close Tests
    // ========================================================================

    #[test]
    fn test_handle_deposit_close_wrong_partner() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let other_partner = create_test_pubkey(3);
        let deposit_pubkey = create_test_pubkey(4);

        let ctx = TestContext::new(our_node_id);

        let msg = DepositCloseMsg {
            reserves_id: other_partner.to_string(), // Not us
            pubkey: deposit_pubkey,
        };

        // We're not the target partner - should be rejected
        let result = handle_deposit_close(&ctx, &msg, operator);
        assert!(matches!(result, Ok(HandlerResult::Rejected(_))));
    }

    #[test]
    fn test_handle_deposit_close_no_ledger() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let deposit_pubkey = create_test_pubkey(3);

        let ctx = TestContext::new(our_node_id);

        let msg = DepositCloseMsg {
            reserves_id: our_node_id.to_string(),
            pubkey: deposit_pubkey,
        };

        // No ledger exists - should error
        let result = handle_deposit_close(&ctx, &msg, operator);
        assert!(matches!(result, Err(HandlerError::LedgerNotFound { .. })));
    }

    #[test]
    fn test_handle_deposit_close_valid() {
        use crate::types::Deposit;

        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let deposit_pubkey = create_test_pubkey(3);

        let mut ctx = TestContext::new(our_node_id);

        // Create a ledger with a deposit that has zero balance
        let mut ledger = Ledger::new(
            operator,
            our_node_id.to_string(),
            LedgerRole::Partner,
            vec![],
            0,
        );
        let deposit = Deposit::from_pubkey(&deposit_pubkey, None); // balance=0 by default
        ledger.state.deposits.insert(deposit.deposit_id, deposit);
        ctx.add_ledger(operator, our_node_id, ledger);

        let msg = DepositCloseMsg {
            reserves_id: our_node_id.to_string(),
            pubkey: deposit_pubkey,
        };

        // Valid deposit close - should return Ok (handler does complete flow)
        let result = handle_deposit_close(&ctx, &msg, operator);
        assert!(matches!(result, Ok(HandlerResult::Ok)));
    }

    #[test]
    fn test_handle_deposit_close_non_zero_balance() {
        use crate::types::Deposit;

        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let deposit_pubkey = create_test_pubkey(3);

        let mut ctx = TestContext::new(our_node_id);

        // Create a ledger with a deposit that has non-zero balance
        let mut ledger = Ledger::new(
            operator,
            our_node_id.to_string(),
            LedgerRole::Partner,
            vec![],
            0,
        );
        let mut deposit = Deposit::from_pubkey(&deposit_pubkey, None);
        deposit.balance = 50_000; // Non-zero balance
        ledger.state.deposits.insert(deposit.deposit_id, deposit);
        ctx.add_ledger(operator, our_node_id, ledger);

        let msg = DepositCloseMsg {
            reserves_id: our_node_id.to_string(),
            pubkey: deposit_pubkey,
        };

        // Non-zero balance - should fail validation
        let result = handle_deposit_close(&ctx, &msg, operator);
        assert!(matches!(result, Err(HandlerError::ValidationFailed(_))));
    }

    #[test]
    fn test_handle_deposit_close_locked_balance() {
        use crate::types::Deposit;

        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let deposit_pubkey = create_test_pubkey(3);

        let mut ctx = TestContext::new(our_node_id);

        // Create a ledger with a deposit that has locked balance
        let mut ledger = Ledger::new(
            operator,
            our_node_id.to_string(),
            LedgerRole::Partner,
            vec![],
            0,
        );
        let mut deposit = Deposit::from_pubkey(&deposit_pubkey, None);
        deposit.locked_balance = 10_000; // Has locked funds
        ledger.state.deposits.insert(deposit.deposit_id, deposit);
        ctx.add_ledger(operator, our_node_id, ledger);

        let msg = DepositCloseMsg {
            reserves_id: our_node_id.to_string(),
            pubkey: deposit_pubkey,
        };

        // Locked balance - should fail validation
        let result = handle_deposit_close(&ctx, &msg, operator);
        assert!(matches!(result, Err(HandlerError::ValidationFailed(_))));
    }

    #[test]
    fn test_handle_deposit_close_idempotent() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let deposit_pubkey = create_test_pubkey(3);

        let mut ctx = TestContext::new(our_node_id);

        // Create a ledger without the deposit (already closed)
        let ledger = Ledger::new(
            operator,
            our_node_id.to_string(),
            LedgerRole::Partner,
            vec![],
            0,
        );
        ctx.add_ledger(operator, our_node_id, ledger);

        let msg = DepositCloseMsg {
            reserves_id: our_node_id.to_string(),
            pubkey: deposit_pubkey,
        };

        // Deposit doesn't exist - should return Ok (idempotent success)
        let result = handle_deposit_close(&ctx, &msg, operator);
        assert!(matches!(result, Ok(HandlerResult::Ok)));
    }

    // ========================================================================
    // Fee Change Tests
    // ========================================================================

    #[test]
    fn test_handle_fee_change_wrong_partner() {
        use crate::types::FeeStructure;

        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let other_partner = create_test_pubkey(3);
        let deposit_pubkey = create_test_pubkey(4);

        let ctx = TestContext::new(our_node_id);

        let msg = FeeChangeMsg {
            reserves_id: other_partner.to_string(), // Not us
            pubkey: deposit_pubkey,
            new_fees: FeeStructure::default(),
        };

        // We're not the target partner - should be rejected
        let result = handle_fee_change(&ctx, &msg, operator);
        assert!(matches!(result, Ok(HandlerResult::Rejected(_))));
    }

    #[test]
    fn test_handle_fee_change_no_ledger() {
        use crate::types::FeeStructure;

        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let deposit_pubkey = create_test_pubkey(3);

        let ctx = TestContext::new(our_node_id);

        let msg = FeeChangeMsg {
            reserves_id: our_node_id.to_string(),
            pubkey: deposit_pubkey,
            new_fees: FeeStructure::default(),
        };

        // No ledger exists - should error
        let result = handle_fee_change(&ctx, &msg, operator);
        assert!(matches!(result, Err(HandlerError::LedgerNotFound { .. })));
    }

    #[test]
    fn test_handle_fee_change_deposit_not_found() {
        use crate::types::FeeStructure;

        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let deposit_pubkey = create_test_pubkey(3);

        let mut ctx = TestContext::new(our_node_id);

        // Create a ledger without the deposit
        let ledger = Ledger::new(
            operator,
            our_node_id.to_string(),
            LedgerRole::Partner,
            vec![],
            0,
        );
        ctx.add_ledger(operator, our_node_id, ledger);

        let msg = FeeChangeMsg {
            reserves_id: our_node_id.to_string(),
            pubkey: deposit_pubkey,
            new_fees: FeeStructure::default(),
        };

        // Deposit not found - should fail validation
        let result = handle_fee_change(&ctx, &msg, operator);
        assert!(matches!(result, Err(HandlerError::ValidationFailed(_))));
    }

    #[test]
    fn test_handle_fee_change_valid() {
        use crate::types::{Deposit, FeeStructure};

        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let deposit_pubkey = create_test_pubkey(3);

        let mut ctx = TestContext::new(our_node_id);

        // Create a ledger with the deposit
        let mut ledger = Ledger::new(
            operator,
            our_node_id.to_string(),
            LedgerRole::Partner,
            vec![],
            0,
        );
        let deposit = Deposit::from_pubkey(&deposit_pubkey, None);
        ledger.state.deposits.insert(deposit.deposit_id, deposit);
        ctx.add_ledger(operator, our_node_id, ledger);

        let new_fees = FeeStructure {
            annualized_msats: 2000,
            annualized_bps: 100,
            frequency_blocks: 288,
        };

        let msg = FeeChangeMsg {
            reserves_id: our_node_id.to_string(),
            pubkey: deposit_pubkey,
            new_fees,
        };

        // Valid fee change - should return Ok (handler does complete flow)
        let result = handle_fee_change(&ctx, &msg, operator);
        assert!(matches!(result, Ok(HandlerResult::Ok)));
    }

    #[test]
    fn test_handle_fee_change_invalid_fees() {
        use crate::types::{Deposit, FeeStructure};

        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let deposit_pubkey = create_test_pubkey(3);

        let mut ctx = TestContext::new(our_node_id);

        // Create a ledger with the deposit
        let mut ledger = Ledger::new(
            operator,
            our_node_id.to_string(),
            LedgerRole::Partner,
            vec![],
            0,
        );
        let deposit = Deposit::from_pubkey(&deposit_pubkey, None);
        ledger.state.deposits.insert(deposit.deposit_id, deposit);
        ctx.add_ledger(operator, our_node_id, ledger);

        // Invalid fee structure with zero frequency
        let invalid_fees = FeeStructure {
            annualized_msats: 2000,
            annualized_bps: 100,
            frequency_blocks: 0, // Invalid
        };

        let msg = FeeChangeMsg {
            reserves_id: our_node_id.to_string(),
            pubkey: deposit_pubkey,
            new_fees: invalid_fees,
        };

        // Invalid fees - should fail validation
        let result = handle_fee_change(&ctx, &msg, operator);
        assert!(matches!(result, Err(HandlerError::ValidationFailed(_))));
    }

    #[test]
    fn test_handle_fee_change_fee_rate_too_high() {
        use crate::types::{Deposit, FeeStructure};

        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let deposit_pubkey = create_test_pubkey(3);

        let mut ctx = TestContext::new(our_node_id);

        // Create a ledger with the deposit
        let mut ledger = Ledger::new(
            operator,
            our_node_id.to_string(),
            LedgerRole::Partner,
            vec![],
            0,
        );
        let deposit = Deposit::from_pubkey(&deposit_pubkey, None);
        ledger.state.deposits.insert(deposit.deposit_id, deposit);
        ctx.add_ledger(operator, our_node_id, ledger);

        // Fee rate too high (over 100%)
        let invalid_fees = FeeStructure {
            annualized_msats: 0,
            annualized_bps: 15000, // 150% - too high
            frequency_blocks: 144,
        };

        let msg = FeeChangeMsg {
            reserves_id: our_node_id.to_string(),
            pubkey: deposit_pubkey,
            new_fees: invalid_fees,
        };

        // Fee rate too high - should fail validation
        let result = handle_fee_change(&ctx, &msg, operator);
        assert!(matches!(result, Err(HandlerError::ValidationFailed(_))));
    }
}
