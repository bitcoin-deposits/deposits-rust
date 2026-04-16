use super::*;

// ============================================================================
// Payment Message Handlers
// ============================================================================

/// Handle a ReceivingCreditPayment message.
///
/// Received by partners when an operator credits a deposit after receiving
/// a Lightning payment. The partner validates the credit and signs the ledger
/// update (porcupine dance).
///
/// # Arguments
/// * `ctx` - Handler context providing access to ledgers and messaging
/// * `msg` - The credit payment message
/// * `sender` - Public key of the message sender (should be the operator)
///
/// # Returns
/// * `HandlerResult::Response(CreditPaymentValidated)` - Credit is valid, partner should sign and ACK
/// * `HandlerResult::Rejected(reason)` - Credit is invalid with explanation
/// * `HandlerError` - Internal error during processing
pub fn handle_receiving_credit_payment<C: HandlerContext>(
    ctx: &C,
    msg: &ReceivingCreditPaymentMsg,
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

    // Validate the credit payment
    {
        let ledger = ledger_arc.read().map_err(|_| {
            HandlerError::Internal("Failed to acquire ledger read lock".to_string())
        })?;

        validate_credit_payment(&ledger, msg.deposit_pubkey, msg.amount, &msg.payment_hash)
            .map_err(HandlerError::ValidationFailed)?;
    }

    // Emit event for credit being received
    ctx.emit_event(ProtocolEvent::InvoiceCredited {
        operator: sender,
        reserves_id: msg.reserves_id.clone(),
        deposit_pubkey: msg.deposit_pubkey,
        amount: msg.amount,
        payment_hash: msg.payment_hash,
    });

    // Return validated data for LDK layer to record to ledger and sign
    Ok(HandlerResult::Response(
        ResponseData::CreditPaymentValidated {
            operator: sender,
            reserves_id: msg.reserves_id.clone(),
            deposit_pubkey: msg.deposit_pubkey,
            amount: msg.amount,
            payment_hash: msg.payment_hash,
            invoice_id: msg.invoice_id.clone(),
            sequence_number: msg.sequence_number,
        },
    ))
}

/// Handle a SendingLockPayment message.
///
/// Received by partners when an operator locks balance for an outbound payment.
/// The partner validates the lock and signs the ledger update.
///
/// # Arguments
/// * `ctx` - Handler context providing access to ledgers and messaging
/// * `msg` - The lock payment message
/// * `sender` - Public key of the message sender (should be the operator)
///
/// # Returns
/// * `HandlerResult::Response(LockPaymentValidated)` - Lock is valid, partner should sign and ACK
/// * `HandlerResult::Rejected(reason)` - Lock is invalid with explanation
/// * `HandlerError` - Internal error during processing
pub fn handle_sending_lock_payment<C: HandlerContext>(
    ctx: &C,
    msg: &SendingLockPaymentMsg,
    sender: PublicKey,
) -> Result<HandlerResult, HandlerError> {
    let our_node_id = ctx.our_node_id();

    // Get the ledger - sender (operator) and us (partner)
    let ledger_arc =
        ctx.get_ledger(&sender, &our_node_id.to_string())
            .ok_or(HandlerError::LedgerNotFound {
                operator: sender,
                reserves_id: our_node_id.to_string(),
            })?;

    // Validate the payment lock
    {
        let ledger = ledger_arc.read().map_err(|_| {
            HandlerError::Internal("Failed to acquire ledger read lock".to_string())
        })?;

        validate_payment_lock(
            &ledger,
            msg.pubkey,
            msg.amount,
            &msg.payment_id,
            &msg.scriptpubkey_signature,
        )
        .map_err(HandlerError::ValidationFailed)?;
    }

    // Return validated data for LDK layer to record to ledger and sign
    Ok(HandlerResult::Response(
        ResponseData::LockPaymentValidated {
            operator: sender,
            reserves_id: our_node_id.to_string(),
            deposit_pubkey: msg.pubkey,
            amount: msg.amount,
            payment_id: msg.payment_id,
            sequence_number: msg.sequence_number,
        },
    ))
}

/// Handle a SendingFulfillPayment message.
///
/// Received by partners when an operator fulfills a payment (preimage received).
/// The partner validates the fulfill and signs the ledger update.
///
/// # Arguments
/// * `ctx` - Handler context providing access to ledgers and messaging
/// * `msg` - The fulfill payment message
/// * `sender` - Public key of the message sender (should be the operator)
///
/// # Returns
/// * `HandlerResult::Response(FulfillPaymentValidated)` - Fulfill is valid, partner should sign and ACK
/// * `HandlerResult::Rejected(reason)` - Fulfill is invalid with explanation
/// * `HandlerError` - Internal error during processing
pub fn handle_sending_fulfill_payment<C: HandlerContext>(
    ctx: &C,
    msg: &SendingFulfillPaymentMsg,
    sender: PublicKey,
) -> Result<HandlerResult, HandlerError> {
    let our_node_id = ctx.our_node_id();

    // Get the ledger - sender (operator) and us (partner)
    let ledger_arc =
        ctx.get_ledger(&sender, &our_node_id.to_string())
            .ok_or(HandlerError::LedgerNotFound {
                operator: sender,
                reserves_id: our_node_id.to_string(),
            })?;

    // Validate the payment fulfill - verifies preimage matches payment_id
    validate_payment_fulfill(
        &msg.pubkey,
        msg.amount,
        &msg.payment_id,
        &msg.scriptpubkey_signature,
        &msg.preimage,
    )
    .map_err(HandlerError::ValidationFailed)?;

    // Also verify deposit exists in ledger
    {
        let ledger = ledger_arc.read().map_err(|_| {
            HandlerError::Internal("Failed to acquire ledger read lock".to_string())
        })?;

        // Convert pubkey to deposit_id for lookup
        let descriptor = format!("pk({})", hex::encode(msg.pubkey.serialize()));
        let deposit_id = crate::types::compute_deposit_id(&descriptor);
        if !ledger.state.deposits.contains_key(&deposit_id) {
            return Ok(HandlerResult::Rejected(format!(
                "Deposit with pubkey {} does not exist",
                msg.pubkey
            )));
        }
    }

    // Emit event for payment being sent
    ctx.emit_event(ProtocolEvent::InvoiceSent {
        operator: sender,
        reserves_id: our_node_id.to_string(),
        deposit_pubkey: msg.pubkey,
        amount: msg.amount,
        payment_id: msg.payment_id,
    });

    // Return validated data for LDK layer to record to ledger and sign
    Ok(HandlerResult::Response(
        ResponseData::FulfillPaymentValidated {
            operator: sender,
            reserves_id: our_node_id.to_string(),
            deposit_pubkey: msg.pubkey,
            amount: msg.amount,
            payment_id: msg.payment_id,
            preimage: msg.preimage,
            sequence_number: msg.sequence_number,
        },
    ))
}

/// Handle a SendingFailPayment message.
///
/// Received by partners when an operator fails a payment (payment didn't complete).
/// The partner validates the fail and signs the ledger update to unlock the balance.
///
/// # Arguments
/// * `ctx` - Handler context providing access to ledgers and messaging
/// * `msg` - The fail payment message
/// * `sender` - Public key of the message sender (should be the operator)
///
/// # Returns
/// * `HandlerResult::Response(FailPaymentValidated)` - Fail is valid, partner should sign and ACK
/// * `HandlerResult::Rejected(reason)` - Fail is invalid with explanation
/// * `HandlerError` - Internal error during processing
pub fn handle_sending_fail_payment<C: HandlerContext>(
    ctx: &C,
    msg: &SendingFailPaymentMsg,
    sender: PublicKey,
) -> Result<HandlerResult, HandlerError> {
    let our_node_id = ctx.our_node_id();

    // Get the ledger - sender (operator) and us (partner)
    let ledger_arc =
        ctx.get_ledger(&sender, &our_node_id.to_string())
            .ok_or(HandlerError::LedgerNotFound {
                operator: sender,
                reserves_id: our_node_id.to_string(),
            })?;

    // Validate the payment fail
    validate_payment_fail(msg.amount).map_err(HandlerError::ValidationFailed)?;

    // Also verify deposit exists in ledger
    {
        let ledger = ledger_arc.read().map_err(|_| {
            HandlerError::Internal("Failed to acquire ledger read lock".to_string())
        })?;

        // Convert pubkey to deposit_id for lookup
        let descriptor = format!("pk({})", hex::encode(msg.pubkey.serialize()));
        let deposit_id = crate::types::compute_deposit_id(&descriptor);
        if !ledger.state.deposits.contains_key(&deposit_id) {
            return Ok(HandlerResult::Rejected(format!(
                "Deposit with pubkey {} does not exist",
                msg.pubkey
            )));
        }
    }

    // Return validated data for LDK layer to record to ledger and sign
    Ok(HandlerResult::Response(
        ResponseData::FailPaymentValidated {
            operator: sender,
            reserves_id: our_node_id.to_string(),
            deposit_pubkey: msg.pubkey,
            amount: msg.amount,
            payment_id: msg.payment_id,
            sequence_number: msg.sequence_number,
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

    /// Insert a dummy collateral attestation so total_collateral() returns the given amount.
    fn set_test_collateral(ledger: &mut Ledger, amount: u64) {
        use crate::types::CollateralAttestation;
        let dummy_key = create_test_pubkey(99);
        ledger.state.collateral_attestations.insert(
            dummy_key,
            CollateralAttestation::new(
                dummy_key,
                dummy_key,
                String::new(),
                amount,
                0,
                0,
                [0u8; 64],
                [0u8; 32],
            ),
        );
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
    // Receiving Credit Payment Tests
    // ========================================================================

    #[test]
    fn test_handle_receiving_credit_payment_wrong_partner() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let other_partner = create_test_pubkey(3);
        let deposit_pubkey = create_test_pubkey(4);

        let ctx = TestContext::new(our_node_id);

        let msg = ReceivingCreditPaymentMsg {
            payment_hash: [0xAB; 32],
            deposit_pubkey,
            amount: 100_000,
            invoice_id: "test_invoice".to_string(),
            reserves_id: other_partner.to_string(), // Not us
            sequence_number: 0,
        };

        // We're not the target partner - should be rejected
        let result = handle_receiving_credit_payment(&ctx, &msg, operator);
        assert!(matches!(result, Ok(HandlerResult::Rejected(_))));
    }

    #[test]
    fn test_handle_receiving_credit_payment_no_ledger() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let deposit_pubkey = create_test_pubkey(3);

        let ctx = TestContext::new(our_node_id);

        let msg = ReceivingCreditPaymentMsg {
            payment_hash: [0xAB; 32],
            deposit_pubkey,
            amount: 100_000,
            invoice_id: "test_invoice".to_string(),
            reserves_id: our_node_id.to_string(),
            sequence_number: 0,
        };

        // No ledger exists - should error
        let result = handle_receiving_credit_payment(&ctx, &msg, operator);
        assert!(matches!(result, Err(HandlerError::LedgerNotFound { .. })));
    }

    #[test]
    fn test_handle_receiving_credit_payment_deposit_not_found() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let deposit_pubkey = create_test_pubkey(3);

        let mut ctx = TestContext::new(our_node_id);

        // Create a ledger without the deposit
        let mut ledger = Ledger::new(
            operator,
            our_node_id.to_string(),
            LedgerRole::Partner,
            vec![],
            0,
        );
        ledger.state.reserves_amount = 100_000;
        set_test_collateral(&mut ledger, 100_000);
        ctx.add_ledger(operator, our_node_id, ledger);

        // Create payment hash that's not all the same byte
        let mut payment_hash = [0u8; 32];
        for i in 0..32 {
            payment_hash[i] = i as u8;
        }

        let msg = ReceivingCreditPaymentMsg {
            payment_hash,
            deposit_pubkey, // This deposit doesn't exist
            amount: 50_000,
            invoice_id: "test_invoice".to_string(),
            reserves_id: our_node_id.to_string(),
            sequence_number: 0,
        };

        // Deposit not found - should fail validation
        let result = handle_receiving_credit_payment(&ctx, &msg, operator);
        assert!(matches!(result, Err(HandlerError::ValidationFailed(_))));
    }

    #[test]
    fn test_handle_receiving_credit_payment_valid() {
        use crate::types::Deposit;

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
        ledger.state.reserves_amount = 100_000;
        set_test_collateral(&mut ledger, 100_000);
        let deposit = Deposit::from_pubkey(&deposit_pubkey, None);
        ledger.state.deposits.insert(deposit.deposit_id, deposit);
        ctx.add_ledger(operator, our_node_id, ledger);

        // Create payment hash that's not all the same byte
        let mut payment_hash = [0u8; 32];
        for i in 0..32 {
            payment_hash[i] = i as u8;
        }

        let msg = ReceivingCreditPaymentMsg {
            payment_hash,
            deposit_pubkey,
            amount: 50_000,
            invoice_id: "test_invoice".to_string(),
            reserves_id: our_node_id.to_string(),
            sequence_number: 0,
        };

        // Valid credit - should return CreditPaymentValidated
        let result = handle_receiving_credit_payment(&ctx, &msg, operator);
        match result {
            Ok(HandlerResult::Response(ResponseData::CreditPaymentValidated {
                amount, ..
            })) => {
                assert_eq!(amount, 50_000);
            }
            other => panic!("Expected Response(CreditPaymentValidated), got {:?}", other),
        }

        // Check that event was emitted
        let events = ctx.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        match &events[0] {
            ProtocolEvent::InvoiceCredited { amount: amt, .. } => {
                assert_eq!(*amt, 50_000);
            }
            other => panic!("Expected InvoiceCredited event, got {:?}", other),
        }
    }

    // ========================================================================
    // Sending Lock Payment Tests
    // ========================================================================

    #[test]
    fn test_handle_sending_lock_payment_no_ledger() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let deposit_pubkey = create_test_pubkey(3);

        let ctx = TestContext::new(our_node_id);

        let msg = SendingLockPaymentMsg {
            pubkey: deposit_pubkey,
            amount: 50_000,
            payment_id: [0xAB; 32],
            sequence_number: 0,
            scriptpubkey_signature: [0u8; 64], // Placeholder accepted during dev
        };

        // No ledger exists - should error
        let result = handle_sending_lock_payment(&ctx, &msg, operator);
        assert!(matches!(result, Err(HandlerError::LedgerNotFound { .. })));
    }

    #[test]
    fn test_handle_sending_lock_payment_deposit_not_found() {
        use crate::types::Deposit;

        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let deposit_pubkey = create_test_pubkey(3);
        let other_deposit = create_test_pubkey(4);

        let mut ctx = TestContext::new(our_node_id);

        // Create a ledger with a different deposit
        let mut ledger = Ledger::new(
            operator,
            our_node_id.to_string(),
            LedgerRole::Partner,
            vec![],
            0,
        );
        let deposit = Deposit::from_pubkey(&other_deposit, None);
        ledger.state.deposits.insert(deposit.deposit_id, deposit);
        ctx.add_ledger(operator, our_node_id, ledger);

        let msg = SendingLockPaymentMsg {
            pubkey: deposit_pubkey, // Different deposit
            amount: 50_000,
            payment_id: [0xAB; 32],
            sequence_number: 0,
            scriptpubkey_signature: [0u8; 64],
        };

        // Deposit not found - should fail validation
        let result = handle_sending_lock_payment(&ctx, &msg, operator);
        assert!(matches!(result, Err(HandlerError::ValidationFailed(_))));
    }

    #[test]
    fn test_handle_sending_lock_payment_insufficient_balance() {
        use crate::types::Deposit;

        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let deposit_pubkey = create_test_pubkey(3);

        let mut ctx = TestContext::new(our_node_id);

        // Create a ledger with a deposit that has low balance
        let mut ledger = Ledger::new(
            operator,
            our_node_id.to_string(),
            LedgerRole::Partner,
            vec![],
            0,
        );
        let mut deposit = Deposit::from_pubkey(&deposit_pubkey, None);
        deposit.balance = 10_000; // Low balance
        ledger.state.deposits.insert(deposit.deposit_id, deposit);
        ctx.add_ledger(operator, our_node_id, ledger);

        let msg = SendingLockPaymentMsg {
            pubkey: deposit_pubkey,
            amount: 50_000, // More than balance
            payment_id: [0xAB; 32],
            sequence_number: 0,
            scriptpubkey_signature: [0u8; 64],
        };

        // Insufficient balance - should fail validation
        let result = handle_sending_lock_payment(&ctx, &msg, operator);
        assert!(matches!(result, Err(HandlerError::ValidationFailed(_))));
    }

    #[test]
    fn test_handle_sending_lock_payment_valid() {
        use crate::types::Deposit;

        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let deposit_pubkey = create_test_pubkey(3);

        let mut ctx = TestContext::new(our_node_id);

        // Create a ledger with a deposit that has sufficient balance
        let mut ledger = Ledger::new(
            operator,
            our_node_id.to_string(),
            LedgerRole::Partner,
            vec![],
            0,
        );
        let mut deposit = Deposit::from_pubkey(&deposit_pubkey, None);
        deposit.balance = 100_000;
        ledger.state.deposits.insert(deposit.deposit_id, deposit);
        ctx.add_ledger(operator, our_node_id, ledger);

        let msg = SendingLockPaymentMsg {
            pubkey: deposit_pubkey,
            amount: 50_000,
            payment_id: [0xAB; 32],
            sequence_number: 0,
            scriptpubkey_signature: [0u8; 64], // Placeholder accepted during dev
        };

        // Valid lock - should return LockPaymentValidated
        let result = handle_sending_lock_payment(&ctx, &msg, operator);
        match result {
            Ok(HandlerResult::Response(ResponseData::LockPaymentValidated { amount, .. })) => {
                assert_eq!(amount, 50_000);
            }
            other => panic!("Expected Response(LockPaymentValidated), got {:?}", other),
        }
    }

    // ========================================================================
    // Sending Fulfill Payment Tests
    // ========================================================================

    #[test]
    fn test_handle_sending_fulfill_payment_no_ledger() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let deposit_pubkey = create_test_pubkey(3);

        let ctx = TestContext::new(our_node_id);

        let msg = SendingFulfillPaymentMsg {
            pubkey: deposit_pubkey,
            amount: 50_000,
            payment_id: [0xAB; 32],
            sequence_number: 0,
            scriptpubkey_signature: [0u8; 64],
            preimage: [0x42; 32],
        };

        // No ledger exists - should error
        let result = handle_sending_fulfill_payment(&ctx, &msg, operator);
        assert!(matches!(result, Err(HandlerError::LedgerNotFound { .. })));
    }

    #[test]
    fn test_handle_sending_fulfill_payment_invalid_preimage() {
        use crate::types::Deposit;

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

        // Create a preimage that doesn't match the payment_id
        let preimage = [42u8; 32];
        let wrong_payment_id = [0xAB; 32]; // Doesn't match SHA256(preimage)

        let msg = SendingFulfillPaymentMsg {
            pubkey: deposit_pubkey,
            amount: 50_000,
            payment_id: wrong_payment_id,
            sequence_number: 0,
            scriptpubkey_signature: [0u8; 64],
            preimage,
        };

        // Invalid preimage - should fail validation
        let result = handle_sending_fulfill_payment(&ctx, &msg, operator);
        assert!(matches!(result, Err(HandlerError::ValidationFailed(_))));
    }

    #[test]
    fn test_handle_sending_fulfill_payment_valid() {
        use crate::types::Deposit;
        use bitcoin::hashes::{sha256, Hash};

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
        let mut deposit = Deposit::from_pubkey(&deposit_pubkey, None);
        deposit.balance = 100_000;
        ledger.state.deposits.insert(deposit.deposit_id, deposit);
        ctx.add_ledger(operator, our_node_id, ledger);

        // Create a valid preimage and compute its hash
        let preimage = [42u8; 32];
        let payment_hash = sha256::Hash::hash(&preimage);

        let msg = SendingFulfillPaymentMsg {
            pubkey: deposit_pubkey,
            amount: 50_000,
            payment_id: *payment_hash.as_byte_array(),
            sequence_number: 0,
            scriptpubkey_signature: [0u8; 64], // Placeholder accepted during dev
            preimage,
        };

        // Valid fulfill - should return FulfillPaymentValidated
        let result = handle_sending_fulfill_payment(&ctx, &msg, operator);
        match result {
            Ok(HandlerResult::Response(ResponseData::FulfillPaymentValidated {
                amount,
                preimage: p,
                ..
            })) => {
                assert_eq!(amount, 50_000);
                assert_eq!(p, preimage);
            }
            other => panic!(
                "Expected Response(FulfillPaymentValidated), got {:?}",
                other
            ),
        }

        // Check that event was emitted
        let events = ctx.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        match &events[0] {
            ProtocolEvent::InvoiceSent { amount: amt, .. } => {
                assert_eq!(*amt, 50_000);
            }
            other => panic!("Expected InvoiceSent event, got {:?}", other),
        }
    }

    // ========================================================================
    // Sending Fail Payment Tests
    // ========================================================================

    #[test]
    fn test_handle_sending_fail_payment_no_ledger() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let deposit_pubkey = create_test_pubkey(3);

        let ctx = TestContext::new(our_node_id);

        let msg = SendingFailPaymentMsg {
            pubkey: deposit_pubkey,
            amount: 50_000,
            payment_id: [0xAB; 32],
            sequence_number: 0,
        };

        // No ledger exists - should error
        let result = handle_sending_fail_payment(&ctx, &msg, operator);
        assert!(matches!(result, Err(HandlerError::LedgerNotFound { .. })));
    }

    #[test]
    fn test_handle_sending_fail_payment_zero_amount() {
        use crate::types::Deposit;

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

        let msg = SendingFailPaymentMsg {
            pubkey: deposit_pubkey,
            amount: 0, // Zero amount
            payment_id: [0xAB; 32],
            sequence_number: 0,
        };

        // Zero amount - should fail validation
        let result = handle_sending_fail_payment(&ctx, &msg, operator);
        assert!(matches!(result, Err(HandlerError::ValidationFailed(_))));
    }

    #[test]
    fn test_handle_sending_fail_payment_deposit_not_found() {
        use crate::types::Deposit;

        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let deposit_pubkey = create_test_pubkey(3);
        let other_deposit = create_test_pubkey(4);

        let mut ctx = TestContext::new(our_node_id);

        // Create a ledger with a different deposit
        let mut ledger = Ledger::new(
            operator,
            our_node_id.to_string(),
            LedgerRole::Partner,
            vec![],
            0,
        );
        let deposit = Deposit::from_pubkey(&other_deposit, None);
        ledger.state.deposits.insert(deposit.deposit_id, deposit);
        ctx.add_ledger(operator, our_node_id, ledger);

        let msg = SendingFailPaymentMsg {
            pubkey: deposit_pubkey, // Different deposit
            amount: 50_000,
            payment_id: [0xAB; 32],
            sequence_number: 0,
        };

        // Deposit not found - should be rejected
        let result = handle_sending_fail_payment(&ctx, &msg, operator);
        assert!(matches!(result, Ok(HandlerResult::Rejected(_))));
    }

    #[test]
    fn test_handle_sending_fail_payment_valid() {
        use crate::types::Deposit;

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

        let msg = SendingFailPaymentMsg {
            pubkey: deposit_pubkey,
            amount: 50_000,
            payment_id: [0xAB; 32],
            sequence_number: 0,
        };

        // Valid fail - should return FailPaymentValidated
        let result = handle_sending_fail_payment(&ctx, &msg, operator);
        match result {
            Ok(HandlerResult::Response(ResponseData::FailPaymentValidated { amount, .. })) => {
                assert_eq!(amount, 50_000);
            }
            other => panic!("Expected Response(FailPaymentValidated), got {:?}", other),
        }
    }
}
