use super::*;

// ============================================================================
// Fee and Ledger Lifecycle Handlers
// ============================================================================

/// Handle a FeeCollect message.
///
/// Received by partners when an operator collects fees from a deposit.
/// The partner validates the fee collection and signs the ledger update (porcupine dance).
///
/// # Arguments
/// * `ctx` - Handler context providing access to ledgers and messaging
/// * `msg` - The fee collect message
/// * `sender` - Public key of the message sender (should be the operator)
///
/// # Returns
/// * `HandlerResult::Response(FeeCollectValidated)` - Fee collection is valid, partner should sign and ACK
/// * `HandlerResult::Rejected(reason)` - Fee collection is invalid with explanation
/// * `HandlerError` - Internal error during processing
pub fn handle_fee_collect<C: HandlerContext>(
    ctx: &C,
    msg: &FeeCollectMsg,
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

    // Validate the fee collection
    let (sequence, prev_hash, new_hash) = {
        let ledger = ledger_arc.read().map_err(|_| {
            HandlerError::Internal("Failed to acquire ledger read lock".to_string())
        })?;

        // Validate the fee collect operation
        validate_fee_collect(&ledger, msg.pubkey, msg.amount, msg.block_height)
            .map_err(HandlerError::ValidationFailed)?;

        // Return current state for response
        (ledger.sequence(), ledger.hash(), ledger.hash())
    };

    // Emit event for fee collection
    ctx.emit_event(ProtocolEvent::FeeCollected {
        operator: sender,
        reserves_id: our_node_id.to_string(),
        deposit_pubkey: msg.pubkey,
        amount: msg.amount,
        block_height: msg.block_height,
    });

    // Return validated data for LDK layer to record to ledger and sign
    Ok(HandlerResult::Response(ResponseData::FeeCollectValidated {
        operator: sender,
        reserves_id: our_node_id.to_string(),
        deposit_pubkey: msg.pubkey,
        amount: msg.amount,
        block_height: msg.block_height,
        sequence,
        prev_hash,
        new_hash,
    }))
}

/// Handle a LedgerClose message.
///
/// Received by partners when an operator requests to close the ledger relationship.
/// The partner validates that the ledger can be safely closed (no outstanding balances).
///
/// # Arguments
/// * `ctx` - Handler context providing access to ledgers and messaging
/// * `msg` - The ledger close message
/// * `sender` - Public key of the message sender (should be the operator)
///
/// # Returns
/// * `HandlerResult::Response(LedgerCloseValidated)` - Close is valid, partner should sign and ACK
/// * `HandlerResult::Rejected(reason)` - Close is invalid with explanation
/// * `HandlerError` - Internal error during processing
pub fn handle_ledger_close<C: HandlerContext>(
    ctx: &C,
    msg: &LedgerCloseMsg,
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
        ctx.get_ledger(&sender, &our_node_id.to_string())
            .ok_or(HandlerError::LedgerNotFound {
                operator: sender,
                reserves_id: our_node_id.to_string(),
            })?;

    // Validate the ledger close
    let (sequence, prev_hash, new_hash) = {
        let ledger = ledger_arc.read().map_err(|_| {
            HandlerError::Internal("Failed to acquire ledger read lock".to_string())
        })?;

        // Validate the ledger can be closed
        validate_ledger_close(&ledger).map_err(HandlerError::ValidationFailed)?;

        // Return current state for response
        (ledger.sequence(), ledger.hash(), ledger.hash())
    };

    // Emit event for ledger close
    ctx.emit_event(ProtocolEvent::LedgerClosed {
        operator: sender,
        reserves_id: our_node_id.to_string(),
    });

    // Return validated data for LDK layer to record to ledger and sign
    Ok(HandlerResult::Response(
        ResponseData::LedgerCloseValidated {
            operator: sender,
            reserves_id: our_node_id.to_string(),
            sequence,
            prev_hash,
            new_hash,
        },
    ))
}

/// Handle a ReceivingCosignInvoice message.
///
/// Received by partners when an operator requests cosigning an invoice for a deposit.
/// This is part of the invoice cosigning flow where the partner validates and signs
/// the invoice to prove their consent to the incoming payment assignment.
///
/// # Arguments
/// * `ctx` - Handler context providing access to ledgers and messaging
/// * `msg` - The cosign invoice message
/// * `sender` - Public key of the message sender (should be the operator)
///
/// # Returns
/// * `HandlerResult::Response(CosignInvoiceValidated)` - Cosign is valid, partner should sign
/// * `HandlerResult::Rejected(reason)` - Cosign is invalid with explanation
/// * `HandlerError` - Internal error during processing
pub fn handle_receiving_cosign_invoice<C: HandlerContext>(
    ctx: &C,
    msg: &ReceivingCosignInvoiceMsg,
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

    // Validate the cosign invoice request
    {
        let ledger = ledger_arc.read().map_err(|_| {
            HandlerError::Internal("Failed to acquire ledger read lock".to_string())
        })?;

        // Validate the cosign operation
        validate_cosign_invoice(
            &ledger,
            msg.assigned_deposit,
            msg.amount,
            &msg.invoice_id,
            &msg.payment_hash,
        )
        .map_err(HandlerError::ValidationFailed)?;
    }

    // Emit event for invoice cosign request
    ctx.emit_event(ProtocolEvent::InvoiceCosignRequested {
        operator: sender,
        reserves_id: our_node_id.to_string(),
        deposit_pubkey: msg.assigned_deposit,
        amount: msg.amount,
        payment_hash: msg.payment_hash,
    });

    // Return validated data for LDK layer to sign the invoice
    Ok(HandlerResult::Response(
        ResponseData::CosignInvoiceValidated {
            operator: sender,
            reserves_id: our_node_id.to_string(),
            deposit_pubkey: msg.assigned_deposit,
            amount: msg.amount,
            payment_hash: msg.payment_hash,
            invoice_id: msg.invoice_id.clone(),
            bolt11: msg.bolt11.clone(),
        },
    ))
}

// ============================================================================
// Ledger Export Handler
// ============================================================================

/// Handle a ledger export request from a partner or quorum member.
///
/// This handler allows peers to request a complete ledger export for
/// validation purposes. The requester can then validate the ledger
/// using `LedgerConformanceValidator`.
///
/// # Arguments
/// * `ctx` - Handler context providing access to ledgers
/// * `msg` - The export request containing operator_id and reserves_id
/// * `sender` - Public key of the sender
///
/// # Returns
/// * `Ok(HandlerResult::Response(LedgerExportResponse))` - Export data
/// * `Ok(HandlerResult::Rejected(reason))` - Request rejected
/// * `Err(HandlerError)` - Internal error
pub fn handle_ledger_export_request<C: HandlerContext>(
    ctx: &C,
    msg: &crate::wire_messages::LedgerExportRequestMsg,
    sender: PublicKey,
) -> Result<HandlerResult, HandlerError> {
    let our_node_id = ctx.our_node_id();

    // Validate: request should be for us as operator
    if msg.operator_id != our_node_id {
        return Ok(HandlerResult::Response(
            ResponseData::LedgerExportResponse {
                operator_id: msg.operator_id,
                reserves_id: msg.reserves_id.clone(),
                version: 1,
                exported_at: crate::now_unix_timestamp(),
                block_height: msg.block_height,
                update_count: 0,
                updates_data: Vec::new(),
                success: false,
                error_message: Some("We are not the operator of this ledger".to_string()),
            },
        ));
    }

    // Get the ledger
    let ledger = ctx.get_ledger(&msg.operator_id, &msg.reserves_id);
    let ledger = match ledger {
        Some(l) => l,
        None => {
            return Ok(HandlerResult::Response(
                ResponseData::LedgerExportResponse {
                    operator_id: msg.operator_id,
                    reserves_id: msg.reserves_id.clone(),
                    version: 1,
                    exported_at: crate::now_unix_timestamp(),
                    block_height: msg.block_height,
                    update_count: 0,
                    updates_data: Vec::new(),
                    success: false,
                    error_message: Some("Ledger not found".to_string()),
                },
            ));
        }
    };

    // Read the ledger and export
    let ledger_guard = ledger
        .read()
        .map_err(|_| HandlerError::Internal("Lock poisoned".to_string()))?;

    // Validate: sender should be a partner or quorum member
    let is_partner =
        ledger_guard.reserves_key() == sender.to_string() || sender.to_string() == msg.reserves_id;
    let is_quorum_member = ledger_guard
        .state
        .quorum_members
        .iter()
        .any(|m| m.pubkey == sender)
        || ledger_guard
            .state
            .next_quorum_members
            .iter()
            .any(|m| m.pubkey == sender);

    if !is_partner && !is_quorum_member {
        return Ok(HandlerResult::Response(
            ResponseData::LedgerExportResponse {
                operator_id: msg.operator_id,
                reserves_id: msg.reserves_id.clone(),
                version: 1,
                exported_at: crate::now_unix_timestamp(),
                block_height: msg.block_height,
                update_count: 0,
                updates_data: Vec::new(),
                success: false,
                error_message: Some("Sender is not authorized to access this ledger".to_string()),
            },
        ));
    }

    // Create the export
    let export = ledger_guard.export(msg.block_height);

    // Serialize updates with length prefixes
    let mut updates_data = Vec::new();
    for update in &export.updates {
        let update_bytes = bincode::serialize(update).unwrap_or_default();
        // Write length as u32, then data
        updates_data.extend_from_slice(&(update_bytes.len() as u32).to_be_bytes());
        updates_data.extend_from_slice(&update_bytes);
    }

    Ok(HandlerResult::Response(
        ResponseData::LedgerExportResponse {
            operator_id: export.operator_id,
            reserves_id: export.reserves_id,
            version: export.version,
            exported_at: export.exported_at,
            block_height: export.block_height,
            update_count: export.updates.len() as u32,
            updates_data,
            success: true,
            error_message: None,
        },
    ))
}

/// Validate a ledger export received from a peer.
///
/// This is a standalone function that validates a received export
/// without needing a HandlerContext. It can be used by clients
/// to verify a peer's ledger conformance.
///
/// # Arguments
/// * `response` - The ledger export response from the peer
///
/// # Returns
/// * `Ok(ValidationReport)` - Validation succeeded (check is_valid field)
/// * `Err(ValidationError)` - Critical validation failure
pub fn validate_ledger_export_response(
    response: &ResponseData,
) -> Result<crate::validation::ValidationReport, crate::validation::ValidationError> {
    // Extract data from ResponseData
    let (
        operator_id,
        reserves_id,
        version,
        exported_at,
        block_height,
        update_count,
        updates_data,
        success,
        error_message,
    ) = match response {
        ResponseData::LedgerExportResponse {
            operator_id,
            reserves_id,
            version,
            exported_at,
            block_height,
            update_count,
            updates_data,
            success,
            error_message,
        } => (
            *operator_id,
            reserves_id.clone(),
            *version,
            *exported_at,
            *block_height,
            *update_count,
            updates_data.clone(),
            *success,
            error_message.clone(),
        ),
        _ => {
            return Err(crate::validation::ValidationError::DecodeError(
                "Expected LedgerExportResponse".to_string(),
            ));
        }
    };

    // Check for error response
    if !success {
        return Err(crate::validation::ValidationError::DecodeError(
            error_message.unwrap_or_else(|| "Export failed".to_string()),
        ));
    }

    // Deserialize updates
    let mut updates = Vec::new();
    let mut cursor = std::io::Cursor::new(&updates_data);
    use std::io::Read;

    for _ in 0..update_count {
        // Read length
        let mut len_bytes = [0u8; 4];
        cursor.read_exact(&mut len_bytes).map_err(|e| {
            crate::validation::ValidationError::DecodeError(format!("Failed to read length: {}", e))
        })?;
        let len = u32::from_be_bytes(len_bytes) as usize;

        // Read update data
        let mut update_bytes = vec![0u8; len];
        cursor.read_exact(&mut update_bytes).map_err(|e| {
            crate::validation::ValidationError::DecodeError(format!("Failed to read update: {}", e))
        })?;

        // Deserialize update
        let update: crate::types::SignedLedgerUpdate = bincode::deserialize(&update_bytes)
            .map_err(|e| {
                crate::validation::ValidationError::DecodeError(format!(
                    "Failed to deserialize update: {}",
                    e
                ))
            })?;
        updates.push(update);
    }

    // Extract genesis_block from the first LedgerOpen operation if available
    // This is a fallback - ideally the export protocol would include these fields
    let genesis_block = updates
        .first()
        .and_then(|u| {
            use crate::tlv::TlvDecode;
            crate::messages::LedgerOperation::tlv_decode(&u.message).ok()
        })
        .and_then(|op| {
            if let crate::messages::LedgerOperation::LedgerOpen { genesis_block, .. } = op {
                Some(genesis_block)
            } else {
                None
            }
        })
        .unwrap_or(0);

    // Compute ledger_id from genesis parameters
    let ledger_id =
        crate::types::LedgerState::compute_ledger_id(&operator_id, &reserves_id, genesis_block);

    // Create LedgerExport and validate
    let export = crate::validation::LedgerExport {
        version,
        ledger_id,
        genesis_block,
        operator_id,
        reserves_id,
        updates,
        exported_at,
        block_height,
    };

    crate::validation::LedgerConformanceValidator::validate(&export)
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
    // Fee Collect Tests
    // ========================================================================

    #[test]
    fn test_handle_fee_collect_no_ledger() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let deposit_pubkey = create_test_pubkey(3);

        let ctx = TestContext::new(our_node_id);

        let msg = FeeCollectMsg {
            pubkey: deposit_pubkey,
            amount: 1000,
            block_height: 100,
        };

        // No ledger exists - should error
        let result = handle_fee_collect(&ctx, &msg, operator);
        assert!(matches!(result, Err(HandlerError::LedgerNotFound { .. })));
    }

    #[test]
    fn test_handle_fee_collect_deposit_not_found() {
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

        let msg = FeeCollectMsg {
            pubkey: deposit_pubkey,
            amount: 1000,
            block_height: 100,
        };

        // Deposit doesn't exist - should fail validation
        let result = handle_fee_collect(&ctx, &msg, operator);
        assert!(matches!(result, Err(HandlerError::ValidationFailed(_))));
    }

    #[test]
    fn test_handle_fee_collect_valid() {
        use crate::types::{Deposit, FeeStructure};

        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let deposit_pubkey = create_test_pubkey(3);

        let mut ctx = TestContext::new(our_node_id);

        // Create a ledger with a deposit that has balance and is eligible for fee collection
        let mut ledger = Ledger::new(
            operator,
            our_node_id.to_string(),
            LedgerRole::Partner,
            vec![],
            0,
        );
        let mut deposit = Deposit::from_pubkey(
            &deposit_pubkey,
            Some(FeeStructure {
                annualized_msats: 0,
                annualized_bps: 100,
                frequency_blocks: 100,
            }),
        );
        deposit.balance = 100_000;
        deposit.last_fee_assessment = 0; // Fee eligible from the start
        ledger.state.deposits.insert(deposit.deposit_id, deposit);
        ctx.add_ledger(operator, our_node_id, ledger);

        let msg = FeeCollectMsg {
            pubkey: deposit_pubkey,
            amount: 1000,
            block_height: 100, // On schedule
        };

        // Valid fee collection
        let result = handle_fee_collect(&ctx, &msg, operator);
        match result {
            Ok(HandlerResult::Response(ResponseData::FeeCollectValidated {
                amount,
                block_height,
                ..
            })) => {
                assert_eq!(amount, 1000);
                assert_eq!(block_height, 100);
            }
            other => panic!("Expected Response(FeeCollectValidated), got {:?}", other),
        }

        // Check that event was emitted
        let events = ctx.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        match &events[0] {
            ProtocolEvent::FeeCollected {
                operator: op,
                amount: amt,
                ..
            } => {
                assert_eq!(*op, operator);
                assert_eq!(*amt, 1000);
            }
            other => panic!("Expected FeeCollected event, got {:?}", other),
        }
    }

    #[test]
    fn test_handle_fee_collect_too_early() {
        use crate::types::{Deposit, FeeStructure};

        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let deposit_pubkey = create_test_pubkey(3);

        let mut ctx = TestContext::new(our_node_id);

        // Create a ledger with a deposit where fees were recently collected
        let mut ledger = Ledger::new(
            operator,
            our_node_id.to_string(),
            LedgerRole::Partner,
            vec![],
            0,
        );
        let mut deposit = Deposit::from_pubkey(
            &deposit_pubkey,
            Some(FeeStructure {
                annualized_msats: 0,
                annualized_bps: 100,
                frequency_blocks: 100,
            }),
        );
        deposit.balance = 100_000;
        deposit.last_fee_assessment = 50; // Collected at block 50
        ledger.state.deposits.insert(deposit.deposit_id, deposit);
        ctx.add_ledger(operator, our_node_id, ledger);

        let msg = FeeCollectMsg {
            pubkey: deposit_pubkey,
            amount: 1000,
            block_height: 100, // Too early - need to wait until block 150
        };

        // Fee collection too early - should fail validation
        let result = handle_fee_collect(&ctx, &msg, operator);
        assert!(matches!(result, Err(HandlerError::ValidationFailed(_))));
    }

    // ========================================================================
    // Ledger Close Tests
    // ========================================================================

    #[test]
    fn test_handle_ledger_close_no_ledger() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);

        let ctx = TestContext::new(our_node_id);

        let msg = LedgerCloseMsg {
            reserves_id: our_node_id.to_string(),
        };

        // No ledger exists - should error
        let result = handle_ledger_close(&ctx, &msg, operator);
        assert!(matches!(result, Err(HandlerError::LedgerNotFound { .. })));
    }

    #[test]
    fn test_handle_ledger_close_wrong_partner() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let wrong_partner = create_test_pubkey(3);

        let ctx = TestContext::new(our_node_id);

        let msg = LedgerCloseMsg {
            reserves_id: wrong_partner.to_string(), // Not us
        };

        // We're not the target partner - should be rejected
        let result = handle_ledger_close(&ctx, &msg, operator);
        assert!(matches!(result, Ok(HandlerResult::Rejected(_))));
    }

    #[test]
    fn test_handle_ledger_close_outstanding_balance() {
        use crate::types::Deposit;

        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let deposit_pubkey = create_test_pubkey(3);

        let mut ctx = TestContext::new(our_node_id);

        // Create a ledger with a deposit that has balance
        let mut ledger = Ledger::new(
            operator,
            our_node_id.to_string(),
            LedgerRole::Partner,
            vec![],
            0,
        );
        let mut deposit = Deposit::from_pubkey(&deposit_pubkey, None);
        deposit.balance = 100_000; // Has balance
        ledger.state.deposits.insert(deposit.deposit_id, deposit);
        ctx.add_ledger(operator, our_node_id, ledger);

        let msg = LedgerCloseMsg {
            reserves_id: our_node_id.to_string(),
        };

        // Outstanding balance - should fail validation
        let result = handle_ledger_close(&ctx, &msg, operator);
        assert!(matches!(result, Err(HandlerError::ValidationFailed(_))));
    }

    #[test]
    fn test_handle_ledger_close_locked_balance() {
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
        deposit.balance = 0;
        deposit.locked_balance = 50_000; // Has locked balance
        ledger.state.deposits.insert(deposit.deposit_id, deposit);
        ctx.add_ledger(operator, our_node_id, ledger);

        let msg = LedgerCloseMsg {
            reserves_id: our_node_id.to_string(),
        };

        // Locked balance - should fail validation
        let result = handle_ledger_close(&ctx, &msg, operator);
        assert!(matches!(result, Err(HandlerError::ValidationFailed(_))));
    }

    #[test]
    fn test_handle_ledger_close_valid_empty() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);

        let mut ctx = TestContext::new(our_node_id);

        // Create an empty ledger
        let ledger = Ledger::new(
            operator,
            our_node_id.to_string(),
            LedgerRole::Partner,
            vec![],
            0,
        );
        ctx.add_ledger(operator, our_node_id, ledger);

        let msg = LedgerCloseMsg {
            reserves_id: our_node_id.to_string(),
        };

        // Valid close of empty ledger
        let result = handle_ledger_close(&ctx, &msg, operator);
        match result {
            Ok(HandlerResult::Response(ResponseData::LedgerCloseValidated {
                operator: op,
                reserves_id,
                ..
            })) => {
                assert_eq!(op, operator);
                assert_eq!(reserves_id, our_node_id.to_string());
            }
            other => panic!("Expected Response(LedgerCloseValidated), got {:?}", other),
        }

        // Check that event was emitted
        let events = ctx.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        match &events[0] {
            ProtocolEvent::LedgerClosed {
                operator: op,
                reserves_id,
            } => {
                assert_eq!(*op, operator);
                assert_eq!(*reserves_id, our_node_id.to_string());
            }
            other => panic!("Expected LedgerClosed event, got {:?}", other),
        }
    }

    #[test]
    fn test_handle_ledger_close_valid_zero_balance_deposits() {
        use crate::types::Deposit;

        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let deposit_pubkey = create_test_pubkey(3);

        let mut ctx = TestContext::new(our_node_id);

        // Create a ledger with zero-balance deposits
        let mut ledger = Ledger::new(
            operator,
            our_node_id.to_string(),
            LedgerRole::Partner,
            vec![],
            0,
        );
        let deposit = Deposit::from_pubkey(&deposit_pubkey, None); // Balance defaults to 0
        ledger.state.deposits.insert(deposit.deposit_id, deposit);
        ctx.add_ledger(operator, our_node_id, ledger);

        let msg = LedgerCloseMsg {
            reserves_id: our_node_id.to_string(),
        };

        // Valid close with zero-balance deposits
        let result = handle_ledger_close(&ctx, &msg, operator);
        assert!(matches!(
            result,
            Ok(HandlerResult::Response(
                ResponseData::LedgerCloseValidated { .. }
            ))
        ));
    }

    // ========================================================================
    // Cosign Invoice Tests
    // ========================================================================

    #[test]
    fn test_handle_receiving_cosign_invoice_no_ledger() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let deposit_pubkey = create_test_pubkey(3);

        let ctx = TestContext::new(our_node_id);

        let msg = ReceivingCosignInvoiceMsg {
            amount: 100_000,
            payment_hash: [0xAB; 32],
            expires: 3600,
            assigned_deposit: deposit_pubkey,
            invoice_id: "test_invoice".to_string(),
            bolt11: "lnbc1...".to_string(),
        };

        // No ledger exists - should error
        let result = handle_receiving_cosign_invoice(&ctx, &msg, operator);
        assert!(matches!(result, Err(HandlerError::LedgerNotFound { .. })));
    }

    #[test]
    fn test_handle_receiving_cosign_invoice_deposit_not_found() {
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

        let msg = ReceivingCosignInvoiceMsg {
            amount: 100_000,
            payment_hash: [0xAB; 32],
            expires: 3600,
            assigned_deposit: deposit_pubkey,
            invoice_id: "test_invoice".to_string(),
            bolt11: "lnbc1...".to_string(),
        };

        // Deposit doesn't exist - should fail validation
        let result = handle_receiving_cosign_invoice(&ctx, &msg, operator);
        assert!(matches!(result, Err(HandlerError::ValidationFailed(_))));
    }

    #[test]
    fn test_handle_receiving_cosign_invoice_zero_amount() {
        use crate::types::Deposit;

        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let deposit_pubkey = create_test_pubkey(3);
        let _spend_to = create_test_pubkey(4);

        let mut ctx = TestContext::new(our_node_id);

        // Create a ledger with a deposit
        let mut ledger = Ledger::new(
            operator,
            our_node_id.to_string(),
            LedgerRole::Partner,
            vec![],
            0,
        );
        let deposit = Deposit::from_pubkey(&deposit_pubkey, None);
        ledger.state.deposits.insert(deposit.deposit_id, deposit);
        ledger.state.reserves_amount = 200_000;
        ctx.add_ledger(operator, our_node_id, ledger);

        let msg = ReceivingCosignInvoiceMsg {
            amount: 0, // Zero amount
            payment_hash: [0xAB; 32],
            expires: 3600,
            assigned_deposit: deposit_pubkey,
            invoice_id: "test_invoice".to_string(),
            bolt11: "lnbc1...".to_string(),
        };

        // Zero amount - should fail validation
        let result = handle_receiving_cosign_invoice(&ctx, &msg, operator);
        assert!(matches!(result, Err(HandlerError::ValidationFailed(_))));
    }

    #[test]
    fn test_handle_receiving_cosign_invoice_valid() {
        use crate::types::Deposit;

        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let deposit_pubkey = create_test_pubkey(3);
        let _spend_to = create_test_pubkey(4);

        let mut ctx = TestContext::new(our_node_id);

        // Create a ledger with a deposit, sufficient reserves, and collateral
        let mut ledger = Ledger::new(
            operator,
            our_node_id.to_string(),
            LedgerRole::Partner,
            vec![],
            0,
        );
        let deposit = Deposit::from_pubkey(&deposit_pubkey, None);
        ledger.state.deposits.insert(deposit.deposit_id, deposit);
        ledger.state.reserves_amount = 200_000;
        set_test_collateral(&mut ledger, 200_000); // Set collateral to allow invoice
        ctx.add_ledger(operator, our_node_id, ledger);

        // Use a varied payment hash (not all same bytes to pass validation)
        let mut payment_hash = [0u8; 32];
        for i in 0..32 {
            payment_hash[i] = i as u8;
        }

        let msg = ReceivingCosignInvoiceMsg {
            amount: 100_000,
            payment_hash,
            expires: 3600,
            assigned_deposit: deposit_pubkey,
            invoice_id: "test_invoice".to_string(),
            bolt11: "lnbc1...".to_string(),
        };

        // Valid cosign invoice request
        let result = handle_receiving_cosign_invoice(&ctx, &msg, operator);
        match result {
            Ok(HandlerResult::Response(ResponseData::CosignInvoiceValidated {
                amount,
                deposit_pubkey: dp,
                ..
            })) => {
                assert_eq!(amount, 100_000);
                assert_eq!(dp, deposit_pubkey);
            }
            other => panic!("Expected Response(CosignInvoiceValidated), got {:?}", other),
        }

        // Check that event was emitted
        let events = ctx.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        match &events[0] {
            ProtocolEvent::InvoiceCosignRequested {
                operator: op,
                amount: amt,
                ..
            } => {
                assert_eq!(*op, operator);
                assert_eq!(*amt, 100_000);
            }
            other => panic!("Expected InvoiceCosignRequested event, got {:?}", other),
        }
    }

    #[test]
    fn test_handle_receiving_cosign_invoice_exceeds_reserves() {
        use crate::types::Deposit;

        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let deposit_pubkey = create_test_pubkey(3);
        let _spend_to = create_test_pubkey(4);

        let mut ctx = TestContext::new(our_node_id);

        // Create a ledger with a deposit but insufficient reserves
        let mut ledger = Ledger::new(
            operator,
            our_node_id.to_string(),
            LedgerRole::Partner,
            vec![],
            0,
        );
        let deposit = Deposit::from_pubkey(&deposit_pubkey, None);
        ledger.state.deposits.insert(deposit.deposit_id, deposit);
        ledger.state.reserves_amount = 50_000; // Only 50k reserves
        ctx.add_ledger(operator, our_node_id, ledger);

        let msg = ReceivingCosignInvoiceMsg {
            amount: 100_000, // Would exceed reserves
            payment_hash: [0xAB; 32],
            expires: 3600,
            assigned_deposit: deposit_pubkey,
            invoice_id: "test_invoice".to_string(),
            bolt11: "lnbc1...".to_string(),
        };

        // Exceeds reserves - should fail validation
        let result = handle_receiving_cosign_invoice(&ctx, &msg, operator);
        assert!(matches!(result, Err(HandlerError::ValidationFailed(_))));
    }
}
