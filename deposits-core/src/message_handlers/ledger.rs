use super::types::*;
use crate::error::HandlerError;
use crate::message_validation::HandlerContext;
use crate::operation_validation::{
    validate_credit_payment_by_id, validate_deposit_add_by_id, validate_deposit_close_by_id,
    validate_deposit_fee_change, validate_deposit_key_rotate, validate_fee_collect_by_id,
    validate_ledger_close, validate_payment_fail, validate_payment_fulfill_by_id,
    validate_payment_lock_by_id,
};

// ============================================================================
// Generic LedgerUpdate Handler
// ============================================================================

/// Handle ANY LedgerUpdate message generically.
///
/// This is the single entry point for all ledger-modifying operations.
/// LDK dispatch code calls this instead of operation-specific handlers.
///
/// The handler:
/// 1. Validates we are the partner
/// 2. Validates the operation based on type
/// 3. Appends operation to ledger
/// 4. Signs the update (porcupine dance)
/// 5. Persists the ledger
/// 6. Sends ACK via provider
///
/// # Arguments
/// * `ctx` - Handler context providing access to ledgers, signing, persistence
/// * `msg` - The full LedgerUpdateMsg (core computes the hash from this)
///
/// # Returns
/// * `Ok(HandlerResult::Ok)` - Operation succeeded, ACK sent via provider
/// * `Ok(HandlerResult::Rejected(reason))` - Operation rejected, NACK sent via provider
/// * `Err(HandlerError)` - Internal error
pub fn handle_ledger_update<C: HandlerContext>(
    ctx: &C,
    msg: &crate::messages::LedgerUpdateMsg,
) -> Result<HandlerResult, HandlerError> {
    use crate::messages::{BinaryCodec, LedgerOperation, LEDGER_UPDATE};
    use bitcoin::hashes::{sha256, Hash};

    let operator = msg.operator_id;
    let partner = msg.reserves_id.clone();
    let operation = msg.operation.clone();

    // Compute message hash from serialized message
    let mut msg_bytes = Vec::new();
    msg.write_to(&mut msg_bytes)
        .map_err(|e| HandlerError::Internal(format!("Serialization error: {}", e)))?;
    let message_hash: [u8; 32] = sha256::Hash::hash(&msg_bytes).to_byte_array();
    let message_type = LEDGER_UPDATE;

    let our_node_id = ctx.our_node_id();

    // We must be the partner to process this message
    if partner != our_node_id.to_string() {
        return Ok(HandlerResult::Rejected(format!(
            "We ({}) are not the target partner ({})",
            our_node_id, partner
        )));
    }

    // Get the ledger
    let ledger_arc = ctx
        .get_ledger(&operator, &partner)
        .ok_or(HandlerError::LedgerNotFound {
            operator,
            reserves_id: partner.clone(),
        })?;

    // Validate and append based on operation type
    let (prev_hash, new_hash, sequence, message_bytes, is_idempotent) = {
        let mut ledger = ledger_arc.write().map_err(|_| {
            HandlerError::Internal("Failed to acquire ledger write lock".to_string())
        })?;

        // Check for idempotent operations first - these still need ACKs but don't modify state
        let is_idempotent = match &operation {
            LedgerOperation::QuorumAddMember { quorum_member, .. } => {
                // Check both active and pending for idempotency
                ledger
                    .state
                    .quorum_members
                    .iter()
                    .any(|m| m.pubkey == *quorum_member)
                    || ledger
                        .state
                        .next_quorum_members
                        .iter()
                        .any(|m| m.pubkey == *quorum_member)
            }
            LedgerOperation::QuorumRemoveMember { quorum_member, .. } => {
                !ledger
                    .state
                    .quorum_members
                    .iter()
                    .any(|m| m.pubkey == *quorum_member)
                    && !ledger
                        .state
                        .next_quorum_members
                        .iter()
                        .any(|m| m.pubkey == *quorum_member)
            }
            LedgerOperation::DepositOpen { deposit_id, .. } => {
                ledger.state.deposits.contains_key(deposit_id)
            }
            LedgerOperation::DepositClose { deposit_id } => {
                !ledger.state.deposits.contains_key(deposit_id)
            }
            _ => false,
        };

        if is_idempotent {
            // For idempotent operations, return current ledger state for ACK
            // Don't append to history, just send ACK with current state
            let content_hash = ledger.tail_hash();
            let current_seq = ledger.state.sequence;
            (content_hash, content_hash, current_seq, Vec::new(), true)
        } else {
            // Operation-specific validation
            match &operation {
                // Deposit operations (non-idempotent cases already filtered above)
                LedgerOperation::DepositOpen {
                    deposit_id, fees, ..
                } => {
                    validate_deposit_add_by_id(&ledger, deposit_id, fees.as_ref())
                        .map_err(HandlerError::ValidationFailed)?;
                }
                LedgerOperation::DepositClose { deposit_id } => {
                    validate_deposit_close_by_id(&ledger, deposit_id)
                        .map_err(HandlerError::ValidationFailed)?;
                }
                LedgerOperation::FeeChange {
                    deposit_id,
                    new_fees,
                    effective_block,
                    ..
                } => {
                    validate_deposit_fee_change(&ledger, deposit_id, new_fees, *effective_block, 0)
                        .map_err(HandlerError::ValidationFailed)?;
                }
                LedgerOperation::DepositKeyRotate {
                    deposit_id,
                    new_descriptor,
                    witness,
                } => {
                    validate_deposit_key_rotate(&ledger, deposit_id, new_descriptor, witness)
                        .map_err(HandlerError::ValidationFailed)?;
                }

                // Invoice operations
                LedgerOperation::InvoiceCredit {
                    payment_hash,
                    deposit_id,
                    amount,
                    invoice_id,
                    ..
                } => {
                    validate_credit_payment_by_id(
                        &ledger,
                        deposit_id,
                        *amount,
                        payment_hash,
                        invoice_id,
                    )
                    .map_err(HandlerError::ValidationFailed)?;
                }
                LedgerOperation::InvoiceLock {
                    deposit_id,
                    amount,
                    payment_id,
                    witness,
                    ..
                } => {
                    validate_payment_lock_by_id(&ledger, deposit_id, *amount, payment_id, witness)
                        .map_err(HandlerError::ValidationFailed)?;
                }
                LedgerOperation::InvoiceFulfill {
                    deposit_id,
                    amount,
                    payment_id,
                    witness,
                    preimage,
                    ..
                } => {
                    validate_payment_fulfill_by_id(
                        deposit_id, *amount, payment_id, witness, preimage,
                    )
                    .map_err(HandlerError::ValidationFailed)?;
                }
                LedgerOperation::InvoiceFail { amount, .. } => {
                    validate_payment_fail(*amount).map_err(HandlerError::ValidationFailed)?;
                }

                // Onchain operations - basic validation
                LedgerOperation::OnchainCredit {
                    deposit_id, amount, ..
                } => {
                    // Verify deposit exists
                    if !ledger.state.deposits.contains_key(deposit_id) {
                        return Err(HandlerError::ValidationFailed(
                            "Deposit not found for onchain credit".to_string(),
                        ));
                    }
                    if *amount == 0 {
                        return Err(HandlerError::ValidationFailed(
                            "Onchain credit amount must be positive".to_string(),
                        ));
                    }
                }
                LedgerOperation::OnchainLock {
                    deposit_id, amount, ..
                } => {
                    if let Some(deposit) = ledger.state.deposits.get(deposit_id) {
                        if deposit.available_balance() < *amount {
                            return Err(HandlerError::ValidationFailed(
                                "Insufficient balance for onchain withdrawal".to_string(),
                            ));
                        }
                    } else {
                        return Err(HandlerError::ValidationFailed(
                            "Deposit not found for onchain withdrawal".to_string(),
                        ));
                    }
                }
                LedgerOperation::OnchainFail { .. } | LedgerOperation::OnchainFulfill { .. } => {
                    // These are validated during apply
                }

                // Fee collection
                LedgerOperation::FeeCollect {
                    deposit_id,
                    amount,
                    block_height,
                } => {
                    validate_fee_collect_by_id(&ledger, deposit_id, *amount, *block_height)
                        .map_err(HandlerError::ValidationFailed)?;
                }

                // Ledger close
                LedgerOperation::LedgerClose => {
                    validate_ledger_close(&ledger).map_err(HandlerError::ValidationFailed)?;
                }

                // Operations that don't need pre-validation (validated during append)
                // or have already been checked for idempotency above
                LedgerOperation::QuorumAddMember { .. }
                | LedgerOperation::QuorumRemoveMember { .. }
                | LedgerOperation::QuorumJoin { .. }
                | LedgerOperation::QuorumBegin { .. }
                | LedgerOperation::DisputeEnter { .. }
                | LedgerOperation::DisputeArmed { .. }
                | LedgerOperation::DisputeAcquire { .. }
                | LedgerOperation::DisputeYield
                | LedgerOperation::TransferLock { .. }
                | LedgerOperation::TransferComplete { .. }
                | LedgerOperation::TransferFail { .. }
                | LedgerOperation::LedgerOpen { .. }
                | LedgerOperation::DeliveryEmbed { .. } => {}
            }

            // Append operation to ledger
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

    // Sign the update (only for non-idempotent operations)
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

    // Update signature in ledger and persist (only for non-idempotent operations)
    if !is_idempotent {
        if let Some(sig) = partner_sig {
            let mut ledger = ledger_arc.write().map_err(|_| {
                HandlerError::Internal("Failed to acquire ledger write lock".to_string())
            })?;
            ledger.sign_last_update(None, Some(sig));
        }
        let _ = ctx.persist_ledger(&operator, &partner);

        // Sync quorum for quorum member changes
        match &operation {
            LedgerOperation::QuorumAddMember { quorum_member, .. } => {
                ctx.sync_quorum_member(operator, &partner, *quorum_member, true);
            }
            LedgerOperation::QuorumRemoveMember { quorum_member, .. } => {
                ctx.sync_quorum_member(operator, &partner, *quorum_member, false);
            }
            _ => {}
        }
    }

    // Send ACK via provider - ALWAYS send, even for idempotent operations
    // This ensures the operator doesn't timeout waiting for a response
    ctx.send_ledger_update_ack(
        operator,
        message_hash,
        message_type,
        true,
        None,
        sequence,
        prev_hash,
        new_hash,
        partner_sig,
    )?;

    Ok(HandlerResult::Ok)
}
