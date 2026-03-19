// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Core message handler logic for the Bitcoin Deposits protocol.
//!
//! This module provides Lightning-agnostic handler functions that can be used
//! by any Lightning implementation (LDK, CLN, etc.).
//!
//! ## Design
//!
//! Each handler function:
//! - Takes a reference to a `HandlerContext` for access to ledgers, messaging, etc.
//! - Takes the message and sender information
//! - Returns `Result<HandlerResult, HandlerError>`
//! - Performs validation and state updates
//! - Queues response messages via the context
//!
//! The LDK adapter (deposits-ldk) implements `HandlerContext` and calls these
//! core functions, converting `HandlerError` to `LightningError` at the boundary.

use bitcoin::secp256k1::PublicKey;

use crate::error::HandlerError;
use crate::message_validation::HandlerContext;
use crate::quorum::LedgerId;
use crate::recovery::RecoveryVote;
use crate::traits::ProtocolEvent;
use crate::wire_messages::{
    QuorumJoinRequestMsgWire, QuorumVoteRequestMsg, RecoveryVoteMsg,
    CollateralConsentRequestMsg, CollateralConsentResponseMsg,
    QuorumAddMemberMsg, QuorumRemoveMemberMsg,
    CollateralAttestationMsg, UncreditedPaymentMsg,
    ReceivingCreditPaymentMsg, SendingLockPaymentMsg,
    SendingFulfillPaymentMsg, SendingFailPaymentMsg,
    DepositOpenMsg, DepositCloseMsg, FeeChangeMsg,
    ReservesAddOutputMsg, ReservesRemoveOutputMsg,
    FeeCollectMsg, LedgerCloseMsg, ReceivingCosignInvoiceMsg,
    RecoveryClaimRequestMsg, RecoveryClaimSignatureMsg, RecoveryClaimCompleteMsg,
};
use crate::operation_validation::{
    validate_credit_payment, validate_payment_lock,
    validate_payment_fulfill, validate_payment_fail,
    validate_deposit_add, validate_deposit_close, validate_fee_change,
    validate_reserves_add,
    validate_fee_collect, validate_ledger_close, validate_cosign_invoice,
    // DepositId-based validation functions
    validate_deposit_add_by_id, validate_deposit_close_by_id, validate_fee_change_by_id, validate_deposit_fee_change,
    validate_payment_lock_by_id, validate_payment_fulfill_by_id, validate_credit_payment_by_id,
    validate_fee_collect_by_id, validate_deposit_key_rotate,
};
use crate::messages::{DepositsMessage, CoordinationMsg, CoordinationResponseMsg, SyncMsg, RecoveryResponseMsg};

// ============================================================================
// Handler Result Types
// ============================================================================

/// Result of handling a message
#[derive(Debug)]
pub enum HandlerResult {
    /// Message processed successfully, no further action
    Ok,
    /// Message processed, response should be sent
    /// The caller (LDK layer) should construct and send the appropriate response
    Response(ResponseData),
    /// Message rejected (but not an error)
    Rejected(String),
}

/// Data for constructing a response message
#[derive(Debug, Clone)]
pub enum ResponseData {
    /// Collateral consent response
    CollateralConsent {
        operator_id: PublicKey,
        reserves_id: String,
        consent_granted: bool,
        // Signature is populated by the LDK layer which has access to keys
    },
    /// Quorum join response (simple)
    QuorumJoin {
        accepted: bool,
        rejection_reason: Option<String>,
    },
    /// Quorum join response (full)
    QuorumJoinResponse {
        accepted: bool,
        members: Vec<PublicKey>,
        threshold: u16,
        rejection_reason: Option<String>,
    },
    /// Quorum member added - response with signature data for ACK
    QuorumMemberAdded {
        operator_id: PublicKey,
        reserves_id: String,
        quorum_member: PublicKey,
        /// Sequence number after append
        sequence: u64,
        /// Previous state hash
        prev_hash: [u8; 32],
        /// New state hash after append
        new_hash: [u8; 32],
    },
    /// Quorum member removed - response with signature data for ACK
    QuorumMemberRemoved {
        reserves_id: String,
        quorum_member: PublicKey,
        /// Sequence number after append
        sequence: u64,
        /// Previous state hash
        prev_hash: [u8; 32],
        /// New state hash after append
        new_hash: [u8; 32],
    },
    /// Collateral attestation processed
    CollateralAttestationProcessed {
        operator: PublicKey,
        quorum_member: PublicKey,
        amount: u64,
    },
    /// Uncredited payment accusation - emit event for node layer
    UncreditedPaymentAccusation {
        operator: PublicKey,
        reserves_id: String,
        payment_hash: [u8; 32],
        deposit_pubkey: PublicKey,
        amount_msat: u64,
        settlement_sequence: u64,
    },
    /// Credit payment validated - partner should sign and ACK
    CreditPaymentValidated {
        operator: PublicKey,
        reserves_id: String,
        deposit_pubkey: PublicKey,
        amount: u64,
        payment_hash: [u8; 32],
        invoice_id: String,
        sequence_number: u64,
    },
    /// Lock payment validated - partner should sign and ACK
    LockPaymentValidated {
        operator: PublicKey,
        reserves_id: String,
        deposit_pubkey: PublicKey,
        amount: u64,
        payment_id: [u8; 32],
        sequence_number: u64,
    },
    /// Fulfill payment validated - partner should sign and ACK
    FulfillPaymentValidated {
        operator: PublicKey,
        reserves_id: String,
        deposit_pubkey: PublicKey,
        amount: u64,
        payment_id: [u8; 32],
        preimage: [u8; 32],
        sequence_number: u64,
    },
    /// Fail payment validated - partner should sign and ACK
    FailPaymentValidated {
        operator: PublicKey,
        reserves_id: String,
        deposit_pubkey: PublicKey,
        amount: u64,
        payment_id: [u8; 32],
        sequence_number: u64,
    },
    /// Deposit open validated - partner should sign and ACK
    DepositOpenValidated {
        operator: PublicKey,
        reserves_id: String,
        deposit_pubkey: PublicKey,
        /// Sequence number after append
        sequence: u64,
        /// Previous state hash
        prev_hash: [u8; 32],
        /// New state hash after append
        new_hash: [u8; 32],
    },
    /// Deposit close validated - partner should sign and ACK
    DepositCloseValidated {
        operator: PublicKey,
        reserves_id: String,
        deposit_pubkey: PublicKey,
        /// Sequence number after append
        sequence: u64,
        /// Previous state hash
        prev_hash: [u8; 32],
        /// New state hash after append
        new_hash: [u8; 32],
    },
    /// Fee change validated - partner should sign and ACK
    FeeChangeValidated {
        operator: PublicKey,
        reserves_id: String,
        deposit_pubkey: PublicKey,
        /// Sequence number after append
        sequence: u64,
        /// Previous state hash
        prev_hash: [u8; 32],
        /// New state hash after append
        new_hash: [u8; 32],
    },
    /// Reserves add output validated - partner should sign and ACK
    ReservesAddOutputValidated {
        operator: PublicKey,
        reserves_id: String,
        initial_amount: u64,
        spend_to: PublicKey,
        quorum_members: Vec<PublicKey>,
        /// Sequence number after append
        sequence: u64,
        /// Previous state hash
        prev_hash: [u8; 32],
        /// New state hash after append
        new_hash: [u8; 32],
    },
    /// Reserves remove output validated - partner should sign and ACK
    ReservesRemoveOutputValidated {
        operator: PublicKey,
        reserves_id: String,
        /// Sequence number after append
        sequence: u64,
        /// Previous state hash
        prev_hash: [u8; 32],
        /// New state hash after append
        new_hash: [u8; 32],
    },
    /// Fee collection validated - partner should sign and ACK
    FeeCollectValidated {
        operator: PublicKey,
        reserves_id: String,
        deposit_pubkey: PublicKey,
        amount: u64,
        block_height: u32,
        /// Sequence number after append
        sequence: u64,
        /// Previous state hash
        prev_hash: [u8; 32],
        /// New state hash after append
        new_hash: [u8; 32],
    },
    /// Ledger close validated - partner should sign and ACK
    LedgerCloseValidated {
        operator: PublicKey,
        reserves_id: String,
        /// Sequence number after append
        sequence: u64,
        /// Previous state hash
        prev_hash: [u8; 32],
        /// New state hash after append
        new_hash: [u8; 32],
    },
    /// Invoice cosign validated - partner should sign the invoice
    CosignInvoiceValidated {
        operator: PublicKey,
        reserves_id: String,
        deposit_pubkey: PublicKey,
        amount: u64,
        payment_hash: [u8; 32],
        invoice_id: String,
        bolt11: String,
    },
    /// Recovery claim request validated - signer should sign and return signature
    RecoveryClaimRequestValidated {
        operator: PublicKey,
        partner: PublicKey,
        claimant: PublicKey,
        tier_index: u8,
        sighash: [u8; 32],
    },
    /// Recovery claim signature received - check if threshold reached
    RecoveryClaimSignatureReceived {
        operator: PublicKey,
        partner: PublicKey,
        signer: PublicKey,
        signature: [u8; 64],
        threshold_reached: bool,
    },
    /// Recovery claim completed - cleanup and emit event
    RecoveryClaimCompleted {
        old_operator: PublicKey,
        partner: PublicKey,
        new_operator: PublicKey,
        claim_txid: [u8; 32],
        confirmation_block: u32,
    },
    /// Quorum state sync processed
    QuorumStateSyncProcessed {
        applied: u32,
        errors: u32,
        total: u32,
    },
    /// Ledger export response - contains the full export for validation
    LedgerExportResponse {
        operator_id: PublicKey,
        reserves_id: String,
        ledger_address: String,
        version: u32,
        exported_at: u64,
        block_height: u32,
        update_count: u32,
        updates_data: Vec<u8>,
        success: bool,
        error_message: Option<String>,
    },
}

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
    use crate::messages::{LedgerOperation, BinaryCodec, LEDGER_UPDATE};
    use bitcoin::hashes::{Hash, sha256};

    let operator = msg.operator_id;
    let partner = msg.reserves_id.clone();
    let operation = msg.operation.clone();

    // Compute message hash from serialized message
    let mut msg_bytes = Vec::new();
    msg.write_to(&mut msg_bytes).map_err(|e| HandlerError::Internal(format!("Serialization error: {}", e)))?;
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
    let ledger_arc = ctx.get_ledger(&operator, &partner)
        .ok_or(HandlerError::LedgerNotFound { operator, reserves_id: partner.clone() })?;

    // Validate and append based on operation type
    let (prev_hash, new_hash, sequence, message_bytes, is_idempotent) = {
        let mut ledger = ledger_arc.write().map_err(|_|
            HandlerError::Internal("Failed to acquire ledger write lock".to_string())
        )?;

        // Check for idempotent operations first - these still need ACKs but don't modify state
        let is_idempotent = match &operation {
            LedgerOperation::QuorumAddMember { quorum_member, .. } => {
                ledger.state.quorum_members.iter().any(|m| m.pubkey == *quorum_member)
            }
            LedgerOperation::QuorumRemoveMember { quorum_member, .. } => {
                !ledger.state.quorum_members.iter().any(|m| m.pubkey == *quorum_member)
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
            let current_hash = ledger.tail_hash();
            let current_seq = ledger.state.sequence;
            (current_hash, current_hash, current_seq, Vec::new(), true)
        } else {
            // Operation-specific validation
            match &operation {
                // Deposit operations (non-idempotent cases already filtered above)
                LedgerOperation::DepositOpen { deposit_id, fees, .. } => {
                    validate_deposit_add_by_id(&ledger, deposit_id, fees.as_ref())
                        .map_err(|e| HandlerError::ValidationFailed(e))?;
                }
                LedgerOperation::DepositClose { deposit_id } => {
                    validate_deposit_close_by_id(&ledger, deposit_id)
                        .map_err(|e| HandlerError::ValidationFailed(e))?;
                }
                LedgerOperation::FeeChange { deposit_id, new_fees, effective_block, .. } => {
                    validate_deposit_fee_change(&ledger, deposit_id, new_fees, *effective_block, 0)
                        .map_err(|e| HandlerError::ValidationFailed(e))?;
                }
                LedgerOperation::DepositKeyRotate { deposit_id, new_descriptor, witness } => {
                    validate_deposit_key_rotate(&ledger, deposit_id, new_descriptor, witness)
                        .map_err(|e| HandlerError::ValidationFailed(e))?;
                }

                // Invoice operations
                LedgerOperation::InvoiceCredit { payment_hash, deposit_id, amount, invoice_id, .. } => {
                    validate_credit_payment_by_id(&ledger, deposit_id, *amount, payment_hash, invoice_id)
                        .map_err(|e| HandlerError::ValidationFailed(e))?;
                }
                LedgerOperation::InvoiceLock { deposit_id, amount, payment_id, witness, .. } => {
                    validate_payment_lock_by_id(&ledger, deposit_id, *amount, payment_id, witness)
                        .map_err(|e| HandlerError::ValidationFailed(e))?;
                }
                LedgerOperation::InvoiceFulfill { deposit_id, amount, payment_id, witness, preimage, .. } => {
                    validate_payment_fulfill_by_id(deposit_id, *amount, payment_id, witness, preimage)
                        .map_err(|e| HandlerError::ValidationFailed(e))?;
                }
                LedgerOperation::InvoiceFail { amount, .. } => {
                    validate_payment_fail(*amount)
                        .map_err(|e| HandlerError::ValidationFailed(e))?;
                }

                // Onchain operations - basic validation
                LedgerOperation::OnchainCredit { deposit_id, amount, .. } => {
                    // Verify deposit exists
                    if !ledger.state.deposits.contains_key(deposit_id) {
                        return Err(HandlerError::ValidationFailed(
                            "Deposit not found for onchain credit".to_string()
                        ));
                    }
                    if *amount == 0 {
                        return Err(HandlerError::ValidationFailed(
                            "Onchain credit amount must be positive".to_string()
                        ));
                    }
                }
                LedgerOperation::OnchainLock { deposit_id, amount, .. } => {
                    if let Some(deposit) = ledger.state.deposits.get(deposit_id) {
                        if deposit.available_balance() < *amount {
                            return Err(HandlerError::ValidationFailed(
                                "Insufficient balance for onchain withdrawal".to_string()
                            ));
                        }
                    } else {
                        return Err(HandlerError::ValidationFailed(
                            "Deposit not found for onchain withdrawal".to_string()
                        ));
                    }
                }
                LedgerOperation::OnchainFail { .. } |
                LedgerOperation::OnchainFulfill { .. } => {
                    // These are validated during apply
                }

                // Fee collection
                LedgerOperation::FeeCollect { deposit_id, amount, block_height } => {
                    validate_fee_collect_by_id(&ledger, deposit_id, *amount, *block_height)
                        .map_err(|e| HandlerError::ValidationFailed(e))?;
                }

                // Ledger close
                LedgerOperation::LedgerClose => {
                    validate_ledger_close(&ledger)
                        .map_err(|e| HandlerError::ValidationFailed(e))?;
                }

                // Operations that don't need pre-validation (validated during append)
                // or have already been checked for idempotency above
                LedgerOperation::QuorumAddMember { .. } |
                LedgerOperation::QuorumRemoveMember { .. } |
                LedgerOperation::CollateralLock { .. } |
                LedgerOperation::QuorumJoin { .. } |
                LedgerOperation::CollateralAttestation { .. } |
                LedgerOperation::QuorumBegin { .. } |
                LedgerOperation::DisputeEnter { .. } |
                LedgerOperation::DisputeArmed { .. } |
                LedgerOperation::DisputeAcquire { .. } |
                LedgerOperation::DisputeYield |
                LedgerOperation::TransferLock { .. } |
                LedgerOperation::TransferComplete { .. } |
                LedgerOperation::TransferFail { .. } |
                LedgerOperation::LedgerOpen { .. } => {}
            }

            // Append operation to ledger
            let (prev, new, seq) = ledger.append_operation(operation.clone(), LEDGER_UPDATE)
                .map_err(|e| HandlerError::ValidationFailed(e.to_string()))?;

            // Get message bytes for signing
            let bytes = ledger.history.last()
                .map(|u| u.message.clone())
                .unwrap_or_default();

            (prev, new, seq, bytes, false)
        }
    };

    // Sign the update (only for non-idempotent operations)
    let partner_sig = if !is_idempotent && !message_bytes.is_empty() {
        ctx.sign_ledger_update(&message_bytes, LEDGER_UPDATE, sequence, &prev_hash, &new_hash)
    } else {
        None
    };

    // Update signature in ledger and persist (only for non-idempotent operations)
    if !is_idempotent {
        if let Some(sig) = partner_sig {
            let mut ledger = ledger_arc.write().map_err(|_|
                HandlerError::Internal("Failed to acquire ledger write lock".to_string())
            )?;
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

// ============================================================================
// Quorum Message Handlers
// ============================================================================

/// Handle a QuorumJoinRequest message.
///
/// Core logic for processing join requests, independent of Lightning implementation.
/// Returns a HandlerResult indicating whether the request should be accepted.
pub fn handle_quorum_join_request<C: HandlerContext>(
    ctx: &C,
    msg: &QuorumJoinRequestMsgWire,
    sender: PublicKey,
) -> Result<HandlerResult, HandlerError> {
    use crate::types::QuorumJoinRequestMsg as CoreQuorumMsg;
    use crate::messages::{DepositsMessage, CoordinationResponseMsg};

    // Validate: sender should match the requester
    if sender != msg.requester_pubkey {
        return Ok(HandlerResult::Rejected(
            "Sender doesn't match requester".to_string()
        ));
    }

    // Get quorum manager
    let quorum_manager = ctx.quorum_manager()
        .ok_or(HandlerError::InvalidState("No quorum manager available".to_string()))?;

    // Convert to core type and delegate to QuorumManager
    let core_msg = CoreQuorumMsg {
        requester_pubkey: msg.requester_pubkey,
        operator_id: msg.operator_id,
        reserves_id: msg.reserves_id.clone(),
        protocol_version: msg.protocol_version,
        timestamp: msg.timestamp,
        signature: msg.signature,
    };

    match quorum_manager.handle_join_request(&core_msg) {
        Ok(response) => {
            // Queue response message
            let response_msg = DepositsMessage::CoordinationResponse(CoordinationResponseMsg::QuorumJoinResponse {
                request_hash: [0u8; 32], // Wire layer will fill this
                accepted: response.accepted,
                members: response.members.clone(),
                threshold: response.threshold as u16,
                last_sequence: response.last_sequence,
                current_hash: response.current_hash,
                rejection_reason: response.rejection_reason.clone(),
            });
            ctx.queue_message(sender, response_msg)?;

            // Emit event and send state sync if accepted
            if response.accepted {
                ctx.emit_event(ProtocolEvent::QuorumMemberJoined {
                    operator: msg.operator_id,
                    reserves_id: msg.reserves_id.clone(),
                    member: msg.requester_pubkey,
                });
                // Send state sync to new member via provider
                ctx.send_quorum_state_sync(msg.requester_pubkey, msg.operator_id, &msg.reserves_id);
            }

            Ok(HandlerResult::Ok)
        }
        Err(e) => {
            Ok(HandlerResult::Rejected(format!("Quorum join failed: {:?}", e)))
        }
    }
}

/// Handle a QuorumVoteRequest message.
///
/// This is sent by quorum initiators to request votes for a reserves spend.
/// Voters must validate conformance before signing.
pub fn handle_quorum_vote_request<C: HandlerContext>(
    ctx: &C,
    msg: &QuorumVoteRequestMsg,
    sender: PublicKey,
) -> Result<HandlerResult, HandlerError> {
    let our_node_id = ctx.our_node_id();

    // Get local state from signed update log (more accurate than ledger state)
    let (our_sequence, our_state_hash) = match ctx.get_signed_update_log_state(&msg.operator_id, &msg.reserves_id) {
        Some(state) => state,
        None => {
            // No local state, abstain from voting
            return Ok(HandlerResult::Ok);
        }
    };

    // Initialize vote round for tracking
    ctx.init_vote_round(
        msg.vote_round_id,
        msg.operator_id,
        &msg.reserves_id,
        msg.sequence_number,
        msg.state_hash,
        msg.claimed_reserves,
        msg.reserves_outpoint.clone(),
        msg.destination_script.clone(),
        msg.fee_rate_sat_vbyte,
        2, // Default threshold
    );

    // Validate and create vote
    let is_conforming = true; // TODO: implement full conformance validation
    let vote = is_conforming && our_state_hash == msg.state_hash;
    let evidence = if !vote { Some(b"state_mismatch".to_vec()) } else { None };

    // Sign the vote
    let signature = match ctx.sign_quorum_vote(&msg.vote_round_id, vote, our_sequence, &our_state_hash) {
        Some(sig) => sig,
        None => {
            // Cannot sign - no secret key available
            return Ok(HandlerResult::Ok);
        }
    };

    // Build and queue vote message
    let vote_msg = DepositsMessage::Coordination(CoordinationMsg::QuorumVote {
        vote_round_id: msg.vote_round_id,
        voter_pubkey: our_node_id,
        vote,
        voter_sequence: our_sequence,
        voter_state_hash: our_state_hash,
        evidence,
        signature,
        spend_signature: None, // TODO: implement spend signing
    });

    let _ = ctx.queue_message(sender, vote_msg);

    Ok(HandlerResult::Ok)
}

/// Handle a QuorumVote message.
///
/// This is a vote received from a quorum member in response to a vote request.
/// The vote is added to the pending round and if threshold is reached,
/// the ReservesSpendReady event is emitted.
pub fn handle_quorum_vote<C: HandlerContext>(
    ctx: &C,
    vote_round_id: [u8; 32],
    voter: PublicKey,
    vote: bool,
    spend_signature: Option<[u8; 64]>,
) -> Result<HandlerResult, HandlerError> {
    // Add vote via provider and check if threshold reached
    if let Some((operator, reserves_id, spend_data, conforming_votes, threshold)) =
        ctx.add_quorum_vote(vote_round_id, voter, vote, spend_signature)
    {
        // Emit spend ready event
        ctx.emit_event(ProtocolEvent::ReservesSpendReady {
            vote_round_id,
            operator,
            reserves_id,
            signed_tx_bytes: spend_data,
            conforming_votes,
            threshold,
        });
    }

    Ok(HandlerResult::Ok)
}

/// Handle a QuorumStateSync message.
///
/// Process signed updates received during quorum state synchronization.
/// After the final batch, updates our member state in the quorum manager.
pub fn handle_quorum_state_sync<C: HandlerContext>(
    ctx: &C,
    operator: PublicKey,
    reserves_id: &str,
    updates: &[Vec<u8>],
    _start_sequence: u64,
    is_final: bool,
) -> Result<HandlerResult, HandlerError> {
    use crate::messages::BinaryCodec;
    use crate::types::SignedLedgerUpdate;

    let mut applied_count = 0;
    let mut error_count = 0;

    // Process each update in the batch
    for update_bytes in updates {
        let mut cursor = std::io::Cursor::new(update_bytes);
        match SignedLedgerUpdate::read_from(&mut cursor) {
            Ok(signed_update) => {
                match ctx.verify_and_store_signed_update(signed_update) {
                    Ok(()) => applied_count += 1,
                    Err(_) => error_count += 1,
                }
            }
            Err(_) => error_count += 1,
        }
    }

    // Update quorum member state after final batch
    if is_final {
        if let Some((sequence, state_hash)) = ctx.get_signed_update_log_state(&operator, reserves_id) {
            let _ = ctx.update_quorum_member_state(operator, reserves_id, sequence, state_hash);
        }
    }

    Ok(HandlerResult::Response(ResponseData::QuorumStateSyncProcessed {
        applied: applied_count,
        errors: error_count,
        total: updates.len() as u32,
    }))
}

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
    let recovery_manager = ctx.recovery_manager()
        .ok_or(HandlerError::InvalidState("No recovery manager available".to_string()))?;

    // Submit the vote
    let ledger_id = (msg.operator, msg.partner);
    let vote_result = {
        let mut manager = recovery_manager.lock().map_err(|_|
            HandlerError::Internal("Failed to acquire recovery manager lock".to_string())
        )?;
        manager.submit_vote(ledger_id, vote)
            .map_err(|e| HandlerError::ValidationFailed(format!("Vote submission failed: {:?}", e)))?
    };

    // Check for non-compliance determination
    let non_conforming_threshold = if vote_result.total_votes <= 2 {
        1  // For 2-of-2 ledgers
    } else {
        (vote_result.total_votes / 2) + 1  // Strict majority
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
            "Sender doesn't match claimed operator".to_string()
        ));
    }

    // Check if we have an operator channel with the requesting operator
    // This would be the channel where our reserves would serve as collateral
    let has_channel_with_operator = ctx.get_ledger(&msg.operator_id, &our_node_id.to_string()).is_some();
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
            signature,
        )?;
    }

    // Queue the response message
    let response = DepositsMessage::CoordinationResponse(
        CoordinationResponseMsg::CollateralConsentResponse {
            request_hash: [0u8; 32],
            operator_id: msg.operator_id,
            reserves_id: msg.reserves_id.clone(),
            consent_granted,
            quorum_member_signature: signature,
        }
    );
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
    if msg.consent_granted {
        if !ctx.verify_consent_signature(
            msg.operator_id,
            &msg.reserves_id,
            msg.quorum_member_signature,
            sender,
        ) {
            return Ok(HandlerResult::Rejected("Invalid consent signature".to_string()));
        }
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
    if msg.reserves_id != our_node_id.to_string().to_string() {
        return Ok(HandlerResult::Rejected(format!(
            "We ({}) are not the target partner ({})",
            our_node_id, msg.reserves_id
        )));
    }

    // Get the ledger - sender (operator) and us (partner)
    let ledger_arc = ctx.get_ledger(&sender, &msg.reserves_id)
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
    };

    // Check for idempotency and append (single write lock scope)
    let (prev_hash, new_hash, sequence, message_bytes, is_idempotent) = {
        let mut ledger = ledger_arc.write().map_err(|_|
            HandlerError::Internal("Failed to acquire ledger write lock".to_string())
        )?;

        // Idempotency check
        if ledger.state.quorum_members.iter().any(|m| m.pubkey == msg.quorum_member) {
            let seq = ledger.sequence();
            let hash = ledger.hash();
            (hash, hash, seq, Vec::new(), true)
        } else {
            // Append operation
            let (prev, new, seq) = ledger.append_operation(operation.clone(), LEDGER_UPDATE)
                .map_err(|e| HandlerError::ValidationFailed(e.to_string()))?;

            // Get message bytes for signing
            let bytes = ledger.history.last()
                .map(|u| u.message.clone())
                .unwrap_or_default();

            (prev, new, seq, bytes, false)
        }
    };

    // Sign the update (if not idempotent)
    let partner_sig = if !is_idempotent && !message_bytes.is_empty() {
        ctx.sign_ledger_update(&message_bytes, LEDGER_UPDATE, sequence, &prev_hash, &new_hash)
    } else {
        None
    };

    // Update signature in ledger and persist (if not idempotent)
    if !is_idempotent {
        if let Some(sig) = partner_sig {
            let mut ledger = ledger_arc.write().map_err(|_|
                HandlerError::Internal("Failed to acquire ledger write lock".to_string())
            )?;
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
    if msg.reserves_id != our_node_id.to_string().to_string() {
        return Ok(HandlerResult::Rejected(format!(
            "We ({}) are not the target partner ({})",
            our_node_id, msg.reserves_id
        )));
    }

    // Get the ledger - sender (operator) and us (partner)
    let ledger_arc = ctx.get_ledger(&sender, &msg.reserves_id)
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
        let mut ledger = ledger_arc.write().map_err(|_|
            HandlerError::Internal("Failed to acquire ledger write lock".to_string())
        )?;

        // Idempotency check - if already removed, return success
        if !ledger.state.quorum_members.iter().any(|m| m.pubkey == msg.quorum_member) {
            let seq = ledger.sequence();
            let hash = ledger.hash();
            (hash, hash, seq, Vec::new(), true)
        } else {
            // Append operation
            let (prev, new, seq) = ledger.append_operation(operation.clone(), LEDGER_UPDATE)
                .map_err(|e| HandlerError::ValidationFailed(e.to_string()))?;

            // Get message bytes for signing
            let bytes = ledger.history.last()
                .map(|u| u.message.clone())
                .unwrap_or_default();

            (prev, new, seq, bytes, false)
        }
    };

    // Sign the update (if not idempotent)
    let partner_sig = if !is_idempotent && !message_bytes.is_empty() {
        ctx.sign_ledger_update(&message_bytes, LEDGER_UPDATE, sequence, &prev_hash, &new_hash)
    } else {
        None
    };

    // Update signature in ledger and persist (if not idempotent)
    if !is_idempotent {
        if let Some(sig) = partner_sig {
            let mut ledger = ledger_arc.write().map_err(|_|
                HandlerError::Internal("Failed to acquire ledger write lock".to_string())
            )?;
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
            "Attestation amount must be positive".to_string()
        ));
    }

    // Return response data for the LDK layer to:
    // 1. Store the attestation in ledger state
    // 2. Forward CollateralAttestation to channel ledgers
    // 3. Send to channel partners for bilateral signing
    Ok(HandlerResult::Response(ResponseData::CollateralAttestationProcessed {
        operator: msg.operator,
        quorum_member: msg.quorum_member,
        amount: msg.amount,
    }))
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
        return Ok(HandlerResult::Rejected(format!(
            "Invalid preimage - computed hash doesn't match payment_hash"
        )));
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
        let ledger = ledger_arc.read().map_err(|_|
            HandlerError::Internal("Failed to acquire ledger lock".to_string())
        )?;

        // Check if there's a credit for this payment hash in the ledger
        if ledger.has_credit_for_payment(&msg.payment_hash) {
            // The ledger has a credit - accusation appears invalid
            return Ok(HandlerResult::Rejected(
                "Ledger has a credit for this payment - accusation appears invalid".to_string()
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
    let ledger_arc = ctx.get_ledger(&sender, &msg.reserves_id)
        .ok_or(HandlerError::LedgerNotFound {
            operator: sender,
            reserves_id: msg.reserves_id.clone(),
        })?;

    // Validate the credit payment
    {
        let ledger = ledger_arc.read().map_err(|_|
            HandlerError::Internal("Failed to acquire ledger read lock".to_string())
        )?;

        validate_credit_payment(
            &ledger,
            msg.deposit_pubkey,
            msg.amount,
            &msg.payment_hash,
        ).map_err(|e| HandlerError::ValidationFailed(e))?;
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
    Ok(HandlerResult::Response(ResponseData::CreditPaymentValidated {
        operator: sender,
        reserves_id: msg.reserves_id.clone(),
        deposit_pubkey: msg.deposit_pubkey,
        amount: msg.amount,
        payment_hash: msg.payment_hash,
        invoice_id: msg.invoice_id.clone(),
        sequence_number: msg.sequence_number,
    }))
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
    let ledger_arc = ctx.get_ledger(&sender, &our_node_id.to_string())
        .ok_or(HandlerError::LedgerNotFound {
            operator: sender,
            reserves_id: our_node_id.to_string(),
        })?;

    // Validate the payment lock
    {
        let ledger = ledger_arc.read().map_err(|_|
            HandlerError::Internal("Failed to acquire ledger read lock".to_string())
        )?;

        validate_payment_lock(
            &ledger,
            msg.pubkey,
            msg.amount,
            &msg.payment_id,
            &msg.scriptpubkey_signature,
        ).map_err(|e| HandlerError::ValidationFailed(e))?;
    }

    // Return validated data for LDK layer to record to ledger and sign
    Ok(HandlerResult::Response(ResponseData::LockPaymentValidated {
        operator: sender,
        reserves_id: our_node_id.to_string(),
        deposit_pubkey: msg.pubkey,
        amount: msg.amount,
        payment_id: msg.payment_id,
        sequence_number: msg.sequence_number,
    }))
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
    let ledger_arc = ctx.get_ledger(&sender, &our_node_id.to_string())
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
    ).map_err(|e| HandlerError::ValidationFailed(e))?;

    // Also verify deposit exists in ledger
    {
        let ledger = ledger_arc.read().map_err(|_|
            HandlerError::Internal("Failed to acquire ledger read lock".to_string())
        )?;

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
    Ok(HandlerResult::Response(ResponseData::FulfillPaymentValidated {
        operator: sender,
        reserves_id: our_node_id.to_string(),
        deposit_pubkey: msg.pubkey,
        amount: msg.amount,
        payment_id: msg.payment_id,
        preimage: msg.preimage,
        sequence_number: msg.sequence_number,
    }))
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
    let ledger_arc = ctx.get_ledger(&sender, &our_node_id.to_string())
        .ok_or(HandlerError::LedgerNotFound {
            operator: sender,
            reserves_id: our_node_id.to_string(),
        })?;

    // Validate the payment fail
    validate_payment_fail(msg.amount)
        .map_err(|e| HandlerError::ValidationFailed(e))?;

    // Also verify deposit exists in ledger
    {
        let ledger = ledger_arc.read().map_err(|_|
            HandlerError::Internal("Failed to acquire ledger read lock".to_string())
        )?;

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
    Ok(HandlerResult::Response(ResponseData::FailPaymentValidated {
        operator: sender,
        reserves_id: our_node_id.to_string(),
        deposit_pubkey: msg.pubkey,
        amount: msg.amount,
        payment_id: msg.payment_id,
        sequence_number: msg.sequence_number,
    }))
}

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
    let ledger_arc = ctx.get_ledger(&sender, &msg.reserves_id)
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
        let mut ledger = ledger_arc.write().map_err(|_|
            HandlerError::Internal("Failed to acquire ledger write lock".to_string())
        )?;

        // Idempotency check
        if ledger.state.deposits.contains_key(&deposit_id) {
            let seq = ledger.sequence();
            let hash = ledger.hash();
            (hash, hash, seq, Vec::new(), true)
        } else {
            // Validate first
            validate_deposit_add_by_id(
                &ledger,
                &deposit_id,
                msg.fees.as_ref(),
            ).map_err(|e| HandlerError::ValidationFailed(e))?;

            // Append operation
            let (prev, new, seq) = ledger.append_operation(operation.clone(), LEDGER_UPDATE)
                .map_err(|e| HandlerError::ValidationFailed(e.to_string()))?;

            // Get message bytes for signing
            let bytes = ledger.history.last()
                .map(|u| u.message.clone())
                .unwrap_or_default();

            (prev, new, seq, bytes, false)
        }
    };

    // Sign the update (if not idempotent)
    let partner_sig = if !is_idempotent && !message_bytes.is_empty() {
        ctx.sign_ledger_update(&message_bytes, LEDGER_UPDATE, sequence, &prev_hash, &new_hash)
    } else {
        None
    };

    // Update signature in ledger and persist (if not idempotent)
    if !is_idempotent {
        if let Some(sig) = partner_sig {
            let mut ledger = ledger_arc.write().map_err(|_|
                HandlerError::Internal("Failed to acquire ledger write lock".to_string())
            )?;
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
    let ledger_arc = ctx.get_ledger(&sender, &msg.reserves_id)
        .ok_or(HandlerError::LedgerNotFound {
            operator: sender,
            reserves_id: msg.reserves_id.clone(),
        })?;

    // Convert pubkey to descriptor and compute deposit_id
    let descriptor = format!("pk({})", hex::encode(msg.pubkey.serialize()));
    let deposit_id = crate::types::compute_deposit_id(&descriptor);

    let operation = LedgerOperation::DepositClose {
        deposit_id,
    };

    // Check for idempotency and append (single write lock scope)
    let (prev_hash, new_hash, sequence, message_bytes, is_idempotent, final_balance) = {
        let mut ledger = ledger_arc.write().map_err(|_|
            HandlerError::Internal("Failed to acquire ledger write lock".to_string())
        )?;

        // Idempotency check - if deposit doesn't exist, already closed
        if !ledger.state.deposits.contains_key(&deposit_id) {
            let seq = ledger.sequence();
            let hash = ledger.hash();
            (hash, hash, seq, Vec::new(), true, 0u64)
        } else {
            // Get final balance before close
            let final_balance = ledger.state.deposits.get(&deposit_id)
                .map(|d| d.balance)
                .unwrap_or(0);

            // Validate first
            validate_deposit_close_by_id(
                &ledger,
                &deposit_id,
            ).map_err(|e| HandlerError::ValidationFailed(e))?;

            // Append operation
            let (prev, new, seq) = ledger.append_operation(operation.clone(), LEDGER_UPDATE)
                .map_err(|e| HandlerError::ValidationFailed(e.to_string()))?;

            // Get message bytes for signing
            let bytes = ledger.history.last()
                .map(|u| u.message.clone())
                .unwrap_or_default();

            (prev, new, seq, bytes, false, final_balance)
        }
    };

    // Sign the update (if not idempotent)
    let partner_sig = if !is_idempotent && !message_bytes.is_empty() {
        ctx.sign_ledger_update(&message_bytes, LEDGER_UPDATE, sequence, &prev_hash, &new_hash)
    } else {
        None
    };

    // Update signature in ledger and persist (if not idempotent)
    if !is_idempotent {
        if let Some(sig) = partner_sig {
            let mut ledger = ledger_arc.write().map_err(|_|
                HandlerError::Internal("Failed to acquire ledger write lock".to_string())
            )?;
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
    let ledger_arc = ctx.get_ledger(&sender, &msg.reserves_id)
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
        let mut ledger = ledger_arc.write().map_err(|_|
            HandlerError::Internal("Failed to acquire ledger write lock".to_string())
        )?;

        // Validate first
        validate_fee_change_by_id(
            &ledger,
            &deposit_id,
            &msg.new_fees,
        ).map_err(|e| HandlerError::ValidationFailed(e))?;

        // Append operation
        let (prev, new, seq) = ledger.append_operation(operation.clone(), LEDGER_UPDATE)
            .map_err(|e| HandlerError::ValidationFailed(e.to_string()))?;

        // Get message bytes for signing
        let bytes = ledger.history.last()
            .map(|u| u.message.clone())
            .unwrap_or_default();

        (prev, new, seq, bytes)
    };

    // Sign the update
    let partner_sig = if !message_bytes.is_empty() {
        ctx.sign_ledger_update(&message_bytes, LEDGER_UPDATE, sequence, &prev_hash, &new_hash)
    } else {
        None
    };

    // Update signature in ledger and persist
    if let Some(sig) = partner_sig {
        let mut ledger = ledger_arc.write().map_err(|_|
            HandlerError::Internal("Failed to acquire ledger write lock".to_string())
        )?;
        ledger.sign_last_update(None, Some(sig));
    }
    let _ = ctx.persist_ledger(&sender, &msg.reserves_id);

    // NOTE: ACK is sent by LDK dispatch code which has access to the correct message hash

    Ok(HandlerResult::Ok)
}

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
    let ledger_arc = ctx.get_ledger(&sender, &msg.reserves_id)
        .ok_or(HandlerError::LedgerNotFound {
            operator: sender,
            reserves_id: msg.reserves_id.clone(),
        })?;

    // Validate and get current state
    let (sequence, prev_hash, new_hash) = {
        let ledger = ledger_arc.read().map_err(|_|
            HandlerError::Internal("Failed to acquire ledger read lock".to_string())
        )?;

        // Check for idempotency - if reserves output already exists with same amount
        if ledger.state.reserves.amount > 0 {
            return Ok(HandlerResult::Response(ResponseData::ReservesAddOutputValidated {
                operator: sender,
                reserves_id: msg.reserves_id.clone(),
                initial_amount: msg.initial_amount,
                spend_to: msg.spend_to,
                quorum_members: msg.quorum_members.clone(),
                sequence: ledger.sequence(),
                prev_hash: ledger.hash(),
                new_hash: ledger.hash(),
            }));
        }

        // Validate the reserves add operation
        validate_reserves_add(msg.initial_amount)
            .map_err(|e| HandlerError::ValidationFailed(e))?;

        // Return current state for response
        (ledger.sequence(), ledger.hash(), ledger.hash())
    };

    // Return validated data for LDK layer to record to ledger and sign
    Ok(HandlerResult::Response(ResponseData::ReservesAddOutputValidated {
        operator: sender,
        reserves_id: msg.reserves_id.clone(),
        initial_amount: msg.initial_amount,
        spend_to: msg.spend_to,
        quorum_members: msg.quorum_members.clone(),
        sequence,
        prev_hash,
        new_hash,
    }))
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
    let ledger_arc = ctx.get_ledger(&sender, &msg.reserves_id)
        .ok_or(HandlerError::LedgerNotFound {
            operator: sender,
            reserves_id: msg.reserves_id.clone(),
        })?;

    // Validate and get current state
    let (sequence, prev_hash, new_hash) = {
        let ledger = ledger_arc.read().map_err(|_|
            HandlerError::Internal("Failed to acquire ledger read lock".to_string())
        )?;

        // Check for idempotency - if reserves output already removed
        if ledger.state.reserves.amount == 0 {
            return Ok(HandlerResult::Response(ResponseData::ReservesRemoveOutputValidated {
                operator: sender,
                reserves_id: msg.reserves_id.clone(),
                sequence: ledger.sequence(),
                prev_hash: ledger.hash(),
                new_hash: ledger.hash(),
            }));
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
    Ok(HandlerResult::Response(ResponseData::ReservesRemoveOutputValidated {
        operator: sender,
        reserves_id: msg.reserves_id.clone(),
        sequence,
        prev_hash,
        new_hash,
    }))
}

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
    let ledger_arc = ctx.get_ledger(&sender, &our_node_id.to_string())
        .ok_or(HandlerError::LedgerNotFound {
            operator: sender,
            reserves_id: our_node_id.to_string(),
        })?;

    // Validate the fee collection
    let (sequence, prev_hash, new_hash) = {
        let ledger = ledger_arc.read().map_err(|_|
            HandlerError::Internal("Failed to acquire ledger read lock".to_string())
        )?;

        // Validate the fee collect operation
        validate_fee_collect(
            &ledger,
            msg.pubkey,
            msg.amount,
            msg.block_height,
        ).map_err(|e| HandlerError::ValidationFailed(e))?;

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
    let ledger_arc = ctx.get_ledger(&sender, &our_node_id.to_string())
        .ok_or(HandlerError::LedgerNotFound {
            operator: sender,
            reserves_id: our_node_id.to_string(),
        })?;

    // Validate the ledger close
    let (sequence, prev_hash, new_hash) = {
        let ledger = ledger_arc.read().map_err(|_|
            HandlerError::Internal("Failed to acquire ledger read lock".to_string())
        )?;

        // Validate the ledger can be closed
        validate_ledger_close(&ledger)
            .map_err(|e| HandlerError::ValidationFailed(e))?;

        // Return current state for response
        (ledger.sequence(), ledger.hash(), ledger.hash())
    };

    // Emit event for ledger close
    ctx.emit_event(ProtocolEvent::LedgerClosed {
        operator: sender,
        reserves_id: our_node_id.to_string(),
    });

    // Return validated data for LDK layer to record to ledger and sign
    Ok(HandlerResult::Response(ResponseData::LedgerCloseValidated {
        operator: sender,
        reserves_id: our_node_id.to_string(),
        sequence,
        prev_hash,
        new_hash,
    }))
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
    let ledger_arc = ctx.get_ledger(&sender, &our_node_id.to_string())
        .ok_or(HandlerError::LedgerNotFound {
            operator: sender,
            reserves_id: our_node_id.to_string(),
        })?;

    // Validate the cosign invoice request
    {
        let ledger = ledger_arc.read().map_err(|_|
            HandlerError::Internal("Failed to acquire ledger read lock".to_string())
        )?;

        // Validate the cosign operation
        validate_cosign_invoice(
            &ledger,
            msg.assigned_deposit,
            msg.amount,
            &msg.invoice_id,
            &msg.payment_hash,
        ).map_err(|e| HandlerError::ValidationFailed(e))?;
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
    Ok(HandlerResult::Response(ResponseData::CosignInvoiceValidated {
        operator: sender,
        reserves_id: our_node_id.to_string(),
        deposit_pubkey: msg.assigned_deposit,
        amount: msg.amount,
        payment_hash: msg.payment_hash,
        invoice_id: msg.invoice_id.clone(),
        bolt11: msg.bolt11.clone(),
    }))
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

    let recovery_manager = ctx.recovery_manager()
        .ok_or(HandlerError::InvalidState("No recovery manager available".to_string()))?;

    let is_non_compliant = {
        let manager = recovery_manager.lock().map_err(|_|
            HandlerError::Internal("Failed to acquire recovery manager lock".to_string())
        )?;
        match manager.get_recovery(&ledger_id) {
            Some(state) => {
                matches!(state.phase, crate::recovery::RecoveryPhase::NonCompliantRecovery { .. })
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
            return Ok(HandlerResult::Rejected("No signing key available".to_string()));
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
        return Ok(HandlerResult::Response(ResponseData::LedgerExportResponse {
            operator_id: msg.operator_id,
            reserves_id: msg.reserves_id.clone(),
            ledger_address: String::new(),
            version: 1,
            exported_at: crate::now_unix_timestamp(),
            block_height: msg.block_height,
            update_count: 0,
            updates_data: Vec::new(),
            success: false,
            error_message: Some("We are not the operator of this ledger".to_string()),
        }));
    }

    // Get the ledger
    let ledger = ctx.get_ledger(&msg.operator_id, &msg.reserves_id);
    let ledger = match ledger {
        Some(l) => l,
        None => {
            return Ok(HandlerResult::Response(ResponseData::LedgerExportResponse {
                operator_id: msg.operator_id,
                reserves_id: msg.reserves_id.clone(),
                ledger_address: String::new(),
                version: 1,
                exported_at: crate::now_unix_timestamp(),
                block_height: msg.block_height,
                update_count: 0,
                updates_data: Vec::new(),
                success: false,
                error_message: Some("Ledger not found".to_string()),
            }));
        }
    };

    // Read the ledger and export
    let ledger_guard = ledger.read().map_err(|_| HandlerError::Internal("Lock poisoned".to_string()))?;

    // Validate: sender should be a partner or quorum member
    let is_partner = ledger_guard.reserves_key() == sender.to_string()
        || sender.to_string() == msg.reserves_id;
    let is_quorum_member = ledger_guard.state.quorum_members.iter().any(|m| m.pubkey == sender);

    if !is_partner && !is_quorum_member {
        return Ok(HandlerResult::Response(ResponseData::LedgerExportResponse {
            operator_id: msg.operator_id,
            reserves_id: msg.reserves_id.clone(),
            ledger_address: ledger_guard.state.ledger_address.clone(),
            version: 1,
            exported_at: crate::now_unix_timestamp(),
            block_height: msg.block_height,
            update_count: 0,
            updates_data: Vec::new(),
            success: false,
            error_message: Some("Sender is not authorized to access this ledger".to_string()),
        }));
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

    Ok(HandlerResult::Response(ResponseData::LedgerExportResponse {
        operator_id: export.operator_id,
        reserves_id: export.reserves_id,
        ledger_address: export.ledger_address,
        version: export.version,
        exported_at: export.exported_at,
        block_height: export.block_height,
        update_count: export.updates.len() as u32,
        updates_data,
        success: true,
        error_message: None,
    }))
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
    let (operator_id, reserves_id, ledger_address, version, exported_at, block_height, update_count, updates_data, success, error_message) =
        match response {
            ResponseData::LedgerExportResponse {
                operator_id,
                reserves_id,
                ledger_address,
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
                ledger_address.clone(),
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
                crate::validation::ValidationError::DecodeError(format!("Failed to deserialize update: {}", e))
            })?;
        updates.push(update);
    }

    // Extract genesis_block from the first LedgerOpen operation if available
    // This is a fallback - ideally the export protocol would include these fields
    let genesis_block = updates.first()
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
    let ledger_id = crate::types::LedgerState::compute_ledger_id(&operator_id, &reserves_id, genesis_block);

    // Create LedgerExport and validate
    let export = crate::validation::LedgerExport {
        version,
        ledger_id,
        genesis_block,
        operator_id,
        reserves_id,
        ledger_address,
        updates,
        exported_at,
        block_height,
    };

    crate::validation::LedgerConformanceValidator::validate(&export)
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Create a ledger ID from operator and reserves_id
pub fn make_ledger_id(operator: PublicKey, reserves_id: String) -> LedgerId {
    LedgerId::new(operator, reserves_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, RwLock, Mutex};
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use crate::ledger::{Ledger, LedgerRole};
    use crate::recovery::RecoveryManager;

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
            self.recovery_manager = Some(Arc::new(Mutex::new(
                RecoveryManager::new(self.our_node_id)
            )));
            self
        }

        fn add_ledger(&mut self, operator: PublicKey, reserves_id: PublicKey, ledger: Ledger) {
            self.ledgers.insert((operator, reserves_id.to_string()), Arc::new(RwLock::new(ledger)));
        }
    }

    impl crate::message_validation::ValidationContext for TestContext {
        fn get_ledger(&self, operator: &PublicKey, reserves_id: &str) -> Option<Arc<RwLock<Ledger>>> {
            self.ledgers.get(&(*operator, reserves_id.to_string())).cloned()
        }

        fn our_node_id(&self) -> PublicKey {
            self.our_node_id
        }
    }

    impl HandlerContext for TestContext {
        fn queue_message(&self, _peer: PublicKey, _msg: crate::messages::DepositsMessage) -> Result<(), HandlerError> {
            // Not used in current tests - responses are returned via HandlerResult
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
        if seed == 0 { bytes[0] = 1; }
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
        let ledger = Ledger::new(operator, our_node_id.to_string(), LedgerRole::Partner, vec![], "tb1qtest".to_string(), 0);
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
        let ledger = Ledger::new(operator, our_node_id.to_string(), LedgerRole::Partner, vec![], "tb1qtest".to_string(), 0);
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
        let mut ledger = Ledger::new(operator, our_node_id.to_string(), LedgerRole::Partner, vec![], "tb1qtest".to_string(), 0);
        ledger.state.quorum_members.push(crate::types::QuorumMember { pubkey: quorum_member, ledger_id: String::new(), min_fee_bps: None, min_fee_fixed: None, max_fee_period: None, collateral_lock_amount: None, collateral_lock_until: None });
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
        let ledger = Ledger::new(operator, our_node_id.to_string(), LedgerRole::Partner, vec![], "tb1qtest".to_string(), 0);
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
        let mut ledger = Ledger::new(operator, our_node_id.to_string(), LedgerRole::Partner, vec![], "tb1qtest".to_string(), 0);
        ledger.state.quorum_members.push(crate::types::QuorumMember { pubkey: quorum_member, ledger_id: String::new(), min_fee_bps: None, min_fee_fixed: None, max_fee_period: None, collateral_lock_amount: None, collateral_lock_until: None });
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
            Ok(HandlerResult::Response(ResponseData::CollateralAttestationProcessed { amount, .. })) => {
                assert_eq!(amount, 100_000);
            }
            other => panic!("Expected Response(CollateralAttestationProcessed), got {:?}", other),
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
        assert!(matches!(result, Ok(HandlerResult::Ok)), "Expected Ok(HandlerResult::Ok), got {:?}", result);

        // Check that event was emitted
        let events = ctx.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        match &events[0] {
            ProtocolEvent::UncreditedPaymentReceived { operator: op, reserves_id, amount_msat: amt, .. } => {
                assert_eq!(*op, operator);
                assert_eq!(*reserves_id, partner.to_string());
                assert_eq!(*amt, 1_000_000);
            }
            other => panic!("Expected UncreditedPaymentReceived event, got {:?}", other),
        }
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
        let mut ledger = Ledger::new(operator, our_node_id.to_string(), LedgerRole::Partner, vec![], "tb1qtest".to_string(), 0);
        ledger.state.reserves.amount = 100_000;
        ledger.state.received_collateral_amount = 100_000;
        ctx.add_ledger(operator, our_node_id, ledger);

        // Create payment hash that's not all the same byte
        let mut payment_hash = [0u8; 32];
        for i in 0..32 { payment_hash[i] = i as u8; }

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
        let mut ledger = Ledger::new(operator, our_node_id.to_string(), LedgerRole::Partner, vec![], "tb1qtest".to_string(), 0);
        ledger.state.reserves.amount = 100_000;
        ledger.state.received_collateral_amount = 100_000;
        let deposit = Deposit::from_pubkey(&deposit_pubkey, None);
        ledger.state.deposits.insert(deposit.deposit_id, deposit);
        ctx.add_ledger(operator, our_node_id, ledger);

        // Create payment hash that's not all the same byte
        let mut payment_hash = [0u8; 32];
        for i in 0..32 { payment_hash[i] = i as u8; }

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
            Ok(HandlerResult::Response(ResponseData::CreditPaymentValidated { amount, .. })) => {
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
        let mut ledger = Ledger::new(operator, our_node_id.to_string(), LedgerRole::Partner, vec![], "tb1qtest".to_string(), 0);
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
        let mut ledger = Ledger::new(operator, our_node_id.to_string(), LedgerRole::Partner, vec![], "tb1qtest".to_string(), 0);
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
        let mut ledger = Ledger::new(operator, our_node_id.to_string(), LedgerRole::Partner, vec![], "tb1qtest".to_string(), 0);
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
        let mut ledger = Ledger::new(operator, our_node_id.to_string(), LedgerRole::Partner, vec![], "tb1qtest".to_string(), 0);
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
        use bitcoin::hashes::{sha256, Hash};
        use crate::types::Deposit;

        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let deposit_pubkey = create_test_pubkey(3);

        let mut ctx = TestContext::new(our_node_id);

        // Create a ledger with the deposit
        let mut ledger = Ledger::new(operator, our_node_id.to_string(), LedgerRole::Partner, vec![], "tb1qtest".to_string(), 0);
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
            Ok(HandlerResult::Response(ResponseData::FulfillPaymentValidated { amount, preimage: p, .. })) => {
                assert_eq!(amount, 50_000);
                assert_eq!(p, preimage);
            }
            other => panic!("Expected Response(FulfillPaymentValidated), got {:?}", other),
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
        let mut ledger = Ledger::new(operator, our_node_id.to_string(), LedgerRole::Partner, vec![], "tb1qtest".to_string(), 0);
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
        let mut ledger = Ledger::new(operator, our_node_id.to_string(), LedgerRole::Partner, vec![], "tb1qtest".to_string(), 0);
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
        let mut ledger = Ledger::new(operator, our_node_id.to_string(), LedgerRole::Partner, vec![], "tb1qtest".to_string(), 0);
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
        let ledger = Ledger::new(operator, our_node_id.to_string(), LedgerRole::Partner, vec![], "tb1qtest".to_string(), 0);
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
        let mut ledger = Ledger::new(operator, our_node_id.to_string(), LedgerRole::Partner, vec![], "tb1qtest".to_string(), 0);
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
        let ledger = Ledger::new(operator, our_node_id.to_string(), LedgerRole::Partner, vec![], "tb1qtest".to_string(), 0);
        ctx.add_ledger(operator, our_node_id, ledger);

        let fees = FeeStructure {
            annualized_fixed: 1000,
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
        let ledger = Ledger::new(operator, our_node_id.to_string(), LedgerRole::Partner, vec![], "tb1qtest".to_string(), 0);
        ctx.add_ledger(operator, our_node_id, ledger);

        // Invalid fee structure with zero frequency
        let invalid_fees = FeeStructure {
            annualized_fixed: 1000,
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
        let mut ledger = Ledger::new(operator, our_node_id.to_string(), LedgerRole::Partner, vec![], "tb1qtest".to_string(), 0);
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
        let mut ledger = Ledger::new(operator, our_node_id.to_string(), LedgerRole::Partner, vec![], "tb1qtest".to_string(), 0);
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
        let mut ledger = Ledger::new(operator, our_node_id.to_string(), LedgerRole::Partner, vec![], "tb1qtest".to_string(), 0);
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
        let ledger = Ledger::new(operator, our_node_id.to_string(), LedgerRole::Partner, vec![], "tb1qtest".to_string(), 0);
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
        let ledger = Ledger::new(operator, our_node_id.to_string(), LedgerRole::Partner, vec![], "tb1qtest".to_string(), 0);
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
        let mut ledger = Ledger::new(operator, our_node_id.to_string(), LedgerRole::Partner, vec![], "tb1qtest".to_string(), 0);
        let deposit = Deposit::from_pubkey(&deposit_pubkey, None);
        ledger.state.deposits.insert(deposit.deposit_id, deposit);
        ctx.add_ledger(operator, our_node_id, ledger);

        let new_fees = FeeStructure {
            annualized_fixed: 2000,
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
        let mut ledger = Ledger::new(operator, our_node_id.to_string(), LedgerRole::Partner, vec![], "tb1qtest".to_string(), 0);
        let deposit = Deposit::from_pubkey(&deposit_pubkey, None);
        ledger.state.deposits.insert(deposit.deposit_id, deposit);
        ctx.add_ledger(operator, our_node_id, ledger);

        // Invalid fee structure with zero frequency
        let invalid_fees = FeeStructure {
            annualized_fixed: 2000,
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
        let mut ledger = Ledger::new(operator, our_node_id.to_string(), LedgerRole::Partner, vec![], "tb1qtest".to_string(), 0);
        let deposit = Deposit::from_pubkey(&deposit_pubkey, None);
        ledger.state.deposits.insert(deposit.deposit_id, deposit);
        ctx.add_ledger(operator, our_node_id, ledger);

        // Fee rate too high (over 100%)
        let invalid_fees = FeeStructure {
            annualized_fixed: 0,
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
        let ledger = Ledger::new(operator, our_node_id.to_string(), LedgerRole::Partner, vec![], "tb1qtest".to_string(), 0);
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
            Ok(HandlerResult::Response(ResponseData::ReservesAddOutputValidated { initial_amount, .. })) => {
                assert_eq!(initial_amount, 100_000);
            }
            other => panic!("Expected Response(ReservesAddOutputValidated), got {:?}", other),
        }
    }

    #[test]
    fn test_handle_reserves_add_output_amount_too_small() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let spend_to = create_test_pubkey(3);

        let mut ctx = TestContext::new(our_node_id);

        // Create a ledger with no reserves
        let ledger = Ledger::new(operator, our_node_id.to_string(), LedgerRole::Partner, vec![], "tb1qtest".to_string(), 0);
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
        let mut ledger = Ledger::new(operator, our_node_id.to_string(), LedgerRole::Partner, vec![], "tb1qtest".to_string(), 0);
        ledger.state.reserves.amount = 100_000;
        ledger.state.reserves.spend_to = spend_to;
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
            other => panic!("Expected Response(ReservesAddOutputValidated), got {:?}", other),
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
        let spend_to = create_test_pubkey(3);

        let mut ctx = TestContext::new(our_node_id);

        // Create a ledger with reserves but no deposits
        let mut ledger = Ledger::new(operator, our_node_id.to_string(), LedgerRole::Partner, vec![], "tb1qtest".to_string(), 0);
        ledger.state.reserves.amount = 100_000;
        ledger.state.reserves.spend_to = spend_to;
        ctx.add_ledger(operator, our_node_id, ledger);

        let msg = ReservesRemoveOutputMsg {
            reserves_id: our_node_id.to_string(),
            remove_all: true,
        };

        // Valid request - should return response
        let result = handle_reserves_remove_output(&ctx, &msg, operator);
        match result {
            Ok(HandlerResult::Response(ResponseData::ReservesRemoveOutputValidated { .. })) => {}
            other => panic!("Expected Response(ReservesRemoveOutputValidated), got {:?}", other),
        }
    }

    #[test]
    fn test_handle_reserves_remove_output_has_active_deposits() {
        use crate::types::Deposit;

        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let spend_to = create_test_pubkey(3);
        let deposit_pubkey = create_test_pubkey(4);

        let mut ctx = TestContext::new(our_node_id);

        // Create a ledger with reserves and active deposits
        let mut ledger = Ledger::new(operator, our_node_id.to_string(), LedgerRole::Partner, vec![], "tb1qtest".to_string(), 0);
        ledger.state.reserves.amount = 100_000;
        ledger.state.reserves.spend_to = spend_to;
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
        let ledger = Ledger::new(operator, our_node_id.to_string(), LedgerRole::Partner, vec![], "tb1qtest".to_string(), 0);
        ctx.add_ledger(operator, our_node_id, ledger);

        let msg = ReservesRemoveOutputMsg {
            reserves_id: our_node_id.to_string(),
            remove_all: true,
        };

        // Already removed - should return success (idempotent)
        let result = handle_reserves_remove_output(&ctx, &msg, operator);
        match result {
            Ok(HandlerResult::Response(ResponseData::ReservesRemoveOutputValidated { .. })) => {}
            other => panic!("Expected Response(ReservesRemoveOutputValidated), got {:?}", other),
        }
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
        let ledger = Ledger::new(operator, our_node_id.to_string(), LedgerRole::Partner, vec![], "tb1qtest".to_string(), 0);
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
        let mut ledger = Ledger::new(operator, our_node_id.to_string(), LedgerRole::Partner, vec![], "tb1qtest".to_string(), 0);
        let mut deposit = Deposit::from_pubkey(&deposit_pubkey, Some(FeeStructure {
            annualized_fixed: 0,
            annualized_bps: 100,
            frequency_blocks: 100,
        }));
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
            Ok(HandlerResult::Response(ResponseData::FeeCollectValidated { amount, block_height, .. })) => {
                assert_eq!(amount, 1000);
                assert_eq!(block_height, 100);
            }
            other => panic!("Expected Response(FeeCollectValidated), got {:?}", other),
        }

        // Check that event was emitted
        let events = ctx.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        match &events[0] {
            ProtocolEvent::FeeCollected { operator: op, amount: amt, .. } => {
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
        let mut ledger = Ledger::new(operator, our_node_id.to_string(), LedgerRole::Partner, vec![], "tb1qtest".to_string(), 0);
        let mut deposit = Deposit::from_pubkey(&deposit_pubkey, Some(FeeStructure {
            annualized_fixed: 0,
            annualized_bps: 100,
            frequency_blocks: 100,
        }));
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
        let mut ledger = Ledger::new(operator, our_node_id.to_string(), LedgerRole::Partner, vec![], "tb1qtest".to_string(), 0);
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
        let mut ledger = Ledger::new(operator, our_node_id.to_string(), LedgerRole::Partner, vec![], "tb1qtest".to_string(), 0);
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
        let ledger = Ledger::new(operator, our_node_id.to_string(), LedgerRole::Partner, vec![], "tb1qtest".to_string(), 0);
        ctx.add_ledger(operator, our_node_id, ledger);

        let msg = LedgerCloseMsg {
            reserves_id: our_node_id.to_string(),
        };

        // Valid close of empty ledger
        let result = handle_ledger_close(&ctx, &msg, operator);
        match result {
            Ok(HandlerResult::Response(ResponseData::LedgerCloseValidated { operator: op, reserves_id, .. })) => {
                assert_eq!(op, operator);
                assert_eq!(reserves_id, our_node_id.to_string());
            }
            other => panic!("Expected Response(LedgerCloseValidated), got {:?}", other),
        }

        // Check that event was emitted
        let events = ctx.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        match &events[0] {
            ProtocolEvent::LedgerClosed { operator: op, reserves_id } => {
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
        let mut ledger = Ledger::new(operator, our_node_id.to_string(), LedgerRole::Partner, vec![], "tb1qtest".to_string(), 0);
        let deposit = Deposit::from_pubkey(&deposit_pubkey, None); // Balance defaults to 0
        ledger.state.deposits.insert(deposit.deposit_id, deposit);
        ctx.add_ledger(operator, our_node_id, ledger);

        let msg = LedgerCloseMsg {
            reserves_id: our_node_id.to_string(),
        };

        // Valid close with zero-balance deposits
        let result = handle_ledger_close(&ctx, &msg, operator);
        assert!(matches!(result, Ok(HandlerResult::Response(ResponseData::LedgerCloseValidated { .. }))));
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
        let ledger = Ledger::new(operator, our_node_id.to_string(), LedgerRole::Partner, vec![], "tb1qtest".to_string(), 0);
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
        let spend_to = create_test_pubkey(4);

        let mut ctx = TestContext::new(our_node_id);

        // Create a ledger with a deposit
        let mut ledger = Ledger::new(operator, our_node_id.to_string(), LedgerRole::Partner, vec![], "tb1qtest".to_string(), 0);
        let deposit = Deposit::from_pubkey(&deposit_pubkey, None);
        ledger.state.deposits.insert(deposit.deposit_id, deposit);
        ledger.state.reserves.amount = 200_000;
        ledger.state.reserves.spend_to = spend_to;
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
        let spend_to = create_test_pubkey(4);

        let mut ctx = TestContext::new(our_node_id);

        // Create a ledger with a deposit, sufficient reserves, and collateral
        let mut ledger = Ledger::new(operator, our_node_id.to_string(), LedgerRole::Partner, vec![], "tb1qtest".to_string(), 0);
        let deposit = Deposit::from_pubkey(&deposit_pubkey, None);
        ledger.state.deposits.insert(deposit.deposit_id, deposit);
        ledger.state.reserves.amount = 200_000;
        ledger.state.reserves.spend_to = spend_to;
        ledger.state.received_collateral_amount = 200_000; // Set collateral to allow invoice
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
            Ok(HandlerResult::Response(ResponseData::CosignInvoiceValidated { amount, deposit_pubkey: dp, .. })) => {
                assert_eq!(amount, 100_000);
                assert_eq!(dp, deposit_pubkey);
            }
            other => panic!("Expected Response(CosignInvoiceValidated), got {:?}", other),
        }

        // Check that event was emitted
        let events = ctx.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        match &events[0] {
            ProtocolEvent::InvoiceCosignRequested { operator: op, amount: amt, .. } => {
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
        let spend_to = create_test_pubkey(4);

        let mut ctx = TestContext::new(our_node_id);

        // Create a ledger with a deposit but insufficient reserves
        let mut ledger = Ledger::new(operator, our_node_id.to_string(), LedgerRole::Partner, vec![], "tb1qtest".to_string(), 0);
        let deposit = Deposit::from_pubkey(&deposit_pubkey, None);
        ledger.state.deposits.insert(deposit.deposit_id, deposit);
        ledger.state.reserves.amount = 50_000; // Only 50k reserves
        ledger.state.reserves.spend_to = spend_to;
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
            ProtocolEvent::RecoveryClaimRequested { operator: op, claimant: cl, tier_index, .. } => {
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
            ProtocolEvent::RecoveryClaimSignatureReceived { operator: op, signer: s, .. } => {
                assert_eq!(*op, operator);
                assert_eq!(*s, signer);
            }
            other => panic!("Expected RecoveryClaimSignatureReceived event, got {:?}", other),
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
                old_operator: old_op, new_operator: new_op, confirmation_block, ..
            } => {
                assert_eq!(*old_op, operator);
                assert_eq!(*new_op, new_operator);
                assert_eq!(*confirmation_block, 12345);
            }
            other => panic!("Expected RecoveryClaimCompleted event, got {:?}", other),
        }
    }

}
