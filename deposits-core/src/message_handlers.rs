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
    CollateralAddPartnerMsg, CollateralRemovePartnerMsg,
    CollateralAttestationMsg, UncreditedPaymentMsg,
    ReceivingCreditPaymentMsg, SendingLockPaymentMsg,
    SendingFulfillPaymentMsg, SendingFailPaymentMsg,
    DepositOpenMsg, DepositCloseMsg, DepositUpdateMsg,
    ReservesAddOutputMsg, ReservesRemoveOutputMsg,
    ReservesIncreaseMsg, ReservesDecreaseMsg,
};
use crate::operation_validation::{
    validate_credit_payment, validate_payment_lock,
    validate_payment_fulfill, validate_payment_fail,
    validate_deposit_add, validate_deposit_close, validate_deposit_update,
    validate_reserves_add, validate_reserves_increase, validate_reserves_decrease,
};

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
        partner_id: PublicKey,
        consent_granted: bool,
        // Signature is populated by the LDK layer which has access to keys
    },
    /// Quorum join response
    QuorumJoin {
        accepted: bool,
        rejection_reason: Option<String>,
    },
    /// Collateral partner added - response with signature data for ACK
    CollateralPartnerAdded {
        operator_id: PublicKey,
        partner_id: PublicKey,
        collateral_partner: PublicKey,
        /// Sequence number after append
        sequence: u64,
        /// Previous state hash
        prev_hash: [u8; 32],
        /// New state hash after append
        new_hash: [u8; 32],
    },
    /// Collateral partner removed - response with signature data for ACK
    CollateralPartnerRemoved {
        partner_id: PublicKey,
        collateral_partner: PublicKey,
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
        collateral_partner: PublicKey,
        amount: u64,
    },
    /// Uncredited payment accusation - emit event for node layer
    UncreditedPaymentAccusation {
        operator: PublicKey,
        partner: PublicKey,
        payment_hash: [u8; 32],
        deposit_pubkey: PublicKey,
        amount_msat: u64,
        settlement_sequence: u64,
    },
    /// Credit payment validated - partner should sign and ACK
    CreditPaymentValidated {
        operator: PublicKey,
        partner: PublicKey,
        deposit_pubkey: PublicKey,
        amount: u64,
        payment_hash: [u8; 32],
        invoice_id: String,
        sequence_number: u64,
    },
    /// Lock payment validated - partner should sign and ACK
    LockPaymentValidated {
        operator: PublicKey,
        partner: PublicKey,
        deposit_pubkey: PublicKey,
        amount: u64,
        payment_id: [u8; 32],
        sequence_number: u64,
    },
    /// Fulfill payment validated - partner should sign and ACK
    FulfillPaymentValidated {
        operator: PublicKey,
        partner: PublicKey,
        deposit_pubkey: PublicKey,
        amount: u64,
        payment_id: [u8; 32],
        preimage: [u8; 32],
        sequence_number: u64,
    },
    /// Fail payment validated - partner should sign and ACK
    FailPaymentValidated {
        operator: PublicKey,
        partner: PublicKey,
        deposit_pubkey: PublicKey,
        amount: u64,
        payment_id: [u8; 32],
        sequence_number: u64,
    },
    /// Deposit open validated - partner should sign and ACK
    DepositOpenValidated {
        operator: PublicKey,
        partner: PublicKey,
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
        partner: PublicKey,
        deposit_pubkey: PublicKey,
        /// Sequence number after append
        sequence: u64,
        /// Previous state hash
        prev_hash: [u8; 32],
        /// New state hash after append
        new_hash: [u8; 32],
    },
    /// Deposit update validated - partner should sign and ACK
    DepositUpdateValidated {
        operator: PublicKey,
        partner: PublicKey,
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
        partner: PublicKey,
        initial_amount: u64,
        spend_to: PublicKey,
        collateral_partners: Vec<PublicKey>,
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
        partner: PublicKey,
        /// Sequence number after append
        sequence: u64,
        /// Previous state hash
        prev_hash: [u8; 32],
        /// New state hash after append
        new_hash: [u8; 32],
    },
    /// Reserves increase validated - partner should sign and ACK
    ReservesIncreaseValidated {
        operator: PublicKey,
        partner: PublicKey,
        new_amount: u64,
        /// Sequence number after append
        sequence: u64,
        /// Previous state hash
        prev_hash: [u8; 32],
        /// New state hash after append
        new_hash: [u8; 32],
    },
    /// Reserves decrease validated - partner should sign and ACK
    ReservesDecreaseValidated {
        operator: PublicKey,
        partner: PublicKey,
        new_amount: u64,
        /// Sequence number after append
        sequence: u64,
        /// Previous state hash
        prev_hash: [u8; 32],
        /// New state hash after append
        new_hash: [u8; 32],
    },
}

// ============================================================================
// Quorum Message Handlers
// ============================================================================

/// Handle a QuorumJoinRequest message.
///
/// Core logic for processing join requests, independent of Lightning implementation.
/// Returns a HandlerResult indicating whether the request should be accepted.
pub fn handle_quorum_join_request<C: HandlerContext>(
    _ctx: &C,
    msg: &QuorumJoinRequestMsgWire,
    sender: PublicKey,
) -> Result<HandlerResult, HandlerError> {
    // Validate: sender should match the requester
    if sender != msg.requester_pubkey {
        return Ok(HandlerResult::Rejected(
            "Sender doesn't match requester".to_string()
        ));
    }

    // For now, return Ok - the actual quorum management happens in the LDK layer
    // because it requires access to the QuorumManager which is LDK-specific state
    //
    // In a full implementation, the HandlerContext would provide access to quorum
    // management operations.

    Ok(HandlerResult::Ok)
}

/// Handle a QuorumVoteRequest message.
///
/// This is sent by quorum initiators to request votes for a reserves spend.
/// Voters must validate conformance before signing.
pub fn handle_quorum_vote_request<C: HandlerContext>(
    ctx: &C,
    msg: &QuorumVoteRequestMsg,
    _sender: PublicKey,
) -> Result<HandlerResult, HandlerError> {
    // Get our node ID (for future use in signing)
    let _our_node_id = ctx.our_node_id();

    // Get the ledger to verify we have state for this ledger
    let ledger_arc = ctx.get_ledger(&msg.operator_id, &msg.partner_id)
        .ok_or(HandlerError::LedgerNotFound {
            operator: msg.operator_id,
            partner: msg.partner_id,
        })?;

    // Read ledger state for validation
    let (our_sequence, our_state_hash) = {
        let ledger = ledger_arc.read().map_err(|_|
            HandlerError::Internal("Failed to acquire ledger lock".to_string())
        )?;
        (ledger.sequence(), ledger.hash())
    };

    // Basic validation: check sequence numbers match
    let _vote = our_state_hash == msg.state_hash && our_sequence >= msg.sequence_number;

    // In the actual implementation, we would:
    // 1. Run full conformance validation
    // 2. Sign the vote
    // 3. Sign the spend transaction if conforming
    // 4. Queue the vote message
    //
    // For now, this demonstrates the structure - the full implementation
    // with signing happens in the LDK layer which has access to keys.

    Ok(HandlerResult::Ok)
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
            partner: msg.partner,
        });
    }

    Ok(HandlerResult::Ok)
}

// ============================================================================
// Collateral Message Handlers
// ============================================================================

/// Handle a CollateralConsentRequest message.
///
/// Sent by operators requesting consent from potential collateral partners.
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
    let has_channel_with_operator = ctx.get_ledger(&msg.operator_id, &our_node_id).is_some();

    let consent_granted = has_channel_with_operator;

    // Return response data - the LDK layer will construct the actual message
    // and sign it with the node's private key
    Ok(HandlerResult::Response(ResponseData::CollateralConsent {
        operator_id: msg.operator_id,
        partner_id: msg.partner_id,
        consent_granted,
    }))
}

/// Handle a CollateralConsentResponse message.
///
/// Received by operators after requesting consent from collateral partners.
pub fn handle_collateral_consent_response<C: HandlerContext>(
    _ctx: &C,
    msg: &CollateralConsentResponseMsg,
    _sender: PublicKey,
) -> Result<HandlerResult, HandlerError> {
    // The sender is the collateral partner

    if msg.consent_granted {
        // In the full implementation:
        // 1. Verify the signature
        // 2. Add the collateral partner to the ledger
        // 3. Send state sync to the new partner
        // 4. Emit event
        // These operations are handled in the LDK layer which has access to
        // the full ledger state and signing keys
    }

    Ok(HandlerResult::Ok)
}

/// Handle a CollateralAddPartner message.
///
/// Received by partners when an operator adds a collateral partner to a ledger.
/// The partner validates and appends to their copy of the ledger.
pub fn handle_collateral_add_partner<C: HandlerContext>(
    ctx: &C,
    msg: &CollateralAddPartnerMsg,
    sender: PublicKey,
) -> Result<HandlerResult, HandlerError> {
    let our_node_id = ctx.our_node_id();

    // We must be the partner_id to process this message
    if msg.partner_id != our_node_id {
        return Ok(HandlerResult::Rejected(format!(
            "We ({}) are not the target partner ({})",
            our_node_id, msg.partner_id
        )));
    }

    // Get the ledger - sender (operator) and us (partner)
    let ledger_arc = ctx.get_ledger(&sender, &msg.partner_id)
        .ok_or(HandlerError::LedgerNotFound {
            operator: sender,
            partner: msg.partner_id,
        })?;

    // Check for idempotency and get state
    {
        let ledger = ledger_arc.read().map_err(|_|
            HandlerError::Internal("Failed to acquire ledger read lock".to_string())
        )?;

        // Idempotency check: if collateral partner already exists, return success
        if ledger.state.collateral_partners.contains(&msg.collateral_partner) {
            return Ok(HandlerResult::Response(ResponseData::CollateralPartnerAdded {
                operator_id: msg.operator_id,
                partner_id: msg.partner_id,
                collateral_partner: msg.collateral_partner,
                sequence: ledger.sequence(),
                prev_hash: ledger.hash(),
                new_hash: ledger.hash(),
            }));
        }
    }

    // Append to ledger - this requires write access
    // The actual append happens in the LDK layer which has mutable access
    // Here we validate and return the data needed for the response
    //
    // Note: The core logic validates that this is a legitimate add request.
    // The LDK layer will:
    // 1. Call append_v1_mut_with_metadata on the ledger
    // 2. Sign the update as partner (porcupine dance)
    // 3. Send the ACK with signature
    // 4. Sync with QuorumManager if applicable

    // For now, return Ok to indicate the request is valid
    // The LDK layer handles the actual mutation and signing
    Ok(HandlerResult::Ok)
}

/// Handle a CollateralRemovePartner message.
///
/// Received by partners when an operator removes a collateral partner from a ledger.
/// The partner validates and appends to their copy of the ledger.
pub fn handle_collateral_remove_partner<C: HandlerContext>(
    ctx: &C,
    msg: &CollateralRemovePartnerMsg,
    sender: PublicKey,
) -> Result<HandlerResult, HandlerError> {
    let our_node_id = ctx.our_node_id();

    // We must be the partner_id to process this message
    if msg.partner_id != our_node_id {
        return Ok(HandlerResult::Rejected(format!(
            "We ({}) are not the target partner ({})",
            our_node_id, msg.partner_id
        )));
    }

    // Get the ledger - sender (operator) and us (partner)
    let ledger_arc = ctx.get_ledger(&sender, &msg.partner_id)
        .ok_or(HandlerError::LedgerNotFound {
            operator: sender,
            partner: msg.partner_id,
        })?;

    // Validate the collateral partner exists
    {
        let ledger = ledger_arc.read().map_err(|_|
            HandlerError::Internal("Failed to acquire ledger read lock".to_string())
        )?;

        // Check that the collateral partner exists
        if !ledger.state.collateral_partners.contains(&msg.collateral_partner) {
            return Ok(HandlerResult::Rejected(format!(
                "Collateral partner {} not found in ledger",
                msg.collateral_partner
            )));
        }
    }

    // The actual removal happens in the LDK layer
    // Return Ok to indicate the request is valid
    Ok(HandlerResult::Ok)
}

/// Handle a CollateralAttestation message.
///
/// Received by operators from collateral partners after they process a CollateralIncrease.
/// The operator stores the attestation as proof and records CollateralStatus on channel ledgers.
pub fn handle_collateral_attestation<C: HandlerContext>(
    ctx: &C,
    msg: &CollateralAttestationMsg,
    sender: PublicKey,
) -> Result<HandlerResult, HandlerError> {
    let our_node_id = ctx.our_node_id();

    // The sender should be the collateral partner
    if sender != msg.collateral_partner {
        return Ok(HandlerResult::Rejected(format!(
            "Sender {} doesn't match collateral_partner {}",
            sender, msg.collateral_partner
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
    // 2. Create CollateralStatus on channel ledgers
    // 3. Send to channel partners for bilateral signing
    Ok(HandlerResult::Response(ResponseData::CollateralAttestationProcessed {
        operator: msg.operator,
        collateral_partner: msg.collateral_partner,
        amount: msg.amount,
    }))
}

/// Handle an UncreditedPayment accusation message.
///
/// This is a fraud proof broadcast by a partner claiming the operator
/// failed to credit a payment they received. Collateral partners must:
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
    if let Some(ledger_arc) = ctx.get_ledger(&msg.operator, &msg.partner) {
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

    // 4. Emit event for node layer to:
    //    - Store the accusation
    //    - Force-close any channel with the operator
    //    - Forward to our own collateral partners
    ctx.emit_event(ProtocolEvent::UncreditedPaymentReceived {
        operator: msg.operator,
        partner: msg.partner,
        payment_hash: msg.payment_hash,
        amount_msat: msg.amount_msat,
    });

    // Return the accusation data for higher layers to act on
    Ok(HandlerResult::Response(ResponseData::UncreditedPaymentAccusation {
        operator: msg.operator,
        partner: msg.partner,
        payment_hash: msg.payment_hash,
        deposit_pubkey: msg.deposit_pubkey,
        amount_msat: msg.amount_msat,
        settlement_sequence: msg.settlement_sequence,
    }))
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
    if msg.partner_id != our_node_id {
        return Ok(HandlerResult::Rejected(format!(
            "We ({}) are not the target partner ({})",
            our_node_id, msg.partner_id
        )));
    }

    // Get the ledger - sender (operator) and us (partner)
    let ledger_arc = ctx.get_ledger(&sender, &msg.partner_id)
        .ok_or(HandlerError::LedgerNotFound {
            operator: sender,
            partner: msg.partner_id,
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
    ctx.emit_event(ProtocolEvent::PaymentCredited {
        operator: sender,
        partner: msg.partner_id,
        deposit_pubkey: msg.deposit_pubkey,
        amount: msg.amount,
        payment_hash: msg.payment_hash,
    });

    // Return validated data for LDK layer to record to ledger and sign
    Ok(HandlerResult::Response(ResponseData::CreditPaymentValidated {
        operator: sender,
        partner: msg.partner_id,
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
    let ledger_arc = ctx.get_ledger(&sender, &our_node_id)
        .ok_or(HandlerError::LedgerNotFound {
            operator: sender,
            partner: our_node_id,
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
        partner: our_node_id,
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
    let ledger_arc = ctx.get_ledger(&sender, &our_node_id)
        .ok_or(HandlerError::LedgerNotFound {
            operator: sender,
            partner: our_node_id,
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

        if !ledger.state.deposits.contains_key(&msg.pubkey) {
            return Ok(HandlerResult::Rejected(format!(
                "Deposit with pubkey {} does not exist",
                msg.pubkey
            )));
        }
    }

    // Emit event for payment being sent
    ctx.emit_event(ProtocolEvent::PaymentSent {
        operator: sender,
        partner: our_node_id,
        deposit_pubkey: msg.pubkey,
        amount: msg.amount,
        payment_id: msg.payment_id,
    });

    // Return validated data for LDK layer to record to ledger and sign
    Ok(HandlerResult::Response(ResponseData::FulfillPaymentValidated {
        operator: sender,
        partner: our_node_id,
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
    let ledger_arc = ctx.get_ledger(&sender, &our_node_id)
        .ok_or(HandlerError::LedgerNotFound {
            operator: sender,
            partner: our_node_id,
        })?;

    // Validate the payment fail
    validate_payment_fail(msg.amount)
        .map_err(|e| HandlerError::ValidationFailed(e))?;

    // Also verify deposit exists in ledger
    {
        let ledger = ledger_arc.read().map_err(|_|
            HandlerError::Internal("Failed to acquire ledger read lock".to_string())
        )?;

        if !ledger.state.deposits.contains_key(&msg.pubkey) {
            return Ok(HandlerResult::Rejected(format!(
                "Deposit with pubkey {} does not exist",
                msg.pubkey
            )));
        }
    }

    // Return validated data for LDK layer to record to ledger and sign
    Ok(HandlerResult::Response(ResponseData::FailPaymentValidated {
        operator: sender,
        partner: our_node_id,
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
    let our_node_id = ctx.our_node_id();

    // We must be the partner to process this message
    if msg.partner_id != our_node_id {
        return Ok(HandlerResult::Rejected(format!(
            "We ({}) are not the target partner ({})",
            our_node_id, msg.partner_id
        )));
    }

    // Get the ledger - sender (operator) and us (partner)
    let ledger_arc = ctx.get_ledger(&sender, &msg.partner_id)
        .ok_or(HandlerError::LedgerNotFound {
            operator: sender,
            partner: msg.partner_id,
        })?;

    // Validate the deposit open
    let (sequence, prev_hash, new_hash) = {
        let ledger = ledger_arc.read().map_err(|_|
            HandlerError::Internal("Failed to acquire ledger read lock".to_string())
        )?;

        // Check for idempotency - if deposit already exists, return success
        if ledger.state.deposits.contains_key(&msg.pubkey) {
            return Ok(HandlerResult::Response(ResponseData::DepositOpenValidated {
                operator: sender,
                partner: msg.partner_id,
                deposit_pubkey: msg.pubkey,
                sequence: ledger.sequence(),
                prev_hash: ledger.hash(),
                new_hash: ledger.hash(),
            }));
        }

        // Validate the deposit add operation
        validate_deposit_add(
            &ledger,
            msg.pubkey,
            msg.fees.as_ref(),
        ).map_err(|e| HandlerError::ValidationFailed(e))?;

        // Return current state for response
        // Note: Actual ledger mutation happens in LDK layer
        (ledger.sequence(), ledger.hash(), ledger.hash())
    };

    // Return validated data for LDK layer to record to ledger and sign
    Ok(HandlerResult::Response(ResponseData::DepositOpenValidated {
        operator: sender,
        partner: msg.partner_id,
        deposit_pubkey: msg.pubkey,
        sequence,
        prev_hash,
        new_hash,
    }))
}

/// Handle a DepositClose message.
///
/// Received by partners when an operator closes a deposit.
/// The partner validates the deposit can be closed and signs the ledger update.
///
/// # Arguments
/// * `ctx` - Handler context providing access to ledgers and messaging
/// * `msg` - The deposit close message
/// * `sender` - Public key of the message sender (should be the operator)
///
/// # Returns
/// * `HandlerResult::Response(DepositCloseValidated)` - Close is valid, partner should sign and ACK
/// * `HandlerResult::Rejected(reason)` - Close is invalid with explanation
/// * `HandlerError` - Internal error during processing
pub fn handle_deposit_close<C: HandlerContext>(
    ctx: &C,
    msg: &DepositCloseMsg,
    sender: PublicKey,
) -> Result<HandlerResult, HandlerError> {
    let our_node_id = ctx.our_node_id();

    // We must be the partner to process this message
    if msg.partner_id != our_node_id {
        return Ok(HandlerResult::Rejected(format!(
            "We ({}) are not the target partner ({})",
            our_node_id, msg.partner_id
        )));
    }

    // Get the ledger - sender (operator) and us (partner)
    let ledger_arc = ctx.get_ledger(&sender, &msg.partner_id)
        .ok_or(HandlerError::LedgerNotFound {
            operator: sender,
            partner: msg.partner_id,
        })?;

    // Validate the deposit close
    let (sequence, prev_hash, new_hash) = {
        let ledger = ledger_arc.read().map_err(|_|
            HandlerError::Internal("Failed to acquire ledger read lock".to_string())
        )?;

        // Check for idempotency - if deposit doesn't exist, it may have already been closed
        if !ledger.state.deposits.contains_key(&msg.pubkey) {
            return Ok(HandlerResult::Response(ResponseData::DepositCloseValidated {
                operator: sender,
                partner: msg.partner_id,
                deposit_pubkey: msg.pubkey,
                sequence: ledger.sequence(),
                prev_hash: ledger.hash(),
                new_hash: ledger.hash(),
            }));
        }

        // Validate the deposit close operation
        validate_deposit_close(
            &ledger,
            msg.pubkey,
        ).map_err(|e| HandlerError::ValidationFailed(e))?;

        // Return current state for response
        (ledger.sequence(), ledger.hash(), ledger.hash())
    };

    // Return validated data for LDK layer to record to ledger and sign
    Ok(HandlerResult::Response(ResponseData::DepositCloseValidated {
        operator: sender,
        partner: msg.partner_id,
        deposit_pubkey: msg.pubkey,
        sequence,
        prev_hash,
        new_hash,
    }))
}

/// Handle a DepositUpdate message.
///
/// Received by partners when an operator updates a deposit's fee structure.
/// The partner validates the update and signs the ledger update.
///
/// # Arguments
/// * `ctx` - Handler context providing access to ledgers and messaging
/// * `msg` - The deposit update message
/// * `sender` - Public key of the message sender (should be the operator)
///
/// # Returns
/// * `HandlerResult::Response(DepositUpdateValidated)` - Update is valid, partner should sign and ACK
/// * `HandlerResult::Rejected(reason)` - Update is invalid with explanation
/// * `HandlerError` - Internal error during processing
pub fn handle_deposit_update<C: HandlerContext>(
    ctx: &C,
    msg: &DepositUpdateMsg,
    sender: PublicKey,
) -> Result<HandlerResult, HandlerError> {
    let our_node_id = ctx.our_node_id();

    // We must be the partner to process this message
    if msg.partner_id != our_node_id {
        return Ok(HandlerResult::Rejected(format!(
            "We ({}) are not the target partner ({})",
            our_node_id, msg.partner_id
        )));
    }

    // Get the ledger - sender (operator) and us (partner)
    let ledger_arc = ctx.get_ledger(&sender, &msg.partner_id)
        .ok_or(HandlerError::LedgerNotFound {
            operator: sender,
            partner: msg.partner_id,
        })?;

    // Validate the deposit update
    let (sequence, prev_hash, new_hash) = {
        let ledger = ledger_arc.read().map_err(|_|
            HandlerError::Internal("Failed to acquire ledger read lock".to_string())
        )?;

        // Validate the deposit update operation
        validate_deposit_update(
            &ledger,
            msg.pubkey,
            &msg.new_fees,
        ).map_err(|e| HandlerError::ValidationFailed(e))?;

        // Return current state for response
        (ledger.sequence(), ledger.hash(), ledger.hash())
    };

    // Return validated data for LDK layer to record to ledger and sign
    Ok(HandlerResult::Response(ResponseData::DepositUpdateValidated {
        operator: sender,
        partner: msg.partner_id,
        deposit_pubkey: msg.pubkey,
        sequence,
        prev_hash,
        new_hash,
    }))
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
    if msg.partner_id != our_node_id {
        return Ok(HandlerResult::Rejected(format!(
            "We ({}) are not the target partner ({})",
            our_node_id, msg.partner_id
        )));
    }

    // Get the ledger - sender (operator) and us (partner)
    let ledger_arc = ctx.get_ledger(&sender, &msg.partner_id)
        .ok_or(HandlerError::LedgerNotFound {
            operator: sender,
            partner: msg.partner_id,
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
                partner: msg.partner_id,
                initial_amount: msg.initial_amount,
                spend_to: msg.spend_to,
                collateral_partners: msg.collateral_partners.clone(),
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
        partner: msg.partner_id,
        initial_amount: msg.initial_amount,
        spend_to: msg.spend_to,
        collateral_partners: msg.collateral_partners.clone(),
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
    if msg.partner_id != our_node_id {
        return Ok(HandlerResult::Rejected(format!(
            "We ({}) are not the target partner ({})",
            our_node_id, msg.partner_id
        )));
    }

    // Get the ledger - sender (operator) and us (partner)
    let ledger_arc = ctx.get_ledger(&sender, &msg.partner_id)
        .ok_or(HandlerError::LedgerNotFound {
            operator: sender,
            partner: msg.partner_id,
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
                partner: msg.partner_id,
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
        partner: msg.partner_id,
        sequence,
        prev_hash,
        new_hash,
    }))
}

/// Handle a ReservesIncrease message.
///
/// Received by partners when an operator increases the reserves backing.
/// This moves funds from the channel balance to the reserves output.
/// The partner validates the message and signs the ledger update (porcupine dance).
///
/// # Arguments
/// * `ctx` - Handler context providing access to ledgers and messaging
/// * `msg` - The reserves increase message
/// * `sender` - Public key of the message sender (should be the operator)
///
/// # Returns
/// * `HandlerResult::Response(ReservesIncreaseValidated)` - Valid, partner should sign and ACK
/// * `HandlerResult::Rejected(reason)` - Invalid with explanation
/// * `HandlerError` - Internal error during processing
pub fn handle_reserves_increase<C: HandlerContext>(
    ctx: &C,
    msg: &ReservesIncreaseMsg,
    sender: PublicKey,
) -> Result<HandlerResult, HandlerError> {
    let our_node_id = ctx.our_node_id();

    // We must be the partner to process this message
    if msg.partner_id != our_node_id {
        return Ok(HandlerResult::Rejected(format!(
            "We ({}) are not the target partner ({})",
            our_node_id, msg.partner_id
        )));
    }

    // Get the ledger - sender (operator) and us (partner)
    let ledger_arc = ctx.get_ledger(&sender, &msg.partner_id)
        .ok_or(HandlerError::LedgerNotFound {
            operator: sender,
            partner: msg.partner_id,
        })?;

    // Validate and get current state
    let (sequence, prev_hash, new_hash) = {
        let ledger = ledger_arc.read().map_err(|_|
            HandlerError::Internal("Failed to acquire ledger read lock".to_string())
        )?;

        let current_reserves = ledger.reserves_amount();

        // Validate the reserves increase operation
        // Note: We don't have channel balance here - LDK layer will verify against actual channel
        validate_reserves_increase(current_reserves, msg.new_amount, None)
            .map_err(|e| HandlerError::ValidationFailed(e))?;

        // Return current state for response
        (ledger.sequence(), ledger.hash(), ledger.hash())
    };

    // Return validated data for LDK layer to record to ledger and sign
    Ok(HandlerResult::Response(ResponseData::ReservesIncreaseValidated {
        operator: sender,
        partner: msg.partner_id,
        new_amount: msg.new_amount,
        sequence,
        prev_hash,
        new_hash,
    }))
}

/// Handle a ReservesDecrease message.
///
/// Received by partners when an operator decreases the reserves backing.
/// This moves funds from the reserves output back to channel balance.
/// The partner validates the message and signs the ledger update (porcupine dance).
///
/// # Arguments
/// * `ctx` - Handler context providing access to ledgers and messaging
/// * `msg` - The reserves decrease message
/// * `sender` - Public key of the message sender (should be the operator)
///
/// # Returns
/// * `HandlerResult::Response(ReservesDecreaseValidated)` - Valid, partner should sign and ACK
/// * `HandlerResult::Rejected(reason)` - Invalid with explanation
/// * `HandlerError` - Internal error during processing
pub fn handle_reserves_decrease<C: HandlerContext>(
    ctx: &C,
    msg: &ReservesDecreaseMsg,
    sender: PublicKey,
) -> Result<HandlerResult, HandlerError> {
    let our_node_id = ctx.our_node_id();

    // We must be the partner to process this message
    if msg.partner_id != our_node_id {
        return Ok(HandlerResult::Rejected(format!(
            "We ({}) are not the target partner ({})",
            our_node_id, msg.partner_id
        )));
    }

    // Get the ledger - sender (operator) and us (partner)
    let ledger_arc = ctx.get_ledger(&sender, &msg.partner_id)
        .ok_or(HandlerError::LedgerNotFound {
            operator: sender,
            partner: msg.partner_id,
        })?;

    // Validate and get current state
    let (sequence, prev_hash, new_hash) = {
        let ledger = ledger_arc.read().map_err(|_|
            HandlerError::Internal("Failed to acquire ledger read lock".to_string())
        )?;

        // Validate the reserves decrease operation
        validate_reserves_decrease(&ledger, msg.new_amount)
            .map_err(|e| HandlerError::ValidationFailed(e))?;

        // Return current state for response
        (ledger.sequence(), ledger.hash(), ledger.hash())
    };

    // Return validated data for LDK layer to record to ledger and sign
    Ok(HandlerResult::Response(ResponseData::ReservesDecreaseValidated {
        operator: sender,
        partner: msg.partner_id,
        new_amount: msg.new_amount,
        sequence,
        prev_hash,
        new_hash,
    }))
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Create a ledger ID from operator and partner pubkeys
pub fn make_ledger_id(operator: PublicKey, partner: PublicKey) -> LedgerId {
    LedgerId::new(operator, partner)
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
        ledgers: HashMap<(PublicKey, PublicKey), Arc<RwLock<Ledger>>>,
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

        fn add_ledger(&mut self, operator: PublicKey, partner: PublicKey, ledger: Ledger) {
            self.ledgers.insert((operator, partner), Arc::new(RwLock::new(ledger)));
        }
    }

    impl crate::message_validation::ValidationContext for TestContext {
        fn get_ledger(&self, operator: &PublicKey, partner: &PublicKey) -> Option<Arc<RwLock<Ledger>>> {
            self.ledgers.get(&(*operator, *partner)).cloned()
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
            partner_id: partner,
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
            partner_id: partner,
            operator_signature: [0u8; 64],
        };

        // Correct sender but no channel - should respond with consent_granted=false
        let result = handle_collateral_consent_request(&ctx, &msg, operator);
        match result {
            Ok(HandlerResult::Response(ResponseData::CollateralConsent { consent_granted, .. })) => {
                assert!(!consent_granted, "Should not grant consent without channel");
            }
            other => panic!("Expected Response(CollateralConsent), got {:?}", other),
        }
    }

    #[test]
    fn test_handle_collateral_consent_request_with_channel() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let partner = create_test_pubkey(3);

        let mut ctx = TestContext::new(our_node_id);

        // Create a ledger where operator is the operator and we are the partner
        let ledger = Ledger::new(operator, our_node_id, LedgerRole::Partner, vec![], "tb1qtest".to_string());
        ctx.add_ledger(operator, our_node_id, ledger);

        let msg = CollateralConsentRequestMsg {
            operator_id: operator,
            partner_id: partner,
            operator_signature: [0u8; 64],
        };

        // Correct sender and we have a channel - should respond with consent_granted=true
        let result = handle_collateral_consent_request(&ctx, &msg, operator);
        match result {
            Ok(HandlerResult::Response(ResponseData::CollateralConsent { consent_granted, .. })) => {
                assert!(consent_granted, "Should grant consent when we have channel with operator");
            }
            other => panic!("Expected Response(CollateralConsent), got {:?}", other),
        }
    }

    // ========================================================================
    // Collateral Add/Remove Partner Tests
    // ========================================================================

    #[test]
    fn test_handle_collateral_add_partner_wrong_partner() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let other_partner = create_test_pubkey(3);
        let collateral_partner = create_test_pubkey(4);

        let ctx = TestContext::new(our_node_id);

        let msg = CollateralAddPartnerMsg {
            operator_id: operator,
            partner_id: other_partner, // Not us
            collateral_partner,
            collateral_partner_signature: [0u8; 64],
        };

        // We're not the target partner - should be rejected
        let result = handle_collateral_add_partner(&ctx, &msg, operator);
        assert!(matches!(result, Ok(HandlerResult::Rejected(_))));
    }

    #[test]
    fn test_handle_collateral_add_partner_no_ledger() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let collateral_partner = create_test_pubkey(3);

        let ctx = TestContext::new(our_node_id);

        let msg = CollateralAddPartnerMsg {
            operator_id: operator,
            partner_id: our_node_id,
            collateral_partner,
            collateral_partner_signature: [0u8; 64],
        };

        // No ledger exists - should error
        let result = handle_collateral_add_partner(&ctx, &msg, operator);
        assert!(matches!(result, Err(HandlerError::LedgerNotFound { .. })));
    }

    #[test]
    fn test_handle_collateral_add_partner_valid() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let collateral_partner = create_test_pubkey(3);

        let mut ctx = TestContext::new(our_node_id);

        // Create a ledger where operator is the operator and we are the partner
        let ledger = Ledger::new(operator, our_node_id, LedgerRole::Partner, vec![], "tb1qtest".to_string());
        ctx.add_ledger(operator, our_node_id, ledger);

        let msg = CollateralAddPartnerMsg {
            operator_id: operator,
            partner_id: our_node_id,
            collateral_partner,
            collateral_partner_signature: [0u8; 64],
        };

        // Valid request - should return Ok (actual mutation happens in LDK layer)
        let result = handle_collateral_add_partner(&ctx, &msg, operator);
        assert!(matches!(result, Ok(HandlerResult::Ok)));
    }

    #[test]
    fn test_handle_collateral_add_partner_idempotent() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let collateral_partner = create_test_pubkey(3);

        let mut ctx = TestContext::new(our_node_id);

        // Create a ledger with the collateral partner already added
        let mut ledger = Ledger::new(operator, our_node_id, LedgerRole::Partner, vec![], "tb1qtest".to_string());
        ledger.state.collateral_partners.push(collateral_partner);
        ctx.add_ledger(operator, our_node_id, ledger);

        let msg = CollateralAddPartnerMsg {
            operator_id: operator,
            partner_id: our_node_id,
            collateral_partner,
            collateral_partner_signature: [0u8; 64],
        };

        // Already exists - should return success (idempotent)
        let result = handle_collateral_add_partner(&ctx, &msg, operator);
        match result {
            Ok(HandlerResult::Response(ResponseData::CollateralPartnerAdded { .. })) => {}
            other => panic!("Expected Response(CollateralPartnerAdded), got {:?}", other),
        }
    }

    #[test]
    fn test_handle_collateral_remove_partner_wrong_partner() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let other_partner = create_test_pubkey(3);
        let collateral_partner = create_test_pubkey(4);

        let ctx = TestContext::new(our_node_id);

        let msg = CollateralRemovePartnerMsg {
            partner_id: other_partner, // Not us
            collateral_partner,
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
        let collateral_partner = create_test_pubkey(3);

        let mut ctx = TestContext::new(our_node_id);

        // Create a ledger without the collateral partner
        let ledger = Ledger::new(operator, our_node_id, LedgerRole::Partner, vec![], "tb1qtest".to_string());
        ctx.add_ledger(operator, our_node_id, ledger);

        let msg = CollateralRemovePartnerMsg {
            partner_id: our_node_id,
            collateral_partner,
            operator_signature: [0u8; 64],
        };

        // Collateral partner doesn't exist - should be rejected
        let result = handle_collateral_remove_partner(&ctx, &msg, operator);
        assert!(matches!(result, Ok(HandlerResult::Rejected(_))));
    }

    #[test]
    fn test_handle_collateral_remove_partner_valid() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let collateral_partner = create_test_pubkey(3);

        let mut ctx = TestContext::new(our_node_id);

        // Create a ledger with the collateral partner
        let mut ledger = Ledger::new(operator, our_node_id, LedgerRole::Partner, vec![], "tb1qtest".to_string());
        ledger.state.collateral_partners.push(collateral_partner);
        ctx.add_ledger(operator, our_node_id, ledger);

        let msg = CollateralRemovePartnerMsg {
            partner_id: our_node_id,
            collateral_partner,
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
        let collateral_partner = create_test_pubkey(2);
        let wrong_sender = create_test_pubkey(3);

        let ctx = TestContext::new(our_node_id);

        let msg = CollateralAttestationMsg {
            operator: our_node_id,
            collateral_partner,
            amount: 100_000,
            block_height: 100,
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
        let collateral_partner = create_test_pubkey(3);

        let ctx = TestContext::new(our_node_id);

        let msg = CollateralAttestationMsg {
            operator: other_operator, // Not us
            collateral_partner,
            amount: 100_000,
            block_height: 100,
            signature: [0u8; 64],
            ledger_hash: [0u8; 32],
        };

        // We're not the operator - should be rejected
        let result = handle_collateral_attestation(&ctx, &msg, collateral_partner);
        assert!(matches!(result, Ok(HandlerResult::Rejected(_))));
    }

    #[test]
    fn test_handle_collateral_attestation_zero_amount() {
        let our_node_id = create_test_pubkey(1);
        let collateral_partner = create_test_pubkey(2);

        let ctx = TestContext::new(our_node_id);

        let msg = CollateralAttestationMsg {
            operator: our_node_id,
            collateral_partner,
            amount: 0, // Zero
            block_height: 100,
            signature: [0u8; 64],
            ledger_hash: [0u8; 32],
        };

        // Zero amount - should be rejected
        let result = handle_collateral_attestation(&ctx, &msg, collateral_partner);
        assert!(matches!(result, Ok(HandlerResult::Rejected(_))));
    }

    #[test]
    fn test_handle_collateral_attestation_valid() {
        let our_node_id = create_test_pubkey(1);
        let collateral_partner = create_test_pubkey(2);

        let ctx = TestContext::new(our_node_id);

        let msg = CollateralAttestationMsg {
            operator: our_node_id,
            collateral_partner,
            amount: 100_000,
            block_height: 100,
            signature: [0u8; 64],
            ledger_hash: [0u8; 32],
        };

        // Valid attestation
        let result = handle_collateral_attestation(&ctx, &msg, collateral_partner);
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
        match result {
            Ok(HandlerResult::Response(ResponseData::UncreditedPaymentAccusation { amount_msat, .. })) => {
                assert_eq!(amount_msat, 1_000_000);
            }
            other => panic!("Expected Response(UncreditedPaymentAccusation), got {:?}", other),
        }

        // Check that event was emitted
        let events = ctx.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        match &events[0] {
            ProtocolEvent::UncreditedPaymentReceived { operator: op, partner: p, amount_msat: amt, .. } => {
                assert_eq!(*op, operator);
                assert_eq!(*p, partner);
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
            partner_id: other_partner, // Not us
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
            partner_id: our_node_id,
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
        let mut ledger = Ledger::new(operator, our_node_id, LedgerRole::Partner, vec![], "tb1qtest".to_string());
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
            partner_id: our_node_id,
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
        let mut ledger = Ledger::new(operator, our_node_id, LedgerRole::Partner, vec![], "tb1qtest".to_string());
        ledger.state.reserves.amount = 100_000;
        ledger.state.received_collateral_amount = 100_000;
        let deposit = Deposit::new(deposit_pubkey, None);
        ledger.state.deposits.insert(deposit_pubkey, deposit);
        ctx.add_ledger(operator, our_node_id, ledger);

        // Create payment hash that's not all the same byte
        let mut payment_hash = [0u8; 32];
        for i in 0..32 { payment_hash[i] = i as u8; }

        let msg = ReceivingCreditPaymentMsg {
            payment_hash,
            deposit_pubkey,
            amount: 50_000,
            invoice_id: "test_invoice".to_string(),
            partner_id: our_node_id,
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
            ProtocolEvent::PaymentCredited { amount: amt, .. } => {
                assert_eq!(*amt, 50_000);
            }
            other => panic!("Expected PaymentCredited event, got {:?}", other),
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
        let mut ledger = Ledger::new(operator, our_node_id, LedgerRole::Partner, vec![], "tb1qtest".to_string());
        let deposit = Deposit::new(other_deposit, None);
        ledger.state.deposits.insert(other_deposit, deposit);
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
        let mut ledger = Ledger::new(operator, our_node_id, LedgerRole::Partner, vec![], "tb1qtest".to_string());
        let mut deposit = Deposit::new(deposit_pubkey, None);
        deposit.balance = 10_000; // Low balance
        ledger.state.deposits.insert(deposit_pubkey, deposit);
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
        let mut ledger = Ledger::new(operator, our_node_id, LedgerRole::Partner, vec![], "tb1qtest".to_string());
        let mut deposit = Deposit::new(deposit_pubkey, None);
        deposit.balance = 100_000;
        ledger.state.deposits.insert(deposit_pubkey, deposit);
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
        let mut ledger = Ledger::new(operator, our_node_id, LedgerRole::Partner, vec![], "tb1qtest".to_string());
        let deposit = Deposit::new(deposit_pubkey, None);
        ledger.state.deposits.insert(deposit_pubkey, deposit);
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
        let mut ledger = Ledger::new(operator, our_node_id, LedgerRole::Partner, vec![], "tb1qtest".to_string());
        let mut deposit = Deposit::new(deposit_pubkey, None);
        deposit.balance = 100_000;
        ledger.state.deposits.insert(deposit_pubkey, deposit);
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
            ProtocolEvent::PaymentSent { amount: amt, .. } => {
                assert_eq!(*amt, 50_000);
            }
            other => panic!("Expected PaymentSent event, got {:?}", other),
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
        let mut ledger = Ledger::new(operator, our_node_id, LedgerRole::Partner, vec![], "tb1qtest".to_string());
        let deposit = Deposit::new(deposit_pubkey, None);
        ledger.state.deposits.insert(deposit_pubkey, deposit);
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
        let mut ledger = Ledger::new(operator, our_node_id, LedgerRole::Partner, vec![], "tb1qtest".to_string());
        let deposit = Deposit::new(other_deposit, None);
        ledger.state.deposits.insert(other_deposit, deposit);
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
        let mut ledger = Ledger::new(operator, our_node_id, LedgerRole::Partner, vec![], "tb1qtest".to_string());
        let deposit = Deposit::new(deposit_pubkey, None);
        ledger.state.deposits.insert(deposit_pubkey, deposit);
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
            partner_id: other_partner, // Not us
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
            partner_id: our_node_id,
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
        let ledger = Ledger::new(operator, our_node_id, LedgerRole::Partner, vec![], "tb1qtest".to_string());
        ctx.add_ledger(operator, our_node_id, ledger);

        let msg = DepositOpenMsg {
            partner_id: our_node_id,
            pubkey: deposit_pubkey,
            fees: None,
            payment_hash: None,
            invoice: None,
            cosigner_guarantee_signature: None,
        };

        // Valid deposit open - should return DepositOpenValidated
        let result = handle_deposit_open(&ctx, &msg, operator);
        match result {
            Ok(HandlerResult::Response(ResponseData::DepositOpenValidated { deposit_pubkey: pk, .. })) => {
                assert_eq!(pk, deposit_pubkey);
            }
            other => panic!("Expected Response(DepositOpenValidated), got {:?}", other),
        }
    }

    #[test]
    fn test_handle_deposit_open_idempotent() {
        use crate::types::Deposit;

        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let deposit_pubkey = create_test_pubkey(3);

        let mut ctx = TestContext::new(our_node_id);

        // Create a ledger with the deposit already added
        let mut ledger = Ledger::new(operator, our_node_id, LedgerRole::Partner, vec![], "tb1qtest".to_string());
        let deposit = Deposit::new(deposit_pubkey, None);
        ledger.state.deposits.insert(deposit_pubkey, deposit);
        ctx.add_ledger(operator, our_node_id, ledger);

        let msg = DepositOpenMsg {
            partner_id: our_node_id,
            pubkey: deposit_pubkey,
            fees: None,
            payment_hash: None,
            invoice: None,
            cosigner_guarantee_signature: None,
        };

        // Already exists - should return success (idempotent)
        let result = handle_deposit_open(&ctx, &msg, operator);
        match result {
            Ok(HandlerResult::Response(ResponseData::DepositOpenValidated { .. })) => {}
            other => panic!("Expected Response(DepositOpenValidated), got {:?}", other),
        }
    }

    #[test]
    fn test_handle_deposit_open_with_fees() {
        use crate::types::FeeStructure;

        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let deposit_pubkey = create_test_pubkey(3);

        let mut ctx = TestContext::new(our_node_id);

        // Create a ledger
        let ledger = Ledger::new(operator, our_node_id, LedgerRole::Partner, vec![], "tb1qtest".to_string());
        ctx.add_ledger(operator, our_node_id, ledger);

        let fees = FeeStructure {
            annualized_fixed: 1000,
            annualized_bps: 50,
            frequency_blocks: 144,
        };

        let msg = DepositOpenMsg {
            partner_id: our_node_id,
            pubkey: deposit_pubkey,
            fees: Some(fees),
            payment_hash: None,
            invoice: None,
            cosigner_guarantee_signature: None,
        };

        // Valid deposit open with fees - should succeed
        let result = handle_deposit_open(&ctx, &msg, operator);
        assert!(matches!(result, Ok(HandlerResult::Response(ResponseData::DepositOpenValidated { .. }))));
    }

    #[test]
    fn test_handle_deposit_open_invalid_fees() {
        use crate::types::FeeStructure;

        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let deposit_pubkey = create_test_pubkey(3);

        let mut ctx = TestContext::new(our_node_id);

        // Create a ledger
        let ledger = Ledger::new(operator, our_node_id, LedgerRole::Partner, vec![], "tb1qtest".to_string());
        ctx.add_ledger(operator, our_node_id, ledger);

        // Invalid fee structure with zero frequency
        let invalid_fees = FeeStructure {
            annualized_fixed: 1000,
            annualized_bps: 50,
            frequency_blocks: 0, // Invalid
        };

        let msg = DepositOpenMsg {
            partner_id: our_node_id,
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
            partner_id: other_partner, // Not us
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
            partner_id: our_node_id,
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
        let mut ledger = Ledger::new(operator, our_node_id, LedgerRole::Partner, vec![], "tb1qtest".to_string());
        let deposit = Deposit::new(deposit_pubkey, None); // balance=0 by default
        ledger.state.deposits.insert(deposit_pubkey, deposit);
        ctx.add_ledger(operator, our_node_id, ledger);

        let msg = DepositCloseMsg {
            partner_id: our_node_id,
            pubkey: deposit_pubkey,
        };

        // Valid deposit close - should return DepositCloseValidated
        let result = handle_deposit_close(&ctx, &msg, operator);
        match result {
            Ok(HandlerResult::Response(ResponseData::DepositCloseValidated { deposit_pubkey: pk, .. })) => {
                assert_eq!(pk, deposit_pubkey);
            }
            other => panic!("Expected Response(DepositCloseValidated), got {:?}", other),
        }
    }

    #[test]
    fn test_handle_deposit_close_non_zero_balance() {
        use crate::types::Deposit;

        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let deposit_pubkey = create_test_pubkey(3);

        let mut ctx = TestContext::new(our_node_id);

        // Create a ledger with a deposit that has non-zero balance
        let mut ledger = Ledger::new(operator, our_node_id, LedgerRole::Partner, vec![], "tb1qtest".to_string());
        let mut deposit = Deposit::new(deposit_pubkey, None);
        deposit.balance = 50_000; // Non-zero balance
        ledger.state.deposits.insert(deposit_pubkey, deposit);
        ctx.add_ledger(operator, our_node_id, ledger);

        let msg = DepositCloseMsg {
            partner_id: our_node_id,
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
        let mut ledger = Ledger::new(operator, our_node_id, LedgerRole::Partner, vec![], "tb1qtest".to_string());
        let mut deposit = Deposit::new(deposit_pubkey, None);
        deposit.locked_balance = 10_000; // Has locked funds
        ledger.state.deposits.insert(deposit_pubkey, deposit);
        ctx.add_ledger(operator, our_node_id, ledger);

        let msg = DepositCloseMsg {
            partner_id: our_node_id,
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
        let ledger = Ledger::new(operator, our_node_id, LedgerRole::Partner, vec![], "tb1qtest".to_string());
        ctx.add_ledger(operator, our_node_id, ledger);

        let msg = DepositCloseMsg {
            partner_id: our_node_id,
            pubkey: deposit_pubkey,
        };

        // Deposit doesn't exist - should return success (idempotent)
        let result = handle_deposit_close(&ctx, &msg, operator);
        match result {
            Ok(HandlerResult::Response(ResponseData::DepositCloseValidated { .. })) => {}
            other => panic!("Expected Response(DepositCloseValidated), got {:?}", other),
        }
    }

    // ========================================================================
    // Deposit Update Tests
    // ========================================================================

    #[test]
    fn test_handle_deposit_update_wrong_partner() {
        use crate::types::FeeStructure;

        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let other_partner = create_test_pubkey(3);
        let deposit_pubkey = create_test_pubkey(4);

        let ctx = TestContext::new(our_node_id);

        let msg = DepositUpdateMsg {
            partner_id: other_partner, // Not us
            pubkey: deposit_pubkey,
            new_fees: FeeStructure::default(),
        };

        // We're not the target partner - should be rejected
        let result = handle_deposit_update(&ctx, &msg, operator);
        assert!(matches!(result, Ok(HandlerResult::Rejected(_))));
    }

    #[test]
    fn test_handle_deposit_update_no_ledger() {
        use crate::types::FeeStructure;

        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let deposit_pubkey = create_test_pubkey(3);

        let ctx = TestContext::new(our_node_id);

        let msg = DepositUpdateMsg {
            partner_id: our_node_id,
            pubkey: deposit_pubkey,
            new_fees: FeeStructure::default(),
        };

        // No ledger exists - should error
        let result = handle_deposit_update(&ctx, &msg, operator);
        assert!(matches!(result, Err(HandlerError::LedgerNotFound { .. })));
    }

    #[test]
    fn test_handle_deposit_update_deposit_not_found() {
        use crate::types::FeeStructure;

        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let deposit_pubkey = create_test_pubkey(3);

        let mut ctx = TestContext::new(our_node_id);

        // Create a ledger without the deposit
        let ledger = Ledger::new(operator, our_node_id, LedgerRole::Partner, vec![], "tb1qtest".to_string());
        ctx.add_ledger(operator, our_node_id, ledger);

        let msg = DepositUpdateMsg {
            partner_id: our_node_id,
            pubkey: deposit_pubkey,
            new_fees: FeeStructure::default(),
        };

        // Deposit not found - should fail validation
        let result = handle_deposit_update(&ctx, &msg, operator);
        assert!(matches!(result, Err(HandlerError::ValidationFailed(_))));
    }

    #[test]
    fn test_handle_deposit_update_valid() {
        use crate::types::{Deposit, FeeStructure};

        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let deposit_pubkey = create_test_pubkey(3);

        let mut ctx = TestContext::new(our_node_id);

        // Create a ledger with the deposit
        let mut ledger = Ledger::new(operator, our_node_id, LedgerRole::Partner, vec![], "tb1qtest".to_string());
        let deposit = Deposit::new(deposit_pubkey, None);
        ledger.state.deposits.insert(deposit_pubkey, deposit);
        ctx.add_ledger(operator, our_node_id, ledger);

        let new_fees = FeeStructure {
            annualized_fixed: 2000,
            annualized_bps: 100,
            frequency_blocks: 288,
        };

        let msg = DepositUpdateMsg {
            partner_id: our_node_id,
            pubkey: deposit_pubkey,
            new_fees,
        };

        // Valid deposit update - should return DepositUpdateValidated
        let result = handle_deposit_update(&ctx, &msg, operator);
        match result {
            Ok(HandlerResult::Response(ResponseData::DepositUpdateValidated { deposit_pubkey: pk, .. })) => {
                assert_eq!(pk, deposit_pubkey);
            }
            other => panic!("Expected Response(DepositUpdateValidated), got {:?}", other),
        }
    }

    #[test]
    fn test_handle_deposit_update_invalid_fees() {
        use crate::types::{Deposit, FeeStructure};

        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let deposit_pubkey = create_test_pubkey(3);

        let mut ctx = TestContext::new(our_node_id);

        // Create a ledger with the deposit
        let mut ledger = Ledger::new(operator, our_node_id, LedgerRole::Partner, vec![], "tb1qtest".to_string());
        let deposit = Deposit::new(deposit_pubkey, None);
        ledger.state.deposits.insert(deposit_pubkey, deposit);
        ctx.add_ledger(operator, our_node_id, ledger);

        // Invalid fee structure with zero frequency
        let invalid_fees = FeeStructure {
            annualized_fixed: 2000,
            annualized_bps: 100,
            frequency_blocks: 0, // Invalid
        };

        let msg = DepositUpdateMsg {
            partner_id: our_node_id,
            pubkey: deposit_pubkey,
            new_fees: invalid_fees,
        };

        // Invalid fees - should fail validation
        let result = handle_deposit_update(&ctx, &msg, operator);
        assert!(matches!(result, Err(HandlerError::ValidationFailed(_))));
    }

    #[test]
    fn test_handle_deposit_update_fee_rate_too_high() {
        use crate::types::{Deposit, FeeStructure};

        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let deposit_pubkey = create_test_pubkey(3);

        let mut ctx = TestContext::new(our_node_id);

        // Create a ledger with the deposit
        let mut ledger = Ledger::new(operator, our_node_id, LedgerRole::Partner, vec![], "tb1qtest".to_string());
        let deposit = Deposit::new(deposit_pubkey, None);
        ledger.state.deposits.insert(deposit_pubkey, deposit);
        ctx.add_ledger(operator, our_node_id, ledger);

        // Fee rate too high (over 100%)
        let invalid_fees = FeeStructure {
            annualized_fixed: 0,
            annualized_bps: 15000, // 150% - too high
            frequency_blocks: 144,
        };

        let msg = DepositUpdateMsg {
            partner_id: our_node_id,
            pubkey: deposit_pubkey,
            new_fees: invalid_fees,
        };

        // Fee rate too high - should fail validation
        let result = handle_deposit_update(&ctx, &msg, operator);
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
            partner_id: other_partner, // Not us
            collateral_partners: vec![],
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
            partner_id: our_node_id,
            collateral_partners: vec![],
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
        let ledger = Ledger::new(operator, our_node_id, LedgerRole::Partner, vec![], "tb1qtest".to_string());
        ctx.add_ledger(operator, our_node_id, ledger);

        let msg = ReservesAddOutputMsg {
            initial_amount: 100_000,
            spend_to,
            partner_id: our_node_id,
            collateral_partners: vec![],
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
        let ledger = Ledger::new(operator, our_node_id, LedgerRole::Partner, vec![], "tb1qtest".to_string());
        ctx.add_ledger(operator, our_node_id, ledger);

        let msg = ReservesAddOutputMsg {
            initial_amount: 100, // Too small
            spend_to,
            partner_id: our_node_id,
            collateral_partners: vec![],
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
        let mut ledger = Ledger::new(operator, our_node_id, LedgerRole::Partner, vec![], "tb1qtest".to_string());
        ledger.state.reserves.amount = 100_000;
        ledger.state.reserves.spend_to = spend_to;
        ctx.add_ledger(operator, our_node_id, ledger);

        let msg = ReservesAddOutputMsg {
            initial_amount: 100_000,
            spend_to,
            partner_id: our_node_id,
            collateral_partners: vec![],
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
            partner_id: other_partner, // Not us
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
            partner_id: our_node_id,
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
        let mut ledger = Ledger::new(operator, our_node_id, LedgerRole::Partner, vec![], "tb1qtest".to_string());
        ledger.state.reserves.amount = 100_000;
        ledger.state.reserves.spend_to = spend_to;
        ctx.add_ledger(operator, our_node_id, ledger);

        let msg = ReservesRemoveOutputMsg {
            partner_id: our_node_id,
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
        let mut ledger = Ledger::new(operator, our_node_id, LedgerRole::Partner, vec![], "tb1qtest".to_string());
        ledger.state.reserves.amount = 100_000;
        ledger.state.reserves.spend_to = spend_to;
        let mut deposit = Deposit::new(deposit_pubkey, None);
        deposit.balance = 50_000;
        ledger.state.deposits.insert(deposit_pubkey, deposit);
        ctx.add_ledger(operator, our_node_id, ledger);

        let msg = ReservesRemoveOutputMsg {
            partner_id: our_node_id,
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
        let ledger = Ledger::new(operator, our_node_id, LedgerRole::Partner, vec![], "tb1qtest".to_string());
        ctx.add_ledger(operator, our_node_id, ledger);

        let msg = ReservesRemoveOutputMsg {
            partner_id: our_node_id,
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
    // Reserves Increase Tests
    // ========================================================================

    #[test]
    fn test_handle_reserves_increase_wrong_partner() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let other_partner = create_test_pubkey(3);

        let ctx = TestContext::new(our_node_id);

        let msg = ReservesIncreaseMsg {
            partner_id: other_partner, // Not us
            new_amount: 200_000,
        };

        // We're not the target partner - should be rejected
        let result = handle_reserves_increase(&ctx, &msg, operator);
        assert!(matches!(result, Ok(HandlerResult::Rejected(_))));
    }

    #[test]
    fn test_handle_reserves_increase_no_ledger() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);

        let ctx = TestContext::new(our_node_id);

        let msg = ReservesIncreaseMsg {
            partner_id: our_node_id,
            new_amount: 200_000,
        };

        // No ledger - should error
        let result = handle_reserves_increase(&ctx, &msg, operator);
        assert!(matches!(result, Err(HandlerError::LedgerNotFound { .. })));
    }

    #[test]
    fn test_handle_reserves_increase_valid() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let spend_to = create_test_pubkey(3);

        let mut ctx = TestContext::new(our_node_id);

        // Create a ledger with existing reserves
        let mut ledger = Ledger::new(operator, our_node_id, LedgerRole::Partner, vec![], "tb1qtest".to_string());
        ledger.state.reserves.amount = 100_000;
        ledger.state.reserves.spend_to = spend_to;
        ctx.add_ledger(operator, our_node_id, ledger);

        let msg = ReservesIncreaseMsg {
            partner_id: our_node_id,
            new_amount: 200_000,
        };

        // Valid request - should return response
        let result = handle_reserves_increase(&ctx, &msg, operator);
        match result {
            Ok(HandlerResult::Response(ResponseData::ReservesIncreaseValidated { new_amount, .. })) => {
                assert_eq!(new_amount, 200_000);
            }
            other => panic!("Expected Response(ReservesIncreaseValidated), got {:?}", other),
        }
    }

    #[test]
    fn test_handle_reserves_increase_not_actually_increasing() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let spend_to = create_test_pubkey(3);

        let mut ctx = TestContext::new(our_node_id);

        // Create a ledger with existing reserves
        let mut ledger = Ledger::new(operator, our_node_id, LedgerRole::Partner, vec![], "tb1qtest".to_string());
        ledger.state.reserves.amount = 200_000;
        ledger.state.reserves.spend_to = spend_to;
        ctx.add_ledger(operator, our_node_id, ledger);

        let msg = ReservesIncreaseMsg {
            partner_id: our_node_id,
            new_amount: 150_000, // Less than current
        };

        // Not actually increasing - should fail validation
        let result = handle_reserves_increase(&ctx, &msg, operator);
        assert!(matches!(result, Err(HandlerError::ValidationFailed(_))));
    }

    // ========================================================================
    // Reserves Decrease Tests
    // ========================================================================

    #[test]
    fn test_handle_reserves_decrease_wrong_partner() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let other_partner = create_test_pubkey(3);

        let ctx = TestContext::new(our_node_id);

        let msg = ReservesDecreaseMsg {
            partner_id: other_partner, // Not us
            new_amount: 50_000,
        };

        // We're not the target partner - should be rejected
        let result = handle_reserves_decrease(&ctx, &msg, operator);
        assert!(matches!(result, Ok(HandlerResult::Rejected(_))));
    }

    #[test]
    fn test_handle_reserves_decrease_no_ledger() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);

        let ctx = TestContext::new(our_node_id);

        let msg = ReservesDecreaseMsg {
            partner_id: our_node_id,
            new_amount: 50_000,
        };

        // No ledger - should error
        let result = handle_reserves_decrease(&ctx, &msg, operator);
        assert!(matches!(result, Err(HandlerError::LedgerNotFound { .. })));
    }

    #[test]
    fn test_handle_reserves_decrease_valid() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let spend_to = create_test_pubkey(3);

        let mut ctx = TestContext::new(our_node_id);

        // Create a ledger with reserves and no deposits
        let mut ledger = Ledger::new(operator, our_node_id, LedgerRole::Partner, vec![], "tb1qtest".to_string());
        ledger.state.reserves.amount = 200_000;
        ledger.state.reserves.spend_to = spend_to;
        ctx.add_ledger(operator, our_node_id, ledger);

        let msg = ReservesDecreaseMsg {
            partner_id: our_node_id,
            new_amount: 100_000,
        };

        // Valid request - should return response
        let result = handle_reserves_decrease(&ctx, &msg, operator);
        match result {
            Ok(HandlerResult::Response(ResponseData::ReservesDecreaseValidated { new_amount, .. })) => {
                assert_eq!(new_amount, 100_000);
            }
            other => panic!("Expected Response(ReservesDecreaseValidated), got {:?}", other),
        }
    }

    #[test]
    fn test_handle_reserves_decrease_not_actually_decreasing() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let spend_to = create_test_pubkey(3);

        let mut ctx = TestContext::new(our_node_id);

        // Create a ledger with reserves
        let mut ledger = Ledger::new(operator, our_node_id, LedgerRole::Partner, vec![], "tb1qtest".to_string());
        ledger.state.reserves.amount = 100_000;
        ledger.state.reserves.spend_to = spend_to;
        ctx.add_ledger(operator, our_node_id, ledger);

        let msg = ReservesDecreaseMsg {
            partner_id: our_node_id,
            new_amount: 150_000, // More than current
        };

        // Not actually decreasing - should fail validation
        let result = handle_reserves_decrease(&ctx, &msg, operator);
        assert!(matches!(result, Err(HandlerError::ValidationFailed(_))));
    }

    #[test]
    fn test_handle_reserves_decrease_below_required() {
        use crate::types::Deposit;

        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let spend_to = create_test_pubkey(3);
        let deposit_pubkey = create_test_pubkey(4);

        let mut ctx = TestContext::new(our_node_id);

        // Create a ledger with reserves and deposits
        let mut ledger = Ledger::new(operator, our_node_id, LedgerRole::Partner, vec![], "tb1qtest".to_string());
        ledger.state.reserves.amount = 200_000;
        ledger.state.reserves.spend_to = spend_to;
        let mut deposit = Deposit::new(deposit_pubkey, None);
        deposit.balance = 100_000;
        ledger.state.deposits.insert(deposit_pubkey, deposit);
        ctx.add_ledger(operator, our_node_id, ledger);

        let msg = ReservesDecreaseMsg {
            partner_id: our_node_id,
            new_amount: 50_000, // Below deposit balance
        };

        // Would drop below required reserves - should fail validation
        let result = handle_reserves_decrease(&ctx, &msg, operator);
        assert!(matches!(result, Err(HandlerError::ValidationFailed(_))));
    }
}
