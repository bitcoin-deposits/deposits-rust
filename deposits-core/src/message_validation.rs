// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Message-level validation for Bitcoin Deposits Protocol
//!
//! This module provides the `ValidationContext` trait and message validation functions
//! that can be used by any Lightning implementation (LDK, CLN, etc.).
//!
//! ## Design
//!
//! The validation is split into two layers:
//!
//! 1. **Operation validation** (`operation_validation.rs`): Pure functions that validate
//!    individual operations given ledger state. No context needed.
//!
//! 2. **Message validation** (this module): Functions that validate incoming messages,
//!    requiring a `ValidationContext` to look up ledgers by operator/partner keys.
//!
//! The `ValidationContext` trait provides the necessary abstractions for ledger lookup
//! and channel state queries, allowing the validation logic to be reused across
//! different Lightning implementations.
//!
//! ## Usage
//!
//! ```ignore
//! // Implement ValidationContext for your handler
//! impl ValidationContext for MyHandler {
//!     fn get_ledger(&self, operator: &PublicKey, partner: &PublicKey) -> Option<Arc<RwLock<Ledger>>> {
//!         // Look up ledger from your storage
//!     }
//!
//!     fn our_node_id(&self) -> PublicKey {
//!         self.node_id
//!     }
//!
//!     fn get_commitment_tx_reserves_amount(&self, operator: PublicKey) -> Option<u64> {
//!         // Query channel state for reserves
//!     }
//! }
//!
//! // Validate individual messages using the context
//! validate_add_deposit_msg(&context, &msg, sender)?;
//! validate_receiving_cosign_invoice_msg(&context, &msg, sender)?;
//! ```

use bitcoin::secp256k1::PublicKey;
use std::sync::{Arc, RwLock};

use crate::ledger::Ledger;
use crate::messages::LedgerOperation;
use crate::operation_validation::{
    validate_cosign_invoice,
    validate_credit_payment,
    validate_credit_payment_by_id,
    validate_deposit_add,
    // DepositId-based validation functions
    validate_deposit_add_by_id,
    validate_deposit_close,
    validate_deposit_close_by_id,
    validate_deposit_key_rotate,
    validate_fee_change,
    validate_fee_change_by_id,
    validate_fee_collect,
    validate_fee_collect_by_id,
    validate_ledger_close,
    validate_onchain_lock_by_id,
    validate_payment_fail,
    validate_payment_fulfill,
    validate_payment_fulfill_by_id,
    validate_payment_lock,
    validate_payment_lock_by_id,
    validate_reserves_add,
    validate_transfer_complete,
    // Transfer validation functions
    validate_transfer_lock,
    ValidationResult,
};
use crate::wire_messages::{
    DepositCloseMsg, DepositOpenMsg, FeeChangeMsg, FeeCollectMsg, LedgerCloseMsg,
    ReceivingCosignInvoiceMsg, ReceivingCreditPaymentMsg, ReservesAddOutputMsg,
    ReservesRemoveOutputMsg, SendingFailPaymentMsg, SendingFulfillPaymentMsg,
    SendingLockPaymentMsg,
};

/// Pending acknowledgment for a sent message.
#[derive(Clone, Debug)]
pub struct PendingAck {
    /// The message type that was sent
    pub message_type: u16,
    /// When the message was sent (Unix timestamp)
    pub sent_at: u64,
}

/// Protocol events emitted by handlers for monitoring and metrics.
#[derive(Clone, Debug)]
pub enum ProtocolEvent {
    LedgerSynced {
        operator: PublicKey,
        reserves_id: String,
        sequence: u64,
        hash: [u8; 32],
    },
    Error {
        operator: PublicKey,
        reserves_id: String,
        error: String,
    },
}

// ============================================================================
// Validation Context Trait
// ============================================================================

/// Context for validating protocol messages.
///
/// This trait provides the necessary context for message validation without
/// requiring any specific Lightning implementation dependencies.
///
/// Implementations should be provided by the Lightning adapter (e.g., deposits-ldk).
pub trait ValidationContext: Send + Sync {
    /// Get a ledger for the given operator/reserves_id pair.
    ///
    /// Returns None if no ledger exists for this pair.
    fn get_ledger(&self, operator: &PublicKey, reserves_id: &str) -> Option<Arc<RwLock<Ledger>>>;

    /// Get our node's public key.
    fn our_node_id(&self) -> PublicKey;

    /// Get the reserves amount from the commitment transaction (optional).
    ///
    /// This is used for LDK-specific validation where we need to check
    /// that reserves don't exceed channel balance. Returns None if
    /// not available or not applicable.
    fn get_commitment_tx_reserves_amount(&self, _operator: PublicKey) -> Option<u64> {
        None
    }
}

// ============================================================================
// Handler Context (extends ValidationContext for message handling)
// ============================================================================

use crate::error::HandlerError;
use crate::messages::DepositsMessage;
use bitcoin::secp256k1::SecretKey;

/// Context for handling protocol messages.
/// Extends ValidationContext with message sending, signing, and persistence.
pub trait HandlerContext: ValidationContext {
    /// Queue a message to be sent to a peer
    fn queue_message(&self, peer: PublicKey, msg: DepositsMessage) -> Result<(), HandlerError>;

    /// Emit a protocol event (deposit event, recovery event, etc.)
    fn emit_event(&self, event: ProtocolEvent);

    /// Get our secret key for signing (optional, for handlers that need it)
    fn our_secret_key(&self) -> Option<SecretKey> {
        None
    }

    /// Sign arbitrary message content with our node key (Schnorr/BIP-340).
    /// Returns 64-byte signature or None if signing unavailable.
    fn sign_message(&self, content: &[u8]) -> Option<[u8; 64]> {
        use bitcoin::hashes::{sha256, Hash};
        use bitcoin::secp256k1::{Keypair, Message, Secp256k1};

        let secret_key = self.our_secret_key()?;
        let hash = sha256::Hash::hash(content);
        let secp_msg = Message::from_digest(hash.to_byte_array());
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, &secret_key);

        let sig = secp.sign_schnorr_no_aux_rand(&secp_msg, &keypair);
        Some(sig.serialize())
    }

    /// Sign a sighash with Schnorr (BIP340) for recovery claims.
    /// Returns 64-byte Schnorr signature or None if signing unavailable.
    fn sign_schnorr(&self, sighash: &[u8; 32]) -> Option<[u8; 64]> {
        use bitcoin::secp256k1::{Keypair, Message, Secp256k1};

        let secret_key = self.our_secret_key()?;
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, &secret_key);
        let msg = Message::from_digest(*sighash);
        let signature = secp.sign_schnorr_no_aux_rand(&msg, &keypair);
        Some(signature.serialize())
    }

    /// Get the current block height
    fn current_block_height(&self) -> u32 {
        0
    }

    /// Sign a ledger update as partner (porcupine dance).
    /// Returns the 64-byte signature or None if signing is not available.
    fn sign_ledger_update(
        &self,
        message_bytes: &[u8],
        message_type: u16,
        sequence: u64,
        prev_hash: &[u8; 32],
        new_hash: &[u8; 32],
    ) -> Option<[u8; 64]> {
        let _ = (message_bytes, message_type, sequence, prev_hash, new_hash);
        None
    }

    /// Persist ledger state to storage.
    /// Returns Ok(()) on success or error message on failure.
    fn persist_ledger(&self, operator: &PublicKey, reserves_id: &str) -> Result<(), String> {
        let _ = (operator, reserves_id);
        Ok(()) // Default: no-op
    }

    /// Sync quorum membership after quorum member change.
    fn sync_quorum_member(
        &self,
        operator: PublicKey,
        reserves_id: &str,
        quorum_member: PublicKey,
        add: bool,
    ) {
        let _ = (operator, reserves_id, quorum_member, add);
        // Default: no-op
    }

    /// Send a ledger update ACK to a peer.
    /// This is called by core handlers after successfully processing a ledger update.
    /// The LDK implementation constructs and sends the appropriate ACK message.
    fn send_ledger_update_ack(
        &self,
        peer: PublicKey,
        message_hash: [u8; 32],
        message_type: u16,
        success: bool,
        error_message: Option<String>,
        sequence: u64,
        prev_hash: [u8; 32],
        new_hash: [u8; 32],
        cosign_signature: Option<[u8; 64]>,
    ) -> Result<(), HandlerError> {
        let _ = (
            peer,
            message_hash,
            message_type,
            success,
            error_message,
            sequence,
            prev_hash,
            new_hash,
            cosign_signature,
        );
        Ok(()) // Default: no-op
    }

    // ========================================================================
    // ACK Tracking Methods
    // ========================================================================

    /// Register a message as pending ACK.
    /// Called when an operator sends a message that requires acknowledgment.
    fn register_pending_ack(&self, hash: [u8; 32], msg_type: u16, peer: PublicKey) {
        let _ = (hash, msg_type, peer);
        // Default: no-op
    }

    /// Complete a pending ACK, returning the pending ack info if found.
    /// Called when an ACK is received for a previously sent message.
    fn complete_pending_ack(&self, hash: &[u8; 32]) -> Option<PendingAck> {
        let _ = hash;
        None // Default: not found
    }

    /// Check for timed-out ACKs.
    /// Returns list of (hash, pending_ack) pairs that have exceeded the threshold.
    fn get_timed_out_acks(&self, threshold_secs: u64) -> Vec<([u8; 32], PendingAck)> {
        let _ = threshold_secs;
        vec![] // Default: none
    }

    // ========================================================================
    // Signed Update Management Methods
    // ========================================================================

    /// Store a signed update for audit trail.
    /// Called after a ledger operation is committed to create the audit record.
    fn store_signed_update(
        &self,
        operator: &PublicKey,
        partner: &PublicKey,
        update: crate::SignedLedgerUpdate,
    ) -> Result<(), String> {
        let _ = (operator, partner, update);
        Ok(()) // Default: no-op
    }

    /// Get signed updates for a ledger (for audit sync).
    fn get_signed_updates(
        &self,
        operator: &PublicKey,
        partner: &PublicKey,
    ) -> Option<Vec<crate::SignedLedgerUpdate>> {
        let _ = (operator, partner);
        None // Default: not available
    }

    /// Verify and store a signed update received from a peer.
    /// Used by third-party auditors to validate and store audit records.
    fn verify_and_store_signed_update(
        &self,
        update: crate::SignedLedgerUpdate,
    ) -> Result<(), String> {
        let _ = update;
        Ok(()) // Default: no-op
    }

    // ========================================================================
    // Broadcast Tracking Methods
    // ========================================================================

    /// Track a message for broadcast after ACK is received.
    fn track_for_broadcast(
        &self,
        msg_hash: [u8; 32],
        operator: PublicKey,
        partner: PublicKey,
        msg: DepositsMessage,
        prev_hash: [u8; 32],
        new_hash: [u8; 32],
        seq: u64,
    ) {
        let _ = (msg_hash, operator, partner, msg, prev_hash, new_hash, seq);
        // Default: no-op
    }

    /// Complete broadcast after ACK received, returns the tracked info if found.
    fn complete_broadcast(
        &self,
        msg_hash: [u8; 32],
        partner_sig: Option<[u8; 64]>,
    ) -> Result<(), String> {
        let _ = (msg_hash, partner_sig);
        Ok(()) // Default: no-op
    }

    /// Get quorum members for broadcast (excluding the direct partner).
    fn get_broadcast_recipients(
        &self,
        operator: &PublicKey,
        partner: &PublicKey,
    ) -> Vec<PublicKey> {
        let _ = (operator, partner);
        vec![] // Default: none
    }

    // ========================================================================
    // Fraud Proof Methods
    // ========================================================================

    /// Handle followup actions after receiving a valid fraud proof (uncredited payment).
    /// - Force-close any channel with the accused operator
    /// - Rebroadcast the accusation to our quorum members
    fn handle_fraud_proof_followup(
        &self,
        accused_operator: PublicKey,
        accusation_msg: DepositsMessage,
    ) {
        let _ = (accused_operator, accusation_msg);
        // Default: no-op (LDK implementation handles channel closure and rebroadcast)
    }

    // ========================================================================
    // Quorum Sync Methods
    // ========================================================================

    /// Send quorum state sync to a new member.
    /// Called after accepting a quorum join request.
    fn send_quorum_state_sync(&self, member: PublicKey, operator: PublicKey, reserves_id: &str) {
        let _ = (member, operator, reserves_id);
        // Default: no-op
    }

    // ========================================================================
    // Vote Round Methods
    // ========================================================================

    /// Add a vote to a pending vote round.
    /// Returns Some(spend_ready_data) if threshold reached, None otherwise.
    /// The spend_ready_data contains: (operator, reserves_id, signed_tx_bytes, conforming_votes, threshold)
    fn add_quorum_vote(
        &self,
        vote_round_id: [u8; 32],
        voter: PublicKey,
        vote: bool,
        spend_signature: Option<[u8; 64]>,
    ) -> Option<(PublicKey, String, Vec<u8>, u32, u32)> {
        let _ = (vote_round_id, voter, vote, spend_signature);
        None // Default: not implemented
    }

    // ========================================================================
    // Collateral Consent Methods
    // ========================================================================

    /// Complete a pending collateral consent request.
    /// Returns true if a pending request was found and completed.
    fn complete_consent_request(
        &self,
        operator: PublicKey,
        reserves_id: &str,
        granted: bool,
        signature: [u8; 64],
    ) -> bool {
        let _ = (operator, reserves_id, granted, signature);
        false // Default: no pending request found
    }

    /// Send audit history to a new quorum member.
    fn send_audit_to_quorum_member(
        &self,
        operator: PublicKey,
        reserves_id: &str,
        new_quorum_member: PublicKey,
        signature: [u8; 64],
    ) {
        let _ = (operator, reserves_id, new_quorum_member, signature);
        // Default: no-op
    }

    /// Verify a collateral consent signature.
    /// Returns true if signature is valid.
    fn verify_consent_signature(
        &self,
        operator: PublicKey,
        reserves_id: &str,
        signature: [u8; 64],
        signer: PublicKey,
    ) -> bool {
        let _ = (operator, reserves_id, signature, signer);
        false // Default: not implemented
    }

    /// Append a QuorumJoin operation to our own operator ledger.
    /// This records that we have agreed to join another operator's quorum.
    /// Called when granting consent to be a quorum member.
    ///
    /// Returns Ok(()) on success, or error if ledger not found or append fails.
    fn append_quorum_join_to_own_ledger(
        &self,
        target_operator: PublicKey,
        target_reserves_id: &str,
        membership_expires: u32,
    ) -> Result<(), HandlerError> {
        let _ = (target_operator, target_reserves_id, membership_expires);
        Ok(()) // Default: no-op
    }

    // ========================================================================
    // Quorum State Sync Methods
    // ========================================================================

    /// Get the current state from the signed update log.
    /// Returns (sequence_number, state_hash) for the ledger.
    fn get_signed_update_log_state(
        &self,
        operator: &PublicKey,
        reserves_id: &str,
    ) -> Option<(u64, [u8; 32])> {
        let _ = (operator, reserves_id);
        None // Default: not available
    }

    /// Update our member state in the quorum after syncing.
    /// Called after receiving the final batch of a quorum state sync.
    fn update_quorum_member_state(
        &self,
        operator: PublicKey,
        reserves_id: &str,
        sequence: u64,
        state_hash: [u8; 32],
    ) -> Result<(), String> {
        let _ = (operator, reserves_id, sequence, state_hash);
        Ok(()) // Default: no-op
    }

    // ========================================================================
    // Vote Request Methods
    // ========================================================================

    /// Initialize a vote round when we receive a vote request.
    /// Returns true if the round was created (or already exists).
    fn init_vote_round(
        &self,
        vote_round_id: [u8; 32],
        operator: PublicKey,
        reserves_id: &str,
        sequence_number: u64,
        state_hash: [u8; 32],
        claimed_reserves: u64,
        reserves_outpoint: Vec<u8>,
        destination_script: Vec<u8>,
        fee_rate_sat_vbyte: u64,
        threshold: usize,
    ) -> bool {
        let _ = (
            vote_round_id,
            operator,
            reserves_id,
            sequence_number,
            state_hash,
            claimed_reserves,
            reserves_outpoint,
            destination_script,
            fee_rate_sat_vbyte,
            threshold,
        );
        false // Default: not implemented
    }

    /// Sign a quorum vote.
    /// Returns 64-byte signature or None if signing unavailable.
    fn sign_quorum_vote(
        &self,
        vote_round_id: &[u8; 32],
        vote: bool,
        sequence: u64,
        state_hash: &[u8; 32],
    ) -> Option<[u8; 64]> {
        let _ = (vote_round_id, vote, sequence, state_hash);
        None // Default: not implemented
    }
}

// ============================================================================
// LedgerOperation Validation (for V2 protocol)
// ============================================================================

/// Validate a LedgerOperation with context.
///
/// This function validates a V2 LedgerOperation by dispatching to the
/// appropriate individual validation function.
///
/// # Arguments
/// * `ctx` - Validation context providing ledger access
/// * `operation` - The operation to validate
/// * `partner_pubkey` - The partner's public key for this ledger
/// * `sender` - The public key of the peer who sent the message
pub fn validate_ledger_operation<C: ValidationContext>(
    ctx: &C,
    operation: &LedgerOperation,
    partner_pubkey: PublicKey,
    sender: PublicKey,
) -> ValidationResult {
    match operation {
        // LedgerOpen is the first operation - always valid
        LedgerOperation::LedgerOpen { .. } => Ok(()),
        LedgerOperation::DepositOpen {
            deposit_id, fees, ..
        } => {
            // Validate deposit doesn't exist and fees are valid
            if let Some(ledger_arc) = ctx.get_ledger(&sender, &ctx.our_node_id().to_string()) {
                let ledger = ledger_arc.read().unwrap();
                validate_deposit_add_by_id(&ledger, deposit_id, fees.as_ref())
            } else {
                Err(format!("No channel ledger found for sender {}", sender))
            }
        }
        LedgerOperation::DepositClose { deposit_id } => {
            // Validate deposit exists and can be closed
            if let Some(ledger_arc) = ctx.get_ledger(&sender, &ctx.our_node_id().to_string()) {
                let ledger = ledger_arc.read().unwrap();
                validate_deposit_close_by_id(&ledger, deposit_id)
            } else {
                Err(format!("No channel ledger found for sender {}", sender))
            }
        }
        LedgerOperation::FeeChange {
            deposit_id,
            new_fees,
            ..
        } => {
            // Validate deposit exists and new fees are valid
            if let Some(ledger_arc) = ctx.get_ledger(&sender, &ctx.our_node_id().to_string()) {
                let ledger = ledger_arc.read().unwrap();
                validate_fee_change_by_id(&ledger, deposit_id, new_fees)
            } else {
                Err(format!("No channel ledger found for sender {}", sender))
            }
        }
        LedgerOperation::DepositKeyRotate {
            deposit_id,
            new_descriptor,
            witness,
        } => {
            // Validate deposit exists and witness satisfies current descriptor
            if let Some(ledger_arc) = ctx.get_ledger(&sender, &ctx.our_node_id().to_string()) {
                let ledger = ledger_arc.read().unwrap();
                validate_deposit_key_rotate(&ledger, deposit_id, new_descriptor, witness)
            } else {
                Err(format!("No channel ledger found for sender {}", sender))
            }
        }
        LedgerOperation::InvoiceLock {
            deposit_id,
            amount,
            payment_id,
            witness,
            ..
        } => {
            // Validate payment lock with descriptor witness
            if let Some(ledger_arc) = ctx.get_ledger(&sender, &ctx.our_node_id().to_string()) {
                let ledger = ledger_arc.read().unwrap();
                validate_payment_lock_by_id(&ledger, deposit_id, *amount, payment_id, witness)
            } else {
                Err(format!("No channel ledger found for sender {}", sender))
            }
        }
        LedgerOperation::InvoiceFulfill {
            deposit_id,
            amount,
            payment_id,
            witness,
            preimage,
            ..
        } => {
            // Validate payment fulfill with descriptor witness
            validate_payment_fulfill_by_id(deposit_id, *amount, payment_id, witness, preimage)
        }
        LedgerOperation::InvoiceFail { amount, .. } => {
            // Basic validation for payment fail
            validate_payment_fail(*amount)
        }
        LedgerOperation::InvoiceCredit {
            payment_hash,
            deposit_id,
            amount,
            invoice_id,
            ..
        } => {
            // Validate credit payment
            if let Some(ledger_arc) = ctx.get_ledger(&sender, &ctx.our_node_id().to_string()) {
                let ledger = ledger_arc.read().unwrap();
                validate_credit_payment_by_id(
                    &ledger,
                    deposit_id,
                    *amount,
                    payment_hash,
                    invoice_id,
                )
            } else {
                Err(format!("No channel ledger found for sender {}", sender))
            }
        }
        // Onchain operations
        LedgerOperation::OnchainCredit { .. }
        | LedgerOperation::OnchainFail { .. }
        | LedgerOperation::OnchainFulfill { .. } => {
            // These onchain operations are validated in message_handlers
            Ok(())
        }
        LedgerOperation::OnchainLock {
            deposit_id,
            amount,
            fee_sats,
            destination_address,
            withdrawal_id,
            witness,
        } => {
            // Validate withdrawal lock with descriptor witness
            if let Some(ledger_arc) = ctx.get_ledger(&sender, &ctx.our_node_id().to_string()) {
                let ledger = ledger_arc.read().unwrap();
                validate_onchain_lock_by_id(
                    &ledger,
                    deposit_id,
                    *amount,
                    *fee_sats,
                    destination_address,
                    withdrawal_id,
                    witness,
                )
            } else {
                Err(format!("No channel ledger found for sender {}", sender))
            }
        }
        LedgerOperation::FeeCollect {
            deposit_id,
            amount,
            block_height,
        } => {
            // Validate fee collection
            if let Some(ledger_arc) = ctx.get_ledger(&sender, &ctx.our_node_id().to_string()) {
                let ledger = ledger_arc.read().unwrap();
                validate_fee_collect_by_id(&ledger, deposit_id, *amount, *block_height)
            } else {
                Err(format!("No channel ledger found for sender {}", sender))
            }
        }
        LedgerOperation::LedgerClose => {
            let msg = LedgerCloseMsg {
                reserves_id: partner_pubkey.to_string(),
            };
            validate_ledger_close_msg(ctx, &msg, sender)
        }
        LedgerOperation::TransferLock {
            nonce,
            source_deposit_id,
            destination_deposit_id,
            amount,
            fee,
            completion_script,
            timeout_height,
            transfer_id,
            witness,
        } => {
            if let Some(ledger_arc) = ctx.get_ledger(&sender, &ctx.our_node_id().to_string()) {
                let ledger = ledger_arc.read().unwrap();
                validate_transfer_lock(
                    &ledger,
                    source_deposit_id,
                    destination_deposit_id,
                    nonce,
                    *amount,
                    *fee,
                    completion_script,
                    *timeout_height,
                    transfer_id,
                    witness,
                )
            } else {
                Err(format!("No channel ledger found for sender {}", sender))
            }
        }
        LedgerOperation::TransferComplete {
            transfer_id,
            script_witness,
        } => {
            if let Some(ledger_arc) = ctx.get_ledger(&sender, &ctx.our_node_id().to_string()) {
                let ledger = ledger_arc.read().unwrap();
                validate_transfer_complete(&ledger, transfer_id, script_witness)
            } else {
                Err(format!("No channel ledger found for sender {}", sender))
            }
        }
        LedgerOperation::TransferFail {
            transfer_id,
            block_hash: _,
            ..
        } => {
            // For timeout, we need current block height - use 0 as placeholder
            // Real validation happens in the handler with actual block context
            if let Some(ledger_arc) = ctx.get_ledger(&sender, &ctx.our_node_id().to_string()) {
                let ledger = ledger_arc.read().unwrap();
                // Check pending transfer exists (block height check done elsewhere)
                if !ledger.state.pending_transfers.contains_key(transfer_id) {
                    return Err(format!(
                        "Pending transfer {} does not exist",
                        hex::encode(transfer_id)
                    ));
                }
                Ok(())
            } else {
                Err(format!("No channel ledger found for sender {}", sender))
            }
        }
        // Operations without specific validation (validated in ledger.rs or by construction)
        LedgerOperation::QuorumAddMember { .. }
        | LedgerOperation::QuorumRemoveMember { .. }
        | LedgerOperation::QuorumJoin { .. }
        | LedgerOperation::QuorumBegin { .. }
        | LedgerOperation::DisputeEnter { .. }
        | LedgerOperation::DisputeArmed { .. }
        | LedgerOperation::DisputeAcquire { .. }
        | LedgerOperation::DisputeYield
        | LedgerOperation::DeliveryEmbed { .. } => Ok(()),
    }
}

// ============================================================================
// Individual Message Validators
// ============================================================================

/// Validate DepositOpen (add deposit) message.
pub fn validate_add_deposit_msg<C: ValidationContext>(
    ctx: &C,
    msg: &DepositOpenMsg,
    sender: PublicKey,
) -> ValidationResult {
    if let Some(ledger_arc) = ctx.get_ledger(&sender, &ctx.our_node_id().to_string()) {
        let ledger = ledger_arc.read().unwrap();
        validate_deposit_add(&ledger, msg.pubkey, msg.fees.as_ref())
    } else {
        Err(format!("No channel ledger found for sender {}", sender))
    }
}

/// Validate DepositClose (remove deposit) message.
pub fn validate_remove_deposit_msg<C: ValidationContext>(
    ctx: &C,
    msg: &DepositCloseMsg,
    sender: PublicKey,
) -> ValidationResult {
    if let Some(ledger_arc) = ctx.get_ledger(&sender, &ctx.our_node_id().to_string()) {
        let ledger = ledger_arc.read().unwrap();
        validate_deposit_close(&ledger, msg.pubkey)
    } else {
        Err(format!("No channel ledger found for sender {}", sender))
    }
}

/// Validate FeeChange message.
pub fn validate_update_deposit_msg<C: ValidationContext>(
    ctx: &C,
    msg: &FeeChangeMsg,
    sender: PublicKey,
) -> ValidationResult {
    if let Some(ledger_arc) = ctx.get_ledger(&sender, &ctx.our_node_id().to_string()) {
        let ledger = ledger_arc.read().unwrap();
        validate_fee_change(&ledger, msg.pubkey, &msg.new_fees)
    } else {
        Err(format!("No channel ledger found for sender {}", sender))
    }
}

/// Validate SendingLockPayment message.
pub fn validate_sending_lock_payment_msg<C: ValidationContext>(
    ctx: &C,
    msg: &SendingLockPaymentMsg,
    sender: PublicKey,
) -> ValidationResult {
    if let Some(ledger_arc) = ctx.get_ledger(&sender, &ctx.our_node_id().to_string()) {
        let ledger = ledger_arc.read().unwrap();
        validate_payment_lock(
            &ledger,
            msg.pubkey,
            msg.amount,
            &msg.payment_id,
            &msg.scriptpubkey_signature,
        )
    } else {
        Err(format!("No channel ledger found for sender {}", sender))
    }
}

/// Validate SendingFulfillPayment message.
///
/// This validation does not require ledger access.
pub fn validate_sending_fulfill_payment_msg(msg: &SendingFulfillPaymentMsg) -> ValidationResult {
    validate_payment_fulfill(
        &msg.pubkey,
        msg.amount,
        &msg.payment_id,
        &msg.scriptpubkey_signature,
        &msg.preimage,
    )
}

/// Validate SendingFailPayment message.
///
/// This validation does not require ledger access.
pub fn validate_sending_fail_payment_msg(msg: &SendingFailPaymentMsg) -> ValidationResult {
    validate_payment_fail(msg.amount)
}

/// Validate ReceivingCreditPayment message.
pub fn validate_receiving_credit_payment_msg<C: ValidationContext>(
    ctx: &C,
    msg: &ReceivingCreditPaymentMsg,
    sender: PublicKey,
) -> ValidationResult {
    // Demo-specific fake invoice check (TODO: move to separate layer)
    if msg.invoice_id.contains("fake") || msg.invoice_id.contains("424242") {
        return Err(format!("Invalid invoice ID: {}", msg.invoice_id));
    }

    if let Some(ledger_arc) = ctx.get_ledger(&sender, &ctx.our_node_id().to_string()) {
        let ledger = ledger_arc.read().unwrap();
        validate_credit_payment(&ledger, msg.deposit_pubkey, msg.amount, &msg.payment_hash)
    } else {
        Err(format!("No channel ledger found for sender {}", sender))
    }
}

/// Validate ReservesAddOutput message.
pub fn validate_reserves_add_output_msg(msg: &ReservesAddOutputMsg) -> ValidationResult {
    validate_reserves_add(msg.initial_amount)
}

/// Validate ReservesRemoveOutput message.
pub fn validate_reserves_remove_msg<C: ValidationContext>(
    ctx: &C,
    msg: &ReservesRemoveOutputMsg,
    sender: PublicKey,
) -> ValidationResult {
    // First check if we have a ledger for this sender
    let has_ledger = ctx
        .get_ledger(&sender, &ctx.our_node_id().to_string())
        .is_some();

    if has_ledger {
        // As the partner, use commitment tx reserves amount (not ledger's declared amount)
        // This is the source of truth for what the operator has actually committed
        let commitment_reserves = ctx.get_commitment_tx_reserves_amount(sender).unwrap_or(0);

        // If remove_all is false, this is a partial removal - validate reserves exist in commitment tx
        if !msg.remove_all && commitment_reserves == 0 {
            return Err("Cannot remove reserves: no reserves committed in channel".to_string());
        }

        Ok(())
    } else {
        Err(format!("No channel ledger found for sender {}", sender))
    }
}

/// Validate FeeCollect message.
pub fn validate_fee_collect_msg<C: ValidationContext>(
    ctx: &C,
    msg: &FeeCollectMsg,
    sender: PublicKey,
) -> ValidationResult {
    if let Some(ledger_arc) = ctx.get_ledger(&sender, &ctx.our_node_id().to_string()) {
        let ledger = ledger_arc.read().unwrap();
        validate_fee_collect(&ledger, msg.pubkey, msg.amount, msg.block_height)
    } else {
        Err(format!("No channel ledger found for sender {}", sender))
    }
}

/// Validate ReceivingCosignInvoice message.
///
/// Partner must verify the invoice amount doesn't exceed reserves/collateral BEFORE cosigning.
pub fn validate_receiving_cosign_invoice_msg<C: ValidationContext>(
    ctx: &C,
    msg: &ReceivingCosignInvoiceMsg,
    sender: PublicKey,
) -> ValidationResult {
    // Sender is the operator, we are the partner being asked to cosign
    if let Some(ledger_arc) = ctx.get_ledger(&sender, &ctx.our_node_id().to_string()) {
        let ledger = ledger_arc.read().unwrap();
        validate_cosign_invoice(
            &ledger,
            msg.assigned_deposit,
            msg.amount,
            &msg.invoice_id,
            &msg.payment_hash,
        )
    } else {
        Err(format!("No channel ledger found for sender {}", sender))
    }
}

/// Validate LedgerClose message.
///
/// Partner must verify the ledger exists and can be closed.
pub fn validate_ledger_close_msg<C: ValidationContext>(
    ctx: &C,
    msg: &LedgerCloseMsg,
    sender: PublicKey,
) -> ValidationResult {
    // Sender is the operator, we are the partner
    if let Some(ledger_arc) = ctx.get_ledger(&sender, &ctx.our_node_id().to_string()) {
        let ledger = ledger_arc.read().unwrap();

        // Check that the reserves_id matches us (context-specific check)
        if msg.reserves_id != ctx.our_node_id().to_string() {
            return Err(format!(
                "LedgerClose reserves_id {} does not match our node {}",
                msg.reserves_id,
                ctx.our_node_id()
            ));
        }

        // Delegate balance checks to core
        validate_ledger_close(&ledger)
    } else {
        Err(format!("No channel ledger found for sender {}", sender))
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::LedgerRole;
    use crate::types::Deposit;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use std::collections::HashMap;

    /// Test implementation of ValidationContext
    struct TestContext {
        ledgers: HashMap<(PublicKey, String), Arc<RwLock<Ledger>>>,
        our_node_id: PublicKey,
    }

    impl TestContext {
        fn new(our_node_id: PublicKey) -> Self {
            Self {
                ledgers: HashMap::new(),
                our_node_id,
            }
        }

        fn add_ledger(&mut self, operator: PublicKey, reserves_id: String, ledger: Ledger) {
            self.ledgers
                .insert((operator, reserves_id), Arc::new(RwLock::new(ledger)));
        }
    }

    impl ValidationContext for TestContext {
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
    fn test_validate_add_deposit_no_ledger() {
        let our_node_id = create_test_pubkey(1);
        let ctx = TestContext::new(our_node_id);
        let sender = create_test_pubkey(2);

        let msg = DepositOpenMsg {
            pubkey: create_test_pubkey(3),
            fees: None,
            payment_hash: None,
            invoice: None,
            cosigner_guarantee_signature: None,
            reserves_id: our_node_id.to_string(),
        };

        let result = validate_add_deposit_msg(&ctx, &msg, sender);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No channel ledger found"));
    }

    #[test]
    fn test_validate_add_deposit_with_ledger() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let deposit_pubkey = create_test_pubkey(3);

        let mut ctx = TestContext::new(our_node_id);
        let ledger = Ledger::new(
            operator,
            our_node_id.to_string(),
            LedgerRole::Partner,
            vec![],
            0,
        );
        ctx.add_ledger(operator, our_node_id.to_string(), ledger);

        let msg = DepositOpenMsg {
            pubkey: deposit_pubkey,
            fees: None,
            payment_hash: None,
            invoice: None,
            cosigner_guarantee_signature: None,
            reserves_id: our_node_id.to_string(),
        };

        let result = validate_add_deposit_msg(&ctx, &msg, operator);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_sending_fulfill_payment_zero_amount() {
        let msg = SendingFulfillPaymentMsg {
            pubkey: create_test_pubkey(1),
            amount: 0,
            payment_id: [0xAB; 32],
            sequence_number: 0,
            scriptpubkey_signature: [0; 64],
            preimage: [0; 32],
        };

        let result = validate_sending_fulfill_payment_msg(&msg);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must be greater than zero"));
    }

    #[test]
    fn test_validate_sending_fail_payment_zero_amount() {
        let msg = SendingFailPaymentMsg {
            pubkey: create_test_pubkey(1),
            amount: 0,
            payment_id: [0xAB; 32],
            sequence_number: 0,
        };

        let result = validate_sending_fail_payment_msg(&msg);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must be greater than zero"));
    }

    #[test]
    fn test_validate_reserves_add_too_small() {
        let msg = ReservesAddOutputMsg {
            initial_amount: 100, // Below minimum
            spend_to: create_test_pubkey(1),
            reserves_id: create_test_pubkey(2).to_string(),
            quorum_members: vec![],
        };

        let result = validate_reserves_add_output_msg(&msg);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("below minimum"));
    }

    #[test]
    fn test_validate_reserves_add_too_large() {
        let msg = ReservesAddOutputMsg {
            initial_amount: 1_000_000_000_000, // Above maximum
            spend_to: create_test_pubkey(1),
            reserves_id: create_test_pubkey(2).to_string(),
            quorum_members: vec![],
        };

        let result = validate_reserves_add_output_msg(&msg);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("exceeds maximum"));
    }

    #[test]
    fn test_validate_ledger_close_outstanding_balance() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let deposit_pubkey = create_test_pubkey(3);

        let mut ctx = TestContext::new(our_node_id);
        let mut ledger = Ledger::new(
            operator,
            our_node_id.to_string(),
            LedgerRole::Partner,
            vec![],
            0,
        );
        let mut deposit = Deposit::from_pubkey(&deposit_pubkey, None);
        deposit.balance = 50_000; // Has balance
        ledger.state.deposits.insert(deposit.deposit_id, deposit);
        ctx.add_ledger(operator, our_node_id.to_string(), ledger);

        let msg = LedgerCloseMsg {
            reserves_id: our_node_id.to_string(),
        };

        let result = validate_ledger_close_msg(&ctx, &msg, operator);
        assert!(
            result.is_err(),
            "Should reject close with outstanding balance"
        );
        assert!(result.unwrap_err().contains("outstanding"));
    }

    #[test]
    fn test_validate_ledger_close_valid_empty() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);

        let mut ctx = TestContext::new(our_node_id);
        let ledger = Ledger::new(
            operator,
            our_node_id.to_string(),
            LedgerRole::Partner,
            vec![],
            0,
        );
        ctx.add_ledger(operator, our_node_id.to_string(), ledger);

        let msg = LedgerCloseMsg {
            reserves_id: our_node_id.to_string(),
        };

        let result = validate_ledger_close_msg(&ctx, &msg, operator);
        assert!(
            result.is_ok(),
            "Valid close of empty ledger should succeed: {:?}",
            result
        );
    }
}
