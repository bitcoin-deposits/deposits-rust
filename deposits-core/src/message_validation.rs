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
//! validate_reserves_increase_msg(&context, &msg, sender)?;
//! ```

use bitcoin::secp256k1::PublicKey;
use std::sync::{Arc, RwLock};

use crate::ledger::Ledger;
use crate::messages::LedgerOperation;
use crate::operation_validation::{
    validate_deposit_add, validate_deposit_close, validate_deposit_update,
    validate_payment_lock, validate_payment_fulfill, validate_payment_fail,
    validate_credit_payment, validate_reserves_add, validate_reserves_increase,
    validate_reserves_decrease, validate_fee_collect,
    validate_collateral_increase, validate_collateral_decrease,
    validate_cosign_invoice, validate_ledger_close,
    ValidationResult,
};
use crate::wire_messages::{
    DepositOpenMsg, DepositCloseMsg, DepositUpdateMsg,
    SendingLockPaymentMsg, SendingFulfillPaymentMsg, SendingFailPaymentMsg,
    ReceivingCreditPaymentMsg, ReservesAddOutputMsg, ReservesRemoveOutputMsg,
    ReservesIncreaseMsg, ReservesDecreaseMsg, FeeCollectMsg,
    CollateralIncreaseMsg, CollateralDecreaseMsg,
    ReceivingCosignInvoiceMsg, LedgerCloseMsg,
};

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
    /// Get a ledger for the given operator/partner pair.
    ///
    /// Returns None if no ledger exists for this pair.
    fn get_ledger(&self, operator: &PublicKey, partner: &PublicKey) -> Option<Arc<RwLock<Ledger>>>;

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
use crate::quorum::QuorumManager;
use crate::recovery::RecoveryManager;
use crate::recovery_claim::ClaimManager;
use bitcoin::secp256k1::SecretKey;
use std::sync::Mutex;

/// Context for handling protocol messages.
/// Extends ValidationContext with message sending, signing, and persistence.
pub trait HandlerContext: ValidationContext {
    /// Queue a message to be sent to a peer
    fn queue_message(&self, peer: PublicKey, msg: DepositsMessage) -> Result<(), HandlerError>;

    /// Emit a protocol event (deposit event, recovery event, etc.)
    fn emit_event(&self, event: crate::traits::ProtocolEvent);

    /// Get recovery manager access
    fn recovery_manager(&self) -> Option<Arc<Mutex<RecoveryManager>>>;

    /// Get claim manager access for recovery claims
    fn claim_manager(&self) -> Option<Arc<Mutex<ClaimManager>>> { None }

    /// Get quorum manager access (returns reference, not Arc since it's not behind Mutex)
    fn quorum_manager(&self) -> Option<&QuorumManager> { None }

    /// Get our secret key for signing (optional, for handlers that need it)
    fn our_secret_key(&self) -> Option<SecretKey> { None }

    /// Sign arbitrary message content with our node key (ECDSA).
    /// Returns 64-byte signature or None if signing unavailable.
    fn sign_message(&self, content: &[u8]) -> Option<[u8; 64]> {
        use bitcoin::hashes::{Hash, sha256};
        use bitcoin::secp256k1::{Secp256k1, Message};

        let secret_key = self.our_secret_key()?;
        let hash = sha256::Hash::hash(content);
        let secp_msg = Message::from_digest(hash.to_byte_array());
        let secp = Secp256k1::new();

        match secp.sign_ecdsa(&secp_msg, &secret_key) {
            sig => Some(sig.serialize_compact())
        }
    }

    /// Sign a sighash with Schnorr (BIP340) for recovery claims.
    /// Returns 64-byte Schnorr signature or None if signing unavailable.
    fn sign_schnorr(&self, sighash: &[u8; 32]) -> Option<[u8; 64]> {
        use bitcoin::secp256k1::{Secp256k1, Message, Keypair};

        let secret_key = self.our_secret_key()?;
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, &secret_key);
        let msg = Message::from_digest(*sighash);
        let signature = secp.sign_schnorr_no_aux_rand(&msg, &keypair);
        Some(signature.serialize())
    }

    /// Get the current block height
    fn current_block_height(&self) -> u32 { 0 }

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
    fn persist_ledger(&self, operator: &PublicKey, partner: &PublicKey) -> Result<(), String> {
        let _ = (operator, partner);
        Ok(()) // Default: no-op
    }

    /// Sync quorum membership after collateral partner change.
    fn sync_quorum_member(&self, operator: PublicKey, partner: PublicKey, collateral_partner: PublicKey, add: bool) {
        let _ = (operator, partner, collateral_partner, add);
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
        partner_signature: Option<[u8; 64]>,
    ) -> Result<(), HandlerError> {
        let _ = (peer, message_hash, message_type, success, error_message, sequence, prev_hash, new_hash, partner_signature);
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
    fn complete_pending_ack(&self, hash: &[u8; 32]) -> Option<crate::PendingAck> {
        let _ = hash;
        None // Default: not found
    }

    /// Check for timed-out ACKs.
    /// Returns list of (hash, pending_ack) pairs that have exceeded the threshold.
    fn get_timed_out_acks(&self, threshold_secs: u64) -> Vec<([u8; 32], crate::PendingAck)> {
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
    fn verify_and_store_signed_update(&self, update: crate::SignedLedgerUpdate) -> Result<(), String> {
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
    fn complete_broadcast(&self, msg_hash: [u8; 32], partner_sig: Option<[u8; 64]>) -> Result<(), String> {
        let _ = (msg_hash, partner_sig);
        Ok(()) // Default: no-op
    }

    /// Get collateral partners for broadcast (excluding the direct partner).
    fn get_broadcast_recipients(&self, operator: &PublicKey, partner: &PublicKey) -> Vec<PublicKey> {
        let _ = (operator, partner);
        vec![] // Default: none
    }

    // ========================================================================
    // Fraud Proof Methods
    // ========================================================================

    /// Handle followup actions after receiving a valid fraud proof (uncredited payment).
    /// - Force-close any channel with the accused operator
    /// - Rebroadcast the accusation to our collateral partners
    fn handle_fraud_proof_followup(
        &self,
        accused_operator: PublicKey,
        accusation_msg: DepositsMessage,
    ) {
        let _ = (accused_operator, accusation_msg);
        // Default: no-op (LDK implementation handles channel closure and rebroadcast)
    }

    // ========================================================================
    // Recovery Claim Management Methods
    // ========================================================================

    /// Add a claim signature and check if threshold is reached.
    /// Returns Ok(true) if threshold is now reached, Ok(false) otherwise.
    /// Emits RecoveryClaimReady event if threshold reached.
    fn add_claim_signature(
        &self,
        operator: PublicKey,
        partner: PublicKey,
        signer: PublicKey,
        signature: [u8; 64],
    ) -> Result<bool, String> {
        let _ = (operator, partner, signer, signature);
        Ok(false) // Default: not implemented
    }

    /// Remove a completed recovery claim from tracking.
    fn remove_claim(&self, operator: PublicKey, partner: PublicKey) {
        let _ = (operator, partner);
        // Default: no-op
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
        LedgerOperation::DepositOpen { pubkey, fees, .. } => {
            let msg = DepositOpenMsg {
                partner_id: partner_pubkey,
                pubkey: *pubkey,
                fees: fees.clone(),
                payment_hash: None, // Not used in validation
                invoice: None,
                cosigner_guarantee_signature: None,
            };
            validate_add_deposit_msg(ctx, &msg, sender)
        }
        LedgerOperation::DepositClose { pubkey } => {
            let msg = DepositCloseMsg {
                partner_id: partner_pubkey,
                pubkey: *pubkey,
            };
            validate_remove_deposit_msg(ctx, &msg, sender)
        }
        LedgerOperation::DepositUpdate { pubkey, new_fees } => {
            let msg = DepositUpdateMsg {
                partner_id: partner_pubkey,
                pubkey: *pubkey,
                new_fees: new_fees.clone(),
            };
            validate_update_deposit_msg(ctx, &msg, sender)
        }
        LedgerOperation::PaymentLock { pubkey, amount, payment_id, scriptpubkey_signature, .. } => {
            let msg = SendingLockPaymentMsg {
                pubkey: *pubkey,
                amount: *amount,
                payment_id: *payment_id,
                sequence_number: 0, // Not used in validation
                scriptpubkey_signature: *scriptpubkey_signature,
            };
            validate_sending_lock_payment_msg(ctx, &msg, sender)
        }
        LedgerOperation::PaymentFulfill { pubkey, amount, payment_id, scriptpubkey_signature, preimage, .. } => {
            let msg = SendingFulfillPaymentMsg {
                pubkey: *pubkey,
                amount: *amount,
                payment_id: *payment_id,
                sequence_number: 0,
                scriptpubkey_signature: *scriptpubkey_signature,
                preimage: *preimage,
            };
            validate_sending_fulfill_payment_msg(&msg)
        }
        LedgerOperation::PaymentFail { amount, .. } => {
            let msg = SendingFailPaymentMsg {
                pubkey: PublicKey::from_slice(&[2; 33]).unwrap(), // Placeholder
                amount: *amount,
                payment_id: [0; 32],
                sequence_number: 0,
            };
            validate_sending_fail_payment_msg(&msg)
        }
        LedgerOperation::PaymentCredit { payment_hash, deposit_pubkey, amount, invoice_id, .. } => {
            let msg = ReceivingCreditPaymentMsg {
                payment_hash: *payment_hash,
                deposit_pubkey: *deposit_pubkey,
                amount: *amount,
                invoice_id: invoice_id.clone(),
                partner_id: partner_pubkey,
                sequence_number: 0,
            };
            validate_receiving_credit_payment_msg(ctx, &msg, sender)
        }
        LedgerOperation::ReservesAdd { amount, spend_to, collateral_partners } => {
            let msg = ReservesAddOutputMsg {
                initial_amount: *amount,
                spend_to: *spend_to,
                partner_id: partner_pubkey,
                collateral_partners: collateral_partners.clone(),
            };
            validate_reserves_add_output_msg(&msg)
        }
        LedgerOperation::ReservesRemove => {
            let msg = ReservesRemoveOutputMsg {
                partner_id: partner_pubkey,
                remove_all: true,
            };
            validate_reserves_remove_msg(ctx, &msg, sender)
        }
        LedgerOperation::ReservesIncrease { new_amount } => {
            let msg = ReservesIncreaseMsg {
                new_amount: *new_amount,
                partner_id: partner_pubkey,
            };
            validate_reserves_increase_msg(ctx, &msg, sender)
        }
        LedgerOperation::ReservesDecrease { new_amount } => {
            let msg = ReservesDecreaseMsg {
                new_amount: *new_amount,
                partner_id: partner_pubkey,
            };
            validate_reserves_decrease_msg(ctx, &msg, sender)
        }
        LedgerOperation::CollateralIncrease { new_amount, block_height } => {
            let msg = CollateralIncreaseMsg {
                partner_id: partner_pubkey,
                new_amount: *new_amount,
                block_height: *block_height,
            };
            validate_collateral_increase_msg(ctx, &msg, sender)
        }
        LedgerOperation::CollateralDecrease { new_amount, block_height } => {
            let msg = CollateralDecreaseMsg {
                partner_id: partner_pubkey,
                new_amount: *new_amount,
                block_height: *block_height,
            };
            validate_collateral_decrease_msg(ctx, &msg, sender)
        }
        LedgerOperation::FeeCollect { pubkey, amount, block_height } => {
            let msg = FeeCollectMsg {
                pubkey: *pubkey,
                amount: *amount,
                block_height: *block_height,
            };
            validate_fee_collect_msg(ctx, &msg, sender)
        }
        LedgerOperation::LedgerClose => {
            let msg = LedgerCloseMsg {
                partner_id: partner_pubkey,
            };
            validate_ledger_close_msg(ctx, &msg, sender)
        }
        // Operations without specific validation
        LedgerOperation::ReservesUpdateSpendTo { .. } |
        LedgerOperation::TransferLock { .. } |
        LedgerOperation::TransferFail { .. } |
        LedgerOperation::TransferFulfill { .. } |
        LedgerOperation::CollateralAttestation { .. } |
        LedgerOperation::CollateralAddPartner { .. } |
        LedgerOperation::CollateralRemovePartner { .. } |
        LedgerOperation::Tombstone { .. } => Ok(()),
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
    if let Some(ledger_arc) = ctx.get_ledger(&sender, &ctx.our_node_id()) {
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
    if let Some(ledger_arc) = ctx.get_ledger(&sender, &ctx.our_node_id()) {
        let ledger = ledger_arc.read().unwrap();
        validate_deposit_close(&ledger, msg.pubkey)
    } else {
        Err(format!("No channel ledger found for sender {}", sender))
    }
}

/// Validate DepositUpdate message.
pub fn validate_update_deposit_msg<C: ValidationContext>(
    ctx: &C,
    msg: &DepositUpdateMsg,
    sender: PublicKey,
) -> ValidationResult {
    if let Some(ledger_arc) = ctx.get_ledger(&sender, &ctx.our_node_id()) {
        let ledger = ledger_arc.read().unwrap();
        validate_deposit_update(&ledger, msg.pubkey, &msg.new_fees)
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
    if let Some(ledger_arc) = ctx.get_ledger(&sender, &ctx.our_node_id()) {
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

    if let Some(ledger_arc) = ctx.get_ledger(&sender, &ctx.our_node_id()) {
        let ledger = ledger_arc.read().unwrap();
        validate_credit_payment(
            &ledger,
            msg.deposit_pubkey,
            msg.amount,
            &msg.payment_hash,
        )
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
    let has_ledger = ctx.get_ledger(&sender, &ctx.our_node_id()).is_some();

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
    if let Some(ledger_arc) = ctx.get_ledger(&sender, &ctx.our_node_id()) {
        let ledger = ledger_arc.read().unwrap();
        validate_fee_collect(&ledger, msg.pubkey, msg.amount, msg.block_height)
    } else {
        Err(format!("No channel ledger found for sender {}", sender))
    }
}

/// Validate CollateralIncrease message.
pub fn validate_collateral_increase_msg<C: ValidationContext>(
    ctx: &C,
    msg: &CollateralIncreaseMsg,
    sender: PublicKey,
) -> ValidationResult {
    if let Some(ledger_arc) = ctx.get_ledger(&sender, &ctx.our_node_id()) {
        let ledger = ledger_arc.read().unwrap();
        validate_collateral_increase(
            ledger.state.collateral_amount,
            msg.new_amount,
            ledger.reserves_amount(),
        )
    } else {
        Err(format!("No channel ledger found for sender {}", sender))
    }
}

/// Validate CollateralDecrease message.
///
/// CONSTRAINT: collateraldecrease doesn't happen in the same reporting period as collateralincrease
pub fn validate_collateral_decrease_msg<C: ValidationContext>(
    ctx: &C,
    msg: &CollateralDecreaseMsg,
    sender: PublicKey,
) -> ValidationResult {
    if let Some(ledger_arc) = ctx.get_ledger(&sender, &ctx.our_node_id()) {
        let ledger = ledger_arc.read().unwrap();
        validate_collateral_decrease(
            ledger.state.collateral_amount,
            msg.new_amount,
            msg.block_height,
            ledger.state.last_collateral_increase_block,
        )
    } else {
        Err(format!("No channel ledger found for sender {}", sender))
    }
}

/// Validate ReservesIncrease message.
///
/// CONSTRAINT: reservesincrease doesn't increase reserves past channel balance
pub fn validate_reserves_increase_msg<C: ValidationContext>(
    ctx: &C,
    msg: &ReservesIncreaseMsg,
    sender: PublicKey,
) -> ValidationResult {
    // Get channel balance for optional constraint check (LDK-specific)
    let channel_balance = ctx.get_commitment_tx_reserves_amount(sender);

    // Get current reserves
    if let Some(ledger_arc) = ctx.get_ledger(&sender, &ctx.our_node_id()) {
        let ledger = ledger_arc.read().unwrap();
        validate_reserves_increase(
            ledger.reserves_amount(),
            msg.new_amount,
            channel_balance,
        )
    } else {
        // No ledger - just do basic validation without current reserves check
        validate_reserves_increase(0, msg.new_amount, channel_balance)
    }
}

/// Validate ReservesDecrease message.
///
/// CONSTRAINT: reservesdecrease doesn't fall below ledger requirement
pub fn validate_reserves_decrease_msg<C: ValidationContext>(
    ctx: &C,
    msg: &ReservesDecreaseMsg,
    sender: PublicKey,
) -> ValidationResult {
    if let Some(ledger_arc) = ctx.get_ledger(&sender, &ctx.our_node_id()) {
        let ledger = ledger_arc.read().unwrap();
        validate_reserves_decrease(&ledger, msg.new_amount)
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
    if let Some(ledger_arc) = ctx.get_ledger(&sender, &ctx.our_node_id()) {
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
    if let Some(ledger_arc) = ctx.get_ledger(&sender, &ctx.our_node_id()) {
        let ledger = ledger_arc.read().unwrap();

        // Check that the partner_id matches us (context-specific check)
        if msg.partner_id != ctx.our_node_id() {
            return Err(format!(
                "LedgerClose partner_id {} does not match our node {}",
                msg.partner_id, ctx.our_node_id()
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
    use std::collections::HashMap;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use crate::ledger::LedgerRole;
    use crate::types::Deposit;

    /// Test implementation of ValidationContext
    struct TestContext {
        ledgers: HashMap<(PublicKey, PublicKey), Arc<RwLock<Ledger>>>,
        our_node_id: PublicKey,
    }

    impl TestContext {
        fn new(our_node_id: PublicKey) -> Self {
            Self {
                ledgers: HashMap::new(),
                our_node_id,
            }
        }

        fn add_ledger(&mut self, operator: PublicKey, partner: PublicKey, ledger: Ledger) {
            self.ledgers.insert((operator, partner), Arc::new(RwLock::new(ledger)));
        }
    }

    impl ValidationContext for TestContext {
        fn get_ledger(&self, operator: &PublicKey, partner: &PublicKey) -> Option<Arc<RwLock<Ledger>>> {
            self.ledgers.get(&(*operator, *partner)).cloned()
        }

        fn our_node_id(&self) -> PublicKey {
            self.our_node_id
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
            partner_id: our_node_id,
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
            our_node_id,
            LedgerRole::Partner,
            vec![],
            "tb1qtest".to_string(),
        );
        ctx.add_ledger(operator, our_node_id, ledger);

        let msg = DepositOpenMsg {
            pubkey: deposit_pubkey,
            fees: None,
            payment_hash: None,
            invoice: None,
            cosigner_guarantee_signature: None,
            partner_id: our_node_id,
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
            partner_id: create_test_pubkey(2),
            collateral_partners: vec![],
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
            partner_id: create_test_pubkey(2),
            collateral_partners: vec![],
        };

        let result = validate_reserves_add_output_msg(&msg);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("exceeds maximum"));
    }

    #[test]
    fn test_validate_reserves_increase_must_actually_increase() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);

        let mut ctx = TestContext::new(our_node_id);
        let mut ledger = Ledger::new(
            operator,
            our_node_id,
            LedgerRole::Partner,
            vec![],
            "tb1qtest".to_string(),
        );
        ledger.state.reserves.amount = 5000;
        ctx.add_ledger(operator, our_node_id, ledger);

        // Try to "increase" to a lower amount - should fail
        let msg = ReservesIncreaseMsg {
            new_amount: 4000, // Less than current 5000
            partner_id: our_node_id,
        };

        let result = validate_reserves_increase_msg(&ctx, &msg, operator);
        assert!(result.is_err(), "ReservesIncrease to lower amount should fail");
        assert!(result.unwrap_err().contains("must be greater than current"));
    }

    #[test]
    fn test_validate_collateral_decrease_too_soon_after_increase() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);

        let mut ctx = TestContext::new(our_node_id);
        let mut ledger = Ledger::new(
            operator,
            our_node_id,
            LedgerRole::Partner,
            vec![],
            "tb1qtest".to_string(),
        );
        ledger.state.collateral_amount = 5000;
        ledger.state.last_collateral_increase_block = Some(100);
        ctx.add_ledger(operator, our_node_id, ledger);

        // Try to decrease at block 150 (within 144-block period)
        let msg = CollateralDecreaseMsg {
            new_amount: 3000,
            partner_id: our_node_id,
            block_height: 150,
        };

        let result = validate_collateral_decrease_msg(&ctx, &msg, operator);
        assert!(result.is_err(), "Decrease too soon after increase should fail");
        assert!(result.unwrap_err().contains("too soon after increase"));
    }

    #[test]
    fn test_validate_collateral_decrease_after_reporting_period() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);

        let mut ctx = TestContext::new(our_node_id);
        let mut ledger = Ledger::new(
            operator,
            our_node_id,
            LedgerRole::Partner,
            vec![],
            "tb1qtest".to_string(),
        );
        ledger.state.collateral_amount = 5000;
        ledger.state.last_collateral_increase_block = Some(100);
        ctx.add_ledger(operator, our_node_id, ledger);

        // Decrease at block 250 (after 144-block period: 100 + 144 = 244)
        let msg = CollateralDecreaseMsg {
            new_amount: 3000,
            partner_id: our_node_id,
            block_height: 250,
        };

        let result = validate_collateral_decrease_msg(&ctx, &msg, operator);
        assert!(result.is_ok(), "Decrease after reporting period should succeed: {:?}", result);
    }

    #[test]
    fn test_validate_reserves_decrease_below_requirement_fails() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let deposit_pubkey = create_test_pubkey(3);

        let mut ctx = TestContext::new(our_node_id);
        let mut ledger = Ledger::new(
            operator,
            our_node_id,
            LedgerRole::Partner,
            vec![],
            "tb1qtest".to_string(),
        );
        ledger.state.reserves.amount = 100_000;

        // Add a deposit with 80k balance - this requires reserves backing
        let mut deposit = Deposit::new(deposit_pubkey, None);
        deposit.balance = 80_000;
        ledger.state.deposits.insert(deposit_pubkey, deposit);
        ctx.add_ledger(operator, our_node_id, ledger);

        // Try to decrease reserves below what's required to back deposits
        let msg = ReservesDecreaseMsg {
            new_amount: 50_000, // Less than the 80k deposit balance
            partner_id: our_node_id,
        };

        let result = validate_reserves_decrease_msg(&ctx, &msg, operator);
        assert!(result.is_err(), "Should fail when decrease falls below requirement");
        assert!(result.unwrap_err().contains("must maintain at least"));
    }

    #[test]
    fn test_validate_ledger_close_outstanding_balance() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);
        let deposit_pubkey = create_test_pubkey(3);

        let mut ctx = TestContext::new(our_node_id);
        let mut ledger = Ledger::new(
            operator,
            our_node_id,
            LedgerRole::Partner,
            vec![],
            "tb1qtest".to_string(),
        );
        let mut deposit = Deposit::new(deposit_pubkey, None);
        deposit.balance = 50_000; // Has balance
        ledger.state.deposits.insert(deposit_pubkey, deposit);
        ctx.add_ledger(operator, our_node_id, ledger);

        let msg = LedgerCloseMsg {
            partner_id: our_node_id,
        };

        let result = validate_ledger_close_msg(&ctx, &msg, operator);
        assert!(result.is_err(), "Should reject close with outstanding balance");
        assert!(result.unwrap_err().contains("outstanding"));
    }

    #[test]
    fn test_validate_ledger_close_valid_empty() {
        let our_node_id = create_test_pubkey(1);
        let operator = create_test_pubkey(2);

        let mut ctx = TestContext::new(our_node_id);
        let ledger = Ledger::new(
            operator,
            our_node_id,
            LedgerRole::Partner,
            vec![],
            "tb1qtest".to_string(),
        );
        ctx.add_ledger(operator, our_node_id, ledger);

        let msg = LedgerCloseMsg {
            partner_id: our_node_id,
        };

        let result = validate_ledger_close_msg(&ctx, &msg, operator);
        assert!(result.is_ok(), "Valid close of empty ledger should succeed: {:?}", result);
    }
}
