// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Implementation of deposits-core's HandlerContext trait for DepositsHandler.
//!
//! This module bridges the LDK-specific DepositsHandler with the Lightning-agnostic
//! handler logic in deposits-core.
//!
//! Note: ValidationContext is implemented in message_validation.rs. This file
//! only implements the HandlerContext extension trait.

use bitcoin::secp256k1::{PublicKey, SecretKey};
use std::ops::Deref;
use std::sync::{Arc, Mutex};
use lightning::util::logger::Logger as LdkLogger;

use deposits_core::error::HandlerError;
use deposits_core::messages::DepositsMessage as CoreDepositsMessage;
use deposits_core::message_validation::HandlerContext;
use deposits_core::recovery::RecoveryManager;
use deposits_core::traits::ProtocolEvent;

use super::core::DepositsHandler;
use super::events::DepositsEvent;
use deposits_core::{log_info, log_warn};

impl<L: Deref + Clone + Send + Sync> HandlerContext for DepositsHandler<L>
where
    L::Target: LdkLogger,
{
    fn queue_message(&self, peer: PublicKey, msg: CoreDepositsMessage) -> Result<(), HandlerError> {
        // Convert the core DepositsMessage (V2) to LDK DepositsMessage (V1)
        // For now, we can only handle certain message types that have equivalents
        // The V2 consolidated protocol is different from V1, so we need
        // to handle this conversion carefully.
        //
        // For the current handlers (collateral consent, quorum, recovery),
        // we use the ResponseData approach instead of directly queuing V2 messages.
        //
        // This method is provided for completeness but the current implementation
        // returns an error for unsupported message types.

        log_warn!(
            self.logger,
            "queue_message called with V2 message type - conversion not yet implemented"
        );

        Err(HandlerError::Internal(
            "V2 message queuing not yet implemented - use ResponseData instead".to_string()
        ))
    }

    fn emit_event(&self, event: ProtocolEvent) {
        // Convert core ProtocolEvent to LDK DepositsEvent
        match event {
            ProtocolEvent::DepositOpened { operator, partner, deposit_pubkey, initial_balance } => {
                // The DepositsEvent doesn't have a direct mapping, log it
                log_info!(
                    self.logger,
                    "Protocol event: DepositOpened - operator={}, partner={}, deposit={}",
                    operator, partner, deposit_pubkey
                );
            }
            ProtocolEvent::DepositClosed { operator, partner, deposit_pubkey, final_balance } => {
                log_info!(
                    self.logger,
                    "Protocol event: DepositClosed - operator={}, partner={}, deposit={}",
                    operator, partner, deposit_pubkey
                );
            }
            ProtocolEvent::PaymentCredited { operator, partner, deposit_pubkey, amount, payment_hash } => {
                log_info!(
                    self.logger,
                    "Protocol event: PaymentCredited - operator={}, partner={}, deposit={}, amount={}",
                    operator, partner, deposit_pubkey, amount
                );
            }
            ProtocolEvent::PaymentSent { operator, partner, deposit_pubkey, amount, payment_id } => {
                log_info!(
                    self.logger,
                    "Protocol event: PaymentSent - operator={}, partner={}, deposit={}, amount={}",
                    operator, partner, deposit_pubkey, amount
                );
            }
            ProtocolEvent::LedgerSynced { operator, partner, sequence, hash } => {
                log_info!(
                    self.logger,
                    "Protocol event: LedgerSynced - operator={}, partner={}, seq={}",
                    operator, partner, sequence
                );
            }
            ProtocolEvent::RecoveryStarted { operator, partner } => {
                log_info!(
                    self.logger,
                    "Protocol event: RecoveryStarted - operator={}, partner={}",
                    operator, partner
                );
                // Emit the LDK event
                let _ = self.event_queue.emit_deposits_event(
                    DepositsEvent::RecoveryNonCompliant {
                        operator_id: operator,
                        partner_id: partner,
                        non_conforming_votes: 0, // Filled in by caller
                        total_votes: 0,
                    }
                );
            }
            ProtocolEvent::RecoveryClaimed { operator, partner, new_operator, claim_txid } => {
                log_info!(
                    self.logger,
                    "Protocol event: RecoveryClaimed - operator={}, partner={}, new_operator={}",
                    operator, partner, new_operator
                );
                let _ = self.event_queue.emit_deposits_event(
                    DepositsEvent::RecoveryClaimCompleted {
                        old_operator: operator,
                        partner_id: partner,
                        new_operator,
                        claim_txid,
                        confirmation_block: 0, // Filled in by caller
                    }
                );
            }
            ProtocolEvent::Error { operator, partner, error } => {
                log_warn!(
                    self.logger,
                    "Protocol error: operator={}, partner={}: {}",
                    operator, partner, error
                );
            }
            ProtocolEvent::UncreditedPaymentReceived { operator, partner, payment_hash, amount_msat } => {
                log_warn!(
                    self.logger,
                    "Protocol event: UncreditedPaymentReceived (fraud proof) - operator={}, partner={}, amount={}",
                    operator, partner, amount_msat
                );
            }
            ProtocolEvent::FeeCollected { operator, partner, deposit_pubkey, amount, block_height } => {
                log_info!(
                    self.logger,
                    "Protocol event: FeeCollected - operator={}, partner={}, deposit={}, amount={}, block={}",
                    operator, partner, deposit_pubkey, amount, block_height
                );
            }
            ProtocolEvent::LedgerClosed { operator, partner } => {
                log_info!(
                    self.logger,
                    "Protocol event: LedgerClosed - operator={}, partner={}",
                    operator, partner
                );
            }
            ProtocolEvent::InvoiceCosignRequested { operator, partner, deposit_pubkey, amount, payment_hash } => {
                log_info!(
                    self.logger,
                    "Protocol event: InvoiceCosignRequested - operator={}, partner={}, deposit={}, amount={}",
                    operator, partner, deposit_pubkey, amount
                );
            }
            ProtocolEvent::RecoveryClaimRequested { operator, partner, claimant, tier_index } => {
                log_info!(
                    self.logger,
                    "Protocol event: RecoveryClaimRequested - operator={}, partner={}, claimant={}, tier={}",
                    operator, partner, claimant, tier_index
                );
            }
            ProtocolEvent::RecoveryClaimSignatureReceived { operator, partner, signer } => {
                log_info!(
                    self.logger,
                    "Protocol event: RecoveryClaimSignatureReceived - operator={}, partner={}, signer={}",
                    operator, partner, signer
                );
            }
            ProtocolEvent::RecoveryClaimCompleted { old_operator, partner, new_operator, claim_txid, confirmation_block } => {
                log_info!(
                    self.logger,
                    "Protocol event: RecoveryClaimCompleted - old_operator={}, partner={}, new_operator={}",
                    old_operator, partner, new_operator
                );
            }
            ProtocolEvent::ChannelClosed { operator, partner, channel_id, reason } => {
                log_info!(
                    self.logger,
                    "Protocol event: ChannelClosed - operator={}, partner={}, reason={:?}",
                    operator, partner, reason
                );
            }
        }
    }

    fn recovery_manager(&self) -> Option<Arc<Mutex<RecoveryManager>>> {
        // Return a clone of our recovery manager wrapped in Arc
        // We need to convert from Mutex to Arc<Mutex>
        // Since we already have a Mutex<RecoveryManager>, we need to handle this
        // by creating an Arc wrapper
        //
        // This is a limitation of the current design - ideally the handler would
        // already use Arc<Mutex<RecoveryManager>>
        //
        // For now, we return None and the handlers will need to access the
        // recovery manager directly through the DepositsHandler
        None
    }

    fn our_secret_key(&self) -> Option<SecretKey> {
        self.node_secret_key
    }

    fn current_block_height(&self) -> u32 {
        // Get current block height from chain source if available
        // For now, return 0 - this would need to be wired to the chain monitor
        0
    }
}

/// Extension trait for using core handlers with LDK
pub trait CoreHandlerExt<L: Deref + Clone + Send + Sync>
where
    L::Target: LdkLogger,
{
    /// Handle a collateral consent request using core logic
    fn handle_collateral_consent_request_core(
        &self,
        msg: &deposits_core::wire_messages::CollateralConsentRequestMsg,
        sender: PublicKey,
    ) -> Result<deposits_core::message_handlers::HandlerResult, HandlerError>;

    /// Handle a collateral consent response using core logic
    fn handle_collateral_consent_response_core(
        &self,
        msg: &deposits_core::wire_messages::CollateralConsentResponseMsg,
        sender: PublicKey,
    ) -> Result<deposits_core::message_handlers::HandlerResult, HandlerError>;

    /// Handle a recovery vote using core logic
    fn handle_recovery_vote_core(
        &self,
        msg: &deposits_core::wire_messages::RecoveryVoteMsg,
        sender: PublicKey,
    ) -> Result<deposits_core::message_handlers::HandlerResult, HandlerError>;
}

impl<L: Deref + Clone + Send + Sync> CoreHandlerExt<L> for DepositsHandler<L>
where
    L::Target: LdkLogger,
{
    fn handle_collateral_consent_request_core(
        &self,
        msg: &deposits_core::wire_messages::CollateralConsentRequestMsg,
        sender: PublicKey,
    ) -> Result<deposits_core::message_handlers::HandlerResult, HandlerError> {
        deposits_core::handle_collateral_consent_request(self, msg, sender)
    }

    fn handle_collateral_consent_response_core(
        &self,
        msg: &deposits_core::wire_messages::CollateralConsentResponseMsg,
        sender: PublicKey,
    ) -> Result<deposits_core::message_handlers::HandlerResult, HandlerError> {
        deposits_core::handle_collateral_consent_response(self, msg, sender)
    }

    fn handle_recovery_vote_core(
        &self,
        msg: &deposits_core::wire_messages::RecoveryVoteMsg,
        sender: PublicKey,
    ) -> Result<deposits_core::message_handlers::HandlerResult, HandlerError> {
        deposits_core::handle_recovery_vote(self, msg, sender)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests would go here
    // For now, we rely on the integration tests in deposits-ldk
}
