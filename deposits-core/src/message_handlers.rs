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
}
