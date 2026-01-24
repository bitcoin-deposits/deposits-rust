// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Message Processing for Bitcoin Deposits Protocol
//!
//! This module provides trait-based message processing that can be used by any
//! Lightning implementation. The LDK-specific handler delegates to these processors.

use bitcoin::secp256k1::PublicKey;
use tracing::{debug, info, warn};

use crate::quorum::{LedgerId, QuorumManager, QuorumMember};

/// Result of processing a quorum message
#[derive(Debug)]
pub enum QuorumMessageResult {
    /// Request accepted, send response to sender
    Accepted {
        response: QuorumResponse,
        sync_to: Option<PublicKey>,
    },
    /// Request rejected with reason
    Rejected {
        response: QuorumResponse,
        reason: String,
    },
    /// Message processed, no response needed
    Processed,
    /// Error occurred
    Error(String),
}

/// Response to a quorum message
#[derive(Debug, Clone)]
pub struct QuorumResponse {
    /// The ledger this response is for
    pub ledger_id: LedgerId,
    /// Whether the request was accepted
    pub accepted: bool,
    /// Current quorum members (if relevant)
    pub members: Vec<QuorumMember>,
    /// Rejection reason (if rejected)
    pub rejection_reason: Option<String>,
}

/// Quorum join request data
#[derive(Debug, Clone)]
pub struct QuorumJoinRequest {
    pub ledger_id: LedgerId,
    pub requester: PublicKey,
    pub signature: [u8; 64],
}

/// Quorum state sync data
#[derive(Debug, Clone)]
pub struct QuorumStateSync {
    pub ledger_id: LedgerId,
    pub from_sequence: u64,
    pub to_sequence: u64,
    pub state_hash: [u8; 32],
}

/// Quorum vote data
#[derive(Debug, Clone)]
pub struct QuorumVote {
    pub ledger_id: LedgerId,
    pub voter: PublicKey,
    pub vote: bool,
    pub sequence: u64,
    pub state_hash: [u8; 32],
    pub signature: [u8; 64],
}

/// Process quorum-related messages
///
/// This processor handles the pure protocol logic for quorum operations,
/// independent of any Lightning implementation.
pub struct QuorumProcessor {
    /// Our node's public key
    node_id: PublicKey,
    /// The quorum manager
    quorum_manager: QuorumManager,
}

impl QuorumProcessor {
    /// Create a new quorum processor
    pub fn new(node_id: PublicKey, quorum_manager: QuorumManager) -> Self {
        Self {
            node_id,
            quorum_manager,
        }
    }

    /// Get the quorum manager
    pub fn quorum_manager(&self) -> &QuorumManager {
        &self.quorum_manager
    }

    /// Get mutable reference to quorum manager
    pub fn quorum_manager_mut(&mut self) -> &mut QuorumManager {
        &mut self.quorum_manager
    }

    /// Process a join request
    pub fn process_join_request(
        &self,
        request: &QuorumJoinRequest,
        sender: PublicKey,
    ) -> QuorumMessageResult {
        info!(
            requester = %request.requester,
            operator = %request.ledger_id.operator_id,
            partner = %request.ledger_id.partner_id,
            "Processing quorum join request"
        );

        // Verify the request is from the requester
        if sender != request.requester {
            return QuorumMessageResult::Rejected {
                response: QuorumResponse {
                    ledger_id: request.ledger_id,
                    accepted: false,
                    members: vec![],
                    rejection_reason: Some("Sender doesn't match requester".to_string()),
                },
                reason: "Sender doesn't match requester".to_string(),
            };
        }

        // Check if we're the operator for this ledger
        if request.ledger_id.operator_id != self.node_id {
            return QuorumMessageResult::Rejected {
                response: QuorumResponse {
                    ledger_id: request.ledger_id,
                    accepted: false,
                    members: vec![],
                    rejection_reason: Some("We are not the operator for this ledger".to_string()),
                },
                reason: "Not operator".to_string(),
            };
        }

        // Try to add the member to the quorum
        match self.quorum_manager.add_member(&request.ledger_id, request.requester) {
            Ok(()) => {
                let members = self.quorum_manager.list_members(&request.ledger_id)
                    .unwrap_or_default();

                info!(
                    requester = %request.requester,
                    member_count = members.len(),
                    "Accepted member into quorum"
                );

                QuorumMessageResult::Accepted {
                    response: QuorumResponse {
                        ledger_id: request.ledger_id,
                        accepted: true,
                        members,
                        rejection_reason: None,
                    },
                    sync_to: Some(request.requester),
                }
            }
            Err(e) => {
                warn!(error = ?e, "Rejected join request");

                QuorumMessageResult::Rejected {
                    response: QuorumResponse {
                        ledger_id: request.ledger_id,
                        accepted: false,
                        members: vec![],
                        rejection_reason: Some(format!("{:?}", e)),
                    },
                    reason: format!("{:?}", e),
                }
            }
        }
    }

    /// Process a state sync message
    pub fn process_state_sync(
        &self,
        sync: &QuorumStateSync,
        _sender: PublicKey,
    ) -> QuorumMessageResult {
        debug!(
            operator = %sync.ledger_id.operator_id,
            partner = %sync.ledger_id.partner_id,
            from_seq = sync.from_sequence,
            to_seq = sync.to_sequence,
            "Processing state sync"
        );

        // Update member's known state
        // This is handled by the caller who has access to the ledger
        QuorumMessageResult::Processed
    }

    /// Process a vote
    pub fn process_vote(
        &self,
        vote: &QuorumVote,
        sender: PublicKey,
    ) -> QuorumMessageResult {
        debug!(
            sender = %sender,
            operator = %vote.ledger_id.operator_id,
            partner = %vote.ledger_id.partner_id,
            vote = vote.vote,
            sequence = vote.sequence,
            "Processing vote"
        );

        // Verify sender matches voter
        if sender != vote.voter {
            return QuorumMessageResult::Error("Sender doesn't match voter".to_string());
        }

        // Record the vote
        match self.quorum_manager.record_vote(
            &vote.ledger_id,
            vote.voter,
            vote.vote,
            vote.sequence,
            vote.state_hash,
        ) {
            Ok(()) => QuorumMessageResult::Processed,
            Err(e) => QuorumMessageResult::Error(format!("{:?}", e)),
        }
    }

    /// Process a membership change
    pub fn process_membership_change(
        &self,
        ledger_id: &LedgerId,
        member: PublicKey,
        add: bool,
    ) -> QuorumMessageResult {
        if add {
            match self.quorum_manager.add_member(ledger_id, member) {
                Ok(()) => {
                    info!(member = %member, "Added member to quorum");
                    QuorumMessageResult::Processed
                }
                Err(e) => QuorumMessageResult::Error(format!("{:?}", e)),
            }
        } else {
            match self.quorum_manager.remove_member(ledger_id, &member) {
                Ok(()) => {
                    info!(member = %member, "Removed member from quorum");
                    QuorumMessageResult::Processed
                }
                Err(e) => QuorumMessageResult::Error(format!("{:?}", e)),
            }
        }
    }
}

/// Result of processing a collateral message
#[derive(Debug)]
pub enum CollateralMessageResult {
    /// Operation accepted
    Accepted {
        signature: Option<[u8; 64]>,
        new_hash: Option<[u8; 32]>,
        sequence: Option<u64>,
    },
    /// Operation rejected
    Rejected { reason: String },
    /// Message processed, no response needed
    Processed,
    /// Error occurred
    Error(String),
}

/// Process collateral-related messages
///
/// This processor handles collateral partner management, consent flow,
/// and attestations.
pub struct CollateralProcessor {
    /// Our node's public key
    #[allow(dead_code)]
    node_id: PublicKey,
}

impl CollateralProcessor {
    /// Create a new collateral processor
    pub fn new(node_id: PublicKey) -> Self {
        Self { node_id }
    }

    /// Verify consent signature
    pub fn verify_consent_signature(
        &self,
        operator: &PublicKey,
        partner: &PublicKey,
        signature: &[u8; 64],
        signer: &PublicKey,
    ) -> bool {
        use bitcoin::hashes::{Hash, sha256};
        use bitcoin::secp256k1::{Secp256k1, Message, ecdsa::Signature};

        // Reconstruct the signed message
        let mut preimage = Vec::new();
        preimage.extend_from_slice(b"COLLATERAL_CONSENT");
        preimage.extend_from_slice(&operator.serialize());
        preimage.extend_from_slice(&partner.serialize());

        let message_hash = sha256::Hash::hash(&preimage);
        let secp_message = Message::from_digest(message_hash.to_byte_array());

        let secp = Secp256k1::new();
        match Signature::from_compact(signature) {
            Ok(sig) => secp.verify_ecdsa(&secp_message, &sig, signer).is_ok(),
            Err(_) => false,
        }
    }

    /// Check if we should grant consent to be a collateral partner
    pub fn should_grant_consent(&self, operator: &PublicKey) -> bool {
        // Default policy: grant consent if we have a relationship with the operator
        // The actual implementation should check if we have a ledger with this operator
        debug!(operator = %operator, "Checking consent policy");
        true // Placeholder - actual logic depends on ledger state
    }

    /// Create a consent signature
    pub fn create_consent_signature(
        &self,
        operator: &PublicKey,
        partner: &PublicKey,
        secret_key: &bitcoin::secp256k1::SecretKey,
    ) -> [u8; 64] {
        use bitcoin::hashes::{Hash, sha256};
        use bitcoin::secp256k1::{Secp256k1, Message};

        let mut preimage = Vec::new();
        preimage.extend_from_slice(b"COLLATERAL_CONSENT");
        preimage.extend_from_slice(&operator.serialize());
        preimage.extend_from_slice(&partner.serialize());

        let message_hash = sha256::Hash::hash(&preimage);
        let secp_message = Message::from_digest(message_hash.to_byte_array());

        let secp = Secp256k1::new();
        let sig = secp.sign_ecdsa(&secp_message, secret_key);
        sig.serialize_compact()
    }
}

/// Result of processing a recovery message
#[derive(Debug)]
pub enum RecoveryMessageResult {
    /// Vote recorded
    VoteRecorded { threshold_reached: bool },
    /// Claim request received
    ClaimReceived { eligible: bool },
    /// Signature provided for claim
    SignatureProvided { signature: [u8; 64] },
    /// Recovery completed
    Completed { new_operator: PublicKey },
    /// Error occurred
    Error(String),
}

/// Process recovery-related messages
///
/// This processor handles recovery voting, claim requests, and signature
/// collection for the recovery protocol.
pub struct RecoveryProcessor {
    /// Our node's public key
    #[allow(dead_code)]
    node_id: PublicKey,
}

impl RecoveryProcessor {
    /// Create a new recovery processor
    pub fn new(node_id: PublicKey) -> Self {
        Self { node_id }
    }

    /// Calculate voting threshold for recovery
    pub fn calculate_threshold(total_members: usize) -> usize {
        // 2/3 majority required
        (total_members * 2 + 2) / 3
    }

    /// Check if we should vote for recovery
    pub fn should_vote_for_recovery(
        &self,
        operator: &PublicKey,
        last_activity: u64,
        current_time: u64,
        timeout_blocks: u32,
    ) -> bool {
        // Vote for recovery if operator has been inactive beyond timeout
        let timeout_seconds = timeout_blocks as u64 * 600; // ~10 min per block
        let inactive_time = current_time.saturating_sub(last_activity);

        let should_vote = inactive_time > timeout_seconds;

        debug!(
            operator = %operator,
            inactive_secs = inactive_time,
            timeout_secs = timeout_seconds,
            should_vote = should_vote,
            "Recovery vote decision"
        );

        should_vote
    }

    /// Check if a peer is eligible to claim based on votes
    pub fn check_claim_eligibility(
        &self,
        claimer: &PublicKey,
        votes_for_claimer: usize,
        total_voters: usize,
    ) -> bool {
        let threshold = Self::calculate_threshold(total_voters);
        let eligible = votes_for_claimer >= threshold;

        debug!(
            claimer = %claimer,
            votes = votes_for_claimer,
            threshold = threshold,
            eligible = eligible,
            "Claim eligibility check"
        );

        eligible
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    fn test_pubkey(seed: u8) -> PublicKey {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[seed; 32]).unwrap();
        PublicKey::from_secret_key(&secp, &sk)
    }

    #[test]
    fn test_recovery_threshold() {
        assert_eq!(RecoveryProcessor::calculate_threshold(3), 2);
        assert_eq!(RecoveryProcessor::calculate_threshold(4), 3);
        assert_eq!(RecoveryProcessor::calculate_threshold(5), 4);
        assert_eq!(RecoveryProcessor::calculate_threshold(6), 4);
        assert_eq!(RecoveryProcessor::calculate_threshold(10), 7);
    }

    #[test]
    fn test_consent_signature() {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let pubkey = PublicKey::from_secret_key(&secp, &secret);

        let operator = test_pubkey(2);
        let partner = test_pubkey(3);

        let processor = CollateralProcessor::new(pubkey);

        // Create signature
        let sig = processor.create_consent_signature(&operator, &partner, &secret);

        // Verify signature
        assert!(processor.verify_consent_signature(&operator, &partner, &sig, &pubkey));

        // Wrong signer should fail
        let wrong_pubkey = test_pubkey(4);
        assert!(!processor.verify_consent_signature(&operator, &partner, &sig, &wrong_pubkey));
    }
}
