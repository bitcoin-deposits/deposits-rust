// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! # Quorum Management
//!
//! This module handles peer quorum formation, state synchronization, and voting
//! for ledger conformance in the Bitcoin Deposits protocol.
//!
//! ## Overview
//!
//! A quorum is a set of peers that maintain synchronized copies of a ledger and
//! can vote on whether the ledger is conforming to protocol rules. The quorum
//! provides:
//!
//! - **Peer Discovery**: Nodes can request to join a quorum for a specific ledger
//! - **State Synchronization**: New members receive full state from existing members
//! - **Conformance Voting**: Members vote on whether the ledger state is valid
//!
//! ## Quorum Lifecycle
//!
//! 1. **Formation**: Operator and partner form the initial quorum (2 members)
//! 2. **Expansion**: Other nodes can request to join as auditors
//! 3. **Synchronization**: New members receive historical signed updates
//! 4. **Voting**: Members periodically vote on ledger conformance
//! 5. **Eviction**: Non-responsive or malicious members can be removed

use bitcoin::secp256k1::PublicKey;
use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

use crate::error::DepositsError;
use crate::types::{QuorumJoinRequestMsg, QuorumJoinResponseMsg, QuorumVoteMsg};

/// Identifies a specific ledger by its operator-partner pair
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LedgerId {
    pub operator_id: PublicKey,
    pub partner_id: PublicKey,
}

impl LedgerId {
    pub fn new(operator_id: PublicKey, partner_id: PublicKey) -> Self {
        Self { operator_id, partner_id }
    }
}

/// Status of a quorum member
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemberStatus {
    /// Member is active and synchronized
    Active,
    /// Member is joining and syncing state
    Syncing,
    /// Member is temporarily offline
    Offline,
    /// Member has been evicted
    Evicted,
}

/// Information about a quorum member
#[derive(Clone, Debug)]
pub struct QuorumMember {
    /// Member's node public key
    pub pubkey: PublicKey,
    /// Current status
    pub status: MemberStatus,
    /// Last known sequence number
    pub last_sequence: u64,
    /// Last known state hash
    pub last_state_hash: [u8; 32],
    /// Timestamp of last activity
    pub last_activity: u64,
}

/// A vote in a conformance round
#[derive(Clone, Debug)]
pub struct ConformanceVote {
    /// The voter's public key
    pub voter: PublicKey,
    /// Whether they voted conforming (true) or non-conforming (false)
    pub vote: bool,
    /// The sequence number they voted on
    pub sequence: u64,
    /// The state hash they have
    pub state_hash: [u8; 32],
    /// Signature over the vote
    pub signature: [u8; 64],
}

/// Result of a conformance vote round
#[derive(Clone, Debug)]
pub struct VoteResult {
    /// Vote round ID
    pub round_id: [u8; 32],
    /// Total votes received
    pub total_votes: usize,
    /// Votes for conforming
    pub conforming_votes: usize,
    /// Votes for non-conforming
    pub non_conforming_votes: usize,
    /// Whether the vote passed (met threshold)
    pub passed: bool,
    /// Individual votes received
    pub votes: Vec<ConformanceVote>,
}

/// Configuration for a quorum
#[derive(Clone, Debug)]
pub struct QuorumConfig {
    /// Minimum threshold for voting (number of votes needed)
    pub threshold: u16,
    /// Maximum number of members allowed
    pub max_members: usize,
    /// Timeout for vote rounds in seconds
    pub vote_timeout_secs: u64,
    /// How often to check for offline members (seconds)
    pub health_check_interval_secs: u64,
}

impl Default for QuorumConfig {
    fn default() -> Self {
        Self {
            threshold: 2,          // At least 2 votes needed
            max_members: 10,       // Maximum 10 quorum members
            vote_timeout_secs: 60, // 1 minute to collect votes
            health_check_interval_secs: 300, // Check health every 5 minutes
        }
    }
}

/// State of a quorum for a specific ledger
#[derive(Debug)]
pub struct QuorumState {
    /// The ledger this quorum is for
    pub ledger_id: LedgerId,
    /// Current members
    pub members: HashMap<PublicKey, QuorumMember>,
    /// Configuration
    pub config: QuorumConfig,
    /// Pending vote rounds
    pub pending_votes: HashMap<[u8; 32], VoteResult>,
    /// Pending join requests
    pub pending_joins: HashSet<PublicKey>,
}

impl QuorumState {
    /// Create a new quorum for a ledger with operator and partner as initial members
    pub fn new(operator_id: PublicKey, partner_id: PublicKey) -> Self {
        let ledger_id = LedgerId::new(operator_id, partner_id);
        let mut members = HashMap::new();

        // Add operator as initial member
        members.insert(operator_id, QuorumMember {
            pubkey: operator_id,
            status: MemberStatus::Active,
            last_sequence: 0,
            last_state_hash: [0u8; 32],
            last_activity: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        });

        // Add partner as initial member
        members.insert(partner_id, QuorumMember {
            pubkey: partner_id,
            status: MemberStatus::Active,
            last_sequence: 0,
            last_state_hash: [0u8; 32],
            last_activity: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        });

        Self {
            ledger_id,
            members,
            config: QuorumConfig::default(),
            pending_votes: HashMap::new(),
            pending_joins: HashSet::new(),
        }
    }

    /// Get the current member count
    pub fn member_count(&self) -> usize {
        self.members.len()
    }

    /// Get active member count
    pub fn active_member_count(&self) -> usize {
        self.members.values()
            .filter(|m| m.status == MemberStatus::Active)
            .count()
    }

    /// Check if a pubkey is a member
    pub fn is_member(&self, pubkey: &PublicKey) -> bool {
        self.members.contains_key(pubkey)
    }

    /// Get list of all member pubkeys
    pub fn member_pubkeys(&self) -> Vec<PublicKey> {
        self.members.keys().copied().collect()
    }
}

/// Manages quorums for multiple ledgers
pub struct QuorumManager {
    /// Our node's public key
    our_node_id: PublicKey,
    /// Quorums we're participating in
    quorums: RwLock<HashMap<LedgerId, QuorumState>>,
}

impl QuorumManager {
    /// Create a new quorum manager
    pub fn new(our_node_id: PublicKey) -> Self {
        Self {
            our_node_id,
            quorums: RwLock::new(HashMap::new()),
        }
    }

    /// Create a new quorum for a ledger (called by operator/partner)
    pub fn create_quorum(
        &self,
        operator_id: PublicKey,
        partner_id: PublicKey,
    ) -> Result<(), DepositsError> {
        let ledger_id = LedgerId::new(operator_id, partner_id);
        let quorum = QuorumState::new(operator_id, partner_id);

        let mut quorums = self.quorums.write().unwrap();
        if quorums.contains_key(&ledger_id) {
            return Err(DepositsError::InvalidState(
                "Quorum already exists for this ledger".to_string()
            ));
        }
        quorums.insert(ledger_id, quorum);
        Ok(())
    }

    /// Handle a join request from another node
    pub fn handle_join_request(
        &self,
        msg: &QuorumJoinRequestMsg,
    ) -> Result<QuorumJoinResponseMsg, DepositsError> {
        let ledger_id = LedgerId::new(msg.operator_id, msg.partner_id);

        let mut quorums = self.quorums.write().unwrap();
        let quorum = quorums.get_mut(&ledger_id).ok_or_else(|| {
            DepositsError::InvalidState("No quorum exists for this ledger".to_string())
        })?;

        // Check if already a member
        if quorum.is_member(&msg.requester_pubkey) {
            return Ok(QuorumJoinResponseMsg {
                accepted: false,
                members: quorum.member_pubkeys(),
                threshold: quorum.config.threshold,
                last_sequence: 0,
                current_state_hash: [0u8; 32],
                rejection_reason: Some("Already a member".to_string()),
            });
        }

        // Check if quorum is full
        if quorum.member_count() >= quorum.config.max_members {
            return Ok(QuorumJoinResponseMsg {
                accepted: false,
                members: quorum.member_pubkeys(),
                threshold: quorum.config.threshold,
                last_sequence: 0,
                current_state_hash: [0u8; 32],
                rejection_reason: Some("Quorum is full".to_string()),
            });
        }

        // Accept the join request
        quorum.pending_joins.insert(msg.requester_pubkey);
        quorum.members.insert(msg.requester_pubkey, QuorumMember {
            pubkey: msg.requester_pubkey,
            status: MemberStatus::Syncing,
            last_sequence: 0,
            last_state_hash: [0u8; 32],
            last_activity: msg.timestamp,
        });

        Ok(QuorumJoinResponseMsg {
            accepted: true,
            members: quorum.member_pubkeys(),
            threshold: quorum.config.threshold,
            last_sequence: 0, // TODO: Get from ledger
            current_state_hash: [0u8; 32], // TODO: Get from ledger
            rejection_reason: None,
        })
    }

    /// Handle a vote submission
    pub fn handle_vote(
        &self,
        msg: &QuorumVoteMsg,
        ledger_id: &LedgerId,
    ) -> Result<(), DepositsError> {
        let mut quorums = self.quorums.write().unwrap();
        let quorum = quorums.get_mut(ledger_id).ok_or_else(|| {
            DepositsError::InvalidState("No quorum exists for this ledger".to_string())
        })?;

        // Verify voter is a member
        if !quorum.is_member(&msg.voter_pubkey) {
            return Err(DepositsError::InvalidState(
                "Voter is not a quorum member".to_string()
            ));
        }

        // Get or create vote result for this round
        let result = quorum.pending_votes
            .entry(msg.vote_round_id)
            .or_insert_with(|| VoteResult {
                round_id: msg.vote_round_id,
                total_votes: 0,
                conforming_votes: 0,
                non_conforming_votes: 0,
                passed: false,
                votes: Vec::new(),
            });

        // Record the vote
        result.total_votes += 1;
        if msg.vote {
            result.conforming_votes += 1;
        } else {
            result.non_conforming_votes += 1;
        }

        result.votes.push(ConformanceVote {
            voter: msg.voter_pubkey,
            vote: msg.vote,
            sequence: msg.voter_sequence,
            state_hash: msg.voter_state_hash,
            signature: msg.signature,
        });

        // Check if threshold is met
        if result.conforming_votes as u16 >= quorum.config.threshold {
            result.passed = true;
        }

        Ok(())
    }

    /// Get quorum state for a ledger
    pub fn get_quorum(&self, ledger_id: &LedgerId) -> Option<Vec<PublicKey>> {
        let quorums = self.quorums.read().unwrap();
        quorums.get(ledger_id).map(|q| q.member_pubkeys())
    }

    /// Add a member directly to the quorum (used when collateral partners are added)
    /// Unlike handle_join_request, this adds the member as Active immediately
    pub fn add_member(
        &self,
        ledger_id: &LedgerId,
        member_pubkey: PublicKey,
    ) -> Result<(), DepositsError> {
        let mut quorums = self.quorums.write().unwrap();
        let quorum = quorums.get_mut(ledger_id).ok_or_else(|| {
            DepositsError::InvalidState("No quorum exists for this ledger".to_string())
        })?;

        // Check if already a member
        if quorum.is_member(&member_pubkey) {
            return Ok(()); // Already a member, nothing to do
        }

        // Check if quorum is full
        if quorum.member_count() >= quorum.config.max_members {
            return Err(DepositsError::InvalidState(
                "Quorum is full".to_string()
            ));
        }

        // Add as active member (collateral partners are trusted, no syncing needed)
        quorum.members.insert(member_pubkey, QuorumMember {
            pubkey: member_pubkey,
            status: MemberStatus::Active,
            last_sequence: 0,
            last_state_hash: [0u8; 32],
            last_activity: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        });

        Ok(())
    }

    /// Remove a member from the quorum (used when collateral partners are removed)
    pub fn remove_member(
        &self,
        ledger_id: &LedgerId,
        member_pubkey: &PublicKey,
    ) -> Result<(), DepositsError> {
        let mut quorums = self.quorums.write().unwrap();
        let quorum = quorums.get_mut(ledger_id).ok_or_else(|| {
            DepositsError::InvalidState("No quorum exists for this ledger".to_string())
        })?;

        // Don't allow removing operator or partner (they're always members)
        if *member_pubkey == quorum.ledger_id.operator_id || *member_pubkey == quorum.ledger_id.partner_id {
            return Err(DepositsError::InvalidState(
                "Cannot remove operator or partner from quorum".to_string()
            ));
        }

        // Remove the member
        quorum.members.remove(member_pubkey);
        quorum.pending_joins.remove(member_pubkey);

        Ok(())
    }

    /// Record a vote directly (used by message processor)
    pub fn record_vote(
        &self,
        ledger_id: &LedgerId,
        voter: PublicKey,
        vote: bool,
        sequence: u64,
        state_hash: [u8; 32],
    ) -> Result<(), DepositsError> {
        let mut quorums = self.quorums.write().unwrap();
        let quorum = quorums.get_mut(ledger_id).ok_or_else(|| {
            DepositsError::InvalidState("No quorum exists for this ledger".to_string())
        })?;

        // Verify voter is a member
        if !quorum.is_member(&voter) {
            return Err(DepositsError::InvalidState(
                "Voter is not a quorum member".to_string()
            ));
        }

        // Create a vote round ID based on sequence
        let mut round_id = [0u8; 32];
        round_id[0..8].copy_from_slice(&sequence.to_be_bytes());

        // Get or create vote result for this round
        let result = quorum.pending_votes
            .entry(round_id)
            .or_insert_with(|| VoteResult {
                round_id,
                total_votes: 0,
                conforming_votes: 0,
                non_conforming_votes: 0,
                passed: false,
                votes: Vec::new(),
            });

        // Record the vote
        result.total_votes += 1;
        if vote {
            result.conforming_votes += 1;
        } else {
            result.non_conforming_votes += 1;
        }

        result.votes.push(ConformanceVote {
            voter,
            vote,
            sequence,
            state_hash,
            signature: [0u8; 64], // Signature verified elsewhere
        });

        // Check if threshold is met
        if result.conforming_votes as u16 >= quorum.config.threshold {
            result.passed = true;
        }

        Ok(())
    }

    /// List all members of a quorum
    pub fn list_members(&self, ledger_id: &LedgerId) -> Result<Vec<QuorumMember>, DepositsError> {
        let quorums = self.quorums.read().unwrap();
        let quorum = quorums.get(ledger_id).ok_or_else(|| {
            DepositsError::InvalidState("No quorum exists for this ledger".to_string())
        })?;
        Ok(quorum.members.values().cloned().collect())
    }

    /// Update member's last known state
    pub fn update_member_state(
        &self,
        ledger_id: &LedgerId,
        member_pubkey: &PublicKey,
        sequence: u64,
        state_hash: [u8; 32],
    ) -> Result<(), DepositsError> {
        let mut quorums = self.quorums.write().unwrap();
        let quorum = quorums.get_mut(ledger_id).ok_or_else(|| {
            DepositsError::InvalidState("No quorum exists for this ledger".to_string())
        })?;

        if let Some(member) = quorum.members.get_mut(member_pubkey) {
            member.last_sequence = sequence;
            member.last_state_hash = state_hash;
            member.last_activity = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            // If member was syncing and now has state, mark as active
            if member.status == MemberStatus::Syncing && sequence > 0 {
                member.status = MemberStatus::Active;
                quorum.pending_joins.remove(member_pubkey);
            }

            Ok(())
        } else {
            Err(DepositsError::InvalidState(
                "Member not found in quorum".to_string()
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    fn generate_test_pubkey(seed: u8) -> PublicKey {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[seed; 32]).unwrap();
        PublicKey::from_secret_key(&secp, &secret)
    }

    #[test]
    fn test_quorum_creation() {
        let operator = generate_test_pubkey(1);
        let partner = generate_test_pubkey(2);

        let manager = QuorumManager::new(operator);
        manager.create_quorum(operator, partner).unwrap();

        let ledger_id = LedgerId::new(operator, partner);
        let members = manager.get_quorum(&ledger_id).unwrap();

        assert_eq!(members.len(), 2);
        assert!(members.contains(&operator));
        assert!(members.contains(&partner));
    }

    #[test]
    fn test_join_request() {
        let operator = generate_test_pubkey(1);
        let partner = generate_test_pubkey(2);
        let auditor = generate_test_pubkey(3);

        let manager = QuorumManager::new(operator);
        manager.create_quorum(operator, partner).unwrap();

        let join_request = QuorumJoinRequestMsg {
            requester_pubkey: auditor,
            operator_id: operator,
            partner_id: partner,
            protocol_version: 1,
            timestamp: 12345,
            signature: [0u8; 64],
        };

        let response = manager.handle_join_request(&join_request).unwrap();
        assert!(response.accepted);
        assert_eq!(response.members.len(), 3);
        assert!(response.members.contains(&auditor));
    }

    #[test]
    fn test_duplicate_join_rejected() {
        let operator = generate_test_pubkey(1);
        let partner = generate_test_pubkey(2);

        let manager = QuorumManager::new(operator);
        manager.create_quorum(operator, partner).unwrap();

        // Try to join as operator (already a member)
        let join_request = QuorumJoinRequestMsg {
            requester_pubkey: operator,
            operator_id: operator,
            partner_id: partner,
            protocol_version: 1,
            timestamp: 12345,
            signature: [0u8; 64],
        };

        let response = manager.handle_join_request(&join_request).unwrap();
        assert!(!response.accepted);
        assert_eq!(response.rejection_reason, Some("Already a member".to_string()));
    }

    #[test]
    fn test_multiple_auditors_join() {
        let operator = generate_test_pubkey(1);
        let partner = generate_test_pubkey(2);
        let auditor1 = generate_test_pubkey(3);
        let auditor2 = generate_test_pubkey(4);
        let auditor3 = generate_test_pubkey(5);

        let manager = QuorumManager::new(operator);
        manager.create_quorum(operator, partner).unwrap();

        // First auditor joins
        let join_request1 = QuorumJoinRequestMsg {
            requester_pubkey: auditor1,
            operator_id: operator,
            partner_id: partner,
            protocol_version: 1,
            timestamp: 12345,
            signature: [0u8; 64],
        };
        let response1 = manager.handle_join_request(&join_request1).unwrap();
        assert!(response1.accepted);
        assert_eq!(response1.members.len(), 3);

        // Second auditor joins
        let join_request2 = QuorumJoinRequestMsg {
            requester_pubkey: auditor2,
            operator_id: operator,
            partner_id: partner,
            protocol_version: 1,
            timestamp: 12346,
            signature: [0u8; 64],
        };
        let response2 = manager.handle_join_request(&join_request2).unwrap();
        assert!(response2.accepted);
        assert_eq!(response2.members.len(), 4);

        // Third auditor joins
        let join_request3 = QuorumJoinRequestMsg {
            requester_pubkey: auditor3,
            operator_id: operator,
            partner_id: partner,
            protocol_version: 1,
            timestamp: 12347,
            signature: [0u8; 64],
        };
        let response3 = manager.handle_join_request(&join_request3).unwrap();
        assert!(response3.accepted);
        assert_eq!(response3.members.len(), 5);

        // Verify all members are present
        let ledger_id = LedgerId::new(operator, partner);
        let members = manager.get_quorum(&ledger_id).unwrap();
        assert!(members.contains(&operator));
        assert!(members.contains(&partner));
        assert!(members.contains(&auditor1));
        assert!(members.contains(&auditor2));
        assert!(members.contains(&auditor3));
    }

    #[test]
    fn test_member_state_update() {
        let operator = generate_test_pubkey(1);
        let partner = generate_test_pubkey(2);
        let auditor = generate_test_pubkey(3);

        let manager = QuorumManager::new(operator);
        manager.create_quorum(operator, partner).unwrap();

        // Auditor joins
        let join_request = QuorumJoinRequestMsg {
            requester_pubkey: auditor,
            operator_id: operator,
            partner_id: partner,
            protocol_version: 1,
            timestamp: 12345,
            signature: [0u8; 64],
        };
        manager.handle_join_request(&join_request).unwrap();

        // Update auditor's state after syncing
        let ledger_id = LedgerId::new(operator, partner);
        let state_hash = [42u8; 32];
        let result = manager.update_member_state(&ledger_id, &auditor, 100, state_hash);
        assert!(result.is_ok());

        // Verify the quorum still contains the member
        let members = manager.get_quorum(&ledger_id).unwrap();
        assert!(members.contains(&auditor));
    }

    #[test]
    fn test_voting() {
        let operator = generate_test_pubkey(1);
        let partner = generate_test_pubkey(2);
        let auditor = generate_test_pubkey(3);

        let manager = QuorumManager::new(operator);
        manager.create_quorum(operator, partner).unwrap();

        // Auditor joins
        let join_request = QuorumJoinRequestMsg {
            requester_pubkey: auditor,
            operator_id: operator,
            partner_id: partner,
            protocol_version: 1,
            timestamp: 12345,
            signature: [0u8; 64],
        };
        manager.handle_join_request(&join_request).unwrap();

        // Cast votes
        let ledger_id = LedgerId::new(operator, partner);
        let vote_round_id = [1u8; 32];

        // Operator votes conforming
        let vote1 = QuorumVoteMsg {
            vote_round_id,
            voter_pubkey: operator,
            vote: true,
            voter_sequence: 100,
            voter_state_hash: [42u8; 32],
            evidence: None,
            signature: [0u8; 64],
            spend_signature: None,
        };
        manager.handle_vote(&vote1, &ledger_id).unwrap();

        // Partner votes conforming
        let vote2 = QuorumVoteMsg {
            vote_round_id,
            voter_pubkey: partner,
            vote: true,
            voter_sequence: 100,
            voter_state_hash: [42u8; 32],
            evidence: None,
            signature: [0u8; 64],
            spend_signature: None,
        };
        manager.handle_vote(&vote2, &ledger_id).unwrap();

        // Auditor votes conforming
        let vote3 = QuorumVoteMsg {
            vote_round_id,
            voter_pubkey: auditor,
            vote: true,
            voter_sequence: 100,
            voter_state_hash: [42u8; 32],
            evidence: None,
            signature: [0u8; 64],
            spend_signature: None,
        };
        manager.handle_vote(&vote3, &ledger_id).unwrap();
    }

    #[test]
    fn test_vote_from_non_member_rejected() {
        let operator = generate_test_pubkey(1);
        let partner = generate_test_pubkey(2);
        let non_member = generate_test_pubkey(99);

        let manager = QuorumManager::new(operator);
        manager.create_quorum(operator, partner).unwrap();

        let ledger_id = LedgerId::new(operator, partner);
        let vote = QuorumVoteMsg {
            vote_round_id: [1u8; 32],
            voter_pubkey: non_member,
            vote: true,
            voter_sequence: 100,
            voter_state_hash: [42u8; 32],
            evidence: None,
            signature: [0u8; 64],
            spend_signature: None,
        };

        let result = manager.handle_vote(&vote, &ledger_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_ledger_id_uniqueness() {
        let operator = generate_test_pubkey(1);
        let partner1 = generate_test_pubkey(2);
        let partner2 = generate_test_pubkey(3);

        let ledger_id1 = LedgerId::new(operator, partner1);
        let ledger_id2 = LedgerId::new(operator, partner2);
        let ledger_id1_again = LedgerId::new(operator, partner1);

        // Different partners = different ledger IDs
        assert_ne!(ledger_id1, ledger_id2);
        // Same operator+partner = same ledger ID
        assert_eq!(ledger_id1, ledger_id1_again);
    }

    #[test]
    fn test_quorum_full_rejection() {
        let operator = generate_test_pubkey(1);
        let partner = generate_test_pubkey(2);

        let manager = QuorumManager::new(operator);
        manager.create_quorum(operator, partner).unwrap();

        // Fill up the quorum (default max is 10, we have 2 already)
        for i in 3..=10 {
            let auditor = generate_test_pubkey(i);
            let join_request = QuorumJoinRequestMsg {
                requester_pubkey: auditor,
                operator_id: operator,
                partner_id: partner,
                protocol_version: 1,
                timestamp: 12340 + i as u64,
                signature: [0u8; 64],
            };
            let response = manager.handle_join_request(&join_request).unwrap();
            assert!(response.accepted, "Member {} should be accepted", i);
        }

        // Now try to add one more - should be rejected
        let extra_auditor = generate_test_pubkey(11);
        let join_request = QuorumJoinRequestMsg {
            requester_pubkey: extra_auditor,
            operator_id: operator,
            partner_id: partner,
            protocol_version: 1,
            timestamp: 12351,
            signature: [0u8; 64],
        };
        let response = manager.handle_join_request(&join_request).unwrap();
        assert!(!response.accepted);
        assert_eq!(response.rejection_reason, Some("Quorum is full".to_string()));
    }

    #[test]
    fn test_update_nonexistent_member_fails() {
        let operator = generate_test_pubkey(1);
        let partner = generate_test_pubkey(2);
        let non_member = generate_test_pubkey(99);

        let manager = QuorumManager::new(operator);
        manager.create_quorum(operator, partner).unwrap();

        let ledger_id = LedgerId::new(operator, partner);
        let result = manager.update_member_state(&ledger_id, &non_member, 100, [42u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_nonexistent_quorum() {
        let operator = generate_test_pubkey(1);
        let partner = generate_test_pubkey(2);

        let manager = QuorumManager::new(operator);
        // Don't create the quorum

        let ledger_id = LedgerId::new(operator, partner);
        let result = manager.get_quorum(&ledger_id);
        assert!(result.is_none());
    }

    // =========================================================================
    // Tests for add_member and remove_member (collateral partner sync)
    // =========================================================================

    #[test]
    fn test_add_member_directly() {
        let operator = generate_test_pubkey(1);
        let partner = generate_test_pubkey(2);
        let collateral_partner = generate_test_pubkey(3);

        let manager = QuorumManager::new(operator);
        manager.create_quorum(operator, partner).unwrap();

        let ledger_id = LedgerId::new(operator, partner);

        // Initially only operator and partner
        let members = manager.get_quorum(&ledger_id).unwrap();
        assert_eq!(members.len(), 2);
        assert!(!members.contains(&collateral_partner));

        // Add collateral partner directly
        let result = manager.add_member(&ledger_id, collateral_partner);
        assert!(result.is_ok());

        // Now should have 3 members
        let members = manager.get_quorum(&ledger_id).unwrap();
        assert_eq!(members.len(), 3);
        assert!(members.contains(&collateral_partner));
    }

    #[test]
    fn test_add_member_idempotent() {
        let operator = generate_test_pubkey(1);
        let partner = generate_test_pubkey(2);
        let collateral_partner = generate_test_pubkey(3);

        let manager = QuorumManager::new(operator);
        manager.create_quorum(operator, partner).unwrap();

        let ledger_id = LedgerId::new(operator, partner);

        // Add same member twice - should be idempotent
        manager.add_member(&ledger_id, collateral_partner).unwrap();
        manager.add_member(&ledger_id, collateral_partner).unwrap();

        // Should still only have 3 members
        let members = manager.get_quorum(&ledger_id).unwrap();
        assert_eq!(members.len(), 3);
    }

    #[test]
    fn test_add_member_to_nonexistent_quorum_fails() {
        let operator = generate_test_pubkey(1);
        let partner = generate_test_pubkey(2);
        let collateral_partner = generate_test_pubkey(3);

        let manager = QuorumManager::new(operator);
        // Don't create the quorum

        let ledger_id = LedgerId::new(operator, partner);
        let result = manager.add_member(&ledger_id, collateral_partner);
        assert!(result.is_err());
    }

    #[test]
    fn test_remove_member_directly() {
        let operator = generate_test_pubkey(1);
        let partner = generate_test_pubkey(2);
        let collateral_partner = generate_test_pubkey(3);

        let manager = QuorumManager::new(operator);
        manager.create_quorum(operator, partner).unwrap();

        let ledger_id = LedgerId::new(operator, partner);

        // Add collateral partner
        manager.add_member(&ledger_id, collateral_partner).unwrap();
        assert_eq!(manager.get_quorum(&ledger_id).unwrap().len(), 3);

        // Remove collateral partner
        let result = manager.remove_member(&ledger_id, &collateral_partner);
        assert!(result.is_ok());

        // Should be back to 2 members
        let members = manager.get_quorum(&ledger_id).unwrap();
        assert_eq!(members.len(), 2);
        assert!(!members.contains(&collateral_partner));
    }

    #[test]
    fn test_remove_member_idempotent() {
        let operator = generate_test_pubkey(1);
        let partner = generate_test_pubkey(2);
        let collateral_partner = generate_test_pubkey(3);

        let manager = QuorumManager::new(operator);
        manager.create_quorum(operator, partner).unwrap();

        let ledger_id = LedgerId::new(operator, partner);

        // Add then remove twice - second remove should be no-op
        manager.add_member(&ledger_id, collateral_partner).unwrap();
        manager.remove_member(&ledger_id, &collateral_partner).unwrap();
        manager.remove_member(&ledger_id, &collateral_partner).unwrap(); // Should succeed (no-op)

        let members = manager.get_quorum(&ledger_id).unwrap();
        assert_eq!(members.len(), 2);
    }

    #[test]
    fn test_cannot_remove_operator() {
        let operator = generate_test_pubkey(1);
        let partner = generate_test_pubkey(2);

        let manager = QuorumManager::new(operator);
        manager.create_quorum(operator, partner).unwrap();

        let ledger_id = LedgerId::new(operator, partner);

        // Try to remove operator - should fail
        let result = manager.remove_member(&ledger_id, &operator);
        assert!(result.is_err());

        // Operator should still be a member
        let members = manager.get_quorum(&ledger_id).unwrap();
        assert!(members.contains(&operator));
    }

    #[test]
    fn test_cannot_remove_partner() {
        let operator = generate_test_pubkey(1);
        let partner = generate_test_pubkey(2);

        let manager = QuorumManager::new(operator);
        manager.create_quorum(operator, partner).unwrap();

        let ledger_id = LedgerId::new(operator, partner);

        // Try to remove partner - should fail
        let result = manager.remove_member(&ledger_id, &partner);
        assert!(result.is_err());

        // Partner should still be a member
        let members = manager.get_quorum(&ledger_id).unwrap();
        assert!(members.contains(&partner));
    }

    #[test]
    fn test_add_multiple_collateral_partners() {
        let operator = generate_test_pubkey(1);
        let partner = generate_test_pubkey(2);
        let collateral1 = generate_test_pubkey(3);
        let collateral2 = generate_test_pubkey(4);
        let collateral3 = generate_test_pubkey(5);

        let manager = QuorumManager::new(operator);
        manager.create_quorum(operator, partner).unwrap();

        let ledger_id = LedgerId::new(operator, partner);

        // Add multiple collateral partners
        manager.add_member(&ledger_id, collateral1).unwrap();
        manager.add_member(&ledger_id, collateral2).unwrap();
        manager.add_member(&ledger_id, collateral3).unwrap();

        let members = manager.get_quorum(&ledger_id).unwrap();
        assert_eq!(members.len(), 5); // operator + partner + 3 collateral
        assert!(members.contains(&collateral1));
        assert!(members.contains(&collateral2));
        assert!(members.contains(&collateral3));
    }

    #[test]
    fn test_add_member_respects_max_members() {
        let operator = generate_test_pubkey(1);
        let partner = generate_test_pubkey(2);

        let manager = QuorumManager::new(operator);
        manager.create_quorum(operator, partner).unwrap();

        let ledger_id = LedgerId::new(operator, partner);

        // Fill up the quorum (default max is 10, we have 2)
        for i in 3..=10 {
            let member = generate_test_pubkey(i);
            let result = manager.add_member(&ledger_id, member);
            assert!(result.is_ok(), "Member {} should be added", i);
        }

        // Try to add one more - should fail
        let extra = generate_test_pubkey(11);
        let result = manager.add_member(&ledger_id, extra);
        assert!(result.is_err());

        // Should still have 10 members
        let members = manager.get_quorum(&ledger_id).unwrap();
        assert_eq!(members.len(), 10);
    }

    #[test]
    fn test_member_added_as_active() {
        let operator = generate_test_pubkey(1);
        let partner = generate_test_pubkey(2);
        let collateral = generate_test_pubkey(3);

        let manager = QuorumManager::new(operator);
        manager.create_quorum(operator, partner).unwrap();

        let ledger_id = LedgerId::new(operator, partner);
        manager.add_member(&ledger_id, collateral).unwrap();

        // Verify member is active by checking we can update their state
        // (only active members can have state updated successfully)
        let result = manager.update_member_state(&ledger_id, &collateral, 100, [42u8; 32]);
        assert!(result.is_ok());
    }
}
