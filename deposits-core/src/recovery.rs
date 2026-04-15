//! # Ledger Recovery After Force Close
//!
//! This module handles the recovery process when a channel is force-closed.
//! Force close can happen for any reason (node offline, HTLC timeout, network
//! issues, etc.) - it does NOT imply operator dishonesty. The evaluation
//! phase objectively determines compliance.
//!
//! ## Key Principle
//!
//! Force close is a trigger for evaluation, not an accusation. Most force
//! closes are legitimate technical events. The cryptographic evaluation
//! ensures compliant operators get their funds back, while non-compliant
//! operators have deposits reassigned to protect depositors.
//!
//! ## Recovery Flow
//!
//! 1. **Force Close Detection**: Either party force-closes the channel for
//!    any reason. Reserves output goes on-chain with final ledger hash.
//!
//! 2. **Peer Synchronization**: Other channel partners (acting as lighthouses)
//!    detect the close and sync their audit records to the on-chain hash.
//!
//! 3. **Conformance Evaluation**: Each partner cryptographically validates the
//!    operator's update chain against protocol rules. This is objective
//!    verification (did updates match the rules?), not subjective judgment.
//!
//! 4. **Vote Submission**: Partners submit RecoveryVotes with:
//!    - Conformance determination (compliant/non-compliant)
//!    - Optional substitute nomination (for non-compliant cases)
//!    - Signature over their evaluation
//!
//! 5. **Outcome Determination**:
//!    - **Compliant**: Partners return full funds to operator - handles
//!      legitimate technical failures without punishment
//!    - **Non-Compliant**: Proceed to deterministic selection for reassignment

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::schnorr::Signature as SchnorrSignature;
use bitcoin::secp256k1::{Keypair, Message, PublicKey, Secp256k1};
use std::collections::HashMap;

/// Block intervals for time-based degradation
pub const ENTROPY_DELAY_BLOCKS: u32 = 6;
pub const DAY_BLOCKS: u32 = 144;
pub const WEEK_BLOCKS: u32 = 1008;
pub const TWO_WEEKS_BLOCKS: u32 = 2016;
pub const THREE_WEEKS_BLOCKS: u32 = 3024;

// ============================================================================
// Pure Validation Functions
// ============================================================================

/// Validate that a preimage matches a payment hash.
///
/// This is a cryptographic check used in recovery fraud proofs to verify
/// that a claimed payment actually occurred.
///
/// # Arguments
/// * `preimage` - The 32-byte preimage to verify
/// * `payment_hash` - The expected SHA256 hash of the preimage
///
/// # Returns
/// * `Ok(())` if the preimage hashes to the payment_hash
/// * `Err(String)` if the preimage doesn't match
pub fn validate_preimage(preimage: &[u8; 32], payment_hash: &[u8; 32]) -> Result<(), String> {
    let computed_hash = sha256::Hash::hash(preimage);
    if computed_hash.as_byte_array() != payment_hash {
        return Err(format!(
            "Invalid preimage: computed hash {} does not match payment hash {}",
            hex::encode(computed_hash.as_byte_array()),
            hex::encode(payment_hash)
        ));
    }
    Ok(())
}

/// State of a ledger recovery process
#[derive(Clone, Debug)]
pub enum RecoveryPhase {
    /// Waiting for entropy block to be mined (force_close + 6)
    WaitingForEntropy {
        force_close_block: u32,
        force_close_txid: [u8; 32],
        on_chain_ledger_hash: [u8; 32],
    },

    /// Partners are evaluating conformance and submitting votes
    Evaluating {
        force_close_block: u32,
        entropy_block_hash: [u8; 32],
        on_chain_ledger_hash: [u8; 32],
        votes: HashMap<PublicKey, RecoveryVote>,
    },

    /// Operator deemed conforming - awaiting cooperative return
    ReturningToOperator {
        operator: PublicKey,
        confirmations_needed: usize,
        confirmations_received: Vec<PublicKey>,
    },

    /// Operator deemed non-conforming - deterministic selection active
    NonCompliantRecovery {
        force_close_block: u32,
        entropy: [u8; 32],
        recovery_pool: RecoveryPool,
        current_eligibility: ClaimEligibility,
    },

    /// Recovery complete - deposits transferred to new operator (or returned)
    Complete { outcome: RecoveryOutcome },
}

/// Final outcome of a recovery process
#[derive(Clone, Debug)]
pub enum RecoveryOutcome {
    /// Funds returned to original operator (was compliant)
    ReturnedToOperator { operator: PublicKey },
    /// Deposits reassigned to a new operator
    ReassignedTo {
        new_operator: PublicKey,
        reason: ReassignmentReason,
    },
    /// Recovery failed (shouldn't happen in normal operation)
    Failed { reason: String },
}

/// Why deposits were reassigned
#[derive(Clone, Debug)]
pub enum ReassignmentReason {
    /// Selected by deterministic pseudorandom process (Day 1)
    DeterministicSelection,
    /// Claimed by 3-partner quorum (Week 1)
    ThreePartnerQuorum { claimants: [PublicKey; 3] },
    /// Claimed by any single partner (Week 2)
    SinglePartnerClaim,
    /// Community fallback (Week 3+)
    CommunityFallback,
}

/// A partner's vote in the recovery process
#[derive(Clone, Debug)]
pub struct RecoveryVote {
    /// The voting partner's pubkey
    pub voter: PublicKey,
    /// Whether they determined the operator was conforming
    pub is_conforming: bool,
    /// The ledger hash they validated against
    pub validated_hash: [u8; 32],
    /// The sequence number they validated up to
    pub validated_sequence: u64,
    /// Optional substitute nomination (for non-conforming vote)
    pub substitute_nomination: Option<PublicKey>,
    /// Whether this partner discovered the violation
    pub discovered_violation: bool,
    /// Signature over (voter || is_conforming || validated_hash || substitute)
    pub signature: [u8; 64],
}

impl RecoveryVote {
    /// Compute the message to be signed/verified for this vote
    ///
    /// The sighash is SHA256(voter || is_conforming || validated_hash || substitute_pubkey)
    /// where substitute_pubkey is either the 33-byte compressed pubkey or 33 zero bytes
    pub fn sighash(&self) -> [u8; 32] {
        let mut preimage = Vec::with_capacity(33 + 1 + 32 + 33);

        // voter pubkey (33 bytes compressed)
        preimage.extend_from_slice(&self.voter.serialize());

        // is_conforming (1 byte)
        preimage.push(if self.is_conforming { 1 } else { 0 });

        // validated_hash (32 bytes)
        preimage.extend_from_slice(&self.validated_hash);

        // substitute_nomination (33 bytes - either pubkey or zeros)
        match &self.substitute_nomination {
            Some(pk) => preimage.extend_from_slice(&pk.serialize()),
            None => preimage.extend_from_slice(&[0u8; 33]),
        }

        sha256::Hash::hash(&preimage).to_byte_array()
    }

    /// Create a new signed recovery vote
    ///
    /// The keypair must correspond to the voter's public key
    pub fn new_signed(
        keypair: &Keypair,
        is_conforming: bool,
        validated_hash: [u8; 32],
        validated_sequence: u64,
        substitute_nomination: Option<PublicKey>,
        discovered_violation: bool,
    ) -> Result<Self, RecoveryError> {
        let secp = Secp256k1::new();
        let voter = keypair.public_key();

        // Create unsigned vote to compute sighash
        let mut vote = Self {
            voter,
            is_conforming,
            validated_hash,
            validated_sequence,
            substitute_nomination,
            discovered_violation,
            signature: [0u8; 64],
        };

        // Compute sighash and sign
        let sighash = vote.sighash();
        let message = Message::from_digest(sighash);
        let sig = secp.sign_schnorr_no_aux_rand(&message, keypair);
        vote.signature = *sig.as_ref();

        Ok(vote)
    }

    /// Verify the signature on this vote
    ///
    /// Returns Ok(()) if the signature is valid for the voter's pubkey
    pub fn verify(&self) -> Result<(), RecoveryError> {
        let secp = Secp256k1::verification_only();

        // Compute the expected sighash
        let sighash = self.sighash();
        let message = Message::from_digest(sighash);

        // Parse the signature
        let sig = SchnorrSignature::from_slice(&self.signature)
            .map_err(|_| RecoveryError::InvalidSignature)?;

        // Get x-only pubkey for Schnorr verification
        let xonly_pk = self.voter.x_only_public_key().0;

        // Verify
        secp.verify_schnorr(&sig, &message, &xonly_pk)
            .map_err(|_| RecoveryError::InvalidSignature)
    }
}

/// Pool of candidates eligible for recovery
#[derive(Clone, Debug)]
pub struct RecoveryPool {
    /// The original operator (being replaced if non-compliant)
    pub original_operator: PublicKey,
    /// Channel partners eligible for recovery
    pub channel_partners: Vec<RecoveryCandidate>,
    /// Operator's nominated substitute (if any)
    pub operator_substitute: Option<PublicKey>,
    /// The partner deterministically selected (computed from entropy)
    pub selected_partner: Option<PublicKey>,
}

/// A candidate eligible to receive recovered deposits
#[derive(Clone, Debug)]
pub struct RecoveryCandidate {
    /// Candidate's pubkey
    pub pubkey: PublicKey,
    /// Whether they're a direct channel partner of the operator
    pub is_channel_partner: bool,
    /// Whether they discovered a violation (incentive for evidence discovery)
    pub discovered_violation: bool,
    /// Their collateral amount (for capacity verification)
    pub collateral_amount: u64,
}

/// Time-based claim eligibility after non-compliance determination
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClaimEligibility {
    /// Only the pseudorandomly selected partner can claim
    SelectedPartnerOnly { partner: PublicKey },
    /// Any 3 channel partners together can claim
    AnyThreePartners,
    /// Any single channel partner can claim
    AnySinglePartner,
    /// Community fallback mechanism
    CommunityFallback,
}

impl ClaimEligibility {
    /// Determine eligibility based on blocks since force close
    pub fn from_blocks_elapsed(blocks: u32, selected_partner: PublicKey) -> Self {
        if blocks < DAY_BLOCKS {
            ClaimEligibility::SelectedPartnerOnly {
                partner: selected_partner,
            }
        } else if blocks < WEEK_BLOCKS {
            ClaimEligibility::AnyThreePartners
        } else if blocks < TWO_WEEKS_BLOCKS {
            ClaimEligibility::AnySinglePartner
        } else {
            ClaimEligibility::CommunityFallback
        }
    }

    /// Check if a set of claimants can claim under current eligibility
    pub fn can_claim(&self, claimants: &[PublicKey], channel_partners: &[PublicKey]) -> bool {
        match self {
            ClaimEligibility::SelectedPartnerOnly { partner } => {
                claimants.len() == 1 && claimants[0] == *partner
            }
            ClaimEligibility::AnyThreePartners => {
                // Need exactly 3, all must be channel partners
                claimants.len() >= 3 && claimants.iter().all(|c| channel_partners.contains(c))
            }
            ClaimEligibility::AnySinglePartner => {
                // Any channel partner can claim
                !claimants.is_empty() && claimants.iter().any(|c| channel_partners.contains(c))
            }
            ClaimEligibility::CommunityFallback => {
                // Community mechanism - always true for now
                true
            }
        }
    }

    /// Get the tier index for this eligibility level (0-3).
    ///
    /// - Tier 0: Selected partner only (first day)
    /// - Tier 1: Any 3 partners (day 1 to week 1)
    /// - Tier 2: Any single partner (week 1 to week 2)
    /// - Tier 3: Community fallback (after week 2)
    pub fn tier_index(&self) -> u8 {
        match self {
            ClaimEligibility::SelectedPartnerOnly { .. } => 0,
            ClaimEligibility::AnyThreePartners => 1,
            ClaimEligibility::AnySinglePartner => 2,
            ClaimEligibility::CommunityFallback => 3,
        }
    }
}

/// Manager for ledger recovery processes
pub struct RecoveryManager {
    /// Our node's pubkey
    our_node_id: PublicKey,
    /// Active recovery processes by (operator, partner) ledger ID
    recoveries: HashMap<(PublicKey, PublicKey), RecoveryState>,
}

/// State for a single recovery process
#[derive(Clone, Debug)]
pub struct RecoveryState {
    /// The ledger being recovered (operator, partner)
    pub ledger_id: (PublicKey, PublicKey),
    /// Current phase
    pub phase: RecoveryPhase,
    /// Timestamp when recovery started
    pub started_at: u64,
    /// Last update timestamp
    pub last_update: u64,
}

impl RecoveryManager {
    /// Create a new recovery manager
    pub fn new(our_node_id: PublicKey) -> Self {
        Self {
            our_node_id,
            recoveries: HashMap::new(),
        }
    }

    /// Start a recovery process when force close is detected
    pub fn start_recovery(
        &mut self,
        operator: PublicKey,
        partner: PublicKey,
        force_close_block: u32,
        force_close_txid: [u8; 32],
        on_chain_ledger_hash: [u8; 32],
    ) -> Result<(), RecoveryError> {
        let ledger_id = (operator, partner);

        if self.recoveries.contains_key(&ledger_id) {
            return Err(RecoveryError::AlreadyInProgress);
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let state = RecoveryState {
            ledger_id,
            phase: RecoveryPhase::WaitingForEntropy {
                force_close_block,
                force_close_txid,
                on_chain_ledger_hash,
            },
            started_at: now,
            last_update: now,
        };

        self.recoveries.insert(ledger_id, state);
        Ok(())
    }

    /// Called when entropy block is confirmed (force_close + 6)
    pub fn on_entropy_block(
        &mut self,
        ledger_id: (PublicKey, PublicKey),
        entropy_block_hash: [u8; 32],
    ) -> Result<(), RecoveryError> {
        let state = self
            .recoveries
            .get_mut(&ledger_id)
            .ok_or(RecoveryError::NotFound)?;

        let (force_close_block, on_chain_ledger_hash) = match &state.phase {
            RecoveryPhase::WaitingForEntropy {
                force_close_block,
                on_chain_ledger_hash,
                ..
            } => (*force_close_block, *on_chain_ledger_hash),
            _ => return Err(RecoveryError::InvalidPhase),
        };

        state.phase = RecoveryPhase::Evaluating {
            force_close_block,
            entropy_block_hash,
            on_chain_ledger_hash,
            votes: HashMap::new(),
        };

        state.last_update = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(())
    }

    /// Submit a recovery vote
    pub fn submit_vote(
        &mut self,
        ledger_id: (PublicKey, PublicKey),
        vote: RecoveryVote,
    ) -> Result<VoteResult, RecoveryError> {
        let state = self
            .recoveries
            .get_mut(&ledger_id)
            .ok_or(RecoveryError::NotFound)?;

        let votes = match &mut state.phase {
            RecoveryPhase::Evaluating { votes, .. } => votes,
            _ => return Err(RecoveryError::InvalidPhase),
        };

        // Verify the vote signature before accepting
        vote.verify()?;

        // Record the vote
        votes.insert(vote.voter, vote);

        state.last_update = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(VoteResult {
            total_votes: votes.len(),
            conforming_votes: votes.values().filter(|v| v.is_conforming).count(),
            non_conforming_votes: votes.values().filter(|v| !v.is_conforming).count(),
        })
    }

    /// Finalize the evaluation phase once all votes are in
    pub fn finalize_evaluation(
        &mut self,
        ledger_id: (PublicKey, PublicKey),
        channel_partners: Vec<RecoveryCandidate>,
        operator_substitute: Option<PublicKey>,
        threshold: usize,
    ) -> Result<RecoveryPhase, RecoveryError> {
        let state = self
            .recoveries
            .get_mut(&ledger_id)
            .ok_or(RecoveryError::NotFound)?;

        let (force_close_block, entropy, votes) = match &state.phase {
            RecoveryPhase::Evaluating {
                force_close_block,
                entropy_block_hash,
                votes,
                ..
            } => (*force_close_block, *entropy_block_hash, votes.clone()),
            _ => return Err(RecoveryError::InvalidPhase),
        };

        let conforming_count = votes.values().filter(|v| v.is_conforming).count();
        let non_conforming_count = votes.values().filter(|v| !v.is_conforming).count();

        if conforming_count >= threshold {
            // Operator is compliant - return funds
            state.phase = RecoveryPhase::ReturningToOperator {
                operator: ledger_id.0,
                confirmations_needed: threshold,
                confirmations_received: Vec::new(),
            };
        } else if non_conforming_count >= threshold {
            // Operator is non-compliant - start deterministic selection
            let partner_pubkeys: Vec<PublicKey> =
                channel_partners.iter().map(|c| c.pubkey).collect();

            let selected = select_recovery_partner(&entropy, &partner_pubkeys);

            let recovery_pool = RecoveryPool {
                original_operator: ledger_id.0,
                channel_partners,
                operator_substitute,
                selected_partner: Some(selected),
            };

            let eligibility = ClaimEligibility::SelectedPartnerOnly { partner: selected };

            state.phase = RecoveryPhase::NonCompliantRecovery {
                force_close_block,
                entropy,
                recovery_pool,
                current_eligibility: eligibility,
            };
        } else {
            // Not enough votes yet
            return Err(RecoveryError::InsufficientVotes {
                received: votes.len(),
                needed: threshold,
            });
        }

        state.last_update = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(state.phase.clone())
    }

    /// Update claim eligibility based on current block height
    pub fn update_eligibility(
        &mut self,
        ledger_id: (PublicKey, PublicKey),
        current_block: u32,
    ) -> Result<ClaimEligibility, RecoveryError> {
        let state = self
            .recoveries
            .get_mut(&ledger_id)
            .ok_or(RecoveryError::NotFound)?;

        let (force_close_block, selected) = match &state.phase {
            RecoveryPhase::NonCompliantRecovery {
                force_close_block,
                recovery_pool,
                ..
            } => {
                let selected = recovery_pool
                    .selected_partner
                    .ok_or(RecoveryError::NoSelectedPartner)?;
                (*force_close_block, selected)
            }
            _ => return Err(RecoveryError::InvalidPhase),
        };

        let blocks_elapsed = current_block.saturating_sub(force_close_block);
        let new_eligibility = ClaimEligibility::from_blocks_elapsed(blocks_elapsed, selected);

        // Update the eligibility in state
        if let RecoveryPhase::NonCompliantRecovery {
            current_eligibility,
            ..
        } = &mut state.phase
        {
            *current_eligibility = new_eligibility.clone();
        }

        Ok(new_eligibility)
    }

    /// Attempt to claim the recovered deposits
    pub fn claim(
        &mut self,
        ledger_id: (PublicKey, PublicKey),
        claimants: &[PublicKey],
        current_block: u32,
    ) -> Result<RecoveryOutcome, RecoveryError> {
        // First update eligibility
        self.update_eligibility(ledger_id, current_block)?;

        let state = self
            .recoveries
            .get_mut(&ledger_id)
            .ok_or(RecoveryError::NotFound)?;

        let (recovery_pool, eligibility) = match &state.phase {
            RecoveryPhase::NonCompliantRecovery {
                recovery_pool,
                current_eligibility,
                ..
            } => (recovery_pool.clone(), current_eligibility.clone()),
            _ => return Err(RecoveryError::InvalidPhase),
        };

        let partner_pubkeys: Vec<PublicKey> = recovery_pool
            .channel_partners
            .iter()
            .map(|c| c.pubkey)
            .collect();

        if !eligibility.can_claim(claimants, &partner_pubkeys) {
            return Err(RecoveryError::NotEligible);
        }

        // Determine the new operator and reason
        let (new_operator, reason) = match &eligibility {
            ClaimEligibility::SelectedPartnerOnly { partner } => {
                (*partner, ReassignmentReason::DeterministicSelection)
            }
            ClaimEligibility::AnyThreePartners => {
                // First claimant becomes the operator
                let claimant_array: [PublicKey; 3] = [
                    claimants[0],
                    claimants.get(1).copied().unwrap_or(claimants[0]),
                    claimants.get(2).copied().unwrap_or(claimants[0]),
                ];
                (
                    claimants[0],
                    ReassignmentReason::ThreePartnerQuorum {
                        claimants: claimant_array,
                    },
                )
            }
            ClaimEligibility::AnySinglePartner => {
                (claimants[0], ReassignmentReason::SinglePartnerClaim)
            }
            ClaimEligibility::CommunityFallback => {
                (claimants[0], ReassignmentReason::CommunityFallback)
            }
        };

        let outcome = RecoveryOutcome::ReassignedTo {
            new_operator,
            reason,
        };

        state.phase = RecoveryPhase::Complete {
            outcome: outcome.clone(),
        };

        state.last_update = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(outcome)
    }

    /// Confirm return to operator (for compliant case)
    pub fn confirm_return(
        &mut self,
        ledger_id: (PublicKey, PublicKey),
        confirmer: PublicKey,
    ) -> Result<Option<RecoveryOutcome>, RecoveryError> {
        let state = self
            .recoveries
            .get_mut(&ledger_id)
            .ok_or(RecoveryError::NotFound)?;

        let (operator, needed, received) = match &mut state.phase {
            RecoveryPhase::ReturningToOperator {
                operator,
                confirmations_needed,
                confirmations_received,
            } => (*operator, *confirmations_needed, confirmations_received),
            _ => return Err(RecoveryError::InvalidPhase),
        };

        if !received.contains(&confirmer) {
            received.push(confirmer);
        }

        state.last_update = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if received.len() >= needed {
            let outcome = RecoveryOutcome::ReturnedToOperator { operator };
            state.phase = RecoveryPhase::Complete {
                outcome: outcome.clone(),
            };
            Ok(Some(outcome))
        } else {
            Ok(None)
        }
    }

    /// Simplified transition to NonCompliantRecovery phase (for testing and direct use)
    ///
    /// This method directly transitions from Evaluating to NonCompliantRecovery without
    /// requiring the full vote threshold checking of `finalize_evaluation`.
    pub fn transition_to_non_compliant(
        &mut self,
        ledger_id: (PublicKey, PublicKey),
        force_close_block: u32,
        channel_partners: Vec<PublicKey>,
    ) -> Result<RecoveryPhase, RecoveryError> {
        let state = self
            .recoveries
            .get_mut(&ledger_id)
            .ok_or(RecoveryError::NotFound)?;

        // Get entropy from current phase
        let entropy = match &state.phase {
            RecoveryPhase::Evaluating {
                entropy_block_hash, ..
            } => *entropy_block_hash,
            _ => return Err(RecoveryError::InvalidPhase),
        };

        // Select partner deterministically
        let selected = select_recovery_partner(&entropy, &channel_partners);

        // Build recovery candidates from pubkeys
        let candidates: Vec<RecoveryCandidate> = channel_partners
            .iter()
            .map(|pk| RecoveryCandidate {
                pubkey: *pk,
                is_channel_partner: true,
                discovered_violation: false,
                collateral_amount: 0,
            })
            .collect();

        let recovery_pool = RecoveryPool {
            original_operator: ledger_id.0,
            channel_partners: candidates,
            operator_substitute: None,
            selected_partner: Some(selected),
        };

        let eligibility = ClaimEligibility::SelectedPartnerOnly { partner: selected };

        state.phase = RecoveryPhase::NonCompliantRecovery {
            force_close_block,
            entropy,
            recovery_pool,
            current_eligibility: eligibility,
        };

        state.last_update = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(state.phase.clone())
    }

    /// Get current state of a recovery
    pub fn get_recovery(&self, ledger_id: &(PublicKey, PublicKey)) -> Option<&RecoveryState> {
        self.recoveries.get(ledger_id)
    }
}

/// Result of submitting a vote
#[derive(Clone, Debug)]
pub struct VoteResult {
    pub total_votes: usize,
    pub conforming_votes: usize,
    pub non_conforming_votes: usize,
}

/// Errors during recovery process
#[derive(Clone, Debug)]
pub enum RecoveryError {
    /// Recovery already in progress for this ledger
    AlreadyInProgress,
    /// No recovery found for this ledger
    NotFound,
    /// Invalid phase for this operation
    InvalidPhase,
    /// Not enough votes to finalize
    InsufficientVotes { received: usize, needed: usize },
    /// No selected partner (shouldn't happen)
    NoSelectedPartner,
    /// Claimants not eligible under current rules
    NotEligible,
    /// Invalid signature on vote
    InvalidSignature,
}

/// Deterministically select a recovery partner using block entropy
///
/// This function is pure and deterministic - given the same entropy and
/// recovery pool, it will always select the same partner.
pub fn select_recovery_partner(
    entropy_block_hash: &[u8; 32],
    recovery_pool: &[PublicKey],
) -> PublicKey {
    if recovery_pool.is_empty() {
        panic!("Recovery pool cannot be empty");
    }

    // Sort partners deterministically by serialized pubkey
    let mut sorted: Vec<_> = recovery_pool.to_vec();
    sorted.sort_by_key(|pk| pk.serialize());

    // Hash entropy with sorted partners to get selection index
    let mut hasher_input = Vec::new();
    hasher_input.extend_from_slice(entropy_block_hash);
    for pk in &sorted {
        hasher_input.extend_from_slice(&pk.serialize());
    }

    let selection_hash = sha256::Hash::hash(&hasher_input);
    let selection_bytes: [u8; 8] = selection_hash.as_byte_array()[0..8].try_into().unwrap();
    let index = u64::from_le_bytes(selection_bytes) as usize % sorted.len();

    sorted[index]
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
    fn test_deterministic_selection_consistency() {
        let entropy = [42u8; 32];
        let partners = vec![
            generate_test_pubkey(1),
            generate_test_pubkey(2),
            generate_test_pubkey(3),
            generate_test_pubkey(4),
        ];

        // Same entropy + partners = same selection
        let selected1 = select_recovery_partner(&entropy, &partners);
        let selected2 = select_recovery_partner(&entropy, &partners);
        assert_eq!(selected1, selected2);

        // Order doesn't matter (sorted internally)
        let mut reversed = partners.clone();
        reversed.reverse();
        let selected3 = select_recovery_partner(&entropy, &reversed);
        assert_eq!(selected1, selected3);
    }

    #[test]
    fn test_deterministic_selection_different_entropy() {
        let partners = vec![
            generate_test_pubkey(1),
            generate_test_pubkey(2),
            generate_test_pubkey(3),
            generate_test_pubkey(4),
        ];

        // Different entropy should (usually) give different selection
        let entropy1 = [1u8; 32];
        let entropy2 = [2u8; 32];

        let selected1 = select_recovery_partner(&entropy1, &partners);
        let selected2 = select_recovery_partner(&entropy2, &partners);

        // Note: With only 4 partners, there's a 25% chance they're the same
        // This test just verifies the function runs, not that they're different
        assert!(partners.contains(&selected1));
        assert!(partners.contains(&selected2));
    }

    #[test]
    fn test_claim_eligibility_time_degradation() {
        let selected = generate_test_pubkey(1);

        // Day 0: Only selected partner
        let elig = ClaimEligibility::from_blocks_elapsed(0, selected);
        assert_eq!(
            elig,
            ClaimEligibility::SelectedPartnerOnly { partner: selected }
        );

        let elig = ClaimEligibility::from_blocks_elapsed(143, selected);
        assert_eq!(
            elig,
            ClaimEligibility::SelectedPartnerOnly { partner: selected }
        );

        // Day 1: Any 3 partners
        let elig = ClaimEligibility::from_blocks_elapsed(144, selected);
        assert_eq!(elig, ClaimEligibility::AnyThreePartners);

        let elig = ClaimEligibility::from_blocks_elapsed(1007, selected);
        assert_eq!(elig, ClaimEligibility::AnyThreePartners);

        // Week 1: Any single partner
        let elig = ClaimEligibility::from_blocks_elapsed(1008, selected);
        assert_eq!(elig, ClaimEligibility::AnySinglePartner);

        let elig = ClaimEligibility::from_blocks_elapsed(2015, selected);
        assert_eq!(elig, ClaimEligibility::AnySinglePartner);

        // Week 2+: Community fallback
        let elig = ClaimEligibility::from_blocks_elapsed(2016, selected);
        assert_eq!(elig, ClaimEligibility::CommunityFallback);
    }

    #[test]
    fn test_claim_eligibility_can_claim() {
        let partner1 = generate_test_pubkey(1);
        let partner2 = generate_test_pubkey(2);
        let partner3 = generate_test_pubkey(3);
        let partner4 = generate_test_pubkey(4);
        let non_partner = generate_test_pubkey(99);

        let channel_partners = vec![partner1, partner2, partner3, partner4];

        // Selected partner only
        let elig = ClaimEligibility::SelectedPartnerOnly { partner: partner1 };
        assert!(elig.can_claim(&[partner1], &channel_partners));
        assert!(!elig.can_claim(&[partner2], &channel_partners));
        assert!(!elig.can_claim(&[partner1, partner2], &channel_partners));

        // Any 3 partners
        let elig = ClaimEligibility::AnyThreePartners;
        assert!(elig.can_claim(&[partner1, partner2, partner3], &channel_partners));
        assert!(elig.can_claim(&[partner2, partner3, partner4], &channel_partners));
        assert!(!elig.can_claim(&[partner1, partner2], &channel_partners));
        assert!(!elig.can_claim(&[partner1, partner2, non_partner], &channel_partners));

        // Any single partner
        let elig = ClaimEligibility::AnySinglePartner;
        assert!(elig.can_claim(&[partner1], &channel_partners));
        assert!(elig.can_claim(&[partner4], &channel_partners));
        assert!(!elig.can_claim(&[non_partner], &channel_partners));
    }

    #[test]
    fn test_recovery_manager_lifecycle() {
        let our_node = generate_test_pubkey(1);
        let operator = generate_test_pubkey(10);
        let partner = generate_test_pubkey(20);

        let mut manager = RecoveryManager::new(our_node);
        let ledger_id = (operator, partner);

        // Start recovery
        manager
            .start_recovery(operator, partner, 100, [1u8; 32], [2u8; 32])
            .unwrap();

        // Verify it's in WaitingForEntropy phase
        let state = manager.get_recovery(&ledger_id).unwrap();
        assert!(matches!(
            state.phase,
            RecoveryPhase::WaitingForEntropy { .. }
        ));

        // Can't start again
        let result = manager.start_recovery(operator, partner, 100, [1u8; 32], [2u8; 32]);
        assert!(matches!(result, Err(RecoveryError::AlreadyInProgress)));
    }

    #[test]
    fn test_recovery_vote_submission() {
        let our_node = generate_test_pubkey(1);
        let operator = generate_test_pubkey(10);
        let partner = generate_test_pubkey(20);
        let voter1_keypair = generate_test_keypair(30);
        let voter2_keypair = generate_test_keypair(31);

        let mut manager = RecoveryManager::new(our_node);
        let ledger_id = (operator, partner);

        // Start and move to evaluating
        manager
            .start_recovery(operator, partner, 100, [1u8; 32], [2u8; 32])
            .unwrap();
        manager.on_entropy_block(ledger_id, [3u8; 32]).unwrap();

        // Submit signed votes
        let vote1 = RecoveryVote::new_signed(
            &voter1_keypair,
            false, // non-conforming
            [2u8; 32],
            100,
            None,
            true, // discovered violation
        )
        .unwrap();

        let result = manager.submit_vote(ledger_id, vote1).unwrap();
        assert_eq!(result.total_votes, 1);
        assert_eq!(result.non_conforming_votes, 1);

        let vote2 = RecoveryVote::new_signed(
            &voter2_keypair,
            false, // non-conforming
            [2u8; 32],
            100,
            None,
            false,
        )
        .unwrap();

        let result = manager.submit_vote(ledger_id, vote2).unwrap();
        assert_eq!(result.total_votes, 2);
        assert_eq!(result.non_conforming_votes, 2);
    }

    fn generate_test_keypair(seed: u8) -> Keypair {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[seed; 32]).unwrap();
        Keypair::from_secret_key(&secp, &secret)
    }

    #[test]
    fn test_recovery_vote_sign_and_verify() {
        let keypair = generate_test_keypair(42);

        // Create a signed vote
        let vote = RecoveryVote::new_signed(
            &keypair, false,     // non-conforming
            [1u8; 32], // validated_hash
            100,       // validated_sequence
            None,      // no substitute
            true,      // discovered violation
        )
        .unwrap();

        // Verify the signature is valid
        assert!(vote.verify().is_ok());

        // Verify voter matches keypair
        let expected_voter = PublicKey::from(keypair.public_key());
        assert_eq!(vote.voter, expected_voter);
        assert!(!vote.is_conforming);
        assert_eq!(vote.validated_hash, [1u8; 32]);
        assert_eq!(vote.validated_sequence, 100);
        assert!(vote.substitute_nomination.is_none());
        assert!(vote.discovered_violation);
    }
}
