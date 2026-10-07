//! Cosignature-threshold computation across the quorum lifecycle.
//!
//! Implements DEP-05 §Lifecycle: the off-chain cosignature threshold
//! for establishment operations (`QuorumAddMember`, `QuorumRemoveMember`,
//! `QuorumBegin`) cascades through the same tier schedule as the
//! on-chain reserves tapscript (`quorum_expiry + {0, 720, 4032, 8064}`).
//! Non-establishment operations stay Tier-0 only and become uncosignable
//! past `quorum_expiry` until a fresh `QuorumBegin` resets the schedule.
//!
//! Gated by the ledger's `active_ruleset_name`:
//! - every registered ruleset: DEP-05 §Lifecycle cascade (tier-1 minority
//!   `ceil(n/2) - 1`);
//! - an unknown ruleset (or none yet): strict majority always.

use crate::messages::LedgerOperation;
use crate::types::LedgerState;

/// Per-tier offset from `quorum_expiry` (blocks). Matches the
/// `cltv-offset-v2` ruleset baked into the on-chain tapscript.
const TIER_1_OFFSET: u32 = 720;
const TIER_2_OFFSET: u32 = 4032;
const TIER_3_OFFSET: u32 = 8064;

/// Classification of a ledger operation for threshold purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationClass {
    /// `QuorumAddMember`, `QuorumRemoveMember`, `QuorumBegin` — the ops
    /// that establish or repair the quorum. Cosignable at any tier
    /// matching the current chain tip.
    Establishment,
    /// Every other op type. Cosignable only at Tier 0 (within the
    /// active period); refused at all degraded tiers.
    ValueMoving,
}

impl OperationClass {
    pub fn of(op: &LedgerOperation) -> Self {
        match op {
            LedgerOperation::QuorumAddMember { .. }
            | LedgerOperation::QuorumRemoveMember { .. }
            | LedgerOperation::QuorumBegin { .. } => OperationClass::Establishment,
            _ => OperationClass::ValueMoving,
        }
    }
}

/// The lifecycle tier in force at a given chain tip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleTier {
    /// Active period (`chain_tip < quorum_expiry`). Strict majority.
    Tier0,
    /// `quorum_expiry <= chain_tip < quorum_expiry + 720`. Strict
    /// majority cosig still works for establishment ops (the
    /// "majority confiscation" / cosigner-driven recovery window).
    Tier0PostExpiry,
    /// `chain_tip >= quorum_expiry + 720`. Minority threshold.
    Tier1,
    /// `chain_tip >= quorum_expiry + 4032`. Single-cosigner threshold.
    Tier2,
    /// `chain_tip >= quorum_expiry + 8064`. Operator-alone (no
    /// cosignatures required).
    Tier3,
}

/// The result of computing the cosignature requirement for an operation.
#[derive(Debug, Clone)]
pub struct CosignRequirement {
    /// Whether the operation is cosignable at all at the current tier.
    /// Value-moving ops past `quorum_expiry` resolve to `allowed=false`.
    pub allowed: bool,
    /// Number of distinct cosignatures required. Zero when
    /// `operator_alone=true` (Tier 3) or when no quorum is established
    /// yet (pre-QuorumBegin).
    pub required_sigs: usize,
    /// The lifecycle tier in force.
    pub tier: LifecycleTier,
    /// True when the threshold path is operator-only (Tier 3) — the
    /// operator signs alone, no cosignatures are needed.
    pub operator_alone: bool,
    /// Human-readable reason when `allowed=false`. Empty otherwise.
    pub reason: String,
}

impl CosignRequirement {
    fn allowed(required: usize, tier: LifecycleTier, operator_alone: bool) -> Self {
        Self {
            allowed: true,
            required_sigs: required,
            tier,
            operator_alone,
            reason: String::new(),
        }
    }

    fn refused(tier: LifecycleTier, reason: impl Into<String>) -> Self {
        Self {
            allowed: false,
            required_sigs: 0,
            tier,
            operator_alone: false,
            reason: reason.into(),
        }
    }
}

/// True if the ledger's active ruleset uses the DEP-05 §Lifecycle
/// cascade. Legacy ledgers keep the pre-Lifecycle "strict majority,
/// fatal at expiry" behavior.
fn uses_lifecycle_cascade(ruleset_name: &str) -> bool {
    crate::types::ruleset_known(ruleset_name)
}

/// Resolve the lifecycle tier for a chain tip against a quorum's
/// expiry. None when the ledger has no `quorum_expiry` (pre-QuorumBegin).
fn tier_for_chain_tip(quorum_expiry: Option<u32>, chain_tip: u32) -> Option<LifecycleTier> {
    let expiry = quorum_expiry?;
    let tier = if chain_tip < expiry {
        LifecycleTier::Tier0
    } else if chain_tip < expiry.saturating_add(TIER_1_OFFSET) {
        LifecycleTier::Tier0PostExpiry
    } else if chain_tip < expiry.saturating_add(TIER_2_OFFSET) {
        LifecycleTier::Tier1
    } else if chain_tip < expiry.saturating_add(TIER_3_OFFSET) {
        LifecycleTier::Tier2
    } else {
        LifecycleTier::Tier3
    };
    Some(tier)
}

/// Strict majority of `n`.
fn majority(n: usize) -> usize {
    (n / 2) + 1
}

/// Minority used at Tier 1, mirroring the on-chain script's
/// Tier-1 minority threshold: `ceil(n/2) - 1` (= n - majority), at least 1.
fn minority(n: usize) -> usize {
    n.div_ceil(2).saturating_sub(1).max(1)
}

/// Compute the cosignature requirement for an operation against a
/// ledger state at a given chain tip.
///
/// See DEP-05 §Lifecycle for the policy this implements.
pub fn cosign_requirement(
    state: &LedgerState,
    op: &LedgerOperation,
    chain_tip: u32,
) -> CosignRequirement {
    // Which signer set is in force? The active quorum once one is
    // established; otherwise the staged set (for the *first*
    // `QuorumBegin`'s self-attestation). Pre-quorum + non-QuorumBegin
    // resolves to "no cosigs required" (the LedgerOpen + opening
    // updates flow).
    let active = !state.quorum_members.is_empty();
    let staged = !state.next_quorum_members.is_empty();
    let signer_count = if active {
        state.quorum_members.len()
    } else if matches!(op, LedgerOperation::QuorumBegin { .. }) && staged {
        state.next_quorum_members.len()
    } else {
        return CosignRequirement::allowed(0, LifecycleTier::Tier0, false);
    };

    let class = OperationClass::of(op);

    // Pre-Lifecycle rulesets (legacy): preserve old behavior. Strict
    // majority always; the cosigner-edge gate (validate_for_cosign)
    // separately refuses everything past expiry.
    if !uses_lifecycle_cascade(&state.active_ruleset_name) {
        return CosignRequirement::allowed(majority(signer_count), LifecycleTier::Tier0, false);
    }

    // The first QuorumBegin (no active quorum yet) is always Tier-0:
    // there's no quorum_expiry to anchor a cascade against. Strict
    // majority of the staged set, per DEP-02 §Hash Chain.
    let Some(tier) = tier_for_chain_tip(state.quorum_expiry, chain_tip) else {
        return CosignRequirement::allowed(majority(signer_count), LifecycleTier::Tier0, false);
    };

    match (class, tier) {
        // Tier 0 (active period): both classes at strict majority.
        (_, LifecycleTier::Tier0) => {
            CosignRequirement::allowed(majority(signer_count), tier, false)
        }

        // Past expiry, value-moving ops are uncosignable. The operator
        // must first re-establish via QuorumBegin (which IS cosignable
        // at the matching degraded threshold).
        (OperationClass::ValueMoving, _) => CosignRequirement::refused(
            tier,
            "value-moving op past quorum_expiry — re-establish via QuorumBegin first",
        ),

        // Establishment ops past expiry follow the tier cascade.
        (OperationClass::Establishment, LifecycleTier::Tier0PostExpiry) => {
            CosignRequirement::allowed(majority(signer_count), tier, false)
        }
        (OperationClass::Establishment, LifecycleTier::Tier1) => {
            CosignRequirement::allowed(minority(signer_count), tier, false)
        }
        (OperationClass::Establishment, LifecycleTier::Tier2) => {
            CosignRequirement::allowed(1, tier, false)
        }
        (OperationClass::Establishment, LifecycleTier::Tier3) => {
            CosignRequirement::allowed(0, tier, true)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{LedgerState, QuorumMember};
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

    fn pk(byte: u8) -> PublicKey {
        let secp = Secp256k1::new();
        let mut bytes = [1u8; 32];
        bytes[0] = byte.max(1);
        let sk = SecretKey::from_slice(&bytes).unwrap();
        PublicKey::from_secret_key(&secp, &sk)
    }

    fn member(byte: u8) -> QuorumMember {
        QuorumMember {
            min_collateral_bps: None,
            pubkey: pk(byte),
            ledger_id: format!("{:064x}", byte as u128),
            min_fee_bps: None,
            min_fee_fixed: None,
            max_fee_period: None,
            membership_until: None,
            dispute_response_blocks: None,
            dispute_arm_blocks: None,
            service_response_blocks: None,
            max_transfer_timeout_blocks: None,
            max_descriptor_bytes: None,
            compensation_bps: None,
            compensation_deposit_id: None,
            compensation_frequency_blocks: None,
            supported_rulesets: vec!["cltv-offset-v2".to_string()],
        }
    }

    fn state_with_quorum(n: usize, ruleset: &str, quorum_expiry: Option<u32>) -> LedgerState {
        let mut s = LedgerState::new(pk(99), "tb1q0".to_string(), 0);
        s.quorum_members = (1..=n as u8).map(member).collect();
        s.active_ruleset_name = ruleset.to_string();
        s.quorum_expiry = quorum_expiry;
        s
    }

    fn value_moving_op() -> LedgerOperation {
        LedgerOperation::LedgerClose
    }

    fn establishment_op() -> LedgerOperation {
        LedgerOperation::QuorumRemoveMember {
            quorum_member: pk(42),
            operator_signature: [0u8; 64],
        }
    }

    // ---- Tier 0 (active period) ----------------------------------

    #[test]
    fn tier0_active_value_moving_majority() {
        let s = state_with_quorum(5, "cltv-offset-v2", Some(1000));
        let r = cosign_requirement(&s, &value_moving_op(), 500);
        assert!(r.allowed);
        assert_eq!(r.required_sigs, 3);
        assert_eq!(r.tier, LifecycleTier::Tier0);
        assert!(!r.operator_alone);
    }

    #[test]
    fn tier0_active_establishment_majority() {
        let s = state_with_quorum(5, "cltv-offset-v2", Some(1000));
        let r = cosign_requirement(&s, &establishment_op(), 500);
        assert!(r.allowed);
        assert_eq!(r.required_sigs, 3);
        assert_eq!(r.tier, LifecycleTier::Tier0);
    }

    // ---- Tier 0 post-expiry (majority confiscation window) -------

    #[test]
    fn tier0_post_expiry_value_moving_refused() {
        let s = state_with_quorum(5, "cltv-offset-v2", Some(1000));
        let r = cosign_requirement(&s, &value_moving_op(), 1500);
        assert!(!r.allowed);
        assert_eq!(r.tier, LifecycleTier::Tier0PostExpiry);
        assert!(r.reason.contains("past quorum_expiry"));
    }

    #[test]
    fn tier0_post_expiry_establishment_still_majority() {
        let s = state_with_quorum(5, "cltv-offset-v2", Some(1000));
        // tip > expiry but < expiry + 720: majority still required for
        // QuorumBegin (i.e. confiscation window)
        let r = cosign_requirement(&s, &establishment_op(), 1500);
        assert!(r.allowed);
        assert_eq!(r.required_sigs, 3);
        assert_eq!(r.tier, LifecycleTier::Tier0PostExpiry);
    }

    // ---- Tier 1 (minority) ---------------------------------------

    #[test]
    fn tier1_establishment_minority() {
        let s = state_with_quorum(5, "cltv-offset-v2", Some(1000));
        let r = cosign_requirement(&s, &establishment_op(), 1000 + TIER_1_OFFSET);
        assert!(r.allowed);
        // minority(5) = ceil(5/2) - 1 = 2
        assert_eq!(r.required_sigs, 2);
        assert_eq!(r.tier, LifecycleTier::Tier1);
    }

    #[test]
    fn tier1_minority_n7() {
        let s = state_with_quorum(7, "cltv-offset-v2", Some(1000));
        let r = cosign_requirement(&s, &establishment_op(), 1000 + TIER_1_OFFSET);
        // minority(7) = ceil(7/2) - 1 = 3
        assert_eq!(r.required_sigs, 3);
    }

    #[test]
    fn tier1_value_moving_still_refused() {
        let s = state_with_quorum(5, "cltv-offset-v2", Some(1000));
        let r = cosign_requirement(&s, &value_moving_op(), 1000 + TIER_1_OFFSET);
        assert!(!r.allowed);
        assert_eq!(r.tier, LifecycleTier::Tier1);
    }

    // ---- Tier 2 (single cosigner) --------------------------------

    #[test]
    fn tier2_establishment_single() {
        let s = state_with_quorum(5, "cltv-offset-v2", Some(1000));
        let r = cosign_requirement(&s, &establishment_op(), 1000 + TIER_2_OFFSET);
        assert!(r.allowed);
        assert_eq!(r.required_sigs, 1);
        assert_eq!(r.tier, LifecycleTier::Tier2);
    }

    // ---- Tier 3 (operator alone) ---------------------------------

    #[test]
    fn tier3_establishment_operator_alone() {
        let s = state_with_quorum(5, "cltv-offset-v2", Some(1000));
        let r = cosign_requirement(&s, &establishment_op(), 1000 + TIER_3_OFFSET);
        assert!(r.allowed);
        assert_eq!(r.required_sigs, 0);
        assert!(r.operator_alone);
        assert_eq!(r.tier, LifecycleTier::Tier3);
    }

    #[test]
    fn tier3_value_moving_still_refused() {
        let s = state_with_quorum(5, "cltv-offset-v2", Some(1000));
        let r = cosign_requirement(&s, &value_moving_op(), 1000 + TIER_3_OFFSET);
        assert!(!r.allowed);
    }

    #[test]
    fn tier1_minority_is_n_minus_majority() {
        for (n, want) in [(5, 2), (6, 2), (7, 3)] {
            let s = state_with_quorum(n, "balance-commit-v4", Some(1000));
            let r = cosign_requirement(&s, &establishment_op(), 1000 + TIER_1_OFFSET);
            assert!(r.allowed);
            assert_eq!(r.required_sigs, want, "n={n}");
        }
    }

    // ---- Unknown ruleset: strict majority -------------------------

    #[test]
    fn unknown_ruleset_strict_majority() {
        let s = state_with_quorum(5, "legacy", Some(1000));
        let r = cosign_requirement(&s, &establishment_op(), 9000);
        assert!(r.allowed);
        assert_eq!(r.required_sigs, 3);
        assert_eq!(r.tier, LifecycleTier::Tier0);
    }

    // ---- Edge cases ----------------------------------------------

    #[test]
    fn pre_quorum_non_quorumbegin_no_cosigs_required() {
        let s = state_with_quorum(0, "cltv-offset-v2", None);
        let r = cosign_requirement(&s, &value_moving_op(), 100);
        assert!(r.allowed);
        assert_eq!(r.required_sigs, 0);
    }

    #[test]
    fn first_quorumbegin_against_staged_majority() {
        let mut s = LedgerState::new(pk(99), "tb1q0".to_string(), 0);
        s.next_quorum_members = (1..=5u8).map(member).collect();
        s.active_ruleset_name = "cltv-offset-v2".to_string();
        s.quorum_expiry = None; // not yet set; first QuorumBegin is committing it
        use crate::messages::QuorumMemberRef;
        let op = LedgerOperation::QuorumBegin {
            exit_cutoff_height: None,
            exit_outputs: Vec::new(),
            splice_in_outpoint: None,
            splice_in_amount: None,
            reserves_id: "bcrt1pdummy".to_string(),
            amount: 100_000_000,
            collateral_amount: 100_000_000,
            spending_txid: [0u8; 32],
            new_outpoint_txid: [0u8; 32],
            new_outpoint_vout: 0,
            ledger_hash: [0u8; 32],
            quorum_members: (1..=5u8)
                .map(|b| QuorumMemberRef {
                    pubkey: pk(b),
                    member_ledger_id: String::new(),
                })
                .collect(),
            quorum_expiry: 1000,
            protocol_version: Some("cltv-offset-v2".to_string()),
        };
        let r = cosign_requirement(&s, &op, 50);
        assert!(r.allowed);
        assert_eq!(r.required_sigs, 3);
        assert_eq!(r.tier, LifecycleTier::Tier0);
    }

    #[test]
    fn no_quorum_expiry_set_resolves_to_tier0() {
        let s = state_with_quorum(5, "cltv-offset-v2", None);
        let r = cosign_requirement(&s, &establishment_op(), 100);
        assert!(r.allowed);
        assert_eq!(r.tier, LifecycleTier::Tier0);
        assert_eq!(r.required_sigs, 3);
    }
}
