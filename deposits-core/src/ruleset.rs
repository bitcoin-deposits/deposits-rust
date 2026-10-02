//! Protocol rulesets.
//!
//! A ledger commits to a `Ruleset` at every `QuorumBegin`. The ruleset
//! determines:
//!   - the on-chain reserves UTXO's Tapscript tree (which tier
//!     thresholds + timelocks the script encodes),
//!   - which validation rules govern operations,
//!   - which fraud-proof variants the cosigner edge accepts,
//!   - and so on.
//!
//! Once written into a `QuorumBegin`, the ruleset is immutable for the
//! lifetime of that quorum: the on-chain UTXO is committed to it, and
//! all cosigners + validators agree on what counts as "conforming"
//! against that ruleset. A new ruleset takes effect at the *next*
//! `QuorumBegin` — operators opt their ledger into a new ruleset by
//! rotating into one.
//!
//! Rulesets are looked up by name via [`lookup`]. The registry is
//! **append-only**: once a name is in the registry, its semantics are
//! fixed forever. Protocol changes that would break that invariant
//! must register a new name instead.
//!
//! The registry holds the v2 cascade family and `minority-v5`; the
//! pre-anchor absolute-height cascades (`legacy`, `cltv-offset-literal`)
//! were removed. See `tapscript_reserves` for the only
//! consumer wired in P0; future phases retrofit validators, fraud
//! verifiers, etc. behind the same lookup.

use crate::tapscript_reserves::{ThresholdConfig, ThresholdTier};

/// A complete description of "what counts as valid" for a quorum's
/// lifetime.
///
/// Currently covers only the tier configuration the on-chain Tapscript
/// commits to. Subsequent phases extend with validators, timeouts,
/// supported fraud types, cosigner-policy defaults, etc. — every site
/// that today uses a compile-time constant will route through here so
/// that protocol forks land cleanly as new ruleset entries.
pub struct Ruleset {
    /// Stable opaque name. The QuorumBegin operation carries this
    /// string verbatim. Receivers look up the matching `Ruleset`
    /// through [`lookup`].
    pub name: &'static str,

    /// Returns a `ThresholdConfig` whose `timelock_blocks` are the
    /// **absolute** `OP_CLTV` targets the script should encode.
    /// Different rulesets bake timelock policy here:
    ///   - `cltv-offset-v2` returns `quorum_expiry + offset` so the
    ///     post-expiry cascade re-pins on each rotation.
    pub tier_config_factory: fn(n_voters: usize, quorum_expiry: u32) -> ThresholdConfig,
}

/// Look up a ruleset by name. `None` for unknown names; callers MUST
/// reject the QuorumBegin in that case (the operator is asking for a
/// ruleset this software doesn't know how to enforce).
pub fn lookup(name: &str) -> Option<&'static Ruleset> {
    match name {
        "cltv-offset-v2" => Some(&CLTV_OFFSET_V2),
        "fee-cap-v3" => Some(&FEE_CAP_V3),
        "balance-commit-v4" => Some(&BALANCE_COMMIT_V4),
        "minority-v5" => Some(&MINORITY_V5),
        _ => None,
    }
}

/// The ruleset new ledgers and rotations commit to when every member supports it.
pub const CURRENT: &str = "minority-v5";

/// Resolve a name to a ruleset, falling back to [`CURRENT`] for a missing or
/// unknown name. Acceptance paths reject unknown names before calling this
/// (a `QuorumBegin` without `protocol_version` is refused at apply), so the
/// fallback only covers display and pre-`QuorumBegin` state.
pub fn resolve_or_current(name: Option<&str>) -> &'static Ruleset {
    name.and_then(lookup).unwrap_or(&MINORITY_V5)
}

/// All ruleset names this binary knows how to enforce. Order is the
/// registry order. Quorum members publish this in their signed
/// `QuorumMemberResponse` so an operator can pick a `protocol_version`
/// at `quorum begin` time that every member can validate.
pub fn all_supported_names() -> Vec<&'static str> {
    vec![
        CLTV_OFFSET_V2.name,
        FEE_CAP_V3.name,
        BALANCE_COMMIT_V4.name,
        MINORITY_V5.name,
    ]
}

/// Decide whether a candidate member's declared `supported_rulesets`
/// covers `target`. An empty list supports nothing.
///
/// Used by `quorum begin` to refuse rotating into a ruleset some
/// pending member can't validate under, since that would silently
/// break their ability to cosign for the rest of the quorum's life.
pub fn member_supports(declared: &[String], target: &str) -> bool {
    declared.iter().any(|s| s == target)
}

#[cfg(test)]
mod gating_tests {
    use super::*;

    #[test]
    fn empty_list_supports_nothing() {
        assert!(!member_supports(&[], "cltv-offset-v2"));
        assert!(!member_supports(&[], CURRENT));
    }

    #[test]
    fn list_with_multiple_entries() {
        let both = vec!["balance-commit-v4".to_string(), "minority-v5".to_string()];
        assert!(member_supports(&both, "balance-commit-v4"));
        assert!(member_supports(&both, "minority-v5"));
        assert!(!member_supports(&both, "unknown"));
    }
}

// ============================================================================
// Registry entries
// ============================================================================

/// Post-redesign cascade: `OP_CLTV <quorum_expiry + offset>`. The
/// post-expiry tiers re-pin to the new deadline on every rotation, so
/// the security model survives long-lived UTXOs. Operator demoted to
/// last in the cascade. See DEP-03 §"Spending Tiers".
///
pub static CLTV_OFFSET_V2: Ruleset = Ruleset {
    name: "cltv-offset-v2",
    tier_config_factory: cltv_offset_v2_tier_config,
};

/// Same on-chain reserves cascade as [`CLTV_OFFSET_V2`] — byte-identical UTXO
/// scripts, i.e. the same reserves-cascade family — plus the off-chain
/// ledger-op conformance rule from DEP-07: cosigners reject a `FeeCollect`
/// exceeding one assessment period (`FeeExceedsAssessment`). Because the
/// reserves shape is unchanged, a ledger adopts this via a cheap `QuorumUpgrade`
/// (DEP-18) instead of an on-chain rotation. The op-rule is gated in
/// deposits-protocol (`ruleset_enforces_fee_cap`); this entry exists so reserves
/// reconstruction and quorum-member support resolve `fee-cap-v3` to the v2
/// cascade.
pub static FEE_CAP_V3: Ruleset = Ruleset {
    name: "fee-cap-v3",
    tier_config_factory: cltv_offset_v2_tier_config,
};

/// Same on-chain reserves cascade as [`CLTV_OFFSET_V2`] / [`FEE_CAP_V3`] —
/// byte-identical UTXO scripts, same reserves-cascade family — plus, on top of
/// `fee-cap-v3`'s rules, the DEP-02 §Balance Commitments requirement: every
/// balance-touching op MUST carry its post-op `(balance, locked_balance)`
/// declaration, and any declaration present under any ruleset must match the
/// replayed state. Adopted via a cheap `QuorumUpgrade` (DEP-18), no reserves
/// rotation. The op-rules are gated in deposits-protocol
/// (`ruleset_requires_balance_commitments` / `ruleset_enforces_fee_cap`); this
/// entry exists so reserves reconstruction and member-support resolve
/// `balance-commit-v4` to the v2 cascade.
pub static BALANCE_COMMIT_V4: Ruleset = Ruleset {
    name: "balance-commit-v4",
    tier_config_factory: cltv_offset_v2_tier_config,
};

/// `balance-commit-v4`'s op rules on a new reserves cascade: the tier-1
/// minority is `ceil(n/2) - 1` (= n - majority: the members a strict majority
/// leaves out), not `n/3`. Timelocks as `cltv-offset-v2`. A new script, so a
/// ledger adopts it by an on-chain rotation.
pub static MINORITY_V5: Ruleset = Ruleset {
    name: "minority-v5",
    tier_config_factory: minority_v5_tier_config,
};

// ============================================================================
// Factories
// ============================================================================

fn cltv_offset_v2_tier_config(n: usize, quorum_expiry: u32) -> ThresholdConfig {
    anchored_tier_config(n, quorum_expiry, (n / 3).max(1))
}

fn minority_v5_tier_config(n: usize, quorum_expiry: u32) -> ThresholdConfig {
    anchored_tier_config(n, quorum_expiry, recovery_minority(n))
}

/// `ceil(n/2) - 1`, at least 1.
pub fn recovery_minority(n: usize) -> usize {
    (n.div_ceil(2).saturating_sub(1)).max(1)
}

fn anchored_tier_config(n: usize, quorum_expiry: u32, minority: usize) -> ThresholdConfig {
    // Helper: encode "anytime" as 0 (no CLTV), or quorum_expiry + offset
    // as the absolute target.
    let absolute = |offset: u32| -> u32 {
        if offset == 0 {
            0
        } else {
            quorum_expiry.saturating_add(offset)
        }
    };

    let tiers = if n <= 2 {
        vec![
            ThresholdTier::new(2, false, absolute(0), "Both quorum members required"),
            ThresholdTier::new(
                1,
                false,
                absolute(720),
                "Single quorum member after expiry+5d",
            ),
            ThresholdTier::new(1, true, absolute(8064), "Operator only after expiry+8w"),
        ]
    } else {
        let majority = (n / 2) + 1;
        vec![
            ThresholdTier::new(
                majority,
                false,
                absolute(0),
                &format!("{}-of-{} quorum (anytime)", majority, n),
            ),
            ThresholdTier::new(
                minority,
                false,
                absolute(720),
                &format!("{}-of-{} quorum after expiry+5d", minority, n),
            ),
            ThresholdTier::new(
                1,
                false,
                absolute(4032),
                "Single quorum member after expiry+4w",
            ),
            ThresholdTier::new(1, true, absolute(8064), "Operator only after expiry+8w"),
        ]
    };
    ThresholdConfig { tiers }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_known_names() {
        assert!(lookup("legacy").is_none());
        assert!(lookup("cltv-offset-literal").is_none());
        assert!(lookup("cltv-offset-v2").is_some());
        assert!(lookup(CURRENT).is_some());
        assert!(lookup("nope").is_none());
        assert!(lookup("").is_none());
    }

    #[test]
    fn resolve_falls_back_to_current() {
        assert_eq!(resolve_or_current(None).name, CURRENT);
        assert_eq!(resolve_or_current(Some("future-version")).name, CURRENT);
        assert_eq!(
            resolve_or_current(Some("cltv-offset-v2")).name,
            "cltv-offset-v2"
        );
    }

    #[test]
    fn minority_v5_is_n_minus_majority() {
        for (n, want) in [(3, 1), (4, 1), (5, 2), (6, 2), (7, 3), (8, 3), (9, 4)] {
            assert_eq!(recovery_minority(n), want, "n={n}");
            let cfg = (MINORITY_V5.tier_config_factory)(n, 800_000);
            assert_eq!(cfg.tiers[1].threshold, want);
            assert_eq!(cfg.tiers[1].timelock_blocks, 800_720);
        }
    }

    #[test]
    fn cltv_offset_v2_anchors_to_quorum_expiry() {
        // n=3, quorum_expiry=800_000 → tier 1 CLTV target = 800_720
        let cfg = (CLTV_OFFSET_V2.tier_config_factory)(3, 800_000);
        assert_eq!(cfg.tiers.len(), 4);
        assert_eq!(cfg.tiers[0].timelock_blocks, 0);
        assert_eq!(cfg.tiers[1].timelock_blocks, 800_720);
        assert_eq!(cfg.tiers[2].timelock_blocks, 804_032);
        assert_eq!(cfg.tiers[3].timelock_blocks, 808_064);
    }

    #[test]
    fn cltv_offset_v2_n_le_2_collapses_to_3_tiers() {
        let cfg = (CLTV_OFFSET_V2.tier_config_factory)(2, 800_000);
        assert_eq!(cfg.tiers.len(), 3);
        assert_eq!(cfg.tiers[0].timelock_blocks, 0);
        assert_eq!(cfg.tiers[1].timelock_blocks, 800_720);
        assert_eq!(cfg.tiers[2].timelock_blocks, 808_064);
    }
}
