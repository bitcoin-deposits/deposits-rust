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
//! Today's registry: just two entries, but the same plumbing handles
//! arbitrary future rulesets. See `tapscript_reserves` for the only
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
    ///   - `legacy` returns plain literals (1008/2016/4032),
    ///   - `cltv-offset-v2` returns `quorum_expiry + offset` so the
    ///     post-expiry cascade re-pins on each rotation.
    pub tier_config_factory: fn(n_voters: usize, quorum_expiry: u32) -> ThresholdConfig,
}

/// Look up a ruleset by name. `None` for unknown names; callers MUST
/// reject the QuorumBegin in that case (the operator is asking for a
/// ruleset this software doesn't know how to enforce).
pub fn lookup(name: &str) -> Option<&'static Ruleset> {
    match name {
        "legacy" => Some(&LEGACY),
        "cltv-offset-literal" => Some(&CLTV_OFFSET_LITERAL),
        "cltv-offset-v2" => Some(&CLTV_OFFSET_V2),
        "fee-cap-v3" => Some(&FEE_CAP_V3),
        "balance-commit-v4" => Some(&BALANCE_COMMIT_V4),
        _ => None,
    }
}

/// Resolve a name to a ruleset, defaulting to [`LEGACY`] when the name
/// is `None` or empty. This is the read path for QuorumBegins that
/// predate the `protocol_version` field — they describe the original
/// production cascade, which is what `legacy` encodes.
pub fn resolve_or_legacy(name: Option<&str>) -> &'static Ruleset {
    match name {
        None => &LEGACY,
        Some("") => &LEGACY,
        Some(s) => lookup(s).unwrap_or(&LEGACY),
    }
}

/// All ruleset names this binary knows how to enforce. Order is the
/// registry order. Quorum members publish this in their signed
/// `QuorumMemberResponse` so an operator can pick a `protocol_version`
/// at `quorum begin` time that every member can validate.
pub fn all_supported_names() -> Vec<&'static str> {
    vec![
        LEGACY.name,
        CLTV_OFFSET_LITERAL.name,
        CLTV_OFFSET_V2.name,
        FEE_CAP_V3.name,
        BALANCE_COMMIT_V4.name,
    ]
}

/// Decide whether a candidate member's declared `supported_rulesets`
/// covers `target`. Treats an empty list as "supports legacy only" —
/// the only ruleset that existed for pre-Q2 `QuorumAddMember` records
/// that lack a signed response blob.
///
/// Used by `quorum begin` to refuse rotating into a ruleset some
/// pending member can't validate under, since that would silently
/// break their ability to cosign for the rest of the quorum's life.
pub fn member_supports(declared: &[String], target: &str) -> bool {
    if declared.is_empty() {
        return target == LEGACY.name;
    }
    declared.iter().any(|s| s == target)
}

#[cfg(test)]
mod gating_tests {
    use super::*;

    #[test]
    fn empty_list_means_legacy_only() {
        assert!(member_supports(&[], "legacy"));
        assert!(!member_supports(&[], "cltv-offset-v2"));
        assert!(!member_supports(&[], "future-version"));
    }

    #[test]
    fn explicit_list_is_authoritative() {
        let v2 = vec!["cltv-offset-v2".to_string()];
        assert!(member_supports(&v2, "cltv-offset-v2"));
        // Even though "legacy" is the catch-all default, an explicit
        // list that omits it is honored verbatim — the member is opting
        // out of legacy.
        assert!(!member_supports(&v2, "legacy"));
    }

    #[test]
    fn list_with_multiple_entries() {
        let both = vec!["legacy".to_string(), "cltv-offset-v2".to_string()];
        assert!(member_supports(&both, "legacy"));
        assert!(member_supports(&both, "cltv-offset-v2"));
        assert!(!member_supports(&both, "unknown"));
    }
}

// ============================================================================
// Registry entries
// ============================================================================

/// Pre-`protocol_version` cascade. `OP_CLTV <literal>` with absolute
/// block heights 1008 / 2016 / 4032. Originally intended as relative
/// timelocks (~1 week / 2 weeks / 4 weeks) but the original code emits
/// CLTV (absolute), which means on mainnet (where `chain_tip ≫ 4032`)
/// every post-expiry tier is *immediately* spendable by anyone holding
/// a key in the corresponding subset. **All on-chain reserves UTXOs
/// produced before `protocol_version` was introduced are governed by
/// this ruleset** — that's the correct shape for reconstructing them.
pub static LEGACY: Ruleset = Ruleset {
    name: "legacy",
    tier_config_factory: legacy_tier_config,
};

/// Intermediate cascade: same 4-tier shape as `cltv-offset-v2`
/// (majority / minority / single / operator) but `OP_CLTV` targets are
/// **literal** 720 / 4032 / 8064 — *not* anchored to `quorum_expiry +
/// offset`. Used by code between commits `c075cc0` (May 7 2026, when
/// the tier redesign landed) and `8ae1c3a` (May 11 2026, when the
/// ruleset registry switched the literals to absolute offsets). UTXOs
/// built in that ~5-day window need this ruleset to reconstruct.
///
/// On mainnet the literal targets 720/4032/8064 are below `chain_tip`
/// the moment the cascade was deployed, so every post-expiry tier is
/// effectively no-op-CLTV — same security hole as `legacy`. Rotating
/// off this ruleset closes it the same way as rotating off legacy.
pub static CLTV_OFFSET_LITERAL: Ruleset = Ruleset {
    name: "cltv-offset-literal",
    tier_config_factory: cltv_offset_literal_tier_config,
};

/// Post-redesign cascade: `OP_CLTV <quorum_expiry + offset>`. The
/// post-expiry tiers re-pin to the new deadline on every rotation, so
/// the security model survives long-lived UTXOs. Operator demoted to
/// last in the cascade. See DEP-03 §"Spending Tiers".
///
/// Use for new ledgers and when rotating off `legacy` to close the
/// no-op-timelock vulnerability.
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

// ============================================================================
// Factories
// ============================================================================

fn legacy_tier_config(n: usize, _quorum_expiry: u32) -> ThresholdConfig {
    let tiers = if n <= 2 {
        vec![
            ThresholdTier::new(2, false, 0, "Both quorum members required"),
            ThresholdTier::new(1, true, 2016, "Operator only after 2016 blocks"),
            ThresholdTier::emergency_recovery(4032),
        ]
    } else {
        let majority = (n / 2) + 1;
        let minority = (n / 3).max(1);
        vec![
            ThresholdTier::new(
                majority,
                false,
                0,
                &format!("{}-of-{} quorum (immediate)", majority, n),
            ),
            ThresholdTier::new(
                minority,
                false,
                1008,
                &format!("{}-of-{} quorum (after 1008 blocks)", minority, n),
            ),
            ThresholdTier::new(1, true, 2016, "Operator only (after 2016 blocks)"),
            ThresholdTier::emergency_recovery(4032),
        ]
    };
    ThresholdConfig { tiers }
}

/// Pre-anchor variant of the v2 cascade. Mirrors `c075cc0` exactly:
/// 4 tiers (or 3 for n≤2) with the timelocks expressed as **literal**
/// block heights — `720 / 4032 / 8064` for the post-expiry tiers
/// instead of `quorum_expiry + offset`. Used by reconstruction to
/// match UTXOs built between commits `c075cc0` and `8ae1c3a`.
fn cltv_offset_literal_tier_config(n: usize, _quorum_expiry: u32) -> ThresholdConfig {
    let tiers = if n <= 2 {
        vec![
            ThresholdTier::new(2, false, 0, "Both quorum members required"),
            ThresholdTier::new(1, false, 720, "Single quorum member after expiry+5d"),
            ThresholdTier::new(1, true, 8064, "Operator only after expiry+8w"),
        ]
    } else {
        let majority = (n / 2) + 1;
        let minority = (n / 3).max(1);
        vec![
            ThresholdTier::new(
                majority,
                false,
                0,
                &format!("{}-of-{} quorum (anytime)", majority, n),
            ),
            ThresholdTier::new(
                minority,
                false,
                720,
                &format!("{}-of-{} quorum after expiry+5d", minority, n),
            ),
            ThresholdTier::new(1, false, 4032, "Single quorum member after expiry+4w"),
            ThresholdTier::new(1, true, 8064, "Operator only after expiry+8w"),
        ]
    };
    ThresholdConfig { tiers }
}

fn cltv_offset_v2_tier_config(n: usize, quorum_expiry: u32) -> ThresholdConfig {
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
        let minority = (n / 3).max(1);
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
        assert!(lookup("legacy").is_some());
        assert!(lookup("cltv-offset-v2").is_some());
        assert!(lookup("nope").is_none());
        assert!(lookup("").is_none());
    }

    #[test]
    fn resolve_or_legacy_defaults_to_legacy() {
        assert_eq!(resolve_or_legacy(None).name, "legacy");
        assert_eq!(resolve_or_legacy(Some("")).name, "legacy");
        assert_eq!(resolve_or_legacy(Some("legacy")).name, "legacy");
        assert_eq!(
            resolve_or_legacy(Some("cltv-offset-v2")).name,
            "cltv-offset-v2"
        );
        // Unknown name falls back to legacy rather than blowing up. The
        // QuorumBegin acceptance path must reject unknown names BEFORE
        // calling this helper; this is just the post-validation
        // resolution step.
        assert_eq!(resolve_or_legacy(Some("future-version")).name, "legacy");
    }

    #[test]
    fn legacy_tiers_match_pre_versioned_production_shape() {
        // n=3: majority=2, minority=1. The shape that produced every
        // QuorumBegin currently on relay.bitcoindeposits.net.
        let cfg = (LEGACY.tier_config_factory)(3, 800_000);
        assert_eq!(cfg.tiers.len(), 4);
        assert_eq!(cfg.tiers[0].threshold, 2);
        assert_eq!(cfg.tiers[0].timelock_blocks, 0);
        assert_eq!(cfg.tiers[1].timelock_blocks, 1008);
        assert_eq!(cfg.tiers[2].timelock_blocks, 2016);
        assert_eq!(cfg.tiers[3].timelock_blocks, 4032);
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
