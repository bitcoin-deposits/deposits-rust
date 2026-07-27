//! Cosigner-edge verification of replacement collateral declared in
//! `DisputeArmed`. See DEP-03 §"Replacement collateral declaration".
//!
//! At confiscation cosign time, every cosigner runs the disputant's
//! declared `replacement_collateral` through this module before signing.
//! A cosigner that observes any disputant's declaration failing must
//! refuse to sign — the dispute then stalls until the failing disputant
//! re-arms with a sufficient UTXO or is excluded by arm-window timeout.

/// Per-cosigner policy for the inequality check.
#[derive(Clone, Copy, Debug)]
pub struct CollateralPolicy {
    /// Minimum confirmations the cosigner requires on the declared UTXO.
    /// 0 admits mempool entries; 1 requires the UTXO to be in a block.
    pub min_confirmations: u32,
    /// Sats of fee budget added to the inequality. Default 5_000 sats
    /// (~25 sat/vB × ~200 vB for a multi-input claim TX).
    pub claim_fee_estimate_sats: u64,
}

impl Default for CollateralPolicy {
    fn default() -> Self {
        Self {
            min_confirmations: 1,
            claim_fee_estimate_sats: 5_000,
        }
    }
}

/// Decision on a single disputant's declaration.
#[derive(Debug, PartialEq, Eq)]
pub enum CollateralCheck {
    Ok,
    /// `DisputeArmed` did not carry a `replacement_collateral` field.
    /// New producers MUST populate it; legacy events without it cause
    /// strict cosigners to refuse confiscation.
    NoDeclaration,
    /// The declared outpoint is not on-chain, is spent, or has fewer
    /// confirmations than `policy.min_confirmations`.
    OutpointUnavailable,
    /// On-chain outpoint exists but its value is below the disputant's
    /// declared `amount` (they're claiming to commit more than the UTXO
    /// holds).
    UndersizedUtxo {
        actual_sats: u64,
        declared_sats: u64,
    },
    /// Inequality fails: the declared amount doesn't cover the required
    /// floor `obligations × ratio + fee`.
    InsufficientAmount {
        required_sats: u64,
        declared_sats: u64,
    },
}

/// Compute the minimum replacement amount (sats) that satisfies the
/// post-takeover collateralization inequality from DEP-03:
///
/// ```text
/// required = obligations × (collateral_at_qb / reserves_at_qb) + fee
/// ```
///
/// Inputs are in millisatoshis (the on-the-wire unit for ledger amounts);
/// the result is converted to sats since on-chain UTXOs are
/// sat-denominated.
///
/// Returns `None` when `reserves_msat == 0` — the divisor would explode,
/// and that condition shouldn't occur on an established ledger that's
/// reached `QuorumBegin`.
pub fn compute_required_replacement_sats(
    obligations_msat: u64,
    collateral_at_qb_msat: u64,
    reserves_at_qb_msat: u64,
    policy: &CollateralPolicy,
) -> Option<u64> {
    if reserves_at_qb_msat == 0 {
        return None;
    }
    // u128 to avoid intermediate overflow on
    // `obligations × collateral` for realistic values.
    let scaled = (obligations_msat as u128).saturating_mul(collateral_at_qb_msat as u128)
        / (reserves_at_qb_msat as u128);
    // msat → sat (round up so the cosigner errs on the strict side).
    let required_sats = ((scaled + 999) / 1000) as u64;
    Some(required_sats.saturating_add(policy.claim_fee_estimate_sats))
}

/// Pure inequality test, separated from I/O so it can be unit-tested.
pub fn check_inequality(declared_sats: u64, required_sats: u64) -> CollateralCheck {
    if declared_sats < required_sats {
        CollateralCheck::InsufficientAmount {
            required_sats,
            declared_sats,
        }
    } else {
        CollateralCheck::Ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inequality_passes_when_declared_meets_floor() {
        let r = check_inequality(30_000, 30_000);
        assert_eq!(r, CollateralCheck::Ok);
    }

    #[test]
    fn inequality_fails_when_declared_short() {
        let r = check_inequality(29_999, 30_000);
        assert_eq!(
            r,
            CollateralCheck::InsufficientAmount {
                required_sats: 30_000,
                declared_sats: 29_999
            }
        );
    }

    #[test]
    fn ratio_preserved_at_constant_obligations() {
        // Quorum opened with 30% collateral on 100 sats reserves (in msat).
        // Obligations stayed at 100 sats. Required collateral = 30 sats + fee.
        let policy = CollateralPolicy {
            min_confirmations: 0,
            claim_fee_estimate_sats: 1_000,
        };
        let req = compute_required_replacement_sats(
            100_000_000, // obligations msat
            30_000_000,  // collateral at QB msat
            100_000_000, // reserves at QB msat
            &policy,
        )
        .unwrap();
        assert_eq!(req, 30_000 + 1_000);
    }

    #[test]
    fn ratio_scales_with_growing_obligations() {
        // Same 30% ratio but obligations doubled to 200 sats. Required
        // collateral scales to 60 sats + fee.
        let policy = CollateralPolicy {
            min_confirmations: 0,
            claim_fee_estimate_sats: 1_000,
        };
        let req = compute_required_replacement_sats(200_000_000, 30_000_000, 100_000_000, &policy)
            .unwrap();
        assert_eq!(req, 60_000 + 1_000);
    }

    #[test]
    fn ratio_scales_down_with_shrinking_obligations() {
        // Obligations shrunk to 50 sats. Required scales down to 15 + fee.
        let policy = CollateralPolicy {
            min_confirmations: 0,
            claim_fee_estimate_sats: 1_000,
        };
        let req = compute_required_replacement_sats(50_000_000, 30_000_000, 100_000_000, &policy)
            .unwrap();
        assert_eq!(req, 15_000 + 1_000);
    }

    #[test]
    fn zero_reserves_returns_none() {
        let policy = CollateralPolicy::default();
        assert!(compute_required_replacement_sats(100, 30, 0, &policy).is_none());
    }
}
