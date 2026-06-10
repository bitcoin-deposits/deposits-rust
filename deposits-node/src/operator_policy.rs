//! Operator-side fee/limits policy persisted to `<data_dir>/operator_policy.json`.
//!
//! Today this file IS the source of truth for the operator's advertised fee
//! schedule. `ledger advertise` reads it as defaults (CLI flags override and
//! write back), `process_deposit_open_request` reads it to enforce minimums on
//! incoming deposits.
//!
//! The shape is deliberately thin so the storage backend can be swapped later.
//! North-star design: this struct moves to a NIP-44 encrypted self-DM keyed by
//! the operator's nsec, with the local file becoming an optional cache. Until
//! then, the file is authoritative and the relay-fetched advertisement is a
//! fallback only when the file is missing (e.g., on a fresh container before
//! the operator has set anything).

use serde::{Deserialize, Serialize};
use std::path::Path;

/// File name within `data_dir`. Public so tests can reference the same path.
pub const POLICY_FILENAME: &str = "operator_policy.json";

/// The DEP-16 capability set this build of the node advertises in Kind 39100,
/// projected to its wire shape ([`deposits_nostr::AdvertisedCapabilities`]).
///
/// Source of truth: `CapabilitySet::everything()` (every primitive the calculus
/// in `third_party/rust-miniscript` implements) → string-projected via
/// [`deposits_core::dep16::capability_set_to_wire_strings`]. As the calculus
/// grows new primitives, this helper grows with it — no manual list-keeping.
///
/// Operators who want to advertise a subset (e.g., omit `attest` until their
/// attestor infrastructure is ready) can construct a custom
/// `AdvertisedCapabilities` and assign it to the ad directly after calling
/// `LedgerAdvertisement::new`. This helper is the default.
pub fn default_advertised_capabilities() -> deposits_nostr::AdvertisedCapabilities {
    let set = deposits_core::dep16::CapabilitySet::everything();
    let (obligations, state_preds, value_fns) =
        deposits_core::dep16::capability_set_to_wire_strings(&set);
    deposits_nostr::AdvertisedCapabilities {
        obligations,
        state_preds,
        value_fns,
    }
}

/// Operator-side advertised policy. Mirrors the subset of `LedgerAdvertisement`
/// fields the operator chooses (everything else on the ad is derived from
/// ledger state or wallet state). All optional so a partial policy is valid.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct OperatorPolicy {
    /// Human-readable name for the operator. Shown to wallets in
    /// `ledger discover` output.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_name: Option<String>,

    /// Description of the operator's service.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    // === Fee schedule ===
    /// Annual custody fee in basis points (e.g. 50 = 0.5%/year).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annual_fee_bps: Option<u32>,

    /// Annualized fixed periodic fee (msats/year).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annualized_fixed_msats: Option<u64>,

    /// Fee collection period in blocks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fee_period_blocks: Option<u32>,

    /// One-time fee on deposits, basis points.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deposit_fee_bps: Option<u32>,

    /// Fee on withdrawals, basis points.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withdrawal_fee_bps: Option<u32>,

    /// Fee per Lightning invoice payment, basis points.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invoice_fee_bps: Option<u32>,

    /// Fixed per-transfer fee in msats.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transfer_fee_fixed_msats: Option<u64>,

    /// Proportional per-transfer fee in basis points.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transfer_fee_rate_bps: Option<u16>,

    // === Deposit-size limits ===
    /// Maximum single deposit size in msats.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_deposit_msats: Option<u64>,

    /// Minimum deposit size in msats.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_deposit_msats: Option<u64>,

    // === Discovery ===
    /// Relay URL to publish advertisements to (overrides the daemon's default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advertise_relay: Option<String>,
}

impl OperatorPolicy {
    /// Path to the policy file inside `data_dir`.
    pub fn path(data_dir: &Path) -> std::path::PathBuf {
        data_dir.join(POLICY_FILENAME)
    }

    /// Load the policy from disk. Returns `Ok(None)` when the file is missing
    /// — distinct from `Err` for "couldn't read/parse." Callers that want
    /// strict behavior (e.g., refuse to start without a policy) check for
    /// `None` explicitly.
    pub fn load(data_dir: &Path) -> Result<Option<Self>, std::io::Error> {
        let path = Self::path(data_dir);
        if !path.exists() {
            return Ok(None);
        }
        let raw = std::fs::read_to_string(&path)?;
        let policy: Self = serde_json::from_str(&raw)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(Some(policy))
    }

    /// Persist the policy to disk. Creates `data_dir` if needed.
    pub fn save(&self, data_dir: &Path) -> Result<(), std::io::Error> {
        std::fs::create_dir_all(data_dir)?;
        let path = Self::path(data_dir);
        let pretty = serde_json::to_string_pretty(self).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, e)
        })?;
        std::fs::write(&path, pretty)
    }

    /// Overlay fee-schedule CLI args onto the policy. Fields that the user
    /// didn't set on the command line stay at their existing value (or
    /// remain `None` if they were never set). Returns `true` if at least
    /// one CLI flag was applied — caller uses that to decide whether to
    /// persist the updated policy back to disk.
    pub fn overlay_fee_args(
        &mut self,
        args: &crate::node_cli::FeeScheduleArgs,
    ) -> bool {
        let mut touched = false;
        if let Some(v) = args.annual_fee_bps {
            self.annual_fee_bps = Some(v);
            touched = true;
        }
        if let Some(v) = args.annualized_fixed_msats {
            self.annualized_fixed_msats = Some(v);
            touched = true;
        }
        if let Some(v) = args.fee_period_blocks {
            self.fee_period_blocks = Some(v);
            touched = true;
        }
        if let Some(v) = args.deposit_fee_bps {
            self.deposit_fee_bps = Some(v);
            touched = true;
        }
        if let Some(v) = args.withdrawal_fee_bps {
            self.withdrawal_fee_bps = Some(v);
            touched = true;
        }
        if let Some(v) = args.invoice_fee_bps {
            self.invoice_fee_bps = Some(v);
            touched = true;
        }
        if let Some(v) = args.transfer_fee_fixed {
            self.transfer_fee_fixed_msats = Some(v);
            touched = true;
        }
        if let Some(v) = args.transfer_fee_rate_bps {
            self.transfer_fee_rate_bps = Some(v);
            touched = true;
        }
        if let Some(v) = args.max_deposit_msats {
            self.max_deposit_msats = Some(v);
            touched = true;
        }
        if let Some(v) = args.min_deposit_msats {
            self.min_deposit_msats = Some(v);
            touched = true;
        }
        if let Some(v) = args.advertise_relay.clone() {
            self.advertise_relay = Some(v);
            touched = true;
        }
        touched
    }

    /// Operator's minimum fees for `validate_fee_minimum`. Falls back to
    /// `(0, 0)` when the field isn't set — `(0, 0)` means "no floor", the
    /// same semantics as the previous relay-fetched-zero-on-missing ad.
    pub fn minimum_fees(&self) -> (u16, u64) {
        let bps = self.annual_fee_bps.unwrap_or(0).min(u16::MAX as u32) as u16;
        let blocks_per_year: u64 = 52560;
        let period = self.fee_period_blocks.unwrap_or(2016).max(1) as u64;
        let periods_per_year = blocks_per_year / period;
        let fixed_per_period = if periods_per_year > 0 {
            self.annualized_fixed_msats.unwrap_or(0) / periods_per_year
        } else {
            0
        };
        (bps, fixed_per_period)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn round_trip_empty() {
        let dir = tempdir().unwrap();
        let policy = OperatorPolicy::default();
        policy.save(dir.path()).unwrap();
        let loaded = OperatorPolicy::load(dir.path()).unwrap().unwrap();
        assert_eq!(policy, loaded);
    }

    #[test]
    fn round_trip_populated() {
        let dir = tempdir().unwrap();
        let policy = OperatorPolicy {
            operator_name: Some("alice".into()),
            annual_fee_bps: Some(50),
            annualized_fixed_msats: Some(1_000_000),
            fee_period_blocks: Some(4032),
            ..Default::default()
        };
        policy.save(dir.path()).unwrap();
        let loaded = OperatorPolicy::load(dir.path()).unwrap().unwrap();
        assert_eq!(policy, loaded);
    }

    #[test]
    fn missing_file_returns_none() {
        let dir = tempdir().unwrap();
        let loaded = OperatorPolicy::load(dir.path()).unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn minimum_fees_unset_is_zero() {
        let p = OperatorPolicy::default();
        assert_eq!(p.minimum_fees(), (0, 0));
    }

    #[test]
    fn minimum_fees_with_values() {
        // 50 bps annual, 26280 msats fixed (over 2016-block periods → 13140
        // periods/year wait that's not right). Let me be deliberate:
        // annual_fixed = 26280 msats/year, period = 2016 blocks (~2 weeks).
        // blocks_per_year = 52560 → 26 periods/year → 26280/26 = 1010 msats/period.
        let p = OperatorPolicy {
            annual_fee_bps: Some(50),
            annualized_fixed_msats: Some(26_280),
            fee_period_blocks: Some(2016),
            ..Default::default()
        };
        let (bps, fixed) = p.minimum_fees();
        assert_eq!(bps, 50);
        assert_eq!(fixed, 1010);
    }
}
