//! Operator-side "liquidity drip" plans persisted to
//! `<data_dir>/operator_drips.json`.
//!
//! A drip is a defense against single-depositor liquidity exhaustion.
//! The operator opens a self-owned deposit (sized so it ties up a chunk
//! of their reserves as obligation), then progressively withdraws from
//! it at a configured cadence. Every tick frees that much reserve
//! capacity back to the operator's general pool — slow enough that no
//! single counterparty can race in and claim it all in one go.
//!
//! Driven by `auto_drip_self_liquidity` in the periodic main loop.
//! Plans live in a thin JSON file alongside `operator_policy.json` so
//! ops tooling can read/diff/back-up them with the rest of the
//! operator's stateful config.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// File name within `data_dir`. Public so tests can reference it.
pub const DRIPS_FILENAME: &str = "operator_drips.json";

/// First BIP-32 child index used for drip-plan deposit keys. Chosen so
/// drip indices never collide with customer wallet deposits (0..) or
/// buffer deposits (1_000_000..). See
/// `request_handlers::admin::next_buffer_index` for the buffer base.
pub const DRIP_INDEX_BASE: u32 = 2_000_000;

/// A single liquidity-drip plan. Identified by `alias` (the plan-level
/// human-readable name); the operator-as-depositor's deposit gets the
/// same alias inside the on-ledger deposit record so manual inspection
/// via `deposits-wallet list` lines up.
///
/// The plan is purely operator-side bookkeeping — cosigners don't see
/// it and don't enforce the cadence. The withdraw + deposit-open
/// operations the drip emits go through the normal protocol paths and
/// are accounted for by the existing rules.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DripPlan {
    /// Human-readable plan name; primary key. Unique within the file.
    pub alias: String,

    /// Operator's own ledger that hosts the self-deposit. Must be one
    /// the operator owns (validated at plan-creation time).
    pub ledger_id: String,

    /// Target size of the self-deposit at open. Once drained to zero,
    /// the plan stops ticking (no auto-refill — the operator can
    /// remove + re-create if they want a fresh cycle).
    pub target_deposit_sats: u64,

    /// Amount withdrawn per tick. Drains the deposit balance by this
    /// much, freeing the same amount of reserves.
    pub decrement_sats: u64,

    /// Seconds between ticks. Not block-bound — this is purely
    /// operator-side scheduling.
    pub interval_sec: u64,

    /// Optional ± jitter on the interval, in seconds. When > 0, each
    /// successful tick rolls a fresh delay of
    /// `interval_sec + uniform(-interval_fuzz_sec, +interval_fuzz_sec)`
    /// (clamped to at least 1 sec) and stores the resulting absolute
    /// `next_tick_unix`. Makes the release schedule unpredictable to
    /// an attacker who's watching balances — they can no longer assume
    /// "next release lands at last_tick + interval."
    ///
    /// 0 (default) means strict periodic, no fuzz.
    #[serde(default)]
    pub interval_fuzz_sec: u64,

    /// BIP-32 child index used to derive the depositor key for this
    /// drip's self-deposit (via `KeyPath::Deposit { index }`). Assigned
    /// at plan-creation time from the `DRIP_INDEX_BASE` (2_000_000+)
    /// range to avoid collisions with both customer wallet keys
    /// (0..1M) and buffer-deposit keys (1M..2M).
    pub key_index: u32,

    /// When true, the auto-task skips this plan. Set via
    /// `liquidity drip-pause`; cleared via `drip-resume`.
    #[serde(default)]
    pub paused: bool,

    /// Unix timestamp when the plan was created (seconds).
    pub created_unix: u64,

    /// Unix timestamp of the last successful tick (seconds). 0 means
    /// "never ticked." Surfaced via the admin API for ops visibility;
    /// the actual due-time decision uses `next_tick_unix` so the fuzz
    /// schedule survives daemon restarts.
    #[serde(default)]
    pub last_tick_unix: u64,

    /// Absolute unix timestamp when the next tick should fire. Rolled
    /// at each successful tick from `now + interval_sec + fuzz`. 0
    /// means "never rolled" — first tick fires immediately on the next
    /// auto-task cycle. Persisting it (rather than recomputing) keeps
    /// the fuzz schedule stable across daemon restarts so an attacker
    /// can't force a fresh roll by triggering a restart.
    #[serde(default)]
    pub next_tick_unix: u64,

    /// Deposit ID of the self-deposit, once opened. Populated by the
    /// auto-task on first tick. `None` means the plan is registered
    /// but the deposit hasn't been opened yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deposit_id: Option<String>,

    /// Number of successful withdraw ticks fired since plan creation.
    /// Surfaced via the admin API for ops visibility.
    #[serde(default)]
    pub ticks_completed: u64,
}

impl DripPlan {
    /// True if the next scheduled tick is due (or none has been
    /// scheduled yet — first tick fires immediately). Caller still
    /// has to check `paused` and deposit balance separately.
    pub fn is_due(&self, now_unix: u64) -> bool {
        if self.next_tick_unix == 0 {
            return true;
        }
        now_unix >= self.next_tick_unix
    }

    /// Roll the next-tick timestamp from `now` using the configured
    /// interval + ± fuzz. Caller passes a 64-bit random source so the
    /// jitter is real entropy, not predictable from plan state.
    /// Clamps the actual delay to at least 1 second so a (large fuzz,
    /// small interval) combo can't produce zero or negative waits.
    pub fn next_tick_at(&self, now_unix: u64, random_u64: u64) -> u64 {
        let delay = if self.interval_fuzz_sec == 0 {
            self.interval_sec
        } else {
            let span = self.interval_fuzz_sec.saturating_mul(2).saturating_add(1);
            let offset = random_u64 % span;
            // offset ∈ [0, 2*fuzz]; subtract fuzz so jitter ∈ [-fuzz, +fuzz]
            let jitter = offset as i128 - self.interval_fuzz_sec as i128;
            let raw = self.interval_sec as i128 + jitter;
            raw.max(1) as u64
        };
        now_unix.saturating_add(delay)
    }
}

/// Registry of all drip plans on this operator. Wraps the JSON file
/// with atomic load + save semantics; in-memory mutations go through
/// `save_to` to persist.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DripRegistry {
    #[serde(default)]
    pub plans: Vec<DripPlan>,
}

impl DripRegistry {
    /// Path to the registry file inside `data_dir`.
    pub fn path(data_dir: &Path) -> std::path::PathBuf {
        data_dir.join(DRIPS_FILENAME)
    }

    /// Load the registry from disk. Returns an empty registry when
    /// the file is missing — drips are opt-in and absence is the
    /// expected default state. Distinct from `Err`, which only fires
    /// on a malformed file the operator should look at.
    pub fn load(data_dir: &Path) -> Result<Self, std::io::Error> {
        let path = Self::path(data_dir);
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = std::fs::read_to_string(&path)?;
        serde_json::from_str(&raw)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    /// Atomically persist the registry. Writes to `<file>.tmp` first,
    /// then renames — survives a crash mid-write.
    pub fn save(&self, data_dir: &Path) -> Result<(), std::io::Error> {
        std::fs::create_dir_all(data_dir)?;
        let path = Self::path(data_dir);
        let tmp = path.with_extension("json.tmp");
        let pretty = serde_json::to_string_pretty(self).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, e)
        })?;
        std::fs::write(&tmp, pretty)?;
        std::fs::rename(&tmp, &path)
    }

    /// Find a plan by alias.
    pub fn find(&self, alias: &str) -> Option<&DripPlan> {
        self.plans.iter().find(|p| p.alias == alias)
    }

    /// Find a mutable plan by alias.
    pub fn find_mut(&mut self, alias: &str) -> Option<&mut DripPlan> {
        self.plans.iter_mut().find(|p| p.alias == alias)
    }

    /// Next unused key index in the drip range. Picks
    /// `max(DRIP_INDEX_BASE, max_used + 1)` so removed-and-recreated
    /// plans don't re-derive an old key (avoids accidentally re-using
    /// a depositor identity whose deposit_id is still on the ledger).
    pub fn next_key_index(&self) -> u32 {
        let max_used = self
            .plans
            .iter()
            .map(|p| p.key_index)
            .filter(|&i| i >= DRIP_INDEX_BASE)
            .max();
        max_used.map(|i| i + 1).unwrap_or(DRIP_INDEX_BASE)
    }

    /// Insert a new plan. Returns `Err` if the alias is already taken.
    pub fn insert(&mut self, plan: DripPlan) -> Result<(), String> {
        if self.find(&plan.alias).is_some() {
            return Err(format!("drip plan with alias '{}' already exists", plan.alias));
        }
        self.plans.push(plan);
        Ok(())
    }

    /// Remove a plan by alias. Returns the removed plan or `None` if
    /// no plan matched.
    pub fn remove(&mut self, alias: &str) -> Option<DripPlan> {
        let idx = self.plans.iter().position(|p| p.alias == alias)?;
        Some(self.plans.remove(idx))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_plan(alias: &str) -> DripPlan {
        DripPlan {
            alias: alias.into(),
            ledger_id: "a".repeat(64),
            target_deposit_sats: 10_000_000,
            decrement_sats: 1_000,
            interval_sec: 60,
            interval_fuzz_sec: 0,
            key_index: DRIP_INDEX_BASE,
            paused: false,
            created_unix: 1_700_000_000,
            last_tick_unix: 0,
            next_tick_unix: 0,
            deposit_id: None,
            ticks_completed: 0,
        }
    }

    #[test]
    fn next_key_index_starts_at_base() {
        let r = DripRegistry::default();
        assert_eq!(r.next_key_index(), DRIP_INDEX_BASE);
    }

    #[test]
    fn next_key_index_advances_past_max() {
        let mut r = DripRegistry::default();
        let mut p = sample_plan("a");
        p.key_index = DRIP_INDEX_BASE + 5;
        r.insert(p).unwrap();
        assert_eq!(r.next_key_index(), DRIP_INDEX_BASE + 6);
    }

    #[test]
    fn is_due_first_tick() {
        let p = sample_plan("x");
        assert!(p.is_due(1));
    }

    #[test]
    fn is_due_respects_next_tick() {
        let mut p = sample_plan("x");
        p.next_tick_unix = 1_060;
        assert!(!p.is_due(1_030));
        assert!(p.is_due(1_060));
        assert!(p.is_due(1_120));
    }

    #[test]
    fn next_tick_at_with_zero_fuzz_is_strict() {
        let p = sample_plan("x");
        assert_eq!(p.next_tick_at(100, 12345), 160);
        assert_eq!(p.next_tick_at(100, 99999), 160);
    }

    #[test]
    fn next_tick_at_with_fuzz_stays_in_range() {
        let mut p = sample_plan("x");
        p.interval_fuzz_sec = 10; // ±10s on a 60s interval → [50, 70]
        for r in [0u64, 1, 5, 10, 11, 20, 21, u64::MAX] {
            let t = p.next_tick_at(100, r);
            assert!(
                (100 + 50..=100 + 70).contains(&t),
                "rand={} produced t={}, outside [150, 170]",
                r,
                t
            );
        }
    }

    #[test]
    fn next_tick_at_clamps_below_one_second() {
        let mut p = sample_plan("x");
        p.interval_sec = 5;
        p.interval_fuzz_sec = 100; // would underflow without the clamp
        for r in 0u64..50 {
            let t = p.next_tick_at(100, r);
            assert!(t >= 101, "rand={} produced t={}, below now+1", r, t);
        }
    }

    #[test]
    fn insert_rejects_duplicate() {
        let mut r = DripRegistry::default();
        r.insert(sample_plan("x")).unwrap();
        assert!(r.insert(sample_plan("x")).is_err());
    }

    #[test]
    fn round_trip_save_load() {
        let tmp = std::env::temp_dir().join(format!("drips-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let mut r = DripRegistry::default();
        r.insert(sample_plan("alpha")).unwrap();
        r.insert(sample_plan("beta")).unwrap();
        r.save(&tmp).unwrap();
        let loaded = DripRegistry::load(&tmp).unwrap();
        assert_eq!(r, loaded);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn load_missing_returns_empty() {
        let tmp = std::env::temp_dir().join(format!("drips-missing-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let r = DripRegistry::load(&tmp).unwrap();
        assert!(r.plans.is_empty());
    }
}
