//! Tier-3 smoke: operator-side liquidity-drip auto-task.
//!
//! Asserts the full lifecycle by leaning on the registry's
//! `ticks_completed` counter as the end-to-end success signal:
//!
//!   1. Plan registered via `deposits-node liquidity drip-create`.
//!   2. Daemon's `auto_drip_self_liquidity` opens a buffer deposit
//!      on its next tick (`buffer_index` is populated).
//!   3. Subsequent tick credits target_deposit_sats (no direct
//!      observability — confirmed implicitly by the next step).
//!   4. Subsequent ticks drain `decrement_sats` each. The auto-task
//!      only bumps `ticks_completed` when the drain succeeds, and
//!      the drain has its own underfunded guard, so
//!      `ticks_completed >= 2` proves open + fund + 2 drain ticks
//!      all worked.
//!
//! Cross-check: `/api/ledgers` aggregate `deposits_total_msats`
//! should move by `target - ticks * decrement` (msats) between a
//! pre-drip snapshot and the post-ticks snapshot, isolating the
//! drip's contribution from any other ledger activity.
//!
//! Requires `./bin/setup.sh 3` and the daemon built with the
//! liquidity feature.
//!
//! Run with: `cargo test -p deposits-test --test liquidity_drip -- --ignored --nocapture`

use deposits_test::regtest::*;
use std::process::Command;
use std::time::{Duration, Instant};

/// How long to wait for each pipeline stage. Generous because the
/// daemon's periodic tick is 5-60s depending on --fast-poll; we
/// can't shorten it from the test side.
const STAGE_TIMEOUT: Duration = Duration::from_secs(180);

#[test]
#[ignore]
fn drip_self_liquidity_opens_funds_and_drains() {
    if !cluster_available() {
        eprintln!("skipping: cluster not running — start with ./bin/setup.sh 3");
        return;
    }

    let node = build_node_with_danger();
    let ledger_id = discover_op0_ledger();
    eprintln!("[setup] op0 ledger: {}…", &ledger_id[..16]);

    // Use a unique alias per run so re-runs against the same cluster
    // don't trip the "alias already exists" guard. Hex of the current
    // unix-second is enough disambiguation.
    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let alias = format!("drip-{}", suffix);

    // Tight cadence so 2+ ticks fit in the test budget.
    let initial_sats: u64 = 5_000;
    let decrement_sats: u64 = 1_000;
    let interval_sec: u64 = 10;

    // ── Pre-baseline: snapshot the aggregate deposits balance ──
    let baseline_msats = ledger_deposits_total_msats(&ledger_id);
    eprintln!(
        "[baseline] op0 ledger deposits_total = {} msats (pre-drip)",
        baseline_msats
    );

    // ── 1. Register the plan via the CLI ──
    eprintln!("[create] drip plan '{}' on op0", alias);
    let out = Command::new(&node)
        .args(["liquidity", "drip-create", &alias, &ledger_id])
        .args(["--initial-sats", &initial_sats.to_string()])
        .args(["--decrement-sats", &decrement_sats.to_string()])
        .args(["--interval-sec", &interval_sec.to_string()])
        .args(["--seed", op0_seed()])
        .args(["--data-dir", op0_data_dir().to_str().unwrap()])
        .args(["--network", "regtest"])
        .output()
        .expect("invoke deposits-node liquidity drip-create");
    assert!(
        out.status.success(),
        "drip-create failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    // ── 2. Wait for the daemon to open the buffer deposit ──
    eprintln!("[open]   waiting for daemon to allocate buffer_index");
    let opened = wait_for(STAGE_TIMEOUT, || plan_buffer_index(&alias).is_some());
    let buffer_index =
        plan_buffer_index(&alias).expect("daemon never populated buffer_index within 180s");
    assert!(
        opened,
        "daemon never opened the buffer deposit (alias={}, ledger={}…)",
        alias,
        &ledger_id[..16]
    );
    eprintln!("[open]   ✓ allocated buffer #{}", buffer_index);

    // ── 3+4. Wait for at least 2 drain ticks. ticks_completed only
    //         advances after fund landed (drain has an underfunded
    //         guard) AND the drain commit succeeded, so this is a
    //         single signal for open + fund + N drains. ──
    let want_ticks: u64 = 2;
    eprintln!("[ticks]  waiting for {} drain ticks", want_ticks);
    let drained = wait_for(STAGE_TIMEOUT, || plan_ticks_completed(&alias) >= want_ticks);
    let ticks_seen = plan_ticks_completed(&alias);
    assert!(
        drained,
        "daemon completed only {} of {} expected drain ticks (registry: alias={})",
        ticks_seen, want_ticks, alias,
    );
    eprintln!("[ticks]  ✓ {} drain ticks fired", ticks_seen);

    // ── 5. Cross-check: aggregate ledger deposits_total should have
    //       moved by exactly target - (ticks * decrement) msats vs the
    //       pre-baseline. Tolerate small movement from other deposits
    //       being credited/withdrawn between snapshots (none expected
    //       in this test, but be defensive). ──
    let target_msats = initial_sats * 1_000;
    let decrement_msats = decrement_sats * 1_000;
    let expected_delta_msats =
        target_msats as i128 - (ticks_seen as i128 * decrement_msats as i128);
    let after_msats = ledger_deposits_total_msats(&ledger_id);
    let actual_delta_msats = after_msats as i128 - baseline_msats as i128;
    eprintln!(
        "[verify] deposits_total {} → {} (delta={} msats, expected={} msats)",
        baseline_msats, after_msats, actual_delta_msats, expected_delta_msats
    );
    let drift = (actual_delta_msats - expected_delta_msats).abs();
    assert!(
        drift <= 1_000_000,
        "deposits_total delta {} drifted >1M msats from expected {} — \
         either drip math is wrong or another ledger op interfered",
        actual_delta_msats,
        expected_delta_msats,
    );

    eprintln!(
        "[pass]   drip plan '{}' lifecycle complete: open → fund → {} drain ticks, \
         deposits_total moved by ~{} msats",
        alias, ticks_seen, actual_delta_msats
    );
}

/// Verify `--interval-fuzz-sec` actually jitters tick spacing.
///
/// Approach: open a plan with a known fuzz, sample the rolled delay
/// (`next_tick_unix - last_tick_unix`) from the registry as each tick
/// completes. Reading from the registry (not wall-clock deltas)
/// sidesteps the polling-loop slop that would otherwise dominate
/// short intervals.
///
/// Assertions:
///   - Every rolled delay falls in `[interval - fuzz, interval + fuzz]`.
///   - At least one rolled delay differs from the strict interval —
///     proves the jitter is non-zero. With fuzz=8 on a 17-value domain,
///     P(all 4 samples == 15) ≈ (1/17)^4 ≈ 1.2e-5, so flakes are rare.
#[test]
#[ignore]
fn drip_interval_fuzz_jitters_tick_spacing() {
    if !cluster_available() {
        eprintln!("skipping: cluster not running — start with ./bin/setup.sh 3");
        return;
    }

    let node = build_node_with_danger();
    let ledger_id = discover_op0_ledger();
    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let alias = format!("fuzz-{}", suffix);

    let initial_sats: u64 = 10_000;
    let decrement_sats: u64 = 1_000;
    let interval_sec: u64 = 15;
    let fuzz_sec: u64 = 8;
    // Plenty of headroom so 5 ticks complete within the deadline.
    let want_samples: u64 = 4;

    eprintln!(
        "[create] '{}' interval={}s ± {}s fuzz, target={} sats",
        alias, interval_sec, fuzz_sec, initial_sats
    );
    let out = Command::new(&node)
        .args(["liquidity", "drip-create", &alias, &ledger_id])
        .args(["--initial-sats", &initial_sats.to_string()])
        .args(["--decrement-sats", &decrement_sats.to_string()])
        .args(["--interval-sec", &interval_sec.to_string()])
        .args(["--interval-fuzz-sec", &fuzz_sec.to_string()])
        .args(["--seed", op0_seed()])
        .args(["--data-dir", op0_data_dir().to_str().unwrap()])
        .args(["--network", "regtest"])
        .output()
        .expect("invoke deposits-node liquidity drip-create");
    assert!(
        out.status.success(),
        "drip-create failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    // Poll the registry, snapshotting the rolled delay each time
    // ticks_completed advances. Capture (last_tick_unix, next_tick_unix)
    // pairs so we can compute the rolled delay even after the plan's
    // state mutates on the following tick.
    let mut samples: Vec<u64> = Vec::new();
    let mut last_seen_ticks: u64 = 0;
    let deadline = Instant::now()
        + Duration::from_secs(
            // open + fund + want_samples ticks at worst-case (interval+fuzz) each + polling slop
            120 + want_samples * (interval_sec + fuzz_sec + 10),
        );
    while samples.len() < want_samples as usize && Instant::now() < deadline {
        if let Some((ticks, last, next)) = plan_tick_state(&alias) {
            if ticks > last_seen_ticks && last > 0 && next > last {
                let rolled = next - last;
                samples.push(rolled);
                eprintln!(
                    "[sample] tick {} rolled delay = {}s (last={} next={})",
                    ticks, rolled, last, next
                );
                last_seen_ticks = ticks;
            }
        }
        std::thread::sleep(Duration::from_millis(500));
    }

    assert!(
        samples.len() >= want_samples as usize,
        "only collected {} of {} samples within budget — daemon may be slow ticking or fuzz not wiring",
        samples.len(),
        want_samples
    );

    // Bounds check — every rolled delay must be in the configured window.
    let lo = interval_sec.saturating_sub(fuzz_sec).max(1);
    let hi = interval_sec + fuzz_sec;
    for (i, &s) in samples.iter().enumerate() {
        assert!(
            (lo..=hi).contains(&s),
            "sample {} = {}s outside [{}, {}] — bounds check failed",
            i,
            s,
            lo,
            hi,
        );
    }

    // Variance check — at least one sample differs from the strict
    // interval. Proves fuzz is actually active (not silently zero).
    let varied = samples.iter().any(|&s| s != interval_sec);
    assert!(
        varied,
        "all {} samples equal interval ({}s) — fuzz isn't taking effect. Samples: {:?}",
        samples.len(),
        interval_sec,
        samples,
    );

    eprintln!(
        "[pass]   fuzz active: {} samples in [{}, {}]s, range [{}, {}]s",
        samples.len(),
        lo,
        hi,
        samples.iter().min().unwrap(),
        samples.iter().max().unwrap()
    );
}

/// Read `(ticks_completed, last_tick_unix, next_tick_unix)` for the
/// named plan. Returns `None` if the plan or any field is missing.
fn plan_tick_state(alias: &str) -> Option<(u64, u64, u64)> {
    let path = op0_data_dir().join("operator_drips.json");
    let raw = std::fs::read_to_string(&path).ok()?;
    let v: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let plans = v.get("plans")?.as_array()?;
    for plan in plans {
        if plan.get("alias").and_then(|x| x.as_str()) == Some(alias) {
            return Some((
                plan.get("ticks_completed")
                    .and_then(|x| x.as_u64())
                    .unwrap_or(0),
                plan.get("last_tick_unix")
                    .and_then(|x| x.as_u64())
                    .unwrap_or(0),
                plan.get("next_tick_unix")
                    .and_then(|x| x.as_u64())
                    .unwrap_or(0),
            ));
        }
    }
    None
}

/// Block until `predicate` returns true or `timeout` elapses. Returns
/// whether the predicate ever fired.
fn wait_for(timeout: Duration, mut predicate: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if predicate() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    false
}

/// Read op0's `operator_drips.json` and pull the allocated
/// buffer_index for the named plan (`None` until the auto-task's
/// first cycle opens the buffer).
fn plan_buffer_index(alias: &str) -> Option<u32> {
    let path = op0_data_dir().join("operator_drips.json");
    let raw = std::fs::read_to_string(&path).ok()?;
    let v: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let plans = v.get("plans")?.as_array()?;
    for plan in plans {
        if plan.get("alias").and_then(|x| x.as_str()) == Some(alias) {
            return plan
                .get("buffer_index")
                .and_then(|x| x.as_u64())
                .map(|n| n as u32);
        }
    }
    None
}

/// Read op0's `operator_drips.json` and pull `ticks_completed` for
/// the named plan. Returns 0 if the plan or field is missing.
fn plan_ticks_completed(alias: &str) -> u64 {
    let path = op0_data_dir().join("operator_drips.json");
    let Some(raw) = std::fs::read_to_string(&path).ok() else {
        return 0;
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return 0;
    };
    let Some(plans) = v.get("plans").and_then(|p| p.as_array()) else {
        return 0;
    };
    for plan in plans {
        if plan.get("alias").and_then(|x| x.as_str()) == Some(alias) {
            return plan
                .get("ticks_completed")
                .and_then(|x| x.as_u64())
                .unwrap_or(0);
        }
    }
    0
}

/// Sum of all deposit balances on `ledger_id`, in msats, as reported
/// by op0's `/api/ledgers`. Returns 0 if the ledger isn't found or
/// the endpoint is unreachable.
fn ledger_deposits_total_msats(ledger_id: &str) -> u128 {
    let token_path = op0_data_dir().join("admin-token");
    let Ok(token) = std::fs::read_to_string(&token_path) else {
        return 0;
    };
    let token = token.trim();
    let url = format!("http://127.0.0.1:{}/api/ledgers", admin_port(0));
    let url = url.as_str();
    let resp = Command::new("curl")
        .args(["-s", "-H", &format!("Authorization: Bearer {}", token), url])
        .output()
        .ok();
    let Some(resp) = resp else { return 0 };
    let body = String::from_utf8_lossy(&resp.stdout);
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) else {
        return 0;
    };
    let Some(arr) = v.as_array() else { return 0 };
    for entry in arr {
        if entry.get("ledger_id").and_then(|x| x.as_str()) == Some(ledger_id) {
            // deposits_total_msats may serialize as a u128 (JSON number
            // or string depending on serde config). Accept either.
            if let Some(n) = entry.get("deposits_total_msats").and_then(|x| x.as_u64()) {
                return n as u128;
            }
            if let Some(s) = entry.get("deposits_total_msats").and_then(|x| x.as_str()) {
                return s.parse().unwrap_or(0);
            }
        }
    }
    0
}
