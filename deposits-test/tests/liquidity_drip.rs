//! Tier-3 smoke: operator-side liquidity-drip auto-task.
//!
//! Asserts the full lifecycle by leaning on the registry's
//! `ticks_completed` counter as the end-to-end success signal:
//!
//!   1. Plan registered via `deposits-node liquidity drip-create`.
//!   2. Daemon's `auto_drip_self_liquidity` opens the self-deposit
//!      on its next tick (`deposit_id` is populated).
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
        .args(["--seed", OP0_SEED])
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

    // ── 2. Wait for the daemon to open the self-deposit ──
    eprintln!("[open]   waiting for daemon to open the self-deposit");
    let opened = wait_for(STAGE_TIMEOUT, || plan_deposit_id(&alias).is_some());
    let deposit_id_hex = plan_deposit_id(&alias)
        .expect("daemon never populated deposit_id within 180s");
    assert!(
        opened,
        "daemon never opened the self-deposit (alias={}, ledger={}…)",
        alias,
        &ledger_id[..16]
    );
    eprintln!("[open]   ✓ opened deposit {}…", &deposit_id_hex[..16]);

    // ── 3+4. Wait for at least 2 drain ticks. ticks_completed only
    //         advances after fund landed (drain has an underfunded
    //         guard) AND the drain commit succeeded, so this is a
    //         single signal for open + fund + N drains. ──
    let want_ticks: u64 = 2;
    eprintln!("[ticks]  waiting for {} drain ticks", want_ticks);
    let drained = wait_for(STAGE_TIMEOUT, || {
        plan_ticks_completed(&alias) >= want_ticks
    });
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
        actual_delta_msats, expected_delta_msats,
    );

    eprintln!(
        "[pass]   drip plan '{}' lifecycle complete: open → fund → {} drain ticks, \
         deposits_total moved by ~{} msats",
        alias, ticks_seen, actual_delta_msats
    );
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

/// Read op0's `operator_drips.json` and pull the deposit_id (if
/// populated) for the named plan.
fn plan_deposit_id(alias: &str) -> Option<String> {
    let path = op0_data_dir().join("operator_drips.json");
    let raw = std::fs::read_to_string(&path).ok()?;
    let v: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let plans = v.get("plans")?.as_array()?;
    for plan in plans {
        if plan.get("alias").and_then(|x| x.as_str()) == Some(alias) {
            return plan
                .get("deposit_id")
                .and_then(|x| x.as_str())
                .map(str::to_string);
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
    let url = "http://127.0.0.1:8765/api/ledgers";
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
