//! Tier-3: end-to-end operator self-rescue past `quorum_expiry` via
//! the DEP-05 §Lifecycle cosign cascade.
//!
//! Today's pre-lifecycle behaviour: past `quorum_expiry`, cosigners
//! refuse every op (`post_expiry_cosign_refused` in
//! `validate_for_cosign`). The operator can't rotate, can't repair,
//! has to let the dispute lottery confiscate the ledger.
//!
//! Under the lifecycle cascade (DEP-05 §Lifecycle, cltv-offset-v2
//! ruleset): post-expiry cosigners refuse only *value-moving* ops;
//! they continue to cosign establishment ops (`QuorumBegin` etc.) at
//! the threshold matching the current lifecycle tier. The operator
//! invokes `deposits-node quorum repair --yes <ledger>` and lands a
//! fresh `QuorumBegin` that resets the schedule. Auto-dispute grace
//! (720 blocks past expiry, the Tier-1 boundary) gives this rescue a
//! real wall-clock window before partner cosigners would start their
//! own confiscation race.
//!
//! Pipeline asserted end-to-end:
//!
//!   1. Discover op0's first cltv-offset-v2 ledger; read its
//!      `quorum_expiry`.
//!   2. Mine to `quorum_expiry + 10` — well into Tier-0 post-expiry,
//!      well before the 720-block grace expires.
//!   3. Verify no partner cosigner has auto-fired a `DisputeEnter`
//!      fork-branch for this ledger (proves the grace is honoured).
//!   4. Invoke `quorum repair --yes` against op0 via the CLI. Daemon
//!      cosign coordinator picks the matching tier; cosigners' loose-
//!      ned post-expiry gate accepts it; rotation TX broadcasts.
//!   5. Wait for a NEW `QuorumBegin` to appear on op0's ledger with
//!      `quorum_expiry > original_expiry`.
//!   6. Verify the on-chain reserves outpoint changed (the rotation
//!      TX actually confirmed).
//!
//! Tier-3 (cluster). Skipped by default per project convention.
//! Cluster prerequisites:
//!   - `./bin/setup.sh 3` (Q=3, cltv-offset-v2 — opt-in handled by
//!     the post-cascade setup.sh).
//!   - Cluster running long enough to have committed its initial
//!     `QuorumBegin`s.

use deposits_core::messages::LedgerOperation;
use deposits_core::tlv::TlvDecode;
use deposits_test::regtest::*;
use std::process::Command;
use std::time::{Duration, Instant};

#[test]
#[ignore]
fn quorum_repair_succeeds_at_tier0_post_expiry() {
    if !cluster_available() {
        eprintln!("skipping: cluster not running — start with ./bin/setup.sh 3");
        return;
    }

    let node = build_node_with_danger();
    let ledger = discover_op0_ledger();
    eprintln!("[setup] op0 ledger: {}…", &ledger[..16]);

    // ── 1. Read original quorum_expiry + ruleset_name ──
    let history = read_ledger_history(&op0_data_dir(), &ledger);
    let mut original_expiry: Option<u32> = None;
    let mut ruleset_name: Option<String> = None;
    let mut original_reserves_id: Option<String> = None;
    for u in history.iter().rev() {
        if let Ok(LedgerOperation::QuorumBegin {
            quorum_expiry,
            protocol_version,
            reserves_id,
            ..
        }) = LedgerOperation::tlv_decode(&u.message)
        {
            original_expiry = Some(quorum_expiry);
            ruleset_name = protocol_version.clone();
            original_reserves_id = Some(reserves_id.clone());
            break;
        }
    }
    let original_expiry = original_expiry.expect("op0 ledger has no QuorumBegin");
    let ruleset_name = ruleset_name.unwrap_or_else(|| "legacy".to_string());
    let original_reserves_id = original_reserves_id.expect("QuorumBegin missing reserves_id");
    eprintln!(
        "[setup] original quorum_expiry={} ruleset={} reserves_id={}…",
        original_expiry,
        ruleset_name,
        &original_reserves_id[..20.min(original_reserves_id.len())],
    );
    assert!(
        ruleset_name == "cltv-offset-v2" || ruleset_name == "cltv-offset-literal",
        "test requires cltv-offset-v2 ledger (got ruleset={}). \
         Re-run setup.sh after the lifecycle-cascade commit so new \
         QuorumBegins opt into cltv-offset-v2.",
        ruleset_name
    );

    // ── 2. Mine to original_expiry + 10 (Tier 0 post-expiry) ──
    // The grace period is 720 blocks (Tier-1 boundary), so anywhere
    // in [expiry, expiry+720) is safe from partner auto-dispute.
    let current = current_block_height();
    let target = original_expiry + 10;
    let to_mine = if current >= target {
        // Already past; mine a small batch so every daemon sees a
        // fresh tip via esplora poll.
        20
    } else {
        target - current
    };
    eprintln!(
        "[mine] current={} → target={} → mining {} blocks",
        current, target, to_mine
    );
    mine_blocks(to_mine);
    // Let daemons sync the new tip.
    std::thread::sleep(Duration::from_secs(5));

    // ── 3. Sanity: no fork-branch DisputeEnter for this ledger ──
    // Grace prevents auto-dispute until chain_tip >= expiry+720;
    // we're at expiry+10ish, so partner cosigners should be quiet.
    // Fork branches are named `{ledger_id:64}_{fork_seq:06}_{op_prefix:16}.jsonl`
    // (94 chars). The canonical ledger file is `{ledger_id}.jsonl` (70 chars).
    let fork_name_len = ledger.len() + 1 + 6 + 1 + 16 + ".jsonl".len();
    for op_idx in 0..10 {
        let ledgers_dir = op_data_dir(op_idx).join("wallet/ledgers");
        let Ok(entries) = std::fs::read_dir(&ledgers_dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with(&ledger[..]) && name.len() == fork_name_len {
                panic!(
                    "[grace-check] unexpected fork branch on op{} for ledger \
                     {}…: {}. Auto-dispute fired before quorum repair could \
                     run — grace period not honoured?",
                    op_idx,
                    &ledger[..16],
                    name
                );
            }
        }
    }
    eprintln!("[grace] no partner auto-dispute fork branches — grace honoured");

    // ── 4. Invoke `quorum repair --yes` against op0 ──
    eprintln!("[repair] invoking `deposits-node quorum repair` on op0…");
    let output = Command::new(&node)
        .args(["quorum", "repair"])
        .args(["--seed", OP0_SEED])
        .args(["--data-dir", op0_data_dir().to_str().unwrap()])
        .args(["--network", "regtest"])
        .args(["--esplora", ELECTRS_URL])
        .args(["--relay", relay_ledgers()])
        .args(["--relay", relay_messaging()])
        .arg(&ledger)
        .arg("--yes")
        .env("RUST_LOG", "warn")
        .output()
        .expect("quorum repair invocation failed to spawn");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprintln!(
        "[repair] exit={} stdout: {}",
        output.status, stdout
    );
    if !output.status.success() {
        eprintln!("[repair] stderr: {}", stderr);
        panic!(
            "quorum repair exited non-zero: status={} stderr={}",
            output.status, stderr
        );
    }

    // ── 5. Wait for a new QuorumBegin on op0's ledger ──
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut new_expiry: Option<u32> = None;
    let mut new_reserves_id: Option<String> = None;
    while Instant::now() < deadline {
        let history = read_ledger_history(&op0_data_dir(), &ledger);
        for u in history.iter().rev() {
            if let Ok(LedgerOperation::QuorumBegin {
                quorum_expiry,
                reserves_id,
                ..
            }) = LedgerOperation::tlv_decode(&u.message)
            {
                if quorum_expiry > original_expiry {
                    new_expiry = Some(quorum_expiry);
                    new_reserves_id = Some(reserves_id.clone());
                    break;
                }
            }
        }
        if new_expiry.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    let new_expiry = new_expiry.expect(
        "no new QuorumBegin landed on op0's ledger within 60s of `quorum repair --yes`",
    );
    let new_reserves_id = new_reserves_id.unwrap();
    eprintln!(
        "[verify] new QuorumBegin: quorum_expiry {} → {}, reserves {} → {}",
        original_expiry,
        new_expiry,
        &original_reserves_id[..20.min(original_reserves_id.len())],
        &new_reserves_id[..20.min(new_reserves_id.len())],
    );

    assert!(
        new_expiry > original_expiry,
        "new quorum_expiry ({}) must be later than original ({})",
        new_expiry,
        original_expiry,
    );
    assert_ne!(
        new_reserves_id, original_reserves_id,
        "rotation TX should have produced a new reserves_id (UTXO consumed + new vault)",
    );

    eprintln!(
        "[pass] op0 self-rescued at Tier 0 post-expiry: chain past quorum_expiry={}, \
         grace honoured, quorum repair landed new QuorumBegin with quorum_expiry={}",
        original_expiry, new_expiry
    );
}
