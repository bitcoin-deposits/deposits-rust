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
//! ## Why the victim ledger is purpose-built, not discovered
//!
//! `setup.sh` activates every ledger in the cluster at roughly the
//! same chain height with the same default expiry window (~4320
//! blocks ≈ 30 days). Mining past one ledger's expiry mines past every other
//! ledger's expiry — which means every member ledger we'd lean on
//! for cosigns is *also* expired. `QuorumJoin` (a value-moving op
//! under the cascade) gets refused by a member whose own ledger has
//! expired, breaking the consent dance for `quorum add`. That's
//! correct protocol behaviour — a member past their own expiry has
//! no business making new commitments — but it makes "everything
//! expires together" a poor test fixture.
//!
//! The fix: open a dedicated victim ledger on op0 with an explicit
//! short `--quorum-expiry-blocks` override, mine past *just* its
//! expiry (the member ledgers are still in their ~4320-block window),
//! then run `quorum repair`. The members' own ledgers are healthy,
//! so they accept the repair cosign request.
//!
//! Pipeline asserted end-to-end:
//!
//!   1. Open a fresh victim ledger on op0, pre-fund it, advertise it.
//!   2. Run `quorum add` for Q=3 cosigners (using setup.sh's
//!      cluster members 1, 2, 3 with their existing healthy ledgers).
//!   3. Run `quorum begin --quorum-expiry-blocks 100` — the victim
//!      activates with an expiry only 100 blocks out.
//!   4. Mine ~110 blocks — the victim is now Tier-0 post-expiry while
//!      member ledgers (~4320-block expiry from setup) stay healthy.
//!   5. Run `quorum repair --yes` against op0. Members' loosened
//!      post-expiry gate accepts the QuorumBegin; rotation TX broadcasts.
//!   6. Verify a NEW `QuorumBegin` lands on op0's victim ledger with
//!      `quorum_expiry > original_short_expiry` and a fresh reserves_id.
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

/// How long the victim ledger lives before it's "expired".
/// Small enough to mine past quickly, large enough to leave room
/// for cluster-internal latency during the `quorum begin` round
/// trip (the daemon mines a confirmation block during activation,
/// so the activation TX itself eats a couple of blocks).
const VICTIM_EXPIRY_BLOCKS: u32 = 100;

/// Common args every node CLI invocation needs.
fn op0_cli_args() -> Vec<String> {
    vec![
        "--seed".into(),
        op0_seed().to_string(),
        "--data-dir".into(),
        op0_data_dir().to_string_lossy().into_owned(),
        "--network".into(),
        "regtest".into(),
        "--esplora".into(),
        ELECTRS_URL.into(),
        "--relay".into(),
        relay_ledgers().to_string(),
        "--relay".into(),
        relay_messaging().to_string(),
    ]
}

/// Run `deposits-node <subcmd> [args...]` against op0; panic on
/// non-zero. Returns combined stdout for the caller to grep.
fn run_op0_node(node: &std::path::Path, subcmd_args: &[&str]) -> String {
    let mut cmd = Command::new(node);
    for a in subcmd_args {
        cmd.arg(a);
    }
    for a in op0_cli_args() {
        cmd.arg(a);
    }
    cmd.env("RUST_LOG", "warn");
    let out = cmd
        .output()
        .expect("deposits-node invocation failed to spawn");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    if !out.status.success() {
        panic!(
            "deposits-node {:?} exited {}: stdout={} stderr={}",
            subcmd_args, out.status, stdout, stderr
        );
    }
    stdout
}

/// Send `amount_sats` from the regtest faucet to `address`. Used to
/// pre-fund a freshly-opened victim ledger so its quorum-begin draws
/// a real UTXO. Mirrors `setup.sh`'s `bitcoin_cli ... sendtoaddress`.
fn faucet_send(address: &str, amount_sats: u64) -> String {
    let btc_str = format!(
        "{}.{:08}",
        amount_sats / 100_000_000,
        amount_sats % 100_000_000
    );
    let out = Command::new("docker")
        .args([
            "exec",
            "bitcoind",
            "bitcoin-cli",
            "-regtest",
            "-rpcwallet=faucet",
            "-rpcuser=user",
            "-rpcpassword=pass",
            "sendtoaddress",
            address,
            &btc_str,
        ])
        .output()
        .expect("docker exec bitcoin-cli sendtoaddress");
    assert!(
        out.status.success(),
        "faucet sendtoaddress failed:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

// `lifecycle_expiry` lives in `deposits_test::regtest` (used by
// invoice_cosign / pay_invoice_self_pay / find_clean_healthy_setup_ledger).
// Imported via the wildcard `use deposits_test::regtest::*`.

/// Find up to `wanted` cluster members (from `op1..op9`) whose own
/// primary ledger is *still healthy* (chain_tip < quorum_expiry).
/// Returns `(op_idx, member_pk, member_ledger_id)` triples.
///
/// Why this is necessary: the manual `discover member 1, 2, 3` path
/// assumes setup.sh's recently-provisioned members haven't aged past
/// their own quorum_expiry. On a long-running cluster that's gone
/// through many cycles of test mining, members can be deep into
/// post-expiry territory — at which point QuorumJoin (value-moving
/// under the cascade) gets refused and `quorum add` times out.
fn find_healthy_members(wanted: usize) -> Vec<(usize, String, String)> {
    let mut found = Vec::new();
    for op_idx in 1..10 {
        if found.len() >= wanted {
            break;
        }
        // node{op_idx}'s operator pubkey + single ledger, from the hub's
        // bootstrap-state.json (was data/state/{node_id_i, ledger_i_1}).
        let (Some(pk), Some(lid)) = (op_node_id(op_idx), try_op_ledger(op_idx)) else {
            continue;
        };
        let Some((tip, exp)) = lifecycle_expiry(op_idx, &lid) else {
            continue;
        };
        // Need real headroom — `quorum begin` on the new victim mines
        // a confirmation block during activation, plus the 45s funding
        // wait elapses; want >= ~50 blocks of cushion so this member's
        // QuorumJoin cosign round isn't itself post-expiry by then.
        if tip + 50 < exp {
            eprintln!(
                "[member]  op{} healthy: tip={} expiry={} (headroom={})",
                op_idx,
                tip,
                exp,
                exp - tip
            );
            found.push((op_idx, pk, lid));
        } else {
            eprintln!(
                "[member]  op{} unfit: tip={} expiry={} (headroom={})",
                op_idx,
                tip,
                exp,
                exp.saturating_sub(tip)
            );
        }
    }
    found
}

/// Read the latest `QuorumBegin` on `ledger_id` from op0's local
/// history. Returns `(quorum_expiry, reserves_id, ruleset_name)`.
/// Panics if none found.
fn latest_quorum_begin(ledger_id: &str) -> (u32, String, String) {
    let history = read_ledger_history(&op0_data_dir(), ledger_id);
    for u in history.iter().rev() {
        if let Ok(LedgerOperation::QuorumBegin {
            quorum_expiry,
            protocol_version,
            reserves_id,
            ..
        }) = LedgerOperation::tlv_decode(&u.message)
        {
            return (
                quorum_expiry,
                reserves_id.clone(),
                protocol_version.clone().unwrap_or_else(|| "legacy".into()),
            );
        }
    }
    panic!("ledger {}… has no QuorumBegin", &ledger_id[..16]);
}

#[test]
#[ignore]
fn quorum_repair_succeeds_at_tier0_post_expiry() {
    if !cluster_available() {
        eprintln!("skipping: cluster not running — start with ./bin/setup.sh 3");
        return;
    }

    let node = build_node_with_danger();

    // ── 1. Open a fresh victim ledger on op0 ──
    eprintln!("[setup] opening fresh victim ledger on op0");
    let open_out = run_op0_node(&node, &["ledger", "open"]);
    let victim = open_out
        .lines()
        .find_map(|l| l.strip_prefix("  Ledger ID: ").map(str::to_string))
        .or_else(|| {
            open_out
                .lines()
                .find_map(|l| l.strip_prefix("Ledger ID: ").map(str::to_string))
        })
        .expect("ledger open produced no Ledger ID line");
    eprintln!("[setup] victim ledger: {}…", &victim[..16]);

    // ── 2. Fund + advertise the victim ──
    let address_out = run_op0_node(&node, &["ledger", "address", &victim]);
    let address = address_out
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .expect("ledger address produced no output")
        .trim()
        .to_string();
    eprintln!("[setup] funding {} → {}", &victim[..16], address);
    // 1 BTC: enough for reserves + collateral split with margin.
    let funding_txid = faucet_send(&address, 100_000_000);
    eprintln!("[setup] funding txid: {}…", &funding_txid[..16]);
    // Confirm + wait for op0's wallet to see the UTXO. Mining 6
    // blocks matches setup.sh; the daemon's fast-poll esplora cycle
    // (~30s) needs a real wait window after that.
    mine_blocks(6);
    let funding_tip = current_block_height();
    let _ = wait_for_daemon_chain_tip(0, funding_tip, Duration::from_secs(60));
    // Belt-and-suspenders: the wallet sync poller can lag the chain
    // tip — give it one fast-poll cycle to ingest the new UTXO.
    std::thread::sleep(Duration::from_secs(45));
    let _ = run_op0_node(
        &node,
        &[
            "ledger",
            "advertise",
            "--name",
            &op_name(0),
            "--advertise-relay",
            relay_ledgers(),
        ],
    );

    // ── 3. Add Q=3 cosigners using whichever members still have
    //       healthy ledgers (chain_tip < quorum_expiry). On a
    //       long-running cluster the default 1..=3 picks may have
    //       aged past their own expiry, breaking the consent dance.
    let members = find_healthy_members(3);
    if members.len() < 3 {
        eprintln!(
            "[skip]  only found {} healthy members (need 3) — cluster has aged past \
             the precondition for this test. Rerun against `setup.sh --fresh 3`.",
            members.len()
        );
        return;
    }
    eprintln!("[stage] requesting consent from {} members", members.len());
    for (op_idx, member_pk, member_ledger) in &members {
        run_op0_node(&node, &["quorum", "add", &victim, member_pk, member_ledger]);
        eprintln!("[stage] op{} added (pk={}…)", op_idx, &member_pk[..16]);
    }

    // ── 4. Activate quorum with a short expiry ──
    eprintln!(
        "[begin] quorum begin --quorum-expiry-blocks {} (victim-only expiry)",
        VICTIM_EXPIRY_BLOCKS
    );
    // Backgrounded so we can mine the activation confirmation while
    // it's blocked waiting for confs — mirrors setup.sh Phase 4.
    let mut begin_cmd = Command::new(&node);
    begin_cmd
        .args(["quorum", "begin", &victim])
        .args(["--amount-sats", "99999000"])
        .args(["--collateral-ratio", "0.6"])
        .args(["--protocol-version", "cltv-offset-v2"])
        .args(["--quorum-expiry-blocks", &VICTIM_EXPIRY_BLOCKS.to_string()]);
    for a in op0_cli_args() {
        begin_cmd.arg(a);
    }
    begin_cmd.env("RUST_LOG", "warn");
    let mut begin_child = begin_cmd
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("quorum begin spawn");
    // Mine periodic blocks so the rotation TX gets a confirmation.
    let begin_deadline = Instant::now() + Duration::from_secs(180);
    loop {
        if begin_child.try_wait().expect("try_wait").is_some() {
            break;
        }
        if Instant::now() > begin_deadline {
            let _ = begin_child.kill();
            panic!("quorum begin did not exit within 180s");
        }
        mine_blocks(1);
        std::thread::sleep(Duration::from_secs(3));
    }
    let begin_out = begin_child.wait_with_output().expect("wait_with_output");
    if !begin_out.status.success() {
        panic!(
            "quorum begin failed: stdout={} stderr={}",
            String::from_utf8_lossy(&begin_out.stdout),
            String::from_utf8_lossy(&begin_out.stderr),
        );
    }

    // ── 5. Read the victim's now-short expiry ──
    let (original_expiry, original_reserves_id, ruleset) = latest_quorum_begin(&victim);
    assert!(
        ruleset == "cltv-offset-v2" || ruleset == "cltv-offset-literal",
        "victim activated with wrong ruleset: {}",
        ruleset,
    );
    let current = current_block_height();
    eprintln!(
        "[begin] victim QuorumBegin landed: expiry={} (current_tip={}, ruleset={})",
        original_expiry, current, ruleset
    );
    assert!(
        original_expiry <= current + VICTIM_EXPIRY_BLOCKS + 20,
        "expiry override didn't take effect: expiry={} current={}",
        original_expiry,
        current,
    );

    // ── 6. Mine past the victim's expiry ──
    let target = original_expiry + 10;
    let to_mine = if current >= target {
        20
    } else {
        target - current
    };
    eprintln!(
        "[mine] tip={} → target={} (expiry+10), mining {}",
        current, target, to_mine
    );
    mine_blocks(to_mine);
    let observed_tip = wait_for_daemon_chain_tip(0, target, Duration::from_secs(60));
    eprintln!("[sync]  op0 caught up to tip={}", observed_tip);

    // ── 7. Sanity: no auto-dispute fork-branches for the victim ──
    // Grace is 720 blocks past expiry, but the victim is only
    // 10 blocks past expiry — partner cosigners should be quiet.
    let fork_name_len = victim.len() + 1 + 6 + 1 + 16 + ".jsonl".len();
    for op_idx in 0..10 {
        let ledgers_dir = op_data_dir(op_idx).join("wallet/ledgers");
        let Ok(entries) = std::fs::read_dir(&ledgers_dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with(&victim[..]) && name.len() == fork_name_len {
                panic!(
                    "premature fork branch on op{} for victim {}…: {}",
                    op_idx,
                    &victim[..16],
                    name
                );
            }
        }
    }
    eprintln!("[grace] no partner auto-dispute fork branches — grace honoured");

    // ── 8. Invoke `quorum repair --yes` ──
    eprintln!("[repair] invoking `quorum repair --yes` on victim…");
    let mut repair_cmd = Command::new(&node);
    repair_cmd.args(["quorum", "repair", &victim, "--yes"]);
    for a in op0_cli_args() {
        repair_cmd.arg(a);
    }
    repair_cmd.env("RUST_LOG", "warn");
    let repair_out = repair_cmd.output().expect("quorum repair spawn");
    let repair_stdout = String::from_utf8_lossy(&repair_out.stdout);
    let repair_stderr = String::from_utf8_lossy(&repair_out.stderr);
    eprintln!(
        "[repair] exit={} stdout: {}",
        repair_out.status, repair_stdout
    );
    if !repair_out.status.success() {
        panic!(
            "quorum repair exited non-zero: status={} stderr={}",
            repair_out.status, repair_stderr
        );
    }

    // ── 9. Wait for a new QuorumBegin past `original_expiry` ──
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut new_expiry: Option<u32> = None;
    let mut new_reserves_id: Option<String> = None;
    while Instant::now() < deadline {
        let (exp, rid, _) = latest_quorum_begin(&victim);
        if exp > original_expiry {
            new_expiry = Some(exp);
            new_reserves_id = Some(rid);
            break;
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    let new_expiry = new_expiry
        .expect("no new QuorumBegin landed on victim within 60s of `quorum repair --yes`");
    let new_reserves_id = new_reserves_id.unwrap();
    eprintln!(
        "[verify] new QuorumBegin: expiry {} → {}, reserves {} → {}",
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
        "rotation TX should have produced a new reserves_id",
    );

    eprintln!(
        "[pass] op0 self-rescued at Tier 0 post-expiry: chain past expiry={}, \
         grace honoured, quorum repair landed new QuorumBegin with expiry={}",
        original_expiry, new_expiry
    );
}

/// Companion to `quorum_repair_succeeds_at_tier0_post_expiry` — proves
/// the same self-rescue happens *autonomously* via auto_quorum_refresh,
/// no operator CLI invocation. Validates the auto_quorum_refresh post-
/// expiry path that ships in the auto-self-rescue commit.
///
/// Uses the same short-expiry victim approach as the manual test (see
/// the module header for why a purpose-built victim is required rather
/// than discovering a setup.sh-provisioned ledger).
///
/// Pipeline:
///   1. Open + activate a fresh victim with `--quorum-expiry-blocks 100`.
///   2. Mine past the victim's expiry.
///   3. Wait — do NOT invoke `quorum repair`. The daemon's periodic
///      auto_quorum_refresh should fire on its own.
///   4. Assert a new QuorumBegin lands within the periodic budget.
#[test]
#[ignore]
fn auto_quorum_refresh_self_rescues_past_expiry() {
    if !cluster_available() {
        eprintln!("skipping: cluster not running — start with ./bin/setup.sh 3");
        return;
    }

    let node = build_node_with_danger();

    // ── Reuse the manual-test setup arc through `quorum begin` ──
    eprintln!("[setup] opening fresh victim ledger on op0");
    let open_out = run_op0_node(&node, &["ledger", "open"]);
    let victim = open_out
        .lines()
        .find_map(|l| l.strip_prefix("  Ledger ID: ").map(str::to_string))
        .or_else(|| {
            open_out
                .lines()
                .find_map(|l| l.strip_prefix("Ledger ID: ").map(str::to_string))
        })
        .expect("ledger open produced no Ledger ID line");
    eprintln!("[setup] victim ledger: {}…", &victim[..16]);

    let address_out = run_op0_node(&node, &["ledger", "address", &victim]);
    let address = address_out
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .expect("ledger address produced no output")
        .trim()
        .to_string();
    let _ = faucet_send(&address, 100_000_000);
    mine_blocks(6);
    let funding_tip = current_block_height();
    let _ = wait_for_daemon_chain_tip(0, funding_tip, Duration::from_secs(60));
    std::thread::sleep(Duration::from_secs(45));
    let _ = run_op0_node(
        &node,
        &[
            "ledger",
            "advertise",
            "--name",
            &op_name(0),
            "--advertise-relay",
            relay_ledgers(),
        ],
    );

    let members = find_healthy_members(3);
    if members.len() < 3 {
        eprintln!(
            "[skip]  only found {} healthy members (need 3) — rerun against \
             `setup.sh --fresh 3` to set the precondition.",
            members.len()
        );
        return;
    }
    for (op_idx, member_pk, member_ledger) in &members {
        run_op0_node(&node, &["quorum", "add", &victim, member_pk, member_ledger]);
        eprintln!("[stage] op{} added", op_idx);
    }

    let mut begin_cmd = Command::new(&node);
    begin_cmd
        .args(["quorum", "begin", &victim])
        .args(["--amount-sats", "99999000"])
        .args(["--collateral-ratio", "0.6"])
        .args(["--protocol-version", "cltv-offset-v2"])
        .args(["--quorum-expiry-blocks", &VICTIM_EXPIRY_BLOCKS.to_string()]);
    for a in op0_cli_args() {
        begin_cmd.arg(a);
    }
    begin_cmd.env("RUST_LOG", "warn");
    let mut begin_child = begin_cmd
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("quorum begin spawn");
    let begin_deadline = Instant::now() + Duration::from_secs(180);
    loop {
        if begin_child.try_wait().expect("try_wait").is_some() {
            break;
        }
        if Instant::now() > begin_deadline {
            let _ = begin_child.kill();
            panic!("quorum begin did not exit within 180s");
        }
        mine_blocks(1);
        std::thread::sleep(Duration::from_secs(3));
    }
    let begin_out = begin_child.wait_with_output().expect("wait_with_output");
    if !begin_out.status.success() {
        panic!(
            "quorum begin failed: stdout={} stderr={}",
            String::from_utf8_lossy(&begin_out.stdout),
            String::from_utf8_lossy(&begin_out.stderr),
        );
    }

    let (original_expiry, original_reserves_id, ruleset) = latest_quorum_begin(&victim);
    assert!(
        ruleset == "cltv-offset-v2" || ruleset == "cltv-offset-literal",
        "victim activated with wrong ruleset: {}",
        ruleset,
    );
    eprintln!(
        "[setup] victim activated: expiry={} ruleset={}",
        original_expiry, ruleset
    );

    // Mine past the victim's expiry.
    let current = current_block_height();
    let target = original_expiry + 10;
    let to_mine = if current >= target {
        20
    } else {
        target - current
    };
    eprintln!(
        "[mine] tip={} → target={}, mining {}",
        current, target, to_mine
    );
    mine_blocks(to_mine);
    let observed_tip = wait_for_daemon_chain_tip(0, target, Duration::from_secs(60));
    eprintln!("[sync]  op0 caught up to tip={}", observed_tip);

    // ── Wait for the daemon's auto_quorum_refresh to land a new QuorumBegin ──
    // auto_tasks periodic cycle is ~10s with --fast-poll, so a 180s
    // deadline gives ~18 cycles. The first attempt may race with cosigner
    // wallet sync; subsequent cycles retry.
    eprintln!("[wait]  awaiting autonomous self-rescue (no `quorum repair` invocation)…");
    let deadline = Instant::now() + Duration::from_secs(180);
    let mut new_expiry: Option<u32> = None;
    let mut new_reserves_id: Option<String> = None;
    while Instant::now() < deadline {
        let (exp, rid, _) = latest_quorum_begin(&victim);
        if exp > original_expiry {
            new_expiry = Some(exp);
            new_reserves_id = Some(rid);
            break;
        }
        std::thread::sleep(Duration::from_secs(5));
    }
    let new_expiry = new_expiry.expect(
        "auto_quorum_refresh did not land a new post-expiry QuorumBegin \
         within 180s — autonomous self-rescue path failed",
    );
    let new_reserves_id = new_reserves_id.unwrap();
    assert!(
        new_expiry > original_expiry,
        "new quorum_expiry ({}) must exceed original ({})",
        new_expiry,
        original_expiry,
    );
    assert_ne!(
        new_reserves_id, original_reserves_id,
        "rotation TX must have produced a new reserves_id",
    );
    eprintln!(
        "[pass] op0 self-rescued AUTONOMOUSLY: expiry {} → {}, \
         no CLI invocation, auto_quorum_refresh drove the rotation",
        original_expiry, new_expiry
    );
}
