//! Tier 1 of the dispute integration suite: fraud-proof publish →
//! quorum-member dispute → operator-side state transition.
//!
//! Flow:
//!   1. Discover one of op0's ledgers.
//!   2. Have op0 publish a deliberately non-conforming `kind:9100`
//!      update via `deposits-node danger publish-invalid` (a feature-
//!      gated test command — see `deposits-node/src/node_cli/danger.rs`).
//!      The update is signed under op0's real key but breaks the hash
//!      chain, so any chain-validating quorum member will detect the
//!      violation.
//!   3. Run `deposits-node recovery dispute <ledger>` from another
//!      operator's CLI (op1). That command independently scans the
//!      ledger, finds the violation, and publishes the kind:9103
//!      dispute event.
//!   4. Op0's daemon receives the dispute event and transitions its
//!      ledger's `dispute_state` from `Normal` to `Disputed`.
//!   5. Poll `deposits-wallet ledger show <ledger>` until the printed
//!      `Dispute:` line shows the new state.
//!
//! Sibling tests:
//!   - `dispute_arm.rs`            (tier 2: through the arm phase)
//!   - `dispute_confiscation.rs`   (tier 3: full confiscation tx)
//!
//! Requires:
//!   ./bin/setup.sh                                              (cluster)
//!
//! AND requires that op0's ledger has been successfully rotated to
//! quorum control (`rotated: yes` in `ledger health`, `Quorum: N
//! members` with N >= 3). Without an active quorum, op0's daemon
//! receives the kind:9103 dispute event but auto_arm_for_dispute
//! fails with "Cannot arm without any quorum members" and
//! `dispute_state` stays at Normal — the test will time out at the
//! polling step.
//!
//! As of this writing the cluster's Phase 4 / quorum_begin path is
//! flaky for several reasons (cosign timeouts when the rotation tx
//! hasn't been broadcast/indexed yet, etc.) — see open work on
//! orchestration. When that's stable, this test should pass against
//! a fresh `setup.sh 5` cluster.
//!
//! Run with:
//!   cargo test -p deposits-test --test dispute_initiation -- --ignored

use deposits_test::regtest::*;
use std::process::Command;
use std::time::{Duration, Instant};

#[test]
#[ignore]
fn fraud_proof_triggers_dispute_state() {
    if !cluster_available() {
        eprintln!("skipping: cluster not running — start with ./bin/setup.sh");
        return;
    }

    // The `danger publish-invalid` subcommand is feature-gated. Build
    // the release `deposits-node` with the feature so subsequent
    // invocations have it.
    let node = build_node_with_danger();

    let ledger = discover_op0_ledger();
    eprintln!("[setup] op0 ledger: {}…", &ledger[..16]);

    // ── 1. Sanity-check pre-state: ledger is Normal ───────────────
    let pre = ledger_health(0, &ledger);
    assert!(
        pre.contains("Dispute:") && !pre.contains("Disputed"),
        "ledger already in Disputed state before test:\n{}",
        pre
    );

    // ── 2. Op0 publishes a deliberately broken update ─────────────
    eprintln!("[fraud] op0 publishes invalid-hash update via `danger publish-invalid`");
    let out = Command::new(&node)
        .args(["danger", "publish-invalid", &ledger, "invalid-hash"])
        .args(["--seed", OP0_SEED])
        .args(["--name", "op0"])
        .args(["--network", "regtest"])
        .args(["--data-dir", op0_data_dir().to_str().unwrap()])
        .args(["--esplora", ELECTRS_URL])
        .args(["--relay", relay_ledgers()])
        .output()
        .expect("invoke danger publish-invalid");
    assert!(
        out.status.success(),
        "danger publish-invalid failed:\n--- stdout ---\n{}\n--- stderr ---\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // Give the relay + every node a moment to absorb the bad event.
    std::thread::sleep(Duration::from_secs(3));

    // ── 3. Op1 (a quorum member) runs `recovery start` ────────────
    //
    // `recovery_start` validates the ledger's hash chain independently
    // and publishes a kind:9103 dispute event when it finds the
    // violation we just injected. (We use `start` rather than
    // `dispute` because the latter requires a seq=0 LedgerOpen on the
    // relay, which setup.sh's flow doesn't produce — `start` walks
    // whatever updates are present and detects gaps/breaks.)
    let op1_seed = op_seed(1);
    let op1_dir = op_data_dir(1);
    eprintln!("[dispute] op1 publishes kind:9103 via `recovery start`");
    let out = Command::new(&node)
        .args(["recovery", "start", &ledger])
        .args(["--reason", "integration test: forged invalid-hash"])
        .args(["--seed", &op1_seed])
        .args(["--name", "op1"])
        .args(["--network", "regtest"])
        .args(["--data-dir", op1_dir.to_str().unwrap()])
        .args(["--esplora", ELECTRS_URL])
        .args(["--relay", relay_ledgers()])
        .output()
        .expect("invoke recovery start");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "recovery dispute failed:\n--- stdout ---\n{}\n--- stderr ---\n{}",
        stdout,
        stderr
    );
    assert!(
        stdout.contains("Violation detected") || stdout.contains("Dispute opened"),
        "expected `recovery dispute` to surface the violation:\n{}",
        stdout
    );

    // ── 4. Poll op0's ledger until dispute_state flips ────────────
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut last_seen = String::new();
    while Instant::now() < deadline {
        last_seen = ledger_health(0, &ledger);
        if last_seen.contains("Dispute:") && last_seen.contains("Disputed") {
            eprintln!("[ok] op0 ledger transitioned to Disputed");
            return;
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    panic!(
        "ledger never transitioned to Disputed within 60s; last `ledger show`:\n{}",
        last_seen
    );
}
