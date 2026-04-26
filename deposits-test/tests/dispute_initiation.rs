//! Tier 1 of the dispute integration suite: fraud-proof publish →
//! quorum-member dispute → custody confiscation.
//!
//! Flow:
//!   1. Discover one of op0's ledgers.
//!   2. Have op0 publish a deliberately non-conforming `kind:9100`
//!      update via `deposits-node danger publish-invalid` (a feature-
//!      gated test command — see `deposits-node/src/node_cli/danger.rs`).
//!      The update is signed under op0's real key but breaks the hash
//!      chain, so any chain-validating quorum member will detect the
//!      violation.
//!   3. Run `deposits-node recovery start <ledger>` from another
//!      operator's CLI (op1). That command independently scans the
//!      ledger, finds the violation, and publishes the kind:9103
//!      dispute event.
//!   4. Quorum members receive the kind:9103, auto-arm by forking
//!      the ledger and applying DisputeEnter + DisputeArmed on the
//!      fork branch. The lottery resolves; one member broadcasts the
//!      confiscation transaction; bitcoind confirms it; that member
//!      writes a `confiscated_<prefix>.marker` file.
//!   5. Poll for the marker on disk on any quorum member's data dir.
//!
//! NOTE on the assertion: tier 1 deliberately does NOT check op0's
//! main-ledger `dispute_state`. The protocol model is that a fork
//! branch carries the dispute; the operator's main chain only flips
//! state on a confirmed `DisputeAcquire` (custody transfer) or
//! `DisputeYield`. Neither happens here — we stop at the on-chain
//! confiscation step. Tier 2/3 should exercise the post-confiscation
//! flows once they exist.
//!
//! Sibling tests:
//!   - `dispute_arm.rs`            (tier 2: through the arm phase)
//!   - `dispute_confiscation.rs`   (tier 3: full confiscation tx)
//!
//! Requires:
//!   ./bin/setup.sh 3                                            (cluster)
//!
//! Q=3 keeps the lottery within its 4-participant cap. With Q>=4 the
//! confiscation step fails to build the lottery script.
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

    // ── 4. Poll for confiscation completion ──────────────────────
    //
    // Quorum members write `confiscated_<prefix>.marker` after their
    // confiscation TX confirms on-chain. Any member's marker proves
    // the dispute pipeline ran end-to-end: detection → fork →
    // DisputeArmed → lottery → confiscation TX broadcast and
    // accepted. Auto-arm + arm + confiscate take ~90s on regtest, so
    // poll generously.
    let prefix = &ledger[..16];
    let marker_name = format!("confiscated_{}.marker", prefix);
    let deadline = Instant::now() + Duration::from_secs(180);
    while Instant::now() < deadline {
        for op_idx in 0..10 {
            let path = op_data_dir(op_idx).join(&marker_name);
            if path.exists() {
                eprintln!(
                    "[ok] confiscation completed: marker at op{}/{}",
                    op_idx, marker_name
                );
                return;
            }
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    panic!(
        "no confiscation marker `{}` found on any operator data dir within 180s",
        marker_name
    );
}
