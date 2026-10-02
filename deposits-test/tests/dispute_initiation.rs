//! Tier 1 of the dispute integration suite: operator-initiated dispute →
//! quorum-member auto-arm → custody confiscation.
//!
//! This exercises the MANUAL `recovery start` → `kind:9103` path (distinct
//! from the auto-detected `kind:9101` FraudBroadcast path that
//! `fraud_proof_equivocation` covers): a quorum member independently scans a
//! ledger, finds a hash-chain break, and publishes a `kind:9103` dispute; the
//! other members auto-arm off that notification and drive confiscation.
//!
//! Flow:
//!   1. Fund every operator's op-key P2WPKH (RC6 auto-arm needs a UTXO at each
//!      disputant's op-key address, else DisputeArmed declares None and the
//!      cosigners refuse to sign the confiscation TX — same recipe as
//!      `fraud_proof_equivocation`).
//!   2. Open a FRESH victim ledger on op0 + 3 healthy cosigners. We do NOT
//!      reuse a setup.sh / discover_op0_ledger ledger: node0's canonical
//!      ledger is actively serviced, so a forged orphan at seq N+1 competes
//!      with real updates at the same seq and `recovery start`'s seq-walk just
//!      follows the real chain past it → "conforming". A quiescent victim
//!      makes the forged update the unambiguous chain tip.
//!   3. op0 publishes a deliberately non-conforming `kind:9100` update via
//!      `deposits-node danger publish-invalid <ledger> skip-sequence` — a
//!      feature-gated test command. `skip-sequence` follows the tip but claims
//!      a later sequence: a NonConformingUpdate members prove on sight. (An
//!      update linking to nothing — `invalid-hash` — is not provable, so
//!      members do not dispute it.)
//!   4. A real quorum member (op0's first cosigner) runs
//!      `deposits-node recovery start <ledger>`. That command independently
//!      scans the ledger, finds the break, and publishes the `kind:9103`
//!      dispute event.
//!   5. Quorum members receive the `kind:9103`, auto-arm (fork the ledger,
//!      apply DisputeEnter + DisputeArmed on the fork branch). The lottery
//!      resolves; one member broadcasts the confiscation TX; bitcoind confirms
//!      it. That shows up chain-side as the reserves UTXO being spent.
//!   6. Poll the chain for the confiscation TX.
//!
//! NOTE on the assertion: tier 1 deliberately does NOT check op0's
//! main-ledger `dispute_state`. The protocol model is that a fork branch
//! carries the dispute; the operator's main chain only flips state on a
//! confirmed `DisputeAcquire` (custody transfer) or `DisputeYield`.
//! `equivocation_recovers_to_serviceable_ledger` covers the post-confiscation
//! resolution flow.
//!
//! Q=3 keeps the lottery within its 4-participant cap. With Q>=4 the
//! confiscation step fails to build the lottery script.
//!
//! Requires:
//!   ./bin/setup.sh                                             (cluster)
//!
//! Run with:
//!   cargo test -p deposits-test --test dispute_initiation -- --ignored

use deposits_test::regtest::*;
use std::process::Command;
use std::time::Duration;

#[test]
#[ignore]
fn fraud_proof_triggers_dispute_state() {
    if !cluster_available() {
        eprintln!("skipping: cluster not running — start with ./bin/setup.sh");
        return;
    }

    // The `danger publish-invalid` subcommand is feature-gated. Build the
    // release `deposits-node` with the feature so subsequent invocations
    // have it.
    let node = build_node_with_danger();

    // ── 0. Fund every operator's op-key P2WPKH ────────────────────
    // RC6 auto-arm needs a UTXO at each disputant's op-key address;
    // unfunded → DisputeArmed declares None → cosigners refuse to sign
    // the confiscation TX. Same recipe as `fraud_proof_equivocation`.
    for op_idx in 0..16 {
        let _ = fund_operator_key_address(op_idx, 100_000);
    }
    mine_blocks(2);

    // ── 1. Open a fresh victim ledger on op0 + 3 healthy cosigners ──
    //
    // Why not reuse discover_op0_ledger's canonical ledger: it is actively
    // serviced, so a forged orphan at seq N+1 races real updates at the same
    // seq and `recovery start`'s raw seq-walk follows the real chain past it
    // → reports "conforming". A fresh quiescent victim makes the forged
    // update the unambiguous chain tip that the seq-walk lands on.
    let accused_op_idx: usize = 0;
    let victim = match open_victim_quorum_ledger(&node, accused_op_idx, 10_000, 3) {
        Some(v) => v,
        None => {
            eprintln!(
                "skipping: couldn't open a fresh Q=3 victim — healthy \
                 members not available on this cluster. Rerun against \
                 `setup.sh --fresh`."
            );
            return;
        }
    };
    let ledger = victim.victim_ledger.clone();
    let cosigner_op_indices: Vec<usize> = victim
        .members
        .iter()
        .map(|(op_idx, _, _)| *op_idx)
        .collect();
    eprintln!(
        "[setup] accused=op{} ledger={}… cosigners={:?}",
        accused_op_idx,
        &ledger[..16],
        cosigner_op_indices
    );

    // ── 2. Sanity-check pre-state: ledger is Normal ───────────────
    let pre = ledger_health(accused_op_idx, &ledger);
    assert!(
        pre.contains("Dispute:") && !pre.contains("Disputed"),
        "ledger already in Disputed state before test:\n{}",
        pre
    );

    // ── 3. Op0 publishes a deliberately broken update ─────────────
    eprintln!("[fraud] op0 publishes skip-sequence update via `danger publish-invalid`");
    let out = Command::new(&node)
        .args(["danger", "publish-invalid", &ledger, "skip-sequence"])
        .args(["--seed", &op_seed(accused_op_idx)])
        .args(["--name", &op_name(accused_op_idx)])
        .args(["--network", "regtest"])
        .args(["--data-dir", op_data_dir(accused_op_idx).to_str().unwrap()])
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

    // ── 4. A real quorum member runs `recovery start` ─────────────
    //
    // `recovery_start` validates the ledger's hash chain independently and
    // publishes a `kind:9103` dispute event when it finds the violation we
    // just injected. The disputer must be an actual quorum member so peers
    // recognize it and so it can drive its own arm. We use `start` (not
    // `dispute`) because it walks whatever updates are present and detects
    // gaps/breaks directly.
    let disputer_op = cosigner_op_indices[0];
    let disputer_seed = op_seed(disputer_op);
    let disputer_dir = op_data_dir(disputer_op);
    eprintln!(
        "[dispute] op{} publishes kind:9103 via `recovery start`",
        disputer_op
    );
    let out = Command::new(&node)
        .args(["recovery", "start", &ledger])
        .args(["--reason", "integration test: forged skip-sequence"])
        .args(["--seed", &disputer_seed])
        .args(["--name", &op_name(disputer_op)])
        .args(["--network", "regtest"])
        .args(["--data-dir", disputer_dir.to_str().unwrap()])
        .args(["--esplora", ELECTRS_URL])
        .args(["--relay", relay_ledgers()])
        .output()
        .expect("invoke recovery start");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "recovery start failed:\n--- stdout ---\n{}\n--- stderr ---\n{}",
        stdout,
        stderr
    );
    assert!(
        stdout.contains("Violation detected") || stdout.contains("Dispute opened"),
        "expected `recovery start` to surface the violation:\n{}",
        stdout
    );

    // ── 5. Poll the chain for confiscation completion ─────────────
    //
    // The dispute pipeline running end-to-end (9103 receive → auto-arm →
    // DisputeArmed → lottery → confiscation TX broadcast) shows up chain-side
    // as the ledger's reserves UTXO being spent by the confiscation TX.
    let (op_idx, txid) = poll_confiscation_txid(&ledger, Duration::from_secs(300));
    eprintln!(
        "[ok] operator-initiated dispute drove confiscation: tx {} (observed via op{})",
        txid, op_idx
    );
}
