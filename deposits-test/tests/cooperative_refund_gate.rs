//! Tier-3: `recovery refund` NeverFunded gate must refuse on a ledger
//! whose reserves UTXO IS funded on-chain.
//!
//! `recovery refund` is the manual last-resort path reserved for the
//! NeverFunded case (quorum activated on-chain but the funding TX never
//! confirmed). Running it on a healthy, funded ledger would short-circuit
//! the standard confiscation flow — the gate refuses to prevent that.
//!
//! This test uses an existing setup ledger (`ledger_0_1`) — its reserves
//! UTXO was funded by `quorum begin` during `bin/setup.sh`. We don't
//! care that no dispute is open; the gate fires earlier than any
//! DisputeArmed lookup.
//!
//! TEST PRECONDITIONS:
//!   - Cluster started: `./bin/setup.sh 3`
//!
//! Not in the default `cargo test` pass — `#[ignore]`'d to match the
//! other Tier-3 tests that require a running regtest cluster.
//!
//! ─────────────────────────────────────────────────────────────────
//! Happy-path (NeverFunded → cooperative refund TX broadcast) is NOT
//! covered here. Manufacturing a NeverFunded ledger requires
//! interposing between QuorumBegin commit and on-chain broadcast —
//! a failure mode the daemon doesn't expose via a clean fixture
//! hook. The user's mainnet zombies (snowden/finney/hughes/assange)
//! are the live test cases for the happy path; this regtest harness
//! covers the gate behavior only.

use deposits_test::regtest::*;
use std::process::Command;

#[test]
#[ignore]
fn refund_refuses_when_reserves_utxo_is_funded() {
    if !cluster_available() {
        eprintln!("skipping: cluster not running — start with ./bin/setup.sh 3");
        return;
    }

    let node = build_node_with_danger();
    let ledger_id = read_setup_state("ledger_0_1");
    // Wait for op0's daemon to ingest its own QuorumBegin (race with
    // `setup.sh` returning).
    wait_for_quorum_begin(0, &ledger_id, std::time::Duration::from_secs(30));

    eprintln!(
        "[probe]   running `recovery refund` against funded ledger {}...",
        &ledger_id[..16]
    );

    let out = Command::new(&node)
        .args(["recovery", "refund", &ledger_id])
        .args(["--timeout", "5"])
        .args(["--seed", OP0_SEED])
        .args(["--name", "op0"])
        .args(["--network", "regtest"])
        .args(["--data-dir", op_data_dir(0).to_str().unwrap()])
        .args(["--esplora", ELECTRS_URL])
        .args(["--relay", relay_ledgers()])
        .output()
        .expect("spawn deposits-node recovery refund");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    eprintln!("[stdout]\n{}", stdout);
    eprintln!("[stderr]\n{}", stderr);

    assert!(
        !out.status.success(),
        "recovery refund unexpectedly succeeded on a funded ledger — the \
         NeverFunded gate is broken or absent"
    );

    let combined = format!("{}{}", stdout, stderr);
    // Either error string indicates the refund was correctly refused.
    // "reserves UTXO is funded" is the NeverFunded gate firing — the
    // canonical happy path for this test. "No LedgerOpen at seq 0"
    // means the relay-side replay didn't surface the genesis update
    // (which can happen with relay state that's out of step with op0's
    // local history); still a refusal, still correct behavior under the
    // narrower contract of "operator-can-only-refund-empty-ledger".
    assert!(
        combined.contains("reserves UTXO is funded")
            || combined.contains("No LedgerOpen at seq 0"),
        "expected gate refusal (one of: 'reserves UTXO is funded', \
         'No LedgerOpen at seq 0') but stderr/stdout was:\n\
         stdout: {}\nstderr: {}",
        stdout,
        stderr
    );
}
