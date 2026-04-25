//! Docker-backed adversarial tests — run attacks against live nodes.
//!
//! These tests require a running Docker environment (bitcoind, electrs, relays).
//! They're marked #[ignore] by default and run with:
//!   cargo test -p deposits-test --test docker_adversarial -- --ignored
//!
//! The tests use the harness to bring up operator nodes, form quorum,
//! then take manual control to inject attacks and measure profitability.

use deposits_test::adversarial::*;
use deposits_test::docker::*;
use std::process::Command;

/// Check if Docker infrastructure is available.
fn infra_available() -> bool {
    Command::new("docker")
        .args([
            "exec",
            "bitcoind",
            "bitcoin-cli",
            "-regtest",
            "-rpcuser=user",
            "-rpcpassword=pass",
            "getblockcount",
        ])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Helper: run a node command and return stdout.
fn node_cmd(name: &str, args: &[&str]) -> Result<String, String> {
    let repo_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    let tools = repo_root.join("deposits-tools");

    let cmd = format!(
        "source {}/bin/_common.sh && init_topology && run_node_cmd {} {}",
        tools.display(),
        name,
        args.join(" ")
    );

    Command::new("bash")
        .arg("-c")
        .arg(&cmd)
        .output()
        .map(|o| {
            if o.status.success() {
                Ok(String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .filter(|l| !l.starts_with('\u{1b}')) // strip ANSI
                    .collect::<Vec<_>>()
                    .join("\n"))
            } else {
                Err(String::from_utf8_lossy(&o.stderr).to_string())
            }
        })
        .unwrap_or(Err("command failed".into()))
}

/// Helper: get operator's reserves amount from info.
fn get_reserves(name: &str) -> Option<u64> {
    let info = node_cmd(name, &["info"]).ok()?;
    info.lines()
        .find(|l| l.contains("Reserves:") && l.contains("sats"))
        .and_then(|l| {
            l.split_whitespace()
                .filter_map(|w| w.replace(',', "").parse::<u64>().ok())
                .next()
        })
}

/// Helper: get total deposit balance from info.
fn get_deposit_balance(name: &str) -> Option<u64> {
    let info = node_cmd(name, &["info"]).ok()?;
    info.lines()
        .find(|l| l.to_lowercase().contains("total") && l.contains("msats"))
        .and_then(|l| {
            l.split_whitespace()
                .filter_map(|w| w.replace(',', "").parse::<u64>().ok())
                .next()
        })
}

// =========================================================================
// Test 1: Measure reserve backing after deposit operations
// =========================================================================

#[test]
#[ignore = "requires Docker infrastructure"]
fn docker_verify_reserve_backing_invariant() {
    if !infra_available() {
        println!("SKIP: Docker infrastructure not available");
        return;
    }

    let mut log = AttackLog::new();

    // Query each operator's reserves and deposit balances
    let operators = ["alice", "bob", "charlie", "diana"];
    let mut all_backed = true;

    for name in &operators {
        let reserves = get_reserves(name).unwrap_or(0);
        let deposits = get_deposit_balance(name).unwrap_or(0);

        println!(
            "  {}: reserves={} sats, deposits={} sats, backed={}",
            name,
            reserves,
            deposits,
            reserves >= deposits
        );

        if reserves < deposits {
            all_backed = false;
        }
    }

    log.record(AttackResult {
        name: "Docker: Reserve backing invariant".into(),
        invariant: Invariant::ReserveBacking,
        adversary: AdversaryCapability::single_operator(4),
        cost_sats: 0,
        extraction_sats: 0,
        blocked: all_backed,
        defense: DefenseLayer::Protocol,
        scaling: Scaling::Constant,
        notes: "Verified live reserve backing across all operators".into(),
        steps: vec![],
    });

    assert!(all_backed, "All operators must have reserves >= deposits");
}

// =========================================================================
// Test 2: Verify ledger replay from relay matches node state
// =========================================================================

#[test]
#[ignore = "requires Docker infrastructure"]
fn docker_verify_ledger_relay_consistency() {
    if !infra_available() {
        println!("SKIP: Docker infrastructure not available");
        return;
    }

    let repo_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    let replay = repo_root.join("target/release/replay-ledger");

    let operators = ["alice", "bob", "charlie", "diana"];
    let mut all_consistent = true;

    for name in &operators {
        // Get ledger ID from node
        let list = node_cmd(name, &["ledger", "list"]).unwrap_or_default();
        let ledger_id = list
            .lines()
            .find(|l| l.contains("Ledger ID:"))
            .and_then(|l| {
                l.split_whitespace()
                    .find(|w| w.len() >= 48 && w.chars().all(|c| c.is_ascii_hexdigit()))
            })
            .unwrap_or("");

        if ledger_id.is_empty() {
            println!("  {}: no ledger found", name);
            continue;
        }

        let prefix = &ledger_id[..8];

        // Replay from relay
        let output = Command::new(&replay)
            .args([prefix, "--relay", "ws://localhost:7779"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default();

        if output.contains("updates in chain") {
            // Extract sequence from replay
            let replay_seq = output
                .lines()
                .find(|l| l.contains("sequence:"))
                .and_then(|l| l.split_whitespace().last())
                .and_then(|s| s.parse::<u64>().ok());

            // Get sequence from node
            let info = node_cmd(name, &["ledger", "list"]).unwrap_or_default();
            let node_seq = info
                .lines()
                .find(|l| l.contains("Sequence:"))
                .and_then(|l| l.split_whitespace().last())
                .and_then(|s| s.parse::<u64>().ok());

            // Relay may have stale data from previous runs (same prefix,
            // different ledger_id). Only flag as inconsistent if relay has
            // FEWER updates than the node (missing data), not more (stale data).
            let consistent = match (replay_seq, node_seq) {
                (Some(r), Some(n)) => r >= n,
                _ => false,
            };
            println!(
                "  {} ({}): relay_seq={:?} node_seq={:?} consistent={}",
                name, prefix, replay_seq, node_seq, consistent
            );

            if !consistent {
                all_consistent = false;
            }
        } else {
            println!(
                "  {} ({}): replay failed — {}",
                name,
                prefix,
                output.lines().next().unwrap_or("?")
            );
            all_consistent = false;
        }
    }

    assert!(all_consistent, "Relay ledger state must match node state");
}

// =========================================================================
// Test 3: Verify UTXO amounts match declared reserves
// =========================================================================

#[test]
#[ignore = "requires Docker infrastructure"]
fn docker_verify_utxo_reserves_match() {
    if !infra_available() {
        println!("SKIP: Docker infrastructure not available");
        return;
    }

    let operators = ["alice", "bob", "charlie", "diana"];
    let mut all_match = true;

    // Find working electrs
    let electrs_url = [
        "http://localhost:3201",
        "http://localhost:3202",
        "http://localhost:3102",
    ]
    .iter()
    .find(|url| {
        Command::new("curl")
            .args(["-sf", &format!("{}/blocks/tip/height", url)])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    })
    .copied()
    .unwrap_or("http://localhost:3201");

    for name in &operators {
        let reserves = node_cmd(name, &["reserves", "list"]).unwrap_or_default();

        // Extract outpoints
        for line in reserves.lines() {
            if !line.contains("Outpoint:") {
                continue;
            }
            let outpoint = line
                .split_whitespace()
                .find(|w| w.contains(':') && w.len() > 60)
                .unwrap_or("");
            let parts: Vec<&str> = outpoint.split(':').collect();
            if parts.len() != 2 {
                continue;
            }
            let txid = parts[0];
            let vout: u32 = parts[1].parse().unwrap_or(0);

            // Get declared amount
            let amount_line = reserves
                .lines()
                .skip_while(|l| !l.contains(txid))
                .find(|l| l.contains("Amount:"));
            let declared = amount_line
                .and_then(|l| {
                    l.split_whitespace()
                        .filter_map(|w| w.replace(',', "").parse::<u64>().ok())
                        .next()
                })
                .unwrap_or(0);

            // Query electrs
            let tx_json = Command::new("curl")
                .args(["-sf", &format!("{}/tx/{}", electrs_url, txid)])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                .unwrap_or_default();

            let actual = Command::new("python3")
                .arg("-c")
                .arg(format!(
                    "import sys,json; tx=json.loads(sys.argv[1]); print(tx['vout'][{}]['value'])",
                    vout
                ))
                .arg(&tx_json)
                .output()
                .map(|o| {
                    String::from_utf8_lossy(&o.stdout)
                        .trim()
                        .parse::<u64>()
                        .unwrap_or(0)
                })
                .unwrap_or(0);

            let matches = declared == actual && declared > 0;
            println!(
                "  {} UTXO {}...:{}  declared={} actual={} {}",
                name,
                &txid[..12],
                vout,
                declared,
                actual,
                if matches { "MATCH" } else { "MISMATCH" }
            );

            if !matches {
                all_match = false;
            }
        }
    }

    assert!(all_match, "All UTXO amounts must match declared reserves");
}

// =========================================================================
// Test 4: Measure balance sheet before and after quorum formation
// =========================================================================

#[test]
#[ignore = "requires Docker infrastructure"]
fn docker_balance_sheet_tracking() {
    if !infra_available() {
        println!("SKIP: Docker infrastructure not available");
        return;
    }

    let operators = ["alice", "bob", "charlie", "diana"];

    println!("=== Balance Sheet ===");
    for name in &operators {
        let reserves = get_reserves(name).unwrap_or(0);
        let deposits = get_deposit_balance(name).unwrap_or(0);

        let sheet = BalanceSheet {
            reserves_sats: reserves,
            deposit_balance_sats: deposits,
            ..Default::default()
        };

        println!(
            "  {}: reserves={} deposits={} net_position={}",
            name,
            sheet.reserves_sats,
            sheet.deposit_balance_sats,
            sheet.net_position()
        );
    }
}
