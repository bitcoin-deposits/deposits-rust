// Discover operators and quorum topology from local ledger data
//
// Reads JSONL ledger files from each node's data directory to build
// a complete picture of the network topology, collateral, and reserves.
//
// Usage:
//   discover                              # Use default data root
//   discover --data-root /path/to/data    # Custom data root

use std::collections::{HashMap, HashSet, BTreeMap};
use std::path::{Path, PathBuf};
use deposits_core::{SignedLedgerUpdate, LedgerState};
use deposits_core::messages::LedgerOperation;
use deposits_core::tlv::TlvDecode;

const DEFAULT_DATA_ROOT: &str = "data";

#[derive(Debug, serde::Deserialize)]
#[serde(tag = "type")]
enum LedgerLogRow {
    Role { role: String },
    State(LedgerState),
    Update(SignedLedgerUpdate),
}

struct OperatorInfo {
    name: String,
    pubkey_hex: String,
    ledgers: Vec<LedgerSummary>,
}

struct LedgerSummary {
    ledger_id: String,
    role: String,
    reserves_msats: u64,
    obligations_msats: u64,
    collateral_msats: u64,
    sequence: u64,
    quorum_members: Vec<String>, // compressed pubkey hex
    deposit_count: usize,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let mut data_root = PathBuf::from(DEFAULT_DATA_ROOT);

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--data-root" | "-d" if i + 1 < args.len() => {
                data_root = PathBuf::from(&args[i + 1]);
                i += 2;
            }
            _ => { i += 1; }
        }
    }

    if !data_root.exists() {
        eprintln!("Data root not found: {}", data_root.display());
        std::process::exit(1);
    }

    // Scan each node directory
    let mut operators: BTreeMap<String, OperatorInfo> = BTreeMap::new(); // name -> info
    let mut pk_to_name: HashMap<String, String> = HashMap::new();

    // Node name mapping from seed
    let node_names: HashMap<&str, &str> = [
        ("416c696365", "Alice"),
        ("426f6200", "Bob"),
        ("436861726c6965", "Charlie"),
        ("4469616e61", "Diana"),
    ].into();

    for entry in std::fs::read_dir(&data_root)? {
        let entry = entry?;
        let node_dir = entry.path();
        if !node_dir.is_dir() { continue; }

        let node_name = entry.file_name().to_string_lossy().to_string();
        // Skip non-node dirs
        if node_name == "relays" { continue; }

        let ledgers_dir = node_dir.join("wallet").join("ledgers");
        if !ledgers_dir.exists() { continue; }

        let mut node_operator_key: Option<String> = None;

        for ledger_file in std::fs::read_dir(&ledgers_dir)? {
            let ledger_file = ledger_file?;
            let path = ledger_file.path();
            if path.extension().and_then(|s| s.to_str()) != Some("jsonl") { continue; }

            let ledger_id = path.file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_string();

            let contents = std::fs::read_to_string(&path)?;

            let mut role = String::from("Unknown");
            let mut state: Option<LedgerState> = None;
            let mut updates: Vec<SignedLedgerUpdate> = Vec::new();

            for line in contents.lines() {
                if line.trim().is_empty() { continue; }
                match serde_json::from_str::<LedgerLogRow>(line) {
                    Ok(LedgerLogRow::Role { role: r }) => { role = r; }
                    Ok(LedgerLogRow::State(s)) => { state = Some(s); }
                    Ok(LedgerLogRow::Update(u)) => { updates.push(u); }
                    Err(_) => {}
                }
            }

            let mut state = match state {
                Some(s) => s,
                None => continue,
            };

            // Only process Operator-role ledgers for the main view
            if role != "Operator" { continue; }

            // Replay operations from updates beyond the state snapshot
            let state_seq = state.sequence;
            updates.sort_by_key(|u| u.sequence_number);
            if let Some(last) = updates.last() {
                state.sequence = last.sequence_number;
                state.chain_tip_hash = last.chain_hash();
            }
            let mut ledger = deposits_core::Ledger {
                state,
                protocol: Default::default(),
                role: deposits_core::ledger::LedgerRole::Operator,
                history: updates,
            };
            for i in 0..ledger.history.len() {
                let u = &ledger.history[i];
                if (u.sequence_number as u64) <= state_seq { continue; }
                if let Ok(op) = LedgerOperation::tlv_decode(&u.message) {
                    let _ = ledger.apply_state_changes(&op);
                }
            }
            let state = ledger.state;

            let op_key = hex::encode(state.operator_key.serialize());
            node_operator_key = Some(op_key.clone());

            // Get quorum members
            let quorum_members: Vec<String> = state.quorum_members.iter()
                .map(|m| hex::encode(m.pubkey.serialize()))
                .collect();

            // Calculate obligations from deposits
            let obligations: u64 = state.deposits.values()
                .map(|d| d.balance + d.locked_balance)
                .sum();

            let deposit_count = state.deposits.len();

            // Get collateral from attestations
            let collateral: u64 = state.collateral_attestations.values()
                .map(|a| a.available_collateral())
                .sum();

            let display_name = node_name.clone();
            let display_name_cap = display_name[..1].to_uppercase() + &display_name[1..];

            let op = operators.entry(display_name_cap.clone()).or_insert_with(|| {
                OperatorInfo {
                    name: display_name_cap.clone(),
                    pubkey_hex: op_key.clone(),
                    ledgers: Vec::new(),
                }
            });

            op.ledgers.push(LedgerSummary {
                ledger_id,
                role,
                reserves_msats: state.reserves_amount,
                obligations_msats: obligations,
                collateral_msats: collateral,
                sequence: state.sequence,
                quorum_members,
                deposit_count,
            });
        }

        // Register pubkey -> name mapping
        if let Some(pk) = node_operator_key {
            let cap_name = node_name[..1].to_uppercase() + &node_name[1..];
            pk_to_name.insert(pk, cap_name);
        }
    }

    if operators.is_empty() {
        println!("No operators found in {}", data_root.display());
        return Ok(());
    }

    println!("Discovered {} operators in {}:\n", operators.len(), data_root.display());

    for (_, op) in &operators {
        let total_reserves: u64 = op.ledgers.iter().map(|l| l.reserves_msats).sum();
        let total_collateral: u64 = op.ledgers.iter().map(|l| l.collateral_msats).sum();
        let total_obligations: u64 = op.ledgers.iter().map(|l| l.obligations_msats).sum();
        let total_deposits: usize = op.ledgers.iter().map(|l| l.deposit_count).sum();

        let collateral_pct = if total_reserves > 0 {
            (total_collateral as f64 / total_reserves as f64 * 100.0) as u64
        } else { 0 };

        println!("  {} ({}...)", op.name, &op.pubkey_hex[..16]);
        println!("    Ledgers: {}  |  Deposits: {}  |  Collateral: {}%", op.ledgers.len(), total_deposits, collateral_pct);
        println!("    Reserves:    {:>12} sats", total_reserves / 1000);
        println!("    Collateral:  {:>12} sats", total_collateral / 1000);
        if total_obligations > 0 {
            println!("    Obligations: {:>12} sats", total_obligations / 1000);
        }

        for ledger in &op.ledgers {
            let pct = if ledger.reserves_msats > 0 {
                (ledger.collateral_msats as f64 / ledger.reserves_msats as f64 * 100.0) as u64
            } else { 0 };

            println!("    {}...", &ledger.ledger_id[..16]);
            println!("      Reserves: {:>10} sats  |  Collateral: {} sats ({}%)  |  seq {}",
                ledger.reserves_msats / 1000, ledger.collateral_msats / 1000, pct, ledger.sequence);

            if !ledger.quorum_members.is_empty() {
                let names: Vec<String> = ledger.quorum_members.iter()
                    .map(|pk| pk_to_name.get(pk).cloned().unwrap_or_else(|| format!("{}...", &pk[..12])))
                    .collect();
                println!("      Quorum ({}): {}", ledger.quorum_members.len(), names.join(", "));
            }
        }
        println!();
    }

    // Topology
    println!("Topology:");
    for (_, op) in &operators {
        let mut peers: HashSet<String> = HashSet::new();
        for ledger in &op.ledgers {
            for member in &ledger.quorum_members {
                if let Some(name) = pk_to_name.get(member) {
                    peers.insert(name.clone());
                }
            }
        }
        if !peers.is_empty() {
            let mut peer_list: Vec<&String> = peers.iter().collect();
            peer_list.sort();
            println!("  {} <-> {}", op.name, peer_list.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "));
        }
    }

    Ok(())
}
