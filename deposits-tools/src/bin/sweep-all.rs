//! sweep-all — drain every reserves UTXO controlled by a set of operator
//! seeds into a single destination address, signing locally with the
//! tier-0 (majority immediate) tapscript leaf. No daemons, no Nostr
//! cosign coordination — assumes the operator holds every key in the
//! quorum (typical when liquidating a test deployment).
//!
//! Directory layout expected:
//! ```text
//! <root>/<name>/node/seed.hex
//! <root>/<name>/node/wallet/ledgers/<ledger_id>.jsonl
//! ```
//! Each `<name>/node/` is a deposits-node `data_dir`. The tool loads every
//! seed.hex, derives the operator pubkey (m/86'/0'/0'/0/0), and builds a
//! keyring `pubkey → seed`. Then for each operator's ledgers (where they
//! are the operator, not a cosigner), it:
//!   1. Replays the jsonl history to recover the latest QuorumBegin and
//!      its (reserves_id, quorum_members, ledger_hash, ruleset, expiry).
//!   2. Looks up the on-chain UTXO at `reserves_id` via Esplora.
//!   3. If unspent, builds a deterministic 1-in/1-out spend to the
//!      destination via `ReservesSpendBuilder`.
//!   4. Computes the tier-0 leaf sighash, signs with the operator + just
//!      enough cosigner keys to meet the majority threshold (we hold them
//!      all from the keyring), assembles the witness, broadcasts via
//!      Esplora.
//!
//! Tier-0 has no timelock, so it works regardless of expiry status. For
//! the rare ledger whose quorum's keys we *don't* fully hold (e.g. an
//! external operator joined our test cluster), the sweep skips it with a
//! warning — recovery there requires the actual cosigners.
//!
//! Usage:
//!   sweep-all --root <dir> --destination <addr> --esplora <url>
//!             [--network bitcoin|testnet|signet|regtest] [--dry-run]
//!
//! Exit code 0 iff every detected reserves UTXO was successfully swept
//! (or skipped cleanly). Errors per ledger are logged but don't abort
//! the run — partial sweeps are still valuable.

use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use bitcoin::{Address, Network, Witness};
use deposits_core::messages::LedgerOperation;
use deposits_core::tapscript_reserves::{
    ReservesSpendBuilder, SpendTxParams, TapscriptReservesBuilder, VoterSet,
};
use deposits_core::tlv::TlvDecode;
use deposits_core::types::LedgerState;
use deposits_core::SignedLedgerUpdate;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::str::FromStr;

#[derive(Debug)]
struct OperatorSlot {
    name: String,
    data_dir: PathBuf,
    seed: [u8; 32],
    operator_pubkey: bitcoin::secp256k1::PublicKey,
}

#[derive(Debug)]
struct SweepArgs {
    root: PathBuf,
    destination: String,
    esplora: String,
    network: Network,
    dry_run: bool,
}

fn parse_args() -> Result<SweepArgs, String> {
    let mut root: Option<PathBuf> = None;
    let mut destination: Option<String> = None;
    let mut esplora = "https://mempool.space/api".to_string();
    let mut network = Network::Bitcoin;
    let mut dry_run = false;

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--root" if i + 1 < args.len() => {
                root = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--destination" if i + 1 < args.len() => {
                destination = Some(args[i + 1].clone());
                i += 2;
            }
            "--esplora" if i + 1 < args.len() => {
                esplora = args[i + 1].clone();
                i += 2;
            }
            "--network" if i + 1 < args.len() => {
                network = match args[i + 1].as_str() {
                    "bitcoin" | "mainnet" => Network::Bitcoin,
                    "testnet" => Network::Testnet,
                    "signet" => Network::Signet,
                    "regtest" => Network::Regtest,
                    other => return Err(format!("unknown network: {}", other)),
                };
                i += 2;
            }
            "--dry-run" => {
                dry_run = true;
                i += 1;
            }
            "--help" | "-h" => {
                eprintln!(
                    "Usage: sweep-all --root <dir> --destination <addr> [options]\n\n\
                     Options:\n  \
                     --root <dir>         Directory containing <name>/node/ subdirs\n  \
                     --destination <addr> Sweep target address\n  \
                     --esplora <url>      Esplora HTTP API (default: mempool.space)\n  \
                     --network <name>     bitcoin|testnet|signet|regtest (default bitcoin)\n  \
                     --dry-run            Build + sign but don't broadcast"
                );
                std::process::exit(0);
            }
            other => return Err(format!("unknown arg: {}", other)),
        }
    }
    Ok(SweepArgs {
        root: root.ok_or("--root is required")?,
        destination: destination.ok_or("--destination is required")?,
        esplora,
        network,
        dry_run,
    })
}

fn derive_operator_secret(seed: &[u8; 32], network: Network) -> Result<SecretKey, String> {
    let secp = Secp256k1::new();
    let xpriv =
        Xpriv::new_master(network, seed).map_err(|e| format!("master xpriv: {}", e))?;
    let path = DerivationPath::from_str("m/86'/0'/0'/0/0")
        .map_err(|e| format!("derivation path: {}", e))?;
    let derived = xpriv
        .derive_priv(&secp, &path)
        .map_err(|e| format!("derive: {}", e))?;
    Ok(derived.private_key)
}

fn load_operators(root: &Path, network: Network) -> Result<Vec<OperatorSlot>, String> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(root).map_err(|e| format!("read {:?}: {}", root, e))? {
        let entry = entry.map_err(|e| format!("entry: {}", e))?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let node_dir = path.join("node");
        let seed_path = node_dir.join("seed.hex");
        if !seed_path.exists() {
            continue;
        }
        let seed_hex = std::fs::read_to_string(&seed_path)
            .map_err(|e| format!("read {:?}: {}", seed_path, e))?;
        let seed_hex = seed_hex.trim();
        let seed_bytes =
            hex::decode(seed_hex).map_err(|e| format!("decode seed {:?}: {}", seed_path, e))?;
        if seed_bytes.len() != 32 {
            return Err(format!(
                "seed {:?}: expected 32 bytes, got {}",
                seed_path,
                seed_bytes.len()
            ));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&seed_bytes);
        let secret = derive_operator_secret(&seed, network)?;
        let secp = Secp256k1::new();
        let operator_pubkey = secret.public_key(&secp);
        out.push(OperatorSlot {
            name: path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("?")
                .to_string(),
            data_dir: node_dir,
            seed,
            operator_pubkey,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// Replay a ledger's jsonl from seq-0 (ignoring State snapshot rows;
/// they're known stale per the project's memory notes) and return the
/// latest QuorumBegin info plus the post-replay LedgerState.
struct LedgerSummary {
    ledger_id: [u8; 32],
    operator_key: bitcoin::secp256k1::PublicKey,
    reserves_id: String,
    quorum_members: Vec<bitcoin::secp256k1::PublicKey>,
    ledger_hash: [u8; 32],
    ruleset_name: String,
    quorum_expiry: u32,
}

fn summarize_ledger(jsonl: &Path) -> Result<Option<LedgerSummary>, String> {
    use std::io::BufRead;
    let file = std::fs::File::open(jsonl).map_err(|e| format!("open {:?}: {}", jsonl, e))?;
    let reader = std::io::BufReader::new(file);

    let mut updates: Vec<SignedLedgerUpdate> = Vec::new();
    for line in reader.lines() {
        let line = line.map_err(|e| format!("read line: {}", e))?;
        let v: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if v.get("type").and_then(|t| t.as_str()) != Some("Update") {
            continue;
        }
        // The jsonl Update rows are JSON-serialized SignedLedgerUpdate
        // with an extra "type":"Update" field. Re-serialize without that
        // field and re-parse as SignedLedgerUpdate. Cheap and avoids a
        // custom deserializer.
        let mut obj = match v.as_object() {
            Some(o) => o.clone(),
            None => continue,
        };
        obj.remove("type");
        let val = serde_json::Value::Object(obj);
        let update: SignedLedgerUpdate = match serde_json::from_value(val) {
            Ok(u) => u,
            Err(_) => continue,
        };
        updates.push(update);
    }
    if updates.is_empty() {
        return Ok(None);
    }
    updates.sort_by_key(|u| u.sequence_number);

    // Find seq-0 LedgerOpen to seed initial state.
    let seq0 = updates.iter().find(|u| u.sequence_number == 0);
    let seq0 = match seq0 {
        Some(u) => u,
        None => return Ok(None),
    };
    let (op_initial, reserves_initial, genesis_block) = match LedgerOperation::tlv_decode(
        &seq0.message,
    ) {
        Ok(LedgerOperation::LedgerOpen {
            operator_id,
            reserves_id,
            genesis_block,
            ..
        }) => (operator_id, reserves_id, genesis_block),
        _ => return Ok(None),
    };

    let mut state = LedgerState::new(op_initial, reserves_initial.clone(), genesis_block);
    let mut latest_qb: Option<(String, Vec<_>, [u8; 32], Option<String>, u32)> = None;

    for u in &updates {
        // We only follow the operator-of-the-moment's chain (DisputeAcquire
        // transitions handled automatically by `state.apply` mutating
        // `parent_pubkey` and `operator_key`).
        if u.operator_id != state.parent_pubkey && u.sequence_number != 0 {
            continue; // fork-branch update; skip
        }
        let op = match LedgerOperation::tlv_decode(&u.message) {
            Ok(o) => o,
            Err(_) => continue,
        };
        if let LedgerOperation::QuorumBegin {
            reserves_id,
            quorum_members,
            ledger_hash,
            protocol_version,
            quorum_expiry,
            ..
        } = &op
        {
            latest_qb = Some((
                reserves_id.clone(),
                quorum_members.iter().map(|m| m.pubkey).collect(),
                *ledger_hash,
                protocol_version.clone(),
                *quorum_expiry,
            ));
        }
        match state.apply(&op) {
            Ok(next) => {
                state = next;
                // chain_tip_hash bookkeeping isn't needed for the summary.
            }
            Err(_) => continue, // best-effort replay
        }
    }

    let (reserves_id, quorum_members, ledger_hash, ruleset, quorum_expiry) = match latest_qb {
        Some(tup) => tup,
        None => return Ok(None), // ledger never reached an Active quorum
    };
    Ok(Some(LedgerSummary {
        ledger_id: state.ledger_id,
        operator_key: state.operator_key,
        reserves_id,
        quorum_members,
        ledger_hash,
        ruleset_name: ruleset.unwrap_or_else(|| "legacy".to_string()),
        quorum_expiry,
    }))
}

fn fetch_utxo(
    address: &Address,
    esplora: &str,
) -> Result<Option<(bitcoin::OutPoint, u64)>, String> {
    let url = format!("{}/address/{}/utxo", esplora, address);
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| format!("http client: {}", e))?;
    let resp = client.get(&url).send().map_err(|e| format!("GET {}: {}", url, e))?;
    if !resp.status().is_success() {
        return Err(format!("esplora {}: status {}", url, resp.status()));
    }
    let utxos: Vec<serde_json::Value> = resp.json().map_err(|e| format!("json: {}", e))?;
    if utxos.is_empty() {
        return Ok(None);
    }
    // Take the first unspent (we expect exactly one for a reserves address).
    let u = &utxos[0];
    let txid_str = u
        .get("txid")
        .and_then(|v| v.as_str())
        .ok_or("missing txid")?;
    let vout = u
        .get("vout")
        .and_then(|v| v.as_u64())
        .ok_or("missing vout")? as u32;
    let value = u
        .get("value")
        .and_then(|v| v.as_u64())
        .ok_or("missing value")?;
    let txid = bitcoin::Txid::from_str(txid_str).map_err(|e| format!("txid: {}", e))?;
    Ok(Some((bitcoin::OutPoint { txid, vout }, value)))
}

fn broadcast_tx(esplora: &str, tx: &bitcoin::Transaction) -> Result<bitcoin::Txid, String> {
    use bitcoin::consensus::encode::serialize_hex;
    let url = format!("{}/tx", esplora);
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("http client: {}", e))?;
    let body = serialize_hex(tx);
    let resp = client
        .post(&url)
        .body(body)
        .header("Content-Type", "text/plain")
        .send()
        .map_err(|e| format!("POST {}: {}", url, e))?;
    let status = resp.status();
    let body = resp.text().unwrap_or_default();
    if !status.is_success() {
        return Err(format!("broadcast: status {} body {}", status, body));
    }
    let txid = bitcoin::Txid::from_str(body.trim()).map_err(|e| format!("txid: {}", e))?;
    Ok(txid)
}

fn sweep_ledger(
    summary: &LedgerSummary,
    keyring: &HashMap<bitcoin::secp256k1::PublicKey, [u8; 32]>,
    destination_script: &bitcoin::ScriptBuf,
    network: Network,
    esplora: &str,
    dry_run: bool,
) -> Result<(), String> {
    // Reconstruct the on-chain Taproot output.
    let other_voters: Vec<bitcoin::secp256k1::PublicKey> = summary
        .quorum_members
        .iter()
        .filter(|pk| **pk != summary.operator_key)
        .copied()
        .collect();
    let voter_set = VoterSet::new(summary.operator_key, other_voters.clone());
    let total_voters = voter_set.all_voters().len();
    let ruleset = deposits_core::ruleset::resolve_or_legacy(Some(&summary.ruleset_name));
    let config = (ruleset.tier_config_factory)(total_voters, summary.quorum_expiry);
    let tier0 = config
        .tiers
        .first()
        .cloned()
        .ok_or("ruleset has no tier 0")?;
    let builder = TapscriptReservesBuilder::new(
        voter_set.clone(),
        config,
        network,
        summary.ledger_hash,
    );
    let taproot_output = builder
        .build()
        .map_err(|e| format!("build taproot: {:?}", e))?;
    let reserves_script = taproot_output.script_pubkey();
    let reserves_address = taproot_output.address.clone();

    // Sanity: the address we just rebuilt must match what the QuorumBegin
    // declared. If it doesn't, our view of (members, ledger_hash, ruleset,
    // expiry) is wrong and signing would produce an unusable witness.
    let declared: Address<bitcoin::address::NetworkUnchecked> = summary
        .reserves_id
        .parse()
        .map_err(|e| format!("parse declared reserves_id: {}", e))?;
    let declared = declared
        .require_network(network)
        .map_err(|e| format!("declared reserves network mismatch: {}", e))?;
    if declared.script_pubkey() != reserves_script {
        return Err(format!(
            "reserves address rebuild mismatch: declared {} but rebuilt {}",
            declared, reserves_address
        ));
    }

    // Find the on-chain UTXO.
    let (outpoint, amount) = match fetch_utxo(&reserves_address, esplora)? {
        Some(u) => u,
        None => {
            println!(
                "  ledger {}…: reserves address has no unspent UTXO; skipping",
                hex::encode(&summary.ledger_id[..8])
            );
            return Ok(());
        }
    };

    // Confirm we hold enough keys to make tier-0's threshold.
    let majority = (total_voters / 2) + 1;
    let available: Vec<bitcoin::secp256k1::PublicKey> = voter_set
        .all_voters()
        .into_iter()
        .filter(|pk| keyring.contains_key(pk))
        .collect();
    if available.len() < majority {
        return Err(format!(
            "only hold {}/{} voter keys (need {} for tier-0 majority)",
            available.len(),
            total_voters,
            majority
        ));
    }

    // Build the spend tx.
    let params = SpendTxParams {
        reserves_outpoint: outpoint,
        reserves_amount: amount,
        destination_script: destination_script.clone(),
        splits: Vec::new(),
        fee_rate_sat_vbyte: 2,
        lock_time: 0,
    };
    let mut tx = ReservesSpendBuilder::build_spend_transaction(&params, &reserves_script)
        .map_err(|e| format!("build spend tx: {:?}", e))?;
    let leaf_script = builder
        .build_threshold_leaf(&tier0)
        .map_err(|e| format!("build tier-0 leaf: {:?}", e))?;
    let sighash = ReservesSpendBuilder::compute_sighash(
        &tx,
        0,
        amount,
        &reserves_script,
        &leaf_script,
    )
    .map_err(|e| format!("compute sighash: {:?}", e))?;
    let sighash_bytes: [u8; 32] = *sighash.as_ref();
    let msg = Message::from_digest(sighash_bytes);

    // Sign with just enough voters to meet the majority threshold.
    let secp = Secp256k1::new();
    let mut sigs: HashMap<bitcoin::secp256k1::XOnlyPublicKey, [u8; 64]> = HashMap::new();
    for voter in voter_set.all_voters() {
        if sigs.len() >= majority {
            break;
        }
        let seed = match keyring.get(&voter) {
            Some(s) => s,
            None => continue,
        };
        let secret = derive_operator_secret(seed, network)?;
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let sig = secp.sign_schnorr(&msg, &keypair);
        sigs.insert(keypair.x_only_public_key().0, *sig.as_ref());
    }
    if sigs.len() < majority {
        return Err(format!("collected {}/{} sigs", sigs.len(), majority));
    }

    // Assemble witness. Stack order: sigs in reverse-sorted-voter order,
    // then leaf_script, then control_block.
    let sorted = voter_set.sorted_x_only_pubkeys();
    let control_block = taproot_output
        .control_block_for_tier(0)
        .ok_or("no control block for tier 0")?;
    let mut witness = Witness::new();
    for x_only in sorted.iter().rev() {
        match sigs.get(x_only) {
            Some(sig) => witness.push(sig),
            None => witness.push([] as [u8; 0]),
        }
    }
    witness.push(leaf_script.as_bytes());
    witness.push(control_block.serialize());
    tx.input[0].witness = witness;

    let txid = tx.compute_txid();
    println!(
        "  ledger {}…: sweeping {} sats from {}:{} → {}",
        hex::encode(&summary.ledger_id[..8]),
        amount,
        outpoint.txid,
        outpoint.vout,
        bitcoin::consensus::encode::serialize_hex(&tx),
    );
    println!(
        "    tx {} ({} → dest), fee {} sats",
        txid,
        tx.output[0].value.to_sat(),
        amount.saturating_sub(tx.output[0].value.to_sat())
    );
    if dry_run {
        return Ok(());
    }
    let broadcast_txid = broadcast_tx(esplora, &tx)?;
    println!("    broadcast: {}", broadcast_txid);
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_args()?;

    println!("Loading operators from {:?}...", args.root);
    let operators = load_operators(&args.root, args.network)?;
    println!("Found {} operator seed(s):", operators.len());
    for op in &operators {
        println!(
            "  {} → {}",
            op.name,
            hex::encode(&op.operator_pubkey.serialize()[..8])
        );
    }

    let mut keyring: HashMap<bitcoin::secp256k1::PublicKey, [u8; 32]> = HashMap::new();
    for op in &operators {
        keyring.insert(op.operator_pubkey, op.seed);
    }

    let destination: Address<bitcoin::address::NetworkUnchecked> = args
        .destination
        .parse()
        .map_err(|e| format!("parse --destination: {}", e))?;
    let destination = destination
        .require_network(args.network)
        .map_err(|e| format!("destination network mismatch: {}", e))?;
    let destination_script = destination.script_pubkey();

    let mut swept_ledgers: HashSet<[u8; 32]> = HashSet::new();
    let mut total_attempted = 0usize;
    let mut total_errors = 0usize;

    for op in &operators {
        let ledgers_dir = op.data_dir.join("wallet/ledgers");
        let entries = match std::fs::read_dir(&ledgers_dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
                continue;
            }
            let summary = match summarize_ledger(&path) {
                Ok(Some(s)) => s,
                Ok(None) => continue,
                Err(e) => {
                    println!(
                        "  skip {:?}: summarize failed: {}",
                        path.file_name().unwrap_or_default(),
                        e
                    );
                    continue;
                }
            };
            if summary.operator_key != op.operator_pubkey {
                continue; // we're a cosigner here, not the operator
            }
            if !swept_ledgers.insert(summary.ledger_id) {
                continue;
            }
            println!(
                "[{}] ledger {}… (operator={})",
                op.name,
                hex::encode(&summary.ledger_id[..8]),
                hex::encode(&summary.operator_key.serialize()[..8]),
            );
            total_attempted += 1;
            if let Err(e) = sweep_ledger(
                &summary,
                &keyring,
                &destination_script,
                args.network,
                &args.esplora,
                args.dry_run,
            ) {
                println!("    ERROR: {}", e);
                total_errors += 1;
            }
        }
    }

    println!();
    println!("=== Summary ===");
    println!("  Ledgers attempted: {}", total_attempted);
    println!("  Errors:            {}", total_errors);
    println!("  Mode:              {}", if args.dry_run { "dry-run" } else { "live" });
    if total_errors > 0 {
        std::process::exit(1);
    }
    Ok(())
}
