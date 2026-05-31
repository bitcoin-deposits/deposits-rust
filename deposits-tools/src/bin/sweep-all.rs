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

use bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{ecdsa, Keypair, Message, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{
    Address, Amount, CompressedPublicKey, Network, OutPoint, ScriptBuf, Sequence,
    Transaction, TxIn, TxOut, Witness,
};
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

/// Derive a child secret key at `m/<change>/<index>` from the master seed.
/// Matches the node-level wallet's `wpkh(master_xpub/{0,1}/*)` descriptor.
fn derive_node_wallet_secret(
    seed: &[u8; 32],
    change: u32,
    index: u32,
    network: Network,
) -> Result<SecretKey, String> {
    let secp = Secp256k1::new();
    let xpriv =
        Xpriv::new_master(network, seed).map_err(|e| format!("master xpriv: {}", e))?;
    let path = DerivationPath::from(vec![
        ChildNumber::Normal { index: change },
        ChildNumber::Normal { index },
    ]);
    let derived = xpriv
        .derive_priv(&secp, &path)
        .map_err(|e| format!("derive: {}", e))?;
    Ok(derived.private_key)
}

/// Derive a child secret key at `m/86'/0'/<account>'/<change>/<index>` from
/// the master seed. Matches the per-ledger BDK wallet's
/// `wpkh(account_xpub/{0,1}/*)` descriptor (account_xpub is the
/// hardened account-level xpub at `m/86'/0'/<account>'`).
fn derive_ledger_wallet_secret(
    seed: &[u8; 32],
    account: u32,
    change: u32,
    index: u32,
    network: Network,
) -> Result<SecretKey, String> {
    let secp = Secp256k1::new();
    let xpriv =
        Xpriv::new_master(network, seed).map_err(|e| format!("master xpriv: {}", e))?;
    let path = DerivationPath::from(vec![
        ChildNumber::Hardened { index: 86 },
        ChildNumber::Hardened { index: 0 },
        ChildNumber::Hardened { index: account },
        ChildNumber::Normal { index: change },
        ChildNumber::Normal { index },
    ]);
    let derived = xpriv
        .derive_priv(&secp, &path)
        .map_err(|e| format!("derive: {}", e))?;
    Ok(derived.private_key)
}

/// Sweep a set of wpkh UTXOs (potentially multiple inputs) into a single
/// output at `destination_script`. `inputs` carries the (outpoint,
/// amount, secret_key) tuples; signing is local — no signer indirection.
fn sweep_wpkh_inputs(
    label: &str,
    inputs: Vec<(OutPoint, u64, SecretKey)>,
    destination_script: &ScriptBuf,
    esplora: &str,
    dry_run: bool,
) -> Result<(), String> {
    if inputs.is_empty() {
        return Ok(());
    }
    let total_in: u64 = inputs.iter().map(|(_, a, _)| *a).sum();
    // Rough fee: ~10 bytes overhead + ~68 vbytes/input (P2WPKH) + ~31 vbytes/output.
    let vbytes = 10 + 68 * inputs.len() as u64 + 31;
    let fee_rate: u64 = 2; // sat/vB; modest, mainnet/testnet appropriate
    let fee = vbytes * fee_rate;
    if fee >= total_in {
        return Err(format!(
            "fee {} ≥ total inputs {}; nothing to sweep",
            fee, total_in
        ));
    }
    let output_value = total_in - fee;

    let mut tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: inputs
            .iter()
            .map(|(op, _, _)| TxIn {
                previous_output: *op,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            })
            .collect(),
        output: vec![TxOut {
            value: Amount::from_sat(output_value),
            script_pubkey: destination_script.clone(),
        }],
    };

    let secp = Secp256k1::new();
    let unsigned_tx_clone = tx.clone();
    let mut cache = SighashCache::new(&unsigned_tx_clone);
    for (i, (_, amount, secret)) in inputs.iter().enumerate() {
        let pubkey = secret.public_key(&secp);
        let compressed = CompressedPublicKey::from_slice(&pubkey.serialize())
            .map_err(|e| format!("compressed pubkey: {}", e))?;
        let wpkh_script = ScriptBuf::new_p2wpkh(&compressed.wpubkey_hash());
        let sighash = cache
            .p2wpkh_signature_hash(
                i,
                &wpkh_script,
                Amount::from_sat(*amount),
                EcdsaSighashType::All,
            )
            .map_err(|e| format!("sighash input {}: {}", i, e))?;
        let msg = Message::from_digest(*sighash.as_ref());
        let sig: ecdsa::Signature = secp.sign_ecdsa(&msg, secret);
        let mut sig_bytes = sig.serialize_der().to_vec();
        sig_bytes.push(EcdsaSighashType::All as u8);
        let mut witness = Witness::new();
        witness.push(sig_bytes);
        witness.push(compressed.to_bytes());
        tx.input[i].witness = witness;
    }

    let txid = tx.compute_txid();
    println!(
        "  {}: sweep {} input(s), {} sats → dest (fee {} sats, txid {})",
        label,
        inputs.len(),
        output_value,
        fee,
        txid
    );
    if dry_run {
        return Ok(());
    }
    broadcast_tx(esplora, &tx)?;
    Ok(())
}

/// Scan a single (xpub-rooted) wpkh wallet by deriving addresses up to
/// `gap_limit` consecutive empties on each change keychain, and return
/// every (outpoint, amount, secret) tuple found.
///
/// `derive_secret` is a closure (change, index) → SecretKey so the same
/// scanner serves both the node-level wallet (m/{0,1}/N) and per-ledger
/// wallets (m/86'/0'/<account>'/{0,1}/N) without duplicating logic.
fn scan_wpkh_utxos<F>(
    derive_secret: F,
    network: Network,
    esplora: &str,
    gap_limit: u32,
) -> Result<Vec<(OutPoint, u64, SecretKey)>, String>
where
    F: Fn(u32, u32) -> Result<SecretKey, String>,
{
    let secp = Secp256k1::new();
    let mut found: Vec<(OutPoint, u64, SecretKey)> = Vec::new();
    for change in 0..=1u32 {
        let mut consecutive_empty = 0u32;
        let mut index = 0u32;
        while consecutive_empty < gap_limit {
            let secret = derive_secret(change, index)?;
            let pubkey = secret.public_key(&secp);
            let compressed = CompressedPublicKey::from_slice(&pubkey.serialize())
                .map_err(|e| format!("compressed pubkey: {}", e))?;
            let address = Address::p2wpkh(&compressed, network);
            match fetch_address_utxos(&address, esplora)? {
                utxos if utxos.is_empty() => {
                    consecutive_empty += 1;
                }
                utxos => {
                    consecutive_empty = 0;
                    for (op, amt) in utxos {
                        found.push((op, amt, secret));
                    }
                }
            }
            index += 1;
        }
    }
    Ok(found)
}

fn fetch_address_utxos(
    address: &Address,
    esplora: &str,
) -> Result<Vec<(OutPoint, u64)>, String> {
    let url = format!("{}/address/{}/utxo", esplora, address);
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| format!("http client: {}", e))?;
    let resp = client
        .get(&url)
        .send()
        .map_err(|e| format!("GET {}: {}", url, e))?;
    if !resp.status().is_success() {
        return Err(format!("esplora {}: status {}", url, resp.status()));
    }
    let utxos: Vec<serde_json::Value> = resp.json().map_err(|e| format!("json: {}", e))?;
    let mut out = Vec::new();
    for u in utxos {
        let txid_str = u.get("txid").and_then(|v| v.as_str()).ok_or("txid")?;
        let vout = u.get("vout").and_then(|v| v.as_u64()).ok_or("vout")? as u32;
        let value = u.get("value").and_then(|v| v.as_u64()).ok_or("value")?;
        let txid = bitcoin::Txid::from_str(txid_str).map_err(|e| format!("txid: {}", e))?;
        out.push((OutPoint { txid, vout }, value));
    }
    Ok(out)
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
    /// (txid, vout) of the actual on-chain reserves UTXO the daemon's
    /// snapshot recorded. We pull this from the legacy json's `outpoint_*`
    /// fields so that when our local rebuild produces a different address
    /// than the on-chain output (script-builder drift), we can still
    /// inspect the real script and report where the money is.
    outpoint: Option<(bitcoin::Txid, u32)>,
    /// When the snapshot is self-describing (new format introduced
    /// 2026-05-29), these carry everything sweep-all needs to spend the
    /// vault without rebuilding the script tree: the on-chain scriptpubkey,
    /// the Taproot internal key, and per-tier (leaf script, control block)
    /// pairs. Old JSONs without this data fall back to the rebuild path.
    persisted_tree: Option<PersistedTree>,
}

#[derive(Clone, Debug)]
struct PersistedTree {
    script_pubkey: bitcoin::ScriptBuf,
    #[allow(dead_code)] // useful for diagnostics; sweep just needs the leaves
    internal_key: bitcoin::secp256k1::XOnlyPublicKey,
    tier_leaves: Vec<PersistedTierLeaf>,
}

#[derive(Clone, Debug)]
struct PersistedTierLeaf {
    tier_index: u32,
    leaf_script: bitcoin::ScriptBuf,
    control_block: bitcoin::taproot::ControlBlock,
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

    let (reserves_id, mut quorum_members, mut ledger_hash, ruleset, mut quorum_expiry) =
        match latest_qb {
            Some(tup) => tup,
            None => return Ok(None), // ledger never reached an Active quorum
        };
    let mut ruleset_name = ruleset.unwrap_or_else(|| "legacy".to_string());
    let mut outpoint: Option<(bitcoin::Txid, u32)> = None;
    let mut persisted_tree: Option<PersistedTree> = None;

    // Prefer the per-ledger `taproot_reserves.json` snapshot if it exists.
    // The QuorumBegin op's `ledger_hash` field is a ledger-state hash and
    // can diverge from the value the daemon actually committed in the
    // Taproot tree at rotation time; only the json (written from
    // `commit_taproot_reserves`) records the build-time inputs verbatim.
    // Same hazard applies to (quorum_members, ruleset_name, quorum_expiry):
    // if anything was rotated using a value that differs from what the
    // history records, trust the json.
    let ledger_id_hex = hex::encode(state.ledger_id);
    let per_ledger_dir = jsonl
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .join(&ledger_id_hex);
    let per_ledger_json = per_ledger_dir.join("taproot_reserves.json");
    if per_ledger_json.exists() {
        if let Ok(raw) = std::fs::read_to_string(&per_ledger_json) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) {
                if let Some(addr) = v.get("address").and_then(|x| x.as_str()) {
                    // Accept either address-match (pre-migration) or
                    // identity-match-with-persisted-script (post-migration:
                    // address was rewritten to on-chain reality, which by
                    // definition differs from the stale QuorumBegin
                    // reserves_id). The post-migration branch is gated on
                    // `script_pubkey` being present so we never silently
                    // accept a stale entry as authoritative.
                    let address_match = addr == reserves_id;
                    let identity_match = !address_match
                        && v.get("script_pubkey").is_some()
                        && entry_identity_matches(&v, &state.operator_key, &quorum_members);
                    if address_match || identity_match {
                        if let Some(h) = v
                            .get("ledger_hash")
                            .and_then(|x| x.as_str())
                            .and_then(|s| hex::decode(s).ok())
                            .and_then(|b| <[u8; 32]>::try_from(b).ok())
                        {
                            ledger_hash = h;
                        }
                        if let Some(members_arr) =
                            v.get("quorum_members").and_then(|x| x.as_array())
                        {
                            let parsed: Result<Vec<_>, _> = members_arr
                                .iter()
                                .filter_map(|m| m.as_str())
                                .map(|s| s.parse::<bitcoin::secp256k1::PublicKey>())
                                .collect();
                            if let Ok(ms) = parsed {
                                if !ms.is_empty() {
                                    quorum_members = ms;
                                }
                            }
                        }
                        if let Some(qe) =
                            v.get("quorum_expiry").and_then(|x| x.as_u64())
                        {
                            quorum_expiry = qe as u32;
                        }
                        if let Some(rs) =
                            v.get("ruleset_name").and_then(|x| x.as_str())
                        {
                            ruleset_name = rs.to_string();
                        }
                        if let (Some(txid_str), Some(vout)) = (
                            v.get("outpoint_txid").and_then(|x| x.as_str()),
                            v.get("outpoint_vout").and_then(|x| x.as_u64()),
                        ) {
                            if let Ok(txid) = bitcoin::Txid::from_str(txid_str) {
                                outpoint = Some((txid, vout as u32));
                            }
                        }
                        persisted_tree = parse_persisted_tree(&v);
                    }
                }
            }
        }
    }

    // Legacy fallback: pre-per-ledger daemons wrote a single array file at
    // `<data_dir>/wallet/taproot_reserves.json`. One entry per active vault
    // across the operator's whole node; we walk for an entry whose
    // `.address` matches `reserves_id` and override the same fields.
    //
    // node_cli/reserves.rs:367+ uses the same lookup for the `reserves spend`
    // path; matching it here keeps sweep-all aligned with the manual flow.
    let wallet_dir = jsonl
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| Path::new(".").to_path_buf());
    let legacy_json = wallet_dir.join("taproot_reserves.json");
    if legacy_json.exists() {
        if let Ok(raw) = std::fs::read_to_string(&legacy_json) {
            if let Ok(arr) = serde_json::from_str::<serde_json::Value>(&raw) {
                if let Some(entries) = arr.as_array() {
                    for entry in entries {
                        let addr = entry
                            .get("address")
                            .and_then(|x| x.as_str())
                            .unwrap_or("");
                        let address_match = addr == reserves_id;
                        let identity_match = !address_match
                            && entry.get("script_pubkey").is_some()
                            && entry_identity_matches(
                                entry,
                                &state.operator_key,
                                &quorum_members,
                            );
                        if !address_match && !identity_match {
                            continue;
                        }
                        if let Some(h) = entry
                            .get("ledger_hash")
                            .and_then(|x| x.as_str())
                            .and_then(|s| hex::decode(s).ok())
                            .and_then(|b| <[u8; 32]>::try_from(b).ok())
                        {
                            ledger_hash = h;
                        }
                        if let Some(members_arr) =
                            entry.get("quorum_members").and_then(|x| x.as_array())
                        {
                            let parsed: Result<Vec<_>, _> = members_arr
                                .iter()
                                .filter_map(|m| m.as_str())
                                .map(|s| s.parse::<bitcoin::secp256k1::PublicKey>())
                                .collect();
                            if let Ok(ms) = parsed {
                                if !ms.is_empty() {
                                    quorum_members = ms;
                                }
                            }
                        }
                        if let Some(qe) =
                            entry.get("quorum_expiry").and_then(|x| x.as_u64())
                        {
                            quorum_expiry = qe as u32;
                        }
                        if let Some(rs) =
                            entry.get("ruleset_name").and_then(|x| x.as_str())
                        {
                            // Skip null (legacy entries have no ruleset_name);
                            // the default we set above stays "legacy", matching
                            // deposits-node's `default_ruleset_name`.
                            ruleset_name = rs.to_string();
                        }
                        if let (Some(txid_str), Some(vout)) = (
                            entry.get("outpoint_txid").and_then(|x| x.as_str()),
                            entry.get("outpoint_vout").and_then(|x| x.as_u64()),
                        ) {
                            if let Ok(txid) = bitcoin::Txid::from_str(txid_str) {
                                outpoint = Some((txid, vout as u32));
                            }
                        }
                        // Pick up the self-describing tree fields if the
                        // snapshot was written by post-2026-05-29 code.
                        persisted_tree = parse_persisted_tree(entry);
                        break;
                    }
                }
            }
        }
    }

    Ok(Some(LedgerSummary {
        ledger_id: state.ledger_id,
        operator_key: state.operator_key,
        reserves_id,
        outpoint,
        persisted_tree,
        quorum_members,
        ledger_hash,
        ruleset_name,
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

/// Parse the self-describing-tree fields from a JSON object describing a
/// vault snapshot. Returns `None` if any required field is missing, malformed,
/// or empty — caller falls back to the rebuild path in that case.
/// Match a `taproot_reserves.json` entry against a ledger's identity
/// (operator + member set) instead of address. Used as a fallback when
/// the entry's `address` field has been rewritten to on-chain reality by
/// a migration but the QuorumBegin op still carries the stale value.
fn entry_identity_matches(
    entry: &serde_json::Value,
    operator: &bitcoin::secp256k1::PublicKey,
    members: &[bitcoin::secp256k1::PublicKey],
) -> bool {
    let op_match = entry
        .get("operator")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<bitcoin::secp256k1::PublicKey>().ok())
        .map(|p| &p == operator)
        .unwrap_or(false);
    if !op_match {
        return false;
    }
    let entry_members: Vec<bitcoin::secp256k1::PublicKey> = entry
        .get("quorum_members")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|m| m.as_str())
                .filter_map(|s| s.parse::<bitcoin::secp256k1::PublicKey>().ok())
                .collect()
        })
        .unwrap_or_default();
    let entry_set: std::collections::HashSet<_> = entry_members.iter().collect();
    let ledger_set: std::collections::HashSet<_> = members.iter().collect();
    entry_set == ledger_set
}

fn parse_persisted_tree(entry: &serde_json::Value) -> Option<PersistedTree> {
    let spk_hex = entry.get("script_pubkey").and_then(|v| v.as_str())?;
    let ik_hex = entry.get("internal_key").and_then(|v| v.as_str())?;
    let tier_leaves_val = entry.get("tier_leaves").and_then(|v| v.as_array())?;
    if tier_leaves_val.is_empty() {
        return None;
    }
    let script_pubkey = bitcoin::ScriptBuf::from_bytes(hex::decode(spk_hex).ok()?);
    let internal_key =
        bitcoin::secp256k1::XOnlyPublicKey::from_slice(&hex::decode(ik_hex).ok()?).ok()?;
    let mut tier_leaves = Vec::with_capacity(tier_leaves_val.len());
    for tl in tier_leaves_val {
        let tier_index = tl.get("tier_index").and_then(|v| v.as_u64())? as u32;
        let script_bytes = hex::decode(tl.get("script_hex").and_then(|v| v.as_str())?).ok()?;
        let cb_bytes =
            hex::decode(tl.get("control_block_hex").and_then(|v| v.as_str())?).ok()?;
        let leaf_script = bitcoin::ScriptBuf::from_bytes(script_bytes);
        let control_block = bitcoin::taproot::ControlBlock::decode(&cb_bytes).ok()?;
        tier_leaves.push(PersistedTierLeaf {
            tier_index,
            leaf_script,
            control_block,
        });
    }
    // Tier-0 must exist — sweep-all signs through it.
    if !tier_leaves.iter().any(|t| t.tier_index == 0) {
        return None;
    }
    Some(PersistedTree {
        script_pubkey,
        internal_key,
        tier_leaves,
    })
}

/// Fetch the scriptpubkey of a specific outpoint via esplora, plus the
/// derived address for the configured network. Returns `None` if the txid
/// can't be retrieved or the vout doesn't exist.
fn fetch_outpoint_script(
    esplora: &str,
    txid: bitcoin::Txid,
    vout: u32,
    network: Network,
) -> Result<Option<(bitcoin::ScriptBuf, Option<Address>)>, String> {
    let url = format!("{}/tx/{}", esplora, txid);
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| format!("http client: {}", e))?;
    let resp = client
        .get(&url)
        .send()
        .map_err(|e| format!("GET {}: {}", url, e))?;
    if !resp.status().is_success() {
        return Ok(None);
    }
    let v: serde_json::Value = resp.json().map_err(|e| format!("json: {}", e))?;
    let vouts = match v.get("vout").and_then(|x| x.as_array()) {
        Some(a) => a,
        None => return Ok(None),
    };
    let vo = match vouts.get(vout as usize) {
        Some(o) => o,
        None => return Ok(None),
    };
    let script_hex = match vo.get("scriptpubkey").and_then(|x| x.as_str()) {
        Some(s) => s,
        None => return Ok(None),
    };
    let script_bytes = hex::decode(script_hex).map_err(|e| format!("script hex: {}", e))?;
    let script = bitcoin::ScriptBuf::from_bytes(script_bytes);
    let address = Address::from_script(&script, network).ok();
    Ok(Some((script, address)))
}

/// Walk forward from a spent reserves address along the largest-value output
/// chain, returning the first unspent UTXO encountered. Stops at depth
/// `max_hops` to avoid infinite chases on pathological data.
///
/// The "rotation" model: when an operator rotates reserves, the spending tx
/// has one large output (the new vault) and possibly some small change /
/// fee-bump outputs. Pick the largest output that's bc1p (taproot-shaped) on
/// each hop; if unspent, return it.
fn chase_reserves_chain(
    start: &Address,
    network: Network,
    esplora: &str,
    max_hops: usize,
) -> Result<Option<(bitcoin::OutPoint, u64, Address)>, String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| format!("http client: {}", e))?;
    let mut current: Address = start.clone();
    let start_str = start.to_string();
    let mut visited: HashSet<String> = HashSet::new();
    visited.insert(start_str.clone());

    for hop in 0..max_hops {
        // First: is `current` itself unspent? (After hop 0 the current
        // address was a vout of a previous spend tx; might still be sitting.)
        if hop > 0 {
            if let Some((op, val)) = fetch_utxo(&current, esplora)? {
                return Ok(Some((op, val, current.clone())));
            }
        }
        // Find the spending tx out of `current`. Esplora returns confirmed
        // txs for an address (newest-first); we look for one whose vin
        // consumes a UTXO of `current`.
        let url = format!("{}/address/{}/txs", esplora, current);
        let resp = client
            .get(&url)
            .send()
            .map_err(|e| format!("GET {}: {}", url, e))?;
        if !resp.status().is_success() {
            return Err(format!("esplora {}: status {}", url, resp.status()));
        }
        let txs: Vec<serde_json::Value> =
            resp.json().map_err(|e| format!("json: {}", e))?;

        let cur_str = current.to_string();
        let spending = txs.iter().find(|tx| {
            tx.get("vin").and_then(|v| v.as_array()).map_or(false, |vin| {
                vin.iter().any(|i| {
                    i.get("prevout")
                        .and_then(|p| p.get("scriptpubkey_address"))
                        .and_then(|v| v.as_str())
                        == Some(cur_str.as_str())
                })
            })
        });
        let tx = match spending {
            Some(t) => t,
            None => {
                println!(
                    "      hop {}: no spending tx found from {}",
                    hop, current
                );
                return Ok(None);
            }
        };
        let txid = tx.get("txid").and_then(|v| v.as_str()).unwrap_or("");
        println!("      hop {}: spent in {} — picking largest vout", hop, txid);

        // Largest taproot-shape (bc1p) output of the spending tx. If none,
        // try the largest output regardless of shape — the rotation may
        // have used a different address class in some old code paths.
        let vout = tx.get("vout").and_then(|v| v.as_array()).cloned().unwrap_or_default();
        let mut candidate: Option<(usize, u64, Address)> = None;
        for (idx, v) in vout.iter().enumerate() {
            let value = match v.get("value").and_then(|x| x.as_u64()) {
                Some(n) => n,
                None => continue,
            };
            let addr_str = match v.get("scriptpubkey_address").and_then(|x| x.as_str()) {
                Some(s) => s,
                None => continue,
            };
            let addr = match addr_str
                .parse::<Address<bitcoin::address::NetworkUnchecked>>()
                .ok()
                .and_then(|a| a.require_network(network).ok())
            {
                Some(a) => a,
                None => continue,
            };
            // Don't backtrack — skip an output that lands at an address we
            // already walked through.
            if visited.contains(&addr_str.to_string()) {
                continue;
            }
            match &candidate {
                None => candidate = Some((idx, value, addr)),
                Some((_, best, _)) if value > *best => {
                    candidate = Some((idx, value, addr))
                }
                _ => {}
            }
        }
        let (_, _, next) = match candidate {
            Some(c) => c,
            None => {
                println!("      hop {}: no usable vout (all already visited)", hop);
                return Ok(None);
            }
        };
        visited.insert(next.to_string());
        current = next;
    }
    println!(
        "      max hops ({}) exhausted without finding an unspent UTXO",
        max_hops
    );
    Ok(None)
}

/// Current chain tip height per esplora.
fn fetch_tip_height(esplora: &str) -> Result<u32, String> {
    let url = format!("{}/blocks/tip/height", esplora);
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| format!("http client: {}", e))?;
    let resp = client
        .get(&url)
        .send()
        .map_err(|e| format!("GET {}: {}", url, e))?;
    if !resp.status().is_success() {
        return Err(format!("esplora {}: status {}", url, resp.status()));
    }
    resp.text()
        .map_err(|e| format!("body: {}", e))?
        .trim()
        .parse::<u32>()
        .map_err(|e| format!("parse height: {}", e))
}

/// Block height of the tx that funded a given UTXO, or `None` for mempool.
fn fetch_tx_block_height(esplora: &str, txid: &bitcoin::Txid) -> Result<Option<u32>, String> {
    let url = format!("{}/tx/{}/status", esplora, txid);
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| format!("http client: {}", e))?;
    let resp = client
        .get(&url)
        .send()
        .map_err(|e| format!("GET {}: {}", url, e))?;
    if !resp.status().is_success() {
        return Err(format!("esplora {}: status {}", url, resp.status()));
    }
    let v: serde_json::Value = resp.json().map_err(|e| format!("json: {}", e))?;
    if v.get("confirmed").and_then(|c| c.as_bool()) != Some(true) {
        return Ok(None);
    }
    Ok(v.get("block_height").and_then(|h| h.as_u64()).map(|h| h as u32))
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
    let mut reserves_script = taproot_output.script_pubkey();
    let mut reserves_address = taproot_output.address.clone();

    // If the snapshot carries a self-describing tree (post-2026-05-29
    // format), trust IT over the rebuild. The rebuild's purpose is to
    // recover when the daemon didn't persist the tree; once persisted,
    // any future builder-code drift is irrelevant to recovery.
    let persisted_used = summary.persisted_tree.is_some();
    if let Some(p) = &summary.persisted_tree {
        reserves_script = p.script_pubkey.clone();
        reserves_address = match Address::from_script(&reserves_script, network) {
            Ok(a) => a,
            Err(e) => {
                return Err(format!(
                    "persisted script_pubkey doesn't parse as a {} address: {:?}",
                    match network {
                        Network::Bitcoin => "mainnet",
                        Network::Testnet => "testnet",
                        Network::Signet => "signet",
                        Network::Regtest => "regtest",
                        _ => "unknown",
                    },
                    e
                ))
            }
        };
        println!(
            "  ledger {}…: using self-describing snapshot ({} tier leaves persisted)",
            hex::encode(&summary.ledger_id[..8]),
            p.tier_leaves.len()
        );
    }

    // Sanity: the address we'll spend from must match what the QuorumBegin
    // declared. SKIP when using a persisted snapshot — the persisted
    // script IS the on-chain reality, and the QuorumBegin's reserves_id
    // can be stale (that's the bug the persisted snapshot exists to
    // route around). The migrate-snapshot tool only writes a persisted
    // tree after verifying it matches the actual UTXO scriptpubkey at
    // the recorded outpoint, so trusting it here is safe.
    if !persisted_used {
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
    }

    // Find the on-chain UTXO. If the rebuilt reserves address has no UTXO,
    // we try three escalations in order:
    //   (1) the JSON-recorded outpoint — the daemon told us exactly which
    //       (txid, vout) the rotation tx wrote, even when its address field
    //       drifts from on-chain reality. This is the most useful diagnostic:
    //       inspect the actual scriptpubkey at that outpoint, report whether
    //       it's still unspent and which address it actually resolves to.
    //   (2) chase the spend chain forward from the rebuilt address (catches
    //       legitimate post-snapshot rotations).
    //   (3) give up cleanly.
    if fetch_utxo(&reserves_address, esplora)?.is_none() {
        // (1) JSON-recorded outpoint diagnostic.
        if let Some((txid, vout)) = summary.outpoint {
            match fetch_outpoint_script(esplora, txid, vout, network)? {
                Some((script, Some(actual_addr))) => {
                    let drift = actual_addr.script_pubkey() != reserves_script;
                    let unspent = fetch_utxo(&actual_addr, esplora)?;
                    println!(
                        "  ledger {}…: snapshot outpoint {}:{} resolves to {}",
                        hex::encode(&summary.ledger_id[..8]),
                        txid,
                        vout,
                        actual_addr
                    );
                    if drift {
                        println!(
                            "    DRIFT: snapshot json says address={} but tx vout's \
                             scriptpubkey resolves to {}",
                            reserves_address, actual_addr
                        );
                        println!(
                            "    on-chain scriptpubkey (hex): {}",
                            hex::encode(script.as_bytes())
                        );
                    }
                    match unspent {
                        Some((op, val)) => {
                            println!(
                                "    UNSPENT chain leaf: {} sats at {}:{}",
                                val, op.txid, op.vout
                            );
                            if drift {
                                println!(
                                    "    funds are recoverable but signing requires \
                                     the script-builder version that produced this \
                                     scriptpubkey. Run reserves-bisect.sh to identify it."
                                );
                                return Ok(());
                            }
                            return Ok(()); // rebuild matched but UTXO at a different op — also bail
                        }
                        None => {
                            println!(
                                "    UTXO at recorded outpoint is already spent."
                            );
                        }
                    }
                }
                Some((script, None)) => {
                    println!(
                        "  ledger {}…: snapshot outpoint {}:{} scriptpubkey {} \
                         doesn't parse as a {} address",
                        hex::encode(&summary.ledger_id[..8]),
                        txid,
                        vout,
                        hex::encode(script.as_bytes()),
                        match network {
                            Network::Bitcoin => "mainnet",
                            Network::Testnet => "testnet",
                            Network::Signet => "signet",
                            Network::Regtest => "regtest",
                            _ => "unknown",
                        }
                    );
                }
                None => {
                    println!(
                        "  ledger {}…: snapshot outpoint {}:{} not found on esplora",
                        hex::encode(&summary.ledger_id[..8]),
                        txid,
                        vout
                    );
                }
            }
        }
    }

    let (outpoint, amount, current_address) = match fetch_utxo(&reserves_address, esplora)? {
        Some((op, val)) => (op, val, reserves_address.clone()),
        None => {
            // (2) chain chase.
            println!(
                "  ledger {}…: reserves address has no unspent UTXO; following spend chain…",
                hex::encode(&summary.ledger_id[..8])
            );
            match chase_reserves_chain(&reserves_address, network, esplora, 10)? {
                Some((op, val, addr)) => {
                    println!(
                        "    chain leaf: {} sats at {}",
                        val, addr
                    );
                    if addr != reserves_address {
                        println!(
                            "    address differs from our rebuild {} — rotation \
                             happened off-state, can't sign blindly; skipping",
                            reserves_address
                        );
                        return Ok(());
                    }
                    (op, val, addr)
                }
                None => {
                    // (3) give up.
                    println!(
                        "    no unspent UTXO downstream — funds left this address tree"
                    );
                    return Ok(());
                }
            }
        }
    };
    let _ = current_address;

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
    // Prefer the persisted tier-0 leaf when a self-describing snapshot is
    // present. Same fallback story: rebuild only if we have to.
    let leaf_script = if let Some(p) = &summary.persisted_tree {
        p.tier_leaves
            .iter()
            .find(|t| t.tier_index == 0)
            .map(|t| t.leaf_script.clone())
            .ok_or("persisted snapshot lacks tier-0 leaf")?
    } else {
        builder
            .build_threshold_leaf(&tier0)
            .map_err(|e| format!("build tier-0 leaf: {:?}", e))?
    };
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
    let control_block = if let Some(p) = &summary.persisted_tree {
        p.tier_leaves
            .iter()
            .find(|t| t.tier_index == 0)
            .map(|t| t.control_block.clone())
            .ok_or("persisted snapshot lacks tier-0 control block")?
    } else {
        taproot_output
            .control_block_for_tier(0)
            .ok_or("no control block for tier 0")?
    };
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

/// For each armed dispute round in a ledger's history, rebuild the lottery
/// script address (same logic as audit-balances::reconstruct_lottery_addresses),
/// look up its on-chain UTXO, and — if unspent and a recovery leaf's CSV is
/// satisfied with keys we hold — sweep via that leaf to `destination_script`.
///
/// The lottery output's claim leaves need preimages we don't have (they live
/// in CustodyLotteryReveal events that may never have been published). The
/// recovery leaves only need a quorum-minus-disputed-operator signature
/// threshold, which sweep-all already holds if it operates the whole cluster.
fn sweep_lottery_recovery_for_ledger(
    jsonl: &std::path::Path,
    operator_name: &str,
    keyring: &HashMap<bitcoin::secp256k1::PublicKey, [u8; 32]>,
    destination_script: &bitcoin::ScriptBuf,
    network: Network,
    esplora: &str,
    dry_run: bool,
) -> Result<usize, String> {
    use deposits_core::tapscript_reserves::{LotteryParticipant, LotteryScriptBuilder};
    use std::io::BufRead;

    // Re-parse the jsonl (same shape sweep-all already uses for
    // summarize_ledger — kept narrow here to avoid threading more data
    // through the existing summary type).
    let file = std::fs::File::open(jsonl).map_err(|e| format!("open {:?}: {}", jsonl, e))?;
    let mut updates: Vec<SignedLedgerUpdate> = Vec::new();
    for line in std::io::BufReader::new(file).lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };
        let v: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if v.get("type").and_then(|t| t.as_str()) != Some("Update") {
            continue;
        }
        let mut obj = match v.as_object() {
            Some(o) => o.clone(),
            None => continue,
        };
        obj.remove("type");
        if let Ok(u) =
            serde_json::from_value::<SignedLedgerUpdate>(serde_json::Value::Object(obj))
        {
            updates.push(u);
        }
    }
    if updates.is_empty() {
        return Ok(0);
    }

    // Original operator from LedgerOpen, most recent QuorumBegin members.
    let mut original_operator: Option<bitcoin::secp256k1::PublicKey> = None;
    let mut qb_members: Vec<bitcoin::secp256k1::PublicKey> = Vec::new();
    for u in &updates {
        match LedgerOperation::tlv_decode(&u.message) {
            Ok(LedgerOperation::LedgerOpen { operator_id, .. })
                if original_operator.is_none() =>
            {
                original_operator = Some(operator_id);
            }
            Ok(LedgerOperation::QuorumBegin { quorum_members, .. }) => {
                qb_members = quorum_members.iter().map(|m| m.pubkey).collect();
            }
            _ => {}
        }
    }
    let original_operator = match original_operator {
        Some(p) => p,
        None => return Ok(0),
    };
    if qb_members.is_empty() {
        return Ok(0);
    }

    // Group DisputeArmed by armed_block (the round identifier).
    let mut rounds: HashMap<u32, Vec<(bitcoin::secp256k1::PublicKey, [u8; 20], String)>> =
        HashMap::new();
    for u in &updates {
        if let Ok(LedgerOperation::DisputeArmed {
            armed_block,
            commitment_hash,
            target_reserves,
            ..
        }) = LedgerOperation::tlv_decode(&u.message)
        {
            let entry = rounds.entry(armed_block).or_default();
            if !entry.iter().any(|(pk, _, _)| pk == &u.operator_id) {
                entry.push((u.operator_id, commitment_hash, target_reserves));
            }
        }
    }

    let mut swept = 0usize;
    for (armed_block, participants_raw) in rounds {
        if participants_raw.len() < 2 {
            continue;
        }
        let mut participants: Vec<LotteryParticipant> = participants_raw
            .into_iter()
            .map(|(pk, commit, target)| {
                LotteryParticipant::new(pk.x_only_public_key().0, commit, target)
            })
            .collect();
        participants.sort_by(|a, b| a.pubkey.serialize().cmp(&b.pubkey.serialize()));

        let recovery_voters: Vec<bitcoin::secp256k1::XOnlyPublicKey> = qb_members
            .iter()
            .filter(|pk| **pk != original_operator)
            .map(|pk| pk.x_only_public_key().0)
            .collect();
        let recovery_threshold = (recovery_voters.len() / 2) + 1;

        let lottery = match LotteryScriptBuilder::new(
            participants,
            recovery_voters.clone(),
            recovery_threshold,
            network,
        )
        .build()
        {
            Ok(l) => l,
            Err(e) => {
                println!(
                    "[{}] lottery round@{}: build failed: {:?}",
                    operator_name, armed_block, e
                );
                continue;
            }
        };

        let (outpoint, value) = match fetch_utxo(&lottery.address, esplora)? {
            Some(u) => u,
            None => continue, // no funds at this lottery output — nothing to sweep
        };

        // CSV gate: confirmations = tip - funding_height + 1 must reach the
        // leaf's csv_blocks. Pick the lowest CSV we satisfy with the keys
        // we hold. If we hold the timeout-recovery (threshold 1) leaf's key
        // and CSV-8064 has elapsed, that's the fallback.
        let funding_height = match fetch_tx_block_height(esplora, &outpoint.txid)? {
            Some(h) => h,
            None => {
                println!(
                    "[{}] lottery round@{} {} sats: still in mempool — skipping",
                    operator_name, armed_block, value
                );
                continue;
            }
        };
        let tip = fetch_tip_height(esplora)?;
        let confirmations = tip.saturating_sub(funding_height) + 1;

        // The order of recovery_leaves() matches the build_recovery_script
        // order — lowest CSV first. Pick the first leaf where we have
        // threshold keys AND CSV is satisfied.
        let recovery_leaves = lottery.recovery_leaves();
        let voter_order = lottery.recovery_voter_order();
        let voter_full_pks: Vec<bitcoin::secp256k1::PublicKey> = qb_members
            .iter()
            .filter(|pk| **pk != original_operator)
            .copied()
            .collect();
        // Map x-only → full pubkey so we can look up the seed in the keyring
        // (keyring is keyed on full secp256k1::PublicKey, but the lottery
        // recovery leaf works in x-only).
        let xonly_to_full: HashMap<bitcoin::secp256k1::XOnlyPublicKey, bitcoin::secp256k1::PublicKey> =
            voter_full_pks
                .iter()
                .map(|pk| (pk.x_only_public_key().0, *pk))
                .collect();

        let chosen = recovery_leaves.iter().find(|(csv, threshold, _)| {
            if confirmations < *csv {
                return false;
            }
            let held = voter_order
                .iter()
                .filter(|xo| {
                    xonly_to_full
                        .get(xo)
                        .map(|pk| keyring.contains_key(pk))
                        .unwrap_or(false)
                })
                .count();
            held >= *threshold
        });
        let (csv_blocks, threshold, leaf_script) = match chosen {
            Some(t) => (t.0, t.1, t.2.clone()),
            None => {
                println!(
                    "[{}] lottery round@{} {} sats: no recovery leaf yet satisfiable \
                     (confirmations={}, smallest CSV=144)",
                    operator_name, armed_block, value, confirmations
                );
                continue;
            }
        };

        // Build spend tx with sequence = csv_blocks (BIP-68 relative timelock).
        let params = SpendTxParams {
            reserves_outpoint: outpoint,
            reserves_amount: value,
            destination_script: destination_script.clone(),
            splits: Vec::new(),
            fee_rate_sat_vbyte: 2,
            lock_time: 0,
        };
        let mut tx = ReservesSpendBuilder::build_spend_transaction(&params, &lottery.script_pubkey())
            .map_err(|e| format!("build spend tx: {:?}", e))?;
        tx.input[0].sequence = Sequence::from_height(csv_blocks as u16);

        let sighash = ReservesSpendBuilder::compute_sighash(
            &tx,
            0,
            value,
            &lottery.script_pubkey(),
            &leaf_script,
        )
        .map_err(|e| format!("compute sighash: {:?}", e))?;
        let sighash_bytes: [u8; 32] = *sighash.as_ref();
        let msg = Message::from_digest(sighash_bytes);

        // Sign with threshold keys in script-key order. The recovery leaf
        // script processes keys sorted by .serialize(); voter_order matches.
        let secp = Secp256k1::new();
        let mut sigs_by_xonly: HashMap<bitcoin::secp256k1::XOnlyPublicKey, [u8; 64]> =
            HashMap::new();
        for xo in &voter_order {
            if sigs_by_xonly.len() >= threshold {
                break;
            }
            let full_pk = match xonly_to_full.get(xo) {
                Some(p) => p,
                None => continue,
            };
            let seed = match keyring.get(full_pk) {
                Some(s) => s,
                None => continue,
            };
            let secret = derive_operator_secret(seed, network)?;
            let keypair = Keypair::from_secret_key(&secp, &secret);
            let sig = secp.sign_schnorr(&msg, &keypair);
            sigs_by_xonly.insert(keypair.x_only_public_key().0, *sig.as_ref());
        }
        if sigs_by_xonly.len() < threshold {
            return Err(format!(
                "collected {}/{} sigs for lottery recovery",
                sigs_by_xonly.len(),
                threshold
            ));
        }

        let signatures: Vec<Option<[u8; 64]>> = voter_order
            .iter()
            .map(|xo| sigs_by_xonly.get(xo).copied())
            .collect();
        let control_block = lottery
            .recovery_control_block(&leaf_script)
            .ok_or("no control block for recovery leaf")?;
        let witness = ReservesSpendBuilder::create_checksigadd_witness(
            &signatures,
            &leaf_script,
            &control_block,
        );
        tx.input[0].witness = witness;

        let txid = tx.compute_txid();
        println!(
            "[{}] lottery round@{}: sweeping {} sats from {}:{} via recovery leaf CSV={} (T={}, confirms={})",
            operator_name,
            armed_block,
            value,
            outpoint.txid,
            outpoint.vout,
            csv_blocks,
            threshold,
            confirmations,
        );
        println!(
            "    tx {} ({} → dest, fee {} sats)",
            txid,
            tx.output[0].value.to_sat(),
            value.saturating_sub(tx.output[0].value.to_sat())
        );
        if dry_run {
            swept += 1;
            continue;
        }
        let broadcast_txid = broadcast_tx(esplora, &tx)?;
        println!("    broadcast: {}", broadcast_txid);
        swept += 1;
    }
    Ok(swept)
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
    let mut reserves_attempted = 0usize;
    let mut reserves_errors = 0usize;
    let mut wpkh_attempted = 0usize;
    let mut wpkh_errors = 0usize;
    let mut lottery_swept = 0usize;
    let mut lottery_errors = 0usize;

    // BIP-44 gap-limit conventionally 20; we keep it generous to catch
    // address-index drift on a busy node.
    const WPKH_GAP_LIMIT: u32 = 50;

    for op in &operators {
        // ===== 1. Reserves UTXOs for ledgers this operator owns =====
        let ledgers_dir = op.data_dir.join("wallet/ledgers");
        let entries = match std::fs::read_dir(&ledgers_dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        let entries: Vec<_> = entries.flatten().collect();
        for entry in &entries {
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
                continue;
            }
            if !swept_ledgers.insert(summary.ledger_id) {
                continue;
            }
            println!(
                "[{}] reserves: ledger {}…",
                op.name,
                hex::encode(&summary.ledger_id[..8]),
            );
            reserves_attempted += 1;
            if let Err(e) = sweep_ledger(
                &summary,
                &keyring,
                &destination_script,
                args.network,
                &args.esplora,
                args.dry_run,
            ) {
                println!("    ERROR: {}", e);
                reserves_errors += 1;
            }

            // Lottery-script recovery sweep for the same ledger. The
            // confiscation-tx output sits at a deterministic P2TR derived
            // from the disputants' commitments + the recovery voter set;
            // if disputants never revealed (or the lottery winner never
            // claimed) and the CSV has elapsed, this sweeps via the
            // smallest-CSV recovery leaf we can satisfy.
            match sweep_lottery_recovery_for_ledger(
                &path,
                &op.name,
                &keyring,
                &destination_script,
                args.network,
                &args.esplora,
                args.dry_run,
            ) {
                Ok(n) => lottery_swept += n,
                Err(e) => {
                    println!("    LOTTERY ERROR: {}", e);
                    lottery_errors += 1;
                }
            }
        }

        // ===== 2. Node-level wpkh wallet (m/{0,1}/*) =====
        let seed = op.seed;
        let scan = scan_wpkh_utxos(
            |change, index| derive_node_wallet_secret(&seed, change, index, args.network),
            args.network,
            &args.esplora,
            WPKH_GAP_LIMIT,
        );
        match scan {
            Ok(utxos) if !utxos.is_empty() => {
                println!(
                    "[{}] node wpkh: {} input(s) total {} sats",
                    op.name,
                    utxos.len(),
                    utxos.iter().map(|(_, a, _)| *a).sum::<u64>()
                );
                wpkh_attempted += 1;
                if let Err(e) = sweep_wpkh_inputs(
                    &format!("{} node wpkh", op.name),
                    utxos,
                    &destination_script,
                    &args.esplora,
                    args.dry_run,
                ) {
                    println!("    ERROR: {}", e);
                    wpkh_errors += 1;
                }
            }
            Ok(_) => {}
            Err(e) => {
                println!("[{}] node wpkh scan failed: {}", op.name, e);
                wpkh_errors += 1;
            }
        }

        // ===== 3. Per-ledger wpkh wallets (m/86'/0'/<account>'/{0,1}/*) =====
        for entry in &entries {
            let path = entry.path();
            // The per-ledger BDK wallet dir lives at <ledger_id>/ alongside
            // the <ledger_id>.jsonl history file. We only sweep wallets
            // for ledgers WE'RE the operator of — otherwise the account
            // belongs to that other operator.
            if !path.is_dir() {
                continue;
            }
            let ledger_id_str = match path.file_name().and_then(|n| n.to_str()) {
                Some(s) => s.to_string(),
                None => continue,
            };
            // Only consider hex-looking 64-char ledger IDs.
            if ledger_id_str.len() != 64
                || !ledger_id_str.bytes().all(|b| b.is_ascii_hexdigit())
            {
                continue;
            }
            // Confirm operator ownership via the jsonl summary (cheap re-replay).
            let jsonl = ledgers_dir.join(format!("{}.jsonl", ledger_id_str));
            let summary = match summarize_ledger(&jsonl) {
                Ok(Some(s)) if s.operator_key == op.operator_pubkey => s,
                _ => continue,
            };
            let account_file = path.join("account_index.txt");
            let account: u32 = match std::fs::read_to_string(&account_file) {
                Ok(s) => match s.trim().parse() {
                    Ok(n) => n,
                    Err(_) => continue,
                },
                Err(_) => continue,
            };
            let scan = scan_wpkh_utxos(
                |change, index| {
                    derive_ledger_wallet_secret(&seed, account, change, index, args.network)
                },
                args.network,
                &args.esplora,
                WPKH_GAP_LIMIT,
            );
            match scan {
                Ok(utxos) if !utxos.is_empty() => {
                    println!(
                        "[{}] ledger-wpkh {}… (account {}): {} input(s) total {} sats",
                        op.name,
                        &ledger_id_str[..16],
                        account,
                        utxos.len(),
                        utxos.iter().map(|(_, a, _)| *a).sum::<u64>(),
                    );
                    wpkh_attempted += 1;
                    if let Err(e) = sweep_wpkh_inputs(
                        &format!("{} ledger-wpkh {}…", op.name, &ledger_id_str[..16]),
                        utxos,
                        &destination_script,
                        &args.esplora,
                        args.dry_run,
                    ) {
                        println!("    ERROR: {}", e);
                        wpkh_errors += 1;
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    println!(
                        "[{}] ledger-wpkh {}… scan failed: {}",
                        op.name,
                        &ledger_id_str[..16],
                        e
                    );
                    wpkh_errors += 1;
                }
            }
            let _ = summary;
        }
    }

    println!();
    println!("=== Summary ===");
    println!("  Reserves attempted: {}", reserves_attempted);
    println!("  Reserves errors:    {}", reserves_errors);
    println!("  WPKH attempted:     {}", wpkh_attempted);
    println!("  WPKH errors:        {}", wpkh_errors);
    println!("  Lottery swept:      {}", lottery_swept);
    println!("  Lottery errors:     {}", lottery_errors);
    println!(
        "  Mode:               {}",
        if args.dry_run { "dry-run" } else { "live" }
    );
    if reserves_errors + wpkh_errors + lottery_errors > 0 {
        std::process::exit(1);
    }
    Ok(())
}
