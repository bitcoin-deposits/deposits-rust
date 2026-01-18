//! Treasury wallet send utility for Mutinynet.
//!
//! Usage: cargo run --bin treasury-send -- <address> <amount_sats>
//!        cargo run --bin treasury-send -- --fund-nodes
//!        cargo run --bin treasury-send -- --reclaim-seeds
//!
//! Sends bitcoin from the treasury wallet to specified addresses.

use std::collections::HashSet;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::str::FromStr;

use bdk_wallet::bitcoin::bip32::{DerivationPath, Xpriv};
use bdk_wallet::bitcoin::hashes::{sha256, Hash};
use bdk_wallet::bitcoin::secp256k1::{Message, Secp256k1};
use bdk_wallet::bitcoin::sighash::SighashCache;
use bdk_wallet::bitcoin::{
    absolute, transaction, Address, Amount, CompressedPublicKey, Network, OutPoint, PrivateKey,
    ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};

const ESPLORA_URL: &str = "https://mutinynet.com/api";
const TREASURY_SEED_PATH: &str = "treasury/treasury_seed";
const SEEDS_LOG_PATH: &str = "treasury/seeds.log";

// Node ports for fund-nodes command
const NODES: &[(&str, u16)] = &[("alice", 3011), ("bob", 3012), ("charlie", 3013)];
const FUNDING_AMOUNT: u64 = 25_000; // 25k sats per node (network-init needs 15k)
const MIN_BALANCE: u64 = 15_000; // Don't fund if already has 15k sats (network-init minimum)

#[derive(Debug)]
struct Utxo {
    txid: bitcoin::Txid,
    vout: u32,
    value: u64,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        print_usage();
        std::process::exit(1);
    }

    if args[1] == "--fund-nodes" {
        return fund_nodes();
    }

    if args[1] == "--reclaim-seeds" {
        return reclaim_seeds();
    }

    if args[1] == "--find-address" {
        if args.len() < 3 {
            eprintln!("Usage: treasury-send --find-address <address>");
            std::process::exit(1);
        }
        return find_address(&args[2]);
    }

    if args.len() < 3 {
        print_usage();
        std::process::exit(1);
    }

    let address_str = &args[1];
    let amount_sats: u64 = args[2].parse()?;

    send_to_address(address_str, amount_sats)?;

    Ok(())
}

fn print_usage() {
    eprintln!("Usage:");
    eprintln!("  treasury-send <address> <amount_sats>  - Send to a single address");
    eprintln!("  treasury-send --fund-nodes             - Auto-fund all nodes");
    eprintln!("  treasury-send --reclaim-seeds          - Sweep from all historical seed addresses");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  treasury-send tb1q... 10000000        - Send 0.1 BTC");
    eprintln!("  treasury-send --fund-nodes            - Fund alice, bob, charlie");
    eprintln!("  treasury-send --reclaim-seeds         - Reclaim funds from old wallets");
}

fn fund_nodes() -> Result<(), Box<dyn std::error::Error>> {
    println!("Checking node balances and funding as needed...\n");

    let client = reqwest::blocking::Client::new();
    let mut nodes_to_fund: Vec<(String, String, u64)> = Vec::new();

    for (name, port) in NODES {
        // Get node address
        let url = format!("http://localhost:{}/bitcoin/address", port);
        let resp: serde_json::Value = match client.get(&url).send() {
            Ok(r) => r.json()?,
            Err(_) => {
                println!("  {}: node not running, skipping", name);
                continue;
            }
        };
        let address = resp["data"]["address"].as_str().unwrap_or("").to_string();

        if address.is_empty() {
            println!("  {}: could not get address", name);
            continue;
        }

        // Get node balance - only check confirmed on-chain balance, not pending Lightning
        let url = format!("http://localhost:{}/bitcoin/balance", port);
        let resp: serde_json::Value = client.get(&url).send()?.json()?;
        let balance = resp["data"]["balance_sat"].as_u64().unwrap_or(0);

        if balance >= MIN_BALANCE {
            println!("  {}: already funded ({} sat on-chain)", name, balance);
        } else {
            let needed = FUNDING_AMOUNT;
            println!("  {}: needs funding ({} sat -> {} sat)", name, balance, needed);
            nodes_to_fund.push((name.to_string(), address, needed));
        }
    }

    if nodes_to_fund.is_empty() {
        println!("\nAll nodes are already funded!");
        return Ok(());
    }

    println!("\nFunding {} nodes from treasury...\n", nodes_to_fund.len());

    for (name, address, amount) in &nodes_to_fund {
        match send_to_address(address, *amount) {
            Ok(txid) => println!("  {}: sent {} sat (txid: {})", name, amount, txid),
            Err(e) => println!("  {}: FAILED - {}", name, e),
        }
    }

    println!("\nFunding complete! Wait ~3 minutes for confirmation on Mutinynet.");
    println!("Check status: ./mutinynet-treasury.sh balance");

    Ok(())
}

fn send_to_address(address_str: &str, amount_sats: u64) -> Result<String, Box<dyn std::error::Error>>
{
    let network = Network::Signet;

    // Load treasury key
    let (private_key, treasury_address, treasury_script) = load_treasury_key(network)?;

    // Parse destination address
    let dest_address = Address::from_str(address_str)?.require_network(network)?;

    // Get UTXOs
    let utxos = get_utxos(&treasury_address.to_string())?;

    if utxos.is_empty() {
        return Err("No UTXOs available in treasury".into());
    }

    let total_available: u64 = utxos.iter().map(|u| u.value).sum();

    // Estimate fee (simple: 1 sat/vbyte, ~150 vbytes for 1-in-1-out p2wpkh)
    let fee_rate = 1; // sat/vbyte - mutinynet has low fees
    let estimated_vsize = 110 + (utxos.len() as u64 * 68); // rough estimate
    let fee = fee_rate * estimated_vsize;

    let total_needed = amount_sats + fee;
    if total_available < total_needed {
        return Err(format!(
            "Insufficient funds: have {} sat, need {} sat (amount {} + fee {})",
            total_available, total_needed, amount_sats, fee
        )
        .into());
    }

    // Build transaction
    let mut inputs = Vec::new();
    let mut input_sum = 0u64;

    for utxo in &utxos {
        inputs.push(TxIn {
            previous_output: OutPoint { txid: utxo.txid, vout: utxo.vout },
            script_sig: ScriptBuf::new(), // Empty for segwit
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::default(),
        });
        input_sum += utxo.value;
        if input_sum >= total_needed {
            break;
        }
    }

    // Recalculate fee based on actual inputs
    let actual_vsize = 10 + (inputs.len() as u64 * 68) + 31 + 31; // header + inputs + 2 outputs
    let actual_fee = fee_rate * actual_vsize;

    let change = input_sum - amount_sats - actual_fee;

    let mut outputs = vec![TxOut {
        value: Amount::from_sat(amount_sats),
        script_pubkey: dest_address.script_pubkey(),
    }];

    // Add change output if significant
    if change > 546 {
        // dust threshold
        outputs.push(TxOut {
            value: Amount::from_sat(change),
            script_pubkey: treasury_script.clone(),
        });
    }

    let mut tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: inputs,
        output: outputs,
    };

    // Sign all inputs
    let secp = Secp256k1::new();

    for (idx, utxo) in utxos.iter().take(tx.input.len()).enumerate() {
        let mut sighash_cache = SighashCache::new(&tx);
        let sighash = sighash_cache.p2wpkh_signature_hash(
            idx,
            &treasury_script,
            Amount::from_sat(utxo.value),
            bitcoin::sighash::EcdsaSighashType::All,
        )?;

        let msg = Message::from_digest(sighash.to_byte_array());
        let sig = secp.sign_ecdsa(&msg, &private_key.inner);

        // Build witness: [signature + sighash_type, pubkey]
        let mut sig_bytes = sig.serialize_der().to_vec();
        sig_bytes.push(0x01); // SIGHASH_ALL

        let pubkey = CompressedPublicKey::from_private_key(&secp, &private_key)?;
        let pubkey_bytes = pubkey.to_bytes().to_vec();

        tx.input[idx].witness = Witness::from_slice(&[&sig_bytes, &pubkey_bytes]);
    }

    // Broadcast
    let txid = broadcast_tx(&tx)?;

    Ok(txid)
}

fn load_treasury_key(
    network: Network,
) -> Result<(PrivateKey, Address, ScriptBuf), Box<dyn std::error::Error>> {
    let seed_path = PathBuf::from(TREASURY_SEED_PATH);

    if !seed_path.exists() {
        return Err(format!(
            "Treasury not initialized. Run: ./mutinynet-treasury.sh init\nSeed file: {}",
            seed_path.display()
        )
        .into());
    }

    let seed_hex = fs::read_to_string(&seed_path)?.trim().to_string();

    if seed_hex.len() != 64 {
        return Err(format!("Invalid seed length: expected 64 hex chars, got {}", seed_hex.len())
            .into());
    }

    let seed_bytes: [u8; 32] =
        hex::decode(&seed_hex)?.try_into().map_err(|_| "Invalid seed length")?;

    // Extend to 64 bytes (same as treasury-address)
    let mut extended_seed = [0u8; 64];
    extended_seed[..32].copy_from_slice(&seed_bytes);
    let chain_code = sha256::Hash::hash(&seed_bytes);
    extended_seed[32..].copy_from_slice(chain_code.as_ref());

    let secp = Secp256k1::new();
    let master = Xpriv::new_master(network, &extended_seed)?;

    // BIP84 path: m/84'/1'/0'/0/0
    let path: DerivationPath = "m/84'/1'/0'/0/0".parse()?;
    let derived = master.derive_priv(&secp, &path)?;

    let private_key = PrivateKey::new(derived.private_key, network);
    let public_key = CompressedPublicKey::from_private_key(&secp, &private_key)?;
    let address = Address::p2wpkh(&public_key, network);
    let script_pubkey = address.script_pubkey();

    Ok((private_key, address, script_pubkey))
}

fn get_utxos(address: &str) -> Result<Vec<Utxo>, Box<dyn std::error::Error>> {
    let url = format!("{}/address/{}/utxo", ESPLORA_URL, address);

    // Use curl command - more reliable than reqwest blocking for HTTPS
    let output = std::process::Command::new("curl")
        .args(["-s", &url])
        .output()?;

    if !output.status.success() {
        return Err(format!("curl failed: {}", String::from_utf8_lossy(&output.stderr)).into());
    }

    let resp: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout)?;

    let utxos: Vec<Utxo> = resp
        .into_iter()
        .filter_map(|u| {
            let txid_str = u["txid"].as_str()?;
            let txid = bitcoin::Txid::from_str(txid_str).ok()?;
            let vout = u["vout"].as_u64()? as u32;
            let value = u["value"].as_u64()?;
            Some(Utxo { txid, vout, value })
        })
        .collect();

    Ok(utxos)
}

fn broadcast_tx(tx: &Transaction) -> Result<String, Box<dyn std::error::Error>> {
    let url = format!("{}/tx", ESPLORA_URL);
    let tx_hex = bitcoin::consensus::encode::serialize_hex(tx);

    // Use curl command for broadcast
    let output = std::process::Command::new("curl")
        .args(["-s", "-X", "POST", "-H", "Content-Type: text/plain", "-d", &tx_hex, &url])
        .output()?;

    let body = String::from_utf8_lossy(&output.stdout);

    if output.status.success() && !body.contains("error") {
        Ok(body.trim().to_string())
    } else {
        Err(format!("Broadcast failed: {}", body).into())
    }
}

/// Parse seeds.log and return unique (seed_hex, node_name) pairs
fn parse_seeds_log() -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
    let seeds_path = PathBuf::from(SEEDS_LOG_PATH);

    if !seeds_path.exists() {
        return Err(format!("Seeds log not found: {}", seeds_path.display()).into());
    }

    let file = fs::File::open(&seeds_path)?;
    let reader = BufReader::new(file);

    let mut seen_seeds: HashSet<String> = HashSet::new();
    let mut results: Vec<(String, String)> = Vec::new();

    // Format: "alice: seed=96553e27... address=tb1q... balance=9674sat"
    for line in reader.lines() {
        let line = line?;

        // Skip header lines and empty lines
        if line.starts_with("===") || line.trim().is_empty() {
            continue;
        }

        // Parse "name: seed=..."
        if let Some(colon_pos) = line.find(':') {
            let name = line[..colon_pos].trim().to_string();

            // Extract seed hex
            if let Some(seed_start) = line.find("seed=") {
                let seed_rest = &line[seed_start + 5..];
                if let Some(space_pos) = seed_rest.find(' ') {
                    let seed_hex = seed_rest[..space_pos].to_string();

                    // Only add if we haven't seen this seed before
                    if !seen_seeds.contains(&seed_hex) {
                        seen_seeds.insert(seed_hex.clone());
                        results.push((seed_hex, name));
                    }
                }
            }
        }
    }

    Ok(results)
}

/// Load key from a 128-char seed hex at a specific derivation index
/// is_change: false = external (receive), true = internal (change)
fn load_key_from_seed_hex_at_index(
    seed_hex: &str,
    network: Network,
    index: u32,
) -> Result<(PrivateKey, Address, ScriptBuf), Box<dyn std::error::Error>> {
    load_key_from_seed_hex_at_path(seed_hex, network, 0, index) // External by default
}

fn load_key_from_seed_hex_at_path(
    seed_hex: &str,
    network: Network,
    chain: u32, // 0 = external, 1 = internal/change
    index: u32,
) -> Result<(PrivateKey, Address, ScriptBuf), Box<dyn std::error::Error>> {
    // Seeds in seeds.log are 128 hex chars (64 bytes) - the raw keys_seed file
    let seed_bytes: Vec<u8> = hex::decode(seed_hex)?;

    if seed_bytes.len() != 64 {
        return Err(format!(
            "Invalid seed length: expected 64 bytes (128 hex chars), got {} bytes",
            seed_bytes.len()
        )
        .into());
    }

    let secp = Secp256k1::new();

    // LDK uses the full 64 bytes as entropy for the master key
    let master = Xpriv::new_master(network, &seed_bytes)?;

    // BIP84 path: m/84'/1'/0'/{chain}/{index} for signet
    // chain 0 = external (receive), chain 1 = internal (change)
    let path: DerivationPath = format!("m/84'/1'/0'/{}/{}", chain, index).parse()?;
    let derived = master.derive_priv(&secp, &path)?;

    let private_key = PrivateKey::new(derived.private_key, network);
    let public_key = CompressedPublicKey::from_private_key(&secp, &private_key)?;
    let address = Address::p2wpkh(&public_key, network);
    let script_pubkey = address.script_pubkey();

    Ok((private_key, address, script_pubkey))
}

/// UTXO with its signing key info
struct UtxoWithKey {
    utxo: Utxo,
    private_key: PrivateKey,
    script_pubkey: ScriptBuf,
}

/// Sweep funds from a seed to the treasury address, scanning multiple derivation indexes
fn sweep_from_seed(
    seed_hex: &str,
    treasury_address: &Address,
) -> Result<Option<(u64, String)>, Box<dyn std::error::Error>> {
    let network = Network::Signet;
    const MAX_INDEX: u32 = 200; // Scan indexes 0-199
    const GAP_LIMIT: u32 = 30; // Stop after 30 consecutive empty addresses

    let mut all_utxos: Vec<UtxoWithKey> = Vec::new();

    // Scan both external (receive) and internal (change) addresses
    for chain in [0, 1] { // 0 = external, 1 = change
        let chain_name = if chain == 0 { "external" } else { "change" };
        let mut empty_streak = 0;

        for index in 0..MAX_INDEX {
            let (private_key, address, script_pubkey) =
                load_key_from_seed_hex_at_path(seed_hex, network, chain, index)?;

            let utxos = get_utxos(&address.to_string()).unwrap_or_default();

            if utxos.is_empty() {
                empty_streak += 1;
                if empty_streak >= GAP_LIMIT {
                    break; // No more addresses likely used in this chain
                }
            } else {
                let balance: u64 = utxos.iter().map(|u| u.value).sum();
                eprintln!("    FOUND: m/84'/1'/0'/{}/{} ({}) = {} sat @ {}",
                         chain, index, chain_name, balance, address);
                empty_streak = 0;
                for utxo in utxos {
                    all_utxos.push(UtxoWithKey {
                        utxo,
                        private_key,
                        script_pubkey: script_pubkey.clone(),
                    });
                }
            }
        }
    }

    if all_utxos.is_empty() {
        return Ok(None);
    }

    let total_available: u64 = all_utxos.iter().map(|u| u.utxo.value).sum();

    // Calculate fee
    let fee_rate = 1; // sat/vbyte
    let estimated_vsize = 10 + (all_utxos.len() as u64 * 68) + 31;
    let fee = fee_rate * estimated_vsize;

    if total_available <= fee + 546 {
        // Not enough to cover fee + dust
        return Ok(None);
    }

    let sweep_amount = total_available - fee;

    // Build transaction
    let inputs: Vec<TxIn> = all_utxos
        .iter()
        .map(|u| TxIn {
            previous_output: OutPoint { txid: u.utxo.txid, vout: u.utxo.vout },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::default(),
        })
        .collect();

    let outputs = vec![TxOut {
        value: Amount::from_sat(sweep_amount),
        script_pubkey: treasury_address.script_pubkey(),
    }];

    let mut tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: inputs,
        output: outputs,
    };

    // Sign all inputs (each may have a different key)
    let secp = Secp256k1::new();

    for (idx, utxo_with_key) in all_utxos.iter().enumerate() {
        let mut sighash_cache = SighashCache::new(&tx);
        let sighash = sighash_cache.p2wpkh_signature_hash(
            idx,
            &utxo_with_key.script_pubkey,
            Amount::from_sat(utxo_with_key.utxo.value),
            bitcoin::sighash::EcdsaSighashType::All,
        )?;

        let msg = Message::from_digest(sighash.to_byte_array());
        let sig = secp.sign_ecdsa(&msg, &utxo_with_key.private_key.inner);

        let mut sig_bytes = sig.serialize_der().to_vec();
        sig_bytes.push(0x01); // SIGHASH_ALL

        let pubkey = CompressedPublicKey::from_private_key(&secp, &utxo_with_key.private_key)?;
        let pubkey_bytes = pubkey.to_bytes().to_vec();

        tx.input[idx].witness = Witness::from_slice(&[&sig_bytes, &pubkey_bytes]);
    }

    // Broadcast
    let txid = broadcast_tx(&tx)?;

    Ok(Some((sweep_amount, txid)))
}

/// Scan multiple indexes and return total balance for a seed
fn scan_seed_balance(seed_hex: &str, network: Network) -> u64 {
    const MAX_INDEX: u32 = 200;
    const GAP_LIMIT: u32 = 30;

    let mut total = 0u64;
    let mut empty_streak = 0;

    for index in 0..MAX_INDEX {
        if let Ok((_, address, _)) = load_key_from_seed_hex_at_index(seed_hex, network, index) {
            let utxos = get_utxos(&address.to_string()).unwrap_or_default();
            let balance: u64 = utxos.iter().map(|u| u.value).sum();

            if balance == 0 {
                empty_streak += 1;
                if empty_streak >= GAP_LIMIT {
                    break;
                }
            } else {
                empty_streak = 0;
                total += balance;
            }
        }
    }

    total
}

fn reclaim_seeds() -> Result<(), Box<dyn std::error::Error>> {
    let network = Network::Signet;

    // Get treasury address to sweep to
    let (_, treasury_address, _) = load_treasury_key(network)?;

    println!("Reclaiming funds from historical seed addresses...");
    println!("Treasury destination: {}", treasury_address);
    println!("Scanning up to 50 derivation indexes per seed...\n");

    // Parse seeds.log
    let seeds = parse_seeds_log()?;

    if seeds.is_empty() {
        println!("No seeds found in {}", SEEDS_LOG_PATH);
        return Ok(());
    }

    println!("Found {} unique seeds in history\n", seeds.len());

    let mut total_reclaimed: u64 = 0;
    let mut successful_sweeps = 0;

    for (seed_hex, name) in &seeds {
        // Scan all indexes for this seed
        let balance = scan_seed_balance(seed_hex, network);

        if balance == 0 {
            println!("  {}: scanning... no funds found", name);
            continue;
        }

        print!("  {}: found {} sat across indexes ... ", name, balance);

        match sweep_from_seed(seed_hex, &treasury_address) {
            Ok(Some((amount, txid))) => {
                println!("swept! txid: {}...", &txid[..16]);
                total_reclaimed += amount;
                successful_sweeps += 1;
            }
            Ok(None) => {
                println!("skipped (dust)");
            }
            Err(e) => {
                println!("FAILED: {}", e);
            }
        }
    }

    println!();
    println!("Reclaim complete!");
    println!("  Seeds checked: {}", seeds.len());
    println!("  Successful sweeps: {}", successful_sweeps);
    println!("  Total reclaimed: {} sat", total_reclaimed);

    if successful_sweeps > 0 {
        println!("\nWait ~3 minutes for confirmations on Mutinynet.");
    }

    Ok(())
}

/// Find which seed and derivation index produces a given address
fn find_address(target_address: &str) -> Result<(), Box<dyn std::error::Error>> {
    let network = Network::Signet;

    println!("Searching for address: {}", target_address);
    println!("Scanning all seeds from seeds.log...\n");

    let seeds = parse_seeds_log()?;

    for (seed_hex, name) in &seeds {
        // Scan both chains, up to 200 indexes
        for chain in [0, 1] {
            let chain_name = if chain == 0 { "external" } else { "change" };

            for index in 0..200 {
                if let Ok((_, address, _)) = load_key_from_seed_hex_at_path(seed_hex, network, chain, index) {
                    if address.to_string() == target_address {
                        println!("FOUND!");
                        println!("  Seed: {} ({})", &seed_hex[..32], name);
                        println!("  Path: m/84'/1'/0'/{}/{} ({})", chain, index, chain_name);
                        println!("  Address: {}", address);
                        return Ok(());
                    }
                }
            }
        }
    }

    println!("Address not found in any seed (checked 200 indexes per chain)");
    Ok(())
}
