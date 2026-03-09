//! Common CLI utilities shared across command modules

use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::Network;
use std::path::PathBuf;
use std::str::FromStr;

use crate::{Node, NodeConfig};

/// Derive the operator secret key from a seed using HD derivation.
/// This matches what the Wallet does, ensuring consistent key usage across the codebase.
pub fn derive_operator_secret(seed: &[u8; 32], network: Network) -> Result<SecretKey, String> {
    let secp = Secp256k1::new();

    let xpriv = Xpriv::new_master(network, seed)
        .map_err(|e| format!("Failed to create master key: {}", e))?;

    // Use the same derivation path as the Wallet: m/86'/0'/0'/0/0
    let operator_path = DerivationPath::from_str("m/86'/0'/0'/0/0")
        .map_err(|e| format!("Invalid derivation path: {}", e))?;

    let operator_xpriv = xpriv
        .derive_priv(&secp, &operator_path)
        .map_err(|e| format!("Failed to derive operator key: {}", e))?;

    Ok(operator_xpriv.private_key)
}

/// Parse command-line arguments into a NodeConfig
pub fn parse_config(args: &[String]) -> Result<NodeConfig, String> {
    let mut seed: Option<[u8; 32]> = None;
    let mut network = Network::Signet;
    let mut electrum_url = "https://mempool.space/signet/api".to_string();
    let mut relays = Vec::new();
    let mut nwc_uri = None;
    let mut operator_name = None;
    let mut fast_poll = false;
    let mut data_dir = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".deposits-bdk");

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--name" | "--operator-name" => {
                i += 1;
                if i >= args.len() {
                    return Err("--name requires a value".to_string());
                }
                operator_name = Some(args[i].clone());
            }
            "--seed" => {
                i += 1;
                if i >= args.len() {
                    return Err("--seed requires a value".to_string());
                }
                let hex = &args[i];
                if hex.len() != 64 {
                    return Err("Seed must be 64 hex characters".to_string());
                }
                let bytes = hex::decode(hex).map_err(|e| format!("Invalid hex: {}", e))?;
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                seed = Some(arr);
            }
            "--network" => {
                i += 1;
                if i >= args.len() {
                    return Err("--network requires a value".to_string());
                }
                network = match args[i].as_str() {
                    "mainnet" | "bitcoin" => Network::Bitcoin,
                    "testnet" | "testnet3" => Network::Testnet,
                    "signet" => Network::Signet,
                    "regtest" => Network::Regtest,
                    n => return Err(format!("Unknown network: {}", n)),
                };
            }
            "--electrum" | "--esplora" => {
                i += 1;
                if i >= args.len() {
                    return Err("--esplora requires a value".to_string());
                }
                electrum_url = args[i].clone();
            }
            "--relay" => {
                i += 1;
                if i >= args.len() {
                    return Err("--relay requires a value".to_string());
                }
                relays.push(args[i].clone());
            }
            "--nwc" => {
                i += 1;
                if i >= args.len() {
                    return Err("--nwc requires a value".to_string());
                }
                nwc_uri = Some(args[i].clone());
            }
            "--data-dir" => {
                i += 1;
                if i >= args.len() {
                    return Err("--data-dir requires a value".to_string());
                }
                data_dir = PathBuf::from(&args[i]);
            }
            "--fast-poll" => {
                fast_poll = true;
            }
            arg => {
                return Err(format!("Unknown argument: {}", arg));
            }
        }
        i += 1;
    }

    // Generate random seed if not provided
    let seed = seed.unwrap_or_else(|| {
        use std::time::{SystemTime, UNIX_EPOCH};
        let mut s = [0u8; 32];
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        s[0..16].copy_from_slice(&now.to_le_bytes());
        // In production, use proper random source
        tracing::warn!("Using timestamp-based seed. In production, provide --seed");
        s
    });

    // Create data directory
    std::fs::create_dir_all(&data_dir)
        .map_err(|e| format!("Failed to create data dir: {}", e))?;

    Ok(NodeConfig {
        seed,
        network,
        electrum_url,
        relays,
        slow_relays: Vec::new(),
        nwc_uri,
        data_dir,
        operator_name,
        fast_poll,
        skip_nostr_verify: false,
    })
}

/// Resolve a ledger_id (hash) to the actual reserves_key
pub fn resolve_ledger_id_to_reserves_key(node: &Node, ledger_id: &str) -> Result<String, String> {
    // Direct lookup by ledger_id (now the key)
    let ledgers = node.list_ledgers();
    if let Some(ledger_arc) = ledgers.get(ledger_id) {
        let ledger = ledger_arc.read().unwrap();
        return Ok(ledger.reserves_key().to_string());
    }
    Err(format!("Ledger not found by hash: {}", ledger_id))
}
