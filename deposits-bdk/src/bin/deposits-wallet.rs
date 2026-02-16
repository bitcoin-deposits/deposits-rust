//! Deposits Wallet - A Nostr-based wallet for depositors
//!
//! Discovers ledger operators, opens deposits, and manages balances.
//!
//! Usage:
//!   deposits-wallet discover                   - Find available ledgers
//!   deposits-wallet open <ledger_id> <sats>    - Open a new deposit
//!   deposits-wallet offer <alias> <sats>       - Add funds to existing deposit
//!   deposits-wallet list                       - List deposits with aliases
//!   deposits-wallet balance                    - Check balances
//!   deposits-wallet withdraw <alias> <amount>  - Withdraw funds (on-chain)
//!   deposits-wallet make_invoice <alias> <amt> - Create Lightning invoice
//!   deposits-wallet pay_invoice <alias> <bolt11> - Pay Lightning invoice

use bitcoin::secp256k1::{Secp256k1, SecretKey};
use chrono::Utc;
use deposits_bdk::nostr::{NostrTransportBuilder, KIND_LEDGER_UPDATE};
use std::collections::{BTreeMap, HashSet};
use std::io::Write;
use std::path::PathBuf;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use nostr_sdk::prelude::*;
use deposits_core::tlv::TlvDecode;
use deposits_core::SignedLedgerUpdate;
use deposits_core::messages::LedgerOperation;

// ANSI color codes for --color-by-pk
const COLORS: &[&str] = &[
    "\x1b[31m", "\x1b[32m", "\x1b[33m", "\x1b[34m", "\x1b[35m", "\x1b[36m",
    "\x1b[91m", "\x1b[92m", "\x1b[93m", "\x1b[94m", "\x1b[95m", "\x1b[96m",
    "\x1b[38;5;208m", "\x1b[38;5;205m", "\x1b[38;5;118m", "\x1b[38;5;39m",
];
const RESET: &str = "\x1b[0m";

#[derive(Debug, Clone)]
struct WalletConfig {
    seed: [u8; 32],
    network: bitcoin::Network,
    data_dir: PathBuf,
    relays: Vec<String>,
}

fn print_usage(program: &str) {
    eprintln!("Deposits Wallet - Nostr-based custody wallet");
    eprintln!();
    eprintln!("Usage: {} <command> [options]", program);
    eprintln!();
    eprintln!("Commands:");
    eprintln!("  discover                    Find available ledgers on the network");
    eprintln!("  info <ledger_id>            Get details about a specific ledger");
    eprintln!("  open <ledger_id> <sats>     Open a new deposit on a ledger");
    eprintln!("  offer <alias> <sats>        Add funds to an existing deposit");
    eprintln!("  balance                     Show balances across all deposits");
    eprintln!("  sync                        Sync deposit statuses from daemon");
    eprintln!("  withdraw <alias> <amt>      Withdraw from a deposit (on-chain)");
    eprintln!("  make_invoice <alias> <amt>  Create Lightning invoice for deposit");
    eprintln!("  pay_invoice <alias> <bolt11> Pay Lightning invoice from deposit");
    eprintln!("  history <alias>             Show transaction history");
    eprintln!("  list                        List all your deposits with aliases");
    eprintln!();
    eprintln!("Ledger inspection (read-only from Nostr):");
    eprintln!("  ledger list                 List all ledgers on the relay");
    eprintln!("  ledger show <id>            Show all updates for a ledger");
    eprintln!("  ledger validate <id>        Validate ledger hash chain");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --relay <url>       Nostr relay URL (required)");
    eprintln!("  --network <net>     Network: bitcoin, testnet, signet, regtest (default: regtest)");
    eprintln!("  --data-dir <path>   Data directory (default: ~/.deposits-wallet)");
    eprintln!("  --seed <hex>        Wallet seed (32 bytes hex)");
    eprintln!("  --alias <name>      Local alias for the deposit (for open command)");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  {} discover --relay ws://localhost:8080", program);
    eprintln!("  {} open abc123... 100000 --alias savings --relay ws://localhost:8080", program);
    eprintln!("  {} offer savings 50000 --relay ws://localhost:8080", program);
    eprintln!("  {} withdraw savings 25000 --to bc1q... --relay ws://localhost:8080", program);
}

fn parse_config(args: &[String]) -> Result<WalletConfig, Box<dyn std::error::Error>> {
    let mut seed: Option<[u8; 32]> = None;
    let mut network = bitcoin::Network::Regtest;
    let mut data_dir: Option<PathBuf> = None;
    let mut relays = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--seed" if i + 1 < args.len() => {
                let seed_hex = &args[i + 1];
                let seed_bytes = hex::decode(seed_hex)?;
                if seed_bytes.len() != 32 {
                    return Err("Seed must be 32 bytes".into());
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&seed_bytes);
                seed = Some(arr);
                i += 1;
            }
            "--network" if i + 1 < args.len() => {
                network = match args[i + 1].as_str() {
                    "bitcoin" | "mainnet" => bitcoin::Network::Bitcoin,
                    "testnet" => bitcoin::Network::Testnet,
                    "signet" => bitcoin::Network::Signet,
                    "regtest" => bitcoin::Network::Regtest,
                    _ => return Err(format!("Unknown network: {}", args[i + 1]).into()),
                };
                i += 1;
            }
            "--data-dir" if i + 1 < args.len() => {
                data_dir = Some(PathBuf::from(&args[i + 1]));
                i += 1;
            }
            "--relay" if i + 1 < args.len() => {
                relays.push(args[i + 1].clone());
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }

    // Default data directory
    let data_dir = data_dir.unwrap_or_else(|| {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".deposits-wallet")
    });

    // Create data dir if needed
    std::fs::create_dir_all(&data_dir)?;

    // Load or generate seed
    let seed = if let Some(s) = seed {
        s
    } else {
        let seed_file = data_dir.join("seed.hex");
        if seed_file.exists() {
            let seed_hex = std::fs::read_to_string(&seed_file)?;
            let seed_bytes = hex::decode(seed_hex.trim())?;
            if seed_bytes.len() != 32 {
                return Err("Invalid seed file".into());
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&seed_bytes);
            arr
        } else {
            // Generate new seed
            use bitcoin::secp256k1::rand::rngs::OsRng;
            use bitcoin::secp256k1::rand::RngCore;
            let mut rng = OsRng;
            let mut arr = [0u8; 32];
            rng.fill_bytes(&mut arr);
            std::fs::write(&seed_file, hex::encode(&arr))?;
            eprintln!("Generated new wallet seed: {}", seed_file.display());
            arr
        }
    };

    Ok(WalletConfig {
        seed,
        network,
        data_dir,
        relays,
    })
}

fn derive_secret_key(seed: &[u8; 32], network: bitcoin::Network) -> Result<SecretKey, Box<dyn std::error::Error>> {
    derive_secret_key_at_index(seed, network, 0)
}

/// Derive a secret key at a specific index for per-deposit key isolation
fn derive_secret_key_at_index(seed: &[u8; 32], network: bitcoin::Network, index: u32) -> Result<SecretKey, Box<dyn std::error::Error>> {
    use bitcoin::bip32::{Xpriv, DerivationPath};
    use std::str::FromStr;

    let xpriv = Xpriv::new_master(network, seed)?;
    let secp = Secp256k1::new();

    // Use BIP-84 path for wallet keys with varying index
    // m/84'/0'/0'/0/{index} - each deposit gets a unique key
    let path = DerivationPath::from_str(&format!("m/84'/0'/0'/0/{}", index))?;
    let derived = xpriv.derive_priv(&secp, &path)?;

    Ok(derived.private_key)
}

/// Load the next available deposit key index from disk
fn load_deposit_key_index(data_dir: &std::path::PathBuf) -> u32 {
    let index_file = data_dir.join("deposit_key_index.txt");
    if !index_file.exists() {
        return 0;
    }
    std::fs::read_to_string(&index_file)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

/// Save the deposit key index to disk
fn save_deposit_key_index(data_dir: &std::path::PathBuf, index: u32) -> Result<(), std::io::Error> {
    let index_file = data_dir.join("deposit_key_index.txt");
    std::fs::write(&index_file, index.to_string())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        print_usage(&args[0]);
        return Ok(());
    }

    match args[1].as_str() {
        "discover" => discover(&args[2..]).await,
        "info" => ledger_info(&args[2..]).await,
        "open" => open_new_deposit(&args[2..]).await,
        "offer" => add_offer(&args[2..]).await,
        "balance" => show_balance(&args[2..]).await,
        "sync" => sync_deposits(&args[2..]).await,
        "withdraw" => withdraw(&args[2..]).await,
        "make_invoice" => make_invoice(&args[2..]).await,
        "pay_invoice" => pay_invoice(&args[2..]).await,
        "history" => show_history(&args[2..]).await,
        "list" => list_deposits(&args[2..]).await,
        "ledger" => ledger_command(&args[2..]).await,
        "help" | "--help" | "-h" => {
            print_usage(&args[0]);
            Ok(())
        }
        cmd => {
            eprintln!("Unknown command: {}", cmd);
            print_usage(&args[0]);
            Ok(())
        }
    }
}

/// Discover available ledgers on the network
async fn discover(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let config = parse_config(args)?;

    if config.relays.is_empty() {
        return Err("No relay specified. Use --relay <url>".into());
    }

    let network_str = match config.network {
        bitcoin::Network::Bitcoin => "bitcoin",
        bitcoin::Network::Testnet => "testnet",
        bitcoin::Network::Signet => "signet",
        bitcoin::Network::Regtest => "regtest",
        _ => "unknown",
    };

    println!("Discovering ledgers on {} network...", network_str);
    println!();

    let secret_key = derive_secret_key(&config.seed, config.network)?;
    let transport = NostrTransportBuilder::new(secret_key)
        .relay(&config.relays[0])
        .build()
        .await?;

    let ads = transport.fetch_ledger_advertisements(network_str).await?;

    if ads.is_empty() {
        println!("No ledgers found.");
        println!();
        println!("Operators can advertise with:");
        println!("  deposits-bdk ledger advertise <reserves_id> --relay <url>");
        return Ok(());
    }

    println!("Found {} ledger(s):", ads.len());
    println!();

    // Build a map of operator pubkey -> name for quorum member lookups
    let pubkey_to_name: std::collections::HashMap<&str, &str> = ads.iter()
        .filter_map(|a| {
            a.operator_name.as_deref()
                .map(|name| (a.operator_pubkey.as_str(), name))
        })
        .collect();

    for (i, ad) in ads.iter().enumerate() {
        let operator_name = ad.operator_name.as_deref().unwrap_or("Anonymous");
        println!("{}. {} ({}...)", i + 1, operator_name, &ad.operator_pubkey[..8.min(ad.operator_pubkey.len())]);
        println!("   Ledger: {}", ad.ledger_id);
        println!("   Available: {} sats ({} BTC)",
            ad.available_headroom_sats,
            ad.available_headroom_sats as f64 / 100_000_000.0);
        println!("   Reserves: {} sats, Obligations: {} sats",
            ad.reserves_amount_sats, ad.total_obligations_sats);
        println!("   Quorum: {} members ({} sats collateral)",
            ad.quorum_size, ad.received_collateral_sats);
        if !ad.quorum_members.is_empty() {
            let member_names: Vec<String> = ad.quorum_members.iter()
                .map(|m| {
                    match pubkey_to_name.get(m.pubkey.as_str()) {
                        Some(name) => format!("{} ({}...)", name, &m.pubkey[..8.min(m.pubkey.len())]),
                        None => format!("{}...", &m.pubkey[..8.min(m.pubkey.len())]),
                    }
                })
                .collect();
            println!("     Members: {}", member_names.join(", "));
        }

        // Fee summary
        let annual_pct = ad.annual_fee_bps as f64 / 100.0;
        // Annualize the fixed fee using actual fee period
        let periods_per_year = 52560u64 / ad.fee_period_blocks.max(1) as u64;
        let annualized_fixed = ad.min_fee_sats.saturating_mul(periods_per_year);

        let fee_str = match (ad.annual_fee_bps > 0, annualized_fixed > 0) {
            (true, true) => format!("{}% and {} sats per year", annual_pct, annualized_fixed),
            (true, false) => format!("{}% per year", annual_pct),
            (false, true) => format!("{} sats per year", annualized_fixed),
            (false, false) => "None".to_string(),
        };

        let deposit_fee = if ad.deposit_fee_bps > 0 {
            format!(" ({}% on deposit)", ad.deposit_fee_bps as f64 / 100.0)
        } else {
            String::new()
        };

        println!("   Fees: {}{}", fee_str, deposit_fee);

        // Limits
        if ad.max_deposit_sats < u64::MAX {
            println!("   Max deposit: {} sats", ad.max_deposit_sats);
        }
        if ad.min_deposit_sats > 0 {
            println!("   Min deposit: {} sats", ad.min_deposit_sats);
        }

        if let Some(desc) = &ad.description {
            println!("   {}", desc);
        }
        println!();
    }

    println!("To open a deposit, use:");
    println!("  deposits-wallet open <ledger_id> <amount_sats> --alias <name>");

    Ok(())
}

/// Get detailed info about a specific ledger
async fn ledger_info(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut ledger_id: Option<String> = None;
    let mut config_args = Vec::new();

    for arg in args {
        if arg.starts_with("--") {
            config_args.push(arg.clone());
        } else if ledger_id.is_none() {
            ledger_id = Some(arg.clone());
        } else {
            config_args.push(arg.clone());
        }
    }

    // Handle --relay after positional
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--relay" && i + 1 < args.len() {
            config_args.push(args[i].clone());
            config_args.push(args[i + 1].clone());
        }
        i += 1;
    }

    let ledger_id = ledger_id.ok_or("Usage: deposits-wallet info <ledger_id> --relay <url>")?;
    let config = parse_config(&config_args)?;

    if config.relays.is_empty() {
        return Err("No relay specified. Use --relay <url>".into());
    }

    let secret_key = derive_secret_key(&config.seed, config.network)?;
    let transport = NostrTransportBuilder::new(secret_key)
        .relay(&config.relays[0])
        .build()
        .await?;

    let network_str = match config.network {
        bitcoin::Network::Bitcoin => "bitcoin",
        bitcoin::Network::Testnet => "testnet",
        bitcoin::Network::Signet => "signet",
        bitcoin::Network::Regtest => "regtest",
        _ => "unknown",
    };

    // Try to find by prefix match
    let full_ledger_id = if ledger_id.len() < 64 {
        // Search for matching ledger
        let ads = transport.fetch_ledger_advertisements(network_str).await?;
        ads.into_iter()
            .find(|a| a.ledger_id.starts_with(&ledger_id))
            .map(|a| a.ledger_id)
            .ok_or_else(|| format!("No ledger found matching: {}", ledger_id))?
    } else {
        ledger_id
    };

    let ad = transport.fetch_ledger_advertisement(&full_ledger_id).await?
        .ok_or_else(|| format!("Ledger not found: {}", full_ledger_id))?;

    println!("Ledger Information");
    println!("==================");
    println!();
    println!("Operator: {}", ad.operator_name.as_deref().unwrap_or("Anonymous"));
    println!("Operator Pubkey: {}", ad.operator_pubkey);
    println!("Ledger ID: {}", ad.ledger_id);
    println!("Reserves Address: {}", ad.reserves_address);
    println!();
    println!("Capacity");
    println!("--------");
    println!("Available Headroom: {} sats ({} BTC)",
        ad.available_headroom_sats,
        ad.available_headroom_sats as f64 / 100_000_000.0);
    println!("Total Reserves: {} sats", ad.reserves_amount_sats);
    println!("Current Obligations: {} sats", ad.total_obligations_sats);
    println!();
    println!("Trust & Security");
    println!("----------------");
    println!("Quorum Size: {} members", ad.quorum_size);
    println!("Received Collateral: {} sats", ad.received_collateral_sats);
    println!("Collateral Enforcement Block: {}", ad.collateral_enforcement_block);
    if !ad.quorum_members.is_empty() {
        // Fetch all ads to build pubkey -> name map for quorum member lookups
        let all_ads = transport.fetch_ledger_advertisements(network_str).await.unwrap_or_default();
        let pubkey_to_name: std::collections::HashMap<&str, &str> = all_ads.iter()
            .filter_map(|a| {
                a.operator_name.as_deref()
                    .map(|name| (a.operator_pubkey.as_str(), name))
            })
            .collect();

        println!("Quorum Members:");
        for member in &ad.quorum_members {
            let name_display = match pubkey_to_name.get(member.pubkey.as_str()) {
                Some(name) => format!("{} ({}...)", name, &member.pubkey[..12.min(member.pubkey.len())]),
                None => format!("{}...", &member.pubkey[..12.min(member.pubkey.len())]),
            };
            if member.collateral_sats > 0 {
                println!("  - {}: {} sats (expires block {})",
                    name_display,
                    member.collateral_sats,
                    member.lock_expires_block);
            } else {
                println!("  - {}: no attestation", name_display);
            }
        }
    }
    println!();
    println!("Fee Structure");
    println!("-------------");
    println!("Annual Fee: {}bps ({}%/year)", ad.annual_fee_bps, ad.annual_fee_bps as f64 / 100.0);
    println!("Deposit Fee: {}bps ({}%)", ad.deposit_fee_bps, ad.deposit_fee_bps as f64 / 100.0);
    println!("Withdrawal Fee: {}bps ({}%)", ad.withdrawal_fee_bps, ad.withdrawal_fee_bps as f64 / 100.0);
    println!("Invoice Fee: {}bps ({}%)", ad.invoice_fee_bps, ad.invoice_fee_bps as f64 / 100.0);
    if ad.min_fee_sats > 0 {
        println!("Minimum Fee: {} sats", ad.min_fee_sats);
    }
    println!();
    println!("Deposit Limits");
    println!("--------------");
    if ad.min_deposit_sats > 0 {
        println!("Minimum: {} sats", ad.min_deposit_sats);
    } else {
        println!("Minimum: None");
    }
    if ad.max_deposit_sats < u64::MAX {
        println!("Maximum: {} sats", ad.max_deposit_sats);
    } else {
        println!("Maximum: Unlimited");
    }
    if let Some(desc) = &ad.description {
        println!();
        println!("Description");
        println!("-----------");
        println!("{}", desc);
    }

    Ok(())
}

/// Open a new deposit on a ledger
async fn open_new_deposit(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut ledger_id: Option<String> = None;
    let mut amount_sats: Option<u64> = None;
    let mut alias: Option<String> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--alias" if i + 1 < args.len() => {
                alias = Some(args[i + 1].clone());
                i += 1;
            }
            s if s.starts_with("--") => {
                config_args.push(args[i].clone());
                if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                    config_args.push(args[i + 1].clone());
                    i += 1;
                }
            }
            _ => {
                if ledger_id.is_none() {
                    ledger_id = Some(args[i].clone());
                } else if amount_sats.is_none() {
                    amount_sats = Some(args[i].parse()?);
                }
            }
        }
        i += 1;
    }

    let ledger_id = ledger_id.ok_or("Usage: deposits-wallet open <ledger_id> <amount_sats> [--alias <name>] --relay <url>")?;
    let amount_sats = amount_sats.ok_or("Missing amount")?;
    let config = parse_config(&config_args)?;

    if config.relays.is_empty() {
        return Err("No relay specified. Use --relay <url>".into());
    }

    // Check if alias is already taken
    if let Some(ref a) = alias {
        let deposits_file = config.data_dir.join("deposits.json");
        if deposits_file.exists() {
            let data = std::fs::read_to_string(&deposits_file)?;
            let deposits: Vec<serde_json::Value> = serde_json::from_str(&data).unwrap_or_default();
            if deposits.iter().any(|d| d.get("alias").and_then(|v| v.as_str()) == Some(a)) {
                return Err(format!("Alias '{}' is already in use. Use 'list' to see existing deposits.", a).into());
            }
        }
    }

    // Get next available key index for this deposit
    let key_index = load_deposit_key_index(&config.data_dir);
    let secret_key = derive_secret_key_at_index(&config.seed, config.network, key_index)?;
    let secp = Secp256k1::new();
    let our_pubkey = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret_key);

    // Also derive the nostr identity key at index 0 for signing requests
    let nostr_key = derive_secret_key(&config.seed, config.network)?;

    let transport = NostrTransportBuilder::new(nostr_key)
        .relay(&config.relays[0])
        .build()
        .await?;

    // Resolve prefix to full ledger ID and fetch advertisement for fees
    let network_str = match config.network {
        bitcoin::Network::Bitcoin => "bitcoin",
        bitcoin::Network::Testnet => "testnet",
        bitcoin::Network::Signet => "signet",
        bitcoin::Network::Regtest => "regtest",
        _ => "unknown",
    };

    let (ledger_id, advertisement) = if ledger_id.len() < 64 {
        let ads = transport.fetch_ledger_advertisements(network_str).await?;
        let ad = ads.into_iter()
            .find(|a| a.ledger_id.starts_with(&ledger_id))
            .ok_or_else(|| format!("No ledger found matching: {}", ledger_id))?;
        let lid = ad.ledger_id.clone();
        (lid, Some(ad))
    } else {
        // Fetch the advertisement for the full ledger ID
        let ad = transport.fetch_ledger_advertisement(&ledger_id).await?;
        (ledger_id, ad)
    };

    println!("Opening deposit...");
    println!("  Ledger: {}...", &ledger_id[..16.min(ledger_id.len())]);
    println!("  Amount: {} sats", amount_sats);
    if let Some(ref a) = alias {
        println!("  Alias: {}", a);
    }

    // Get fee structure from advertisement
    // If fee_period_blocks is 0 (not set), use default of 2016 blocks (~2 weeks)
    let (fee_fixed, fee_bps, fee_frequency) = if let Some(ref ad) = advertisement {
        let period = if ad.fee_period_blocks > 0 { ad.fee_period_blocks } else { 2016 };
        let fee_struct = ad.to_fee_structure();
        println!("  Fees: {} bps/year + {} sats/year fixed (period: {} blocks)",
            ad.annual_fee_bps, fee_struct.annualized_fixed, period);
        (fee_struct.annualized_fixed, fee_struct.annualized_bps as u64, period as u64)
    } else {
        println!("  Fees: (using defaults - no advertisement found)");
        (0, 0, 2016)
    };
    println!();

    // Step 1: Send deposit_open request to create the deposit account
    let open_params = serde_json::json!({
        "deposit_pubkey": hex::encode(our_pubkey.serialize()),
        "fee_fixed": fee_fixed,
        "fee_bps": fee_bps,
        "fee_frequency": fee_frequency,
    });

    println!("Sending deposit_open request to operator...");

    let open_request_id = transport.send_ledger_request(
        &ledger_id,
        "deposit_open",
        open_params,
    ).await?;

    println!("  Request ID: {}...", &open_request_id[..16]);

    // Wait for deposit_open response
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let max_attempts = 15;
    let poll_interval = std::time::Duration::from_secs(2);
    let mut deposit_opened = false;

    for _attempt in 1..=max_attempts {
        tokio::time::sleep(poll_interval).await;

        let responses = match transport.fetch_responses_since(
            nostr_sdk::Timestamp::now() - 60
        ).await {
            Ok(r) => r,
            Err(_) => continue,
        };

        print!(".");
        std::io::stdout().flush().ok();

        for response in responses {
            if response.request_id == open_request_id {
                println!();
                if response.success {
                    println!("  Deposit account created!");
                    deposit_opened = true;
                } else {
                    let error = response.error.as_deref().unwrap_or("Unknown error");
                    // If deposit already exists, that's fine - continue to create offer
                    if error.contains("already exists") || error.contains("Deposit already") {
                        println!("  Deposit account already exists, continuing...");
                        deposit_opened = true;
                    } else {
                        return Err(format!("Failed to open deposit: {}", error).into());
                    }
                }
                break;
            }
        }

        if deposit_opened {
            break;
        }
    }

    if !deposit_opened {
        return Err("Timeout waiting for deposit_open response".into());
    }

    // Step 2: Send make_offer request to get a funding address
    // max_sats = requested amount, min_sats = 1 (or less than max), blocks_valid = 144 (~1 day)
    let min_sats = std::cmp::min(1000_u64, amount_sats.saturating_sub(1).max(1));
    let offer_params = serde_json::json!({
        "deposit_pubkey": hex::encode(our_pubkey.serialize()),
        "max_sats": amount_sats,
        "min_sats": min_sats,
        "blocks_valid": 144_u64,
        "fee_fixed": fee_fixed,
        "fee_bps": fee_bps,
        "fee_frequency": fee_frequency,
    });

    println!("Sending make_offer request for funding address...");

    let request_id = transport.send_ledger_request(
        &ledger_id,
        "make_offer",
        offer_params,
    ).await?;

    println!("  Request ID: {}...", &request_id[..16]);
    println!();

    // Poll for response
    println!("Waiting for operator response...");

    // Give the relay a moment to store and propagate the request
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let max_attempts = 30;
    let poll_interval = std::time::Duration::from_secs(2);

    for attempt in 1..=max_attempts {
        tokio::time::sleep(poll_interval).await;

        let responses = match transport.fetch_responses_since(
            nostr_sdk::Timestamp::now() - 120
        ).await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("  [Poll {}] Fetch error: {}", attempt, e);
                continue;
            }
        };

        // Show progress
        print!(".");
        std::io::stdout().flush().ok();

        for response in responses {
            if response.request_id == request_id {
                println!(); // newline after dots
                if response.success {
                    if let Some(result) = &response.result {
                        let address = result.get("funding_address").and_then(|v| v.as_str());
                        let offer_id = result.get("offer_id").and_then(|v| v.as_str());
                        let min_sats = result.get("min_sats").and_then(|v| v.as_u64()).unwrap_or(1);
                        let max_sats = result.get("max_sats").and_then(|v| v.as_u64()).unwrap_or(amount_sats);

                        if let (Some(address), Some(offer_id)) = (address, offer_id) {
                            // Save deposit to local storage with alias
                            let deposits_file = config.data_dir.join("deposits.json");
                            let mut deposits: Vec<serde_json::Value> = if deposits_file.exists() {
                                let data = std::fs::read_to_string(&deposits_file)?;
                                serde_json::from_str(&data).unwrap_or_default()
                            } else {
                                Vec::new()
                            };

                            // Generate auto-alias if none provided
                            let final_alias = alias.clone().unwrap_or_else(|| {
                                format!("deposit-{}", deposits.len() + 1)
                            });

                            deposits.push(serde_json::json!({
                                "alias": final_alias,
                                "offer_id": offer_id,
                                "ledger_id": ledger_id,
                                "funding_address": address,
                                "deposit_pubkey": hex::encode(our_pubkey.serialize()),
                                "key_index": key_index,
                                "min_sats": min_sats,
                                "max_sats": max_sats,
                                "status": "pending",
                                "created_at": Utc::now().to_rfc3339(),
                            }));
                            std::fs::write(&deposits_file, serde_json::to_string_pretty(&deposits)?)?;

                            // Increment and save the key index for next deposit
                            save_deposit_key_index(&config.data_dir, key_index + 1)?;

                            println!("Deposit '{}' created!", final_alias);
                            println!();
                            println!("Fund with {}-{} sats:", min_sats, max_sats);
                            println!("  {}", address);
                            return Ok(());
                        } else {
                            // Response missing required fields
                            return Err(format!("Response missing funding_address or offer_id: {:?}", result).into());
                        }
                    } else {
                        return Err("Response missing result data".into());
                    }
                } else {
                    let error = response.error.as_deref().unwrap_or("Unknown error");
                    return Err(format!("Deposit request failed: {}", error).into());
                }
            }
        }

        print!(".");
        use std::io::Write;
        let _ = std::io::stdout().flush();
    }

    println!();
    Err("Timeout waiting for operator response".into())
}

/// Add funds to an existing deposit
async fn add_offer(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut alias: Option<String> = None;
    let mut amount_sats: Option<u64> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with("--") {
            config_args.push(args[i].clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
                i += 1;
            }
        } else if alias.is_none() {
            alias = Some(args[i].clone());
        } else if amount_sats.is_none() {
            amount_sats = Some(args[i].parse()?);
        }
        i += 1;
    }

    let alias = alias.ok_or("Usage: deposits-wallet offer <alias> <amount_sats> --relay <url>")?;
    let amount_sats = amount_sats.ok_or("Missing amount")?;
    let config = parse_config(&config_args)?;

    if config.relays.is_empty() {
        return Err("No relay specified. Use --relay <url>".into());
    }

    // Look up deposit by alias
    let deposits_file = config.data_dir.join("deposits.json");
    if !deposits_file.exists() {
        return Err("No deposits found. Use 'open' to create a new deposit first.".into());
    }

    let data = std::fs::read_to_string(&deposits_file)?;
    let deposits: Vec<serde_json::Value> = serde_json::from_str(&data)?;

    let deposit = deposits.iter()
        .find(|d| d.get("alias").and_then(|v| v.as_str()) == Some(&alias))
        .ok_or_else(|| format!("No deposit found with alias '{}'. Use 'list' to see your deposits.", alias))?;

    let ledger_id = deposit.get("ledger_id")
        .and_then(|v| v.as_str())
        .ok_or("Invalid deposit record: missing ledger_id")?;

    let deposit_pubkey = deposit.get("deposit_pubkey")
        .and_then(|v| v.as_str());

    println!("Adding funds to deposit...");
    println!("  Alias: {}", alias);
    println!("  Ledger: {}...", &ledger_id[..16.min(ledger_id.len())]);
    println!("  Amount: {} sats", amount_sats);
    println!();

    // Get the key_index for this deposit (defaults to 0 for legacy deposits)
    let key_index = deposit.get("key_index")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;

    let secret_key = derive_secret_key_at_index(&config.seed, config.network, key_index)?;
    let secp = Secp256k1::new();
    let our_pubkey = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret_key);

    // Use stored pubkey or derive fresh (should match what's in the record)
    let pubkey_hex = deposit_pubkey
        .map(|s| s.to_string())
        .unwrap_or_else(|| hex::encode(our_pubkey.serialize()));

    // Use nostr identity key (index 0) for transport signing
    let nostr_key = derive_secret_key(&config.seed, config.network)?;

    let transport = NostrTransportBuilder::new(nostr_key)
        .relay(&config.relays[0])
        .build()
        .await?;

    // Fetch advertisement for fee structure
    let advertisement = transport.fetch_ledger_advertisement(ledger_id).await?;
    let (fee_fixed, fee_bps, fee_frequency) = if let Some(ref ad) = advertisement {
        let period = if ad.fee_period_blocks > 0 { ad.fee_period_blocks } else { 2016 };
        let fee_struct = ad.to_fee_structure();
        (fee_struct.annualized_fixed, fee_struct.annualized_bps as u64, period as u64)
    } else {
        (0, 0, 2016)
    };

    // Send make_offer request for existing deposit
    let request_params = serde_json::json!({
        "deposit_pubkey": pubkey_hex,
        "max_sats": amount_sats,
        "min_sats": 1000_u64,
        "blocks_valid": 144_u64,
        "fee_fixed": fee_fixed,
        "fee_bps": fee_bps,
        "fee_frequency": fee_frequency,
    });

    println!("Sending offer request to operator...");

    let request_id = transport.send_ledger_request(
        ledger_id,
        "make_offer",
        request_params,
    ).await?;

    println!("  Request ID: {}...", &request_id[..16]);
    println!();

    // Poll for response
    println!("Waiting for operator response...");

    // Give the relay a moment to store and propagate the request
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let max_attempts = 30;
    let poll_interval = std::time::Duration::from_secs(2);

    for _attempt in 1..=max_attempts {
        tokio::time::sleep(poll_interval).await;

        let responses = transport.fetch_responses_since(
            nostr_sdk::Timestamp::now() - 120
        ).await?;

        for response in responses {
            if response.request_id == request_id {
                if response.success {
                    println!("Offer accepted!");
                    if let Some(result) = &response.result {
                        if let Some(address) = result.get("funding_address").and_then(|v| v.as_str()) {
                            println!();
                            println!("Send {} sats to:", amount_sats);
                            println!("  {}", address);
                            println!();
                            println!("After funding, the deposit will be automatically completed.");
                        }
                        if let Some(offer_id) = result.get("offer_id").and_then(|v| v.as_str()) {
                            println!("Offer ID: {}", offer_id);
                        }
                    }
                    return Ok(());
                } else {
                    let error = response.error.as_deref().unwrap_or("Unknown error");
                    return Err(format!("Offer request failed: {}", error).into());
                }
            }
        }

        print!(".");
        use std::io::Write;
        let _ = std::io::stdout().flush();
    }

    println!();
    Err("Timeout waiting for operator response".into())
}

/// List all deposits with aliases
async fn list_deposits(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let config = parse_config(args)?;

    let deposits_file = config.data_dir.join("deposits.json");
    if !deposits_file.exists() {
        println!("No deposits found.");
        println!();
        println!("To open a deposit:");
        println!("  deposits-wallet discover --relay <url>");
        println!("  deposits-wallet open <ledger_id> <amount_sats> --alias <name> --relay <url>");
        return Ok(());
    }

    let data = std::fs::read_to_string(&deposits_file)?;
    let deposits: Vec<serde_json::Value> = serde_json::from_str(&data)?;

    if deposits.is_empty() {
        println!("No deposits found.");
        return Ok(());
    }

    println!("Your Deposits");
    println!("=============");
    println!();

    for deposit in &deposits {
        let alias = deposit.get("alias").and_then(|v| v.as_str()).unwrap_or("(none)");
        let ledger_id = deposit.get("ledger_id").and_then(|v| v.as_str()).unwrap_or("unknown");
        let amount = deposit.get("amount_sats").and_then(|v| v.as_u64()).unwrap_or(0);
        let status = deposit.get("status").and_then(|v| v.as_str()).unwrap_or("unknown");
        let created_at = deposit.get("created_at").and_then(|v| v.as_str()).unwrap_or("");
        let deposit_pubkey = deposit.get("deposit_pubkey").and_then(|v| v.as_str()).unwrap_or("");

        // Compute descriptor and deposit_id from pubkey
        let descriptor = if !deposit_pubkey.is_empty() {
            format!("pk({})", deposit_pubkey)
        } else {
            "unknown".to_string()
        };
        let deposit_id = if !deposit_pubkey.is_empty() {
            use bitcoin::hashes::{sha256, Hash};
            let hash = sha256::Hash::hash(descriptor.as_bytes());
            hex::encode(&hash[..16])
        } else {
            "unknown".to_string()
        };

        println!("  {} ", alias);
        println!("    Deposit ID:  {}", deposit_id);
        println!("    Descriptor:  {}", descriptor);
        println!("    Ledger:      {}...", &ledger_id[..16.min(ledger_id.len())]);
        println!("    Amount:      {} sats", amount);
        println!("    Status:      {}", status);
        if !created_at.is_empty() {
            println!("    Created:     {}", created_at);
        }
        println!();
    }

    println!("Commands:");
    println!("  offer <alias> <sats>      Add funds to a deposit");
    println!("  withdraw <alias> <sats>   Withdraw from a deposit");
    println!("  history <alias>           View transaction history");

    Ok(())
}

/// Show balances across all deposits
async fn show_balance(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let config = parse_config(args)?;

    // Auto-sync if relay is provided
    if !config.relays.is_empty() {
        if let Err(e) = sync_deposits(args).await {
            // Don't fail on sync error, just log it
            eprintln!("Note: sync failed: {}", e);
        }
    }

    let deposits_file = config.data_dir.join("deposits.json");
    if !deposits_file.exists() {
        println!("No deposits found.");
        println!();
        println!("To open a deposit:");
        println!("  deposits-wallet discover --relay <url>");
        println!("  deposits-wallet open <ledger_id> <amount_sats> --alias <name> --relay <url>");
        return Ok(());
    }

    let data = std::fs::read_to_string(&deposits_file)?;
    let deposits: Vec<serde_json::Value> = serde_json::from_str(&data)?;

    if deposits.is_empty() {
        println!("No deposits found.");
        return Ok(());
    }

    println!("Deposit Balances");
    println!("================");
    println!();

    let mut total_sats = 0u64;

    let mut total_locked = 0u64;

    for deposit in &deposits {
        let alias = deposit.get("alias").and_then(|v| v.as_str()).unwrap_or("(none)");
        let deposit_pubkey = deposit.get("deposit_pubkey").and_then(|v| v.as_str()).unwrap_or("unknown");
        let amount = deposit.get("amount_sats").and_then(|v| v.as_u64()).unwrap_or(0);
        let locked = deposit.get("locked_sats").and_then(|v| v.as_u64()).unwrap_or(0);
        let status = deposit.get("status").and_then(|v| v.as_str()).unwrap_or("unknown");

        let status_symbol = match status {
            "completed" | "funded" => "+",
            "pending" => "~",
            _ => "?",
        };

        if locked > 0 {
            println!("  {} {} {:>10} sats  ({})  [{} pending]",
                status_symbol, alias, amount, &deposit_pubkey[..8.min(deposit_pubkey.len())], locked);
        } else {
            println!("  {} {} {:>10} sats  ({})",
                status_symbol, alias, amount, &deposit_pubkey[..8.min(deposit_pubkey.len())]);
        }

        if status == "funded" || status == "completed" {
            total_sats += amount;
            total_locked += locked;
        }
    }

    println!();
    if total_locked > 0 {
        println!("  Total:  {} sats ({} BTC)  [{} pending]", total_sats, total_sats as f64 / 100_000_000.0, total_locked);
    } else {
        println!("  Total:  {} sats ({} BTC)", total_sats, total_sats as f64 / 100_000_000.0);
    }
    println!();
    println!("  + = funded/completed, ~ = pending, [N pending] = locked for withdrawal");

    Ok(())
}

/// Sync deposit statuses from the daemon
async fn sync_deposits(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let config = parse_config(args)?;

    if config.relays.is_empty() {
        return Err("No relay specified. Use --relay <url>".into());
    }

    let deposits_file = config.data_dir.join("deposits.json");
    if !deposits_file.exists() {
        println!("No deposits to sync.");
        return Ok(());
    }

    let data = std::fs::read_to_string(&deposits_file)?;
    let mut deposits: Vec<serde_json::Value> = serde_json::from_str(&data)?;

    if deposits.is_empty() {
        println!("No deposits to sync.");
        return Ok(());
    }

    // Generate our secret key for signing requests
    let secret_key = SecretKey::from_slice(&config.seed)?;

    // Connect to relay
    let transport = NostrTransportBuilder::new(secret_key)
        .relay(&config.relays[0])
        .build()
        .await?;

    println!("Syncing deposit statuses...");

    let mut updated = false;

    for deposit in &mut deposits {
        let alias = deposit.get("alias").and_then(|v| v.as_str()).unwrap_or("unknown");
        let offer_id = deposit.get("offer_id").and_then(|v| v.as_str());
        let ledger_id = deposit.get("ledger_id").and_then(|v| v.as_str());
        let deposit_pubkey = deposit.get("deposit_pubkey").and_then(|v| v.as_str());
        let current_status = deposit.get("status").and_then(|v| v.as_str()).unwrap_or("unknown");

        // For funded/completed deposits, query the actual balance
        if current_status == "completed" || current_status == "funded" {
            if let (Some(ledger_id), Some(deposit_pubkey)) = (ledger_id, deposit_pubkey) {
                let params = serde_json::json!({
                    "deposit_pubkey": deposit_pubkey,
                });

                let request_id = transport.send_ledger_request(ledger_id, "balance_query", params).await?;

                // Wait for response (with timeout)
                let start = std::time::Instant::now();
                let timeout = std::time::Duration::from_secs(10);

                while start.elapsed() < timeout {
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                    match transport.fetch_response(&request_id).await {
                        Ok(Some(response)) => {
                            if response.success {
                                if let Some(result) = &response.result {
                                    // Get balance and locked from response
                                    let balance_msats = result.get("balance_msats").and_then(|v| v.as_u64()).unwrap_or(0);
                                    let locked_msats = result.get("locked_msats").and_then(|v| v.as_u64()).unwrap_or(0);
                                    let available_sats = (balance_msats.saturating_sub(locked_msats)) / 1000;
                                    let locked_sats = locked_msats / 1000;

                                    let current_amount = deposit.get("amount_sats").and_then(|v| v.as_u64()).unwrap_or(0);
                                    let current_locked = deposit.get("locked_sats").and_then(|v| v.as_u64()).unwrap_or(0);

                                    if available_sats != current_amount || locked_sats != current_locked {
                                        if locked_sats > 0 {
                                            println!("  {} balance: {} sats ({} pending)", alias, available_sats, locked_sats);
                                        } else {
                                            println!("  {} balance: {} sats", alias, available_sats);
                                        }
                                        deposit["amount_sats"] = serde_json::json!(available_sats);
                                        deposit["locked_sats"] = serde_json::json!(locked_sats);
                                        updated = true;
                                    }
                                }
                            }
                            break;
                        }
                        Ok(None) => {
                            // No response yet, keep polling
                        }
                        Err(_) => {
                            break;
                        }
                    }
                }
            }
            continue;
        }

        if let (Some(offer_id), Some(ledger_id)) = (offer_id, ledger_id) {
            // Query daemon for offer status
            let params = serde_json::json!({
                "offer_id": offer_id,
            });

            let request_id = transport.send_ledger_request(ledger_id, "offer_status", params).await?;

            // Wait for response (with timeout)
            let start = std::time::Instant::now();
            let timeout = std::time::Duration::from_secs(10);

            while start.elapsed() < timeout {
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                match transport.fetch_response(&request_id).await {
                    Ok(Some(response)) => {
                        if response.success {
                            if let Some(result) = &response.result {
                                // Get status from response
                                if let Some(status_obj) = result.get("status") {
                                    let status_str = status_obj.get("status").and_then(|v| v.as_str());
                                    let amount = status_obj.get("amount_sats").and_then(|v| v.as_u64());

                                    if let Some(status_str) = status_str {
                                        if status_str != current_status {
                                            println!("  {} {} -> {}", alias, current_status, status_str);

                                            // Update status
                                            deposit["status"] = serde_json::json!(status_str);

                                            // Update amount if completed
                                            if let Some(amt) = amount {
                                                deposit["amount_sats"] = serde_json::json!(amt);
                                            }

                                            updated = true;
                                        }
                                    }
                                }
                            }
                        }
                        break;
                    }
                    Ok(None) => {
                        // No response yet, keep polling
                    }
                    Err(_) => {
                        break;
                    }
                }
            }
        }
    }

    if updated {
        // Save updated deposits
        let data = serde_json::to_string_pretty(&deposits)?;
        std::fs::write(&deposits_file, data)?;
        println!("Deposits updated.");
    } else {
        println!("All deposits up to date.");
    }

    Ok(())
}

/// Withdraw from a deposit
async fn withdraw(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use bitcoin::hashes::{sha256, Hash};
    use bitcoin::secp256k1::rand::rngs::OsRng;
    use bitcoin::secp256k1::rand::RngCore;

    let mut alias: Option<String> = None;
    let mut amount_sats: Option<u64> = None;
    let mut destination: Option<String> = None;
    let mut fee_sats: u64 = 500; // Default fee
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--to" if i + 1 < args.len() => {
                destination = Some(args[i + 1].clone());
                i += 1;
            }
            "--fee" if i + 1 < args.len() => {
                fee_sats = args[i + 1].parse()?;
                i += 1;
            }
            s if s.starts_with("--") => {
                config_args.push(args[i].clone());
                if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                    config_args.push(args[i + 1].clone());
                    i += 1;
                }
            }
            _ => {
                if alias.is_none() {
                    alias = Some(args[i].clone());
                } else if amount_sats.is_none() {
                    amount_sats = Some(args[i].parse()?);
                }
            }
        }
        i += 1;
    }

    let alias = alias.ok_or(
        "Usage: deposits-wallet withdraw <alias> <amount_sats> --to <address> --relay <url>"
    )?;
    let amount_sats = amount_sats.ok_or("Missing amount")?;
    let destination = destination.ok_or("Missing destination. Use --to <address>")?;
    let config = parse_config(&config_args)?;

    if config.relays.is_empty() {
        return Err("No relay specified. Use --relay <url>".into());
    }

    // Look up deposit by alias
    let deposits_file = config.data_dir.join("deposits.json");
    if !deposits_file.exists() {
        return Err("No deposits found. Use 'open' to create a deposit first.".into());
    }

    let data = std::fs::read_to_string(&deposits_file)?;
    let deposits: Vec<serde_json::Value> = serde_json::from_str(&data)?;

    let deposit = deposits.iter()
        .find(|d| d.get("alias").and_then(|v| v.as_str()) == Some(&alias))
        .ok_or_else(|| format!("No deposit found with alias '{}'. Use 'list' to see your deposits.", alias))?;

    let ledger_id = deposit.get("ledger_id")
        .and_then(|v| v.as_str())
        .ok_or("Invalid deposit record: missing ledger_id")?;

    // Get the key_index for this deposit (defaults to 0 for legacy deposits)
    let key_index = deposit.get("key_index")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;

    let secret_key = derive_secret_key_at_index(&config.seed, config.network, key_index)?;
    let secp = Secp256k1::new();
    let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &secret_key);
    let our_pubkey = keypair.public_key();

    // Use nostr identity key (index 0) for transport signing
    let nostr_key = derive_secret_key(&config.seed, config.network)?;

    // Generate nonce
    let mut rng = OsRng;
    let mut nonce = [0u8; 32];
    rng.fill_bytes(&mut nonce);
    let nonce_hex = hex::encode(&nonce);

    // Sign the withdrawal message
    // Format must match node.rs process_withdraw_request: "withdraw:{address}:{amount}:{fee}:{nonce}"
    let msg_str = format!("withdraw:{}:{}:{}:{}", destination, amount_sats, fee_sats, nonce_hex);
    let msg_hash = sha256::Hash::hash(msg_str.as_bytes());
    let msg = bitcoin::secp256k1::Message::from_digest(*msg_hash.as_byte_array());
    let signature = secp.sign_schnorr(&msg, &keypair);

    println!("Withdrawal Request");
    println!("==================");
    println!("  Alias: {}", alias);
    println!("  Ledger: {}...", &ledger_id[..16.min(ledger_id.len())]);
    println!("  Amount: {} sats", amount_sats);
    println!("  Fee: {} sats", fee_sats);
    println!("  To: {}", destination);
    println!();

    let transport = NostrTransportBuilder::new(nostr_key)
        .relay(&config.relays[0])
        .build()
        .await?;

    let request_params = serde_json::json!({
        "deposit_pubkey": hex::encode(our_pubkey.serialize()),
        "address": destination,
        "amount_sats": amount_sats,
        "fee_sats": fee_sats,
        "nonce": nonce_hex,
        "signature": hex::encode(signature.serialize()),
    });

    println!("Sending signed withdrawal request...");

    let request_id = transport.send_ledger_request(
        ledger_id,
        "withdraw",
        request_params,
    ).await?;

    println!("  Request ID: {}...", &request_id[..16]);
    println!();

    // Poll for response
    println!("Waiting for operator response...");

    // Give the relay a moment to store and propagate the request
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let max_attempts = 30;
    let poll_interval = std::time::Duration::from_secs(2);

    for _attempt in 1..=max_attempts {
        tokio::time::sleep(poll_interval).await;

        let responses = transport.fetch_responses_since(
            nostr_sdk::Timestamp::now() - 120
        ).await?;

        for response in responses {
            if response.request_id == request_id {
                if response.success {
                    println!("Withdrawal accepted!");
                    if let Some(result) = &response.result {
                        if let Some(withdrawal_id) = result.get("withdrawal_id").and_then(|v| v.as_str()) {
                            println!("  Withdrawal ID: {}", withdrawal_id);
                        }
                        if let Some(message) = result.get("message").and_then(|v| v.as_str()) {
                            println!("  {}", message);
                        }
                    }
                    return Ok(());
                } else {
                    let error = response.error.as_deref().unwrap_or("Unknown error");
                    return Err(format!("Withdrawal failed: {}", error).into());
                }
            }
        }

        print!(".");
        use std::io::Write;
        let _ = std::io::stdout().flush();
    }

    println!();
    Err("Timeout waiting for operator response".into())
}

/// Create a Lightning invoice for a deposit
/// The operator's LDK sidecar creates the invoice, payment credits the deposit
async fn make_invoice(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut alias: Option<String> = None;
    let mut amount_sats: Option<u64> = None;
    let mut description: Option<String> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--description" | "-d" if i + 1 < args.len() => {
                description = Some(args[i + 1].clone());
                i += 1;
            }
            s if s.starts_with("--") => {
                config_args.push(args[i].clone());
                if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                    config_args.push(args[i + 1].clone());
                    i += 1;
                }
            }
            _ => {
                if alias.is_none() {
                    alias = Some(args[i].clone());
                } else if amount_sats.is_none() {
                    amount_sats = Some(args[i].parse()?);
                }
            }
        }
        i += 1;
    }

    let alias = alias.ok_or("Usage: deposits-wallet make_invoice <alias> <amount_sats> --relay <url>")?;
    let amount_sats = amount_sats.ok_or("Missing amount")?;
    let config = parse_config(&config_args)?;

    if config.relays.is_empty() {
        return Err("No relay specified. Use --relay <url>".into());
    }

    // Look up deposit by alias
    let deposits_file = config.data_dir.join("deposits.json");
    if !deposits_file.exists() {
        return Err("No deposits found. Use 'open' to create a deposit first.".into());
    }

    let data = std::fs::read_to_string(&deposits_file)?;
    let deposits: Vec<serde_json::Value> = serde_json::from_str(&data)?;

    let deposit = deposits.iter()
        .find(|d| d.get("alias").and_then(|v| v.as_str()) == Some(&alias))
        .ok_or_else(|| format!("No deposit found with alias '{}'. Use 'list' to see your deposits.", alias))?;

    let ledger_id = deposit.get("ledger_id")
        .and_then(|v| v.as_str())
        .ok_or("Invalid deposit record: missing ledger_id")?;

    let deposit_pubkey = deposit.get("deposit_pubkey")
        .and_then(|v| v.as_str())
        .ok_or("Invalid deposit record: missing deposit_pubkey")?;

    // Use nostr identity key for transport
    let nostr_key = derive_secret_key(&config.seed, config.network)?;

    let transport = NostrTransportBuilder::new(nostr_key)
        .relay(&config.relays[0])
        .build()
        .await?;

    let request_params = serde_json::json!({
        "deposit_pubkey": deposit_pubkey,
        "amount_sats": amount_sats,
        "description": description.unwrap_or_else(|| format!("Deposit to {}", alias)),
    });

    println!("Requesting Lightning invoice...");
    println!("  Alias: {}", alias);
    println!("  Amount: {} sats", amount_sats);

    let request_id = transport.send_ledger_request(
        ledger_id,
        "make_invoice",
        request_params,
    ).await?;

    // Poll for response
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let max_attempts = 30;
    let poll_interval = std::time::Duration::from_secs(2);

    for _attempt in 1..=max_attempts {
        tokio::time::sleep(poll_interval).await;

        let responses = transport.fetch_responses_since(
            nostr_sdk::Timestamp::now() - 120
        ).await?;

        for response in responses {
            if response.request_id == request_id {
                if response.success {
                    if let Some(result) = &response.result {
                        if let Some(invoice) = result.get("invoice").and_then(|v| v.as_str()) {
                            println!();
                            println!("{}", invoice);
                            return Ok(());
                        }
                    }
                    return Err("Response missing invoice".into());
                } else {
                    let error = response.error.as_deref().unwrap_or("Unknown error");
                    return Err(format!("Invoice request failed: {}", error).into());
                }
            }
        }

        print!(".");
        std::io::stdout().flush().ok();
    }

    println!();
    Err("Timeout waiting for operator response".into())
}

/// Pay a Lightning invoice from a deposit
/// The operator's LDK sidecar pays the invoice, debiting the deposit
async fn pay_invoice(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {

    let mut alias: Option<String> = None;
    let mut invoice: Option<String> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            s if s.starts_with("--") => {
                config_args.push(args[i].clone());
                if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                    config_args.push(args[i + 1].clone());
                    i += 1;
                }
            }
            _ => {
                if alias.is_none() {
                    alias = Some(args[i].clone());
                } else if invoice.is_none() {
                    invoice = Some(args[i].clone());
                }
            }
        }
        i += 1;
    }

    let alias = alias.ok_or("Usage: deposits-wallet pay_invoice <alias> <bolt11> --relay <url>")?;
    let invoice = invoice.ok_or("Missing bolt11 invoice")?;
    let config = parse_config(&config_args)?;

    if config.relays.is_empty() {
        return Err("No relay specified. Use --relay <url>".into());
    }

    // Look up deposit by alias
    let deposits_file = config.data_dir.join("deposits.json");
    if !deposits_file.exists() {
        return Err("No deposits found. Use 'open' to create a deposit first.".into());
    }

    let data = std::fs::read_to_string(&deposits_file)?;
    let deposits: Vec<serde_json::Value> = serde_json::from_str(&data)?;

    let deposit = deposits.iter()
        .find(|d| d.get("alias").and_then(|v| v.as_str()) == Some(&alias))
        .ok_or_else(|| format!("No deposit found with alias '{}'. Use 'list' to see your deposits.", alias))?;

    let ledger_id = deposit.get("ledger_id")
        .and_then(|v| v.as_str())
        .ok_or("Invalid deposit record: missing ledger_id")?;

    // Get key for signing
    let key_index = deposit.get("key_index")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;

    let secret_key = derive_secret_key_at_index(&config.seed, config.network, key_index)?;
    let secp = Secp256k1::new();
    let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &secret_key);
    let our_pubkey = keypair.public_key();

    // Use nostr identity key for transport
    let nostr_key = derive_secret_key(&config.seed, config.network)?;

    // Parse the bolt11 invoice to extract payment_hash and amount
    use lightning_invoice::Bolt11Invoice;
    use std::str::FromStr;

    let parsed_invoice = Bolt11Invoice::from_str(&invoice)
        .map_err(|e| format!("Invalid bolt11 invoice: {:?}", e))?;

    let payment_hash = parsed_invoice.payment_hash();
    let mut payment_hash_bytes = [0u8; 32];
    payment_hash_bytes.copy_from_slice(payment_hash.as_ref());

    let amount_msats = parsed_invoice.amount_milli_satoshis()
        .ok_or("Invoice has no amount")?;

    // Compute deposit_id from descriptor
    let descriptor = format!("pk({})", hex::encode(our_pubkey.serialize()));
    let deposit_id = deposits_core::types::compute_deposit_id(&descriptor);

    // Sign the INVOICE_LOCK message (deposit_id, payment_hash, amount)
    let msg_hash = deposits_core::signature_utils::invoice_lock_signing_message(
        &deposit_id,
        &payment_hash_bytes,
        amount_msats,
    );
    let msg = bitcoin::secp256k1::Message::from_digest(msg_hash);
    let signature = secp.sign_schnorr(&msg, &keypair);

    let transport = NostrTransportBuilder::new(nostr_key)
        .relay(&config.relays[0])
        .build()
        .await?;

    let request_params = serde_json::json!({
        "deposit_pubkey": hex::encode(our_pubkey.serialize()),
        "invoice": invoice,
        "payment_hash": hex::encode(payment_hash_bytes),
        "amount_msats": amount_msats,
        "signature": hex::encode(signature.serialize()),
    });

    println!("Paying Lightning invoice...");
    println!("  Alias: {}", alias);
    println!("  Invoice: {}...", &invoice[..40.min(invoice.len())]);
    println!("  Amount: {} msats", amount_msats);

    let request_id = transport.send_ledger_request(
        ledger_id,
        "pay_invoice",
        request_params,
    ).await?;

    // Poll for response
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let max_attempts = 60; // Longer timeout for LN payments
    let poll_interval = std::time::Duration::from_secs(2);

    for _attempt in 1..=max_attempts {
        tokio::time::sleep(poll_interval).await;

        let responses = transport.fetch_responses_since(
            nostr_sdk::Timestamp::now() - 180
        ).await?;

        for response in responses {
            if response.request_id == request_id {
                if response.success {
                    println!();
                    println!("Payment successful!");
                    if let Some(result) = &response.result {
                        if let Some(preimage) = result.get("preimage").and_then(|v| v.as_str()) {
                            println!("  Preimage: {}", preimage);
                        }
                    }
                    return Ok(());
                } else {
                    let error = response.error.as_deref().unwrap_or("Unknown error");
                    return Err(format!("Payment failed: {}", error).into());
                }
            }
        }

        print!(".");
        std::io::stdout().flush().ok();
    }

    println!();
    Err("Timeout waiting for payment confirmation".into())
}

/// Show transaction history for a deposit
async fn show_history(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut alias: Option<String> = None;
    let mut config_args = Vec::new();

    for arg in args {
        if arg.starts_with("--") {
            config_args.push(arg.clone());
        } else if alias.is_none() {
            alias = Some(arg.clone());
        }
    }

    let alias = alias.ok_or("Usage: deposits-wallet history <alias> --relay <url>")?;
    let config = parse_config(&config_args)?;

    // Look up deposit by alias
    let deposits_file = config.data_dir.join("deposits.json");
    if !deposits_file.exists() {
        return Err("No deposits found. Use 'open' to create a deposit first.".into());
    }

    let data = std::fs::read_to_string(&deposits_file)?;
    let deposits: Vec<serde_json::Value> = serde_json::from_str(&data)?;

    let deposit = deposits.iter()
        .find(|d| d.get("alias").and_then(|v| v.as_str()) == Some(&alias))
        .ok_or_else(|| format!("No deposit found with alias '{}'. Use 'list' to see your deposits.", alias))?;

    let ledger_id = deposit.get("ledger_id")
        .and_then(|v| v.as_str())
        .ok_or("Invalid deposit record: missing ledger_id")?;

    println!("Transaction History: {}", alias);
    println!("====================");
    println!();
    println!("  Ledger: {}", ledger_id);
    println!();
    println!("(History implementation pending - use deposits-bdk for now)");

    Ok(())
}

// ============================================================================
// Ledger inspection commands (read-only Nostr queries)
// ============================================================================

/// Relay's max events per request (strfry default)
const RELAY_PAGE_SIZE: usize = 500;

/// Fetch all events matching a filter using pagination.
async fn fetch_all_events_paginated(
    client: &Client,
    base_filter: Filter,
) -> Result<Vec<Event>, Box<dyn std::error::Error>> {
    let mut all_events = Vec::new();
    let mut until: Option<Timestamp> = None;
    let mut seen_ids: HashSet<EventId> = HashSet::new();
    let mut last_count = 0usize;
    let mut stall_count = 0usize;

    loop {
        let mut filter = base_filter.clone().limit(RELAY_PAGE_SIZE);
        if let Some(ts) = until {
            filter = filter.until(ts);
        }

        let events = client
            .fetch_events(vec![filter], None)
            .await
            .map_err(|e| format!("Failed to fetch events: {}", e))?;

        let batch_size = events.len();
        let mut oldest_ts: Option<Timestamp> = None;
        let mut new_events = 0usize;

        for event in events {
            if oldest_ts.is_none() || event.created_at < oldest_ts.unwrap() {
                oldest_ts = Some(event.created_at);
            }
            if seen_ids.insert(event.id) {
                all_events.push(event);
                new_events += 1;
            }
        }

        // Stop if we got fewer events than page size (end of data)
        if batch_size < RELAY_PAGE_SIZE {
            break;
        }

        // Stop if we're not making progress (no new events)
        if new_events == 0 {
            stall_count += 1;
            if stall_count > 3 {
                break; // Give up after 3 stalls
            }
        } else {
            stall_count = 0;
        }

        // Stop if total count hasn't changed (safety valve)
        if all_events.len() == last_count {
            break;
        }
        last_count = all_events.len();

        // Use the oldest timestamp for next page (don't subtract 1 - rely on dedup)
        if let Some(ts) = oldest_ts {
            until = Some(ts);
        } else {
            break;
        }
    }

    Ok(all_events)
}

/// Handle ledger subcommands
async fn ledger_command(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.is_empty() {
        eprintln!("Usage: deposits-wallet ledger <list|show|validate> [args...] --relay <url>");
        return Ok(());
    }

    match args[0].as_str() {
        "list" | "ls" => ledger_list(&args[1..]).await,
        "show" => ledger_show(&args[1..]).await,
        "validate" => ledger_validate(&args[1..]).await,
        cmd => {
            eprintln!("Unknown ledger subcommand: {}", cmd);
            eprintln!("Usage: deposits-wallet ledger <list|show|validate> [args...] --relay <url>");
            Ok(())
        }
    }
}

/// Parse relay URL from args
fn get_relay_url(args: &[String]) -> Option<String> {
    for (i, arg) in args.iter().enumerate() {
        if arg == "--relay" && i + 1 < args.len() {
            return Some(args[i + 1].clone());
        }
    }
    None
}

/// List all ledgers on the relay
async fn ledger_list(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let relay_url = get_relay_url(args)
        .ok_or("Missing --relay <url>")?;

    println!("Fetching ledgers from {}...", relay_url);
    println!();

    let keys = Keys::generate();
    let client = Client::new(keys);
    client.add_relay(&relay_url).await?;
    client.connect().await;

    let filter = Filter::new().kind(Kind::Custom(KIND_LEDGER_UPDATE));
    let events = fetch_all_events_paginated(&client, filter).await?;

    client.disconnect().await.ok();

    if events.is_empty() {
        println!("No ledgers found.");
        return Ok(());
    }

    // Group by ledger_id and count
    let mut ledgers: std::collections::HashMap<String, (u64, usize)> = std::collections::HashMap::new();

    for event in &events {
        let ledger_id = event.tags.iter().find_map(|tag| {
            if tag.kind() == TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::D)) {
                tag.content().map(|s| s.to_string())
            } else {
                None
            }
        });

        if let Some(lid) = ledger_id {
            // Get sequence from tag
            let seq = event.tags.iter().find_map(|tag| {
                if tag.kind() == TagKind::Custom(std::borrow::Cow::Borrowed("seq")) {
                    tag.content().and_then(|s| s.parse::<u64>().ok())
                } else {
                    None
                }
            }).unwrap_or(0);

            let entry = ledgers.entry(lid).or_insert((0, 0));
            if seq > entry.0 {
                entry.0 = seq;
            }
            entry.1 += 1;
        }
    }

    println!("Found {} ledger(s) ({} total events):", ledgers.len(), events.len());
    println!();

    let mut sorted: Vec<_> = ledgers.into_iter().collect();
    sorted.sort_by(|a, b| b.1.0.cmp(&a.1.0)); // Sort by max sequence desc

    for (lid, (max_seq, count)) in sorted {
        println!("  {}  seq={:<4} updates={}", lid, max_seq, count);
    }

    Ok(())
}

/// Find full ledger ID from partial prefix
async fn find_ledger_id(client: &Client, prefix: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
    // Fetch all updates to find matching ledger_id
    let filter = Filter::new().kind(Kind::Custom(KIND_LEDGER_UPDATE));
    let events = fetch_all_events_paginated(client, filter).await?;

    for event in events {
        if let Some(lid) = event.tags.iter().find_map(|tag| {
            if tag.kind() == TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::D)) {
                tag.content().map(|s| s.to_string())
            } else {
                None
            }
        }) {
            if lid.starts_with(prefix) {
                return Ok(Some(lid));
            }
        }
    }
    Ok(None)
}

/// Show all updates for a specific ledger
async fn ledger_show(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let relay_url = get_relay_url(args)
        .ok_or("Missing --relay <url>")?;

    // Check for --color-by-pk flag
    let color_by_pk = args.iter().any(|a| a == "--color-by-pk" || a == "--color");

    // Get ledger_id prefix (first non-flag arg that isn't after --relay)
    let ledger_prefix = args.iter()
        .enumerate()
        .find(|(i, a)| {
            !a.starts_with("--") &&
            (*i == 0 || args[i - 1] != "--relay")
        })
        .map(|(_, a)| a)
        .ok_or("Missing ledger_id")?;

    println!("Fetching ledger {}... from {}...", &ledger_prefix[..16.min(ledger_prefix.len())], relay_url);

    let keys = Keys::generate();
    let client = Client::new(keys);
    client.add_relay(&relay_url).await?;
    client.connect().await;

    // Find full ledger ID from prefix
    let ledger_id = match find_ledger_id(&client, ledger_prefix).await? {
        Some(id) => id,
        None => {
            println!("No ledger found with prefix {}", ledger_prefix);
            client.disconnect().await.ok();
            return Ok(());
        }
    };

    println!("Found: {}", ledger_id);
    println!();
    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .custom_tag(SingleLetterTag::lowercase(Alphabet::D), [ledger_id.as_str()]);

    let events = fetch_all_events_paginated(&client, filter).await?;
    client.disconnect().await.ok();

    if events.is_empty() {
        println!("No updates found for ledger {}", ledger_id);
        return Ok(());
    }

    // Decode and sort updates
    let mut updates: Vec<SignedLedgerUpdate> = Vec::new();
    for event in &events {
        if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
            if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                updates.push(update);
            }
        }
    }

    updates.sort_by_key(|u| u.sequence_number);
    updates.dedup_by_key(|u| (u.sequence_number, u.current_hash));

    println!("=== Ledger {} ({} updates) ===", &ledger_id[..16.min(ledger_id.len())], updates.len());
    println!();

    // Track deposit_id -> color mapping
    let mut id_colors: std::collections::HashMap<[u8; 16], usize> = std::collections::HashMap::new();
    let mut next_color = 0usize;

    for update in &updates {
        let (op_type, deposit_id) = match LedgerOperation::tlv_decode(&update.message) {
            Ok(op) => format_operation(&op),
            Err(_) => (format!("type=0x{:04X}", update.message_type), None),
        };

        let hash_short = &hex::encode(update.current_hash)[..8];

        // Show deposit_id if present, otherwise operator
        let (id_label, id_short) = if let Some(did) = deposit_id {
            ("id", hex::encode(&did[..4]))
        } else {
            let op_bytes = update.operator_id.serialize();
            ("op", hex::encode(&op_bytes[..4]))
        };

        if color_by_pk {
            // For coloring, use deposit_id if present, otherwise hash of operator
            let color_key: [u8; 16] = if let Some(did) = deposit_id {
                did
            } else {
                let op_bytes = update.operator_id.serialize();
                let mut key = [0u8; 16];
                key.copy_from_slice(&op_bytes[..16]);
                key
            };
            let color_idx = *id_colors.entry(color_key).or_insert_with(|| {
                let idx = next_color;
                next_color = (next_color + 1) % COLORS.len();
                idx
            });
            let color = COLORS[color_idx];
            println!("{}  [{:>4}] {:<16} {}={} hash={}{}",
                color, update.sequence_number, op_type, id_label, id_short, hash_short, RESET);
        } else {
            println!("  [{:>4}] {:<16} {}={} hash={}",
                update.sequence_number, op_type, id_label, id_short, hash_short);
        }
    }

    Ok(())
}

/// Format operation type for display and extract deposit_id if present
fn format_operation(op: &LedgerOperation) -> (String, Option<deposits_core::types::DepositId>) {
    match op {
        LedgerOperation::LedgerOpen { .. } => ("LedgerOpen".to_string(), None),
        LedgerOperation::QuorumAddMember { .. } => ("QuorumAdd".to_string(), None),
        LedgerOperation::QuorumRemoveMember { .. } => ("QuorumRemove".to_string(), None),
        LedgerOperation::QuorumJoin { .. } => ("QuorumJoin".to_string(), None),
        LedgerOperation::DepositOpen { deposit_id, .. } => ("DepositOpen".to_string(), Some(*deposit_id)),
        LedgerOperation::DepositClose { deposit_id, .. } => ("DepositClose".to_string(), Some(*deposit_id)),
        LedgerOperation::DepositUpdate { deposit_id, .. } => ("DepositUpdate".to_string(), Some(*deposit_id)),
        LedgerOperation::OnchainLock { deposit_id, .. } => ("OnchainLock".to_string(), Some(*deposit_id)),
        LedgerOperation::OnchainFulfill { deposit_id, .. } => ("OnchainFulfill".to_string(), Some(*deposit_id)),
        LedgerOperation::OnchainFail { deposit_id, .. } => ("OnchainFail".to_string(), Some(*deposit_id)),
        LedgerOperation::OnchainCredit { deposit_id, .. } => ("OnchainCredit".to_string(), Some(*deposit_id)),
        LedgerOperation::InvoiceLock { deposit_id, .. } => ("InvoiceLock".to_string(), Some(*deposit_id)),
        LedgerOperation::InvoiceFulfill { deposit_id, .. } => ("InvoiceFulfill".to_string(), Some(*deposit_id)),
        LedgerOperation::InvoiceFail { deposit_id, .. } => ("InvoiceFail".to_string(), Some(*deposit_id)),
        LedgerOperation::InvoiceCredit { deposit_id, .. } => ("InvoiceCredit".to_string(), Some(*deposit_id)),
        LedgerOperation::FeeCollect { deposit_id, .. } => ("FeeCollect".to_string(), Some(*deposit_id)),
        LedgerOperation::CollateralLock { deposit_id, .. } => ("CollateralLock".to_string(), Some(*deposit_id)),
        LedgerOperation::CollateralAttestation { .. } => ("CollateralAttest".to_string(), None),
        LedgerOperation::ReservesRotate { .. } => ("ReservesRotate".to_string(), None),
        LedgerOperation::ReservesIncrease { .. } => ("ReservesIncrease".to_string(), None),
        LedgerOperation::ReservesDecrease { .. } => ("ReservesDecrease".to_string(), None),
        _ => ("Unknown".to_string(), None),
    }
}

/// Validate ledger hash chain
async fn ledger_validate(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let relay_url = get_relay_url(args)
        .ok_or("Missing --relay <url>")?;

    let ledger_prefix = args.iter()
        .find(|a| !a.starts_with("--") && args.iter().position(|x| x == *a).map(|i| i == 0 || args[i-1] != "--relay").unwrap_or(true))
        .ok_or("Missing ledger_id")?;

    println!("Validating ledger {}... from {}...", &ledger_prefix[..16.min(ledger_prefix.len())], relay_url);

    let keys = Keys::generate();
    let client = Client::new(keys);
    client.add_relay(&relay_url).await?;
    client.connect().await;

    // Find full ledger ID from prefix
    let ledger_id = match find_ledger_id(&client, ledger_prefix).await? {
        Some(id) => id,
        None => {
            println!("No ledger found with prefix {}", ledger_prefix);
            client.disconnect().await.ok();
            return Ok(());
        }
    };

    println!("Found: {}", ledger_id);
    println!();

    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .custom_tag(SingleLetterTag::lowercase(Alphabet::D), [ledger_id.as_str()]);

    let events = fetch_all_events_paginated(&client, filter).await?;
    client.disconnect().await.ok();

    if events.is_empty() {
        println!("No updates found for ledger {}", ledger_id);
        return Ok(());
    }

    // Decode and sort updates
    let mut updates: Vec<SignedLedgerUpdate> = Vec::new();
    for event in &events {
        if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
            if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                updates.push(update);
            }
        }
    }

    updates.sort_by_key(|u| u.sequence_number);

    // Check for LedgerOpen at seq 0
    let has_genesis = updates.iter().any(|u| u.sequence_number == 0);
    if !has_genesis {
        println!("ERROR: No LedgerOpen found at sequence 0");
        println!("  Fetched {} updates, min seq = {}",
            updates.len(),
            updates.first().map(|u| u.sequence_number).unwrap_or(0));
        return Ok(());
    }

    // Validate hash chain
    let mut errors = 0;
    let mut prev_hash = [0u8; 32];

    for update in &updates {
        if update.sequence_number == 0 {
            prev_hash = update.current_hash;
            continue;
        }

        if update.previous_hash != prev_hash {
            println!("  ERROR at seq {}: prev_hash mismatch", update.sequence_number);
            println!("    expected: {}", hex::encode(prev_hash));
            println!("    got:      {}", hex::encode(update.previous_hash));
            errors += 1;
        }
        prev_hash = update.current_hash;
    }

    if errors == 0 {
        println!("Hash chain valid: {} updates, final hash {}",
            updates.len(), &hex::encode(prev_hash)[..16]);
    } else {
        println!("Hash chain INVALID: {} errors in {} updates", errors, updates.len());
    }

    Ok(())
}
