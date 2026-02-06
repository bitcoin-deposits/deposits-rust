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
//!   deposits-wallet withdraw <alias> <amount>  - Withdraw funds

use bitcoin::secp256k1::{Secp256k1, SecretKey};
use chrono::Utc;
use deposits_bdk::nostr::NostrTransportBuilder;
use std::path::PathBuf;

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
    eprintln!("  withdraw <alias> <amt>      Withdraw from a deposit");
    eprintln!("  history <alias>             Show transaction history");
    eprintln!("  list                        List all your deposits with aliases");
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
    use bitcoin::bip32::{Xpriv, DerivationPath};
    use std::str::FromStr;

    let xpriv = Xpriv::new_master(network, seed)?;
    let secp = Secp256k1::new();

    // Use BIP-84 path for wallet keys
    let path = DerivationPath::from_str("m/84'/0'/0'/0/0")?;
    let derived = xpriv.derive_priv(&secp, &path)?;

    Ok(derived.private_key)
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
        "withdraw" => withdraw(&args[2..]).await,
        "history" => show_history(&args[2..]).await,
        "list" => list_deposits(&args[2..]).await,
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

    for (i, ad) in ads.iter().enumerate() {
        let name = ad.name.as_deref().unwrap_or("Unnamed");
        println!("{}. {}", i + 1, name);
        println!("   Ledger: {}...", &ad.ledger_id[..16.min(ad.ledger_id.len())]);
        println!("   Available: {} sats ({} BTC)",
            ad.available_headroom_sats,
            ad.available_headroom_sats as f64 / 100_000_000.0);
        println!("   Reserves: {} sats, Obligations: {} sats",
            ad.reserves_amount_sats, ad.total_obligations_sats);
        println!("   Quorum: {} members ({} sats collateral)",
            ad.quorum_size, ad.received_collateral_sats);

        // Fee summary
        let mut fees = Vec::new();
        if ad.annual_fee_bps > 0 {
            fees.push(format!("{}% annual", ad.annual_fee_bps as f64 / 100.0));
        }
        if ad.deposit_fee_bps > 0 {
            fees.push(format!("{}% deposit", ad.deposit_fee_bps as f64 / 100.0));
        }
        if fees.is_empty() {
            println!("   Fees: None");
        } else {
            println!("   Fees: {}", fees.join(", "));
        }

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

    // Try to find by prefix match
    let full_ledger_id = if ledger_id.len() < 64 {
        // Search for matching ledger
        let network_str = match config.network {
            bitcoin::Network::Bitcoin => "bitcoin",
            bitcoin::Network::Testnet => "testnet",
            bitcoin::Network::Signet => "signet",
            bitcoin::Network::Regtest => "regtest",
            _ => "unknown",
        };
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
    println!("Name: {}", ad.name.as_deref().unwrap_or("Unnamed"));
    println!("Ledger ID: {}", ad.ledger_id);
    println!("Operator: {}", ad.operator_pubkey);
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
        println!("Quorum Members:");
        for member in &ad.quorum_members {
            if member.collateral_sats > 0 {
                println!("  - {}...: {} sats (expires block {})",
                    &member.pubkey[..12.min(member.pubkey.len())],
                    member.collateral_sats,
                    member.lock_expires_block);
            } else {
                println!("  - {}...: no attestation", &member.pubkey[..12.min(member.pubkey.len())]);
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

    println!("Opening deposit...");
    println!("  Ledger: {}...", &ledger_id[..16.min(ledger_id.len())]);
    println!("  Amount: {} sats", amount_sats);
    if let Some(ref a) = alias {
        println!("  Alias: {}", a);
    }
    println!();

    let secret_key = derive_secret_key(&config.seed, config.network)?;
    let secp = Secp256k1::new();
    let our_pubkey = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret_key);

    let transport = NostrTransportBuilder::new(secret_key)
        .relay(&config.relays[0])
        .build()
        .await?;

    // Send deposit_offer request
    let request_params = serde_json::json!({
        "pubkey": hex::encode(our_pubkey.serialize()),
        "amount_sats": amount_sats,
    });

    println!("Sending deposit request to operator...");

    let request_id = transport.send_ledger_request(
        &ledger_id,
        "deposit_offer",
        request_params,
    ).await?;

    println!("  Request ID: {}...", &request_id[..16]);
    println!();

    // Poll for response
    println!("Waiting for operator response...");

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
                    println!("Deposit offer accepted!");
                    if let Some(result) = &response.result {
                        if let Some(address) = result.get("deposit_address").and_then(|v| v.as_str()) {
                            println!();
                            println!("Send {} sats to:", amount_sats);
                            println!("  {}", address);
                            println!();
                            println!("After funding, the deposit will be automatically completed.");
                        }
                        if let Some(offer_id) = result.get("offer_id").and_then(|v| v.as_str()) {
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
                                "amount_sats": amount_sats,
                                "status": "pending",
                                "created_at": Utc::now().to_rfc3339(),
                            }));
                            std::fs::write(&deposits_file, serde_json::to_string_pretty(&deposits)?)?;

                            println!();
                            println!("Deposit alias: {}", final_alias);
                            println!("Offer ID: {}", offer_id);
                        }
                    }
                    return Ok(());
                } else {
                    let error = response.error.as_deref().unwrap_or("Unknown error");
                    return Err(format!("Deposit request failed: {}", error).into());
                }
            }
        }

        print!(".");
        use std::io::Write;
        std::io::stdout().flush()?;
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

    let secret_key = derive_secret_key(&config.seed, config.network)?;
    let secp = Secp256k1::new();
    let our_pubkey = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret_key);

    // Use stored pubkey or derive fresh
    let pubkey_hex = deposit_pubkey
        .map(|s| s.to_string())
        .unwrap_or_else(|| hex::encode(our_pubkey.serialize()));

    let transport = NostrTransportBuilder::new(secret_key)
        .relay(&config.relays[0])
        .build()
        .await?;

    // Send deposit_offer request for existing deposit
    let request_params = serde_json::json!({
        "pubkey": pubkey_hex,
        "amount_sats": amount_sats,
    });

    println!("Sending offer request to operator...");

    let request_id = transport.send_ledger_request(
        ledger_id,
        "deposit_offer",
        request_params,
    ).await?;

    println!("  Request ID: {}...", &request_id[..16]);
    println!();

    // Poll for response
    println!("Waiting for operator response...");

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
                        if let Some(address) = result.get("deposit_address").and_then(|v| v.as_str()) {
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
        std::io::stdout().flush()?;
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

        println!("  {} ", alias);
        println!("    Ledger: {}...", &ledger_id[..16.min(ledger_id.len())]);
        println!("    Amount: {} sats", amount);
        println!("    Status: {}", status);
        if !created_at.is_empty() {
            println!("    Created: {}", created_at);
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

    for deposit in &deposits {
        let alias = deposit.get("alias").and_then(|v| v.as_str()).unwrap_or("(none)");
        let ledger_id = deposit.get("ledger_id").and_then(|v| v.as_str()).unwrap_or("unknown");
        let amount = deposit.get("amount_sats").and_then(|v| v.as_u64()).unwrap_or(0);
        let status = deposit.get("status").and_then(|v| v.as_str()).unwrap_or("unknown");

        let status_symbol = match status {
            "completed" | "funded" => "+",
            "pending" => "~",
            _ => "?",
        };

        println!("  {} {} {:>10} sats  ({})", status_symbol, alias, amount, &ledger_id[..8.min(ledger_id.len())]);

        if status == "funded" || status == "completed" {
            total_sats += amount;
        }
    }

    println!();
    println!("  Total:  {} sats ({} BTC)", total_sats, total_sats as f64 / 100_000_000.0);
    println!();
    println!("  + = funded/completed, ~ = pending");

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

    let secret_key = derive_secret_key(&config.seed, config.network)?;
    let secp = Secp256k1::new();
    let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &secret_key);
    let our_pubkey = keypair.public_key();

    // Generate nonce
    let mut rng = OsRng;
    let mut nonce = [0u8; 32];
    rng.fill_bytes(&mut nonce);
    let nonce_hex = hex::encode(&nonce);

    // Sign the withdrawal message
    // Format: "withdraw:{address}:{amount_sats}:{fee_sats}:{nonce_hex}"
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

    let transport = NostrTransportBuilder::new(secret_key)
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
        std::io::stdout().flush()?;
    }

    println!();
    Err("Timeout waiting for operator response".into())
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
