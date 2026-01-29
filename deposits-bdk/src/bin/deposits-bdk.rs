// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! deposits-bdk CLI
//!
//! A deposits protocol node using BDK for on-chain reserves and Nostr for messaging.

use bitcoin::secp256k1::PublicKey;
use bitcoin::Network;
use deposits_bdk::{Node, NodeConfig};
use std::path::PathBuf;
use std::str::FromStr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    // Parse command line arguments
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        print_usage(&args[0]);
        return Ok(());
    }

    match args[1].as_str() {
        "run" => run_node(&args[2..]).await?,
        "info" => show_info(&args[2..]).await?,
        "address" => show_address(&args[2..]).await?,
        "reserves" => create_reserves(&args[2..]).await?,
        "ledger" => ledger_command(&args[2..]).await?,
        "partner" => partner_command(&args[2..]).await?,
        "deposit" => deposit_command(&args[2..]).await?,
        "withdraw" => withdraw_command(&args[2..]).await?,
        "help" | "--help" | "-h" => print_usage(&args[0]),
        cmd => {
            eprintln!("Unknown command: {}", cmd);
            print_usage(&args[0]);
        }
    }

    Ok(())
}

fn print_usage(program: &str) {
    println!(
        r#"deposits-bdk - Bitcoin Deposits Protocol Node (BDK + Nostr)

USAGE:
    {} <COMMAND> [OPTIONS]

COMMANDS:
    run             Run the deposits node
    info            Show node info
    address         Generate a new receiving address
    reserves        Create a reserves UTXO
    ledger          Manage ledgers (open, list)
    partner         Manage collateral partners (request, list)
    deposit         Manage deposit offers for on-chain funding
    withdraw        Manage on-chain withdrawals
    help            Show this help message

LEDGER SUBCOMMANDS:
    ledger open <partner_pubkey> [enforcement_block]
                    Open a ledger with a partner. Set enforcement_block to a
                    future block for bootstrap phase, or 0 for immediate enforcement.
    ledger list     List all ledgers

PARTNER SUBCOMMANDS:
    partner request <pubkey>   Send collateral partnership request
    partner list               List all collateral partners

DEPOSIT SUBCOMMANDS:
    deposit offer <partner_pubkey> <deposit_pubkey> <max_sats> <min_sats> <blocks_valid>
                    Create a signed deposit offer for on-chain funding
    deposit list    List all deposit offers
    deposit open <partner_pubkey> <deposit_pubkey>
                    Open a new deposit in a ledger
    deposit ls <partner_pubkey>
                    List all deposits in a ledger
    deposit credit <partner_pubkey> <deposit_pubkey> <amount_msats> <invoice_id>
                    Manually credit a deposit
    deposit transfer <partner_pubkey> <from_deposit> <to_deposit> <amount_msats>
                    Transfer funds between deposits in the same ledger
    deposit check <offer_id>
                    Check if a deposit offer has been funded
    deposit complete <offer_id> <txid> <amount_sats>
                    Complete a funded deposit offer and credit the deposit

WITHDRAW SUBCOMMANDS:
    withdraw lock <deposit_pubkey> <address> <amount_sats> <fee_sats> <signature>
                    Lock funds for an on-chain withdrawal (signature must be from depositor)
    withdraw complete <withdrawal_id>
                    Complete a withdrawal by broadcasting the transaction
    withdraw cancel <withdrawal_id>
                    Cancel a pending withdrawal (only before broadcast)
    withdraw list   List all withdrawals

OPTIONS:
    --seed <hex>       Seed for wallet/identity (64 hex chars)
    --network <net>    Bitcoin network: mainnet, testnet, signet, regtest (default: signet)
    --esplora <url>    Esplora server URL (default: https://mempool.space/signet/api)
    --relay <url>      Nostr relay URL (can be specified multiple times)
    --nwc <uri>        NWC connection string for Lightning operations
    --data-dir <path>  Data directory (default: ~/.deposits-bdk)

EXAMPLES:
    # Run a node on signet
    {} run --network signet

    # Run with custom esplora and relay
    {} run --esplora http://localhost:3002 --relay ws://localhost:7777

    # Show node info
    {} info

    # Create reserves (1 BTC default)
    {} reserves 100000000 --network regtest

    # Open a ledger with bootstrap phase (enforcement at block 1000)
    {} ledger open 02abc...pubkey 1000 --network regtest

"#,
        program, program, program, program, program, program
    );
}

fn parse_config(args: &[String]) -> Result<NodeConfig, String> {
    let mut seed: Option<[u8; 32]> = None;
    let mut network = Network::Signet;
    let mut electrum_url = "https://mempool.space/signet/api".to_string();
    let mut relays = Vec::new();
    let mut nwc_uri = None;
    let mut data_dir = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".deposits-bdk");

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
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
        nwc_uri,
        data_dir,
    })
}

async fn run_node(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let config = parse_config(args)?;

    tracing::info!("Starting deposits-bdk node...");
    tracing::info!("Network: {:?}", config.network);
    tracing::info!("Electrum: {}", config.electrum_url);
    tracing::info!(
        "Relays: {:?}",
        if config.relays.is_empty() {
            deposits_bdk::nostr::DEFAULT_RELAYS
                .iter()
                .map(|s| s.to_string())
                .collect()
        } else {
            config.relays.clone()
        }
    );

    let mut node = Node::new(config).await?;

    tracing::info!("Node ID: {}", node.node_id);

    // Sync wallet
    tracing::info!("Syncing wallet...");
    if let Err(e) = node.sync_wallet() {
        tracing::warn!("Initial wallet sync failed: {}", e);
    }

    // Show balance
    match node.wallet_balance() {
        Ok(balance) => tracing::info!("Wallet balance: {} sats", balance),
        Err(e) => tracing::warn!("Failed to get balance: {}", e),
    }

    // Start the node
    node.start().await?;

    tracing::info!("Node running. Press Ctrl+C to stop.");

    // Run the event loop
    node.run().await?;

    Ok(())
}

async fn show_info(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let config = parse_config(args)?;
    let node = Node::new(config).await?;

    println!("Node ID: {}", node.node_id);
    println!("Nostr pubkey: {}", node.nostr.nostr_pubkey());

    if let Err(e) = node.sync_wallet() {
        println!("Wallet sync failed: {}", e);
    } else {
        println!("Wallet balance: {} sats", node.wallet_balance()?);
        println!("Reserves balance: {} sats", node.reserves_balance()?);
    }

    if let Some(lightning) = &node.lightning {
        match lightning.get_balance().await {
            Ok(balance) => println!("Lightning balance: {} msats", balance),
            Err(e) => println!("Lightning balance: error - {}", e),
        }
    } else {
        println!("Lightning: not configured (provide --nwc to enable)");
    }

    Ok(())
}

async fn show_address(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let config = parse_config(args)?;
    let node = Node::new(config).await?;

    let address = node.new_address()?;
    println!("{}", address);

    Ok(())
}

async fn create_reserves(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    // Parse amount from first positional argument
    let mut amount_sats: u64 = 100_000_000; // Default 1 BTC
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with("--") {
            // Config argument - pass through
            config_args.push(args[i].clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
                i += 1;
            }
        } else {
            // Positional argument - amount in sats
            amount_sats = args[i]
                .parse()
                .map_err(|_| format!("Invalid amount: {}", args[i]))?;
        }
        i += 1;
    }

    let config = parse_config(&config_args)?;
    let node = Node::new(config).await?;

    // Sync wallet first
    node.sync_wallet()?;

    let balance = node.wallet_balance()?;
    if balance < amount_sats + 1000 {
        // Need funds + fee
        return Err(format!(
            "Insufficient balance: {} sats (need {} + fees)",
            balance, amount_sats
        )
        .into());
    }

    println!("Creating reserves output for {} sats...", amount_sats);

    // Create reserves with no partners initially (operator-only for now)
    let reserves = node.create_reserves(amount_sats, vec![], 0)?;

    // Broadcast the transaction
    let txid = node.wallet.broadcast(&reserves.tx)?;

    println!("Reserves created!");
    println!("  TXID: {}", txid);
    println!("  Vout: {}", reserves.outpoint.vout);
    println!("  Amount: {} sats", reserves.amount);
    println!("  Address: {}", reserves.address);
    println!("  Timeout height: {}", reserves.timeout_height);

    Ok(())
}

/// Handle ledger subcommands
async fn ledger_command(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.is_empty() {
        eprintln!("Usage: deposits-bdk ledger <open|list> [args...]");
        return Ok(());
    }

    match args[0].as_str() {
        "open" => ledger_open(&args[1..]).await,
        "list" => ledger_list(&args[1..]).await,
        cmd => {
            eprintln!("Unknown ledger subcommand: {}", cmd);
            eprintln!("Usage: deposits-bdk ledger <open|list> [args...]");
            Ok(())
        }
    }
}

/// Open a new ledger with a partner
async fn ledger_open(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    // Parse positional arguments: <partner_pubkey> [enforcement_block]
    let mut partner_pubkey_str: Option<String> = None;
    let mut enforcement_block: u64 = 0; // Default: immediate enforcement
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with("--") {
            // Config argument - pass through
            config_args.push(args[i].clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
                i += 1;
            }
        } else if partner_pubkey_str.is_none() {
            // First positional argument - partner pubkey
            partner_pubkey_str = Some(args[i].clone());
        } else {
            // Second positional argument - enforcement block
            enforcement_block = args[i]
                .parse()
                .map_err(|_| format!("Invalid enforcement block: {}", args[i]))?;
        }
        i += 1;
    }

    let partner_pubkey_str = partner_pubkey_str.ok_or("Partner pubkey required")?;
    let partner_pubkey = PublicKey::from_str(&partner_pubkey_str)
        .map_err(|e| format!("Invalid partner pubkey: {}", e))?;

    let config = parse_config(&config_args)?;
    let node = Node::new(config).await?;

    // Sync wallet to get current state
    node.sync_wallet()?;

    // Check if we have reserves
    let reserves_balance = node.reserves_balance()?;
    if reserves_balance == 0 {
        return Err("No reserves found. Create reserves first with 'reserves' command.".into());
    }

    println!("Opening ledger with partner: {}", partner_pubkey);
    println!("  Our node ID: {}", node.node_id);
    println!("  Reserves: {} sats", reserves_balance);
    println!("  Collateral enforcement block: {}", enforcement_block);

    // Create the ledger
    let ledger = node.open_ledger(partner_pubkey, enforcement_block)?;

    println!("\nLedger opened successfully!");
    println!("  Operator: {}", ledger.state.operator_key);
    println!("  Partner: {}", ledger.state.partner_key);
    println!("  Sequence: {}", ledger.state.sequence);
    println!("  Hash: {:02x?}", &ledger.state.hash[0..8]);
    if let Some(block) = ledger.state.collateral_enforcement_block {
        if block > 0 {
            println!("  Bootstrap phase: collateral requirements enforced at block {}", block);
        } else {
            println!("  Immediate collateral enforcement");
        }
    }

    Ok(())
}

/// List all ledgers
async fn ledger_list(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let config = parse_config(args)?;
    let node = Node::new(config).await?;

    let ledgers = node.list_ledgers();

    if ledgers.is_empty() {
        println!("No ledgers found.");
        return Ok(());
    }

    println!("Ledgers ({} total):", ledgers.len());
    println!();

    for ((operator, partner), ledger_arc) in ledgers {
        let ledger = ledger_arc.read().unwrap();
        let role = if operator == node.node_id {
            "Operator"
        } else {
            "Partner"
        };

        println!("  {} ({})", partner, role);
        println!("    Operator: {}", operator);
        println!("    Partner: {}", partner);
        println!("    Sequence: {}", ledger.state.sequence);
        println!("    Deposits: {} total, {} sats balance",
            ledger.state.deposits.len(),
            ledger.state.total_deposit_balance());
        println!("    Reserves: {} sats", ledger.state.reserves_amount());
        if let Some(block) = ledger.state.collateral_enforcement_block {
            println!("    Enforcement block: {}", block);
        }
        println!();
    }

    Ok(())
}

/// Handle partner subcommands
async fn partner_command(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.is_empty() {
        eprintln!("Usage: deposits-bdk partner <request|list> [args...]");
        return Ok(());
    }

    match args[0].as_str() {
        "request" => partner_request(&args[1..]).await,
        "list" => partner_list(&args[1..]).await,
        cmd => {
            eprintln!("Unknown partner subcommand: {}", cmd);
            eprintln!("Usage: deposits-bdk partner <request|list> [args...]");
            Ok(())
        }
    }
}

/// Request a peer to be a collateral partner
async fn partner_request(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    // Parse positional argument: <peer_pubkey>
    let mut peer_pubkey_str: Option<String> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with("--") {
            config_args.push(args[i].clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
                i += 1;
            }
        } else if peer_pubkey_str.is_none() {
            peer_pubkey_str = Some(args[i].clone());
        }
        i += 1;
    }

    let peer_pubkey_str = peer_pubkey_str.ok_or("Peer pubkey required")?;
    let peer_pubkey = PublicKey::from_str(&peer_pubkey_str)
        .map_err(|e| format!("Invalid peer pubkey: {}", e))?;

    let config = parse_config(&config_args)?;
    let node = Node::new(config).await?;

    println!("Requesting collateral partnership with: {}", peer_pubkey);

    // Send partnership request via Nostr
    node.request_partner(peer_pubkey).await?;

    println!("Partnership request sent!");
    println!("  The peer will need to accept the request to establish the partnership.");

    Ok(())
}

/// List collateral partners
async fn partner_list(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let config = parse_config(args)?;
    let node = Node::new(config).await?;

    let partners = node.list_partners();

    if partners.is_empty() {
        println!("No collateral partners found.");
        return Ok(());
    }

    println!("Collateral Partners ({} total):", partners.len());
    for (pubkey, role) in partners {
        println!("  {} - {}", pubkey, role);
    }

    Ok(())
}

// ============================================================================
// Deposit Offer Commands
// ============================================================================

/// Handle deposit subcommands
async fn deposit_command(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.is_empty() {
        eprintln!("Usage: deposits-bdk deposit <offer|list|open|ls|credit|transfer|check|complete> [args...]");
        return Ok(());
    }

    match args[0].as_str() {
        "offer" => deposit_offer(&args[1..]).await,
        "list" => deposit_list(&args[1..]).await,
        "open" => deposit_open(&args[1..]).await,
        "ls" => deposit_ls(&args[1..]).await,
        "credit" => deposit_credit(&args[1..]).await,
        "transfer" => deposit_transfer(&args[1..]).await,
        "check" => deposit_check(&args[1..]).await,
        "complete" => deposit_complete(&args[1..]).await,
        cmd => {
            eprintln!("Unknown deposit subcommand: {}", cmd);
            eprintln!("Usage: deposits-bdk deposit <offer|list|open|ls|credit|transfer|check|complete> [args...]");
            Ok(())
        }
    }
}

/// Create a deposit offer for on-chain funding
async fn deposit_offer(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    // Parse positional arguments:
    // <partner_pubkey> <deposit_pubkey> <max_sats> <min_sats> <blocks_valid>
    let mut positional: Vec<String> = Vec::new();
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with("--") {
            config_args.push(args[i].clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
                i += 1;
            }
        } else {
            positional.push(args[i].clone());
        }
        i += 1;
    }

    if positional.len() < 5 {
        eprintln!("Usage: deposits-bdk deposit offer <partner_pubkey> <deposit_pubkey> <max_sats> <min_sats> <blocks_valid> [options]");
        eprintln!("\nExample:");
        eprintln!("  deposits-bdk deposit offer 02abc...partner 02def...deposit 1000000 10000 144");
        eprintln!("\nThis creates a signed offer committing to credit the deposit");
        eprintln!("with on-chain funds sent to a new address, up to max_sats,");
        eprintln!("with minimum min_sats, valid for blocks_valid blocks.");
        return Ok(());
    }

    let partner_pubkey = PublicKey::from_str(&positional[0])
        .map_err(|e| format!("Invalid partner pubkey: {}", e))?;
    let deposit_pubkey = PublicKey::from_str(&positional[1])
        .map_err(|e| format!("Invalid deposit pubkey: {}", e))?;
    let max_sats: u64 = positional[2]
        .parse()
        .map_err(|_| format!("Invalid max_sats: {}", positional[2]))?;
    let min_sats: u64 = positional[3]
        .parse()
        .map_err(|_| format!("Invalid min_sats: {}", positional[3]))?;
    let blocks_valid: u32 = positional[4]
        .parse()
        .map_err(|_| format!("Invalid blocks_valid: {}", positional[4]))?;

    if min_sats >= max_sats {
        return Err("min_sats must be less than max_sats".into());
    }

    let config = parse_config(&config_args)?;
    let node = Node::new(config).await?;

    // Sync wallet to get current block height
    node.sync_wallet()?;

    println!("Creating deposit offer...");
    println!("  Partner: {}", partner_pubkey);
    println!("  Deposit: {}", deposit_pubkey);
    println!("  Max amount: {} sats", max_sats);
    println!("  Min amount: {} sats", min_sats);
    println!("  Valid for: {} blocks", blocks_valid);

    // Create the offer
    let offer = node.create_deposit_offer(
        partner_pubkey,
        deposit_pubkey,
        max_sats,
        min_sats,
        blocks_valid,
    )?;

    println!("\nDeposit offer created!");
    println!("  Offer ID: {}", hex::encode(&offer.offer_id));
    println!("  Funding address: {}", offer.funding_address);
    println!("  Deadline block: {}", offer.deadline_block);
    println!("  Created at block: {}", offer.created_at_block);
    println!("  Signature: {}", hex::encode(&offer.operator_signature[..32]));
    println!("\nSend {} to {} sats to: {}", min_sats, max_sats, offer.funding_address);
    println!("Before block: {}", offer.deadline_block);

    // Output JSON for programmatic use
    let json = serde_json::to_string_pretty(&offer)?;
    println!("\nOffer JSON:");
    println!("{}", json);

    Ok(())
}

/// List deposit offers
async fn deposit_list(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let config = parse_config(args)?;
    let node = Node::new(config).await?;

    // Check for expired offers
    if let Err(e) = node.check_expired_offers() {
        tracing::warn!("Failed to check expired offers: {}", e);
    }

    let offers = node.list_deposit_offers();

    if offers.is_empty() {
        println!("No deposit offers found.");
        return Ok(());
    }

    println!("Deposit Offers ({} total):", offers.len());
    println!();

    for (offer, status) in offers {
        let status_str = match &status {
            deposits_core::DepositOfferStatus::Pending => "Pending".to_string(),
            deposits_core::DepositOfferStatus::FundingReceived { txid, amount_sats, .. } => {
                format!("Funding received: {} sats ({})", amount_sats, &txid[..16])
            }
            deposits_core::DepositOfferStatus::Completed { amount_sats, .. } => {
                format!("Completed: {} sats", amount_sats)
            }
            deposits_core::DepositOfferStatus::Expired { expired_at_block } => {
                format!("Expired at block {}", expired_at_block)
            }
            deposits_core::DepositOfferStatus::Cancelled => "Cancelled".to_string(),
        };

        println!("  Offer: {}", hex::encode(&offer.offer_id[..8]));
        println!("    Status: {}", status_str);
        println!("    Address: {}", offer.funding_address);
        println!("    Amount: {} - {} sats", offer.min_amount_sats, offer.max_amount_sats);
        println!("    Deadline: block {}", offer.deadline_block);
        println!("    Partner: {}", offer.partner_id);
        println!("    Deposit: {}", offer.deposit_pubkey);
        println!();
    }

    Ok(())
}

/// Open a new deposit in a ledger
async fn deposit_open(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    // Parse positional arguments: <partner_pubkey> <deposit_pubkey>
    let mut positional: Vec<String> = Vec::new();
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with("--") {
            config_args.push(args[i].clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
                i += 1;
            }
        } else {
            positional.push(args[i].clone());
        }
        i += 1;
    }

    if positional.len() < 2 {
        eprintln!("Usage: deposits-bdk deposit open <partner_pubkey> <deposit_pubkey> [options]");
        eprintln!("\nExample:");
        eprintln!("  deposits-bdk deposit open 02abc...partner 02def...deposit");
        eprintln!("\nThis opens a new deposit in the ledger with the given partner.");
        return Ok(());
    }

    let partner_pubkey = PublicKey::from_str(&positional[0])
        .map_err(|e| format!("Invalid partner pubkey: {}", e))?;
    let deposit_pubkey = PublicKey::from_str(&positional[1])
        .map_err(|e| format!("Invalid deposit pubkey: {}", e))?;

    let config = parse_config(&config_args)?;
    let node = Node::new(config).await?;

    println!("Opening deposit...");
    println!("  Partner: {}", partner_pubkey);
    println!("  Deposit pubkey: {}", deposit_pubkey);

    let deposit = node.open_deposit(partner_pubkey, deposit_pubkey, None)?;

    println!("\nDeposit opened!");
    println!("  Pubkey: {}", deposit.pubkey);
    println!("  Balance: {} msats", deposit.balance);

    Ok(())
}

/// List deposits in a specific ledger
async fn deposit_ls(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    // Parse positional arguments: <partner_pubkey>
    let mut partner_pubkey_str: Option<String> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with("--") {
            config_args.push(args[i].clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
                i += 1;
            }
        } else if partner_pubkey_str.is_none() {
            partner_pubkey_str = Some(args[i].clone());
        }
        i += 1;
    }

    let partner_pubkey_str = partner_pubkey_str.ok_or("Partner pubkey required")?;
    let partner_pubkey = PublicKey::from_str(&partner_pubkey_str)
        .map_err(|e| format!("Invalid partner pubkey: {}", e))?;

    let config = parse_config(&config_args)?;
    let node = Node::new(config).await?;

    let deposits = node.list_deposits(partner_pubkey);

    if deposits.is_empty() {
        println!("No deposits found in ledger with partner {}", partner_pubkey);
        return Ok(());
    }

    println!("Deposits in ledger with {} ({} total):", partner_pubkey, deposits.len());
    println!();

    for (pubkey, deposit) in deposits {
        println!("  Deposit: {}", pubkey);
        println!("    Balance: {} msats ({} sats)", deposit.balance, deposit.balance / 1000);
        println!("    Locked: {} msats", deposit.locked_balance);
        let fees = &deposit.fees;
        println!("    Fees: {} fixed + {} bps every {} blocks",
            fees.annualized_fixed, fees.annualized_bps, fees.frequency_blocks);
        println!();
    }

    Ok(())
}

/// Credit a deposit manually
async fn deposit_credit(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    // Parse positional arguments: <partner_pubkey> <deposit_pubkey> <amount_msats> <invoice_id>
    let mut positional: Vec<String> = Vec::new();
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with("--") {
            config_args.push(args[i].clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
                i += 1;
            }
        } else {
            positional.push(args[i].clone());
        }
        i += 1;
    }

    if positional.len() < 4 {
        eprintln!("Usage: deposits-bdk deposit credit <partner_pubkey> <deposit_pubkey> <amount_msats> <invoice_id> [options]");
        eprintln!("\nExample:");
        eprintln!("  deposits-bdk deposit credit 02abc...partner 02def...deposit 1000000 inv123");
        eprintln!("\nThis credits the deposit with the specified amount.");
        return Ok(());
    }

    let partner_pubkey = PublicKey::from_str(&positional[0])
        .map_err(|e| format!("Invalid partner pubkey: {}", e))?;
    let deposit_pubkey = PublicKey::from_str(&positional[1])
        .map_err(|e| format!("Invalid deposit pubkey: {}", e))?;
    let amount_msats: u64 = positional[2]
        .parse()
        .map_err(|_| format!("Invalid amount_msats: {}", positional[2]))?;
    let invoice_id = positional[3].clone();

    // Generate a payment hash
    use bitcoin::hashes::{sha256, Hash};
    let payment_hash = sha256::Hash::hash(invoice_id.as_bytes()).to_byte_array();

    let config = parse_config(&config_args)?;
    let node = Node::new(config).await?;

    println!("Crediting deposit...");
    println!("  Partner: {}", partner_pubkey);
    println!("  Deposit: {}", deposit_pubkey);
    println!("  Amount: {} msats ({} sats)", amount_msats, amount_msats / 1000);
    println!("  Invoice ID: {}", invoice_id);

    let new_balance = node.credit_deposit(
        partner_pubkey,
        deposit_pubkey,
        amount_msats,
        payment_hash,
        invoice_id,
    )?;

    println!("\nDeposit credited!");
    println!("  New balance: {} msats ({} sats)", new_balance, new_balance / 1000);

    Ok(())
}

/// Transfer between deposits in the same ledger
async fn deposit_transfer(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    // Parse positional arguments: <partner_pubkey> <from_deposit> <to_deposit> <amount_msats>
    let mut positional: Vec<String> = Vec::new();
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with("--") {
            config_args.push(args[i].clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
                i += 1;
            }
        } else {
            positional.push(args[i].clone());
        }
        i += 1;
    }

    if positional.len() < 4 {
        eprintln!("Usage: deposits-bdk deposit transfer <partner_pubkey> <from_deposit> <to_deposit> <amount_msats> [options]");
        eprintln!("\nExample:");
        eprintln!("  deposits-bdk deposit transfer 02abc...partner 02def...from 02ghi...to 1000000");
        eprintln!("\nThis transfers funds from one deposit to another within the same ledger.");
        return Ok(());
    }

    let partner_pubkey = PublicKey::from_str(&positional[0])
        .map_err(|e| format!("Invalid partner pubkey: {}", e))?;
    let from_deposit = PublicKey::from_str(&positional[1])
        .map_err(|e| format!("Invalid from_deposit pubkey: {}", e))?;
    let to_deposit = PublicKey::from_str(&positional[2])
        .map_err(|e| format!("Invalid to_deposit pubkey: {}", e))?;
    let amount_msats: u64 = positional[3]
        .parse()
        .map_err(|_| format!("Invalid amount_msats: {}", positional[3]))?;

    let config = parse_config(&config_args)?;
    let node = Node::new(config).await?;

    println!("Transferring funds...");
    println!("  Partner: {}", partner_pubkey);
    println!("  From: {}", from_deposit);
    println!("  To: {}", to_deposit);
    println!("  Amount: {} msats ({} sats)", amount_msats, amount_msats / 1000);

    let (transfer_id, from_balance, to_balance) = node.transfer_between_deposits(
        partner_pubkey,
        from_deposit,
        to_deposit,
        amount_msats,
    )?;

    println!("\nTransfer complete!");
    println!("  Transfer ID: {}", hex::encode(&transfer_id[..8]));
    println!("  From balance: {} msats ({} sats)", from_balance, from_balance / 1000);
    println!("  To balance: {} msats ({} sats)", to_balance, to_balance / 1000);

    Ok(())
}

/// Check if a deposit offer has been funded
async fn deposit_check(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    // Parse positional arguments: <offer_id>
    let mut offer_id_str: Option<String> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with("--") {
            config_args.push(args[i].clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
                i += 1;
            }
        } else if offer_id_str.is_none() {
            offer_id_str = Some(args[i].clone());
        }
        i += 1;
    }

    let offer_id_str = offer_id_str.ok_or("Offer ID required")?;
    let offer_id_bytes = hex::decode(&offer_id_str)
        .map_err(|e| format!("Invalid offer ID hex: {}", e))?;

    if offer_id_bytes.len() != 32 {
        return Err("Offer ID must be 32 bytes (64 hex characters)".into());
    }

    let mut offer_id = [0u8; 32];
    offer_id.copy_from_slice(&offer_id_bytes);

    let config = parse_config(&config_args)?;
    let node = Node::new(config).await?;

    println!("Checking deposit offer funding...");
    println!("  Offer ID: {}", hex::encode(&offer_id[..8]));

    // Sync wallet first
    node.sync_wallet()?;

    // Check for funding
    match node.check_deposit_offer_funding(&offer_id)? {
        Some((txid, amount_sats)) => {
            println!("\nFunding detected!");
            println!("  Transaction: {}", txid);
            println!("  Amount: {} sats", amount_sats);
            println!("\nUse 'deposit complete <offer_id> <txid> <amount_sats>' to credit the deposit.");
        }
        None => {
            println!("\nNo funding detected yet.");
            if let Some((offer, _)) = node.get_deposit_offer(&offer_id) {
                println!("  Funding address: {}", offer.funding_address);
                println!("  Waiting for payment of {} - {} sats", offer.min_amount_sats, offer.max_amount_sats);
            }
        }
    }

    Ok(())
}

/// Complete a deposit offer by crediting the deposit
async fn deposit_complete(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    // Parse positional arguments: <offer_id> <txid> <amount_sats>
    let mut positional: Vec<String> = Vec::new();
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with("--") {
            config_args.push(args[i].clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
                i += 1;
            }
        } else {
            positional.push(args[i].clone());
        }
        i += 1;
    }

    if positional.len() < 3 {
        eprintln!("Usage: deposits-bdk deposit complete <offer_id> <txid> <amount_sats> [options]");
        eprintln!("\nExample:");
        eprintln!("  deposits-bdk deposit complete abc123...offerid tx123...txid 100000");
        eprintln!("\nThis marks the deposit offer as complete and credits the deposit.");
        return Ok(());
    }

    let offer_id_bytes = hex::decode(&positional[0])
        .map_err(|e| format!("Invalid offer ID hex: {}", e))?;

    if offer_id_bytes.len() != 32 {
        return Err("Offer ID must be 32 bytes (64 hex characters)".into());
    }

    let mut offer_id = [0u8; 32];
    offer_id.copy_from_slice(&offer_id_bytes);

    let txid = positional[1].clone();
    let amount_sats: u64 = positional[2]
        .parse()
        .map_err(|_| format!("Invalid amount_sats: {}", positional[2]))?;

    let config = parse_config(&config_args)?;
    let node = Node::new(config).await?;

    println!("Completing deposit offer...");
    println!("  Offer ID: {}", hex::encode(&offer_id[..8]));
    println!("  Transaction: {}", txid);
    println!("  Amount: {} sats", amount_sats);

    let new_balance = node.complete_deposit_offer(&offer_id, txid, amount_sats)?;

    println!("\nDeposit offer completed!");
    println!("  New balance: {} msats ({} sats)", new_balance, new_balance / 1000);

    Ok(())
}

// ============================================================================
// Withdraw Commands
// ============================================================================

/// Handle withdraw subcommands
async fn withdraw_command(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.is_empty() {
        eprintln!("Usage: deposits-bdk withdraw <lock|complete|cancel|list> [args...]");
        return Ok(());
    }

    match args[0].as_str() {
        "lock" => withdraw_lock(&args[1..]).await,
        "complete" => withdraw_complete(&args[1..]).await,
        "cancel" => withdraw_cancel(&args[1..]).await,
        "list" => withdraw_list(&args[1..]).await,
        cmd => {
            eprintln!("Unknown withdraw subcommand: {}", cmd);
            eprintln!("Usage: deposits-bdk withdraw <lock|complete|cancel|list> [args...]");
            Ok(())
        }
    }
}

/// Lock funds for an on-chain withdrawal
async fn withdraw_lock(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    // Parse positional arguments:
    // <deposit_pubkey> <address> <amount_sats> <fee_sats> <signature_hex>
    let mut positional: Vec<String> = Vec::new();
    let mut config_args = Vec::new();
    let mut memo: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        if args[i] == "--memo" {
            i += 1;
            if i < args.len() {
                memo = Some(args[i].clone());
            }
        } else if args[i].starts_with("--") {
            config_args.push(args[i].clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
                i += 1;
            }
        } else {
            positional.push(args[i].clone());
        }
        i += 1;
    }

    if positional.len() < 5 {
        eprintln!("Usage: deposits-bdk withdraw lock <deposit_pubkey> <address> <amount_sats> <fee_sats> <signature_hex> [--memo <text>] [options]");
        eprintln!("\nThe signature must be created by the depositor authorizing the withdrawal.");
        eprintln!("Format: ECDSA signature over 'WITHDRAWAL:<nonce>:<deposit>:<address>:<amount>:<fee>'");
        return Ok(());
    }

    let deposit_pubkey = PublicKey::from_str(&positional[0])
        .map_err(|e| format!("Invalid deposit pubkey: {}", e))?;
    let destination_address = positional[1].clone();
    let amount_sats: u64 = positional[2]
        .parse()
        .map_err(|_| format!("Invalid amount_sats: {}", positional[2]))?;
    let fee_sats: u64 = positional[3]
        .parse()
        .map_err(|_| format!("Invalid fee_sats: {}", positional[3]))?;
    let signature_hex = &positional[4];

    // Parse signature
    let sig_bytes = hex::decode(signature_hex)
        .map_err(|e| format!("Invalid signature hex: {}", e))?;
    if sig_bytes.len() != 64 {
        return Err("Signature must be 64 bytes".into());
    }
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&sig_bytes);

    let config = parse_config(&config_args)?;
    let node = Node::new(config).await?;

    // Sync wallet
    node.sync_wallet()?;

    println!("Locking withdrawal...");
    println!("  Deposit: {}", deposit_pubkey);
    println!("  Destination: {}", destination_address);
    println!("  Amount: {} sats", amount_sats);
    println!("  Fee: {} sats", fee_sats);
    if let Some(ref m) = memo {
        println!("  Memo: {}", m);
    }

    // Lock the withdrawal
    let result = node.lock_withdrawal(
        deposit_pubkey,
        destination_address,
        amount_sats,
        fee_sats,
        signature,
        memo,
    )?;

    println!("\nWithdrawal locked!");
    println!("  Withdrawal ID: {}", hex::encode(&result.withdrawal.withdrawal_id));
    println!("  Nonce: {}", hex::encode(&result.withdrawal.nonce[..8]));
    println!("  Total debit: {} sats", result.withdrawal.total_debit());
    println!("\nThe withdrawal can now be completed with:");
    println!("  deposits-bdk withdraw complete {}", hex::encode(&result.withdrawal.withdrawal_id));

    Ok(())
}

/// Complete a withdrawal by broadcasting the transaction
async fn withdraw_complete(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut withdrawal_id_hex: Option<String> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with("--") {
            config_args.push(args[i].clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
                i += 1;
            }
        } else if withdrawal_id_hex.is_none() {
            withdrawal_id_hex = Some(args[i].clone());
        }
        i += 1;
    }

    let withdrawal_id_hex = withdrawal_id_hex.ok_or("Withdrawal ID required")?;
    let id_bytes = hex::decode(&withdrawal_id_hex)
        .map_err(|e| format!("Invalid withdrawal ID hex: {}", e))?;
    if id_bytes.len() != 32 {
        return Err("Withdrawal ID must be 32 bytes".into());
    }
    let mut withdrawal_id = [0u8; 32];
    withdrawal_id.copy_from_slice(&id_bytes);

    let config = parse_config(&config_args)?;
    let node = Node::new(config).await?;

    // Sync wallet
    node.sync_wallet()?;

    println!("Completing withdrawal {}...", &withdrawal_id_hex[..16]);

    let result = node.complete_withdrawal(&withdrawal_id)?;

    println!("\nWithdrawal completed!");
    println!("  Transaction ID: {}", result.txid);
    println!("  Amount: {} sats", result.amount_sats);
    println!("  Fee: {} sats", result.fee_sats);
    println!("\nThe transaction includes an OP_RETURN commitment proving");
    println!("this withdrawal was executed for the specific request.");

    Ok(())
}

/// Cancel a pending withdrawal
async fn withdraw_cancel(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut withdrawal_id_hex: Option<String> = None;
    let mut reason = "Cancelled by operator".to_string();
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        if args[i] == "--reason" {
            i += 1;
            if i < args.len() {
                reason = args[i].clone();
            }
        } else if args[i].starts_with("--") {
            config_args.push(args[i].clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
                i += 1;
            }
        } else if withdrawal_id_hex.is_none() {
            withdrawal_id_hex = Some(args[i].clone());
        }
        i += 1;
    }

    let withdrawal_id_hex = withdrawal_id_hex.ok_or("Withdrawal ID required")?;
    let id_bytes = hex::decode(&withdrawal_id_hex)
        .map_err(|e| format!("Invalid withdrawal ID hex: {}", e))?;
    if id_bytes.len() != 32 {
        return Err("Withdrawal ID must be 32 bytes".into());
    }
    let mut withdrawal_id = [0u8; 32];
    withdrawal_id.copy_from_slice(&id_bytes);

    let config = parse_config(&config_args)?;
    let node = Node::new(config).await?;

    println!("Cancelling withdrawal {}...", &withdrawal_id_hex[..16]);

    node.cancel_withdrawal(&withdrawal_id, reason)?;

    println!("Withdrawal cancelled!");
    println!("Funds have been unlocked and returned to the deposit.");

    Ok(())
}

/// List all withdrawals
async fn withdraw_list(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let config = parse_config(args)?;
    let node = Node::new(config).await?;

    let withdrawals = node.list_withdrawals();

    if withdrawals.is_empty() {
        println!("No withdrawals found.");
        return Ok(());
    }

    println!("Withdrawals ({} total):", withdrawals.len());
    println!();

    for (withdrawal, status) in withdrawals {
        let status_str = match &status {
            deposits_core::OnChainWithdrawalStatus::Locked { locked_at_block } => {
                format!("Locked at block {}", locked_at_block)
            }
            deposits_core::OnChainWithdrawalStatus::Broadcast { txid, broadcast_at_block } => {
                format!("Broadcast at block {} (txid: {})", broadcast_at_block, &txid[..16])
            }
            deposits_core::OnChainWithdrawalStatus::Completed { txid, confirmed_at_block, confirmations } => {
                format!("Completed at block {} ({} confs, txid: {})", confirmed_at_block, confirmations, &txid[..16])
            }
            deposits_core::OnChainWithdrawalStatus::Cancelled { cancelled_at_block, reason } => {
                format!("Cancelled at block {}: {}", cancelled_at_block, reason)
            }
        };

        println!("  Withdrawal: {}", hex::encode(&withdrawal.withdrawal_id[..8]));
        println!("    Status: {}", status_str);
        println!("    Deposit: {}", withdrawal.deposit_pubkey);
        println!("    Destination: {}", withdrawal.destination_address);
        println!("    Amount: {} sats + {} fee", withdrawal.amount_sats, withdrawal.fee_sats);
        if let Some(ref memo) = withdrawal.memo {
            println!("    Memo: {}", memo);
        }
        println!();
    }

    Ok(())
}
