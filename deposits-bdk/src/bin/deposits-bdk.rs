// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! deposits-bdk CLI
//!
//! A deposits protocol node using BDK for on-chain reserves and Nostr for messaging.

use bitcoin::secp256k1::{PublicKey, Secp256k1};
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
        "reserves" => reserves_command(&args[2..]).await?,
        "ledger" => ledger_command(&args[2..]).await?,
        "partner" => partner_command(&args[2..]).await?,
        "collateral" => collateral_command(&args[2..]).await?,
        "deposit" => deposit_command(&args[2..]).await?,
        "withdraw" => withdraw_command(&args[2..]).await?,
        "keygen" => keygen(),
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
    keygen          Generate a new secp256k1 keypair for deposits
    reserves        Manage reserves UTXOs (create, rotate, list)
    ledger          Manage ledgers (open, list)
    partner         Manage quorum members (request, add, join, list)
    collateral      Manage collateral pledges
    deposit         Manage deposit offers for on-chain funding
    withdraw        Manage on-chain withdrawals
    help            Show this help message

RESERVES SUBCOMMANDS:
    reserves create [amount_sats]
                    Create a new reserves UTXO (default: 100M sats / 1 BTC)
    reserves rotate <reserves_id>
                    Rotate reserves to quorum-based Taproot spending
    reserves list   List all reserves outputs

LEDGER SUBCOMMANDS:
    ledger open [enforcement_block]
                    Open a ledger backed by your reserves UTXO. Set enforcement_block to a
                    future block for bootstrap phase, or 0 for immediate enforcement.
    ledger list     List all ledgers
    ledger history [reserves_id]
                    Show hash chain history for a ledger (default: primary ledger)

PARTNER SUBCOMMANDS:
    partner request <pubkey>   Send quorum membership request
    partner add <reserves_id> <quorum_member_pubkey>
                    Add a quorum member to your ledger (records QuorumAddMember)
    partner join <our_reserves_id> <target_operator> <target_reserves_id> <expires_block>
                    Record that you joined another operator's quorum (records QuorumJoin)
    partner list               List all quorum members

COLLATERAL SUBCOMMANDS:
    collateral pledge <reserves_id> <deposit_secret> <amount_msats> <lock_blocks>
                    Pledge deposit balance as collateral backing for the operator.
                    lock_blocks is how many blocks from now until the lock expires.

DEPOSIT SUBCOMMANDS:
    deposit offer <reserves_id> <deposit_pubkey> <max_sats> <min_sats> <blocks_valid>
                    Create a signed deposit offer for on-chain funding
    deposit list    List all deposit offers
    deposit open <reserves_id> <deposit_pubkey>
                    Open a new deposit in a ledger
    deposit ls <reserves_id>
                    List all deposits in a ledger
    deposit credit <reserves_id> <deposit_pubkey> <amount_msats> <invoice_id>
                    Manually credit a deposit
    deposit check <offer_id>
                    Check if a deposit offer has been funded
    deposit complete <offer_id> <txid> <amount_sats>
                    Complete a funded deposit offer and credit the deposit

WITHDRAW SUBCOMMANDS:
    withdraw request <partner_id> <deposit_secret> <address> <amount_sats> <fee_sats>
                    Request withdrawal (generates nonce, signs, and locks in one step)
    withdraw lock <partner_id> <deposit_pubkey> <address> <amount_sats> <fee_sats> <nonce> <signature>
                    Lock funds for withdrawal (operator-side, requires pre-signed request)
    withdraw complete <partner_id> <withdrawal_id>
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
    {} ledger open 1000 --network regtest

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
        if let Some(addr) = node.wallet.get_reserves_address() {
            println!("Reserves address: {}", addr);
        }
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

/// Generate a new secp256k1 keypair for deposits
fn keygen() {
    use bitcoin::secp256k1::rand::rngs::OsRng;

    let secp = Secp256k1::new();
    let (secret_key, public_key) = secp.generate_keypair(&mut OsRng);

    // Output: secret_key_hex public_key_hex
    println!("{} {}", hex::encode(secret_key.secret_bytes()), public_key);
}

/// Handle reserves subcommands
async fn reserves_command(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.is_empty() {
        // Default behavior: create reserves (backwards compatible)
        return reserves_create(&[]).await;
    }

    match args[0].as_str() {
        "create" => reserves_create(&args[1..]).await,
        "rotate" => reserves_rotate(&args[1..]).await,
        "list" => reserves_list(&args[1..]).await,
        arg if !arg.starts_with("--") && arg.parse::<u64>().is_ok() => {
            // Legacy: direct amount argument (backwards compatible)
            reserves_create(args).await
        }
        _ => {
            // Could be config args for create (backwards compatible)
            reserves_create(args).await
        }
    }
}

/// Create a new reserves UTXO
async fn reserves_create(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
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

/// Rotate reserves to quorum-based Taproot spending
async fn reserves_rotate(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut reserves_id: Option<String> = None;
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
        } else if reserves_id.is_none() {
            reserves_id = Some(args[i].clone());
        }
        i += 1;
    }

    let config = parse_config(&config_args)?;
    let node = Node::new(config).await?;

    // Sync wallet first
    node.sync_wallet()?;

    // If no reserves_id provided, use the primary ledger
    let reserves_id = match reserves_id {
        Some(id) => id,
        None => {
            // Get the primary ledger's reserves_id
            match node.get_primary_ledger() {
                Some((rid, _)) => rid,
                None => return Err("No ledger found. Open a ledger first with 'ledger open'.".into()),
            }
        }
    };

    println!("Rotating reserves to quorum-based Taproot spending...");
    println!("  Ledger: {}", reserves_id);

    let result = node.rotate_reserves_to_quorum(&reserves_id)?;

    println!("\nReserves rotated successfully!");
    println!("  TXID: {}", result.txid);
    println!("  New Address: {}", result.new_address);
    println!("  Amount: {} sats", result.amount_sats);
    println!("  Quorum Members: {}", result.quorum_member_count);
    println!("  First Expiry Block: {}", result.first_expiry_block);
    println!("  Ledger Hash: {}", hex::encode(&result.ledger_hash[..8]));
    println!("\nSpending tiers:");
    println!("  Tier 0: Majority of quorum + operator (immediate)");
    println!("  Tier 1: Operator only (after block {})", result.first_expiry_block);
    println!("  Tier 2: Emergency recovery (extended timeout)");

    Ok(())
}

/// List all reserves outputs
async fn reserves_list(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let config = parse_config(args)?;
    let node = Node::new(config).await?;

    // Sync wallet first
    node.sync_wallet()?;

    let reserves = node.wallet.get_reserves();
    let taproot_reserves = node.wallet.get_taproot_reserves();

    if reserves.is_empty() && taproot_reserves.is_empty() {
        println!("No reserves outputs found.");
        return Ok(());
    }

    println!("=== Legacy Reserves (P2WSH) ===");
    for info in &reserves {
        println!("  Outpoint: {}", info.outpoint);
        println!("    Amount: {} sats", info.amount);
        println!("    Operator: {}", info.operator);
        println!("    Partners: {}", info.partners.len());
        println!("    Timeout: block {}", info.timeout_height);
        println!("    Confirmed: {}", info.confirmed);
        println!();
    }

    println!("=== Taproot Reserves (Quorum-based) ===");
    for info in &taproot_reserves {
        println!("  Outpoint: {}", info.outpoint);
        println!("    Amount: {} sats", info.amount);
        println!("    Operator: {}", info.operator);
        println!("    Quorum Members: {}", info.quorum_members.len());
        for (i, member) in info.quorum_members.iter().enumerate() {
            println!("      {}: {}", i + 1, member);
        }
        println!("    First Expiry: block {}", info.first_expiry_block);
        println!("    Ledger Hash: {}", hex::encode(&info.ledger_hash[..8]));
        println!("    Confirmed: {}", info.confirmed);

        // Dump Taproot details
        println!();
        println!("    === Taproot Script Details ===");
        println!("    Internal Key: {}", info.taproot_output.internal_key());
        if let Some(merkle_root) = info.taproot_output.merkle_root() {
            println!("    Merkle Root: {}", merkle_root);
        }
        println!("    ScriptPubKey: {}", hex::encode(info.taproot_output.script_pubkey().as_bytes()));
        println!();
        println!("    === Spending Tiers (Script Leaves) ===");
        for (i, tier) in info.taproot_output.config.tiers.iter().enumerate() {
            println!("    Tier {}: {} (threshold={}, tie_breaker={}, timelock={})",
                i, tier.description, tier.threshold, tier.requires_tie_breaker, tier.timelock_blocks);

            // Get the control block for this tier
            if let Some(cb) = info.taproot_output.control_block_for_tier(i) {
                println!("      Control Block: {}", hex::encode(cb.serialize()));
            }
        }
        println!();

        // Dump the full script tree
        println!("    === Full Script Tree (for decoding) ===");
        // Rebuild and show each leaf script
        let voter_set = deposits_core::VoterSet::new(info.operator, info.quorum_members.clone());
        for (i, tier) in info.taproot_output.config.tiers.iter().enumerate() {
            let builder = deposits_core::TapscriptReservesBuilder::new(
                voter_set.clone(),
                info.taproot_output.config.clone(),
                node.wallet.network(),
                info.ledger_hash,
            );
            if let Ok(script) = builder.build_threshold_leaf(tier) {
                println!("    Leaf {}: {}", i, hex::encode(script.as_bytes()));
            }
        }
        println!();
    }

    Ok(())
}

/// Handle ledger subcommands
async fn ledger_command(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.is_empty() {
        eprintln!("Usage: deposits-bdk ledger <open|list|history> [args...]");
        return Ok(());
    }

    match args[0].as_str() {
        "open" => ledger_open(&args[1..]).await,
        "list" => ledger_list(&args[1..]).await,
        "history" => ledger_history(&args[1..]).await,
        cmd => {
            eprintln!("Unknown ledger subcommand: {}", cmd);
            eprintln!("Usage: deposits-bdk ledger <open|list|history> [args...]");
            Ok(())
        }
    }
}

/// Open a new ledger backed by our reserves UTXO
async fn ledger_open(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    // Parse positional arguments: [enforcement_block]
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
        } else {
            // First positional argument - enforcement block
            enforcement_block = args[i]
                .parse()
                .map_err(|_| format!("Invalid enforcement block: {}", args[i]))?;
        }
        i += 1;
    }

    let config = parse_config(&config_args)?;
    let node = Node::new(config).await?;

    // Sync wallet to get current state
    node.sync_wallet()?;

    // Check if we have reserves
    let reserves_balance = node.reserves_balance()?;
    if reserves_balance == 0 {
        return Err("No reserves found. Create reserves first with 'reserves' command.".into());
    }

    println!("Opening ledger backed by reserves UTXO");
    println!("  Our node ID: {}", node.node_id);
    println!("  Reserves: {} sats", reserves_balance);
    println!("  Collateral enforcement block: {}", enforcement_block);

    // Create the ledger
    let ledger = node.open_ledger(enforcement_block)?;

    println!("\nLedger opened successfully!");
    println!("  Operator: {}", ledger.state.operator_key);
    println!("  Partner: {}", ledger.state.reserves_key);
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
        println!("    Reserves: {}", partner);
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

/// Show ledger history (hash chain updates)
async fn ledger_history(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    // Parse positional argument: [reserves_id] (optional)
    let mut reserves_id_str: Option<String> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with("--") {
            config_args.push(args[i].clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
                i += 1;
            }
        } else if reserves_id_str.is_none() {
            reserves_id_str = Some(args[i].clone());
        }
        i += 1;
    }

    let config = parse_config(&config_args)?;
    let node = Node::new(config).await?;

    // Get the ledger - either by reserves_id or primary ledger
    let (reserves_id, ledger) = if let Some(id_str) = reserves_id_str {
        // Look up ledger by reserves_id (Bitcoin address string)
        node.get_ledger_by_reserves_id(&id_str)
            .ok_or_else(|| format!("Ledger not found for reserves_id: {}", id_str))?
    } else {
        // No argument - get primary ledger
        node.get_primary_ledger()
            .ok_or("No ledger found. Run 'ledger open' first.")?
    };

    // Print header with short ID
    let id_str = reserves_id.to_string();
    let short_id = &id_str[..8.min(id_str.len())];

    println!("Updates for ledger {}...:", short_id);

    if ledger.history.is_empty() {
        println!("  (no updates)");
        return Ok(());
    }

    // Print each update in the history
    for update in &ledger.history {
        let seq = update.sequence_number;
        let prev = &update.previous_hash;
        let curr = &update.current_hash;

        // Determine signature status
        let has_partner_sig = update.partner_signature != [0u8; 64];
        let has_operator_sig = update.operator_signature != [0u8; 64];
        let sig_status = if has_partner_sig && has_operator_sig {
            "✓"
        } else if has_partner_sig || has_operator_sig {
            "·"
        } else {
            " "
        };

        // Lock status (both signatures = committed)
        let lock_status = if has_partner_sig && has_operator_sig {
            "🔒"
        } else {
            "  "
        };

        // Get operation name and details
        let (op_name, op_details) = format_operation(update.message_type, &update.message);

        println!("{:>4} ↑{:<6} [{:08x}~{:08x}] {}{} {}{}",
            seq,
            update.block_height,
            u32::from_be_bytes([prev[0], prev[1], prev[2], prev[3]]),
            u32::from_be_bytes([curr[0], curr[1], curr[2], curr[3]]),
            sig_status,
            lock_status,
            op_name,
            if op_details.is_empty() { String::new() } else { format!("  {}", op_details) }
        );
    }

    Ok(())
}

/// Format an operation type and extract details from the message
fn format_operation(msg_type: u16, message: &[u8]) -> (String, String) {
    use deposits_core::messages::consts::*;
    use deposits_core::messages::LedgerOperation;
    use deposits_core::tlv::TlvDecode;

    let name = match msg_type {
        LEDGER_OPEN_REQUEST => "LedgerOpen",
        HANDSHAKE => "Handshake",
        RESERVES_ADD_OUTPUT => "ReservesAdd",
        RESERVES_REMOVE_OUTPUT => "ReservesRemove",
        RESERVES_INCREASE => "ReservesIncrease",
        RESERVES_DECREASE => "ReservesDecrease",
        RESERVES_ROTATE => "ReservesRotate",
        RESERVES_UPDATE_OUTPUT => "ReservesUpdate",
        COLLATERAL_INCREASE => "CollateralIncrease",
        COLLATERAL_DECREASE => "CollateralDecrease",
        COLLATERAL_STATUS => "CollateralStatus",
        COLLATERAL_ATTESTATION => "CollateralAttestation",
        QUORUM_ADD_MEMBER => "QuorumAddMember",
        QUORUM_REMOVE_MEMBER => "QuorumRemoveMember",
        COLLATERAL_LOCK => "CollateralLock",
        QUORUM_JOIN => "QuorumJoin",
        DEPOSIT_OPEN => "DepositOpen",
        DEPOSIT_CLOSE => "DepositClose",
        DEPOSIT_UPDATE => "DepositUpdate",
        SENDING_LOCK_PAYMENT => "InvoiceLock",
        SENDING_FAIL_PAYMENT => "InvoiceFail",
        SENDING_FULFILL_PAYMENT => "InvoiceFulfill",
        RECEIVING_CREDIT_PAYMENT => "InvoiceCredit",
        RECEIVING_COSIGN_INVOICE => "CosignInvoice",
        ONCHAIN_CREDIT => "OnchainCredit",
        ONCHAIN_LOCK => "OnchainLock",
        ONCHAIN_FAIL => "OnchainFail",
        ONCHAIN_FULFILL => "OnchainFulfill",
        MAINTENANCE_FEE_COLLECT => "FeeCollect",
        LEDGER_CLOSE => "LedgerClose",
        _ => "Unknown",
    }.to_string();

    // Try to decode the operation using TLV and extract details
    let details = if !message.is_empty() {
        if let Ok(op) = LedgerOperation::tlv_decode(message) {
            match op {
                LedgerOperation::ReservesIncrease { new_amount } |
                LedgerOperation::ReservesDecrease { new_amount } => {
                    format!("{} sat", new_amount)
                }
                LedgerOperation::DepositOpen { pubkey, .. } |
                LedgerOperation::DepositClose { pubkey, .. } => {
                    let pk_bytes = pubkey.serialize();
                    format!("pk:{:02x}{:02x}{:02x}{:02x}", pk_bytes[0], pk_bytes[1], pk_bytes[2], pk_bytes[3])
                }
                LedgerOperation::QuorumAddMember { quorum_member, .. } |
                LedgerOperation::QuorumRemoveMember { quorum_member, .. } => {
                    let pk_bytes = quorum_member.serialize();
                    format!("member:{:02x}{:02x}{:02x}{:02x}", pk_bytes[0], pk_bytes[1], pk_bytes[2], pk_bytes[3])
                }
                LedgerOperation::CollateralAttestation { collateral_operator, amount, lock_until_block, .. } => {
                    let pk_bytes = collateral_operator.serialize();
                    format!("from:{:02x}{:02x}{:02x}{:02x}  amt:{} msat  until_block:{}",
                        pk_bytes[0], pk_bytes[1], pk_bytes[2], pk_bytes[3], amount, lock_until_block)
                }
                LedgerOperation::CollateralLock { deposit_pubkey, amount, lock_until_block, .. } => {
                    let pk_bytes = deposit_pubkey.serialize();
                    format!("pk:{:02x}{:02x}{:02x}{:02x}  amt:{} msat  until_block:{}",
                        pk_bytes[0], pk_bytes[1], pk_bytes[2], pk_bytes[3], amount, lock_until_block)
                }
                LedgerOperation::LedgerOpen { ledger_address, .. } => {
                    // Shorten address for display (first 8 and last 6 chars)
                    let addr_short = if ledger_address.len() > 20 {
                        format!("{}..{}", &ledger_address[..8], &ledger_address[ledger_address.len()-6..])
                    } else {
                        ledger_address.clone()
                    };
                    format!("addr:{}", addr_short)
                }
                LedgerOperation::OnchainCredit { deposit_pubkey, amount, funding_address, .. } => {
                    let pk_bytes = deposit_pubkey.serialize();
                    // Shorten address for display (first 8 and last 6 chars)
                    let addr_short = if funding_address.len() > 20 {
                        format!("{}..{}", &funding_address[..8], &funding_address[funding_address.len()-6..])
                    } else {
                        funding_address.clone()
                    };
                    format!("pk:{:02x}{:02x}{:02x}{:02x}  amt:{} msat  addr:{}",
                        pk_bytes[0], pk_bytes[1], pk_bytes[2], pk_bytes[3], amount, addr_short)
                }
                LedgerOperation::OnchainLock { deposit_pubkey, amount, destination_address, withdrawal_id, .. } => {
                    let pk_bytes = deposit_pubkey.serialize();
                    let addr_short = if destination_address.len() > 20 {
                        format!("{}..{}", &destination_address[..8], &destination_address[destination_address.len()-6..])
                    } else {
                        destination_address.clone()
                    };
                    format!("pk:{:02x}{:02x}{:02x}{:02x}  amt:{} msat  wdrl:{}  addr:{}",
                        pk_bytes[0], pk_bytes[1], pk_bytes[2], pk_bytes[3], amount,
                        hex::encode(&withdrawal_id[..4]), addr_short)
                }
                LedgerOperation::OnchainFail { deposit_pubkey, withdrawal_id, .. } => {
                    let pk_bytes = deposit_pubkey.serialize();
                    format!("pk:{:02x}{:02x}{:02x}{:02x}  wdrl:{}",
                        pk_bytes[0], pk_bytes[1], pk_bytes[2], pk_bytes[3],
                        hex::encode(&withdrawal_id[..4]))
                }
                LedgerOperation::OnchainFulfill { deposit_pubkey, withdrawal_id, amount, txid, .. } => {
                    let pk_bytes = deposit_pubkey.serialize();
                    format!("pk:{:02x}{:02x}{:02x}{:02x}  amt:{} msat  wdrl:{}  txn:{}",
                        pk_bytes[0], pk_bytes[1], pk_bytes[2], pk_bytes[3],
                        amount,
                        hex::encode(&withdrawal_id[..4]),
                        hex::encode(&txid[..4]))
                }
                LedgerOperation::InvoiceCredit { deposit_pubkey, amount, .. } => {
                    let pk_bytes = deposit_pubkey.serialize();
                    format!("pk:{:02x}{:02x}{:02x}{:02x}  amt:{} msat",
                        pk_bytes[0], pk_bytes[1], pk_bytes[2], pk_bytes[3], amount)
                }
                LedgerOperation::InvoiceLock { pubkey, amount, .. } => {
                    let pk_bytes = pubkey.serialize();
                    format!("pk:{:02x}{:02x}{:02x}{:02x}  amt:{} msat",
                        pk_bytes[0], pk_bytes[1], pk_bytes[2], pk_bytes[3], amount)
                }
                _ => String::new(),
            }
        } else {
            String::new()
        }
    } else {
        String::new()
    };

    (name, details)
}

/// Handle partner subcommands
async fn partner_command(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.is_empty() {
        eprintln!("Usage: deposits-bdk partner <request|add|join|list> [args...]");
        return Ok(());
    }

    match args[0].as_str() {
        "request" => partner_request(&args[1..]).await,
        "add" => partner_add(&args[1..]).await,
        "join" => partner_join(&args[1..]).await,
        "list" => partner_list(&args[1..]).await,
        cmd => {
            eprintln!("Unknown partner subcommand: {}", cmd);
            eprintln!("Usage: deposits-bdk partner <request|add|join|list> [args...]");
            Ok(())
        }
    }
}

/// Request a peer to be a quorum member
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

    println!("Requesting quorum membership with: {}", peer_pubkey);

    // Send membership request via Nostr
    node.request_partner(peer_pubkey).await?;

    println!("Membership request sent!");
    println!("  The peer will need to accept the request to establish the membership.");

    Ok(())
}

/// Add a quorum member to our ledger
/// Usage: partner add <reserves_id> <quorum_member_pubkey>
async fn partner_add(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut reserves_id: Option<String> = None;
    let mut quorum_member_str: Option<String> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with("--") {
            config_args.push(args[i].clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
                i += 1;
            }
        } else if reserves_id.is_none() {
            reserves_id = Some(args[i].clone());
        } else if quorum_member_str.is_none() {
            quorum_member_str = Some(args[i].clone());
        }
        i += 1;
    }

    let reserves_id = reserves_id.ok_or("Reserves ID required")?;
    let quorum_member_str = quorum_member_str.ok_or("Quorum member pubkey required")?;
    let quorum_member = PublicKey::from_str(&quorum_member_str)
        .map_err(|e| format!("Invalid quorum member pubkey: {}", e))?;

    let config = parse_config(&config_args)?;
    let node = Node::new(config).await?;

    println!("Adding quorum member {} to ledger {}...", quorum_member, reserves_id);

    // For testing, use a placeholder signature (in production this would come from the member)
    let placeholder_sig = [0u8; 64];

    node.add_quorum_member(&reserves_id, quorum_member, placeholder_sig)?;

    println!("Quorum member added!");
    println!("  Member: {}", quorum_member);
    println!("  Ledger: {}", reserves_id);

    Ok(())
}

/// Record that we have joined another operator's quorum
/// Usage: partner join <our_reserves_id> <target_operator> <target_reserves_id> <expires_block>
async fn partner_join(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut our_reserves_id: Option<String> = None;
    let mut target_operator_str: Option<String> = None;
    let mut target_reserves_id: Option<String> = None;
    let mut expires_block: Option<u32> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with("--") {
            config_args.push(args[i].clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
                i += 1;
            }
        } else if our_reserves_id.is_none() {
            our_reserves_id = Some(args[i].clone());
        } else if target_operator_str.is_none() {
            target_operator_str = Some(args[i].clone());
        } else if target_reserves_id.is_none() {
            target_reserves_id = Some(args[i].clone());
        } else if expires_block.is_none() {
            expires_block = Some(args[i].parse()
                .map_err(|_| "Invalid expires_block")?);
        }
        i += 1;
    }

    let our_reserves_id = our_reserves_id.ok_or("Our reserves ID required")?;
    let target_operator_str = target_operator_str.ok_or("Target operator pubkey required")?;
    let target_reserves_id = target_reserves_id.ok_or("Target reserves ID required")?;
    let expires_block = expires_block.ok_or("Expires block required")?;

    let target_operator = PublicKey::from_str(&target_operator_str)
        .map_err(|e| format!("Invalid target operator pubkey: {}", e))?;

    let config = parse_config(&config_args)?;
    let node = Node::new(config).await?;

    println!("Recording quorum join for operator {}...", target_operator);

    // For testing, use a placeholder signature
    let placeholder_sig = [0u8; 64];

    node.record_quorum_join(
        &our_reserves_id,
        target_operator,
        &target_reserves_id,
        expires_block,
        placeholder_sig,
    )?;

    println!("Quorum join recorded!");
    println!("  Target operator: {}", target_operator);
    println!("  Target ledger: {}", target_reserves_id);
    println!("  Expires at block: {}", expires_block);

    Ok(())
}

/// List quorum members
async fn partner_list(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let config = parse_config(args)?;
    let node = Node::new(config).await?;

    let partners = node.list_partners();

    if partners.is_empty() {
        println!("No quorum members found.");
        return Ok(());
    }

    println!("Quorum Members ({} total):", partners.len());
    for (pubkey, role) in partners {
        println!("  {} - {}", pubkey, role);
    }

    Ok(())
}

// ============================================================================
// Collateral Commands
// ============================================================================

/// Handle collateral subcommands
async fn collateral_command(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.is_empty() {
        eprintln!("Usage: deposits-bdk collateral <lock> [args...]");
        return Ok(());
    }

    match args[0].as_str() {
        "lock" | "pledge" => collateral_lock(&args[1..]).await,
        "record" => collateral_record(&args[1..]).await,
        cmd => {
            eprintln!("Unknown collateral subcommand: {}", cmd);
            eprintln!("Usage: deposits-bdk collateral <lock|record> [args...]");
            Ok(())
        }
    }
}

/// Lock deposit balance as collateral backing for the operator
/// Returns a signed attestation that the requesting operator can record on their ledger
async fn collateral_lock(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    // Parse positional arguments: <reserves_id> <deposit_secret> <amount_msats> <lock_blocks> [requesting_operator]
    let mut reserves_id: Option<String> = None;
    let mut deposit_secret_hex: Option<String> = None;
    let mut amount_msats: Option<u64> = None;
    let mut lock_blocks: Option<u32> = None;
    let mut requesting_operator_hex: Option<String> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with("--") {
            config_args.push(args[i].clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
                i += 1;
            }
        } else if reserves_id.is_none() {
            reserves_id = Some(args[i].clone());
        } else if deposit_secret_hex.is_none() {
            deposit_secret_hex = Some(args[i].clone());
        } else if amount_msats.is_none() {
            amount_msats = Some(args[i].parse().map_err(|_| "Invalid amount_msats")?);
        } else if lock_blocks.is_none() {
            lock_blocks = Some(args[i].parse().map_err(|_| "Invalid lock_blocks")?);
        } else if requesting_operator_hex.is_none() {
            requesting_operator_hex = Some(args[i].clone());
        }
        i += 1;
    }

    let reserves_id = reserves_id.ok_or("reserves_id required")?;
    let deposit_secret_hex = deposit_secret_hex.ok_or("deposit_secret required")?;
    let amount_msats = amount_msats.ok_or("amount_msats required")?;
    let lock_blocks = lock_blocks.ok_or("lock_blocks required")?;

    // Parse the deposit secret
    let secret_bytes = hex::decode(&deposit_secret_hex)
        .map_err(|e| format!("Invalid deposit secret hex: {}", e))?;
    let deposit_secret = bitcoin::secp256k1::SecretKey::from_slice(&secret_bytes)
        .map_err(|e| format!("Invalid deposit secret: {}", e))?;

    // Derive the deposit pubkey from the secret
    let secp = Secp256k1::new();
    let deposit_pubkey = PublicKey::from_secret_key(&secp, &deposit_secret);

    let config = parse_config(&config_args)?;
    let node = Node::new(config).await?;

    // Get current block height and compute lock_until_block
    let current_block = node.wallet.get_block_height()?;
    let lock_until_block = current_block + lock_blocks;

    // Parse requesting operator (defaults to self if not specified)
    let requesting_operator = if let Some(hex) = requesting_operator_hex {
        PublicKey::from_str(&hex).map_err(|e| format!("Invalid requesting_operator: {}", e))?
    } else {
        node.node_id
    };

    println!("Creating collateral lock...");
    println!("  Reserves ID: {}", reserves_id);
    println!("  Deposit: {}", deposit_pubkey);
    println!("  Amount: {} msats", amount_msats);
    println!("  Lock until block: {} (current: {}, +{} blocks)", lock_until_block, current_block, lock_blocks);
    println!("  Requesting operator: {}", requesting_operator);

    let attestation = node.lock_collateral(
        &reserves_id,
        deposit_pubkey,
        &deposit_secret,
        amount_msats,
        lock_until_block,
        requesting_operator,
    )?;

    println!("\nCollateral lock created!");
    println!("  Total locked: {} msats", attestation.amount);
    println!("  Lock expires: block {}", attestation.lock_until_block);
    println!("  Attestation for: {}", attestation.quorum_member);

    // Output the attestation as JSON for the requesting operator to use
    let attestation_json = serde_json::to_string(&attestation)?;
    println!("\nAttestation (record on requesting operator's ledger):");
    println!("ATTESTATION_JSON:{}", attestation_json);

    Ok(())
}

/// Record a received CollateralAttestation on our own ledger
async fn collateral_record(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    // Parse positional arguments: <reserves_id> <attestation_json>
    let mut reserves_id: Option<String> = None;
    let mut attestation_json: Option<String> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with("--") {
            config_args.push(args[i].clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
                i += 1;
            }
        } else if reserves_id.is_none() {
            reserves_id = Some(args[i].clone());
        } else if attestation_json.is_none() {
            // Take just this arg as the JSON (should be a single quoted string from shell)
            attestation_json = Some(args[i].clone());
        }
        i += 1;
    }

    let reserves_id = reserves_id.ok_or("reserves_id required")?;
    let attestation_json = attestation_json.ok_or("attestation_json required")?;

    // Parse the attestation
    let attestation: deposits_core::CollateralAttestationMsg = serde_json::from_str(&attestation_json)
        .map_err(|e| format!("Invalid attestation JSON: {}", e))?;

    let config = parse_config(&config_args)?;
    let node = Node::new(config).await?;

    println!("Recording collateral attestation...");
    println!("  Reserves ID: {}", reserves_id);
    println!("  From operator: {}", attestation.operator);
    println!("  Amount: {} msats", attestation.amount);
    println!("  Lock until: block {}", attestation.lock_until_block);

    node.record_collateral_attestation(&reserves_id, attestation.clone())?;

    println!("\nCollateral attestation recorded!");
    println!("  Operator: {}", attestation.operator);
    println!("  Amount: {} msats", attestation.amount);

    Ok(())
}

// ============================================================================
// Deposit Offer Commands
// ============================================================================

/// Handle deposit subcommands
async fn deposit_command(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.is_empty() {
        eprintln!("Usage: deposits-bdk deposit <offer|list|open|ls|credit|check|complete> [args...]");
        return Ok(());
    }

    match args[0].as_str() {
        "offer" => deposit_offer(&args[1..]).await,
        "list" => deposit_list(&args[1..]).await,
        "open" => deposit_open(&args[1..]).await,
        "ls" => deposit_ls(&args[1..]).await,
        "credit" => deposit_credit(&args[1..]).await,
        "check" => deposit_check(&args[1..]).await,
        "complete" => deposit_complete(&args[1..]).await,
        cmd => {
            eprintln!("Unknown deposit subcommand: {}", cmd);
            eprintln!("Usage: deposits-bdk deposit <offer|list|open|ls|credit|check|complete> [args...]");
            Ok(())
        }
    }
}

/// Create a deposit offer for on-chain funding
async fn deposit_offer(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    // Parse positional arguments:
    // <reserves_id> <deposit_pubkey> <max_sats> <min_sats> <blocks_valid>
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
        eprintln!("Usage: deposits-bdk deposit offer <reserves_id> <deposit_pubkey> <max_sats> <min_sats> <blocks_valid> [options]");
        eprintln!("\nExample:");
        eprintln!("  deposits-bdk deposit offer 02abc...partner 02def...deposit 1000000 10000 144");
        eprintln!("\nThis creates a signed offer committing to credit the deposit");
        eprintln!("with on-chain funds sent to a new address, up to max_sats,");
        eprintln!("with minimum min_sats, valid for blocks_valid blocks.");
        return Ok(());
    }

    let reserves_id = &positional[0];
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
    println!("  Reserves ID: {}", reserves_id);
    println!("  Deposit: {}", deposit_pubkey);
    println!("  Max amount: {} sats", max_sats);
    println!("  Min amount: {} sats", min_sats);
    println!("  Valid for: {} blocks", blocks_valid);

    // Create the offer
    let offer = node.create_deposit_offer(
        reserves_id,
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
        println!("    Reserves: {}", offer.reserves_id);
        println!("    Deposit: {}", offer.deposit_pubkey);
        println!();
    }

    Ok(())
}

/// Open a new deposit in a ledger
async fn deposit_open(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    // Parse positional arguments: <reserves_id> <deposit_pubkey>
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
        eprintln!("Usage: deposits-bdk deposit open <reserves_id> <deposit_pubkey> [options]");
        eprintln!("\nExample:");
        eprintln!("  deposits-bdk deposit open 02abc...partner 02def...deposit");
        eprintln!("\nThis opens a new deposit in the ledger with the given partner.");
        return Ok(());
    }

    let reserves_id = &positional[0];
    let deposit_pubkey = PublicKey::from_str(&positional[1])
        .map_err(|e| format!("Invalid deposit pubkey: {}", e))?;

    let config = parse_config(&config_args)?;
    let node = Node::new(config).await?;

    println!("Opening deposit...");
    println!("  Reserves ID: {}", reserves_id);
    println!("  Deposit pubkey: {}", deposit_pubkey);

    let deposit = node.open_deposit(reserves_id, deposit_pubkey, None)?;

    println!("\nDeposit opened!");
    println!("  Pubkey: {}", deposit.pubkey);
    println!("  Balance: {} msats", deposit.balance);

    Ok(())
}

/// List deposits in a specific ledger
async fn deposit_ls(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    // Parse positional arguments: <reserves_id>
    let mut reserves_id_str: Option<String> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with("--") {
            config_args.push(args[i].clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
                i += 1;
            }
        } else if reserves_id_str.is_none() {
            reserves_id_str = Some(args[i].clone());
        }
        i += 1;
    }

    let reserves_id = reserves_id_str.ok_or("Reserves ID required")?;

    let config = parse_config(&config_args)?;
    let node = Node::new(config).await?;

    let deposits = node.list_deposits(&reserves_id);

    if deposits.is_empty() {
        println!("No deposits found in ledger with reserves {}", reserves_id);
        return Ok(());
    }

    println!("Deposits in ledger with {} ({} total):", reserves_id, deposits.len());
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
    // Parse positional arguments: <reserves_id> <deposit_pubkey> <amount_msats> <invoice_id>
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
        eprintln!("Usage: deposits-bdk deposit credit <reserves_id> <deposit_pubkey> <amount_msats> <invoice_id> [options]");
        eprintln!("\nExample:");
        eprintln!("  deposits-bdk deposit credit 02abc...partner 02def...deposit 1000000 inv123");
        eprintln!("\nThis credits the deposit with the specified amount.");
        return Ok(());
    }

    let reserves_id = &positional[0];
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
    println!("  Reserves ID: {}", reserves_id);
    println!("  Deposit: {}", deposit_pubkey);
    println!("  Amount: {} msats ({} sats)", amount_msats, amount_msats / 1000);
    println!("  Invoice ID: {}", invoice_id);

    let new_balance = node.credit_deposit(
        reserves_id,
        deposit_pubkey,
        amount_msats,
        payment_hash,
        invoice_id,
    )?;

    println!("\nDeposit credited!");
    println!("  New balance: {} msats ({} sats)", new_balance, new_balance / 1000);

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
        eprintln!("Usage: deposits-bdk withdraw <request|lock|complete|cancel|list> [args...]");
        return Ok(());
    }

    match args[0].as_str() {
        "request" => withdraw_request(&args[1..]).await,
        "lock" => withdraw_lock(&args[1..]).await,
        "complete" => withdraw_complete(&args[1..]).await,
        "cancel" => withdraw_cancel(&args[1..]).await,
        "list" => withdraw_list(&args[1..]).await,
        cmd => {
            eprintln!("Unknown withdraw subcommand: {}", cmd);
            eprintln!("Usage: deposits-bdk withdraw <request|lock|complete|cancel|list> [args...]");
            Ok(())
        }
    }
}

/// Request a withdrawal (for depositors) - generates nonce and signature, then locks
///
/// This combines nonce generation, signing, and locking into one step for convenience.
/// In production, the depositor would sign on their own device and send nonce+signature to operator.
async fn withdraw_request(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use bitcoin::secp256k1::SecretKey;

    // Parse positional arguments:
    // <partner_id> <deposit_secret> <address> <amount_sats> <fee_sats>
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
        eprintln!("Usage: deposits-bdk withdraw request <reserves_id> <deposit_secret_hex> <address> <amount_sats> <fee_sats> [--memo <text>] [options]");
        eprintln!("\nThis command generates a nonce, signs the withdrawal request, and locks the funds.");
        return Ok(());
    }

    let reserves_id = &positional[0];
    let secret_hex = &positional[1];
    let destination_address = positional[2].clone();
    let amount_sats: u64 = positional[3]
        .parse()
        .map_err(|_| format!("Invalid amount_sats: {}", positional[3]))?;
    let fee_sats: u64 = positional[4]
        .parse()
        .map_err(|_| format!("Invalid fee_sats: {}", positional[4]))?;

    // Parse secret key
    let secret_bytes = hex::decode(secret_hex)
        .map_err(|e| format!("Invalid secret hex: {}", e))?;
    if secret_bytes.len() != 32 {
        return Err("Secret key must be 32 bytes".into());
    }
    let secret_key = SecretKey::from_slice(&secret_bytes)
        .map_err(|e| format!("Invalid secret key: {}", e))?;

    // Derive public key
    let secp = Secp256k1::new();
    let deposit_pubkey = PublicKey::from_secret_key(&secp, &secret_key);

    // Generate random nonce
    use bitcoin::secp256k1::rand::rngs::OsRng;
    use bitcoin::secp256k1::rand::RngCore;
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);

    // Create signature
    let signature = deposits_core::create_withdrawal_signature(
        &secret_key,
        &nonce,
        &deposit_pubkey,
        &destination_address,
        amount_sats,
        fee_sats,
    ).map_err(|e| format!("Failed to create signature: {:?}", e))?;

    let config = parse_config(&config_args)?;
    let node = Node::new(config).await?;

    // Sync wallet
    node.sync_wallet()?;

    println!("Requesting withdrawal...");
    println!("  Deposit: {}", deposit_pubkey);
    println!("  Destination: {}", destination_address);
    println!("  Amount: {} sats", amount_sats);
    println!("  Fee: {} sats", fee_sats);
    if let Some(ref m) = memo {
        println!("  Memo: {}", m);
    }

    // Lock the withdrawal
    let result = node.lock_withdrawal(
        reserves_id,
        deposit_pubkey,
        destination_address,
        amount_sats,
        fee_sats,
        nonce,
        signature,
        memo,
    )?;

    println!("\nWithdrawal locked!");
    println!("  Withdrawal ID: {}", hex::encode(&result.withdrawal.withdrawal_id));
    println!("  Nonce: {}", hex::encode(&result.withdrawal.nonce[..8]));
    println!("  Total debit: {} sats", result.withdrawal.total_debit());
    println!("  Previous balance: {} msats", result.previous_balance_msats);
    println!("  New balance: {} msats", result.new_balance_msats);
    println!("\nThe withdrawal can now be completed with:");
    println!("  deposits-bdk withdraw complete {} {}", reserves_id, hex::encode(&result.withdrawal.withdrawal_id));

    Ok(())
}

/// Lock funds for an on-chain withdrawal (operator-side, requires pre-signed request)
async fn withdraw_lock(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    // Parse positional arguments:
    // <deposit_pubkey> <address> <amount_sats> <fee_sats> <nonce_hex> <signature_hex>
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

    if positional.len() < 7 {
        eprintln!("Usage: deposits-bdk withdraw lock <reserves_id> <deposit_pubkey> <address> <amount_sats> <fee_sats> <nonce_hex> <signature_hex> [--memo <text>] [options]");
        eprintln!("\nThe nonce and signature must be provided by the depositor.");
        eprintln!("For testing, use 'withdraw request' which handles signing automatically.");
        return Ok(());
    }

    let reserves_id = &positional[0];
    let deposit_pubkey = PublicKey::from_str(&positional[1])
        .map_err(|e| format!("Invalid deposit pubkey: {}", e))?;
    let destination_address = positional[2].clone();
    let amount_sats: u64 = positional[3]
        .parse()
        .map_err(|_| format!("Invalid amount_sats: {}", positional[3]))?;
    let fee_sats: u64 = positional[4]
        .parse()
        .map_err(|_| format!("Invalid fee_sats: {}", positional[4]))?;
    let nonce_hex = &positional[5];
    let signature_hex = &positional[6];

    // Parse nonce
    let nonce_bytes = hex::decode(nonce_hex)
        .map_err(|e| format!("Invalid nonce hex: {}", e))?;
    if nonce_bytes.len() != 32 {
        return Err("Nonce must be 32 bytes".into());
    }
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&nonce_bytes);

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
    println!("  Reserves ID: {}", reserves_id);
    println!("  Deposit: {}", deposit_pubkey);
    println!("  Destination: {}", destination_address);
    println!("  Amount: {} sats", amount_sats);
    println!("  Fee: {} sats", fee_sats);
    if let Some(ref m) = memo {
        println!("  Memo: {}", m);
    }

    // Lock the withdrawal
    let result = node.lock_withdrawal(
        reserves_id,
        deposit_pubkey,
        destination_address,
        amount_sats,
        fee_sats,
        nonce,
        signature,
        memo,
    )?;

    println!("\nWithdrawal locked!");
    println!("  Withdrawal ID: {}", hex::encode(&result.withdrawal.withdrawal_id));
    println!("  Nonce: {}", hex::encode(&result.withdrawal.nonce[..8]));
    println!("  Total debit: {} sats", result.withdrawal.total_debit());
    println!("  Previous balance: {} msats", result.previous_balance_msats);
    println!("  New balance: {} msats", result.new_balance_msats);
    println!("\nThe withdrawal can now be completed with:");
    println!("  deposits-bdk withdraw complete {} {}", positional[0], hex::encode(&result.withdrawal.withdrawal_id));

    Ok(())
}

/// Complete a withdrawal by broadcasting the transaction
async fn withdraw_complete(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
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
        eprintln!("Usage: deposits-bdk withdraw complete <reserves_id> <withdrawal_id> [options]");
        return Ok(());
    }

    let reserves_id = &positional[0];
    let withdrawal_id_hex = &positional[1];
    let id_bytes = hex::decode(withdrawal_id_hex)
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

    let result = node.complete_withdrawal(reserves_id, &withdrawal_id)?;

    println!("\nWithdrawal completed!");
    println!("  Transaction ID: {}", result.txid);
    println!("  Amount: {} sats", result.amount_sats);
    println!("  Fee: {} sats", result.fee_sats);
    println!("  Final balance: {} msats", result.final_balance_msats);
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
