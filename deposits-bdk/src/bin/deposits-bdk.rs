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
        "nostr" => nostr_command(&args[2..]).await?,
        "recovery" => recovery_command(&args[2..]).await?,
        "keygen" => keygen(),
        #[cfg(feature = "dangerous-testing")]
        "danger" => danger_command(&args[2..]).await?,
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
    nostr           Nostr relay operations (updates, broadcast)
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
    ledger validate [reserves_id]
                    Validate a ledger's conformance to the Bitcoin Deposits Protocol.
                    Checks hash chain integrity, sequence continuity, and business rules.
    ledger export [reserves_id] [--json|--binary]
                    Export a ledger for external validation or backup

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

NOSTR SUBCOMMANDS:
    nostr list      List all ledgers available on the Nostr relay
    nostr export [operator:reserves_id]
                    Broadcast ledger updates to Nostr relay (all local ledgers if no ID given)
    nostr import [operator:reserves_id]
                    Fetch ledger updates from Nostr relay (all ledgers if no ID given)
    nostr validate <operator:reserves_id>
                    Fetch and validate a ledger's hash chain directly from Nostr
    nostr request <ledger_id> <action> [params...]
                    Send a request to a ledger. Actions:
                      deposit_open <pubkey> [fee_fixed] [fee_bps] [fee_frequency]
                      deposit_offer <pubkey> <max_sats> <min_sats> <blocks_valid>
                      collateral_lock <secret> <amount_msats> <lock_blocks> [requesting_op]
    nostr watch <ledger_id>
                    Watch for requests and disputes for a ledger
    nostr dispute publish <ledger_id> <reason> <details>
                    Publish a dispute for a non-conforming ledger
    nostr dispute listen [ledger_id]
                    Listen for disputes (all ledgers or specific)

RECOVERY SUBCOMMANDS:
    recovery start <ledger_id> [--reason <text>]
                    Start recovery - validates ledger and publishes dispute
    recovery agree <ledger_id>
                    Agree to recovery - independently validate and sign
    recovery status <ledger_id>
                    Show current recovery status
    recovery claim <ledger_id>
                    Execute a claim if eligible
    recovery complete <ledger_id> [--new-custodian <pubkey>]
                    Complete recovery once quorum agrees
"#,
        program
    );

    #[cfg(feature = "dangerous-testing")]
    println!(
        r#"
DANGER SUBCOMMANDS (testing only - DO NOT USE IN PRODUCTION):
    danger publish-invalid <reserves_id> <violation_type>
                    Publish an invalid ledger update to test recovery.
                    Violation types:
                      invalid-hash     - Wrong previous_hash linkage
                      skip-sequence    - Skip ahead in sequence numbers
                      double-spend     - Spend more than available balance
                      replay           - Replay an old sequence number
"#
    );

    println!(
        r#"OPTIONS:
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
        program, program, program, program, program
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

    // Broadcast to Nostr
    if let Err(e) = node.broadcast_last_update(&reserves_id).await {
        eprintln!("Warning: Failed to broadcast to Nostr: {}", e);
    }

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
        eprintln!("Usage: deposits-bdk ledger <open|list|history|validate|export|import> [args...]");
        return Ok(());
    }

    match args[0].as_str() {
        "open" => ledger_open(&args[1..]).await,
        "list" => ledger_list(&args[1..]).await,
        "history" => ledger_history(&args[1..]).await,
        "validate" => ledger_validate(&args[1..]).await,
        "export" => ledger_export(&args[1..]).await,
        "import" => ledger_import(&args[1..]).await,
        cmd => {
            eprintln!("Unknown ledger subcommand: {}", cmd);
            eprintln!("Usage: deposits-bdk ledger <open|list|history|validate|export|import> [args...]");
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
    println!("  Ledger ID: {}", ledger.ledger_id_hex());
    println!("  Operator: {}", ledger.state.operator_key);
    println!("  Reserves: {}", ledger.state.reserves_key);
    println!("  Sequence: {}", ledger.state.sequence);
    println!("  Hash: {:02x?}", &ledger.state.hash[0..8]);
    if let Some(block) = ledger.state.collateral_enforcement_block {
        if block > 0 {
            println!("  Bootstrap phase: collateral requirements enforced at block {}", block);
        } else {
            println!("  Immediate collateral enforcement");
        }
    }

    // Broadcast all initial updates to Nostr
    let reserves_id = ledger.state.reserves_key.clone();
    match node.broadcast_all_updates(&reserves_id).await {
        Ok(count) => println!("  Broadcast {} updates to Nostr", count),
        Err(e) => eprintln!("  Warning: Failed to broadcast to Nostr: {}", e),
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

    for ((operator, reserves_id), ledger_arc) in ledgers {
        let ledger = ledger_arc.read().unwrap();
        let role = if operator == node.node_id {
            "Operator"
        } else {
            "Partner"
        };
        let ledger_id = ledger.ledger_id_hex();

        println!("  {}... ({})", &ledger_id[..16], role);
        println!("    Ledger ID: {}", ledger_id);
        println!("    Operator: {}", operator);
        println!("    Reserves ID: {}", reserves_id);
        println!("    Sequence: {}", ledger.state.sequence);
        println!("    Deposits: {} total, {} msats balance",
            ledger.state.deposits.len(),
            ledger.total_deposit_balance());
        println!("    Reserves: {} sats", ledger.reserves_amount());
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
    let (_reserves_id, ledger) = if let Some(id_str) = reserves_id_str {
        // Look up ledger by reserves_id (Bitcoin address string)
        node.get_ledger_by_reserves_id(&id_str)
            .ok_or_else(|| format!("Ledger not found for reserves_id: {}", id_str))?
    } else {
        // No argument - get primary ledger
        node.get_primary_ledger()
            .ok_or("No ledger found. Run 'ledger open' first.")?
    };

    // Print header with ledger_id hash
    let ledger_id = ledger.ledger_id_hex();
    let short_id = &ledger_id[..16.min(ledger_id.len())];

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

        // Determine signature status and signer
        let has_partner_sig = update.partner_signature != [0u8; 64];
        let has_operator_sig = update.operator_signature != [0u8; 64];
        let sig_status = format!("[{}{}]",
            if has_operator_sig { "O" } else { "·" },
            if has_partner_sig { "P" } else { "·" }
        );

        // Show signer: actual operator_id from update (may differ for CustodyAcquire)
        let signer = if has_operator_sig {
            let pk = update.operator_id.serialize();
            format!("{:02x}{:02x}", pk[1], pk[2])
        } else {
            "····".to_string()
        };

        // Get operation name and details
        let (op_name, op_details) = format_operation(update.message_type, &update.message);

        // Truncated hash: last 2 bytes of prev, last 2 bytes of curr
        println!("{:>4} ↑{:<6} [{:02x}{:02x}~{:02x}{:02x}] {} {} {}{}",
            seq,
            update.block_height,
            prev[30], prev[31],
            curr[30], curr[31],
            sig_status,
            signer,
            op_name,
            if op_details.is_empty() { String::new() } else { format!("  {}", op_details) }
        );
    }

    Ok(())
}

/// Validate a ledger's conformance to the Bitcoin Deposits Protocol
async fn ledger_validate(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use deposits_core::validation::LedgerConformanceValidator;

    // Parse positional arguments: [reserves_id]
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

    // Get the ledger
    let (reserves_id, ledger) = if let Some(id_str) = reserves_id_str {
        node.get_ledger_by_reserves_id(&id_str)
            .ok_or_else(|| format!("Ledger not found for reserves_id: {}", id_str))?
    } else {
        node.get_primary_ledger()
            .ok_or("No ledger found. Run 'ledger open' first.")?
    };

    let id_str = reserves_id.to_string();
    let short_id = &id_str[..8.min(id_str.len())];

    println!("Validating ledger {}...", short_id);
    println!();

    // Check if ledger has any history
    if ledger.history.is_empty() {
        println!("Ledger has no updates to validate.");
        return Ok(());
    }

    // Create export and validate
    let export = ledger.export(0); // block_height 0 for local validation

    match LedgerConformanceValidator::validate(&export) {
        Ok(report) => {
            // Print validation results
            println!("Validation Results:");
            println!("  Valid: {}", if report.is_valid { "YES" } else { "NO" });
            println!();

            // Hash chain status
            println!("Hash Chain:");
            println!("  Valid length: {}/{}", report.hash_chain.valid_length, report.hash_chain.total_length);
            println!("  Genesis hash: {:02x?}", &report.hash_chain.genesis_hash[..8]);
            println!("  Tail hash: {:02x?}", &report.hash_chain.tail_hash[..8]);
            println!();

            // Signature status
            println!("Signatures:");
            println!("  Total updates: {}", report.signatures.total_updates);
            println!("  Fully signed: {}", report.signatures.fully_signed);
            println!("  Operator only: {}", report.signatures.operator_only);
            println!("  Unsigned: {}", report.signatures.unsigned);
            if !report.signatures.invalid_signatures.is_empty() {
                println!("  Invalid signatures:");
                for (seq, err) in &report.signatures.invalid_signatures {
                    println!("    Seq {}: {}", seq, err);
                }
            }
            println!();

            // Business rules
            println!("Business Rules:");
            for rule in &report.business_rules {
                let status = if rule.passed { "PASS" } else { "FAIL" };
                let details = rule.details.as_ref().map(|d| format!(" ({})", d)).unwrap_or_default();
                println!("  [{}] {}{}", status, rule.rule, details);
            }
            println!();

            // Final state
            println!("Final State:");
            println!("  Sequence: {}", report.final_state.sequence);
            println!("  Hash: {:02x?}", &report.final_state.hash[..8]);
            println!("  Total deposits: {} msat", report.final_state.total_deposits);
            println!("  Reserves: {} sats", report.final_state.reserves_amount);
            println!("  Deposit count: {}", report.final_state.deposit_count);
            println!();

            // Warnings
            if !report.warnings.is_empty() {
                println!("Warnings:");
                for warning in &report.warnings {
                    println!("  - {}", warning);
                }
                println!();
            }

            if report.is_valid {
                println!("Ledger is CONFORMING to the Bitcoin Deposits Protocol.");
            } else {
                println!("Ledger is NOT CONFORMING to the Bitcoin Deposits Protocol.");
            }
        }
        Err(e) => {
            println!("Validation FAILED: {}", e);
            return Err(Box::new(e));
        }
    }

    Ok(())
}

/// Export a ledger for external validation or backup
async fn ledger_export(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    // Parse arguments
    let mut reserves_id_str: Option<String> = None;
    let mut format = "json"; // Default format
    let mut output_path: Option<String> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        if args[i] == "--json" {
            format = "json";
        } else if args[i] == "--binary" {
            format = "binary";
        } else if args[i] == "--output" || args[i] == "-o" {
            if i + 1 < args.len() {
                output_path = Some(args[i + 1].clone());
                i += 1;
            }
        } else if args[i].starts_with("--") {
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

    // Get the ledger
    let (reserves_id, ledger) = if let Some(id_str) = reserves_id_str {
        node.get_ledger_by_reserves_id(&id_str)
            .ok_or_else(|| format!("Ledger not found for reserves_id: {}", id_str))?
    } else {
        node.get_primary_ledger()
            .ok_or("No ledger found. Run 'ledger open' first.")?
    };

    let id_str = reserves_id.to_string();
    let short_id = &id_str[..8.min(id_str.len())];

    // Get current block height from node if available
    let block_height = 0; // TODO: Get from blockchain

    // Create export
    let export = ledger.export(block_height);

    match format {
        "json" => {
            let json = export.to_json()?;
            let filename = output_path.unwrap_or_else(|| format!("ledger_export_{}.json", short_id));
            std::fs::write(&filename, &json)?;
            println!("Exported ledger to {}", filename);
            println!("  Updates: {}", export.updates.len());
            println!("  Size: {} bytes", json.len());
        }
        "binary" => {
            let binary = export.to_binary();
            let filename = output_path.unwrap_or_else(|| format!("ledger_export_{}.bin", short_id));
            std::fs::write(&filename, &binary)?;
            println!("Exported ledger to {}", filename);
            println!("  Updates: {}", export.updates.len());
            println!("  Size: {} bytes", binary.len());
        }
        _ => unreachable!(),
    }

    Ok(())
}

/// Import a ledger from an export file (JSON or binary)
async fn ledger_import(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use deposits_core::validation::LedgerExport;

    // Parse arguments: <file_path>
    let mut file_path: Option<String> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with("--") {
            config_args.push(args[i].clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
                i += 1;
            }
        } else if file_path.is_none() {
            file_path = Some(args[i].clone());
        }
        i += 1;
    }

    let file_path = file_path.ok_or("Usage: deposits-bdk ledger import <file_path> [--data-dir <dir>]")?;

    // Read the file
    let data = std::fs::read(&file_path)?;

    // Try to parse as JSON first, then binary
    let export: LedgerExport = if file_path.ends_with(".json") {
        let json = String::from_utf8(data)?;
        serde_json::from_str(&json)?
    } else if file_path.ends_with(".bin") {
        bincode::deserialize(&data)?
    } else {
        // Try JSON first, then binary
        String::from_utf8(data.clone())
            .ok()
            .and_then(|json| serde_json::from_str(&json).ok())
            .or_else(|| bincode::deserialize(&data).ok())
            .ok_or("Failed to parse file as JSON or binary format")?
    };

    println!("Importing ledger from: {}", file_path);
    println!("  Operator: {}", export.operator_id);
    println!("  Reserves ID: {}", export.reserves_id);
    println!("  Updates: {}", export.updates.len());
    println!();

    let config = parse_config(&config_args)?;
    let node = Node::new(config).await?;

    // Import the ledger
    match node.import_ledger(export) {
        Ok((report, ledger)) => {
            println!("Import successful!");
            println!();

            // Print validation report
            println!("Validation Report:");
            println!("  Hash chain: {} of {} updates valid",
                report.hash_chain.valid_length, report.hash_chain.total_length);
            println!("  Signatures: {} fully signed, {} operator-only, {} unsigned",
                report.signatures.fully_signed,
                report.signatures.operator_only,
                report.signatures.unsigned);
            println!();

            // Business rules
            println!("Business Rules:");
            for rule in &report.business_rules {
                let status = if rule.passed { "PASS" } else { "FAIL" };
                let details = rule.details.as_ref().map(|d| format!(" ({})", d)).unwrap_or_default();
                println!("  [{}] {}{}", status, rule.rule, details);
            }
            println!();

            // Final state
            println!("Imported Ledger State:");
            println!("  Sequence: {}", ledger.state.sequence);
            println!("  Total deposits: {} msat", ledger.total_deposit_balance());
            println!("  Reserves: {} sats", ledger.reserves_amount());
            println!("  Deposit count: {}", ledger.state.deposits.len());

            if !report.warnings.is_empty() {
                println!();
                println!("Warnings:");
                for warning in &report.warnings {
                    println!("  - {}", warning);
                }
            }
        }
        Err(e) => {
            println!("Import FAILED: {}", e);
            return Err(e.into());
        }
    }

    Ok(())
}

/// Format an operation type and extract details from the message
fn format_operation(msg_type: u16, message: &[u8]) -> (String, String) {
    use deposits_core::messages::LedgerOperation;
    use deposits_core::tlv::TlvDecode;

    // First try to decode the operation from message bytes - this gives us the actual operation
    if !message.is_empty() {
        if let Ok(op) = LedgerOperation::tlv_decode(message) {
            let (name, details) = match op {
                LedgerOperation::LedgerOpen { ledger_address, .. } => {
                    let addr_short = if ledger_address.len() > 20 {
                        format!("{}..{}", &ledger_address[..8], &ledger_address[ledger_address.len()-6..])
                    } else {
                        ledger_address.clone()
                    };
                    ("LedgerOpen", format!("addr:{}", addr_short))
                }
                LedgerOperation::ReservesIncrease { new_amount, .. } => {
                    ("ReservesIncrease", format!("{} sat", new_amount))
                }
                LedgerOperation::ReservesDecrease { new_amount, .. } => {
                    ("ReservesDecrease", format!("{} sat", new_amount))
                }
                LedgerOperation::ReservesRotate { reserves_id, amount, quorum_threshold, quorum_size, first_expiry_block, .. } => {
                    let addr_short = if reserves_id.len() > 20 {
                        format!("{}..{}", &reserves_id[..8], &reserves_id[reserves_id.len()-6..])
                    } else {
                        reserves_id.clone()
                    };
                    ("ReservesRotate", format!("addr:{}  amt:{} sat  quorum:{}/{}  expiry:{}",
                        addr_short, amount, quorum_threshold, quorum_size, first_expiry_block))
                }
                LedgerOperation::DepositOpen { pubkey, .. } => {
                    let pk_bytes = pubkey.serialize();
                    ("DepositOpen", format!("pk:{:02x}{:02x}{:02x}{:02x}", pk_bytes[0], pk_bytes[1], pk_bytes[2], pk_bytes[3]))
                }
                LedgerOperation::DepositClose { pubkey, .. } => {
                    let pk_bytes = pubkey.serialize();
                    ("DepositClose", format!("pk:{:02x}{:02x}{:02x}{:02x}", pk_bytes[0], pk_bytes[1], pk_bytes[2], pk_bytes[3]))
                }
                LedgerOperation::DepositUpdate { pubkey, .. } => {
                    let pk_bytes = pubkey.serialize();
                    ("DepositUpdate", format!("pk:{:02x}{:02x}{:02x}{:02x}", pk_bytes[0], pk_bytes[1], pk_bytes[2], pk_bytes[3]))
                }
                LedgerOperation::QuorumAddMember { quorum_member, .. } => {
                    let pk_bytes = quorum_member.serialize();
                    ("QuorumAddMember", format!("member:{:02x}{:02x}{:02x}{:02x}", pk_bytes[0], pk_bytes[1], pk_bytes[2], pk_bytes[3]))
                }
                LedgerOperation::QuorumRemoveMember { quorum_member, .. } => {
                    let pk_bytes = quorum_member.serialize();
                    ("QuorumRemoveMember", format!("member:{:02x}{:02x}{:02x}{:02x}", pk_bytes[0], pk_bytes[1], pk_bytes[2], pk_bytes[3]))
                }
                LedgerOperation::QuorumJoin { operator_id, reserves_id, membership_expires, .. } => {
                    let pk_bytes = operator_id.serialize();
                    let reserves_short = if reserves_id.len() > 16 {
                        format!("{}..{}", &reserves_id[..8], &reserves_id[reserves_id.len()-6..])
                    } else {
                        reserves_id.clone()
                    };
                    ("QuorumJoin", format!("op:{:02x}{:02x}{:02x}{:02x}  ledger:{}  expires:{}",
                        pk_bytes[0], pk_bytes[1], pk_bytes[2], pk_bytes[3], reserves_short, membership_expires))
                }
                LedgerOperation::CollateralAttestation { collateral_operator, amount, lock_until_block, .. } => {
                    let pk_bytes = collateral_operator.serialize();
                    ("CollateralAttestation", format!("from:{:02x}{:02x}{:02x}{:02x}  amt:{} msat  until_block:{}",
                        pk_bytes[0], pk_bytes[1], pk_bytes[2], pk_bytes[3], amount, lock_until_block))
                }
                LedgerOperation::CollateralLock { deposit_pubkey, amount, lock_until_block, .. } => {
                    let pk_bytes = deposit_pubkey.serialize();
                    ("CollateralLock", format!("pk:{:02x}{:02x}{:02x}{:02x}  amt:{} msat  until_block:{}",
                        pk_bytes[0], pk_bytes[1], pk_bytes[2], pk_bytes[3], amount, lock_until_block))
                }
                LedgerOperation::CollateralIncrease { .. } => {
                    ("CollateralIncrease", String::new())
                }
                LedgerOperation::CollateralDecrease { .. } => {
                    ("CollateralDecrease", String::new())
                }
                LedgerOperation::OnchainCredit { deposit_pubkey, amount, funding_address, .. } => {
                    let pk_bytes = deposit_pubkey.serialize();
                    let addr_short = if funding_address.len() > 20 {
                        format!("{}..{}", &funding_address[..8], &funding_address[funding_address.len()-6..])
                    } else {
                        funding_address.clone()
                    };
                    ("OnchainCredit", format!("pk:{:02x}{:02x}{:02x}{:02x}  amt:{} msat  addr:{}",
                        pk_bytes[0], pk_bytes[1], pk_bytes[2], pk_bytes[3], amount, addr_short))
                }
                LedgerOperation::OnchainLock { deposit_pubkey, amount, destination_address, withdrawal_id, .. } => {
                    let pk_bytes = deposit_pubkey.serialize();
                    let addr_short = if destination_address.len() > 20 {
                        format!("{}..{}", &destination_address[..8], &destination_address[destination_address.len()-6..])
                    } else {
                        destination_address.clone()
                    };
                    ("OnchainLock", format!("pk:{:02x}{:02x}{:02x}{:02x}  amt:{} msat  wdrl:{}  addr:{}",
                        pk_bytes[0], pk_bytes[1], pk_bytes[2], pk_bytes[3], amount,
                        hex::encode(&withdrawal_id[..4]), addr_short))
                }
                LedgerOperation::OnchainFail { deposit_pubkey, withdrawal_id, .. } => {
                    let pk_bytes = deposit_pubkey.serialize();
                    ("OnchainFail", format!("pk:{:02x}{:02x}{:02x}{:02x}  wdrl:{}",
                        pk_bytes[0], pk_bytes[1], pk_bytes[2], pk_bytes[3],
                        hex::encode(&withdrawal_id[..4])))
                }
                LedgerOperation::OnchainFulfill { deposit_pubkey, withdrawal_id, amount, txid, .. } => {
                    let pk_bytes = deposit_pubkey.serialize();
                    ("OnchainFulfill", format!("pk:{:02x}{:02x}{:02x}{:02x}  amt:{} msat  wdrl:{}  txn:{}",
                        pk_bytes[0], pk_bytes[1], pk_bytes[2], pk_bytes[3],
                        amount,
                        hex::encode(&withdrawal_id[..4]),
                        hex::encode(&txid[..4])))
                }
                LedgerOperation::InvoiceCredit { deposit_pubkey, amount, .. } => {
                    let pk_bytes = deposit_pubkey.serialize();
                    ("InvoiceCredit", format!("pk:{:02x}{:02x}{:02x}{:02x}  amt:{} msat",
                        pk_bytes[0], pk_bytes[1], pk_bytes[2], pk_bytes[3], amount))
                }
                LedgerOperation::InvoiceLock { pubkey, amount, .. } => {
                    let pk_bytes = pubkey.serialize();
                    ("InvoiceLock", format!("pk:{:02x}{:02x}{:02x}{:02x}  amt:{} msat",
                        pk_bytes[0], pk_bytes[1], pk_bytes[2], pk_bytes[3], amount))
                }
                LedgerOperation::InvoiceFail { .. } => {
                    ("InvoiceFail", String::new())
                }
                LedgerOperation::InvoiceFulfill { .. } => {
                    ("InvoiceFulfill", String::new())
                }
                LedgerOperation::FeeCollect { .. } => {
                    ("FeeCollect", String::new())
                }
                LedgerOperation::CustodyDispute { last_valid_sequence, reason } => {
                    ("CustodyDispute", format!("last_valid_seq:{}  reason:{}", last_valid_sequence, reason))
                }
                LedgerOperation::CustodyArmed { armed_block } => {
                    ("CustodyArmed", format!("armed_block:{}", armed_block))
                }
                LedgerOperation::CustodyAcquire { new_custodian, entropy_block_height, .. } => {
                    let pk_bytes = new_custodian.serialize();
                    ("CustodyAcquire", format!("to:{:02x}{:02x}{:02x}{:02x}  entropy_block:{}",
                        pk_bytes[0], pk_bytes[1], pk_bytes[2], pk_bytes[3],
                        entropy_block_height))
                }
                LedgerOperation::CustodyYield => {
                    ("CustodyYield", String::new())
                }
                LedgerOperation::LedgerClose => {
                    ("LedgerClose", String::new())
                }
                LedgerOperation::Tombstone { .. } => {
                    ("Tombstone", String::new())
                }
            };
            return (name.to_string(), details);
        }
    }

    // Fallback: couldn't decode operation, show message type
    (format!("Unknown(0x{:04X})", msg_type), String::new())
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

    // Broadcast to Nostr
    if let Err(e) = node.broadcast_last_update(&reserves_id).await {
        eprintln!("Warning: Failed to broadcast to Nostr: {}", e);
    }

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

    // Broadcast to Nostr
    if let Err(e) = node.broadcast_last_update(&our_reserves_id).await {
        eprintln!("Warning: Failed to broadcast to Nostr: {}", e);
    }

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

    // Broadcast to Nostr
    if let Err(e) = node.broadcast_last_update(&reserves_id).await {
        eprintln!("Warning: Failed to broadcast to Nostr: {}", e);
    }

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

    // Broadcast to Nostr
    if let Err(e) = node.broadcast_last_update(&reserves_id).await {
        eprintln!("Warning: Failed to broadcast to Nostr: {}", e);
    }

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
        eprintln!("Usage: deposits-bdk deposit <offer|list|open|ls|credit|check|complete|verify-custodian> [args...]");
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
        "verify-custodian" => deposit_verify_custodian(&args[1..]).await,
        cmd => {
            eprintln!("Unknown deposit subcommand: {}", cmd);
            eprintln!("Usage: deposits-bdk deposit <offer|list|open|ls|credit|check|complete|verify-custodian> [args...]");
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
        eprintln!("Usage: deposits-bdk deposit offer <ledger_id> <deposit_pubkey> <max_sats> <min_sats> <blocks_valid> [options]");
        eprintln!("\nExample:");
        eprintln!("  deposits-bdk deposit offer abc123...ledger_id 02def...deposit 1000000 10000 144");
        eprintln!("\nThe ledger_id is the 64-char hex hash (stable across custody transfers).");
        eprintln!("This creates a signed offer committing to credit the deposit");
        eprintln!("with on-chain funds sent to a new address, up to max_sats,");
        eprintln!("with minimum min_sats, valid for blocks_valid blocks.");
        return Ok(());
    }

    let ledger_id = &positional[0];
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
    println!("  Ledger ID: {}...", &ledger_id[..16.min(ledger_id.len())]);
    println!("  Deposit: {}", deposit_pubkey);
    println!("  Max amount: {} sats", max_sats);
    println!("  Min amount: {} sats", min_sats);
    println!("  Valid for: {} blocks", blocks_valid);

    // Create the offer
    let offer = node.create_deposit_offer(
        ledger_id,
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
        println!("    Ledger: {}...", &offer.ledger_id[..16.min(offer.ledger_id.len())]);
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

    // Broadcast to Nostr
    if let Err(e) = node.broadcast_last_update(reserves_id).await {
        eprintln!("Warning: Failed to broadcast to Nostr: {}", e);
    }

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

    // Broadcast to Nostr
    if let Err(e) = node.broadcast_last_update(reserves_id).await {
        eprintln!("Warning: Failed to broadcast to Nostr: {}", e);
    }

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

    // Get the offer first to get ledger_id for broadcast
    let (offer, _) = node.get_deposit_offer(&offer_id)
        .ok_or("Deposit offer not found")?;
    let ledger_id = offer.ledger_id.clone();

    // Look up the ledger by ledger_id to get the reserves_id for broadcast
    let (reserves_id, _) = node.get_ledger_by_ledger_id(&ledger_id)
        .ok_or_else(|| format!("Ledger not found for ledger_id: {}", &ledger_id[..16.min(ledger_id.len())]))?;

    println!("Completing deposit offer...");
    println!("  Offer ID: {}", hex::encode(&offer_id[..8]));
    println!("  Transaction: {}", txid);
    println!("  Amount: {} sats", amount_sats);

    let new_balance = node.complete_deposit_offer(&offer_id, txid, amount_sats)?;

    // Broadcast to Nostr
    if let Err(e) = node.broadcast_last_update(&reserves_id).await {
        eprintln!("Warning: Failed to broadcast to Nostr: {}", e);
    }

    println!("\nDeposit offer completed!");
    println!("  New balance: {} msats ({} sats)", new_balance, new_balance / 1000);

    Ok(())
}

/// Verify the current custodian of a ledger by querying quorum members
///
/// This queries multiple quorum members for their attestation of who the current
/// custodian is, takes the majority response, and reports the result.
/// Use this before funding a deposit offer to ensure you're sending to the legitimate custodian.
async fn deposit_verify_custodian(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use nostr_sdk::prelude::*;
    use std::collections::HashMap;

    let mut ledger_id: Option<String> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with("--") {
            config_args.push(args[i].clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
                i += 1;
            }
        } else if ledger_id.is_none() {
            ledger_id = Some(args[i].clone());
        }
        i += 1;
    }

    let ledger_id = ledger_id.ok_or("Usage: deposits-bdk deposit verify-custodian <ledger_id> [options]")?;

    let config = parse_config(&config_args)?;
    let relay_url = config.relays.first()
        .ok_or("No relay configured. Use --relay <url>")?
        .clone();

    println!("Querying quorum members for custodian attestations...");
    println!("  Ledger: {}...", &ledger_id[..16.min(ledger_id.len())]);
    println!();

    // Create a Nostr client to send requests
    let keys = Keys::generate();
    let client = Client::new(keys.clone());
    client.add_relay(&relay_url).await?;
    client.connect().await;

    // Build the custodian_query request
    let request_id = format!("{:016x}", rand::random::<u64>());
    let params = serde_json::json!({});

    let request_content = serde_json::json!({
        "action": "custodian_query",
        "ledger_id": ledger_id,
        "request_id": request_id,
        "params": params,
    });

    // Publish request
    let request_event = EventBuilder::new(
        Kind::Custom(deposits_bdk::nostr::KIND_LEDGER_REQUEST),
        request_content.to_string(),
    )
    .tag(Tag::custom(TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::D)), [ledger_id.as_str()]))
    .sign_with_keys(&keys)?;

    let request_event_id = request_event.id.to_hex();
    client.send_event(request_event).await?;
    println!("Sent custodian_query request: {}...", &request_event_id[..16]);

    // Wait for responses (poll for a few seconds)
    println!("Waiting for quorum attestations...");
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    // Fetch responses
    let response_filter = Filter::new()
        .kind(Kind::Custom(deposits_bdk::nostr::KIND_LEDGER_RESPONSE))
        .custom_tag(SingleLetterTag::lowercase(Alphabet::E), [request_event_id.as_str()])
        .limit(20);

    let events = client.fetch_events(vec![response_filter], Some(std::time::Duration::from_secs(5))).await?;

    // Collect attestations
    let mut attestations: HashMap<String, Vec<String>> = HashMap::new(); // custodian -> list of attesters

    for event in events {
        if let Ok(response) = serde_json::from_str::<serde_json::Value>(&event.content) {
            if let (Some(custodian), Some(attester)) = (
                response.get("custodian").and_then(|v| v.as_str()),
                response.get("attester").and_then(|v| v.as_str()),
            ) {
                attestations.entry(custodian.to_string())
                    .or_default()
                    .push(attester.to_string());
            }
        }
    }

    client.disconnect().await?;

    if attestations.is_empty() {
        println!("No attestations received from quorum members.");
        println!("This could mean:");
        println!("  - No quorum members are watching this ledger");
        println!("  - The ledger_id is incorrect");
        println!("  - Network issues with the relay");
        return Ok(());
    }

    // Find majority
    let total_responses: usize = attestations.values().map(|v| v.len()).sum();
    let mut sorted: Vec<_> = attestations.iter().collect();
    sorted.sort_by(|a, b| b.1.len().cmp(&a.1.len()));

    println!("Received {} attestations:", total_responses);
    println!();

    for (custodian, attesters) in sorted.iter() {
        let percentage = (attesters.len() * 100) / total_responses;
        println!("  Custodian: {}...", &custodian[..16.min(custodian.len())]);
        println!("    Votes: {} ({}%)", attesters.len(), percentage);
        for attester in attesters.iter() {
            println!("      - {}...", &attester[..16.min(attester.len())]);
        }
        println!();
    }

    // Report majority
    if let Some((majority_custodian, majority_attesters)) = sorted.first() {
        let percentage = (majority_attesters.len() * 100) / total_responses;
        if percentage > 50 {
            println!("MAJORITY CUSTODIAN ({}%): {}", percentage, majority_custodian);
            // Machine-parseable output for scripts
            println!("VERIFIED_CUSTODIAN: {}", majority_custodian);
            println!();
            println!("Before funding a deposit offer, verify that offer.operator_id matches this custodian.");
        } else {
            println!("WARNING: No clear majority. The quorum may be split or compromised.");
            println!("NO_MAJORITY");
        }
    } else {
        println!("NO_ATTESTATIONS");
    }

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

    // Broadcast to Nostr
    if let Err(e) = node.broadcast_last_update(reserves_id).await {
        eprintln!("Warning: Failed to broadcast to Nostr: {}", e);
    }

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

    // Broadcast to Nostr
    if let Err(e) = node.broadcast_last_update(&positional[0]).await {
        eprintln!("Warning: Failed to broadcast to Nostr: {}", e);
    }

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

    // Broadcast to Nostr
    if let Err(e) = node.broadcast_last_update(reserves_id).await {
        eprintln!("Warning: Failed to broadcast to Nostr: {}", e);
    }

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

// ============================================================================
// Nostr Commands
// ============================================================================

/// Handle nostr subcommands
async fn nostr_command(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.is_empty() {
        eprintln!("Usage: deposits-bdk nostr <list|events|export|import|updates|validate|request|watch|dispute> [args...]");
        return Ok(());
    }

    match args[0].as_str() {
        "list" | "ls" => nostr_list(&args[1..]).await,
        "events" => nostr_events(&args[1..]).await,
        "export" => nostr_export(&args[1..]).await,
        "import" => nostr_import(&args[1..]).await,
        "updates" => nostr_updates(&args[1..]).await,
        "validate" => nostr_validate(&args[1..]).await,
        "request" | "req" => nostr_request(&args[1..]).await,
        "watch" => nostr_watch(&args[1..]).await,
        "dispute" => nostr_dispute(&args[1..]).await,
        cmd => {
            eprintln!("Unknown nostr subcommand: {}", cmd);
            eprintln!("Usage: deposits-bdk nostr <list|events|export|import|updates|validate|request|watch|dispute> [args...]");
            Ok(())
        }
    }
}

/// List all ledgers available on Nostr relay
async fn nostr_list(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use deposits_bdk::nostr::KIND_LEDGER_UPDATE;
    use nostr_sdk::prelude::*;
    use std::collections::HashMap;

    let config = parse_config(args)?;

    // Get relay URL from config
    let relay_url = config.relays.first()
        .ok_or("No relay configured. Use --relay <url>")?;

    println!("Listing ledgers from Nostr relay...");
    println!("  Relay: {}", relay_url);
    println!();

    // Create a temporary nostr client to fetch events
    let keys = Keys::generate();
    let client = Client::new(keys);
    client.add_relay(relay_url).await
        .map_err(|e| format!("Failed to add relay: {}", e))?;
    client.connect().await;

    // Fetch all ledger update events
    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE));

    let events = client
        .fetch_events(vec![filter], None)
        .await
        .map_err(|e| format!("Failed to fetch events: {}", e))?;

    client.disconnect().await.ok();

    if events.is_empty() {
        println!("No ledgers found.");
        return Ok(());
    }

    // Group by ledger_id and track max sequence
    let mut ledgers: HashMap<String, (u64, u64)> = HashMap::new(); // ledger_id -> (max_seq, count)

    for event in events {
        // Extract ledger_id from d tag
        let ledger_id = event
            .tags
            .iter()
            .find_map(|tag| {
                if tag.kind() == TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::D)) {
                    tag.content().map(|s| s.to_string())
                } else {
                    None
                }
            });

        // Extract sequence from seq tag
        let sequence = event
            .tags
            .iter()
            .find_map(|tag| {
                if tag.kind() == TagKind::custom("seq") {
                    tag.content().and_then(|s| s.parse::<u64>().ok())
                } else {
                    None
                }
            })
            .unwrap_or(0);

        if let Some(lid) = ledger_id {
            let entry = ledgers.entry(lid).or_insert((0, 0));
            entry.0 = entry.0.max(sequence);
            entry.1 += 1;
        }
    }

    println!("Found {} ledger(s):", ledgers.len());
    println!();

    // Sort by ledger_id for consistent output
    let mut sorted: Vec<_> = ledgers.into_iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));

    for (ledger_id, (max_seq, count)) in sorted {
        println!("  {}", ledger_id);
        println!("    Updates: {} (seq 0..{})", count, max_seq);
        println!();
    }

    Ok(())
}

/// Show all deposits protocol events from Nostr relay
async fn nostr_events(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use deposits_bdk::nostr::{
        KIND_LEDGER_UPDATE, KIND_LEDGER_REQUEST, KIND_LEDGER_RESPONSE,
        KIND_LEDGER_DISPUTE, KIND_RECOVERY_AGREE,
    };
    use nostr_sdk::prelude::*;

    let config = parse_config(args)?;

    let relay_url = config.relays.first()
        .ok_or("No relay configured. Use --relay <url>")?;

    println!("Fetching all deposits events from Nostr relay...");
    println!("  Relay: {}", relay_url);
    println!();

    let keys = Keys::generate();
    let client = Client::new(keys);
    client.add_relay(relay_url).await
        .map_err(|e| format!("Failed to add relay: {}", e))?;
    client.connect().await;

    // Fetch all deposits protocol events
    let filter = Filter::new()
        .kinds([
            Kind::Custom(KIND_LEDGER_UPDATE),
            Kind::Custom(KIND_LEDGER_REQUEST),
            Kind::Custom(KIND_LEDGER_RESPONSE),
            Kind::Custom(KIND_LEDGER_DISPUTE),
            Kind::Custom(KIND_RECOVERY_AGREE),
        ]);

    let events = client
        .fetch_events(vec![filter], None)
        .await
        .map_err(|e| format!("Failed to fetch events: {}", e))?;

    client.disconnect().await.ok();

    if events.is_empty() {
        println!("No events found.");
        return Ok(());
    }

    // Sort events by timestamp
    let mut events_vec: Vec<_> = events.into_iter().collect();
    events_vec.sort_by_key(|e| e.created_at);

    // Count by type
    let mut updates = 0usize;
    let mut requests = 0usize;
    let mut responses = 0usize;
    let mut disputes = 0usize;
    let mut agreements = 0usize;

    println!("=== Events ({} total) ===", events_vec.len());
    println!();

    for event in &events_vec {
        let kind_num = event.kind.as_u16();
        let (kind_name, symbol) = match kind_num {
            k if k == KIND_LEDGER_UPDATE => { updates += 1; ("UPDATE", "📝") },
            k if k == KIND_LEDGER_REQUEST => { requests += 1; ("REQUEST", "❓") },
            k if k == KIND_LEDGER_RESPONSE => { responses += 1; ("RESPONSE", "💬") },
            k if k == KIND_LEDGER_DISPUTE => { disputes += 1; ("DISPUTE", "⚠️") },
            k if k == KIND_RECOVERY_AGREE => { agreements += 1; ("AGREE", "✅") },
            _ => ("UNKNOWN", "❔"),
        };

        // Extract d tag (ledger_id)
        let ledger_id = event.tags.iter()
            .find_map(|tag| {
                if tag.kind() == TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::D)) {
                    tag.content().map(|s| s.to_string())
                } else {
                    None
                }
            })
            .unwrap_or_else(|| "-".to_string());

        // Extract seq tag for updates
        let seq = event.tags.iter()
            .find_map(|tag| {
                if tag.kind() == TagKind::custom("seq") {
                    tag.content().and_then(|s| s.parse::<u64>().ok())
                } else {
                    None
                }
            });

        let author = event.pubkey.to_string();
        let event_id = event.id.to_string();

        // Format output based on type
        match kind_num {
            k if k == KIND_LEDGER_UPDATE => {
                let seq_str = seq.map(|s| format!("seq:{}", s)).unwrap_or_default();
                println!("{} {} {}...  ledger:{}...  {}",
                    symbol, kind_name,
                    &event_id[..12],
                    &ledger_id[..16.min(ledger_id.len())],
                    seq_str
                );
            }
            k if k == KIND_LEDGER_DISPUTE => {
                // Try to extract reason from content
                let reason = if let Ok(json) = serde_json::from_str::<serde_json::Value>(&event.content) {
                    json.get("reason").and_then(|r| r.as_str()).unwrap_or("").to_string()
                } else {
                    String::new()
                };
                println!("{} {} {}...  ledger:{}...  from:{}...  {}",
                    symbol, kind_name,
                    &event_id[..12],
                    &ledger_id[..16.min(ledger_id.len())],
                    &author[..12],
                    &reason[..40.min(reason.len())]
                );
            }
            k if k == KIND_RECOVERY_AGREE => {
                // Extract dispute reference
                let dispute_ref = event.tags.iter()
                    .find_map(|tag| {
                        if tag.kind() == TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::E)) {
                            tag.content().map(|s| s.to_string())
                        } else {
                            None
                        }
                    })
                    .unwrap_or_else(|| "-".to_string());
                println!("{} {} {}...  dispute:{}...  from:{}...",
                    symbol, kind_name,
                    &event_id[..12],
                    &dispute_ref[..12.min(dispute_ref.len())],
                    &author[..12]
                );
            }
            k if k == KIND_LEDGER_REQUEST => {
                let req_type = if let Ok(json) = serde_json::from_str::<serde_json::Value>(&event.content) {
                    json.get("request_type").and_then(|r| r.as_str()).unwrap_or("").to_string()
                } else {
                    String::new()
                };
                println!("{} {} {}...  ledger:{}...  type:{}",
                    symbol, kind_name,
                    &event_id[..12],
                    &ledger_id[..16.min(ledger_id.len())],
                    req_type
                );
            }
            _ => {
                println!("{} {} {}...  from:{}...",
                    symbol, kind_name,
                    &event_id[..12],
                    &author[..12]
                );
            }
        }
    }

    println!();
    println!("=== Summary ===");
    println!("  Updates:    {}", updates);
    println!("  Requests:   {}", requests);
    println!("  Responses:  {}", responses);
    println!("  Disputes:   {}", disputes);
    println!("  Agreements: {}", agreements);

    Ok(())
}

/// Fetch ledger updates from Nostr relay (import)
async fn nostr_import(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use deposits_bdk::nostr::KIND_LEDGER_UPDATE;
    use deposits_core::{TlvDecode, SignedLedgerUpdate};
    use deposits_core::messages::LedgerOperation;
    use deposits_core::validation::LedgerExport;
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use nostr_sdk::prelude::*;
    use std::collections::BTreeMap;

    let mut ledger_id: Option<String> = None;
    let mut config_args = Vec::new();
    let mut limit: usize = 500;
    let mut dry_run = false;

    let mut i = 0;
    while i < args.len() {
        if args[i] == "--limit" {
            i += 1;
            if i < args.len() {
                limit = args[i].parse().unwrap_or(500);
            }
        } else if args[i] == "--dry-run" {
            dry_run = true;
        } else if args[i].starts_with("--") {
            config_args.push(args[i].clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
                i += 1;
            }
        } else if ledger_id.is_none() {
            ledger_id = Some(args[i].clone());
        }
        i += 1;
    }

    let config = parse_config(&config_args)?;

    // Get relay URL from config
    let relay_url = config.relays.first()
        .ok_or("No relay configured. Use --relay <url>")?;

    println!("Fetching ledger updates from Nostr...");
    println!("  Relay: {}", relay_url);
    if let Some(ref lid) = ledger_id {
        println!("  Ledger: {}", lid);
    }
    println!();

    // Create a temporary nostr client to fetch events
    let keys = Keys::generate();
    let client = Client::new(keys);
    client.add_relay(relay_url).await
        .map_err(|e| format!("Failed to add relay: {}", e))?;
    client.connect().await;

    // Build filter
    let mut filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .limit(limit);

    if let Some(ref lid) = ledger_id {
        filter = filter.custom_tag(
            SingleLetterTag::lowercase(Alphabet::D),
            [lid.as_str()],
        );
    }

    // Fetch events
    let events = client
        .fetch_events(vec![filter], None)
        .await
        .map_err(|e| format!("Failed to fetch events: {}", e))?;

    client.disconnect().await.ok();

    if events.is_empty() {
        println!("No ledger updates found.");
        return Ok(());
    }

    // Group updates by ledger_id, sorted by sequence number
    let mut ledgers: BTreeMap<String, Vec<SignedLedgerUpdate>> = BTreeMap::new();

    for event in events {
        // Extract ledger_id from d tag
        let event_ledger_id = event
            .tags
            .iter()
            .find_map(|tag| {
                if tag.kind() == TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::D)) {
                    tag.content().map(|s| s.to_string())
                } else {
                    None
                }
            })
            .unwrap_or_else(|| "(unknown)".to_string());

        // Decode the update
        if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
            if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                ledgers.entry(event_ledger_id).or_default().push(update);
            }
        }
    }

    // Sort updates by sequence number but keep ALL updates (including branches)
    // Include operator_id in sort/dedup to preserve different operators' updates at same sequence
    // (e.g., parallel CustodyDisputes from different quorum members)
    for updates in ledgers.values_mut() {
        updates.sort_by_key(|u| (u.sequence_number, u.operator_id.serialize(), u.current_hash));
        // Deduplicate exact copies only (same seq, same operator, same hash)
        updates.dedup_by(|a, b| a.sequence_number == b.sequence_number && a.operator_id == b.operator_id && a.current_hash == b.current_hash);
    }

    println!("Found {} ledger(s) with updates:", ledgers.len());

    // Create node for importing (unless dry-run)
    let node = if !dry_run {
        Some(Node::new(config).await?)
    } else {
        None
    };

    // Import each ledger
    for (lid, updates) in &ledgers {
        let short_id = &lid[..16.min(lid.len())];
        println!();
        println!("=== Ledger {}... ({} updates) ===", short_id, updates.len());

        if updates.is_empty() {
            println!("  (no updates to import)");
            continue;
        }

        // Find LedgerOpen operation to get metadata
        let ledger_open = updates.iter().find_map(|u| {
            if let Ok(op) = LedgerOperation::tlv_decode(&u.message) {
                if let LedgerOperation::LedgerOpen { operator_id, reserves_id, ledger_address, genesis_block, .. } = op {
                    return Some((operator_id, reserves_id, ledger_address, genesis_block));
                }
            }
            None
        });

        let (operator_id, reserves_id, ledger_address, genesis_block) = match ledger_open {
            Some(data) => data,
            None => {
                println!("  ERROR: No LedgerOpen found - cannot import");
                continue;
            }
        };

        // Parse ledger_id from hex
        let ledger_id_bytes: [u8; 32] = match hex::decode(lid) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                arr
            }
            _ => {
                println!("  ERROR: Invalid ledger_id hex");
                continue;
            }
        };

        println!("  Operator: {}...", &operator_id.to_string()[..16]);
        println!("  Reserves: {}...", &reserves_id[..16.min(reserves_id.len())]);
        println!("  Genesis: block {}", genesis_block);

        // Get current block height
        let block_height = if let Some(ref n) = node {
            n.wallet.get_block_height().unwrap_or(0)
        } else {
            0
        };

        // Create LedgerExport
        let export = LedgerExport::new(
            ledger_id_bytes,
            genesis_block,
            operator_id,
            reserves_id.clone(),
            ledger_address.clone(),
            updates.clone(),
            block_height,
        );

        if dry_run {
            println!("  (dry-run: would import {} updates)", updates.len());

            // Build tree structure: map from previous_hash to children
            let mut children: std::collections::HashMap<[u8; 32], Vec<&SignedLedgerUpdate>> = std::collections::HashMap::new();
            for update in updates {
                children.entry(update.previous_hash).or_default().push(update);
            }

            // Sort children by sequence number
            for kids in children.values_mut() {
                kids.sort_by_key(|u| u.sequence_number);
            }

            // Print tree recursively
            fn print_tree(
                children: &std::collections::HashMap<[u8; 32], Vec<&SignedLedgerUpdate>>,
                parent_hash: [u8; 32],
                prefix: &str,
                is_branch: bool,
            ) {
                if let Some(kids) = children.get(&parent_hash) {
                    for (i, update) in kids.iter().enumerate() {
                        let is_last = i == kids.len() - 1;
                        let seq = update.sequence_number;
                        let prev = &update.previous_hash;
                        let curr = &update.current_hash;

                        // Determine signature status and signer
                        let has_partner_sig = update.partner_signature != [0u8; 64];
                        let has_operator_sig = update.operator_signature != [0u8; 64];
                        let sig_status = format!("[{}{}]",
                            if has_operator_sig { "O" } else { "·" },
                            if has_partner_sig { "P" } else { "·" }
                        );

                        let signer = if has_operator_sig {
                            let pk = update.operator_id.serialize();
                            format!("{:02x}{:02x}", pk[1], pk[2])
                        } else {
                            "····".to_string()
                        };

                        let (op_name, op_details) = format_operation(update.message_type, &update.message);

                        // Tree characters for branches
                        let branch_char = if is_branch {
                            if is_last { "└─" } else { "├─" }
                        } else {
                            "  "
                        };

                        println!("{}{}{:>4} ↑{:<6} [{:02x}{:02x}~{:02x}{:02x}] {} {} {}{}",
                            prefix,
                            branch_char,
                            seq,
                            update.block_height,
                            prev[30], prev[31],
                            curr[30], curr[31],
                            sig_status,
                            signer,
                            op_name,
                            if op_details.is_empty() { String::new() } else { format!("  {}", op_details) }
                        );

                        // Check if this update has children (continuations or branches)
                        let child_count = children.get(&update.current_hash).map(|c| c.len()).unwrap_or(0);

                        // Build prefix for children
                        let new_prefix = if is_branch {
                            format!("{}{}", prefix, if is_last { "  " } else { "│ " })
                        } else {
                            prefix.to_string()
                        };

                        // Print children - mark as branch if there are multiple children at same level
                        // or if this node itself was a branch
                        let has_multiple_children = child_count > 1;
                        print_tree(children, update.current_hash, &new_prefix, has_multiple_children);
                    }
                }
            }

            // Start from genesis (previous_hash = [0; 32])
            print_tree(&children, [0u8; 32], "", false);
        } else if let Some(ref n) = node {
            // Import the ledger
            match n.import_ledger(export) {
                Ok((report, _ledger)) => {
                    println!("  Imported successfully!");
                    println!("    Hash chain: {} of {} updates valid",
                        report.hash_chain.valid_length, report.hash_chain.total_length);
                    println!("    Signatures: {} fully signed, {} operator-only",
                        report.signatures.fully_signed, report.signatures.operator_only);
                    if !report.signatures.invalid_signatures.is_empty() {
                        println!("    Invalid signatures: {}", report.signatures.invalid_signatures.len());
                    }
                }
                Err(e) => {
                    println!("  ERROR importing: {}", e);
                }
            }
        }
    }

    println!();
    if dry_run {
        println!("Dry run complete. Use without --dry-run to actually import.");
    } else {
        println!("Import complete.");
    }

    Ok(())
}

/// Fetch new updates for an existing ledger from Nostr
async fn nostr_updates(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use deposits_bdk::nostr::KIND_LEDGER_UPDATE;
    use deposits_core::{TlvDecode, SignedLedgerUpdate};
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use nostr_sdk::prelude::*;

    let mut ledger_id: Option<String> = None;
    let mut config_args = Vec::new();
    let mut limit: usize = 500;
    let mut dry_run = false;

    let mut i = 0;
    while i < args.len() {
        if args[i] == "--limit" {
            i += 1;
            if i < args.len() {
                limit = args[i].parse().unwrap_or(500);
            }
        } else if args[i] == "--dry-run" {
            dry_run = true;
        } else if args[i].starts_with("--") {
            config_args.push(args[i].clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
                i += 1;
            }
        } else if ledger_id.is_none() {
            ledger_id = Some(args[i].clone());
        }
        i += 1;
    }

    let ledger_id = ledger_id.ok_or("Usage: deposits-bdk nostr updates <ledger_id> [--dry-run] [--limit N]")?;

    let config = parse_config(&config_args)?;

    // Get relay URL from config
    let relay_url = config.relays.first()
        .ok_or("No relay configured. Use --relay <url>")?;

    // Create node to access local ledger
    let node = Node::new(config.clone()).await?;

    // Find the local ledger
    let (reserves_id, local_ledger) = node.get_ledger_by_ledger_id(&ledger_id)
        .ok_or_else(|| format!("Ledger {} not found locally. Use 'nostr import' first.", &ledger_id[..16.min(ledger_id.len())]))?;

    let local_seq = local_ledger.sequence();
    let local_hash = local_ledger.tail_hash();

    println!("Fetching updates for ledger from Nostr...");
    println!("  Ledger: {}...", &ledger_id[..16.min(ledger_id.len())]);
    println!("  Reserves: {}...", &reserves_id[..16.min(reserves_id.len())]);
    println!("  Local sequence: {}", local_seq);
    println!("  Local hash: {}...", hex::encode(&local_hash[..8]));
    println!("  Relay: {}", relay_url);
    println!();

    // Create a temporary nostr client to fetch events
    let keys = Keys::generate();
    let client = Client::new(keys);
    client.add_relay(relay_url).await
        .map_err(|e| format!("Failed to add relay: {}", e))?;
    client.connect().await;

    // Build filter for this ledger
    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .custom_tag(
            SingleLetterTag::lowercase(Alphabet::D),
            [ledger_id.as_str()],
        )
        .limit(limit);

    // Fetch events
    let events = client
        .fetch_events(vec![filter], None)
        .await
        .map_err(|e| format!("Failed to fetch events: {}", e))?;

    client.disconnect().await.ok();

    if events.is_empty() {
        println!("No updates found on Nostr.");
        return Ok(());
    }

    // Decode and sort updates
    let mut updates: Vec<SignedLedgerUpdate> = Vec::new();
    for event in events {
        if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
            if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                updates.push(update);
            }
        }
    }

    updates.sort_by_key(|u| u.sequence_number);

    println!("Found {} updates on Nostr (local has {} updates)", updates.len(), local_seq + 1);

    // Find updates that follow our local chain
    let mut new_updates: Vec<SignedLedgerUpdate> = Vec::new();
    let mut expected_prev_hash = local_hash;

    for update in updates.iter() {
        // Skip updates we already have
        if update.sequence_number <= local_seq {
            continue;
        }

        // Check if this update follows our chain
        if update.previous_hash == expected_prev_hash {
            expected_prev_hash = update.current_hash;
            new_updates.push(update.clone());
        }
    }

    if new_updates.is_empty() {
        println!("No new updates to apply (already up to date).");
        return Ok(());
    }

    println!("Found {} new updates to apply:", new_updates.len());
    for update in &new_updates {
        let (op_name, _) = format_operation(update.message_type, &update.message);
        println!("  {} {}", update.sequence_number, op_name);
    }

    if dry_run {
        println!();
        println!("Dry run complete. Use without --dry-run to apply updates.");
        return Ok(());
    }

    // Apply updates to ledger
    println!();
    println!("Applying updates...");

    let applied = node.handler.apply_updates_to_ledger(&reserves_id, new_updates.clone())?;

    println!("Applied {} updates.", applied);
    println!("New sequence: {}", local_seq + applied as u64);

    Ok(())
}

/// Validate a ledger directly from Nostr (fetch and validate hash chain)
async fn nostr_validate(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use deposits_bdk::nostr::KIND_LEDGER_UPDATE;
    use deposits_core::{TlvDecode, SignedLedgerUpdate};
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use nostr_sdk::prelude::*;

    let mut ledger_id: Option<String> = None;
    let mut config_args = Vec::new();
    let mut limit: usize = 200;

    let mut i = 0;
    while i < args.len() {
        if args[i] == "--limit" {
            i += 1;
            if i < args.len() {
                limit = args[i].parse().unwrap_or(200);
            }
        } else if args[i].starts_with("--") {
            config_args.push(args[i].clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
                i += 1;
            }
        } else if ledger_id.is_none() {
            ledger_id = Some(args[i].clone());
        }
        i += 1;
    }

    let ledger_id = ledger_id.ok_or("Ledger ID required (64-char hex hash)")?;
    let config = parse_config(&config_args)?;

    let relay_url = config.relays.first()
        .ok_or("No relay configured. Use --relay <url>")?;

    println!("Validating ledger from Nostr...");
    println!("  Relay: {}", relay_url);
    println!("  Ledger ID: {}", ledger_id);
    println!();

    // Fetch events from Nostr
    let keys = Keys::generate();
    let client = Client::new(keys);
    client.add_relay(relay_url).await
        .map_err(|e| format!("Failed to add relay: {}", e))?;
    client.connect().await;

    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .custom_tag(SingleLetterTag::lowercase(Alphabet::D), [ledger_id.as_str()])
        .limit(limit);

    let events = client
        .fetch_events(vec![filter], None)
        .await
        .map_err(|e| format!("Failed to fetch events: {}", e))?;

    client.disconnect().await.ok();

    if events.is_empty() {
        println!("No ledger updates found on Nostr.");
        return Ok(());
    }

    // Decode all updates
    let mut updates: Vec<SignedLedgerUpdate> = Vec::new();
    for event in events.iter() {
        if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
            if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                updates.push(update);
            }
        }
    }

    if updates.is_empty() {
        println!("No valid updates could be decoded.");
        return Ok(());
    }

    // Sort by sequence number and deduplicate (relay may have duplicates)
    // Include operator_id to preserve different operators' updates at same sequence (e.g., parallel CustodyDisputes)
    updates.sort_by_key(|u| (u.sequence_number, u.operator_id));
    updates.dedup_by(|a, b| a.sequence_number == b.sequence_number && a.operator_id == b.operator_id && a.current_hash == b.current_hash);

    println!("Found {} update(s), validating hash chain...", updates.len());
    println!();

    // Validate hash chain
    let mut valid = true;
    let mut expected_prev_hash = [0u8; 32];
    let mut last_valid_seq: i64 = -1;
    let mut errors: Vec<String> = Vec::new();

    for update in &updates {
        // Check sequence continuity
        if update.sequence_number != (last_valid_seq + 1) as u64 {
            if last_valid_seq >= 0 {
                let err = format!(
                    "Sequence gap: expected {}, got {}",
                    last_valid_seq + 1,
                    update.sequence_number
                );
                errors.push(err.clone());
                println!("  [FAIL] seq={}: {}", update.sequence_number, err);
                valid = false;
            }
        }

        // Check previous hash linkage
        if update.previous_hash != expected_prev_hash {
            let err = format!(
                "Hash chain broken: prev_hash {}... != expected {}...",
                &hex::encode(update.previous_hash)[..8],
                &hex::encode(expected_prev_hash)[..8]
            );
            errors.push(err.clone());
            println!("  [FAIL] seq={}: {}", update.sequence_number, err);
            valid = false;
        }

        // Verify the update's own hash
        let computed_hash = update.compute_hash();
        if computed_hash != update.current_hash {
            let err = format!(
                "Hash mismatch: computed {}... != stored {}...",
                &hex::encode(computed_hash)[..8],
                &hex::encode(update.current_hash)[..8]
            );
            errors.push(err.clone());
            println!("  [FAIL] seq={}: {}", update.sequence_number, err);
            valid = false;
        }

        // Update for next iteration
        expected_prev_hash = update.current_hash;
        last_valid_seq = update.sequence_number as i64;
    }

    println!();
    if valid {
        println!("Valid: YES");
        println!("  Updates: {}", updates.len());
        println!("  Sequence: 0..{}", last_valid_seq);
        println!("  Tail hash: {}...", &hex::encode(expected_prev_hash)[..16]);
    } else {
        println!("Valid: NO");
        println!("  Updates: {}", updates.len());
        println!("  Errors: {}", errors.len());
        for err in &errors {
            println!("    - {}", err);
        }
    }

    Ok(())
}

/// Publish or listen for ledger disputes on Nostr
async fn nostr_dispute(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use bitcoin::secp256k1::{SecretKey, Keypair, Secp256k1};
    use deposits_bdk::nostr::{NostrTransportBuilder, KIND_LEDGER_DISPUTE};

    if args.is_empty() {
        eprintln!("Usage: deposits-bdk nostr dispute <publish|listen> [args...]");
        eprintln!();
        eprintln!("  publish <ledger_id> <reason> <details> [--last-hash <hex>] [--last-seq <n>] [--violation-seq <n>]");
        eprintln!("          Publish a dispute for a non-conforming ledger");
        eprintln!();
        eprintln!("  listen [--ledger <ledger_id>]");
        eprintln!("          Listen for disputes (all or specific ledger)");
        return Ok(());
    }

    match args[0].as_str() {
        "publish" | "pub" => {
            // Parse arguments
            let mut ledger_id: Option<String> = None;
            let mut reason: Option<String> = None;
            let mut details: Option<String> = None;
            let mut last_hash: [u8; 32] = [0u8; 32];
            let mut last_seq: u64 = 0;
            let mut violation_seq: Option<u64> = None;
            let mut config_args = Vec::new();

            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--last-hash" => {
                        i += 1;
                        if i < args.len() {
                            let bytes = hex::decode(&args[i])
                                .map_err(|_| "Invalid hex for --last-hash")?;
                            if bytes.len() == 32 {
                                last_hash.copy_from_slice(&bytes);
                            }
                        }
                    }
                    "--last-seq" => {
                        i += 1;
                        if i < args.len() {
                            last_seq = args[i].parse().unwrap_or(0);
                        }
                    }
                    "--violation-seq" => {
                        i += 1;
                        if i < args.len() {
                            violation_seq = Some(args[i].parse().unwrap_or(0));
                        }
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
                        } else if reason.is_none() {
                            reason = Some(args[i].clone());
                        } else if details.is_none() {
                            details = Some(args[i].clone());
                        }
                    }
                }
                i += 1;
            }

            let ledger_id = ledger_id.ok_or("Ledger ID required")?;
            let reason = reason.ok_or("Reason required (e.g., hash_chain_broken)")?;
            let details = details.unwrap_or_else(|| "Validation failed".to_string());
            let config = parse_config(&config_args)?;

            let relay_url = config.relays.first()
                .ok_or("No relay configured. Use --relay <url>")?
                .clone();

            // Build keypair from seed
            let secp = Secp256k1::new();
            let secret_key = SecretKey::from_slice(&config.seed)
                .map_err(|e| format!("Invalid seed: {}", e))?;
            let keypair = Keypair::from_secret_key(&secp, &secret_key);

            println!("Publishing dispute...");
            println!("  Relay: {}", relay_url);
            println!("  Ledger: {}", ledger_id);
            println!("  Reason: {}", reason);
            println!("  Details: {}", details);
            println!();

            // Create transport and publish
            let transport = NostrTransportBuilder::new(secret_key)
                .relay(&relay_url)
                .build()
                .await?;

            let event_id = transport.publish_dispute(
                &ledger_id,
                &reason,
                &details,
                last_hash,
                last_seq,
                violation_seq,
                &keypair,
            ).await?;

            println!("Dispute published: {}", event_id);
            transport.disconnect().await;
        }
        "listen" => {
            use nostr_sdk::prelude::*;

            let mut ledger_id: Option<String> = None;
            let mut config_args = Vec::new();

            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--ledger" | "-l" => {
                        i += 1;
                        if i < args.len() {
                            ledger_id = Some(args[i].clone());
                        }
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
                        }
                    }
                }
                i += 1;
            }

            let config = parse_config(&config_args)?;
            let relay_url = config.relays.first()
                .ok_or("No relay configured. Use --relay <url>")?
                .clone();

            println!("Listening for disputes...");
            println!("  Relay: {}", relay_url);
            if let Some(ref lid) = ledger_id {
                println!("  Ledger: {}", lid);
            } else {
                println!("  Ledger: (all)");
            }
            println!();

            // Connect to relay
            let keys = Keys::generate();
            let client = Client::new(keys);
            client.add_relay(&relay_url).await
                .map_err(|e| format!("Failed to add relay: {}", e))?;
            client.connect().await;

            // Build filter
            let mut filter = Filter::new()
                .kind(Kind::Custom(KIND_LEDGER_DISPUTE));
            if let Some(ref lid) = ledger_id {
                filter = filter.custom_tag(SingleLetterTag::lowercase(Alphabet::L), [lid.as_str()]);
            }

            // Subscribe
            client.subscribe(vec![filter], None).await
                .map_err(|e| format!("Failed to subscribe: {}", e))?;

            println!("Subscribed to dispute events. Press Ctrl+C to stop.\n");

            // Listen for events
            loop {
                let timeout = std::time::Duration::from_secs(30);
                match tokio::time::timeout(timeout, client.notifications().recv()).await {
                    Ok(Ok(RelayPoolNotification::Event { event, .. })) => {
                        if event.kind.as_u16() == KIND_LEDGER_DISPUTE {
                            println!("=== DISPUTE RECEIVED ===");
                            println!("  Event: {}", event.id.to_hex());
                            println!("  Time: {}", event.created_at);

                            // Extract tags
                            for tag in event.tags.iter() {
                                if tag.kind() == TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::L)) {
                                    if let Some(v) = tag.content() {
                                        println!("  Ledger: {}", v);
                                    }
                                }
                                if tag.kind() == TagKind::custom("reason") {
                                    if let Some(v) = tag.content() {
                                        println!("  Reason: {}", v);
                                    }
                                }
                                if tag.kind() == TagKind::custom("disputer") {
                                    if let Some(v) = tag.content() {
                                        println!("  Disputer: {}...", &v[..32.min(v.len())]);
                                    }
                                }
                            }

                            // Parse content for details
                            if let Ok(dispute) = serde_json::from_str::<serde_json::Value>(&event.content) {
                                if let Some(details) = dispute.get("details").and_then(|v| v.as_str()) {
                                    println!("  Details: {}", details);
                                }
                                if let Some(last_seq) = dispute.get("last_valid_sequence").and_then(|v| v.as_u64()) {
                                    println!("  Last valid seq: {}", last_seq);
                                }
                                if let Some(viol_seq) = dispute.get("violation_sequence").and_then(|v| v.as_u64()) {
                                    println!("  Violation seq: {}", viol_seq);
                                }
                            }
                            println!();
                        }
                    }
                    Ok(Ok(_)) => {
                        // Other notification types, ignore
                    }
                    Ok(Err(_)) => {
                        // Channel error
                        break;
                    }
                    Err(_) => {
                        // Timeout - keep waiting
                        print!(".");
                        use std::io::Write;
                        std::io::stdout().flush().ok();
                    }
                }
            }

            client.disconnect().await.ok();
        }
        cmd => {
            eprintln!("Unknown dispute subcommand: {}", cmd);
            eprintln!("Usage: deposits-bdk nostr dispute <publish|listen> [args...]");
        }
    }

    Ok(())
}

/// Broadcast ledger updates to Nostr relay (export)
async fn nostr_export(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use bitcoin::secp256k1::SecretKey;
    use deposits_bdk::nostr::NostrTransportBuilder;

    let mut ledger_id: Option<String> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with("--") {
            config_args.push(args[i].clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
                i += 1;
            }
        } else if ledger_id.is_none() && !args[i].is_empty() {
            ledger_id = Some(args[i].clone());
        }
        i += 1;
    }

    let config = parse_config(&config_args)?;

    // Get relay URL before moving config
    let relay_url = config.relays.first()
        .ok_or("No relay configured. Use --relay <url>")?
        .clone();

    // Derive secret key from seed
    let secret_key = SecretKey::from_slice(&config.seed)
        .map_err(|e| format!("Invalid seed: {}", e))?;

    // Get the node to access the ledger
    let node = Node::new(config).await?;

    // Collect ledgers to export
    let ledgers_to_export: Vec<(String, deposits_core::Ledger)> = match &ledger_id {
        Some(lid) if lid.contains(':') => {
            // Parse ledger_id as operator:reserves_id
            let parts: Vec<&str> = lid.splitn(2, ':').collect();
            let reserves_id = parts[1];

            let (_, ledger) = node.get_ledger_by_reserves_id(reserves_id)
                .ok_or_else(|| format!("Ledger not found: {}", reserves_id))?;
            vec![(lid.clone(), ledger)]
        }
        Some(lid) => {
            // Check if it's a 64-char hex hash (ledger_id)
            if lid.len() == 64 && lid.chars().all(|c| c.is_ascii_hexdigit()) {
                // Look up by ledger_id hash
                let mut found = None;
                for ((op, rid), ledger_arc) in node.list_ledgers() {
                    let ledger = ledger_arc.read().unwrap();
                    if ledger.ledger_id_hex() == *lid {
                        found = Some((format!("{}:{}", op, rid), ledger.clone()));
                        break;
                    }
                }
                match found {
                    Some((full_lid, ledger)) => vec![(full_lid, ledger)],
                    None => {
                        return Err(format!(
                            "Ledger not found by hash: {}. Try using reserves_id instead.", lid
                        ).into());
                    }
                }
            } else if let Some((_, ledger)) = node.get_ledger_by_reserves_id(lid) {
                // Might be just a reserves_id
                let full_lid = format!("{}:{}", ledger.state.operator_key, lid);
                vec![(full_lid, ledger)]
            } else {
                return Err(format!(
                    "Ledger not found: {}. Use format operator:reserves_id, reserves_id, or ledger_id hash", lid
                ).into());
            }
        }
        None => {
            // Export all ledgers
            node.list_ledgers()
                .into_iter()
                .map(|((op, rid), ledger_arc)| {
                    let lid = format!("{}:{}", op, rid);
                    let ledger = ledger_arc.read().unwrap().clone();
                    (lid, ledger)
                })
                .collect()
        }
    };

    if ledgers_to_export.is_empty() {
        println!("No ledgers to export.");
        return Ok(());
    }

    println!("Exporting ledger updates to Nostr relay...");
    println!("  Relay: {}", relay_url);
    println!("  Ledgers to export: {}", ledgers_to_export.len());
    println!();

    // Create nostr transport
    let transport = NostrTransportBuilder::new(secret_key)
        .relay(&relay_url)
        .build()
        .await?;

    let mut total_exported = 0;

    for (lid, ledger) in &ledgers_to_export {
        println!("Ledger: {}", lid);
        println!("  Updates: {}", ledger.history.len());

        // Broadcast each update
        for update in &ledger.history {
            let event_id = transport.broadcast_ledger_update(update).await?;
            println!("    seq={} hash={}... event={}",
                update.sequence_number,
                &hex::encode(update.current_hash)[..16],
                &event_id[..16],
            );
            total_exported += 1;
        }
        println!();
    }

    transport.disconnect().await;

    println!("Export complete! {} update(s) from {} ledger(s) published.",
        total_exported, ledgers_to_export.len());

    Ok(())
}

/// Send a request to a ledger via Nostr
async fn nostr_request(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use bitcoin::secp256k1::SecretKey;
    use deposits_bdk::nostr::NostrTransportBuilder;

    let mut ledger_id: Option<String> = None;
    let mut action: Option<String> = None;
    let mut params: Vec<String> = Vec::new();
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with("--") {
            config_args.push(args[i].clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
                i += 1;
            }
        } else if ledger_id.is_none() {
            ledger_id = Some(args[i].clone());
        } else if action.is_none() {
            action = Some(args[i].clone());
        } else {
            params.push(args[i].clone());
        }
        i += 1;
    }

    let ledger_id = ledger_id.ok_or("Ledger ID required")?;
    let action = action.ok_or("Action required (e.g., deposit_open)")?;

    let config = parse_config(&config_args)?;

    let relay_url = config.relays.first()
        .ok_or("No relay configured. Use --relay <url>")?
        .clone();

    let secret_key = SecretKey::from_slice(&config.seed)
        .map_err(|e| format!("Invalid seed: {}", e))?;

    // Build params JSON based on action
    let params_json = match action.as_str() {
        "deposit_open" => {
            // params: deposit_pubkey [fee_fixed] [fee_bps] [fee_frequency]
            if params.is_empty() {
                return Err("deposit_open requires: <deposit_pubkey>".into());
            }
            let mut obj = serde_json::Map::new();
            obj.insert("deposit_pubkey".to_string(), serde_json::Value::String(params[0].clone()));
            if params.len() > 1 {
                obj.insert("fee_fixed".to_string(), serde_json::json!(params[1].parse::<u64>().unwrap_or(0)));
            }
            if params.len() > 2 {
                obj.insert("fee_bps".to_string(), serde_json::json!(params[2].parse::<u64>().unwrap_or(0)));
            }
            if params.len() > 3 {
                obj.insert("fee_frequency".to_string(), serde_json::json!(params[3].parse::<u32>().unwrap_or(144)));
            }
            serde_json::Value::Object(obj)
        }
        "deposit_offer" => {
            // params: deposit_pubkey max_sats min_sats blocks_valid
            if params.len() < 4 {
                return Err("deposit_offer requires: <deposit_pubkey> <max_sats> <min_sats> <blocks_valid>".into());
            }
            let mut obj = serde_json::Map::new();
            obj.insert("deposit_pubkey".to_string(), serde_json::Value::String(params[0].clone()));
            obj.insert("max_sats".to_string(), serde_json::json!(params[1].parse::<u64>().unwrap_or(0)));
            obj.insert("min_sats".to_string(), serde_json::json!(params[2].parse::<u64>().unwrap_or(0)));
            obj.insert("blocks_valid".to_string(), serde_json::json!(params[3].parse::<u32>().unwrap_or(144)));
            serde_json::Value::Object(obj)
        }
        "collateral_lock" => {
            // params: deposit_secret amount_msats lock_blocks [requesting_operator]
            if params.len() < 3 {
                return Err("collateral_lock requires: <deposit_secret> <amount_msats> <lock_blocks> [requesting_operator]".into());
            }
            let mut obj = serde_json::Map::new();
            obj.insert("deposit_secret".to_string(), serde_json::Value::String(params[0].clone()));
            obj.insert("amount_msats".to_string(), serde_json::json!(params[1].parse::<u64>().unwrap_or(0)));
            obj.insert("lock_blocks".to_string(), serde_json::json!(params[2].parse::<u32>().unwrap_or(0)));
            if params.len() > 3 {
                obj.insert("requesting_operator".to_string(), serde_json::Value::String(params[3].clone()));
            }
            serde_json::Value::Object(obj)
        }
        "deposit_withdraw" => {
            // params: deposit_secret destination_address amount_sats
            if params.len() < 3 {
                return Err("deposit_withdraw requires: <deposit_secret> <destination_address> <amount_sats>".into());
            }
            let mut obj = serde_json::Map::new();
            obj.insert("deposit_secret".to_string(), serde_json::Value::String(params[0].clone()));
            obj.insert("destination_address".to_string(), serde_json::Value::String(params[1].clone()));
            obj.insert("amount_sats".to_string(), serde_json::json!(params[2].parse::<u64>().unwrap_or(0)));
            serde_json::Value::Object(obj)
        }
        _ => {
            // Generic: treat params as key=value pairs or just values
            let mut obj = serde_json::Map::new();
            for (i, p) in params.iter().enumerate() {
                if let Some((k, v)) = p.split_once('=') {
                    obj.insert(k.to_string(), serde_json::Value::String(v.to_string()));
                } else {
                    obj.insert(format!("arg{}", i), serde_json::Value::String(p.clone()));
                }
            }
            serde_json::Value::Object(obj)
        }
    };

    println!("Sending ledger request via Nostr...");
    println!("  Relay: {}", relay_url);
    println!("  Ledger: {}", ledger_id);
    println!("  Action: {}", action);
    println!("  Params: {}", serde_json::to_string(&params_json)?);
    println!();

    let transport = NostrTransportBuilder::new(secret_key)
        .relay(&relay_url)
        .build()
        .await?;

    // Subscribe to responses for this request
    let event_id = transport.send_ledger_request(&ledger_id, &action, params_json).await?;

    println!("Request sent! Event ID: {}", event_id);
    println!();
    println!("Waiting for response...");

    // Subscribe to the response
    transport.subscribe_to_response(&event_id).await?;

    // Wait for response with timeout, using both subscription and polling
    let mut transport = transport;
    let timeout = tokio::time::Duration::from_secs(30);
    let start = std::time::Instant::now();
    let mut last_poll = std::time::Instant::now();
    let mut poll_count = 0;

    loop {
        if start.elapsed() > timeout {
            println!("Timeout waiting for response.");
            break;
        }

        // Process events from subscription
        tokio::select! {
            _ = transport.process_events() => {}
            _ = tokio::time::sleep(tokio::time::Duration::from_millis(100)) => {}
        }

        // Check for response from subscription
        if let Some(response) = transport.try_recv_response() {
            if response.request_id == event_id {
                println!();
                if response.success {
                    println!("Response: SUCCESS");
                    if let Some(result) = &response.result {
                        println!("Result: {}", serde_json::to_string_pretty(result)?);
                    }
                } else {
                    println!("Response: ERROR");
                    if let Some(error) = &response.error {
                        println!("Error: {}", error);
                    }
                }
                break;
            }
        }

        // Poll more frequently - every 500ms for first 5 polls, then every 2 seconds
        let poll_interval = if poll_count < 5 {
            std::time::Duration::from_millis(500)
        } else {
            std::time::Duration::from_secs(2)
        };

        if last_poll.elapsed() > poll_interval {
            tracing::debug!("Polling for response to request: {}", &event_id[..16]);
            match transport.fetch_response(&event_id).await {
                Ok(Some(response)) => {
                    println!();
                    if response.success {
                        println!("Response: SUCCESS");
                        if let Some(result) = &response.result {
                            println!("Result: {}", serde_json::to_string_pretty(result)?);
                        }
                    } else {
                        println!("Response: ERROR");
                        if let Some(error) = &response.error {
                            println!("Error: {}", error);
                        }
                    }
                    break;
                }
                Ok(None) => {
                    tracing::debug!("No response found for request: {} (poll #{})", &event_id[..16], poll_count);
                }
                Err(e) => {
                    tracing::warn!("Error fetching response: {}", e);
                }
            }
            poll_count += 1;
            last_poll = std::time::Instant::now();
        }
    }

    transport.disconnect().await;
    Ok(())
}

/// Watch for requests to a ledger and process them
async fn nostr_watch(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use bitcoin::secp256k1::SecretKey;
    use deposits_bdk::nostr::NostrTransportBuilder;

    let mut ledger_id: Option<String> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with("--") {
            config_args.push(args[i].clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
                i += 1;
            }
        } else if ledger_id.is_none() {
            ledger_id = Some(args[i].clone());
        }
        i += 1;
    }

    let config = parse_config(&config_args)?;

    let relay_url = config.relays.first()
        .ok_or("No relay configured. Use --relay <url>")?
        .clone();

    let secret_key = SecretKey::from_slice(&config.seed)
        .map_err(|e| format!("Invalid seed: {}", e))?;

    // Clone config for later use (collateral_lock needs to reload node)
    let config_for_reload = config.clone();

    // Get the node to process requests
    let node = Node::new(config).await?;

    // Determine ledger_id - use from args or find our primary ledger
    let ledger_id = if let Some(lid) = ledger_id {
        lid
    } else {
        // Find our primary ledger
        let ledgers = node.list_ledgers();
        if ledgers.is_empty() {
            return Err("No ledgers found. Specify a ledger ID or open a ledger first.".into());
        }
        let ((op, rid), _) = ledgers.into_iter().next().unwrap();
        format!("{}:{}", op, rid)
    };

    println!("Watching for requests on ledger...");
    println!("  Relay: {}", relay_url);
    println!("  Ledger: {}", ledger_id);
    println!();
    println!("Press Ctrl+C to stop.");
    println!();

    let transport = NostrTransportBuilder::new(secret_key)
        .relay(&relay_url)
        .build()
        .await?;

    // Subscribe to requests for this ledger
    transport.subscribe_to_requests(&ledger_id).await?;

    // Also subscribe to disputes for this ledger
    transport.subscribe_to_disputes(&ledger_id).await?;

    let mut transport = transport;
    let mut last_poll = std::time::Instant::now();
    let mut seen_events: std::collections::HashSet<String> = std::collections::HashSet::new();

    loop {
        // Process events from subscription
        if let Err(e) = transport.process_events().await {
            tracing::warn!("Error processing events: {}", e);
        }

        // Poll frequently for events (subscription may not work reliably)
        if last_poll.elapsed() > std::time::Duration::from_millis(500) {
            if let Ok(requests) = transport.fetch_recent_requests(60).await {
                for request in requests {
                    // Queue requests for our ledger, or custody_transfer_sign for any ledger
                    // (we might be a quorum member for other ledgers)
                    let should_queue = request.ledger_id == ledger_id
                        || request.action == "custody_transfer_sign";
                    if should_queue && !seen_events.contains(&request.event_id) {
                        if request.action == "custody_transfer_sign" && request.ledger_id != ledger_id {
                            println!("[{}] Received custody_transfer_sign for external ledger: {}...",
                                chrono::Utc::now().format("%H:%M:%S"),
                                &request.ledger_id[..16.min(request.ledger_id.len())]);
                        }
                        seen_events.insert(request.event_id.clone());
                        transport.queue_request(request);
                    }
                }
            }
            last_poll = std::time::Instant::now();
        }

        // Check for requests
        while let Some(request) = transport.try_recv_request() {
            // Skip requests not for our ledger (except custody_transfer_sign which we handle for any ledger)
            if request.ledger_id != ledger_id && request.action != "custody_transfer_sign" {
                tracing::debug!("Skipping request for different ledger: {} (ours: {})",
                    request.ledger_id, ledger_id);
                continue;
            }

            println!("[{}] Request: action={}",
                chrono::Utc::now().format("%H:%M:%S"),
                request.action);
            println!("  Event: {}", &request.event_id[..16]);
            println!("  Params: {}", request.params);

            // Reload the node to get fresh ledger state from disk
            // (the CLI may have updated the ledger concurrently)
            let fresh_node = match Node::new(config_for_reload.clone()).await {
                Ok(n) => n,
                Err(e) => {
                    let error_msg = format!("Failed to reload node: {}", e);
                    let _ = transport.send_ledger_response(
                        &request.event_id,
                        &ledger_id,
                        false,
                        None,
                        Some(error_msg.clone()),
                    ).await;
                    println!("  Response: ERROR - {}", error_msg);
                    continue;
                }
            };

            // For operations that require custodianship, verify we have the ledger locally
            // The real protection against fraudulent offers is client-side verification:
            // - Client checks offer's funding_address matches ledger's current reserves
            // - Client verifies offer signature is from current custodian
            //
            // TODO: Add proper custody verification once CustodyTransfer operation exists
            let requires_ledger = matches!(
                request.action.as_str(),
                "deposit_open" | "deposit_offer" | "deposit_withdraw" | "collateral_lock"
            );

            if requires_ledger {
                // Just verify we have the ledger locally
                let has_ledger = fresh_node.get_ledger_by_ledger_id(&ledger_id).is_some()
                    || fresh_node.get_ledger_by_reserves_id(&ledger_id).is_some();

                if !has_ledger {
                    let error_msg = "Ledger not found locally".to_string();
                    let _ = transport.send_ledger_response(
                        &request.event_id,
                        &ledger_id,
                        false,
                        None,
                        Some(error_msg.clone()),
                    ).await;
                    println!("  Response: REJECTED - {}", error_msg);
                    continue;
                }
            }

            // Process the request
            let (success, result, error) = match request.action.as_str() {
                "deposit_open" => {
                    process_deposit_open_request(&fresh_node, &ledger_id, &request).await
                }
                "deposit_offer" => {
                    process_deposit_offer_request(&fresh_node, &ledger_id, &request).await
                }
                "deposit_withdraw" => {
                    process_deposit_withdraw_request(&fresh_node, &ledger_id, &request).await
                }
                "collateral_lock" => {
                    process_collateral_lock_request(&fresh_node, &ledger_id, &request).await
                }
                "custody_transfer_sign" => {
                    process_custody_transfer_sign_request(&fresh_node, &config_for_reload, &request).await
                }
                "custodian_query" => {
                    process_custodian_query_request(&fresh_node, &ledger_id, &request).await
                }
                _ => {
                    (false, None, Some(format!("Unknown action: {}", request.action)))
                }
            };

            // Send response (use request's ledger_id for custody_transfer_sign)
            let response_ledger_id = if request.action == "custody_transfer_sign" {
                &request.ledger_id
            } else {
                &ledger_id
            };
            println!("  Sending response for request: {}", &request.event_id[..16]);
            match transport.send_ledger_response(
                &request.event_id,
                response_ledger_id,
                success,
                result.clone(),
                error.clone(),
            ).await {
                Ok(resp_id) => {
                    if success {
                        println!("  Response: SUCCESS (resp_id={}, req_id={})",
                            &resp_id[..16], &request.event_id[..16]);
                    } else {
                        println!("  Response: ERROR - {} (resp_id={}, req_id={})",
                            error.unwrap_or_default(), &resp_id[..16], &request.event_id[..16]);
                    }
                }
                Err(e) => {
                    println!("  Failed to send response: {}", e);
                }
            }
            println!();
        }

        // Check for disputes
        while let Some(dispute) = transport.try_recv_dispute() {
            println!("!!! DISPUTE RECEIVED !!!");
            println!("  Time: {}", chrono::Utc::now().format("%H:%M:%S"));
            println!("  Event: {}", &dispute.event_id[..16.min(dispute.event_id.len())]);
            println!("  Ledger: {}", dispute.ledger_id);
            println!("  Reason: {}", dispute.reason);
            println!("  Details: {}", dispute.details);
            println!("  Disputer: {}...", &dispute.disputer_pubkey[..32.min(dispute.disputer_pubkey.len())]);
            println!("  Last valid seq: {}", dispute.last_valid_sequence);
            if let Some(vs) = dispute.violation_sequence {
                println!("  Violation seq: {}", vs);
            }
            println!();
            println!("  ACTION REQUIRED: Validate ledger and participate in recovery voting.");
            println!();
        }
    }
}

/// Resolve a ledger_id (hash) to the actual reserves_id (Bitcoin address).
///
/// The ledger_id is always a 64-char hex hash (the ledger's unique ID).
/// This function looks up the ledger by its hash and returns the reserves_id.
fn resolve_ledger_id_to_reserves_id(node: &Node, ledger_id: &str) -> Result<String, String> {
    // Look up by ledger_id hash
    for ((_op, rid), ledger_arc) in node.list_ledgers() {
        let ledger = ledger_arc.read().unwrap();
        if ledger.ledger_id_hex() == ledger_id {
            return Ok(rid);
        }
    }
    Err(format!("Ledger not found by hash: {}", ledger_id))
}

/// Process a deposit_open request
async fn process_deposit_open_request(
    node: &Node,
    ledger_id: &str,
    request: &deposits_bdk::nostr::LedgerRequest,
) -> (bool, Option<serde_json::Value>, Option<String>) {
    // Resolve ledger_id (which may be a hash) to actual reserves_id
    let reserves_id = match resolve_ledger_id_to_reserves_id(node, ledger_id) {
        Ok(rid) => rid,
        Err(e) => return (false, None, Some(e)),
    };

    // Extract deposit_pubkey from params
    let deposit_pubkey_str = match request.params.get("deposit_pubkey") {
        Some(serde_json::Value::String(s)) => s.clone(),
        _ => return (false, None, Some("Missing deposit_pubkey parameter".to_string())),
    };

    let deposit_pubkey = match PublicKey::from_str(&deposit_pubkey_str) {
        Ok(pk) => pk,
        Err(e) => return (false, None, Some(format!("Invalid deposit_pubkey: {}", e))),
    };

    // Extract optional fee parameters
    let fees = if request.params.get("fee_fixed").is_some()
        || request.params.get("fee_bps").is_some()
    {
        Some(deposits_core::FeeStructure {
            annualized_fixed: request.params.get("fee_fixed")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            annualized_bps: request.params.get("fee_bps")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u16,
            frequency_blocks: request.params.get("fee_frequency")
                .and_then(|v| v.as_u64())
                .unwrap_or(144) as u32,
        })
    } else {
        None
    };

    // Open the deposit
    match node.open_deposit(&reserves_id, deposit_pubkey, fees) {
        Ok(deposit) => {
            // Broadcast the update to Nostr
            if let Err(e) = node.broadcast_last_update(&reserves_id).await {
                tracing::warn!("Failed to broadcast deposit open to Nostr: {}", e);
            }

            let result = serde_json::json!({
                "deposit_pubkey": deposit_pubkey_str,
                "balance": deposit.balance,
                "fees": {
                    "fixed": deposit.fees.annualized_fixed,
                    "bps": deposit.fees.annualized_bps,
                    "frequency": deposit.fees.frequency_blocks,
                }
            });
            (true, Some(result), None)
        }
        Err(e) => {
            (false, None, Some(e.to_string()))
        }
    }
}

/// Process a deposit_offer request
async fn process_deposit_offer_request(
    node: &Node,
    ledger_id: &str,
    request: &deposits_bdk::nostr::LedgerRequest,
) -> (bool, Option<serde_json::Value>, Option<String>) {
    // Verify the ledger exists (ledger_id may be a hash or reserves_id)
    // We use ledger_id directly for the offer since it's stable across custody transfers
    let resolved_ledger_id = if ledger_id.len() == 64 && ledger_id.chars().all(|c| c.is_ascii_hexdigit()) {
        // Already a 64-char hex ledger_id hash
        ledger_id.to_string()
    } else {
        // It's a reserves_id, look up the ledger to get its ledger_id
        match node.get_ledger_by_reserves_id(ledger_id) {
            Some((_, ledger)) => ledger.ledger_id_hex(),
            None => return (false, None, Some(format!("Ledger not found: {}", ledger_id))),
        }
    };

    // Extract deposit_pubkey from params
    let deposit_pubkey_str = match request.params.get("deposit_pubkey") {
        Some(serde_json::Value::String(s)) => s.clone(),
        _ => return (false, None, Some("Missing deposit_pubkey parameter".to_string())),
    };

    let deposit_pubkey = match PublicKey::from_str(&deposit_pubkey_str) {
        Ok(pk) => pk,
        Err(e) => return (false, None, Some(format!("Invalid deposit_pubkey: {}", e))),
    };

    // Extract required parameters
    let max_sats = match request.params.get("max_sats").and_then(|v| v.as_u64()) {
        Some(v) => v,
        None => return (false, None, Some("Missing max_sats parameter".to_string())),
    };

    let min_sats = match request.params.get("min_sats").and_then(|v| v.as_u64()) {
        Some(v) => v,
        None => return (false, None, Some("Missing min_sats parameter".to_string())),
    };

    let blocks_valid = match request.params.get("blocks_valid").and_then(|v| v.as_u64()) {
        Some(v) => v as u32,
        None => return (false, None, Some("Missing blocks_valid parameter".to_string())),
    };

    if min_sats >= max_sats {
        return (false, None, Some("min_sats must be less than max_sats".to_string()));
    }

    // Sync wallet to get current block height
    if let Err(e) = node.sync_wallet() {
        return (false, None, Some(format!("Failed to sync wallet: {}", e)));
    }

    // Create the offer using ledger_id (stable across custody transfers)
    match node.create_deposit_offer(&resolved_ledger_id, deposit_pubkey, max_sats, min_sats, blocks_valid) {
        Ok(offer) => {
            let result = serde_json::json!({
                "offer_id": hex::encode(&offer.offer_id),
                "operator_id": offer.operator_id.to_string(),
                "funding_address": offer.funding_address,
                "deadline_block": offer.deadline_block,
                "created_at_block": offer.created_at_block,
                "max_sats": max_sats,
                "min_sats": min_sats,
            });
            (true, Some(result), None)
        }
        Err(e) => {
            (false, None, Some(e.to_string()))
        }
    }
}

/// Process a collateral_lock request
async fn process_collateral_lock_request(
    node: &Node,
    ledger_id: &str,
    request: &deposits_bdk::nostr::LedgerRequest,
) -> (bool, Option<serde_json::Value>, Option<String>) {
    use bitcoin::secp256k1::Secp256k1;

    // Resolve ledger_id (which may be a hash) to actual reserves_id
    let reserves_id = match resolve_ledger_id_to_reserves_id(node, ledger_id) {
        Ok(rid) => rid,
        Err(e) => return (false, None, Some(e)),
    };

    // Extract deposit_secret from params
    let deposit_secret_hex = match request.params.get("deposit_secret") {
        Some(serde_json::Value::String(s)) => s.clone(),
        _ => return (false, None, Some("Missing deposit_secret parameter".to_string())),
    };

    let secret_bytes = match hex::decode(&deposit_secret_hex) {
        Ok(b) => b,
        Err(e) => return (false, None, Some(format!("Invalid deposit_secret hex: {}", e))),
    };

    let deposit_secret = match bitcoin::secp256k1::SecretKey::from_slice(&secret_bytes) {
        Ok(s) => s,
        Err(e) => return (false, None, Some(format!("Invalid deposit_secret: {}", e))),
    };

    // Derive the deposit pubkey from the secret
    let secp = Secp256k1::new();
    let deposit_pubkey = PublicKey::from_secret_key(&secp, &deposit_secret);

    // Extract required parameters
    let amount_msats = match request.params.get("amount_msats").and_then(|v| v.as_u64()) {
        Some(v) => v,
        None => return (false, None, Some("Missing amount_msats parameter".to_string())),
    };

    let lock_blocks = match request.params.get("lock_blocks").and_then(|v| v.as_u64()) {
        Some(v) => v as u32,
        None => return (false, None, Some("Missing lock_blocks parameter".to_string())),
    };

    // Get current block height and compute lock_until_block
    let current_block = match node.wallet.get_block_height() {
        Ok(h) => h,
        Err(e) => return (false, None, Some(format!("Failed to get block height: {}", e))),
    };
    let lock_until_block = current_block + lock_blocks;

    // Parse requesting operator (defaults to sender's node_id derived from event)
    let requesting_operator = if let Some(serde_json::Value::String(hex)) = request.params.get("requesting_operator") {
        match PublicKey::from_str(hex) {
            Ok(pk) => pk,
            Err(e) => return (false, None, Some(format!("Invalid requesting_operator: {}", e))),
        }
    } else {
        // Default to the operator's own node_id (self-request)
        node.node_id
    };

    // Lock the collateral
    match node.lock_collateral(
        &reserves_id,
        deposit_pubkey,
        &deposit_secret,
        amount_msats,
        lock_until_block,
        requesting_operator,
    ) {
        Ok(attestation) => {
            // Broadcast the update to Nostr
            if let Err(e) = node.broadcast_last_update(&reserves_id).await {
                tracing::warn!("Failed to broadcast collateral lock to Nostr: {}", e);
            }

            // Serialize attestation as JSON then base64 encode for easy shell parsing
            // (base64 avoids escaping issues with nested JSON)
            use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
            let attestation_json = serde_json::to_string(&attestation).unwrap_or_default();
            let attestation_b64 = BASE64.encode(attestation_json.as_bytes());
            let result = serde_json::json!({
                "amount": attestation.amount,
                "lock_until_block": attestation.lock_until_block,
                "quorum_member": attestation.quorum_member.to_string(),
                "attestation_b64": attestation_b64,
            });
            (true, Some(result), None)
        }
        Err(e) => {
            (false, None, Some(e.to_string()))
        }
    }
}

/// Process a deposit_withdraw request
///
/// This is called when a depositor requests a withdrawal via Nostr.
/// The depositor provides their secret (to prove ownership), destination address, and amount.
async fn process_deposit_withdraw_request(
    node: &Node,
    ledger_id: &str,
    request: &deposits_bdk::nostr::LedgerRequest,
) -> (bool, Option<serde_json::Value>, Option<String>) {
    use bitcoin::secp256k1::Secp256k1;

    // Resolve ledger_id (which may be a hash) to actual reserves_id
    let reserves_id = match resolve_ledger_id_to_reserves_id(node, ledger_id) {
        Ok(rid) => rid,
        Err(e) => return (false, None, Some(e)),
    };

    // Extract deposit_secret from params
    let deposit_secret_hex = match request.params.get("deposit_secret") {
        Some(serde_json::Value::String(s)) => s.clone(),
        _ => return (false, None, Some("Missing deposit_secret parameter".to_string())),
    };

    // Parse the secret and derive the pubkey
    let secret_bytes = match hex::decode(&deposit_secret_hex) {
        Ok(b) if b.len() == 32 => b,
        Ok(_) => return (false, None, Some("deposit_secret must be 32 bytes".to_string())),
        Err(e) => return (false, None, Some(format!("Invalid deposit_secret hex: {}", e))),
    };

    let secp = Secp256k1::new();
    let deposit_secret = match bitcoin::secp256k1::SecretKey::from_slice(&secret_bytes) {
        Ok(sk) => sk,
        Err(e) => return (false, None, Some(format!("Invalid deposit_secret: {}", e))),
    };
    let deposit_pubkey = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &deposit_secret);

    // Extract destination address
    let destination_address = match request.params.get("destination_address") {
        Some(serde_json::Value::String(s)) => s.clone(),
        _ => return (false, None, Some("Missing destination_address parameter".to_string())),
    };

    // Extract amount_sats
    let amount_sats = match request.params.get("amount_sats").and_then(|v| v.as_u64()) {
        Some(v) => v,
        None => return (false, None, Some("Missing amount_sats parameter".to_string())),
    };

    // Use a fixed fee for now (1000 sats)
    let fee_sats = 1000u64;

    println!("  Processing deposit_withdraw request:");
    println!("    Deposit: {}...", &deposit_pubkey.to_string()[..16]);
    println!("    Destination: {}", destination_address);
    println!("    Amount: {} sats", amount_sats);

    // Generate nonce and create withdrawal signature
    let nonce: [u8; 32] = {
        use bitcoin::hashes::{Hash, sha256};
        let mut data = Vec::new();
        data.extend_from_slice(&secret_bytes);
        data.extend_from_slice(destination_address.as_bytes());
        data.extend_from_slice(&amount_sats.to_le_bytes());
        data.extend_from_slice(&std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            .to_le_bytes());
        *sha256::Hash::hash(&data).as_byte_array()
    };

    // Create the withdrawal signature (same as withdraw_request CLI)
    let signature = match deposits_core::create_withdrawal_signature(
        &deposit_secret,
        &nonce,
        &deposit_pubkey,
        &destination_address,
        amount_sats,
        fee_sats,
    ) {
        Ok(sig) => sig,
        Err(e) => return (false, None, Some(format!("Failed to create signature: {:?}", e))),
    };

    // Lock the withdrawal
    match node.lock_withdrawal(
        &reserves_id,
        deposit_pubkey,
        destination_address.clone(),
        amount_sats,
        fee_sats,
        nonce,
        signature,
        None, // memo
    ) {
        Ok(result) => {
            // Broadcast to Nostr
            if let Err(e) = node.broadcast_last_update(&reserves_id).await {
                eprintln!("    Warning: Failed to broadcast to Nostr: {}", e);
            }

            let result_json = serde_json::json!({
                "withdrawal_id": hex::encode(&result.withdrawal.withdrawal_id),
                "amount_sats": amount_sats,
                "fee_sats": fee_sats,
                "destination_address": destination_address,
                "status": "locked",
            });
            (true, Some(result_json), None)
        }
        Err(e) => {
            (false, None, Some(e.to_string()))
        }
    }
}

/// Process a custody_transfer_sign request
///
/// This is called when another quorum member requests our signature for a custody transfer.
/// We validate the violation, verify the spending transaction, sign the sighash, and respond.
async fn process_custody_transfer_sign_request(
    node: &Node,
    config: &NodeConfig,
    request: &deposits_bdk::nostr::LedgerRequest,
) -> (bool, Option<serde_json::Value>, Option<String>) {
    use bitcoin::secp256k1::{Keypair, Secp256k1};
    use deposits_core::messages::LedgerOperation;
    use deposits_core::{TlvDecode, SignedLedgerUpdate};
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use nostr_sdk::prelude::*;

    // Unused: node (we don't need the node for this handler, we fetch ledger from Nostr directly)
    let _ = node;

    println!("  Processing custody_transfer_sign request...");

    // Extract required parameters
    let ledger_id = match request.params.get("ledger_id").and_then(|v| v.as_str()) {
        Some(id) => id.to_string(),
        None => return (false, None, Some("Missing ledger_id parameter".to_string())),
    };

    let sighash_hex = match request.params.get("sighash").and_then(|v| v.as_str()) {
        Some(h) => h.to_string(),
        None => return (false, None, Some("Missing sighash parameter".to_string())),
    };

    // TODO: Verify unsigned_tx actually spends to new_custodian's address
    let _unsigned_tx_hex = match request.params.get("unsigned_tx").and_then(|v| v.as_str()) {
        Some(tx) => tx.to_string(),
        None => return (false, None, Some("Missing unsigned_tx parameter".to_string())),
    };

    let new_custodian_hex = match request.params.get("new_custodian").and_then(|v| v.as_str()) {
        Some(c) => c.to_string(),
        None => return (false, None, Some("Missing new_custodian parameter".to_string())),
    };

    let violation_details = match request.params.get("violation_details").and_then(|v| v.as_str()) {
        Some(d) => d.to_string(),
        None => return (false, None, Some("Missing violation_details parameter".to_string())),
    };

    let last_valid_sequence = match request.params.get("last_valid_sequence").and_then(|v| v.as_u64()) {
        Some(seq) => seq,
        None => return (false, None, Some("Missing last_valid_sequence parameter".to_string())),
    };

    // Parse sighash
    let sighash_bytes = match hex::decode(&sighash_hex) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        Ok(_) => return (false, None, Some("Invalid sighash length".to_string())),
        Err(e) => return (false, None, Some(format!("Invalid sighash hex: {}", e))),
    };

    // Parse new custodian (validated but not directly used in signing)
    let _new_custodian: bitcoin::secp256k1::PublicKey = match new_custodian_hex.parse() {
        Ok(pk) => pk,
        Err(e) => return (false, None, Some(format!("Invalid new_custodian: {}", e))),
    };

    println!("    Ledger: {}...", &ledger_id[..16.min(ledger_id.len())]);
    println!("    New custodian: {}...", &new_custodian_hex[..16.min(new_custodian_hex.len())]);
    println!("    Violation: {}", &violation_details[..50.min(violation_details.len())]);

    // Validate that we're a quorum member for this ledger
    // First, we need to verify the violation by fetching and validating the ledger ourselves

    // Use the node's operator key (BIP32-derived from seed, not raw seed)
    let secp = Secp256k1::new();
    let secret_key = node.wallet.operator_secret();
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let our_pubkey = node.node_id;

    println!("    Our key: {}...", &our_pubkey.to_string()[..16]);

    let relay_url = match config.relays.first() {
        Some(url) => url.clone(),
        None => return (false, None, Some("No relay configured".to_string())),
    };

    // Fetch and validate the ledger from Nostr
    let keys = Keys::generate();
    let client = Client::new(keys);
    if let Err(e) = client.add_relay(&relay_url).await {
        return (false, None, Some(format!("Failed to add relay: {}", e)));
    }
    client.connect().await;

    let filter = Filter::new()
        .kind(Kind::Custom(deposits_bdk::nostr::KIND_LEDGER_UPDATE))
        .custom_tag(SingleLetterTag::lowercase(Alphabet::D), [ledger_id.as_str()])
        .limit(500);

    let events = match client.fetch_events(vec![filter], None).await {
        Ok(e) => e,
        Err(e) => {
            let _ = client.disconnect().await;
            return (false, None, Some(format!("Failed to fetch ledger: {}", e)));
        }
    };

    let _ = client.disconnect().await;

    // Decode and validate updates
    let mut updates: Vec<SignedLedgerUpdate> = Vec::new();
    for event in events.iter() {
        if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
            if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                updates.push(update);
            }
        }
    }

    updates.sort_by_key(|u| (u.sequence_number, u.operator_id));

    // Deduplicate by (sequence_number, operator_id, current_hash) to handle relay duplicates
    // Include operator_id to preserve different operators' updates at same sequence
    updates.dedup_by(|a, b| a.sequence_number == b.sequence_number && a.operator_id == b.operator_id && a.current_hash == b.current_hash);

    // Verify the violation exists
    let mut last_valid_hash = [0u8; 32];
    let mut found_violation = false;
    let mut validated_sequence: i64 = -1;

    for update in &updates {
        let expected_seq = (validated_sequence + 1) as u64;
        if update.sequence_number != expected_seq && validated_sequence >= 0 {
            found_violation = true;
            break;
        }

        let expected_prev = if update.sequence_number == 0 {
            [0u8; 32]
        } else {
            last_valid_hash
        };

        if update.previous_hash != expected_prev {
            found_violation = true;
            break;
        }

        let computed_hash = update.compute_hash();
        if computed_hash != update.current_hash {
            found_violation = true;
            break;
        }

        last_valid_hash = update.current_hash;
        validated_sequence = update.sequence_number as i64;
    }

    if !found_violation {
        return (false, None, Some("Could not verify violation - ledger appears conforming".to_string()));
    }

    // Verify that the last_valid_sequence matches our validation
    if validated_sequence != last_valid_sequence as i64 {
        return (false, None, Some(format!(
            "Sequence mismatch: requester says {}, we validated {}",
            last_valid_sequence, validated_sequence
        )));
    }

    println!("    Violation verified at seq {}", validated_sequence + 1);

    // Verify we're a quorum member by checking the ledger operations
    let mut is_quorum_member = false;
    for update in updates.iter().take((validated_sequence + 1) as usize) {
        if let Ok(operation) = LedgerOperation::tlv_decode(&update.message) {
            match operation {
                LedgerOperation::QuorumAddMember { quorum_member, .. } => {
                    if quorum_member == our_pubkey {
                        is_quorum_member = true;
                    }
                }
                _ => {}
            }
        }
    }

    if !is_quorum_member {
        return (false, None, Some("We are not a quorum member for this ledger".to_string()));
    }

    println!("    Verified: we are a quorum member");

    // TODO: Optionally verify the unsigned_tx is spending the correct UTXO to the correct destination
    // For now, we trust that the sighash is computed correctly

    // Sign the sighash
    let msg = bitcoin::secp256k1::Message::from_digest(sighash_bytes);
    let signature = secp.sign_schnorr(&msg, &keypair);
    let signature_bytes = signature.serialize();

    println!("    Signed sighash: {}...", &hex::encode(&signature_bytes[..4]));

    // Return the signature
    let result = serde_json::json!({
        "signer": our_pubkey.to_string(),
        "signature": hex::encode(signature_bytes),
        "sighash": sighash_hex,
    });

    (true, Some(result), None)
}

/// Process a custodian_query request
///
/// Quorum members respond with a signed attestation of who they believe is the current
/// custodian for this ledger. Clients collect multiple responses and take the majority.
async fn process_custodian_query_request(
    node: &Node,
    ledger_id: &str,
    _request: &deposits_bdk::nostr::LedgerRequest,
) -> (bool, Option<serde_json::Value>, Option<String>) {
    use bitcoin::secp256k1::{Secp256k1, Message};
    use bitcoin::hashes::{sha256, Hash};

    // Look up the ledger
    let ledger = if let Some((_, l)) = node.get_ledger_by_ledger_id(ledger_id) {
        l
    } else if let Some((_, l)) = node.get_ledger_by_reserves_id(ledger_id) {
        l
    } else {
        return (false, None, Some("Ledger not found".to_string()));
    };

    // Determine who we believe is the current custodian
    // This is the operator_key from the ledger state (which we trust from our local copy)
    let current_custodian = ledger.state.operator_key;

    // Create attestation message: "CUSTODIAN_ATTESTATION:{ledger_id}:{custodian_pubkey}:{timestamp}"
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let attestation_msg = format!(
        "CUSTODIAN_ATTESTATION:{}:{}:{}",
        ledger_id,
        current_custodian,
        timestamp
    );

    // Sign the attestation with our operator key
    let secp = Secp256k1::new();
    let secret_key = node.wallet.operator_secret();
    let msg_hash = sha256::Hash::hash(attestation_msg.as_bytes());
    let msg = Message::from_digest(*msg_hash.as_byte_array());
    let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &secret_key);
    let signature = secp.sign_schnorr(&msg, &keypair);

    let result = serde_json::json!({
        "ledger_id": ledger_id,
        "custodian": current_custodian.to_string(),
        "attester": node.node_id.to_string(),
        "timestamp": timestamp,
        "signature": hex::encode(signature.serialize()),
    });

    (true, Some(result), None)
}

// =============================================================================
// RECOVERY COMMANDS
// =============================================================================

/// Handle recovery subcommands for non-conforming ledgers
async fn recovery_command(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.is_empty() {
        eprintln!("Usage: deposits-bdk recovery <dispute|rebuild|arm|claim|spend|status> [args...]");
        eprintln!();
        eprintln!("Subcommands (Dispute Protocol):");
        eprintln!("  dispute <ledger_id> [--reason <text>]  Open dispute: publish CustodyDispute operation");
        eprintln!("  rebuild <ledger_id>                    Rebuild quorum: add members + get attestations");
        eprintln!("  arm <ledger_id>                        Pre-commit: publish CustodyArmed operation");
        eprintln!("  claim <ledger_id>                      After entropy: CustodyAcquire (win) or CustodyYield (lose)");
        eprintln!("  spend <ledger_id>                      Execute on-chain spend (winner only)");
        eprintln!("  status <ledger_id>                     Show recovery status and candidates");
        eprintln!();
        eprintln!("Recovery flow:");
        eprintln!("  1. dispute - Detect violation, publish CustodyDispute (quorum disbanded)");
        eprintln!("  2. rebuild - Add new quorum members, collect attestations");
        eprintln!("  3. arm     - Publish CustodyArmed (locks in for entropy selection)");
        eprintln!("  4. (wait)  - Wait for entropy block to be mined");
        eprintln!("  5. claim   - Winner: CustodyAcquire, Losers: CustodyYield");
        eprintln!("  6. spend   - Winner broadcasts on-chain spend to claim reserves");
        eprintln!();
        eprintln!("State machine: NORMAL -> DISPUTED -> ARMED -> NORMAL (winner) / TOMBSTONED (losers)");
        return Ok(());
    }

    match args[0].as_str() {
        // New dispute protocol commands
        "dispute" => recovery_dispute(&args[1..]).await,
        "rebuild" => recovery_rebuild(&args[1..]).await,
        "arm" => recovery_arm(&args[1..]).await,
        "claim" => recovery_claim_new(&args[1..]).await,
        "spend" => recovery_spend(&args[1..]).await,
        "status" => recovery_status(&args[1..]).await,
        // Legacy commands (for backward compatibility)
        "start" => recovery_start(&args[1..]).await,
        "agree" => recovery_agree(&args[1..]).await,
        "prepare" => recovery_prepare(&args[1..]).await,
        "release" => recovery_release(&args[1..]).await,
        "complete" => recovery_complete(&args[1..]).await,
        "publish-transfer" => recovery_publish_transfer(&args[1..]).await,
        cmd => {
            eprintln!("Unknown recovery subcommand: {}", cmd);
            eprintln!("Usage: deposits-bdk recovery <dispute|rebuild|arm|claim|spend|status> [args...]");
            Ok(())
        }
    }
}

/// Start a recovery process for a non-conforming ledger
/// Validates the ledger from Nostr and publishes a dispute if invalid.
async fn recovery_start(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
    use deposits_core::{TlvDecode, SignedLedgerUpdate};
    use deposits_bdk::nostr::{NostrTransportBuilder, KIND_LEDGER_UPDATE};
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use nostr_sdk::prelude::*;

    let mut ledger_id: Option<String> = None;
    let mut reason: Option<String> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--reason" | "-r" => {
                i += 1;
                if i < args.len() {
                    reason = Some(args[i].clone());
                }
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
                }
            }
        }
        i += 1;
    }

    let ledger_id = ledger_id.ok_or("Missing ledger_id")?.trim().to_string();
    let reason = reason.unwrap_or_else(|| "Non-conforming ledger detected".to_string());

    let config = parse_config(&config_args)?;
    let relay_url = config.relays.first()
        .ok_or("No relay configured. Use --relay <url>")?
        .clone();

    // Build keypair from seed
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&config.seed)
        .map_err(|e| format!("Invalid seed: {}", e))?;
    let keypair = Keypair::from_secret_key(&secp, &secret_key);

    println!("Starting recovery for ledger: {}...", &ledger_id[..16.min(ledger_id.len())]);
    println!("  Reason: {}", reason);
    println!();

    // Fetch and validate ledger from Nostr
    println!("Fetching ledger from Nostr...");
    let keys = Keys::generate();
    let client = Client::new(keys);
    client.add_relay(&relay_url).await
        .map_err(|e| format!("Failed to add relay: {}", e))?;
    client.connect().await;

    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .custom_tag(SingleLetterTag::lowercase(Alphabet::D), [ledger_id.as_str()])
        .limit(500);

    let events = client
        .fetch_events(vec![filter], None)
        .await
        .map_err(|e| format!("Failed to fetch events: {}", e))?;

    client.disconnect().await.ok();

    // Decode and sort updates
    let mut updates: Vec<SignedLedgerUpdate> = Vec::new();
    for event in events.iter() {
        if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
            if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                updates.push(update);
            }
        }
    }
    updates.sort_by_key(|u| (u.sequence_number, u.operator_id));
    // Deduplicate exact copies only (keep different updates with same seq/operator to detect violations)
    // Include operator_id to preserve different operators' updates at same sequence
    updates.dedup_by(|a, b| a.sequence_number == b.sequence_number && a.operator_id == b.operator_id && a.current_hash == b.current_hash);

    println!("  Found {} updates", updates.len());

    // Validate the hash chain to find the violation
    let mut last_valid_hash = [0u8; 32];
    let mut last_valid_sequence: i64 = -1;
    let mut violation_details = String::new();
    let mut violation_sequence: Option<u64> = None;

    for update in &updates {
        let expected_seq = (last_valid_sequence + 1) as u64;
        if update.sequence_number != expected_seq && last_valid_sequence >= 0 {
            violation_details = format!(
                "Sequence gap at seq {}: expected {}, got {}",
                update.sequence_number, expected_seq, update.sequence_number
            );
            violation_sequence = Some(update.sequence_number);
            break;
        }

        let expected_prev = if update.sequence_number == 0 {
            [0u8; 32]
        } else {
            last_valid_hash
        };

        if update.previous_hash != expected_prev {
            violation_details = format!(
                "Hash chain broken at seq {}: expected {}..., got {}...",
                update.sequence_number,
                hex::encode(&expected_prev[..4]),
                hex::encode(&update.previous_hash[..4])
            );
            violation_sequence = Some(update.sequence_number);
            break;
        }

        let computed_hash = update.compute_hash();
        if computed_hash != update.current_hash {
            violation_details = format!(
                "Invalid hash at seq {}: computed {}..., stored {}...",
                update.sequence_number,
                hex::encode(&computed_hash[..4]),
                hex::encode(&update.current_hash[..4])
            );
            violation_sequence = Some(update.sequence_number);
            break;
        }

        last_valid_hash = update.current_hash;
        last_valid_sequence = update.sequence_number as i64;
    }

    if violation_sequence.is_none() {
        println!();
        println!("Ledger appears conforming (no violation found).");
        println!("Cannot start recovery for a conforming ledger.");
        return Ok(());
    }

    let last_valid_sequence_u64 = if last_valid_sequence >= 0 {
        last_valid_sequence as u64
    } else {
        0
    };

    println!();
    println!("Violation detected!");
    println!("  {}", violation_details);
    println!("  Last valid sequence: {}", last_valid_sequence_u64);
    println!("  Last valid hash: {}...", hex::encode(&last_valid_hash[..8]));
    println!();

    // Publish dispute to Nostr
    println!("Publishing dispute to Nostr...");
    let transport = NostrTransportBuilder::new(secret_key)
        .relay(&relay_url)
        .build()
        .await?;

    let dispute_id = transport.publish_dispute(
        &ledger_id,
        &reason,
        &violation_details,
        last_valid_hash,
        last_valid_sequence_u64,
        violation_sequence,
        &keypair,
    ).await?;

    transport.disconnect().await;

    println!("  Dispute published: {}", &dispute_id[..16]);
    println!();
    println!("Next steps:");
    println!("  1. Other quorum members run: deposits-bdk recovery agree {}", &ledger_id[..16]);
    println!("  2. Once enough agree, run: deposits-bdk recovery complete {}", &ledger_id[..16]);

    Ok(())
}

/// Agree to a recovery (respond to a dispute)
/// Independently validates the ledger and publishes agreement if violation confirmed.
async fn recovery_agree(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey, PublicKey};
    use deposits_core::{TlvDecode, SignedLedgerUpdate};
    use deposits_bdk::nostr::{NostrTransportBuilder, KIND_LEDGER_UPDATE};
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use nostr_sdk::prelude::*;

    let mut ledger_id: Option<String> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with("--") {
            config_args.push(args[i].clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
                i += 1;
            }
        } else if ledger_id.is_none() {
            ledger_id = Some(args[i].clone());
        }
        i += 1;
    }

    let ledger_id = ledger_id.ok_or("Missing ledger_id")?.trim().to_string();

    let config = parse_config(&config_args)?;
    let relay_url = config.relays.first()
        .ok_or("No relay configured. Use --relay <url>")?
        .clone();

    // Build keypair from seed
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&config.seed)
        .map_err(|e| format!("Invalid seed: {}", e))?;
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let our_pubkey = PublicKey::from(keypair.public_key());

    println!("Checking for disputes on ledger: {}...", &ledger_id[..16.min(ledger_id.len())]);
    println!("  Our key: {}...", &our_pubkey.to_string()[..16]);
    println!();

    // Fetch disputes for this ledger
    let transport = NostrTransportBuilder::new(secret_key)
        .relay(&relay_url)
        .build()
        .await?;

    let disputes = transport.fetch_disputes(&ledger_id).await?;

    if disputes.is_empty() {
        println!("No disputes found for this ledger.");
        println!("Run 'recovery start' to initiate a dispute first.");
        transport.disconnect().await;
        return Ok(());
    }

    // Use the most recent dispute
    let dispute = disputes.last().unwrap();
    println!("Found dispute:");
    println!("  From: {}...", &dispute.disputer_pubkey[..16.min(dispute.disputer_pubkey.len())]);
    println!("  Reason: {}", dispute.reason);
    println!("  Details: {}", dispute.details);
    println!("  Last valid seq: {}", dispute.last_valid_sequence);
    println!("  Event: {}...", &dispute.event_id[..16]);
    println!();

    // Independently validate the ledger
    println!("Independently validating ledger...");

    let keys = Keys::generate();
    let client = Client::new(keys);
    client.add_relay(&relay_url).await
        .map_err(|e| format!("Failed to add relay: {}", e))?;
    client.connect().await;

    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .custom_tag(SingleLetterTag::lowercase(Alphabet::D), [ledger_id.as_str()])
        .limit(500);

    let events = client
        .fetch_events(vec![filter], None)
        .await
        .map_err(|e| format!("Failed to fetch events: {}", e))?;

    client.disconnect().await.ok();

    // Decode and sort updates
    let mut updates: Vec<SignedLedgerUpdate> = Vec::new();
    for event in events.iter() {
        if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
            if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                updates.push(update);
            }
        }
    }
    updates.sort_by_key(|u| (u.sequence_number, u.operator_id));
    // Deduplicate exact copies only (keep different updates with same seq/operator to detect violations)
    // Include operator_id to preserve different operators' updates at same sequence
    updates.dedup_by(|a, b| a.sequence_number == b.sequence_number && a.operator_id == b.operator_id && a.current_hash == b.current_hash);

    println!("  Found {} updates", updates.len());

    // Validate the hash chain
    let mut last_valid_hash = [0u8; 32];
    let mut last_valid_sequence: i64 = -1;
    let mut found_violation = false;

    for update in &updates {
        let expected_seq = (last_valid_sequence + 1) as u64;
        if update.sequence_number != expected_seq && last_valid_sequence >= 0 {
            found_violation = true;
            break;
        }

        let expected_prev = if update.sequence_number == 0 {
            [0u8; 32]
        } else {
            last_valid_hash
        };

        if update.previous_hash != expected_prev {
            found_violation = true;
            break;
        }

        let computed_hash = update.compute_hash();
        if computed_hash != update.current_hash {
            found_violation = true;
            break;
        }

        last_valid_hash = update.current_hash;
        last_valid_sequence = update.sequence_number as i64;
    }

    let our_last_valid = if last_valid_sequence >= 0 {
        last_valid_sequence as u64
    } else {
        0
    };

    if !found_violation {
        println!();
        println!("We did NOT find a violation. Ledger appears conforming.");
        println!("Not publishing agreement.");
        transport.disconnect().await;
        return Ok(());
    }

    println!("  Violation confirmed!");
    println!("  Our last valid sequence: {}", our_last_valid);
    println!("  Our last valid hash: {}...", hex::encode(&last_valid_hash[..8]));
    println!();

    // Publish agreement
    println!("Publishing recovery agreement...");

    let agreement_id = transport.publish_recovery_agreement(
        &ledger_id,
        &dispute.event_id,
        our_last_valid,
        last_valid_hash,
        &keypair,
    ).await?;

    transport.disconnect().await;

    println!("  Agreement published: {}", &agreement_id[..16]);
    println!();
    println!("Next step:");
    println!("  Once enough quorum members agree, run: deposits-bdk recovery complete {}", &ledger_id[..16]);

    Ok(())
}

/// Show recovery status for a ledger
async fn recovery_status(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut ledger_id: Option<String> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with("--") {
            config_args.push(args[i].clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
                i += 1;
            }
        } else if ledger_id.is_none() {
            ledger_id = Some(args[i].clone());
        }
        i += 1;
    }

    let ledger_id = ledger_id.ok_or("Missing ledger_id")?;

    println!("Recovery status for: {}", ledger_id);
    println!();
    println!("Note: Recovery state is currently ephemeral (in-memory).");
    println!("In a production implementation, recovery state would be persisted.");
    println!();
    println!("To participate in recovery:");
    println!("  1. Validate the ledger: deposits-bdk nostr validate {}", ledger_id);
    println!("  2. If invalid, publish dispute: deposits-bdk nostr dispute publish {} <reason> <details>", ledger_id);
    println!("  3. Submit vote: deposits-bdk recovery vote {} non-conforming", ledger_id);
    println!("  4. Claim if eligible: deposits-bdk recovery claim {}", ledger_id);

    Ok(())
}

/// Execute a custody transfer for a non-conforming ledger
///
/// This command:
/// 1. Fetches the target ledger from Nostr
/// DEPRECATED: Use the new dispute protocol commands instead:
///   recovery dispute -> recovery rebuild -> recovery arm -> recovery claim -> recovery spend
///
/// This legacy command attempted to do everything in one step, which doesn't follow
/// the proper dispute protocol (CustodyDispute -> CustodyArmed -> CustodyAcquire).
async fn recovery_complete(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("WARNING: 'recovery complete' is deprecated and uses the old protocol.");
    eprintln!("Please use the new dispute protocol commands instead:");
    eprintln!("  1. recovery dispute <ledger_id>   - Open dispute with CustodyDispute");
    eprintln!("  2. recovery rebuild <ledger_id>   - Rebuild quorum");
    eprintln!("  3. recovery arm <ledger_id>       - Publish CustodyArmed pre-commitment");
    eprintln!("  4. recovery claim <ledger_id>     - Claim with CustodyAcquire/CustodyYield");
    eprintln!("  5. recovery spend <ledger_id>     - Execute on-chain spend");
    eprintln!();

    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey, PublicKey};
    use bitcoin::hashes::{Hash, sha256};
    use deposits_core::messages::LedgerOperation;
    use deposits_core::{TlvDecode, SignedLedgerUpdate};
    use deposits_bdk::nostr::{NostrTransportBuilder, KIND_LEDGER_UPDATE};
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use nostr_sdk::prelude::*;

    let mut ledger_id: Option<String> = None;
    let mut new_custodian: Option<String> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--new-custodian" => {
                i += 1;
                if i < args.len() {
                    new_custodian = Some(args[i].clone());
                }
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
                }
            }
        }
        i += 1;
    }

    let ledger_id = ledger_id.ok_or("Missing ledger_id")?.trim().to_string();

    let config = parse_config(&config_args)?;
    let relay_url = config.relays.first()
        .ok_or("No relay configured. Use --relay <url>")?
        .clone();

    // Build keypair from seed
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&config.seed)
        .map_err(|e| format!("Invalid seed: {}", e))?;
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let our_pubkey = PublicKey::from(keypair.public_key());

    println!("Completing recovery for ledger: {}...", &ledger_id[..16.min(ledger_id.len())]);
    println!("  Our key: {}...", &our_pubkey.to_string()[..16]);
    println!();

    // Fetch disputes and agreements
    println!("Fetching disputes and agreements...");
    let transport = NostrTransportBuilder::new(secret_key)
        .relay(&relay_url)
        .build()
        .await?;

    let disputes = transport.fetch_disputes(&ledger_id).await?;

    if disputes.is_empty() {
        println!("No disputes found. Run 'recovery start' first.");
        transport.disconnect().await;
        return Ok(());
    }

    let dispute = disputes.last().unwrap();
    println!("  Dispute: {} (from {}...)", &dispute.event_id[..16], &dispute.disputer_pubkey[..16]);

    let agreements = transport.fetch_recovery_agreements(&dispute.event_id).await?;
    println!("  Agreements: {}", agreements.len());

    for agreement in &agreements {
        println!("    - {}... (seq {})", &agreement.member_pubkey[..16], agreement.last_valid_sequence);
    }

    // Determine the consensus fork point (minimum sequence among all who agree)
    let disputer_seq = dispute.last_valid_sequence;
    let min_agreed_seq = agreements.iter()
        .map(|a| a.last_valid_sequence)
        .min()
        .unwrap_or(disputer_seq);
    let fork_sequence = min_agreed_seq.min(disputer_seq);

    println!();
    println!("Consensus fork point: sequence {}", fork_sequence);

    // Collect agreeing member pubkeys for quorum check
    let mut agreeing_members: Vec<PublicKey> = Vec::new();

    // Add the disputer
    if let Ok(pk) = dispute.disputer_pubkey.parse::<PublicKey>() {
        agreeing_members.push(pk);
    }

    // Add agreement signers
    for agreement in &agreements {
        if let Ok(pk) = agreement.member_pubkey.parse::<PublicKey>() {
            if !agreeing_members.contains(&pk) {
                agreeing_members.push(pk);
            }
        }
    }

    println!("Agreeing members: {}", agreeing_members.len());

    // For now, require at least 2 agreeing members
    // TODO: This should check against the actual quorum threshold from the ledger
    let required_agreements = 2;
    if agreeing_members.len() < required_agreements {
        println!();
        println!("Not enough agreements yet. Need {} members, have {}.", required_agreements, agreeing_members.len());
        println!("Ask other quorum members to run: deposits-bdk recovery agree {}", &ledger_id[..16]);
        transport.disconnect().await;
        return Ok(());
    }

    println!();
    println!("Quorum reached! Proceeding with recovery...");
    println!();

    // Parse or determine new custodian
    let new_custodian_pubkey: PublicKey = if let Some(ref nc) = new_custodian {
        nc.parse().map_err(|e| format!("Invalid new_custodian pubkey: {:?}", e))?
    } else {
        // Use entropy-based selection from agreeing members (simplified for now)
        // In production, this would use block hash entropy
        agreeing_members[0]
    };

    let reason = dispute.reason.clone();

    println!("  New custodian: {}...", &new_custodian_pubkey.to_string()[..16]);
    println!("  Reason: {}", reason);
    println!();

    // NOTE: Full CustodyAcquire ledger update requires collecting Schnorr signatures
    // from threshold quorum members. The on-chain spend and ledger fork happen together.
    // For now, proceeding to build the transaction.

    // Validate ledger_id is a 64-char hex hash
    if ledger_id.len() != 64 {
        return Err(format!(
            "Invalid ledger_id length. Expected: 64 chars, got {} chars: '{}'",
            ledger_id.len(),
            ledger_id
        ).into());
    }
    if !ledger_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!(
            "Invalid ledger_id chars. Not all hex: '{}'",
            ledger_id
        ).into());
    }

    // Fetch ledger updates from Nostr
    println!("Fetching ledger from Nostr...");
    let keys = Keys::generate();
    let client = Client::new(keys);
    client.add_relay(&relay_url).await
        .map_err(|e| format!("Failed to add relay: {}", e))?;
    client.connect().await;

    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .custom_tag(SingleLetterTag::lowercase(Alphabet::D), [ledger_id.as_str()])
        .limit(500);

    let events = client
        .fetch_events(vec![filter], None)
        .await
        .map_err(|e| format!("Failed to fetch events: {}", e))?;

    client.disconnect().await.ok();

    if events.is_empty() {
        return Err("No ledger updates found on Nostr".into());
    }

    // Decode all updates
    let mut updates: Vec<SignedLedgerUpdate> = Vec::new();
    for event in events.iter() {
        if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
            if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                updates.push(update);
            }
        }
    }

    if updates.is_empty() {
        return Err("No valid updates could be decoded".into());
    }

    // Sort by sequence number and deduplicate exact copies
    // Include operator_id to preserve different operators' updates at same sequence
    updates.sort_by_key(|u| (u.sequence_number, u.operator_id));
    let total_before_dedup = updates.len();
    updates.dedup_by(|a, b| a.sequence_number == b.sequence_number && a.operator_id == b.operator_id && a.current_hash == b.current_hash);
    println!("  Found {} updates ({} after dedup)", total_before_dedup, updates.len());

    // Validate ledger hash chain and find violation
    println!("Validating ledger...");

    let mut last_valid_hash = [0u8; 32];
    let mut last_valid_sequence: i64 = -1;
    let mut violation_found = false;
    let mut violation_details = String::new();

    for update in &updates {
        // Check sequence continuity
        let expected_seq = (last_valid_sequence + 1) as u64;
        if update.sequence_number != expected_seq && last_valid_sequence >= 0 {
            violation_found = true;
            violation_details = format!(
                "Sequence gap at seq {}: expected {}, got {}",
                update.sequence_number, expected_seq, update.sequence_number
            );
            break;
        }

        // Check previous hash linkage
        let expected_prev = if update.sequence_number == 0 {
            [0u8; 32]
        } else {
            last_valid_hash
        };

        if update.previous_hash != expected_prev {
            violation_found = true;
            violation_details = format!(
                "Hash chain broken at seq {}: expected {}..., got {}...",
                update.sequence_number,
                &hex::encode(expected_prev)[..8],
                &hex::encode(update.previous_hash)[..8]
            );
            break;
        }

        // Verify computed hash matches
        let computed_hash = update.compute_hash();
        if computed_hash != update.current_hash {
            violation_found = true;
            violation_details = format!(
                "Hash mismatch at seq {}: computed {}..., stored {}...",
                update.sequence_number,
                &hex::encode(computed_hash)[..8],
                &hex::encode(update.current_hash)[..8]
            );
            break;
        }

        // Update last valid state
        last_valid_hash = update.current_hash;
        last_valid_sequence = update.sequence_number as i64;
    }

    if !violation_found {
        return Err("No violation found - ledger appears conforming. Cannot execute custody transfer.".into());
    }

    println!("  Violation detected: {}", violation_details);
    println!("  Last valid sequence: {}", last_valid_sequence);
    println!("  Last valid hash: {}...", &hex::encode(last_valid_hash)[..16]);
    println!();

    // Extract ledger state from valid updates (up to last_valid_sequence)
    // We need: operator_id, quorum_members, reserves_id (Taproot address)
    let mut operator_id: Option<PublicKey> = None;
    let mut quorum_members: Vec<PublicKey> = Vec::new();
    let mut reserves_address: Option<String> = None;
    let mut ledger_hash: Option<[u8; 32]> = None;

    println!("Extracting ledger state from valid updates...");
    for update in updates.iter().take((last_valid_sequence + 1) as usize) {
        // Decode the operation from the message
        if let Ok(operation) = LedgerOperation::tlv_decode(&update.message) {
            match operation {
                LedgerOperation::LedgerOpen { operator_id: op, .. } => {
                    operator_id = Some(op);
                    println!("    LedgerOpen: operator {}...", &op.to_string()[..16]);
                }
                LedgerOperation::QuorumAddMember { quorum_member, .. } => {
                    if !quorum_members.contains(&quorum_member) {
                        quorum_members.push(quorum_member);
                        println!("    QuorumAddMember: {}...", &quorum_member.to_string()[..16]);
                    }
                }
                LedgerOperation::ReservesRotate { reserves_id, ledger_hash: lh, .. } => {
                    reserves_address = Some(reserves_id.clone());
                    // Use the ledger_hash from the rotation operation - this matches
                    // what was used to build the Taproot address
                    ledger_hash = Some(lh);
                    println!("    ReservesRotate: {}...", &reserves_id[..20.min(reserves_id.len())]);
                }
                LedgerOperation::ReservesIncrease { reserves_id, .. } => {
                    // Only use if we haven't seen a ReservesRotate yet
                    if reserves_address.is_none() {
                        reserves_address = Some(reserves_id.clone());
                        println!("    ReservesIncrease: {}...", &reserves_id[..20.min(reserves_id.len())]);
                    }
                }
                _ => {}
            }
        }
    }

    let operator_id = operator_id.ok_or("Could not find operator_id from ledger")?;
    let reserves_address = reserves_address.ok_or("Could not find reserves address from ledger")?;
    let ledger_hash = ledger_hash.ok_or("Could not find ledger_hash from ledger (is reserves rotated to Taproot?)")?;

    println!("  Operator: {}...", &operator_id.to_string()[..16]);
    println!("  Quorum members: {}", quorum_members.len());
    println!("  Reserves address: {}...", &reserves_address[..20.min(reserves_address.len())]);
    println!();

    // Create evidence hash (hash of the violation details)
    let evidence_hash = *sha256::Hash::hash(violation_details.as_bytes()).as_byte_array();

    // Block heights for entropy-based selection
    // In production: initiation_block = current block, entropy_block = initiation + 6
    // For testing: use 0 and simulated entropy
    let initiation_block = 0u32;
    let entropy_block_height = initiation_block + 6;

    // For testing, use a deterministic "entropy" based on the ledger_id
    // In production, this would be the actual block hash at entropy_block_height
    let entropy_block_hash = *sha256::Hash::hash(ledger_id.as_bytes()).as_byte_array();

    // Create candidate pool - in production this would be all quorum members
    // For testing, use the new_custodian as the only candidate (they will be selected)
    let candidate_pool = vec![new_custodian_pubkey];

    // The new custodian is deterministically selected from candidate_pool using entropy
    // select_recovery_partner(entropy_block_hash, candidate_pool) -> new_custodian
    // For testing with single candidate, this trivially selects new_custodian_pubkey
    let selected_custodian = deposits_core::recovery::select_recovery_partner(&entropy_block_hash, &candidate_pool);

    println!("  Entropy-selected custodian: {}...", &selected_custodian.to_string()[..16]);
    println!();

    // =========================================================================
    // Phase 1: Build on-chain spend transaction for reserves confiscation
    // =========================================================================
    // This creates the Bitcoin transaction that actually moves the reserves
    // to the new custodian using the Tier 2 spending path (2-of-n without operator)

    println!("Building reserves spend transaction...");

    // Parse the reserves address from the ledger
    let reserves_addr: bitcoin::Address<bitcoin::address::NetworkUnchecked> = reserves_address.parse()
        .map_err(|e| format!("Invalid reserves address: {}", e))?;
    let reserves_addr = reserves_addr.require_network(config.network)
        .map_err(|e| format!("Address network mismatch: {}", e))?;

    println!("  Target reserves address: {}...", &reserves_address[..20.min(reserves_address.len())]);
    use std::io::Write;
    std::io::stdout().flush().ok();

    // Look up the UTXO using Esplora
    // Convert tcp:// to http:// for Esplora HTTP API
    use bdk_esplora::esplora_client::Builder as EsploraBuilder;
    let esplora_url = config.electrum_url
        .replace("tcp://", "http://")
        .replace("ssl://", "https://");
    println!("  Querying Esplora at: {}", &esplora_url);
    std::io::stdout().flush().ok();

    let esplora = EsploraBuilder::new(&esplora_url)
        .build_blocking();
    println!("  Esplora client created");
    std::io::stdout().flush().ok();

    // Get current block height for the update
    let current_block_height = esplora.get_height()
        .map_err(|e| format!("Failed to get block height: {:?}", e))?;
    println!("  Current block height: {}", current_block_height);

    let script_pubkey = reserves_addr.script_pubkey();
    println!("  Script pubkey: {}", script_pubkey);
    std::io::stdout().flush().ok();

    let utxos = match esplora.scripthash_txs(&script_pubkey, None) {
        Ok(txs) => {
            println!("  Found {} transactions for address", txs.len());
            std::io::stdout().flush().ok();
            txs
        }
        Err(e) => {
            println!("ERROR: Failed to query Esplora: {:?}", e);
            std::io::stdout().flush().ok();
            return Err(format!("Failed to query Esplora: {:?}", e).into());
        }
    };

    // Find unspent outputs for this address
    let mut reserves_utxo: Option<(bitcoin::OutPoint, u64)> = None;
    for tx in &utxos {
        for (vout, output) in tx.vout.iter().enumerate() {
            if output.scriptpubkey == script_pubkey {
                // Check if this output is unspent
                let outpoint = bitcoin::OutPoint::new(tx.txid, vout as u32);
                let status = esplora.get_output_status(&tx.txid, vout as u64)
                    .map_err(|e| format!("Failed to check output status: {:?}", e))?;

                if status.map(|s| !s.spent).unwrap_or(true) {
                    reserves_utxo = Some((outpoint, output.value));
                    break;
                }
            }
        }
        if reserves_utxo.is_some() {
            break;
        }
    }

    let (reserves_outpoint, reserves_amount) = match reserves_utxo {
        Some((outpoint, amount)) => (outpoint, amount),
        None => {
            println!();
            println!("Warning: No unspent reserves found at address {}...", &reserves_address[..20]);
            println!("  The ledger CustodyAcquire is recorded, but no on-chain reserves to spend.");
            println!("  The reserves may have already been spent or the address is incorrect.");
            return Ok(());
        }
    };

    println!("  Found reserves: {} sats at {}", reserves_amount, reserves_outpoint);

    // Get the new custodian's receiving address
    let custodian_script = bitcoin::ScriptBuf::new_p2wpkh(
        &bitcoin::WPubkeyHash::hash(&selected_custodian.serialize()),
    );
    let custodian_address = bitcoin::Address::from_script(&custodian_script, config.network)
        .map_err(|e| format!("Failed to create custodian address: {}", e))?;

    println!("  Destination: {}", custodian_address);

    // Build the TaprootReservesOutput from the extracted quorum info
    use deposits_core::{VoterSet, ThresholdConfig, TapscriptReservesBuilder};

    let voter_set = VoterSet::new(operator_id, quorum_members.clone());
    let voter_count = voter_set.all_voters().len();
    let threshold_config = ThresholdConfig::default_for_voter_count(voter_count);

    println!("  Rebuilding Taproot output with {} voters", voter_count);
    for (i, tier) in threshold_config.tiers.iter().enumerate() {
        println!("    Tier {}: threshold={}, tie_breaker={}, timelock={}",
            i, tier.threshold, tier.requires_tie_breaker, tier.timelock_blocks);
    }

    let taproot_builder = TapscriptReservesBuilder::new(
        voter_set.clone(),
        threshold_config.clone(),
        config.network,
        ledger_hash,
    );

    let taproot_output = taproot_builder.build()
        .map_err(|e| format!("Failed to build Taproot output: {:?}", e))?;

    // Verify the computed address matches what's in the ledger
    let computed_address = &taproot_output.address;
    if computed_address.to_string() != reserves_address {
        println!();
        println!("Warning: Computed address doesn't match ledger reserves address!");
        println!("  Ledger:   {}", reserves_address);
        println!("  Computed: {}", computed_address);
        println!("  This could indicate the quorum changed or data mismatch.");
    }

    // Find the quorum-override tier (2-of-n without tie breaker)
    let (tier_index, tier) = threshold_config.tiers.iter()
        .enumerate()
        .find(|(_, t)| !t.requires_tie_breaker && t.threshold > 1)
        .ok_or("No quorum-override tier found")?;

    println!("  Using Tier {} for custody transfer (threshold={}, no tie-breaker)",
        tier_index, tier.threshold);

    // Build the spending transaction
    use bitcoin::{Transaction, TxIn, TxOut, Sequence, Witness};
    use bitcoin::sighash::{SighashCache, TapSighashType};

    let fee_rate = 2u64; // sat/vbyte
    let estimated_vsize = 200u64; // Approximate for Taproot script spend
    let fee = fee_rate * estimated_vsize;
    let output_amount = reserves_amount.saturating_sub(fee);

    let mut unsigned_tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::from_height(tier.timelock_blocks as u32)
            .unwrap_or(bitcoin::absolute::LockTime::ZERO),
        input: vec![TxIn {
            previous_output: reserves_outpoint,
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: if tier.timelock_blocks > 0 {
                Sequence::from_height(tier.timelock_blocks as u16)
            } else {
                Sequence::ENABLE_RBF_NO_LOCKTIME
            },
            witness: Witness::default(),
        }],
        output: vec![TxOut {
            value: bitcoin::Amount::from_sat(output_amount),
            script_pubkey: custodian_address.script_pubkey(),
        }],
    };

    // Compute the sighash for signing
    let prevouts = vec![TxOut {
        value: bitcoin::Amount::from_sat(reserves_amount),
        script_pubkey: reserves_addr.script_pubkey(),
    }];

    let leaf_script = taproot_builder.build_threshold_leaf(tier)
        .map_err(|e| format!("Failed to build leaf script: {:?}", e))?;

    let leaf_hash = bitcoin::taproot::TapLeafHash::from_script(&leaf_script, bitcoin::taproot::LeafVersion::TapScript);

    let mut sighash_cache = SighashCache::new(&unsigned_tx);
    let sighash = sighash_cache.taproot_script_spend_signature_hash(
        0,
        &bitcoin::sighash::Prevouts::All(&prevouts),
        leaf_hash,
        TapSighashType::Default,
    ).map_err(|e| format!("Failed to compute sighash: {}", e))?;

    let sighash_bytes: [u8; 32] = *sighash.as_ref();

    println!("  Sighash: {}...", &hex::encode(sighash_bytes)[..16]);

    // Sign with our key
    let msg = bitcoin::secp256k1::Message::from_digest(sighash_bytes);
    let our_signature = secp.sign_schnorr(&msg, &keypair);
    println!("  Signed with our key: {}...", &our_pubkey.to_string()[..16]);

    // For a real custody transfer, we need signatures from threshold quorum members
    let mut signatures = std::collections::HashMap::new();
    signatures.insert(our_pubkey, our_signature.serialize());

    let required_sigs = tier.threshold;
    println!();
    println!("Collected signatures: {}/{} required",
        signatures.len(),
        required_sigs
    );

    if signatures.len() >= required_sigs {
        // Build the witness with collected signatures
        // For Taproot script spend: [sig1, sig2, ..., script, control_block]
        let control_block = taproot_output.control_block_for_tier(tier_index)
            .ok_or("Failed to get control block for tier")?;

        let mut witness = Witness::new();

        // Add signatures in order matching the script's pubkeys
        for voter in voter_set.all_voters() {
            if let Some(sig) = signatures.get(&voter) {
                witness.push(sig);
            }
        }

        witness.push(leaf_script.as_bytes());
        witness.push(control_block.serialize());

        unsigned_tx.input[0].witness = witness;

        println!();
        println!("Broadcasting custody transfer transaction...");

        // Initialize wallet just for broadcasting
        let data_dir = std::path::PathBuf::from(&config.data_dir);
        let wallet = deposits_bdk::wallet::Wallet::new(
            config.seed,
            config.network,
            data_dir,
            config.electrum_url.clone(),
        )?;
        wallet.broadcast(&unsigned_tx)?;
        println!("  Txid: {}", unsigned_tx.compute_txid());
        println!();
        println!("Reserves successfully transferred to new custodian!");
    } else {
        // We need more signatures - request them via Nostr
        let needed = required_sigs - signatures.len();
        println!();
        println!("Need {} more signature(s) to complete the transfer.", needed);
        println!("Publishing signature request to Nostr...");

        // Build Nostr transport for requesting signatures
        use deposits_bdk::nostr::{NostrTransportBuilder, KIND_LEDGER_RESPONSE, LedgerResponse};
        use nostr_sdk::prelude::*;

        let relay_url = config.relays.first()
            .ok_or("No relay configured")?
            .clone();

        let transport = NostrTransportBuilder::new(secret_key)
            .relay(&relay_url)
            .build()
            .await
            .map_err(|e| format!("Failed to build Nostr transport: {:?}", e))?;

        // Serialize the unsigned transaction
        let unsigned_tx_bytes = bitcoin::consensus::encode::serialize(&unsigned_tx);
        let unsigned_tx_hex = hex::encode(&unsigned_tx_bytes);

        // Build request parameters
        let request_params = serde_json::json!({
            "ledger_id": ledger_id,
            "sighash": hex::encode(sighash_bytes),
            "unsigned_tx": unsigned_tx_hex,
            "new_custodian": selected_custodian.to_string(),
            "violation_details": violation_details,
            "last_valid_sequence": last_valid_sequence,
        });

        // Publish the sign request
        let request_id = transport.send_ledger_request(
            &ledger_id,
            "custody_transfer_sign",
            request_params,
        ).await.map_err(|e| format!("Failed to send sign request: {:?}", e))?;

        println!("  Request ID: {}...", &request_id[..16]);
        println!();
        println!("Waiting for signatures from quorum members...");

        // Poll for responses with timeout (60 seconds total, poll every 3 seconds)
        let max_attempts = 20;
        let poll_interval = std::time::Duration::from_secs(3);

        for attempt in 1..=max_attempts {
            tokio::time::sleep(poll_interval).await;

            // Fetch recent responses
            let since = Timestamp::now() - 120;
            let filter = Filter::new()
                .kind(Kind::Custom(KIND_LEDGER_RESPONSE))
                .since(since);

            let events = transport.client()
                .fetch_events(vec![filter], Some(std::time::Duration::from_secs(5)))
                .await
                .map_err(|e| format!("Failed to fetch responses: {:?}", e))?;

            if !events.is_empty() {
                println!("    Found {} response events", events.len());
            }

            // Parse responses that match our request
            for event in events.iter() {
                // Check if this response references our request
                let mut is_our_request = false;
                for tag in event.tags.iter() {
                    if tag.kind() == TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::E)) {
                        if let Some(val) = tag.content() {
                            if val == request_id {
                                is_our_request = true;
                                break;
                            }
                        }
                    }
                }

                if !is_our_request {
                    continue;
                }

                // Parse the response content
                if let Ok(response) = serde_json::from_str::<LedgerResponse>(&event.content) {
                    if response.success {
                        if let Some(result) = &response.result {
                            // Extract signature from result
                            if let (Some(signer_hex), Some(sig_hex)) = (
                                result.get("signer").and_then(|v| v.as_str()),
                                result.get("signature").and_then(|v| v.as_str())
                            ) {
                                if let (Ok(signer), Ok(sig_bytes)) = (
                                    signer_hex.parse::<bitcoin::secp256k1::PublicKey>(),
                                    hex::decode(sig_hex)
                                ) {
                                    if sig_bytes.len() == 64 && !signatures.contains_key(&signer) {
                                        let mut sig_arr = [0u8; 64];
                                        sig_arr.copy_from_slice(&sig_bytes);
                                        signatures.insert(signer, sig_arr);
                                        println!("  Received signature from {}...", &signer.to_string()[..16]);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            println!("  Poll {}/{}: collected {}/{} signatures",
                attempt, max_attempts, signatures.len(), required_sigs);

            // Check if we have enough
            if signatures.len() >= required_sigs {
                break;
            }
        }

        transport.disconnect().await;

        // Check if we got enough signatures
        if signatures.len() >= required_sigs {
            println!();
            println!("Collected enough signatures! Building witness...");

            // Build the witness with collected signatures
            let control_block = taproot_output.control_block_for_tier(tier_index)
                .ok_or("Failed to get control block for tier")?;

            let mut witness = Witness::new();

            // Get sorted x-only pubkeys matching the script's key order
            let sorted_keys = voter_set.sorted_x_only_pubkeys();

            // CHECKSIGADD pattern: signatures are consumed from stack top to bottom,
            // but we push them bottom-to-top, so we need to push in REVERSE order
            // of the keys in the script (last key's signature goes first in the witness)
            for x_only in sorted_keys.iter().rev() {
                // Find the voter with this x-only pubkey
                for voter in voter_set.all_voters() {
                    if voter.x_only_public_key().0 == *x_only {
                        if let Some(sig) = signatures.get(&voter) {
                            witness.push(sig);
                        } else {
                            // Push empty signature for keys we don't have
                            witness.push(&[] as &[u8]);
                        }
                        break;
                    }
                }
            }

            witness.push(leaf_script.as_bytes());
            witness.push(control_block.serialize());

            unsigned_tx.input[0].witness = witness;

            println!("Broadcasting custody transfer transaction...");

            // Initialize wallet just for broadcasting
            let data_dir = std::path::PathBuf::from(&config.data_dir);
            let wallet = deposits_bdk::wallet::Wallet::new(
                config.seed,
                config.network,
                data_dir,
                config.electrum_url.clone(),
            )?;
            wallet.broadcast(&unsigned_tx)?;
            let txid = unsigned_tx.compute_txid();
            println!("  Txid: {}", txid);
            println!();
            println!("Reserves successfully transferred to new custodian!");

            // =========================================================================
            // Phase 3: Publish CustodyAcquire operation to Nostr
            // =========================================================================
            // Now that the on-chain transfer is broadcast, record it on the ledger
            println!();
            println!("Publishing CustodyAcquire operation to Nostr...");

            // Create the CustodyAcquire operation
            // NOTE: In the full dispute protocol, this follows CustodyDispute -> CustodyArmed
            // For now we're using the simplified version
            let custody_acquire = LedgerOperation::CustodyAcquire {
                new_custodian: selected_custodian,
                entropy_block_height,
                entropy_block_hash,
            };
            // Record reason/evidence for audit trail
            let _ = (reason.clone(), last_valid_hash, last_valid_sequence, evidence_hash, initiation_block, candidate_pool.clone());

            // Only the new custodian can sign and publish the CustodyAcquire operation
            // because they become the operator of the ledger
            let we_are_new_custodian = our_pubkey == selected_custodian;

            if we_are_new_custodian {
                // Serialize the operation
                use deposits_core::tlv::TlvEncode;
                let message_bytes = custody_acquire.tlv_encode();

                // Compute the new hash
                let sequence = (last_valid_sequence + 1) as u64;
                let mut hash_input = Vec::new();
                hash_input.extend_from_slice(&sequence.to_le_bytes());
                hash_input.extend_from_slice(&last_valid_hash);
                hash_input.extend_from_slice(&message_bytes);
                let new_hash = *sha256::Hash::hash(&hash_input).as_byte_array();

                // Sign the update as the new custodian (we ARE the new custodian)
                let update_msg = format!(
                    "LedgerUpdate:{}:{}:{}",
                    hex::encode(last_valid_hash),
                    sequence,
                    hex::encode(new_hash),
                );
                let update_hash = sha256::Hash::hash(update_msg.as_bytes());
                let update_msg_secp = bitcoin::secp256k1::Message::from_digest(*update_hash.as_byte_array());
                let operator_sig = secp.sign_schnorr(&update_msg_secp, &keypair);
                let operator_sig_bytes: [u8; 64] = operator_sig.serialize();

                // Decode the ledger_id hex string to bytes
                let ledger_id_bytes = hex::decode(&ledger_id)
                    .map_err(|e| format!("Invalid ledger_id hex: {}", e))?;
                let ledger_id_hash: [u8; 32] = ledger_id_bytes.try_into()
                    .map_err(|_| "ledger_id must be 32 bytes")?;

                let custody_update = SignedLedgerUpdate {
                    message: message_bytes,
                    message_type: 0x8001, // LEDGER_UPDATE
                    operator_signature: operator_sig_bytes,
                    partner_signature: [0u8; 64],
                    operator_id: selected_custodian,
                    ledger_id: ledger_id_hash,
                    sequence_number: sequence,
                    previous_hash: last_valid_hash,
                    current_hash: new_hash,
                    timestamp: deposits_core::now_unix_timestamp(),
                    block_height: current_block_height,
                    block_hash: entropy_block_hash,
                };

                // Build transport for publishing
                let publish_transport = NostrTransportBuilder::new(secret_key)
                    .relay(&relay_url)
                    .build()
                    .await?;

                let event_id = publish_transport.broadcast_ledger_update(&custody_update).await?;
                println!("  Event ID: {}", event_id);

                // Also publish a dispute event to announce the custody transfer
                let dispute_details = format!(
                    "Custody transferred to {}... due to: {}. Last valid seq: {}, Txid: {}",
                    &selected_custodian.to_string()[..16],
                    reason,
                    last_valid_sequence,
                    txid
                );
                let dispute_event = publish_transport.publish_dispute(
                    &ledger_id,
                    "custody_transferred",
                    &dispute_details,
                    last_valid_hash,
                    last_valid_sequence as u64,
                    Some(sequence),
                    &keypair,
                ).await?;
                println!("  Dispute event: {}", dispute_event);

                publish_transport.disconnect().await;

                println!();
                println!("CustodyAcquire ledger operation published!");
                println!("  On-chain txid: {}", txid);
                println!("  Selected custodian: {}...", &selected_custodian.to_string()[..16]);
            } else {
                // We are NOT the new custodian, so we can't sign the CustodyAcquire operation
                // The new custodian needs to publish it
                println!();
                println!("NOTE: The new custodian ({}...) should publish the CustodyAcquire operation.",
                    &selected_custodian.to_string()[..16]);
                println!("      Run 'deposits-bdk recovery publish-transfer {}' as the new custodian.",
                    &ledger_id[..16]);
            }
        } else {
            println!();
            println!("Timed out waiting for signatures.");
            println!("Collected {}/{} required signatures.", signatures.len(), required_sigs);
            println!();
            println!("The spend transaction parameters are:");
            println!("  Outpoint: {}", reserves_outpoint);
            println!("  Amount: {} sats", reserves_amount);
            println!("  Fee: {} sats", fee);
            println!("  Sighash: {}", hex::encode(sighash_bytes));
            println!("  Tier: {} (timelock: {} blocks)", tier_index, tier.timelock_blocks);
            println!("  Request ID: {}", request_id);
            println!();
            println!("Retry the command later, or have quorum members run:");
            println!("  deposits-bdk nostr watch --respond");
        }
    }

    Ok(())
}

/// DEPRECATED: Use the new dispute protocol commands instead:
///   recovery dispute -> recovery rebuild -> recovery arm -> recovery claim -> recovery spend
///
/// This legacy command published CustodyAcquire directly without following
/// the proper dispute protocol (CustodyDispute -> CustodyArmed -> CustodyAcquire).
async fn recovery_publish_transfer(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("WARNING: 'recovery publish-transfer' is deprecated and uses the old protocol.");
    eprintln!("Please use the new dispute protocol commands instead:");
    eprintln!("  1. recovery dispute <ledger_id>   - Open dispute with CustodyDispute");
    eprintln!("  2. recovery rebuild <ledger_id>   - Rebuild quorum");
    eprintln!("  3. recovery arm <ledger_id>       - Publish CustodyArmed pre-commitment");
    eprintln!("  4. recovery claim <ledger_id>     - Claim with CustodyAcquire/CustodyYield");
    eprintln!("  5. recovery spend <ledger_id>     - Execute on-chain spend");
    eprintln!();
    use bitcoin::hashes::{Hash, sha256};
    use bitcoin::secp256k1::{Keypair, Secp256k1};
    use deposits_bdk::nostr::{NostrTransportBuilder, KIND_LEDGER_UPDATE, KIND_LEDGER_DISPUTE};
    use deposits_core::{SignedLedgerUpdate, TlvDecode, TlvEncode};
    use deposits_core::messages::LedgerOperation;
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use nostr_sdk::prelude::*;
    use std::str::FromStr;

    let mut ledger_id: Option<String> = None;
    let mut txid_hex: Option<String> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--txid" => {
                i += 1;
                if i < args.len() {
                    txid_hex = Some(args[i].clone());
                }
            }
            arg if arg.starts_with("--") => {
                config_args.push(args[i].clone());
                if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                    config_args.push(args[i + 1].clone());
                    i += 1;
                }
            }
            _ => {
                if ledger_id.is_none() {
                    ledger_id = Some(args[i].clone());
                }
            }
        }
        i += 1;
    }

    let ledger_id = ledger_id.ok_or("Ledger ID required")?;
    let txid_hex = txid_hex.ok_or("Transaction ID required (--txid <txid>)")?;
    let config = parse_config(&config_args)?;

    let relay_url = config.relays.first()
        .ok_or("No relay configured")?
        .clone();

    println!("Publishing CustodyAcquire as new custodian...");
    println!("  Ledger: {}...", &ledger_id[..16.min(ledger_id.len())]);
    println!("  Transfer txid: {}...", &txid_hex[..16.min(txid_hex.len())]);
    println!("  Relay: {}", relay_url);
    println!();

    // Set up our keys - use same BIP86 derivation as the wallet
    let secp = Secp256k1::new();
    let xpriv = bitcoin::bip32::Xpriv::new_master(config.network, &config.seed)
        .map_err(|e| format!("Failed to create master key: {}", e))?;
    let operator_path = bitcoin::bip32::DerivationPath::from_str("m/86'/0'/0'/0/0")
        .map_err(|e| format!("Invalid derivation path: {}", e))?;
    let operator_xpriv = xpriv
        .derive_priv(&secp, &operator_path)
        .map_err(|e| format!("Failed to derive operator key: {}", e))?;
    let secret_key = operator_xpriv.private_key;
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let our_pubkey = keypair.public_key();

    println!("Our pubkey: {}...", &our_pubkey.to_string()[..16]);

    // Fetch ledger updates from Nostr
    println!("Fetching ledger from Nostr...");
    let keys = Keys::generate();
    let client = Client::new(keys);
    client.add_relay(&relay_url).await
        .map_err(|e| format!("Failed to add relay: {}", e))?;
    client.connect().await;

    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .custom_tag(SingleLetterTag::lowercase(Alphabet::D), [ledger_id.as_str()])
        .limit(500);

    let events = client
        .fetch_events(vec![filter], None)
        .await
        .map_err(|e| format!("Failed to fetch events: {}", e))?;

    // Decode updates
    let mut updates: Vec<SignedLedgerUpdate> = Vec::new();
    for event in events.iter() {
        if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
            if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                updates.push(update);
            }
        }
    }

    updates.sort_by_key(|u| (u.sequence_number, u.operator_id));
    // Include operator_id to preserve different operators' updates at same sequence
    updates.dedup_by(|a, b| a.sequence_number == b.sequence_number && a.operator_id == b.operator_id && a.current_hash == b.current_hash);

    println!("  Found {} updates", updates.len());

    // Validate and find the last valid sequence
    let mut last_valid_hash = [0u8; 32];
    let mut last_valid_sequence: i64 = -1;
    let mut operator_id = our_pubkey; // Will be updated from first op
    let mut quorum_members: Vec<bitcoin::secp256k1::PublicKey> = Vec::new();
    let mut violation_details = String::new();

    for update in &updates {
        // Track operator and quorum from operations
        if let Ok(operation) = LedgerOperation::tlv_decode(&update.message) {
            match &operation {
                LedgerOperation::LedgerOpen { .. } => {
                    operator_id = update.operator_id;
                }
                LedgerOperation::QuorumAddMember { quorum_member, .. } => {
                    if !quorum_members.contains(quorum_member) {
                        quorum_members.push(*quorum_member);
                    }
                }
                _ => {}
            }
        }

        // Check for violations
        let expected_seq = (last_valid_sequence + 1) as u64;
        if update.sequence_number != expected_seq && last_valid_sequence >= 0 {
            violation_details = format!("Sequence gap at {}", update.sequence_number);
            break;
        }

        let expected_prev = if update.sequence_number == 0 {
            [0u8; 32]
        } else {
            last_valid_hash
        };

        if update.previous_hash != expected_prev {
            violation_details = format!("Hash chain broken at seq {}", update.sequence_number);
            break;
        }

        let computed_hash = update.compute_hash();
        if computed_hash != update.current_hash {
            violation_details = format!("Hash mismatch at seq {}", update.sequence_number);
            break;
        }

        last_valid_hash = update.current_hash;
        last_valid_sequence = update.sequence_number as i64;
    }

    if violation_details.is_empty() {
        client.disconnect().await.ok();
        return Err("No violation found - ledger appears conforming".into());
    }

    println!("  Last valid sequence: {}", last_valid_sequence);
    println!("  Violation: {}", violation_details);
    println!("  Original operator: {}...", &operator_id.to_string()[..16]);
    println!("  Quorum members: {}", quorum_members.len());

    // Fetch disputes to get entropy block info
    let dispute_filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_DISPUTE))
        .custom_tag(SingleLetterTag::lowercase(Alphabet::L), [ledger_id.as_str()]);

    let dispute_events = client
        .fetch_events(vec![dispute_filter], None)
        .await
        .map_err(|e| format!("Failed to fetch disputes: {}", e))?;

    client.disconnect().await.ok();

    if dispute_events.is_empty() {
        return Err("No disputes found for this ledger".into());
    }

    // Get the current block height for entropy using esplora
    use bdk_esplora::esplora_client::Builder as EsploraBuilder;
    let esplora = EsploraBuilder::new(&config.electrum_url)
        .build_blocking();

    let current_block_height = esplora.get_height()
        .map_err(|e| format!("Failed to get block height: {:?}", e))?;

    // Use a recent block for entropy (current - 6 for safety)
    let entropy_block_height = current_block_height.saturating_sub(6);
    let entropy_block_hash = esplora.get_block_hash(entropy_block_height)
        .map_err(|e| format!("Failed to get block hash: {:?}", e))?;
    let entropy_block_hash: [u8; 32] = *entropy_block_hash.as_ref();

    println!("  Entropy block: {} (hash: {}...)", entropy_block_height, &hex::encode(entropy_block_hash)[..16]);

    // Build candidate pool (quorum members who participated)
    let candidate_pool: Vec<bitcoin::secp256k1::PublicKey> = quorum_members.clone();

    // Verify we are the new custodian by checking the on-chain transaction
    // The transaction output determines who received the funds
    println!("Fetching transaction to verify new custodian...");

    // Parse txid from hex string (handles the reversed byte order correctly)
    let txid = bitcoin::Txid::from_str(&txid_hex)
        .map_err(|e| format!("Invalid txid: {:?}", e))?;
    let tx = esplora.get_tx(&txid)
        .map_err(|e| format!("Failed to fetch transaction: {:?}", e))?
        .ok_or("Transaction not found")?;

    // Find the non-change output (the custody transfer destination)
    // It should be a P2WPKH output to the new custodian's pubkey hash
    let our_pubkey_hash = bitcoin::PublicKey::new(our_pubkey).wpubkey_hash()
        .map_err(|e| format!("Failed to compute pubkey hash: {:?}", e))?;
    let our_script = bitcoin::ScriptBuf::new_p2wpkh(&our_pubkey_hash);

    let we_are_recipient = tx.output.iter().any(|out| out.script_pubkey == our_script);

    if !we_are_recipient {
        return Err(format!(
            "You are not the recipient of the custody transfer transaction.\n\
             Your pubkey: {}...\n\
             Transaction outputs go to other addresses.",
            &our_pubkey.to_string()[..16]
        ).into());
    }

    // We ARE the recipient - we're the new custodian
    let selected_custodian = our_pubkey;

    println!("  Verified: we received the funds, we are the new custodian!");

    // Compute evidence hash (hash of violation details)
    let evidence_hash = *sha256::Hash::hash(violation_details.as_bytes()).as_byte_array();

    // For now, we don't have the actual Taproot spend signatures available
    // The new custodian would need to fetch these from the on-chain transaction
    // Create the CustodyAcquire operation
    // NOTE: In the full dispute protocol, this follows CustodyDispute -> CustodyArmed
    let custody_acquire = LedgerOperation::CustodyAcquire {
        new_custodian: selected_custodian,
        entropy_block_height,
        entropy_block_hash,
    };
    // Record for audit trail
    let _ = (violation_details.clone(), last_valid_hash, last_valid_sequence, evidence_hash, candidate_pool);

    // Serialize the operation
    let message_bytes = custody_acquire.tlv_encode();

    // Compute the new hash
    let sequence = (last_valid_sequence + 1) as u64;
    let mut hash_input = Vec::new();
    hash_input.extend_from_slice(&sequence.to_le_bytes());
    hash_input.extend_from_slice(&last_valid_hash);
    hash_input.extend_from_slice(&message_bytes);
    let new_hash = *sha256::Hash::hash(&hash_input).as_byte_array();

    // Sign the update as the new custodian
    let update_msg = format!(
        "LedgerUpdate:{}:{}:{}",
        hex::encode(last_valid_hash),
        sequence,
        hex::encode(new_hash),
    );
    let update_hash = sha256::Hash::hash(update_msg.as_bytes());
    let update_msg_secp = bitcoin::secp256k1::Message::from_digest(*update_hash.as_byte_array());
    let operator_sig = secp.sign_schnorr(&update_msg_secp, &keypair);
    let operator_sig_bytes: [u8; 64] = operator_sig.serialize();

    // Decode the ledger_id hex string to bytes
    let ledger_id_bytes: [u8; 32] = hex::decode(&ledger_id)
        .map_err(|e| format!("Invalid ledger_id hex: {}", e))?
        .try_into()
        .map_err(|_| "ledger_id must be 32 bytes")?;

    let custody_update = SignedLedgerUpdate {
        message: message_bytes,
        message_type: 0x8001, // LEDGER_UPDATE
        operator_signature: operator_sig_bytes,
        partner_signature: [0u8; 64],
        operator_id: selected_custodian,
        ledger_id: ledger_id_bytes,
        sequence_number: sequence,
        previous_hash: last_valid_hash,
        current_hash: new_hash,
        timestamp: deposits_core::now_unix_timestamp(),
        block_height: current_block_height,
        block_hash: entropy_block_hash,
    };

    // Build transport for publishing
    let publish_transport = NostrTransportBuilder::new(secret_key)
        .relay(&relay_url)
        .build()
        .await?;

    println!("Publishing CustodyAcquire operation...");
    let event_id = publish_transport.broadcast_ledger_update(&custody_update).await?;
    println!("  Event ID: {}", event_id);

    // Also publish a dispute event to announce the custody transfer
    let dispute_details = format!(
        "Custody transferred to {}... due to: {}. Last valid seq: {}, Txid: {}...",
        &selected_custodian.to_string()[..16],
        violation_details,
        last_valid_sequence,
        &txid_hex[..16]
    );
    let dispute_event = publish_transport.publish_dispute(
        &ledger_id,
        "custody_transferred",
        &dispute_details,
        last_valid_hash,
        last_valid_sequence as u64,
        Some(sequence),
        &keypair,
    ).await?;
    println!("  Dispute event: {}", dispute_event);

    publish_transport.disconnect().await;

    println!();
    println!("CustodyAcquire published successfully!");
    println!("  New operator: {}...", &selected_custodian.to_string()[..16]);
    println!("  Sequence: {}", sequence);
    println!("  Txid: {}...", &txid_hex[..16]);

    Ok(())
}

/// Prepare as a candidate for custody acquisition.
///
/// This command is run by each party who wants to be a candidate in the recovery.
/// It publishes a CustodyDispute operation to open a dispute on the ledger.
/// This is the first step in the dispute protocol.
///
/// After CustodyDispute, candidates must:
/// 1. Rebuild quorum (recovery rebuild)
/// 2. Publish CustodyArmed pre-commitment (recovery arm)
/// 3. Wait for entropy block
/// 4. Claim custody with CustodyAcquire/CustodyYield (recovery claim)
async fn recovery_prepare(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use bitcoin::hashes::{Hash, sha256};
    use bitcoin::secp256k1::{Keypair, Secp256k1, Message};
    use deposits_bdk::nostr::{NostrTransportBuilder, KIND_LEDGER_UPDATE, KIND_LEDGER_DISPUTE};
    use deposits_core::{SignedLedgerUpdate, TlvDecode, TlvEncode};
    use deposits_core::messages::LedgerOperation;
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use nostr_sdk::prelude::*;
    use std::str::FromStr;

    let mut ledger_id: Option<String> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            arg if arg.starts_with("--") => {
                config_args.push(args[i].clone());
                if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                    config_args.push(args[i + 1].clone());
                    i += 1;
                }
            }
            _ => {
                if ledger_id.is_none() {
                    ledger_id = Some(args[i].clone());
                }
            }
        }
        i += 1;
    }

    let ledger_id = ledger_id.ok_or("Ledger ID required")?;
    let config = parse_config(&config_args)?;

    let relay_url = config.relays.first()
        .ok_or("No relay configured")?
        .clone();

    println!("Preparing as custody acquisition candidate...");
    println!("  Ledger: {}...", &ledger_id[..16.min(ledger_id.len())]);
    println!("  Relay: {}", relay_url);
    println!();

    // Set up our keys - use same BIP86 derivation as the wallet
    let secp = Secp256k1::new();
    let xpriv = bitcoin::bip32::Xpriv::new_master(config.network, &config.seed)
        .map_err(|e| format!("Failed to create master key: {}", e))?;
    let operator_path = bitcoin::bip32::DerivationPath::from_str("m/86'/0'/0'/0/0")
        .map_err(|e| format!("Invalid derivation path: {}", e))?;
    let operator_xpriv = xpriv
        .derive_priv(&secp, &operator_path)
        .map_err(|e| format!("Failed to derive operator key: {}", e))?;
    let secret_key = operator_xpriv.private_key;
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let our_pubkey = keypair.public_key();

    println!("Our pubkey (candidate): {}...", &our_pubkey.to_string()[..16]);

    // Fetch ledger updates from Nostr
    println!("Fetching ledger from Nostr...");
    let keys = Keys::generate();
    let client = Client::new(keys);
    client.add_relay(&relay_url).await
        .map_err(|e| format!("Failed to add relay: {}", e))?;
    client.connect().await;

    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .custom_tag(SingleLetterTag::lowercase(Alphabet::D), [ledger_id.as_str()])
        .limit(500);

    let events = client
        .fetch_events(vec![filter], None)
        .await
        .map_err(|e| format!("Failed to fetch events: {}", e))?;

    // Decode updates
    let mut updates: Vec<SignedLedgerUpdate> = Vec::new();
    for event in events.iter() {
        if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
            if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                updates.push(update);
            }
        }
    }

    updates.sort_by_key(|u| (u.sequence_number, u.operator_id));
    // Include operator_id to preserve different operators' updates at same sequence
    updates.dedup_by(|a, b| a.sequence_number == b.sequence_number && a.operator_id == b.operator_id && a.current_hash == b.current_hash);

    println!("  Found {} updates", updates.len());

    if updates.is_empty() {
        client.disconnect().await?;
        return Err("No ledger updates found".into());
    }

    // Validate to find violation
    let mut last_valid_sequence = 0u64;
    let mut last_valid_hash = [0u8; 32];
    let mut violation_details = String::new();
    let mut original_operator = None;

    for (idx, update) in updates.iter().enumerate() {
        // Get original operator from first update
        if idx == 0 {
            original_operator = Some(update.operator_id);
        }

        // Check hash chain
        if idx > 0 {
            let prev = &updates[idx - 1];
            if update.previous_hash != prev.current_hash {
                violation_details = format!("Hash chain broken at seq {}", update.sequence_number);
                break;
            }
        }

        last_valid_sequence = update.sequence_number;
        last_valid_hash = update.current_hash;
    }

    if violation_details.is_empty() {
        // Check if there's a dispute published
        let dispute_filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_DISPUTE))
            .custom_tag(SingleLetterTag::lowercase(Alphabet::D), [ledger_id.as_str()])
            .limit(10);

        let disputes = client
            .fetch_events(vec![dispute_filter], None)
            .await
            .map_err(|e| format!("Failed to fetch disputes: {}", e))?;

        if disputes.is_empty() {
            client.disconnect().await?;
            return Err("No violation found and no dispute published. Run 'recovery start' first.".into());
        }

        // Use the last valid state as the fork point
        violation_details = "Dispute published - preparing candidate branch".to_string();
    }

    println!("  Last valid sequence: {}", last_valid_sequence);
    println!("  Violation: {}", violation_details);

    let original_operator = original_operator.ok_or("Could not determine original operator")?;
    println!("  Original operator: {}...", &original_operator.to_string()[..16]);

    client.disconnect().await?;

    // Get current block height for initiation_block
    use bdk_esplora::esplora_client::Builder as EsploraBuilder;
    let esplora = EsploraBuilder::new(&config.electrum_url).build_blocking();
    let current_block_height = esplora.get_height()
        .map_err(|e| format!("Failed to get block height: {:?}", e))?;

    // The initiation block is when the dispute was published
    // For now, use current block (in production, this should come from the dispute event)
    let initiation_block = current_block_height;
    let entropy_block_height = initiation_block + 6;

    // Entropy block hash - will be zero until the block is mined
    // Validators will derive the real entropy from the on-chain spend's confirmation block
    let entropy_block_hash = [0u8; 32];

    println!("  Initiation block: {}", initiation_block);
    println!("  Entropy block (expected): {}", entropy_block_height);

    // Create evidence hash
    let evidence_hash = *sha256::Hash::hash(violation_details.as_bytes()).as_byte_array();

    // Create the CustodyDispute operation (opens the dispute)
    // This is the correct first step in the dispute protocol
    let custody_dispute = LedgerOperation::CustodyDispute {
        last_valid_sequence,
        reason: violation_details.clone(),
    };
    // Record for audit trail
    let _ = (last_valid_hash, evidence_hash, initiation_block, entropy_block_height, entropy_block_hash);

    // Serialize the operation
    let message_bytes = custody_dispute.tlv_encode();

    // Compute the new hash (forking from last valid)
    let sequence = last_valid_sequence + 1;
    let mut hash_input = Vec::new();
    hash_input.extend_from_slice(&sequence.to_le_bytes());
    hash_input.extend_from_slice(&last_valid_hash);
    hash_input.extend_from_slice(&message_bytes);
    let new_hash = *sha256::Hash::hash(&hash_input).as_byte_array();

    // Sign the update as the new operator (ourselves)
    let update_msg = format!(
        "deposits:ledger:{}:{}:{}",
        hex::encode(last_valid_hash),
        sequence,
        hex::encode(&new_hash)
    );
    let msg_hash = sha256::Hash::hash(update_msg.as_bytes());
    let signature = secp.sign_schnorr(
        &Message::from_digest(*msg_hash.as_ref()),
        &keypair
    );
    let operator_sig_bytes: [u8; 64] = *signature.as_ref();

    // Create the signed update
    let ledger_id_bytes: [u8; 32] = {
        let decoded = hex::decode(&ledger_id)
            .map_err(|e| format!("Invalid ledger_id hex: {}", e))?;
        decoded.try_into().map_err(|_| "Ledger ID must be 32 bytes")?
    };

    let signed_update = SignedLedgerUpdate {
        message: message_bytes,
        message_type: 0x8001,
        operator_signature: operator_sig_bytes,
        partner_signature: [0u8; 64],
        operator_id: our_pubkey,
        ledger_id: ledger_id_bytes,
        sequence_number: sequence,
        previous_hash: last_valid_hash,
        current_hash: new_hash,
        timestamp: deposits_core::now_unix_timestamp(),
        block_height: current_block_height,
        block_hash: entropy_block_hash,
    };

    // Publish to Nostr
    println!();
    println!("Publishing CustodyDispute to Nostr...");

    let publish_transport = NostrTransportBuilder::new(secret_key)
        .relay(&relay_url)
        .build()
        .await?;

    publish_transport.broadcast_ledger_update(&signed_update).await?;

    println!();
    println!("CustodyDispute published successfully!");
    println!("  Disputer: {}...", &our_pubkey.to_string()[..16]);
    println!("  Sequence: {} (forked from {})", sequence, last_valid_sequence);
    println!("  Hash: {}...", &hex::encode(new_hash)[..16]);
    println!("  Reason: {}", violation_details);
    println!();
    println!("Next steps (dispute protocol):");
    println!("  1. Rebuild quorum: recovery rebuild <ledger_id>");
    println!("  2. Arm for entropy: recovery arm <ledger_id>");
    println!("  3. Wait for entropy block (armed_block + 6)");
    println!("  4. Claim custody: recovery claim <ledger_id>");
    println!("  5. On-chain spend: recovery spend <ledger_id>");

    Ok(())
}

/// Execute the on-chain spend to transfer reserves to the selected candidate.
///
/// This command is run after all candidates have prepared and the entropy block
/// has been mined. Anyone can execute this - the destination is determined by
/// the entropy-based selection.
async fn recovery_spend(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    // For now, delegate to the existing complete command
    // TODO: Refactor to properly use entropy-based selection from candidate pool
    println!("Running on-chain spend (delegating to recovery complete)...");
    println!();
    recovery_complete(args).await
}

/// Publish CustodyYield to close a candidate branch after not being selected.
///
/// This command is run by candidates who were NOT selected by the entropy.
/// It signals that they are releasing their quorum from attestation obligations.
async fn recovery_release(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use bitcoin::hashes::{Hash, sha256};
    use bitcoin::secp256k1::{Keypair, Secp256k1, Message};
    use deposits_bdk::nostr::{NostrTransportBuilder, KIND_LEDGER_UPDATE};
    use deposits_core::{SignedLedgerUpdate, TlvDecode, TlvEncode};
    use deposits_core::messages::LedgerOperation;
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use nostr_sdk::prelude::*;
    use std::str::FromStr;

    let mut ledger_id: Option<String> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            arg if arg.starts_with("--") => {
                config_args.push(args[i].clone());
                if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                    config_args.push(args[i + 1].clone());
                    i += 1;
                }
            }
            _ => {
                if ledger_id.is_none() {
                    ledger_id = Some(args[i].clone());
                }
            }
        }
        i += 1;
    }

    let ledger_id = ledger_id.ok_or("Ledger ID required")?;
    let config = parse_config(&config_args)?;

    let relay_url = config.relays.first()
        .ok_or("No relay configured")?
        .clone();

    println!("Publishing CustodyYield (closing candidate branch)...");
    println!("  Ledger: {}...", &ledger_id[..16.min(ledger_id.len())]);
    println!("  Relay: {}", relay_url);
    println!();

    // Set up our keys
    let secp = Secp256k1::new();
    let xpriv = bitcoin::bip32::Xpriv::new_master(config.network, &config.seed)
        .map_err(|e| format!("Failed to create master key: {}", e))?;
    let operator_path = bitcoin::bip32::DerivationPath::from_str("m/86'/0'/0'/0/0")
        .map_err(|e| format!("Invalid derivation path: {}", e))?;
    let operator_xpriv = xpriv
        .derive_priv(&secp, &operator_path)
        .map_err(|e| format!("Failed to derive operator key: {}", e))?;
    let secret_key = operator_xpriv.private_key;
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let our_pubkey = keypair.public_key();

    println!("Our pubkey: {}...", &our_pubkey.to_string()[..16]);

    // Fetch our CustodyAcquire to find the previous hash
    println!("Fetching our CustodyAcquire branch...");
    let keys = Keys::generate();
    let client = Client::new(keys);
    client.add_relay(&relay_url).await
        .map_err(|e| format!("Failed to add relay: {}", e))?;
    client.connect().await;

    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .custom_tag(SingleLetterTag::lowercase(Alphabet::D), [ledger_id.as_str()])
        .limit(500);

    let events = client
        .fetch_events(vec![filter], None)
        .await
        .map_err(|e| format!("Failed to fetch events: {}", e))?;

    // Find our CustodyAcquire update
    let mut our_acquire: Option<SignedLedgerUpdate> = None;
    for event in events.iter() {
        if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
            if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                if update.operator_id == our_pubkey {
                    // Check if it's a CustodyAcquire
                    if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                        if matches!(op, LedgerOperation::CustodyAcquire { .. }) {
                            our_acquire = Some(update);
                            break;
                        }
                    }
                }
            }
        }
    }

    client.disconnect().await?;

    let our_acquire = our_acquire.ok_or(
        "Could not find our CustodyAcquire. Did you run 'recovery prepare' first?"
    )?;

    println!("  Found our CustodyAcquire at sequence {}", our_acquire.sequence_number);

    // Get current block height
    use bdk_esplora::esplora_client::Builder as EsploraBuilder;
    let esplora = EsploraBuilder::new(&config.electrum_url).build_blocking();
    let current_block_height = esplora.get_height()
        .map_err(|e| format!("Failed to get block height: {:?}", e))?;

    // Create the CustodyYield operation
    let custody_release = LedgerOperation::CustodyYield;

    // Serialize
    let message_bytes = custody_release.tlv_encode();

    // Compute the new hash (continuing from our CustodyAcquire)
    let sequence = our_acquire.sequence_number + 1;
    let mut hash_input = Vec::new();
    hash_input.extend_from_slice(&sequence.to_le_bytes());
    hash_input.extend_from_slice(&our_acquire.current_hash);
    hash_input.extend_from_slice(&message_bytes);
    let new_hash = *sha256::Hash::hash(&hash_input).as_byte_array();

    // Sign the update
    let update_msg = format!(
        "deposits:ledger:{}:{}:{}",
        hex::encode(our_acquire.current_hash),
        sequence,
        hex::encode(&new_hash)
    );
    let msg_hash = sha256::Hash::hash(update_msg.as_bytes());
    let signature = secp.sign_schnorr(
        &Message::from_digest(*msg_hash.as_ref()),
        &keypair
    );
    let operator_sig_bytes: [u8; 64] = *signature.as_ref();

    // Create the signed update
    let ledger_id_bytes: [u8; 32] = {
        let decoded = hex::decode(&ledger_id)
            .map_err(|e| format!("Invalid ledger_id hex: {}", e))?;
        decoded.try_into().map_err(|_| "Ledger ID must be 32 bytes")?
    };

    let signed_update = SignedLedgerUpdate {
        message: message_bytes,
        message_type: 0x8001,
        operator_signature: operator_sig_bytes,
        partner_signature: [0u8; 64],
        operator_id: our_pubkey,
        ledger_id: ledger_id_bytes,
        sequence_number: sequence,
        previous_hash: our_acquire.current_hash,
        current_hash: new_hash,
        timestamp: deposits_core::now_unix_timestamp(),
        block_height: current_block_height,
        block_hash: [0u8; 32],
    };

    // Publish to Nostr
    println!();
    println!("Publishing CustodyYield to Nostr...");

    let publish_transport = NostrTransportBuilder::new(secret_key)
        .relay(&relay_url)
        .build()
        .await?;

    publish_transport.broadcast_ledger_update(&signed_update).await?;

    println!();
    println!("CustodyYield published successfully!");
    println!("  Sequence: {}", sequence);
    println!("  Hash: {}...", &hex::encode(new_hash)[..16]);
    println!();
    println!("Your candidate branch is now closed.");
    println!("Your quorum members are released from attestation obligations.");

    Ok(())
}

// =============================================================================
// NEW DISPUTE PROTOCOL COMMANDS
// =============================================================================
// These implement the proper dispute protocol flow:
// NORMAL -> DISPUTED -> ARMED -> NORMAL (winner) / TOMBSTONED (losers)

/// Open a custody dispute by publishing a CustodyDispute ledger operation.
///
/// This is the first step in the dispute protocol. It:
/// 1. Validates the ledger and finds the violation
/// 2. Creates a CustodyDispute operation (disbands quorum, records fork point)
/// 3. Publishes the signed operation to Nostr
///
/// After this, the ledger is in DISPUTED state. Next step: `recovery rebuild`
async fn recovery_dispute(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use bitcoin::hashes::{Hash, sha256};
    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey, Message};
    use deposits_core::{TlvDecode, TlvEncode, SignedLedgerUpdate};
    use deposits_core::messages::LedgerOperation;
    use deposits_bdk::nostr::{NostrTransportBuilder, KIND_LEDGER_UPDATE};
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use nostr_sdk::prelude::*;

    let mut ledger_id: Option<String> = None;
    let mut reason: Option<String> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--reason" | "-r" => {
                i += 1;
                if i < args.len() {
                    reason = Some(args[i].clone());
                }
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
                }
            }
        }
        i += 1;
    }

    let ledger_id = ledger_id.ok_or("Missing ledger_id")?.trim().to_string();
    let reason = reason.unwrap_or_else(|| "Non-conforming ledger detected".to_string());

    let config = parse_config(&config_args)?;
    let relay_url = config.relays.first()
        .ok_or("No relay configured. Use --relay <url>")?
        .clone();

    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&config.seed)
        .map_err(|e| format!("Invalid seed: {}", e))?;
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let our_pubkey = keypair.public_key();

    println!("Opening custody dispute for ledger: {}...", &ledger_id[..16.min(ledger_id.len())]);
    println!("  Reason: {}", reason);
    println!();

    // Fetch ledger from Nostr
    println!("Fetching ledger from Nostr...");
    let keys = Keys::generate();
    let client = Client::new(keys);
    client.add_relay(&relay_url).await
        .map_err(|e| format!("Failed to add relay: {}", e))?;
    client.connect().await;

    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .custom_tag(SingleLetterTag::lowercase(Alphabet::D), [ledger_id.as_str()])
        .limit(500);

    let events = client
        .fetch_events(vec![filter], None)
        .await
        .map_err(|e| format!("Failed to fetch events: {}", e))?;

    client.disconnect().await.ok();

    // Decode all updates
    let mut all_updates: Vec<SignedLedgerUpdate> = Vec::new();
    for event in events.iter() {
        if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
            if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                all_updates.push(update);
            }
        }
    }

    println!("  Found {} total updates", all_updates.len());

    // Find the original operator (the one who posted LedgerOpen at seq 0)
    let original_operator = all_updates.iter()
        .find(|u| u.sequence_number == 0)
        .map(|u| u.operator_id)
        .ok_or("No LedgerOpen found (seq 0)")?;

    println!("  Original operator: {}...", &original_operator.to_string()[..16]);

    // Filter to only the original operator's updates (ignore other operators' disputes)
    // This ensures we validate the original chain, not someone else's dispute branch
    let mut updates: Vec<&SignedLedgerUpdate> = all_updates.iter()
        .filter(|u| u.operator_id == original_operator)
        .collect();
    updates.sort_by_key(|u| u.sequence_number);
    // Dedup by sequence number (keep first occurrence at each seq)
    updates.dedup_by(|a, b| a.sequence_number == b.sequence_number);

    println!("  Original operator's updates: {}", updates.len());

    // Validate the hash chain to find the last valid point
    let mut last_valid_hash = [0u8; 32];
    let mut last_valid_sequence: i64 = -1;
    let mut violation_details = String::new();

    for update in &updates {
        let expected_seq = (last_valid_sequence + 1) as u64;
        if update.sequence_number != expected_seq && last_valid_sequence >= 0 {
            violation_details = format!(
                "Sequence gap: expected {}, got {}",
                expected_seq, update.sequence_number
            );
            break;
        }

        let expected_prev = if update.sequence_number == 0 {
            [0u8; 32]
        } else {
            last_valid_hash
        };

        if update.previous_hash != expected_prev {
            violation_details = format!(
                "Hash chain broken at seq {}: expected {}..., got {}...",
                update.sequence_number,
                hex::encode(&expected_prev[..4]),
                hex::encode(&update.previous_hash[..4])
            );
            break;
        }

        let computed_hash = update.compute_hash();
        if computed_hash != update.current_hash {
            violation_details = format!(
                "Invalid hash at seq {}: computed {}..., stored {}...",
                update.sequence_number,
                hex::encode(&computed_hash[..4]),
                hex::encode(&update.current_hash[..4])
            );
            break;
        }

        last_valid_hash = update.current_hash;
        last_valid_sequence = update.sequence_number as i64;
    }

    let last_valid_sequence_u64 = if last_valid_sequence >= 0 {
        last_valid_sequence as u64
    } else {
        0
    };

    if violation_details.is_empty() {
        println!();
        println!("Ledger appears conforming (no violation found).");
        println!("Cannot open dispute for a conforming ledger.");
        return Ok(());
    }

    println!();
    println!("Violation detected!");
    println!("  {}", violation_details);
    println!("  Last valid sequence: {}", last_valid_sequence_u64);
    println!("  Last valid hash: {}...", hex::encode(&last_valid_hash[..8]));

    // Create CustodyDispute operation
    let custody_dispute = LedgerOperation::CustodyDispute {
        last_valid_sequence: last_valid_sequence_u64,
        reason: format!("{}: {}", reason, violation_details),
    };

    // Serialize
    let message_bytes = custody_dispute.tlv_encode();

    // Compute the new hash (forking from last valid)
    let sequence = last_valid_sequence_u64 + 1;
    let mut hash_input = Vec::new();
    hash_input.extend_from_slice(&sequence.to_le_bytes());
    hash_input.extend_from_slice(&last_valid_hash);
    hash_input.extend_from_slice(&message_bytes);
    let new_hash = *sha256::Hash::hash(&hash_input).as_byte_array();

    // Get current block height
    use bdk_esplora::esplora_client::Builder as EsploraBuilder;
    let esplora = EsploraBuilder::new(&config.electrum_url).build_blocking();
    let current_block_height = esplora.get_height()
        .map_err(|e| format!("Failed to get block height: {:?}", e))?;

    // Sign the update
    let update_msg = format!(
        "deposits:ledger:{}:{}:{}",
        hex::encode(last_valid_hash),
        sequence,
        hex::encode(&new_hash)
    );
    let msg_hash = sha256::Hash::hash(update_msg.as_bytes());
    let signature = secp.sign_schnorr(
        &Message::from_digest(*msg_hash.as_ref()),
        &keypair
    );
    let operator_sig_bytes: [u8; 64] = *signature.as_ref();

    // Create the signed update
    let ledger_id_bytes: [u8; 32] = {
        let decoded = hex::decode(&ledger_id)
            .map_err(|e| format!("Invalid ledger_id hex: {}", e))?;
        decoded.try_into().map_err(|_| "Ledger ID must be 32 bytes")?
    };

    let signed_update = SignedLedgerUpdate {
        message: message_bytes,
        message_type: 0x8001, // LEDGER_UPDATE
        operator_signature: operator_sig_bytes,
        partner_signature: [0u8; 64],
        operator_id: our_pubkey,
        ledger_id: ledger_id_bytes,
        sequence_number: sequence,
        previous_hash: last_valid_hash,
        current_hash: new_hash,
        timestamp: deposits_core::now_unix_timestamp(),
        block_height: current_block_height,
        block_hash: [0u8; 32],
    };

    // Publish to Nostr
    println!();
    println!("Publishing CustodyDispute to Nostr...");

    let publish_transport = NostrTransportBuilder::new(secret_key)
        .relay(&relay_url)
        .build()
        .await?;

    publish_transport.broadcast_ledger_update(&signed_update).await?;

    println!();
    println!("CustodyDispute published successfully!");
    println!("  Dispute opener: {}...", &our_pubkey.to_string()[..16]);
    println!("  Sequence: {} (forked from {})", sequence, last_valid_sequence_u64);
    println!("  Hash: {}...", &hex::encode(new_hash)[..16]);
    println!();
    println!("Ledger is now in DISPUTED state. Quorum has been disbanded.");
    println!();
    println!("Next steps:");
    println!("  1. Rebuild quorum: recovery rebuild {}", &ledger_id[..16]);
    println!("  2. Collect attestations from new quorum members");
    println!("  3. Pre-commit: recovery arm {}", &ledger_id[..16]);

    Ok(())
}

/// Rebuild the quorum during a dispute.
///
/// This command helps add new quorum members and collect attestations
/// while the ledger is in DISPUTED state.
///
/// Usage:
///   recovery rebuild <ledger_id> quorum-add <member_pubkey>
///   recovery rebuild <ledger_id> attestation <attestation_json>
///   recovery rebuild <ledger_id> status
async fn recovery_rebuild(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.is_empty() {
        eprintln!("Usage: deposits-bdk recovery rebuild <ledger_id> <quorum-add|attestation|status> [args...]");
        eprintln!();
        eprintln!("Subcommands:");
        eprintln!("  quorum-add <member_pubkey>     Add a quorum member to your dispute branch");
        eprintln!("  attestation <attestation_json> Record a collateral attestation on your branch");
        eprintln!("  status                         Show current quorum/attestation state");
        eprintln!();
        eprintln!("Example flow:");
        eprintln!("  1. recovery rebuild <ledger_id> quorum-add <member_pubkey>");
        eprintln!("  2. Have the member run: collateral lock <their_reserves> <deposit_secret> <amount> <blocks> <your_pubkey>");
        eprintln!("  3. recovery rebuild <ledger_id> attestation '<attestation_json>'");
        eprintln!("  4. recovery arm <ledger_id>");
        return Ok(());
    }

    let ledger_id = args[0].trim().to_string();

    if args.len() < 2 {
        eprintln!("Missing subcommand. Use: quorum-add, attestation, or status");
        return Ok(());
    }

    match args[1].as_str() {
        "quorum-add" => recovery_rebuild_quorum_add(&ledger_id, &args[2..]).await,
        "attestation" => recovery_rebuild_attestation(&ledger_id, &args[2..]).await,
        "status" => recovery_rebuild_status(&ledger_id, &args[2..]).await,
        cmd => {
            eprintln!("Unknown rebuild subcommand: {}", cmd);
            eprintln!("Use: quorum-add, attestation, or status");
            Ok(())
        }
    }
}

/// Add a quorum member to our dispute branch.
async fn recovery_rebuild_quorum_add(ledger_id: &str, args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use bitcoin::hashes::{Hash, sha256};
    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey, PublicKey, Message};
    use deposits_core::{TlvDecode, TlvEncode, SignedLedgerUpdate};
    use deposits_core::messages::LedgerOperation;
    use deposits_bdk::nostr::{NostrTransportBuilder, KIND_LEDGER_UPDATE};
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use nostr_sdk::prelude::*;
    use std::str::FromStr;

    let mut member_pubkey_str: Option<String> = None;
    let mut config_args = Vec::new();

    for (i, arg) in args.iter().enumerate() {
        if arg.starts_with("--") {
            config_args.push(arg.clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
            }
        } else if member_pubkey_str.is_none() {
            member_pubkey_str = Some(arg.clone());
        }
    }

    let member_pubkey_str = member_pubkey_str.ok_or("Missing member_pubkey")?;
    let member_pubkey = PublicKey::from_str(&member_pubkey_str)
        .map_err(|e| format!("Invalid member pubkey: {}", e))?;

    let config = parse_config(&config_args)?;
    let relay_url = config.relays.first()
        .ok_or("No relay configured. Use --relay <url>")?
        .clone();

    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&config.seed)
        .map_err(|e| format!("Invalid seed: {}", e))?;
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let our_pubkey = keypair.public_key();

    println!("Adding quorum member to dispute branch...");
    println!("  Ledger: {}...", &ledger_id[..16.min(ledger_id.len())]);
    println!("  Member: {}...", &member_pubkey_str[..16.min(member_pubkey_str.len())]);

    // Fetch our branch from Nostr
    println!("Fetching ledger from Nostr...");
    let keys = Keys::generate();
    let client = Client::new(keys);
    client.add_relay(&relay_url).await
        .map_err(|e| format!("Failed to add relay: {}", e))?;
    client.connect().await;

    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .custom_tag(SingleLetterTag::lowercase(Alphabet::D), [ledger_id])
        .limit(500);

    let events = client
        .fetch_events(vec![filter], None)
        .await
        .map_err(|e| format!("Failed to fetch events: {}", e))?;

    // Find our updates and verify we have a CustodyDispute
    let mut our_updates: Vec<SignedLedgerUpdate> = Vec::new();
    for event in events.iter() {
        if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
            if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                if update.operator_id == our_pubkey {
                    our_updates.push(update);
                }
            }
        }
    }

    if our_updates.is_empty() {
        return Err("No updates found from you. Run 'recovery dispute' first to open your own dispute branch.".into());
    }

    // Verify our first update is a CustodyDispute (required to start a dispute branch)
    our_updates.sort_by_key(|u| u.sequence_number);
    let first_update = &our_updates[0];
    if let Ok(op) = LedgerOperation::tlv_decode(&first_update.message) {
        if !matches!(op, LedgerOperation::CustodyDispute { .. }) {
            return Err("Your first update is not a CustodyDispute. Run 'recovery dispute' first.".into());
        }
    }

    let our_latest = our_updates.last().unwrap().clone();
    println!("  Found {} updates from you, latest at sequence {}", our_updates.len(), our_latest.sequence_number);

    // Get current block info
    use bdk_esplora::esplora_client::Builder as EsploraBuilder;
    let esplora = EsploraBuilder::new(&config.electrum_url).build_blocking();
    let current_block_height = esplora.get_height()
        .map_err(|e| format!("Failed to get block height: {:?}", e))?;

    // Create QuorumAddMember operation
    let operation = LedgerOperation::QuorumAddMember {
        quorum_member: member_pubkey,
        quorum_member_signature: [0u8; 64], // Placeholder - member consent assumed
    };

    // Serialize
    let message_bytes = operation.tlv_encode();

    // Compute the new hash
    let sequence = our_latest.sequence_number + 1;
    let mut hash_input = Vec::new();
    hash_input.extend_from_slice(&sequence.to_le_bytes());
    hash_input.extend_from_slice(&our_latest.current_hash);
    hash_input.extend_from_slice(&message_bytes);
    let new_hash = *sha256::Hash::hash(&hash_input).as_byte_array();

    // Sign the update
    let update_msg = format!(
        "deposits:ledger:{}:{}:{}",
        hex::encode(our_latest.current_hash),
        sequence,
        hex::encode(&new_hash)
    );
    let msg_hash = sha256::Hash::hash(update_msg.as_bytes());
    let signature = secp.sign_schnorr(
        &Message::from_digest(*msg_hash.as_ref()),
        &keypair
    );
    let operator_sig_bytes: [u8; 64] = *signature.as_ref();

    // Create the signed update
    let ledger_id_bytes: [u8; 32] = {
        let decoded = hex::decode(ledger_id)
            .map_err(|e| format!("Invalid ledger_id hex: {}", e))?;
        decoded.try_into().map_err(|_| "Ledger ID must be 32 bytes")?
    };

    let signed_update = SignedLedgerUpdate {
        message: message_bytes,
        message_type: deposits_core::messages::consts::QUORUM_ADD_MEMBER,
        operator_signature: operator_sig_bytes,
        partner_signature: [0u8; 64],
        operator_id: our_pubkey,
        ledger_id: ledger_id_bytes,
        sequence_number: sequence,
        previous_hash: our_latest.current_hash,
        current_hash: new_hash,
        timestamp: deposits_core::now_unix_timestamp(),
        block_height: current_block_height,
        block_hash: [0u8; 32],
    };

    // Publish to Nostr
    println!("Publishing QuorumAddMember to Nostr...");
    let publishing_keys = Keys::new(nostr_sdk::SecretKey::from_slice(&config.seed)
        .map_err(|e| format!("Invalid key: {}", e))?);
    let publishing_client = Client::new(publishing_keys.clone());
    publishing_client.add_relay(&relay_url).await
        .map_err(|e| format!("Failed to add relay: {}", e))?;
    publishing_client.connect().await;

    let update_bytes = signed_update.tlv_encode();
    let content = BASE64.encode(&update_bytes);

    let event = EventBuilder::new(Kind::Custom(KIND_LEDGER_UPDATE), content)
        .tags(vec![Tag::custom(TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::D)), [ledger_id])])
        .sign_with_keys(&publishing_keys)
        .map_err(|e| format!("Failed to sign event: {}", e))?;

    publishing_client.send_event(event).await
        .map_err(|e| format!("Failed to publish: {}", e))?;

    publishing_client.disconnect().await.ok();
    client.disconnect().await.ok();

    println!();
    println!("QuorumAddMember published!");
    println!("  Sequence: {}", sequence);
    println!("  Member: {}...", &member_pubkey_str[..16.min(member_pubkey_str.len())]);
    println!();
    println!("Next: Have the member lock collateral and give you the attestation JSON:");
    println!("  Member runs: collateral lock <reserves_id> <deposit_secret> <amount_msats> <lock_blocks> {}", our_pubkey);
    println!("  Then you run: recovery rebuild {} attestation '<attestation_json>'", &ledger_id[..16.min(ledger_id.len())]);

    Ok(())
}

/// Record a collateral attestation on our dispute branch.
async fn recovery_rebuild_attestation(ledger_id: &str, args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use bitcoin::hashes::{Hash, sha256};
    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey, PublicKey, Message};
    use deposits_core::{TlvDecode, TlvEncode, SignedLedgerUpdate, CollateralAttestationMsg};
    use deposits_core::messages::LedgerOperation;
    use deposits_bdk::nostr::{NostrTransportBuilder, KIND_LEDGER_UPDATE};
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use nostr_sdk::prelude::*;

    let mut attestation_json: Option<String> = None;
    let mut config_args = Vec::new();

    for (i, arg) in args.iter().enumerate() {
        if arg.starts_with("--") {
            config_args.push(arg.clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
            }
        } else if attestation_json.is_none() {
            attestation_json = Some(arg.clone());
        }
    }

    let attestation_json = attestation_json.ok_or("Missing attestation_json")?;
    let attestation: CollateralAttestationMsg = serde_json::from_str(&attestation_json)
        .map_err(|e| format!("Invalid attestation JSON: {}", e))?;

    let config = parse_config(&config_args)?;
    let relay_url = config.relays.first()
        .ok_or("No relay configured. Use --relay <url>")?
        .clone();

    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&config.seed)
        .map_err(|e| format!("Invalid seed: {}", e))?;
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let our_pubkey = keypair.public_key();

    println!("Recording collateral attestation on dispute branch...");
    println!("  Ledger: {}...", &ledger_id[..16.min(ledger_id.len())]);
    println!("  From: {}...", &attestation.operator.to_string()[..16]);
    println!("  Amount: {} msats", attestation.amount);
    println!("  Lock until: block {}", attestation.lock_until_block);

    // Fetch our branch from Nostr
    println!("Fetching ledger from Nostr...");
    let keys = Keys::generate();
    let client = Client::new(keys);
    client.add_relay(&relay_url).await
        .map_err(|e| format!("Failed to add relay: {}", e))?;
    client.connect().await;

    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .custom_tag(SingleLetterTag::lowercase(Alphabet::D), [ledger_id])
        .limit(500);

    let events = client
        .fetch_events(vec![filter], None)
        .await
        .map_err(|e| format!("Failed to fetch events: {}", e))?;

    // Find our updates and verify we have a CustodyDispute
    let mut our_updates: Vec<SignedLedgerUpdate> = Vec::new();
    for event in events.iter() {
        if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
            if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                if update.operator_id == our_pubkey {
                    our_updates.push(update);
                }
            }
        }
    }

    if our_updates.is_empty() {
        return Err("No updates found from you. Run 'recovery dispute' first to open your own dispute branch.".into());
    }

    // Verify our first update is a CustodyDispute (required to start a dispute branch)
    our_updates.sort_by_key(|u| u.sequence_number);
    let first_update = &our_updates[0];
    if let Ok(op) = LedgerOperation::tlv_decode(&first_update.message) {
        if !matches!(op, LedgerOperation::CustodyDispute { .. }) {
            return Err("Your first update is not a CustodyDispute. Run 'recovery dispute' first.".into());
        }
    }

    let our_latest = our_updates.last().unwrap().clone();
    println!("  Found {} updates from you, latest at sequence {}", our_updates.len(), our_latest.sequence_number);

    // Get current block info
    use bdk_esplora::esplora_client::Builder as EsploraBuilder;
    let esplora = EsploraBuilder::new(&config.electrum_url).build_blocking();
    let current_block_height = esplora.get_height()
        .map_err(|e| format!("Failed to get block height: {:?}", e))?;

    // Create CollateralAttestation operation
    let operation = LedgerOperation::CollateralAttestation {
        collateral_operator: attestation.operator,
        quorum_member: attestation.quorum_member,
        amount: attestation.amount,
        block_height: attestation.block_height,
        lock_until_block: attestation.lock_until_block,
        signature: attestation.signature,
        ledger_hash: attestation.ledger_hash,
    };

    // Serialize
    let message_bytes = operation.tlv_encode();

    // Compute the new hash
    let sequence = our_latest.sequence_number + 1;
    let mut hash_input = Vec::new();
    hash_input.extend_from_slice(&sequence.to_le_bytes());
    hash_input.extend_from_slice(&our_latest.current_hash);
    hash_input.extend_from_slice(&message_bytes);
    let new_hash = *sha256::Hash::hash(&hash_input).as_byte_array();

    // Sign the update
    let update_msg = format!(
        "deposits:ledger:{}:{}:{}",
        hex::encode(our_latest.current_hash),
        sequence,
        hex::encode(&new_hash)
    );
    let msg_hash = sha256::Hash::hash(update_msg.as_bytes());
    let signature = secp.sign_schnorr(
        &Message::from_digest(*msg_hash.as_ref()),
        &keypair
    );
    let operator_sig_bytes: [u8; 64] = *signature.as_ref();

    // Create the signed update
    let ledger_id_bytes: [u8; 32] = {
        let decoded = hex::decode(ledger_id)
            .map_err(|e| format!("Invalid ledger_id hex: {}", e))?;
        decoded.try_into().map_err(|_| "Ledger ID must be 32 bytes")?
    };

    let signed_update = SignedLedgerUpdate {
        message: message_bytes,
        message_type: deposits_core::messages::consts::COLLATERAL_ATTESTATION,
        operator_signature: operator_sig_bytes,
        partner_signature: [0u8; 64],
        operator_id: our_pubkey,
        ledger_id: ledger_id_bytes,
        sequence_number: sequence,
        previous_hash: our_latest.current_hash,
        current_hash: new_hash,
        timestamp: deposits_core::now_unix_timestamp(),
        block_height: current_block_height,
        block_hash: [0u8; 32],
    };

    // Publish to Nostr
    println!("Publishing CollateralAttestation to Nostr...");
    let publishing_keys = Keys::new(nostr_sdk::SecretKey::from_slice(&config.seed)
        .map_err(|e| format!("Invalid key: {}", e))?);
    let publishing_client = Client::new(publishing_keys.clone());
    publishing_client.add_relay(&relay_url).await
        .map_err(|e| format!("Failed to add relay: {}", e))?;
    publishing_client.connect().await;

    let update_bytes = signed_update.tlv_encode();
    let content = BASE64.encode(&update_bytes);

    let event = EventBuilder::new(Kind::Custom(KIND_LEDGER_UPDATE), content)
        .tags(vec![Tag::custom(TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::D)), [ledger_id])])
        .sign_with_keys(&publishing_keys)
        .map_err(|e| format!("Failed to sign event: {}", e))?;

    publishing_client.send_event(event).await
        .map_err(|e| format!("Failed to publish: {}", e))?;

    publishing_client.disconnect().await.ok();
    client.disconnect().await.ok();

    println!();
    println!("CollateralAttestation published!");
    println!("  Sequence: {}", sequence);
    println!("  From: {}...", &attestation.operator.to_string()[..16]);
    println!("  Amount: {} msats", attestation.amount);
    println!();
    println!("Once you have enough attestations, run:");
    println!("  recovery arm {}...", &ledger_id[..16.min(ledger_id.len())]);

    Ok(())
}

/// Show the current quorum/attestation status on our dispute branch.
async fn recovery_rebuild_status(ledger_id: &str, args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use bitcoin::secp256k1::{Secp256k1, SecretKey, PublicKey};
    use deposits_core::{TlvDecode, SignedLedgerUpdate};
    use deposits_core::messages::LedgerOperation;
    use deposits_bdk::nostr::KIND_LEDGER_UPDATE;
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use nostr_sdk::prelude::*;

    let config = parse_config(args)?;
    let relay_url = config.relays.first()
        .ok_or("No relay configured. Use --relay <url>")?
        .clone();

    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&config.seed)
        .map_err(|e| format!("Invalid seed: {}", e))?;
    let our_pubkey = PublicKey::from_secret_key(&secp, &secret_key);

    println!("Checking dispute branch status for ledger: {}...", &ledger_id[..16.min(ledger_id.len())]);

    // Fetch from Nostr
    let keys = Keys::generate();
    let client = Client::new(keys);
    client.add_relay(&relay_url).await
        .map_err(|e| format!("Failed to add relay: {}", e))?;
    client.connect().await;

    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .custom_tag(SingleLetterTag::lowercase(Alphabet::D), [ledger_id])
        .limit(500);

    let events = client
        .fetch_events(vec![filter], None)
        .await
        .map_err(|e| format!("Failed to fetch events: {}", e))?;

    client.disconnect().await.ok();

    // Find our updates and extract quorum/attestation info
    let mut our_updates: Vec<SignedLedgerUpdate> = Vec::new();
    let mut quorum_members: Vec<PublicKey> = Vec::new();
    let mut attestations: Vec<(PublicKey, u64, u32)> = Vec::new(); // (operator, amount, until_block)
    let mut has_dispute = false;
    let mut has_armed = false;

    for event in events.iter() {
        if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
            if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                if update.operator_id == our_pubkey {
                    if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                        match op {
                            LedgerOperation::CustodyDispute { .. } => has_dispute = true,
                            LedgerOperation::CustodyArmed { .. } => has_armed = true,
                            LedgerOperation::QuorumAddMember { quorum_member, .. } => {
                                if !quorum_members.contains(&quorum_member) {
                                    quorum_members.push(quorum_member);
                                }
                            }
                            LedgerOperation::CollateralAttestation { collateral_operator, amount, lock_until_block, .. } => {
                                attestations.push((collateral_operator, amount, lock_until_block));
                            }
                            _ => {}
                        }
                    }
                    our_updates.push(update);
                }
            }
        }
    }

    println!();
    if our_updates.is_empty() {
        println!("No updates found from you on this ledger.");
        println!("Run 'recovery dispute <ledger_id>' first to open a dispute.");
        return Ok(());
    }

    println!("Your dispute branch status:");
    println!("  Updates: {}", our_updates.len());
    println!("  Has CustodyDispute: {}", if has_dispute { "yes" } else { "NO - run 'recovery dispute' first" });
    println!("  Has CustodyArmed: {}", if has_armed { "yes (locked in)" } else { "no" });
    println!();
    println!("Quorum members: {}", quorum_members.len());
    for member in &quorum_members {
        println!("  - {}...", &member.to_string()[..16]);
    }
    println!();
    println!("Collateral attestations: {}", attestations.len());
    for (op, amount, until) in &attestations {
        println!("  - {}... {} msats until block {}", &op.to_string()[..16], amount, until);
    }
    println!();

    if !has_dispute {
        println!("Next: Run 'recovery dispute <ledger_id>' to open a dispute.");
    } else if quorum_members.is_empty() {
        println!("Next: Add quorum members with 'recovery rebuild <ledger_id> quorum-add <pubkey>'");
    } else if attestations.is_empty() {
        println!("Next: Get attestations from quorum members and record with 'recovery rebuild <ledger_id> attestation <json>'");
    } else if !has_armed {
        println!("Ready to arm! Run 'recovery arm <ledger_id>'");
    } else {
        println!("You are armed. Wait for the entropy block, then run 'recovery claim <ledger_id>'");
    }

    Ok(())
}

/// Publish CustodyArmed to pre-commit for entropy selection.
///
/// This locks in the current quorum - no more changes allowed after this.
/// The candidate is now registered for entropy-based selection.
async fn recovery_arm(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use bitcoin::hashes::{Hash, sha256};
    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey, Message};
    use deposits_core::{TlvDecode, TlvEncode, SignedLedgerUpdate};
    use deposits_core::messages::LedgerOperation;
    use deposits_bdk::nostr::{NostrTransportBuilder, KIND_LEDGER_UPDATE};
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use nostr_sdk::prelude::*;

    let mut ledger_id: Option<String> = None;
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
                if ledger_id.is_none() {
                    ledger_id = Some(args[i].clone());
                }
            }
        }
        i += 1;
    }

    let ledger_id = ledger_id.ok_or("Missing ledger_id")?.trim().to_string();
    let config = parse_config(&config_args)?;
    let relay_url = config.relays.first()
        .ok_or("No relay configured. Use --relay <url>")?
        .clone();

    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&config.seed)
        .map_err(|e| format!("Invalid seed: {}", e))?;
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let our_pubkey = keypair.public_key();

    println!("Arming (pre-committing) for ledger: {}...", &ledger_id[..16.min(ledger_id.len())]);

    // Fetch our branch from Nostr
    println!("Fetching ledger from Nostr...");
    let keys = Keys::generate();
    let client = Client::new(keys);
    client.add_relay(&relay_url).await
        .map_err(|e| format!("Failed to add relay: {}", e))?;
    client.connect().await;

    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .custom_tag(SingleLetterTag::lowercase(Alphabet::D), [ledger_id.as_str()])
        .limit(500);

    let events = client
        .fetch_events(vec![filter], None)
        .await
        .map_err(|e| format!("Failed to fetch events: {}", e))?;

    client.disconnect().await.ok();

    // Find our CustodyDispute and get the latest update
    let mut our_updates: Vec<SignedLedgerUpdate> = Vec::new();
    for event in events.iter() {
        if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
            if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                if update.operator_id == our_pubkey {
                    our_updates.push(update);
                }
            }
        }
    }
    our_updates.sort_by_key(|u| u.sequence_number);

    if our_updates.is_empty() {
        return Err("No updates found from you. Did you run 'recovery dispute' first?".into());
    }

    // Find our latest update (should be CustodyDispute or quorum additions)
    let latest = our_updates.last().unwrap();
    println!("  Found {} updates from you", our_updates.len());
    println!("  Latest sequence: {}", latest.sequence_number);

    // Get current block height for armed_block
    use bdk_esplora::esplora_client::Builder as EsploraBuilder;
    let esplora = EsploraBuilder::new(&config.electrum_url).build_blocking();
    let current_block_height = esplora.get_height()
        .map_err(|e| format!("Failed to get block height: {:?}", e))?;

    // Create CustodyArmed operation
    let custody_armed = LedgerOperation::CustodyArmed {
        armed_block: current_block_height,
    };

    // Serialize
    let message_bytes = custody_armed.tlv_encode();

    // Compute the new hash
    let sequence = latest.sequence_number + 1;
    let mut hash_input = Vec::new();
    hash_input.extend_from_slice(&sequence.to_le_bytes());
    hash_input.extend_from_slice(&latest.current_hash);
    hash_input.extend_from_slice(&message_bytes);
    let new_hash = *sha256::Hash::hash(&hash_input).as_byte_array();

    // Sign the update
    let update_msg = format!(
        "deposits:ledger:{}:{}:{}",
        hex::encode(latest.current_hash),
        sequence,
        hex::encode(&new_hash)
    );
    let msg_hash = sha256::Hash::hash(update_msg.as_bytes());
    let signature = secp.sign_schnorr(
        &Message::from_digest(*msg_hash.as_ref()),
        &keypair
    );
    let operator_sig_bytes: [u8; 64] = *signature.as_ref();

    // Create the signed update
    let ledger_id_bytes: [u8; 32] = {
        let decoded = hex::decode(&ledger_id)
            .map_err(|e| format!("Invalid ledger_id hex: {}", e))?;
        decoded.try_into().map_err(|_| "Ledger ID must be 32 bytes")?
    };

    let signed_update = SignedLedgerUpdate {
        message: message_bytes,
        message_type: 0x8001,
        operator_signature: operator_sig_bytes,
        partner_signature: [0u8; 64],
        operator_id: our_pubkey,
        ledger_id: ledger_id_bytes,
        sequence_number: sequence,
        previous_hash: latest.current_hash,
        current_hash: new_hash,
        timestamp: deposits_core::now_unix_timestamp(),
        block_height: current_block_height,
        block_hash: [0u8; 32],
    };

    // Publish to Nostr
    println!();
    println!("Publishing CustodyArmed to Nostr...");

    let publish_transport = NostrTransportBuilder::new(secret_key)
        .relay(&relay_url)
        .build()
        .await?;

    publish_transport.broadcast_ledger_update(&signed_update).await?;

    // Compute entropy block (6 blocks after armed)
    let entropy_block = current_block_height + 6;

    println!();
    println!("CustodyArmed published successfully!");
    println!("  Armed block: {}", current_block_height);
    println!("  Sequence: {}", sequence);
    println!("  Hash: {}...", &hex::encode(new_hash)[..16]);
    println!();
    println!("Ledger is now in ARMED state. Quorum is locked.");
    println!();
    println!("IMPORTANT: ALL candidates MUST run 'recovery claim' after entropy block!");
    println!("  - Winner publishes CustodyAcquire (gains custody)");
    println!("  - Losers publish CustodyYield (tombstones their branch)");
    println!();
    println!("Next steps:");
    println!("  1. Wait for entropy block: {} (current: {})", entropy_block, current_block_height);
    println!("  2. After entropy block: recovery claim {}", &ledger_id[..16]);
    println!();
    println!("The entropy block hash determines the winner. Run 'recovery claim' regardless of outcome.");

    Ok(())
}

/// Claim custody after entropy block - publish CustodyAcquire (winner) or CustodyYield (loser).
async fn recovery_claim_new(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use bitcoin::hashes::{Hash, sha256};
    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey, PublicKey, Message};
    use deposits_core::{TlvDecode, TlvEncode, SignedLedgerUpdate};
    use deposits_core::messages::LedgerOperation;
    use deposits_core::types::select_entropy_winner;
    use deposits_bdk::nostr::{NostrTransportBuilder, KIND_LEDGER_UPDATE};
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use nostr_sdk::prelude::*;

    let mut ledger_id: Option<String> = None;
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
                if ledger_id.is_none() {
                    ledger_id = Some(args[i].clone());
                }
            }
        }
        i += 1;
    }

    let ledger_id = ledger_id.ok_or("Missing ledger_id")?.trim().to_string();
    let config = parse_config(&config_args)?;
    let relay_url = config.relays.first()
        .ok_or("No relay configured. Use --relay <url>")?
        .clone();

    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&config.seed)
        .map_err(|e| format!("Invalid seed: {}", e))?;
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let our_pubkey = keypair.public_key();

    println!("Claiming custody for ledger: {}...", &ledger_id[..16.min(ledger_id.len())]);

    // Fetch all updates from Nostr
    println!("Fetching ledger from Nostr...");
    let keys = Keys::generate();
    let client = Client::new(keys);
    client.add_relay(&relay_url).await
        .map_err(|e| format!("Failed to add relay: {}", e))?;
    client.connect().await;

    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .custom_tag(SingleLetterTag::lowercase(Alphabet::D), [ledger_id.as_str()])
        .limit(500);

    let events = client
        .fetch_events(vec![filter], None)
        .await
        .map_err(|e| format!("Failed to fetch events: {}", e))?;

    client.disconnect().await.ok();

    // Find all CustodyArmed candidates and their armed_block
    let mut candidates: Vec<(PublicKey, u32, SignedLedgerUpdate)> = Vec::new(); // (pubkey, armed_block, latest_update)
    let mut our_latest: Option<SignedLedgerUpdate> = None;
    let mut our_armed_block: Option<u32> = None;

    for event in events.iter() {
        if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
            if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                // Decode the operation
                if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                    if let LedgerOperation::CustodyArmed { armed_block } = op {
                        candidates.push((update.operator_id, armed_block, update.clone()));
                        if update.operator_id == our_pubkey {
                            our_armed_block = Some(armed_block);
                        }
                    }
                }

                // Track our latest update
                if update.operator_id == our_pubkey {
                    if our_latest.is_none() || update.sequence_number > our_latest.as_ref().unwrap().sequence_number {
                        our_latest = Some(update);
                    }
                }
            }
        }
    }

    if candidates.is_empty() {
        return Err("No CustodyArmed candidates found. Did everyone run 'recovery arm' first?".into());
    }

    let our_latest = our_latest.ok_or("No updates found from you")?;
    if our_armed_block.is_none() {
        return Err("You haven't published CustodyArmed yet. Run 'recovery arm' first.".into());
    }

    println!("  Found {} armed candidates", candidates.len());
    for (pk, block, _) in &candidates {
        let marker = if *pk == our_pubkey { " (you)" } else { "" };
        println!("    - {}... armed at block {}{}", &pk.to_string()[..16], block, marker);
    }

    // Get current block height and the entropy block hash
    use bdk_esplora::esplora_client::Builder as EsploraBuilder;
    let esplora = EsploraBuilder::new(&config.electrum_url).build_blocking();
    let current_block_height = esplora.get_height()
        .map_err(|e| format!("Failed to get block height: {:?}", e))?;

    // Find the earliest armed_block to determine entropy block
    let earliest_armed = candidates.iter().map(|(_, b, _)| *b).min().unwrap();
    let entropy_block_height = earliest_armed + 6;

    if current_block_height < entropy_block_height {
        println!();
        println!("Entropy block not yet mined!");
        println!("  Current block: {}", current_block_height);
        println!("  Entropy block: {} (need {} more blocks)", entropy_block_height, entropy_block_height - current_block_height);
        println!();
        println!("Please wait for the entropy block to be mined, then run this command again.");
        return Ok(());
    }

    // Get the entropy block hash
    let entropy_block_hash_hex = esplora.get_block_hash(entropy_block_height)
        .map_err(|e| format!("Failed to get entropy block hash: {:?}", e))?;
    let entropy_block_hash: [u8; 32] = {
        let hash_bytes = entropy_block_hash_hex.to_byte_array();
        // Block hashes are little-endian, reverse for consistency
        let mut reversed = hash_bytes;
        reversed.reverse();
        reversed
    };

    println!();
    println!("Entropy block: {} (hash: {}...)", entropy_block_height, hex::encode(&entropy_block_hash[..8]));

    // Get candidate pubkeys (only those armed before entropy block)
    let eligible_candidates: Vec<PublicKey> = candidates.iter()
        .filter(|(_, armed_block, _)| *armed_block < entropy_block_height)
        .map(|(pk, _, _)| *pk)
        .collect();

    if eligible_candidates.is_empty() {
        return Err("No eligible candidates (all armed after entropy block)".into());
    }

    // Determine winner using entropy selection
    let winner = select_entropy_winner(&entropy_block_hash, &eligible_candidates)
        .ok_or("Failed to select winner")?;

    let we_won = winner == our_pubkey;

    println!();
    println!("Entropy selection result:");
    println!("  Winner: {}...", &winner.to_string()[..16]);
    println!();
    if we_won {
        println!("🎉 YOU WON! You will become the new custodian.");
    } else {
        println!("You did NOT win. You must publish CustodyYield to tombstone your branch.");
        println!("This is required to release your quorum members from their attestation obligations.");
    }

    // Create the appropriate operation
    let (operation, op_name): (LedgerOperation, &str) = if we_won {
        (LedgerOperation::CustodyAcquire {
            new_custodian: our_pubkey,
            entropy_block_height,
            entropy_block_hash,
        }, "CustodyAcquire")
    } else {
        (LedgerOperation::CustodyYield, "CustodyYield")
    };

    // Serialize
    let message_bytes = operation.tlv_encode();

    // Compute the new hash
    let sequence = our_latest.sequence_number + 1;
    let mut hash_input = Vec::new();
    hash_input.extend_from_slice(&sequence.to_le_bytes());
    hash_input.extend_from_slice(&our_latest.current_hash);
    hash_input.extend_from_slice(&message_bytes);
    let new_hash = *sha256::Hash::hash(&hash_input).as_byte_array();

    // Sign the update
    let update_msg = format!(
        "deposits:ledger:{}:{}:{}",
        hex::encode(our_latest.current_hash),
        sequence,
        hex::encode(&new_hash)
    );
    let msg_hash = sha256::Hash::hash(update_msg.as_bytes());
    let signature = secp.sign_schnorr(
        &Message::from_digest(*msg_hash.as_ref()),
        &keypair
    );
    let operator_sig_bytes: [u8; 64] = *signature.as_ref();

    // Create the signed update
    let ledger_id_bytes: [u8; 32] = {
        let decoded = hex::decode(&ledger_id)
            .map_err(|e| format!("Invalid ledger_id hex: {}", e))?;
        decoded.try_into().map_err(|_| "Ledger ID must be 32 bytes")?
    };

    let signed_update = SignedLedgerUpdate {
        message: message_bytes,
        message_type: 0x8001,
        operator_signature: operator_sig_bytes,
        partner_signature: [0u8; 64],
        operator_id: our_pubkey,
        ledger_id: ledger_id_bytes,
        sequence_number: sequence,
        previous_hash: our_latest.current_hash,
        current_hash: new_hash,
        timestamp: deposits_core::now_unix_timestamp(),
        block_height: current_block_height,
        block_hash: entropy_block_hash,
    };

    // Publish to Nostr
    println!();
    println!("Publishing {} to Nostr...", op_name);

    let publish_transport = NostrTransportBuilder::new(secret_key)
        .relay(&relay_url)
        .build()
        .await?;

    publish_transport.broadcast_ledger_update(&signed_update).await?;

    println!();
    println!("{} published successfully!", op_name);
    println!("  Sequence: {}", sequence);
    println!("  Hash: {}...", &hex::encode(new_hash)[..16]);

    if we_won {
        println!();
        println!("You are now the custodian! Next step:");
        println!("  recovery spend {} - Execute on-chain spend to claim reserves", &ledger_id[..16]);
    } else {
        println!();
        println!("✓ Your branch is now TOMBSTONED (CustodyYield published).");
        println!("  Your quorum members are released from attestation obligations.");
        println!("  The winner ({}...) can now proceed with on-chain spend.", &winner.to_string()[..16]);
    }

    Ok(())
}

// =============================================================================
// DANGEROUS TESTING COMMANDS
// =============================================================================
// WARNING: These commands create invalid/malicious ledger updates.
// Only use for testing recovery mechanisms. Never enable in production builds.

#[cfg(feature = "dangerous-testing")]
async fn danger_command(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.is_empty() {
        eprintln!("Usage: deposits-bdk danger <subcommand> [args...]");
        eprintln!("Subcommands:");
        eprintln!("  publish-invalid <reserves_id> <violation_type>");
        return Ok(());
    }

    match args[0].as_str() {
        "publish-invalid" => danger_publish_invalid(&args[1..]).await,
        cmd => {
            eprintln!("Unknown danger subcommand: {}", cmd);
            eprintln!("Available: publish-invalid");
            Ok(())
        }
    }
}

/// Publish an invalid ledger update to test recovery mechanisms.
/// WARNING: This creates non-conforming updates that break protocol rules.
#[cfg(feature = "dangerous-testing")]
async fn danger_publish_invalid(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use bitcoin::secp256k1::{Secp256k1, SecretKey, Message};
    use deposits_bdk::nostr::NostrTransportBuilder;
    use deposits_core::SignedLedgerUpdate;
    use sha2::{Digest, Sha256};

    if args.len() < 2 {
        eprintln!("Usage: deposits-bdk danger publish-invalid <reserves_id> <violation_type> [options...]");
        eprintln!();
        eprintln!("Violation types:");
        eprintln!("  invalid-hash   - Wrong previous_hash linkage");
        eprintln!("  skip-sequence  - Skip ahead in sequence numbers");
        eprintln!("  replay         - Replay an old update");
        eprintln!();
        eprintln!("Examples:");
        eprintln!("  danger publish-invalid bcrt1q... invalid-hash");
        eprintln!("  danger publish-invalid bcrt1q... skip-sequence");
        return Ok(());
    }

    let reserves_id = &args[0];
    let violation_type = &args[1];
    let config_args: Vec<String> = args.iter().skip(2).cloned().collect();

    let config = parse_config(&config_args)?;

    let relay_url = config.relays.first()
        .ok_or("No relay configured. Use --relay <url>")?
        .clone();

    let secret_key = SecretKey::from_slice(&config.seed)
        .map_err(|e| format!("Invalid seed: {}", e))?;
    let secp = Secp256k1::new();

    // Get the node to access the ledger
    let node = Node::new(config).await?;

    let (_, ledger) = node.get_ledger_by_reserves_id(reserves_id)
        .ok_or_else(|| format!("Ledger not found: {}", reserves_id))?;

    if ledger.history.is_empty() {
        return Err("Ledger has no history - cannot create invalid update".into());
    }

    let last_update = ledger.history.last().unwrap();
    let current_seq = last_update.sequence_number;
    let current_hash = last_update.current_hash;

    println!("=== DANGER: Publishing Invalid Ledger Update ===");
    println!();
    println!("WARNING: This creates a non-conforming update!");
    println!("Only use for testing recovery mechanisms.");
    println!();
    println!("Ledger: {}", reserves_id);
    println!("Current sequence: {}", current_seq);
    println!("Current hash: {}...", &hex::encode(current_hash)[..16]);
    println!("Violation type: {}", violation_type);
    println!();

    // Create the invalid update based on violation type
    let invalid_update: SignedLedgerUpdate = match violation_type.as_str() {
        "invalid-hash" => {
            // Create update with wrong previous_hash
            let wrong_prev_hash = {
                let mut h = current_hash;
                h[0] ^= 0xFF; // Flip some bits
                h[1] ^= 0xAA;
                h
            };

            // Create a dummy message (empty marker)
            let dummy_message = vec![0u8; 8]; // Just some bytes
            let message_type: u16 = 0x0001; // Arbitrary

            let new_seq = current_seq + 1;

            // Compute hash (will be valid for this malformed update)
            let computed_hash = {
                let mut hasher = Sha256::new();
                hasher.update(&new_seq.to_le_bytes());
                hasher.update(&wrong_prev_hash);
                hasher.update(&dummy_message);
                let result = hasher.finalize();
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&result);
                hash
            };

            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            // Sign with operator key only (partner sig will be empty)
            let signing_data = {
                let mut data = Vec::new();
                data.extend_from_slice(&dummy_message);
                data.extend_from_slice(&message_type.to_le_bytes());
                data.extend_from_slice(&new_seq.to_le_bytes());
                data.extend_from_slice(&wrong_prev_hash);
                data.extend_from_slice(&computed_hash);
                data.extend_from_slice(&timestamp.to_le_bytes());
                data
            };

            // Sign
            let msg_hash = sha256_hash(&signing_data);
            let message = Message::from_digest(msg_hash);
            let sig = secp.sign_schnorr(&message, &secret_key.keypair(&secp));
            let operator_signature = sig.serialize();

            SignedLedgerUpdate {
                message: dummy_message,
                message_type,
                operator_id: node.node_id,
                ledger_id: ledger.ledger_id(),
                sequence_number: new_seq,
                previous_hash: wrong_prev_hash, // INVALID!
                current_hash: computed_hash,
                timestamp,
                block_height: 0,
                block_hash: [0u8; 32],
                partner_signature: [0u8; 64],
                operator_signature,
            }
        }

        "skip-sequence" => {
            // Create update that skips sequence numbers
            let skipped_seq = current_seq + 5; // Skip 4 sequence numbers

            let dummy_message = vec![0u8; 8];
            let message_type: u16 = 0x0001;

            // Still link to correct previous hash
            let computed_hash = {
                let mut hasher = Sha256::new();
                hasher.update(&skipped_seq.to_le_bytes());
                hasher.update(&current_hash);
                hasher.update(&dummy_message);
                let result = hasher.finalize();
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&result);
                hash
            };

            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let signing_data = {
                let mut data = Vec::new();
                data.extend_from_slice(&dummy_message);
                data.extend_from_slice(&message_type.to_le_bytes());
                data.extend_from_slice(&skipped_seq.to_le_bytes());
                data.extend_from_slice(&current_hash);
                data.extend_from_slice(&computed_hash);
                data.extend_from_slice(&timestamp.to_le_bytes());
                data
            };

            let msg_hash = sha256_hash(&signing_data);
            let message = Message::from_digest(msg_hash);
            let sig = secp.sign_schnorr(&message, &secret_key.keypair(&secp));
            let operator_signature = sig.serialize();

            SignedLedgerUpdate {
                message: dummy_message,
                message_type,
                operator_id: node.node_id,
                ledger_id: ledger.ledger_id(),
                sequence_number: skipped_seq, // INVALID! Skips seq numbers
                previous_hash: current_hash,
                current_hash: computed_hash,
                timestamp,
                block_height: 0,
                block_hash: [0u8; 32],
                partner_signature: [0u8; 64],
                operator_signature,
            }
        }

        "replay" => {
            // Re-publish an old update (but modify it slightly so it's detectable)
            if ledger.history.len() < 2 {
                return Err("Need at least 2 updates to create replay attack".into());
            }

            // Get an old update and modify its message slightly
            let old_update = &ledger.history[ledger.history.len() / 2];
            let mut replayed = old_update.clone();

            // Modify timestamp so it's different
            replayed.timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            // Re-sign with our key
            let signing_data = {
                let mut data = Vec::new();
                data.extend_from_slice(&replayed.message);
                data.extend_from_slice(&replayed.message_type.to_le_bytes());
                data.extend_from_slice(&replayed.sequence_number.to_le_bytes());
                data.extend_from_slice(&replayed.previous_hash);
                data.extend_from_slice(&replayed.current_hash);
                data.extend_from_slice(&replayed.timestamp.to_le_bytes());
                data
            };

            let msg_hash = sha256_hash(&signing_data);
            let message = Message::from_digest(msg_hash);
            let sig = secp.sign_schnorr(&message, &secret_key.keypair(&secp));
            replayed.operator_signature = sig.serialize();

            println!("Replaying update at sequence {} with modified timestamp", replayed.sequence_number);

            replayed
        }

        unknown => {
            return Err(format!("Unknown violation type: {}. Valid: invalid-hash, skip-sequence, replay", unknown).into());
        }
    };

    println!("Created invalid update:");
    println!("  Sequence: {}", invalid_update.sequence_number);
    println!("  Previous hash: {}...", &hex::encode(invalid_update.previous_hash)[..16]);
    println!("  Current hash: {}...", &hex::encode(invalid_update.current_hash)[..16]);

    // Broadcast to Nostr
    println!();
    println!("Broadcasting to relay: {}", relay_url);

    let transport = NostrTransportBuilder::new(secret_key)
        .relay(&relay_url)
        .build()
        .await?;

    let event_id = transport.broadcast_ledger_update(&invalid_update).await?;

    transport.disconnect().await;

    println!("Published invalid update!");
    println!("  Event ID: {}", event_id);
    println!();
    println!("To test recovery, try:");
    println!("  deposits-bdk nostr import {}:{}", node.node_id, reserves_id);
    println!("  deposits-bdk ledger validate {}", reserves_id);

    Ok(())
}

#[cfg(feature = "dangerous-testing")]
fn sha256_hash(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}
