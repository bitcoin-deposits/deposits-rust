// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! deposits-node CLI
//!
//! A deposits protocol node using BDK for on-chain reserves and Nostr for messaging.

#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

use base64::Engine;
use bitcoin::secp256k1::{PublicKey, SecretKey, Secp256k1};
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::Network;
use deposits_node::{Node, NodeConfig};
use deposits_node::cli::{nostr_commands, recovery};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

/// Derive the operator secret key from a seed using HD derivation.
/// This matches what the Wallet does, ensuring consistent key usage across the codebase.
fn derive_operator_secret(seed: &[u8; 32], network: Network) -> Result<SecretKey, String> {
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name_fn(|| {
            static ID: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            let id = ID.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            format!("dep-worker-{}", id)
        })
        .build()?;
    runtime.block_on(async_main())
}

async fn async_main() -> Result<(), Box<dyn std::error::Error>> {
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
        "lightning" | "ln" => lightning_command(&args[2..]).await?,
        "nostr" => nostr_commands::nostr_command(&args[2..]).await?,
        "recovery" => recovery::recovery_command(&args[2..]).await?,
        "keygen" => keygen(),
        "derive-deposit-key" => derive_deposit_key(&args[2..])?,
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
        r#"deposits-node - Bitcoin Deposits Protocol Node (BDK + Nostr)

USAGE:
    {} <COMMAND> [OPTIONS]

COMMANDS:
    run             Run the deposits node
    info            Show node info
    address         Generate a new receiving address
    keygen          Generate a new secp256k1 keypair for deposits
    derive-deposit-key
                    Derive wallet deposit secret key from seed (for collateral lock)
    reserves        Manage reserves UTXOs (create, rotate, list)
    ledger          Manage ledgers (open, list)
    partner         Manage quorum members (request, add, join, list)
    collateral      Manage collateral pledges
    deposit         Manage deposit offers for on-chain funding
    withdraw        Manage on-chain withdrawals
    lightning (ln)  Lightning invoice payment operations (lock, fail, fulfill)
    nostr           Nostr relay operations (updates, broadcast)
    help            Show this help message

RESERVES SUBCOMMANDS:
    reserves create [amount_sats]
                    Create a new reserves UTXO (default: 100M sats / 1 BTC)
    reserves rotate <reserves_id>
                    Rotate reserves to quorum-based Taproot spending
    reserves list   List all reserves outputs

LEDGER SUBCOMMANDS:
    ledger open [fee options]
                    Open a ledger backed by your reserves UTXO.
                    Fee options set advertised minimums for deposit negotiation:
                      --annual-fee-bps <N>        Annual custody fee in basis points
                      --min-fee-sats <N>          Minimum fee per period in sats
                      --fee-period <N>            Fee collection period in blocks (default: 2016)
                      --transfer-fee-fixed <N>    Fixed per-transfer fee in sats
                      --transfer-fee-rate-bps <N> Proportional per-transfer fee in basis points
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
    partner add <reserves_id> <quorum_member_pubkey> <member_ledger_id>
                    Add a quorum member to your ledger (records QuorumAddMember)
                    member_ledger_id: 64-char hex hash identifying member's collateral ledger
    partner join <our_ledger_id> <target_operator> <target_ledger_id> <expires_block>
                    Record that you joined another operator's quorum (records QuorumJoin)
                    target_ledger_id: 64-char hex hash identifying target operator's ledger
    partner list               List all quorum members

COLLATERAL SUBCOMMANDS:
    collateral lock <ledger_id> <amount_msats> <lock_blocks>
                    Lock deposit balance as collateral (derives key from seed).
    collateral lock <reserves_id> <deposit_secret> <amount_msats> <lock_blocks>
                    Lock deposit balance as collateral (explicit secret).
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

LIGHTNING SUBCOMMANDS (alias: ln):
  LDK Sidecar (via ldk-server-cli):
    lightning invoice <amount_sats> [description]
                    Create a Lightning invoice via LDK sidecar
    lightning pay <bolt11_invoice>
                    Pay a Lightning invoice via LDK sidecar
    lightning balance
                    Show Lightning wallet balance
    lightning info  Show LDK node info
    lightning channels
                    List Lightning channels
    lightning payments
                    List Lightning payments
  Ledger Operations:
    lightning lock <reserves_id> <deposit_pubkey> <amount_msats> <payment_id> <signature>
                    Lock deposit funds for an outgoing Lightning payment
    lightning fail <reserves_id> <deposit_pubkey> <amount_msats> <payment_id>
                    Fail/cancel a pending Lightning payment and unlock funds
    lightning fulfill <reserves_id> <deposit_pubkey> <amount_msats> <payment_id> <preimage> <signature>
                    Complete a Lightning payment with the preimage

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
                      make_offer <pubkey> <max_sats> <min_sats> <blocks_valid>
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
    --data-dir <path>  Data directory (default: ~/.deposits-node)
    --metrics-port <port>  Port for Prometheus metrics endpoint (run command only)

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
    let mut slow_relays = Vec::new();
    let mut operator_name = None;
    let mut fast_poll = false;
    let mut skip_nostr_verify = false;
    let mut data_dir = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".deposits-node");

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
            "--slow-relay" => {
                i += 1;
                if i >= args.len() {
                    return Err("--slow-relay requires a value".to_string());
                }
                slow_relays.push(args[i].clone());
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
            "--skip-nostr-verify" => {
                skip_nostr_verify = true;
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
        slow_relays,
        data_dir,
        operator_name,
        fast_poll,
        skip_nostr_verify,
    })
}

/// Send a Nostr request to the daemon and wait for a response.
///
/// This is used by CLI commands that delegate ledger mutations to the running daemon.
/// Returns the response result JSON on success, or an error string on failure.
async fn send_daemon_request(
    config: &NodeConfig,
    ledger_id: &str,
    action: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    use deposits_node::nostr::NostrTransportBuilder;

    if config.relays.is_empty() {
        return Err("No relay configured. Use --relay <url>".into());
    }

    let secret_key = derive_operator_secret(&config.seed, config.network)?;

    let transport = NostrTransportBuilder::new(secret_key)
        .relays(config.relays.iter().cloned())
        .build()
        .await?;

    let event_id = transport
        .send_ledger_request(ledger_id, action, params)
        .await?;

    transport.subscribe_to_response(&event_id).await?;

    let mut transport = transport;
    let timeout = tokio::time::Duration::from_secs(30);
    let start = std::time::Instant::now();
    let mut last_poll = std::time::Instant::now();
    let mut poll_count = 0;

    loop {
        if start.elapsed() > timeout {
            return Err("No response from daemon. Ensure 'deposits-node run' is running.".into());
        }

        tokio::select! {
            _ = transport.process_events() => {}
            _ = tokio::time::sleep(tokio::time::Duration::from_millis(100)) => {}
        }

        if let Some(response) = transport.try_recv_response() {
            if response.request_id == event_id {
                if response.success {
                    return Ok(response.result.unwrap_or(serde_json::Value::Null));
                } else {
                    let err_msg = response.error.unwrap_or_else(|| "Unknown error".to_string());
                    return Err(err_msg.into());
                }
            }
        }

        let poll_interval = if poll_count < 5 {
            std::time::Duration::from_millis(500)
        } else {
            std::time::Duration::from_secs(2)
        };

        if last_poll.elapsed() > poll_interval {
            match transport.fetch_response(&event_id).await {
                Ok(Some(response)) => {
                    if response.success {
                        return Ok(response.result.unwrap_or(serde_json::Value::Null));
                    } else {
                        let err_msg = response.error.unwrap_or_else(|| "Unknown error".to_string());
                        return Err(err_msg.into());
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::debug!("Poll error: {}", e);
                }
            }
            last_poll = std::time::Instant::now();
            poll_count += 1;
        }
    }
}

async fn run_node(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    // Parse --metrics-port separately (before parse_config since it's run-specific)
    let mut metrics_port: Option<u16> = None;
    let mut filtered_args: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--metrics-port" {
            i += 1;
            if i < args.len() {
                metrics_port = Some(args[i].parse().map_err(|_| "Invalid metrics port")?);
            }
        } else {
            filtered_args.push(args[i].clone());
        }
        i += 1;
    }

    let config = parse_config(&filtered_args)?;

    // Initialize metrics if port specified
    if let Some(port) = metrics_port {
        if let Err(e) = deposits_node::metrics::init_metrics(port) {
            tracing::warn!("Failed to initialize metrics: {}", e);
        }
    }

    tracing::info!("Starting deposits-node node...");
    tracing::info!("Network: {:?}", config.network);
    tracing::info!("Electrum: {}", config.electrum_url);
    tracing::info!(
        "Relays: {:?}",
        if config.relays.is_empty() {
            deposits_node::nostr::DEFAULT_RELAYS
                .iter()
                .map(|s| s.to_string())
                .collect()
        } else {
            config.relays.clone()
        }
    );
    if !config.slow_relays.is_empty() {
        tracing::info!("Slow relays: {:?}", config.slow_relays);
    }

    let node = Arc::new(Node::new(config).await?);

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

    // Continuous CPU profiler using pprof-rs (timer-based sampling via ITIMER_PROF).
    // Works in Docker on any host OS — no hardware PMU or perf_event support needed.
    // SIGUSR1 triggers: stop guard, dump collapsed stacks, restart profiling.
    // Also auto-dumps every 60s.
    // Opt-in: set ENABLE_PROFILING=1 to activate (ITIMER can conflict with jemalloc).
    #[cfg(unix)]
    {
        let data_dir = node.data_dir().to_path_buf();
        let profiling_enabled = std::env::var("ENABLE_PROFILING").map(|v| v == "1").unwrap_or(false);
        tokio::spawn(async move {
            use tokio::signal::unix::{signal, SignalKind};

            let mut sig = signal(SignalKind::user_defined1())
                .expect("Failed to register SIGUSR1 handler");

            if !profiling_enabled {
                tracing::info!("CPU profiling disabled (set ENABLE_PROFILING=1 to enable)");
                // Still handle SIGUSR1 to avoid killing the process
                loop { sig.recv().await; tracing::info!("SIGUSR1 received but profiling disabled"); }
            }

            use pprof::ProfilerGuardBuilder;
            let profile_dir = data_dir.clone();
            let mut dump_count = 0u32;

            let start_profiler = || -> Option<pprof::ProfilerGuard<'static>> {
                match ProfilerGuardBuilder::default()
                    .frequency(99)
                    .blocklist(&["libc", "libgcc", "pthread", "vdso", "jemalloc"])
                    .build()
                {
                    Ok(guard) => {
                        tracing::info!("Started pprof CPU profiling (99 Hz)");
                        Some(guard)
                    }
                    Err(e) => {
                        tracing::error!("Failed to start pprof: {}", e);
                        None
                    }
                }
            };

            let mut guard = start_profiler();
            let mut dump_interval = tokio::time::interval(tokio::time::Duration::from_secs(60));

            loop {
                tokio::select! {
                    _ = sig.recv() => {
                        tracing::info!("SIGUSR1 received — dumping profile");
                    }
                    _ = dump_interval.tick() => {}
                }

                dump_count += 1;

                if let Some(g) = guard.take() {
                    match g.report().build() {
                        Ok(report) => {
                            // Write collapsed stacks (compatible with flamegraph.pl and speedscope)
                            let collapsed_path = profile_dir.join("profile-latest.collapsed");
                            let mut stacks: std::collections::HashMap<String, isize> =
                                std::collections::HashMap::new();

                            for (frames, count) in report.data.iter() {
                                // Frames.frames is Vec<Vec<Symbol>> — flatten inline frames
                                let names: Vec<String> = frames.frames.iter().rev().flat_map(|syms| {
                                    syms.iter().map(|s| s.name())
                                }).collect();
                                if !names.is_empty() {
                                    *stacks.entry(names.join(";")).or_insert(0) += *count;
                                }
                            }

                            if !stacks.is_empty() {
                                let total: isize = stacks.values().sum();
                                let mut sorted: Vec<_> = stacks.into_iter().collect();
                                sorted.sort_by(|a, b| b.1.cmp(&a.1));
                                if let Ok(mut f) = std::fs::File::create(&collapsed_path) {
                                    use std::io::Write;
                                    for (stack, count) in &sorted {
                                        let _ = writeln!(f, "{} {}", stack, count);
                                    }
                                }
                                tracing::info!(
                                    "Profile dump #{}: {} samples, {} unique stacks",
                                    dump_count, total, sorted.len()
                                );
                            } else {
                                tracing::debug!("Profile dump #{}: no samples", dump_count);
                            }

                            // Also write protobuf for pprof tooling
                            let proto_path = profile_dir.join("profile-latest.pb");
                            if let Ok(mut f) = std::fs::File::create(&proto_path) {
                                use pprof::protos::Message;
                                if let Ok(proto) = report.pprof() {
                                    let _ = proto.write_to_writer(&mut f);
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!("Failed to build profile report: {}", e);
                        }
                    }
                }

                // Restart profiler
                guard = start_profiler();
            }
        });
    }

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

/// Derive the wallet deposit secret key from seed.
/// This matches the derivation used by deposits-wallet at m/84'/0'/0'/0/{index}.
fn derive_deposit_key(args: &[String]) -> Result<(), String> {
    let mut seed: Option<[u8; 32]> = None;
    let mut network = Network::Signet;
    let mut index: u32 = 0;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--seed" => {
                i += 1;
                if i >= args.len() {
                    return Err("--seed requires a value".to_string());
                }
                let hex_str = &args[i];
                if hex_str.len() != 64 {
                    return Err("Seed must be 64 hex characters".to_string());
                }
                let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid hex: {}", e))?;
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
            "--index" => {
                i += 1;
                if i >= args.len() {
                    return Err("--index requires a value".to_string());
                }
                index = args[i].parse::<u32>()
                    .map_err(|e| format!("Invalid index: {}", e))?;
            }
            _ => {}
        }
        i += 1;
    }

    let seed = seed.ok_or("--seed is required")?;

    // Derive the deposit key using BIP-84 path (same as wallet)
    let secp = Secp256k1::new();
    let xpriv = Xpriv::new_master(network, &seed)
        .map_err(|e| format!("Failed to create master key: {}", e))?;

    let deposit_path = DerivationPath::from_str(&format!("m/84'/0'/0'/0/{}", index))
        .map_err(|e| format!("Invalid derivation path: {}", e))?;

    let deposit_xpriv = xpriv
        .derive_priv(&secp, &deposit_path)
        .map_err(|e| format!("Failed to derive deposit key: {}", e))?;

    // Output just the secret key hex (for piping)
    println!("{}", hex::encode(deposit_xpriv.private_key.secret_bytes()));

    Ok(())
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
    println!("  Amount: {} sats", reserves.amount); // wallet ReservesOutput.amount is in sats
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

    // Load state from disk to resolve ledger_id
    let node = Node::new(config.clone()).await?;
    let ledger_id = match reserves_id {
        Some(id) => {
            if id.len() == 64 && id.chars().all(|c| c.is_ascii_hexdigit()) {
                id
            } else {
                node.get_ledger_with_id(&id)
                    .map(|(lid, _)| lid)
                    .ok_or_else(|| format!("Ledger not found for: {}", id))?
            }
        }
        None => {
            match node.get_primary_ledger() {
                Some((lid, _)) => lid,
                None => return Err("No ledger found. Open a ledger first with 'ledger open'.".into()),
            }
        }
    };
    drop(node);

    println!("Rotating reserves via daemon...");
    println!("  Ledger: {}...", &ledger_id[..16]);

    let params = serde_json::json!({});
    let result = send_daemon_request(&config, &ledger_id, "reserves_rotate", params).await?;

    println!("\nReserves rotated successfully!");
    if let Some(txid) = result.get("txid").and_then(|v| v.as_str()) {
        println!("  TXID: {}", txid);
    }
    if let Some(addr) = result.get("new_address").and_then(|v| v.as_str()) {
        println!("  New Address: {}", addr);
    }
    if let Some(amt) = result.get("amount_sats").and_then(|v| v.as_u64()) {
        println!("  Amount: {} sats", amt);
    }
    if let Some(count) = result.get("quorum_member_count").and_then(|v| v.as_u64()) {
        println!("  Quorum Members: {}", count);
    }
    if let Some(expiry) = result.get("quorum_expiry").and_then(|v| v.as_u64()) {
        println!("  First Expiry Block: {}", expiry);
        println!("\nSpending tiers:");
        println!("  Tier 0: Majority of quorum + operator (immediate)");
        println!("  Tier 1: Operator only (after block {})", expiry);
        println!("  Tier 2: Emergency recovery (extended timeout)");
    }

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
        let addr = bitcoin::Address::p2wsh(&info.redeem_script, node.wallet.network());
        println!("  Outpoint: {}", info.outpoint);
        println!("    Address: {}", addr);
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
        println!("    First Expiry: block {}", info.quorum_expiry);
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
        eprintln!("Usage: deposits-node ledger <open|list|history|validate|health|export|import|advertise|discover> [args...]");
        return Ok(());
    }

    match args[0].as_str() {
        "open" => ledger_open(&args[1..]).await,
        "list" => ledger_list(&args[1..]).await,
        "history" => ledger_history(&args[1..]).await,
        "validate" => ledger_validate(&args[1..]).await,
        "health" => ledger_health(&args[1..]).await,
        "export" => ledger_export(&args[1..]).await,
        "import" => ledger_import(&args[1..]).await,
        "advertise" => ledger_advertise(&args[1..]).await,
        "discover" => ledger_discover(&args[1..]).await,
        cmd => {
            eprintln!("Unknown ledger subcommand: {}", cmd);
            eprintln!("Usage: deposits-node ledger <open|list|history|validate|health|export|import|advertise|discover> [args...]");
            Ok(())
        }
    }
}

/// Fee schedule arguments parsed from CLI flags
#[derive(Default)]
struct FeeScheduleArgs {
    annual_fee_bps: Option<u32>,
    min_fee_sats: Option<u64>,
    fee_period_blocks: Option<u32>,
    transfer_fee_fixed: Option<u64>,
    transfer_fee_rate_bps: Option<u16>,
    advertise_relay: Option<String>,
}

impl FeeScheduleArgs {
    fn has_any(&self) -> bool {
        self.annual_fee_bps.is_some()
            || self.min_fee_sats.is_some()
            || self.fee_period_blocks.is_some()
            || self.transfer_fee_fixed.is_some()
            || self.transfer_fee_rate_bps.is_some()
    }
}

/// Helper to auto-advertise a ledger for wallet discovery
/// Accepts either reserves_key (bcrt1q...) or ledger_id (64-char hex)
async fn auto_advertise_ledger(
    node: &Node,
    identifier: &str,
    seed: &[u8; 32],
    network: bitcoin::Network,
    relays: &[String],
    operator_name: Option<&str>,
    fee_schedule: &FeeScheduleArgs,
) {
    use deposits_node::nostr::{NostrTransportBuilder, LedgerAdvertisement};

    let relay_url = match relays.first() {
        Some(r) => r,
        None => return,
    };

    // Resolve identifier to ledger (supports both ledger_id and reserves_key)
    let ledger = match node.get_ledger_with_id(identifier) {
        Some((_, l)) => l,
        None => return,
    };

    let ledger_id_hex = ledger.ledger_id_hex();
    let reserves_key = ledger.reserves_key().to_string();
    let operator_pubkey = hex::encode(ledger.operator_key().serialize());
    let network_str = match network {
        bitcoin::Network::Bitcoin => "bitcoin",
        bitcoin::Network::Testnet => "testnet",
        bitcoin::Network::Signet => "signet",
        bitcoin::Network::Regtest => "regtest",
        _ => "unknown",
    };

    let mut ad = LedgerAdvertisement::new(
        ledger_id_hex.clone(),
        operator_pubkey,
        reserves_key,
        network_str.to_string(),
    );
    ad.operator_name = operator_name.map(|s| s.to_string());
    ad.relay_url = fee_schedule.advertise_relay.clone();
    ad.reserves_amount_sats = ledger.reserves_amount() / 1000; // msats to sats for advertisement
    ad.received_collateral_sats = ledger.state.received_collateral_amount / 1000;

    // Apply fee schedule from CLI flags
    if let Some(bps) = fee_schedule.annual_fee_bps {
        ad.annual_fee_bps = bps;
    }
    if let Some(sats) = fee_schedule.min_fee_sats {
        ad.min_fee_sats = sats;
    }
    if let Some(blocks) = fee_schedule.fee_period_blocks {
        ad.fee_period_blocks = blocks;
    }
    if let Some(fixed) = fee_schedule.transfer_fee_fixed {
        ad.transfer_fee_fixed_msats = fixed;
    }
    if let Some(bps) = fee_schedule.transfer_fee_rate_bps {
        ad.transfer_fee_rate_bps = bps;
    }

    // Calculate headroom
    let total_obligations_sats = ledger.total_deposit_balance() / 1000;
    ad.total_obligations_sats = total_obligations_sats;
    let raw_headroom = ad.reserves_amount_sats.saturating_sub(total_obligations_sats);
    ad.available_headroom_sats = (raw_headroom * 80) / 100;

    let secret_key = match derive_operator_secret(seed, network) {
        Ok(sk) => sk,
        Err(_) => return,
    };

    let transport = match NostrTransportBuilder::new(secret_key)
        .relay(relay_url)
        .build()
        .await
    {
        Ok(t) => t,
        Err(_) => return,
    };

    match transport.publish_ledger_advertisement(&ad).await {
        Ok(_) => println!("  Advertised ledger for wallet discovery"),
        Err(e) => eprintln!("  Warning: Failed to advertise ledger: {}", e),
    }
}

/// Open a new ledger backed by our reserves UTXO
async fn ledger_open(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    // Parse fee schedule flags
    let mut config_args = Vec::new();

    // Fee schedule (advertised minimums)
    let mut annual_fee_bps: Option<u32> = None;
    let mut min_fee_sats: Option<u64> = None;
    let mut fee_period_blocks: Option<u32> = None;
    let mut transfer_fee_fixed: Option<u64> = None;
    let mut transfer_fee_rate_bps: Option<u16> = None;
    let mut advertise_relay: Option<String> = None;

    let fee_flags = [
        "--annual-fee-bps", "--min-fee-sats", "--fee-period",
        "--transfer-fee-fixed", "--transfer-fee-rate-bps",
    ];

    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with("--") {
            match args[i].as_str() {
                "--annual-fee-bps" if i + 1 < args.len() => {
                    annual_fee_bps = Some(args[i + 1].parse().map_err(|_| format!("Invalid {}: {}", args[i], args[i + 1]))?);
                    i += 1;
                }
                "--min-fee-sats" if i + 1 < args.len() => {
                    min_fee_sats = Some(args[i + 1].parse().map_err(|_| format!("Invalid {}: {}", args[i], args[i + 1]))?);
                    i += 1;
                }
                "--fee-period" if i + 1 < args.len() => {
                    fee_period_blocks = Some(args[i + 1].parse().map_err(|_| format!("Invalid {}: {}", args[i], args[i + 1]))?);
                    i += 1;
                }
                "--transfer-fee-fixed" if i + 1 < args.len() => {
                    transfer_fee_fixed = Some(args[i + 1].parse().map_err(|_| format!("Invalid {}: {}", args[i], args[i + 1]))?);
                    i += 1;
                }
                "--transfer-fee-rate-bps" if i + 1 < args.len() => {
                    transfer_fee_rate_bps = Some(args[i + 1].parse().map_err(|_| format!("Invalid {}: {}", args[i], args[i + 1]))?);
                    i += 1;
                }
                "--advertise-relay" if i + 1 < args.len() => {
                    advertise_relay = Some(args[i + 1].clone());
                    i += 1;
                }
                _ => {
                    // Config argument - pass through
                    config_args.push(args[i].clone());
                    if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                        config_args.push(args[i + 1].clone());
                        i += 1;
                    }
                }
            }
        } else {
            // Skip unknown positional arguments (enforcement_block was removed)
        }
        i += 1;
    }

    let fee_schedule = FeeScheduleArgs {
        annual_fee_bps,
        min_fee_sats,
        fee_period_blocks,
        transfer_fee_fixed,
        transfer_fee_rate_bps,
        advertise_relay,
    };

    let config = parse_config(&config_args)?;
    let seed = config.seed.clone();
    let network = config.network;
    let relays = config.relays.clone();
    let operator_name = config.operator_name.clone();
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

    // Create the ledger
    let ledger = node.open_ledger()?;

    println!("\nLedger opened successfully!");
    println!("  Ledger ID: {}", ledger.ledger_id_hex());
    println!("  Operator: {}", ledger.state.operator_key);
    println!("  Reserves: {}", ledger.state.reserves_key);
    println!("  Sequence: {}", ledger.state.sequence);
    println!("  Hash: {:02x?}", &ledger.state.hash[0..8]);
    // Get ledger identifiers
    let ledger_id = ledger.ledger_id_hex();
    let reserves_key = ledger.state.reserves_key.clone();

    // Broadcast all initial updates to Nostr
    match node.broadcast_all_updates(&ledger_id).await {
        Ok(count) => println!("  Broadcast {} updates to Nostr", count),
        Err(e) => eprintln!("  Warning: Failed to broadcast to Nostr: {}", e),
    }

    // Print fee schedule if any flags were set
    if fee_schedule.has_any() {
        println!("  Fee schedule:");
        if let Some(bps) = fee_schedule.annual_fee_bps {
            println!("    Annual custody fee: {} bps ({:.2}%)", bps, bps as f64 / 100.0);
        }
        if let Some(sats) = fee_schedule.min_fee_sats {
            println!("    Minimum fee per period: {} sats", sats);
        }
        if let Some(blocks) = fee_schedule.fee_period_blocks {
            println!("    Fee collection period: {} blocks", blocks);
        }
        if let Some(fixed) = fee_schedule.transfer_fee_fixed {
            println!("    Transfer fee (fixed): {} sats", fixed);
        }
        if let Some(bps) = fee_schedule.transfer_fee_rate_bps {
            println!("    Transfer fee (rate): {} bps ({:.2}%)", bps, bps as f64 / 100.0);
        }
    }

    // Auto-advertise ledger for wallet discovery
    auto_advertise_ledger(&node, &reserves_key, &seed, network, &relays, operator_name.as_deref(), &fee_schedule).await;
    if let Err(e) = node.subscribe_to_ledger(&ledger_id).await {
        eprintln!("  Warning: Failed to subscribe to ledger events: {}", e);
    } else {
        println!("  Subscribed to ledger events (requests/disputes)");
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

    for (ledger_id, ledger_arc) in ledgers {
        let ledger = ledger_arc.read().unwrap();
        let operator = ledger.operator_key();
        let reserves_key = ledger.reserves_key();
        let role = if operator == node.node_id {
            "Operator"
        } else {
            "Partner"
        };

        println!("  {}... ({})", &ledger_id[..16], role);
        println!("    Ledger ID: {}", ledger_id);
        println!("    Operator: {}", operator);
        println!("    Reserves Key: {}", reserves_key);
        println!("    Sequence: {}", ledger.state.sequence);
        println!("    Deposits: {} total, {} msats balance",
            ledger.state.deposits.len(),
            ledger.total_deposit_balance());
        println!("    Reserves: {} sats", ledger.reserves_amount() / 1000);
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
        node.get_ledger_with_id(&id_str)
            .ok_or_else(|| format!("Ledger not found: {}", id_str))?
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
        let has_partner_sig = update.cosign_signature != [0u8; 64];
        let has_operator_sig = update.operator_signature != [0u8; 64];
        let sig_status = format!("[{}{}]",
            if has_operator_sig { "O" } else { "·" },
            if has_partner_sig { "P" } else { "·" }
        );

        // Show signer: actual operator_id from update (may differ for DisputeAcquire)
        let signer = if has_operator_sig {
            let pk = update.operator_id.serialize();
            format!("{:02x}{:02x}", pk[1], pk[2])
        } else {
            "····".to_string()
        };

        // Show cosigner pubkey (4 hex chars or dashes if no co-signature)
        let cosigner = if let Some(ref pk) = update.cosigner_pubkey {
            let pk_bytes = pk.serialize();
            format!("{:02x}{:02x}", pk_bytes[1], pk_bytes[2])
        } else {
            "----".to_string()
        };

        // Show member ledger hash (4 hex chars or dashes if no co-signature)
        let member_hash = if let Some(ref h) = update.member_ledger_hash {
            format!("{:02x}{:02x}", h[0], h[1])
        } else {
            "----".to_string()
        };

        // Get operation name and details
        let (op_name, op_details) = format_operation(update.message_type, &update.message);

        // Truncated hash: last 2 bytes of prev, last 2 bytes of curr
        println!("{:>4} ↑{:<6} [{:02x}{:02x}~{:02x}{:02x}] {} {} {} {} {}{}",
            seq,
            update.block_height,
            prev[30], prev[31],
            curr[30], curr[31],
            sig_status,
            signer,
            cosigner,
            member_hash,
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
        node.get_ledger_with_id(&id_str)
            .ok_or_else(|| format!("Ledger not found: {}", id_str))?
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
            println!("  Reserves: {} sats", report.final_state.reserves_amount / 1000);
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

/// Check the health of ledgers: reserves, quorum, co-sign readiness, conformance
async fn ledger_health(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use deposits_core::messages::consts;
    use deposits_core::validation::LedgerConformanceValidator;

    // Parse positional arguments: [ledger_id]
    let mut ledger_id_str: Option<String> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with("--") {
            config_args.push(args[i].clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
                i += 1;
            }
        } else if ledger_id_str.is_none() {
            ledger_id_str = Some(args[i].clone());
        }
        i += 1;
    }

    if config_args.is_empty() {
        eprintln!("Usage: deposits-node ledger health [ledger_id] --seed <hex> --data-dir <path> [--network <net>] [--esplora <url>] [--relay <url>]");
        return Err("--seed and --data-dir are required".into());
    }

    let config = parse_config(&config_args)?;
    let node = Node::new(config).await?;

    // Sync wallet for on-chain state
    if let Err(e) = node.sync_wallet() {
        eprintln!("Warning: wallet sync failed: {}", e);
    }
    let block_height = node.wallet.get_block_height().unwrap_or(0);
    let wallet_balance = node.wallet_balance().unwrap_or(0);

    // Relay connectivity
    let (connected, total, relay_details) = node.nostr.relay_status().await;

    // Print node-level header
    let node_id_hex = hex::encode(node.node_id.serialize());
    println!("Node Health Report");
    println!("==================");
    println!("  Node ID:       {}", node_id_hex);
    println!("  Block height:  {}", block_height);
    println!("  Wallet:        {} sats", wallet_balance);
    println!("  Relays:        {}/{} connected", connected, total);
    for (url, status) in &relay_details {
        println!("    - {} ({})", url, status);
    }
    println!();

    // Collect ledgers to report on
    let ledger_snapshots: Vec<(String, deposits_core::ledger::Ledger)> = if let Some(id_str) = ledger_id_str {
        let (lid, ledger) = node.get_ledger_with_id(&id_str)
            .ok_or_else(|| format!("Ledger not found: {}", id_str))?;
        vec![(lid, ledger)]
    } else {
        let all = node.list_ledgers();
        if all.is_empty() {
            println!("No ledgers found.");
            return Ok(());
        }
        let mut result = Vec::new();
        for (lid, arc) in &all {
            let ledger = arc.read().unwrap().clone();
            result.push((lid.clone(), ledger));
        }
        result.sort_by(|a, b| a.0.cmp(&b.0));
        result
    };

    for (ledger_id, ledger) in &ledger_snapshots {
        let short_id = &ledger_id[..16.min(ledger_id.len())];

        let is_operator = ledger.operator_key() == node.node_id;
        let role = if is_operator { "Operator" } else { "Partner" };

        println!("Ledger {}... ({})", short_id, role);
        println!("------");

        if !is_operator {
            let op_hex = hex::encode(ledger.operator_key().serialize());
            println!("  Operator:      {}", op_hex);
        }

        // Reserves status - scan history for rotation (inline to avoid deadlock)
        let has_rotation = ledger.history.iter()
            .any(|u| u.message_type == consts::QUORUM_BEGIN);
        let reserves_sats = ledger.reserves_amount() / 1000;
        println!("  Reserves:      {} sats (rotated: {})",
            reserves_sats, if has_rotation { "yes" } else { "no" });

        // Deposits
        let total_balance_msat = ledger.total_deposit_balance();
        let deposit_count = ledger.state.deposits.len();
        println!("  Deposits:      {} msat across {} accounts",
            total_balance_msat, deposit_count);

        // Quorum members (partners backing this ledger)
        let quorum_count = ledger.state.quorum_members.len();
        println!("  Quorum:        {} members", quorum_count);
        for member in &ledger.state.quorum_members {
            let pubkey_hex = hex::encode(member.pubkey.serialize());
            let short_pubkey = &pubkey_hex[..16];
            let short_lid = if member.ledger_id.len() >= 12 {
                &member.ledger_id[..12]
            } else {
                &member.ledger_id
            };
            // Check attestation status
            let attestation = ledger.state.collateral_attestations.get(&member.pubkey);
            let attest_info = match attestation {
                Some(a) => format!("attested {} sats, expires block {}", a.amount / 1000, a.lock_until_block),
                None => "no attestation".to_string(),
            };
            println!("    - {} (ledger: {}..., {})", short_pubkey, short_lid, attest_info);
        }

        // Joined quorums (ledgers we are backing as partner)
        if !ledger.state.joined_quorums.is_empty() {
            println!("  Backing:       {} operator ledgers", ledger.state.joined_quorums.len());
            for membership in &ledger.state.joined_quorums {
                let op_hex = hex::encode(membership.operator_id.serialize());
                let short_lid = if membership.ledger_id.len() >= 12 {
                    &membership.ledger_id[..12]
                } else {
                    &membership.ledger_id
                };
                println!("    - operator {}... (ledger: {}..., expires block {})",
                    &op_hex[..16], short_lid, membership.membership_expires);
            }
        }

        // Co-sign readiness
        if has_rotation && quorum_count == 0 {
            println!("  Co-sign:       BLOCKED - reserves rotated but no quorum members!");
        } else if has_rotation {
            println!("  Co-sign:       OK (quorum co-signature required)");
        } else {
            println!("  Co-sign:       OK (operator-only signing)");
        }

        // Dispute state
        println!("  Dispute:       {:?}", ledger.state.dispute_state);

        // Pending transfers
        let pending_count = ledger.state.pending_transfers.len();
        if pending_count > 0 {
            println!("  Transfers:     {} pending", pending_count);
        }

        // Conformance
        if ledger.history.is_empty() {
            println!("  Conformance:   N/A (no history)");
        } else {
            let export = ledger.export(block_height);
            match LedgerConformanceValidator::validate(&export) {
                Ok(report) => {
                    if report.is_valid {
                        println!("  Conformance:   PASS");
                    } else {
                        println!("  Conformance:   FAIL");
                        if report.hash_chain.valid_length < report.hash_chain.total_length {
                            println!("    - Hash chain: {}/{} valid",
                                report.hash_chain.valid_length, report.hash_chain.total_length);
                        }
                        for rule in &report.business_rules {
                            if !rule.passed {
                                let details = rule.details.as_ref()
                                    .map(|d| format!(" ({})", d)).unwrap_or_default();
                                println!("    - {}{}", rule.rule, details);
                            }
                        }
                    }
                }
                Err(e) => {
                    println!("  Conformance:   ERROR ({})", e);
                }
            }
        }

        // Sequence/hash
        let hash_hex = hex::encode(&ledger.state.hash[..8]);
        println!("  Sequence:      {} (hash: {}...)", ledger.state.sequence, hash_hex);
        println!();
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
        node.get_ledger_with_id(&id_str)
            .ok_or_else(|| format!("Ledger not found: {}", id_str))?
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

    let file_path = file_path.ok_or("Usage: deposits-node ledger import <file_path> [--data-dir <dir>]")?;

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
            println!("  Reserves: {} sats", ledger.reserves_amount() / 1000);
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

/// Publish a ledger advertisement to Nostr
async fn ledger_advertise(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use deposits_node::nostr::{NostrTransportBuilder, LedgerAdvertisement};

    // Parse arguments: <reserves_id> [options]
    let mut reserves_id: Option<String> = None;
    let mut operator_name: Option<String> = None;
    let mut description: Option<String> = None;
    let mut annual_fee_bps: u32 = 0;
    let mut deposit_fee_bps: u32 = 0;
    let mut withdrawal_fee_bps: u32 = 0;
    let mut invoice_fee_bps: u32 = 0;
    let mut min_fee_sats: u64 = 0;
    let mut fee_period_blocks: u32 = 2016; // default ~2 weeks
    let mut max_deposit_sats: u64 = u64::MAX;
    let mut min_deposit_sats: u64 = 0;
    let mut advertise_relay_url: Option<String> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--name" | "--operator-name" if i + 1 < args.len() => { operator_name = Some(args[i + 1].clone()); i += 1; }
            "--description" if i + 1 < args.len() => { description = Some(args[i + 1].clone()); i += 1; }
            "--advertise-relay" if i + 1 < args.len() => { advertise_relay_url = Some(args[i + 1].clone()); i += 1; }
            "--annual-fee" if i + 1 < args.len() => {
                annual_fee_bps = args[i + 1].parse().map_err(|e| {
                    format!("Invalid --annual-fee value '{}': {}", args[i + 1], e)
                })?;
                i += 1;
            }
            "--deposit-fee" if i + 1 < args.len() => { deposit_fee_bps = args[i + 1].parse()?; i += 1; }
            "--withdrawal-fee" if i + 1 < args.len() => { withdrawal_fee_bps = args[i + 1].parse()?; i += 1; }
            "--invoice-fee" if i + 1 < args.len() => { invoice_fee_bps = args[i + 1].parse()?; i += 1; }
            "--min-fee" if i + 1 < args.len() => {
                min_fee_sats = args[i + 1].parse().map_err(|e| {
                    format!("Invalid --min-fee value '{}': {}", args[i + 1], e)
                })?;
                i += 1;
            }
            "--fee-period" if i + 1 < args.len() => {
                fee_period_blocks = args[i + 1].parse().map_err(|e| {
                    format!("Invalid --fee-period value '{}': {}", args[i + 1], e)
                })?;
                i += 1;
            }
            "--max-deposit" if i + 1 < args.len() => { max_deposit_sats = args[i + 1].parse()?; i += 1; }
            "--min-deposit" if i + 1 < args.len() => { min_deposit_sats = args[i + 1].parse()?; i += 1; }
            s if s.starts_with("--") => {
                config_args.push(args[i].clone());
                if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                    config_args.push(args[i + 1].clone());
                    i += 1;
                }
            }
            _ => {
                if reserves_id.is_none() {
                    reserves_id = Some(args[i].clone());
                }
            }
        }
        i += 1;
    }

    let reserves_id = reserves_id.ok_or(
        "Usage: deposits-node ledger advertise <reserves_id> [--name <name>] [--annual-fee <bps>] ..."
    )?;

    let config = parse_config(&config_args)?;
    let relay_url = config.relays.first()
        .ok_or("No relay configured. Use --relay <url>")?
        .clone();

    // Load node to get ledger info
    let node = Node::new(config.clone()).await?;

    // Find the ledger
    let (_, ledger) = node.get_ledger_with_id(&reserves_id)
        .ok_or_else(|| format!("Ledger not found for reserves: {}", reserves_id))?;

    let ledger_id = ledger.ledger_id_hex();
    let operator_pubkey = hex::encode(ledger.operator_key().serialize());
    let quorum_members: Vec<_> = ledger.state.quorum_members.iter().collect();

    let network = match config.network {
        bitcoin::Network::Bitcoin => "bitcoin",
        bitcoin::Network::Testnet => "testnet",
        bitcoin::Network::Signet => "signet",
        bitcoin::Network::Regtest => "regtest",
        _ => "unknown",
    };

    let mut ad = LedgerAdvertisement::new(
        ledger_id.clone(),
        operator_pubkey,
        reserves_id.clone(),
        network.to_string(),
    );

    ad.operator_name = operator_name;
    ad.description = description;
    ad.relay_url = advertise_relay_url;
    ad.annual_fee_bps = annual_fee_bps;
    ad.deposit_fee_bps = deposit_fee_bps;
    ad.withdrawal_fee_bps = withdrawal_fee_bps;
    ad.invoice_fee_bps = invoice_fee_bps;
    ad.min_fee_sats = min_fee_sats;
    ad.fee_period_blocks = fee_period_blocks;
    ad.max_deposit_sats = max_deposit_sats;
    ad.min_deposit_sats = min_deposit_sats;
    ad.reserves_amount_sats = ledger.reserves_amount() / 1000; // msats to sats for advertisement

    // Calculate obligations and headroom
    let total_obligations_msats = ledger.total_deposit_balance();
    let total_obligations_sats = total_obligations_msats / 1000;
    ad.total_obligations_sats = total_obligations_sats;

    // Headroom is the difference between reserves and obligations
    // For BDK, we advertise 80% of the raw headroom as available
    let raw_headroom = ad.reserves_amount_sats.saturating_sub(total_obligations_sats);
    ad.available_headroom_sats = (raw_headroom * 80) / 100;

    // Received collateral
    ad.received_collateral_sats = ledger.state.received_collateral_amount / 1000; // msats to sats

    println!("Publishing ledger advertisement...");
    println!("  Ledger ID: {}...", &ledger_id[..16]);
    println!("  Reserves: {} sats", ad.reserves_amount_sats);
    println!("  Obligations: {} sats", ad.total_obligations_sats);
    println!("  Available headroom: {} sats (80% of {})", ad.available_headroom_sats, raw_headroom);
    println!("  Collateral: {} sats", ad.received_collateral_sats);
    let periods_per_year = 52560u64 / ad.fee_period_blocks.max(1) as u64;
    let annualized_msats = ad.min_fee_sats.saturating_mul(periods_per_year);
    let annual_pct = ad.annual_fee_bps as f64 / 100.0;
    let fee_str = match (ad.annual_fee_bps > 0, annualized_msats > 0) {
        (true, true) => format!("{}% and {} sats per year", annual_pct, annualized_msats),
        (true, false) => format!("{}% per year", annual_pct),
        (false, true) => format!("{} sats per year", annualized_msats),
        (false, false) => "None".to_string(),
    };
    println!("  Fees: {} (period: {} blocks, {}bps deposit, {}bps withdrawal)",
        fee_str, ad.fee_period_blocks, ad.deposit_fee_bps, ad.withdrawal_fee_bps);
    println!();

    let secret_key = derive_operator_secret(&config.seed, config.network)?;
    let transport = NostrTransportBuilder::new(secret_key)
        .relay(&relay_url)
        .build()
        .await?;

    let event_id = transport.publish_ledger_advertisement(&ad).await?;
    println!("Advertisement published!");
    println!("  Event ID: {}", event_id);

    Ok(())
}

/// Discover ledgers advertising on Nostr
async fn ledger_discover(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use deposits_node::nostr::NostrTransportBuilder;

    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with("--") {
            config_args.push(args[i].clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
                i += 1;
            }
        }
        i += 1;
    }

    let config = parse_config(&config_args)?;
    let relay_url = config.relays.first()
        .ok_or("No relay configured. Use --relay <url>")?
        .clone();

    let network = match config.network {
        bitcoin::Network::Bitcoin => "bitcoin",
        bitcoin::Network::Testnet => "testnet",
        bitcoin::Network::Signet => "signet",
        bitcoin::Network::Regtest => "regtest",
        _ => "unknown",
    };

    println!("Discovering ledgers on {} network...", network);
    println!();

    let secret_key = derive_operator_secret(&config.seed, config.network)?;
    let transport = NostrTransportBuilder::new(secret_key)
        .relay(&relay_url)
        .build()
        .await?;

    let ads = transport.fetch_ledger_advertisements(network).await?;

    if ads.is_empty() {
        println!("No ledger advertisements found.");
        return Ok(());
    }

    println!("Found {} ledger(s):", ads.len());
    println!();

    for ad in ads {
        let operator_name = ad.operator_name.as_deref().unwrap_or("Anonymous");
        println!("{} ({}...):", operator_name, &ad.operator_pubkey[..12.min(ad.operator_pubkey.len())]);
        println!("  Ledger ID: {}...", &ad.ledger_id[..16.min(ad.ledger_id.len())]);
        println!("  Capacity:");
        println!("    Reserves: {} sats", ad.reserves_amount_sats);
        println!("    Obligations: {} sats", ad.total_obligations_sats);
        println!("    Available: {} sats", ad.available_headroom_sats);
        println!("  Collateral: {} sats", ad.received_collateral_sats);
        println!("  Fees:");
        println!("    Annual: {}bps ({}%)", ad.annual_fee_bps, ad.annual_fee_bps as f64 / 100.0);
        println!("    Deposit: {}bps", ad.deposit_fee_bps);
        println!("    Withdrawal: {}bps", ad.withdrawal_fee_bps);
        println!("    Invoice: {}bps", ad.invoice_fee_bps);
        if ad.min_fee_sats > 0 {
            println!("    Min fee: {} sats", ad.min_fee_sats);
        }
        println!("  Limits:");
        if ad.max_deposit_sats < u64::MAX {
            println!("    Max deposit: {} sats", ad.max_deposit_sats);
        }
        if ad.min_deposit_sats > 0 {
            println!("    Min deposit: {} sats", ad.min_deposit_sats);
        }
        if let Some(desc) = &ad.description {
            println!("  Description: {}", desc);
        }
        println!();
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
                LedgerOperation::LedgerOpen { reserves_id, .. } => {
                    let id_short = if reserves_id.len() > 20 {
                        format!("{}..{}", &reserves_id[..8], &reserves_id[reserves_id.len()-6..])
                    } else {
                        reserves_id.clone()
                    };
                    ("LedgerOpen", format!("reserves:{}", id_short))
                }
                LedgerOperation::QuorumBegin { reserves_id, amount, quorum_expiry, quorum_members, .. } => {
                    let addr_short = if reserves_id.len() > 20 {
                        format!("{}..{}", &reserves_id[..8], &reserves_id[reserves_id.len()-6..])
                    } else {
                        reserves_id.clone()
                    };
                    ("QuorumBegin", format!("addr:{}  amt:{} sat  quorum:{}/{}  expiry:{}",
                        addr_short, amount, quorum_members.len(), quorum_members.len(), quorum_expiry))
                }
                LedgerOperation::DepositOpen { deposit_id, .. } => {
                    ("DepositOpen", format!("id:{:02x}{:02x}{:02x}{:02x}", deposit_id[0], deposit_id[1], deposit_id[2], deposit_id[3]))
                }
                LedgerOperation::DepositClose { deposit_id, .. } => {
                    ("DepositClose", format!("id:{:02x}{:02x}{:02x}{:02x}", deposit_id[0], deposit_id[1], deposit_id[2], deposit_id[3]))
                }
                LedgerOperation::FeeChange { deposit_id, .. } => {
                    ("FeeChange", format!("id:{:02x}{:02x}{:02x}{:02x}", deposit_id[0], deposit_id[1], deposit_id[2], deposit_id[3]))
                }
                LedgerOperation::DepositKeyRotate { deposit_id, .. } => {
                    ("DepositKeyRotate", format!("id:{:02x}{:02x}{:02x}{:02x}", deposit_id[0], deposit_id[1], deposit_id[2], deposit_id[3]))
                }
                LedgerOperation::QuorumAddMember { quorum_member, .. } => {
                    let pk_bytes = quorum_member.serialize();
                    ("QuorumAddMember", format!("member:{:02x}{:02x}{:02x}{:02x}", pk_bytes[0], pk_bytes[1], pk_bytes[2], pk_bytes[3]))
                }
                LedgerOperation::QuorumRemoveMember { quorum_member, .. } => {
                    let pk_bytes = quorum_member.serialize();
                    ("QuorumRemoveMember", format!("member:{:02x}{:02x}{:02x}{:02x}", pk_bytes[0], pk_bytes[1], pk_bytes[2], pk_bytes[3]))
                }
                LedgerOperation::QuorumJoin { operator_id, ledger_id, membership_expires, .. } => {
                    let pk_bytes = operator_id.serialize();
                    let ledger_short = if ledger_id.len() > 16 {
                        format!("{}...", &ledger_id[..16])
                    } else {
                        ledger_id.clone()
                    };
                    ("QuorumJoin", format!("op:{:02x}{:02x}{:02x}{:02x}  ledger:{}  expires:{}",
                        pk_bytes[0], pk_bytes[1], pk_bytes[2], pk_bytes[3], ledger_short, membership_expires))
                }
                LedgerOperation::CollateralAttestation { collateral_operator, amount, lock_until_block, .. } => {
                    let pk_bytes = collateral_operator.serialize();
                    ("CollateralAttestation", format!("from:{:02x}{:02x}{:02x}{:02x}  amt:{} msat  until_block:{}",
                        pk_bytes[0], pk_bytes[1], pk_bytes[2], pk_bytes[3], amount, lock_until_block))
                }
                LedgerOperation::CollateralLock { deposit_id, amount, lock_until_block, .. } => {
                    ("CollateralLock", format!("id:{:02x}{:02x}{:02x}{:02x}  amt:{} msat  until_block:{}",
                        deposit_id[0], deposit_id[1], deposit_id[2], deposit_id[3], amount, lock_until_block))
                }
                LedgerOperation::OnchainCredit { deposit_id, amount, funding_address, .. } => {
                    let addr_short = if funding_address.len() > 20 {
                        format!("{}..{}", &funding_address[..8], &funding_address[funding_address.len()-6..])
                    } else {
                        funding_address.clone()
                    };
                    ("OnchainCredit", format!("id:{:02x}{:02x}{:02x}{:02x}  amt:{} msat  addr:{}",
                        deposit_id[0], deposit_id[1], deposit_id[2], deposit_id[3], amount, addr_short))
                }
                LedgerOperation::OnchainLock { deposit_id, amount, destination_address, withdrawal_id, .. } => {
                    let addr_short = if destination_address.len() > 20 {
                        format!("{}..{}", &destination_address[..8], &destination_address[destination_address.len()-6..])
                    } else {
                        destination_address.clone()
                    };
                    ("OnchainLock", format!("id:{:02x}{:02x}{:02x}{:02x}  amt:{} msat  wdrl:{}  addr:{}",
                        deposit_id[0], deposit_id[1], deposit_id[2], deposit_id[3], amount,
                        hex::encode(&withdrawal_id[..4]), addr_short))
                }
                LedgerOperation::OnchainFail { deposit_id, withdrawal_id, .. } => {
                    ("OnchainFail", format!("id:{:02x}{:02x}{:02x}{:02x}  wdrl:{}",
                        deposit_id[0], deposit_id[1], deposit_id[2], deposit_id[3],
                        hex::encode(&withdrawal_id[..4])))
                }
                LedgerOperation::OnchainFulfill { deposit_id, withdrawal_id, amount, txid, .. } => {
                    ("OnchainFulfill", format!("id:{:02x}{:02x}{:02x}{:02x}  amt:{} msat  wdrl:{}  txn:{}",
                        deposit_id[0], deposit_id[1], deposit_id[2], deposit_id[3],
                        amount,
                        hex::encode(&withdrawal_id[..4]),
                        hex::encode(&txid[..4])))
                }
                LedgerOperation::InvoiceCredit { deposit_id, amount, .. } => {
                    ("InvoiceCredit", format!("id:{:02x}{:02x}{:02x}{:02x}  amt:{} msat",
                        deposit_id[0], deposit_id[1], deposit_id[2], deposit_id[3], amount))
                }
                LedgerOperation::InvoiceLock { deposit_id, amount, .. } => {
                    ("InvoiceLock", format!("id:{:02x}{:02x}{:02x}{:02x}  amt:{} msat",
                        deposit_id[0], deposit_id[1], deposit_id[2], deposit_id[3], amount))
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
                LedgerOperation::DisputeEnter { last_valid_sequence, reason } => {
                    ("DisputeEnter", format!("last_valid_seq:{}  reason:{}", last_valid_sequence, reason))
                }
                LedgerOperation::DisputeArmed { armed_block, commitment_hash, target_reserves } => {
                    let hash_hex = hex::encode(commitment_hash);
                    let target_short = if target_reserves.len() > 16 {
                        format!("{}..{}", &target_reserves[..8], &target_reserves[target_reserves.len()-6..])
                    } else {
                        target_reserves.clone()
                    };
                    ("DisputeArmed", format!("armed_block:{}  commit:{}..  target:{}", armed_block, &hash_hex[..8], target_short))
                }
                LedgerOperation::DisputeAcquire { new_custodian, entropy_block_height, spend_txid, new_reserves_address, .. } => {
                    let pk_bytes = new_custodian.serialize();
                    let txid_hex = hex::encode(spend_txid);
                    ("DisputeAcquire", format!("to:{:02x}{:02x}{:02x}{:02x}  entropy_block:{}  txid:{}..  reserves:{}..{}",
                        pk_bytes[0], pk_bytes[1], pk_bytes[2], pk_bytes[3],
                        entropy_block_height,
                        &txid_hex[..8],
                        &new_reserves_address[..10.min(new_reserves_address.len())],
                        &new_reserves_address[new_reserves_address.len().saturating_sub(6)..]))
                }
                LedgerOperation::DisputeYield => {
                    ("DisputeYield", String::new())
                }
                LedgerOperation::LedgerClose => {
                    ("LedgerClose", String::new())
                }
                LedgerOperation::TransferLock { source_deposit_id, destination_deposit_id, amount, fee, timeout_height, .. } => (
                    "TransferLock",
                    format!(
                        "{}→{} amt={} fee={} timeout={}",
                        hex::encode(&source_deposit_id[..4]),
                        hex::encode(&destination_deposit_id[..4]),
                        amount,
                        fee,
                        timeout_height
                    ),
                ),
                LedgerOperation::TransferComplete { transfer_id, .. } => (
                    "TransferComplete",
                    format!("id={}", hex::encode(&transfer_id[..8])),
                ),
                LedgerOperation::TransferFail { transfer_id, .. } => (
                    "TransferFail",
                    format!("id={}", hex::encode(&transfer_id[..8])),
                ),
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
        eprintln!("Usage: deposits-node partner <request|add|join|list> [args...]");
        return Ok(());
    }

    match args[0].as_str() {
        "request" => partner_request(&args[1..]).await,
        "add" => partner_add(&args[1..]).await,
        "join" => partner_join(&args[1..]).await,
        "list" => partner_list(&args[1..]).await,
        cmd => {
            eprintln!("Unknown partner subcommand: {}", cmd);
            eprintln!("Usage: deposits-node partner <request|add|join|list> [args...]");
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
/// Usage: partner add <reserves_id> <quorum_member_pubkey> <member_ledger_id>
async fn partner_add(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut reserves_id: Option<String> = None;
    let mut quorum_member_str: Option<String> = None;
    let mut member_ledger_id: Option<String> = None;
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
        } else if member_ledger_id.is_none() {
            member_ledger_id = Some(args[i].clone());
        }
        i += 1;
    }

    let reserves_id = reserves_id.ok_or("Reserves ID required")?;
    let quorum_member_str = quorum_member_str.ok_or("Quorum member pubkey required")?;
    let member_ledger_id = member_ledger_id.ok_or("Member ledger ID required (64-char hex hash of member's ledger)")?;
    let quorum_member = PublicKey::from_str(&quorum_member_str)
        .map_err(|e| format!("Invalid quorum member pubkey: {}", e))?;

    // Validate ledger ID format (should be 64 hex chars)
    if member_ledger_id.len() != 64 || !member_ledger_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("Member ledger ID must be a 64-character hex string".into());
    }

    let config = parse_config(&config_args)?;

    // Load state from disk to resolve ledger_id
    let node = Node::new(config.clone()).await?;
    let ledger_id = if reserves_id.len() == 64 && reserves_id.chars().all(|c| c.is_ascii_hexdigit()) {
        reserves_id.clone()
    } else {
        node.get_ledger_with_id(&reserves_id)
            .map(|(lid, _)| lid)
            .ok_or_else(|| format!("Ledger not found for reserves: {}", reserves_id))?
    };
    drop(node);

    println!("Adding quorum member via daemon...");
    println!("  Ledger:   {}...", &ledger_id[..16]);
    println!("  Member:   {}", quorum_member);
    println!("  Member's collateral ledger: {}...", &member_ledger_id[..16]);

    // Extract fee limit flags
    let min_fee_bps: Option<u64> = config_args.windows(2)
        .find(|w| w[0] == "--min-fee-bps")
        .and_then(|w| w[1].parse().ok());
    let min_fee_fixed: Option<u64> = config_args.windows(2)
        .find(|w| w[0] == "--min-fee-fixed")
        .and_then(|w| w[1].parse().ok());
    let max_fee_period: Option<u64> = config_args.windows(2)
        .find(|w| w[0] == "--max-fee-period")
        .and_then(|w| w[1].parse().ok());
    let collateral_lock_amount: Option<u64> = config_args.windows(2)
        .find(|w| w[0] == "--collateral-amount")
        .and_then(|w| w[1].parse().ok());
    let collateral_lock_until: Option<u64> = config_args.windows(2)
        .find(|w| w[0] == "--collateral-lock-until")
        .and_then(|w| w[1].parse().ok());

    let mut params = serde_json::json!({
        "member_pubkey": quorum_member_str,
        "member_ledger_id": member_ledger_id,
    });
    if let Some(v) = min_fee_bps { params["min_fee_bps"] = v.into(); }
    if let Some(v) = min_fee_fixed { params["min_fee_fixed"] = v.into(); }
    if let Some(v) = max_fee_period { params["max_fee_period"] = v.into(); }
    if let Some(v) = collateral_lock_amount { params["collateral_lock_amount"] = v.into(); }
    if let Some(v) = collateral_lock_until { params["collateral_lock_until"] = v.into(); }

    let result = send_daemon_request(&config, &ledger_id, "partner_add", params).await?;

    println!("Quorum member added!");
    if let Some(event_id) = result.get("event_id").and_then(|v| v.as_str()) {
        println!("  Broadcast: {}...", &event_id[..16.min(event_id.len())]);
    }
    println!("  Member: {}", quorum_member);
    println!("  Ledger: {}", ledger_id);
    println!("  Member's collateral ledger: {}", member_ledger_id);

    Ok(())
}

/// Record that we have joined another operator's quorum
/// Usage: partner join <our_ledger_id> <target_operator> <target_ledger_id> <expires_block>
async fn partner_join(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut our_id: Option<String> = None;
    let mut target_operator_str: Option<String> = None;
    let mut target_id: Option<String> = None;
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
        } else if our_id.is_none() {
            our_id = Some(args[i].clone());
        } else if target_operator_str.is_none() {
            target_operator_str = Some(args[i].clone());
        } else if target_id.is_none() {
            target_id = Some(args[i].clone());
        } else if expires_block.is_none() {
            expires_block = Some(args[i].parse()
                .map_err(|_| "Invalid expires_block")?);
        }
        i += 1;
    }

    let our_id = our_id.ok_or("Our ledger ID required (64-char hex hash or reserves address)")?;
    let target_operator_str = target_operator_str.ok_or("Target operator pubkey required")?;
    let target_id = target_id.ok_or("Target ledger ID required (64-char hex hash)")?;
    let expires_block = expires_block.ok_or("Expires block required")?;

    let target_operator = PublicKey::from_str(&target_operator_str)
        .map_err(|e| format!("Invalid target operator pubkey: {}", e))?;

    let config = parse_config(&config_args)?;

    // Load state from disk to resolve our ledger_id
    let node = Node::new(config.clone()).await?;
    let our_ledger_id = if our_id.len() == 64 && our_id.chars().all(|c| c.is_ascii_hexdigit()) {
        our_id.clone()
    } else {
        node.get_ledger_with_id(&our_id)
            .map(|(lid, _)| lid)
            .ok_or_else(|| format!("Ledger not found for reserves: {}", our_id))?
    };
    drop(node);

    // Target must be a ledger_id hash (64 hex chars)
    let target_ledger_id = if target_id.len() == 64 && target_id.chars().all(|c| c.is_ascii_hexdigit()) {
        target_id.clone()
    } else {
        return Err(format!("Target ledger ID must be a 64-char hex hash, got: {}", target_id).into());
    };

    println!("Recording quorum join via daemon...");
    println!("  Our ledger:       {}...", &our_ledger_id[..16]);
    println!("  Target operator:  {}", target_operator);
    println!("  Target ledger:    {}...", &target_ledger_id[..16]);
    println!("  Expires at block: {}", expires_block);

    let params = serde_json::json!({
        "target_operator": target_operator_str,
        "target_ledger_id": target_ledger_id,
        "membership_expires": expires_block,
    });

    let result = send_daemon_request(&config, &our_ledger_id, "partner_join", params).await?;

    println!("Quorum join recorded!");
    if let Some(event_id) = result.get("event_id").and_then(|v| v.as_str()) {
        println!("  Broadcast: {}...", &event_id[..16.min(event_id.len())]);
    }
    println!("  Target operator: {}", target_operator);
    println!("  Target ledger: {}", target_ledger_id);
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
        eprintln!("Usage: deposits-node collateral <lock> [args...]");
        return Ok(());
    }

    match args[0].as_str() {
        "lock" | "pledge" => collateral_lock(&args[1..]).await,
        "record" => collateral_record(&args[1..]).await,
        cmd => {
            eprintln!("Unknown collateral subcommand: {}", cmd);
            eprintln!("Usage: deposits-node collateral <lock|record> [args...]");
            Ok(())
        }
    }
}

/// Lock deposit balance as collateral backing for the operator
/// Returns a signed attestation that the requesting operator can record on their ledger
///
/// Usage:
///   collateral lock <ledger_id> <amount_msats> <lock_blocks> [requesting_operator]
///       Derives deposit key from seed (wallet mode)
///   collateral lock <reserves_id> <deposit_secret> <amount_msats> <lock_blocks> [requesting_operator]
///       Uses explicit deposit secret (legacy mode)
async fn collateral_lock(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use bitcoin::bip32::{Xpriv, DerivationPath};
    use std::str::FromStr as _;

    let mut config_args = Vec::new();
    let mut positional_args = Vec::new();

    // Separate config args from positional args
    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with("--") {
            config_args.push(args[i].clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
                i += 1;
            }
        } else {
            positional_args.push(args[i].clone());
        }
        i += 1;
    }

    let config = parse_config(&config_args)?;
    let mut node = Node::new(config.clone()).await?;

    // Determine if we're in wallet mode (3 positional args) or legacy mode (4+ positional args)
    // Wallet mode: <ledger_id> <amount_msats> <lock_blocks>
    // Legacy mode: <reserves_id> <deposit_secret> <amount_msats> <lock_blocks>
    let (ledger_id, deposit_secret, amount_msats, lock_blocks, requesting_operator_hex) =
        if positional_args.len() >= 4 && positional_args[1].len() == 64 && hex::decode(&positional_args[1]).is_ok() {
            // Legacy mode: second arg looks like a hex secret
            let reserves_id = positional_args[0].clone();
            let secret_hex = positional_args[1].clone();
            let amount: u64 = positional_args[2].parse().map_err(|_| "Invalid amount_msats")?;
            let blocks: u32 = positional_args[3].parse().map_err(|_| "Invalid lock_blocks")?;
            let req_op = positional_args.get(4).cloned();

            let secret_bytes = hex::decode(&secret_hex)
                .map_err(|e| format!("Invalid deposit secret hex: {}", e))?;
            let secret = bitcoin::secp256k1::SecretKey::from_slice(&secret_bytes)
                .map_err(|e| format!("Invalid deposit secret: {}", e))?;

            (reserves_id, secret, amount, blocks, req_op)
        } else if positional_args.len() >= 3 {
            // Wallet mode: derive key from seed
            let ledger_id = positional_args[0].clone();
            let amount: u64 = positional_args[1].parse().map_err(|_| "Invalid amount_msats")?;
            let blocks: u32 = positional_args[2].parse().map_err(|_| "Invalid lock_blocks")?;
            let req_op = positional_args.get(3).cloned();

            // Look up key_index from wallet deposits.json for this ledger
            let wallet_dir = config.data_dir.join("wallet");
            let deposits_file = wallet_dir.join("deposits.json");
            let key_index: u32 = if deposits_file.exists() {
                let data = std::fs::read_to_string(&deposits_file)?;
                let deposits: Vec<serde_json::Value> = serde_json::from_str(&data).unwrap_or_default();
                deposits.iter()
                    .find(|d| d.get("ledger_id").and_then(|v| v.as_str()) == Some(&ledger_id))
                    .and_then(|d| d.get("key_index").and_then(|v| v.as_u64()))
                    .unwrap_or(0) as u32
            } else { 0 };

            let xpriv = Xpriv::new_master(config.network, &config.seed)?;
            let secp = Secp256k1::new();
            let path = DerivationPath::from_str(&format!("m/84'/0'/0'/0/{}", key_index))?;
            let derived = xpriv.derive_priv(&secp, &path)?;
            let secret = derived.private_key;

            println!("(Using wallet key index {} for ledger {}...)", key_index, &ledger_id[..16.min(ledger_id.len())]);

            (ledger_id, secret, amount, blocks, req_op)
        } else {
            return Err("Usage: collateral lock <ledger_id> <amount_msats> <lock_blocks> [requesting_op]\n       collateral lock <reserves_id> <deposit_secret> <amount_msats> <lock_blocks> [requesting_op]".into());
        };

    // Derive the deposit pubkey from the secret and create descriptor
    let secp = Secp256k1::new();
    let deposit_pubkey = PublicKey::from_secret_key(&secp, &deposit_secret);
    let descriptor = format!("pk({})", hex::encode(deposit_pubkey.serialize()));

    // Get current block height and compute lock_until_block
    let current_block = node.wallet.get_block_height()?;
    let lock_until_block = current_block + lock_blocks;

    // Parse requesting operator (defaults to self if not specified)
    let requesting_operator = if let Some(hex) = requesting_operator_hex {
        PublicKey::from_str(&hex).map_err(|e| format!("Invalid requesting_operator: {}", e))?
    } else {
        node.node_id
    };

    println!("Creating collateral lock via Nostr...");
    println!("  Ledger: {}", ledger_id);
    println!("  Deposit: {}", deposit_pubkey);
    println!("  Amount: {} msats", amount_msats);
    println!("  Lock until block: {} (current: {}, +{} blocks)", lock_until_block, current_block, lock_blocks);
    println!("  Requesting operator: {}", requesting_operator);

    // Send collateral_lock request via Nostr
    // NOTE: current handler expects deposit_secret (private key) — this is a known
    // security concern that should be replaced with signature-based auth in the future.
    let request_params = serde_json::json!({
        "deposit_secret": hex::encode(deposit_secret.secret_bytes()),
        "amount_msats": amount_msats,
        "lock_blocks": lock_blocks,
        "requesting_operator": hex::encode(requesting_operator.serialize()),
    });

    let request_id = node.nostr.send_ledger_request(
        &ledger_id,
        "collateral_lock",
        request_params,
    ).await?;

    println!("  Request ID: {}...", &request_id[..16]);

    // Wait for response
    match node.nostr.wait_for_response(&request_id, 30000).await {
        Ok(response) => {
            if response.success {
                if let Some(result) = &response.result {
                    println!("\nCollateral locked!");
                    // Extract attestation from response
                    if let Some(att_str) = result.as_str().or_else(|| result.get("attestation").and_then(|v| v.as_str())) {
                        println!("ATTESTATION_JSON:{}", att_str);
                    } else {
                        println!("ATTESTATION_JSON:{}", result);
                    }
                } else {
                    println!("\nCollateral locked! (no attestation in response)");
                }
            } else {
                let error = response.error.as_deref().unwrap_or("Unknown error");
                return Err(format!("Collateral lock failed: {}", error).into());
            }
        }
        Err(e) => return Err(format!("Timeout waiting for collateral_lock response: {}", e).into()),
    }

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

    let reserves_id_arg = reserves_id.ok_or("reserves_id required")?;
    let attestation_json = attestation_json.ok_or("attestation_json required")?;

    // Parse the attestation
    let attestation: deposits_core::CollateralAttestationMsg = serde_json::from_str(&attestation_json)
        .map_err(|e| format!("Invalid attestation JSON: {}", e))?;

    let config = parse_config(&config_args)?;

    // Load state from disk to resolve ledger_id
    let node = Node::new(config.clone()).await?;
    let ledger_id = if reserves_id_arg.len() == 64 && reserves_id_arg.chars().all(|c| c.is_ascii_hexdigit()) {
        reserves_id_arg.clone()
    } else {
        node.get_ledger_with_id(&reserves_id_arg)
            .map(|(lid, _)| lid)
            .ok_or_else(|| format!("Ledger not found for reserves: {}", reserves_id_arg))?
    };
    drop(node);

    println!("Recording collateral attestation via daemon...");
    println!("  Ledger ID: {}...", &ledger_id[..16]);
    println!("  From operator: {}", attestation.operator);
    println!("  Amount: {} msats", attestation.amount);
    println!("  Lock until: block {}", attestation.lock_until_block);

    let params = serde_json::json!({
        "attestation": attestation_json,
    });

    send_daemon_request(&config, &ledger_id, "collateral_record", params).await?;

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
        eprintln!("Usage: deposits-node deposit <offer|list|open|ls|credit|check|complete|verify-custodian|collect-fees> [args...]");
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
        "collect-fees" => deposit_collect_fees(&args[1..]).await,
        cmd => {
            eprintln!("Unknown deposit subcommand: {}", cmd);
            eprintln!("Usage: deposits-node deposit <offer|list|open|ls|credit|check|complete|verify-custodian|collect-fees> [args...]");
            Ok(())
        }
    }
}

/// Create a deposit offer for on-chain funding
async fn deposit_offer(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use deposits_node::nostr::NostrTransportBuilder;

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
        eprintln!("Usage: deposits-node deposit offer <ledger_id> <deposit_pubkey> <max_sats> <min_sats> <blocks_valid> [options]");
        eprintln!("\nExample:");
        eprintln!("  deposits-node deposit offer abc123...ledger_id 02def...deposit 1000000 10000 144");
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
    let node = Node::new(config.clone()).await?;

    // Sync wallet to get current block height
    node.sync_wallet()?;

    // Fetch the advertisement to get fee structure
    let relay_url = config.relays.first()
        .ok_or("No relay configured. Use --relay <url>")?
        .clone();
    let secret_key = derive_operator_secret(&config.seed, config.network)?;
    let transport = NostrTransportBuilder::new(secret_key)
        .relay(&relay_url)
        .build()
        .await?;

    let fees = match transport.fetch_ledger_advertisement(ledger_id).await? {
        Some(ad) => {
            let fee_struct = ad.to_fee_structure();
            println!("  Using fees from advertisement:");
            println!("    {} bps/year + {} sats/year (period: {} blocks)",
                fee_struct.annualized_bps, fee_struct.annualized_msats, fee_struct.frequency_blocks);
            Some(fee_struct)
        }
        None => {
            println!("  No advertisement found - using default fees");
            None
        }
    };

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
        fees,
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
        println!("    Deposit ID: {}", hex::encode(offer.deposit_id));
        println!();
    }

    Ok(())
}

/// Open a new deposit in a ledger
async fn deposit_open(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use deposits_node::nostr::NostrTransportBuilder;

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
        eprintln!("Usage: deposits-node deposit open <reserves_id> <deposit_pubkey> [options]");
        eprintln!("\nExample:");
        eprintln!("  deposits-node deposit open 02abc...partner 02def...deposit");
        eprintln!("\nThis opens a new deposit in the ledger with the given partner.");
        return Ok(());
    }

    let reserves_id_arg = &positional[0];
    // Validate pubkey hex (used for descriptor creation below)
    let _deposit_pubkey = PublicKey::from_str(&positional[1])
        .map_err(|e| format!("Invalid deposit pubkey: {}", e))?;

    let config = parse_config(&config_args)?;
    let mut node = Node::new(config.clone()).await?;

    // Resolve reserves_id to ledger_id
    let ledger_id = if reserves_id_arg.len() == 64 && reserves_id_arg.chars().all(|c| c.is_ascii_hexdigit()) {
        reserves_id_arg.clone()
    } else {
        node.get_ledger_with_id(reserves_id_arg)
            .map(|(lid, _)| lid)
            .ok_or_else(|| format!("Ledger not found for reserves: {}", reserves_id_arg))?
    };

    let relay_url = config.relays.first()
        .ok_or("No relay configured. Use --relay <url>")?
        .clone();
    let secret_key = derive_operator_secret(&config.seed, config.network)?;
    let transport = NostrTransportBuilder::new(secret_key)
        .relay(&relay_url)
        .build()
        .await?;

    let fees = match transport.fetch_ledger_advertisement(&ledger_id).await? {
        Some(ad) => {
            let fee_struct = ad.to_fee_structure();
            Some(fee_struct)
        }
        None => None,
    };

    // Create descriptor from pubkey
    let descriptor = format!("pk({})", positional[1]);

    println!("Opening deposit...");
    println!("  Ledger ID: {}", ledger_id);
    println!("  Descriptor: {}", descriptor);
    if let Some(ref f) = fees {
        println!("  Fees: {} bps/year + {} sats/year (period: {} blocks)",
            f.annualized_bps, f.annualized_msats, f.frequency_blocks);
    }

    let deposit = node.open_deposit(&ledger_id, &descriptor, fees, None, false, false).await?;

    println!("\nDeposit opened!");
    println!("  Deposit ID: {}", hex::encode(deposit.deposit_id));
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

    let reserves_id_arg = reserves_id_str.ok_or("Reserves ID required")?;

    let config = parse_config(&config_args)?;
    let node = Node::new(config).await?;

    // Resolve reserves_id to ledger_id
    let ledger_id = if reserves_id_arg.len() == 64 && reserves_id_arg.chars().all(|c| c.is_ascii_hexdigit()) {
        reserves_id_arg.clone()
    } else {
        node.get_ledger_with_id(&reserves_id_arg)
            .map(|(lid, _)| lid)
            .ok_or_else(|| format!("Ledger not found for reserves: {}", reserves_id_arg))?
    };

    let deposits = node.list_deposits(&ledger_id);

    if deposits.is_empty() {
        println!("No deposits found in ledger {}", ledger_id);
        return Ok(());
    }

    println!("Deposits in ledger {} ({} total):", ledger_id, deposits.len());
    println!();

    for (deposit_id, deposit) in deposits {
        println!("  Deposit ID: {}", hex::encode(deposit_id));
        println!("    Balance: {} msats ({} sats)", deposit.balance, deposit.balance / 1000);
        println!("    Locked: {} msats", deposit.locked_balance);
        let fees = &deposit.fees;
        println!("    Fees: {} fixed + {} bps every {} blocks",
            fees.annualized_msats, fees.annualized_bps, fees.frequency_blocks);
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
        eprintln!("Usage: deposits-node deposit credit <reserves_id> <deposit_pubkey> <amount_msats> <invoice_id> [options]");
        eprintln!("\nExample:");
        eprintln!("  deposits-node deposit credit 02abc...partner 02def...deposit 1000000 inv123");
        eprintln!("\nThis credits the deposit with the specified amount.");
        return Ok(());
    }

    let reserves_id_arg = &positional[0];
    let deposit_pubkey_hex = &positional[1];
    let _deposit_pubkey = PublicKey::from_str(deposit_pubkey_hex)
        .map_err(|e| format!("Invalid deposit pubkey: {}", e))?;
    let amount_msats: u64 = positional[2]
        .parse()
        .map_err(|_| format!("Invalid amount_msats: {}", positional[2]))?;
    let invoice_id = positional[3].clone();

    // Generate a payment hash
    use bitcoin::hashes::{sha256, Hash};
    let payment_hash = sha256::Hash::hash(invoice_id.as_bytes()).to_byte_array();

    // Compute deposit_id from pubkey
    let descriptor = format!("pk({})", deposit_pubkey_hex);
    let deposit_id = deposits_core::types::compute_deposit_id(&descriptor);

    let config = parse_config(&config_args)?;
    let mut node = Node::new(config).await?;

    // Resolve reserves_id to ledger_id
    let ledger_id = if reserves_id_arg.len() == 64 && reserves_id_arg.chars().all(|c| c.is_ascii_hexdigit()) {
        reserves_id_arg.clone()
    } else {
        node.get_ledger_with_id(reserves_id_arg)
            .map(|(lid, _)| lid)
            .ok_or_else(|| format!("Ledger not found for reserves: {}", reserves_id_arg))?
    };

    println!("Crediting deposit...");
    println!("  Ledger ID: {}", ledger_id);
    println!("  Deposit ID: {}", hex::encode(deposit_id));
    println!("  Amount: {} msats ({} sats)", amount_msats, amount_msats / 1000);
    println!("  Invoice ID: {}", invoice_id);

    let new_balance = node.credit_deposit(
        &ledger_id,
        deposit_id,
        amount_msats,
        payment_hash,
        invoice_id,
    ).await?;

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

    // First check if already completed
    if let Some((_, status)) = node.get_deposit_offer(&offer_id) {
        use deposits_core::types::DepositOfferStatus;
        if let DepositOfferStatus::Completed { txid, amount_sats, .. } = status {
            println!("\nFunding detected! (already completed)");
            println!("  Transaction: {}", txid);
            println!("  Amount: {} sats", amount_sats);
            return Ok(());
        }
    }

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
        eprintln!("Usage: deposits-node deposit complete <offer_id> <txid> <amount_sats> [options]");
        eprintln!("\nExample:");
        eprintln!("  deposits-node deposit complete abc123...offerid tx123...txid 100000");
        eprintln!("\nThis marks the deposit offer as complete and credits the deposit.");
        return Ok(());
    }

    let offer_id_hex = &positional[0];
    let offer_id_bytes = hex::decode(offer_id_hex)
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

    // Load state from disk to resolve the offer's ledger_id
    let node = Node::new(config.clone()).await?;
    let ledger_id = match node.get_deposit_offer(&offer_id) {
        Some((offer, _)) => offer.ledger_id.clone(),
        None => return Err(format!("Deposit offer not found: {}...", &offer_id_hex[..16]).into()),
    };
    drop(node);

    println!("Completing deposit offer via daemon...");
    println!("  Offer ID: {}", &offer_id_hex[..16]);
    println!("  Ledger:   {}...", &ledger_id[..16]);
    println!("  Transaction: {}", txid);
    println!("  Amount: {} sats", amount_sats);

    let params = serde_json::json!({
        "offer_id": offer_id_hex,
        "txid": txid,
        "amount_sats": amount_sats,
    });

    let result = send_daemon_request(&config, &ledger_id, "complete_offer", params).await?;

    let new_balance_msats = result.get("new_balance_msats").and_then(|v| v.as_u64()).unwrap_or(0);
    let new_balance_sats = result.get("new_balance_sats").and_then(|v| v.as_u64()).unwrap_or(0);

    println!("\nDeposit offer completed!");
    println!("  New balance: {} msats ({} sats)", new_balance_msats, new_balance_sats);

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

    let ledger_id = ledger_id.ok_or("Usage: deposits-node deposit verify-custodian <ledger_id> [options]")?;

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

    // Publish request (use "l" tag for ledger_id and "action" tag like other requests)
    let request_event = EventBuilder::new(
        Kind::Custom(deposits_node::nostr::KIND_LEDGER_REQUEST),
        request_content.to_string(),
    )
    .tag(Tag::custom(TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::L)), [ledger_id.as_str()]))
    .tag(Tag::custom(TagKind::custom("action"), ["custodian_query"]))
    .sign_with_keys(&keys)?;

    let request_event_id = request_event.id.to_hex();
    client.send_event(request_event).await?;
    println!("Sent custodian_query request: {}...", &request_event_id[..16]);

    // Wait for responses (poll for a few seconds)
    println!("Waiting for quorum attestations...");
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    // Fetch responses
    let response_filter = Filter::new()
        .kind(Kind::Custom(deposits_node::nostr::KIND_LEDGER_RESPONSE))
        .custom_tag(SingleLetterTag::lowercase(Alphabet::E), [request_event_id.as_str()])
        .limit(20);

    let events = client.fetch_events(vec![response_filter], Some(std::time::Duration::from_secs(5))).await?;

    // Collect attestations
    let mut attestations: HashMap<String, Vec<String>> = HashMap::new(); // custodian -> list of attesters

    for event in events {
        if let Ok(response) = serde_json::from_str::<serde_json::Value>(&event.content) {
            // Response is wrapped in LedgerResponse with "result" field
            let result = response.get("result").unwrap_or(&response);
            if let (Some(custodian), Some(attester)) = (
                result.get("custodian").and_then(|v| v.as_str()),
                result.get("attester").and_then(|v| v.as_str()),
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

/// Manually trigger fee collection for all operated ledgers
async fn deposit_collect_fees(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let config = parse_config(args)?;
    let node = Node::new(config).await?;

    println!("Collecting fees from deposits...");

    // Sync wallet first to get current block height
    if let Err(e) = node.sync_wallet() {
        eprintln!("Warning: Wallet sync failed: {}", e);
    }

    let current_block = node.wallet.get_block_height()?;
    println!("  Current block: {}", current_block);

    // Debug: show deposit fee info
    let ledgers = node.handler.ledgers.lock().unwrap().clone();
    for (_ledger_id, ledger_arc) in ledgers.iter() {
        let ledger = ledger_arc.read().unwrap();
        if ledger.operator_key() != node.node_id {
            continue;
        }
        for (deposit_id, deposit) in &ledger.state.deposits {
            let fee_due = deposit.calculate_fees_due(current_block);
            println!("  Deposit {}...:", &hex::encode(deposit_id)[..16]);
            println!("    Balance: {} msats", deposit.balance);
            println!("    Fee structure: {} bps, {} fixed, {} block period",
                deposit.fees.annualized_bps, deposit.fees.annualized_msats, deposit.fees.frequency_blocks);
            println!("    Last fee assessment: block {}", deposit.last_fee_assessment);
            println!("    Blocks since assessment: {}", current_block.saturating_sub(deposit.last_fee_assessment));
            println!("    Fee due: {} msats", fee_due);
        }
    }

    // Run fee collection
    node.auto_collect_fees().await;

    println!("Fee collection complete.");
    Ok(())
}

// ============================================================================
// Withdraw Commands
// ============================================================================

/// Handle withdraw subcommands
async fn withdraw_command(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.is_empty() {
        eprintln!("Usage: deposits-node withdraw <request|lock|complete|cancel|list> [args...]");
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
            eprintln!("Usage: deposits-node withdraw <request|lock|complete|cancel|list> [args...]");
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
        eprintln!("Usage: deposits-node withdraw request <reserves_id> <deposit_secret_hex> <address> <amount_sats> <fee_sats> [--memo <text>] [options]");
        eprintln!("\nThis command generates a nonce, signs the withdrawal request, and locks the funds.");
        return Ok(());
    }

    let reserves_id_arg = &positional[0];
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
    let mut node = Node::new(config).await?;

    // Resolve reserves_id to ledger_id
    let ledger_id = if reserves_id_arg.len() == 64 && reserves_id_arg.chars().all(|c| c.is_ascii_hexdigit()) {
        reserves_id_arg.clone()
    } else {
        node.get_ledger_with_id(reserves_id_arg)
            .map(|(lid, _)| lid)
            .ok_or_else(|| format!("Ledger not found for reserves: {}", reserves_id_arg))?
    };

    // Sync wallet
    node.sync_wallet()?;

    // Compute deposit_id from pubkey and create witness
    let descriptor = format!("pk({})", hex::encode(deposit_pubkey.serialize()));
    let deposit_id = deposits_core::types::compute_deposit_id(&descriptor);
    let depositor_witness = deposits_core::types::DescriptorWitness {
        stack: vec![signature.to_vec()],
    };

    println!("Requesting withdrawal...");
    println!("  Ledger ID: {}", ledger_id);
    println!("  Deposit ID: {}", hex::encode(deposit_id));
    println!("  Destination: {}", destination_address);
    println!("  Amount: {} sats", amount_sats);
    println!("  Fee: {} sats", fee_sats);
    if let Some(ref m) = memo {
        println!("  Memo: {}", m);
    }

    // Lock the withdrawal with co-signing
    let result = node.lock_withdrawal(
        &ledger_id,
        deposit_id,
        destination_address,
        amount_sats,
        fee_sats,
        nonce,
        depositor_witness,
        memo,
    ).await?;

    println!("\nWithdrawal locked!");
    println!("  Withdrawal ID: {}", hex::encode(&result.withdrawal.withdrawal_id));
    println!("  Nonce: {}", hex::encode(&result.withdrawal.nonce[..8]));
    println!("  Total debit: {} sats", result.withdrawal.total_debit());
    println!("  Previous balance: {} msats", result.previous_balance_msats);
    println!("  New balance: {} msats", result.new_balance_msats);
    println!("\nThe withdrawal can now be completed with:");
    println!("  deposits-node withdraw complete {} {}", ledger_id, hex::encode(&result.withdrawal.withdrawal_id));

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
        eprintln!("Usage: deposits-node withdraw lock <reserves_id> <deposit_pubkey> <address> <amount_sats> <fee_sats> <nonce_hex> <signature_hex> [--memo <text>] [options]");
        eprintln!("\nThe nonce and signature must be provided by the depositor.");
        eprintln!("For testing, use 'withdraw request' which handles signing automatically.");
        return Ok(());
    }

    let reserves_id_arg = &positional[0];
    // Validate pubkey hex (used for descriptor creation below)
    let _deposit_pubkey = PublicKey::from_str(&positional[1])
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
    let mut node = Node::new(config).await?;

    // Resolve reserves_id to ledger_id
    let ledger_id = if reserves_id_arg.len() == 64 && reserves_id_arg.chars().all(|c| c.is_ascii_hexdigit()) {
        reserves_id_arg.clone()
    } else {
        node.get_ledger_with_id(reserves_id_arg)
            .map(|(lid, _)| lid)
            .ok_or_else(|| format!("Ledger not found for reserves: {}", reserves_id_arg))?
    };

    // Sync wallet
    node.sync_wallet()?;

    println!("Locking withdrawal...");
    println!("  Ledger ID: {}", ledger_id);
    // Compute deposit_id from pubkey and create witness
    let descriptor = format!("pk({})", positional[1]);
    let deposit_id = deposits_core::types::compute_deposit_id(&descriptor);
    let depositor_witness = deposits_core::types::DescriptorWitness {
        stack: vec![signature.to_vec()],
    };

    println!("  Deposit ID: {}", hex::encode(deposit_id));
    println!("  Destination: {}", destination_address);
    println!("  Amount: {} sats", amount_sats);
    println!("  Fee: {} sats", fee_sats);
    if let Some(ref m) = memo {
        println!("  Memo: {}", m);
    }

    // Lock the withdrawal with co-signing
    let result = node.lock_withdrawal(
        &ledger_id,
        deposit_id,
        destination_address,
        amount_sats,
        fee_sats,
        nonce,
        depositor_witness,
        memo,
    ).await?;

    println!("\nWithdrawal locked!");
    println!("  Withdrawal ID: {}", hex::encode(&result.withdrawal.withdrawal_id));
    println!("  Nonce: {}", hex::encode(&result.withdrawal.nonce[..8]));
    println!("  Total debit: {} sats", result.withdrawal.total_debit());
    println!("  Previous balance: {} msats", result.previous_balance_msats);
    println!("  New balance: {} msats", result.new_balance_msats);
    println!("\nThe withdrawal can now be completed with:");
    println!("  deposits-node withdraw complete {} {}", ledger_id, hex::encode(&result.withdrawal.withdrawal_id));

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
        eprintln!("Usage: deposits-node withdraw complete <reserves_id> <withdrawal_id> [options]");
        return Ok(());
    }

    let reserves_id_arg = &positional[0];
    let withdrawal_id_hex = &positional[1];
    let id_bytes = hex::decode(withdrawal_id_hex)
        .map_err(|e| format!("Invalid withdrawal ID hex: {}", e))?;
    if id_bytes.len() != 32 {
        return Err("Withdrawal ID must be 32 bytes".into());
    }
    let mut withdrawal_id = [0u8; 32];
    withdrawal_id.copy_from_slice(&id_bytes);

    let config = parse_config(&config_args)?;
    let mut node = Node::new(config).await?;

    // Resolve reserves_id to ledger_id
    let ledger_id = if reserves_id_arg.len() == 64 && reserves_id_arg.chars().all(|c| c.is_ascii_hexdigit()) {
        reserves_id_arg.clone()
    } else {
        node.get_ledger_with_id(reserves_id_arg)
            .map(|(lid, _)| lid)
            .ok_or_else(|| format!("Ledger not found for reserves: {}", reserves_id_arg))?
    };

    // Sync wallet
    node.sync_wallet()?;

    println!("Completing withdrawal {}...", &withdrawal_id_hex[..16]);

    let result = node.complete_withdrawal(&ledger_id, &withdrawal_id).await?;

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
        println!("    Deposit ID: {}", hex::encode(withdrawal.deposit_id));
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
// Lightning Commands
// ============================================================================

/// Handle lightning (ln) subcommands
async fn lightning_command(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.is_empty() {
        eprintln!("Usage: deposits-node lightning <command> [args...]");
        eprintln!("\nLDK Sidecar Commands (via ldk-server-cli):");
        eprintln!("  invoice <amount_sats> [description]  Create a Lightning invoice");
        eprintln!("  pay <bolt11_invoice>                 Pay a Lightning invoice");
        eprintln!("  balance                              Show Lightning wallet balance");
        eprintln!("  info                                 Show LDK node info");
        eprintln!("  channels                             List Lightning channels");
        eprintln!("  payments                             List payments");
        eprintln!("\nDeposit Payment Commands:");
        eprintln!("  send     Pay invoice FROM a deposit (lock, pay, fulfill in one step)");
        eprintln!("\nLedger Operation Commands:");
        eprintln!("  lock     Lock deposit funds for an outgoing Lightning payment");
        eprintln!("  fail     Fail/cancel a pending Lightning payment and unlock funds");
        eprintln!("  fulfill  Complete a Lightning payment with the preimage");
        return Ok(());
    }

    match args[0].as_str() {
        // LDK sidecar commands
        "invoice" => lightning_invoice(&args[1..]).await,
        "pay" => lightning_pay(&args[1..]).await,
        "balance" => lightning_balance(&args[1..]).await,
        "info" => lightning_info(&args[1..]).await,
        "channels" => lightning_channels(&args[1..]).await,
        "payments" => lightning_payments(&args[1..]).await,
        // Ledger operation commands
        "lock" => lightning_lock(&args[1..]).await,
        "fail" => lightning_fail(&args[1..]).await,
        "fulfill" => lightning_fulfill(&args[1..]).await,
        // Combined commands
        "send" => lightning_send(&args[1..]).await,
        cmd => {
            eprintln!("Unknown lightning subcommand: {}", cmd);
            eprintln!("Usage: deposits-node lightning <invoice|pay|balance|info|channels|send|lock|fail|fulfill> [args...]");
            Ok(())
        }
    }
}

/// Create a Lightning invoice via LDK sidecar
async fn lightning_invoice(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use deposits_node::ldk_cli::LdkCli;

    if args.is_empty() {
        eprintln!("Usage: deposits-node lightning invoice <amount_sats> [description]");
        eprintln!("\nExample:");
        eprintln!("  deposits-node lightning invoice 50000 \"Payment for service\"");
        return Ok(());
    }

    let amount_sats: u64 = args[0].parse()
        .map_err(|_| format!("Invalid amount: {}", args[0]))?;
    let amount_msat = amount_sats * 1000;
    let description = args.get(1).map(|s| s.as_str()).unwrap_or("Deposit invoice");

    let cli = LdkCli::from_env();
    let invoice = cli.create_invoice(amount_msat, description)?;

    println!("{}", invoice);
    Ok(())
}

/// Pay a Lightning invoice via LDK sidecar
async fn lightning_pay(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use deposits_node::ldk_cli::LdkCli;

    if args.is_empty() {
        eprintln!("Usage: deposits-node lightning pay <bolt11_invoice>");
        eprintln!("\nExample:");
        eprintln!("  deposits-node lightning pay lnbc50u1p...");
        return Ok(());
    }

    let invoice = &args[0];

    let cli = LdkCli::from_env();
    let payment_id = cli.pay_invoice(invoice)?;

    println!("Payment initiated!");
    println!("  Payment ID: {}", payment_id);
    Ok(())
}

/// Show Lightning wallet balance
async fn lightning_balance(_args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use deposits_node::ldk_cli::LdkCli;

    let cli = LdkCli::from_env();
    let balances = cli.get_balances()?;

    println!("Lightning Wallet Balance:");
    println!("  On-chain total:     {} sats", balances.total_onchain_balance_sats);
    println!("  On-chain spendable: {} sats", balances.spendable_onchain_balance_sats);
    println!("  Lightning balance:  {} sats", balances.total_lightning_balance_sats);
    println!("  Anchor reserves:    {} sats", balances.total_anchor_channels_reserve_sats);
    Ok(())
}

/// Show LDK node info
async fn lightning_info(_args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use deposits_node::ldk_cli::LdkCli;

    let cli = LdkCli::from_env();
    let info = cli.get_node_info()?;

    println!("LDK Node Info:");
    println!("  Node ID: {}", info.node_id);
    if let Some(block) = info.current_best_block {
        println!("  Block height: {}", block.height);
        println!("  Block hash: {}", block.block_hash);
    }
    Ok(())
}

/// List Lightning channels
async fn lightning_channels(_args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use deposits_node::ldk_cli::LdkCli;

    let cli = LdkCli::from_env();
    let response = cli.list_channels()?;

    if response.channels.is_empty() {
        println!("No channels found.");
        return Ok(());
    }

    println!("Lightning Channels ({} total):", response.channels.len());
    println!();

    for channel in response.channels {
        let status = if channel.is_usable {
            "usable"
        } else if channel.is_channel_ready {
            "ready"
        } else {
            "pending"
        };

        println!("  Channel: {}...", &channel.channel_id[..16]);
        println!("    Counterparty: {}...", &channel.counterparty_node_id[..16]);
        println!("    Capacity:  {} sats", channel.channel_value_sats);
        println!("    Outbound:  {} msat", channel.outbound_capacity_msat);
        println!("    Inbound:   {} msat", channel.inbound_capacity_msat);
        println!("    Status:    {}", status);
        println!();
    }
    Ok(())
}

/// List Lightning payments
async fn lightning_payments(_args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use deposits_node::ldk_cli::LdkCli;

    let cli = LdkCli::from_env();
    let response = cli.list_payments()?;

    if response.payments.is_empty() {
        println!("No payments found.");
        return Ok(());
    }

    println!("Lightning Payments ({} total):", response.payments.len());
    println!();

    for payment in response.payments {
        let status = match payment.status {
            0 => "pending",
            1 => "succeeded",
            2 => "failed",
            _ => "unknown",
        };

        println!("  Payment: {}...", &payment.id[..16.min(payment.id.len())]);
        if let Some(amount) = payment.amount_msat {
            println!("    Amount: {} msat ({} sats)", amount, amount / 1000);
        }
        println!("    Status: {}", status);
        println!();
    }
    Ok(())
}

/// Lock deposit funds for an outgoing Lightning payment
async fn lightning_lock(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    // Parse positional arguments:
    // <reserves_id> <deposit_pubkey> <amount_msats> <payment_id> <signature>
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
        eprintln!("Usage: deposits-node lightning lock <reserves_id> <deposit_pubkey> <amount_msats> <payment_id> <signature>");
        eprintln!("\nExample:");
        eprintln!("  deposits-node lightning lock 02abc...partner 02def...deposit 1000000 abc123...hash def456...sig");
        eprintln!("\nThis locks funds from a deposit for an outgoing Lightning payment.");
        return Ok(());
    }

    let reserves_id = &positional[0];
    let _deposit_pubkey = PublicKey::from_str(&positional[1])
        .map_err(|e| format!("Invalid deposit pubkey: {}", e))?;
    let amount_msats: u64 = positional[2]
        .parse()
        .map_err(|_| format!("Invalid amount_msats: {}", positional[2]))?;

    let payment_id_bytes = hex::decode(&positional[3])
        .map_err(|e| format!("Invalid payment_id hex: {}", e))?;
    if payment_id_bytes.len() != 32 {
        return Err("Payment ID must be 32 bytes (64 hex characters)".into());
    }
    let mut payment_id = [0u8; 32];
    payment_id.copy_from_slice(&payment_id_bytes);

    let signature_bytes = hex::decode(&positional[4])
        .map_err(|e| format!("Invalid signature hex: {}", e))?;
    if signature_bytes.len() != 64 {
        return Err("Signature must be 64 bytes (128 hex characters)".into());
    }
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&signature_bytes);

    // Compute deposit_id from pubkey and create witness
    let descriptor = format!("pk({})", positional[1]);
    let deposit_id = deposits_core::types::compute_deposit_id(&descriptor);
    let witness = deposits_core::types::DescriptorWitness {
        stack: vec![signature.to_vec()],
    };

    let config = parse_config(&config_args)?;
    let mut node = Node::new(config).await?;

    println!("Locking deposit for Lightning payment...");
    println!("  Reserves ID: {}", reserves_id);
    println!("  Deposit ID: {}", hex::encode(deposit_id));
    println!("  Amount: {} msats ({} sats)", amount_msats, amount_msats / 1000);
    println!("  Payment ID: {}", &positional[3][..16.min(positional[3].len())]);

    let new_locked = node.lock_invoice_payment(
        reserves_id,
        deposit_id,
        amount_msats,
        payment_id,
        witness,
    ).await?;

    println!("\nPayment locked!");
    println!("  Locked balance: {} msats ({} sats)", new_locked, new_locked / 1000);

    Ok(())
}

/// Fail/cancel a pending Lightning payment
async fn lightning_fail(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    // Parse positional arguments:
    // <reserves_id> <deposit_pubkey> <amount_msats> <payment_id>
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
        eprintln!("Usage: deposits-node lightning fail <reserves_id> <deposit_pubkey> <amount_msats> <payment_id>");
        eprintln!("\nExample:");
        eprintln!("  deposits-node lightning fail 02abc...partner 02def...deposit 1000000 abc123...hash");
        eprintln!("\nThis cancels a pending Lightning payment and unlocks the funds.");
        return Ok(());
    }

    let reserves_id = &positional[0];
    let _deposit_pubkey = PublicKey::from_str(&positional[1])
        .map_err(|e| format!("Invalid deposit pubkey: {}", e))?;
    let amount_msats: u64 = positional[2]
        .parse()
        .map_err(|_| format!("Invalid amount_msats: {}", positional[2]))?;

    let payment_id_bytes = hex::decode(&positional[3])
        .map_err(|e| format!("Invalid payment_id hex: {}", e))?;
    if payment_id_bytes.len() != 32 {
        return Err("Payment ID must be 32 bytes (64 hex characters)".into());
    }
    let mut payment_id = [0u8; 32];
    payment_id.copy_from_slice(&payment_id_bytes);

    // Compute deposit_id from pubkey
    let descriptor = format!("pk({})", positional[1]);
    let deposit_id = deposits_core::types::compute_deposit_id(&descriptor);

    let config = parse_config(&config_args)?;
    let mut node = Node::new(config).await?;

    println!("Failing Lightning payment...");
    println!("  Reserves ID: {}", reserves_id);
    println!("  Deposit ID: {}", hex::encode(deposit_id));
    println!("  Amount to unlock: {} msats ({} sats)", amount_msats, amount_msats / 1000);
    println!("  Payment ID: {}", &positional[3][..16.min(positional[3].len())]);

    let new_balance = node.fail_invoice_payment(
        reserves_id,
        deposit_id,
        amount_msats,
        payment_id,
    ).await?;

    println!("\nPayment failed/cancelled!");
    println!("  New balance: {} msats ({} sats)", new_balance, new_balance / 1000);

    Ok(())
}

/// Complete a Lightning payment with the preimage
async fn lightning_fulfill(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    // Parse positional arguments:
    // <reserves_id> <deposit_pubkey> <amount_msats> <payment_id> <preimage> <signature>
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

    if positional.len() < 6 {
        eprintln!("Usage: deposits-node lightning fulfill <reserves_id> <deposit_pubkey> <amount_msats> <payment_id> <preimage> <signature>");
        eprintln!("\nExample:");
        eprintln!("  deposits-node lightning fulfill 02abc...partner 02def...deposit 1000000 abc123...hash fed987...preimage def456...sig");
        eprintln!("\nThis completes a Lightning payment by providing the preimage.");
        return Ok(());
    }

    let reserves_id = &positional[0];
    let _deposit_pubkey = PublicKey::from_str(&positional[1])
        .map_err(|e| format!("Invalid deposit pubkey: {}", e))?;
    let amount_msats: u64 = positional[2]
        .parse()
        .map_err(|_| format!("Invalid amount_msats: {}", positional[2]))?;

    let payment_id_bytes = hex::decode(&positional[3])
        .map_err(|e| format!("Invalid payment_id hex: {}", e))?;
    if payment_id_bytes.len() != 32 {
        return Err("Payment ID must be 32 bytes (64 hex characters)".into());
    }
    let mut payment_id = [0u8; 32];
    payment_id.copy_from_slice(&payment_id_bytes);

    let preimage_bytes = hex::decode(&positional[4])
        .map_err(|e| format!("Invalid preimage hex: {}", e))?;
    if preimage_bytes.len() != 32 {
        return Err("Preimage must be 32 bytes (64 hex characters)".into());
    }
    let mut preimage = [0u8; 32];
    preimage.copy_from_slice(&preimage_bytes);

    let signature_bytes = hex::decode(&positional[5])
        .map_err(|e| format!("Invalid signature hex: {}", e))?;
    if signature_bytes.len() != 64 {
        return Err("Signature must be 64 bytes (128 hex characters)".into());
    }
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&signature_bytes);

    // Compute deposit_id from pubkey and create witness
    let descriptor = format!("pk({})", positional[1]);
    let deposit_id = deposits_core::types::compute_deposit_id(&descriptor);
    let witness = deposits_core::types::DescriptorWitness {
        stack: vec![signature.to_vec()],
    };

    let config = parse_config(&config_args)?;
    let mut node = Node::new(config).await?;

    println!("Fulfilling Lightning payment...");
    println!("  Reserves ID: {}", reserves_id);
    println!("  Deposit ID: {}", hex::encode(deposit_id));
    println!("  Amount: {} msats ({} sats)", amount_msats, amount_msats / 1000);
    println!("  Payment ID: {}", &positional[3][..16.min(positional[3].len())]);

    let new_balance = node.fulfill_invoice_payment(
        reserves_id,
        deposit_id,
        amount_msats,
        payment_id,
        preimage,
        witness,
    ).await?;

    println!("\nPayment fulfilled!");
    println!("  New balance: {} msats ({} sats)", new_balance, new_balance / 1000);

    Ok(())
}

/// Send a Lightning payment FROM a deposit (combined lock + pay + fulfill)
///
/// This is the depositor-facing command that:
/// 1. Locks funds from the deposit (InvoiceLock)
/// 2. Pays the invoice via the LDK sidecar
/// 3. Fulfills the payment with the preimage (InvoiceFulfill)
async fn lightning_send(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use bitcoin::secp256k1::SecretKey;
    use deposits_node::ldk_cli::LdkCli;

    // Parse positional arguments:
    // <reserves_id> <deposit_secret> <bolt11_invoice>
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
        eprintln!("Usage: deposits-node lightning send <reserves_id> <deposit_secret_hex> <bolt11_invoice>");
        eprintln!("\nExample:");
        eprintln!("  deposits-node lightning send bcrt1q... abc123...secret lnbc50u1p...");
        eprintln!("\nThis pays an invoice FROM a deposit by:");
        eprintln!("  1. Locking funds (InvoiceLock)");
        eprintln!("  2. Paying via Lightning (LDK sidecar)");
        eprintln!("  3. Fulfilling with preimage (InvoiceFulfill)");
        return Ok(());
    }

    let reserves_id = &positional[0];
    let secret_hex = &positional[1];
    let invoice = &positional[2];

    // Parse secret key
    let secret_bytes = hex::decode(secret_hex)
        .map_err(|e| format!("Invalid secret hex: {}", e))?;
    if secret_bytes.len() != 32 {
        return Err("Secret key must be 32 bytes".into());
    }
    let secret_key = SecretKey::from_slice(&secret_bytes)
        .map_err(|e| format!("Invalid secret key: {}", e))?;

    // Derive public key and compute deposit_id
    let secp = Secp256k1::new();
    let deposit_pubkey = PublicKey::from_secret_key(&secp, &secret_key);
    let descriptor = format!("pk({})", hex::encode(deposit_pubkey.serialize()));
    let deposit_id = deposits_core::types::compute_deposit_id(&descriptor);

    // Decode invoice to get amount
    // For now, we'll pay via LDK first to get the amount, then do ledger operations
    // In production, we'd parse the BOLT11 invoice to get the amount
    let cli = LdkCli::from_env();

    println!("Sending Lightning payment from deposit...");
    println!("  Reserves: {}", reserves_id);
    println!("  Deposit ID: {}", hex::encode(deposit_id));
    println!("  Invoice: {}...", &invoice[..40.min(invoice.len())]);

    // Step 1: Pay the invoice via LDK to get payment_id and check success
    println!("\nStep 1: Paying invoice via Lightning...");
    let payment_id_hex = cli.pay_invoice(invoice)?;
    println!("  Payment initiated: {}...", &payment_id_hex[..20.min(payment_id_hex.len())]);

    // Convert payment_id to bytes
    let payment_id_bytes = hex::decode(&payment_id_hex)
        .map_err(|e| format!("Invalid payment_id hex: {}", e))?;
    if payment_id_bytes.len() != 32 {
        return Err(format!("Payment ID unexpected length: {}", payment_id_bytes.len()).into());
    }
    let mut payment_id = [0u8; 32];
    payment_id.copy_from_slice(&payment_id_bytes);

    // Wait for payment to complete
    println!("  Waiting for payment to settle...");
    std::thread::sleep(std::time::Duration::from_secs(3));

    // Check payment status and get preimage
    let payments = cli.list_payments()?;
    let payment = payments.payments.iter()
        .find(|p| p.id == payment_id_hex)
        .ok_or("Payment not found in payment list")?;

    if payment.status != 1 {
        return Err(format!("Payment failed with status: {}", payment.status).into());
    }

    let preimage_hex = payment.preimage.as_ref()
        .ok_or("Payment succeeded but no preimage returned")?;
    let preimage_bytes = hex::decode(preimage_hex)
        .map_err(|e| format!("Invalid preimage hex: {}", e))?;
    if preimage_bytes.len() != 32 {
        return Err("Preimage unexpected length".into());
    }
    let mut preimage = [0u8; 32];
    preimage.copy_from_slice(&preimage_bytes);

    let amount_msats = payment.amount_msat
        .ok_or("Payment succeeded but no amount returned")?;

    println!("  Payment succeeded!");
    println!("  Amount: {} msats", amount_msats);
    println!("  Preimage: {}...", &preimage_hex[..16]);

    // Step 2: Create signatures and record ledger operations
    println!("\nStep 2: Recording on ledger...");

    let config = parse_config(&config_args)?;
    let mut node = Node::new(config).await?;

    // Create signatures for lock and fulfill
    let lock_signature = deposits_core::create_payment_signature(
        &secret_key,
        &payment_id,
        amount_msats,
    ).map_err(|e| format!("Failed to create lock signature: {:?}", e))?;

    let fulfill_signature = deposits_core::create_payment_signature(
        &secret_key,
        &payment_id,
        amount_msats,
    ).map_err(|e| format!("Failed to create fulfill signature: {:?}", e))?;

    // Create witnesses from signatures
    let lock_witness = deposits_core::types::DescriptorWitness {
        stack: vec![lock_signature.to_vec()],
    };
    let fulfill_witness = deposits_core::types::DescriptorWitness {
        stack: vec![fulfill_signature.to_vec()],
    };

    // Lock the funds with co-signing
    println!("  Locking {} msats...", amount_msats);
    let locked_balance = node.lock_invoice_payment(
        reserves_id,
        deposit_id,
        amount_msats,
        payment_id,
        lock_witness,
    ).await?;
    println!("  Locked balance: {} msats", locked_balance);

    // Fulfill with preimage and co-signing
    println!("  Fulfilling with preimage...");
    let new_balance = node.fulfill_invoice_payment(
        reserves_id,
        deposit_id,
        amount_msats,
        payment_id,
        preimage,
        fulfill_witness,
    ).await?;

    println!("\nPayment complete!");
    println!("  Paid: {} msats ({} sats)", amount_msats, amount_msats / 1000);
    println!("  New balance: {} msats ({} sats)", new_balance, new_balance / 1000);

    Ok(())
}

// Request handlers moved to deposits_node::cli::handlers

// =============================================================================
// DANGEROUS TESTING COMMANDS
// =============================================================================
// WARNING: These commands create invalid/malicious ledger updates.
// Only use for testing recovery mechanisms. Never enable in production builds.

#[cfg(feature = "dangerous-testing")]
async fn danger_command(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.is_empty() {
        eprintln!("Usage: deposits-node danger <subcommand> [args...]");
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
    use deposits_node::nostr::NostrTransportBuilder;
    use deposits_core::SignedLedgerUpdate;
    use sha2::{Digest, Sha256};

    if args.len() < 2 {
        eprintln!("Usage: deposits-node danger publish-invalid <reserves_id> <violation_type> [options...]");
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

    let reserves_id_arg = &args[0];
    let violation_type = &args[1];
    let config_args: Vec<String> = args.iter().skip(2).cloned().collect();

    let config = parse_config(&config_args)?;

    let relay_url = config.relays.first()
        .ok_or("No relay configured. Use --relay <url>")?
        .clone();

    let secret_key = derive_operator_secret(&config.seed, config.network)?;
    let secp = Secp256k1::new();

    // Get the node to access the ledger
    let node = Node::new(config).await?;

    // Resolve reserves_id to ledger_id
    let (ledger_id, ledger) = node.get_ledger_with_id(reserves_id_arg)
        .ok_or_else(|| format!("Ledger not found: {}", reserves_id_arg))?;

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
    println!("Ledger: {}", ledger_id);
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
                cosign_signature: [0u8; 64],
                operator_signature,
                cosigner_pubkey: None,
                member_ledger_hash: None,
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
                cosign_signature: [0u8; 64],
                operator_signature,
                cosigner_pubkey: None,
                member_ledger_hash: None,
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

            // Re-sign with our key
            let signing_data = {
                let mut data = Vec::new();
                data.extend_from_slice(&replayed.message);
                data.extend_from_slice(&replayed.message_type.to_le_bytes());
                data.extend_from_slice(&replayed.sequence_number.to_le_bytes());
                data.extend_from_slice(&replayed.previous_hash);
                data.extend_from_slice(&replayed.current_hash);
                data
            };

            let msg_hash = sha256_hash(&signing_data);
            let message = Message::from_digest(msg_hash);
            let sig = secp.sign_schnorr(&message, &secret_key.keypair(&secp));
            replayed.operator_signature = sig.serialize();

            println!("Replaying update at sequence {}", replayed.sequence_number);

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
    println!("  deposits-node nostr import {}:{}", node.node_id, ledger_id);
    println!("  deposits-node ledger validate {}", ledger_id);

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
