// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! CLI command modules for deposits-node.

pub mod admin;
pub mod bootstrap;
pub mod deposit;
pub mod health;
pub mod keys;
pub mod ledger;
pub mod lightning;
pub mod nostr_commands;
pub mod quorum;
pub mod recovery;
pub mod reserves;
pub mod run;
pub mod withdraw;

#[cfg(feature = "dangerous-testing")]
pub mod danger;

use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::Network;
use crate::{Node, NodeConfig};
use std::path::PathBuf;
use std::str::FromStr;

/// Derive the operator secret key from a seed using HD derivation.
/// Matches what the Wallet does, ensuring consistent key usage across
/// the codebase. Shared by all node_cli subcommands that need to
/// reconstruct the operator's signing key from the seed.
pub fn derive_operator_secret(
    seed: &[u8; 32],
    network: Network,
) -> Result<SecretKey, String> {
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

pub fn print_usage(program: &str) {
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
    reserves        Manage reserves UTXOs (create, list)
    quorum          Manage quorum (add, remove, join, begin, request, list)
    ledger          Manage ledgers (open, list, history, validate, export,
                    import, advertise, republish, discover, health)
    collateral      Manage collateral pledges
    deposit         Manage deposit offers and credits
    withdraw        Manage on-chain withdrawals
    lightning (ln)  Lightning operations (LDK sidecar + ledger lock/fail/fulfill)
    nostr           Nostr relay operations (export, import, validate, request,
                    watch, dispute)
    recovery        Recovery and dispute pipeline (start, agree, claim, …)
    health          Cluster health checks (ping, chains, relays)
    bootstrap       Helper bring-up flows (init, reserves, quorum)
    admin           Admin daemon-side operations (buffer)
    help            Show this help message

RESERVES SUBCOMMANDS:
    reserves create [amount_sats]
                    Create a new reserves UTXO (default: 100M sats / 1 BTC)
    reserves list   List all reserves outputs

QUORUM SUBCOMMANDS:
    quorum add <ledger_id> <member_pubkey> <member_ledger_id>
                    Add a quorum member to your ledger (requests consent, records QuorumAddMember)
    quorum join <our_ledger_id> <target_operator> <target_ledger_id> <expires_block>
                    Record that you joined another operator's quorum (records QuorumJoin)
    quorum begin [reserves_id]
                    Activate quorum-based Taproot spending (rotates reserves into multisig)
    quorum request <pubkey>
                    Send quorum membership request
    quorum list     List all quorum relationships

LEDGER SUBCOMMANDS:
    ledger open [fee options]
                    Open a ledger backed by your reserves UTXO. Sets the
                    operator's *charged* fee schedule (not quorum-side
                    minimums — those live on `quorum add`):
                      --annual-fee-bps <N>             Proportional annual custody fee in basis points
                      --annual-fee-fixed-msats <N>     Fixed annual periodic fee in msats
                      --fee-period-blocks <N>          Fee collection period in blocks (default: 2016)
                      --transfer-fee-fixed-msats <N>   Fixed per-transfer fee in msats
                      --transfer-fee-rate-bps <N>      Proportional per-transfer fee in basis points
    ledger list     List all ledgers
    ledger history [reserves_id]
                    Show hash chain history for a ledger (default: primary ledger)
    ledger validate [reserves_id]
                    Validate a ledger's conformance to the Bitcoin Deposits Protocol.
                    Checks hash chain integrity, sequence continuity, and business rules.
    ledger export [reserves_id] [--json|--binary]
                    Export a ledger for external validation or backup

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
    nostr export [operator:reserves_id]
                    Broadcast ledger updates to Nostr relay (all local ledgers if no ID given)
    nostr import [operator:reserves_id]
                    Fetch ledger updates from Nostr relay (all ledgers if no ID given)
    nostr updates [ledger_id]
                    Stream ledger update events from the relay
    nostr validate <operator:reserves_id>
                    Fetch and validate a ledger's hash chain directly from Nostr
    nostr request <ledger_id> <action> [params...]
                    Send a request to a ledger. Actions:
                      deposit_open <pubkey> [fee_fixed_msats] [fee_bps] [fee_frequency_blocks]
                      make_offer <pubkey> <max_sats> <min_sats> <blocks_valid>
                      deposit_withdraw <…>
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
    {} reserves create 100000000 --network regtest

    # Open a ledger backed by your reserves UTXO
    {} ledger open --network regtest \
        --annual-fee-bps 50 --annual-fee-fixed-msats 1000000 \
        --fee-period-blocks 2016

"#,
        program, program, program, program, program
    );
}

pub fn parse_config(args: &[String]) -> Result<NodeConfig, String> {
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
    std::fs::create_dir_all(&data_dir).map_err(|e| format!("Failed to create data dir: {}", e))?;

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

/// Send a gift-wrapped admin request to the local daemon and wait for a
/// response. Use this for operations that must run inside the daemon (hold
/// the wallet lock, touch the data dir) — `reserves_create`, `ledger_open`,
/// etc. The rumor is signed by the operator key so the daemon's admin auth
/// guard accepts it as if it came from the operator themselves.
pub async fn send_admin_daemon_request(
    config: &NodeConfig,
    action: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    use crate::nostr::NostrTransportBuilder;

    if config.relays.is_empty() {
        return Err("No relay configured. Use --relay <url>".into());
    }

    let secret_key = derive_operator_secret(&config.seed, config.network)?;
    let (xonly, _) = PublicKey::from_secret_key(&bitcoin::secp256k1::Secp256k1::new(), &secret_key)
        .x_only_public_key();
    let recipient = hex::encode(xonly.serialize());

    let mut builder = NostrTransportBuilder::new(secret_key);
    for relay in &config.relays {
        builder = builder.relay(relay);
    }
    let transport = builder.build().await?;

    // Admin requests aren't tied to a ledger; use the operator's own pubkey
    // as the #l sentinel. The daemon's filter bypasses it anyway when #p
    // matches self, and handlers dispatch by action.
    let req_id = transport
        .send_admin_request(&recipient, &recipient, action, params)
        .await?;
    let resp = transport
        .wait_for_response(&req_id, 60_000)
        .await
        .map_err(|e| format!("admin request timeout: {}", e))?;

    if !resp.success {
        return Err(format!(
            "admin {} rejected: {}",
            action,
            resp.error.as_deref().unwrap_or("unknown")
        )
        .into());
    }
    resp.result
        .ok_or_else(|| "daemon returned no result".into())
}

/// Send a Nostr request to the daemon and wait for a response.
///
/// This is used by CLI commands that delegate ledger mutations to the running daemon.
/// Returns the response result JSON on success, or an error string on failure.
pub async fn send_daemon_request(
    config: &NodeConfig,
    ledger_id: &str,
    action: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    use crate::nostr::NostrTransportBuilder;

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
                    let err_msg = response
                        .error
                        .unwrap_or_else(|| "Unknown error".to_string());
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
                        let err_msg = response
                            .error
                            .unwrap_or_else(|| "Unknown error".to_string());
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

/// Fee schedule arguments parsed from CLI flags
#[derive(Default)]
pub struct FeeScheduleArgs {
    pub annual_fee_bps: Option<u32>,
    pub annualized_fixed_msats: Option<u64>,
    pub fee_period_blocks: Option<u32>,
    pub transfer_fee_fixed: Option<u64>,
    pub transfer_fee_rate_bps: Option<u16>,
    pub advertise_relay: Option<String>,
}

impl FeeScheduleArgs {
    pub fn has_any(&self) -> bool {
        self.annual_fee_bps.is_some()
            || self.annualized_fixed_msats.is_some()
            || self.fee_period_blocks.is_some()
            || self.transfer_fee_fixed.is_some()
            || self.transfer_fee_rate_bps.is_some()
    }
}

/// Helper to auto-advertise a ledger for wallet discovery
/// Accepts either reserves_key (bcrt1q...) or ledger_id (64-char hex)
/// Uses the node's existing transport to avoid ephemeral connection race conditions.
pub async fn auto_advertise_ledger(
    node: &Node,
    identifier: &str,
    _seed: &[u8; 32],
    network: bitcoin::Network,
    _relays: &[String],
    operator_name: Option<&str>,
    fee_schedule: &FeeScheduleArgs,
) {
    use crate::nostr::LedgerAdvertisement;

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
    ad.reserves_amount_msats = ledger.reserves_amount();
    ad.collateral_amount_msats = ledger.state.collateral_amount;

    // Apply fee schedule from CLI flags
    if let Some(bps) = fee_schedule.annual_fee_bps {
        ad.annual_fee_bps = bps;
    }
    if let Some(msats) = fee_schedule.annualized_fixed_msats {
        ad.annualized_fixed_msats = msats;
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

    // Access control policy
    ad.access_control = std::env::var("DEPOSIT_ACCESS_CONTROL")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);
    if ad.access_control {
        if let Ok(domains) =
            std::fs::read_to_string(node.data_dir().join("deposit_domain_allowlist.txt"))
        {
            ad.allowed_domains = domains
                .lines()
                .map(|l| l.trim().to_lowercase())
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .collect();
        }
    }

    // Per-deposit balance limit
    if let Ok(limit) = std::env::var("MAX_DEPOSIT_BALANCE_MSATS") {
        if let Ok(v) = limit.parse::<u64>() {
            if v > 0 {
                ad.max_deposit_msats = v;
            }
        }
    }

    // Obligations and headroom deliberately NOT advertised — the operator
    // can inflate them via self-paid Lightning invoices, so they're not a
    // useful trust signal. Capacity information comes from couriers (swap
    // ads) and the protocol invariant `reserves ≥ obligations` enforced by
    // the quorum.

    // Chain tip — lets wallets pick transfer timeouts without a balance_query.
    // Use the last ledger update's block_height because that's what the operator
    // validates timeouts against (current_block + max_timeout). The BDK wallet
    // tip can run ahead if the ledger is idle, which would let wallets pick
    // timeouts the operator then rejects.
    ad.current_block = ledger
        .history
        .last()
        .map(|u| u.block_height)
        .unwrap_or_else(|| node.wallet.get_block_height().unwrap_or(0));

    // Use the node's existing transport — avoids ephemeral connection race where
    // a new transport disconnects before the relay processes the write.
    match node.nostr.publish_ledger_advertisement(&ad).await {
        Ok(_) => println!("  Advertised ledger for wallet discovery"),
        Err(e) => eprintln!("  Warning: Failed to advertise ledger: {}", e),
    }
}

/// Refresh ledger advertisements on startup so the chain tip and obligation
/// counters aren't stale.
///
/// Fetches the most recent ad for each operator ledger, replaces the dynamic
/// fields (current_block, obligations, headroom, collateral counters), and
/// republishes. Static fields (fees, limits, name, description, relay_url) are
/// preserved — the original `ledger advertise` call is the source of truth for
/// those. If no prior ad exists for a ledger, it is skipped (the operator must
/// run `ledger advertise` to set initial terms).
pub async fn republish_ledger_advertisements(node: &Node) -> usize {
    let ledger_ids: Vec<String> = {
        let ledgers = node.handler.ledgers.lock().unwrap();
        ledgers
            .iter()
            .filter(|(_, arc)| {
                let l = arc.read().unwrap();
                matches!(l.role, deposits_core::ledger::LedgerRole::Operator)
            })
            .map(|(lid, _)| lid.clone())
            .collect()
    };

    let wallet_tip = node.wallet.get_block_height().unwrap_or(0);
    let mut published = 0;

    for ledger_id in ledger_ids {
        let existing = match node.nostr.fetch_ledger_advertisement(&ledger_id).await {
            Ok(Some(ad)) => ad,
            Ok(None) => {
                tracing::debug!(
                    "No prior advertisement for ledger {} — skipping republish",
                    &ledger_id[..16]
                );
                continue;
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to fetch advertisement for {}: {}",
                    &ledger_id[..16],
                    e
                );
                continue;
            }
        };

        let mut ad = existing;

        // Refresh dynamic fields from the local ledger snapshot.
        let refreshed = {
            let ledgers = node.handler.ledgers.lock().unwrap();
            ledgers.get(&ledger_id).map(|arc| {
                let l = arc.read().unwrap();
                // Use last ledger update's block_height — that's what operator
                // validators compare timeouts against (see request_handlers.rs).
                let last_block = l
                    .history
                    .last()
                    .map(|u| u.block_height)
                    .unwrap_or(wallet_tip);
                (l.reserves_amount(), l.state.collateral_amount, last_block)
            })
        };
        let Some((reserves, collateral, last_block)) = refreshed else {
            continue;
        };

        ad.reserves_amount_msats = reserves;
        ad.collateral_amount_msats = collateral;
        // obligations/headroom intentionally omitted — see comment at the
        // populate site in auto_advertise_ledger.
        ad.current_block = last_block;

        match node.nostr.publish_ledger_advertisement(&ad).await {
            Ok(_) => {
                published += 1;
                tracing::debug!("Republished advertisement for {}", &ledger_id[..16]);
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to republish advertisement for {}: {}",
                    &ledger_id[..16],
                    e
                );
            }
        }
    }

    published
}

/// Format an operation type and extract details from the message
pub fn format_operation(msg_type: u16, message: &[u8]) -> (String, String) {
    use deposits_core::messages::LedgerOperation;
    use deposits_core::tlv::TlvDecode;

    // First try to decode the operation from message bytes - this gives us the actual operation
    if !message.is_empty() {
        if let Ok(op) = LedgerOperation::tlv_decode(message) {
            let (name, details) = match op {
                LedgerOperation::LedgerOpen { reserves_id, .. } => {
                    let id_short = if reserves_id.len() > 20 {
                        format!(
                            "{}..{}",
                            &reserves_id[..8],
                            &reserves_id[reserves_id.len() - 6..]
                        )
                    } else {
                        reserves_id.clone()
                    };
                    ("LedgerOpen", format!("reserves:{}", id_short))
                }
                LedgerOperation::QuorumBegin {
                    reserves_id,
                    amount,
                    quorum_expiry,
                    quorum_members,
                    ..
                } => {
                    let addr_short = if reserves_id.len() > 20 {
                        format!(
                            "{}..{}",
                            &reserves_id[..8],
                            &reserves_id[reserves_id.len() - 6..]
                        )
                    } else {
                        reserves_id.clone()
                    };
                    (
                        "QuorumBegin",
                        format!(
                            "addr:{}  amt:{} sat  quorum:{}/{}  expiry:{}",
                            addr_short,
                            amount,
                            quorum_members.len(),
                            quorum_members.len(),
                            quorum_expiry
                        ),
                    )
                }
                LedgerOperation::DepositOpen { deposit_id, .. } => (
                    "DepositOpen",
                    format!(
                        "id:{:02x}{:02x}{:02x}{:02x}",
                        deposit_id[0], deposit_id[1], deposit_id[2], deposit_id[3]
                    ),
                ),
                LedgerOperation::DepositClose { deposit_id, .. } => (
                    "DepositClose",
                    format!(
                        "id:{:02x}{:02x}{:02x}{:02x}",
                        deposit_id[0], deposit_id[1], deposit_id[2], deposit_id[3]
                    ),
                ),
                LedgerOperation::FeeChange { deposit_id, .. } => (
                    "FeeChange",
                    format!(
                        "id:{:02x}{:02x}{:02x}{:02x}",
                        deposit_id[0], deposit_id[1], deposit_id[2], deposit_id[3]
                    ),
                ),
                LedgerOperation::DepositKeyRotate { deposit_id, .. } => (
                    "DepositKeyRotate",
                    format!(
                        "id:{:02x}{:02x}{:02x}{:02x}",
                        deposit_id[0], deposit_id[1], deposit_id[2], deposit_id[3]
                    ),
                ),
                LedgerOperation::QuorumAddMember { quorum_member, .. } => {
                    let pk_bytes = quorum_member.serialize();
                    (
                        "QuorumAddMember",
                        format!(
                            "member:{:02x}{:02x}{:02x}{:02x}",
                            pk_bytes[0], pk_bytes[1], pk_bytes[2], pk_bytes[3]
                        ),
                    )
                }
                LedgerOperation::QuorumRemoveMember { quorum_member, .. } => {
                    let pk_bytes = quorum_member.serialize();
                    (
                        "QuorumRemoveMember",
                        format!(
                            "member:{:02x}{:02x}{:02x}{:02x}",
                            pk_bytes[0], pk_bytes[1], pk_bytes[2], pk_bytes[3]
                        ),
                    )
                }
                LedgerOperation::QuorumJoin {
                    operator_id,
                    ledger_id,
                    membership_expires,
                    ..
                } => {
                    let pk_bytes = operator_id.serialize();
                    let ledger_short = if ledger_id.len() > 16 {
                        format!("{}...", &ledger_id[..16])
                    } else {
                        ledger_id.clone()
                    };
                    (
                        "QuorumJoin",
                        format!(
                            "op:{:02x}{:02x}{:02x}{:02x}  ledger:{}  expires:{}",
                            pk_bytes[0],
                            pk_bytes[1],
                            pk_bytes[2],
                            pk_bytes[3],
                            ledger_short,
                            membership_expires
                        ),
                    )
                }
                LedgerOperation::OnchainCredit {
                    deposit_id,
                    amount,
                    funding_address,
                    ..
                } => {
                    let addr_short = if funding_address.len() > 20 {
                        format!(
                            "{}..{}",
                            &funding_address[..8],
                            &funding_address[funding_address.len() - 6..]
                        )
                    } else {
                        funding_address.clone()
                    };
                    (
                        "OnchainCredit",
                        format!(
                            "id:{:02x}{:02x}{:02x}{:02x}  amt:{} msat  addr:{}",
                            deposit_id[0],
                            deposit_id[1],
                            deposit_id[2],
                            deposit_id[3],
                            amount,
                            addr_short
                        ),
                    )
                }
                LedgerOperation::OnchainLock {
                    deposit_id,
                    amount,
                    destination_address,
                    withdrawal_id,
                    ..
                } => {
                    let addr_short = if destination_address.len() > 20 {
                        format!(
                            "{}..{}",
                            &destination_address[..8],
                            &destination_address[destination_address.len() - 6..]
                        )
                    } else {
                        destination_address.clone()
                    };
                    (
                        "OnchainLock",
                        format!(
                            "id:{:02x}{:02x}{:02x}{:02x}  amt:{} msat  wdrl:{}  addr:{}",
                            deposit_id[0],
                            deposit_id[1],
                            deposit_id[2],
                            deposit_id[3],
                            amount,
                            hex::encode(&withdrawal_id[..4]),
                            addr_short
                        ),
                    )
                }
                LedgerOperation::OnchainFail {
                    deposit_id,
                    withdrawal_id,
                    ..
                } => (
                    "OnchainFail",
                    format!(
                        "id:{:02x}{:02x}{:02x}{:02x}  wdrl:{}",
                        deposit_id[0],
                        deposit_id[1],
                        deposit_id[2],
                        deposit_id[3],
                        hex::encode(&withdrawal_id[..4])
                    ),
                ),
                LedgerOperation::OnchainFulfill {
                    deposit_id,
                    withdrawal_id,
                    amount,
                    txid,
                    ..
                } => (
                    "OnchainFulfill",
                    format!(
                        "id:{:02x}{:02x}{:02x}{:02x}  amt:{} msat  wdrl:{}  txn:{}",
                        deposit_id[0],
                        deposit_id[1],
                        deposit_id[2],
                        deposit_id[3],
                        amount,
                        hex::encode(&withdrawal_id[..4]),
                        hex::encode(&txid[..4])
                    ),
                ),
                LedgerOperation::InvoiceCredit {
                    deposit_id, amount, ..
                } => (
                    "InvoiceCredit",
                    format!(
                        "id:{:02x}{:02x}{:02x}{:02x}  amt:{} msat",
                        deposit_id[0], deposit_id[1], deposit_id[2], deposit_id[3], amount
                    ),
                ),
                LedgerOperation::InvoiceLock {
                    deposit_id, amount, ..
                } => (
                    "InvoiceLock",
                    format!(
                        "id:{:02x}{:02x}{:02x}{:02x}  amt:{} msat",
                        deposit_id[0], deposit_id[1], deposit_id[2], deposit_id[3], amount
                    ),
                ),
                LedgerOperation::InvoiceFail { .. } => ("InvoiceFail", String::new()),
                LedgerOperation::InvoiceFulfill { .. } => ("InvoiceFulfill", String::new()),
                LedgerOperation::FeeCollect { .. } => ("FeeCollect", String::new()),
                LedgerOperation::DisputeEnter {
                    last_valid_sequence,
                    reason,
                } => (
                    "DisputeEnter",
                    format!("last_valid_seq:{}  reason:{}", last_valid_sequence, reason),
                ),
                LedgerOperation::DisputeArmed {
                    armed_block,
                    commitment_hash,
                    target_reserves,
                } => {
                    let hash_hex = hex::encode(commitment_hash);
                    let target_short = if target_reserves.len() > 16 {
                        format!(
                            "{}..{}",
                            &target_reserves[..8],
                            &target_reserves[target_reserves.len() - 6..]
                        )
                    } else {
                        target_reserves.clone()
                    };
                    (
                        "DisputeArmed",
                        format!(
                            "armed_block:{}  commit:{}..  target:{}",
                            armed_block,
                            &hash_hex[..8],
                            target_short
                        ),
                    )
                }
                LedgerOperation::DisputeAcquire {
                    new_custodian,
                    claim_txid,
                    new_reserves_address,
                    ..
                } => {
                    let pk_bytes = new_custodian.serialize();
                    let txid_hex = hex::encode(claim_txid);
                    ("DisputeAcquire", format!("to:{:02x}{:02x}{:02x}{:02x}  claim_txid:{}..  reserves:{}..{}",
                        pk_bytes[0], pk_bytes[1], pk_bytes[2], pk_bytes[3],
                        &txid_hex[..8],
                        &new_reserves_address[..10.min(new_reserves_address.len())],
                        &new_reserves_address[new_reserves_address.len().saturating_sub(6)..]))
                }
                LedgerOperation::DisputeYield => ("DisputeYield", String::new()),
                LedgerOperation::DeliveryEmbed {
                    target_ledger_id, ..
                } => (
                    "DeliveryEmbed",
                    format!("target_ledger={}...", &hex::encode(target_ledger_id)[..16]),
                ),
                LedgerOperation::LedgerClose => ("LedgerClose", String::new()),
                LedgerOperation::TransferLock {
                    source_deposit_id,
                    destination_deposit_id,
                    amount,
                    fee,
                    timeout_height,
                    ..
                } => (
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

pub async fn show_info(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
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

pub async fn show_address(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let config = parse_config(args)?;
    let node = Node::new(config).await?;

    let address = node.new_address()?;
    println!("{}", address);

    Ok(())
}

pub async fn collateral_command(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    // Collateral operations have been removed in the collateral-in-UTXO migration.
    let _ = args;
    eprintln!(
        "The 'collateral' subcommand has been removed. Collateral is now tracked \
         at the UTXO level via collateral_amount on LedgerOpen/QuorumBegin."
    );
    Ok(())
}
