// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

use super::{parse_config, send_daemon_request};
use bitcoin::secp256k1::{PublicKey, Secp256k1};
use deposits_node::Node;
use std::str::FromStr;

/// Handle deposit subcommands
pub async fn deposit_command(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.is_empty() {
        eprintln!("Usage: deposits-node deposit <offer|list|open|ls|credit|check|complete|verify-custodian|collect-fees> [args...]");
        return Ok(());
    }

    match args[0].as_str() {
        "offer" => deposit_offer(&args[1..]).await,
        "list" => deposit_list(&args[1..]).await,
        "open" => deposit_open(&args[1..]).await,
        "ls" => deposit_ls(&args[1..]).await,
        "address" => deposit_address(&args[1..]),
        "invoice" => deposit_invoice(&args[1..]).await,
        "pending" => deposit_pending(&args[1..]).await,
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
        eprintln!(
            "  deposits-node deposit offer abc123...ledger_id 02def...deposit 1000000 10000 144"
        );
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
    let relay_url = config
        .relays
        .first()
        .ok_or("No relay configured. Use --relay <url>")?
        .clone();
    let secret_key = super::super::derive_operator_secret(&config.seed, config.network)?;
    let transport = NostrTransportBuilder::new(secret_key)
        .relay(&relay_url)
        .build()
        .await?;

    let fees = match transport.fetch_ledger_advertisement(ledger_id).await? {
        Some(ad) => {
            let fee_struct = ad.to_fee_structure();
            println!("  Using fees from advertisement:");
            println!(
                "    {} bps/year + {} sats/year (period: {} blocks)",
                fee_struct.annualized_bps, fee_struct.annualized_msats, fee_struct.frequency_blocks
            );
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
    println!("  Offer ID: {}", hex::encode(offer.offer_id));
    println!("  Funding address: {}", offer.funding_address);
    println!("  Deadline block: {}", offer.deadline_block);
    println!("  Created at block: {}", offer.created_at_block);
    println!(
        "  Signature: {}",
        hex::encode(&offer.operator_signature[..32])
    );
    println!(
        "\nSend {} to {} sats to: {}",
        min_sats, max_sats, offer.funding_address
    );
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
            deposits_core::DepositOfferStatus::FundingReceived {
                txid, amount_sats, ..
            } => {
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
        println!(
            "    Amount: {} - {} sats",
            offer.min_amount_sats, offer.max_amount_sats
        );
        println!("    Deadline: block {}", offer.deadline_block);
        println!(
            "    Ledger: {}...",
            &offer.ledger_id[..16.min(offer.ledger_id.len())]
        );
        println!("    Deposit ID: {}", hex::encode(offer.deposit_id));
        println!();
    }

    Ok(())
}

/// Show the lightning address for a deposit (for use with LNURL gateway).
/// Usage: deposit address <ledger_id> <deposit_pubkey> [--domain pay.example.com]
fn deposit_address(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    const BECH32_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    fn hex_to_bech32(hex_id: &str) -> Result<String, Box<dyn std::error::Error>> {
        let bytes = hex::decode(hex_id)?;
        let mut result = Vec::new();
        let mut acc: u32 = 0;
        let mut bits: u32 = 0;
        for &b in &bytes {
            acc = (acc << 8) | b as u32;
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                result.push(BECH32_CHARSET[((acc >> bits) & 0x1f) as usize]);
            }
        }
        if bits > 0 {
            result.push(BECH32_CHARSET[((acc << (5 - bits)) & 0x1f) as usize]);
        }
        Ok(String::from_utf8(result)?)
    }

    let mut positional = Vec::new();
    let mut domain = "pay.example.com".to_string();

    let mut i = 0;
    while i < args.len() {
        if args[i] == "--domain" && i + 1 < args.len() {
            domain = args[i + 1].clone();
            i += 2;
            continue;
        }
        if !args[i].starts_with("--") {
            positional.push(args[i].clone());
        }
        i += 1;
    }

    if positional.len() < 2 {
        eprintln!("Usage: deposits-node deposit address <ledger_id> <deposit_pubkey> [--domain pay.example.com]");
        return Ok(());
    }

    let ledger_id = &positional[0];
    let pubkey = &positional[1];
    let subdomain = hex_to_bech32(ledger_id)?;

    println!("{}@{}.{}", pubkey, subdomain, domain);

    Ok(())
}

async fn deposit_invoice(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
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
        eprintln!("Usage: deposits-node deposit invoice <ledger_id> <deposit_pubkey> <amount_sats> [description]");
        eprintln!("\nCreates a BOLT11 invoice that credits the deposit when paid.");
        return Ok(());
    }

    let ledger_id = &positional[0];
    let deposit_pubkey = &positional[1];
    let amount_sats: u64 = positional[2].parse().map_err(|_| "Invalid amount_sats")?;
    let description = positional
        .get(3)
        .map(|s| s.as_str())
        .unwrap_or("Deposit credit");

    let config = parse_config(&config_args)?;

    let params = serde_json::json!({
        "deposit_pubkey": deposit_pubkey,
        "amount_sats": amount_sats,
        "description": description,
    });

    let result = send_daemon_request(&config, ledger_id, "make_invoice", params).await?;

    if let Some(invoice) = result.get("invoice").and_then(|v| v.as_str()) {
        println!("{}", invoice);
    } else {
        println!("{}", serde_json::to_string_pretty(&result)?);
    }

    Ok(())
}

/// Show pending invoices and deposit offers
async fn deposit_pending(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let config = parse_config(args)?;
    let wallet_dir = config.data_dir.join("wallet");

    // Pending invoices
    let invoices_file = wallet_dir.join("pending_invoices.json");
    if invoices_file.exists() {
        let contents = std::fs::read_to_string(&invoices_file)?;
        let invoices: Vec<serde_json::Value> = serde_json::from_str(&contents).unwrap_or_default();
        if invoices.is_empty() {
            println!("No pending invoices.");
        } else {
            println!("Pending invoices ({}):", invoices.len());
            for inv in &invoices {
                let hash = inv
                    .get("payment_hash_hex")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                let ledger = inv.get("ledger_id").and_then(|v| v.as_str()).unwrap_or("?");
                let amount = inv.get("amount_msat").and_then(|v| v.as_u64()).unwrap_or(0);
                let created = inv.get("created_at").and_then(|v| v.as_u64()).unwrap_or(0);
                let age_secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs().saturating_sub(created))
                    .unwrap_or(0);
                let age_min = age_secs / 60;
                println!(
                    "  hash:{:.16}  ledger:{:.16}  {} sats  {}m ago",
                    hash,
                    ledger,
                    amount / 1000,
                    age_min
                );
            }
        }
    } else {
        println!("No pending invoices.");
    }

    // Pending deposit offers
    let offers_file = wallet_dir.join("deposit_offers.json");
    if offers_file.exists() {
        let contents = std::fs::read_to_string(&offers_file)?;
        let offers: Vec<serde_json::Value> = serde_json::from_str(&contents).unwrap_or_default();
        let pending: Vec<&serde_json::Value> = offers
            .iter()
            .filter(|o| {
                o.get(1).and_then(|s| s.as_str()) == Some("Pending")
                    || o.get(1).and_then(|v| v.get("FundingReceived")).is_some()
            })
            .collect();
        if pending.is_empty() {
            println!("No pending deposit offers.");
        } else {
            println!("\nPending deposit offers ({}):", pending.len());
            for offer in &pending {
                if let Some(o) = offer.get(0) {
                    let id = o.get("offer_id").and_then(|v| v.as_str()).unwrap_or("?");
                    let ledger = o.get("ledger_id").and_then(|v| v.as_str()).unwrap_or("?");
                    let status = offer.get(1).map(|v| v.to_string()).unwrap_or_default();
                    println!("  offer:{:.16}  ledger:{:.16}  {}", id, ledger, status);
                }
            }
        }
    } else {
        println!("No pending deposit offers.");
    }

    Ok(())
}

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

    // Check for --collateral flag
    let is_collateral = config_args.iter().any(|a| a == "--collateral");
    let config_args: Vec<String> = config_args
        .into_iter()
        .filter(|a| a != "--collateral")
        .collect();

    if positional.len() < 2 {
        eprintln!("Usage: deposits-node deposit open <reserves_id> <deposit_pubkey> [--collateral] [options]");
        eprintln!("\nExample:");
        eprintln!("  deposits-node deposit open 02abc...partner 02def...deposit");
        eprintln!("  deposits-node deposit open <ledger_id> <pubkey> --collateral");
        return Ok(());
    }

    let ledger_id = &positional[0];
    let deposit_pubkey = &positional[1];

    // Validate pubkey
    let _ = PublicKey::from_str(deposit_pubkey)
        .map_err(|e| format!("Invalid deposit pubkey: {}", e))?;

    let config = parse_config(&config_args)?;

    println!("Opening deposit...");
    println!("  Ledger ID: {}", ledger_id);
    println!("  Deposit pubkey: {}", deposit_pubkey);
    if is_collateral {
        println!("  Type: COLLATERAL");
    }

    let mut params = serde_json::json!({
        "deposit_pubkey": deposit_pubkey,
    });
    if is_collateral {
        params["is_collateral"] = serde_json::json!(true);
    }

    let result = send_daemon_request(&config, ledger_id, "deposit_open", params).await?;

    println!("\nDeposit opened!");
    if let Some(deposit_id) = result.get("deposit_id").and_then(|v| v.as_str()) {
        println!("  Deposit ID: {}", deposit_id);
    }
    println!("  {}", serde_json::to_string_pretty(&result)?);

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
    let ledger_id =
        if reserves_id_arg.len() == 64 && reserves_id_arg.chars().all(|c| c.is_ascii_hexdigit()) {
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

    println!(
        "Deposits in ledger {} ({} total):",
        ledger_id,
        deposits.len()
    );
    println!();

    for (deposit_id, deposit) in deposits {
        println!("  Deposit ID: {}", hex::encode(deposit_id));
        println!(
            "    Balance: {} msats ({} sats)",
            deposit.balance,
            deposit.balance / 1000
        );
        println!("    Locked: {} msats", deposit.locked_balance);
        let fees = &deposit.fees;
        println!(
            "    Fees: {} fixed + {} bps every {} blocks",
            fees.annualized_msats, fees.annualized_bps, fees.frequency_blocks
        );
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
        eprintln!("\nThis credits the deposit with the specified amount via the running daemon.");
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

    // Compute deposit_id from pubkey
    let descriptor = format!("pk({})", deposit_pubkey_hex);
    let deposit_id = deposits_core::types::compute_deposit_id(&descriptor);

    let config = parse_config(&config_args)?;

    // Resolve reserves_id to ledger_id
    let ledger_id =
        if reserves_id_arg.len() == 64 && reserves_id_arg.chars().all(|c| c.is_ascii_hexdigit()) {
            reserves_id_arg.clone()
        } else {
            let node = Node::new(config.clone()).await?;
            node.get_ledger_with_id(reserves_id_arg)
                .map(|(lid, _)| lid)
                .ok_or_else(|| format!("Ledger not found for reserves: {}", reserves_id_arg))?
        };

    println!("Crediting deposit via daemon...");
    println!("  Ledger ID: {}", ledger_id);
    println!("  Deposit ID: {}", hex::encode(deposit_id));
    println!(
        "  Amount: {} msats ({} sats)",
        amount_msats,
        amount_msats / 1000
    );
    println!("  Invoice ID: {}", invoice_id);

    let params = serde_json::json!({
        "deposit_pubkey": deposit_pubkey_hex,
        "amount_msats": amount_msats,
        "invoice_id": invoice_id,
    });

    let result = send_daemon_request(&config, &ledger_id, "deposit_credit", params).await?;

    let new_balance_msats = result
        .get("new_balance_msats")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let new_balance_sats = result
        .get("new_balance_sats")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    println!("\nDeposit credited!");
    println!(
        "  New balance: {} msats ({} sats)",
        new_balance_msats, new_balance_sats
    );

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
    let offer_id_bytes =
        hex::decode(&offer_id_str).map_err(|e| format!("Invalid offer ID hex: {}", e))?;

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
        if let DepositOfferStatus::Completed {
            txid, amount_sats, ..
        } = status
        {
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
            println!(
                "\nUse 'deposit complete <offer_id> <txid> <amount_sats>' to credit the deposit."
            );
        }
        None => {
            println!("\nNo funding detected yet.");
            if let Some((offer, _)) = node.get_deposit_offer(&offer_id) {
                println!("  Funding address: {}", offer.funding_address);
                println!(
                    "  Waiting for payment of {} - {} sats",
                    offer.min_amount_sats, offer.max_amount_sats
                );
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
        eprintln!(
            "Usage: deposits-node deposit complete <offer_id> <txid> <amount_sats> [options]"
        );
        eprintln!("\nExample:");
        eprintln!("  deposits-node deposit complete abc123...offerid tx123...txid 100000");
        eprintln!("\nThis marks the deposit offer as complete and credits the deposit.");
        return Ok(());
    }

    let offer_id_hex = &positional[0];
    let offer_id_bytes =
        hex::decode(offer_id_hex).map_err(|e| format!("Invalid offer ID hex: {}", e))?;

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

    let new_balance_msats = result
        .get("new_balance_msats")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let new_balance_sats = result
        .get("new_balance_sats")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    println!("\nDeposit offer completed!");
    println!(
        "  New balance: {} msats ({} sats)",
        new_balance_msats, new_balance_sats
    );

    Ok(())
}

/// Verify the current custodian of a ledger by querying quorum members
async fn deposit_verify_custodian(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use deposits_node::nostr::{TAG_EVENT_REF, TAG_LEDGER_REQ};
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

    let ledger_id =
        ledger_id.ok_or("Usage: deposits-node deposit verify-custodian <ledger_id> [options]")?;

    let config = parse_config(&config_args)?;
    let relay_url = config
        .relays
        .first()
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
    .tag(Tag::custom(
        TagKind::SingleLetter(TAG_LEDGER_REQ),
        [ledger_id.as_str()],
    ))
    .tag(Tag::custom(TagKind::custom("action"), ["custodian_query"]))
    .sign_with_keys(&keys)?;

    let request_event_id = request_event.id.to_hex();
    client.send_event(request_event).await?;
    println!(
        "Sent custodian_query request: {}...",
        &request_event_id[..16]
    );

    // Wait for responses (poll for a few seconds)
    println!("Waiting for quorum attestations...");
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    // Fetch responses
    let response_filter = Filter::new()
        .kind(Kind::Custom(deposits_node::nostr::KIND_LEDGER_RESPONSE))
        .custom_tag(TAG_EVENT_REF, [request_event_id.as_str()])
        .limit(20);

    let events = client
        .fetch_events(
            vec![response_filter],
            Some(std::time::Duration::from_secs(5)),
        )
        .await?;

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
                attestations
                    .entry(custodian.to_string())
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
            println!(
                "MAJORITY CUSTODIAN ({}%): {}",
                percentage, majority_custodian
            );
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
            println!(
                "    Fee structure: {} bps, {} fixed, {} block period",
                deposit.fees.annualized_bps,
                deposit.fees.annualized_msats,
                deposit.fees.frequency_blocks
            );
            println!(
                "    Last fee assessment: block {}",
                deposit.last_fee_assessment
            );
            println!(
                "    Blocks since assessment: {}",
                current_block.saturating_sub(deposit.last_fee_assessment)
            );
            println!("    Fee due: {} msats", fee_due);
        }
    }

    // Run fee collection
    node.auto_collect_fees().await;

    println!("Fee collection complete.");
    Ok(())
}
