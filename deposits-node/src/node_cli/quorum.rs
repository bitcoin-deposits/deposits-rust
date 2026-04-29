// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

use super::{parse_config, send_daemon_request};
use bitcoin::secp256k1::PublicKey;
use crate::Node;
use std::str::FromStr;

pub async fn quorum_command(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.is_empty() {
        eprintln!("Usage: deposits-node quorum <add|remove|join|begin|request|list> [args...]");
        eprintln!("  add      Add a quorum member to our ledger");
        eprintln!("  remove   Remove a quorum member from our ledger");
        eprintln!("  join     Record that we joined another operator's quorum");
        eprintln!("  begin    Activate quorum-based Taproot spending");
        eprintln!("  request  Request a peer to join our quorum");
        eprintln!("  list     List quorum relationships");
        return Ok(());
    }
    match args[0].as_str() {
        "add" => quorum_add(&args[1..]).await,
        "remove" => quorum_remove(&args[1..]).await,
        "join" => quorum_join_cmd(&args[1..]).await,
        "begin" => quorum_begin(&args[1..]).await,
        "request" => quorum_request(&args[1..]).await,
        "list" => quorum_list(&args[1..]).await,
        cmd => {
            eprintln!("Unknown quorum subcommand: {}", cmd);
            eprintln!("Usage: deposits-node quorum <add|remove|join|begin|request|list> [args...]");
            Ok(())
        }
    }
}

/// Activate quorum-based Taproot spending (rotates reserves into quorum multisig)
async fn quorum_begin(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut reserves_id: Option<String> = None;
    let mut collateral_bps: Option<u32> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with("--") {
            match args[i].as_str() {
                "--collateral-ratio" if i + 1 < args.len() => {
                    let raw = &args[i + 1];
                    let ratio: f64 = raw.parse().map_err(|_| {
                        format!("Invalid --collateral-ratio value: {} (expected float in [0, 1])", raw)
                    })?;
                    if !ratio.is_finite() || ratio < 0.0 || ratio > 1.0 {
                        return Err(format!(
                            "--collateral-ratio {} must be in [0.0, 1.0] \
                             (e.g. 0.5 for 50% collateral)",
                            raw
                        )
                        .into());
                    }
                    // Convert to basis points for the wire — the
                    // daemon expects integer bps to avoid float
                    // precision drift across the JSON boundary.
                    collateral_bps = Some((ratio * 10_000.0).round() as u32);
                    i += 1;
                }
                _ => {
                    // Config argument — pass through
                    config_args.push(args[i].clone());
                    if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                        config_args.push(args[i + 1].clone());
                        i += 1;
                    }
                }
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
        Some(id) => super::resolve_to_ledger_id(&node, &id)?,
        None => match node.get_primary_ledger() {
            Some((lid, _)) => lid,
            None => return Err("No ledger found. Open a ledger first with 'ledger open'.".into()),
        },
    };
    drop(node);

    println!("Activating quorum via daemon...");
    println!("  Ledger: {}...", &ledger_id[..16]);
    if let Some(bps) = collateral_bps {
        println!(
            "  Collateral ratio: {:.4} ({}% of UTXO held as bond)",
            bps as f64 / 10_000.0,
            bps as f64 / 100.0
        );
    }

    let mut params = serde_json::Map::new();
    if let Some(bps) = collateral_bps {
        params.insert("collateral_bps".to_string(), serde_json::json!(bps));
    }
    let result = send_daemon_request(
        &config,
        &ledger_id,
        "quorum_begin",
        serde_json::Value::Object(params),
    )
    .await?;

    println!("\nQuorum activated!");
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

/// Request a peer to be a quorum member
async fn quorum_request(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
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
    let peer_pubkey =
        PublicKey::from_str(&peer_pubkey_str).map_err(|e| format!("Invalid peer pubkey: {}", e))?;

    let config = parse_config(&config_args)?;
    let node = Node::new(config).await?;

    println!("Requesting quorum membership with: {}", peer_pubkey);

    // Send membership request via Nostr
    node.request_quorum_member(peer_pubkey).await?;

    println!("Membership request sent!");
    println!("  The peer will need to accept the request to establish the membership.");

    Ok(())
}

/// Add a quorum member to our ledger
/// Usage: quorum add <reserves_id> <quorum_member_pubkey> <member_ledger_id>
async fn quorum_add(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
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
    let member_ledger_id = member_ledger_id
        .ok_or("Member ledger ID required (64-char hex hash of member's ledger)")?;
    let quorum_member = PublicKey::from_str(&quorum_member_str)
        .map_err(|e| format!("Invalid quorum member pubkey: {}", e))?;

    // Validate ledger ID format (should be 64 hex chars)
    if !super::is_ledger_id(&member_ledger_id) {
        return Err("Member ledger ID must be a 64-character hex string".into());
    }

    let config = parse_config(&config_args)?;

    // Load state from disk to resolve ledger_id
    let node = Node::new(config.clone()).await?;
    let ledger_id = super::resolve_to_ledger_id(&node, &reserves_id)?;
    drop(node);

    println!("Adding quorum member (requesting consent from member)...");
    println!("  Ledger:   {}...", &ledger_id[..16]);
    println!("  Member:   {}", quorum_member);
    println!(
        "  Member's collateral ledger: {}...",
        &member_ledger_id[..16]
    );

    // Extract fee limit flags
    let min_fee_bps: Option<u64> = config_args
        .windows(2)
        .find(|w| w[0] == "--min-fee-bps")
        .and_then(|w| w[1].parse().ok());
    let min_fee_fixed: Option<u64> = config_args
        .windows(2)
        .find(|w| w[0] == "--min-fee-fixed")
        .and_then(|w| w[1].parse().ok());
    let max_fee_period: Option<u64> = config_args
        .windows(2)
        .find(|w| w[0] == "--max-fee-period")
        .and_then(|w| w[1].parse().ok());
    let membership_until: Option<u64> = config_args
        .windows(2)
        .find(|w| w[0] == "--membership-until")
        .and_then(|w| w[1].parse().ok());

    let mut params = serde_json::json!({
        "member_pubkey": quorum_member_str,
        "member_ledger_id": member_ledger_id,
    });
    if let Some(v) = min_fee_bps {
        params["min_fee_bps"] = v.into();
    }
    if let Some(v) = min_fee_fixed {
        params["min_fee_fixed"] = v.into();
    }
    if let Some(v) = max_fee_period {
        params["max_fee_period"] = v.into();
    }
    if let Some(v) = membership_until {
        params["membership_until"] = v.into();
    }

    let result = send_daemon_request(&config, &ledger_id, "quorum_add", params).await?;

    println!("Quorum member added!");
    if let Some(event_id) = result.get("event_id").and_then(|v| v.as_str()) {
        println!("  Broadcast: {}...", &event_id[..16.min(event_id.len())]);
    }
    println!("  Member: {}", quorum_member);
    println!("  Ledger: {}", ledger_id);
    println!("  Member's collateral ledger: {}", member_ledger_id);

    Ok(())
}

/// Remove a quorum member from our ledger (before quorum is activated).
/// Usage: quorum remove <ledger_id> <member_pubkey>
async fn quorum_remove(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut positional = Vec::new();
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
        eprintln!("Usage: deposits-node quorum remove <ledger_id> <member_pubkey>");
        return Ok(());
    }

    let ledger_id = &positional[0];
    let member_pubkey = &positional[1];

    let config = parse_config(&config_args)?;

    println!("Removing quorum member...");
    println!("  Ledger: {}...", &ledger_id[..16.min(ledger_id.len())]);
    println!(
        "  Member: {}...",
        &member_pubkey[..16.min(member_pubkey.len())]
    );

    let params = serde_json::json!({
        "member_pubkey": member_pubkey,
    });

    let result = send_daemon_request(&config, ledger_id, "quorum_remove", params).await?;
    println!("Quorum member removed.");
    println!("{}", serde_json::to_string_pretty(&result)?);

    Ok(())
}

/// Record that we have joined another operator's quorum
/// Usage: quorum join <our_ledger_id> <target_operator> <target_ledger_id> <expires_block>
async fn quorum_join_cmd(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
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
            expires_block = Some(args[i].parse().map_err(|_| "Invalid expires_block")?);
        }
        i += 1;
    }

    let our_id = our_id.ok_or("Our ledger ID required (64-char hex hash or reserves address)")?;
    let target_operator_str = target_operator_str.ok_or("Target operator pubkey required")?;
    let target_id = target_id.ok_or("Target ledger ID required (64-char hex hash)")?;
    let expires_block = expires_block.ok_or("Expires block required")?;

    let _target_operator = PublicKey::from_str(&target_operator_str)
        .map_err(|e| format!("Invalid target operator pubkey: {}", e))?;

    let config = parse_config(&config_args)?;

    // Load state from disk to resolve our ledger_id
    let node = Node::new(config.clone()).await?;
    let our_ledger_id = super::resolve_to_ledger_id(&node, &our_id)?;
    drop(node);

    // Target must be a ledger_id hash (64 hex chars) — we cannot
    // resolve a foreign reserves address without already knowing
    // the ledger.
    if !super::is_ledger_id(&target_id) {
        return Err(format!(
            "Target ledger ID must be a 64-char hex hash, got: {}",
            target_id
        )
        .into());
    }
    let target_ledger_id = target_id.clone();

    println!("Recording quorum join via daemon...");
    println!("  Our ledger:       {}...", &our_ledger_id[..16]);
    println!("  Target operator:  {}", target_operator_str);
    println!("  Target ledger:    {}...", &target_ledger_id[..16]);
    println!("  Expires at block: {}", expires_block);

    let params = serde_json::json!({
        "target_operator": target_operator_str,
        "target_ledger_id": target_ledger_id,
        "membership_expires": expires_block,
    });

    let result = send_daemon_request(&config, &our_ledger_id, "quorum_join", params).await?;

    println!("Quorum join recorded!");
    if let Some(event_id) = result.get("event_id").and_then(|v| v.as_str()) {
        println!("  Broadcast: {}...", &event_id[..16.min(event_id.len())]);
    }
    println!("  Target operator: {}", target_operator_str);
    println!("  Target ledger: {}", target_ledger_id);
    println!("  Expires at block: {}", expires_block);

    Ok(())
}

/// List quorum members
async fn quorum_list(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let config = parse_config(args)?;
    let node = Node::new(config).await?;

    let (our_ledgers, joined) = node.list_quorum_info();

    if our_ledgers.is_empty() && joined.is_empty() {
        println!("No quorum relationships.");
        return Ok(());
    }

    let pk_short = |pk: &PublicKey| {
        let s = pk.to_string();
        format!("{}...", &s[..16.min(s.len())])
    };
    let lid_short = |id: &str| format!("{}...", &id[..16.min(id.len())]);

    // Our ledgers and their quorum members
    if !our_ledgers.is_empty() {
        println!("Our ledgers:");
        for (ledger_id, active, pending) in &our_ledgers {
            println!("  {}", lid_short(ledger_id));
            if active.is_empty() && pending.is_empty() {
                println!("    (no quorum members)");
            }
            for pk in active {
                println!("    {} (active)", pk_short(pk));
            }
            for pk in pending {
                println!("    {} (pending)", pk_short(pk));
            }
        }
    }

    // Quorums we've joined, grouped by our ledger
    if !joined.is_empty() {
        println!("\nServing on quorums:");
        for (our_ledger_id, memberships) in &joined {
            println!("  via {}:", lid_short(our_ledger_id));
            for (operator, their_ledger, expires) in memberships {
                println!(
                    "    operator {} ledger {} (expires block {})",
                    pk_short(operator),
                    lid_short(their_ledger),
                    expires
                );
            }
        }
    }

    Ok(())
}
