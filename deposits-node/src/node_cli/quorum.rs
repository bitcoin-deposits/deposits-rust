// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

use super::{parse_config, send_daemon_request};
use crate::Node;
use bitcoin::secp256k1::PublicKey;
use std::str::FromStr;

pub async fn quorum_command(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.is_empty() {
        eprintln!(
            "Usage: deposits-node quorum <add|remove|join|begin|repair|refresh|request|list|form-with|show-identity|candidate> [args...]"
        );
        eprintln!("  add            Add a single quorum member to our ledger");
        eprintln!("  remove         Remove a quorum member from our ledger");
        eprintln!("  join           Record that we joined another operator's quorum");
        eprintln!("  begin          Activate quorum-based Taproot spending");
        eprintln!(
            "  upgrade        Off-chain consensus-version bump (DEP-18; same reserves family)"
        );
        eprintln!("  repair         Re-establish quorum past `quorum_expiry` via the DEP-05 §Lifecycle cascade");
        eprintln!(
            "  refresh        Re-add active members and rotate when all responded (idempotent)"
        );
        eprintln!("  request        Request a peer to join our quorum");
        eprintln!("  list           List quorum relationships");
        eprintln!("  form-with      Form a quorum with N named peers in one shot (add + begin)");
        eprintln!("  show-identity  Print this operator's pubkey + owned ledger IDs (for peer coordination)");
        eprintln!("  candidate      Manage the pre-curated queue of replacement-member candidates");
        return Ok(());
    }
    match args[0].as_str() {
        "add" => quorum_add(&args[1..]).await,
        "remove" => quorum_remove(&args[1..]).await,
        "join" => quorum_join_cmd(&args[1..]).await,
        "begin" => quorum_begin(&args[1..]).await,
        "upgrade" => quorum_upgrade(&args[1..]).await,
        "repair" => quorum_repair(&args[1..]).await,
        "refresh" => quorum_refresh(&args[1..]).await,
        "request" => quorum_request(&args[1..]).await,
        "list" => quorum_list(&args[1..]).await,
        "form-with" => quorum_form_with(&args[1..]).await,
        "show-identity" => quorum_show_identity(&args[1..]).await,
        "candidate" => quorum_candidate(&args[1..]).await,
        cmd => {
            eprintln!("Unknown quorum subcommand: {}", cmd);
            eprintln!(
                "Usage: deposits-node quorum <add|remove|join|begin|repair|refresh|request|list|form-with|show-identity|candidate> [args...]"
            );
            Ok(())
        }
    }
}

/// Activate quorum-based Taproot spending (rotates reserves into quorum multisig)
async fn quorum_begin(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut reserves_id: Option<String> = None;
    let mut collateral_bps: Option<u32> = None;
    let mut amount_sats: Option<u64> = None;
    let mut protocol_version: Option<String> = None;
    let mut expiry_blocks: Option<u32> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with("--") {
            match args[i].as_str() {
                "--collateral-ratio" if i + 1 < args.len() => {
                    let raw = &args[i + 1];
                    let ratio: f64 = raw.parse().map_err(|_| {
                        format!(
                            "Invalid --collateral-ratio value: {} (expected float in [0, 1])",
                            raw
                        )
                    })?;
                    if !ratio.is_finite() || !(0.0..=1.0).contains(&ratio) {
                        return Err(
                            format!("--collateral-ratio {} must be in [0.0, 1.0]", raw).into()
                        );
                    }
                    collateral_bps = Some((ratio * 10_000.0).round() as u32);
                    i += 1;
                }
                "--amount-sats" if i + 1 < args.len() => {
                    let raw = &args[i + 1];
                    let v: u64 = raw.parse().map_err(|_| {
                        format!(
                            "Invalid --amount-sats value: {} (expected positive integer)",
                            raw
                        )
                    })?;
                    amount_sats = Some(v);
                    i += 1;
                }
                "--protocol-version" if i + 1 < args.len() => {
                    protocol_version = Some(args[i + 1].clone());
                    i += 1;
                }
                "--quorum-expiry-blocks" if i + 1 < args.len() => {
                    let raw = &args[i + 1];
                    let v: u32 = raw.parse().map_err(|_| {
                        format!(
                            "Invalid --quorum-expiry-blocks value: {} (expected positive integer)",
                            raw
                        )
                    })?;
                    expiry_blocks = Some(v);
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
            "  Collateral ratio: {:.4} ({}% of UTXO held as bond) — override",
            bps as f64 / 10_000.0,
            bps as f64 / 100.0
        );
    }

    let mut params = serde_json::Map::new();
    if let Some(bps) = collateral_bps {
        params.insert("collateral_bps".to_string(), serde_json::json!(bps));
    }
    if let Some(amt) = amount_sats {
        params.insert("amount_sats".to_string(), serde_json::json!(amt));
    }
    if let Some(ref pv) = protocol_version {
        println!("  Protocol version: {}", pv);
        params.insert("protocol_version".to_string(), serde_json::json!(pv));
    }
    if let Some(n) = expiry_blocks {
        println!("  Quorum expiry: current_block + {} blocks (override)", n);
        params.insert("expiry_blocks".to_string(), serde_json::json!(n));
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

/// DEP-18 off-chain consensus-version upgrade. Moves the ledger to a target
/// ruleset in the SAME reserves-cascade family (op-rules only — e.g. enabling
/// the DEP-07 fee cap via `fee-cap-v3`). No reserves rotation, no on-chain TX —
/// just a cosigned ledger op. A family-changing target is rejected by
/// conformance and must use `quorum begin` instead.
///
/// Usage: deposits-node quorum upgrade [<reserves_id>] <new_protocol_version>
async fn quorum_upgrade(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut positionals: Vec<String> = Vec::new();
    let mut config_args: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with("--") {
            config_args.push(args[i].clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
                i += 1;
            }
        } else {
            positionals.push(args[i].clone());
        }
        i += 1;
    }

    let (reserves_id, new_version) = match positionals.as_slice() {
        [v] => (None, v.clone()),
        [r, v] => (Some(r.clone()), v.clone()),
        _ => {
            return Err(
                "Usage: deposits-node quorum upgrade [<reserves_id>] <new_protocol_version>".into(),
            )
        }
    };

    let config = parse_config(&config_args)?;
    let node = Node::new(config.clone()).await?;
    let ledger_id = match reserves_id {
        Some(id) => super::resolve_to_ledger_id(&node, &id)?,
        None => match node.get_primary_ledger() {
            Some((lid, _)) => lid,
            None => return Err("No ledger found. Open a ledger first with 'ledger open'.".into()),
        },
    };
    drop(node);

    println!("Upgrading ledger consensus version via daemon...");
    println!("  Ledger: {}...", &ledger_id[..16.min(ledger_id.len())]);
    println!("  Target ruleset: {}", new_version);

    let mut params = serde_json::Map::new();
    params.insert(
        "new_protocol_version".to_string(),
        serde_json::json!(new_version),
    );
    let result = send_daemon_request(
        &config,
        &ledger_id,
        "quorum_upgrade",
        serde_json::Value::Object(params),
    )
    .await?;

    println!("\nUpgrade committed.");
    if let Some(h) = result.get("content_hash").and_then(|v| v.as_str()) {
        println!("  Update hash: {}", h);
    }
    Ok(())
}

/// Re-establish quorum past `quorum_expiry` via the DEP-05 §Lifecycle
/// cascade.
///
/// Sibling to `quorum begin`. Difference: this one expects the ledger
/// to be *past* `quorum_expiry` and is the operator's degraded
/// self-rescue path. The daemon-side cosign coordinator already picks
/// the right threshold for the current tier via the shared
/// `cosign_threshold::cosign_requirement` helper — this command is
/// the explicit-intent entry point, plus a pre-flight that prints the
/// current tier and refuses unless the operator confirms (or passes
/// `--yes`).
///
/// Refuses if the ledger is still in Tier 0 (pre-expiry) — use
/// `quorum begin` for routine rotation.
async fn quorum_repair(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use deposits_core::cosign_threshold::{cosign_requirement, LifecycleTier};
    use deposits_core::messages::LedgerOperation;

    let mut reserves_id: Option<String> = None;
    let mut amount_sats: Option<u64> = None;
    let mut protocol_version: Option<String> = None;
    let mut yes = false;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with("--") {
            match args[i].as_str() {
                "--amount-sats" if i + 1 < args.len() => {
                    amount_sats = Some(args[i + 1].parse()?);
                    i += 2;
                    continue;
                }
                "--protocol-version" if i + 1 < args.len() => {
                    protocol_version = Some(args[i + 1].clone());
                    i += 2;
                    continue;
                }
                "--yes" | "-y" => {
                    yes = true;
                    i += 1;
                    continue;
                }
                _ => {
                    config_args.push(args[i].clone());
                    if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                        config_args.push(args[i + 1].clone());
                        i += 2;
                        continue;
                    }
                    i += 1;
                    continue;
                }
            }
        }
        if reserves_id.is_none() {
            reserves_id = Some(args[i].clone());
        } else {
            config_args.push(args[i].clone());
        }
        i += 1;
    }

    let config = parse_config(&config_args)?;
    let node = Node::new(config.clone()).await?;
    let ledger_id = match reserves_id {
        Some(id) => super::resolve_to_ledger_id(&node, &id)?,
        None => match node.get_primary_ledger() {
            Some((lid, _)) => lid,
            None => return Err("No ledger found. Open a ledger first with 'ledger open'.".into()),
        },
    };

    // Pre-flight: look up the ledger, compute current tier via the
    // shared helper. Refuse if we're not past expiry (Tier 0).
    let (tier, required, qsize, expiry_block) = {
        let ledgers = node.handler.ledgers.lock().unwrap();
        let arc = ledgers
            .get(&ledger_id)
            .ok_or_else(|| format!("Ledger not found locally: {}", ledger_id))?;
        let l = arc.read().unwrap();
        let chain_tip = node.wallet.get_block_height().unwrap_or(0);
        // Probe with a representative establishment op — every
        // Establishment-class op yields the same required_sigs at the
        // same tier.
        let probe = LedgerOperation::QuorumRemoveMember {
            quorum_member: node.node_id,
            operator_signature: [0u8; 64],
        };
        let req = cosign_requirement(&l.state, &probe, chain_tip);
        (
            req.tier,
            req.required_sigs,
            l.state.quorum_members.len(),
            l.state.quorum_expiry,
        )
    };
    drop(node);

    println!("Ledger {}", ledger_id);
    match (expiry_block, tier) {
        (None, _) => {
            return Err(
                "No quorum_expiry set — this ledger has no active quorum to repair. \
                                  Use `quorum begin` instead."
                    .into(),
            )
        }
        (Some(_), LifecycleTier::Tier0) => {
            return Err(format!(
                "Ledger is at Tier 0 (active period, before quorum_expiry={}). \
                 Use `quorum begin` for routine rotation. `quorum repair` is only \
                 meaningful past quorum_expiry.",
                expiry_block.unwrap()
            )
            .into());
        }
        (Some(e), t) => {
            println!("  quorum_expiry: {}", e);
            println!("  current tier:  {:?}", t);
            println!(
                "  required:      {} of {} cosignatures{}",
                required,
                qsize,
                if matches!(t, LifecycleTier::Tier3) {
                    " (operator alone — no cosig solicited)"
                } else {
                    ""
                }
            );
        }
    }

    if !yes {
        eprintln!(
            "\nThis is a degraded re-establishment per DEP-05 §Lifecycle. \
             Pass --yes to proceed."
        );
        return Ok(());
    }

    let mut params = serde_json::Map::new();
    if let Some(amt) = amount_sats {
        params.insert("amount_sats".to_string(), serde_json::json!(amt));
    }
    if let Some(pv) = protocol_version {
        params.insert("protocol_version".to_string(), serde_json::json!(pv));
    }
    let result = send_daemon_request(
        &config,
        &ledger_id,
        "quorum_begin",
        serde_json::Value::Object(params),
    )
    .await?;

    println!("\nRe-established!");
    if let Some(txid) = result.get("txid").and_then(|v| v.as_str()) {
        println!("  TXID: {}", txid);
    }
    if let Some(addr) = result.get("new_address").and_then(|v| v.as_str()) {
        println!("  New Address: {}", addr);
    }
    if let Some(expiry) = result.get("quorum_expiry").and_then(|v| v.as_u64()) {
        println!("  Next expiry: {}", expiry);
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

/// Idempotent quorum-refresh state machine.
///
/// Each invocation:
///   1. reads the ledger's *active* quorum members (`state.quorum_members`),
///   2. for each member m:
///      - if m is already in `state.next_quorum_members` with
///        `membership_until ≥ current_block + --threshold-blocks` →
///        nothing to do, m is already refreshed,
///      - otherwise, kicks off a `quorum_add` daemon RPC for m with a
///        new `--membership-until`. The RPC dispatches the request to
///        m's daemon and writes a `QuorumAddMember` op when m's
///        `QuorumJoin` reply arrives. On timeout (m offline) the call
///        fails; we log and move on.
///   3. After the loop, if every active member is now refreshed in
///      `next_quorum_members`, fires `quorum begin` to rotate the
///      reserves UTXO with the freshly-extended membership.
///
/// Designed to be invoked from cron / a systemd timer / a watchdog. The
/// command itself doesn't block waiting for offline members — each run
/// makes whatever forward progress it can and exits. Re-running picks up
/// where the previous run stopped.
async fn quorum_refresh(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut ledger_id_arg: Option<String> = None;
    let mut explicit_membership_until: Option<u32> = None;
    let mut threshold_blocks: u32 = 144; // ~1 day; below this counts as "stale"
    let mut extension_blocks: u32 = 1000; // default new membership_until = current + 1000
    let mut config_args: Vec<String> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--membership-until" if i + 1 < args.len() => {
                explicit_membership_until = Some(
                    args[i + 1]
                        .parse()
                        .map_err(|e| format!("--membership-until: {}", e))?,
                );
                i += 2;
            }
            "--threshold-blocks" if i + 1 < args.len() => {
                threshold_blocks = args[i + 1]
                    .parse()
                    .map_err(|e| format!("--threshold-blocks: {}", e))?;
                i += 2;
            }
            "--extension-blocks" if i + 1 < args.len() => {
                extension_blocks = args[i + 1]
                    .parse()
                    .map_err(|e| format!("--extension-blocks: {}", e))?;
                i += 2;
            }
            s if s.starts_with("--") => {
                config_args.push(args[i].clone());
                if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                    config_args.push(args[i + 1].clone());
                    i += 2;
                } else {
                    i += 1;
                }
            }
            _ => {
                if ledger_id_arg.is_none() {
                    ledger_id_arg = Some(args[i].clone());
                }
                i += 1;
            }
        }
    }

    let config = parse_config(&config_args)?;
    let node = Node::new(config.clone()).await?;

    let ledger_id = match ledger_id_arg {
        Some(id) => super::resolve_to_ledger_id(&node, &id)?,
        None => match node.get_primary_ledger() {
            Some((lid, _)) => lid,
            None => return Err("No ledger found. Pass <ledger_id> or open one first.".into()),
        },
    };

    // Snapshot the state we need before dropping the Node — quorum
    // members, pending entries, and the chain tip for staleness math.
    let (active_members, pending_members, current_block) = {
        let ledgers = node.handler.ledgers.lock().unwrap();
        let arc = ledgers
            .get(&ledger_id)
            .ok_or_else(|| format!("Ledger {} not found", &ledger_id[..16.min(ledger_id.len())]))?;
        let ledger = arc.read().unwrap();
        let active = ledger.state.quorum_members.clone();
        let pending = ledger.state.next_quorum_members.clone();
        let height = node.wallet.get_block_height().unwrap_or(0);
        (active, pending, height)
    };
    drop(node);

    let new_membership_until =
        explicit_membership_until.unwrap_or(current_block.saturating_add(extension_blocks));

    if active_members.is_empty() {
        println!(
            "Ledger {} has no active quorum members yet. \
             Use `quorum add` first; refresh only re-extends an existing quorum.",
            &ledger_id[..16.min(ledger_id.len())]
        );
        return Ok(());
    }

    println!("Quorum refresh");
    println!("  Ledger:                {}...", &ledger_id[..16]);
    println!("  Active members:        {}", active_members.len());
    println!("  Current block:         {}", current_block);
    println!("  New membership_until:  {}", new_membership_until);
    println!(
        "  Stale threshold:       current + {} blocks",
        threshold_blocks
    );
    println!();

    // Per-member state: is the active member already represented in
    // `next_quorum_members` with a `membership_until` that's still far
    // enough from expiring?
    let staleness_floor = current_block.saturating_add(threshold_blocks);
    let mut stale_members = Vec::new();
    let mut fresh_count = 0;
    for m in &active_members {
        let pending_match = pending_members.iter().find(|p| p.pubkey == m.pubkey);
        let fresh = pending_match
            .and_then(|p| p.membership_until)
            .map(|until| until >= staleness_floor)
            .unwrap_or(false);
        let prefix = &m.pubkey.to_string()[..16];
        if fresh {
            let until = pending_match.and_then(|p| p.membership_until).unwrap_or(0);
            println!("  ✓ {}... fresh (pending until {})", prefix, until);
            fresh_count += 1;
        } else {
            let why = match pending_match {
                None => "not in pending".to_string(),
                Some(p) => format!("stale (pending until {})", p.membership_until.unwrap_or(0)),
            };
            println!("  ⟳ {}... needs refresh — {}", prefix, why);
            stale_members.push(m.clone());
        }
    }
    println!();

    // Phase 1: kick off `quorum_add` for each stale member. We sequence
    // these (rather than firing in parallel) because the daemon side
    // serializes ledger writes and parallel quorum_adds against the same
    // ledger would just queue anyway. Each call may block for the
    // daemon-side cosign timeout if the member is offline; we catch
    // failures and continue so one offline member doesn't block the rest.
    let mut newly_added = 0;
    for m in &stale_members {
        let prefix = &m.pubkey.to_string()[..16];
        println!("→ requesting refresh from {}...", prefix);

        let mut params = serde_json::json!({
            "member_pubkey": m.pubkey.to_string(),
            "member_ledger_id": m.ledger_id.clone(),
            "membership_until": new_membership_until,
        });
        if let Some(v) = m.min_fee_bps {
            params["min_fee_bps"] = (v as u64).into();
        }
        if let Some(v) = m.min_fee_fixed {
            params["min_fee_fixed"] = v.into();
        }
        if let Some(v) = m.max_fee_period {
            params["max_fee_period"] = v.into();
        }

        match send_daemon_request(&config, &ledger_id, "quorum_add", params).await {
            Ok(_) => {
                println!("  ✓ {}... refreshed", prefix);
                newly_added += 1;
            }
            Err(e) => {
                println!("  ⏳ {}... not yet refreshed ({})", prefix, e);
            }
        }
    }

    // Phase 2: if EVERY active member is now in pending with a fresh
    // membership_until, rotate. Re-read the state because Phase 1
    // mutated it via the daemon RPC.
    let total_fresh = fresh_count + newly_added;
    println!();
    println!(
        "Refresh status: {}/{} active members refreshed in this run",
        total_fresh,
        active_members.len()
    );

    if total_fresh < active_members.len() {
        println!();
        println!(
            "Not all members refreshed yet ({} pending). Re-run after they come online.",
            active_members.len() - total_fresh
        );
        return Ok(());
    }

    println!();
    println!("All members refreshed — running quorum begin to rotate the UTXO...");

    let begin_params = serde_json::json!({});
    let result = send_daemon_request(&config, &ledger_id, "quorum_begin", begin_params).await?;

    println!();
    println!("Quorum rotated!");
    if let Some(txid) = result.get("txid").and_then(|v| v.as_str()) {
        println!("  TXID: {}", txid);
    }
    if let Some(addr) = result.get("new_address").and_then(|v| v.as_str()) {
        println!("  New address: {}", addr);
    }
    if let Some(expiry) = result.get("quorum_expiry").and_then(|v| v.as_u64()) {
        println!("  New quorum_expiry: {}", expiry);
    }

    Ok(())
}

/// Form a quorum with N named peers in one shot.
///
/// Private flow: operators who know each
/// other's pubkeys + ledger IDs out-of-band (via the show-identity
/// command + a side channel) form a quorum with a single command instead
/// of running `quorum add` N times manually.
///
/// Usage:
///   deposits-node quorum form-with --ledger-id <our_ledger_id> \
///       --member <pubkey>:<ledger_id> \
///       --member <pubkey>:<ledger_id> \
///       [--member ...] \
///       [--begin --amount-sats N]
///
/// The optional `--begin --amount-sats N` runs `quorum begin` after all
/// members are added — without it, the operator can review the state
/// (e.g. `quorum list`) before activating.
async fn quorum_form_with(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut our_ledger_id: Option<String> = None;
    let mut members: Vec<(String, String)> = Vec::new(); // (pubkey_str, ledger_id)
    let mut do_begin = false;
    let mut amount_sats: Option<u64> = None;
    let mut config_args: Vec<String> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--ledger-id" if i + 1 < args.len() => {
                our_ledger_id = Some(args[i + 1].clone());
                i += 2;
            }
            "--member" if i + 1 < args.len() => {
                let raw = &args[i + 1];
                let (pk, lid) = raw.split_once(':').ok_or_else(|| {
                    format!("--member must be <pubkey>:<ledger_id>, got: {}", raw)
                })?;
                members.push((pk.to_string(), lid.to_string()));
                i += 2;
            }
            "--begin" => {
                do_begin = true;
                i += 1;
            }
            "--amount-sats" if i + 1 < args.len() => {
                amount_sats = Some(
                    args[i + 1]
                        .parse()
                        .map_err(|_| format!("Invalid --amount-sats value: {}", args[i + 1]))?,
                );
                i += 2;
            }
            // Pass-through for daemon-config flags like --relay, --data-dir
            other if other.starts_with("--") => {
                config_args.push(args[i].clone());
                if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                    config_args.push(args[i + 1].clone());
                    i += 2;
                } else {
                    i += 1;
                }
            }
            _ => i += 1,
        }
    }

    let our_ledger_id = our_ledger_id
        .ok_or("--ledger-id required (use `quorum show-identity` to list your ledger IDs)")?;
    if members.is_empty() {
        return Err("at least one --member required".into());
    }
    if !super::is_ledger_id(&our_ledger_id) {
        return Err(format!("--ledger-id must be 64 hex chars; got: {}", our_ledger_id).into());
    }
    if do_begin && amount_sats.is_none() {
        return Err("--begin requires --amount-sats <N>".into());
    }

    // Validate each member tuple up-front so partial failures aren't possible.
    for (pk_str, lid) in &members {
        PublicKey::from_str(pk_str)
            .map_err(|e| format!("invalid member pubkey {}: {}", pk_str, e))?;
        if !super::is_ledger_id(lid) {
            return Err(format!("member's ledger_id must be 64 hex chars; got: {}", lid).into());
        }
    }

    let config = parse_config(&config_args)?;

    println!(
        "Forming quorum on ledger {}... with {} member(s):",
        &our_ledger_id[..16],
        members.len()
    );
    for (pk, lid) in &members {
        println!(
            "  - {}... (collateral ledger {}...)",
            &pk[..16.min(pk.len())],
            &lid[..16.min(lid.len())]
        );
    }
    println!();

    // Add each member via the same daemon RPC `quorum add` uses. Sequential
    // — gives clear progress signal and avoids racing the daemon's
    // membership-request flow against itself.
    let mut succeeded = 0usize;
    let mut failures: Vec<(String, String)> = Vec::new();
    for (pk_str, member_ledger_id) in &members {
        let params = serde_json::json!({
            "member_pubkey": pk_str,
            "member_ledger_id": member_ledger_id,
        });
        print!("  adding {}... ", &pk_str[..16.min(pk_str.len())]);
        match send_daemon_request(&config, &our_ledger_id, "quorum_add", params).await {
            Ok(_) => {
                println!("✓");
                succeeded += 1;
            }
            Err(e) => {
                println!("✗ ({})", e);
                failures.push((pk_str.clone(), e.to_string()));
            }
        }
    }

    println!();
    if !failures.is_empty() {
        println!(
            "Failed to add {} of {} members; check daemon logs and re-run after fixing:",
            failures.len(),
            members.len()
        );
        for (pk, err) in &failures {
            println!("  - {}: {}", pk, err);
        }
        return Err("not all members added; refusing to begin".into());
    }
    println!("All {} member(s) added.", succeeded);

    if do_begin {
        println!();
        println!(
            "Activating quorum: begin --amount-sats {}",
            amount_sats.unwrap()
        );
        let params = serde_json::json!({
            "amount_sats": amount_sats.unwrap(),
        });
        match send_daemon_request(&config, &our_ledger_id, "quorum_begin", params).await {
            Ok(result) => {
                println!("Quorum activated.");
                if let Some(addr) = result.get("new_address").and_then(|v| v.as_str()) {
                    println!("  New reserves address: {}", addr);
                }
                if let Some(txid) = result.get("txid").and_then(|v| v.as_str()) {
                    println!("  Rotation txid:        {}", txid);
                }
            }
            Err(e) => {
                return Err(format!("members added but begin failed: {}", e).into());
            }
        }
    } else {
        println!();
        println!("Members added. Run `quorum begin <ledger_id> --amount-sats N` when ready");
        println!("to rotate reserves into the quorum multisig, OR re-run form-with with");
        println!("--begin --amount-sats N to do both in one shot.");
    }

    Ok(())
}

/// Print this operator's pubkey + owned ledger IDs in a copy-paste-friendly
/// format. Peers paste the output into a chat / email when coordinating
/// quorum formation; the receiving operator passes the pubkey + ledger_id
/// to their own `quorum form-with --member <pk>:<lid>`.
async fn quorum_show_identity(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let config = parse_config(args)?;
    let node = Node::new(config).await?;

    println!("Operator pubkey: {}", node.node_id);
    let (our_ledgers, _joined) = node.list_quorum_info();
    if our_ledgers.is_empty() {
        println!();
        println!("(no owned ledgers — open one with `ledger open` first)");
        return Ok(());
    }
    println!();
    println!("Owned ledgers (any can be used as your collateral on a peer's quorum):");
    for (ledger_id, active, _pending) in &our_ledgers {
        let role_hint = if active.is_empty() {
            ""
        } else {
            "  [quorum already active]"
        };
        println!("  {}{}", ledger_id, role_hint);
    }
    println!();
    println!("Share with a peer who wants you in their quorum:");
    println!("  pubkey:   {}", node.node_id);
    println!("  ledger:   <pick one ledger ID from the list above>");
    println!();
    println!("Or paste this line for one of your ledgers:");
    if let Some((ledger_id, _, _)) = our_ledgers.first() {
        println!("  {}:{}", node.node_id, ledger_id);
    }

    Ok(())
}

/// Manage the pre-curated queue of replacement-member candidates.
///
/// Each entry is a `pubkey:member_ledger_id` pair the operator
/// trusts as a potential cosigner. `auto_quorum_refresh` consumes
/// from this queue (FIFO) when it needs to replace an unresponsive
/// active member during a post-expiry self-rescue.
///
/// Queue is persisted at `<data-dir>/candidate_queue.json`. No
/// network calls — these subcommands just mutate the local file.
async fn quorum_candidate(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.is_empty() {
        eprintln!("Usage: deposits-node quorum candidate <add|list|remove> [args...]");
        eprintln!("  add <pubkey>:<member_ledger_id>");
        eprintln!("  list");
        eprintln!("  remove <pubkey>");
        return Ok(());
    }
    match args[0].as_str() {
        "add" => quorum_candidate_add(&args[1..]).await,
        "list" => quorum_candidate_list(&args[1..]).await,
        "remove" => quorum_candidate_remove(&args[1..]).await,
        cmd => {
            eprintln!("Unknown candidate subcommand: {}", cmd);
            eprintln!("Usage: deposits-node quorum candidate <add|list|remove> [args...]");
            Ok(())
        }
    }
}

fn parse_pk_lid(s: &str) -> Result<(String, String), String> {
    let (pk, lid) = s
        .split_once(':')
        .ok_or_else(|| format!("expected <pubkey>:<member_ledger_id>, got {:?}", s))?;
    let pk = pk.trim();
    let lid = lid.trim();
    if pk.len() != 66 || !pk.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!(
            "pubkey must be 66 hex chars (compressed secp256k1), got {} chars",
            pk.len()
        ));
    }
    if lid.len() != 64 || !lid.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!(
            "member_ledger_id must be 64 hex chars, got {} chars",
            lid.len()
        ));
    }
    Ok((pk.to_string(), lid.to_string()))
}

async fn quorum_candidate_add(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut entry: Option<String> = None;
    let mut config_args = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with("--") {
            config_args.push(args[i].clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
                i += 2;
                continue;
            }
        } else if entry.is_none() {
            entry = Some(args[i].clone());
        }
        i += 1;
    }
    let entry = entry.ok_or("Usage: quorum candidate add <pubkey>:<member_ledger_id>")?;
    let (pubkey, member_ledger_id) = parse_pk_lid(&entry)?;

    let config = parse_config(&config_args)?;
    let mut queue = crate::candidate_queue::CandidateQueue::load(&config.data_dir);
    let added = queue.enqueue(
        &config.data_dir,
        crate::candidate_queue::Candidate {
            pubkey: pubkey.clone(),
            member_ledger_id: member_ledger_id.clone(),
            added_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        },
    )?;
    if added {
        println!(
            "Enqueued candidate: {}:{}",
            &pubkey[..16],
            &member_ledger_id[..16]
        );
        println!("  Queue now has {} candidate(s)", queue.entries.len());
    } else {
        println!("Candidate already in queue: {}", &pubkey[..16]);
    }
    Ok(())
}

async fn quorum_candidate_list(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let config = parse_config(args)?;
    let queue = crate::candidate_queue::CandidateQueue::load(&config.data_dir);
    if queue.is_empty() {
        println!("Queue is empty.");
        return Ok(());
    }
    println!(
        "{} candidate(s) in queue (FIFO order):",
        queue.entries.len()
    );
    for (i, c) in queue.entries.iter().enumerate() {
        println!(
            "  {}: pubkey={} ledger={} added_at={}",
            i,
            c.pubkey,
            &c.member_ledger_id[..16],
            c.added_at
        );
    }
    Ok(())
}

async fn quorum_candidate_remove(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut pubkey: Option<String> = None;
    let mut config_args = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with("--") {
            config_args.push(args[i].clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
                i += 2;
                continue;
            }
        } else if pubkey.is_none() {
            pubkey = Some(args[i].clone());
        }
        i += 1;
    }
    let pubkey = pubkey.ok_or("Usage: quorum candidate remove <pubkey>")?;
    let config = parse_config(&config_args)?;
    let mut queue = crate::candidate_queue::CandidateQueue::load(&config.data_dir);
    if queue.drain(&config.data_dir, &pubkey)? {
        println!(
            "Removed candidate {} from queue.",
            &pubkey[..16.min(pubkey.len())]
        );
    } else {
        println!(
            "Candidate {} not in queue.",
            &pubkey[..16.min(pubkey.len())]
        );
    }
    Ok(())
}
