// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

use super::{
    auto_advertise_ledger, format_operation, parse_config, send_daemon_request, FeeScheduleArgs,
};
use crate::Node;

/// Handle ledger subcommands
pub async fn ledger_command(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.is_empty() {
        eprintln!("Usage: deposits-node ledger <open|list|history|validate|health|export|import|advertise|discover|address> [args...]");
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
        "republish" => ledger_republish(&args[1..]).await,
        "discover" => ledger_discover(&args[1..]).await,
        "address" => ledger_address(&args[1..]).await,
        cmd => {
            eprintln!("Unknown ledger subcommand: {}", cmd);
            eprintln!("Usage: deposits-node ledger <open|list|history|validate|health|export|import|advertise|discover|address> [args...]");
            Ok(())
        }
    }
}

/// Print a fresh receive address for the per-ledger BDK wallet.
///
/// Used by external pre-funding flows: `ledger open` provisions the
/// wallet, `ledger address <id>` hands out an address, the operator
/// (or a faucet) sends sats to it, then `quorum begin` builds the
/// activation tx from the ledger's own UTXOs.
async fn ledger_address(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
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
    let ledger_id = ledger_id.ok_or("Usage: deposits-node ledger address <ledger_id>")?;

    let config = parse_config(&config_args)?;
    let node = Node::new(config).await?;
    let wallet = node.ensure_ledger_wallet(&ledger_id)?;
    let addr = wallet.get_new_address()?;
    println!("{}", addr);
    Ok(())
}

/// Open a new ledger backed by our reserves UTXO
async fn ledger_open(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut config_args = Vec::new();
    let mut fee_schedule = FeeScheduleArgs::default();
    let mut collateral_bps: Option<u32> = None;

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
                            "--collateral-ratio {} must be in [0.0, 1.0]",
                            raw
                        )
                        .into());
                    }
                    collateral_bps = Some((ratio * 10_000.0).round() as u32);
                    i += 1;
                }
                _ => {
                    if fee_schedule.try_consume(args, &mut i)? {
                        i += 1;
                        continue;
                    }
                    config_args.push(args[i].clone());
                    if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                        config_args.push(args[i + 1].clone());
                        i += 1;
                    }
                }
            }
        }
        // Positional arguments are ignored (enforcement_block was removed).
        i += 1;
    }

    let config = parse_config(&config_args)?;
    let seed = config.seed;
    let network = config.network;
    let relays = config.relays.clone();
    let operator_name = config.operator_name.clone();

    // Persist any fee/limit flags into operator_policy.json so subsequent
    // `ledger advertise` runs (and `process_deposit_open_request` enforcement)
    // see them. Pre-fix, these flags only got printed by ledger_open and were
    // silently lost — operators thought they'd set fees but the advertised
    // ones came out as zeros.
    {
        use crate::operator_policy::OperatorPolicy;
        let mut policy = OperatorPolicy::load(&config.data_dir)
            .map_err(|e| format!("Failed to load operator_policy.json: {}", e))?
            .unwrap_or_default();
        if policy.overlay_fee_args(&fee_schedule) {
            policy
                .save(&config.data_dir)
                .map_err(|e| format!("Failed to save operator_policy.json: {}", e))?;
            println!(
                "Saved fee/limit policy to {}",
                OperatorPolicy::path(&config.data_dir).display()
            );
        }
    }

    println!("Opening ledger backed by reserves UTXO (via daemon)...");
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
    let result = super::send_admin_daemon_request(
        &config,
        "ledger_open",
        serde_json::Value::Object(params),
    )
    .await?;
    let ledger_id = result
        .get("ledger_id")
        .and_then(|v| v.as_str())
        .ok_or("daemon did not return ledger_id")?
        .to_string();
    let reserves_key = result
        .get("reserves_key")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    println!("\nLedger opened successfully!");
    println!("  Ledger ID: {}", ledger_id);
    if let Some(op) = result.get("operator").and_then(|v| v.as_str()) {
        println!("  Operator: {}", op);
    }
    if !reserves_key.is_empty() {
        println!("  Reserves: {}", reserves_key);
    }

    // Print fee schedule if any flags were set
    if fee_schedule.has_any() {
        println!("  Fee schedule:");
        if let Some(bps) = fee_schedule.annual_fee_bps {
            println!(
                "    Annual custody fee: {} bps ({:.2}%)",
                bps,
                bps as f64 / 100.0
            );
        }
        if let Some(msats) = fee_schedule.annualized_fixed_msats {
            println!("    Annual fixed custody fee: {} msats", msats);
        }
        if let Some(blocks) = fee_schedule.fee_period_blocks {
            println!("    Fee collection period: {} blocks", blocks);
        }
        if let Some(fixed) = fee_schedule.transfer_fee_fixed {
            println!("    Transfer fee (fixed): {} sats", fixed);
        }
        if let Some(bps) = fee_schedule.transfer_fee_rate_bps {
            println!(
                "    Transfer fee (rate): {} bps ({:.2}%)",
                bps,
                bps as f64 / 100.0
            );
        }
        if let Some(bps) = fee_schedule.deposit_fee_bps {
            println!("    Deposit fee: {} bps", bps);
        }
        if let Some(bps) = fee_schedule.withdrawal_fee_bps {
            println!("    Withdrawal fee: {} bps", bps);
        }
        if let Some(bps) = fee_schedule.invoice_fee_bps {
            println!("    Invoice fee: {} bps", bps);
        }
        if let Some(msats) = fee_schedule.max_deposit_msats {
            println!("    Max deposit: {} msats", msats);
        }
        if let Some(msats) = fee_schedule.min_deposit_msats {
            println!("    Min deposit: {} msats", msats);
        }
    }

    // Note: the daemon already loads the new ledger into its state and will
    // include it in the next `republish_ledger_advertisements` pass (fires on
    // daemon startup). Operators can also run `ledger advertise` explicitly
    // after setting their preferred fee schedule.
    let _ = (seed, network, relays, operator_name, fee_schedule);

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
        println!(
            "    Deposits: {} total, {} msats balance",
            ledger.state.deposits.len(),
            ledger.total_deposit_balance()
        );
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
        let curr = &update.content_hash;

        // Determine signature status and signer
        let has_partner_sig = update.cosign_signature != [0u8; 64];
        let has_operator_sig = update.operator_signature != [0u8; 64];
        let sig_status = format!(
            "[{}{}]",
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
        println!(
            "{:>4} ↑{:<6} [{:02x}{:02x}~{:02x}{:02x}] {} {} {} {} {}{}",
            seq,
            update.block_height,
            prev[30],
            prev[31],
            curr[30],
            curr[31],
            sig_status,
            signer,
            cosigner,
            member_hash,
            op_name,
            if op_details.is_empty() {
                String::new()
            } else {
                format!("  {}", op_details)
            }
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
            println!(
                "  Valid length: {}/{}",
                report.hash_chain.valid_length, report.hash_chain.total_length
            );
            println!(
                "  Genesis hash: {:02x?}",
                &report.hash_chain.genesis_hash[..8]
            );
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
                let details = rule
                    .details
                    .as_ref()
                    .map(|d| format!(" ({})", d))
                    .unwrap_or_default();
                println!("  [{}] {}{}", status, rule.rule, details);
            }
            println!();

            // Final state
            println!("Final State:");
            println!("  Sequence: {}", report.final_state.sequence);
            println!("  Hash: {:02x?}", &report.final_state.hash[..8]);
            println!(
                "  Total deposits: {} msat",
                report.final_state.total_deposits
            );
            println!(
                "  Reserves: {} sats",
                report.final_state.reserves_amount / 1000
            );
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
    let ledger_snapshots: Vec<(String, deposits_core::ledger::Ledger)> =
        if let Some(id_str) = ledger_id_str {
            let (lid, ledger) = node
                .get_ledger_with_id(&id_str)
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

        // Reserves status - use derived quorum_state instead of scanning history
        let has_rotation = ledger.state.quorum_state == deposits_core::QuorumState::Active;
        let reserves_sats = ledger.reserves_amount() / 1000;
        println!(
            "  Reserves:      {} sats (rotated: {})",
            reserves_sats,
            if has_rotation { "yes" } else { "no" }
        );

        // Deposits
        let total_balance_msat = ledger.total_deposit_balance();
        let deposit_count = ledger.state.deposits.len();
        println!(
            "  Deposits:      {} msat across {} accounts",
            total_balance_msat, deposit_count
        );

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
            let membership_info = match member.membership_until {
                Some(until) => format!("membership until block {}", until),
                None => "no membership expiry".to_string(),
            };
            println!(
                "    - {} (ledger: {}..., {})",
                short_pubkey, short_lid, membership_info
            );
        }

        // Joined quorums (ledgers we are backing as partner)
        if !ledger.state.joined_quorums.is_empty() {
            println!(
                "  Backing:       {} operator ledgers",
                ledger.state.joined_quorums.len()
            );
            for membership in &ledger.state.joined_quorums {
                let op_hex = hex::encode(membership.operator_id.serialize());
                let short_lid = if membership.ledger_id.len() >= 12 {
                    &membership.ledger_id[..12]
                } else {
                    &membership.ledger_id
                };
                println!(
                    "    - operator {}... (ledger: {}..., expires block {})",
                    &op_hex[..16],
                    short_lid,
                    membership.membership_expires
                );
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
                            println!(
                                "    - Hash chain: {}/{} valid",
                                report.hash_chain.valid_length, report.hash_chain.total_length
                            );
                        }
                        for rule in &report.business_rules {
                            if !rule.passed {
                                let details = rule
                                    .details
                                    .as_ref()
                                    .map(|d| format!(" ({})", d))
                                    .unwrap_or_default();
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
        let hash_hex = hex::encode(&ledger.state.chain_tip_hash[..8]);
        println!(
            "  Sequence:      {} (hash: {}...)",
            ledger.state.sequence, hash_hex
        );
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
            let filename =
                output_path.unwrap_or_else(|| format!("ledger_export_{}.json", short_id));
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

    let file_path =
        file_path.ok_or("Usage: deposits-node ledger import <file_path> [--data-dir <dir>]")?;

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
            println!(
                "  Hash chain: {} of {} updates valid",
                report.hash_chain.valid_length, report.hash_chain.total_length
            );
            println!(
                "  Signatures: {} fully signed, {} operator-only, {} unsigned",
                report.signatures.fully_signed,
                report.signatures.operator_only,
                report.signatures.unsigned
            );
            println!();

            // Business rules
            println!("Business Rules:");
            for rule in &report.business_rules {
                let status = if rule.passed { "PASS" } else { "FAIL" };
                let details = rule
                    .details
                    .as_ref()
                    .map(|d| format!(" ({})", d))
                    .unwrap_or_default();
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
    use crate::nostr::LedgerAdvertisement;

    // Parse arguments: <reserves_id> [options]
    let mut reserves_id: Option<String> = None;
    let mut operator_name: Option<String> = None;
    let mut description: Option<String> = None;
    let mut fee_schedule = FeeScheduleArgs::default();
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        // Hard-rejected legacy flag names: surface a clear rename
        // pointer instead of either silently accepting wrong-units
        // numbers or routing through to config_args (which would
        // produce an opaque "Unknown config arg" later).
        match args[i].as_str() {
            "--min-fee" => {
                return Err("--min-fee was renamed to --annual-fee-fixed-msats \
                            (annualized msats, no longer per-period sats)"
                    .into());
            }
            "--annual-fee" => {
                return Err("--annual-fee was renamed to --annual-fee-bps".into());
            }
            "--deposit-fee" => {
                return Err("--deposit-fee was renamed to --deposit-fee-bps".into());
            }
            "--withdrawal-fee" => {
                return Err("--withdrawal-fee was renamed to --withdrawal-fee-bps".into());
            }
            "--invoice-fee" => {
                return Err("--invoice-fee was renamed to --invoice-fee-bps".into());
            }
            "--fee-period" => {
                return Err("--fee-period was renamed to --fee-period-blocks".into());
            }
            "--max-deposit" => {
                return Err("--max-deposit was renamed to --max-deposit-msats".into());
            }
            "--min-deposit" => {
                return Err("--min-deposit was renamed to --min-deposit-msats".into());
            }
            _ => {}
        }

        if args[i].starts_with("--") {
            // Try the canonical fee/limit flag set first.
            if fee_schedule.try_consume(args, &mut i)? {
                i += 1;
                continue;
            }
            match args[i].as_str() {
                "--name" | "--operator-name" if i + 1 < args.len() => {
                    operator_name = Some(args[i + 1].clone());
                    i += 1;
                }
                "--description" if i + 1 < args.len() => {
                    description = Some(args[i + 1].clone());
                    i += 1;
                }
                _ => {
                    // Unrecognised flag — pass through as a possible
                    // config arg (handles --seed, --network, --relay,
                    // etc.).
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

    // Layered fee/policy resolution:
    //   1. Load existing operator_policy.json (or empty if absent).
    //   2. Apply CLI overrides on top of it.
    //   3. If any CLI flag was set, persist the merged policy back —
    //      so re-running `ledger advertise` without flags keeps the
    //      previous values rather than silently zeroing them.
    use crate::operator_policy::OperatorPolicy;
    let mut policy = OperatorPolicy::load(&config.data_dir)
        .map_err(|e| format!("Failed to load operator_policy.json: {}", e))?
        .unwrap_or_default();
    if policy.overlay_fee_args(&fee_schedule) {
        policy
            .save(&config.data_dir)
            .map_err(|e| format!("Failed to save operator_policy.json: {}", e))?;
        println!(
            "Saved policy update to {}",
            OperatorPolicy::path(&config.data_dir).display()
        );
    }

    // Materialize concrete values from the merged policy. `fee_period_blocks`
    // defaults to 2016 (~2 weeks); other fields default to 0 / u64::MAX.
    let annual_fee_bps = policy.annual_fee_bps.unwrap_or(0);
    let annualized_fixed_msats = policy.annualized_fixed_msats.unwrap_or(0);
    let fee_period_blocks = policy.fee_period_blocks.unwrap_or(2016);
    let deposit_fee_bps = policy.deposit_fee_bps.unwrap_or(0);
    let withdrawal_fee_bps = policy.withdrawal_fee_bps.unwrap_or(0);
    let invoice_fee_bps = policy.invoice_fee_bps.unwrap_or(0);
    let max_deposit_msats = policy.max_deposit_msats.unwrap_or(u64::MAX);
    let min_deposit_msats = policy.min_deposit_msats.unwrap_or(0);
    let advertise_relay_url = policy.advertise_relay.clone();

    let node = Node::new(config.clone()).await?;

    // If no reserves_id given, advertise all operator ledgers
    let ledger_ids: Vec<(String, String)> = if let Some(rid) = reserves_id {
        let (_, ledger) = node
            .get_ledger_with_id(&rid)
            .ok_or_else(|| format!("Ledger not found: {}", rid))?;
        vec![(ledger.ledger_id_hex(), rid)]
    } else {
        let ledgers = node.handler.ledgers.lock().unwrap();
        ledgers
            .iter()
            .filter(|(_, arc)| {
                let l = arc.read().unwrap();
                matches!(l.role, deposits_core::ledger::LedgerRole::Operator)
            })
            .map(|(lid, arc)| {
                let l = arc.read().unwrap();
                (lid.clone(), l.state.reserves_key.clone())
            })
            .collect()
    };

    if ledger_ids.is_empty() {
        println!("No operator ledgers to advertise.");
        return Ok(());
    }

    for (ledger_id_hex, rid) in &ledger_ids {
        let (_, ledger) = node
            .get_ledger_with_id(ledger_id_hex)
            .ok_or_else(|| format!("Ledger not found: {}", ledger_id_hex))?;

        let ledger_id = ledger.ledger_id_hex();
        let operator_pubkey = hex::encode(ledger.operator_key().serialize());

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
            rid.clone(),
            network.to_string(),
        );

        ad.operator_name = operator_name.clone();
        ad.description = description.clone();
        ad.relay_url = advertise_relay_url.clone();
        ad.annual_fee_bps = annual_fee_bps;
        ad.deposit_fee_bps = deposit_fee_bps;
        ad.withdrawal_fee_bps = withdrawal_fee_bps;
        ad.invoice_fee_bps = invoice_fee_bps;
        ad.annualized_fixed_msats = annualized_fixed_msats;
        ad.fee_period_blocks = fee_period_blocks;
        ad.max_deposit_msats = max_deposit_msats;
        ad.min_deposit_msats = min_deposit_msats;
        ad.max_deposit_balance_msats = node.max_deposit_balance_msats();
        ad.reserves_amount_msats = ledger.reserves_amount();
        ad.collateral_amount_msats = ledger.state.collateral_amount;

        // Obligations and headroom deliberately NOT advertised — both are
        // trivially inflatable by the operator via self-paid Lightning
        // invoices, so they aren't reliable trust signals. Wallets discover
        // capacity through couriers (swap ads).

        // Chain tip — lets wallets pick transfer timeouts without a balance_query.
        // Use the last ledger update's block_height (matches operator's validator).
        ad.current_block = ledger
            .history
            .last()
            .map(|u| u.block_height)
            .unwrap_or_else(|| node.wallet.get_block_height().unwrap_or(0));

        // Quorum state lets wallets distinguish provisional ledgers (PreQuorum,
        // no on-chain commitment yet, no enforcement) from active ones.
        // The membership list (operator NOT included) lets wallets see
        // exactly who's backing this operator, since quorum membership
        // is public chain state.
        ad.quorum_state = format!("{:?}", ledger.state.quorum_state);
        ad.quorum_members = ledger
            .state
            .quorum_members
            .iter()
            .map(|m| m.pubkey.to_string())
            .collect();

        println!("Publishing ledger advertisement...");
        println!("  Ledger ID: {}...", &ledger_id[..16]);
        println!("  Reserves: {} msats", ad.reserves_amount_msats);
        println!("  Collateral: {} msats", ad.collateral_amount_msats);
        let annual_pct = ad.annual_fee_bps as f64 / 100.0;
        let annualized_fixed = ad.annualized_fixed_msats;
        let fee_str = match (ad.annual_fee_bps > 0, annualized_fixed > 0) {
            (true, true) => format!("{}% and {} msats per year", annual_pct, annualized_fixed),
            (true, false) => format!("{}% per year", annual_pct),
            (false, true) => format!("{} msats per year", annualized_fixed),
            (false, false) => "None".to_string(),
        };
        println!(
            "  Fees: {} (period: {} blocks, {}bps deposit, {}bps withdrawal)",
            fee_str, ad.fee_period_blocks, ad.deposit_fee_bps, ad.withdrawal_fee_bps
        );
        println!();

        // Use the node's existing transport to avoid ephemeral connection race
        // where a new transport disconnects before the relay processes the write.
        let event_id = node.nostr.publish_ledger_advertisement(&ad).await?;
        println!("Advertisement published!");
        println!("  Event ID: {}", event_id);
        println!();
    } // end for each ledger

    Ok(())
}

/// Re-broadcast all ledger updates to relays (triggers resync from seq 0).
async fn ledger_republish(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut ledger_id_arg: Option<String> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with("--") {
            config_args.push(args[i].clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
                i += 1;
            }
        } else if ledger_id_arg.is_none() {
            ledger_id_arg = Some(args[i].clone());
        }
        i += 1;
    }

    let config = parse_config(&config_args)?;

    // If no ledger specified, find ours
    let node = Node::new(config.clone()).await?;
    let ledger_id = match ledger_id_arg {
        Some(lid) => lid,
        None => {
            let ledgers = node.handler.ledgers.lock().unwrap();
            ledgers.keys().next().ok_or("No ledgers found")?.clone()
        }
    };

    println!(
        "Re-publishing ledger {}... to relays",
        &ledger_id[..16.min(ledger_id.len())]
    );

    let params = serde_json::json!({ "from_seq": 0 });
    let result = send_daemon_request(&config, &ledger_id, "resync", params).await?;

    let count = result
        .get("rebroadcast_count")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let through = result
        .get("through_seq")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    println!("Re-published {} updates (through seq {})", count, through);

    Ok(())
}

/// Discover ledgers advertising on Nostr
pub async fn ledger_discover(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use crate::nostr::NostrTransportBuilder;

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
    let relay_url = config
        .relays
        .first()
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

    let secret_key = super::derive_operator_secret(&config.seed, config.network)?;
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
        println!(
            "{} ({}...):",
            operator_name,
            &ad.operator_pubkey[..12.min(ad.operator_pubkey.len())]
        );
        println!(
            "  Ledger ID: {}...",
            &ad.ledger_id[..16.min(ad.ledger_id.len())]
        );
        println!("  Reserves: {} msats", ad.reserves_amount_msats);
        println!("  Collateral: {} msats", ad.collateral_amount_msats);
        println!("  Fees:");
        println!(
            "    Annual: {}bps ({}%)",
            ad.annual_fee_bps,
            ad.annual_fee_bps as f64 / 100.0
        );
        println!("    Deposit: {}bps", ad.deposit_fee_bps);
        println!("    Withdrawal: {}bps", ad.withdrawal_fee_bps);
        println!("    Invoice: {}bps", ad.invoice_fee_bps);
        if ad.annualized_fixed_msats > 0 {
            println!("    Annual fixed: {} msats", ad.annualized_fixed_msats);
        }
        println!("  Limits:");
        if ad.max_deposit_msats < u64::MAX {
            println!("    Max deposit: {} sats", ad.max_deposit_msats);
        }
        if ad.min_deposit_msats > 0 {
            println!("    Min deposit: {} sats", ad.min_deposit_msats);
        }
        if let Some(desc) = &ad.description {
            println!("  Description: {}", desc);
        }
        println!();
    }

    Ok(())
}
