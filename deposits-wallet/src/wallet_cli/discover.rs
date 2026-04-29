use super::{derive_secret_key, parse_config, NostrTransportBuilder};

/// Discover available ledgers on the network
pub async fn discover(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let config = parse_config(args)?;

    // Check for --json flag
    let json_output = args.iter().any(|a| a == "--json");

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

    if !json_output {
        println!("Discovering ledgers on {} network...", network_str);
        println!();
    }

    let secret_key = config.nostr_key()?;
    let transport = NostrTransportBuilder::new(secret_key)
        .relay(&config.relays[0])
        .build()
        .await?;

    let ads = transport.fetch_ledger_advertisements(network_str).await?;

    if json_output {
        // Machine-readable: one JSON object per line
        for ad in &ads {
            println!(
                "{}",
                serde_json::json!({
                    "type": "ledger",
                    "ledger_id": ad.ledger_id,
                    "operator_pubkey": ad.operator_pubkey,
                    "operator_name": ad.operator_name,
                    "relay_url": ad.relay_url,
                    "reserves_msats": ad.reserves_amount_msats,
                    "current_block": ad.current_block,
                })
            );
        }
        // Also include agent advertisements
        let agent_ads = transport
            .fetch_agent_advertisements(network_str)
            .await
            .unwrap_or_default();
        for ad in &agent_ads {
            println!(
                "{}",
                serde_json::json!({
                    "type": "agent",
                    "agent_pubkey": ad.agent_pubkey,
                    "service": ad.service,
                    "ledgers": ad.ledgers,
                })
            );
        }
        return Ok(());
    }

    if ads.is_empty() {
        println!("No ledgers found.");
        println!();
        println!("Operators can advertise with:");
        println!("  deposits-node ledger advertise <reserves_id> --relay <url>");
        return Ok(());
    }

    println!("Found {} ledger(s):", ads.len());
    println!();

    // Build a map of operator pubkey -> name for quorum member lookups
    let _pubkey_to_name: std::collections::HashMap<&str, &str> = ads
        .iter()
        .filter_map(|a| {
            a.operator_name
                .as_deref()
                .map(|name| (a.operator_pubkey.as_str(), name))
        })
        .collect();

    for (i, ad) in ads.iter().enumerate() {
        let operator_name = ad.operator_name.as_deref().unwrap_or("Anonymous");
        println!(
            "{}. {} ({}...)",
            i + 1,
            operator_name,
            &ad.operator_pubkey[..8.min(ad.operator_pubkey.len())]
        );
        println!("   Ledger: {}", ad.ledger_id);
        println!(
            "   Reserves: {} sats ({} BTC)",
            ad.reserves_amount_msats / 1000,
            ad.reserves_amount_msats as f64 / 100_000_000_000.0
        );
        println!(
            "   Collateral: {} sats ({} BTC)",
            ad.collateral_amount_msats / 1000,
            ad.collateral_amount_msats as f64 / 100_000_000_000.0
        );

        // Fee summary
        let annual_pct = ad.annual_fee_bps as f64 / 100.0;
        let annualized_fixed = ad.annualized_fixed_msats;

        let fee_str = match (ad.annual_fee_bps > 0, annualized_fixed > 0) {
            (true, true) => format!("{}% and {} msats per year", annual_pct, annualized_fixed),
            (true, false) => format!("{}% per year", annual_pct),
            (false, true) => format!("{} msats per year", annualized_fixed),
            (false, false) => "None".to_string(),
        };

        let deposit_fee = if ad.deposit_fee_bps > 0 {
            format!(" ({}% on deposit)", ad.deposit_fee_bps as f64 / 100.0)
        } else {
            String::new()
        };

        println!("   Fees: {}{}", fee_str, deposit_fee);

        // Limits
        if ad.max_deposit_msats < u64::MAX {
            println!("   Max deposit: {} sats", ad.max_deposit_msats);
        }
        if ad.min_deposit_msats > 0 {
            println!("   Min deposit: {} sats", ad.min_deposit_msats);
        }

        if let Some(desc) = &ad.description {
            println!("   {}", desc);
        }
        println!();
    }

    println!("To open a deposit, use:");
    println!("  deposits-wallet open <ledger_id> <amount_sats> --alias <name>");

    // ── Agent advertisements (Kind 39101) ──
    let agent_ads = transport
        .fetch_agent_advertisements(network_str)
        .await
        .unwrap_or_default();
    if !agent_ads.is_empty() {
        // Build ledger_id -> operator name map for display
        let ledger_to_operator: std::collections::HashMap<&str, &str> = ads
            .iter()
            .filter_map(|a| {
                a.operator_name
                    .as_deref()
                    .map(|name| (a.ledger_id.as_str(), name))
            })
            .collect();

        println!();
        println!("─── Routing Agents ───");
        println!();

        // Helper: "Operator/abcd" label to disambiguate multiple ledgers per operator
        let ledger_label = |lid: &str| -> String {
            let op = ledger_to_operator.get(lid).copied().unwrap_or("?");
            let prefix = &lid[..4.min(lid.len())];
            format!("{}/{}", op, prefix)
        };

        for ad in &agent_ads {
            println!(
                "Agent: {}...",
                &ad.agent_pubkey[..16.min(ad.agent_pubkey.len())]
            );
            println!("  Service: {}", ad.service);
            println!("  Ledgers:");
            for entry in &ad.ledgers {
                let label = ledger_label(&entry.ledger_id);
                let balance_sats = entry.balance_msats / 1000;
                println!("    {}: {} sats", label, balance_sats);
                println!(
                    "      in:  {} msats + {} bps",
                    entry.fee_in_fixed_msats, entry.fee_in_rate_bps
                );
                println!(
                    "      out: {} msats + {} bps",
                    entry.fee_out_fixed_msats, entry.fee_out_rate_bps
                );
            }

            // Show example route cost (first cross-operator pair)
            if ad.ledgers.len() >= 2 {
                for i in 0..ad.ledgers.len() {
                    let mut shown = false;
                    for j in 0..ad.ledgers.len() {
                        if i == j {
                            continue;
                        }
                        let a = &ad.ledgers[i];
                        let b = &ad.ledgers[j];
                        let op_a = ledger_to_operator
                            .get(a.ledger_id.as_str())
                            .copied()
                            .unwrap_or("");
                        let op_b = ledger_to_operator
                            .get(b.ledger_id.as_str())
                            .copied()
                            .unwrap_or("");
                        if op_a == op_b {
                            continue;
                        } // skip same-operator
                        println!(
                            "  Route {} → {}: {} + {} bps",
                            ledger_label(&a.ledger_id),
                            ledger_label(&b.ledger_id),
                            a.fee_out_fixed_msats + b.fee_in_fixed_msats,
                            a.fee_out_rate_bps + b.fee_in_rate_bps
                        );
                        shown = true;
                        break; // one example is enough
                    }
                    if shown {
                        break;
                    }
                }
            }
            println!();
        }
    }

    Ok(())
}

/// Get detailed info about a specific ledger
pub async fn ledger_info(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
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

    let secret_key = config.nostr_key()?;
    let transport = NostrTransportBuilder::new(secret_key)
        .relay(&config.relays[0])
        .build()
        .await?;

    let network_str = match config.network {
        bitcoin::Network::Bitcoin => "bitcoin",
        bitcoin::Network::Testnet => "testnet",
        bitcoin::Network::Signet => "signet",
        bitcoin::Network::Regtest => "regtest",
        _ => "unknown",
    };

    // Try to find by prefix match
    let full_ledger_id = if ledger_id.len() < 64 {
        // Search for matching ledger
        let ads = transport.fetch_ledger_advertisements(network_str).await?;
        ads.into_iter()
            .find(|a| a.ledger_id.starts_with(&ledger_id))
            .map(|a| a.ledger_id)
            .ok_or_else(|| format!("No ledger found matching: {}", ledger_id))?
    } else {
        ledger_id
    };

    let ad = transport
        .fetch_ledger_advertisement(&full_ledger_id)
        .await?
        .ok_or_else(|| format!("Ledger not found: {}", full_ledger_id))?;

    println!("Ledger Information");
    println!("==================");
    println!();
    println!(
        "Operator: {}",
        ad.operator_name.as_deref().unwrap_or("Anonymous")
    );
    println!("Operator Pubkey: {}", ad.operator_pubkey);
    println!("Ledger ID: {}", ad.ledger_id);
    println!("Reserves Address: {}", ad.reserves_address);
    println!();
    println!("Reserves & Collateral");
    println!("---------------------");
    println!(
        "Reserves: {} sats ({} BTC)",
        ad.reserves_amount_msats / 1000,
        ad.reserves_amount_msats as f64 / 100_000_000_000.0
    );
    println!(
        "Collateral: {} sats ({} BTC)",
        ad.collateral_amount_msats / 1000,
        ad.collateral_amount_msats as f64 / 100_000_000_000.0
    );
    println!();
    println!("Fee Structure");
    println!("-------------");
    println!(
        "Annual Fee: {}bps ({}%/year)",
        ad.annual_fee_bps,
        ad.annual_fee_bps as f64 / 100.0
    );
    println!(
        "Deposit Fee: {}bps ({}%)",
        ad.deposit_fee_bps,
        ad.deposit_fee_bps as f64 / 100.0
    );
    println!(
        "Withdrawal Fee: {}bps ({}%)",
        ad.withdrawal_fee_bps,
        ad.withdrawal_fee_bps as f64 / 100.0
    );
    println!(
        "Invoice Fee: {}bps ({}%)",
        ad.invoice_fee_bps,
        ad.invoice_fee_bps as f64 / 100.0
    );
    if ad.annualized_fixed_msats > 0 {
        println!("Annual fixed fee: {} msats", ad.annualized_fixed_msats);
    }
    println!();
    println!("Deposit Limits");
    println!("--------------");
    if ad.min_deposit_msats > 0 {
        println!("Minimum: {} sats", ad.min_deposit_msats);
    } else {
        println!("Minimum: None");
    }
    if ad.max_deposit_msats < u64::MAX {
        println!("Maximum: {} sats", ad.max_deposit_msats);
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
