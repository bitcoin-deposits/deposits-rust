// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

use super::{parse_config, send_daemon_request};
use crate::Node;

pub async fn health_command(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.is_empty() {
        eprintln!("Usage: deposits-node health <ping>");
        eprintln!("  ping    Measure co-sign latency to each quorum member");
        return Ok(());
    }
    match args[0].as_str() {
        "ping" => health_ping(&args[1..]).await,
        "chains" => health_chains(&args[1..]).await,
        "relays" => health_relays(&args[1..]).await,
        _ => {
            eprintln!("Unknown health subcommand: {}", args[0]);
            eprintln!("Usage: deposits-node health <ping|chains|relays>");
            Ok(())
        }
    }
}

/// Probe quorum member co-sign latency by requesting cosignature on a
/// temporary FeeCollect(0) update. The update is never finalized/broadcast.
/// Ping quorum members via the running daemon.
/// Sends a health_ping request that the daemon processes using its live connections.
async fn health_ping(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let config = parse_config(args)?;

    // Find our ledger
    let node = Node::new(config.clone()).await?;
    let ledger_id = {
        let ledgers = node.handler.ledgers.lock().unwrap();
        ledgers.keys().next().cloned().unwrap_or_default()
    };
    drop(node);

    if ledger_id.is_empty() {
        eprintln!("No ledgers found");
        return Ok(());
    }

    println!(
        "Pinging quorum via daemon on ledger {}...\n",
        &ledger_id[..16]
    );

    let rounds = 3;
    for round in 1..=rounds {
        print!("  Round {}/{}: ", round, rounds);
        use std::io::Write;
        std::io::stdout().flush().ok();

        let start = std::time::Instant::now();
        match send_daemon_request(&config, &ledger_id, "health_ping", serde_json::json!({})).await {
            Ok(result) => {
                let rtt = start.elapsed();
                let member = result
                    .get("cosigner")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                let cosign_ms = result
                    .get("cosign_ms")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0);
                println!(
                    "{}... {:.0}ms (cosign: {:.0}ms)",
                    &member[..12.min(member.len())],
                    rtt.as_secs_f64() * 1000.0,
                    cosign_ms
                );
            }
            Err(e) => {
                let rtt = start.elapsed();
                println!("FAIL ({:.0}ms) {}", rtt.as_secs_f64() * 1000.0, e);
            }
        }
    }

    Ok(())
}

/// Query the running daemon's relay health via Nostr.
async fn health_relays(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let config = parse_config(args)?;

    // Find our ledger to address the request
    let node = Node::new(config.clone()).await?;
    let ledger_id = {
        let ledgers = node.handler.ledgers.lock().unwrap();
        ledgers.keys().next().cloned().unwrap_or_default()
    };

    if ledger_id.is_empty() {
        eprintln!("No ledgers found");
        return Ok(());
    }

    let result =
        send_daemon_request(&config, &ledger_id, "health_status", serde_json::json!({})).await?;
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

/// Report chain validity for all own ledgers and joined quorum ledgers.
pub async fn health_chains(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let config = parse_config(args)?;
    let node = Node::new(config.clone()).await?;

    let ledgers = node.handler.ledgers.lock().unwrap();

    if ledgers.is_empty() {
        println!("No ledgers.");
        return Ok(());
    }

    for (lid, ledger_arc) in ledgers.iter() {
        let ledger = ledger_arc.read().unwrap();
        let role = match ledger.role {
            deposits_core::ledger::LedgerRole::Operator => "operator",
            deposits_core::ledger::LedgerRole::Partner => "quorum",
            deposits_core::ledger::LedgerRole::Auditor => "auditor",
        };
        let short_lid = &lid[..16.min(lid.len())];

        println!("=== {} [{}] ===", short_lid, role);
        println!("  Sequence:   {}", ledger.state.sequence);
        println!(
            "  Hash:       {}",
            hex::encode(&ledger.state.chain_tip_hash[..8])
        );
        println!("  Deposits:   {}", ledger.state.deposits.len());
        println!(
            "  Quorum:     {} members",
            ledger.state.quorum_members.len()
        );

        // Validate hash chain
        let history_len = ledger.history.len();
        println!("  History:    {} updates", history_len);

        if history_len == 0 {
            println!("  Chain:      EMPTY (no updates on relay?)");
            println!();
            continue;
        }

        let mut chain_ok = true;
        let mut prev_hash = [0u8; 32];

        for (i, update) in ledger.history.iter().enumerate() {
            // Check sequence
            if update.sequence_number != i as u64 {
                println!(
                    "  Chain:      BREAK at seq {} (expected {})",
                    update.sequence_number, i
                );
                chain_ok = false;
                break;
            }

            // Check previous hash linkage
            if update.previous_hash != prev_hash {
                println!(
                    "  Chain:      BREAK at seq {} (prev_hash mismatch: expected {}... got {}...)",
                    i,
                    hex::encode(&prev_hash[..4]),
                    hex::encode(&update.previous_hash[..4])
                );
                chain_ok = false;
                break;
            }

            // Verify the update's own hash
            let computed = update.compute_hash();
            if computed != update.current_hash {
                println!(
                    "  Chain:      BREAK at seq {} (hash mismatch: computed {}... stored {}...)",
                    i,
                    hex::encode(&computed[..4]),
                    hex::encode(&update.current_hash[..4])
                );
                chain_ok = false;
                break;
            }

            prev_hash = update.current_hash;
        }

        if chain_ok {
            // Check tip matches state
            if prev_hash == ledger.state.chain_tip_hash {
                println!("  Chain:      OK ({} updates verified)", history_len);
            } else {
                println!(
                    "  Chain:      DIVERGED (history tip {}... != state {}...)",
                    hex::encode(&prev_hash[..4]),
                    hex::encode(&ledger.state.chain_tip_hash[..4])
                );
            }
        }

        // Show quorum join status for joined ledgers
        if !ledger.state.joined_quorums.is_empty() {
            println!("  Joined quorums:");
            for jq in &ledger.state.joined_quorums {
                let op_short = hex::encode(jq.operator_id.serialize());
                println!(
                    "    {}... ledger:{}... expires:{}",
                    &op_short[..12],
                    &jq.ledger_id[..16.min(jq.ledger_id.len())],
                    jq.membership_expires
                );
            }
        }

        println!();
    }

    Ok(())
}
