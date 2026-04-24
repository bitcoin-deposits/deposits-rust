//! `deposits-node admin` — operator-side buffer deposit management.
//!
//! Buffer deposits are deposits the operator opens on their own ledger,
//! using the same seed that was DM'd to the admin at bootstrap. They're
//! used to:
//!
//!   - bootstrap "over-reserves" appearance before real customer
//!     deposits arrive;
//!   - fund a courier that sits on the operator's own ledger with
//!     pre-allocated capacity;
//!   - provide a protocol-level anti-confiscation stake (if the
//!     ledger is confiscated, the new operator inherits obligations
//!     to the old operator via the buffer deposit).
//!
//! Subcommands:
//!   - `open   [--amount-sats N] [--ledger <id>]`  open a new buffer deposit
//!   - `fill   <index> <sats>`                     InvoiceCredit to grow balance
//!   - `drain  <index> <sats>`                     InvoiceLock+Fulfill to shrink
//!   - `list`                                      show all opened buffers
//!
//! All commands run as gift-wrapped admin DMs against the local
//! daemon, same auth path as `reserves create`/`ledger open`.

use super::{parse_config, send_admin_daemon_request};

pub async fn admin_command(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.is_empty() {
        print_usage();
        return Ok(());
    }
    match args[0].as_str() {
        "buffer" => buffer_subcommand(&args[1..]).await,
        cmd => {
            eprintln!("unknown admin subcommand: {}", cmd);
            print_usage();
            Ok(())
        }
    }
}

fn print_usage() {
    eprintln!("Usage: deposits-node admin <buffer> [args...]");
    eprintln!();
    eprintln!("  buffer open  [--amount-sats N] [--ledger <id>] [--index N]");
    eprintln!("      open a new buffer deposit, optionally fill to the given amount");
    eprintln!("  buffer fill  <index> <amount_sats>");
    eprintln!("      credit the buffer via InvoiceCredit (no Lightning)");
    eprintln!("  buffer drain <index> <amount_sats>");
    eprintln!("      drain the buffer via InvoiceLock + InvoiceFulfill (no Lightning)");
    eprintln!("  buffer list");
    eprintln!("      list all opened buffer deposits and their balances");
}

async fn buffer_subcommand(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.is_empty() {
        print_usage();
        return Ok(());
    }
    match args[0].as_str() {
        "open" => buffer_open(&args[1..]).await,
        "fill" => buffer_fill(&args[1..]).await,
        "drain" => buffer_drain(&args[1..]).await,
        "list" => buffer_list(&args[1..]).await,
        cmd => {
            eprintln!("unknown buffer subcommand: {}", cmd);
            print_usage();
            Ok(())
        }
    }
}

async fn buffer_open(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut amount_sats: Option<u64> = None;
    let mut ledger: Option<String> = None;
    let mut index: Option<u32> = None;
    let mut config_args: Vec<String> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--amount-sats" if i + 1 < args.len() => {
                amount_sats = Some(args[i + 1].parse()?);
                i += 1;
            }
            "--ledger" if i + 1 < args.len() => {
                ledger = Some(args[i + 1].clone());
                i += 1;
            }
            "--index" if i + 1 < args.len() => {
                index = Some(args[i + 1].parse()?);
                i += 1;
            }
            _ => {
                config_args.push(args[i].clone());
                if args[i].starts_with("--")
                    && i + 1 < args.len()
                    && !args[i + 1].starts_with("--")
                {
                    config_args.push(args[i + 1].clone());
                    i += 1;
                }
            }
        }
        i += 1;
    }
    let config = parse_config(&config_args)?;

    let mut params = serde_json::json!({});
    if let Some(lid) = ledger {
        params["ledger_id"] = serde_json::json!(lid);
    }
    if let Some(i) = index {
        params["index"] = serde_json::json!(i);
    }

    let result = send_admin_daemon_request(&config, "admin_buffer_open", params).await?;
    let new_index = result
        .get("index")
        .and_then(|v| v.as_u64())
        .ok_or("daemon did not return index")?;
    println!("Buffer deposit opened.");
    if let Some(pk) = result.get("deposit_pubkey").and_then(|v| v.as_str()) {
        println!("  index:    {}", new_index);
        println!("  pubkey:   {}", pk);
    }
    if let Some(did) = result.get("deposit_id").and_then(|v| v.as_str()) {
        println!("  deposit_id: {}", did);
    }
    if let Some(lid) = result.get("ledger_id").and_then(|v| v.as_str()) {
        println!("  ledger:   {}", lid);
    }

    // If --amount-sats was provided, immediately fill to that amount.
    if let Some(sats) = amount_sats {
        let fill_params = serde_json::json!({
            "index": new_index,
            "amount_msats": sats.saturating_mul(1000),
        });
        let fill_result =
            send_admin_daemon_request(&config, "admin_buffer_fill", fill_params).await?;
        if let Some(b) = fill_result.get("new_balance_msats").and_then(|v| v.as_u64()) {
            println!();
            println!("Filled to {} sats ({} msats).", b / 1000, b);
        }
    }

    Ok(())
}

async fn buffer_fill(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    buffer_fill_or_drain("admin_buffer_fill", args, "Filled").await
}

async fn buffer_drain(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    buffer_fill_or_drain("admin_buffer_drain", args, "Drained").await
}

async fn buffer_fill_or_drain(
    action: &str,
    args: &[String],
    verb: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut index: Option<u32> = None;
    let mut amount_sats: Option<u64> = None;
    let mut config_args: Vec<String> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with("--") {
            config_args.push(args[i].clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
                i += 1;
            }
        } else if index.is_none() {
            index = Some(args[i].parse()?);
        } else if amount_sats.is_none() {
            amount_sats = Some(args[i].parse()?);
        }
        i += 1;
    }

    let index = index.ok_or("missing <index>")?;
    let amount_sats = amount_sats.ok_or("missing <amount_sats>")?;
    let config = parse_config(&config_args)?;

    let params = serde_json::json!({
        "index": index,
        "amount_msats": amount_sats.saturating_mul(1000),
    });
    let result = send_admin_daemon_request(&config, action, params).await?;
    let new_balance = result
        .get("new_balance_msats")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    println!(
        "{} buffer {}. New balance: {} sats ({} msats).",
        verb, index, new_balance / 1000, new_balance
    );
    Ok(())
}

async fn buffer_list(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let config = parse_config(args)?;
    let result = send_admin_daemon_request(&config, "admin_buffer_list", serde_json::json!({}))
        .await?;
    let buffers = result
        .get("buffers")
        .and_then(|v| v.as_array())
        .ok_or("malformed response from daemon")?;

    if buffers.is_empty() {
        println!("No buffer deposits opened.");
        return Ok(());
    }

    println!("Buffer deposits ({}):", buffers.len());
    for b in buffers {
        let idx = b.get("index").and_then(|v| v.as_u64()).unwrap_or(0);
        let bal = b.get("balance_msats").and_then(|v| v.as_u64()).unwrap_or(0);
        let locked = b.get("locked_msats").and_then(|v| v.as_u64()).unwrap_or(0);
        let pk = b
            .get("deposit_pubkey")
            .and_then(|v| v.as_str())
            .unwrap_or("?");
        let did = b.get("deposit_id").and_then(|v| v.as_str()).unwrap_or("?");
        let lid = b.get("ledger_id").and_then(|v| v.as_str()).unwrap_or("?");
        println!();
        println!("  [{}] {} sats ({} locked)", idx, bal / 1000, locked / 1000);
        println!("       deposit_id: {}", did);
        println!("       pubkey:     {}", pk);
        println!("       ledger:     {}...", &lid[..16.min(lid.len())]);
    }

    Ok(())
}
