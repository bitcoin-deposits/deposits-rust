//! `liquidity` CLI: manage operator-side liquidity-drip plans.
//!
//! Drip plans live in `<data_dir>/operator_drips.json`. The CLI just
//! reads + writes that file directly; the running daemon re-reads it
//! on each periodic tick (cheap — the file is small) so changes pick
//! up without a restart or admin-RPC round trip.
//!
//! The drip itself is fired by `auto_drip_self_liquidity` inside the
//! daemon's main_loop — this CLI is plan management only.

use super::parse_config;
use crate::operator_drips::{DripPlan, DripRegistry};

pub async fn liquidity_command(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.is_empty() {
        print_usage();
        return Ok(());
    }
    match args[0].as_str() {
        "drip-create" => drip_create(&args[1..]).await,
        "drip-list" | "list" => drip_list(&args[1..]).await,
        "drip-pause" => drip_pause(&args[1..]).await,
        "drip-resume" => drip_resume(&args[1..]).await,
        "drip-remove" => drip_remove(&args[1..]).await,
        other => {
            eprintln!("Unknown liquidity subcommand: {}", other);
            print_usage();
            Ok(())
        }
    }
}

fn print_usage() {
    eprintln!("Usage: deposits-node liquidity <drip-create|drip-list|drip-pause|drip-resume|drip-remove>");
    eprintln!();
    eprintln!("  drip-create <alias> <ledger_id> --initial-sats N --decrement-sats M \\");
    eprintln!("              --interval-sec S [--interval-fuzz-sec F]");
    eprintln!("      Register a drip plan. Opens a self-deposit of size N on the");
    eprintln!("      given ledger, then drains M sats per S seconds back to the");
    eprintln!("      operator's free reserves (synthetic InvoiceLock/Fulfill — no");
    eprintln!("      on-chain or external LDK movement).");
    eprintln!();
    eprintln!("      --interval-fuzz-sec F (optional): add \u{00b1}F seconds of");
    eprintln!("        jitter per tick so an attacker watching balances can't");
    eprintln!("        predict the next release. Each successful tick rolls a");
    eprintln!("        fresh delay from OS entropy. Default 0 (strict periodic).");
    eprintln!();
    eprintln!("      First open happens on the daemon's next auto-task tick.");
    eprintln!();
    eprintln!("  drip-list");
    eprintln!("      Show every registered plan (active + paused).");
    eprintln!();
    eprintln!("  drip-pause <alias>     Stop ticking the named plan (does not close the deposit).");
    eprintln!("  drip-resume <alias>    Re-enable a paused plan.");
    eprintln!("  drip-remove <alias>    Forget the plan entirely (deposit untouched).");
}

/// Best-effort current Unix timestamp. Used for `created_unix`.
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

async fn drip_create(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut alias: Option<String> = None;
    let mut ledger_id: Option<String> = None;
    let mut initial_sats: Option<u64> = None;
    let mut decrement_sats: Option<u64> = None;
    let mut interval_sec: Option<u64> = None;
    let mut interval_fuzz_sec: u64 = 0;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--initial-sats" if i + 1 < args.len() => {
                initial_sats = Some(args[i + 1].parse()?);
                i += 2;
                continue;
            }
            "--decrement-sats" if i + 1 < args.len() => {
                decrement_sats = Some(args[i + 1].parse()?);
                i += 2;
                continue;
            }
            "--interval-sec" if i + 1 < args.len() => {
                interval_sec = Some(args[i + 1].parse()?);
                i += 2;
                continue;
            }
            "--interval-fuzz-sec" if i + 1 < args.len() => {
                interval_fuzz_sec = args[i + 1].parse()?;
                i += 2;
                continue;
            }
            s if s.starts_with("--") => {
                config_args.push(args[i].clone());
                if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                    config_args.push(args[i + 1].clone());
                    i += 2;
                    continue;
                }
                i += 1;
                continue;
            }
            _ => {
                if alias.is_none() {
                    alias = Some(args[i].clone());
                } else if ledger_id.is_none() {
                    ledger_id = Some(args[i].clone());
                }
                i += 1;
            }
        }
    }

    let alias = alias.ok_or(
        "Missing <alias>. Usage: liquidity drip-create <alias> <ledger_id> --initial-sats N \
         --decrement-sats M --interval-sec S",
    )?;
    let ledger_id = ledger_id.ok_or("Missing <ledger_id>")?;
    let initial_sats = initial_sats.ok_or("Missing --initial-sats")?;
    let decrement_sats = decrement_sats.ok_or("Missing --decrement-sats")?;
    let interval_sec = interval_sec.ok_or("Missing --interval-sec")?;

    if decrement_sats == 0 || interval_sec == 0 || initial_sats == 0 {
        return Err("--initial-sats, --decrement-sats, --interval-sec must all be > 0".into());
    }
    if decrement_sats > initial_sats {
        return Err(format!(
            "--decrement-sats ({}) must not exceed --initial-sats ({}) — the first tick would over-draw",
            decrement_sats, initial_sats
        )
        .into());
    }

    let config = parse_config(&config_args)?;
    let data_dir = &config.data_dir;

    let mut registry = DripRegistry::load(data_dir)?;
    let plan = DripPlan {
        alias: alias.clone(),
        ledger_id: ledger_id.clone(),
        target_deposit_sats: initial_sats,
        decrement_sats,
        interval_sec,
        interval_fuzz_sec,
        buffer_index: None,
        paused: false,
        created_unix: now_unix(),
        last_tick_unix: 0,
        next_tick_unix: 0,
        ticks_completed: 0,
    };
    registry.insert(plan).map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    registry.save(data_dir)?;

    let ticks = initial_sats / decrement_sats;
    let total_sec = ticks * interval_sec;
    println!("Registered drip plan '{}'", alias);
    println!("  Ledger:    {}…", &ledger_id[..16.min(ledger_id.len())]);
    println!("  Initial:   {} sats", initial_sats);
    if interval_fuzz_sec > 0 {
        println!(
            "  Decrement: {} sats every {} sec (\u{00b1}{} sec jitter)",
            decrement_sats, interval_sec, interval_fuzz_sec
        );
    } else {
        println!("  Decrement: {} sats every {} sec", decrement_sats, interval_sec);
    }
    println!(
        "  Lifetime:  ~{} ticks (~{} min total at full pace)",
        ticks,
        total_sec / 60
    );
    println!();
    println!("The daemon's next auto-task tick will open the self-deposit.");
    Ok(())
}

async fn drip_list(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let config = parse_config(args)?;
    let registry = DripRegistry::load(&config.data_dir)?;
    if registry.plans.is_empty() {
        println!("No drip plans registered.");
        return Ok(());
    }
    let now = now_unix();
    println!(
        "{:<12} {:<18} {:>12} {:>10} {:>7} {:>10} {:>10} state",
        "alias", "ledger", "initial", "tick", "every", "ticks", "next_in"
    );
    for p in &registry.plans {
        let state = if p.paused {
            "paused".to_string()
        } else if p.buffer_index.is_none() {
            "pending-open".to_string()
        } else {
            "active".to_string()
        };
        let next_in = if p.paused {
            "—".to_string()
        } else if p.next_tick_unix == 0 {
            "due".to_string()
        } else if now >= p.next_tick_unix {
            "due".to_string()
        } else {
            format!("{}s", p.next_tick_unix - now)
        };
        println!(
            "{:<12} {:<18} {:>12} {:>10} {:>6}s {:>10} {:>10} {}",
            truncate(&p.alias, 12),
            format!("{}…", &p.ledger_id[..14.min(p.ledger_id.len())]),
            p.target_deposit_sats,
            p.decrement_sats,
            p.interval_sec,
            p.ticks_completed,
            next_in,
            state,
        );
    }
    Ok(())
}

async fn drip_pause(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    set_paused(args, true).await
}

async fn drip_resume(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    set_paused(args, false).await
}

async fn set_paused(args: &[String], paused: bool) -> Result<(), Box<dyn std::error::Error>> {
    let mut alias: Option<String> = None;
    let mut config_args = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with("--") {
            config_args.push(args[i].clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
                i += 1;
            }
        } else if alias.is_none() {
            alias = Some(args[i].clone());
        }
        i += 1;
    }
    let alias = alias.ok_or("Missing <alias>")?;
    let config = parse_config(&config_args)?;
    let mut registry = DripRegistry::load(&config.data_dir)?;
    let plan = registry
        .find_mut(&alias)
        .ok_or_else(|| format!("No drip plan with alias '{}'", alias))?;
    plan.paused = paused;
    registry.save(&config.data_dir)?;
    println!("{} drip plan '{}'", if paused { "Paused" } else { "Resumed" }, alias);
    Ok(())
}

async fn drip_remove(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut alias: Option<String> = None;
    let mut config_args = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with("--") {
            config_args.push(args[i].clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
                i += 1;
            }
        } else if alias.is_none() {
            alias = Some(args[i].clone());
        }
        i += 1;
    }
    let alias = alias.ok_or("Missing <alias>")?;
    let config = parse_config(&config_args)?;
    let mut registry = DripRegistry::load(&config.data_dir)?;
    if registry.remove(&alias).is_none() {
        return Err(format!("No drip plan with alias '{}'", alias).into());
    }
    registry.save(&config.data_dir)?;
    println!("Removed drip plan '{}'. The self-deposit (if any) is untouched.", alias);
    Ok(())
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max - 1])
    }
}
