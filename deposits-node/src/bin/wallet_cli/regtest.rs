//! Regtest-only helpers. These shell out to `bitcoin-cli` against a
//! local bitcoind RPC (defaults to localhost:18543, which matches
//! deposits-tools/docker-compose.yml). Not available on other
//! networks — intentional, to make the "free money" operations
//! obvious and prevent accidents.

use std::path::PathBuf;
use std::process::Command;

use super::parse_config;

/// Bitcoin RPC connection parameters. All overridable via env.
struct RpcConfig {
    host: String,
    port: String,
    user: String,
    password: String,
    wallet: String,
}

impl RpcConfig {
    fn from_env() -> Self {
        Self {
            host: std::env::var("BITCOIN_RPC_HOST").unwrap_or_else(|_| "localhost".into()),
            port: std::env::var("BITCOIN_RPC_PORT").unwrap_or_else(|_| "18543".into()),
            user: std::env::var("BITCOIN_RPC_USER").unwrap_or_else(|_| "user".into()),
            password: std::env::var("BITCOIN_RPC_PASS").unwrap_or_else(|_| "pass".into()),
            wallet: std::env::var("BITCOIN_RPC_WALLET").unwrap_or_else(|_| "faucet".into()),
        }
    }

    fn base_args(&self) -> Vec<String> {
        vec![
            "-regtest".into(),
            format!("-rpcconnect={}", self.host),
            format!("-rpcport={}", self.port),
            format!("-rpcuser={}", self.user),
            format!("-rpcpassword={}", self.password),
            format!("-rpcwallet={}", self.wallet),
        ]
    }
}

fn run_bitcoin_cli(rpc: &RpcConfig, args: &[&str]) -> Result<String, Box<dyn std::error::Error>> {
    let mut all = rpc.base_args();
    for a in args {
        all.push((*a).to_string());
    }
    let output = Command::new("bitcoin-cli")
        .args(&all)
        .output()
        .map_err(|e| {
            format!(
                "failed to exec `bitcoin-cli`: {e}. Install bitcoin-cli on PATH, \
                 or override the RPC connection via BITCOIN_RPC_HOST/PORT/USER/PASS."
            )
        })?;
    if !output.status.success() {
        return Err(format!(
            "bitcoin-cli {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr).trim()
        )
        .into());
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Send a faucet payment to either an address or an alias-resolved
/// deposit's funding_address, then mine one block to confirm.
pub async fn faucet(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut target: Option<String> = None;
    let mut sats_arg: Option<u64> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with("--") {
            config_args.push(args[i].clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
                i += 1;
            }
        } else if target.is_none() {
            target = Some(args[i].clone());
        } else if sats_arg.is_none() {
            sats_arg = Some(args[i].parse()?);
        }
        i += 1;
    }

    let target = target.ok_or("Usage: deposits-wallet regtest-faucet <alias|address> [sats]")?;
    let config = parse_config(&config_args)?;

    if config.network != bitcoin::Network::Regtest {
        return Err(format!(
            "regtest-faucet refuses to run on {:?} — the faucet is a local-bitcoind \
             operation intended only for a disposable regtest environment.",
            config.network
        )
        .into());
    }

    // Resolve `target` into (address, min_sats, max_sats). An alias
    // requires deposits.json; a bech32 address can go straight through.
    let (address, min_sats, max_sats) =
        if target.starts_with("bc1") || target.starts_with("tb1") || target.starts_with("bcrt1") {
            (target.clone(), 546u64, 0u64)
        } else {
            resolve_alias(&config.data_dir, &target)?
        };

    // Choose amount. Priority: explicit CLI arg → max_sats from deposit
    // → 10k default.
    let mut sats = match sats_arg {
        Some(s) => s,
        None if max_sats > 0 => max_sats,
        None => 10_000,
    };

    // Clamp to [min_sats, max_sats] if the deposit advertised a range.
    if max_sats > 0 {
        if sats > max_sats {
            eprintln!("Clamping {} to max {}", sats, max_sats);
            sats = max_sats;
        }
        if sats < min_sats {
            eprintln!("Clamping {} to min {}", sats, min_sats);
            sats = min_sats;
        }
    } else if sats < min_sats {
        // Just a bare address — enforce dust limit only.
        sats = min_sats;
    }

    let btc = format!("{:.8}", sats as f64 / 100_000_000.0);
    println!("Funding from regtest faucet...");
    println!("  Address: {}", address);
    println!("  Amount:  {} sats ({} BTC)", sats, btc);

    let rpc = RpcConfig::from_env();
    let txid = run_bitcoin_cli(&rpc, &["sendtoaddress", &address, &btc])?;
    println!("  Sent!    txid: {}...", &txid[..txid.len().min(16)]);

    // Confirm the transfer by mining one block. Any address works;
    // using -generate lets bitcoind pick a wallet address for the
    // coinbase.
    println!("Mining 1 block to confirm...");
    run_bitcoin_cli(&rpc, &["-generate", "1"])?;

    println!("Done. Deposit should credit automatically via the daemon's auto-sync.");
    Ok(())
}

fn resolve_alias(
    data_dir: &std::path::Path,
    alias: &str,
) -> Result<(String, u64, u64), Box<dyn std::error::Error>> {
    let deposits_file: PathBuf = data_dir.join("deposits.json");
    let raw = std::fs::read_to_string(&deposits_file).map_err(|_| {
        format!(
            "No deposits.json at {} — can't resolve alias '{}'. \
             Either pass a bech32 address directly, or open+offer a deposit first.",
            deposits_file.display(),
            alias
        )
    })?;
    let deposits: Vec<serde_json::Value> = serde_json::from_str(&raw)?;
    let deposit = deposits
        .iter()
        .find(|d| d.get("alias").and_then(|v| v.as_str()) == Some(alias))
        .ok_or_else(|| format!("No deposit with alias '{}'", alias))?;
    let address = deposit
        .get("funding_address")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            format!(
                "Deposit '{}' has no funding_address — run `deposits-wallet offer {} <sats>` first.",
                alias, alias
            )
        })?
        .to_string();
    let min_sats = deposit
        .get("min_sats")
        .and_then(|v| v.as_u64())
        .unwrap_or(546);
    let max_sats = deposit
        .get("max_sats")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    Ok((address, min_sats, max_sats))
}
