//! seed-funds — given a `seed.hex`, derive every wallet-style address
//! a deposits-node would have created and scan Esplora for unspent
//! UTXOs at each. Useful when you suspect funds are stranded
//! somewhere a `data_dir`-less view (e.g. audit-balances looking at
//! relay reserves only) doesn't cover.
//!
//! Paths scanned (matches the daemon's wallet construction):
//!   - Node-level wpkh: `wpkh(m/{0,1}/0..gap)`
//!   - Per-ledger BDK wpkh: `wpkh(m/86'/0'/<account>'/{0,1}/0..gap)`
//!     for `account ∈ 0..max-accounts`.
//!
//! Each address with any history (funded > 0) is printed; addresses
//! with current unspent balance are flagged. Totals at the end.
//!
//! Usage:
//!   seed-funds --seed <path/to/seed.hex>
//!              [--esplora https://mempool.space/api]
//!              [--network bitcoin|testnet|signet|regtest]
//!              [--gap N]           # gap limit per change branch (default 20)
//!              [--max-accounts N]  # ledger account indices to scan (default 32)
//!              [--verbose]

use bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv, Xpub};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Address, CompressedPublicKey, Network};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let mut seed_path: Option<PathBuf> = None;
    let mut esplora = "https://mempool.space/api".to_string();
    let mut network = Network::Bitcoin;
    let mut gap: u32 = 20;
    let mut max_accounts: u32 = 32;
    let mut verbose = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--seed" if i + 1 < args.len() => {
                seed_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--esplora" if i + 1 < args.len() => {
                esplora = args[i + 1].clone();
                i += 2;
            }
            "--network" if i + 1 < args.len() => {
                network = match args[i + 1].as_str() {
                    "bitcoin" | "mainnet" => Network::Bitcoin,
                    "testnet" => Network::Testnet,
                    "signet" => Network::Signet,
                    "regtest" => Network::Regtest,
                    n => return Err(format!("unknown network: {}", n).into()),
                };
                i += 2;
            }
            "--gap" if i + 1 < args.len() => {
                gap = args[i + 1].parse()?;
                i += 2;
            }
            "--max-accounts" if i + 1 < args.len() => {
                max_accounts = args[i + 1].parse()?;
                i += 2;
            }
            "--verbose" | "-v" => {
                verbose = true;
                i += 1;
            }
            "--help" | "-h" => {
                println!("Usage: seed-funds --seed <path> [--esplora URL] [--network NAME] [--gap N] [--max-accounts N]");
                return Ok(());
            }
            _ => i += 1,
        }
    }

    let seed_path = seed_path.ok_or("--seed is required")?;
    let seed_hex = std::fs::read_to_string(&seed_path)?
        .trim()
        .to_string();
    let seed_bytes = hex::decode(&seed_hex)?;
    if seed_bytes.len() != 32 {
        return Err(format!("seed must be 32 bytes; got {}", seed_bytes.len()).into());
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);

    let secp = Secp256k1::new();
    let xpriv = Xpriv::new_master(network, &seed)?;
    eprintln!("Master xpub: {}", Xpub::from_priv(&secp, &xpriv));
    eprintln!();

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(scan(
        &xpriv, &secp, network, &esplora, gap, max_accounts, verbose,
    ))
}

async fn scan(
    xpriv: &Xpriv,
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    network: Network,
    esplora: &str,
    gap: u32,
    max_accounts: u32,
    verbose: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()?;

    println!(
        "{:<48} {:<22} {:>14} {:>14} {:>14} {:>5}",
        "address", "path", "funded_sats", "spent_sats", "balance_sats", "txs"
    );
    println!("{}", "─".repeat(48 + 1 + 22 + 1 + 14 + 1 + 14 + 1 + 14 + 1 + 5));

    let mut totals = Totals::default();

    // 1. Node-level wpkh: m/<change>/<index>
    eprintln!("Scanning node-level wpkh m/{{0,1}}/0..{} …", gap);
    for change in [0u32, 1] {
        let stretch_misses = scan_branch(
            xpriv,
            secp,
            network,
            esplora,
            &http,
            &[ChildNumber::Normal { index: change }],
            gap,
            &mut totals,
            verbose,
        )
        .await?;
        if verbose {
            eprintln!("  m/{}  (terminated after {} empty addrs)", change, stretch_misses);
        }
    }

    // 2. Per-ledger BDK wpkh: m/86'/0'/<account>'/<change>/<index>.
    //    Scan accounts 0..max_accounts; bail early when an account's
    //    external + internal branches are both totally empty (no prior
    //    activity → this account was never created).
    eprintln!(
        "Scanning per-ledger BDK m/86'/0'/<account>'/{{0,1}}/0..{} for accounts 0..{} …",
        gap, max_accounts
    );
    let mut consecutive_empty_accounts = 0u32;
    const ACCOUNT_GAP: u32 = 4;
    for account in 0..max_accounts {
        let mut account_had_activity = false;
        for change in [0u32, 1] {
            let prefix = &[
                ChildNumber::Hardened { index: 86 },
                ChildNumber::Hardened { index: 0 },
                ChildNumber::Hardened { index: account },
                ChildNumber::Normal { index: change },
            ];
            let before = totals.queries;
            let _ = scan_branch(
                xpriv, secp, network, esplora, &http, prefix, gap, &mut totals, verbose,
            )
            .await?;
            if totals.queries > before && totals.found_any_in_branch {
                account_had_activity = true;
            }
            totals.found_any_in_branch = false;
        }
        if account_had_activity {
            consecutive_empty_accounts = 0;
        } else {
            consecutive_empty_accounts += 1;
        }
        if consecutive_empty_accounts >= ACCOUNT_GAP {
            if verbose {
                eprintln!(
                    "  account gap reached at {} ({} consecutive empty); stopping",
                    account, consecutive_empty_accounts
                );
            }
            break;
        }
    }

    println!();
    println!("=== Totals ===");
    println!("  Addresses queried:  {}", totals.queries);
    println!("  Addresses w/ history: {}", totals.with_history);
    println!("  Total funded:       {} sats", totals.funded);
    println!("  Total spent:        {} sats", totals.spent);
    println!(
        "  Net balance:        {} sats ({:.8} BTC)",
        totals.balance(),
        totals.balance() as f64 / 100_000_000.0
    );
    Ok(())
}

#[derive(Default)]
struct Totals {
    queries: usize,
    with_history: usize,
    funded: u64,
    spent: u64,
    /// Per-branch flag the caller resets between branches; set when
    /// any address in the current branch had history.
    found_any_in_branch: bool,
}

impl Totals {
    fn balance(&self) -> i64 {
        self.funded as i64 - self.spent as i64
    }
}

async fn scan_branch(
    xpriv: &Xpriv,
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    network: Network,
    esplora: &str,
    http: &reqwest::Client,
    prefix: &[ChildNumber],
    gap: u32,
    totals: &mut Totals,
    verbose: bool,
) -> Result<u32, Box<dyn std::error::Error>> {
    let mut consecutive_misses = 0u32;
    let mut index = 0u32;
    while consecutive_misses < gap {
        let mut path = prefix.to_vec();
        path.push(ChildNumber::Normal { index });
        let derivation_path = DerivationPath::from(path.clone());
        let child = xpriv.derive_priv(secp, &derivation_path)?;
        let pubkey = child.private_key.public_key(secp);
        let compressed = CompressedPublicKey::from_slice(&pubkey.serialize())?;
        let addr = Address::p2wpkh(&compressed, network);
        totals.queries += 1;
        // Throttle to ~10 qps so we don't immediately trip public
        // esplora rate-limiters (mempool.space caps low). Self-hosted
        // esplora: doesn't matter, 100ms is unnoticed.
        tokio::time::sleep(Duration::from_millis(100)).await;
        match fetch_chain_stats(http, esplora, &addr.to_string()).await {
            Ok(stats) if stats.has_history() => {
                totals.with_history += 1;
                totals.found_any_in_branch = true;
                totals.funded += stats.funded;
                totals.spent += stats.spent;
                consecutive_misses = 0;
                println!(
                    "{:<48} {:<22} {:>14} {:>14} {:>14} {:>5}",
                    addr,
                    format_path(&path),
                    stats.funded,
                    stats.spent,
                    stats.balance(),
                    stats.tx_count
                );
            }
            Ok(_) => {
                consecutive_misses += 1;
                if verbose {
                    println!(
                        "{:<48} {:<22} {:>14} {:>14} {:>14} {:>5}",
                        addr,
                        format_path(&path),
                        0,
                        0,
                        0,
                        0
                    );
                }
            }
            Err(e) => {
                eprintln!("  query failed for {}: {}", addr, e);
                consecutive_misses += 1;
            }
        }
        index += 1;
    }
    Ok(consecutive_misses)
}

fn format_path(path: &[ChildNumber]) -> String {
    let mut s = String::from("m/");
    for (i, c) in path.iter().enumerate() {
        if i > 0 {
            s.push('/');
        }
        match c {
            ChildNumber::Normal { index } => s.push_str(&index.to_string()),
            ChildNumber::Hardened { index } => {
                s.push_str(&format!("{}'", index));
            }
        }
    }
    s
}

#[derive(Default)]
struct ChainStats {
    funded: u64,
    spent: u64,
    tx_count: u64,
}

impl ChainStats {
    fn balance(&self) -> i64 {
        self.funded as i64 - self.spent as i64
    }
    fn has_history(&self) -> bool {
        self.tx_count > 0
    }
}

async fn fetch_chain_stats(
    http: &reqwest::Client,
    esplora_url: &str,
    address: &str,
) -> Result<ChainStats, String> {
    let url = format!("{}/address/{}", esplora_url, address);
    let resp = http
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("GET {}: {}", url, e))?;
    if !resp.status().is_success() {
        return Err(format!("status {}", resp.status()));
    }
    let v: serde_json::Value = resp.json().await.map_err(|e| format!("json: {}", e))?;
    let take = |scope: &str, field: &str| -> u64 {
        v.get(scope)
            .and_then(|s| s.get(field))
            .and_then(|x| x.as_u64())
            .unwrap_or(0)
    };
    let funded = take("chain_stats", "funded_txo_sum") + take("mempool_stats", "funded_txo_sum");
    let spent = take("chain_stats", "spent_txo_sum") + take("mempool_stats", "spent_txo_sum");
    let tx_count = take("chain_stats", "tx_count") + take("mempool_stats", "tx_count");
    Ok(ChainStats {
        funded,
        spent,
        tx_count,
    })
}
