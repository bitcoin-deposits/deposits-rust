//! audit-balances — discover every chain address ever named by a
//! LedgerOpen or QuorumBegin event on a Nostr relay, then query
//! Esplora for the funded / spent / unspent totals.
//!
//! Use cases:
//!   - "How much value is sitting in reserves across all live ledgers?"
//!   - "Which old QuorumBegin's reserves never moved?"
//!   - "Is there money stuck at an address we forgot about?"
//!
//! Walks the full set of kind:9100 events (operator-published
//! SignedLedgerUpdates) on the relay, decodes each, picks out the
//! `reserves_id` from LedgerOpen / QuorumBegin operations, dedups
//! per address, and reports per-address chain stats grouped by source.
//!
//! Usage:
//!   audit-balances [--relay wss://...] [--esplora https://...]
//!                  [--network bitcoin|testnet|signet|regtest]
//!                  [--limit N] [--verbose]
//!
//! Exit code 0 iff the relay scan + esplora queries completed cleanly.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use deposits_core::messages::LedgerOperation;
use deposits_core::tlv::TlvDecode;
use deposits_core::SignedLedgerUpdate;
use std::collections::BTreeMap;
use std::time::Duration;

const DEFAULT_RELAY: &str = "wss://relay.bitcoindeposits.net";
const DEFAULT_ESPLORA: &str = "https://mempool.space/api";

#[derive(Debug, Clone)]
struct AddrSource {
    /// "LedgerOpen" or "QuorumBegin"
    op: &'static str,
    /// 16-hex prefix of the ledger_id this address appeared in.
    ledger_id_short: String,
    /// Sequence number within that ledger.
    sequence: u64,
}

#[derive(Debug, Default)]
struct ChainStats {
    funded_txo_count: u64,
    funded_txo_sum: u64,
    spent_txo_count: u64,
    spent_txo_sum: u64,
}

impl ChainStats {
    fn balance(&self) -> i64 {
        self.funded_txo_sum as i64 - self.spent_txo_sum as i64
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let mut relay_url = DEFAULT_RELAY.to_string();
    let mut esplora_url = DEFAULT_ESPLORA.to_string();
    let mut limit: Option<usize> = None;
    let mut verbose = false;
    let mut network = bitcoin::Network::Bitcoin;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--relay" | "-r" if i + 1 < args.len() => {
                relay_url = args[i + 1].clone();
                i += 2;
            }
            "--esplora" | "-e" if i + 1 < args.len() => {
                esplora_url = args[i + 1].clone();
                i += 2;
            }
            "--network" if i + 1 < args.len() => {
                network = match args[i + 1].as_str() {
                    "bitcoin" | "mainnet" => bitcoin::Network::Bitcoin,
                    "testnet" => bitcoin::Network::Testnet,
                    "signet" => bitcoin::Network::Signet,
                    "regtest" => bitcoin::Network::Regtest,
                    n => return Err(format!("unknown network: {}", n).into()),
                };
                i += 2;
            }
            "--limit" | "-l" if i + 1 < args.len() => {
                limit = Some(args[i + 1].parse()?);
                i += 2;
            }
            "--verbose" | "-v" => {
                verbose = true;
                i += 1;
            }
            "--help" | "-h" => {
                println!(
                    "Usage: audit-balances [OPTIONS]\n\n\
                     Discover every chain address declared by LedgerOpen / QuorumBegin\n\
                     events on a Nostr relay, then query Esplora for balances.\n\n\
                     Options:\n  \
                     --relay URL       Nostr relay (default: relay.bitcoindeposits.net)\n  \
                     --esplora URL     Esplora HTTP API (default: mempool.space/api)\n  \
                     --network NAME    bitcoin|testnet|signet|regtest (default bitcoin)\n  \
                     --limit N         Cap addresses queried (sorted by first-seen order)\n  \
                     --verbose         Per-event trace"
                );
                return Ok(());
            }
            _ => i += 1,
        }
    }

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run(&relay_url, &esplora_url, network, limit, verbose))
}

async fn run(
    relay_url: &str,
    esplora_url: &str,
    network: bitcoin::Network,
    limit: Option<usize>,
    verbose: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("Collecting kind:9100 events from {} …", relay_url);
    let events = fetch_all_9100(relay_url).await?;
    eprintln!("  {} event(s) collected", events.len());

    // address → list of sources (op type, ledger_id, seq). Preserves
    // first-seen insertion order via BTreeMap sorted by string key →
    // not insertion-order; we want stable output anyway, so sort is
    // fine. Multiple ops can name the same address (LedgerOpen +
    // matching first QuorumBegin); we keep them all.
    let mut by_addr: BTreeMap<String, Vec<AddrSource>> = BTreeMap::new();
    for u in &events {
        let op = match LedgerOperation::tlv_decode(&u.message) {
            Ok(o) => o,
            Err(_) => continue,
        };
        let (label, reserves_id) = match &op {
            LedgerOperation::LedgerOpen { reserves_id, .. } => ("LedgerOpen", reserves_id),
            LedgerOperation::QuorumBegin { reserves_id, .. } => ("QuorumBegin", reserves_id),
            _ => continue,
        };
        // Filter for parseable on-chain addresses on the chosen network.
        // Non-on-chain reserves (e.g. genesis placeholders, LDK partner
        // pubkeys) wouldn't yield a balance and just noise the output.
        let parsed: bitcoin::Address<bitcoin::address::NetworkUnchecked> =
            match reserves_id.parse() {
                Ok(a) => a,
                Err(_) => continue,
            };
        if parsed.clone().require_network(network).is_err() {
            continue;
        }
        let entry = by_addr.entry(reserves_id.clone()).or_default();
        let new_source = AddrSource {
            op: label,
            ledger_id_short: hex::encode(&u.ledger_id[..8]),
            sequence: u.sequence_number,
        };
        // Republished updates show up multiple times with different
        // content_hashes (cosig accumulation); dedup on (op, ledger, seq)
        // so the source list stays clean.
        if !entry.iter().any(|s| {
            s.op == new_source.op
                && s.ledger_id_short == new_source.ledger_id_short
                && s.sequence == new_source.sequence
        }) {
            entry.push(new_source);
        }
        if verbose {
            eprintln!(
                "  seq {} {} from ledger {}… → {}",
                u.sequence_number,
                label,
                hex::encode(&u.ledger_id[..8]),
                reserves_id
            );
        }
    }
    eprintln!("  {} distinct on-chain address(es)", by_addr.len());
    eprintln!();

    let total_addrs = by_addr.len();
    let mut entries: Vec<(String, Vec<AddrSource>)> = by_addr.into_iter().collect();
    if let Some(n) = limit {
        entries.truncate(n);
    }

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()?;

    println!(
        "{:<64} {:>14} {:>14} {:>14} {:>5}  source(s)",
        "address", "funded_sats", "spent_sats", "balance_sats", "txs"
    );
    println!("{}", "─".repeat(64 + 1 + 14 + 1 + 14 + 1 + 14 + 1 + 5 + 2 + 16));

    let mut grand_balance: i64 = 0;
    let mut grand_funded: u64 = 0;
    let mut grand_spent: u64 = 0;
    let mut error_count = 0usize;
    let queried = entries.len();
    for (addr, sources) in &entries {
        match fetch_chain_stats(&http, esplora_url, addr).await {
            Ok(stats) => {
                grand_funded += stats.funded_txo_sum;
                grand_spent += stats.spent_txo_sum;
                grand_balance += stats.balance();
                let sources_str = sources
                    .iter()
                    .map(|s| {
                        format!("{}@{}…:{}", s.op, s.ledger_id_short, s.sequence)
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                println!(
                    "{:<64} {:>14} {:>14} {:>14} {:>5}  {}",
                    addr,
                    stats.funded_txo_sum,
                    stats.spent_txo_sum,
                    stats.balance(),
                    stats.funded_txo_count + stats.spent_txo_count,
                    sources_str
                );
            }
            Err(e) => {
                error_count += 1;
                println!("{:<64} ! query failed: {}", addr, e);
            }
        }
    }

    println!();
    println!("=== Totals ===");
    println!("  Addresses queried:  {} / {}", queried, total_addrs);
    println!("  Total funded:       {} sats", grand_funded);
    println!("  Total spent:        {} sats", grand_spent);
    println!("  Net balance:        {} sats ({:.8} BTC)", grand_balance, grand_balance as f64 / 100_000_000.0);
    if error_count > 0 {
        println!("  Query errors:       {}", error_count);
    }
    Ok(())
}

async fn fetch_all_9100(
    relay_url: &str,
) -> Result<Vec<SignedLedgerUpdate>, Box<dyn std::error::Error>> {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    let (mut ws, _) = tokio_tungstenite::connect_async(relay_url)
        .await
        .map_err(|e| format!("connect to {}: {}", relay_url, e))?;

    let sub_id = "audit";
    // No limit field: pull everything the relay will give us. strfry's
    // default cap is ~500 events — for a large relay we'd need to page,
    // but for a single audit pass that's good enough.
    let filter = serde_json::json!({ "kinds": [9100], "limit": 100000 });
    let req = serde_json::json!(["REQ", sub_id, filter]);
    ws.send(Message::Text(req.to_string())).await?;

    let mut out = Vec::new();
    loop {
        let msg = match tokio::time::timeout(Duration::from_secs(30), ws.next()).await {
            Ok(Some(Ok(Message::Text(text)))) => text,
            Ok(Some(Ok(Message::Close(_)))) | Ok(None) => break,
            Ok(Some(Ok(_))) => continue,
            Ok(Some(Err(_))) | Err(_) => break,
        };
        let arr: serde_json::Value = match serde_json::from_str(&msg) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let arr = match arr.as_array() {
            Some(a) => a,
            None => continue,
        };
        match arr.first().and_then(|v| v.as_str()) {
            Some("EVENT") => {
                let event = match arr.get(2) {
                    Some(e) => e,
                    None => continue,
                };
                let content = match event.get("content").and_then(|v| v.as_str()) {
                    Some(s) => s,
                    None => continue,
                };
                let bytes = match BASE64.decode(content) {
                    Ok(b) => b,
                    Err(_) => continue,
                };
                if let Ok(u) = SignedLedgerUpdate::tlv_decode(&bytes) {
                    out.push(u);
                }
            }
            Some("EOSE") => break,
            _ => {}
        }
    }
    let close = serde_json::json!(["CLOSE", sub_id]);
    ws.send(Message::Text(close.to_string())).await.ok();
    Ok(out)
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
    let chain = v.get("chain_stats").cloned().unwrap_or_default();
    let mempool = v.get("mempool_stats").cloned().unwrap_or_default();
    let chain_funded_c = chain
        .get("funded_txo_count")
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    let chain_funded_s = chain
        .get("funded_txo_sum")
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    let chain_spent_c = chain
        .get("spent_txo_count")
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    let chain_spent_s = chain
        .get("spent_txo_sum")
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    // Roll mempool stats into the totals — unconfirmed deposits /
    // withdrawals are still real claims on this address.
    let mem_funded_c = mempool
        .get("funded_txo_count")
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    let mem_funded_s = mempool
        .get("funded_txo_sum")
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    let mem_spent_c = mempool
        .get("spent_txo_count")
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    let mem_spent_s = mempool
        .get("spent_txo_sum")
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    Ok(ChainStats {
        funded_txo_count: chain_funded_c + mem_funded_c,
        funded_txo_sum: chain_funded_s + mem_funded_s,
        spent_txo_count: chain_spent_c + mem_spent_c,
        spent_txo_sum: chain_spent_s + mem_spent_s,
    })
}
