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
//!                  [--limit N] [--verbose] [--trace-spends]
//!
//! `--trace-spends` walks every spending tx out of each tracked address and
//! reports where the sats went, labeling destinations as `change` (same
//! address), `tracked` (another tracked reserves address), or `external`
//! (anything else). Useful for "I thought no money left the system — did it?".
//!
//! Exit code 0 iff the relay scan + esplora queries completed cleanly.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use deposits_core::messages::LedgerOperation;
use deposits_core::tlv::TlvDecode;
use deposits_core::SignedLedgerUpdate;
use std::time::Duration;

const DEFAULT_RELAY: &str = "wss://relay.bitcoindeposits.net";
const DEFAULT_ESPLORA: &str = "https://mempool.space/api";

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
    let mut trace_spends = false;
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
            "--trace-spends" => {
                trace_spends = true;
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
                     --verbose         Per-event trace\n  \
                     --trace-spends    For each address with spent_sats > 0, walk the\n  \
                     \x20                spending tx(s) and report destinations"
                );
                return Ok(());
            }
            _ => i += 1,
        }
    }

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run(&relay_url, &esplora_url, network, limit, verbose, trace_spends))
}

async fn run(
    relay_url: &str,
    esplora_url: &str,
    network: bitcoin::Network,
    limit: Option<usize>,
    verbose: bool,
    trace_spends: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("Collecting kind:9100 events from {} …", relay_url);
    let events = fetch_all_9100(relay_url).await?;
    eprintln!("  {} event(s) collected", events.len());

    // One row per LedgerOpen / QuorumBegin event — no filtering, no
    // dedup. Republish duplicates and non-on-chain placeholders both
    // show up as their own rows.
    #[derive(Debug)]
    struct Row {
        op: &'static str,
        field: &'static str,
        ledger_id_short: String,
        sequence: u64,
        reserves_id: String,
        /// `Some(stats)` when reserves_id parsed as an on-chain address on
        /// the chosen network and Esplora returned chain_stats; `None`
        /// otherwise (genesis placeholder, LDK partner pubkey, wrong-network
        /// address, query error, etc.). Each unparseable form is annotated.
        chain: Option<ChainStats>,
        note: String,
    }
    let mut rows: Vec<Row> = Vec::new();

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()?;

    for u in &events {
        let op = match LedgerOperation::tlv_decode(&u.message) {
            Ok(o) => o,
            Err(_) => continue,
        };
        // Every op variant that names a chain address. The `field`
        // column lets the output disambiguate (e.g. OnchainLock's
        // destination_address vs OnchainCredit's funding_address).
        let mut hits: Vec<(&'static str, &'static str, String)> = Vec::new();
        match &op {
            LedgerOperation::LedgerOpen { reserves_id, .. } => {
                hits.push(("LedgerOpen", "reserves_id", reserves_id.clone()));
            }
            LedgerOperation::QuorumBegin { reserves_id, .. } => {
                hits.push(("QuorumBegin", "reserves_id", reserves_id.clone()));
            }
            LedgerOperation::DisputeAcquire {
                new_reserves_address,
                ..
            } => {
                hits.push((
                    "DisputeAcquire",
                    "new_reserves",
                    new_reserves_address.clone(),
                ));
            }
            LedgerOperation::OnchainCredit {
                funding_address, ..
            } => {
                hits.push(("OnchainCredit", "funding", funding_address.clone()));
            }
            LedgerOperation::OnchainLock {
                destination_address,
                ..
            } => {
                hits.push((
                    "OnchainLock",
                    "destination",
                    destination_address.clone(),
                ));
            }
            LedgerOperation::OnchainFulfill {
                destination_address,
                ..
            } => {
                hits.push((
                    "OnchainFulfill",
                    "destination",
                    destination_address.clone(),
                ));
            }
            _ => {}
        }
        if hits.is_empty() {
            continue;
        }
        let ledger_id_short = hex::encode(&u.ledger_id[..8]);
        for (label, field, addr_str) in hits {
            if verbose {
                eprintln!(
                    "  seq {} {} ({}) from ledger {}… → {}",
                    u.sequence_number, label, field, ledger_id_short, addr_str
                );
            }
            let (chain, note) = classify_and_query(
                &http, esplora_url, network, &addr_str,
            )
            .await;
            rows.push(Row {
                op: label,
                field,
                ledger_id_short: ledger_id_short.clone(),
                sequence: u.sequence_number,
                reserves_id: addr_str,
                chain,
                note,
            });
        }
    }

    // Stable sort: by ledger_id, then sequence, then op (LedgerOpen<QuorumBegin).
    rows.sort_by(|a, b| {
        a.ledger_id_short
            .cmp(&b.ledger_id_short)
            .then(a.sequence.cmp(&b.sequence))
            .then(a.op.cmp(b.op))
    });
    if let Some(n) = limit {
        rows.truncate(n);
    }

    eprintln!();
    println!(
        "{:<12} {:>4} {:<15} {:<14} {:<64} {:>14} {:>14} {:>14} {:>5}  note",
        "ledger", "seq", "op", "field", "address", "funded_sats", "spent_sats", "balance", "txs"
    );
    println!("{}", "─".repeat(170));

    let mut grand_balance: i64 = 0;
    let mut grand_funded: u64 = 0;
    let mut grand_spent: u64 = 0;
    let mut counts: std::collections::BTreeMap<&'static str, usize> = Default::default();
    for r in &rows {
        *counts.entry(r.op).or_insert(0) += 1;
        match &r.chain {
            Some(stats) => {
                grand_funded += stats.funded_txo_sum;
                grand_spent += stats.spent_txo_sum;
                grand_balance += stats.balance();
                println!(
                    "{:<12} {:>4} {:<15} {:<14} {:<64} {:>14} {:>14} {:>14} {:>5}  {}",
                    r.ledger_id_short,
                    r.sequence,
                    r.op,
                    r.field,
                    r.reserves_id,
                    stats.funded_txo_sum,
                    stats.spent_txo_sum,
                    stats.balance(),
                    stats.funded_txo_count + stats.spent_txo_count,
                    r.note
                );
            }
            None => {
                println!(
                    "{:<12} {:>4} {:<15} {:<14} {:<64} {:>14} {:>14} {:>14} {:>5}  {}",
                    r.ledger_id_short,
                    r.sequence,
                    r.op,
                    r.field,
                    r.reserves_id,
                    "-",
                    "-",
                    "-",
                    "-",
                    r.note
                );
            }
        }
    }

    println!();
    println!("=== Totals ===");
    println!("  Events scanned:        {}", events.len());
    for (op_name, n) in &counts {
        println!("  {:<22} {}", format!("{}:", op_name), n);
    }
    println!("  Total funded:          {} sats", grand_funded);
    println!("  Total spent:           {} sats", grand_spent);
    println!(
        "  Net balance:           {} sats ({:.8} BTC)",
        grand_balance,
        grand_balance as f64 / 100_000_000.0
    );

    if trace_spends {
        let known: std::collections::HashMap<String, String> = rows
            .iter()
            .filter(|r| r.chain.is_some())
            .map(|r| (r.reserves_id.clone(), format!("{} {}", r.op, r.field)))
            .collect();
        let to_trace: Vec<&Row> = rows
            .iter()
            .filter(|r| r.chain.as_ref().is_some_and(|c| c.spent_txo_sum > 0))
            .collect();
        if to_trace.is_empty() {
            println!();
            println!("=== Spend traces ===");
            println!("  (no tracked address has any spends)");
        } else {
            println!();
            println!("=== Spend traces ===");
            // Dedup by address — many `LedgerOpen` rows share a reserves_id.
            let mut seen_addrs: std::collections::HashSet<&str> =
                std::collections::HashSet::new();
            for r in to_trace {
                if !seen_addrs.insert(r.reserves_id.as_str()) {
                    continue;
                }
                println!();
                println!(
                    "{} ({} {}) — spent {} sats:",
                    r.reserves_id,
                    r.op,
                    r.field,
                    r.chain.as_ref().unwrap().spent_txo_sum
                );
                match fetch_spend_traces(&http, esplora_url, &r.reserves_id).await {
                    Ok(traces) if traces.is_empty() => {
                        println!("  (esplora returned no spending txs — maybe rate-limited?)");
                    }
                    Ok(traces) => {
                        for t in traces {
                            println!(
                                "  tx {} ({} sats from this address):",
                                t.txid, t.inputs_from_us
                            );
                            for (dst, val) in &t.destinations {
                                let label = if dst == &r.reserves_id {
                                    "change".to_string()
                                } else if let Some(meta) = known.get(dst) {
                                    format!("tracked: {}", meta)
                                } else {
                                    "external".to_string()
                                };
                                println!(
                                    "    {:>14} sats → {}  [{}]",
                                    val, dst, label
                                );
                            }
                        }
                    }
                    Err(e) => println!("  trace failed: {}", e),
                }
            }
        }
    }

    Ok(())
}

/// A single tx that spends one or more UTXOs of an address we care about.
/// `inputs_from_us` is the total sats from `addr` consumed by this tx (the
/// other inputs, if any, came from other addresses and aren't our concern).
struct SpendTrace {
    txid: String,
    inputs_from_us: u64,
    destinations: Vec<(String, u64)>,
}

/// Walk every spending tx of `addr` via the esplora `/address/<a>/txs` +
/// `/address/<a>/txs/chain/<last>` pagination, returning one `SpendTrace`
/// per tx that consumes at least one UTXO of `addr`.
async fn fetch_spend_traces(
    http: &reqwest::Client,
    esplora_url: &str,
    addr: &str,
) -> Result<Vec<SpendTrace>, String> {
    let mut traces = Vec::new();
    let mut last_seen: Option<String> = None;
    loop {
        let url = match &last_seen {
            Some(last) => format!("{}/address/{}/txs/chain/{}", esplora_url, addr, last),
            None => format!("{}/address/{}/txs", esplora_url, addr),
        };
        let resp = http
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("GET {}: {}", url, e))?;
        if !resp.status().is_success() {
            return Err(format!("status {}", resp.status()));
        }
        let txs: Vec<serde_json::Value> =
            resp.json().await.map_err(|e| format!("json: {}", e))?;
        if txs.is_empty() {
            break;
        }
        let last_txid = txs
            .last()
            .and_then(|t| t.get("txid"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        for tx in &txs {
            let txid = match tx.get("txid").and_then(|v| v.as_str()) {
                Some(t) => t.to_string(),
                None => continue,
            };
            let mut inputs_from_us: u64 = 0;
            let mut spending = false;
            if let Some(vin) = tx.get("vin").and_then(|v| v.as_array()) {
                for input in vin {
                    let prev_addr = input
                        .get("prevout")
                        .and_then(|p| p.get("scriptpubkey_address"))
                        .and_then(|v| v.as_str());
                    if prev_addr == Some(addr) {
                        spending = true;
                        inputs_from_us += input
                            .get("prevout")
                            .and_then(|p| p.get("value"))
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                    }
                }
            }
            if !spending {
                continue;
            }
            let mut destinations = Vec::new();
            if let Some(vout) = tx.get("vout").and_then(|v| v.as_array()) {
                for out in vout {
                    let dst = out
                        .get("scriptpubkey_address")
                        .and_then(|v| v.as_str())
                        .unwrap_or("OP_RETURN")
                        .to_string();
                    let val = out
                        .get("value")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    destinations.push((dst, val));
                }
            }
            traces.push(SpendTrace {
                txid,
                inputs_from_us,
                destinations,
            });
        }
        // Esplora pages are bounded (mempool.space ~25-50 per page); stop
        // when we get a short page or fail to extract a cursor.
        match last_txid {
            Some(t) if txs.len() >= 25 => last_seen = Some(t),
            _ => break,
        }
    }
    Ok(traces)
}

/// Try to parse `addr_str` as a Bitcoin address on `network`; if it
/// parses, look it up via Esplora. Else categorize the form so the
/// output can explain why it's not chain-queryable.
async fn classify_and_query(
    http: &reqwest::Client,
    esplora_url: &str,
    network: bitcoin::Network,
    addr_str: &str,
) -> (Option<ChainStats>, String) {
    match addr_str.parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>() {
        Ok(parsed) => match parsed.clone().require_network(network) {
            Ok(_) => match fetch_chain_stats(http, esplora_url, addr_str).await {
                Ok(stats) => (Some(stats), String::new()),
                Err(e) => (None, format!("query-failed: {}", e)),
            },
            Err(_) => (None, "wrong-network".to_string()),
        },
        Err(_) => {
            if addr_str.starts_with("genesis:") {
                (None, "genesis-placeholder".to_string())
            } else if addr_str.len() == 66
                && addr_str.chars().all(|c| c.is_ascii_hexdigit())
            {
                (None, "pubkey-hex".to_string())
            } else {
                (None, "unparseable".to_string())
            }
        }
    }
}

/// `t`-tag discriminants of every op that names a chain address. The relay
/// can filter on these natively (operators tag their kind:9100 events with
/// the op discriminant at publish time — see deposits-nostr's TAG_OP_TYPE),
/// so the audit pulls only the events it actually decodes.
const ADDRESS_BEARING_DISCRIMINANTS: &[&str] = &[
    "1",  // LedgerOpen      → reserves_id
    "12", // QuorumBegin     → reserves_id
    "35", // OnchainCredit   → funding_address
    "36", // OnchainLock     → destination_address
    "38", // OnchainFulfill  → destination_address
    "55", // DisputeAcquire  → new_reserves_address
];

/// Page through every kind:9100 event the relay holds whose `t` tag is in
/// [`ADDRESS_BEARING_DISCRIMINANTS`]. Pagination uses `until = oldest_seen - 1`
/// after each page; we stop when a page returns zero events.
async fn fetch_all_9100(
    relay_url: &str,
) -> Result<Vec<SignedLedgerUpdate>, Box<dyn std::error::Error>> {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    let (mut ws, _) = tokio_tungstenite::connect_async(relay_url)
        .await
        .map_err(|e| format!("connect to {}: {}", relay_url, e))?;

    let mut out = Vec::new();
    let mut until: Option<u64> = None;
    let mut page = 0usize;
    loop {
        page += 1;
        let sub_id = format!("audit-{}", page);
        let mut filter = serde_json::json!({
            "kinds": [9100],
            "#t": ADDRESS_BEARING_DISCRIMINANTS,
            "limit": 500,
        });
        if let Some(u) = until {
            filter["until"] = serde_json::Value::from(u);
        }
        let req = serde_json::json!(["REQ", sub_id, filter]);
        ws.send(Message::Text(req.to_string())).await?;

        let mut page_count = 0usize;
        let mut page_oldest: Option<u64> = None;
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
                Some("EVENT") if arr.get(1).and_then(|v| v.as_str()) == Some(sub_id.as_str()) => {
                    let event = match arr.get(2) {
                        Some(e) => e,
                        None => continue,
                    };
                    let created_at = event.get("created_at").and_then(|v| v.as_u64()).unwrap_or(0);
                    page_oldest = Some(match page_oldest {
                        Some(o) => o.min(created_at),
                        None => created_at,
                    });
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
                        page_count += 1;
                    }
                }
                Some("EOSE") if arr.get(1).and_then(|v| v.as_str()) == Some(sub_id.as_str()) => {
                    break;
                }
                _ => {}
            }
        }
        let close = serde_json::json!(["CLOSE", sub_id]);
        ws.send(Message::Text(close.to_string())).await.ok();

        eprintln!("  page {}: {} event(s)", page, page_count);
        if page_count == 0 {
            break;
        }
        // Cursor for the next page: one second before the oldest event on
        // this page. If the relay returned events but no `created_at`,
        // there's nothing to advance to — stop to avoid an infinite loop.
        until = match page_oldest {
            Some(o) if o > 0 => Some(o - 1),
            _ => break,
        };
    }

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
