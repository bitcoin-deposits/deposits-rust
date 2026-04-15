//! Nostr ping test using real Deposits protocol messages.
//!
//! Measures round-trip latency for KIND_LEDGER_REQUEST/RESPONSE (20101/20102)
//! including full JSON serialization/deserialization.
//!
//! Usage:
//!   # Start responder (acts like an operator):
//!   nostr-ping --relay ws://localhost:7778 --mode responder --seed 0001...
//!
//!   # Start requester (acts like a wallet):
//!   nostr-ping --relay ws://localhost:7778 --mode requester --peer <responder_pubkey> --count 100
//!
//! The responder echoes back "ping" requests as responses, measuring full protocol overhead.

use deposits_node::nostr::{TAG_LEDGER_REQ, TAG_PUBKEY};
use nostr_sdk::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// Deposits protocol kinds (ephemeral range — relays auto-delete)
const KIND_LEDGER_REQUEST: u16 = 20101;
const KIND_LEDGER_RESPONSE: u16 = 20102;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LedgerRequest {
    ledger_id: String,
    action: String,
    params: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LedgerResponse {
    request_id: String,
    success: bool,
    result: Option<serde_json::Value>,
    error: Option<String>,
}

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Requester,
    Responder,
}

struct PingStats {
    sent: u64,
    received: u64,
    min_ms: f64,
    max_ms: f64,
    total_ms: f64,
    latencies: Vec<f64>,
}

impl PingStats {
    fn new() -> Self {
        Self {
            sent: 0,
            received: 0,
            min_ms: f64::MAX,
            max_ms: 0.0,
            total_ms: 0.0,
            latencies: Vec::new(),
        }
    }

    fn record(&mut self, latency_ms: f64) {
        self.received += 1;
        self.min_ms = self.min_ms.min(latency_ms);
        self.max_ms = self.max_ms.max(latency_ms);
        self.total_ms += latency_ms;
        self.latencies.push(latency_ms);
    }

    fn avg_ms(&self) -> f64 {
        if self.received == 0 {
            0.0
        } else {
            self.total_ms / self.received as f64
        }
    }

    fn percentile(&self, p: usize) -> f64 {
        if self.latencies.is_empty() {
            return 0.0;
        }
        let mut sorted = self.latencies.clone();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let idx = (p * sorted.len() / 100).min(sorted.len() - 1);
        sorted[idx]
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    let mut relay = "ws://localhost:7778".to_string();
    let mut mode = Mode::Requester;
    let mut peer_pubkey: Option<String> = None;
    let mut count: u64 = 10;
    let mut interval_ms: u64 = 100;
    let mut seed: Option<String> = None;
    let mut ledger_id = "test0000000000000000000000000000".to_string();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--relay" => {
                relay = args.get(i + 1).cloned().unwrap_or_default();
                i += 2;
            }
            "--mode" => {
                mode = match args.get(i + 1).map(|s| s.as_str()) {
                    Some("requester") | Some("sender") => Mode::Requester,
                    Some("responder") | Some("receiver") => Mode::Responder,
                    _ => Mode::Requester,
                };
                i += 2;
            }
            "--peer" => {
                peer_pubkey = args.get(i + 1).cloned();
                i += 2;
            }
            "--count" => {
                count = args.get(i + 1).and_then(|s| s.parse().ok()).unwrap_or(10);
                i += 2;
            }
            "--interval" => {
                interval_ms = args.get(i + 1).and_then(|s| s.parse().ok()).unwrap_or(100);
                i += 2;
            }
            "--seed" => {
                seed = args.get(i + 1).cloned();
                i += 2;
            }
            "--ledger" => {
                ledger_id = args.get(i + 1).cloned().unwrap_or_default();
                i += 2;
            }
            "--help" | "-h" => {
                print_help();
                return Ok(());
            }
            _ => i += 1,
        }
    }

    // Generate keys
    let keys = if let Some(seed_hex) = seed {
        let seed_bytes = hex::decode(&seed_hex)?;
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&seed_bytes[..32]);
        let secret = SecretKey::from_slice(&key_bytes)?;
        Keys::new(secret)
    } else {
        Keys::generate()
    };

    let my_pubkey = keys.public_key();
    println!("My pubkey: {}", my_pubkey.to_hex());

    // Connect
    let client = Client::new(keys.clone());
    client.add_relay(&relay).await?;
    client.connect().await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    match mode {
        Mode::Responder => run_responder(&client, &keys, &ledger_id).await?,
        Mode::Requester => {
            let peer = peer_pubkey.ok_or("--peer required for requester mode")?;
            run_requester(&client, &keys, &peer, &ledger_id, count, interval_ms).await?;
        }
    }

    Ok(())
}

fn print_help() {
    println!("Nostr Ping - Measure Deposits protocol latency");
    println!();
    println!("Usage:");
    println!("  nostr-ping --mode responder [options]");
    println!("  nostr-ping --mode requester --peer <pubkey> [options]");
    println!();
    println!("Options:");
    println!("  --relay <url>      Relay URL (default: ws://localhost:7778)");
    println!("  --mode <mode>      requester or responder");
    println!("  --peer <pubkey>    Responder's public key (hex)");
    println!("  --count <n>        Number of pings (default: 10)");
    println!("  --interval <ms>    Interval between pings (default: 100)");
    println!("  --seed <hex>       64-char hex seed for keys");
    println!("  --ledger <id>      Fake ledger ID (default: test0...)");
    println!();
    println!("Measures KIND_LEDGER_REQUEST (20101) -> KIND_LEDGER_RESPONSE (20102)");
    println!("round-trip time including full JSON serialization.");
}

async fn run_responder(
    client: &Client,
    keys: &Keys,
    ledger_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Running as RESPONDER (operator simulation)");
    println!("Ledger: {}", ledger_id);
    println!("Waiting for requests...");
    println!();

    // Subscribe to all ledger requests (like a real operator)
    let filter = Filter::new().kind(Kind::Custom(KIND_LEDGER_REQUEST));
    client.subscribe(vec![filter], None).await?;

    let mut notifications = client.notifications();
    let mut response_count = 0u64;

    loop {
        let recv_start = Instant::now();
        match notifications.recv().await {
            Ok(RelayPoolNotification::Event { event, .. }) => {
                let recv_time = recv_start.elapsed();
                let proc_start = Instant::now();

                if event.kind.as_u16() != KIND_LEDGER_REQUEST {
                    continue;
                }

                // Parse request (full deserialization like real code)
                let request: LedgerRequest = match serde_json::from_str(&event.content) {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("Parse error: {}", e);
                        continue;
                    }
                };
                let parse_time = proc_start.elapsed();

                // Only respond to ping action on our ledger
                if request.action != "ping" {
                    continue;
                }

                response_count += 1;
                let request_id = event.id.to_hex();

                // Build response (full serialization like real code)
                let build_start = Instant::now();
                let response = LedgerResponse {
                    request_id: request_id.clone(),
                    success: true,
                    result: Some(json!({
                        "pong": request.params.get("seq").unwrap_or(&json!(0)),
                        "responder": keys.public_key().to_hex(),
                        "timestamp_ms": std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_millis()
                    })),
                    error: None,
                };

                let response_json = serde_json::to_string(&response)?;

                // Send response event
                let response_event =
                    EventBuilder::new(Kind::Custom(KIND_LEDGER_RESPONSE), &response_json)
                        .tag(Tag::event(event.id)) // Reference request
                        .tag(Tag::public_key(event.pubkey)); // Tag requester
                let build_time = build_start.elapsed();

                let send_start = Instant::now();
                client.send_event_builder(response_event).await?;
                let send_time = send_start.elapsed();

                println!(
                    "[{}] REQ {} -> RESP (recv:{:?} parse:{:?} build:{:?} send:{:?})",
                    response_count,
                    &request_id[..16],
                    recv_time,
                    parse_time,
                    build_time,
                    send_time
                );
            }
            Ok(_) => {}
            Err(e) => {
                eprintln!("Notification error: {}", e);
                break;
            }
        }
    }

    Ok(())
}

async fn run_requester(
    client: &Client,
    keys: &Keys,
    peer_hex: &str,
    ledger_id: &str,
    count: u64,
    interval_ms: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Running as REQUESTER (wallet simulation)");
    println!("Peer: {}", peer_hex);
    println!("Ledger: {}", ledger_id);
    println!("Count: {}, Interval: {}ms", count, interval_ms);
    println!();

    // Subscribe to responses tagged to us
    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_RESPONSE))
        .custom_tag(TAG_PUBKEY, vec![keys.public_key().to_hex()]);
    client.subscribe(vec![filter], None).await?;

    // Also subscribe to all responses (in case tag filtering doesn't work)
    let filter_all = Filter::new().kind(Kind::Custom(KIND_LEDGER_RESPONSE));
    client.subscribe(vec![filter_all], None).await?;

    let pending: Arc<Mutex<HashMap<String, Instant>>> = Arc::new(Mutex::new(HashMap::new()));
    let stats: Arc<Mutex<PingStats>> = Arc::new(Mutex::new(PingStats::new()));

    // Spawn receiver
    let pending_clone = pending.clone();
    let stats_clone = stats.clone();
    let my_pubkey = keys.public_key();
    let mut notifications = client.notifications();

    let receiver_handle = tokio::spawn(async move {
        loop {
            match tokio::time::timeout(Duration::from_secs(10), notifications.recv()).await {
                Ok(Ok(RelayPoolNotification::Event { event, .. })) => {
                    if event.kind.as_u16() != KIND_LEDGER_RESPONSE {
                        continue;
                    }

                    // Check if tagged to us
                    let for_us = event.tags.iter().any(|t| {
                        if let Some(TagStandard::PublicKey { public_key, .. }) = t.as_standardized()
                        {
                            *public_key == my_pubkey
                        } else {
                            false
                        }
                    });

                    if !for_us {
                        continue;
                    }

                    // Parse response
                    let response: LedgerResponse = match serde_json::from_str(&event.content) {
                        Ok(r) => r,
                        Err(_) => continue,
                    };

                    // Look up request ID in pending
                    let latency = {
                        let mut pending = pending_clone.lock().unwrap();
                        pending
                            .remove(&response.request_id)
                            .map(|start| start.elapsed())
                    };

                    if let Some(lat) = latency {
                        let lat_ms = lat.as_secs_f64() * 1000.0;
                        let mut stats = stats_clone.lock().unwrap();
                        stats.record(lat_ms);
                        println!("  RESP {} - {:.2}ms", &response.request_id[..16], lat_ms);
                    }
                }
                Ok(Ok(_)) => {}
                Ok(Err(_)) => break,
                Err(_) => {
                    // Timeout - check if done
                    let pending = pending_clone.lock().unwrap();
                    if pending.is_empty() {
                        break;
                    }
                }
            }
        }
    });

    // Send requests
    for i in 0..count {
        let request = LedgerRequest {
            ledger_id: ledger_id.to_string(),
            action: "ping".to_string(),
            params: json!({
                "seq": i,
                "timestamp_ms": std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis()
            }),
        };

        let request_json = serde_json::to_string(&request)?;

        // Build request event
        let request_event = EventBuilder::new(Kind::Custom(KIND_LEDGER_REQUEST), &request_json)
            .tag(Tag::custom(
                TagKind::SingleLetter(TAG_LEDGER_REQ),
                vec![ledger_id.to_string()],
            ));

        // Send and get event ID
        let output = client.send_event_builder(request_event).await?;
        let event_id = output.id().to_hex();

        // Record pending
        {
            let mut pending = pending.lock().unwrap();
            pending.insert(event_id.clone(), Instant::now());
        }
        {
            let mut stats = stats.lock().unwrap();
            stats.sent += 1;
        }

        print!("REQ {} ", &event_id[..8]);
        std::io::Write::flush(&mut std::io::stdout())?;

        if i < count - 1 {
            tokio::time::sleep(Duration::from_millis(interval_ms)).await;
        }
    }

    println!();
    println!("All requests sent, waiting for responses...");

    let _ = tokio::time::timeout(Duration::from_secs(5), receiver_handle).await;

    // Print stats
    let stats = stats.lock().unwrap();
    println!();
    println!("=== Results (KIND_LEDGER_REQUEST/RESPONSE) ===");
    println!("Sent:     {}", stats.sent);
    println!(
        "Received: {} ({:.1}%)",
        stats.received,
        100.0 * stats.received as f64 / stats.sent.max(1) as f64
    );
    println!("Lost:     {}", stats.sent - stats.received);
    println!();
    if stats.received > 0 {
        println!("Round-trip latency:");
        println!("  Min:  {:.2}ms", stats.min_ms);
        println!("  Max:  {:.2}ms", stats.max_ms);
        println!("  Avg:  {:.2}ms", stats.avg_ms());
        println!("  P50:  {:.2}ms", stats.percentile(50));
        println!("  P95:  {:.2}ms", stats.percentile(95));
        println!("  P99:  {:.2}ms", stats.percentile(99));
        println!();
        println!("Effective TPS: {:.1}", 1000.0 / stats.avg_ms());
    }

    Ok(())
}
