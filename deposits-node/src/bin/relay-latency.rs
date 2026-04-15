//! Simple relay latency test using broadcast messages with epoch timestamps.
//!
//! Sender: posts messages with current epoch millis
//! Receiver: compares received timestamp to local clock
//!
//! This isolates relay broadcast latency from other nostr-sdk overhead.

use nostr_sdk::prelude::*;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const KIND_TIMING_TEST: u16 = 29999;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    let mut relay = "ws://localhost:7778".to_string();
    let mut mode = "receiver";
    let mut count: u64 = 10;
    let mut interval_ms: u64 = 100;
    let mut seed: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--relay" => {
                relay = args.get(i + 1).cloned().unwrap_or_default();
                i += 2;
            }
            "--mode" => {
                mode = args.get(i + 1).map(|s| s.as_str()).unwrap_or("receiver");
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
            "--help" | "-h" => {
                println!("Relay latency test");
                println!("  --mode sender|receiver");
                println!("  --relay <url>");
                println!("  --count <n>");
                println!("  --interval <ms>");
                println!("  --seed <hex>");
                return Ok(());
            }
            _ => i += 1,
        }
    }

    let keys = if let Some(seed_hex) = seed {
        let seed_bytes = hex::decode(&seed_hex)?;
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&seed_bytes[..32]);
        let secret = SecretKey::from_slice(&key_bytes)?;
        Keys::new(secret)
    } else {
        Keys::generate()
    };

    println!("Pubkey: {}", keys.public_key().to_hex());

    let client = Client::new(keys.clone());
    client.add_relay(&relay).await?;
    client.connect().await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    match mode {
        "sender" => run_sender(&client, count, interval_ms).await?,
        _ => run_receiver(&client).await?,
    }

    Ok(())
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

async fn run_sender(
    client: &Client,
    count: u64,
    interval_ms: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "SENDER: Broadcasting {} messages at {}ms intervals",
        count, interval_ms
    );
    println!();

    for i in 0..count {
        let send_time = now_millis();
        let content = format!("{}:{}", i, send_time);

        let event = EventBuilder::new(Kind::Custom(KIND_TIMING_TEST), &content);

        let start = Instant::now();
        client.send_event_builder(event).await?;
        let send_elapsed = start.elapsed();

        println!(
            "[{}] sent ts={} (send took {:?})",
            i, send_time, send_elapsed
        );

        if i < count - 1 {
            tokio::time::sleep(Duration::from_millis(interval_ms)).await;
        }
    }

    println!();
    println!("Done sending.");
    Ok(())
}

async fn run_receiver(client: &Client) -> Result<(), Box<dyn std::error::Error>> {
    println!("RECEIVER: Waiting for broadcast messages...");
    println!();

    // Subscribe to timing test events
    let filter = Filter::new()
        .kind(Kind::Custom(KIND_TIMING_TEST))
        .since(Timestamp::now()); // Only new events
    client.subscribe(vec![filter], None).await?;

    let mut notifications = client.notifications();
    let mut latencies: Vec<f64> = Vec::new();

    loop {
        match tokio::time::timeout(Duration::from_secs(30), notifications.recv()).await {
            Ok(Ok(RelayPoolNotification::Event { event, .. })) => {
                let recv_time = now_millis();

                if event.kind.as_u16() != KIND_TIMING_TEST {
                    continue;
                }

                // Parse "seq:timestamp" from content
                let parts: Vec<&str> = event.content.split(':').collect();
                if parts.len() != 2 {
                    continue;
                }

                let seq: u64 = parts[0].parse().unwrap_or(0);
                let send_time: u64 = parts[1].parse().unwrap_or(0);

                let latency_ms = recv_time.saturating_sub(send_time) as f64;
                latencies.push(latency_ms);

                println!(
                    "[{}] send={} recv={} latency={:.1}ms",
                    seq, send_time, recv_time, latency_ms
                );
            }
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                eprintln!("Error: {}", e);
                break;
            }
            Err(_) => {
                println!();
                println!("Timeout - no messages for 30s");
                break;
            }
        }
    }

    if !latencies.is_empty() {
        latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let min = latencies.first().unwrap();
        let max = latencies.last().unwrap();
        let avg: f64 = latencies.iter().sum::<f64>() / latencies.len() as f64;
        let p50 = latencies[latencies.len() / 2];

        println!();
        println!("=== Relay Broadcast Latency ===");
        println!("Count: {}", latencies.len());
        println!("Min:   {:.1}ms", min);
        println!("Max:   {:.1}ms", max);
        println!("Avg:   {:.1}ms", avg);
        println!("P50:   {:.1}ms", p50);
    }

    Ok(())
}
