//! Microbenchmark for nostr-sdk overhead components.
//!
//! Build: cargo build --release --bin nostr-bench
//! Run: ./target/release/nostr-bench

use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};
use sha2::{Digest, Sha256};
use std::time::Instant;

fn main() {
    let secp = Secp256k1::new();

    // Create a keypair
    let secret = SecretKey::from_slice(&[1u8; 32]).unwrap();
    let keypair = Keypair::from_secret_key(&secp, &secret);
    let pubkey = XOnlyPublicKey::from_keypair(&keypair).0;

    // Create a message and signature
    let msg_bytes = [2u8; 32];
    let msg = Message::from_digest(msg_bytes);
    let sig = secp.sign_schnorr(&msg, &keypair);

    // Benchmark Schnorr verification
    let iterations = 10000;

    // Warmup
    for _ in 0..100 {
        let _ = secp.verify_schnorr(&sig, &msg, &pubkey);
    }

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = secp.verify_schnorr(&sig, &msg, &pubkey);
    }
    let verify_time = start.elapsed();

    // Benchmark SHA-256 hash (for event ID computation)
    let data = b"[0,\"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\",1234567890,1,[],\"test content\"]";
    let start = Instant::now();
    for _ in 0..iterations {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let _ = hasher.finalize();
    }
    let hash_time = start.elapsed();

    // Benchmark JSON parsing (typical nostr event)
    let json = r#"{"id":"0000000000000000000000000000000000000000000000000000000000000000","pubkey":"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","created_at":1234567890,"kind":1,"tags":[],"content":"test content","sig":"0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"}"#;
    let start = Instant::now();
    for _ in 0..iterations {
        let _: serde_json::Value = serde_json::from_str(json).unwrap();
    }
    let parse_time = start.elapsed();

    // Benchmark JSON serialization
    let value: serde_json::Value = serde_json::from_str(json).unwrap();
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = serde_json::to_string(&value).unwrap();
    }
    let serialize_time = start.elapsed();

    // Benchmark tokio mutex (simulating nostr-sdk database locks)
    use std::collections::HashMap;
    use std::sync::Arc;
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mutex: Arc<tokio::sync::Mutex<HashMap<u64, u64>>> =
        Arc::new(tokio::sync::Mutex::new(HashMap::new()));

    let start = Instant::now();
    rt.block_on(async {
        for i in 0..iterations as u64 {
            let mut guard = mutex.lock().await;
            guard.insert(i, i);
        }
    });
    let mutex_time = start.elapsed();

    println!("=== Microbenchmark Results ({} iterations) ===", iterations);
    println!();
    println!(
        "Schnorr verify:    {:>8.2} µs/op ({:.0} ops/sec)",
        verify_time.as_micros() as f64 / iterations as f64,
        iterations as f64 / verify_time.as_secs_f64()
    );
    println!(
        "SHA-256 hash:      {:>8.2} µs/op ({:.0} ops/sec)",
        hash_time.as_micros() as f64 / iterations as f64,
        iterations as f64 / hash_time.as_secs_f64()
    );
    println!(
        "JSON parse:        {:>8.2} µs/op ({:.0} ops/sec)",
        parse_time.as_micros() as f64 / iterations as f64,
        iterations as f64 / parse_time.as_secs_f64()
    );
    println!(
        "JSON serialize:    {:>8.2} µs/op ({:.0} ops/sec)",
        serialize_time.as_micros() as f64 / iterations as f64,
        iterations as f64 / serialize_time.as_secs_f64()
    );
    println!(
        "Tokio mutex lock:  {:>8.2} µs/op ({:.0} ops/sec)",
        mutex_time.as_micros() as f64 / iterations as f64,
        iterations as f64 / mutex_time.as_secs_f64()
    );
    println!();

    let crypto_ops = verify_time.as_micros() as f64 + hash_time.as_micros() as f64;
    let json_ops = parse_time.as_micros() as f64 + serialize_time.as_micros() as f64;
    println!(
        "Crypto per event:  {:>8.2} µs",
        crypto_ops / iterations as f64
    );
    println!(
        "JSON per event:    {:>8.2} µs",
        json_ops / iterations as f64
    );
    println!();

    let total_per_event = (verify_time + hash_time + parse_time + serialize_time + mutex_time)
        .as_micros() as f64
        / iterations as f64;
    println!("Total per event:   {:>8.2} µs", total_per_event);
    println!();

    // nostr-sdk does 3 mutex locks per incoming event + 1 for send
    let nostr_sdk_db = mutex_time.as_micros() as f64 * 4.0 / iterations as f64;
    println!(
        "Estimated nostr-sdk DB overhead (4 locks): {:.2} µs",
        nostr_sdk_db
    );
    println!();
    println!(
        "For 148ms overhead, that's {:.0}x these operations",
        148000.0 / total_per_event
    );
    println!();
    println!(
        "Mystery overhead = 148ms - {:.2}ms = {:.2}ms",
        total_per_event / 1000.0,
        148.0 - total_per_event / 1000.0
    );
}
