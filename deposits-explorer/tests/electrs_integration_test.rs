//! Integration test for electrs client
//!
//! Run with: cargo test -p deposits-explorer --test electrs_integration_test
//!
//! Requires electrs running at http://localhost:3102

use std::env;

/// Skip test if electrs is not available
fn skip_if_no_electrs() -> bool {
    env::var("SKIP_ELECTRS_TESTS").is_ok()
}

#[tokio::test]
async fn test_fetch_blocks_from_electrs() {
    if skip_if_no_electrs() {
        println!("Skipping electrs test (SKIP_ELECTRS_TESTS set)");
        return;
    }

    let client = reqwest::Client::new();
    let url = "http://localhost:3102/blocks";

    match client.get(url).send().await {
        Ok(response) => {
            if response.status().is_success() {
                let blocks: Vec<serde_json::Value> = response.json().await.unwrap();
                assert!(!blocks.is_empty(), "Should have at least one block");

                let first_block = &blocks[0];
                assert!(first_block.get("id").is_some(), "Block should have id");
                assert!(first_block.get("height").is_some(), "Block should have height");
                assert!(first_block.get("timestamp").is_some(), "Block should have timestamp");

                println!(
                    "Successfully fetched {} blocks, tip at height {}",
                    blocks.len(),
                    first_block["height"]
                );
            } else {
                println!("Electrs returned error status: {}", response.status());
            }
        }
        Err(e) => {
            println!("Could not connect to electrs at {}: {}", url, e);
            println!("This is expected if electrs is not running");
        }
    }
}

#[tokio::test]
async fn test_fetch_transaction_from_electrs() {
    if skip_if_no_electrs() {
        return;
    }

    let client = reqwest::Client::new();

    // First get a block to find a txid
    let blocks_url = "http://localhost:3102/blocks";
    let blocks_resp = match client.get(blocks_url).send().await {
        Ok(r) if r.status().is_success() => r,
        _ => {
            println!("Skipping - electrs not available");
            return;
        }
    };

    let blocks: Vec<serde_json::Value> = blocks_resp.json().await.unwrap();
    if blocks.is_empty() {
        println!("No blocks available");
        return;
    }

    // Get txids from first block
    let block_hash = blocks[0]["id"].as_str().unwrap();
    let txids_url = format!("http://localhost:3102/block/{}/txids", block_hash);

    let txids_resp = client.get(&txids_url).send().await.unwrap();
    let txids: Vec<String> = txids_resp.json().await.unwrap();

    if txids.is_empty() {
        println!("No transactions in block");
        return;
    }

    // Fetch the first transaction
    let txid = &txids[0];
    let tx_url = format!("http://localhost:3102/tx/{}", txid);
    let tx_resp = client.get(&tx_url).send().await.unwrap();

    assert!(tx_resp.status().is_success());
    let tx: serde_json::Value = tx_resp.json().await.unwrap();

    assert_eq!(tx["txid"].as_str().unwrap(), txid);
    assert!(tx.get("vin").is_some(), "Transaction should have inputs");
    assert!(tx.get("vout").is_some(), "Transaction should have outputs");

    println!("Successfully fetched tx {}", txid);
}
