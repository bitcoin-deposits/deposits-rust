//! legacy-recover — given an on-chain Taproot scriptpubkey known to be a
//! `v_2026_04_17`-era reserves vault, find the `ledger_hash` value that
//! produced it. Use case: snowden/finney/hughes-style drift where the
//! daemon's metadata-writing path persisted a different ledger_hash than
//! the tx-construction path used.
//!
//! Pulls all kind:9100 events for the given ledger from a Nostr relay,
//! walks the chain (`chain_tip_hash` after each apply), and tries every
//! intermediate hash as a `ledger_hash` candidate against
//! `legacy_builders::v_2026_04_17::build`. Reports the matching event's
//! seq + content_hash on success.
//!
//! Usage:
//!   legacy-recover --relay wss://... --ledger-id <hex32> \
//!                  --operator <pubkey-hex> \
//!                  --member <pk-hex> [--member ...] \
//!                  --network bitcoin|testnet|signet|regtest \
//!                  --target-address bc1p...
//!
//! Exit 0 if a match is found; exit 1 otherwise.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use deposits_core::legacy_builders::v_2026_04_17;
use deposits_core::messages::LedgerOperation;
use deposits_core::tapscript_reserves::VoterSet;
use deposits_core::tlv::TlvDecode;
use deposits_core::SignedLedgerUpdate;
use std::str::FromStr;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let mut relay = "wss://relay.bitcoindeposits.net".to_string();
    let mut ledger_id_hex: Option<String> = None;
    let mut operator: Option<bitcoin::secp256k1::PublicKey> = None;
    let mut members: Vec<bitcoin::secp256k1::PublicKey> = Vec::new();
    let mut network = bitcoin::Network::Bitcoin;
    let mut target: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--relay" if i + 1 < args.len() => {
                relay = args[i + 1].clone();
                i += 2;
            }
            "--ledger-id" if i + 1 < args.len() => {
                ledger_id_hex = Some(args[i + 1].clone());
                i += 2;
            }
            "--operator" if i + 1 < args.len() => {
                operator = Some(bitcoin::secp256k1::PublicKey::from_str(&args[i + 1])?);
                i += 2;
            }
            "--member" if i + 1 < args.len() => {
                members.push(bitcoin::secp256k1::PublicKey::from_str(&args[i + 1])?);
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
            "--target-address" if i + 1 < args.len() => {
                target = Some(args[i + 1].clone());
                i += 2;
            }
            "--help" | "-h" => {
                eprintln!("{}", env!("CARGO_BIN_NAME"));
                eprintln!("Find the ledger_hash that produced an on-chain reserves scriptpubkey.");
                eprintln!();
                eprintln!("Required: --ledger-id, --operator, --member (1+), --target-address");
                return Ok(());
            }
            _ => i += 1,
        }
    }

    let ledger_id_hex = ledger_id_hex.ok_or("missing --ledger-id")?;
    let operator = operator.ok_or("missing --operator")?;
    let target = target.ok_or("missing --target-address")?;
    if members.is_empty() {
        return Err("missing --member (need at least 1)".into());
    }
    let ledger_tag = &ledger_id_hex[..16.min(ledger_id_hex.len())];

    let rt = tokio::runtime::Runtime::new()?;
    let events = rt.block_on(fetch_ledger_history(&relay, ledger_tag))?;
    eprintln!("Fetched {} event(s) for ledger {}…", events.len(), ledger_tag);

    let voter_set = VoterSet::new(operator, members.clone());
    let tiers = v_2026_04_17::default_tiers(members.len() + 1);

    // For each event, try BOTH `content_hash` AND `previous_hash` as the
    // candidate ledger_hash. Hand-validate against the target address.
    let mut tried: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
    for u in &events {
        for (label, h) in [("content_hash", u.content_hash), ("previous_hash", u.previous_hash)] {
            if !tried.insert(h) {
                continue;
            }
            let (addr, _, _) = match v_2026_04_17::build(&voter_set, &tiers, network, h) {
                Ok(t) => t,
                Err(_) => continue,
            };
            if addr.to_string() == target {
                eprintln!();
                eprintln!("✔ MATCH at seq {} {} = {}", u.sequence_number, label, hex::encode(h));
                eprintln!("  → ledger_hash to use for tier-leaf reconstruction: {}", hex::encode(h));
                // Also dump op type for context.
                if let Ok(op) = LedgerOperation::tlv_decode(&u.message) {
                    eprintln!("  (event op: {})", op.discriminant());
                }
                return Ok(());
            }
        }
    }

    eprintln!();
    eprintln!("✘ No event's content_hash or previous_hash produces target {}", target);
    eprintln!("  Tried {} unique hashes from {} events.", tried.len(), events.len());
    std::process::exit(1);
}

async fn fetch_ledger_history(
    relay_url: &str,
    ledger_tag: &str,
) -> Result<Vec<SignedLedgerUpdate>, Box<dyn std::error::Error>> {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    let (mut ws, _) = tokio_tungstenite::connect_async(relay_url).await?;
    let sub_id = "legacy-recover";
    let filter = serde_json::json!({
        "kinds": [9100],
        "#d": [ledger_tag],
        "limit": 10000,
    });
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
                if let Some(event) = arr.get(2) {
                    if let Some(content) = event.get("content").and_then(|v| v.as_str()) {
                        if let Ok(bytes) = BASE64.decode(content) {
                            if let Ok(u) = SignedLedgerUpdate::tlv_decode(&bytes) {
                                out.push(u);
                            }
                        }
                    }
                }
            }
            Some("EOSE") => break,
            _ => {}
        }
    }
    let close = serde_json::json!(["CLOSE", sub_id]);
    ws.send(Message::Text(close.to_string())).await.ok();
    out.sort_by_key(|u| u.sequence_number);
    Ok(out)
}
