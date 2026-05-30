//! migrate-snapshot — given an operator's `taproot_reserves.json` whose
//! `address` field doesn't match the on-chain UTXO at the recorded outpoint
//! (the v_2026_04_17 ledger_hash-drift bug we identified for the 2026-05-01
//! deployment), bisect the relay's full ledger history to find the
//! `ledger_hash` that produced the on-chain script. Then materialise the
//! Phase 1 self-describing fields (`script_pubkey`, `internal_key`,
//! `tier_leaves`) back into the JSON so sweep-all can sign without
//! re-running the buggy build path.
//!
//! Read-mode by default; pass `--write` to actually mutate the JSON.
//!
//! Usage:
//!   migrate-snapshot --root /mnt/bitcoind/deposits/ \
//!                    --esplora http://localhost:3100 \
//!                    --relay wss://relay.bitcoindeposits.net \
//!                    --network bitcoin \
//!                    [--operator <name>] [--write]

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use bitcoin::secp256k1::{PublicKey, XOnlyPublicKey};
use bitcoin::taproot::LeafVersion;
use bitcoin::{Address, Network};
use deposits_core::legacy_builders::v_2026_04_17;
use deposits_core::tapscript_reserves::VoterSet;
use deposits_core::tlv::TlvDecode;
use deposits_core::SignedLedgerUpdate;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

struct Args {
    root: PathBuf,
    esplora: String,
    relay: String,
    network: Network,
    operator_filter: Option<String>,
    write: bool,
}

fn parse_args() -> Result<Args, String> {
    let argv: Vec<String> = std::env::args().collect();
    let mut root: Option<PathBuf> = None;
    let mut esplora = "http://localhost:3100".to_string();
    let mut relay = "wss://relay.bitcoindeposits.net".to_string();
    let mut network = Network::Bitcoin;
    let mut operator_filter: Option<String> = None;
    let mut write = false;
    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "--root" if i + 1 < argv.len() => {
                root = Some(PathBuf::from(&argv[i + 1]));
                i += 2;
            }
            "--esplora" if i + 1 < argv.len() => {
                esplora = argv[i + 1].clone();
                i += 2;
            }
            "--relay" if i + 1 < argv.len() => {
                relay = argv[i + 1].clone();
                i += 2;
            }
            "--network" if i + 1 < argv.len() => {
                network = match argv[i + 1].as_str() {
                    "bitcoin" | "mainnet" => Network::Bitcoin,
                    "testnet" => Network::Testnet,
                    "signet" => Network::Signet,
                    "regtest" => Network::Regtest,
                    n => return Err(format!("unknown network: {}", n)),
                };
                i += 2;
            }
            "--operator" if i + 1 < argv.len() => {
                operator_filter = Some(argv[i + 1].clone());
                i += 2;
            }
            "--write" => {
                write = true;
                i += 1;
            }
            "--help" | "-h" => {
                println!("Usage: migrate-snapshot --root <dir> [--esplora <url>] [--relay <url>] [--network <n>] [--operator <name>] [--write]");
                std::process::exit(0);
            }
            _ => i += 1,
        }
    }
    Ok(Args {
        root: root.ok_or("missing --root")?,
        esplora,
        relay,
        network,
        operator_filter,
        write,
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_args()?;
    let rt = tokio::runtime::Runtime::new()?;

    let mut total_migrated = 0usize;
    let mut total_skipped = 0usize;

    for op_entry in std::fs::read_dir(&args.root)? {
        let op_entry = op_entry?;
        let op_name = op_entry.file_name().to_string_lossy().to_string();
        if let Some(ref f) = args.operator_filter {
            if &op_name != f {
                continue;
            }
        }
        let json_path = op_entry.path().join("node/wallet/taproot_reserves.json");
        if !json_path.exists() {
            continue;
        }
        println!();
        println!("=== {} ({}) ===", op_name, json_path.display());

        let raw = std::fs::read_to_string(&json_path)?;
        let mut arr: serde_json::Value = serde_json::from_str(&raw)?;
        let entries = match arr.as_array_mut() {
            Some(a) => a,
            None => {
                println!("  not a JSON array; skipping");
                total_skipped += 1;
                continue;
            }
        };

        for (idx, entry) in entries.iter_mut().enumerate() {
            // Skip already-migrated entries.
            if entry.get("tier_leaves").and_then(|v| v.as_array()).map(|a| !a.is_empty()).unwrap_or(false) {
                println!("  entry[{}]: already self-describing; skipping", idx);
                continue;
            }
            let declared_address = entry.get("address").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let outpoint_txid = entry.get("outpoint_txid").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let outpoint_vout = entry.get("outpoint_vout").and_then(|v| v.as_u64()).unwrap_or(0) as u32;

            if outpoint_txid.is_empty() {
                println!("  entry[{}]: no outpoint_txid; skipping", idx);
                continue;
            }
            // Fetch the on-chain scriptpubkey at the recorded outpoint.
            let on_chain = match rt.block_on(fetch_outpoint_address(
                &args.esplora,
                &outpoint_txid,
                outpoint_vout,
                args.network,
            )) {
                Ok(Some(a)) => a,
                Ok(None) => {
                    println!("  entry[{}]: couldn't fetch outpoint {} from esplora", idx, outpoint_txid);
                    continue;
                }
                Err(e) => {
                    println!("  entry[{}]: esplora error: {}", idx, e);
                    continue;
                }
            };
            if on_chain == declared_address {
                println!("  entry[{}]: declared address == on-chain; no drift", idx);
                continue;
            }
            println!("  entry[{}]: DRIFT — declared={} on-chain={}", idx, declared_address, on_chain);

            // Parse the recorded inputs.
            let operator = match entry.get("operator").and_then(|v| v.as_str()).and_then(|s| PublicKey::from_str(s).ok()) {
                Some(p) => p,
                None => {
                    println!("    can't parse operator; skipping");
                    continue;
                }
            };
            let members: Vec<PublicKey> = entry
                .get("quorum_members")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|m| m.as_str().and_then(|s| PublicKey::from_str(s).ok()))
                        .collect()
                })
                .unwrap_or_default();
            if members.is_empty() {
                println!("    no quorum_members; skipping");
                continue;
            }

            // Figure out which ledger this entry belongs to by bisecting against the
            // recorded `address` — we know v_2026_04_17::build with the recorded
            // members + some ledger_hash produces the declared address; we need to
            // find the ledger_id whose history contains a content_hash that does so.
            //
            // Simpler: pull every kind:9100 event tagged by every ledger this
            // operator owns. The relay's `#d` filter lets us scope to one ledger
            // at a time. We don't know the ledger_id from the JSON directly, so
            // walk the operator's `wallet/ledgers/` dir for `<ledger_id>.jsonl`
            // filenames.
            let ledgers_dir = op_entry.path().join("node/wallet/ledgers");
            let ledger_id_candidates: Vec<String> = std::fs::read_dir(&ledgers_dir)
                .map(|rd| {
                    rd.filter_map(|e| e.ok())
                        .filter_map(|e| e.file_name().to_str().map(|s| s.to_string()))
                        .filter_map(|n| n.strip_suffix(".jsonl").map(|s| s.to_string()))
                        .filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
                        .collect()
                })
                .unwrap_or_default();
            if ledger_id_candidates.is_empty() {
                println!("    no ledger jsonls in {}; skipping", ledgers_dir.display());
                continue;
            }

            let voter_set = VoterSet::new(operator, members.clone());
            let tiers = v_2026_04_17::default_tiers(members.len() + 1);

            // For each candidate ledger, fetch its history and find the matching
            // ledger_hash (content_hash OR previous_hash) that produces the on-chain
            // address.
            let mut found: Option<(String, [u8; 32], u64)> = None;
            'outer: for ledger_id in &ledger_id_candidates {
                let tag = &ledger_id[..16];
                let events = match rt.block_on(fetch_ledger_history(&args.relay, tag)) {
                    Ok(e) => e,
                    Err(_) => continue,
                };
                let mut tried: HashSet<[u8; 32]> = HashSet::new();
                for u in &events {
                    for h in [u.content_hash, u.previous_hash] {
                        if !tried.insert(h) {
                            continue;
                        }
                        if let Ok((addr, _, _)) = v_2026_04_17::build(&voter_set, &tiers, args.network, h) {
                            if addr.to_string() == on_chain {
                                found = Some((ledger_id.clone(), h, u.sequence_number));
                                break 'outer;
                            }
                        }
                    }
                }
            }

            let (ledger_id_hex, ledger_hash, seq) = match found {
                Some(t) => t,
                None => {
                    println!("    no matching ledger_hash found in any history; skipping");
                    continue;
                }
            };
            println!("    matched ledger {} at seq {}: ledger_hash={}", &ledger_id_hex[..16], seq, hex::encode(ledger_hash));

            // Rebuild + extract tier leaves and control blocks.
            let (rebuilt_addr, spend_info, leaf_scripts) =
                v_2026_04_17::build(&voter_set, &tiers, args.network, ledger_hash)?;
            assert_eq!(rebuilt_addr.to_string(), on_chain);
            let internal_key: XOnlyPublicKey = spend_info.internal_key();
            let script_pubkey_hex = hex::encode(rebuilt_addr.script_pubkey().as_bytes());
            let internal_key_hex = hex::encode(internal_key.serialize());

            let mut tier_leaves_json = serde_json::Value::Array(Vec::new());
            for (i, leaf) in leaf_scripts.iter().enumerate() {
                let cb = match spend_info.control_block(&(leaf.clone(), LeafVersion::TapScript)) {
                    Some(cb) => cb,
                    None => {
                        println!("    tier {} control block missing; skipping", i);
                        continue;
                    }
                };
                tier_leaves_json.as_array_mut().unwrap().push(serde_json::json!({
                    "tier_index": i as u32,
                    "script_hex": hex::encode(leaf.as_bytes()),
                    "control_block_hex": hex::encode(cb.serialize()),
                }));
            }

            // Write the new fields onto the entry (Phase 1 self-describing format).
            let obj = entry.as_object_mut().unwrap();
            obj.insert("script_pubkey".to_string(), serde_json::Value::String(script_pubkey_hex));
            obj.insert("internal_key".to_string(), serde_json::Value::String(internal_key_hex));
            obj.insert("tier_leaves".to_string(), tier_leaves_json);
            // ALSO update the address field to point to the on-chain reality —
            // every downstream tool that trusts `address` should agree with on-chain.
            obj.insert("address".to_string(), serde_json::Value::String(on_chain.clone()));
            // And the ledger_hash, since we now know the correct one.
            obj.insert("ledger_hash".to_string(), serde_json::Value::String(hex::encode(ledger_hash)));
            println!("    materialized self-describing fields ({} tier leaves)", leaf_scripts.len());
            total_migrated += 1;
        }

        if args.write {
            let formatted = serde_json::to_string_pretty(&arr)?;
            std::fs::write(&json_path, formatted)?;
            println!("  written.");
        } else {
            println!("  (dry-run — pass --write to persist)");
        }
    }

    println!();
    println!("=== Summary ===");
    println!("  migrated: {}", total_migrated);
    println!("  skipped:  {}", total_skipped);
    println!("  mode:     {}", if args.write { "WRITE" } else { "dry-run" });
    Ok(())
}

async fn fetch_outpoint_address(
    esplora: &str,
    txid: &str,
    vout: u32,
    network: Network,
) -> Result<Option<String>, String> {
    let url = format!("{}/tx/{}", esplora, txid);
    let resp = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| format!("client: {}", e))?
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("GET {}: {}", url, e))?;
    if !resp.status().is_success() {
        return Ok(None);
    }
    let v: serde_json::Value = resp.json().await.map_err(|e| format!("json: {}", e))?;
    let vouts = match v.get("vout").and_then(|x| x.as_array()) {
        Some(a) => a,
        None => return Ok(None),
    };
    let vo = match vouts.get(vout as usize) {
        Some(o) => o,
        None => return Ok(None),
    };
    let script_hex = match vo.get("scriptpubkey").and_then(|x| x.as_str()) {
        Some(s) => s,
        None => return Ok(None),
    };
    let script_bytes = hex::decode(script_hex).map_err(|e| format!("hex: {}", e))?;
    let script = bitcoin::ScriptBuf::from_bytes(script_bytes);
    Ok(Address::from_script(&script, network).ok().map(|a| a.to_string()))
}

async fn fetch_ledger_history(
    relay_url: &str,
    ledger_tag: &str,
) -> Result<Vec<SignedLedgerUpdate>, Box<dyn std::error::Error>> {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    let (mut ws, _) = tokio_tungstenite::connect_async(relay_url).await?;
    let sub_id = "migrate-snapshot";
    let filter = serde_json::json!({
        "kinds": [9100],
        "#d": [ledger_tag],
        "limit": 10000,
    });
    ws.send(Message::Text(serde_json::json!(["REQ", sub_id, filter]).to_string()))
        .await?;

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
                if let Some(content) = arr.get(2).and_then(|e| e.get("content")).and_then(|v| v.as_str()) {
                    if let Ok(bytes) = BASE64.decode(content) {
                        if let Ok(u) = SignedLedgerUpdate::tlv_decode(&bytes) {
                            out.push(u);
                        }
                    }
                }
            }
            Some("EOSE") => break,
            _ => {}
        }
    }
    ws.send(Message::Text(serde_json::json!(["CLOSE", sub_id]).to_string())).await.ok();
    out.sort_by_key(|u| u.sequence_number);
    Ok(out)
}

#[allow(dead_code)]
fn _unused_path(_: &Path) {}
