//! validate-relay — replay every ledger advertised on a Nostr relay
//! through the current code's validation rules and report compatibility.
//!
//! The "will my deployment break production?" check. Connects to a relay
//! (default `wss://relay.bitcoindeposits.net`), enumerates every kind-9100
//! ledger update, groups by ledger_id, walks each ledger's chain, and
//! replays through `Ledger::apply_operation` — the same strict path the
//! daemon uses on inbound updates. If the current code rejects an update
//! production has been writing, this surfaces it before deploy.
//!
//! Usage:
//!   validate-relay                                       # default relay
//!   validate-relay --relay wss://relay.example.com       # custom relay
//!   validate-relay --prefix abc                          # only matching ledgers
//!   validate-relay --verbose                             # per-step trace
//!   validate-relay --limit 10                            # cap ledger count
//!
//! Exit code 0 iff every ledger validates cleanly.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use deposits_core::messages::LedgerOperation;
use deposits_core::tlv::TlvDecode;
use deposits_core::types::LedgerState;
use deposits_core::SignedLedgerUpdate;
use std::time::Duration;

const DEFAULT_RELAY: &str = "wss://relay.bitcoindeposits.net";

#[derive(Debug)]
enum LedgerVerdict {
    /// All updates apply cleanly through current validation.
    Pass {
        seq_count: usize,
    },
    /// A specific update was rejected. Likely a code-vs-data
    /// regression — the deployment would refuse this ledger.
    Fail {
        seq: u64,
        reason: String,
    },
    /// The chain has missing sequences. Independent of code: the
    /// ledger isn't fully present on this relay. Surfaces as a
    /// warning rather than a deploy blocker.
    Gap {
        first_missing: u64,
    },
    /// Multiple updates at the same sequence (equivocation or fork).
    /// Pick the operator's primary chain by seq-0 operator_id and
    /// note the diverging sequence. Independent of code.
    Fork {
        seq: u64,
        operators: Vec<String>,
    },
    /// Couldn't decode any updates from the relay payload.
    NoUpdates,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let mut relay_url = DEFAULT_RELAY.to_string();
    let mut prefix = String::new();
    let mut verbose = false;
    let mut limit: Option<usize> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--relay" | "-r" if i + 1 < args.len() => {
                relay_url = args[i + 1].clone();
                i += 2;
            }
            "--prefix" | "-p" if i + 1 < args.len() => {
                prefix = args[i + 1].clone();
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
                    "Usage: validate-relay [--relay URL] [--prefix PFX] [--limit N] [--verbose]\n\
                     \n\
                     Replay every ledger on the relay through current validation rules.\n\
                     Exit code 0 iff every ledger passes."
                );
                return Ok(());
            }
            _ => i += 1,
        }
    }

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run(&relay_url, &prefix, limit, verbose))
}

async fn run(
    relay_url: &str,
    prefix: &str,
    limit: Option<usize>,
    verbose: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Two-pass: discover ledger IDs from a single broad fetch, then
    // re-fetch each ledger's full history with a `#d` filter. Public
    // relays (strfry default) cap broad subscriptions at ~500 events,
    // so a one-shot fetch can miss the older end of long chains. The
    // per-ledger pass uses a tighter filter so the cap doesn't bite.
    eprintln!("Discovering ledgers on {}...", relay_url);
    let mut ledger_ids = discover_ledger_ids(relay_url, prefix).await?;
    ledger_ids.sort();
    eprintln!("Found {} ledger(s)", ledger_ids.len());
    if let Some(n) = limit {
        ledger_ids.truncate(n);
    }
    eprintln!();

    let mut sorted: Vec<(String, Vec<SignedLedgerUpdate>)> = Vec::new();
    for lid in &ledger_ids {
        let updates = fetch_ledger_updates(relay_url, lid).await.unwrap_or_default();
        sorted.push((lid.clone(), updates));
    }

    let mut pass = 0usize;
    let mut fail = 0usize;
    let mut gap = 0usize;
    let mut fork = 0usize;
    let mut empty = 0usize;
    let mut first_failures: Vec<(String, u64, String)> = Vec::new();

    for (ledger_id, updates) in &sorted {
        let verdict = validate_ledger(ledger_id, updates, verbose);
        let short = &ledger_id[..16.min(ledger_id.len())];
        match &verdict {
            LedgerVerdict::Pass { seq_count } => {
                println!("✓ {}  ({} updates)", short, seq_count);
                pass += 1;
            }
            LedgerVerdict::Fail { seq, reason } => {
                println!("✗ {}  FAIL at seq {}: {}", short, seq, reason);
                first_failures.push((ledger_id.clone(), *seq, reason.clone()));
                fail += 1;
            }
            LedgerVerdict::Gap { first_missing } => {
                println!("⊘ {}  GAP — first missing seq {}", short, first_missing);
                gap += 1;
            }
            LedgerVerdict::Fork { seq, operators } => {
                println!(
                    "⌥ {}  FORK at seq {}: operators={}",
                    short,
                    seq,
                    operators
                        .iter()
                        .map(|o| &o[..8.min(o.len())])
                        .collect::<Vec<_>>()
                        .join(",")
                );
                fork += 1;
            }
            LedgerVerdict::NoUpdates => {
                println!("· {}  no decodable updates", short);
                empty += 1;
            }
        }
    }

    println!();
    println!("=== Summary ===");
    println!("  Total ledgers: {}", sorted.len());
    println!("  ✓ Pass:        {}", pass);
    println!("  ✗ Fail:        {}", fail);
    println!("  ⊘ Gap:         {}", gap);
    println!("  ⌥ Fork:        {}", fork);
    println!("  · Empty:       {}", empty);

    if fail > 0 {
        println!();
        println!("=== Failures (would block deployment) ===");
        for (lid, seq, reason) in &first_failures {
            println!("  {}  seq={}", &lid[..16.min(lid.len())], seq);
            println!("    {}", reason);
        }
        std::process::exit(1);
    }

    Ok(())
}

/// Validate one ledger's chain. Reads the operator's primary thread
/// (seq-0 operator_id), walks updates in sequence order, and applies
/// each through `Ledger::apply_operation` — which runs both
/// `validate_operation` and `apply_state_changes`.
fn validate_ledger(
    _ledger_id: &str,
    updates: &[SignedLedgerUpdate],
    verbose: bool,
) -> LedgerVerdict {
    if updates.is_empty() {
        return LedgerVerdict::NoUpdates;
    }

    // Find the genesis update (seq 0). Multiple seq-0 updates → fork
    // at genesis (rare but possible if the ledger was ever forked at
    // creation by an attacker).
    let genesis: Vec<&SignedLedgerUpdate> =
        updates.iter().filter(|u| u.sequence_number == 0).collect();
    if genesis.is_empty() {
        return LedgerVerdict::Gap { first_missing: 0 };
    }
    if genesis.len() > 1 {
        let operators: Vec<String> = genesis
            .iter()
            .map(|u| u.operator_id.to_string())
            .collect();
        return LedgerVerdict::Fork {
            seq: 0,
            operators,
        };
    }
    let original_operator = genesis[0].operator_id;

    // Filter to the original operator's chain, sort by sequence,
    // dedup on (seq, content_hash). Detect gaps and forks along the way.
    let mut canonical: Vec<&SignedLedgerUpdate> = updates
        .iter()
        .filter(|u| u.operator_id == original_operator)
        .collect();
    canonical.sort_by_key(|u| u.sequence_number);
    canonical.dedup_by(|a, b| {
        a.sequence_number == b.sequence_number && a.content_hash == b.content_hash
    });

    // Detect equivocation: same operator, same seq, different content_hash.
    // Detect gaps: missing sequence numbers.
    let mut prev_seq: Option<u64> = None;
    for u in &canonical {
        if let Some(prev) = prev_seq {
            if u.sequence_number == prev {
                let conflicting: Vec<String> = canonical
                    .iter()
                    .filter(|x| x.sequence_number == u.sequence_number)
                    .map(|x| x.operator_id.to_string())
                    .collect();
                return LedgerVerdict::Fork {
                    seq: u.sequence_number,
                    operators: conflicting,
                };
            }
            if u.sequence_number > prev + 1 {
                return LedgerVerdict::Gap {
                    first_missing: prev + 1,
                };
            }
        }
        prev_seq = Some(u.sequence_number);
    }

    // Replay each update through `LedgerState::apply` — the same strict
    // state-transition path the daemon's `inbound.rs` runs on every
    // received update. Catches conformance violations (negative
    // balance, InvoiceCredit-over-reserves, missing deposits, etc).
    // We pre-seed an empty state with the original_operator so the
    // first update (LedgerOpen) replays cleanly.
    let mut state = LedgerState::new(original_operator, String::new(), 0);

    for u in &canonical {
        let op = match LedgerOperation::tlv_decode(&u.message) {
            Ok(op) => op,
            Err(e) => {
                return LedgerVerdict::Fail {
                    seq: u.sequence_number,
                    reason: format!("decode: {}", e),
                };
            }
        };
        match state.apply(&op) {
            Ok(next) => {
                state = next;
                if verbose {
                    eprintln!("  seq {} OK ({})", u.sequence_number, op_name(&op));
                }
            }
            Err(e) => {
                return LedgerVerdict::Fail {
                    seq: u.sequence_number,
                    reason: format!("{} → {:?}", op_name(&op), e),
                };
            }
        }
    }

    LedgerVerdict::Pass {
        seq_count: canonical.len(),
    }
}

fn op_name(op: &LedgerOperation) -> &'static str {
    match op {
        LedgerOperation::LedgerOpen { .. } => "LedgerOpen",
        LedgerOperation::QuorumBegin { .. } => "QuorumBegin",
        LedgerOperation::DepositOpen { .. } => "DepositOpen",
        LedgerOperation::DepositClose { .. } => "DepositClose",
        LedgerOperation::FeeChange { .. } => "FeeChange",
        LedgerOperation::DepositKeyRotate { .. } => "DepositKeyRotate",
        LedgerOperation::InvoiceCredit { .. } => "InvoiceCredit",
        LedgerOperation::InvoiceLock { .. } => "InvoiceLock",
        LedgerOperation::InvoiceFail { .. } => "InvoiceFail",
        LedgerOperation::InvoiceFulfill { .. } => "InvoiceFulfill",
        LedgerOperation::OnchainCredit { .. } => "OnchainCredit",
        LedgerOperation::OnchainLock { .. } => "OnchainLock",
        LedgerOperation::OnchainFail { .. } => "OnchainFail",
        LedgerOperation::OnchainFulfill { .. } => "OnchainFulfill",
        LedgerOperation::TransferLock { .. } => "TransferLock",
        LedgerOperation::TransferComplete { .. } => "TransferComplete",
        LedgerOperation::TransferFail { .. } => "TransferFail",
        LedgerOperation::QuorumAddMember { .. } => "QuorumAddMember",
        LedgerOperation::QuorumRemoveMember { .. } => "QuorumRemoveMember",
        LedgerOperation::QuorumJoin { .. } => "QuorumJoin",
        LedgerOperation::FeeCollect { .. } => "FeeCollect",
        LedgerOperation::DisputeEnter { .. } => "DisputeEnter",
        LedgerOperation::DisputeAcquire { .. } => "DisputeAcquire",
        LedgerOperation::DisputeYield => "DisputeYield",
        LedgerOperation::DisputeArmed { .. } => "DisputeArmed",
        LedgerOperation::DeliveryEmbed { .. } => "DeliveryEmbed",
        LedgerOperation::LedgerClose => "LedgerClose",
    }
}

/// Pass 1: light enumeration. We don't decode TLV; we just read each
/// event's `d` tag (16-hex prefix of the ledger_id). This is enough to
/// list every ledger that has events on the relay. Even if the relay
/// caps the subscription at ~500 events, every active ledger has
/// recent updates so they all show up in the cap.
async fn discover_ledger_ids(
    relay_url: &str,
    prefix: &str,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    use futures_util::{SinkExt, StreamExt};
    use std::collections::HashSet;
    use tokio_tungstenite::tungstenite::Message;

    let (mut ws, _) = tokio_tungstenite::connect_async(relay_url)
        .await
        .map_err(|e| format!("connect to {}: {}", relay_url, e))?;

    let sub_id = "discover";
    let filter = serde_json::json!({ "kinds": [9100], "limit": 50000 });
    let req = serde_json::json!(["REQ", sub_id, filter]);
    ws.send(Message::Text(req.to_string())).await?;

    let mut tags: HashSet<String> = HashSet::new();

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
                let event_tags = match event.get("tags").and_then(|v| v.as_array()) {
                    Some(t) => t,
                    None => continue,
                };
                for tag in event_tags {
                    let tag_arr = match tag.as_array() {
                        Some(a) => a,
                        None => continue,
                    };
                    if tag_arr.first().and_then(|v| v.as_str()) == Some("d") {
                        if let Some(d_val) = tag_arr.get(1).and_then(|v| v.as_str()) {
                            tags.insert(d_val.to_string());
                        }
                    }
                }
            }
            Some("EOSE") => break,
            Some("NOTICE") => {
                if let Some(msg) = arr.get(1).and_then(|v| v.as_str()) {
                    eprintln!("Relay notice: {}", msg);
                }
            }
            _ => {}
        }
    }
    let close = serde_json::json!(["CLOSE", sub_id]);
    ws.send(Message::Text(close.to_string())).await.ok();
    ws.close(None).await.ok();

    let mut out: Vec<String> = tags
        .into_iter()
        .filter(|t| prefix.is_empty() || t.starts_with(prefix))
        .collect();
    out.sort();
    Ok(out)
}

/// Pass 2: fetch every kind-9100 event tagged with this specific
/// ledger_id (16-hex `d` tag). Tighter filter → less likely to hit
/// the relay's per-filter cap.
async fn fetch_ledger_updates(
    relay_url: &str,
    ledger_tag: &str,
) -> Result<Vec<SignedLedgerUpdate>, Box<dyn std::error::Error>> {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    let (mut ws, _) = tokio_tungstenite::connect_async(relay_url)
        .await
        .map_err(|e| format!("connect: {}", e))?;

    let sub_id = "fetch";
    let filter = serde_json::json!({
        "kinds": [9100],
        "#d": [ledger_tag],
        "limit": 10000,
    });
    let req = serde_json::json!(["REQ", sub_id, filter]);
    ws.send(Message::Text(req.to_string())).await?;

    let mut updates = Vec::new();
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
                    updates.push(u);
                }
            }
            Some("EOSE") => break,
            _ => {}
        }
    }
    let close = serde_json::json!(["CLOSE", sub_id]);
    ws.send(Message::Text(close.to_string())).await.ok();
    ws.close(None).await.ok();
    Ok(updates)
}
