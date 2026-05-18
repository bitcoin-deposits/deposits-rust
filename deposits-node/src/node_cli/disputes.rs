//! `disputes` CLI: surface the dispute pipeline's per-ledger state.
//!
//! `disputes list` — one-line summary per ledger that has any
//! dispute activity (main `dispute_state != Normal`, OR a
//! fork-branch ledger present in `handler.ledgers`, OR a quorum
//! past its `quorum_expiry`).
//!
//! `disputes show <ledger_id_or_prefix>` — detailed view: each fork
//! by disputer, sequence of dispute ops on that fork, replacement
//! collateral declaration, on-chain confiscation state, and a
//! "next step" hint based on what the daemon would be waiting on.

use super::parse_config;
use crate::Node;
use bitcoin::secp256k1::PublicKey;
use deposits_core::messages::LedgerOperation;
use deposits_core::tlv::TlvDecode;
use deposits_core::types::DisputeState;
use std::sync::Arc;

pub async fn disputes_command(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.is_empty() {
        eprintln!("Usage: deposits-node disputes <list|show>");
        eprintln!("  list                   One-line summary of every ledger with dispute activity.");
        eprintln!("  show <ledger_id|prefix> Detailed view of one ledger + its forks.");
        return Ok(());
    }
    match args[0].as_str() {
        "list" => disputes_list(&args[1..]).await,
        "show" => disputes_show(&args[1..]).await,
        other => {
            eprintln!("Unknown disputes subcommand: {}", other);
            eprintln!("Usage: deposits-node disputes <list|show>");
            Ok(())
        }
    }
}

/// Per-fork summary derived from the fork-branch JSONL.
#[derive(Debug, Clone)]
struct ForkSummary {
    fork_key: String,
    disputer_pubkey: Option<PublicKey>,
    last_valid_seq: u64,
    has_dispute_enter: bool,
    anchor_block_height: Option<u32>,
    quorum_member_count: usize,
    has_dispute_armed: bool,
    armed_block: Option<u32>,
    has_replacement_collateral: bool,
    has_dispute_acquire: bool,
    has_dispute_yield: bool,
    dispute_state: DisputeState,
}

/// Build a fork summary from the union of local fork history and
/// any relay-fetched updates for the same fork. The caller is
/// responsible for ensuring the iterator covers everything it can
/// — a partial local JSONL (post disk-full) plus a relay fetch is
/// the recommended source.
fn summarize_fork(
    fork_key: &str,
    ledger: &deposits_core::ledger::Ledger,
    extra_updates: &[deposits_core::types::SignedLedgerUpdate],
) -> Option<ForkSummary> {
    let mut s = ForkSummary {
        fork_key: fork_key.to_string(),
        disputer_pubkey: None,
        last_valid_seq: 0,
        has_dispute_enter: false,
        anchor_block_height: None,
        quorum_member_count: 0,
        has_dispute_armed: false,
        armed_block: None,
        has_replacement_collateral: false,
        has_dispute_acquire: false,
        has_dispute_yield: false,
        dispute_state: ledger.state.dispute_state,
    };
    // Compound key format: `{ledger_id:64}_{seq:06}_{pk_16}`
    if fork_key.len() <= 64 {
        return None;
    }
    let parts: Vec<&str> = fork_key.splitn(3, '_').collect();
    if parts.len() != 3 {
        return None;
    }
    s.last_valid_seq = parts[1].parse().ok()?;
    let disputer_prefix = parts[2]; // 16 hex chars of disputer pubkey

    // Combine local fork history with extra (relay-fetched) updates,
    // dedup by content_hash. The local JSONL may be truncated by a
    // prior disk-full event; the relay fetch fills the gaps.
    let mut seen: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
    let chain: Vec<&deposits_core::types::SignedLedgerUpdate> = ledger
        .history
        .iter()
        .chain(extra_updates.iter())
        .filter(|u| {
            // Only updates on this disputer's fork branch.
            let op_hex = hex::encode(u.operator_id.serialize());
            if !op_hex.starts_with(disputer_prefix) {
                return false;
            }
            // Strictly past the divergence seq.
            if u.sequence_number < s.last_valid_seq {
                return false;
            }
            seen.insert(u.content_hash)
        })
        .collect();

    for u in chain {
        let Ok(op) = LedgerOperation::tlv_decode(&u.message) else {
            continue;
        };
        match op {
            LedgerOperation::DisputeEnter {
                anchor_block_height,
                ..
            } => {
                s.has_dispute_enter = true;
                s.anchor_block_height = anchor_block_height;
                s.disputer_pubkey = Some(u.operator_id);
            }
            LedgerOperation::QuorumAddMember { .. } => {
                s.quorum_member_count += 1;
            }
            LedgerOperation::DisputeArmed {
                armed_block,
                replacement_collateral,
                ..
            } => {
                s.has_dispute_armed = true;
                s.armed_block = Some(armed_block);
                s.has_replacement_collateral = replacement_collateral.is_some();
            }
            LedgerOperation::DisputeAcquire { .. } => {
                s.has_dispute_acquire = true;
            }
            LedgerOperation::DisputeYield => {
                s.has_dispute_yield = true;
            }
            _ => {}
        }
    }
    Some(s)
}

/// Fetch every kind:9100 event tagged with `ledger_id` from the
/// relay pool and decode the inner TLV SignedLedgerUpdates. Used
/// by the disputes CLI to backfill fork-branch history that's
/// missing from the local JSONL (post disk-full, or for forks the
/// local daemon never personally observed).
///
/// Paginates forward by `created_at` so forks with thousands of
/// rows (e.g. a fork with hundreds of duplicate QuorumAddMember
/// updates pre-dedup-fix) don't truncate to the first 500 events
/// the relay returns — the relay serves newest-first, so a single
/// 500-event fetch on a 1000-row fork misses the OLDEST entries
/// (which is exactly where DisputeEnter lives).
///
/// Returns an empty vec on any relay error — the caller falls
/// back to local-only history.
async fn fetch_ledger_updates_from_relay(
    node: &Node,
    ledger_id: &str,
) -> Vec<deposits_core::types::SignedLedgerUpdate> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use nostr_sdk::{Filter, Kind, Timestamp};

    const PAGE_LIMIT: usize = 500;
    const MAX_PAGES: u32 = 20; // 20 × 500 = 10k events should cover any pathological fork
    const PAGE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

    let client = node.nostr.fetch_client();
    let mut all_updates = Vec::new();
    let mut seen: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
    let mut cursor_ts: u64 = 0;
    let mut pages = 0u32;

    loop {
        let mut filter = Filter::new()
            .kind(Kind::Custom(crate::nostr::KIND_LEDGER_UPDATE))
            .custom_tag(
                crate::nostr::TAG_LEDGER_ID,
                [crate::nostr::ledger_tag(ledger_id)],
            )
            .limit(PAGE_LIMIT);
        if cursor_ts > 0 {
            // Walk newer-than-cursor on each iteration — the relay
            // still returns newest-first within the window, so we
            // shift the floor up after every page and drain the
            // whole timeline this way.
            filter = filter.since(Timestamp::from(cursor_ts));
        }

        let events = match client.fetch_events(vec![filter], Some(PAGE_TIMEOUT)).await {
            Ok(e) => e,
            Err(_) => break,
        };
        if events.is_empty() {
            break;
        }

        let mut page_max_ts = cursor_ts;
        let mut page_added = 0usize;
        for event in events.iter() {
            let ts = event.created_at.as_u64();
            if ts > page_max_ts {
                page_max_ts = ts;
            }
            if let Ok(tlv) = BASE64.decode(&event.content) {
                if let Ok(u) = deposits_core::types::SignedLedgerUpdate::tlv_decode(&tlv) {
                    if seen.insert(u.content_hash) {
                        all_updates.push(u);
                        page_added += 1;
                    }
                }
            }
        }
        let _ = page_added;
        pages += 1;
        // Stop when the page didn't push the cursor forward (no
        // events newer than what we already saw) or we hit the
        // page cap. The "page fewer than limit" check is the
        // natural end-of-stream signal.
        if page_max_ts <= cursor_ts
            || events.len() < PAGE_LIMIT
            || pages >= MAX_PAGES
        {
            break;
        }
        cursor_ts = page_max_ts;
    }

    all_updates
}

/// "What is the pipeline waiting on next?" derived from a fork
/// summary plus the on-chain reserves-UTXO spent status.
fn next_step_hint(
    fork: &ForkSummary,
    reserves_spent: Option<bool>,
    current_block: u32,
    quorum_expiry: Option<u32>,
) -> &'static str {
    if fork.has_dispute_acquire {
        return "won — rotate (recovery rotate-to-quorum)";
    }
    if fork.has_dispute_yield {
        return "yielded — branch tombstoned";
    }
    if !fork.has_dispute_enter {
        return "fork created but DisputeEnter missing (auto-arm should retry)";
    }
    if !fork.has_dispute_armed {
        return "DisputeEnter present, waiting for DisputeArmed";
    }
    if !fork.has_replacement_collateral {
        return "armed without replacement_collateral — fund operator P2WPKH then re-arm";
    }
    match reserves_spent {
        Some(true) => "confiscation TX landed — waiting for lottery reveal/claim",
        Some(false) => "armed with collateral — waiting on quorum cosignatures for confiscation TX",
        None => match quorum_expiry {
            Some(expiry) if current_block > expiry => {
                "armed; chain query unavailable — confiscation pending"
            }
            _ => "armed",
        },
    }
}

async fn disputes_list(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let config = parse_config(args)?;
    let node = Arc::new(Node::new(config).await?);
    let _ = node.sync_wallet();
    let current_block = node.wallet.get_block_height().unwrap_or(0);

    // Collect: every main ledger + every fork. Group by main ledger_id.
    let snapshot: Vec<(String, deposits_core::ledger::Ledger)> = {
        let ledgers = node.handler.ledgers.lock().unwrap();
        ledgers
            .iter()
            .map(|(k, arc)| (k.clone(), arc.read().unwrap().clone()))
            .collect()
    };

    let mut by_ledger: std::collections::BTreeMap<String, Vec<(String, ForkSummary)>> =
        std::collections::BTreeMap::new();
    let mut mains: std::collections::BTreeMap<String, deposits_core::ledger::Ledger> =
        std::collections::BTreeMap::new();
    let mut fork_keys: std::collections::BTreeMap<String, Vec<(String, deposits_core::ledger::Ledger)>> =
        std::collections::BTreeMap::new();
    for (key, ledger) in snapshot {
        if key.len() == 64 {
            // Main ledger.
            mains.insert(key, ledger);
        } else if key.len() > 64 {
            // Fork-branch. Key prefix == main ledger_id.
            let main_id = key[..64].to_string();
            fork_keys.entry(main_id).or_default().push((key, ledger));
        }
    }

    // Backfill fork-branch history from the relay: a disk-full
    // event can truncate the on-disk JSONL such that DisputeEnter /
    // DisputeArmed are missing from history even though the fork's
    // `state.dispute_state` reflects them. We re-fetch each
    // affected ledger's kind:9100 events from the relay and pass
    // them into `summarize_fork` as a parallel source.
    let mut relay_updates: std::collections::HashMap<String, Vec<deposits_core::types::SignedLedgerUpdate>> =
        std::collections::HashMap::new();
    for main_id in fork_keys.keys() {
        let fetched = fetch_ledger_updates_from_relay(&node, main_id).await;
        relay_updates.insert(main_id.clone(), fetched);
    }

    for (main_id, forks) in &fork_keys {
        let empty = Vec::new();
        let extras = relay_updates.get(main_id).unwrap_or(&empty);
        for (fork_key, fork_ledger) in forks {
            if let Some(s) = summarize_fork(fork_key, fork_ledger, extras) {
                by_ledger
                    .entry(main_id.clone())
                    .or_default()
                    .push((fork_key.clone(), s));
            }
        }
    }

    // Interesting = main is in dispute state, OR has any fork, OR
    // past quorum_expiry.
    let mut printed = false;
    println!(
        "{:<18} {:<10} {:<11} {:<9} {:<7} {:<7} {:<7} next step",
        "ledger", "state", "expiry", "forks", "armed", "rc=Some", "spent"
    );
    println!("{}", "─".repeat(110));
    for (lid, main) in &mains {
        let forks = by_ledger.get(lid).cloned().unwrap_or_default();
        let in_dispute = main.state.dispute_state != DisputeState::Normal;
        let past_expiry = main
            .state
            .quorum_expiry
            .map(|e| current_block > e)
            .unwrap_or(false);
        let has_fork = !forks.is_empty();
        if !in_dispute && !past_expiry && !has_fork {
            continue;
        }
        printed = true;

        let armed = forks.iter().filter(|(_, f)| f.has_dispute_armed).count();
        let with_rc = forks
            .iter()
            .filter(|(_, f)| f.has_replacement_collateral)
            .count();

        let reserves_spent = is_reserves_unspent(&node, main).await.map(|u| !u);
        let spent_label = match reserves_spent {
            Some(true) => "yes",
            Some(false) => "no",
            None => "?",
        };
        let expiry_label = main
            .state
            .quorum_expiry
            .map(|e| {
                if current_block > e {
                    format!("EXPIRED(+{})", current_block - e)
                } else {
                    format!("in {}", e - current_block)
                }
            })
            .unwrap_or_else(|| "—".to_string());
        let state_label = format!("{:?}", main.state.dispute_state);

        // Best fork (the most-advanced one) for next-step hint.
        let best = forks
            .iter()
            .max_by_key(|(_, f)| {
                (
                    f.has_dispute_acquire as u8,
                    f.has_dispute_yield as u8,
                    f.has_replacement_collateral as u8,
                    f.has_dispute_armed as u8,
                    f.has_dispute_enter as u8,
                )
            });
        let hint = match best {
            Some((_, f)) => next_step_hint(f, reserves_spent, current_block, main.state.quorum_expiry),
            None => {
                if past_expiry {
                    "quorum expired — waiting for auto-arm"
                } else {
                    "in-dispute"
                }
            }
        };

        println!(
            "{:<18} {:<10} {:<11} {:<9} {:<7} {:<7} {:<7} {}",
            &lid[..16],
            state_label,
            expiry_label,
            format!("{}", forks.len()),
            format!("{}", armed),
            format!("{}", with_rc),
            spent_label,
            hint
        );
    }
    if !printed {
        println!("(no ledgers in dispute or past quorum expiry)");
    }
    Ok(())
}

async fn disputes_show(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut positional: Option<String> = None;
    let mut config_args = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with("--") {
            config_args.push(args[i].clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
                i += 1;
            }
        } else if positional.is_none() {
            positional = Some(args[i].clone());
        }
        i += 1;
    }
    let target = positional.ok_or("Usage: deposits-node disputes show <ledger_id|prefix>")?;
    let config = parse_config(&config_args)?;
    let node = Arc::new(Node::new(config).await?);
    let _ = node.sync_wallet();
    let current_block = node.wallet.get_block_height().unwrap_or(0);

    // Resolve target → full ledger_id. Match prefix.
    let snapshot: Vec<(String, deposits_core::ledger::Ledger)> = {
        let ledgers = node.handler.ledgers.lock().unwrap();
        ledgers
            .iter()
            .map(|(k, arc)| (k.clone(), arc.read().unwrap().clone()))
            .collect()
    };
    let main_id = snapshot
        .iter()
        .find_map(|(k, _)| {
            if k.len() == 64 && k.starts_with(&target) {
                Some(k.clone())
            } else {
                None
            }
        })
        .ok_or_else(|| format!("No ledger matches prefix `{}`", target))?;
    let main = snapshot
        .iter()
        .find(|(k, _)| *k == main_id)
        .map(|(_, l)| l.clone())
        .unwrap();

    println!("Ledger:        {}", main_id);
    println!("Dispute state: {:?}", main.state.dispute_state);
    println!("Block tip:     {}", current_block);
    if let Some(exp) = main.state.quorum_expiry {
        let delta = current_block as i64 - exp as i64;
        let label = if delta > 0 {
            format!("EXPIRED +{}", delta)
        } else {
            format!("in {}", -delta)
        };
        println!("Quorum expiry: {} ({})", exp, label);
    } else {
        println!("Quorum expiry: —");
    }
    let reserves_unspent = is_reserves_unspent(&node, &main).await;
    let reserves_spent = reserves_unspent.map(|u| !u);
    match reserves_unspent {
        Some(true) => println!("Reserves UTXO: unspent ({})", main.state.reserves_key),
        Some(false) => println!("Reserves UTXO: SPENT — confiscation TX landed ({})", main.state.reserves_key),
        None => println!("Reserves UTXO: chain query failed ({})", main.state.reserves_key),
    }
    println!();

    // Each fork by disputer. Relay backfill: pull every kind:9100
    // for this ledger and pass into `summarize_fork` so disk-full
    // truncated history (DisputeEnter / DisputeArmed rows gone
    // locally) still surfaces in the output.
    let forks: Vec<(String, deposits_core::ledger::Ledger)> = snapshot
        .into_iter()
        .filter(|(k, _)| k.starts_with(&main_id) && k.len() > 64)
        .collect();
    let relay_extras = fetch_ledger_updates_from_relay(&node, &main_id).await;
    if forks.is_empty() {
        println!("(no fork branches)");
    }
    for (fork_key, fork_ledger) in &forks {
        let s = match summarize_fork(fork_key, fork_ledger, &relay_extras) {
            Some(s) => s,
            None => continue,
        };
        println!("Fork branch:   {}", fork_key);
        println!(
            "  disputer:    {}",
            s.disputer_pubkey
                .map(|pk| hex::encode(pk.serialize()))
                .unwrap_or_else(|| "(none — DisputeEnter not observed)".to_string())
        );
        println!("  fork_seq:    {}", s.last_valid_seq);
        println!("  state:       {:?}", fork_ledger.state.dispute_state);
        println!(
            "  ops:         DisputeEnter={}  QuorumAddMember={}  DisputeArmed={}  Acquire={}  Yield={}",
            yes_no(s.has_dispute_enter),
            s.quorum_member_count,
            yes_no(s.has_dispute_armed),
            yes_no(s.has_dispute_acquire),
            yes_no(s.has_dispute_yield),
        );
        if s.has_dispute_armed {
            if let Some(blk) = s.armed_block {
                println!("  armed_block: {}", blk);
            }
            println!(
                "  collateral:  {}",
                if s.has_replacement_collateral {
                    "declared (Some)"
                } else {
                    "MISSING (None) — fund operator P2WPKH and re-arm"
                }
            );
        }
        if let Some(anchor) = s.anchor_block_height {
            println!("  anchor:      block {}", anchor);
        }
        println!(
            "  next step:   {}",
            next_step_hint(&s, reserves_spent, current_block, main.state.quorum_expiry)
        );
        println!();
    }
    Ok(())
}

fn yes_no(b: bool) -> &'static str {
    if b {
        "yes"
    } else {
        "no"
    }
}

/// Esplora query: is the ledger's reserves UTXO still on the
/// scripthash's unspent list? `Some(true)` if at least one unspent
/// matches the script, `Some(false)` if the script has no unspent
/// outputs (confiscation TX landed). `None` on transport/parse
/// failure — caller should treat as "unknown".
async fn is_reserves_unspent(
    node: &Node,
    ledger: &deposits_core::ledger::Ledger,
) -> Option<bool> {
    let addr_str = &ledger.state.reserves_key;
    let address: bitcoin::Address<bitcoin::address::NetworkUnchecked> = addr_str.parse().ok()?;
    let address = address.require_network(node.wallet.network()).ok()?;
    let script_pubkey = address.script_pubkey();
    match node.wallet.find_utxo_for_script(&script_pubkey) {
        Ok(Some(_)) => Some(true),
        Ok(None) => Some(false),
        Err(_) => None,
    }
}
