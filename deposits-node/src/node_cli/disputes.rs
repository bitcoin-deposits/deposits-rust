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
        eprintln!(
            "  list                   One-line summary of every ledger with dispute activity."
        );
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
    let mut until_ts: Option<u64> = None;
    let mut pages = 0u32;
    let mut stalls = 0u32;

    loop {
        let mut filter = Filter::new()
            .kind(Kind::Custom(crate::nostr::KIND_LEDGER_UPDATE))
            .custom_tag(
                crate::nostr::TAG_LEDGER_ID,
                [crate::nostr::ledger_tag(ledger_id)],
            )
            .limit(PAGE_LIMIT);
        if let Some(ts) = until_ts {
            // Page BACKWARDS: the relay returns newest-first and caps each
            // query below our limit, so lower the ceiling to the oldest event
            // seen and walk toward genesis. The old forward `.since` cursor only
            // ever drained the newest page — a deep fork's early QuorumBegin
            // (needed for lottery-N / recovery-voter derivation) never came back.
            filter = filter.until(Timestamp::from(ts));
        }

        let events = match client.fetch_events(vec![filter], Some(PAGE_TIMEOUT)).await {
            Ok(e) => e,
            Err(_) => break,
        };
        if events.is_empty() {
            break;
        }

        let mut page_min_ts: Option<u64> = None;
        let mut fresh = 0usize;
        for event in events.iter() {
            let ts = event.created_at.as_u64();
            if page_min_ts.is_none() || ts < page_min_ts.unwrap() {
                page_min_ts = Some(ts);
            }
            if let Ok(tlv) = BASE64.decode(&event.content) {
                if let Ok(u) = deposits_core::types::SignedLedgerUpdate::tlv_decode(&tlv) {
                    if seen.insert(u.content_hash) {
                        all_updates.push(u);
                        fresh += 1;
                    }
                }
            }
        }
        pages += 1;
        // Terminate on a stall (a page with no NEW events — the whole chain is
        // walked) or the page cap, never on page size (the relay caps below
        // PAGE_LIMIT, so a short page is normal, not end-of-stream).
        if fresh == 0 {
            stalls += 1;
            if stalls > 3 {
                break;
            }
        } else {
            stalls = 0;
        }
        if pages >= MAX_PAGES {
            break;
        }
        match page_min_ts {
            Some(ts) => until_ts = Some(ts),
            None => break,
        }
    }

    all_updates
}

/// On-chain status of the ledger's reserves address.
#[derive(Debug, Clone, Copy)]
enum ReservesStatus {
    /// Never funded — no txs to the address ever.
    NeverFunded,
    /// Has unspent funds (the live, pre-confiscation state).
    Funded,
    /// Was funded historically but has no unspent outputs left
    /// (the post-confiscation state — input was consumed).
    Confiscated,
    /// Esplora query failed; status unknown.
    Unknown,
}

impl ReservesStatus {
    fn label(&self) -> &'static str {
        match self {
            ReservesStatus::NeverFunded => "never funded (quorum never activated on-chain)",
            ReservesStatus::Funded => "unspent",
            ReservesStatus::Confiscated => "SPENT — confiscation TX landed",
            ReservesStatus::Unknown => "chain query failed",
        }
    }
}

/// "What is the pipeline waiting on next?" derived from a fork
/// summary plus the on-chain reserves-UTXO status.
fn next_step_hint(
    fork: &ForkSummary,
    reserves: ReservesStatus,
    current_block: u32,
    quorum_expiry: Option<u32>,
) -> &'static str {
    if fork.has_dispute_acquire {
        return "won — rotate (recovery rotate-to-quorum)";
    }
    if fork.has_dispute_yield {
        return "yielded — branch tombstoned";
    }
    // DisputeArmed implies DisputeEnter must have been applied
    // (state machine doesn't allow Armed without Disputed first).
    // If we observed Armed but not Enter, the Enter is on-chain
    // but the relay evicted it from history.
    let armed = fork.has_dispute_armed;
    let entered = fork.has_dispute_enter || armed;
    if !entered {
        return "fork created but DisputeEnter missing (auto-arm should retry)";
    }
    if !armed {
        return "DisputeEnter present, waiting for DisputeArmed";
    }
    if !fork.has_replacement_collateral {
        return "armed without replacement_collateral — fund operator P2WPKH then re-arm";
    }
    match reserves {
        ReservesStatus::NeverFunded => {
            "quorum never activated on-chain — no reserves to confiscate; dispute is moot"
        }
        ReservesStatus::Confiscated => "confiscation TX landed — waiting for lottery reveal/claim",
        ReservesStatus::Funded => {
            "armed with collateral — waiting on quorum cosignatures for confiscation TX"
        }
        ReservesStatus::Unknown => match quorum_expiry {
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
    let mut fork_keys: std::collections::BTreeMap<
        String,
        Vec<(String, deposits_core::ledger::Ledger)>,
    > = std::collections::BTreeMap::new();
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
    let mut relay_updates: std::collections::HashMap<
        String,
        Vec<deposits_core::types::SignedLedgerUpdate>,
    > = std::collections::HashMap::new();
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

        let reserves = reserves_status(&node, main).await;
        let spent_label = match reserves {
            ReservesStatus::NeverFunded => "none",
            ReservesStatus::Funded => "no",
            ReservesStatus::Confiscated => "yes",
            ReservesStatus::Unknown => "?",
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
        let best = forks.iter().max_by_key(|(_, f)| {
            (
                f.has_dispute_acquire as u8,
                f.has_dispute_yield as u8,
                f.has_replacement_collateral as u8,
                f.has_dispute_armed as u8,
                f.has_dispute_enter as u8,
            )
        });
        let hint = match best {
            Some((_, f)) => next_step_hint(f, reserves, current_block, main.state.quorum_expiry),
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
    let reserves = reserves_status(&node, &main).await;
    println!(
        "Reserves UTXO: {} ({})",
        reserves.label(),
        main.state.reserves_key
    );
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
            next_step_hint(&s, reserves, current_block, main.state.quorum_expiry)
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

/// Esplora query for the ledger's reserves address — distinguishes
/// "never funded" (quorum never activated on-chain) from "funded
/// then spent" (confiscation TX landed). `find_utxo_for_script`
/// alone can't tell those apart since both return an empty UTXO
/// list. We instead read the address's chain_stats from Esplora's
/// `/scripthash/<hash>` endpoint, which carries `funded_txo_count`
/// and `spent_txo_count` separately.
async fn reserves_status(node: &Node, ledger: &deposits_core::ledger::Ledger) -> ReservesStatus {
    use bitcoin::hashes::{sha256, Hash};

    let addr_str = &ledger.state.reserves_key;
    let address: bitcoin::Address<bitcoin::address::NetworkUnchecked> = match addr_str.parse() {
        Ok(a) => a,
        Err(_) => return ReservesStatus::Unknown,
    };
    let address = match address.require_network(node.wallet.network()) {
        Ok(a) => a,
        Err(_) => return ReservesStatus::Unknown,
    };
    let script_hash = sha256::Hash::hash(address.script_pubkey().as_bytes());
    let url = format!(
        "{}/scripthash/{}",
        node.wallet.electrum_url(),
        hex::encode(script_hash.to_byte_array())
    );
    let resp = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map(|c| c.get(&url).send())
    {
        Ok(fut) => match fut.await {
            Ok(r) => r,
            Err(_) => return ReservesStatus::Unknown,
        },
        Err(_) => return ReservesStatus::Unknown,
    };
    if !resp.status().is_success() {
        return ReservesStatus::Unknown;
    }
    let stats: serde_json::Value = match resp.json().await {
        Ok(v) => v,
        Err(_) => return ReservesStatus::Unknown,
    };
    let funded = stats
        .get("chain_stats")
        .and_then(|c| c.get("funded_txo_count"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let spent = stats
        .get("chain_stats")
        .and_then(|c| c.get("spent_txo_count"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    if funded == 0 {
        ReservesStatus::NeverFunded
    } else if spent >= funded {
        ReservesStatus::Confiscated
    } else {
        ReservesStatus::Funded
    }
}
