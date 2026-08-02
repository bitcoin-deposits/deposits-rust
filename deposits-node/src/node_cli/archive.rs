// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! `deposits-node archive` — a semi-trusted archivist.
//!
//! ## What it is
//!
//! A read-only process that runs adjacent to a web-of-trust trust anchor. It
//! connects to Nostr relay(s), keeps a durable, COMPLETE, VALIDATED copy of
//! every quorum's ledger (normal updates AND disputes), and backfills relays
//! that lost history (e.g. a relay DB reset). It gives the network an
//! independent durable source of ledger history beyond the quorum members.
//!
//! ## Trust model — semi-trusted, can withhold but cannot forge
//!
//! The archivist NEVER signs, cosigns, or authors ledger content. It only:
//!   1. reads events off the relay,
//!   2. VALIDATES them with the SAME gate the daemon uses to accept an update
//!      ([`deposits_core::types::LedgerState::apply_signed`] — operator BIP-340
//!      signature + quorum cosignatures at the DEP-05 threshold, tracked from
//!      the ledger's own `QuorumBegin` chain as the fold progresses + hash-chain
//!      continuity + sequence + content-hash integrity + state-machine
//!      conformance),
//!   3. stores accepted data append-only, and
//!   4. re-broadcasts already-quorum-signed events a relay is missing.
//!
//! Because it re-wraps the SAME [`SignedLedgerUpdate`] bytes (which carry the
//! operator's signature and the quorum's cosignatures), a compromised archivist
//! can withhold history but can never mint a ledger state the quorum didn't
//! sign. Forged / uncosigned / bad-chain events are DROPPED and counted.
//!
//! ## Reuse (no hand-rolled crypto)
//!
//! | concern                    | reused from                                            |
//! |----------------------------|--------------------------------------------------------|
//! | paginated relay fetch      | mirrors `Node::fetch_all_ledger_updates_paginated`     |
//! |                            | + shared `plan_reimport_page` loop-control             |
//! | accept/reject (cosig+chain)| `LedgerState::apply_signed` (the daemon's accept gate) |
//! | fraud-proof verify         | `deposits_core::fraud::verify_fraud_broadcast`         |
//! | fork best-chain split      | mirrors the `main_loop.rs` `by_prev` best-chain walk   |
//! | JSONL persistence          | `DepositsHandler::archive_append_updates_at` (writes   |
//! |                            | the same `LedgerLogRow::Update` rows the daemon does)  |
//! | archive-vs-relay diff      | `heal::missing_updates`                                |
//! | fork tracking key          | `DepositsHandler::fork_tracking_key`                   |

use crate::handler::DepositsHandler;
use crate::node::heal::missing_updates;
use crate::node::main_loop::{plan_reimport_page, ReimportPage};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use bitcoin::secp256k1::PublicKey;
use deposits_core::dep16::Dep16Authorizer;
use deposits_core::fraud::{BlockOracle, FraudBroadcast, LedgerProvider};
use deposits_core::messages::LedgerOperation;
use deposits_core::tlv::TlvDecode;
use deposits_core::types::{LedgerState, SignedLedgerUpdate};
use deposits_nostr::{
    ledger_tag, NostrTransport, KIND_FRAUD_PROOF, KIND_LEDGER_UPDATE, TAG_LEDGER_ID,
};
use nostr_sdk::{Filter, Kind, Timestamp};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::Duration;

/// Per-page relay fetch cap (mirrors `Node::RELAY_FETCH_PAGE_LIMIT`).
const FETCH_PAGE_LIMIT: usize = 5000;
/// Max pages walked backward per fetch (mirrors `Node::RELAY_FETCH_MAX_PAGES`).
const FETCH_MAX_PAGES: u32 = 50;
/// Per-ledger re-publish cap per backfill pass (mirrors `heal::HEAL_BATCH_LIMIT`).
const BACKFILL_BATCH_LIMIT: usize = 500;
/// Throttle between backfill re-publishes so we don't storm the relay
/// (matches the daemon healer's 20ms inter-publish sleep).
const BACKFILL_THROTTLE: Duration = Duration::from_millis(20);
/// Long-lived loop interval between sync passes.
const SYNC_INTERVAL: Duration = Duration::from_secs(30);

// ============================================================================
// Accept / reject decision — the pure validator
// ============================================================================

/// Outcome of validating a candidate chain for one ledger (or fork branch).
#[derive(Debug, Clone)]
pub struct ChainValidation {
    /// The prefix of the input chain that validated cleanly from genesis
    /// (seq 0, empty quorum) up to the first failure (or the whole chain).
    /// This is exactly what gets archived — always a genesis-rooted prefix,
    /// never a floating tail.
    pub accepted: Vec<SignedLedgerUpdate>,
    /// Human-readable reason the chain stopped validating, if it did. `None`
    /// means the entire input chain was accepted.
    pub stopped_reason: Option<String>,
}

impl ChainValidation {
    /// Number of updates that failed validation (were dropped).
    pub fn dropped(&self, input_len: usize) -> usize {
        input_len.saturating_sub(self.accepted.len())
    }
}

/// The archivist's accept/reject decision, as a PURE function over
/// (candidate chain) — no relay, no I/O, no `Node`. This is what the unit
/// tests exercise, and it is a thin driver over `LedgerState::apply_signed`,
/// the SAME gate the daemon runs before it accepts an update.
///
/// Rules (kept):
///   - the chain must start at seq 0 with a `LedgerOpen` and link
///     `previous_hash → chain_hash()` with contiguous sequence numbers;
///   - each update's `content_hash` must equal `compute_hash()`;
///   - each update's operator BIP-340 signature must verify;
///   - once a `QuorumBegin` establishes the active quorum, every subsequent
///     update must carry quorum cosignatures meeting the DEP-05 threshold
///     (the quorum set + threshold are folded from the chain itself, so the
///     archivist trusts no externally-supplied quorum);
///   - each op must pass the state-machine + conformance verifier.
///
/// Rules (dropped): anything that fails ANY of the above — a bad hash chain,
/// a missing/forged operator signature, insufficient/forged cosignatures, an
/// out-of-sequence or non-conforming op. On the FIRST failure we stop and
/// return the validated genesis-rooted prefix; the rest is dropped.
///
/// `chain` may be in any order; it is sorted by `(sequence_number,
/// content_hash)` first so the caller can pass a raw relay dump. Duplicate
/// `content_hash`es are removed.
pub fn validate_ledger_chain(chain: &[SignedLedgerUpdate]) -> ChainValidation {
    // De-dup by content_hash and order by sequence so the fold sees a clean
    // oldest-first candidate. Fork siblings share a sequence_number but differ
    // in content_hash; `apply_signed`'s previous_hash check picks exactly one
    // continuation, so a well-formed main chain folds and the alternates are
    // rejected at their divergence point (the caller splits forks out first).
    let mut ordered: Vec<SignedLedgerUpdate> = {
        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        let mut v: Vec<SignedLedgerUpdate> = Vec::new();
        for u in chain {
            if seen.insert(u.content_hash) {
                v.push(u.clone());
            }
        }
        v
    };
    ordered.sort_by(|a, b| {
        a.sequence_number
            .cmp(&b.sequence_number)
            .then(a.content_hash.cmp(&b.content_hash))
    });

    let authorizer = Dep16Authorizer::new();
    let mut accepted: Vec<SignedLedgerUpdate> = Vec::new();

    // Seed an empty genesis state. `apply_signed`'s genesis branch requires
    // `chain_tip_hash == [0;32] && sequence == 0`, which `LedgerState::new`
    // gives; the seq-0 `LedgerOpen` then overwrites operator/reserves/genesis
    // as it applies, so the seed's placeholder fields don't matter.
    let seed_op = ordered
        .first()
        .and_then(|u| LedgerOperation::tlv_decode(&u.message).ok());
    let Some(first) = ordered.first() else {
        return ChainValidation {
            accepted,
            stopped_reason: Some("empty chain".to_string()),
        };
    };
    let (seed_operator, seed_reserves, seed_genesis) = match seed_op {
        Some(LedgerOperation::LedgerOpen {
            operator_id,
            reserves_id,
            genesis_block,
            ..
        }) => (operator_id, reserves_id, genesis_block),
        _ => {
            return ChainValidation {
                accepted,
                stopped_reason: Some(format!(
                    "chain does not start with a seq-0 LedgerOpen (first seq={})",
                    first.sequence_number
                )),
            };
        }
    };

    let mut state = LedgerState::new(seed_operator, seed_reserves, seed_genesis);

    for update in &ordered {
        match state.apply_signed(update, &authorizer) {
            Ok(next) => {
                state = next;
                accepted.push(update.clone());
            }
            Err(e) => {
                return ChainValidation {
                    accepted,
                    stopped_reason: Some(format!(
                        "rejected at seq {}: {}",
                        update.sequence_number, e
                    )),
                };
            }
        }
    }

    ChainValidation {
        accepted,
        stopped_reason: None,
    }
}

// ============================================================================
// Fork-branch splitting
// ============================================================================

/// A ledger's relay dump split into its canonical main chain and any
/// dispute fork branches, each keyed for its own JSONL file.
#[derive(Debug, Default)]
pub struct SplitChains {
    /// The best (canonical) chain from genesis, before validation.
    pub main: Vec<SignedLedgerUpdate>,
    /// Fork branches: `(fork_tracking_key, branch_updates)`. The branch
    /// updates are the divergent tail (from the first update whose
    /// `previous_hash` was already consumed by the main chain, onward).
    pub forks: Vec<(String, Vec<SignedLedgerUpdate>)>,
}

/// Split a raw per-ledger relay dump into a canonical main chain plus fork
/// branches — mirroring the `main_loop.rs` best-chain walk (`by_prev` keyed on
/// `chain_hash()`, preferring a branch carrying `DisputeAcquire`, else the
/// longest). Everything not on the chosen main chain is grouped into fork
/// branches by their divergence point + authoring operator, keyed with
/// [`DepositsHandler::fork_tracking_key`] exactly like the daemon.
pub fn split_main_and_forks(ledger_id: &str, updates: &[SignedLedgerUpdate]) -> SplitChains {
    // Index children by the parent link (previous_hash == parent.chain_hash()).
    let mut by_prev: HashMap<[u8; 32], Vec<&SignedLedgerUpdate>> = HashMap::new();
    for u in updates {
        by_prev.entry(u.previous_hash).or_default().push(u);
    }

    let branch_is_acquire = |u: &SignedLedgerUpdate| {
        LedgerOperation::tlv_decode(&u.message)
            .map(|op| matches!(op, LedgerOperation::DisputeAcquire { .. }))
            .unwrap_or(false)
    };

    // Walk from genesis (cursor [0;32]); at a fork prefer the DisputeAcquire
    // branch, else the deepest. Identical selection to the daemon's importer.
    let mut main: Vec<SignedLedgerUpdate> = Vec::new();
    let mut on_main: HashSet<[u8; 32]> = HashSet::new();
    let mut cursor = [0u8; 32];
    while let Some(children) = by_prev.get(&cursor) {
        let next = if let [single] = children.as_slice() {
            *single
        } else {
            let mut best: Option<&SignedLedgerUpdate> = None;
            let mut best_acquire = false;
            let mut best_depth = 0usize;
            for &child in children {
                let mut has_acquire = branch_is_acquire(child);
                let mut depth = 1usize;
                let mut h = child.chain_hash();
                while let Some(nc) = by_prev.get(&h) {
                    if let Some(f) = nc.first() {
                        if branch_is_acquire(f) {
                            has_acquire = true;
                        }
                        h = f.chain_hash();
                        depth += 1;
                    } else {
                        break;
                    }
                }
                let better = best.is_none()
                    || (has_acquire && !best_acquire)
                    || (has_acquire == best_acquire && depth > best_depth);
                if better {
                    best = Some(child);
                    best_acquire = has_acquire;
                    best_depth = depth;
                }
            }
            // `children` is never empty (entries are created via push), so at a
            // real fork `best` is always Some; break defensively otherwise.
            match best {
                Some(c) => c,
                None => break,
            }
        };
        on_main.insert(next.content_hash);
        cursor = next.chain_hash();
        main.push(next.clone());
    }

    // Everything not on the main chain is a fork-branch update. Group each by
    // (fork sequence, authoring operator) using the same compound key the
    // daemon stores forks under.
    let mut fork_map: HashMap<String, Vec<SignedLedgerUpdate>> = HashMap::new();
    for u in updates {
        if on_main.contains(&u.content_hash) {
            continue;
        }
        let key = DepositsHandler::fork_tracking_key(ledger_id, u.sequence_number, &u.operator_id);
        fork_map.entry(key).or_default().push(u.clone());
    }
    let mut forks: Vec<(String, Vec<SignedLedgerUpdate>)> = fork_map.into_iter().collect();
    forks.sort_by(|a, b| a.0.cmp(&b.0));
    for (_, branch) in forks.iter_mut() {
        branch.sort_by_key(|u| u.sequence_number);
    }

    SplitChains { main, forks }
}

// ============================================================================
// Fraud-proof verification (reuse the protocol verifier)
// ============================================================================

/// Back the protocol fraud verifier's `LedgerProvider` with the archive's own
/// validated in-memory chains — so a fraud proof only verifies if the ledgers
/// it references are ones the archivist has already accepted (validated) from
/// the relay. A relay can't hand us a proof that references a fabricated
/// history: the referenced history must itself be quorum-signed & archived.
struct ArchiveLedgers<'a> {
    chains: &'a HashMap<String, Vec<SignedLedgerUpdate>>,
}
impl<'a> LedgerProvider for ArchiveLedgers<'a> {
    fn ledger_history(&self, ledger_id: &str) -> Option<Vec<SignedLedgerUpdate>> {
        self.chains.get(ledger_id).cloned()
    }
}

/// Fail-closed block oracle: the archivist has no chain access, so it returns
/// `None` for every block. Fraud types that need on-chain confirmation (e.g.
/// `WinnerCollateralDeviation`) therefore fail closed and are dropped — but the
/// self-contained proofs (Equivocation, StaleCosignature, …) verify from the
/// proof + archived histories alone, matching the daemon's pure verifier path.
struct NoChainOracle;
impl BlockOracle for NoChainOracle {
    fn confirms(&self, _hash: &[u8; 32]) -> Option<u32> {
        None
    }
}

/// Verify a fraud broadcast against the archive's validated chains using the
/// SAME `verify_fraud_broadcast` the daemon runs. Returns `Ok(())` only if the
/// proof is structurally sound, embedded in a validated ledger, its causal
/// chain present, and its per-type evidence checks out.
pub fn verify_archived_fraud(
    broadcast: &FraudBroadcast,
    chains: &HashMap<String, Vec<SignedLedgerUpdate>>,
) -> Result<(), String> {
    let provider = ArchiveLedgers { chains };
    let oracle = NoChainOracle;
    deposits_core::fraud::verify_fraud_broadcast(broadcast, &provider, &oracle)
}

// ============================================================================
// Relay fetch (standalone — no Node)
// ============================================================================

/// Fetch every kind:9100 event on the relay, paginating `created_at` backward
/// until exhaustion, and return the decoded [`SignedLedgerUpdate`]s deduped by
/// `content_hash`. With `ledger_id = Some(id)` the query is `#d`-filtered to one
/// ledger (matches `Node::fetch_all_ledger_updates_paginated`); with `None` it
/// pulls ALL ledgers so the archivist can discover every quorum without an
/// author allow-list.
async fn fetch_updates_paginated(
    transport: &NostrTransport,
    ledger_id: Option<&str>,
) -> Vec<SignedLedgerUpdate> {
    let client = transport.fetch_client();
    let mut all: Vec<SignedLedgerUpdate> = Vec::new();
    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    let mut until_ts: Option<u64> = None;
    let mut pages = 0u32;
    let mut stalls = 0u32;

    loop {
        let mut filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_UPDATE))
            .limit(FETCH_PAGE_LIMIT);
        if let Some(id) = ledger_id {
            filter = filter.custom_tag(TAG_LEDGER_ID, [ledger_tag(id)]);
        }
        if let Some(ts) = until_ts {
            filter = filter.until(Timestamp::from(ts));
        }

        let events = match client
            .fetch_events(vec![filter], Some(Duration::from_secs(15)))
            .await
        {
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
            if page_min_ts.map(|m| ts < m).unwrap_or(true) {
                page_min_ts = Some(ts);
            }
            if let Ok(tlv) = BASE64.decode(&event.content) {
                if let Ok(u) = SignedLedgerUpdate::tlv_decode(&tlv) {
                    if seen.insert(u.content_hash) {
                        all.push(u);
                        fresh += 1;
                    }
                }
            }
        }
        pages += 1;
        match plan_reimport_page(fresh, page_min_ts, pages, FETCH_MAX_PAGES, &mut stalls) {
            ReimportPage::Stop => break,
            ReimportPage::Continue { until_ts: next } => until_ts = Some(next),
        }
        tokio::task::yield_now().await;
    }
    all
}

/// Fetch every kind:9101 fraud-proof event on the relay, single page (fraud
/// proofs are rare), and decode the `FraudBroadcast` bodies.
async fn fetch_fraud_broadcasts(transport: &NostrTransport) -> Vec<FraudBroadcast> {
    let client = transport.fetch_client();
    let filter = Filter::new()
        .kind(Kind::Custom(KIND_FRAUD_PROOF))
        .limit(FETCH_PAGE_LIMIT);
    let events = match client
        .fetch_events(vec![filter], Some(Duration::from_secs(15)))
        .await
    {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for event in events.iter() {
        if let Ok(b) = serde_json::from_str::<FraudBroadcast>(&event.content) {
            let h = hex::encode(b.proof.proof_hash());
            if seen.insert(h) {
                out.push(b);
            }
        }
    }
    out
}

// ============================================================================
// One sync pass
// ============================================================================

/// Counters for a single archive sync pass, logged at the end.
#[derive(Debug, Default)]
struct PassStats {
    ledgers_seen: usize,
    updates_archived: usize,
    updates_dropped: usize,
    forks_archived: usize,
    fraud_archived: usize,
    fraud_dropped: usize,
    backfilled: usize,
}

/// Run one full sync pass: discover all ledgers, fetch+validate+persist each
/// (main chain + fork branches), verify+persist fraud proofs, and backfill the
/// relay with anything it's missing. Returns the pass stats.
async fn sync_pass(transport: &NostrTransport, archive_dir: &PathBuf, backfill: bool) -> PassStats {
    let mut stats = PassStats::default();

    // 1. Discover every ledger from a single all-ledgers 9100 pull.
    let all_updates = fetch_updates_paginated(transport, None).await;
    let ledger_ids: HashSet<String> = all_updates.iter().map(|u| u.ledger_id_hex()).collect();
    stats.ledgers_seen = ledger_ids.len();
    tracing::info!(
        "archive: discovered {} ledger(s) on relay",
        ledger_ids.len()
    );

    // Group the bulk pull by ledger so we usually avoid a second per-ledger
    // fetch. For deep ledgers a targeted re-fetch fills any gap the bulk
    // pagination missed.
    let mut by_ledger: HashMap<String, Vec<SignedLedgerUpdate>> = HashMap::new();
    for u in &all_updates {
        by_ledger
            .entry(u.ledger_id_hex())
            .or_default()
            .push(u.clone());
    }

    // Accumulate validated main chains for the fraud verifier's provider.
    let mut validated_chains: HashMap<String, Vec<SignedLedgerUpdate>> = HashMap::new();

    for ledger_id in &ledger_ids {
        // Prefer the per-ledger paginated fetch (matches the daemon's healer)
        // so a deep chain comes back whole; fall back to the bulk slice.
        let mut raw = fetch_updates_paginated(transport, Some(ledger_id)).await;
        if raw.is_empty() {
            raw = by_ledger.get(ledger_id).cloned().unwrap_or_default();
        }
        if raw.is_empty() {
            continue;
        }

        let split = split_main_and_forks(ledger_id, &raw);

        // --- Main chain ---
        let main_result = validate_ledger_chain(&split.main);
        let dropped = main_result.dropped(split.main.len());
        if dropped > 0 {
            tracing::warn!(
                "archive: ledger {}… dropped {} update(s) from main chain: {}",
                &ledger_id[..16.min(ledger_id.len())],
                dropped,
                main_result.stopped_reason.as_deref().unwrap_or("?"),
            );
        }
        stats.updates_dropped += dropped;
        if !main_result.accepted.is_empty() {
            match DepositsHandler::archive_append_updates_at(
                archive_dir,
                ledger_id,
                &main_result.accepted,
            ) {
                Ok(n) => {
                    stats.updates_archived += n;
                    if n > 0 {
                        tracing::info!(
                            "archive: ledger {}… archived {} new update(s) (chain len {})",
                            &ledger_id[..16.min(ledger_id.len())],
                            n,
                            main_result.accepted.len(),
                        );
                    }
                }
                Err(e) => tracing::error!(
                    "archive: failed to persist ledger {}: {}",
                    &ledger_id[..16.min(ledger_id.len())],
                    e
                ),
            }
            validated_chains.insert(ledger_id.clone(), main_result.accepted.clone());
        }

        // --- Fork branches (disputes) ---
        // A fork branch is validated by prepending the shared main-chain prefix
        // up to its divergence point, so `apply_signed` folds it from genesis
        // with the correct quorum. Only the divergent updates are archived to
        // the fork's own file.
        for (fork_key, branch) in &split.forks {
            let fork_seq = branch.iter().map(|u| u.sequence_number).min().unwrap_or(0);
            let prefix: Vec<SignedLedgerUpdate> = main_result
                .accepted
                .iter()
                .filter(|u| u.sequence_number < fork_seq)
                .cloned()
                .collect();
            let mut candidate = prefix;
            candidate.extend(branch.iter().cloned());

            let fork_result = validate_ledger_chain(&candidate);
            // Keep only the divergent (fork-owned) accepted updates.
            let fork_accepted: Vec<SignedLedgerUpdate> = fork_result
                .accepted
                .into_iter()
                .filter(|u| u.sequence_number >= fork_seq)
                .collect();
            let fdrop = branch.len().saturating_sub(fork_accepted.len());
            stats.updates_dropped += fdrop;
            if fdrop > 0 {
                tracing::warn!(
                    "archive: fork {}… dropped {} update(s): {}",
                    &fork_key[..24.min(fork_key.len())],
                    fdrop,
                    fork_result.stopped_reason.as_deref().unwrap_or("?"),
                );
            }
            if !fork_accepted.is_empty() {
                match DepositsHandler::archive_append_updates_at(
                    archive_dir,
                    fork_key,
                    &fork_accepted,
                ) {
                    Ok(n) if n > 0 => {
                        stats.forks_archived += 1;
                        tracing::info!(
                            "archive: fork {}… archived {} dispute update(s)",
                            &fork_key[..24.min(fork_key.len())],
                            n
                        );
                    }
                    Ok(_) => {}
                    Err(e) => {
                        tracing::error!("archive: failed to persist fork {}: {}", fork_key, e)
                    }
                }
            }
        }
    }

    // 2. Fraud proofs (kind 9101) — verify against the validated chains.
    let broadcasts = fetch_fraud_broadcasts(transport).await;
    for b in &broadcasts {
        match verify_archived_fraud(b, &validated_chains) {
            Ok(()) => {
                if persist_fraud_proof(archive_dir, b) {
                    stats.fraud_archived += 1;
                    tracing::info!(
                        "archive: kept fraud proof {:?} on ledger {}…",
                        b.proof.proof_type,
                        &b.proof.ledger_id[..16.min(b.proof.ledger_id.len())],
                    );
                }
            }
            Err(e) => {
                stats.fraud_dropped += 1;
                tracing::warn!(
                    "archive: dropped unverifiable fraud proof {:?}: {}",
                    b.proof.proof_type,
                    e
                );
            }
        }
    }

    // 3. Backfill: re-publish anything the relay is missing vs the archive.
    if backfill {
        stats.backfilled = backfill_relay(transport, archive_dir, &ledger_ids).await;
    }

    tracing::info!(
        "archive: pass complete — {} ledger(s), {} update(s) archived, {} dropped, \
         {} fork branch(es), {} fraud kept / {} dropped, {} update(s) backfilled",
        stats.ledgers_seen,
        stats.updates_archived,
        stats.updates_dropped,
        stats.forks_archived,
        stats.fraud_archived,
        stats.fraud_dropped,
        stats.backfilled,
    );
    stats
}

/// Persist a verified fraud broadcast to `{archive-dir}/fraud/{proof_hash}.json`,
/// append-only (never overwritten). Returns true if newly written.
fn persist_fraud_proof(archive_dir: &PathBuf, b: &FraudBroadcast) -> bool {
    let dir = archive_dir.join("fraud");
    if std::fs::create_dir_all(&dir).is_err() {
        return false;
    }
    let path = dir.join(format!("{}.json", hex::encode(b.proof.proof_hash())));
    if path.exists() {
        return false;
    }
    match serde_json::to_string_pretty(b) {
        Ok(json) => std::fs::write(&path, json).is_ok(),
        Err(_) => false,
    }
}

/// Backfill the relay: for each archived ledger (and fork branch) diff the
/// relay's current set against the FULL archived chain and re-publish anything
/// missing, oldest-first, batched + throttled. Reuses `heal::missing_updates`
/// and the 9100 publish path. Returns the number of updates re-published.
async fn backfill_relay(
    transport: &NostrTransport,
    archive_dir: &PathBuf,
    ledger_ids: &HashSet<String>,
) -> usize {
    // Include fork-branch files (compound keys) alongside base ledger ids.
    let mut keys: HashSet<String> = ledger_ids.clone();
    if let Ok(entries) = std::fs::read_dir(archive_dir.join("ledgers")) {
        for e in entries.flatten() {
            if e.path().extension().and_then(|s| s.to_str()) == Some("jsonl") {
                if let Some(stem) = e.path().file_stem().and_then(|s| s.to_str()) {
                    keys.insert(stem.to_string());
                }
            }
        }
    }

    let mut total = 0usize;
    for key in keys {
        let archived = match DepositsHandler::read_persisted_history_at(archive_dir, &key) {
            Some(h) if !h.is_empty() => h,
            _ => continue,
        };
        // What does the relay hold for this (base or fork) ledger right now?
        // Fork branches carry the base ledger's `#d` tag, so query by the base
        // ledger id (the 64-hex prefix of the key).
        let base_id = &key[..64.min(key.len())];
        let relay_updates = fetch_updates_paginated(transport, Some(base_id)).await;
        let relay_present: HashSet<[u8; 32]> =
            relay_updates.iter().map(|u| u.content_hash).collect();

        let to_publish: Vec<SignedLedgerUpdate> =
            missing_updates(&relay_present, &archived, BACKFILL_BATCH_LIMIT)
                .into_iter()
                .cloned()
                .collect();
        if to_publish.is_empty() {
            continue;
        }
        tracing::info!(
            "archive: backfilling {}… — relay holds {} of {} archived update(s), re-publishing {}",
            &key[..24.min(key.len())],
            relay_present.len(),
            archived.len(),
            to_publish.len(),
        );
        for update in &to_publish {
            // Re-wrap the SAME already-quorum-signed SignedLedgerUpdate with a
            // fresh created_at (None) — no new consensus, no new signatures.
            match transport.broadcast_ledger_update_at(update, None).await {
                Ok(_) => {
                    total += 1;
                    tokio::time::sleep(BACKFILL_THROTTLE).await;
                }
                Err(e) => tracing::warn!(
                    "archive: backfill re-publish of {}… seq={} failed: {}",
                    &key[..16.min(key.len())],
                    update.sequence_number,
                    e
                ),
            }
        }
    }
    total
}

// ============================================================================
// CLI entry point
// ============================================================================

struct ArchiveArgs {
    relays: Vec<String>,
    archive_dir: PathBuf,
    once: bool,
}

fn parse_args(args: &[String]) -> Result<ArchiveArgs, String> {
    let mut relays: Vec<String> = Vec::new();
    let mut archive_dir: Option<PathBuf> = None;
    let mut once = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--relay" => {
                i += 1;
                let url = args.get(i).ok_or("--relay needs a value")?;
                relays.push(url.clone());
            }
            "--archive-dir" => {
                i += 1;
                archive_dir = Some(PathBuf::from(
                    args.get(i).ok_or("--archive-dir needs a value")?,
                ));
            }
            // --network is accepted for symmetry with other subcommands and to
            // pin the operator's mental model; the archivist validates purely
            // from chain data (no on-chain access), so it doesn't branch on it.
            "--network" => {
                i += 1;
                let _ = args.get(i).ok_or("--network needs a value")?;
            }
            "--once" => once = true,
            other => return Err(format!("unknown argument: {}", other)),
        }
        i += 1;
    }

    if relays.is_empty() {
        return Err("at least one --relay <url> is required".to_string());
    }
    let archive_dir = archive_dir.ok_or("--archive-dir <path> is required")?;
    Ok(ArchiveArgs {
        relays,
        archive_dir,
        once,
    })
}

/// `deposits-node archive` — see module docs.
pub async fn archive_command(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let parsed = match parse_args(args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error: {}", e);
            eprintln!();
            eprintln!("Usage:");
            eprintln!(
                "  deposits-node archive --relay <url> [--relay <url>...] \\
                     --archive-dir <path> [--network <net>] [--once]"
            );
            eprintln!();
            eprintln!("A semi-trusted archivist: keeps a durable, VALIDATED copy of every");
            eprintln!("quorum's ledger (updates + disputes + fraud proofs) and backfills");
            eprintln!("relays that lost history. Never signs — only reads, validates, stores,");
            eprintln!("and re-broadcasts already-quorum-signed events.");
            return Ok(());
        }
    };

    std::fs::create_dir_all(parsed.archive_dir.join("ledgers"))?;

    // Read-only: a throwaway Nostr key. The archivist authors NO ledger content;
    // re-broadcasts re-wrap the operator's already-signed SignedLedgerUpdate
    // bytes, so this key only signs the outer Nostr event envelope (which any
    // relay accepts) — it never touches consensus.
    let throwaway = bitcoin::secp256k1::SecretKey::new(&mut bitcoin::secp256k1::rand::thread_rng());
    let transport = NostrTransport::new(throwaway, parsed.relays.clone())
        .await
        .map_err(|e| format!("connect to relay(s): {}", e))?;

    tracing::info!(
        "archive: starting ({} relay(s), archive-dir {}, mode {})",
        parsed.relays.len(),
        parsed.archive_dir.display(),
        if parsed.once { "once" } else { "long-lived" },
    );

    if parsed.once {
        sync_pass(&transport, &parsed.archive_dir, true).await;
        return Ok(());
    }

    // Long-lived: periodic sync + backfill. A tick both ingests new history and
    // heals the relay, so a relay reset self-repairs within one interval.
    loop {
        sync_pass(&transport, &parsed.archive_dir, true).await;
        tokio::time::sleep(SYNC_INTERVAL).await;
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
    use deposits_core::tlv::TlvEncode;

    // --- helpers to mint a small, correctly-signed ledger chain ---------------

    fn kp(byte: u8) -> (SecretKey, PublicKey) {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[byte; 32]).unwrap();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        (sk, pk)
    }

    /// Operator-sign an update in place (v1 tagged digest, matching the daemon).
    fn operator_sign(update: &mut SignedLedgerUpdate, sk: &SecretKey) {
        let secp = Secp256k1::new();
        let digest = update.operator_sign_digest_v1();
        let kp = Keypair::from_secret_key(&secp, sk);
        let msg = bitcoin::secp256k1::Message::from_digest(digest);
        let sig = secp.sign_schnorr_no_aux_rand(&msg, &kp);
        update.operator_signature = sig.serialize();
    }

    /// Build a genesis (seq-0) LedgerOpen update, operator-signed.
    fn genesis(operator_sk: &SecretKey, operator: &PublicKey) -> SignedLedgerUpdate {
        let op = LedgerOperation::LedgerOpen {
            operator_id: *operator,
            reserves_id: "bcrt1qtestreserves".to_string(),
            genesis_block: 100,
            reserves_amount: 1_000_000_000,
            collateral_amount: 0,
        };
        let message = op.tlv_encode();
        let mut u = SignedLedgerUpdate {
            message,
            message_type: 0x0001,
            operator_id: *operator,
            ledger_id: LedgerState::compute_ledger_id(operator, "bcrt1qtestreserves", 100),
            sequence_number: 0,
            previous_hash: [0u8; 32],
            content_hash: [0u8; 32],
            block_height: 100,
            block_hash: [0u8; 32],
            cosign_signature: [0u8; 64],
            operator_signature: [0u8; 64],
            cosigner_pubkey: None,
            member_ledger_hash: None,
            cosignatures: Vec::new(),
        };
        u.content_hash = u.compute_hash();
        operator_sign(&mut u, operator_sk);
        u
    }

    #[test]
    fn accepts_a_valid_genesis_and_rejects_a_forged_tail() {
        let (op_sk, op_pk) = kp(1);
        let g = genesis(&op_sk, &op_pk);

        // A valid single-update (genesis-only) chain is accepted whole.
        let res = validate_ledger_chain(std::slice::from_ref(&g));
        assert_eq!(res.accepted.len(), 1, "genesis LedgerOpen should validate");
        assert!(res.stopped_reason.is_none());

        // Forge a seq-1 update: valid tags, but its operator_signature is
        // garbage (not signed by anyone). It must be DROPPED — the genesis
        // prefix stays, the forged tail is rejected.
        let mut forged = g.clone();
        forged.sequence_number = 1;
        forged.previous_hash = g.chain_hash();
        forged.operator_signature = [0x7u8; 64]; // not a valid signature
        forged.content_hash = forged.compute_hash();

        let res = validate_ledger_chain(&[g.clone(), forged]);
        assert_eq!(res.accepted.len(), 1, "forged tail must be dropped");
        assert!(
            res.stopped_reason.unwrap().contains("seq 1"),
            "stop reason should name the rejected seq"
        );
    }

    #[test]
    fn rejects_a_chain_that_does_not_start_at_genesis() {
        let (op_sk, op_pk) = kp(2);
        let mut g = genesis(&op_sk, &op_pk);
        // Claim seq 5 with a non-zero previous_hash — no LedgerOpen at seq 0.
        g.sequence_number = 5;
        g.previous_hash = [9u8; 32];
        g.content_hash = g.compute_hash();
        operator_sign(&mut g, &op_sk);

        let res = validate_ledger_chain(&[g]);
        assert!(
            res.accepted.is_empty(),
            "a floating tail must not be archived"
        );
        assert!(res.stopped_reason.is_some());
    }

    #[test]
    fn rejects_a_hash_chain_break() {
        let (op_sk, op_pk) = kp(3);
        let g = genesis(&op_sk, &op_pk);
        // A seq-1 update whose content_hash lies about its body.
        let mut bad = g.clone();
        bad.sequence_number = 1;
        bad.previous_hash = g.chain_hash();
        bad.content_hash = [0xEE; 32]; // deliberately wrong
        operator_sign(&mut bad, &op_sk);

        let res = validate_ledger_chain(&[g, bad]);
        assert_eq!(
            res.accepted.len(),
            1,
            "content_hash mismatch must be dropped"
        );
    }

    #[test]
    fn empty_chain_is_rejected() {
        let res = validate_ledger_chain(&[]);
        assert!(res.accepted.is_empty());
        assert_eq!(res.stopped_reason.as_deref(), Some("empty chain"));
    }

    // --- fork split -----------------------------------------------------------

    #[test]
    fn split_keeps_single_chain_as_main_no_forks() {
        let (op_sk, op_pk) = kp(4);
        let g = genesis(&op_sk, &op_pk);
        let ledger_id = g.ledger_id_hex();
        let split = split_main_and_forks(&ledger_id, &[g]);
        assert_eq!(split.main.len(), 1);
        assert!(
            split.forks.is_empty(),
            "a linear chain has no fork branches"
        );
    }

    #[test]
    fn split_separates_a_fork_sibling_into_a_fork_branch() {
        let (op_sk, op_pk) = kp(5);
        let g = genesis(&op_sk, &op_pk);
        let ledger_id = g.ledger_id_hex();

        // Two seq-1 siblings sharing genesis as parent (a fork at seq 1). Give
        // one a deeper tail so the best-chain walk prefers it as `main`.
        let mut child_a = g.clone();
        child_a.sequence_number = 1;
        child_a.previous_hash = g.chain_hash();
        child_a.block_height = 101;
        child_a.content_hash = child_a.compute_hash();
        operator_sign(&mut child_a, &op_sk);

        let mut child_a2 = g.clone();
        child_a2.sequence_number = 2;
        child_a2.previous_hash = child_a.chain_hash();
        child_a2.block_height = 102;
        child_a2.content_hash = child_a2.compute_hash();
        operator_sign(&mut child_a2, &op_sk);

        let mut child_b = g.clone();
        child_b.sequence_number = 1;
        child_b.previous_hash = g.chain_hash();
        // A distinct op body → distinct content_hash (block_height alone is not
        // hashed into content_hash, so the two siblings must differ in `message`
        // — exactly the shape of a real equivocation fork).
        child_b.message.push(0xAB);
        child_b.content_hash = child_b.compute_hash();
        operator_sign(&mut child_b, &op_sk);

        let split = split_main_and_forks(
            &ledger_id,
            &[g.clone(), child_a.clone(), child_a2, child_b.clone()],
        );
        // Main = genesis + the deeper (a) branch.
        assert_eq!(split.main.len(), 3, "main = genesis + deeper branch");
        // The shorter sibling is a fork branch keyed by fork_tracking_key.
        assert_eq!(split.forks.len(), 1, "one fork branch");
        let (fork_key, branch) = &split.forks[0];
        assert_eq!(branch.len(), 1);
        assert_eq!(branch[0].content_hash, child_b.content_hash);
        assert_eq!(
            *fork_key,
            DepositsHandler::fork_tracking_key(&ledger_id, 1, &op_pk),
            "fork keyed exactly like the daemon"
        );
    }

    // --- archive-vs-relay diff (reuses heal::missing_updates) -----------------

    #[test]
    fn archive_vs_relay_diff_finds_only_the_gap() {
        let (op_sk, op_pk) = kp(6);
        let g = genesis(&op_sk, &op_pk);
        let mut s1 = g.clone();
        s1.sequence_number = 1;
        s1.previous_hash = g.chain_hash();
        s1.block_height = 101;
        s1.content_hash = s1.compute_hash();
        operator_sign(&mut s1, &op_sk);

        let archived = vec![g.clone(), s1.clone()];
        // Relay holds only genesis → seq-1 is the gap to backfill.
        let relay_present: HashSet<[u8; 32]> = [g.content_hash].into_iter().collect();
        let missing = missing_updates(&relay_present, &archived, BACKFILL_BATCH_LIMIT);
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].content_hash, s1.content_hash);

        // Relay fully caught up → nothing to backfill.
        let full: HashSet<[u8; 32]> = archived.iter().map(|u| u.content_hash).collect();
        assert!(missing_updates(&full, &archived, BACKFILL_BATCH_LIMIT).is_empty());
    }

    // --- persistence round-trip ----------------------------------------------

    #[test]
    fn archive_append_is_append_only_and_deduped() {
        let (op_sk, op_pk) = kp(7);
        let g = genesis(&op_sk, &op_pk);
        let ledger_id = g.ledger_id_hex();
        let tmp = std::env::temp_dir().join(format!("archive-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);

        let n =
            DepositsHandler::archive_append_updates_at(&tmp, &ledger_id, std::slice::from_ref(&g))
                .unwrap();
        assert_eq!(n, 1);
        // Re-appending the same update writes nothing (content_hash dedup).
        let n2 =
            DepositsHandler::archive_append_updates_at(&tmp, &ledger_id, std::slice::from_ref(&g))
                .unwrap();
        assert_eq!(n2, 0, "append-only + deduped: no duplicate rows");

        // Read back through the SAME reader the daemon healer uses.
        let back = DepositsHandler::read_persisted_history_at(&tmp, &ledger_id).unwrap();
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].content_hash, g.content_hash);
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
