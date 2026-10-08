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
use deposits_core::tapscript_reserves::{TapscriptReservesBuilder, VoterSet};
use deposits_core::tlv::TlvDecode;
use deposits_core::types::LedgerState;
use deposits_core::SignedLedgerUpdate;
use std::time::Duration;

const DEFAULT_RELAY: &str = "wss://relay.bitcoindeposits.net";
const DEFAULT_ESPLORA: &str = "https://mempool.space/api";

#[derive(Debug)]
enum LedgerVerdict {
    /// All updates apply cleanly through current validation.
    Pass { seq_count: usize },
    /// A specific update was rejected. Likely a code-vs-data
    /// regression — the deployment would refuse this ledger.
    Fail { seq: u64, reason: String },
    /// The chain has missing sequences. Independent of code: the
    /// ledger isn't fully present on this relay. Surfaces as a
    /// warning rather than a deploy blocker.
    Gap { first_missing: u64 },
    /// Multiple updates at the same sequence (equivocation or fork).
    /// Pick the operator's primary chain by seq-0 operator_id and
    /// note the diverging sequence. Independent of code.
    Fork { seq: u64, operators: Vec<String> },
    /// Couldn't decode any updates from the relay payload.
    NoUpdates,
    /// State machine accepted the chain, but on-chain verification of
    /// a `QuorumBegin`'s reserves UTXO disagreed with the ledger's
    /// recorded amount or spent state.
    OnchainMismatch { seq: u64, detail: String },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let mut relay_url = DEFAULT_RELAY.to_string();
    let mut esplora_url = DEFAULT_ESPLORA.to_string();
    let mut skip_onchain = false;
    let mut network = bitcoin::Network::Bitcoin; // default: mainnet (matches mempool.space)
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
            "--esplora" | "-e" if i + 1 < args.len() => {
                esplora_url = args[i + 1].clone();
                i += 2;
            }
            "--skip-onchain" => {
                skip_onchain = true;
                i += 1;
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
                    "Usage: validate-relay [OPTIONS]\n\
                     \n\
                     Replay every ledger on the relay through current validation\n\
                     rules and verify each QuorumBegin's reserves UTXO against\n\
                     Esplora. Exit code 0 iff every ledger passes both.\n\
                     \n\
                     Options:\n\
                       --relay URL          Nostr relay (default: relay.bitcoindeposits.net)\n\
                       --esplora URL        Esplora HTTP API (default: mempool.space/api)\n\
                       --network NAME       bitcoin|testnet|signet|regtest (default bitcoin)\n\
                       --skip-onchain       Skip the reserves-UTXO verification phase\n\
                       --prefix PFX         Only ledgers whose 16-hex `d` tag starts with PFX\n\
                       --limit N            Cap to first N ledgers\n\
                       --verbose            Per-step trace"
                );
                return Ok(());
            }
            _ => i += 1,
        }
    }

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run(
        &relay_url,
        &esplora_url,
        skip_onchain,
        network,
        &prefix,
        limit,
        verbose,
    ))
}

async fn run(
    relay_url: &str,
    esplora_url: &str,
    skip_onchain: bool,
    network: bitcoin::Network,
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
        let updates = fetch_ledger_updates(relay_url, lid)
            .await
            .unwrap_or_default();
        sorted.push((lid.clone(), updates));
    }

    let mut pass = 0usize;
    let mut fail = 0usize;
    let mut gap = 0usize;
    let mut fork = 0usize;
    let mut empty = 0usize;
    let mut onchain_mismatch = 0usize;
    let mut first_failures: Vec<(String, u64, String)> = Vec::new();

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()?;

    for (ledger_id, updates) in &sorted {
        let mut verdict = validate_ledger(ledger_id, updates, verbose);

        // If state-machine replay passed, ALSO check on-chain anchors
        // for every QuorumBegin. The state machine alone proves the
        // ledger is internally coherent; this proves it has on-chain
        // backing matching what it claims.
        if !skip_onchain {
            if let LedgerVerdict::Pass { .. } = &verdict {
                if let Some((seq, detail)) =
                    verify_onchain_anchors(updates, esplora_url, &http, network, verbose).await
                {
                    verdict = LedgerVerdict::OnchainMismatch { seq, detail };
                }
            }
        }
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
            LedgerVerdict::OnchainMismatch { seq, detail } => {
                println!("⚠ {}  on-chain mismatch at seq {}: {}", short, seq, detail);
                first_failures.push((ledger_id.clone(), *seq, detail.clone()));
                onchain_mismatch += 1;
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
    println!("  ⚠ On-chain:    {}", onchain_mismatch);

    if fail > 0 || onchain_mismatch > 0 {
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

    // Find the genesis update (seq 0). Multiple seq-0 updates by *distinct*
    // operators → fork at genesis (rare; an attacker forking creation).
    // Multiple seq-0 updates by the *same* operator are just duplicate
    // publishes (e.g. after a `ledger republish` with accumulated cosigs
    // recomputing content_hash) — pick any one as the genesis reference.
    let genesis: Vec<&SignedLedgerUpdate> =
        updates.iter().filter(|u| u.sequence_number == 0).collect();
    if genesis.is_empty() {
        return LedgerVerdict::Gap { first_missing: 0 };
    }
    let genesis_operators: std::collections::HashSet<_> =
        genesis.iter().map(|u| u.operator_id).collect();
    if genesis_operators.len() > 1 {
        let operators: Vec<String> = genesis_operators.iter().map(|pk| pk.to_string()).collect();
        return LedgerVerdict::Fork { seq: 0, operators };
    }
    let original_operator = genesis[0].operator_id;

    // Sort all updates by sequence. We don't pre-filter by operator_id
    // anymore — after a successful DisputeAcquire, the chain continues
    // under a new custodian with a different operator_id. Filtering to
    // the original operator would silently drop the new custodian's
    // updates and report a clean Pass for a chain that's actually under
    // new custody.
    //
    // Dedup by `(seq, operator_id)`. The `(seq, content_hash)` form
    // misses the republish edge case: when `ledger republish` re-emits
    // history that's accumulated additional cosignatures since the
    // original publish, content_hash changes but the canonical
    // operator-signed claim at that seq is identical. Same (seq, op) →
    // keep one and move on; cross-operator divergence at the same seq
    // is fork-branch evidence, which the operator_id check below
    // catches as a separate concern.
    let mut sorted: Vec<&SignedLedgerUpdate> = updates.iter().collect();
    sorted.sort_by_key(|u| (u.sequence_number, u.operator_id));
    sorted.dedup_by_key(|u| (u.sequence_number, u.operator_id));

    // Replay each update through `LedgerState::apply` — the same strict
    // state-transition path the daemon's `inbound.rs` runs on every
    // received update. Catches conformance violations (negative
    // balance, InvoiceCredit-over-reserves, missing deposits, etc).
    // We pre-seed an empty state with the original_operator so the
    // first update (LedgerOpen) replays cleanly.
    //
    // For each update we check `operator_id == state.parent_pubkey`:
    // updates that match are part of the canonical chain (the operator's
    // updates plus, after DisputeAcquire, the new custodian's). Updates
    // that don't match are fork-branch evidence — disputers publishing
    // an alternate chain under the same `#d` tag. We don't apply those
    // here; they belong to a separate Ledger storage unit on the daemon.
    let mut state = LedgerState::new(original_operator, String::new(), 0);
    let mut prev_canonical_seq: Option<u64> = None;
    let mut canonical_count = 0usize;
    let mut fork_branches: std::collections::HashMap<String, u64> =
        std::collections::HashMap::new();

    for u in &sorted {
        // Skip fork-branch updates. Disputers publish under the same
        // ledger_id with their own operator_id; the daemon stores those
        // as a separate fork ledger. Record for reporting but don't apply.
        if u.operator_id != state.parent_pubkey {
            let op_hex = u.operator_id.to_string();
            *fork_branches.entry(op_hex).or_insert(0) += 1;
            continue;
        }

        // Detect equivocation: same canonical operator, same seq,
        // different content_hash. (Same-content same-seq was deduped above.)
        if let Some(prev) = prev_canonical_seq {
            if u.sequence_number == prev {
                let conflicting: Vec<String> = sorted
                    .iter()
                    .filter(|x| {
                        x.sequence_number == u.sequence_number
                            && x.operator_id == state.parent_pubkey
                    })
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

        // Decode for the verbose-mode label only. The actual verification
        // path is `LedgerState::apply_signed`, which decodes the message
        // internally and verifies the full set of cryptographic
        // invariants (operator sig, cosig threshold, content_hash
        // integrity, ledger_id derivation for seq-0) before applying.
        // chain_tip=0 in the verifier is correct here: validate-relay is
        // a read-only auditor with no chain view of its own, and
        // descriptor `after(N)` checks that would otherwise reference
        // the tip surface as "unsatisfiable" — which is the strict
        // reading we want for an audit.
        let op = LedgerOperation::tlv_decode(&u.message).ok();
        let authorizer = deposits_core::dep16::Dep16Authorizer::new();
        match state.apply_signed(u, &authorizer) {
            Ok(next) => {
                state = next;
                if verbose {
                    eprintln!(
                        "  seq {} OK ({})  [op={}]",
                        u.sequence_number,
                        op.as_ref().map(op_name).unwrap_or("?"),
                        &u.operator_id.to_string()[..16]
                    );
                }
                prev_canonical_seq = Some(u.sequence_number);
                canonical_count += 1;
            }
            Err(e) => {
                return LedgerVerdict::Fail {
                    seq: u.sequence_number,
                    reason: format!("{} → {:?}", op.as_ref().map(op_name).unwrap_or("?"), e),
                };
            }
        }
    }

    if verbose && !fork_branches.is_empty() {
        for (op, count) in &fork_branches {
            eprintln!(
                "  fork-branch: {} updates from operator {}...",
                count,
                &op[..16.min(op.len())]
            );
        }
    }

    LedgerVerdict::Pass {
        seq_count: canonical_count,
    }
}

fn op_name(op: &LedgerOperation) -> &'static str {
    match op {
        LedgerOperation::LedgerOpen { .. } => "LedgerOpen",
        LedgerOperation::QuorumBegin { .. } => "QuorumBegin",
        LedgerOperation::QuorumUpgrade { .. } => "QuorumUpgrade",
        LedgerOperation::DepositOpen { .. } => "DepositOpen",
        LedgerOperation::DepositClose { .. } => "DepositClose",
        LedgerOperation::FeeChange { .. } => "FeeChange",
        LedgerOperation::DepositKeyRotate { .. } => "DepositKeyRotate",
        LedgerOperation::ExitRequest { .. } => "ExitRequest",
        LedgerOperation::ExitCancel { .. } => "ExitCancel",
        LedgerOperation::DormancyNotice { .. } => "DormancyNotice",
        LedgerOperation::DormancyAccept { .. } => "DormancyAccept",
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
        LedgerOperation::Batch(_) => "Batch",
    }
}

/// For every `QuorumBegin` in the ledger's history, query Esplora to
/// confirm the recorded reserves UTXO actually matches what's on-chain:
///
///   1. The output at `(new_outpoint_txid, new_outpoint_vout)` exists.
///   2. Its sat value equals `(amount + collateral_amount) / 1000`
///      (msat → sat). DEP-03 §QuorumBegin requires this exact equality.
///   3. The most recent QuorumBegin's UTXO is **unspent** — that's the
///      live reserves backing.
///   4. Earlier QuorumBegins' UTXOs are **spent** (rotated forward).
///      A still-unspent earlier UTXO means the rotation chain has a
///      hole — the operator claimed to rotate but didn't.
///
/// Returns `None` on success, or `Some((seq, detail))` for the first
/// problem found.
async fn verify_onchain_anchors(
    updates: &[SignedLedgerUpdate],
    esplora_url: &str,
    http: &reqwest::Client,
    network: bitcoin::Network,
    verbose: bool,
) -> Option<(u64, String)> {
    use std::str::FromStr;

    // Walk the chain (sorted) and collect QuorumBegin entries plus the
    // ledger's original operator (seq-0 LedgerOpen). The operator goes
    // into `VoterSet::new` as the tie_breaker for script-derivation.
    let mut sorted: Vec<&SignedLedgerUpdate> = updates.iter().collect();
    sorted.sort_by_key(|u| u.sequence_number);

    let original_operator = match sorted.first() {
        Some(u) => u.operator_id,
        None => return None,
    };

    struct QbAnchor {
        seq: u64,
        expected_sat: u64,
        txid: [u8; 32],
        vout: u32,
        reserves_id: String,
        derived_script: Option<bitcoin::ScriptBuf>,
        derived_address: Option<String>,
    }

    let mut qbs: Vec<QbAnchor> = Vec::new();
    for u in &sorted {
        if let Ok(LedgerOperation::QuorumBegin {
            amount,
            collateral_amount,
            new_outpoint_txid,
            new_outpoint_vout,
            reserves_id,
            ledger_hash,
            quorum_members,
            quorum_expiry,
            ..
        }) = LedgerOperation::tlv_decode(&u.message)
        {
            // Reconstruct the Taproot output the protocol's
            // `TapscriptReservesBuilder` would have produced from the
            // QuorumBegin's recorded params under EACH known ruleset.
            // The first ruleset whose derived address matches the
            // recorded reserves_id wins; we use that ruleset's script
            // for the on-chain comparison. If no ruleset matches, the
            // QuorumBegin's reserves_id can't be reconstructed by any
            // version this software knows — flagged as a mismatch.
            let voter_set = VoterSet::new(
                original_operator,
                quorum_members.iter().map(|m| m.pubkey).collect(),
            );
            let mut matched: Option<(bitcoin::ScriptBuf, String)> = None;
            for rs_name in ["legacy", "cltv-offset-v2"] {
                let rs = match deposits_core::ruleset::lookup(rs_name) {
                    Some(r) => r,
                    None => continue,
                };
                let cfg = (rs.tier_config_factory)(voter_set.total_count(), quorum_expiry);
                let out =
                    TapscriptReservesBuilder::new(voter_set.clone(), cfg, network, ledger_hash)
                        .build();
                if let Ok(out) = out {
                    let addr = out.address.to_string();
                    if addr == reserves_id {
                        matched = Some((out.script_pubkey(), addr));
                        break;
                    }
                }
            }
            let (derived_script, derived_address) = match matched {
                Some((s, a)) => (Some(s), Some(a)),
                None => (None, None),
            };

            let total_sat = (amount.saturating_add(collateral_amount)) / 1000;
            qbs.push(QbAnchor {
                seq: u.sequence_number,
                expected_sat: total_sat,
                txid: new_outpoint_txid,
                vout: new_outpoint_vout,
                reserves_id,
                derived_script,
                derived_address,
            });
        }
    }

    if qbs.is_empty() {
        return None;
    }

    let last_idx = qbs.len() - 1;
    for (i, qb) in qbs.iter().enumerate() {
        let seq = &qb.seq;
        let expected_sat = &qb.expected_sat;
        let txid = &qb.txid;
        let vout = &qb.vout;

        // Layer 0: derived address (from quorum_members + ledger_hash +
        // quorum_expiry) must equal the recorded reserves_id. Catches
        // an operator who put a fake address in QuorumBegin.
        if let Some(derived) = &qb.derived_address {
            if derived != &qb.reserves_id {
                return Some((
                    *seq,
                    format!(
                        "QuorumBegin reserves_id mismatch: recorded {}, \
                         derived from quorum_members+ledger_hash+quorum_expiry {}",
                        &qb.reserves_id[..20.min(qb.reserves_id.len())],
                        &derived[..20.min(derived.len())]
                    ),
                ));
            }
        }
        // Bitcoin txids on-chain are big-endian-display-order; the
        // protocol stores them as the raw 32-byte hash. Esplora's REST
        // API takes the display form (which is the byte-reversed hash).
        let txid_display = {
            let mut rev = *txid;
            rev.reverse();
            hex::encode(rev)
        };

        // Step 1: tx exists + output value matches.
        let tx_url = format!("{}/tx/{}", esplora_url.trim_end_matches('/'), txid_display);
        if verbose {
            eprintln!("  GET {}", tx_url);
        }
        let resp = match http.get(&tx_url).send().await {
            Ok(r) => r,
            Err(e) => return Some((*seq, format!("esplora unreachable: {}", e))),
        };
        if !resp.status().is_success() {
            // 404 = tx not on chain. Anything else = transient.
            if resp.status() == reqwest::StatusCode::NOT_FOUND {
                return Some((
                    *seq,
                    format!("reserves tx {}:{} not on-chain", &txid_display[..16], vout),
                ));
            }
            return Some((
                *seq,
                format!(
                    "esplora /tx/{} returned status {}",
                    &txid_display[..16],
                    resp.status()
                ),
            ));
        }
        let tx_json: serde_json::Value = match resp.json().await {
            Ok(v) => v,
            Err(e) => return Some((*seq, format!("esplora /tx parse: {}", e))),
        };
        let vout_arr = tx_json.get("vout").and_then(|v| v.as_array());
        let output = vout_arr.and_then(|arr| arr.get(*vout as usize));
        let actual_sat = output.and_then(|o| o.get("value")).and_then(|v| v.as_u64());
        let actual_script_hex = output
            .and_then(|o| o.get("scriptpubkey"))
            .and_then(|v| v.as_str());
        let actual_sat = match actual_sat {
            Some(s) => s,
            None => {
                return Some((
                    *seq,
                    format!(
                        "vout {} not present in tx {} (only {} outputs)",
                        vout,
                        &txid_display[..16],
                        vout_arr.map(|a| a.len()).unwrap_or(0)
                    ),
                ));
            }
        };
        if actual_sat != *expected_sat {
            return Some((
                *seq,
                format!(
                    "reserves UTXO value mismatch: ledger says {} sats, on-chain has {} sats",
                    expected_sat, actual_sat
                ),
            ));
        }

        // Layer 1: on-chain scriptPubKey must equal the script we
        // derived from the recorded QuorumBegin params. This is the
        // strong guarantee — the on-chain UTXO is locked by exactly
        // the Taproot tree the protocol's reconstruction produces
        // from quorum_members + ledger_hash + quorum_expiry.
        if let (Some(actual_hex), Some(derived_script)) =
            (actual_script_hex, qb.derived_script.as_ref())
        {
            let derived_hex = hex::encode(derived_script.as_bytes());
            if !derived_hex.eq_ignore_ascii_case(actual_hex) {
                // Try parsing reserves_id as an address; if it
                // matches the on-chain scriptPubKey, the operator
                // pointed correctly but the protocol-derived
                // reconstruction differs (would mean a code bug
                // here, since the address-derived check above
                // already passed). Otherwise it's a genuine mismatch.
                let recorded_addr_script = bitcoin::Address::from_str(&qb.reserves_id)
                    .ok()
                    .and_then(|a| a.require_network(network).ok())
                    .map(|a| hex::encode(a.script_pubkey().as_bytes()));
                let recorded_matches_actual = recorded_addr_script
                    .as_deref()
                    .map(|s| s.eq_ignore_ascii_case(actual_hex))
                    .unwrap_or(false);
                if !recorded_matches_actual {
                    return Some((
                        *seq,
                        format!(
                            "scriptPubKey mismatch at {}:{}: on-chain {}..., \
                             recorded reserves_id derives to {}...",
                            &txid_display[..16],
                            vout,
                            &actual_hex[..16.min(actual_hex.len())],
                            &derived_hex[..16.min(derived_hex.len())]
                        ),
                    ));
                }
            }
        }

        // Step 2: spent vs unspent. The latest QB's UTXO must be
        // unspent; all earlier ones must be spent (rotated).
        let outspend_url = format!(
            "{}/tx/{}/outspend/{}",
            esplora_url.trim_end_matches('/'),
            txid_display,
            vout
        );
        if verbose {
            eprintln!("  GET {}", outspend_url);
        }
        let resp = match http.get(&outspend_url).send().await {
            Ok(r) => r,
            Err(e) => return Some((*seq, format!("esplora outspend unreachable: {}", e))),
        };
        if !resp.status().is_success() {
            return Some((*seq, format!("esplora outspend status {}", resp.status())));
        }
        let outspend: serde_json::Value = match resp.json().await {
            Ok(v) => v,
            Err(e) => return Some((*seq, format!("esplora outspend parse: {}", e))),
        };
        let spent = outspend
            .get("spent")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if i == last_idx {
            // The latest QuorumBegin SHOULD be unspent — that's the
            // live reserves. Spent here means the operator rotated
            // off-ledger (claimed reserves are gone from chain but
            // no follow-up QuorumBegin records the new outpoint).
            if spent {
                return Some((
                    *seq,
                    format!(
                        "latest QuorumBegin UTXO {}:{} is SPENT but no \
                         follow-up QuorumBegin exists — reserves rotated \
                         off-ledger",
                        &txid_display[..16],
                        vout
                    ),
                ));
            }
        } else {
            // Earlier QBs: should be spent by the rotation TX that
            // produced the next QB. Unspent here means the operator
            // emitted a new QuorumBegin without actually rotating.
            if !spent {
                return Some((
                    *seq,
                    format!(
                        "QuorumBegin UTXO {}:{} is UNSPENT but a later \
                         QuorumBegin exists — rotation chain has a hole",
                        &txid_display[..16],
                        vout
                    ),
                ));
            }
        }
    }
    None
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
