// Replay a ledger chain: fetch updates, walk backward, play forward, pretty-print state.
//
// Two modes:
//   1. JSONL (local):  Read from data/<node>/wallet/ledgers/<id>.jsonl
//   2. Nostr (relay):  Fetch Kind 9100 events from a relay, walk chain backward
//
// Usage:
//   # JSONL mode (default when no --relay)
//   replay-ledger <ledger_id_prefix>                          # Search in ./data/
//   replay-ledger <ledger_id_prefix> --node alice             # Only search alice's ledgers
//   replay-ledger <ledger_id_prefix> --until <hash_prefix>    # Stop at a specific chain_hash
//
//   # Nostr mode
//   replay-ledger --relay ws://localhost:7779                 # List ledgers on relay
//   replay-ledger 183c --relay ws://localhost:7779            # Prefix match on relay
//   replay-ledger <ledger_id> --relay ws://localhost:7779     # Fetch from relay
//
//   # Common options
//   replay-ledger <ledger_id_prefix> --verbose                # Print each operation as applied

use std::collections::HashMap;
use std::path::PathBuf;
use deposits_core::{SignedLedgerUpdate, LedgerState, TlvEncode};
use deposits_core::messages::LedgerOperation;
use deposits_core::tlv::TlvDecode;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

const DEFAULT_DATA_ROOT: &str = "data";

// =========================================================================
// Formatting helpers
// =========================================================================

fn format_msats(msats: u64) -> String {
    if msats == 0 { return "0".to_string(); }
    let sats = msats / 1000;
    let rem = msats % 1000;
    if rem == 0 {
        format_sats(sats)
    } else {
        format!("{}.{:03} sat", format_sats(sats), rem)
    }
}

fn format_sats(sats: u64) -> String {
    if sats >= 100_000_000 {
        format!("{:.8} BTC", sats as f64 / 100_000_000.0)
    } else if sats >= 1_000_000 {
        format!("{},{:03},{:03} sat", sats / 1_000_000, (sats / 1_000) % 1_000, sats % 1_000)
    } else if sats >= 1_000 {
        format!("{},{:03} sat", sats / 1_000, sats % 1_000)
    } else {
        format!("{} sat", sats)
    }
}

fn short_hex(bytes: &[u8]) -> String {
    if bytes.len() >= 4 { format!("{}...", hex::encode(&bytes[..4])) }
    else { hex::encode(bytes) }
}

fn short_pubkey(pk: &bitcoin::secp256k1::PublicKey) -> String {
    let s = hex::encode(pk.serialize());
    format!("{}..{}", &s[..6], &s[s.len()-4..])
}

fn deposit_id_hex(id: &[u8; 16]) -> String { hex::encode(id) }

fn short_deposit_id(id: &[u8; 16]) -> String {
    let h = hex::encode(id);
    format!("{}..{}", &h[..4], &h[h.len()-4..])
}

/// Format a LedgerOperation into a one-line summary
fn format_op(op: &LedgerOperation) -> String {
    match op {
        LedgerOperation::LedgerOpen { reserves_amount, genesis_block, .. } =>
            format!("LedgerOpen  reserves={} genesis_block={}", format_msats(*reserves_amount), genesis_block),
        LedgerOperation::QuorumBegin { amount, quorum_expiry, reserves_id, .. } => {
            let short_res = if reserves_id.len() > 20 { format!("{}...", &reserves_id[..20]) } else { reserves_id.clone() };
            format!("QuorumBegin  reserves={} expiry={} addr={}", format_msats(*amount), quorum_expiry, short_res)
        }
        LedgerOperation::QuorumAddMember { quorum_member, member_ledger_id, .. } => {
            let lid = if member_ledger_id.len() > 16 { format!("{}...", &member_ledger_id[..16]) } else { member_ledger_id.clone() };
            format!("QuorumAddMember  member={} ledger={}", short_pubkey(quorum_member), lid)
        }
        LedgerOperation::QuorumRemoveMember { quorum_member, .. } =>
            format!("QuorumRemoveMember  member={}", short_pubkey(quorum_member)),
        LedgerOperation::QuorumJoin { operator_id, ledger_id, membership_expires, .. } => {
            let lid = if ledger_id.len() > 16 { format!("{}...", &ledger_id[..16]) } else { ledger_id.clone() };
            format!("QuorumJoin  operator={} ledger={} expires={}", short_pubkey(operator_id), lid, membership_expires)
        }
        LedgerOperation::DepositOpen { deposit_id, descriptor, fees, is_collateral, .. } => {
            let desc = if descriptor.len() > 30 { format!("{}...", &descriptor[..30]) } else { descriptor.clone() };
            let coll = if *is_collateral { " [collateral]" } else { "" };
            let fee_str = match fees {
                Some(f) => format!("{}bps+{}/yr", f.annualized_bps, format_msats(f.annualized_msats)),
                None => "default".to_string(),
            };
            format!("DepositOpen  id={} desc={} fee={}{}", short_deposit_id(deposit_id), desc, fee_str, coll)
        }
        LedgerOperation::DepositClose { deposit_id } =>
            format!("DepositClose  id={}", short_deposit_id(deposit_id)),
        LedgerOperation::FeeChange { deposit_id, new_fees, effective_block } =>
            format!("FeeChange  id={} new={}bps+{}/yr effective={}", short_deposit_id(deposit_id), new_fees.annualized_bps, format_msats(new_fees.annualized_msats), effective_block),
        LedgerOperation::DepositKeyRotate { deposit_id, new_descriptor, .. } => {
            let desc = if new_descriptor.len() > 30 { format!("{}...", &new_descriptor[..30]) } else { new_descriptor.clone() };
            format!("DepositKeyRotate  id={} new_desc={}", short_deposit_id(deposit_id), desc)
        }
        LedgerOperation::InvoiceCredit { deposit_id, amount, .. } =>
            format!("InvoiceCredit  id={} +{}", short_deposit_id(deposit_id), format_msats(*amount)),
        LedgerOperation::InvoiceLock { deposit_id, amount, .. } =>
            format!("InvoiceLock  id={} -{}", short_deposit_id(deposit_id), format_msats(*amount)),
        LedgerOperation::InvoiceFail { deposit_id, amount, .. } =>
            format!("InvoiceFail  id={} +{}", short_deposit_id(deposit_id), format_msats(*amount)),
        LedgerOperation::InvoiceFulfill { deposit_id, amount, .. } =>
            format!("InvoiceFulfill  id={} -{}", short_deposit_id(deposit_id), format_msats(*amount)),
        LedgerOperation::OnchainCredit { deposit_id, amount, .. } =>
            format!("OnchainCredit  id={} +{}", short_deposit_id(deposit_id), format_msats(*amount)),
        LedgerOperation::OnchainLock { deposit_id, amount, .. } =>
            format!("OnchainLock  id={} -{}", short_deposit_id(deposit_id), format_msats(*amount)),
        LedgerOperation::OnchainFail { deposit_id, .. } =>
            format!("OnchainFail  id={}", short_deposit_id(deposit_id)),
        LedgerOperation::OnchainFulfill { deposit_id, amount, .. } =>
            format!("OnchainFulfill  id={} -{}", short_deposit_id(deposit_id), format_msats(*amount)),
        LedgerOperation::FeeCollect { deposit_id, amount, block_height } =>
            format!("FeeCollect  id={} {} block={}", short_deposit_id(deposit_id), format_msats(*amount), block_height),
        LedgerOperation::CollateralAttestation { collateral_operator, amount, block_height, .. } =>
            format!("CollateralAttest  operator={} amount={} block={}", short_pubkey(collateral_operator), format_msats(*amount), block_height),
        LedgerOperation::CollateralLock { deposit_id, amount, lock_until_block, .. } =>
            format!("CollateralLock  id={} amount={} until={}", short_deposit_id(deposit_id), format_msats(*amount), lock_until_block),
        LedgerOperation::TransferLock { source_deposit_id, destination_deposit_id, amount, timeout_height, .. } =>
            format!("TransferLock  {} -> {} amount={} timeout={}", short_deposit_id(source_deposit_id), short_deposit_id(destination_deposit_id), format_msats(*amount), timeout_height),
        LedgerOperation::TransferComplete { transfer_id, .. } =>
            format!("TransferComplete  id={}", short_hex(transfer_id)),
        LedgerOperation::TransferFail { transfer_id, .. } =>
            format!("TransferFail  id={}", short_hex(transfer_id)),
        LedgerOperation::DisputeEnter { reason, last_valid_sequence, .. } =>
            format!("DisputeEnter  reason={:?} last_valid_seq={}", reason, last_valid_sequence),
        LedgerOperation::DisputeAcquire { new_custodian, .. } =>
            format!("DisputeAcquire  new_custodian={}", short_pubkey(new_custodian)),
        LedgerOperation::DisputeYield => "DisputeYield".to_string(),
        LedgerOperation::DisputeArmed { armed_block, .. } =>
            format!("DisputeArmed  block={}", armed_block),
        LedgerOperation::LedgerClose => "LedgerClose".to_string(),
        LedgerOperation::DeliveryEmbed { request_hash, .. } =>
            format!("DeliveryEmbed  req={}", short_hex(request_hash)),
    }
}

// =========================================================================
// Pretty-print LedgerState
// =========================================================================

fn print_state(state: &LedgerState) {
    println!("Ledger State");
    println!("============");
    println!("  ledger_id:   {}", hex::encode(state.ledger_id));
    println!("  operator:    {}", short_pubkey(&state.operator_key));
    let res = if state.reserves_key.len() > 40 { format!("{}...", &state.reserves_key[..40]) } else { state.reserves_key.clone() };
    println!("  reserves:    {}", res);
    println!("  reserves_amt:{}", format_msats(state.reserves_amount));
    println!("  genesis:     block {}", state.genesis_block);
    println!("  sequence:    {}", state.sequence);
    println!("  chain_tip:   {}", hex::encode(state.chain_tip_hash));
    println!("  dispute:     {:?}", state.dispute_state);
    println!("  quorum:      {:?}", state.quorum_state);
    if let Some(exp) = state.quorum_expiry {
        println!("  quorum_exp:  block {}", exp);
    }

    if !state.quorum_members.is_empty() {
        println!();
        println!("  Quorum Members (active):");
        for m in &state.quorum_members {
            let mut details = vec![format!("ledger={}", if m.ledger_id.len() > 16 { format!("{}...", &m.ledger_id[..16]) } else { m.ledger_id.clone() })];
            if let Some(bps) = m.min_fee_bps { details.push(format!("min_fee={}bps", bps)); }
            if let Some(lock) = m.collateral_lock_amount { details.push(format!("coll_lock={}", format_msats(lock))); }
            println!("    {}  {}", short_pubkey(&m.pubkey), details.join("  "));
        }
    }

    if !state.next_quorum_members.is_empty() {
        println!();
        println!("  Next Quorum Members (pending):");
        for m in &state.next_quorum_members {
            println!("    {}  ledger={}", short_pubkey(&m.pubkey), if m.ledger_id.len() > 16 { format!("{}...", &m.ledger_id[..16]) } else { m.ledger_id.clone() });
        }
    }

    if !state.collateral_attestations.is_empty() {
        println!();
        println!("  Collateral Attestations:");
        for (pk, att) in &state.collateral_attestations {
            println!("    {}  amount={}  block={}  lock_until={}", short_pubkey(pk), format_msats(att.amount), att.block_height, att.lock_until_block);
        }
    }

    if !state.deposits.is_empty() {
        println!();
        println!("  Deposits:");
        let mut deposits: Vec<_> = state.deposits.iter().collect();
        deposits.sort_by_key(|(id, _)| **id);
        for (id, dep) in deposits {
            let coll = if dep.is_collateral { " [collateral]" } else { "" };
            println!("    {}{}", deposit_id_hex(id), coll);
            let desc = if dep.descriptor.len() > 50 { format!("{}...", &dep.descriptor[..50]) } else { dep.descriptor.clone() };
            println!("      descriptor: {}", desc);
            println!("      balance:    {}  locked: {}", format_msats(dep.balance), format_msats(dep.locked_balance));
            println!("      fees:       {}bps + {}/yr  (every {} blocks)", dep.fees.annualized_bps, format_msats(dep.fees.annualized_msats), dep.fees.frequency_blocks);
            if dep.collateral_lock_amount > 0 {
                println!("      coll_lock:  {} until block {}", format_msats(dep.collateral_lock_amount), dep.collateral_lock_expires);
            }
            if let Some((ref new_fees, eff)) = dep.pending_fee_change {
                println!("      pending_fee: {}bps + {}/yr at block {}", new_fees.annualized_bps, format_msats(new_fees.annualized_msats), eff);
            }
        }
    }

    if !state.pending_transfers.is_empty() {
        println!();
        println!("  Pending Transfers:");
        for (id, t) in &state.pending_transfers {
            println!("    {}  {} -> {}  amount={}  timeout={}",
                short_hex(id), short_deposit_id(&t.source_deposit_id), short_deposit_id(&t.destination_deposit_id),
                format_msats(t.amount), t.timeout_height);
        }
    }

    if !state.joined_quorums.is_empty() {
        println!();
        println!("  Joined Quorums (as member):");
        for m in &state.joined_quorums {
            let lid = if m.ledger_id.len() > 16 { format!("{}...", &m.ledger_id[..16]) } else { m.ledger_id.clone() };
            println!("    operator={}  ledger={}  expires={}  joined_at_seq={}",
                short_pubkey(&m.operator_id), lid, m.membership_expires, m.joined_at_sequence);
        }
    }

    let total_balance: u64 = state.deposits.values().map(|d| d.balance).sum();
    let total_locked: u64 = state.deposits.values().map(|d| d.locked_balance).sum();
    let total_collateral: u64 = state.collateral_attestations.values().map(|a| a.available_collateral()).sum();

    println!();
    println!("  Summary:");
    println!("    deposits:    {}", state.deposits.len());
    println!("    total_bal:   {}", format_msats(total_balance));
    if total_locked > 0 { println!("    total_lock:  {}", format_msats(total_locked)); }
    println!("    reserves:    {}", format_msats(state.reserves_amount));
    if total_collateral > 0 { println!("    collateral:  {}", format_msats(total_collateral)); }
    let solvent = state.reserves_amount >= total_balance + total_locked;
    println!("    solvent:     {}", if solvent { "YES" } else { "NO" });
}

// =========================================================================
// Replay engine (shared between JSONL and Nostr modes)
// =========================================================================

/// Given an ordered chain of updates (genesis first), replay through LedgerState.
/// If `until_hash` is set, stop when we reach a chain_hash matching that prefix.
fn replay_chain(chain: &[SignedLedgerUpdate], verbose: bool, until_hash: Option<&str>) -> (LedgerState, Vec<String>) {
    let mut errors = Vec::new();

    if chain.is_empty() {
        return (LedgerState::new(
            bitcoin::secp256k1::PublicKey::from_slice(&[2; 33]).unwrap_or_else(|_| unreachable!()),
            String::new(), 0,
        ), vec!["Empty chain".to_string()]);
    }

    // Bootstrap from first operation
    let first = &chain[0];
    let first_op = match LedgerOperation::tlv_decode(&first.message) {
        Ok(op) => op,
        Err(e) => {
            errors.push(format!("seq=0: decode failed: {:?}", e));
            return (LedgerState::new(first.operator_id, String::new(), 0), errors);
        }
    };

    let (operator_key, reserves_key, genesis_block) = match &first_op {
        LedgerOperation::LedgerOpen { operator_id, reserves_id, genesis_block, .. } =>
            (*operator_id, reserves_id.clone(), *genesis_block),
        _ => (first.operator_id, String::new(), 0),
    };

    let mut state = LedgerState::new(operator_key, reserves_key, genesis_block);
    let mut expected_prev = [0u8; 32];

    for update in chain {
        // Validate chain linkage
        if update.previous_hash != expected_prev {
            errors.push(format!("seq={}: chain break (prev={} expected={})",
                update.sequence_number, short_hex(&update.previous_hash), short_hex(&expected_prev)));
        }

        // Validate hash
        let computed = update.compute_hash();
        if computed != update.current_hash {
            errors.push(format!("seq={}: hash mismatch (computed={} stored={})",
                update.sequence_number, short_hex(&computed), short_hex(&update.current_hash)));
        }

        // Decode and apply
        match LedgerOperation::tlv_decode(&update.message) {
            Ok(op) => {
                if verbose {
                    let cosigned = if update.cosigner_pubkey.is_some() { " [cosigned]" } else { "" };
                    println!("  {:>4}  {}{}", update.sequence_number, format_op(&op), cosigned);
                }
                match state.apply(&op) {
                    Ok(next) => {
                        state = next;
                        state.sequence = update.sequence_number;
                        state.chain_tip_hash = update.chain_hash();
                    }
                    Err(e) => {
                        errors.push(format!("seq={}: apply failed: {:?}", update.sequence_number, e));
                        state.sequence = update.sequence_number;
                        state.chain_tip_hash = update.chain_hash();
                    }
                }
            }
            Err(e) => {
                errors.push(format!("seq={}: decode failed: {:?}", update.sequence_number, e));
                state.sequence = update.sequence_number;
                state.chain_tip_hash = update.chain_hash();
            }
        }

        expected_prev = update.chain_hash();

        // Check if we've reached the target hash
        if let Some(prefix) = until_hash {
            let h = hex::encode(update.chain_hash());
            if h.starts_with(prefix) {
                if verbose { println!("  -- stopped at chain_hash {}...", &h[..16]); }
                break;
            }
        }
    }

    if verbose { println!(); }
    (state, errors)
}

/// Build an ordered chain from a set of updates by walking backward from the tip.
fn build_chain(updates: &[SignedLedgerUpdate]) -> Vec<usize> {
    if updates.is_empty() { return vec![]; }

    // Map chain_hash -> index for backward walking
    let mut by_chain_hash: HashMap<[u8; 32], usize> = HashMap::new();
    for (i, u) in updates.iter().enumerate() {
        by_chain_hash.insert(u.chain_hash(), i);
    }

    // Start from the highest-sequence update
    let mut chain_indices = Vec::new();
    let mut current_idx = updates.len() - 1;
    chain_indices.push(current_idx);

    loop {
        let u = &updates[current_idx];
        if u.previous_hash == [0u8; 32] { break; }

        if let Some(&prev_idx) = by_chain_hash.get(&u.previous_hash) {
            chain_indices.push(prev_idx);
            current_idx = prev_idx;
        } else {
            // Sequence-based fallback
            if u.sequence_number > 0 {
                if let Some(pos) = updates.iter().position(|x| x.sequence_number == u.sequence_number - 1) {
                    chain_indices.push(pos);
                    current_idx = pos;
                    continue;
                }
            }
            eprintln!("Warning: chain breaks at seq={}, prev_hash={}", u.sequence_number, short_hex(&u.previous_hash));
            break;
        }
    }

    chain_indices.reverse();
    chain_indices
}

// =========================================================================
// JSONL mode
// =========================================================================

#[derive(Debug, serde::Deserialize)]
#[serde(tag = "type")]
enum LedgerLogRow {
    Role { role: String },
    #[allow(dead_code)]
    State(LedgerState),
    Update(SignedLedgerUpdate),
}

/// Read the Role line from the first line of a JSONL ledger file.
fn read_role(path: &std::path::Path) -> String {
    use std::io::BufRead;
    if let Ok(f) = std::fs::File::open(path) {
        let reader = std::io::BufReader::new(f);
        if let Some(Ok(line)) = reader.lines().next() {
            if let Ok(LedgerLogRow::Role { role }) = serde_json::from_str(&line) {
                return role;
            }
        }
    }
    "Unknown".to_string()
}

struct LedgerMatch {
    node_name: String,
    ledger_id: String,
    path: PathBuf,
    role: String,
}

fn find_ledger_files(data_root: &PathBuf, prefix: &str, node_filter: Option<&str>) -> Vec<LedgerMatch> {
    let mut results = Vec::new();
    let entries = match std::fs::read_dir(data_root) {
        Ok(e) => e,
        Err(_) => return results,
    };

    for entry in entries.flatten() {
        let node_dir = entry.path();
        if !node_dir.is_dir() { continue; }
        let node_name = entry.file_name().to_string_lossy().to_string();
        if node_name == "relays" || node_name == "self-pay" || node_name == "htlc-agent" { continue; }
        if let Some(filter) = node_filter {
            if node_name != filter { continue; }
        }

        let ledgers_dir = node_dir.join("wallet").join("ledgers");
        if !ledgers_dir.exists() { continue; }

        for ledger_file in std::fs::read_dir(&ledgers_dir).into_iter().flatten().flatten() {
            let path = ledger_file.path();
            if path.extension().and_then(|s| s.to_str()) != Some("jsonl") { continue; }
            let ledger_id = path.file_stem().and_then(|s| s.to_str()).unwrap_or("").to_string();
            if ledger_id.starts_with(prefix) || prefix.is_empty() {
                let role = read_role(&path);
                results.push(LedgerMatch { node_name: node_name.clone(), ledger_id, path, role });
            }
        }
    }
    results
}

/// Deduplicate ledger matches: prefer the Operator copy of each ledger_id.
/// When a node_filter is active, skip deduplication (show what the user asked for).
fn dedup_ledger_files(matches: Vec<LedgerMatch>, has_node_filter: bool) -> Vec<LedgerMatch> {
    if has_node_filter { return matches; }

    let mut by_ledger: HashMap<String, Vec<LedgerMatch>> = HashMap::new();
    for m in matches {
        by_ledger.entry(m.ledger_id.clone()).or_default().push(m);
    }

    let mut results: Vec<LedgerMatch> = Vec::new();
    for (_lid, mut copies) in by_ledger {
        // Sort: Operator first, then alphabetically by node name
        copies.sort_by(|a, b| {
            let a_op = a.role == "Operator";
            let b_op = b.role == "Operator";
            b_op.cmp(&a_op).then(a.node_name.cmp(&b.node_name))
        });
        results.push(copies.into_iter().next().unwrap());
    }
    results.sort_by(|a, b| a.node_name.cmp(&b.node_name).then(a.ledger_id.cmp(&b.ledger_id)));
    results
}

fn run_jsonl(data_root: &PathBuf, prefix: &str, node_filter: Option<&str>, verbose: bool, until_hash: Option<&str>, decode_seq: Option<u64>, browse: bool) -> Result<(), Box<dyn std::error::Error>> {
    let all_matches = find_ledger_files(data_root, prefix, node_filter);
    let matches = dedup_ledger_files(all_matches, node_filter.is_some());

    if matches.is_empty() {
        if prefix.is_empty() {
            eprintln!("No ledger files found in {}", data_root.display());
        } else {
            eprintln!("No ledger matching '{}' found in {}", prefix, data_root.display());
        }
        std::process::exit(1);
    }

    if prefix.is_empty() || matches.len() > 1 {
        println!("Available ledgers:");
        for m in &matches {
            let short_id = if m.ledger_id.len() > 16 { &m.ledger_id[..16] } else { &m.ledger_id };
            println!("  {}  {}  ({})", short_id, m.node_name, m.role);
        }
        if matches.len() > 1 && !prefix.is_empty() {
            eprintln!("\nMultiple matches for '{}'. Provide a longer prefix or --node.", prefix);
        }
        return Ok(());
    }

    let m = &matches[0];
    let contents = std::fs::read_to_string(&m.path)?;

    let mut updates: Vec<SignedLedgerUpdate> = Vec::new();

    for line in contents.lines() {
        if line.trim().is_empty() { continue; }
        match serde_json::from_str::<LedgerLogRow>(line) {
            Ok(LedgerLogRow::Update(u)) => { updates.push(u); }
            _ => {}
        }
    }

    if updates.is_empty() {
        eprintln!("No updates found in {}", m.path.display());
        std::process::exit(1);
    }

    updates.sort_by_key(|u| u.sequence_number);

    if browse {
        return browse_updates(&updates, decode_seq);
    }

    if let Some(seq) = decode_seq {
        match updates.iter().find(|u| u.sequence_number == seq) {
            Some(update) => { decode_update(update); return Ok(()); }
            None => {
                eprintln!("No update with sequence {} in {}", seq, m.path.display());
                std::process::exit(1);
            }
        }
    }

    let chain_indices = build_chain(&updates);
    let chain: Vec<SignedLedgerUpdate> = chain_indices.iter().map(|&i| updates[i].clone()).collect();

    println!("{}/{}  (role: {})", m.node_name, m.ledger_id, m.role);
    println!("{} updates in chain (of {} total in file)", chain.len(), updates.len());
    println!();

    let (state, errors) = replay_chain(&chain, verbose, until_hash);

    if !errors.is_empty() {
        println!("Errors ({}):", errors.len());
        for e in &errors { println!("  {}", e); }
        println!();
    }

    print_state(&state);
    Ok(())
}

// =========================================================================
// Nostr mode — raw websocket REQ/EVENT/EOSE
// =========================================================================

/// List all ledgers available on a relay, optionally filtered by prefix.
/// Returns the full ledger_id of a single match (for auto-selection), or None.
async fn list_relay_ledgers(relay_url: &str, prefix: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
    use tokio_tungstenite::tungstenite::Message;
    use futures_util::{SinkExt, StreamExt};

    eprintln!("Connecting to {}...", relay_url);
    let (mut ws, _) = tokio_tungstenite::connect_async(relay_url).await
        .map_err(|e| format!("Failed to connect to {}: {}", relay_url, e))?;

    let sub_id = "list";
    let filter = serde_json::json!({ "kinds": [9100], "limit": 50000 });
    let req = serde_json::json!(["REQ", sub_id, filter]);
    ws.send(Message::Text(req.to_string())).await?;

    // ledger_id -> (max_seq, update_count, operator_npub)
    let mut ledgers: HashMap<String, (u64, usize, Option<String>)> = HashMap::new();

    loop {
        let msg = match tokio::time::timeout(std::time::Duration::from_secs(30), ws.next()).await {
            Ok(Some(Ok(Message::Text(text)))) => text,
            Ok(Some(Ok(Message::Close(_)))) | Ok(None) => break,
            Ok(Some(Ok(_))) => continue,
            Ok(Some(Err(e))) => { eprintln!("WebSocket error: {}", e); break; }
            Err(_) => { eprintln!("Timeout waiting for relay response"); break; }
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
                    let pubkey = event.get("pubkey").and_then(|v| v.as_str()).map(|s| s.to_string());
                    if let Some(tags) = event.get("tags").and_then(|v| v.as_array()) {
                        let mut lid = None;
                        let mut seq = 0u64;
                        for tag in tags {
                            if let Some(tag_arr) = tag.as_array() {
                                match tag_arr.first().and_then(|v| v.as_str()) {
                                    Some("d") => lid = tag_arr.get(1).and_then(|v| v.as_str()).map(|s| s.to_string()),
                                    Some("n") => seq = tag_arr.get(1).and_then(|v| v.as_str()).and_then(|s| s.parse().ok()).unwrap_or(0),
                                    _ => {}
                                }
                            }
                        }
                        if let Some(id) = lid {
                            if prefix.is_empty() || id.starts_with(prefix) {
                                let entry = ledgers.entry(id).or_insert((0, 0, None));
                                if seq > entry.0 { entry.0 = seq; }
                                entry.1 += 1;
                                if entry.2.is_none() { entry.2 = pubkey; }
                            }
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

    if ledgers.is_empty() {
        if prefix.is_empty() {
            println!("No ledgers found on {}", relay_url);
        } else {
            println!("No ledgers matching '{}' on {}", prefix, relay_url);
        }
        return Ok(None);
    }

    // Single match with a prefix → auto-select
    if ledgers.len() == 1 && !prefix.is_empty() {
        let (lid, _) = ledgers.into_iter().next().unwrap();
        return Ok(Some(lid));
    }

    let mut sorted: Vec<_> = ledgers.into_iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));

    println!("Ledgers on {}:", relay_url);
    for (lid, (max_seq, count, pubkey)) in &sorted {
        let short_id = if lid.len() > 16 { &lid[..16] } else { lid.as_str() };
        let pk_str = match pubkey {
            Some(pk) if pk.len() >= 12 => format!("  pk={}...", &pk[..12]),
            _ => String::new(),
        };
        println!("  {}  seq={:<4}  updates={}{}", short_id, max_seq, count, pk_str);
    }

    if !prefix.is_empty() {
        eprintln!("\nMultiple matches for '{}'. Provide a longer prefix.", prefix);
    }

    Ok(None)
}

async fn fetch_updates_from_relay(relay_url: &str, ledger_id: &str) -> Result<Vec<SignedLedgerUpdate>, Box<dyn std::error::Error>> {
    use tokio_tungstenite::tungstenite::Message;
    use futures_util::{SinkExt, StreamExt};

    let ledger_tag = &ledger_id[..16.min(ledger_id.len())];

    eprintln!("Connecting to {}...", relay_url);
    let (mut ws, _) = tokio_tungstenite::connect_async(relay_url).await
        .map_err(|e| format!("Failed to connect to {}: {}", relay_url, e))?;

    // Send REQ with filter for Kind 9100 + ledger_id tag
    let sub_id = "replay";
    let filter = serde_json::json!({
        "kinds": [9100],
        "#d": [ledger_tag],
        "limit": 10000
    });
    let req = serde_json::json!(["REQ", sub_id, filter]);
    ws.send(Message::Text(req.to_string())).await?;

    let mut updates: Vec<SignedLedgerUpdate> = Vec::new();
    let mut event_count = 0u64;

    loop {
        let msg = match tokio::time::timeout(std::time::Duration::from_secs(15), ws.next()).await {
            Ok(Some(Ok(Message::Text(text)))) => text,
            Ok(Some(Ok(Message::Close(_)))) | Ok(None) => break,
            Ok(Some(Ok(_))) => continue,
            Ok(Some(Err(e))) => { eprintln!("WebSocket error: {}", e); break; }
            Err(_) => { eprintln!("Timeout waiting for relay response"); break; }
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
                        if let Ok(tlv_bytes) = BASE64.decode(content) {
                            if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                                updates.push(update);
                            }
                        }
                    }
                }
                event_count += 1;
            }
            Some("EOSE") => {
                // End of stored events
                break;
            }
            Some("NOTICE") => {
                if let Some(msg) = arr.get(1).and_then(|v| v.as_str()) {
                    eprintln!("Relay notice: {}", msg);
                }
            }
            _ => {}
        }
    }

    // Close subscription + websocket
    let close = serde_json::json!(["CLOSE", sub_id]);
    ws.send(Message::Text(close.to_string())).await.ok();
    ws.close(None).await.ok();

    eprintln!("Received {} events, decoded {} updates", event_count, updates.len());
    Ok(updates)
}

async fn run_nostr(relay_url: &str, ledger_id: &str, verbose: bool, until_hash: Option<&str>, decode_seq: Option<u64>, browse: bool) -> Result<(), Box<dyn std::error::Error>> {
    let mut updates = fetch_updates_from_relay(relay_url, ledger_id).await?;

    if updates.is_empty() {
        eprintln!("No updates found for ledger {}... on {}", &ledger_id[..16.min(ledger_id.len())], relay_url);
        std::process::exit(1);
    }

    // Sort by sequence, dedup
    updates.sort_by_key(|u| u.sequence_number);
    updates.dedup_by(|a, b| a.sequence_number == b.sequence_number && a.current_hash == b.current_hash);

    if browse {
        return browse_updates(&updates, decode_seq);
    }

    if let Some(seq) = decode_seq {
        match updates.iter().find(|u| u.sequence_number == seq) {
            Some(update) => { decode_update(update); return Ok(()); }
            None => {
                eprintln!("No update with sequence {} from relay", seq);
                std::process::exit(1);
            }
        }
    }

    // Walk backward from tip to build chain
    let chain_indices = build_chain(&updates);
    let chain: Vec<SignedLedgerUpdate> = chain_indices.iter().map(|&i| updates[i].clone()).collect();

    println!("nostr:{} ledger={}", relay_url, &ledger_id[..16.min(ledger_id.len())]);
    println!("{} updates in chain (of {} fetched)", chain.len(), updates.len());
    println!();

    let (state, errors) = replay_chain(&chain, verbose, until_hash);

    if !errors.is_empty() {
        println!("Errors ({}):", errors.len());
        for e in &errors { println!("  {}", e); }
        println!();
    }

    print_state(&state);
    Ok(())
}

// =========================================================================
// Annotated TLV Decode (replaces bin/decode-update.py)
// =========================================================================

#[cfg(unix)]
fn use_color() -> bool {
    extern "C" { fn isatty(fd: i32) -> i32; }
    std::env::var("NO_COLOR").is_err() && unsafe { isatty(1) != 0 }
}

#[cfg(not(unix))]
fn use_color() -> bool { false }

struct Col(bool);
impl Col {
    fn dim(&self, s: &str) -> String { if self.0 { format!("\x1b[2m{}\x1b[0m", s) } else { s.to_string() } }
    fn bold(&self, s: &str) -> String { if self.0 { format!("\x1b[1m{}\x1b[0m", s) } else { s.to_string() } }
    fn cyan(&self, s: &str) -> String { if self.0 { format!("\x1b[36m{}\x1b[0m", s) } else { s.to_string() } }
    fn green(&self, s: &str) -> String { if self.0 { format!("\x1b[32m{}\x1b[0m", s) } else { s.to_string() } }
    fn yellow(&self, s: &str) -> String { if self.0 { format!("\x1b[33m{}\x1b[0m", s) } else { s.to_string() } }
}

/// Read a BigEndian varint from a byte slice at `offset`. Returns (value, bytes_consumed).
fn read_varint_at(data: &[u8], offset: usize) -> Option<(u64, usize)> {
    if offset >= data.len() { return None; }
    match data[offset] {
        b @ 0..=0xfc => Some((b as u64, 1)),
        0xfd if offset + 3 <= data.len() =>
            Some((u16::from_be_bytes([data[offset+1], data[offset+2]]) as u64, 3)),
        0xfe if offset + 5 <= data.len() => {
            let mut buf = [0u8; 4];
            buf.copy_from_slice(&data[offset+1..offset+5]);
            Some((u32::from_be_bytes(buf) as u64, 5))
        }
        0xff if offset + 9 <= data.len() => {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&data[offset+1..offset+9]);
            Some((u64::from_be_bytes(buf), 9))
        }
        _ => None,
    }
}

#[derive(Copy, Clone, PartialEq)]
enum Enc { U8, U16, U32, U64, Pubkey, Hash, Sig, DepId, Str, Bytes, OpTlv, FeeTlv, Witness }

fn lookup_slu_field(tag: u64) -> (&'static str, Enc) {
    match tag {
        0  => ("operator_id", Enc::Pubkey),
        2  => ("ledger_id", Enc::Hash),
        4  => ("sequence_number", Enc::U64),
        6  => ("previous_hash", Enc::Hash),
        8  => ("message", Enc::OpTlv),
        10 => ("block_height", Enc::U32),
        12 => ("block_hash", Enc::Hash),
        14 => ("cosigner_pubkey", Enc::Pubkey),
        16 => ("member_ledger_hash", Enc::Hash),
        18 => ("cosign_signature", Enc::Sig),
        20 => ("operator_signature", Enc::Sig),
        _  => ("unknown", Enc::Bytes),
    }
}

fn lookup_op_field(tag: u64) -> (&'static str, Enc) {
    match tag {
        0   => ("discriminant", Enc::U8),
        2   => ("amount", Enc::U64),
        4   => ("spend_to", Enc::Pubkey),
        6   => ("quorum_members", Enc::Bytes),
        12  => ("fees", Enc::FeeTlv),
        14  => ("payment_hash", Enc::Hash),
        16  => ("invoice", Enc::Str),
        18  => ("cosigner_sig", Enc::Sig),
        20  => ("new_fees", Enc::FeeTlv),
        24  => ("deposit_pubkey", Enc::Pubkey),
        26  => ("invoice_id", Enc::Str),
        28  => ("sequence_number", Enc::U64),
        30  => ("payment_id", Enc::Hash),
        34  => ("preimage", Enc::Hash),
        36  => ("block_height", Enc::U32),
        38  => ("collateral_operator", Enc::Pubkey),
        40  => ("signature", Enc::Sig),
        42  => ("ledger_hash", Enc::Hash),
        44  => ("quorum_member", Enc::Pubkey),
        46  => ("quorum_member_sig", Enc::Sig),
        48  => ("operator_sig", Enc::Sig),
        56  => ("operator_id", Enc::Pubkey),
        58  => ("reserves_id", Enc::Str),
        62  => ("reserves_amount", Enc::U64),
        66  => ("txid", Enc::Hash),
        68  => ("vout", Enc::U32),
        70  => ("destination_address", Enc::Str),
        72  => ("withdrawal_id", Enc::Hash),
        74  => ("funding_address", Enc::Str),
        76  => ("lock_until_block", Enc::U32),
        // tag 80 (our_signature) removed from QuorumJoin
        82  => ("membership_expires", Enc::U32),
        84  => ("new_outpoint_txid", Enc::Hash),
        86  => ("quorum_expiry", Enc::U32),
        88  => ("total_collateral", Enc::U64),
        90  => ("spending_txid", Enc::Hash),
        92  => ("new_outpoint_vout", Enc::U32),
        96  => ("genesis_block", Enc::U32),
        100 => ("reason", Enc::Str),
        102 => ("last_valid_sequence", Enc::U64),
        106 => ("entropy_block_hash", Enc::Hash),
        108 => ("new_custodian", Enc::Pubkey),
        110 => ("spend_txid", Enc::Hash),
        112 => ("commitment_hash", Enc::Hash),
        114 => ("member_ledger_id", Enc::Str),
        116 => ("entropy_block_height", Enc::U32),
        118 => ("armed_block", Enc::U32),
        120 => ("new_reserves_address", Enc::Str),
        122 => ("target_reserves", Enc::U64),
        124 => ("collateral_ledger_id", Enc::Str),
        200 => ("deposit_id", Enc::DepId),
        202 => ("descriptor", Enc::Str),
        204 => ("witness", Enc::Witness),
        208 => ("new_descriptor", Enc::Str),
        210 => ("nonce", Enc::Hash),
        212 => ("source_deposit_id", Enc::DepId),
        214 => ("destination_deposit_id", Enc::DepId),
        216 => ("completion_script", Enc::Bytes),
        218 => ("timeout_height", Enc::U32),
        220 => ("transfer_id", Enc::Hash),
        222 => ("block_hash", Enc::Hash),
        224 => ("script_witness", Enc::Witness),
        226 => ("transfer_fees", Enc::FeeTlv),
        228 => ("fail_reason", Enc::U8),
        230 => ("is_collateral", Enc::U8),
        232 => ("receive_requires_sig", Enc::U8),
        234 => ("min_fee_bps", Enc::U16),
        236 => ("min_fee_fixed", Enc::U64),
        238 => ("max_fee_period", Enc::U32),
        240 => ("collateral_lock_amount", Enc::U64),
        242 => ("collateral_lock_until", Enc::U32),
        244 => ("fee_change_after", Enc::U32),
        246 => ("fee_change_notice", Enc::U32),
        248 => ("fee_change_limit_bps", Enc::U16),
        250 => ("effective_block", Enc::U32),
        252 => ("dispute_response_blocks", Enc::U32),
        254 => ("dispute_arm_blocks", Enc::U32),
        256 => ("service_response_blocks", Enc::U32),
        258 => ("max_transfer_timeout_blocks", Enc::U32),
        262 => ("max_descriptor_bytes", Enc::U32),
        270 => ("request_hash", Enc::Hash),
        272 => ("target_ledger_id", Enc::Hash),
        274 => ("target_operator", Enc::Pubkey),
        _   => ("unknown", Enc::Bytes),
    }
}

fn lookup_fee_field(tag: u64) -> (&'static str, Enc) {
    match tag {
        0 => ("annualized_msats", Enc::U64),
        2 => ("annualized_bps", Enc::U16),
        4 => ("frequency_blocks", Enc::U32),
        _ => ("unknown", Enc::Bytes),
    }
}

fn discriminant_name(disc: u8) -> &'static str {
    match disc {
        1  => "LedgerOpen",        12 => "QuorumBegin",
        20 => "DepositOpen",       21 => "DepositClose",
        22 => "FeeChange",         23 => "DepositKeyRotate",
        30 => "InvoiceCredit",     31 => "InvoiceLock",
        32 => "InvoiceFail",       33 => "InvoiceFulfill",
        35 => "OnchainCredit",     36 => "OnchainLock",
        37 => "OnchainFail",       38 => "OnchainFulfill",
        42 => "CollateralAttestation", 43 => "QuorumAddMember",
        44 => "QuorumRemoveMember",45 => "CollateralLock",
        46 => "QuorumJoin",        50 => "FeeCollect",
        54 => "DisputeEnter",      55 => "DisputeAcquire",
        56 => "DisputeYield",      57 => "DisputeArmed",
        60 => "LedgerClose",       70 => "TransferLock",
        71 => "TransferComplete",  72 => "TransferFail",
        80 => "DeliveryEmbed",
        _  => "unknown",
    }
}

fn format_field_value(val: &[u8], enc: Enc, name: &str, col: &Col) -> String {
    match enc {
        Enc::U8 => {
            let v = val.first().copied().unwrap_or(0);
            if name == "discriminant" {
                format!("{} = {}", v, col.green(discriminant_name(v)))
            } else if name == "is_collateral" || name == "receive_requires_sig" {
                format!("{} ({})", v, if v != 0 { "true" } else { "false" })
            } else {
                format!("{}", v)
            }
        }
        Enc::U16 => {
            if val.len() >= 2 {
                format!("{}", u16::from_be_bytes([val[0], val[1]]))
            } else { "0".into() }
        }
        Enc::U32 => {
            if val.len() >= 4 {
                let v = u32::from_be_bytes([val[0], val[1], val[2], val[3]]);
                format!("{} {}", v, col.dim(&format!("(0x{:x})", v)))
            } else { "0".into() }
        }
        Enc::U64 => {
            if val.len() >= 8 {
                let v = u64::from_be_bytes([val[0], val[1], val[2], val[3], val[4], val[5], val[6], val[7]]);
                if v == 0 { return "0".into(); }
                let hint = if v >= 1_000_000_000 {
                    let sats = v / 1000;
                    let rem = v % 1000;
                    if rem == 0 { format!("({})", format_sats(sats)) }
                    else { format!("({}.{:03} sat)", format_sats(sats), rem) }
                } else if v >= 1000 {
                    format!("({})", format_sats(v))
                } else { String::new() };
                if hint.is_empty() { format!("{}", v) }
                else { format!("{} {}", v, col.dim(&hint)) }
            } else { "0".into() }
        }
        Enc::Pubkey => col.yellow(&hex::encode(val)),
        Enc::Hash | Enc::Sig => {
            if val.iter().all(|&b| b == 0) { col.dim("(zero)") }
            else {
                let h = hex::encode(val);
                if h.len() > 20 { col.yellow(&format!("{}...", &h[..16])) }
                else { col.yellow(&h) }
            }
        }
        Enc::DepId => col.yellow(&hex::encode(val)),
        Enc::Str => {
            match std::str::from_utf8(val) {
                Ok(s) if s.len() > 60 => col.yellow(&format!("\"{}...\"", &s[..57])),
                Ok(s) => col.yellow(&format!("\"{}\"", s)),
                Err(_) => hex::encode(val),
            }
        }
        Enc::Bytes => {
            let h = hex::encode(val);
            if h.len() > 40 { format!("{} {}", &h[..40], col.dim(&format!("...{} bytes total", val.len()))) }
            else { h }
        }
        Enc::OpTlv | Enc::FeeTlv => col.dim(&format!("({} bytes, nested TLV)", val.len())),
        Enc::Witness => {
            if let Some((count, _)) = read_varint_at(val, 0) {
                col.dim(&format!("({} element(s))", count))
            } else { col.dim("(witness)") }
        }
    }
}

fn print_tlv_annotated(
    data: &[u8],
    base_offset: usize,
    lookup: fn(u64) -> (&'static str, Enc),
    depth: usize,
    col: &Col,
) {
    let indent = "  ".repeat(depth);
    let mut offset = 0;

    while offset < data.len() {
        let record_start = offset;

        let (tag, tag_sz) = match read_varint_at(data, offset) {
            Some(v) => v, None => break,
        };
        offset += tag_sz;

        let (length, _len_sz) = match read_varint_at(data, offset) {
            Some(v) => v, None => break,
        };
        offset += _len_sz;

        let val_start = offset;
        let val_end = (offset + length as usize).min(data.len());
        let val = &data[val_start..val_end];
        offset = val_end;

        let (name, enc) = lookup(tag);
        let abs_off = base_offset + record_start;
        let abs_val = base_offset + val_start;

        // Header line: tag + length bytes
        let hdr = &data[record_start..val_start];
        let hdr_hex: String = hdr.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
        println!("  {}{}  {:<51}  {}{}  {}",
            col.dim(&format!("{:04x}", abs_off)), indent,
            hdr_hex,
            col.cyan(&format!("tag={}", tag)),
            col.dim(&format!(" len={}", length)),
            col.bold(name));

        // Value lines — skip raw hex for nested types that we destructure below
        let nested = matches!(enc, Enc::OpTlv | Enc::FeeTlv | Enc::Witness);
        if !nested {
            let display = format_field_value(val, enc, name, col);
            if val.len() <= 17 {
                let val_hex: String = val.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
                println!("  {}{}  {:<51}  {}",
                    col.dim(&format!("{:04x}", abs_val)), indent, val_hex, display);
            } else {
                let first: String = val[..17].iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
                println!("  {}{}  {:<51}  {}",
                    col.dim(&format!("{:04x}", abs_val)), indent, first, display);
                for i in (17..val.len()).step_by(17) {
                    let end = (i + 17).min(val.len());
                    let line: String = val[i..end].iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
                    println!("  {}{}  {}",
                        col.dim(&format!("{:04x}", abs_val + i)), indent, line);
                }
            }
        }

        // Recurse into nested TLV
        match enc {
            Enc::OpTlv => print_tlv_annotated(val, abs_val, lookup_op_field, depth + 1, col),
            Enc::FeeTlv => print_tlv_annotated(val, abs_val, lookup_fee_field, depth + 1, col),
            Enc::Witness if !val.is_empty() => {
                let mut woff = 0usize;
                if let Some((count, sz)) = read_varint_at(val, woff) {
                    woff += sz;
                    for i in 0..count as usize {
                        if let Some((elen, esz)) = read_varint_at(val, woff) {
                            woff += esz;
                            let eend = (woff + elen as usize).min(val.len());
                            let elem = &val[woff..eend];
                            let eh = hex::encode(elem);
                            let display = if eh.len() > 40 { format!("{}...", &eh[..40]) } else { eh };
                            println!("  {}{}    elem[{}]: {} {}",
                                col.dim(&format!("{:04x}", abs_val + woff)), indent,
                                i, col.yellow(&display), col.dim(&format!("({} bytes)", elen)));
                            woff = eend;
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

fn decode_update(update: &SignedLedgerUpdate) {
    let bytes = update.tlv_encode();
    let col = Col(use_color());

    println!("\n{}  ({} bytes)\n", col.bold("SignedLedgerUpdate"), bytes.len());
    print_tlv_annotated(&bytes, 0, lookup_slu_field, 0, &col);

    // Derived values
    println!("\n{}", col.bold("--- Derived ---"));
    println!("  current_hash:  {}", hex::encode(update.current_hash));
    println!("  chain_hash:    {}", hex::encode(update.chain_hash()));

    if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
        println!("  seq={}  op={}", update.sequence_number, format_op(&op));
    } else {
        println!("  seq={}", update.sequence_number);
    }
    println!();
}

// =========================================================================
// TUI Browse Mode
// =========================================================================

use ratatui::{
    DefaultTerminal,
    layout::{Constraint, Layout},
    style::{Color, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, List, ListItem, ListState, Paragraph},
};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, MouseEventKind};

/// Short label for the left panel list.
fn update_label(update: &SignedLedgerUpdate) -> String {
    let cosigned = if update.cosigner_pubkey.is_some() { " *" } else { "" };
    // Peek at discriminant byte directly: tag=0, len=1, disc_byte
    let name = if update.message.len() >= 3 && update.message[0] == 0 && update.message[1] == 1 {
        discriminant_name(update.message[2])
    } else { "unknown" };
    format!("{:>4}  {}{}", update.sequence_number, name, cosigned)
}

/// Styled variant of format_field_value — returns Spans for ratatui.
fn format_field_spans(val: &[u8], enc: Enc, name: &str) -> Vec<Span<'static>> {
    let dim = Style::default().dim();
    let yellow = Style::default().fg(Color::Yellow);
    let green = Style::default().fg(Color::Green);

    match enc {
        Enc::U8 => {
            let v = val.first().copied().unwrap_or(0);
            if name == "discriminant" {
                vec![Span::raw(format!("{} = ", v)), Span::styled(discriminant_name(v).to_string(), green)]
            } else if name == "is_collateral" || name == "receive_requires_sig" {
                vec![Span::raw(format!("{} ({})", v, if v != 0 { "true" } else { "false" }))]
            } else {
                vec![Span::raw(format!("{}", v))]
            }
        }
        Enc::U16 => {
            let v = if val.len() >= 2 { u16::from_be_bytes([val[0], val[1]]) } else { 0 };
            vec![Span::raw(format!("{}", v))]
        }
        Enc::U32 => {
            let v = if val.len() >= 4 { u32::from_be_bytes([val[0], val[1], val[2], val[3]]) } else { 0 };
            vec![Span::raw(format!("{} ", v)), Span::styled(format!("(0x{:x})", v), dim)]
        }
        Enc::U64 => {
            let v = if val.len() >= 8 {
                u64::from_be_bytes([val[0], val[1], val[2], val[3], val[4], val[5], val[6], val[7]])
            } else { 0 };
            if v == 0 { return vec![Span::raw("0".to_string())]; }
            let hint = if v >= 1_000_000_000 {
                let sats = v / 1000; let rem = v % 1000;
                if rem == 0 { format!("({})", format_sats(sats)) }
                else { format!("({}.{:03} sat)", format_sats(sats), rem) }
            } else if v >= 1000 {
                format!("({})", format_sats(v))
            } else { String::new() };
            if hint.is_empty() { vec![Span::raw(format!("{}", v))] }
            else { vec![Span::raw(format!("{} ", v)), Span::styled(hint, dim)] }
        }
        Enc::Pubkey => vec![Span::styled(hex::encode(val), yellow)],
        Enc::Hash | Enc::Sig => {
            if val.iter().all(|&b| b == 0) {
                vec![Span::styled("(zero)".to_string(), dim)]
            } else {
                let h = hex::encode(val);
                if h.len() > 20 { vec![Span::styled(format!("{}...", &h[..16]), yellow)] }
                else { vec![Span::styled(h, yellow)] }
            }
        }
        Enc::DepId => vec![Span::styled(hex::encode(val), yellow)],
        Enc::Str => match std::str::from_utf8(val) {
            Ok(s) if s.len() > 60 => vec![Span::styled(format!("\"{}...\"", &s[..57]), yellow)],
            Ok(s) => vec![Span::styled(format!("\"{}\"", s), yellow)],
            Err(_) => vec![Span::raw(hex::encode(val))],
        },
        Enc::Bytes => {
            let h = hex::encode(val);
            if h.len() > 40 { vec![Span::raw(format!("{} ", &h[..40])), Span::styled(format!("...{} bytes total", val.len()), dim)] }
            else { vec![Span::raw(h)] }
        }
        Enc::OpTlv | Enc::FeeTlv => vec![Span::styled(format!("({} bytes, nested TLV)", val.len()), dim)],
        Enc::Witness => {
            if let Some((count, _)) = read_varint_at(val, 0) {
                vec![Span::styled(format!("({} element(s))", count), dim)]
            } else { vec![Span::styled("(witness)".to_string(), dim)] }
        }
    }
}

/// Styled variant of print_tlv_annotated — returns Lines for ratatui.
fn tlv_lines(
    data: &[u8], base_offset: usize,
    lookup: fn(u64) -> (&'static str, Enc), depth: usize,
) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    let indent = "  ".repeat(depth);
    let dim = Style::default().dim();
    let cyan = Style::default().fg(Color::Cyan);
    let bold_s = Style::default().bold();
    let yellow = Style::default().fg(Color::Yellow);
    let mut offset = 0;

    while offset < data.len() {
        let record_start = offset;
        let (tag, tsz) = match read_varint_at(data, offset) { Some(v) => v, None => break };
        offset += tsz;
        let (length, lsz) = match read_varint_at(data, offset) { Some(v) => v, None => break };
        offset += lsz;
        let val_start = offset;
        let val_end = (offset + length as usize).min(data.len());
        let val = &data[val_start..val_end];
        offset = val_end;

        let (name, enc) = lookup(tag);
        let abs_off = base_offset + record_start;
        let abs_val = base_offset + val_start;

        // Header line
        let hdr = &data[record_start..val_start];
        let hdr_hex: String = hdr.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
        lines.push(Line::from(vec![
            Span::styled(format!("  {:04x}", abs_off), dim),
            Span::raw(indent.clone()),
            Span::raw(format!("  {:<51}  ", hdr_hex)),
            Span::styled(format!("tag={}", tag), cyan),
            Span::styled(format!(" len={}", length), dim),
            Span::raw("  "), Span::styled(name.to_string(), bold_s),
        ]));

        // Value line(s) — skip raw hex for nested types that we destructure below
        let nested = matches!(enc, Enc::OpTlv | Enc::FeeTlv | Enc::Witness);
        if !nested {
            let display = format_field_spans(val, enc, name);
            if val.len() <= 17 {
                let vh: String = val.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
                let mut s = vec![
                    Span::styled(format!("  {:04x}", abs_val), dim),
                    Span::raw(indent.clone()),
                    Span::raw(format!("  {:<51}  ", vh)),
                ];
                s.extend(display);
                lines.push(Line::from(s));
            } else {
                let first: String = val[..17].iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
                let mut s = vec![
                    Span::styled(format!("  {:04x}", abs_val), dim),
                    Span::raw(indent.clone()),
                    Span::raw(format!("  {:<51}  ", first)),
                ];
                s.extend(display);
                lines.push(Line::from(s));
                for i in (17..val.len()).step_by(17) {
                    let end = (i + 17).min(val.len());
                    let ch: String = val[i..end].iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
                    lines.push(Line::from(vec![
                        Span::styled(format!("  {:04x}", abs_val + i), dim),
                        Span::raw(indent.clone()), Span::raw(format!("  {}", ch)),
                    ]));
                }
            }
        }

        // Recurse
        match enc {
            Enc::OpTlv => lines.extend(tlv_lines(val, abs_val, lookup_op_field, depth + 1)),
            Enc::FeeTlv => lines.extend(tlv_lines(val, abs_val, lookup_fee_field, depth + 1)),
            Enc::Witness if !val.is_empty() => {
                let mut woff = 0usize;
                if let Some((count, sz)) = read_varint_at(val, woff) {
                    woff += sz;
                    for i in 0..count as usize {
                        if let Some((elen, esz)) = read_varint_at(val, woff) {
                            woff += esz;
                            let eend = (woff + elen as usize).min(val.len());
                            let elem = &val[woff..eend];
                            let eh = hex::encode(elem);
                            let d = if eh.len() > 40 { format!("{}...", &eh[..40]) } else { eh };
                            lines.push(Line::from(vec![
                                Span::styled(format!("  {:04x}", abs_val + woff), dim),
                                Span::raw(format!("{}    ", indent)),
                                Span::raw(format!("elem[{}]: ", i)),
                                Span::styled(d, yellow),
                                Span::styled(format!(" ({} bytes)", elen), dim),
                            ]));
                            woff = eend;
                        }
                    }
                }
            }
            _ => {}
        }
    }
    lines
}

/// Build the full styled decode for one update (right panel content).
fn decode_lines(update: &SignedLedgerUpdate) -> Vec<Line<'static>> {
    let bytes = update.tlv_encode();
    let dim = Style::default().dim();
    let bold_s = Style::default().bold();
    let mut lines = Vec::new();

    lines.push(Line::from(vec![
        Span::styled("SignedLedgerUpdate".to_string(), bold_s),
        Span::styled(format!("  ({} bytes)", bytes.len()), dim),
    ]));
    lines.push(Line::raw(""));
    lines.extend(tlv_lines(&bytes, 0, lookup_slu_field, 0));

    lines.push(Line::raw(""));
    lines.push(Line::styled("--- Derived ---".to_string(), bold_s));
    lines.push(Line::raw(format!("  current_hash:  {}", hex::encode(update.current_hash))));
    lines.push(Line::raw(format!("  chain_hash:    {}", hex::encode(update.chain_hash()))));
    if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
        lines.push(Line::raw(format!("  seq={}  op={}", update.sequence_number, format_op(&op))));
    }
    lines.push(Line::raw(""));
    lines
}

struct BrowseState {
    list_state: ListState,
    labels: Vec<String>,
    right_lines: Vec<Line<'static>>,
    right_scroll: u16,
    cached_idx: Option<usize>,
}

fn refresh_right(state: &mut BrowseState, updates: &[SignedLedgerUpdate]) {
    if let Some(idx) = state.list_state.selected() {
        if idx >= updates.len() {
            state.list_state.select(Some(updates.len().saturating_sub(1)));
            return refresh_right(state, updates);
        }
        if state.cached_idx != Some(idx) {
            state.right_lines = decode_lines(&updates[idx]);
            state.cached_idx = Some(idx);
            state.right_scroll = 0;
        }
    }
}

fn browse_loop(
    terminal: &mut DefaultTerminal,
    state: &mut BrowseState,
    updates: &[SignedLedgerUpdate],
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        terminal.draw(|frame| {
            let [left, right] = Layout::horizontal([
                Constraint::Length(32),
                Constraint::Fill(1),
            ]).areas(frame.area());

            // Left: update list
            let items: Vec<ListItem> = state.labels.iter()
                .map(|l| ListItem::new(l.as_str()))
                .collect();
            let list = List::new(items)
                .block(Block::bordered().title(" Updates "))
                .highlight_style(Style::default().bg(Color::DarkGray).bold())
                .highlight_symbol("▸ ");
            frame.render_stateful_widget(list, left, &mut state.list_state);

            // Right: TLV decode
            let title = if let Some(idx) = state.list_state.selected() {
                format!(" seq {} ", updates[idx].sequence_number)
            } else { " Decode ".to_string() };
            let para = Paragraph::new(state.right_lines.clone())
                .block(Block::bordered().title(title))
                .scroll((state.right_scroll, 0));
            frame.render_widget(para, right);
        })?;

        if event::poll(std::time::Duration::from_millis(50))? {
            match event::read()? {
                Event::Key(key) => {
                    if key.kind != KeyEventKind::Press { continue; }
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => break,
                        KeyCode::Down | KeyCode::Char('j') => {
                            state.list_state.select_next();
                            refresh_right(state, updates);
                        }
                        KeyCode::Up | KeyCode::Char('k') => {
                            state.list_state.select_previous();
                            refresh_right(state, updates);
                        }
                        KeyCode::Home | KeyCode::Char('g') => {
                            state.list_state.select_first();
                            refresh_right(state, updates);
                        }
                        KeyCode::End | KeyCode::Char('G') => {
                            state.list_state.select_last();
                            refresh_right(state, updates);
                        }
                        KeyCode::PageDown | KeyCode::Char(' ') => {
                            state.right_scroll = state.right_scroll.saturating_add(20);
                        }
                        KeyCode::PageUp => {
                            state.right_scroll = state.right_scroll.saturating_sub(20);
                        }
                        _ => {}
                    }
                }
                Event::Mouse(mouse) => {
                    let in_left = mouse.column < 32;
                    match mouse.kind {
                        MouseEventKind::ScrollUp => {
                            if in_left {
                                state.list_state.select_previous();
                                refresh_right(state, updates);
                            } else {
                                state.right_scroll = state.right_scroll.saturating_sub(3);
                            }
                        }
                        MouseEventKind::ScrollDown => {
                            if in_left {
                                state.list_state.select_next();
                                refresh_right(state, updates);
                            } else {
                                state.right_scroll = state.right_scroll.saturating_add(3);
                            }
                        }
                        MouseEventKind::Down(_) if in_left => {
                            // Click in left panel: row 0 is border, rows 1..N are items
                            let row = mouse.row as usize;
                            if row >= 1 {
                                let offset = state.list_state.offset();
                                let idx = offset + row - 1;
                                if idx < updates.len() {
                                    state.list_state.select(Some(idx));
                                    refresh_right(state, updates);
                                }
                            }
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }
    }
    Ok(())
}

fn browse_updates(updates: &[SignedLedgerUpdate], start_seq: Option<u64>) -> Result<(), Box<dyn std::error::Error>> {
    if updates.is_empty() {
        eprintln!("No updates to browse");
        std::process::exit(1);
    }

    let labels: Vec<String> = updates.iter().map(update_label).collect();
    let start_idx = start_seq
        .and_then(|seq| updates.iter().position(|u| u.sequence_number == seq))
        .unwrap_or(0);

    let mut state = BrowseState {
        list_state: ListState::default().with_selected(Some(start_idx)),
        labels,
        right_lines: Vec::new(),
        right_scroll: 0,
        cached_idx: None,
    };
    refresh_right(&mut state, updates);

    let mut terminal = ratatui::try_init().map_err(|e| {
        format!("--browse requires a terminal: {}", e)
    })?;
    crossterm::execute!(std::io::stdout(), crossterm::event::EnableMouseCapture)?;
    let result = browse_loop(&mut terminal, &mut state, updates);
    crossterm::execute!(std::io::stdout(), crossterm::event::DisableMouseCapture)?;
    ratatui::restore();
    result
}

// =========================================================================
// Main
// =========================================================================

fn print_help() {
    eprintln!("Usage: replay-ledger [ledger_id_prefix] [options]");
    eprintln!();
    eprintln!("Replays a ledger chain: walks backward from tip, plays forward through");
    eprintln!("LedgerState, and pretty-prints the result.");
    eprintln!();
    eprintln!("With no prefix (or a prefix matching multiple ledgers), lists available");
    eprintln!("ledgers. Works in both JSONL and relay modes.");
    eprintln!();
    eprintln!("Modes:");
    eprintln!("  JSONL (default):  Reads from data/<node>/wallet/ledgers/<id>.jsonl");
    eprintln!("  Nostr:            Fetches Kind 9100 events from a relay (--relay)");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --relay <url>           Fetch from Nostr relay (ws:// or wss://)");
    eprintln!("  --data-root, -d <path>  JSONL data directory (default: ./data)");
    eprintln!("  --node, -n <name>       Only search this node's ledgers (JSONL mode)");
    eprintln!("  --until <hash_prefix>   Stop replay at this chain_hash");
    eprintln!("  --decode <seq>          Annotated TLV hexdump of a single update");
    eprintln!("  --browse                TUI browser (up/down to navigate, q to quit)");
    eprintln!("  --verbose, -v           Print each operation as it's applied");
    eprintln!("  --help, -h              Show this help");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  replay-ledger                               # List all local ledgers");
    eprintln!("  replay-ledger 183c -n alice -v              # JSONL, verbose");
    eprintln!("  replay-ledger 183c --until a536             # JSONL, stop at hash");
    eprintln!("  replay-ledger 183c --decode 5               # Decode seq 5");
    eprintln!("  replay-ledger 183c --browse                 # TUI browser");
    eprintln!("  replay-ledger 183c --browse --decode 5      # Browse starting at seq 5");
    eprintln!("  replay-ledger --relay ws://localhost:7779    # List ledgers on relay");
    eprintln!("  replay-ledger 183c --relay ws://localhost:7779        # Prefix match");
    eprintln!("  replay-ledger 183c96af... --relay ws://localhost:7779 # Full replay");
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let mut data_root = PathBuf::from(DEFAULT_DATA_ROOT);
    let mut prefix = String::new();
    let mut node_filter: Option<String> = None;
    let mut relay_url: Option<String> = None;
    let mut until_hash: Option<String> = None;
    let mut decode_seq: Option<u64> = None;
    let mut browse = false;
    let mut verbose = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--data-root" | "-d" if i + 1 < args.len() => {
                data_root = PathBuf::from(&args[i + 1]);
                i += 2;
            }
            "--node" | "-n" if i + 1 < args.len() => {
                node_filter = Some(args[i + 1].clone());
                i += 2;
            }
            "--relay" | "-r" if i + 1 < args.len() => {
                relay_url = Some(args[i + 1].clone());
                i += 2;
            }
            "--until" if i + 1 < args.len() => {
                until_hash = Some(args[i + 1].clone());
                i += 2;
            }
            "--decode" if i + 1 < args.len() => {
                decode_seq = Some(args[i + 1].parse().expect("--decode requires a sequence number"));
                i += 2;
            }
            "--browse" => { browse = true; i += 1; }
            "--verbose" | "-v" => { verbose = true; i += 1; }
            "--help" | "-h" => { print_help(); return Ok(()); }
            other => {
                if prefix.is_empty() && !other.starts_with('-') {
                    prefix = other.to_string();
                }
                i += 1;
            }
        }
    }

    if let Some(url) = relay_url {
        // Nostr mode
        let rt = tokio::runtime::Runtime::new()?;
        // Short or empty prefix: list ledgers, auto-select single match
        if prefix.is_empty() || prefix.len() < 16 {
            let selected = rt.block_on(list_relay_ledgers(&url, &prefix))?;
            match selected {
                Some(lid) => rt.block_on(run_nostr(&url, &lid, verbose, until_hash.as_deref(), decode_seq, browse)),
                None => Ok(()),
            }
        } else {
            rt.block_on(run_nostr(&url, &prefix, verbose, until_hash.as_deref(), decode_seq, browse))
        }
    } else {
        // JSONL mode
        if !data_root.exists() {
            eprintln!("Data root not found: {}. Use --data-root or --relay.", data_root.display());
            std::process::exit(1);
        }
        run_jsonl(&data_root, &prefix, node_filter.as_deref(), verbose, until_hash.as_deref(), decode_seq, browse)
    }
}
