//! Shared ledger audit / solvency computation.
//!
//! Given a set of signed ledger updates (any order), this orders them into the
//! canonical chain, replays them through `LedgerState::apply_signed` — the same
//! state machine the node and `replay-ledger` use — and reports the headline
//! audit figures: obligations (Σ deposit balance) vs reserves, locked funds,
//! collateral, an op-type tally, and a solvency verdict.
//!
//! The balance arithmetic is NOT reimplemented here; it lives in
//! `deposits-core`'s `LedgerState`. This crate only orders, drives the replay,
//! and reads the resulting totals — so the CLI and the browser (via
//! `deposits-audit-wasm`) produce identical numbers.

use deposits_core::dep16::Dep16Authorizer;
use deposits_core::messages::LedgerOperation;
use deposits_core::{LedgerState, SignedLedgerUpdate, TlvDecode};
use std::collections::{BTreeMap, HashMap};

/// Headline audit result for one ledger.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuditReport {
    /// Number of live deposits after replay.
    pub deposits: usize,
    /// Total obligation backed by reserves: Σ deposit balance (msats).
    /// `locked` is a subset of this, not additive — see deposits-core.
    pub obligations_msats: u64,
    /// Funds earmarked for in-flight ops (a subset of obligations), msats.
    pub locked_msats: u64,
    /// Declared reserves backing obligations (msats).
    pub reserves_msats: u64,
    /// Declared quorum collateral (msats).
    pub collateral_msats: u64,
    /// `reserves_msats >= obligations_msats`. Locked is NOT added — doing so
    /// double-counts in-flight earmarks (the bug that wedged make_invoice).
    pub solvent: bool,
    /// Highest applied sequence number.
    pub sequence: u64,
    /// Count of each operation type in the replayed chain (e.g. how many
    /// InvoiceCredit vs InvoiceFulfill — surfaces credits-without-fulfills).
    pub op_counts: BTreeMap<String, u32>,
    /// Number of updates that failed to decode or apply during replay.
    pub replay_errors: usize,
}

/// Variant name of an operation (e.g. "InvoiceLock"), used for the op tally.
fn op_name(op: &LedgerOperation) -> String {
    let dbg = format!("{:?}", op);
    dbg.split(|c| c == ' ' || c == '{' || c == '(')
        .next()
        .unwrap_or("Unknown")
        .to_string()
}

/// Order updates into the canonical chain by walking backward from the
/// highest-sequence tip via `chain_hash`, with a sequence-number fallback.
/// Returns indices into `updates` in genesis-first order.
pub fn build_chain(updates: &[SignedLedgerUpdate]) -> Vec<usize> {
    if updates.is_empty() {
        return vec![];
    }

    let mut by_chain_hash: HashMap<[u8; 32], usize> = HashMap::new();
    for (i, u) in updates.iter().enumerate() {
        by_chain_hash.insert(u.chain_hash(), i);
    }

    // Start from the highest-sequence update (the tip), not merely the last
    // element — the input may arrive unordered from a relay.
    let mut current_idx = 0usize;
    for (i, u) in updates.iter().enumerate() {
        if u.sequence_number >= updates[current_idx].sequence_number {
            current_idx = i;
        }
    }

    let mut chain = vec![current_idx];
    loop {
        let u = &updates[current_idx];
        if u.previous_hash == [0u8; 32] {
            break;
        }
        if let Some(&prev) = by_chain_hash.get(&u.previous_hash) {
            chain.push(prev);
            current_idx = prev;
        } else if u.sequence_number > 0 {
            if let Some(pos) = updates
                .iter()
                .position(|x| x.sequence_number == u.sequence_number - 1)
            {
                chain.push(pos);
                current_idx = pos;
                continue;
            } else {
                break;
            }
        } else {
            break;
        }
    }

    chain.reverse();
    chain
}

/// Replay a set of signed updates and report the audit figures.
///
/// Mirrors `replay-ledger`: builds the chain, drives `apply_signed` with a
/// strict `Dep16Authorizer` (chain_tip = 0, the read-only replay reading),
/// and tolerates per-update failures (counted in `replay_errors`) so a single
/// bad update doesn't abort the whole audit.
pub fn audit_updates(updates: &[SignedLedgerUpdate]) -> AuditReport {
    let mut op_counts: BTreeMap<String, u32> = BTreeMap::new();
    let mut replay_errors = 0usize;

    if updates.is_empty() {
        return AuditReport {
            deposits: 0,
            obligations_msats: 0,
            locked_msats: 0,
            reserves_msats: 0,
            collateral_msats: 0,
            solvent: true,
            sequence: 0,
            op_counts,
            replay_errors,
        };
    }

    let order = build_chain(updates);
    let chain: Vec<&SignedLedgerUpdate> = order.iter().map(|&i| &updates[i]).collect();

    // Seed state from the genesis op (LedgerOpen) when present.
    let first = chain[0];
    let (operator_key, reserves_key, genesis_block) = match LedgerOperation::tlv_decode(&first.message)
    {
        Ok(LedgerOperation::LedgerOpen {
            operator_id,
            reserves_id,
            genesis_block,
            ..
        }) => (operator_id, reserves_id, genesis_block),
        _ => (first.operator_id, String::new(), 0),
    };
    let mut state = LedgerState::new(operator_key, reserves_key, genesis_block);
    let authorizer = Dep16Authorizer::new();

    for update in &chain {
        match LedgerOperation::tlv_decode(&update.message) {
            Ok(op) => {
                *op_counts.entry(op_name(&op)).or_insert(0) += 1;
                match state.apply_signed(update, &authorizer) {
                    Ok(next) => state = next,
                    Err(_) => {
                        replay_errors += 1;
                        state.sequence = update.sequence_number;
                        state.chain_tip_hash = update.chain_hash();
                    }
                }
            }
            Err(_) => {
                replay_errors += 1;
                state.sequence = update.sequence_number;
                state.chain_tip_hash = update.chain_hash();
            }
        }
    }

    let obligations_msats = state.total_deposit_balance();
    let locked_msats = state.total_locked_balance();
    let reserves_msats = state.reserves_amount;
    let collateral_msats = state.total_collateral();
    // Obligation = Σ balance only; locked is a subset, not additive.
    let solvent = reserves_msats >= obligations_msats;

    AuditReport {
        deposits: state.deposits.len(),
        obligations_msats,
        locked_msats,
        reserves_msats,
        collateral_msats,
        solvent,
        sequence: state.sequence,
        op_counts,
        replay_errors,
    }
}

/// Convenience: decode a set of base64-encoded TLV update blobs (as the
/// explorer/relay serve them) and audit them. Blobs that fail base64 or TLV
/// decode are counted in `replay_errors`.
pub fn audit_base64(blobs: &[String]) -> AuditReport {
    use base64::Engine;
    let mut updates = Vec::with_capacity(blobs.len());
    let mut predecode_errors = 0usize;
    for b in blobs {
        match base64::engine::general_purpose::STANDARD.decode(b) {
            Ok(bytes) => match SignedLedgerUpdate::tlv_decode(&bytes) {
                Ok(u) => updates.push(u),
                Err(_) => predecode_errors += 1,
            },
            Err(_) => predecode_errors += 1,
        }
    }
    let mut rep = audit_updates(&updates);
    rep.replay_errors += predecode_errors;
    rep
}
