//! Lottery participants: the DEP-03 §"Replacement collateral declaration"
//! eligibility cut.
//!
//! Every site that builds, verifies or reconstructs a dispute's lottery
//! takes its participant set from [`eligible_armers`], so the operator who
//! proposes the confiscation, each cosigner, the claimant and the recovery
//! paths all agree. A failing declaration excludes that armer; it never
//! stalls the dispute.

use bitcoin::secp256k1::{PublicKey, XOnlyPublicKey};
use bitcoin::{OutPoint, Txid};
use deposits_core::messages::{LedgerOperation, ReplacementCollateral};
use deposits_core::tapscript_reserves::LotteryParticipant;
use deposits_core::{SignedLedgerUpdate, TlvDecode};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use crate::chain_backend::ChainBackend;

/// DEP-03 `claim_fee_floor` when the governing `QuorumBegin` records no
/// reference feerate (this implementation never records one).
pub use deposits_core::tapscript_reserves::CLAIM_FEE_FLOOR_SATS;

/// Arms that count per armer: the first arm and up to three re-arms. Later
/// arms are ignored, so a griefer cannot keep moving E (DEP-03).
pub const MAX_ARMS: usize = 4;

/// `DisputeArmed` updates in a fork's history.
pub fn arm_count(history: &[SignedLedgerUpdate]) -> usize {
    history
        .iter()
        .filter(|u| {
            matches!(
                LedgerOperation::tlv_decode(&u.message),
                Ok(LedgerOperation::DisputeArmed { .. })
            )
        })
        .count()
}

/// Depth past E at which a verdict can no longer change, so it is cached.
const BURIED: u32 = 6;

/// One armer's latest `DisputeArmed`.
#[derive(Clone, Debug)]
pub struct Armer {
    pub key: PublicKey,
    pub participant: LotteryParticipant,
    /// Signed-header `block_height` of the armer's latest `DisputeArmed`.
    pub arm_height: u32,
    /// Sequence of that `DisputeArmed` on the armer's fork.
    pub arm_seq: u64,
    pub collateral: Option<ReplacementCollateral>,
}

impl Armer {
    pub fn xonly(&self) -> XOnlyPublicKey {
        self.participant.pubkey
    }
}

/// The armers of a dispute, split by the eligibility cut.
#[derive(Clone, Debug, Default)]
pub struct ArmerSet {
    /// Lottery participants, sorted by x-only key (the lottery's order).
    pub participants: Vec<Armer>,
    /// Excluded armers with the reason.
    pub excluded: Vec<(Armer, String)>,
    /// E: the snapshot height.
    pub snapshot: u32,
    pub required_sats: u64,
}

impl ArmerSet {
    pub fn lottery_participants(&self) -> Vec<LotteryParticipant> {
        self.participants
            .iter()
            .map(|a| a.participant.clone())
            .collect()
    }
}

/// The original operator: the author of sequence 0.
pub fn original_operator(updates: &[SignedLedgerUpdate]) -> Option<PublicKey> {
    updates
        .iter()
        .find(|u| u.sequence_number == 0)
        .map(|u| u.operator_id)
}

/// Each armer's latest `DisputeArmed` (highest sequence; a re-arm replaces
/// the declaration), excluding the original operator, sorted by x-only key.
pub fn collect_armers(updates: &[SignedLedgerUpdate]) -> Vec<Armer> {
    collect_armers_until(updates, None)
}

/// [`collect_armers`] as of the block the confiscation confirmed in (DEP-03 "When the set
/// is final"): an arm whose signed header is above `until` does not count, so each armer's
/// latest arm at or below it is its arm.
pub fn collect_armers_until(updates: &[SignedLedgerUpdate], until: Option<u32>) -> Vec<Armer> {
    let operator = original_operator(updates);
    // Each armer's first `MAX_ARMS` arms, by sequence; the latest of them counts.
    let mut by_seq: Vec<&SignedLedgerUpdate> = updates.iter().collect();
    by_seq.sort_by_key(|u| u.sequence_number);
    let mut seen_arms: HashMap<PublicKey, usize> = HashMap::new();
    let mut latest: HashMap<PublicKey, (u64, Armer)> = HashMap::new();
    for u in by_seq {
        if Some(u.operator_id) == operator || until.is_some_and(|c| u.block_height > c) {
            continue;
        }
        let Ok(LedgerOperation::DisputeArmed {
            commitment_hash,
            target_reserves,
            replacement_collateral,
            ..
        }) = LedgerOperation::tlv_decode(&u.message)
        else {
            continue;
        };
        let count = seen_arms.entry(u.operator_id).or_insert(0);
        *count += 1;
        if *count > MAX_ARMS {
            continue;
        }
        let armer = Armer {
            key: u.operator_id,
            participant: LotteryParticipant::new(
                u.operator_id.x_only_public_key().0,
                commitment_hash,
                target_reserves,
            ),
            arm_height: u.block_height,
            arm_seq: u.sequence_number,
            collateral: replacement_collateral,
        };
        match latest.get(&u.operator_id) {
            Some((seq, _)) if *seq >= u.sequence_number => {}
            _ => {
                latest.insert(u.operator_id, (u.sequence_number, armer));
            }
        }
    }
    let mut out: Vec<Armer> = latest.into_values().map(|(_, a)| a).collect();
    out.sort_by_key(|a| a.xonly().serialize());
    out
}

/// An output confirmed at or before `snapshot` and unspent through it: its sats.
pub fn outpoint_at_snapshot(
    chain: &dyn ChainBackend,
    txid: Txid,
    vout: u32,
    snapshot: u32,
) -> Result<Option<u64>, String> {
    let e = |x: crate::error::Error| x.to_string();
    let created = match chain.get_tx_block_height(&txid).map_err(e)? {
        Some(h) if h <= snapshot => h,
        _ => return Ok(None),
    };
    let Some(tx) = chain.get_tx(&txid).map_err(e)? else {
        return Ok(None);
    };
    let Some(output) = tx.output.get(vout as usize).cloned() else {
        return Ok(None);
    };
    match chain
        .spent_within(
            &OutPoint::new(txid, vout),
            &output.script_pubkey,
            created,
            snapshot,
        )
        .map_err(e)?
    {
        None => Ok(Some(output.value.to_sat())),
        Some(_) => Ok(None),
    }
}

/// DEP-06 §Confiscation obligations: what a confiscation sweeps and splices out.
#[derive(Clone, Debug, Default)]
pub struct ConfiscationObligations {
    /// Migration outputs at the vault's script, ascending (txid, vout), with their sats.
    pub swept: Vec<(OutPoint, u64)>,
    /// Splice-outs ascending by deposit id.
    pub splice_outs: Vec<(bitcoin::ScriptBuf, u64)>,
    /// Owed entries no splice-out pays (sats).
    pub residue_sats: u64,
}

/// The obligations of a confiscation (mirrors cl-deposits' `confiscation-obligations`): from the
/// ledger at the fork point (replayed from `updates`) and the `ObligationRecord`s on `set`'s
/// participants' forks below their `DisputeArmed`, at the snapshot E.
pub fn confiscation_obligations(
    chain: &dyn ChainBackend,
    updates: &[SignedLedgerUpdate],
    set: &ArmerSet,
) -> Result<ConfiscationObligations, String> {
    use bitcoin::hashes::Hash;
    let Some(operator) = original_operator(updates) else {
        return Ok(ConfiscationObligations::default());
    };
    let lvs = dispute_last_valid_sequence(updates).unwrap_or(u64::MAX);
    let mut canonical: Vec<&SignedLedgerUpdate> = updates
        .iter()
        .filter(|u| u.operator_id == operator && u.sequence_number <= lvs)
        .collect();
    canonical.sort_by_key(|u| u.sequence_number);
    let mut state = deposits_core::types::LedgerState::new(operator, String::new(), 0);
    for u in &canonical {
        let op = LedgerOperation::tlv_decode(&u.message).map_err(|e| e.to_string())?;
        state = state
            .apply_for(u, &op)
            .map_err(|e| format!("replay seq {}: {:?}", u.sequence_number, e))?;
    }
    let mut out = ConfiscationObligations::default();
    let Some(a) = state.dormancy_accept.clone() else {
        return Ok(out);
    };
    if let Some((t, v)) = a.outpoint {
        if let Some(sats) = outpoint_at_snapshot(chain, Txid::from_byte_array(t), v, set.snapshot)?
        {
            out.swept
                .push((OutPoint::new(Txid::from_byte_array(t), v), sats));
        }
    }
    let mut outs: Vec<(deposits_core::types::DepositId, bitcoin::ScriptBuf, u64)> = Vec::new();
    if !a.resolved {
        let mut seen: Vec<([u8; 32], u32)> = Vec::new();
        for p in &set.participants {
            for u in updates.iter().filter(|u| {
                u.operator_id == p.key && u.sequence_number > lvs && u.sequence_number < p.arm_seq
            }) {
                let Ok(LedgerOperation::ObligationRecord {
                    source_notice_update: Some(source_notice_update),
                    source_qb_update: Some(source_qb_update),
                    ..
                }) = LedgerOperation::tlv_decode(&u.message)
                else {
                    continue;
                };
                let Ok(ev) = deposits_core::types::migration_evidence(
                    &state.ledger_id,
                    &source_notice_update,
                    &source_qb_update,
                ) else {
                    continue;
                };
                if !ev.to_us
                    || ev.manifest_hash != a.manifest_hash
                    || ev.qb_update.block_height >= a.expires
                    || seen.contains(&(ev.txid, ev.vout))
                {
                    continue;
                }
                let Some(sats) = outpoint_at_snapshot(
                    chain,
                    Txid::from_byte_array(ev.txid),
                    ev.vout,
                    set.snapshot,
                )?
                else {
                    continue;
                };
                seen.push((ev.txid, ev.vout));
                out.swept
                    .push((OutPoint::new(Txid::from_byte_array(ev.txid), ev.vout), sats));
                for e in &ev.migrated {
                    match deposits_core::types::owed_spk_sats(e) {
                        Some((spk, v)) => outs.push((e.deposit_id, spk, v)),
                        None => out.residue_sats += e.amount / 1000,
                    }
                }
            }
        }
    }
    // DEP-06: proven-uncredited offer payments recorded on the participants' forks are owed too
    // (paid from the vault: the payment itself sits at the operator's offer address).
    let canonical_all: Vec<SignedLedgerUpdate> = updates
        .iter()
        .filter(|u| u.operator_id == operator)
        .cloned()
        .collect();
    let oracle = |b: &[u8; 32]| {
        chain
            .get_block_height_if_in_best_chain(&bitcoin::BlockHash::from_byte_array(*b))
            .ok()
            .flatten()
    };
    let mut paid: Vec<([u8; 32], u32)> = Vec::new();
    for p in &set.participants {
        for u in updates.iter().filter(|u| {
            u.operator_id == p.key && u.sequence_number > lvs && u.sequence_number < p.arm_seq
        }) {
            let Ok(LedgerOperation::ObligationRecord {
                uncredited_proof: Some(json),
                ..
            }) = LedgerOperation::tlv_decode(&u.message)
            else {
                continue;
            };
            let Ok(proof) = serde_json::from_slice::<deposits_core::fraud::FraudProof>(&json)
            else {
                continue;
            };
            let deposits_core::fraud::FraudEvidence::UncreditedOnchain {
                deposit_id,
                descriptor,
                txid,
                vout,
                amount_sats,
                ..
            } = &proof.evidence
            else {
                continue;
            };
            let (Ok(t), Ok(d)) = (hex::decode(txid), hex::decode(deposit_id)) else {
                continue;
            };
            let (Ok(t), Ok(d)) = (<[u8; 32]>::try_from(t), <[u8; 16]>::try_from(d)) else {
                continue;
            };
            if paid.contains(&(t, *vout))
                || proof.ledger_id != hex::encode(state.ledger_id)
                || deposits_core::fraud::verify_uncredited_onchain(&proof, &canonical_all, &oracle)
                    .is_err()
                || onchain_credited(&canonical_all, lvs, t, *vout)
            {
                continue;
            }
            paid.push((t, *vout));
            let e = deposits_core::messages::ManifestEntry {
                deposit_id: d,
                amount: amount_sats * 1000,
                fees: Default::default(),
                descriptor: descriptor.clone(),
            };
            match deposits_core::types::owed_spk_sats(&e) {
                Some((spk, v)) => outs.push((d, spk, v)),
                None => out.residue_sats += e.amount / 1000,
            }
        }
    }
    out.swept
        .sort_by_key(|(o, _)| (o.txid.to_byte_array(), o.vout));
    outs.sort_by_key(|(id, _, _)| *id);
    out.splice_outs = outs.into_iter().map(|(_, spk, v)| (spk, v)).collect();
    Ok(out)
}

/// An OnchainCredit of `txid`:`vout` in `history` at or before `upto_seq`.
fn onchain_credited(
    history: &[SignedLedgerUpdate],
    upto_seq: u64,
    txid: [u8; 32],
    vout: u32,
) -> bool {
    fn hit(op: &LedgerOperation, txid: [u8; 32], vout: u32) -> bool {
        match op {
            LedgerOperation::OnchainCredit {
                txid: t, vout: v, ..
            } => *t == txid && *v == vout,
            LedgerOperation::Batch(inner) => inner.iter().any(|o| hit(o, txid, vout)),
            _ => false,
        }
    }
    history
        .iter()
        .filter(|u| u.sequence_number <= upto_seq)
        .filter_map(|u| LedgerOperation::tlv_decode(&u.message).ok())
        .any(|op| hit(&op, txid, vout))
}

/// E: the highest signed-header height among the armers' latest arms.
pub fn snapshot_height(armers: &[Armer]) -> u32 {
    armers.iter().map(|a| a.arm_height).max().unwrap_or(0)
}

/// The dispute's fork point: the lowest `last_valid_sequence` any
/// `DisputeEnter` names.
pub fn dispute_last_valid_sequence(updates: &[SignedLedgerUpdate]) -> Option<u64> {
    updates
        .iter()
        .filter_map(|u| match LedgerOperation::tlv_decode(&u.message) {
            Ok(LedgerOperation::DisputeEnter {
                last_valid_sequence,
                ..
            }) => Some(last_valid_sequence),
            _ => None,
        })
        .min()
}

/// `obligations × collateral_ratio + claim_fee_floor` at the fork point.
pub fn required_sats(
    updates: &[SignedLedgerUpdate],
    last_valid_sequence: Option<u64>,
) -> Result<u64, String> {
    use crate::node::replacement_collateral::{collateral_basis_at, CollateralPolicy};
    let operator = original_operator(updates).ok_or("could not find ledger genesis")?;
    let lvs = last_valid_sequence
        .or_else(|| dispute_last_valid_sequence(updates))
        .ok_or("no DisputeEnter names a last_valid_sequence")?;
    let mut sorted: Vec<SignedLedgerUpdate> = updates.to_vec();
    sorted.sort_by_key(|u| (u.sequence_number, u.operator_id));
    let basis = collateral_basis_at(&sorted, operator, lvs)?;
    let policy = CollateralPolicy {
        claim_fee_estimate_sats: CLAIM_FEE_FLOOR_SATS,
        ..CollateralPolicy::default()
    };
    basis
        .required_sats(&policy)
        .ok_or_else(|| "QuorumBegin reserves were zero".to_string())
}

/// Why a pledge fails the cut, or `None` if it passes.
pub fn pledge_failure(
    chain: &dyn ChainBackend,
    rc: &ReplacementCollateral,
    snapshot: u32,
    required: u64,
) -> Result<Option<String>, String> {
    if rc.amount < required {
        return Ok(Some(format!(
            "declared {} sats, below the floor {}",
            rc.amount, required
        )));
    }
    let txid = Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array(rc.txid));
    let key = (txid, rc.vout, rc.amount, snapshot);
    if let Some(v) = cache().lock().unwrap().get(&key) {
        return Ok(v.clone());
    }
    let verdict = pledge_failure_uncached(chain, txid, rc, snapshot)?;
    let tip = chain.get_tip_height().map_err(|e| e.to_string())?;
    if tip >= snapshot.saturating_add(BURIED) {
        cache().lock().unwrap().insert(key, verdict.clone());
    }
    Ok(verdict)
}

fn pledge_failure_uncached(
    chain: &dyn ChainBackend,
    txid: Txid,
    rc: &ReplacementCollateral,
    snapshot: u32,
) -> Result<Option<String>, String> {
    let e = |x: crate::error::Error| x.to_string();
    let created = match chain.get_tx_block_height(&txid).map_err(e)? {
        Some(h) => h,
        None => return Ok(Some("pledge is unconfirmed or unknown".into())),
    };
    if created > snapshot {
        return Ok(Some(format!(
            "pledge confirmed at {}, after the snapshot {}",
            created, snapshot
        )));
    }
    let tx = match chain.get_tx(&txid).map_err(e)? {
        Some(tx) => tx,
        None => return Ok(Some("pledge transaction not found".into())),
    };
    let output = match tx.output.get(rc.vout as usize) {
        Some(o) => o.clone(),
        None => return Ok(Some("pledge output does not exist".into())),
    };
    if output.value.to_sat() < rc.amount {
        return Ok(Some(format!(
            "pledge holds {} sats, less than the {} declared",
            output.value.to_sat(),
            rc.amount
        )));
    }
    let outpoint = OutPoint::new(txid, rc.vout);
    // Only blocks created..=snapshot decide it, a fixed range: walking to the
    // tip grew every block and starved the lottery claim's 10 s periodic.
    match chain
        .spent_within(&outpoint, &output.script_pubkey, created, snapshot)
        .map_err(e)?
    {
        None => Ok(None),
        Some(h) => Ok(Some(format!(
            "pledge spent at {}, at or before the snapshot {}",
            h, snapshot
        ))),
    }
}

type VerdictKey = (Txid, u32, u64, u32);

fn cache() -> &'static Mutex<HashMap<VerdictKey, Option<String>>> {
    static CACHE: OnceLock<Mutex<HashMap<VerdictKey, Option<String>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Split `armers` by the cut against `required` sats.
pub fn split(
    chain: &dyn ChainBackend,
    armers: Vec<Armer>,
    required: u64,
) -> Result<ArmerSet, String> {
    split_at(chain, armers, required, None)
}

/// [`split`] once the confiscation has confirmed in block `confiscated_at`: an arm above it
/// does not count (DEP-03 "When the set is final"); it neither moves E nor joins.
pub fn split_at(
    chain: &dyn ChainBackend,
    armers: Vec<Armer>,
    required: u64,
    confiscated_at: Option<u32>,
) -> Result<ArmerSet, String> {
    let armers: Vec<Armer> = armers
        .into_iter()
        .filter(|a| confiscated_at.is_none_or(|c| a.arm_height <= c))
        .collect();
    let snapshot = snapshot_height(&armers);
    let mut set = ArmerSet {
        snapshot,
        required_sats: required,
        ..Default::default()
    };
    for a in armers {
        let failure = match &a.collateral {
            None => Some("declared no replacement collateral".to_string()),
            Some(rc) => pledge_failure(chain, rc, snapshot, required)?,
        };
        match failure {
            None => set.participants.push(a),
            Some(reason) => set.excluded.push((a, reason)),
        }
    }
    for (a, reason) in &set.excluded {
        tracing::info!(
            "armer {} excluded from the lottery: {}",
            &hex::encode(a.key.serialize())[..16],
            reason
        );
    }
    Ok(set)
}

/// The dispute's armers split by the eligibility cut, from the ledger's
/// updates (fork branches included) and the confirmed chain.
pub fn eligible_armers(
    chain: &dyn ChainBackend,
    updates: &[SignedLedgerUpdate],
    last_valid_sequence: Option<u64>,
) -> Result<ArmerSet, String> {
    eligible_armers_at(chain, updates, last_valid_sequence, None)
}

/// [`eligible_armers`] once the confiscation has confirmed in block `confiscated_at`.
pub fn eligible_armers_at(
    chain: &dyn ChainBackend,
    updates: &[SignedLedgerUpdate],
    last_valid_sequence: Option<u64>,
    confiscated_at: Option<u32>,
) -> Result<ArmerSet, String> {
    let required = required_sats(updates, last_valid_sequence)?;
    split_at(
        chain,
        collect_armers_until(updates, confiscated_at),
        required,
        confiscated_at,
    )
}

/// Whether `vault` is spent on the confirmed chain: `Some(true)` spent, `Some(false)` unspent,
/// `None` unknown (not confirmed, or the chain did not answer). A dispute whose vault is spent
/// is over (DEP-03 "When the set is final"): no member enters or arms it again.
pub fn vault_spent_on_chain(chain: &dyn ChainBackend, vault: &OutPoint) -> Option<bool> {
    chain.get_tx_block_height(&vault.txid).ok()??;
    match chain
        .confirmed_spend(vault, bitcoin::Script::new(), u32::MAX)
        .ok()?
    {
        crate::chain_backend::ConfirmedSpend::Unspent => Some(false),
        _ => Some(true),
    }
}

/// The signed-header height of the dispute's first arm: no confiscation can precede it, so
/// the search for the landed one starts here, not at E (which later arms may have lifted
/// past it; DEP-03 "When the set is final").
pub fn first_arm_height(updates: &[SignedLedgerUpdate]) -> Option<u32> {
    updates
        .iter()
        .filter(|u| {
            matches!(
                LedgerOperation::tlv_decode(&u.message),
                Ok(LedgerOperation::DisputeArmed { .. })
            )
        })
        .map(|u| u.block_height)
        .min()
}

/// For the CLI: the armer set from relay events (base64 TLV updates).
pub fn cli_armer_set<'a>(
    electrum_url: &str,
    events: impl IntoIterator<Item = &'a nostr_sdk::Event>,
) -> Result<ArmerSet, String> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    let updates: Vec<SignedLedgerUpdate> = events
        .into_iter()
        .filter_map(|e| BASE64.decode(&e.content).ok())
        .filter_map(|b| SignedLedgerUpdate::tlv_decode(&b).ok())
        .collect();
    eligible_armers(
        &*crate::chain_backend::from_env(electrum_url),
        &updates,
        None,
    )
}

/// DEP-06 lottery recovery voters from raw relay events (the CLI's view).
pub fn cli_recovery_voters<'a>(
    events: impl IntoIterator<Item = &'a nostr_sdk::Event>,
) -> Option<(Vec<bitcoin::secp256k1::XOnlyPublicKey>, usize)> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    let updates: Vec<SignedLedgerUpdate> = events
        .into_iter()
        .filter_map(|e| BASE64.decode(&e.content).ok())
        .filter_map(|b| SignedLedgerUpdate::tlv_decode(&b).ok())
        .collect();
    deposits_core::rotation_order::lottery_recovery_voters(&updates)
}

/// For the CLI, from decoded updates.
pub fn cli_armer_set_updates(
    electrum_url: &str,
    updates: &[SignedLedgerUpdate],
) -> Result<ArmerSet, String> {
    eligible_armers(
        &*crate::chain_backend::from_env(electrum_url),
        updates,
        None,
    )
}

fn ledger_cache() -> &'static Mutex<HashMap<String, ArmerSet>> {
    static CACHE: OnceLock<Mutex<HashMap<String, ArmerSet>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

impl crate::node::Node {
    /// The dispute's armer set for `ledger_id`. Once its snapshot is buried
    /// it cannot change (nothing after E counts), so it is kept per ledger
    /// and the claim and recovery periodics never refetch whole ledgers.
    pub(crate) async fn lottery_armer_set(&self, ledger_id: &str) -> Result<ArmerSet, String> {
        if let Some(set) = ledger_cache().lock().unwrap().get(ledger_id) {
            return Ok(set.clone());
        }
        let t = std::time::Instant::now();
        let updates = self.fetch_all_ledger_updates_paginated(ledger_id).await;
        if t.elapsed().as_millis() >= 1000 {
            tracing::warn!(
                "lottery {}: fetching {} updates took {} ms",
                &ledger_id[..16.min(ledger_id.len())],
                updates.len(),
                t.elapsed().as_millis()
            );
        }
        if updates.is_empty() {
            return Err("failed to fetch ledger updates from relay".into());
        }
        let chain = self.wallet.chain_backend();
        let t = std::time::Instant::now();
        // DEP-03 "When the set is final": once the confiscation confirmed, arms above its
        // block do not count (a restarted member's late re-arm moved E past it).
        let confiscated_at = super::lottery_recovery::confiscation_height(&*chain, &updates);
        let set = eligible_armers_at(&*chain, &updates, None, confiscated_at)?;
        if t.elapsed().as_millis() >= 1000 {
            tracing::warn!(
                "lottery {}: eligibility took {} ms",
                &ledger_id[..16.min(ledger_id.len())],
                t.elapsed().as_millis()
            );
        }
        let tip = chain.get_tip_height().map_err(|e| e.to_string())?;
        if !set.participants.is_empty() && tip >= set.snapshot.saturating_add(BURIED) {
            ledger_cache()
                .lock()
                .unwrap()
                .insert(ledger_id.to_string(), set.clone());
        }
        Ok(set)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain_backend::ConfirmedSpend;
    use crate::chain_backend::UnspentOutput;
    use crate::error::Error;
    use bitcoin::{
        absolute, transaction, Amount, BlockHash, Script, ScriptBuf, Transaction, TxOut,
    };

    /// A chain where each pledge tx has a creation height and an optional
    /// confirmed spend height.
    struct Chain {
        tip: u32,
        txs: HashMap<Txid, (u32, Transaction, Option<u32>)>,
    }

    impl ChainBackend for Chain {
        fn get_tip_height(&self) -> Result<u32, Error> {
            Ok(self.tip)
        }
        fn get_block_hash(&self, _: u32) -> Result<BlockHash, Error> {
            unimplemented!()
        }
        fn get_block_height_if_in_best_chain(&self, _: &BlockHash) -> Result<Option<u32>, Error> {
            unimplemented!()
        }
        fn get_tx(&self, t: &Txid) -> Result<Option<Transaction>, Error> {
            Ok(self.txs.get(t).map(|x| x.1.clone()))
        }
        fn get_tx_block_height(&self, t: &Txid) -> Result<Option<u32>, Error> {
            Ok(self.txs.get(t).map(|x| x.0))
        }
        fn is_output_unspent(&self, _: &Txid, _: u32) -> Result<Option<bool>, Error> {
            unimplemented!()
        }
        fn find_unspent_output_at(&self, _: &Script) -> Result<Option<UnspentOutput>, Error> {
            unimplemented!()
        }
        fn find_spending_tx(
            &self,
            _: &OutPoint,
            _: &Script,
            _: u32,
        ) -> Result<Option<Transaction>, Error> {
            unimplemented!()
        }
        fn confirmed_spend(
            &self,
            o: &OutPoint,
            _: &Script,
            from: u32,
        ) -> Result<ConfirmedSpend, Error> {
            Ok(match self.txs.get(&o.txid).and_then(|x| x.2) {
                None => ConfirmedSpend::Unspent,
                Some(h) if h >= from => ConfirmedSpend::SpentAt(h),
                Some(_) => ConfirmedSpend::SpentBefore(from),
            })
        }
        fn broadcast_tx(&self, _: &Transaction) -> Result<Txid, Error> {
            unimplemented!()
        }
    }

    fn tx(value: u64, tag: u32) -> Transaction {
        Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::from_consensus(tag),
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(value),
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }

    fn armer(seed: u8, arm_height: u32, rc: Option<ReplacementCollateral>) -> Armer {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let sk = bitcoin::secp256k1::SecretKey::from_slice(&[seed; 32]).unwrap();
        let key = PublicKey::from_secret_key(&secp, &sk);
        Armer {
            key,
            participant: LotteryParticipant::new(key.x_only_public_key().0, [seed; 20], "t".into()),
            arm_height,
            arm_seq: 0,
            collateral: rc,
        }
    }

    #[test]
    fn spent_short_late_or_missing_pledges_exclude_only_their_armer() {
        let mut txs = HashMap::new();
        let mut rc = |value: u64, created: u32, spent: Option<u32>, tag: u32, amount: u64| {
            let t = tx(value, tag);
            let id = t.compute_txid();
            txs.insert(id, (created, t, spent));
            Some(ReplacementCollateral {
                txid: id.to_byte_array(),
                vout: 0,
                amount,
            })
        };
        use bitcoin::hashes::Hash as _;
        let armers = vec![
            armer(1, 100, rc(50_000, 90, None, 1, 50_000)), // good
            armer(2, 104, rc(50_000, 95, Some(110), 2, 50_000)), // spent after E (=104): good
            armer(3, 102, rc(50_000, 95, Some(103), 3, 50_000)), // spent before E: veto attempt
            armer(4, 101, rc(40_000, 95, None, 4, 50_000)), // undersized
            armer(5, 103, rc(50_000, 105, None, 5, 50_000)), // confirmed after E
            armer(6, 100, rc(50_000, 90, None, 6, 1_000)),  // below the floor
            armer(7, 100, None),                            // no declaration
        ];
        let chain = Chain { tip: 120, txs };
        let set = split(&chain, armers, 10_000).unwrap();
        assert_eq!(set.snapshot, 104);
        let keep: Vec<u8> = set
            .participants
            .iter()
            .map(|a| a.participant.commitment_hash[0])
            .collect();
        let mut keep = keep;
        keep.sort();
        assert_eq!(keep, vec![1, 2]);
        assert_eq!(set.excluded.len(), 5);
    }

    #[test]
    fn verdict_is_stable_after_the_winner_spends_its_pledge() {
        use bitcoin::hashes::Hash as _;
        let t = tx(60_000, 9);
        let id = t.compute_txid();
        let rc = ReplacementCollateral {
            txid: id.to_byte_array(),
            vout: 0,
            amount: 60_000,
        };
        let before = Chain {
            tip: 130,
            txs: HashMap::from([(id, (90, t.clone(), None))]),
        };
        let after = Chain {
            tip: 140,
            txs: HashMap::from([(id, (90, t, Some(135)))]),
        };
        assert_eq!(
            pledge_failure_uncached(&before, id, &rc, 120).unwrap(),
            None
        );
        assert_eq!(pledge_failure_uncached(&after, id, &rc, 120).unwrap(), None);
    }
    /// The eligibility cut never asks the chain about blocks past the snapshot:
    /// walking to the tip for a pledge spent after it (the winner's, by design)
    /// grew every block and starved the lottery claim's 10 s periodic task.
    #[test]
    fn pledge_lookup_stays_within_the_snapshot() {
        use bitcoin::hashes::Hash as _;
        struct Bounded(Chain);
        impl ChainBackend for Bounded {
            fn get_tip_height(&self) -> Result<u32, Error> {
                self.0.get_tip_height()
            }
            fn get_block_hash(&self, h: u32) -> Result<BlockHash, Error> {
                self.0.get_block_hash(h)
            }
            fn get_block_height_if_in_best_chain(
                &self,
                b: &BlockHash,
            ) -> Result<Option<u32>, Error> {
                self.0.get_block_height_if_in_best_chain(b)
            }
            fn get_tx(&self, t: &Txid) -> Result<Option<Transaction>, Error> {
                self.0.get_tx(t)
            }
            fn get_tx_block_height(&self, t: &Txid) -> Result<Option<u32>, Error> {
                self.0.get_tx_block_height(t)
            }
            fn is_output_unspent(&self, _: &Txid, _: u32) -> Result<Option<bool>, Error> {
                unimplemented!()
            }
            fn find_unspent_output_at(&self, _: &Script) -> Result<Option<UnspentOutput>, Error> {
                unimplemented!()
            }
            fn find_spending_tx(
                &self,
                _: &OutPoint,
                _: &Script,
                _: u32,
            ) -> Result<Option<Transaction>, Error> {
                panic!("eligibility must not walk to the tip")
            }
            fn confirmed_spend(
                &self,
                _: &OutPoint,
                _: &Script,
                _: u32,
            ) -> Result<ConfirmedSpend, Error> {
                panic!("eligibility must not walk to the tip")
            }
            fn spent_within(
                &self,
                o: &OutPoint,
                _: &Script,
                from: u32,
                to: u32,
            ) -> Result<Option<u32>, Error> {
                assert!(
                    to <= 120,
                    "asked about blocks past the snapshot: {from}..={to}"
                );
                Ok(self
                    .0
                    .txs
                    .get(&o.txid)
                    .and_then(|x| x.2)
                    .filter(|h| (from..=to).contains(h)))
            }
            fn broadcast_tx(&self, _: &Transaction) -> Result<Txid, Error> {
                unimplemented!()
            }
        }
        let t = tx(60_000, 11);
        let id = t.compute_txid();
        let rc = ReplacementCollateral {
            txid: id.to_byte_array(),
            vout: 0,
            amount: 60_000,
        };
        let spent_after = Bounded(Chain {
            tip: 5_000,
            txs: HashMap::from([(id, (90, t.clone(), Some(4_000)))]),
        });
        assert_eq!(
            pledge_failure_uncached(&spent_after, id, &rc, 120).unwrap(),
            None
        );
        assert_eq!(
            outpoint_at_snapshot(&spent_after, id, 0, 120).unwrap(),
            Some(60_000)
        );
        let spent_before = Bounded(Chain {
            tip: 5_000,
            txs: HashMap::from([(id, (90, t, Some(110)))]),
        });
        assert!(pledge_failure_uncached(&spent_before, id, &rc, 120)
            .unwrap()
            .is_some());
        assert_eq!(
            outpoint_at_snapshot(&spent_before, id, 0, 120).unwrap(),
            None
        );
    }
    /// A restarted member must not reopen a dispute whose vault the confiscation spent.
    #[test]
    fn a_spent_vault_ends_the_dispute() {
        let (live, gone) = (tx(1_000, 1), tx(1_000, 2));
        let chain = Chain {
            tip: 500,
            txs: HashMap::from([
                (live.compute_txid(), (100, live.clone(), None)),
                (gone.compute_txid(), (100, gone.clone(), Some(300))),
            ]),
        };
        let op = |t: &Transaction| OutPoint::new(t.compute_txid(), 0);
        assert_eq!(vault_spent_on_chain(&chain, &op(&live)), Some(false));
        assert_eq!(vault_spent_on_chain(&chain, &op(&gone)), Some(true));
        assert_eq!(
            vault_spent_on_chain(&chain, &op(&tx(1_000, 3))),
            None,
            "an unknown vault proves nothing"
        );
    }

    /// The cross-implementation vector (cl-deposits checks the same file).
    #[test]
    fn eligibility_vector() {
        use bitcoin::hashes::Hash as _;
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/vectors/armer_eligibility.json"))
                .unwrap();
        for case in v["cases"].as_array().unwrap() {
            let mut txs = HashMap::new();
            let mut armers = Vec::new();
            let mut names = HashMap::new();
            for (i, a) in case["armers"].as_array().unwrap().iter().enumerate() {
                let rc = if a["pledge"].is_null() {
                    None
                } else {
                    let p = &a["pledge"];
                    let t = tx(p["value"].as_u64().unwrap(), 1000 + i as u32);
                    let id = t.compute_txid();
                    if let Some(created) = p["created"].as_u64() {
                        txs.insert(
                            id,
                            (created as u32, t, p["spent_at"].as_u64().map(|h| h as u32)),
                        );
                    }
                    Some(ReplacementCollateral {
                        txid: id.to_byte_array(),
                        vout: 0,
                        amount: a["declared"].as_u64().unwrap(),
                    })
                };
                let ar = armer(10 + i as u8, a["arm_height"].as_u64().unwrap() as u32, rc);
                names.insert(ar.key, a["id"].as_str().unwrap().to_string());
                armers.push(ar);
            }
            let chain = Chain { tip: 1000, txs };
            let set = split_at(
                &chain,
                armers,
                case["required_sats"].as_u64().unwrap(),
                case["confiscation_height"].as_u64().map(|c| c as u32),
            )
            .unwrap();
            let mut got: Vec<String> = set
                .participants
                .iter()
                .map(|a| names[&a.key].clone())
                .collect();
            got.sort();
            let want: Vec<String> = case["expect"]["participants"]
                .as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_str().unwrap().to_string())
                .collect();
            assert_eq!(got, want, "{}", case["name"]);
            assert_eq!(
                set.snapshot as u64,
                case["expect"]["snapshot"].as_u64().unwrap(),
                "{}",
                case["name"]
            );
        }
    }
}
