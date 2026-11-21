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
    collect_armers_round(updates, until, 1)
}

/// DEP-06 Phase 4 (strict-lottery-v8): [`collect_armers_until`] for re-arm round `round`
/// (`rearm_round`, TLV 366; absent is round 1). The `MAX_ARMS` bound spans every round: an
/// armer's first `MAX_ARMS` arms by sequence count, and of those, its latest arm of `round`
/// is its arm in that round. Mirrors cl's `armers-of :round`.
pub fn collect_armers_round(
    updates: &[SignedLedgerUpdate],
    until: Option<u32>,
    round: u32,
) -> Vec<Armer> {
    collect_armers_in(updates, until, round, None)
}

/// One arm, as [`pick_round_arms`] sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArmRow<K> {
    pub armer: K,
    pub seq: u64,
    pub height: u32,
    pub round: u32,
}

/// DEP-06 Phase 4 step 2: of `arms`, the index of each armer's arm for re-arm round `round` in the
/// window `(opens, closes]`: the latest (by sequence) of its first [`MAX_ARMS`] arms that is of
/// `round` and whose signed `block_height` lies inside the window. Arms outside the window, or of
/// other rounds, count against the bound but never displace an in-window arm: taking the latest
/// counted arm and filtering it by the window after let a later same-round arm signed past the
/// close withdraw its armer from a closed window, or empty the cut (2026-11-15). Mirrors cl's
/// `pick-round-arms`; vector `rearm_window_arms.json`.
pub fn pick_round_arms<K: std::hash::Hash + Eq + Clone>(
    arms: &[ArmRow<K>],
    round: u32,
    opens: u32,
    closes: u32,
) -> Vec<usize> {
    let mut order: Vec<usize> = (0..arms.len()).collect();
    order.sort_by_key(|&i| arms[i].seq);
    let mut counted: HashMap<K, usize> = HashMap::new();
    let mut chosen: HashMap<K, usize> = HashMap::new();
    for i in order {
        let a = &arms[i];
        let n = counted.entry(a.armer.clone()).or_insert(0);
        *n += 1;
        if *n > MAX_ARMS || a.round != round || a.height <= opens || a.height > closes {
            continue;
        }
        chosen.insert(a.armer.clone(), i);
    }
    let mut out: Vec<usize> = chosen.into_values().collect();
    out.sort_unstable();
    out
}

/// Every counted-or-not `DisputeArmed` of the dispute's armers (not the original operator), as
/// [`ArmRow`]s for [`pick_round_arms`].
pub fn arm_rows(updates: &[SignedLedgerUpdate]) -> Vec<ArmRow<PublicKey>> {
    let operator = original_operator(updates);
    updates
        .iter()
        .filter(|u| Some(u.operator_id) != operator)
        .filter_map(|u| match LedgerOperation::tlv_decode(&u.message) {
            Ok(LedgerOperation::DisputeArmed { rearm_round, .. }) => Some(ArmRow {
                armer: u.operator_id,
                seq: u.sequence_number,
                height: u.block_height,
                round: rearm_round.unwrap_or(1),
            }),
            _ => None,
        })
        .collect()
}

/// DEP-06 §Arm manifests (DEP-03, strict-lottery-v8; ruled 2026-11-15, option A): the indices into
/// `arms` that `manifest` (a list of (armer, seq)) names, or why it is not a valid arm set for
/// round `round`'s window `(opens, closes]` (round 1: `(-1, C]`). Valid: every entry names an arm,
/// no armer twice, each arm among its armer's first [`MAX_ARMS`] by sequence (every round), of
/// `round`, and signed inside the window. Omitting an armer is not a fault. Mirrors cl's
/// `manifest-arms`; vector `arm_manifest.json`.
pub fn manifest_arms<K: std::hash::Hash + Eq + Clone + std::fmt::Debug>(
    arms: &[ArmRow<K>],
    manifest: &[(K, u64)],
    round: u32,
    opens: i64,
    closes: u32,
) -> Result<Vec<usize>, String> {
    if manifest.is_empty() {
        return Err("empty manifest".into());
    }
    let mut by: HashMap<K, Vec<usize>> = HashMap::new();
    for (i, a) in arms.iter().enumerate() {
        by.entry(a.armer.clone()).or_default().push(i);
    }
    for v in by.values_mut() {
        v.sort_by_key(|i| arms[*i].seq);
    }
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for (armer, seq) in manifest {
        if !seen.insert(armer.clone()) {
            return Err(format!("armer {:?} named twice", armer));
        }
        let list = by.get(armer).map(|v| v.as_slice()).unwrap_or(&[]);
        let Some(pos) = list.iter().position(|i| arms[*i].seq == *seq) else {
            return Err(format!("no arm {:?}/{}", armer, seq));
        };
        if pos >= MAX_ARMS {
            return Err(format!(
                "arm {:?}/{} is past the {}-arm bound",
                armer, seq, MAX_ARMS
            ));
        }
        let a = &arms[list[pos]];
        if a.round != round {
            return Err(format!("arm {:?}/{} is of round {}", armer, seq, a.round));
        }
        if !((a.height as i64) > opens && a.height <= closes) {
            return Err(format!(
                "arm {:?}/{} signed at {}, outside ({}, {}]",
                armer, seq, a.height, opens, closes
            ));
        }
        out.push(list[pos]);
    }
    Ok(out)
}

/// The armers a valid manifest names, as [`collect_armers_until`] gives them (sorted by x-only
/// key), or why the manifest is not valid ([`manifest_arms`]).
pub fn collect_manifest_armers(
    updates: &[SignedLedgerUpdate],
    manifest: &[(PublicKey, u64)],
    round: u32,
    opens: i64,
    closes: u32,
) -> Result<Vec<Armer>, String> {
    let operator = original_operator(updates);
    let mut rows = Vec::new();
    let mut armed = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for u in updates.iter().filter(|u| Some(u.operator_id) != operator) {
        if let Ok(LedgerOperation::DisputeArmed {
            commitment_hash,
            target_reserves,
            replacement_collateral,
            rearm_round,
            ..
        }) = LedgerOperation::tlv_decode(&u.message)
        {
            if !seen.insert((u.operator_id, u.sequence_number)) {
                continue;
            }
            rows.push(ArmRow {
                armer: u.operator_id,
                seq: u.sequence_number,
                height: u.block_height,
                round: rearm_round.unwrap_or(1),
            });
            armed.push(Armer {
                key: u.operator_id,
                participant: LotteryParticipant::new(
                    u.operator_id.x_only_public_key().0,
                    commitment_hash,
                    target_reserves,
                ),
                arm_height: u.block_height,
                arm_seq: u.sequence_number,
                collateral: replacement_collateral,
            });
        }
    }
    let idx = manifest_arms(&rows, manifest, round, opens, closes)?;
    let mut out: Vec<Armer> = idx.into_iter().map(|i| armed[i].clone()).collect();
    out.sort_by_key(|a| a.xonly().serialize());
    Ok(out)
}

/// A manifest's JSON `arms` ([{armer, seq}]), as (key, seq); `None` when malformed.
pub fn parse_manifest(v: &serde_json::Value) -> Option<Vec<(PublicKey, u64)>> {
    v.as_array()?
        .iter()
        .map(|a| {
            let k = PublicKey::from_slice(&hex::decode(a.get("armer")?.as_str()?).ok()?).ok()?;
            Some((k, a.get("seq")?.as_u64()?))
        })
        .collect()
}

/// Round `round`'s armers in the window `(opens, closes]` ([`pick_round_arms`]).
pub fn collect_armers_window(
    updates: &[SignedLedgerUpdate],
    round: u32,
    opens: u32,
    closes: u32,
) -> Vec<Armer> {
    collect_armers_in(updates, None, round, Some((opens, closes)))
}

fn collect_armers_in(
    updates: &[SignedLedgerUpdate],
    until: Option<u32>,
    round: u32,
    window: Option<(u32, u32)>,
) -> Vec<Armer> {
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
            rearm_round,
            ..
        }) = LedgerOperation::tlv_decode(&u.message)
        else {
            continue;
        };
        let count = seen_arms.entry(u.operator_id).or_insert(0);
        *count += 1;
        if *count > MAX_ARMS || rearm_round.unwrap_or(1) != round {
            continue;
        }
        // In a window, only an arm inside it is a candidate (pick_round_arms).
        if window.is_some_and(|(o, c)| u.block_height <= o || u.block_height > c) {
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

/// [`eligible_armers`] with each disputant's grounds judged (DEP-03 §Grounded arms):
/// `grounds` from [`crate::node::Node::grounds_verdicts`]. Without them, a proven ground is
/// not judged and stops a cut under grounded arms.
pub fn eligible_armers_grounded(
    chain: &dyn ChainBackend,
    updates: &[SignedLedgerUpdate],
    last_valid_sequence: Option<u64>,
    grounds: &GroundsVerdicts,
) -> Result<ArmerSet, String> {
    eligible_armers_grounded_at(chain, updates, last_valid_sequence, None, grounds)
}

/// [`eligible_armers`] once the confiscation has confirmed in block `confiscated_at`.
pub fn eligible_armers_at(
    chain: &dyn ChainBackend,
    updates: &[SignedLedgerUpdate],
    last_valid_sequence: Option<u64>,
    confiscated_at: Option<u32>,
) -> Result<ArmerSet, String> {
    eligible_armers_grounded_at(
        chain,
        updates,
        last_valid_sequence,
        confiscated_at,
        &GroundsVerdicts::pure(updates),
    )
}

/// [`eligible_armers_at`] with judged grounds: an arm without grounds is disregarded before the
/// snapshot under grounded arms (it moves neither E nor joins) and listed as excluded.
pub fn eligible_armers_grounded_at(
    chain: &dyn ChainBackend,
    updates: &[SignedLedgerUpdate],
    last_valid_sequence: Option<u64>,
    confiscated_at: Option<u32>,
    grounds: &GroundsVerdicts,
) -> Result<ArmerSet, String> {
    cut_armers(
        chain,
        updates,
        last_valid_sequence,
        collect_armers_until(updates, confiscated_at),
        confiscated_at,
        grounds,
    )
}

/// DEP-06 Phase 4 step 3 (strict-lottery-v8): re-arm round `round`'s participants, the arms
/// for that round signed inside the window `(opens, closes]`, through the same grounds,
/// accused exclusion and eligibility cut as round 1, the window's close standing in for the
/// confiscation's block. Mirrors cl's `rearm-armers`.
pub fn eligible_armers_round(
    chain: &dyn ChainBackend,
    updates: &[SignedLedgerUpdate],
    round: u32,
    opens: u32,
    closes: u32,
    grounds: &GroundsVerdicts,
) -> Result<ArmerSet, String> {
    let arms = collect_armers_window(updates, round, opens, closes);
    cut_armers(chain, updates, None, arms, Some(closes), grounds)
}

/// The grounds filter, the accused exclusion and the eligibility split over `arms`.
fn cut_armers(
    chain: &dyn ChainBackend,
    updates: &[SignedLedgerUpdate],
    last_valid_sequence: Option<u64>,
    arms: Vec<Armer>,
    confiscated_at: Option<u32>,
    grounds: &GroundsVerdicts,
) -> Result<ArmerSet, String> {
    let required = required_sats(updates, last_valid_sequence)?;
    let (armers, ungrounded) = grounds.filter(arms)?;
    // DEP-03 §Lottery: a key the dispute's own grounds convict never wins. Dropped before the
    // cut, so the lottery is the cut of a subset of the arms, which every judge already accepts.
    let mut accused = dispute_accused_keys(updates, grounds);
    // The operator at the fork point is accused too ("it cannot dispute its own ledger"), as in
    // cl's dispute-accused-keys.
    if let Some(op) = last_valid_sequence
        .and_then(|lvs| updates.iter().find(|u| u.sequence_number == lvs))
        .map(|u| u.operator_id.x_only_public_key().0)
    {
        accused.push(op);
    }
    let (armers, convicted): (Vec<Armer>, Vec<Armer>) = armers
        .into_iter()
        .partition(|a| !accused.contains(&a.xonly()));
    let mut set = split_at(chain, armers, required, confiscated_at)?;
    set.excluded.extend(ungrounded);
    set.excluded.extend(
        convicted
            .into_iter()
            .map(|a| (a, "accused by the dispute's own grounds".to_string())),
    );
    Ok(set)
}

/// DEP-06 §Lottery, the lottery's recovery voters and threshold: the governing QuorumBegin's
/// members other than the operator; under `strict-lottery-v8` (provisional, cl-deposits
/// `docs/REVIEW.md`) also without the keys the dispute's own grounds convict, the threshold the
/// strict majority of what remains (`0` when none remain: only the full-set leaf). Mirrors cl's
/// `lottery-voters`; vector `lottery_voters_accused.txt`.
pub fn lottery_voters_with(
    updates: &[SignedLedgerUpdate],
    grounds: &GroundsVerdicts,
) -> Option<(Vec<XOnlyPublicKey>, usize)> {
    let (voters, threshold) = deposits_core::rotation_order::lottery_recovery_voters(updates)?;
    if !deposits_core::types::ruleset_strict_lottery(&grounds.ruleset) {
        return Some((voters, threshold));
    }
    Some(deposits_core::types::strict_voters(
        &voters,
        &dispute_accused_keys(updates, grounds),
    ))
}

/// DEP-03 §Lottery: the x-only keys the dispute's own grounds convict, from the proof each
/// counted DisputeEnter carries (TLV 345, [`deposits_core::fraud::FraudProof::accused_keys`]).
/// Under grounded arms only grounded DisputeEnters count. Only this dispute's grounds: a key
/// convicted on another ledger is not excluded here. Mirrors cl's `dispute-accused-keys`.
pub fn dispute_accused_keys(
    updates: &[SignedLedgerUpdate],
    grounds: &GroundsVerdicts,
) -> Vec<XOnlyPublicKey> {
    let grounded_rule = deposits_core::types::ruleset_grounds_arms(&grounds.ruleset);
    let mut out: Vec<XOnlyPublicKey> = Vec::new();
    for (k, _, class) in dispute_enter_grounds(updates) {
        if let GroundsClass::Verify(b) = class {
            let counts =
                !grounded_rule || matches!(grounds.by_key.get(&k), Some((Verdict::Grounded, _)));
            if counts {
                out.extend(b.proof.accused_keys());
            }
        }
    }
    out.sort_by_key(|k| k.serialize());
    out.dedup();
    out
}

// ============================================================================
// DEP-03 §Grounded arms (DEP-18 grounded-arms-v7)
// ============================================================================
//
// The winner's fork becomes the ledger's canonical history, so under grounded-arms-v7 an arm
// counts in the cut, and a DisputeEnter in the confiscation's shape, only if its DisputeEnter
// has grounds: an expiry ground, or the broadcast proof it acts on carried on the fork (TLV
// 345), hashing to its fraud_proof_hash, accusing the operator at its fork point, and
// verifying as a received proof does. Motive is never examined. Mirrors cl-deposits'
// grounds-class / cut-by-grounds / shape-by-grounds; vector grounded_arms.txt.

/// A DisputeEnter's grounds, once judged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Grounded,
    Ungrounded,
    /// Not judged yet (evidence this node does not hold): stops the cut and the shape.
    Unknown,
}

/// A DisputeEnter's grounds from the DisputeEnter alone.
#[derive(Clone, Debug)]
pub enum GroundsClass {
    Expiry,
    Ungrounded(String),
    /// A carried proof that must verify as a received proof does.
    Verify(Box<deposits_core::fraud::FraudBroadcast>),
}

/// DEP-03 §Grounded arms from one DisputeEnter: its reason, expiry anchor, `fraud_proof_hash`,
/// carried `fraud_proof`, signed height, the `quorum_expiry` in force at its
/// `last_valid_sequence`, and the operator of the update there.
pub fn grounds_class(
    reason: &str,
    anchor_block_height: Option<u32>,
    fraud_proof_hash: Option<[u8; 32]>,
    fraud_proof: Option<&str>,
    enter_height: u32,
    governing_expiry: Option<u32>,
    fork_point_operator: Option<&PublicKey>,
) -> GroundsClass {
    if deposits_core::types::dispute_is_expiry(
        reason,
        anchor_block_height.is_some(),
        fraud_proof_hash.is_some(),
        enter_height,
        governing_expiry,
    ) {
        return match governing_expiry {
            Some(e) if enter_height > e => GroundsClass::Expiry,
            Some(e) => GroundsClass::Ungrounded(format!(
                "a quorum_expired dispute entered at {enter_height}, not past the quorum_expiry {e}"
            )),
            None => GroundsClass::Ungrounded(
                "a quorum_expired dispute with no quorum_expiry in force at its fork point".into(),
            ),
        };
    }
    let Some(body) = fraud_proof else {
        return GroundsClass::Ungrounded(
            "a punitive DisputeEnter that carries no fraud_proof".into(),
        );
    };
    let Ok(b) = serde_json::from_str::<deposits_core::fraud::FraudBroadcast>(body) else {
        return GroundsClass::Ungrounded("its fraud_proof does not parse".into());
    };
    if fraud_proof_hash != Some(b.proof.proof_hash()) {
        return GroundsClass::Ungrounded(
            "its fraud_proof does not hash to its fraud_proof_hash".into(),
        );
    }
    match fork_point_operator {
        Some(op)
            if b.proof
                .accused
                .eq_ignore_ascii_case(&hex::encode(op.serialize())) =>
        {
            GroundsClass::Verify(Box::new(b))
        }
        _ => GroundsClass::Ungrounded(
            "its proof does not accuse the operator at its fork point".into(),
        ),
    }
}

/// The cut's grounds step: under a ruleset with grounded arms, the grounded entries (in order)
/// and the ungrounded with why; an `Unknown` stops it. Under any other ruleset, every entry.
pub fn cut_by_grounds<T: Clone>(
    ruleset: &str,
    entries: &[(T, Verdict, String)],
) -> Result<(Vec<T>, Vec<(T, String)>), String> {
    if !deposits_core::types::ruleset_grounds_arms(ruleset) {
        return Ok((entries.iter().map(|e| e.0.clone()).collect(), Vec::new()));
    }
    let mut kept = Vec::new();
    let mut out = Vec::new();
    for (item, verdict, why) in entries {
        match verdict {
            Verdict::Grounded => kept.push(item.clone()),
            Verdict::Ungrounded => out.push((item.clone(), format!("no grounds: {why}"))),
            Verdict::Unknown => return Err(format!("grounds not judged yet: {why}")),
        }
    }
    Ok((kept, out))
}

/// The confiscation's shape (DEP-06 §Respectful vs punitive): respectful iff every counted
/// DisputeEnter is for a lapsed quorum and at least one counts; under grounded arms only the
/// grounded ones count, and an `Unknown` stops it.
pub fn shape_by_grounds(ruleset: &str, entries: &[(String, Verdict)]) -> Result<bool, String> {
    let reasons: Vec<&String> = if deposits_core::types::ruleset_grounds_arms(ruleset) {
        let mut r = Vec::new();
        for (reason, v) in entries {
            match v {
                Verdict::Grounded => r.push(reason),
                Verdict::Ungrounded => {}
                Verdict::Unknown => return Err("grounds not judged yet".into()),
            }
        }
        r
    } else {
        entries.iter().map(|(r, _)| r).collect()
    };
    Ok(!reasons.is_empty()
        && reasons
            .iter()
            .all(|r| r.replace('-', "_") == "quorum_expired"))
}

/// The ruleset in force at `seq` on the operator's chain: its latest `QuorumBegin` or
/// `QuorumUpgrade` at or below it, else its `LedgerOpen`'s; "" when none names one.
pub fn ruleset_at(updates: &[SignedLedgerUpdate], seq: u64) -> String {
    let Some(origin) = original_operator(updates) else {
        return String::new();
    };
    let mut chain: Vec<&SignedLedgerUpdate> = updates
        .iter()
        .filter(|u| u.operator_id == origin && u.sequence_number <= seq)
        .collect();
    chain.sort_by_key(|u| u.sequence_number);
    let mut ruleset = String::new();
    for u in chain {
        match LedgerOperation::tlv_decode(&u.message) {
            Ok(LedgerOperation::LedgerOpen {
                protocol_version, ..
            })
            | Ok(LedgerOperation::QuorumBegin {
                protocol_version, ..
            }) => {
                if let Some(p) = protocol_version {
                    ruleset = p;
                }
            }
            Ok(LedgerOperation::QuorumUpgrade {
                new_protocol_version,
                ..
            }) => ruleset = new_protocol_version,
            _ => {}
        }
    }
    ruleset
}

/// The `quorum_expiry` of the operator's latest `QuorumBegin` at or below `seq`.
pub fn governing_expiry_at(updates: &[SignedLedgerUpdate], seq: u64) -> Option<u32> {
    let origin = original_operator(updates)?;
    updates
        .iter()
        .filter(|u| u.operator_id == origin && u.sequence_number <= seq)
        .filter_map(|u| match LedgerOperation::tlv_decode(&u.message) {
            Ok(LedgerOperation::QuorumBegin { quorum_expiry, .. }) => {
                Some((u.sequence_number, quorum_expiry))
            }
            _ => None,
        })
        .max_by_key(|(s, _)| *s)
        .map(|(_, e)| e)
}

/// Each disputant's latest `DisputeEnter` in the current dispute (DEP-03 §The dispute), with
/// its grounds class and reason.
pub fn dispute_enter_grounds(
    updates: &[SignedLedgerUpdate],
) -> Vec<(PublicKey, String, GroundsClass)> {
    let scoped = deposits_core::rotation_order::dispute_scope(updates);
    let origin = original_operator(&scoped);
    let mut latest: HashMap<PublicKey, &SignedLedgerUpdate> = HashMap::new();
    for u in scoped.iter().filter(|u| Some(u.operator_id) != origin) {
        if matches!(
            LedgerOperation::tlv_decode(&u.message),
            Ok(LedgerOperation::DisputeEnter { .. })
        ) && latest
            .get(&u.operator_id)
            .is_none_or(|p| p.sequence_number < u.sequence_number)
        {
            latest.insert(u.operator_id, u);
        }
    }
    let mut out: Vec<(PublicKey, String, GroundsClass)> = latest
        .into_iter()
        .filter_map(|(k, u)| match LedgerOperation::tlv_decode(&u.message) {
            Ok(LedgerOperation::DisputeEnter {
                last_valid_sequence,
                reason,
                anchor_block_height,
                fraud_proof_hash,
                fraud_proof,
                ..
            }) => {
                let fork_op = origin.filter(|_| {
                    scoped.iter().any(|x| {
                        Some(x.operator_id) == origin && x.sequence_number == last_valid_sequence
                    })
                });
                let class = grounds_class(
                    &reason,
                    anchor_block_height,
                    fraud_proof_hash,
                    fraud_proof.as_deref(),
                    u.block_height,
                    governing_expiry_at(&scoped, last_valid_sequence),
                    fork_op.as_ref(),
                );
                Some((k, reason, class))
            }
            _ => None,
        })
        .collect();
    out.sort_by_key(|(k, _, _)| k.serialize());
    out
}

/// The grounds verdict of every disputant, and the ruleset in force at the dispute's fork point.
#[derive(Clone, Debug, Default)]
pub struct GroundsVerdicts {
    pub ruleset: String,
    pub by_key: HashMap<PublicKey, (Verdict, String)>,
    pub reasons: HashMap<PublicKey, String>,
}

impl GroundsVerdicts {
    /// From the updates alone: a proven ground that would need verifying is `Unknown`.
    pub fn pure(updates: &[SignedLedgerUpdate]) -> Self {
        Self::with_verifier(updates, |_| (Verdict::Unknown, "not verified here".into()))
    }

    /// `verify` judges each carried proof.
    pub fn with_verifier(
        updates: &[SignedLedgerUpdate],
        mut verify: impl FnMut(&deposits_core::fraud::FraudBroadcast) -> (Verdict, String),
    ) -> Self {
        let judged = dispute_enter_grounds(updates)
            .into_iter()
            .map(|(k, reason, class)| {
                let verdict = match class {
                    GroundsClass::Expiry => (Verdict::Grounded, "an expiry ground".to_string()),
                    GroundsClass::Ungrounded(why) => (Verdict::Ungrounded, why),
                    GroundsClass::Verify(b) => verify(&b),
                };
                (k, reason, verdict)
            })
            .collect();
        Self::from_judged(updates, judged)
    }

    /// From each disputant's judged verdict, with the ruleset at the dispute's fork point.
    pub fn from_judged(
        updates: &[SignedLedgerUpdate],
        judged: Vec<(PublicKey, String, (Verdict, String))>,
    ) -> Self {
        let scoped = deposits_core::rotation_order::dispute_scope(updates);
        let lvs = dispute_last_valid_sequence(&scoped);
        let mut v = GroundsVerdicts {
            ruleset: lvs.map(|s| ruleset_at(&scoped, s)).unwrap_or_default(),
            ..Default::default()
        };
        for (k, reason, verdict) in judged {
            v.by_key.insert(k, verdict);
            v.reasons.insert(k, reason);
        }
        v
    }

    /// The armers with grounds (the cut's grounds step), and those without.
    pub fn filter(&self, armers: Vec<Armer>) -> Result<(Vec<Armer>, Vec<(Armer, String)>), String> {
        let entries: Vec<(Armer, Verdict, String)> = armers
            .into_iter()
            .map(|a| {
                let (v, why) = self.by_key.get(&a.key).cloned().unwrap_or((
                    Verdict::Ungrounded,
                    "no DisputeEnter in the current dispute".into(),
                ));
                (a, v, why)
            })
            .collect();
        cut_by_grounds(&self.ruleset, &entries)
    }

    /// The shape under grounded arms; `None` under any other ruleset.
    pub fn respectful(&self) -> Option<Result<bool, String>> {
        if !deposits_core::types::ruleset_grounds_arms(&self.ruleset) {
            return None;
        }
        let entries: Vec<(String, Verdict)> = self
            .by_key
            .iter()
            .map(|(k, (v, _))| (self.reasons.get(k).cloned().unwrap_or_default(), *v))
            .collect();
        Some(shape_by_grounds(&self.ruleset, &entries))
    }
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

/// Whether a dispute forking at `last_valid_seq` comes after a custody change: `history`
/// holds a `DisputeAcquire` at or before `last_valid_seq` and after its last `QuorumBegin`
/// before that. Such a dispute (DEP-06 proof 11, against the winner) is a new one, and the
/// spent vault of that QuorumBegin is the old dispute's, not grounds to stand down.
pub fn forks_past_custody_change(history: &[SignedLedgerUpdate], last_valid_seq: u64) -> bool {
    let mut last_qb = None;
    let mut acquired_after_qb = false;
    for u in history
        .iter()
        .filter(|u| u.sequence_number <= last_valid_seq)
    {
        match LedgerOperation::tlv_decode(&u.message) {
            Ok(LedgerOperation::QuorumBegin { .. }) => {
                last_qb = Some(u.sequence_number);
                acquired_after_qb = false;
            }
            Ok(LedgerOperation::DisputeAcquire { .. }) if last_qb.is_some() => {
                acquired_after_qb = true;
            }
            _ => {}
        }
    }
    acquired_after_qb
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

/// Whether a dispute's armer set can no longer change: its confiscation confirmed in block
/// `confiscated_at`, buried (DEP-03 "When the set is final"). A buried E alone is not final.
pub fn set_is_final(set: &ArmerSet, confiscated_at: Option<u32>, tip: u32) -> bool {
    !set.participants.is_empty() && confiscated_at.is_some_and(|c| tip >= c.saturating_add(BURIED))
}

fn ledger_cache() -> &'static Mutex<HashMap<String, ArmerSet>> {
    static CACHE: OnceLock<Mutex<HashMap<String, ArmerSet>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// A non-final dispute's updates, kept between armer-set passes so a pass fetches only what
/// is new. A deep dispute's set was rebuilt from a whole-ledger fetch every pass: 94k-250k
/// updates, 37-56 s each, every 4-5 minutes per ledger (signet ref2/ref4, 2026-11-18).
#[derive(Clone)]
pub(crate) struct LotteryUpdates {
    pub updates: std::sync::Arc<Vec<SignedLedgerUpdate>>,
    keys: std::collections::HashSet<([u8; 33], [u8; 32])>,
    /// The newest `created_at` fetched.
    pub newest_ts: u64,
    /// The last whole-ledger fetch.
    full_at: std::time::Instant,
    /// The last [`LOTTERY_SWEEP_OP_TYPES`] sweep (or whole fetch, which covers it).
    swept_at: std::time::Instant,
}

/// A pass fetches from this long before the newest event it holds, for events published late
/// with a slightly older `created_at`.
const LOTTERY_FETCH_OVERLAP_SECS: u64 = 600;
/// How often a pass also sweeps the WHOLE time range for the operations the armer set is built
/// from ([`LOTTERY_SWEEP_OP_TYPES`]), for one backdated past the overlap (an arm can be:
/// DEP-03 §"Backdated arms"). It used to refetch the whole ledger this often: 250k updates,
/// 27-140 s per fetch, five ledgers, every 30 minutes (signet ref4, 2026-11-21). The `t`-tag
/// sweep is a handful of events, and the whole fetch it replaced was capped at
/// `RELAY_FETCH_MAX_PAGES` x `RELAY_FETCH_PAGE_LIMIT` = 250k newest events, so it never saw an
/// arm backdated below that on these ledgers either.
const LOTTERY_SWEEP_EVERY: std::time::Duration = std::time::Duration::from_secs(30 * 60);
/// A whole-ledger refetch happens only when a pass cannot vouch for what it holds (the
/// incremental fetch's overlap failed, or a DisputeEnter's fork point is held nowhere), and
/// then at most this often.
const LOTTERY_FULL_REFETCH: std::time::Duration = std::time::Duration::from_secs(30 * 60);

/// What an armer set reads off the forks and the ruleset (`t` tags): LedgerOpen, QuorumBegin,
/// QuorumUpgrade, DisputeEnter, DisputeAcquire, DisputeYield, DisputeArmed. The canonical chain
/// below the fork point is the operator's signed history, which a pass already holds and a
/// backdated event cannot change.
pub(crate) const LOTTERY_SWEEP_OP_TYPES: [u8; 7] = [1, 12, 45, 54, 55, 56, 57];

/// The kind of relay fetch a pass makes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LotteryFetch {
    /// Nothing held: the whole ledger.
    Whole,
    /// From `since`; with `sweep`, also the backdated-arm sweep.
    Incremental { since: u64, sweep: bool },
}

/// What [`LotteryUpdates::merge_checked`] found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Merged {
    /// How many updates were new.
    pub fresh: usize,
    /// Whether the fetch re-served anything already held. An incremental fetch starts
    /// [`LOTTERY_FETCH_OVERLAP_SECS`] before the newest event held, so a complete one always
    /// brings that event back; one that does not was cut short (the page cap) or the relay lost
    /// what we hold, and the gap between can only be closed by a whole fetch.
    pub overlapped: bool,
}

impl LotteryUpdates {
    pub(crate) fn new(updates: Vec<SignedLedgerUpdate>, newest_ts: Option<u64>) -> Self {
        let mut keys = std::collections::HashSet::with_capacity(updates.len());
        let mut kept = Vec::with_capacity(updates.len());
        for u in updates {
            if keys.insert((u.operator_id.serialize(), u.content_hash)) {
                kept.push(u);
            }
        }
        let now = std::time::Instant::now();
        Self {
            updates: std::sync::Arc::new(kept),
            keys,
            newest_ts: newest_ts.unwrap_or(0),
            full_at: now,
            swept_at: now,
        }
    }

    /// Where the next incremental fetch starts: just before the newest event held.
    pub(crate) fn since(&self) -> u64 {
        self.newest_ts.saturating_sub(LOTTERY_FETCH_OVERLAP_SECS)
    }

    /// The next pass's fetch: always incremental once something is held, with the backdated-arm
    /// sweep every [`LOTTERY_SWEEP_EVERY`].
    pub(crate) fn plan(&self, now: std::time::Instant) -> LotteryFetch {
        LotteryFetch::Incremental {
            since: self.since(),
            sweep: now.duration_since(self.swept_at) >= LOTTERY_SWEEP_EVERY,
        }
    }

    /// Whether a whole refetch may run now (it is rate-limited even when a pass asks for one).
    pub(crate) fn full_allowed(&self, now: std::time::Instant) -> bool {
        now.duration_since(self.full_at) >= LOTTERY_FULL_REFETCH
    }

    pub(crate) fn mark_swept(&mut self, now: std::time::Instant) {
        self.swept_at = now;
    }

    pub(crate) fn mark_full(&mut self, now: std::time::Instant) {
        self.full_at = now;
        self.swept_at = now;
    }

    /// Add what an incremental fetch brought that is not held yet (keyed as the fetch keys
    /// them: by operator and content). Returns how many were new.
    pub(crate) fn merge(
        &mut self,
        fetched: Vec<SignedLedgerUpdate>,
        newest_ts: Option<u64>,
    ) -> usize {
        self.merge_checked(fetched, newest_ts).fresh
    }

    /// [`Self::merge`], also reporting whether the fetch overlapped what was held.
    pub(crate) fn merge_checked(
        &mut self,
        fetched: Vec<SignedLedgerUpdate>,
        newest_ts: Option<u64>,
    ) -> Merged {
        let mut overlapped = false;
        let fresh: Vec<SignedLedgerUpdate> = fetched
            .into_iter()
            .filter(|u| {
                let new = self
                    .keys
                    .insert((u.operator_id.serialize(), u.content_hash));
                overlapped |= !new;
                new
            })
            .collect();
        if let Some(ts) = newest_ts {
            self.newest_ts = self.newest_ts.max(ts);
        }
        let n = fresh.len();
        if n > 0 {
            // In place when no caller still holds the previous pass's updates: no 250k copy.
            std::sync::Arc::make_mut(&mut self.updates).extend(fresh);
        }
        Merged {
            fresh: n,
            overlapped,
        }
    }
}

/// Per ledger, one slot behind an async lock: two passes over one ledger (the claim periodic and
/// a request handler) queue instead of each fetching, and a pass mutates the kept updates in
/// place instead of copying them out of the cache and back.
type LotterySlot = std::sync::Arc<tokio::sync::Mutex<Option<LotteryUpdates>>>;

fn lottery_updates_cache() -> &'static Mutex<HashMap<String, LotterySlot>> {
    static CACHE: OnceLock<Mutex<HashMap<String, LotterySlot>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Relay fetches made by [`crate::node::Node::lottery_updates`], by kind, for tests and logs.
#[derive(Default, Debug)]
pub(crate) struct LotteryFetchCounts {
    pub whole: std::sync::atomic::AtomicU64,
    pub incremental: std::sync::atomic::AtomicU64,
    pub sweep: std::sync::atomic::AtomicU64,
}

pub(crate) fn lottery_fetch_counts() -> &'static LotteryFetchCounts {
    static C: OnceLock<LotteryFetchCounts> = OnceLock::new();
    C.get_or_init(LotteryFetchCounts::default)
}

/// Whether a pass must refetch the whole ledger: its incremental fetch brought events and none
/// of them was held (the overlap failed), or a DisputeEnter's fork point is held nowhere.
pub(crate) fn lottery_needs_whole(
    incremental: Option<Merged>,
    fetched_any: bool,
    missing_fork_points: bool,
) -> bool {
    let overlap_failed = fetched_any && incremental.is_some_and(|m| !m.overlapped);
    overlap_failed || missing_fork_points
}

impl crate::node::Node {
    /// A dispute's updates for its armer set: the whole ledger on the first pass, and after it
    /// only what came since the last pass plus, every [`LOTTERY_SWEEP_EVERY`], the armer-set
    /// operations over the whole time range. A whole refetch again only when a pass cannot vouch
    /// for what it holds ([`lottery_needs_whole`]), at most every [`LOTTERY_FULL_REFETCH`]; it
    /// MERGES, so a capped refetch never drops what an earlier pass held.
    async fn lottery_updates(&self, ledger_id: &str) -> std::sync::Arc<Vec<SignedLedgerUpdate>> {
        use std::sync::atomic::Ordering::Relaxed;
        let slot = lottery_updates_cache()
            .lock()
            .unwrap()
            .entry(ledger_id.to_string())
            .or_default()
            .clone();
        let mut guard = slot.lock().await;
        let now = std::time::Instant::now();
        let t = std::time::Instant::now();
        let counts = lottery_fetch_counts();
        let mut kind = "whole ledger";
        let plan = guard
            .as_ref()
            .map(|c| c.plan(now))
            .unwrap_or(LotteryFetch::Whole);
        match (guard.as_mut(), plan) {
            (Some(c), LotteryFetch::Incremental { since, sweep }) => {
                kind = "incremental";
                counts.incremental.fetch_add(1, Relaxed);
                let (fetched, newest) = self
                    .fetch_ledger_updates_window(ledger_id, &[], Some(since))
                    .await;
                let fetched_any = !fetched.is_empty();
                let merged = c.merge_checked(fetched, newest);
                let mut fresh = merged.fresh;
                if sweep {
                    kind = "incremental + sweep";
                    counts.sweep.fetch_add(1, Relaxed);
                    let (swept, newest) = self
                        .fetch_ledger_updates_window(ledger_id, &LOTTERY_SWEEP_OP_TYPES, None)
                        .await;
                    fresh += c.merge(swept, newest);
                    c.mark_swept(now);
                }
                // A fork point can only go missing with a new DisputeEnter: no decode pass over
                // the whole ledger when nothing arrived.
                let mut missing = if fresh > 0 {
                    super::lottery_recovery::missing_fork_points(&c.updates)
                } else {
                    Vec::new()
                };
                if !missing.is_empty() {
                    if let Some(found) = self.local_updates_at(ledger_id, &missing) {
                        c.merge(found, None);
                        missing.clear();
                    }
                }
                if lottery_needs_whole(Some(merged), fetched_any, !missing.is_empty())
                    && c.full_allowed(now)
                {
                    kind = "whole ledger (overlap or fork point)";
                    counts.whole.fetch_add(1, Relaxed);
                    let (fetched, newest) =
                        self.fetch_ledger_updates_window(ledger_id, &[], None).await;
                    c.merge(fetched, newest);
                    c.mark_full(now);
                }
            }
            _ => {
                counts.whole.fetch_add(1, Relaxed);
                let (fetched, newest) =
                    self.fetch_ledger_updates_window(ledger_id, &[], None).await;
                if !fetched.is_empty() {
                    *guard = Some(LotteryUpdates::new(fetched, newest));
                }
            }
        }
        let updates = guard
            .as_ref()
            .map(|c| c.updates.clone())
            .unwrap_or_default();
        if t.elapsed().as_millis() >= 1000 {
            tracing::warn!(
                "lottery {}: fetching {} updates took {} ms ({})",
                &ledger_id[..16.min(ledger_id.len())],
                updates.len(),
                t.elapsed().as_millis(),
                kind
            );
        }
        updates
    }

    /// The dispute's armer set for `ledger_id`. Once its confiscation has confirmed and is
    /// buried the set cannot change (DEP-03), so it is kept per ledger and the claim and
    /// recovery periodics never refetch whole ledgers; before that a later arm may move E.
    pub(crate) async fn lottery_armer_set(&self, ledger_id: &str) -> Result<ArmerSet, String> {
        if let Some(set) = ledger_cache().lock().unwrap().get(ledger_id) {
            return Ok(set.clone());
        }
        let updates = self.lottery_updates(ledger_id).await;
        let updates: &[SignedLedgerUpdate] = &updates;
        if updates.is_empty() {
            return Err("failed to fetch ledger updates from relay".into());
        }
        let chain = self.wallet.chain_backend();
        let t = std::time::Instant::now();
        // DEP-03 "When the set is final": once the confiscation confirmed, arms above its
        // block do not count (a restarted member's late re-arm moved E past it).
        let confiscated_at = super::lottery_recovery::confiscation_height(&*chain, &updates);
        // DEP-03 §Grounded arms: each disputant's grounds, judged here.
        let grounds = Box::pin(self.grounds_verdicts(&updates)).await;
        let set = eligible_armers_grounded_at(&*chain, &updates, None, confiscated_at, &grounds)?;
        if t.elapsed().as_millis() >= 1000 {
            tracing::warn!(
                "lottery {}: eligibility took {} ms",
                &ledger_id[..16.min(ledger_id.len())],
                t.elapsed().as_millis()
            );
        }
        // Cache only a final set: once the confiscation has confirmed (DEP-03 "When the set
        // is final"). A buried E is not enough: a later arm (a member that entered the
        // dispute late) moves E, and a set cached at the old E made the claim path compute a
        // two-armer lottery the landed four-armer confiscation did not pay, so no one revealed.
        let tip = chain.get_tip_height().map_err(|e| e.to_string())?;
        if set_is_final(&set, confiscated_at, tip) {
            ledger_cache()
                .lock()
                .unwrap()
                .insert(ledger_id.to_string(), set.clone());
            lottery_updates_cache().lock().unwrap().remove(ledger_id);
        }
        Ok(set)
    }
}

#[cfg(test)]
mod window_arms_vector {
    use super::{pick_round_arms, ArmRow};

    #[test]
    fn each_armer_s_in_window_arm_matches_the_shared_vector() {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/vectors/rearm_window_arms.json"))
                .unwrap();
        let mut cases = 0;
        for c in v["cases"].as_array().unwrap() {
            let arms: Vec<ArmRow<String>> = c["arms"]
                .as_array()
                .unwrap()
                .iter()
                .map(|a| ArmRow {
                    armer: a["armer"].as_str().unwrap().to_string(),
                    seq: a["seq"].as_u64().unwrap(),
                    height: a["height"].as_u64().unwrap() as u32,
                    round: a["round"].as_u64().unwrap() as u32,
                })
                .collect();
            let mut got: Vec<(String, u64)> = pick_round_arms(
                &arms,
                c["round"].as_u64().unwrap() as u32,
                c["opens"].as_u64().unwrap() as u32,
                c["closes"].as_u64().unwrap() as u32,
            )
            .into_iter()
            .map(|i| (arms[i].armer.clone(), arms[i].seq))
            .collect();
            got.sort();
            let want: Vec<(String, u64)> = c["expect"]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| {
                    (
                        e["armer"].as_str().unwrap().to_string(),
                        e["seq"].as_u64().unwrap(),
                    )
                })
                .collect();
            assert_eq!(got, want, "{}", c["name"]);
            cases += 1;
        }
        assert_eq!(cases, 8, "every rearm_window_arms case ran");
    }
}

#[cfg(test)]
mod arm_manifest_vector {
    use super::{manifest_arms, ArmRow};

    #[test]
    fn manifests_match_the_shared_vector() {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/vectors/arm_manifest.json")).unwrap();
        let mut cases = 0;
        for c in v["cases"].as_array().unwrap() {
            let arms: Vec<ArmRow<String>> = c["arms"]
                .as_array()
                .unwrap()
                .iter()
                .map(|a| ArmRow {
                    armer: a["armer"].as_str().unwrap().to_string(),
                    seq: a["seq"].as_u64().unwrap(),
                    height: a["height"].as_u64().unwrap() as u32,
                    round: a["round"].as_u64().unwrap() as u32,
                })
                .collect();
            let manifest: Vec<(String, u64)> = c["manifest"]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| {
                    (
                        e["armer"].as_str().unwrap().to_string(),
                        e["seq"].as_u64().unwrap(),
                    )
                })
                .collect();
            let got = manifest_arms(
                &arms,
                &manifest,
                c["round"].as_u64().unwrap() as u32,
                c["opens"].as_i64().unwrap(),
                c["closes"].as_u64().unwrap() as u32,
            );
            assert_eq!(
                got.is_ok(),
                c["valid"].as_bool().unwrap(),
                "{}: {:?}",
                c["name"],
                got
            );
            if let Ok(idx) = got {
                let mut named: Vec<(String, u64)> = idx
                    .iter()
                    .map(|i| (arms[*i].armer.clone(), arms[*i].seq))
                    .collect();
                named.sort();
                let mut want = manifest.clone();
                want.sort();
                assert_eq!(named, want, "{}", c["name"]);
            }
            cases += 1;
        }
        assert_eq!(cases, 11, "every arm_manifest case ran");
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
    /// A set cached at a buried E went stale when a late arm moved E (regtest 2026-10-14:
    /// the claim path kept a two-armer cut the landed four-armer confiscation did not pay).
    #[test]
    fn only_a_confiscated_set_is_final() {
        let set = ArmerSet {
            participants: vec![armer(1, 100, None)],
            snapshot: 100,
            ..Default::default()
        };
        assert!(!set_is_final(&set, None, 10_000), "a buried E is not final");
        assert!(
            !set_is_final(&set, Some(500), 502),
            "a fresh confiscation is not buried"
        );
        assert!(set_is_final(&set, Some(500), 500 + BURIED));
        assert!(!set_is_final(&ArmerSet::default(), Some(500), 10_000));
    }

    /// Proof 11 disputes the winner from past its DisputeAcquire: that is a new dispute, not
    /// the old one the spent vault closed (the vector's chain: a QuorumBegin, then the acquire).
    #[test]
    fn a_dispute_past_the_custody_change_is_a_new_one() {
        let history: Vec<SignedLedgerUpdate> =
            include_str!("../../../deposits-core/tests/vectors/unhonoured_obligation.txt")
                .lines()
                .filter_map(|l| l.strip_prefix("update "))
                .map(|h| SignedLedgerUpdate::tlv_decode(&hex::decode(h).unwrap()).unwrap())
                .collect();
        let acquire = history
            .iter()
            .find(|u| {
                matches!(
                    LedgerOperation::tlv_decode(&u.message),
                    Ok(LedgerOperation::DisputeAcquire { .. })
                )
            })
            .unwrap()
            .sequence_number;
        assert!(
            !forks_past_custody_change(&history, acquire - 1),
            "the old dispute"
        );
        assert!(forks_past_custody_change(&history, acquire));
        assert!(forks_past_custody_change(&history, acquire + 3));
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

#[cfg(test)]
mod lottery_updates_cache_tests {
    use super::{
        lottery_needs_whole, LotteryFetch, LotteryUpdates, Merged, LOTTERY_FETCH_OVERLAP_SECS,
        LOTTERY_FULL_REFETCH, LOTTERY_SWEEP_EVERY,
    };
    use deposits_core::SignedLedgerUpdate;

    fn upd(seq: u64, op: u8) -> SignedLedgerUpdate {
        use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
        SignedLedgerUpdate {
            message: Vec::new(),
            message_type: 0x8001,
            operator_id: PublicKey::from_secret_key(
                &Secp256k1::new(),
                &SecretKey::from_slice(&[op; 32]).unwrap(),
            ),
            ledger_id: [0u8; 32],
            sequence_number: seq,
            previous_hash: [0u8; 32],
            content_hash: [seq as u8; 32],
            block_height: 0,
            block_hash: [0u8; 32],
            operator_signature: [0u8; 64],
            cosignatures: Vec::new(),
        }
    }

    /// A pass after the first fetches from just before the newest event held, adds only what
    /// it does not hold (a fork's update at an OLD sequence included: the key is the operator
    /// and content, never the sequence), and every 30 minutes sweeps the whole time range for
    /// the armer-set operations (it refetched the whole ledger then, before cpu-trim).
    #[test]
    fn a_pass_fetches_only_what_is_new_and_sweeps_on_schedule() {
        let mut c = LotteryUpdates::new((0..100).map(|s| upd(s, 1)).collect(), Some(5_000));
        let now = std::time::Instant::now();
        assert_eq!(c.since(), 5_000 - LOTTERY_FETCH_OVERLAP_SECS);
        assert_eq!(
            c.plan(now),
            LotteryFetch::Incremental {
                since: 5_000 - LOTTERY_FETCH_OVERLAP_SECS,
                sweep: false
            }
        );

        // The overlap re-serves 98 and 99; a disputant's arm at seq 40 is new.
        let fetched = vec![upd(98, 1), upd(99, 1), upd(100, 1), upd(40, 2)];
        assert_eq!(c.merge(fetched, Some(5_200)), 2);
        assert_eq!(c.updates.len(), 102);
        assert_eq!(c.newest_ts, 5_200);
        // Nothing new: no copy, no change.
        let before = std::sync::Arc::as_ptr(&c.updates);
        assert_eq!(c.merge(vec![upd(100, 1)], None), 0);
        assert_eq!(std::sync::Arc::as_ptr(&c.updates), before);
        assert_eq!(c.newest_ts, 5_200);

        // Every 30 minutes the pass is still incremental, and adds the backdated-arm sweep.
        assert_eq!(
            c.plan(now + LOTTERY_SWEEP_EVERY),
            LotteryFetch::Incremental {
                since: 5_200 - LOTTERY_FETCH_OVERLAP_SECS,
                sweep: true
            }
        );
        assert!(matches!(
            c.plan(now),
            LotteryFetch::Incremental { sweep: false, .. }
        ));
        c.mark_swept(now + LOTTERY_SWEEP_EVERY);
        assert!(matches!(
            c.plan(now + LOTTERY_SWEEP_EVERY),
            LotteryFetch::Incremental { sweep: false, .. }
        ));
    }

    /// The overlap check: an incremental fetch starts before the newest event held, so a
    /// complete one re-serves something held; one that re-serves nothing was cut short.
    #[test]
    fn the_overlap_check_and_when_a_whole_refetch_is_due() {
        let mut c = LotteryUpdates::new((0..10).map(|s| upd(s, 1)).collect(), Some(1_000));
        let m = c.merge_checked(vec![upd(9, 1), upd(10, 1)], Some(1_100));
        assert_eq!(
            m,
            Merged {
                fresh: 1,
                overlapped: true
            }
        );
        let gap = c.merge_checked(vec![upd(50, 1), upd(51, 1)], Some(2_000));
        assert_eq!(
            gap,
            Merged {
                fresh: 2,
                overlapped: false
            }
        );
        // Whole only on a failed overlap that brought events, or a fork point held nowhere.
        assert!(!lottery_needs_whole(Some(m), true, false));
        assert!(lottery_needs_whole(Some(gap), true, false));
        // An empty fetch (relay error, or nothing new and nothing re-served) is no evidence.
        assert!(!lottery_needs_whole(
            Some(Merged {
                fresh: 0,
                overlapped: false
            }),
            false,
            false
        ));
        assert!(lottery_needs_whole(Some(m), true, true));
        // And rate-limited: not again within LOTTERY_FULL_REFETCH of the last whole fetch.
        let now = std::time::Instant::now();
        assert!(!c.full_allowed(now));
        assert!(c.full_allowed(now + LOTTERY_FULL_REFETCH));
        c.mark_full(now + LOTTERY_FULL_REFETCH);
        assert!(!c.full_allowed(now + LOTTERY_FULL_REFETCH));
    }

    /// A merge extends in place when no caller holds the previous updates, and leaves a
    /// caller's copy untouched when one does.
    #[test]
    fn a_merge_does_not_copy_unless_the_updates_are_shared() {
        let mut c = LotteryUpdates::new((0..200).map(|s| upd(s, 1)).collect(), Some(1));
        let p = std::sync::Arc::as_ptr(&c.updates);
        assert_eq!(c.merge(vec![upd(200, 2)], None), 1);
        assert_eq!(
            std::sync::Arc::as_ptr(&c.updates),
            p,
            "unique: extended in place"
        );
        let held = c.updates.clone();
        assert_eq!(c.merge(vec![upd(201, 2)], None), 1);
        assert_eq!(held.len(), 201, "a caller's updates do not change under it");
        assert_eq!(c.updates.len(), 202);
    }

    /// Counting the work: a non-final dispute's passes every 5 minutes for 6 hours. Before
    /// cpu-trim a pass refetched the whole ledger every 30 minutes (13 whole fetches of up to
    /// 250k updates); now only the first is whole, and 12 passes add a `t`-filtered sweep.
    #[test]
    fn six_hours_of_passes_fetch_the_whole_ledger_once() {
        let mut c = LotteryUpdates::new((0..10).map(|s| upd(s, 1)).collect(), Some(1_000));
        let t0 = std::time::Instant::now();
        let (mut whole, mut sweeps, mut incremental) = (1u32, 0u32, 0u32);
        let mut old_whole = 1u32;
        let mut old_full_at = t0;
        for k in 1..=72u32 {
            let now = t0 + std::time::Duration::from_secs(300 * k as u64);
            // The previous schedule, for the comparison.
            if now.duration_since(old_full_at) >= LOTTERY_FULL_REFETCH {
                old_whole += 1;
                old_full_at = now;
            }
            match c.plan(now) {
                LotteryFetch::Whole => whole += 1,
                LotteryFetch::Incremental { sweep, .. } => {
                    incremental += 1;
                    // The incremental fetch re-serves the newest held event: overlap passes.
                    let m = c.merge_checked(vec![upd(9, 1)], None);
                    if lottery_needs_whole(Some(m), true, false) && c.full_allowed(now) {
                        whole += 1;
                        c.mark_full(now);
                    }
                    if sweep {
                        sweeps += 1;
                        c.mark_swept(now);
                    }
                }
            }
        }
        assert_eq!(old_whole, 13);
        assert_eq!(whole, 1);
        assert_eq!(incremental, 72);
        assert_eq!(sweeps, 12);
    }
}
