//! DEP-06 "Authorised confiscation": a spend of a disputed ledger's vault is a confiscation
//! iff it is byte-identical to the confiscation the rules build from public state (the ledger's
//! history, the public `DisputeArmed` events, the eligibility cut as of the spend's block, the
//! obligations, the fee rule), its lottery over the set the cut yields for some subset of the
//! arms. Never "one we know of": a member that missed the dispute (a restart, a node that
//! joined later) rebuilds it from the relay and reaches the same verdict as one that signed it.

use bitcoin::hashes::Hash;
use bitcoin::{OutPoint, Transaction};
use deposits_core::messages::LedgerOperation;
use deposits_core::{SignedLedgerUpdate, TlvDecode};

use super::armers::{
    collect_armers_until, confiscation_obligations, dispute_last_valid_sequence, required_sats,
    split_at,
};
use crate::chain_backend::ChainBackend;

/// The relay's updates of `ledger_id` reduced to what the dispute is: the original operator's
/// chain by its hash links from the `LedgerOpen` that derives the id, until it forks (an
/// equivocation: every dispute forks before its fault), then each disputant's own updates past
/// its `DisputeEnter`'s fork point. Relabelled updates of other ledgers and the second branch
/// of an equivocation fall away.
pub fn dispute_view(
    ledger_id: &[u8; 32],
    updates: &[SignedLedgerUpdate],
) -> Option<Vec<SignedLedgerUpdate>> {
    let open = updates
        .iter()
        .find(|u| deposits_core::fraud::update_opens_ledger(u, ledger_id))?;
    let origin = open.operator_id;
    let mut base = vec![open.clone()];
    loop {
        let tip = base.last().unwrap();
        let mut next: Vec<&SignedLedgerUpdate> = updates
            .iter()
            .filter(|u| {
                u.operator_id == origin
                    && u.sequence_number == tip.sequence_number + 1
                    && u.previous_hash == tip.chain_hash()
            })
            .collect();
        next.sort_by_key(|u| u.chain_hash());
        next.dedup_by_key(|u| u.chain_hash());
        if next.len() != 1 {
            break;
        }
        base.push(next[0].clone());
    }
    let mut out = base;
    let mut disputants: Vec<bitcoin::secp256k1::PublicKey> = updates
        .iter()
        .filter(|u| u.operator_id != origin)
        .filter(|u| {
            matches!(
                LedgerOperation::tlv_decode(&u.message),
                Ok(LedgerOperation::DisputeEnter { .. })
            )
        })
        .map(|u| u.operator_id)
        .collect();
    disputants.sort_by_key(|k| k.serialize());
    disputants.dedup();
    for d in disputants {
        let mut mine: Vec<SignedLedgerUpdate> = updates
            .iter()
            .filter(|u| u.operator_id == d)
            .cloned()
            .collect();
        mine.sort_by_key(|u| u.sequence_number);
        mine.dedup_by_key(|u| u.chain_hash());
        out.extend(mine);
    }
    Some(out)
}

/// DEP-06: a confiscation is respectful iff every `DisputeEnter` of the dispute is for a lapsed
/// quorum; any punitive ground makes it punitive.
pub fn dispute_is_respectful(view: &[SignedLedgerUpdate]) -> bool {
    let reasons: Vec<String> = view
        .iter()
        .filter_map(|u| match LedgerOperation::tlv_decode(&u.message) {
            Ok(LedgerOperation::DisputeEnter { reason, .. }) => Some(reason),
            _ => None,
        })
        .collect();
    !reasons.is_empty()
        && reasons
            .iter()
            .all(|r| r.replace('-', "_") == "quorum_expired")
}

/// Whether `spend` (a spend of the disputed vault, confirmed in block `spend_height`) is the
/// confiscation the rules build from `updates` (the relay's, every operator's).
pub fn is_authorised_confiscation(
    chain: &dyn ChainBackend,
    ledger_id: &[u8; 32],
    updates: &[SignedLedgerUpdate],
    network: bitcoin::Network,
    spend: &Transaction,
    spend_height: Option<u32>,
) -> bool {
    let grounds = crate::node::armers::GroundsVerdicts::pure(updates);
    rebuild_matching(
        chain,
        ledger_id,
        updates,
        network,
        spend,
        spend_height,
        &grounds,
    )
    .is_ok()
}

/// The verdict with its reason (for logs and tests): `Ok(())` when `spend` is a rebuild of the
/// current dispute (DEP-03 §"The dispute", [`dispute_scope`]). A confiscation built before that
/// rule, over every DisputeEnter a disputant ever made, is also excused: the reading only ever
/// excuses more, never convicts more, so it holds under every ruleset (DEP-18).
///
/// [`dispute_scope`]: deposits_core::rotation_order::dispute_scope
pub fn rebuild_matching(
    chain: &dyn ChainBackend,
    ledger_id: &[u8; 32],
    updates: &[SignedLedgerUpdate],
    network: bitcoin::Network,
    spend: &Transaction,
    spend_height: Option<u32>,
    grounds: &crate::node::armers::GroundsVerdicts,
) -> Result<(), String> {
    let scoped = deposits_core::rotation_order::dispute_scope_final(updates, spend_height);
    match rebuild_matching_in(
        chain,
        ledger_id,
        &scoped,
        network,
        spend,
        spend_height,
        grounds,
        None,
    ) {
        Ok(()) => Ok(()),
        Err(e) if scoped.len() != updates.len() => rebuild_matching_in(
            chain,
            ledger_id,
            updates,
            network,
            spend,
            spend_height,
            grounds,
            None,
        )
        .map_err(|e2| format!("{}; and under every DisputeEnter: {}", e, e2)),
        Err(e) => Err(e),
    }
}

fn rebuild_matching_in(
    chain: &dyn ChainBackend,
    ledger_id: &[u8; 32],
    updates: &[SignedLedgerUpdate],
    network: bitcoin::Network,
    spend: &Transaction,
    spend_height: Option<u32>,
    grounds: &crate::node::armers::GroundsVerdicts,
    manifest: Option<&[(bitcoin::secp256k1::PublicKey, u64)]>,
) -> Result<(), String> {
    rebuild_set_in(
        chain,
        ledger_id,
        updates,
        network,
        spend,
        spend_height,
        grounds,
        manifest,
    )
    .map(|_| ())
}

/// The arm set (key, arm sequence per participant) whose rebuild is `spend`: its manifest.
pub fn rebuild_arm_set(
    chain: &dyn ChainBackend,
    ledger_id: &[u8; 32],
    updates: &[SignedLedgerUpdate],
    network: bitcoin::Network,
    spend: &Transaction,
    spend_height: Option<u32>,
    grounds: &crate::node::armers::GroundsVerdicts,
) -> Result<Vec<(bitcoin::secp256k1::PublicKey, u64)>, String> {
    let scoped = deposits_core::rotation_order::dispute_scope_final(updates, spend_height);
    rebuild_set_in(
        chain,
        ledger_id,
        &scoped,
        network,
        spend,
        spend_height,
        grounds,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn rebuild_set_in(
    chain: &dyn ChainBackend,
    ledger_id: &[u8; 32],
    updates: &[SignedLedgerUpdate],
    network: bitcoin::Network,
    spend: &Transaction,
    spend_height: Option<u32>,
    grounds: &crate::node::armers::GroundsVerdicts,
    manifest: Option<&[(bitcoin::secp256k1::PublicKey, u64)]>,
) -> Result<Vec<(bitcoin::secp256k1::PublicKey, u64)>, String> {
    use deposits_core::tapscript_reserves::{
        build_confiscation_ladder, confiscation_feerate, ConfiscationTxParams, LotteryScriptBuilder,
    };
    let view = dispute_view(ledger_id, updates).ok_or("no LedgerOpen for this ledger")?;
    let origin = view[0].operator_id;
    let fork_point = dispute_last_valid_sequence(&view).ok_or("no DisputeEnter")?;

    // The governing QuorumBegin: the original operator's newest at or before the fork point.
    let (qb_members, qb_expiry, qb_ruleset, vault, qb_feerate, qb_collateral) = view
        .iter()
        .filter(|u| u.operator_id == origin && u.sequence_number <= fork_point)
        .filter_map(|u| match LedgerOperation::tlv_decode(&u.message) {
            Ok(
                op @ LedgerOperation::QuorumBegin {
                    new_outpoint_vout,
                    amount,
                    collateral_amount,
                    ..
                },
            ) => {
                let rungs = deposits_core::vault_spend::quorum_begin_rungs(&op);
                let LedgerOperation::QuorumBegin {
                    quorum_members,
                    quorum_expiry,
                    protocol_version,
                    reference_feerate,
                    ..
                } = op
                else {
                    unreachable!()
                };
                Some((
                    u.sequence_number,
                    quorum_members.iter().map(|m| m.pubkey).collect::<Vec<_>>(),
                    quorum_expiry,
                    protocol_version,
                    (
                        rungs,
                        new_outpoint_vout,
                        (amount + collateral_amount) / 1000,
                    ),
                    reference_feerate,
                    collateral_amount,
                ))
            }
            _ => None,
        })
        .max_by_key(|(seq, ..)| *seq)
        .map(|(_, m, e, r, v, f, c)| (m, e, r, v, f, c))
        .ok_or("no QuorumBegin at or before the fork point")?;

    // DEP-03 §Fee ladder: the vault is output 0 of whichever rung confirmed; rung 0 holds the
    // recorded amounts, a higher one what the chain says.
    let vault = {
        let (rungs, vout, recorded) = vault;
        let input0 = spend
            .input
            .first()
            .map(|i| i.previous_output)
            .ok_or("no input")?;
        let rung = rungs
            .iter()
            .position(|t| input0.txid.to_byte_array() == *t && input0.vout == vout)
            .ok_or("input 0 is not the vault")?;
        let sats = if rung == 0 {
            recorded
        } else {
            chain
                .get_tx(&input0.txid)
                .ok()
                .flatten()
                .and_then(|t| t.output.get(vout as usize).map(|o| o.value.to_sat()))
                .ok_or("the confirmed rung is not on our chain")?
        };
        (input0, sats)
    };
    // DEP-03 §On-Chain State Anchor: the chain hash at the dispute's fork point.
    let anchor =
        deposits_core::rotation_order::dispute_anchor(&view).ok_or("no DisputeEnter to anchor")?;

    // The tier: the spend's nLockTime must be a confiscation tier's CLTV (never the operator's
    // tie-breaker tier).
    let voters_n = qb_members.iter().filter(|pk| **pk != origin).count() + 1;
    let ruleset = deposits_core::ruleset::resolve_or_current(qb_ruleset.as_deref());
    let tiers = (ruleset.tier_config_factory)(voters_n, qb_expiry).tiers;
    let lock_time = spend.lock_time.to_consensus_u32();
    if !tiers
        .iter()
        .any(|t| !t.requires_tie_breaker && t.timelock_blocks == lock_time)
    {
        return Err(format!(
            "nLockTime {lock_time} is no confiscation tier's CLTV"
        ));
    }

    // Obligations at the fork point, in sats.
    let obligations_sats = {
        let mut state = deposits_core::types::LedgerState::new(origin, String::new(), 0);
        for u in view
            .iter()
            .filter(|u| u.operator_id == origin && u.sequence_number <= fork_point)
        {
            let op = LedgerOperation::tlv_decode(&u.message)
                .map_err(|e| format!("decode at seq {}: {e}", u.sequence_number))?;
            state = state
                .apply_for(u, &op)
                .map_err(|e| format!("replay seq {}: {e:?}", u.sequence_number))?;
        }
        state.total_deposit_balance() / 1000
    };
    // On the reduced view this is the current dispute's voters; on the unreduced one (the
    // fallback in `rebuild_matching`) the reading before DEP-03 §"The dispute", which only
    // ever excuses more.
    let (recovery_voters, recovery_threshold) =
        super::armers::lottery_voters_every_enter_with(&view, grounds)
            .ok_or("no recovery voters")?;
    // DEP-03 §Grounded arms: under grounded-arms-v7 the shape counts grounded DisputeEnters only.
    let respectful = match grounds.respectful() {
        Some(r) => r?,
        None => dispute_is_respectful(&view),
    };
    let required = required_sats(&view, None)?;

    // The arms that count as of the spend's block; the cut of each subset of them (the full
    // set first: the cut every member computes once the relay has delivered every arm).
    // DEP-03 §Grounded arms: an arm without grounds is disregarded (a judge that cannot judge
    // one yet reaches no verdict, the error).
    // DEP-03 §Arm manifests (strict-lottery-v8): with a manifest, exactly the arms it names, valid
    // as of the spend's block, and only that set; never each armer's latest arm.
    let (armers, _) = match manifest {
        Some(m) => {
            let named = super::armers::collect_manifest_armers(
                &view,
                m,
                1,
                -1,
                spend_height.unwrap_or(u32::MAX),
            )?;
            let (kept, dropped) = grounds.filter(named)?;
            if kept.len() != m.len() {
                return Err(format!(
                    "{} named arm(s) are ungrounded",
                    m.len() - kept.len()
                ));
            }
            (kept, dropped)
        }
        None => grounds.filter(collect_armers_until(&view, spend_height))?,
    };
    // DEP-03 §The accused never win, under strict-lottery-v8 (the ruleset at the fork point, as
    // grounded arms): a lottery with a key the dispute's own grounds convict, or the operator
    // at the fork point, is not authorised. Under an earlier ruleset it is still the cut of a
    // subset of the arms, and authorised. A colluding majority that confiscated itself into a
    // lottery of its own colluders, which none of them claimed, left a ledger's lottery output
    // stranded (signet soak 30ea46ac, 2026-11-05).
    let accused: Vec<bitcoin::secp256k1::XOnlyPublicKey> = {
        let mut a = super::armers::dispute_accused_keys(&view, grounds);
        if let Some(op) = view
            .iter()
            .find(|u| u.sequence_number == fork_point && u.operator_id == origin)
            .or_else(|| view.iter().find(|u| u.sequence_number == fork_point))
        {
            a.push(op.operator_id.x_only_public_key().0);
        }
        a
    };
    if armers.is_empty() || armers.len() > 8 {
        return Err(format!("{} armers", armers.len()));
    }
    let n = armers.len();
    let mut tried = std::collections::HashSet::new();
    let mut closest: Option<String> = None;
    let lowest = if manifest.is_some() {
        (1u32 << n) - 1
    } else {
        1
    };
    for mask in (lowest..(1 << n)).rev() {
        let subset: Vec<_> = (0..n)
            .filter(|i| mask & (1 << i) != 0)
            .map(|i| armers[i].clone())
            .collect();
        let set = split_at(chain, subset, required, spend_height)?;
        if set.participants.is_empty() {
            continue;
        }
        let key: Vec<[u8; 32]> = set
            .participants
            .iter()
            .map(|a| a.xonly().serialize())
            .collect();
        if !tried.insert(key) {
            continue;
        }
        let participants: Vec<_> = set.participants.iter().map(|a| a.xonly()).collect();
        if !deposits_core::types::lottery_admissible(&grounds.ruleset, &participants, &accused) {
            if closest.is_none() {
                closest = Some("a lottery over a key the dispute's own grounds convict".into());
            }
            continue;
        }
        let lottery = LotteryScriptBuilder::new(
            set.lottery_participants(),
            recovery_voters.clone(),
            recovery_threshold,
            network,
        )
        .build()
        .map_err(|e| format!("lottery: {e:?}"))?;
        let obligations = confiscation_obligations(chain, &view, &set)?;
        // DEP-06: byte-identical to any rung of the ladder (DEP-03 §Confiscation ladder).
        let ladder = build_confiscation_ladder(
            &ConfiscationTxParams {
                vault,
                swept: obligations.swept.clone(),
                lottery_spk: lottery.script_pubkey(),
                voters: voters_n,
                lock_time,
                respectful,
                obligations_sats,
                residue_sats: obligations.residue_sats,
                splice_outs: obligations.splice_outs.clone(),
                operator: origin,
                anchor,
                feerate_sat_vb: confiscation_feerate(qb_feerate),
            },
            qb_collateral,
        );
        let spend_txid = spend.compute_txid();
        if ladder.iter().any(|r| r.compute_txid() == spend_txid) {
            return Ok(set
                .participants
                .iter()
                .map(|a| (a.key, a.arm_seq))
                .collect());
        }
        let rebuilt = ladder[0].clone();
        if closest.is_none() {
            closest = Some(format!(
                "{}; lottery {}",
                describe_difference(&rebuilt, spend),
                crate::node::dispute::lottery_inputs_line(
                    &set.lottery_participants(),
                    &recovery_voters,
                    recovery_threshold
                )
            ));
        }
    }
    Err(format!(
        "no rebuild from public state is this transaction (the full cut's: {})",
        closest.unwrap_or_default()
    ))
}

/// DEP-03 §Arm manifests (strict-lottery-v8): `spend` is the confiscation some published arm
/// manifest rebuilds (`Ok(index)` of the first that does). The judge is existential: arms a
/// manifest does not name, a backdated re-arm or a newcomer published after the spend, play no
/// part. Earlier rulesets never read manifests.
pub fn rebuild_matching_manifest(
    chain: &dyn ChainBackend,
    ledger_id: &[u8; 32],
    updates: &[SignedLedgerUpdate],
    network: bitcoin::Network,
    spend: &Transaction,
    spend_height: Option<u32>,
    grounds: &crate::node::armers::GroundsVerdicts,
    manifests: &[Vec<(bitcoin::secp256k1::PublicKey, u64)>],
) -> Result<usize, String> {
    if !deposits_core::types::ruleset_strict_lottery(&grounds.ruleset) {
        return Err("arm manifests are read only under strict-lottery-v8".into());
    }
    let scoped = deposits_core::rotation_order::dispute_scope_final(updates, spend_height);
    let mut why = Vec::new();
    for (i, m) in manifests.iter().enumerate() {
        match rebuild_matching_in(
            chain,
            ledger_id,
            &scoped,
            network,
            spend,
            spend_height,
            grounds,
            Some(m),
        ) {
            Ok(()) => return Ok(i),
            Err(e) => why.push(e),
        }
    }
    Err(format!(
        "no published arm manifest rebuilds it ({})",
        why.join("; ")
    ))
}

fn manifest_queue() -> &'static std::sync::Mutex<Vec<(String, Transaction)>> {
    static Q: std::sync::OnceLock<std::sync::Mutex<Vec<(String, Transaction)>>> =
        std::sync::OnceLock::new();
    Q.get_or_init(Default::default)
}

/// What differs between a rebuild and a spend, for the log.
fn describe_difference(rebuilt: &Transaction, spend: &Transaction) -> String {
    let mut d = Vec::new();
    if rebuilt.lock_time != spend.lock_time {
        d.push(format!(
            "lock_time {} vs {}",
            rebuilt.lock_time, spend.lock_time
        ));
    }
    let ins = |t: &Transaction| -> Vec<String> {
        t.input
            .iter()
            .map(|i| format!("{}/{}", i.previous_output, i.sequence.0))
            .collect()
    };
    if ins(rebuilt) != ins(spend) {
        d.push(format!("inputs {:?} vs {:?}", ins(rebuilt), ins(spend)));
    }
    let outs = |t: &Transaction| -> Vec<String> {
        t.output
            .iter()
            .map(|o| {
                format!(
                    "{}:{}",
                    o.value.to_sat(),
                    &hex::encode(o.script_pubkey.as_bytes())[..12.min(o.script_pubkey.len() * 2)]
                )
            })
            .collect()
    };
    if outs(rebuilt) != outs(spend) {
        d.push(format!("outputs {:?} vs {:?}", outs(rebuilt), outs(spend)));
    }
    if rebuilt.version != spend.version {
        d.push(format!("version {} vs {}", rebuilt.version, spend.version));
    }
    if d.is_empty() {
        "identical but for witnesses".into()
    } else {
        d.join("; ")
    }
}

impl crate::node::Node {
    /// DEP-03 §Arm manifests: the distinct arm sets published for `ledger_id`'s round `round` (the
    /// `arms` of its Challenge Answers, Kind 9112), from the relay.
    pub(crate) async fn arm_manifests(
        &self,
        ledger_id: &str,
        round: u32,
    ) -> Vec<Vec<(bitcoin::secp256k1::PublicKey, u64)>> {
        let events = self
            .nostr
            .fetch_spend_challenge_events(deposits_nostr::KIND_CHALLENGE_ANSWER, ledger_id)
            .await
            .unwrap_or_default();
        let mut out: Vec<Vec<(bitcoin::secp256k1::PublicKey, u64)>> = Vec::new();
        for v in events {
            if v.get("round").and_then(|r| r.as_u64()).unwrap_or(1) != round as u64 {
                continue;
            }
            let Some(mut m) = v.get("arms").and_then(super::armers::parse_manifest) else {
                continue;
            };
            if m.is_empty() {
                continue;
            }
            m.sort_by_key(|(k, _)| k.serialize());
            if !out.contains(&m) {
                out.push(m);
            }
        }
        out
    }

    /// DEP-03 §Arm manifests: publish the arm set `armers` (the participants `spend`'s lottery
    /// was built from) as a Challenge Answer with `round` and `arms`, once per txid.
    pub(crate) async fn publish_arm_manifest(
        &self,
        ledger_id: &str,
        spend: &Transaction,
        round: u32,
        armers: &[(bitcoin::secp256k1::PublicKey, u64)],
    ) {
        use std::sync::{Mutex, OnceLock};
        static SENT: OnceLock<Mutex<std::collections::HashSet<bitcoin::Txid>>> = OnceLock::new();
        let txid = spend.compute_txid();
        if armers.is_empty()
            || !SENT
                .get_or_init(Default::default)
                .lock()
                .unwrap()
                .insert(txid)
        {
            return;
        }
        let arms: Vec<serde_json::Value> = armers
            .iter()
            .map(|(k, q)| serde_json::json!({"armer": k.to_string(), "seq": q}))
            .collect();
        let anchor = deposits_core::tapscript_reserves::anchor_of(spend)
            .map(hex::encode)
            .unwrap_or_default();
        match self
            .nostr
            .publish_arm_manifest_event(
                ledger_id,
                &hex::encode(txid.to_byte_array()),
                &anchor,
                round,
                &arms,
            )
            .await
        {
            Ok(_) => tracing::info!(
                "published the arm manifest of {}'s {} (round {}): {} arms",
                &ledger_id[..8.min(ledger_id.len())],
                &txid.to_string()[..16],
                round,
                arms.len()
            ),
            Err(e) => tracing::warn!("arm manifest of {}: {:?}", &ledger_id[..8], e),
        }
    }

    /// Whether `tx`, a spend of `ledger_id`'s vault confirmed at `height`, is the confiscation
    /// the rules build from public state (the relay's updates of the ledger). A match is
    /// final and cached; a miss is not (the relay may not have delivered every arm yet).
    pub(crate) async fn authorised_confiscation_spend(
        &self,
        ledger_id: &str,
        tx: &Transaction,
        height: Option<u32>,
    ) -> bool {
        use std::sync::{Mutex, OnceLock};
        static MATCHED: OnceLock<Mutex<std::collections::HashSet<bitcoin::Txid>>> = OnceLock::new();
        let matched = MATCHED.get_or_init(|| Mutex::new(std::collections::HashSet::new()));
        let txid = tx.compute_txid();
        if matched.lock().unwrap().contains(&txid) {
            return true;
        }
        let Some(lid) = hex::decode(ledger_id)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
        else {
            return false;
        };
        let updates = self.judge_updates(ledger_id).await;
        if updates.is_empty() {
            return false;
        }
        let chain = self.wallet.chain_backend();
        let network = self.wallet.network();
        let tx = tx.clone();
        self.judge_with(
            ledger_id, lid, updates, chain, network, tx, height, txid, matched,
        )
        .await
    }

    /// Every update a judge reads of `ledger_id`: the relay's, our replica's, and those published
    /// as Challenge Answers.
    pub(crate) async fn judge_updates(&self, ledger_id: &str) -> Vec<SignedLedgerUpdate> {
        let mut updates = self.fetch_all_ledger_updates_paginated(ledger_id).await;
        // Our own replica of the base chain too: an answer carries only the dispute's updates, so
        // a judge whose relay lacks the ledger rebuilt from them alone, with no LedgerOpen, and
        // could never accept it (regtest confiscation-answer, 2026-11-04).
        let replica: Vec<SignedLedgerUpdate> = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            ledgers
                .get(ledger_id)
                .map(|l| l.read().unwrap().history.clone())
                .unwrap_or_default()
        };
        for u in replica {
            if !updates.iter().any(|h| h.chain_hash() == u.chain_hash()) {
                updates.push(u);
            }
        }
        // DEP-06 §Spend challenge: the dispute updates published as Challenge Answers (Kind
        // 9112) count too, for a judge whose relay view lacks them.
        for u in self.handler.spend_answers_for(ledger_id) {
            if !updates.iter().any(|h| h.chain_hash() == u.chain_hash()) {
                updates.push(u);
            }
        }
        updates
    }

    /// Queue a spend whose manifest we owe (a request handler answers first; the periodic loop
    /// publishes, [`Self::publish_queued_manifests`]).
    pub(crate) fn queue_confiscation_manifest(ledger_id: &str, spend: Transaction) {
        manifest_queue()
            .lock()
            .unwrap()
            .push((ledger_id.to_string(), spend));
    }

    pub(crate) async fn publish_queued_manifests(&self) {
        let q: Vec<(String, Transaction)> = std::mem::take(&mut *manifest_queue().lock().unwrap());
        for (id, tx) in q {
            self.publish_confiscation_manifest(&id, &tx, None).await;
        }
    }

    /// DEP-03 §Arm manifests: publish the arm set our own rebuild of `spend` (a confiscation of
    /// `ledger_id`'s vault, unconfirmed or confirmed at `height`) uses; strict-lottery-v8 only.
    pub(crate) async fn publish_confiscation_manifest(
        &self,
        ledger_id: &str,
        spend: &Transaction,
        height: Option<u32>,
    ) {
        let Some(lid) = hex::decode(ledger_id)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
        else {
            return;
        };
        let updates = self.judge_updates(ledger_id).await;
        let grounds = Box::pin(self.grounds_verdicts(&updates)).await;
        if !deposits_core::types::ruleset_strict_lottery(&grounds.ruleset) {
            return;
        }
        let chain = self.wallet.chain_backend();
        let network = self.wallet.network();
        let tx = spend.clone();
        let set = tokio::task::spawn_blocking(move || {
            rebuild_arm_set(&*chain, &lid, &updates, network, &tx, height, &grounds)
        })
        .await;
        match set {
            Ok(Ok(arms)) => self.publish_arm_manifest(ledger_id, spend, 1, &arms).await,
            Ok(Err(e)) => tracing::info!(
                "arm manifest of {}'s {}: no rebuild ({})",
                &ledger_id[..8.min(ledger_id.len())],
                &spend.compute_txid().to_string()[..16],
                e
            ),
            Err(_) => {}
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn judge_with(
        &self,
        ledger_id: &str,
        lid: [u8; 32],
        updates: Vec<SignedLedgerUpdate>,
        chain: std::sync::Arc<dyn ChainBackend>,
        network: bitcoin::Network,
        tx: Transaction,
        height: Option<u32>,
        txid: bitcoin::Txid,
        matched: &std::sync::Mutex<std::collections::HashSet<bitcoin::Txid>>,
    ) -> bool {
        // DEP-03 §When the set is final: a DisputeEnter signed above the spend's block takes no
        // part (its grounds are not judged, so they convict nobody).
        let updates = deposits_core::rotation_order::without_enters_above(&updates, height);
        // DEP-03 §Grounded arms: each disputant's grounds, judged here before the rebuild.
        // Boxed: judging a carried vault-spend proof can ask this again for the spend it cites.
        let grounds = Box::pin(self.grounds_verdicts(&updates)).await;
        let manifests = self.arm_manifests(ledger_id, 1).await;
        let id_log = ledger_id.to_string();
        let verdict = tokio::task::spawn_blocking(move || {
            // DEP-03 §Arm manifests: a published arm set first, then (a judge without one) the
            // subsets of the latest arms, whose match is a valid set too.
            if !manifests.is_empty() {
                match rebuild_matching_manifest(
                    &*chain, &lid, &updates, network, &tx, height, &grounds, &manifests,
                ) {
                    Ok(i) => {
                        tracing::info!(
                            "{}'s spend {} rebuilds from its arm manifest ({} arms)",
                            &id_log[..8.min(id_log.len())],
                            &tx.compute_txid().to_string()[..16],
                            manifests[i].len()
                        );
                        return Ok(());
                    }
                    Err(e) => tracing::debug!("{}: {}", &id_log[..8.min(id_log.len())], e),
                }
            }
            rebuild_matching(&*chain, &lid, &updates, network, &tx, height, &grounds)
        })
        .await;
        match verdict {
            Ok(Ok(())) => {
                matched.lock().unwrap().insert(txid);
                true
            }
            Ok(Err(why)) => {
                tracing::info!(
                    "spend {} of {}'s vault is not its confiscation rebuilt from public state: {}",
                    &txid.to_string()[..16],
                    &ledger_id[..16.min(ledger_id.len())],
                    why
                );
                false
            }
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain_backend::{ConfirmedSpend, UnspentOutput};
    use crate::error::Error;
    use bitcoin::{absolute, transaction, Amount, BlockHash, Script, ScriptBuf, TxOut, Txid};
    use std::collections::HashMap;

    /// Pledges as the vector states them: created at a height, the declared value, unspent.
    struct Pledges(HashMap<Txid, (u32, u32, u64)>);

    impl ChainBackend for Pledges {
        fn get_tip_height(&self) -> Result<u32, Error> {
            Ok(1_000_000)
        }
        fn get_block_hash(&self, _: u32) -> Result<BlockHash, Error> {
            Err(Error::Wallet("no blocks".into()))
        }
        fn get_block_height_if_in_best_chain(&self, _: &BlockHash) -> Result<Option<u32>, Error> {
            Ok(None)
        }
        fn get_tx(&self, t: &Txid) -> Result<Option<Transaction>, Error> {
            Ok(self.0.get(t).map(|(_, vout, sats)| Transaction {
                version: transaction::Version::TWO,
                lock_time: absolute::LockTime::ZERO,
                input: vec![],
                output: (0..=*vout)
                    .map(|i| TxOut {
                        value: Amount::from_sat(if i == *vout { *sats } else { 0 }),
                        script_pubkey: ScriptBuf::new(),
                    })
                    .collect(),
            }))
        }
        fn get_tx_block_height(&self, t: &Txid) -> Result<Option<u32>, Error> {
            Ok(self.0.get(t).map(|x| x.0))
        }
        fn is_output_unspent(&self, _: &Txid, _: u32) -> Result<Option<bool>, Error> {
            Ok(Some(true))
        }
        fn find_unspent_output_at(&self, _: &Script) -> Result<Option<UnspentOutput>, Error> {
            Ok(None)
        }
        fn find_spending_tx(
            &self,
            _: &OutPoint,
            _: &Script,
            _: u32,
        ) -> Result<Option<Transaction>, Error> {
            Ok(None)
        }
        fn confirmed_spend(
            &self,
            _: &OutPoint,
            _: &Script,
            _: u32,
        ) -> Result<ConfirmedSpend, Error> {
            Ok(ConfirmedSpend::Unspent)
        }
        fn spent_within(
            &self,
            _: &OutPoint,
            _: &Script,
            _: u32,
            _: u32,
        ) -> Result<Option<u32>, Error> {
            Ok(None)
        }
        fn broadcast_tx(&self, _: &Transaction) -> Result<Txid, Error> {
            Err(Error::Wallet("no broadcast".into()))
        }
    }

    /// DEP-06 "Authorised confiscation", against the vector cl-deposits generates
    /// (inspect/vectors/authorised_confiscation.txt): from the relay's updates alone, as a node
    /// that never saw the dispute, the real confiscation (and a lottery over a set the cut
    /// yields for a subset of the arms) is excused; a spend that merely pays a lottery (a
    /// stranger in it, a short output, an extra output) or the proposer's key is not.
    #[test]
    fn authorised_confiscation_vector() {
        authorised_confiscation_cases(
            include_str!("../../tests/vectors/authorised_confiscation.txt"),
            6,
        );
    }

    /// DEP-06 "Authorised confiscation": the base ends at the dispute's last fork point, against
    /// the vector cl-deposits generated from the signet soak's ledger 6056fb38
    /// (tests/vectors/confiscation_past_fault.txt). The operator's chain carries on past the fork
    /// point with the fault itself; the honest rung 1 that confirmed is excused, an amount off by
    /// one is not.
    #[test]
    fn confiscation_past_fault_vector() {
        authorised_confiscation_cases(
            include_str!("../../tests/vectors/confiscation_past_fault.txt"),
            2,
        );
    }

    /// DEP-03 §Fee ladder: a confiscation of a vault whose rotation confirmed at a higher rung,
    /// judged after the vault was spent, against the vector cl-deposits generated on regtest
    /// (tests/vectors/confiscation_vault_rung.txt; signet soak 2026-11-08, ledger G). The rung is
    /// read from the spend's input and its value from that output; the real spend is excused, one
    /// a sat short is not.
    #[test]
    fn confiscation_vault_rung_vector() {
        authorised_confiscation_cases(
            include_str!("../../tests/vectors/confiscation_vault_rung.txt"),
            2,
        );
    }

    /// DEP-03 §Arm manifests (ruled 2026-11-15, option A), against the vector cl-deposits
    /// generates (inspect/vectors/confiscation_manifest.txt): authorised_confiscation.txt's
    /// dispute plus a participant's round-1 re-arm signed at the spend's block, pledging an
    /// unknown coin, published after the spend. Each armer's latest arm no longer rebuilds the
    /// confiscation; the arm set its signers used does; a set missing a participant, or naming
    /// the backdated arm, does not.
    #[test]
    fn confiscation_manifest_vector() {
        use bitcoin::hashes::Hash;
        let text = include_str!("../../tests/vectors/confiscation_manifest.txt");
        let mut kv: HashMap<&str, &str> = HashMap::new();
        let mut updates = Vec::new();
        let mut pledges = HashMap::new();
        let mut cases = Vec::new();
        for line in text
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
        {
            let w: Vec<&str> = line.split(' ').collect();
            match w[0] {
                "update" => updates
                    .push(SignedLedgerUpdate::tlv_decode(&hex::decode(w[1]).unwrap()).unwrap()),
                "pledge" => {
                    let txid =
                        Txid::from_byte_array(hex::decode(w[1]).unwrap().try_into().unwrap());
                    pledges.insert(
                        txid,
                        (
                            w[4].parse().unwrap(),
                            w[2].parse().unwrap(),
                            w[3].parse().unwrap(),
                        ),
                    );
                }
                "case" => cases.push((w[1], w[2] == "1", w[3], w[4])),
                k => {
                    kv.insert(k, w[1]);
                }
            }
        }
        let chain = Pledges(pledges);
        let lid: [u8; 32] = hex::decode(kv["ledger"]).unwrap().try_into().unwrap();
        let h: u32 = kv["spend_height"].parse().unwrap();
        assert_eq!(cases.len(), 4);
        let origin = crate::node::armers::original_operator(&updates).unwrap();
        let mut history: Vec<SignedLedgerUpdate> = updates
            .iter()
            .filter(|u| u.operator_id == origin)
            .cloned()
            .collect();
        history.sort_by_key(|u| u.sequence_number);
        let grounds = crate::node::armers::GroundsVerdicts::with_verifier(&updates, |b| {
            use crate::node::armers::Verdict;
            match &b.proof.evidence {
                deposits_core::fraud::FraudEvidence::NonConformingUpdate { .. } => {
                    match deposits_core::fraud::verify_non_conforming_update(
                        &b.proof,
                        &history,
                        &deposits_core::dep16::Dep16Authorizer::new(),
                    ) {
                        Ok(()) => (Verdict::Grounded, "its proof verifies".into()),
                        Err(e) => (Verdict::Ungrounded, e),
                    }
                }
                _ => (Verdict::Unknown, "not verified here".into()),
            }
        });
        for (name, excused, manifest, hex_tx) in cases {
            let tx: Transaction =
                bitcoin::consensus::deserialize(&hex::decode(hex_tx).unwrap()).unwrap();
            let v = if manifest == "-" {
                rebuild_matching(
                    &chain,
                    &lid,
                    &updates,
                    bitcoin::Network::Signet,
                    &tx,
                    Some(h),
                    &grounds,
                )
            } else {
                let m: Vec<(bitcoin::secp256k1::PublicKey, u64)> = manifest
                    .split(',')
                    .map(|e| {
                        let (k, q) = e.split_once(':').unwrap();
                        (
                            bitcoin::secp256k1::PublicKey::from_slice(&hex::decode(k).unwrap())
                                .unwrap(),
                            q.parse().unwrap(),
                        )
                    })
                    .collect();
                // The fixture's ruleset predates strict-lottery-v8; the manifest rule itself
                // is what is checked here (rebuild_matching_manifest gates on the ruleset).
                let scoped = deposits_core::rotation_order::dispute_scope(&updates);
                rebuild_matching_in(
                    &chain,
                    &lid,
                    &scoped,
                    bitcoin::Network::Signet,
                    &tx,
                    Some(h),
                    &grounds,
                    Some(&m),
                )
            };
            assert_eq!(v.is_ok(), excused, "{name}: {v:?}");
        }
    }

    fn authorised_confiscation_cases(text: &str, expected_cases: usize) {
        use bitcoin::hashes::Hash;
        let mut kv: HashMap<&str, &str> = HashMap::new();
        let mut updates = Vec::new();
        let mut pledges = HashMap::new();
        let mut cases = Vec::new();
        for line in text
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
        {
            let w: Vec<&str> = line.split(' ').collect();
            match w[0] {
                "update" => updates
                    .push(SignedLedgerUpdate::tlv_decode(&hex::decode(w[1]).unwrap()).unwrap()),
                "pledge" => {
                    let txid =
                        Txid::from_byte_array(hex::decode(w[1]).unwrap().try_into().unwrap());
                    pledges.insert(
                        txid,
                        (
                            w[4].parse().unwrap(),
                            w[2].parse().unwrap(),
                            w[3].parse().unwrap(),
                        ),
                    );
                }
                "case" => cases.push((w[1], w[2] == "1", w[3])),
                k => {
                    kv.insert(k, w[1]);
                }
            }
        }
        let chain = Pledges(pledges);
        let lid: [u8; 32] = hex::decode(kv["ledger"]).unwrap().try_into().unwrap();
        let h: u32 = kv["spend_height"].parse().unwrap();
        assert_eq!(cases.len(), expected_cases);
        // Grounds are judged as a node holding the ledger judges them: a carried
        // NonConformingUpdate against the original operator's chain.
        let origin = crate::node::armers::original_operator(&updates).unwrap();
        let mut history: Vec<SignedLedgerUpdate> = updates
            .iter()
            .filter(|u| u.operator_id == origin)
            .cloned()
            .collect();
        history.sort_by_key(|u| u.sequence_number);
        let grounds = crate::node::armers::GroundsVerdicts::with_verifier(&updates, |b| {
            use crate::node::armers::Verdict;
            match &b.proof.evidence {
                deposits_core::fraud::FraudEvidence::NonConformingUpdate { .. } => {
                    match deposits_core::fraud::verify_non_conforming_update(
                        &b.proof,
                        &history,
                        &deposits_core::dep16::Dep16Authorizer::new(),
                    ) {
                        Ok(()) => (Verdict::Grounded, "its proof verifies".into()),
                        Err(e) => (Verdict::Ungrounded, e),
                    }
                }
                _ => (Verdict::Unknown, "not verified here".into()),
            }
        });
        for (name, excused, hex_tx) in cases {
            let tx: Transaction =
                bitcoin::consensus::deserialize(&hex::decode(hex_tx).unwrap()).unwrap();
            let v = rebuild_matching(
                &chain,
                &lid,
                &updates,
                bitcoin::Network::Signet,
                &tx,
                Some(h),
                &grounds,
            );
            assert_eq!(v.is_ok(), excused, "{name}: {v:?}");
        }
    }
}
