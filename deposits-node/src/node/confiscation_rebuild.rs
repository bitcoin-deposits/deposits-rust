//! DEP-06 "Authorised confiscation": a spend of a disputed ledger's vault is a confiscation
//! iff it is byte-identical to the confiscation the rules build from public state (the ledger's
//! history, the public `DisputeArmed` events, the eligibility cut as of the spend's block, the
//! obligations, the fee rule), its lottery over the set the cut yields for some subset of the
//! arms. Never "one we know of": a member that missed the dispute (a restart, a node that
//! joined later) rebuilds it from the relay and reaches the same verdict as one that signed it.

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
    rebuild_matching(chain, ledger_id, updates, network, spend, spend_height).is_ok()
}

/// The verdict with its reason (for logs and tests): `Ok(())` when `spend` is a rebuild.
pub fn rebuild_matching(
    chain: &dyn ChainBackend,
    ledger_id: &[u8; 32],
    updates: &[SignedLedgerUpdate],
    network: bitcoin::Network,
    spend: &Transaction,
    spend_height: Option<u32>,
) -> Result<(), String> {
    use deposits_core::tapscript_reserves::{
        build_confiscation_tx, ConfiscationTxParams, LotteryScriptBuilder,
    };
    let view = dispute_view(ledger_id, updates).ok_or("no LedgerOpen for this ledger")?;
    let origin = view[0].operator_id;
    let fork_point = dispute_last_valid_sequence(&view).ok_or("no DisputeEnter")?;

    // The governing QuorumBegin: the original operator's newest at or before the fork point.
    let (qb_members, qb_expiry, qb_ruleset, vault) = view
        .iter()
        .filter(|u| u.operator_id == origin && u.sequence_number <= fork_point)
        .filter_map(|u| match LedgerOperation::tlv_decode(&u.message) {
            Ok(LedgerOperation::QuorumBegin {
                quorum_members,
                quorum_expiry,
                protocol_version,
                new_outpoint_txid,
                new_outpoint_vout,
                amount,
                collateral_amount,
                ..
            }) => Some((
                u.sequence_number,
                quorum_members.iter().map(|m| m.pubkey).collect::<Vec<_>>(),
                quorum_expiry,
                protocol_version,
                (
                    OutPoint::new(
                        bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array(
                            new_outpoint_txid,
                        )),
                        new_outpoint_vout,
                    ),
                    (amount + collateral_amount) / 1000,
                ),
            )),
            _ => None,
        })
        .max_by_key(|(seq, ..)| *seq)
        .map(|(_, m, e, r, v)| (m, e, r, v))
        .ok_or("no QuorumBegin at or before the fork point")?;

    if spend.input.first().map(|i| i.previous_output) != Some(vault.0) {
        return Err("input 0 is not the vault".into());
    }

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
    let (recovery_voters, recovery_threshold) =
        deposits_core::rotation_order::lottery_recovery_voters(&view)
            .ok_or("no recovery voters")?;
    let respectful = dispute_is_respectful(&view);
    let required = required_sats(&view, None)?;

    // The arms that count as of the spend's block; the cut of each subset of them (the full
    // set first: the cut every member computes once the relay has delivered every arm).
    let armers = collect_armers_until(&view, spend_height);
    if armers.is_empty() || armers.len() > 8 {
        return Err(format!("{} armers", armers.len()));
    }
    let n = armers.len();
    let mut tried = std::collections::HashSet::new();
    let mut closest: Option<String> = None;
    for mask in (1u32..(1 << n)).rev() {
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
        let lottery = LotteryScriptBuilder::new(
            set.lottery_participants(),
            recovery_voters.clone(),
            recovery_threshold,
            network,
        )
        .build()
        .map_err(|e| format!("lottery: {e:?}"))?;
        let obligations = confiscation_obligations(chain, &view, &set)?;
        let rebuilt = build_confiscation_tx(&ConfiscationTxParams {
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
        });
        if rebuilt.compute_txid() == spend.compute_txid() {
            return Ok(());
        }
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
        let updates = self.fetch_all_ledger_updates_paginated(ledger_id).await;
        if updates.is_empty() {
            return false;
        }
        let chain = self.wallet.chain_backend();
        let network = self.wallet.network();
        let tx = tx.clone();
        let verdict = tokio::task::spawn_blocking(move || {
            rebuild_matching(&*chain, &lid, &updates, network, &tx, height)
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
        use bitcoin::hashes::Hash;
        let text = include_str!("../../tests/vectors/authorised_confiscation.txt");
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
        assert_eq!(cases.len(), 6);
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
            );
            assert_eq!(v.is_ok(), excused, "{name}: {v:?}");
        }
    }
}
