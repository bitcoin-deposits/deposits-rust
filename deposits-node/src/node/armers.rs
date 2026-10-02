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

use crate::chain_backend::{ChainBackend, ConfirmedSpend};

/// DEP-03 `claim_fee_floor` when the governing `QuorumBegin` records no
/// reference feerate (this implementation never records one).
pub const CLAIM_FEE_FLOOR_SATS: u64 = 5_000;

/// Depth past E at which a verdict can no longer change, so it is cached.
const BURIED: u32 = 6;

/// One armer's latest `DisputeArmed`.
#[derive(Clone, Debug)]
pub struct Armer {
    pub key: PublicKey,
    pub participant: LotteryParticipant,
    /// Signed-header `block_height` of the armer's latest `DisputeArmed`.
    pub arm_height: u32,
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
    let operator = original_operator(updates);
    let mut latest: HashMap<PublicKey, (u64, Armer)> = HashMap::new();
    for u in updates {
        if Some(u.operator_id) == operator {
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
        let armer = Armer {
            key: u.operator_id,
            participant: LotteryParticipant::new(
                u.operator_id.x_only_public_key().0,
                commitment_hash,
                target_reserves,
            ),
            arm_height: u.block_height,
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
    match chain
        .confirmed_spend(&outpoint, &output.script_pubkey, snapshot + 1)
        .map_err(e)?
    {
        ConfirmedSpend::Unspent => Ok(None),
        ConfirmedSpend::SpentAt(h) if h > snapshot => Ok(None),
        ConfirmedSpend::SpentAt(h) => Ok(Some(format!(
            "pledge spent at {}, at or before the snapshot {}",
            h, snapshot
        ))),
        ConfirmedSpend::SpentBefore(_) => Ok(Some(format!(
            "pledge spent at or before the snapshot {}",
            snapshot
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
    let required = required_sats(updates, last_valid_sequence)?;
    split(chain, collect_armers(updates), required)
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
        let updates = self.fetch_all_ledger_updates_paginated(ledger_id).await;
        if updates.is_empty() {
            return Err("failed to fetch ledger updates from relay".into());
        }
        let chain = self.wallet.chain_backend();
        let set = eligible_armers(&*chain, &updates, None)?;
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
            let set = split(&chain, armers, case["required_sats"].as_u64().unwrap()).unwrap();
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
