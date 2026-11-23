//! DEP-06 "An acquire binds once its claim confirms" (strict-lottery-v8): a `DisputeAcquire`
//! binds iff its `claim_txid` is confirmed AND its input 0 spends the dispute's current
//! lottery outpoint. Confirmation alone is not enough: in regtest rearm-rust 1120-090836
//! a606a4ca's acquire named 21910507, a confirmed claim of 70b0abb3's round-2 output
//! (46a66b12:0, the same script and value), and every node read a606a4ca's custody as moved
//! while its own lottery output 1d89bd45:0 stayed unspent. Any armer could likewise name any
//! confirmed transaction. Judged from the chain alone, from the claim back; vector
//! `tests/vectors/acquire_binding.json`, shared with cl-deposits.

use bitcoin::{OutPoint, Transaction, Txid};

/// The recovery tiers' CSVs: a re-arm spend's one input carries one of them (DEP-06 Phase 4
/// step 4); a claim's input 0 carries `0xfffffffd` or `LOTTERY_REVEAL_CSV` (DEP-03).
pub(crate) const REARM_TIER_CSVS: [u32; 4] = [144, 1008, 4032, 8064];
/// Rounds followed back from a claim (an armer's arms span at most this many rounds).
pub(crate) const MAX_ROUNDS: usize = 8;

/// Whether an acquire binds, and if not, why.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AcquireVerdict {
    Binds,
    /// The claim is unknown or unconfirmed (or a transaction on its way back is unknown):
    /// asked again later.
    Unconfirmed,
    /// The named transaction is a re-arm spend: it moved an older round's lottery output on.
    NotAClaim,
    /// The claim spends something other than this dispute's lottery.
    NotThisLottery,
}

impl AcquireVerdict {
    /// The vector's spelling.
    pub(crate) fn reason(&self) -> &'static str {
        match self {
            AcquireVerdict::Binds => "binds",
            AcquireVerdict::Unconfirmed => "unconfirmed",
            AcquireVerdict::NotAClaim => "not-a-claim",
            AcquireVerdict::NotThisLottery => "not-this-lottery",
        }
    }
    /// A verdict that cannot change: worth remembering.
    pub(crate) fn is_final(&self) -> bool {
        !matches!(self, AcquireVerdict::Unconfirmed)
    }
}

/// One input, one output, the input's nSequence a recovery tier's CSV.
pub(crate) fn rearm_shaped(tx: &Transaction) -> bool {
    tx.input.len() == 1
        && tx.output.len() == 1
        && REARM_TIER_CSVS.contains(&tx.input[0].sequence.to_consensus_u32())
}

/// Judge `claim` for the dispute that confiscated the vault `vaults` names (the vault
/// outpoint of every rung of its QuorumBegin's fee ladder, DEP-03: any may have confirmed).
/// `tx` answers a transaction and whether it is confirmed, or `None` when the judge does not
/// know it.
pub(crate) fn judge_acquire(
    tx: impl Fn(&Txid) -> Option<(Transaction, bool)>,
    vaults: &[OutPoint],
    claim: &Txid,
) -> AcquireVerdict {
    judge_acquire_round(tx, vaults, claim).0
}

/// [`judge_acquire`], with the round the claim closes when it binds: 1 when it spends the
/// confiscation's lottery output, one more for each re-arm spend followed back (0 when it
/// does not bind).
pub(crate) fn judge_acquire_round(
    tx: impl Fn(&Txid) -> Option<(Transaction, bool)>,
    vaults: &[OutPoint],
    claim: &Txid,
) -> (AcquireVerdict, u32) {
    let Some((claim_tx, true)) = tx(claim) else {
        return (AcquireVerdict::Unconfirmed, 0);
    };
    if rearm_shaped(&claim_tx) {
        return (AcquireVerdict::NotAClaim, 0);
    }
    let Some(mut spent) = claim_tx.input.first().map(|i| i.previous_output) else {
        return (AcquireVerdict::NotThisLottery, 0);
    };
    for hops in 0..=MAX_ROUNDS {
        if spent.vout != 0 {
            return (AcquireVerdict::NotThisLottery, 0);
        }
        let Some((t, confirmed)) = tx(&spent.txid) else {
            return (AcquireVerdict::Unconfirmed, 0);
        };
        if t.input.iter().any(|i| vaults.contains(&i.previous_output)) {
            return (AcquireVerdict::Binds, hops as u32 + 1);
        }
        if !(confirmed && rearm_shaped(&t)) {
            return (AcquireVerdict::NotThisLottery, 0);
        }
        spent = t.input[0].previous_output;
    }
    (AcquireVerdict::NotThisLottery, 0)
}

/// DEP-06 "What a yield must say" (`yield-evidence-v9`, ruled 2026-11-23): the verdict on a
/// `DisputeYield`'s reason. Shared with cl's `judge-yield`; vector `yield_evidence.json`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum YieldVerdict {
    Valid,
    Invalid,
    /// No verdict yet: something named is unknown or unconfirmed; asked again later.
    Pending,
}

impl YieldVerdict {
    /// The vector's spelling.
    pub(crate) fn name(&self) -> &'static str {
        match self {
            YieldVerdict::Valid => "valid",
            YieldVerdict::Invalid => "invalid",
            YieldVerdict::Pending => "pending",
        }
    }
}

/// What a judge knows when it judges a yield (see [`judge_yield`]).
pub(crate) struct YieldContext<'a> {
    /// The fork's ruleset (the fork point's).
    pub ruleset: &'a str,
    /// The yield's signed `block_height`.
    pub yield_height: u32,
    /// The round of the yielder's latest arm before the yield.
    pub arm_round: u32,
    /// The yielder's x-only key.
    pub yielder: [u8; 32],
    /// The scriptPubKeys of every `target_reserves` the yielder declared in the dispute.
    pub targets: &'a [bitcoin::ScriptBuf],
    /// Every replacement collateral outpoint the yielder declared in the dispute.
    pub pledges: &'a [OutPoint],
    /// The dispute's vault outpoints ([`judge_acquire`]).
    pub vaults: &'a [OutPoint],
    /// The fork's latest `DisputeEnter`: its reason and `last_valid_sequence`.
    pub dispute_reason: &'a str,
    pub last_valid_sequence: u64,
    /// The operator chain's `QuorumBegin`s: (`content_hash`, sequence, rotation spend confirmed).
    pub quorum_begins: &'a [([u8; 32], u64, bool)],
    /// The x-only keys of the lottery an `excluded_by` names, as the judge rebuilt it.
    pub participants: &'a [[u8; 32]],
}

/// The round of the lottery `txid` created for the dispute of `vaults`: 1 when it spends a
/// vault, one more for each confirmed re-arm spend walked back (each spending output 0 of the
/// previous). `tx` answers a transaction and whether it is confirmed.
pub(crate) fn lottery_tx_round(
    tx: impl Fn(&Txid) -> Option<(Transaction, bool)>,
    vaults: &[OutPoint],
    txid: &Txid,
) -> (AcquireVerdict, u32) {
    let mut cur = *txid;
    for round in 1..=(MAX_ROUNDS as u32 + 1) {
        let Some((t, confirmed)) = tx(&cur) else {
            return (AcquireVerdict::Unconfirmed, 0);
        };
        if t.input.iter().any(|i| vaults.contains(&i.previous_output)) {
            return (AcquireVerdict::Binds, round);
        }
        if !(confirmed && rearm_shaped(&t)) || t.input[0].previous_output.vout != 0 {
            return (AcquireVerdict::NotThisLottery, 0);
        }
        cur = t.input[0].previous_output.txid;
    }
    (AcquireVerdict::NotThisLottery, 0)
}

/// The verdict on a `DisputeYield` carrying `lost_to` / `reestablished` / `excluded_by`, and
/// why (the vector's `why`). `tx` answers a transaction and its block height (None:
/// unconfirmed), or None when the judge does not know it. Checked in the vector's order.
pub(crate) fn judge_yield(
    tx: impl Fn(&Txid) -> Option<(Transaction, Option<u32>)>,
    ctx: &YieldContext<'_>,
    lost_to: Option<[u8; 32]>,
    reestablished: Option<[u8; 32]>,
    excluded_by: Option<[u8; 32]>,
) -> (YieldVerdict, &'static str) {
    use bitcoin::hashes::Hash;
    use YieldVerdict::*;
    if !deposits_core::types::ruleset_yield_evidence(ctx.ruleset) {
        return (Valid, "legacy");
    }
    let named = [lost_to, reestablished, excluded_by]
        .iter()
        .filter(|r| r.is_some())
        .count();
    if named != 1 {
        return (Invalid, "no-reason");
    }
    let confirmed = |t: &Txid| tx(t).map(|(t, h)| (t, h.is_some()));
    // The named transaction: confirmed, and at or below the yield's height.
    let seen = |t: &Txid| -> Result<Transaction, (YieldVerdict, &'static str)> {
        match tx(t) {
            Some((t, Some(h))) if h <= ctx.yield_height => Ok(t),
            Some((_, Some(_))) => Err((Invalid, "early")),
            _ => Err((Pending, "unconfirmed")),
        }
    };
    if let Some(l) = lost_to {
        let t = Txid::from_byte_array(l);
        let claim = match seen(&t) {
            Ok(c) => c,
            Err(v) => return v,
        };
        let (v, round) = judge_acquire_round(confirmed, ctx.vaults, &t);
        return match v {
            AcquireVerdict::Unconfirmed => (Pending, "unconfirmed"),
            AcquireVerdict::NotAClaim | AcquireVerdict::NotThisLottery => (Invalid, v.reason()),
            AcquireVerdict::Binds if round < ctx.arm_round => (Invalid, "earlier-round"),
            AcquireVerdict::Binds => {
                let own_target = claim
                    .output
                    .first()
                    .is_some_and(|o| ctx.targets.contains(&o.script_pubkey));
                let own_pledge = claim
                    .input
                    .get(1)
                    .is_some_and(|i| ctx.pledges.contains(&i.previous_output));
                if own_target || own_pledge {
                    (Invalid, "own-claim")
                } else {
                    (Valid, "valid")
                }
            }
        };
    }
    if let Some(h) = reestablished {
        if !crate::node::expiry_watch::is_expiry_reason(ctx.dispute_reason) {
            return (Invalid, "not-expiry");
        }
        let Some((_, seq, spent)) = ctx.quorum_begins.iter().find(|(q, _, _)| *q == h) else {
            return (Pending, "unknown-quorum-begin");
        };
        if *seq <= ctx.last_valid_sequence {
            return (Invalid, "not-after-fork-point");
        }
        if !spent {
            return (Pending, "rotation-unconfirmed");
        }
        return (Valid, "valid");
    }
    let t = Txid::from_byte_array(excluded_by.expect("one reason is named"));
    if let Err(v) = seen(&t) {
        return v;
    }
    match lottery_tx_round(confirmed, ctx.vaults, &t) {
        (AcquireVerdict::Unconfirmed, _) => (Pending, "unconfirmed"),
        (AcquireVerdict::Binds, round) if round < ctx.arm_round => (Invalid, "earlier-round"),
        (AcquireVerdict::Binds, _) if ctx.participants.contains(&ctx.yielder) => {
            (Invalid, "in-lottery")
        }
        (AcquireVerdict::Binds, _) => (Valid, "valid"),
        _ => (Invalid, "not-this-lottery"),
    }
}

/// [`judge_acquire`] against a chain backend.
pub(crate) fn judge_acquire_on(
    backend: &dyn crate::chain_backend::ChainBackend,
    vaults: &[OutPoint],
    claim: &Txid,
) -> AcquireVerdict {
    judge_acquire_round_on(backend, vaults, claim).0
}

/// [`judge_acquire_round`] against a chain backend.
pub(crate) fn judge_acquire_round_on(
    backend: &dyn crate::chain_backend::ChainBackend,
    vaults: &[OutPoint],
    claim: &Txid,
) -> (AcquireVerdict, u32) {
    judge_acquire_round(
        |t| {
            let tx = backend.get_tx(t).ok().flatten()?;
            let confirmed = matches!(backend.get_tx_block_height(t), Ok(Some(_)));
            Some((tx, confirmed))
        },
        vaults,
        claim,
    )
}

/// One `DisputeAcquire` and the vault it is judged against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AcquireRef {
    /// The vault of the latest `QuorumBegin` before the acquire not authored by the acquirer
    /// (an acquirer rotates only after it acquired), or `fallback` when the history holds none.
    pub vault: Option<Vault>,
    pub claim: [u8; 32],
    pub custodian: bitcoin::secp256k1::PublicKey,
    /// DEP-06 "A claim after the claimant's own yield" (the advantage rule): when the acquirer
    /// yielded after its latest arm, the round its claim must bind (that arm's or a later one);
    /// 0 when there is no bound ([`min_round`]).
    pub min_round: u32,
}

impl AcquireRef {
    /// Whether this acquire is known to bind against `vault`, with its round bound.
    pub(crate) fn binds_on(&self, vault: &[OutPoint]) -> bool {
        binds(vault, &self.claim)
            && (self.min_round == 0
                || binds_round(vault, &self.claim).is_some_and(|r| r >= self.min_round))
    }
}

/// One of an acquirer's own dispute operations before its acquire, oldest first, as
/// [`min_round`] reads them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OwnOp {
    Arm(u32),
    Yield,
    Acquire,
}

/// DEP-06 "A claim after the claimant's own yield": when a yield follows the acquirer's latest
/// arm, its acquire must bind that arm's round or a later one, and that round is the bound;
/// otherwise 0 (no bound). Shared with cl's `acquire-min-round`; vector claim_after_yield.json.
pub(crate) fn min_round(ops: &[OwnOp]) -> u32 {
    let (mut arm, mut yielded) = (0, false);
    for o in ops {
        match o {
            OwnOp::Arm(r) => (arm, yielded) = (*r, false),
            OwnOp::Yield => yielded = true,
            OwnOp::Acquire => yielded = false,
        }
    }
    if yielded {
        arm
    } else {
        0
    }
}

/// [`min_round`] of the acquire at `sorted[i]`, from its author's updates before it.
fn min_round_at(sorted: &[&deposits_core::SignedLedgerUpdate], i: usize) -> u32 {
    min_round_for(&sorted[..i], sorted[i])
}

/// [`min_round`] of `acquire`, from its author's updates in `history` below its sequence (any
/// order: a relay fetch mixes forks, and only the author's own updates are read).
pub(crate) fn min_round_for<'a>(
    history: impl IntoIterator<Item = &'a &'a deposits_core::SignedLedgerUpdate>,
    acquire: &deposits_core::SignedLedgerUpdate,
) -> u32 {
    use deposits_core::messages::LedgerOperation;
    use deposits_core::TlvDecode;
    let me = acquire.operator_id;
    let mut mine: Vec<&deposits_core::SignedLedgerUpdate> = history
        .into_iter()
        .copied()
        .filter(|u| u.operator_id == me && u.sequence_number < acquire.sequence_number)
        .collect();
    mine.sort_by_key(|u| u.sequence_number);
    let ops: Vec<OwnOp> = mine
        .iter()
        .filter_map(|u| match LedgerOperation::tlv_decode(&u.message).ok()? {
            LedgerOperation::DisputeArmed { rearm_round, .. } => {
                Some(OwnOp::Arm(rearm_round.unwrap_or(1)))
            }
            LedgerOperation::DisputeYield { .. } => Some(OwnOp::Yield),
            LedgerOperation::DisputeAcquire { .. } => Some(OwnOp::Acquire),
            _ => None,
        })
        .collect();
    min_round(&ops)
}

/// A `QuorumBegin`'s vault: the vault outpoint of every rung of its fee ladder (DEP-03), rung
/// 0 first. Rung 0 names it.
pub(crate) type Vault = Vec<OutPoint>;

fn qb_vault(op: &deposits_core::messages::LedgerOperation) -> Option<Vault> {
    use bitcoin::hashes::Hash;
    match op {
        deposits_core::messages::LedgerOperation::QuorumBegin {
            new_outpoint_vout, ..
        } => Some(
            deposits_core::vault_spend::quorum_begin_rungs(op)
                .into_iter()
                .map(|t| OutPoint::new(Txid::from_byte_array(t), *new_outpoint_vout))
                .collect(),
        ),
        _ => None,
    }
}

/// Every `DisputeAcquire` among the newest `tail` updates of `history` (any order), each
/// with its vault: searched back from the acquire, else `fallback`.
pub(crate) fn acquires_in(
    history: &[deposits_core::SignedLedgerUpdate],
    tail: usize,
    fallback: Option<Vault>,
) -> Vec<AcquireRef> {
    use deposits_core::messages::LedgerOperation;
    use deposits_core::TlvDecode;
    let mut sorted: Vec<&deposits_core::SignedLedgerUpdate> = history.iter().collect();
    sorted.sort_by_key(|u| u.sequence_number);
    let start = sorted.len().saturating_sub(tail);
    let mut out = Vec::new();
    for i in start..sorted.len() {
        let u = sorted[i];
        let Ok(LedgerOperation::DisputeAcquire {
            claim_txid,
            new_custodian,
            ..
        }) = LedgerOperation::tlv_decode(&u.message)
        else {
            continue;
        };
        let vault = sorted[..i]
            .iter()
            .rev()
            .filter(|q| q.operator_id != u.operator_id)
            .find_map(|q| qb_vault(&LedgerOperation::tlv_decode(&q.message).ok()?))
            .or_else(|| fallback.clone());
        out.push(AcquireRef {
            vault,
            claim: claim_txid,
            custodian: new_custodian,
            min_round: min_round_at(&sorted, i),
        });
    }
    out
}

/// The vault of the latest `QuorumBegin` in `history` at or below `seq`.
pub(crate) fn vault_at(history: &[deposits_core::SignedLedgerUpdate], seq: u64) -> Option<Vault> {
    use deposits_core::messages::LedgerOperation;
    use deposits_core::TlvDecode;
    history
        .iter()
        .filter(|u| u.sequence_number <= seq)
        .filter_map(|u| {
            Some((
                u.sequence_number,
                qb_vault(&LedgerOperation::tlv_decode(&u.message).ok()?)?,
            ))
        })
        .max_by_key(|(s, _)| *s)
        .map(|(_, v)| v)
}

/// (the vault's rung 0, claim).
type VerdictKey = (OutPoint, [u8; 32]);

fn key(vault: &[OutPoint], claim: &[u8; 32]) -> Option<VerdictKey> {
    vault.first().map(|v| (*v, *claim))
}

/// Final verdicts, keyed by (vault, claim). Filled off the co-sign path by
/// [`note_verdicts`], so a co-sign or adoption decision never waits on the chain.
fn verdicts() -> &'static std::sync::Mutex<std::collections::HashMap<VerdictKey, AcquireVerdict>> {
    static M: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<VerdictKey, AcquireVerdict>>,
    > = std::sync::OnceLock::new();
    M.get_or_init(Default::default)
}

/// The round each binding (vault, claim) closes ([`judge_acquire_round`]).
fn rounds() -> &'static std::sync::Mutex<std::collections::HashMap<VerdictKey, u32>> {
    static M: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<VerdictKey, u32>>> =
        std::sync::OnceLock::new();
    M.get_or_init(Default::default)
}

/// The round the acquire naming `claim` closes, when it is known to bind against `vault`.
pub(crate) fn binds_round(vault: &[OutPoint], claim: &[u8; 32]) -> Option<u32> {
    let k = key(vault, claim)?;
    rounds().lock().ok()?.get(&k).copied()
}

/// (vault, claim) -> when it was last judged not final: asked again after a minute, not on
/// every pass (a phantom acquire's claim never confirms; asking every claim on every pass
/// flooded the regtest bitcoind's RPC, 2026-11-10).
fn retry_after(
) -> &'static std::sync::Mutex<std::collections::HashMap<VerdictKey, std::time::Instant>> {
    static M: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<VerdictKey, std::time::Instant>>,
    > = std::sync::OnceLock::new();
    M.get_or_init(Default::default)
}

/// At most this many acquires judged per pass; the rest wait for the next.
const JUDGED_PER_PASS: usize = 16;

/// Whether the acquire naming `claim`, judged against `vault`, is known to bind.
pub(crate) fn binds(vault: &[OutPoint], claim: &[u8; 32]) -> bool {
    let Some(k) = key(vault, claim) else {
        return false;
    };
    verdicts()
        .lock()
        .map(|m| m.get(&k) == Some(&AcquireVerdict::Binds))
        .unwrap_or(false)
}

/// Whether `(vault, claim)` still needs judging.
pub(crate) fn pending(vault: &[OutPoint], claim: &[u8; 32]) -> bool {
    let Some(k) = key(vault, claim) else {
        return false;
    };
    verdicts()
        .lock()
        .map(|m| !m.contains_key(&k))
        .unwrap_or(true)
}

/// Judge `acquires` (from [`acquires_in`]) against the chain and remember the final verdicts.
pub(crate) fn note_verdicts(
    backend: &dyn crate::chain_backend::ChainBackend,
    acquires: &[(Vault, [u8; 32])],
) {
    use bitcoin::hashes::Hash;
    let now = std::time::Instant::now();
    let due: Vec<(Vault, [u8; 32], VerdictKey)> = {
        let seen = retry_after().lock().unwrap();
        acquires
            .iter()
            .filter(|(v, c)| pending(v, c))
            .filter_map(|(v, c)| Some((v.clone(), *c, key(v, c)?)))
            .filter(|(_, _, k)| {
                seen.get(k)
                    .map(|t| now.duration_since(*t).as_secs() >= 60)
                    .unwrap_or(true)
            })
            .take(JUDGED_PER_PASS)
            .collect()
    };
    for (vault, claim, k) in due {
        let (v, round) = judge_acquire_round_on(backend, &vault, &Txid::from_byte_array(claim));
        if v == AcquireVerdict::Binds {
            rounds().lock().unwrap().insert(k, round);
        }
        if v.is_final() {
            if v != AcquireVerdict::Binds {
                tracing::warn!(
                    "DisputeAcquire claim {} does not bind for vault {}: {}",
                    Txid::from_byte_array(claim),
                    k.0,
                    v.reason()
                );
            }
            verdicts().lock().unwrap().insert(k, v);
            retry_after().lock().unwrap().remove(&k);
        } else {
            retry_after().lock().unwrap().insert(k, now);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{
        absolute::LockTime, transaction::Version, Amount, ScriptBuf, Sequence, TxIn, TxOut,
    };
    use std::collections::HashMap;
    use std::str::FromStr;

    fn view(v: &serde_json::Value) -> HashMap<Txid, (Transaction, bool)> {
        v["txs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| {
                let input = t["inputs"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|i| TxIn {
                        previous_output: OutPoint::new(
                            Txid::from_str(i["txid"].as_str().unwrap()).unwrap(),
                            i["vout"].as_u64().unwrap() as u32,
                        ),
                        script_sig: ScriptBuf::new(),
                        sequence: Sequence(i["sequence"].as_u64().unwrap() as u32),
                        witness: Default::default(),
                    })
                    .collect();
                let output = (0..t["outputs"].as_u64().unwrap())
                    .map(|_| TxOut {
                        value: Amount::from_sat(1000),
                        script_pubkey: ScriptBuf::new(),
                    })
                    .collect();
                (
                    Txid::from_str(t["txid"].as_str().unwrap()).unwrap(),
                    (
                        Transaction {
                            version: Version::TWO,
                            lock_time: LockTime::ZERO,
                            input,
                            output,
                        },
                        t["confirmed"].as_bool().unwrap(),
                    ),
                )
            })
            .collect()
    }

    fn vector() -> serde_json::Value {
        serde_json::from_str(include_str!("../../tests/vectors/acquire_binding.json")).unwrap()
    }

    fn judge_case(c: &serde_json::Value) -> AcquireVerdict {
        let txs = view(c);
        let vaults: Vec<OutPoint> = c["vaults"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| {
                OutPoint::new(
                    Txid::from_str(v["txid"].as_str().unwrap()).unwrap(),
                    v["vout"].as_u64().unwrap() as u32,
                )
            })
            .collect();
        let claim = Txid::from_str(c["claim_txid"].as_str().unwrap()).unwrap();
        judge_acquire(|t| txs.get(t).cloned(), &vaults, &claim)
    }

    /// The round a binding claim closes (0 when it does not bind): DEP-03 "When a pledge is
    /// live" frees our arms of that round when another participant's acquire binds.
    #[test]
    fn the_round_a_claim_closes_matches_the_shared_vector() {
        let v = vector();
        for c in v["cases"].as_array().unwrap() {
            let txs = view(c);
            let vaults: Vec<OutPoint> = c["vaults"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| {
                    OutPoint::new(
                        Txid::from_str(v["txid"].as_str().unwrap()).unwrap(),
                        v["vout"].as_u64().unwrap() as u32,
                    )
                })
                .collect();
            let claim = Txid::from_str(c["claim_txid"].as_str().unwrap()).unwrap();
            let (_, round) = judge_acquire_round(|t| txs.get(t).cloned(), &vaults, &claim);
            assert_eq!(round as u64, c["round"].as_u64().unwrap(), "{}", c["name"]);
        }
    }

    #[test]
    fn acquire_binding_matches_shared_vector() {
        let v = vector();
        assert_eq!(v["tier_csvs"], serde_json::json!(REARM_TIER_CSVS));
        assert_eq!(v["max_rounds"].as_u64().unwrap() as usize, MAX_ROUNDS);
        let cases = v["cases"].as_array().unwrap();
        assert!(cases.len() >= 13);
        for c in cases {
            let got = judge_case(c);
            assert_eq!(got.reason(), c["reason"].as_str().unwrap(), "{}", c["name"]);
            assert_eq!(
                got == AcquireVerdict::Binds,
                c["binds"].as_bool().unwrap(),
                "{}",
                c["name"]
            );
        }
    }

    /// The exact incident: a606a4ca's acquire names 21910507, confirmed, which spent
    /// 70b0abb3's round-2 output. Confirmation alone (the old rule) bound it.
    #[test]
    fn a606a4ca_acquire_naming_21910507_does_not_bind() {
        let v = vector();
        let c = v["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"].as_str().unwrap().contains("1120-090836"))
            .unwrap();
        let claim =
            Txid::from_str("21910507ef3364bc74d898f339b19c293d49abcd478b99168c907d02de3b3711")
                .unwrap();
        assert_eq!(c["claim_txid"].as_str().unwrap(), claim.to_string());
        let txs = view(c);
        assert!(
            txs[&claim].1,
            "the claim is confirmed: the old rule bound it"
        );
        assert_eq!(
            txs[&claim].0.input[0].previous_output.to_string(),
            "46a66b127e0e3afd04f2e4399681128399caab6d6133320c7d02d3569f5c3c79:0"
        );
        assert_eq!(judge_case(c), AcquireVerdict::NotThisLottery);
    }

    use bitcoin::hashes::Hash as _;

    fn cay_vector() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../../../deposits-core/tests/vectors/claim_after_yield.json"
        ))
        .unwrap()
    }

    fn key_of(b: u8) -> bitcoin::secp256k1::PublicKey {
        use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
        PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[b; 32]).unwrap())
    }

    /// DEP-06 "A claim after the claimant's own yield" (ruled 2026-11-23, the advantage rule),
    /// against the vector shared with cl-deposits and the spec: for every acquire the fold takes,
    /// the round bound, the claim's binding judgment, whether custody moves (and `binds_on`
    /// agrees), and what the claimant's fork still holds.
    #[test]
    fn claim_after_yield_matches_the_shared_vector() {
        let v = cay_vector();
        let cases = v["cases"].as_array().unwrap();
        assert!(cases.len() >= 8);
        for c in cases {
            let name = c["name"].as_str().unwrap();
            // The fold half (taken or refused, and the custodian of record) is deposits-core's
            // `claim_after_yield_fold_vector`; a refused acquire has nothing to judge.
            if c["fold"] == "reject" {
                continue;
            }
            let claim: [u8; 32] = c["claim_txid"]
                .as_str()
                .map(|t| Txid::from_str(t).unwrap().to_byte_array())
                .unwrap_or([4; 32]);
            // The round bound from the acquirer's own ops (production reads the same off the
            // fork's history: `min_round_at`, exercised on ref7's real fork in dispute_tip).
            let ops: Vec<OwnOp> = c["ops"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|o| match o["op"].as_str().unwrap() {
                    "arm" => Some(OwnOp::Arm(1)),
                    "arm_round_2" => Some(OwnOp::Arm(2)),
                    "yield" => Some(OwnOp::Yield),
                    _ => None,
                })
                .collect();
            let a = AcquireRef {
                vault: None,
                claim,
                custodian: key_of(1),
                min_round: min_round(&ops),
            };
            assert_eq!(a.min_round as u64, c["min_round"].as_u64().unwrap(), "{name}: min_round");
            let txs = view(c);
            let vaults: Vec<OutPoint> = c["vaults"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| {
                    OutPoint::new(
                        Txid::from_str(v["txid"].as_str().unwrap()).unwrap(),
                        v["vout"].as_u64().unwrap() as u32,
                    )
                })
                .collect();
            let (verdict, round) =
                judge_acquire_round(|t| txs.get(t).cloned(), &vaults, &Txid::from_byte_array(claim));
            assert_eq!(verdict.reason(), c["binding"].as_str().unwrap(), "{name}: binding");
            assert_eq!(round as u64, c["round"].as_u64().unwrap(), "{name}: round");
            let moves = verdict == AcquireVerdict::Binds && round >= a.min_round;
            assert_eq!(
                if moves { "self" } else { "none" },
                c["custodian"].as_str().unwrap(),
                "{name}: custodian"
            );
            // The production predicate agrees, once the verdict is cached as `note_verdicts` would.
            if verdict.is_final() {
                if let Some(k) = key(&vaults, &claim) {
                    verdicts().lock().unwrap().insert(k, verdict);
                    if verdict == AcquireVerdict::Binds {
                        rounds().lock().unwrap().insert(k, round);
                    }
                }
                assert_eq!(a.binds_on(&vaults), moves, "{name}: binds_on");
            }
            // What the claimant's fork still holds: the pledge_pick fork fold.
            let events: Vec<crate::node::dispute::ForkEvent> = c["ops"]
                .as_array()
                .unwrap()
                .iter()
                .map(|o| match o["op"].as_str().unwrap() {
                    "enter" => crate::node::dispute::ForkEvent::Enter,
                    "arm" => crate::node::dispute::ForkEvent::Arm {
                        pledge: Some(OutPoint::from_str(&format!("{}:0", "d4".repeat(32))).unwrap()),
                        round: 1,
                    },
                    "arm_round_2" => crate::node::dispute::ForkEvent::Arm {
                        pledge: Some(OutPoint::from_str(&format!("{}:0", "d5".repeat(32))).unwrap()),
                        round: 2,
                    },
                    "yield" => crate::node::dispute::ForkEvent::Yield,
                    other => panic!("{other}"),
                })
                .chain(std::iter::once(crate::node::dispute::ForkEvent::Acquire {
                    claim: OutPoint::new(Txid::from_byte_array(claim), 0),
                    binds: moves,
                }))
                .collect();
            let (pledges, custody) = crate::node::dispute::fork_holds(&events, false, &[]);
            let held = &c["held"];
            assert_eq!(
                pledges.iter().map(|p| p.to_string()).collect::<Vec<_>>(),
                held["pledges"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|p| p.as_str().unwrap().to_string())
                    .collect::<Vec<_>>(),
                "{name}: held pledges"
            );
            assert_eq!(
                custody.map(|p| p.to_string()),
                held["custody"].as_str().map(str::to_string),
                "{name}: held custody"
            );
        }
    }

    fn ye_vector() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../../../deposits-core/tests/vectors/yield_evidence.json"
        ))
        .unwrap()
    }

    /// A vector `reasons` object: txids (display hex) as wire bytes, the reestablished hash as
    /// written.
    fn ye_reasons(r: &serde_json::Value) -> (Option<[u8; 32]>, Option<[u8; 32]>, Option<[u8; 32]>) {
        let txid = |k: &str| r[k].as_str().map(|t| Txid::from_str(t).unwrap().to_byte_array());
        let hash = r["reestablished"]
            .as_str()
            .map(|h| hex::decode(h).unwrap().try_into().unwrap());
        (txid("lost_to"), hash, txid("excluded_by"))
    }

    /// DEP-06 "What a yield must say" (`yield-evidence-v9`), against the vector shared with
    /// cl-deposits and the spec: the reasons on the wire, and the judge.
    #[test]
    fn yield_evidence_matches_the_shared_vector() {
        use deposits_core::messages::LedgerOperation;
        use deposits_core::{TlvDecode, TlvEncode};
        let v = ye_vector();
        for w in v["wire"].as_array().unwrap() {
            let (lost_to, reestablished, excluded_by) = ye_reasons(&w["reasons"]);
            let op = LedgerOperation::DisputeYield {
                lost_to,
                reestablished,
                excluded_by,
            };
            assert_eq!(hex::encode(op.tlv_encode()), w["hex"].as_str().unwrap(), "{}", w["name"]);
            assert_eq!(
                LedgerOperation::tlv_decode(&hex::decode(w["hex"].as_str().unwrap()).unwrap())
                    .unwrap(),
                op,
                "{}",
                w["name"]
            );
        }
        let cases = v["cases"].as_array().unwrap();
        assert!(cases.len() >= 24);
        for c in cases {
            let name = c["name"].as_str().unwrap();
            let (lost_to, reestablished, excluded_by) = ye_reasons(&c["reasons"]);
            // (The fold half is deposits-core's `yield_evidence_fold_vector`.)
            // The judge.
            let txs: HashMap<Txid, (Transaction, Option<u32>)> = c["txs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|t| {
                    let input = t["inputs"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|i| TxIn {
                            previous_output: OutPoint::new(
                                Txid::from_str(i["txid"].as_str().unwrap()).unwrap(),
                                i["vout"].as_u64().unwrap() as u32,
                            ),
                            script_sig: ScriptBuf::new(),
                            sequence: Sequence(i["sequence"].as_u64().unwrap() as u32),
                            witness: Default::default(),
                        })
                        .collect();
                    let output = t["outputs"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|o| TxOut {
                            value: Amount::from_sat(1000),
                            script_pubkey: ScriptBuf::from_hex(o.as_str().unwrap()).unwrap(),
                        })
                        .collect();
                    (
                        Txid::from_str(t["txid"].as_str().unwrap()).unwrap(),
                        (
                            Transaction {
                                version: Version::TWO,
                                lock_time: LockTime::ZERO,
                                input,
                                output,
                            },
                            t["height"].as_u64().map(|h| h as u32),
                        ),
                    )
                })
                .collect();
            let outpoints = |a: &serde_json::Value| -> Vec<OutPoint> {
                a.as_array()
                    .unwrap()
                    .iter()
                    .map(|p| {
                        OutPoint::new(
                            Txid::from_str(p["txid"].as_str().unwrap()).unwrap(),
                            p["vout"].as_u64().unwrap() as u32,
                        )
                    })
                    .collect()
            };
            let x32 = |s: &serde_json::Value| -> [u8; 32] {
                hex::decode(s.as_str().unwrap()).unwrap().try_into().unwrap()
            };
            let y = &c["yielder"];
            let targets: Vec<ScriptBuf> = y["targets"]
                .as_array()
                .unwrap()
                .iter()
                .map(|t| ScriptBuf::from_hex(t.as_str().unwrap()).unwrap())
                .collect();
            let pledges = outpoints(&y["pledges"]);
            let vaults = outpoints(&c["vaults"]);
            let qbs: Vec<([u8; 32], u64, bool)> = c["quorum_begins"]
                .as_array()
                .unwrap()
                .iter()
                .map(|q| {
                    (
                        x32(&q["hash"]),
                        q["seq"].as_u64().unwrap(),
                        q["spend_confirmed"].as_bool().unwrap(),
                    )
                })
                .collect();
            let participants: Vec<[u8; 32]> =
                c["participants"].as_array().unwrap().iter().map(x32).collect();
            let ctx = YieldContext {
                ruleset: c["ruleset"].as_str().unwrap(),
                yield_height: c["yield_height"].as_u64().unwrap() as u32,
                arm_round: c["arm_round"].as_u64().unwrap() as u32,
                yielder: x32(&y["xonly"]),
                targets: &targets,
                pledges: &pledges,
                vaults: &vaults,
                dispute_reason: c["dispute"]["reason"].as_str().unwrap(),
                last_valid_sequence: c["dispute"]["last_valid_sequence"].as_u64().unwrap(),
                quorum_begins: &qbs,
                participants: &participants,
            };
            let (verdict, why) =
                judge_yield(|t| txs.get(t).cloned(), &ctx, lost_to, reestablished, excluded_by);
            assert_eq!(verdict.name(), c["verdict"].as_str().unwrap(), "{name}: verdict");
            assert_eq!(why, c["why"].as_str().unwrap(), "{name}: why");
        }
    }
}
