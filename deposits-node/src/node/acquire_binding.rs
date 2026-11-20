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
    let Some((claim_tx, true)) = tx(claim) else {
        return AcquireVerdict::Unconfirmed;
    };
    if rearm_shaped(&claim_tx) {
        return AcquireVerdict::NotAClaim;
    }
    let Some(mut spent) = claim_tx.input.first().map(|i| i.previous_output) else {
        return AcquireVerdict::NotThisLottery;
    };
    for _ in 0..=MAX_ROUNDS {
        if spent.vout != 0 {
            return AcquireVerdict::NotThisLottery;
        }
        let Some((t, confirmed)) = tx(&spent.txid) else {
            return AcquireVerdict::Unconfirmed;
        };
        if t.input.iter().any(|i| vaults.contains(&i.previous_output)) {
            return AcquireVerdict::Binds;
        }
        if !(confirmed && rearm_shaped(&t)) {
            return AcquireVerdict::NotThisLottery;
        }
        spent = t.input[0].previous_output;
    }
    AcquireVerdict::NotThisLottery
}

/// [`judge_acquire`] against a chain backend.
pub(crate) fn judge_acquire_on(
    backend: &dyn crate::chain_backend::ChainBackend,
    vaults: &[OutPoint],
    claim: &Txid,
) -> AcquireVerdict {
    judge_acquire(
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
        let v = judge_acquire_on(backend, &vault, &Txid::from_byte_array(claim));
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
}
