//! DEP-05 §"Deposed operator": when a member refuses to co-sign the operator's chain.
//! Pinned by `tests/vectors/cosign_refusal.json`, shared with cl-deposits.

use super::expiry_watch::is_expiry_reason;

/// One dispute fork of the ledger, as a member sees it.
#[derive(Clone, Debug)]
pub(crate) struct DisputeView {
    /// The forking member's key (hex).
    pub forker: String,
    pub last_valid_sequence: u64,
    pub reason: String,
    /// The fork carries a `DisputeAcquire`: custody moved (under `strict-lottery-v8`, only
    /// with `acquire_confirmed`).
    pub acquired: bool,
    /// The acquire's `claim_txid` is confirmed on chain (DEP-06 §Phase 4, strict-lottery-v8).
    pub acquire_confirmed: bool,
}

/// `Some(reason)` when a member `own` (hex) of `members` must refuse: custody moved, or
/// a non-expiry dispute at or after the latest `QuorumBegin` by `own` or by a majority.
/// Under `ruleset` `strict-lottery-v8` (the ledger's latest `QuorumBegin`'s; ruled 2026-11-10) a
/// rotation does not end a fraud dispute (a non-expiry dispute counts whatever its
/// `last_valid_sequence`), and an acquire moves custody only once its claim is confirmed.
pub(crate) fn cosign_refusal(
    own: &str,
    members: &[String],
    latest_quorum_begin_seq: u64,
    disputes: &[DisputeView],
    ruleset: &str,
) -> Option<String> {
    let fraud_survives = deposits_core::types::ruleset_fraud_survives_rotation(ruleset);
    let on_confirm = deposits_core::types::ruleset_acquire_on_confirm(ruleset);
    if disputes
        .iter()
        .any(|d| d.acquired && (!on_confirm || d.acquire_confirmed))
    {
        return Some("custody moved by DisputeAcquire".to_string());
    }
    let mut freezing: Vec<&str> = disputes
        .iter()
        .filter(|d| {
            (fraud_survives || d.last_valid_sequence >= latest_quorum_begin_seq)
                && !is_expiry_reason(&d.reason)
                && members.iter().any(|m| m == &d.forker)
        })
        .map(|d| d.forker.as_str())
        .collect();
    freezing.sort_unstable();
    freezing.dedup();
    if freezing.contains(&own) {
        return Some("we disputed this ledger; not extending the operator's chain".to_string());
    }
    if freezing.len() > members.len() / 2 {
        return Some(format!(
            "{} of {} quorum members disputed this ledger",
            freezing.len(),
            members.len()
        ));
    }
    None
}

/// The refusal for the base ledger `ledger_id` given every fork of it in `ledgers`
/// (keys `<ledger_id>_<seq>_<pk16>`), as member `own_hex`.
pub(crate) fn refusal_for(
    ledgers: &std::collections::HashMap<
        String,
        std::sync::Arc<std::sync::RwLock<deposits_core::Ledger>>,
    >,
    ledger_id: &str,
    base: &deposits_core::Ledger,
    own_hex: &str,
) -> Option<String> {
    use deposits_core::messages::LedgerOperation;
    use deposits_core::TlvDecode;
    let prefix = format!("{ledger_id}_");
    let disputes: Vec<DisputeView> = ledgers
        .iter()
        .filter(|(k, _)| k.starts_with(&prefix))
        .filter_map(|(_, arc)| {
            let fork = arc.read().ok()?;
            // DEP-05 §"The ground of a dispute": read from the record, not only its label, so
            // a legacy generic reason on an expiry dispute stops freezing co-signing.
            let label = super::expiry_watch::dispute_enter_reason(&fork.history)?;
            let reason = if super::expiry_watch::dispute_enter_is_expiry(
                &fork.history,
                base.state.quorum_expiry,
            )? {
                "quorum_expired".to_string()
            } else {
                label
            };
            let claims: Vec<[u8; 32]> = fork
                .history
                .iter()
                .filter_map(|u| match LedgerOperation::tlv_decode(&u.message) {
                    Ok(LedgerOperation::DisputeAcquire { claim_txid, .. }) => Some(claim_txid),
                    _ => None,
                })
                .collect();
            Some(DisputeView {
                forker: hex::encode(fork.state.parent_pubkey.serialize()),
                last_valid_sequence: fork.state.dispute_fork_sequence,
                reason,
                acquired: !claims.is_empty(),
                acquire_confirmed: claims.iter().any(claim_confirmed),
            })
        })
        .collect();
    let members: Vec<String> = base
        .state
        .quorum_members
        .iter()
        .map(|m| hex::encode(m.pubkey.serialize()))
        .collect();
    cosign_refusal(
        own_hex,
        &members,
        base.state.quorum_begin_sequence.unwrap_or(0),
        &disputes,
        &base.state.active_ruleset_name,
    )
}

/// Claim txids (internal byte order) seen confirmed. Filled off the co-sign path by
/// [`note_confirmed_claims`], so a co-sign decision never waits on the chain backend; a
/// confirmation is never re-read.
fn confirmed_claims() -> &'static std::sync::Mutex<std::collections::HashSet<[u8; 32]>> {
    static SET: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<[u8; 32]>>> =
        std::sync::OnceLock::new();
    SET.get_or_init(Default::default)
}

/// Whether the claim `txid` of a `DisputeAcquire` is known confirmed.
pub(crate) fn claim_confirmed(txid: &[u8; 32]) -> bool {
    confirmed_claims().lock().map(|s| s.contains(txid)).unwrap_or(false)
}

/// The `claim_txid` of every `DisputeAcquire` on any fork in `ledgers` not yet known confirmed.
pub(crate) fn unconfirmed_claims(
    ledgers: &std::collections::HashMap<
        String,
        std::sync::Arc<std::sync::RwLock<deposits_core::Ledger>>,
    >,
) -> Vec<[u8; 32]> {
    use deposits_core::messages::LedgerOperation;
    use deposits_core::TlvDecode;
    let mut out = Vec::new();
    for arc in ledgers.values() {
        let Ok(l) = arc.read() else { continue };
        // An acquire sits near the tail of the winner's fork (or of a replica carrying its chain).
        for u in l.history.iter().rev().take(64) {
            if let Ok(LedgerOperation::DisputeAcquire { claim_txid, .. }) =
                LedgerOperation::tlv_decode(&u.message)
            {
                if !claim_confirmed(&claim_txid) {
                    out.push(claim_txid);
                }
            }
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// Ask the chain about `claims` (from [`unconfirmed_claims`]) and remember the confirmed ones.
pub(crate) fn note_confirmed_claims(
    backend: &dyn crate::chain_backend::ChainBackend,
    claims: &[[u8; 32]],
) {
    use bitcoin::hashes::Hash;
    for c in claims {
        let txid = bitcoin::Txid::from_byte_array(*c);
        if let Ok(Some(_height)) = backend.get_tx_block_height(&txid) {
            if let Ok(mut s) = confirmed_claims().lock() {
                s.insert(*c);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cosign_refusal_matches_shared_vector() {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/vectors/cosign_refusal.json")).unwrap();
        let cases = v["cases"].as_array().unwrap();
        assert!(cases.len() >= 10);
        for c in cases {
            let n = c["members"].as_u64().unwrap() as usize;
            let members: Vec<String> = (0..n).map(|i| format!("m{i}")).collect();
            let disputes: Vec<DisputeView> = c["disputes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|d| DisputeView {
                    forker: d["by"].as_str().unwrap().to_string(),
                    last_valid_sequence: d["last_valid_sequence"].as_u64().unwrap(),
                    reason: d["reason"].as_str().unwrap().to_string(),
                    acquired: d["acquired"].as_bool().unwrap(),
                    acquire_confirmed: d["acquire_confirmed"].as_bool().unwrap_or(false),
                })
                .collect();
            let got = cosign_refusal(
                "m0",
                &members,
                c["latest_quorum_begin_seq"].as_u64().unwrap(),
                &disputes,
                c["ruleset"].as_str().unwrap_or(""),
            );
            assert_eq!(
                got.is_some(),
                c["refuse"].as_bool().unwrap(),
                "{}",
                c["name"]
            );
        }
    }
}
