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
            // DEP-06: an acquire binds iff its claim is confirmed AND spends this dispute's
            // lottery outpoint (`acquire_binding`), judged against the vault it confiscated.
            let acquires = if claims.is_empty() {
                Vec::new()
            } else {
                super::acquire_binding::acquires_in(
                    &fork.history,
                    usize::MAX,
                    super::acquire_binding::vault_at(
                        &base.history,
                        fork.state.dispute_fork_sequence,
                    ),
                )
            };
            Some(DisputeView {
                forker: hex::encode(fork.state.parent_pubkey.serialize()),
                last_valid_sequence: fork.state.dispute_fork_sequence,
                reason,
                acquired: !claims.is_empty(),
                acquire_confirmed: acquires.iter().any(|a| {
                    a.vault
                        .as_ref()
                        .is_some_and(|v| a.binds_on(v))
                }),
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

/// Every `DisputeAcquire` near the tail of a fork (or of a replica carrying the winner's
/// chain) in `ledgers` whose binding is not yet judged, with the vault it is judged against.
/// A fork whose own history holds no `QuorumBegin` before its acquire falls back to its base
/// replica's at the fork point.
pub(crate) fn pending_acquires(
    ledgers: &std::collections::HashMap<
        String,
        std::sync::Arc<std::sync::RwLock<deposits_core::Ledger>>,
    >,
) -> Vec<(super::acquire_binding::Vault, [u8; 32])> {
    let mut out = Vec::new();
    for (k, arc) in ledgers.iter() {
        let Ok(l) = arc.read() else { continue };
        let tail = l.history.len().saturating_sub(64);
        if !l.history[tail..].iter().any(|u| {
            matches!(
                <deposits_core::messages::LedgerOperation as deposits_core::TlvDecode>::tlv_decode(
                    &u.message
                ),
                Ok(deposits_core::messages::LedgerOperation::DisputeAcquire { .. })
            )
        }) {
            continue;
        }
        let base_vault = || {
            (k.len() > 64)
                .then(|| ledgers.get(&k[..64]))
                .flatten()
                .and_then(|b| {
                    b.read().ok().and_then(|b| {
                        super::acquire_binding::vault_at(&b.history, l.state.dispute_fork_sequence)
                    })
                })
        };
        for a in super::acquire_binding::acquires_in(&l.history, 64, None) {
            if let Some(v) = a.vault.or_else(base_vault) {
                let v: super::acquire_binding::Vault = v;
                if super::acquire_binding::pending(&v, &a.claim) {
                    out.push((v, a.claim));
                }
            }
        }
    }
    out.sort_unstable_by_key(|(v, c)| (format!("{v:?}"), *c));
    out.dedup();
    out
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
