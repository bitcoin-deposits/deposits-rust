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
    /// The fork carries a `DisputeAcquire`: custody moved.
    pub acquired: bool,
}

/// `Some(reason)` when a member `own` (hex) of `members` must refuse: custody moved, or
/// a non-expiry dispute at or after the latest `QuorumBegin` by `own` or by a majority.
pub(crate) fn cosign_refusal(
    own: &str,
    members: &[String],
    latest_quorum_begin_seq: u64,
    disputes: &[DisputeView],
) -> Option<String> {
    if disputes.iter().any(|d| d.acquired) {
        return Some("custody moved by DisputeAcquire".to_string());
    }
    let mut freezing: Vec<&str> = disputes
        .iter()
        .filter(|d| {
            d.last_valid_sequence >= latest_quorum_begin_seq
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
            let reason = super::expiry_watch::dispute_enter_reason(&fork.history)?;
            let acquired = fork.history.iter().any(|u| {
                matches!(
                    LedgerOperation::tlv_decode(&u.message),
                    Ok(LedgerOperation::DisputeAcquire { .. })
                )
            });
            Some(DisputeView {
                forker: hex::encode(fork.state.parent_pubkey.serialize()),
                last_valid_sequence: fork.state.dispute_fork_sequence,
                reason,
                acquired,
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
    )
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
                })
                .collect();
            let got = cosign_refusal(
                "m0",
                &members,
                c["latest_quorum_begin_seq"].as_u64().unwrap(),
                &disputes,
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
