//! The quorum-expiry watch judges only a current replica, and a member stands
//! down from an expiry dispute once the operator re-establishes the quorum.
//!
//! On the signet devnet ref3 held its replica of ledger C at seq 67859 while
//! C ran on past 101k: every minute `auto_dispute_expired_quorums` read the
//! replica's stale `quorum_expiry` (7191, from a QuorumBegin two rotations
//! old) and fired at an operator whose quorum ran to 8888. The same port as
//! cl-deposits 7913002:
//!
//! - the watch compares each candidate replica with the newest updates the
//!   relay holds from the ledger's operator and does not judge one that is
//!   behind; it queues it for gap-fill instead (the replica lane catches it
//!   up);
//! - a `quorum_expired` dispute whose base replica now shows a quorum that
//!   has not expired, with nothing confiscated, is withdrawn: `DisputeYield`
//!   on our armed fork (DEP-06 §Race: the re-establishment prevailed).

use super::*;

use deposits_core::types::DisputeState;
use deposits_core::SignedLedgerUpdate;

/// Blocks past `quorum_expiry` before a member auto-disputes: the Tier-1
/// boundary (DEP-05 §Lifecycle), giving the operator the window to
/// re-establish before cosigners race to confiscate. Override via
/// `DEPOSITS_AUTO_DISPUTE_GRACE_BLOCKS` for test/dev.
pub(crate) fn auto_dispute_grace_blocks() -> u32 {
    const DEFAULT_GRACE_BLOCKS: u32 = 720;
    std::env::var("DEPOSITS_AUTO_DISPUTE_GRACE_BLOCKS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_GRACE_BLOCKS)
}

/// Updates the watch fetches from the relay to find the operator's tip. The
/// newest by `created_at`; a heal pass republishes old updates with fresh
/// timestamps, so ask for more than a handful.
const RELAY_TIP_FETCH_LIMIT: usize = 50;

/// The highest sequence among `updates` that belong to `ledger_id` and were
/// signed by its `operator` (members' fork branches share the ledger's tag).
pub(crate) fn operator_tip_seq(
    updates: &[SignedLedgerUpdate],
    ledger_id: &[u8; 32],
    operator: &bitcoin::secp256k1::PublicKey,
) -> Option<u64> {
    updates
        .iter()
        .filter(|u| u.ledger_id == *ledger_id && u.operator_id == *operator)
        .map(|u| u.sequence_number)
        .max()
}

/// A replica whose tip is below the operator's newest update on the relay has
/// not seen everything the operator committed (a rotation among it), so its
/// `quorum_expiry` is no ground for a dispute. No relay tip (relay down or
/// empty) proves nothing either way.
pub(crate) fn replica_behind_relay(local_seq: u64, relay_tip: Option<u64>) -> bool {
    relay_tip.is_some_and(|tip| tip > local_seq)
}

/// A `DisputeEnter` reason for a lapsed quorum, in either spelling written:
/// the reference's `quorum_expired`, and cl-deposits' older `quorum-expired`.
pub(crate) fn is_expiry_reason(reason: &str) -> bool {
    reason.replace('-', "_") == "quorum_expired"
}

/// Whether a dispute we opened should be withdrawn: it was opened because the
/// quorum expired, and the base replica now shows a quorum that has not (a
/// `QuorumBegin` the operator committed since, whose expiry is not behind the
/// chain tip). Confiscation is checked separately: once one is under way the
/// race is decided on chain, not here.
pub(crate) fn expiry_dispute_stands_down(
    reason: &str,
    base_quorum_expiry: Option<u32>,
    height: u32,
) -> bool {
    is_expiry_reason(reason) && base_quorum_expiry.is_some_and(|expiry| height <= expiry)
}

/// The `last_valid_sequence` of the `DisputeEnter` on a fork branch, if it holds one.
pub(crate) fn dispute_enter_last_valid(history: &[SignedLedgerUpdate]) -> Option<u64> {
    use deposits_core::messages::LedgerOperation;
    use deposits_core::TlvDecode;
    history
        .iter()
        .rev()
        .find_map(|u| match LedgerOperation::tlv_decode(&u.message) {
            Ok(LedgerOperation::DisputeEnter {
                last_valid_sequence,
                ..
            }) => Some(last_valid_sequence),
            _ => None,
        })
}

/// The sequence of the latest `QuorumBegin` in a ledger's history.
pub(crate) fn latest_quorum_begin_seq(history: &[SignedLedgerUpdate]) -> Option<u64> {
    use deposits_core::messages::LedgerOperation;
    use deposits_core::TlvDecode;
    history.iter().rev().find_map(|u| {
        matches!(
            LedgerOperation::tlv_decode(&u.message),
            Ok(LedgerOperation::QuorumBegin { .. })
        )
        .then_some(u.sequence_number)
    })
}

/// The sequence of a base ledger's latest `QuorumBegin`, judged from the LEDGER: its state's
/// record of it (`LedgerState::quorum_begin_sequence`, kept across the RAM cap and a restart),
/// or the newest one its in-memory history holds, whichever is later.
///
/// The in-memory history is a window (`DepositsHandler::HISTORY_RETAIN`, 50 000 updates), so on a
/// busy ledger a rotation scrolls out of it in hours. Read from the window alone, a
/// re-established quorum is forgotten and our expiry dispute stands for good, which DEP-05
/// §"When a quorum_expired dispute ends" forbids (signet soak, 2026-11-22: ref4's un-armed fork of
/// 0aeebcc5 at 359090; the base re-established at 359228..436154, tip 492248, window from 442249).
pub(crate) fn base_latest_quorum_begin_seq(
    state_quorum_begin_seq: Option<u64>,
    history: &[SignedLedgerUpdate],
) -> Option<u64> {
    state_quorum_begin_seq.max(latest_quorum_begin_seq(history))
}

/// Whether `history` holds every update after `last_valid_sequence` the ledger has (its window
/// starts at or before the update after the fork point). When it does not, a `QuorumBegin` after
/// the fork point may lie below the window, on disk only.
pub(crate) fn history_covers_after(history: &[SignedLedgerUpdate], last_valid_sequence: u64) -> bool {
    history
        .first()
        .is_none_or(|u| u.sequence_number <= last_valid_sequence.saturating_add(1))
}

/// The rung txids of each `QuorumBegin` among `updates` whose sequence is after
/// `last_valid_sequence` (strict-lottery-v8: a re-establishment ends an expiry dispute only once
/// some rung of some such `QuorumBegin` confirmed).
pub(crate) fn quorum_begin_rungs_after(
    updates: &[SignedLedgerUpdate],
    last_valid_sequence: u64,
) -> Vec<Vec<[u8; 32]>> {
    use deposits_core::messages::LedgerOperation;
    use deposits_core::TlvDecode;
    updates
        .iter()
        .filter(|u| u.sequence_number > last_valid_sequence)
        .filter_map(|u| match LedgerOperation::tlv_decode(&u.message) {
            Ok(op @ LedgerOperation::QuorumBegin { .. }) => {
                Some(deposits_core::vault_spend::quorum_begin_rungs(&op))
            }
            _ => None,
        })
        .collect()
}

/// For our expiry fork with `fork_history`, against its base (`base_quorum_begin_seq` from the
/// base's state, `base_history` its in-memory window): (re-established since the fork point;
/// under `on_spend`, the rungs of each QuorumBegin after the fork point the window holds; and,
/// when the window starts after the fork point, (fork point, the window's first and last
/// sequences): below the first, the QuorumBegins are on disk only). Judged from the ledger, never the window
/// alone (see [`base_latest_quorum_begin_seq`]).
pub(crate) fn judge_reestablishment(
    fork_history: &[SignedLedgerUpdate],
    on_spend: bool,
    base_quorum_begin_seq: Option<u64>,
    base_history: &[SignedLedgerUpdate],
) -> (bool, Vec<Vec<[u8; 32]>>, Option<(u64, u64, u64)>) {
    let Some(lvs) = dispute_enter_last_valid(fork_history) else {
        return (false, Vec::new(), None);
    };
    let reestablished = base_latest_quorum_begin_seq(base_quorum_begin_seq, base_history)
        .is_some_and(|qb| deposits_core::types::expiry_dispute_ended(lvs, qb, false));
    if !on_spend {
        return (reestablished, Vec::new(), None);
    }
    let below = (!history_covers_after(base_history, lvs)).then(|| {
        (
            lvs,
            base_history.first().map_or(0, |u| u.sequence_number),
            base_history.last().map_or(0, |u| u.sequence_number),
        )
    });
    (reestablished, quorum_begin_rungs_after(base_history, lvs), below)
}

/// One stand-down pass's rungs of the QuorumBegins after fork point `lvs`, for a base whose
/// in-memory window spans `window_start..=window_end` and holds `in_window` (their rungs), given
/// what earlier passes saw (`entry`, see [`PERSISTED_RUNGS`]). `read(after, below)` reads the
/// persisted log's QuorumBegins in `(after, below)`; it is called only for a stretch never seen,
/// and `None` from it (unread) leaves the entry as it was. Returns (the new entry, if any; every
/// rung known after the fork point).
pub(crate) fn rungs_seen(
    entry: Option<(u64, Vec<Vec<[u8; 32]>>)>,
    lvs: u64,
    window_start: u64,
    window_end: u64,
    in_window: Vec<Vec<[u8; 32]>>,
    read: impl FnOnce(u64, u64) -> Option<Vec<SignedLedgerUpdate>>,
) -> (Option<(u64, Vec<Vec<[u8; 32]>>)>, Vec<Vec<[u8; 32]>>) {
    let (mut seen_below, mut seen) = entry.unwrap_or((lvs.saturating_add(1), Vec::new()));
    if window_start > seen_below {
        match read(seen_below - 1, window_start) {
            Some(updates) => {
                seen.extend(quorum_begin_rungs_after(&updates, lvs));
                seen_below = window_start;
            }
            None => {
                let mut all = seen;
                all.extend(in_window);
                return (None, all);
            }
        }
    }
    for r in in_window {
        if !seen.contains(&r) {
            seen.push(r);
        }
    }
    seen_below = seen_below.max(window_end.saturating_add(1));
    (Some((seen_below, seen.clone())), seen)
}

/// `QuorumBegin` rungs after a fork point, per (base ledger id, fork point): (every update after the
/// fork point and below this sequence has been seen, in memory or read from the persisted log;
/// the rungs of the QuorumBegins among them). What scrolls out of the in-memory window was seen
/// in it, so the log is read only for a stretch never seen, normally once per process.
type PersistedRungs = HashMap<(String, u64), (u64, Vec<Vec<[u8; 32]>>)>;
static PERSISTED_RUNGS: std::sync::OnceLock<std::sync::Mutex<PersistedRungs>> =
    std::sync::OnceLock::new();

/// The `reason` of the `DisputeEnter` on a fork branch, if it holds one.
/// The newest `DisputeEnter` of a fork's history judged by its ground (DEP-05 §"The ground of a
/// dispute"): `Some(true)` for a `quorum_expired` dispute, whatever label a legacy record carries.
/// `governing_quorum_expiry` is the base ledger's: only disputes at or after its latest
/// `QuorumBegin` count, and that is the one governing them.
pub(crate) fn dispute_enter_is_expiry(
    history: &[SignedLedgerUpdate],
    governing_quorum_expiry: Option<u32>,
) -> Option<bool> {
    use deposits_core::messages::LedgerOperation;
    use deposits_core::TlvDecode;
    history
        .iter()
        .rev()
        .find_map(|u| match LedgerOperation::tlv_decode(&u.message) {
            Ok(LedgerOperation::DisputeEnter {
                reason,
                anchor_block_height,
                fraud_proof_hash,
                ..
            }) => Some(deposits_core::types::dispute_is_expiry(
                &reason,
                anchor_block_height.is_some(),
                fraud_proof_hash.is_some(),
                u.block_height,
                governing_quorum_expiry,
            )),
            _ => None,
        })
}

pub(crate) fn dispute_enter_reason(history: &[SignedLedgerUpdate]) -> Option<String> {
    use deposits_core::messages::LedgerOperation;
    use deposits_core::TlvDecode;
    history
        .iter()
        .rev()
        .find_map(|u| match LedgerOperation::tlv_decode(&u.message) {
            Ok(LedgerOperation::DisputeEnter { reason, .. }) => Some(reason),
            _ => None,
        })
}

impl Node {
    /// The operator's newest sequence for `ledger_id` among the newest
    /// updates the relay holds, or `None` if the relay gave nothing.
    pub(crate) async fn relay_tip_seq(
        &self,
        ledger_id: &str,
        operator: &bitcoin::secp256k1::PublicKey,
    ) -> Option<u64> {
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
        use deposits_core::TlvDecode;
        use nostr_sdk::{Filter, Kind};

        let ledger_id_bytes: [u8; 32] = hex::decode(ledger_id).ok()?.try_into().ok()?;
        let filter = Filter::new()
            .kind(Kind::Custom(crate::nostr::KIND_LEDGER_UPDATE))
            .custom_tag(
                crate::nostr::TAG_LEDGER_ID,
                [crate::nostr::ledger_tag(ledger_id)],
            )
            .limit(RELAY_TIP_FETCH_LIMIT);
        let events = self
            .nostr
            .fetch_client()
            .fetch_events(vec![filter], Some(std::time::Duration::from_secs(5)))
            .await
            .ok()?;
        let updates: Vec<SignedLedgerUpdate> = events
            .iter()
            .filter_map(|e| BASE64.decode(&e.content).ok())
            .filter_map(|tlv| SignedLedgerUpdate::tlv_decode(&tlv).ok())
            .collect();
        operator_tip_seq(&updates, &ledger_id_bytes, operator)
    }

    /// Periodic: withdraw each `quorum_expired` dispute we opened whose
    /// operator has since re-established the quorum, unless a confiscation is
    /// already under way: a `DisputeYield` on our fork, armed or not (DEP-05
    /// §"When a quorum_expired dispute ends", DEP-06 §"Where a yield is valid"),
    /// which Tombstones it, so the confiscation and lottery tasks pass it by.
    /// "Re-established" is judged from the ledger (its state's latest
    /// QuorumBegin, and under v8 the rotations' rungs from disk when the
    /// in-memory window no longer reaches the fork point), never from the
    /// window alone, and never from the chain tip.
    pub(crate) async fn stand_down_reestablished_expiry_disputes(&self) {
        // (fork key, base id, reason, base expiry, fork state, re-established since the fork
        // point) for every fork of ours still live that was opened for a lapsed quorum.
        // (fork key, ledger id, reason, base expiry, state, re-established, on_spend, the rung
        // txids of each QuorumBegin after the fork point, and, when some of those lie below the
        // base's in-memory window, (fork point, first and last sequence in the window)).
        type Live = (
            String,
            String,
            String,
            Option<u32>,
            DisputeState,
            bool,
            bool,
            Vec<Vec<[u8; 32]>>,
            Option<(u64, u64, u64)>,
        );
        let live: Vec<Live> = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            ledgers
                .iter()
                .filter(|(key, _)| key.len() > 64)
                .filter_map(|(key, arc)| {
                    let fork = arc.read().unwrap();
                    if fork.state.parent_pubkey != self.node_id
                        || !matches!(
                            fork.state.dispute_state,
                            DisputeState::Disputed | DisputeState::Armed
                        )
                    {
                        return None;
                    }
                    let base_id = key[..64].to_string();
                    let base = ledgers.get(&base_id);
                    // A fork of a ledger we operate is void (DEP-06 §Enter), never
                    // yielded: its DisputeYield would be another update under our
                    // key past the fork point, conflicting with our own chain.
                    if base.is_some_and(|b| {
                        !Arc::ptr_eq(b, arc) && b.read().unwrap().state.parent_pubkey == self.node_id
                    }) {
                        return None;
                    }
                    let base_expiry = base.and_then(|b| b.read().unwrap().state.quorum_expiry);
                    if !dispute_enter_is_expiry(&fork.history, base_expiry)? {
                        return None;
                    }
                    // Stood down as the expiry dispute it is, whatever label it was written with.
                    let reason = "quorum_expired".to_string();
                    // DEP-05 §"When a quorum_expired dispute ends": a QuorumBegin after the
                    // fork point answers the dispute's ground, whatever the tip says now.
                    // strict-lottery-v8, judged at the fork point (never by the QuorumBegin under
                    // judgement): only a re-establishment whose spend of the vault confirmed
                    // ends it. Collected here, asked of the chain below, outside the lock.
                    let on_spend = deposits_core::types::ruleset_expiry_ends_on_spend(
                        &fork.state.active_ruleset_name,
                    );
                    let (reestablished, rungs_after, below_window) = match base {
                        Some(b) => {
                            let b = b.read().unwrap();
                            judge_reestablishment(
                                &fork.history,
                                on_spend,
                                b.state.quorum_begin_sequence,
                                &b.history,
                            )
                        }
                        None => (false, Vec::new(), None),
                    };
                    Some((
                        key.clone(),
                        base_id,
                        reason,
                        base_expiry,
                        fork.state.dispute_state,
                        reestablished,
                        on_spend,
                        rungs_after,
                        below_window,
                    ))
                })
                .collect()
        };
        if live.is_empty() {
            return;
        }

        // QuorumBegins after a fork point that the base's in-memory window no longer holds, from
        // its persisted log: read once per base and fork point, then kept current from the
        // window itself (see PERSISTED_RUNGS), so the log is not re-read as the window scrolls.
        let mut live = live;
        for (_, base_id, _, _, _, _, _, rungs_after, below_window) in live.iter_mut() {
            let Some((lvs, window_start, window_end)) = *below_window else {
                continue;
            };
            let cache = PERSISTED_RUNGS.get_or_init(Default::default);
            let key = (base_id.clone(), lvs);
            let entry = cache.lock().unwrap().get(&key).cloned();
            let dir = self.handler.data_dir.clone();
            let id = base_id.clone();
            let in_window = std::mem::take(rungs_after);
            // Off the async runtime: a stretch never seen is a sequential read of the log.
            let judged = tokio::task::spawn_blocking(move || {
                let (entry, rungs) =
                    rungs_seen(entry, lvs, window_start, window_end, in_window, |after, below| {
                        crate::handler::DepositsHandler::read_persisted_quorum_begins_at(
                            &dir, &id, after, below,
                        )
                    });
                (entry, rungs)
            })
            .await;
            let Ok((entry, rungs)) = judged else {
                continue;
            };
            if let Some(entry) = entry {
                cache.lock().unwrap().insert(key, entry);
            }
            *rungs_after = rungs;
        }

        // Live chain tip, as the watch that opened them reads it.
        let height = match self.wallet.fetch_block_info() {
            Ok((h, _)) => h,
            Err(_) => return,
        };
        // Under v8 a stand-down also needs the re-establishment's spend confirmed: some rung of
        // some QuorumBegin after the fork point in a block (regtest, 2026-11-15: we yielded our
        // armed stake while our own confiscation sat in the mempool, and it then confirmed).
        use bitcoin::hashes::Hash as _;
        let rotation_spend_confirmed = |rungs_after: &Vec<Vec<[u8; 32]>>| {
            rungs_after.iter().any(|rungs| {
                rungs.iter().any(|t| {
                    matches!(
                        self.wallet
                            .tx_block_height(bitcoin::Txid::from_byte_array(*t)),
                        Ok(Some(_))
                    )
                })
            })
        };
        let candidates: Vec<Live> = live
            .into_iter()
            .filter(|(_, _, reason, expiry, _, reestablished, on_spend, rungs_after, _)| {
                (*reestablished || expiry_dispute_stands_down(reason, *expiry, height))
                    && (!*on_spend || rotation_spend_confirmed(rungs_after))
            })
            .collect();

        for (fork_key, ledger_id, _, expiry, state, _, _, _, _) in candidates {
            let prefix = &ledger_id[..16];

            // DEP-06 §Race (ruled 2026-11-14): a re-establishment ends our expiry
            // dispute whether or not we armed it, so an un-armed disputant yields
            // too. It used to leave its DisputeEnter standing for good (signet
            // soak, 2026-11-14: ref2, ref3 and ref7 on ledger J after its
            // post-expiry rotation). Nothing confiscated: no confiscation of ours
            // in flight, no lottery reveal (which follows a confirmed
            // confiscation), and no lottery output on chain for this dispute.
            let armed = state == DisputeState::Armed;
            let ours_pending = self
                .pending_confiscations
                .lock()
                .unwrap()
                .contains_key(prefix);
            let confiscated = ours_pending
                || self.have_revealed_lottery(&ledger_id).await
                || matches!(
                    self.check_confiscation_confirmed(&ledger_id, 0).await,
                    Ok(true)
                );
            let (stand_down, _release_pledge) =
                deposits_core::types::expiry_dispute_outcome(armed, true, confiscated);
            if !stand_down {
                tracing::info!(
                    "Expiry dispute on {}: quorum re-established (expiry {:?}) but a \
                     confiscation is under way; not standing down",
                    prefix,
                    expiry
                );
                continue;
            }

            if let Err(e) = self.withdraw_dispute(&fork_key, height).await {
                tracing::warn!("Expiry dispute on {}: DisputeYield: {}", prefix, e);
                continue;
            }
            tracing::warn!(
                "Expiry dispute on {}: quorum re-established (expiry {:?}, height {}); \
                 published DisputeYield, standing down",
                prefix,
                expiry,
                height
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
    use deposits_core::messages::LedgerOperation;
    use deposits_core::TlvEncode;

    fn pk(seed: u8) -> PublicKey {
        PublicKey::from_secret_key(
            &Secp256k1::new(),
            &SecretKey::from_slice(&[seed; 32]).unwrap(),
        )
    }

    fn update(ledger: [u8; 32], seq: u64, operator_id: PublicKey) -> SignedLedgerUpdate {
        SignedLedgerUpdate {
            message: LedgerOperation::DisputeYield.tlv_encode(),
            message_type: 0x8001,
            operator_id,
            ledger_id: ledger,
            sequence_number: seq,
            previous_hash: [0u8; 32],
            content_hash: [seq as u8; 32],
            block_height: 0,
            block_hash: [0u8; 32],
            operator_signature: [0u8; 64],
            cosignatures: Vec::new(),
        }
    }

    /// ref3 on ledger C: the replica held 67859 and the relay carried the
    /// operator's 101369. Not current, so not judged.
    #[test]
    fn a_replica_behind_the_relay_is_not_current() {
        assert!(replica_behind_relay(67_859, Some(101_369)));
        assert!(!replica_behind_relay(101_369, Some(101_369)));
        // A replica ahead of the relay (its newest events not yet stored) is current.
        assert!(!replica_behind_relay(101_370, Some(101_369)));
        // Nothing on the relay proves nothing.
        assert!(!replica_behind_relay(67_859, None));
    }

    /// Only the operator's updates for this ledger count toward its tip: a
    /// member's fork branch carries the same tag, and another ledger can share
    /// the 16-hex tag prefix.
    #[test]
    fn relay_tip_counts_only_the_operators_updates_for_this_ledger() {
        let (c, other) = ([0xc0; 32], [0xc1; 32]);
        let (operator, member) = (pk(1), pk(2));
        let updates = vec![
            update(c, 101_369, operator),
            update(c, 101_368, operator),
            update(c, 200_000, member),
            update(other, 300_000, operator),
            // a heal pass republishing an old update with a fresh created_at
            update(c, 17_862, operator),
        ];
        assert_eq!(operator_tip_seq(&updates, &c, &operator), Some(101_369));
        assert_eq!(operator_tip_seq(&updates, &c, &pk(3)), None);
        assert_eq!(operator_tip_seq(&[], &c, &operator), None);
    }

    #[test]
    fn expiry_reason_in_either_spelling() {
        assert!(is_expiry_reason("quorum_expired"));
        assert!(is_expiry_reason("quorum-expired"));
        assert!(!is_expiry_reason("auto_dispute"));
        assert!(!is_expiry_reason("equivocation"));
        assert!(!is_expiry_reason(""));
    }

    /// C's quorum now runs to 8888; at height 8160 an expiry dispute stands down.
    #[test]
    fn stands_down_once_the_quorum_is_reestablished() {
        assert!(expiry_dispute_stands_down(
            "quorum_expired",
            Some(8888),
            8160
        ));
        // Still valid at the expiry block itself (expired means past it).
        assert!(expiry_dispute_stands_down(
            "quorum_expired",
            Some(8160),
            8160
        ));
    }

    /// The replica still shows the lapsed quorum (7191 at 8160): keep going.
    #[test]
    fn keeps_a_dispute_whose_quorum_is_still_expired() {
        assert!(!expiry_dispute_stands_down(
            "quorum_expired",
            Some(7191),
            8160
        ));
        // Expired but inside the auto-dispute hold-off: another member may
        // have opened it (the peer path arms without the hold-off); the
        // quorum has not come back, so neither do we stand down.
        assert!(!expiry_dispute_stands_down(
            "quorum_expired",
            Some(8000),
            8160
        ));
        assert!(!expiry_dispute_stands_down("quorum_expired", None, 8160));
    }

    /// Only expiry disputes: a fraud dispute is not answered by a rotation.
    #[test]
    fn other_disputes_do_not_stand_down() {
        assert!(!expiry_dispute_stands_down(
            "auto_dispute",
            Some(8888),
            8160
        ));
        assert!(!expiry_dispute_stands_down(
            "non_conforming_update",
            Some(8888),
            8160
        ));
    }

    #[test]
    fn reads_the_reason_from_the_forks_dispute_enter() {
        let mut enter = update([0; 32], 67_860, pk(2));
        enter.message = LedgerOperation::DisputeEnter {
            last_valid_sequence: 67_859,
            reason: "quorum_expired".to_string(),
            anchor_block_hash: Some([7; 32]),
            anchor_block_height: Some(8160),
            fraud_proof_hash: None,
            fraud_proof: None,
        }
        .tlv_encode();
        let history = vec![
            update([0; 32], 67_859, pk(1)),
            enter,
            update([0; 32], 67_861, pk(2)),
        ];
        assert_eq!(
            dispute_enter_reason(&history).as_deref(),
            Some("quorum_expired")
        );
        assert_eq!(dispute_enter_reason(&history[..1]), None);
    }

    /// A persisted `Update` row of the soak, as `SignedLedgerUpdate`.
    fn soak_row(line: &str) -> SignedLedgerUpdate {
        let mut v: serde_json::Value = serde_json::from_str(line).unwrap();
        v.as_object_mut().unwrap().remove("type");
        serde_json::from_value(v).unwrap()
    }

    /// Signet soak, ref4, ledger 0aeebcc5 (2026-11-22). Our un-armed `quorum_expired` fork at
    /// 359090 (DisputeEnter 359091, the real row). The operator re-established at 359228 and
    /// rotated three more times, to 436154 (real rows; each has a rung confirmed on signet:
    /// 64fa8935… at 8212, 099729ed… at 9650, 8e3bce16… at 10529, 5cced468… at 11236). That quorum
    /// expired again at 12209. The base's tip was 492248, so its 50 000-update in-memory window
    /// began at 442249 and held no QuorumBegin at all. Judged from the window, the
    /// re-establishment was forgotten: ref4 yielded only while `height <= quorum_expiry` (the
    /// last refusal 04:47:33Z, block 12210 at 04:48:41Z) and never again, so the DisputeEnter
    /// stood for good. The window here is the base's last three real rows.
    #[test]
    fn a_reestablishment_below_the_history_window_still_ends_the_dispute() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/signet-0aeebcc5");
        let base_id = "0aeebcc51f7dc6142f8e7a804e96fbe441ddb852401ad3f55837f7d13155669b";
        let enter = soak_row(
            std::fs::read_to_string(dir.join("fork-dispute-enter.json"))
                .unwrap()
                .trim(),
        );
        let lvs = dispute_enter_last_valid(std::slice::from_ref(&enter)).unwrap();
        assert_eq!(lvs, 359_090);

        let log = std::fs::read_to_string(dir.join("ledgers").join(format!("{base_id}.jsonl")))
            .unwrap();
        let rows: Vec<SignedLedgerUpdate> = log.lines().map(soak_row).collect();
        let window: Vec<SignedLedgerUpdate> = rows
            .iter()
            .filter(|u| u.sequence_number >= 442_249)
            .cloned()
            .collect();
        assert_eq!(window.len(), 3);

        // The defect: the window alone knows of no QuorumBegin.
        assert_eq!(latest_quorum_begin_seq(&window), None);
        // The ledger does: its state records the latest one (ref4's checkpoint of 0aeebcc5:
        // quorum_begin_sequence 436154), and that ends the dispute (vector
        // expiry_dispute_ends.json, "re-established, expired again": ended).
        let qb = base_latest_quorum_begin_seq(Some(436_154), &window).unwrap();
        assert_eq!(qb, 436_154);
        assert!(deposits_core::types::expiry_dispute_ended(lvs, qb, false));
        // Nor does a state that never saw one invent it, and a later one in the window wins.
        assert_eq!(base_latest_quorum_begin_seq(None, &window), None);
        assert_eq!(base_latest_quorum_begin_seq(Some(1), &rows), Some(436_154));

        // The watch's own judgement of this fork against that base.
        let (reestablished, in_window, below) =
            judge_reestablishment(std::slice::from_ref(&enter), true, Some(436_154), &window);
        assert!(reestablished, "the re-establishment at 359228..436154 ends the dispute");
        assert!(in_window.is_empty());
        assert_eq!(below, Some((359_090, 492_259, 492_261)));
        // With the whole history in memory nothing is read from disk.
        let (r, all, below) = judge_reestablishment(std::slice::from_ref(&enter), true, None, &rows);
        assert!(r);
        assert_eq!(all.len(), 4);
        assert_eq!(below, None);

        // v8: the rotations after the fork point are below the window, so their rungs come from
        // disk, and only those after the fork point (325917 is before it).
        assert!(!history_covers_after(&window, lvs));
        assert!(history_covers_after(&rows, lvs));
        assert!(quorum_begin_rungs_after(&window, lvs).is_empty());
        let persisted = crate::handler::DepositsHandler::read_persisted_quorum_begins_at(
            &dir,
            base_id,
            lvs,
            window[0].sequence_number,
        )
        .unwrap();
        assert_eq!(
            persisted.iter().map(|u| u.sequence_number).collect::<Vec<_>>(),
            vec![359_228, 389_318, 420_023, 436_154]
        );
        let rungs = quorum_begin_rungs_after(&persisted, lvs);
        assert_eq!(rungs.len(), 4);
        // 359228's rung confirmed at 8212 (txid display order is the reverse of the bytes).
        let mut confirmed =
            hex::decode("64fa8935f4dcc8c62e1c4be032547931ca67a719c440c86b35f7cbd65f9e419b").unwrap();
        confirmed.reverse();
        assert!(rungs[0].iter().any(|t| t[..] == confirmed[..]));
        // The same read over the whole history agrees with the in-memory reading.
        assert_eq!(quorum_begin_rungs_after(&rows, lvs), rungs);
        // The watch reads the log once, then keeps up from the window as it scrolls.
        let read_log = |after: u64, below: u64| {
            crate::handler::DepositsHandler::read_persisted_quorum_begins_at(
                &dir, base_id, after, below,
            )
        };
        let (entry, first) = rungs_seen(None, lvs, 492_259, 492_261, Vec::new(), read_log);
        assert_eq!(first, rungs);
        assert_eq!(entry.as_ref().unwrap().0, 492_262);
        let no_read = |_: u64, _: u64| -> Option<Vec<SignedLedgerUpdate>> {
            panic!("a stretch already seen is not read again")
        };
        let (entry2, second) =
            rungs_seen(entry.clone(), lvs, 492_261, 492_270, Vec::new(), no_read);
        assert_eq!(second, rungs);
        assert_eq!(entry2.unwrap().0, 492_271);
        // A stretch that scrolled past unseen (window now from 500000) is read, from where the
        // last pass stopped.
        let mut asked = None;
        let (_, third) = rungs_seen(entry.clone(), lvs, 500_000, 500_010, Vec::new(), |a, b| {
            asked = Some((a, b));
            Some(Vec::new())
        });
        assert_eq!(asked, Some((492_261, 500_000)));
        assert_eq!(third, rungs);
        // Unread is not "none": no entry is written, and what was known stands.
        let (none, fourth) = rungs_seen(entry, lvs, 500_000, 500_010, Vec::new(), |_, _| None);
        assert!(none.is_none());
        assert_eq!(fourth, rungs);

        // Every QuorumBegin row carries the pre-filter mark, and only those do.
        for line in log.lines() {
            let is_qb = matches!(
                LedgerOperation::tlv_decode(&soak_row(line).message),
                Ok(LedgerOperation::QuorumBegin { .. })
            );
            assert_eq!(line.contains(crate::handler::QUORUM_BEGIN_ROW_MARK), is_qb);
        }
    }
}
