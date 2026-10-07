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

/// The `reason` of the `DisputeEnter` on a fork branch, if it holds one.
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
    /// already under way. An armed fork gets a `DisputeYield` (it is then
    /// Tombstoned, so the confiscation and lottery tasks pass it by); a fork
    /// not yet armed has nothing to yield (the state machine allows
    /// `DisputeYield` only once armed) and is simply no longer pursued: the
    /// watch does not re-fire on a quorum that has not expired.
    pub(crate) async fn stand_down_reestablished_expiry_disputes(&self) {
        // (fork key, base id, reason, base expiry, fork state) for every fork
        // of ours still live that was opened for a lapsed quorum.
        type Live = (String, String, String, Option<u32>, DisputeState);
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
                    let reason = dispute_enter_reason(&fork.history)?;
                    if !is_expiry_reason(&reason) {
                        return None;
                    }
                    let base_id = key[..64].to_string();
                    let base_expiry = ledgers
                        .get(&base_id)
                        .and_then(|b| b.read().unwrap().state.quorum_expiry);
                    Some((
                        key.clone(),
                        base_id,
                        reason,
                        base_expiry,
                        fork.state.dispute_state,
                    ))
                })
                .collect()
        };
        if live.is_empty() {
            return;
        }

        // Live chain tip, as the watch that opened them reads it.
        let height = match self.wallet.fetch_block_info() {
            Ok((h, _)) => h,
            Err(_) => return,
        };
        let candidates = live.into_iter().filter(|(_, _, reason, expiry, _)| {
            expiry_dispute_stands_down(reason, *expiry, height)
        });

        for (fork_key, ledger_id, _, expiry, state) in candidates {
            let prefix = &ledger_id[..16];

            if state != DisputeState::Armed {
                tracing::debug!(
                    "Expiry dispute on {}: quorum re-established (expiry {:?}, height {}); \
                     not armed, not pursuing it",
                    prefix,
                    expiry,
                    height
                );
                continue;
            }

            // Nothing confiscated: no confiscation of ours in flight, no
            // lottery reveal (which follows a confirmed confiscation), and no
            // lottery output on chain for this dispute's armers.
            let ours_pending = self
                .pending_confiscations
                .lock()
                .unwrap()
                .contains_key(prefix);
            if ours_pending
                || self.have_revealed_lottery(&ledger_id).await
                || matches!(
                    self.check_confiscation_confirmed(&ledger_id, 0).await,
                    Ok(true)
                )
            {
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
}
