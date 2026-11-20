//! Publishing a dispute fork: only the fork's own updates, and never silently
//! lost.
//!
//! When ref3 forked ledger C at seq 17839 on the signet devnet (2026-09-28
//! 01:19:37Z) it published the fork with `broadcast_all_updates`: the whole
//! history, 17,844 updates from genesis, sent in one loop. nostr-sdk's
//! `send_msg_to` only enqueues: each relay connection has a bounded 1024-slot
//! channel filled with `try_send`, so once the loop outran the writer every
//! send failed with "message not sent". The relay received seq 0-9977 and
//! none of 9978-17843, which included the fork's DisputeEnter (17840), its
//! QuorumAddMembers and its DisputeArmed (17843). Each failure was logged at
//! warn from `node::init`, but `broadcast_all_updates` returned `Ok`, the
//! caller logged "Published DisputeArmed on fork", and nothing ever retried:
//! the next auto-arm pass found the fork armed and did not broadcast. No
//! other node could see ref3's fork.
//!
//! The prefix (seq <= last_valid_sequence) is the original operator's chain
//! and is on the relay under their events; republishing it adds nothing but
//! load, and a burst of old updates with fresh timestamps also confuses the
//! backwards relay walk (see `expiry_watch::reimport_reached_tip`). So:
//!
//! - a fork publishes only its own updates, the ones past the fork point;
//! - each send is retried with backoff, a long tail is paced so it cannot
//!   fill the channel, and publication stops at the first update that still
//!   fails (receivers need them in chain order) and reports an error;
//! - a fork whose tail did not go out is kept in `pending_fork_publications`
//!   and retried every periodic until it does; at startup our live forks
//!   (Disputed or Armed) are queued once, so a tail lost before an upgrade or
//!   restart goes out too.
//!
//! What a startup must NOT republish (signet soak, 2026-11-20): ref4, operator
//! of 5effb9e8, had forked its OWN ledger at 432509 on a QuorumExpired proof
//! against itself (2026-11-19T21:46:50Z) and then signed the main chain's
//! 432510 too. Its next restart queued that fork as live and republished its
//! DisputeEnter at 432510, and every member that held the main chain's 432510
//! saw two operator signatures at one sequence and published an Equivocation
//! proof. So at startup:
//!
//! - a fork of a ledger we operate is VOID (DEP-06 §Enter): dropped from
//!   memory, its actor stopped, its JSONL renamed `.jsonl.void` for the record,
//!   and never published or yielded;
//! - a fork superseded by a later `QuorumBegin` on its base, past the fork
//!   point, is RETIRED from publication (kept, so the expiry stand-down can
//!   still yield it); under `strict-lottery-v8` an expiry fork stays published
//!   until the re-establishment's spend confirms, as `stand_down` judges it;
//! - and no fork update is ever sent that conflicts with an update we signed
//!   on the base chain at the same sequence (`own_conflicting_signatures`), the
//!   property the two rules above exist to keep.

use super::*;

use deposits_core::types::DisputeState;
use deposits_core::SignedLedgerUpdate;

/// Attempts per update before publication gives up for this pass.
const SEND_ATTEMPTS: u32 = 4;
/// First retry delay; doubles each attempt (250ms, 500ms, 1s).
const RETRY_BASE_DELAY: std::time::Duration = std::time::Duration::from_millis(250);
/// Pause after every `PACE_EVERY` updates, so a long tail drains through the
/// relay connection's 1024-slot queue instead of overflowing it.
const PACE_EVERY: usize = 100;
const PACE_DELAY: std::time::Duration = std::time::Duration::from_millis(200);

/// The fork point encoded in a fork tracking key
/// (`<ledger_id>_<seq:06>_<pk16>`, see `DepositsHandler::fork_tracking_key`).
pub(crate) fn fork_key_last_valid_seq(fork_key: &str) -> Option<u64> {
    let mut parts = fork_key.rsplitn(3, '_');
    let _pk = parts.next()?;
    let seq = parts.next()?;
    let ledger_id = parts.next()?;
    if ledger_id.is_empty() {
        return None;
    }
    seq.parse().ok()
}

/// The fork's own updates: those past the fork point, in sequence order.
pub(crate) fn fork_tail(
    history: &[SignedLedgerUpdate],
    last_valid_seq: u64,
) -> Vec<SignedLedgerUpdate> {
    let mut tail: Vec<SignedLedgerUpdate> = history
        .iter()
        .filter(|u| u.sequence_number > last_valid_seq)
        .cloned()
        .collect();
    tail.sort_by_key(|u| u.sequence_number);
    tail
}

/// What startup does with a fork record we hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ForkFate {
    /// Not our live fork (another member's, concluded, or tombstoned).
    NotOurs,
    /// Our live fork: republish its tail.
    Publish,
    /// Superseded by a later `QuorumBegin` on the base: do not republish.
    Retire,
    /// A fork of a ledger we operate: void (DEP-06 §Enter).
    Void,
}

/// The facts `fork_fate` decides on, read from the fork and its base record.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ForkFacts {
    /// The fork's branch owner (`parent_pubkey`).
    pub fork_owner: bitcoin::secp256k1::PublicKey,
    /// Disputed or Armed.
    pub live: bool,
    /// The base key points at this same fork (a won dispute, promoted).
    pub promoted: bool,
    /// The base ledger's current operator (`parent_pubkey`), if we hold it.
    pub base_operator: Option<bitcoin::secp256k1::PublicKey>,
    /// The fork point (`last_valid_sequence`).
    pub fork_point: u64,
    /// The base's latest `QuorumBegin` sequence, if any.
    pub base_quorum_begin: Option<u64>,
    /// An expiry dispute under a ruleset where only a confirmed spend ends it.
    pub expiry_ends_on_spend: bool,
}

/// Startup's verdict on one fork record (see the module comment).
pub(crate) fn fork_fate(our_key: &bitcoin::secp256k1::PublicKey, f: &ForkFacts) -> ForkFate {
    if f.fork_owner != *our_key || !f.live {
        return ForkFate::NotOurs;
    }
    if f.promoted {
        return ForkFate::Publish;
    }
    if f.base_operator.as_ref() == Some(our_key) {
        return ForkFate::Void;
    }
    if f.base_quorum_begin.is_some_and(|qb| qb > f.fork_point) && !f.expiry_ends_on_spend {
        return ForkFate::Retire;
    }
    ForkFate::Publish
}

/// The sequences at which `fork_tail` holds an update signed by `our_key`
/// whose content differs from an update `our_key` signed on the base chain at
/// the same sequence: each is an equivocation proof against us. A node must
/// never publish such an update; empty for every honest fork, whose updates
/// are signed by a member that is not the base's signer at those sequences.
pub(crate) fn own_conflicting_signatures(
    our_key: &bitcoin::secp256k1::PublicKey,
    base_history: &[SignedLedgerUpdate],
    fork_tail: &[SignedLedgerUpdate],
) -> Vec<u64> {
    let ours: std::collections::HashMap<u64, [u8; 32]> = base_history
        .iter()
        .filter(|u| u.operator_id == *our_key)
        .map(|u| (u.sequence_number, u.content_hash))
        .collect();
    let mut seqs: Vec<u64> = fork_tail
        .iter()
        .filter(|u| u.operator_id == *our_key)
        .filter(|u| {
            ours.get(&u.sequence_number)
                .is_some_and(|h| *h != u.content_hash)
        })
        .map(|u| u.sequence_number)
        .collect();
    seqs.sort_unstable();
    seqs.dedup();
    seqs
}

/// Why a publication pass stopped.
#[derive(Debug)]
pub(crate) struct PublishFailure {
    /// Updates that went out before the failure.
    pub sent: usize,
    /// The update that could not be sent, even after retries.
    pub sequence: u64,
    pub error: String,
}

/// Send `updates` in order through `send`, retrying each up to `attempts`
/// times with a doubling `base_delay`, and pausing `pace_delay` after every
/// `pace_every` updates. Stops at the first update that still fails.
pub(crate) async fn publish_in_order<F, Fut>(
    updates: &[SignedLedgerUpdate],
    attempts: u32,
    base_delay: std::time::Duration,
    pace_every: usize,
    pace_delay: std::time::Duration,
    mut send: F,
) -> Result<usize, PublishFailure>
where
    F: FnMut(SignedLedgerUpdate) -> Fut,
    Fut: std::future::Future<Output = Result<(), String>>,
{
    for (i, update) in updates.iter().enumerate() {
        if i > 0 && pace_every > 0 && i % pace_every == 0 {
            tokio::time::sleep(pace_delay).await;
        }
        let mut delay = base_delay;
        let mut attempt = 1;
        loop {
            match send(update.clone()).await {
                Ok(()) => break,
                Err(error) if attempt >= attempts => {
                    return Err(PublishFailure {
                        sent: i,
                        sequence: update.sequence_number,
                        error,
                    });
                }
                Err(error) => {
                    tracing::warn!(
                        "Fork publish: seq {} attempt {}/{} failed: {}; retrying in {:?}",
                        update.sequence_number,
                        attempt,
                        attempts,
                        error,
                        delay
                    );
                    tokio::time::sleep(delay).await;
                    delay *= 2;
                    attempt += 1;
                }
            }
        }
    }
    Ok(updates.len())
}

impl Node {
    /// Publish our fork's own updates (past the fork point). On failure the
    /// fork is queued for the periodic retry and the error is logged; on
    /// success it leaves the queue.
    pub(crate) async fn publish_fork(&self, fork_key: &str) -> Result<usize, Error> {
        if let Some(seqs) = self.fork_conflicts_with_our_base(fork_key) {
            self.void_fork(
                fork_key,
                &format!(
                    "its update(s) at seq {:?} conflict with ones we signed on the base",
                    seqs
                ),
            );
            return Err(Error::Protocol(format!(
                "fork {} not published: it would equivocate at seq {:?}",
                &fork_key[..32.min(fork_key.len())],
                seqs
            )));
        }
        let result = self.publish_fork_tail(fork_key).await;
        let mut pending = self.pending_fork_publications.lock().unwrap();
        match &result {
            Ok(n) => {
                pending.remove(fork_key);
                tracing::info!(
                    "Published dispute fork {}: {} own update(s) past the fork point",
                    &fork_key[..32.min(fork_key.len())],
                    n
                );
            }
            Err(e) => {
                pending.insert(fork_key.to_string());
                tracing::error!(
                    "Dispute fork {} not fully published ({}); will retry every periodic",
                    &fork_key[..32.min(fork_key.len())],
                    e
                );
            }
        }
        result
    }

    async fn publish_fork_tail(&self, fork_key: &str) -> Result<usize, Error> {
        let last_valid_seq = fork_key_last_valid_seq(fork_key)
            .ok_or_else(|| Error::Protocol(format!("not a fork tracking key: {}", fork_key)))?;
        let ledger_arc = self
            .handler
            .ledgers
            .lock()
            .unwrap()
            .get(fork_key)
            .cloned()
            .ok_or_else(|| Error::Protocol(format!("Fork not found: {}", fork_key)))?;
        let tail = {
            let fork = ledger_arc.read().unwrap();
            fork_tail(&fork.history, last_valid_seq)
        };
        let nostr = &self.nostr;
        publish_in_order(
            &tail,
            SEND_ATTEMPTS,
            RETRY_BASE_DELAY,
            PACE_EVERY,
            PACE_DELAY,
            |update| async move {
                nostr
                    .broadcast_ledger_update(&update)
                    .await
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            },
        )
        .await
        .map_err(|f| {
            Error::Protocol(format!(
                "seq {} failed after {} attempts ({}); {} of {} sent",
                f.sequence,
                SEND_ATTEMPTS,
                f.error,
                f.sent,
                tail.len()
            ))
        })
    }

    /// Periodic: retry every fork whose publication failed.
    pub(crate) async fn retry_fork_publications(&self) {
        let pending: Vec<String> = self
            .pending_fork_publications
            .lock()
            .unwrap()
            .iter()
            .cloned()
            .collect();
        for fork_key in pending {
            let _ = self.publish_fork(&fork_key).await;
        }
    }

    /// `own_conflicting_signatures` of a fork against our copy of its base,
    /// or `None` when it has none (or either record is missing).
    pub(crate) fn fork_conflicts_with_our_base(&self, fork_key: &str) -> Option<Vec<u64>> {
        let last_valid_seq = fork_key_last_valid_seq(fork_key)?;
        let ledgers = self.handler.ledgers.lock().unwrap();
        let fork = ledgers.get(fork_key)?;
        let base = ledgers.get(fork_key.get(..64)?)?;
        if Arc::ptr_eq(fork, base) {
            return None;
        }
        let tail = fork_tail(&fork.read().unwrap().history, last_valid_seq);
        let seqs = own_conflicting_signatures(&self.node_id, &base.read().unwrap().history, &tail);
        (!seqs.is_empty()).then_some(seqs)
    }

    /// Void a fork record (DEP-06 §Enter): drop it from memory and from the
    /// publication queue, stop its actor, and rename its JSONL to
    /// `.jsonl.void` (kept for the record; the loader reads only `.jsonl`).
    /// Nothing is signed or published: a void fork is never yielded either,
    /// since a yield would be one more update under our key past the fork point.
    pub(crate) fn void_fork(&self, fork_key: &str, why: &str) {
        self.handler.ledgers.lock().unwrap().remove(fork_key);
        self.ledger_actors.lock().unwrap().remove(fork_key);
        self.pending_fork_publications
            .lock()
            .unwrap()
            .remove(fork_key);
        let dir = self.data_dir.join("wallet").join("ledgers");
        let from = dir.join(format!("{}.jsonl", fork_key));
        let to = dir.join(format!("{}.jsonl.void", fork_key));
        if from.exists() {
            if let Err(e) = std::fs::rename(&from, &to) {
                tracing::error!(
                    "Voiding fork {}: could not rename its JSONL: {}",
                    fork_key,
                    e
                );
            }
        }
        tracing::warn!(
            "Voided dispute fork {}: {} (DEP-06 §Enter); not published, not yielded",
            &fork_key[..32.min(fork_key.len())],
            why
        );
    }

    /// The `ForkFacts` of every fork record we hold, keyed by fork key.
    fn fork_facts(&self) -> Vec<(String, ForkFacts)> {
        use super::expiry_watch::{
            dispute_enter_is_expiry, dispute_enter_last_valid, latest_quorum_begin_seq,
        };
        let ledgers = self.handler.ledgers.lock().unwrap();
        ledgers
            .iter()
            .filter(|(key, _)| key.len() > 64)
            .filter_map(|(key, arc)| {
                let fork_point = fork_key_last_valid_seq(key)?;
                let base_arc = ledgers.get(&key[..64]);
                let fork = arc.read().unwrap();
                let promoted = base_arc.is_some_and(|b| Arc::ptr_eq(b, arc));
                let (base_operator, base_quorum_begin, base_expiry) = match base_arc {
                    Some(b) if !promoted => {
                        let b = b.read().unwrap();
                        let qb =
                            latest_quorum_begin_seq(&b.history).max(b.state.quorum_begin_sequence);
                        (Some(b.state.parent_pubkey), qb, b.state.quorum_expiry)
                    }
                    _ => (None, None, None),
                };
                let fork_point = dispute_enter_last_valid(&fork.history).unwrap_or(fork_point);
                // Unknown ground counts as an expiry dispute: kept published, as before.
                let expiry = dispute_enter_is_expiry(&fork.history, base_expiry).unwrap_or(true);
                let expiry_ends_on_spend = expiry
                    && deposits_core::types::ruleset_expiry_ends_on_spend(
                        &fork.state.active_ruleset_name,
                    );
                Some((
                    key.clone(),
                    ForkFacts {
                        fork_owner: fork.state.parent_pubkey,
                        live: matches!(
                            fork.state.dispute_state,
                            DisputeState::Disputed | DisputeState::Armed
                        ),
                        promoted,
                        base_operator,
                        fork_point,
                        base_quorum_begin,
                        expiry_ends_on_spend,
                    },
                ))
            })
            .collect()
    }

    /// Startup: void our forks of ledgers we operate, then queue our live
    /// forks (Disputed or Armed, operated by us, not superseded) for
    /// publication, so a tail lost before a restart still goes out.
    pub(crate) fn queue_live_forks_for_publication(&self) {
        let mut live = Vec::new();
        for (key, facts) in self.fork_facts() {
            match fork_fate(&self.node_id, &facts) {
                ForkFate::NotOurs => {}
                ForkFate::Publish => live.push(key),
                ForkFate::Retire => tracing::info!(
                    "Dispute fork {} retired from publication: superseded by QuorumBegin \
                     seq {:?} past its fork point {}",
                    &key[..32.min(key.len())],
                    facts.base_quorum_begin,
                    facts.fork_point
                ),
                ForkFate::Void => self.void_fork(&key, "a fork of a ledger we operate"),
            }
        }
        if !live.is_empty() {
            tracing::info!("Queued {} live dispute fork(s) for publication", live.len());
            self.pending_fork_publications.lock().unwrap().extend(live);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;

    fn pk(seed: u8) -> PublicKey {
        let secp = Secp256k1::new();
        PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[seed; 32]).unwrap())
    }

    fn upd(seq: u64, operator: PublicKey) -> SignedLedgerUpdate {
        SignedLedgerUpdate {
            message: Vec::new(),
            message_type: 0,
            operator_id: operator,
            ledger_id: [7u8; 32],
            sequence_number: seq,
            previous_hash: [0u8; 32],
            content_hash: [seq as u8; 32],
            block_height: 0,
            block_hash: [0u8; 32],
            operator_signature: [0u8; 64],
            cosignatures: Vec::new(),
        }
    }

    /// A fork of C at 17839 in miniature: the operator's prefix, then our
    /// DisputeEnter, two QuorumAddMembers and DisputeArmed.
    fn fork_history(lvs: u64) -> Vec<SignedLedgerUpdate> {
        let (operator, us) = (pk(1), pk(2));
        let mut h: Vec<_> = (0..=lvs).map(|s| upd(s, operator)).collect();
        h.extend((lvs + 1..=lvs + 4).map(|s| upd(s, us)));
        h
    }

    /// DEP-06 §Enter, shared with cl-deposits (`self_dispute.json`, `fork_cases`).
    #[test]
    fn fork_fate_vector() {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/vectors/self_dispute.json")).unwrap();
        let name_key = |n: &str| match n {
            "op" => pk(1),
            "m1" => pk(2),
            "m2" => pk(3),
            "w" => pk(4),
            other => panic!("unknown key name {other}"),
        };
        let mut n = 0;
        for case in v["fork_cases"].as_array().unwrap() {
            let facts = ForkFacts {
                fork_owner: name_key(case["fork_owner"].as_str().unwrap()),
                live: case["live"].as_bool().unwrap(),
                promoted: case["promoted"].as_bool().unwrap(),
                base_operator: case["base_operator"].as_str().map(name_key),
                fork_point: case["fork_point"].as_u64().unwrap(),
                base_quorum_begin: case["base_quorum_begin"].as_u64(),
                expiry_ends_on_spend: case["expiry_ends_on_spend"].as_bool().unwrap(),
            };
            let want = match case["expect"]["fate"].as_str().unwrap() {
                "void" => ForkFate::Void,
                "retire" => ForkFate::Retire,
                "publish" => ForkFate::Publish,
                "not_ours" => ForkFate::NotOurs,
                other => panic!("unknown fate {other}"),
            };
            let us = name_key(case["us"].as_str().unwrap());
            assert_eq!(fork_fate(&us, &facts), want, "{}", case["name"]);
            n += 1;
        }
        assert_eq!(n, 9);
    }

    fn upd_c(seq: u64, operator: PublicKey, content: u8) -> SignedLedgerUpdate {
        SignedLedgerUpdate {
            content_hash: [content; 32],
            ..upd(seq, operator)
        }
    }

    /// ref4's shape (signet, 2026-11-19): its main chain's 432510 and its own
    /// fork's DisputeEnter at 432510, both under its key, different content.
    #[test]
    fn a_self_fork_tail_conflicts_with_our_own_chain() {
        let us = pk(1);
        let base: Vec<_> = (432_500..=432_520).map(|s| upd_c(s, us, 0xA0)).collect();
        let fork: Vec<_> = (432_500..=432_509)
            .map(|s| upd_c(s, us, 0xA0))
            .chain(std::iter::once(upd_c(432_510, us, 0x0F)))
            .collect();
        let tail = fork_tail(&fork, 432_509);
        assert_eq!(own_conflicting_signatures(&us, &base, &tail), vec![432_510]);
        // Before the main chain reached 432510 (21:46 to 22:17Z) there was nothing
        // to conflict with yet: why the guard has to be at the dispute, not here.
        let short: Vec<_> = (432_500..=432_509).map(|s| upd_c(s, us, 0xA0)).collect();
        assert!(own_conflicting_signatures(&us, &short, &tail).is_empty());
    }

    /// The honest shape: a member's fork tail is under the member's key, the
    /// base under the operator's, so nothing of ours conflicts.
    #[test]
    fn a_member_fork_tail_never_conflicts() {
        let (operator, us) = (pk(1), pk(2));
        let base: Vec<_> = (0..=60).map(|s| upd_c(s, operator, 1)).collect();
        let tail = fork_tail(&fork_history(50), 50);
        assert!(own_conflicting_signatures(&us, &base, &tail).is_empty());
        // Same content re-signed is a duplicate, not an equivocation.
        let same: Vec<_> = (51..=54).map(|s| upd_c(s, us, s as u8)).collect();
        let base_us: Vec<_> = (51..=54).map(|s| upd(s, us)).collect();
        assert!(own_conflicting_signatures(&us, &base_us, &same).is_empty());
    }

    #[test]
    fn fork_key_carries_the_fork_point() {
        let key = crate::handler::DepositsHandler::fork_tracking_key(
            "eff805009bb9a7e3bd31dd24cf93ec3b08ac0dac24e81c27abb3b27a03a2db1a",
            17839,
            &pk(2),
        );
        assert_eq!(fork_key_last_valid_seq(&key), Some(17839));
        assert_eq!(
            fork_key_last_valid_seq(
                "eff805009bb9a7e3bd31dd24cf93ec3b08ac0dac24e81c27abb3b27a03a2db1a"
            ),
            None
        );
    }

    #[test]
    fn fork_publishes_only_updates_past_the_fork_point() {
        let tail = fork_tail(&fork_history(17839), 17839);
        let seqs: Vec<u64> = tail.iter().map(|u| u.sequence_number).collect();
        assert_eq!(seqs, vec![17840, 17841, 17842, 17843]);
        assert!(tail.iter().all(|u| u.operator_id == pk(2)));
    }

    #[tokio::test]
    async fn only_the_tail_is_sent() {
        let tail = fork_tail(&fork_history(50), 50);
        let sent = std::sync::Mutex::new(Vec::new());
        let n = publish_in_order(&tail, 1, Duration::ZERO, 0, Duration::ZERO, |u| {
            sent.lock().unwrap().push(u.sequence_number);
            async { Ok(()) }
        })
        .await
        .unwrap();
        assert_eq!(n, 4);
        assert_eq!(*sent.lock().unwrap(), vec![51, 52, 53, 54]);
    }

    #[tokio::test]
    async fn a_failed_send_is_retried() {
        let tail = fork_tail(&fork_history(10), 10);
        // DisputeEnter's first two sends hit a full channel.
        let failures = AtomicU32::new(2);
        let sends = std::sync::Mutex::new(Vec::new());
        let n = publish_in_order(&tail, 4, Duration::from_millis(1), 0, Duration::ZERO, |u| {
            sends.lock().unwrap().push(u.sequence_number);
            let fail = u.sequence_number == 11
                && failures
                    .try_update(Ordering::SeqCst, Ordering::SeqCst, |f| f.checked_sub(1))
                    .is_ok();
            async move {
                if fail {
                    Err("message not sent".to_string())
                } else {
                    Ok(())
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(n, 4);
        assert_eq!(*sends.lock().unwrap(), vec![11, 11, 11, 12, 13, 14]);
    }

    #[tokio::test]
    async fn a_send_that_keeps_failing_is_reported_and_stops_in_order() {
        let tail = fork_tail(&fork_history(10), 10);
        let sends = std::sync::Mutex::new(Vec::new());
        let err = publish_in_order(&tail, 3, Duration::from_millis(1), 0, Duration::ZERO, |u| {
            sends.lock().unwrap().push(u.sequence_number);
            let fail = u.sequence_number == 13;
            async move {
                if fail {
                    Err("message not sent".to_string())
                } else {
                    Ok(())
                }
            }
        })
        .await
        .unwrap_err();
        assert_eq!((err.sent, err.sequence), (2, 13));
        assert_eq!(err.error, "message not sent");
        // Three attempts at 13, and 14 (DisputeArmed) is not sent past the gap.
        assert_eq!(*sends.lock().unwrap(), vec![11, 12, 13, 13, 13]);
    }

    #[tokio::test]
    async fn a_long_tail_is_paced() {
        let tail: Vec<_> = (1..=250).map(|s| upd(s, pk(2))).collect();
        let start = tokio::time::Instant::now();
        let n = publish_in_order(
            &tail,
            1,
            Duration::ZERO,
            100,
            Duration::from_millis(20),
            |_| async { Ok(()) },
        )
        .await
        .unwrap();
        assert_eq!(n, 250);
        // Paused after 100 and after 200.
        assert!(start.elapsed() >= Duration::from_millis(40));
    }
}
