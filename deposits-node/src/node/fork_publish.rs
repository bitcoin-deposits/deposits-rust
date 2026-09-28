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

    /// Startup: queue our live forks (Disputed or Armed, operated by us) for
    /// publication, so a tail lost before a restart still goes out.
    pub(crate) fn queue_live_forks_for_publication(&self) {
        let live: Vec<String> = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            ledgers
                .iter()
                .filter(|(key, _)| key.len() > 64 && fork_key_last_valid_seq(key).is_some())
                .filter(|(_, arc)| {
                    let l = arc.read().unwrap();
                    l.state.parent_pubkey == self.node_id
                        && matches!(
                            l.state.dispute_state,
                            DisputeState::Disputed | DisputeState::Armed
                        )
                })
                .map(|(key, _)| key.clone())
                .collect()
        };
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
            cosign_signature: [0u8; 64],
            operator_signature: [0u8; 64],
            cosigner_pubkey: None,
            member_ledger_hash: None,
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
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |f| f.checked_sub(1))
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
