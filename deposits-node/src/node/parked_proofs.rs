//! Fraud proofs a member cannot judge YET, parked until its replica catches up.
//!
//! Regtest run 1120-075609 (2026-11-20T08:02:51Z, scenario rearm-rust): ref7
//! was about 3 s behind ledger 7341c3d1, holding seq 0-4, when four members'
//! NonConformingUpdate proofs arrived whose fault update is at seq 9. Each was
//! refused for good: "fault update at seq 9 follows an update that is not in
//! this ledger's history". Milliseconds later ref7 caught up ("gap: local=8,
//! incoming seq=9"), but nothing judged the proofs again, so ref7 never forked,
//! armed or proposed, and the scenario failed. A member that is briefly behind
//! lost its dispute standing for good: a liveness hole, and an attack (deliver
//! the proof to a member before the updates it rests on).
//!
//! So a verdict that fails while our replica of a ledger the evidence rests on
//! is BEHIND the sequence the evidence needs is "cannot judge yet", not
//! "invalid": the proof is parked here, keyed by the accused ledger, with the
//! `(ledger, sequence)` pairs it needs (`FraudBroadcast::history_needs`). The node queues those
//! ledgers for catch-up and re-judges a parked proof once every need is met.
//! A proof that fails with every need met is invalid, as before.
//! The needs are an upper bound (a fault that skips, signed at T+2 onto T,
//! needs T), so a parked proof is also judged again when our replica merely
//! ADVANCES, at most every [`PROGRESS_REJUDGE`], staying parked meanwhile.
//!
//! Bounded: at most [`PARK_CAP_PER_LEDGER`] proofs per accused ledger (one per
//! proof hash), each for at most [`PARK_TTL`]. When a ledger's set is full a new
//! proof displaces the parked one whose needs reach furthest past our replica
//! (the least likely to become judgeable), or is dropped if it reaches further
//! itself.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// How long a proof stays parked before it is dropped unjudged.
pub(crate) const PARK_TTL: Duration = Duration::from_secs(60 * 60);
/// Parked proofs per accused ledger.
pub(crate) const PARK_CAP_PER_LEDGER: usize = 32;

pub(crate) use deposits_core::fraud::unmet_history_needs as unmet_needs;

/// How far a proof's needs reach past our replicas (0 once all are met).
fn shortfall(needs: &[(String, u64)], tip_of: &impl Fn(&str) -> Option<u64>) -> u64 {
    needs
        .iter()
        .map(|(l, s)| s.saturating_sub(tip_of(l).map_or(0, |t| t)))
        .max()
        .unwrap_or(0)
}

/// What `park` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ParkOutcome {
    Parked,
    /// The same proof (by hash) is already parked.
    AlreadyParked,
    /// The ledger's set was full: this one displaced a further-reaching proof.
    ParkedDisplacing,
    /// The ledger's set was full and this proof reaches furthest: not parked.
    Full,
}

pub(crate) struct Parked<E> {
    pub event: E,
    pub hash: [u8; 32],
    pub needs: Vec<(String, u64)>,
    pub parked_at: Instant,
    /// Our replica tips of the needed ledgers when last judged.
    tips: Vec<Option<u64>>,
    judged_at: Instant,
}

/// A parked proof is judged again on PROGRESS too, not only once its needs are
/// met, at most this often. The needs are an upper bound: a fault that SKIPS
/// (signed at seq T+2 onto the update at T) needs T, not T+1, so a member that
/// was behind and has reached T can judge it although T+1 may never exist.
pub(crate) const PROGRESS_REJUDGE: Duration = Duration::from_secs(60);

/// The parked set. Generic over the event so tests need no relay types.
pub(crate) struct ParkedProofs<E> {
    by_ledger: HashMap<String, Vec<Parked<E>>>,
    pub(crate) cap: usize,
    pub(crate) ttl: Duration,
    pub(crate) progress_rejudge: Duration,
}

impl<E> Default for ParkedProofs<E> {
    fn default() -> Self {
        Self {
            by_ledger: HashMap::new(),
            cap: PARK_CAP_PER_LEDGER,
            ttl: PARK_TTL,
            progress_rejudge: PROGRESS_REJUDGE,
        }
    }
}

fn tips_of(needs: &[(String, u64)], tip_of: &impl Fn(&str) -> Option<u64>) -> Vec<Option<u64>> {
    needs.iter().map(|(l, _)| tip_of(l)).collect()
}

impl<E: Clone> ParkedProofs<E> {
    pub(crate) fn len(&self) -> usize {
        self.by_ledger.values().map(Vec::len).sum()
    }

    /// Park `event` (its proof hash `hash`, accused ledger `ledger`) until
    /// every one of `needs` is met.
    pub(crate) fn park(
        &mut self,
        ledger: &str,
        hash: [u8; 32],
        needs: Vec<(String, u64)>,
        event: E,
        now: Instant,
        tip_of: &impl Fn(&str) -> Option<u64>,
    ) -> ParkOutcome {
        let ttl = self.ttl;
        let cap = self.cap;
        let set = self.by_ledger.entry(ledger.to_string()).or_default();
        set.retain(|p| now.duration_since(p.parked_at) < ttl);
        if set.iter().any(|p| p.hash == hash) {
            return ParkOutcome::AlreadyParked;
        }
        let entry = Parked {
            event,
            hash,
            tips: tips_of(&needs, tip_of),
            needs,
            parked_at: now,
            judged_at: now,
        };
        if set.len() < cap {
            set.push(entry);
            return ParkOutcome::Parked;
        }
        let ours = shortfall(&entry.needs, tip_of);
        let (worst, worst_reach) = set
            .iter()
            .enumerate()
            .map(|(i, p)| (i, shortfall(&p.needs, tip_of)))
            .max_by_key(|&(_, r)| r)
            .expect("a full set is not empty");
        if worst_reach > ours {
            set[worst] = entry;
            ParkOutcome::ParkedDisplacing
        } else {
            ParkOutcome::Full
        }
    }

    /// Drop expired proofs; return every parked proof to judge again, with
    /// the number expired. A proof whose needs are all met leaves the set; one
    /// whose replicas merely ADVANCED since it was last judged is returned
    /// (at most every `progress_rejudge`) and stays parked, so a failed
    /// re-judge finds it already parked and its expiry is not reset.
    pub(crate) fn take_ready(
        &mut self,
        now: Instant,
        tip_of: &impl Fn(&str) -> Option<u64>,
    ) -> (Vec<E>, usize) {
        let ttl = self.ttl;
        let every = self.progress_rejudge;
        let mut ready = Vec::new();
        let mut expired = 0;
        for set in self.by_ledger.values_mut() {
            let mut keep = Vec::with_capacity(set.len());
            for mut p in set.drain(..) {
                if now.duration_since(p.parked_at) >= ttl {
                    expired += 1;
                } else if unmet_needs(&p.needs, tip_of).is_empty() {
                    ready.push(p.event);
                } else {
                    let tips = tips_of(&p.needs, tip_of);
                    let advanced = tips.iter().zip(&p.tips).any(|(now_t, then)| now_t > then);
                    if advanced && now.duration_since(p.judged_at) >= every {
                        ready.push(p.event.clone());
                        p.tips = tips;
                        p.judged_at = now;
                    }
                    keep.push(p);
                }
            }
            *set = keep;
        }
        self.by_ledger.retain(|_, s| !s.is_empty());
        (ready, expired)
    }
}

impl super::Node {
    /// Our replica's highest sequence of `ledger_id`, `None` if we hold none.
    pub(crate) fn replica_tip(&self, ledger_id: &str) -> Option<u64> {
        let arc = self
            .handler
            .ledgers
            .lock()
            .unwrap()
            .get(ledger_id)
            .cloned()?;
        let l = arc.read().unwrap();
        l.history.last().map(|u| u.sequence_number)
    }

    /// Judge again every parked fraud proof whose needs our replicas now meet;
    /// drop the expired ones. Called from the run loop after each batch of
    /// ledger updates, so a proof is judged within one pass of the update it
    /// was waiting for.
    pub(crate) async fn rejudge_parked_fraud_proofs(&self) {
        let (ready, expired) = {
            let mut parked = self.parked_fraud_proofs.lock().unwrap();
            if parked.len() == 0 {
                return;
            }
            parked.take_ready(Instant::now(), &|l: &str| self.replica_tip(l))
        };
        if expired > 0 {
            tracing::warn!(
                "Dropped {} parked fraud proof(s) unjudged: our replica did not catch up within {:?}",
                expired,
                PARK_TTL
            );
        }
        for fp in ready {
            tracing::info!(
                "Re-judging parked fraud proof {}... on {}...: our replica has caught up",
                &hex::encode(fp.broadcast.proof.proof_hash())[..16],
                &fp.broadcast.proof.ledger_id[..16.min(fp.broadcast.proof.ledger_id.len())]
            );
            if tokio::time::timeout(Duration::from_secs(5), self.handle_fraud_proof(fp))
                .await
                .is_err()
            {
                tracing::error!(
                    "handle_fraud_proof (re-judging a parked proof) timed out after 5s"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const L: &str = "7341c3d17651952c3d6ba043578afabec9145784da1ab3805c5b46d00a34d059";

    fn h(b: u8) -> [u8; 32] {
        [b; 32]
    }

    #[test]
    fn a_parked_proof_is_released_once_the_replica_reaches_its_need() {
        let mut parked = ParkedProofs::<&str>::default();
        let now = Instant::now();
        let behind = |l: &str| (l == L).then_some(4);
        let needs = vec![(L.to_string(), 8)];
        assert_eq!(
            parked.park(L, h(1), needs.clone(), "proof", now, &behind),
            ParkOutcome::Parked
        );
        // Four members publish the same proof: it is parked once.
        assert_eq!(
            parked.park(L, h(1), needs, "proof", now, &behind),
            ParkOutcome::AlreadyParked
        );
        let (ready, expired) = parked.take_ready(now, &behind);
        assert!(ready.is_empty());
        assert_eq!(expired, 0);
        assert_eq!(parked.len(), 1);
        let caught_up = |l: &str| (l == L).then_some(8);
        let (ready, _) = parked.take_ready(now, &caught_up);
        assert_eq!(ready, vec!["proof"]);
        assert_eq!(parked.len(), 0);
    }

    #[test]
    fn a_parked_proof_expires() {
        let mut parked = ParkedProofs::<&str>::default();
        let t0 = Instant::now();
        let behind = |_: &str| Some(0);
        parked.park(L, h(1), vec![(L.to_string(), 8)], "p", t0, &behind);
        let (ready, expired) = parked.take_ready(t0 + PARK_TTL, &behind);
        assert!(ready.is_empty());
        assert_eq!(expired, 1);
        assert_eq!(parked.len(), 0);
    }

    /// A flood of proofs that reach far ahead cannot push out one the replica
    /// is about to be able to judge.
    #[test]
    fn a_full_set_keeps_the_proofs_nearest_to_judgeable() {
        let mut parked = ParkedProofs::<u8> {
            cap: 3,
            ..Default::default()
        };
        let now = Instant::now();
        let tip = |_: &str| Some(4);
        for i in 0..3 {
            assert_eq!(
                parked.park(
                    L,
                    h(i),
                    vec![(L.to_string(), 1_000 + i as u64)],
                    i,
                    now,
                    &tip
                ),
                ParkOutcome::Parked
            );
        }
        // The real proof needs seq 8: it displaces the furthest-reaching junk.
        assert_eq!(
            parked.park(L, h(9), vec![(L.to_string(), 8)], 9, now, &tip),
            ParkOutcome::ParkedDisplacing
        );
        // More junk, reaching further than everything held: dropped.
        assert_eq!(
            parked.park(L, h(10), vec![(L.to_string(), 5_000)], 10, now, &tip),
            ParkOutcome::Full
        );
        assert_eq!(parked.len(), 3);
        let (ready, _) = parked.take_ready(now, &|_: &str| Some(8));
        assert_eq!(ready, vec![9]);
        // The cap is per accused ledger.
        let other = "ab".repeat(32);
        assert_eq!(
            parked.park(&other, h(1), vec![(other.clone(), 3)], 1, now, &tip),
            ParkOutcome::Parked
        );
    }

    /// A skip (fault at T+2 onto T) needs only T; the needs say T+1. A member
    /// that was behind is given the proof again once its replica advances,
    /// rate-limited, and the proof stays parked meanwhile.
    #[test]
    fn progress_rejudges_without_releasing_the_slot() {
        let mut parked = ParkedProofs::<&str>::default();
        let t0 = Instant::now();
        parked.park(L, h(1), vec![(L.to_string(), 8)], "skip", t0, &|_: &str| {
            Some(2)
        });
        // No progress: nothing.
        assert!(parked
            .take_ready(t0 + PROGRESS_REJUDGE, &|_: &str| Some(2))
            .0
            .is_empty());
        // Progress, too soon: nothing.
        assert!(parked
            .take_ready(t0 + Duration::from_secs(1), &|_: &str| Some(7))
            .0
            .is_empty());
        // Progress, after the interval: judged again, still parked.
        let (ready, _) = parked.take_ready(t0 + PROGRESS_REJUDGE, &|_: &str| Some(7));
        assert_eq!(ready, vec!["skip"]);
        assert_eq!(parked.len(), 1);
        // Same tip again: not re-judged.
        assert!(parked
            .take_ready(t0 + PROGRESS_REJUDGE * 3, &|_: &str| Some(7))
            .0
            .is_empty());
        // Still expires from when it was FIRST parked.
        let (_, expired) = parked.take_ready(t0 + PARK_TTL, &|_: &str| Some(7));
        assert_eq!(expired, 1);
    }
}
