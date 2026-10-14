//! DEP-05 §Cosign rounds: an operator keeps the cosignatures it collects for one
//! `cosign_data` past the round's deadline. A member that answers late still lands
//! in the round, and a retry of the same update starts from what has arrived
//! instead of asking every member again from nothing.

use super::CosignCollector;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// DEP-05 `cosign_response_seconds`: the advisory time a member has to answer a
/// cosign request, and so the least an operator waits before calling a round short.
pub const COSIGN_RESPONSE_SECONDS: u64 = 30;

/// How long a round that fell short is kept for late answers and retries. A retry
/// of the same update signs the same `cosign_data` only within its block, so a
/// few blocks bound it.
pub const COSIGN_ROUND_KEEP: Duration = Duration::from_secs(30 * 60);

struct Round {
    started: Instant,
    collector: Arc<CosignCollector>,
    request_ids: Vec<String>,
}

#[derive(Default)]
pub struct CosignRounds {
    rounds: HashMap<[u8; 32], Round>,
}

impl CosignRounds {
    fn key(cosign_data: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        Sha256::digest(cosign_data).into()
    }

    fn prune(&mut self, now: Instant) {
        self.rounds
            .retain(|_, r| now.duration_since(r.started) < COSIGN_ROUND_KEEP);
    }

    /// The round for `cosign_data`: the one kept from an earlier attempt (its
    /// cosignatures carried over), or a fresh one.
    pub(super) fn begin(
        &mut self,
        cosign_data: &[u8],
        threshold: usize,
        now: Instant,
    ) -> Arc<CosignCollector> {
        self.prune(now);
        let key = Self::key(cosign_data);
        let round = self.rounds.entry(key).or_insert_with(|| Round {
            started: now,
            collector: Arc::new(CosignCollector::for_data(threshold, cosign_data.to_vec())),
            request_ids: Vec::new(),
        });
        if round.collector.threshold != threshold {
            // The requirement moved (another tier): same signatures, new target.
            let c = Arc::new(CosignCollector::for_data(threshold, cosign_data.to_vec()));
            for r in round.collector.results() {
                c.add(r);
            }
            round.collector = c;
        }
        round.collector.clone()
    }

    /// Route answers to REQUEST_ID into the round for `cosign_data`, after its deadline too.
    pub(super) fn attach(&mut self, cosign_data: &[u8], request_id: &str) {
        if let Some(r) = self.rounds.get_mut(&Self::key(cosign_data)) {
            r.request_ids.push(request_id.to_string());
        }
    }

    /// The collector a (possibly late) answer to REQUEST_ID belongs to.
    pub(super) fn collector_for(&self, request_id: &str) -> Option<Arc<CosignCollector>> {
        self.rounds
            .values()
            .find(|r| r.request_ids.iter().any(|id| id == request_id))
            .map(|r| r.collector.clone())
    }

    /// The round reached its threshold and the update is built: nothing more to keep.
    pub(super) fn finish(&mut self, cosign_data: &[u8]) {
        self.rounds.remove(&Self::key(cosign_data));
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.rounds.len()
    }
}

#[cfg(test)]
mod tests {
    use super::super::CoSignResult;
    use super::*;
    use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};

    fn answer(seed: u8, data: &[u8]) -> CoSignResult {
        let secp = Secp256k1::new();
        let kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[seed; 32]).unwrap());
        let mlh = [seed; 32];
        let digest = deposits_core::SignedLedgerUpdate::cosign_digest_for_data(data, &mlh);
        CoSignResult {
            cosign_signature: *secp
                .sign_schnorr_no_aux_rand(&Message::from_digest(digest), &kp)
                .as_ref(),
            cosigner_pubkey: kp.public_key(),
            member_ledger_hash: mlh,
            t1_recv_us: None,
            t2_send_us: None,
        }
    }

    #[test]
    fn a_late_answer_lands_and_the_retry_reuses_it() {
        let (data, now) = (b"cosign data".to_vec(), Instant::now());
        let mut rounds = CosignRounds::default();
        let c = rounds.begin(&data, 2, now);
        rounds.attach(&data, "req-1");
        c.add(answer(1, &data));
        // The deadline passes short (1 of 2); member 2 answers req-1 afterwards.
        rounds
            .collector_for("req-1")
            .expect("a round kept past its deadline")
            .add(answer(2, &data));
        // The retry of the same update starts with both.
        let retry = rounds.begin(&data, 2, now + Duration::from_secs(40));
        assert_eq!(retry.count(), 2);
        rounds.finish(&data);
        assert_eq!(rounds.len(), 0);
    }

    #[test]
    fn only_valid_signatures_over_this_data_are_kept() {
        let (data, now) = (b"cosign data".to_vec(), Instant::now());
        let mut rounds = CosignRounds::default();
        let c = rounds.begin(&data, 2, now);
        assert!(
            !c.add(answer(1, b"another update")),
            "signed something else"
        );
        let mut forged = answer(2, &data);
        forged.cosign_signature[0] ^= 1;
        c.add(forged);
        assert_eq!(c.count(), 0);
        // The member's valid signature is not shadowed by its bad one.
        c.add(answer(2, &data));
        assert_eq!(c.count(), 1);
    }

    #[test]
    fn another_update_is_another_round_and_old_rounds_expire() {
        let now = Instant::now();
        let mut rounds = CosignRounds::default();
        let a = rounds.begin(b"update a", 2, now);
        a.add(answer(1, b"update a"));
        assert_eq!(rounds.begin(b"update b", 2, now).count(), 0);
        assert_eq!(
            rounds.begin(b"update a", 3, now).count(),
            1,
            "a tier change keeps them"
        );
        rounds.begin(b"update c", 2, now + COSIGN_ROUND_KEEP);
        assert_eq!(rounds.len(), 1);
    }
}
