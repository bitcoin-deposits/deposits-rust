//! Ledger healing — re-publish locally-held update chains that the relay has
//! dropped from its retention window.
//!
//! ## Why this exists
//!
//! The durable ledger-update events (kind 9100) form append-only per-ledger
//! chains on the relay. A public strfry relay expires old events out of its
//! retention window: our events carry no NIP-40 `expiration` tag, so this is
//! purely server-side retention, not self-expiry. Observed live: a relay that
//! held 4 ledgers / ~16.7k update events aged down to 507 events / 1 ledger
//! within days. Once a ledger's chain ages out:
//!   - a depositor can no longer reconstruct / `open` the ledger (the chain,
//!     including the seq-0 `LedgerOpen`, is gone), and
//!   - a disputed ledger can't be recovered (its `QuorumBegin` is gone).
//!
//! The daemons still hold the FULL chain locally (funds are safe), so the fix
//! is for each daemon to periodically re-publish any locally-held update that
//! is missing from the relay, keeping the on-relay chain backfilled regardless
//! of retention.
//!
//! ## Design
//!
//! * **Scope — owner heals owned.** We heal only ledgers this daemon OWNS
//!   (`operator_key == self.node_id`). The owner is the party responsible for
//!   its ledger's durability, and owner-heal is exactly what re-lands a
//!   disputed ledger's `QuorumBegin`. We deliberately do NOT heal *joined*
//!   ledgers: N members each re-publishing the same missing event with a fresh
//!   `created_at` would mint N distinct event ids (the relay dedups by id, so a
//!   new timestamp = new id = a genuine duplicate), fanning N copies of the
//!   chain onto the relay. Since every ledger has exactly one owner, owner-heal
//!   gives single-writer, duplicate-free durability. (See the module-level
//!   note in the report for the residual member-heal risk.)
//!
//! * **Diff by `content_hash`.** Fork updates share `sequence_number`, so the
//!   relay-present set and the local history are compared by `content_hash`,
//!   which is unique per update body. [`missing_updates`] is the pure core.
//!
//! * **Fresh `created_at`.** Re-publishing re-wraps the SAME
//!   `SignedLedgerUpdate` (no new consensus state, no new signatures) with a
//!   fresh `created_at`, refreshing the event back into the retention window.
//!   Reconstruction sorts by `sequence_number` in the TLV, not `created_at`, so
//!   a new timestamp is safe. (A pinned old timestamp would just age straight
//!   back out — the opposite of what healing needs.)
//!
//! * **Batched + throttled.** A healthy ledger has few (usually zero) missing
//!   updates; a post-wipe ledger can have thousands. We publish at most
//!   [`HEAL_BATCH_LIMIT`] updates per ledger per pass (oldest first, so the
//!   chain re-lands root → tip and a partway-through pass still lets a
//!   depositor make progress), and log how many were healed. The next pass
//!   picks up the remainder. This bounds relay load per interval.

use super::*;

/// Max updates re-published per owned ledger per heal pass. A wiped deep ledger
/// (~12k updates observed) heals over several passes rather than in one storm.
pub(crate) const HEAL_BATCH_LIMIT: usize = 500;

/// Pure diff: given the `content_hash`es the relay currently holds and the
/// daemon's local history (in sequence order), return references to the local
/// updates that are NOT on the relay, oldest-first, capped at `batch_limit`.
///
/// This is the whole correctness-critical core of healing, factored out so it
/// can be unit-tested without a live relay or `Node`. Safety invariant: the
/// result is always a subset of `local_history`, so a caller that only ever
/// feeds validated, locally-persisted updates can never publish anything it
/// doesn't already hold.
pub(crate) fn missing_updates<'a>(
    relay_present: &std::collections::HashSet<[u8; 32]>,
    local_history: &'a [deposits_core::types::SignedLedgerUpdate],
    batch_limit: usize,
) -> Vec<&'a deposits_core::types::SignedLedgerUpdate> {
    local_history
        .iter()
        .filter(|u| !relay_present.contains(&u.content_hash))
        .take(batch_limit)
        .collect()
}

impl Node {
    /// Heal every owned ledger's on-relay chain: fetch what the relay currently
    /// holds, diff against local history, and re-publish the missing updates.
    ///
    /// Cheap in steady state (a healthy ledger diffs to empty and publishes
    /// nothing); bounded after a relay wipe by [`HEAL_BATCH_LIMIT`] per ledger.
    pub(crate) async fn auto_heal_ledgers(self: &Arc<Self>) {
        // Snapshot the set of owned ledger ids without holding the lock across
        // the (awaiting) relay fetches below.
        let owned: Vec<String> = {
            let ledgers = match self.handler.ledgers.try_lock() {
                Ok(l) => l,
                Err(_) => {
                    tracing::warn!(
                        "auto_heal_ledgers: ledgers lock contended, skipping this cycle"
                    );
                    return;
                }
            };
            ledgers
                .iter()
                .filter(|(_, a)| a.read().unwrap().operator_key() == self.node_id)
                .map(|(k, _)| k.clone())
                .collect()
        };

        tracing::debug!("heal: pass over {} owned ledger(s)", owned.len());
        for lid in owned {
            match self.heal_owned_ledger(&lid).await {
                Ok(n) if n > 0 => tracing::info!(
                    "heal: owned ledger {}… re-published {} update(s) missing from relay",
                    &lid[..16.min(lid.len())],
                    n
                ),
                Ok(_) => {}
                Err(e) => tracing::warn!(
                    "heal: owned ledger {}… failed: {}",
                    &lid[..16.min(lid.len())],
                    e
                ),
            }
        }
    }

    /// Heal a single owned ledger. Returns the number of updates re-published
    /// this pass (0 if the relay already holds the full chain, or if the ledger
    /// is not owned / not present locally).
    pub(crate) async fn heal_owned_ledger(
        self: &Arc<Self>,
        ledger_id: &str,
    ) -> Result<usize, Error> {
        // Own-ledger guard: healing re-lands OUR authored chain. Joined ledgers
        // are intentionally skipped (see module docs) to avoid duplicate fan-out.
        let is_own = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            ledgers
                .get(ledger_id)
                .map(|arc| arc.read().unwrap().operator_key() == self.node_id)
                .unwrap_or(false)
        };
        if !is_own {
            return Ok(0);
        }

        // What does the relay currently hold for this ledger? Pages the FULL
        // chain backward (as of 62d78bcf) so we don't mistake a paged-out tail
        // for "missing" and re-publish the whole chain every pass.
        let relay_updates = self.fetch_all_ledger_updates_paginated(ledger_id).await;
        let relay_present: std::collections::HashSet<[u8; 32]> =
            relay_updates.iter().map(|u| u.content_hash).collect();

        // Source the local history from the FULL persisted JSONL on disk, NOT
        // the in-memory `Ledger::history` (which is truncated to the most recent
        // HISTORY_RETAIN entries — a RAM optimization). A deep ledger's genesis
        // `LedgerOpen` (seq 0) and early `QuorumBegin` live only on disk once
        // the chain grows past the retain window; healing must re-publish that
        // old span or a depositor can never reconstruct/`open` from genesis and
        // a disputed deep ledger can't recover (its QuorumBegin derives N=Q).
        //
        // Fall back to the in-memory history only if the JSONL is missing or
        // unreadable. Reading from our own persisted log preserves the safety
        // invariant: we only ever re-publish updates we hold AND have persisted
        // (validated) — never anything fabricated.
        let disk_history = self.handler.read_persisted_history(ledger_id);
        let history_source = if disk_history.is_some() {
            "disk"
        } else {
            "memory"
        };

        // Clone the missing subset out while holding the read lock (for the
        // in-memory fallback), then release it before awaiting the broadcasts.
        let (local_len, to_publish): (usize, Vec<deposits_core::types::SignedLedgerUpdate>) =
            match &disk_history {
                Some(history) => (
                    history.len(),
                    missing_updates(&relay_present, history, HEAL_BATCH_LIMIT)
                        .into_iter()
                        .cloned()
                        .collect(),
                ),
                None => {
                    let ledgers = self.handler.ledgers.lock().unwrap();
                    let arc = match ledgers.get(ledger_id) {
                        Some(a) => a,
                        None => return Ok(0),
                    };
                    let ledger = arc.read().unwrap();
                    (
                        ledger.history.len(),
                        missing_updates(&relay_present, &ledger.history, HEAL_BATCH_LIMIT)
                            .into_iter()
                            .cloned()
                            .collect(),
                    )
                }
            };

        tracing::debug!(
            "heal: ledger {}… relay_present={} local_history={} (source={})",
            &ledger_id[..16.min(ledger_id.len())],
            relay_present.len(),
            local_len,
            history_source,
        );

        if to_publish.is_empty() {
            return Ok(0);
        }

        // How much of the chain is still missing beyond this capped pass, so a
        // deep ledger's multi-pass progress is visible in the logs.
        let total_missing = local_len.saturating_sub(relay_present.len());
        let remaining_after = total_missing.saturating_sub(to_publish.len());
        tracing::info!(
            "heal: ledger {}… relay holds {} of {} update(s) (source={}); \
             re-publishing {} missing this pass (oldest-first, cap {}); {} remaining after",
            &ledger_id[..16.min(ledger_id.len())],
            relay_present.len(),
            local_len,
            history_source,
            to_publish.len(),
            HEAL_BATCH_LIMIT,
            remaining_after,
        );

        // Re-publish oldest-first with a FRESH created_at (None) so the events
        // land back inside the relay's retention window. Reuse the node's own
        // publish path — no hand-rolled event. We do NOT record_created_at here:
        // healing must not overwrite the ledger's pinned genesis timestamp, and
        // the fresh timestamp is intentionally ephemeral (it only needs to be
        // "recent enough" for the relay to keep it around until the next heal).
        let mut healed = 0usize;
        for update in &to_publish {
            match self.nostr.broadcast_ledger_update_at(update, None).await {
                Ok(_) => {
                    healed += 1;
                    // Yield between publishes so a large batch never starves the
                    // runtime, and give the relay a moment to ingest.
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
                Err(e) => {
                    tracing::warn!(
                        "heal: ledger {}… re-publish of seq={} failed: {}",
                        &ledger_id[..16.min(ledger_id.len())],
                        update.sequence_number,
                        e
                    );
                }
            }
        }

        Ok(healed)
    }
}

#[cfg(test)]
mod tests {
    use super::missing_updates;
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
    use deposits_core::types::SignedLedgerUpdate;
    use std::collections::HashSet;

    fn test_pubkey() -> PublicKey {
        let secp = Secp256k1::new();
        PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[1u8; 32]).unwrap())
    }

    // Build a placeholder update carrying a distinct content_hash + seq.
    // seq and content_hash are set independently so tests can exercise
    // fork siblings (same seq, different content_hash).
    fn upd(seq: u64, hash_byte: u8) -> SignedLedgerUpdate {
        SignedLedgerUpdate {
            message: vec![hash_byte],
            message_type: 0x0001,
            operator_id: test_pubkey(),
            ledger_id: [0u8; 32],
            sequence_number: seq,
            previous_hash: [0u8; 32],
            content_hash: [hash_byte; 32],
            block_height: 100 + seq as u32,
            block_hash: [0u8; 32],
            cosign_signature: [0u8; 64],
            operator_signature: [0u8; 64],
            cosigner_pubkey: None,
            member_ledger_hash: None,
            cosignatures: Vec::new(),
        }
    }

    fn present(bytes: &[u8]) -> HashSet<[u8; 32]> {
        bytes.iter().map(|b| [*b; 32]).collect()
    }

    #[test]
    fn empty_relay_yields_full_history_up_to_batch_limit() {
        // Post-wipe: relay holds nothing, so every local update is missing.
        let history: Vec<_> = (0..5).map(|i| upd(i, i as u8)).collect();
        let relay = present(&[]);
        let missing = missing_updates(&relay, &history, 500);
        assert_eq!(missing.len(), 5);
        // Oldest-first ordering preserved (chain re-lands root → tip).
        let seqs: Vec<u64> = missing.iter().map(|u| u.sequence_number).collect();
        assert_eq!(seqs, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn healthy_ledger_diffs_to_empty() {
        // Steady state: relay already holds the whole chain → nothing to heal.
        let history: Vec<_> = (0..4).map(|i| upd(i, i as u8)).collect();
        let relay = present(&[0, 1, 2, 3]);
        assert!(missing_updates(&relay, &history, 500).is_empty());
    }

    #[test]
    fn partial_relay_yields_only_the_gap() {
        // Relay has the head + tail but dropped a middle span; heal fills the gap.
        let history: Vec<_> = (0..6).map(|i| upd(i, i as u8)).collect();
        let relay = present(&[0, 1, 4, 5]); // missing content_hash 2 and 3
        let missing = missing_updates(&relay, &history, 500);
        let hashes: Vec<u8> = missing.iter().map(|u| u.content_hash[0]).collect();
        assert_eq!(hashes, vec![2, 3]);
    }

    #[test]
    fn diff_is_by_content_hash_not_sequence_number() {
        // Fork updates share a sequence_number; the diff must key on
        // content_hash so a fork sibling the relay lacks still gets healed.
        let a = upd(3, 0xAA); // seq 3, hash AA — present on relay
        let b = upd(3, 0xBB); // seq 3, hash BB — fork sibling, NOT on relay
        let history = vec![a, b];
        let relay = present(&[0xAA]);
        let missing = missing_updates(&relay, &history, 500);
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].content_hash[0], 0xBB);
    }

    #[test]
    fn batch_limit_caps_and_preserves_oldest_first() {
        // A deep wiped ledger heals in bounded passes; this pass takes the
        // oldest `limit` updates, leaving the rest for the next interval.
        let history: Vec<_> = (0..10).map(|i| upd(i, i as u8)).collect();
        let relay = present(&[]);
        let missing = missing_updates(&relay, &history, 3);
        let seqs: Vec<u64> = missing.iter().map(|u| u.sequence_number).collect();
        assert_eq!(
            seqs,
            vec![0, 1, 2],
            "batch takes the oldest `limit`, oldest-first"
        );
    }
}
