//! Startup repair of ledger JSONLs that skip sequences.
//!
//! Until the append cursor became a sequence (see `handler::compact_ledger`),
//! compaction could count updates as written that never were, and replicas'
//! JSONLs lost them: ref3's C (53330, 60353), ref2's F (100033 and
//! 121035-122035), ref2's A (97173), and more. A replica replayed across such a
//! hole folds into wrong balances, and judged the operator from them (ref3
//! disputed C over seq 67860, which it could not apply). The handler finds the
//! holes at load; here each one is fetched from the relay by sequence, checked
//! to chain exactly between its neighbours, written, and the ledger is rebuilt
//! from the whole file. A ledger left with holes stays marked damaged, and the
//! dispute paths do not judge it.

use super::*;

use crate::handler::{describe_gaps, SequenceGap};
use deposits_core::SignedLedgerUpdate;

/// Sequences asked for per relay query.
const GAP_FETCH_CHUNK: usize = 200;

/// The updates that fill `gap`, in order, if `candidates` hold a run that
/// chains from the update before it to the update after it, signed by the
/// operator of the update before it. The neighbours' hashes pin every link,
/// so nothing else fits.
pub(crate) fn fill_gap(
    gap: &SequenceGap,
    candidates: &[SignedLedgerUpdate],
) -> Option<Vec<SignedLedgerUpdate>> {
    // The relay can hold more than one update at a sequence (a member's
    // fork shares the tag); follow each that links, back out of dead ends.
    fn extend(
        gap: &SequenceGap,
        candidates: &[SignedLedgerUpdate],
        seq: u64,
        link: [u8; 32],
        run: &mut Vec<SignedLedgerUpdate>,
    ) -> bool {
        if seq > gap.last {
            return link == gap.before;
        }
        for u in candidates.iter().filter(|u| {
            u.sequence_number == seq && u.previous_hash == link && u.operator_id == gap.operator
        }) {
            run.push(u.clone());
            if extend(gap, candidates, seq + 1, u.chain_hash(), run) {
                return true;
            }
            run.pop();
        }
        false
    }
    let mut run = Vec::new();
    extend(gap, candidates, gap.first, gap.after, &mut run).then_some(run)
}

impl Node {
    /// Repair every damaged base ledger from the relay (see the module docs).
    /// Runs at startup, before any update is applied: the rebuild takes the
    /// file as the truth.
    pub(crate) async fn repair_damaged_ledgers(&self) {
        for (ledger_id, gaps) in self.handler.damaged_ledgers() {
            // A fork file copies its base's history; it is repaired with it
            // only by being recreated. Report it, leave it marked.
            if ledger_id.len() != 64 {
                tracing::warn!(
                    "Dispute fork {} holds the holes of its base ({}); not repaired",
                    &ledger_id[..32.min(ledger_id.len())],
                    describe_gaps(&gaps)
                );
                continue;
            }
            let candidates = self.fetch_updates_by_seq(&ledger_id, &gaps).await;
            let fills: Vec<SignedLedgerUpdate> = gaps
                .iter()
                .filter_map(|g| fill_gap(g, &candidates))
                .flatten()
                .collect();
            if fills.is_empty() {
                tracing::error!(
                    "Ledger {}: the relay has none of its missing updates ({}); replica \
                     left marked damaged, not judged, and needs a re-import",
                    &ledger_id[..16],
                    describe_gaps(&gaps)
                );
                continue;
            }
            match self.handler.repair_ledger_gaps(&ledger_id, &fills) {
                Ok(left) if left.is_empty() => tracing::warn!(
                    "Ledger {}: repaired {} missing update(s) ({}) from the relay and \
                     rebuilt its state",
                    &ledger_id[..16],
                    fills.len(),
                    describe_gaps(&gaps)
                ),
                Ok(left) => tracing::error!(
                    "Ledger {}: repaired {} update(s) from the relay; still missing {} \
                     — replica left marked damaged, not judged, and needs a re-import",
                    &ledger_id[..16],
                    fills.len(),
                    describe_gaps(&left)
                ),
                Err(e) => tracing::error!(
                    "Ledger {}: repair failed ({}); replica left marked damaged",
                    &ledger_id[..16],
                    e
                ),
            }
        }
    }

    /// The ledger's updates the relay holds at the sequences in `gaps`
    /// (queried by the `n` tag every update carries).
    async fn fetch_updates_by_seq(
        &self,
        ledger_id: &str,
        gaps: &[SequenceGap],
    ) -> Vec<SignedLedgerUpdate> {
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
        use deposits_core::TlvDecode;
        use nostr_sdk::{Filter, Kind};

        let Some(ledger_id_bytes) = hex::decode(ledger_id)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
        else {
            return Vec::new();
        };
        let seqs: Vec<String> = gaps
            .iter()
            .flat_map(|g| g.first..=g.last)
            .map(|s| s.to_string())
            .collect();
        let mut out = Vec::new();
        for chunk in seqs.chunks(GAP_FETCH_CHUNK) {
            let filter = Filter::new()
                .kind(Kind::Custom(crate::nostr::KIND_LEDGER_UPDATE))
                .custom_tag(
                    crate::nostr::TAG_LEDGER_ID,
                    [crate::nostr::ledger_tag(ledger_id)],
                )
                .custom_tag(crate::nostr::TAG_SEQUENCE, chunk.iter().cloned())
                .limit(chunk.len() * 4);
            let events = match self
                .nostr
                .fetch_client()
                .fetch_events(vec![filter], Some(std::time::Duration::from_secs(15)))
                .await
            {
                Ok(e) => e,
                Err(e) => {
                    tracing::warn!(
                        "Ledger {}: fetching missing updates: {}",
                        &ledger_id[..16],
                        e
                    );
                    continue;
                }
            };
            out.extend(
                events
                    .iter()
                    .filter_map(|e| BASE64.decode(&e.content).ok())
                    .filter_map(|tlv| SignedLedgerUpdate::tlv_decode(&tlv).ok())
                    .filter(|u| u.ledger_id == ledger_id_bytes),
            );
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::sequence_gaps;
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

    fn pk(seed: u8) -> PublicKey {
        PublicKey::from_secret_key(
            &Secp256k1::new(),
            &SecretKey::from_slice(&[seed; 32]).unwrap(),
        )
    }

    /// A chain 0..n linked on `chain_hash`, as the ledger links it.
    fn chain(n: u64, operator: PublicKey) -> Vec<SignedLedgerUpdate> {
        let mut out: Vec<SignedLedgerUpdate> = Vec::new();
        for seq in 0..n {
            let previous_hash = out.last().map_or([0u8; 32], |u| u.chain_hash());
            out.push(SignedLedgerUpdate {
                message: vec![seq as u8],
                message_type: 0x8001,
                operator_id: operator,
                ledger_id: [7u8; 32],
                sequence_number: seq,
                previous_hash,
                content_hash: [seq as u8; 32],
                block_height: 0,
                block_hash: [0u8; 32],
                cosign_signature: [0u8; 64],
                operator_signature: [seq as u8; 64],
                cosignatures: Vec::new(),
                cosigner_pubkey: None,
                member_ledger_hash: None,
            });
        }
        out
    }

    fn without(full: &[SignedLedgerUpdate], missing: &[u64]) -> Vec<SignedLedgerUpdate> {
        full.iter()
            .filter(|u| !missing.contains(&u.sequence_number))
            .cloned()
            .collect()
    }

    /// ref3's C in miniature: two single holes, and ref2's F: a run.
    #[test]
    fn finds_every_run_of_missing_sequences() {
        let full = chain(20, pk(1));
        let held = without(&full, &[3, 9, 10, 11]);
        let gaps = sequence_gaps(&held);
        assert_eq!(
            gaps.iter().map(|g| (g.first, g.last)).collect::<Vec<_>>(),
            vec![(3, 3), (9, 11)]
        );
        assert_eq!(gaps[0].after, full[2].chain_hash());
        assert_eq!(gaps[0].before, full[4].previous_hash);
        assert_eq!(gaps[1].operator, pk(1));
        assert_eq!(describe_gaps(&gaps), "3, 9-11");
        // A whole chain, and a fork file starting mid-chain, have none.
        assert!(sequence_gaps(&full).is_empty());
        assert!(sequence_gaps(&full[5..]).is_empty());
        assert!(sequence_gaps(&[]).is_empty());
    }

    #[test]
    fn fills_a_gap_only_with_the_run_that_chains_between_its_neighbours() {
        let operator = pk(1);
        let full = chain(20, operator);
        let held = without(&full, &[9, 10, 11]);
        let gap = &sequence_gaps(&held)[0];

        // The relay's copies (with noise: a fork's update at seq 10, and an
        // update from elsewhere in the chain) fill it exactly.
        let mut fork_update = full[10].clone();
        fork_update.operator_id = pk(2);
        let candidates = vec![
            full[12].clone(),
            fork_update,
            full[9].clone(),
            full[10].clone(),
            full[11].clone(),
        ];
        let run = fill_gap(gap, &candidates).expect("fills");
        assert_eq!(run, full[9..12].to_vec());

        // Missing one of the run: no fill.
        assert!(fill_gap(gap, &[full[9].clone(), full[11].clone()]).is_none());
        // A different update at a sequence (another branch) does not chain;
        // beside the real one, it is passed over.
        let mut forged = full[10].clone();
        forged.content_hash = [0xee; 32];
        assert!(fill_gap(gap, &[full[9].clone(), forged.clone(), full[11].clone()]).is_none());
        let both = [full[9].clone(), forged, full[10].clone(), full[11].clone()];
        assert_eq!(fill_gap(gap, &both).expect("fills"), full[9..12].to_vec());
        // Signed by someone other than the operator: no fill.
        let mut other = full.clone();
        for u in &mut other {
            u.operator_id = pk(3);
        }
        assert!(fill_gap(gap, &other[9..12]).is_none());
    }
}
