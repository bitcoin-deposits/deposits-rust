//! Custody lottery claims (DEP-06 Phase 4).
//!
//! Every participant revealed: the winner claims through the full-set leaf.
//! Past the reveal deadline (`LOTTERY_REVEAL_CSV_BLOCKS` after the
//! confiscation) with some missing: the winner over the revealers R claims
//! through R's subset leaf, which needs the recovery voters' attestation
//! (`lottery_subset_attest`). A voter signs only for exactly the reveals it
//! holds, and only a claim paying R's winner. Nobody revealing sends the
//! output to a re-arm round (not yet orchestrated); no recovery spend to the
//! accused operator is ever built or signed.

use super::dispute::recovery_voters_from_updates;
use super::*;

use bitcoin::secp256k1::XOnlyPublicKey;
use bitcoin::{OutPoint, Transaction, TxOut};
use deposits_core::tapscript_reserves::{
    LotteryOutput, LotteryParticipant, LotteryScriptBuilder, LOTTERY_MAX_PREIMAGE_LEN,
    LOTTERY_REVEAL_CSV_BLOCKS,
};

/// Seconds a `lottery_subset_attest` request is waited on before it is
/// re-sent (as `collect_confiscation_signatures`).
const LOTTERY_ATTEST_REQUEST_TIMEOUT_SECS: u64 = 120;

/// How a lottery can be claimed now, from the preimages revealed so far.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LotteryClaimPath {
    /// Every participant revealed: the full-set leaf, preimages in order.
    Full(Vec<Vec<u8>>),
    /// Past the reveal deadline with some missing: the subset leaf of the
    /// revealers (ascending indices) and their preimages.
    Subset(Vec<usize>, Vec<Vec<u8>>),
    /// Not yet: waiting for reveals or the deadline, or nobody revealed.
    Wait(String),
}

type Participant = (bitcoin::secp256k1::PublicKey, LotteryParticipant);

/// The subset of `candidates` (trying `current` first) whose lottery output is
/// `spk`, sorted canonically; `None` if none is. At most 8 candidates (255 subsets).
pub(crate) fn match_landed_set(
    spk: &bitcoin::ScriptBuf,
    current: &[Participant],
    candidates: &[Participant],
    voters: &[XOnlyPublicKey],
    threshold: usize,
    network: bitcoin::Network,
) -> Option<Vec<Participant>> {
    let pays = |set: &[Participant]| {
        let mut sorted = set.to_vec();
        sorted.sort_by_key(|(_, p)| p.pubkey.serialize());
        LotteryScriptBuilder::new(
            sorted.iter().map(|(_, p)| p.clone()).collect(),
            voters.to_vec(),
            threshold,
            network,
        )
        .build()
        .ok()
        .filter(|l| &l.script_pubkey() == spk)
        .map(|_| sorted)
    };
    if let Some(s) = pays(current) {
        return Some(s);
    }
    let n = candidates.len();
    if n == 0 || n > 8 {
        return None;
    }
    (1u32..(1 << n)).rev().find_map(|mask| {
        let subset: Vec<_> = (0..n)
            .filter(|i| mask & (1 << i) != 0)
            .map(|i| candidates[i].clone())
            .collect();
        pays(&subset)
    })
}

/// `preimages` parallel the participants (`None` where unrevealed). A
/// preimage outside 17..=76 bytes cannot satisfy any leaf and counts as
/// unrevealed.
pub(crate) fn lottery_claim_path(
    preimages: &[Option<Vec<u8>>],
    deadline_passed: bool,
) -> LotteryClaimPath {
    let valid: Vec<(usize, Vec<u8>)> = preimages
        .iter()
        .enumerate()
        .filter_map(|(i, p)| {
            p.as_ref()
                .filter(|p| (17..=LOTTERY_MAX_PREIMAGE_LEN).contains(&p.len()))
                .map(|p| (i, p.clone()))
        })
        .collect();
    let k = preimages.len();
    if k == 1 || valid.len() == k {
        return LotteryClaimPath::Full(valid.into_iter().map(|(_, p)| p).collect());
    }
    if !deadline_passed {
        return LotteryClaimPath::Wait(format!(
            "{} of {} revealed; the reveal deadline is {} blocks after the confiscation",
            valid.len(),
            k,
            LOTTERY_REVEAL_CSV_BLOCKS
        ));
    }
    if valid.is_empty() {
        return LotteryClaimPath::Wait(
            "nobody revealed: the output waits for a re-arm round".to_string(),
        );
    }
    let (idx, pre) = valid.into_iter().unzip();
    LotteryClaimPath::Subset(idx, pre)
}

/// Parse a proposed unsigned tx. cl-deposits serializes its unsigned txs
/// in the segwit form with an empty witness (marker, flag, a zero-length
/// stack per input), which rust-bitcoin's decoder rejects ("witness flag
/// set but no witnesses present"); accept that form as well as the
/// legacy one.
pub(crate) fn parse_unsigned_tx(bytes: &[u8]) -> Result<Transaction, String> {
    use bitcoin::consensus::Decodable;

    if let Ok(tx) = bitcoin::consensus::encode::deserialize::<Transaction>(bytes) {
        return Ok(tx);
    }
    if bytes.len() < 6 || bytes[4] != 0 || bytes[5] != 1 {
        return Err("unsigned_tx does not parse".to_string());
    }
    let mut r = bytes;
    let version = bitcoin::transaction::Version::consensus_decode(&mut r)
        .map_err(|e| format!("unsigned_tx version: {}", e))?;
    r = &r[2..]; // marker, flag
    let mut input = Vec::<bitcoin::TxIn>::consensus_decode(&mut r)
        .map_err(|e| format!("unsigned_tx inputs: {}", e))?;
    let output = Vec::<TxOut>::consensus_decode(&mut r)
        .map_err(|e| format!("unsigned_tx outputs: {}", e))?;
    for txin in input.iter_mut() {
        txin.witness = bitcoin::Witness::consensus_decode(&mut r)
            .map_err(|e| format!("unsigned_tx witness: {}", e))?;
    }
    let lock_time = bitcoin::absolute::LockTime::consensus_decode(&mut r)
        .map_err(|e| format!("unsigned_tx locktime: {}", e))?;
    if !r.is_empty() {
        return Err("unsigned_tx has trailing bytes".to_string());
    }
    Ok(Transaction {
        version,
        lock_time,
        input,
        output,
    })
}

/// Operation discriminants (`t` tag) a lottery is rebuilt from: LedgerOpen,
/// QuorumBegin, DisputeArmed.
/// LedgerOpen, QuorumBegin, QuorumUpgrade, DisputeEnter, DisputeArmed. The DisputeEnters and the
/// ruleset ops are what the recovery voters and the cut are judged from: without them the ruleset at
/// the fork point read as none, so under strict-lottery-v8 the voters kept the accused and the
/// derived lottery was not the one cl paid (751e6951's ref6, signet soak Nov 7..10).
pub(crate) const LOTTERY_OP_TYPES: [u8; 5] = [1, 12, 45, 54, 57];

/// The `last_valid_sequence` of each DisputeEnter in `updates` whose update is not among them.
pub(crate) fn missing_fork_points(updates: &[deposits_core::SignedLedgerUpdate]) -> Vec<u64> {
    use deposits_core::messages::LedgerOperation;
    use deposits_core::tlv::TlvDecode;
    let mut out: Vec<u64> = updates
        .iter()
        .filter_map(|u| match LedgerOperation::tlv_decode(&u.message) {
            Ok(LedgerOperation::DisputeEnter {
                last_valid_sequence,
                ..
            }) => Some(last_valid_sequence),
            _ => None,
        })
        .filter(|s| !updates.iter().any(|u| u.sequence_number == *s))
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// Whether `updates` hold what a lottery is rebuilt from: the LedgerOpen,
/// a QuorumBegin, a DisputeEnter and at least one DisputeArmed. A `t`-filtered fetch that
/// misses any of them (an update published without the tag) falls back to
/// the whole chain.
pub(crate) fn lottery_updates_complete(updates: &[deposits_core::SignedLedgerUpdate]) -> bool {
    use deposits_core::messages::LedgerOperation;
    let (mut open, mut qb, mut entered, mut armed) = (false, false, false, false);
    for u in updates {
        match LedgerOperation::tlv_decode(&u.message) {
            Ok(LedgerOperation::LedgerOpen { .. }) => open = true,
            Ok(LedgerOperation::QuorumBegin { .. }) => qb = true,
            Ok(LedgerOperation::DisputeEnter { .. }) => entered = true,
            Ok(LedgerOperation::DisputeArmed { .. }) => armed = true,
            _ => {}
        }
    }
    open && qb && entered && armed
}

/// For each participant, the revealed preimage whose HASH160 is its
/// commitment, if any.
pub(crate) fn match_revealed_preimages(
    participants: &[(bitcoin::secp256k1::PublicKey, LotteryParticipant)],
    revealed: &[Vec<u8>],
) -> Vec<Option<Vec<u8>>> {
    use bitcoin::hashes::{hash160, Hash as _};
    participants
        .iter()
        .map(|(_, p)| {
            revealed
                .iter()
                .find(|r| hash160::Hash::hash(r).to_byte_array() == p.commitment_hash)
                .cloned()
        })
        .collect()
}

/// The preimage of a `lottery_reveal` request's JSON params or content.
pub(crate) fn reveal_request_preimage(params: &serde_json::Value) -> Option<Vec<u8>> {
    params
        .get("preimage")?
        .as_str()
        .and_then(|h| hex::decode(h).ok())
}

/// The public state of a dispute's lottery, rebuilt from the relay.
pub(crate) struct LotteryContext {
    /// DisputeArmed participants, one per armer, sorted by x-only key (the
    /// order the claim leaf and `initiate_confiscations` use).
    pub participants: Vec<(bitcoin::secp256k1::PublicKey, LotteryParticipant)>,
    /// Revealed preimage per participant (matched by commitment hash),
    /// `None` where it has not revealed yet.
    pub preimages: Vec<Option<Vec<u8>>>,
    /// Latest QuorumBegin minus the operator: what the lottery committed to.
    pub recovery_voters: Vec<XOnlyPublicKey>,
    pub recovery_threshold: usize,
    /// Our own DisputeArmed, if we armed.
    pub our_armed: Option<deposits_core::SignedLedgerUpdate>,
    /// Round 1's lottery output, once the confiscation landed: output 0 of the transaction
    /// that spent the vault. The lottery is found at THIS outpoint, never by its script: two
    /// disputes with one sole armer and one quorum pay the same script (regtest 2026-11-20).
    pub landed: Option<OutPoint>,
}

impl LotteryContext {
    pub(crate) fn build_lottery(&self, network: bitcoin::Network) -> Result<LotteryOutput, Error> {
        LotteryScriptBuilder::new(
            self.participants.iter().map(|(_, p)| p.clone()).collect(),
            self.recovery_voters.clone(),
            self.recovery_threshold,
            network,
        )
        .build()
        .map_err(|e| Error::Protocol(format!("Failed to build lottery output: {:?}", e)))
    }
}

/// A `lottery_subset_attest` request awaiting voter signatures.
pub(crate) struct PendingSubsetClaim {
    request_id: String,
    /// Sighash the request is for; a rebuilt claim that differs drops it.
    sighash: [u8; 32],
    signatures: HashMap<XOnlyPublicKey, [u8; 64]>,
    created_at: std::time::Instant,
}

impl Node {
    /// Rebuild a dispute's lottery state from the relay: participants,
    /// preimages revealed so far, and the recovery-voter set.
    pub(crate) async fn lottery_context(&self, ledger_id: &str) -> Result<LotteryContext, Error> {
        use bitcoin::hashes::{hash160, Hash as _};
        use deposits_core::messages::LedgerOperation;
        use nostr_sdk::{Filter, Kind, TagKind};

        // Only the operations the lottery is built from (LedgerOpen,
        // QuorumBegin, DisputeArmed): a handful of events, not a deep
        // ledger's whole chain inside the claim task's 10 s periodic.
        let pfx = &ledger_id[..16.min(ledger_id.len())];
        let t0 = std::time::Instant::now();
        let slow = |phase: &str, t: std::time::Instant| {
            let ms = t.elapsed().as_millis();
            if ms >= 1000 {
                tracing::warn!("lottery {}: {} took {} ms", pfx, phase, ms);
            }
        };
        let updates = self.fetch_lottery_updates(ledger_id).await;
        slow("fetch_lottery_updates", t0);
        // DEP-03 §"The dispute": the arms, manifests and voters of the CURRENT dispute only. A
        // stale DisputeEnter (a yielded dispute of a vault since rotated) is no part of it; read
        // over every DisputeEnter it took the voters to the old QuorumBegin (regtest 8082521c,
        // 34651658, 12bc96d2: "no unspent output pays our participant set"). Vector
        // rearm_round_agree.json.
        // DEP-03 §When the set is final: nor a DisputeEnter signed above the confiscation's block.
        let confiscated_at = confiscation_height(&*self.wallet.chain_backend(), &updates);
        let updates = deposits_core::rotation_order::dispute_scope_final(&updates, confiscated_at);

        let mut our_armed = None;
        let mut has_ledger_open = false;
        for update in &updates {
            match LedgerOperation::tlv_decode(&update.message) {
                Ok(LedgerOperation::LedgerOpen { .. }) => has_ledger_open = true,
                Ok(LedgerOperation::DisputeArmed { .. }) if update.operator_id == self.node_id => {
                    our_armed = Some(update.clone());
                }
                _ => {}
            }
        }
        // Participants: the DEP-03 eligibility cut, one per armer, sorted. A late arm
        // at or below E changes the cut without moving E, so once a confiscation has
        // landed its set is final: the one its lottery output commits to (DEP-03
        // §"Replacement collateral declaration"), whatever our view says now.
        let t1 = std::time::Instant::now();
        let set = self
            .lottery_armer_set(ledger_id)
            .await
            .map_err(Error::Protocol)?;
        slow("lottery_armer_set", t1);
        let t1 = std::time::Instant::now();
        let mut participants: Vec<(bitcoin::secp256k1::PublicKey, LotteryParticipant)> = set
            .participants
            .iter()
            .map(|a| (a.key, a.participant.clone()))
            .collect();
        if let Some((voters, threshold)) = Box::pin(self.lottery_voters(&updates)).await {
            let candidates: Vec<(bitcoin::secp256k1::PublicKey, LotteryParticipant)> = set
                .participants
                .iter()
                .chain(set.excluded.iter().map(|(a, _)| a))
                .map(|a| (a.key, a.participant.clone()))
                .collect();
            // DEP-03 §Arm manifests: the published arm sets first (a backdated arm or a ninth
            // armer cannot hide the landed set), then our cut, then the subsets of every arm.
            let manifests: Vec<Vec<(bitcoin::secp256k1::PublicKey, LotteryParticipant)>> = self
                .arm_manifests(ledger_id, 1)
                .await
                .iter()
                .filter_map(|m| {
                    super::armers::collect_manifest_armers(&updates, m, 1, -1, u32::MAX).ok()
                })
                .map(|v| v.into_iter().map(|a| (a.key, a.participant)).collect())
                .collect();
            if let Some(landed) = manifests
                .iter()
                .find_map(|named| {
                    self.landed_lottery_set(
                        &updates,
                        named,
                        &[],
                        &voters,
                        threshold,
                        super::armers::first_arm_height(&updates).unwrap_or(set.snapshot),
                    )
                })
                .or_else(|| {
                    self.landed_lottery_set(
                        &updates,
                        &participants,
                        &candidates,
                        &voters,
                        threshold,
                        super::armers::first_arm_height(&updates).unwrap_or(set.snapshot),
                    )
                })
            {
                participants = landed;
            }
        }
        if participants.is_empty() {
            return Err(Error::Protocol(
                "No DisputeArmed participants found".to_string(),
            ));
        }

        // Preimages are matched to participants by HASH160(preimage) ==
        // commitment_hash, NOT by who published them: the reveal is authored
        // by the node's Nostr/delegate key, not the participant's operator
        // key committed in DisputeArmed. The commitment hash is the
        // authorless, cryptographically-bound link, so a preimage from any
        // source can be trusted once it matches.
        slow("landed_lottery_set", t1);
        let t2 = std::time::Instant::now();
        let revealed = self.revealed_lottery_preimages(ledger_id, &updates).await;
        slow("revealed_lottery_preimages", t2);
        let preimages = match_revealed_preimages(&participants, &revealed);

        // Recovery voters MUST come from the latest QuorumBegin (minus
        // operator): the set the confiscation's lottery output commits to.
        let (recovery_voters, recovery_threshold) = Box::pin(self.lottery_voters(&updates))
            .await
            .ok_or_else(|| {
            Error::Protocol("No QuorumBegin/LedgerOpen found to derive recovery voters".to_string())
        })?;
        if !has_ledger_open {
            return Err(Error::Protocol("No LedgerOpen found".to_string()));
        }

        let landed = landed_lottery_outpoint(&*self.wallet.chain_backend(), &updates);
        Ok(LotteryContext {
            participants,
            preimages,
            recovery_voters,
            recovery_threshold,
            our_armed,
            landed,
        })
    }

    /// The lottery's updates from the relay: `t`-filtered to
    /// [`LOTTERY_OP_TYPES`], the whole chain only when that comes back
    /// incomplete.
    pub(crate) async fn fetch_lottery_updates(
        &self,
        ledger_id: &str,
    ) -> Vec<deposits_core::SignedLedgerUpdate> {
        let updates = self
            .fetch_ledger_updates_paginated_filtered(ledger_id, &LOTTERY_OP_TYPES)
            .await;
        if lottery_updates_complete(&updates) {
            // The grounds of a DisputeEnter are judged against the operator of the update at
            // its `last_valid_sequence` (`dispute_enter_grounds`), which no op-type tag
            // selects: without it every punitive DisputeEnter read as "its proof does not
            // accuse the operator at its fork point", nothing was accused, and under
            // strict-lottery-v8 the voters kept the accused (rearm-mixed, 2026-11-14).
            let missing = missing_fork_points(&updates);
            if missing.is_empty() {
                return updates;
            }
            if let Some(found) = self.local_updates_at(ledger_id, &missing) {
                let mut updates = updates;
                updates.extend(found);
                updates.sort_by_key(|u| u.sequence_number);
                return updates;
            }
        }
        tracing::debug!(
            "Lottery ops for {} incomplete by op-type tag ({} found); fetching the whole chain",
            &ledger_id[..16.min(ledger_id.len())],
            updates.len()
        );
        self.fetch_all_ledger_updates_paginated(ledger_id).await
    }

    /// The base ledger's updates at `seqs`, from the ledger we hold (its in-memory history,
    /// then the disk log); `None` unless every one is found.
    pub(crate) fn local_updates_at(
        &self,
        ledger_id: &str,
        seqs: &[u64],
    ) -> Option<Vec<deposits_core::SignedLedgerUpdate>> {
        let history = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let l = ledgers.get(ledger_id)?.read().unwrap();
            l.history.clone()
        };
        let pick = |h: &[deposits_core::SignedLedgerUpdate]| -> Option<Vec<_>> {
            seqs.iter()
                .map(|s| h.iter().find(|u| u.sequence_number == *s).cloned())
                .collect()
        };
        pick(&history).or_else(|| pick(&self.handler.complete_history(ledger_id, history)))
    }

    /// Every preimage revealed for `ledger_id` that we can get at. The
    /// `lottery_reveal` request is kind 20101, an ephemeral kind the relay
    /// does not store, so fetching it back (the only source this used to
    /// read) finds nothing unless the relay happens to keep ephemerals; on
    /// the signet devnet it found nothing, and the winner never claimed.
    /// So also: the durable Kind 9106 reveals (ours and cl-deposits', which
    /// publishes both), the reveal requests this daemon received live, and
    /// our own preimage, which we derive.
    pub(crate) async fn revealed_lottery_preimages(
        &self,
        ledger_id: &str,
        updates: &[deposits_core::SignedLedgerUpdate],
    ) -> Vec<Vec<u8>> {
        use nostr_sdk::{Filter, Kind, TagKind};

        let mut revealed: Vec<Vec<u8>> = Vec::new();
        let mut add = |p: Vec<u8>, revealed: &mut Vec<Vec<u8>>| {
            if !revealed.contains(&p) {
                revealed.push(p);
            }
        };

        // Durable Kind 9106 reveals.
        match self.nostr.fetch_custody_lottery_reveals(ledger_id).await {
            Ok(reveals) => {
                for r in reveals {
                    if let Ok(p) = hex::decode(&r.preimage_hex) {
                        add(p, &mut revealed);
                    }
                }
            }
            Err(e) => tracing::debug!("Kind 9106 reveal fetch failed: {}", e),
        }

        // Reveal requests seen live.
        if let Some(seen) = self.seen_lottery_reveals.lock().unwrap().get(ledger_id) {
            for p in seen {
                add(p.clone(), &mut revealed);
            }
        }

        // Reveal requests, if the relay kept any.
        let reveal_filter = Filter::new()
            .kind(Kind::Custom(crate::nostr::KIND_LEDGER_REQUEST))
            .custom_tag(crate::nostr::TAG_LEDGER_REQ, [ledger_id])
            .limit(100);
        if let Ok(events) = self
            .nostr
            .fetch_client()
            .fetch_events(vec![reveal_filter], Some(std::time::Duration::from_secs(5)))
            .await
        {
            for event in events.iter() {
                let is_lottery_reveal = event.tags.iter().any(|tag| {
                    tag.kind() == TagKind::custom("action")
                        && tag
                            .content()
                            .map(|c| c == "lottery_reveal")
                            .unwrap_or(false)
                });
                if !is_lottery_reveal {
                    continue;
                }
                if let Some(p) = serde_json::from_str::<serde_json::Value>(&event.content)
                    .ok()
                    .and_then(|c| reveal_request_preimage(&c))
                {
                    add(p, &mut revealed);
                }
            }
        }

        // Our own, derived, whether or not our reveal made it back to us;
        // but only once we have revealed it. Otherwise a loser could see
        // everyone else's reveal, yield (which tombstones its fork, and the
        // reveal task then skips it) and never reveal, and the winner could
        // never claim. The reveal task publishes it within a periodic.
        if self.have_revealed_lottery(ledger_id).await {
            if let Some(p) = self.own_lottery_preimage(ledger_id) {
                add(p, &mut revealed);
            }
        }

        revealed
    }

    /// The participant set of the confiscation that spent the vault, if one has: the
    /// subset of `candidates` whose lottery output its first output pays. `current`
    /// (our cut now) is tried first. `None` while the vault is unspent or no subset
    /// matches.
    fn landed_lottery_set(
        &self,
        updates: &[deposits_core::SignedLedgerUpdate],
        current: &[(bitcoin::secp256k1::PublicKey, LotteryParticipant)],
        candidates: &[(bitcoin::secp256k1::PublicKey, LotteryParticipant)],
        voters: &[XOnlyPublicKey],
        threshold: usize,
        floor: u32,
    ) -> Option<Vec<(bitcoin::secp256k1::PublicKey, LotteryParticipant)>> {
        let (vault, _) = super::vault_watch::current_vault(updates)?;
        let backend = self.wallet.chain_backend();
        let (spk, _, _) = landed_spender(&*backend, &vault, floor)?;
        match_landed_set(
            &spk,
            current,
            candidates,
            voters,
            threshold,
            self.wallet.network(),
        )
    }

    /// The unspent lottery output and its confirmations, if it is on chain.
    pub(crate) fn locate_lottery_output(
        &self,
        lottery: &LotteryOutput,
        landed: Option<OutPoint>,
    ) -> Result<Option<(OutPoint, u64, u32)>, Error> {
        // By outpoint: the landed confiscation's output 0, if it pays this lottery and is
        // unspent. Not "an unspent output at the lottery's script", which ref7 read as another
        // ledger's unclaimed round-2 output of the same script and value and claimed instead
        // (regtest rearm-rust 1120-090836: a606a4ca's claim spent 70b0abb3's 46a66b12:0).
        let Some(outpoint) = landed else {
            return Ok(None);
        };
        Ok(self
            .wallet
            .unspent_output_paying(outpoint, &lottery.script_pubkey())?
            .map(|(value, confirmations)| (outpoint, value, confirmations)))
    }

    /// The recovery voters' attestations of a subset claim, parallel to
    /// `lottery.recovery_voter_order()`: ours if we are a voter, then a
    /// `lottery_subset_attest` request, collected over the following
    /// periodic passes (non-blocking, as `initiate_confiscations`). `None`
    /// while the threshold is not yet met.
    pub(crate) async fn subset_attestations(
        &self,
        ledger_id: &str,
        lottery: &LotteryOutput,
        indices: &[usize],
        tx: &Transaction,
        prevouts: &[TxOut],
        sighash: [u8; 32],
    ) -> Result<Option<Vec<Option<[u8; 64]>>>, Error> {
        use deposits_signer_api::{SigPurpose, SignContext};
        let ledger_prefix = &ledger_id[..16.min(ledger_id.len())];
        let order = lottery.recovery_voter_order();
        let threshold = lottery.recovery_threshold;
        let finish = |sigs: &HashMap<XOnlyPublicKey, [u8; 64]>| {
            order
                .iter()
                .map(|v| sigs.get(v).copied())
                .collect::<Vec<_>>()
        };

        let in_flight = {
            let mut pending = self.pending_subset_claims.lock().unwrap();
            match pending.get(ledger_id) {
                Some(p)
                    if p.sighash == sighash
                        && p.created_at.elapsed().as_secs()
                            < LOTTERY_ATTEST_REQUEST_TIMEOUT_SECS =>
                {
                    Some(p.request_id.clone())
                }
                Some(_) => {
                    pending.remove(ledger_id);
                    None
                }
                None => None,
            }
        };
        if let Some(request_id) = in_flight {
            let responses = self.fetch_sign_responses(&request_id).await;
            let mut pending = self.pending_subset_claims.lock().unwrap();
            let Some(p) = pending.get_mut(ledger_id) else {
                return Ok(None);
            };
            let msg = bitcoin::secp256k1::Message::from_digest(sighash);
            let secp = bitcoin::secp256k1::Secp256k1::verification_only();
            for (signer, sig) in responses {
                let xonly = signer.x_only_public_key().0;
                let ok = order.contains(&xonly)
                    && bitcoin::secp256k1::schnorr::Signature::from_slice(&sig)
                        .map(|s| secp.verify_schnorr(&s, &msg, &xonly).is_ok())
                        .unwrap_or(false);
                if ok && !p.signatures.contains_key(&xonly) {
                    let mut arr = [0u8; 64];
                    arr.copy_from_slice(&sig);
                    p.signatures.insert(xonly, arr);
                    tracing::info!(
                        "Lottery {}: subset attestation from {}... ({}/{})",
                        ledger_prefix,
                        &signer.to_string()[..16],
                        p.signatures.len(),
                        threshold
                    );
                }
            }
            if p.signatures.len() < threshold {
                return Ok(None);
            }
            let sigs = pending
                .remove(ledger_id)
                .map(|p| p.signatures)
                .unwrap_or_default();
            return Ok(Some(finish(&sigs)));
        }

        let mut signatures = HashMap::new();
        let our_xonly = self.node_id.x_only_public_key().0;
        if order.contains(&our_xonly) {
            let our_sig = self
                .handler
                .signer
                .bip340_sign(
                    &SignContext::no_ledger(SigPurpose::OnchainSighash),
                    &sighash,
                )
                .map_err(|e| Error::Protocol(format!("subset attestation sign: {}", e)))?;
            signatures.insert(our_xonly, our_sig);
        }
        if signatures.len() >= threshold {
            return Ok(Some(finish(&signatures)));
        }
        let subset: Vec<String> = indices
            .iter()
            .map(|&i| hex::encode(lottery.participants[i].pubkey.serialize()))
            .collect();
        let params = serde_json::json!({
            "unsigned_tx": hex::encode(bitcoin::consensus::encode::serialize(tx)),
            "sighash": hex::encode(sighash),
            "subset": subset,
            "prevout_amounts": prevouts.iter().map(|p| p.value.to_sat()).collect::<Vec<_>>(),
            "prevout_spks": prevouts.iter().map(|p| hex::encode(p.script_pubkey.as_bytes())).collect::<Vec<_>>(),
        });
        let request_id = self
            .nostr
            .send_ledger_request(ledger_id, "lottery_subset_attest", params)
            .await
            .map_err(|e| Error::Protocol(format!("send lottery_subset_attest: {:?}", e)))?;
        self.track_sent_event(&request_id);
        tracing::info!(
            "Lottery {}: requested attestations of revealer subset {:?} ({} needed)",
            ledger_prefix,
            indices,
            threshold
        );
        self.pending_subset_claims.lock().unwrap().insert(
            ledger_id.to_string(),
            PendingSubsetClaim {
                request_id,
                sighash,
                signatures,
                created_at: std::time::Instant::now(),
            },
        );
        Ok(None)
    }

    /// `(signer, signature)` pairs from successful responses to
    /// `request_id` (the relay scan `collect_confiscation_signatures` does).
    pub(crate) async fn fetch_sign_responses(
        &self,
        request_id: &str,
    ) -> Vec<(bitcoin::secp256k1::PublicKey, Vec<u8>)> {
        use nostr_sdk::{Filter, Kind};

        let filter = Filter::new()
            .kind(Kind::Custom(crate::nostr::KIND_LEDGER_RESPONSE))
            .since(nostr_sdk::Timestamp::now() - LOTTERY_ATTEST_REQUEST_TIMEOUT_SECS);
        let events = match self
            .nostr
            .client()
            .fetch_events(vec![filter], Some(std::time::Duration::from_secs(5)))
            .await
        {
            Ok(e) => e,
            Err(_) => return Vec::new(),
        };
        let mut out = Vec::new();
        for event in events.iter() {
            let answers_us = event.tags.iter().any(|tag| {
                tag.kind() == nostr_sdk::TagKind::SingleLetter(crate::nostr::TAG_EVENT_REF)
                    && tag.content() == Some(request_id)
            });
            if !answers_us {
                continue;
            }
            let response =
                match serde_json::from_str::<crate::nostr::LedgerResponse>(&event.content) {
                    Ok(r) if r.success => r,
                    Ok(r) => {
                        tracing::info!(
                            "lottery_subset_attest refused: {}",
                            r.error.unwrap_or_default()
                        );
                        continue;
                    }
                    Err(_) => continue,
                };
            let result = match &response.result {
                Some(r) => r,
                None => continue,
            };
            if let (Some(signer), Some(sig)) = (
                result
                    .get("signer")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<bitcoin::secp256k1::PublicKey>().ok()),
                result
                    .get("signature")
                    .and_then(|v| v.as_str())
                    .and_then(|s| hex::decode(s).ok()),
            ) {
                out.push((signer, sig));
            }
        }
        out
    }

    /// A recovery voter (cl-deposits `handle-lottery-subset-attest`): sign a
    /// revealer-subset claim only past the reveal deadline, only for exactly
    /// the reveals we hold, only for that subset's winner, and only a claim
    /// of the lottery output paying the winner's declared target.
    pub(crate) async fn process_lottery_subset_attest_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        let ledger_prefix = &request.ledger_id[..16.min(request.ledger_id.len())];
        match self.check_lottery_subset_attest(request).await {
            Ok(sighash) => {
                use deposits_signer_api::{SigPurpose, SignContext};
                let signature = match self.handler.signer.bip340_sign(
                    &SignContext::no_ledger(SigPurpose::OnchainSighash),
                    &sighash,
                ) {
                    Ok(s) => s,
                    Err(e) => {
                        return (false, None, Some(format!("subset attestation sign: {}", e)))
                    }
                };
                tracing::info!("Attested a lottery subset claim for {}", ledger_prefix);
                let result = serde_json::json!({
                    "signer": self.node_id_hex.clone(),
                    "signature": hex::encode(signature),
                });
                (true, Some(result.to_string()), None)
            }
            Err(reason) => {
                tracing::info!(
                    "Refused lottery_subset_attest for {}: {}",
                    ledger_prefix,
                    reason
                );
                (false, None, Some(reason))
            }
        }
    }

    async fn check_lottery_subset_attest(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> Result<[u8; 32], String> {
        use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
        use bitcoin::taproot::{LeafVersion, TapLeafHash};
        let p = &request.params;
        let claimed_sighash: [u8; 32] = p
            .get("sighash")
            .and_then(|v| v.as_str())
            .and_then(|h| hex::decode(h).ok())
            .and_then(|b| b.try_into().ok())
            .ok_or("missing or invalid sighash")?;
        let proposed = p
            .get("unsigned_tx")
            .and_then(|v| v.as_str())
            .and_then(|h| hex::decode(h).ok())
            .ok_or_else(|| "missing or invalid unsigned_tx".to_string())
            .and_then(|b| parse_unsigned_tx(&b))?;
        let asked: Vec<XOnlyPublicKey> = p
            .get("subset")
            .and_then(|v| v.as_array())
            .ok_or("missing subset")?
            .iter()
            .map(|v| {
                v.as_str()
                    .and_then(|h| hex::decode(h).ok())
                    .and_then(|b| XOnlyPublicKey::from_slice(&b).ok())
                    .ok_or_else(|| "bad subset key".to_string())
            })
            .collect::<Result<_, _>>()?;
        let amounts: Vec<u64> = p
            .get("prevout_amounts")
            .and_then(|v| v.as_array())
            .ok_or("missing prevout_amounts")?
            .iter()
            .map(|v| v.as_u64().ok_or_else(|| "bad prevout amount".to_string()))
            .collect::<Result<_, _>>()?;
        let spks: Vec<bitcoin::ScriptBuf> = p
            .get("prevout_spks")
            .and_then(|v| v.as_array())
            .ok_or("missing prevout_spks")?
            .iter()
            .map(|v| {
                v.as_str()
                    .and_then(|h| hex::decode(h).ok())
                    .map(bitcoin::ScriptBuf::from_bytes)
                    .ok_or_else(|| "bad prevout spk".to_string())
            })
            .collect::<Result<_, _>>()?;
        if amounts.len() != spks.len() || amounts.len() != proposed.input.len() {
            return Err("prevouts do not match the claim's inputs".to_string());
        }

        let ctx = self
            .lottery_context(&request.ledger_id)
            .await
            .map_err(|e| e.to_string())?;
        let our_xonly = self.node_id.x_only_public_key().0;
        if !ctx.recovery_voters.contains(&our_xonly) {
            return Err("not a recovery voter".to_string());
        }
        let lottery = ctx
            .build_lottery(self.wallet.network())
            .map_err(|e| e.to_string())?;
        let (outpoint, value, confirmations) = self
            .locate_lottery_output(&lottery, ctx.landed)
            .map_err(|e| e.to_string())?
            .ok_or("no pending lottery on chain")?;
        let path = lottery_claim_path(&ctx.preimages, confirmations >= LOTTERY_REVEAL_CSV_BLOCKS);
        let (idx, pre) = match path {
            LotteryClaimPath::Subset(idx, pre) => (idx, pre),
            LotteryClaimPath::Full(_) => {
                return Err("everyone revealed: the full-set leaf needs no attestation".to_string())
            }
            LotteryClaimPath::Wait(why) => return Err(why),
        };
        let mut asked_idx: Vec<usize> = asked
            .iter()
            .map(|k| {
                lottery
                    .participants
                    .iter()
                    .position(|p| p.pubkey == *k)
                    .ok_or_else(|| "a subset key is not a participant".to_string())
            })
            .collect::<Result<_, _>>()?;
        asked_idx.sort_unstable();
        if asked_idx != idx {
            return Err(format!(
                "subset {:?} is not the reveals we hold {:?}",
                asked_idx, idx
            ));
        }
        let winner = LotteryOutput::subset_winner(&idx, &pre).map_err(|e| format!("{:?}", e))?;
        let target: bitcoin::Address<bitcoin::address::NetworkUnchecked> = lottery.participants
            [winner]
            .target_reserves
            .parse()
            .map_err(|e| format!("winner target: {}", e))?;
        let target = target
            .require_network(self.wallet.network())
            .map_err(|e| format!("winner target network: {}", e))?;
        if proposed.input.first().map(|i| i.previous_output) != Some(outpoint) {
            return Err("the claim does not spend the lottery output".to_string());
        }
        if proposed.output.len() != 1 || proposed.output[0].script_pubkey != target.script_pubkey()
        {
            return Err("the claim does not pay the winner's target".to_string());
        }
        if spks[0] != lottery.script_pubkey() || amounts[0] != value {
            return Err("prevout 0 is not the lottery output".to_string());
        }
        let prevouts: Vec<TxOut> = amounts
            .iter()
            .zip(spks)
            .map(|(a, s)| TxOut {
                value: bitcoin::Amount::from_sat(*a),
                script_pubkey: s,
            })
            .collect();
        let leaf = lottery.subset_leaf(&idx).ok_or("no leaf for the subset")?;
        let sighash = SighashCache::new(&proposed)
            .taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(&prevouts),
                TapLeafHash::from_script(leaf, LeafVersion::TapScript),
                TapSighashType::Default,
            )
            .map_err(|e| format!("sighash: {}", e))?;
        let sighash: [u8; 32] = *sighash.as_ref();
        if sighash != claimed_sighash {
            return Err("sighash mismatch".to_string());
        }
        Ok(sighash)
    }
}

/// The first output script of the transaction that spent `vault`, once it has.
/// A spend is final, so once found it is cached. The search starts at `floor`
/// (a confiscation cannot precede the arms it pays) and advances at most
/// `LANDED_SCAN_CHUNK` blocks per pass, remembering how far it got, so one slow
/// or failed RPC costs a pass, not the whole walk; an unspent vault costs one
/// `gettxout`. (Walking every block from the vault's creation to the tip on
/// every pass of the 10 s claim task, for every armed fork, took ~60 s on
/// bitcoind and stalled the lottery for good.)
/// The block the dispute's confiscation confirmed in: the confirmed spend of the vault the
/// ledger's latest `QuorumBegin` names, searched from the dispute's first arm. `None` while
/// the vault is unspent (or the search has not reached the spend yet).
pub(crate) fn confiscation_height(
    backend: &dyn crate::chain_backend::ChainBackend,
    updates: &[deposits_core::SignedLedgerUpdate],
) -> Option<u32> {
    dispute_confiscation(backend, updates).map(|(h, _)| h)
}

/// Round 1's lottery outpoint: output 0 of the confirmed confiscation of the dispute's vault
/// ([`dispute_confiscation`]), once the search has found it.
pub(crate) fn landed_lottery_outpoint(
    backend: &dyn crate::chain_backend::ChainBackend,
    updates: &[deposits_core::SignedLedgerUpdate],
) -> Option<OutPoint> {
    dispute_confiscation(backend, updates).map(|(_, txid)| OutPoint { txid, vout: 0 })
}

/// The dispute's confiscation, (block C, txid): the confirmed spend of the vault of the
/// dispute's own fork point, Q read over the DisputeEnters signed at or below C (DEP-03 §When
/// the set is final), never the vault of whatever QuorumBegin is latest. The latest one can be
/// a disputant's fork's, or the operator's past the fork point; and a DisputeEnter signed after
/// the confiscation naming a higher fork point would otherwise move Q, the vault and C with it,
/// and so count itself back in.
///
/// The DisputeEnters are taken in block order. For each prefix, Q is the original operator's
/// latest QuorumBegin at or below the prefix's highest `last_valid_sequence`, and its vault's
/// landed spend at C answers when the prefix is exactly the DisputeEnters at or below C (its
/// last at or below C, the next above it). A spend that is a later QuorumBegin's rotation (one
/// of its rungs) confiscates nothing: the dispute moved on with the vault. The search for a
/// spend is chunked across calls (`landed_spender`); until a prefix's spent vault is found the
/// answer is `None`, never a later prefix's.
pub(crate) fn dispute_confiscation(
    backend: &dyn crate::chain_backend::ChainBackend,
    updates: &[deposits_core::SignedLedgerUpdate],
) -> Option<(u32, bitcoin::Txid)> {
    use deposits_core::messages::LedgerOperation;
    use deposits_core::TlvDecode;
    let origin = updates
        .iter()
        .find(|u| u.sequence_number == 0)
        .map(|u| u.operator_id)?;
    let floor = super::armers::first_arm_height(updates)?;
    // the original operator's QuorumBegins: (seq, vault, rungs)
    let mut qbs: Vec<(u64, OutPoint, Vec<[u8; 32]>)> = updates
        .iter()
        .filter(|u| u.operator_id == origin)
        .filter_map(|u| match LedgerOperation::tlv_decode(&u.message) {
            Ok(
                op @ LedgerOperation::QuorumBegin {
                    new_outpoint_txid,
                    new_outpoint_vout,
                    ..
                },
            ) => Some((
                u.sequence_number,
                OutPoint::new(
                    bitcoin::Txid::from_byte_array(new_outpoint_txid),
                    new_outpoint_vout,
                ),
                deposits_core::vault_spend::quorum_begin_rungs(&op),
            )),
            _ => None,
        })
        .collect();
    qbs.sort_by_key(|q| q.0);
    qbs.dedup_by_key(|q| q.0);
    let mut enters: Vec<(u32, u64, u64)> = updates
        .iter()
        .filter(|u| u.operator_id != origin)
        .filter_map(|u| match LedgerOperation::tlv_decode(&u.message) {
            Ok(LedgerOperation::DisputeEnter {
                last_valid_sequence,
                ..
            }) => Some((u.block_height, u.sequence_number, last_valid_sequence)),
            _ => None,
        })
        .collect();
    enters.sort();
    let mut top = 0u64;
    for k in 0..enters.len() {
        top = top.max(enters[k].2);
        let Some(qi) = qbs.iter().rposition(|q| q.0 <= top) else {
            continue;
        };
        let (_, vault, _) = &qbs[qi];
        let Some((_, c, txid)) = landed_spender(backend, vault, floor) else {
            // Unspent: no confiscation of this Q's vault, so the next enter may move Q.
            // Spent but not yet found (the search is chunked): wait, or a later prefix's
            // vault, found first, would answer for this one.
            if backend
                .is_output_unspent(&vault.txid, vault.vout)
                .ok()
                .flatten()
                == Some(true)
            {
                continue;
            }
            return None;
        };
        let rotation = qbs[qi + 1..]
            .iter()
            .any(|q| q.2.contains(&txid.to_byte_array()));
        if rotation {
            continue;
        }
        let next_above = enters.get(k + 1).is_none_or(|e| e.0 > c);
        if enters[k].0 <= c && next_above {
            return Some((c, txid));
        }
    }
    None
}

/// The landed spender of `vault` (its first output's script), the block it confirmed
/// in and its txid, searched from `floor` a chunk per call, progress remembered.
fn landed_spender(
    backend: &dyn crate::chain_backend::ChainBackend,
    vault: &OutPoint,
    floor: u32,
) -> Option<(bitcoin::ScriptBuf, u32, bitcoin::Txid)> {
    use std::sync::{Mutex, OnceLock};
    const LANDED_SCAN_CHUNK: u32 = 50;
    enum Progress {
        ScannedTo(u32),
        Found(bitcoin::ScriptBuf, u32, bitcoin::Txid),
    }
    static CACHE: OnceLock<Mutex<HashMap<OutPoint, Progress>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let start = match cache.lock().unwrap().get(vault) {
        Some(Progress::Found(spk, h, txid)) => return Some((spk.clone(), *h, *txid)),
        Some(Progress::ScannedTo(h)) => h + 1,
        None => {
            let created = backend.get_tx_block_height(&vault.txid).ok().flatten()?;
            created.max(floor)
        }
    };
    let tip = backend.get_tip_height().ok()?;
    if start > tip {
        return None;
    }
    let end = tip.min(start.saturating_add(LANDED_SCAN_CHUNK - 1));
    let height = match backend.spent_within(vault, bitcoin::Script::new(), start, end) {
        Ok(Some(h)) => h,
        Ok(None) => {
            // Unspent (spent_within returns None after one gettxout without
            // walking), or not in start..=end: either way nothing below end+1.
            if backend
                .is_output_unspent(&vault.txid, vault.vout)
                .ok()
                .flatten()
                != Some(true)
            {
                cache
                    .lock()
                    .unwrap()
                    .insert(*vault, Progress::ScannedTo(end));
            }
            return None;
        }
        Err(e) => {
            tracing::warn!(
                "landed spender {}: scan {}..={} failed: {}",
                vault,
                start,
                end,
                e
            );
            return None;
        }
    };
    let spender = backend
        .find_spending_tx(vault, bitcoin::Script::new(), height)
        .ok()
        .flatten()?;
    let spk = spender.output.first()?.script_pubkey.clone();
    let txid = spender.compute_txid();
    cache
        .lock()
        .unwrap()
        .insert(*vault, Progress::Found(spk.clone(), height, txid));
    Some((spk, height, txid))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    fn secret(seed: u8) -> SecretKey {
        SecretKey::from_slice(&[seed; 32]).unwrap()
    }
    fn pubkey(seed: u8) -> bitcoin::secp256k1::PublicKey {
        bitcoin::secp256k1::PublicKey::from_secret_key(&Secp256k1::new(), &secret(seed))
    }

    #[test]
    fn the_landed_set_is_recovered_from_the_confirmed_output() {
        let p = |i: u8| {
            (
                pubkey(i),
                LotteryParticipant::new(pubkey(i).x_only_public_key().0, [i; 20], "t".into()),
            )
        };
        let voters: Vec<XOnlyPublicKey> = (20..23u8)
            .map(|i| pubkey(i).x_only_public_key().0)
            .collect();
        let all = vec![p(1), p(2), p(3), p(4)];
        // The confiscation was built over 1, 2, 4; a late arm (3) joined our view since.
        let mut landed = [p(1), p(2), p(4)];
        landed.sort_by_key(|(_, x)| x.pubkey.serialize());
        let spk = LotteryScriptBuilder::new(
            landed.iter().map(|(_, x)| x.clone()).collect(),
            voters.clone(),
            2,
            bitcoin::Network::Regtest,
        )
        .build()
        .unwrap()
        .script_pubkey();
        let got =
            match_landed_set(&spk, &all, &all, &voters, 2, bitcoin::Network::Regtest).unwrap();
        assert_eq!(
            got.iter().map(|(k, _)| *k).collect::<Vec<_>>(),
            landed.iter().map(|(k, _)| *k).collect::<Vec<_>>()
        );
        let other = bitcoin::ScriptBuf::from_bytes(vec![0x51]);
        assert!(
            match_landed_set(&other, &all, &all, &voters, 2, bitcoin::Network::Regtest).is_none()
        );
    }

    /// The backdated-arm question for round 1 (docs/ADVERSARIAL.md §Rule inverters, unruled). A
    /// fork's DisputeArmed is not cosigned, so an armer can sign one with a `block_height` at or
    /// below the confiscation block and publish it after the confiscation confirmed. The landed
    /// set is recovered by searching subsets of the current arms (`match_landed_set`; cl
    /// `lottery-paid-by`). The output script binds only each participant's key and commitment,
    /// and the fold makes a same-round re-arm repeat its commitment, so a backdated re-arm that
    /// changes a target or collateral still matches, and a backdated newcomer leaves the landed set
    /// a subset. What loses it: more than 8 candidates, where the subset search does not run.
    /// This asserts today's behaviour.
    #[test]
    fn a_backdated_round_1_arm_loses_the_landed_set_only_past_8_armers() {
        let p = |i: u8, target: &str| {
            (
                pubkey(i),
                LotteryParticipant::new(pubkey(i).x_only_public_key().0, [i; 20], target.into()),
            )
        };
        let voters: Vec<XOnlyPublicKey> = (20..23u8)
            .map(|i| pubkey(i).x_only_public_key().0)
            .collect();
        let net = bitcoin::Network::Regtest;
        let mut landed = vec![p(1, "t"), p(2, "t")];
        landed.sort_by_key(|(_, x)| x.pubkey.serialize());
        let spk = LotteryScriptBuilder::new(
            landed.iter().map(|(_, x)| x.clone()).collect(),
            voters.clone(),
            2,
            net,
        )
        .build()
        .unwrap()
        .script_pubkey();
        // A newcomer's backdated arm (3): the landed set is still a subset.
        let grown = vec![p(1, "t"), p(2, "t"), p(3, "t")];
        assert!(match_landed_set(&spk, &grown, &grown, &voters, 2, net).is_some());
        // Participant 2 re-arms, backdated, same commitment (the fold requires it), another
        // target: the script does not bind targets, so the output still matches (paying the new
        // target on a claim).
        let changed = vec![p(1, "t"), p(2, "elsewhere")];
        let got = match_landed_set(&spk, &changed, &changed, &voters, 2, net).unwrap();
        assert!(got.iter().any(|(_, x)| x.target_reserves == "elsewhere"));
        // Nine candidates (seven backdated newcomers): the subset search does not run.
        let crowd: Vec<_> = (1..=9u8).map(|i| p(i, "t")).collect();
        assert!(match_landed_set(&spk, &crowd, &crowd, &voters, 2, net).is_none());
    }

    #[test]
    fn claim_path_full_subset_or_wait() {
        let p = |n: usize| Some(vec![0u8; n]);
        assert_eq!(
            lottery_claim_path(&[p(20), p(30)], false),
            LotteryClaimPath::Full(vec![vec![0u8; 20], vec![0u8; 30]])
        );
        assert!(matches!(
            lottery_claim_path(&[p(20), None, p(30)], false),
            LotteryClaimPath::Wait(_)
        ));
        assert_eq!(
            lottery_claim_path(&[p(20), None, p(30)], true),
            LotteryClaimPath::Subset(vec![0, 2], vec![vec![0u8; 20], vec![0u8; 30]])
        );
        // An out-of-range preimage satisfies no leaf: it counts as unrevealed.
        assert_eq!(
            lottery_claim_path(&[p(77), p(40)], true),
            LotteryClaimPath::Subset(vec![1], vec![vec![0u8; 40]])
        );
        assert!(matches!(
            lottery_claim_path(&[None, None], true),
            LotteryClaimPath::Wait(_)
        ));
        // A sole participant needs no preimage at all.
        assert_eq!(
            lottery_claim_path(&[None], false),
            LotteryClaimPath::Full(vec![])
        );
    }

    // ── The winner never claimed (devnet, ledger C, 2026-09-28) ──────────
    //
    // ref3 won C's lottery (cld3 18 bytes, cld4 17, ref3 18: sum of
    // contributions 5, 5 mod 3 = 2) but saw no reveal at all: it read only
    // `lottery_reveal` requests back from the relay, kind 20101, which the
    // relay does not store. These pin the sources it reads now.

    fn preimage(len: usize, fill: u8) -> Vec<u8> {
        vec![fill; len]
    }

    fn commit(p: &[u8]) -> [u8; 20] {
        use bitcoin::hashes::{hash160, Hash as _};
        hash160::Hash::hash(p).to_byte_array()
    }

    /// Three participants in canonical x-only order, the winner's
    /// (index 2) preimage 18 bytes as ref3's was.
    fn devnet_c_lottery() -> (
        Vec<(bitcoin::secp256k1::PublicKey, LotteryParticipant)>,
        [Vec<u8>; 3],
    ) {
        let mut keys: Vec<bitcoin::secp256k1::PublicKey> = (1..=3u8).map(pubkey).collect();
        keys.sort_by(|a, b| {
            a.x_only_public_key()
                .0
                .serialize()
                .cmp(&b.x_only_public_key().0.serialize())
        });
        let preimages = [preimage(18, 0xA1), preimage(17, 0xB2), preimage(18, 0xC3)];
        let participants = keys
            .iter()
            .zip(preimages.iter())
            .map(|(k, p)| {
                (
                    *k,
                    LotteryParticipant::new(k.x_only_public_key().0, commit(p), "tb1pw".into()),
                )
            })
            .collect();
        (participants, preimages)
    }

    #[test]
    fn two_durable_reveals_and_our_own_make_the_lottery_claimable() {
        let (participants, [cld3, cld4, ours]) = devnet_c_lottery();
        // Before: nothing came back from the relay.
        assert!(matches!(
            lottery_claim_path(&match_revealed_preimages(&participants, &[]), false),
            LotteryClaimPath::Wait(_)
        ));
        // The two Kind 9106 reveals alone are not enough before the deadline...
        let from_9106 = vec![cld4.clone(), cld3.clone()];
        assert!(matches!(
            lottery_claim_path(&match_revealed_preimages(&participants, &from_9106), false),
            LotteryClaimPath::Wait(_)
        ));
        // ...with our own (derived) preimage the full set is claimable, and
        // we (index 2) win: (2 + 1 + 2) mod 3.
        let revealed = vec![cld4, cld3, ours.clone()];
        let matched = match_revealed_preimages(&participants, &revealed);
        let LotteryClaimPath::Full(ordered) = lottery_claim_path(&matched, false) else {
            panic!("expected the full set");
        };
        assert_eq!(ordered[2], ours);
        assert_eq!(LotteryOutput::calculate_winner(&ordered).unwrap(), 2);
    }

    #[test]
    fn a_preimage_matches_only_its_own_commitment() {
        let (participants, [a, _, _]) = devnet_c_lottery();
        let stray = preimage(18, 0xEE);
        let matched = match_revealed_preimages(&participants, &[stray, a.clone()]);
        assert_eq!(matched, vec![Some(a), None, None]);
    }

    #[test]
    fn reveal_request_params_yield_the_preimage() {
        let p = serde_json::json!({"ledger_id": "ab", "preimage": "7f387fb7"});
        assert_eq!(
            reveal_request_preimage(&p),
            Some(vec![0x7f, 0x38, 0x7f, 0xb7])
        );
        assert_eq!(
            reveal_request_preimage(&serde_json::json!({"ledger_id": "ab"})),
            None
        );
        assert_eq!(
            reveal_request_preimage(&serde_json::json!({"preimage": "zz"})),
            None
        );
    }

    fn update_with(
        op: &deposits_core::messages::LedgerOperation,
    ) -> deposits_core::SignedLedgerUpdate {
        use deposits_core::TlvEncode;
        deposits_core::SignedLedgerUpdate {
            message: op.tlv_encode(),
            message_type: 0,
            operator_id: pubkey(1),
            ledger_id: [7u8; 32],
            sequence_number: 0,
            previous_hash: [0u8; 32],
            content_hash: [0u8; 32],
            block_height: 0,
            block_hash: [0u8; 32],
            operator_signature: [0u8; 64],
            cosignatures: Vec::new(),
        }
    }

    #[test]
    fn a_dispute_enter_s_fork_point_is_fetched_when_no_tag_selected_it() {
        use deposits_core::messages::LedgerOperation;
        let enter_at = |lvs: u64, seq: u64| {
            let mut u = update_with(&LedgerOperation::DisputeEnter {
                last_valid_sequence: lvs,
                reason: "r".into(),
                anchor_block_hash: None,
                anchor_block_height: None,
                fraud_proof_hash: None,
                fraud_proof: None,
            });
            u.sequence_number = seq;
            u
        };
        let mut point = update_with(&LedgerOperation::DisputeArmed {
            armed_block: 1,
            commitment_hash: [1; 20],
            target_reserves: "tb1pw".into(),
            replacement_collateral: None,
            rearm_round: None,
        });
        point.sequence_number = 8;
        // Two DisputeEnters at fork point 8, one at 5: 8 is held, 5 is not.
        let ups = [enter_at(8, 9), enter_at(8, 9), enter_at(5, 6), point];
        assert_eq!(missing_fork_points(&ups), vec![5]);
        assert_eq!(missing_fork_points(&ups[3..]), Vec::<u64>::new());
    }

    #[test]
    fn a_tag_filtered_fetch_is_used_only_when_complete() {
        use deposits_core::messages::{LedgerOperation, QuorumMemberRef};
        let open = update_with(&LedgerOperation::LedgerOpen {
            operator_id: pubkey(1),
            reserves_id: "r".into(),
            genesis_block: 0,
            reserves_amount: 1,
            collateral_amount: 1,
            protocol_version: None,
        });
        let qb = update_with(&LedgerOperation::QuorumBegin {
            exit_cutoff_height: None,
            exit_outputs: Vec::new(),
            splice_in_outpoint: None,
            splice_in_amount: None,
            reference_feerate: None,
            dormancy_outputs: Vec::new(),
            migration_manifest: Vec::new(),
            migration_receiver: None,
            migration_vout: None,
            consumed_notice: None,
            rotation_rungs: vec![],
            reserves_id: "r".into(),
            spending_txid: [0; 32],
            new_outpoint_txid: [0; 32],
            new_outpoint_vout: 0,
            amount: 1,
            quorum_expiry: 1,
            ledger_hash: [0; 32],
            quorum_members: vec![QuorumMemberRef::pubkey_only(pubkey(2))],
            collateral_amount: 1,
            protocol_version: Some("cltv-offset-v2".to_string()),
        });
        let armed = update_with(&LedgerOperation::DisputeArmed {
            armed_block: 1,
            commitment_hash: [1; 20],
            target_reserves: "tb1pw".into(),
            replacement_collateral: None,
            rearm_round: None,
        });
        let enter = update_with(&LedgerOperation::DisputeEnter {
            last_valid_sequence: 0,
            reason: "r".into(),
            anchor_block_hash: None,
            anchor_block_height: None,
            fraud_proof_hash: None,
            fraud_proof: None,
        });
        assert!(lottery_updates_complete(&[
            open.clone(),
            qb.clone(),
            enter.clone(),
            armed.clone()
        ]));
        // Without the DisputeEnter the ruleset at the fork point (and the accused) cannot be read.
        assert!(!lottery_updates_complete(&[
            open.clone(),
            qb.clone(),
            armed.clone()
        ]));
        assert!(!lottery_updates_complete(&[qb.clone(), armed.clone()]));
        assert!(!lottery_updates_complete(&[open.clone(), armed]));
        assert!(!lottery_updates_complete(&[open, qb]));
        // The discriminants the relay filter asks for are these ops'.
        assert_eq!(
            LOTTERY_OP_TYPES,
            [
                LedgerOperation::LedgerOpen {
                    operator_id: pubkey(1),
                    reserves_id: String::new(),
                    genesis_block: 0,
                    reserves_amount: 0,
                    collateral_amount: 0,
                    protocol_version: None,
                }
                .discriminant(),
                12,
                45,
                54,
                57
            ]
        );
    }

    /// DEP-03 §When the set is final: C is the confiscation of the vault of the dispute's own
    /// fork point. A DisputeEnter signed after it that names a higher fork point (past a later
    /// QuorumBegin of the operator, whose vault was spent later) must not move Q to that vault,
    /// C to that spend, and so count itself back in.
    mod dispute_confiscation_tests {
        use super::*;
        use crate::chain_backend::{ChainBackend, ConfirmedSpend, UnspentOutput};
        use crate::error::Error;
        use bitcoin::hashes::Hash as _;
        use bitcoin::{BlockHash, Script, Txid};
        use deposits_core::messages::{LedgerOperation, QuorumMemberRef};
        use deposits_core::{SignedLedgerUpdate, TlvEncode};

        /// vault -> (created at, its confirmed spender, confirmed at)
        struct Chain {
            tip: u32,
            spends: HashMap<OutPoint, (u32, Transaction, u32)>,
        }
        impl ChainBackend for Chain {
            fn get_tip_height(&self) -> Result<u32, Error> {
                Ok(self.tip)
            }
            fn get_block_hash(&self, _: u32) -> Result<BlockHash, Error> {
                unimplemented!()
            }
            fn get_block_height_if_in_best_chain(
                &self,
                _: &BlockHash,
            ) -> Result<Option<u32>, Error> {
                unimplemented!()
            }
            fn get_tx(&self, _: &Txid) -> Result<Option<Transaction>, Error> {
                Ok(None)
            }
            fn get_tx_block_height(&self, t: &Txid) -> Result<Option<u32>, Error> {
                Ok(self.spends.iter().find_map(|(o, (created, tx, h))| {
                    if o.txid == *t {
                        Some(*created)
                    } else if tx.compute_txid() == *t {
                        Some(*h)
                    } else {
                        None
                    }
                }))
            }
            fn is_output_unspent(&self, t: &Txid, v: u32) -> Result<Option<bool>, Error> {
                Ok(Some(!self.spends.contains_key(&OutPoint::new(*t, v))))
            }
            fn find_unspent_output_at(&self, _: &Script) -> Result<Option<UnspentOutput>, Error> {
                Ok(None)
            }
            fn find_spending_tx(
                &self,
                o: &OutPoint,
                _: &Script,
                _: u32,
            ) -> Result<Option<Transaction>, Error> {
                Ok(self.spends.get(o).map(|x| x.1.clone()))
            }
            fn confirmed_spend(
                &self,
                o: &OutPoint,
                _: &Script,
                from: u32,
            ) -> Result<ConfirmedSpend, Error> {
                Ok(match self.spends.get(o) {
                    None => ConfirmedSpend::Unspent,
                    Some((_, _, h)) if *h >= from => ConfirmedSpend::SpentAt(*h),
                    Some(_) => ConfirmedSpend::SpentBefore(from),
                })
            }
            fn broadcast_tx(&self, _: &Transaction) -> Result<Txid, Error> {
                unimplemented!()
            }
        }

        fn update(
            seq: u64,
            height: u32,
            operator_id: PublicKey,
            op: LedgerOperation,
        ) -> SignedLedgerUpdate {
            SignedLedgerUpdate {
                message: op.tlv_encode(),
                message_type: 0x8001,
                operator_id,
                ledger_id: [0x5c; 32],
                sequence_number: seq,
                previous_hash: [0u8; 32],
                content_hash: [0u8; 32],
                block_height: height,
                block_hash: [0u8; 32],
                operator_signature: [0u8; 64],
                cosignatures: Vec::new(),
            }
        }
        fn qb(vault: [u8; 32], members: &[PublicKey]) -> LedgerOperation {
            LedgerOperation::QuorumBegin {
                exit_cutoff_height: None,
                exit_outputs: Vec::new(),
                splice_in_outpoint: None,
                splice_in_amount: None,
                reference_feerate: None,
                dormancy_outputs: Vec::new(),
                migration_manifest: Vec::new(),
                migration_receiver: None,
                migration_vout: None,
                consumed_notice: None,
                rotation_rungs: vec![],
                reserves_id: "bcrt1q...".to_string(),
                spending_txid: [0; 32],
                new_outpoint_txid: vault,
                new_outpoint_vout: 0,
                amount: 1_000_000,
                quorum_expiry: 1_000_000,
                ledger_hash: [0; 32],
                quorum_members: members
                    .iter()
                    .copied()
                    .map(QuorumMemberRef::pubkey_only)
                    .collect(),
                collateral_amount: 0,
                protocol_version: Some("cltv-offset-v2".to_string()),
            }
        }
        fn enter(lvs: u64) -> LedgerOperation {
            LedgerOperation::DisputeEnter {
                last_valid_sequence: lvs,
                reason: "fraud_proof".to_string(),
                anchor_block_hash: None,
                anchor_block_height: None,
                fraud_proof_hash: None,
                fraud_proof: None,
            }
        }
        fn armed() -> LedgerOperation {
            LedgerOperation::DisputeArmed {
                armed_block: 1_000,
                commitment_hash: [1; 20],
                target_reserves: "t".into(),
                replacement_collateral: None,
                rearm_round: None,
            }
        }
        fn spender(tag: u32) -> Transaction {
            Transaction {
                version: bitcoin::transaction::Version::TWO,
                lock_time: bitcoin::absolute::LockTime::from_consensus(tag),
                input: vec![],
                output: vec![TxOut {
                    value: bitcoin::Amount::from_sat(1_000),
                    script_pubkey: bitcoin::ScriptBuf::new(),
                }],
            }
        }

        #[test]
        fn a_late_enter_naming_a_higher_fork_point_cannot_redirect_c() {
            let (op, a, b, late) = (pubkey(0x51), pubkey(0x52), pubkey(0x53), pubkey(0x54));
            // unique vault txids: landed_spender's progress cache is process-wide
            let (v1, v2) = ([0xd1; 32], [0xd2; 32]);
            let o1 = OutPoint::new(Txid::from_byte_array(v1), 0);
            let o2 = OutPoint::new(Txid::from_byte_array(v2), 0);
            let open = LedgerOperation::LedgerOpen {
                operator_id: op,
                reserves_id: "bcrt1q...".to_string(),
                genesis_block: 0,
                reserves_amount: 100_000,
                collateral_amount: 0,
                protocol_version: None,
            };
            let members = [op, a, b, late];
            let mut updates = vec![
                update(0, 900, op, open),
                update(3, 950, op, qb(v1, &members)),
                // in time: A and B fork after 4, Q = 3, vault v1
                update(5, 1_000, a, enter(4)),
                update(5, 1_001, b, enter(4)),
                update(6, 1_002, a, armed()),
            ];
            // the operator goes on and records QuorumBegin 9 on its own chain (vault v2)
            updates.push(update(9, 1_100, op, qb(v2, &members)));
            let (c1, c2) = (2_000u32, 2_500u32);
            let (t1, t2) = (spender(1), spender(2));
            let chain = Chain {
                tip: 3_000,
                spends: HashMap::from([(o1, (950, t1.clone(), c1)), (o2, (1_100, t2.clone(), c2))]),
            };
            // the search is chunked, a call at a time: poll as the node's passes do
            let settle =
                |u: &[SignedLedgerUpdate]| (0..200).find_map(|_| dispute_confiscation(&chain, u));
            // the dispute's vault is v1, confiscated at c1
            assert_eq!(settle(&updates), Some((c1, t1.compute_txid())));
            // a DisputeEnter signed after C naming fork point 10 (Q would be 9, vault v2)
            updates.push(update(11, c1 + 100, late, enter(10)));
            assert_eq!(
                settle(&updates),
                Some((c1, t1.compute_txid())),
                "a late enter must not move Q to v2 and C to its spend"
            );
            assert_eq!(confiscation_height(&chain, &updates), Some(c1));
            assert_eq!(
                landed_lottery_outpoint(&chain, &updates),
                Some(OutPoint {
                    txid: t1.compute_txid(),
                    vout: 0
                })
            );
            // so dispute_scope_final drops the late enter, and its fork takes no part
            let scoped = deposits_core::rotation_order::dispute_scope_final(&updates, Some(c1));
            assert!(
                scoped.iter().all(|u| u.operator_id != late),
                "the late enter's fork takes no part"
            );
            // control: the ledger's latest QuorumBegin (the old lookup) is v2, spent at c2, under
            // which the late enter (signed at c1+100 < c2) would have counted
            let (latest, _) = super::super::super::vault_watch::current_vault(&updates).unwrap();
            assert_eq!(latest, o2);
            let unscoped = deposits_core::rotation_order::dispute_scope_final(&updates, Some(c2));
            assert!(
                unscoped.iter().any(|u| u.operator_id == late),
                "control: under c2 it counts"
            );
        }
    }
}
