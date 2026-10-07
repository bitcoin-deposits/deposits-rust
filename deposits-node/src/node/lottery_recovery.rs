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
pub(crate) const LOTTERY_OP_TYPES: [u8; 3] = [1, 12, 57];

/// Whether `updates` hold what a lottery is rebuilt from: the LedgerOpen,
/// a QuorumBegin and at least one DisputeArmed. A `t`-filtered fetch that
/// misses any of them (an update published without the tag) falls back to
/// the whole chain.
pub(crate) fn lottery_updates_complete(updates: &[deposits_core::SignedLedgerUpdate]) -> bool {
    use deposits_core::messages::LedgerOperation;
    let (mut open, mut qb, mut armed) = (false, false, false);
    for u in updates {
        match LedgerOperation::tlv_decode(&u.message) {
            Ok(LedgerOperation::LedgerOpen { .. }) => open = true,
            Ok(LedgerOperation::QuorumBegin { .. }) => qb = true,
            Ok(LedgerOperation::DisputeArmed { .. }) => armed = true,
            _ => {}
        }
    }
    open && qb && armed
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
        let updates = self.fetch_lottery_updates(ledger_id).await;

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
        let set = self
            .lottery_armer_set(ledger_id)
            .await
            .map_err(Error::Protocol)?;
        let mut participants: Vec<(bitcoin::secp256k1::PublicKey, LotteryParticipant)> = set
            .participants
            .iter()
            .map(|a| (a.key, a.participant.clone()))
            .collect();
        if let Some((voters, threshold)) = recovery_voters_from_updates(&updates) {
            let candidates: Vec<(bitcoin::secp256k1::PublicKey, LotteryParticipant)> = set
                .participants
                .iter()
                .chain(set.excluded.iter().map(|(a, _)| a))
                .map(|a| (a.key, a.participant.clone()))
                .collect();
            if let Some(landed) =
                self.landed_lottery_set(&updates, &participants, &candidates, &voters, threshold)
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
        let revealed = self.revealed_lottery_preimages(ledger_id, &updates).await;
        let preimages = match_revealed_preimages(&participants, &revealed);

        // Recovery voters MUST come from the latest QuorumBegin (minus
        // operator): the set the confiscation's lottery output commits to.
        let (recovery_voters, recovery_threshold) = recovery_voters_from_updates(&updates)
            .ok_or_else(|| {
                Error::Protocol(
                    "No QuorumBegin/LedgerOpen found to derive recovery voters".to_string(),
                )
            })?;
        if !has_ledger_open {
            return Err(Error::Protocol("No LedgerOpen found".to_string()));
        }

        Ok(LotteryContext {
            participants,
            preimages,
            recovery_voters,
            recovery_threshold,
            our_armed,
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
            return updates;
        }
        tracing::debug!(
            "Lottery ops for {} incomplete by op-type tag ({} found); fetching the whole chain",
            &ledger_id[..16.min(ledger_id.len())],
            updates.len()
        );
        self.fetch_all_ledger_updates_paginated(ledger_id).await
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
    ) -> Option<Vec<(bitcoin::secp256k1::PublicKey, LotteryParticipant)>> {
        let (vault, _) = super::vault_watch::current_vault(updates)?;
        let backend = self.wallet.chain_backend();
        let from = backend.get_tx_block_height(&vault.txid).ok().flatten()?;
        let spender = backend
            .find_spending_tx(&vault, bitcoin::Script::new(), from)
            .ok()
            .flatten()?;
        let spk = spender.output.first()?.script_pubkey.clone();
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
    ) -> Result<Option<(OutPoint, u64, u32)>, Error> {
        let Some((outpoint, value)) = self.wallet.find_utxo_for_script(&lottery.script_pubkey())?
        else {
            return Ok(None);
        };
        let confirmations = self
            .wallet
            .get_outpoint_value_and_confs(outpoint.txid, outpoint.vout)?
            .map(|(_, c)| c)
            .unwrap_or(0);
        Ok(Some((outpoint, value, confirmations)))
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
    async fn fetch_sign_responses(
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
            .locate_lottery_output(&lottery)
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
    fn a_tag_filtered_fetch_is_used_only_when_complete() {
        use deposits_core::messages::{LedgerOperation, QuorumMemberRef};
        let open = update_with(&LedgerOperation::LedgerOpen {
            operator_id: pubkey(1),
            reserves_id: "r".into(),
            genesis_block: 0,
            reserves_amount: 1,
            collateral_amount: 1,
        });
        let qb = update_with(&LedgerOperation::QuorumBegin {
            exit_cutoff_height: None,
            exit_outputs: Vec::new(),
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
        });
        assert!(lottery_updates_complete(&[
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
                }
                .discriminant(),
                12,
                57
            ]
        );
    }
}
