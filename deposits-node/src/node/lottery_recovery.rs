//! Unclaimable custody lotteries: detect them and sweep them through the
//! lottery output's CSV-144 recovery leaf.
//!
//! Armers commit their lottery preimage under `N = Q` (the recovery voters:
//! the latest `QuorumBegin`'s members minus the operator, see
//! [`dispute_lottery_n_from_history`]), but the claim leaf is built by
//! [`LotteryScriptBuilder`] for the `k` members who actually armed, and its
//! `OP_SIZE` bound is `16 + k`. With `k < Q` a revealed preimage longer than
//! `16 + k` makes the claim leaf unsatisfiable forever; only
//! `(k/Q)^k` of such lotteries can be claimed (cl-deposits
//! docs/LOTTERY-N.md). The protocol is unchanged; two mitigations, the same
//! as cl-deposits c3cd4cd:
//!
//! - `initiate_confiscations` does not confiscate with fewer than `Q` armed
//!   until [`FULL_ARMING_WAIT_BLOCKS`] have passed, so in the normal case
//!   `k = Q` and the lottery is always claimable;
//! - a lottery that cannot be claimed is swept, once its output is
//!   [`LOTTERY_RECOVERY_CSV`] blocks deep, through the first recovery leaf to
//!   the original operator's P2WPKH: the destination DEP-06 names for
//!   lottery-recovery funds, where the respectful confiscation's change
//!   already goes. The fee is fixed so every recovery voter rebuilds the
//!   same sweep, and a `lottery_recovery_sign` request gathers the leaf's
//!   threshold. The sweep is byte-identical to cl-deposits'
//!   `build-lottery-recovery`, so cl and reference voters sign each other's.
//!
//! [`dispute_lottery_n_from_history`]: super::dispute::dispute_lottery_n_from_history

use super::dispute::recovery_voters_from_updates;
use super::*;

use bitcoin::secp256k1::XOnlyPublicKey;
use bitcoin::{OutPoint, ScriptBuf, Transaction, TxOut};
use deposits_core::tapscript_reserves::{
    LotteryOutput, LotteryParticipant, LotteryScriptBuilder, ReservesSpendBuilder,
};

/// Blocks past the point the reference would otherwise confiscate (the
/// second arm) that a proposer waits for every recovery voter to arm
/// before confiscating with fewer. The same 720 as the reference's own
/// auto-dispute hold-off (`auto_dispute_expired_quorums`) and cl-deposits'
/// `*full-arming-wait-blocks*`: a member whose daemon only auto-arms at
/// `quorum_expiry + 720` still makes it in.
pub(crate) const FULL_ARMING_WAIT_BLOCKS: u32 = 720;

/// Fixed fee of the recovery sweep, so every voter rebuilds the same tx
/// (cl-deposits `*lottery-recovery-fee*`).
pub(crate) const LOTTERY_RECOVERY_FEE_SATS: u64 = 500;

/// CSV of the first recovery leaf (threshold `T`), the one the sweep spends.
pub(crate) const LOTTERY_RECOVERY_CSV: u32 = 144;

/// Seconds a `lottery_recovery_sign` request is waited on before it is
/// re-sent (as `collect_confiscation_signatures`).
const LOTTERY_RECOVERY_REQUEST_TIMEOUT_SECS: u64 = 120;

/// Whether a lottery's claim leaf can still be satisfied, judged from the
/// preimages revealed so far (cl-deposits `lottery-claimable`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LotteryClaimability {
    /// Every participant revealed, each within the claim leaf's bounds.
    Claimable,
    /// A revealed preimage is longer than the claim leaf's `16 + k`: the
    /// lottery can never be claimed.
    Unclaimable { preimage_len: usize, max_len: usize },
    /// Nothing out of bounds yet, but not every participant has revealed.
    Unknown,
}

/// `preimages` is parallel to the lottery's participants (`k` =
/// `preimages.len()`), `None` where that participant has not revealed.
pub(crate) fn lottery_claimability(preimages: &[Option<Vec<u8>>]) -> LotteryClaimability {
    let max_len = 16 + preimages.len();
    if let Some(preimage_len) = preimages
        .iter()
        .flatten()
        .map(|p| p.len())
        .find(|len| *len > max_len)
    {
        return LotteryClaimability::Unclaimable {
            preimage_len,
            max_len,
        };
    }
    if preimages.iter().all(|p| p.is_some()) {
        LotteryClaimability::Claimable
    } else {
        LotteryClaimability::Unknown
    }
}

/// The CSV-144 recovery sweep of a lottery output, unsigned, with what it
/// takes to sign and assemble it.
#[derive(Debug, Clone)]
pub(crate) struct LotteryRecoverySweep {
    /// Unsigned sweep: v2, locktime 0, one input (the lottery output,
    /// nSequence 144), one output to the original operator's P2WPKH.
    pub tx: Transaction,
    /// The lottery output being spent (value, lottery scriptPubKey).
    pub prevout: TxOut,
    /// The CSV-144 recovery leaf.
    pub leaf_script: ScriptBuf,
    pub control_block: bitcoin::taproot::ControlBlock,
    /// The lottery's output key, to check the control block against.
    pub output_key: XOnlyPublicKey,
    /// Recovery voters in the leaf's key order (sorted x-only).
    pub voters: Vec<XOnlyPublicKey>,
    /// Signatures the leaf requires.
    pub threshold: usize,
    /// BIP-341 script-path sighash (SIGHASH_DEFAULT) over `leaf_script`.
    pub sighash: [u8; 32],
}

/// Build the recovery sweep of `lottery`'s output at `lottery_outpoint`
/// (the confiscation's vout 0) to `original_operator` (the disputed
/// ledger's LedgerOpen operator). Deterministic, so every voter rebuilds
/// the identical tx; byte-for-byte cl-deposits' `build-lottery-recovery`.
pub(crate) fn build_lottery_recovery_sweep(
    lottery: &LotteryOutput,
    lottery_outpoint: OutPoint,
    lottery_value: u64,
    original_operator: &bitcoin::secp256k1::PublicKey,
) -> Result<LotteryRecoverySweep, String> {
    use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
    use bitcoin::taproot::{LeafVersion, TapLeafHash};
    use bitcoin::{Amount, Sequence, TxIn, Witness};

    let (_, threshold, leaf_script) = lottery
        .recovery_leaves()
        .into_iter()
        .find(|(csv, _, _)| *csv == LOTTERY_RECOVERY_CSV)
        .ok_or_else(|| "lottery has no CSV-144 recovery leaf".to_string())?;
    let control_block = lottery
        .recovery_control_block(&leaf_script)
        .ok_or_else(|| "recovery leaf is not in the lottery's tree".to_string())?;

    let value = lottery_value
        .checked_sub(LOTTERY_RECOVERY_FEE_SATS)
        .filter(|v| *v > 0)
        .ok_or_else(|| {
            format!(
                "lottery output of {} sats does not cover the {} sat fee",
                lottery_value, LOTTERY_RECOVERY_FEE_SATS
            )
        })?;
    // 0x00 0x14 || HASH160(operator33): the respectful confiscation's
    // change destination.
    let destination =
        ScriptBuf::new_p2wpkh(&bitcoin::CompressedPublicKey(*original_operator).wpubkey_hash());

    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: lottery_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::from_consensus(LOTTERY_RECOVERY_CSV),
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: destination,
        }],
    };
    let prevout = TxOut {
        value: Amount::from_sat(lottery_value),
        script_pubkey: lottery.script_pubkey(),
    };
    let sighash = SighashCache::new(&tx)
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(std::slice::from_ref(&prevout)),
            TapLeafHash::from_script(&leaf_script, LeafVersion::TapScript),
            TapSighashType::Default,
        )
        .map_err(|e| format!("recovery sighash: {}", e))?;

    Ok(LotteryRecoverySweep {
        tx,
        prevout,
        leaf_script,
        control_block,
        output_key: lottery.spend_info.output_key().to_x_only_public_key(),
        voters: lottery.recovery_voter_order(),
        threshold,
        sighash: *sighash.as_ref(),
    })
}

/// The signer of a `lottery_recovery_sign` response, if its signature is a
/// valid BIP-340 signature over the sweep's sighash by a recovery voter.
pub(crate) fn verify_lottery_recovery_signature(
    sweep: &LotteryRecoverySweep,
    signer: &bitcoin::secp256k1::PublicKey,
    signature: &[u8],
) -> Option<XOnlyPublicKey> {
    let xonly = signer.x_only_public_key().0;
    if !sweep.voters.contains(&xonly) {
        return None;
    }
    let sig = bitcoin::secp256k1::schnorr::Signature::from_slice(signature).ok()?;
    let msg = bitcoin::secp256k1::Message::from_digest(sweep.sighash);
    Secp256k1::verification_only()
        .verify_schnorr(&sig, &msg, &xonly)
        .ok()
        .map(|_| xonly)
}

/// Assemble the signed sweep: signatures parallel to the sorted voter keys,
/// reversed onto the stack for the leaf's CHECKSIGADD chain with an empty
/// push per absent signer, then the leaf script and control block
/// (cl-deposits `recovery-witness`). Every signature and the control block
/// are checked first; we have no script interpreter to run the spend.
pub(crate) fn assemble_lottery_recovery(
    sweep: &LotteryRecoverySweep,
    signatures: &HashMap<XOnlyPublicKey, [u8; 64]>,
) -> Result<Transaction, String> {
    let secp = Secp256k1::verification_only();
    let msg = bitcoin::secp256k1::Message::from_digest(sweep.sighash);
    let ordered: Vec<Option<[u8; 64]>> = sweep
        .voters
        .iter()
        .map(|k| signatures.get(k).copied())
        .collect();
    for (key, sig) in sweep.voters.iter().zip(&ordered) {
        if let Some(sig) = sig {
            let parsed = bitcoin::secp256k1::schnorr::Signature::from_slice(sig)
                .map_err(|e| format!("signature by {}: {}", key, e))?;
            secp.verify_schnorr(&parsed, &msg, key)
                .map_err(|_| format!("signature by {} does not verify", key))?;
        }
    }
    let present = ordered.iter().filter(|s| s.is_some()).count();
    if present < sweep.threshold {
        return Err(format!(
            "only {} of {} recovery signatures",
            present, sweep.threshold
        ));
    }
    if !sweep.control_block.verify_taproot_commitment(
        &secp,
        sweep.output_key,
        &sweep.leaf_script,
    ) {
        return Err("control block does not commit to the recovery leaf".to_string());
    }

    let witness = if sweep.threshold == 1 {
        // A threshold-1 leaf names only the lowest sorted key.
        let sig = ordered[0].ok_or_else(|| {
            "threshold-1 recovery leaf needs the lowest voter's signature".to_string()
        })?;
        let mut w = bitcoin::Witness::new();
        w.push(sig);
        w.push(sweep.leaf_script.as_bytes());
        w.push(sweep.control_block.serialize());
        w
    } else {
        ReservesSpendBuilder::create_checksigadd_witness(
            &ordered,
            &sweep.leaf_script,
            &sweep.control_block,
        )
    };
    let mut tx = sweep.tx.clone();
    tx.input[0].witness = witness;
    Ok(tx)
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
    let mut r = &bytes[..];
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

/// A recovery voter's checks before signing a proposed sweep
/// (cl-deposits `handle-lottery-recovery-sign`): the lottery can never be
/// claimed, its output is past the leaf's CSV, and the proposal is exactly
/// the sweep we rebuild ourselves (same txid, same sighash).
pub(crate) fn check_lottery_recovery_proposal(
    claimability: LotteryClaimability,
    lottery_confirmations: u32,
    ours: &LotteryRecoverySweep,
    proposed: &Transaction,
    claimed_sighash: &[u8; 32],
) -> Result<(), String> {
    if !matches!(claimability, LotteryClaimability::Unclaimable { .. }) {
        return Err("the lottery can still be claimed".to_string());
    }
    if lottery_confirmations < LOTTERY_RECOVERY_CSV {
        return Err(format!(
            "recovery leaf not open yet (CSV {}, lottery output has {} confirmations)",
            LOTTERY_RECOVERY_CSV, lottery_confirmations
        ));
    }
    if proposed.compute_txid() != ours.tx.compute_txid() || *claimed_sighash != ours.sighash {
        return Err("not the sweep we expect".to_string());
    }
    Ok(())
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
    /// The disputed ledger's LedgerOpen operator.
    pub original_operator: bitcoin::secp256k1::PublicKey,
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

/// A `lottery_recovery_sign` request awaiting signatures.
pub(crate) struct PendingLotteryRecovery {
    request_id: String,
    /// Txid of the sweep the request is for; a rebuilt sweep that differs
    /// drops the request.
    txid: bitcoin::Txid,
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

        // Paginated fetch — bloated forks (thousands of duplicate
        // QuorumAddMember rows pre-2d3ae43 dedup-fix) overflow a single
        // 500-event window and would hide DisputeArmed at the tail.
        let updates = self.fetch_all_ledger_updates_paginated(ledger_id).await;

        let reveal_filter = Filter::new()
            .kind(Kind::Custom(crate::nostr::KIND_LEDGER_REQUEST))
            .custom_tag(crate::nostr::TAG_LEDGER_REQ, [ledger_id])
            .limit(100);
        let reveal_events = self
            .nostr
            .fetch_client()
            .fetch_events(vec![reveal_filter], None)
            .await
            .map_err(|e| Error::Protocol(format!("Failed to fetch reveals: {}", e)))?;

        // One participant per armer: a re-arm (collateral upgrade) repeats
        // DisputeArmed with the same commitment, and a duplicate would put
        // the wrong k into the claim leaf (as `initiate_confiscations`).
        let mut participants: Vec<(bitcoin::secp256k1::PublicKey, LotteryParticipant)> =
            Vec::new();
        let mut our_armed = None;
        let mut original_operator = None;
        for update in &updates {
            match LedgerOperation::tlv_decode(&update.message) {
                Ok(LedgerOperation::LedgerOpen { operator_id, .. }) => {
                    original_operator = Some(operator_id);
                }
                Ok(LedgerOperation::DisputeArmed {
                    commitment_hash,
                    target_reserves,
                    ..
                }) => {
                    let x_only = update.operator_id.x_only_public_key().0;
                    if !participants.iter().any(|(_, p)| p.pubkey == x_only) {
                        participants.push((
                            update.operator_id,
                            LotteryParticipant::new(x_only, commitment_hash, target_reserves),
                        ));
                    }
                    if update.operator_id == self.node_id {
                        our_armed = Some(update.clone());
                    }
                }
                _ => {}
            }
        }
        if participants.is_empty() {
            return Err(Error::Protocol(
                "No DisputeArmed participants found".to_string(),
            ));
        }
        participants.sort_by(|a, b| a.1.pubkey.serialize().cmp(&b.1.pubkey.serialize()));

        // Preimages are matched to participants by HASH160(preimage) ==
        // commitment_hash, NOT by the reveal event's author key. The
        // reveal is a Nostr request authored by the node's Nostr/delegate
        // key, which is NOT the same as the participant's on-chain
        // (bitcoin x-only) operator key committed in DisputeArmed. Keying
        // the preimage map by `event.pubkey` and looking it up by the
        // participant's x-only key therefore never matched, and the claim
        // stalled forever on "Missing preimage from participant". The
        // commitment hash is the authorless, cryptographically-bound link.
        let mut revealed: Vec<Vec<u8>> = Vec::new();
        for event in reveal_events.iter() {
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
            if let Some(preimage) = serde_json::from_str::<serde_json::Value>(&event.content)
                .ok()
                .and_then(|c| c.get("preimage")?.as_str().map(str::to_string))
                .and_then(|h| hex::decode(h).ok())
            {
                if !revealed.contains(&preimage) {
                    revealed.push(preimage);
                }
            }
        }
        let preimages = participants
            .iter()
            .map(|(_, p)| {
                revealed
                    .iter()
                    .find(|r| hash160::Hash::hash(r).to_byte_array() == p.commitment_hash)
                    .cloned()
            })
            .collect();

        // Recovery voters MUST come from the latest QuorumBegin (minus
        // operator): the set the confiscation's lottery output commits to.
        let (recovery_voters, recovery_threshold) = recovery_voters_from_updates(&updates)
            .ok_or_else(|| {
                Error::Protocol(
                    "No QuorumBegin/LedgerOpen found to derive recovery voters".to_string(),
                )
            })?;
        let original_operator = original_operator
            .ok_or_else(|| Error::Protocol("No LedgerOpen found".to_string()))?;

        Ok(LotteryContext {
            participants,
            preimages,
            recovery_voters,
            recovery_threshold,
            original_operator,
            our_armed,
        })
    }

    fn lottery_outpoint_file(&self, ledger_id: &str) -> PathBuf {
        self.data_dir.join(format!(
            "lottery_outpoint_{}.txt",
            &ledger_id[..16.min(ledger_id.len())]
        ))
    }

    /// The lottery output: `(outpoint, value, unspent)`. While it is
    /// unspent we record where it is, so that once a sweep (ours or another
    /// voter's) has spent it we can still rebuild that sweep and find it.
    fn locate_lottery_output(
        &self,
        ledger_id: &str,
        lottery: &LotteryOutput,
    ) -> Result<Option<(OutPoint, u64, bool)>, Error> {
        let file = self.lottery_outpoint_file(ledger_id);
        if let Some((outpoint, value)) = self.wallet.find_utxo_for_script(&lottery.script_pubkey())?
        {
            if !file.exists() {
                if let Err(e) =
                    std::fs::write(&file, format!("{}:{}:{}", outpoint.txid, outpoint.vout, value))
                {
                    tracing::warn!("Failed to record lottery outpoint: {}", e);
                }
            }
            return Ok(Some((outpoint, value, true)));
        }
        let recorded = std::fs::read_to_string(&file).ok().and_then(|s| {
            let mut parts = s.trim().split(':');
            let txid: bitcoin::Txid = parts.next()?.parse().ok()?;
            let vout: u32 = parts.next()?.parse().ok()?;
            let value: u64 = parts.next()?.parse().ok()?;
            Some((OutPoint::new(txid, vout), value, false))
        });
        Ok(recorded)
    }

    /// Whether the (deterministic) recovery sweep is in the chain or the
    /// mempool, whoever broadcast it.
    fn lottery_sweep_seen(&self, sweep: &LotteryRecoverySweep) -> bool {
        let txid = sweep.tx.compute_txid();
        let backend = crate::chain_backend::from_env(self.wallet.electrum_url());
        matches!(backend.is_output_unspent(&txid, 0), Ok(Some(_)))
            || matches!(backend.get_tx(&txid), Ok(Some(_)))
    }

    /// Drive an unclaimable lottery (`try_lottery_claim_or_yield` found a
    /// revealed preimage out of the claim leaf's bounds): wait for the
    /// recovery leaf's CSV, gather the threshold and broadcast the sweep,
    /// and once a sweep is on chain stand down with a DisputeYield.
    /// `Ok(true)` when the dispute is concluded.
    pub(crate) async fn recover_unclaimable_lottery(
        &self,
        ledger_id: &str,
        ctx: &LotteryContext,
        our_armed: &deposits_core::SignedLedgerUpdate,
    ) -> Result<bool, Error> {
        let ledger_prefix = &ledger_id[..16.min(ledger_id.len())];
        let lottery = ctx.build_lottery(self.wallet.network())?;
        let (outpoint, value, unspent) = self
            .locate_lottery_output(ledger_id, &lottery)?
            .ok_or_else(|| Error::Protocol("lottery output not found".to_string()))?;
        let sweep = build_lottery_recovery_sweep(&lottery, outpoint, value, &ctx.original_operator)
            .map_err(Error::Protocol)?;

        if self.lottery_sweep_seen(&sweep) {
            tracing::info!(
                "Lottery for {} could not be claimed; recovered to the operator (sweep {}). \
                 Publishing DisputeYield.",
                ledger_prefix,
                sweep.tx.compute_txid()
            );
            self.pending_lottery_recoveries
                .lock()
                .unwrap()
                .remove(ledger_id);
            self.publish_custody_yield(ledger_id, our_armed).await?;
            let _ = std::fs::remove_file(self.lottery_outpoint_file(ledger_id));
            return Ok(true);
        }
        if !unspent {
            return Err(Error::Protocol(
                "lottery output spent, but not by the recovery sweep".to_string(),
            ));
        }

        let confirmations = self
            .wallet
            .get_outpoint_value_and_confs(outpoint.txid, outpoint.vout)?
            .map(|(_, c)| c)
            .unwrap_or(0);
        if confirmations < LOTTERY_RECOVERY_CSV {
            return Err(Error::Protocol(format!(
                "lottery cannot be claimed (a preimage is out of the claim leaf's bounds); \
                 its recovery leaf opens after {} confirmations ({} now)",
                LOTTERY_RECOVERY_CSV, confirmations
            )));
        }

        self.propose_lottery_recovery(ledger_id, &sweep).await?;
        Ok(false)
    }

    /// Our signature plus `lottery_recovery_sign` requests until the leaf's
    /// threshold is met, then assemble and broadcast. Non-blocking like
    /// `initiate_confiscations`: a request is sent once, and the responses
    /// are collected on the following periodic passes.
    async fn propose_lottery_recovery(
        &self,
        ledger_id: &str,
        sweep: &LotteryRecoverySweep,
    ) -> Result<(), Error> {
        use deposits_signer_api::{SigPurpose, SignContext};

        let ledger_prefix = &ledger_id[..16.min(ledger_id.len())];
        let txid = sweep.tx.compute_txid();
        let our_xonly = self.node_id.x_only_public_key().0;
        if !sweep.voters.contains(&our_xonly) {
            return Err(Error::Protocol("not a recovery voter".to_string()));
        }

        // A request in flight for this sweep: collect what has come back.
        let in_flight = {
            let mut pending = self.pending_lottery_recoveries.lock().unwrap();
            match pending.get(ledger_id) {
                Some(p)
                    if p.txid == txid
                        && p.created_at.elapsed().as_secs()
                            < LOTTERY_RECOVERY_REQUEST_TIMEOUT_SECS =>
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
            let signatures = {
                let mut pending = self.pending_lottery_recoveries.lock().unwrap();
                let p = match pending.get_mut(ledger_id) {
                    Some(p) => p,
                    None => return Ok(()),
                };
                for (signer, sig) in responses {
                    match verify_lottery_recovery_signature(sweep, &signer, &sig) {
                        Some(xonly) if !p.signatures.contains_key(&xonly) => {
                            let mut arr = [0u8; 64];
                            arr.copy_from_slice(&sig);
                            p.signatures.insert(xonly, arr);
                            tracing::info!(
                                "Lottery recovery {}: signature from {}... ({}/{})",
                                ledger_prefix,
                                &signer.to_string()[..16],
                                p.signatures.len(),
                                sweep.threshold
                            );
                        }
                        Some(_) => {}
                        None => tracing::warn!(
                            "Lottery recovery {}: ignoring a signature from {}... that does not \
                             verify for a recovery voter",
                            ledger_prefix,
                            &signer.to_string()[..16]
                        ),
                    }
                }
                if p.signatures.len() < sweep.threshold {
                    return Ok(());
                }
                pending.remove(ledger_id).map(|p| p.signatures)
            };
            if let Some(signatures) = signatures {
                self.broadcast_lottery_recovery(ledger_prefix, sweep, &signatures);
            }
            return Ok(());
        }

        let our_sig = self
            .handler
            .signer
            .bip340_sign(
                &SignContext::no_ledger(SigPurpose::OnchainSighash),
                &sweep.sighash,
            )
            .map_err(|e| Error::Protocol(format!("lottery recovery sighash sign: {}", e)))?;
        let mut signatures = HashMap::new();
        signatures.insert(our_xonly, our_sig);
        if signatures.len() >= sweep.threshold {
            self.broadcast_lottery_recovery(ledger_prefix, sweep, &signatures);
            return Ok(());
        }

        let params = serde_json::json!({
            "sighash": hex::encode(sweep.sighash),
            "unsigned_tx": hex::encode(bitcoin::consensus::encode::serialize(&sweep.tx)),
        });
        let request_id = self
            .nostr
            .send_ledger_request(ledger_id, "lottery_recovery_sign", params)
            .await
            .map_err(|e| Error::Protocol(format!("send lottery_recovery_sign: {:?}", e)))?;
        self.track_sent_event(&request_id);
        tracing::info!(
            "Lottery for {} cannot be claimed; requested recovery signatures ({} needed) for \
             sweep {} of {} sats to the operator",
            ledger_prefix,
            sweep.threshold,
            txid,
            sweep.tx.output[0].value.to_sat()
        );
        self.pending_lottery_recoveries.lock().unwrap().insert(
            ledger_id.to_string(),
            PendingLotteryRecovery {
                request_id,
                txid,
                signatures,
                created_at: std::time::Instant::now(),
            },
        );
        Ok(())
    }

    fn broadcast_lottery_recovery(
        &self,
        ledger_prefix: &str,
        sweep: &LotteryRecoverySweep,
        signatures: &HashMap<XOnlyPublicKey, [u8; 64]>,
    ) {
        let signed = match assemble_lottery_recovery(sweep, signatures) {
            Ok(tx) => tx,
            Err(e) => {
                tracing::error!("Lottery recovery {}: assembly failed: {}", ledger_prefix, e);
                return;
            }
        };
        match self.wallet.broadcast(&signed) {
            Ok(txid) => tracing::info!(
                "Lottery for {} could not be claimed; swept to the operator ({})",
                ledger_prefix,
                txid
            ),
            Err(e) => tracing::error!(
                "Lottery recovery {}: broadcast failed: {}",
                ledger_prefix,
                e
            ),
        }
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
            .since(nostr_sdk::Timestamp::now() - LOTTERY_RECOVERY_REQUEST_TIMEOUT_SECS);
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
            let response = match serde_json::from_str::<crate::nostr::LedgerResponse>(&event.content)
            {
                Ok(r) if r.success => r,
                Ok(r) => {
                    tracing::info!(
                        "lottery_recovery_sign refused: {}",
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

    /// Whether we are a disputant of `ledger_id`: we hold our own fork of it.
    pub(crate) fn is_disputant_of(&self, ledger_id: &str) -> bool {
        let ledgers = self.handler.ledgers.lock().unwrap();
        ledgers.iter().any(|(key, arc)| {
            key.len() > 64
                && key.starts_with(ledger_id)
                && arc.read().unwrap().state.parent_pubkey == self.node_id
        })
    }

    /// Sign another voter's recovery sweep (cl-deposits
    /// `handle-lottery-recovery-sign`): only of a lottery we also find
    /// unclaimable, once its CSV has passed, and only the exact sweep we
    /// rebuild ourselves. The caller answers only if we are a disputant.
    pub(crate) async fn process_lottery_recovery_sign_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        let ledger_prefix = &request.ledger_id[..16.min(request.ledger_id.len())];
        match self.check_lottery_recovery_request(request).await {
            Ok(sighash) => {
                use deposits_signer_api::{SigPurpose, SignContext};
                let signature = match self.handler.signer.bip340_sign(
                    &SignContext::no_ledger(SigPurpose::OnchainSighash),
                    &sighash,
                ) {
                    Ok(s) => s,
                    Err(e) => {
                        return (
                            false,
                            None,
                            Some(format!("lottery recovery sighash sign: {}", e)),
                        )
                    }
                };
                tracing::info!("Signed lottery recovery of {}", ledger_prefix);
                let result = serde_json::json!({
                    "signer": self.node_id_hex.clone(),
                    "signature": hex::encode(signature),
                });
                (true, Some(result.to_string()), None)
            }
            Err(reason) => {
                tracing::info!(
                    "Refused lottery_recovery_sign for {}: {}",
                    ledger_prefix,
                    reason
                );
                (false, None, Some(reason))
            }
        }
    }

    /// The sighash to sign, if the request passes every check.
    async fn check_lottery_recovery_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> Result<[u8; 32], String> {
        let claimed_sighash: [u8; 32] = request
            .params
            .get("sighash")
            .and_then(|v| v.as_str())
            .and_then(|h| hex::decode(h).ok())
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| "missing or invalid sighash".to_string())?;
        let proposed = request
            .params
            .get("unsigned_tx")
            .and_then(|v| v.as_str())
            .and_then(|h| hex::decode(h).ok())
            .ok_or_else(|| "missing or invalid unsigned_tx".to_string())
            .and_then(|b| parse_unsigned_tx(&b))?;

        let ctx = self
            .lottery_context(&request.ledger_id)
            .await
            .map_err(|e| e.to_string())?;
        let claimability = lottery_claimability(&ctx.preimages);
        if !matches!(claimability, LotteryClaimability::Unclaimable { .. }) {
            return Err("the lottery can still be claimed".to_string());
        }
        let lottery = ctx
            .build_lottery(self.wallet.network())
            .map_err(|e| e.to_string())?;
        let (outpoint, value, unspent) = self
            .locate_lottery_output(&request.ledger_id, &lottery)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "no lottery output on chain".to_string())?;
        if !unspent {
            return Err("no pending lottery on chain".to_string());
        }
        let confirmations = self
            .wallet
            .get_outpoint_value_and_confs(outpoint.txid, outpoint.vout)
            .map_err(|e| e.to_string())?
            .map(|(_, c)| c)
            .unwrap_or(0);
        let ours = build_lottery_recovery_sweep(&lottery, outpoint, value, &ctx.original_operator)?;
        check_lottery_recovery_proposal(
            claimability,
            confirmations,
            &ours,
            &proposed,
            &claimed_sighash,
        )?;
        Ok(ours.sighash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Keypair, SecretKey};
    use bitcoin::Network;

    fn secret(seed: u8) -> SecretKey {
        SecretKey::from_slice(&[seed; 32]).unwrap()
    }
    fn pubkey(seed: u8) -> bitcoin::secp256k1::PublicKey {
        bitcoin::secp256k1::PublicKey::from_secret_key(&Secp256k1::new(), &secret(seed))
    }
    fn xonly(seed: u8) -> XOnlyPublicKey {
        pubkey(seed).x_only_public_key().0
    }

    /// Fixed inputs shared with the cl-deposits vector below: operator
    /// seed 0x11, recovery voters seeds 21..23 (T = 2), participants seeds
    /// 1 and 2 with commitments [i; 20], signet.
    fn fixture_lottery() -> LotteryOutput {
        let mut participants: Vec<LotteryParticipant> = (1..=2u8)
            .map(|i| LotteryParticipant::new(xonly(i), [i; 20], format!("tb1p{}", i)))
            .collect();
        participants.sort_by(|a, b| a.pubkey.serialize().cmp(&b.pubkey.serialize()));
        LotteryScriptBuilder::new(
            participants,
            vec![xonly(21), xonly(22), xonly(23)],
            2,
            Network::Signet,
        )
        .build()
        .unwrap()
    }
    fn fixture_outpoint() -> OutPoint {
        let mut bytes = [0u8; 32];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = i as u8;
        }
        OutPoint::new(bitcoin::Txid::from_byte_array(bytes), 0)
    }
    fn fixture_sweep() -> LotteryRecoverySweep {
        build_lottery_recovery_sweep(&fixture_lottery(), fixture_outpoint(), 478_907, &pubkey(0x11))
            .unwrap()
    }
    fn sign(seed: u8, sighash: [u8; 32]) -> [u8; 64] {
        let kp = Keypair::from_secret_key(&Secp256k1::new(), &secret(seed));
        Secp256k1::new()
            .sign_schnorr_no_aux_rand(&bitcoin::secp256k1::Message::from_digest(sighash), &kp)
            .serialize()
    }

    #[test]
    fn claimability_bounds_on_k_not_q() {
        use LotteryClaimability::*;
        // k = 2 participants: the claim leaf accepts 17..=18 bytes.
        assert_eq!(
            lottery_claimability(&[Some(vec![0; 18]), Some(vec![0; 17])]),
            Claimable
        );
        assert_eq!(lottery_claimability(&[Some(vec![0; 18]), None]), Unknown);
        // A 19-byte preimage (committed under Q = 3) can never be claimed,
        // even before the other participant reveals (ledger F on the devnet).
        assert_eq!(
            lottery_claimability(&[Some(vec![0; 19]), None]),
            Unclaimable {
                preimage_len: 19,
                max_len: 18
            }
        );
        assert_eq!(
            lottery_claimability(&[Some(vec![0; 18]), Some(vec![0; 19])]),
            Unclaimable {
                preimage_len: 19,
                max_len: 18
            }
        );
        // k = 3: 19 bytes is within bounds.
        assert_eq!(
            lottery_claimability(&[Some(vec![0; 19]), Some(vec![0; 17]), Some(vec![0; 18])]),
            Claimable
        );
    }

    #[test]
    fn sweep_has_the_exact_fields() {
        let lottery = fixture_lottery();
        let sweep = fixture_sweep();
        let tx = &sweep.tx;
        assert_eq!(tx.version, bitcoin::transaction::Version::TWO);
        assert_eq!(tx.lock_time, bitcoin::absolute::LockTime::ZERO);
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.input[0].previous_output, fixture_outpoint());
        assert_eq!(tx.input[0].sequence.to_consensus_u32(), 144);
        assert!(tx.input[0].script_sig.is_empty());
        assert_eq!(tx.output.len(), 1);
        assert_eq!(tx.output[0].value.to_sat(), 478_907 - 500);
        let mut spk = vec![0x00, 0x14];
        spk.extend_from_slice(
            &bitcoin::hashes::hash160::Hash::hash(&pubkey(0x11).serialize()).to_byte_array(),
        );
        assert_eq!(tx.output[0].script_pubkey.as_bytes(), &spk[..]);
        // The first recovery leaf: after the claim leaf (no partial-reveal
        // leaves at k = 2), CSV 144 with threshold T.
        assert_eq!(sweep.leaf_script, lottery.recovery_leaves()[0].2);
        assert_eq!(sweep.threshold, 2);
        assert_eq!(sweep.prevout.value.to_sat(), 478_907);
        assert_eq!(sweep.prevout.script_pubkey, lottery.script_pubkey());
        assert_eq!(sweep.voters, lottery.recovery_voter_order());
        // Too small to pay the fee.
        assert!(
            build_lottery_recovery_sweep(&lottery, fixture_outpoint(), 500, &pubkey(0x11))
                .is_err()
        );
    }

    /// Cross-implementation vector: the same inputs through cl-deposits
    /// (`lot:build-lottery`, the tx `build-lottery-recovery` makes,
    /// `rot:tier-sighash`, `lot:recovery-witness`), printed by a script
    /// run against cl-deposits 403d451.
    #[test]
    fn sweep_matches_cl_deposits() {
        let sweep = fixture_sweep();
        assert_eq!(
            hex::encode(pubkey(0x11).serialize()),
            "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa"
        );
        assert_eq!(
            hex::encode(sweep.prevout.script_pubkey.as_bytes()),
            "512044ded9ce0ee8379eb1250ee49adc8244afca3fd827dd332f2fc0f151866f2f38"
        );
        // Legacy (txid) serialization.
        assert_eq!(
            hex::encode(bitcoin::consensus::encode::serialize(&sweep.tx)),
            "0200000001000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000000\
             009000000001c74c070000000000160014fc7250a211deddc70ee5a2738de5f07817351cef00000000"
        );
        assert_eq!(
            sweep.tx.compute_txid().to_string(),
            "ec81d43a32d4732a10e8059e9ee342034f2a7f5113656e8a92d10e8c0a56c8f4"
        );
        assert_eq!(
            hex::encode(sweep.sighash),
            "917d9df1e89714775932177886a560e18ac535f8d777ab657e7ad82d0551a0f1"
        );
        assert_eq!(
            hex::encode(sweep.leaf_script.as_bytes()),
            "029000b2752057eb3638f51f4dc5c8d5a7324b47df99e816cfcc5b5eb1245bc8c98029f9e674ac20a8\
             397a935f0dfceba6ba9618f6451ef4d80637abf4e6af2669fbc9de6a8fd2acba20d793631af7aa0e70\
             9439dd47fc001acd0b0727670b6670ea528ac83cb0127f4aba52a2"
        );
        assert_eq!(
            hex::encode(sweep.control_block.serialize()),
            "c050929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0ae8c2bdd99e3f908\
             e401e8f15b81d98ad8b16adbdfb149d36384272edb469b860df5c8f42aceda9d55e9de18e48d196679\
             2527cd396fae3a647a87f19330fa0aade24b3a859986ba2a2fdc0e68b4cbe2a5f09d885e445fb9ad2c\
             72d8858c31aa"
        );
        // cl's wire form of the unsigned tx: segwit marker with an empty
        // witness. It must parse, to the same tx.
        let cl_wire = hex::decode(
            "02000000000101000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00\
             000000009000000001c74c070000000000160014fc7250a211deddc70ee5a2738de5f07817351cef\
             0000000000",
        )
        .unwrap();
        assert!(bitcoin::consensus::encode::deserialize::<Transaction>(&cl_wire).is_err());
        assert_eq!(parse_unsigned_tx(&cl_wire).unwrap(), sweep.tx);
        assert_eq!(
            parse_unsigned_tx(&bitcoin::consensus::encode::serialize(&sweep.tx)).unwrap(),
            sweep.tx
        );

        // Witness layout, with stand-in signatures for the first and third
        // sorted voters and none for the second (cl `recovery-witness`
        // with (aa.. nil cc..)): the check is layout only, so bypass the
        // signature verification by building through the same helper.
        let ordered = vec![Some([0xaa; 64]), None, Some([0xcc; 64])];
        let witness = ReservesSpendBuilder::create_checksigadd_witness(
            &ordered,
            &sweep.leaf_script,
            &sweep.control_block,
        );
        let items: Vec<String> = witness.iter().map(hex::encode).collect();
        assert_eq!(items[0], "cc".repeat(64));
        assert_eq!(items[1], "");
        assert_eq!(items[2], "aa".repeat(64));
        assert_eq!(items[3], hex::encode(sweep.leaf_script.as_bytes()));
        assert_eq!(items[4], hex::encode(sweep.control_block.serialize()));
        assert_eq!(items.len(), 5);
    }

    #[test]
    fn assembly_verifies_signatures_and_threshold() {
        let sweep = fixture_sweep();
        let mut sigs = HashMap::new();
        sigs.insert(xonly(21), sign(21, sweep.sighash));
        assert!(assemble_lottery_recovery(&sweep, &sigs)
            .unwrap_err()
            .contains("only 1 of 2"));
        sigs.insert(xonly(23), sign(23, sweep.sighash));
        let tx = assemble_lottery_recovery(&sweep, &sigs).unwrap();
        assert_eq!(tx.compute_txid(), sweep.tx.compute_txid());
        let w: Vec<&[u8]> = tx.input[0].witness.iter().collect();
        assert_eq!(w.len(), 5);
        // Parallel to the sorted keys, reversed onto the stack.
        let order = &sweep.voters;
        for (slot, key) in order.iter().rev().enumerate() {
            match sigs.get(key) {
                Some(s) => assert_eq!(w[slot], &s[..]),
                None => assert!(w[slot].is_empty()),
            }
        }
        // A bad signature is refused, not broadcast.
        sigs.insert(xonly(22), [7u8; 64]);
        assert!(assemble_lottery_recovery(&sweep, &sigs).is_err());

        // Response verification: a voter's real signature, a non-voter's,
        // and a voter's over the wrong message.
        assert_eq!(
            verify_lottery_recovery_signature(&sweep, &pubkey(22), &sign(22, sweep.sighash)),
            Some(xonly(22))
        );
        assert_eq!(
            verify_lottery_recovery_signature(&sweep, &pubkey(9), &sign(9, sweep.sighash)),
            None
        );
        assert_eq!(
            verify_lottery_recovery_signature(&sweep, &pubkey(22), &sign(22, [0u8; 32])),
            None
        );
    }

    #[test]
    fn signer_refuses_claimable_early_or_foreign_sweeps() {
        let sweep = fixture_sweep();
        let unclaimable = LotteryClaimability::Unclaimable {
            preimage_len: 19,
            max_len: 18,
        };
        // The sweep we rebuild, past the CSV: signed.
        assert!(
            check_lottery_recovery_proposal(unclaimable, 144, &sweep, &sweep.tx, &sweep.sighash)
                .is_ok()
        );
        // A lottery that can still be claimed (or may yet be).
        for c in [LotteryClaimability::Claimable, LotteryClaimability::Unknown] {
            assert!(
                check_lottery_recovery_proposal(c, 500, &sweep, &sweep.tx, &sweep.sighash)
                    .unwrap_err()
                    .contains("can still be claimed")
            );
        }
        // Before the CSV.
        assert!(
            check_lottery_recovery_proposal(unclaimable, 143, &sweep, &sweep.tx, &sweep.sighash)
                .unwrap_err()
                .contains("not open yet")
        );
        // A tx that differs from our rebuild: another destination, and a
        // different fee.
        let mut elsewhere = sweep.tx.clone();
        elsewhere.output[0].script_pubkey = ScriptBuf::new_p2wpkh(
            &bitcoin::CompressedPublicKey(pubkey(9)).wpubkey_hash(),
        );
        let mut richer = sweep.tx.clone();
        richer.output[0].value = bitcoin::Amount::from_sat(478_907 - 200);
        for proposed in [elsewhere, richer] {
            assert!(
                check_lottery_recovery_proposal(unclaimable, 200, &sweep, &proposed, &sweep.sighash)
                    .unwrap_err()
                    .contains("not the sweep we expect")
            );
        }
        // Our tx, but a sighash that is not ours.
        assert!(
            check_lottery_recovery_proposal(unclaimable, 200, &sweep, &sweep.tx, &[1u8; 32])
                .is_err()
        );
    }
}
