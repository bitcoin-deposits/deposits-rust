//! DEP-06 Phase 4 re-arm rounds (strict-lottery-v8): a recovery voter's side.
//!
//! An unclaimed lottery output is spent by the recovery quorum, through the first recovery
//! tier its signers reach, into the next round's lottery output. The next round's
//! participants are the arms for that round (`rearm_round`, TLV 366) signed inside the
//! round's window, through the same grounds, accused exclusion and eligibility cut as
//! round 1. The first window that closed with a non-empty cut counts: the scheduled one,
//! its one reopening, then windows recurring every `k` blocks while the output is unspent.
//!
//! A voter signs a re-arm spend (`lottery_rearm_sign`) only if it is, byte for byte, the
//! spend it rebuilds from public state, through a tier whose CSV has passed. This mirrors
//! cl-deposits' `handle-lottery-rearm-sign`; the spend is the shared `rearm_spend.txt`
//! construction and the windows are `rearm_windows.json`.

use super::*;

use bitcoin::secp256k1::XOnlyPublicKey;
use bitcoin::OutPoint;
use deposits_core::tapscript_reserves::{
    rearm_round_opens, rearm_round_window, LotteryOutput, LotteryParticipant, LotteryScriptBuilder,
};
use std::collections::HashMap;

/// The arm window, in blocks, when no quorum member names one (cl's
/// `*default-dispute-arm-blocks*`).
pub(crate) const DEFAULT_DISPUTE_ARM_BLOCKS: u32 = 6;

/// sat/vB a confiscation and a re-arm spend pay while the QuorumBegin records no
/// `reference_feerate_sat_vb` (cl's `+confiscation-default-feerate+`).
pub(crate) const DEFAULT_REARM_FEERATE: u64 = 2;

/// Most re-arm rounds followed: an armer's arms over every round are bounded by
/// `MAX_ARMS`, so a dispute has at most that many rounds with a participant.
const MAX_ROUNDS: u32 = 8;

/// One round's lottery output on chain.
pub(crate) struct RoundLottery {
    pub round: u32,
    pub lottery: LotteryOutput,
    pub outpoint: OutPoint,
    pub value: u64,
    /// The block the output confirmed in.
    pub height: u32,
    /// Whether any of the round's participants has revealed.
    pub revealed: bool,
    /// Round 1's confiscation: a later round's DisputeAcquire names it, as cl's does.
    pub confiscation_txid: bitcoin::Txid,
}

/// The public state a re-arm decision is made from.
pub(crate) struct RearmView {
    pub updates: Vec<deposits_core::SignedLedgerUpdate>,
    pub grounds: super::armers::GroundsVerdicts,
    pub voters: Vec<XOnlyPublicKey>,
    pub threshold: usize,
    pub revealed: Vec<Vec<u8>>,
    pub arm_window: u32,
    pub feerate: u64,
}

/// The newest `QuorumBegin`'s `reference_feerate_sat_vb`, else the default.
pub(crate) fn rearm_feerate(updates: &[deposits_core::SignedLedgerUpdate]) -> u64 {
    use deposits_core::messages::LedgerOperation;
    use deposits_core::tlv::TlvDecode;
    let mut by_seq: Vec<&deposits_core::SignedLedgerUpdate> = updates.iter().collect();
    by_seq.sort_by_key(|u| u.sequence_number);
    by_seq
        .iter()
        .rev()
        .find_map(|u| match LedgerOperation::tlv_decode(&u.message) {
            Ok(LedgerOperation::QuorumBegin {
                reference_feerate, ..
            }) => Some(reference_feerate),
            _ => None,
        })
        .flatten()
        .filter(|f| *f > 0)
        .map(u64::from)
        .unwrap_or(DEFAULT_REARM_FEERATE)
}

/// The dispute's arm window: the largest `dispute_arm_blocks` a quorum member names, else
/// [`DEFAULT_DISPUTE_ARM_BLOCKS`] (cl's `rearm-window`).
pub(crate) fn arm_window_of(named: impl IntoIterator<Item = Option<u32>>) -> u32 {
    named
        .into_iter()
        .flatten()
        .filter(|b| *b > 0)
        .max()
        .unwrap_or(DEFAULT_DISPUTE_ARM_BLOCKS)
}

/// A lottery over `participants` (any order: sorted by x-only key here).
fn lottery_over(
    mut participants: Vec<LotteryParticipant>,
    voters: &[XOnlyPublicKey],
    threshold: usize,
    network: bitcoin::Network,
) -> Result<LotteryOutput, String> {
    participants.sort_by_key(|p| p.pubkey.serialize());
    LotteryScriptBuilder::new(participants, voters.to_vec(), threshold, network)
        .build()
        .map_err(|e| format!("build lottery: {:?}", e))
}

/// Outputs whose spend lies past the chain backend's scan window from where we can start
/// looking (bitcoind walks at most 4320 blocks): unknown to this node, and asked once.
fn spend_unknown() -> &'static std::sync::Mutex<std::collections::HashSet<OutPoint>> {
    static SET: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<OutPoint>>> =
        std::sync::OnceLock::new();
    SET.get_or_init(Default::default)
}

/// Whether a `find_spending_tx` error says the spend is beyond the backend's scan window.
pub(crate) fn is_beyond_scan_window(e: &str) -> bool {
    e.contains("scans stop after")
}

/// `find_spending_tx`, except that a spend beyond the backend's scan window is recorded as
/// unknown with ONE warning and is not looked for again: an old re-arm's every pass re-walked
/// 4320 blocks and logged the same error (ref7 on regtest, 2026-11-19).
fn find_spend_or_unknown(
    chain: &dyn crate::chain_backend::ChainBackend,
    ledger_id: &str,
    outpoint: &OutPoint,
    spk: &bitcoin::Script,
    from: u32,
) -> Result<Option<bitcoin::Transaction>, String> {
    if spend_unknown().lock().unwrap().contains(outpoint) {
        return Ok(None);
    }
    match chain.find_spending_tx(outpoint, spk, from) {
        Ok(t) => Ok(t),
        Err(e) if is_beyond_scan_window(&e.to_string()) => {
            spend_unknown().lock().unwrap().insert(*outpoint);
            tracing::warn!(
                "re-arm {}: the spend of {} is beyond this backend's scan window from {}; \
                 treated as unknown and not looked for again ({})",
                &ledger_id[..16.min(ledger_id.len())],
                outpoint,
                from,
                e
            );
            Ok(None)
        }
        Err(e) => Err(e.to_string()),
    }
}

impl Node {
    /// The public state for re-arm decisions on `ledger_id`.
    pub(crate) async fn rearm_view(&self, ledger_id: &str) -> Result<RearmView, String> {
        // The whole chain, as round 1's cut (`lottery_armer_set`): a later round's cut splits
        // the armers' collateral at its window's close by replaying the ledger, which a
        // `t`-filtered fetch cannot ("replay failed at seq 8: DepositNotFound", rearm-mixed).
        // A sign request is rare; the claim task's periodic keeps the filtered fetch.
        let updates = self.fetch_all_ledger_updates_paginated(ledger_id).await;
        if updates.is_empty() {
            return Err("no ledger updates on the relay".into());
        }
        let grounds = Box::pin(self.grounds_verdicts(&updates)).await;
        let (voters, threshold) = super::armers::lottery_voters_with(&updates, &grounds)
            .ok_or("no QuorumBegin to derive the recovery voters from")?;
        let revealed = self.revealed_lottery_preimages(ledger_id, &updates).await;
        let members = self
            .get_ledger(ledger_id)
            .map(|l| {
                if l.state.quorum_members.is_empty() {
                    l.state.quorum_at_fork.clone()
                } else {
                    l.state.quorum_members.clone()
                }
            })
            .unwrap_or_default();
        let feerate = rearm_feerate(&updates);
        Ok(RearmView {
            updates,
            grounds,
            voters,
            threshold,
            revealed,
            arm_window: arm_window_of(members.iter().map(|m| m.dispute_arm_blocks)),
            feerate,
        })
    }

    /// Round `round`'s lottery for an output of the previous round confirmed at `prev_height`
    /// (`prev_revealed`: whether any of its participants revealed), as of `tip`: built over
    /// the cut of the first window that closed with a non-empty cut, or `None` while none has.
    /// cl's `rearm-lottery`.
    pub(crate) fn rearm_round_lottery(
        &self,
        view: &RearmView,
        round: u32,
        prev_height: u32,
        prev_revealed: bool,
        tip: u32,
    ) -> Result<Option<(LotteryOutput, Vec<LotteryParticipant>)>, String> {
        let chain = self.wallet.chain_backend();
        let o = rearm_round_opens(prev_height, prev_revealed);
        let rows = super::armers::arm_rows(&view.updates);
        let cut_err: std::cell::RefCell<Option<String>> = std::cell::RefCell::new(None);
        let cut = |opens: u32, closes: u32| -> Option<Vec<LotteryParticipant>> {
            if super::armers::pick_round_arms(&rows, round, opens, closes).is_empty() {
                return None;
            }
            match super::armers::eligible_armers_round(
                &*chain,
                &view.updates,
                round,
                opens,
                closes,
                &view.grounds,
            ) {
                Ok(set) if !set.participants.is_empty() => Some(set.lottery_participants()),
                Ok(_) => None,
                Err(e) => {
                    *cut_err.borrow_mut() = Some(e);
                    None
                }
            }
        };
        let window = rearm_round_window(o, view.arm_window, tip, |a, b| cut(a, b).is_some());
        if let Some(e) = cut_err.borrow_mut().take() {
            return Err(format!("round {} cut: {}", round, e));
        }
        let Some((_, opens, closes)) = window else {
            return Ok(None);
        };
        let participants = cut(opens, closes).ok_or("the window's cut changed")?;
        let lottery = lottery_over(
            participants.clone(),
            &view.voters,
            view.threshold,
            self.wallet.network(),
        )?;
        Ok(Some((lottery, participants)))
    }

    /// The arm set (key, arm sequence per participant) of round `round`'s cut, as
    /// [`Self::rearm_round_lottery`] picks it: the manifest its spend's signers publish.
    pub(crate) fn rearm_round_arm_set(
        &self,
        view: &RearmView,
        round: u32,
        prev_height: u32,
        prev_revealed: bool,
        tip: u32,
    ) -> Option<Vec<(bitcoin::secp256k1::PublicKey, u64)>> {
        let chain = self.wallet.chain_backend();
        let o = rearm_round_opens(prev_height, prev_revealed);
        let rows = super::armers::arm_rows(&view.updates);
        let set_at = |opens: u32, closes: u32| {
            if super::armers::pick_round_arms(&rows, round, opens, closes).is_empty() {
                return None;
            }
            super::armers::eligible_armers_round(
                &*chain,
                &view.updates,
                round,
                opens,
                closes,
                &view.grounds,
            )
            .ok()
            .filter(|s| !s.participants.is_empty())
        };
        let (_, opens, closes) =
            rearm_round_window(o, view.arm_window, tip, |a, b| set_at(a, b).is_some())?;
        Some(
            set_at(opens, closes)?
                .participants
                .iter()
                .map(|a| (a.key, a.arm_seq))
                .collect(),
        )
    }

    /// Round `round`'s lottery from a published arm manifest: one valid in a window of the round
    /// (opening at `o`) that closed at or before `spend_height`, whose lottery pays `spk`.
    pub(crate) async fn manifest_round_lottery(
        &self,
        ledger_id: &str,
        view: &RearmView,
        round: u32,
        o: u32,
        spend_height: u32,
        spk: &bitcoin::ScriptBuf,
    ) -> Option<(LotteryOutput, Vec<LotteryParticipant>)> {
        let manifests = self.arm_manifests(ledger_id, round).await;
        for m in &manifests {
            for j in 0.. {
                let (opens, closes) =
                    deposits_core::tapscript_reserves::rearm_window_nth(o, view.arm_window, j);
                if closes > spend_height {
                    break;
                }
                let Ok(named) = super::armers::collect_manifest_armers(
                    &view.updates,
                    m,
                    round,
                    opens as i64,
                    closes,
                ) else {
                    continue;
                };
                let participants: Vec<LotteryParticipant> =
                    named.into_iter().map(|a| a.participant).collect();
                if let Ok(l) = lottery_over(
                    participants.clone(),
                    &view.voters,
                    view.threshold,
                    self.wallet.network(),
                ) {
                    if &l.script_pubkey() == spk {
                        return Some((l, participants));
                    }
                }
            }
        }
        None
    }

    /// The dispute's newest unspent lottery output: round 1's (the confiscation's first
    /// output), or a later round's, followed through each re-arm spend. `None` once a claim
    /// spent it, or while there is none.
    pub(crate) async fn current_round_lottery(
        &self,
        ledger_id: &str,
        view: &RearmView,
    ) -> Result<Option<RoundLottery>, String> {
        let chain = self.wallet.chain_backend();
        let tip = chain.get_tip_height().map_err(|e| e.to_string())?;
        let ctx = self
            .lottery_context(ledger_id)
            .await
            .map_err(|e| e.to_string())?;
        let mut lottery = ctx
            .build_lottery(self.wallet.network())
            .map_err(|e| e.to_string())?;
        let mut revealed = ctx.preimages.iter().any(|p| p.is_some());
        // Round 1's output is the confiscation's output 0.
        let Some((vault, _)) = super::vault_watch::current_vault(&view.updates) else {
            return Ok(None);
        };
        // Scan from the block the confiscation landed in when the chunked landed-spender search
        // knows it, else from the dispute's first arm (a confiscation cannot precede the arms
        // it pays). A bitcoind scan walks at most 4320 blocks from there; it used to refuse any
        // range to the tip longer than that, so a dispute armed at 582 failed every pass and
        // every lottery_rearm_sign at tip 19166 (regtest rearm-rust 1119-013201).
        if chain
            .is_output_unspent(&vault.txid, vault.vout)
            .map_err(|e| e.to_string())?
            == Some(true)
        {
            return Ok(None); // not confiscated: nothing to walk
        }
        let landed = super::lottery_recovery::confiscation_height(&*chain, &view.updates)
            .or_else(|| super::armers::first_arm_height(&view.updates))
            .unwrap_or(0);
        let Some(confiscation) =
            find_spend_or_unknown(&*chain, ledger_id, &vault, bitcoin::Script::new(), landed)?
        else {
            return Ok(None);
        };
        let mut outpoint = OutPoint {
            txid: confiscation.compute_txid(),
            vout: 0,
        };
        let mut value = confiscation
            .output
            .first()
            .map(|o| o.value.to_sat())
            .unwrap_or(0);
        if confiscation.output.first().map(|o| &o.script_pubkey) != Some(&lottery.script_pubkey()) {
            let keys: Vec<String> = ctx
                .participants
                .iter()
                .map(|(k, _)| hex::encode(&k.serialize()[..4]))
                .collect();
            let voters: Vec<String> = ctx
                .recovery_voters
                .iter()
                .map(|k| hex::encode(&k.serialize()[..4]))
                .collect();
            tracing::info!(
                "re-arm {}: our round-1 lottery: participants [{}], voters [{}] of {}, ruleset {:?}",
                &ledger_id[..16.min(ledger_id.len())],
                keys.join(" "),
                voters.join(" "),
                ctx.recovery_threshold,
                view.grounds.ruleset
            );
            let verdicts: Vec<String> = view
                .grounds
                .by_key
                .iter()
                .map(|(k, (v, w))| format!("{}={:?}({})", hex::encode(&k.serialize()[..4]), v, w))
                .collect();
            let accused: Vec<String> =
                super::armers::dispute_accused_keys(&view.updates, &view.grounds)
                    .iter()
                    .map(|k| hex::encode(&k.serialize()[..4]))
                    .collect();
            tracing::info!(
                "re-arm {}: grounds {}; accused [{}]; view voters {} of {}",
                &ledger_id[..16.min(ledger_id.len())],
                verdicts.join(", "),
                accused.join(" "),
                view.voters.len(),
                view.threshold
            );
            return Err("the confiscation does not pay the lottery we derive".into());
        }
        let Some(mut height) = chain
            .get_tx_block_height(&outpoint.txid)
            .map_err(|e| e.to_string())?
        else {
            return Ok(None);
        };
        let mut round = 1;
        loop {
            if chain
                .is_output_unspent(&outpoint.txid, outpoint.vout)
                .map_err(|e| e.to_string())?
                == Some(true)
            {
                return Ok(Some(RoundLottery {
                    round,
                    lottery,
                    outpoint,
                    value,
                    height,
                    revealed,
                    confiscation_txid: confiscation.compute_txid(),
                }));
            }
            if round >= MAX_ROUNDS {
                return Ok(None);
            }
            let Some(spend) = find_spend_or_unknown(
                &*chain,
                ledger_id,
                &outpoint,
                &lottery.script_pubkey(),
                height,
            )?
            else {
                return Ok(None);
            };
            let Some(spend_height) = chain
                .get_tx_block_height(&spend.compute_txid())
                .map_err(|e| e.to_string())?
            else {
                // In the mempool: judged only once it confirms.
                return Ok(None);
            };
            // A re-arm spend has one input and one output paying the next round's lottery;
            // anything else (a claim) ended the dispute.
            if spend.input.len() != 1 || spend.output.len() != 1 {
                return Ok(None);
            }
            // DEP-03 §Arm manifests (DEP-06 Phase 4 step 5): the next round is the output the
            // confirmed spend pays, its set named by a valid published manifest for the round;
            // re-deriving the window's cut (each armer's latest in-window arm) is the fallback.
            let from_manifest = self
                .manifest_round_lottery(
                    ledger_id,
                    view,
                    round + 1,
                    rearm_round_opens(height, revealed),
                    spend_height,
                    &spend.output[0].script_pubkey,
                )
                .await;
            let (next, participants) = match from_manifest {
                Some(x) => x,
                None => {
                    let Some((next, participants)) =
                        self.rearm_round_lottery(view, round + 1, height, revealed, spend_height)?
                    else {
                        return Ok(None);
                    };
                    if spend.output[0].script_pubkey != next.script_pubkey() {
                        return Ok(None);
                    }
                    (next, participants)
                }
            };
            revealed = super::lottery_recovery::match_revealed_preimages(
                &participants
                    .iter()
                    .map(|p| {
                        (
                            bitcoin::secp256k1::PublicKey::from_x_only_public_key(
                                p.pubkey,
                                bitcoin::secp256k1::Parity::Even,
                            ),
                            p.clone(),
                        )
                    })
                    .collect::<Vec<_>>(),
                &view.revealed,
            )
            .iter()
            .any(|p| p.is_some());
            round += 1;
            lottery = next;
            outpoint = OutPoint {
                txid: spend.compute_txid(),
                vout: 0,
            };
            value = spend.output[0].value.to_sat();
            height = spend_height;
        }
    }

    /// `lottery_rearm_sign`: sign a re-arm recovery spend as a recovery voter.
    pub(crate) async fn process_lottery_rearm_sign_request(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> (bool, Option<String>, Option<String>) {
        let ledger_prefix = &request.ledger_id[..16.min(request.ledger_id.len())];
        match self.check_lottery_rearm_sign(request).await {
            Ok((sighash, round, tier, spend, arms)) => {
                use deposits_signer_api::{SigPurpose, SignContext};
                let signature = match self.handler.signer.bip340_sign(
                    &SignContext::no_ledger(SigPurpose::OnchainSighash),
                    &sighash,
                ) {
                    Ok(s) => s,
                    Err(e) => return (false, None, Some(format!("re-arm sign: {}", e))),
                };
                tracing::info!(
                    "Signed the re-arm spend of {}'s round-{} lottery (tier {})",
                    ledger_prefix,
                    round,
                    tier
                );
                let result = serde_json::json!({
                    "signer": self.node_id_hex.clone(),
                    "signature": hex::encode(signature),
                });
                // DEP-03 §Arm manifests: the arm set of the round the spend pays into.
                self.publish_arm_manifest(&request.ledger_id, &spend, round + 1, &arms)
                    .await;
                (true, Some(result.to_string()), None)
            }
            Err(reason) => {
                tracing::info!(
                    "Refused lottery_rearm_sign for {}: {}",
                    ledger_prefix,
                    reason
                );
                (false, None, Some(reason))
            }
        }
    }

    async fn check_lottery_rearm_sign(
        &self,
        request: &crate::nostr::LedgerRequest,
    ) -> Result<
        (
            [u8; 32],
            u32,
            usize,
            bitcoin::Transaction,
            Vec<(bitcoin::secp256k1::PublicKey, u64)>,
        ),
        String,
    > {
        use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
        use bitcoin::taproot::{LeafVersion, TapLeafHash};
        let p = &request.params;
        let claimed: [u8; 32] = p
            .get("sighash")
            .and_then(|v| v.as_str())
            .and_then(|h| hex::decode(h).ok())
            .and_then(|b| b.try_into().ok())
            .ok_or("missing or invalid sighash")?;
        let tier = p
            .get("tier")
            .and_then(|v| v.as_u64())
            .ok_or("missing tier")? as usize;
        let asked = p
            .get("unsigned_tx")
            .and_then(|v| v.as_str())
            .and_then(|h| hex::decode(h).ok())
            .ok_or_else(|| "missing or invalid unsigned_tx".to_string())
            .and_then(|b| super::lottery_recovery::parse_unsigned_tx(&b))?;

        let view = self.rearm_view(&request.ledger_id).await?;
        if !deposits_core::types::ruleset_strict_lottery(&view.grounds.ruleset) {
            return Err(format!(
                "re-arm rounds run under strict-lottery-v8, not {}",
                view.grounds.ruleset
            ));
        }
        let cur = self
            .current_round_lottery(&request.ledger_id, &view)
            .await?
            .ok_or("no unclaimed lottery output on chain")?;
        let our_xonly = self.node_id.x_only_public_key().0;
        if !cur.lottery.recovery_voters.contains(&our_xonly) {
            return Err("not a recovery voter".into());
        }
        let leaves = cur.lottery.recovery_leaves();
        let (csv, _, leaf) = leaves
            .get(tier)
            .cloned()
            .ok_or_else(|| format!("no recovery tier {}", tier))?;
        let tip = self
            .wallet
            .chain_backend()
            .get_tip_height()
            .map_err(|e| e.to_string())?;
        // The spend's nSequence is the tier's CSV; it must have passed at the next block.
        if tip + 1 < cur.height + csv {
            return Err(format!("recovery tier {} is not open yet", tier));
        }
        let (next, _) = self
            .rearm_round_lottery(&view, cur.round + 1, cur.height, cur.revealed, tip)?
            .ok_or_else(|| {
                format!(
                    "no re-arm spend is due for round {} (no window has closed with a cut)",
                    cur.round
                )
            })?;
        let (ours, _, _) = cur
            .lottery
            .rearm_spend(
                cur.outpoint,
                cur.value,
                tier,
                next.script_pubkey(),
                view.feerate,
            )
            .map_err(|e| e.to_string())?;
        if bitcoin::consensus::serialize(&asked) != bitcoin::consensus::serialize(&ours) {
            return Err(format!(
                "the re-arm spend is not the one we rebuild (tier {})",
                tier
            ));
        }
        let prevouts = [bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(cur.value),
            script_pubkey: cur.lottery.script_pubkey(),
        }];
        let sighash = SighashCache::new(&ours)
            .taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(&prevouts),
                TapLeafHash::from_script(&leaf, LeafVersion::TapScript),
                TapSighashType::Default,
            )
            .map_err(|e| format!("sighash: {}", e))?;
        let sighash: [u8; 32] = *sighash.as_ref();
        if sighash != claimed {
            return Err("sighash mismatch".into());
        }
        let arms = self
            .rearm_round_arm_set(&view, cur.round + 1, cur.height, cur.revealed, tip)
            .unwrap_or_default();
        Ok((sighash, cur.round, tier, ours, arms))
    }
}

/// A re-arm spend this node proposed, collecting the other voters' signatures over later passes
/// (non-blocking, as `subset_attestations`).
struct PendingRearm {
    request_id: String,
    sighash: [u8; 32],
    tier: usize,
    signatures: HashMap<XOnlyPublicKey, [u8; 64]>,
    created_at: std::time::Instant,
}

/// What a pass over one dispute found, for its back-off.
pub(crate) enum RearmPass {
    Progress,
    Idle,
    NoOutput,
}

/// How long a `lottery_rearm_sign` request is waited on before the next open tier is tried.
const REARM_SIGN_WAIT_SECS: u64 = 90;
/// Seconds between two passes over one dispute (each fetches the ledger's chain).
const REARM_PASS_SECS: u64 = 30;

fn pending_rearms() -> &'static std::sync::Mutex<HashMap<String, PendingRearm>> {
    static P: std::sync::OnceLock<std::sync::Mutex<HashMap<String, PendingRearm>>> =
        std::sync::OnceLock::new();
    P.get_or_init(Default::default)
}
fn next_rearm_pass() -> &'static std::sync::Mutex<HashMap<String, std::time::Instant>> {
    static P: std::sync::OnceLock<std::sync::Mutex<HashMap<String, std::time::Instant>>> =
        std::sync::OnceLock::new();
    P.get_or_init(Default::default)
}
/// (ledger, round, what): reveals published and yields made, once each.
fn rearm_done() -> &'static std::sync::Mutex<std::collections::HashSet<(String, u32, &'static str)>>
{
    static P: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashSet<(String, u32, &'static str)>>,
    > = std::sync::OnceLock::new();
    P.get_or_init(Default::default)
}

/// Our preimage for re-arm round `round` from round 1's seed: a fresh preimage per round (cl's
/// `lottery-seed` takes the round too); round 1's is unchanged. Implementation-private: only
/// its HASH160 is public, in the round's DisputeArmed.
pub(crate) fn round_seed(round1_seed: &[u8; 32], round: u32) -> [u8; 32] {
    use bitcoin::hashes::{sha256, Hash, HashEngine};
    if round <= 1 {
        return *round1_seed;
    }
    let mut e = sha256::Hash::engine();
    e.input(b"deposits/rust/lottery-seed/rearm-round/v1");
    e.input(round1_seed);
    e.input(&round.to_le_bytes());
    sha256::Hash::from_engine(e).to_byte_array()
}

/// The tier a proposer asks for and whether it starts a fresh request: the pending request's tier
/// while it is waited on and still open; once it timed out (or its tier closed), the next open
/// tier above it, else the lowest open one. `prior` is (tier, timed out).
pub(crate) fn rearm_tier_choice(open: &[usize], prior: Option<(usize, bool)>) -> (usize, bool) {
    match prior {
        Some((t, false)) if open.contains(&t) => (t, false),
        Some((t, _)) => (
            open.iter().copied().find(|x| *x > t).unwrap_or(open[0]),
            true,
        ),
        None => (open[0], true),
    }
}

/// The recovery witness's signatures, parallel to the sorted voters: a threshold-1 leaf names
/// only the lowest sorted voter; otherwise exactly `threshold` of the held signatures, the
/// lowest sorted voters' (the fee was sized for a `threshold`-signature witness).
pub(crate) fn witness_signatures(
    order: &[XOnlyPublicKey],
    held: &HashMap<XOnlyPublicKey, [u8; 64]>,
    threshold: usize,
) -> Vec<Option<[u8; 64]>> {
    if threshold == 1 {
        return order
            .iter()
            .enumerate()
            .map(|(i, v)| if i == 0 { held.get(v).copied() } else { None })
            .collect();
    }
    let mut n = 0;
    order
        .iter()
        .map(|v| match held.get(v) {
            Some(s) if n < threshold => {
                n += 1;
                Some(*s)
            }
            _ => None,
        })
        .collect()
}

/// Whether `key` is a dispute fork of ours: one we armed (arming sets its `parent_pubkey`)
/// or one we entered without arming, whose tracking key names us
/// (`DepositsHandler::fork_tracking_key`). A member that sat out round 1's arms is still a
/// recovery voter and may arm a later round, and the driver passed over its fork because only
/// arming sets `parent_pubkey` (regtest rearm-rust 1119-013201: ref7 never drove 4061136e).
pub(crate) fn is_our_fork(
    key: &str,
    parent_pubkey: &bitcoin::secp256k1::PublicKey,
    me: &bitcoin::secp256k1::PublicKey,
) -> bool {
    key.len() > 64
        && (parent_pubkey == me
            || key.ends_with(&format!("_{}", &hex::encode(me.serialize())[..16])))
}

impl Node {
    /// Our lottery preimage for `ledger_id`'s re-arm round `round`.
    pub(crate) fn round_preimage(&self, ledger_id: &str, round: u32) -> Option<Vec<u8>> {
        if round <= 1 {
            return self.own_lottery_preimage(ledger_id);
        }
        let fork_key = self.handler.find_our_fork(ledger_id)?;
        let lvs = super::fork_publish::fork_key_last_valid_seq(&fork_key)?;
        let seed = self
            .handler
            .signer
            .derive_dispute_lottery_preimage(ledger_id, lvs)
            .ok()?;
        Some(LotteryOutput::derive_lottery_preimage(&round_seed(
            &seed, round,
        )))
    }

    /// DEP-06 Phase 4 for every dispute we hold a fork in (a yielded one included: a yield ends
    /// a round, not the dispute). cl's `drive-rearms`.
    pub(crate) async fn drive_rearms(&self) {
        self.publish_queued_manifests().await;
        // Arming, proposing and claiming re-arm rounds are not yet regtest-verified
        // (cl-deposits redteam/check-rearm-rust.sh): off unless DEPOSITS_REARM_DRIVE=1.
        if std::env::var("DEPOSITS_REARM_DRIVE").ok().as_deref() != Some("1") {
            return;
        }
        // Only our forks under strict-lottery-v8 (read locally: the pass itself fetches the
        // ledger's whole chain from the relay).
        let ids: Vec<String> = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            ledgers
                .iter()
                .filter(|(k, arc)| {
                    let l = arc.read().unwrap();
                    is_our_fork(k, &l.state.parent_pubkey, &self.node_id)
                        && deposits_core::types::ruleset_strict_lottery(
                            &l.state.active_ruleset_name,
                        )
                })
                .map(|(k, _)| k[..64].to_string())
                .collect()
        };
        for id in ids {
            {
                let mut next = next_rearm_pass().lock().unwrap();
                if next
                    .get(&id)
                    .is_some_and(|t| *t > std::time::Instant::now())
                {
                    continue;
                }
            }
            // Back off by outcome: 30 s while a round moves, 60 s while nothing is due, 1 h
            // once the dispute has no unclaimed lottery output (claimed, or none yet).
            let wait = match self.drive_rearm(&id).await {
                Ok(RearmPass::Progress) => REARM_PASS_SECS,
                Ok(RearmPass::Idle) => 60,
                Ok(RearmPass::NoOutput) => 3600,
                Err(e) => {
                    tracing::info!("re-arm {}: {}", &id[..16], e);
                    300
                }
            };
            next_rearm_pass().lock().unwrap().insert(
                id.clone(),
                std::time::Instant::now() + std::time::Duration::from_secs(wait),
            );
        }
    }

    /// One pass of the re-arm round for `ledger_id` (cl's `drive-rearm`): in a later round we
    /// are a participant of, reveal and then claim or yield; otherwise arm the next round while
    /// a window of it is open, and once a window has closed with a non-empty cut, as a recovery
    /// voter, propose the spend into that round's lottery and gather the signatures.
    pub(crate) async fn drive_rearm(&self, ledger_id: &str) -> Result<RearmPass, String> {
        let fork_key = self
            .handler
            .find_our_fork(ledger_id)
            .ok_or("no fork of ours")?;
        let view = self.rearm_view(ledger_id).await?;
        if !deposits_core::types::ruleset_strict_lottery(&view.grounds.ruleset) {
            return Ok(RearmPass::NoOutput);
        }
        let Some(cur) = self.current_round_lottery(ledger_id, &view).await? else {
            return Ok(RearmPass::NoOutput);
        };
        let tip = self
            .wallet
            .chain_backend()
            .get_tip_height()
            .map_err(|e| e.to_string())?;
        let me = self.node_id.x_only_public_key().0;
        if cur.round > 1 && cur.lottery.participants.iter().any(|p| p.pubkey == me) {
            return self
                .rearm_reveal_and_claim(ledger_id, &fork_key, &view, &cur, tip)
                .await
                .map(|_| RearmPass::Progress);
        }
        // Round 1 is claimed or yielded by its own path (auto_lottery_claim_or_yield); a round
        // re-arms only once that round's reveal deadline has passed unclaimed.
        let due = self.rearm_round_lottery(&view, cur.round + 1, cur.height, cur.revealed, tip)?;
        match due {
            None => {
                let o = rearm_round_opens(cur.height, cur.revealed);
                let Some((_, wo, wc)) =
                    deposits_core::tapscript_reserves::rearm_open_window(o, view.arm_window, tip)
                else {
                    return Ok(RearmPass::Idle);
                };
                let rows = super::armers::arm_rows(&view.updates);
                let ours: Vec<_> = rows.iter().filter(|r| r.armer == self.node_id).collect();
                let armed_here = super::armers::pick_round_arms(&rows, cur.round + 1, wo, wc)
                    .into_iter()
                    .any(|i| rows[i].armer == self.node_id);
                if armed_here || ours.len() >= super::armers::MAX_ARMS {
                    return Ok(RearmPass::Progress);
                }
                self.arm_rearm_round(ledger_id, &fork_key, cur.round + 1)
                    .await
                    .map(|_| RearmPass::Progress)
                    .map_err(|e| format!("arm round {}: {}", cur.round + 1, e))
            }
            Some((next, _)) => {
                if !cur.lottery.recovery_voters.contains(&me) {
                    return Ok(RearmPass::Idle);
                }
                self.propose_rearm(ledger_id, &view, &cur, &next, tip)
                    .await
                    .map(|_| RearmPass::Progress)
            }
        }
    }

    /// As a recovery voter: the re-arm spend of the current round's output into `next`, through
    /// the first open tier its signers reach; our signature, the others' by `lottery_rearm_sign`
    /// over later passes, then the witness and the broadcast.
    async fn propose_rearm(
        &self,
        ledger_id: &str,
        view: &RearmView,
        cur: &RoundLottery,
        next: &LotteryOutput,
        tip: u32,
    ) -> Result<(), String> {
        use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
        use bitcoin::taproot::{LeafVersion, TapLeafHash};
        use deposits_signer_api::{SigPurpose, SignContext};
        let pfx = &ledger_id[..16];
        let leaves = cur.lottery.recovery_leaves();
        let open: Vec<usize> = leaves
            .iter()
            .enumerate()
            .filter(|(_, (csv, _, _))| tip + 1 >= cur.height + csv)
            .map(|(i, _)| i)
            .collect();
        if open.is_empty() {
            return Ok(());
        }
        let order = cur.lottery.recovery_voter_order();
        let me = self.node_id.x_only_public_key().0;
        // The tier: the pending request's while it is waited on, else the next open tier after
        // the one that timed out (tier 0 first).
        let (tier, fresh) = {
            let mut pending = pending_rearms().lock().unwrap();
            let prior = pending.get(ledger_id).map(|p| {
                (
                    p.tier,
                    p.created_at.elapsed().as_secs() >= REARM_SIGN_WAIT_SECS,
                )
            });
            let (t, fresh) = rearm_tier_choice(&open, prior);
            if fresh {
                pending.remove(ledger_id);
            }
            (t, fresh)
        };
        let (csv, threshold, leaf) = leaves[tier].clone();
        let (mut spend, _, _) = cur
            .lottery
            .rearm_spend(
                cur.outpoint,
                cur.value,
                tier,
                next.script_pubkey(),
                view.feerate,
            )
            .map_err(|e| e.to_string())?;
        let prevouts = [bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(cur.value),
            script_pubkey: cur.lottery.script_pubkey(),
        }];
        let sighash: [u8; 32] = *SighashCache::new(&spend)
            .taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(&prevouts),
                TapLeafHash::from_script(&leaf, LeafVersion::TapScript),
                TapSighashType::Default,
            )
            .map_err(|e| format!("sighash: {}", e))?
            .as_ref();
        if fresh {
            let mut signatures = HashMap::new();
            let ours = self
                .handler
                .signer
                .bip340_sign(
                    &SignContext::no_ledger(SigPurpose::OnchainSighash),
                    &sighash,
                )
                .map_err(|e| format!("re-arm sign: {}", e))?;
            signatures.insert(me, ours);
            let request_id = if signatures.len() < threshold {
                let params = serde_json::json!({
                    "unsigned_tx": hex::encode(bitcoin::consensus::serialize(&spend)),
                    "tier": tier,
                    "sighash": hex::encode(sighash),
                });
                let id = self
                    .nostr
                    .send_ledger_request(ledger_id, "lottery_rearm_sign", params)
                    .await
                    .map_err(|e| format!("send lottery_rearm_sign: {:?}", e))?;
                self.track_sent_event(&id);
                tracing::info!(
                    "re-arm {}: proposed round {}'s spend through tier {} (CSV {}); asking for {} more signature(s)",
                    pfx,
                    cur.round + 1,
                    tier,
                    csv,
                    threshold - signatures.len()
                );
                id
            } else {
                String::new()
            };
            pending_rearms().lock().unwrap().insert(
                ledger_id.to_string(),
                PendingRearm {
                    request_id,
                    sighash,
                    tier,
                    signatures,
                    created_at: std::time::Instant::now(),
                },
            );
        } else {
            let request_id = pending_rearms()
                .lock()
                .unwrap()
                .get(ledger_id)
                .map(|p| p.request_id.clone())
                .unwrap_or_default();
            let responses = self.fetch_sign_responses(&request_id).await;
            let msg = bitcoin::secp256k1::Message::from_digest(sighash);
            let secp = bitcoin::secp256k1::Secp256k1::verification_only();
            let mut pending = pending_rearms().lock().unwrap();
            if let Some(p) = pending.get_mut(ledger_id) {
                if p.sighash != sighash {
                    pending.remove(ledger_id);
                    return Ok(());
                }
                for (signer, sig) in responses {
                    let x = signer.x_only_public_key().0;
                    let ok = order.contains(&x)
                        && bitcoin::secp256k1::schnorr::Signature::from_slice(&sig)
                            .map(|s| secp.verify_schnorr(&s, &msg, &x).is_ok())
                            .unwrap_or(false);
                    if ok && !p.signatures.contains_key(&x) {
                        let mut a = [0u8; 64];
                        a.copy_from_slice(&sig);
                        p.signatures.insert(x, a);
                        tracing::info!(
                            "re-arm {}: signature from {} ({}/{})",
                            pfx,
                            &signer.to_string()[..16],
                            p.signatures.len(),
                            threshold
                        );
                    }
                }
            }
        }
        // Enough? Exactly `threshold` signatures, the lowest sorted voters' we hold (the fee was
        // sized for that witness); a threshold-1 leaf names only the lowest sorted voter.
        let held = pending_rearms()
            .lock()
            .unwrap()
            .get(ledger_id)
            .map(|p| p.signatures.clone())
            .unwrap_or_default();
        let sigs = witness_signatures(&order, &held, threshold);
        if sigs.iter().flatten().count() < threshold {
            return Ok(());
        }
        spend.input[0].witness = cur
            .lottery
            .recovery_witness(tier, &sigs)
            .map_err(|e| e.to_string())?;
        let txid = self
            .wallet
            .broadcast(&spend)
            .map_err(|e| format!("broadcast: {}", e))?;
        pending_rearms().lock().unwrap().remove(ledger_id);
        if let Some(arms) =
            self.rearm_round_arm_set(view, cur.round + 1, cur.height, cur.revealed, tip)
        {
            self.publish_arm_manifest(ledger_id, &spend, cur.round + 1, &arms)
                .await;
        }
        tracing::info!(
            "re-arm {}: lottery round {} unclaimed; spent into round {}'s lottery (tier {}): {}",
            pfx,
            cur.round,
            cur.round + 1,
            tier,
            txid
        );
        Ok(())
    }

    /// In a later round we are a participant of: reveal, then claim if we drew it, else yield.
    async fn rearm_reveal_and_claim(
        &self,
        ledger_id: &str,
        fork_key: &str,
        view: &RearmView,
        cur: &RoundLottery,
        tip: u32,
    ) -> Result<(), String> {
        use deposits_core::messages::LedgerOperation;
        use deposits_core::tapscript_reserves::LOTTERY_REVEAL_CSV_BLOCKS;
        use deposits_core::tlv::TlvDecode;
        let pfx = &ledger_id[..16];
        let round = cur.round;
        let our_armed = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let l = ledgers
                .get(fork_key)
                .ok_or("our fork is gone")?
                .read()
                .unwrap();
            l.history
                .iter()
                .rev()
                .find(|u| {
                    matches!(
                        LedgerOperation::tlv_decode(&u.message),
                        Ok(LedgerOperation::DisputeArmed { rearm_round: Some(r), .. }) if r == round
                    )
                })
                .cloned()
                .ok_or_else(|| format!("no round-{} arm on our fork", round))?
        };
        let preimage = self
            .round_preimage(ledger_id, round)
            .ok_or("no preimage for the round")?;
        let key = (ledger_id.to_string(), round, "reveal");
        if !rearm_done().lock().unwrap().contains(&key) {
            self.publish_lottery_reveal(ledger_id, &preimage).await;
            rearm_done().lock().unwrap().insert(key);
            tracing::info!(
                "re-arm {}: round {}'s lottery on chain; revealed",
                pfx,
                round
            );
        }
        let parts: Vec<(bitcoin::secp256k1::PublicKey, LotteryParticipant)> = cur
            .lottery
            .participants
            .iter()
            .map(|p| {
                (
                    bitcoin::secp256k1::PublicKey::from_x_only_public_key(
                        p.pubkey,
                        bitcoin::secp256k1::Parity::Even,
                    ),
                    p.clone(),
                )
            })
            .collect();
        let mut revealed = view.revealed.clone();
        revealed.push(preimage);
        let preimages = super::lottery_recovery::match_revealed_preimages(&parts, &revealed);
        let past = tip + 1 >= cur.height + LOTTERY_REVEAL_CSV_BLOCKS;
        let (subset, ordered, winner) =
            match super::lottery_recovery::lottery_claim_path(&preimages, past) {
                super::lottery_recovery::LotteryClaimPath::Wait(why) => {
                    tracing::debug!("re-arm {}: round {}: {}", pfx, round, why);
                    return Ok(());
                }
                super::lottery_recovery::LotteryClaimPath::Full(pre) => {
                    let w =
                        LotteryOutput::calculate_winner(&pre).map_err(|e| format!("{:?}", e))?;
                    (None, pre, w)
                }
                super::lottery_recovery::LotteryClaimPath::Subset(idx, pre) => {
                    let w =
                        LotteryOutput::subset_winner(&idx, &pre).map_err(|e| format!("{:?}", e))?;
                    (Some(idx), pre, w)
                }
            };
        let me = self.node_id.x_only_public_key().0;
        if parts[winner].1.pubkey != me {
            let key = (ledger_id.to_string(), round, "yield");
            if !rearm_done().lock().unwrap().contains(&key) {
                self.publish_custody_yield(ledger_id, &our_armed)
                    .await
                    .map_err(|e| e.to_string())?;
                rearm_done().lock().unwrap().insert(key);
                tracing::info!("re-arm {}: re-arm round {}: yielded", pfx, round);
            }
            return Ok(());
        }
        use bitcoin::hashes::Hash;
        let claimed = self
            .claim_lottery(
                ledger_id,
                // The round walk's own outpoint, never a by-script lookup (1120-090836).
                (cur.outpoint, cur.value),
                &parts,
                &ordered,
                winner,
                subset.as_deref(),
                &our_armed,
                cur.lottery.recovery_voters.clone(),
                cur.lottery.recovery_threshold,
                Some(cur.confiscation_txid.to_byte_array()),
            )
            .await
            .map_err(|e| e.to_string())?;
        if claimed {
            tracing::info!("re-arm {}: re-arm round {}: won", pfx, round);
        }
        Ok(())
    }
}

#[cfg(test)]
mod drive_tests {
    use super::*;

    fn key(i: u8) -> XOnlyPublicKey {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let sk = bitcoin::secp256k1::SecretKey::from_slice(&[i; 32]).unwrap();
        bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk)
            .x_only_public_key()
            .0
    }

    #[test]
    fn round_seeds_are_fresh_per_round_and_round_1_is_unchanged() {
        let s = [7u8; 32];
        assert_eq!(round_seed(&s, 1), s);
        assert_ne!(round_seed(&s, 2), s);
        assert_ne!(round_seed(&s, 2), round_seed(&s, 3));
        assert_eq!(round_seed(&s, 2), round_seed(&s, 2));
    }

    #[test]
    fn the_tier_waits_then_falls_through() {
        assert_eq!(rearm_tier_choice(&[0], None), (0, true));
        assert_eq!(rearm_tier_choice(&[0, 1], Some((0, false))), (0, false));
        assert_eq!(rearm_tier_choice(&[0, 1], Some((0, true))), (1, true));
        assert_eq!(rearm_tier_choice(&[0, 1], Some((1, true))), (0, true));
        assert_eq!(rearm_tier_choice(&[1], Some((0, false))), (1, true));
    }

    #[test]
    fn the_witness_holds_exactly_the_threshold_lowest_voters() {
        let mut order = vec![key(1), key(2), key(3)];
        order.sort_by_key(|k| k.serialize());
        let held: HashMap<_, _> = [
            (order[0], [1u8; 64]),
            (order[1], [2u8; 64]),
            (order[2], [3u8; 64]),
        ]
        .into_iter()
        .collect();
        assert_eq!(
            witness_signatures(&order, &held, 2),
            vec![Some([1u8; 64]), Some([2u8; 64]), None]
        );
        assert_eq!(
            witness_signatures(&order, &held, 1),
            vec![Some([1u8; 64]), None, None]
        );
        let mut gap = held.clone();
        gap.remove(&order[0]);
        assert_eq!(witness_signatures(&order, &gap, 1), vec![None, None, None]);
        assert_eq!(
            witness_signatures(&order, &gap, 2),
            vec![None, Some([2u8; 64]), Some([3u8; 64])]
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_arm_window_is_the_largest_named_else_six() {
        assert_eq!(arm_window_of([]), DEFAULT_DISPUTE_ARM_BLOCKS);
        assert_eq!(arm_window_of([None, Some(0)]), DEFAULT_DISPUTE_ARM_BLOCKS);
        assert_eq!(arm_window_of([Some(9), None, Some(4)]), 9);
    }
}

#[cfg(test)]
mod our_fork_tests {
    use super::is_our_fork;

    fn key(b: u8) -> bitcoin::secp256k1::PublicKey {
        use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
        PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[b; 32]).unwrap())
    }

    #[test]
    fn an_unarmed_fork_we_entered_is_ours() {
        let (me, op, other) = (key(1), key(2), key(3));
        let id = "ab".repeat(32);
        let ours = crate::handler::DepositsHandler::fork_tracking_key(&id, 10, &me);
        let theirs = crate::handler::DepositsHandler::fork_tracking_key(&id, 10, &other);
        // Unarmed: parent_pubkey is still the ledger's operator.
        assert!(is_our_fork(&ours, &op, &me));
        assert!(!is_our_fork(&theirs, &op, &me));
        // Armed: parent_pubkey names us whatever the key says.
        assert!(is_our_fork(&theirs, &me, &me));
        // The base ledger is never a fork.
        assert!(!is_our_fork(&id, &me, &me));
    }
}

#[cfg(test)]
mod scan_window_tests {
    use super::{find_spend_or_unknown, is_beyond_scan_window};
    use crate::chain_backend::{ChainBackend, UnspentOutput};
    use crate::Error;
    use bitcoin::{OutPoint, Script, Transaction, Txid};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Beyond(AtomicUsize);
    impl ChainBackend for Beyond {
        fn get_tip_height(&self) -> Result<u32, Error> {
            Ok(19_166)
        }
        fn get_block_hash(&self, _: u32) -> Result<bitcoin::BlockHash, Error> {
            Err(Error::Wallet("unused".into()))
        }
        fn get_block_height_if_in_best_chain(
            &self,
            _: &bitcoin::BlockHash,
        ) -> Result<Option<u32>, Error> {
            Ok(None)
        }
        fn get_tx(&self, _: &Txid) -> Result<Option<Transaction>, Error> {
            Ok(None)
        }
        fn get_tx_block_height(&self, _: &Txid) -> Result<Option<u32>, Error> {
            Ok(None)
        }
        fn is_output_unspent(&self, _: &Txid, _: u32) -> Result<Option<bool>, Error> {
            Ok(None)
        }
        fn find_unspent_output_at(&self, _: &Script) -> Result<Option<UnspentOutput>, Error> {
            Ok(None)
        }
        fn broadcast_tx(&self, _: &Transaction) -> Result<Txid, Error> {
            Err(Error::Wallet("unused".into()))
        }
        fn find_spending_tx(
            &self,
            o: &OutPoint,
            _: &Script,
            from: u32,
        ) -> Result<Option<Transaction>, Error> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(Error::Wallet(format!(
                "bitcoind find_spending_tx: no spend of {} in {}..={} and the tip is 19166; \
                 scans stop after 4320 blocks: pass a tighter scan_from_height",
                o,
                from,
                from + 4320
            )))
        }
    }

    /// A spend past the scan window is asked once, then unknown: no second walk, no error.
    #[test]
    fn a_spend_beyond_the_window_is_asked_once() {
        let b = Beyond(AtomicUsize::new(0));
        let o = OutPoint::new(Txid::from_raw_hash(bitcoin::hashes::Hash::all_zeros()), 7);
        for _ in 0..3 {
            assert!(
                find_spend_or_unknown(&b, &"ab".repeat(32), &o, Script::new(), 582)
                    .unwrap()
                    .is_none()
            );
        }
        assert_eq!(b.0.load(Ordering::SeqCst), 1);
        assert!(!is_beyond_scan_window(
            "bitcoind RPC error: connection refused"
        ));
    }
}
