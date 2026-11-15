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
        let arms = super::armers::collect_armers_round(&view.updates, None, round);
        let cut_err: std::cell::RefCell<Option<String>> = std::cell::RefCell::new(None);
        let cut = |opens: u32, closes: u32| -> Option<Vec<LotteryParticipant>> {
            if !arms
                .iter()
                .any(|a| opens < a.arm_height && a.arm_height <= closes)
            {
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
        let floor = super::armers::first_arm_height(&view.updates).unwrap_or(0);
        let Some(confiscation) = chain
            .find_spending_tx(&vault, bitcoin::Script::new(), floor)
            .map_err(|e| e.to_string())?
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
                }));
            }
            if round >= MAX_ROUNDS {
                return Ok(None);
            }
            let Some(spend) = chain
                .find_spending_tx(&outpoint, &lottery.script_pubkey(), height)
                .map_err(|e| e.to_string())?
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
            let Some((next, participants)) =
                self.rearm_round_lottery(view, round + 1, height, revealed, spend_height)?
            else {
                return Ok(None);
            };
            if spend.output[0].script_pubkey != next.script_pubkey() {
                return Ok(None);
            }
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
            Ok((sighash, round, tier)) => {
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
    ) -> Result<([u8; 32], u32, usize), String> {
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
        Ok((sighash, cur.round, tier))
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
