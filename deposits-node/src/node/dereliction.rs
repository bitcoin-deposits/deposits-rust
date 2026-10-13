// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Producer for `DisputeDereliction` fraud proofs (DEP-19 §6 / DEP-11
//! §Dispute Participation).
//!
//! The reference already *verifies* and *acts on* a received
//! `DisputeDereliction` (see `fraud.rs::verify_inactive_quorum_member` and
//! `inbound.rs::handle_fraud_proof`). This module is the missing *producer*:
//! after the node verifies a punitive fraud proof and disputes the faulted
//! ledger, it records the fault; a periodic task then scans the faulted
//! ledger's OTHER quorum members and, for each one that kept operating its
//! own ledger past the response window WITHOUT acting on the proof,
//! broadcasts one `DisputeDereliction` against that member's own ledger.
//!
//! Mirrors cl-deposits' `report-derelict-members` (src/node.lisp): the node
//! only accuses a member whose own ledger it replicates (needed to cite the
//! member's active sequence), never itself, and never a member that acted.

use std::collections::HashSet;

use bitcoin::secp256k1::PublicKey;
use deposits_core::fraud::{make_dispute_dereliction_proof, FraudBroadcast, FraudProof};
use deposits_core::messages::LedgerOperation;
use deposits_core::types::{QuorumMember, SignedLedgerUpdate};
use deposits_core::{TlvDecode, TlvEncode};

/// A punitive fraud proof we verified and disputed, with our own
/// `DisputeEnter` that cites it (the disclosure, whose block anchors the
/// window), held until co-members have had their windows to respond.
#[derive(Clone, Debug)]
pub struct DerelictionWatch {
    /// The punitive proof that was (or should have been) acted on.
    pub original: FraudProof,
    /// Our signed `DisputeEnter` on the faulted ledger citing its hash.
    pub disclosure: SignedLedgerUpdate,
}

/// The set of members who *acted* on a dispute of a ledger: everyone who
/// authored a `DisputeEnter` or `DisputeArmed` on it. Fork-branch dispute
/// updates are signed by the disputer, so their `operator_id` is the acting
/// member. Disputes are public (relay / fork state), so `updates` is the
/// faulted ledger's full update stream fetched from the relay.
pub(crate) fn collect_acting_members(updates: &[SignedLedgerUpdate]) -> HashSet<PublicKey> {
    let mut acted = HashSet::new();
    for u in updates {
        match LedgerOperation::tlv_decode(&u.message) {
            Ok(LedgerOperation::DisputeEnter { .. }) | Ok(LedgerOperation::DisputeArmed { .. }) => {
                acted.insert(u.operator_id);
            }
            _ => {}
        }
    }
    acted
}

/// Decide which co-members of a disputed ledger are derelict and build a
/// `DisputeDereliction` against each on every ledger it operates (DEP-19 §6:
/// one accusation, every vault it runs, as contagion). Pure: every replica /
/// relay access is injected; `operated` gives the ledgers a member operates
/// that we hold, with their histories. A member is derelict iff it is not us,
/// did not act (`acted`), is seated by the QuorumBegin governing at the
/// disclosure, and cosigned the faulted ledger (`chain`) at or after the
/// disclosure's block; a ledger it operates is accused iff it signed an update
/// there at least its `dispute_response_blocks` after that, and the built proof
/// passes `verify` (the same verifier receivers run).
#[allow(clippy::too_many_arguments)]
pub(crate) fn plan_dereliction_proofs(
    members: &[QuorumMember],
    our_key: &PublicKey,
    watch: &DerelictionWatch,
    chain: &[SignedLedgerUpdate],
    acted: &HashSet<PublicKey>,
    operated: &dyn Fn(&PublicKey) -> Vec<(String, Vec<SignedLedgerUpdate>)>,
    already_reported: &dyn Fn(&str) -> bool,
    verify: &dyn Fn(&FraudBroadcast, &[SignedLedgerUpdate]) -> Result<(), String>,
) -> Vec<FraudBroadcast> {
    let mut out = Vec::new();
    let anchor = watch.disclosure.block_height;
    let Ok(LedgerOperation::DisputeEnter {
        last_valid_sequence: lvs,
        ..
    }) = LedgerOperation::tlv_decode(&watch.disclosure.message)
    else {
        return out;
    };
    let mut ascending: Vec<&SignedLedgerUpdate> = chain.iter().collect();
    ascending.sort_by_key(|u| u.sequence_number);
    let qb = ascending.iter().rev().find(|u| {
        u.sequence_number <= lvs
            && matches!(
                LedgerOperation::tlv_decode(&u.message),
                Ok(LedgerOperation::QuorumBegin { .. })
            )
    });
    let Some(qb) = qb else {
        return out;
    };
    let seated: Vec<PublicKey> = match LedgerOperation::tlv_decode(&qb.message) {
        Ok(LedgerOperation::QuorumBegin { quorum_members, .. }) => {
            quorum_members.iter().map(|m| m.pubkey).collect()
        }
        _ => return out,
    };
    let mut seen_members: HashSet<PublicKey> = HashSet::new();

    for m in members {
        if m.pubkey == *our_key
            || acted.contains(&m.pubkey)
            || !seated.contains(&m.pubkey)
            || !seen_members.insert(m.pubkey)
        {
            continue;
        }
        let Some(vis) = ascending.iter().find(|u| {
            u.block_height >= anchor && u.cosignatures.iter().any(|c| c.cosigner_pubkey == m.pubkey)
        }) else {
            continue;
        };
        let required = m.dispute_response_blocks.unwrap_or(144);
        let deadline = vis.block_height.saturating_add(required);
        for (target, history) in operated(&m.pubkey) {
            if already_reported(&target) {
                continue;
            }
            let Some(target_bytes) = decode_ledger_id(&target) else {
                continue;
            };
            let Some(active) = history
                .iter()
                .filter(|u| u.operator_id == m.pubkey && u.block_height >= deadline)
                .max_by_key(|u| u.sequence_number)
            else {
                continue;
            };
            let broadcast = make_dispute_dereliction_proof(
                &m.pubkey,
                &target_bytes,
                &watch.original,
                &watch.disclosure,
                qb,
                vis,
                active.sequence_number,
            );
            match verify(&broadcast, &history) {
                Ok(()) => out.push(broadcast),
                Err(e) => tracing::info!(
                    "not reporting {} on {}: our own dereliction proof does not verify: {}",
                    hex::encode(&m.pubkey.serialize()[..8]),
                    &target[..16.min(target.len())],
                    e
                ),
            }
        }
    }
    out
}

/// A 64-char hex ledger id to its 32 bytes, or `None` if malformed.
fn decode_ledger_id(ledger_id: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(ledger_id).ok()?;
    bytes.try_into().ok()
}

impl crate::Node {
    /// Record a punitive fraud proof we just disputed, with our own
    /// `DisputeEnter` citing it, so the periodic scan can accuse co-members
    /// that saw it and stayed active without acting. First writer wins.
    pub(crate) fn register_dereliction_watch(&self, faulted_ledger_id: &str, original: FraudProof) {
        let hash = original.proof_hash();
        let Some(disclosure) = self.our_disclosure(faulted_ledger_id, &hash) else {
            tracing::warn!(
                "dereliction watch on {}: no DisputeEnter of ours cites the proof",
                &faulted_ledger_id[..16.min(faulted_ledger_id.len())]
            );
            return;
        };
        self.pending_dereliction_watches
            .lock()
            .unwrap()
            .entry(faulted_ledger_id.to_string())
            .or_insert(DerelictionWatch {
                original,
                disclosure,
            });
    }

    /// Our signed `DisputeEnter` on a fork of `ledger_id` citing `proof_hash`.
    pub(crate) fn our_disclosure(
        &self,
        ledger_id: &str,
        proof_hash: &[u8; 32],
    ) -> Option<SignedLedgerUpdate> {
        let ledgers = self.handler.ledgers.lock().unwrap();
        ledgers
            .iter()
            .filter(|(k, _)| k.as_str() != ledger_id && k.starts_with(ledger_id))
            .find_map(|(_, arc)| {
                arc.read().unwrap().history.iter().rev().find(|u| {
                    u.operator_id == self.node_id
                        && matches!(
                            LedgerOperation::tlv_decode(&u.message),
                            Ok(LedgerOperation::DisputeEnter { fraud_proof_hash: Some(h), .. }) if h == *proof_hash
                        )
                }).cloned()
            })
    }

    /// Periodic producer: for each pending watch, broadcast a
    /// `DisputeDereliction` against every co-member that saw the fraud and
    /// stayed active past its window without acting.
    pub(crate) async fn auto_report_derelict_members(&self) {
        let watches: Vec<(String, DerelictionWatch)> = {
            let w = self.pending_dereliction_watches.lock().unwrap();
            w.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
        };
        for (faulted_ledger_id, watch) in watches {
            let (members, chain) = {
                let ledgers = self.handler.ledgers.lock().unwrap();
                match ledgers.get(&faulted_ledger_id) {
                    Some(arc) => {
                        let l = arc.read().unwrap();
                        (l.state.quorum_members.clone(), l.history.clone())
                    }
                    None => continue,
                }
            };
            if members.is_empty() {
                continue;
            }
            let updates = self
                .fetch_all_ledger_updates_paginated(&faulted_ledger_id)
                .await;
            let acted = collect_acting_members(&updates);
            let mut all = chain.clone();
            all.extend(updates.iter().cloned());
            let hash_hex = hex::encode(watch.original.proof_hash());
            // Every ledger each member operates that we hold (advertisements +
            // replicas, as contagion finds them), with its history.
            let mut operated_by: std::collections::HashMap<
                PublicKey,
                Vec<(String, Vec<SignedLedgerUpdate>)>,
            > = Default::default();
            for m in &members {
                let ids = self.ledgers_operated_by(&m.pubkey).await;
                let held: Vec<(String, Vec<SignedLedgerUpdate>)> = {
                    let ledgers = self.handler.ledgers.lock().unwrap();
                    ids.into_iter()
                        .filter_map(|id| {
                            let h = ledgers
                                .get(&id)
                                .map(|arc| arc.read().unwrap().history.clone())?;
                            Some((id, h))
                        })
                        .collect()
                };
                operated_by.insert(m.pubkey, held);
            }
            let operated = |pk: &PublicKey| operated_by.get(pk).cloned().unwrap_or_default();
            let already_reported = |lid: &str| {
                self.reported_derelictions
                    .lock()
                    .unwrap()
                    .contains(&(lid.to_string(), hash_hex.clone()))
            };
            struct WalletOracle<'a>(&'a crate::wallet::Wallet);
            impl deposits_core::fraud::BlockOracle for WalletOracle<'_> {
                fn confirms(&self, hash: &[u8; 32]) -> Option<u32> {
                    self.0.confirms_block(hash)
                }
            }
            let oracle = WalletOracle(&self.wallet);
            let authorizer = deposits_core::dep16::Dep16Authorizer::new();
            let verify = |b: &FraudBroadcast, history: &[SignedLedgerUpdate]| {
                deposits_core::fraud::verify_inactive_quorum_member(
                    &b.proof,
                    history,
                    &all,
                    &oracle,
                    &authorizer,
                )
            };
            let proofs = plan_dereliction_proofs(
                &members,
                &self.node_id,
                &watch,
                &chain,
                &acted,
                &operated,
                &already_reported,
                &verify,
            );
            for broadcast in &proofs {
                tracing::warn!(
                    "DERELICTION: member {} saw fraud {} on {} and stayed active on {} past its \
                     window without disputing; broadcasting DisputeDereliction",
                    &broadcast.proof.accused[..16.min(broadcast.proof.accused.len())],
                    &hash_hex[..16],
                    &faulted_ledger_id[..16.min(faulted_ledger_id.len())],
                    &broadcast.proof.ledger_id[..16.min(broadcast.proof.ledger_id.len())],
                );
                match self.nostr.broadcast_fraud_proof(broadcast).await {
                    // marked only once published: a failed publish is retried next pass
                    Ok(_) => {
                        self.reported_derelictions
                            .lock()
                            .unwrap()
                            .insert((broadcast.proof.ledger_id.clone(), hash_hex.clone()));
                    }
                    Err(e) => tracing::error!("Dereliction: fraud broadcast failed: {}", e),
                }
            }
            let max_required = members
                .iter()
                .map(|m| m.dispute_response_blocks.unwrap_or(144))
                .max()
                .unwrap_or(144);
            let retire_at = watch
                .disclosure
                .block_height
                .saturating_add(max_required)
                .saturating_add(DERELICTION_WATCH_GRACE_BLOCKS);
            if self.wallet.get_block_height().unwrap_or(0) > retire_at {
                self.pending_dereliction_watches
                    .lock()
                    .unwrap()
                    .remove(&faulted_ledger_id);
            }
        }
    }
}

/// Blocks past the last member's deadline before a watch is retired (~1 week).
const DERELICTION_WATCH_GRACE_BLOCKS: u32 = 1008;

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    fn pk(byte: u8) -> PublicKey {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[byte; 32]).unwrap();
        PublicKey::from_secret_key(&secp, &sk)
    }

    fn blank_member(pubkey: PublicKey, ledger_id: String) -> QuorumMember {
        QuorumMember {
            min_collateral_bps: None,
            dormancy_blocks: None,
            dormancy_notice_blocks: None,
            pubkey,
            ledger_id,
            min_fee_bps: None,
            min_fee_fixed: None,
            max_fee_period: None,
            membership_until: None,
            dispute_response_blocks: Some(5),
            dispute_arm_blocks: None,
            service_response_blocks: None,
            max_transfer_timeout_blocks: None,
            max_descriptor_bytes: None,
            compensation_bps: None,
            compensation_deposit_id: None,
            compensation_frequency_blocks: None,
            supported_rulesets: vec![],
        }
    }

    /// DEP-19 §6 scope: a derelict member is accused on every ledger it
    /// operates. From the shared cl vector (deposits-core/tests/vectors): d is
    /// reported on both ledgers it runs — the same signed history under a second
    /// id stands in for a second ledger; receivers fetch each ledger's own — and
    /// c, which disputed in time, on none.
    #[test]
    fn accuses_on_every_ledger_the_member_operates() {
        use deposits_core::fraud::{BlockOracle, FraudEvidence};
        let v: serde_json::Value = serde_json::from_str(include_str!(
            "../../../deposits-core/tests/vectors/dereliction.json"
        ))
        .unwrap();
        let decode = |x: &serde_json::Value| {
            SignedLedgerUpdate::tlv_decode(&hex::decode(x.as_str().unwrap()).unwrap()).unwrap()
        };
        let case = |name: &str| {
            v["cases"]
                .as_array()
                .unwrap()
                .iter()
                .find(|c| c["name"] == name)
                .unwrap()
                .clone()
        };
        let valid = case("valid");
        let rebutted = case("rebutted: the accused disputed within its window");
        let proof: FraudProof = serde_json::from_value(valid["proof"].clone()).unwrap();
        let rproof: FraudProof = serde_json::from_value(rebutted["proof"].clone()).unwrap();
        let FraudEvidence::DisputeDereliction {
            original_proof,
            disclosure_update,
            ..
        } = &proof.evidence
        else {
            panic!("not a dereliction")
        };
        let watch = DerelictionWatch {
            original: (**original_proof).clone(),
            disclosure: SignedLedgerUpdate::tlv_decode(&hex::decode(disclosure_update).unwrap())
                .unwrap(),
        };
        let all: Vec<SignedLedgerUpdate> = v["defrauded_updates"]
            .as_array()
            .unwrap()
            .iter()
            .map(decode)
            .collect();
        let accused_op: PublicKey = original_proof.accused.parse().unwrap();
        let chain: Vec<SignedLedgerUpdate> = all
            .iter()
            .filter(|u| u.operator_id == accused_op)
            .cloned()
            .collect();
        let d: PublicKey = proof.accused.parse().unwrap();
        let c: PublicKey = rproof.accused.parse().unwrap();
        let d_hist: Vec<SignedLedgerUpdate> = valid["member_ledger"]
            .as_array()
            .unwrap()
            .iter()
            .map(decode)
            .collect();
        let c_hist: Vec<SignedLedgerUpdate> = rebutted["member_ledger"]
            .as_array()
            .unwrap()
            .iter()
            .map(decode)
            .collect();
        let second = "ee".repeat(32);
        let members = vec![
            blank_member(d, proof.ledger_id.clone()),
            blank_member(c, rproof.ledger_id.clone()),
        ];
        let operated = |pk: &PublicKey| {
            if *pk == d {
                vec![
                    (proof.ledger_id.clone(), d_hist.clone()),
                    (second.clone(), d_hist.clone()),
                ]
            } else if *pk == c {
                vec![(rproof.ledger_id.clone(), c_hist.clone())]
            } else {
                vec![]
            }
        };
        struct O(std::collections::HashMap<[u8; 32], u32>);
        impl BlockOracle for O {
            fn confirms(&self, h: &[u8; 32]) -> Option<u32> {
                self.0.get(h).copied()
            }
        }
        let oracle = O(v["blocks"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, h)| {
                (
                    <[u8; 32]>::try_from(hex::decode(k).unwrap()).unwrap(),
                    h.as_u64().unwrap() as u32,
                )
            })
            .collect());
        let authorizer = deposits_core::dep16::Dep16Authorizer::new();
        let verify = |b: &FraudBroadcast, history: &[SignedLedgerUpdate]| {
            deposits_core::fraud::verify_inactive_quorum_member(
                &b.proof,
                history,
                &all,
                &oracle,
                &authorizer,
            )
        };
        let out = plan_dereliction_proofs(
            &members,
            &pk(99),
            &watch,
            &chain,
            &collect_acting_members(&all),
            &operated,
            &|_| false,
            &verify,
        );
        let mut got: Vec<(String, String)> = out
            .iter()
            .map(|b| (b.proof.accused.clone(), b.proof.ledger_id.clone()))
            .collect();
        got.sort();
        let mut want = vec![
            (proof.accused.clone(), proof.ledger_id.clone()),
            (proof.accused.clone(), second),
        ];
        want.sort();
        assert_eq!(got, want);
    }

    #[test]
    fn collect_acting_members_ignores_non_dispute_updates() {
        let u = SignedLedgerUpdate {
            message: LedgerOperation::LedgerClose.tlv_encode(),
            message_type: 0,
            operator_id: pk(1),
            ledger_id: [0; 32],
            sequence_number: 1,
            previous_hash: [0; 32],
            content_hash: [0; 32],
            block_height: 0,
            block_hash: [0; 32],
            operator_signature: [0; 64],
            cosignatures: Vec::new(),
        };
        assert!(collect_acting_members(&[u]).is_empty());
    }
}
