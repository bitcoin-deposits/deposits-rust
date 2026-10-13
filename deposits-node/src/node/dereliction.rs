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

/// Decide which co-members of a disputed ledger are derelict and build one
/// `DisputeDereliction` for each (DEP-19 §6). Pure: every replica / relay
/// access is injected. A member yields a proof iff it is not us, did not act
/// (`acted`), is seated by the QuorumBegin governing at the disclosure, cosigned
/// the faulted ledger (`chain`) at or after the disclosure's block, and signed
/// an update on its own ledger at least its `dispute_response_blocks` after
/// that — and the built proof passes `verify` (the same verifier receivers run).
#[allow(clippy::too_many_arguments)]
pub(crate) fn plan_dereliction_proofs(
    members: &[QuorumMember],
    our_key: &PublicKey,
    watch: &DerelictionWatch,
    chain: &[SignedLedgerUpdate],
    acted: &HashSet<PublicKey>,
    own_history: &dyn Fn(&str) -> Option<Vec<SignedLedgerUpdate>>,
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
    let mut seen_member_ledgers: HashSet<String> = HashSet::new();

    for m in members {
        if m.pubkey == *our_key || acted.contains(&m.pubkey) || !seated.contains(&m.pubkey) {
            continue;
        }
        if !seen_member_ledgers.insert(m.ledger_id.clone()) || already_reported(&m.ledger_id) {
            continue;
        }
        let Some(member_ledger_bytes) = decode_ledger_id(&m.ledger_id) else {
            continue;
        };
        let Some(history) = own_history(&m.ledger_id) else {
            continue;
        };
        let Some(vis) = ascending.iter().find(|u| {
            u.block_height >= anchor && u.cosignatures.iter().any(|c| c.cosigner_pubkey == m.pubkey)
        }) else {
            continue;
        };
        let required = m.dispute_response_blocks.unwrap_or(144);
        let deadline = vis.block_height.saturating_add(required);
        let Some(active) = history
            .iter()
            .filter(|u| u.operator_id == m.pubkey && u.block_height >= deadline)
            .max_by_key(|u| u.sequence_number)
        else {
            continue;
        };
        let broadcast = make_dispute_dereliction_proof(
            &m.pubkey,
            &member_ledger_bytes,
            &watch.original,
            &watch.disclosure,
            qb,
            vis,
            active.sequence_number,
        );
        match verify(&broadcast, &history) {
            Ok(()) => out.push(broadcast),
            Err(e) => tracing::info!(
                "not reporting {}: our own dereliction proof does not verify: {}",
                hex::encode(&m.pubkey.serialize()[..8]),
                e
            ),
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
            let own_history = |lid: &str| -> Option<Vec<SignedLedgerUpdate>> {
                let ledgers = self.handler.ledgers.lock().unwrap();
                ledgers
                    .get(lid)
                    .map(|arc| arc.read().unwrap().history.clone())
            };
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
                &own_history,
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
