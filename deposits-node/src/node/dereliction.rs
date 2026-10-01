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
use deposits_core::fraud::{make_dispute_dereliction_proof, FraudBroadcast};
use deposits_core::messages::LedgerOperation;
use deposits_core::types::{QuorumMember, SignedLedgerUpdate};
use deposits_core::TlvDecode;

/// A punitive fraud proof we verified and disputed, held until the faulted
/// ledger's co-members have had `dispute_response_blocks` to respond.
#[derive(Clone, Debug)]
pub struct DerelictionWatch {
    /// Hash of the punitive proof that was (or should have been) acted on.
    pub original_fraud_hash: [u8; 32],
    /// Block where the proof became visible to us — the embed block if the
    /// broadcast carried one, else our chain tip when we first verified it.
    /// `verify_inactive_quorum_member` resolves this to a height via the
    /// block oracle and measures the response window from it.
    pub visible_block_hash: [u8; 32],
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
/// `DisputeDereliction` for each. Pure: every chain / relay / replica access
/// is injected, so the policy is unit-testable without a live node.
///
/// A member yields a proof iff all of:
///   - it is not us (`our_key`),
///   - it did not act on the dispute (`acted` excludes its pubkey),
///   - we have not already accused it for this proof (`already_reported`),
///   - its own ledger is one we replicate (`own_history` returns `Some`),
///   - that ledger carries an update it signed whose block confirms at
///     `visible_height + dispute_response_blocks` or later (it stayed online
///     past the deadline). The height is read via `confirms` — the same
///     block oracle the verifier uses — never the update's stamped height.
#[allow(clippy::too_many_arguments)]
pub(crate) fn plan_dereliction_proofs(
    members: &[QuorumMember],
    our_key: &PublicKey,
    visible_block_hash: [u8; 32],
    visible_height: u32,
    original_fraud_hash: [u8; 32],
    acted: &HashSet<PublicKey>,
    own_history: &dyn Fn(&str) -> Option<Vec<SignedLedgerUpdate>>,
    confirms: &dyn Fn(&[u8; 32]) -> Option<u32>,
    already_reported: &dyn Fn(&str) -> bool,
) -> Vec<FraudBroadcast> {
    let mut out = Vec::new();
    let mut seen_member_ledgers: HashSet<String> = HashSet::new();

    for m in members {
        // Never accuse our own key, a member that acted, or a ledger we've
        // already accused (also de-dupe members sharing a collateral ledger).
        if m.pubkey == *our_key || acted.contains(&m.pubkey) {
            continue;
        }
        if !seen_member_ledgers.insert(m.ledger_id.clone()) || already_reported(&m.ledger_id) {
            continue;
        }

        let member_ledger_bytes = match decode_ledger_id(&m.ledger_id) {
            Some(b) => b,
            None => continue,
        };

        // We must replicate the member's own ledger to cite its activity.
        let history = match own_history(&m.ledger_id) {
            Some(h) => h,
            None => continue,
        };

        let required = m.dispute_response_blocks.unwrap_or(144);
        let deadline = visible_height.saturating_add(required);

        // The newest update the member signed on its own ledger whose block
        // the verifier confirms at or past the deadline. Newest-first so the
        // first qualifying hit is the one we cite.
        let active_sequence = history
            .iter()
            .filter(|u| u.operator_id == m.pubkey)
            .filter_map(|u| confirms(&u.block_hash).map(|h| (u.sequence_number, h)))
            .filter(|(_, h)| *h >= deadline)
            .map(|(seq, _)| seq)
            .max();

        let Some(active_sequence) = active_sequence else {
            continue;
        };

        out.push(make_dispute_dereliction_proof(
            &m.pubkey,
            &member_ledger_bytes,
            &original_fraud_hash,
            visible_block_hash,
            required,
            active_sequence,
        ));
    }

    out
}

/// A 64-char hex ledger id to its 32 bytes, or `None` if malformed.
fn decode_ledger_id(ledger_id: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(ledger_id).ok()?;
    bytes.try_into().ok()
}

impl crate::Node {
    /// Record a punitive fraud proof we just disputed so the periodic
    /// dereliction scan can, once the window elapses, accuse any co-member
    /// of the faulted ledger that stayed active without acting. First writer
    /// wins per faulted ledger — the earliest visibility anchor is kept.
    pub(crate) fn register_dereliction_watch(
        &self,
        faulted_ledger_id: &str,
        original_fraud_hash: [u8; 32],
        visible_block_hash: [u8; 32],
    ) {
        self.pending_dereliction_watches
            .lock()
            .unwrap()
            .entry(faulted_ledger_id.to_string())
            .or_insert(DerelictionWatch {
                original_fraud_hash,
                visible_block_hash,
            });
    }

    /// The block hash where a fraud broadcast became visible to us: the
    /// block of the update it was embedded in (if we hold that ledger and
    /// update), else our current chain tip. Matches what
    /// `verify_inactive_quorum_member` resolves against the block oracle.
    pub(crate) fn dereliction_visible_block_hash(
        &self,
        broadcast: &deposits_core::fraud::FraudBroadcast,
    ) -> Option<[u8; 32]> {
        if let Some(embedding) = &broadcast.embedding {
            let ledgers = self.handler.ledgers.lock().unwrap();
            if let Some(arc) = ledgers.get(&embedding.ledger_id) {
                let ledger = arc.read().unwrap();
                if let Some(u) = ledger
                    .history
                    .iter()
                    .find(|u| u.sequence_number == embedding.sequence)
                {
                    if u.block_hash != [0u8; 32] {
                        return Some(u.block_hash);
                    }
                }
            }
        }
        self.wallet.get_block_hash().ok()
    }

    /// Periodic producer: scan each pending dereliction watch and broadcast
    /// a `DisputeDereliction` for every co-member of the faulted ledger that
    /// stayed active past its response window without acting.
    pub(crate) async fn auto_report_derelict_members(&self) {
        let watches: Vec<(String, DerelictionWatch)> = {
            let w = self.pending_dereliction_watches.lock().unwrap();
            w.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
        };
        if watches.is_empty() {
            return;
        }

        for (faulted_ledger_id, watch) in watches {
            // The visibility anchor must be confirmed in our own chain
            // before we can measure any window from it; keep waiting if not.
            let Some(visible_height) = self.wallet.confirms_block(&watch.visible_block_hash) else {
                continue;
            };

            // The faulted ledger's quorum members, from our replica of it.
            let members = {
                let ledgers = self.handler.ledgers.lock().unwrap();
                ledgers
                    .get(&faulted_ledger_id)
                    .map(|arc| arc.read().unwrap().state.quorum_members.clone())
            };
            let Some(members) = members else {
                continue;
            };
            if members.is_empty() {
                continue;
            }

            // Who acted: fork-branch DisputeEnter / DisputeArmed authors,
            // read from the faulted ledger's public update stream.
            let updates = self
                .fetch_all_ledger_updates_paginated(&faulted_ledger_id)
                .await;
            let acted = collect_acting_members(&updates);

            let original_fraud_hash_hex = hex::encode(watch.original_fraud_hash);

            let own_history = |lid: &str| -> Option<Vec<SignedLedgerUpdate>> {
                let ledgers = self.handler.ledgers.lock().unwrap();
                ledgers
                    .get(lid)
                    .map(|arc| arc.read().unwrap().history.clone())
            };
            let confirms = |hash: &[u8; 32]| self.wallet.confirms_block(hash);
            let already_reported = |lid: &str| {
                self.reported_derelictions
                    .lock()
                    .unwrap()
                    .contains(&(lid.to_string(), original_fraud_hash_hex.clone()))
            };

            let proofs = plan_dereliction_proofs(
                &members,
                &self.node_id,
                watch.visible_block_hash,
                visible_height,
                watch.original_fraud_hash,
                &acted,
                &own_history,
                &confirms,
                &already_reported,
            );

            for broadcast in &proofs {
                // Mark before broadcasting so a relay echo / next tick never
                // re-accuses even if the broadcast itself is slow.
                self.reported_derelictions.lock().unwrap().insert((
                    broadcast.proof.ledger_id.clone(),
                    original_fraud_hash_hex.clone(),
                ));
                tracing::warn!(
                    "DERELICTION: member {} stayed active on ledger {} past the response \
                     window without acting on fraud {} (faulted ledger {}); broadcasting \
                     DisputeDereliction",
                    &broadcast.proof.accused[..16.min(broadcast.proof.accused.len())],
                    &broadcast.proof.ledger_id[..16.min(broadcast.proof.ledger_id.len())],
                    &original_fraud_hash_hex[..16],
                    &faulted_ledger_id[..16.min(faulted_ledger_id.len())],
                );
                if let Err(e) = self.nostr.broadcast_fraud_proof(broadcast).await {
                    tracing::error!("Dereliction: fraud broadcast failed: {}", e);
                }
            }

            // Retire the watch once the window has long closed for every
            // member (tip well past the latest deadline): anyone who would
            // act has, and further scans would just re-page the relay.
            let max_required = members
                .iter()
                .map(|m| m.dispute_response_blocks.unwrap_or(144))
                .max()
                .unwrap_or(144);
            let retire_at = visible_height
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

    fn member(pubkey: PublicKey, ledger_id: [u8; 32], required: u32) -> QuorumMember {
        QuorumMember {
            pubkey,
            ledger_id: hex::encode(ledger_id),
            min_fee_bps: None,
            min_fee_fixed: None,
            max_fee_period: None,
            membership_until: None,
            dispute_response_blocks: Some(required),
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

    /// Minimal update signed by `operator`, at `seq`, stamped with `block_hash`.
    fn update(operator: PublicKey, seq: u64, block_hash: [u8; 32]) -> SignedLedgerUpdate {
        SignedLedgerUpdate {
            message: vec![],
            message_type: 0,
            operator_id: operator,
            ledger_id: [0u8; 32],
            sequence_number: seq,
            previous_hash: [0u8; 32],
            content_hash: [0u8; 32],
            block_height: 0,
            block_hash,
            operator_signature: [0u8; 64],
            cosignatures: vec![],
        }
    }

    // Shared scaffolding: member M (pubkey 0x02) with its own ledger 0xBB,
    // required window 144, visible at height 1000.
    struct Scene {
        members: Vec<QuorumMember>,
        our_key: PublicKey,
        visible_block_hash: [u8; 32],
        visible_height: u32,
        fraud_hash: [u8; 32],
        member_pk: PublicKey,
        member_ledger: [u8; 32],
        member_block_hash: [u8; 32],
        member_block_height: u32,
        member_history: Vec<SignedLedgerUpdate>,
    }

    fn scene(member_block_height: u32) -> Scene {
        let member_pk = pk(2);
        let member_ledger = [0xBB; 32];
        let member_block_hash = [0xCC; 32];
        let member_history = vec![update(member_pk, 200, member_block_hash)];
        Scene {
            members: vec![member(member_pk, member_ledger, 144)],
            our_key: pk(9),
            visible_block_hash: [0xAA; 32],
            visible_height: 1000,
            fraud_hash: [0x66; 32],
            member_pk,
            member_ledger,
            member_block_hash,
            member_block_height,
            member_history,
        }
    }

    impl Scene {
        fn own_history(&self) -> impl Fn(&str) -> Option<Vec<SignedLedgerUpdate>> + '_ {
            let want = hex::encode(self.member_ledger);
            let hist = self.member_history.clone();
            move |lid: &str| {
                if lid == want {
                    Some(hist.clone())
                } else {
                    None
                }
            }
        }
        fn confirms(&self) -> impl Fn(&[u8; 32]) -> Option<u32> + '_ {
            move |h: &[u8; 32]| {
                if *h == self.member_block_hash {
                    Some(self.member_block_height)
                } else {
                    None
                }
            }
        }
        fn plan(
            &self,
            acted: &HashSet<PublicKey>,
            already: &dyn Fn(&str) -> bool,
        ) -> Vec<FraudBroadcast> {
            plan_dereliction_proofs(
                &self.members,
                &self.our_key,
                self.visible_block_hash,
                self.visible_height,
                self.fraud_hash,
                acted,
                &self.own_history(),
                &self.confirms(),
                already,
            )
        }
    }

    #[test]
    fn accuses_member_active_past_window_that_did_not_act() {
        let s = scene(1000 + 200); // 200 blocks past visibility, window 144
        let proofs = s.plan(&HashSet::new(), &|_| false);
        assert_eq!(proofs.len(), 1, "expected one dereliction proof");
        let b = &proofs[0];
        assert_eq!(b.proof.accused, hex::encode(s.member_pk.serialize()));
        assert_eq!(b.proof.ledger_id, hex::encode(s.member_ledger));
        assert!(b.embedding.is_none(), "self-evident: no embedding");
        if let deposits_core::fraud::FraudEvidence::DisputeDereliction {
            original_fraud_hash,
            member_active_sequence,
            required_response_blocks,
            ..
        } = &b.proof.evidence
        {
            assert_eq!(*original_fraud_hash, hex::encode(s.fraud_hash));
            assert_eq!(*member_active_sequence, 200);
            assert_eq!(*required_response_blocks, 144);
        } else {
            panic!("wrong evidence variant");
        }
    }

    #[test]
    fn does_not_accuse_member_that_disputed() {
        let s = scene(1000 + 200);
        let mut acted = HashSet::new();
        acted.insert(s.member_pk); // the member acted on the dispute
        assert!(s.plan(&acted, &|_| false).is_empty());
    }

    #[test]
    fn does_not_accuse_member_still_inside_window() {
        // Member's newest update is only 100 blocks past visibility (< 144).
        let s = scene(1000 + 100);
        assert!(s.plan(&HashSet::new(), &|_| false).is_empty());
    }

    #[test]
    fn does_not_accuse_member_whose_ledger_we_do_not_hold() {
        let mut s = scene(1000 + 200);
        s.member_history.clear(); // own_history still returns Some(empty)...
                                  // ...so drop the whole ledger instead:
        let own_history = |_: &str| -> Option<Vec<SignedLedgerUpdate>> { None };
        let proofs = plan_dereliction_proofs(
            &s.members,
            &s.our_key,
            s.visible_block_hash,
            s.visible_height,
            s.fraud_hash,
            &HashSet::new(),
            &own_history,
            &s.confirms(),
            &|_| false,
        );
        assert!(proofs.is_empty());
    }

    #[test]
    fn never_accuses_our_own_key() {
        let mut s = scene(1000 + 200);
        s.our_key = s.member_pk; // we ARE the member
        assert!(s.plan(&HashSet::new(), &|_| false).is_empty());
    }

    #[test]
    fn skips_members_already_reported() {
        let s = scene(1000 + 200);
        let want = hex::encode(s.member_ledger);
        assert!(s.plan(&HashSet::new(), &|lid| lid == want).is_empty());
    }

    #[test]
    fn collect_acting_members_ignores_non_dispute_updates() {
        // An update with an undecodable/empty message is not a dispute action.
        let acted = collect_acting_members(&[update(pk(2), 1, [0u8; 32])]);
        assert!(acted.is_empty());
    }
}
