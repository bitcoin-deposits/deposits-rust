//! A loser's `DisputeYield` that we signed and broadcast but never recorded on our own fork.
//!
//! Until b758991 `publish_custody_yield` broadcast the yield and never appended it to our
//! fork, so the fork stayed Armed in our own records for good and its pledge was never released
//! (regtest 1120-next4: ref6, 86 of 151 forks entered and armed, never concluded locally, 29 of
//! them marked `lottery_completed`). Those yields are SIGNED AND PUBLISHED at the sequence after
//! our arm. Signing a fresh one there now, with any other header, would be an equivocation by us,
//! so the backfill adopts the exact published bytes, and signs only when we know nothing of ours
//! was ever published at that sequence.
//!
//! The rule, as a pure function ([`backfill_decision`]):
//! - the relay query failed: hold (ask again next pass);
//! - exactly one yield of ours chains onto our arm at that sequence: adopt THOSE bytes;
//! - two different updates of ours already sit there, or one that is not that yield: hold,
//!   and never add another;
//! - nothing of ours there, but we know we published a yield (`lottery_completed`, written only
//!   after the broadcast returned): hold. The relays have lost it or not returned it; signing a
//!   second one is the equivocation this module exists to avoid. The fork stays Armed and its
//!   pledge stays held (a lost acquire would look the same from here); it is logged each pass;
//! - nothing of ours there, and nothing says we published: sign one ([`Backfill::Sign`]).
//!
//! The same decision guards the live loser path (`publish_custody_yield`), so a restart between
//! the broadcast and the marker cannot sign twice either.

use deposits_core::messages::LedgerOperation;
use deposits_core::SignedLedgerUpdate;
use deposits_core::TlvDecode;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Backfill {
    /// Append these exact signed bytes: our yield as the relays hold it.
    Adopt(SignedLedgerUpdate),
    /// Nothing of ours was ever published at this sequence: sign a yield.
    Sign,
    /// Do nothing (now).
    Hold(&'static str),
}

/// What to do at the sequence after `tip` (our own `DisputeArmed`, the tip of our fork).
/// `relay` is every update the relays returned at `tip.sequence_number + 1` (`Err(())` when
/// the query failed); `published` that we know a yield of ours went out for this fork.
pub(crate) fn backfill_decision(
    tip: &SignedLedgerUpdate,
    me: &bitcoin::secp256k1::PublicKey,
    relay: Result<&[SignedLedgerUpdate], ()>,
    published: bool,
) -> Backfill {
    let Ok(relay) = relay else {
        return Backfill::Hold("the relay query failed");
    };
    let seq = tip.sequence_number + 1;
    // Ours: signed by our key, intact, at this sequence. Distinct by content.
    let mut ours: Vec<&SignedLedgerUpdate> = Vec::new();
    for u in relay.iter().filter(|u| {
        u.sequence_number == seq
            && u.operator_id == *me
            && u.content_hash == u.compute_hash()
            && u.verify_operator_signature().is_ok()
    }) {
        if !ours.iter().any(|o| o.content_hash == u.content_hash) {
            ours.push(u);
        }
    }
    match ours.as_slice() {
        [] if published => Backfill::Hold(
            "we published a yield here that no relay returns; not signing a second",
        ),
        [] => Backfill::Sign,
        [one] => {
            let is_yield = matches!(
                LedgerOperation::tlv_decode(&one.message),
                Ok(LedgerOperation::DisputeYield { .. })
            );
            if is_yield && one.previous_hash == tip.chain_hash() {
                Backfill::Adopt((*one).clone())
            } else {
                Backfill::Hold("an update of ours other than this fork's yield is at that sequence")
            }
        }
        _ => Backfill::Hold("two different updates of ours are already at that sequence"),
    }
}

/// Our `DisputeArmed` at the tip of `history`, if that is what the tip is, and it is a round-1
/// arm (a later round's arm is not concluded by the round-1 lottery marker).
pub(crate) fn armed_round1_tip<'a>(
    history: &'a [SignedLedgerUpdate],
    me: &bitcoin::secp256k1::PublicKey,
) -> Option<&'a SignedLedgerUpdate> {
    let tip = history.last()?;
    (tip.operator_id == *me
        && matches!(
            LedgerOperation::tlv_decode(&tip.message),
            Ok(LedgerOperation::DisputeArmed { rearm_round, .. }) if rearm_round.unwrap_or(1) <= 1
        ))
    .then_some(tip)
}

impl super::Node {
    /// Whether we recorded this ledger's lottery as completed (claimed or yielded).
    pub(crate) fn lottery_completed(&self, ledger_id: &str) -> bool {
        self.data_dir
            .join(format!(
                "lottery_completed_{}.marker",
                &ledger_id[..16.min(ledger_id.len())]
            ))
            .exists()
    }

    /// Ask the relays what is at `tip`'s next sequence of `ledger_id` and decide.
    pub(crate) async fn yield_backfill_for(
        &self,
        ledger_id: &str,
        tip: &SignedLedgerUpdate,
        published: bool,
    ) -> Backfill {
        let relay = self
            .nostr
            .fetch_ledger_updates_at_seq(ledger_id, tip.sequence_number + 1)
            .await
            .map_err(|e| {
                tracing::warn!(
                    "yield backfill {}: relay query at seq {}: {:?}",
                    &ledger_id[..16.min(ledger_id.len())],
                    tip.sequence_number + 1,
                    e
                )
            });
        backfill_decision(tip, &self.node_id, relay.as_deref().map_err(|_| ()), published)
    }

    /// Startup and every stand-down pass: for each fork of ours whose tip is our round-1 arm and
    /// whose lottery we recorded as completed, adopt the yield we published there.
    pub(crate) async fn reconcile_published_yields(&self) {
        let candidates: Vec<(String, String, SignedLedgerUpdate)> = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            ledgers
                .iter()
                .filter(|(k, _)| k.len() > 64)
                .filter_map(|(k, arc)| {
                    let l = arc.read().unwrap();
                    if l.state.parent_pubkey != self.node_id
                        || l.state.dispute_state != deposits_core::types::DisputeState::Armed
                    {
                        return None;
                    }
                    let tip = armed_round1_tip(&l.history, &self.node_id)?;
                    Some((k.clone(), k[..64].to_string(), tip.clone()))
                })
                .filter(|(_, lid, _)| self.lottery_completed(lid))
                .collect()
        };
        for (fork_key, ledger_id, tip) in candidates {
            let pfx = &ledger_id[..16];
            match self.yield_backfill_for(&ledger_id, &tip, true).await {
                Backfill::Adopt(y) => match self.handler.commit_self_authored_update(
                    &fork_key,
                    // the op those bytes carry, reason and all
                    &LedgerOperation::tlv_decode(&y.message)
                        .unwrap_or_else(|_| LedgerOperation::dispute_yield()),
                    y.clone(),
                    y.block_height,
                ) {
                    Ok(_) => tracing::warn!(
                        "yield backfill {}: recorded our published DisputeYield at seq {} \
                         (the exact relay bytes); the fork is tombstoned and its pledge free",
                        pfx,
                        y.sequence_number
                    ),
                    Err(e) => tracing::warn!("yield backfill {}: {}", pfx, e),
                },
                Backfill::Hold(why) => {
                    tracing::warn!("yield backfill {}: holding: {}", pfx, why)
                }
                // Not reachable with `published`: never sign here.
                Backfill::Sign => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
    use deposits_core::TlvEncode;

    fn key(b: u8) -> Keypair {
        Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[b; 32]).unwrap())
    }

    fn signed(kp: &Keypair, seq: u64, prev: [u8; 32], op: &LedgerOperation, header: u32) -> SignedLedgerUpdate {
        let mut u = SignedLedgerUpdate {
            message: op.tlv_encode(),
            message_type: 0x8001,
            operator_id: kp.public_key(),
            ledger_id: [5u8; 32],
            sequence_number: seq,
            previous_hash: prev,
            content_hash: [0u8; 32],
            block_height: header,
            block_hash: [header as u8; 32],
            operator_signature: [0u8; 64],
            cosignatures: Vec::new(),
        };
        u.content_hash = u.compute_hash();
        u.operator_signature = Secp256k1::new()
            .sign_schnorr_no_aux_rand(&Message::from_digest(u.operator_digest()), kp)
            .serialize();
        u
    }

    fn arm() -> LedgerOperation {
        LedgerOperation::DisputeArmed {
            armed_block: 100,
            commitment_hash: [1; 20],
            target_reserves: "t".into(),
            replacement_collateral: None,
            rearm_round: None,
        }
    }

    /// DEP-06 "An invalid yield is void": a yield naming a transaction that is not confirmed
    /// frees no pledge (it reads as absent), and frees it once that transaction confirms; a
    /// reasonless yield (an earlier ruleset's) frees it as before. The same fork with the
    /// reason's check removed would free the pledge in every row.
    #[test]
    fn a_yield_whose_named_transaction_is_unconfirmed_frees_no_pledge() {
        use crate::node::dispute::{fork_events, fork_holds};
        use bitcoin::hashes::Hash as _;
        let me = key(1);
        let pledged = LedgerOperation::DisputeArmed {
            armed_block: 100,
            commitment_hash: [1; 20],
            target_reserves: "t".into(),
            replacement_collateral: Some(deposits_core::messages::ReplacementCollateral {
                txid: [7; 32],
                vout: 1,
                amount: 50_000,
            }),
            rearm_round: None,
        };
        let a = signed(&me, 10, [0; 32], &pledged, 100);
        let named = [0xab; 32];
        let held = |y: &LedgerOperation, confirmed: bool| {
            let h = vec![a.clone(), signed(&me, 11, a.chain_hash(), y, 101)];
            let c = move |t: &bitcoin::Txid| confirmed && t.to_byte_array() == named;
            fork_holds(&fork_events(&h, &me.public_key(), &c), false, &[]).0.len()
        };
        let lost_to = LedgerOperation::DisputeYield {
            lost_to: Some(named),
            reestablished: None,
            excluded_by: None,
            superseded_by: None,
        };
        let excluded_by = LedgerOperation::DisputeYield {
            lost_to: None,
            reestablished: None,
            excluded_by: Some(named),
            superseded_by: None,
        };
        assert_eq!(held(&lost_to, false), 1, "lost_to unconfirmed: the pledge is held");
        assert_eq!(held(&lost_to, true), 0, "lost_to confirmed: freed");
        assert_eq!(held(&excluded_by, false), 1, "excluded_by unconfirmed: held");
        assert_eq!(held(&excluded_by, true), 0, "excluded_by confirmed: freed");
        assert_eq!(held(&LedgerOperation::dispute_yield(), false), 0, "a reasonless yield: freed");
    }

    /// ref6's disk: our arm at the tip, `lottery_completed`, our yield on the relay.
    #[test]
    fn ref6s_shape_adopts_the_published_bytes() {
        let me = key(1);
        let tip = signed(&me, 23, [0; 32], &arm(), 100);
        let y = signed(&me, 24, tip.chain_hash(), &LedgerOperation::dispute_yield(), 140);
        let other = signed(&key(2), 24, tip.chain_hash(), &LedgerOperation::dispute_yield(), 141);
        let relay = vec![other.clone(), y.clone(), y.clone()];
        assert_eq!(
            backfill_decision(&tip, &me.public_key(), Ok(&relay), true),
            Backfill::Adopt(y)
        );
        // Not on the relay: published, so hold rather than sign a second.
        assert!(matches!(
            backfill_decision(&tip, &me.public_key(), Ok(&[other]), true),
            Backfill::Hold(_)
        ));
        // The query failed: hold.
        assert!(matches!(
            backfill_decision(&tip, &me.public_key(), Err(()), false),
            Backfill::Hold(_)
        ));
        // Never published, nothing of ours there: sign.
        assert_eq!(
            backfill_decision(&tip, &me.public_key(), Ok(&[]), false),
            Backfill::Sign
        );
    }

    #[test]
    fn a_round_two_arm_is_not_concluded_by_the_round_one_marker() {
        let me = key(1);
        let r2 = LedgerOperation::DisputeArmed {
            armed_block: 100,
            commitment_hash: [2; 20],
            target_reserves: "t".into(),
            replacement_collateral: None,
            rearm_round: Some(2),
        };
        let h = vec![signed(&me, 30, [0; 32], &r2, 100)];
        assert!(armed_round1_tip(&h, &me.public_key()).is_none());
        let h = vec![signed(&me, 30, [0; 32], &arm(), 100)];
        assert!(armed_round1_tip(&h, &me.public_key()).is_some());
        let h = vec![signed(&key(2), 30, [0; 32], &arm(), 100)];
        assert!(armed_round1_tip(&h, &me.public_key()).is_none());
    }

    /// The property: across reconciliation, no two of our signatures share (ledger, seq) with
    /// different content. Every scenario the relays can present at the sequence after our arm
    /// (nothing; our yield; a second yield of ours with another header; another update of ours;
    /// others' updates; a failed query; with and without the `published` mark), many times over,
    /// with the decision acted on: an adopted update must be one of ours already there, and a
    /// fresh signature only where nothing of ours was.
    #[test]
    fn reconciliation_never_signs_two_updates_at_one_sequence() {
        let me = key(1);
        let them = key(2);
        let mut state: u64 = 0x5eed_1120;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut signed_fresh = 0;
        let mut adopted = 0;
        for _ in 0..4000 {
            let seq = 10 + next() % 100;
            let tip = signed(&me, seq, [(next() % 255) as u8; 32], &arm(), 100);
            let mut relay = Vec::new();
            let r = next();
            if r & 1 != 0 {
                relay.push(signed(&me, seq + 1, tip.chain_hash(), &LedgerOperation::dispute_yield(), 140));
            }
            if r & 2 != 0 {
                // The equivocation the old code could produce: our second yield, another header.
                relay.push(signed(&me, seq + 1, tip.chain_hash(), &LedgerOperation::dispute_yield(), 150));
            }
            if r & 4 != 0 {
                relay.push(signed(&me, seq + 1, tip.chain_hash(), &arm(), 160));
            }
            if r & 8 != 0 {
                relay.push(signed(&them, seq + 1, tip.chain_hash(), &LedgerOperation::dispute_yield(), 140));
            }
            if r & 16 != 0 {
                // Ours, at another sequence: irrelevant here.
                relay.push(signed(&me, seq + 2, [9; 32], &LedgerOperation::dispute_yield(), 170));
            }
            if r & 32 != 0 {
                // Tampered: claims to be ours, signature does not verify.
                let mut t = signed(&me, seq + 1, tip.chain_hash(), &LedgerOperation::dispute_yield(), 180);
                t.operator_signature[0] ^= 1;
                relay.push(t);
            }
            let failed = r & 64 != 0;
            let published = r & 128 != 0;
            let ours_before: std::collections::BTreeSet<[u8; 32]> = relay
                .iter()
                .filter(|u| {
                    u.sequence_number == seq + 1
                        && u.operator_id == me.public_key()
                        && u.verify_operator_signature().is_ok()
                })
                .map(|u| u.content_hash)
                .collect();
            let decision = backfill_decision(
                &tip,
                &me.public_key(),
                if failed { Err(()) } else { Ok(&relay) },
                published,
            );
            let mut ours_after = ours_before.clone();
            match &decision {
                Backfill::Adopt(u) => {
                    adopted += 1;
                    assert!(ours_before.contains(&u.content_hash), "adopted something not ours on the relay");
                    assert_eq!(ours_before.len(), 1, "adopted where two of ours already disagree");
                    assert!(u.verify_operator_signature().is_ok());
                }
                Backfill::Sign => {
                    signed_fresh += 1;
                    assert!(!failed && !published, "signed without knowing nothing of ours went out");
                    let fresh = signed(&me, seq + 1, tip.chain_hash(), &LedgerOperation::dispute_yield(), 200 + (next() % 50) as u32);
                    ours_after.insert(fresh.content_hash);
                }
                Backfill::Hold(_) => {}
            }
            assert!(
                ours_after.len() <= ours_before.len().max(1),
                "{:?} added a second signature at (ledger, {}): before {} after {}",
                decision,
                seq + 1,
                ours_before.len(),
                ours_after.len()
            );
        }
        // Both arms of the decision actually ran.
        assert!(signed_fresh > 0 && adopted > 0, "fresh {signed_fresh} adopted {adopted}");
    }

    /// ref6's own disk, a fork marked `lottery_completed` whose local tip is its round-1 arm
    /// (regtest 1120-next4, ledger 04f435e3…, fork at seq 4, arm at seq 12). The yield the
    /// relays hold is ref6-signed, which this test cannot reproduce, so the relay half is the
    /// decision above; this half is that adopting bytes that chain onto the arm concludes the
    /// fork in our records, persists them unchanged, and frees its pledge.
    #[test]
    fn ref6s_disk_concludes_when_the_published_yield_is_adopted() {
        use crate::handler::DepositsHandler;
        let key = "04f435e315169389fe189a4236aaa56ad17f73370fcc96c880c7e4ac98f9f77b_000004_02a417593a974f4f";
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/ref6_armed_fork.jsonl");
        let ledger = DepositsHandler::load_single_ledger_from_jsonl(key, &src).expect("fixture loads");
        let ref6 = ledger.history.last().unwrap().operator_id;
        assert_eq!(&ref6.serialize()[..8], &hex::decode("02a417593a974f4f").unwrap()[..]);
        assert_eq!(ledger.state.dispute_state, deposits_core::types::DisputeState::Armed);
        let tip = armed_round1_tip(&ledger.history, &ref6).expect("tip is ref6's round-1 arm").clone();
        let held = |h: &[SignedLedgerUpdate]| super::super::dispute::fork_holds(&super::super::dispute::fork_events(h, &ref6, &|_| false), false, &[]).0;
        assert_eq!(held(&ledger.history).len(), 1, "the arm holds its pledge");

        // The relay's yield, as published: ref6's, chained onto the arm, at arm+1.
        let mut y = signed(&key_of_bytes(), tip.sequence_number + 1, tip.chain_hash(), &LedgerOperation::dispute_yield(), tip.block_height + 3);
        y.operator_id = ref6;
        y.content_hash = y.compute_hash();

        let dir = tempfile::TempDir::new().unwrap();
        let wallet = std::sync::Arc::new(crate::wallet::Wallet::new_mock(dir.path().to_path_buf()));
        let signer: std::sync::Arc<dyn deposits_signer_api::Signer> = std::sync::Arc::new(
            deposits_signer_api::LocalSigner::new(bitcoin::secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap()),
        );
        let (handler, _rx) = DepositsHandler::new(signer, wallet, dir.path().to_path_buf(), false);
        handler.ledgers.lock().unwrap().insert(key.into(), std::sync::Arc::new(std::sync::RwLock::new(ledger)));
        assert_eq!(
            handler.commit_self_authored_update(key, &LedgerOperation::dispute_yield(), y.clone(), y.block_height),
            Ok(true)
        );
        // Idempotent: the same bytes again add nothing.
        assert_eq!(
            handler.commit_self_authored_update(key, &LedgerOperation::dispute_yield(), y.clone(), y.block_height),
            Ok(false)
        );
        let arc = handler.ledgers.lock().unwrap().get(key).cloned().unwrap();
        let l = arc.read().unwrap();
        assert_eq!(l.state.dispute_state, deposits_core::types::DisputeState::Tombstoned);
        assert_eq!(l.history.last(), Some(&y), "the exact bytes, unchanged");
        assert!(held(&l.history).is_empty(), "a concluded fork holds no pledge");
        assert!(armed_round1_tip(&l.history, &ref6).is_none(), "not a candidate on the next pass");
        // Persisted: what reloads is those bytes.
        let disk = dir.path().join("ledgers").join(format!("{key}.jsonl"));
        let back = DepositsHandler::load_single_ledger_from_jsonl(key, &disk).expect("persisted");
        assert_eq!(back.history.last(), Some(&y));
        assert_eq!(back.state.dispute_state, deposits_core::types::DisputeState::Tombstoned);
    }

    fn key_of_bytes() -> Keypair {
        key(7)
    }

}
