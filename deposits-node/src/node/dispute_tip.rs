//! Where a dispute fork's next update of ours goes: read off the fork's STORED history.
//!
//! A `DisputeAcquire` and a `DisputeYield` were both built at `our_armed.sequence_number + 1`,
//! chained onto the arm. That is the fork's tip only when nothing followed the arm, and the fold
//! lets things follow it: an Armed fork takes `QuorumAddMember` (43) and a collateral-upgrade
//! re-arm (`DisputeState::allows_operation`), and a yield or an acquire ends the round
//! (DEP-06 §"Where a yield is valid", DEP-03 §"When a pledge is live"). Regtest rearm-rust
//! (2026-11-21, ref7):
//!
//! - c8b9b7b1: seq 26 is ref7's ROUND-2 arm and seq 27 a `DisputeYield` the round-1 claim-or-yield
//!   pass signed on top of it. ref7 then won round 2, broadcast its claim (it confirmed), and
//!   computed the acquire at 26 + 1 = 27, where the write-ahead guard found the yield and refused.
//!   On that fork the round is over: a yield after an arm Tombstones the fork and the fold takes
//!   nothing more (`DisputeState::Tombstoned` allows no operation), so no acquire is valid there at
//!   ANY sequence; the claim must not be broadcast at all.
//! - 2fea4c6b: seq 221 is ref7's arm and 222..228 are its own `QuorumAddMember`s. The yield was
//!   computed at 222, found our 43 there, and was refused every pass; it belongs at 229.
//!
//! [`after_our_arm`] answers from the fork itself, so the acquire and the yield append at the
//! real tip, or are refused BEFORE anything irreversible happens.

use deposits_core::messages::LedgerOperation;
use deposits_core::SignedLedgerUpdate;
use deposits_core::TlvDecode;

/// What follows our arm on our fork.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AfterArm<'a> {
    /// Nothing ends the arm's round: the next update goes at `tip.sequence_number + 1`,
    /// chained on `tip.chain_hash()`, its header no earlier than `tip`'s.
    Append(&'a SignedLedgerUpdate),
    /// The round is already over on this fork: this acquire or yield follows the arm.
    Concluded(&'a SignedLedgerUpdate),
    /// Our arm is not on this fork, or a later arm (or a new dispute) follows it, so the arm
    /// the caller holds is stale.
    NotOurs(&'static str),
}

/// What follows `arm` (matched by sequence and content hash) in `history`.
pub(crate) fn after_our_arm<'a>(
    history: &'a [SignedLedgerUpdate],
    arm: &SignedLedgerUpdate,
) -> AfterArm<'a> {
    let Some(at) = history.iter().position(|u| {
        u.sequence_number == arm.sequence_number && u.content_hash == arm.content_hash
    }) else {
        return AfterArm::NotOurs("our arm is not on this fork");
    };
    for u in &history[at + 1..] {
        match LedgerOperation::tlv_decode(&u.message) {
            Ok(LedgerOperation::DisputeAcquire { .. }) | Ok(LedgerOperation::DisputeYield) => {
                return AfterArm::Concluded(u)
            }
            Ok(LedgerOperation::DisputeArmed { .. }) => {
                return AfterArm::NotOurs("a later arm follows ours on the fork")
            }
            Ok(LedgerOperation::DisputeEnter { .. }) => {
                return AfterArm::NotOurs("a later dispute follows ours on the fork")
            }
            _ => {}
        }
    }
    AfterArm::Append(history.last().expect("the arm is in history"))
}

/// The sequence and parent of the `DisputeAcquire` for `our_armed`, decided BEFORE the claim is
/// broadcast. `fork` is our fork's history (None: a fork-less, manual-recovery operator, which
/// chains on the arm as before). `Ok((seq, None))` means an acquire of ours is already at `seq`:
/// a retry, which republishes those bytes and signs nothing.
pub(crate) fn acquire_slot(
    fork: Option<&[SignedLedgerUpdate]>,
    our_armed: &SignedLedgerUpdate,
) -> Result<(u64, Option<SignedLedgerUpdate>), String> {
    let Some(history) = fork else {
        return Ok((our_armed.sequence_number + 1, Some(our_armed.clone())));
    };
    match after_our_arm(history, our_armed) {
        AfterArm::Append(tip) => Ok((tip.sequence_number + 1, Some(tip.clone()))),
        AfterArm::Concluded(u) => match LedgerOperation::tlv_decode(&u.message) {
            Ok(LedgerOperation::DisputeAcquire { .. }) => Ok((u.sequence_number, None)),
            _ => Err(format!(
                "our fork yielded this arm's round at seq {} (arm at seq {}); no acquire is valid \
                 on it, so the claim is not broadcast",
                u.sequence_number, our_armed.sequence_number
            )),
        },
        AfterArm::NotOurs(why) => Err(format!(
            "{} (arm at seq {}); not claiming",
            why, our_armed.sequence_number
        )),
    }
}

/// The round an arm is for (round 1's arms carry no TLV 366).
pub(crate) fn arm_round(arm: &SignedLedgerUpdate) -> Option<u32> {
    match LedgerOperation::tlv_decode(&arm.message) {
        Ok(LedgerOperation::DisputeArmed { rearm_round, .. }) => Some(rearm_round.unwrap_or(1)),
        _ => None,
    }
}

/// Whether the round-1 claim-or-yield pass may decide for this arm. A later round's arm is
/// `rearm.rs`'s (`rearm_reveal_and_claim`, which builds THAT round's lottery): the round-1 pass
/// builds round 1's lottery, in which a round-2-only armer is not a participant, so it always
/// "loses" and yields, Tombstoning the fork for the round it actually armed in (c8b9b7b1, ref7).
pub(crate) fn round1_pass_decides(our_armed: &SignedLedgerUpdate) -> bool {
    arm_round(our_armed) == Some(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::DepositsHandler;
    use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
    use deposits_core::types::DisputeState;
    use deposits_core::TlvEncode;

    const C8B9: &str =
        "c8b9b7b179ff1a17f8d5a9262cf16b27924a23e43919218c0df992db92a37564_000008_02c1e295f385acd7";

    fn fixture() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/vectors/ref7_rearm_yielded_fork.jsonl")
    }

    fn load(path: &std::path::Path) -> deposits_core::ledger::Ledger {
        DepositsHandler::load_single_ledger_from_jsonl(C8B9, path).expect("fixture loads")
    }

    /// The fixture without its last update: what ref7's fork was before the round-1 pass
    /// yielded on top of the round-2 arm.
    fn without_the_yield(dir: &std::path::Path) -> deposits_core::ledger::Ledger {
        let text = std::fs::read_to_string(fixture()).unwrap();
        let mut lines: Vec<&str> = text.lines().collect();
        while lines.last().is_some_and(|l| l.trim().is_empty()) {
            lines.pop();
        }
        assert!(lines.last().unwrap().contains("\"sequence_number\":27"));
        lines.pop();
        let p = dir.join("armed.jsonl");
        std::fs::write(&p, lines.join("\n") + "\n").unwrap();
        load(&p)
    }

    fn handler_with(
        dir: &std::path::Path,
        ledger: deposits_core::ledger::Ledger,
    ) -> DepositsHandler {
        let wallet = std::sync::Arc::new(crate::wallet::Wallet::new_mock(dir.to_path_buf()));
        let signer: std::sync::Arc<dyn deposits_signer_api::Signer> = std::sync::Arc::new(
            deposits_signer_api::LocalSigner::new(SecretKey::from_slice(&[1u8; 32]).unwrap()),
        );
        let (handler, _rx) = DepositsHandler::new(signer, wallet, dir.to_path_buf(), false);
        handler.ledgers.lock().unwrap().insert(
            C8B9.into(),
            std::sync::Arc::new(std::sync::RwLock::new(ledger)),
        );
        handler
    }

    fn acquire_op(custodian: bitcoin::secp256k1::PublicKey) -> LedgerOperation {
        LedgerOperation::DisputeAcquire {
            new_custodian: custodian,
            claim_txid: [0xae; 32],
            new_reserves_address: "bcrt1qref7".into(),
            confiscation_txid: Some([0x4c; 32]),
        }
    }

    /// An update of `op` at `parent`'s next slot, under ref7's operator id (the fold and
    /// `commit_self_authored_update` do not check the operator signature).
    fn child(parent: &SignedLedgerUpdate, seq: u64, op: &LedgerOperation) -> SignedLedgerUpdate {
        let kp =
            Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[7; 32]).unwrap());
        let mut u = SignedLedgerUpdate {
            message: op.tlv_encode(),
            message_type: 0x8001,
            operator_id: parent.operator_id,
            ledger_id: parent.ledger_id,
            sequence_number: seq,
            previous_hash: parent.chain_hash(),
            content_hash: [0u8; 32],
            block_height: parent.block_height + 1,
            block_hash: parent.block_hash,
            operator_signature: [0u8; 64],
            cosignatures: Vec::new(),
        };
        u.content_hash = u.compute_hash();
        u.operator_signature = Secp256k1::new()
            .sign_schnorr_no_aux_rand(&Message::from_digest(u.operator_digest()), &kp)
            .serialize();
        u
    }

    /// ref7's real fork of c8b9b7b1 (regtest rearm-rust, 2026-11-21): seq 9 DisputeEnter,
    /// 10..25 QuorumAddMember, 26 its ROUND-2 arm, 27 a DisputeYield. The round is over on that
    /// fork. The acquire must not be computed at 27 (the arm's seq + 1, where the yield is), and
    /// it must not go at 28 either: the fold refuses any update on a Tombstoned fork, so it is
    /// refused before the claim is broadcast.
    #[test]
    fn ref7s_yielded_fork_refuses_the_acquire_before_the_claim() {
        let fork = load(&fixture());
        let ref7 = fork.history.last().unwrap().operator_id;
        assert_eq!(
            &ref7.serialize()[..8],
            &hex::decode("02c1e295f385acd7").unwrap()[..]
        );
        assert_eq!(fork.state.dispute_state, DisputeState::Tombstoned);
        let arm = fork
            .history
            .iter()
            .find(|u| u.sequence_number == 26)
            .unwrap()
            .clone();
        assert_eq!(arm_round(&arm), Some(2), "seq 26 is the round-2 arm");
        let y = fork.history.last().unwrap();
        assert_eq!(y.sequence_number, 27);
        assert!(matches!(
            LedgerOperation::tlv_decode(&y.message),
            Ok(LedgerOperation::DisputeYield)
        ));

        assert_eq!(after_our_arm(&fork.history, &arm), AfterArm::Concluded(y));
        let refused =
            acquire_slot(Some(&fork.history), &arm).expect_err("no acquire on a yielded round");
        assert!(refused.contains("seq 27"), "{refused}");

        // And the fold agrees: an acquire chained on the yield is not a valid update, for any
        // member replaying the fork, nor for our own record.
        assert!(!fork.dispute_state_allows(&acquire_op(ref7)));
        let dir = tempfile::TempDir::new().unwrap();
        let h = handler_with(dir.path(), fork.clone());
        let a28 = child(y, 28, &acquire_op(ref7));
        assert!(h
            .commit_self_authored_update(C8B9, &acquire_op(ref7), a28.clone(), a28.block_height)
            .is_err());

        // The round-1 pass would not have decided for this arm, so it never yields it.
        assert!(!round1_pass_decides(&arm));
    }

    /// The same fork as it was before the stray yield (enter, adds, round-2 arm): ref7 wins
    /// round 2 and its acquire lands at the fork's tip + 1 = 27, chained onto the arm, and
    /// the fold takes it (custody to ref7, back to Normal). Then with QuorumAddMembers after
    /// the arm (Armed takes 43): the acquire goes after the LAST of them, never at arm + 1.
    #[test]
    fn a_round_two_win_appends_at_the_real_tip() {
        let dir = tempfile::TempDir::new().unwrap();
        let fork = without_the_yield(dir.path());
        assert_eq!(fork.state.dispute_state, DisputeState::Armed);
        let arm = fork.history.last().unwrap().clone();
        assert_eq!((arm.sequence_number, arm_round(&arm)), (26, Some(2)));
        let ref7 = arm.operator_id;

        let (seq, parent) = acquire_slot(Some(&fork.history), &arm).unwrap();
        let parent = parent.unwrap();
        assert_eq!((seq, parent.sequence_number), (27, 26));
        let a = child(&parent, seq, &acquire_op(ref7));
        assert_eq!(a.previous_hash, arm.chain_hash());

        // Our arm's own adds, copied from the fork (their content is ref7's, re-chained).
        let add = fork
            .history
            .iter()
            .find(|u| u.sequence_number == 25)
            .unwrap()
            .message
            .clone();
        let add_op = LedgerOperation::tlv_decode(&add).unwrap();
        assert!(matches!(add_op, LedgerOperation::QuorumAddMember { .. }));
        let mut longer = fork.history.clone();
        for s in 27..=29 {
            let next = child(longer.last().unwrap(), s, &add_op);
            longer.push(next);
        }
        let tip = longer.last().unwrap().clone();
        assert_eq!(after_our_arm(&longer, &arm), AfterArm::Append(&tip));
        let (seq2, parent2) = acquire_slot(Some(&longer), &arm).unwrap();
        assert_eq!(
            (seq2, parent2.as_ref().map(|p| p.chain_hash())),
            (30, Some(tip.chain_hash()))
        );

        // The fork takes the acquire at 27 (and it is idempotent).
        let h = handler_with(dir.path(), fork);
        assert_eq!(
            h.commit_self_authored_update(C8B9, &acquire_op(ref7), a.clone(), a.block_height),
            Ok(true)
        );
        let arc = h.ledgers.lock().unwrap().get(C8B9).cloned().unwrap();
        {
            let l = arc.read().unwrap();
            assert_eq!(l.state.dispute_state, DisputeState::Normal);
            assert_eq!(l.state.operator_key, ref7);
            assert_eq!(l.history.last(), Some(&a));
            // Nothing of ours at 27 but the acquire: one update per (ledger, seq).
            assert_eq!(
                l.history.iter().filter(|u| u.sequence_number == 27).count(),
                1
            );
            // A retry finds the acquire already there and signs nothing.
            assert_eq!(acquire_slot(Some(&l.history), &arm), Ok((27, None)));
        }
    }

    /// A round-1 yield followed by a round-2 arm (DEP-06 Phase 4: "a DisputeYield ends a
    /// round, not the dispute"; the fold takes a later round's arm on a Tombstoned fork): the
    /// round-2 acquire chains onto the round-2 arm, after the yield, never onto the round-1 arm.
    #[test]
    fn after_a_round_one_yield_the_round_two_acquire_follows_the_round_two_arm() {
        let dir = tempfile::TempDir::new().unwrap();
        let fork = without_the_yield(dir.path());
        let r2 = fork.history.last().unwrap().clone();
        let LedgerOperation::DisputeArmed {
            armed_block,
            commitment_hash,
            target_reserves,
            replacement_collateral,
            ..
        } = LedgerOperation::tlv_decode(&r2.message).unwrap()
        else {
            panic!()
        };
        let mut h = fork.history[..fork.history.len() - 1].to_vec();
        let r1 = child(
            h.last().unwrap(),
            26,
            &LedgerOperation::DisputeArmed {
                armed_block,
                commitment_hash,
                target_reserves: target_reserves.clone(),
                replacement_collateral: replacement_collateral.clone(),
                rearm_round: None,
            },
        );
        h.push(r1.clone());
        h.push(child(&r1, 27, &LedgerOperation::DisputeYield));
        let r2b = child(
            h.last().unwrap(),
            28,
            &LedgerOperation::DisputeArmed {
                armed_block,
                commitment_hash: [0x22; 20],
                target_reserves,
                replacement_collateral,
                rearm_round: Some(2),
            },
        );
        h.push(r2b.clone());
        // The round-1 arm's round is over; the round-1 pass does not decide the round-2 arm.
        assert!(matches!(after_our_arm(&h, &r1), AfterArm::Concluded(_)));
        assert!(round1_pass_decides(&r1) && !round1_pass_decides(&r2b));
        let (seq, parent) = acquire_slot(Some(&h), &r2b).unwrap();
        assert_eq!((seq, parent.unwrap().chain_hash()), (29, r2b.chain_hash()));
        // The stale round-1 arm can never anchor an acquire.
        assert!(acquire_slot(Some(&h), &r1).is_err());
    }

    /// ref7's 2fea4c6b (regtest 2026-11-21): arm at 221, its own QuorumAddMembers at 222..228,
    /// and the yield computed at 222 every pass, where `backfill_decision` found our add and held
    /// ("an update of ours other than this fork's yield is at that sequence"). Asked at the
    /// fork's real tip there is nothing of ours yet, so the yield is signed at 229 onto 228.
    #[test]
    fn a_yield_after_our_adds_goes_at_the_real_tip() {
        use super::super::yield_backfill::{backfill_decision, Backfill};
        let kp =
            Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[7; 32]).unwrap());
        let me = kp.public_key();
        let fork = load(&fixture());
        let add_op = LedgerOperation::tlv_decode(
            &fork
                .history
                .iter()
                .find(|u| u.sequence_number == 25)
                .unwrap()
                .message,
        )
        .unwrap();
        let arm_op = LedgerOperation::tlv_decode(
            &fork
                .history
                .iter()
                .find(|u| u.sequence_number == 26)
                .unwrap()
                .message,
        )
        .unwrap();
        let mut base = fork
            .history
            .iter()
            .find(|u| u.sequence_number == 25)
            .unwrap()
            .clone();
        base.operator_id = me;
        let mut h = vec![base];
        let arm = child(h.last().unwrap(), 221, &arm_op);
        h.push(arm.clone());
        for s in 222..=228 {
            let next = child(h.last().unwrap(), s, &add_op);
            h.push(next);
        }
        let tip = h.last().unwrap().clone();
        assert_eq!(after_our_arm(&h, &arm), AfterArm::Append(&tip));
        // What the relay holds at arm + 1 is our add, so the arm-anchored yield is held forever.
        let at_222: Vec<SignedLedgerUpdate> = h
            .iter()
            .filter(|u| u.sequence_number == 222)
            .cloned()
            .collect();
        assert!(matches!(
            backfill_decision(&arm, &me, Ok(&at_222), false),
            Backfill::Hold(_)
        ));
        // At the real tip nothing of ours is at 229: sign there, chained on 228.
        assert_eq!(backfill_decision(&tip, &me, Ok(&[]), false), Backfill::Sign);
        let y = child(
            &tip,
            tip.sequence_number + 1,
            &LedgerOperation::DisputeYield,
        );
        assert_eq!(
            (y.sequence_number, y.previous_hash),
            (229, tip.chain_hash())
        );
        h.push(y.clone());
        // Once it is there the round is concluded: no second yield, and no acquire.
        assert_eq!(after_our_arm(&h, &arm), AfterArm::Concluded(&y));
        assert!(acquire_slot(Some(&h), &arm).is_err());
    }

    /// A fork-less operator (manual recovery, journaled) chains on its arm, as before.
    #[test]
    fn without_a_fork_the_acquire_chains_on_the_arm() {
        let fork = load(&fixture());
        let arm = fork
            .history
            .iter()
            .find(|u| u.sequence_number == 26)
            .unwrap()
            .clone();
        let (seq, parent) = acquire_slot(None, &arm).unwrap();
        assert_eq!((seq, parent.unwrap().chain_hash()), (27, arm.chain_hash()));
        assert!(matches!(
            after_our_arm(&fork.history[..20], &arm),
            AfterArm::NotOurs(_)
        ));
    }
}
