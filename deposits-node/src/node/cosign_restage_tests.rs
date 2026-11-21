// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! A cosign draft that falls behind the cosigners' window is RE-STAGED, never resent, and the
//! operator signs that sequence exactly once (cosign_restage; regtest 1121-101522).
//!
//! A real `LedgerActor` over a real operator ledger with an active three-member quorum. The
//! actor's outbox is served by the same round loop the daemon's drainer runs
//! (`drive_cosign_round`), whose attempt is three cosigners applying this crate's own header rule,
//! `check_cosign_header` (DEP-02's 6-block window, `COSIGN_MAX_BLOCK_SKEW`), at their own heights,
//! and signing what passes. Mirrors cl-deposits' restart gate "a cosign draft that falls behind
//! the window is re-stamped on retry", scenarios 1 and 2.

use super::cosign_restage::{drive_cosign_round, is_stale_refusal, CosignFailure};
use super::ledger_actor::{LedgerActor, LedgerEvent, LedgerOutbound};
use super::request_handlers::cosign::check_cosign_header;
use crate::handler::DepositsHandler;
use crate::wallet::Wallet;
use bitcoin::secp256k1::{
    ecdsa, Keypair, Message, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey,
};
use deposits_core::messages::LedgerOperation;
use deposits_core::types::{CosignData, CosignEntry, QuorumMember, SignedLedgerUpdate};
use deposits_signer_api::{LocalSigner, SigRole, SignContext, Signer, SignerError};
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::TempDir;
use tokio::sync::{mpsc, oneshot};

/// The mock wallet's height, which the ledger's LedgerOpen carries (a draft is never dated below it).
const H: u32 = 800_000;

/// The operator's signer, counting operator-update signatures per sequence: the write-ahead
/// property is "one signature at that (ledger, sequence)", so it is counted where it happens.
struct CountingSigner {
    inner: LocalSigner,
    by_seq: Mutex<std::collections::HashMap<u64, usize>>,
}

impl Signer for CountingSigner {
    fn pubkey(&self) -> PublicKey {
        self.inner.pubkey()
    }
    fn xonly_pubkey(&self) -> XOnlyPublicKey {
        self.inner.xonly_pubkey()
    }
    fn bip340_sign(&self, ctx: &SignContext, digest: &[u8; 32]) -> Result<[u8; 64], SignerError> {
        if let SigRole::OperatorUpdate { seq, .. } = ctx.role {
            *self.by_seq.lock().unwrap().entry(seq).or_default() += 1;
        }
        self.inner.bip340_sign(ctx, digest)
    }
    fn ecdsa_sign_sighash(
        &self,
        ctx: &SignContext,
        sighash: &[u8; 32],
    ) -> Result<ecdsa::Signature, SignerError> {
        self.inner.ecdsa_sign_sighash(ctx, sighash)
    }
    fn ecdh(&self, peer: &PublicKey) -> Result<[u8; 32], SignerError> {
        self.inner.ecdh(peer)
    }
    fn nip04_shared_key(&self, peer: &PublicKey) -> Result<[u8; 32], SignerError> {
        self.inner.nip04_shared_key(peer)
    }
}

fn member(pk: PublicKey) -> QuorumMember {
    QuorumMember {
        min_collateral_bps: None,
        dormancy_blocks: None,
        dormancy_notice_blocks: None,
        pubkey: pk,
        ledger_id: "a".repeat(64),
        min_fee_bps: None,
        min_fee_fixed: None,
        max_fee_period: None,
        membership_until: None,
        dispute_response_blocks: None,
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

/// A QuorumAddMember: an establishment operation, a rotation's first step (the one regtest lost).
fn add_member_op(pk: PublicKey, ledger_id: [u8; 32]) -> LedgerOperation {
    LedgerOperation::QuorumAddMember {
        min_collateral_bps: None,
        dormancy_blocks: None,
        dormancy_notice_blocks: None,
        quorum_member: pk,
        quorum_member_signature: [0u8; 64],
        member_ledger_id: hex::encode(ledger_id),
        min_fee_bps: None,
        min_fee_fixed: None,
        max_fee_period: None,
        membership_until: None,
        dispute_response_blocks: None,
        dispute_arm_blocks: None,
        service_response_blocks: None,
        max_transfer_timeout_blocks: None,
        max_descriptor_bytes: None,
        compensation_bps: None,
        compensation_deposit_id: None,
        compensation_frequency_blocks: None,
        member_response: None,
        member_signature: None,
    }
}

fn hash_at(h: u32) -> [u8; 32] {
    let mut b = [0x5au8; 32];
    b[..4].copy_from_slice(&h.to_le_bytes());
    b
}

/// When the scenario moves a height.
#[derive(Clone, Copy)]
enum Scenario {
    /// Seven blocks arrive between the draft and its first cosign request; everyone sees them.
    BlocksWhileQueued,
    /// The operator's view lags the members' by seven (a stale height cache under load); it
    /// catches up after the first attempt is refused.
    OperatorViewLags,
}

struct Outcome {
    result: Result<SignedLedgerUpdate, String>,
    history: Vec<SignedLedgerUpdate>,
    published: Vec<SignedLedgerUpdate>,
    signed_at_seq: usize,
    requests: usize,
    refusals: Vec<String>,
    seq: u64,
    data_dir: TempDir,
}

async fn run(scenario: Scenario) -> Outcome {
    let temp = TempDir::new().unwrap();
    let secp = Secp256k1::new();
    let op_sk = SecretKey::from_slice(&[0x11; 32]).unwrap();
    let local = LocalSigner::new(op_sk);
    let op_pk = local.pubkey();
    let signer = Arc::new(CountingSigner {
        inner: local,
        by_seq: Mutex::new(Default::default()),
    });
    let wallet = Arc::new(Wallet::new_mock(temp.path().to_path_buf()));
    let handler = Arc::new(
        DepositsHandler::new(
            signer.clone() as Arc<dyn Signer>,
            wallet,
            temp.path().to_path_buf(),
            false,
        )
        .0,
    );

    let cosigners: Vec<SecretKey> = (1u8..=3)
        .map(|i| SecretKey::from_slice(&[0x20 + i; 32]).unwrap())
        .collect();
    let ledger_arc = handler.get_or_create_ledger(op_pk, "test:restage".to_string());
    let (ledger_id, seq) = {
        let mut l = ledger_arc.write().unwrap();
        l.state.parent_pubkey = op_pk;
        l.state.quorum_state = deposits_core::QuorumState::Active;
        l.state.quorum_members = cosigners
            .iter()
            .map(|sk| member(PublicKey::from_secret_key(&secp, sk)))
            .collect();
        l.state.quorum_expiry = Some(H + 10_000);
        (l.state.ledger_id, l.next_sequence())
    };
    let ledger_hex = hex::encode(ledger_id);

    // Heights: the operator's view, and the cosigners' (one shared view).
    let (op_h, member_h) = match scenario {
        Scenario::BlocksWhileQueued => (H, H),
        Scenario::OperatorViewLags => (H, H + 7),
    };
    let op_height = Arc::new(AtomicU32::new(op_h));
    let member_height = Arc::new(AtomicU32::new(member_h));

    let (inbox_tx, inbox_rx) = mpsc::channel::<LedgerEvent>(8);
    let (outbox_tx, mut outbox_rx) = mpsc::unbounded_channel::<(String, LedgerOutbound)>();
    let tip = op_height.clone();
    let actor = LedgerActor {
        inbox: inbox_rx,
        outbox: outbox_tx,
        ledger: Arc::clone(&ledger_arc),
        ledger_id: ledger_hex.clone(),
        signer: signer.clone() as Arc<dyn Signer>,
        handler: Arc::clone(&handler),
        apply_wakeup: Arc::new(tokio::sync::Notify::new()),
        chain_tip: Arc::new(move || {
            let h = tip.load(Ordering::SeqCst);
            Some((h, hash_at(h)))
        }),
    };
    tokio::spawn(actor.run());

    // The drainer: Broadcast is recorded; RequestCosig runs the daemon's round loop over the
    // cosigners below.
    let published = Arc::new(Mutex::new(Vec::<SignedLedgerUpdate>::new()));
    let refusals = Arc::new(Mutex::new(Vec::<String>::new()));
    let requests = Arc::new(AtomicUsize::new(0));
    {
        let (published, refusals, requests) =
            (published.clone(), refusals.clone(), requests.clone());
        let (op_height, member_height) = (op_height.clone(), member_height.clone());
        tokio::spawn(async move {
            while let Some((_lid, ev)) = outbox_rx.recv().await {
                match ev {
                    LedgerOutbound::Broadcast { update, reply } => {
                        published.lock().unwrap().push(*update);
                        if let Some(r) = reply {
                            let _ = r.send(Ok("event".to_string()));
                        }
                    }
                    LedgerOutbound::RequestCosig {
                        update,
                        threshold,
                        reply,
                        ..
                    } => {
                        let n = requests.fetch_add(1, Ordering::SeqCst);
                        if n == 0 {
                            if let Scenario::BlocksWhileQueued = scenario {
                                op_height.fetch_add(7, Ordering::SeqCst);
                                member_height.fetch_add(7, Ordering::SeqCst);
                            }
                        }
                        let attempts = AtomicUsize::new(0);
                        let result = drive_cosign_round(
                            &update,
                            false,
                            || op_height.load(Ordering::SeqCst),
                            || {
                                let a = attempts.fetch_add(1, Ordering::SeqCst);
                                let update = update.clone();
                                let (refusals, op_height, member_height) =
                                    (refusals.clone(), op_height.clone(), member_height.clone());
                                let cosigners = cosigners.clone();
                                async move {
                                    let data = update.cosign_data();
                                    let fields =
                                        CosignData::parse(&data).map_err(CosignFailure::Failed)?;
                                    let mut entries: Vec<CosignEntry> = Vec::new();
                                    let mut refused: Vec<String> = Vec::new();
                                    for (i, sk) in cosigners.iter().enumerate() {
                                        match check_cosign_header(
                                            &fields,
                                            update.sequence_number,
                                            Some(ledger_id),
                                            member_height.load(Ordering::SeqCst),
                                            None,
                                        ) {
                                            Ok(()) => {
                                                let secp = Secp256k1::new();
                                                let mlh = [0x70 + i as u8; 32];
                                                let msg = Message::from_digest(
                                                    update.cosign_digest(&mlh),
                                                );
                                                let sig = secp.sign_schnorr_no_aux_rand(
                                                    &msg,
                                                    &Keypair::from_secret_key(&secp, sk),
                                                );
                                                entries.push(CosignEntry {
                                                    cosigner_pubkey: PublicKey::from_secret_key(
                                                        &secp, sk,
                                                    ),
                                                    cosign_signature: sig.serialize(),
                                                    member_ledger_hash: mlh,
                                                });
                                            }
                                            Err(m) => refused.push(m),
                                        }
                                    }
                                    refusals.lock().unwrap().extend(refused.iter().cloned());
                                    // The operator's cache refreshes once the first attempt is back.
                                    if let (Scenario::OperatorViewLags, 0) = (scenario, a) {
                                        op_height.store(
                                            member_height.load(Ordering::SeqCst),
                                            Ordering::SeqCst,
                                        );
                                    }
                                    if entries.len() >= threshold {
                                        Ok(entries)
                                    } else if refused.iter().any(|m| is_stale_refusal(m)) {
                                        Err(CosignFailure::StaleRefused(refused.join("; ")))
                                    } else {
                                        Err(CosignFailure::Failed(format!(
                                            "Cosign timeout: got {}/{} cosigs (refused: {})",
                                            entries.len(),
                                            threshold,
                                            refused.join("; ")
                                        )))
                                    }
                                }
                            },
                            Duration::from_millis(0),
                        )
                        .await;
                        let _ = reply.send(result);
                    }
                    LedgerOutbound::MaybeConfiscate { .. } => {}
                }
            }
        });
    }

    // The draft is dated at the operator's view when it is asked for.
    let (reply, rx) = oneshot::channel();
    inbox_tx
        .send(LedgerEvent::Commit {
            operation: add_member_op(
                PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[0x42; 32]).unwrap()),
                ledger_id,
            ),
            block_height: H,
            block_hash: hash_at(H),
            tier_floor: None,
            reply,
        })
        .await
        .unwrap();
    let result = tokio::time::timeout(Duration::from_secs(20), rx)
        .await
        .expect("the commit answered")
        .expect("the actor replied")
        .map(|r| r.update);

    let history = ledger_arc.read().unwrap().history.clone();
    let signed_at_seq = signer
        .by_seq
        .lock()
        .unwrap()
        .get(&seq)
        .copied()
        .unwrap_or(0);
    let published = published.lock().unwrap().clone();
    let refusals = refusals.lock().unwrap().clone();
    Outcome {
        result,
        history,
        published,
        signed_at_seq,
        requests: requests.load(Ordering::SeqCst),
        refusals,
        seq,
        data_dir: temp,
    }
}

fn assert_restaged(o: &Outcome, label: &str) {
    let u = match &o.result {
        Ok(u) => u,
        Err(e) => panic!("{label}: the commit failed: {e}"),
    };
    assert_eq!(
        u.block_height,
        H + 7,
        "{label}: dated at the tip, not at the stale draft's height"
    );
    assert!(
        u.cosignatures.len() >= 2,
        "{label}: carries a majority of cosignatures"
    );
    let at_seq: Vec<_> = o
        .history
        .iter()
        .filter(|x| x.sequence_number == o.seq)
        .collect();
    assert_eq!(
        at_seq.len(),
        1,
        "{label}: the ledger records one update at that seq"
    );
    let pub_at_seq: Vec<_> = o
        .published
        .iter()
        .filter(|x| x.sequence_number == o.seq)
        .collect();
    assert_eq!(
        pub_at_seq.len(),
        1,
        "{label}: one update of ours at that seq reached the relay"
    );
    assert!(
        pub_at_seq.iter().all(|x| x.block_height == H + 7),
        "{label}: nothing dated at the stale height was published"
    );
    assert_eq!(
        o.signed_at_seq, 1,
        "{label}: the operator signed that sequence exactly once (write-ahead)"
    );
    assert_eq!(
        o.requests, 2,
        "{label}: the stale draft was asked for once, the re-staged one once"
    );
    assert!(
        std::fs::read_dir(o.data_dir.path().join("pending"))
            .map(|d| d.count())
            .unwrap_or(0)
            == 0,
        "{label}: nothing left pending"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_draft_queued_past_the_window_is_restaged_not_resent() {
    let o = run(Scenario::BlocksWhileQueued).await;
    assert_restaged(&o, "blocks while queued");
    // The round saw the draft was stale BEFORE sending it: no member was asked for the old bytes.
    assert!(
        o.refusals.is_empty(),
        "no cosigner was sent the stale draft: {:?}",
        o.refusals
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_draft_refused_as_too_old_is_restaged_once_our_view_moves() {
    let o = run(Scenario::OperatorViewLags).await;
    assert_restaged(&o, "operator view lags");
    // Every member refused the first draft for its height, in this crate's own words.
    assert_eq!(o.refusals.len(), 3, "{:?}", o.refusals);
    assert!(
        o.refusals.iter().all(|m| m.contains(&format!(
            "block_height {H} is more than 6 blocks from our height {}",
            H + 7
        ))),
        "{:?}",
        o.refusals
    );
}

#[test]
fn write_ahead_refuses_to_redate_what_we_signed_or_recorded() {
    use super::write_ahead::{check_restampable, journal_put, write_pending};
    let temp = TempDir::new().unwrap();
    let key = "ab".repeat(32);
    let draft = SignedLedgerUpdate {
        message: vec![],
        message_type: 0,
        operator_id: PublicKey::from_secret_key(
            &Secp256k1::new(),
            &SecretKey::from_slice(&[0x11; 32]).unwrap(),
        ),
        ledger_id: [0xab; 32],
        sequence_number: 5,
        previous_hash: [0; 32],
        content_hash: [0; 32],
        block_height: H,
        block_hash: hash_at(H),
        operator_signature: [0u8; 64],
        cosignatures: vec![],
    };
    assert_eq!(
        check_restampable(temp.path(), &key, &[], &draft),
        Ok(()),
        "an unsigned, unrecorded draft"
    );

    let mut signed = draft.clone();
    signed.operator_signature = [1u8; 64];
    assert!(
        check_restampable(temp.path(), &key, &[], &signed).is_err(),
        "an operator-signed draft"
    );

    assert!(
        check_restampable(temp.path(), &key, std::slice::from_ref(&signed), &draft).is_err(),
        "a sequence the ledger records"
    );

    let t2 = TempDir::new().unwrap();
    write_pending(t2.path(), &key, &signed, false).unwrap();
    assert!(
        check_restampable(t2.path(), &key, &[], &draft).is_err(),
        "a sequence a pending file names"
    );

    let t3 = TempDir::new().unwrap();
    journal_put(t3.path(), &key, &signed).unwrap();
    assert!(
        check_restampable(t3.path(), &key, &[], &draft).is_err(),
        "a sequence the signed journal holds"
    );
}
