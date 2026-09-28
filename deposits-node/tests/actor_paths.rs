//! Behavioural soundness test for the per-ledger actor.
//!
//! Constructs a real `DepositsHandler` + a `LedgerActor` that share
//! the same `Arc<RwLock<Ledger>>`, sends an `Inbound` event through
//! the actor's channel, and asserts:
//!
//! 1. The actor applies the update (history grows, sequence
//!    advances).
//! 2. `handler.ledgers` reflects the actor's write — i.e. the
//!    Arc-sharing trick works.
//! 3. `persist_ledger_to_disk` runs and the `.jsonl` on disk matches
//!    the in-memory tip.
//!
//! This is the dynamic half of the migration's "single writer"
//! property. The static half lives in `actor_no_bypass.rs`.

use bitcoin::secp256k1::{Keypair, PublicKey, Secp256k1, SecretKey};
use deposits_core::messages::LedgerOperation;
use deposits_core::types::SignedLedgerUpdate;
use deposits_core::TlvEncode;
use deposits_node::handler::DepositsHandler;
use deposits_node::node::ledger_actor::{LedgerActor, LedgerEvent};
use deposits_node::wallet::Wallet;
use deposits_signer_api::{LocalSigner, Signer};
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::sync::mpsc;

fn local_signer(seed_byte: u8) -> (Arc<dyn Signer>, PublicKey) {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[seed_byte; 32]).unwrap();
    let pk = PublicKey::from_secret_key(&secp, &sk);
    (Arc::new(LocalSigner::new(sk)), pk)
}

fn build_handler(temp: &TempDir) -> (Arc<DepositsHandler>, PublicKey, Arc<dyn Signer>) {
    let (signer, our_pk) = local_signer(0x11);
    let wallet = Arc::new(Wallet::new_mock(temp.path().to_path_buf()));
    let (handler, _outbound_rx) =
        DepositsHandler::new(signer.clone(), wallet, temp.path().to_path_buf(), false);
    (Arc::new(handler), our_pk, signer)
}

/// Manually construct a `QuorumAddMember` update at `sequence_number`
/// that chains from `previous_hash`, signed under `kp`. The actor's
/// `apply_inbound` only consults the chain-linkage fields (not the
/// signature), so a deterministic build is enough to drive its path.
fn build_quorum_add_member_update(
    kp: &Keypair,
    ledger_id_bytes: [u8; 32],
    sequence_number: u64,
    previous_hash: [u8; 32],
) -> SignedLedgerUpdate {
    use bitcoin::hashes::{sha256, Hash};
    use bitcoin::secp256k1::Message;

    let secp = Secp256k1::new();
    // A fresh foreign-operator pubkey for the QuorumAddMember
    // payload — nothing in this test references it beyond keeping
    // the op well-formed.
    let member_sk = SecretKey::from_slice(&[0x42; 32]).unwrap();
    let member_pk = PublicKey::from_secret_key(&secp, &member_sk);

    let op = LedgerOperation::QuorumAddMember {
        quorum_member: member_pk,
        quorum_member_signature: [0u8; 64],
        member_ledger_id: hex::encode(ledger_id_bytes),
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
    };
    let message_bytes = op.tlv_encode();

    let mut update = SignedLedgerUpdate {
        message: message_bytes,
        message_type: op.message_type(),
        operator_id: kp.public_key(),
        ledger_id: ledger_id_bytes,
        sequence_number,
        previous_hash,
        content_hash: [0u8; 32], // patched below
        block_height: 0,
        block_hash: [0u8; 32],
        operator_signature: [0u8; 64],
        cosignatures: Vec::new(),
    };
    update.content_hash = update.compute_hash();

    let msg = Message::from_digest(update.operator_digest());
    let sig = secp.sign_schnorr_no_aux_rand(&msg, kp);
    update.operator_signature = sig.serialize();

    update
}

#[tokio::test(flavor = "current_thread")]
async fn actor_inbound_apply_visible_through_handler_ledgers() {
    let temp = TempDir::new().unwrap();
    let (handler, our_pk, signer) = build_handler(&temp);

    // The actor only processes seq >= 1 (the first update at seq 0
    // is the pre-actor LedgerOpen path in `handler.rs:999`).
    // Create the ledger as Operator so LedgerOpen is auto-appended,
    // then send a QuorumAddMember at seq 1 through the actor.
    let secp = Secp256k1::new();
    let our_sk = SecretKey::from_slice(&[0x11; 32]).unwrap();
    let our_kp = Keypair::from_secret_key(&secp, &our_sk);

    let reserves_id = "test:reserves".to_string();
    let ledger_arc = handler.get_or_create_ledger(our_pk, reserves_id.clone());

    // Sanity: Operator ledger has LedgerOpen at seq 0.
    let (initial_seq, initial_tip, ledger_id_bytes) = {
        let l = ledger_arc.read().unwrap();
        assert_eq!(
            l.history.len(),
            1,
            "operator ledger should have LedgerOpen auto-appended"
        );
        (l.state.sequence, l.state.chain_tip_hash, l.state.ledger_id)
    };
    assert_eq!(initial_seq, 0, "LedgerOpen sits at seq 0");

    let ledger_id = hex::encode(ledger_id_bytes);
    {
        // `get_or_create_ledger` populates `parent_pubkey` from the
        // operator arg, but pin it here to make the test
        // independent of that detail.
        let mut l = ledger_arc.write().unwrap();
        l.state.parent_pubkey = our_pk;
    }

    // Spawn the actor with the SAME Arc the handler holds.
    let (inbox_tx, inbox_rx) = mpsc::channel::<LedgerEvent>(8);
    let (outbox_tx, _outbox_rx) = mpsc::unbounded_channel();
    let actor = LedgerActor {
        inbox: inbox_rx,
        outbox: outbox_tx,
        ledger: Arc::clone(&ledger_arc),
        ledger_id: ledger_id.clone(),
        signer: signer.clone(),
        handler: Arc::clone(&handler),
        apply_wakeup: std::sync::Arc::new(tokio::sync::Notify::new()),
    };
    tokio::spawn(actor.run());

    // Build a QuorumAddMember at seq 1 chaining from the LedgerOpen.
    let update = build_quorum_add_member_update(&our_kp, ledger_id_bytes, 1, initial_tip);
    inbox_tx
        .send(LedgerEvent::Inbound(Box::new(update.clone())))
        .await
        .expect("send Inbound");

    // Wait for the actor to drain its inbox.
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        let l = ledger_arc.read().unwrap();
        if l.history.len() >= 2 {
            break;
        }
    }

    // ── Assertion 1: actor wrote to the shared Arc ──────────────
    {
        let l = ledger_arc.read().unwrap();
        assert_eq!(
            l.history.len(),
            2,
            "expected LedgerOpen + QuorumAddMember; got {} entries",
            l.history.len()
        );
        assert_eq!(l.state.sequence, 1, "tip seq should advance to 1");
        assert_eq!(
            l.history[1].content_hash, update.content_hash,
            "stored content_hash should match the update we sent"
        );
    }

    // ── Assertion 2: handler.ledgers reads see the actor's write ─
    {
        let ledgers = handler.ledgers.lock().unwrap();
        let from_handler = ledgers
            .get(&ledger_id)
            .expect("handler.ledgers should have the ledger we created");
        assert!(
            Arc::ptr_eq(&ledger_arc, from_handler),
            "actor.ledger and handler.ledgers[id] must be the same Arc"
        );
        let l = from_handler.read().unwrap();
        assert_eq!(l.state.sequence, 1, "handler reader sees actor's apply");
    }

    // ── Assertion 3: jsonl on disk matches the in-memory tip ────
    let jsonl_path = temp
        .path()
        .join("ledgers")
        .join(format!("{}.jsonl", ledger_id));
    assert!(
        jsonl_path.exists(),
        "actor's persist_ledger_to_disk should have written {}",
        jsonl_path.display()
    );
    let contents = std::fs::read_to_string(&jsonl_path).expect("read jsonl");
    // Should have at least two Update rows (LedgerOpen + QuorumAddMember).
    let update_lines = contents
        .lines()
        .filter(|l| l.contains("\"type\":\"Update\""))
        .count();
    assert!(
        update_lines >= 2,
        "jsonl should contain 2+ Update rows; got {}: {}",
        update_lines,
        contents.lines().take(5).collect::<Vec<_>>().join(" | ")
    );
}
