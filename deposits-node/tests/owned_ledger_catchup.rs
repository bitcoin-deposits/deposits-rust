//! Phase 0/4 foundation for the "operator adopts its own newer cosigned seqs"
//! work. Establishes the invariant the fix relies on: catching a ledger up via
//! `apply_updates_to_ledger` mutates the SAME `Arc<RwLock<Ledger>>` in place
//! (the one a `LedgerActor` shares), so it advances the operator's writer view
//! too — no second copy, no orphaned actor. Also pins the prefix-apply
//! behaviour: a non-chaining update partway through a batch stops there and the
//! validated prefix before it is kept + persisted (not discarded).
//!
//! These are deterministic stand-ins for the live-cluster regression
//! (operator restarted behind the relay's cosigned chain → 1/2 cosigns); the
//! production split-brain came from REPLACING the Arc (remove+insert), which
//! these tests guard against by only ever applying in place.

use bitcoin::secp256k1::{Keypair, PublicKey, Secp256k1, SecretKey};
use deposits_core::messages::LedgerOperation;
use deposits_core::types::SignedLedgerUpdate;
use deposits_core::TlvEncode;
use deposits_node::handler::DepositsHandler;
use deposits_node::wallet::Wallet;
use deposits_signer_api::{LocalSigner, Signer};
use std::sync::Arc;
use tempfile::TempDir;

fn local_signer(seed_byte: u8) -> (Arc<dyn Signer>, PublicKey) {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[seed_byte; 32]).unwrap();
    let pk = PublicKey::from_secret_key(&secp, &sk);
    (Arc::new(LocalSigner::new(sk)), pk)
}

fn build_handler(temp: &TempDir) -> (Arc<DepositsHandler>, PublicKey) {
    let (signer, our_pk) = local_signer(0x11);
    let wallet = Arc::new(Wallet::new_mock(temp.path().to_path_buf()));
    let (handler, _outbound_rx) =
        DepositsHandler::new(signer, wallet, temp.path().to_path_buf(), false);
    (Arc::new(handler), our_pk)
}

/// A QuorumAddMember update at `sequence_number` chaining from `previous_hash`,
/// signed under `kp`. (QuorumAddMember is the simplest op the actor/apply path
/// accepts in `actor_paths.rs`.)
fn build_update(
    kp: &Keypair,
    ledger_id_bytes: [u8; 32],
    sequence_number: u64,
    previous_hash: [u8; 32],
) -> SignedLedgerUpdate {
    use bitcoin::hashes::{sha256, Hash};
    use bitcoin::secp256k1::Message;
    let secp = Secp256k1::new();
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
    let mut update = SignedLedgerUpdate {
        message: op.tlv_encode(),
        message_type: op.message_type(),
        operator_id: kp.public_key(),
        ledger_id: ledger_id_bytes,
        sequence_number,
        previous_hash,
        content_hash: [0u8; 32],
        block_height: 0,
        block_hash: [0u8; 32],
        cosign_signature: [0u8; 64],
        operator_signature: [0u8; 64],
        cosigner_pubkey: None,
        member_ledger_hash: None,
        cosignatures: Vec::new(),
    };
    update.content_hash = update.compute_hash();
    let signing_data = update.operator_signing_data();
    let hash = sha256::Hash::hash(&signing_data);
    let msg = Message::from_digest(*hash.as_byte_array());
    update.operator_signature = secp.sign_schnorr_no_aux_rand(&msg, kp).serialize();
    update
}

/// Create an operator ledger (LedgerOpen at seq 0) and return its handle + id.
fn make_owned_ledger(
    handler: &Arc<DepositsHandler>,
    our_pk: PublicKey,
) -> (String, [u8; 32], [u8; 32]) {
    let arc = handler.get_or_create_ledger(our_pk, "test:reserves".to_string());
    let mut l = arc.write().unwrap();
    l.state.parent_pubkey = our_pk;
    (
        hex::encode(l.state.ledger_id),
        l.state.ledger_id,
        l.state.chain_tip_hash,
    )
}

#[test]
fn catchup_applies_in_place_and_is_prefix_safe() {
    let temp = TempDir::new().unwrap();
    let (handler, our_pk) = build_handler(&temp);
    let secp = Secp256k1::new();
    let kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[0x11; 32]).unwrap());

    let (ledger_id, ledger_id_bytes, open_tip) = make_owned_ledger(&handler, our_pk);

    // The Arc the actor would share with the handler.
    let actor_arc = handler
        .ledgers
        .lock()
        .unwrap()
        .get(&ledger_id)
        .cloned()
        .unwrap();

    // Build a clean chain seq 1..=3 (the "relay tail" we missed).
    let u1 = build_update(&kp, ledger_id_bytes, 1, open_tip);
    let u2 = build_update(&kp, ledger_id_bytes, 2, u1.chain_hash());
    let u3 = build_update(&kp, ledger_id_bytes, 3, u2.chain_hash());

    let applied = handler
        .apply_updates_to_ledger(&ledger_id, vec![u1.clone(), u2.clone(), u3.clone()])
        .expect("catch-up applies");
    assert_eq!(applied, 3, "all three updates applied");

    // Invariant: the SAME Arc the actor holds advanced — no orphaned copy.
    assert_eq!(
        actor_arc.read().unwrap().state.sequence,
        3,
        "shared Arc advanced to tip 3"
    );

    // And the writer can keep going from the caught-up tip (seq 4 chains cleanly).
    let u4 = build_update(&kp, ledger_id_bytes, 4, u3.chain_hash());
    let applied = handler
        .apply_updates_to_ledger(&ledger_id, vec![u4])
        .expect("write continues past catch-up");
    assert_eq!(applied, 1);
    assert_eq!(actor_arc.read().unwrap().state.sequence, 4);
}

#[test]
fn prefix_apply_stops_at_break_and_keeps_validated_prefix() {
    let temp = TempDir::new().unwrap();
    let (handler, our_pk) = build_handler(&temp);
    let secp = Secp256k1::new();
    let kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[0x11; 32]).unwrap());

    let (ledger_id, ledger_id_bytes, open_tip) = make_owned_ledger(&handler, our_pk);

    // seq 1 chains cleanly; seq 2 carries a bogus previous_hash (the chain
    // break); seq 3 would chain off a correct seq 2. The batch must apply seq 1,
    // stop at seq 2, and persist tip=1 — NOT discard seq 1 (the pre-fix bug).
    let u1 = build_update(&kp, ledger_id_bytes, 1, open_tip);
    let u2_broken = build_update(&kp, ledger_id_bytes, 2, [0xAB; 32]);
    let u3 = build_update(&kp, ledger_id_bytes, 3, u2_broken.chain_hash());

    let applied = handler
        .apply_updates_to_ledger(&ledger_id, vec![u1, u2_broken, u3])
        .expect("apply returns Ok with the valid prefix");
    assert_eq!(applied, 1, "only the validated prefix (seq 1) is applied");
    assert_eq!(
        handler
            .ledgers
            .lock()
            .unwrap()
            .get(&ledger_id)
            .unwrap()
            .read()
            .unwrap()
            .state
            .sequence,
        1,
        "tip persists at the last valid seq, not rolled back to 0",
    );
}

fn tip_seq(handler: &Arc<DepositsHandler>, ledger_id: &str) -> u64 {
    handler
        .ledgers
        .lock()
        .unwrap()
        .get(ledger_id)
        .unwrap()
        .read()
        .unwrap()
        .state
        .sequence
}

// ── adopt_owned_updates: the regressed-operator decision logic ──────────────

#[test]
fn adopt_catches_up_a_regressed_operator() {
    let temp = TempDir::new().unwrap();
    let (handler, our_pk) = build_handler(&temp);
    let secp = Secp256k1::new();
    let kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[0x11; 32]).unwrap());
    let (ledger_id, idb, open_tip) = make_owned_ledger(&handler, our_pk);

    // The canonical cosigned chain seq 1..=5 (what the relay holds).
    let u1 = build_update(&kp, idb, 1, open_tip);
    let u2 = build_update(&kp, idb, 2, u1.chain_hash());
    let u3 = build_update(&kp, idb, 3, u2.chain_hash());
    let u4 = build_update(&kp, idb, 4, u3.chain_hash());
    let u5 = build_update(&kp, idb, 5, u4.chain_hash());
    let relay_chain = vec![u1.clone(), u2.clone(), u3.clone(), u4.clone(), u5.clone()];

    // Our operator regressed: local only has up to seq 2.
    handler
        .apply_updates_to_ledger(&ledger_id, vec![u1, u2])
        .unwrap();
    assert_eq!(tip_seq(&handler, &ledger_id), 2, "regressed to seq 2");

    // Feed the full relay chain → adopt only 3,4,5, advancing to the real tip.
    let adopted = handler.adopt_owned_updates(&ledger_id, relay_chain.clone());
    assert_eq!(adopted, 3, "adopted seqs 3,4,5");
    assert_eq!(
        tip_seq(&handler, &ledger_id),
        5,
        "caught up to canonical tip"
    );

    // Idempotent: feeding the same chain again adopts nothing.
    assert_eq!(
        handler.adopt_owned_updates(&ledger_id, relay_chain),
        0,
        "already caught up"
    );
}

#[test]
fn adopt_refuses_a_fork_at_our_tip() {
    let temp = TempDir::new().unwrap();
    let (handler, our_pk) = build_handler(&temp);
    let secp = Secp256k1::new();
    let kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[0x11; 32]).unwrap());
    let (ledger_id, idb, open_tip) = make_owned_ledger(&handler, our_pk);

    // Local advances to seq 2 on its own chain.
    let u1 = build_update(&kp, idb, 1, open_tip);
    let u2 = build_update(&kp, idb, 2, u1.chain_hash());
    handler
        .apply_updates_to_ledger(&ledger_id, vec![u1, u2])
        .unwrap();

    // The relay offers a seq 3 that chains off a DIFFERENT seq 2 (fork at tip).
    let fork3 = build_update(&kp, idb, 3, [0xCD; 32]);
    let adopted = handler.adopt_owned_updates(&ledger_id, vec![fork3]);
    assert_eq!(adopted, 0, "a fork at our tip must NOT be adopted");
    assert_eq!(
        tip_seq(&handler, &ledger_id),
        2,
        "owned ledger left intact for manual reconciliation"
    );
}

#[test]
fn adopt_is_a_noop_when_already_ahead() {
    let temp = TempDir::new().unwrap();
    let (handler, our_pk) = build_handler(&temp);
    let secp = Secp256k1::new();
    let kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[0x11; 32]).unwrap());
    let (ledger_id, idb, open_tip) = make_owned_ledger(&handler, our_pk);

    let u1 = build_update(&kp, idb, 1, open_tip);
    let u2 = build_update(&kp, idb, 2, u1.chain_hash());
    let u3 = build_update(&kp, idb, 3, u2.chain_hash());
    handler
        .apply_updates_to_ledger(&ledger_id, vec![u1.clone(), u2.clone(), u3])
        .unwrap();

    // Relay only knows up to seq 2 (we're ahead) → nothing to adopt.
    assert_eq!(handler.adopt_owned_updates(&ledger_id, vec![u1, u2]), 0);
    assert_eq!(
        tip_seq(&handler, &ledger_id),
        3,
        "stayed at our own higher tip"
    );
}
