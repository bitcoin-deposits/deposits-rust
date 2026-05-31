//! End-to-end receive-witness authorization.
//!
//! Demonstrates the wallet-side signing flow and the node-side verification
//! flow for `receive_witness` (see `RECEIVE-WITNESS.md` at the workspace root
//! for the wire format). Three scenarios:
//!
//! 1. Happy path: single-key descriptor, valid signature → authorized.
//! 2. Replay: same signature against a different deposit_id → rejected.
//! 3. Transfer-release: receive op carries `transfer_id`; signature binds to it.
//!
//! Run with: `cargo run --example receive_auth -p deposits-core`.

use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use bitcoin::PublicKey;
use deposits_core::dep16::operations::receive_op_sighash;
use deposits_core::dep16::{Dep16Authorizer, ReceiveWitness};
use std::collections::BTreeMap;

fn main() {
    let secp = Secp256k1::new();

    // Wallet-side: own a single ECDSA key. In production this comes from
    // the wallet's per-deposit signing path.
    let sk = SecretKey::from_slice(&[0x11; 32]).unwrap();
    let pk = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk));

    // Operator-side: the deposit's descriptor. Single-key here; multi-key
    // works the same way with one signature entry per signing participant.
    let descriptor = format!("wsh(prove(pk({})))", pk);
    let deposit_id = [0xCC; 16];
    let nonce: u64 = 1;
    let expiry: u32 = u32::MAX;

    // --- (1) Happy path -------------------------------------------------
    let sighash = receive_op_sighash(&deposit_id, nonce, expiry, None);
    let sig = secp
        .sign_ecdsa(&Message::from_digest(sighash), &sk)
        .serialize_compact();

    let witness = ReceiveWitness {
        nonce,
        expiry,
        signatures: {
            let mut m = BTreeMap::new();
            m.insert(hex::encode(pk.to_bytes()), hex::encode(sig));
            m
        },
    };
    // What goes over the wire (the make_invoice / make_offer request param):
    let wire_json = serde_json::to_string_pretty(&witness).unwrap();
    println!("=== happy path ===\nreceive_witness JSON:\n{}\n", wire_json);

    let authorizer = Dep16Authorizer::new();
    let ok = authorizer.authorize_receive(&descriptor, &deposit_id, None, &witness);
    assert!(ok, "happy path must authorize");
    println!("verdict: AUTHORIZED ✓\n");

    // --- (2) Replay against a different deposit_id ----------------------
    // The same signature, used against a different deposit, must fail.
    // The preimage binds `deposit_id`; the signature was made over the
    // preimage with deposit_id = 0xCC..., so it doesn't satisfy the
    // preimage built with deposit_id = 0xDD....
    let other_deposit_id = [0xDD; 16];
    let replayed = authorizer.authorize_receive(&descriptor, &other_deposit_id, None, &witness);
    assert!(!replayed, "replay across deposit_ids must be rejected");
    println!("=== cross-deposit replay ===\nverdict: REJECTED ✓ (signature bound to original deposit_id)\n");

    // --- (3) Transfer-release: receive op carries transfer_id -----------
    let transfer_id = [0xAB; 32];
    let release_sighash = receive_op_sighash(&deposit_id, nonce, expiry, Some(&transfer_id));
    let release_sig = secp
        .sign_ecdsa(&Message::from_digest(release_sighash), &sk)
        .serialize_compact();
    let release_witness = ReceiveWitness {
        nonce,
        expiry,
        signatures: {
            let mut m = BTreeMap::new();
            m.insert(hex::encode(pk.to_bytes()), hex::encode(release_sig));
            m
        },
    };
    let release_ok =
        authorizer.authorize_receive(&descriptor, &deposit_id, Some(&transfer_id), &release_witness);
    assert!(release_ok, "transfer-release receive must authorize");
    println!("=== transfer-release ===\nverdict: AUTHORIZED ✓\n");

    // Cross-transfer replay: same release signature against a different
    // transfer_id must fail (the preimage binds transfer_id).
    let other_transfer_id = [0xEE; 32];
    let replayed_release = authorizer.authorize_receive(
        &descriptor,
        &deposit_id,
        Some(&other_transfer_id),
        &release_witness,
    );
    assert!(
        !replayed_release,
        "cross-transfer replay must be rejected"
    );
    println!("=== cross-transfer replay ===\nverdict: REJECTED ✓ (signature bound to original transfer_id)");
}
