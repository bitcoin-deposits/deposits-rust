//! End-to-end smoke test: handshake + a few sign requests, all in-process
//! over a tokio duplex pipe. This is the test the integration test in
//! deposits-node will mirror, but at the deposits-signer level it
//! exercises the server's framing + handshake + dispatch loop without
//! pulling in any of the daemon's plumbing.

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{Keypair, Message, Secp256k1};
use deposits_signer::data::TransportKey;
use deposits_signer::framing::{read_frame, write_frame};
use deposits_signer::server::{serve_connection, ServerCtx};
use deposits_signer_api::wire::{
    auth_digest, hello_ack_digest, Auth, Hello, HelloAck, SignOp, SignRequest, SignResponse,
    SignResult,
};
use deposits_signer_api::{LocalSigner, SigPurpose, SignContext, Signer};
use std::sync::Arc;
use tokio::io::duplex;

#[tokio::test]
async fn handshake_then_sign_and_verify() {
    let secp = Secp256k1::<bitcoin::secp256k1::All>::new();

    // Provision: signer transport, daemon transport, and an operator key
    // the signer holds. Daemon's transport pubkey is on the signer's
    // allowlist.
    let signer_transport = TransportKey::random();
    let daemon_transport = TransportKey::random();
    let operator_signer = LocalSigner::random();
    let operator_pubkey = operator_signer.pubkey();
    let operator_xonly = operator_signer.xonly_pubkey();

    let ctx = Arc::new(ServerCtx {
        transport: Keypair::from_secret_key(&secp, &signer_transport.secret),
        allowlist: vec![daemon_transport.public],
        signer: Arc::new(operator_signer),
    });

    let (mut server_side, mut client_side) = duplex(64 * 1024);

    let ctx_for_task = Arc::clone(&ctx);
    let server_task = tokio::spawn(async move {
        serve_connection(&mut server_side, &ctx_for_task).await
    });

    // ---- Daemon-side handshake -----------------------------------------------

    let nonce_a = [9u8; 32];
    let hello = Hello {
        version: [0u8; 16],
        node_pubkey: daemon_transport.public,
        nonce_a,
    };
    write_frame(&mut client_side, &hello).await.unwrap();

    let ack: HelloAck = read_frame(&mut client_side).await.unwrap();
    // Verify the signer's HelloAck signature.
    {
        let dgst = hello_ack_digest(&nonce_a, &daemon_transport.public);
        let msg = Message::from_digest(dgst);
        let sig = bitcoin::secp256k1::schnorr::Signature::from_slice(&ack.sig_signer).unwrap();
        let xonly = ack.signer_pubkey.x_only_public_key().0;
        secp.verify_schnorr(&sig, &msg, &xonly)
            .expect("signer HelloAck signature must verify");
    }
    assert_eq!(ack.signer_pubkey, signer_transport.public);

    // Sign and send Auth.
    let auth_dgst = auth_digest(&ack.nonce_b, &ack.signer_pubkey);
    let auth_msg = Message::from_digest(auth_dgst);
    let daemon_kp = Keypair::from_secret_key(&secp, &daemon_transport.secret);
    let sig_node = secp
        .sign_schnorr_no_aux_rand(&auth_msg, &daemon_kp)
        .serialize();
    let auth = Auth { sig_node };
    write_frame(&mut client_side, &auth).await.unwrap();

    // ---- BIP-340 sign + verify -----------------------------------------------

    let payload = b"this is a test payload";
    let digest = sha256::Hash::hash(payload).to_byte_array();
    let req = SignRequest {
        id: 1,
        ctx: SignContext::no_ledger(SigPurpose::Bip340Untagged),
        op: SignOp::Bip340 { digest },
    };
    write_frame(&mut client_side, &req).await.unwrap();
    let resp: SignResponse = read_frame(&mut client_side).await.unwrap();
    assert_eq!(resp.id, 1);
    let sig_bytes = match resp.result {
        SignResult::Bip340Sig { sig } => sig,
        other => panic!("unexpected result: {:?}", other),
    };
    let sig = bitcoin::secp256k1::schnorr::Signature::from_slice(&sig_bytes).unwrap();
    let msg = Message::from_digest(digest);
    secp.verify_schnorr(&sig, &msg, &operator_xonly)
        .expect("signer's BIP-340 sig must verify against operator xonly");

    // ---- ECDH against a known peer -------------------------------------------

    let peer_signer = LocalSigner::random();
    let req = SignRequest {
        id: 2,
        ctx: SignContext::no_ledger(SigPurpose::Bip340Untagged),
        op: SignOp::Ecdh {
            peer: peer_signer.pubkey(),
        },
    };
    write_frame(&mut client_side, &req).await.unwrap();
    let resp: SignResponse = read_frame(&mut client_side).await.unwrap();
    let from_signer = match resp.result {
        SignResult::EcdhSecret { shared } => shared,
        other => panic!("unexpected result: {:?}", other),
    };
    // Compute the same ECDH on the peer side; it must match.
    let from_peer = peer_signer.ecdh(&operator_pubkey).unwrap();
    assert_eq!(from_signer, from_peer);

    // ---- PubkeyQuery returns the operator pubkey ------------------------------

    let req = SignRequest {
        id: 3,
        ctx: SignContext::no_ledger(SigPurpose::Bip340Untagged),
        op: SignOp::PubkeyQuery,
    };
    write_frame(&mut client_side, &req).await.unwrap();
    let resp: SignResponse = read_frame(&mut client_side).await.unwrap();
    let (pk, xo) = match resp.result {
        SignResult::Pubkey { pubkey, xonly } => (pubkey, xonly),
        other => panic!("unexpected result: {:?}", other),
    };
    assert_eq!(pk, operator_pubkey);
    assert_eq!(xo, operator_xonly);

    // Drop client side; server should return Ok cleanly on EOF.
    drop(client_side);
    let server_result = server_task.await.unwrap();
    server_result.expect("server returned cleanly");
}

#[tokio::test]
async fn rejects_unallowlisted_node() {
    let secp = Secp256k1::<bitcoin::secp256k1::All>::new();
    let signer_transport = TransportKey::random();
    let intruder_transport = TransportKey::random();
    let operator_signer = LocalSigner::random();
    let ctx = Arc::new(ServerCtx {
        transport: Keypair::from_secret_key(&secp, &signer_transport.secret),
        allowlist: vec![],   // empty: nobody is allowed.
        signer: Arc::new(operator_signer),
    });

    let (mut server_side, mut client_side) = duplex(8 * 1024);

    let ctx_for_task = Arc::clone(&ctx);
    let server_task = tokio::spawn(async move {
        serve_connection(&mut server_side, &ctx_for_task).await
    });

    let hello = Hello {
        version: [0u8; 16],
        node_pubkey: intruder_transport.public,
        nonce_a: [0xFF; 32],
    };
    write_frame(&mut client_side, &hello).await.unwrap();

    let server_result = server_task.await.unwrap();
    assert!(server_result.is_err(), "server should refuse non-allowlisted hello");
}
