//! End-to-end round-trip smoke for the hub control plane wire.
//!
//! Spins up the shared in-process relay, connects two `HubTransport`
//! instances ("hub" and "signer") to it, sends a `Register` from
//! signer→hub, then a `RegisterAck` from hub→signer, and verifies
//! both arrive decoded correctly.
//!
//! This is the lowest-level smoke that proves the full stack:
//!   * gift-wrap encode + decode
//!   * nostr-sdk subscription filter matches our kind+#p tags
//!   * HubMessage JSON round-trips through the rumor

use deposits_hub_proto::proto::{HubMessage, NextAction, Role};
use deposits_hub_proto::test_relay;
use deposits_hub_proto::transport::HubTransport;
use std::time::Duration;

fn fresh_secret_hex() -> String {
    use nostr_sdk::prelude::*;
    Keys::generate().secret_key().to_secret_hex()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn register_and_ack_round_trip() {
    let url = test_relay::spawn().await;
    // Give the relay accept() a tick to register before connect.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let hub_secret = fresh_secret_hex();
    let signer_secret = fresh_secret_hex();

    let hub = HubTransport::connect(&hub_secret, &[url.clone()])
        .await
        .expect("hub connect");
    let signer = HubTransport::connect(&signer_secret, &[url.clone()])
        .await
        .expect("signer connect");

    let hub_pk_hex = hub.hub_pubkey().to_hex();
    let signer_pk_hex = signer.hub_pubkey().to_hex();

    let mut hub_inbox = hub.subscribe().await.expect("hub subscribe");
    let mut signer_inbox = signer.subscribe().await.expect("signer subscribe");

    // Let the REQ frames settle on the relay.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Signer → Hub: Register.
    let register = HubMessage::Register {
        role: Role::Signer,
        identity_pubkey: "02deadbeef".repeat(6).chars().take(66).collect(),
        version: "0.1.0-test".to_string(),
        label: Some("test-signer".to_string()),
        signer_pubkey: None,
    };
    signer
        .send(&hub_pk_hex, register.clone())
        .await
        .expect("signer send");

    let received = tokio::time::timeout(Duration::from_secs(5), hub_inbox.recv())
        .await
        .expect("hub recv timed out")
        .expect("hub inbox closed");
    assert_eq!(received.from.to_hex(), signer_pk_hex);
    match received.msg {
        HubMessage::Register {
            role,
            label,
            version,
            ..
        } => {
            assert_eq!(role, Role::Signer);
            assert_eq!(label.as_deref(), Some("test-signer"));
            assert_eq!(version, "0.1.0-test");
        }
        other => panic!("expected Register, got {:?}", other),
    }

    // Hub → Signer: RegisterAck.
    let ack = HubMessage::RegisterAck {
        accepted: true,
        message: "ok".to_string(),
        next_action: NextAction::Heartbeat,
    };
    hub.send(&signer_pk_hex, ack.clone())
        .await
        .expect("hub send ack");

    let ack_recv = tokio::time::timeout(Duration::from_secs(5), signer_inbox.recv())
        .await
        .expect("signer recv ack timed out")
        .expect("signer inbox closed");
    assert_eq!(ack_recv.from.to_hex(), hub_pk_hex);
    match ack_recv.msg {
        HubMessage::RegisterAck {
            accepted,
            message,
            next_action,
        } => {
            assert!(accepted);
            assert_eq!(message, "ok");
            assert_eq!(next_action, NextAction::Heartbeat);
        }
        other => panic!("expected RegisterAck, got {:?}", other),
    }
}
