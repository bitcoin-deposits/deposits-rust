//! End-to-end round-trip smoke for the hub control plane wire.
//!
//! Spins up a tiny in-process nostr relay, connects two `HubTransport`
//! instances ("hub" and "signer") to it, sends a `Register` from
//! signer→hub, then a `RegisterAck` from hub→signer, and verifies
//! both arrive decoded correctly.
//!
//! This is the lowest-level smoke that proves the full stack:
//!   * gift-wrap encode + decode
//!   * nostr-sdk subscription filter matches our kind+#p tags
//!   * HubMessage JSON round-trips through the rumor
//!
//! No binaries are spawned — that's a separate concern from "does the
//! wire work?". If the binaries' arg parsing changes, the spawn module's
//! own tests cover it.

use deposits_hub_proto::proto::{HubMessage, NextAction, Role};
use deposits_hub_proto::transport::HubTransport;
use futures::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::Message;

/// Bind to 127.0.0.1:0, run a tiny relay that echoes EVENTs to active
/// REQ subscribers whose filter `#p` tag matches. Returns the WS URL
/// once the listener is bound — the caller can connect immediately.
async fn spawn_test_relay() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let url = format!("ws://{}", addr);

    // Map from connection id → outbound channel. Subscribers' filters
    // are tracked alongside so we can route EVENTs.
    let conns: Arc<Mutex<HashMap<u64, ConnState>>> = Arc::new(Mutex::new(HashMap::new()));
    let mut next_id = 0u64;

    tokio::spawn(async move {
        loop {
            let (stream, _addr) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => return,
            };
            let id = next_id;
            next_id = next_id.wrapping_add(1);
            let conns = conns.clone();
            tokio::spawn(handle_connection(id, stream, conns));
        }
    });

    url
}

#[derive(Default, Clone)]
struct Subscription {
    /// `#p` tag values to match. Empty == match all.
    p_tags: Vec<String>,
    /// Kinds to match. Empty == match all.
    kinds: Vec<u64>,
    sub_id: String,
}

struct ConnState {
    outbound: tokio::sync::mpsc::UnboundedSender<String>,
    subscriptions: Vec<Subscription>,
}

async fn handle_connection(
    id: u64,
    stream: tokio::net::TcpStream,
    conns: Arc<Mutex<HashMap<u64, ConnState>>>,
) {
    let ws = match tokio_tungstenite::accept_async(stream).await {
        Ok(w) => w,
        Err(_) => return,
    };
    let (mut sink, mut source) = ws.split();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    {
        let mut c = conns.lock().await;
        c.insert(
            id,
            ConnState {
                outbound: tx,
                subscriptions: Vec::new(),
            },
        );
    }

    // Writer task.
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if sink.send(Message::Text(msg)).await.is_err() {
                return;
            }
        }
    });

    // Reader loop.
    while let Some(Ok(msg)) = source.next().await {
        let text = match msg {
            Message::Text(t) => t,
            Message::Close(_) => break,
            _ => continue,
        };
        let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(&text) else {
            continue;
        };
        let Some(verb) = arr.first().and_then(|v| v.as_str()) else {
            continue;
        };
        match verb {
            "EVENT" => {
                let Some(event) = arr.get(1) else { continue };
                // Note the event's kind + #p tags for routing.
                let kind = event.get("kind").and_then(|k| k.as_u64()).unwrap_or(0);
                let event_p_tags: Vec<String> = event
                    .get("tags")
                    .and_then(|t| t.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|tag| {
                                let tarr = tag.as_array()?;
                                if tarr.first()?.as_str()? == "p" {
                                    Some(tarr.get(1)?.as_str()?.to_string())
                                } else {
                                    None
                                }
                            })
                            .collect()
                    })
                    .unwrap_or_default();

                // ACK the publisher.
                if let Some(eid) = event.get("id").and_then(|v| v.as_str()) {
                    let ok = serde_json::json!(["OK", eid, true, ""]).to_string();
                    if let Some(c) = conns.lock().await.get(&id) {
                        let _ = c.outbound.send(ok);
                    }
                }

                // Route to every connection whose subscriptions match.
                let conns_snap = {
                    let g = conns.lock().await;
                    g.iter()
                        .map(|(k, v)| {
                            (
                                *k,
                                v.outbound.clone(),
                                v.subscriptions.clone(),
                            )
                        })
                        .collect::<Vec<_>>()
                };
                for (_cid, out, subs) in conns_snap {
                    for sub in &subs {
                        let kind_ok = sub.kinds.is_empty() || sub.kinds.contains(&kind);
                        let p_ok = sub.p_tags.is_empty()
                            || event_p_tags.iter().any(|p| sub.p_tags.contains(p));
                        if kind_ok && p_ok {
                            let frame =
                                serde_json::json!(["EVENT", sub.sub_id, event]).to_string();
                            let _ = out.send(frame);
                        }
                    }
                }
            }
            "REQ" => {
                let Some(sub_id) = arr.get(1).and_then(|v| v.as_str()) else {
                    continue;
                };
                let mut p_tags = Vec::new();
                let mut kinds = Vec::new();
                for filter in arr.iter().skip(2) {
                    if let Some(ks) = filter.get("kinds").and_then(|k| k.as_array()) {
                        for k in ks {
                            if let Some(n) = k.as_u64() {
                                kinds.push(n);
                            }
                        }
                    }
                    if let Some(ps) = filter.get("#p").and_then(|p| p.as_array()) {
                        for p in ps {
                            if let Some(s) = p.as_str() {
                                p_tags.push(s.to_string());
                            }
                        }
                    }
                }
                let mut g = conns.lock().await;
                if let Some(c) = g.get_mut(&id) {
                    c.subscriptions.push(Subscription {
                        p_tags,
                        kinds,
                        sub_id: sub_id.to_string(),
                    });
                    let eose = serde_json::json!(["EOSE", sub_id]).to_string();
                    let _ = c.outbound.send(eose);
                }
            }
            "CLOSE" => {
                if let Some(sub_id) = arr.get(1).and_then(|v| v.as_str()) {
                    let mut g = conns.lock().await;
                    if let Some(c) = g.get_mut(&id) {
                        c.subscriptions.retain(|s| s.sub_id != sub_id);
                    }
                }
            }
            _ => {}
        }
    }

    let mut g = conns.lock().await;
    g.remove(&id);
}

fn fresh_secret_hex() -> String {
    use nostr_sdk::prelude::*;
    Keys::generate().secret_key().to_secret_hex()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn register_and_ack_round_trip() {
    let url = spawn_test_relay().await;
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
    };
    signer
        .send(&hub_pk_hex, register.clone())
        .await
        .expect("signer send");

    // Hub should receive it within a few seconds.
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
