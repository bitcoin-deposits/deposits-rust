//! Tiny in-process nostr relay for tests.
//!
//! Only handles the subset of the protocol the deposits-hub control
//! plane uses: EVENT echoes routed to REQ subscribers whose filter
//! `#p` tag matches the event's `p` tag. No persistence, no NIP-42
//! auth, no rate limiting — anything beyond round-trip plumbing is
//! out of scope.
//!
//! Gated behind the `test-relay` feature so production builds don't
//! pull in `tokio-tungstenite`.

use futures::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::Message;

/// Bind to 127.0.0.1:0, spawn a relay task, return the `ws://…` URL
/// once the listener is bound. The relay shuts down when the process
/// exits — there's no explicit handle to keep it running.
pub async fn spawn() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let url = format!("ws://{}", addr);

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
    p_tags: Vec<String>,
    kinds: Vec<u64>,
    /// `since` filter (unix seconds). Events with `created_at` below
    /// this are dropped. None == no lower bound. Real relays honor
    /// this strictly; our test relay used to skip the check, which
    /// hid a NIP-59 gift-wrap bug where a too-narrow `since` window
    /// silently filtered out jittered wraps.
    since: Option<u64>,
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

    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if sink.send(Message::Text(msg)).await.is_err() {
                return;
            }
        }
    });

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
                let kind = event.get("kind").and_then(|k| k.as_u64()).unwrap_or(0);
                let event_created_at =
                    event.get("created_at").and_then(|c| c.as_u64()).unwrap_or(0);
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

                if let Some(eid) = event.get("id").and_then(|v| v.as_str()) {
                    let ok = serde_json::json!(["OK", eid, true, ""]).to_string();
                    if let Some(c) = conns.lock().await.get(&id) {
                        let _ = c.outbound.send(ok);
                    }
                }

                let conns_snap = {
                    let g = conns.lock().await;
                    g.iter()
                        .map(|(k, v)| (*k, v.outbound.clone(), v.subscriptions.clone()))
                        .collect::<Vec<_>>()
                };
                for (_cid, out, subs) in conns_snap {
                    for sub in &subs {
                        let kind_ok = sub.kinds.is_empty() || sub.kinds.contains(&kind);
                        let p_ok = sub.p_tags.is_empty()
                            || event_p_tags.iter().any(|p| sub.p_tags.contains(p));
                        let since_ok = match sub.since {
                            Some(s) => event_created_at >= s,
                            None => true,
                        };
                        if kind_ok && p_ok && since_ok {
                            let frame = serde_json::json!(["EVENT", sub.sub_id, event]).to_string();
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
                let mut since: Option<u64> = None;
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
                    if let Some(s) = filter.get("since").and_then(|v| v.as_u64()) {
                        // Multiple filters' `since` values: take the
                        // most permissive (smallest). A single filter
                        // is the common case.
                        since = Some(match since {
                            Some(prev) => prev.min(s),
                            None => s,
                        });
                    }
                }
                let mut g = conns.lock().await;
                if let Some(c) = g.get_mut(&id) {
                    c.subscriptions.push(Subscription {
                        p_tags,
                        kinds,
                        since,
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
