//! LNURL-pay gateway for Bitcoin Deposits
//!
//! Serves LUD-06/LUD-16 endpoints that translate LNURL-pay callbacks into
//! deposits-node `make_invoice` requests via Nostr.
//!
//! Each deposit gets a lightning address: `<deposit_id>@<domain>`
//!
//! Flow:
//!   1. Payer resolves `user@domain` → GET /.well-known/lnurlp/<deposit_id>
//!   2. Response: metadata, min/max, callback URL
//!   3. Payer calls callback with ?amount=<msats>
//!   4. Server sends kind 20101 make_invoice to operator relay
//!   5. Operator responds with kind 20102 containing BOLT11 invoice
//!   6. Server returns invoice to payer
//!
//! Env vars:
//!   LNURL_NSEC          - Service key (hex or nsec) for signing Nostr requests
//!   LNURL_RELAYS        - Comma-separated relay URLs
//!   LNURL_DOMAIN        - Public domain (for lightning address metadata)
//!   LNURL_LISTEN        - HTTP listen address (default: 0.0.0.0:3000)
//!   LNURL_MIN_SATS      - Minimum payment (default: 1)
//!   LNURL_MAX_SATS      - Maximum payment (default: 1000000)

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::get,
    Router,
};
use nostr_sdk::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

// ============================================================================
// Types
// ============================================================================

struct AppState {
    keys: Keys,
    client: Client,
    domain: String,
    min_msats: u64,
    max_msats: u64,
    /// Pending make_invoice requests: request_event_id → oneshot sender
    pending: Mutex<HashMap<String, tokio::sync::oneshot::Sender<serde_json::Value>>>,
}

#[derive(Serialize)]
struct LnurlPayResponse {
    tag: &'static str,
    callback: String,
    #[serde(rename = "minSendable")]
    min_sendable: u64,
    #[serde(rename = "maxSendable")]
    max_sendable: u64,
    metadata: String,
    #[serde(rename = "commentAllowed")]
    comment_allowed: u16,
}

#[derive(Deserialize)]
struct CallbackParams {
    amount: u64, // msats
    comment: Option<String>,
}

#[derive(Serialize)]
struct CallbackResponse {
    pr: String, // BOLT11 invoice
    routes: Vec<()>,
}

#[derive(Serialize)]
struct LnurlError {
    status: &'static str,
    reason: String,
}

// ============================================================================
// Env helpers
// ============================================================================

fn env_or_file(name: &str) -> Option<String> {
    if let Ok(val) = std::env::var(name) {
        return Some(val);
    }
    if let Ok(path) = std::env::var(format!("{}_FILE", name)) {
        return std::fs::read_to_string(path).ok().map(|s| s.trim().to_string());
    }
    None
}

// ============================================================================
// LNURL-pay endpoints
// ============================================================================

/// GET /.well-known/lnurlp/<deposit_id>
///
/// Returns LNURL-pay metadata for the deposit. The deposit_id encodes
/// both the ledger and deposit: `<ledger_prefix>-<deposit_pubkey>`
async fn lnurlp_metadata(
    State(state): State<Arc<AppState>>,
    Path(deposit_id): Path<String>,
) -> Result<Json<LnurlPayResponse>, (StatusCode, Json<LnurlError>)> {
    // deposit_id format: <ledger_id_hex>-<deposit_pubkey_hex>
    // or just <deposit_pubkey_hex> if ledger is implicit
    let metadata = format!(
        "[[\"text/plain\",\"Pay to deposit {}\"],[\"text/identifier\",\"{}@{}\"]]",
        &deposit_id[..16.min(deposit_id.len())],
        deposit_id,
        state.domain,
    );

    Ok(Json(LnurlPayResponse {
        tag: "payRequest",
        callback: format!("https://{}/lnurl/callback/{}", state.domain, deposit_id),
        min_sendable: state.min_msats,
        max_sendable: state.max_msats,
        metadata,
        comment_allowed: 0,
    }))
}

/// GET /lnurl/callback/<deposit_id>?amount=<msats>
///
/// Creates an invoice via the operator's deposits-node and returns it.
async fn lnurlp_callback(
    State(state): State<Arc<AppState>>,
    Path(deposit_id): Path<String>,
    Query(params): Query<CallbackParams>,
) -> Result<Json<CallbackResponse>, (StatusCode, Json<LnurlError>)> {
    let err = |msg: &str| -> (StatusCode, Json<LnurlError>) {
        (StatusCode::BAD_REQUEST, Json(LnurlError {
            status: "ERROR",
            reason: msg.to_string(),
        }))
    };

    if params.amount < state.min_msats || params.amount > state.max_msats {
        return Err(err(&format!("Amount must be between {} and {} msats",
            state.min_msats, state.max_msats)));
    }

    // Parse deposit_id: "ledger_hex-pubkey_hex"
    let (ledger_id, deposit_pubkey) = match deposit_id.split_once('-') {
        Some((l, p)) => (l.to_string(), p.to_string()),
        None => return Err(err("Invalid deposit_id format. Expected: <ledger_id>-<deposit_pubkey>")),
    };

    let amount_sats = params.amount / 1000;
    let description = params.comment.as_deref().unwrap_or("LNURL deposit");

    // Build make_invoice request
    let content = serde_json::json!({
        "deposit_pubkey": deposit_pubkey,
        "amount_sats": amount_sats,
        "description": description,
    });

    let tags = vec![
        Tag::custom(TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::L)), [ledger_id.as_str()]),
        Tag::custom(TagKind::custom("action"), ["make_invoice"]),
    ];

    let event = EventBuilder::new(Kind::Custom(20101), content.to_string())
        .tags(tags)
        .sign_with_keys(&state.keys)
        .map_err(|e| err(&format!("Failed to sign event: {}", e)))?;

    let event_id = event.id.to_hex();

    // Set up response listener
    let (tx, rx) = tokio::sync::oneshot::channel();
    state.pending.lock().await.insert(event_id.clone(), tx);

    // Send to relays
    if let Err(e) = state.client.send_event(event).await {
        state.pending.lock().await.remove(&event_id);
        return Err(err(&format!("Failed to send request: {}", e)));
    }

    log::info!("Sent make_invoice: deposit={}-{}, amount={} sats, event={}...",
        &ledger_id[..16.min(ledger_id.len())],
        &deposit_pubkey[..16.min(deposit_pubkey.len())],
        amount_sats, &event_id[..16]);

    // Wait for response with timeout
    let response = match tokio::time::timeout(
        std::time::Duration::from_secs(15),
        rx,
    ).await {
        Ok(Ok(resp)) => resp,
        Ok(Err(_)) => {
            state.pending.lock().await.remove(&event_id);
            return Err(err("Request cancelled"));
        }
        Err(_) => {
            state.pending.lock().await.remove(&event_id);
            return Err(err("Timeout waiting for invoice from operator"));
        }
    };

    // Extract invoice from response
    let invoice = response.get("invoice")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            let error = response.get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("No invoice in response");
            err(error)
        })?;

    Ok(Json(CallbackResponse {
        pr: invoice.to_string(),
        routes: vec![],
    }))
}

// ============================================================================
// Nostr response listener
// ============================================================================

async fn listen_for_responses(state: Arc<AppState>) {
    log::info!("Listening for kind 20102 responses...");

    loop {
        let notifications = state.client.notifications();
        let mut rx = notifications;

        loop {
            match rx.recv().await {
                Ok(RelayPoolNotification::Event { event, .. }) => {
                    if event.kind.as_u16() != 20102 {
                        continue;
                    }

                    // Find the request ID from the 'e' tag
                    let request_id = event.tags.iter().find_map(|tag| {
                        if tag.kind() == TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::E)) {
                            tag.content().map(|s| s.to_string())
                        } else {
                            None
                        }
                    });

                    if let Some(req_id) = request_id {
                        let mut pending = state.pending.lock().await;
                        if let Some(tx) = pending.remove(&req_id) {
                            match serde_json::from_str::<serde_json::Value>(&event.content) {
                                Ok(response) => {
                                    let success = response.get("success")
                                        .and_then(|v| v.as_bool())
                                        .unwrap_or(false);
                                    if success {
                                        if let Some(result) = response.get("result") {
                                            let _ = tx.send(result.clone());
                                        } else {
                                            let _ = tx.send(response);
                                        }
                                    } else {
                                        let _ = tx.send(response);
                                    }
                                }
                                Err(e) => {
                                    log::warn!("Failed to parse response: {}", e);
                                }
                            }
                        }
                    }
                }
                Ok(_) => {} // other notification types
                Err(e) => {
                    log::warn!("Notification error: {}, reconnecting...", e);
                    break;
                }
            }
        }

        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}

// ============================================================================
// Main
// ============================================================================

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    // Parse config
    let nsec_str = env_or_file("LNURL_NSEC")
        .expect("Set LNURL_NSEC (hex or nsec) or LNURL_NSEC_FILE");
    let nostr_secret = if nsec_str.starts_with("nsec1") {
        nostr_sdk::SecretKey::from_bech32(&nsec_str)?
    } else {
        let bytes = hex::decode(&nsec_str)?;
        nostr_sdk::SecretKey::from_slice(&bytes)?
    };
    let keys = Keys::new(nostr_secret);

    let relay_urls: Vec<String> = std::env::var("LNURL_RELAYS")
        .unwrap_or_else(|_| "wss://relay.damus.io".to_string())
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let domain = std::env::var("LNURL_DOMAIN")
        .unwrap_or_else(|_| "localhost:3000".to_string());
    let listen = std::env::var("LNURL_LISTEN")
        .unwrap_or_else(|_| "0.0.0.0:3000".to_string());
    let min_sats: u64 = std::env::var("LNURL_MIN_SATS")
        .ok().and_then(|s| s.parse().ok()).unwrap_or(1);
    let max_sats: u64 = std::env::var("LNURL_MAX_SATS")
        .ok().and_then(|s| s.parse().ok()).unwrap_or(1_000_000);

    log::info!("deposits-lnurl starting");
    log::info!("  pubkey: {}", keys.public_key().to_bech32()?);
    log::info!("  domain: {}", domain);
    log::info!("  relays: {:?}", relay_urls);
    log::info!("  limits: {}-{} sats", min_sats, max_sats);

    // Connect to relays
    let opts = Options::default().connection_timeout(Some(std::time::Duration::from_secs(30)));
    let client = Client::with_opts(keys.clone(), opts);
    for url in &relay_urls {
        client.add_relay(url).await?;
    }
    client.connect_with_timeout(std::time::Duration::from_secs(10)).await;

    // Subscribe to responses
    let response_filter = Filter::new().kind(Kind::Custom(20102));
    client.subscribe(vec![response_filter], None).await?;

    let state = Arc::new(AppState {
        keys,
        client,
        domain,
        min_msats: min_sats * 1000,
        max_msats: max_sats * 1000,
        pending: Mutex::new(HashMap::new()),
    });

    // Spawn response listener
    let listener_state = Arc::clone(&state);
    tokio::spawn(async move {
        listen_for_responses(listener_state).await;
    });

    // Build HTTP routes
    let app = Router::new()
        .route("/.well-known/lnurlp/{deposit_id}", get(lnurlp_metadata))
        .route("/lnurl/callback/{deposit_id}", get(lnurlp_callback))
        .with_state(state);

    log::info!("Listening on {}", listen);
    let listener = tokio::net::TcpListener::bind(&listen).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
