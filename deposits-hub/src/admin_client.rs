//! Hub-side admin RPC client.
//!
//! Sends gift-wrapped Kind 20101 admin requests to a registered
//! daemon, signed with the hub's own nostr secret. The daemon's
//! `check_admin_authorized` accepts the request iff its operator has
//! configured the hub's pubkey in `<data_dir>/admin.npub` — that's
//! the operator-side opt-in for letting the hub drive the daemon.
//!
//! Wraps [`deposits_nostr::NostrTransport::send_admin_request`] +
//! [`wait_for_response`], plus a tiny per-call connection lifecycle:
//! each admin RPC opens a fresh transport against the same relays
//! the hub uses, since the hub's own `HubTransport` uses a different
//! event-kind subscription (Kind 1059 gift wraps) and would collide
//! with the daemon-response Kind 20102 stream we need to await here.
//!
//! Future: pool the per-call transport so repeated calls amortize
//! the connect cost. For an interactive wizard with a few calls per
//! session, a fresh connect per call is fine.

use deposits_nostr::{NostrTransportBuilder, KIND_LEDGER_REQUEST as _};
use std::time::Duration;

/// Default response timeout. Mirrors `send_admin_daemon_request` in
/// the daemon's CLI — most admin handlers return in well under a
/// second; 60s is just a safety net against a daemon that's stuck.
pub const DEFAULT_TIMEOUT_MS: u64 = 60_000;

/// Errors surfacing from the hub-side admin client.
#[derive(Debug, thiserror::Error)]
pub enum AdminError {
    #[error("no relays configured — hub needs at least one --relay")]
    NoRelays,
    #[error("invalid hub secret: {0}")]
    HubSecret(String),
    #[error("nostr transport: {0}")]
    Transport(String),
    #[error("daemon rejected request: {0}")]
    Rejected(String),
    #[error("daemon returned no result")]
    EmptyResult,
}

/// Send a single admin request to a registered daemon.
///
/// `daemon_operator_pubkey_hex` is the x-only operator pubkey from
/// the daemon's `NodeRecord` (the hub already knows it from the
/// daemon's Register message).
///
/// `ledger_id` may be any 64-hex value the action references, or the
/// recipient's own pubkey for non-ledger-scoped admin actions
/// (mirrors how `deposits-node admin` does it — the daemon's
/// dispatch keys on the `action` tag, not on `l`).
pub async fn send_admin_request(
    hub_secret_hex: &str,
    relays: &[String],
    daemon_operator_pubkey_hex: &str,
    ledger_id: &str,
    action: &str,
    params: serde_json::Value,
    timeout_ms: u64,
) -> Result<serde_json::Value, AdminError> {
    if relays.is_empty() {
        return Err(AdminError::NoRelays);
    }
    let secret = bitcoin::secp256k1::SecretKey::from_slice(
        &hex::decode(hub_secret_hex)
            .map_err(|e| AdminError::HubSecret(format!("hex: {}", e)))?,
    )
    .map_err(|e| AdminError::HubSecret(format!("parse: {}", e)))?;

    let mut builder = NostrTransportBuilder::new(secret);
    for r in relays {
        builder = builder.relay(r);
    }
    let mut transport = builder
        .build()
        .await
        .map_err(|e| AdminError::Transport(format!("build: {}", e)))?;

    let req_id = transport
        .send_admin_request(daemon_operator_pubkey_hex, ledger_id, action, params)
        .await
        .map_err(|e| AdminError::Transport(format!("send: {}", e)))?;

    let resp = transport
        .wait_for_response(&req_id, timeout_ms)
        .await
        .map_err(|e| AdminError::Transport(format!("wait: {}", e)))?;

    if !resp.success {
        return Err(AdminError::Rejected(
            resp.error.unwrap_or_else(|| "unknown".to_string()),
        ));
    }
    resp.result.ok_or(AdminError::EmptyResult)
}

// Re-export so callers don't have to depend on deposits-nostr directly
// just to reach the wire-kind constant in tests / diagnostics.
pub use deposits_nostr::KIND_LEDGER_REQUEST;
