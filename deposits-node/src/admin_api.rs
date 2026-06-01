//! Operator admin HTTP API + embedded frontend.
//!
//! Per PACKAGING_PLAN.md Tier 5. Runs alongside the metrics server on a
//! separate port (`--admin-bind`, default `127.0.0.1:9210`), serves a
//! single-page vanilla-JS frontend that reads from a small JSON API.
//!
//! ## Auth
//!
//! Bearer-token via `Authorization: Bearer <hex>`. The token is a 32-byte
//! random value generated on first run, written to `<data-dir>/admin-token`
//! mode 0600. The operator copies the token into the browser once; it
//! lives in localStorage thereafter.
//!
//! The `/` route serves the unauthenticated HTML; only `/api/*` requires
//! the token. So the browser can load the page, the JS prompts for the
//! token, fetches the API with it.
//!
//! ## Style
//!
//! The embedded frontend lives at `deposits-node/admin-ui/index.html`
//! and mirrors the visual idiom from `deposits-web/explorer/` (same
//! CSS variables, brand bar, card/stats grid). Operators who already
//! use the explorer get the same look.
//!
//! ## Scope (this iteration)
//!
//! Read-only dashboard surface: `/api/status`, `/api/ledgers`,
//! `/api/quorum`, `/api/activity`, `/api/signer`. Action endpoints
//! (rotate quorum, respond to dispute, etc.) land in a follow-on
//! commit so the trait + UI scaffolding can be validated first.

use axum::{
    extract::{Request, State},
    http::{header, HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Json, Response},
    routing::get,
    Router,
};
use rand::RngCore;
use serde::Serialize;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use crate::node::Node;
use crate::Error;

/// Static frontend served at `/`. One file, no build step, no framework
/// — same shape as `deposits-web/explorer/`'s pages.
const INDEX_HTML: &str = include_str!("../admin-ui/index.html");

#[derive(Clone)]
pub struct AdminConfig {
    pub bind_addr: SocketAddr,
    pub token: String,
}

/// Idempotently produce a 32-byte hex token at `<data_dir>/admin-token`.
/// On first call: generate via OS RNG, write mode 0600, log the path +
/// the token itself with a "PASTE INTO BROWSER" hint. On subsequent
/// calls: read and return.
pub fn ensure_token(data_dir: &Path) -> Result<String, Error> {
    let path = data_dir.join("admin-token");
    if path.exists() {
        let s = std::fs::read_to_string(&path)
            .map_err(|e| Error::Wallet(format!("read admin-token {}: {}", path.display(), e)))?;
        return Ok(s.trim().to_string());
    }
    std::fs::create_dir_all(data_dir).map_err(|e| {
        Error::Wallet(format!("create data_dir {}: {}", data_dir.display(), e))
    })?;
    let mut buf = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut buf);
    let token = hex::encode(buf);
    std::fs::write(&path, &token)
        .map_err(|e| Error::Wallet(format!("write admin-token: {}", e)))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&path)
            .map_err(|e| Error::Wallet(format!("stat admin-token: {}", e)))?
            .permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&path, perms)
            .map_err(|e| Error::Wallet(format!("chmod admin-token: {}", e)))?;
    }
    tracing::warn!(
        "Generated admin token at {}. PASTE THIS INTO YOUR BROWSER once:\n\n    {}\n",
        path.display(),
        token
    );
    Ok(token)
}

/// Start the admin HTTP server. Blocks the task until shutdown.
pub async fn serve(config: AdminConfig, node: Arc<Node>) -> Result<(), Error> {
    let api_routes = Router::new()
        .route("/status", get(get_status))
        .route("/ledgers", get(get_ledgers))
        .route("/quorum", get(get_quorum))
        .route("/activity", get(get_activity))
        .route("/signer", get(get_signer))
        .with_state(node)
        .route_layer(middleware::from_fn_with_state(
            config.token.clone(),
            auth_middleware,
        ));

    let app = Router::new()
        .route("/", get(serve_index))
        .nest("/api", api_routes);

    let listener = tokio::net::TcpListener::bind(&config.bind_addr)
        .await
        .map_err(|e| Error::Wallet(format!("admin bind {}: {}", config.bind_addr, e)))?;
    tracing::info!("Admin UI listening on http://{}/", config.bind_addr);
    axum::serve(listener, app)
        .await
        .map_err(|e| Error::Wallet(format!("admin serve: {}", e)))?;
    Ok(())
}

// -- routes ----------------------------------------------------------------

async fn serve_index() -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        INDEX_HTML,
    )
        .into_response()
}

async fn auth_middleware(
    State(expected): State<String>,
    headers: HeaderMap,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let token = auth.strip_prefix("Bearer ").unwrap_or("");
    // Constant-time-ish compare via length+iteration; for a 64-char hex
    // value this isn't a meaningful side-channel surface but it's the
    // right habit.
    if token.len() != expected.len() || !token.bytes().zip(expected.bytes()).all(|(a, b)| a == b) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(next.run(req).await)
}

#[derive(Serialize)]
struct Status {
    operator_pubkey: String,
    network: String,
    chain_tip_height: u32,
    ledgers_count: usize,
    active_quorums: usize,
    serving_on_quorums: usize,
    version: &'static str,
}

async fn get_status(State(node): State<Arc<Node>>) -> Json<Status> {
    let (our_ledgers, joined) = node.list_quorum_info();
    let active_quorums = our_ledgers
        .iter()
        .filter(|(_, active, _)| !active.is_empty())
        .count();
    let serving_on_quorums: usize = joined.iter().map(|(_, v)| v.len()).sum();
    Json(Status {
        operator_pubkey: node.node_id.to_string(),
        network: format!("{:?}", node.wallet.network()).to_lowercase(),
        chain_tip_height: node.wallet.get_block_height().unwrap_or(0),
        ledgers_count: our_ledgers.len(),
        active_quorums,
        serving_on_quorums,
        version: env!("CARGO_PKG_VERSION"),
    })
}

#[derive(Serialize)]
struct LedgerSummary {
    ledger_id: String,
    role: &'static str, // "operator" | "partner"
    reserves_address: String,
    reserves_sats: u64,
    deposits_count: usize,
    deposits_total_msats: u128,
    quorum_size: usize,
    quorum_active: bool,
    next_sequence: u64,
}

async fn get_ledgers(State(node): State<Arc<Node>>) -> Json<Vec<LedgerSummary>> {
    let ledgers = node.handler.ledgers.lock().unwrap();
    let mut out = Vec::new();
    for (ledger_id, arc) in ledgers.iter() {
        let l = arc.read().unwrap();
        let is_ours = l.operator_key() == node.node_id;
        let deposits_total: u128 = l
            .state
            .deposits
            .values()
            .map(|d| d.balance as u128)
            .sum();
        out.push(LedgerSummary {
            ledger_id: ledger_id.clone(),
            role: if is_ours { "operator" } else { "partner" },
            // `reserves_key` is the BIP-340 reserves *address* in string
            // form — historic naming (key meant "identifier" here, not a
            // pubkey). Tomorrow's rename can fix that without changing
            // the on-wire shape.
            reserves_address: l.state.reserves_key.clone(),
            reserves_sats: l.state.reserves_amount,
            deposits_count: l.state.deposits.len(),
            deposits_total_msats: deposits_total,
            quorum_size: l.state.quorum_members.len(),
            quorum_active: !l.state.quorum_members.is_empty(),
            next_sequence: l.next_sequence(),
        });
    }
    out.sort_by(|a, b| a.ledger_id.cmp(&b.ledger_id));
    Json(out)
}

#[derive(Serialize)]
struct QuorumInfo {
    our_ledgers: Vec<OurLedgerQuorum>,
    serving_on: Vec<ServingEntry>,
}

#[derive(Serialize)]
struct OurLedgerQuorum {
    ledger_id: String,
    active_members: Vec<String>,
    pending_members: Vec<String>,
}

#[derive(Serialize)]
struct ServingEntry {
    via_our_ledger: String,
    operator: String,
    their_ledger: String,
    expires_block: u32,
}

async fn get_quorum(State(node): State<Arc<Node>>) -> Json<QuorumInfo> {
    let (our_ledgers, joined) = node.list_quorum_info();
    let our_ledgers = our_ledgers
        .into_iter()
        .map(|(ledger_id, active, pending)| OurLedgerQuorum {
            ledger_id,
            active_members: active.into_iter().map(|p| p.to_string()).collect(),
            pending_members: pending.into_iter().map(|p| p.to_string()).collect(),
        })
        .collect();
    let mut serving_on = Vec::new();
    for (our_lid, list) in joined {
        for (op, their_lid, exp) in list {
            serving_on.push(ServingEntry {
                via_our_ledger: our_lid.clone(),
                operator: op.to_string(),
                their_ledger: their_lid,
                expires_block: exp,
            });
        }
    }
    Json(QuorumInfo {
        our_ledgers,
        serving_on,
    })
}

#[derive(Serialize)]
struct ActivityEntry {
    ledger_id: String,
    sequence: u64,
    op_type: String,
    block_height: u32,
}

async fn get_activity(State(node): State<Arc<Node>>) -> Json<Vec<ActivityEntry>> {
    use deposits_core::messages::LedgerOperation;
    use deposits_core::tlv::TlvDecode;

    let ledgers = node.handler.ledgers.lock().unwrap();
    let mut out = Vec::new();
    for (ledger_id, arc) in ledgers.iter() {
        let l = arc.read().unwrap();
        // Most-recent 20 history entries per ledger, oldest-first.
        let take = 20.min(l.history.len());
        let start = l.history.len().saturating_sub(take);
        for u in &l.history[start..] {
            let op_type = match LedgerOperation::tlv_decode(&u.message) {
                Ok(op) => op_name(&op).to_string(),
                Err(_) => "Unknown".to_string(),
            };
            out.push(ActivityEntry {
                ledger_id: ledger_id.clone(),
                sequence: u.sequence_number,
                op_type,
                block_height: u.block_height,
            });
        }
    }
    // Newest first across ledgers.
    out.sort_by(|a, b| b.block_height.cmp(&a.block_height).then(b.sequence.cmp(&a.sequence)));
    out.truncate(100);
    Json(out)
}

/// Human-readable name for a LedgerOperation variant. Matches the
/// variant ident; cheap pattern match. Used by the activity feed.
fn op_name(op: &deposits_core::messages::LedgerOperation) -> &'static str {
    use deposits_core::messages::LedgerOperation as Op;
    match op {
        Op::LedgerOpen { .. } => "LedgerOpen",
        Op::LedgerClose { .. } => "LedgerClose",
        Op::DepositOpen { .. } => "DepositOpen",
        Op::DepositClose { .. } => "DepositClose",
        Op::FeeChange { .. } => "FeeChange",
        Op::DepositKeyRotate { .. } => "DepositKeyRotate",
        Op::QuorumAddMember { .. } => "QuorumAddMember",
        Op::QuorumRemoveMember { .. } => "QuorumRemoveMember",
        Op::QuorumJoin { .. } => "QuorumJoin",
        Op::QuorumBegin { .. } => "QuorumBegin",
        Op::InvoiceLock { .. } => "InvoiceLock",
        Op::InvoiceFulfill { .. } => "InvoiceFulfill",
        Op::InvoiceFail { .. } => "InvoiceFail",
        Op::InvoiceCredit { .. } => "InvoiceCredit",
        Op::OnchainLock { .. } => "OnchainLock",
        Op::OnchainFulfill { .. } => "OnchainFulfill",
        Op::OnchainFail { .. } => "OnchainFail",
        Op::OnchainCredit { .. } => "OnchainCredit",
        Op::TransferLock { .. } => "TransferLock",
        Op::TransferComplete { .. } => "TransferComplete",
        Op::DisputeEnter { .. } => "DisputeEnter",
        Op::DisputeArmed { .. } => "DisputeArmed",
        Op::DisputeAcquire { .. } => "DisputeAcquire",
        Op::DisputeYield { .. } => "DisputeYield",
        _ => "Other",
    }
}

#[derive(Serialize)]
struct SignerStatus {
    pubkey: String,
    /// "local" (in-process LocalSigner) or "remote" (RemoteSigner socket)
    transport: &'static str,
    connected: bool,
}

async fn get_signer(State(node): State<Arc<Node>>) -> Json<SignerStatus> {
    use deposits_signer_api::Signer;
    // Round-trip the operator pubkey through the signer trait as a
    // liveness check: success = signer connected and the right
    // identity. For RemoteSigner this exercises the socket; for
    // LocalSigner it's an in-process call.
    let signer = node.handler.signer.clone();
    let result = tokio::task::spawn_blocking(move || signer.xonly_pubkey()).await;
    let (connected, pubkey) = match result {
        Ok(pk) => (true, pk.to_string()),
        Err(_) => (false, String::new()),
    };
    // Approximation: a real local-vs-remote split needs threading the
    // signer choice through NodeConfig. Until that, report "unknown" —
    // the connection state above is the load-bearing field for ops.
    let transport = "unknown";
    Json(SignerStatus {
        pubkey,
        transport,
        connected,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn ensure_token_generates_then_reads() {
        let tmp = TempDir::new().unwrap();
        let t1 = ensure_token(tmp.path()).unwrap();
        assert_eq!(t1.len(), 64); // 32 bytes hex
        let t2 = ensure_token(tmp.path()).unwrap();
        assert_eq!(t1, t2);
    }

    #[test]
    #[cfg(unix)]
    fn ensure_token_writes_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let _ = ensure_token(tmp.path()).unwrap();
        let path = tmp.path().join("admin-token");
        let perms = std::fs::metadata(&path).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);
    }
}
