//! LNURL-pay gateway for Bitcoin Deposits
//!
//! Serves LUD-06/LUD-16 endpoints that translate LNURL-pay callbacks into
//! deposits-node `make_invoice` requests via Nostr.
//!
//! Lightning address format: `<deposit_pubkey>@<ledger_prefix>.<base_domain>`
//!
//! The ledger ID comes from the subdomain (wildcard DNS). A single server
//! handles all ledgers via `*.<base_domain>`.
//!
//! Flow:
//!   1. Payer resolves `pubkey@a08153ed.pay.example.com`
//!   2. GET https://a08153ed.pay.example.com/.well-known/lnurlp/<pubkey>
//!   3. Response: metadata, min/max, callback URL
//!   4. Payer calls callback with ?amount=<msats>
//!   5. Server extracts ledger ID from Host header subdomain
//!   6. Server sends kind 20101 make_invoice to operator relay
//!   7. Operator responds with kind 20102 containing BOLT11 invoice
//!   8. Server returns invoice to payer
//!
//! Env vars:
//!   LNURL_NSEC          - Service key (hex or nsec) for signing Nostr requests
//!   LNURL_RELAYS        - Comma-separated relay URLs
//!   LNURL_DOMAIN        - Base domain (e.g. pay.example.com). Subdomains = ledger IDs.
//!   LNURL_LISTEN        - HTTP listen address (default: 0.0.0.0:3000)
//!   LNURL_MIN_SATS      - Minimum payment (default: 1)
//!   LNURL_MAX_SATS      - Maximum payment (default: 1000000)

use axum::{
    extract::{Host, Path, Query, State},
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
    /// Cache of discovered operator pubkeys per ledger (from Kind 39100 ads).
    /// Used to gift-wrap requests so the relay never sees ledger_id /
    /// deposit_pubkey / amount in cleartext.
    operator_keys: Mutex<HashMap<String, PublicKey>>,
    /// NIP-57 zap-request lifecycle: payment_hash (hex) → recorded
    /// pending zap. When the matching `InvoiceCredit` is observed on
    /// the operator's ledger, we publish a Kind 9735 receipt
    /// referencing the original zap request. Lost on gateway restart —
    /// the credit still happens, but the depositor doesn't get a zap
    /// receipt for that one.
    pending_zaps: Mutex<HashMap<String, PendingZap>>,
}

/// Recorded NIP-57 zap request awaiting payment confirmation.
struct PendingZap {
    /// Original zap-request event JSON (Kind 9734) as the wallet sent
    /// it. Embedded verbatim into the eventual receipt as the
    /// `description` tag value, per NIP-57.
    request_json: String,
    /// BOLT11 invoice we returned to the wallet. Goes into the receipt's
    /// `bolt11` tag.
    bolt11: String,
    /// `p` tag from the zap request — the recipient (deposit owner) the
    /// zap is addressed to.
    recipient_pubkey: String,
    /// `e` tag from the zap request, if any — the event being zapped.
    event_id: Option<String>,
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
    /// NIP-57: signals to wallets that the callback accepts a `nostr=`
    /// param carrying a zap-request event.
    #[serde(rename = "allowsNostr")]
    allows_nostr: bool,
    /// NIP-57: hex pubkey wallets should expect to author the eventual
    /// Kind 9735 zap receipt. Must equal `state.keys.public_key()`.
    #[serde(rename = "nostrPubkey")]
    nostr_pubkey: String,
}

#[derive(Deserialize)]
struct CallbackParams {
    amount: u64, // msats
    comment: Option<String>,
    /// NIP-57 zap-request event, urlencoded JSON. When present the
    /// invoice's description_hash commits to sha256 of this raw value
    /// and we record a pending zap for receipt publishing later.
    nostr: Option<String>,
}

#[derive(Serialize)]
struct CallbackResponse {
    pr: String, // BOLT11 invoice
    routes: Vec<()>,
    /// Operator + cosigner attestation artifacts forwarded from the
    /// operator's `make_invoice` response. A depositor who pays the
    /// invoice and never sees the credit can use these to file a
    /// fraud proof and burn the operator's collateral.
    #[serde(skip_serializing_if = "Option::is_none")]
    attestations: Option<serde_json::Value>,
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
        return std::fs::read_to_string(path)
            .ok()
            .map(|s| s.trim().to_string());
    }
    None
}

// ============================================================================
// LNURL-pay endpoints
// ============================================================================

// Bech32 charset for encoding ledger IDs into DNS-safe subdomains
const BECH32_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// Encode bytes as bech32 data characters (no HRP, no checksum — just the data part).
/// 32 bytes → 52 chars, fits in a DNS label.
fn bytes_to_bech32_data(bytes: &[u8]) -> String {
    // Convert 8-bit groups to 5-bit groups
    let mut result = Vec::new();
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &b in bytes {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            result.push(BECH32_CHARSET[((acc >> bits) & 0x1f) as usize]);
        }
    }
    if bits > 0 {
        result.push(BECH32_CHARSET[((acc << (5 - bits)) & 0x1f) as usize]);
    }
    String::from_utf8(result).unwrap()
}

/// Decode bech32 data characters back to bytes.
fn bech32_data_to_bytes(s: &str) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut result = Vec::new();
    for c in s.bytes() {
        let idx = BECH32_CHARSET.iter().position(|&ch| ch == c)?;
        acc = (acc << 5) | idx as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            result.push((acc >> bits) as u8);
        }
    }
    Some(result)
}

/// Encode a hex ledger ID to a bech32-data subdomain label.
fn ledger_to_subdomain(hex_id: &str) -> Option<String> {
    let bytes = hex::decode(hex_id).ok()?;
    Some(bytes_to_bech32_data(&bytes))
}

/// Decode a bech32-data subdomain label back to a hex ledger ID.
fn subdomain_to_ledger(subdomain: &str) -> Option<String> {
    let bytes = bech32_data_to_bytes(subdomain)?;
    if bytes.len() == 32 {
        Some(hex::encode(bytes))
    } else {
        None
    }
}

fn lnurl_err(msg: &str) -> (StatusCode, Json<LnurlError>) {
    (
        StatusCode::BAD_REQUEST,
        Json(LnurlError {
            status: "ERROR",
            reason: msg.to_string(),
        }),
    )
}

/// Extract the full hex ledger ID from the Host header subdomain.
///
/// Host `<sub>.<base_domain>` → 64-char lowercase hex. Two accepted forms:
///   1. `<sub>` is exactly 52 bech32-data chars → decodes to 32 bytes
///   2. `<sub>` is exactly 64 hex chars → returned verbatim (lowercased)
///
/// Anything else (including short bech32 / hex prefixes) is rejected.
/// Accepting prefixes here would let an attacker register a colliding
/// ledger whose ID shares the same prefix and intercept payments — a
/// 32-byte ledger ID fits in a single 63-char DNS label as bech32, so
/// there's no benefit to allowing shorter forms server-side.
///
/// Falls back to LNURL_DEFAULT_LEDGER (full 64-hex) if no subdomain.
fn extract_ledger_from_host(host: &str, base_domain: &str) -> Option<String> {
    // Strip port if present
    let host_no_port = host.split(':').next().unwrap_or(host);
    let base_no_port = base_domain.split(':').next().unwrap_or(base_domain);

    if host_no_port.ends_with(base_no_port) && host_no_port.len() > base_no_port.len() {
        let prefix = &host_no_port[..host_no_port.len() - base_no_port.len()];
        let prefix = prefix.trim_end_matches('.');
        if !prefix.is_empty() {
            // Full bech32 (52 chars → 32 bytes → 64 hex)
            if let Some(hex_id) = subdomain_to_ledger(prefix) {
                return Some(hex_id);
            }
            // Raw 64-char hex
            if prefix.len() == 64 && prefix.chars().all(|c| c.is_ascii_hexdigit()) {
                return Some(prefix.to_lowercase());
            }
            return None;
        }
    }

    // Fallback: check env var for single-ledger deployments
    std::env::var("LNURL_DEFAULT_LEDGER").ok()
}

/// GET /.well-known/lnurlp/<deposit_pubkey>
///
/// Returns LNURL-pay metadata. Ledger ID comes from the Host subdomain.
async fn lnurlp_metadata(
    State(state): State<Arc<AppState>>,
    Host(host): Host,
    Path(deposit_pubkey): Path<String>,
) -> Result<Json<LnurlPayResponse>, (StatusCode, Json<LnurlError>)> {
    let _ledger_hex = extract_ledger_from_host(&host, &state.domain)
        .ok_or_else(|| lnurl_err("Could not determine ledger from host. Subdomain must be the full 52-char bech32 (or 64-char hex) ledger ID."))?;

    // Echo back the host the user came in on so the address wallets
    // display matches whatever DNS shape the operator's serving.
    let addr_domain = host.clone();
    let metadata = format!(
        "[[\"text/plain\",\"Pay to deposit {}\"],[\"text/identifier\",\"{}@{}\"]]",
        &deposit_pubkey[..16.min(deposit_pubkey.len())],
        deposit_pubkey,
        addr_domain,
    );

    Ok(Json(LnurlPayResponse {
        tag: "payRequest",
        callback: format!("https://{}/lnurl/callback/{}", addr_domain, deposit_pubkey),
        min_sendable: state.min_msats,
        max_sendable: state.max_msats,
        metadata,
        comment_allowed: 0,
        allows_nostr: true,
        nostr_pubkey: state.keys.public_key().to_hex(),
    }))
}

/// Discover the operator's nostr pubkey for a ledger by querying its
/// Kind 39100 advertisement. Cached per-ledger; misses fall back to plaintext.
///
/// The ad is signed by the operator's nostr key, so `event.pubkey` is the
/// authoritative operator identity (the `o` tag is informational and equal
/// in practice but not signature-bound).
async fn discover_operator(state: &AppState, ledger_id: &str) -> Option<PublicKey> {
    if let Some(pk) = state.operator_keys.lock().await.get(ledger_id).copied() {
        return Some(pk);
    }
    let filter = Filter::new()
        .kind(Kind::Custom(39100))
        .custom_tag(SingleLetterTag::lowercase(Alphabet::L), [ledger_id])
        .limit(1);
    let events = state
        .client
        .fetch_events(vec![filter], Some(std::time::Duration::from_secs(5)))
        .await
        .ok()?;
    let event = events.into_iter().max_by_key(|e| e.created_at)?;
    let pk = event.pubkey;
    state
        .operator_keys
        .lock()
        .await
        .insert(ledger_id.to_string(), pk);
    Some(pk)
}

/// Build a NIP-59-shaped gift-wrap (rumor → seal → wrap) for a Kind 20101
/// request, mirroring `send_admin_request` in deposits-node/src/nostr.rs.
///
/// Uses NIP-04 (not NIP-44) and Kind 20101 for the outer wrap so the daemon's
/// `process_ledger_request` accepts it via its existing unwrap path.
fn gift_wrap_request(
    sender: &Keys,
    recipient: &PublicKey,
    ledger_id: &str,
    action: &str,
    content: &str,
) -> Result<Event, String> {
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Rumor: unsigned 20101 event.
    let rumor_json = serde_json::json!({
        "kind": 20101,
        "content": content,
        "tags": [["l", ledger_id], ["action", action]],
        "pubkey": sender.public_key().to_hex(),
        "created_at": created_at,
    })
    .to_string();

    // Seal: NIP-04-encrypted rumor, kind 13, signed by us.
    let seal_content = nip04::encrypt(sender.secret_key(), recipient, &rumor_json)
        .map_err(|e| format!("seal encrypt failed: {}", e))?;
    let seal_event = EventBuilder::new(Kind::Custom(13), &seal_content)
        .sign_with_keys(sender)
        .map_err(|e| format!("seal sign failed: {}", e))?;
    let seal_json = serde_json::json!({
        "id": seal_event.id.to_hex(),
        "pubkey": seal_event.pubkey.to_hex(),
        "created_at": seal_event.created_at.as_u64(),
        "kind": 13,
        "content": seal_event.content,
        "sig": seal_event.sig.to_string(),
    })
    .to_string();

    // Wrap: outer kind 20101, NIP-04-encrypted to recipient, signed by a
    // throwaway key so relays can't link wraps to a long-lived identity.
    let throwaway = Keys::generate();
    let wrap_content = nip04::encrypt(throwaway.secret_key(), recipient, &seal_json)
        .map_err(|e| format!("wrap encrypt failed: {}", e))?;
    EventBuilder::new(Kind::Custom(20101), &wrap_content)
        .tag(Tag::public_key(*recipient))
        .tag(Tag::custom(
            TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::L)),
            [ledger_id],
        ))
        .tag(Tag::custom(TagKind::custom("action"), [action]))
        .sign_with_keys(&throwaway)
        .map_err(|e| format!("wrap sign failed: {}", e))
}

/// Try to gift-unwrap a kind-20102 response addressed to us.
/// Returns the inner response JSON on success, or None if the event isn't
/// a wrap or decryption fails.
fn gift_unwrap_response(recipient: &Keys, event: &Event) -> Option<serde_json::Value> {
    // Outer: encrypted by throwaway sender to us.
    let seal_json = nip04::decrypt(recipient.secret_key(), &event.pubkey, &event.content).ok()?;
    let seal: serde_json::Value = serde_json::from_str(&seal_json).ok()?;
    // Seal: encrypted by real operator key to us.
    let seal_pubkey_hex = seal.get("pubkey")?.as_str()?;
    let seal_pubkey = PublicKey::from_hex(seal_pubkey_hex).ok()?;
    let seal_content = seal.get("content")?.as_str()?;
    let rumor_json = nip04::decrypt(recipient.secret_key(), &seal_pubkey, seal_content).ok()?;
    let rumor: serde_json::Value = serde_json::from_str(&rumor_json).ok()?;
    let inner_content = rumor.get("content")?.as_str()?;
    serde_json::from_str(inner_content).ok()
}

/// GET /lnurl/callback/<deposit_pubkey>?amount=<msats>
///
/// Creates an invoice via the operator's deposits-node. Ledger from Host subdomain.
async fn lnurlp_callback(
    State(state): State<Arc<AppState>>,
    Host(host): Host,
    Path(deposit_pubkey): Path<String>,
    Query(params): Query<CallbackParams>,
) -> Result<Json<CallbackResponse>, (StatusCode, Json<LnurlError>)> {
    let ledger_id = extract_ledger_from_host(&host, &state.domain)
        .ok_or_else(|| lnurl_err("Could not determine ledger from host. Subdomain must be the full 52-char bech32 (or 64-char hex) ledger ID."))?;

    if params.amount < state.min_msats || params.amount > state.max_msats {
        return Err(lnurl_err(&format!(
            "Amount must be between {} and {} msats",
            state.min_msats, state.max_msats
        )));
    }

    let amount_sats = params.amount / 1000;

    // NIP-57 zap: parse the `nostr=` param if present and compute its
    // sha256 — that's the description_hash the wallet will check the
    // invoice's `h` field against. We also stash the parsed event so a
    // successful invoice lets us record a pending zap for receipt
    // publishing later.
    let zap_request = match params.nostr.as_ref() {
        Some(raw) => {
            let parsed: serde_json::Value = serde_json::from_str(raw)
                .map_err(|e| lnurl_err(&format!("invalid `nostr=` JSON: {}", e)))?;
            if parsed.get("kind").and_then(|v| v.as_u64()) != Some(9734) {
                return Err(lnurl_err("`nostr=` event must be Kind 9734 (zap request)"));
            }
            Some((raw.clone(), parsed))
        }
        None => None,
    };
    let description_hash_hex: Option<String> = zap_request.as_ref().map(|(raw, _)| {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(raw.as_bytes()))
    });
    let description = params.comment.as_deref().unwrap_or("LNURL deposit");

    // Build make_invoice request — operator picks `h` field over `d`
    // when description_hash is set.
    let mut content = serde_json::json!({
        "deposit_pubkey": deposit_pubkey,
        "amount_sats": amount_sats,
        "description": description,
    });
    if let Some(ref dh) = description_hash_hex {
        content["description_hash"] = serde_json::Value::String(dh.clone());
    }

    // Try to gift-wrap to the operator. Falls back to plaintext if the ad
    // hasn't propagated yet (matches the web wallet's pre-discovery behavior).
    let operator_pk = discover_operator(&state, &ledger_id).await;
    let (event, wrapped) = match operator_pk {
        Some(recipient) => {
            let wrap = gift_wrap_request(
                &state.keys,
                &recipient,
                &ledger_id,
                "make_invoice",
                &content.to_string(),
            )
            .map_err(|e| lnurl_err(&format!("Gift-wrap failed: {}", e)))?;
            (wrap, true)
        }
        None => {
            let tags = vec![
                Tag::custom(
                    TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::L)),
                    [ledger_id.as_str()],
                ),
                Tag::custom(TagKind::custom("action"), ["make_invoice"]),
            ];
            let plain = EventBuilder::new(Kind::Custom(20101), content.to_string())
                .tags(tags)
                .sign_with_keys(&state.keys)
                .map_err(|e| lnurl_err(&format!("Failed to sign event: {}", e)))?;
            (plain, false)
        }
    };

    let event_id = event.id.to_hex();

    // Set up response listener
    let (tx, rx) = tokio::sync::oneshot::channel();
    state.pending.lock().await.insert(event_id.clone(), tx);

    // Send to relays
    if let Err(e) = state.client.send_event(event).await {
        state.pending.lock().await.remove(&event_id);
        return Err(lnurl_err(&format!("Failed to send request: {}", e)));
    }

    log::info!(
        "Sent make_invoice: deposit={}-{}, amount={} sats, event={}... wrapped={}",
        &ledger_id[..16.min(ledger_id.len())],
        &deposit_pubkey[..16.min(deposit_pubkey.len())],
        amount_sats,
        &event_id[..16],
        wrapped,
    );

    // Wait for response with timeout
    let response = match tokio::time::timeout(std::time::Duration::from_secs(15), rx).await {
        Ok(Ok(resp)) => resp,
        Ok(Err(_)) => {
            state.pending.lock().await.remove(&event_id);
            return Err(lnurl_err("Request cancelled"));
        }
        Err(_) => {
            state.pending.lock().await.remove(&event_id);
            return Err(lnurl_err("Timeout waiting for invoice from operator"));
        }
    };

    // Extract invoice from response
    let invoice = response
        .get("invoice")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            let error = response
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("No invoice in response");
            lnurl_err(error)
        })?;
    let payment_hash_hex = response
        .get("payment_hash")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Record the pending zap so the receipt publisher can find it when
    // the matching `InvoiceCredit` lands on the operator's ledger.
    if let (Some((raw, parsed)), Some(payment_hash)) = (zap_request, payment_hash_hex.as_ref()) {
        let recipient_pubkey = parsed
            .get("tags")
            .and_then(|v| v.as_array())
            .and_then(|tags| {
                tags.iter().find_map(|t| {
                    let arr = t.as_array()?;
                    if arr.first()?.as_str()? == "p" {
                        arr.get(1)?.as_str().map(String::from)
                    } else {
                        None
                    }
                })
            })
            .unwrap_or_default();
        let event_id = parsed
            .get("tags")
            .and_then(|v| v.as_array())
            .and_then(|tags| {
                tags.iter().find_map(|t| {
                    let arr = t.as_array()?;
                    if arr.first()?.as_str()? == "e" {
                        arr.get(1)?.as_str().map(String::from)
                    } else {
                        None
                    }
                })
            });
        state.pending_zaps.lock().await.insert(
            payment_hash.clone(),
            PendingZap {
                request_json: raw,
                bolt11: invoice.to_string(),
                recipient_pubkey,
                event_id,
            },
        );
        log::info!(
            "Recorded pending zap for payment_hash={}…",
            &payment_hash[..16.min(payment_hash.len())]
        );
    }

    // Forward operator + cosigner artifacts to the LNURL caller. Lets
    // a depositor who paid an invoice they never got credit for file
    // a fraud proof against the operator's collateral.
    let attestations = {
        let mut out = serde_json::Map::new();
        for k in [
            "deposit_id",
            "payment_hash",
            "operator_pubkey",
            "operator_ledger_hash",
            "operator_signature",
            "cosigner_pubkey",
            "cosigner_ledger_hash",
            "cosign_signature",
        ] {
            if let Some(v) = response.get(k) {
                out.insert(k.to_string(), v.clone());
            }
        }
        if out.is_empty() {
            None
        } else {
            Some(serde_json::Value::Object(out))
        }
    };

    Ok(Json(CallbackResponse {
        pr: invoice.to_string(),
        routes: vec![],
        attestations,
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
                        if tag.kind()
                            == TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::E))
                        {
                            tag.content().map(|s| s.to_string())
                        } else {
                            None
                        }
                    });

                    if let Some(req_id) = request_id {
                        let mut pending = state.pending.lock().await;
                        if let Some(tx) = pending.remove(&req_id) {
                            // Operator mirrors our wrap state — plaintext
                            // request → plaintext response, wrapped → wrapped.
                            let parsed = serde_json::from_str::<serde_json::Value>(&event.content)
                                .ok()
                                .or_else(|| gift_unwrap_response(&state.keys, &event));
                            match parsed {
                                Some(response) => {
                                    let success = response
                                        .get("success")
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
                                None => {
                                    log::warn!(
                                        "Failed to parse response (plaintext + unwrap both failed)"
                                    );
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
    let nsec_str =
        env_or_file("LNURL_NSEC").expect("Set LNURL_NSEC (hex or nsec) or LNURL_NSEC_FILE");
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

    let domain = std::env::var("LNURL_DOMAIN").unwrap_or_else(|_| "localhost:3000".to_string());
    let listen = std::env::var("LNURL_LISTEN").unwrap_or_else(|_| "0.0.0.0:3000".to_string());
    let min_sats: u64 = std::env::var("LNURL_MIN_SATS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    let max_sats: u64 = std::env::var("LNURL_MAX_SATS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1_000_000);

    log::info!("deposits-lnurl starting");
    log::info!("  pubkey: {}", keys.public_key().to_bech32()?);
    log::info!("  domain: {}", domain);
    log::info!("  relays: {:?}", relay_urls);
    log::info!("  limits: {}-{} sats", min_sats, max_sats);
    log::info!(
        "  address format: <deposit_pubkey>@<bech32_ledger_id>.{}",
        domain
    );

    // Connect to relays
    #[allow(deprecated)]
    let opts = Options::default().connection_timeout(Some(std::time::Duration::from_secs(30)));
    let client = Client::builder().signer(keys.clone()).opts(opts).build();
    for url in &relay_urls {
        client.add_relay(url).await?;
    }
    client
        .connect_with_timeout(std::time::Duration::from_secs(10))
        .await;

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
        operator_keys: Mutex::new(HashMap::new()),
        pending_zaps: Mutex::new(HashMap::new()),
    });

    // Spawn response listener
    let listener_state = Arc::clone(&state);
    tokio::spawn(async move {
        listen_for_responses(listener_state).await;
    });

    // Build HTTP routes
    let app = Router::new()
        .route("/.well-known/lnurlp/:deposit_id", get(lnurlp_metadata))
        .route("/lnurl/callback/:deposit_id", get(lnurlp_callback))
        .with_state(state);

    log::info!("Listening on {}", listen);
    let listener = tokio::net::TcpListener::bind(&listen).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
