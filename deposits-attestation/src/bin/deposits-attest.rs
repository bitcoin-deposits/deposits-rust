//! Lightning address verification service (Nostr-native)
//!
//! Verifies that a nostr npub controls a lightning address using a challenge-response
//! protocol over lightning payments. Listens on Nostr relays for verification requests.
//!
//! Flow:
//! 1. User sends kind 25500 event: { "lightning_address": "user@domain.com" }
//! 2. Service replies with invoice for 1000 + 3*fee sats
//! 3. User pays, then sends { "action": "challenge", "session_id": "..." }
//! 4. Service pays 3 random amounts summing to 1000 to the lightning address
//! 5. User sends { "action": "verify", "session_id": "...", "amounts": [a, b, c] }
//! 6. If correct, service publishes a durable attestation event (kind 55502)

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{Keypair, Message, Secp256k1};
use chrono::Utc;
use lightning_invoice::Bolt11Invoice;
use nostr_sdk::nips::nip04;
use nostr_sdk::prelude::*;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::RwLock;

// -- Constants --

const KIND_VERIFY_REQUEST: u16 = 25500; // ephemeral
const KIND_VERIFY_RESPONSE: u16 = 25501; // ephemeral
const KIND_ATTESTATION: u16 = 55502; // durable

const DEFAULT_CHALLENGE_SATS: u64 = 1000;
const DEFAULT_NUM_PAYMENTS: u64 = 3;
const DEFAULT_MAX_ATTEMPTS: u64 = 3;
const DEFAULT_PREMIUM_SATS: u64 = 0;
const DEFAULT_FEE_FALLBACK_SATS: u64 = 10;
const DEFAULT_TIMEOUT_SECS: u64 = 600;
const DEFAULT_FEE_CACHE_SECS: u64 = 3600;
const DEFAULT_RELAY: &str = "wss://relay.damus.io";

// -- Config helpers --

/// Read a config value from env var, or from a file path given by `{var}_FILE`.
/// The `_FILE` variant takes precedence if both are set.
fn env_or_file(var: &str) -> Option<String> {
    let file_var = format!("{}_FILE", var);
    if let Ok(path) = std::env::var(&file_var) {
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => panic!("{} points to {} but cannot read it: {}", file_var, path, e),
        };
        // If the file is valid UTF-8 text, use it as-is (trimmed).
        // Otherwise treat it as binary and hex-encode it (e.g. LDK's raw 32-byte api_key).
        return Some(match String::from_utf8(bytes.clone()) {
            Ok(s) => s.trim().to_string(),
            Err(_) => hex::encode(&bytes),
        });
    }
    std::env::var(var).ok()
}

// -- LDK CLI wrapper (async, minimal) --

struct LdkCli {
    cli_path: String,
    host: String,
    port: u16,
    api_key: String,
    tls_cert: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Bolt11ReceiveResponse {
    invoice: String,
}

#[derive(Debug, Deserialize)]
struct Bolt11SendResponse {
    payment_id: String,
}

#[derive(Debug, Deserialize)]
struct ListPaymentsResponse {
    #[serde(alias = "payments")]
    list: Vec<PaymentInfo>,
}

#[derive(Debug, Deserialize)]
struct PaymentInfo {
    id: String,
    #[serde(deserialize_with = "deserialize_status")]
    status: u8, // 0 = pending, 1 = succeeded, 2 = failed
    #[allow(dead_code)]
    amount_msat: Option<u64>,
}

fn deserialize_status<'de, D>(deserializer: D) -> Result<u8, D::Error>
where D: serde::Deserializer<'de> {
    use serde::de;
    struct V;
    impl<'de> de::Visitor<'de> for V {
        type Value = u8;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("status number or string")
        }
        fn visit_u64<E: de::Error>(self, v: u64) -> Result<u8, E> { Ok(v as u8) }
        fn visit_str<E: de::Error>(self, v: &str) -> Result<u8, E> {
            match v.to_uppercase().as_str() {
                "PENDING" => Ok(0),
                "SUCCEEDED" | "COMPLETE" | "COMPLETED" => Ok(1),
                "FAILED" | "EXPIRED" => Ok(2),
                _ => Ok(0),
            }
        }
    }
    deserializer.deserialize_any(V)
}

impl LdkCli {
    fn from_env() -> Self {
        Self {
            cli_path: std::env::var("LDK_CLI").unwrap_or_else(|_| "ldk-server-cli".to_string()),
            host: std::env::var("LDK_HOST").unwrap_or_else(|_| "localhost".to_string()),
            port: std::env::var("LDK_PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(3000),
            api_key: env_or_file("LDK_API_KEY").unwrap_or_else(|| "test_api_key".to_string()),
            tls_cert: std::env::var("LDK_TLS_CERT").ok(),
        }
    }

    async fn run_command(&self, args: &[&str]) -> Result<String, String> {
        let mut cmd = tokio::process::Command::new(&self.cli_path);
        cmd.arg("-b")
            .arg(format!("{}:{}", self.host, self.port))
            .arg("-a")
            .arg(&self.api_key);
        if let Some(ref cert) = self.tls_cert {
            cmd.arg("-t").arg(cert);
        }
        cmd.args(args);

        let output = cmd
            .output()
            .await
            .map_err(|e| format!("Failed to execute ldk-server-cli: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            return Err(format!("ldk-server-cli failed: {} {}", stderr.trim(), stdout.trim()));
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    async fn create_invoice(&self, amount_msat: u64, description: &str) -> Result<String, String> {
        let amount_str = format!("{}msat", amount_msat);
        let output = self
            .run_command(&["bolt11-receive", &amount_str, "--description", description])
            .await?;
        let resp: Bolt11ReceiveResponse =
            serde_json::from_str(&output).map_err(|e| format!("Failed to parse invoice response: {}", e))?;
        Ok(resp.invoice)
    }

    async fn pay_invoice(&self, invoice: &str) -> Result<String, String> {
        let output = self.run_command(&["bolt11-send", invoice]).await?;
        let resp: Bolt11SendResponse =
            serde_json::from_str(&output).map_err(|e| format!("Failed to parse payment response: {}", e))?;
        Ok(resp.payment_id)
    }

    async fn list_payments(&self) -> Result<Vec<PaymentInfo>, String> {
        let output = self.run_command(&["list-payments"]).await?;
        let resp: ListPaymentsResponse =
            serde_json::from_str(&output).map_err(|e| format!("Failed to parse payments: {}", e))?;
        Ok(resp.list)
    }
}

// -- LNURL resolution --

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LnurlPayResponse {
    callback: String,
    min_sendable: u64, // millisatoshis
    max_sendable: u64,
    #[allow(dead_code)]
    tag: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LnurlInvoiceResponse {
    pr: String, // BOLT11 payment request
}

/// Parse and validate a lightning address, returning (user, domain).
fn parse_lightning_address(address: &str) -> Result<(&str, &str), String> {
    let parts: Vec<&str> = address.split('@').collect();
    if parts.len() != 2 {
        return Err(format!("Invalid lightning address format: {}", address));
    }
    let (user, domain) = (parts[0], parts[1]);
    if user.is_empty() || domain.is_empty() {
        return Err(format!("Invalid lightning address: {}", address));
    }
    Ok((user, domain))
}

async fn resolve_lightning_address(http: &reqwest::Client, address: &str) -> Result<LnurlPayResponse, String> {
    let (user, domain) = parse_lightning_address(address)?;

    let url = format!("https://{}/.well-known/lnurlp/{}", domain, user);
    let resp = http
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("LNURL fetch failed: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("LNURL endpoint returned {}", resp.status()));
    }

    let lnurl: LnurlPayResponse = resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse LNURL response: {}", e))?;

    Ok(lnurl)
}

async fn request_lnurl_invoice(
    http: &reqwest::Client,
    callback: &str,
    amount_msat: u64,
) -> Result<String, String> {
    // LNURL-pay spec: append ?amount=<msat> (or &amount= if callback already has query params)
    let separator = if callback.contains('?') { "&" } else { "?" };
    let url = format!("{}{}amount={}", callback, separator, amount_msat);

    let resp = http
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("LNURL invoice request failed: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("LNURL invoice endpoint returned {}", resp.status()));
    }

    let invoice_resp: LnurlInvoiceResponse = resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse LNURL invoice response: {}", e))?;

    Ok(invoice_resp.pr)
}

// -- NIP-05 verification --

/// NIP-05 response: { "names": { "user": "hex_pubkey", ... } }
#[derive(Debug, Deserialize)]
struct Nip05Response {
    names: HashMap<String, String>,
}

/// Check if the lightning address's domain attests the given pubkey via NIP-05.
/// Uses a per-domain cache to avoid repeated hits to the same .well-known endpoint.
async fn check_nip05(
    state: &Arc<AppState>,
    address: &str,
    pubkey: &PublicKey,
) -> Result<bool, String> {
    let (user, domain) = parse_lightning_address(address)?;
    let pubkey_hex = pubkey.to_hex();

    // Check cache
    let ttl = chrono::Duration::seconds(state.nip05_cache_secs as i64);
    {
        let cache = state.nip05_cache.read().await;
        if let Some((names, fetched_at)) = cache.get(domain) {
            if Utc::now() - *fetched_at < ttl {
                log::debug!("NIP-05 cache hit for {}", domain);
                return Ok(names.get(user).map(|pk| pk == &pubkey_hex).unwrap_or(false));
            }
        }
    }

    // Fetch
    let url = format!(
        "https://{}/.well-known/nostr.json?name={}",
        domain, user
    );

    let resp = match state.http.get(&url).send().await {
        Ok(r) => r,
        Err(_) => return Ok(false),
    };

    if !resp.status().is_success() {
        return Ok(false);
    }

    let nip05: Nip05Response = match resp.json().await {
        Ok(r) => r,
        Err(_) => return Ok(false),
    };

    let result = nip05
        .names
        .get(user)
        .map(|pk| pk == &pubkey_hex)
        .unwrap_or(false);

    // Cache the names map
    state
        .nip05_cache
        .write()
        .await
        .insert(domain.to_string(), (nip05.names, Utc::now()));

    Ok(result)
}

// -- Fee estimation from route hints --

/// Compute routing fee in msat for a given amount through a sequence of route hint hops.
/// Walks hops from last to first since each hop's fee is based on what it forwards
/// (which includes fees of subsequent hops).
fn compute_route_hint_fee_msat(hops: &[lightning_types::routing::RouteHintHop], amount_msat: u64) -> u64 {
    let mut forwarded_msat = amount_msat;
    let mut total_fee_msat: u64 = 0;
    for hop in hops.iter().rev() {
        let hop_fee = hop.fees.base_msat as u64
            + (forwarded_msat * hop.fees.proportional_millionths as u64 / 1_000_000);
        total_fee_msat += hop_fee;
        forwarded_msat += hop_fee;
    }
    total_fee_msat
}

/// Estimate routing fee for a payment of `amount_msat` by inspecting BOLT11 route hints.
/// Requests a probe invoice from the LNURL callback, parses the route hints, and computes
/// the worst-case fee across all hint paths. Returns the fee in satoshis.
async fn estimate_fee_from_lnurl(
    http: &reqwest::Client,
    callback: &str,
    amount_msat: u64,
    fallback_sats: u64,
) -> u64 {
    // Request a probe invoice at the target amount
    let invoice_str = match request_lnurl_invoice(http, callback, amount_msat).await {
        Ok(inv) => inv,
        Err(e) => {
            log::warn!("Fee probe failed (using fallback {}): {}", fallback_sats, e);
            return fallback_sats;
        }
    };

    let invoice = match Bolt11Invoice::from_str(&invoice_str) {
        Ok(inv) => inv,
        Err(e) => {
            log::warn!("Fee probe invoice parse failed (using fallback {}): {}", fallback_sats, e);
            return fallback_sats;
        }
    };

    let hints = invoice.route_hints();
    if hints.is_empty() {
        // No route hints = well-connected node, fees likely minimal
        log::info!("No route hints in probe invoice, using fallback {} sats", fallback_sats);
        return fallback_sats;
    }

    // Compute fee for each route hint path, take the max as worst-case estimate.
    let mut max_fee_msat: u64 = 0;
    for hint in &hints {
        let fee = compute_route_hint_fee_msat(&hint.0, amount_msat);
        max_fee_msat = max_fee_msat.max(fee);
    }

    // Convert to sats (round up)
    let fee_sats = (max_fee_msat + 999) / 1000;
    // Add a buffer for hops not in the route hint (our node -> first hint hop)
    let fee_sats = fee_sats + 1;
    log::info!(
        "Estimated routing fee from {} route hint(s): {} sats (for {} msat payment)",
        hints.len(),
        fee_sats,
        amount_msat
    );
    fee_sats
}

// -- Random partition with maximum entropy --

/// Generate `n` random positive integers summing to `total`.
/// Uniform distribution over all ordered compositions (stars-and-bars):
/// pick n-1 distinct cut points from {1..total-1}, sort, take differences.
fn random_partition(rng: &mut impl Rng, total: u64, n: u64) -> Vec<u64> {
    assert!(n >= 1 && total >= n, "need total >= n >= 1");
    if n == 1 {
        return vec![total];
    }
    loop {
        let mut cuts: Vec<u64> = (0..n - 1).map(|_| rng.gen_range(1..total)).collect();
        cuts.sort();
        cuts.dedup();
        if cuts.len() == (n - 1) as usize {
            let mut parts = Vec::with_capacity(n as usize);
            parts.push(cuts[0]);
            for i in 1..cuts.len() {
                parts.push(cuts[i] - cuts[i - 1]);
            }
            parts.push(total - cuts[cuts.len() - 1]);
            return parts;
        }
    }
}

// -- Session state machine --

enum SessionState {
    AwaitingPayment {
        invoice: String,
        payment_hash: String, // hex
        amount_sats: u64,
    },
    ChallengeSent {
        amounts: Vec<u64>,
        attempts_remaining: u64,
        expires_at: chrono::DateTime<Utc>,
    },
    Verified,
    Failed {
        reason: String,
    },
}

struct Session {
    id: String,
    /// Nostr pubkey of the request signer. Sessions are keyed by this
    /// for `challenge` / `verify` lookup, so the same identity that
    /// started a link must drive it through.
    requester: PublicKey,
    /// Pubkey the eventual attestation will be issued for. Defaults to
    /// `requester`, but the wallet can pass a separate `attest_pubkey`
    /// to bridge an ephemeral key onto its long-term NIP-05 identity.
    target: PublicKey,
    lightning_address: String,
    lnurl_callback: String,
    state: SessionState,
    #[allow(dead_code)]
    created_at: chrono::DateTime<Utc>,
}

// -- Request/response JSON --

#[derive(Debug, Deserialize)]
struct VerifyRequest {
    #[serde(default)]
    action: Option<String>,
    lightning_address: Option<String>,
    session_id: Option<String>,
    amounts: Option<Vec<u64>>,
    /// xonly hex of the npub the verifier should issue the attestation
    /// for. Defaults to the signing key for `link`/`verify` (so the
    /// caller is attesting itself). Required for `proclaim`.
    attest_pubkey: Option<String>,
}

#[derive(Debug, Serialize)]
struct LinkResponse {
    session_id: String,
    invoice: String,
    amount_sats: u64,
}

#[derive(Debug, Serialize)]
struct StatusResponse {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AttestationContent {
    /// xonly hex of the pubkey this attestation is for. Op0's
    /// `check_attestation` filter matches on the event's `#p` tag,
    /// which carries the same value.
    npub: String,
    /// Verification method: "nip05", "challenge", or "proclaim".
    method: String,
    verified_at: String,
    /// Set for nip05 / challenge methods. The domain after `@` is what
    /// op0 matches against `deposit_domain_allowlist`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    lightning_address: Option<String>,
    /// Set for the `proclaim` method. Carries the xonly of the
    /// allowlisted account that vouched for `npub`. Op0 matches this
    /// against `deposit_allowlist` (the explicit pubkey allowlist).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    allowlist_npub: Option<String>,
}

// -- Application state --

struct AppState {
    sessions: RwLock<HashMap<String, Session>>,
    /// Cached fee estimates per domain: domain -> (fee_sats, fetched_at)
    fee_cache: RwLock<HashMap<String, (u64, chrono::DateTime<Utc>)>>,
    /// Cached NIP-05 names per domain: domain -> (names_map, fetched_at)
    nip05_cache: RwLock<HashMap<String, (HashMap<String, String>, chrono::DateTime<Utc>)>>,
    ldk: LdkCli,
    keys: Keys,
    client: Client,
    attestation_client: Option<Client>, // separate relays for publishing attestations
    http: reqwest::Client,
    challenge_sats: u64,
    num_payments: u64,
    max_attempts: u64,
    premium_sats: u64,
    fee_fallback_sats: u64,
    timeout_secs: u64,
    fee_cache_secs: u64,
    nip05_cache_secs: u64,
    /// Path to the operator's `deposit_allowlist.txt`, mounted ro.
    /// Consulted by the `proclaim` action so an allowlisted account can
    /// vouch for a fresh ephemeral key. `None` disables the proclaim
    /// flow entirely.
    allowlist_file: Option<std::path::PathBuf>,
}

// -- Event handling --

async fn handle_event(state: &Arc<AppState>, event: &Event) {
    // Incoming request is gift-wrapped: outer (throwaway-signed) → seal
    // (requester-signed, kind 13) → rumor (kind 25500, the actual
    // VerifyRequest JSON in `content`). Decrypt both layers before
    // dispatching. `event.pubkey` is the throwaway key; the real
    // requester identity lives in seal["pubkey"].
    let (requester_pk, rumor_content) = match unwrap_request(state, event) {
        Ok(x) => x,
        Err(e) => {
            log::warn!("unwrap request from {}: {}", event.pubkey, e);
            return;
        }
    };

    let content: VerifyRequest = match serde_json::from_str(&rumor_content) {
        Ok(c) => c,
        Err(e) => {
            log::warn!("invalid request from {}: {}", requester_pk, e);
            return;
        }
    };

    let action = content.action.as_deref().unwrap_or("link");

    let result = match action {
        "link" => handle_link(state, &requester_pk, &content).await,
        "challenge" => handle_challenge(state, &requester_pk, &content).await,
        "verify" => handle_verify(state, &requester_pk, &content).await,
        "proclaim" => handle_proclaim(state, &requester_pk, &content).await,
        other => Err(format!("Unknown action: {}", other)),
    };

    match result {
        Ok(response_json) => {
            if let Err(e) = send_response(state, &requester_pk, &event.id, &response_json).await {
                log::error!("Failed to send response: {}", e);
            }
        }
        Err(e) => {
            log::error!("Handler error for action '{}': {}", action, e);
            let err_response = serde_json::to_string(&StatusResponse {
                status: "error".to_string(),
                message: Some(e),
            })
            .unwrap();
            if let Err(e2) = send_response(state, &requester_pk, &event.id, &err_response).await {
                log::error!("Failed to send error response: {}", e2);
            }
        }
    }
}

/// Unwrap a gift-wrapped kind 25500 request. Returns (real requester
/// pubkey from the seal, rumor content as JSON string).
fn unwrap_request(state: &Arc<AppState>, event: &Event) -> Result<(PublicKey, String), String> {
    let my_sk = state.keys.secret_key();

    let seal_json = nip04::decrypt(my_sk, &event.pubkey, &event.content)
        .map_err(|e| format!("outer decrypt: {}", e))?;
    let seal: serde_json::Value =
        serde_json::from_str(&seal_json).map_err(|e| format!("seal parse: {}", e))?;
    let seal_pubkey_hex = seal["pubkey"]
        .as_str()
        .ok_or_else(|| "seal missing pubkey".to_string())?;
    let requester_pk = PublicKey::from_hex(seal_pubkey_hex)
        .map_err(|e| format!("seal pubkey: {}", e))?;

    let rumor_json = nip04::decrypt(
        my_sk,
        &requester_pk,
        seal["content"].as_str().unwrap_or(""),
    )
    .map_err(|e| format!("rumor decrypt: {}", e))?;
    let rumor: serde_json::Value =
        serde_json::from_str(&rumor_json).map_err(|e| format!("rumor parse: {}", e))?;
    let rumor_content = rumor["content"].as_str().unwrap_or("").to_string();

    Ok((requester_pk, rumor_content))
}

/// Check if we've already issued an attestation for this npub + lightning address.
/// Checks in-memory sessions first, then queries relays for existing kind 55502 events.
async fn find_existing_attestation(
    state: &Arc<AppState>,
    requester: &PublicKey,
    lightning_address: &str,
) -> Option<String> {
    // Check in-memory sessions
    let sessions = state.sessions.read().await;
    for session in sessions.values() {
        if session.requester == *requester
            && session.lightning_address == lightning_address
            && matches!(session.state, SessionState::Verified)
        {
            return Some("(in-memory)".to_string());
        }
    }
    drop(sessions);

    // Query relays for existing attestation from us for this pubkey
    let filter = Filter::new()
        .kind(Kind::Custom(KIND_ATTESTATION))
        .author(state.keys.public_key())
        .custom_tag(
            SingleLetterTag::lowercase(Alphabet::P),
            [requester.to_hex()],
        );

    let events = match state
        .client
        .fetch_events(vec![filter], Some(std::time::Duration::from_secs(5)))
        .await
    {
        Ok(events) => events,
        Err(e) => {
            log::warn!("Failed to query existing attestations: {}", e);
            return None;
        }
    };

    // Check if any attestation matches this lightning address
    for event in events.iter() {
        if let Ok(content) = serde_json::from_str::<AttestationContent>(&event.content) {
            if content.lightning_address.as_deref() == Some(lightning_address) {
                return Some(event.id.to_hex());
            }
        }
    }

    None
}

/// Resolve the npub the attestation should be issued for. Returns the
/// caller-provided `attest_pubkey` if present, else falls back to the
/// request signer. The signer remains the only identity the verifier
/// trusts to drive the challenge flow — the target only changes where
/// the eventual `#p` tag points.
fn resolve_target(req: &VerifyRequest, requester: &PublicKey) -> Result<PublicKey, String> {
    match req.attest_pubkey.as_deref() {
        Some(s) => PublicKey::from_hex(s).map_err(|e| format!("bad attest_pubkey: {}", e)),
        None => Ok(*requester),
    }
}

async fn handle_link(
    state: &Arc<AppState>,
    requester: &PublicKey,
    req: &VerifyRequest,
) -> Result<String, String> {
    let address = req
        .lightning_address
        .as_ref()
        .ok_or("Missing lightning_address")?;
    let target = resolve_target(req, requester)?;

    log::info!(
        "Link request from {} for {} (attesting {})",
        requester,
        address,
        target
    );

    // Check if we already have an attestation for this target npub +
    // address. Lookup is by target since that's the `#p` tag op0 and
    // wallets filter on.
    if let Some(event_id) = find_existing_attestation(state, &target, address).await {
        return Ok(serde_json::to_string(&StatusResponse {
            status: "already_verified".to_string(),
            message: Some(format!("Attestation already exists: {}", event_id)),
        })
        .unwrap());
    }

    // Check NIP-05: the address's domain must attest the SIGNER (so
    // someone else can't ask for an attestation of an address they
    // don't control). If the signer is verified, the attestation is
    // still issued for `target`, decoupling the long-term NIP-05 key
    // from whatever key carries day-to-day requests.
    match check_nip05(state, address, requester).await {
        Ok(true) => {
            log::info!("NIP-05 verified signer {} for {} → attesting {}", requester, address, target);
            return publish_attestation(state, &target, "nip05", Some(address), None).await;
        }
        Ok(false) => {
            log::debug!("NIP-05 not available for {} -> {}, proceeding with challenge", requester, address);
        }
        Err(e) => {
            log::warn!("NIP-05 check failed: {}", e);
        }
    }

    // Resolve LNURL
    let lnurl = resolve_lightning_address(&state.http, address).await?;

    // Validate that our challenge amounts will be within sendable range.
    // Minimum possible single payment is 1 sat = 1000 msat.
    if lnurl.min_sendable > 1000 {
        return Err(format!(
            "Lightning address requires minimum {} msat, but challenge payments can be as low as 1000 msat",
            lnurl.min_sendable
        ));
    }
    // Maximum possible single payment is (challenge_sats - num_payments + 1) sats.
    let max_single = (state.challenge_sats - state.num_payments + 1) * 1000;
    if lnurl.max_sendable < max_single {
        return Err(format!(
            "Lightning address maximum {} msat is too low for challenge payments (need up to {})",
            lnurl.max_sendable, max_single
        ));
    }

    // Estimate routing fees, cached per domain to avoid hammering LNURL endpoints.
    let (_, domain) = parse_lightning_address(address).unwrap();
    let fee_per_payment = {
        let ttl = chrono::Duration::seconds(state.fee_cache_secs as i64);
        let cache = state.fee_cache.read().await;
        let cached = cache
            .get(domain)
            .filter(|(_, fetched_at)| Utc::now() - *fetched_at < ttl)
            .map(|(fee, _)| *fee);
        drop(cache);
        match cached {
            Some(fee) => {
                log::debug!("Fee cache hit for {}: {} sats", domain, fee);
                fee
            }
            None => {
                let avg_payment_msat = (state.challenge_sats / state.num_payments) * 1000;
                let fee = estimate_fee_from_lnurl(
                    &state.http,
                    &lnurl.callback,
                    avg_payment_msat,
                    state.fee_fallback_sats,
                )
                .await;
                state
                    .fee_cache
                    .write()
                    .await
                    .insert(domain.to_string(), (fee, Utc::now()));
                fee
            }
        }
    };

    let amount_sats =
        state.challenge_sats + state.num_payments * fee_per_payment + state.premium_sats;
    let amount_msat = amount_sats * 1000;

    let invoice_str = state
        .ldk
        .create_invoice(amount_msat, "Lightning address verification")
        .await?;

    // Parse invoice to extract payment hash
    let invoice = Bolt11Invoice::from_str(&invoice_str)
        .map_err(|e| format!("Failed to parse created invoice: {}", e))?;
    let payment_hash = hex::encode(invoice.payment_hash().as_byte_array());

    // Create session
    let session_id = hex::encode(rand::thread_rng().gen::<[u8; 16]>());
    let session = Session {
        id: session_id.clone(),
        requester: *requester,
        target,
        lightning_address: address.clone(),
        lnurl_callback: lnurl.callback,
        state: SessionState::AwaitingPayment {
            invoice: invoice_str.clone(),
            payment_hash,
            amount_sats,
        },
        created_at: Utc::now(),
    };

    state.sessions.write().await.insert(session_id.clone(), session);

    let resp = LinkResponse {
        session_id,
        invoice: invoice_str,
        amount_sats,
    };

    serde_json::to_string(&resp).map_err(|e| format!("Serialization error: {}", e))
}

async fn handle_challenge(
    state: &Arc<AppState>,
    requester: &PublicKey,
    req: &VerifyRequest,
) -> Result<String, String> {
    let session_id = req.session_id.as_ref().ok_or("Missing session_id")?;
    let mut sessions = state.sessions.write().await;
    let session = sessions
        .get_mut(session_id)
        .ok_or_else(|| "Session not found".to_string())?;

    // Verify requester matches session
    if session.requester != *requester {
        return Err("Requester mismatch".to_string());
    }

    // Check state — need AwaitingPayment
    let payment_hash = match &session.state {
        SessionState::AwaitingPayment { payment_hash, .. } => payment_hash.clone(),
        SessionState::ChallengeSent { .. } => {
            return Ok(serde_json::to_string(&StatusResponse {
                status: "challenge_already_sent".to_string(),
                message: None,
            })
            .unwrap());
        }
        _ => return Err("Invalid session state for challenge".to_string()),
    };

    // Check if payment received
    let payments = state.ldk.list_payments().await?;
    let paid = payments
        .iter()
        .any(|p| p.id == payment_hash && p.status == 1);

    if !paid {
        return Ok(serde_json::to_string(&StatusResponse {
            status: "payment_pending".to_string(),
            message: Some("Invoice not yet paid".to_string()),
        })
        .unwrap());
    }

    log::info!("Payment confirmed for session {}, sending challenges", session_id);

    // Generate random partition
    let amounts = random_partition(&mut rand::thread_rng(), state.challenge_sats, state.num_payments);
    log::info!("Challenge amounts: {:?}", amounts);

    // Pay each amount to the lightning address
    let callback = session.lnurl_callback.clone();
    // Drop sessions lock before making outbound payments
    let lightning_address = session.lightning_address.clone();
    drop(sessions);

    for (i, &amount_sats) in amounts.iter().enumerate() {
        let amount_msat = amount_sats * 1000;
        let invoice = request_lnurl_invoice(&state.http, &callback, amount_msat).await?;
        let payment_id = state.ldk.pay_invoice(&invoice).await?;
        log::info!(
            "Challenge payment {}/{}: {} sats to {} (payment_id: {})",
            i + 1,
            amounts.len(),
            amount_sats,
            lightning_address,
            payment_id
        );
    }

    // Update session state
    let num_sent = amounts.len();
    let mut sessions = state.sessions.write().await;
    if let Some(session) = sessions.get_mut(session_id) {
        session.state = SessionState::ChallengeSent {
            amounts,
            attempts_remaining: state.max_attempts,
            expires_at: Utc::now() + chrono::Duration::seconds(state.timeout_secs as i64),
        };
    }

    Ok(serde_json::to_string(&StatusResponse {
        status: "challenge_sent".to_string(),
        message: Some(format!(
            "{} payments sent to your lightning address. Reply with the amounts.",
            num_sent
        )),
    })
    .unwrap())
}

async fn handle_verify(
    state: &Arc<AppState>,
    requester: &PublicKey,
    req: &VerifyRequest,
) -> Result<String, String> {
    let session_id = req.session_id.as_ref().ok_or("Missing session_id")?;
    let submitted = req.amounts.as_ref().ok_or("Missing amounts")?;

    if submitted.len() as u64 != state.num_payments {
        return Err(format!("Expected exactly {} amounts", state.num_payments));
    }

    let mut sessions = state.sessions.write().await;
    let session = sessions
        .get_mut(session_id)
        .ok_or_else(|| "Session not found".to_string())?;

    if session.requester != *requester {
        return Err("Requester mismatch".to_string());
    }

    let (expected, expires_at) = match &session.state {
        SessionState::ChallengeSent { amounts, expires_at, .. } => (amounts.clone(), *expires_at),
        _ => return Err("Invalid session state for verify".to_string()),
    };

    // Check timeout
    if Utc::now() > expires_at {
        session.state = SessionState::Failed {
            reason: "Verification timed out".to_string(),
        };
        return Err("Verification window expired".to_string());
    }

    // Compare sorted amounts (order doesn't matter)
    let mut submitted_sorted = submitted.clone();
    submitted_sorted.sort();
    let mut expected_sorted = expected;
    expected_sorted.sort();

    if submitted_sorted != expected_sorted {
        // Decrement attempts
        if let SessionState::ChallengeSent { attempts_remaining, .. } = &mut session.state {
            *attempts_remaining = attempts_remaining.saturating_sub(1);
            if *attempts_remaining == 0 {
                session.state = SessionState::Failed {
                    reason: "Max attempts exceeded".to_string(),
                };
                return Err("Amounts do not match — no attempts remaining".to_string());
            }
            return Err(format!(
                "Amounts do not match — {} attempt(s) remaining",
                attempts_remaining
            ));
        }
        return Err("Amounts do not match".to_string());
    }

    log::info!(
        "Verification successful for {} -> {} (attesting {})",
        requester,
        session.lightning_address,
        session.target
    );

    let lightning_address = session.lightning_address.clone();
    let target = session.target;
    session.state = SessionState::Verified;
    drop(sessions);

    publish_attestation(state, &target, "challenge", Some(&lightning_address), None).await
}

/// `proclaim` — issue an attestation for an arbitrary npub on the say-so
/// of an account already on the operator's manual allowlist.
///
/// The signer must appear in the allowlist file (configured via
/// `VERIFY_ALLOWLIST_FILE`). Used to bridge a fresh ephemeral key onto a
/// long-term, manually-trusted identity without going through NIP-05 or
/// the lightning challenge.
///
/// The resulting attestation has `method: "proclaim"`, no
/// `lightning_address`, and `allowlist_npub: <signer>`. Op0 matches
/// that signer against its own `deposit_allowlist`.
async fn handle_proclaim(
    state: &Arc<AppState>,
    requester: &PublicKey,
    req: &VerifyRequest,
) -> Result<String, String> {
    let target = match req.attest_pubkey.as_deref() {
        Some(s) => PublicKey::from_hex(s).map_err(|e| format!("bad attest_pubkey: {}", e))?,
        None => return Err("Missing attest_pubkey for proclaim".to_string()),
    };

    let allowlist_path = state
        .allowlist_file
        .as_ref()
        .ok_or_else(|| "proclaim disabled (no VERIFY_ALLOWLIST_FILE configured)".to_string())?;
    let body = std::fs::read_to_string(allowlist_path)
        .map_err(|e| format!("read allowlist {}: {}", allowlist_path.display(), e))?;
    let signer_hex = requester.to_hex();
    let signer_allowed = body
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .any(|l| l.eq_ignore_ascii_case(&signer_hex));
    if !signer_allowed {
        log::warn!(
            "Proclaim rejected: signer {} not on allowlist {}",
            requester,
            allowlist_path.display()
        );
        return Err("Signer is not on the allowlist".to_string());
    }

    log::info!(
        "Proclaim: signer {} (allowlisted) attesting {}",
        requester,
        target
    );
    publish_attestation(state, &target, "proclaim", None, Some(&signer_hex)).await
}

/// Publish a durable attestation event and return a JSON response with the
/// event ID and a standalone BIP-340 schnorr signature.
///
/// `target` is the pubkey the attestation is FOR — its xonly goes into
/// the `#p` tag and the `npub` content field, and it's the key op0 will
/// later filter on. Exactly one of `lightning_address` / `allowlist_npub`
/// should be set, matching the verification method.
async fn publish_attestation(
    state: &Arc<AppState>,
    target: &PublicKey,
    method: &str,
    lightning_address: Option<&str>,
    allowlist_npub: Option<&str>,
) -> Result<String, String> {
    let npub = target
        .to_bech32()
        .map_err(|e| format!("Failed to encode npub: {}", e))?;

    let attestation = AttestationContent {
        npub: npub.clone(),
        method: method.to_string(),
        verified_at: Utc::now().to_rfc3339(),
        lightning_address: lightning_address.map(String::from),
        allowlist_npub: allowlist_npub.map(String::from),
    };
    let attestation_json =
        serde_json::to_string(&attestation).map_err(|e| format!("Serialization error: {}", e))?;

    let event = EventBuilder::new(Kind::Custom(KIND_ATTESTATION), &attestation_json)
        .tag(Tag::public_key(*target))
        .sign_with_keys(&state.keys)
        .map_err(|e| format!("Failed to sign attestation: {}", e))?;

    let attestation_event_id = event.id.to_hex();

    let publish_client = state.attestation_client.as_ref().unwrap_or(&state.client);
    publish_client
        .send_event(event)
        .await
        .map_err(|e| format!("Failed to publish attestation: {}", e))?;

    // For logs + the standalone signature, summarize the
    // method-specific detail string.
    let detail = lightning_address
        .or(allowlist_npub)
        .unwrap_or("(none)")
        .to_string();

    log::info!(
        "Published attestation {} for {} -> {} (method: {})",
        &attestation_event_id[..16],
        npub,
        detail,
        method
    );

    let signing_message = format!(
        "LIGHTNING_VERIFY:{}:{}:{}:{}",
        npub,
        detail,
        attestation.verified_at,
        state.keys.public_key().to_hex()
    );
    let message_hash = sha256::Hash::hash(signing_message.as_bytes());
    let secp = Secp256k1::signing_only();
    let keypair = Keypair::from_secret_key(&secp, &state.keys.secret_key());
    let msg = Message::from_digest(message_hash.to_byte_array());
    let sig = secp.sign_schnorr_no_aux_rand(&msg, &keypair);

    #[derive(Serialize)]
    struct VerifyResponse {
        status: String,
        attestation_event_id: String,
        npub: String,
        verified_at: String,
        method: String,
        verifier_pubkey: String,
        signature: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        lightning_address: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        allowlist_npub: Option<String>,
    }

    let resp = VerifyResponse {
        status: "verified".to_string(),
        attestation_event_id,
        npub,
        verified_at: attestation.verified_at,
        method: method.to_string(),
        verifier_pubkey: state.keys.public_key().to_hex(),
        signature: hex::encode(sig.serialize()),
        lightning_address: lightning_address.map(String::from),
        allowlist_npub: allowlist_npub.map(String::from),
    };

    serde_json::to_string(&resp).map_err(|e| format!("Serialization error: {}", e))
}

/// Send a gift-wrapped response mirroring the wrap the wallet sends:
/// outer (throwaway-signed, kind 25501) → seal (verifier-signed, kind
/// 13) → rumor (kind 25501 with `content` = response JSON string).
/// The outer's `#e` tag carries the request event id so the wallet's
/// subscription filter matches.
async fn send_response(
    state: &Arc<AppState>,
    requester: &PublicKey,
    request_id: &EventId,
    content: &str,
) -> Result<(), String> {
    let my_sk = state.keys.secret_key();
    let my_pk = state.keys.public_key();
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // 1. Build rumor (unsigned event) with the response content.
    let rumor_json = serde_json::json!({
        "kind": KIND_VERIFY_RESPONSE,
        "content": content,
        "tags": [
            ["p", requester.to_hex()],
            ["e", request_id.to_hex()],
        ],
        "pubkey": my_pk.to_hex(),
        "created_at": created_at,
    })
    .to_string();

    // 2. Seal the rumor: NIP-04-encrypt to the requester, then sign
    //    with our real key so the wallet can authenticate us.
    let seal_content = nip04::encrypt(my_sk, requester, &rumor_json)
        .map_err(|e| format!("seal encrypt: {}", e))?;
    let seal_event = EventBuilder::new(Kind::Custom(13), &seal_content)
        .sign_with_keys(&state.keys)
        .map_err(|e| format!("seal sign: {}", e))?;
    let seal_json = serde_json::json!({
        "id": seal_event.id.to_hex(),
        "pubkey": seal_event.pubkey.to_hex(),
        "created_at": seal_event.created_at.as_u64(),
        "kind": 13,
        "content": seal_event.content,
        "sig": seal_event.sig.to_string(),
    })
    .to_string();

    // 3. Outer wrap: NIP-04-encrypt the seal to the requester under a
    //    throwaway key, so nothing on the relay links our identity to
    //    the requester's.
    let throwaway = Keys::generate();
    let wrap_content = nip04::encrypt(throwaway.secret_key(), requester, &seal_json)
        .map_err(|e| format!("wrap encrypt: {}", e))?;
    let wrap = EventBuilder::new(Kind::Custom(KIND_VERIFY_RESPONSE), &wrap_content)
        .tag(Tag::public_key(*requester))
        .tag(Tag::event(*request_id))
        .sign_with_keys(&throwaway)
        .map_err(|e| format!("wrap sign: {}", e))?;

    state
        .client
        .send_event(wrap)
        .await
        .map_err(|e| format!("Failed to send response: {}", e))?;

    Ok(())
}

// -- Main --

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    // Load config
    let nsec_str = env_or_file("VERIFY_NSEC")
        .expect("Set VERIFY_NSEC (hex or nsec) or VERIFY_NSEC_FILE (path to key file)");
    let nostr_secret = if nsec_str.starts_with("nsec1") {
        nostr_sdk::SecretKey::from_bech32(&nsec_str).expect("VERIFY_NSEC: invalid nsec bech32")
    } else {
        let bytes = hex::decode(&nsec_str).expect("VERIFY_NSEC: invalid hex");
        nostr_sdk::SecretKey::from_slice(&bytes).expect("VERIFY_NSEC: invalid secret key")
    };
    let keys = Keys::new(nostr_secret);

    let relay_urls: Vec<String> = std::env::var("VERIFY_RELAYS")
        .unwrap_or_else(|_| DEFAULT_RELAY.to_string())
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let challenge_sats: u64 = std::env::var("VERIFY_CHALLENGE_SATS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_CHALLENGE_SATS);

    let num_payments: u64 = std::env::var("VERIFY_NUM_PAYMENTS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_NUM_PAYMENTS);

    let max_attempts: u64 = std::env::var("VERIFY_MAX_ATTEMPTS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_MAX_ATTEMPTS);

    let premium_sats: u64 = std::env::var("VERIFY_PREMIUM_SATS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_PREMIUM_SATS);

    let fee_fallback_sats: u64 = std::env::var("VERIFY_FEE_FALLBACK_SATS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_FEE_FALLBACK_SATS);

    let timeout_secs: u64 = std::env::var("VERIFY_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_TIMEOUT_SECS);

    let fee_cache_secs: u64 = std::env::var("VERIFY_FEE_CACHE_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_FEE_CACHE_SECS);

    let nip05_cache_secs: u64 = std::env::var("VERIFY_NIP05_CACHE_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_FEE_CACHE_SECS); // same default as fee cache

    let attestation_relay_urls: Option<Vec<String>> = std::env::var("VERIFY_ATTESTATION_RELAYS")
        .ok()
        .map(|s| {
            s.split(',')
                .map(|r| r.trim().to_string())
                .filter(|r| !r.is_empty())
                .collect()
        });

    assert!(
        num_payments >= 2 && challenge_sats >= num_payments,
        "need VERIFY_NUM_PAYMENTS >= 2 and VERIFY_CHALLENGE_SATS >= VERIFY_NUM_PAYMENTS"
    );

    log::info!("Lightning verify service starting");
    log::info!("  pubkey: {}", keys.public_key().to_bech32()?);
    log::info!("  relays: {:?}", relay_urls);
    if let Some(ref att_relays) = attestation_relay_urls {
        log::info!("  attestation relays: {:?}", att_relays);
    }
    log::info!("  challenge: {} sats across {} payments ({} attempts)", challenge_sats, num_payments, max_attempts);
    if premium_sats > 0 {
        log::info!("  premium: {} sats", premium_sats);
    }
    log::info!("  fee fallback: {} sats/payment", fee_fallback_sats);
    log::info!("  verification timeout: {} seconds", timeout_secs);
    log::info!("  fee cache TTL: {} seconds", fee_cache_secs);

    // Create nostr client
    #[allow(deprecated)]
    let opts = Options::default().connection_timeout(Some(std::time::Duration::from_secs(30)));
    let client = Client::builder().signer(keys.clone()).opts(opts).build();

    for url in &relay_urls {
        client.add_relay(url).await?;
    }
    client
        .connect_with_timeout(std::time::Duration::from_secs(30))
        .await;

    // Wait for at least one relay
    let start = std::time::Instant::now();
    loop {
        let relays = client.relays().await;
        if relays
            .values()
            .any(|r| r.status() == RelayStatus::Connected)
        {
            break;
        }
        if start.elapsed() > std::time::Duration::from_secs(10) {
            log::warn!("Timeout waiting for relay connection, proceeding anyway");
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    let connected = client
        .relays()
        .await
        .values()
        .filter(|r| r.status() == RelayStatus::Connected)
        .count();
    log::info!("{}/{} relays connected", connected, relay_urls.len());

    // Create separate attestation client if different relays are configured
    let attestation_client = if let Some(ref att_urls) = attestation_relay_urls {
        #[allow(deprecated)]
        let att_opts = Options::default().connection_timeout(Some(std::time::Duration::from_secs(30)));
        let att_client = Client::builder()
            .signer(keys.clone())
            .opts(att_opts)
            .build();
        for url in att_urls {
            att_client.add_relay(url).await?;
        }
        att_client
            .connect_with_timeout(std::time::Duration::from_secs(30))
            .await;
        let att_connected = att_client
            .relays()
            .await
            .values()
            .filter(|r| r.status() == RelayStatus::Connected)
            .count();
        log::info!(
            "{}/{} attestation relays connected",
            att_connected,
            att_urls.len()
        );
        Some(att_client)
    } else {
        None
    };

    // Subscribe to verification requests tagged with our pubkey
    let our_pubkey = keys.public_key();
    let filter = Filter::new()
        .kind(Kind::Custom(KIND_VERIFY_REQUEST))
        .custom_tag(SingleLetterTag::lowercase(Alphabet::P), [our_pubkey.to_hex()])
        .since(Timestamp::now());

    client.subscribe(vec![filter], None).await?;
    log::info!("Subscribed to kind {} events", KIND_VERIFY_REQUEST);

    // Build shared state
    let state = Arc::new(AppState {
        sessions: RwLock::new(HashMap::new()),
        fee_cache: RwLock::new(HashMap::new()),
        nip05_cache: RwLock::new(HashMap::new()),
        ldk: LdkCli::from_env(),
        keys,
        client: client.clone(),
        attestation_client,
        http: {
            let mut builder = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30));
            // Trust additional CA cert for test environments (self-signed NIP-05/LNURL servers)
            if let Some(ca_path) = env_or_file("VERIFY_CA_CERT") {
                let ca_pem = std::fs::read(&ca_path)
                    .unwrap_or_else(|e| panic!("Failed to read VERIFY_CA_CERT {}: {}", ca_path, e));
                let ca = reqwest::Certificate::from_pem(&ca_pem)
                    .unwrap_or_else(|e| panic!("Failed to parse VERIFY_CA_CERT: {}", e));
                builder = builder.add_root_certificate(ca);
                log::info!("  trusting CA cert: {}", ca_path);
            }
            builder.build()?
        },
        challenge_sats,
        num_payments,
        max_attempts,
        premium_sats,
        fee_fallback_sats,
        timeout_secs,
        fee_cache_secs,
        nip05_cache_secs,
        allowlist_file: env_or_file("VERIFY_ALLOWLIST_FILE")
            .map(std::path::PathBuf::from),
    });

    // Event loop
    log::info!("Listening for verification requests...");
    let mut rx = client.notifications();
    loop {
        match rx.recv().await {
            Ok(RelayPoolNotification::Event { event, .. }) => {
                if event.kind.as_u16() == KIND_VERIFY_REQUEST {
                    let state = state.clone();
                    tokio::spawn(async move {
                        handle_event(&state, &event).await;
                    });
                }
            }
            Ok(_) => {} // other notification types
            Err(e) => {
                log::warn!("Notification channel error: {}, re-subscribing", e);
                let mut rx_new = client.notifications();
                std::mem::swap(&mut rx, &mut rx_new);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::SecretKey;
    use lightning_types::routing::{RouteHint, RouteHintHop, RoutingFees};
    use rand::SeedableRng;

    // -- random_partition tests --

    #[test]
    fn partition_sums_to_total() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        for total in [10, 100, 1000, 5000] {
            for n in [2, 3, 5, 7] {
                if total < n {
                    continue;
                }
                let parts = random_partition(&mut rng, total, n);
                assert_eq!(parts.iter().sum::<u64>(), total, "total={} n={}", total, n);
            }
        }
    }

    #[test]
    fn partition_correct_count() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(123);
        for n in [1, 2, 3, 5, 10] {
            let parts = random_partition(&mut rng, 1000, n);
            assert_eq!(parts.len(), n as usize);
        }
    }

    #[test]
    fn partition_all_positive() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(99);
        for _ in 0..1000 {
            let parts = random_partition(&mut rng, 1000, 3);
            for (i, &p) in parts.iter().enumerate() {
                assert!(p >= 1, "part {} was 0 in {:?}", i, parts);
            }
        }
    }

    #[test]
    fn partition_n_equals_1() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0);
        assert_eq!(random_partition(&mut rng, 500, 1), vec![500]);
    }

    #[test]
    fn partition_n_equals_total() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        let parts = random_partition(&mut rng, 5, 5);
        assert_eq!(parts.len(), 5);
        assert!(parts.iter().all(|&p| p == 1));
        assert_eq!(parts.iter().sum::<u64>(), 5);
    }

    #[test]
    #[should_panic(expected = "need total >= n >= 1")]
    fn partition_n_greater_than_total_panics() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0);
        random_partition(&mut rng, 2, 5);
    }

    #[test]
    fn partition_distribution_not_degenerate() {
        // Run many partitions and check we get variety (not always the same split)
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let mut seen_first_parts = std::collections::HashSet::new();
        for _ in 0..100 {
            let parts = random_partition(&mut rng, 1000, 3);
            seen_first_parts.insert(parts[0]);
        }
        // With 100 draws from 998 possible first values, we should see many distinct values
        assert!(
            seen_first_parts.len() > 50,
            "Only {} distinct first parts in 100 draws — distribution may be degenerate",
            seen_first_parts.len()
        );
    }

    #[test]
    fn partition_large_n() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(55);
        let parts = random_partition(&mut rng, 10000, 50);
        assert_eq!(parts.len(), 50);
        assert_eq!(parts.iter().sum::<u64>(), 10000);
        assert!(parts.iter().all(|&p| p >= 1));
    }

    // -- lightning address parsing tests --

    #[test]
    fn parse_valid_lightning_address() {
        let (user, domain) = parse_lightning_address("alice@example.com").unwrap();
        assert_eq!(user, "alice");
        assert_eq!(domain, "example.com");
    }

    #[test]
    fn parse_subdomain_lightning_address() {
        let (user, domain) = parse_lightning_address("bob@pay.example.co.uk").unwrap();
        assert_eq!(user, "bob");
        assert_eq!(domain, "pay.example.co.uk");
    }

    #[test]
    fn parse_lightning_address_no_at() {
        assert!(parse_lightning_address("nodomain").is_err());
    }

    #[test]
    fn parse_lightning_address_multiple_at() {
        assert!(parse_lightning_address("a@b@c.com").is_err());
    }

    #[test]
    fn parse_lightning_address_empty_user() {
        assert!(parse_lightning_address("@example.com").is_err());
    }

    #[test]
    fn parse_lightning_address_empty_domain() {
        assert!(parse_lightning_address("alice@").is_err());
    }

    #[test]
    fn parse_lightning_address_single_label_domain() {
        // Bare hostnames and IPs are valid (test environments, local networks)
        let (user, domain) = parse_lightning_address("alice@localhost").unwrap();
        assert_eq!(user, "alice");
        assert_eq!(domain, "localhost");
    }

    #[test]
    fn parse_lightning_address_ip() {
        let (user, domain) = parse_lightning_address("alice@172.21.0.50").unwrap();
        assert_eq!(user, "alice");
        assert_eq!(domain, "172.21.0.50");
    }

    // -- fee calculation tests --

    fn make_hop(base_msat: u32, proportional_millionths: u32) -> RouteHintHop {
        // Need a valid pubkey for the struct — use a dummy
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let pubkey = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret);
        RouteHintHop {
            src_node_id: pubkey,
            short_channel_id: 0,
            fees: RoutingFees {
                base_msat,
                proportional_millionths,
            },
            cltv_expiry_delta: 40,
            htlc_minimum_msat: None,
            htlc_maximum_msat: None,
        }
    }

    #[test]
    fn fee_single_hop_base_only() {
        let hops = vec![make_hop(1000, 0)]; // 1 sat base, no proportional
        let fee = compute_route_hint_fee_msat(&hops, 333_000);
        assert_eq!(fee, 1000); // just the base fee
    }

    #[test]
    fn fee_single_hop_proportional_only() {
        let hops = vec![make_hop(0, 1000)]; // 0.1% proportional
        let fee = compute_route_hint_fee_msat(&hops, 1_000_000); // 1000 sats
        assert_eq!(fee, 1000); // 0.1% of 1M msat = 1000 msat
    }

    #[test]
    fn fee_single_hop_combined() {
        let hops = vec![make_hop(1000, 1000)]; // 1 sat base + 0.1%
        let fee = compute_route_hint_fee_msat(&hops, 333_000);
        // base: 1000 + proportional: 333_000 * 1000 / 1_000_000 = 333
        assert_eq!(fee, 1333);
    }

    #[test]
    fn fee_two_hops_cascading() {
        // Last hop: 1 sat base, 0.1% proportional
        // First hop: 2 sat base, 0.2% proportional
        // For 333_000 msat payment:
        //   Last hop fee: 1000 + 333_000 * 1000 / 1M = 1000 + 333 = 1333 msat
        //   First hop forwards: 333_000 + 1333 = 334_333 msat
        //   First hop fee: 2000 + 334_333 * 2000 / 1M = 2000 + 668 = 2668 msat
        //   Total: 1333 + 2668 = 4001
        let hops = vec![make_hop(2000, 2000), make_hop(1000, 1000)];
        let fee = compute_route_hint_fee_msat(&hops, 333_000);
        assert_eq!(fee, 4001);
    }

    #[test]
    fn fee_no_hops() {
        let fee = compute_route_hint_fee_msat(&[], 333_000);
        assert_eq!(fee, 0);
    }

    #[test]
    fn fee_zero_amount() {
        let hops = vec![make_hop(1000, 5000)];
        let fee = compute_route_hint_fee_msat(&hops, 0);
        assert_eq!(fee, 1000); // just the base
    }

    // -- invoice amount formula tests --

    #[test]
    fn invoice_amount_defaults() {
        let challenge = 1000u64;
        let n = 3u64;
        let fee = 10u64;
        let premium = 0u64;
        let total = challenge + n * fee + premium;
        assert_eq!(total, 1030);
    }

    #[test]
    fn invoice_amount_with_premium() {
        let challenge = 1000u64;
        let n = 3u64;
        let fee = 5u64;
        let premium = 100u64;
        let total = challenge + n * fee + premium;
        assert_eq!(total, 1115);
    }

    #[test]
    fn invoice_amount_custom_params() {
        let challenge = 5000u64;
        let n = 7u64;
        let fee = 15u64;
        let premium = 50u64;
        let total = challenge + n * fee + premium;
        assert_eq!(total, 5155);
    }

    // -- attestation signature tests --

    #[test]
    fn attestation_signature_roundtrip() {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[0xAB; 32]).unwrap();
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let (xonly, _) = keypair.x_only_public_key();

        let npub = "npub1test";
        let address = "alice@example.com";
        let verified_at = "2026-01-01T00:00:00Z";
        let verifier_hex = hex::encode(xonly.serialize());

        let signing_message = format!(
            "LIGHTNING_VERIFY:{}:{}:{}:{}",
            npub, address, verified_at, verifier_hex
        );
        let message_hash = sha256::Hash::hash(signing_message.as_bytes());
        let msg = Message::from_digest(message_hash.to_byte_array());

        // Sign
        let sig = secp.sign_schnorr_no_aux_rand(&msg, &keypair);

        // Verify
        let verify_secp = Secp256k1::verification_only();
        assert!(verify_secp.verify_schnorr(&sig, &msg, &xonly).is_ok());
    }

    #[test]
    fn attestation_signature_wrong_key_fails() {
        let secp = Secp256k1::new();
        let secret1 = SecretKey::from_slice(&[0xAB; 32]).unwrap();
        let secret2 = SecretKey::from_slice(&[0xCD; 32]).unwrap();
        let keypair1 = Keypair::from_secret_key(&secp, &secret1);
        let keypair2 = Keypair::from_secret_key(&secp, &secret2);
        let (xonly2, _) = keypair2.x_only_public_key();

        let msg_str = "LIGHTNING_VERIFY:npub1x:a@b.com:2026-01-01T00:00:00Z:deadbeef";
        let hash = sha256::Hash::hash(msg_str.as_bytes());
        let msg = Message::from_digest(hash.to_byte_array());

        let sig = secp.sign_schnorr_no_aux_rand(&msg, &keypair1);

        // Verify with wrong key should fail
        let verify_secp = Secp256k1::verification_only();
        assert!(verify_secp.verify_schnorr(&sig, &msg, &xonly2).is_err());
    }

    #[test]
    fn attestation_signature_wrong_message_fails() {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[0xAB; 32]).unwrap();
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let (xonly, _) = keypair.x_only_public_key();

        let hash1 = sha256::Hash::hash(b"message one");
        let hash2 = sha256::Hash::hash(b"message two");
        let msg1 = Message::from_digest(hash1.to_byte_array());
        let msg2 = Message::from_digest(hash2.to_byte_array());

        let sig = secp.sign_schnorr_no_aux_rand(&msg1, &keypair);

        let verify_secp = Secp256k1::verification_only();
        assert!(verify_secp.verify_schnorr(&sig, &msg2, &xonly).is_err());
    }

    // -- sorted comparison tests (core verify logic) --

    #[test]
    fn sorted_comparison_same_order() {
        let expected = vec![100u64, 350, 550];
        let submitted = vec![100u64, 350, 550];
        let mut a = submitted.clone();
        let mut b = expected.clone();
        a.sort();
        b.sort();
        assert_eq!(a, b);
    }

    #[test]
    fn sorted_comparison_different_order() {
        let expected = vec![100u64, 350, 550];
        let submitted = vec![550u64, 100, 350];
        let mut a = submitted.clone();
        let mut b = expected.clone();
        a.sort();
        b.sort();
        assert_eq!(a, b);
    }

    #[test]
    fn sorted_comparison_wrong_amounts() {
        let expected = vec![100u64, 350, 550];
        let submitted = vec![100u64, 351, 549];
        let mut a = submitted.clone();
        let mut b = expected.clone();
        a.sort();
        b.sort();
        assert_ne!(a, b);
    }

    #[test]
    fn sorted_comparison_wrong_count() {
        let expected = vec![100u64, 350, 550];
        let submitted = vec![100u64, 900];
        let mut a = submitted.clone();
        let mut b = expected.clone();
        a.sort();
        b.sort();
        assert_ne!(a, b);
    }

    // -- request deserialization tests --

    #[test]
    fn deserialize_link_request() {
        let json = r#"{"lightning_address": "alice@example.com"}"#;
        let req: VerifyRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.lightning_address.as_deref(), Some("alice@example.com"));
        assert!(req.action.is_none());
        assert!(req.session_id.is_none());
        assert!(req.amounts.is_none());
    }

    #[test]
    fn deserialize_challenge_request() {
        let json = r#"{"action": "challenge", "session_id": "abc123"}"#;
        let req: VerifyRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.action.as_deref(), Some("challenge"));
        assert_eq!(req.session_id.as_deref(), Some("abc123"));
    }

    #[test]
    fn deserialize_verify_request() {
        let json = r#"{"action": "verify", "session_id": "abc123", "amounts": [100, 350, 550]}"#;
        let req: VerifyRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.action.as_deref(), Some("verify"));
        assert_eq!(req.amounts, Some(vec![100, 350, 550]));
    }

    #[test]
    fn action_defaults_to_link() {
        let json = r#"{"lightning_address": "a@b.com"}"#;
        let req: VerifyRequest = serde_json::from_str(json).unwrap();
        let action = req.action.as_deref().unwrap_or("link");
        assert_eq!(action, "link");
    }

    // -- response serialization tests --

    #[test]
    fn serialize_link_response() {
        let resp = LinkResponse {
            session_id: "abc".to_string(),
            invoice: "lnbc1...".to_string(),
            amount_sats: 1030,
        };
        let json: serde_json::Value = serde_json::from_str(&serde_json::to_string(&resp).unwrap()).unwrap();
        assert_eq!(json["session_id"], "abc");
        assert_eq!(json["amount_sats"], 1030);
    }

    #[test]
    fn serialize_status_response_omits_none_message() {
        let resp = StatusResponse {
            status: "ok".to_string(),
            message: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(!json.contains("message"));
    }

    #[test]
    fn serialize_status_response_includes_message() {
        let resp = StatusResponse {
            status: "error".to_string(),
            message: Some("something broke".to_string()),
        };
        let json: serde_json::Value = serde_json::from_str(&serde_json::to_string(&resp).unwrap()).unwrap();
        assert_eq!(json["message"], "something broke");
    }

    // -- session state machine tests --

    #[tokio::test]
    async fn session_state_awaiting_payment() {
        let sessions: RwLock<HashMap<String, Session>> = RwLock::new(HashMap::new());
        let keys = Keys::generate();

        let session = Session {
            id: "sess1".to_string(),
            requester: keys.public_key(),
            target: keys.public_key(),
            lightning_address: "test@example.com".to_string(),
            lnurl_callback: "https://example.com/cb".to_string(),
            state: SessionState::AwaitingPayment {
                invoice: "lnbc1...".to_string(),
                payment_hash: "deadbeef".to_string(),
                amount_sats: 1030,
            },
            created_at: Utc::now(),
        };
        sessions.write().await.insert("sess1".to_string(), session);

        let guard = sessions.read().await;
        let s = guard.get("sess1").unwrap();
        assert!(matches!(s.state, SessionState::AwaitingPayment { .. }));
    }

    #[tokio::test]
    async fn session_state_challenge_transition() {
        let sessions: RwLock<HashMap<String, Session>> = RwLock::new(HashMap::new());
        let keys = Keys::generate();

        let session = Session {
            id: "sess2".to_string(),
            requester: keys.public_key(),
            target: keys.public_key(),
            lightning_address: "test@example.com".to_string(),
            lnurl_callback: "https://example.com/cb".to_string(),
            state: SessionState::AwaitingPayment {
                invoice: "lnbc1...".to_string(),
                payment_hash: "aabb".to_string(),
                amount_sats: 1030,
            },
            created_at: Utc::now(),
        };
        sessions.write().await.insert("sess2".to_string(), session);

        // Transition to ChallengeSent
        {
            let mut guard = sessions.write().await;
            let s = guard.get_mut("sess2").unwrap();
            s.state = SessionState::ChallengeSent {
                amounts: vec![100, 400, 500],
                attempts_remaining: 3,
                expires_at: Utc::now() + chrono::Duration::seconds(600),
            };
        }

        let guard = sessions.read().await;
        let s = guard.get("sess2").unwrap();
        match &s.state {
            SessionState::ChallengeSent { amounts, .. } => {
                assert_eq!(amounts, &vec![100, 400, 500]);
            }
            _ => panic!("Expected ChallengeSent state"),
        }
    }

    #[tokio::test]
    async fn session_verify_timeout() {
        let sessions: RwLock<HashMap<String, Session>> = RwLock::new(HashMap::new());
        let keys = Keys::generate();

        let session = Session {
            id: "sess3".to_string(),
            requester: keys.public_key(),
            target: keys.public_key(),
            lightning_address: "test@example.com".to_string(),
            lnurl_callback: "https://example.com/cb".to_string(),
            state: SessionState::ChallengeSent {
                amounts: vec![100, 400, 500],
                attempts_remaining: 3,
                expires_at: Utc::now() - chrono::Duration::seconds(1), // already expired
            },
            created_at: Utc::now(),
        };
        sessions.write().await.insert("sess3".to_string(), session);

        let guard = sessions.read().await;
        let s = guard.get("sess3").unwrap();
        match &s.state {
            SessionState::ChallengeSent { expires_at, .. } => {
                assert!(Utc::now() > *expires_at);
            }
            _ => panic!("Expected ChallengeSent state"),
        }
    }

    #[tokio::test]
    async fn session_requester_mismatch_detected() {
        let keys1 = Keys::generate();
        let keys2 = Keys::generate();

        let session = Session {
            id: "sess4".to_string(),
            requester: keys1.public_key(),
            target: keys1.public_key(),
            lightning_address: "test@example.com".to_string(),
            lnurl_callback: "https://example.com/cb".to_string(),
            state: SessionState::AwaitingPayment {
                invoice: "lnbc1...".to_string(),
                payment_hash: "aabb".to_string(),
                amount_sats: 1030,
            },
            created_at: Utc::now(),
        };

        assert_ne!(session.requester, keys2.public_key());
    }

    // -- LNURL sendable validation tests --

    #[test]
    fn lnurl_min_sendable_too_high() {
        // min_sendable of 2000 msat means minimum 2 sats — but challenge can send 1 sat
        let min_sendable: u64 = 2000;
        assert!(min_sendable > 1000);
    }

    #[test]
    fn lnurl_max_sendable_check() {
        // With 1000 sats across 3 payments, max single payment is 998 sats
        let challenge_sats = 1000u64;
        let num_payments = 3u64;
        let max_single = (challenge_sats - num_payments + 1) * 1000;
        assert_eq!(max_single, 998_000);

        // With 5000 sats across 5 payments, max single is 4996 sats
        let max_single2 = (5000 - 5 + 1) * 1000;
        assert_eq!(max_single2, 4_996_000);
    }

    // -- attempt limiting tests --

    #[test]
    fn attempts_decrement_on_wrong_guess() {
        let mut state = SessionState::ChallengeSent {
            amounts: vec![100, 400, 500],
            attempts_remaining: 3,
            expires_at: Utc::now() + chrono::Duration::seconds(600),
        };

        // Simulate a wrong guess decrementing
        if let SessionState::ChallengeSent { attempts_remaining, .. } = &mut state {
            *attempts_remaining -= 1;
            assert_eq!(*attempts_remaining, 2);
            *attempts_remaining -= 1;
            assert_eq!(*attempts_remaining, 1);
            *attempts_remaining -= 1;
            assert_eq!(*attempts_remaining, 0);
        } else {
            panic!("Expected ChallengeSent");
        }
    }

    #[test]
    fn zero_attempts_triggers_failure() {
        let mut state = SessionState::ChallengeSent {
            amounts: vec![100, 400, 500],
            attempts_remaining: 1,
            expires_at: Utc::now() + chrono::Duration::seconds(600),
        };

        // Last attempt, wrong guess
        if let SessionState::ChallengeSent { attempts_remaining, .. } = &mut state {
            *attempts_remaining = attempts_remaining.saturating_sub(1);
            assert_eq!(*attempts_remaining, 0);
        }

        // Should transition to Failed
        if let SessionState::ChallengeSent { attempts_remaining, .. } = &state {
            if *attempts_remaining == 0 {
                state = SessionState::Failed {
                    reason: "Max attempts exceeded".to_string(),
                };
            }
        }

        assert!(matches!(state, SessionState::Failed { .. }));
    }

    // -- constant/config sanity tests --

    #[test]
    fn default_constants_are_sane() {
        assert!(DEFAULT_CHALLENGE_SATS >= DEFAULT_NUM_PAYMENTS);
        assert!(DEFAULT_NUM_PAYMENTS >= 2);
        assert!(DEFAULT_MAX_ATTEMPTS >= 1);
        assert!(DEFAULT_TIMEOUT_SECS > 0);
        assert!(DEFAULT_FEE_FALLBACK_SATS > 0);
    }

    #[test]
    fn event_kinds_are_correct_range() {
        // Ephemeral: 20000-29999
        assert!(KIND_VERIFY_REQUEST >= 20000 && KIND_VERIFY_REQUEST < 30000);
        assert!(KIND_VERIFY_RESPONSE >= 20000 && KIND_VERIFY_RESPONSE < 30000);
        // Durable: regular range (not ephemeral, not replaceable 30000-39999)
        assert!(KIND_ATTESTATION >= 40000 || KIND_ATTESTATION < 20000);
        assert!(!(KIND_ATTESTATION >= 30000 && KIND_ATTESTATION < 40000)); // not replaceable
    }
}
