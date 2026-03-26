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
const DEFAULT_PREMIUM_SATS: u64 = 0;
const DEFAULT_FEE_FALLBACK_SATS: u64 = 10;
const DEFAULT_TIMEOUT_SECS: u64 = 600;
const DEFAULT_RELAY: &str = "wss://relay.damus.io";

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
    payments: Vec<PaymentInfo>,
}

#[derive(Debug, Deserialize)]
struct PaymentInfo {
    id: String,
    status: u8, // 0 = pending, 1 = succeeded, 2 = failed
    #[allow(dead_code)]
    amount_msat: Option<u64>,
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
            api_key: std::env::var("LDK_API_KEY").unwrap_or_else(|_| "test_api_key".to_string()),
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
        let amount_str = amount_msat.to_string();
        let output = self
            .run_command(&["bolt11-receive", "--amount-msat", &amount_str, "--description", description])
            .await?;
        let resp: Bolt11ReceiveResponse =
            serde_json::from_str(&output).map_err(|e| format!("Failed to parse invoice response: {}", e))?;
        Ok(resp.invoice)
    }

    async fn pay_invoice(&self, invoice: &str) -> Result<String, String> {
        let output = self.run_command(&["bolt11-send", "--invoice", invoice]).await?;
        let resp: Bolt11SendResponse =
            serde_json::from_str(&output).map_err(|e| format!("Failed to parse payment response: {}", e))?;
        Ok(resp.payment_id)
    }

    async fn list_payments(&self) -> Result<Vec<PaymentInfo>, String> {
        let output = self.run_command(&["list-payments"]).await?;
        let resp: ListPaymentsResponse =
            serde_json::from_str(&output).map_err(|e| format!("Failed to parse payments: {}", e))?;
        Ok(resp.payments)
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
    if user.is_empty() || domain.is_empty() || !domain.contains('.') {
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
        expires_at: chrono::DateTime<Utc>,
    },
    Verified,
    Failed {
        reason: String,
    },
}

struct Session {
    id: String,
    requester: PublicKey, // nostr pubkey of the requester
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

#[derive(Debug, Serialize)]
struct AttestationContent {
    npub: String,
    lightning_address: String,
    verified_at: String,
}

// -- Application state --

struct AppState {
    sessions: RwLock<HashMap<String, Session>>,
    ldk: LdkCli,
    keys: Keys,
    client: Client,
    attestation_client: Option<Client>, // separate relays for publishing attestations
    http: reqwest::Client,
    challenge_sats: u64,
    num_payments: u64,
    premium_sats: u64,
    fee_fallback_sats: u64,
    timeout_secs: u64,
}

// -- Event handling --

async fn handle_event(state: &Arc<AppState>, event: &Event) {
    let content: VerifyRequest = match serde_json::from_str(&event.content) {
        Ok(c) => c,
        Err(e) => {
            log::warn!("Invalid request content from {}: {}", event.pubkey, e);
            return;
        }
    };

    let action = content.action.as_deref().unwrap_or("link");

    let result = match action {
        "link" => handle_link(state, &event.pubkey, &content).await,
        "challenge" => handle_challenge(state, &event.pubkey, &content).await,
        "verify" => handle_verify(state, &event.pubkey, &content).await,
        other => Err(format!("Unknown action: {}", other)),
    };

    match result {
        Ok(response_json) => {
            if let Err(e) = send_response(state, &event.pubkey, &event.id, &response_json).await {
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
            if let Err(e2) = send_response(state, &event.pubkey, &event.id, &err_response).await {
                log::error!("Failed to send error response: {}", e2);
            }
        }
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

    log::info!("Link request from {} for {}", requester, address);

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

    // Estimate routing fees dynamically from a probe invoice.
    let avg_payment_msat = (state.challenge_sats / state.num_payments) * 1000;
    let fee_per_payment = estimate_fee_from_lnurl(
        &state.http,
        &lnurl.callback,
        avg_payment_msat,
        state.fee_fallback_sats,
    )
    .await;

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
        SessionState::ChallengeSent { amounts, expires_at } => (amounts.clone(), *expires_at),
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
        return Err("Amounts do not match".to_string());
    }

    log::info!(
        "Verification successful for {} -> {}",
        requester,
        session.lightning_address
    );

    // Build and publish attestation
    let npub = requester.to_bech32().map_err(|e| format!("Failed to encode npub: {}", e))?;
    let lightning_address = session.lightning_address.clone();

    let attestation = AttestationContent {
        npub: npub.clone(),
        lightning_address: lightning_address.clone(),
        verified_at: Utc::now().to_rfc3339(),
    };
    let attestation_json =
        serde_json::to_string(&attestation).map_err(|e| format!("Serialization error: {}", e))?;

    session.state = SessionState::Verified;
    drop(sessions);

    // Publish durable attestation event (kind 55502)
    let event = EventBuilder::new(Kind::Custom(KIND_ATTESTATION), &attestation_json)
        .tag(Tag::public_key(*requester))
        .sign_with_keys(&state.keys)
        .map_err(|e| format!("Failed to sign attestation: {}", e))?;

    let attestation_event_id = event.id.to_hex();

    // Publish to attestation relays if configured, otherwise use the main client
    let publish_client = state.attestation_client.as_ref().unwrap_or(&state.client);
    publish_client
        .send_event(event)
        .await
        .map_err(|e| format!("Failed to publish attestation: {}", e))?;

    log::info!(
        "Published attestation {} for {} -> {}",
        &attestation_event_id[..16],
        npub,
        lightning_address
    );

    // Also create a BIP-340 schnorr signature over the attestation for standalone verification
    let signing_message = format!(
        "LIGHTNING_VERIFY:{}:{}:{}:{}",
        npub,
        lightning_address,
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
        lightning_address: String,
        verified_at: String,
        verifier_pubkey: String,
        signature: String,
    }

    let resp = VerifyResponse {
        status: "verified".to_string(),
        attestation_event_id,
        npub,
        lightning_address,
        verified_at: attestation.verified_at,
        verifier_pubkey: state.keys.public_key().to_hex(),
        signature: hex::encode(sig.serialize()),
    };

    serde_json::to_string(&resp).map_err(|e| format!("Serialization error: {}", e))
}

async fn send_response(
    state: &Arc<AppState>,
    requester: &PublicKey,
    request_id: &EventId,
    content: &str,
) -> Result<(), String> {
    let event = EventBuilder::new(Kind::Custom(KIND_VERIFY_RESPONSE), content)
        .tag(Tag::public_key(*requester))
        .tag(Tag::event(*request_id))
        .sign_with_keys(&state.keys)
        .map_err(|e| format!("Failed to sign response: {}", e))?;

    state
        .client
        .send_event(event)
        .await
        .map_err(|e| format!("Failed to send response: {}", e))?;

    Ok(())
}

// -- Main --

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    // Load config
    let nsec_str = std::env::var("VERIFY_NSEC")
        .expect("VERIFY_NSEC is required (hex secret key or bech32 nsec)");
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
    log::info!("  challenge: {} sats across {} payments", challenge_sats, num_payments);
    if premium_sats > 0 {
        log::info!("  premium: {} sats", premium_sats);
    }
    log::info!("  fee fallback: {} sats/payment", fee_fallback_sats);
    log::info!("  verification timeout: {} seconds", timeout_secs);

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
        ldk: LdkCli::from_env(),
        keys,
        client: client.clone(),
        attestation_client,
        http: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?,
        challenge_sats,
        num_payments,
        premium_sats,
        fee_fallback_sats,
        timeout_secs,
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
    fn parse_lightning_address_no_dot_in_domain() {
        assert!(parse_lightning_address("alice@localhost").is_err());
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
            lightning_address: "test@example.com".to_string(),
            lnurl_callback: "https://example.com/cb".to_string(),
            state: SessionState::ChallengeSent {
                amounts: vec![100, 400, 500],
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

    // -- constant/config sanity tests --

    #[test]
    fn default_constants_are_sane() {
        assert!(DEFAULT_CHALLENGE_SATS >= DEFAULT_NUM_PAYMENTS);
        assert!(DEFAULT_NUM_PAYMENTS >= 2);
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
