//! deposits-bridge — LN ↔ ledger bridge daemon (DEP-10 §Lightning)
//!
//! Runs the two HTLC-bridge flows against a deposit the bridge holds on one
//! or more ledgers:
//!
//! 1. **Receive** (DEP-10 §Receive): wallet sends `issue_hold_invoice` with a
//!    payment hash H it controls the preimage for; we issue a BOLT-11 hold
//!    invoice for `X + service_fee + transfer_fee`; when the HTLC parks we
//!    MEASURE the hold window from the held HTLC's CLTV expiry and submit a
//!    `TransferLock` (sha256(H), timeout = htlc_expiry − Δ) to the wallet's
//!    deposit; the wallet's on-ledger reveal of `r` is scraped off Kind 9100
//!    and used to settle the upstream HTLC.
//! 2. **Pay** (DEP-10 §Pay): wallet asks `quote_invoice` for an external
//!    BOLT-11; we quote a service fee; the wallet TransferLocks
//!    `invoice_amount + service_fee` to our deposit with the invoice's
//!    payment hash; we pay the invoice, learn `r`, and `TransferComplete`.
//!
//! The hold window is measured, never assumed (DEP-10 §"Hold windows"):
//! `T_ledger = htlc_expiry_height − BRIDGE_SETTLE_MARGIN_BLOCKS`.
//!
//! Usage:
//!   deposits-bridge \
//!     --relay ws://localhost:7801 \
//!     --ledgers-relay ws://localhost:17779 \
//!     --network regtest \
//!     --node bridge:~/.deposits-bridge
//!
//! Env: LIGHTNING_BACKEND (ldk|lnd|cln), BRIDGE_RECEIVE_FEE_FIXED_MSATS,
//! BRIDGE_RECEIVE_FEE_BPS, BRIDGE_PAY_FEE_FIXED_MSATS, BRIDGE_PAY_FEE_BPS,
//! BRIDGE_HOLD_WINDOW_BLOCKS, BRIDGE_API_PORT.

use base64::prelude::*;
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::secp256k1::rand::rngs::OsRng;
use bitcoin::secp256k1::rand::RngCore;
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
use deposits_core::{compute_deposit_id, LedgerOperation, TlvDecode};
use deposits_node::lightning_backend::{self, HoldInvoiceState, LightningBackend};
use deposits_node::nostr::{
    ledger_tag, TAG_DEPOSIT_ID, TAG_EVENT_REF, TAG_LEDGER_ID, TAG_LEDGER_REQ, TAG_OP_TYPE,
    TAG_PUBKEY, TAG_SEQUENCE,
};
use nostr_sdk::prelude::*;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, oneshot};

const KIND_LEDGER_REQUEST: u16 = 20101;
const KIND_LEDGER_RESPONSE: u16 = 20102;
const KIND_LEDGER_UPDATE: u16 = 9100;
const KIND_LEDGER_ADVERTISE: u16 = 39100;
const KIND_BRIDGE_ADVERTISE: u16 = 39104; // 39103 is KIND_SWAP_ADVERTISE

/// Δ — the bridge's scrape-reveal-and-settle margin between the on-ledger
/// lock timeout and the measured HTLC expiry (DEP-10 §"Hold windows").
const BRIDGE_SETTLE_MARGIN_BLOCKS: u32 = 6;
/// When the backend reports `Accepted` without an HTLC expiry height, fall
/// back to a conservative window of LN tip + this many blocks.
const ACCEPTED_NO_HEIGHT_FALLBACK_BLOCKS: u32 = 12;
/// Pay direction: refuse inbound locks whose timeout window is shorter than
/// this (advertised as `min_lock_window_blocks` in quote responses).
const MIN_LOCK_WINDOW_BLOCKS: u32 = 18;
/// How long a stored pay quote stays matchable against an inbound lock.
const QUOTE_RETENTION_SECS: u64 = 600;
/// `quote_expiry_secs` advertised to wallets in quote responses.
const QUOTE_VALID_SECS: u64 = 120;
/// Receive amount bounds advertised in the Kind 39104 ad and enforced on
/// `issue_hold_invoice` requests.
const RECEIVE_MIN_AMOUNT_MSATS: u64 = 1000;
const RECEIVE_MAX_AMOUNT_MSATS: u64 = 100_000_000;
/// BOLT-11 invoice expiry for hold invoices (payer's window to start paying).
const HOLD_INVOICE_EXPIRY_SECS: u32 = 3600;
/// Blocks past `t_ledger` before we cancel an unsettled hold invoice.
const TIMEOUT_SWEEP_GRACE_BLOCKS: u32 = 2;
/// Receive-side poll interval over awaiting/locked entries.
const POLL_INTERVAL_SECS: u64 = 3;
/// Ad republish interval.
const AD_REPUBLISH_SECS: u64 = 600;

// ─── Hex serde helpers ──────────────────────────────────────────────────────

mod hex32 {
    pub fn serialize<S: serde::Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s: String = serde::Deserialize::deserialize(d)?;
        let b = hex::decode(&s).map_err(serde::de::Error::custom)?;
        b.try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
    }
}

mod hex16 {
    pub fn serialize<S: serde::Serializer>(v: &[u8; 16], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<[u8; 16], D::Error> {
        let s: String = serde::Deserialize::deserialize(d)?;
        let b = hex::decode(&s).map_err(serde::de::Error::custom)?;
        b.try_into()
            .map_err(|_| serde::de::Error::custom("expected 16 bytes"))
    }
}

// ─── Data Types ─────────────────────────────────────────────────────────────

struct NodeConfig {
    name: String,
    seed: [u8; 32],
    data_dir: PathBuf,
}

#[derive(Clone)]
struct AgentDeposit {
    alias: String,
    ledger_id: String,
    deposit_id: [u8; 16],
    deposit_id_hex: String,
    keypair: Keypair,
    balance_msats: i64,
    /// Operator's transfer fee (bridge pays this on outbound locks)
    operator_fee_fixed_msats: u64,
    operator_fee_rate_bps: u16,
}

/// Bridge service fees (the bridge's own margin, captured via the BOLT-11
/// spread — DEP-10 §Lightning) plus the advertised typical hold window.
#[derive(Clone, Copy)]
struct BridgeFees {
    receive_fixed_msats: u64,
    receive_rate_bps: u64,
    pay_fixed_msats: u64,
    pay_rate_bps: u64,
    hold_window_blocks: u32,
}

/// Receive-direction state machine (DEP-10 §Receive). Persisted to the
/// bridge state file on every transition for crash recovery.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
enum ReceiveState {
    /// Hold invoice issued; waiting for the payer's HTLC to park.
    AwaitingHtlc,
    /// TransferLock submitted to the ledger; waiting for the wallet's reveal.
    Locked {
        #[serde(with = "hex32")]
        transfer_id: [u8; 32],
        t_ledger: u32,
    },
    /// Preimage scraped off Kind 9100 and upstream HTLC settled.
    Settled,
    /// Lock window passed without a reveal; hold invoice canceled.
    Cancelled,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct PendingReceive {
    #[serde(with = "hex32")]
    payment_hash: [u8; 32],
    ledger_id: String,
    #[serde(with = "hex16")]
    wallet_deposit_id: [u8; 16],
    /// X — what the wallet receives on-ledger.
    amount_x_msats: u64,
    service_fee_msats: u64,
    transfer_fee_msats: u64,
    bolt11: String,
    state: ReceiveState,
}

/// Pay-direction state machine (DEP-10 §Pay). Persisted alongside the
/// receive table: a crash between "paid the invoice" and "claimed the lock"
/// would otherwise eat the payment — the lock refunds, the sats are gone.
/// On restart, LockSeen/Paying entries are re-driven through `execute_pay`,
/// which checks for an existing preimage before paying (LN nodes dedup by
/// payment_hash, so the retry can't double-spend).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct QuotedPay {
    #[serde(with = "hex32")]
    payment_hash: [u8; 32],
    bolt11: String,
    ledger_id: String,
    invoice_amount_msats: u64,
    service_fee_msats: u64,
    /// Unix seconds (Instant doesn't survive a restart).
    quoted_at_unix: u64,
    state: PayState,
}

impl QuotedPay {
    fn age(&self) -> Duration {
        Duration::from_secs(now_unix().saturating_sub(self.quoted_at_unix))
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
enum PayState {
    Quoted,
    LockSeen {
        transfer_id: [u8; 32],
        amount_msats: u64,
    },
    Paying {
        transfer_id: [u8; 32],
    },
    Completed,
    Failed(String),
}

/// The witness material revealed when a lock is satisfied. HTLC-only for the
/// bridge (PTLC hold invoices need LN-side support that doesn't exist yet).
#[derive(Debug, Clone, Copy)]
enum WitnessMaterial {
    Preimage([u8; 32]),
}

/// An inbound TransferLock targeting one of our deposits (pay direction).
#[derive(Debug, Clone)]
struct InboundLock {
    ledger_id: String,
    transfer_id: [u8; 32],
    source_deposit_id: [u8; 16],
    amount_msats: u64,
    /// The lock's sha256(H) hash.
    hash: [u8; 32],
    timeout_height: u32,
}

struct Config {
    relay: String,
    ledgers_relay: String,
    network: bitcoin::Network,
    nodes: Vec<NodeConfig>,
    fees: BridgeFees,
    api_port: u16,
}

/// On-disk state file format (`<data_dir>/bridge-state.json`):
/// `{ "seen_hashes": [...], "receives": [...], "pays": [...] }`
/// (`pays` added later — default tolerates older files).
#[derive(serde::Serialize, serde::Deserialize, Default)]
struct PersistedState {
    seen_hashes: Vec<String>,
    receives: Vec<PendingReceive>,
    #[serde(default)]
    pays: Vec<QuotedPay>,
}

#[derive(Default)]
struct BridgeStats {
    receives_settled: std::sync::atomic::AtomicU64,
    receives_cancelled: std::sync::atomic::AtomicU64,
    pays_completed: std::sync::atomic::AtomicU64,
    pays_failed: std::sync::atomic::AtomicU64,
}

struct SharedState {
    deposits: Vec<AgentDeposit>,
    receives: Mutex<Vec<PendingReceive>>,
    pays: Mutex<HashMap<[u8; 32], QuotedPay>>,
    seen_hashes: Mutex<HashSet<[u8; 32]>>,
    state_file: PathBuf,
    stats: BridgeStats,
    started_at: Instant,
    fees: BridgeFees,
    holds_supported: bool,
}

impl SharedState {
    /// Write the receive table + pay table + seen-hash set to the state
    /// file. Called on every state transition (crash recovery: reload +
    /// resume).
    fn persist(&self) {
        let doc = PersistedState {
            seen_hashes: self
                .seen_hashes
                .lock()
                .unwrap()
                .iter()
                .map(hex::encode)
                .collect(),
            receives: self.receives.lock().unwrap().clone(),
            pays: self.pays.lock().unwrap().values().cloned().collect(),
        };
        let json = match serde_json::to_string_pretty(&doc) {
            Ok(j) => j,
            Err(e) => {
                eprintln!("[STATE] serialize failed: {}", e);
                return;
            }
        };
        let tmp = self.state_file.with_extension("json.tmp");
        let res = std::fs::write(&tmp, &json).and_then(|_| std::fs::rename(&tmp, &self.state_file));
        if let Err(e) = res {
            eprintln!(
                "[STATE] persist to {} failed: {}",
                self.state_file.display(),
                e
            );
        }
    }
}

fn load_persisted_state(path: &PathBuf) -> PersistedState {
    if !path.exists() {
        return PersistedState::default();
    }
    match std::fs::read_to_string(path).map_err(|e| e.to_string()).and_then(|s| {
        serde_json::from_str::<PersistedState>(&s).map_err(|e| e.to_string())
    }) {
        Ok(doc) => doc,
        Err(e) => {
            eprintln!("[STATE] failed to load {}: {} — starting fresh", path.display(), e);
            PersistedState::default()
        }
    }
}

// ─── Pure helpers (unit-tested below) ───────────────────────────────────────

/// Service fee = fixed + amount · bps / 10_000, computed in u128 to avoid
/// overflow on large amounts.
fn service_fee_msats(fixed_msats: u64, rate_bps: u64, amount_msats: u64) -> u64 {
    let proportional = (amount_msats as u128 * rate_bps as u128) / 10_000;
    fixed_msats.saturating_add(u64::try_from(proportional).unwrap_or(u64::MAX))
}

/// Derive the on-ledger lock timeout from the measured HTLC expiry
/// (DEP-10 §Receive step 3). When the backend accepted without reporting a
/// height, fall back to a conservative LN-tip-relative bound — the caller
/// logs a warning in that case.
fn derive_t_ledger(htlc_expiry_height: Option<u32>, ln_tip: u32) -> u32 {
    match htlc_expiry_height {
        Some(h) => h.saturating_sub(BRIDGE_SETTLE_MARGIN_BLOCKS),
        None => ln_tip.saturating_add(ACCEPTED_NO_HEIGHT_FALLBACK_BLOCKS),
    }
}

/// First-use registration of a payment hash. Returns false when the hash was
/// already seen — re-using H across invoices would let an old on-ledger
/// reveal settle a new HTLC (DEP-04 §"Bridge request envelopes").
fn register_payment_hash(seen: &mut HashSet<[u8; 32]>, hash: [u8; 32]) -> bool {
    seen.insert(hash)
}

/// Whether a stored pay quote is still matchable against an inbound lock.
fn quote_expired(age: Duration) -> bool {
    age >= Duration::from_secs(QUOTE_RETENTION_SECS)
}

fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let b = hex::decode(s).ok()?;
    b.try_into().ok()
}

fn parse_hex16(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 {
        return None;
    }
    let b = hex::decode(s).ok()?;
    b.try_into().ok()
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

// ─── Transport (adapted from htlc-agent) ────────────────────────────────────

struct AgentTransport {
    client: Client,
    keys: Keys,
    pending_responses: Arc<Mutex<HashMap<String, oneshot::Sender<ResponseData>>>>,
}

#[derive(Debug, Clone)]
struct ResponseData {
    success: bool,
    error: Option<String>,
    result: Option<serde_json::Value>,
}

#[derive(Debug)]
enum UpdateEvent {
    /// A TransferLock where destination is one of our deposits (pay path).
    InboundLock(InboundLock),
    /// A TransferComplete on one of our ledgers (receive path: the wallet's
    /// reveal of `r` for a lock we issued).
    WitnessRevealed {
        ledger_id: String,
        transfer_id: [u8; 32],
        material: WitnessMaterial,
    },
    /// An issue_hold_invoice / quote_invoice request addressed to us.
    BridgeRequest {
        event_id: String,
        /// `#l` tag from the request — echoed on the response so wallets
        /// with a per-ledger response filter (relay-side `#l`) see it.
        ledger_id: String,
        action: String,
        params: serde_json::Value,
    },
}

impl AgentTransport {
    async fn new(
        secret_key: SecretKey,
        relay_urls: &[String],
        deposit_id_hexes: &[String],
        ledger_ids: &[String],
    ) -> Result<(Self, mpsc::Receiver<UpdateEvent>), Box<dyn std::error::Error>> {
        let secret_bytes = secret_key.secret_bytes();
        let nostr_secret = nostr_sdk::SecretKey::from_slice(&secret_bytes)
            .map_err(|e| format!("Invalid key: {}", e))?;
        let keys = Keys::new(nostr_secret);

        let opts = Options::default().notification_channel_size(65536);
        let client = Client::builder().signer(keys.clone()).opts(opts).build();

        for url in relay_urls {
            client
                .add_relay(url.as_str())
                .await
                .map_err(|e| format!("Failed to add relay {}: {}", url, e))?;
        }
        client.connect_with_timeout(Duration::from_secs(10)).await;

        // Wait for at least one relay
        let start = Instant::now();
        loop {
            let relays = client.relays().await;
            if relays
                .values()
                .any(|r| r.status() == RelayStatus::Connected)
            {
                break;
            }
            if start.elapsed() > Duration::from_secs(10) {
                return Err("No relay connected after 10s".into());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // Subscribe to Kind 9100 updates for our deposit IDs (catches
        // TransferLock with #i tag — the pay path's inbound locks).
        let mut filters = Vec::new();
        if !deposit_id_hexes.is_empty() {
            let update_filter = Filter::new()
                .kind(Kind::Custom(KIND_LEDGER_UPDATE))
                .custom_tag(TAG_DEPOSIT_ID, deposit_id_hexes.iter().map(|s| s.as_str()));
            filters.push(update_filter);
        }

        // Also subscribe to Kind 9100 on our ledgers for TransferComplete
        // events (no #i tag, only #d + #t=71) — the receive path's reveals.
        if !ledger_ids.is_empty() {
            let complete_filter = Filter::new()
                .kind(Kind::Custom(KIND_LEDGER_UPDATE))
                .custom_tag(
                    TAG_LEDGER_ID,
                    ledger_ids.iter().map(|s| ledger_tag(s.as_str())),
                )
                .custom_tag(TAG_OP_TYPE, ["71"]);
            filters.push(complete_filter);
        }

        // Subscribe to Kind 20102 responses for our ledgers
        if !ledger_ids.is_empty() {
            let response_filter = Filter::new()
                .kind(Kind::Custom(KIND_LEDGER_RESPONSE))
                .custom_tag(TAG_LEDGER_REQ, ledger_ids.iter().map(|s| s.as_str()));
            filters.push(response_filter);
        }

        // Subscribe to Kind 20101 requests addressed to us (#p = our pubkey)
        let bridge_pubkey_hex = keys.public_key().to_hex();
        let request_filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_REQUEST))
            .custom_tag(TAG_PUBKEY, [bridge_pubkey_hex.as_str()]);
        filters.push(request_filter);

        client
            .subscribe(filters, None)
            .await
            .map_err(|e| format!("Failed to subscribe: {}", e))?;

        let pending: Arc<Mutex<HashMap<String, oneshot::Sender<ResponseData>>>> =
            Arc::new(Mutex::new(HashMap::new()));

        let (update_tx, update_rx) = mpsc::channel::<UpdateEvent>(1024);

        // Background dispatcher
        let pending_clone = pending.clone();
        let deposit_ids: Vec<String> = deposit_id_hexes.to_vec();
        let mut notification_rx = client.notifications();
        tokio::spawn(async move {
            loop {
                match notification_rx.recv().await {
                    Ok(RelayPoolNotification::Event { event, .. }) => {
                        let kind = event.kind.as_u16();
                        if kind == KIND_LEDGER_RESPONSE {
                            // Route response to waiting request
                            let request_id = event.tags.iter().find_map(|tag| {
                                if tag.kind() == TagKind::SingleLetter(TAG_EVENT_REF) {
                                    tag.content().map(|s| s.to_string())
                                } else {
                                    None
                                }
                            });
                            if let Some(req_id) = request_id {
                                let response: ResponseData =
                                    match serde_json::from_str::<serde_json::Value>(&event.content)
                                    {
                                        Ok(v) => ResponseData {
                                            success: v
                                                .get("success")
                                                .and_then(|s| s.as_bool())
                                                .unwrap_or(false),
                                            error: v
                                                .get("error")
                                                .and_then(|s| s.as_str())
                                                .map(|s| s.to_string()),
                                            result: v.get("result").cloned(),
                                        },
                                        Err(_) => continue,
                                    };
                                let sender = pending_clone.lock().unwrap().remove(&req_id);
                                if let Some(tx) = sender {
                                    let _ = tx.send(response);
                                }
                            }
                        } else if kind == KIND_LEDGER_UPDATE {
                            if let Some(evt) = decode_update_event(&event, &deposit_ids) {
                                let _ = update_tx.send(evt).await;
                            }
                        } else if kind == KIND_LEDGER_REQUEST {
                            let action = event.tags.iter().find_map(|tag| {
                                if tag.kind() == TagKind::custom("action") {
                                    tag.content().map(|s| s.to_string())
                                } else {
                                    None
                                }
                            });
                            if let Some(action) = action {
                                if action == "issue_hold_invoice" || action == "quote_invoice" {
                                    let ledger_id = event
                                        .tags
                                        .iter()
                                        .find_map(|tag| {
                                            if tag.kind()
                                                == TagKind::SingleLetter(TAG_LEDGER_REQ)
                                            {
                                                tag.content().map(|s| s.to_string())
                                            } else {
                                                None
                                            }
                                        })
                                        .unwrap_or_default();
                                    if let Ok(params) =
                                        serde_json::from_str::<serde_json::Value>(&event.content)
                                    {
                                        let _ = update_tx
                                            .send(UpdateEvent::BridgeRequest {
                                                event_id: event.id.to_hex(),
                                                ledger_id,
                                                action,
                                                params,
                                            })
                                            .await;
                                    }
                                }
                            }
                        }
                    }
                    Ok(RelayPoolNotification::Shutdown) => break,
                    _ => {}
                }
            }
        });

        Ok((
            Self {
                client,
                keys,
                pending_responses: pending,
            },
            update_rx,
        ))
    }

    async fn send_request(
        &self,
        ledger_id: &str,
        action: &str,
        params: serde_json::Value,
    ) -> Result<(String, oneshot::Receiver<ResponseData>), Box<dyn std::error::Error + Send + Sync>>
    {
        let content = serde_json::to_string(&params)?;

        let event = EventBuilder::new(Kind::Custom(KIND_LEDGER_REQUEST), &content)
            .tag(Tag::custom(
                TagKind::SingleLetter(TAG_LEDGER_REQ),
                [ledger_id],
            ))
            .tag(Tag::custom(TagKind::custom("action"), [action]))
            .sign_with_keys(&self.keys)
            .map_err(|e| format!("Sign failed: {}", e))?;

        let event_id = event.id.to_hex();

        let (tx, rx) = oneshot::channel();
        self.pending_responses
            .lock()
            .unwrap()
            .insert(event_id.clone(), tx);

        let urls: Vec<_> = self.client.relays().await.keys().cloned().collect();
        self.client
            .send_msg_to(urls, ClientMessage::event(event))
            .await
            .map_err(|e| format!("Send failed: {}", e))?;

        Ok((event_id, rx))
    }

    /// Send a response to a request event (Kind 20102 with #e tag).
    ///
    /// Echoes the request's `#l` tag: wallets configure a per-ledger
    /// response filter (`subscribe_to_response` with relay-side `#l`),
    /// so an untagged response never reaches them.
    async fn send_response(
        &self,
        request_event_id: &str,
        ledger_id: &str,
        response: serde_json::Value,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let content = serde_json::to_string(&response)?;
        let mut builder = EventBuilder::new(Kind::Custom(KIND_LEDGER_RESPONSE), &content)
            .tag(Tag::custom(
                TagKind::SingleLetter(TAG_EVENT_REF),
                [request_event_id],
            ));
        if !ledger_id.is_empty() {
            builder = builder.tag(Tag::custom(
                TagKind::SingleLetter(TAG_LEDGER_REQ),
                [ledger_id],
            ));
        }
        let event = builder
            .sign_with_keys(&self.keys)
            .map_err(|e| format!("Sign failed: {}", e))?;

        let urls: Vec<_> = self.client.relays().await.keys().cloned().collect();
        self.client
            .send_msg_to(urls, ClientMessage::event(event))
            .await
            .map_err(|e| format!("Send failed: {}", e))?;

        Ok(())
    }
}

// ─── Update Decoding ────────────────────────────────────────────────────────

/// Decode a Kind 9100 event into the subset the bridge cares about.
///
/// InboundLock is only emitted when the lock's DESTINATION is one of our
/// deposits — this is what keeps receive-side locks (outbound from us, the
/// destination is the wallet) from ever entering the pay path. Pay matching
/// additionally checks the stored quote table, and the main loop refuses
/// hashes that collide with a PendingReceive as a second guard.
fn decode_update_event(event: &Event, our_deposit_ids: &[String]) -> Option<UpdateEvent> {
    let ledger_id = event.tags.iter().find_map(|tag| {
        if tag.kind() == TagKind::SingleLetter(TAG_LEDGER_ID) {
            tag.content().map(|s| s.to_string())
        } else {
            None
        }
    })?;

    let op_type: u16 = event.tags.iter().find_map(|tag| {
        if tag.kind() == TagKind::SingleLetter(TAG_OP_TYPE) {
            tag.content().and_then(|s| s.parse().ok())
        } else {
            None
        }
    })?;

    // Only care about TransferLock (70) and TransferComplete (71)
    if op_type != 70 && op_type != 71 {
        return None;
    }

    let tlv_bytes = BASE64_STANDARD.decode(event.content.as_bytes()).ok()?;
    let update = deposits_core::SignedLedgerUpdate::tlv_decode(&tlv_bytes).ok()?;
    let op = LedgerOperation::tlv_decode(&update.message).ok()?;

    match op {
        LedgerOperation::TransferLock {
            source_deposit_id,
            destination_deposit_id,
            amount,
            completion_script,
            timeout_height,
            transfer_id,
            ..
        } => {
            // Pay path: only locks whose destination is one of our deposits.
            let dest_hex = hex::encode(destination_deposit_id);
            if !our_deposit_ids.contains(&dest_hex) {
                return None;
            }

            // HTLC-only: `sha256(<64 hex>)`. The bridge doesn't service
            // pointlock(...) locks (no LN-side PTLC support yet).
            let hash = extract_sha256_hash_from_script(&completion_script)?;

            Some(UpdateEvent::InboundLock(InboundLock {
                ledger_id,
                transfer_id,
                source_deposit_id,
                amount_msats: amount,
                hash,
                timeout_height,
            }))
        }
        LedgerOperation::TransferComplete {
            transfer_id,
            script_witness, .. } => {
            // Witness stack[0] is the 32-byte preimage for sha256(H) locks.
            let bytes = script_witness.stack.first()?;
            if bytes.len() != 32 {
                return None;
            }
            let mut buf = [0u8; 32];
            buf.copy_from_slice(bytes);

            Some(UpdateEvent::WitnessRevealed {
                ledger_id,
                transfer_id,
                material: WitnessMaterial::Preimage(buf),
            })
        }
        _ => None,
    }
}

/// `sha256(<64 hex>)` → the 32-byte hash. Anything else (pointlock, custom
/// descriptors) returns None and the lock flows past the bridge.
fn extract_sha256_hash_from_script(script: &str) -> Option<[u8; 32]> {
    let inner = script.strip_prefix("sha256(")?.strip_suffix(')')?;
    parse_hex32(inner)
}

// ─── Key Derivation (same as htlc-agent / transfer-simulator) ───────────────

fn derive_secret_key(
    seed: &[u8; 32],
    network: bitcoin::Network,
) -> Result<SecretKey, Box<dyn std::error::Error>> {
    use bitcoin::bip32::{DerivationPath, Xpriv};
    let xpriv = Xpriv::new_master(network, seed)?;
    let secp = Secp256k1::new();
    let path: DerivationPath = "m/44'/1237'/0'/0/0".parse()?;
    let child = xpriv.derive_priv(&secp, &path)?;
    Ok(child.private_key)
}

fn derive_secret_key_at_index(
    seed: &[u8; 32],
    network: bitcoin::Network,
    index: u32,
) -> Result<SecretKey, Box<dyn std::error::Error>> {
    use bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv};
    let xpriv = Xpriv::new_master(network, seed)?;
    let secp = Secp256k1::new();
    let path: DerivationPath = "m/84'/0'/0'/0".parse()?;
    let parent = xpriv.derive_priv(&secp, &path)?;
    let child = parent.derive_priv(&secp, &[ChildNumber::from_normal_idx(index)?])?;
    Ok(child.private_key)
}

// ─── Deposit Loading (same wallet-format as htlc-agent) ─────────────────────

fn load_deposits(
    node: &NodeConfig,
    network: bitcoin::Network,
) -> Result<Vec<AgentDeposit>, Box<dyn std::error::Error>> {
    let secp = Secp256k1::new();
    let deposits_file = node.data_dir.join("deposits.json");
    if !deposits_file.exists() {
        return Ok(Vec::new());
    }

    let data = std::fs::read_to_string(&deposits_file)?;
    let entries: Vec<serde_json::Value> = serde_json::from_str(&data)?;

    let mut deposits = Vec::new();
    for entry in &entries {
        let alias = entry
            .get("alias")
            .and_then(|v| v.as_str())
            .unwrap_or("?")
            .to_string();
        let ledger_id = entry
            .get("ledger_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        // Source of identity: prefer the explicit `descriptor` (new format),
        // fall back to pk(<deposit_pubkey>) for legacy records.
        let descriptor = match entry.get("descriptor").and_then(|v| v.as_str()) {
            Some(d) if !d.is_empty() => d.to_string(),
            _ => {
                let pk = entry
                    .get("deposit_pubkey")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if pk.is_empty() {
                    continue;
                }
                format!("pk({})", pk)
            }
        };
        let key_index = entry.get("key_index").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        let balance_msats = entry
            .get("balance_msats")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);

        if ledger_id.is_empty() {
            continue;
        }

        let deposit_id = compute_deposit_id(&descriptor);

        let secret_key = derive_secret_key_at_index(&node.seed, network, key_index)?;
        let keypair = Keypair::from_secret_key(&secp, &secret_key);

        deposits.push(AgentDeposit {
            alias,
            ledger_id,
            deposit_id,
            deposit_id_hex: hex::encode(deposit_id),
            keypair,
            balance_msats,
            operator_fee_fixed_msats: 0,
            operator_fee_rate_bps: 0,
        });
    }

    eprintln!(
        "  Loaded {} deposits from {}",
        deposits.len(),
        deposits_file.display()
    );
    Ok(deposits)
}

// ─── Operator Advertisement Fetching ────────────────────────────────────────

struct OperatorAdInfo {
    relay_url: String,
    transfer_fee_fixed_msats: u64,
    transfer_fee_rate_bps: u16,
}

async fn fetch_advertisements(
    relay_url: &str,
) -> Result<HashMap<String, OperatorAdInfo>, Box<dyn std::error::Error>> {
    let keys = Keys::generate();
    let client = Client::builder().signer(keys).build();

    client
        .add_relay(relay_url)
        .await
        .map_err(|e| format!("Failed to add relay: {}", e))?;
    client.connect_with_timeout(Duration::from_secs(10)).await;

    let filter = Filter::new().kind(Kind::Custom(KIND_LEDGER_ADVERTISE));

    let events = client
        .fetch_events(vec![filter], Some(Duration::from_secs(10)))
        .await
        .map_err(|e| format!("Relay fetch failed: {}", e))?;

    let mut ledger_map: HashMap<String, OperatorAdInfo> = HashMap::new();

    for event in events.iter() {
        let ad: serde_json::Value = match serde_json::from_str(&event.content) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let ledger_id = event
            .tags
            .iter()
            .find_map(|tag| {
                if tag.kind() == TagKind::SingleLetter(TAG_LEDGER_ID) {
                    tag.content().map(|s| s.to_string())
                } else {
                    None
                }
            })
            .or_else(|| {
                ad.get("ledger_id")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            });

        let ledger_id = match ledger_id {
            Some(id) if id.len() == 64 && id.chars().all(|c| c.is_ascii_hexdigit()) => id,
            _ => continue,
        };

        let relay = ad
            .get("relay_url")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let fee_fixed = ad
            .get("transfer_fee_fixed_msats")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let fee_bps = ad
            .get("transfer_fee_rate_bps")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u16;

        if !relay.is_empty() {
            ledger_map.insert(
                ledger_id,
                OperatorAdInfo {
                    relay_url: relay,
                    transfer_fee_fixed_msats: fee_fixed,
                    transfer_fee_rate_bps: fee_bps,
                },
            );
        }
    }

    let _ = client.disconnect().await;
    Ok(ledger_map)
}

// ─── Bridge Advertisement (Kind 39104, DEP-04 §"Bridge Advertisements") ─────

async fn publish_bridge_advertisement(
    keys: &Keys,
    ledgers_relay: &str,
    deposits: &[AgentDeposit],
    fees: &BridgeFees,
    network: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::builder().signer(keys.clone()).build();
    client
        .add_relay(ledgers_relay)
        .await
        .map_err(|e| format!("Failed to add relay: {}", e))?;
    client.connect_with_timeout(Duration::from_secs(10)).await;

    let bridge_pubkey = keys.public_key().to_hex();

    let ledger_entries: Vec<serde_json::Value> = deposits
        .iter()
        .map(|d| {
            serde_json::json!({
                "ledger_id": d.ledger_id,
                "deposit_id": d.deposit_id_hex,
                "balance_msats": d.balance_msats,
                "lock_type": ["htlc"],
                "receive": {
                    "fee_fixed_msats": fees.receive_fixed_msats,
                    "fee_rate_bps": fees.receive_rate_bps,
                    "min_amount_msats": RECEIVE_MIN_AMOUNT_MSATS,
                    "max_amount_msats": RECEIVE_MAX_AMOUNT_MSATS,
                    "hold_window_blocks": fees.hold_window_blocks,
                },
                "pay": {
                    "fee_fixed_msats": fees.pay_fixed_msats,
                    "fee_rate_bps": fees.pay_rate_bps,
                    "quote_endpoint": "quote_invoice",
                },
            })
        })
        .collect();

    let content = serde_json::json!({
        "bridge_pubkey": bridge_pubkey,
        "network": network,
        "ledgers": ledger_entries,
    });

    // Query existing ad timestamp so we can set a strictly newer one
    let existing_ts = {
        let filter = Filter::new()
            .kind(Kind::Custom(KIND_BRIDGE_ADVERTISE))
            .custom_tag(TAG_LEDGER_ID, [&bridge_pubkey])
            .limit(1);
        let events = client
            .fetch_events(vec![filter], Some(std::time::Duration::from_secs(5)))
            .await
            .ok();
        events
            .and_then(|evs| evs.iter().next().map(|e| e.created_at.as_u64()))
            .unwrap_or(0)
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let ts = std::cmp::max(now, existing_ts + 1);

    // NIP-33: #d tag = bridge pubkey, #n tag = network
    let event = EventBuilder::new(Kind::Custom(KIND_BRIDGE_ADVERTISE), content.to_string())
        .custom_created_at(Timestamp::from(ts))
        .tag(Tag::custom(
            TagKind::SingleLetter(TAG_LEDGER_ID),
            [&bridge_pubkey],
        ))
        .tag(Tag::custom(TagKind::SingleLetter(TAG_SEQUENCE), [network]));

    let signed = event
        .sign_with_keys(keys)
        .map_err(|e| format!("Failed to sign advertisement: {}", e))?;
    eprintln!(
        "  [AD] kind={} ts={} (old={}) ledgers={}",
        KIND_BRIDGE_ADVERTISE,
        ts,
        existing_ts,
        deposits.len()
    );
    let output = client
        .send_event(signed)
        .await
        .map_err(|e| format!("Failed to publish advertisement: {}", e))?;
    if !output.failed.is_empty() {
        eprintln!("  [AD] publish failures: {:?}", output.failed);
    }

    tokio::time::sleep(Duration::from_secs(2)).await;
    let _ = client.disconnect().await;
    Ok(())
}

// ─── Transfer Execution (adapted from htlc-agent) ───────────────────────────

/// Submit a TransferLock from our deposit to the wallet's (receive path).
/// `bridge_bolt11` rides as an extra aux param in the request JSON so
/// cosigners that implement the when-supplied BOLT-11 checks (DEP-10
/// §"Bridge cosigner rules") can verify the timeout ordering; operators that
/// don't recognize it ignore it.
#[allow(clippy::too_many_arguments)]
async fn execute_transfer_lock(
    transport: &AgentTransport,
    source: &AgentDeposit,
    dest_deposit_id: &[u8; 16],
    amount_msats: u64,
    fee_msats: u64,
    hash: &[u8; 32],
    timeout_height: u32,
    bridge_bolt11: Option<&str>,
) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
    let mut rng = OsRng;
    let mut transfer_nonce = [0u8; 32];
    rng.fill_bytes(&mut transfer_nonce);
    let mut transfer_id = [0u8; 32];
    rng.fill_bytes(&mut transfer_id);

    let completion_script = format!("sha256({})", hex::encode(hash));

    let op_nonce = deposits_core::signing::fresh_op_nonce();
    let op_expiry = u32::MAX;
    let proto = deposits_core::messages::LedgerOperation::TransferLock {
        transfer_nonce,
        source_deposit_id: source.deposit_id,
        destination_deposit_id: *dest_deposit_id,
        amount: amount_msats,
        fee: fee_msats,
        completion_script: completion_script.clone(),
        timeout_height,
        transfer_id,
        nonce: op_nonce,
        expiry: op_expiry,
        witness: deposits_core::types::DescriptorWitness::new(),
        commitment: None,
    };
    let signed = deposits_core::signing::sign_op(proto, &source.keypair.secret_key())
        .ok_or("sign_op failed: unsignable variant")?;
    let signature_bytes = match &signed {
        deposits_core::messages::LedgerOperation::TransferLock { witness, .. } => {
            witness.stack[0].clone()
        }
        _ => unreachable!("sign_op preserves variant"),
    };

    let mut params = serde_json::json!({
        "transfer_nonce": hex::encode(transfer_nonce),
        "source_deposit_id": hex::encode(source.deposit_id),
        "destination_deposit_id": hex::encode(dest_deposit_id),
        "amount": amount_msats,
        "fee": fee_msats,
        "completion_script": completion_script,
        "timeout_height": timeout_height,
        "transfer_id": hex::encode(transfer_id),
        "op_nonce": op_nonce,
        "op_expiry": op_expiry,
        "signature": hex::encode(&signature_bytes),
    });
    if let Some(bolt11) = bridge_bolt11 {
        params["bridge_bolt11"] = serde_json::Value::String(bolt11.to_string());
    }

    let (_, rx) = transport
        .send_request(&source.ledger_id, "transfer_lock", params)
        .await?;

    let resp = tokio::time::timeout(Duration::from_secs(30), rx)
        .await
        .map_err(|_| "transfer_lock timeout")?
        .map_err(|_| "channel closed")?;

    if !resp.success {
        return Err(format!("transfer_lock failed: {}", resp.error.unwrap_or_default()).into());
    }

    Ok(transfer_id)
}

async fn execute_transfer_complete(
    transport: &AgentTransport,
    ledger_id: &str,
    transfer_id: &[u8; 32],
    material: &WitnessMaterial,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let params = match material {
        WitnessMaterial::Preimage(p) => serde_json::json!({
            "transfer_id": hex::encode(transfer_id),
            "preimage": hex::encode(p),
        }),
    };

    let (_, rx) = transport
        .send_request(ledger_id, "transfer_complete", params)
        .await?;

    let resp = tokio::time::timeout(Duration::from_secs(30), rx)
        .await
        .map_err(|_| "transfer_complete timeout")?
        .map_err(|_| "channel closed")?;

    if !resp.success {
        return Err(format!(
            "transfer_complete failed: {}",
            resp.error.unwrap_or_default()
        )
        .into());
    }

    Ok(())
}

// ─── Request Handlers ───────────────────────────────────────────────────────

fn err_response(msg: impl Into<String>) -> serde_json::Value {
    serde_json::json!({ "success": false, "error": msg.into() })
}

/// Handle `issue_hold_invoice` (DEP-04 §"Bridge request envelopes",
/// receive direction). Validates, issues the hold invoice, and registers a
/// PendingReceive in AwaitingHtlc for the poll loop to drive.
async fn handle_issue_hold_invoice(
    state: &Arc<SharedState>,
    ln: &Arc<dyn LightningBackend>,
    params: &serde_json::Value,
) -> serde_json::Value {
    let ledger_id = match params["ledger_id"].as_str() {
        Some(s) => s.to_string(),
        None => return err_response("missing ledger_id"),
    };
    let wallet_deposit_id = match params["deposit_id"].as_str().and_then(parse_hex16) {
        Some(d) => d,
        None => return err_response("deposit_id must be 32 hex chars"),
    };
    let amount_x_msats = match params["amount_msats"].as_u64() {
        Some(a) if a > 0 => a,
        _ => return err_response("missing or zero amount_msats"),
    };

    match params["lock_type"].as_str().unwrap_or("htlc") {
        "htlc" => {}
        "ptlc" => {
            return err_response(
                "ptlc unsupported: hold-invoice PTLC needs LN-side support that doesn't exist yet",
            )
        }
        other => return err_response(format!("unknown lock_type {:?}", other)),
    }

    let payment_hash = match params["payment_hash"].as_str().and_then(parse_hex32) {
        Some(h) => h,
        None => return err_response("payment_hash must be 64 hex chars"),
    };

    let deposit = match state.deposits.iter().find(|d| d.ledger_id == ledger_id) {
        Some(d) => d.clone(),
        None => return err_response("bridge holds no deposit on that ledger"),
    };

    if amount_x_msats < RECEIVE_MIN_AMOUNT_MSATS || amount_x_msats > RECEIVE_MAX_AMOUNT_MSATS {
        return err_response(format!(
            "amount_msats out of range [{}, {}]",
            RECEIVE_MIN_AMOUNT_MSATS, RECEIVE_MAX_AMOUNT_MSATS
        ));
    }

    if !state.holds_supported {
        return err_response("bridge's Lightning backend does not support hold invoices");
    }

    // Refuse hashes we've seen before: re-using H across invoices would let
    // an old on-ledger reveal settle a new HTLC.
    if !register_payment_hash(&mut state.seen_hashes.lock().unwrap(), payment_hash) {
        return err_response("payment_hash already seen — generate a fresh preimage");
    }

    let service_fee_msats = service_fee_msats(
        state.fees.receive_fixed_msats,
        state.fees.receive_rate_bps,
        amount_x_msats,
    );
    // Operator transfer fee on the upcoming TransferLock (TransferFeeSchedule
    // math — same as htlc-agent's execute paths).
    let transfer_fee_msats = deposits_core::types::TransferFeeSchedule::new(
        deposit.operator_fee_fixed_msats,
        deposit.operator_fee_rate_bps,
    )
    .calculate_fee(amount_x_msats);

    let invoice_amount = amount_x_msats
        .saturating_add(service_fee_msats)
        .saturating_add(transfer_fee_msats);
    let hash_hex = hex::encode(payment_hash);

    let ln_c = ln.clone();
    let hash_hex_c = hash_hex.clone();
    let created = tokio::task::spawn_blocking(move || {
        ln_c.create_hold_invoice(
            invoice_amount,
            &hash_hex_c,
            "deposits-bridge",
            HOLD_INVOICE_EXPIRY_SECS,
            None,
        )
    })
    .await;

    let bolt11 = match created {
        Ok(Ok(b)) => b,
        Ok(Err(e)) => {
            // No invoice exists for this hash; let the wallet retry with it.
            state.seen_hashes.lock().unwrap().remove(&payment_hash);
            return err_response(format!("create_hold_invoice failed: {}", e));
        }
        Err(e) => {
            state.seen_hashes.lock().unwrap().remove(&payment_hash);
            return err_response(format!("create_hold_invoice task failed: {}", e));
        }
    };

    state.receives.lock().unwrap().push(PendingReceive {
        payment_hash,
        ledger_id,
        wallet_deposit_id,
        amount_x_msats,
        service_fee_msats,
        transfer_fee_msats,
        bolt11: bolt11.clone(),
        state: ReceiveState::AwaitingHtlc,
    });
    state.persist();

    eprintln!(
        "[RECEIVE] hold invoice issued: hash={}... X={} sf={} tf={}",
        &hash_hex[..16],
        amount_x_msats,
        service_fee_msats,
        transfer_fee_msats
    );

    serde_json::json!({
        "success": true,
        "result": {
            "bolt11": bolt11,
            "service_fee_msats": service_fee_msats,
            "transfer_fee_msats": transfer_fee_msats,
            "hold_window_blocks": state.fees.hold_window_blocks,
        }
    })
}

/// Handle `quote_invoice` (pay direction). Decodes the BOLT-11, quotes a
/// service fee, and stores the quote keyed by payment hash so the inbound
/// lock can be matched later.
fn handle_quote_invoice(state: &Arc<SharedState>, params: &serde_json::Value) -> serde_json::Value {
    let ledger_id = match params["ledger_id"].as_str() {
        Some(s) => s.to_string(),
        None => return err_response("missing ledger_id"),
    };
    let bolt11 = match params["bolt11"].as_str() {
        Some(s) => s.to_string(),
        None => return err_response("missing bolt11"),
    };

    let deposit = match state.deposits.iter().find(|d| d.ledger_id == ledger_id) {
        Some(d) => d,
        None => return err_response("bridge holds no deposit on that ledger"),
    };

    let invoice = match lightning_invoice::Bolt11Invoice::from_str(&bolt11) {
        Ok(i) => i,
        Err(e) => return err_response(format!("invalid bolt11: {}", e)),
    };
    let mut payment_hash = [0u8; 32];
    payment_hash.copy_from_slice(invoice.payment_hash().as_ref());
    let invoice_amount_msats = match invoice.amount_milli_satoshis() {
        Some(a) if a > 0 => a,
        _ => return err_response("amountless invoices not supported — bolt11 must carry an amount"),
    };

    let service_fee_msats = service_fee_msats(
        state.fees.pay_fixed_msats,
        state.fees.pay_rate_bps,
        invoice_amount_msats,
    );

    {
        let mut pays = state.pays.lock().unwrap();
        // Evict stale quotes (and finished entries past retention).
        pays.retain(|_, q| !quote_expired(q.age()));
        pays.insert(
            payment_hash,
            QuotedPay {
                payment_hash,
                bolt11,
                ledger_id,
                invoice_amount_msats,
                service_fee_msats,
                quoted_at_unix: now_unix(),
                state: PayState::Quoted,
            },
        );
    }
    state.persist();

    eprintln!(
        "[PAY] quoted: hash={}... amount={} sf={}",
        &hex::encode(payment_hash)[..16],
        invoice_amount_msats,
        service_fee_msats
    );

    serde_json::json!({
        "success": true,
        "result": {
            "bridge_deposit_id": deposit.deposit_id_hex,
            "service_fee_msats": service_fee_msats,
            "quote_expiry_secs": QUOTE_VALID_SECS,
            "min_lock_window_blocks": MIN_LOCK_WINDOW_BLOCKS,
        }
    })
}

// ─── LN backend async wrappers ──────────────────────────────────────────────
//
// The LightningBackend trait is synchronous (it blocks on subprocesses /
// HTTP); wrap each call in spawn_blocking so the bridge's event loop and
// poll loop stay responsive.

async fn ln_lookup_hold_invoice(
    ln: &Arc<dyn LightningBackend>,
    hash_hex: String,
) -> Result<HoldInvoiceState, String> {
    let ln = ln.clone();
    tokio::task::spawn_blocking(move || ln.lookup_hold_invoice(&hash_hex))
        .await
        .map_err(|e| format!("join: {}", e))?
        .map_err(|e| e.to_string())
}

async fn ln_settle_hold_invoice(
    ln: &Arc<dyn LightningBackend>,
    preimage_hex: String,
) -> Result<(), String> {
    let ln = ln.clone();
    tokio::task::spawn_blocking(move || ln.settle_hold_invoice(&preimage_hex))
        .await
        .map_err(|e| format!("join: {}", e))?
        .map_err(|e| e.to_string())
}

async fn ln_cancel_hold_invoice(
    ln: &Arc<dyn LightningBackend>,
    hash_hex: String,
) -> Result<(), String> {
    let ln = ln.clone();
    tokio::task::spawn_blocking(move || ln.cancel_hold_invoice(&hash_hex))
        .await
        .map_err(|e| format!("join: {}", e))?
        .map_err(|e| e.to_string())
}

async fn ln_pay_invoice(ln: &Arc<dyn LightningBackend>, bolt11: String) -> Result<String, String> {
    let ln = ln.clone();
    tokio::task::spawn_blocking(move || ln.pay_invoice(&bolt11))
        .await
        .map_err(|e| format!("join: {}", e))?
        .map_err(|e| e.to_string())
}

async fn ln_get_payment_preimage(
    ln: &Arc<dyn LightningBackend>,
    payment_id_hex: String,
) -> Result<Option<[u8; 32]>, String> {
    let ln = ln.clone();
    tokio::task::spawn_blocking(move || ln.get_payment_preimage(&payment_id_hex))
        .await
        .map_err(|e| format!("join: {}", e))?
        .map_err(|e| e.to_string())
}

/// Best block height from the LN backend's chain view. None when the
/// backend is unsynced or the call fails.
async fn ln_tip(ln: &Arc<dyn LightningBackend>) -> Option<u32> {
    let ln = ln.clone();
    tokio::task::spawn_blocking(move || ln.get_node_info())
        .await
        .ok()?
        .ok()?
        .current_best_block_height
}

// ─── Receive Poll Loop ──────────────────────────────────────────────────────

/// Every POLL_INTERVAL_SECS: drive AwaitingHtlc entries forward (lookup the
/// hold invoice, lock on-ledger when HTLCs park) and sweep Locked entries
/// whose window passed without a reveal.
async fn run_receive_poll_loop(
    state: Arc<SharedState>,
    transport: Arc<AgentTransport>,
    ln: Arc<dyn LightningBackend>,
    deposits_by_ledger: HashMap<String, AgentDeposit>,
) {
    loop {
        tokio::time::sleep(Duration::from_secs(POLL_INTERVAL_SECS)).await;

        // Snapshot the entries needing work; never hold the lock across LN
        // or ledger awaits.
        let awaiting: Vec<PendingReceive> = state
            .receives
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.state == ReceiveState::AwaitingHtlc)
            .cloned()
            .collect();
        let locked: Vec<PendingReceive> = state
            .receives
            .lock()
            .unwrap()
            .iter()
            .filter(|r| matches!(r.state, ReceiveState::Locked { .. }))
            .cloned()
            .collect();

        if awaiting.is_empty() && locked.is_empty() {
            continue;
        }

        let tip = ln_tip(&ln).await;

        for rcv in awaiting {
            let hash_hex = hex::encode(rcv.payment_hash);
            let st = match ln_lookup_hold_invoice(&ln, hash_hex.clone()).await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[POLL] lookup {}... failed: {}", &hash_hex[..16], e);
                    continue;
                }
            };
            match st {
                HoldInvoiceState::Open => {}
                HoldInvoiceState::Accepted { htlc_expiry_height } => {
                    let Some(tip) = tip.or(htlc_expiry_height) else {
                        eprintln!(
                            "[POLL] {}... accepted but no LN tip available — deferring lock",
                            &hash_hex[..16]
                        );
                        continue;
                    };
                    if htlc_expiry_height.is_none() {
                        eprintln!(
                            "[WARN] {}... accepted with no HTLC expiry height — using \
                             conservative T_ledger = tip + {}",
                            &hash_hex[..16],
                            ACCEPTED_NO_HEIGHT_FALLBACK_BLOCKS
                        );
                    }
                    let t_ledger = derive_t_ledger(htlc_expiry_height, tip);

                    let Some(dep) = deposits_by_ledger.get(&rcv.ledger_id) else {
                        eprintln!(
                            "[POLL] {}... no deposit on ledger {} — cannot lock",
                            &hash_hex[..16],
                            &rcv.ledger_id[..16]
                        );
                        continue;
                    };

                    eprintln!(
                        "[HTLC-PARKED] {}... expiry={:?} T_ledger={} → locking {} msats to {}",
                        &hash_hex[..16],
                        htlc_expiry_height,
                        t_ledger,
                        rcv.amount_x_msats,
                        hex::encode(rcv.wallet_deposit_id)
                    );

                    match execute_transfer_lock(
                        &transport,
                        dep,
                        &rcv.wallet_deposit_id,
                        rcv.amount_x_msats,
                        rcv.transfer_fee_msats,
                        &rcv.payment_hash,
                        t_ledger,
                        Some(&rcv.bolt11),
                    )
                    .await
                    {
                        Ok(tid) => {
                            eprintln!(
                                "[LOCKED] {}... transfer {}... t_ledger={}",
                                &hash_hex[..16],
                                hex::encode(&tid[..8]),
                                t_ledger
                            );
                            set_receive_state(
                                &state,
                                &rcv.payment_hash,
                                ReceiveState::Locked {
                                    transfer_id: tid,
                                    t_ledger,
                                },
                            );
                        }
                        Err(e) => {
                            // Stay in AwaitingHtlc; retried next poll. The
                            // HTLC keeps holding upstream — no funds at risk.
                            eprintln!("[FAIL] transfer_lock for {}...: {}", &hash_hex[..16], e);
                        }
                    }
                }
                HoldInvoiceState::Canceled => {
                    eprintln!(
                        "[POLL] {}... canceled/expired with no HTLC — dropping",
                        &hash_hex[..16]
                    );
                    set_receive_state(&state, &rcv.payment_hash, ReceiveState::Cancelled);
                    state
                        .stats
                        .receives_cancelled
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                HoldInvoiceState::Settled => {
                    // Shouldn't happen pre-lock (we never handed out r), but
                    // record it rather than poll forever.
                    eprintln!("[POLL] {}... unexpectedly settled pre-lock", &hash_hex[..16]);
                    set_receive_state(&state, &rcv.payment_hash, ReceiveState::Settled);
                    state
                        .stats
                        .receives_settled
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            }
        }

        // Timeout sweep: lock window passed without a reveal → release the
        // upstream HTLCs back to the payer.
        if let Some(tip) = tip {
            for rcv in locked {
                let ReceiveState::Locked { t_ledger, .. } = rcv.state else {
                    continue;
                };
                if tip > t_ledger.saturating_add(TIMEOUT_SWEEP_GRACE_BLOCKS) {
                    let hash_hex = hex::encode(rcv.payment_hash);
                    eprintln!(
                        "[SWEEP] {}... tip {} passed t_ledger {} + {} — canceling hold invoice",
                        &hash_hex[..16],
                        tip,
                        t_ledger,
                        TIMEOUT_SWEEP_GRACE_BLOCKS
                    );
                    match ln_cancel_hold_invoice(&ln, hash_hex.clone()).await {
                        Ok(()) => {
                            set_receive_state(&state, &rcv.payment_hash, ReceiveState::Cancelled);
                            state
                                .stats
                                .receives_cancelled
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                        Err(e) => {
                            eprintln!(
                                "[FAIL] cancel_hold_invoice {}...: {} (will retry)",
                                &hash_hex[..16],
                                e
                            );
                        }
                    }
                }
            }
        }
    }
}

/// Transition a receive entry and persist the state file.
fn set_receive_state(state: &Arc<SharedState>, payment_hash: &[u8; 32], new_state: ReceiveState) {
    {
        let mut receives = state.receives.lock().unwrap();
        if let Some(r) = receives.iter_mut().find(|r| r.payment_hash == *payment_hash) {
            r.state = new_state;
        }
    }
    state.persist();
}

// ─── Receive Settle (witness scraped off Kind 9100) ────────────────────────

/// The wallet revealed `r` on-ledger for one of our receive locks. Settle the
/// upstream HTLC. Retries up to 5 times with backoff — failure here means the
/// on-ledger credit landed but the LN claim didn't (funds at risk), so log
/// LOUDLY.
async fn settle_receive(
    state: Arc<SharedState>,
    ln: Arc<dyn LightningBackend>,
    payment_hash: [u8; 32],
    preimage: [u8; 32],
) {
    let hash_hex = hex::encode(payment_hash);
    let preimage_hex = hex::encode(preimage);
    let mut backoff = Duration::from_secs(1);
    for attempt in 1..=5u32 {
        match ln_settle_hold_invoice(&ln, preimage_hex.clone()).await {
            Ok(()) => {
                eprintln!("[SETTLED] {}... upstream HTLC claimed", &hash_hex[..16]);
                set_receive_state(&state, &payment_hash, ReceiveState::Settled);
                state
                    .stats
                    .receives_settled
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return;
            }
            Err(e) => {
                eprintln!(
                    "[CRITICAL] settle_hold_invoice {}... attempt {}/5 failed: {} — \
                     on-ledger credit landed but LN claim has not; FUNDS AT RISK",
                    &hash_hex[..16],
                    attempt,
                    e
                );
                if attempt < 5 {
                    tokio::time::sleep(backoff).await;
                    backoff *= 2;
                }
            }
        }
    }
    eprintln!(
        "[CRITICAL] {}... settle FAILED after 5 attempts. Preimage {} is public on the \
         relay — settle manually against the LN node before the HTLC expires.",
        &hash_hex[..16],
        preimage_hex
    );
}

// ─── Pay Execution ──────────────────────────────────────────────────────────

/// An inbound lock matched a stored quote: pay the BOLT-11, learn the
/// preimage, and claim the lock via TransferComplete.
async fn execute_pay(
    state: Arc<SharedState>,
    transport: Arc<AgentTransport>,
    ln: Arc<dyn LightningBackend>,
    payment_hash: [u8; 32],
    bolt11: String,
    ledger_id: String,
    transfer_id: [u8; 32],
) {
    let hash_hex = hex::encode(payment_hash);

    let fail = |state: &Arc<SharedState>, reason: String| {
        eprintln!(
            "[PAY-FAIL] {}...: {} — lock times out on its own; wallet refunded per DEP-09",
            &hash_hex[..16],
            reason
        );
        if let Some(q) = state.pays.lock().unwrap().get_mut(&payment_hash) {
            q.state = PayState::Failed(reason);
        }
        state.persist();
        state
            .stats
            .pays_failed
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    };

    // LockSeen → Paying: about to hand the BOLT-11 to the LN node. Persisted
    // BEFORE paying — if we crash past this point, restart recovery re-enters
    // here and the preimage check below makes the retry idempotent.
    if let Some(q) = state.pays.lock().unwrap().get_mut(&payment_hash) {
        q.state = PayState::Paying { transfer_id };
    }
    state.persist();

    // Recovery-safe ordering: a crash-restart may re-run this for an invoice
    // we ALREADY paid. Check for the preimage first; only pay when absent.
    let mut preimage: Option<[u8; 32]> = ln_get_payment_preimage(&ln, hash_hex.clone())
        .await
        .ok()
        .flatten();

    if preimage.is_none() {
        if let Err(e) = ln_pay_invoice(&ln, bolt11).await {
            // "already paid"/"in flight" from the LN node's payment-hash
            // dedup is success-shaped here — fall through to the poll.
            let msg = e.to_lowercase();
            if !(msg.contains("already") || msg.contains("in flight") || msg.contains("in-flight"))
            {
                fail(&state, format!("pay_invoice failed: {}", e));
                return;
            }
            eprintln!(
                "[PAY] {}... pay_invoice says '{}' — treating as paid/in-flight, polling preimage",
                &hash_hex[..16],
                e
            );
        }
    }

    // Test hook: simulate the worst-case crash window — invoice paid,
    // lock not yet claimed. Used by the restart drill.
    if std::env::var("BRIDGE_CRASH_AFTER_PAY").is_ok() {
        eprintln!("[CRASH-HOOK] BRIDGE_CRASH_AFTER_PAY set — exiting after pay, before claim");
        std::process::exit(42);
    }

    // Payment may settle async on some backends — poll for the preimage.
    if preimage.is_none() {
        for _ in 0..30 {
            match ln_get_payment_preimage(&ln, hash_hex.clone()).await {
                Ok(Some(p)) => {
                    preimage = Some(p);
                    break;
                }
                Ok(None) => {}
                Err(e) => {
                    eprintln!("[PAY] {}... preimage lookup error: {}", &hash_hex[..16], e);
                }
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    let Some(preimage) = preimage else {
        fail(
            &state,
            "paid (or in flight) but no preimage after 30s".to_string(),
        );
        return;
    };

    match execute_transfer_complete(
        &transport,
        &ledger_id,
        &transfer_id,
        &WitnessMaterial::Preimage(preimage),
    )
    .await
    {
        Ok(()) => {
            eprintln!(
                "[PAY-DONE] {}... invoice paid, lock {}... claimed",
                &hash_hex[..16],
                hex::encode(&transfer_id[..8])
            );
            if let Some(q) = state.pays.lock().unwrap().get_mut(&payment_hash) {
                q.state = PayState::Completed;
            }
            state.persist();
            state
                .stats
                .pays_completed
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        Err(e) => {
            // Invoice IS paid; the claim failed. Retryable by hand — keep the
            // preimage in the log.
            fail(
                &state,
                format!(
                    "invoice paid but transfer_complete failed: {} (preimage {})",
                    e,
                    hex::encode(preimage)
                ),
            );
        }
    }
}

// ─── HTTP Status API ────────────────────────────────────────────────────────

async fn run_api_server(port: u16, state: Arc<SharedState>) {
    let listener = match tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port)).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[API] failed to bind port {}: {}", port, e);
            return;
        }
    };
    eprintln!("[API] listening on http://127.0.0.1:{}", port);

    loop {
        let (mut stream, _) = match listener.accept().await {
            Ok(s) => s,
            Err(_) => continue,
        };
        let state = state.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let n = match tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await {
                Ok(n) if n > 0 => n,
                _ => return,
            };
            let request = String::from_utf8_lossy(&buf[..n]);
            let path = request.split_whitespace().nth(1).unwrap_or("/");

            let (status, body) = if path == "/status" {
                let (recv_active, recv_settled_total, recv_cancelled_total) = {
                    let receives = state.receives.lock().unwrap();
                    let active = receives
                        .iter()
                        .filter(|r| {
                            matches!(
                                r.state,
                                ReceiveState::AwaitingHtlc | ReceiveState::Locked { .. }
                            )
                        })
                        .count();
                    let settled = receives
                        .iter()
                        .filter(|r| r.state == ReceiveState::Settled)
                        .count();
                    let cancelled = receives
                        .iter()
                        .filter(|r| r.state == ReceiveState::Cancelled)
                        .count();
                    (active, settled, cancelled)
                };
                let (quotes_open, pays_active) = {
                    let pays = state.pays.lock().unwrap();
                    let quotes = pays
                        .values()
                        .filter(|q| q.state == PayState::Quoted)
                        .count();
                    let active = pays
                        .values()
                        .filter(|q| {
                            matches!(
                                q.state,
                                PayState::LockSeen { .. } | PayState::Paying { .. }
                            )
                        })
                        .count();
                    (quotes, active)
                };
                use std::sync::atomic::Ordering::Relaxed;
                let json = serde_json::json!({
                    "uptime_secs": state.started_at.elapsed().as_secs(),
                    "deposits": state.deposits.len(),
                    "holds_supported": state.holds_supported,
                    "receives_active": recv_active,
                    "receives_settled": state.stats.receives_settled.load(Relaxed),
                    "receives_cancelled": state.stats.receives_cancelled.load(Relaxed),
                    "receives_settled_in_table": recv_settled_total,
                    "receives_cancelled_in_table": recv_cancelled_total,
                    "quotes_open": quotes_open,
                    "pays_active": pays_active,
                    "pays_completed": state.stats.pays_completed.load(Relaxed),
                    "pays_failed": state.stats.pays_failed.load(Relaxed),
                    "receive_fee": {
                        "fixed_msats": state.fees.receive_fixed_msats,
                        "rate_bps": state.fees.receive_rate_bps,
                    },
                    "pay_fee": {
                        "fixed_msats": state.fees.pay_fixed_msats,
                        "rate_bps": state.fees.pay_rate_bps,
                    },
                    "hold_window_blocks": state.fees.hold_window_blocks,
                });
                ("200 OK", serde_json::to_string_pretty(&json).unwrap())
            } else {
                let json = serde_json::json!({ "endpoints": ["/status"] });
                (
                    "404 Not Found",
                    serde_json::to_string_pretty(&json).unwrap(),
                )
            };

            let response = format!(
                "HTTP/1.1 {}\r\n\
                 Content-Type: application/json\r\n\
                 Access-Control-Allow-Origin: *\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n{}",
                status,
                body.len(),
                body,
            );
            let _ = stream.write_all(response.as_bytes()).await;
        });
    }
}

// ─── CLI Parsing ────────────────────────────────────────────────────────────

fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(path)
}

fn load_or_generate_seed(data_dir: &PathBuf) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    std::fs::create_dir_all(data_dir)?;
    let seed_file = data_dir.join("seed.hex");
    if seed_file.exists() {
        let hex_str = std::fs::read_to_string(&seed_file)?.trim().to_string();
        let bytes = hex::decode(&hex_str)?;
        if bytes.len() != 32 {
            return Err(format!("Seed must be 32 bytes, got {}", bytes.len()).into());
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes);
        eprintln!("  Loaded seed from {}", seed_file.display());
        Ok(seed)
    } else {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        std::fs::write(&seed_file, hex::encode(seed))?;
        eprintln!("  Generated new seed at {}", seed_file.display());
        Ok(seed)
    }
}

fn parse_args() -> Result<Config, Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let mut config = Config {
        relay: "ws://localhost:7801".to_string(),
        ledgers_relay: std::env::var("RELAY_LEDGERS")
            .unwrap_or_else(|_| "ws://localhost:17779".to_string()),
        network: bitcoin::Network::Regtest,
        nodes: Vec::new(),
        fees: BridgeFees {
            receive_fixed_msats: env_u64("BRIDGE_RECEIVE_FEE_FIXED_MSATS", 100),
            receive_rate_bps: env_u64("BRIDGE_RECEIVE_FEE_BPS", 30),
            pay_fixed_msats: env_u64("BRIDGE_PAY_FEE_FIXED_MSATS", 200),
            pay_rate_bps: env_u64("BRIDGE_PAY_FEE_BPS", 50),
            hold_window_blocks: env_u64("BRIDGE_HOLD_WINDOW_BLOCKS", 18) as u32,
        },
        api_port: env_u64("BRIDGE_API_PORT", 9740) as u16,
    };

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--relay" => {
                i += 1;
                config.relay = args[i].clone();
            }
            "--ledgers-relay" | "--slow-relay" => {
                i += 1;
                config.ledgers_relay = args[i].clone();
            }
            "--network" => {
                i += 1;
                config.network = match args[i].as_str() {
                    "regtest" => bitcoin::Network::Regtest,
                    "testnet" | "testnet3" => bitcoin::Network::Testnet,
                    "bitcoin" | "mainnet" => bitcoin::Network::Bitcoin,
                    "signet" => bitcoin::Network::Signet,
                    _ => return Err(format!("Unknown network: {}", args[i]).into()),
                };
            }
            "--node" => {
                i += 1;
                let parts: Vec<&str> = args[i].splitn(2, ':').collect();
                if parts.len() != 2 {
                    return Err(format!("--node must be name:data_dir, got: {}", args[i]).into());
                }
                let data_dir = expand_tilde(parts[1]);
                let seed = load_or_generate_seed(&data_dir)?;
                config.nodes.push(NodeConfig {
                    name: parts[0].to_string(),
                    seed,
                    data_dir,
                });
            }
            "--api-port" => {
                i += 1;
                config.api_port = args[i].parse()?;
            }
            "--help" | "-h" => {
                eprintln!("Usage: deposits-bridge [OPTIONS]");
                eprintln!();
                eprintln!("Options:");
                eprintln!(
                    "  --relay <url>              Primary relay (default: ws://localhost:7801)"
                );
                eprintln!("  --ledgers-relay <url>      Durable relay for advertisements (default: $RELAY_LEDGERS or ws://localhost:17779)");
                eprintln!("  --network <net>            Network (default: regtest)");
                eprintln!("  --node <name:data_dir>     Bridge identity and data directory (seed.hex + deposits.json)");
                eprintln!("  --api-port <port>          HTTP status port (default: $BRIDGE_API_PORT or 9740)");
                eprintln!();
                eprintln!("Env:");
                eprintln!("  LIGHTNING_BACKEND               ldk|lnd|cln (default ldk)");
                eprintln!("  BRIDGE_RECEIVE_FEE_FIXED_MSATS  receive service fee, fixed (default 100)");
                eprintln!("  BRIDGE_RECEIVE_FEE_BPS          receive service fee, bps (default 30)");
                eprintln!("  BRIDGE_PAY_FEE_FIXED_MSATS      pay service fee, fixed (default 200)");
                eprintln!("  BRIDGE_PAY_FEE_BPS              pay service fee, bps (default 50)");
                eprintln!("  BRIDGE_HOLD_WINDOW_BLOCKS       advertised typical hold window (default 18)");
                std::process::exit(0);
            }
            other => return Err(format!("Unknown option: {}", other).into()),
        }
        i += 1;
    }

    if config.nodes.is_empty() {
        return Err("At least one --node is required".into());
    }

    Ok(config)
}

// ─── Helpers ────────────────────────────────────────────────────────────────

fn sha256_of(bytes: &[u8; 32]) -> [u8; 32] {
    let mut e = sha256::Hash::engine();
    e.input(bytes);
    sha256::Hash::from_engine(e).to_byte_array()
}

fn network_str(network: bitcoin::Network) -> &'static str {
    match network {
        bitcoin::Network::Bitcoin => "bitcoin",
        bitcoin::Network::Testnet => "testnet",
        bitcoin::Network::Signet => "signet",
        bitcoin::Network::Regtest => "regtest",
        _ => "unknown",
    }
}

// ─── Main ───────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = parse_args()?;

    eprintln!("=== deposits-bridge ===");
    eprintln!("Relay:         {}", config.relay);
    eprintln!("Ledgers relay: {}", config.ledgers_relay);
    eprintln!(
        "Receive fee:   {} msats + {} bps",
        config.fees.receive_fixed_msats, config.fees.receive_rate_bps
    );
    eprintln!(
        "Pay fee:       {} msats + {} bps",
        config.fees.pay_fixed_msats, config.fees.pay_rate_bps
    );
    eprintln!(
        "Hold window:   {} blocks (advertised; actual is measured per-HTLC)",
        config.fees.hold_window_blocks
    );
    eprintln!("Settle margin: {} blocks (Δ)", BRIDGE_SETTLE_MARGIN_BLOCKS);
    eprintln!();

    // Load deposits from all nodes
    let mut deposits: Vec<AgentDeposit> = Vec::new();
    for node in &config.nodes {
        let node_deposits = load_deposits(node, config.network)?;
        deposits.extend(node_deposits);
    }
    if deposits.is_empty() {
        return Err("No deposits found. Create deposits first using the wallet.".into());
    }

    let deposit_id_hexes: Vec<String> = deposits.iter().map(|d| d.deposit_id_hex.clone()).collect();
    let ledger_ids: Vec<String> = {
        let mut ids: Vec<String> = deposits.iter().map(|d| d.ledger_id.clone()).collect();
        ids.sort();
        ids.dedup();
        ids
    };

    eprintln!(
        "Deposits: {} across {} ledgers",
        deposits.len(),
        ledger_ids.len()
    );
    for d in &deposits {
        eprintln!(
            "  {} — ledger {}... deposit {}...",
            d.alias,
            &d.ledger_id[..16],
            &d.deposit_id_hex[..16]
        );
    }
    eprintln!();

    // Lightning backend (env-selected). Construction happens off the async
    // runtime: the blocking HTTP client inside (reqwest::blocking) creates
    // and drops its own mini-runtime, which panics inside a tokio context.
    let ln: Arc<dyn LightningBackend> =
        tokio::task::spawn_blocking(|| Arc::from(lightning_backend::from_env())).await?;
    let holds_supported = {
        let ln_c = ln.clone();
        tokio::task::spawn_blocking(move || ln_c.supports_hold_invoices())
            .await
            .unwrap_or(false)
    };
    eprintln!(
        "Lightning backend: hold invoices {}",
        if holds_supported {
            "supported"
        } else {
            "NOT supported — receive direction disabled"
        }
    );

    // Discover relay routing and operator fees from advertisements
    eprintln!("Fetching operator advertisements...");
    let ledger_ad_map = fetch_advertisements(&config.ledgers_relay).await?;
    let mut relay_urls: Vec<String> = vec![config.relay.clone()];
    for info in ledger_ad_map.values() {
        if !relay_urls.contains(&info.relay_url) {
            relay_urls.push(info.relay_url.clone());
        }
    }
    eprintln!("Connected to {} relays", relay_urls.len());

    // Apply operator transfer fees; fall back to the protocol default
    // schedule when the advertisement omits them (same as htlc-agent).
    let default_fee = deposits_core::types::TransferFeeSchedule::default();
    for d in &mut deposits {
        let (fixed, rate) = match ledger_ad_map.get(&d.ledger_id) {
            Some(info) if info.transfer_fee_fixed_msats > 0 || info.transfer_fee_rate_bps > 0 => {
                (info.transfer_fee_fixed_msats, info.transfer_fee_rate_bps)
            }
            _ => (default_fee.fixed_msats, default_fee.rate_bps),
        };
        d.operator_fee_fixed_msats = fixed;
        d.operator_fee_rate_bps = rate;
        eprintln!(
            "  {} operator transfer fee: {} msats + {} bps",
            d.alias, fixed, rate
        );
    }

    // Reload persisted receive state (crash recovery: resume polling)
    let state_file = config.nodes[0].data_dir.join("bridge-state.json");
    let persisted = load_persisted_state(&state_file);
    let resumable = persisted
        .receives
        .iter()
        .filter(|r| {
            matches!(
                r.state,
                ReceiveState::AwaitingHtlc | ReceiveState::Locked { .. }
            )
        })
        .count();
    if resumable > 0 {
        eprintln!(
            "Resuming {} in-flight receive(s) from {}",
            resumable,
            state_file.display()
        );
    }
    let seen_hashes: HashSet<[u8; 32]> = persisted
        .seen_hashes
        .iter()
        .filter_map(|s| parse_hex32(s))
        .collect();

    // Transport
    let nostr_key = derive_secret_key(&config.nodes[0].seed, config.network)?;
    let (transport, mut update_rx) =
        AgentTransport::new(nostr_key, &relay_urls, &deposit_id_hexes, &ledger_ids).await?;
    let transport = Arc::new(transport);
    eprintln!("bridge pubkey: {}", transport.keys.public_key().to_hex());

    let deposits_by_ledger: HashMap<String, AgentDeposit> = deposits
        .iter()
        .map(|d| (d.ledger_id.clone(), d.clone()))
        .collect();

    let pays_map: HashMap<[u8; 32], QuotedPay> = persisted
        .pays
        .into_iter()
        .filter(|q| {
            // Drop quotes that expired while we were down; keep everything
            // in-flight or finished (retention pruning handles the rest).
            !(q.state == PayState::Quoted && quote_expired(q.age()))
        })
        .map(|q| (q.payment_hash, q))
        .collect();
    let recoverable: Vec<QuotedPay> = pays_map
        .values()
        .filter(|q| {
            matches!(
                q.state,
                PayState::LockSeen { .. } | PayState::Paying { .. }
            )
        })
        .cloned()
        .collect();
    if !recoverable.is_empty() {
        eprintln!(
            "Resuming {} in-flight pay(s) from {}",
            recoverable.len(),
            state_file.display()
        );
    }

    let shared = Arc::new(SharedState {
        deposits: deposits.clone(),
        receives: Mutex::new(persisted.receives),
        pays: Mutex::new(pays_map),
        seen_hashes: Mutex::new(seen_hashes),
        state_file,
        stats: BridgeStats::default(),
        started_at: Instant::now(),
        fees: config.fees,
        holds_supported,
    });

    // HTTP status endpoint
    tokio::spawn(run_api_server(config.api_port, shared.clone()));

    // Crash recovery for in-flight pays: re-drive each through execute_pay.
    // Its preimage-before-pay ordering makes the retry idempotent — if the
    // pre-crash payment went through, we claim with the found preimage; if
    // it didn't, we pay now (the LN node dedups by payment_hash either way).
    for q in recoverable {
        let (transfer_id, label) = match q.state {
            PayState::LockSeen { transfer_id, .. } => (transfer_id, "lock-seen"),
            PayState::Paying { transfer_id } => (transfer_id, "paying"),
            _ => unreachable!("recoverable filter"),
        };
        eprintln!(
            "[RECOVER] pay {}... ({}) — resuming",
            &hex::encode(q.payment_hash)[..16],
            label
        );
        tokio::spawn(execute_pay(
            shared.clone(),
            transport.clone(),
            ln.clone(),
            q.payment_hash,
            q.bolt11,
            q.ledger_id,
            transfer_id,
        ));
    }

    // Kind 39104 advertisement, now + every AD_REPUBLISH_SECS
    let net = network_str(config.network);
    let bridge_keys = transport.keys.clone();
    match publish_bridge_advertisement(
        &bridge_keys,
        &config.ledgers_relay,
        &deposits,
        &config.fees,
        net,
    )
    .await
    {
        Ok(()) => eprintln!("Published bridge advertisement to {}", config.ledgers_relay),
        Err(e) => eprintln!("Warning: failed to publish advertisement: {}", e),
    }
    {
        let ad_keys = bridge_keys.clone();
        let ad_relay = config.ledgers_relay.clone();
        let ad_deposits = deposits.clone();
        let ad_fees = config.fees;
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(AD_REPUBLISH_SECS)).await;
                if let Err(e) = publish_bridge_advertisement(
                    &ad_keys,
                    &ad_relay,
                    &ad_deposits,
                    &ad_fees,
                    net,
                )
                .await
                {
                    eprintln!("Warning: ad republish failed: {}", e);
                }
            }
        });
    }

    // Receive poll loop
    tokio::spawn(run_receive_poll_loop(
        shared.clone(),
        transport.clone(),
        ln.clone(),
        deposits_by_ledger,
    ));

    eprintln!("Listening for bridge requests and ledger updates...\n");

    // Main event loop
    loop {
        let evt = match update_rx.recv().await {
            Some(e) => e,
            None => {
                eprintln!("Update channel closed, shutting down");
                break;
            }
        };

        match evt {
            UpdateEvent::BridgeRequest {
                event_id,
                ledger_id,
                action,
                params,
            } => {
                eprintln!("[REQ] {} from event {}...", action, &event_id[..16]);
                let state_c = shared.clone();
                let ln_c = ln.clone();
                let transport_c = transport.clone();
                tokio::spawn(async move {
                    let response = match action.as_str() {
                        "issue_hold_invoice" => {
                            handle_issue_hold_invoice(&state_c, &ln_c, &params).await
                        }
                        "quote_invoice" => handle_quote_invoice(&state_c, &params),
                        _ => err_response(format!("unknown action {:?}", action)),
                    };
                    if let Err(e) = transport_c
                        .send_response(&event_id, &ledger_id, response)
                        .await
                    {
                        eprintln!("  Failed to send response: {}", e);
                    }
                });
            }

            UpdateEvent::WitnessRevealed {
                ledger_id,
                transfer_id,
                material,
            } => {
                // Receive path: did the wallet just reveal r for one of our
                // locks?
                let matched = shared.receives.lock().unwrap().iter().find_map(|r| {
                    match r.state {
                        ReceiveState::Locked { transfer_id: tid, .. } if tid == transfer_id => {
                            Some(r.payment_hash)
                        }
                        _ => None,
                    }
                });

                let Some(payment_hash) = matched else {
                    continue; // not one of ours (e.g. our own pay-side claim)
                };

                let WitnessMaterial::Preimage(preimage) = material;
                if sha256_of(&preimage) != payment_hash {
                    eprintln!(
                        "[WITNESS] transfer {}... witness does not hash to our payment_hash \
                         — ignoring",
                        hex::encode(&transfer_id[..8])
                    );
                    continue;
                }

                eprintln!(
                    "[WITNESS] preimage revealed on ledger {}... for transfer {}... — settling",
                    &ledger_id[..16],
                    hex::encode(&transfer_id[..8])
                );
                tokio::spawn(settle_receive(
                    shared.clone(),
                    ln.clone(),
                    payment_hash,
                    preimage,
                ));
            }

            UpdateEvent::InboundLock(lock) => {
                let hash_hex = hex::encode(lock.hash);
                eprintln!(
                    "[INBOUND] {} msats on ledger {}... hash={}... timeout={}",
                    lock.amount_msats,
                    &lock.ledger_id[..16],
                    &hash_hex[..16],
                    lock.timeout_height,
                );

                // Disambiguation (DEP-10): a hash belonging to a receive flow
                // must never trigger the pay path. Receive locks are outbound
                // from us (destination = wallet) so the our-deposit
                // destination filter in decode_update_event already excludes
                // them; this guards against a malicious lock TO us re-using a
                // receive hash.
                let is_receive_hash = shared
                    .receives
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|r| r.payment_hash == lock.hash);
                if is_receive_hash {
                    eprintln!("  [SKIP] hash belongs to a pending receive — not a pay lock");
                    continue;
                }

                // Match against a stored, unexpired quote.
                let quote = {
                    let pays = shared.pays.lock().unwrap();
                    pays.get(&lock.hash).and_then(|q| {
                        if q.state == PayState::Quoted && !quote_expired(q.age()) {
                            Some((
                                q.bolt11.clone(),
                                q.ledger_id.clone(),
                                q.invoice_amount_msats,
                                q.service_fee_msats,
                            ))
                        } else {
                            None
                        }
                    })
                };
                let Some((bolt11, quote_ledger, invoice_amount, service_fee)) = quote else {
                    eprintln!("  [SKIP] no live quote for this hash — ignoring lock");
                    continue;
                };

                // Kind 9100 `#l` tags are truncated (16 chars); resolve the
                // lock's ledger against the full ids we hold deposits on
                // before comparing — `e8ae…` IS `e8ae…<48 more>`.
                let lock_ledger_full = shared
                    .deposits
                    .iter()
                    .map(|d| &d.ledger_id)
                    .find(|l| l.starts_with(&lock.ledger_id))
                    .cloned()
                    .unwrap_or_else(|| lock.ledger_id.clone());
                if lock_ledger_full != quote_ledger {
                    eprintln!(
                        "  [REFUSE] lock arrived on ledger {} but quote was for {}...",
                        lock.ledger_id,
                        &quote_ledger[..16]
                    );
                    continue;
                }

                let required = invoice_amount.saturating_add(service_fee);
                if lock.amount_msats < required {
                    eprintln!(
                        "  [REFUSE] lock amount {} < invoice {} + service fee {} — ignoring",
                        lock.amount_msats, invoice_amount, service_fee
                    );
                    continue;
                }

                let tip = ln_tip(&ln).await;
                let Some(tip) = tip else {
                    eprintln!("  [REFUSE] LN tip unavailable — cannot verify lock window");
                    continue;
                };
                if lock.timeout_height < tip.saturating_add(MIN_LOCK_WINDOW_BLOCKS) {
                    eprintln!(
                        "  [REFUSE] lock window too short: timeout {} < tip {} + {}",
                        lock.timeout_height, tip, MIN_LOCK_WINDOW_BLOCKS
                    );
                    continue;
                }

                {
                    let mut pays = shared.pays.lock().unwrap();
                    if let Some(q) = pays.get_mut(&lock.hash) {
                        q.state = PayState::LockSeen {
                            transfer_id: lock.transfer_id,
                            amount_msats: lock.amount_msats,
                        };
                    }
                }
                shared.persist();

                eprintln!(
                    "  [PAY] lock accepted from {} — paying invoice ({} msats)",
                    hex::encode(lock.source_deposit_id),
                    invoice_amount
                );
                tokio::spawn(execute_pay(
                    shared.clone(),
                    transport.clone(),
                    ln.clone(),
                    lock.hash,
                    bolt11,
                    lock_ledger_full,
                    lock.transfer_id,
                ));
            }
        }
    }

    Ok(())
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_fee_matches_dep04_ad_defaults() {
        // Receive defaults: 100 fixed + 30 bps. 1_000_000 msats → 100 + 3000.
        assert_eq!(service_fee_msats(100, 30, 1_000_000), 3_100);
        // Pay defaults: 200 fixed + 50 bps. 2_000_000 msats → 200 + 10_000.
        assert_eq!(service_fee_msats(200, 50, 2_000_000), 10_200);
        // Zero amount → fixed only.
        assert_eq!(service_fee_msats(100, 30, 0), 100);
        // No u64 overflow on huge amounts (u128 intermediate).
        let huge = service_fee_msats(0, 10_000, u64::MAX);
        assert_eq!(huge, u64::MAX); // 100% of u64::MAX
    }

    #[test]
    fn t_ledger_is_measured_expiry_minus_delta() {
        // Measured hold window: T_ledger = htlc_expiry − Δ (Δ = 6).
        assert_eq!(derive_t_ledger(Some(120), 999), 114);
        // The LN tip is irrelevant when the expiry is measured.
        assert_eq!(derive_t_ledger(Some(120), 0), 114);
        // Saturates instead of wrapping for absurdly low expiries.
        assert_eq!(derive_t_ledger(Some(3), 0), 0);
    }

    #[test]
    fn t_ledger_accepted_none_falls_back_to_tip_plus_12() {
        // Backend accepted but reported no height → conservative tip + 12.
        assert_eq!(derive_t_ledger(None, 100), 112);
        assert_eq!(derive_t_ledger(None, 0), 12);
        // Tip near u32::MAX saturates.
        assert_eq!(derive_t_ledger(None, u32::MAX), u32::MAX);
    }

    #[test]
    fn seen_hashes_are_refused_on_reuse() {
        let mut seen = HashSet::new();
        let h1 = [1u8; 32];
        let h2 = [2u8; 32];
        assert!(register_payment_hash(&mut seen, h1), "first use accepted");
        assert!(
            !register_payment_hash(&mut seen, h1),
            "re-use of H must be refused — an old on-ledger reveal would settle a new HTLC"
        );
        assert!(register_payment_hash(&mut seen, h2), "fresh hash accepted");
    }

    #[test]
    fn quote_expiry_boundaries() {
        assert!(!quote_expired(Duration::from_secs(0)));
        assert!(!quote_expired(Duration::from_secs(QUOTE_RETENTION_SECS - 1)));
        assert!(quote_expired(Duration::from_secs(QUOTE_RETENTION_SECS)));
        // The advertised validity window is tighter than the retention window
        // (a wallet locking slightly late is still served).
        assert!(QUOTE_VALID_SECS < QUOTE_RETENTION_SECS);
    }

    #[test]
    fn sha256_script_extraction() {
        let h = [0xabu8; 32];
        let script = format!("sha256({})", hex::encode(h));
        assert_eq!(extract_sha256_hash_from_script(&script), Some(h));
        // Pointlock and malformed scripts are not bridge business.
        assert_eq!(
            extract_sha256_hash_from_script(&format!("pointlock({})", hex::encode([2u8; 33]))),
            None
        );
        assert_eq!(extract_sha256_hash_from_script("sha256(zz)"), None);
        assert_eq!(extract_sha256_hash_from_script("sha256(abcd)"), None);
    }

    #[test]
    fn state_file_roundtrip() {
        let doc = PersistedState {
            seen_hashes: vec![hex::encode([7u8; 32])],
            receives: vec![
                PendingReceive {
                    payment_hash: [1u8; 32],
                    ledger_id: "aa".repeat(32),
                    wallet_deposit_id: [2u8; 16],
                    amount_x_msats: 250_000,
                    service_fee_msats: 175,
                    transfer_fee_msats: 502,
                    bolt11: "lnbcrt...".to_string(),
                    state: ReceiveState::AwaitingHtlc,
                },
                PendingReceive {
                    payment_hash: [3u8; 32],
                    ledger_id: "bb".repeat(32),
                    wallet_deposit_id: [4u8; 16],
                    amount_x_msats: 1_000_000,
                    service_fee_msats: 3_100,
                    transfer_fee_msats: 2_002,
                    bolt11: "lnbcrt1...".to_string(),
                    state: ReceiveState::Locked {
                        transfer_id: [5u8; 32],
                        t_ledger: 114,
                    },
                },
            ],
            pays: vec![QuotedPay {
                payment_hash: [6u8; 32],
                bolt11: "lnbcrt9...".to_string(),
                ledger_id: "cc".repeat(32),
                invoice_amount_msats: 1_000_000,
                service_fee_msats: 5_200,
                quoted_at_unix: 1_700_000_000,
                state: PayState::Paying {
                    transfer_id: [8u8; 32],
                },
            }],
        };
        let json = serde_json::to_string(&doc).unwrap();
        // Byte arrays persist as hex strings.
        assert!(json.contains(&hex::encode([1u8; 32])));
        assert!(json.contains(&hex::encode([5u8; 32])));
        let back: PersistedState = serde_json::from_str(&json).unwrap();
        assert_eq!(back.receives.len(), 2);
        assert_eq!(back.pays.len(), 1);
        assert_eq!(back.pays[0].payment_hash, [6u8; 32]);
        assert_eq!(
            back.pays[0].state,
            PayState::Paying {
                transfer_id: [8u8; 32]
            }
        );
        // Older state files (no `pays` key) still load.
        let legacy: PersistedState =
            serde_json::from_str(r#"{"seen_hashes":[],"receives":[]}"#).unwrap();
        assert!(legacy.pays.is_empty());
        assert_eq!(back.receives[0].payment_hash, [1u8; 32]);
        assert_eq!(back.receives[0].state, ReceiveState::AwaitingHtlc);
        assert_eq!(
            back.receives[1].state,
            ReceiveState::Locked {
                transfer_id: [5u8; 32],
                t_ledger: 114
            }
        );
        assert_eq!(back.seen_hashes, vec![hex::encode([7u8; 32])]);
    }

    #[test]
    fn preimage_hash_check() {
        let preimage = [9u8; 32];
        let hash = sha256_of(&preimage);
        assert_ne!(hash, preimage);
        assert_eq!(sha256_of(&preimage), hash, "deterministic");
    }
}
