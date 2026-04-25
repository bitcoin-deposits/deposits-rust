//! HTLC Agent — cross-ledger and Lightning payment routing
//!
//! Holds deposits on multiple ledgers and provides two services:
//!
//! 1. **Cross-ledger transfers**: Customer locks transfer to agent's deposit on ledger A
//!    with hash H; agent locks matching transfer from its deposit on ledger B to the
//!    customer's deposit on ledger B with the same hash; preimage reveal completes both.
//!
//! 2. **Lightning payments**: Customer locks transfer to agent's deposit with the
//!    payment_hash from a Lightning invoice; agent pays the invoice (revealing preimage);
//!    agent completes the inbound transfer.
//!
//! Detection is via Kind 9100 ledger updates tagged with the agent's deposit IDs (#i).
//!
//! Usage:
//!   htlc-agent \
//!     --relay ws://localhost:7801 \
//!     --ledgers-relay ws://localhost:7779 \
//!     --node sim:~/.deposits-wallet \
//!     --fee-fixed 100 --fee-bps 10

use base64::prelude::*;
use bitcoin::secp256k1::rand::rngs::OsRng;
use bitcoin::secp256k1::rand::RngCore;
use bitcoin::secp256k1::{self, Keypair, Message, Secp256k1, SecretKey};
use deposits_core::{compute_deposit_id, LedgerOperation, TlvDecode};
use deposits_node::nostr::{
    ledger_tag, TAG_DEPOSIT_ID, TAG_EVENT_REF, TAG_LEDGER_ID, TAG_LEDGER_REQ, TAG_OP_TYPE,
    TAG_PUBKEY, TAG_SEQUENCE,
};
use nostr_sdk::prelude::*;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, oneshot};

const KIND_LEDGER_REQUEST: u16 = 20101;
const KIND_LEDGER_RESPONSE: u16 = 20102;
const KIND_LEDGER_UPDATE: u16 = 9100;
const KIND_LEDGER_ADVERTISE: u16 = 39100;
const KIND_AGENT_ADVERTISE: u16 = 39102;

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
    /// Operator's transfer fee (agent pays this on outbound locks)
    operator_fee_fixed_msats: u64,
    operator_fee_rate_bps: u16,
}

/// Per-ledger directional fees advertised to wallets.
/// Total route cost from A→B = fee_out(A, amount) + fee_in(B, amount).
#[derive(Clone, serde::Serialize)]
struct LedgerFees {
    /// Fee for the agent to receive on this ledger (agent margin)
    fee_in_fixed_msats: u64,
    fee_in_rate_bps: u64,
    /// Fee for the agent to send from this ledger (operator transfer fee + agent margin)
    fee_out_fixed_msats: u64,
    fee_out_rate_bps: u64,
}

/// An inbound TransferLock targeting one of our deposits.
#[derive(Debug, Clone)]
struct InboundLock {
    ledger_id: String,
    transfer_id: [u8; 32],
    source_deposit_id: [u8; 16],
    destination_deposit_id: [u8; 16],
    amount_msats: u64,
    fee_msats: u64,
    hash: [u8; 32], // extracted from completion_script "sha256(<hex>)"
    timeout_height: u32,
    detected_at: Instant,
}

/// A pending route the agent is managing.
#[derive(Debug)]
enum Route {
    CrossLedger {
        inbound: InboundLock,
        outbound_ledger_id: String,
        outbound_deposit_id_hex: String,
        dest_deposit_id_hex: String,
        outbound_transfer_id: Option<[u8; 32]>,
        preimage: Option<[u8; 32]>,
        status: RouteStatus,
    },
    Lightning {
        inbound: InboundLock,
        invoice: String,
        preimage: Option<[u8; 32]>,
        status: RouteStatus,
    },
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
enum RouteStatus {
    Pending,
    OutboundLocked,
    PreimageObtained,
    Completing,
    Done,
    Failed(String),
}

/// Serializable snapshot of a route for the API.
#[derive(serde::Serialize)]
struct RouteSnapshot {
    kind: String,
    status: RouteStatus,
    inbound_ledger: String,
    inbound_transfer_id: String,
    amount_msats: u64,
    hash: String,
    outbound_ledger: Option<String>,
    outbound_transfer_id: Option<String>,
    age_secs: u64,
}

impl Route {
    fn to_snapshot(&self) -> RouteSnapshot {
        match self {
            Route::CrossLedger {
                inbound,
                outbound_ledger_id,
                outbound_transfer_id,
                status,
                ..
            } => RouteSnapshot {
                kind: "cross_ledger".into(),
                status: status.clone(),
                inbound_ledger: inbound.ledger_id[..16].to_string(),
                inbound_transfer_id: hex::encode(inbound.transfer_id),
                amount_msats: inbound.amount_msats,
                hash: hex::encode(inbound.hash),
                outbound_ledger: Some(outbound_ledger_id[..16].to_string()),
                outbound_transfer_id: outbound_transfer_id.map(hex::encode),
                age_secs: inbound.detected_at.elapsed().as_secs(),
            },
            Route::Lightning {
                inbound,
                invoice,
                status,
                ..
            } => RouteSnapshot {
                kind: "lightning".into(),
                status: status.clone(),
                inbound_ledger: inbound.ledger_id[..16].to_string(),
                inbound_transfer_id: hex::encode(inbound.transfer_id),
                amount_msats: inbound.amount_msats,
                hash: hex::encode(inbound.hash),
                outbound_ledger: None,
                outbound_transfer_id: Some(invoice.clone()),
                age_secs: inbound.detected_at.elapsed().as_secs(),
            },
        }
    }
}

struct Config {
    relay: String,
    ledgers_relay: String,
    network: bitcoin::Network,
    nodes: Vec<NodeConfig>,
    /// Agent's own margin — applied to the inbound side of each route
    margin_fixed_msats: u64,
    margin_rate_bps: u64,
    timeout_margin_blocks: u32,
    bitcoin_cli: String,
    api_port: u16,
}

/// A pending route request from a wallet (before the inbound lock arrives).
#[derive(Debug, Clone)]
struct PendingRoute {
    /// Hash the wallet will use in the transfer_lock
    hash: [u8; 32],
    /// Where the agent should forward funds on the outbound ledger
    dest_deposit_id: [u8; 16],
    /// Outbound ledger
    dest_ledger_id: String,
    /// Amount the wallet is sending (inbound)
    amount_msats: u64,
    /// When this request was created (for expiry)
    created_at: Instant,
}

/// Shared state exposed via the HTTP API.
struct SharedState {
    deposits: Vec<DepositInfo>,
    routes: Mutex<Vec<Route>>,
    stats: AgentStats,
    started_at: Instant,
    margin_fixed_msats: u64,
    margin_rate_bps: u64,
    /// Per-ledger directional fees
    ledger_fees: HashMap<String, LedgerFees>,
    /// Pending route requests: hash → routing info (wallet calls /request-route before locking)
    pending_routes: Mutex<HashMap<[u8; 32], PendingRoute>>,
}

#[derive(Clone, serde::Serialize)]
struct DepositInfo {
    alias: String,
    ledger_id: String,
    deposit_id: String,
    balance_msats: i64,
}

// ─── Transport ──────────────────────────────────────────────────────────────

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

        // Subscribe to Kind 9100 updates for our deposit IDs (catches TransferLock with #i tag)
        let mut filters = Vec::new();
        if !deposit_id_hexes.is_empty() {
            let update_filter = Filter::new()
                .kind(Kind::Custom(KIND_LEDGER_UPDATE))
                .custom_tag(TAG_DEPOSIT_ID, deposit_id_hexes.iter().map(|s| s.as_str()));
            filters.push(update_filter);
        }

        // Also subscribe to Kind 9100 on our ledgers for TransferComplete events
        // (TransferComplete events don't carry #i tags, only #d + #t=71)
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
        let agent_pubkey_hex = keys.public_key().to_hex();
        let request_filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_REQUEST))
            .custom_tag(TAG_PUBKEY, [agent_pubkey_hex.as_str()]);
        filters.push(request_filter);

        if !filters.is_empty() {
            client
                .subscribe(filters, None)
                .await
                .map_err(|e| format!("Failed to subscribe: {}", e))?;
        }

        let pending: Arc<Mutex<HashMap<String, oneshot::Sender<ResponseData>>>> =
            Arc::new(Mutex::new(HashMap::new()));

        // Channel for inbound updates
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
                            // Decode update and check if it's a TransferLock/TransferComplete for us
                            if let Some(evt) = decode_update_event(&event, &deposit_ids) {
                                let _ = update_tx.send(evt).await;
                            }
                        } else if kind == KIND_LEDGER_REQUEST {
                            // Check if this is a route request addressed to us (#p tag)
                            let action = event.tags.iter().find_map(|tag| {
                                if tag.kind() == TagKind::custom("action") {
                                    tag.content().map(|s| s.to_string())
                                } else {
                                    None
                                }
                            });
                            if action.as_deref() == Some("request_route") {
                                if let Ok(params) =
                                    serde_json::from_str::<serde_json::Value>(&event.content)
                                {
                                    let _ = update_tx
                                        .send(UpdateEvent::RouteRequest {
                                            event_id: event.id.to_hex(),
                                            params,
                                        })
                                        .await;
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
    /// Send a response to a request event (Kind 20102 with #e tag)
    async fn send_response(
        &self,
        request_event_id: &str,
        response: serde_json::Value,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let content = serde_json::to_string(&response)?;
        let event = EventBuilder::new(Kind::Custom(KIND_LEDGER_RESPONSE), &content)
            .tag(Tag::custom(
                TagKind::SingleLetter(TAG_EVENT_REF),
                [request_event_id],
            ))
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

#[derive(Debug)]
enum UpdateEvent {
    /// A TransferLock where destination is one of our deposits
    InboundLock(InboundLock),
    /// A TransferComplete for a transfer we're tracking (preimage revealed)
    PreimageRevealed {
        ledger_id: String,
        transfer_id: [u8; 32],
        preimage: [u8; 32],
    },
    /// A route request from a wallet (via Nostr)
    RouteRequest {
        event_id: String,
        params: serde_json::Value,
    },
}

fn decode_update_event(event: &Event, our_deposit_ids: &[String]) -> Option<UpdateEvent> {
    // Get ledger_id from #d tag
    let ledger_id = event.tags.iter().find_map(|tag| {
        if tag.kind() == TagKind::SingleLetter(TAG_LEDGER_ID) {
            tag.content().map(|s| s.to_string())
        } else {
            None
        }
    })?;

    // Get operation discriminant from #t tag
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

    // Decode TLV from base64 content
    let tlv_bytes = BASE64_STANDARD.decode(event.content.as_bytes()).ok()?;

    // The content is a full SignedLedgerUpdate; the operation is in the `message` field.
    // We need to decode the SignedLedgerUpdate first, then the operation from its message.
    let update = deposits_core::SignedLedgerUpdate::tlv_decode(&tlv_bytes).ok()?;
    let op = LedgerOperation::tlv_decode(&update.message).ok()?;

    match op {
        LedgerOperation::TransferLock {
            source_deposit_id,
            destination_deposit_id,
            amount,
            fee,
            completion_script,
            timeout_height,
            transfer_id,
            ..
        } => {
            // Is the destination one of our deposits?
            let dest_hex = hex::encode(destination_deposit_id);
            if !our_deposit_ids.contains(&dest_hex) {
                return None;
            }

            // Extract hash from completion_script: "sha256(<64hex>)"
            let hash = extract_hash_from_script(&completion_script)?;

            Some(UpdateEvent::InboundLock(InboundLock {
                ledger_id,
                transfer_id,
                source_deposit_id,
                destination_deposit_id,
                amount_msats: amount,
                fee_msats: fee,
                hash,
                timeout_height,
                detected_at: Instant::now(),
            }))
        }
        LedgerOperation::TransferComplete {
            transfer_id,
            script_witness,
        } => {
            // Extract preimage from witness stack[0]
            let preimage_bytes = script_witness.stack.first()?;
            if preimage_bytes.len() != 32 {
                return None;
            }
            let mut preimage = [0u8; 32];
            preimage.copy_from_slice(preimage_bytes);

            Some(UpdateEvent::PreimageRevealed {
                ledger_id,
                transfer_id,
                preimage,
            })
        }
        _ => None,
    }
}

fn extract_hash_from_script(script: &str) -> Option<[u8; 32]> {
    // "sha256(abcdef...)" → parse the hex inside parens
    let inner = script.strip_prefix("sha256(")?.strip_suffix(')')?;
    let bytes = hex::decode(inner).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes);
    Some(hash)
}

// ─── Key Derivation (same as transfer-simulator) ────────────────────────────

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

// ─── Deposit Loading ────────────────────────────────────────────────────────

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
        let pubkey_hex = entry
            .get("deposit_pubkey")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let key_index = entry.get("key_index").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        let balance_msats = entry
            .get("balance_msats")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);

        if ledger_id.is_empty() || pubkey_hex.is_empty() {
            continue;
        }

        let descriptor = format!("pk({})", pubkey_hex);
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

// ─── Advertisement Fetching ─────────────────────────────────────────────────

/// Per-ledger info extracted from operator advertisements.
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

// ─── Agent Advertisement ─────────────────────────────────────────────────────

async fn publish_agent_advertisement(
    keys: &Keys,
    ledgers_relay: &str,
    deposits: &[AgentDeposit],
    ledger_fees: &HashMap<String, LedgerFees>,
    network: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::builder().signer(keys.clone()).build();
    client
        .add_relay(ledgers_relay)
        .await
        .map_err(|e| format!("Failed to add relay: {}", e))?;
    client.connect_with_timeout(Duration::from_secs(10)).await;

    // Build per-ledger deposit info with directional fees
    let ledger_entries: Vec<serde_json::Value> = deposits
        .iter()
        .map(|d| {
            let fees = ledger_fees.get(&d.ledger_id);
            serde_json::json!({
                "ledger_id": d.ledger_id,
                "deposit_id": d.deposit_id_hex,
                "balance_msats": d.balance_msats,
                "fee_in_fixed_msats": fees.map(|f| f.fee_in_fixed_msats).unwrap_or(0),
                "fee_in_rate_bps": fees.map(|f| f.fee_in_rate_bps).unwrap_or(0),
                "fee_out_fixed_msats": fees.map(|f| f.fee_out_fixed_msats).unwrap_or(0),
                "fee_out_rate_bps": fees.map(|f| f.fee_out_rate_bps).unwrap_or(0),
            })
        })
        .collect();

    let agent_pubkey = keys.public_key().to_hex();

    let content = serde_json::json!({
        "agent_pubkey": agent_pubkey,
        "service": "htlc_routing",
        "ledgers": ledger_entries,
        "network": network,
    });

    // Query existing ad timestamp so we can set a strictly newer one
    let existing_ts = {
        let filter = Filter::new()
            .kind(Kind::Custom(KIND_AGENT_ADVERTISE))
            .custom_tag(TAG_LEDGER_ID, [&agent_pubkey])
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

    // NIP-33: use #d tag as the stable identifier (agent pubkey)
    let event = EventBuilder::new(Kind::Custom(KIND_AGENT_ADVERTISE), content.to_string())
        .custom_created_at(Timestamp::from(ts))
        .tag(Tag::custom(
            TagKind::SingleLetter(TAG_LEDGER_ID),
            [&agent_pubkey],
        ))
        .tag(Tag::custom(TagKind::custom("service"), ["htlc_routing"]))
        .tag(Tag::custom(TagKind::SingleLetter(TAG_SEQUENCE), [network]));

    let signed = event
        .sign_with_keys(keys)
        .map_err(|e| format!("Failed to sign advertisement: {}", e))?;
    eprintln!(
        "  Ad: kind={} ts={} (old={}) ledgers={}",
        KIND_AGENT_ADVERTISE,
        ts,
        existing_ts,
        deposits.len()
    );
    let output = client
        .send_event(signed)
        .await
        .map_err(|e| format!("Failed to publish advertisement: {}", e))?;
    if !output.failed.is_empty() {
        eprintln!("  Ad publish failures: {:?}", output.failed);
    }

    // Allow time for the relay to process the event before disconnecting
    tokio::time::sleep(Duration::from_secs(2)).await;
    let _ = client.disconnect().await;
    Ok(())
}

// ─── Transfer Execution ─────────────────────────────────────────────────────

async fn execute_transfer_lock(
    transport: &AgentTransport,
    secp: &Secp256k1<secp256k1::All>,
    source: &AgentDeposit,
    dest_deposit_id: &[u8; 16],
    amount_msats: u64,
    fee_msats: u64,
    hash: &[u8; 32],
    timeout_height: u32,
) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
    let mut rng = OsRng;
    let mut nonce = [0u8; 32];
    rng.fill_bytes(&mut nonce);

    let completion_script = format!("sha256({})", hex::encode(hash));

    let msg_hash = deposits_core::transfer_lock_signing_message(
        &nonce,
        &source.deposit_id,
        dest_deposit_id,
        amount_msats,
        fee_msats,
        &completion_script,
        timeout_height,
    );
    let transfer_id = deposits_core::compute_transfer_id(&msg_hash);

    let msg = Message::from_digest(msg_hash);
    let signature = secp.sign_schnorr(&msg, &source.keypair);

    let params = serde_json::json!({
        "nonce": hex::encode(nonce),
        "source_deposit_id": hex::encode(source.deposit_id),
        "destination_deposit_id": hex::encode(dest_deposit_id),
        "amount": amount_msats,
        "fee": fee_msats,
        "completion_script": completion_script,
        "timeout_height": timeout_height,
        "transfer_id": hex::encode(transfer_id),
        "signature": hex::encode(signature.serialize()),
    });

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
    preimage: &[u8; 32],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let params = serde_json::json!({
        "transfer_id": hex::encode(transfer_id),
        "preimage": hex::encode(preimage),
    });

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
        ledgers_relay: "ws://localhost:7779".to_string(),
        network: bitcoin::Network::Regtest,
        nodes: Vec::new(),
        margin_fixed_msats: 100,
        margin_rate_bps: 10,
        timeout_margin_blocks: 144,
        bitcoin_cli: "docker exec bitcoind bitcoin-cli -regtest -rpcuser=user -rpcpassword=pass"
            .to_string(),
        api_port: 3200,
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
            "--fee-fixed" | "--margin-fixed" => {
                i += 1;
                config.margin_fixed_msats = args[i].parse()?;
            }
            "--fee-bps" | "--margin-bps" => {
                i += 1;
                config.margin_rate_bps = args[i].parse()?;
            }
            "--timeout-margin" => {
                i += 1;
                config.timeout_margin_blocks = args[i].parse()?;
            }
            "--bitcoin-cli" => {
                i += 1;
                config.bitcoin_cli = args[i].clone();
            }
            "--api-port" => {
                i += 1;
                config.api_port = args[i].parse()?;
            }
            "--help" | "-h" => {
                eprintln!("Usage: htlc-agent [OPTIONS]");
                eprintln!();
                eprintln!("Options:");
                eprintln!(
                    "  --relay <url>              Primary relay (default: ws://localhost:7801)"
                );
                eprintln!("  --ledgers-relay <url>      Durable relay for advertisements (default: ws://localhost:7779)");
                eprintln!("  --network <net>            Network (default: regtest)");
                eprintln!("  --node <name:data_dir>     Node identity and data directory");
                eprintln!(
                    "  --margin-fixed <msats>     Agent margin per route in msats (default: 100)"
                );
                eprintln!(
                    "  --margin-bps <bps>         Agent margin per route in bps (default: 10)"
                );
                eprintln!("  --timeout-margin <blocks>  Safety margin for outbound timeout (default: 144)");
                eprintln!("  --bitcoin-cli <cmd>        bitcoin-cli command");
                eprintln!("  --api-port <port>          HTTP API port (default: 3200)");
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

// ─── HTTP API Server ─────────────────────────────────────────────────────────

async fn run_api_server(port: u16, state: Arc<SharedState>) {
    let listener = match tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port)).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("API server failed to bind to port {}: {}", port, e);
            return;
        }
    };
    eprintln!("API server listening on http://127.0.0.1:{}", port);

    loop {
        let (mut stream, _) = match listener.accept().await {
            Ok(s) => s,
            Err(_) => continue,
        };
        let state = state.clone();
        tokio::spawn(async move {
            // Read request — may arrive in multiple chunks for POST bodies
            let mut buf = vec![0u8; 16384];
            let mut total = 0;
            loop {
                match tokio::io::AsyncReadExt::read(&mut stream, &mut buf[total..]).await {
                    Ok(0) => break,
                    Ok(n) => {
                        total += n;
                        // Check if we have the full request (headers + body)
                        let s = std::str::from_utf8(&buf[..total]).unwrap_or("");
                        if let Some(hdr_end) = s.find("\r\n\r\n") {
                            // Extract Content-Length if present
                            let headers = &s[..hdr_end];
                            let content_len = headers
                                .lines()
                                .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
                                .and_then(|l| l.split(':').nth(1)?.trim().parse::<usize>().ok())
                                .unwrap_or(0);
                            let body_start = hdr_end + 4;
                            if total >= body_start + content_len {
                                break;
                            }
                        }
                        if total >= buf.len() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            if total == 0 {
                return;
            }
            let request = String::from_utf8_lossy(&buf[..total]);
            let method = request.split_whitespace().next().unwrap_or("GET");
            let path = request.split_whitespace().nth(1).unwrap_or("/");

            // CORS preflight
            if method == "OPTIONS" {
                let resp = "HTTP/1.1 204 No Content\r\n\
                    Access-Control-Allow-Origin: *\r\n\
                    Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\
                    Access-Control-Allow-Headers: Content-Type\r\n\
                    Content-Length: 0\r\n\
                    Connection: close\r\n\r\n";
                let _ = stream.write_all(resp.as_bytes()).await;
                return;
            }

            let (status, body) = match (method, path) {
                (_, "/status") => {
                    let active = state
                        .stats
                        .routes_active
                        .load(std::sync::atomic::Ordering::Relaxed);
                    let completed = state
                        .stats
                        .routes_completed
                        .load(std::sync::atomic::Ordering::Relaxed);
                    let failed = state
                        .stats
                        .routes_failed
                        .load(std::sync::atomic::Ordering::Relaxed);
                    let uptime = state.started_at.elapsed().as_secs();
                    let json = serde_json::json!({
                        "uptime_secs": uptime,
                        "deposits": state.deposits.len(),
                        "routes_active": active,
                        "routes_completed": completed,
                        "routes_failed": failed,
                        "margin_fixed_msats": state.margin_fixed_msats,
                        "margin_rate_bps": state.margin_rate_bps,
                        "ledger_fees": state.ledger_fees,
                    });
                    ("200 OK", serde_json::to_string_pretty(&json).unwrap())
                }
                (_, "/deposits") => {
                    let json = serde_json::to_string_pretty(&state.deposits).unwrap();
                    ("200 OK", json)
                }
                (_, "/routes") => {
                    let routes = state.routes.lock().unwrap();
                    let snapshots: Vec<RouteSnapshot> =
                        routes.iter().map(|r| r.to_snapshot()).collect();
                    let json = serde_json::to_string_pretty(&snapshots).unwrap();
                    ("200 OK", json)
                }
                _ => {
                    let json = serde_json::json!({
                        "endpoints": ["/status", "/deposits", "/routes"]
                    });
                    (
                        "404 Not Found",
                        serde_json::to_string_pretty(&json).unwrap(),
                    )
                }
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

// Dead code — kept temporarily for reference; route requests now go through Nostr.
#[allow(dead_code)]
fn handle_request_route(request: &str, state: &SharedState) -> (&'static str, String) {
    // Extract JSON body after \r\n\r\n
    let body = match request.find("\r\n\r\n") {
        Some(pos) => &request[pos + 4..],
        None => return ("400 Bad Request", r#"{"error":"no body"}"#.into()),
    };

    let req: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => {
            return (
                "400 Bad Request",
                format!(r#"{{"error":"invalid json: {}"}}"#, e),
            )
        }
    };

    let source_ledger = match req["source_ledger"].as_str() {
        Some(s) => s.to_string(),
        None => {
            return (
                "400 Bad Request",
                r#"{"error":"missing source_ledger"}"#.into(),
            )
        }
    };
    let dest_ledger = match req["dest_ledger"].as_str() {
        Some(s) => s.to_string(),
        None => {
            return (
                "400 Bad Request",
                r#"{"error":"missing dest_ledger"}"#.into(),
            )
        }
    };
    let dest_deposit_id_hex = match req["dest_deposit_id"].as_str() {
        Some(s) if s.len() == 32 => s.to_string(),
        _ => {
            return (
                "400 Bad Request",
                r#"{"error":"dest_deposit_id must be 32 hex chars"}"#.into(),
            )
        }
    };
    let amount_msats = match req["amount_msats"].as_u64() {
        Some(a) if a > 0 => a,
        _ => {
            return (
                "400 Bad Request",
                r#"{"error":"missing or zero amount_msats"}"#.into(),
            )
        }
    };

    // Validate agent has deposits on both ledgers
    let agent_in = state.deposits.iter().find(|d| d.ledger_id == source_ledger);
    let agent_out = state.deposits.iter().find(|d| d.ledger_id == dest_ledger);

    let agent_in = match agent_in {
        Some(d) => d,
        None => {
            return (
                "400 Bad Request",
                r#"{"error":"agent has no deposit on source_ledger"}"#.into(),
            )
        }
    };
    let _agent_out = match agent_out {
        Some(d) => d,
        None => {
            return (
                "400 Bad Request",
                r#"{"error":"agent has no deposit on dest_ledger"}"#.into(),
            )
        }
    };

    // Calculate fees
    let in_fees = state.ledger_fees.get(&source_ledger);
    let out_fees = state.ledger_fees.get(&dest_ledger);
    let fee_in = in_fees
        .map(|f| f.fee_in_fixed_msats + amount_msats * f.fee_in_rate_bps / 10000)
        .unwrap_or(0);
    let fee_out = out_fees
        .map(|f| f.fee_out_fixed_msats + amount_msats * f.fee_out_rate_bps / 10000)
        .unwrap_or(0);
    let total_fee = fee_in + fee_out;

    if amount_msats <= total_fee {
        return (
            "400 Bad Request",
            r#"{"error":"amount too small to cover fees"}"#.into(),
        );
    }
    let forward_amount = amount_msats - total_fee;

    // Generate hash (preimage generated by wallet)
    // Agent generates its own random preimage for the hash — wallet will NOT know this.
    // Instead: wallet generates preimage, sends hash. But then we need the hash from the wallet.
    // Better: agent generates a random hash for the route, wallet uses it in the lock.
    // The DESTINATION completes the outbound leg by revealing the preimage.
    // Flow: wallet locks with hash → agent locks outbound with same hash → dest reveals preimage
    //       → agent sees preimage → agent completes inbound
    //
    // Who generates the preimage? The WALLET — it controls both endpoints.
    // Wallet generates preimage, sends hash to agent. Agent returns its deposit_id + fees.
    let hash_hex = match req["hash"].as_str() {
        Some(s) if s.len() == 64 => s.to_string(),
        _ => {
            return (
                "400 Bad Request",
                r#"{"error":"hash must be 64 hex chars"}"#.into(),
            )
        }
    };
    let hash: [u8; 32] = match hex::decode(&hash_hex) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => return ("400 Bad Request", r#"{"error":"invalid hash"}"#.into()),
    };

    let dest_deposit_id: [u8; 16] = match hex::decode(&dest_deposit_id_hex) {
        Ok(b) if b.len() == 16 => {
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&b);
            arr
        }
        _ => {
            return (
                "400 Bad Request",
                r#"{"error":"invalid dest_deposit_id"}"#.into(),
            )
        }
    };

    // Store pending route
    {
        let mut pending = state.pending_routes.lock().unwrap();

        // Evict stale entries (older than 10 minutes)
        pending.retain(|_, r| r.created_at.elapsed() < Duration::from_secs(600));

        pending.insert(
            hash,
            PendingRoute {
                hash,
                dest_deposit_id,
                dest_ledger_id: dest_ledger,
                amount_msats,
                created_at: Instant::now(),
            },
        );
    }

    let json = serde_json::json!({
        "courier_deposit_id": agent_in.deposit_id,
        "hash": hash_hex,
        "fee_msats": total_fee,
        "forward_amount_msats": forward_amount,
    });
    ("200 OK", serde_json::to_string_pretty(&json).unwrap())
}

// ─── CLI Client ──────────────────────────────────────────────────────────────

async fn cli_command(cmd: &str, port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let endpoint = match cmd {
        "status" => "/status",
        "deposits" => "/deposits",
        "routes" => "/routes",
        _ => {
            eprintln!("Unknown command: {}", cmd);
            eprintln!("Commands: status, deposits, routes");
            std::process::exit(1);
        }
    };

    let stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .map_err(|_| format!("Cannot connect to agent on port {} — is it running?", port))?;

    let (mut reader, mut writer) = stream.into_split();
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        endpoint
    );
    writer.write_all(request.as_bytes()).await?;
    writer.shutdown().await?;

    let mut response = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut reader, &mut response).await?;
    let response = String::from_utf8_lossy(&response);

    // Strip HTTP headers
    if let Some(body_start) = response.find("\r\n\r\n") {
        let body = &response[body_start + 4..];

        match cmd {
            "status" => print_status(body),
            "deposits" => print_deposits(body),
            "routes" => print_routes(body),
            _ => println!("{}", body),
        }
    } else {
        eprintln!("Invalid response from agent");
    }
    Ok(())
}

fn print_status(body: &str) {
    let v: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => {
            println!("{}", body);
            return;
        }
    };
    let uptime = v["uptime_secs"].as_u64().unwrap_or(0);
    let h = uptime / 3600;
    let m = (uptime % 3600) / 60;
    let s = uptime % 60;

    println!("HTLC Agent Status");
    println!("  Uptime:     {}h {}m {}s", h, m, s);
    println!("  Deposits:   {}", v["deposits"]);
    println!(
        "  Margin:     {} msats + {} bps",
        v["margin_fixed_msats"], v["margin_rate_bps"]
    );
    println!();
    println!("Routes:");
    println!("  Active:     {}", v["routes_active"]);
    println!("  Completed:  {}", v["routes_completed"]);
    println!("  Failed:     {}", v["routes_failed"]);

    if let Some(fees) = v["ledger_fees"].as_object() {
        println!();
        println!("Ledger fees:");
        for (lid, f) in fees {
            let short = &lid[..16.min(lid.len())];
            println!(
                "  {}...  in: {} + {}bps  out: {} + {}bps",
                short,
                f["fee_in_fixed_msats"],
                f["fee_in_rate_bps"],
                f["fee_out_fixed_msats"],
                f["fee_out_rate_bps"]
            );
        }
    }
}

fn print_deposits(body: &str) {
    let deposits: Vec<serde_json::Value> = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => {
            println!("{}", body);
            return;
        }
    };
    if deposits.is_empty() {
        println!("No deposits.");
        return;
    }
    println!("Deposits ({}):", deposits.len());
    for d in &deposits {
        let alias = d["alias"].as_str().unwrap_or("?");
        let lid = d["ledger_id"].as_str().unwrap_or("?");
        let did = d["deposit_id"].as_str().unwrap_or("?");
        let bal = d["balance_msats"].as_i64().unwrap_or(0);
        println!(
            "  {:16}  ledger {}...  deposit {}...  {} msats",
            alias,
            &lid[..16.min(lid.len())],
            &did[..16.min(did.len())],
            bal
        );
    }
}

fn print_routes(body: &str) {
    let routes: Vec<serde_json::Value> = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => {
            println!("{}", body);
            return;
        }
    };
    if routes.is_empty() {
        println!("No active routes.");
        return;
    }
    println!("Routes ({}):", routes.len());
    for r in &routes {
        let kind = r["kind"].as_str().unwrap_or("?");
        let status = &r["status"];
        let status_str = if status.is_string() {
            status.as_str().unwrap().to_string()
        } else if let Some(obj) = status.as_object() {
            obj.keys()
                .next()
                .map(|k| format!("Failed: {}", obj[k]))
                .unwrap_or("?".into())
        } else {
            "?".into()
        };
        let amount = r["amount_msats"].as_u64().unwrap_or(0);
        let age = r["age_secs"].as_u64().unwrap_or(0);
        let inbound = r["inbound_ledger"].as_str().unwrap_or("?");
        let outbound = r["outbound_ledger"].as_str().unwrap_or("-");

        println!(
            "  {} | {} msats | {} → {} | {} | {}s",
            kind, amount, inbound, outbound, status_str, age
        );
    }
}

// ─── Main ───────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // CLI subcommands: htlc-agent status|deposits|routes [--api-port PORT]
    let args: Vec<String> = std::env::args().collect();
    if args.len() >= 2 && !args[1].starts_with('-') {
        let cmd = &args[1];
        let mut port: u16 = 3200;
        let mut i = 2;
        while i < args.len() {
            if args[i] == "--api-port" && i + 1 < args.len() {
                port = args[i + 1].parse().unwrap_or(3200);
                i += 2;
            } else {
                i += 1;
            }
        }
        return cli_command(cmd, port).await;
    }

    let config = parse_args()?;

    eprintln!("=== HTLC Agent ===");
    eprintln!("Relay:         {}", config.relay);
    eprintln!("Ledgers relay: {}", config.ledgers_relay);
    eprintln!(
        "Agent margin:  {} msats + {} bps",
        config.margin_fixed_msats, config.margin_rate_bps
    );
    eprintln!("Timeout margin: {} blocks", config.timeout_margin_blocks);
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

    // Build indexes
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

    // Apply operator transfer fees to deposits. If the advertisement
    // omits them (older operators), fall back to the protocol's default
    // schedule — that's what operators enforce when no fee was agreed
    // at make_offer time.
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
    }

    // Compute per-ledger directional fees:
    //   fee_in  = agent margin (receiving costs the agent nothing, this is pure margin)
    //   fee_out = operator transfer fee + agent margin (agent pays operator to send)
    let mut ledger_fees: HashMap<String, LedgerFees> = HashMap::new();
    for d in &deposits {
        ledger_fees
            .entry(d.ledger_id.clone())
            .or_insert_with(|| LedgerFees {
                fee_in_fixed_msats: config.margin_fixed_msats,
                fee_in_rate_bps: config.margin_rate_bps,
                fee_out_fixed_msats: d.operator_fee_fixed_msats + config.margin_fixed_msats,
                fee_out_rate_bps: (d.operator_fee_rate_bps as u64) + config.margin_rate_bps,
            });
    }

    for d in &deposits {
        let fees = ledger_fees.get(&d.ledger_id).unwrap();
        eprintln!(
            "  {} fees: in={}/{}bps out={}/{}bps (operator={}/{}bps)",
            d.alias,
            fees.fee_in_fixed_msats,
            fees.fee_in_rate_bps,
            fees.fee_out_fixed_msats,
            fees.fee_out_rate_bps,
            d.operator_fee_fixed_msats,
            d.operator_fee_rate_bps
        );
    }

    // Create transport
    let nostr_key = derive_secret_key(&config.nodes[0].seed, config.network)?;
    let (transport, mut update_rx) =
        AgentTransport::new(nostr_key, &relay_urls, &deposit_id_hexes, &ledger_ids).await?;
    let transport = Arc::new(transport);

    let secp = Secp256k1::new();

    // Deposit lookup indexes
    let deposits_by_ledger: HashMap<String, Vec<AgentDeposit>> = {
        let mut map: HashMap<String, Vec<AgentDeposit>> = HashMap::new();
        for d in &deposits {
            map.entry(d.ledger_id.clone()).or_default().push(d.clone());
        }
        map
    };

    // Shared state for API
    let shared = Arc::new(SharedState {
        deposits: deposits
            .iter()
            .map(|d| DepositInfo {
                alias: d.alias.clone(),
                ledger_id: d.ledger_id.clone(),
                deposit_id: d.deposit_id_hex.clone(),
                balance_msats: d.balance_msats,
            })
            .collect(),
        routes: Mutex::new(Vec::new()),
        stats: AgentStats::default(),
        started_at: Instant::now(),
        margin_fixed_msats: config.margin_fixed_msats,
        margin_rate_bps: config.margin_rate_bps,
        ledger_fees: ledger_fees.clone(),
        pending_routes: Mutex::new(HashMap::new()),
    });

    // Convenience aliases matching old variable names
    let routes = shared.clone();
    let stats = shared.clone();

    // Start API server
    let api_state = shared.clone();
    tokio::spawn(run_api_server(config.api_port, api_state));

    // Publish agent advertisement
    let network_str = match config.network {
        bitcoin::Network::Bitcoin => "bitcoin",
        bitcoin::Network::Testnet => "testnet",
        bitcoin::Network::Signet => "signet",
        bitcoin::Network::Regtest => "regtest",
        _ => "unknown",
    };
    let nostr_secret =
        nostr_sdk::SecretKey::from_slice(&nostr_key.secret_bytes()).expect("valid key");
    let agent_keys = Keys::new(nostr_secret);
    match publish_agent_advertisement(
        &agent_keys,
        &config.ledgers_relay,
        &deposits,
        &ledger_fees,
        network_str,
    )
    .await
    {
        Ok(()) => eprintln!("Published agent advertisement to {}", config.ledgers_relay),
        Err(e) => eprintln!("Warning: failed to publish advertisement: {}", e),
    }

    // Re-advertise periodically (every 30 minutes)
    let ad_keys = agent_keys.clone();
    let ad_relay = config.ledgers_relay.clone();
    let ad_deposits = deposits.clone();
    let ad_fees = ledger_fees.clone();
    let ad_network = network_str.to_string();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(1800)).await;
            let _ = publish_agent_advertisement(
                &ad_keys,
                &ad_relay,
                &ad_deposits,
                &ad_fees,
                &ad_network,
            )
            .await;
        }
    });

    eprintln!("Listening for inbound transfers...\n");

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
            UpdateEvent::InboundLock(lock) => {
                let hash_hex = hex::encode(lock.hash);
                eprintln!(
                    "[INBOUND] {} msats on ledger {}... hash={}... timeout={}",
                    lock.amount_msats,
                    &lock.ledger_id[..16],
                    &hash_hex[..16],
                    lock.timeout_height,
                );

                // Check if a pending route specifies the destination ledger
                let pending_hint = shared
                    .pending_routes
                    .lock()
                    .unwrap()
                    .get(&lock.hash)
                    .map(|pr| pr.dest_ledger_id.clone());

                // Find a deposit on the target ledger (or first different ledger)
                let source_ledger = &lock.ledger_id;
                let mut outbound_deposit = None;
                if let Some(ref target_ledger) = pending_hint {
                    // Prefer the ledger from the pending route request
                    if let Some(deps) = deposits_by_ledger.get(target_ledger.as_str()) {
                        outbound_deposit = deps.first().cloned();
                    }
                }
                if outbound_deposit.is_none() {
                    for (lid, deps) in &deposits_by_ledger {
                        if lid != source_ledger {
                            if let Some(dep) = deps.first() {
                                outbound_deposit = Some(dep.clone());
                                break;
                            }
                        }
                    }
                }

                if let Some(out_dep) = outbound_deposit {
                    // Cross-ledger route: fee = fee_in(source) + fee_out(dest)
                    // fee_in covers the agent's margin for receiving on the inbound ledger
                    // fee_out covers operator transfer fee + margin for sending on the outbound ledger
                    let in_fees = ledger_fees.get(&lock.ledger_id);
                    let out_fees = ledger_fees.get(&out_dep.ledger_id);

                    let fee_in = in_fees
                        .map(|f| {
                            f.fee_in_fixed_msats + lock.amount_msats * f.fee_in_rate_bps / 10000
                        })
                        .unwrap_or(0);
                    let fee_out = out_fees
                        .map(|f| {
                            f.fee_out_fixed_msats + lock.amount_msats * f.fee_out_rate_bps / 10000
                        })
                        .unwrap_or(0);
                    let total_fee = fee_in + fee_out;
                    let forward_amount = lock.amount_msats.saturating_sub(total_fee);

                    // Operator's transfer fee for the outbound leg (agent pays this)
                    let transfer_fee = out_dep.operator_fee_fixed_msats
                        + (forward_amount * out_dep.operator_fee_rate_bps as u64 / 10000);

                    let outbound_timeout = lock
                        .timeout_height
                        .saturating_sub(config.timeout_margin_blocks);

                    eprintln!(
                        "  → Cross-ledger route: {} msats via {} on ledger {}...",
                        forward_amount,
                        out_dep.alias,
                        &out_dep.ledger_id[..16],
                    );

                    // Look up pending route request by hash for the destination deposit_id.
                    // Wallet calls POST /request-route before locking, which stores
                    // the destination info keyed by hash.
                    let pending = shared.pending_routes.lock().unwrap().remove(&lock.hash);
                    let dest_on_outbound = if let Some(pr) = &pending {
                        eprintln!(
                            "  (matched pending route → dest {})",
                            hex::encode(pr.dest_deposit_id)
                        );
                        pr.dest_deposit_id
                    } else {
                        eprintln!("  (no pending route — using source as fallback)");
                        lock.source_deposit_id
                    };

                    let transport_c = transport.clone();
                    let routes_c = routes.clone();
                    let stats_c = stats.clone();
                    let hash = lock.hash;
                    let _transfer_id_inbound = lock.transfer_id;
                    let _inbound_ledger = lock.ledger_id.clone();
                    let secp_c = secp.clone();

                    tokio::spawn(async move {
                        match execute_transfer_lock(
                            &transport_c,
                            &secp_c,
                            &out_dep,
                            &dest_on_outbound,
                            forward_amount,
                            transfer_fee,
                            &hash,
                            outbound_timeout,
                        )
                        .await
                        {
                            Ok(outbound_tid) => {
                                eprintln!(
                                    "  [LOCKED] outbound transfer {}... on ledger {}...",
                                    hex::encode(&outbound_tid[..8]),
                                    &out_dep.ledger_id[..16],
                                );
                                routes_c.routes.lock().unwrap().push(Route::CrossLedger {
                                    inbound: lock,
                                    outbound_ledger_id: out_dep.ledger_id.clone(),
                                    outbound_deposit_id_hex: out_dep.deposit_id_hex.clone(),
                                    dest_deposit_id_hex: hex::encode(dest_on_outbound),
                                    outbound_transfer_id: Some(outbound_tid),
                                    preimage: None,
                                    status: RouteStatus::OutboundLocked,
                                });
                                stats_c
                                    .stats
                                    .routes_active
                                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            }
                            Err(e) => {
                                eprintln!("  [FAIL] outbound lock failed: {}", e);
                                stats_c
                                    .stats
                                    .routes_failed
                                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            }
                        }
                    });
                } else {
                    eprintln!("  No outbound deposit available — skipping");
                }
            }

            UpdateEvent::PreimageRevealed {
                ledger_id,
                transfer_id,
                preimage,
            } => {
                eprintln!(
                    "[PREIMAGE] transfer {}... on ledger {}...",
                    hex::encode(&transfer_id[..8]),
                    &ledger_id[..16],
                );

                // Find the matching route and complete the inbound leg
                let mut routes_guard = routes.routes.lock().unwrap();
                let route = routes_guard.iter_mut().find(|r| {
                    matches!(r,
                        Route::CrossLedger {
                            outbound_transfer_id: Some(tid),
                            status,
                            ..
                        } if *tid == transfer_id && *status == RouteStatus::OutboundLocked
                    )
                });

                if let Some(Route::CrossLedger {
                    inbound,
                    status,
                    preimage: ref mut p,
                    ..
                }) = route
                {
                    *p = Some(preimage);
                    *status = RouteStatus::Completing;
                    let inbound_ledger = inbound.ledger_id.clone();
                    let inbound_tid = inbound.transfer_id;
                    let preimage_copy = preimage;
                    let transport_c = transport.clone();
                    let stats_c = stats.clone();

                    // Drop lock before spawning
                    drop(routes_guard);

                    tokio::spawn(async move {
                        match execute_transfer_complete(
                            &transport_c,
                            &inbound_ledger,
                            &inbound_tid,
                            &preimage_copy,
                        )
                        .await
                        {
                            Ok(()) => {
                                eprintln!(
                                    "  [DONE] completed inbound transfer {}...",
                                    hex::encode(&inbound_tid[..8]),
                                );
                                stats_c
                                    .stats
                                    .routes_completed
                                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                stats_c
                                    .stats
                                    .routes_active
                                    .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                            }
                            Err(e) => {
                                eprintln!("  [FAIL] complete inbound failed: {}", e,);
                                stats_c
                                    .stats
                                    .routes_failed
                                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            }
                        }
                    });
                } else {
                    drop(routes_guard);
                    eprintln!("  (no matching route — may be a direct transfer)");
                }
            }

            UpdateEvent::RouteRequest { event_id, params } => {
                eprintln!("[ROUTE-REQ] from event {}...", &event_id[..16]);

                let response = process_route_request(&params, &shared);
                let transport_c = transport.clone();
                let event_id_c = event_id.clone();
                tokio::spawn(async move {
                    if let Err(e) = transport_c.send_response(&event_id_c, response).await {
                        eprintln!("  Failed to send route response: {}", e);
                    }
                });
            }
        }
    }

    Ok(())
}

/// Process a route request and return the response JSON.
fn process_route_request(params: &serde_json::Value, state: &SharedState) -> serde_json::Value {
    let source_ledger = match params["source_ledger"].as_str() {
        Some(s) => s.to_string(),
        None => return serde_json::json!({"success": false, "error": "missing source_ledger"}),
    };
    let dest_ledger = match params["dest_ledger"].as_str() {
        Some(s) => s.to_string(),
        None => return serde_json::json!({"success": false, "error": "missing dest_ledger"}),
    };
    let dest_deposit_id_hex = match params["dest_deposit_id"].as_str() {
        Some(s) if s.len() == 32 => s.to_string(),
        _ => {
            return serde_json::json!({"success": false, "error": "dest_deposit_id must be 32 hex chars"})
        }
    };
    let amount_msats = match params["amount_msats"].as_u64() {
        Some(a) if a > 0 => a,
        _ => return serde_json::json!({"success": false, "error": "missing or zero amount_msats"}),
    };
    let hash_hex = match params["hash"].as_str() {
        Some(s) if s.len() == 64 => s.to_string(),
        _ => return serde_json::json!({"success": false, "error": "hash must be 64 hex chars"}),
    };
    let hash: [u8; 32] = match hex::decode(&hash_hex) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => return serde_json::json!({"success": false, "error": "invalid hash"}),
    };
    let dest_deposit_id: [u8; 16] = match hex::decode(&dest_deposit_id_hex) {
        Ok(b) if b.len() == 16 => {
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&b);
            arr
        }
        _ => return serde_json::json!({"success": false, "error": "invalid dest_deposit_id"}),
    };

    // Validate agent has deposits on both ledgers
    let agent_in = match state.deposits.iter().find(|d| d.ledger_id == source_ledger) {
        Some(d) => d,
        None => {
            return serde_json::json!({"success": false, "error": "agent has no deposit on source_ledger"})
        }
    };
    if state
        .deposits
        .iter()
        .find(|d| d.ledger_id == dest_ledger)
        .is_none()
    {
        return serde_json::json!({"success": false, "error": "agent has no deposit on dest_ledger"});
    }

    // Calculate fees
    let in_fees = state.ledger_fees.get(&source_ledger);
    let out_fees = state.ledger_fees.get(&dest_ledger);
    let fee_in = in_fees
        .map(|f| f.fee_in_fixed_msats + amount_msats * f.fee_in_rate_bps / 10000)
        .unwrap_or(0);
    let fee_out = out_fees
        .map(|f| f.fee_out_fixed_msats + amount_msats * f.fee_out_rate_bps / 10000)
        .unwrap_or(0);
    let total_fee = fee_in + fee_out;

    if amount_msats <= total_fee {
        return serde_json::json!({"success": false, "error": "amount too small to cover fees"});
    }
    let forward_amount = amount_msats - total_fee;

    // Store pending route
    {
        let mut pending = state.pending_routes.lock().unwrap();
        pending.retain(|_, r| r.created_at.elapsed() < Duration::from_secs(600));
        pending.insert(
            hash,
            PendingRoute {
                hash,
                dest_deposit_id,
                dest_ledger_id: dest_ledger,
                amount_msats,
                created_at: Instant::now(),
            },
        );
    }

    eprintln!(
        "  Route registered: {} → agent deposit {}, fee={}, forward={}",
        &source_ledger[..8],
        agent_in.deposit_id,
        total_fee,
        forward_amount
    );

    serde_json::json!({
        "success": true,
        "result": {
            "courier_deposit_id": agent_in.deposit_id,
            "hash": hash_hex,
            "fee_msats": total_fee,
            "forward_amount_msats": forward_amount,
        }
    })
}

// ─── Stats ──────────────────────────────────────────────────────────────────

#[derive(Default)]
struct AgentStats {
    routes_active: std::sync::atomic::AtomicU64,
    routes_completed: std::sync::atomic::AtomicU64,
    routes_failed: std::sync::atomic::AtomicU64,
}
