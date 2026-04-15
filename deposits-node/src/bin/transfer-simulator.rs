//! Rust transfer simulator — replaces the Python payment-simulator's transfer loop.
//!
//! Sends transfer_lock and transfer_complete requests directly over Nostr,
//! eliminating the Python GIL bottleneck and subprocess overhead.
//!
//! Usage:
//!   transfer-simulator \
//!     --relay ws://localhost:7801 \
//!     --node alice:416c696365..01:/data/alice \
//!     --node bob:426f6200..02:/data/bob \
//!     --target-tps 500

use bitcoin::hashes::Hash as _;
use bitcoin::secp256k1::rand::rngs::OsRng;
use bitcoin::secp256k1::rand::RngCore;
use bitcoin::secp256k1::{self, Keypair, Message, Secp256k1, SecretKey};
use deposits_node::nostr::{TAG_EVENT_REF, TAG_LEDGER_ID, TAG_LEDGER_REQ};
use nostr_sdk::prelude::*;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::oneshot;

// Nostr event kinds (must match deposits-node/src/nostr.rs)
const KIND_LEDGER_REQUEST: u16 = 20101;
const KIND_LEDGER_RESPONSE: u16 = 20102;
const KIND_LEDGER_ADVERTISE: u16 = 39100;

// ─── Data Types ─────────────────────────────────────────────────────────────

struct NodeConfig {
    name: String,
    seed: [u8; 32],
    data_dir: PathBuf,
}

struct SimDeposit {
    alias: String,
    ledger_id: String,
    deposit_id: [u8; 16],
    keypair: Keypair,
    node_idx: AtomicUsize, // index into transports vec (for relay lookup)
    balance_msats: AtomicI64,
}

struct TransferWork {
    sender_idx: usize,
    receiver_idx: usize,
    amount_sats: u64,
    fee_msats: u64,
    preimage: [u8; 32],
    hash: [u8; 32],
}

#[derive(Debug)]
struct TransferResult {
    success: bool,
    locked: bool,
    lock_us: u64,
    complete_us: u64,
    error: Option<String>,
}

struct SimMetrics {
    success: AtomicU64,
    failed: AtomicU64,
    timeouts: AtomicU64,
    volume_sats: AtomicU64,
    lock_latency_us: AtomicU64,
    lock_count: AtomicU64,
    complete_latency_us: AtomicU64,
    complete_count: AtomicU64,
    inflight: AtomicU64,
    error_counts: Mutex<HashMap<String, u64>>,
}

impl SimMetrics {
    fn new() -> Self {
        Self {
            success: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            timeouts: AtomicU64::new(0),
            volume_sats: AtomicU64::new(0),
            lock_latency_us: AtomicU64::new(0),
            lock_count: AtomicU64::new(0),
            complete_latency_us: AtomicU64::new(0),
            complete_count: AtomicU64::new(0),
            inflight: AtomicU64::new(0),
            error_counts: Mutex::new(HashMap::new()),
        }
    }

    fn record_error(&self, error: &str) {
        // Truncate to first 80 chars for grouping
        let key = if error.len() > 80 {
            &error[..80]
        } else {
            error
        };
        let mut counts = self.error_counts.lock().unwrap();
        let count = counts.entry(key.to_string()).or_insert(0);
        *count += 1;
        if *count == 1 {
            eprintln!("[error] {}", error);
        }
    }
}

// ─── SimTransport ───────────────────────────────────────────────────────────
//
// Thin wrapper over nostr_sdk::Client. Supports concurrent sends (&self)
// and routes responses to per-request oneshot channels via a background task.

struct SimTransport {
    client: Client,
    keys: Keys,
    pending: Arc<Mutex<HashMap<String, oneshot::Sender<LedgerResponseData>>>>,
}

#[derive(Debug, Clone)]
struct LedgerResponseData {
    success: bool,
    error: Option<String>,
    result: Option<serde_json::Value>,
}

impl SimTransport {
    async fn new(
        secret_key: SecretKey,
        relay_url: &str,
        ledger_ids: &[String],
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Self::new_multi(secret_key, &[relay_url.to_string()], ledger_ids).await
    }

    async fn new_multi(
        secret_key: SecretKey,
        relay_urls: &[String],
        ledger_ids: &[String],
    ) -> Result<Self, Box<dyn std::error::Error>> {
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

        // Wait for connection
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

        // Subscribe to responses for our ledger IDs
        let mut filter = Filter::new().kind(Kind::Custom(KIND_LEDGER_RESPONSE));
        if !ledger_ids.is_empty() {
            filter = filter.custom_tag(TAG_LEDGER_REQ, ledger_ids.iter().map(|s| s.as_str()));
        }
        client
            .subscribe(vec![filter], None)
            .await
            .map_err(|e| format!("Failed to subscribe: {}", e))?;

        let pending: Arc<Mutex<HashMap<String, oneshot::Sender<LedgerResponseData>>>> =
            Arc::new(Mutex::new(HashMap::new()));

        // Background response dispatcher
        let pending_clone = pending.clone();
        let mut notification_rx = client.notifications();
        tokio::spawn(async move {
            loop {
                match notification_rx.recv().await {
                    Ok(RelayPoolNotification::Event { event, .. }) => {
                        let kind_num = event.kind.as_u16();
                        if kind_num != KIND_LEDGER_RESPONSE {
                            continue;
                        }
                        // Extract request_id from #e tag
                        let request_id = event.tags.iter().find_map(|tag| {
                            if tag.kind() == TagKind::SingleLetter(TAG_EVENT_REF) {
                                tag.content().map(|s| s.to_string())
                            } else {
                                None
                            }
                        });
                        let request_id = match request_id {
                            Some(id) => id,
                            None => continue,
                        };

                        // Parse response
                        let response: LedgerResponseData =
                            match serde_json::from_str::<serde_json::Value>(&event.content) {
                                Ok(v) => LedgerResponseData {
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

                        // Route to waiting task
                        let sender = pending_clone.lock().unwrap().remove(&request_id);
                        if let Some(tx) = sender {
                            let _ = tx.send(response);
                        }
                    }
                    Ok(RelayPoolNotification::Shutdown) => break,
                    _ => {}
                }
            }
        });

        Ok(Self {
            client,
            keys,
            pending,
        })
    }

    /// Send a transfer_lock request. Returns (request_event_id, oneshot_receiver).
    async fn send_transfer_lock(
        &self,
        ledger_id: &str,
        params: serde_json::Value,
    ) -> Result<
        (String, oneshot::Receiver<LedgerResponseData>),
        Box<dyn std::error::Error + Send + Sync>,
    > {
        self.send_request(ledger_id, "transfer_lock", params).await
    }

    /// Send a transfer_complete request. Returns (request_event_id, oneshot_receiver).
    async fn send_transfer_complete(
        &self,
        ledger_id: &str,
        params: serde_json::Value,
    ) -> Result<
        (String, oneshot::Receiver<LedgerResponseData>),
        Box<dyn std::error::Error + Send + Sync>,
    > {
        self.send_request(ledger_id, "transfer_complete", params)
            .await
    }

    async fn send_request(
        &self,
        ledger_id: &str,
        action: &str,
        params: serde_json::Value,
    ) -> Result<
        (String, oneshot::Receiver<LedgerResponseData>),
        Box<dyn std::error::Error + Send + Sync>,
    > {
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

        // Register oneshot BEFORE sending (avoid race)
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(event_id.clone(), tx);

        // Fire-and-forget send
        let urls: Vec<_> = self.client.relays().await.keys().cloned().collect();
        self.client
            .send_msg_to(urls, ClientMessage::event(event))
            .await
            .map_err(|e| format!("Send failed: {}", e))?;

        Ok((event_id, rx))
    }

    async fn disconnect(&self) {
        let _ = self.client.disconnect().await;
    }
}

// ─── Key Derivation ─────────────────────────────────────────────────────────
// Copied from deposits-wallet.rs (private functions, cannot import)

fn derive_secret_key(
    seed: &[u8; 32],
    network: bitcoin::Network,
) -> Result<SecretKey, Box<dyn std::error::Error>> {
    derive_secret_key_at_index(seed, network, 0)
}

fn derive_secret_key_at_index(
    seed: &[u8; 32],
    network: bitcoin::Network,
    index: u32,
) -> Result<SecretKey, Box<dyn std::error::Error>> {
    use bitcoin::bip32::{DerivationPath, Xpriv};
    use std::str::FromStr;

    let xpriv = Xpriv::new_master(network, seed)?;
    let secp = Secp256k1::new();
    let path = DerivationPath::from_str(&format!("m/84'/0'/0'/0/{}", index))?;
    let derived = xpriv.derive_priv(&secp, &path)?;
    Ok(derived.private_key)
}

// ─── WalletRunner ────────────────────────────────────────────────────────────
// Shells out to sibling deposits-wallet binary for ledger discovery and deposit management.

struct WalletRunner {
    wallet_bin: PathBuf,
    relays: Vec<String>,
    network: String,
    data_dir: PathBuf,
    seed_hex: String,
}

impl WalletRunner {
    fn new(
        config: &Config,
        node: &NodeConfig,
        extra_relays: &HashMap<String, String>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let exe = std::env::current_exe()?;
        let bin_dir = exe.parent().ok_or("Cannot determine binary directory")?;
        let wallet_bin = bin_dir.join("deposits-wallet");
        if !wallet_bin.exists() {
            return Err(format!(
                "deposits-wallet not found at {}. Build it with: cargo build --release --bin deposits-wallet",
                wallet_bin.display()
            ).into());
        }
        let network = match config.network {
            bitcoin::Network::Regtest => "regtest",
            bitcoin::Network::Testnet => "testnet",
            bitcoin::Network::Bitcoin => "bitcoin",
            bitcoin::Network::Signet => "signet",
            _ => "regtest",
        };
        let mut relays = vec![config.relay.clone()];
        for url in extra_relays.values() {
            if !relays.contains(url) {
                relays.push(url.clone());
            }
        }
        Ok(Self {
            wallet_bin,
            relays,
            network: network.to_string(),
            data_dir: node.data_dir.clone(),
            seed_hex: hex::encode(node.seed),
        })
    }

    fn base_args(&self) -> Vec<String> {
        let mut args = Vec::new();
        for relay in &self.relays {
            args.push("--relay".to_string());
            args.push(relay.clone());
        }
        args.push("--network".to_string());
        args.push(self.network.clone());
        args.push("--data-dir".to_string());
        args.push(self.data_dir.to_string_lossy().to_string());
        args.push("--seed".to_string());
        args.push(self.seed_hex.clone());
        args
    }

    /// Discover available ledgers, returns (ledger IDs, ledger→relay_url map).
    /// Sync deposits and return balances: alias -> sats.
    fn sync_and_get_balances(&self) -> Result<HashMap<String, u64>, Box<dyn std::error::Error>> {
        // Run sync
        let mut sync_args = vec!["sync".to_string()];
        sync_args.extend(self.base_args());
        let output = std::process::Command::new(&self.wallet_bin)
            .args(&sync_args)
            .output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            eprintln!("  Warning: sync failed: {}", stderr.trim());
        }

        // Run balance
        let mut bal_args = vec!["balance".to_string()];
        bal_args.extend(self.base_args());
        let output = std::process::Command::new(&self.wallet_bin)
            .args(&bal_args)
            .output()?;
        let stdout = String::from_utf8_lossy(&output.stdout);

        let mut balances = HashMap::new();
        for line in stdout.lines() {
            let line = line.trim();
            // Format: "+ alias  12345 sats  (pubkey)" or "~ alias  12345 sats  (pubkey)"
            if line.starts_with('+') || line.starts_with('~') {
                let parts: Vec<&str> = line[1..].split_whitespace().collect();
                // parts: ["alias", "12345", "sats", "(pubkey)", ...]
                if parts.len() >= 3 && parts[2] == "sats" {
                    if let Ok(sats) = parts[1].parse::<u64>() {
                        balances.insert(parts[0].to_string(), sats);
                    }
                }
            }
        }
        Ok(balances)
    }
}

// ─── Faucet ─────────────────────────────────────────────────────────────────
// Funds deposits directly via bitcoin-cli. No wallet.sh dependency.

struct Faucet {
    cli_parts: Vec<String>,
    data_dir: PathBuf,
}

impl Faucet {
    fn new(bitcoin_cli: &str, data_dir: &PathBuf) -> Self {
        let cli_parts: Vec<String> = bitcoin_cli
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();
        Self {
            cli_parts,
            data_dir: data_dir.clone(),
        }
    }

    /// Send BTC to a deposit's funding address (no block mining).
    fn send(&self, alias: &str, sats: u64) -> Result<(), Box<dyn std::error::Error>> {
        let deposits_file = self.data_dir.join("deposits.json");
        let data = std::fs::read_to_string(&deposits_file)
            .map_err(|e| format!("Cannot read {}: {}", deposits_file.display(), e))?;
        let entries: Vec<serde_json::Value> = serde_json::from_str(&data)?;

        let entry = entries
            .iter()
            .find(|e| e.get("alias").and_then(|v| v.as_str()) == Some(alias))
            .ok_or_else(|| format!("Deposit '{}' not found in deposits.json", alias))?;

        let address = entry
            .get("funding_address")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("No funding_address for deposit '{}'", alias))?;

        let btc = format!("{:.8}", sats as f64 / 1e8);

        let (cmd, base_args) = self
            .cli_parts
            .split_first()
            .ok_or("Empty bitcoin_cli command")?;
        let mut send_args: Vec<&str> = base_args.iter().map(|s| s.as_str()).collect();
        send_args.extend(["-rpcwallet=faucet", "sendtoaddress", address, &btc]);

        eprintln!(
            "  Funding '{}' with {} sats ({} BTC) → {}",
            alias,
            sats,
            btc,
            &address[..20]
        );
        let output = std::process::Command::new(cmd).args(&send_args).output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("sendtoaddress failed: {}", stderr.trim()).into());
        }
        Ok(())
    }

    /// Mine blocks to confirm pending transactions.
    fn generate_blocks(&self, count: u32) -> Result<(), Box<dyn std::error::Error>> {
        let (cmd, base_args) = self
            .cli_parts
            .split_first()
            .ok_or("Empty bitcoin_cli command")?;
        let count_str = count.to_string();
        let mut gen_args: Vec<&str> = base_args.iter().map(|s| s.as_str()).collect();
        gen_args.extend(["-rpcwallet=faucet", "-generate", &count_str]);
        let output = std::process::Command::new(cmd).args(&gen_args).output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("block generation failed: {}", stderr.trim()).into());
        }
        Ok(())
    }

    /// Send + mine (convenience for auto-topoff single deposit).
    fn fund(&self, alias: &str, sats: u64) -> Result<(), Box<dyn std::error::Error>> {
        self.send(alias, sats)?;
        self.generate_blocks(1)?;
        Ok(())
    }
}

// ─── Relay Scan ─────────────────────────────────────────────────────────────
// Fallback ledger discovery: connect to relay and fetch recent events with #l tags.

/// Fee minimums extracted from an operator advertisement.
#[derive(Debug, Clone)]
struct LedgerFees {
    annual_fee_bps: u64,
    /// Annualized fixed fee (min_fee_sats_per_period * periods_per_year)
    annualized_fixed: u64,
    fee_period_blocks: u64,
}

/// Fetch ledger advertisements from a relay. Returns (ledger_ids, ledger→relay_url mapping, ledger→fees mapping).
/// Advertisements (Kind 39100) are NIP-33 replaceable events published by operators,
/// containing ledger_id and the operator's primary relay_url.
async fn fetch_advertisements(
    relay_url: &str,
) -> Result<
    (
        Vec<String>,
        HashMap<String, String>,
        HashMap<String, LedgerFees>,
    ),
    Box<dyn std::error::Error>,
> {
    let keys = Keys::generate();
    let opts = Options::default();
    let client = Client::builder().signer(keys).opts(opts).build();

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

    let mut ledger_ids = std::collections::HashSet::new();
    let mut ledger_relay_map: HashMap<String, String> = HashMap::new();
    let mut ledger_fees_map: HashMap<String, LedgerFees> = HashMap::new();

    for event in events.iter() {
        // Parse advertisement JSON content
        let ad: serde_json::Value = match serde_json::from_str(&event.content) {
            Ok(v) => v,
            Err(_) => continue,
        };

        // Extract ledger_id from #d tag (NIP-33 identifier) or JSON content
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

        // Extract relay_url from advertisement
        if let Some(url) = ad.get("relay_url").and_then(|v| v.as_str()) {
            if !url.is_empty() {
                ledger_relay_map.insert(ledger_id.clone(), url.to_string());
            }
        }

        // Extract fee minimums from advertisement
        // fee_fixed in the request is annualized_msats, so we must convert:
        //   annualized = min_fee_sats_per_period * (52560 / fee_period_blocks)
        let annual_fee_bps = ad
            .get("annual_fee_bps")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let min_fee_sats = ad.get("min_fee_sats").and_then(|v| v.as_u64()).unwrap_or(0);
        let fee_period_blocks = ad
            .get("fee_period_blocks")
            .and_then(|v| v.as_u64())
            .unwrap_or(2016);
        let periods_per_year = if fee_period_blocks > 0 {
            52560 / fee_period_blocks
        } else {
            26
        };
        ledger_fees_map.insert(
            ledger_id.clone(),
            LedgerFees {
                annual_fee_bps,
                annualized_fixed: min_fee_sats.saturating_mul(periods_per_year),
                fee_period_blocks,
            },
        );

        ledger_ids.insert(ledger_id);
    }

    let _ = client.disconnect().await;
    let mut result: Vec<String> = ledger_ids.into_iter().collect();
    result.sort();
    Ok((result, ledger_relay_map, ledger_fees_map))
}

// ─── Bootstrap ──────────────────────────────────────────────────────────────

fn load_deposit_key_index(data_dir: &PathBuf) -> u32 {
    let path = data_dir.join("deposit_key_index.txt");
    if path.exists() {
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0)
    } else {
        0
    }
}

fn save_deposit_key_index(data_dir: &PathBuf, index: u32) {
    let path = data_dir.join("deposit_key_index.txt");
    let _ = std::fs::write(&path, index.to_string());
}

/// Create deposits directly via Nostr using a single connection.
/// Much faster than spawning deposits-wallet per deposit.
async fn batch_open_deposits(
    relay_urls: &[String],
    seed: &[u8; 32],
    network: bitcoin::Network,
    data_dir: &PathBuf,
    ledger_ids: &[String],
    aliases: &[String],
    amount_sats: u64,
    ledger_fees: &HashMap<String, LedgerFees>,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let secp = Secp256k1::new();
    let nostr_key = derive_secret_key(seed, network)?;

    // Connect to all relays so we can see responses from any operator's primary relay
    let transport = SimTransport::new_multi(nostr_key, relay_urls, ledger_ids).await?;

    let mut key_index = load_deposit_key_index(data_dir);
    let mut created = Vec::new();

    // Prepare all deposit info upfront
    struct DepInfo {
        alias: String,
        ledger_id: String,
        pubkey_hex: String,
        key_idx: u32,
    }
    let mut dep_infos = Vec::new();
    for (i, alias) in aliases.iter().enumerate() {
        let ledger_id = ledger_ids[i % ledger_ids.len()].clone();
        let secret_key = derive_secret_key_at_index(seed, network, key_index)?;
        let pubkey = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
        dep_infos.push(DepInfo {
            alias: alias.clone(),
            ledger_id,
            pubkey_hex: hex::encode(pubkey.serialize()),
            key_idx: key_index,
        });
        key_index += 1;
    }

    // Phase 1: Fire all deposit_open requests concurrently (batched by ledger to avoid flooding)
    const BATCH_SIZE: usize = 8;
    let mut opened = Vec::new(); // indices that succeeded

    for batch in dep_infos.chunks(BATCH_SIZE) {
        let mut futures = Vec::new();
        for (batch_idx, info) in batch.iter().enumerate() {
            let fees = ledger_fees.get(&info.ledger_id);
            let open_params = serde_json::json!({
                "deposit_pubkey": info.pubkey_hex,
                "fee_fixed": fees.map_or(0, |f| f.annualized_fixed),
                "fee_bps": fees.map_or(0, |f| f.annual_fee_bps),
                "fee_frequency": fees.map_or(2016, |f| f.fee_period_blocks),
            });
            let rx_result = transport
                .send_request(&info.ledger_id, "deposit_open", open_params)
                .await;
            match rx_result {
                Ok((_, rx)) => futures.push((batch_idx, rx)),
                Err(e) => eprintln!("  {} deposit_open send failed: {}", info.alias, e),
            }
        }

        // Collect results
        for (batch_idx, rx) in futures {
            let info = &batch[batch_idx];
            match tokio::time::timeout(Duration::from_secs(30), rx).await {
                Ok(Ok(resp)) => {
                    if resp.success || resp.error.as_deref().is_some_and(|e| e.contains("already"))
                    {
                        opened.push(info.alias.clone());
                    } else {
                        eprintln!(
                            "  {} deposit_open failed: {}",
                            info.alias,
                            resp.error.as_deref().unwrap_or("unknown")
                        );
                    }
                }
                Ok(Err(_)) => eprintln!("  {} deposit_open: channel closed", info.alias),
                Err(_) => eprintln!("  {} deposit_open: timeout", info.alias),
            }
        }
    }

    // Phase 2: Fire make_offer for all opened deposits
    let opened_set: std::collections::HashSet<&str> = opened.iter().map(|s| s.as_str()).collect();

    for batch in dep_infos.chunks(BATCH_SIZE) {
        let batch_infos: Vec<&DepInfo> = batch
            .iter()
            .filter(|i| opened_set.contains(i.alias.as_str()))
            .collect();
        if batch_infos.is_empty() {
            continue;
        }

        let mut futures = Vec::new();
        for info in &batch_infos {
            let fees = ledger_fees.get(&info.ledger_id);
            let offer_params = serde_json::json!({
                "deposit_pubkey": info.pubkey_hex,
                "max_sats": amount_sats,
                "min_sats": std::cmp::min(1000_u64, amount_sats.saturating_sub(1).max(1)),
                "blocks_valid": 10000_u64,
                "fee_fixed": fees.map_or(0, |f| f.annualized_fixed),
                "fee_bps": fees.map_or(0, |f| f.annual_fee_bps),
                "fee_frequency": fees.map_or(2016, |f| f.fee_period_blocks),
            });
            let rx_result = transport
                .send_request(&info.ledger_id, "make_offer", offer_params)
                .await;
            match rx_result {
                Ok((_, rx)) => futures.push((*info, rx)),
                Err(e) => eprintln!("  {} make_offer send failed: {}", info.alias, e),
            }
        }

        for (info, rx) in futures {
            match tokio::time::timeout(Duration::from_secs(30), rx).await {
                Ok(Ok(resp)) if resp.success => {
                    if let Some(ref result) = resp.result {
                        let address = result
                            .get("funding_address")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let offer_id = result
                            .get("offer_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let min = result.get("min_sats").and_then(|v| v.as_u64()).unwrap_or(1);
                        let max = result
                            .get("max_sats")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(amount_sats);

                        if address.is_empty() || offer_id.is_empty() {
                            eprintln!("  {} make_offer: missing fields", info.alias);
                            continue;
                        }

                        eprintln!(
                            "  {} → {} (ledger {}...)",
                            info.alias,
                            &address[..20],
                            &info.ledger_id[..8]
                        );
                        created.push(serde_json::json!({
                            "alias": info.alias,
                            "offer_id": offer_id,
                            "ledger_id": info.ledger_id,
                            "funding_address": address,
                            "deposit_pubkey": info.pubkey_hex,
                            "key_index": info.key_idx,
                            "min_sats": min,
                            "max_sats": max,
                            "status": "pending",
                            "created_at": chrono::Utc::now().to_rfc3339(),
                        }));
                    } else {
                        eprintln!("  {} make_offer: no result", info.alias);
                    }
                }
                Ok(Ok(resp)) => {
                    eprintln!(
                        "  {} make_offer failed: {}",
                        info.alias,
                        resp.error.as_deref().unwrap_or("unknown")
                    );
                }
                Ok(Err(_)) => eprintln!("  {} make_offer: channel closed", info.alias),
                Err(_) => eprintln!("  {} make_offer: timeout", info.alias),
            }
        }
    }

    save_deposit_key_index(data_dir, key_index);
    transport.disconnect().await;

    Ok(created)
}

async fn run_bootstrap(config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    if config.nodes.is_empty() {
        return Err("No nodes specified for bootstrap".into());
    }
    let node = &config.nodes[0];
    let faucet = Faucet::new(&config.bitcoin_cli, &node.data_dir);

    eprintln!("\n=== Bootstrap ===");

    // 1. Discover ledgers (explicit --ledger flags take priority)
    let (ledger_ids, relay_map, fees_map) = if !config.ledger_ids.is_empty() {
        eprintln!("Using {} explicit ledger ID(s)", config.ledger_ids.len());
        (config.ledger_ids.clone(), HashMap::new(), HashMap::new())
    } else {
        eprintln!("Discovering ledgers...");
        let (ids, relay_map, fees_map) = fetch_advertisements(&config.ledgers_relay).await?;
        eprintln!(
            "  Found {} ledger(s) with {} relay mappings",
            ids.len(),
            relay_map.len()
        );
        if ids.is_empty() {
            return Err(
                "No ledgers found. Start operator nodes first, or use --ledger <id>.".into(),
            );
        }
        (ids, relay_map, fees_map)
    };
    let wallet = WalletRunner::new(config, node, &relay_map)?;
    for id in &ledger_ids {
        eprintln!("  Ledger: {}...{}", &id[..8], &id[56..]);
    }

    // 2. Count existing deposits
    let deposits_file = node.data_dir.join("deposits.json");
    let existing: Vec<serde_json::Value> = if deposits_file.exists() {
        let data = std::fs::read_to_string(&deposits_file)?;
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        Vec::new()
    };
    let existing_count = existing.len();

    // 3. Create deposits if needed (direct Nostr, single connection)
    let target_count = if config.deposit_count > 0 {
        config.deposit_count
    } else {
        std::cmp::max(4, ledger_ids.len() * 2)
    };

    if existing_count < target_count {
        let to_create = target_count - existing_count;
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            % 100000;

        let aliases: Vec<String> = (0..to_create)
            .map(|i| format!("sim-{}-{:02}", ts, existing_count + i))
            .collect();

        eprintln!(
            "Creating {} deposits (have {}, target {})...",
            to_create, existing_count, target_count
        );
        // Collect all unique relay URLs for bootstrap (need to hear responses from all operators)
        let mut all_relay_urls: Vec<String> = vec![config.relay.clone()];
        for url in relay_map.values() {
            if !all_relay_urls.contains(url) {
                all_relay_urls.push(url.clone());
            }
        }
        let new_deposits = batch_open_deposits(
            &all_relay_urls,
            &node.seed,
            config.network,
            &node.data_dir,
            &ledger_ids,
            &aliases,
            config.funding_sats,
            &fees_map,
        )
        .await?;

        // Merge with existing and save
        let mut all = existing;
        all.extend(new_deposits.iter().cloned());
        let json = serde_json::to_string_pretty(&all)?;
        std::fs::write(&deposits_file, json)?;
        eprintln!(
            "Created {} deposits ({} total)",
            new_deposits.len(),
            all.len()
        );
    } else {
        eprintln!(
            "Already have {} deposits (target {}), skipping creation",
            existing_count, target_count
        );
    }

    // 4. Fund unfunded deposits (batched: send all txs, then mine once)
    eprintln!("Checking deposit funding...");
    if !deposits_file.exists() {
        eprintln!("  No deposits.json found — no deposits were created successfully");
        eprintln!("Bootstrap complete (no deposits created).\n");
        return Ok(());
    }
    let data = std::fs::read_to_string(&deposits_file)?;
    let entries: Vec<serde_json::Value> = serde_json::from_str(&data)?;

    let mut sent_count = 0u32;
    let mut already_funded = 0u32;
    let mut total_count = 0u32;
    for entry in &entries {
        let alias = match entry.get("alias").and_then(|v| v.as_str()) {
            Some(a) => a,
            None => continue,
        };
        total_count += 1;

        let status = entry
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("pending");
        if status == "funded" {
            already_funded += 1;
            continue;
        }

        if entry
            .get("funding_address")
            .and_then(|v| v.as_str())
            .is_none()
        {
            eprintln!("  Skipping '{}' — no funding_address", alias);
            continue;
        }

        if let Err(e) = faucet.send(alias, config.funding_sats) {
            eprintln!("  Warning: failed to send to '{}': {}", alias, e);
        } else {
            sent_count += 1;
        }
    }

    if sent_count > 0 {
        eprintln!("  Sent {} funding txs, mining 1 block...", sent_count);
        if let Err(e) = faucet.generate_blocks(1) {
            eprintln!("  Warning: {}", e);
        }
    }
    eprintln!(
        "Funding: {} sent, {} already funded, {} total",
        sent_count, already_funded, total_count
    );

    if sent_count > 0 {
        // 5. Wait for confirmation — sync until all show balance > 0
        eprintln!("Waiting for deposit confirmations...");
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            let balances = wallet.sync_and_get_balances()?;
            let confirmed = balances.values().filter(|&&v| v > 0).count();
            let total = balances.len();
            eprintln!("  {}/{} deposits confirmed", confirmed, total);
            if confirmed >= total && total > 0 {
                break;
            }
            if Instant::now() > deadline {
                eprintln!(
                    "  Warning: timeout waiting for confirmations ({}/{} confirmed)",
                    confirmed, total
                );
                break;
            }
        }

        // 6. Settle — let operators finish processing deposit completions
        eprintln!("Settling (10s for operators to finish co-signing)...");
        tokio::time::sleep(Duration::from_secs(10)).await;
    }

    eprintln!("Bootstrap complete.\n");
    Ok(())
}

// ─── Deposit Loading ────────────────────────────────────────────────────────

fn load_deposits(
    node: &NodeConfig,
    node_idx: usize,
    network: bitcoin::Network,
) -> Result<Vec<SimDeposit>, Box<dyn std::error::Error>> {
    let deposits_file = node.data_dir.join("deposits.json");
    if !deposits_file.exists() {
        eprintln!(
            "  {} — no deposits.json at {}",
            node.name,
            deposits_file.display()
        );
        return Ok(Vec::new());
    }

    let data = std::fs::read_to_string(&deposits_file)?;
    let entries: Vec<serde_json::Value> = serde_json::from_str(&data)?;
    let secp = Secp256k1::new();

    let mut deposits = Vec::new();
    for d in &entries {
        let alias = match d.get("alias").and_then(|v| v.as_str()) {
            Some(a) => a.to_string(),
            None => continue,
        };
        let ledger_id = match d.get("ledger_id").and_then(|v| v.as_str()) {
            Some(l) => l.to_string(),
            None => continue,
        };
        let key_index = d.get("key_index").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        let balance_msats = d
            .get("balance_msats")
            .and_then(|v| v.as_i64())
            .or_else(|| {
                d.get("amount_sats")
                    .and_then(|v| v.as_i64())
                    .map(|s| s * 1000)
            })
            .unwrap_or(0);

        let secret_key = match derive_secret_key_at_index(&node.seed, network, key_index) {
            Ok(k) => k,
            Err(e) => {
                eprintln!(
                    "  {} — key derivation failed for {}: {}",
                    node.name, alias, e
                );
                continue;
            }
        };
        let keypair = Keypair::from_secret_key(&secp, &secret_key);
        let pubkey = keypair.public_key();
        let descriptor = format!("pk({})", hex::encode(pubkey.serialize()));
        let deposit_id = deposits_core::types::compute_deposit_id(&descriptor);

        deposits.push(SimDeposit {
            alias,
            ledger_id,
            deposit_id,
            keypair,
            node_idx: AtomicUsize::new(node_idx),
            balance_msats: AtomicI64::new(balance_msats),
        });
    }

    eprintln!(
        "  {} — loaded {} deposits from {}",
        node.name,
        deposits.len(),
        deposits_file.display()
    );
    Ok(deposits)
}

// ─── Transfer Execution ─────────────────────────────────────────────────────

async fn execute_transfer(
    transports: &[Arc<SimTransport>],
    deposits: &[Arc<SimDeposit>],
    secp: &Secp256k1<secp256k1::All>,
    work: &TransferWork,
    timeout_height: u32,
    lock_timeout_secs: u64,
) -> TransferResult {
    let sender = &deposits[work.sender_idx];
    let receiver = &deposits[work.receiver_idx];
    let transport = &transports[sender.node_idx.load(Ordering::Relaxed)];

    // Generate nonce
    let mut rng = OsRng;
    let mut nonce = [0u8; 32];
    rng.fill_bytes(&mut nonce);

    let completion_script = format!("sha256({})", hex::encode(work.hash));

    // Convert to msats for signing and request
    let amount_msats = work.amount_sats * 1000;
    // Fee is computed in msats: fixed_msats + rate_bps on amount_msats
    let fee_msats = work.fee_msats;

    // Compute signing message and transfer_id (all in msats)
    let msg_hash = deposits_core::signature_utils::transfer_lock_signing_message(
        &nonce,
        &sender.deposit_id,
        &receiver.deposit_id,
        amount_msats,
        fee_msats,
        &completion_script,
        timeout_height,
    );
    let transfer_id = deposits_core::signature_utils::compute_transfer_id(&msg_hash);

    // Sign
    let msg = Message::from_digest(msg_hash);
    let signature = secp.sign_schnorr(&msg, &sender.keypair);

    let lock_params = serde_json::json!({
        "nonce": hex::encode(nonce),
        "source_deposit_id": hex::encode(sender.deposit_id),
        "destination_deposit_id": hex::encode(receiver.deposit_id),
        "amount": amount_msats,
        "fee": fee_msats,
        "completion_script": completion_script,
        "timeout_height": timeout_height,
        "transfer_id": hex::encode(transfer_id),
        "signature": hex::encode(signature.serialize()),
    });

    // ── transfer_lock ──
    let lock_start = Instant::now();
    let (_, lock_rx) = match transport
        .send_transfer_lock(&sender.ledger_id, lock_params)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            return TransferResult {
                success: false,
                locked: false,
                lock_us: 0,
                complete_us: 0,
                error: Some(format!("send lock: {}", e)),
            }
        }
    };

    let lock_response =
        match tokio::time::timeout(Duration::from_secs(lock_timeout_secs), lock_rx).await {
            Ok(Ok(resp)) => resp,
            Ok(Err(_)) => {
                return TransferResult {
                    success: false,
                    locked: false,
                    lock_us: lock_start.elapsed().as_micros() as u64,
                    complete_us: 0,
                    error: Some("lock oneshot closed".into()),
                }
            }
            Err(_) => {
                return TransferResult {
                    success: false,
                    locked: false,
                    lock_us: lock_start.elapsed().as_micros() as u64,
                    complete_us: 0,
                    error: Some("lock timeout".into()),
                }
            }
        };
    let lock_us = lock_start.elapsed().as_micros() as u64;

    if !lock_response.success {
        return TransferResult {
            success: false,
            locked: false,
            lock_us,
            complete_us: 0,
            error: lock_response.error,
        };
    }

    // ── transfer_complete (with retry on co-sign failures) ──
    let complete_start = Instant::now();
    let max_complete_attempts = 3;
    let mut last_error = None;

    for attempt in 0..max_complete_attempts {
        if attempt > 0 {
            // Back off before retry — give quorum members breathing room
            tokio::time::sleep(Duration::from_millis(500 * attempt as u64)).await;
        }

        let complete_params = serde_json::json!({
            "transfer_id": hex::encode(transfer_id),
            "preimage": hex::encode(work.preimage),
        });

        let (_, complete_rx) = match transport
            .send_transfer_complete(&sender.ledger_id, complete_params)
            .await
        {
            Ok(r) => r,
            Err(e) => {
                last_error = Some(format!("send complete: {}", e));
                continue;
            }
        };

        match tokio::time::timeout(Duration::from_secs(lock_timeout_secs), complete_rx).await {
            Ok(Ok(resp)) if resp.success => {
                let complete_us = complete_start.elapsed().as_micros() as u64;
                return TransferResult {
                    success: true,
                    locked: true,
                    lock_us,
                    complete_us,
                    error: None,
                };
            }
            Ok(Ok(resp)) => {
                let err = resp.error.unwrap_or_else(|| "unknown".into());
                // Only retry on co-sign failures
                if err.contains("Co-sign") || err.contains("co-sign") || err.contains("cosign") {
                    last_error = Some(err);
                    continue;
                }
                let complete_us = complete_start.elapsed().as_micros() as u64;
                return TransferResult {
                    success: false,
                    locked: true,
                    lock_us,
                    complete_us,
                    error: Some(err),
                };
            }
            Ok(Err(_)) => {
                last_error = Some("complete oneshot closed".into());
                continue;
            }
            Err(_) => {
                last_error = Some("complete timeout".into());
                continue;
            }
        }
    }

    let complete_us = complete_start.elapsed().as_micros() as u64;
    TransferResult {
        success: false,
        locked: true,
        lock_us,
        complete_us,
        error: last_error,
    }
}

// ─── CLI Parsing ────────────────────────────────────────────────────────────

/// Expand leading ~ to home directory.
fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest);
        }
    } else if path == "~" {
        if let Some(home) = dirs::home_dir() {
            return home;
        }
    }
    PathBuf::from(path)
}

struct Config {
    relay: String,
    ledgers_relay: String,
    network: bitcoin::Network,
    target_tps: u64,
    max_workers: usize,
    min_amount: u64,
    max_amount: u64,
    timeout_height: u32,
    fee_fixed: u64,
    fee_rate_bps: u64,
    max_transfers: u64, // 0 = unlimited
    config_file: Option<PathBuf>,
    nodes: Vec<NodeConfig>,
    bootstrap: bool,
    deposit_count: usize, // 0 = auto (max(8, ledgers * 6))
    funding_sats: u64,
    auto_topoff: bool,
    bitcoin_cli: String,
    ledger_ids: Vec<String>, // explicit --ledger <id> overrides
    lock_timeout_secs: u64,
}

/// Load seed from data_dir/seed.hex, or generate a new one if it doesn't exist.
/// Matches deposits-wallet's auto-seed behavior.
fn load_or_generate_seed(data_dir: &PathBuf) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    std::fs::create_dir_all(data_dir)?;
    let seed_file = data_dir.join("seed.hex");
    if seed_file.exists() {
        let seed_hex = std::fs::read_to_string(&seed_file)?;
        let seed_bytes = hex::decode(seed_hex.trim())?;
        if seed_bytes.len() != 32 {
            return Err(format!(
                "Invalid seed file at {} (expected 32 bytes, got {})",
                seed_file.display(),
                seed_bytes.len()
            )
            .into());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&seed_bytes);
        eprintln!("  Loaded seed from {}", seed_file.display());
        Ok(arr)
    } else {
        let mut rng = OsRng;
        let mut arr = [0u8; 32];
        rng.fill_bytes(&mut arr);
        std::fs::write(&seed_file, hex::encode(arr))?;
        eprintln!("  Generated new seed: {}", seed_file.display());
        Ok(arr)
    }
}

fn parse_args() -> Result<Config, Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let mut config = Config {
        relay: "ws://localhost:7801".to_string(),
        ledgers_relay: "ws://localhost:7779".to_string(),
        network: bitcoin::Network::Regtest,
        target_tps: 500,
        max_workers: 50,
        min_amount: 10,
        max_amount: 50,
        timeout_height: 0, // 0 = auto (current_block + 500)
        fee_fixed: 2,
        fee_rate_bps: 20,
        max_transfers: 0,
        config_file: None,
        nodes: Vec::new(),
        bootstrap: false,
        deposit_count: 0,
        funding_sats: 1_000_000,
        auto_topoff: false,
        bitcoin_cli: "docker exec bitcoind bitcoin-cli -regtest -rpcuser=user -rpcpassword=pass"
            .to_string(),
        ledger_ids: Vec::new(),
        lock_timeout_secs: 30,
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
                    "testnet" => bitcoin::Network::Testnet,
                    "bitcoin" | "mainnet" => bitcoin::Network::Bitcoin,
                    "signet" => bitcoin::Network::Signet,
                    _ => return Err(format!("Unknown network: {}", args[i]).into()),
                };
            }
            "--target-tps" => {
                i += 1;
                config.target_tps = args[i].parse()?;
            }
            "--workers" => {
                i += 1;
                config.max_workers = args[i].parse()?;
            }
            "--min-amount" => {
                i += 1;
                config.min_amount = args[i].parse()?;
            }
            "--max-amount" => {
                i += 1;
                config.max_amount = args[i].parse()?;
            }
            "--timeout-height" => {
                i += 1;
                config.timeout_height = args[i].parse()?;
            }
            "--fee-fixed" => {
                i += 1;
                config.fee_fixed = args[i].parse()?;
            }
            "--fee-rate-bps" => {
                i += 1;
                config.fee_rate_bps = args[i].parse()?;
            }
            "--max-transfers" => {
                i += 1;
                config.max_transfers = args[i].parse()?;
            }
            "--config" => {
                i += 1;
                config.config_file = Some(PathBuf::from(&args[i]));
            }
            "--bootstrap" => {
                config.bootstrap = true;
            }
            "--deposit-count" => {
                i += 1;
                config.deposit_count = args[i].parse()?;
            }
            "--funding-sats" => {
                i += 1;
                config.funding_sats = args[i].parse()?;
            }
            "--auto-topoff" => {
                config.auto_topoff = true;
            }
            "--bitcoin-cli" => {
                i += 1;
                config.bitcoin_cli = args[i].clone();
            }
            "--lock-timeout" => {
                i += 1;
                config.lock_timeout_secs = args[i].parse()?;
            }
            "--ledger" => {
                i += 1;
                let id = args[i].clone();
                if id.len() != 64 || !id.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err(format!("--ledger must be 64 hex chars, got: {}", id).into());
                }
                config.ledger_ids.push(id);
            }
            "--node" => {
                i += 1;
                // Format: name:seed_hex:data_dir  OR  name:data_dir (seed auto-loaded)
                let parts: Vec<&str> = args[i].splitn(3, ':').collect();
                let (name, seed, data_dir) = match parts.len() {
                    3 => {
                        // name:seed_hex:data_dir
                        let seed_bytes = hex::decode(parts[1])?;
                        if seed_bytes.len() != 32 {
                            return Err(format!(
                                "Seed must be 32 bytes (64 hex chars), got {}",
                                seed_bytes.len()
                            )
                            .into());
                        }
                        let mut seed = [0u8; 32];
                        seed.copy_from_slice(&seed_bytes);
                        (parts[0], seed, expand_tilde(parts[2]))
                    }
                    2 => {
                        // name:data_dir — load or generate seed from data_dir/seed.hex
                        let data_dir = expand_tilde(parts[1]);
                        let seed = load_or_generate_seed(&data_dir)?;
                        (parts[0], seed, data_dir)
                    }
                    _ => {
                        return Err(format!(
                            "--node must be name:seed_hex:data_dir or name:data_dir, got: {}",
                            args[i]
                        )
                        .into())
                    }
                };
                config.nodes.push(NodeConfig {
                    name: name.to_string(),
                    seed,
                    data_dir,
                });
            }
            "--help" | "-h" => {
                eprintln!("Usage: transfer-simulator [OPTIONS]");
                eprintln!();
                eprintln!("Options:");
                eprintln!(
                    "  --relay <url>              Nostr relay (default: ws://localhost:7801)"
                );
                eprintln!("  --network <net>             Bitcoin network (default: regtest)");
                eprintln!("  --target-tps <n>            Target TPS (default: 500)");
                eprintln!("  --workers <n>               Concurrent workers (default: 50)");
                eprintln!("  --min-amount <sats>         Min transfer (default: 10)");
                eprintln!("  --max-amount <sats>         Max transfer (default: 50)");
                eprintln!("  --timeout-height <n>        HTLC timeout (default: 99999)");
                eprintln!("  --fee-fixed <sats>          Fixed fee (default: 2)");
                eprintln!("  --fee-rate-bps <n>          Rate in bps (default: 20)");
                eprintln!("  --lock-timeout <secs>       Lock/complete timeout (default: 30)");
                eprintln!("  --max-transfers <n>         Stop after N (default: unlimited)");
                eprintln!("  --config <path>             Config file for runtime TPS updates");
                eprintln!("  --node <name:seed:dir>      Add node (repeatable)");
                eprintln!("  --node <name:dir>           Add node, auto-load/generate seed");
                eprintln!();
                eprintln!("Bootstrap & Topoff:");
                eprintln!(
                    "  --bootstrap                 Discover ledgers, create and fund deposits"
                );
                eprintln!("  --deposit-count <n>         Target deposit count (default: auto)");
                eprintln!(
                    "  --funding-sats <n>          Sats to fund each deposit (default: 1000000)"
                );
                eprintln!(
                    "  --auto-topoff               Re-fund depleted deposits during transfers"
                );
                eprintln!(
                    "  --bitcoin-cli <cmd>         bitcoin-cli command (default: docker exec ...)"
                );
                eprintln!("  --ledger <id>               Explicit ledger ID, 64 hex (repeatable)");
                std::process::exit(0);
            }
            other => return Err(format!("Unknown arg: {}", other).into()),
        }
        i += 1;
    }

    if config.nodes.is_empty() {
        return Err("No nodes specified. Use --node name:seed_hex:data_dir".into());
    }

    // Auto-default config file to simulator-config.json (check CWD/bin/, CWD/, then next to binary)
    if config.config_file.is_none() {
        let candidates = [
            PathBuf::from("bin/simulator-config.json"),
            PathBuf::from("simulator-config.json"),
        ];
        for c in &candidates {
            if c.exists() {
                config.config_file = Some(c.clone());
                break;
            }
        }
        if config.config_file.is_none() {
            if let Ok(exe) = std::env::current_exe() {
                if let Some(dir) = exe.parent() {
                    let p = dir.join("simulator-config.json");
                    if p.exists() {
                        config.config_file = Some(p);
                    }
                }
            }
        }
    }

    Ok(config)
}

// ─── Main ───────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = parse_args()?;

    eprintln!("=== Transfer Simulator ===");
    eprintln!("Relay:       {}", config.relay);
    eprintln!("Target TPS:  {}", config.target_tps);
    eprintln!("Workers:     {}", config.max_workers);
    eprintln!(
        "Amount:      {}-{} sats",
        config.min_amount, config.max_amount
    );
    eprintln!(
        "Fee:         {} + {}bps",
        config.fee_fixed, config.fee_rate_bps
    );
    eprintln!("Nodes:       {}", config.nodes.len());
    if config.bootstrap {
        eprintln!(
            "Bootstrap:   enabled (funding: {} sats)",
            config.funding_sats
        );
    }
    if config.auto_topoff {
        eprintln!(
            "Auto-topoff: enabled (threshold: 20% of {} sats)",
            config.funding_sats
        );
    }
    eprintln!();

    // Bootstrap if requested
    if config.bootstrap {
        run_bootstrap(&config).await?;
    }

    // Load all deposits
    eprintln!("Loading deposits...");
    let mut all_deposits: Vec<Arc<SimDeposit>> = Vec::new();
    for (idx, node) in config.nodes.iter().enumerate() {
        let node_deposits = load_deposits(node, idx, config.network)?;
        for d in node_deposits {
            all_deposits.push(Arc::new(d));
        }
    }

    if all_deposits.is_empty() {
        return Err(
            "No deposits found. Use --bootstrap to create and fund deposits automatically.".into(),
        );
    }

    // Build ledger → deposit indices map for receiver selection
    let mut ledger_deposits: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, d) in all_deposits.iter().enumerate() {
        ledger_deposits
            .entry(d.ledger_id.clone())
            .or_default()
            .push(i);
    }

    eprintln!(
        "Loaded {} deposits across {} ledgers",
        all_deposits.len(),
        ledger_deposits.len()
    );
    for (lid, indices) in &ledger_deposits {
        eprintln!(
            "  ledger {}... — {} deposits",
            &lid[..16.min(lid.len())],
            indices.len()
        );
    }

    // No per-ledger concurrency limit — operators process requests sequentially
    // and the cosign mini-loop handles cross-operator requests inline.

    // Filter to ledgers with >=2 deposits (need sender + receiver)
    let eligible_deposit_indices: Vec<usize> = all_deposits
        .iter()
        .enumerate()
        .filter(|(_, d)| {
            ledger_deposits
                .get(&d.ledger_id)
                .is_some_and(|v| v.len() >= 2)
        })
        .map(|(i, _)| i)
        .collect();

    if eligible_deposit_indices.is_empty() {
        return Err(
            "No ledgers with >=2 deposits. Need at least 2 deposits on the same ledger.".into(),
        );
    }

    eprintln!(
        "{} eligible deposits (on ledgers with >=2 deposits)",
        eligible_deposit_indices.len()
    );

    // Discover ledger→relay mapping from advertisements
    eprintln!("Fetching relay routing from advertisements...");
    let (_, ledger_relay_map, _) = fetch_advertisements(&config.ledgers_relay).await?;
    if !ledger_relay_map.is_empty() {
        eprintln!(
            "Relay routing: {} ledgers mapped to per-operator relays",
            ledger_relay_map.len()
        );
        let mut relay_counts: HashMap<&str, usize> = HashMap::new();
        for url in ledger_relay_map.values() {
            *relay_counts.entry(url.as_str()).or_default() += 1;
        }
        for (url, count) in &relay_counts {
            eprintln!("  {} — {} ledgers", url, count);
        }
    }

    // Build per-relay ledger groups for transport creation.
    // Each unique relay URL gets its own SimTransport.
    // Deposits whose ledger has no relay mapping fall back to config.relay.
    let mut relay_ledger_groups: HashMap<String, Vec<String>> = HashMap::new();
    for d in &all_deposits {
        let relay = ledger_relay_map
            .get(&d.ledger_id)
            .cloned()
            .unwrap_or_else(|| config.relay.clone());
        let lids = relay_ledger_groups.entry(relay).or_default();
        if !lids.contains(&d.ledger_id) {
            lids.push(d.ledger_id.clone());
        }
    }

    // Create one transport per relay, map relay URL → transport index
    eprintln!("\nConnecting to relays...");
    let mut transports: Vec<Arc<SimTransport>> = Vec::new();
    let mut relay_to_transport_idx: HashMap<String, usize> = HashMap::new();
    let node = &config.nodes[0]; // simulator has one node identity
    let nostr_key_base = derive_secret_key(&node.seed, config.network)?;
    for (relay_url, ledger_ids_for_relay) in &relay_ledger_groups {
        let idx = transports.len();
        // Derive a unique key per relay to avoid nostr-sdk dedup issues
        // (same pubkey on multiple relays is fine, but separate clients need separate keys)
        let nostr_key = if idx == 0 {
            nostr_key_base
        } else {
            // Derive a child key: hash(base_key || relay_idx)
            use bitcoin::hashes::{sha256, Hash};
            let mut preimage = nostr_key_base.secret_bytes().to_vec();
            preimage.extend_from_slice(&(idx as u64).to_le_bytes());
            let hash = sha256::Hash::hash(&preimage);
            SecretKey::from_slice(&hash[..]).unwrap()
        };
        let transport = SimTransport::new(nostr_key, relay_url, ledger_ids_for_relay).await?;
        eprintln!(
            "  relay {} — {} ledgers, connected",
            relay_url,
            ledger_ids_for_relay.len()
        );
        relay_to_transport_idx.insert(relay_url.clone(), idx);
        transports.push(Arc::new(transport));
    }

    // Re-map each deposit's node_idx to point to the correct transport
    for d in &all_deposits {
        let relay = ledger_relay_map
            .get(&d.ledger_id)
            .cloned()
            .unwrap_or_else(|| config.relay.clone());
        if let Some(&tidx) = relay_to_transport_idx.get(&relay) {
            d.node_idx.store(tidx, Ordering::Relaxed);
        }
    }

    let metrics = Arc::new(SimMetrics::new());
    let deposits = Arc::new(all_deposits);
    let transports = Arc::new(transports);
    let robin = Arc::new(AtomicUsize::new(0));
    let eligible = Arc::new(eligible_deposit_indices);
    let ledger_deps = Arc::new(ledger_deposits);

    // Adaptive rate control: start slow, ramp up while healthy, back off on failures.
    // Prevents the thundering-herd cosign deadlock where all operators simultaneously
    // enter their cosign mini-loops and can't respond to each other.
    let effective_tps = Arc::new(AtomicU64::new(5)); // start at 5 TPS
    let target_tps_dynamic = Arc::new(AtomicU64::new(config.target_tps));

    // Shared rate limit interval (derived from effective_tps)
    let interval_us = Arc::new(AtomicU64::new(1_000_000 / 5));

    // Dynamic config: paused flag and max workers (hot-reloadable via config file)
    let paused = Arc::new(AtomicBool::new(false));
    let max_workers_dynamic = Arc::new(AtomicUsize::new(config.max_workers));

    // Metrics reporter task
    let metrics_clone = metrics.clone();
    let effective_tps_clone = effective_tps.clone();
    let paused_clone = paused.clone();
    let max_workers_clone = max_workers_dynamic.clone();
    let report_start = Instant::now();
    let reporter = tokio::spawn(async move {
        let mut last_success = 0u64;
        let mut last_time = Instant::now();
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            let now = Instant::now();
            let elapsed = now.duration_since(last_time).as_secs_f64();
            last_time = now;

            let success = metrics_clone.success.load(Ordering::Relaxed);
            let failed = metrics_clone.failed.load(Ordering::Relaxed);
            let timeouts = metrics_clone.timeouts.load(Ordering::Relaxed);
            let volume = metrics_clone.volume_sats.load(Ordering::Relaxed);
            let inflight = metrics_clone.inflight.load(Ordering::Relaxed);
            let eff_tps = effective_tps_clone.load(Ordering::Relaxed);
            let is_paused = paused_clone.load(Ordering::Relaxed);

            let delta = success - last_success;
            last_success = success;
            let tps = delta as f64 / elapsed;

            let avg_lock = {
                let count = metrics_clone.lock_count.load(Ordering::Relaxed);
                if count > 0 {
                    metrics_clone.lock_latency_us.load(Ordering::Relaxed) as f64
                        / count as f64
                        / 1000.0
                } else {
                    0.0
                }
            };
            let avg_complete = {
                let count = metrics_clone.complete_count.load(Ordering::Relaxed);
                if count > 0 {
                    metrics_clone.complete_latency_us.load(Ordering::Relaxed) as f64
                        / count as f64
                        / 1000.0
                } else {
                    0.0
                }
            };

            let uptime = now.duration_since(report_start).as_secs();
            let pause_tag = if is_paused { " PAUSED" } else { "" };
            eprintln!(
                "[{}s] TPS: {:.1}/{} | ok: {} fail: {} timeout: {} | vol: {} sats | lock: {:.1}ms complete: {:.1}ms | inflight: {}/{}{}",
                uptime, tps, eff_tps, success, failed, timeouts, volume, avg_lock, avg_complete, inflight, max_workers_clone.load(Ordering::Relaxed), pause_tag,
            );
        }
    });

    // Ctrl-C handler
    let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        eprintln!("\nShutting down...");
        shutdown_clone.store(true, Ordering::Relaxed);
    });

    let secp = Arc::new(Secp256k1::new());
    let sem = Arc::new(tokio::sync::Semaphore::new(config.max_workers * 2)); // headroom for dynamic changes
    let start_time = Instant::now();

    // Config file watcher — polls every 1s for runtime changes
    if let Some(config_path) = &config.config_file {
        eprintln!(
            "Config file: {} (hot-reload enabled)",
            config_path.display()
        );
        let path = config_path.clone();
        let target_tps_w = target_tps_dynamic.clone();
        let effective_tps_w = effective_tps.clone();
        let interval_us_w = interval_us.clone();
        let paused_w = paused.clone();
        let max_workers_w = max_workers_dynamic.clone();
        let mut last_mtime = std::fs::metadata(&path)
            .ok()
            .and_then(|m| m.modified().ok())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
        let mut current_tps = config.target_tps;
        let mut current_workers = config.max_workers;
        let mut current_paused = false;
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                let mtime = match std::fs::metadata(&path)
                    .ok()
                    .and_then(|m| m.modified().ok())
                {
                    Some(t) => t,
                    None => continue,
                };
                if mtime <= last_mtime {
                    continue;
                }
                last_mtime = mtime;
                let data = match std::fs::read_to_string(&path) {
                    Ok(d) => d,
                    Err(_) => continue,
                };
                let json: serde_json::Value = match serde_json::from_str(&data) {
                    Ok(v) => v,
                    Err(_) => continue,
                };

                // target_tps / target_qps
                if let Some(tps) = json
                    .get("target_tps")
                    .or_else(|| json.get("target_qps"))
                    .and_then(|v| v.as_f64())
                    .map(|v| v as u64)
                {
                    if tps != current_tps {
                        eprintln!("[config] target_tps: {} -> {}", current_tps, tps);
                        target_tps_w.store(tps, Ordering::Relaxed);
                        // If effective TPS is above new target, clamp it down
                        let eff = effective_tps_w.load(Ordering::Relaxed);
                        if eff > tps {
                            effective_tps_w.store(tps, Ordering::Relaxed);
                            let new_interval = if tps > 0 { 1_000_000 / tps } else { 0 };
                            interval_us_w.store(new_interval, Ordering::Relaxed);
                        }
                        current_tps = tps;
                    }
                }

                // max_concurrent
                if let Some(workers) = json
                    .get("max_concurrent")
                    .and_then(|v| v.as_u64())
                    .map(|v| v as usize)
                {
                    if workers != current_workers && workers > 0 {
                        eprintln!(
                            "[config] max_concurrent: {} -> {}",
                            current_workers, workers
                        );
                        max_workers_w.store(workers, Ordering::Relaxed);
                        current_workers = workers;
                    }
                }

                // paused
                if let Some(p) = json.get("paused").and_then(|v| v.as_bool()) {
                    if p != current_paused {
                        eprintln!("[config] paused: {} -> {}", current_paused, p);
                        paused_w.store(p, Ordering::Relaxed);
                        current_paused = p;
                    }
                }
            }
        });
    }

    let mut next_send = Instant::now();
    let mut total_dispatched = 0u64;
    let mut last_dispatch_time = Instant::now();

    // Auto-topoff state (runs in background to avoid blocking transfers)
    let mut last_topoff_check = Instant::now();
    let topoff_threshold_sats = config.funding_sats / 5; // 20%
    let topoff_running = Arc::new(AtomicBool::new(false));
    let topoff_wallet = if config.auto_topoff {
        Some(Arc::new(WalletRunner::new(
            &config,
            &config.nodes[0],
            &ledger_relay_map,
        )?))
    } else {
        None
    };
    let topoff_faucet = if config.auto_topoff {
        Some(Arc::new(Faucet::new(
            &config.bitcoin_cli,
            &config.nodes[0].data_dir,
        )))
    } else {
        None
    };
    let topoff_funding_sats = config.funding_sats;

    // Resolve timeout_height: 0 → current_block + 500
    if config.timeout_height == 0 {
        let output = std::process::Command::new("sh")
            .args(["-c", &format!("{} getblockcount", config.bitcoin_cli)])
            .output();
        let height: u32 = output
            .ok()
            .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse().ok())
            .unwrap_or(200);
        config.timeout_height = height + 500;
        eprintln!(
            "Timeout height: {} (current block {} + 500)",
            config.timeout_height, height
        );
    }

    eprintln!(
        "\nStarting transfers (ramp 5 → {} TPS, {} workers, no throttle)...\n",
        config.target_tps, config.max_workers
    );

    // Ramp-up: increase TPS by 10% every 2s until target, then hold steady
    let mut last_adapt_time = Instant::now();

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }
        if config.max_transfers > 0 && total_dispatched >= config.max_transfers {
            break;
        }

        // Pause check
        if paused.load(Ordering::Relaxed) {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        }

        // Ramp-up: every 2s, increase TPS by 10% until target. No throttling back.
        if last_adapt_time.elapsed() >= Duration::from_secs(2) {
            last_adapt_time = Instant::now();
            let current = effective_tps.load(Ordering::Relaxed);
            let target_tps = target_tps_dynamic.load(Ordering::Relaxed);

            if current < target_tps {
                let increase = (current / 10).max(2);
                let new_tps = (current + increase).min(target_tps);
                effective_tps.store(new_tps, Ordering::Relaxed);
                let new_interval = if new_tps > 0 { 1_000_000 / new_tps } else { 0 };
                interval_us.store(new_interval, Ordering::Relaxed);
                if new_tps == target_tps {
                    eprintln!("[ramp] reached target {} TPS", target_tps);
                }
            }
        }

        // Auto-topoff check every 60s (runs in background thread to avoid blocking transfers)
        if config.auto_topoff
            && last_topoff_check.elapsed() > Duration::from_secs(60)
            && !topoff_running.load(Ordering::Relaxed)
        {
            last_topoff_check = Instant::now();
            if let (Some(ref wallet), Some(ref faucet)) = (&topoff_wallet, &topoff_faucet) {
                let wallet_c = wallet.clone();
                let faucet_c = faucet.clone();
                let deposits_c: Vec<Arc<SimDeposit>> = deposits.iter().cloned().collect();
                let threshold = topoff_threshold_sats;
                let funding = topoff_funding_sats;
                let running = topoff_running.clone();
                running.store(true, Ordering::Relaxed);
                tokio::task::spawn_blocking(move || {
                    match wallet_c.sync_and_get_balances() {
                        Ok(balances) => {
                            for (alias, balance) in &balances {
                                if *balance > 0 && *balance < threshold {
                                    let topoff_amount = funding - balance;
                                    eprintln!("[topoff] '{}' balance {} sats < threshold {} sats, funding {} sats",
                                        alias, balance, threshold, topoff_amount);
                                    if let Err(e) = faucet_c.fund(alias, topoff_amount) {
                                        eprintln!(
                                            "[topoff] Warning: failed to fund '{}': {}",
                                            alias, e
                                        );
                                    } else {
                                        if let Some(dep) =
                                            deposits_c.iter().find(|d| &d.alias == alias)
                                        {
                                            dep.balance_msats
                                                .store(funding as i64 * 1000, Ordering::Relaxed);
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("[topoff] Warning: sync failed: {}", e);
                        }
                    }
                    running.store(false, Ordering::Relaxed);
                });
            }
        }

        // Rate limit
        let current_interval = interval_us.load(Ordering::Relaxed);
        if current_interval > 0 {
            let now = Instant::now();
            if now < next_send {
                tokio::time::sleep(next_send - now).await;
            }
            // Advance from previous deadline, not from now — ensures work time
            // between sends doesn't eat into the interval
            let interval = Duration::from_micros(current_interval);
            next_send += interval;
            // If we fell behind (next_send is still in the past), snap forward
            // to avoid a burst of catch-up sends
            let now = Instant::now();
            if next_send < now {
                next_send = now + interval;
            }
        }

        // Pick sender (round-robin across eligible deposits)
        let eligible_len = eligible.len();
        let robin_val = robin.fetch_add(1, Ordering::Relaxed);
        let sender_idx = eligible[robin_val % eligible_len];
        let sender = &deposits[sender_idx];

        // Try to acquire per-ledger semaphore (non-blocking).
        // If this ledger already has an in-flight transfer, skip to avoid
        // Compute amount and fee
        let mut rng = OsRng;
        let range = config.max_amount - config.min_amount + 1;
        let amount_sats = config.min_amount + (rng.next_u64() % range);
        let amount_msats = amount_sats * 1000;
        let fee_msats = config.fee_fixed + (amount_msats * config.fee_rate_bps / 10000);
        let debit_msats = amount_msats as i64 + fee_msats as i64;

        // Pre-debit balance atomically
        let old_bal = sender
            .balance_msats
            .fetch_sub(debit_msats, Ordering::Relaxed);
        if old_bal - debit_msats < 0 {
            sender
                .balance_msats
                .fetch_add(debit_msats, Ordering::Relaxed);
            // Check if all deposits are depleted
            if last_dispatch_time.elapsed() > Duration::from_secs(30) {
                let min_amount_msats = config.min_amount * 1000;
                let min_fee_msats =
                    config.fee_fixed + (min_amount_msats * config.fee_rate_bps / 10000);
                let min_needed = min_amount_msats as i64 + min_fee_msats as i64;
                let any_funded = deposits
                    .iter()
                    .any(|d| d.balance_msats.load(Ordering::Relaxed) >= min_needed);
                if !any_funded {
                    eprintln!("\nAll deposits depleted — no deposit has enough balance for min transfer ({} sats + {} fee):", config.min_amount, config.fee_fixed);
                    for d in deposits.iter() {
                        let bal = d.balance_msats.load(Ordering::Relaxed);
                        eprintln!("  {}: {} msats ({} sats)", d.alias, bal, bal / 1000);
                    }
                    break;
                }
            }
            continue;
        }
        last_dispatch_time = Instant::now();

        // Pick receiver (random deposit on same ledger, different from sender)
        let same_ledger = &ledger_deps[&sender.ledger_id];
        let candidates: Vec<usize> = same_ledger
            .iter()
            .copied()
            .filter(|&i| i != sender_idx)
            .collect();
        if candidates.is_empty() {
            sender
                .balance_msats
                .fetch_add(debit_msats, Ordering::Relaxed);
            continue;
        }
        let receiver_idx = candidates[rng.next_u64() as usize % candidates.len()];

        // Generate HTLC preimage/hash
        let mut preimage = [0u8; 32];
        rng.fill_bytes(&mut preimage);
        let hash = bitcoin::hashes::sha256::Hash::hash(&preimage).to_byte_array();

        let work = TransferWork {
            sender_idx,
            receiver_idx,
            amount_sats,
            fee_msats,
            preimage,
            hash,
        };

        // Hard gate at max_workers
        let max_w = max_workers_dynamic.load(Ordering::Relaxed) as u64;
        while metrics.inflight.load(Ordering::Relaxed) >= max_w {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }

        // Acquire semaphore permit and spawn task
        let permit = sem.clone().acquire_owned().await.unwrap();
        let deposits_c = deposits.clone();
        let transports_c = transports.clone();
        let secp_c = secp.clone();
        let metrics_c = metrics.clone();
        let timeout_height = config.timeout_height;
        let lock_timeout_secs = config.lock_timeout_secs;

        metrics.inflight.fetch_add(1, Ordering::Relaxed);
        total_dispatched += 1;

        tokio::spawn(async move {
            let result = execute_transfer(
                &transports_c,
                &deposits_c,
                &secp_c,
                &work,
                timeout_height,
                lock_timeout_secs,
            )
            .await;

            // Process result
            if result.success {
                let credit_msats = work.amount_sats as i64 * 1000;
                deposits_c[work.receiver_idx]
                    .balance_msats
                    .fetch_add(credit_msats, Ordering::Relaxed);
                metrics_c.success.fetch_add(1, Ordering::Relaxed);
                metrics_c
                    .volume_sats
                    .fetch_add(work.amount_sats, Ordering::Relaxed);
            } else if !result.locked {
                // Lock failed — restore sender balance
                let restore = work.amount_sats as i64 * 1000 + work.fee_msats as i64;
                deposits_c[work.sender_idx]
                    .balance_msats
                    .fetch_add(restore, Ordering::Relaxed);
                metrics_c.failed.fetch_add(1, Ordering::Relaxed);
                if result
                    .error
                    .as_deref()
                    .is_some_and(|e| e.contains("timeout"))
                {
                    metrics_c.timeouts.fetch_add(1, Ordering::Relaxed);
                }
                if let Some(ref e) = result.error {
                    metrics_c.record_error(&format!("lock: {}", e));
                }
            } else {
                // Lock succeeded but complete failed — funds stuck
                metrics_c.failed.fetch_add(1, Ordering::Relaxed);
                if let Some(ref e) = result.error {
                    metrics_c.record_error(&format!("complete: {}", e));
                }
            }

            if result.lock_us > 0 {
                metrics_c
                    .lock_latency_us
                    .fetch_add(result.lock_us, Ordering::Relaxed);
                metrics_c.lock_count.fetch_add(1, Ordering::Relaxed);
            }
            if result.complete_us > 0 {
                metrics_c
                    .complete_latency_us
                    .fetch_add(result.complete_us, Ordering::Relaxed);
                metrics_c.complete_count.fetch_add(1, Ordering::Relaxed);
            }

            metrics_c.inflight.fetch_sub(1, Ordering::Relaxed);
            drop(permit);
        });
    }

    // Wait for in-flight transfers to complete
    eprintln!("Waiting for in-flight transfers...");
    let drain_start = Instant::now();
    loop {
        let inflight = metrics.inflight.load(Ordering::Relaxed);
        if inflight == 0 || drain_start.elapsed() > Duration::from_secs(30) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Print summary
    let elapsed = start_time.elapsed().as_secs_f64();
    let success = metrics.success.load(Ordering::Relaxed);
    let failed = metrics.failed.load(Ordering::Relaxed);
    let timeouts = metrics.timeouts.load(Ordering::Relaxed);
    let volume = metrics.volume_sats.load(Ordering::Relaxed);

    eprintln!("\n=== Summary ===");
    eprintln!("Duration:     {:.1}s", elapsed);
    eprintln!("Dispatched:   {}", total_dispatched);
    eprintln!("Success:      {}", success);
    eprintln!("Failed:       {} (timeouts: {})", failed, timeouts);
    eprintln!("Volume:       {} sats", volume);
    eprintln!("Avg TPS:      {:.1}", success as f64 / elapsed);

    if metrics.lock_count.load(Ordering::Relaxed) > 0 {
        let avg_lock = metrics.lock_latency_us.load(Ordering::Relaxed) as f64
            / metrics.lock_count.load(Ordering::Relaxed) as f64
            / 1000.0;
        eprintln!("Avg lock:     {:.1}ms", avg_lock);
    }
    if metrics.complete_count.load(Ordering::Relaxed) > 0 {
        let avg_complete = metrics.complete_latency_us.load(Ordering::Relaxed) as f64
            / metrics.complete_count.load(Ordering::Relaxed) as f64
            / 1000.0;
        eprintln!("Avg complete: {:.1}ms", avg_complete);
    }

    // Error breakdown
    {
        let errors = metrics.error_counts.lock().unwrap();
        if !errors.is_empty() {
            eprintln!("\nErrors:");
            let mut sorted: Vec<_> = errors.iter().collect();
            sorted.sort_by(|a, b| b.1.cmp(a.1));
            for (msg, count) in sorted {
                eprintln!("  {:>5}x  {}", count, msg);
            }
        }
    }

    // Disconnect transports
    for t in transports.iter() {
        t.disconnect().await;
    }
    reporter.abort();

    Ok(())
}
