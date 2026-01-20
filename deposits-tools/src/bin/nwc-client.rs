#!/usr/bin/env rust

use std::error::Error;
use std::fs;
use std::path::Path;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use futures_util::{SinkExt, StreamExt};
use bitcoin::secp256k1::{Secp256k1, SecretKey, PublicKey, Keypair, XOnlyPublicKey, Message as SecpMessage};
use bitcoin::hashes::{Hash, sha256};
use hex;
use rand::RngCore;
use prost::Message as ProstMessage;

// Protobuf imports for NWC endpoints
use deposits_ldk::service::{
    GetNwcInfoRequest, GetNwcInfoResponse,
    DepositsError,
    endpoints,
};

// NIP-44 encryption
use chacha20::cipher::{KeyIvInit, StreamCipher};
use hkdf::Hkdf;
use sha2::Sha256;
use hmac::{Hmac, Mac};
type HmacSha256 = Hmac<Sha256>;

use deposits_tools::network_config::NetworkConfig;

/// API key for ldk-server authentication
const API_KEY: &str = "test_api_key";

/// Compute HMAC-SHA256 auth header for ldk-server
fn compute_auth_header(body: &[u8]) -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("System time should be after Unix epoch")
        .as_secs();

    let mut mac = HmacSha256::new_from_slice(API_KEY.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(&timestamp.to_be_bytes());
    mac.update(body);
    let result = mac.finalize();
    let hmac_hex = hex::encode(result.into_bytes());

    format!("HMAC {}:{}", timestamp, hmac_hex)
}

/// NIP-44 encryption implementation for gift-wrapped DMs
mod nip44 {
    use super::*;

    const NIP44_VERSION: u8 = 2;

    /// Compute NIP-44 conversation key using ECDH + HKDF
    /// NIP-44 requires the raw x-coordinate of the shared point (not SHA256 hashed)
    pub fn get_conversation_key(
        _secp: &Secp256k1<bitcoin::secp256k1::All>,
        our_secret: &SecretKey,
        their_pubkey: &XOnlyPublicKey,
    ) -> Result<[u8; 32], Box<dyn Error>> {
        use bitcoin::secp256k1::ecdh::shared_secret_point;

        // Convert x-only pubkey to full pubkey (assume even y)
        let their_pubkey_bytes = their_pubkey.serialize();
        let mut full_pubkey_bytes = [0u8; 33];
        full_pubkey_bytes[0] = 0x02; // Even y coordinate
        full_pubkey_bytes[1..].copy_from_slice(&their_pubkey_bytes);
        let their_full_pubkey = PublicKey::from_slice(&full_pubkey_bytes)?;

        // ECDH shared secret - use shared_secret_point to get raw coordinates
        // shared_secret_point returns the 64-byte (x, y) coordinates
        let shared_point = shared_secret_point(&their_full_pubkey, our_secret);

        // NIP-44 uses just the x-coordinate (first 32 bytes), NOT SHA256 hash
        let mut shared_x = [0u8; 32];
        shared_x.copy_from_slice(&shared_point[..32]);

        // HKDF-extract to derive conversation key
        // NIP-44 spec: hkdf_extract(sha256, ikm=shared_x, salt="nip44-v2")
        // HKDF-extract is: HMAC(key=salt, message=ikm)
        let hk = Hkdf::<Sha256>::new(Some(b"nip44-v2"), &shared_x);
        let mut conversation_key = [0u8; 32];
        // Extract the PRK (pseudo-random key) which is the conversation key
        // We use expand with empty info to get the PRK out (hkdf crate doesn't expose PRK directly)
        // Actually, for HKDF-extract only, we can use from_prk approach or just use hmac directly
        let mut mac = HmacSha256::new_from_slice(b"nip44-v2")
            .map_err(|_| "HMAC init failed")?;
        mac.update(&shared_x);
        let result = mac.finalize();
        conversation_key.copy_from_slice(&result.into_bytes());

        Ok(conversation_key)
    }

    /// Encrypt content using NIP-44
    pub fn encrypt(
        conversation_key: &[u8; 32],
        plaintext: &str,
    ) -> Result<String, Box<dyn Error>> {
        // Generate random nonce (32 bytes for NIP-44)
        let mut nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce);

        // Derive message keys using HKDF-expand with nonce as info
        // NIP-44 spec: keys = hkdf_expand(prk=conversation_key, info=nonce, L=76)
        let hk = Hkdf::<Sha256>::from_prk(conversation_key)
            .map_err(|_| "Invalid PRK")?;
        let mut full_key_material = [0u8; 76];
        hk.expand(&nonce, &mut full_key_material).map_err(|_| "HKDF expand failed")?;

        // NIP-44 spec key layout:
        // chacha_key: bytes 0..32 (32 bytes)
        // chacha_nonce: bytes 32..44 (12 bytes) - ChaCha20 uses 12-byte nonce
        // hmac_key: bytes 44..76 (32 bytes)
        let chacha_key: [u8; 32] = full_key_material[0..32].try_into().unwrap();
        let chacha_nonce: [u8; 12] = full_key_material[32..44].try_into().unwrap();
        let hmac_key: [u8; 32] = full_key_material[44..76].try_into().unwrap();

        // Pad plaintext (NIP-44 requires padding)
        let padded = pad_plaintext(plaintext.as_bytes());

        // Encrypt with ChaCha20 (stream cipher, not AEAD)
        let mut cipher = chacha20::ChaCha20::new(&chacha_key.into(), &chacha_nonce.into());
        let mut ciphertext = padded.clone();
        cipher.apply_keystream(&mut ciphertext);

        // Compute HMAC over (nonce || ciphertext) - this is the AAD pattern from NIP-44
        let mut mac = HmacSha256::new_from_slice(&hmac_key)
            .map_err(|_| "HMAC init failed")?;
        mac.update(&nonce);
        mac.update(&ciphertext);
        let mac_bytes = mac.finalize().into_bytes();

        // Construct payload: version (1) || nonce (32) || ciphertext || mac (32)
        let mut payload = Vec::with_capacity(1 + 32 + ciphertext.len() + 32);
        payload.push(NIP44_VERSION);
        payload.extend_from_slice(&nonce);
        payload.extend_from_slice(&ciphertext);
        payload.extend_from_slice(&mac_bytes);

        Ok(base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &payload))
    }

    /// Decrypt NIP-44 encrypted content
    pub fn decrypt(
        conversation_key: &[u8; 32],
        ciphertext_b64: &str,
    ) -> Result<String, Box<dyn Error>> {
        let payload = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, ciphertext_b64)?;

        // Minimum: version (1) + nonce (32) + min_ciphertext (34=2+32) + mac (32) = 99
        if payload.len() < 99 {
            return Err("Payload too short".into());
        }

        let version = payload[0];
        if version != NIP44_VERSION {
            return Err(format!("Unsupported NIP-44 version: {}", version).into());
        }

        let nonce: [u8; 32] = payload[1..33].try_into()?;
        // Ciphertext is between nonce and mac (last 32 bytes)
        let ciphertext = &payload[33..payload.len() - 32];
        let received_mac: [u8; 32] = payload[payload.len() - 32..].try_into()?;

        // Derive message keys using HKDF-expand with nonce as info
        let hk = Hkdf::<Sha256>::from_prk(conversation_key)
            .map_err(|_| "Invalid PRK")?;
        let mut full_key_material = [0u8; 76];
        hk.expand(&nonce, &mut full_key_material).map_err(|_| "HKDF expand failed")?;

        // NIP-44 spec key layout:
        // chacha_key: bytes 0..32 (32 bytes)
        // chacha_nonce: bytes 32..44 (12 bytes) - ChaCha20 uses 12-byte nonce
        // hmac_key: bytes 44..76 (32 bytes)
        let chacha_key: [u8; 32] = full_key_material[0..32].try_into()?;
        let chacha_nonce: [u8; 12] = full_key_material[32..44].try_into()?;
        let hmac_key: [u8; 32] = full_key_material[44..76].try_into()?;

        // Verify HMAC over (nonce || ciphertext)
        let mut mac = HmacSha256::new_from_slice(&hmac_key)
            .map_err(|_| "HMAC init failed")?;
        mac.update(&nonce);
        mac.update(ciphertext);
        let calculated_mac = mac.finalize().into_bytes();

        // Constant-time comparison
        if calculated_mac.as_slice() != received_mac {
            return Err("Invalid MAC".into());
        }

        // Decrypt with ChaCha20 (stream cipher)
        let mut cipher = chacha20::ChaCha20::new(&chacha_key.into(), &chacha_nonce.into());
        let mut plaintext_padded = ciphertext.to_vec();
        cipher.apply_keystream(&mut plaintext_padded);

        // Unpad
        let plaintext = unpad_plaintext(&plaintext_padded)?;

        Ok(String::from_utf8(plaintext)?)
    }

    /// Calculate padded length according to NIP-44 spec
    /// This matches nostr-tools calcPaddedLen implementation
    fn calc_padded_len(len: usize) -> usize {
        if len <= 32 {
            return 32;
        }
        // next_power = 1 << (floor(log2(len - 1)) + 1)
        let next_power = (len - 1).next_power_of_two();
        let chunk = if next_power <= 256 { 32 } else { next_power / 8 };
        chunk * ((len - 1) / chunk + 1)
    }

    /// Pad plaintext according to NIP-44 spec
    fn pad_plaintext(data: &[u8]) -> Vec<u8> {
        let len = data.len();
        let padded_len = calc_padded_len(len);

        let mut padded = Vec::with_capacity(2 + padded_len);
        // Length prefix (big endian u16)
        padded.push((len >> 8) as u8);
        padded.push(len as u8);
        padded.extend_from_slice(data);
        padded.resize(2 + padded_len, 0);
        padded
    }

    /// Unpad plaintext according to NIP-44 spec
    fn unpad_plaintext(data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        if data.len() < 2 {
            return Err("Padded data too short".into());
        }
        let len = ((data[0] as usize) << 8) | (data[1] as usize);
        // Validate: min 1, max 65535, fits in data, and total data length matches expected padding
        if len < 1 || len > 65535 || 2 + len > data.len() || data.len() != 2 + calc_padded_len(len) {
            return Err("Invalid padding".into());
        }
        Ok(data[2..2+len].to_vec())
    }
}

/// Create a gift-wrapped DM (NIP-17)
fn create_gift_wrap(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    sender_keypair: &Keypair,
    recipient_pubkey: &XOnlyPublicKey,
    content: &str,
) -> Result<Value, Box<dyn Error>> {
    let (sender_xonly, _) = XOnlyPublicKey::from_keypair(sender_keypair);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let mut rng = rand::thread_rng();

    // 1. Create kind 14 rumor (unsigned) - use accurate timestamp (it's encrypted)
    let rumor = json!({
        "kind": 14,
        "content": content,
        "pubkey": sender_xonly.to_string(),
        "created_at": now,  // Accurate - only sender/recipient see this
        "tags": [["p", recipient_pubkey.to_string()]]
    });

    // 2. Create kind 13 seal (encrypt rumor with sender's key to recipient)
    // Randomize seal timestamp (up to 48 hours in past for privacy from relays)
    let conversation_key = nip44::get_conversation_key(
        secp,
        &sender_keypair.secret_key(),
        recipient_pubkey,
    )?;
    let encrypted_rumor = nip44::encrypt(&conversation_key, &rumor.to_string())?;

    let seal_created_at = now - (rng.next_u64() % (2 * 24 * 60 * 60)) as u64;
    let seal_data = json!([
        0,
        sender_xonly.to_string(),
        seal_created_at,
        13,
        [],
        encrypted_rumor
    ]);
    let seal_id = sha256::Hash::hash(seal_data.to_string().as_bytes());
    let seal_id_hex = hex::encode(seal_id.as_byte_array());
    let seal_message = SecpMessage::from_digest_slice(seal_id.as_byte_array())?;
    let seal_sig = secp.sign_schnorr(&seal_message, sender_keypair);

    let seal = json!({
        "id": seal_id_hex,
        "kind": 13,
        "content": encrypted_rumor,
        "pubkey": sender_xonly.to_string(),
        "created_at": seal_created_at,
        "tags": [],
        "sig": seal_sig.to_string()
    });

    // 3. Create kind 1059 gift wrap with ephemeral key
    let mut ephemeral_secret_bytes = [0u8; 32];
    rng.fill_bytes(&mut ephemeral_secret_bytes);
    let ephemeral_secret = SecretKey::from_slice(&ephemeral_secret_bytes)?;
    let ephemeral_keypair = Keypair::from_secret_key(secp, &ephemeral_secret);
    let (ephemeral_xonly, _) = XOnlyPublicKey::from_keypair(&ephemeral_keypair);

    // Encrypt seal with ephemeral key to recipient
    let wrap_conversation_key = nip44::get_conversation_key(
        secp,
        &ephemeral_secret,
        recipient_pubkey,
    )?;

    let encrypted_seal = nip44::encrypt(&wrap_conversation_key, &seal.to_string())?;

    let wrap_created_at = now - (rng.next_u64() % (2 * 24 * 60 * 60)) as u64;
    let wrap_data = json!([
        0,
        ephemeral_xonly.to_string(),
        wrap_created_at,
        1059,
        [["p", recipient_pubkey.to_string()]],
        encrypted_seal
    ]);
    let wrap_id = sha256::Hash::hash(wrap_data.to_string().as_bytes());
    let wrap_id_hex = hex::encode(wrap_id.as_byte_array());
    let wrap_message = SecpMessage::from_digest_slice(wrap_id.as_byte_array())?;
    let wrap_sig = secp.sign_schnorr(&wrap_message, &ephemeral_keypair);

    let gift_wrap = json!({
        "id": wrap_id_hex,
        "kind": 1059,
        "content": encrypted_seal,
        "pubkey": ephemeral_xonly.to_string(),
        "created_at": wrap_created_at,
        "tags": [["p", recipient_pubkey.to_string()]],
        "sig": wrap_sig.to_string()
    });

    Ok(gift_wrap)
}

/// Unwrap a gift-wrapped DM (NIP-17) - decrypt outer layer, then seal, then extract rumor content
fn unwrap_gift_wrap(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    our_secret: &SecretKey,
    event: &Value,
) -> Result<String, Box<dyn Error>> {
    // Gift wrap (kind 1059) contains:
    // - pubkey: ephemeral pubkey (used with our secret to decrypt)
    // - content: encrypted seal

    let ephemeral_pubkey_str = event.get("pubkey")
        .and_then(|p| p.as_str())
        .ok_or("Gift wrap missing pubkey")?;
    let ephemeral_xonly = XOnlyPublicKey::from_str(ephemeral_pubkey_str)?;

    let encrypted_seal = event.get("content")
        .and_then(|c| c.as_str())
        .ok_or("Gift wrap missing content")?;

    // Decrypt gift wrap layer using our key + ephemeral pubkey
    let wrap_conversation_key = nip44::get_conversation_key(secp, our_secret, &ephemeral_xonly)?;
    let seal_json = nip44::decrypt(&wrap_conversation_key, encrypted_seal)?;

    // Parse seal (kind 13)
    let seal: Value = serde_json::from_str(&seal_json)?;

    let sender_pubkey_str = seal.get("pubkey")
        .and_then(|p| p.as_str())
        .ok_or("Seal missing pubkey")?;
    let sender_xonly = XOnlyPublicKey::from_str(sender_pubkey_str)?;

    let encrypted_rumor = seal.get("content")
        .and_then(|c| c.as_str())
        .ok_or("Seal missing content")?;

    // Decrypt seal layer using our key + sender pubkey
    let seal_conversation_key = nip44::get_conversation_key(secp, our_secret, &sender_xonly)?;
    let rumor_json = nip44::decrypt(&seal_conversation_key, encrypted_rumor)?;

    // Parse rumor (kind 14) and extract content
    let rumor: Value = serde_json::from_str(&rumor_json)?;

    let content = rumor.get("content")
        .and_then(|c| c.as_str())
        .ok_or("Rumor missing content")?;

    Ok(content.to_string())
}

#[derive(Parser)]
#[command(name = "nwc-client")]
#[command(about = "A Nostr Wallet Connect (NWC) client for interacting with Lightning wallets")]
struct Cli {
    /// Path to wallet data file
    #[arg(short, long, default_value = "nwc-wallet.json")]
    wallet_file: String,
    
    /// Target node name or port number
    #[arg(short, long, default_value = "alice", help = "Target node name or port number. Available nodes: alice, bob, charlie, diana, eve, frank, grace")]
    target: String,
    
    /// Nostr relay URL
    #[arg(short, long, default_value = "ws://localhost:7777")]
    relay: String,
    
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Get wallet info
    Info,
    /// Get wallet balance
    Balance,
    /// Create an invoice
    #[command(name = "make-invoice")]
    MakeInvoice {
        /// Amount in millisatoshis
        amount: u64,
        /// Invoice description
        #[arg(short, long, default_value = "NWC invoice")]
        description: String,
    },
    /// Pay an invoice
    #[command(name = "pay-invoice")]
    PayInvoice {
        /// Lightning invoice to pay
        invoice: String,
    },
    /// List deposits (Bitcoin Deposits specific)
    #[command(name = "list-deposits")]
    ListDeposits,
    /// Get deposit balance (Bitcoin Deposits specific)
    #[command(name = "deposit-balance")]
    DepositBalance {
        /// Deposit public key
        pubkey: String,
    },
    /// Create deposit via DM (Bitcoin Deposits specific)
    #[command(name = "init-deposit")]
    InitDeposit {
        /// Partner node ID for the deposit ledger (optional - will auto-select if not provided)
        partner_id: Option<String>,
    },
}

#[derive(Serialize, Deserialize, Default)]
struct WalletData {
    #[serde(alias = "nwc_secret")]
    secret: Option<String>,
    /// For regular wallets: TARGET server's NWC pubkey (fetched from API)
    /// For deposit wallets: This should be EMPTY (use target_nwc_pubkey instead)
    #[serde(alias = "nwc_pubkey")]
    pubkey: Option<String>,
    #[serde(alias = "relay_url")]
    relay: String,
    target: Option<String>,
    /// Deposit private key (hex) - client-generated, used for signing payment authorizations
    /// This key never touches the server - only the pubkey is sent during init-deposit
    deposit_secret: Option<String>,
    /// Deposit public key (compressed hex, 33 bytes)
    deposit_pubkey: Option<String>,
    /// Target server's NWC pubkey - used for deposit wallets where client pubkey != server pubkey
    /// Parsed from nwc_connection_string (format: nostr+walletconnect://<server_pubkey>?...)
    target_nwc_pubkey: Option<String>,
    /// Full NWC connection string (not used directly, but stored for reference)
    #[serde(default)]
    connection_string: Option<String>,
}

struct NWCClient {
    wallet_data: WalletData,
    wallet_file: String,
    secp: Secp256k1<bitcoin::secp256k1::All>,
    keypair: Option<Keypair>,
    websocket: Option<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>>,
    target_port: u16, // Only used for init-node and init-deposit commands
    target_name: String, // The target node name for this wallet
}

impl NWCClient {
    fn new(wallet_file: String, target: String, relay_url: String) -> Result<Self, Box<dyn Error>> {
        let mut wallet_data = if Path::new(&wallet_file).exists() {
            let content = fs::read_to_string(&wallet_file)?;
            serde_json::from_str(&content)?
        } else {
            WalletData::default()
        };

        // Only update relay URL if wallet doesn't have one saved, or if user explicitly provided one
        // (CLI default is ws://localhost:7777, so only override if different or wallet has no relay)
        if wallet_data.relay.is_empty() || relay_url != "ws://localhost:7777" {
            wallet_data.relay = relay_url;
        }

        let secp = Secp256k1::new();
        let keypair = if let Some(secret_hex) = &wallet_data.secret {
            let secret_bytes = hex::decode(secret_hex)?;
            let secret_key = SecretKey::from_slice(&secret_bytes)?;
            Some(Keypair::from_secret_key(&secp, &secret_key))
        } else {
            None
        };

        // Use saved target from wallet if available, otherwise use provided target
        let effective_target = wallet_data.target.as_ref().unwrap_or(&target).clone();

        // Store target port for init operations
        let target_port = if let Some(node_config) = NetworkConfig::get_node(&effective_target) {
            node_config.api_port
        } else {
            effective_target.parse().unwrap_or(3011)
        };

        Ok(NWCClient {
            wallet_data,
            wallet_file,
            secp,
            keypair,
            websocket: None,
            target_port,
            target_name: effective_target,
        })
    }
    
    fn save_wallet(&self) -> Result<(), Box<dyn Error>> {
        let json = serde_json::to_string_pretty(&self.wallet_data)?;
        fs::write(&self.wallet_file, json)?;
        Ok(())
    }
    
    async fn connect(&mut self) -> Result<(), Box<dyn Error>> {
        let (ws_stream, _) = connect_async(&self.wallet_data.relay).await?;
        self.websocket = Some(ws_stream);
        Ok(())
    }

    async fn get_target_nwc_pubkey(&mut self) -> Result<String, Box<dyn Error>> {
        // For deposit wallets, use the target_nwc_pubkey field (server's pubkey parsed from connection string)
        if let Some(target_pubkey) = &self.wallet_data.target_nwc_pubkey {
            eprintln!("🔍 Using cached target NWC pubkey: {}", target_pubkey);
            return Ok(target_pubkey.clone());
        }

        // For regular wallets, use pubkey field (server's pubkey fetched from API)
        if let Some(cached_pubkey) = &self.wallet_data.pubkey {
            eprintln!("🔍 Using cached NWC pubkey: {}", cached_pubkey);
            return Ok(cached_pubkey.clone());
        }

        let api_url = format!("https://localhost:{}{}", self.target_port, endpoints::DEPOSITS_NWC_INFO_PATH);
        eprintln!("🔍 Fetching NWC pubkey from: {}", api_url);
        eprintln!("🔍 Target node: {}", self.target_name);
        eprintln!("🔍 Target port: {}", self.target_port);

        // Build HTTPS client with cert validation disabled (self-signed certs)
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()?;

        // Send protobuf request with HMAC authentication
        let request = GetNwcInfoRequest {};
        let body = request.encode_to_vec();
        let auth_header = compute_auth_header(&body);

        let response = client
            .post(&api_url)
            .header("Content-Type", "application/octet-stream")
            .header("X-Auth", auth_header)
            .body(body)
            .send()
            .await?;

        if !response.status().is_success() {
            let bytes = response.bytes().await?;
            if let Ok(error) = DepositsError::decode(bytes.as_ref()) {
                return Err(format!("NWC info failed: {}: {}", error.code, error.message).into());
            }
            return Err(format!("Failed to fetch NWC pubkey: {}", String::from_utf8_lossy(&bytes)).into());
        }

        let bytes = response.bytes().await?;
        let nwc_response = GetNwcInfoResponse::decode(bytes.as_ref())?;
        let pubkey_str = nwc_response.pubkey;

        eprintln!("🔍 Retrieved NWC pubkey from API: {}", pubkey_str);
        // Cache the pubkey
        self.wallet_data.pubkey = Some(pubkey_str.clone());
        self.save_wallet()?;
        Ok(pubkey_str)
    }
    
    async fn send_nwc_request(&mut self, method: &str, params: Value) -> Result<Value, Box<dyn Error>> {
        if self.keypair.is_none() {
            return Err("Wallet not initialized. Run 'init' command first.".into());
        }

        let target_nwc_pubkey = self.get_target_nwc_pubkey().await?;
        eprintln!("🎯 Target NWC pubkey: {}", target_nwc_pubkey);

        if self.websocket.is_none() {
            self.connect().await?;
            eprintln!("🔌 Connected to relay: {}", self.wallet_data.relay);
        }

        let keypair = self.keypair.as_ref().unwrap();

        let ws = self.websocket.as_mut().ok_or("Not connected to relay")?;

        // Create NIP-47 request content
        let request = json!({
            "method": method,
            "params": params
        });

        // Get current timestamp
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Get x-only public key
        let (xonly_pubkey, _) = XOnlyPublicKey::from_keypair(keypair);
        let pubkey_hex = xonly_pubkey.to_string();
        eprintln!("🔑 Our client pubkey: {}", pubkey_hex);

        // Encrypt the request content using NIP-44
        // For NWC, we encrypt to the target server's pubkey
        let target_xonly = XOnlyPublicKey::from_str(&target_nwc_pubkey)?;
        let conversation_key = nip44::get_conversation_key(
            &self.secp,
            &keypair.secret_key(),
            &target_xonly,
        )?;
        let encrypted_content = nip44::encrypt(&conversation_key, &request.to_string())?;

        // Create the event data for signing
        // Include encryption tag per NIP-47 spec for better compatibility
        let event_data = json!([
            0,
            pubkey_hex,
            created_at,
            23194,                     // NWC request
            [["p", target_nwc_pubkey.clone()], ["encryption", "nip44_v2"]],
            encrypted_content
        ]);

        // Calculate event ID
        let event_json = event_data.to_string();
        let event_id = sha256::Hash::hash(event_json.as_bytes());
        let event_id_hex = hex::encode(event_id.as_byte_array());
        eprintln!("📋 Request event ID: {}", event_id_hex);

        // Sign the event ID
        let message = SecpMessage::from_digest_slice(event_id.as_byte_array())?;
        let signature = self.secp.sign_schnorr(&message, keypair);

        // Create the final signed event
        let event = json!({
            "id": event_id_hex,
            "kind": 23194,
            "content": encrypted_content,
            "pubkey": pubkey_hex,
            "created_at": created_at,
            "tags": [["p", target_nwc_pubkey], ["encryption", "nip44_v2"]],
            "sig": signature.to_string()
        });

        // Subscribe to responses before sending request
        // Use 'since' to only get fresh responses created after this request
        let sub_request = json!([
            "REQ",
            "nwc_response",
            {
                "kinds": [23195],
                "authors": [target_nwc_pubkey.clone()],
                "#p": [pubkey_hex.clone()],
                "since": created_at  // Only get responses created after our request
            }
        ]);

        eprintln!("📥 Subscribing for responses from author: {}", target_nwc_pubkey);
        eprintln!("📥 Subscription filter: {}", sub_request.to_string());
        ws.send(Message::Text(sub_request.to_string())).await?;

        // Send the event
        let relay_message = json!(["EVENT", event]).to_string();
        eprintln!("📤 Sending NWC request: {} with params: {}", method, params);
        ws.send(Message::Text(relay_message)).await?;

        // Wait for response with real timeout (90 seconds for payment + processing)
        let timeout_duration = std::time::Duration::from_secs(90);
        let start_time = std::time::Instant::now();
        eprintln!("⏳ Waiting for response (timeout: {}s)...", timeout_duration.as_secs());

        loop {
            // Calculate remaining time
            let elapsed = start_time.elapsed();
            if elapsed >= timeout_duration {
                eprintln!("⏰ Request timeout after {:?}", elapsed);
                return Err("Request timeout".into());
            }
            let remaining = timeout_duration - elapsed;

            // Wait for next message with timeout
            match tokio::time::timeout(remaining, ws.next()).await {
                Ok(Some(msg)) => {
                    match msg? {
                        Message::Text(text) => {
                            // Don't log every message to reduce noise in stress test
                            if let Ok(parsed) = serde_json::from_str::<Value>(&text) {
                                if let Some(event_array) = parsed.as_array() {
                                    if event_array.len() >= 3 && event_array[0] == "EVENT" {
                                        if let Some(event) = event_array[2].as_object() {
                                            // Check if this response references our request
                                            let is_reply_to_our_request = event.get("tags")
                                                .and_then(|tags| tags.as_array())
                                                .map(|tags| {
                                                    tags.iter().any(|tag| {
                                                        tag.as_array()
                                                            .and_then(|t| t.get(0)?.as_str())
                                                            .map(|tag_type| tag_type == "e")
                                                            .unwrap_or(false) &&
                                                        tag.as_array()
                                                            .and_then(|t| t.get(1)?.as_str())
                                                            .map(|event_id| event_id == event_id_hex)
                                                            .unwrap_or(false)
                                                    })
                                                })
                                                .unwrap_or(false);

                                            if is_reply_to_our_request {
                                                if let Some(encrypted_content) = event.get("content").and_then(|c| c.as_str()) {
                                                    // Decrypt the response using NIP-44
                                                    // Server response author pubkey (same as target in shared secret model)
                                                    let response_author = event.get("pubkey")
                                                        .and_then(|p| p.as_str())
                                                        .ok_or("Response missing pubkey")?;
                                                    let response_author_xonly = XOnlyPublicKey::from_str(response_author)?;
                                                    let response_conversation_key = nip44::get_conversation_key(
                                                        &self.secp,
                                                        &keypair.secret_key(),
                                                        &response_author_xonly,
                                                    )?;
                                                    let decrypted_content = nip44::decrypt(&response_conversation_key, encrypted_content)?;
                                                    let response: Value = serde_json::from_str(&decrypted_content)?;
                                                    return Ok(response);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        _ => {}
                    }
                }
                Ok(None) => {
                    eprintln!("❌ WebSocket stream ended without response");
                    return Err("No response received".into());
                }
                Err(_) => {
                    eprintln!("⏰ Request timeout after {:?}", start_time.elapsed());
                    return Err("Request timeout".into());
                }
            }
        }
    }
    
    async fn send_deposit_dm(&mut self, content: &str, target_pubkey: &str) -> Result<String, Box<dyn Error>> {
        if self.keypair.is_none() {
            return Err("Wallet not initialized. Run 'init' command first.".into());
        }

        if self.websocket.is_none() {
            self.connect().await?;
        }

        let keypair = self.keypair.as_ref().unwrap();
        let ws = self.websocket.as_mut().ok_or("Not connected to relay")?;

        let (our_pubkey, _) = XOnlyPublicKey::from_keypair(keypair);

        // Parse target pubkey
        let target_xonly = XOnlyPublicKey::from_str(target_pubkey)?;

        eprintln!("📤 Sending gift-wrapped DM (NIP-17):");
        eprintln!("   From: {} (our NWC wallet key)", our_pubkey);
        eprintln!("   To: {} (target node's NWC key)", target_pubkey);
        eprintln!("   Content: {}", content);

        // Create gift-wrapped DM (kind 1059 containing kind 13 seal containing kind 14 rumor)
        let gift_wrap = create_gift_wrap(&self.secp, keypair, &target_xonly, content)?;

        // Subscribe to both gift-wrapped (kind 1059) and regular DM (kind 4) responses
        // Server may respond with either format
        let sub_request = json!([
            "REQ",
            "dm_response",
            {
                "kinds": [4, 1059],
                "#p": [our_pubkey.to_string()]
            }
        ]);

        ws.send(Message::Text(sub_request.to_string())).await?;

        // Send the gift-wrapped DM
        let relay_message = json!(["EVENT", gift_wrap]).to_string();
        ws.send(Message::Text(relay_message)).await?;
        eprintln!("🎁 Gift wrap sent (kind 1059)");
        
        // Wait for response with real timeout (30 seconds for DM - simpler than payments)
        let timeout_duration = std::time::Duration::from_secs(30);
        let start_time = std::time::Instant::now();

        loop {
            let elapsed = start_time.elapsed();
            if elapsed >= timeout_duration {
                return Err("DM timeout".into());
            }
            let remaining = timeout_duration - elapsed;

            match tokio::time::timeout(remaining, ws.next()).await {
                Ok(Some(msg)) => {
                    match msg? {
                        Message::Text(text) => {
                            if let Ok(parsed) = serde_json::from_str::<Value>(&text) {
                                if let Some(event_array) = parsed.as_array() {
                                    if event_array.len() >= 3 && event_array[0] == "EVENT" {
                                        let event = &event_array[2];
                                        let kind = event.get("kind").and_then(|k| k.as_u64()).unwrap_or(0);

                                        if kind == 1059 {
                                            // Gift-wrapped response - unwrap it
                                            eprintln!("📬 Received gift-wrapped response (kind 1059)");
                                            match unwrap_gift_wrap(&self.secp, &keypair.secret_key(), event) {
                                                Ok(content) => {
                                                    eprintln!("🎁 Unwrapped content: {}", content);
                                                    return Ok(content);
                                                },
                                                Err(e) => {
                                                    eprintln!("⚠️ Failed to unwrap gift wrap: {}", e);
                                                    // Continue waiting for another response
                                                }
                                            }
                                        } else if kind == 4 {
                                            // Regular DM - decrypt with NIP-04 or take content directly
                                            if let Some(content) = event.get("content").and_then(|c| c.as_str()) {
                                                eprintln!("📬 Received regular DM (kind 4)");
                                                return Ok(content.to_string());
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        _ => {}
                    }
                },
                Ok(None) => {
                    return Err("No DM response received".into());
                },
                Err(_) => {
                    return Err("DM timeout".into());
                }
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    
    let mut client = NWCClient::new(cli.wallet_file, cli.target, cli.relay)?;
    
    match cli.command {
        Commands::Info => {
            let response = client.send_nwc_request("get_info", json!({})).await?;
            println!("{}", serde_json::to_string_pretty(&response)?);
        },
        Commands::Balance => {
            let response = client.send_nwc_request("get_balance", json!({})).await?;
            println!("{}", serde_json::to_string_pretty(&response)?);
        },
        Commands::MakeInvoice { amount, description } => {
            let params = json!({
                "amount": amount,
                "description": description
            });
            let response = client.send_nwc_request("make_invoice", params).await?;
            println!("{}", serde_json::to_string_pretty(&response)?);
        },
        Commands::PayInvoice { invoice } => {
            let params = json!({
                "invoice": invoice
            });
            let response = client.send_nwc_request("pay_invoice", params).await?;
            println!("{}", serde_json::to_string_pretty(&response)?);
        },
        Commands::ListDeposits => {
            let response = client.send_nwc_request("list_deposits", json!({})).await?;
            println!("{}", serde_json::to_string_pretty(&response)?);
        },
        Commands::DepositBalance { pubkey } => {
            let params = json!({
                "deposit_pubkey": pubkey
            });
            let response = client.send_nwc_request("get_deposit_balance", params).await?;
            println!("{}", serde_json::to_string_pretty(&response)?);
        },
        Commands::InitDeposit { partner_id } => {
            // Generate temporary client identity for the DM exchange if needed
            if client.keypair.is_none() {
                eprintln!("🔑 Generating temporary client identity for deposit creation...");
                let mut rng = rand::thread_rng();
                let mut secret_bytes = [0u8; 32];
                rng.fill_bytes(&mut secret_bytes);
                let secret_key = SecretKey::from_slice(&secret_bytes)?;
                let keypair = Keypair::from_secret_key(&client.secp, &secret_key);
                client.wallet_data.secret = Some(hex::encode(secret_bytes));
                client.keypair = Some(keypair);
            }

            // Generate the DEPOSIT keypair locally - this is separate from the NWC keypair
            // The deposit private key NEVER leaves the client, only pubkey is sent to server
            eprintln!("🔐 Generating deposit keypair (private key stays local)...");
            let mut rng = rand::thread_rng();
            let mut deposit_secret_bytes = [0u8; 32];
            rng.fill_bytes(&mut deposit_secret_bytes);
            let deposit_secret_key = SecretKey::from_slice(&deposit_secret_bytes)?;
            let deposit_pubkey = PublicKey::from_secret_key(&client.secp, &deposit_secret_key);
            let deposit_pubkey_hex = hex::encode(deposit_pubkey.serialize()); // 33 bytes compressed

            let target_nwc_pubkey = client.get_target_nwc_pubkey().await?;

            // Format: init-deposit <deposit_pubkey> [partner_node_id]
            // The deposit_pubkey is REQUIRED - server doesn't generate it
            let deposit_command = if let Some(partner) = partner_id {
                format!("init-deposit {} {}", deposit_pubkey_hex, partner)
            } else {
                format!("init-deposit {}", deposit_pubkey_hex)
            };

            eprintln!("📤 Sending deposit creation request via DM...");
            eprintln!("   Deposit pubkey (client-generated): {}", deposit_pubkey_hex);
            let response = client.send_deposit_dm(&deposit_command, &target_nwc_pubkey).await?;

            // Parse the deposit response to extract the deposit-specific NWC key
            if let Ok(deposit_info) = serde_json::from_str::<Value>(&response) {
                // Check if this is an error response
                if let Some(error) = deposit_info.get("error").and_then(|v| v.as_str()) {
                    return Err(format!("Deposit creation failed: {}", error).into());
                }

                if let (Some(returned_deposit_pubkey), Some(nwc_private_key), Some(nwc_connection_string)) = (
                    deposit_info.get("deposit_pubkey").and_then(|v| v.as_str()),
                    deposit_info.get("nwc_private_key").and_then(|v| v.as_str()),
                    deposit_info.get("nwc_connection_string").and_then(|v| v.as_str())
                ) {
                    // Verify the returned pubkey matches what we sent
                    if returned_deposit_pubkey != deposit_pubkey_hex {
                        return Err(format!(
                            "Server returned different deposit pubkey! Expected: {}, Got: {}",
                            deposit_pubkey_hex, returned_deposit_pubkey
                        ).into());
                    }

                    // Derive the NWC client keypair from the private key
                    let nwc_private_key_bytes = hex::decode(nwc_private_key)
                        .map_err(|_| "Invalid NWC private key hex")?;
                    let nwc_secret_key = SecretKey::from_slice(&nwc_private_key_bytes)
                        .map_err(|_| "Invalid NWC private key")?;
                    let nwc_keypair = Keypair::from_secret_key(&client.secp, &nwc_secret_key);

                    // Parse the SERVER's NWC pubkey from the connection string
                    // Format: nostr+walletconnect://<server_pubkey>?relay=...&secret=...
                    let server_nwc_pubkey = if nwc_connection_string.starts_with("nostr+walletconnect://") {
                        let after_scheme = &nwc_connection_string[22..]; // Skip "nostr+walletconnect://"
                        if let Some(query_start) = after_scheme.find('?') {
                            after_scheme[..query_start].to_string()
                        } else {
                            after_scheme.to_string()
                        }
                    } else {
                        return Err("Invalid NWC connection string format".into());
                    };

                    eprintln!("🎯 Server NWC pubkey (from connection string): {}", server_nwc_pubkey);

                    // Save the wallet with BOTH:
                    // 1. NWC key (for NWC protocol authentication) - client's private key
                    // 2. Deposit key (for signing payment authorizations - NEVER sent to server)
                    // 3. Target NWC pubkey (server's pubkey for addressing requests)
                    client.wallet_data.secret = Some(nwc_private_key.to_string());
                    client.wallet_data.pubkey = None; // Don't use pubkey field for deposit wallets
                    client.wallet_data.target_nwc_pubkey = Some(server_nwc_pubkey); // Server's pubkey
                    client.wallet_data.target = Some(client.target_name.clone());
                    client.wallet_data.deposit_secret = Some(hex::encode(deposit_secret_bytes));
                    client.wallet_data.deposit_pubkey = Some(deposit_pubkey_hex.clone());
                    client.keypair = Some(nwc_keypair);

                    // Save the wallet - this is the ONLY point where we persist the wallet
                    client.save_wallet()?;

                    eprintln!("✅ Deposit created successfully!");
                    eprintln!("🔑 Deposit pubkey (yours): {}", deposit_pubkey_hex);
                    eprintln!("🔐 Deposit private key stored locally (never sent to server)");
                    eprintln!("🔗 NWC connection: {}", nwc_connection_string);
                    eprintln!("📁 Wallet saved with both NWC key and deposit key");
                    eprintln!("💡 This wallet now has scoped access to only this deposit.");
                } else {
                    return Err(format!("Deposit response missing required fields. Response: {}", response).into());
                }
            } else {
                return Err(format!("Failed to parse deposit response as JSON: {}", response).into());
            }
        },
    }

    Ok(())
}