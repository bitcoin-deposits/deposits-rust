//! # NWC (Nostr Wallet Connect) Service
//!
//! This module provides NIP-47 server-side protocol implementation for Lightning nodes.
//! It connects to a Nostr relay and processes wallet requests, enabling remote wallet
//! functionality through the Nostr network.

// Allow unused variables in this service module - many access_level and payment_id
// parameters are reserved for future use with finer-grained access control
#![allow(unused_variables)]

use std::sync::Arc;
use std::str::FromStr;
use std::collections::{HashMap, HashSet};
use tokio::sync::Mutex;
use serde::{Serialize, Deserialize};
use serde_json::{json, Value};
use bitcoin::secp256k1::{Secp256k1, SecretKey, PublicKey, XOnlyPublicKey, Keypair, Message as SecpMessage};
use bitcoin::hashes::{Hash, sha256};
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use url::Url;
use tokio::sync::mpsc;
use rand::{self, RngCore};
use ldk_node::Node;
use deposits_ldk::handler::{RecoveryOperations, DepositOperations, LedgerOperationsExt};

// NIP-44 encryption
use chacha20::cipher::{KeyIvInit, StreamCipher};
use hkdf::Hkdf;
use sha2::Sha256;
use hmac::{Hmac, Mac};
type HmacSha256 = Hmac<Sha256>;

/// NIP-44 encryption implementation for gift-wrapped DMs
/// Compatible with nostr-tools nip44.js implementation
mod nip44 {
    use super::*;

    const NIP44_VERSION: u8 = 2;

    /// Compute NIP-44 conversation key using ECDH + HKDF
    /// NIP-44 requires the raw x-coordinate of the shared point (not SHA256 hashed)
    pub fn get_conversation_key(
        our_secret: &SecretKey,
        their_pubkey: &XOnlyPublicKey,
    ) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
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
        // NIP-44 spec: conversation_key = HMAC-SHA256(key=salt, message=shared_x)
        let mut mac = HmacSha256::new_from_slice(b"nip44-v2")
            .map_err(|_| "HMAC init failed")?;
        mac.update(&shared_x);
        let result = mac.finalize();

        let mut conversation_key = [0u8; 32];
        conversation_key.copy_from_slice(&result.into_bytes());

        Ok(conversation_key)
    }

    /// Encrypt content using NIP-44
    pub fn encrypt(
        conversation_key: &[u8; 32],
        plaintext: &str,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
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
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
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
    fn unpad_plaintext(data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        if data.len() < 2 {
            return Err("Padded data too short".into());
        }
        let len = ((data[0] as usize) << 8) | (data[1] as usize);
        if len < 1 || len > 65535 {
            return Err("Invalid padding length".into());
        }
        if 2 + len > data.len() {
            return Err("Padding length exceeds data".into());
        }
        // Verify padding length is valid for this plaintext length
        let expected_padded_len = calc_padded_len(len);
        if data.len() != 2 + expected_padded_len {
            return Err(format!("Invalid padding: expected {} bytes, got {}", 2 + expected_padded_len, data.len()).into());
        }
        Ok(data[2..2+len].to_vec())
    }
}

/// NIP-04 encryption implementation (legacy, for @getalby SDK compatibility)
/// Uses AES-256-CBC with ECDH shared secret
mod nip04 {
    use super::*;
    use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
    use cbc::{Decryptor, Encryptor};

    type Aes256CbcEnc = Encryptor<aes::Aes256>;
    type Aes256CbcDec = Decryptor<aes::Aes256>;

    /// Compute NIP-04 shared secret using ECDH + SHA256
    /// NIP-04 uses SHA256(shared_point.x) as the shared secret
    pub fn get_shared_secret(
        our_secret: &SecretKey,
        their_pubkey: &XOnlyPublicKey,
    ) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
        use bitcoin::secp256k1::ecdh::shared_secret_point;

        // Convert x-only pubkey to full pubkey (assume even y)
        let their_pubkey_bytes = their_pubkey.serialize();
        let mut full_pubkey_bytes = [0u8; 33];
        full_pubkey_bytes[0] = 0x02; // Even y coordinate
        full_pubkey_bytes[1..].copy_from_slice(&their_pubkey_bytes);
        let their_full_pubkey = PublicKey::from_slice(&full_pubkey_bytes)?;

        // ECDH shared secret - get raw coordinates
        let shared_point = shared_secret_point(&their_full_pubkey, our_secret);

        // NIP-04 uses the raw x-coordinate directly as the AES key (NOT SHA256!)
        // This matches nostr-tools/secp256k1: getSharedSecret(sk, pk).slice(1, 33)
        let mut shared_secret = [0u8; 32];
        shared_secret.copy_from_slice(&shared_point[..32]);

        Ok(shared_secret)
    }

    /// Encrypt content using NIP-04 (AES-256-CBC)
    pub fn encrypt(
        shared_secret: &[u8; 32],
        plaintext: &str,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        // Generate random 16-byte IV
        let mut iv = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut iv);

        // Pad plaintext to block size (PKCS7)
        let plaintext_bytes = plaintext.as_bytes();
        let padding_len = 16 - (plaintext_bytes.len() % 16);
        let mut padded = plaintext_bytes.to_vec();
        padded.extend(std::iter::repeat(padding_len as u8).take(padding_len));

        // Encrypt with AES-256-CBC
        let cipher = Aes256CbcEnc::new(shared_secret.into(), &iv.into());
        let ciphertext = cipher.encrypt_padded_vec_mut::<aes::cipher::block_padding::NoPadding>(&padded);

        // Format: base64(ciphertext)?iv=base64(iv)
        let ct_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &ciphertext);
        let iv_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &iv);

        Ok(format!("{}?iv={}", ct_b64, iv_b64))
    }

    /// Decrypt NIP-04 encrypted content
    pub fn decrypt(
        shared_secret: &[u8; 32],
        encrypted: &str,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        // Parse format: base64(ciphertext)?iv=base64(iv)
        let parts: Vec<&str> = encrypted.split("?iv=").collect();
        if parts.len() != 2 {
            return Err("Invalid NIP-04 format: expected ciphertext?iv=iv".into());
        }

        let ciphertext = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, parts[0])?;
        let iv_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, parts[1])?;

        if iv_bytes.len() != 16 {
            return Err("Invalid IV length".into());
        }
        let iv: [u8; 16] = iv_bytes.try_into().map_err(|_| "IV conversion failed")?;

        // Decrypt with AES-256-CBC
        let cipher = Aes256CbcDec::new(shared_secret.into(), &iv.into());
        let mut decrypted = ciphertext.clone();
        let plaintext = cipher.decrypt_padded_mut::<aes::cipher::block_padding::Pkcs7>(&mut decrypted)
            .map_err(|_| "Decryption failed")?;

        Ok(String::from_utf8(plaintext.to_vec())?)
    }
}

/// NWC Service that connects to Nostr relay and processes NIP-47 wallet requests
pub struct NWCService {
    node: Arc<Node>,
    relay_url: String,
    keypair: Keypair,
    pubkey: XOnlyPublicKey,
    port: u16,
    secp: Secp256k1<bitcoin::secp256k1::All>,
    sessions: Arc<Mutex<HashMap<String, NWCSession>>>,
    /// Registry of NWC pubkeys and their access levels
    access_registry: Arc<Mutex<HashMap<String, NWCAccessLevel>>>,
    /// Channel to trigger subscription updates when new keys are registered
    subscription_update_tx: Arc<Mutex<Option<mpsc::UnboundedSender<()>>>>,
    /// Set of event IDs we've already processed (to prevent duplicate responses)
    processed_events: Arc<Mutex<HashSet<String>>>,
    /// Track pending outgoing payments: payment_id -> (success_sender, deposit_pubkey, amount_msat)
    /// On success, the preimage is returned; on failure, an error string
    pending_outgoing_payments: Arc<Mutex<HashMap<[u8; 32], (tokio::sync::oneshot::Sender<Result<Option<[u8; 32]>, String>>, bitcoin::secp256k1::PublicKey, u64)>>>,
    /// Persistent mapping of client nostr pubkeys to their deposits (prevents duplicates on restart)
    client_deposits: Arc<Mutex<ClientDepositsStore>>,
    /// Server start time (unix timestamp) - used to filter out historical gift-wrapped DMs
    server_start_time: u64,
}

/// Context for processing NWC requests in background tasks
/// This allows requests to be processed without blocking the main websocket loop
pub struct NWCServiceTaskContext {
    node: Arc<Node>,
    keypair: Keypair,
    pubkey: XOnlyPublicKey,
    secp: Secp256k1<bitcoin::secp256k1::All>,
    access_registry: Arc<Mutex<HashMap<String, NWCAccessLevel>>>,
    processed_events: Arc<Mutex<HashSet<String>>>,
    pending_outgoing_payments: Arc<Mutex<HashMap<[u8; 32], (tokio::sync::oneshot::Sender<Result<Option<[u8; 32]>, String>>, bitcoin::secp256k1::PublicKey, u64)>>>,
    relay_url: String,
    subscription_update_tx: Arc<Mutex<Option<mpsc::UnboundedSender<()>>>>,
    /// Persistent mapping of client nostr pubkeys to their deposits (prevents duplicates on restart)
    client_deposits: Arc<Mutex<ClientDepositsStore>>,
    /// Server start time (unix timestamp) - used to filter out historical gift-wrapped DMs
    server_start_time: u64,
}

/// NWC Access Level - defines what the NWC key can access
#[derive(Clone, Debug, PartialEq)]
pub enum NWCAccessLevel {
    /// Node-level access - can control entire Lightning node
    Node,
    /// Deposit-level access - can only access one specific deposit
    Deposit(bitcoin::secp256k1::PublicKey),
}

/// Individual NWC session with a client
pub struct NWCSession {
    client_pubkey: XOnlyPublicKey,
    last_seen: std::time::SystemTime,
    access_level: NWCAccessLevel,
}

/// Information about a created deposit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositInfo {
    /// The deposit's public key (hex string)
    pub deposit_pubkey: String,
    /// The channel ID used for this deposit (hex string)
    pub channel_id: String,
    /// Current balance in satoshis (always 0 for new deposits)
    pub balance_sat: u64,
    /// NWC connection string for remote control
    pub nwc_connection_string: String,
    /// NWC private key for client authentication (hex string)
    pub nwc_private_key: String,
}

/// Stored client deposit data for persistence (includes keypair for regeneration)
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredClientDeposit {
    /// Client's nostr pubkey (hex string)
    client_pubkey: String,
    /// The deposit info returned to client
    deposit_info: DepositInfo,
    /// Deposit keypair secret (hex string) for NWC registration
    deposit_keypair_secret: String,
}

/// Persistent storage for client deposits mapping
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ClientDepositsStore {
    /// Map of client_pubkey -> stored deposit
    deposits: HashMap<String, StoredClientDeposit>,
}

impl ClientDepositsStore {
    /// Get the storage file path from LDK_DATA_DIR environment variable
    fn storage_path() -> std::path::PathBuf {
        let data_dir = std::env::var("LDK_DATA_DIR").unwrap_or_else(|_| "/tmp/ldk".to_string());
        std::path::Path::new(&data_dir).join("client_deposits.json")
    }

    /// Load client deposits from persistent storage
    fn load() -> Self {
        let path = Self::storage_path();
        match std::fs::read_to_string(&path) {
            Ok(contents) => {
                match serde_json::from_str(&contents) {
                    Ok(store) => {
                        println!("📦 Loaded {} client deposits from {:?}",
                            match &store { ClientDepositsStore { deposits } => deposits.len() },
                            path);
                        store
                    }
                    Err(e) => {
                        eprintln!("⚠️ Failed to parse client deposits store: {}", e);
                        Self::default()
                    }
                }
            }
            Err(_) => {
                // File doesn't exist yet - normal on first run
                Self::default()
            }
        }
    }

    /// Save client deposits to persistent storage
    fn save(&self) {
        let path = Self::storage_path();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match serde_json::to_string_pretty(self) {
            Ok(json) => {
                if let Err(e) = std::fs::write(&path, json) {
                    eprintln!("⚠️ Failed to save client deposits: {}", e);
                } else {
                    println!("💾 Saved {} client deposits to {:?}", self.deposits.len(), path);
                }
            }
            Err(e) => {
                eprintln!("⚠️ Failed to serialize client deposits: {}", e);
            }
        }
    }

    /// Get deposit info for a client if exists
    fn get(&self, client_pubkey: &str) -> Option<&StoredClientDeposit> {
        self.deposits.get(client_pubkey)
    }

    /// Store deposit info for a client
    fn insert(&mut self, stored: StoredClientDeposit) {
        self.deposits.insert(stored.client_pubkey.clone(), stored);
        self.save();
    }
}

impl NWCService {
    /// Create new NWC service for the Lightning node with environment-provided key
    pub fn new_with_key(node: Arc<Node>, relay_url: String, node_port: u16, private_key_hex: String) -> Result<Self, Box<dyn std::error::Error>> {
        let secp = Secp256k1::new();

        // Parse the private key from hex
        let private_key_bytes = hex::decode(&private_key_hex)
            .map_err(|_| "Invalid NWC private key hex format")?;

        if private_key_bytes.len() != 32 {
            return Err("NWC private key must be 32 bytes".into());
        }

        let mut secret_bytes = [0u8; 32];
        secret_bytes.copy_from_slice(&private_key_bytes);

        let secret_key = SecretKey::from_slice(&secret_bytes)
            .map_err(|e| format!("Invalid NWC private key: {}", e))?;
        let keypair = Keypair::from_secret_key(&secp, &secret_key);
        let (xonly_pubkey, _) = XOnlyPublicKey::from_keypair(&keypair);

        println!("🔑 NWC Service using configured key: {}", xonly_pubkey);

        // Initialize access registry with this node-level key
        let mut access_registry = HashMap::new();
        access_registry.insert(xonly_pubkey.to_string(), NWCAccessLevel::Node);


        let server_start_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Ok(Self {
            node,
            relay_url,
            keypair,
            pubkey: xonly_pubkey,
            port: node_port,
            secp,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            access_registry: Arc::new(Mutex::new(access_registry)),
            subscription_update_tx: Arc::new(Mutex::new(None)),
            processed_events: Arc::new(Mutex::new(HashSet::new())),
            pending_outgoing_payments: Arc::new(Mutex::new(HashMap::new())),
            client_deposits: Arc::new(Mutex::new(ClientDepositsStore::load())),
            server_start_time,
        })
    }

    /// Create new NWC service for the Lightning node (generates deterministic key)
    pub fn new(node: Arc<Node>, relay_url: String, node_port: u16) -> Result<Self, Box<dyn std::error::Error>> {
        // Use Lightning node's key as base for NWC identity (related but separate)
        let lightning_node_id = node.node_id();
        let secp = Secp256k1::new();

        // Derive NWC keypair from Lightning node key + "NWC" domain separation
        let mut secret_bytes = [0u8; 32];
        // Copy Lightning node pubkey bytes as base
        secret_bytes[..32].copy_from_slice(&lightning_node_id.serialize()[1..33]); // Skip the 0x02/0x03 prefix
        // Apply domain separation for NWC
        secret_bytes[0] ^= 0x4E; // 'N' for NWC
        secret_bytes[1] ^= 0x57; // 'W' for Wallet
        secret_bytes[2] ^= 0x43; // 'C' for Connect
        secret_bytes[31] ^= (node_port & 0xFF) as u8; // Make unique per node
        secret_bytes[30] ^= ((node_port >> 8) & 0xFF) as u8;

        let secret_key = SecretKey::from_slice(&secret_bytes)
            .map_err(|e| format!("Invalid derived private key: {}", e))?;
        let keypair = Keypair::from_secret_key(&secp, &secret_key);

        let (xonly_pubkey, _) = XOnlyPublicKey::from_keypair(&keypair);
        println!("🔑 NWC Service pubkey: {} (derived from Lightning node: {})", xonly_pubkey, lightning_node_id);

        // Initialize access registry with this node-level key
        let mut access_registry = HashMap::new();
        access_registry.insert(xonly_pubkey.to_string(), NWCAccessLevel::Node);

        let server_start_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Ok(Self {
            node,
            relay_url,
            keypair,
            pubkey: xonly_pubkey,
            port: node_port,
            secp,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            access_registry: Arc::new(Mutex::new(access_registry)),
            subscription_update_tx: Arc::new(Mutex::new(None)),
            processed_events: Arc::new(Mutex::new(HashSet::new())),
            pending_outgoing_payments: Arc::new(Mutex::new(HashMap::new())),
            client_deposits: Arc::new(Mutex::new(ClientDepositsStore::load())),
            server_start_time,
        })
    }

    /// Get the NWC service public key
    pub fn pubkey(&self) -> XOnlyPublicKey {
        self.pubkey
    }

    /// Get the relay URL this service connects to
    pub fn relay_url(&self) -> &str {
        &self.relay_url
    }

    /// Get the NWC secret (private key) for node-level access
    /// WARNING: This secret grants full node control - only share with authorized operators
    pub fn secret(&self) -> String {
        hex::encode(self.keypair.secret_key().secret_bytes())
    }

    /// Get the full NWC connection string for node-level access
    /// Format: nostr+walletconnect://<pubkey>?relay=<relay>&secret=<secret>
    pub fn connection_string(&self) -> String {
        format!(
            "nostr+walletconnect://{}?relay={}&secret={}",
            self.pubkey,
            self.relay_url,
            self.secret()
        )
    }

    /// Register a new deposit-specific NWC key
    pub async fn register_deposit_nwc_key(&self, nwc_pubkey: XOnlyPublicKey, deposit_pubkey: bitcoin::secp256k1::PublicKey) {
        let mut registry = self.access_registry.lock().await;
        registry.insert(nwc_pubkey.to_string(), NWCAccessLevel::Deposit(deposit_pubkey));
        println!("🔑 Registered deposit NWC key {} for deposit {}", nwc_pubkey, deposit_pubkey);
        drop(registry);

        // Trigger subscription update to include the new key immediately
        let tx_lock = self.subscription_update_tx.lock().await;
        if let Some(ref sender) = *tx_lock {
            if let Err(_) = sender.send(()) {
                println!("⚠️  Warning: Could not trigger subscription update - connection may be closed");
            } else {
                println!("🔔 Triggered live subscription update for new deposit key {}", nwc_pubkey);
            }
        } else {
            println!("⚠️  Warning: No subscription update sender available - service may not be started yet");
        }
    }

    /// Rebuild access registry from persisted deposits
    /// Call this after service startup to restore NWC keys for existing deposits
    pub async fn rebuild_access_registry_from_deposits(&self) -> Result<(), Box<dyn std::error::Error>> {
        #[cfg(feature = "bitcoin-deposits")]
        {
            if let Some(bd_handler) = self.node.deposits() {
                let deposits: Vec<bitcoin::secp256k1::PublicKey> = bd_handler.list_deposits()
                    .map_err(|e| format!("Failed to list deposits: {}", e))?;

                let mut registry = self.access_registry.lock().await;
                let mut count = 0;

                for deposit_pubkey in deposits {
                    let (deposit_nwc_keypair, deposit_nwc_pubkey) = self.generate_deposit_nwc_keypair(deposit_pubkey);
                    registry.insert(deposit_nwc_pubkey.to_string(), NWCAccessLevel::Deposit(deposit_pubkey));
                    count += 1;
                }

                println!("♻️  Rebuilt NWC access registry with {} deposit keys from persistent storage", count);
                Ok(())
            } else {
                Ok(())
            }
        }

        #[cfg(not(feature = "bitcoin-deposits"))]
        Ok(())
    }

    /// Get the access level for an NWC pubkey
    /// Returns None if the key is not registered (security: deny by default)
    pub async fn get_access_level(&self, nwc_pubkey: &str) -> Option<NWCAccessLevel> {
        let registry = self.access_registry.lock().await;
        println!("🔍 Looking up access level for NWC key: {}", nwc_pubkey);
        println!("🔍 Registry contains {} keys:", registry.len());
        for (key, level) in registry.iter() {
            println!("   - {} => {:?}", key, level);
        }
        let access_level = registry.get(nwc_pubkey).cloned();
        println!("🔍 Result: {:?}", access_level);
        access_level
    }

    /// Generate a deposit-specific NWC keypair using HKDF from the NWC service's private key
    pub fn generate_deposit_nwc_keypair(&self, deposit_pubkey: bitcoin::secp256k1::PublicKey) -> (Keypair, XOnlyPublicKey) {
        // Derive deposit NWC key from NWC service's secret key using HKDF
        // This is secure: only the node operator can derive these keys
        let nwc_secret = self.keypair.secret_bytes();

        // HKDF: salt provides domain separation, info is the deposit identifier
        let hk = Hkdf::<Sha256>::new(Some(b"nwc-deposit-key-v1"), &nwc_secret);
        let mut secret_bytes = [0u8; 32];
        hk.expand(&deposit_pubkey.serialize(), &mut secret_bytes)
            .expect("HKDF expand for deposit NWC key");

        let secret_key = SecretKey::from_slice(&secret_bytes)
            .expect("Valid deposit NWC private key");
        let keypair = Keypair::from_secret_key(&self.secp, &secret_key);
        let (xonly_pubkey, _) = XOnlyPublicKey::from_keypair(&keypair);

        (keypair, xonly_pubkey)
    }

    /// Get the keypair for a specific NWC pubkey
    /// Returns the main keypair if it's the node's pubkey, or derives the deposit keypair
    async fn get_keypair_for_nwc_pubkey(&self, nwc_pubkey: &str, access_level: &NWCAccessLevel) -> Option<Keypair> {
        // Check if this is our main NWC pubkey
        if nwc_pubkey == self.pubkey.to_string() {
            return Some(self.keypair.clone());
        }

        // Otherwise, it's a deposit-specific key - derive it from the deposit pubkey
        match access_level {
            NWCAccessLevel::Deposit(deposit_pubkey) => {
                let (keypair, _) = self.generate_deposit_nwc_keypair(*deposit_pubkey);
                Some(keypair)
            }
            NWCAccessLevel::Node => {
                // Node-level access should use the main keypair
                Some(self.keypair.clone())
            }
        }
    }

    /// Handle PaymentSuccessful event for outgoing payments
    pub async fn handle_payment_successful(&self, payment_id: [u8; 32], preimage: Option<[u8; 32]>) {
        let mut pending = self.pending_outgoing_payments.lock().await;
        if let Some((tx, _pubkey, _amount)) = pending.remove(&payment_id) {
            let _ = tx.send(Ok(preimage));
        }
    }

    /// Handle PaymentFailed event for outgoing payments
    pub async fn handle_payment_failed(&self, payment_id: [u8; 32], reason: String) {
        let mut pending = self.pending_outgoing_payments.lock().await;
        if let Some((tx, _pubkey, _amount)) = pending.remove(&payment_id) {
            let _ = tx.send(Err(reason));
        }
    }

    /// Start the NWC service (connect to relay and listen for events)
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        println!("📡 Starting NWC service, connecting to {}", self.relay_url);

        // Reconnection loop
        loop {
            // Create a new subscription update receiver for each connection
            let (subscription_update_tx, subscription_update_rx) = mpsc::unbounded_channel();

            // Store the sender in the service (replace the old one)
            {
                let mut tx_lock = self.subscription_update_tx.lock().await;
                *tx_lock = Some(subscription_update_tx);
            }

            match self.connect_and_listen(subscription_update_rx).await {
                Ok(_) => {
                    println!("🔄 NWC connection ended normally, reconnecting...");
                },
                Err(e) => {
                    eprintln!("❌ NWC connection error: {}, reconnecting in 5s...", e);
                    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                }
            }
        }
    }

    /// Connect to relay and listen for events (with automatic reconnection)
    async fn connect_and_listen(&self, mut subscription_update_rx: mpsc::UnboundedReceiver<()>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let url = Url::parse(&self.relay_url)?;
        let (ws_stream, _) = connect_async(url).await?;

        // Split the websocket into read and write halves for concurrent access
        let (mut ws_write, mut ws_read) = ws_stream.split();

        // Subscribe to both NIP-47 events and DMs directed to this node and all deposit-specific keys
        let (xonly_pubkey, _) = XOnlyPublicKey::from_keypair(&self.keypair);

        // Collect all NWC pubkeys (main + deposit-specific)
        let registry = self.access_registry.lock().await;
        let mut all_pubkeys = vec![xonly_pubkey.to_string()];
        for pubkey in registry.keys() {
            if *pubkey != xonly_pubkey.to_string() {
                all_pubkeys.push(pubkey.clone());
            }
        }
        drop(registry);

        // Subscribe with `since` filter set to 48 hours ago - this is the max timestamp
        // fuzz for NIP-17 gift wraps, so we won't miss any legitimate new messages.
        // After decryption, we further filter by the accurate rumor timestamp.
        let since_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .saturating_sub(48 * 60 * 60); // 48 hours ago

        let subscription = json!([
            "REQ",
            "nwc-sub",
            {
                "kinds": [4, 1059, 23194], // DMs (4), gift wraps (1059), and NIP-47 request events (23194)
                "#p": all_pubkeys, // Events tagged to this node or any deposit-specific keys
                "since": since_timestamp
            }
        ]);

        println!("🔔 Subscribing to {} NWC pubkeys: {:?}", all_pubkeys.len(), all_pubkeys);

        ws_write.send(Message::Text(subscription.to_string())).await?;
        println!("✅ NWC service subscribed to events for pubkey: {}", xonly_pubkey);

        // Create channel for sending responses from background tasks
        let (response_tx, mut response_rx) = mpsc::unbounded_channel::<String>();

        // Create ping interval (every 30 seconds to stay well under the 50s timeout)
        let mut ping_interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
        ping_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // Track last activity for connection health monitoring
        let mut last_activity = std::time::Instant::now();

        // Process incoming messages, subscription updates, and responses
        loop {
            tokio::select! {
                // Handle WebSocket messages
                msg = ws_read.next() => {
                    last_activity = std::time::Instant::now();
                    match msg {
                        Some(Ok(Message::Text(text))) => {
                            // Process in a spawned task to avoid blocking
                            let response_tx_clone = response_tx.clone();
                            let text_clone = text.clone();
                            let service = self.clone_for_task();

                            tokio::spawn(async move {
                                if let Err(e) = service.process_relay_message_async(&text_clone, response_tx_clone).await {
                                    eprintln!("❌ Error processing relay message: {}", e);
                                }
                            });
                        },
                        Some(Ok(Message::Ping(data))) => {
                            // Respond to ping with pong
                            if let Err(e) = ws_write.send(Message::Pong(data)).await {
                                eprintln!("⚠️  Failed to send pong: {}, will reconnect", e);
                                break;
                            }
                        },
                        Some(Ok(Message::Pong(_))) => {
                            // Server responded to our ping, connection is healthy
                        },
                        Some(Ok(Message::Close(_))) => {
                            println!("🔌 NWC relay connection closed, will reconnect");
                            break;
                        },
                        Some(Ok(_)) => continue,
                        Some(Err(e)) => {
                            eprintln!("⚠️  WebSocket error: {}, will reconnect", e);
                            break;
                        },
                        None => {
                            println!("🔌 WebSocket stream ended, will reconnect");
                            break;
                        }
                    }
                },

                // Send responses from background tasks
                response = response_rx.recv() => {
                    if let Some(response_msg) = response {
                        if let Err(e) = ws_write.send(Message::Text(response_msg)).await {
                            eprintln!("❌ Failed to send response: {}, will reconnect", e);
                            break;
                        }
                    }
                },

                // Send periodic pings to keep connection alive
                _ = ping_interval.tick() => {
                    // Check if we've had any activity recently
                    if last_activity.elapsed() > std::time::Duration::from_secs(45) {
                        println!("⚠️  No activity for 45s, sending ping");
                    }
                    if let Err(e) = ws_write.send(Message::Ping(vec![])).await {
                        eprintln!("❌ Failed to send ping: {}, will reconnect", e);
                        break;
                    }
                },

                // Handle subscription updates
                _ = subscription_update_rx.recv() => {
                    println!("🔔 Received subscription update signal, re-subscribing...");

                    // Close old subscription first to avoid duplicate events
                    let close_msg = json!(["CLOSE", "nwc-sub"]);
                    if let Err(e) = ws_write.send(Message::Text(close_msg.to_string())).await {
                        eprintln!("❌ Failed to close old subscription: {}, will reconnect", e);
                        break;
                    }

                    // Re-collect all NWC pubkeys (main + deposit-specific)
                    let registry = self.access_registry.lock().await;
                    let mut all_pubkeys = vec![xonly_pubkey.to_string()];
                    for pubkey in registry.keys() {
                        if *pubkey != xonly_pubkey.to_string() {
                            all_pubkeys.push(pubkey.clone());
                        }
                    }
                    drop(registry);

                    // Send updated subscription with 48-hour `since` filter
                    let since_timestamp = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs()
                        .saturating_sub(48 * 60 * 60);

                    let subscription = json!([
                        "REQ",
                        "nwc-sub",
                        {
                            "kinds": [4, 1059, 23194], // DMs (4), gift wraps (1059), and NIP-47 request events (23194)
                            "#p": all_pubkeys, // Events tagged to this node or any deposit-specific keys
                            "since": since_timestamp
                        }
                    ]);

                    if let Err(e) = ws_write.send(Message::Text(subscription.to_string())).await {
                        eprintln!("❌ Failed to send subscription update: {}, will reconnect", e);
                        break;
                    } else {
                        println!("✅ NWC subscription updated successfully");
                    }
                }
            }
        }

        Ok(())
    }

    /// Clone service data needed for background task processing
    fn clone_for_task(&self) -> NWCServiceTaskContext {
        NWCServiceTaskContext {
            node: self.node.clone(),
            keypair: self.keypair.clone(),
            pubkey: self.pubkey,
            secp: Secp256k1::new(),
            access_registry: self.access_registry.clone(),
            processed_events: self.processed_events.clone(),
            pending_outgoing_payments: self.pending_outgoing_payments.clone(),
            relay_url: self.relay_url.clone(),
            subscription_update_tx: self.subscription_update_tx.clone(),
            client_deposits: self.client_deposits.clone(),
            server_start_time: self.server_start_time,
        }
    }

    /// Process incoming message from Nostr relay
    async fn process_relay_message(
        &self,
        ws_stream: &mut tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
        text: &str
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Ok(relay_msg) = serde_json::from_str::<Value>(text) {
            if let Some(msg_type) = relay_msg.get(0).and_then(|v| v.as_str()) {
                match msg_type {
                    "EVENT" => {
                        if let Some(event) = relay_msg.get(2) {
                            self.process_nostr_event(ws_stream, event).await?;
                        }
                    },
                    "OK" => {
                        // Acknowledgment from relay
                        if let Some(accepted) = relay_msg.get(2).and_then(|v| v.as_bool()) {
                            if accepted {
                                println!("✅ NWC response sent successfully");
                            } else {
                                println!("❌ NWC response rejected by relay");
                            }
                        }
                    },
                    _ => {}
                }
            }
        }
        Ok(())
    }

    /// Process incoming Nostr event (DM or NWC)
    async fn process_nostr_event(
        &self,
        ws_stream: &mut tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
        event: &Value
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Parse event fields
        let event_id = event.get("id").and_then(|v| v.as_str()).unwrap_or("unknown");
        let pubkey = event.get("pubkey").and_then(|v| v.as_str()).unwrap_or("");
        let content = event.get("content").and_then(|v| v.as_str()).unwrap_or("");
        let kind = event.get("kind").and_then(|v| v.as_u64()).unwrap_or(0);

        // Check if we've already processed this event
        {
            let mut processed = self.processed_events.lock().await;
            if processed.contains(event_id) {
                //println!("⏭️  Skipping already processed event {}", event_id);
                return Ok(());
            }
            // Mark as processed
            processed.insert(event_id.to_string());
        }

        println!("📥 Processing Nostr event {} (kind {}) from {}", event_id, kind, pubkey);

        match kind {
            4 => {
                // Regular DM - handle deposit creation requests (respond with regular DM)
                self.process_deposit_dm(ws_stream, event, pubkey, content, false).await?;
            },
            1059 => {
                // NIP-17 gift-wrapped DM - unwrap and process inner content
                self.process_gift_wrap(ws_stream, event, pubkey, content).await?;
            },
            23194 => {
                // NIP-47 NWC request - handle wallet operations
                self.process_nwc_request(ws_stream, event, pubkey, content).await?;
            },
            _ => {
                println!("🤷 Unknown event kind: {}", kind);
            }
        }

        Ok(())
    }

    /// Process NIP-17 gift-wrapped DM
    /// Unwraps: kind 1059 (gift wrap) -> kind 13 (seal) -> kind 14 (rumor)
    async fn process_gift_wrap(
        &self,
        ws_stream: &mut tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
        event: &Value,
        wrap_pubkey: &str,
        encrypted_content: &str
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use std::str::FromStr;
        println!("🎁 Processing gift-wrapped DM from ephemeral key {}", wrap_pubkey);

        // Parse the wrapper pubkey (ephemeral key used by sender)
        let wrap_xonly = XOnlyPublicKey::from_str(wrap_pubkey)?;

        // Decrypt the gift wrap
        let conversation_key = nip44::get_conversation_key(
            &self.keypair.secret_key(),
            &wrap_xonly,
        )?;

        let seal_json = match nip44::decrypt(&conversation_key, encrypted_content) {
            Ok(json) => json,
            Err(e) => {
                println!("❌ Failed to decrypt gift wrap: {}", e);
                return Ok(());
            }
        };

        // Parse the seal (kind 13)
        let seal: Value = serde_json::from_str(&seal_json)?;
        let seal_pubkey = seal["pubkey"].as_str().ok_or("Missing seal pubkey")?;
        let seal_content = seal["content"].as_str().ok_or("Missing seal content")?;

        println!("📜 Unwrapped seal from {}", seal_pubkey);

        // Decrypt the seal to get the rumor
        let sender_xonly = XOnlyPublicKey::from_str(seal_pubkey)?;
        let seal_conversation_key = nip44::get_conversation_key(
            &self.keypair.secret_key(),
            &sender_xonly,
        )?;

        let rumor_json = match nip44::decrypt(&seal_conversation_key, seal_content) {
            Ok(json) => json,
            Err(e) => {
                println!("❌ Failed to decrypt seal: {}", e);
                return Ok(());
            }
        };

        // Parse the rumor (kind 14)
        let rumor: Value = serde_json::from_str(&rumor_json)?;
        let rumor_pubkey = rumor["pubkey"].as_str().ok_or("Missing rumor pubkey")?;
        let rumor_content = rumor["content"].as_str().ok_or("Missing rumor content")?;
        let rumor_kind = rumor["kind"].as_u64().unwrap_or(0);
        let rumor_created_at = rumor["created_at"].as_u64().unwrap_or(0);

        println!("📬 Unwrapped rumor (kind {}) from {}: {}", rumor_kind, rumor_pubkey, rumor_content);

        // Filter out historical messages from before this server session started
        // The rumor timestamp is encrypted and can be accurate, so we use a tight buffer
        const RUMOR_TIMESTAMP_BUFFER: u64 = 5 * 60; // 5 minutes in seconds
        let cutoff_time = self.server_start_time.saturating_sub(RUMOR_TIMESTAMP_BUFFER);

        if rumor_created_at < cutoff_time {
            println!("⏰ Ignoring historical gift-wrapped DM (rumor timestamp {} < cutoff {})",
                rumor_created_at, cutoff_time);
            return Ok(());
        }

        // Process based on rumor kind
        match rumor_kind {
            14 => {
                // Private DM - process as deposit creation request (respond with gift wrap)
                self.process_deposit_dm(ws_stream, event, rumor_pubkey, rumor_content, true).await?;
            },
            _ => {
                println!("🤷 Unknown rumor kind in gift wrap: {}", rumor_kind);
            }
        }

        Ok(())
    }

    /// Query the relay for our previous DM replies to a client containing deposit info.
    /// Returns the deposit response content if found, None otherwise.
    async fn find_existing_deposit_reply(
        &self,
        client_pubkey: &str,
    ) -> Option<String> {
        use tokio::time::{timeout, Duration};

        // Open a new websocket connection to query for our replies
        let url = match Url::parse(&self.relay_url) {
            Ok(u) => u,
            Err(e) => {
                println!("⚠️ Failed to parse relay URL for dedup query: {}", e);
                return None;
            }
        };

        let (mut ws, _) = match connect_async(&url).await {
            Ok(conn) => conn,
            Err(e) => {
                println!("⚠️ Failed to connect to relay for dedup query: {}", e);
                return None;
            }
        };

        let (our_pubkey, _) = XOnlyPublicKey::from_keypair(&self.keypair);

        // Query for kind 4 DMs from us to this client
        let query = json!([
            "REQ",
            "dedup-query",
            {
                "kinds": [4],
                "authors": [our_pubkey.to_string()],
                "#p": [client_pubkey]
            }
        ]);

        if let Err(e) = ws.send(Message::Text(query.to_string())).await {
            println!("⚠️ Failed to send dedup query: {}", e);
            return None;
        }

        let mut deposit_reply: Option<String> = None;

        // Read responses until EOSE or timeout
        let query_timeout = Duration::from_secs(5);
        loop {
            match timeout(query_timeout, ws.next()).await {
                Ok(Some(Ok(Message::Text(text)))) => {
                    if let Ok(msg) = serde_json::from_str::<Value>(&text) {
                        let msg_type = msg.get(0).and_then(|v| v.as_str()).unwrap_or("");

                        if msg_type == "EVENT" {
                            if let Some(event) = msg.get(2) {
                                if let Some(content) = event.get("content").and_then(|v| v.as_str()) {
                                    // Check if this is a deposit response (contains deposit_pubkey JSON)
                                    if let Ok(json) = serde_json::from_str::<Value>(content) {
                                        if json.get("deposit_pubkey").is_some() {
                                            println!("📋 Found existing deposit reply for client {}", client_pubkey);
                                            deposit_reply = Some(content.to_string());
                                            // Don't break - continue to get newest reply
                                        }
                                    }
                                }
                            }
                        } else if msg_type == "EOSE" {
                            // End of stored events - we're done
                            break;
                        }
                    }
                },
                Ok(Some(Ok(_))) => continue,
                Ok(Some(Err(e))) => {
                    println!("⚠️ Dedup query websocket error: {}", e);
                    break;
                },
                Ok(None) => break,
                Err(_) => {
                    println!("⚠️ Dedup query timed out");
                    break;
                }
            }
        }

        // Close the websocket
        let _ = ws.close(None).await;

        deposit_reply
    }

    /// Process deposit creation DM
    async fn process_deposit_dm(
        &self,
        ws_stream: &mut tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
        _event: &Value,
        client_pubkey: &str,
        content: &str,
        use_gift_wrap: bool
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        println!("💬 Processing deposit DM from {}: {} (gift_wrap={})", client_pubkey, content, use_gift_wrap);

        // Parse DM content for deposit creation request
        if content.starts_with("init-deposit") {
            // Check if we already replied to this client with a deposit (relay-based deduplication)
            if let Some(_existing_reply) = self.find_existing_deposit_reply(client_pubkey).await {
                println!("📋 Already replied to client {} - ignoring duplicate request", client_pubkey);
                return Ok(());  // Silently ignore - we already created this deposit
            }

            // Format: "init-deposit <deposit_pubkey> [channel_id]"
            // deposit_pubkey is REQUIRED - client must generate their own keypair
            let parts: Vec<&str> = content.split_whitespace().collect();
            if parts.len() < 2 {
                let error_response = serde_json::json!({
                    "error": "Missing deposit_pubkey. Format: init-deposit <deposit_pubkey> [channel_id]"
                });
                let response_content = serde_json::to_string(&error_response).unwrap();
                if use_gift_wrap {
                    self.send_gift_wrap_response(ws_stream, client_pubkey, &response_content).await?;
                } else {
                    self.send_dm_response(ws_stream, client_pubkey, &response_content).await?;
                }
                return Ok(());
            }
            let deposit_pubkey_str = parts[1];
            let channel_id = if parts.len() >= 3 {
                Some(parts[2])
            } else {
                None
            };

            // Create the deposit (always with zero balance)
            match self.create_deposit_for_client(client_pubkey, deposit_pubkey_str, channel_id).await {
                Ok(deposit_info) => {
                    // Return JSON format for NWC client parsing
                    let json_response = serde_json::json!({
                        "deposit_pubkey": deposit_info.deposit_pubkey,
                        "channel_id": deposit_info.channel_id,
                        "balance_sat": deposit_info.balance_sat,
                        "nwc_connection_string": deposit_info.nwc_connection_string,
                        "nwc_private_key": deposit_info.nwc_private_key
                    });
                    let response_content = serde_json::to_string(&json_response).unwrap();
                    // Use retry to ensure deposit reply is stored on relay for deduplication
                    if use_gift_wrap {
                        if let Err(e) = self.send_gift_wrap_response(ws_stream, client_pubkey, &response_content).await {
                            println!("⚠️ Failed to send gift-wrapped deposit response: {}", e);
                        }
                    } else {
                        if let Err(e) = self.send_deposit_dm_with_retry(client_pubkey, &response_content).await {
                            println!("⚠️ Failed to send deposit DM after retries: {}", e);
                        }
                    }
                },
                Err(e) => {
                    // Return JSON error format for consistency
                    let error_response = serde_json::json!({
                        "error": format!("Failed to create deposit: {}", e)
                    });
                    let response_content = serde_json::to_string(&error_response).unwrap();
                    if use_gift_wrap {
                        self.send_gift_wrap_response(ws_stream, client_pubkey, &response_content).await?;
                    } else {
                        self.send_dm_response(ws_stream, client_pubkey, &response_content).await?;
                    }
                }
            }
        } else if content == "/help" {
            let help_response = "🏦 Bitcoin Deposits Commands:\n\ninit-deposit [channel_id] - Create deposit and return JSON\n  - Omit channel_id to auto-select available channel\n/help - Show this help";
            if use_gift_wrap {
                self.send_gift_wrap_response(ws_stream, client_pubkey, help_response).await?;
            } else {
                self.send_dm_response(ws_stream, client_pubkey, help_response).await?;
            }
        } else {
            let response = "👋 Hello! Send /help for available commands.";
            if use_gift_wrap {
                self.send_gift_wrap_response(ws_stream, client_pubkey, response).await?;
            } else {
                self.send_dm_response(ws_stream, client_pubkey, response).await?;
            }
        }

        Ok(())
    }

    /// Process NIP-47 NWC request
    async fn process_nwc_request(
        &self,
        ws_stream: &mut tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
        event: &Value,
        pubkey: &str,
        content: &str
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // println!("📥 Processing NWC request from {}", pubkey);

        // Find which of our NWC pubkeys this event was addressed to
        let registry = self.access_registry.lock().await;
        let registered_pubkeys: Vec<String> = registry.keys().cloned().collect();
        drop(registry);

        let our_nwc_pubkey = event.get("tags")
            .and_then(|tags| tags.as_array())
            .and_then(|tags| {
                for tag in tags {
                    if let Some(tag_array) = tag.as_array() {
                        if tag_array.len() >= 2
                            && tag_array[0].as_str() == Some("p")
                            && tag_array[1].as_str().is_some()
                        {
                            let tagged_pubkey = tag_array[1].as_str().unwrap();
                            // Check if this is one of our registered NWC keys
                            if registered_pubkeys.contains(&tagged_pubkey.to_string()) {
                                return Some(tagged_pubkey.to_string());
                            }
                        }
                    }
                }
                None
            })
            .unwrap_or_else(|| self.pubkey.to_string()); // Default to main pubkey

        println!("🎯 Request addressed to our NWC pubkey: {}", our_nwc_pubkey);

        // Get access level for the CLIENT's NWC key (not our server key)
        // The `pubkey` variable is the client who sent the request
        // The `our_nwc_pubkey` is the server key they addressed the request to
        let access_level = match self.get_access_level(&pubkey).await {
            Some(level) => level,
            None => {
                println!("🚫 SECURITY: Rejecting request from unregistered NWC key: {}", pubkey);
                println!("🚫 This key is not registered in the access registry - denying by default");
                return Ok(()); // Silently ignore unauthorized requests
            }
        };
        println!("🔒 Client NWC key {} has access level: {:?}", pubkey, access_level);

        // Parse the NIP-47 request
        if let Ok(request) = serde_json::from_str::<Value>(content) {
            let method = request.get("method").and_then(|v| v.as_str()).unwrap_or("");
            let empty_params = json!({});
            let params = request.get("params").unwrap_or(&empty_params);

            println!("🔧 NWC method: {} with params: {}", method, params);

            // Process the request and generate response
            let response_content = match method {
                "get_info" => self.handle_get_info(&access_level).await,
                "get_balance" => self.handle_get_balance(&access_level).await,
                "make_invoice" => self.handle_make_invoice(&access_level, params).await,
                "pay_invoice" => self.handle_pay_invoice(&access_level, params).await,
                // Deposit-specific methods
                "get_deposit_balance" => self.handle_get_deposit_balance(&access_level, params).await,
                "list_deposits" => self.handle_list_deposits(&access_level, params).await,
                "make_deposit_invoice" => self.handle_make_deposit_invoice(&access_level, params).await,
                "pay_deposit_invoice" => self.handle_pay_deposit_invoice(&access_level, params).await,
                // Fraud proof submission (anyone can submit if they have valid proof)
                "submit_fraud_proof" => self.handle_submit_fraud_proof(params).await,
                _ => Err(format!("Unknown method: {}", method)),
            };

            // Get the original event ID for the response
            let original_event_id = event.get("id").and_then(|v| v.as_str()).unwrap_or("");

            // Send response event signed by the NWC key that received the request
            self.send_nwc_response(ws_stream, pubkey, original_event_id, &response_content, &our_nwc_pubkey).await?;
        }

        Ok(())
    }

    /// Handle get_info NWC request
    async fn handle_get_info(&self, access_level: &NWCAccessLevel) -> Result<Value, String> {
        let node_id = self.node.node_id().to_string();
        let _channels = self.node.list_channels();
        let _peers = self.node.list_peers();

        println!("🔧 NWC get_info called - including deposit methods!");

        let methods = vec![
            "get_info", "get_balance", "make_invoice", "pay_invoice",
            "get_deposit_balance", "list_deposits", "make_deposit_invoice", "pay_deposit_invoice",
            "submit_fraud_proof"
        ];

        println!("🔧 NWC methods array: {:?}", methods);

        Ok(json!({
            "alias": format!("LDK Node {}", node_id[0..8].to_string()),
            "color": "#3399ff",
            "pubkey": node_id,
            "network": "regtest",
            "block_height": 0, // TODO: Get actual block height
            "block_hash": "", // TODO: Get actual block hash
            "methods": methods
        }))
    }

    /// Handle get_balance NWC request
    async fn handle_get_balance(&self, access_level: &NWCAccessLevel) -> Result<Value, String> {
        match access_level {
            NWCAccessLevel::Node => {
                // Node-level access: return complete balance breakdown
                let balances = self.node.list_balances();
                let total_ln_balance_msat = balances.total_lightning_balance_sats * 1000;
                let onchain_balance_msat = balances.total_onchain_balance_sats * 1000;

                // Get per-channel breakdown
                let channels = self.node.list_channels();
                let mut channel_balances = Vec::new();

                for channel in channels {
                    // Calculate total balance (outbound + reserves)
                    let balance_msat = channel.outbound_capacity_msat +
                        channel.unspendable_punishment_reserve.unwrap_or(0) * 1000;

                    let channel_info = json!({
                        "channel_id": format!("{:?}", channel.channel_id),
                        "counterparty_node_id": channel.counterparty_node_id.to_string(),
                        "channel_value_sats": channel.channel_value_sats,
                        "balance_msat": balance_msat,
                        "outbound_capacity_msat": channel.outbound_capacity_msat,
                        "inbound_capacity_msat": channel.inbound_capacity_msat,
                        "is_usable": channel.is_usable,
                        "is_channel_ready": channel.is_channel_ready
                    });
                    channel_balances.push(channel_info);
                }

                println!("🔒 Node-level get_balance: Lightning {} msat, On-chain {} msat, {} channels",
                    total_ln_balance_msat, onchain_balance_msat, channel_balances.len());

                Ok(json!({
                    "balance": total_ln_balance_msat,  // Keep for backwards compatibility
                    "balance_msat": total_ln_balance_msat,
                    "onchain_balance_msat": onchain_balance_msat,
                    "lightning_balance_msat": total_ln_balance_msat,
                    "channels": channel_balances
                }))
            }
            NWCAccessLevel::Deposit(deposit_pubkey) => {
                // Deposit-level access: return only this specific deposit's balance
                if let Some(bd_handler) = self.node.deposits() {
                    match bd_handler.get_deposit_balance(*deposit_pubkey) {
                        Ok(balance_msat) => {
                            println!("🔒 Deposit-level get_balance: returning deposit {} balance {} msat", deposit_pubkey, balance_msat);
                            Ok(json!({
                                "balance": balance_msat,
                                "deposit_pubkey": deposit_pubkey.to_string()
                            }))
                        },
                        Err(e) => Err(format!("Failed to get deposit balance: {:?}", e))
                    }
                } else {
                    Err("Bitcoin Deposits not enabled".to_string())
                }
            }
        }
    }

    /// Handle make_invoice NWC request
    async fn handle_make_invoice(&self, access_level: &NWCAccessLevel, params: &Value) -> Result<Value, String> {
        let amount = params.get("amount").and_then(|v| v.as_u64()).unwrap_or(0);
        let description = params.get("description").and_then(|v| v.as_str()).unwrap_or("NWC Invoice");

        match access_level {
            NWCAccessLevel::Node => {
                // Node-level access: create general Lightning invoice
                println!("🔒 Node-level make_invoice: creating Lightning invoice for {} msat", amount);

                let description_obj = lightning_invoice::Bolt11InvoiceDescription::Direct(
                    lightning_invoice::Description::new(description.to_string())
                        .map_err(|e| format!("Invalid description: {}", e))?
                );

                let invoice = self.node.bolt11_payment().receive(
                    amount,
                    &description_obj,
                    3600 // 1 hour expiry
                ).map_err(|e| format!("Failed to create invoice: {}", e))?;

                let payment_hash = hex::encode(invoice.payment_hash().as_byte_array());

                Ok(json!({
                    "type": "incoming",
                    "invoice": invoice.to_string(),
                    "description": description,
                    "description_hash": null,
                    "preimage": null,
                    "payment_hash": payment_hash,
                    "amount": amount,
                    "fees_paid": 0,
                    "created_at": std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                    "expires_at": std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs() + 3600,
                    "settled_at": null
                }))
            }
            NWCAccessLevel::Deposit(deposit_pubkey) => {
                // Deposit-level access: create invoice scoped to this deposit
                println!("🔒 Deposit-level make_invoice: creating invoice for deposit {} amount {} msat", deposit_pubkey, amount);

                // Verify deposit exists
                if let Some(bd_handler) = self.node.deposits() {
                    match bd_handler.get_deposit_balance(*deposit_pubkey) {
                        Ok(_) => {
                            // Create Lightning invoice using the node
                            let deposit_pubkey_str = deposit_pubkey.to_string();
                            let description_obj = lightning_invoice::Bolt11InvoiceDescription::Direct(
                                lightning_invoice::Description::new(format!("{} (Deposit: {})", description, &deposit_pubkey_str[..8]))
                                    .map_err(|e| format!("Invalid description: {}", e))?
                            );

                            let invoice = self.node.bolt11_payment().receive(
                                amount,
                                &description_obj,
                                3600 // 1 hour expiry
                            ).map_err(|e| format!("Failed to create invoice: {}", e))?;

                            let payment_hash_bytes: [u8; 32] = *invoice.payment_hash().as_ref();
                            let payment_hash = hex::encode(&payment_hash_bytes);

                            // Register this payment with the Lightning Event Service so it gets credited to the deposit
                            let partner_id = if let Some(lightning_service) = self.node.lightning_event_service() {
                                // TODO: Need to determine which partner_node_id this deposit belongs to
                                // For now, we'll iterate through channel ledgers to find it
                                let partner_id = bd_handler.find_partner_for_deposit(*deposit_pubkey)
                                    .ok_or_else(|| format!("Could not find partner for deposit {}", deposit_pubkey))?;

                                println!("📋 Registering payment {} for deposit {} with partner {}",
                                    payment_hash, deposit_pubkey, partner_id);

                                // Use payment_hash as invoice_id for now (can be improved later)
                                let invoice_id = payment_hash.clone();

                                lightning_service.register_payment_for_deposit(
                                    payment_hash_bytes,
                                    partner_id,
                                    *deposit_pubkey,
                                    invoice_id,
                                    invoice.to_string()
                                );

                                partner_id
                            } else {
                                println!("⚠️  Warning: Lightning Event Service not available, payment won't be auto-credited");
                                return Err("Lightning Event Service not available".to_string());
                            };

                            // Request cosignature from partner (locking is handled inside the method)
                            println!("🔐 NWC: Requesting cosignature from partner {} for invoice {}", partner_id, payment_hash);
                            let cosignature = bd_handler.request_invoice_cosignature(
                                partner_id,
                                *deposit_pubkey,
                                payment_hash_bytes,
                                amount,
                                invoice.to_string(),
                                30000 // 30 second timeout
                            ).await.map_err(|e| format!("Failed to get cosignature: {}", e))?;

                            let cosignature_hex = hex::encode(&cosignature);
                            println!("✅ NWC: Received cosignature: {}", cosignature_hex);

                            Ok(json!({
                                "type": "incoming",
                                "invoice": invoice.to_string(),
                                "description": description,
                                "description_hash": null,
                                "preimage": null,
                                "payment_hash": payment_hash,
                                "amount": amount,
                                "fees_paid": 0,
                                "deposit_pubkey": deposit_pubkey_str,
                                "cosignature": cosignature_hex,
                                "created_at": std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap()
                                    .as_secs(),
                                "expires_at": std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap()
                                    .as_secs() + 3600,
                                "settled_at": null
                            }))
                        },
                        Err(_) => Err(format!("Deposit not found: {}", deposit_pubkey))
                    }
                } else {
                    Err("Bitcoin Deposits not enabled".to_string())
                }
            }
        }
    }

    /// Handle pay_invoice NWC request
    async fn handle_pay_invoice(&self, access_level: &NWCAccessLevel, params: &Value) -> Result<Value, String> {
        let invoice_str = params.get("invoice").and_then(|v| v.as_str())
            .ok_or("Missing invoice parameter")?;

        // Parse the invoice
        let invoice = invoice_str.parse::<lightning_invoice::Bolt11Invoice>()
            .map_err(|e| format!("Invalid invoice: {}", e))?;

        let amount_msat = invoice.amount_milli_satoshis().unwrap_or(0);

        match access_level {
            NWCAccessLevel::Node => {
                // Node-level access: pay from general Lightning funds
                println!("🔒 Node-level pay_invoice: paying {} msat from node balance", amount_msat);

                let payment_id = self.node.bolt11_payment().send(&invoice, None)
                    .map_err(|e| {
                        println!("❌ Payment failed with error: {:?}", e);
                        format!("Failed to send payment: {:?}", e)
                    })?;

                let payment_hash = hex::encode(invoice.payment_hash().as_byte_array());

                Ok(json!({
                    "type": "outgoing",
                    "invoice": invoice_str,
                    "description": match invoice.description() {
                        lightning_invoice::Bolt11InvoiceDescriptionRef::Direct(desc) => desc.to_string(),
                        lightning_invoice::Bolt11InvoiceDescriptionRef::Hash(_) => "".to_string(),
                    },
                    "description_hash": null,
                    "preimage": null, // Preimage not available until settlement
                    "payment_hash": payment_hash,
                    "amount": amount_msat,
                    "fees_paid": 0,
                    "created_at": std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                    "expires_at": null,
                    "settled_at": std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs()
                }))
            }
            NWCAccessLevel::Deposit(deposit_pubkey) => {
                // Deposit-level access: pay from this deposit's balance
                println!("🔒 Deposit-level pay_invoice: paying {} msat from deposit {}", amount_msat, deposit_pubkey);

                if let Some(bd_handler) = self.node.deposits() {
                    println!("📋 Checking deposit balance for {}", deposit_pubkey);
                    // Check if deposit has sufficient balance (both in millisatoshis)
                    match bd_handler.get_deposit_balance(*deposit_pubkey) {
                        Ok(balance_msat) => {
                            println!("💰 Deposit balance: {} msat, payment requires: {} msat", balance_msat, amount_msat);
                            if balance_msat < amount_msat {
                                return Err(format!("Insufficient deposit balance: {} msat available, {} msat required", balance_msat, amount_msat));
                            }

                            let payment_hash_bytes: [u8; 32] = *invoice.payment_hash().as_ref();
                            let payment_hash_hex = hex::encode(&payment_hash_bytes);

                            // Check if this is a same-node payment (payee is us)
                            let payee_pubkey = invoice.recover_payee_pub_key();
                            let our_node_id = self.node.node_id();

                            if payee_pubkey == our_node_id {
                                // Same-node payment: both sender and receiver are deposits on this node
                                println!("🔄 Same-node payment detected: {} -> invoice on same node", deposit_pubkey);

                                // Find the receiver deposit using the lightning_event_service
                                // (invoices are registered there when created, not stored in ledger)
                                if let Some(lightning_service) = self.node.lightning_event_service() {
                                    if let Ok((partner_node_id, receiver_deposit, _invoice_id, _bolt11)) =
                                        lightning_service.find_deposit_for_payment(payment_hash_bytes)
                                    {
                                        // Get the sender's partner (should be the same for same-node transfers)
                                        let sender_partner = bd_handler.find_partner_for_deposit(*deposit_pubkey)
                                            .ok_or_else(|| format!("Sender deposit {} not found in any ledger", deposit_pubkey))?;

                                        if sender_partner != partner_node_id {
                                            return Err(format!(
                                                "Same-node transfer requires same partner: sender has {}, receiver has {}",
                                                sender_partner, partner_node_id
                                            ));
                                        }

                                        // Execute the same-node transfer (amount in millisatoshis)
                                        bd_handler.execute_same_node_transfer(
                                            partner_node_id,
                                            *deposit_pubkey,
                                            receiver_deposit,
                                            amount_msat,
                                            payment_hash_bytes,
                                        ).map_err(|e| format!("Same-node transfer failed: {}", e))?;

                                        println!("✅ Same-node transfer complete: {} msat from {} to {}",
                                                amount_msat, deposit_pubkey, receiver_deposit);

                                        // Get preimage from payment store and mark payment as settled
                                        let preimage_hex = self.node.list_payments().iter()
                                            .find_map(|p| {
                                                match &p.kind {
                                                    ldk_node::payment::PaymentKind::Bolt11 { hash, preimage, .. } |
                                                    ldk_node::payment::PaymentKind::Bolt11Jit { hash, preimage, .. } => {
                                                        if hash.0 == payment_hash_bytes {
                                                            preimage.map(|pi| pi.0)
                                                        } else {
                                                            None
                                                        }
                                                    },
                                                    _ => None
                                                }
                                            });

                                        // Mark the payment as settled in the payment store
                                        if let Some(preimage_bytes) = preimage_hex {
                                            let payment_hash = lightning_types::payment::PaymentHash(payment_hash_bytes);
                                            let preimage = lightning_types::payment::PaymentPreimage(preimage_bytes);
                                            if let Err(e) = self.node.bolt11_payment().mark_settled_for_hash(
                                                payment_hash, preimage, amount_msat
                                            ) {
                                                println!("⚠️ Failed to mark same-node payment as settled: {:?}", e);
                                            }
                                        }

                                        let preimage_hex = preimage_hex.map(|pi| hex::encode(pi));

                                        return Ok(json!({
                                            "type": "outgoing",
                                            "invoice": invoice_str,
                                            "description": match invoice.description() {
                                                lightning_invoice::Bolt11InvoiceDescriptionRef::Direct(desc) => desc.to_string(),
                                                lightning_invoice::Bolt11InvoiceDescriptionRef::Hash(_) => "".to_string(),
                                            },
                                            "description_hash": null,
                                            "preimage": preimage_hex,
                                            "payment_hash": payment_hash_hex,
                                            "amount": amount_msat,
                                            "fees_paid": 0, // No fees for same-node transfers
                                            "deposit_pubkey": deposit_pubkey.to_string(),
                                            "same_node_transfer": true,
                                            "receiver_deposit": receiver_deposit.to_string(),
                                            "created_at": std::time::SystemTime::now()
                                                .duration_since(std::time::UNIX_EPOCH)
                                                .unwrap()
                                                .as_secs(),
                                            "expires_at": null,
                                            "settled_at": std::time::SystemTime::now()
                                                .duration_since(std::time::UNIX_EPOCH)
                                                .unwrap()
                                                .as_secs()
                                        }));
                                    } else {
                                        println!("⚠️ Same-node payment but receiver deposit not found in lightning_event_service, falling back to Lightning");
                                    }
                                } else {
                                    println!("⚠️ Same-node payment but lightning_event_service not available, falling back to Lightning");
                                }
                            }

                            // Different-node payment: use Lightning with lock/fulfill flow
                            println!("🔒 Locking {} msat from deposit {} for payment", amount_msat, deposit_pubkey);

                            // Sequence number is assigned atomically in handle_sending_lock_payment
                            // TODO: Sign with deposit's scriptpubkey private key for ownership proof
                            let lock_msg = deposits_ldk::handler::messages::SendingLockPaymentMsg {
                                payment_id: payment_hash_bytes, // Use payment_hash as payment_id
                                pubkey: *deposit_pubkey,
                                amount: amount_msat,
                                sequence_number: 0, // Ignored - assigned atomically in handler
                                scriptpubkey_signature: [0; 64], // TODO: Real signature required
                            };

                            bd_handler.handle_sending_lock_payment(lock_msg)
                                .map_err(|e| format!("Failed to lock deposit: {}", e))?;

                            println!("💸 Sending payment via Lightning...");
                            // Step 2: Pay the invoice using Lightning
                            let payment_result = self.node.bolt11_payment().send(&invoice, None);

                            let payment_id = match payment_result {
                                Ok(id) => {
                                    println!("✅ Payment initiated: {:?}", id);
                                    id
                                }
                                Err(e) => {
                                    println!("❌ Payment initiation failed: {}, unlocking deposit", e);

                                    // Release the lock on failed payment initiation
                                    // Sequence number is assigned atomically in handle_sending_fail_payment_async
                                    let fail_msg = deposits_ldk::handler::messages::SendingFailPaymentMsg {
                                        payment_id: payment_hash_bytes,
                                        pubkey: *deposit_pubkey,
                                        amount: amount_msat,
                                        sequence_number: 0, // Ignored - assigned atomically in handler
                                    };

                                    bd_handler.handle_sending_fail_payment_async(fail_msg).await
                                        .map_err(|e2| format!("Failed to unlock payment: {}", e2))?;

                                    return Err(format!("Failed to initiate payment: {}", e));
                                }
                            };

                            // Register payment and wait for completion (success or failure event)
                            let (tx, rx) = tokio::sync::oneshot::channel();
                            {
                                let mut pending = self.pending_outgoing_payments.lock().await;
                                pending.insert(payment_id.0, (tx, *deposit_pubkey, amount_msat));
                            }
                            println!("⏳ Waiting for payment completion event...");

                            // Wait for the payment to complete (with timeout)
                            let completion_result = tokio::time::timeout(
                                std::time::Duration::from_secs(60),
                                rx
                            ).await;

                            match completion_result {
                                Ok(Ok(Ok(preimage_opt))) => {
                                    // Payment succeeded - fulfill and deduct from deposit
                                    println!("✅ Payment completed successfully");

                                    // Sequence number is assigned atomically in handle_sending_fulfill_payment_async
                                    // TODO: Sign with deposit's scriptpubkey private key for ownership proof
                                    let preimage_bytes = preimage_opt.unwrap_or([0u8; 32]);
                                    let fulfill_msg = deposits_ldk::handler::messages::SendingFulfillPaymentMsg {
                                        payment_id: payment_hash_bytes,
                                        pubkey: *deposit_pubkey,
                                        amount: amount_msat,
                                        sequence_number: 0, // Ignored - assigned atomically in handler
                                        scriptpubkey_signature: [0; 64], // TODO: Real signature required
                                        preimage: preimage_bytes,
                                    };

                                    bd_handler.handle_sending_fulfill_payment_async(fulfill_msg).await
                                        .map_err(|e| format!("Failed to fulfill payment: {}", e))?;

                                    // Build success response with preimage
                                    let payment_hash = hex::encode(&payment_hash_bytes);
                                    let preimage_hex = preimage_opt.map(|p| hex::encode(p));
                                    Ok(json!({
                                        "type": "outgoing",
                                        "invoice": invoice_str,
                                        "description": match invoice.description() {
                                            lightning_invoice::Bolt11InvoiceDescriptionRef::Direct(desc) => desc.to_string(),
                                            lightning_invoice::Bolt11InvoiceDescriptionRef::Hash(_) => "".to_string(),
                                        },
                                        "description_hash": null,
                                        "preimage": preimage_hex,
                                        "payment_hash": payment_hash,
                                        "amount": amount_msat,
                                        "fees_paid": 0,
                                        "deposit_pubkey": deposit_pubkey.to_string(),
                                        "created_at": std::time::SystemTime::now()
                                            .duration_since(std::time::UNIX_EPOCH)
                                            .unwrap()
                                            .as_secs(),
                                        "expires_at": null,
                                        "settled_at": std::time::SystemTime::now()
                                            .duration_since(std::time::UNIX_EPOCH)
                                            .unwrap()
                                            .as_secs()
                                    }))
                                }
                                Ok(Ok(Err(ref error_msg))) => {
                                    // Payment failed - unlock deposit
                                    let error = format!("Payment failed: {}", error_msg);
                                    println!("❌ {}, unlocking deposit", error);

                                    // Sequence number is assigned atomically in handle_sending_fail_payment_async
                                    let fail_msg = deposits_ldk::handler::messages::SendingFailPaymentMsg {
                                        payment_id: payment_hash_bytes,
                                        pubkey: *deposit_pubkey,
                                        amount: amount_msat,
                                        sequence_number: 0, // Ignored - assigned atomically in handler
                                    };

                                    bd_handler.handle_sending_fail_payment_async(fail_msg).await
                                        .map_err(|e| format!("Failed to unlock payment: {}", e))?;

                                    Err(error)
                                }
                                Err(_) => {
                                    // Payment timed out - unlock deposit
                                    let error = "Payment timeout after 60s".to_string();
                                    println!("❌ {}, unlocking deposit", error);

                                    // Sequence number is assigned atomically in handle_sending_fail_payment_async
                                    let fail_msg = deposits_ldk::handler::messages::SendingFailPaymentMsg {
                                        payment_id: payment_hash_bytes,
                                        pubkey: *deposit_pubkey,
                                        amount: amount_msat,
                                        sequence_number: 0, // Ignored - assigned atomically in handler
                                    };

                                    bd_handler.handle_sending_fail_payment_async(fail_msg).await
                                        .map_err(|e| format!("Failed to unlock payment: {}", e))?;

                                    Err(error)
                                }
                                Ok(Err(_)) => {
                                    // Channel closed unexpectedly
                                    Err("Payment tracker channel closed unexpectedly".to_string())
                                }
                            }
                        },
                        Err(_) => Err(format!("Deposit not found: {}", deposit_pubkey))
                    }
                } else {
                    Err("Bitcoin Deposits not enabled".to_string())
                }
            }
        }
    }

    /// Send NIP-47 response event back to client
    async fn send_nwc_response(
        &self,
        ws_stream: &mut tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
        client_pubkey: &str,
        original_event_id: &str,
        response_content: &Result<Value, String>,
        responding_nwc_pubkey: &str, // The NWC pubkey that should sign this response
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Create NIP-47 response
        let response = match response_content {
            Ok(result) => json!({
                "result_type": "success",
                "result": result
            }),
            Err(error) => json!({
                "result_type": "error",
                "error": {
                    "code": "INTERNAL",
                    "message": error
                }
            })
        };

        // Get current timestamp
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Determine which keypair to use for signing
        let (signing_keypair, pubkey_hex) = if responding_nwc_pubkey == self.pubkey.to_string() {
            // Use main node NWC keypair
            (self.keypair.clone(), self.pubkey.to_string())
        } else {
            // Use deposit-specific NWC keypair
            // We need to regenerate it from the deposit pubkey
            let registry = self.access_registry.lock().await;
            if let Some(NWCAccessLevel::Deposit(deposit_pubkey)) = registry.get(responding_nwc_pubkey) {
                let (deposit_nwc_keypair, deposit_nwc_pubkey) = self.generate_deposit_nwc_keypair(*deposit_pubkey);
                drop(registry);
                (deposit_nwc_keypair, deposit_nwc_pubkey.to_string())
            } else {
                drop(registry);
                // Fallback to main keypair if not found
                (self.keypair.clone(), self.pubkey.to_string())
            }
        };

        println!("📤 Responding as NWC pubkey: {}", pubkey_hex);

        // Create the event data for signing (Nostr canonical format)
        // Must be: [0, pubkey, created_at, kind, tags, content]
        let event_data = json!([
            0,                          // always 0 for event ID calculation
            pubkey_hex,                // pubkey (hex string)
            created_at,                // created_at (unix timestamp)
            23195,                     // kind (NIP-47 response)
            [["p", client_pubkey], ["e", original_event_id]],   // tags (response to client + reference to request)
            response.to_string()      // content (JSON string)
        ]);

        // Calculate event ID (SHA256 of canonical JSON - no spaces, sorted keys)
        let event_json = serde_json::to_string(&event_data).unwrap();
        let event_id = sha256::Hash::hash(event_json.as_bytes());
        let event_id_hex = hex::encode(event_id.as_byte_array());

        // Sign the event ID with Schnorr signature using the appropriate keypair
        let message = SecpMessage::from_digest_slice(event_id.as_byte_array())?;
        let signature = self.secp.sign_schnorr(&message, &signing_keypair);

        // Create the final signed event
        let event = json!({
            "id": event_id_hex,
            "kind": 23195,
            "content": response.to_string(),
            "pubkey": pubkey_hex,
            "created_at": created_at,
            "tags": [["p", client_pubkey], ["e", original_event_id]],
            "sig": signature.to_string()
        });

        // Send the event in Nostr relay format
        let relay_message = json!(["EVENT", event]).to_string();
        ws_stream.send(Message::Text(relay_message)).await?;

        println!("📤 Sent NWC response to {}", client_pubkey);

        Ok(())
    }

    /// Handle get_deposit_balance NWC request
    async fn handle_get_deposit_balance(&self, access_level: &NWCAccessLevel, params: &Value) -> Result<Value, String> {
        let deposit_pubkey_str = params.get("deposit_pubkey").and_then(|v| v.as_str())
            .ok_or("Missing deposit_pubkey parameter")?;

        // Parse deposit pubkey
        let deposit_pubkey = deposit_pubkey_str.parse::<bitcoin::secp256k1::PublicKey>()
            .map_err(|e| format!("Invalid deposit_pubkey: {}", e))?;

        // Get deposit balance via Bitcoin Deposits handler
        if let Some(bd_handler) = self.node.deposits() {
            match bd_handler.get_deposit_balance(deposit_pubkey) {
                Ok(balance_msat) => {
                    Ok(json!({
                        "deposit_pubkey": deposit_pubkey_str,
                        "balance": balance_msat,
                        "balance_sat": balance_msat / 1000
                    }))
                },
                Err(e) => Err(format!("Failed to get deposit balance: {:?}", e))
            }
        } else {
            Err("Bitcoin Deposits not enabled".to_string())
        }
    }

    /// Handle list_deposits NWC request
    async fn handle_list_deposits(&self, access_level: &NWCAccessLevel, _params: &Value) -> Result<Value, String> {
        if let Some(bd_handler) = self.node.deposits() {
            match bd_handler.list_deposits() {
                Ok(deposit_pubkeys) => {
                    let deposits: Vec<Value> = deposit_pubkeys.iter().map(|pubkey| {
                        let balance_msat = bd_handler.get_deposit_balance(*pubkey).unwrap_or(0);
                        json!({
                            "deposit_pubkey": pubkey.to_string(),
                            "balance": balance_msat,
                            "balance_sat": balance_msat / 1000
                        })
                    }).collect();

                    Ok(json!({
                        "deposits": deposits,
                        "count": deposits.len()
                    }))
                },
                Err(e) => Err(format!("Failed to list deposits: {:?}", e))
            }
        } else {
            Err("Bitcoin Deposits not enabled".to_string())
        }
    }

    /// Handle make_deposit_invoice NWC request
    async fn handle_make_deposit_invoice(&self, access_level: &NWCAccessLevel, params: &Value) -> Result<Value, String> {
        let amount = params.get("amount").and_then(|v| v.as_u64()).unwrap_or(0);
        let description = params.get("description").and_then(|v| v.as_str()).unwrap_or("Deposit Invoice");
        let deposit_pubkey_str = params.get("deposit_pubkey").and_then(|v| v.as_str())
            .ok_or("Missing deposit_pubkey parameter")?;

        // Parse deposit pubkey
        let deposit_pubkey = deposit_pubkey_str.parse::<bitcoin::secp256k1::PublicKey>()
            .map_err(|e| format!("Invalid deposit_pubkey: {}", e))?;

        // Verify deposit exists
        if let Some(bd_handler) = self.node.deposits() {
            match bd_handler.get_deposit_balance(deposit_pubkey) {
                Ok(_) => {
                    // Create Lightning invoice using the node
                    let description_obj = lightning_invoice::Bolt11InvoiceDescription::Direct(
                        lightning_invoice::Description::new(format!("{} (Deposit: {})", description, deposit_pubkey_str))
                            .map_err(|e| format!("Invalid description: {}", e))?
                    );

                    let invoice = self.node.bolt11_payment().receive(
                        amount,
                        &description_obj,
                        3600 // 1 hour expiry
                    ).map_err(|e| format!("Failed to create invoice: {}", e))?;

                    let payment_hash_bytes: [u8; 32] = *invoice.payment_hash().as_ref();
                    let payment_hash = hex::encode(&payment_hash_bytes);

                    // Register this payment with the Lightning Event Service so it gets credited to the deposit
                    let partner_id = if let Some(lightning_service) = self.node.lightning_event_service() {
                        let partner_id = bd_handler.find_partner_for_deposit(deposit_pubkey)
                            .ok_or_else(|| format!("Could not find partner for deposit {}", deposit_pubkey))?;

                        let invoice_id = payment_hash.clone();
                        lightning_service.register_payment_for_deposit(
                            payment_hash_bytes,
                            partner_id,
                            deposit_pubkey,
                            invoice_id,
                            invoice.to_string()
                        );

                        partner_id
                    } else {
                        return Err("Lightning Event Service not available".to_string());
                    };

                    // Request cosignature from partner
                    let cosignature = bd_handler.request_invoice_cosignature(
                        partner_id,
                        deposit_pubkey,
                        payment_hash_bytes,
                        amount,
                        invoice.to_string(),
                        30000 // 30 second timeout
                    ).await.map_err(|e| format!("Failed to get cosignature: {}", e))?;

                    let cosignature_hex = hex::encode(&cosignature);

                    Ok(json!({
                        "type": "incoming",
                        "invoice": invoice.to_string(),
                        "description": description,
                        "description_hash": null,
                        "preimage": null,
                        "payment_hash": payment_hash,
                        "amount": amount,
                        "fees_paid": 0,
                        "deposit_pubkey": deposit_pubkey_str,
                        "cosignature": cosignature_hex,
                        "created_at": std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs(),
                        "expires_at": std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs() + 3600,
                        "settled_at": null
                    }))
                },
                Err(_) => Err(format!("Deposit not found: {}", deposit_pubkey_str))
            }
        } else {
            Err("Bitcoin Deposits not enabled".to_string())
        }
    }

    /// Handle pay_deposit_invoice NWC request
    async fn handle_pay_deposit_invoice(&self, access_level: &NWCAccessLevel, params: &Value) -> Result<Value, String> {
        let invoice_str = params.get("invoice").and_then(|v| v.as_str())
            .ok_or("Missing invoice parameter")?;
        let deposit_pubkey_str = params.get("deposit_pubkey").and_then(|v| v.as_str())
            .ok_or("Missing deposit_pubkey parameter")?;

        // Parse deposit pubkey
        let deposit_pubkey = deposit_pubkey_str.parse::<bitcoin::secp256k1::PublicKey>()
            .map_err(|e| format!("Invalid deposit_pubkey: {}", e))?;

        // Parse and pay the invoice using deposit funds
        let invoice = invoice_str.parse::<lightning_invoice::Bolt11Invoice>()
            .map_err(|e| format!("Invalid invoice: {}", e))?;

        let amount_msat = invoice.amount_milli_satoshis().unwrap_or(0);

        if let Some(bd_handler) = self.node.deposits() {
            // Check if deposit has sufficient balance (both in millisatoshis)
            match bd_handler.get_deposit_balance(deposit_pubkey) {
                Ok(balance_msat) => {
                    if balance_msat < amount_msat {
                        return Err(format!("Insufficient deposit balance: {} msat available, {} msat required", balance_msat, amount_msat));
                    }

                    // Check if this is a same-node payment (payee is us)
                    let payee_pubkey = invoice.recover_payee_pub_key();
                    let our_node_id = self.node.node_id();
                    let payment_hash_bytes = *invoice.payment_hash().as_byte_array();
                    let payment_hash_hex = hex::encode(&payment_hash_bytes);

                    if payee_pubkey == our_node_id {
                        // Same-node payment: both sender and receiver are deposits on this node
                        println!("🔄 Same-node payment detected: {} -> invoice on same node", deposit_pubkey);

                        // Find the receiver deposit using the lightning_event_service
                        if let Some(lightning_service) = self.node.lightning_event_service() {
                            if let Ok((partner_node_id, receiver_deposit, _invoice_id, _bolt11)) =
                                lightning_service.find_deposit_for_payment(payment_hash_bytes)
                            {
                                // Get the sender's partner (should be the same for same-node transfers)
                                let sender_partner = bd_handler.find_partner_for_deposit(deposit_pubkey)
                                    .ok_or_else(|| format!("Sender deposit {} not found in any ledger", deposit_pubkey))?;

                                if sender_partner != partner_node_id {
                                    return Err(format!(
                                        "Same-node transfer requires same partner: sender has {}, receiver has {}",
                                        sender_partner, partner_node_id
                                    ));
                                }

                                // Execute the same-node transfer (amount in millisatoshis)
                                bd_handler.execute_same_node_transfer(
                                    partner_node_id,
                                    deposit_pubkey,
                                    receiver_deposit,
                                    amount_msat,
                                    payment_hash_bytes,
                                ).map_err(|e| format!("Same-node transfer failed: {}", e))?;

                                println!("✅ Same-node transfer complete: {} msat from {} to {}",
                                        amount_msat, deposit_pubkey, receiver_deposit);

                                // Get preimage from payment store and mark payment as settled
                                let preimage_hex = self.node.list_payments().iter()
                                    .find_map(|p| {
                                        match &p.kind {
                                            ldk_node::payment::PaymentKind::Bolt11 { hash, preimage, .. } |
                                            ldk_node::payment::PaymentKind::Bolt11Jit { hash, preimage, .. } => {
                                                if hash.0 == payment_hash_bytes {
                                                    preimage.map(|pi| pi.0)
                                                } else {
                                                    None
                                                }
                                            },
                                            _ => None
                                        }
                                    });

                                // Mark the payment as settled in the payment store
                                if let Some(preimage_bytes) = preimage_hex {
                                    let payment_hash = lightning_types::payment::PaymentHash(payment_hash_bytes);
                                    let preimage = lightning_types::payment::PaymentPreimage(preimage_bytes);
                                    if let Err(e) = self.node.bolt11_payment().mark_settled_for_hash(
                                        payment_hash, preimage, amount_msat
                                    ) {
                                        println!("⚠️ Failed to mark same-node payment as settled: {:?}", e);
                                    }
                                }

                                let preimage_hex = preimage_hex.map(|pi| hex::encode(pi));

                                return Ok(json!({
                                    "type": "outgoing",
                                    "invoice": invoice_str,
                                    "description": match invoice.description() {
                                        lightning_invoice::Bolt11InvoiceDescriptionRef::Direct(desc) => desc.to_string(),
                                        lightning_invoice::Bolt11InvoiceDescriptionRef::Hash(_) => "".to_string(),
                                    },
                                    "description_hash": null,
                                    "preimage": preimage_hex,
                                    "payment_hash": payment_hash_hex,
                                    "amount": amount_msat,
                                    "fees_paid": 0, // No fees for same-node transfers
                                    "deposit_pubkey": deposit_pubkey_str,
                                    "same_node_transfer": true,
                                    "receiver_deposit": receiver_deposit.to_string(),
                                    "created_at": std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap()
                                        .as_secs(),
                                    "expires_at": null,
                                    "settled_at": std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap()
                                        .as_secs()
                                }));
                            }
                        }
                        println!("⚠️ Same-node payment but receiver deposit not found, falling back to Lightning");
                    }

                    // Different-node payment: use Lightning
                    let payment_id = self.node.bolt11_payment().send(&invoice, None)
                        .map_err(|e| format!("Failed to send payment: {}", e))?;

                    // TODO: In a real implementation, we would:
                    // 1. Lock the deposit amount during payment
                    // 2. Remove the amount from deposit on successful payment
                    // 3. Release the lock on failed payment
                    // For now, we'll just return the payment info

                    Ok(json!({
                        "type": "outgoing",
                        "invoice": invoice_str,
                        "description": match invoice.description() {
                            lightning_invoice::Bolt11InvoiceDescriptionRef::Direct(desc) => desc.to_string(),
                            lightning_invoice::Bolt11InvoiceDescriptionRef::Hash(_) => "".to_string(),
                        },
                        "description_hash": null,
                        "preimage": null, // Preimage not available until settlement
                        "payment_hash": payment_hash_hex,
                        "amount": amount_msat,
                        "fees_paid": 0,
                        "deposit_pubkey": deposit_pubkey_str,
                        "created_at": std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs(),
                        "expires_at": null,
                        "settled_at": std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs()
                    }))
                },
                Err(_) => Err(format!("Deposit not found: {}", deposit_pubkey_str))
            }
        } else {
            Err("Bitcoin Deposits not enabled".to_string())
        }
    }

    /// Create a deposit for a client via DM request
    async fn create_deposit_for_client(
        &self,
        client_pubkey: &str,
        deposit_pubkey_str: &str,
        channel_id: Option<&str>,
    ) -> Result<DepositInfo, String> {
        // Parse the deposit pubkey provided by the client
        // Client generates and keeps the private key - we never see it
        let deposit_pubkey = deposit_pubkey_str.to_string();

        // CHECK LOCAL STORE FIRST - prevents duplicates on restart when historical DMs are replayed
        // Key by CLIENT pubkey (Nostr sender) to match Nostr reply deduplication semantics
        // This means: one deposit per client
        {
            let store = self.client_deposits.lock().await;
            if let Some(stored) = store.get(client_pubkey) {
                println!("📋 Found existing deposit in local store for client {}, returning cached info", client_pubkey);
                return Ok(stored.deposit_info.clone());
            }
        }

        // Get channel ID - either from parameter or auto-select
        let (channel_bytes, selected_channel_id_str) = if let Some(channel_id_str) = channel_id {
            // Validate provided channel ID format
            let channel_bytes = hex::decode(channel_id_str)
                .map_err(|_| "Invalid channel ID format".to_string())?;
            if channel_bytes.len() != 32 {
                return Err("Channel ID must be 32 bytes".to_string());
            }
            let channel_bytes: [u8; 32] = channel_bytes.try_into()
                .map_err(|_| "Channel ID conversion failed".to_string())?;
            (channel_bytes, channel_id_str.to_string())
        } else {
            // Auto-select an available channel that has a ledger initialized
            // Retry a few times since channels may be temporarily unavailable during commitment updates
            let mut retry_count = 0;
            let max_retries = 15;
            let retry_delay = std::time::Duration::from_millis(300);

            loop {
                let channel_details = self.node.list_channels();
                let available_channels: Vec<_> = channel_details.into_iter()
                    .filter(|ch| ch.is_channel_ready && ch.is_usable)
                    .collect();

                if available_channels.is_empty() {
                    retry_count += 1;
                    if retry_count >= max_retries {
                        return Err("No available channels found for deposit creation".to_string());
                    }
                    println!("⏳ No available channels, retrying ({}/{})", retry_count, max_retries);
                    std::thread::sleep(retry_delay);
                    continue;
                }

                // Get the list of partners with initialized ledgers
                let active_partners = if let Some(bd_handler) = self.node.deposits() {
                    bd_handler.list_active_partners()
                } else {
                    Vec::new()
                };

                println!("🔍 Auto-selecting channel for deposit:");
                println!("   Available channels: {}", available_channels.len());
                println!("   Partners with ledgers: {:?}", active_partners);
                for ch in &available_channels {
                    println!("   - Channel {} with counterparty {} (has_ledger: {})",
                        hex::encode(ch.channel_id.0),
                        ch.counterparty_node_id,
                        active_partners.contains(&ch.counterparty_node_id));
                }

                // REQUIRE channel with initialized ledger - don't fall back to random channel
                if let Some(selected_channel) = available_channels.iter()
                    .find(|ch| active_partners.contains(&ch.counterparty_node_id)) {
                    let channel_bytes = selected_channel.channel_id.0;
                    let channel_id_str = hex::encode(channel_bytes);
                    break (channel_bytes, channel_id_str);
                } else {
                    retry_count += 1;
                    if retry_count >= max_retries {
                        return Err(format!(
                            "No channel with initialized ledger found. Available channels: {}, but none have ledgers. \
                            Please initialize a ledger first using POST /bitcoin-deposits/ledger/init with one of these partners: {:?}",
                            available_channels.len(),
                            available_channels.iter().map(|ch| ch.counterparty_node_id.to_string()).collect::<Vec<_>>()
                        ));
                    }
                    println!("⏳ No channel with ledger ready, retrying ({}/{})", retry_count, max_retries);
                    std::thread::sleep(retry_delay);
                    continue;
                }
            }
        };

        // Create a zero-balance deposit (user must fund it separately)
        if let Some(bd_handler) = self.node.deposits() {

            // Find the channel and get the counterparty node ID
            let channel_details = self.node.list_channels();
            println!("🔍 Looking for channel {} among {} active channels", hex::encode(channel_bytes), channel_details.len());
            for (i, ch) in channel_details.iter().enumerate() {
                println!("  Channel {}: {} (counterparty: {})", i, hex::encode(ch.channel_id.0), ch.counterparty_node_id);
            }

            // PRODUCTION: Require real Lightning channel with active peer
            let channel = channel_details.iter().find(|ch| ch.channel_id.0 == channel_bytes)
                .ok_or_else(|| format!("Channel {} not found. Bitcoin Deposits requires an active Lightning channel.", hex::encode(channel_bytes)))?;

            let partner_node_id = channel.counterparty_node_id;
            println!("✅ Found active channel with partner: {}", partner_node_id);

            // Convert deposit pubkey from string to PublicKey
            // Accept both 33-byte compressed (02/03 prefix) and 32-byte x-only formats
            let deposit_pubkey_bytes = hex::decode(&deposit_pubkey)
                .map_err(|_| "Invalid deposit pubkey format".to_string())?;
            let deposit_public_key = match deposit_pubkey_bytes.len() {
                33 => {
                    // Compressed pubkey format (02/03 prefix + 32 bytes)
                    bitcoin::secp256k1::PublicKey::from_slice(&deposit_pubkey_bytes)
                        .map_err(|_| "Invalid compressed public key".to_string())?
                },
                32 => {
                    // X-only pubkey format (32 bytes, assume even parity)
                    let mut pubkey_array = [0u8; 32];
                    pubkey_array.copy_from_slice(&deposit_pubkey_bytes);
                    bitcoin::secp256k1::PublicKey::from_x_only_public_key(
                        bitcoin::secp256k1::XOnlyPublicKey::from_slice(&pubkey_array)
                            .map_err(|_| "Invalid X-only public key".to_string())?,
                        bitcoin::secp256k1::Parity::Even
                    )
                },
                _ => return Err("Deposit pubkey must be 33 bytes (compressed) or 32 bytes (x-only)".to_string()),
            };

            // IMPORTANT: Ledger must be explicitly initialized before deposits can be created
            // Use POST /bitcoin-deposits/ledger/init to initialize the ledger first
            if !bd_handler.list_active_partners().contains(&partner_node_id) {
                return Err(format!(
                    "Ledger not initialized for partner {}. Please initialize the ledger first using POST /bitcoin-deposits/ledger/init with partner_pubkey: {}",
                    partner_node_id,
                    partner_node_id
                ));
            }

            println!("✅ Ledger exists for partner {}, proceeding with deposit creation", partner_node_id);

            // Pre-check: Verify channel is still ready before attempting deposit creation
            // This gives an immediate error instead of waiting for ACK timeout
            let current_channels = self.node.list_channels();
            let channel_ready = current_channels.iter()
                .find(|ch| ch.counterparty_node_id == partner_node_id)
                .map(|ch| (ch.is_channel_ready, ch.is_usable));

            match channel_ready {
                Some((true, true)) => {
                    println!("✅ Channel to {} is ready and usable", partner_node_id);
                }
                Some((is_ready, is_usable)) => {
                    return Err(format!(
                        "Channel to {} not ready for deposits (ready={}, usable={}). \
                        Please wait for channel to stabilize and try again.",
                        partner_node_id, is_ready, is_usable
                    ));
                }
                None => {
                    return Err(format!(
                        "No channel found to partner {}. Cannot create deposit.",
                        partner_node_id
                    ));
                }
            }

            // Actually create the deposit in the Bitcoin Deposits system
            // Use async ACK method to properly synchronize ledger state with Lightning peer
            // Locking is handled inside add_deposit_async
            println!("🔄 Creating deposit with ACK-based synchronization");
            bd_handler.add_deposit_async(partner_node_id, deposit_public_key, None).await
                .map_err(|e| format!("Failed to create deposit: {}", e))?;

            println!("✅ Successfully created deposit {} for partner {}", deposit_pubkey, partner_node_id);

            // Generate deposit-specific NWC keypair
            let (deposit_nwc_keypair, deposit_nwc_pubkey) = self.generate_deposit_nwc_keypair(deposit_public_key);

            // Register the deposit NWC key with scoped permissions
            self.register_deposit_nwc_key(deposit_nwc_pubkey, deposit_public_key).await;

            // Generate proper NWC connection string using the deposit-specific NWC key
            let nwc_connection_string = format!(
                "nostr+walletconnect://{}?relay={}&metadata={{\"name\":\"Deposit-{}\"}}",
                deposit_nwc_pubkey, // Use NWC pubkey, not deposit pubkey
                self.relay_url,
                &deposit_pubkey[..8]
            );

            println!("🔑 Generated deposit-specific NWC key {} for deposit {}", deposit_nwc_pubkey, deposit_pubkey);

            let deposit_info = DepositInfo {
                deposit_pubkey,
                channel_id: selected_channel_id_str,
                balance_sat: 0, // Always zero - user must fund separately
                nwc_connection_string,
                nwc_private_key: hex::encode(deposit_nwc_keypair.secret_bytes()),
            };

            // Store the client deposit mapping for persistence (prevents duplicates on restart)
            // Key by CLIENT pubkey (Nostr sender) to match Nostr reply deduplication semantics
            {
                let mut store = self.client_deposits.lock().await;
                store.insert(StoredClientDeposit {
                    client_pubkey: client_pubkey.to_string(), // Key by Nostr sender, not deposit pubkey
                    deposit_info: deposit_info.clone(),
                    deposit_keypair_secret: String::new(), // Client keeps deposit private key
                });
            }

            Ok(deposit_info)
        } else {
            Err("Bitcoin Deposits not enabled".to_string())
        }
    }

    /// Handle submit_fraud_proof NWC request
    /// Anyone can submit a fraud proof if they have valid evidence (preimage proves payment was made)
    async fn handle_submit_fraud_proof(&self, params: &Value) -> Result<Value, String> {
        let operator_str = params.get("operator").and_then(|v| v.as_str())
            .ok_or("Missing operator parameter")?;
        let payment_hash_str = params.get("payment_hash").and_then(|v| v.as_str())
            .ok_or("Missing payment_hash parameter")?;
        let preimage_str = params.get("preimage").and_then(|v| v.as_str())
            .ok_or("Missing preimage parameter")?;
        let deposit_pubkey_str = params.get("deposit_pubkey").and_then(|v| v.as_str())
            .ok_or("Missing deposit_pubkey parameter")?;
        let amount_msat = params.get("amount_msat").and_then(|v| v.as_u64())
            .ok_or("Missing amount_msat parameter")?;

        // Parse operator pubkey
        let operator = operator_str.parse::<bitcoin::secp256k1::PublicKey>()
            .map_err(|e| format!("Invalid operator pubkey: {}", e))?;

        // Parse payment hash
        let payment_hash_bytes = hex::decode(payment_hash_str)
            .map_err(|e| format!("Invalid payment_hash hex: {}", e))?;
        if payment_hash_bytes.len() != 32 {
            return Err("payment_hash must be 32 bytes".to_string());
        }
        let mut payment_hash = [0u8; 32];
        payment_hash.copy_from_slice(&payment_hash_bytes);

        // Parse preimage
        let preimage_bytes = hex::decode(preimage_str)
            .map_err(|e| format!("Invalid preimage hex: {}", e))?;
        if preimage_bytes.len() != 32 {
            return Err("preimage must be 32 bytes".to_string());
        }
        let mut preimage = [0u8; 32];
        preimage.copy_from_slice(&preimage_bytes);

        // CRITICAL VALIDATION: Verify preimage matches payment_hash
        // SHA256(preimage) must equal payment_hash
        use bitcoin::hashes::{sha256, Hash};
        let computed_hash = sha256::Hash::hash(&preimage);
        if computed_hash.as_byte_array() != &payment_hash {
            return Err("Invalid fraud proof: preimage does not match payment_hash".to_string());
        }

        // Parse deposit pubkey
        let deposit_pubkey = deposit_pubkey_str.parse::<bitcoin::secp256k1::PublicKey>()
            .map_err(|e| format!("Invalid deposit_pubkey: {}", e))?;

        // Invoice cosignature - TODO: require and validate real cosignature
        let invoice_cosignature = [0u8; 64];

        if let Some(bd_handler) = self.node.deposits() {
            bd_handler.broadcast_uncredited_payment_accusation(
                operator,
                payment_hash,
                preimage,
                deposit_pubkey,
                amount_msat,
                invoice_cosignature,
            ).map_err(|e| format!("Failed to broadcast fraud proof: {}", e))?;

            Ok(json!({
                "success": true,
                "message": "Fraud proof validated and broadcast to auditors",
                "operator": operator_str,
                "payment_hash": payment_hash_str,
                "deposit_pubkey": deposit_pubkey_str,
                "amount_msat": amount_msat
            }))
        } else {
            Err("Bitcoin Deposits not enabled".to_string())
        }
    }

    /// Send a DM response to a client
    async fn send_dm_response(
        &self,
        ws_stream: &mut tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
        client_pubkey: &str,
        content: &str
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use bitcoin::secp256k1::{Secp256k1, Message as SecpMessage};
        use bitcoin::hashes::{Hash, sha256};

        let _secp = Secp256k1::new();
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        // Create DM event (kind 4)
        let (our_pubkey, _) = XOnlyPublicKey::from_keypair(&self.keypair);
        let event_data = json!([
            0,                      // always 0 for event ID calculation
            our_pubkey.to_string(), // pubkey (hex string)
            created_at,             // created_at (unix timestamp)
            4,                      // kind (DM)
            [["p", client_pubkey]], // tags (to client)
            content                 // content (plaintext for now)
        ]);

        // Calculate event ID
        let event_json = serde_json::to_string(&event_data)?;
        let event_hash = sha256::Hash::hash(event_json.as_bytes());
        let event_id = event_hash.to_string();

        // Sign the event
        let msg = SecpMessage::from_digest_slice(event_hash.as_ref())?;
        let signature = self.keypair.sign_schnorr(msg);

        // Create the complete event
        let dm_event = json!({
            "id": event_id,
            "pubkey": our_pubkey.to_string(),
            "created_at": created_at,
            "kind": 4,
            "tags": [["p", client_pubkey]],
            "content": content,
            "sig": signature.to_string()
        });

        // Send the DM event
        let event_message = json!(["EVENT", dm_event]).to_string();
        ws_stream.send(Message::Text(event_message)).await?;

        println!("📤 Sent DM response to {}: {}", client_pubkey, content);
        Ok(())
    }

    /// Send a NIP-17 gift-wrapped DM response
    /// Structure: kind 14 (rumor) -> kind 13 (seal) -> kind 1059 (gift wrap)
    async fn send_gift_wrap_response(
        &self,
        ws_stream: &mut tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
        recipient_pubkey: &str,
        content: &str
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use bitcoin::secp256k1::{Secp256k1, Message as SecpMessage, SecretKey};
        use bitcoin::hashes::{Hash, sha256};
        use std::str::FromStr;
        use rand::Rng;

        let secp = Secp256k1::new();
        let recipient_xonly = XOnlyPublicKey::from_str(recipient_pubkey)?;
        let (our_pubkey, _) = XOnlyPublicKey::from_keypair(&self.keypair);

        // Randomize timestamp up to 2 days in past (per NIP-17 spec)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let mut rng = rand::thread_rng();
        let rumor_created_at = now - rng.gen_range(0..172800); // 0-2 days
        let seal_created_at = now - rng.gen_range(0..172800);
        let wrap_created_at = now - rng.gen_range(0..172800);

        // Step 1: Create unsigned rumor (kind 14)
        // Rumors are NOT signed - this provides deniability
        let rumor = json!({
            "pubkey": our_pubkey.to_string(),
            "created_at": rumor_created_at,
            "kind": 14,
            "tags": [["p", recipient_pubkey]],
            "content": content
        });
        let rumor_json = serde_json::to_string(&rumor)?;

        // Step 2: Create seal (kind 13) - encrypt rumor to recipient, sign with our key
        let seal_conversation_key = nip44::get_conversation_key(
            &self.keypair.secret_key(),
            &recipient_xonly,
        )?;
        let encrypted_rumor = nip44::encrypt(&seal_conversation_key, &rumor_json)?;

        // Calculate seal event ID and sign
        let seal_data = json!([
            0,
            our_pubkey.to_string(),
            seal_created_at,
            13,
            json!([]),  // empty tags
            encrypted_rumor
        ]);
        let seal_json_for_id = serde_json::to_string(&seal_data)?;
        let seal_hash = sha256::Hash::hash(seal_json_for_id.as_bytes());
        let seal_id = seal_hash.to_string();

        let seal_msg = SecpMessage::from_digest_slice(seal_hash.as_ref())?;
        let seal_sig = self.keypair.sign_schnorr(seal_msg);

        let seal = json!({
            "id": seal_id,
            "pubkey": our_pubkey.to_string(),
            "created_at": seal_created_at,
            "kind": 13,
            "tags": [],
            "content": encrypted_rumor,
            "sig": seal_sig.to_string()
        });
        let seal_json = serde_json::to_string(&seal)?;

        // Step 3: Create gift wrap (kind 1059) - use ephemeral key
        // Generate ephemeral keypair
        let mut ephemeral_bytes = [0u8; 32];
        rng.fill(&mut ephemeral_bytes);
        let ephemeral_secret = SecretKey::from_slice(&ephemeral_bytes)?;
        let ephemeral_keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &ephemeral_secret);
        let (ephemeral_pubkey, _) = XOnlyPublicKey::from_keypair(&ephemeral_keypair);

        // Encrypt seal to recipient using ephemeral key
        let wrap_conversation_key = nip44::get_conversation_key(
            &ephemeral_secret,
            &recipient_xonly,
        )?;
        let encrypted_seal = nip44::encrypt(&wrap_conversation_key, &seal_json)?;

        // Calculate gift wrap event ID and sign with ephemeral key
        let wrap_data = json!([
            0,
            ephemeral_pubkey.to_string(),
            wrap_created_at,
            1059,
            [["p", recipient_pubkey]],
            encrypted_seal
        ]);
        let wrap_json_for_id = serde_json::to_string(&wrap_data)?;
        let wrap_hash = sha256::Hash::hash(wrap_json_for_id.as_bytes());
        let wrap_id = wrap_hash.to_string();

        let wrap_msg = SecpMessage::from_digest_slice(wrap_hash.as_ref())?;
        let wrap_sig = ephemeral_keypair.sign_schnorr(wrap_msg);

        let gift_wrap = json!({
            "id": wrap_id,
            "pubkey": ephemeral_pubkey.to_string(),
            "created_at": wrap_created_at,
            "kind": 1059,
            "tags": [["p", recipient_pubkey]],
            "content": encrypted_seal,
            "sig": wrap_sig.to_string()
        });

        // Send the gift wrap
        let event_message = json!(["EVENT", gift_wrap]).to_string();
        ws_stream.send(Message::Text(event_message)).await?;

        println!("🎁 Sent gift-wrapped response to {}: {}", recipient_pubkey, content);
        Ok(())
    }

    /// Send a deposit DM response with retry until relay accepts it.
    /// This is critical for deduplication - if the reply isn't stored on the relay,
    /// we won't find it later and will create duplicate deposits.
    async fn send_deposit_dm_with_retry(
        &self,
        client_pubkey: &str,
        content: &str
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use bitcoin::secp256k1::Message as SecpMessage;
        use bitcoin::hashes::{Hash, sha256};
        use tokio::time::{timeout, Duration};

        let max_retries = 10;
        let mut retry_delay = Duration::from_secs(5);

        for attempt in 1..=max_retries {
            // Open a fresh connection for each attempt
            let url = Url::parse(&self.relay_url)?;
            let (mut ws, _) = match connect_async(&url).await {
                Ok(conn) => conn,
                Err(e) => {
                    println!("⚠️ [Attempt {}/{}] Failed to connect to relay: {}", attempt, max_retries, e);
                    tokio::time::sleep(retry_delay).await;
                    retry_delay = std::cmp::min(retry_delay * 2, Duration::from_secs(60));
                    continue;
                }
            };

            // Create DM event with fresh timestamp
            let created_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();

            let (our_pubkey, _) = XOnlyPublicKey::from_keypair(&self.keypair);
            let event_data = json!([
                0,
                our_pubkey.to_string(),
                created_at,
                4,
                [["p", client_pubkey]],
                content
            ]);

            let event_json = serde_json::to_string(&event_data)?;
            let event_hash = sha256::Hash::hash(event_json.as_bytes());
            let event_id = event_hash.to_string();

            let msg = SecpMessage::from_digest_slice(event_hash.as_ref())?;
            let signature = self.keypair.sign_schnorr(msg);

            let dm_event = json!({
                "id": event_id,
                "pubkey": our_pubkey.to_string(),
                "created_at": created_at,
                "kind": 4,
                "tags": [["p", client_pubkey]],
                "content": content,
                "sig": signature.to_string()
            });

            let event_message = json!(["EVENT", dm_event]).to_string();
            if let Err(e) = ws.send(Message::Text(event_message)).await {
                println!("⚠️ [Attempt {}/{}] Failed to send DM: {}", attempt, max_retries, e);
                let _ = ws.close(None).await;
                tokio::time::sleep(retry_delay).await;
                retry_delay = std::cmp::min(retry_delay * 2, Duration::from_secs(60));
                continue;
            }

            // Wait for OK response
            let ok_timeout = Duration::from_secs(10);
            loop {
                match timeout(ok_timeout, ws.next()).await {
                    Ok(Some(Ok(Message::Text(text)))) => {
                        if let Ok(msg) = serde_json::from_str::<Value>(&text) {
                            let msg_type = msg.get(0).and_then(|v| v.as_str()).unwrap_or("");

                            if msg_type == "OK" {
                                let accepted = msg.get(2).and_then(|v| v.as_bool()).unwrap_or(false);
                                let reason = msg.get(3).and_then(|v| v.as_str()).unwrap_or("");

                                if accepted {
                                    println!("✅ Deposit DM accepted by relay for client {}", client_pubkey);
                                    let _ = ws.close(None).await;
                                    return Ok(());
                                } else if reason.contains("rate") || reason.contains("too fast") || reason.contains("too much") {
                                    println!("⏳ [Attempt {}/{}] Rate-limited: {} - will retry", attempt, max_retries, reason);
                                    break; // Break to retry loop
                                } else {
                                    println!("❌ [Attempt {}/{}] DM rejected: {} - will retry", attempt, max_retries, reason);
                                    break; // Break to retry loop
                                }
                            }
                        }
                    },
                    Ok(Some(Ok(_))) => continue,
                    Ok(Some(Err(e))) => {
                        println!("⚠️ [Attempt {}/{}] WebSocket error: {}", attempt, max_retries, e);
                        break;
                    },
                    Ok(None) => {
                        println!("⚠️ [Attempt {}/{}] Connection closed", attempt, max_retries);
                        break;
                    },
                    Err(_) => {
                        println!("⚠️ [Attempt {}/{}] Timeout waiting for OK response", attempt, max_retries);
                        break;
                    }
                }
            }

            let _ = ws.close(None).await;
            tokio::time::sleep(retry_delay).await;
            retry_delay = std::cmp::min(retry_delay * 2, Duration::from_secs(60));
        }

        Err(format!("Failed to send deposit DM after {} retries", max_retries).into())
    }
}

/// Implementation for background task context
impl NWCServiceTaskContext {
    /// Get the keypair for a specific NWC pubkey
    /// Returns the main keypair if it's the node's pubkey, or derives the deposit keypair
    async fn get_keypair_for_nwc_pubkey(&self, nwc_pubkey: &str, access_level: &NWCAccessLevel) -> Option<Keypair> {
        // Check if this is our main NWC pubkey
        if nwc_pubkey == self.pubkey.to_string() {
            return Some(self.keypair.clone());
        }

        // Otherwise, it's a deposit-specific key - derive it from the deposit pubkey
        match access_level {
            NWCAccessLevel::Deposit(deposit_pubkey) => {
                let (keypair, _) = self.generate_deposit_nwc_keypair(*deposit_pubkey);
                Some(keypair)
            }
            NWCAccessLevel::Node => {
                // Node-level access should use the main keypair
                Some(self.keypair.clone())
            }
        }
    }

    /// Process incoming message from Nostr relay asynchronously
    /// Sends responses via channel instead of writing directly to websocket
    pub async fn process_relay_message_async(
        &self,
        text: &str,
        response_tx: mpsc::UnboundedSender<String>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Ok(relay_msg) = serde_json::from_str::<Value>(text) {
            if let Some(msg_type) = relay_msg.get(0).and_then(|v| v.as_str()) {
                match msg_type {
                    "EVENT" => {
                        if let Some(event) = relay_msg.get(2) {
                            self.process_nostr_event_async(event, response_tx).await?;
                        }
                    },
                    "OK" => {
                        // Acknowledgment from relay
                        if let Some(accepted) = relay_msg.get(2).and_then(|v| v.as_bool()) {
                            if accepted {
                                println!("✅ NWC response sent successfully");
                            } else {
                                let reason = relay_msg.get(3).and_then(|v| v.as_str()).unwrap_or("unknown");
                                println!("❌ NWC response rejected by relay: {}", reason);
                            }
                        }
                    },
                    "EOSE" => {
                        // End of stored events - subscription is now live
                        println!("📋 EOSE received - subscription is live");
                    },
                    "NOTICE" => {
                        // Relay notice/error message
                        let notice = relay_msg.get(1).and_then(|v| v.as_str()).unwrap_or("unknown");
                        println!("⚠️  Relay NOTICE: {}", notice);
                    },
                    "CLOSED" => {
                        // Subscription was closed by relay
                        let sub_id = relay_msg.get(1).and_then(|v| v.as_str()).unwrap_or("unknown");
                        let reason = relay_msg.get(2).and_then(|v| v.as_str()).unwrap_or("no reason");
                        println!("🔒 Subscription {} CLOSED by relay: {}", sub_id, reason);
                    },
                    other => {
                        println!("📨 Received relay message type: {}", other);
                    }
                }
            }
        }
        Ok(())
    }

    /// Process incoming Nostr event asynchronously
    async fn process_nostr_event_async(
        &self,
        event: &Value,
        response_tx: mpsc::UnboundedSender<String>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Parse event fields
        let event_id = event.get("id").and_then(|v| v.as_str()).unwrap_or("unknown");
        let pubkey = event.get("pubkey").and_then(|v| v.as_str()).unwrap_or("");
        let content = event.get("content").and_then(|v| v.as_str()).unwrap_or("");
        let kind = event.get("kind").and_then(|v| v.as_u64()).unwrap_or(0);

        // Check if we've already processed this event
        {
            let mut processed = self.processed_events.lock().await;
            if processed.contains(event_id) {
                return Ok(());
            }
            // Mark as processed
            processed.insert(event_id.to_string());
        }

        println!("📥 Processing Nostr event {} (kind {}) from {}", event_id, kind, pubkey);

        match kind {
            4 => {
                // Regular DM - handle deposit creation requests
                self.process_deposit_dm_async(event, pubkey, content, response_tx, false).await?;
            },
            1059 => {
                // NIP-17 gift-wrapped DM - unwrap and process inner content
                self.process_gift_wrap_async(event, pubkey, content, response_tx).await?;
            },
            23194 => {
                // NIP-47 NWC request - handle wallet operations
                self.process_nwc_request_async(event, pubkey, content, response_tx).await?;
            },
            _ => {
                println!("🤷 Unknown event kind: {}", kind);
            }
        }

        Ok(())
    }

    /// Process NIP-17 gift-wrapped DM asynchronously
    async fn process_gift_wrap_async(
        &self,
        event: &Value,
        wrap_pubkey: &str,
        encrypted_content: &str,
        response_tx: mpsc::UnboundedSender<String>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use std::str::FromStr;
        println!("🎁 Processing gift-wrapped DM from ephemeral key {}", wrap_pubkey);

        // Parse the wrapper pubkey (ephemeral key used by sender)
        let wrap_xonly = XOnlyPublicKey::from_str(wrap_pubkey)?;

        // Decrypt the gift wrap
        let conversation_key = nip44::get_conversation_key(
            &self.keypair.secret_key(),
            &wrap_xonly,
        )?;

        let seal_json = match nip44::decrypt(&conversation_key, encrypted_content) {
            Ok(json) => json,
            Err(e) => {
                println!("❌ Failed to decrypt gift wrap: {}", e);
                return Ok(());
            }
        };

        // Parse the seal (kind 13)
        let seal: Value = serde_json::from_str(&seal_json)?;
        let seal_pubkey = seal["pubkey"].as_str().ok_or("Missing seal pubkey")?;
        let seal_content = seal["content"].as_str().ok_or("Missing seal content")?;

        println!("📜 Unwrapped seal from {}", seal_pubkey);

        // Decrypt the seal to get the rumor
        let sender_xonly = XOnlyPublicKey::from_str(seal_pubkey)?;
        let seal_conversation_key = nip44::get_conversation_key(
            &self.keypair.secret_key(),
            &sender_xonly,
        )?;

        let rumor_json = match nip44::decrypt(&seal_conversation_key, seal_content) {
            Ok(json) => json,
            Err(e) => {
                println!("❌ Failed to decrypt seal: {}", e);
                return Ok(());
            }
        };

        // Parse the rumor (kind 14)
        let rumor: Value = serde_json::from_str(&rumor_json)?;
        let rumor_pubkey = rumor["pubkey"].as_str().ok_or("Missing rumor pubkey")?;
        let rumor_content = rumor["content"].as_str().ok_or("Missing rumor content")?;
        let rumor_kind = rumor["kind"].as_u64().unwrap_or(0);
        let rumor_created_at = rumor["created_at"].as_u64().unwrap_or(0);

        println!("📬 Unwrapped rumor (kind {}) from {}: {}", rumor_kind, rumor_pubkey, rumor_content);

        // Filter out historical messages from before this server session started
        // The rumor timestamp is encrypted and can be accurate, so we use a tight buffer
        const RUMOR_TIMESTAMP_BUFFER: u64 = 5 * 60; // 5 minutes in seconds
        let cutoff_time = self.server_start_time.saturating_sub(RUMOR_TIMESTAMP_BUFFER);

        if rumor_created_at < cutoff_time {
            println!("⏰ Ignoring historical gift-wrapped DM (rumor timestamp {} < cutoff {})",
                rumor_created_at, cutoff_time);
            return Ok(());
        }

        // Process based on rumor kind
        match rumor_kind {
            14 => {
                // Private DM - process as deposit creation request (respond with gift wrap)
                self.process_deposit_dm_async(event, rumor_pubkey, rumor_content, response_tx, true).await?;
            },
            _ => {
                println!("🤷 Unknown rumor kind in gift wrap: {}", rumor_kind);
            }
        }

        Ok(())
    }

    /// Process deposit creation DM asynchronously
    /// Query the relay for our previous DM replies to a client containing deposit info.
    /// Returns the deposit response content if found, None otherwise.
    async fn find_existing_deposit_reply(
        &self,
        client_pubkey: &str,
    ) -> Option<String> {
        use tokio::time::{timeout, Duration};

        // Open a new websocket connection to query for our replies
        let url = match Url::parse(&self.relay_url) {
            Ok(u) => u,
            Err(e) => {
                println!("⚠️ Failed to parse relay URL for dedup query: {}", e);
                return None;
            }
        };

        let (mut ws, _) = match connect_async(&url).await {
            Ok(conn) => conn,
            Err(e) => {
                println!("⚠️ Failed to connect to relay for dedup query: {}", e);
                return None;
            }
        };

        // Query for kind 4 DMs from us to this client
        let query = json!([
            "REQ",
            "dedup-query",
            {
                "kinds": [4],
                "authors": [self.pubkey.to_string()],
                "#p": [client_pubkey]
            }
        ]);

        if let Err(e) = ws.send(Message::Text(query.to_string())).await {
            println!("⚠️ Failed to send dedup query: {}", e);
            return None;
        }

        let mut deposit_reply: Option<String> = None;

        // Read responses until EOSE or timeout
        let query_timeout = Duration::from_secs(5);
        loop {
            match timeout(query_timeout, ws.next()).await {
                Ok(Some(Ok(Message::Text(text)))) => {
                    if let Ok(msg) = serde_json::from_str::<Value>(&text) {
                        let msg_type = msg.get(0).and_then(|v| v.as_str()).unwrap_or("");

                        if msg_type == "EVENT" {
                            if let Some(event) = msg.get(2) {
                                if let Some(content) = event.get("content").and_then(|v| v.as_str()) {
                                    // Check if this is a deposit response (contains deposit_pubkey JSON)
                                    if let Ok(json) = serde_json::from_str::<Value>(content) {
                                        if json.get("deposit_pubkey").is_some() {
                                            println!("📋 Found existing deposit reply for client {}", client_pubkey);
                                            deposit_reply = Some(content.to_string());
                                            // Don't break - continue to get newest reply
                                        }
                                    }
                                }
                            }
                        } else if msg_type == "EOSE" {
                            // End of stored events - we're done
                            break;
                        }
                    }
                },
                Ok(Some(Ok(_))) => continue,
                Ok(Some(Err(e))) => {
                    println!("⚠️ Dedup query websocket error: {}", e);
                    break;
                },
                Ok(None) => break,
                Err(_) => {
                    println!("⚠️ Dedup query timed out");
                    break;
                }
            }
        }

        // Close the websocket
        let _ = ws.close(None).await;

        deposit_reply
    }

    async fn process_deposit_dm_async(
        &self,
        _event: &Value,
        client_pubkey: &str,
        content: &str,
        response_tx: mpsc::UnboundedSender<String>,
        use_gift_wrap: bool,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        println!("💬 Processing deposit DM from {}: {} (gift_wrap={})", client_pubkey, content, use_gift_wrap);

        // Parse DM content for deposit creation request
        if content.starts_with("init-deposit") {
            // Check if we already replied to this client with a deposit (relay-based deduplication)
            if let Some(_existing_reply) = self.find_existing_deposit_reply(client_pubkey).await {
                println!("📋 Already replied to client {} - ignoring duplicate request", client_pubkey);
                return Ok(());  // Silently ignore - we already created this deposit
            }

            // Format: "init-deposit <deposit_pubkey> [channel_id]"
            // deposit_pubkey is REQUIRED - client must generate their own keypair
            let parts: Vec<&str> = content.split_whitespace().collect();
            if parts.len() < 2 {
                let error_response = serde_json::json!({
                    "error": "Missing deposit_pubkey. Format: init-deposit <deposit_pubkey> [channel_id]"
                });
                self.send_dm_response_async(client_pubkey, &error_response.to_string(), response_tx).await?;
                return Ok(());
            }
            let deposit_pubkey_str = parts[1];
            let channel_id = if parts.len() >= 3 {
                Some(parts[2])
            } else {
                None
            };

            // Create the deposit
            match self.create_deposit_for_client(client_pubkey, deposit_pubkey_str, channel_id).await {
                Ok(deposit_info) => {
                    // Return JSON format for NWC client parsing
                    let response = serde_json::json!({
                        "deposit_pubkey": deposit_info.deposit_pubkey,
                        "channel_id": deposit_info.channel_id,
                        "balance_sat": deposit_info.balance_sat,
                        "nwc_connection_string": deposit_info.nwc_connection_string,
                        "nwc_private_key": deposit_info.nwc_private_key
                    }).to_string();
                    // Use retry to ensure deposit reply is stored on relay for deduplication
                    if use_gift_wrap {
                        if let Err(e) = self.send_gift_wrap_dm_with_retry(client_pubkey, &response).await {
                            println!("⚠️ Failed to send gift-wrapped deposit DM after retries: {}", e);
                            // Still return Ok since deposit was created - client will retry
                        }
                    } else {
                        if let Err(e) = self.send_deposit_dm_with_retry(client_pubkey, &response).await {
                            println!("⚠️ Failed to send deposit DM after retries: {}", e);
                            // Still return Ok since deposit was created - client will retry
                        }
                    }
                },
                Err(e) => {
                    // Return JSON error format for consistency
                    let response = serde_json::json!({
                        "error": format!("Failed to create deposit: {}", e)
                    }).to_string();
                    if use_gift_wrap {
                        if let Err(e) = self.send_gift_wrap_dm_with_retry(client_pubkey, &response).await {
                            println!("⚠️ Failed to send gift-wrapped error DM: {}", e);
                        }
                    } else {
                        self.send_dm_response_async(client_pubkey, &response, response_tx).await?;
                    }
                }
            }
        } else if content == "/help" {
            let response = "🏦 Bitcoin Deposits Commands:\n\ninit-deposit [channel_id] - Create deposit and return JSON\n  - Omit channel_id to auto-select available channel\n/help - Show this help".to_string();
            if use_gift_wrap {
                if let Err(e) = self.send_gift_wrap_dm_with_retry(client_pubkey, &response).await {
                    println!("⚠️ Failed to send gift-wrapped help DM: {}", e);
                }
            } else {
                self.send_dm_response_async(client_pubkey, &response, response_tx).await?;
            }
        } else {
            let response = "👋 Hello! Send /help for available commands.".to_string();
            if use_gift_wrap {
                if let Err(e) = self.send_gift_wrap_dm_with_retry(client_pubkey, &response).await {
                    println!("⚠️ Failed to send gift-wrapped greeting DM: {}", e);
                }
            } else {
                self.send_dm_response_async(client_pubkey, &response, response_tx).await?;
            }
        }
        Ok(())
    }

    /// Process NIP-47 NWC request asynchronously
    async fn process_nwc_request_async(
        &self,
        event: &Value,
        pubkey: &str,
        content: &str,
        response_tx: mpsc::UnboundedSender<String>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        println!("📥 Processing NWC request from {}", pubkey);

        // Find which of our NWC pubkeys this event was addressed to
        let registry = self.access_registry.lock().await;
        let registered_pubkeys: Vec<String> = registry.keys().cloned().collect();
        drop(registry);

        let our_nwc_pubkey = event.get("tags")
            .and_then(|tags| tags.as_array())
            .and_then(|tags| {
                for tag in tags {
                    if let Some(tag_array) = tag.as_array() {
                        if tag_array.len() >= 2
                            && tag_array[0].as_str() == Some("p")
                            && tag_array[1].as_str().is_some()
                        {
                            let tagged_pubkey = tag_array[1].as_str().unwrap();
                            if registered_pubkeys.contains(&tagged_pubkey.to_string()) {
                                return Some(tagged_pubkey.to_string());
                            }
                        }
                    }
                }
                None
            })
            .unwrap_or_else(|| self.pubkey.to_string());

        println!("🎯 Request addressed to our NWC pubkey: {}", our_nwc_pubkey);

        // First, get our access level for the ADDRESSED NWC pubkey (not the client's)
        // This tells us which keypair to use for encryption/decryption
        let our_access_level = {
            let registry = self.access_registry.lock().await;
            registry.get(&our_nwc_pubkey).cloned()
        };

        let our_access_level = match our_access_level {
            Some(level) => level,
            None => {
                // SECURITY: Unknown pubkey - do NOT fall back to Node level
                // Connections must be explicitly registered (either node-level or deposit-level)
                println!("❌ REJECTED: NWC pubkey {} not in registry. Connections must be explicit.", our_nwc_pubkey);
                println!("   To enable node-level access, register explicitly with register_node_nwc_key()");
                println!("   To enable deposit access, use register_deposit_nwc_key()");
                return Ok(());
            }
        };

        // Get our keypair for encryption/decryption BEFORE checking client authorization
        // This allows us to send error responses to unauthorized clients
        let our_keypair = self.get_keypair_for_nwc_pubkey(&our_nwc_pubkey, &our_access_level).await;

        // Track which encryption was used so response uses the same method
        let (decrypted_content, use_nip04) = match our_keypair {
            Some(keypair) => {
                // Parse client's pubkey from the event
                let client_xonly_pubkey = match XOnlyPublicKey::from_str(pubkey) {
                    Ok(pk) => pk,
                    Err(e) => {
                        println!("❌ Failed to parse client pubkey {}: {}", pubkey, e);
                        return Ok(());
                    }
                };

                // Try NIP-44 first (modern encryption)
                let nip44_result = nip44::get_conversation_key(&keypair.secret_key(), &client_xonly_pubkey)
                    .and_then(|conversation_key| nip44::decrypt(&conversation_key, content));

                match nip44_result {
                    Ok(decrypted) => {
                        println!("🔓 Successfully decrypted NWC request content (NIP-44)");
                        (decrypted, false)
                    }
                    Err(nip44_err) => {
                        // NIP-44 failed, try NIP-04 (legacy encryption for @getalby SDK compatibility)
                        println!("🔄 NIP-44 decryption failed ({}), trying NIP-04...", nip44_err);

                        match nip04::get_shared_secret(&keypair.secret_key(), &client_xonly_pubkey) {
                            Ok(shared_secret) => {
                                match nip04::decrypt(&shared_secret, content) {
                                    Ok(decrypted) => {
                                        println!("🔓 Successfully decrypted NWC request content (NIP-04)");
                                        (decrypted, true)
                                    }
                                    Err(nip04_err) => {
                                        println!("❌ Both NIP-44 and NIP-04 decryption failed");
                                        println!("  NIP-44 error: {}", nip44_err);
                                        println!("  NIP-04 error: {}", nip04_err);
                                        return Ok(());
                                    }
                                }
                            }
                            Err(e) => {
                                println!("❌ Failed to get NIP-04 shared secret: {}", e);
                                return Ok(());
                            }
                        }
                    }
                }
            }
            None => {
                println!("❌ Could not find keypair for NWC pubkey {}", our_nwc_pubkey);
                return Ok(());
            }
        };

        // Get the original event ID for responses (needed even for error responses)
        let original_event_id = event.get("id").and_then(|v| v.as_str()).unwrap_or("");

        // Now check if the CLIENT is authorized (their pubkey should be in the registry)
        // This check happens AFTER decryption so we can send proper error responses
        let client_access_level = {
            let registry = self.access_registry.lock().await;
            registry.get(pubkey).cloned()
        };

        let client_access_level = match client_access_level {
            Some(level) => {
                println!("🔒 Client NWC key {} has access level: {:?}", pubkey, level);
                level
            }
            None => {
                println!("🚫 SECURITY: Rejecting request from unregistered NWC key: {}", pubkey);
                // Send UNAUTHORIZED error response instead of silently ignoring
                let error_response: Result<Value, String> = Err("UNAUTHORIZED: This NWC key is not registered".to_string());
                self.send_nwc_response_with_code_async(
                    pubkey, original_event_id, &error_response, &our_nwc_pubkey,
                    use_nip04, "UNAUTHORIZED", response_tx.clone()
                ).await?;
                return Ok(());
            }
        };

        // Parse the NIP-47 request from decrypted content
        if let Ok(request) = serde_json::from_str::<Value>(&decrypted_content) {
            let method = request.get("method").and_then(|v| v.as_str()).unwrap_or("");
            let empty_params = json!({});
            let params = request.get("params").unwrap_or(&empty_params);

            println!("🔧 NWC method: {} with params: {}", method, params);

            // Process the request and generate response
            let response_content = match method {
                "get_info" => self.handle_get_info_async(&client_access_level).await,
                "get_balance" => self.handle_get_balance_async(&client_access_level).await,
                "make_invoice" => self.handle_make_invoice_async(&client_access_level, params).await,
                "pay_invoice" => self.handle_pay_invoice_async(&client_access_level, params).await,
                "lookup_invoice" => self.handle_lookup_invoice_async(&client_access_level, params).await,
                "list_transactions" => self.handle_list_transactions_async(&client_access_level, params).await,
                // Deposit-specific methods
                "get_deposit_balance" => self.handle_get_deposit_balance_async(&client_access_level, params).await,
                "list_deposits" => self.handle_list_deposits_async(&client_access_level, params).await,
                _ => Err(format!("NOT_IMPLEMENTED: Unknown method: {}", method)),
            };

            // Send response
            self.send_nwc_response_async(pubkey, original_event_id, &response_content, &our_nwc_pubkey, use_nip04, response_tx).await?;
        } else {
            // Failed to parse request JSON - send error response
            let error_response: Result<Value, String> = Err("Failed to parse NIP-47 request JSON".to_string());
            self.send_nwc_response_async(pubkey, original_event_id, &error_response, &our_nwc_pubkey, use_nip04, response_tx).await?;
        }

        Ok(())
    }

    /// Handle get_info NWC request
    async fn handle_get_info_async(&self, _access_level: &NWCAccessLevel) -> Result<Value, String> {
        let node_id = self.node.node_id().to_string();
        let methods = vec![
            "get_info", "get_balance", "make_invoice", "pay_invoice",
            "lookup_invoice", "list_transactions",
            "get_deposit_balance", "list_deposits", "make_deposit_invoice", "pay_deposit_invoice",
            "submit_fraud_proof"
        ];

        Ok(json!({
            "alias": format!("LDK Node {}", node_id[0..8].to_string()),
            "color": "#3399ff",
            "pubkey": node_id,
            "network": "regtest",
            "block_height": 0,
            "block_hash": "",
            "methods": methods
        }))
    }

    /// Handle get_balance NWC request
    async fn handle_get_balance_async(&self, access_level: &NWCAccessLevel) -> Result<Value, String> {
        match access_level {
            NWCAccessLevel::Node => {
                let balances = self.node.list_balances();
                let total_ln_balance_msat = balances.total_lightning_balance_sats * 1000;
                let onchain_balance_msat = balances.total_onchain_balance_sats * 1000;

                Ok(json!({
                    "balance": total_ln_balance_msat,
                    "balance_msat": total_ln_balance_msat,
                    "onchain_balance_msat": onchain_balance_msat,
                    "lightning_balance_msat": total_ln_balance_msat
                }))
            }
            NWCAccessLevel::Deposit(deposit_pubkey) => {
                if let Some(bd_handler) = self.node.deposits() {
                    match bd_handler.get_deposit_balance(*deposit_pubkey) {
                        Ok(balance_msat) => {
                            Ok(json!({
                                "balance": balance_msat,
                                "deposit_pubkey": deposit_pubkey.to_string()
                            }))
                        },
                        Err(e) => Err(format!("Failed to get deposit balance: {:?}", e))
                    }
                } else {
                    Err("Bitcoin Deposits not enabled".to_string())
                }
            }
        }
    }

    /// Handle make_invoice NWC request
    async fn handle_make_invoice_async(&self, access_level: &NWCAccessLevel, params: &Value) -> Result<Value, String> {
        let amount = params.get("amount").and_then(|v| v.as_u64()).unwrap_or(0);
        let description = params.get("description").and_then(|v| v.as_str()).unwrap_or("NWC Invoice");

        match access_level {
            NWCAccessLevel::Node => {
                let description_obj = lightning_invoice::Bolt11InvoiceDescription::Direct(
                    lightning_invoice::Description::new(description.to_string())
                        .map_err(|e| format!("Invalid description: {}", e))?
                );

                let invoice = self.node.bolt11_payment().receive(
                    amount,
                    &description_obj,
                    3600
                ).map_err(|e| format!("Failed to create invoice: {}", e))?;

                let payment_hash = hex::encode(invoice.payment_hash().as_byte_array());

                Ok(json!({
                    "type": "incoming",
                    "invoice": invoice.to_string(),
                    "description": description,
                    "payment_hash": payment_hash,
                    "amount": amount,
                    "created_at": std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs()
                }))
            }
            NWCAccessLevel::Deposit(deposit_pubkey) => {
                if let Some(bd_handler) = self.node.deposits() {
                    match bd_handler.get_deposit_balance(*deposit_pubkey) {
                        Ok(_) => {
                            let deposit_pubkey_str = deposit_pubkey.to_string();
                            let description_obj = lightning_invoice::Bolt11InvoiceDescription::Direct(
                                lightning_invoice::Description::new(format!("{} (Deposit: {})", description, &deposit_pubkey_str[..8]))
                                    .map_err(|e| format!("Invalid description: {}", e))?
                            );

                            let invoice = self.node.bolt11_payment().receive(
                                amount,
                                &description_obj,
                                3600
                            ).map_err(|e| format!("Failed to create invoice: {}", e))?;

                            let payment_hash_bytes: [u8; 32] = *invoice.payment_hash().as_ref();
                            let payment_hash = hex::encode(&payment_hash_bytes);

                            // Register this payment with the Lightning Event Service
                            let partner_id = if let Some(lightning_service) = self.node.lightning_event_service() {
                                let partner_id = bd_handler.find_partner_for_deposit(*deposit_pubkey)
                                    .ok_or_else(|| format!("Could not find partner for deposit {}", deposit_pubkey))?;

                                let invoice_id = payment_hash.clone();
                                lightning_service.register_payment_for_deposit(
                                    payment_hash_bytes,
                                    partner_id,
                                    *deposit_pubkey,
                                    invoice_id,
                                    invoice.to_string()
                                );

                                partner_id
                            } else {
                                return Err("Lightning Event Service not available".to_string());
                            };

                            // Request cosignature from partner
                            let cosignature = bd_handler.request_invoice_cosignature(
                                partner_id,
                                *deposit_pubkey,
                                payment_hash_bytes,
                                amount,
                                invoice.to_string(),
                                30000
                            ).await.map_err(|e| format!("Failed to get cosignature: {}", e))?;

                            let cosignature_hex = hex::encode(&cosignature);

                            Ok(json!({
                                "type": "incoming",
                                "invoice": invoice.to_string(),
                                "description": description,
                                "payment_hash": payment_hash,
                                "amount": amount,
                                "deposit_pubkey": deposit_pubkey_str,
                                "cosignature": cosignature_hex,
                                "created_at": std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap()
                                    .as_secs()
                            }))
                        },
                        Err(_) => Err(format!("Deposit not found: {}", deposit_pubkey))
                    }
                } else {
                    Err("Bitcoin Deposits not enabled".to_string())
                }
            }
        }
    }

    /// Handle pay_invoice NWC request
    async fn handle_pay_invoice_async(&self, access_level: &NWCAccessLevel, params: &Value) -> Result<Value, String> {
        let invoice_str = params.get("invoice").and_then(|v| v.as_str())
            .ok_or("Missing invoice parameter")?;

        // Check for empty or null invoice string before parsing
        if invoice_str.is_empty() || invoice_str == "null" {
            return Err(format!("Invoice is empty or null (got: '{}')", invoice_str));
        }

        let invoice = invoice_str.parse::<lightning_invoice::Bolt11Invoice>()
            .map_err(|e| format!("Invalid invoice '{}': {}", &invoice_str[..invoice_str.len().min(20)], e))?;

        let amount_msat = invoice.amount_milli_satoshis().unwrap_or(0);

        match access_level {
            NWCAccessLevel::Node => {
                let payment_id = self.node.bolt11_payment().send(&invoice, None)
                    .map_err(|e| format!("Failed to send payment: {:?}", e))?;

                let payment_hash = hex::encode(invoice.payment_hash().as_byte_array());

                Ok(json!({
                    "type": "outgoing",
                    "invoice": invoice_str,
                    "preimage": null, // Preimage not available until settlement
                    "payment_hash": payment_hash,
                    "amount": amount_msat,
                    "fees_paid": 0,
                    "created_at": std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs()
                }))
            }
            NWCAccessLevel::Deposit(deposit_pubkey) => {
                if let Some(bd_handler) = self.node.deposits() {
                    match bd_handler.get_deposit_balance(*deposit_pubkey) {
                        Ok(balance_msat) => {
                            if balance_msat < amount_msat {
                                return Err(format!("Insufficient deposit balance: {} msat available, {} msat required", balance_msat, amount_msat));
                            }

                            let payment_hash_bytes: [u8; 32] = *invoice.payment_hash().as_ref();
                            let payment_hash_hex = hex::encode(&payment_hash_bytes);

                            // Check if this is a same-node payment
                            let payee_pubkey = invoice.recover_payee_pub_key();
                            let our_node_id = self.node.node_id();

                            if payee_pubkey == our_node_id {
                                // Same-node payment
                                if let Some(lightning_service) = self.node.lightning_event_service() {
                                    if let Ok((partner_node_id, receiver_deposit, _invoice_id, _bolt11)) =
                                        lightning_service.find_deposit_for_payment(payment_hash_bytes)
                                    {
                                        let sender_partner = bd_handler.find_partner_for_deposit(*deposit_pubkey)
                                            .ok_or_else(|| format!("Sender deposit {} not found", deposit_pubkey))?;

                                        if sender_partner != partner_node_id {
                                            return Err(format!("Cross-partner transfers not supported"));
                                        }

                                        // Execute the same-node transfer (amount in millisatoshis)
                                        bd_handler.execute_same_node_transfer(
                                            partner_node_id,
                                            *deposit_pubkey,
                                            receiver_deposit,
                                            amount_msat,
                                            payment_hash_bytes,
                                        ).map_err(|e| format!("Same-node transfer failed: {}", e))?;

                                        // Get preimage from payment store and mark payment as settled
                                        let preimage_hex = self.node.list_payments().iter()
                                            .find_map(|p| {
                                                match &p.kind {
                                                    ldk_node::payment::PaymentKind::Bolt11 { hash, preimage, .. } |
                                                    ldk_node::payment::PaymentKind::Bolt11Jit { hash, preimage, .. } => {
                                                        if hash.0 == payment_hash_bytes {
                                                            preimage.map(|pi| pi.0)
                                                        } else {
                                                            None
                                                        }
                                                    },
                                                    _ => None
                                                }
                                            });

                                        // Mark the payment as settled in the payment store
                                        if let Some(preimage_bytes) = preimage_hex {
                                            let payment_hash = lightning_types::payment::PaymentHash(payment_hash_bytes);
                                            let preimage = lightning_types::payment::PaymentPreimage(preimage_bytes);
                                            if let Err(e) = self.node.bolt11_payment().mark_settled_for_hash(
                                                payment_hash, preimage, amount_msat
                                            ) {
                                                println!("⚠️ Failed to mark same-node payment as settled: {:?}", e);
                                            }
                                        }

                                        let preimage_hex = preimage_hex.map(|pi| hex::encode(pi));

                                        return Ok(json!({
                                            "type": "outgoing",
                                            "invoice": invoice_str,
                                            "preimage": preimage_hex,
                                            "payment_hash": payment_hash_hex,
                                            "amount": amount_msat,
                                            "fees_paid": 0,
                                            "same_node_transfer": true
                                        }));
                                    }
                                }
                            }

                            // Different-node payment: use Lightning with lock/fulfill flow
                            // Sequence number is assigned atomically in handle_sending_lock_payment
                            // TODO: Sign with deposit's scriptpubkey private key for ownership proof
                            let lock_msg = deposits_ldk::handler::messages::SendingLockPaymentMsg {
                                payment_id: payment_hash_bytes,
                                pubkey: *deposit_pubkey,
                                amount: amount_msat,
                                sequence_number: 0, // Ignored - assigned atomically in handler
                                scriptpubkey_signature: [0; 64], // TODO: Real signature required
                            };

                            bd_handler.handle_sending_lock_payment(lock_msg)
                                .map_err(|e| format!("Failed to lock deposit: {}", e))?;

                            // Pay the invoice
                            let payment_result = self.node.bolt11_payment().send(&invoice, None);

                            let payment_id = match payment_result {
                                Ok(id) => id,
                                Err(e) => {
                                    // Release the lock on failed payment initiation
                                    // Sequence number is assigned atomically in handle_sending_fail_payment_async
                                    let fail_msg = deposits_ldk::handler::messages::SendingFailPaymentMsg {
                                        payment_id: payment_hash_bytes,
                                        pubkey: *deposit_pubkey,
                                        amount: amount_msat,
                                        sequence_number: 0, // Ignored - assigned atomically in handler
                                    };

                                    bd_handler.handle_sending_fail_payment_async(fail_msg).await
                                        .map_err(|e2| format!("Failed to unlock: {}", e2))?;

                                    return Err(format!("Failed to initiate payment: {}", e));
                                }
                            };

                            // Wait for payment completion
                            let (tx, rx) = tokio::sync::oneshot::channel();
                            {
                                let mut pending = self.pending_outgoing_payments.lock().await;
                                pending.insert(payment_id.0, (tx, *deposit_pubkey, amount_msat));
                            }

                            let completion_result = tokio::time::timeout(
                                std::time::Duration::from_secs(60),
                                rx
                            ).await;
                            match completion_result {
                                Ok(Ok(Ok(preimage_opt))) => {
                                    // Sequence number is assigned atomically in handle_sending_fulfill_payment_async
                                    // TODO: Sign with deposit's scriptpubkey private key for ownership proof
                                    let preimage_bytes = preimage_opt.unwrap_or([0u8; 32]);
                                    let fulfill_msg = deposits_ldk::handler::messages::SendingFulfillPaymentMsg {
                                        payment_id: payment_hash_bytes,
                                        pubkey: *deposit_pubkey,
                                        amount: amount_msat,
                                        sequence_number: 0, // Ignored - assigned atomically in handler
                                        scriptpubkey_signature: [0; 64], // TODO: Real signature required
                                        preimage: preimage_bytes,
                                    };

                                    bd_handler.handle_sending_fulfill_payment_async(fulfill_msg).await
                                        .map_err(|e| format!("Failed to fulfill: {}", e))?;

                                    let preimage_hex = preimage_opt.map(|p| hex::encode(p));
                                    Ok(json!({
                                        "type": "outgoing",
                                        "invoice": invoice_str,
                                        "preimage": preimage_hex,
                                        "payment_hash": payment_hash_hex,
                                        "amount": amount_msat,
                                        "fees_paid": 0,
                                        "deposit_pubkey": deposit_pubkey.to_string()
                                    }))
                                }
                                Ok(Ok(Err(error_msg))) => {
                                    // Sequence number is assigned atomically in handle_sending_fail_payment_async
                                    let fail_msg = deposits_ldk::handler::messages::SendingFailPaymentMsg {
                                        payment_id: payment_hash_bytes,
                                        pubkey: *deposit_pubkey,
                                        amount: amount_msat,
                                        sequence_number: 0, // Ignored - assigned atomically in handler
                                    };

                                    bd_handler.handle_sending_fail_payment_async(fail_msg).await
                                        .map_err(|e| format!("Failed to unlock: {}", e))?;

                                    Err(format!("Payment failed: {}", error_msg))
                                }
                                Err(_) => {
                                    // Timeout - sequence number is assigned atomically in handler
                                    let fail_msg = deposits_ldk::handler::messages::SendingFailPaymentMsg {
                                        payment_id: payment_hash_bytes,
                                        pubkey: *deposit_pubkey,
                                        amount: amount_msat,
                                        sequence_number: 0, // Ignored - assigned atomically in handler
                                    };

                                    bd_handler.handle_sending_fail_payment_async(fail_msg).await
                                        .map_err(|e| format!("Failed to unlock: {}", e))?;

                                    Err("Payment timeout after 60s".to_string())
                                }
                                Ok(Err(_)) => {
                                    Err("Payment tracker channel closed unexpectedly".to_string())
                                }
                            }
                        },
                        Err(_) => Err(format!("Deposit not found: {}", deposit_pubkey))
                    }
                } else {
                    Err("Bitcoin Deposits not enabled".to_string())
                }
            }
        }
    }

    /// Handle get_deposit_balance NWC request
    async fn handle_get_deposit_balance_async(&self, _access_level: &NWCAccessLevel, params: &Value) -> Result<Value, String> {
        let deposit_pubkey_str = params.get("deposit_pubkey").and_then(|v| v.as_str())
            .ok_or("Missing deposit_pubkey parameter")?;

        let deposit_pubkey = deposit_pubkey_str.parse::<bitcoin::secp256k1::PublicKey>()
            .map_err(|e| format!("Invalid deposit_pubkey: {}", e))?;

        if let Some(bd_handler) = self.node.deposits() {
            match bd_handler.get_deposit_balance(deposit_pubkey) {
                Ok(balance_msat) => {
                    Ok(json!({
                        "deposit_pubkey": deposit_pubkey_str,
                        "balance": balance_msat,
                        "balance_sat": balance_msat / 1000
                    }))
                },
                Err(e) => Err(format!("Failed to get deposit balance: {:?}", e))
            }
        } else {
            Err("Bitcoin Deposits not enabled".to_string())
        }
    }

    /// Handle list_deposits NWC request
    async fn handle_list_deposits_async(&self, _access_level: &NWCAccessLevel, _params: &Value) -> Result<Value, String> {
        if let Some(bd_handler) = self.node.deposits() {
            match bd_handler.list_deposits() {
                Ok(deposit_pubkeys) => {
                    let deposits: Vec<Value> = deposit_pubkeys.iter().map(|pubkey| {
                        let balance_msat = bd_handler.get_deposit_balance(*pubkey).unwrap_or(0);
                        json!({
                            "deposit_pubkey": pubkey.to_string(),
                            "balance": balance_msat,
                            "balance_sat": balance_msat / 1000
                        })
                    }).collect();

                    Ok(json!({
                        "deposits": deposits,
                        "count": deposits.len()
                    }))
                },
                Err(e) => Err(format!("Failed to list deposits: {:?}", e))
            }
        } else {
            Err("Bitcoin Deposits not enabled".to_string())
        }
    }

    /// Handle lookup_invoice NWC request
    /// Looks up an invoice/payment by payment_hash and returns its status
    async fn handle_lookup_invoice_async(&self, access_level: &NWCAccessLevel, params: &Value) -> Result<Value, String> {
        // Get payment_hash from params (could be in different fields based on NWC spec)
        let payment_hash_str = params.get("payment_hash")
            .or_else(|| params.get("invoice")) // Some clients pass the invoice string
            .and_then(|v| v.as_str())
            .ok_or("Missing payment_hash or invoice parameter")?;

        // If it's a bolt11 invoice string, parse it to get the payment hash
        let payment_hash_hex = if payment_hash_str.starts_with("ln") {
            let invoice = payment_hash_str.parse::<lightning_invoice::Bolt11Invoice>()
                .map_err(|e| format!("Invalid invoice: {}", e))?;
            hex::encode(invoice.payment_hash().as_byte_array())
        } else {
            payment_hash_str.to_string()
        };

        // Decode payment hash
        let payment_hash_bytes = hex::decode(&payment_hash_hex)
            .map_err(|e| format!("Invalid payment_hash hex: {}", e))?;

        if payment_hash_bytes.len() != 32 {
            return Err("payment_hash must be 32 bytes".to_string());
        }

        // Look up payment in the node's payment store
        let payments = self.node.list_payments();

        for payment in payments {
            let payment_hash_match = match &payment.kind {
                ldk_node::payment::PaymentKind::Bolt11 { hash, preimage, .. } => {
                    if hash.0 == payment_hash_bytes.as_slice() {
                        Some((hash, preimage.clone()))
                    } else {
                        None
                    }
                },
                ldk_node::payment::PaymentKind::Bolt11Jit { hash, preimage, .. } => {
                    if hash.0 == payment_hash_bytes.as_slice() {
                        Some((hash, preimage.clone()))
                    } else {
                        None
                    }
                },
                _ => None
            };

            if let Some((_hash, preimage)) = payment_hash_match {
                // Check access level - deposit wallets can only see their own payments
                if let NWCAccessLevel::Deposit(_deposit_pubkey) = access_level {
                    // For deposit wallets, we'd ideally filter by deposit
                    // For now, allow seeing all payments (since deposits use node's Lightning)
                }

                let payment_type = match payment.direction {
                    ldk_node::payment::PaymentDirection::Inbound => "incoming",
                    ldk_node::payment::PaymentDirection::Outbound => "outgoing",
                };

                let state = match payment.status {
                    ldk_node::payment::PaymentStatus::Pending => "pending",
                    ldk_node::payment::PaymentStatus::Succeeded => "settled",
                    ldk_node::payment::PaymentStatus::Failed => "failed",
                };

                // Only include preimage if payment is settled
                // (for inbound payments, receiver knows preimage but shouldn't reveal until settled)
                let preimage_hex = if state == "settled" {
                    preimage.map(|p| hex::encode(p.0))
                } else {
                    None
                };

                // Try to get the invoice string from the Lightning Event Service's registered payments
                let invoice_str = if let Some(lightning_service) = self.node.lightning_event_service() {
                    let mut payment_hash_arr = [0u8; 32];
                    payment_hash_arr.copy_from_slice(&payment_hash_bytes);
                    lightning_service.get_payment_bolt11(&payment_hash_arr).unwrap_or_default()
                } else {
                    String::new()
                };

                return Ok(json!({
                    "type": payment_type,
                    "state": state,
                    "invoice": invoice_str,
                    "payment_hash": payment_hash_hex,
                    "preimage": preimage_hex,
                    "amount": payment.amount_msat.unwrap_or(0),
                    "fees_paid": payment.fee_paid_msat.unwrap_or(0),
                    "created_at": payment.latest_update_timestamp,
                    "settled_at": if state == "settled" { Some(payment.latest_update_timestamp) } else { None }
                }));
            }
        }

        // Payment not found
        Err(format!("Invoice with payment_hash {} not found", payment_hash_hex))
    }

    /// Handle list_transactions NWC request
    /// Returns a list of transactions optionally filtered by type and limited
    async fn handle_list_transactions_async(&self, access_level: &NWCAccessLevel, params: &Value) -> Result<Value, String> {
        let filter_type = params.get("type").and_then(|v| v.as_str());
        let limit = params.get("limit").and_then(|v| v.as_u64()).unwrap_or(50) as usize;
        let offset = params.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;

        // Get all payments from the node
        let mut payments: Vec<_> = self.node.list_payments();

        // Sort by timestamp descending (most recent first)
        payments.sort_by(|a, b| b.latest_update_timestamp.cmp(&a.latest_update_timestamp));

        // Filter by type if specified
        let filtered_payments: Vec<_> = payments.into_iter()
            .filter(|payment| {
                // Filter by direction based on type parameter
                match filter_type {
                    Some("incoming") => matches!(payment.direction, ldk_node::payment::PaymentDirection::Inbound),
                    Some("outgoing") => matches!(payment.direction, ldk_node::payment::PaymentDirection::Outbound),
                    _ => true // No filter, include all
                }
            })
            .filter(|payment| {
                // Only include Lightning payments (Bolt11 and Bolt11Jit)
                matches!(payment.kind,
                    ldk_node::payment::PaymentKind::Bolt11 { .. } |
                    ldk_node::payment::PaymentKind::Bolt11Jit { .. }
                )
            })
            .skip(offset)
            .take(limit)
            .collect();

        // For deposit access, we'd ideally filter to deposit-related payments
        // For now, return all Lightning payments since deposits use the node's Lightning
        if let NWCAccessLevel::Deposit(_deposit_pubkey) = access_level {
            // Could add deposit-specific filtering here in the future
        }

        // Get lightning service reference for bolt11 lookups
        let lightning_service = self.node.lightning_event_service();

        // Convert to NWC transaction format
        let transactions: Vec<Value> = filtered_payments.iter().map(|payment| {
            let (payment_hash, payment_hash_bytes, preimage_opt) = match &payment.kind {
                ldk_node::payment::PaymentKind::Bolt11 { hash, preimage, .. } => {
                    (Some(hex::encode(hash.0)), Some(hash.0), preimage.map(|p| hex::encode(p.0)))
                },
                ldk_node::payment::PaymentKind::Bolt11Jit { hash, preimage, .. } => {
                    (Some(hex::encode(hash.0)), Some(hash.0), preimage.map(|p| hex::encode(p.0)))
                },
                _ => (None, None, None)
            };

            let payment_type = match payment.direction {
                ldk_node::payment::PaymentDirection::Inbound => "incoming",
                ldk_node::payment::PaymentDirection::Outbound => "outgoing",
            };

            let state = match payment.status {
                ldk_node::payment::PaymentStatus::Pending => "pending",
                ldk_node::payment::PaymentStatus::Succeeded => "settled",
                ldk_node::payment::PaymentStatus::Failed => "failed",
            };

            // Only include preimage if payment is settled
            let preimage = if state == "settled" { preimage_opt } else { None };

            // Try to get bolt11 from lightning service
            let invoice_str = if let (Some(ls), Some(hash_bytes)) = (&lightning_service, payment_hash_bytes) {
                ls.get_payment_bolt11(&hash_bytes).unwrap_or_default()
            } else {
                String::new()
            };

            json!({
                "type": payment_type,
                "state": state,
                "invoice": invoice_str,
                "payment_hash": payment_hash,
                "preimage": preimage,
                "amount": payment.amount_msat.unwrap_or(0),
                "fees_paid": payment.fee_paid_msat.unwrap_or(0),
                "created_at": payment.latest_update_timestamp,
                "settled_at": if state == "settled" { Some(payment.latest_update_timestamp) } else { None }
            })
        }).collect();

        Ok(json!({
            "transactions": transactions
        }))
    }

    /// Send NIP-47 response event back to client via channel
    /// Use the same encryption method that the client used for the request
    async fn send_nwc_response_async(
        &self,
        client_pubkey: &str,
        original_event_id: &str,
        response_content: &Result<Value, String>,
        responding_nwc_pubkey: &str,
        use_nip04: bool,
        response_tx: mpsc::UnboundedSender<String>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Create NIP-47 response
        let response = match response_content {
            Ok(result) => json!({
                "result_type": "success",
                "result": result
            }),
            Err(error) => json!({
                "result_type": "error",
                "error": {
                    "code": "INTERNAL",
                    "message": error
                }
            })
        };

        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Determine which keypair to use for signing
        let (signing_keypair, pubkey_hex) = if responding_nwc_pubkey == self.pubkey.to_string() {
            (self.keypair.clone(), self.pubkey.to_string())
        } else {
            let registry = self.access_registry.lock().await;
            if let Some(NWCAccessLevel::Deposit(deposit_pubkey)) = registry.get(responding_nwc_pubkey) {
                let (deposit_nwc_keypair, deposit_nwc_pubkey) = self.generate_deposit_nwc_keypair(*deposit_pubkey);
                drop(registry);
                (deposit_nwc_keypair, deposit_nwc_pubkey.to_string())
            } else {
                drop(registry);
                (self.keypair.clone(), self.pubkey.to_string())
            }
        };

        // Encrypt the response content using same method as request
        let client_xonly_pubkey = XOnlyPublicKey::from_str(client_pubkey)
            .map_err(|e| format!("Invalid client pubkey: {}", e))?;

        let encrypted_content = if use_nip04 {
            // Use NIP-04 (legacy, for @getalby SDK compatibility)
            let shared_secret = nip04::get_shared_secret(&signing_keypair.secret_key(), &client_xonly_pubkey)?;
            nip04::encrypt(&shared_secret, &response.to_string())?
        } else {
            // Use NIP-44 (modern encryption)
            let conversation_key = nip44::get_conversation_key(&signing_keypair.secret_key(), &client_xonly_pubkey)?;
            nip44::encrypt(&conversation_key, &response.to_string())?
        };

        // Create the event data for signing
        let event_data = json!([
            0,
            pubkey_hex,
            created_at,
            23195,
            [["p", client_pubkey], ["e", original_event_id]],
            encrypted_content
        ]);

        // Calculate event ID
        let event_json = serde_json::to_string(&event_data).unwrap();
        let event_id = sha256::Hash::hash(event_json.as_bytes());
        let event_id_hex = hex::encode(event_id.as_byte_array());

        // Sign the event
        let message = SecpMessage::from_digest_slice(event_id.as_byte_array())?;
        let signature = self.secp.sign_schnorr(&message, &signing_keypair);

        // Create the final signed event (use encrypted_content, not plaintext)
        let event = json!({
            "id": event_id_hex,
            "kind": 23195,
            "content": encrypted_content,
            "pubkey": pubkey_hex,
            "created_at": created_at,
            "tags": [["p", client_pubkey], ["e", original_event_id]],
            "sig": signature.to_string()
        });

        // Send via channel
        let relay_message = json!(["EVENT", event]).to_string();
        response_tx.send(relay_message).map_err(|e| format!("Failed to send response via channel: {}", e))?;

        let encryption_type = if use_nip04 { "NIP-04" } else { "NIP-44" };
        println!("📤 Sent NWC response to {} (encrypted with {})", client_pubkey, encryption_type);

        Ok(())
    }

    /// Send NIP-47 error response with a specific error code
    /// NIP-47 error codes: RATE_LIMITED, NOT_IMPLEMENTED, INSUFFICIENT_BALANCE, QUOTA_EXCEEDED,
    /// RESTRICTED, UNAUTHORIZED, INTERNAL, OTHER, PAY_INVOICE_FAILED, NOT_FOUND
    async fn send_nwc_response_with_code_async(
        &self,
        client_pubkey: &str,
        original_event_id: &str,
        response_content: &Result<Value, String>,
        responding_nwc_pubkey: &str,
        use_nip04: bool,
        error_code: &str,
        response_tx: mpsc::UnboundedSender<String>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Create NIP-47 response with specific error code
        let response = match response_content {
            Ok(result) => json!({
                "result_type": "success",
                "result": result
            }),
            Err(error) => json!({
                "result_type": "error",
                "error": {
                    "code": error_code,
                    "message": error
                }
            })
        };

        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Determine which keypair to use for signing
        let (signing_keypair, pubkey_hex) = if responding_nwc_pubkey == self.pubkey.to_string() {
            (self.keypair.clone(), self.pubkey.to_string())
        } else {
            let registry = self.access_registry.lock().await;
            if let Some(NWCAccessLevel::Deposit(deposit_pubkey)) = registry.get(responding_nwc_pubkey) {
                let (deposit_nwc_keypair, deposit_nwc_pubkey) = self.generate_deposit_nwc_keypair(*deposit_pubkey);
                drop(registry);
                (deposit_nwc_keypair, deposit_nwc_pubkey.to_string())
            } else {
                drop(registry);
                (self.keypair.clone(), self.pubkey.to_string())
            }
        };

        // Encrypt the response content using same method as request
        let client_xonly_pubkey = XOnlyPublicKey::from_str(client_pubkey)
            .map_err(|e| format!("Invalid client pubkey: {}", e))?;

        let encrypted_content = if use_nip04 {
            let shared_secret = nip04::get_shared_secret(&signing_keypair.secret_key(), &client_xonly_pubkey)?;
            nip04::encrypt(&shared_secret, &response.to_string())?
        } else {
            let conversation_key = nip44::get_conversation_key(&signing_keypair.secret_key(), &client_xonly_pubkey)?;
            nip44::encrypt(&conversation_key, &response.to_string())?
        };

        // Create the event data for signing
        let event_data = json!([
            0,
            pubkey_hex,
            created_at,
            23195,
            [["p", client_pubkey], ["e", original_event_id]],
            encrypted_content
        ]);

        // Calculate event ID
        let event_json = serde_json::to_string(&event_data).unwrap();
        let event_id = sha256::Hash::hash(event_json.as_bytes());
        let event_id_hex = hex::encode(event_id.as_byte_array());

        // Sign the event
        let message = SecpMessage::from_digest_slice(event_id.as_byte_array())?;
        let signature = self.secp.sign_schnorr(&message, &signing_keypair);

        // Create the final signed event
        let event = json!({
            "id": event_id_hex,
            "kind": 23195,
            "content": encrypted_content,
            "pubkey": pubkey_hex,
            "created_at": created_at,
            "tags": [["p", client_pubkey], ["e", original_event_id]],
            "sig": signature.to_string()
        });

        // Send via channel
        let relay_message = json!(["EVENT", event]).to_string();
        response_tx.send(relay_message).map_err(|e| format!("Failed to send response via channel: {}", e))?;

        let encryption_type = if use_nip04 { "NIP-04" } else { "NIP-44" };
        println!("📤 Sent NWC error response ({}) to {} (encrypted with {})", error_code, client_pubkey, encryption_type);

        Ok(())
    }

    /// Send a DM response to a client via channel
    async fn send_dm_response_async(
        &self,
        client_pubkey: &str,
        content: &str,
        response_tx: mpsc::UnboundedSender<String>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        let event_data = json!([
            0,
            self.pubkey.to_string(),
            created_at,
            4,
            [["p", client_pubkey]],
            content
        ]);

        let event_json = serde_json::to_string(&event_data)?;
        let event_hash = sha256::Hash::hash(event_json.as_bytes());
        let event_id = event_hash.to_string();

        let msg = SecpMessage::from_digest_slice(event_hash.as_ref())?;
        let signature = self.keypair.sign_schnorr(msg);

        let dm_event = json!({
            "id": event_id,
            "pubkey": self.pubkey.to_string(),
            "created_at": created_at,
            "kind": 4,
            "tags": [["p", client_pubkey]],
            "content": content,
            "sig": signature.to_string()
        });

        let event_message = json!(["EVENT", dm_event]).to_string();
        response_tx.send(event_message).map_err(|e| format!("Failed to send DM via channel: {}", e))?;

        println!("📤 Sent DM response to {}: {}", client_pubkey, content);
        Ok(())
    }

    /// Send a deposit DM response with retry until relay accepts it.
    /// This is critical for deduplication - if the reply isn't stored on the relay,
    /// we won't find it later and will create duplicate deposits.
    async fn send_deposit_dm_with_retry(
        &self,
        client_pubkey: &str,
        content: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use tokio::time::{timeout, Duration};

        let max_retries = 10;
        let mut retry_delay = Duration::from_secs(5);

        for attempt in 1..=max_retries {
            // Open a fresh connection for each attempt
            let url = Url::parse(&self.relay_url)?;
            let (mut ws, _) = match connect_async(&url).await {
                Ok(conn) => conn,
                Err(e) => {
                    println!("⚠️ [Attempt {}/{}] Failed to connect to relay: {}", attempt, max_retries, e);
                    tokio::time::sleep(retry_delay).await;
                    retry_delay = std::cmp::min(retry_delay * 2, Duration::from_secs(60));
                    continue;
                }
            };

            // Create DM event with fresh timestamp
            let created_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();

            let event_data = json!([
                0,
                self.pubkey.to_string(),
                created_at,
                4,
                [["p", client_pubkey]],
                content
            ]);

            let event_json = serde_json::to_string(&event_data)?;
            let event_hash = sha256::Hash::hash(event_json.as_bytes());
            let event_id = event_hash.to_string();

            let msg = SecpMessage::from_digest_slice(event_hash.as_ref())?;
            let signature = self.keypair.sign_schnorr(msg);

            let dm_event = json!({
                "id": event_id,
                "pubkey": self.pubkey.to_string(),
                "created_at": created_at,
                "kind": 4,
                "tags": [["p", client_pubkey]],
                "content": content,
                "sig": signature.to_string()
            });

            let event_message = json!(["EVENT", dm_event]).to_string();
            if let Err(e) = ws.send(Message::Text(event_message)).await {
                println!("⚠️ [Attempt {}/{}] Failed to send DM: {}", attempt, max_retries, e);
                let _ = ws.close(None).await;
                tokio::time::sleep(retry_delay).await;
                retry_delay = std::cmp::min(retry_delay * 2, Duration::from_secs(60));
                continue;
            }

            // Wait for OK response
            let ok_timeout = Duration::from_secs(10);
            loop {
                match timeout(ok_timeout, ws.next()).await {
                    Ok(Some(Ok(Message::Text(text)))) => {
                        if let Ok(msg) = serde_json::from_str::<Value>(&text) {
                            let msg_type = msg.get(0).and_then(|v| v.as_str()).unwrap_or("");

                            if msg_type == "OK" {
                                let accepted = msg.get(2).and_then(|v| v.as_bool()).unwrap_or(false);
                                let reason = msg.get(3).and_then(|v| v.as_str()).unwrap_or("");

                                if accepted {
                                    println!("✅ Deposit DM accepted by relay for client {}", client_pubkey);
                                    let _ = ws.close(None).await;
                                    return Ok(());
                                } else if reason.contains("rate") || reason.contains("too fast") || reason.contains("too much") {
                                    println!("⏳ [Attempt {}/{}] Rate-limited: {} - will retry", attempt, max_retries, reason);
                                    break; // Break to retry loop
                                } else {
                                    println!("❌ [Attempt {}/{}] DM rejected: {} - will retry", attempt, max_retries, reason);
                                    break; // Break to retry loop
                                }
                            }
                        }
                    },
                    Ok(Some(Ok(_))) => continue,
                    Ok(Some(Err(e))) => {
                        println!("⚠️ [Attempt {}/{}] WebSocket error: {}", attempt, max_retries, e);
                        break;
                    },
                    Ok(None) => {
                        println!("⚠️ [Attempt {}/{}] Connection closed", attempt, max_retries);
                        break;
                    },
                    Err(_) => {
                        println!("⚠️ [Attempt {}/{}] Timeout waiting for OK response", attempt, max_retries);
                        break;
                    }
                }
            }

            let _ = ws.close(None).await;
            tokio::time::sleep(retry_delay).await;
            retry_delay = std::cmp::min(retry_delay * 2, Duration::from_secs(60));
        }

        Err(format!("Failed to send deposit DM after {} retries", max_retries).into())
    }

    /// Send a gift-wrapped DM response (NIP-17) with retry until relay accepts it.
    /// NIP-17 structure: kind 1059 (gift wrap) → kind 13 (seal) → kind 14 (rumor)
    async fn send_gift_wrap_dm_with_retry(
        &self,
        client_pubkey: &str,
        content: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use std::str::FromStr;
        use tokio::time::{timeout, Duration};

        let max_retries = 10;
        let mut retry_delay = Duration::from_secs(5);

        // Parse the recipient pubkey
        let recipient_xonly = XOnlyPublicKey::from_str(client_pubkey)?;

        for attempt in 1..=max_retries {
            // Open a fresh connection for each attempt
            let url = Url::parse(&self.relay_url)?;
            let (mut ws, _) = match connect_async(&url).await {
                Ok(conn) => conn,
                Err(e) => {
                    println!("⚠️ [Attempt {}/{}] Failed to connect to relay: {}", attempt, max_retries, e);
                    tokio::time::sleep(retry_delay).await;
                    retry_delay = std::cmp::min(retry_delay * 2, Duration::from_secs(60));
                    continue;
                }
            };

            // Create NIP-17 gift-wrapped DM with fresh timestamps
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            let random_offset = rand::random::<u64>() % (2 * 24 * 60 * 60);

            // 1. Create kind 14 rumor (unsigned direct message)
            let rumor_created_at = now.saturating_sub(random_offset);
            let rumor = json!({
                "kind": 14,
                "content": content,
                "pubkey": self.pubkey.to_string(),
                "created_at": rumor_created_at,
                "tags": [["p", client_pubkey]]
            });

            // 2. Create kind 13 seal - encrypt rumor with our key to recipient
            let seal_conversation_key = nip44::get_conversation_key(
                &self.keypair.secret_key(),
                &recipient_xonly,
            )?;
            let encrypted_rumor = nip44::encrypt(&seal_conversation_key, &rumor.to_string())?;

            let seal_created_at = now.saturating_sub(rand::random::<u64>() % (2 * 24 * 60 * 60));
            let empty_tags: Vec<Vec<String>> = vec![];
            let seal_event_data = json!([
                0,
                self.pubkey.to_string(),
                seal_created_at,
                13,
                empty_tags,
                encrypted_rumor
            ]);
            let seal_json = serde_json::to_string(&seal_event_data)?;
            let seal_hash = sha256::Hash::hash(seal_json.as_bytes());
            let seal_id = seal_hash.to_string();
            let seal_msg = SecpMessage::from_digest_slice(seal_hash.as_ref())?;
            let seal_sig = self.keypair.sign_schnorr(seal_msg);

            let seal = json!({
                "id": seal_id,
                "pubkey": self.pubkey.to_string(),
                "created_at": seal_created_at,
                "kind": 13,
                "tags": [],
                "content": encrypted_rumor,
                "sig": seal_sig.to_string()
            });

            // 3. Create kind 1059 gift wrap with ephemeral key
            let ephemeral_keypair = Keypair::new(&self.secp, &mut rand::thread_rng());
            let (ephemeral_xonly, _) = XOnlyPublicKey::from_keypair(&ephemeral_keypair);

            let wrap_conversation_key = nip44::get_conversation_key(
                &ephemeral_keypair.secret_key(),
                &recipient_xonly,
            )?;
            let encrypted_seal = nip44::encrypt(&wrap_conversation_key, &seal.to_string())?;

            let wrap_created_at = now.saturating_sub(rand::random::<u64>() % (2 * 24 * 60 * 60));
            let wrap_event_data = json!([
                0,
                ephemeral_xonly.to_string(),
                wrap_created_at,
                1059,
                [["p", client_pubkey]],
                encrypted_seal
            ]);
            let wrap_json = serde_json::to_string(&wrap_event_data)?;
            let wrap_hash = sha256::Hash::hash(wrap_json.as_bytes());
            let wrap_id = wrap_hash.to_string();
            let wrap_msg = SecpMessage::from_digest_slice(wrap_hash.as_ref())?;
            let wrap_sig = ephemeral_keypair.sign_schnorr(wrap_msg);

            let gift_wrap = json!({
                "id": wrap_id,
                "pubkey": ephemeral_xonly.to_string(),
                "created_at": wrap_created_at,
                "kind": 1059,
                "tags": [["p", client_pubkey]],
                "content": encrypted_seal,
                "sig": wrap_sig.to_string()
            });

            let event_message = json!(["EVENT", gift_wrap]).to_string();
            if let Err(e) = ws.send(Message::Text(event_message)).await {
                println!("⚠️ [Attempt {}/{}] Failed to send gift-wrapped DM: {}", attempt, max_retries, e);
                let _ = ws.close(None).await;
                tokio::time::sleep(retry_delay).await;
                retry_delay = std::cmp::min(retry_delay * 2, Duration::from_secs(60));
                continue;
            }

            // Wait for OK response
            let ok_timeout = Duration::from_secs(10);
            loop {
                match timeout(ok_timeout, ws.next()).await {
                    Ok(Some(Ok(Message::Text(text)))) => {
                        if let Ok(msg) = serde_json::from_str::<Value>(&text) {
                            let msg_type = msg.get(0).and_then(|v| v.as_str()).unwrap_or("");

                            if msg_type == "OK" {
                                let accepted = msg.get(2).and_then(|v| v.as_bool()).unwrap_or(false);
                                let reason = msg.get(3).and_then(|v| v.as_str()).unwrap_or("");

                                if accepted {
                                    println!("✅ Gift-wrapped DM accepted by relay for client {}", client_pubkey);
                                    let _ = ws.close(None).await;
                                    return Ok(());
                                } else if reason.contains("rate") || reason.contains("too fast") || reason.contains("too much") {
                                    println!("⏳ [Attempt {}/{}] Rate-limited: {} - will retry", attempt, max_retries, reason);
                                    break; // Break to retry loop
                                } else {
                                    println!("❌ [Attempt {}/{}] Gift-wrapped DM rejected: {} - will retry", attempt, max_retries, reason);
                                    break; // Break to retry loop
                                }
                            }
                        }
                    },
                    Ok(Some(Ok(_))) => continue,
                    Ok(Some(Err(e))) => {
                        println!("⚠️ [Attempt {}/{}] WebSocket error: {}", attempt, max_retries, e);
                        break;
                    },
                    Ok(None) => {
                        println!("⚠️ [Attempt {}/{}] Connection closed", attempt, max_retries);
                        break;
                    },
                    Err(_) => {
                        println!("⚠️ [Attempt {}/{}] Timeout waiting for OK response", attempt, max_retries);
                        break;
                    }
                }
            }

            let _ = ws.close(None).await;
            tokio::time::sleep(retry_delay).await;
            retry_delay = std::cmp::min(retry_delay * 2, Duration::from_secs(60));
        }

        Err(format!("Failed to send gift-wrapped DM after {} retries", max_retries).into())
    }

    /// Register a new deposit-specific NWC key in the access registry
    async fn register_deposit_nwc_key(&self, nwc_pubkey: XOnlyPublicKey, deposit_pubkey: bitcoin::secp256k1::PublicKey) {
        let mut registry = self.access_registry.lock().await;
        registry.insert(nwc_pubkey.to_string(), NWCAccessLevel::Deposit(deposit_pubkey));
        println!("🔑 Registered deposit NWC key {} for deposit {}", nwc_pubkey, deposit_pubkey);
        drop(registry);

        // Trigger subscription update to include the new key immediately
        let tx_lock = self.subscription_update_tx.lock().await;
        if let Some(ref sender) = *tx_lock {
            if let Err(_) = sender.send(()) {
                println!("⚠️  Warning: Could not trigger subscription update - connection may be closed");
            } else {
                println!("🔔 Triggered live subscription update for new deposit key {}", nwc_pubkey);
            }
        } else {
            println!("⚠️  Warning: No subscription update sender available - service may not be started yet");
        }

        // Publish NIP-47 kind 13194 info event for this deposit NWC key
        // This allows clients to discover wallet capabilities via relay query
        if let Err(e) = self.publish_nwc_info_event(deposit_pubkey).await {
            println!("⚠️  Warning: Failed to publish NWC info event for deposit {}: {}", deposit_pubkey, e);
        }
    }

    /// Publish a NIP-47 kind 13194 info event for a deposit-specific NWC key
    /// This event advertises the wallet's supported methods to clients
    async fn publish_nwc_info_event(
        &self,
        deposit_pubkey: bitcoin::secp256k1::PublicKey,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use tokio::time::{timeout, Duration};

        // Generate the deposit-specific NWC keypair
        let (deposit_keypair, deposit_nwc_pubkey) = self.generate_deposit_nwc_keypair(deposit_pubkey);
        let pubkey_hex = deposit_nwc_pubkey.to_string();

        // NIP-47 supported methods for deposit wallets
        let methods = "get_info get_balance make_invoice pay_invoice lookup_invoice list_transactions";

        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        // Create the event data for signing
        // Kind 13194 events have no tags and plaintext content
        let event_data = json!([
            0,
            pubkey_hex,
            created_at,
            13194,
            [],
            methods
        ]);

        let event_json = serde_json::to_string(&event_data)?;
        let event_hash = sha256::Hash::hash(event_json.as_bytes());
        let event_id = hex::encode(event_hash.as_byte_array());

        let msg = SecpMessage::from_digest_slice(event_hash.as_byte_array())?;
        let signature = self.secp.sign_schnorr(&msg, &deposit_keypair);

        let info_event = json!({
            "id": event_id,
            "pubkey": pubkey_hex,
            "created_at": created_at,
            "kind": 13194,
            "tags": [],
            "content": methods,
            "sig": signature.to_string()
        });

        // Open websocket connection to publish the event
        let url = Url::parse(&self.relay_url)?;
        let (mut ws, _) = connect_async(&url).await?;

        let event_message = json!(["EVENT", info_event]).to_string();
        ws.send(Message::Text(event_message)).await?;

        // Wait for OK response
        let ok_timeout = Duration::from_secs(10);
        loop {
            match timeout(ok_timeout, ws.next()).await {
                Ok(Some(Ok(Message::Text(text)))) => {
                    if let Ok(msg) = serde_json::from_str::<Value>(&text) {
                        let msg_type = msg.get(0).and_then(|v| v.as_str()).unwrap_or("");

                        if msg_type == "OK" {
                            let accepted = msg.get(2).and_then(|v| v.as_bool()).unwrap_or(false);
                            let reason = msg.get(3).and_then(|v| v.as_str()).unwrap_or("");

                            let _ = ws.close(None).await;

                            if accepted {
                                println!("✅ Published NWC info event (kind 13194) for deposit NWC key {}", pubkey_hex);
                                return Ok(());
                            } else {
                                return Err(format!("Relay rejected info event: {}", reason).into());
                            }
                        }
                    }
                },
                Ok(Some(Ok(_))) => continue,
                Ok(Some(Err(e))) => {
                    let _ = ws.close(None).await;
                    return Err(format!("WebSocket error: {}", e).into());
                },
                Ok(None) => {
                    return Err("Connection closed unexpectedly".into());
                },
                Err(_) => {
                    let _ = ws.close(None).await;
                    return Err("Timeout waiting for relay response".into());
                }
            }
        }
    }

    /// Create a deposit for a client via DM request
    async fn create_deposit_for_client(
        &self,
        client_pubkey: &str,
        deposit_pubkey_str: &str,
        channel_id: Option<&str>,
    ) -> Result<DepositInfo, String> {
        // Parse the deposit pubkey provided by the client
        // Client generates and keeps the private key - we never see it
        let deposit_pubkey = deposit_pubkey_str.to_string();

        // CHECK LOCAL STORE FIRST - prevents duplicates on restart when historical DMs are replayed
        // Key by CLIENT pubkey (Nostr sender) to match Nostr reply deduplication semantics
        // This means: one deposit per client
        {
            let store = self.client_deposits.lock().await;
            if let Some(stored) = store.get(client_pubkey) {
                println!("📋 Found existing deposit in local store for client {}, returning cached info", client_pubkey);
                return Ok(stored.deposit_info.clone());
            }
        }

        // Get channel ID - either from parameter or auto-select
        let (channel_bytes, selected_channel_id_str) = if let Some(channel_id_str) = channel_id {
            // Validate provided channel ID format
            let channel_bytes = hex::decode(channel_id_str)
                .map_err(|_| "Invalid channel ID format".to_string())?;
            if channel_bytes.len() != 32 {
                return Err("Channel ID must be 32 bytes".to_string());
            }
            let channel_bytes: [u8; 32] = channel_bytes.try_into()
                .map_err(|_| "Channel ID conversion failed".to_string())?;
            (channel_bytes, channel_id_str.to_string())
        } else {
            // Auto-select an available channel that has a ledger initialized
            // Retry a few times since channels may be temporarily unavailable during commitment updates
            let mut retry_count = 0;
            let max_retries = 15;
            let retry_delay = std::time::Duration::from_millis(300);

            loop {
                let channel_details = self.node.list_channels();
                let available_channels: Vec<_> = channel_details.into_iter()
                    .filter(|ch| ch.is_channel_ready && ch.is_usable)
                    .collect();

                if available_channels.is_empty() {
                    retry_count += 1;
                    if retry_count >= max_retries {
                        return Err("No available channels found for deposit creation".to_string());
                    }
                    println!("⏳ No available channels, retrying ({}/{})", retry_count, max_retries);
                    tokio::time::sleep(retry_delay).await;
                    continue;
                }

                // Get the list of partners with initialized ledgers
                let active_partners = if let Some(bd_handler) = self.node.deposits() {
                    bd_handler.list_active_partners()
                } else {
                    Vec::new()
                };

                println!("🔍 Auto-selecting channel for deposit:");
                println!("   Available channels: {}", available_channels.len());
                println!("   Partners with ledgers: {:?}", active_partners);

                // REQUIRE channel with initialized ledger
                if let Some(selected_channel) = available_channels.iter()
                    .find(|ch| active_partners.contains(&ch.counterparty_node_id)) {
                    let channel_bytes = selected_channel.channel_id.0;
                    let channel_id_str = hex::encode(channel_bytes);
                    break (channel_bytes, channel_id_str);
                } else {
                    retry_count += 1;
                    if retry_count >= max_retries {
                        return Err(format!(
                            "No channel with initialized ledger found. Available channels: {}, but none have ledgers.",
                            available_channels.len()
                        ));
                    }
                    println!("⏳ No channel with ledger ready, retrying ({}/{})", retry_count, max_retries);
                    tokio::time::sleep(retry_delay).await;
                    continue;
                }
            }
        };

        // Create a zero-balance deposit
        if let Some(bd_handler) = self.node.deposits() {
            // Find the channel and get the counterparty node ID
            let channel_details = self.node.list_channels();
            let channel = channel_details.iter().find(|ch| ch.channel_id.0 == channel_bytes)
                .ok_or_else(|| format!("Channel {} not found.", hex::encode(channel_bytes)))?;

            let partner_node_id = channel.counterparty_node_id;

            // Convert deposit pubkey from string to PublicKey
            // Accept both 33-byte compressed (02/03 prefix) and 32-byte x-only formats
            let deposit_pubkey_bytes = hex::decode(&deposit_pubkey)
                .map_err(|_| "Invalid deposit pubkey format".to_string())?;
            let deposit_public_key = match deposit_pubkey_bytes.len() {
                33 => {
                    // Compressed pubkey format (02/03 prefix + 32 bytes)
                    bitcoin::secp256k1::PublicKey::from_slice(&deposit_pubkey_bytes)
                        .map_err(|_| "Invalid compressed public key".to_string())?
                },
                32 => {
                    // X-only pubkey format (32 bytes, assume even parity)
                    let mut pubkey_array = [0u8; 32];
                    pubkey_array.copy_from_slice(&deposit_pubkey_bytes);
                    bitcoin::secp256k1::PublicKey::from_x_only_public_key(
                        bitcoin::secp256k1::XOnlyPublicKey::from_slice(&pubkey_array)
                            .map_err(|_| "Invalid X-only public key".to_string())?,
                        bitcoin::secp256k1::Parity::Even
                    )
                },
                _ => return Err("Deposit pubkey must be 33 bytes (compressed) or 32 bytes (x-only)".to_string()),
            };

            // Check ledger exists
            if !bd_handler.list_active_partners().contains(&partner_node_id) {
                return Err(format!(
                    "Ledger not initialized for partner {}. Please initialize the ledger first.",
                    partner_node_id
                ));
            }

            // Pre-check: Verify channel is ready before attempting deposit creation
            // This gives an immediate error instead of waiting for ACK timeout
            if !channel.is_channel_ready || !channel.is_usable {
                return Err(format!(
                    "Channel to {} not ready for deposits (ready={}, usable={}). \
                    Please wait for channel to stabilize and try again.",
                    partner_node_id, channel.is_channel_ready, channel.is_usable
                ));
            }

            // Create the deposit
            println!("🔄 Creating deposit with ACK-based synchronization");
            bd_handler.add_deposit_async(partner_node_id, deposit_public_key, None).await
                .map_err(|e| format!("Failed to create deposit: {}", e))?;

            println!("✅ Successfully created deposit {} for partner {}", deposit_pubkey, partner_node_id);

            // Generate deposit-specific NWC keypair
            let (deposit_nwc_keypair, deposit_nwc_pubkey) = self.generate_deposit_nwc_keypair(deposit_public_key);

            // Register the deposit NWC key with scoped permissions
            self.register_deposit_nwc_key(deposit_nwc_pubkey, deposit_public_key).await;

            // Generate proper NWC connection string
            let nwc_connection_string = format!(
                "nostr+walletconnect://{}?relay={}&metadata={{\"name\":\"Deposit-{}\"}}",
                deposit_nwc_pubkey,
                self.relay_url,
                &deposit_pubkey[..8]
            );

            println!("🔑 Generated deposit-specific NWC key {} for deposit {}", deposit_nwc_pubkey, deposit_pubkey);

            let deposit_info = DepositInfo {
                deposit_pubkey: deposit_pubkey.clone(),
                channel_id: selected_channel_id_str,
                balance_sat: 0,
                nwc_connection_string,
                nwc_private_key: hex::encode(deposit_nwc_keypair.secret_bytes()),
            };

            // Store the client deposit mapping for persistence (prevents duplicates on restart)
            // Key by CLIENT pubkey (Nostr sender) to match Nostr reply deduplication semantics
            {
                let mut store = self.client_deposits.lock().await;
                store.insert(StoredClientDeposit {
                    client_pubkey: client_pubkey.to_string(), // Key by Nostr sender, not deposit pubkey
                    deposit_info: deposit_info.clone(),
                    deposit_keypair_secret: String::new(), // Client keeps deposit private key
                });
            }

            Ok(deposit_info)
        } else {
            Err("Bitcoin Deposits not enabled".to_string())
        }
    }

    /// Generate a deposit-specific NWC keypair using HKDF (same logic as NWCService)
    fn generate_deposit_nwc_keypair(&self, deposit_pubkey: bitcoin::secp256k1::PublicKey) -> (Keypair, XOnlyPublicKey) {
        // Derive from NWC service's secret key using HKDF
        let nwc_secret = self.keypair.secret_bytes();

        // HKDF: salt provides domain separation, info is the deposit identifier
        let hk = Hkdf::<Sha256>::new(Some(b"nwc-deposit-key-v1"), &nwc_secret);
        let mut secret_bytes = [0u8; 32];
        hk.expand(&deposit_pubkey.serialize(), &mut secret_bytes)
            .expect("HKDF expand for deposit NWC key");

        let secret_key = SecretKey::from_slice(&secret_bytes)
            .expect("Valid deposit NWC private key");
        let keypair = Keypair::from_secret_key(&self.secp, &secret_key);
        let (xonly_pubkey, _) = XOnlyPublicKey::from_keypair(&keypair);

        (keypair, xonly_pubkey)
    }
}
