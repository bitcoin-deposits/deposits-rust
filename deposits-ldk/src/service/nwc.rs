//! NWC (Nostr Wallet Connect) service handlers
//!
//! Provides NWC pubkey and connection string endpoints for wallet initialization.

use crate::handler::DepositsHandler;
use crate::logger::LdkLogger;
use super::proto::{
    GetNwcInfoRequest, GetNwcInfoResponse,
    GetNwcConnectRequest, GetNwcConnectResponse,
    GetDepositNwcRequest, GetDepositNwcResponse,
    DepositsError,
};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{Secp256k1, SecretKey, PublicKey, Keypair};
use hkdf::Hkdf;
use sha2::Sha256;
use std::ops::Deref;

/// Default relay URL for NWC connections
const DEFAULT_RELAY_URL: &str = "ws://localhost:7777";

/// Generate a deterministic NWC keypair from the node pubkey
/// Returns (secret_hex, pubkey_hex) where pubkey is derived from secret
fn generate_nwc_keypair(node_pubkey_hex: &str) -> (String, String) {
    // Generate deterministic secret from node pubkey using SHA256
    // Must match nwc_service.rs derivation
    let mut data = b"nwc-secret-v2-".to_vec();
    data.extend_from_slice(node_pubkey_hex.as_bytes());
    let hash = sha256::Hash::hash(&data);
    let secret_bytes: &[u8] = hash.as_ref();

    // Derive the NWC pubkey from the secret
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(secret_bytes)
        .expect("32 bytes from sha256 is always valid");
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let (xonly_pubkey, _) = keypair.x_only_public_key();

    // Return x-only pubkey (32 bytes) for Nostr compatibility
    let xonly_hex = hex::encode(xonly_pubkey.serialize());
    let secret_hex = hex::encode(secret_bytes);

    (secret_hex, xonly_hex)
}

/// Handle get NWC info request
/// Returns the NWC pubkey (derived from deterministic secret) and relay URL
pub fn handle_get_nwc_info<L>(
    handler: &DepositsHandler<L>,
    _request: GetNwcInfoRequest,
) -> Result<GetNwcInfoResponse, DepositsError>
where
    L: Deref + Clone + Send + Sync,
    L::Target: LdkLogger,
{
    let node_pubkey = handler.our_node_id();
    let node_pubkey_hex = hex::encode(node_pubkey.serialize());

    // Get the NWC pubkey (derived from deterministic secret)
    let (_secret, nwc_pubkey) = generate_nwc_keypair(&node_pubkey_hex);

    Ok(GetNwcInfoResponse {
        pubkey: nwc_pubkey,
        relay_url: DEFAULT_RELAY_URL.to_string(),
    })
}

/// Handle get NWC connect request
/// Returns a full NWC connection string with secret for node-level access
pub fn handle_get_nwc_connect<L>(
    handler: &DepositsHandler<L>,
    _request: GetNwcConnectRequest,
) -> Result<GetNwcConnectResponse, DepositsError>
where
    L: Deref + Clone + Send + Sync,
    L::Target: LdkLogger,
{
    let node_pubkey = handler.our_node_id();
    let node_pubkey_hex = hex::encode(node_pubkey.serialize());

    // Generate NWC keypair - pubkey is derived from secret
    let (secret, nwc_pubkey) = generate_nwc_keypair(&node_pubkey_hex);
    let relay_url = DEFAULT_RELAY_URL;

    // Build the nostr+walletconnect:// URI (simple URL encoding for relay)
    let encoded_relay = relay_url.replace(":", "%3A").replace("/", "%2F");
    let connection_string = format!(
        "nostr+walletconnect://{}?relay={}&secret={}",
        nwc_pubkey,
        encoded_relay,
        secret
    );

    Ok(GetNwcConnectResponse {
        connection_string,
        pubkey: nwc_pubkey,
        secret,
        relay_url: relay_url.to_string(),
    })
}

/// Generate a deposit-specific NWC keypair using HKDF from the NWC service's private key
/// Returns (secret_hex, xonly_pubkey_hex)
fn generate_deposit_nwc_keypair(nwc_secret_bytes: &[u8], deposit_pubkey: &PublicKey) -> (String, String) {
    // HKDF: salt provides domain separation, info is the deposit identifier
    let hk = Hkdf::<Sha256>::new(Some(b"nwc-deposit-key-v1"), nwc_secret_bytes);
    let mut secret_bytes = [0u8; 32];
    hk.expand(&deposit_pubkey.serialize(), &mut secret_bytes)
        .expect("HKDF expand for deposit NWC key");

    // Create keypair from derived secret
    let secp = Secp256k1::new();
    let keypair = Keypair::from_seckey_slice(&secp, &secret_bytes)
        .expect("valid secret key from HKDF");
    let (xonly_pubkey, _parity) = keypair.x_only_public_key();

    let secret_hex = hex::encode(secret_bytes);
    let pubkey_hex = hex::encode(xonly_pubkey.serialize());

    (secret_hex, pubkey_hex)
}

/// Handle get deposit-specific NWC credentials request
/// Returns:
/// - nwc_pubkey: the SERVER's NWC pubkey (client encrypts TO this)
/// - nwc_secret: the CLIENT's deposit-specific secret (client signs WITH this)
pub fn handle_get_deposit_nwc<L>(
    handler: &DepositsHandler<L>,
    request: GetDepositNwcRequest,
) -> Result<GetDepositNwcResponse, DepositsError>
where
    L: Deref + Clone + Send + Sync,
    L::Target: LdkLogger,
{
    // Parse the deposit pubkey from hex
    let deposit_pubkey_bytes = hex::decode(&request.deposit_pubkey)
        .map_err(|e| DepositsError {
            code: "INVALID_DEPOSIT_PUBKEY".to_string(),
            message: format!("Invalid deposit pubkey hex: {}", e),
        })?;

    let deposit_pubkey = PublicKey::from_slice(&deposit_pubkey_bytes)
        .map_err(|e| DepositsError {
            code: "INVALID_DEPOSIT_PUBKEY".to_string(),
            message: format!("Invalid deposit pubkey: {}", e),
        })?;

    // Get the node's main NWC keypair (server's keypair)
    let node_pubkey = handler.our_node_id();
    let node_pubkey_hex = hex::encode(node_pubkey.serialize());
    let (server_nwc_secret_hex, server_nwc_pubkey) = generate_nwc_keypair(&node_pubkey_hex);
    let server_nwc_secret_bytes = hex::decode(&server_nwc_secret_hex)
        .expect("nwc_secret_hex is valid hex");

    // Derive deposit-specific client keypair (for client to sign with)
    let (client_nwc_secret, _client_nwc_pubkey) =
        generate_deposit_nwc_keypair(&server_nwc_secret_bytes, &deposit_pubkey);

    let relay_url = DEFAULT_RELAY_URL;

    // Build the nostr+walletconnect:// URI
    // Format: nostr+walletconnect://<server_pubkey>?relay=<relay>&secret=<client_secret>
    let encoded_relay = relay_url.replace(":", "%3A").replace("/", "%2F");
    let connection_string = format!(
        "nostr+walletconnect://{}?relay={}&secret={}",
        server_nwc_pubkey,  // Server's pubkey (to encrypt TO)
        encoded_relay,
        client_nwc_secret   // Client's secret (to sign WITH)
    );

    Ok(GetDepositNwcResponse {
        nwc_pubkey: server_nwc_pubkey,   // Server's pubkey
        nwc_secret: client_nwc_secret,   // Client's secret
        relay_url: relay_url.to_string(),
        connection_string,
    })
}
