//! NWC (Nostr Wallet Connect) service handlers
//!
//! Provides NWC pubkey and connection string endpoints for wallet initialization.

use crate::handler::DepositsHandler;
use crate::logger::LdkLogger;
use super::proto::{
    GetNwcInfoRequest, GetNwcInfoResponse,
    GetNwcConnectRequest, GetNwcConnectResponse,
    DepositsError,
};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{Secp256k1, SecretKey, PublicKey};
use std::ops::Deref;

/// Default relay URL for NWC connections
const DEFAULT_RELAY_URL: &str = "ws://localhost:7777";

/// Generate a deterministic NWC keypair from the node pubkey
/// Returns (secret_hex, pubkey_hex) where pubkey is derived from secret
fn generate_nwc_keypair(node_pubkey_hex: &str) -> (String, String) {
    // Generate deterministic secret from node pubkey
    let mut data = b"nwc-secret-".to_vec();
    data.extend_from_slice(node_pubkey_hex.as_bytes());
    let hash = sha256::Hash::hash(&data);
    let secret_bytes: &[u8] = hash.as_ref();

    // Derive the NWC pubkey from the secret
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(secret_bytes)
        .expect("32 bytes from sha256 is always valid");
    let nwc_pubkey = PublicKey::from_secret_key(&secp, &secret_key);

    // Return x-only pubkey (32 bytes) for Nostr compatibility
    let pubkey_bytes = nwc_pubkey.serialize();
    // Skip the 02/03 prefix byte to get x-only format
    let xonly_hex = hex::encode(&pubkey_bytes[1..]);
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
    L: Deref + Clone,
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
    L: Deref + Clone,
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
