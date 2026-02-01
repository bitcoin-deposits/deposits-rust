// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Nostr transport for peer-to-peer messaging
//!
//! Uses Nostr encrypted direct messages (NIP-04) to send deposits protocol
//! messages between peers.

use bitcoin::secp256k1::{PublicKey, SecretKey};
use deposits_core::messages::DepositsMessage;
use nostr_sdk::prelude::*;
use std::collections::HashMap;
use std::sync::RwLock;
use tokio::sync::mpsc;

use crate::Error;

/// Default relay URLs for the network
/// Empty by default - relays should be explicitly configured
pub const DEFAULT_RELAYS: &[&str] = &[];

/// Nostr transport for deposits protocol messages
pub struct NostrTransport {
    /// The nostr client
    client: Client,

    /// Our keypair for signing/decryption
    keys: Keys,

    /// Our secp256k1 pubkey (same as deposits node ID)
    our_pubkey: PublicKey,

    /// Pending inbound messages
    inbound_rx: mpsc::UnboundedReceiver<InboundMessage>,

    /// Sender for inbound messages (used by subscription task)
    inbound_tx: mpsc::UnboundedSender<InboundMessage>,

    /// Peer pubkey mapping (secp256k1 -> nostr)
    peer_keys: RwLock<HashMap<PublicKey, nostr_sdk::PublicKey>>,
}

/// An inbound message from a peer
#[derive(Debug, Clone)]
pub struct InboundMessage {
    /// The deposits protocol message
    pub message: DepositsMessage,

    /// Sender's secp256k1 public key
    pub sender: PublicKey,

    /// Timestamp
    pub timestamp: u64,
}

impl NostrTransport {
    /// Create a new Nostr transport
    pub async fn new(secret_key: SecretKey, relays: Vec<String>) -> Result<Self, Error> {
        // Convert secp256k1 key to nostr keys
        let secret_bytes = secret_key.secret_bytes();
        let nostr_secret = nostr_sdk::SecretKey::from_slice(&secret_bytes)
            .map_err(|e| Error::Nostr(format!("Invalid secret key: {}", e)))?;
        let keys = Keys::new(nostr_secret);

        // Get our secp256k1 pubkey
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let our_pubkey = PublicKey::from_secret_key(&secp, &secret_key);

        // Create nostr client
        let client = Client::new(keys.clone());

        // Add relays
        let relay_list: Vec<String> = if relays.is_empty() {
            DEFAULT_RELAYS.iter().map(|s| s.to_string()).collect()
        } else {
            relays
        };

        for relay in &relay_list {
            client
                .add_relay(relay)
                .await
                .map_err(|e| Error::Nostr(format!("Failed to add relay {}: {}", relay, e)))?;
        }

        // Connect to relays
        client.connect().await;

        // Create channel for inbound messages
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();

        Ok(Self {
            client,
            keys,
            our_pubkey,
            inbound_rx,
            inbound_tx,
            peer_keys: RwLock::new(HashMap::new()),
        })
    }

    /// Get our secp256k1 public key (node ID)
    pub fn our_pubkey(&self) -> PublicKey {
        self.our_pubkey
    }

    /// Get our nostr public key
    pub fn nostr_pubkey(&self) -> nostr_sdk::PublicKey {
        self.keys.public_key()
    }

    /// Convert a secp256k1 pubkey to nostr pubkey
    fn secp_to_nostr(pubkey: &PublicKey) -> Result<nostr_sdk::PublicKey, Error> {
        // secp256k1 pubkeys are 33 bytes compressed, nostr uses x-only (32 bytes)
        let serialized = pubkey.serialize();
        // Skip the first byte (0x02 or 0x03 prefix) to get x-only
        let x_only = &serialized[1..];
        nostr_sdk::PublicKey::from_slice(x_only)
            .map_err(|e| Error::Nostr(format!("Invalid pubkey conversion: {}", e)))
    }

    /// Send a message to a peer via encrypted DM (NIP-04)
    pub async fn send_message(&self, peer: PublicKey, msg: DepositsMessage) -> Result<(), Error> {
        // Convert peer pubkey to nostr pubkey
        let nostr_peer = Self::secp_to_nostr(&peer)?;

        // Serialize the message
        let bytes = msg.encode();

        // Encode as hex for transport
        let plaintext = hex::encode(&bytes);

        // Encrypt using NIP-04
        let encrypted = nip04::encrypt(self.keys.secret_key(), &nostr_peer, &plaintext)
            .map_err(|e| Error::Nostr(format!("Encryption failed: {}", e)))?;

        // Build the event (kind 4 = encrypted DM)
        let event = EventBuilder::new(Kind::EncryptedDirectMessage, encrypted)
            .tag(Tag::public_key(nostr_peer))
            .sign_with_keys(&self.keys)
            .map_err(|e| Error::Nostr(format!("Failed to sign event: {}", e)))?;

        // Send
        self.client
            .send_event(event)
            .await
            .map_err(|e| Error::Nostr(format!("Failed to send message: {}", e)))?;

        tracing::debug!("Sent message to {}", peer);
        Ok(())
    }

    /// Start listening for inbound messages
    pub async fn start_listening(&self) -> Result<(), Error> {
        // Subscribe to DMs addressed to us
        let filter = Filter::new()
            .kind(Kind::EncryptedDirectMessage)
            .pubkey(self.keys.public_key());

        self.client
            .subscribe(vec![filter], None)
            .await
            .map_err(|e| Error::Nostr(format!("Subscribe failed: {}", e)))?;

        Ok(())
    }

    /// Process incoming events (call this in a loop)
    /// This awaits on the notification channel, blocking until a message arrives
    pub async fn process_events(&mut self) -> Result<(), Error> {
        // Wait for a notification (this blocks until one arrives)
        match self.client.notifications().recv().await {
            Ok(notification) => {
                if let RelayPoolNotification::Event { event, .. } = notification {
                    if event.kind == Kind::EncryptedDirectMessage {
                        if let Ok(msg) = self.process_dm(&event) {
                            let _ = self.inbound_tx.send(msg);
                        }
                    }
                }
                // Drain any additional pending notifications without blocking
                while let Ok(notification) = self.client.notifications().try_recv() {
                    if let RelayPoolNotification::Event { event, .. } = notification {
                        if event.kind == Kind::EncryptedDirectMessage {
                            if let Ok(msg) = self.process_dm(&event) {
                                let _ = self.inbound_tx.send(msg);
                            }
                        }
                    }
                }
            }
            Err(_) => {
                // Channel closed or lagged, wait a bit before retrying
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }
        }
        Ok(())
    }

    /// Process an encrypted DM event
    fn process_dm(&self, event: &Event) -> Result<InboundMessage, Error> {
        // Decrypt the content using NIP-04
        let content = nip04::decrypt(self.keys.secret_key(), &event.pubkey, &event.content)
            .map_err(|e| Error::Nostr(format!("Failed to decrypt DM: {}", e)))?;

        // Decode from hex
        let bytes = hex::decode(&content)
            .map_err(|e| Error::Serialization(format!("Invalid hex in message: {}", e)))?;

        // Parse as DepositsMessage
        let msg = DepositsMessage::decode(&bytes)
            .map_err(|e| Error::Serialization(format!("Failed to parse message: {:?}", e)))?;

        // Convert sender nostr pubkey to secp256k1
        // Note: This is lossy - we lose the y-coordinate parity
        // In production, messages should include the full sender pubkey
        let sender_bytes = event.pubkey.to_bytes();
        let mut full_pubkey = [0u8; 33];
        full_pubkey[0] = 0x02; // Assume even y
        full_pubkey[1..].copy_from_slice(&sender_bytes);
        let sender = PublicKey::from_slice(&full_pubkey)
            .map_err(|e| Error::Nostr(format!("Invalid sender pubkey: {}", e)))?;

        Ok(InboundMessage {
            message: msg,
            sender,
            timestamp: event.created_at.as_u64(),
        })
    }

    /// Receive the next inbound message (non-blocking)
    pub fn try_recv(&mut self) -> Option<InboundMessage> {
        self.inbound_rx.try_recv().ok()
    }

    /// Receive the next inbound message (blocking)
    pub async fn recv(&mut self) -> Option<InboundMessage> {
        self.inbound_rx.recv().await
    }

    /// Disconnect from all relays
    pub async fn disconnect(&self) {
        self.client.disconnect().await.ok();
    }
}

/// Builder for NostrTransport with configuration options
pub struct NostrTransportBuilder {
    secret_key: SecretKey,
    relays: Vec<String>,
}

impl NostrTransportBuilder {
    pub fn new(secret_key: SecretKey) -> Self {
        Self {
            secret_key,
            relays: Vec::new(),
        }
    }

    pub fn relay(mut self, url: impl Into<String>) -> Self {
        self.relays.push(url.into());
        self
    }

    pub fn relays(mut self, urls: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.relays.extend(urls.into_iter().map(|s| s.into()));
        self
    }

    pub async fn build(self) -> Result<NostrTransport, Error> {
        NostrTransport::new(self.secret_key, self.relays).await
    }
}
