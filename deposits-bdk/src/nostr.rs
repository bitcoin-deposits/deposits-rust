// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Nostr transport for peer-to-peer messaging
//!
//! Uses Nostr encrypted direct messages (NIP-04 or NIP-44) to send
//! deposits protocol messages between peers.

use bitcoin::secp256k1::PublicKey;
use deposits_core::messages::DepositsMessage;
use std::sync::Arc;
use tokio::sync::mpsc;

use crate::Error;

/// Nostr relay URLs
pub const DEFAULT_RELAYS: &[&str] = &[
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://relay.nostr.band",
];

/// Nostr transport for deposits protocol messages
pub struct NostrTransport {
    /// Outbound message sender
    outbound_tx: mpsc::UnboundedSender<(PublicKey, Vec<u8>)>,

    /// Our Nostr public key (same as deposits node ID)
    our_pubkey: PublicKey,
}

impl NostrTransport {
    /// Create a new Nostr transport
    ///
    /// Returns the transport and a receiver for inbound messages
    pub fn new(
        our_pubkey: PublicKey,
    ) -> (Self, mpsc::UnboundedReceiver<(PublicKey, Vec<u8>)>) {
        let (outbound_tx, _outbound_rx) = mpsc::unbounded_channel();
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();

        // TODO: Spawn background task to:
        // 1. Connect to relays
        // 2. Subscribe to DMs addressed to us
        // 3. Forward received messages to inbound_tx
        // 4. Process outbound_rx and send encrypted DMs

        let _ = inbound_tx; // Will be used by background task

        (
            Self {
                outbound_tx,
                our_pubkey,
            },
            inbound_rx,
        )
    }

    /// Send a message to a peer via Nostr DM
    pub fn send_message(&self, peer: PublicKey, msg: DepositsMessage) -> Result<(), Error> {
        // Serialize the message using encode() which returns [type: u16][payload]
        let bytes = msg.encode();

        // Queue for sending
        self.outbound_tx
            .send((peer, bytes))
            .map_err(|_| Error::Nostr("Channel closed".to_string()))?;

        Ok(())
    }

    /// Get our Nostr public key
    pub fn our_pubkey(&self) -> PublicKey {
        self.our_pubkey
    }
}

/// Message wrapper for Nostr transport
///
/// Deposits messages are wrapped with metadata for Nostr transmission.
#[derive(Debug, Clone)]
pub struct NostrMessage {
    /// The deposits protocol message
    pub message: DepositsMessage,

    /// Sender's public key
    pub sender: PublicKey,

    /// Timestamp (Nostr event created_at)
    pub timestamp: u64,
}

/// Background task for Nostr relay management
pub struct NostrRelayManager {
    relays: Vec<String>,
}

impl NostrRelayManager {
    pub fn new(relays: Vec<String>) -> Self {
        Self { relays }
    }

    /// Start the relay manager (spawns background tasks)
    pub async fn start(
        self: Arc<Self>,
        _our_secret: bitcoin::secp256k1::SecretKey,
        _inbound_tx: mpsc::UnboundedSender<(PublicKey, Vec<u8>)>,
        _outbound_rx: mpsc::UnboundedReceiver<(PublicKey, Vec<u8>)>,
    ) -> Result<(), Error> {
        // TODO: Implement relay connection and message handling
        //
        // 1. Connect to each relay
        // 2. Subscribe to kind:4 (encrypted DM) events addressed to us
        // 3. Decrypt and forward to inbound_tx
        // 4. Process outbound_rx, encrypt, and publish to relays

        tracing::info!("Starting Nostr relay manager with {} relays", self.relays.len());

        Ok(())
    }
}
