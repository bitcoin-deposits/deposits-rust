// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Nostr transport for peer-to-peer messaging
//!
//! Uses Nostr encrypted direct messages (NIP-04) to send deposits protocol
//! messages between peers, and public events for ledger updates.
//!
//! # Custom Kinds
//!
//! - **Kind 21100**: Ledger updates (regular event, not replaceable)
//!   - Tag `d`: `<operator_pubkey>:<reserves_id>` (ledger identifier)
//!   - Tag `seq`: sequence number
//!   - Tag `prev`: previous hash (hex)
//!   - Tag `hash`: current hash (hex)
//!   - Content: base64-encoded TLV wire format of SignedLedgerUpdate
//!
//! - **Kind 21101**: Ledger requests (deposit_open, etc.)
//!   - Tag `l`: `<operator_pubkey>:<reserves_id>` (ledger identifier)
//!   - Tag `action`: action name (e.g., "deposit_open")
//!   - Content: JSON with action parameters
//!
//! - **Kind 21102**: Ledger responses (replies to requests)
//!   - Tag `e`: reference to request event ID
//!   - Tag `l`: ledger identifier
//!   - Tag `status`: "ok" or "error"
//!   - Content: JSON with result or error message

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use bitcoin::secp256k1::{PublicKey, SecretKey};
use deposits_core::messages::DepositsMessage;
use deposits_core::types::SignedLedgerUpdate;
use deposits_core::{TlvDecode, TlvEncode};
use nostr_sdk::prelude::*;
use std::collections::HashMap;
use std::sync::RwLock;
use tokio::sync::mpsc;

use crate::Error;

/// Custom Kind for ledger updates.
/// Uses range 1000-9999 (regular custom events) to ensure relay storage.
/// Each update is a separate event that relays should retain.
pub const KIND_LEDGER_UPDATE: u16 = 9100;

/// Custom Kind for ledger requests (deposit_open, etc.)
/// Uses range 1000-9999 (regular custom events) for relay storage.
pub const KIND_LEDGER_REQUEST: u16 = 9101;

/// Custom Kind for ledger responses (replies to requests)
/// Uses range 1000-9999 (regular custom events) for relay storage.
pub const KIND_LEDGER_RESPONSE: u16 = 9102;

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

    /// Pending inbound messages (encrypted DMs)
    inbound_rx: mpsc::UnboundedReceiver<InboundMessage>,

    /// Sender for inbound messages (used by subscription task)
    inbound_tx: mpsc::UnboundedSender<InboundMessage>,

    /// Pending inbound ledger updates (broadcasts)
    ledger_rx: mpsc::UnboundedReceiver<InboundLedgerUpdate>,

    /// Sender for ledger updates
    ledger_tx: mpsc::UnboundedSender<InboundLedgerUpdate>,

    /// Pending inbound ledger requests
    request_rx: mpsc::UnboundedReceiver<LedgerRequest>,

    /// Sender for ledger requests
    request_tx: mpsc::UnboundedSender<LedgerRequest>,

    /// Pending inbound ledger responses
    response_rx: mpsc::UnboundedReceiver<LedgerResponse>,

    /// Sender for ledger responses
    response_tx: mpsc::UnboundedSender<LedgerResponse>,

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

/// An inbound ledger update from a broadcast
#[derive(Debug, Clone)]
pub struct InboundLedgerUpdate {
    /// The signed ledger update
    pub update: SignedLedgerUpdate,

    /// Ledger identifier (operator_pubkey:reserves_id)
    pub ledger_id: String,

    /// Nostr event timestamp
    pub timestamp: u64,

    /// Nostr event ID for reference
    pub event_id: String,
}

/// A ledger request (e.g., deposit_open)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LedgerRequest {
    /// Action to perform
    pub action: String,

    /// Ledger identifier (operator:reserves_id)
    pub ledger_id: String,

    /// Action-specific parameters as JSON
    pub params: serde_json::Value,

    /// Nostr event ID of this request
    #[serde(skip)]
    pub event_id: String,

    /// Sender's nostr pubkey (for responses)
    #[serde(skip)]
    pub sender: String,

    /// Timestamp
    #[serde(skip)]
    pub timestamp: u64,
}

/// A ledger response (reply to a request)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LedgerResponse {
    /// Was the request successful?
    pub success: bool,

    /// Result data (if successful)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,

    /// Error message (if failed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    /// Reference to the request event ID
    #[serde(skip)]
    pub request_id: String,

    /// Ledger identifier
    #[serde(skip)]
    pub ledger_id: String,

    /// Nostr event ID of this response
    #[serde(skip)]
    pub event_id: String,

    /// Timestamp
    #[serde(skip)]
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

        // Create channels for inbound messages, ledger updates, requests, and responses
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
        let (ledger_tx, ledger_rx) = mpsc::unbounded_channel();
        let (request_tx, request_rx) = mpsc::unbounded_channel();
        let (response_tx, response_rx) = mpsc::unbounded_channel();

        Ok(Self {
            client,
            keys,
            our_pubkey,
            inbound_rx,
            inbound_tx,
            ledger_rx,
            ledger_tx,
            request_rx,
            request_tx,
            response_rx,
            response_tx,
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

    /// Broadcast a ledger update to the network.
    ///
    /// Creates a parameterized replaceable event (Kind 30100) that can be
    /// subscribed to by anyone interested in this ledger.
    pub async fn broadcast_ledger_update(&self, update: &SignedLedgerUpdate) -> Result<String, Error> {
        // Create ledger identifier from operator pubkey and reserves_id
        let ledger_id = format!("{}:{}", update.operator_id, update.reserves_id);

        // Encode update as TLV, then base64
        let tlv_bytes = update.tlv_encode();
        let content = BASE64.encode(&tlv_bytes);

        // Build the event with appropriate tags
        let event = EventBuilder::new(Kind::Custom(KIND_LEDGER_UPDATE), &content)
            .tag(Tag::custom(
                TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::D)),
                [&ledger_id],
            ))
            .tag(Tag::custom(
                TagKind::custom("seq"),
                [update.sequence_number.to_string()],
            ))
            .tag(Tag::custom(
                TagKind::custom("prev"),
                [hex::encode(update.previous_hash)],
            ))
            .tag(Tag::custom(
                TagKind::custom("hash"),
                [hex::encode(update.current_hash)],
            ))
            .sign_with_keys(&self.keys)
            .map_err(|e| Error::Nostr(format!("Failed to sign event: {}", e)))?;

        let event_id = event.id.to_hex();

        // Broadcast
        self.client
            .send_event(event)
            .await
            .map_err(|e| Error::Nostr(format!("Failed to broadcast ledger update: {}", e)))?;

        tracing::info!(
            "Broadcast ledger update: ledger={}, seq={}, hash={}",
            ledger_id,
            update.sequence_number,
            &hex::encode(update.current_hash)[..16]
        );

        Ok(event_id)
    }

    /// Subscribe to ledger updates for a specific ledger.
    ///
    /// The ledger_id format is `<operator_pubkey>:<reserves_id>`.
    pub async fn subscribe_to_ledger(&self, ledger_id: &str) -> Result<(), Error> {
        let filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_UPDATE))
            .custom_tag(
                SingleLetterTag::lowercase(Alphabet::D),
                [ledger_id],
            );

        self.client
            .subscribe(vec![filter], None)
            .await
            .map_err(|e| Error::Nostr(format!("Failed to subscribe to ledger: {}", e)))?;

        tracing::info!("Subscribed to ledger updates: {}", ledger_id);
        Ok(())
    }

    /// Subscribe to all ledger updates from a specific operator.
    ///
    /// Uses prefix matching on the `d` tag to find all ledgers from this operator.
    pub async fn subscribe_to_operator(&self, operator_pubkey: &PublicKey) -> Result<(), Error> {
        // We can't do prefix matching in Nostr filters, so we subscribe to all
        // ledger update events and filter locally. For now, subscribe to all.
        let filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_UPDATE));

        self.client
            .subscribe(vec![filter], None)
            .await
            .map_err(|e| Error::Nostr(format!("Failed to subscribe to operator: {}", e)))?;

        tracing::info!("Subscribed to ledger updates from operator: {}", operator_pubkey);
        Ok(())
    }

    /// Send a ledger request (e.g., deposit_open)
    ///
    /// Returns the event ID for tracking the response.
    pub async fn send_ledger_request(
        &self,
        ledger_id: &str,
        action: &str,
        params: serde_json::Value,
    ) -> Result<String, Error> {
        let content = serde_json::to_string(&params)
            .map_err(|e| Error::Serialization(format!("Failed to serialize params: {}", e)))?;

        let event = EventBuilder::new(Kind::Custom(KIND_LEDGER_REQUEST), &content)
            .tag(Tag::custom(
                TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::L)),
                [ledger_id],
            ))
            .tag(Tag::custom(
                TagKind::custom("action"),
                [action],
            ))
            .sign_with_keys(&self.keys)
            .map_err(|e| Error::Nostr(format!("Failed to sign event: {}", e)))?;

        let event_id = event.id.to_hex();

        self.client
            .send_event(event)
            .await
            .map_err(|e| Error::Nostr(format!("Failed to send request: {}", e)))?;

        tracing::info!(
            "Sent ledger request: ledger={}, action={}, event={}",
            ledger_id,
            action,
            &event_id[..16]
        );

        Ok(event_id)
    }

    /// Send a ledger response (reply to a request)
    pub async fn send_ledger_response(
        &self,
        request_id: &str,
        ledger_id: &str,
        success: bool,
        result: Option<serde_json::Value>,
        error: Option<String>,
    ) -> Result<String, Error> {
        let response = LedgerResponse {
            success,
            result,
            error,
            request_id: String::new(),
            ledger_id: String::new(),
            event_id: String::new(),
            timestamp: 0,
        };

        let content = serde_json::to_string(&response)
            .map_err(|e| Error::Serialization(format!("Failed to serialize response: {}", e)))?;

        let status = if success { "ok" } else { "error" };

        let event = EventBuilder::new(Kind::Custom(KIND_LEDGER_RESPONSE), &content)
            .tag(Tag::custom(
                TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::E)),
                [request_id],
            ))
            .tag(Tag::custom(
                TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::L)),
                [ledger_id],
            ))
            .tag(Tag::custom(
                TagKind::custom("status"),
                [status],
            ))
            .sign_with_keys(&self.keys)
            .map_err(|e| Error::Nostr(format!("Failed to sign event: {}", e)))?;

        let event_id = event.id.to_hex();

        self.client
            .send_event(event)
            .await
            .map_err(|e| Error::Nostr(format!("Failed to send response: {}", e)))?;

        tracing::info!(
            "Sent ledger response: request={}, status={}, event={}",
            &request_id[..16],
            status,
            &event_id[..16]
        );

        Ok(event_id)
    }

    /// Subscribe to ledger requests for a specific ledger (for operators)
    pub async fn subscribe_to_requests(&self, ledger_id: &str) -> Result<(), Error> {
        // Subscribe to ALL requests of this kind (filter by ledger_id in handler)
        // This avoids potential issues with custom tag filters on some relays
        let filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_REQUEST));

        self.client
            .subscribe(vec![filter], None)
            .await
            .map_err(|e| Error::Nostr(format!("Failed to subscribe to requests: {}", e)))?;

        tracing::info!("Subscribed to ledger requests (kind {}), filtering for: {}", KIND_LEDGER_REQUEST, ledger_id);
        Ok(())
    }

    /// Fetch recent ledger requests (polling fallback)
    pub async fn fetch_recent_requests(&self, since_secs: u64) -> Result<Vec<LedgerRequest>, Error> {
        use nostr_sdk::Timestamp;

        let since = Timestamp::now() - since_secs;
        let filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_REQUEST))
            .since(since);

        let events = self.client
            .fetch_events(vec![filter], Some(tokio::time::Duration::from_secs(5)))
            .await
            .map_err(|e| Error::Nostr(format!("Failed to fetch events: {}", e)))?;

        let mut requests = Vec::new();
        for event in events.into_iter() {
            if let Ok(req) = self.process_ledger_request(&event) {
                requests.push(req);
            }
        }

        tracing::debug!("Fetched {} recent requests", requests.len());
        Ok(requests)
    }

    /// Subscribe to responses for a specific request (for requesters)
    pub async fn subscribe_to_response(&self, request_id: &str) -> Result<(), Error> {
        let filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_RESPONSE))
            .custom_tag(
                SingleLetterTag::lowercase(Alphabet::E),
                [request_id],
            );

        self.client
            .subscribe(vec![filter], None)
            .await
            .map_err(|e| Error::Nostr(format!("Failed to subscribe to response: {}", e)))?;

        tracing::debug!("Subscribed to response for request: {}", &request_id[..16]);
        Ok(())
    }

    /// Fetch response for a specific request (polling fallback)
    pub async fn fetch_response(&self, request_id: &str) -> Result<Option<LedgerResponse>, Error> {
        use nostr_sdk::Timestamp;

        // Look for responses from the last 60 seconds
        let since = Timestamp::now() - 60;
        let filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_RESPONSE))
            .custom_tag(
                SingleLetterTag::lowercase(Alphabet::E),
                [request_id],
            )
            .since(since);

        let events = self.client
            .fetch_events(vec![filter], Some(tokio::time::Duration::from_secs(5)))
            .await
            .map_err(|e| Error::Nostr(format!("Failed to fetch events: {}", e)))?;

        for event in events.into_iter() {
            if let Ok(response) = self.process_ledger_response(&event) {
                if response.request_id == request_id {
                    tracing::debug!("Fetched response for request: {}", &request_id[..16]);
                    return Ok(Some(response));
                }
            }
        }

        Ok(None)
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
    /// This awaits on the notification channel with a timeout
    pub async fn process_events(&mut self) -> Result<(), Error> {
        // Wait for a notification with timeout
        let timeout = tokio::time::Duration::from_millis(500);
        match tokio::time::timeout(timeout, self.client.notifications().recv()).await {
            Ok(Ok(notification)) => {
                tracing::debug!("Received notification: {:?}", notification);
                self.handle_notification(notification);
                // Drain any additional pending notifications without blocking
                while let Ok(notification) = self.client.notifications().try_recv() {
                    self.handle_notification(notification);
                }
            }
            Ok(Err(_)) => {
                // Channel closed or lagged
                tracing::debug!("Notification channel error");
            }
            Err(_) => {
                // Timeout - no notification received, that's ok
            }
        }
        Ok(())
    }

    /// Handle a single notification
    fn handle_notification(&self, notification: RelayPoolNotification) {
        if let RelayPoolNotification::Event { event, .. } = notification {
            // Use numeric kind value for comparison since Kind::Custom(n) and Kind::Regular(n)
            // are different enum variants but represent the same kind number
            let kind_num = event.kind.as_u16();

            if event.kind == Kind::EncryptedDirectMessage {
                if let Ok(msg) = self.process_dm(&event) {
                    let _ = self.inbound_tx.send(msg);
                }
            } else if kind_num == KIND_LEDGER_UPDATE {
                if let Ok(update) = self.process_ledger_update(&event) {
                    let _ = self.ledger_tx.send(update);
                }
            } else if kind_num == KIND_LEDGER_REQUEST {
                if let Ok(request) = self.process_ledger_request(&event) {
                    let _ = self.request_tx.send(request);
                }
            } else if kind_num == KIND_LEDGER_RESPONSE {
                if let Ok(response) = self.process_ledger_response(&event) {
                    let _ = self.response_tx.send(response);
                }
            }
        }
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

    /// Process a ledger update event
    fn process_ledger_update(&self, event: &Event) -> Result<InboundLedgerUpdate, Error> {
        // Extract ledger_id from the d tag
        let ledger_id = event
            .tags
            .iter()
            .find_map(|tag| {
                if tag.kind() == TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::D)) {
                    tag.content().map(|s| s.to_string())
                } else {
                    None
                }
            })
            .ok_or_else(|| Error::Nostr("Missing d tag in ledger update".to_string()))?;

        // Decode content from base64
        let tlv_bytes = BASE64
            .decode(&event.content)
            .map_err(|e| Error::Serialization(format!("Invalid base64 in ledger update: {}", e)))?;

        // Decode TLV to SignedLedgerUpdate
        let update = SignedLedgerUpdate::tlv_decode(&tlv_bytes)
            .map_err(|e| Error::Serialization(format!("Failed to decode ledger update: {:?}", e)))?;

        tracing::debug!(
            "Received ledger update: ledger={}, seq={}, hash={}",
            ledger_id,
            update.sequence_number,
            &hex::encode(update.current_hash)[..16]
        );

        Ok(InboundLedgerUpdate {
            update,
            ledger_id,
            timestamp: event.created_at.as_u64(),
            event_id: event.id.to_hex(),
        })
    }

    /// Process a ledger request event
    fn process_ledger_request(&self, event: &Event) -> Result<LedgerRequest, Error> {
        // Extract ledger_id from the l tag
        let ledger_id = event
            .tags
            .iter()
            .find_map(|tag| {
                if tag.kind() == TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::L)) {
                    tag.content().map(|s| s.to_string())
                } else {
                    None
                }
            })
            .ok_or_else(|| Error::Nostr("Missing l tag in ledger request".to_string()))?;

        // Extract action from the action tag
        let action = event
            .tags
            .iter()
            .find_map(|tag| {
                if tag.kind() == TagKind::custom("action") {
                    tag.content().map(|s| s.to_string())
                } else {
                    None
                }
            })
            .ok_or_else(|| Error::Nostr("Missing action tag in ledger request".to_string()))?;

        // Parse params from content
        let params: serde_json::Value = serde_json::from_str(&event.content)
            .unwrap_or(serde_json::Value::Null);

        tracing::debug!(
            "Received ledger request: ledger={}, action={}, event={}",
            ledger_id,
            action,
            &event.id.to_hex()[..16]
        );

        Ok(LedgerRequest {
            action,
            ledger_id,
            params,
            event_id: event.id.to_hex(),
            sender: event.pubkey.to_hex(),
            timestamp: event.created_at.as_u64(),
        })
    }

    /// Process a ledger response event
    fn process_ledger_response(&self, event: &Event) -> Result<LedgerResponse, Error> {
        // Extract request_id from the e tag
        let request_id = event
            .tags
            .iter()
            .find_map(|tag| {
                if tag.kind() == TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::E)) {
                    tag.content().map(|s| s.to_string())
                } else {
                    None
                }
            })
            .ok_or_else(|| Error::Nostr("Missing e tag in ledger response".to_string()))?;

        // Extract ledger_id from the l tag
        let ledger_id = event
            .tags
            .iter()
            .find_map(|tag| {
                if tag.kind() == TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::L)) {
                    tag.content().map(|s| s.to_string())
                } else {
                    None
                }
            })
            .unwrap_or_default();

        // Extract status from the status tag
        let status = event
            .tags
            .iter()
            .find_map(|tag| {
                if tag.kind() == TagKind::custom("status") {
                    tag.content().map(|s| s.to_string())
                } else {
                    None
                }
            })
            .unwrap_or_else(|| "unknown".to_string());

        // Parse response from content
        let mut response: LedgerResponse = serde_json::from_str(&event.content)
            .unwrap_or(LedgerResponse {
                success: status == "ok",
                result: None,
                error: Some("Failed to parse response".to_string()),
                request_id: String::new(),
                ledger_id: String::new(),
                event_id: String::new(),
                timestamp: 0,
            });

        response.request_id = request_id.clone();
        response.ledger_id = ledger_id;
        response.event_id = event.id.to_hex();
        response.timestamp = event.created_at.as_u64();

        tracing::debug!(
            "Received ledger response: request={}, status={}, event={}",
            &request_id[..16.min(request_id.len())],
            status,
            &event.id.to_hex()[..16]
        );

        Ok(response)
    }

    /// Receive the next inbound message (non-blocking)
    pub fn try_recv(&mut self) -> Option<InboundMessage> {
        self.inbound_rx.try_recv().ok()
    }

    /// Receive the next inbound message (blocking)
    pub async fn recv(&mut self) -> Option<InboundMessage> {
        self.inbound_rx.recv().await
    }

    /// Receive the next ledger update (non-blocking)
    pub fn try_recv_ledger_update(&mut self) -> Option<InboundLedgerUpdate> {
        self.ledger_rx.try_recv().ok()
    }

    /// Receive the next ledger update (blocking)
    pub async fn recv_ledger_update(&mut self) -> Option<InboundLedgerUpdate> {
        self.ledger_rx.recv().await
    }

    /// Receive the next ledger request (non-blocking)
    pub fn try_recv_request(&mut self) -> Option<LedgerRequest> {
        self.request_rx.try_recv().ok()
    }

    /// Queue a request for processing (used by polling fallback)
    pub fn queue_request(&self, request: LedgerRequest) {
        let _ = self.request_tx.send(request);
    }

    /// Receive the next ledger request (blocking)
    pub async fn recv_request(&mut self) -> Option<LedgerRequest> {
        self.request_rx.recv().await
    }

    /// Receive the next ledger response (non-blocking)
    pub fn try_recv_response(&mut self) -> Option<LedgerResponse> {
        self.response_rx.try_recv().ok()
    }

    /// Receive the next ledger response (blocking)
    pub async fn recv_response(&mut self) -> Option<LedgerResponse> {
        self.response_rx.recv().await
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
