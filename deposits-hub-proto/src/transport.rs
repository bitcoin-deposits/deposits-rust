//! Nostr transport for the hub control plane.
//!
//! Used by both ends of the conversation: the hub's own process and any
//! daemon (signer/node) that registers with it. Owns a long-lived
//! `Keys` + `Client` against the configured relays, subscribes to
//! gift-wrapped DMs addressed to the local pubkey, decodes them as
//! [`crate::proto::HubMessage`], and exposes:
//!
//!   * `send(recipient, msg)` — publish a `KIND_HUB` rumor inside a
//!     NIP-59 gift wrap, addressed to `recipient`
//!   * `subscribe()` — receive a `tokio::sync::mpsc::Receiver` of
//!     `(sender_pubkey, msg)` pairs; the background pump fills it as
//!     gift wraps arrive
//!
//! No retry / backoff / queueing — peers that need delivery guarantees
//! re-send. This is a best-effort control plane, not a reliable
//! message bus.

use crate::proto::{HubMessage, KIND_HUB};
use nostr_sdk::prelude::*;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

/// Inbound message: a `HubMessage` together with the pubkey it came
/// from (extracted from the rumor — gift-wrap layer uses an ephemeral
/// throwaway key, so the rumor's pubkey is the real sender).
#[derive(Debug)]
pub struct Inbound {
    pub from: PublicKey,
    pub msg: HubMessage,
}

#[derive(Debug, thiserror::Error)]
pub enum NostrError {
    #[error("nostr client: {0}")]
    Sdk(String),
    #[error("encode message: {0}")]
    Encode(#[from] serde_json::Error),
    #[error("invalid recipient pubkey: {0}")]
    Recipient(String),
}

/// Owns the relay client + hub keypair. Cheap to clone (Arc inside).
#[derive(Clone)]
pub struct HubTransport {
    keys: Keys,
    client: Client,
}

impl HubTransport {
    /// Connect to the given relays as the hub. Returns once at least
    /// one relay is connected (with a 5s ceiling — partial connectivity
    /// is fine, the pump retries forever).
    pub async fn connect(
        secret_hex: &str,
        relays: &[String],
    ) -> Result<Self, NostrError> {
        let secret = SecretKey::from_hex(secret_hex)
            .map_err(|e| NostrError::Sdk(format!("decode hub secret: {}", e)))?;
        let keys = Keys::new(secret);

        let client = Client::new(keys.clone());
        for r in relays {
            client
                .add_relay(r)
                .await
                .map_err(|e| NostrError::Sdk(format!("add relay {}: {}", r, e)))?;
        }
        client.connect().await;

        // Don't wait — the pump tolerates disconnects.
        tracing::info!(
            hub_pubkey = %keys.public_key().to_hex(),
            relays = ?relays,
            "hub nostr client connected"
        );
        Ok(Self { keys, client })
    }

    /// Public pubkey of the hub (as seen on the wire).
    pub fn hub_pubkey(&self) -> PublicKey {
        self.keys.public_key()
    }

    /// Subscribe to inbound gift wraps for the hub pubkey. The returned
    /// receiver yields decoded `HubMessage`s as they arrive. The
    /// background pump runs until the transport is dropped.
    ///
    /// Channel buffer: 256 — bursts of registrations during a cluster
    /// startup get absorbed; sustained backpressure is unlikely on a
    /// control plane.
    pub async fn subscribe(&self) -> Result<mpsc::Receiver<Inbound>, NostrError> {
        let me = self.keys.public_key();
        let filter = Filter::new()
            .kind(Kind::GiftWrap)
            .pubkey(me)
            // NIP-59 says wraps SHOULD jitter their `created_at` to a
            // random point in [now - 2 days, now]. A narrow window
            // (e.g. `now - 1h`) silently drops most legitimate wraps
            // because their stamped time is hours-to-days in the past.
            // Use `now - 2 days` exactly: matches the spec's worst
            // case, and gives a re-subscribing hub a chance to pick
            // up retries that real peers sent before we restarted.
            .since(Timestamp::now() - Duration::from_secs(172_800));

        self.client
            .subscribe(vec![filter], None)
            .await
            .map_err(|e| NostrError::Sdk(format!("subscribe: {}", e)))?;

        let (tx, rx) = mpsc::channel::<Inbound>(256);
        let client = self.client.clone();
        let keys = Arc::new(self.keys.clone());

        tokio::spawn(async move {
            let mut notifications = client.notifications();
            while let Ok(notif) = notifications.recv().await {
                if let RelayPoolNotification::Event { event, .. } = notif {
                    if event.kind != Kind::GiftWrap {
                        continue;
                    }
                    let rumor = match nip59::extract_rumor(&*keys, &event).await {
                        Ok(r) => r,
                        Err(e) => {
                            tracing::debug!("unwrap gift wrap: {}", e);
                            continue;
                        }
                    };
                    if rumor.rumor.kind != Kind::Custom(KIND_HUB) {
                        // Not for us — could be NIP-17 DM or similar.
                        continue;
                    }
                    let msg: HubMessage = match serde_json::from_str(&rumor.rumor.content) {
                        Ok(m) => m,
                        Err(e) => {
                            tracing::warn!(
                                "decode HubMessage from {}: {}",
                                rumor.sender.to_hex(),
                                e
                            );
                            continue;
                        }
                    };
                    if tx
                        .send(Inbound {
                            from: rumor.sender,
                            msg,
                        })
                        .await
                        .is_err()
                    {
                        // Receiver dropped — pump exits.
                        return;
                    }
                }
            }
        });

        Ok(rx)
    }

    /// Publish a self-encrypted parameterized-replaceable event (NIP-33
    /// kind + NIP-44 encrypted content). The relay deduplicates by
    /// `(pubkey, kind, d-tag)`, so each call **replaces** the prior
    /// snapshot — exactly what state backup needs. Storage stays at
    /// one event per hub instead of accumulating one-per-save.
    ///
    /// Encrypted to self: same secret on both sides of the NIP-44
    /// conversation key, which produces a deterministic shared key
    /// the operator can re-derive from just the hub's nostr secret.
    /// An observer scraping the relay sees that this pubkey publishes
    /// encrypted snapshots, but can't read content.
    pub async fn publish_replaceable_to_self(
        &self,
        kind: u16,
        d_tag: &str,
        plaintext: &str,
    ) -> Result<(), NostrError> {
        let self_pk = self.keys.public_key();
        let ciphertext = nip44::encrypt(
            self.keys.secret_key(),
            &self_pk,
            plaintext,
            nip44::Version::V2,
        )
        .map_err(|e| NostrError::Sdk(format!("nip44 encrypt: {}", e)))?;
        let event = EventBuilder::new(Kind::Custom(kind), ciphertext)
            .tags([Tag::identifier(d_tag)])
            .sign(&self.keys)
            .await
            .map_err(|e| NostrError::Sdk(format!("sign: {}", e)))?;
        self.client
            .send_event(event)
            .await
            .map_err(|e| NostrError::Sdk(format!("send_event: {}", e)))?;
        Ok(())
    }

    /// Fetch the latest self-published replaceable snapshot at
    /// `(kind, d_tag)` and decrypt with NIP-44. Returns `None` if no
    /// snapshot arrives within `timeout`. At most one event per relay
    /// is served because of NIP-33 replacement semantics; if the
    /// operator publishes to multiple relays we accept the first one
    /// to arrive (caller can pick newest by `created_at` if needed).
    pub async fn fetch_replaceable_from_self(
        &self,
        kind: u16,
        d_tag: &str,
        timeout: Duration,
    ) -> Result<Option<(u64, String)>, NostrError> {
        use nostr_sdk::SingleLetterTag;

        let self_pk = self.keys.public_key();
        let filter = Filter::new()
            .kind(Kind::Custom(kind))
            .author(self_pk)
            .custom_tag(SingleLetterTag::lowercase(nostr_sdk::Alphabet::D), [d_tag]);

        let events = self
            .client
            .fetch_events(vec![filter], Some(timeout))
            .await
            .map_err(|e| NostrError::Sdk(format!("fetch_events: {}", e)))?;

        // Pick newest by created_at — relays SHOULD only serve one per
        // (pubkey, kind, d), but multi-relay setups can fan in.
        let newest = events
            .into_iter()
            .max_by_key(|e| e.created_at.as_u64());
        let Some(event) = newest else {
            return Ok(None);
        };
        let plaintext = nip44::decrypt(self.keys.secret_key(), &self_pk, &event.content)
            .map_err(|e| NostrError::Sdk(format!("nip44 decrypt: {}", e)))?;
        Ok(Some((event.created_at.as_u64(), plaintext)))
    }

    /// Send a `HubMessage` to a peer via gift-wrap. Returns once the
    /// event is sent to the relay; relays may further fan-out.
    pub async fn send(
        &self,
        recipient: &str,
        msg: HubMessage,
    ) -> Result<(), NostrError> {
        let recipient_pk = PublicKey::from_hex(recipient)
            .map_err(|e| NostrError::Recipient(format!("{}: {}", recipient, e)))?;
        let payload = serde_json::to_string(&msg)?;
        let rumor = EventBuilder::new(Kind::Custom(KIND_HUB), payload);
        let wrap = EventBuilder::gift_wrap(&self.keys, &recipient_pk, rumor, [])
            .await
            .map_err(|e| NostrError::Sdk(format!("gift_wrap: {}", e)))?;
        self.client
            .send_event(wrap)
            .await
            .map_err(|e| NostrError::Sdk(format!("send_event: {}", e)))?;
        Ok(())
    }
}
