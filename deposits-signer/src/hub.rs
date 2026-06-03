//! Hub registration loop for `deposits-signer run --hub-pubkey/--hub-relay`.
//!
//! When the operator points a signer at a hub, this task runs alongside
//! the unix-socket server:
//!
//!   1. derive the signer's nostr identity from the same seed already
//!      loaded for signing (`m/85'/.../0`, [`crate::data::derive_keys_from_seed`])
//!   2. open a `HubTransport`, subscribe to inbound gift-wraps
//!   3. send `Register` to the hub pubkey, naming the signer's socket
//!      transport pubkey as `identity_pubkey` (that's the value the
//!      operator-side TUI shows when approving)
//!   4. loop: on `RegisterAck` → log + flip state; on `Heartbeat` tick
//!      → send another `Heartbeat`; on `Shutdown` ack → exit the process
//!
//! Failures here never block signing — the unix socket keeps serving
//! the daemon even if relays are down. A warn-level log on failure is
//! enough; the operator can re-launch with corrected flags.

use bitcoin::secp256k1::SecretKey;
use deposits_hub_proto::proto::{HubMessage, NextAction, Role};
use deposits_hub_proto::transport::{HubTransport, Inbound};
use std::time::Duration;

/// Heartbeat interval. Matches the hub's "trust the peer is alive if
/// we've heard from it within ~30s" assumption with a 3× safety margin.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);

/// Run the hub registration loop. Never returns under normal operation —
/// either heartbeats forever, exits the whole process on Shutdown ack,
/// or returns Err so the caller can decide what to do.
pub async fn run(
    hub_nostr_secret: SecretKey,
    hub_pubkey_hex: String,
    relays: Vec<String>,
    transport_pubkey_hex: String,
    label: Option<String>,
) -> Result<(), String> {
    let secret_hex = hex::encode(hub_nostr_secret.secret_bytes());
    let transport = HubTransport::connect(&secret_hex, &relays)
        .await
        .map_err(|e| format!("hub nostr connect: {}", e))?;
    let mut inbox = transport
        .subscribe()
        .await
        .map_err(|e| format!("hub subscribe: {}", e))?;

    let signer_nostr_pubkey = transport.hub_pubkey().to_hex();
    tracing::info!(
        signer_nostr_pubkey = %signer_nostr_pubkey,
        hub_pubkey = %hub_pubkey_hex,
        relays = ?relays,
        "signer ↔ hub: connected"
    );

    // Initial Register. If the operator-side TUI hasn't approved yet
    // the hub will reply RegisterAck { accepted: false }; we keep
    // heartbeating + the hub auto-replies with the latest state on the
    // next Heartbeat-as-cue isn't a thing, so we just re-register on a
    // longer cadence as a backstop.
    let register = HubMessage::Register {
        role: Role::Signer,
        identity_pubkey: transport_pubkey_hex.clone(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        label,
    };
    if let Err(e) = transport.send(&hub_pubkey_hex, register.clone()).await {
        tracing::warn!("hub register send: {}", e);
    }

    let mut heartbeat_tick = tokio::time::interval(HEARTBEAT_INTERVAL);
    heartbeat_tick.tick().await; // consume the immediate-fire
    // Re-Register every 5 minutes as a coarse fallback — covers the
    // case where the hub restarted and lost our pending entry between
    // its `since` filter window. Cheap.
    let mut reregister_tick = tokio::time::interval(Duration::from_secs(300));
    reregister_tick.tick().await;

    let mut accepted = false;

    loop {
        tokio::select! {
            _ = heartbeat_tick.tick() => {
                let hb = HubMessage::Heartbeat {
                    identity_pubkey: transport_pubkey_hex.clone(),
                    ts: unix_secs(),
                };
                if let Err(e) = transport.send(&hub_pubkey_hex, hb).await {
                    tracing::debug!("hub heartbeat send: {}", e);
                }
            }
            _ = reregister_tick.tick() => {
                if !accepted {
                    if let Err(e) = transport.send(&hub_pubkey_hex, register.clone()).await {
                        tracing::debug!("hub re-register send: {}", e);
                    }
                }
            }
            maybe = inbox.recv() => {
                let Some(Inbound { from, msg }) = maybe else {
                    return Err("hub inbox closed".to_string());
                };
                if from.to_hex() != hub_pubkey_hex {
                    // Stray gift-wrap from a peer that's not the hub
                    // we registered with — log and drop.
                    tracing::debug!(
                        from = %from.to_hex(),
                        "ignoring hub-protocol message from unexpected sender"
                    );
                    continue;
                }
                handle_from_hub(msg, &mut accepted);
            }
        }
    }
}

fn handle_from_hub(msg: HubMessage, accepted: &mut bool) {
    match msg {
        HubMessage::RegisterAck {
            accepted: ok,
            message,
            next_action,
        } => {
            *accepted = ok;
            tracing::info!(
                accepted = ok,
                next = ?next_action,
                "hub: {}",
                message
            );
            if matches!(next_action, NextAction::Shutdown) {
                tracing::warn!("hub rejected this signer — exiting per operator request");
                // Hard exit: there's no graceful path here, the
                // operator has explicitly rejected this signer and
                // continuing to serve the socket would defeat that.
                std::process::exit(0);
            }
        }
        HubMessage::StatusReq => {
            // Not implemented yet — silently drop. The hub will move
            // on; this is a control-plane request, not load-bearing.
            tracing::debug!("hub: StatusReq received (not implemented)");
        }
        other => {
            tracing::debug!("hub: unexpected inbound {:?}", std::mem::discriminant(&other));
        }
    }
}

fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
