//! Hub control-plane registration for the daemon.
//!
//! When `deposits-node run` is launched with `--hub-pubkey` and at
//! least one `--hub-relay`, a tokio task connects to the hub over
//! gift-wrapped DMs (same NIP-59 wire as the signer side) and
//! registers as a node. The operator pubkey is the identity — that's
//! the value `HubMessage::Register::Node` is documented to carry, and
//! it's what the operator's TUI displays when listing nodes.
//!
//! Behavior mirrors `deposits-signer::hub`:
//!   * `Register` on startup, retry every 5 minutes until accepted
//!   * `Heartbeat` every 10s
//!   * on `RegisterAck { next_action: Shutdown }`, exit the daemon
//!
//! Failures are non-fatal — the daemon keeps serving operator traffic
//! even if relays are down. A warn-level log on errors is enough.

use crate::Node;
use deposits_hub_proto::proto::{HubMessage, NextAction, NodeStats, Role};
use deposits_hub_proto::transport::{HubTransport, Inbound};
use std::sync::Arc;
use std::time::Duration;

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);
const REREGISTER_INTERVAL: Duration = Duration::from_secs(300);
const STATUS_PUSH_INTERVAL: Duration = Duration::from_secs(30);

/// Run the hub registration loop. Spawn this from the daemon startup
/// when both `hub_pubkey` and at least one `hub_relay` are set.
///
/// Arguments:
///   * `nostr_secret_hex` — the daemon's nostr identity secret. Per
///     convention, derived from the operator seed at `m/85'/0'/0'/0/0`
///     so a re-init under the same seed keeps the hub identity stable.
///   * `hub_pubkey_hex` — operator-provided hub identity (32-byte
///     x-only nostr pubkey).
///   * `relays` — relay URLs to connect to (gift-wraps fan out across
///     all of them).
///   * `operator_pubkey_hex` — the daemon's operator pubkey, sent as
///     `identity_pubkey` in `Register::Node`. This is the value the
///     hub keys the node entry by in `hub.json`.
///   * `label` — operator-friendly name, defaults to the operator's
///     `--name` flag if set, else `None` (hub uses a short-pk fallback).
///   * `signer_pubkey_hex` — transport pk of the `deposits-signer`
///     this daemon is paired with (its `--signer-pubkey`), or `None`
///     if running with an in-process LocalSigner. Hub stores it on
///     approval so the dashboard can resolve each node's signer.
pub async fn run(
    nostr_secret_hex: String,
    hub_pubkey_hex: String,
    relays: Vec<String>,
    operator_pubkey_hex: String,
    label: Option<String>,
    signer_pubkey_hex: Option<String>,
    node: Arc<Node>,
) -> Result<(), String> {
    let transport = HubTransport::connect(&nostr_secret_hex, &relays)
        .await
        .map_err(|e| format!("hub nostr connect: {}", e))?;
    let mut inbox = transport
        .subscribe()
        .await
        .map_err(|e| format!("hub subscribe: {}", e))?;

    tracing::info!(
        node_nostr_pubkey = %transport.hub_pubkey().to_hex(),
        hub_pubkey = %hub_pubkey_hex,
        relays = ?relays,
        "node ↔ hub: connected"
    );

    let register = HubMessage::Register {
        role: Role::Node,
        identity_pubkey: operator_pubkey_hex.clone(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        label,
        signer_pubkey: signer_pubkey_hex,
    };
    if let Err(e) = transport.send(&hub_pubkey_hex, register.clone()).await {
        tracing::warn!("hub register send: {}", e);
    }

    let mut heartbeat_tick = tokio::time::interval(HEARTBEAT_INTERVAL);
    heartbeat_tick.tick().await;
    let mut reregister_tick = tokio::time::interval(REREGISTER_INTERVAL);
    reregister_tick.tick().await;
    let mut status_tick = tokio::time::interval(STATUS_PUSH_INTERVAL);
    // Fire the first status push immediately so the dashboard has
    // something to show before the 30s tick rolls around.

    let mut accepted = false;

    loop {
        tokio::select! {
            _ = heartbeat_tick.tick() => {
                let hb = HubMessage::Heartbeat {
                    identity_pubkey: operator_pubkey_hex.clone(),
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
            _ = status_tick.tick() => {
                let stats = compute_node_stats(&node);
                let resp = HubMessage::StatusResp {
                    identity_pubkey: operator_pubkey_hex.clone(),
                    ready: stats.ledger_count > 0,
                    operator_pubkey: Some(operator_pubkey_hex.clone()),
                    allowlist: Vec::new(),
                    summary: None,
                    node_stats: Some(stats),
                };
                if let Err(e) = transport.send(&hub_pubkey_hex, resp).await {
                    tracing::debug!("hub status push: {}", e);
                }
            }
            maybe = inbox.recv() => {
                let Some(Inbound { from, msg }) = maybe else {
                    return Err("hub inbox closed".to_string());
                };
                if from.to_hex() != hub_pubkey_hex {
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

/// Snapshot the counts the dashboard cares about. Cheap (lock + iter
/// over ledgers — same path the /api/lifecycle handler uses). Errors
/// fall back to zeros so a transient wallet-sync failure doesn't
/// drop the whole status push.
fn compute_node_stats(node: &Node) -> NodeStats {
    use deposits_core::messages::LedgerOperation;
    use deposits_core::cosign_threshold::{cosign_requirement, LifecycleTier};

    let chain_tip = node.wallet.get_block_height().unwrap_or(0);
    let wallet_balance_sats = node.wallet_balance().unwrap_or(0);

    let probe_op = LedgerOperation::QuorumRemoveMember {
        quorum_member: node.node_id,
        operator_signature: [0u8; 64],
    };

    let mut ledger_count = 0u32; // own (operator)
    let mut active_ledger_count = 0u32; // own + Tier 0
    let mut quorum_member_count = 0u32; // partner positions in other ops' ledgers

    if let Ok(ledgers) = node.handler.ledgers.lock() {
        for (_id, arc) in ledgers.iter() {
            if let Ok(l) = arc.read() {
                if l.operator_key() == node.node_id {
                    ledger_count += 1;
                    let req = cosign_requirement(&l.state, &probe_op, chain_tip);
                    if matches!(req.tier, LifecycleTier::Tier0) {
                        active_ledger_count += 1;
                    }
                } else {
                    quorum_member_count += 1;
                }
            }
        }
    }

    let next_address = node
        .wallet
        .peek_unused_address()
        .ok()
        .map(|a| a.to_string());

    NodeStats {
        wallet_balance_sats,
        ledger_count,
        active_ledger_count,
        quorum_member_count,
        chain_tip,
        next_address,
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
            tracing::info!(accepted = ok, next = ?next_action, "hub: {}", message);
            if matches!(next_action, NextAction::Shutdown) {
                tracing::warn!("hub rejected this node — exiting per operator request");
                std::process::exit(0);
            }
        }
        HubMessage::StatusReq => {
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
