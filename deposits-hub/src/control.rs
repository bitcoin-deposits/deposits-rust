//! Headless control-plane logic, factored out of the TUI.
//!
//! Both the TUI and the `--headless` daemon mode call the same
//! functions here for parking registrations and approving / rejecting
//! peers. Keeping the mutations in one place is the easiest way to
//! make sure a CI run of the headless mode behaves identically to an
//! operator hitting `a`/`x` in the TUI.

use crate::nostr::HubTransport;
use crate::proto::{HubMessage, NextAction, Role};
use crate::state::{HubState, NodeRecord, PendingRegistration, SignerRecord};
use std::path::Path;

/// Park or refresh a Register from `sender_pk`. Returns `true` if the
/// peer was already in inventory (caller should respond with an
/// accepted ack) or `false` if it was just parked (caller responds
/// with a waiting/Retry ack).
pub fn ingest_register(
    state: &mut HubState,
    data_dir: &Path,
    sender_pk: &str,
    role: Role,
    identity_pubkey: String,
    version: String,
    label: Option<String>,
) -> Result<bool, String> {
    if state.signers.contains_key(sender_pk) || state.nodes.contains_key(sender_pk) {
        return Ok(true);
    }
    let now = unix_secs();
    let entry = state
        .pending
        .entry(sender_pk.to_string())
        .or_insert_with(|| PendingRegistration {
            role,
            identity_pubkey: identity_pubkey.clone(),
            suggested_label: label.clone(),
            version: version.clone(),
            first_seen: now,
            last_seen: now,
        });
    entry.last_seen = now;
    entry.version = version;
    if entry.suggested_label.is_none() {
        entry.suggested_label = label;
    }
    state.save(data_dir).map_err(|e| format!("save: {}", e))?;
    Ok(false)
}

/// Move a pending entry into the approved inventory. Returns the label
/// chosen for the peer (used in logs / acks). `override_label` wins if
/// set; otherwise the peer's `suggested_label` is used, falling back to
/// a short-form pubkey.
pub fn approve(
    state: &mut HubState,
    data_dir: &Path,
    sender_pk: &str,
    override_label: Option<String>,
) -> Result<String, String> {
    let entry = state
        .pending
        .get(sender_pk)
        .cloned()
        .ok_or_else(|| format!("no pending entry for {}", sender_pk))?;
    let now = unix_secs();
    let label = override_label
        .or(entry.suggested_label.clone())
        .unwrap_or_else(|| short_pk(sender_pk));
    match entry.role {
        Role::Signer => {
            state.signers.insert(
                sender_pk.to_string(),
                SignerRecord {
                    label: label.clone(),
                    spawned_by_hub: false,
                    registered_at: now,
                    last_version: entry.version.clone(),
                },
            );
        }
        Role::Node => {
            state.nodes.insert(
                sender_pk.to_string(),
                NodeRecord {
                    label: label.clone(),
                    spawned_by_hub: false,
                    registered_at: now,
                    last_version: entry.version.clone(),
                    signer_pubkey: None,
                },
            );
        }
    }
    state.pending.remove(sender_pk);
    state.save(data_dir).map_err(|e| format!("save: {}", e))?;
    Ok(label)
}

/// Drop a pending entry. Caller should follow up with a
/// `RegisterAck { next_action: Shutdown }` so the peer stops trying.
pub fn reject(state: &mut HubState, data_dir: &Path, sender_pk: &str) -> Result<(), String> {
    if state.pending.remove(sender_pk).is_none() {
        return Err(format!("no pending entry for {}", sender_pk));
    }
    state.save(data_dir).map_err(|e| format!("save: {}", e))?;
    Ok(())
}

/// Send the standard "approved" ack (best-effort — heartbeat retries
/// snap a missing ack out within a few seconds).
pub async fn send_accept_ack(
    transport: &HubTransport,
    sender_pk: &str,
    label: &str,
) {
    let ack = HubMessage::RegisterAck {
        accepted: true,
        message: format!("approved as '{}'", label),
        next_action: NextAction::Heartbeat,
    };
    if let Err(e) = transport.send(sender_pk, ack).await {
        tracing::debug!("approve ack send: {}", e);
    }
}

/// Send the standard "rejected" ack so the peer exits.
pub async fn send_reject_ack(transport: &HubTransport, sender_pk: &str) {
    let ack = HubMessage::RegisterAck {
        accepted: false,
        message: "operator rejected this peer".to_string(),
        next_action: NextAction::Shutdown,
    };
    if let Err(e) = transport.send(sender_pk, ack).await {
        tracing::debug!("reject ack send: {}", e);
    }
}

/// Send the standard "waiting for approval" ack — used when we just
/// parked a fresh Register.
pub async fn send_waiting_ack(transport: &HubTransport, sender_pk: &str) {
    let ack = HubMessage::RegisterAck {
        accepted: false,
        message: "waiting for operator approval".to_string(),
        next_action: NextAction::Retry,
    };
    if let Err(e) = transport.send(sender_pk, ack).await {
        tracing::debug!("waiting ack send: {}", e);
    }
}

/// Send the standard "already approved" ack — used when an already-
/// inventoried peer re-Registers (e.g., after their restart).
pub async fn send_already_approved_ack(transport: &HubTransport, sender_pk: &str) {
    let ack = HubMessage::RegisterAck {
        accepted: true,
        message: "already approved".to_string(),
        next_action: NextAction::Heartbeat,
    };
    if let Err(e) = transport.send(sender_pk, ack).await {
        tracing::debug!("already-approved ack send: {}", e);
    }
}

fn short_pk(pk: &str) -> String {
    if pk.len() > 12 {
        format!("{}…{}", &pk[..6], &pk[pk.len() - 4..])
    } else {
        pk.to_string()
    }
}

fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
