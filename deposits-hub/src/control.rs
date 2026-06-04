//! Headless control-plane logic, factored out of the TUI.
//!
//! Both the TUI and the `--headless` daemon mode call the same
//! functions here for parking registrations and approving / rejecting
//! peers. Keeping the mutations in one place is the easiest way to
//! make sure a CI run of the headless mode behaves identically to an
//! operator hitting `a`/`x` in the TUI.

use crate::nostr::HubTransport;
use crate::proto::{
    BackupPayload, HubMessage, NextAction, Role, HUB_STATE_BACKUP_D_TAG, KIND_HUB_STATE_BACKUP,
};
use crate::state::{HubState, NodeRecord, PendingRegistration, SignerRecord};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Publish a self-encrypted snapshot of `hub.json` (plus master seed,
/// if present) to the relay as a parameterized-replaceable event.
/// Each call replaces the prior snapshot on the relay — NIP-33
/// `(pubkey, kind, d-tag)` dedup — so storage stays at one event per
/// hub instead of accumulating one per save.
///
/// Best-effort: if the relay is down or publish fails, logs a warning
/// and returns. Local state is always saved first; relay backup is a
/// belt-and-suspenders convenience for the lost-box scenario.
pub async fn publish_backup(
    transport: &HubTransport,
    state: &HubState,
    data_dir: &Path,
) {
    let hub_json = match serde_json::to_string(state) {
        Ok(j) => j,
        Err(e) => {
            tracing::warn!("backup: serialize hub.json: {}", e);
            return;
        }
    };
    let master_seed = std::fs::read_to_string(HubState::master_seed_path(data_dir))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let payload = BackupPayload {
        last_modified: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        hub_json,
        master_seed,
    };
    let blob = match serde_json::to_string(&payload) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("backup: serialize payload: {}", e);
            return;
        }
    };
    if let Err(e) = transport
        .publish_replaceable_to_self(KIND_HUB_STATE_BACKUP, HUB_STATE_BACKUP_D_TAG, &blob)
        .await
    {
        tracing::warn!("backup: publish to relay failed: {}", e);
    } else {
        tracing::debug!("backup: snapshot published");
    }
}

/// Park or refresh a Register from `sender_pk`. Returns `true` if the
/// peer was already in inventory **for the same role** (caller should
/// respond with an accepted ack) or `false` if it was just parked
/// (caller responds with a waiting/Retry ack).
///
/// Dedupe is per-role: a single operator running both `deposits-node`
/// and `deposits-signer` derives the same nostr identity from the
/// shared operator seed, so both register with the same sender pubkey
/// but distinct roles. Treating them as one (the original bug) made
/// the node's Register collide with the signer's already-approved
/// entry; the node never landed in inventory.
///
/// Pending entries are also role-scoped — the key is `<role>:<pk>` —
/// so an outstanding Signer registration doesn't shadow a Node
/// registration from the same key.
pub fn ingest_register(
    state: &mut HubState,
    data_dir: &Path,
    sender_pk: &str,
    role: Role,
    identity_pubkey: String,
    version: String,
    label: Option<String>,
    signer_pubkey: Option<String>,
) -> Result<bool, String> {
    let already = match role {
        Role::Signer => state.signers.contains_key(sender_pk),
        Role::Node => state.nodes.contains_key(sender_pk),
    };
    if already {
        // Re-Register from an already-approved node may carry a fresh
        // signer_pubkey (operator paired the node with a new signer
        // and restarted the daemon). Keep the inventory in sync.
        if matches!(role, Role::Node) {
            if let Some(node) = state.nodes.get_mut(sender_pk) {
                if node.signer_pubkey != signer_pubkey {
                    node.signer_pubkey = signer_pubkey;
                    state.save(data_dir).map_err(|e| format!("save: {}", e))?;
                }
            }
        }
        return Ok(true);
    }
    let now = unix_secs();
    let pkey = pending_key(role, sender_pk);
    let entry = state
        .pending
        .entry(pkey)
        .or_insert_with(|| PendingRegistration {
            role,
            identity_pubkey: identity_pubkey.clone(),
            suggested_label: label.clone(),
            version: version.clone(),
            first_seen: now,
            last_seen: now,
            signer_pubkey: signer_pubkey.clone(),
        });
    entry.last_seen = now;
    entry.version = version;
    if entry.suggested_label.is_none() {
        entry.suggested_label = label;
    }
    // Pin/refresh signer_pubkey on the pending entry too — a node
    // that restarts with a different signer before being approved
    // should reflect the new pairing.
    if matches!(role, Role::Node) {
        entry.signer_pubkey = signer_pubkey;
    }
    state.save(data_dir).map_err(|e| format!("save: {}", e))?;
    Ok(false)
}

/// Compose the `state.pending` key: `<role>:<sender_pk>`. Keeps Signer
/// and Node pending entries separate when they come from the same
/// shared-identity operator.
pub fn pending_key(role: Role, sender_pk: &str) -> String {
    let prefix = match role {
        Role::Signer => "signer",
        Role::Node => "node",
    };
    format!("{}:{}", prefix, sender_pk)
}

/// Move a pending entry into the approved inventory. The operator
/// passes a pending-map key (e.g. `signer:<pk>` or `node:<pk>`) —
/// these are what `state.pending` is keyed by. For convenience the
/// CLI also accepts a bare pubkey and prefers the unique pending
/// entry if there is exactly one.
pub fn approve(
    state: &mut HubState,
    data_dir: &Path,
    pending_key_or_pk: &str,
    override_label: Option<String>,
) -> Result<String, String> {
    let resolved_key = resolve_pending_key(state, pending_key_or_pk)?;
    let entry = state
        .pending
        .get(&resolved_key)
        .cloned()
        .ok_or_else(|| format!("no pending entry for {}", resolved_key))?;
    // The sender pubkey is the second half of `<role>:<pk>`.
    let sender_pk = resolved_key
        .splitn(2, ':')
        .nth(1)
        .unwrap_or(&resolved_key)
        .to_string();
    let now = unix_secs();
    let label = override_label
        .or(entry.suggested_label.clone())
        .unwrap_or_else(|| short_pk(&sender_pk));
    match entry.role {
        Role::Signer => {
            state.signers.insert(
                sender_pk.clone(),
                SignerRecord {
                    label: label.clone(),
                    spawned_by_hub: false,
                    registered_at: now,
                    last_version: entry.version.clone(),
                    transport_pubkey: entry.identity_pubkey.clone(),
                },
            );
        }
        Role::Node => {
            state.nodes.insert(
                sender_pk.clone(),
                NodeRecord {
                    label: label.clone(),
                    spawned_by_hub: false,
                    registered_at: now,
                    last_version: entry.version.clone(),
                    signer_pubkey: entry.signer_pubkey.clone(),
                },
            );
        }
    }
    state.pending.remove(&resolved_key);
    state.save(data_dir).map_err(|e| format!("save: {}", e))?;
    Ok(label)
}

/// Drop a pending entry. Caller should follow up with a
/// `RegisterAck { next_action: Shutdown }` so the peer stops trying.
pub fn reject(state: &mut HubState, data_dir: &Path, pending_key_or_pk: &str) -> Result<(), String> {
    let resolved_key = resolve_pending_key(state, pending_key_or_pk)?;
    if state.pending.remove(&resolved_key).is_none() {
        return Err(format!("no pending entry for {}", resolved_key));
    }
    state.save(data_dir).map_err(|e| format!("save: {}", e))?;
    Ok(())
}

/// Look up a pending entry by either the full `<role>:<pk>` key or
/// just the pubkey (works if exactly one role is pending for that pk).
fn resolve_pending_key(state: &HubState, k: &str) -> Result<String, String> {
    if state.pending.contains_key(k) {
        return Ok(k.to_string());
    }
    // Bare pubkey path: find the unique role.
    let matches: Vec<&String> = state
        .pending
        .keys()
        .filter(|key| {
            key.splitn(2, ':').nth(1) == Some(k)
        })
        .collect();
    match matches.len() {
        0 => Err(format!("no pending entry for {}", k)),
        1 => Ok(matches[0].clone()),
        n => Err(format!(
            "{} pending entries match pubkey {} — disambiguate with `<role>:<pk>`",
            n, k
        )),
    }
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
