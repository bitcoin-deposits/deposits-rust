//! `HubState` — single-JSON-file persistent inventory.
//!
//! Layout under the hub's data dir:
//! ```text
//! <data-dir>/
//!   hub.json                   — JSON state (this module)
//!   hub-nostr-secret           — 32-byte hex, mode 0600 (loaded by ctor)
//!   spawned/                   — per-spawned-process workspaces
//!     <name>/
//!       data-dir/              — handed to the spawned binary
//!       stdout.log / stderr.log
//! ```
//!
//! Writes are atomic via tmp + rename; the file is small (10s of
//! entries) and only the operator's hub process writes it. Sqlite or
//! similar is overkill here.

use crate::proto::Role;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Persisted under `<data-dir>/hub.json`. Loaded at startup,
/// rewritten atomically on every mutation that touches durable state
/// (registration approvals, name edits, peer arrivals/departures).
/// Heartbeats live in-memory only — losing them on restart is fine
/// because peers re-heartbeat on the next interval.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct HubState {
    /// Hub's nostr identity pubkey (hex). The secret lives in the
    /// sibling `hub-nostr-secret` file (mode 0600), not in this JSON,
    /// so a casual `cat hub.json` doesn't expose key material.
    pub hub_pubkey: String,

    /// Approved signers, keyed by their nostr pubkey (the transport
    /// pubkey daemons connect to).
    #[serde(default)]
    pub signers: HashMap<String, SignerRecord>,

    /// Approved nodes, keyed by operator pubkey.
    #[serde(default)]
    pub nodes: HashMap<String, NodeRecord>,

    /// Peers that have sent Register messages we haven't accepted or
    /// rejected yet. Operator processes these from the TUI's approval
    /// page. Keyed by sender pubkey to dedupe rapid retries.
    #[serde(default)]
    pub pending: HashMap<String, PendingRegistration>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerRecord {
    /// Operator-chosen short name (e.g., "op-alice", "vault-1"). Free
    /// text, max 64 chars on accept.
    pub label: String,
    /// Whether this signer was spawned by the hub (true) or registered
    /// itself externally (false). Spawned signers get auto-restarted by
    /// the supervisor; external ones don't.
    pub spawned_by_hub: bool,
    /// Unix seconds at first acceptance. Doesn't change on reconnect.
    pub registered_at: u64,
    /// Semver of the signer binary at the most recent registration.
    pub last_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeRecord {
    pub label: String,
    pub spawned_by_hub: bool,
    pub registered_at: u64,
    pub last_version: String,
    /// Which signer this node uses. Set when the node registers; the
    /// node's Register payload includes the signer pubkey it's pinned
    /// to. Empty until first Register lands.
    #[serde(default)]
    pub signer_pubkey: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingRegistration {
    pub role: Role,
    /// What the peer claimed as its identity (transport pk for signer,
    /// operator pk for node). Operator sees this in the TUI to decide.
    pub identity_pubkey: String,
    pub suggested_label: Option<String>,
    pub version: String,
    /// First time we saw this Register attempt (peers may retry; we
    /// keep the earliest).
    pub first_seen: u64,
    /// Most recent retry time. Helps the operator decide if a peer is
    /// still actively trying or has given up.
    pub last_seen: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse hub.json: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("decode nostr secret: {0}")]
    Hex(String),
    #[error("invalid nostr secret length: expected 32 bytes, got {0}")]
    BadKeyLen(usize),
}

impl HubState {
    /// Load `<dir>/hub.json` + `<dir>/hub-nostr-secret`. If neither
    /// exists, create both: generate a fresh nostr secret, write
    /// mode-0600, write the matching hub.json. Idempotent.
    pub fn load_or_init(dir: &Path) -> Result<Self, StateError> {
        let state_path = dir.join("hub.json");
        let secret_path = dir.join("hub-nostr-secret");

        let mut state: HubState = if state_path.exists() {
            let raw = std::fs::read_to_string(&state_path)?;
            serde_json::from_str(&raw)?
        } else {
            HubState::default()
        };

        // Make sure the nostr secret exists; derive the pubkey and
        // sync it into state.hub_pubkey if it changed (shouldn't, but
        // be defensive — a wiped secret with a stale state file would
        // be confusing otherwise).
        let secret_bytes = if secret_path.exists() {
            let raw = std::fs::read_to_string(&secret_path)?;
            let bytes = hex::decode(raw.trim())
                .map_err(|e| StateError::Hex(format!("nostr secret: {}", e)))?;
            if bytes.len() != 32 {
                return Err(StateError::BadKeyLen(bytes.len()));
            }
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes);
            out
        } else {
            // Generate fresh + persist mode 0600.
            use bitcoin::secp256k1::{rand::rngs::OsRng, Secp256k1, SecretKey};
            let secp = Secp256k1::new();
            let (sk, _pk) = secp.generate_keypair(&mut OsRng);
            let bytes = sk.secret_bytes();
            // Cast to bitcoin::secp256k1 to ensure type alignment.
            let _: SecretKey = SecretKey::from_slice(&bytes)
                .expect("freshly generated key is valid");
            std::fs::write(&secret_path, hex::encode(bytes))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = std::fs::metadata(&secret_path)?.permissions();
                perms.set_mode(0o600);
                std::fs::set_permissions(&secret_path, perms)?;
            }
            bytes
        };

        // Derive pubkey from secret to populate / sanity-check state.
        // Nostr addresses peers by 32-byte x-only schnorr pubkeys (no
        // 02/03 parity prefix), so we serialize as x-only here — any
        // 33-byte compressed form would round-trip through the wire
        // as a malformed key.
        let pubkey_hex = {
            use bitcoin::secp256k1::{Secp256k1, SecretKey};
            let secp = Secp256k1::new();
            let sk = SecretKey::from_slice(&secret_bytes)
                .map_err(|e| StateError::Hex(format!("secret decode: {}", e)))?;
            let (xonly, _parity) = sk.x_only_public_key(&secp);
            hex::encode(xonly.serialize())
        };
        if state.hub_pubkey.is_empty() {
            state.hub_pubkey = pubkey_hex;
            state.save(dir)?;
        } else if state.hub_pubkey != pubkey_hex {
            // Defensive: hub.json claims one pubkey but the secret on
            // disk derives a different one. Treat the secret as ground
            // truth (it's the actual key material) and overwrite the
            // stale state field.
            tracing::warn!(
                "hub.json pubkey ({}) differs from secret-derived pubkey ({}); using secret",
                &state.hub_pubkey[..16.min(state.hub_pubkey.len())],
                &pubkey_hex[..16.min(pubkey_hex.len())],
            );
            state.hub_pubkey = pubkey_hex;
            state.save(dir)?;
        }

        Ok(state)
    }

    /// Atomic save: write to a sibling tmp file, then rename. Crash
    /// during write leaves the prior state intact.
    pub fn save(&self, dir: &Path) -> Result<(), StateError> {
        let path = dir.join("hub.json");
        let tmp = path.with_extension("json.tmp");
        let body = serde_json::to_string_pretty(self)?;
        std::fs::write(&tmp, body)?;
        std::fs::rename(tmp, path)?;
        Ok(())
    }

    pub fn hub_pubkey_hex(&self) -> &str {
        &self.hub_pubkey
    }

    /// Convenience: the nostr secret lives in a sibling file. Caller
    /// passes the data dir; this resolves the path. Reading it
    /// requires the operator's process to be running as the same
    /// user that owns the file (mode 0600).
    pub fn nostr_secret_path(dir: &Path) -> PathBuf {
        dir.join("hub-nostr-secret")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn fresh_init_generates_keypair_and_persists() {
        let tmp = TempDir::new().unwrap();
        let s1 = HubState::load_or_init(tmp.path()).unwrap();
        // 32-byte x-only schnorr pubkey, hex-encoded → 64 chars. (NOT
        // 66 — a 33-byte compressed key would be malformed on the
        // nostr wire.)
        assert_eq!(s1.hub_pubkey.len(), 64);
        assert!(tmp.path().join("hub.json").exists());
        assert!(tmp.path().join("hub-nostr-secret").exists());

        // Reload should give the same pubkey.
        let s2 = HubState::load_or_init(tmp.path()).unwrap();
        assert_eq!(s1.hub_pubkey, s2.hub_pubkey);
    }

    #[test]
    fn save_round_trips() {
        let tmp = TempDir::new().unwrap();
        let mut s = HubState::load_or_init(tmp.path()).unwrap();
        s.signers.insert(
            "02abcdef".repeat(8).chars().take(66).collect(),
            SignerRecord {
                label: "test".to_string(),
                spawned_by_hub: true,
                registered_at: 1_000_000,
                last_version: "0.1.0".to_string(),
            },
        );
        s.save(tmp.path()).unwrap();
        let s2 = HubState::load_or_init(tmp.path()).unwrap();
        assert_eq!(s2.signers.len(), 1);
        assert_eq!(s2.signers.values().next().unwrap().label, "test");
    }
}
