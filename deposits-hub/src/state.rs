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
use std::collections::BTreeMap;
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
    pub signers: BTreeMap<String, SignerRecord>,

    /// Approved nodes, keyed by operator pubkey.
    #[serde(default)]
    pub nodes: BTreeMap<String, NodeRecord>,

    /// Peers that have sent Register messages we haven't accepted or
    /// rejected yet. Operator processes these from the TUI's approval
    /// page. Keyed by sender pubkey to dedupe rapid retries.
    #[serde(default)]
    pub pending: BTreeMap<String, PendingRegistration>,

    /// Stable index per hub-spawned signer name, used to derive the
    /// signer's seed from `hub-master-seed` via the BIP-85 path
    /// `m/83696968'/128169'/32'/<index>'`. Recovery: restore the
    /// master seed file, look up the name's index here, re-derive —
    /// no per-signer backup needed.
    #[serde(default)]
    pub signer_indexes: BTreeMap<String, u32>,

    /// Next index to allocate when a fresh name is spawned. Persisted
    /// so re-spawning an already-allocated name re-uses its index
    /// (idempotency) and a *new* name gets a never-before-used slot
    /// even if some entries above it have been removed from
    /// `signer_indexes`.
    #[serde(default)]
    pub next_signer_index: u32,

    /// True once the operator has confirmed they wrote down the
    /// BIP-39 mnemonic of `hub-master-seed`. The first-launch view
    /// in the TUI gates everything else on this flag — losing the
    /// mnemonic means losing every spawned signer's keys, so we
    /// refuse to proceed until the operator explicitly acknowledges.
    #[serde(default)]
    pub mnemonic_acknowledged: bool,
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
    /// Signer's transport pubkey (the value daemons pass as
    /// `--signer-pubkey`). Stored at approval time so the dashboard
    /// can resolve `NodeRecord.signer_pubkey → SignerRecord.label`.
    /// Empty string for signers approved before this field existed.
    #[serde(default)]
    pub transport_pubkey: String,
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
    /// Nodes only: signer transport pubkey the node declared. Carried
    /// from `HubMessage::Register::signer_pubkey` to `NodeRecord`
    /// on approval.
    #[serde(default)]
    pub signer_pubkey: Option<String>,
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
    #[error("bip39 mnemonic conversion: {0}")]
    Bip39(String),
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

    /// Path to the hub-wide master seed used to derive every
    /// hub-spawned signer's seed deterministically. One file to back
    /// up; restoring it + `hub.json` re-derives every spawned
    /// signer's identity.
    pub fn master_seed_path(dir: &Path) -> PathBuf {
        dir.join("hub-master-seed")
    }

    /// Load `<dir>/hub-master-seed`, generating a fresh 32-byte seed
    /// (mode 0600) on first use. Lazy — only called when a spawn
    /// actually needs to derive.
    pub fn load_or_init_master_seed(dir: &Path) -> Result<[u8; 32], StateError> {
        let path = Self::master_seed_path(dir);
        if path.exists() {
            let raw = std::fs::read_to_string(&path)?;
            let bytes = hex::decode(raw.trim())
                .map_err(|e| StateError::Hex(format!("master seed: {}", e)))?;
            if bytes.len() != 32 {
                return Err(StateError::BadKeyLen(bytes.len()));
            }
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes);
            return Ok(out);
        }
        use bitcoin::secp256k1::rand::rngs::OsRng;
        use bitcoin::secp256k1::rand::RngCore;
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        std::fs::write(&path, hex::encode(seed))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&path)?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&path, perms)?;
        }
        tracing::warn!(
            "hub: generated new master seed at {} — back this file up; \
             losing it means losing every hub-spawned signer's keys",
            path.display()
        );
        Ok(seed)
    }

    /// Convert the 32-byte master seed into a 24-word BIP-39 mnemonic.
    /// Used by the first-launch TUI view so the operator can write
    /// down a recoverable backup before any signer is derived.
    ///
    /// Returns the canonical space-separated phrase. Errors only on
    /// truly broken entropy (the bip39 crate's check) — should be
    /// infallible for any 32 bytes that came from a CSPRNG.
    pub fn master_seed_mnemonic(dir: &Path) -> Result<String, StateError> {
        let seed = Self::load_or_init_master_seed(dir)?;
        let mnemonic = bip39::Mnemonic::from_entropy(&seed)
            .map_err(|e| StateError::Bip39(e.to_string()))?;
        Ok(mnemonic.to_string())
    }

    /// Mark the operator as having acknowledged the BIP-39 mnemonic.
    /// One-way flag — once set, the first-launch overlay never shows
    /// again (the seed is what it is; re-confirming after the fact
    /// adds no value).
    pub fn acknowledge_mnemonic(&mut self) {
        self.mnemonic_acknowledged = true;
    }

    /// Look up or assign the BIP-32 derivation index for a signer
    /// name. Idempotent: same name always returns the same index, even
    /// after restart. New names get the current `next_signer_index`
    /// which is then bumped + persisted.
    pub fn signer_index_for(
        &mut self,
        name: &str,
        dir: &Path,
    ) -> Result<u32, StateError> {
        if let Some(&i) = self.signer_indexes.get(name) {
            return Ok(i);
        }
        let i = self.next_signer_index;
        self.signer_indexes.insert(name.to_string(), i);
        self.next_signer_index = i.checked_add(1).unwrap_or(u32::MAX);
        self.save(dir)?;
        Ok(i)
    }
}

/// Derive a signer seed deterministically from the hub master using
/// BIP-85 (deterministic entropy from a BIP-32 root key).
///
/// Path: `m / 83696968' / 128169' / 32' / index'`
///   * 83696968 — BIP-85 namespace constant (chosen by the spec
///     author; far outside any plausible BIP purpose registration).
///   * 128169 — application code for "HEX" entropy.
///   * 32 — length of the requested entropy in bytes.
///   * index — caller-supplied slot, allocated via
///     [`HubState::signer_index_for`].
///
/// The output is `HMAC-SHA512(key="bip-entropy-from-k",
/// msg=derived_private_key_bytes)` truncated to the first 32 bytes,
/// per BIP-85. This is the canonical "give me reproducible child
/// seed material for another tool" interface; using anything else
/// risks colliding with future BIP registrations.
pub fn derive_signer_seed(master: &[u8; 32], index: u32) -> Result<[u8; 32], StateError> {
    use bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv};
    use bitcoin::hashes::{sha512, Hash, HashEngine, Hmac, HmacEngine};
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::Network;

    const BIP85_NAMESPACE: u32 = 83_696_968;
    const APP_HEX: u32 = 128_169;
    const ENTROPY_LEN: u32 = 32;
    const HMAC_KEY: &[u8] = b"bip-entropy-from-k";

    let secp = Secp256k1::new();
    let xpriv = Xpriv::new_master(Network::Bitcoin, master)
        .map_err(|e| StateError::Hex(format!("master xpriv: {}", e)))?;
    let path = DerivationPath::from(vec![
        ChildNumber::from_hardened_idx(BIP85_NAMESPACE).expect("namespace fits in 31 bits"),
        ChildNumber::from_hardened_idx(APP_HEX).expect("app code fits"),
        ChildNumber::from_hardened_idx(ENTROPY_LEN).expect("32 fits"),
        ChildNumber::from_hardened_idx(index)
            .map_err(|e| StateError::Hex(format!("index hardened: {}", e)))?,
    ]);
    let child = xpriv
        .derive_priv(&secp, &path)
        .map_err(|e| StateError::Hex(format!("derive bip-85 child: {}", e)))?;

    let mut engine: HmacEngine<sha512::Hash> = HmacEngine::new(HMAC_KEY);
    engine.input(&child.private_key.secret_bytes());
    let mac = Hmac::<sha512::Hash>::from_engine(engine);
    let bytes = mac.as_byte_array();

    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes[..32]);
    Ok(out)
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
    fn derive_signer_seed_is_deterministic() {
        let master = [0x42u8; 32];
        let a0 = derive_signer_seed(&master, 0).unwrap();
        let a1 = derive_signer_seed(&master, 1).unwrap();
        // Same input → same output.
        assert_eq!(a0, derive_signer_seed(&master, 0).unwrap());
        // Different index → different bytes (otherwise the whole
        // point of indexed derivation is moot).
        assert_ne!(a0, a1);
        // Different master → different output.
        let other = [0x99u8; 32];
        assert_ne!(a0, derive_signer_seed(&other, 0).unwrap());
    }

    /// Conformance check against the published BIP-85 HEX test vector
    /// (length=64, index=0). Our `derive_signer_seed` is hardcoded to
    /// length=32, but the HMAC step is identical so we exercise the
    /// underlying derivation directly. If this breaks, the BIP-85 path
    /// numbers, the HMAC key string, or the derived-key extraction is
    /// off — none of which should ever change.
    ///
    /// Vector source: https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki
    ///   master xprv: xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb
    ///   path:        `m/83696968'/128169'/64'/0'`
    ///   entropy:     `492db4698cf3b73a5a24998aa3e9d7fa96275d85724a91e71aa2d645442f878555d078fd1f1f67e368976f04137b1f7a0d19232136ca50c44614af72b5582a5c`
    #[test]
    fn bip85_conformance_64byte_hex() {
        use bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv};
        use bitcoin::hashes::{sha512, Hash, HashEngine, Hmac, HmacEngine};
        use bitcoin::secp256k1::Secp256k1;
        use std::str::FromStr;

        let xpriv = Xpriv::from_str(
            "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb"
        ).unwrap();
        let secp = Secp256k1::new();
        // m/83696968'/128169'/64'/0'
        let path = DerivationPath::from(vec![
            ChildNumber::from_hardened_idx(83_696_968).unwrap(),
            ChildNumber::from_hardened_idx(128_169).unwrap(),
            ChildNumber::from_hardened_idx(64).unwrap(),
            ChildNumber::from_hardened_idx(0).unwrap(),
        ]);
        let child = xpriv.derive_priv(&secp, &path).unwrap();
        let mut eng: HmacEngine<sha512::Hash> = HmacEngine::new(b"bip-entropy-from-k");
        eng.input(&child.private_key.secret_bytes());
        let mac = Hmac::<sha512::Hash>::from_engine(eng);

        let expected = "492db4698cf3b73a5a24998aa3e9d7fa96275d85724a91e71aa2d645442f878555d078fd1f1f67e368976f04137b1f7a0d19232136ca50c44614af72b5582a5c";
        assert_eq!(hex::encode(mac.as_byte_array()), expected);
    }

    #[test]
    fn signer_index_for_is_stable_and_increments() {
        let tmp = TempDir::new().unwrap();
        let mut s = HubState::load_or_init(tmp.path()).unwrap();
        let alice = s.signer_index_for("alice", tmp.path()).unwrap();
        let bob = s.signer_index_for("bob", tmp.path()).unwrap();
        assert_eq!(alice, 0);
        assert_eq!(bob, 1);
        // Re-asking returns the same index — survives a reload.
        let s2 = HubState::load_or_init(tmp.path()).unwrap();
        let mut s2 = s2;
        assert_eq!(s2.signer_index_for("alice", tmp.path()).unwrap(), 0);
        assert_eq!(s2.signer_index_for("bob", tmp.path()).unwrap(), 1);
        // New name continues the sequence (doesn't reuse alice/bob slots).
        assert_eq!(s2.signer_index_for("carol", tmp.path()).unwrap(), 2);
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
                transport_pubkey: "02deadbeef".to_string(),
            },
        );
        s.save(tmp.path()).unwrap();
        let s2 = HubState::load_or_init(tmp.path()).unwrap();
        assert_eq!(s2.signers.len(), 1);
        assert_eq!(s2.signers.values().next().unwrap().label, "test");
    }

    #[test]
    fn mnemonic_is_24_words_and_stable() {
        let tmp = TempDir::new().unwrap();
        let _ = HubState::load_or_init(tmp.path()).unwrap();
        let phrase = HubState::master_seed_mnemonic(tmp.path()).unwrap();
        let words: Vec<&str> = phrase.split_whitespace().collect();
        // 32 bytes of entropy → 24-word BIP-39 phrase.
        assert_eq!(words.len(), 24, "expected 24 words, got {}: {}", words.len(), phrase);
        // Repeated calls return the same phrase (seed file is stable).
        let phrase2 = HubState::master_seed_mnemonic(tmp.path()).unwrap();
        assert_eq!(phrase, phrase2);
    }

    #[test]
    fn acknowledge_mnemonic_round_trips() {
        let tmp = TempDir::new().unwrap();
        let mut s = HubState::load_or_init(tmp.path()).unwrap();
        assert!(!s.mnemonic_acknowledged);
        s.acknowledge_mnemonic();
        s.save(tmp.path()).unwrap();
        let s2 = HubState::load_or_init(tmp.path()).unwrap();
        assert!(s2.mnemonic_acknowledged);
    }
}
