//! Hub ↔ peer wire protocol.
//!
//! One new nostr KIND, JSON payloads typed by a `type` field. Sent
//! gift-wrapped (NIP-44 inside kind:1059) like every other inter-peer
//! message in the deposits-rust protocol. JSON-over-one-kind for
//! legibility — you can grep transcripts and skim the protocol without
//! a decoder.
//!
//! ## Kind assignment
//!
//! `KIND_HUB = 30420` — a parameterized-replaceable kind in the NIP-33
//! application-defined range (30000-39999). Pinned in the nostr-sdk
//! deposits-rust uses (v0.37) as a generic application kind, so no
//! collision with existing protocol traffic (1059 gift-wrap, 9101/9106
//! disputes, 20101/20102 ledger req/resp).
//!
//! ## Versioning
//!
//! Payloads carry no explicit version field today. Wire compat:
//! `#[serde(rename_all = "snake_case")]` on variant names, additive
//! field changes via `#[serde(default)]`, and the typed `type` tag
//! gives forward extensibility — unknown variants decode as an error,
//! which is the right default for control-plane messages.

use serde::{Deserialize, Serialize};

/// Nostr event kind for hub control-plane DMs. See module docs.
pub const KIND_HUB: u16 = 30420;

/// Identity of a peer that registers with the hub.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// `deposits-signer` instance — holds a seed, signs for one
    /// operator identity.
    Signer,
    /// `deposits-node` instance — daemon serving the operator's ledger
    /// traffic, talks to a signer for keys.
    Node,
}

/// All hub-protocol messages. Sent as the body of a gift-wrapped DM
/// (kind:1059 wrapping a kind:30420 event) to the recipient's nostr
/// pubkey.
///
/// Convention: the originator's pubkey is in the nostr event's `pubkey`
/// field (set by nostr-sdk); we don't duplicate it in the payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HubMessage {
    /// Peer announces itself to the hub. Sent on startup and after
    /// reconnects. Operator decides whether to accept (manual approval
    /// in the TUI) before the peer is added to inventory.
    Register {
        role: Role,
        /// For signers: the transport pubkey (what daemons connect to).
        /// For nodes: the operator pubkey (the daemon's protocol identity).
        identity_pubkey: String,
        /// Semver of the binary, for diagnostics.
        version: String,
        /// Free-form human label the peer suggests (e.g., the operator
        /// can override in the TUI). Limited to 64 chars on accept.
        #[serde(default)]
        label: Option<String>,
        /// Nodes only: transport pubkey of the `deposits-signer` this
        /// daemon is paired with (its `--signer-pubkey` value). The
        /// hub stores it on approval so the dashboard can resolve each
        /// node's signer label. `None` for nodes using LocalSigner
        /// (in-process) and always `None` for Role::Signer registrations.
        #[serde(default)]
        signer_pubkey: Option<String>,
    },
    /// Hub's response to a Register. `accepted = false` means the
    /// operator hasn't approved (or rejected) yet — peer should keep
    /// retrying with backoff, OR shut down per `next_action`.
    RegisterAck {
        accepted: bool,
        /// Operator-facing message (e.g., "waiting for approval",
        /// "registered as 'op-alice'", "rejected").
        message: String,
        /// Hint to the peer about what to do next.
        #[serde(default)]
        next_action: NextAction,
    },
    /// Liveness ping. Sent every ~10s by registered peers. The hub
    /// updates `last_heartbeat` in state.
    Heartbeat {
        identity_pubkey: String,
        /// Unix seconds when the peer composed the message. Mostly
        /// informational — the hub trusts its own clock for staleness
        /// checks but logs the delta.
        ts: u64,
    },
    /// Hub asks a peer for more detail. Optional (heartbeats already
    /// imply liveness); used for the TUI drill-down.
    StatusReq,
    /// Detailed status reply. Daemons also push these unsolicited
    /// every ~30s so the hub dashboard can render current per-node
    /// state without polling.
    StatusResp {
        identity_pubkey: String,
        /// Signers: true if a seed is installed (operator-key derivable).
        /// Nodes: true if `quorum_members` exist on at least one ledger.
        ready: bool,
        /// Signers: operator pubkey (derived from seed). Nodes: equals
        /// identity_pubkey.
        #[serde(default)]
        operator_pubkey: Option<String>,
        /// Signers: list of allowlisted daemon transport pubkeys.
        /// Nodes: empty.
        #[serde(default)]
        allowlist: Vec<String>,
        /// Free-form one-line status (e.g., "syncing wallet",
        /// "waiting for cosignatures", "idle 5m").
        #[serde(default)]
        summary: Option<String>,
        /// Nodes only: live counts for the dashboard.
        #[serde(default)]
        node_stats: Option<NodeStats>,
    },
}

/// Per-node counts surfaced in the hub dashboard. Cheap to recompute
/// (the node already tracks all this for its admin API); pushed every
/// 30s alongside the heartbeat cadence.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NodeStats {
    /// Confirmed wallet balance in satoshis.
    pub wallet_balance_sats: u64,
    /// Ledgers this node is the *operator* of — the ones it's
    /// actually offering. This is the count the operator cares about
    /// at the dashboard level.
    pub ledger_count: u32,
    /// Of `ledger_count`, how many are in Tier 0 (active, value-moving
    /// allowed). Lagging means an own ledger has slipped past quorum
    /// expiry into the cascade.
    pub active_ledger_count: u32,
    /// Ledgers where this node is a partner-role quorum member for
    /// some other operator. Surfaced separately because they're a
    /// different obligation kind — "people relying on me as a witness"
    /// rather than "deposits I'm offering."
    pub quorum_member_count: u32,
    /// Current chain tip height the node observed (informational; lets
    /// the dashboard show "behind by N blocks" if a node lags).
    pub chain_tip: u32,
    /// Lowest-indexed receiving address that hasn't seen funds yet —
    /// stable across status pushes until a tx arrives. The hub
    /// dashboard renders this as a QR for phone-wallet funding.
    /// `None` when the wallet can't materialize an address (e.g.,
    /// not yet synced) — TUI shows "(awaiting address)" in that case.
    #[serde(default)]
    pub next_address: Option<String>,
}

/// What the hub asks the peer to do next after a Register. Defaults
/// to `Retry` so older peers (no `next_action` field) keep pinging.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum NextAction {
    /// Keep retrying — the operator hasn't approved yet.
    #[default]
    Retry,
    /// Registered + accepted — peer can settle into Heartbeat mode.
    Heartbeat,
    /// Operator rejected this peer — peer should stop trying.
    Shutdown,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_round_trips_json() {
        let m = HubMessage::Register {
            role: Role::Signer,
            identity_pubkey: "0299aabbcc".repeat(6).chars().take(66).collect(),
            version: "0.1.0".to_string(),
            label: Some("test-signer".to_string()),
            signer_pubkey: None,
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains("\"type\":\"register\""));
        assert!(s.contains("\"role\":\"signer\""));
        let back: HubMessage = serde_json::from_str(&s).unwrap();
        match back {
            HubMessage::Register { role, label, .. } => {
                assert_eq!(role, Role::Signer);
                assert_eq!(label.as_deref(), Some("test-signer"));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn next_action_defaults_to_retry() {
        // RegisterAck without next_action in JSON should decode with
        // NextAction::Retry default.
        let s = r#"{"type":"register_ack","accepted":false,"message":"waiting"}"#;
        let m: HubMessage = serde_json::from_str(s).unwrap();
        match m {
            HubMessage::RegisterAck { next_action, .. } => {
                assert_eq!(next_action, NextAction::Retry);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn heartbeat_minimal_shape() {
        let m = HubMessage::Heartbeat {
            identity_pubkey: "0".repeat(66),
            ts: 1234567890,
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains("\"type\":\"heartbeat\""));
        let back: HubMessage = serde_json::from_str(&s).unwrap();
        match back {
            HubMessage::Heartbeat { ts, .. } => assert_eq!(ts, 1234567890),
            _ => panic!("wrong variant"),
        }
    }
}
