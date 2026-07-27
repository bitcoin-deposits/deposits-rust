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

/// Parameterized-replaceable (NIP-33) event kind for the hub's
/// self-encrypted state snapshot. Relays keep only the latest event
/// per `(pubkey, kind, d-tag)`, so each `publish_replaceable_to_self`
/// call replaces the prior snapshot — storage stays at one event per
/// hub instead of accumulating one per save (the older approach,
/// which gift-wrapped the BackupSnapshot variant on kind:1059, was
/// correct but wasteful).
///
/// Content is NIP-44-encrypted with the hub's own keypair on both
/// sides of the conversation-key derivation. An observer of the
/// relay sees frequency + size, not the inventory.
pub const KIND_HUB_STATE_BACKUP: u16 = 30421;

/// Single d-tag value used for the state-backup parameterized-
/// replaceable event. A hub can technically multiplex distinct
/// snapshots by varying this — useful if we ever split inventory
/// from secrets — but today there's only one.
pub const HUB_STATE_BACKUP_D_TAG: &str = "hub-state";

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

/// Self-encrypted hub state snapshot. Lives on the relay as a
/// parameterized-replaceable event (kind = [`KIND_HUB_STATE_BACKUP`],
/// d-tag = [`HUB_STATE_BACKUP_D_TAG`]), NIP-44-encrypted with the
/// hub's own keypair on both sides. Operator restoring on a fresh
/// box needs only `hub-nostr-secret` + relay access.
///
/// Not part of the gift-wrap control plane — distinct channel with
/// its own kind so it gets NIP-33 replacement semantics (one event
/// per hub on the relay, not one per save).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupPayload {
    /// Unix seconds at the time of save. Diagnostic — NIP-33
    /// replacement already keeps the newest by created_at.
    pub last_modified: u64,
    /// Serialized hub.json (pretty-printed by the publisher; restore
    /// re-pretty-prints to dodge HashMap-iteration ordering quirks).
    pub hub_json: String,
    /// Hub master seed (64-char hex) if one has been generated.
    /// None for hubs that haven't spawned a derived signer yet.
    #[serde(default)]
    pub master_seed: Option<String>,
}

/// One quorum member, for the node-details pane. `pubkey` is the
/// member's signing key (hex); `ledger_id` is the ledger where that
/// member locks its collateral.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct QuorumMemberInfo {
    pub pubkey: String,
    pub ledger_id: String,
}

/// Per-own-ledger health the hub watches to build its "needs attention"
/// list and node-details pane. One entry per ledger this node operates.
/// Everything here the daemon already computes for its admin API
/// (`/api/lifecycle`, reserves, disputes) — this just rides the 30s
/// status push so the hub can rank deadlines and show detail fleet-wide
/// without polling each daemon.
///
/// Block-delta fields are `i64` so an already-passed deadline reads as a
/// negative number (overdue) rather than saturating to zero.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LedgerHealth {
    /// 16-hex ledger tag (matches the explorer's `d` tag / nostr filter).
    pub ledger_id: String,
    /// DEP-05 lifecycle tier: 0 = active (value-moving), rising into the
    /// post-expiry confiscation cascade (1 = minority … 3 = operator alone).
    pub tier: u8,
    /// `quorum_expiry` height from the most recent QuorumBegin, if any.
    pub quorum_expiry: Option<u32>,
    /// `quorum_expiry − chain_tip`. Negative once the quorum has lapsed.
    /// `None` for pre-quorum ledgers (no expiry set yet).
    pub blocks_to_expiry: Option<i64>,
    /// Whether value-moving ops can still be cosigned (Tier 0 only).
    pub value_moving_allowed: bool,
    /// Count of disputes currently open against this ledger.
    pub open_disputes: u32,
    /// Blocks until the soonest dispute response/arm deadline. Negative
    /// = overdue. `None` when no dispute is open.
    pub blocks_to_dispute_deadline: Option<i64>,
    /// On-chain reserves backing this ledger's deposits, in sats.
    pub reserves_sats: u64,
    /// Total depositor balance owed on this ledger (the obligation that
    /// `reserves_sats` must cover), in sats.
    pub obligations_sats: u64,
    /// Ledger length — sequence number of the latest committed update.
    #[serde(default)]
    pub sequence: u64,
    /// Number of open deposits on this ledger.
    #[serde(default)]
    pub deposit_count: u32,
    /// Quorum members (for the details pane). Empty pre-quorum.
    #[serde(default)]
    pub members: Vec<QuorumMemberInfo>,
    /// Block height the active quorum's QuorumBegin was committed. With
    /// `quorum_expiry` this gives the full begin→expiry duration.
    #[serde(default)]
    pub quorum_begin_block: Option<u32>,
    /// Sequence number of that QuorumBegin entry.
    #[serde(default)]
    pub quorum_begin_sequence: Option<u64>,
    /// Content hash (hex) of that QuorumBegin entry, for explorer links.
    #[serde(default)]
    pub quorum_begin_hash: Option<String>,
}

/// A ledger this node is a *partner* quorum member of (someone else's
/// operator ledger), for the "serving on" section of node details. We
/// witness/cosign for it but don't operate it, so its liabilities are
/// the operator's — surfaced read-only so the operator can see what
/// they're on the hook to co-sign for.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServingLedger {
    /// 16-hex ledger tag.
    pub ledger_id: String,
    /// The operator of this ledger (pubkey hex).
    pub operator: String,
    /// DEP-05 lifecycle tier of the ledger.
    pub tier: u8,
    pub quorum_expiry: Option<u32>,
    pub blocks_to_expiry: Option<i64>,
    pub deposit_count: u32,
    pub obligations_sats: u64,
    pub reserves_sats: u64,
    /// The full quorum, including this node.
    pub members: Vec<QuorumMemberInfo>,
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
    /// Per-own-ledger health for the hub's "needs attention" list.
    /// `#[serde(default)]`: daemons predating this field send nothing,
    /// and the hub falls back to the aggregate counts above.
    #[serde(default)]
    pub ledgers: Vec<LedgerHealth>,
    /// Partner ledgers this node co-signs for ("serving on" in the
    /// node-details pane). `#[serde(default)]` for the same compat reason.
    #[serde(default)]
    pub serving: Vec<ServingLedger>,
    /// `None` when the node reached its Lightning backend at the last
    /// status push; `Some(error)` when the probe failed — the daemon
    /// can't mint/pay invoices. The hub raises this as a critical
    /// concern. `#[serde(default)]` → old daemons report `None` (no
    /// false alarm).
    #[serde(default)]
    pub ln_error: Option<String>,
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
