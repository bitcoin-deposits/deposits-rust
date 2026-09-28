// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Node implementation that ties together wallet, nostr, and lightning

use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{PublicKey, Secp256k1};
use bitcoin::Network;
use deposits_core::ledger::Ledger;
use deposits_core::message_validation::HandlerContext;
use deposits_core::messages::LedgerOperation;
use deposits_core::types::{
    compute_deposit_id, Deposit, DepositId, DepositOffer, DepositOfferStatus, DescriptorWitness,
    FeeStructure, OnChainWithdrawal, OnChainWithdrawalStatus, WithdrawalCompleteResult,
    WithdrawalLockResult,
};
use deposits_core::TlvDecode;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use tokio::sync::mpsc;

use crate::handler::{DepositsHandler, OutboundMessage};

/// Fast hex encoding for PublicKey (avoids byte-by-byte fmt::LowerHex overhead).
#[inline]
fn pubkey_hex(pk: &PublicKey) -> String {
    hex::encode(pk.serialize())
}
use crate::metrics;
use crate::nostr::{InboundMessage, NostrTransport};
use crate::wallet::Wallet;
use crate::Error;

/// Maximum number of quorum members a node will accept on its ledger.
/// Beyond this limit, add_quorum_member requests will be rejected.
pub const MAX_QUORUM_MEMBERS: usize = 8;

/// Default `quorum_expiry` window applied by `quorum begin` when the
/// operator doesn't pass `--quorum-expiry-blocks`. 4320 blocks ≈ 30
/// days at Bitcoin's 10-minute target. Long enough that routine
/// operation never hits the lifecycle cascade unintentionally; short
/// enough that an abandoned ledger lands in `auto_dispute_expired_quorums`
/// territory before customer funds get stuck.
///
/// Operators with stronger uptime can override per-rotation via the
/// CLI flag; tests that need a short-lived quorum (e.g.
/// `lifecycle_self_rescue`) also use the override.
pub const DEFAULT_QUORUM_EXPIRY_BLOCKS: u32 = 4320;

/// Configuration for the deposits-node node
#[derive(Clone)]
pub struct NodeConfig {
    /// Seed for wallet/identity (32 bytes)
    pub seed: [u8; 32],

    /// Bitcoin network
    pub network: Network,

    /// Electrum server URL
    pub electrum_url: String,

    /// Nostr relay URLs (fast relays for subscriptions + publishing)
    pub relays: Vec<String>,

    /// Slow (durable) relay URLs for gap-fill fetch_events only
    pub slow_relays: Vec<String>,

    /// Data directory
    pub data_dir: PathBuf,

    /// Operator name for advertisements (optional)
    pub operator_name: Option<String>,

    /// Use fast polling intervals (for regtest/testing)
    /// When enabled: periodic=5s, poll=5s, reload=2s
    /// When disabled: periodic=60s, poll=30s, reload=5s
    pub fast_poll: bool,

    /// Skip Schnorr signature verification of incoming Nostr events.
    /// Only use with trusted relays (e.g., local/private relays).
    pub skip_nostr_verify: bool,

    /// If `Some`, the daemon connects to a `deposits-signer` process at
    /// `socket_path` for operator-protocol signs (BIP-340 / ECDSA / ECDH /
    /// IssueNostrSecret). The signer's transport pubkey is pinned at
    /// connect; the daemon persists its own transport keypair under
    /// `data_dir/transport_secret`. Mutually exclusive with
    /// LocalSigner-from-seed (which is what the daemon does when this is
    /// `None`).
    ///
    /// The wallet (BDK) still derives from `seed` regardless — the
    /// watch-only descriptor split is its own follow-up.
    pub signer: Option<RemoteSignerConfig>,

    /// How many days before `quorum_expiry` the daemon should auto-rotate
    /// the quorum. The auto-refresh task triggers when
    /// `current_block + rotate_before_expiry_days × 144 ≥ quorum_expiry`,
    /// matching the same staleness check `quorum refresh` uses for its
    /// `--threshold-blocks` flag (just expressed in days for ergonomics).
    ///
    /// Default: `3` days. Tuning: shorter = tighter on-chain protection
    /// (less time spent in the post-expiry CLTV cascade window per the
    /// new tier design); longer = more headroom for offline cosigners
    /// to come back. Three days lets cosigners miss two cycles of a
    /// 24-hour cron and still come back before the cascade opens.
    pub rotate_before_expiry_days: u32,

    /// If `Some`, daemon registers with a deposits-hub control plane
    /// over gift-wrapped nostr DMs (see `crate::hub`). The pubkey is
    /// the hub's 32-byte x-only nostr identity; relays are where the
    /// hub listens. Both must be set for registration to fire.
    pub hub: Option<HubConfig>,
}

/// Daemon ↔ hub control-plane wiring.
#[derive(Debug, Clone)]
pub struct HubConfig {
    /// 32-byte x-only nostr pubkey of the hub.
    pub pubkey_hex: String,
    /// Relays the hub listens on (gift-wraps fan out across all).
    pub relays: Vec<String>,
}

/// Configuration for the daemon ↔ signer link.
#[derive(Debug, Clone)]
pub struct RemoteSignerConfig {
    /// Path to the signer's Unix socket.
    pub socket_path: PathBuf,
    /// Pinned signer transport pubkey (33-byte compressed). If the
    /// signer's `HelloAck` doesn't sign with this key, the daemon
    /// refuses to proceed.
    pub signer_pubkey: bitcoin::secp256k1::PublicKey,
}

/// Result of rotating reserves to quorum-based Taproot spending
#[derive(Debug, Clone)]
pub struct RotateReservesResult {
    /// The transaction ID of the rotation transaction
    pub txid: String,

    /// The new Taproot reserves address
    pub new_address: String,

    /// Amount in satoshis
    pub amount_sats: u64,

    /// Number of quorum members in the new output
    pub quorum_member_count: usize,

    /// Block height when first quorum member expires (operator-only unlock)
    pub quorum_expiry: u32,

    /// The ledger hash committed to in the new Taproot tree
    pub ledger_hash: [u8; 32],
}

/// Result of a co-sign request from a quorum member
#[derive(Debug, Clone)]
pub struct CoSignResult {
    /// The co-signer's ECDSA signature over (cosign_data || member_ledger_hash)
    pub cosign_signature: [u8; 64],

    /// The public key of the quorum member who co-signed
    pub cosigner_pubkey: PublicKey,

    /// The current hash of the quorum member's own ledger at time of signing
    /// This binds the co-signature to the member's ledger state
    pub member_ledger_hash: [u8; 32],

    /// Distributed tracing timestamps (microseconds since epoch)
    pub t1_recv_us: Option<u64>,
    pub t2_send_us: Option<u64>,
}

/// Collector for majority cosignatures.
/// Accumulates responses from quorum members until threshold is reached.
struct CosignCollector {
    threshold: usize,
    results: std::sync::Mutex<Vec<CoSignResult>>,
    seen_pubkeys: std::sync::Mutex<std::collections::HashSet<[u8; 33]>>,
    notify: tokio::sync::Notify,
}

impl CosignCollector {
    fn new(threshold: usize) -> Self {
        Self {
            threshold,
            results: std::sync::Mutex::new(Vec::new()),
            seen_pubkeys: std::sync::Mutex::new(std::collections::HashSet::new()),
            notify: tokio::sync::Notify::new(),
        }
    }

    /// Add a cosign result. Returns true if threshold is now met.
    fn add(&self, result: CoSignResult) -> bool {
        let pk_bytes = result.cosigner_pubkey.serialize();
        {
            let mut seen = self.seen_pubkeys.lock().unwrap();
            if !seen.insert(pk_bytes) {
                return false; // duplicate pubkey
            }
        }
        let count = {
            let mut results = self.results.lock().unwrap();
            results.push(result);
            results.len()
        };
        if count >= self.threshold {
            self.notify.notify_one();
            true
        } else {
            false
        }
    }

    /// Take collected results.
    fn take_results(&self) -> Vec<CoSignResult> {
        std::mem::take(&mut *self.results.lock().unwrap())
    }
}

/// Result of a consent request from a quorum member
#[derive(Debug, Clone)]
pub struct ConsentResult {
    /// The member's Schnorr signature over the consent content
    pub consent_signature: [u8; 64],
    /// Block height when the member's commitment expires
    pub membership_expires: u32,
    /// Canonical TLV-encoded `QuorumMemberResponse` returned by the
    /// member. Populated when the member supports the Q1 wire (current
    /// node releases). `None` from legacy members.
    pub member_response: Option<Vec<u8>>,
    /// BIP-340 signature by the member over
    /// `quorum_member_response_digest(member_response)`. Always `Some`
    /// when `member_response` is `Some`.
    pub member_signature: Option<[u8; 64]>,
}

/// Result of a deposit offer co-sign request from a quorum member
#[derive(Debug, Clone)]
pub struct OfferCoSignResult {
    /// The ECDSA signature over the offer signing data
    pub signature: [u8; 64],

    /// The public key of the quorum member who co-signed
    pub cosigner_pubkey: PublicKey,

    /// The current hash of the quorum member's own ledger at time of signing
    /// This binds the co-signature to the member's ledger state
    pub member_ledger_hash: [u8; 32],
}

/// One entry in `{data_dir}/buffer_indices.json` tracking a buffer
/// deposit the operator opened via `admin buffer open`. The index is
/// the BIP32 derivation index used for the deposit key (same path the
/// wallet uses), so admins can reconstruct the key from the mnemonic
/// they received at bootstrap.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BufferIndexEntry {
    pub index: u32,
    pub ledger_id: String,
    pub deposit_pubkey: String,
}

/// A pending Lightning invoice waiting for payment
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PendingInvoice {
    /// The ledger this invoice belongs to
    pub ledger_id: String,
    /// The deposit_id to credit
    pub deposit_id: DepositId,
    /// The descriptor for this deposit
    pub descriptor: String,
    /// Amount in millisatoshis
    pub amount_msat: u64,
    /// The bolt11 invoice string
    pub invoice: String,
    /// When the invoice was created
    pub created_at: u64,
    /// Payment hash (hex) — for persistence/lookup
    #[serde(default)]
    pub payment_hash_hex: String,
}

/// State for a non-blocking confiscation request awaiting co-signatures.
struct PendingConfiscation {
    /// Nostr event ID of our confiscation_sign request
    request_id: String,
    /// The unsigned confiscation transaction
    confiscation_tx: bitcoin::Transaction,
    /// Sighash bytes that all signers sign
    sighash_bytes: [u8; 32],
    /// Signatures collected so far (signer pubkey -> 64-byte Schnorr sig)
    signatures: std::collections::HashMap<bitcoin::secp256k1::PublicKey, [u8; 64]>,
    /// Number of signatures required
    required_sigs: usize,
    /// The VoterSet for building the witness
    voter_set: deposits_core::VoterSet,
    /// Tier index in threshold config for the control block
    tier_index: usize,
    /// The leaf script for the Taproot spend
    leaf_script: bitcoin::ScriptBuf,
    /// The TaprootReservesOutput (for control block)
    taproot_output: deposits_core::TaprootReservesOutput,
    /// Lottery address (for logging)
    lottery_address: String,
    /// Ledger prefix (for logging)
    ledger_prefix: String,
    /// When we sent the request (for timeout)
    created_at: std::time::Instant,
}

/// A deposits-node node
pub struct Node {
    /// Our node ID (secp256k1 pubkey)
    pub node_id: PublicKey,

    /// Pre-computed hex string of node_id (avoids repeated byte-by-byte formatting)
    node_id_hex: String,

    /// Shared secp256k1 context (expensive to create — ~1MB allocation + randomization)
    secp: Secp256k1<bitcoin::secp256k1::All>,

    /// The wallet for on-chain operations
    pub wallet: Arc<Wallet>,

    /// Nostr transport for peer messaging
    pub nostr: NostrTransport,

    /// The protocol handler
    pub handler: Arc<DepositsHandler>,

    /// Outbound message receiver (for async sending via nostr).
    /// Wrapped in Mutex so run loop can drain with &self.
    outbound_rx: Mutex<mpsc::UnboundedReceiver<OutboundMessage>>,

    /// Pending deposit offers indexed by offer_id
    deposit_offers: Mutex<HashMap<[u8; 32], (DepositOffer, DepositOfferStatus)>>,

    /// Pending withdrawals indexed by withdrawal_id
    withdrawals: Mutex<HashMap<[u8; 32], (OnChainWithdrawal, OnChainWithdrawalStatus)>>,

    /// Pending co-sign requests: request_id -> (ledger_id, oneshot sender for co-sign result)
    /// The result includes the co-signer's signature and the member's ledger hash
    pending_cosign_requests: Arc<Mutex<HashMap<String, (String, Arc<CosignCollector>)>>>,

    /// Pending consent requests: request_id -> oneshot sender for consent result
    /// Used by quorum_add to await the member's consent signature
    pending_consent_requests:
        Arc<Mutex<HashMap<String, tokio::sync::oneshot::Sender<ConsentResult>>>>,

    /// Per-ledger staging lock. Only one update can be in-flight at a time per ledger.
    /// Prevents concurrent state mutations and ensures cosign requests are serialized.
    staging_locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,

    /// Ledger ids whose `auto_quorum_refresh` is currently rotating. The
    /// rotation flow can take ~1–10 minutes (cosign collection + wait
    /// for confirmation + QuorumBegin cosign), which is much longer
    /// than the 10s periodic-task timeout. We detach the work as a
    /// background task and use this set to guard against re-launching
    /// while the prior rotation is still in flight.
    pub(crate) rotating_ledgers: Arc<Mutex<std::collections::HashSet<String>>>,

    /// Semaphore to limit concurrent request_cosign calls.
    /// Multiple concurrent mini loops compete for shared channels (response_rx,
    /// ledger_rx) and can deadlock when all operators are in batch-await simultaneously.
    /// Serializing cosign requests prevents this while still allowing concurrent
    /// processing of non-cosign requests (cosign_update, quorum_join, etc.).
    cosign_semaphore: Arc<tokio::sync::Semaphore>,

    /// Apply-edge wakeup for dispute confiscation. A per-ledger
    /// actor signals this Notify when it observes a fork-branch
    /// `DisputeArmed`; main_loop's periodic block awaits on it so
    /// it wakes immediately instead of after the next
    /// `periodic_interval` tick.
    pub(crate) dispute_wakeup: Arc<tokio::sync::Notify>,

    /// Pending Lightning invoices: payment_hash -> (ledger_id, deposit_pubkey, amount_msat)
    /// Used to credit deposits when payments are received
    pending_invoices: Arc<Mutex<HashMap<[u8; 32], PendingInvoice>>>,

    /// Processed request event IDs (to avoid duplicate processing from polling).
    /// Two-generation design: on periodic cleanup, current is swapped to prev.
    /// Lookups check both; inserts go to current. This caps memory at ~2 periods
    /// while never losing entries within the last period (preventing re-processing
    /// of transfer_lock/transfer_complete which consume one-time nonces).
    processed_requests: Mutex<std::collections::HashSet<String>>,
    processed_requests_prev: Mutex<std::collections::HashSet<String>>,

    /// Event IDs of requests sent by THIS daemon process.
    /// Used to filter out our own requests (Nostr broadcasts to all subscribers).
    /// Two-generation design (same as processed_requests): current + prev.
    sent_events: Mutex<std::collections::HashSet<String>>,
    sent_events_prev: Mutex<std::collections::HashSet<String>>,

    /// Ledger IDs for which we've published (or observed on the relay
    /// that we previously published) a lottery_reveal request. Used as
    /// the publish-idempotency gate for `auto_reveal_preimage` and as
    /// the "ready to claim/yield" signal for `auto_lottery_claim_or_yield`.
    ///
    /// Replaces the on-disk `lottery_revealed_<prefix>.marker` files;
    /// the durable backing store is the kind:9100 reveal request on
    /// the relay, queried on first access per ledger after restart.
    pub(crate) revealed_ledgers: Mutex<std::collections::HashSet<String>>,
    /// A `stand_down_reestablished_expiry_disputes` run is in flight.
    pub(crate) expiry_stand_down_running: std::sync::atomic::AtomicBool,

    /// Last-broadcast timestamp per `(ledger_id, from_seq)` rolled-back
    /// resync range. The relay's pub/sub fans a single broadcast out
    /// to every subscribed peer, so if multiple peers ask us to
    /// resync the same range within a few seconds (a common pattern
    /// when several quorum members come back online at once), only
    /// the first request needs to do work. Subsequent requests inside
    /// the cooldown return success without re-broadcasting.
    pub(crate) resync_last_broadcast: Mutex<HashMap<(String, u64), std::time::Instant>>,

    /// Active per-ledger request processing tasks.
    /// Only one task runs per ledger at a time to maintain hash-chain serialization.
    /// The main loop checks for completion and spawns new tasks without blocking.
    active_ledger_tasks: Mutex<HashMap<String, tokio::task::JoinHandle<(String, usize, usize)>>>,

    /// Persistent per-ledger worker channels. Each owned ledger gets a dedicated
    /// mpsc channel. The main loop routes requests to the channel. A persistent
    /// tokio task reads and processes requests one at a time — no spawn/reap gaps.
    ledger_workers:
        Mutex<HashMap<String, tokio::sync::mpsc::UnboundedSender<crate::nostr::LedgerRequest>>>,

    /// Persistent per-ledger workers for cosign requests (where we're a quorum member).
    /// Separate from ledger_workers so cosign request processing never blocks the main
    /// loop — the main loop must stay free to pump process_events + drain_responses so
    /// our OWN cosign responses get routed to oneshot channels.
    cosign_workers:
        Mutex<HashMap<String, tokio::sync::mpsc::UnboundedSender<crate::nostr::LedgerRequest>>>,

    /// Per-ledger actor handles, keyed by ledger_id. Each actor owns
    /// the apply path for its ledger via a shared
    /// `Arc<RwLock<Ledger>>` it co-owns with `handler.ledgers`.
    /// Inbound updates and operator-driven commits flow into the
    /// actor's inbox; the actor emits broadcast / cosig requests /
    /// dispute-pipeline wakeups via the shared outbox.
    pub(crate) ledger_actors: Mutex<HashMap<String, ledger_actor::LedgerActorHandle>>,

    /// Outbox sender shared with every actor in the pool. Held on
    /// `Node` so ledgers created post-startup (via `ledger open`,
    /// `import_ledger`, or inbound discovery) can lazy-spawn an
    /// actor without restarting the daemon. The matching receiver
    /// is parked in `actor_outbox_rx` until `run()` takes it.
    pub(crate) actor_outbox_tx:
        tokio::sync::mpsc::UnboundedSender<(String, ledger_actor::LedgerOutbound)>,

    /// Parked receiver for the actor outbox. `Node::new` doesn't
    /// spawn the drainer itself — the drainer needs `Arc<Node>` for
    /// `request_cosign` / `broadcast_ledger_update` callbacks that
    /// don't exist until `Self` is constructed. The rx is parked
    /// here and `main_loop.rs::run` takes it (with
    /// `Arc::clone(self)` in scope) and spawns the drainer there.
    /// Wrapped in `Option` so `take()` consumes it on first run; a
    /// second call to `run()` would find `None` and skip spawning.
    pub(crate) actor_outbox_rx:
        Mutex<Option<tokio::sync::mpsc::UnboundedReceiver<(String, ledger_actor::LedgerOutbound)>>>,

    /// Whether deposit access control is enabled (DEPOSIT_ACCESS_CONTROL=true).
    /// When false, all deposit opens are allowed (denylist still checked).
    deposit_access_control: bool,

    /// Allowlist of npubs (hex) that can open deposits.
    /// Loaded from {data_dir}/deposit_allowlist.txt.
    deposit_allowlist: RwLock<std::collections::HashSet<String>>,

    /// Denylist of npubs (hex). Checked even when access control is off.
    /// Loaded from {data_dir}/deposit_denylist.txt.
    deposit_denylist: RwLock<std::collections::HashSet<String>>,

    /// Allowlist of lightning address domains. If an npub isn't in the
    /// explicit allowlist, we check for a lightning-verify attestation (kind 55502)
    /// and allow if the attested domain is in this list.
    /// Loaded from {data_dir}/deposit_domain_allowlist.txt.
    deposit_domain_allowlist: RwLock<std::collections::HashSet<String>>,

    /// Pubkey (hex) of the lightning-verify service whose attestations we trust.
    /// Loaded from ATTESTATION_VERIFIER_PUBKEY env var. Empty = attestation check disabled.
    attestation_verifier_pubkey: Option<String>,

    /// Maximum balance any single deposit can hold (msats). 0 = unlimited.
    /// Loaded from MAX_DEPOSIT_BALANCE_MSATS env var.
    max_deposit_balance_msats: u64,

    /// Operator display name from `--name` / `NODE_NAME`. Surfaced on
    /// the ledger advertisement so wallets / explorer label this
    /// operator with something more readable than the hex pubkey.
    operator_name: Option<String>,

    /// Data directory for persistence
    data_dir: PathBuf,

    /// Primary relay URL for Nostr
    relay_url: String,

    /// Use fast polling intervals (for regtest/testing)
    fast_poll: bool,

    /// Auto-rotate threshold (days). The periodic `auto_quorum_refresh`
    /// task triggers when `current_block + rotate_before_expiry_days × 144
    /// ≥ quorum_expiry`. Mirror of `NodeConfig::rotate_before_expiry_days`.
    pub rotate_before_expiry_days: u32,

    /// Cached joined ledger IDs (from QuorumJoin history scan).
    /// Self-validates by checking history lengths — only rescans when history grows.
    joined_ledger_cache: Mutex<Option<Vec<String>>>,
    /// History lengths at last cache fill. Used to detect when rescan is needed
    /// without doing the full O(history_len) scan every cycle.
    joined_ledger_cache_versions: Mutex<HashMap<String, usize>>,

    /// Joined ledger IDs that have been imported from Nostr (or attempted).
    /// Prevents re-importing on every reload cycle.
    imported_joined_ledgers: Mutex<std::collections::HashSet<String>>,

    /// Pending confiscation requests awaiting co-signatures from quorum members.
    /// Key is the ledger prefix (from custody_armed marker).
    pending_confiscations: Mutex<HashMap<String, PendingConfiscation>>,

    /// Pending `lottery_recovery_sign` requests for unclaimable lotteries,
    /// keyed by ledger id (see `lottery_recovery`).
    pending_lottery_recoveries:
        Mutex<HashMap<String, lottery_recovery::PendingLotteryRecovery>>,

    /// Joined ledger IDs detected as stale during cosign requests.
    /// Drained and re-imported in the run loop to avoid blocking request handlers.
    stale_joined_ledgers: Mutex<std::collections::HashSet<String>>,

    /// Our dispute forks whose own updates did not all reach the relay;
    /// retried every periodic (see `fork_publish`).
    pending_fork_publications: Mutex<std::collections::HashSet<String>>,

    /// Rate-limiter for background relay fetches of stale joined ledgers.
    /// Tracks when each ledger was last fetched from relay (30s cooldown per ledger).
    last_relay_fetch_times: Mutex<HashMap<String, std::time::Instant>>,

    /// Cache mapping target_ledger_id → our member ledger key (in the ledgers HashMap).
    /// Populated on first cosign request per target, invalidated with joined_ledger_cache.
    /// Eliminates the O(N) full history TLV-decode scan in process_cosign_request.
    cosign_member_cache: Mutex<HashMap<String, String>>,

    /// Ledger IDs that have been modified but not yet persisted to disk.
    /// Flushed at the end of each request drain batch to reduce write syscalls.
    dirty_ledgers: Mutex<std::collections::HashSet<String>>,

    /// Cache for is_operator_of_ledger: ledger_id → (result, history_len_when_scanned).
    /// Once true (operator found), the result is permanent.
    /// For false results, we rescan when history grows.
    operator_of_cache: Mutex<HashMap<String, (bool, usize)>>,

    /// Admin identity authorized to send admin-class requests (gift-wrapped
    /// Kind 20101) alongside our own operator key. Set at bootstrap and
    /// persisted in {data_dir}/admin.npub (32-byte x-only hex).
    pub admin_pubkey: Option<nostr_sdk::PublicKey>,

    /// Per-ledger BDK wallets. Each ledger has its own UTXO set so a
    /// `quorum begin` activation tx draws inputs only from the
    /// ledger's own funded outputs — no shared pool, no race across
    /// ledgers. Lazy-created at `ledger open` time and reloaded from
    /// `<data_dir>/wallet/ledgers/<ledger_id>/` at startup.
    pub(crate) ledger_wallets:
        Arc<RwLock<HashMap<String, Arc<crate::ledger_wallet::LedgerWallet>>>>,

    /// Next BIP-32 account index to assign to a fresh ledger wallet.
    /// Initialized to (max existing on disk) + 1 at startup, then
    /// incremented per `ensure_ledger_wallet` call.
    pub(crate) next_ledger_account: Mutex<u32>,

    /// Esplora endpoint for chain sync, retained so per-ledger wallets
    /// can build their own clients. Comes from `NodeConfig::electrum_url`.
    pub(crate) electrum_url: String,
}

impl Node {
    /// Clock-skew buffer (seconds) when computing `since` for relay fetches.
    const RELAY_FETCH_CLOCK_SKEW_SECS: u64 = 30;
    /// Events requested per relay page during joined-ledger reimport.
    const RELAY_FETCH_PAGE_LIMIT: usize = 5000;
    /// Stop paginating if a page returns fewer than this many events.
    const RELAY_FETCH_MIN_PAGE: usize = 1000;
    /// Maximum pages before giving up (safety cap).
    const RELAY_FETCH_MAX_PAGES: u32 = 50;
    /// Per-ledger cooldown between background relay fetches.
    const RELAY_FETCH_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(30);
    /// Maximum updates re-broadcast per resync request.
    const RESYNC_BATCH_CAP: usize = 500;
}

pub mod auto_tasks;
pub mod coordination;
pub mod dispute;
pub mod expiry_watch;
pub mod fork_publish;
pub mod heal;
pub mod inbound;
pub mod init;
pub mod ledger_actor;
pub mod ledger_queries;
pub mod ledger_repair;
pub mod lottery_recovery;
pub mod main_loop;
pub mod operations;
pub mod replacement_collateral;
pub mod request_handlers;
