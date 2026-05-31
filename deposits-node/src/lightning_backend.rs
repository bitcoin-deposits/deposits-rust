//! Pluggable Lightning backend.
//!
//! Today's `deposits-node` calls `ldk-server-cli` directly from `ldk_backend.rs`,
//! which means the audience of operators who run LND or CLN (or any non-LDK
//! Lightning daemon) can't install us. This module is the structural fix:
//! a trait that captures every Lightning operation the daemon currently
//! performs, with implementations swappable at runtime via config.
//!
//! Per [PACKAGING_PLAN.md](../../PACKAGING_PLAN.md) Tier 1: the trait
//! lands first, [`crate::ldk_backend::LdkBackend`] becomes the first impl, then
//! `LndBackend` / `ClnBackend` follow as separate commits without touching
//! the trait surface.
//!
//! ## Why neutral types
//!
//! The response types live here, not on each impl. LDK's JSON shape has
//! anchor-channel reserve fields that LND doesn't compute and CLN reports
//! differently; if the trait surfaced LDK's response structs directly, the
//! other backends would have to fabricate values to satisfy the type, and
//! every caller would silently inherit LDK-specific semantics. The neutral
//! types here are the intersection of what the backends actually agree on
//! plus what daemon callers actually consume.
//!
//! Backend-specific extras (e.g. LDK's anchor reserve, LND's channel-policy
//! routing fees) can land later as either separate trait methods or as a
//! `backend_specific: serde_json::Value` escape hatch — neither is needed
//! by anything in the daemon today.
//!
//! ## Sync vs async
//!
//! Every method is synchronous because every current caller is synchronous;
//! `ldk_backend.rs` blocks on a subprocess. When a future async-native backend
//! lands (e.g. an LND gRPC client), it either blocks on its own tokio
//! runtime (the [`crate::remote_signer::RemoteSigner`] pattern) or this
//! trait grows an async variant. Today async would be premature.

use crate::Error;

/// Lightning backend the daemon talks to for invoice / payment ops. See module
/// docs for design rationale and the path to LND / CLN impls.
pub trait LightningBackend: Send + Sync {
    /// Identity and chain-tip view of the underlying node.
    fn get_node_info(&self) -> Result<NodeInfo, Error>;

    /// On-chain + lightning balances. Used by operator CLI status pages
    /// and the future web admin UI; not on the protocol hot path.
    fn get_balances(&self) -> Result<Balances, Error>;

    /// Create a fixed-amount BOLT11 invoice with a plain-text description.
    /// Returns the bech32-encoded invoice string.
    fn create_invoice(&self, amount_msat: u64, description: &str) -> Result<String, Error>;

    /// Create a fixed-amount BOLT11 invoice committing to a 32-byte
    /// description hash instead of a plaintext description. Required by
    /// NIP-57 zaps — the wallet sha256s the zap-request JSON and expects
    /// the invoice's `h` field to match exactly so the payment can be tied
    /// back to the zap request.
    fn create_invoice_with_desc_hash(
        &self,
        amount_msat: u64,
        desc_hash_hex: &str,
    ) -> Result<String, Error>;

    /// Create a variable-amount BOLT11 invoice (payer chooses amount).
    fn create_invoice_any_amount(&self, description: &str) -> Result<String, Error>;

    /// Pay a fixed-amount BOLT11 invoice. Returns the backend's payment_id
    /// (typically the payment_hash in hex).
    fn pay_invoice(&self, invoice: &str) -> Result<String, Error>;

    /// Pay a variable-amount BOLT11 invoice with the given amount.
    fn pay_invoice_with_amount(
        &self,
        invoice: &str,
        amount_msat: u64,
    ) -> Result<String, Error>;

    /// Currently-open channels. Used for status display and quorum sanity
    /// checks; not on the protocol hot path.
    fn list_channels(&self) -> Result<Vec<ChannelInfo>, Error>;

    /// All recent payments (inbound + outbound where the backend exposes
    /// both). Used by the auto-settle loop to discover paid invoices and
    /// by status display. Hot path on a busy daemon.
    fn list_payments(&self) -> Result<Vec<PaymentInfo>, Error>;

    /// Look up a specific payment by id and return its BOLT11 preimage if
    /// the backend has one. Used on the self-pay path: when an operator
    /// settles an invoice internally (no Lightning hop), they still need
    /// the preimage to commit a real proof-of-payment in `InvoiceFulfill`.
    /// Returns `Ok(None)` for unknown ids or payments with no preimage
    /// (in-flight, failed, BOLT12, on-chain, etc.).
    fn get_payment_preimage(
        &self,
        payment_id_hex: &str,
    ) -> Result<Option<[u8; 32]>, Error>;
}

#[derive(Debug, Clone)]
pub struct NodeInfo {
    /// 33-byte compressed pubkey of the Lightning node, hex-encoded.
    pub node_id: String,
    /// Best block height the backend has seen. `None` if the backend's
    /// chain view isn't synchronized or doesn't expose this.
    pub current_best_block_height: Option<u32>,
    /// Best block hash the backend has seen, hex-encoded. Pairs with
    /// `current_best_block_height`.
    pub current_best_block_hash: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Balances {
    /// Total on-chain bitcoin under the backend's control, sats. Includes
    /// confirmed UTXOs that are reserved (anchor commitments, in-flight tx
    /// outputs, etc.).
    pub onchain_total_sats: u64,
    /// On-chain bitcoin freely spendable right now — excludes anchor
    /// reserves, in-flight outputs, and anything otherwise pinned.
    pub onchain_spendable_sats: u64,
    /// Sum of all channel balances available for routing/sending, sats.
    pub lightning_total_sats: u64,
}

#[derive(Debug, Clone)]
pub struct ChannelInfo {
    /// Funding-txid-based channel id, hex-encoded.
    pub channel_id: String,
    /// Peer's node pubkey, hex-encoded.
    pub counterparty_node_id: String,
    /// Total channel value (funding amount), sats.
    pub capacity_sats: u64,
    /// Amount sendable from this side, msat.
    pub outbound_capacity_msat: u64,
    /// Amount receivable on this side, msat.
    pub inbound_capacity_msat: u64,
    /// True iff the channel is usable for routing right now (confirmed,
    /// peer reachable, not in dispute).
    pub is_usable: bool,
    /// True iff the channel is opened (funding confirmed) — broader than
    /// `is_usable`; a ready channel may not currently route if the peer
    /// is offline.
    pub is_ready: bool,
}

#[derive(Debug, Clone)]
pub struct PaymentInfo {
    /// Backend-assigned payment id. By convention the BOLT11 payment_hash
    /// in hex, but treated as an opaque string by the trait.
    pub id: String,
    /// Lifecycle stage.
    pub status: PaymentStatus,
    /// Amount of the payment, msat. `None` for amountless invoices that
    /// haven't been paid yet.
    pub amount_msat: Option<u64>,
    /// Preimage hex if the backend has surfaced one. May be `None` even
    /// for succeeded payments — depends on the backend's data model.
    pub preimage_hex: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaymentStatus {
    Pending,
    Succeeded,
    Failed,
}

/// Build the [`LightningBackend`] selected at runtime via environment.
///
/// `LIGHTNING_BACKEND` selects the impl. Today only `ldk` is implemented;
/// `lnd` and `cln` are added in follow-on commits. Defaulting to `ldk`
/// keeps existing deployments working without any env changes.
///
/// Reads per-backend config from env too — the LDK backend uses
/// `LDK_CLI`, `LDK_HOST`, `LDK_PORT`, `LDK_API_KEY` (see
/// [`crate::ldk_backend::LdkBackendConfig::from_env`]).
pub fn from_env() -> Box<dyn LightningBackend> {
    match std::env::var("LIGHTNING_BACKEND")
        .ok()
        .as_deref()
        .unwrap_or("ldk")
    {
        "ldk" => Box::new(crate::ldk_backend::LdkBackend::from_env()),
        other => panic!(
            "LIGHTNING_BACKEND={:?} not implemented. Supported: \"ldk\" \
             (lnd / cln land in follow-on commits per PACKAGING_PLAN.md Tier 1a).",
            other
        ),
    }
}
