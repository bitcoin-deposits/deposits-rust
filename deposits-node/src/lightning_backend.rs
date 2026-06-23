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

    /// Pay a fixed-amount BOLT11 invoice, capping total routing fees at
    /// `max_fee_msat` and (when `Some`) the total route CLTV at
    /// `max_cltv_blocks`. The fee cap is the depositor's signed
    /// `InvoiceLock.fee` budget, so the operator never spends more routing than
    /// funded. The CLTV cap bounds how long an in-flight HTLC can live, which
    /// must match the deposit's fund-lock timeout so timing the lock out is
    /// safe (no HTLC can still settle past it). A route exceeding either cap
    /// fails the payment → InvoiceFail → depositor refunded. Default impl
    /// ignores both and falls back to `pay_invoice` for backends that don't
    /// expose these limits yet (lnd/cln).
    fn pay_invoice_with_fee_cap(
        &self,
        invoice: &str,
        _max_fee_msat: u64,
        _max_cltv_blocks: Option<u32>,
    ) -> Result<String, Error> {
        self.pay_invoice(invoice)
    }

    /// Estimate the LN routing fee (msats) to pay this BOLT-11, WITHOUT sending.
    /// Powers the `quote_invoice` pre-flight (DEP-10 §Pay) so the wallet funds a
    /// realistic `InvoiceLock.fee` instead of a blind guess. Backends estimate
    /// natively where they can (LND `routerrpc.estimateroutefee`, CLN
    /// `getroute`, LDK via the sidecar's route-estimate endpoint). The default
    /// returns `Unsupported` so the quote handler falls back to its bps
    /// heuristic — the routing cap still bounds the actual spend either way.
    fn estimate_routing_fee(&self, _invoice: &str) -> Result<u64, Error> {
        Err(Error::Protocol(
            "routing-fee estimation not implemented for this backend".to_string(),
        ))
    }

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

    // ── Hold invoices (Lightning bridge — DEP-10 §Receive) ─────────────────
    //
    // A hold invoice is a BOLT-11 for an EXTERNALLY-supplied payment hash:
    // the node doesn't know the preimage, so arriving HTLCs are parked
    // ("accepted") rather than settled, until the caller either settles with
    // the preimage or cancels and releases the HTLCs back to the payer.
    //
    // This is the LN-side half of the HTLC bridge: the wallet holds the
    // preimage, the bridge issues the hold invoice, the on-ledger reveal is
    // what unlocks the upstream settlement. Backend support varies — see
    // `supports_hold_invoices` — and a bridge daemon MUST consult the probe
    // before advertising `invoice_receive` (bridge-pay needs none of this
    // and works on every backend).

    /// Whether this backend can do hold invoices.
    ///
    /// - LND: `true` — native `invoicesrpc` support, in stock release builds.
    /// - LDK: `true` against an ldk-server built with the hold-invoice
    ///   commands; `false` against an older sidecar (probe at construction).
    /// - CLN: `true` iff the `holdinvoice` plugin is loaded
    ///   (github.com/daywalker90/holdinvoice); core CLN has no hold support.
    fn supports_hold_invoices(&self) -> bool {
        false
    }

    /// Create a BOLT-11 invoice for an externally-supplied payment hash.
    /// HTLCs paying it are held unsettled until [`Self::settle_hold_invoice`]
    /// or [`Self::cancel_hold_invoice`]. Returns the bech32 invoice string.
    ///
    /// `expiry_secs` is the BOLT-11 invoice expiry (how long the payer has
    /// to start paying) — NOT the HTLC hold window, which is governed by the
    /// HTLC's own CLTV and surfaced via [`Self::lookup_hold_invoice`].
    ///
    /// `cltv_expiry_delta` REQUESTS a hold window (the invoice's
    /// `min_final_cltv_expiry_delta`). Backend support varies — LND honors
    /// it, CLN's hold-plugin RPC and LDK's `receive_for_hash` ignore it —
    /// so the bridge MUST still treat the window as measured, not assumed:
    /// read the actual expiry from [`Self::lookup_hold_invoice`]'s
    /// `Accepted::htlc_expiry_height` after HTLCs park (DEP-10 §"Hold
    /// windows"). Keep requests ≤ ~288: payer wallets cap total route CLTV
    /// (CLN's `pay` maxdelay defaults to 2016 across the whole route) and
    /// refuse invoices demanding extreme final deltas.
    fn create_hold_invoice(
        &self,
        _amount_msat: u64,
        _payment_hash_hex: &str,
        _description: &str,
        _expiry_secs: u32,
        _cltv_expiry_delta: Option<u16>,
    ) -> Result<String, Error> {
        Err(Error::Protocol(
            "hold invoices not supported by this Lightning backend".to_string(),
        ))
    }

    /// Current state of a hold invoice previously created with
    /// [`Self::create_hold_invoice`], keyed by its payment hash.
    ///
    /// `Accepted` is the bridge's gate: HTLCs are parked, and
    /// `htlc_expiry_height` (when the backend surfaces it) is the earliest
    /// CLTV among the held HTLCs — the bridge derives its on-ledger
    /// `TransferLock.timeout_height` from this, minus the safety margin Δ.
    fn lookup_hold_invoice(
        &self,
        _payment_hash_hex: &str,
    ) -> Result<HoldInvoiceState, Error> {
        Err(Error::Protocol(
            "hold invoices not supported by this Lightning backend".to_string(),
        ))
    }

    /// Settle the held HTLCs with the preimage (learned from the on-ledger
    /// `TransferComplete` reveal). Idempotent on already-settled invoices
    /// where the backend allows it; otherwise returns the backend's error.
    fn settle_hold_invoice(&self, _preimage_hex: &str) -> Result<(), Error> {
        Err(Error::Protocol(
            "hold invoices not supported by this Lightning backend".to_string(),
        ))
    }

    /// Cancel the hold invoice and release any held HTLCs back to the payer
    /// (used when the on-ledger lock timed out without a reveal).
    fn cancel_hold_invoice(&self, _payment_hash_hex: &str) -> Result<(), Error> {
        Err(Error::Protocol(
            "hold invoices not supported by this Lightning backend".to_string(),
        ))
    }
}

/// Lifecycle of a hold invoice. The bridge's receive loop polls
/// [`LightningBackend::lookup_hold_invoice`] and acts on transitions:
/// `Open → Accepted` triggers the on-ledger `TransferLock`;
/// ledger reveal triggers settle; ledger timeout triggers cancel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HoldInvoiceState {
    /// Invoice issued; no HTLCs have arrived yet.
    Open,
    /// HTLC(s) arrived and are being held unsettled. Safe to lock on-ledger.
    Accepted {
        /// Earliest CLTV expiry height among the held HTLCs, when the
        /// backend surfaces it (LND: `htlcs[].expiry_height`; LDK:
        /// `claim_deadline`). `None` means the backend accepted but didn't
        /// report a height — the bridge MUST then derive a conservative
        /// bound from the BOLT-11's `min_final_cltv_expiry` + chain tip.
        htlc_expiry_height: Option<u32>,
    },
    /// Preimage was provided; HTLCs settled; upstream funds claimed.
    Settled,
    /// Invoice canceled; held HTLCs released back to the payer.
    Canceled,
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
/// `LIGHTNING_BACKEND` selects the impl. Defaults to `ldk` so existing
/// deployments keep working without any env changes.
///
/// Per-backend config also comes from env:
/// - `ldk` — `LDK_CLI`, `LDK_HOST`, `LDK_PORT`, `LDK_API_KEY` (see
///   [`crate::ldk_backend::LdkBackendConfig::from_env`])
/// - `lnd` — `LND_REST_URL`, `LND_MACAROON_HEX` or `LND_MACAROON_FILE`,
///   `LND_TLS_CERT_FILE`, `LND_TLS_INSECURE` (see
///   [`crate::lnd_backend::LndBackend::from_env`])
/// - `cln` — `CLN_SOCKET_PATH` (see
///   [`crate::cln_backend::ClnBackend::from_env`])
///
/// Construction errors (missing macaroon, unreadable socket, etc.) panic
/// — these are startup-time misconfiguration the operator needs to see
/// immediately, not runtime errors callers should try to recover from.
pub fn from_env() -> Box<dyn LightningBackend> {
    match std::env::var("LIGHTNING_BACKEND")
        .ok()
        .as_deref()
        .unwrap_or("ldk")
    {
        "ldk" => Box::new(crate::ldk_backend::LdkBackend::from_env()),
        "lnd" => Box::new(
            crate::lnd_backend::LndBackend::from_env()
                .unwrap_or_else(|e| panic!("LND backend init failed: {}", e)),
        ),
        "cln" => Box::new(
            crate::cln_backend::ClnBackend::from_env()
                .unwrap_or_else(|e| panic!("CLN backend init failed: {}", e)),
        ),
        other => panic!(
            "LIGHTNING_BACKEND={:?} not supported. Supported: \"ldk\", \"lnd\", \"cln\".",
            other
        ),
    }
}
