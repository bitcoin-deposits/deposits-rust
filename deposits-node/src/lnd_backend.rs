//! [`LightningBackend`] impl talking to LND via its REST API.
//!
//! Per PACKAGING_PLAN.md Tier 1a. LND's gRPC interface is the recommended
//! one upstream, but REST is sufficient for everything the trait needs and
//! avoids dragging tonic + lnrpc generated bindings into deposits-node.
//!
//! ## Authentication
//!
//! LND's REST API uses:
//! - **TLS**: self-signed cert at `~/.lnd/tls.cert` (configurable). Standard
//!   browser CAs don't sign it, so we feed it to rustls explicitly via
//!   `LND_TLS_CERT_FILE` (path) or skip with `LND_TLS_INSECURE=1` (don't, in
//!   production).
//! - **Macaroon**: bearer token sent as the `Grpc-Metadata-Macaroon` header,
//!   hex-encoded. `LND_MACAROON_HEX` (inline) or `LND_MACAROON_FILE` (path to
//!   binary macaroon file, we hex-encode it). The default admin macaroon at
//!   `~/.lnd/data/chain/bitcoin/mainnet/admin.macaroon` grants every permission
//!   we use; for production, scope to invoice + onchain via `lncli bakemacaroon`.
//!
//! ## Why REST and not gRPC
//!
//! - reqwest is already in deposits-node's dep tree (esplora) — zero new deps.
//! - LND's REST gateway is a thin wrapper over the same gRPC services; behaviour
//!   is identical for the methods we call.
//! - gRPC would mean adding tonic + prost + ~10MB of generated lnrpc code. Not
//!   worth it for ten thin method bindings.
//! - When/if we need streaming (e.g. SubscribeInvoices instead of polling
//!   ListInvoices), gRPC's bidi streams are nicer, but the trait's surface is
//!   request/response — never streaming — so REST is a clean fit.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

use crate::lightning_backend::{
    Balances, ChannelInfo, HoldInvoiceState, LightningBackend, NodeInfo, PaymentInfo,
    PaymentStatus,
};
use crate::Error;

/// LND backend. Selection: `LIGHTNING_BACKEND=lnd`.
pub struct LndBackend {
    /// Base REST URL, e.g. `https://127.0.0.1:8080`.
    base_url: String,
    /// Macaroon hex for the `Grpc-Metadata-Macaroon` header.
    macaroon_hex: String,
    /// Reused blocking client with the TLS cert configured.
    client: reqwest::blocking::Client,
}

impl LndBackend {
    /// Build from explicit config. See [`Self::from_env`] for env-driven
    /// construction.
    pub fn new(
        base_url: impl Into<String>,
        macaroon_hex: impl Into<String>,
        tls_cert_pem: Option<&[u8]>,
        insecure: bool,
    ) -> Result<Self, Error> {
        let mut builder = reqwest::blocking::Client::builder().timeout(Duration::from_secs(30));
        if insecure {
            builder = builder.danger_accept_invalid_certs(true);
        } else if let Some(pem) = tls_cert_pem {
            let cert = reqwest::Certificate::from_pem(pem)
                .map_err(|e| Error::Wallet(format!("LND TLS cert parse: {}", e)))?;
            builder = builder.add_root_certificate(cert);
        }
        let client = builder
            .build()
            .map_err(|e| Error::Wallet(format!("build LND http client: {}", e)))?;
        Ok(Self {
            base_url: base_url.into(),
            macaroon_hex: macaroon_hex.into(),
            client,
        })
    }

    /// Build from environment:
    /// - `LND_REST_URL`        (default `https://127.0.0.1:8080`)
    /// - `LND_MACAROON_HEX`    (preferred for non-file deployments)
    /// - `LND_MACAROON_FILE`   (binary macaroon file, hex-encoded on load)
    /// - `LND_TLS_CERT_FILE`   (PEM path; omit if you trust the default chain)
    /// - `LND_TLS_INSECURE=1`  (skip TLS verification; dev only)
    pub fn from_env() -> Result<Self, Error> {
        let base_url = std::env::var("LND_REST_URL")
            .unwrap_or_else(|_| "https://127.0.0.1:8080".to_string());

        let macaroon_hex = match std::env::var("LND_MACAROON_HEX") {
            Ok(h) => h,
            Err(_) => {
                let path = std::env::var("LND_MACAROON_FILE").map_err(|_| {
                    Error::Wallet(
                        "LND backend selected but neither LND_MACAROON_HEX nor \
                         LND_MACAROON_FILE is set"
                            .to_string(),
                    )
                })?;
                let bytes = std::fs::read(&path).map_err(|e| {
                    Error::Wallet(format!("read LND_MACAROON_FILE={}: {}", path, e))
                })?;
                hex::encode(bytes)
            }
        };

        let tls_cert_pem = match std::env::var("LND_TLS_CERT_FILE") {
            Ok(path) => Some(std::fs::read(&path).map_err(|e| {
                Error::Wallet(format!("read LND_TLS_CERT_FILE={}: {}", path, e))
            })?),
            Err(_) => None,
        };
        let insecure = std::env::var("LND_TLS_INSECURE").is_ok();

        Self::new(base_url, macaroon_hex, tls_cert_pem.as_deref(), insecure)
    }

    fn get<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T, Error> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .client
            .get(&url)
            .header("Grpc-Metadata-Macaroon", &self.macaroon_hex)
            .send()
            .map_err(|e| Error::Wallet(format!("LND GET {}: {}", url, e)))?;
        check_status(&url, resp)?.json().map_err(|e| {
            Error::Wallet(format!("LND parse response from {}: {}", url, e))
        })
    }

    fn post<B: Serialize, T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, Error> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .client
            .post(&url)
            .header("Grpc-Metadata-Macaroon", &self.macaroon_hex)
            .json(body)
            .send()
            .map_err(|e| Error::Wallet(format!("LND POST {}: {}", url, e)))?;
        check_status(&url, resp)?.json().map_err(|e| {
            Error::Wallet(format!("LND parse response from {}: {}", url, e))
        })
    }

    /// LND identifies invoices by `payment_addr`-less r_hash (the payment_hash
    /// in hex). Our trait's `payment_id` carries that same hex.
    fn lookup_invoice(&self, r_hash_hex: &str) -> Result<Option<LndInvoice>, Error> {
        // The /v1/invoice/{r_hash} path parameter is HEX — verified live
        // against LND v0.19 (URL-safe base64 here returns 500
        // "encoding/hex: invalid byte"). Validate the hex before
        // interpolating into the URL.
        hex::decode(r_hash_hex)
            .map_err(|e| Error::Wallet(format!("LND r_hash hex decode: {}", e)))?;
        let url = format!("/v1/invoice/{}", r_hash_hex);
        // 404 → None; other non-2xx errors propagate.
        let full_url = format!("{}{}", self.base_url, url);
        let resp = self
            .client
            .get(&full_url)
            .header("Grpc-Metadata-Macaroon", &self.macaroon_hex)
            .send()
            .map_err(|e| Error::Wallet(format!("LND GET {}: {}", full_url, e)))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        Ok(Some(check_status(&full_url, resp)?.json().map_err(|e| {
            Error::Wallet(format!("LND parse invoice from {}: {}", full_url, e))
        })?))
    }
}

fn check_status(
    url: &str,
    resp: reqwest::blocking::Response,
) -> Result<reqwest::blocking::Response, Error> {
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        return Err(Error::Wallet(format!(
            "LND {} returned {}: {}",
            url, status, body
        )));
    }
    Ok(resp)
}

// -- REST response types ---------------------------------------------------
//
// Each Deserialize struct mirrors only the LND JSON fields we read. LND
// emits everything as strings (even numbers) for grpc-gateway round-trip
// reasons; deserialize_with helpers below handle string-to-u64 coercion.

fn de_u64_str<'de, D>(d: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(d)?;
    s.parse::<u64>().map_err(serde::de::Error::custom)
}

fn de_opt_u64_str<'de, D>(d: D) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = Option::<String>::deserialize(d)?;
    match s {
        Some(s) if !s.is_empty() => s
            .parse::<u64>()
            .map(Some)
            .map_err(serde::de::Error::custom),
        _ => Ok(None),
    }
}

#[derive(Deserialize)]
struct LndGetInfo {
    identity_pubkey: String,
    #[serde(default)]
    block_height: u32,
    #[serde(default)]
    block_hash: String,
}

#[derive(Deserialize)]
struct LndOnchainBalance {
    #[serde(deserialize_with = "de_u64_str")]
    total_balance: u64,
    #[serde(deserialize_with = "de_u64_str")]
    confirmed_balance: u64,
}

#[derive(Deserialize)]
struct LndChannelBalance {
    /// Total local balance across channels, in sats (as a {sat, msat} struct or
    /// a stringified sats value depending on LND version). Newer LND uses the
    /// `local_balance` object; older returns `balance` directly. Handle both.
    #[serde(default, deserialize_with = "de_opt_u64_str")]
    balance: Option<u64>,
    #[serde(default)]
    local_balance: Option<LndAmount>,
}

#[derive(Deserialize)]
struct LndAmount {
    #[serde(deserialize_with = "de_u64_str")]
    sat: u64,
}

#[derive(Deserialize)]
struct LndAddInvoiceResp {
    payment_request: String,
}

#[derive(Deserialize)]
struct LndSendResp {
    payment_error: String,
    payment_preimage: String,
    payment_hash: String,
}

#[derive(Deserialize)]
struct LndListChannelsResp {
    channels: Vec<LndChannel>,
}

#[derive(Deserialize)]
struct LndChannel {
    chan_id: String,
    remote_pubkey: String,
    #[serde(deserialize_with = "de_u64_str")]
    capacity: u64,
    #[serde(deserialize_with = "de_u64_str")]
    local_balance: u64,
    #[serde(deserialize_with = "de_u64_str")]
    remote_balance: u64,
    active: bool,
}

#[derive(Deserialize)]
struct LndListPaymentsResp {
    #[serde(default)]
    payments: Vec<LndPayment>,
}

#[derive(Deserialize)]
struct LndPayment {
    payment_hash: String,
    payment_preimage: String,
    /// LND payment status: 0=UNKNOWN, 1=IN_FLIGHT, 2=SUCCEEDED, 3=FAILED.
    /// Newer versions emit the string name; handle both.
    #[serde(default)]
    status: String,
    #[serde(default, deserialize_with = "de_opt_u64_str")]
    value_msat: Option<u64>,
}

#[derive(Deserialize)]
struct LndInvoice {
    r_preimage: String,
    /// Settled bool. Set when the invoice was actually paid.
    #[serde(default)]
    settled: bool,
    /// Invoice lifecycle state: "OPEN" | "SETTLED" | "CANCELED" | "ACCEPTED".
    /// ACCEPTED is the hold-invoice "HTLCs parked, awaiting settle/cancel"
    /// state the bridge polls for. Older LND emits the numeric enum
    /// (0..=3 in the same order); handle both via the string the REST
    /// gateway produces (modern gateways emit the name).
    #[serde(default)]
    state: String,
    /// Per-HTLC detail; populated once HTLCs arrive. `expiry_height` is the
    /// CLTV height at which the HTLC times out — the bridge's upper bound
    /// for its on-ledger lock timeout.
    #[serde(default)]
    htlcs: Vec<LndInvoiceHtlc>,
}

#[derive(Deserialize)]
struct LndInvoiceHtlc {
    #[serde(default)]
    expiry_height: u32,
}

/// `/v2/invoices/hodl` response — same shape as AddInvoice.
#[derive(Deserialize)]
struct LndAddHoldInvoiceResp {
    payment_request: String,
}

/// `/v2/invoices/settle` and `/v2/invoices/cancel` return empty objects on
/// success; deserialize into this to confirm valid JSON came back.
#[derive(Deserialize)]
struct LndEmptyResp {}

// -- LightningBackend impl -------------------------------------------------

impl LightningBackend for LndBackend {
    fn get_node_info(&self) -> Result<NodeInfo, Error> {
        let info: LndGetInfo = self.get("/v1/getinfo")?;
        Ok(NodeInfo {
            node_id: info.identity_pubkey,
            current_best_block_height: (info.block_height > 0).then_some(info.block_height),
            current_best_block_hash: (!info.block_hash.is_empty()).then_some(info.block_hash),
        })
    }

    fn get_balances(&self) -> Result<Balances, Error> {
        let onchain: LndOnchainBalance = self.get("/v1/balance/blockchain")?;
        let channels: LndChannelBalance = self.get("/v1/balance/channels")?;
        let lightning_total_sats = channels
            .local_balance
            .map(|a| a.sat)
            .or(channels.balance)
            .unwrap_or(0);
        Ok(Balances {
            onchain_total_sats: onchain.total_balance,
            onchain_spendable_sats: onchain.confirmed_balance,
            lightning_total_sats,
        })
    }

    fn create_invoice(&self, amount_msat: u64, description: &str) -> Result<String, Error> {
        let body = serde_json::json!({
            "value_msat": amount_msat.to_string(),
            "memo": description,
        });
        let resp: LndAddInvoiceResp = self.post("/v1/invoices", &body)?;
        Ok(resp.payment_request)
    }

    fn create_invoice_with_desc_hash(
        &self,
        amount_msat: u64,
        desc_hash_hex: &str,
    ) -> Result<String, Error> {
        let desc_hash = hex::decode(desc_hash_hex)
            .map_err(|e| Error::Wallet(format!("LND desc_hash hex decode: {}", e)))?;
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let body = serde_json::json!({
            "value_msat": amount_msat.to_string(),
            "description_hash": STANDARD.encode(&desc_hash),
        });
        let resp: LndAddInvoiceResp = self.post("/v1/invoices", &body)?;
        Ok(resp.payment_request)
    }

    fn create_invoice_any_amount(&self, description: &str) -> Result<String, Error> {
        let body = serde_json::json!({
            "value_msat": "0",
            "memo": description,
        });
        let resp: LndAddInvoiceResp = self.post("/v1/invoices", &body)?;
        Ok(resp.payment_request)
    }

    fn pay_invoice(&self, invoice: &str) -> Result<String, Error> {
        // /v1/channels/transactions is sync — blocks until terminal state.
        let body = serde_json::json!({ "payment_request": invoice });
        let resp: LndSendResp = self.post("/v1/channels/transactions", &body)?;
        if !resp.payment_error.is_empty() {
            return Err(Error::Wallet(format!(
                "LND pay_invoice failed: {}",
                resp.payment_error
            )));
        }
        Ok(resp.payment_hash)
    }

    fn pay_invoice_with_amount(
        &self,
        invoice: &str,
        amount_msat: u64,
    ) -> Result<String, Error> {
        let body = serde_json::json!({
            "payment_request": invoice,
            "amt_msat": amount_msat.to_string(),
        });
        let resp: LndSendResp = self.post("/v1/channels/transactions", &body)?;
        if !resp.payment_error.is_empty() {
            return Err(Error::Wallet(format!(
                "LND pay_invoice_with_amount failed: {}",
                resp.payment_error
            )));
        }
        Ok(resp.payment_hash)
    }

    fn list_channels(&self) -> Result<Vec<ChannelInfo>, Error> {
        let resp: LndListChannelsResp = self.get("/v1/channels")?;
        Ok(resp
            .channels
            .into_iter()
            .map(|c| ChannelInfo {
                channel_id: c.chan_id,
                counterparty_node_id: c.remote_pubkey,
                capacity_sats: c.capacity,
                outbound_capacity_msat: c.local_balance.saturating_mul(1000),
                inbound_capacity_msat: c.remote_balance.saturating_mul(1000),
                is_usable: c.active,
                is_ready: c.active,
            })
            .collect())
    }

    fn list_payments(&self) -> Result<Vec<PaymentInfo>, Error> {
        let resp: LndListPaymentsResp = self.get("/v1/payments?include_incomplete=true")?;
        Ok(resp
            .payments
            .into_iter()
            .map(|p| PaymentInfo {
                id: p.payment_hash,
                status: match p.status.as_str() {
                    "SUCCEEDED" | "2" => PaymentStatus::Succeeded,
                    "FAILED" | "3" => PaymentStatus::Failed,
                    _ => PaymentStatus::Pending,
                },
                amount_msat: p.value_msat,
                preimage_hex: (!p.payment_preimage.is_empty()
                    && p.payment_preimage != "0000000000000000000000000000000000000000000000000000000000000000")
                    .then_some(p.payment_preimage),
            })
            .collect())
    }

    fn get_payment_preimage(
        &self,
        payment_id_hex: &str,
    ) -> Result<Option<[u8; 32]>, Error> {
        // Trait's `get_payment_preimage` is "given a payment_hash, give me the
        // preimage" — used on the self-pay path where the daemon settles an
        // invoice it issued itself. For LND, that's LookupInvoice (NOT
        // ListPayments, which is outbound-only).
        let invoice = match self.lookup_invoice(payment_id_hex)? {
            Some(i) => i,
            None => return Ok(None),
        };
        if !invoice.settled || invoice.r_preimage.is_empty() {
            return Ok(None);
        }
        // LND emits r_preimage as base64; decode and pack.
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let bytes = STANDARD
            .decode(&invoice.r_preimage)
            .map_err(|e| Error::Wallet(format!("LND r_preimage base64: {}", e)))?;
        if bytes.len() != 32 {
            return Err(Error::Wallet(format!(
                "LND r_preimage wrong length: {} bytes",
                bytes.len()
            )));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(Some(out))
    }

    // ── Hold invoices — native invoicesrpc support ──────────────────────────
    //
    // LND ships hold invoices in stock release builds via the invoicesrpc
    // subserver. REST surface:
    //   POST /v2/invoices/hodl      AddHoldInvoice (external hash → BOLT-11)
    //   GET  /v1/invoice/{r_hash}   state OPEN|ACCEPTED|SETTLED|CANCELED + htlcs
    //   POST /v2/invoices/settle    SettleInvoice (preimage)
    //   POST /v2/invoices/cancel    CancelInvoice (payment_hash)
    // Byte fields are standard base64 in POST bodies (grpc-gateway), and the
    // invoice macaroon (or admin) covers all four.

    fn supports_hold_invoices(&self) -> bool {
        true
    }

    fn create_hold_invoice(
        &self,
        amount_msat: u64,
        payment_hash_hex: &str,
        description: &str,
        expiry_secs: u32,
        cltv_expiry_delta: Option<u16>,
    ) -> Result<String, Error> {
        let hash_bytes = hex::decode(payment_hash_hex)
            .map_err(|e| Error::Wallet(format!("LND hold hash hex decode: {}", e)))?;
        if hash_bytes.len() != 32 {
            return Err(Error::Wallet(format!(
                "LND hold hash wrong length: {} bytes",
                hash_bytes.len()
            )));
        }
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let mut body = serde_json::json!({
            "hash": STANDARD.encode(&hash_bytes),
            "value_msat": amount_msat.to_string(),
            "memo": description,
            "expiry": expiry_secs.to_string(),
        });
        // LND honors a requested hold window via cltv_expiry (the invoice's
        // min_final_cltv_expiry_delta). String-typed per grpc-gateway.
        if let Some(delta) = cltv_expiry_delta {
            body["cltv_expiry"] = serde_json::Value::String(delta.to_string());
        }
        let resp: LndAddHoldInvoiceResp = self.post("/v2/invoices/hodl", &body)?;
        Ok(resp.payment_request)
    }

    fn lookup_hold_invoice(
        &self,
        payment_hash_hex: &str,
    ) -> Result<HoldInvoiceState, Error> {
        let invoice = self.lookup_invoice(payment_hash_hex)?.ok_or_else(|| {
            Error::Wallet(format!(
                "LND hold invoice not found for hash {}…",
                &payment_hash_hex[..16.min(payment_hash_hex.len())]
            ))
        })?;
        // Modern REST gateways emit the enum name; some older ones emit the
        // numeric value as a bare integer (which our String field would fail
        // to capture — those versions also predate widespread hold-invoice
        // REST use, so the name-match is the practical surface).
        match invoice.state.as_str() {
            "SETTLED" => Ok(HoldInvoiceState::Settled),
            "CANCELED" => Ok(HoldInvoiceState::Canceled),
            "ACCEPTED" => Ok(HoldInvoiceState::Accepted {
                htlc_expiry_height: invoice
                    .htlcs
                    .iter()
                    .map(|h| h.expiry_height)
                    .filter(|&h| h > 0)
                    .min(),
            }),
            // "OPEN", "", or anything unrecognized: no HTLCs parked yet.
            _ => Ok(HoldInvoiceState::Open),
        }
    }

    fn settle_hold_invoice(&self, preimage_hex: &str) -> Result<(), Error> {
        let preimage_bytes = hex::decode(preimage_hex)
            .map_err(|e| Error::Wallet(format!("LND settle preimage hex decode: {}", e)))?;
        if preimage_bytes.len() != 32 {
            return Err(Error::Wallet(format!(
                "LND settle preimage wrong length: {} bytes",
                preimage_bytes.len()
            )));
        }
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let body = serde_json::json!({ "preimage": STANDARD.encode(&preimage_bytes) });
        let _: LndEmptyResp = self.post("/v2/invoices/settle", &body)?;
        Ok(())
    }

    fn cancel_hold_invoice(&self, payment_hash_hex: &str) -> Result<(), Error> {
        let hash_bytes = hex::decode(payment_hash_hex)
            .map_err(|e| Error::Wallet(format!("LND cancel hash hex decode: {}", e)))?;
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let body = serde_json::json!({ "payment_hash": STANDARD.encode(&hash_bytes) });
        let _: LndEmptyResp = self.post("/v2/invoices/cancel", &body)?;
        Ok(())
    }
}

#[allow(dead_code)]
fn _path_for_doc() -> PathBuf {
    PathBuf::from("/var/lib/lnd/data/chain/bitcoin/mainnet/admin.macaroon")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time check: `LndBackend` satisfies the `LightningBackend`
    /// trait. If the trait or impl drifts, this fails at type-check time
    /// before runtime exercises it.
    #[test]
    fn lnd_backend_implements_lightning_backend() {
        fn assert_backend<T: LightningBackend>() {}
        assert_backend::<LndBackend>();
    }

    /// LND emits balance fields as strings (grpc-gateway convention). Parse
    /// against a fixture matching the live JSON shape.
    #[test]
    fn parses_onchain_balance() {
        let json = r#"{"total_balance":"100000","confirmed_balance":"95000",
                        "unconfirmed_balance":"5000"}"#;
        let b: LndOnchainBalance = serde_json::from_str(json).unwrap();
        assert_eq!(b.total_balance, 100_000);
        assert_eq!(b.confirmed_balance, 95_000);
    }

    /// Newer LND uses `local_balance: {sat: "..."}`; older uses
    /// `balance: "..."`. Backend impl must handle both shapes.
    #[test]
    fn parses_channel_balance_both_shapes() {
        let new = r#"{"balance":"50000","local_balance":{"sat":"50000","msat":"50000000"}}"#;
        let b: LndChannelBalance = serde_json::from_str(new).unwrap();
        assert_eq!(b.local_balance.map(|a| a.sat), Some(50_000));

        let old = r#"{"balance":"42000"}"#;
        let b: LndChannelBalance = serde_json::from_str(old).unwrap();
        assert_eq!(b.balance, Some(42_000));
        assert!(b.local_balance.is_none());
    }

    /// Payment status comes as either the enum name ("SUCCEEDED") or the
    /// stringified numeric tag ("2"); list_payments normalizes both to
    /// PaymentStatus::Succeeded. Spot-check via direct match.
    #[test]
    fn normalizes_payment_status_strings_and_numbers() {
        let by_name = "SUCCEEDED";
        let by_number = "2";
        let unknown = "WHATEVER";
        let to_status = |s: &str| match s {
            "SUCCEEDED" | "2" => PaymentStatus::Succeeded,
            "FAILED" | "3" => PaymentStatus::Failed,
            _ => PaymentStatus::Pending,
        };
        assert_eq!(to_status(by_name), PaymentStatus::Succeeded);
        assert_eq!(to_status(by_number), PaymentStatus::Succeeded);
        assert_eq!(to_status(unknown), PaymentStatus::Pending);
    }
}
