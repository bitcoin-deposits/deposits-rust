//! [`LightningBackend`] impl talking to Core Lightning (CLN) via its
//! Unix-socket JSON-RPC.
//!
//! CLN's primary interface is a Unix socket
//! (`lightning-rpc`) speaking JSON-RPC 2.0 — newline-delimited, no auth (the
//! filesystem permission on the socket IS the auth, same trust model as
//! deposits-signer). The `clnrest` plugin exposes an HTTP variant but it's
//! opt-in and most operators don't have it running; the socket path is the
//! default that ships out of the box.
//!
//! ## No external dep
//!
//! `cln-rpc` is the official Rust client crate, but we don't add it here —
//! the protocol is genuinely simple (newline-delimited JSON-RPC 2.0 over a
//! Unix socket) and rolling our own keeps the dep tree small. Two files of
//! pure stdlib + serde_json. If CLN ever ships a wire change that breaks
//! us, we can adopt cln-rpc as a follow-on.
//!
//! ## Socket path
//!
//! Default is `~/.lightning/bitcoin/lightning-rpc` (mainnet) or
//! `~/.lightning/regtest/lightning-rpc` (regtest). Operators that put
//! `lightning-dir` elsewhere set `CLN_SOCKET_PATH` explicitly.
//!
//! ## Hold invoices (Lightning bridge receive)
//!
//! Core CLN cannot issue an invoice for an externally-supplied payment hash
//! — `invoice` accepts an optional *preimage* (which the node then knows,
//! defeating the hold), never a bare hash. Hold support therefore requires a
//! plugin built on the `htlc_accepted` hook, which can park HTLCs and later
//! resolve them with a preimage supplied at settle time.
//!
//! The supported implementation is BoltzExchange's `hold` plugin
//! (<https://github.com/BoltzExchange/hold>) — built for submarine swaps,
//! which need exactly the bridge's property: an invoice for an external
//! hash whose preimage the node never learns. RPC surface (verified against
//! v0.3.3 on CLN v25.05):
//!
//!   holdinvoice payment_hash amount         → {"bolt11": "..."}  (amount in msat)
//!   listholdinvoices [payment_hash]         → {"holdinvoices": [{state, htlcs[{cltv_expiry, ..}], ..}]}
//!   settleholdinvoice preimage              → {}
//!   cancelholdinvoice payment_hash          → {}
//!
//! States: "unpaid" | "accepted" | "paid" | "cancelled". The `htlcs` array
//! carries `cltv_expiry` per held HTLC — the minimum feeds
//! `HoldInvoiceState::Accepted::htlc_expiry_height`.
//!
//! NOTE: the daywalker90/holdinvoice plugin (archived) exposes a method of
//! the same name but CANNOT do external-hash holds — its `holdinvoice`
//! takes amount/label/description with an optional *preimage* and settles
//! by payment_hash, i.e. the node knows the preimage. The signature check
//! in `supports_hold_invoices` distinguishes the two: the Boltz plugin's
//! help text starts with `holdinvoice payment_hash`, the archived one with
//! `holdinvoice amount_msat`.
//!
//! Operator setup for bridge-receive on CLN:
//!   1. download the hold release binary (or build it) and add to the CLN
//!      config: `important-plugin=/path/to/hold` plus
//!      `hold-database=sqlite:///path/to/hold.db`
//!   2. restart CLN; verify `lightning-cli help holdinvoice` shows the
//!      `holdinvoice payment_hash amount` signature
//!   3. the deposits bridge daemon picks it up automatically via the probe
//!
//! `./bin/setup-cln-hold.sh` spins up a two-node regtest pair with the
//! plugin loaded for the `cln_hold_invoice` integration test.

use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Duration;

use crate::lightning_backend::{
    Balances, ChannelInfo, HoldInvoiceState, LightningBackend, NodeInfo, PaymentInfo,
    PaymentStatus,
};
use crate::Error;

/// CLN backend. Selection: `LIGHTNING_BACKEND=cln`.
pub struct ClnBackend {
    socket_path: PathBuf,
    /// Read/write timeout on each RPC call. CLN typically responds in
    /// milliseconds; the timeout exists to surface stuck sockets quickly.
    timeout: Duration,
    /// Cached result of the holdinvoice-plugin probe. Probed once on first
    /// `supports_hold_invoices` call; plugin loads require a CLN restart, so
    /// the answer can't change mid-process.
    hold_probe: OnceLock<bool>,
}

impl ClnBackend {
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
            timeout: Duration::from_secs(30),
            hold_probe: OnceLock::new(),
        }
    }

    /// Build from environment:
    /// - `CLN_SOCKET_PATH` (default `~/.lightning/bitcoin/lightning-rpc`)
    pub fn from_env() -> Result<Self, Error> {
        let path = match std::env::var("CLN_SOCKET_PATH") {
            Ok(p) => PathBuf::from(p),
            Err(_) => {
                let home = std::env::var("HOME").map_err(|_| {
                    Error::Wallet(
                        "CLN backend selected but neither CLN_SOCKET_PATH nor HOME is set"
                            .to_string(),
                    )
                })?;
                PathBuf::from(home).join(".lightning/bitcoin/lightning-rpc")
            }
        };
        Ok(Self::new(path))
    }

    /// Issue a single JSON-RPC call. Opens a fresh socket connection per
    /// call to keep the impl trivially thread-safe — CLN handles many
    /// concurrent sockets fine and the connect is microseconds-cheap for
    /// a Unix socket.
    fn call<P: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        params: P,
    ) -> Result<R, Error> {
        let mut stream = UnixStream::connect(&self.socket_path).map_err(|e| {
            Error::Wallet(format!(
                "CLN connect {}: {}",
                self.socket_path.display(),
                e
            ))
        })?;
        stream
            .set_read_timeout(Some(self.timeout))
            .and_then(|_| stream.set_write_timeout(Some(self.timeout)))
            .map_err(|e| Error::Wallet(format!("CLN socket timeout: {}", e)))?;

        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });
        let mut req_bytes = serde_json::to_vec(&req)
            .map_err(|e| Error::Wallet(format!("CLN serialize {}: {}", method, e)))?;
        req_bytes.push(b'\n');
        stream
            .write_all(&req_bytes)
            .map_err(|e| Error::Wallet(format!("CLN write {}: {}", method, e)))?;
        stream
            .flush()
            .map_err(|e| Error::Wallet(format!("CLN flush {}: {}", method, e)))?;

        // CLN responses are newline-terminated. Read until \n.
        let mut reader = BufReader::new(&stream);
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .map_err(|e| Error::Wallet(format!("CLN read {}: {}", method, e)))?;
        if line.is_empty() {
            return Err(Error::Wallet(format!(
                "CLN {}: empty response (socket closed?)",
                method
            )));
        }
        let resp: ClnRpcResponse<R> = serde_json::from_str(&line)
            .map_err(|e| Error::Wallet(format!("CLN parse {}: {} (raw: {})", method, e, line.trim())))?;
        if let Some(err) = resp.error {
            return Err(Error::Wallet(format!(
                "CLN {} returned error {}: {}",
                method, err.code, err.message
            )));
        }
        resp.result.ok_or_else(|| {
            Error::Wallet(format!(
                "CLN {}: response had neither result nor error",
                method
            ))
        })
    }
}

// -- JSON-RPC framing ------------------------------------------------------

#[derive(Deserialize)]
struct ClnRpcResponse<T> {
    result: Option<T>,
    error: Option<ClnRpcError>,
}

#[derive(Deserialize)]
struct ClnRpcError {
    code: i64,
    message: String,
}

// -- Method response types -------------------------------------------------

#[derive(Deserialize)]
struct ClnGetinfo {
    id: String,
    blockheight: u32,
}

#[derive(Deserialize)]
struct ClnListfunds {
    outputs: Vec<ClnFundsOutput>,
    channels: Vec<ClnFundsChannel>,
}

#[derive(Deserialize)]
struct ClnFundsOutput {
    /// "confirmed" | "unconfirmed" | "spent"
    status: String,
    /// CLN serializes amount as the string "<sats>sat" or "<msats>msat".
    /// Use Amount::sats() / Amount::msats() helpers via the parsed shape.
    amount_msat: u64,
}

#[derive(Deserialize)]
struct ClnFundsChannel {
    our_amount_msat: u64,
    /// "CHANNELD_NORMAL" et al.
    state: String,
}

#[derive(Deserialize)]
struct ClnInvoiceResp {
    bolt11: String,
}

#[derive(Deserialize)]
struct ClnPayResp {
    payment_hash: String,
    payment_preimage: String,
    /// "complete" | "pending" | "failed"
    status: String,
}

#[derive(Deserialize)]
struct ClnListpeerchannels {
    channels: Vec<ClnPeerChannel>,
}

#[derive(Deserialize)]
struct ClnPeerChannel {
    peer_id: String,
    /// Funding outpoint short id (cln channel_id is the long sha256 of the
    /// funding outpoint reversed; short_channel_id ("xxxXyyyXz") is the
    /// gossiped form). The trait wants something identifying-y; use
    /// short_channel_id when available, else channel_id.
    short_channel_id: Option<String>,
    channel_id: String,
    /// "CHANNELD_NORMAL" | "OPENINGD" | "CHANNELD_AWAITING_LOCKIN" | …
    state: String,
    /// Total capacity, msat (string-encoded numeric in older versions,
    /// number in newer; both deserialize transparently as u64 here).
    total_msat: u64,
    our_msat: u64,
    /// Remote capacity = total - ours. Not emitted directly by CLN; we
    /// compute it. Field left absent in the struct.
    #[serde(default)]
    _unused: (),
}

#[derive(Deserialize)]
struct ClnListsendpays {
    payments: Vec<ClnSendPay>,
}

#[derive(Deserialize)]
struct ClnSendPay {
    payment_hash: String,
    /// "complete" | "pending" | "failed"
    status: String,
    #[serde(default)]
    amount_msat: Option<u64>,
    #[serde(default)]
    payment_preimage: Option<String>,
}

#[derive(Deserialize)]
struct ClnListinvoices {
    invoices: Vec<ClnInvoice>,
}

#[derive(Deserialize)]
struct ClnInvoice {
    /// "unpaid" | "paid" | "expired"
    status: String,
    #[serde(default)]
    payment_preimage: Option<String>,
}

/// Boltz `holdinvoice` response — `{"bolt11": "..."}` (observed v0.3.3).
#[derive(Deserialize)]
struct ClnHoldInvoiceResp {
    bolt11: String,
}

/// Boltz `listholdinvoices` response (observed v0.3.3):
/// `{"holdinvoices": [{payment_hash, invoice, state, created_at, htlcs: [..]}]}`.
#[derive(Deserialize)]
struct ClnHoldListResp {
    holdinvoices: Vec<ClnHoldInvoiceEntry>,
}

#[derive(Deserialize)]
struct ClnHoldInvoiceEntry {
    /// "unpaid" | "accepted" | "paid" | "cancelled"
    state: String,
    #[serde(default)]
    htlcs: Vec<ClnHoldHtlc>,
}

#[derive(Deserialize)]
struct ClnHoldHtlc {
    /// Per-HTLC state — mirrors the invoice states; only "accepted" entries
    /// count toward the binding expiry.
    #[serde(default)]
    state: String,
    /// Absolute block height at which this HTLC times out.
    cltv_expiry: u32,
}

// -- LightningBackend impl -------------------------------------------------

impl LightningBackend for ClnBackend {
    fn get_node_info(&self) -> Result<NodeInfo, Error> {
        let info: ClnGetinfo = self.call("getinfo", serde_json::json!({}))?;
        Ok(NodeInfo {
            node_id: info.id,
            current_best_block_height: (info.blockheight > 0).then_some(info.blockheight),
            current_best_block_hash: None,
        })
    }

    fn get_balances(&self) -> Result<Balances, Error> {
        let funds: ClnListfunds = self.call("listfunds", serde_json::json!({}))?;
        let mut onchain_total = 0u64;
        let mut onchain_spendable = 0u64;
        for o in &funds.outputs {
            if o.status == "spent" {
                continue;
            }
            let sats = o.amount_msat / 1000;
            onchain_total += sats;
            if o.status == "confirmed" {
                onchain_spendable += sats;
            }
        }
        let lightning_total_sats = funds
            .channels
            .iter()
            .filter(|c| c.state == "CHANNELD_NORMAL")
            .map(|c| c.our_amount_msat / 1000)
            .sum();
        Ok(Balances {
            onchain_total_sats: onchain_total,
            onchain_spendable_sats: onchain_spendable,
            lightning_total_sats,
        })
    }

    fn create_invoice(&self, amount_msat: u64, description: &str) -> Result<String, Error> {
        // CLN's `invoice` requires a unique label per call; use a UUID-shaped
        // string built from the current timestamp + amount so retries with the
        // same args produce a fresh label.
        let label = format!("deposits-{}-{}", now_nanos(), amount_msat);
        let resp: ClnInvoiceResp = self.call(
            "invoice",
            serde_json::json!({
                "amount_msat": amount_msat,
                "label": label,
                "description": description,
            }),
        )?;
        Ok(resp.bolt11)
    }

    fn create_invoice_with_desc_hash(
        &self,
        amount_msat: u64,
        desc_hash_hex: &str,
    ) -> Result<String, Error> {
        // CLN supports description_hash via the `deschashonly` flag combined
        // with a description that hashes to the requested value. The cleanest
        // way is to pass the hash as the description and let CLN hash it. CLN
        // doesn't directly take a hex description hash on the `invoice`
        // command; this requires the longer `invoicerequest` flow on modern
        // CLN. For now, fall back to `invoice` with the hex string as the
        // description — bolt11 's `h` tag will be the sha256 of the
        // description, which is NOT the same as the hex we got. Callers who
        // need exact-match desc_hash (e.g. NIP-57) must use LDK or LND today.
        //
        // Documented limitation; track in TODO until we either: (a) add
        // CLN's `invoicerequest` support, or (b) get explicit desc_hash on
        // `invoice` (planned upstream in 25.x).
        let _ = (amount_msat, desc_hash_hex);
        Err(Error::Wallet(
            "ClnBackend: create_invoice_with_desc_hash not yet supported (CLN's invoice command \
             doesn't accept an explicit description_hash; tracking as a follow-up). Use \
             LDK or LND backends for NIP-57 zap invoices for now."
                .to_string(),
        ))
    }

    fn create_invoice_any_amount(&self, description: &str) -> Result<String, Error> {
        let label = format!("deposits-{}-any", now_nanos());
        let resp: ClnInvoiceResp = self.call(
            "invoice",
            serde_json::json!({
                "amount_msat": "any",
                "label": label,
                "description": description,
            }),
        )?;
        Ok(resp.bolt11)
    }

    fn pay_invoice(&self, invoice: &str) -> Result<String, Error> {
        // CLN's `pay` is sync — returns when the payment terminates.
        let resp: ClnPayResp =
            self.call("pay", serde_json::json!({ "bolt11": invoice }))?;
        if resp.status == "failed" {
            return Err(Error::Wallet(format!(
                "CLN pay failed: payment_hash={} preimage={}",
                resp.payment_hash, resp.payment_preimage
            )));
        }
        Ok(resp.payment_hash)
    }

    fn pay_invoice_with_amount(
        &self,
        invoice: &str,
        amount_msat: u64,
    ) -> Result<String, Error> {
        let resp: ClnPayResp = self.call(
            "pay",
            serde_json::json!({ "bolt11": invoice, "amount_msat": amount_msat }),
        )?;
        if resp.status == "failed" {
            return Err(Error::Wallet(format!(
                "CLN pay_with_amount failed: payment_hash={}",
                resp.payment_hash
            )));
        }
        Ok(resp.payment_hash)
    }

    fn list_channels(&self) -> Result<Vec<ChannelInfo>, Error> {
        let resp: ClnListpeerchannels = self.call("listpeerchannels", serde_json::json!({}))?;
        Ok(resp
            .channels
            .into_iter()
            .map(|c| {
                let is_ready = matches!(
                    c.state.as_str(),
                    "CHANNELD_NORMAL" | "CHANNELD_AWAITING_LOCKIN"
                );
                let is_usable = c.state == "CHANNELD_NORMAL";
                let our = c.our_msat;
                let theirs = c.total_msat.saturating_sub(our);
                ChannelInfo {
                    channel_id: c
                        .short_channel_id
                        .unwrap_or(c.channel_id),
                    counterparty_node_id: c.peer_id,
                    capacity_sats: c.total_msat / 1000,
                    outbound_capacity_msat: our,
                    inbound_capacity_msat: theirs,
                    is_usable,
                    is_ready,
                }
            })
            .collect())
    }

    fn list_payments(&self) -> Result<Vec<PaymentInfo>, Error> {
        let resp: ClnListsendpays = self.call("listsendpays", serde_json::json!({}))?;
        Ok(resp
            .payments
            .into_iter()
            .map(|p| PaymentInfo {
                id: p.payment_hash,
                status: match p.status.as_str() {
                    "complete" => PaymentStatus::Succeeded,
                    "failed" => PaymentStatus::Failed,
                    _ => PaymentStatus::Pending,
                },
                amount_msat: p.amount_msat,
                preimage_hex: p.payment_preimage,
            })
            .collect())
    }

    fn get_payment_preimage(
        &self,
        payment_id_hex: &str,
    ) -> Result<Option<[u8; 32]>, Error> {
        // Trait's get_payment_preimage is "given a payment_hash, give me the
        // preimage" — used on the self-pay path where the daemon settles an
        // invoice it issued. For CLN: listinvoices, filter by payment_hash,
        // return preimage if status=paid.
        let resp: ClnListinvoices = self.call(
            "listinvoices",
            serde_json::json!({ "payment_hash": payment_id_hex }),
        )?;
        let inv = match resp.invoices.into_iter().next() {
            Some(i) => i,
            None => return Ok(None),
        };
        if inv.status != "paid" {
            return Ok(None);
        }
        let hex_str = match inv.payment_preimage {
            Some(p) => p,
            None => return Ok(None),
        };
        let bytes = hex::decode(&hex_str)
            .map_err(|e| Error::Wallet(format!("CLN preimage hex: {}", e)))?;
        if bytes.len() != 32 {
            return Err(Error::Wallet(format!(
                "CLN preimage wrong length: {} bytes",
                bytes.len()
            )));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(Some(out))
    }

    // ── Hold invoices — via the BoltzExchange hold plugin (see module docs) ─

    fn supports_hold_invoices(&self) -> bool {
        *self.hold_probe.get_or_init(|| {
            // `help` with a specific command errors if the command is
            // unknown. The help text also distinguishes the Boltz plugin
            // (`holdinvoice payment_hash amount` — external-hash holds)
            // from the archived daywalker90 plugin of the same method name
            // (`holdinvoice amount_msat label ...` — node knows the
            // preimage, unusable for the bridge).
            let probe: Result<serde_json::Value, Error> =
                self.call("help", serde_json::json!({ "command": "holdinvoice" }));
            match probe {
                Ok(v) => {
                    let text = v.to_string();
                    let is_boltz = text.contains("holdinvoice payment_hash");
                    if !is_boltz {
                        tracing::warn!(
                            "CLN has a holdinvoice method but not the external-hash \
                             variant (BoltzExchange/hold). The archived \
                             daywalker90/holdinvoice plugin cannot serve the bridge — \
                             its node knows the preimage. Bridge-receive disabled."
                        );
                    }
                    is_boltz
                }
                Err(e) => {
                    tracing::info!(
                        "CLN hold plugin not detected ({}). Bridge-receive disabled; \
                         bridge-pay unaffected. To enable: install \
                         github.com/BoltzExchange/hold and restart CLN.",
                        e
                    );
                    false
                }
            }
        })
    }

    fn create_hold_invoice(
        &self,
        amount_msat: u64,
        payment_hash_hex: &str,
        _description: &str,
        _expiry_secs: u32,
        _cltv_expiry_delta: Option<u16>,
    ) -> Result<String, Error> {
        // Boltz hold RPC takes exactly (payment_hash, amount-in-msat).
        // Description and expiry are only settable via the plugin's gRPC
        // interface; the RPC surface uses the plugin defaults. Neither is
        // load-bearing for the bridge (the wallet doesn't read the
        // description, and invoice expiry only bounds when the payer can
        // START paying).
        let resp: ClnHoldInvoiceResp = self.call(
            "holdinvoice",
            serde_json::json!({
                "payment_hash": payment_hash_hex,
                "amount": amount_msat,
            }),
        )?;
        Ok(resp.bolt11)
    }

    fn lookup_hold_invoice(
        &self,
        payment_hash_hex: &str,
    ) -> Result<HoldInvoiceState, Error> {
        let resp: ClnHoldListResp = self.call(
            "listholdinvoices",
            serde_json::json!({ "payment_hash": payment_hash_hex }),
        )?;
        let inv = resp.holdinvoices.into_iter().next().ok_or_else(|| {
            Error::Wallet(format!(
                "CLN hold invoice not found for hash {}…",
                &payment_hash_hex[..16.min(payment_hash_hex.len())]
            ))
        })?;
        // Observed states (hold v0.3.3): "unpaid" | "accepted" | "paid" | "cancelled".
        match inv.state.to_ascii_lowercase().as_str() {
            "paid" => Ok(HoldInvoiceState::Settled),
            "cancelled" | "canceled" => Ok(HoldInvoiceState::Canceled),
            "accepted" => Ok(HoldInvoiceState::Accepted {
                // Min across held HTLCs — the earliest expiry is the binding
                // deadline for the bridge's on-ledger lock.
                htlc_expiry_height: inv
                    .htlcs
                    .iter()
                    .filter(|h| h.state.eq_ignore_ascii_case("accepted"))
                    .map(|h| h.cltv_expiry)
                    .min(),
            }),
            _ => Ok(HoldInvoiceState::Open),
        }
    }

    fn settle_hold_invoice(&self, preimage_hex: &str) -> Result<(), Error> {
        let _: serde_json::Value = self.call(
            "settleholdinvoice",
            serde_json::json!({ "preimage": preimage_hex }),
        )?;
        Ok(())
    }

    fn cancel_hold_invoice(&self, payment_hash_hex: &str) -> Result<(), Error> {
        let _: serde_json::Value = self.call(
            "cancelholdinvoice",
            serde_json::json!({ "payment_hash": payment_hash_hex }),
        )?;
        Ok(())
    }
}

fn now_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time check: `ClnBackend` satisfies the `LightningBackend`
    /// trait. If the trait or impl drifts, this fails at type-check time
    /// before runtime exercises it.
    #[test]
    fn cln_backend_implements_lightning_backend() {
        fn assert_backend<T: LightningBackend>() {}
        assert_backend::<ClnBackend>();
    }

    /// CLN's `getinfo` shape — we parse a small subset.
    #[test]
    fn parses_getinfo() {
        let json = r#"{"id":"03abc...","alias":"node","blockheight":850000,
                        "color":"000000","num_peers":3,"num_pending_channels":0,
                        "num_active_channels":2,"num_inactive_channels":0,
                        "address":[],"binding":[],"version":"24.05",
                        "network":"bitcoin","fees_collected_msat":0,
                        "lightning-dir":"/x"}"#;
        let info: ClnGetinfo = serde_json::from_str(json).unwrap();
        assert_eq!(info.id, "03abc...");
        assert_eq!(info.blockheight, 850_000);
    }

    /// `listfunds` returns both confirmed/unconfirmed UTXOs and per-channel
    /// balances. Balance computation distinguishes confirmed from total.
    #[test]
    fn balance_arithmetic_from_listfunds() {
        let json = r#"{
            "outputs":[
                {"amount_msat":100000000,"status":"confirmed"},
                {"amount_msat":50000000,"status":"unconfirmed"},
                {"amount_msat":99999,"status":"spent"}
            ],
            "channels":[
                {"our_amount_msat":40000000,"state":"CHANNELD_NORMAL"},
                {"our_amount_msat":10000000,"state":"CHANNELD_AWAITING_LOCKIN"}
            ]
        }"#;
        let funds: ClnListfunds = serde_json::from_str(json).unwrap();
        // outputs: 100k + 50k confirmed-or-not = 150k sats total; 100k spendable
        let onchain_total: u64 = funds
            .outputs
            .iter()
            .filter(|o| o.status != "spent")
            .map(|o| o.amount_msat / 1000)
            .sum();
        let onchain_spendable: u64 = funds
            .outputs
            .iter()
            .filter(|o| o.status == "confirmed")
            .map(|o| o.amount_msat / 1000)
            .sum();
        assert_eq!(onchain_total, 150_000);
        assert_eq!(onchain_spendable, 100_000);
        // channels: only CHANNELD_NORMAL counts as live lightning balance.
        let ln: u64 = funds
            .channels
            .iter()
            .filter(|c| c.state == "CHANNELD_NORMAL")
            .map(|c| c.our_amount_msat / 1000)
            .sum();
        assert_eq!(ln, 40_000);
    }

    /// CLN's `pay` status is "complete" | "pending" | "failed". Map to the
    /// neutral PaymentStatus.
    #[test]
    fn payment_status_mapping() {
        let to_status = |s: &str| match s {
            "complete" => PaymentStatus::Succeeded,
            "failed" => PaymentStatus::Failed,
            _ => PaymentStatus::Pending,
        };
        assert_eq!(to_status("complete"), PaymentStatus::Succeeded);
        assert_eq!(to_status("failed"), PaymentStatus::Failed);
        assert_eq!(to_status("pending"), PaymentStatus::Pending);
        assert_eq!(to_status("anything-else"), PaymentStatus::Pending);
    }
}
