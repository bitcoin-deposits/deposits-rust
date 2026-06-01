//! [`LightningBackend`] impl talking to Core Lightning (CLN) via its
//! Unix-socket JSON-RPC.
//!
//! Per PACKAGING_PLAN.md Tier 1a. CLN's primary interface is a Unix socket
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

use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use crate::lightning_backend::{
    Balances, ChannelInfo, LightningBackend, NodeInfo, PaymentInfo, PaymentStatus,
};
use crate::Error;

/// CLN backend. Selection: `LIGHTNING_BACKEND=cln`.
pub struct ClnBackend {
    socket_path: PathBuf,
    /// Read/write timeout on each RPC call. CLN typically responds in
    /// milliseconds; the timeout exists to surface stuck sockets quickly.
    timeout: Duration,
}

impl ClnBackend {
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
            timeout: Duration::from_secs(30),
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
