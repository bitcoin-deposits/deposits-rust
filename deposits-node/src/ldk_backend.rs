// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! `LightningBackend` impl talking to LDK Server via `ldk-server-cli`.
//!
//! Shells out to the `ldk-server-cli` binary for each operation; the CLI
//! handles protobuf encoding and HMAC authentication against the ldk-server
//! HTTP API. Sibling impls (`LndBackend`, `ClnBackend`) land per
//! PACKAGING_PLAN.md Tier 1a; the trait surface stays unchanged.

use serde::Deserialize;
use std::process::Command;

use crate::Error;

/// Configuration for connecting to an LDK server
#[derive(Debug, Clone)]
pub struct LdkBackendConfig {
    /// Path to ldk-server-cli binary
    pub cli_path: String,
    /// LDK server host
    pub host: String,
    /// LDK server port
    pub port: u16,
    /// API key for authentication
    pub api_key: String,
    /// Path to TLS certificate
    pub tls_cert: Option<String>,
}

impl Default for LdkBackendConfig {
    fn default() -> Self {
        Self {
            cli_path: std::env::var("LDK_CLI").unwrap_or_else(|_| "ldk-server-cli".to_string()),
            host: std::env::var("LDK_HOST").unwrap_or_else(|_| "localhost".to_string()),
            port: std::env::var("LDK_PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(3000),
            api_key: std::env::var("LDK_API_KEY")
                .or_else(|_| {
                    std::fs::read_to_string("/data/ldk_api_key_hex").map(|s| s.trim().to_string())
                })
                .unwrap_or_else(|_| "test_api_key".to_string()),
            tls_cert: std::env::var("LDK_TLS_CERT").ok(),
        }
    }
}

impl LdkBackendConfig {
    /// Create from environment variables
    pub fn from_env() -> Self {
        Self::default()
    }
}

/// LDK Server client - uses ldk-server-cli binary
pub struct LdkBackend {
    config: LdkBackendConfig,
}

impl LdkBackend {
    /// Create a new LDK client
    pub fn new(config: LdkBackendConfig) -> Self {
        Self { config }
    }

    /// Create from environment variables
    pub fn from_env() -> Self {
        Self::new(LdkBackendConfig::from_env())
    }

    /// Run CLI command and return the JSON output
    fn run_command(&self, args: &[&str]) -> Result<String, Error> {
        let mut cmd = Command::new(&self.config.cli_path);

        // Add connection arguments
        cmd.arg("-b")
            .arg(format!("{}:{}", self.config.host, self.config.port));
        cmd.arg("-a").arg(&self.config.api_key);

        // Add TLS cert if specified
        if let Some(ref cert) = self.config.tls_cert {
            cmd.arg("-t").arg(cert);
        }

        // Add command arguments
        cmd.args(args);

        tracing::debug!("Running ldk-server-cli: {:?}", cmd);

        let output = cmd
            .output()
            .map_err(|e| Error::Protocol(format!("Failed to execute ldk-server-cli: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            return Err(Error::Protocol(format!(
                "ldk-server-cli failed: {} {}",
                stderr.trim(),
                stdout.trim()
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        Ok(stdout)
    }

    /// Get node info
    pub fn get_node_info(&self) -> Result<NodeInfo, Error> {
        let output = self.run_command(&["get-node-info"])?;
        serde_json::from_str(&output).map_err(|e| {
            Error::Protocol(format!(
                "Failed to parse node info: {} (output: {})",
                e, output
            ))
        })
    }

    /// Get balances
    pub fn get_balances(&self) -> Result<Balances, Error> {
        let output = self.run_command(&["get-balances"])?;
        serde_json::from_str(&output).map_err(|e| {
            Error::Protocol(format!(
                "Failed to parse balances: {} (output: {})",
                e, output
            ))
        })
    }

    /// Create a BOLT11 invoice
    pub fn create_invoice(&self, amount_msat: u64, description: &str) -> Result<String, Error> {
        // The fork's bolt11-receive defaults to a 24h expiry, which makes the
        // payer's fund-lock (invoice_expiry + settlement margin) needlessly
        // long. Callers that care pass an explicit expiry via
        // create_invoice_with_expiry; this no-expiry entry keeps the backend
        // default for non-pay paths (e.g. zaps).
        self.create_invoice_expiry(amount_msat, description, None)
    }

    /// Create a BOLT11 invoice with an explicit expiry (seconds). `None` →
    /// backend default. Shorter expiries shorten the payer's fund-lock window.
    pub fn create_invoice_expiry(
        &self,
        amount_msat: u64,
        description: &str,
        expiry_secs: Option<u32>,
    ) -> Result<String, Error> {
        tracing::info!(
            "Creating invoice via ldk-server-cli: {} msat (expiry {:?})",
            amount_msat,
            expiry_secs
        );
        let amount_str = format!("{}msat", amount_msat);
        let mut args = vec!["bolt11-receive", &amount_str, "--description", description];
        let exp_str;
        if let Some(e) = expiry_secs {
            exp_str = e.to_string();
            args.push("--expiry-secs");
            args.push(&exp_str);
        }
        let output = self.run_command(&args)?;

        let response: Bolt11ReceiveResponse = serde_json::from_str(&output).map_err(|e| {
            Error::Protocol(format!(
                "Failed to parse invoice response: {} (output: {})",
                e, output
            ))
        })?;
        Ok(response.invoice)
    }

    /// Create a BOLT11 invoice committing to a 32-byte description hash
    /// instead of a plaintext description. Required by NIP-57 zaps —
    /// the wallet sha256s the zap-request JSON and expects the invoice's
    /// `h` field to match exactly so the payment can be tied back to the
    /// zap request.
    pub fn create_invoice_with_desc_hash(
        &self,
        amount_msat: u64,
        desc_hash_hex: &str,
    ) -> Result<String, Error> {
        tracing::info!(
            "Creating invoice via ldk-server-cli: {} msat (desc_hash={})",
            amount_msat,
            &desc_hash_hex[..16.min(desc_hash_hex.len())]
        );
        let amount_str = format!("{}msat", amount_msat);
        let output = self.run_command(&[
            "bolt11-receive",
            &amount_str,
            "--description-hash",
            desc_hash_hex,
        ])?;

        let response: Bolt11ReceiveResponse = serde_json::from_str(&output).map_err(|e| {
            Error::Protocol(format!(
                "Failed to parse invoice response: {} (output: {})",
                e, output
            ))
        })?;
        Ok(response.invoice)
    }

    /// Create a variable amount BOLT11 invoice
    pub fn create_invoice_any_amount(&self, description: &str) -> Result<String, Error> {
        tracing::info!("Creating any-amount invoice via ldk-server-cli");
        let output = self.run_command(&["bolt11-receive", "--description", description])?;

        let response: Bolt11ReceiveResponse = serde_json::from_str(&output).map_err(|e| {
            Error::Protocol(format!(
                "Failed to parse invoice response: {} (output: {})",
                e, output
            ))
        })?;
        Ok(response.invoice)
    }

    /// Pay a BOLT11 invoice
    pub fn pay_invoice(&self, invoice: &str) -> Result<String, Error> {
        tracing::info!("Paying invoice via ldk-server-cli");
        let output = self.run_command(&["bolt11-send", invoice])?;

        let response: Bolt11SendResponse = serde_json::from_str(&output).map_err(|e| {
            Error::Protocol(format!(
                "Failed to parse payment response: {} (output: {})",
                e, output
            ))
        })?;
        Ok(response.payment_id)
    }

    /// Pay a BOLT11 invoice, capping total routing fees. The fork's
    /// `bolt11-send` takes `--max-total-routing-fee` (e.g. `50000msat`); LDK
    /// fails the payment if no route fits under it.
    pub fn pay_invoice_capped(&self, invoice: &str, max_fee_msat: u64) -> Result<String, Error> {
        tracing::info!(
            "Paying invoice via ldk-server-cli (routing cap {} msat)",
            max_fee_msat
        );
        let cap = format!("{}msat", max_fee_msat);
        let output =
            self.run_command(&["bolt11-send", invoice, "--max-total-routing-fee", &cap])?;

        let response: Bolt11SendResponse = serde_json::from_str(&output).map_err(|e| {
            Error::Protocol(format!(
                "Failed to parse payment response: {} (output: {})",
                e, output
            ))
        })?;
        Ok(response.payment_id)
    }

    /// Estimate the routing fee (msats) for a BOLT-11 without sending, via the
    /// fork's `bolt11-estimate-route-fee` command (find_route over the node's
    /// network graph). Errors (older sidecar without the command, no route
    /// found) propagate so the caller falls back to a heuristic.
    pub fn estimate_route_fee(&self, invoice: &str) -> Result<u64, Error> {
        let output = self.run_command(&["bolt11-estimate-route-fee", invoice])?;
        let v: serde_json::Value = serde_json::from_str(&output).map_err(|e| {
            Error::Protocol(format!("estimate-route-fee parse: {} (output: {})", e, output))
        })?;
        v.get("routing_fee_msat")
            .and_then(|x| x.as_u64())
            .ok_or_else(|| Error::Protocol(format!("estimate-route-fee: no routing_fee_msat in {}", output)))
    }

    /// Pay a BOLT11 invoice with a specific amount (for amountless invoices)
    pub fn pay_invoice_with_amount(
        &self,
        invoice: &str,
        amount_msat: u64,
    ) -> Result<String, Error> {
        tracing::info!(
            "Paying invoice via ldk-server-cli with amount: {} msat",
            amount_msat
        );
        let amount_str = format!("{}msat", amount_msat);
        let output = self.run_command(&["bolt11-send", invoice, &amount_str])?;

        let response: Bolt11SendResponse = serde_json::from_str(&output).map_err(|e| {
            Error::Protocol(format!(
                "Failed to parse payment response: {} (output: {})",
                e, output
            ))
        })?;
        Ok(response.payment_id)
    }

    /// List channels
    pub fn list_channels(&self) -> Result<ListChannelsResponse, Error> {
        let output = self.run_command(&["list-channels"])?;
        serde_json::from_str(&output).map_err(|e| {
            Error::Protocol(format!(
                "Failed to parse channels: {} (output: {})",
                e, output
            ))
        })
    }

    /// List payments
    pub fn list_payments(&self) -> Result<ListPaymentsResponse, Error> {
        let output = self.run_command(&["list-payments"])?;
        serde_json::from_str(&output).map_err(|e| {
            Error::Protocol(format!(
                "Failed to parse payments: {} (output: {})",
                e, output
            ))
        })
    }

    /// Look up a single payment by its `payment_id` (= payment_hash hex).
    /// Unlike `list-payments`, this returns INBOUND entries — invoices we
    /// created via `bolt11-receive` — and exposes the BOLT11 preimage in
    /// `payment.kind.kind.bolt11.preimage`. We need that on the self-pay
    /// path: the operator never sends a Lightning payment for invoices it
    /// settles internally, so it has to fish the preimage out of the
    /// receive-side record to commit a real proof-of-payment in
    /// `InvoiceFulfill.preimage`. Returns `Ok(None)` if LDK doesn't
    /// recognize the id.
    pub fn get_payment_preimage(
        &self,
        payment_id_hex: &str,
    ) -> Result<Option<[u8; 32]>, Error> {
        let output = match self.run_command(&["get-payment-details", payment_id_hex]) {
            Ok(s) => s,
            Err(e) => {
                // get-payment-details returns 404 / error on unknown id;
                // surface as None rather than propagating.
                tracing::debug!(
                    "get-payment-details {}: {} (treating as unknown)",
                    &payment_id_hex[..16.min(payment_id_hex.len())],
                    e
                );
                return Ok(None);
            }
        };
        let v: serde_json::Value = serde_json::from_str(&output).map_err(|e| {
            Error::Protocol(format!(
                "Failed to parse get-payment-details: {} (output: {})",
                e, output
            ))
        })?;
        // Path: payment.kind.kind.bolt11.preimage. The double `kind` nesting
        // mirrors LDK Server's discriminated-union JSON shape; we handle it
        // by walking instead of typing it out, since the variants for
        // BOLT12 / on-chain / etc. don't carry a preimage anyway.
        let preimage_hex = match v
            .pointer("/payment/kind/kind/bolt11/preimage")
            .and_then(|p| p.as_str())
        {
            Some(p) => p,
            None => return Ok(None),
        };
        let bytes = hex::decode(preimage_hex).map_err(|e| {
            Error::Protocol(format!("Bad preimage hex from LDK: {}", e))
        })?;
        if bytes.len() != 32 {
            return Err(Error::Protocol(format!(
                "Preimage from LDK was {} bytes, want 32",
                bytes.len()
            )));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(Some(out))
    }

    // ── Hold invoices — via the fork's for-hash command set ─────────────────
    //
    // Requires an ldk-server built from our fork (or upstream ≥ the rev that
    // added the for-hash commands + GetClaimableDetails). The probe below
    // detects an older sidecar and degrades to no-hold-support instead of
    // failing at first use.

    /// Probe: does the installed ldk-server-cli know the for-hash command
    /// set? `--help` on a subcommand exits 0 iff clap recognizes it; no
    /// server round-trip involved.
    pub fn probe_hold_invoice_support(&self) -> bool {
        let out = std::process::Command::new(&self.config.cli_path)
            .args(["bolt11-receive-for-hash", "--help"])
            .output();
        match out {
            Ok(o) if o.status.success() => true,
            _ => {
                tracing::info!(
                    "ldk-server-cli lacks bolt11-receive-for-hash — hold invoices \
                     disabled. Rebuild ldk-server from the deposits fork to enable \
                     bridge-receive."
                );
                false
            }
        }
    }
}

// -- Status deserializer (handles both u8 and string formats) --

fn deserialize_status<'de, D>(deserializer: D) -> Result<u8, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de;

    struct StatusVisitor;
    impl<'de> de::Visitor<'de> for StatusVisitor {
        type Value = u8;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a status number or string")
        }
        fn visit_u64<E: de::Error>(self, v: u64) -> Result<u8, E> {
            Ok(v as u8)
        }
        fn visit_str<E: de::Error>(self, v: &str) -> Result<u8, E> {
            match v.to_lowercase().as_str() {
                "pending" => Ok(0),
                "succeeded" | "complete" | "completed" => Ok(1),
                "failed" | "expired" => Ok(2),
                _ => Ok(0),
            }
        }
    }
    deserializer.deserialize_any(StatusVisitor)
}

// Response types for parsing CLI JSON output

#[derive(Debug, Deserialize)]
pub struct NodeInfo {
    pub node_id: String,
    pub current_best_block: Option<BlockInfo>,
    pub latest_lightning_wallet_sync_timestamp: Option<u64>,
    pub latest_onchain_wallet_sync_timestamp: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct BlockInfo {
    pub block_hash: String,
    pub height: u32,
}

#[derive(Debug, Deserialize)]
pub struct Balances {
    pub total_onchain_balance_sats: u64,
    pub spendable_onchain_balance_sats: u64,
    pub total_anchor_channels_reserve_sats: u64,
    pub total_lightning_balance_sats: u64,
}

#[derive(Debug, Deserialize)]
pub struct Bolt11ReceiveResponse {
    pub invoice: String,
}

#[derive(Debug, Deserialize)]
pub struct Bolt11SendResponse {
    pub payment_id: String,
}

#[derive(Debug, Deserialize)]
pub struct ListChannelsResponse {
    pub channels: Vec<ChannelInfo>,
}

#[derive(Debug, Deserialize)]
pub struct ChannelInfo {
    pub channel_id: String,
    pub counterparty_node_id: String,
    pub channel_value_sats: u64,
    pub outbound_capacity_msat: u64,
    pub inbound_capacity_msat: u64,
    pub is_usable: bool,
    pub is_channel_ready: bool,
}

#[derive(Debug, Deserialize)]
pub struct ListPaymentsResponse {
    /// Newer ldk-server-cli uses "list", older uses "payments"
    #[serde(alias = "list")]
    pub payments: Vec<PaymentInfo>,
}

#[derive(Debug, Deserialize)]
pub struct PaymentInfo {
    #[serde(alias = "payment_id")]
    pub id: String,
    #[serde(deserialize_with = "deserialize_status")]
    pub status: u8, // 0 = pending, 1 = succeeded, 2 = failed
    pub amount_msat: Option<u64>,
    pub preimage: Option<String>,
}

// -- LightningBackend impl --
//
// Adapts the LDK-shaped response types above to the neutral types the
// `LightningBackend` trait declares. See deposits-node/src/lightning_backend.rs
// for the design rationale; per PACKAGING_PLAN.md Tier 1 this is the first
// of three backends (LDK, LND, CLN) the daemon will eventually swap between
// at startup. The inherent methods on `LdkBackend` stay so existing callers
// don't break; the trait impl just forwards and converts.

use crate::lightning_backend::{
    Balances as BackendBalances, ChannelInfo as BackendChannelInfo, HoldInvoiceState,
    LightningBackend, NodeInfo as BackendNodeInfo, PaymentInfo as BackendPaymentInfo,
    PaymentStatus,
};

impl LightningBackend for LdkBackend {
    fn get_node_info(&self) -> Result<BackendNodeInfo, Error> {
        let info = self.get_node_info()?;
        Ok(BackendNodeInfo {
            node_id: info.node_id,
            current_best_block_height: info.current_best_block.as_ref().map(|b| b.height),
            current_best_block_hash: info.current_best_block.map(|b| b.block_hash),
        })
    }

    fn get_balances(&self) -> Result<BackendBalances, Error> {
        let b = self.get_balances()?;
        Ok(BackendBalances {
            onchain_total_sats: b.total_onchain_balance_sats,
            onchain_spendable_sats: b.spendable_onchain_balance_sats,
            lightning_total_sats: b.total_lightning_balance_sats,
        })
    }

    fn create_invoice(&self, amount_msat: u64, description: &str) -> Result<String, Error> {
        LdkBackend::create_invoice(self, amount_msat, description)
    }

    fn create_invoice_with_expiry(
        &self,
        amount_msat: u64,
        description: &str,
        expiry_secs: u32,
    ) -> Result<String, Error> {
        LdkBackend::create_invoice_expiry(self, amount_msat, description, Some(expiry_secs))
    }

    fn create_invoice_with_desc_hash(
        &self,
        amount_msat: u64,
        desc_hash_hex: &str,
    ) -> Result<String, Error> {
        LdkBackend::create_invoice_with_desc_hash(self, amount_msat, desc_hash_hex)
    }

    fn create_invoice_any_amount(&self, description: &str) -> Result<String, Error> {
        LdkBackend::create_invoice_any_amount(self, description)
    }

    fn pay_invoice(&self, invoice: &str) -> Result<String, Error> {
        LdkBackend::pay_invoice(self, invoice)
    }

    fn pay_invoice_with_amount(
        &self,
        invoice: &str,
        amount_msat: u64,
    ) -> Result<String, Error> {
        LdkBackend::pay_invoice_with_amount(self, invoice, amount_msat)
    }

    fn pay_invoice_with_fee_cap(
        &self,
        invoice: &str,
        max_fee_msat: u64,
    ) -> Result<String, Error> {
        LdkBackend::pay_invoice_capped(self, invoice, max_fee_msat)
    }

    fn estimate_routing_fee(&self, invoice: &str) -> Result<u64, Error> {
        LdkBackend::estimate_route_fee(self, invoice)
    }

    fn list_channels(&self) -> Result<Vec<BackendChannelInfo>, Error> {
        let resp = LdkBackend::list_channels(self)?;
        Ok(resp
            .channels
            .into_iter()
            .map(|c| BackendChannelInfo {
                channel_id: c.channel_id,
                counterparty_node_id: c.counterparty_node_id,
                capacity_sats: c.channel_value_sats,
                outbound_capacity_msat: c.outbound_capacity_msat,
                inbound_capacity_msat: c.inbound_capacity_msat,
                is_usable: c.is_usable,
                is_ready: c.is_channel_ready,
            })
            .collect())
    }

    fn list_payments(&self) -> Result<Vec<BackendPaymentInfo>, Error> {
        let resp = LdkBackend::list_payments(self)?;
        Ok(resp
            .payments
            .into_iter()
            .map(|p| BackendPaymentInfo {
                id: p.id,
                status: match p.status {
                    1 => PaymentStatus::Succeeded,
                    2 => PaymentStatus::Failed,
                    _ => PaymentStatus::Pending,
                },
                amount_msat: p.amount_msat,
                preimage_hex: p.preimage,
            })
            .collect())
    }

    fn get_payment_preimage(
        &self,
        payment_id_hex: &str,
    ) -> Result<Option<[u8; 32]>, Error> {
        LdkBackend::get_payment_preimage(self, payment_id_hex)
    }

    // ── Hold invoices ───────────────────────────────────────────────────────

    fn supports_hold_invoices(&self) -> bool {
        self.probe_hold_invoice_support()
    }

    fn create_hold_invoice(
        &self,
        amount_msat: u64,
        payment_hash_hex: &str,
        description: &str,
        expiry_secs: u32,
        // ldk-node's receive_for_hash has no CLTV parameter — the window is
        // fixed at min_final_cltv (24) minus LDK's fail-back buffer (~18
        // usable blocks). Measured via lookup, per the trait contract.
        _cltv_expiry_delta: Option<u16>,
    ) -> Result<String, Error> {
        let amount_arg = format!("{}msat", amount_msat);
        let expiry_arg = expiry_secs.to_string();
        let output = self.run_command(&[
            "bolt11-receive-for-hash",
            payment_hash_hex,
            &amount_arg,
            "--description",
            description,
            "--expiry-secs",
            &expiry_arg,
        ])?;
        let v: serde_json::Value = serde_json::from_str(&output).map_err(|e| {
            Error::Protocol(format!(
                "Failed to parse bolt11-receive-for-hash: {} (output: {})",
                e, output
            ))
        })?;
        v.get("invoice")
            .and_then(|i| i.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| {
                Error::Protocol(format!(
                    "bolt11-receive-for-hash response missing invoice: {}",
                    output
                ))
            })
    }

    fn lookup_hold_invoice(
        &self,
        payment_hash_hex: &str,
    ) -> Result<HoldInvoiceState, Error> {
        // Terminal states come from the payment record; the held/accepted
        // distinction comes from the fork's GetClaimableDetails (the
        // PaymentClaimable event tracking — PaymentDetails alone reports
        // Pending for both "unpaid" and "HTLCs parked").
        let details = self.run_command(&["get-payment-details", payment_hash_hex]);
        if let Ok(output) = details {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&output) {
                match v
                    .pointer("/payment/status")
                    .and_then(|s| s.as_str())
                    .unwrap_or("")
                    .to_ascii_uppercase()
                    .as_str()
                {
                    "SUCCEEDED" => return Ok(HoldInvoiceState::Settled),
                    "FAILED" => return Ok(HoldInvoiceState::Canceled),
                    _ => {}
                }
            }
        }

        let output = self.run_command(&["get-claimable-details", payment_hash_hex])?;
        let v: serde_json::Value = serde_json::from_str(&output).map_err(|e| {
            Error::Protocol(format!(
                "Failed to parse get-claimable-details: {} (output: {})",
                e, output
            ))
        })?;
        if v.get("claimable").and_then(|c| c.as_bool()).unwrap_or(false) {
            Ok(HoldInvoiceState::Accepted {
                htlc_expiry_height: v
                    .get("claim_deadline")
                    .and_then(|d| d.as_u64())
                    .map(|d| d as u32),
            })
        } else {
            Ok(HoldInvoiceState::Open)
        }
    }

    fn settle_hold_invoice(&self, preimage_hex: &str) -> Result<(), Error> {
        let _ = self.run_command(&["bolt11-claim-for-hash", preimage_hex])?;
        Ok(())
    }

    fn cancel_hold_invoice(&self, payment_hash_hex: &str) -> Result<(), Error> {
        let _ = self.run_command(&["bolt11-fail-for-hash", payment_hash_hex])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_from_env() {
        let config = LdkBackendConfig::default();
        assert_eq!(config.port, 3000);
    }

    /// Compile-time check: `LdkBackend` actually satisfies the
    /// `LightningBackend` trait. If the trait or impl drifts, this fails
    /// to type-check before runtime exercises it.
    #[test]
    fn ldk_backend_implements_lightning_backend() {
        fn assert_backend<T: LightningBackend>() {}
        assert_backend::<LdkBackend>();
    }
}
