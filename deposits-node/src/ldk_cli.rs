// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! LDK Server client for Lightning operations
//!
//! This module provides a client for ldk-server via the ldk-server-cli binary.
//! The CLI handles the protobuf encoding and HMAC authentication required by ldk-server.

use serde::Deserialize;
use std::process::Command;

use crate::Error;

/// Configuration for connecting to an LDK server
#[derive(Debug, Clone)]
pub struct LdkCliConfig {
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

impl Default for LdkCliConfig {
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

impl LdkCliConfig {
    /// Create from environment variables
    pub fn from_env() -> Self {
        Self::default()
    }
}

/// LDK Server client - uses ldk-server-cli binary
pub struct LdkCli {
    config: LdkCliConfig,
}

impl LdkCli {
    /// Create a new LDK client
    pub fn new(config: LdkCliConfig) -> Self {
        Self { config }
    }

    /// Create from environment variables
    pub fn from_env() -> Self {
        Self::new(LdkCliConfig::from_env())
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
        tracing::info!("Creating invoice via ldk-server-cli: {} msat", amount_msat);
        let amount_str = format!("{}msat", amount_msat);
        let output =
            self.run_command(&["bolt11-receive", &amount_str, "--description", description])?;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_from_env() {
        let config = LdkCliConfig::default();
        assert_eq!(config.port, 3000);
    }
}
