// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! LDK Server client for Lightning operations
//!
//! This module provides a client for ldk-server's REST API. It can use either:
//! - Direct HTTP calls (preferred, no external binary needed)
//! - Shell out to ldk-server-cli (fallback if HTTP fails)

use std::process::Command;
use serde::{Deserialize, Serialize};

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
    /// Path to TLS certificate (optional, for self-signed certs)
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
            api_key: std::env::var("LDK_API_KEY").unwrap_or_else(|_| "test_api_key".to_string()),
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

/// LDK Server client - uses HTTP API directly
pub struct LdkCli {
    config: LdkCliConfig,
    http_client: reqwest::blocking::Client,
}

impl LdkCli {
    /// Create a new LDK client
    pub fn new(config: LdkCliConfig) -> Self {
        let http_client = reqwest::blocking::Client::builder()
            .danger_accept_invalid_certs(true)  // For self-signed certs in dev
            .build()
            .unwrap_or_else(|_| reqwest::blocking::Client::new());

        Self { config, http_client }
    }

    /// Create from environment variables
    pub fn from_env() -> Self {
        Self::new(LdkCliConfig::from_env())
    }

    /// Get the base URL for the LDK server
    fn base_url(&self) -> String {
        format!("https://{}:{}", self.config.host, self.config.port)
    }

    /// Make an HTTP POST request to the LDK server
    fn http_post<T: Serialize, R: for<'de> Deserialize<'de>>(&self, endpoint: &str, body: &T) -> Result<R, Error> {
        let url = format!("{}{}", self.base_url(), endpoint);

        let response = self.http_client
            .post(&url)
            .header("X-Auth", &self.config.api_key)
            .json(body)
            .send()
            .map_err(|e| Error::Protocol(format!("HTTP request failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().unwrap_or_default();
            return Err(Error::Protocol(format!("LDK server error {}: {}", status, body)));
        }

        response.json::<R>()
            .map_err(|e| Error::Protocol(format!("Failed to parse response: {}", e)))
    }

    /// Make an HTTP GET request to the LDK server
    fn http_get<R: for<'de> Deserialize<'de>>(&self, endpoint: &str) -> Result<R, Error> {
        let url = format!("{}{}", self.base_url(), endpoint);

        let response = self.http_client
            .get(&url)
            .header("X-Auth", &self.config.api_key)
            .send()
            .map_err(|e| Error::Protocol(format!("HTTP request failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().unwrap_or_default();
            return Err(Error::Protocol(format!("LDK server error {}: {}", status, body)));
        }

        response.json::<R>()
            .map_err(|e| Error::Protocol(format!("Failed to parse response: {}", e)))
    }

    /// Fallback: Run CLI command and return the JSON output
    fn run_command(&self, args: &[&str]) -> Result<String, Error> {
        let mut cmd = Command::new(&self.config.cli_path);

        // Add connection arguments
        cmd.arg("-b").arg(format!("{}:{}", self.config.host, self.config.port));
        cmd.arg("-a").arg(&self.config.api_key);

        // Add TLS cert if specified
        if let Some(ref cert) = self.config.tls_cert {
            cmd.arg("-t").arg(cert);
        }

        // Add command arguments
        cmd.args(args);

        let output = cmd.output()
            .map_err(|e| Error::Protocol(format!("Failed to execute ldk-server-cli: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::Protocol(format!("ldk-server-cli failed: {}", stderr)));
        }

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        Ok(stdout)
    }

    /// Get node info
    pub fn get_node_info(&self) -> Result<NodeInfo, Error> {
        let output = self.run_command(&["get-node-info"])?;
        serde_json::from_str(&output)
            .map_err(|e| Error::Protocol(format!("Failed to parse node info: {}", e)))
    }

    /// Get balances
    pub fn get_balances(&self) -> Result<Balances, Error> {
        let output = self.run_command(&["get-balances"])?;
        serde_json::from_str(&output)
            .map_err(|e| Error::Protocol(format!("Failed to parse balances: {}", e)))
    }

    /// Create a BOLT11 invoice via HTTP API
    pub fn create_invoice(&self, amount_msat: u64, description: &str) -> Result<String, Error> {
        #[derive(Serialize)]
        struct Bolt11ReceiveRequest {
            amount_msat: Option<u64>,
            description: String,
            expiry_secs: Option<u64>,
        }

        let request = Bolt11ReceiveRequest {
            amount_msat: Some(amount_msat),
            description: description.to_string(),
            expiry_secs: Some(3600),
        };

        tracing::info!("Creating invoice via {}/bolt11/receive", self.base_url());
        let response: Bolt11ReceiveResponse = self.http_post("/bolt11/receive", &request)?;
        Ok(response.invoice)
    }

    /// Create a variable amount BOLT11 invoice
    pub fn create_invoice_any_amount(&self, description: &str) -> Result<String, Error> {
        #[derive(Serialize)]
        struct Bolt11ReceiveRequest {
            amount_msat: Option<u64>,
            description: String,
            expiry_secs: Option<u64>,
        }

        let request = Bolt11ReceiveRequest {
            amount_msat: None,
            description: description.to_string(),
            expiry_secs: Some(3600),
        };

        tracing::info!("Creating invoice via {}/bolt11/receive", self.base_url());
        let response: Bolt11ReceiveResponse = self.http_post("/bolt11/receive", &request)?;
        Ok(response.invoice)
    }

    /// Pay a BOLT11 invoice via HTTP API
    pub fn pay_invoice(&self, invoice: &str) -> Result<String, Error> {
        #[derive(Serialize)]
        struct Bolt11SendRequest {
            invoice: String,
            amount_msat: Option<u64>,
        }

        let request = Bolt11SendRequest {
            invoice: invoice.to_string(),
            amount_msat: None,
        };

        tracing::info!("Paying invoice via {}/bolt11/send", self.base_url());
        let response: Bolt11SendResponse = self.http_post("/bolt11/send", &request)?;
        Ok(response.payment_id)
    }

    /// Pay a BOLT11 invoice with a specific amount (for amountless invoices)
    pub fn pay_invoice_with_amount(&self, invoice: &str, amount_msat: u64) -> Result<String, Error> {
        #[derive(Serialize)]
        struct Bolt11SendRequest {
            invoice: String,
            amount_msat: Option<u64>,
        }

        let request = Bolt11SendRequest {
            invoice: invoice.to_string(),
            amount_msat: Some(amount_msat),
        };

        tracing::info!("Paying invoice via {}/bolt11/send", self.base_url());
        let response: Bolt11SendResponse = self.http_post("/bolt11/send", &request)?;
        Ok(response.payment_id)
    }

    /// List channels
    pub fn list_channels(&self) -> Result<ListChannelsResponse, Error> {
        let output = self.run_command(&["list-channels"])?;
        serde_json::from_str(&output)
            .map_err(|e| Error::Protocol(format!("Failed to parse channels: {}", e)))
    }

    /// List payments
    pub fn list_payments(&self) -> Result<ListPaymentsResponse, Error> {
        let output = self.run_command(&["list-payments"])?;
        serde_json::from_str(&output)
            .map_err(|e| Error::Protocol(format!("Failed to parse payments: {}", e)))
    }
}

// Response types

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
    pub payments: Vec<PaymentInfo>,
}

#[derive(Debug, Deserialize)]
pub struct PaymentInfo {
    pub id: String,
    pub status: u8,  // 0 = pending, 1 = succeeded, 2 = failed
    pub amount_msat: Option<u64>,
    pub preimage: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_from_env() {
        // Just test that default config is created
        let config = LdkCliConfig::default();
        assert_eq!(config.port, 3000);
    }
}
