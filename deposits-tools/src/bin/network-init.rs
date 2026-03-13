use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::sleep;
use clap::{Arg, Command};
use deposits_tools::network_config::{Network, NetworkConfig, NodeConfig};
// TODO: These service types were protobuf-generated in deposits-ldk, which has been removed.
// This binary needs to be updated to use the deposits-node API.
// Stub types to keep the binary compiling:
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListLedgersRequest {}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListLedgersResponse {
    #[prost(message, repeated, tag = "1")]
    pub ledgers: Vec<LedgerInfoStub>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LedgerInfoStub {
    #[prost(string, tag = "1")]
    pub ledger_id: String,
    #[prost(string, tag = "2")]
    pub partner_node_id: String,
}

mod endpoints {
    pub const DEPOSITS_LIST_LEDGERS_PATH: &str = "/v1/deposits/list-ledgers";
}

use prost::Message;
use hmac::{Hmac, Mac};
use sha2::Sha256;

const API_KEY: &str = "test_api_key";

// Simple protobuf messages for ldk-server API
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetNodeInfoResponse {
    #[prost(string, tag = "1")]
    pub node_id: String,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct OnchainReceiveResponse {
    #[prost(string, tag = "1")]
    pub address: String,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetBalancesResponse {
    #[prost(uint64, tag = "1")]
    pub total_onchain_balance_sats: u64,
    #[prost(uint64, tag = "2")]
    pub spendable_onchain_balance_sats: u64,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct OpenChannelRequest {
    #[prost(string, tag = "1")]
    pub node_pubkey: String,
    #[prost(string, tag = "2")]
    pub address: String,
    #[prost(uint64, tag = "3")]
    pub channel_amount_sats: u64,
    #[prost(uint64, optional, tag = "4")]
    pub push_to_counterparty_msat: Option<u64>,
    #[prost(bool, tag = "6")]
    pub announce_channel: bool,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct OpenChannelResponse {
    #[prost(string, tag = "1")]
    pub user_channel_id: String,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListChannelsResponse {
    #[prost(message, repeated, tag = "1")]
    pub channels: Vec<ChannelInfo>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ChannelInfo {
    #[prost(string, tag = "2")]
    pub counterparty_node_id: String,
    #[prost(bool, tag = "13")]
    pub is_channel_ready: bool,
    #[prost(bool, tag = "14")]
    pub is_usable: bool,
}

/// Compute HMAC-SHA256 auth header for ldk-server
/// Format: "HMAC <timestamp>:<hmac_hex>"
fn compute_auth_header(body: &[u8]) -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("System time should be after Unix epoch")
        .as_secs();

    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(API_KEY.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(&timestamp.to_be_bytes());
    mac.update(body);
    let result = mac.finalize();
    let hmac_hex = hex::encode(result.into_bytes());

    format!("HMAC {}:{}", timestamp, hmac_hex)
}

#[derive(Debug, Serialize, Deserialize)]
struct ApiResponse<T> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct NodeInfo {
    node_id: String,
    listening_addresses: Vec<String>,
    num_channels: usize,
    num_peers: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct BitcoinAddress {
    address: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct BitcoinBalance {
    balance_sat: u64,
    pending_balance_sat: u64,
}

// ConnectPeerRequest removed - using OpenChannel address field instead

#[derive(Debug, Serialize, Deserialize)]
struct BitcoinRpcRequest {
    jsonrpc: String,
    method: String,
    params: serde_json::Value,
    id: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct BitcoinRpcResponse {
    result: Option<serde_json::Value>,
    error: Option<serde_json::Value>,
    id: u32,
}

// JSON ChannelInfo and ChannelsResponse removed - using protobuf ListChannelsResponse instead

#[derive(Debug, Serialize, Deserialize)]
struct ChainInfo {
    block_height: u64,
}


struct NetworkInitializer {
    client: Client,
    network: Network,
    nodes: HashMap<String, NodeConfig>,
    node_pubkeys: HashMap<String, String>,
    channels: HashMap<String, String>,
}

impl NetworkInitializer {
    fn new(network: Network) -> Self {
        let nodes = NetworkConfig::nodes_for_network(network);

        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .danger_accept_invalid_certs(true)  // Accept self-signed certs for dev
                .build()
                .expect("Failed to create HTTP client"),
            network,
            nodes,
            node_pubkeys: HashMap::new(),
            channels: HashMap::new(),
        }
    }

    fn with_nodes(mut self, node_names: Vec<String>) -> Self {
        if !node_names.is_empty() {
            // Filter nodes to only include specified ones
            let mut filtered_nodes = HashMap::new();
            for node_name in node_names {
                if let Some(config) = self.nodes.remove(&node_name) {
                    filtered_nodes.insert(node_name, config);
                } else {
                    eprintln!("Warning: Unknown node '{}' specified", node_name);
                }
            }
            self.nodes = filtered_nodes;
        }
        self
    }

    fn log(&self, message: &str) {
        let timestamp = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S");
        println!("\x1b[32m[{}] INFO: {}\x1b[0m", timestamp, message);
    }

    fn error(&self, message: &str) {
        let timestamp = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S");
        eprintln!("\x1b[31m[{}] ERROR: {}\x1b[0m", timestamp, message);
    }

    fn warn(&self, message: &str) {
        let timestamp = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S");
        println!("\x1b[33m[{}] WARNING: {}\x1b[0m", timestamp, message);
    }

    async fn bitcoin_rpc(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        // Determine if this method requires wallet access
        let wallet_methods = ["getnewaddress", "sendtoaddress", "getbalance", "listunspent"];
        let endpoint = if wallet_methods.contains(&method) {
            "http://localhost:18443/wallet/default"
        } else {
            "http://localhost:18443/"
        };

        let request = BitcoinRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: method.to_string(),
            params,
            id: 1,
        };

        let response = self.client
            .post(endpoint)
            .basic_auth("user", Some("pass"))
            .json(&request)
            .send()
            .await?;

        let rpc_response: BitcoinRpcResponse = response.json().await?;

        if let Some(error) = rpc_response.error {
            return Err(format!("Bitcoin RPC error: {}", error).into());
        }

        Ok(rpc_response.result.unwrap_or(serde_json::Value::Null))
    }

    async fn get_bitcoin_height(&self) -> Result<u64, Box<dyn std::error::Error>> {
        let result = self.bitcoin_rpc("getblockcount", serde_json::json!([])).await?;
        Ok(result.as_u64().unwrap_or(0))
    }

    async fn wait_for_all_nodes_sync(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Just a brief pause - electrs will handle the sync
        // Mining in small batches means nodes stay mostly in sync anyway
        sleep(Duration::from_millis(500)).await;
        Ok(())
    }

    async fn mine_blocks_safely(&self, count: u32, reason: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.log(&format!("⛏️ Mining {} blocks for: {}", count, reason));

        let address = self.bitcoin_rpc("getnewaddress", serde_json::json!([])).await?;
        let address_str = address.as_str().unwrap();

        // Determine batch size based on count - use larger batches for initial funding
        let batch_size = if count > 50 {
            10  // Larger batches for initial 101 block mining
        } else {
            3   // Smaller batches for channel confirmations
        };

        let mut remaining = count;

        while remaining > 0 {
            let batch = remaining.min(batch_size);

            // Mine the batch
            self.bitcoin_rpc("generatetoaddress", serde_json::json!([batch, address_str])).await?;
            remaining -= batch;

            // Brief pause for nodes to sync
            self.wait_for_all_nodes_sync().await?;
        }

        self.log(&format!("✅ Successfully mined {} blocks with sync", count));
        Ok(())
    }

    async fn wait_for_funding_transactions(&self, expected_count: usize) -> Result<(), Box<dyn std::error::Error>> {
        self.log(&format!("⏳ Waiting for {} funding transaction(s) to appear in mempool...", expected_count));

        let timeout = Duration::from_secs(60);
        let poll_interval = Duration::from_secs(2);
        let start = std::time::Instant::now();

        loop {
            // Get mempool size
            let result = self.bitcoin_rpc("getmempoolinfo", serde_json::json!([])).await?;
            let mempool_size = result.get("size").and_then(|s| s.as_u64()).unwrap_or(0) as usize;

            if mempool_size >= expected_count {
                self.log(&format!("✅ Found {} transaction(s) in mempool", mempool_size));
                return Ok(());
            }

            if start.elapsed() > timeout {
                self.warn(&format!("⚠️ Timeout waiting for funding transactions (found {} of {} expected)", mempool_size, expected_count));
                // Don't fail - some channels may have been created, proceed with mining
                return Ok(());
            }

            sleep(poll_interval).await;
        }
    }

    // Helper method that can call ANY node (not just selected ones)
    async fn ldk_api_call_any<T>(&self, node_config: &NodeConfig, endpoint: &str, method: &str, data: Option<serde_json::Value>) -> Result<ApiResponse<T>, Box<dyn std::error::Error>>
    where
        T: for<'de> Deserialize<'de>,
    {
        let url = format!("https://localhost:{}{}", node_config.api_port, endpoint);

        let body = data.as_ref()
            .map(|json| serde_json::to_vec(json).unwrap_or_default())
            .unwrap_or_default();
        let auth_header = compute_auth_header(&body);

        let request = match method {
            "GET" => self.client.get(&url).header("X-Auth", auth_header),
            "POST" => {
                self.client.post(&url)
                    .header("X-Auth", auth_header)
                    .header("Content-Type", "application/json")
                    .body(body)
            }
            _ => return Err(format!("Unsupported HTTP method: {}", method).into()),
        };

        let response = request.send().await?;
        let api_response: ApiResponse<T> = response.json().await?;

        Ok(api_response)
    }

    async fn ldk_api_call<T>(&self, node: &str, endpoint: &str, method: &str, data: Option<serde_json::Value>) -> Result<ApiResponse<T>, Box<dyn std::error::Error>>
    where
        T: for<'de> Deserialize<'de>,
    {
        let node_config = self.nodes.get(node)
            .ok_or_else(|| format!("Unknown node: {}", node))?;

        let url = format!("https://localhost:{}{}", node_config.api_port, endpoint);

        let body = data.as_ref()
            .map(|json| serde_json::to_vec(json).unwrap_or_default())
            .unwrap_or_default();
        let auth_header = compute_auth_header(&body);

        let request = match method {
            "GET" => self.client.get(&url).header("X-Auth", auth_header),
            "POST" => {
                self.client.post(&url)
                    .header("X-Auth", auth_header)
                    .header("Content-Type", "application/json")
                    .body(body)
            }
            _ => return Err(format!("Unsupported HTTP method: {}", method).into()),
        };

        let response = request.send().await?;
        let api_response: ApiResponse<T> = response.json().await?;

        Ok(api_response)
    }

    /// Make a protobuf API call to a deposits endpoint
    async fn proto_request<Req: Message, Resp: Message + Default>(
        &self,
        node: &str,
        path: &str,
        request: Req,
    ) -> Result<Resp, Box<dyn std::error::Error>> {
        let node_config = self.nodes.get(node)
            .ok_or_else(|| format!("Unknown node: {}", node))?;

        let url = format!("https://localhost:{}{}", node_config.api_port, path);
        let body = request.encode_to_vec();
        let auth_header = compute_auth_header(&body);

        let response = self.client
            .post(&url)
            .header("Content-Type", "application/octet-stream")
            .header("X-Auth", auth_header)
            .body(body)
            .send()
            .await?;

        let status = response.status();
        let bytes = response.bytes().await?;

        if !status.is_success() {
            return Err(format!("HTTP {}: {}", status, String::from_utf8_lossy(&bytes)).into());
        }

        let resp = Resp::decode(bytes.as_ref())?;
        Ok(resp)
    }

    async fn wait_for_nodes(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.log("🔄 Waiting for all LDK nodes to be ready...");

        for (node_id, node_config) in &self.nodes {
            let max_retries = 30;
            let mut retry_count = 0;

            while retry_count < max_retries {
                // Use GetNodeInfo protobuf endpoint to check if node is ready
                let url = format!("https://localhost:{}/GetNodeInfo", node_config.api_port);
                let body: Vec<u8> = vec![];  // Empty protobuf request
                let auth_header = compute_auth_header(&body);
                let result = self.client
                    .post(&url)
                    .header("Content-Type", "application/octet-stream")
                    .header("X-Auth", auth_header)
                    .body(body)
                    .send()
                    .await;

                match result {
                    Ok(response) if response.status().is_success() => {
                        self.log(&format!("✅ {} is ready", node_config.name));
                        break;
                    }
                    _ => {
                        retry_count += 1;
                        if retry_count < max_retries {
                            sleep(Duration::from_secs(2)).await;
                        } else {
                            return Err(format!("❌ {} failed to start after {} seconds",
                                node_config.name, max_retries * 2).into());
                        }
                    }
                }
            }
        }

        self.log("✅ All LDK nodes are ready");
        Ok(())
    }

    async fn setup_bitcoin_funding(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.log("💰 Setting up Bitcoin funding...");

        // Ensure Bitcoin wallet exists
        match self.bitcoin_rpc("createwallet", serde_json::json!(["default"])).await {
            Ok(_) => {
                self.log("✅ Created Bitcoin wallet");
            }
            Err(_) => {
                // Wallet might already exist, try to load it
                match self.bitcoin_rpc("loadwallet", serde_json::json!(["default"])).await {
                    Ok(_) => {
                        self.log("✅ Loaded existing Bitcoin wallet");
                    }
                    Err(_) => {
                        self.log("ℹ️ Bitcoin wallet already active");
                    }
                }
            }
        }

        // Generate initial blocks using safe mining
        self.mine_blocks_safely(101, "Bitcoin coinbase maturity").await?;

        // Get node addresses and fund them using OnchainReceive protobuf endpoint
        for (_node_id, node_config) in &self.nodes {
            let url = format!("https://localhost:{}/OnchainReceive", node_config.api_port);
            let body: Vec<u8> = vec![];  // Empty request
            let auth_header = compute_auth_header(&body);

            match self.client
                .post(&url)
                .header("Content-Type", "application/octet-stream")
                .header("X-Auth", auth_header)
                .body(body)
                .send()
                .await
            {
                Ok(response) if response.status().is_success() => {
                    let bytes = response.bytes().await?;
                    if let Ok(addr_resp) = OnchainReceiveResponse::decode(bytes.as_ref()) {
                        self.bitcoin_rpc("sendtoaddress", serde_json::json!([addr_resp.address, 1.0])).await?;
                        self.log(&format!("💸 Sent 1 BTC to {} ({})", node_config.name, addr_resp.address));
                    }
                }
                _ => {
                    self.warn(&format!("⚠️ Could not get address for {}", node_config.name));
                }
            }
        }

        // Mine blocks to confirm funding transactions
        self.mine_blocks_safely(6, "funding transaction confirmations").await?;

        // Poll until all nodes have detected their funds (or timeout)
        self.log("⏳ Waiting for nodes to detect funds...");
        let timeout = Duration::from_secs(120);
        let poll_interval = Duration::from_secs(5);
        let start = std::time::Instant::now();

        loop {
            let mut all_funded = true;
            let mut balances: Vec<(String, u64)> = vec![];

            for (_node_id, node_config) in &self.nodes {
                let balance = self.get_node_balance(node_config).await.unwrap_or(0);
                balances.push((node_config.name.clone(), balance));
                if balance == 0 {
                    all_funded = false;
                }
            }

            if all_funded {
                for (name, balance) in &balances {
                    self.log(&format!("💰 {} balance: {} sat", name, balance));
                }
                break;
            }

            if start.elapsed() > timeout {
                self.warn("⚠️ Timeout waiting for balance detection. Current balances:");
                for (name, balance) in &balances {
                    self.log(&format!("💰 {} balance: {} sat", name, balance));
                }
                break;
            }

            sleep(poll_interval).await;
        }

        Ok(())
    }

    async fn get_node_balance(&self, node_config: &NodeConfig) -> Result<u64, Box<dyn std::error::Error>> {
        let url = format!("https://localhost:{}/GetBalances", node_config.api_port);
        let body: Vec<u8> = vec![];
        let auth_header = compute_auth_header(&body);

        let response = self.client
            .post(&url)
            .header("Content-Type", "application/octet-stream")
            .header("X-Auth", auth_header)
            .body(body)
            .send()
            .await?;

        if response.status().is_success() {
            let bytes = response.bytes().await?;
            if let Ok(balance) = GetBalancesResponse::decode(bytes.as_ref()) {
                return Ok(balance.total_onchain_balance_sats);
            }
        }
        Ok(0)
    }

    async fn get_node_pubkeys(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.log("🔑 Collecting node public keys from ALL available nodes...");

        // Get pubkeys for ALL available nodes, not just the selected ones
        // This allows creating channels from selected nodes to any running node
        let all_available_nodes = NetworkConfig::nodes_for_network(self.network);

        for (node_id, node_config) in &all_available_nodes {
            // Use protobuf GetNodeInfo endpoint
            let url = format!("https://localhost:{}/GetNodeInfo", node_config.api_port);
            let body: Vec<u8> = vec![];
            let auth_header = compute_auth_header(&body);

            match self.client
                .post(&url)
                .header("Content-Type", "application/octet-stream")
                .header("X-Auth", auth_header)
                .body(body)
                .send()
                .await
            {
                Ok(response) if response.status().is_success() => {
                    let bytes = response.bytes().await?;
                    // Parse protobuf - node_id is field 1 (string)
                    if let Ok(info) = GetNodeInfoResponse::decode(bytes.as_ref()) {
                        self.node_pubkeys.insert(node_id.clone(), info.node_id.clone());
                        self.log(&format!("🔑 {}: {}", node_config.name, info.node_id));
                    }
                }
                _ => {
                    // Only error if this is a selected node, otherwise just warn
                    if self.nodes.contains_key(node_id) {
                        return Err(format!("Could not get pubkey for selected node {}", node_config.name).into());
                    } else {
                        self.log(&format!("⚠️ {} is not running (skipping)", node_config.name));
                    }
                }
            }
        }

        Ok(())
    }

    async fn check_existing_channel(&self, node1: &str, node2_pubkey: &str) -> Result<bool, Box<dyn std::error::Error>> {
        let node_config = self.nodes.get(node1)
            .ok_or_else(|| format!("Unknown node: {}", node1))?;

        let url = format!("https://localhost:{}/ListChannels", node_config.api_port);
        let body: Vec<u8> = vec![];
        let auth_header = compute_auth_header(&body);

        let response = self.client
            .post(&url)
            .header("Content-Type", "application/octet-stream")
            .header("X-Auth", auth_header)
            .body(body)
            .send()
            .await?;

        if response.status().is_success() {
            let bytes = response.bytes().await?;
            if let Ok(list) = ListChannelsResponse::decode(bytes.as_ref()) {
                for channel in &list.channels {
                    if channel.counterparty_node_id == node2_pubkey {
                        return Ok(true);
                    }
                }
            }
        }

        Ok(false)
    }

    async fn check_sufficient_funds(&self, min_balance_sat: u64) -> Result<(), Box<dyn std::error::Error>> {
        self.log(&format!("💰 Checking node balances (minimum {} sat required)...", min_balance_sat));

        let mut insufficient_nodes = Vec::new();

        for (_node_id, node_config) in &self.nodes {
            let total = self.get_node_balance(node_config).await.unwrap_or(0);
            if total < min_balance_sat {
                self.warn(&format!("❌ {} has insufficient funds: {} sat (need {} sat)",
                    node_config.name, total, min_balance_sat));
                insufficient_nodes.push(node_config.name.clone());
            } else {
                self.log(&format!("✅ {} balance: {} sat", node_config.name, total));
            }
        }

        if !insufficient_nodes.is_empty() {
            self.log("");
            self.log("📍 Fund these addresses from your treasury wallet:");
            for (_node_id, node_config) in &self.nodes {
                let url = format!("https://localhost:{}/OnchainReceive", node_config.api_port);
                let body: Vec<u8> = vec![];
                let auth_header = compute_auth_header(&body);

                if let Ok(response) = self.client
                    .post(&url)
                    .header("Content-Type", "application/octet-stream")
                    .header("X-Auth", auth_header)
                    .body(body)
                    .send()
                    .await
                {
                    if response.status().is_success() {
                        if let Ok(bytes) = response.bytes().await {
                            if let Ok(addr) = OnchainReceiveResponse::decode(bytes.as_ref()) {
                                self.log(&format!("   {}: {}", node_config.name, addr.address));
                            }
                        }
                    }
                }
            }
            self.log("");
            self.log("Then re-run: cargo run --bin network-init -- --network mutinynet");

            return Err(format!(
                "Insufficient funds on nodes: {}",
                insufficient_nodes.join(", ")
            ).into());
        }

        Ok(())
    }

    async fn create_full_mesh_channels(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.log("🔗 Creating Lightning channels from selected nodes to all available nodes...");

        let channel_amount = 100_000u64; // 100k sats per channel
        let mut total_channel_count = 0;
        let mut total_existing_count = 0;
        let max_passes = 2; // Run the entire channel creation process twice

        // Get all available node configurations for connection details
        let all_available_nodes = NetworkConfig::nodes_for_network(self.network);

        for pass in 1..=max_passes {
            self.log(&format!("🔄 Channel creation pass {} of {}", pass, max_passes));
            let mut pass_channel_count = 0;
            let mut pass_existing_count = 0;

            // Collect all potential channel pairs
            let mut channel_pairs: Vec<(String, String)> = Vec::new();
            for (selected_node_id, _) in &self.nodes {
                for (target_node_id, _) in &all_available_nodes {
                    if selected_node_id == target_node_id {
                        continue;
                    }
                    if self.node_pubkeys.get(target_node_id).is_none() {
                        continue;
                    }
                    channel_pairs.push((selected_node_id.clone(), target_node_id.clone()));
                }
            }

            // Reorder pairs so no node creates two channels in a row (round-robin by source)
            let mut by_source: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
            for (src, dst) in channel_pairs {
                by_source.entry(src).or_default().push(dst);
            }
            let mut reordered: Vec<(String, String)> = Vec::new();
            let sources: Vec<String> = by_source.keys().cloned().collect();
            loop {
                let mut added = false;
                for src in &sources {
                    if let Some(targets) = by_source.get_mut(src) {
                        if let Some(target) = targets.pop() {
                            reordered.push((src.clone(), target));
                            added = true;
                        }
                    }
                }
                if !added {
                    break;
                }
            }

            // Process channels in reordered sequence (one from each node at a time)
            for (selected_node_id, target_node_id) in reordered {
                let selected_node_config = &all_available_nodes[&selected_node_id];
                let target_node_config = &all_available_nodes[&target_node_id];
                let target_pubkey = &self.node_pubkeys[&target_node_id];
                let selected_pubkey = &self.node_pubkeys[&selected_node_id];

                // Check if channel already exists (from either direction)
                let channel_exists = self.check_existing_channel(&selected_node_id, target_pubkey).await.unwrap_or(false) ||
                                   self.check_existing_channel(&target_node_id, selected_pubkey).await.unwrap_or(false);

                if channel_exists {
                    self.log(&format!("✅ Channel already exists: {} <-> {}", selected_node_config.name, target_node_config.name));
                    // Track existing channel for topology display (normalize key to avoid duplicates)
                    let channel_key = if selected_node_id < target_node_id {
                        format!("{}-{}", selected_node_id, target_node_id)
                    } else {
                        format!("{}-{}", target_node_id, selected_node_id)
                    };
                    self.channels.entry(channel_key).or_insert_with(|| "existing".to_string());
                    pass_existing_count += 1;
                    continue;
                }


                self.log(&format!("🔗 Creating channel: {} -> {}", selected_node_config.name, target_node_config.name));

                // Open channel using protobuf API (includes peer connection)
                let push_msat = Some((channel_amount * 1000) / 2); // Push 50% in millisats
                let target_address = format!("{}:{}", target_node_config.ip, target_node_config.p2p_port);

                let request = OpenChannelRequest {
                    node_pubkey: target_pubkey.clone(),
                    address: target_address,
                    channel_amount_sats: channel_amount,
                    push_to_counterparty_msat: push_msat,
                    announce_channel: true,
                };

                let url = format!("https://localhost:{}/OpenChannel", selected_node_config.api_port);
                let body = request.encode_to_vec();
                let auth_header = compute_auth_header(&body);

                let channel_created = match self.client
                    .post(&url)
                    .header("Content-Type", "application/octet-stream")
                    .header("X-Auth", auth_header)
                    .body(body)
                    .send()
                    .await
                {
                    Ok(response) if response.status().is_success() => {
                        let bytes = response.bytes().await?;
                        if let Ok(resp) = OpenChannelResponse::decode(bytes.as_ref()) {
                            // Normalize key to avoid duplicates (smaller node ID first)
                            let channel_key = if selected_node_id < target_node_id {
                                format!("{}-{}", selected_node_id, target_node_id)
                            } else {
                                format!("{}-{}", target_node_id, selected_node_id)
                            };
                            self.channels.insert(channel_key, resp.user_channel_id.clone());
                            pass_channel_count += 1;
                            self.log(&format!("✅ Channel created: {}", resp.user_channel_id));
                            true
                        } else {
                            false
                        }
                    }
                    Ok(response) => {
                        let status = response.status();
                        let body = response.text().await.unwrap_or_default();
                        self.warn(&format!("⚠️ Channel creation failed: {} - {}", status, body));
                        false
                    }
                    Err(e) => {
                        self.warn(&format!("⚠️ Channel creation error: {}", e));
                        false
                    }
                };

                // Only wait for funding tx and mine blocks if channel was successfully created
                if channel_created {
                    if self.network == Network::Regtest {
                        sleep(Duration::from_secs(2)).await;
                        self.wait_for_funding_transactions(1).await?;
                        // Mine 6 blocks to fully confirm the funding tx before creating next channel
                        // This ensures the wallet sees the tx as confirmed and updates its UTXO set
                        self.mine_blocks_safely(6, "channel funding confirmation").await?;
                        // Wait for wallet to sync with new blocks
                        sleep(Duration::from_secs(5)).await;
                    } else {
                        // On mutinynet, just wait - we can't mine on demand
                        sleep(Duration::from_secs(5)).await;
                    }
                }
            }

            // Update totals
            total_channel_count += pass_channel_count;
            total_existing_count += pass_existing_count;

            self.log(&format!("📊 Pass {} summary: {} new channels, {} existing", pass, pass_channel_count, pass_existing_count));

            // Wait for channel_ready messages (channels already have 6 confirmations from above)
            if pass_channel_count > 0 {
                if self.network == Network::Regtest {
                    self.log("⏳ Waiting for channel_ready messages...");
                    sleep(Duration::from_secs(10)).await;
                } else {
                    // Mutinynet: wait for natural blocks (~30s each, need 6 confirmations)
                    self.log("⏳ Waiting for mutinynet blocks (6 confirmations @ ~30s each = ~3 min)...");
                    sleep(Duration::from_secs(200)).await;
                }
            }
        }

        // Final stabilization - only needed if we created new channels
        if total_channel_count > 0 {
            if self.network == Network::Regtest {
                self.mine_blocks_safely(10, "final channel stabilization").await?;
            } else {
                self.log("⏳ Waiting for additional mutinynet confirmations...");
                sleep(Duration::from_secs(60)).await;
            }

            // Wait for channel processing - LDK needs time to exchange channel_ready messages
            self.log("⏳ Waiting for channel_ready message exchange...");
            sleep(Duration::from_secs(20)).await;
        } else {
            self.log("✅ No new channels created, skipping confirmation wait");
        }

        // Verify channel readiness using protobuf API
        self.log("🔍 Verifying channel readiness...");
        let mut ready_channels = 0;
        let mut total_channels = 0;

        for (node_id, node_config) in &self.nodes {
            let url = format!("https://localhost:{}/ListChannels", node_config.api_port);
            let body: Vec<u8> = vec![];
            let auth_header = compute_auth_header(&body);

            match self.client
                .post(&url)
                .header("Content-Type", "application/octet-stream")
                .header("X-Auth", auth_header)
                .body(body)
                .send()
                .await
            {
                Ok(response) if response.status().is_success() => {
                    if let Ok(bytes) = response.bytes().await {
                        if let Ok(list_response) = ListChannelsResponse::decode(bytes.as_ref()) {
                            for channel in &list_response.channels {
                                total_channels += 1;
                                if channel.is_channel_ready {
                                    ready_channels += 1;
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        self.log(&format!("📊 Channel readiness: {}/{} channels ready", ready_channels, total_channels));
        if ready_channels == 0 && total_channels > 0 {
            self.warn("⚠️ No channels are ready yet - may need more confirmations");
        }

        self.log(&format!("✅ Created {} new Lightning channels, {} already existed", total_channel_count, total_existing_count));
        Ok(())
    }

    async fn check_existing_ledger(&self, node: &str, partner_pubkey: &str) -> Result<bool, Box<dyn std::error::Error>> {
        // Try to check if ledger already exists using proto API
        let request = ListLedgersRequest {};
        match self.proto_request::<_, ListLedgersResponse>(
            node,
            endpoints::DEPOSITS_LIST_LEDGERS_PATH,
            request,
        ).await {
            Ok(response) => {
                for ledger in &response.ledgers {
                    if ledger.partner_node_id == partner_pubkey {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            Err(_) => {
                // If endpoint doesn't exist, assume no existing ledgers
                Ok(false)
            }
        }
    }

    async fn initialize_deposits_ledgers(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.log("📋 Skipping automatic Bitcoin Deposits ledger initialization...");
        self.log("   Ledgers will be created on-demand when deposits are made");

        // NOTE: We no longer pre-initialize ledgers for all channels.
        // Ledgers are now created on-demand using the ledger open protocol when:
        // 1. A user creates a deposit wallet (calls /bitcoin-deposits/ledger/init)
        // 2. The operator's node sends LedgerOpenRequest to the partner
        // 3. The partner automatically creates their audit ledger
        //
        // This ensures ledgers are only created when actually needed, not for every channel pair.

        Ok(())
    }

    fn print_network_summary(&self) {
        println!();
        println!("================================================================================");
        self.log("🎉 BITCOIN DEPOSITS LIGHTNING NETWORK INITIALIZED");
        println!("================================================================================");

        self.log(&format!("📊 Network Statistics:"));
        self.log(&format!("   • Nodes: {}", self.nodes.len()));
        self.log(&format!("   • Channels: {}", self.channels.len()));
        self.log(&format!("   • Bitcoin Deposits Ledgers: 0 (created on demand)"));

        println!();
        self.log("📡 Node Information:");
        for (node_id, node_config) in &self.nodes {
            let pubkey = self.node_pubkeys.get(node_id).map(|s| s.as_str()).unwrap_or("Unknown");
            self.log(&format!("   • {}", node_config.name));
            self.log(&format!("     - API: https://localhost:{}", node_config.api_port));
            self.log(&format!("     - P2P: {}:{}", node_config.ip, node_config.p2p_port));
            self.log(&format!("     - PubKey: {}", pubkey));
        }

        println!();
        self.log("⚡ Channel Topology (Full Mesh):");
        for (channel_key, _channel_id) in &self.channels {
            let parts: Vec<&str> = channel_key.split('-').collect();
            if parts.len() == 2 {
                // Only show channels between selected nodes (skip external nodes)
                if let (Some(node1), Some(node2)) = (self.nodes.get(parts[0]), self.nodes.get(parts[1])) {
                    self.log(&format!("   • {} <-> {} (5,000 sat)", node1.name, node2.name));
                }
            }
        }

        println!();
        self.log("✅ Network ready for Bitcoin Deposits operations!");
        println!("================================================================================");
    }

    async fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.log("🚀 Starting Bitcoin Deposits Lightning Network initialization...");
        self.log(&format!("🌐 Network: {:?}", self.network));

        // Step 1: Wait for nodes
        self.wait_for_nodes().await?;

        // Step 2: Setup Bitcoin funding (regtest only - can mine blocks)
        if self.network == Network::Regtest {
            self.setup_bitcoin_funding().await?;
        } else {
            self.log("💰 Checking node funding (mutinynet)...");

            // Check that nodes have sufficient funds before trying to open channels
            // Need ~15k sats per node for a 5k sat channel + fees
            self.check_sufficient_funds(15_000).await?;
        }

        // Step 3: Get node public keys
        self.get_node_pubkeys().await?;

        // Step 4: Create full mesh of channels
        self.create_full_mesh_channels().await?;

        // Step 5: Initialize Bitcoin Deposits ledgers
        self.initialize_deposits_ledgers().await?;

        // Step 6: Print summary
        self.print_network_summary();

        self.log("✅ Network initialization completed successfully!");
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = Command::new("network-init")
        .about("Initialize Lightning Network with Bitcoin Deposits support")
        .arg(
            Arg::new("network")
                .long("network")
                .short('N')
                .help(&format!("Network to initialize (required). Valid values: {}", Network::valid_names()))
                .value_name("NETWORK")
                .required(true)
        )
        .arg(
            Arg::new("nodes")
                .long("nodes")
                .short('n')
                .help(&format!("Comma-separated list of nodes to initialize (default: {})",
                    NetworkConfig::default_nodes().join(",")))
                .value_name("NODE_LIST")
                .required(false)
        )
        .arg(
            Arg::new("include-dev")
                .long("include-dev")
                .help("Include development node (grace) in initialization")
                .action(clap::ArgAction::SetTrue)
        )
        .get_matches();

    // Parse network (required)
    let network_str = matches.get_one::<String>("network").expect("network is required");
    let network = Network::from_str(network_str)
        .ok_or_else(|| format!("Invalid network '{}'. Valid values: {}", network_str, Network::valid_names()))?;

    // Parse node list
    let node_names = if let Some(nodes_str) = matches.get_one::<String>("nodes") {
        nodes_str.split(',').map(|s| s.trim().to_string()).collect()
    } else {
        // Use centralized configuration
        if matches.get_flag("include-dev") {
            NetworkConfig::default_with_dev_nodes()
        } else {
            NetworkConfig::default_nodes()
        }
    };

    println!("🌐 Network: {:?}", network);
    println!("🎯 Initializing nodes: {}", node_names.join(", "));

    let mut initializer = NetworkInitializer::new(network).with_nodes(node_names);

    if let Err(e) = initializer.run().await {
        eprintln!("❌ Network initialization failed: {}", e);
        std::process::exit(1);
    }

    Ok(())
}
