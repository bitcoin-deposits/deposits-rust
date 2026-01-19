use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use tokio::time::sleep;
use clap::{Arg, Command};
use deposits_tools::network_config::{Network, NetworkConfig, NodeConfig};
use deposits_ldk::service::{
    endpoints,
    ListLedgersRequest, ListLedgersResponse,
};
use prost::Message;

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

#[derive(Debug, Serialize, Deserialize)]
struct ConnectPeerRequest {
    pubkey: String,
    host: String,
    port: u16,
}

#[derive(Debug, Serialize, Deserialize)]
struct OpenChannelRequest {
    pubkey: String,
    amount_sat: u64,
    push_to_counterparty_msat: Option<u64>,
    announce: bool,
}

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

#[derive(Debug, Serialize, Deserialize)]
struct ChannelInfo {
    channel_id: Option<String>,
    counterparty_node_id: Option<String>,
    channel_value_satoshis: Option<u64>,
    balance_msat: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ChannelsResponse {
    success: bool,
    data: Option<Vec<ChannelInfo>>,
    error: Option<String>,
}

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

    // Helper method that can call ANY node (not just selected ones)
    async fn ldk_api_call_any<T>(&self, node_config: &NodeConfig, endpoint: &str, method: &str, data: Option<serde_json::Value>) -> Result<ApiResponse<T>, Box<dyn std::error::Error>>
    where
        T: for<'de> Deserialize<'de>,
    {
        let url = format!("http://localhost:{}{}", node_config.api_port, endpoint);

        let request = match method {
            "GET" => self.client.get(&url),
            "POST" => {
                let mut req = self.client.post(&url);
                if let Some(json) = data {
                    req = req.json(&json);
                }
                req
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

        let url = format!("http://localhost:{}{}", node_config.api_port, endpoint);

        let request = match method {
            "GET" => self.client.get(&url),
            "POST" => {
                let mut req = self.client.post(&url);
                if let Some(json) = data {
                    req = req.json(&json);
                }
                req
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

        let url = format!("http://localhost:{}{}", node_config.api_port, path);
        let body = request.encode_to_vec();

        let response = self.client
            .post(&url)
            .header("Content-Type", "application/octet-stream")
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
                match self.ldk_api_call::<serde_json::Value>(node_id, "/health", "GET", None).await {
                    Ok(response) if response.success => {
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

        // Get node addresses and fund them
        for (node_id, node_config) in &self.nodes {
            match self.ldk_api_call::<BitcoinAddress>(node_id, "/bitcoin/address", "GET", None).await {
                Ok(response) if response.success => {
                    if let Some(addr_data) = response.data {
                        self.bitcoin_rpc("sendtoaddress", serde_json::json!([addr_data.address, 1.0])).await?;
                        self.log(&format!("💸 Sent 1 BTC to {} ({})", node_config.name, addr_data.address));
                    }
                }
                _ => {
                    self.warn(&format!("⚠️ Could not get address for {}", node_config.name));
                }
            }
        }

        // Mine blocks to confirm funding transactions
        self.mine_blocks_safely(6, "funding transaction confirmations").await?;

        // Wait longer for electrs to index and LDK nodes to detect the transactions
        self.log("⏳ Waiting for electrs sync and balance detection...");
        sleep(Duration::from_secs(30)).await;

        // Verify node balances
        for (node_id, node_config) in &self.nodes {
            match self.ldk_api_call::<BitcoinBalance>(node_id, "/bitcoin/balance", "GET", None).await {
                Ok(response) if response.success => {
                    if let Some(balance_data) = response.data {
                        self.log(&format!("💰 {} balance: {} sat",
                            node_config.name, balance_data.balance_sat));
                    }
                }
                _ => {
                    self.warn(&format!("Could not check balance for {}", node_config.name));
                }
            }
        }

        Ok(())
    }

    async fn get_node_pubkeys(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.log("🔑 Collecting node public keys from ALL available nodes...");

        // Get pubkeys for ALL available nodes, not just the selected ones
        // This allows creating channels from selected nodes to any running node
        let all_available_nodes = NetworkConfig::nodes_for_network(self.network);

        for (node_id, node_config) in &all_available_nodes {
            match self.ldk_api_call_any::<NodeInfo>(node_config, "/info", "GET", None).await {
                Ok(response) if response.success => {
                    if let Some(info) = response.data {
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
        let response = self.ldk_api_call::<serde_json::Value>(node1, "/channels", "GET", None).await?;

        if response.success {
            if let Some(data) = response.data {
                if let Some(channels) = data.as_array() {
                    for channel in channels {
                        if let Some(counterparty) = channel.get("counterparty_node_id") {
                            if let Some(counterparty_str) = counterparty.as_str() {
                                if counterparty_str == node2_pubkey {
                                    return Ok(true);
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(false)
    }

    async fn check_sufficient_funds(&self, min_balance_sat: u64) -> Result<(), Box<dyn std::error::Error>> {
        self.log(&format!("💰 Checking node balances (minimum {} sat required)...", min_balance_sat));

        let mut insufficient_nodes = Vec::new();

        for (node_id, node_config) in &self.nodes {
            match self.ldk_api_call::<BitcoinBalance>(node_id, "/bitcoin/balance", "GET", None).await {
                Ok(response) if response.success => {
                    if let Some(balance_data) = response.data {
                        let total = balance_data.balance_sat + balance_data.pending_balance_sat;
                        if total < min_balance_sat {
                            self.warn(&format!("❌ {} has insufficient funds: {} sat (need {} sat)",
                                node_config.name, total, min_balance_sat));
                            insufficient_nodes.push(node_config.name.clone());
                        } else {
                            self.log(&format!("✅ {} balance: {} sat", node_config.name, total));
                        }
                    }
                }
                _ => {
                    self.warn(&format!("Could not check balance for {}", node_config.name));
                    insufficient_nodes.push(node_config.name.clone());
                }
            }
        }

        if !insufficient_nodes.is_empty() {
            self.log("");
            self.log("📍 Fund these addresses from your treasury wallet:");
            for (node_id, node_config) in &self.nodes {
                match self.ldk_api_call::<BitcoinAddress>(node_id, "/bitcoin/address", "GET", None).await {
                    Ok(response) if response.success => {
                        if let Some(addr_data) = response.data {
                            self.log(&format!("   {}: {}", node_config.name, addr_data.address));
                        }
                    }
                    _ => {}
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

        let channel_amount = 5_000u64; // 5k sats per channel (for testing)
        let mut total_channel_count = 0;
        let mut total_existing_count = 0;
        let max_passes = 2; // Run the entire channel creation process twice

        // Get all available node configurations for connection details
        let all_available_nodes = NetworkConfig::nodes_for_network(self.network);

        for pass in 1..=max_passes {
            self.log(&format!("🔄 Channel creation pass {} of {}", pass, max_passes));
            let mut pass_channel_count = 0;
            let mut pass_existing_count = 0;

            // Create channels from each selected node to all other running nodes
            for (selected_node_id, selected_node_config) in &self.nodes {
                for (target_node_id, target_node_config) in &all_available_nodes {
                    // Skip if trying to connect to self
                    if selected_node_id == target_node_id {
                        continue;
                    }

                    // Skip if target node is not running (no pubkey available)
                    let target_pubkey = match self.node_pubkeys.get(target_node_id) {
                        Some(pubkey) => pubkey,
                        None => {
                            // Target node is not running, skip
                            continue;
                        }
                    };

                    let selected_pubkey = &self.node_pubkeys[selected_node_id];

                    // Check if channel already exists (from either direction)
                    let channel_exists = self.check_existing_channel(selected_node_id, target_pubkey).await.unwrap_or(false) ||
                                       self.check_existing_channel(target_node_id, selected_pubkey).await.unwrap_or(false);

                    if channel_exists {
                        self.log(&format!("✅ Channel already exists: {} <-> {}", selected_node_config.name, target_node_config.name));
                        pass_existing_count += 1;
                        continue;
                    }

                    self.log(&format!("🔗 Creating channel: {} -> {}", selected_node_config.name, target_node_config.name));

                    // Connect peers first
                    let connect_data = ConnectPeerRequest {
                        pubkey: target_pubkey.clone(),
                        host: target_node_config.ip.clone(),
                        port: target_node_config.p2p_port,
                    };

                    // Try to connect (ignore if already connected)
                    let _ = self.ldk_api_call::<serde_json::Value>(
                        selected_node_id, "/peers/connect", "POST",
                        Some(serde_json::to_value(&connect_data)?)
                    ).await;

                    // Wait for connection
                    sleep(Duration::from_secs(2)).await;

                    // Open channel with 50/50 balance (push half to counterparty)
                    let push_msat = Some((channel_amount * 1000) / 2); // Push 50% in millisats
                    let channel_data = OpenChannelRequest {
                        pubkey: target_pubkey.clone(),
                        amount_sat: channel_amount,
                        push_to_counterparty_msat: push_msat,
                        announce: true,
                    };

                    match self.ldk_api_call::<serde_json::Value>(
                        selected_node_id, "/channels/open", "POST",
                        Some(serde_json::to_value(&channel_data)?)
                    ).await {
                        Ok(response) if response.success => {
                            if let Some(data) = response.data {
                                if let Some(channel_id) = data.get("channel_id") {
                                    let channel_key = format!("{}-{}", selected_node_id, target_node_id);
                                    self.channels.insert(channel_key, channel_id.as_str().unwrap_or("").to_string());
                                    pass_channel_count += 1;
                                    self.log(&format!("✅ Channel created: {}", channel_id));
                                }
                            }
                        }
                        Ok(response) => {
                            self.warn(&format!("⚠️ Channel creation failed: {:?}", response.error));
                        }
                        Err(e) => {
                            self.warn(&format!("⚠️ Channel creation error: {}", e));
                        }
                    }

                    // Longer delay to give nodes time to fully process the channel
                    sleep(Duration::from_secs(3)).await;
                }
            }

            // Update totals
            total_channel_count += pass_channel_count;
            total_existing_count += pass_existing_count;

            self.log(&format!("📊 Pass {} summary: {} new channels, {} existing", pass, pass_channel_count, pass_existing_count));

            // Wait for channel confirmations
            if pass_channel_count > 0 {
                if self.network == Network::Regtest {
                    // Regtest: mine blocks
                    self.mine_blocks_safely(6, &format!("pass {} channel confirmations", pass)).await?;
                    self.log("⏳ Waiting for channel_ready messages and processing...");
                    sleep(Duration::from_secs(30)).await;
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

        // Verify channel readiness
        self.log("🔍 Verifying channel readiness...");
        let mut ready_channels = 0;
        let mut total_channels = 0;

        for (node_id, _) in &self.nodes {
            match self.ldk_api_call::<serde_json::Value>(node_id, "/channels", "GET", None).await {
                Ok(response) if response.success => {
                    if let Some(data) = response.data {
                        if let Some(channels) = data.as_array() {
                            for channel in channels {
                                total_channels += 1;
                                if let Some(is_ready) = channel.get("is_channel_ready") {
                                    if is_ready.as_bool().unwrap_or(false) {
                                        ready_channels += 1;
                                    }
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

    async fn setup_nwc_services(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.log("📱 Setting up NWC (Nostr Wallet Connect) services...");

        for (node_id, node_config) in &self.nodes {
            let nwc_config = serde_json::json!({
                "enable_nwc_server": true,
                "nwc_relay_urls": ["wss://relay.damus.io", "wss://nos.lol"],
                "max_sessions": 100
            });

            match self.ldk_api_call::<serde_json::Value>(
                node_id, "/bitcoin-deposits/nwc/start", "POST",
                Some(nwc_config)
            ).await {
                Ok(response) if response.success => {
                    self.log(&format!("✅ NWC service started for {}", node_config.name));
                }
                _ => {
                    self.warn(&format!("⚠️ Could not start NWC service for {}", node_config.name));
                }
            }
        }

        self.log("✅ NWC services configured");
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
        self.log(&format!("   • Bitcoin Deposits Ledgers: {}", self.channels.len()));

        println!();
        self.log("📡 Node Information:");
        for (node_id, node_config) in &self.nodes {
            let pubkey = self.node_pubkeys.get(node_id).map(|s| s.as_str()).unwrap_or("Unknown");
            self.log(&format!("   • {}", node_config.name));
            self.log(&format!("     - API: http://localhost:{}", node_config.api_port));
            self.log(&format!("     - P2P: {}:{}", node_config.ip, node_config.p2p_port));
            self.log(&format!("     - PubKey: {}", pubkey));
        }

        println!();
        self.log("⚡ Channel Topology (Full Mesh):");
        for (channel_key, _channel_id) in &self.channels {
            let parts: Vec<&str> = channel_key.split('-').collect();
            if parts.len() == 2 {
                let name1 = &self.nodes[parts[0]].name;
                let name2 = &self.nodes[parts[1]].name;
                self.log(&format!("   • {} <-> {} (5,000 sat)", name1, name2));
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

        // Step 6: Setup NWC services
        self.setup_nwc_services().await?;

        // Step 7: Print summary
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
