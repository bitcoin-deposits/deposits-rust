use clap::{Arg, Command};
use reqwest::Client;
use serde_json::Value;
use std::collections::HashMap;
use std::error::Error;
use std::time::Duration;
use tokio;
use deposits_tools::network_config::NetworkConfig;
use deposits_ldk::service::{
    endpoints,
    ListLedgersRequest, ListLedgersResponse,
    ListDepositsRequest, ListDepositsResponse,
    GetLedgerUpdatesRequest, GetLedgerUpdatesResponse,
};
use prost::Message;

struct NetworkStatus {
    client: Client,
    nodes: HashMap<String, NodeInfo>,
    pubkey_to_name: HashMap<String, String>,
}

#[derive(Debug, Clone)]
struct NodeInfo {
    name: String,
    api_url: String,
}

impl NetworkStatus {
    fn new() -> Self {
        let mut nodes = HashMap::new();

        let node_configs = NetworkConfig::status_node_configs();

        for (id, name, port) in node_configs {
            nodes.insert(id.to_string(), NodeInfo {
                name: name.to_string(),
                api_url: format!("http://localhost:{}", port),
            });
        }

        // Create client with longer timeout to avoid intermittent failures
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_else(|_| Client::new());

        Self {
            client,
            nodes,
            pubkey_to_name: HashMap::new(),
        }
    }

    async fn init_pubkey_cache(&mut self) -> Result<(), Box<dyn Error>> {
        for (node_id, node_info) in &self.nodes {
            match self.get_node_pubkey(node_id).await {
                Ok(pubkey) => {
                    self.pubkey_to_name.insert(pubkey.clone(), node_info.name.clone());
                }
                Err(_) => {
                    // Node might not be running, skip it
                }
            }
        }
        Ok(())
    }

    /// Make a protobuf API call to a deposits endpoint
    async fn proto_request<Req: Message, Resp: Message + Default>(
        &self,
        node_id: &str,
        path: &str,
        request: Req,
    ) -> Result<Resp, Box<dyn Error>> {
        let node = self.nodes.get(node_id)
            .ok_or_else(|| format!("Unknown node: {}", node_id))?;

        let url = format!("{}{}", node.api_url, path);
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

    /// Make a protobuf API call using a NodeInfo directly
    async fn proto_request_with_url<Req: Message, Resp: Message + Default>(
        &self,
        api_url: &str,
        path: &str,
        request: Req,
    ) -> Result<Resp, Box<dyn Error>> {
        let url = format!("{}{}", api_url, path);
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

    async fn get_node_info(&self, node_id: &str) -> Result<Value, Box<dyn Error>> {
        let node = self.nodes.get(node_id)
            .ok_or_else(|| format!("Unknown node: {}", node_id))?;

        let response = self.client
            .get(&format!("{}/info", node.api_url))
            .send()
            .await?;

        Ok(response.json().await?)
    }

    async fn get_node_balance(&self, node_id: &str) -> Result<Value, Box<dyn Error>> {
        let node = self.nodes.get(node_id)
            .ok_or_else(|| format!("Unknown node: {}", node_id))?;

        let response = self.client
            .get(&format!("{}/bitcoin/balance", node.api_url))
            .send()
            .await?;

        Ok(response.json().await?)
    }

    async fn get_node_channels(&self, node_id: &str) -> Result<Value, Box<dyn Error>> {
        let node = self.nodes.get(node_id)
            .ok_or_else(|| format!("Unknown node: {}", node_id))?;

        let response = self.client
            .get(&format!("{}/channels", node.api_url))
            .send()
            .await?;

        Ok(response.json().await?)
    }

    async fn print_node_status(&self, node_id: &str) -> Result<(), Box<dyn Error>> {
        let node = self.nodes.get(node_id)
            .ok_or_else(|| format!("Unknown node: {}", node_id))?;

        println!("📡 Node Status: {}", node.name);
        println!("{}", "=".repeat(50));

        // Basic info
        match self.get_node_info(node_id).await {
            Ok(info) => {
                if let Some(data) = info.get("data") {
                    if let Some(node_pubkey) = data.get("node_id") {
                        println!("🔑 Public Key: {}", node_pubkey.as_str().unwrap_or("unknown"));
                    }
                    if let Some(num_channels) = data.get("num_channels") {
                        println!("⚡ Channels: {}", num_channels);
                    }
                    if let Some(num_peers) = data.get("num_peers") {
                        println!("🤝 Peers: {}", num_peers);
                    }
                    if let Some(addresses) = data.get("listening_addresses") {
                        if let Some(addresses_array) = addresses.as_array() {
                            println!("📍 Listening: {:?}", addresses_array);
                        }
                    }
                }
            }
            Err(e) => println!("❌ Failed to get node info: {}", e),
        }

        // On-chain Balance
        match self.get_node_balance(node_id).await {
            Ok(balance) => {
                if let Some(data) = balance.get("data") {
                    if let Some(balance_sat) = data.get("balance_sat") {
                        let balance_btc = balance_sat.as_u64().unwrap_or(0) as f64 / 100_000_000.0;
                        println!("💰 On-chain Balance: {} sat ({:.8} BTC)", balance_sat, balance_btc);
                    }
                }
            }
            Err(e) => println!("❌ Failed to get on-chain balance: {}", e),
        }

        // Lightning Channels
        match self.get_node_channels(node_id).await {
            Ok(channels) => {
                if let Some(data) = channels.get("data") {
                    if let Some(channels_array) = data.as_array() {
                        if channels_array.is_empty() {
                            println!("⚡ Lightning Channels: None");
                        } else {
                            let mut total_ln_balance = 0u64;
                            println!("⚡ Lightning Channels ({} total):", channels_array.len());
                            for (i, channel) in channels_array.iter().enumerate() {
                                println!("  {}. Channel ID: {}",
                                    i + 1,
                                    channel.get("channel_id").unwrap_or(&Value::String("unknown".to_string()))
                                );
                                if let Some(capacity) = channel.get("channel_value_satoshis") {
                                    println!("     Capacity: {} sat", capacity);
                                }
                                if let Some(balance) = channel.get("balance_msat") {
                                    let balance_sat = balance.as_u64().unwrap_or(0) / 1000;
                                    total_ln_balance += balance_sat;
                                    println!("     Your Balance: {} sat", balance_sat);
                                }
                                if let Some(outbound) = channel.get("outbound_capacity_msat") {
                                    let outbound_sat = outbound.as_u64().unwrap_or(0) / 1000;
                                    println!("     Outbound (spendable): {} sat", outbound_sat);
                                }
                                if let Some(inbound) = channel.get("inbound_capacity_msat") {
                                    let inbound_sat = inbound.as_u64().unwrap_or(0) / 1000;
                                    println!("     Inbound (receivable): {} sat", inbound_sat);
                                }
                                if let Some(counterparty) = channel.get("counterparty_node_id") {
                                    let counterparty_str = counterparty.as_str().unwrap_or("unknown");
                                    println!("     Counterparty: {}", counterparty_str);

                                    // Try to fetch Bitcoin Deposits ledger data for this counterparty
                                    if counterparty_str != "unknown" {
                                        if let Ok(ledger_response) = self.client.get(&format!("{}/bitcoin-deposits/ledger-updates/{}", node.api_url, counterparty_str))
                                            .send()
                                            .await {
                                            if ledger_response.status().is_success() {
                                                if let Ok(ledger_json) = ledger_response.json::<Value>().await {
                                                    if let Some(data) = ledger_json.get("data") {
                                                        if let Some(updates) = data.get("updates") {
                                                            if let Some(updates_array) = updates.as_array() {
                                                                let update_count = updates_array.len();
                                                                if update_count > 0 {
                                                                    println!("     📜 Bitcoin Deposits Ledger: {} updates", update_count);

                                                                    // Show last update
                                                                    if let Some(last_update) = updates_array.last() {
                                                                        if let Some(update_type) = last_update.get("update_type").and_then(|v| v.as_str()) {
                                                                            println!("        Last: {}", update_type);
                                                                        }
                                                                        if let Some(timestamp) = last_update.get("timestamp").and_then(|v| v.as_u64()) {
                                                                            let datetime = chrono::DateTime::from_timestamp(timestamp as i64, 0)
                                                                                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                                                                                .unwrap_or_else(|| format!("{}", timestamp));
                                                                            println!("        Time: {}", datetime);
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            let total_ln_btc = total_ln_balance as f64 / 100_000_000.0;
                            println!("⚡ Total Lightning Balance: {} sat ({:.8} BTC)", total_ln_balance, total_ln_btc);
                        }
                    } else {
                        println!("⚡ Lightning Channels: No data available");
                    }
                }
            }
            Err(e) => println!("❌ Failed to get channels: {}", e),
        }

        // Bitcoin Deposits
        match self.client.get(&format!("{}/bitcoin-deposits/ledgers", node.api_url))
            .send()
            .await {
            Ok(response) => {
                if response.status().is_success() {
                    if let Ok(ledgers_json) = response.json::<Value>().await {
                        if let Some(data) = ledgers_json.get("data") {
                            if let Some(ledgers) = data.get("ledgers").and_then(|l| l.as_array()) {
                                let mut total_deposits = 0u64;
                                let mut total_reserves = 0u64;
                                let mut deposit_count = 0;

                                for ledger in ledgers {
                                    if let Some(deposits_sat) = ledger.get("deposit_amounts_sat").and_then(|v| v.as_u64()) {
                                        if deposits_sat > 0 {
                                            total_deposits += deposits_sat;
                                            deposit_count += 1;
                                        }
                                    }
                                    if let Some(reserves_sat) = ledger.get("reserves_sat").and_then(|v| v.as_u64()) {
                                        total_reserves += reserves_sat;
                                    }
                                }

                                if deposit_count > 0 {
                                    println!("💎 Bitcoin Deposits:");
                                    println!("   • Active Deposits: {} (across {} ledgers)", deposit_count, ledgers.len());
                                    println!("   • Total Deposited: {} sat", total_deposits);
                                    println!("   • Total Reserves: {} sat", total_reserves);

                                    // List individual ledgers with deposits
                                    for (i, ledger) in ledgers.iter().enumerate() {
                                        if let Some(deposits_sat) = ledger.get("deposit_amounts_sat").and_then(|v| v.as_u64()) {
                                            if deposits_sat > 0 {
                                                let counterparty_str = ledger.get("counterparty_node_id")
                                                    .and_then(|v| v.as_str())
                                                    .unwrap_or("unknown");

                                                let display_id = if counterparty_str.len() >= 16 {
                                                    &counterparty_str[..16]
                                                } else {
                                                    counterparty_str
                                                };
                                                println!("   {}. Ledger with {}...", i + 1, display_id);
                                                println!("      Total Deposits: {} sat", deposits_sat);
                                                if let Some(reserves_sat) = ledger.get("reserves_sat").and_then(|v| v.as_u64()) {
                                                    println!("      Reserves: {} sat", reserves_sat);
                                                }
                                                if let Some(operator_sat) = ledger.get("operator_sat").and_then(|v| v.as_u64()) {
                                                    println!("      Operator Balance: {} sat", operator_sat);
                                                }

                                                // Fetch individual deposit entries for this counterparty
                                                if counterparty_str != "unknown" {
                                                    if let Ok(deposits_response) = self.client.get(&format!("{}/bitcoin-deposits/deposits/{}", node.api_url, counterparty_str))
                                                        .send()
                                                        .await {
                                                        if deposits_response.status().is_success() {
                                                            if let Ok(deposits_json) = deposits_response.json::<Value>().await {
                                                                if let Some(data) = deposits_json.get("data") {
                                                                    if let Some(deposits_array) = data.get("deposits").and_then(|d| d.as_array()) {
                                                                        if !deposits_array.is_empty() {
                                                                            println!("      Deposit Entries:");
                                                                            for (j, deposit) in deposits_array.iter().enumerate() {
                                                                                if let Some(depositor_pubkey) = deposit.get("depositor_pubkey").and_then(|v| v.as_str()) {
                                                                                    println!("         {}. Depositor: {}...", j + 1, &depositor_pubkey[..16]);
                                                                                }
                                                                                if let Some(balance) = deposit.get("balance").and_then(|v| v.as_u64()) {
                                                                                    println!("            Balance: {} sat", balance);
                                                                                }
                                                                                if let Some(locked) = deposit.get("locked_balance").and_then(|v| v.as_u64()) {
                                                                                    if locked > 0 {
                                                                                        println!("            Locked: {} sat", locked);
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                } else {
                                    println!("💎 Bitcoin Deposits: No active deposits");
                                }
                                println!("📱 NWC Service: ✅ Available");
                            } else {
                                println!("📱 NWC Service: ✅ Available (no ledgers)");
                            }
                        } else {
                            println!("📱 NWC Service: ✅ Available");
                        }
                    } else {
                        println!("📱 NWC Service: ✅ Available");
                    }
                } else {
                    println!("📱 NWC Service: ⚠️  Bitcoin Deposits not available");
                }
            }
            Err(_) => println!("📱 NWC Service: ❌ Not available"),
        }

        println!();
        Ok(())
    }

    async fn print_all_nodes_status(&self) -> Result<(), Box<dyn Error>> {
        println!("🌐 Network Status - All Nodes");
        println!("{}", "=".repeat(60));

        let mut total_balance = 0u64;
        let mut total_channels = 0u64;
        let mut online_nodes = 0;

        for (node_id, node_info) in &self.nodes {
            print!("📡 {} ... ", node_info.name);

            match self.get_node_info(node_id).await {
                Ok(info) => {
                    if let Some(data) = info.get("data") {
                        online_nodes += 1;

                        let channels = data.get("num_channels").unwrap_or(&Value::Number(0.into())).as_u64().unwrap_or(0);
                        total_channels += channels;

                        // Get balance
                        if let Ok(balance_resp) = self.get_node_balance(node_id).await {
                            if let Some(balance_data) = balance_resp.get("data") {
                                if let Some(balance_sat) = balance_data.get("balance_sat") {
                                    total_balance += balance_sat.as_u64().unwrap_or(0);
                                }
                            }
                        }

                        println!("✅ Online ({} channels)", channels);
                    } else {
                        println!("⚠️  No data");
                    }
                }
                Err(_) => println!("❌ Offline"),
            }
        }

        println!();
        println!("📊 Network Summary:");
        println!("   • Total Nodes: {}", self.nodes.len());
        println!("   • Online Nodes: {}", online_nodes);
        println!("   • Total Channels: {}", total_channels);
        println!("   • Total Balance: {} sat ({:.8} BTC)", total_balance, total_balance as f64 / 100_000_000.0);

        // Calculate expected full mesh channels
        let expected_channels = if self.nodes.len() > 1 {
            (self.nodes.len() * (self.nodes.len() - 1)) / 2
        } else {
            0
        };

        if total_channels as usize >= expected_channels {
            println!("   • Network Topology: ✅ Full Mesh ({} channels)", total_channels);
        } else {
            println!("   • Network Topology: ⚠️  Partial ({}/{} channels)", total_channels, expected_channels);
        }

        println!();
        Ok(())
    }

    async fn print_network_channels(&self) -> Result<(), Box<dyn Error>> {
        println!("⚡ Network Channels");
        println!("{}", "=".repeat(60));

        let mut all_channels = Vec::new();

        for (node_id, node_info) in &self.nodes {
            match self.get_node_channels(node_id).await {
                Ok(channels_resp) => {
                    if let Some(data) = channels_resp.get("data") {
                        if let Some(channels) = data.as_array() {
                            for channel in channels {
                                all_channels.push((node_info.name.clone(), channel.clone()));
                            }
                        }
                    }
                }
                Err(e) => println!("❌ Failed to get channels for {}: {}", node_info.name, e),
            }
        }

        if all_channels.is_empty() {
            println!("No channels found");
            return Ok(());
        }

        println!("Found {} channel entries:", all_channels.len());
        for (i, (node_name, channel)) in all_channels.iter().enumerate() {
            println!("{}. {} - Channel: {}",
                i + 1,
                node_name,
                channel.get("channel_id").unwrap_or(&Value::String("unknown".to_string()))
            );

            if let Some(capacity) = channel.get("channel_value_satoshis") {
                println!("   Capacity: {} sat", capacity);
            }
            if let Some(balance) = channel.get("balance_msat") {
                let balance_sat = balance.as_u64().unwrap_or(0) / 1000;
                println!("   Balance: {} sat", balance_sat);
            }
            if let Some(counterparty) = channel.get("counterparty_node_id") {
                let counterparty_str = counterparty.as_str().unwrap_or("unknown");
                // Try to find the counterparty name
                let counterparty_name = self.nodes.values()
                    .find(|_node| {
                        // This is a simplified check - in reality we'd need to get the actual pubkey
                        counterparty_str.len() > 10
                    })
                    .map(|node| node.name.as_str())
                    .unwrap_or("Unknown");
                println!("   Counterparty: {} ({}...)", counterparty_name, &counterparty_str[..16]);
            }
            println!();
        }

        Ok(())
    }

    async fn print_node_ledgers(&self, node_id: &str) -> Result<(), Box<dyn Error>> {
        let node = self.nodes.get(node_id)
            .ok_or_else(|| format!("Unknown node: {}", node_id))?;

        println!("📋 Bitcoin Deposits Ledgers - {}", node.name);
        println!("{}", "=".repeat(60));

        // Get ledgers from this specific node
        match self.client.get(&format!("{}/bitcoin-deposits/ledgers", node.api_url))
            .send()
            .await {
            Ok(response) => {
                if response.status().is_success() {
                    match response.json::<serde_json::Value>().await {
                        Ok(json) => {
                            if let Some(data) = json.get("data") {
                                if let Some(ledgers) = data.get("ledgers") {
                                    if let Some(ledgers_array) = ledgers.as_array() {
                                        if ledgers_array.is_empty() {
                                            println!("   📭 No ledgers found for {}", node.name);
                                        } else {
                                            for (i, ledger) in ledgers_array.iter().enumerate() {
                                                // Extract ledger data
                                                let operator_str = ledger.get("operator_node_id")
                                                    .and_then(|v| v.as_str())
                                                    .unwrap_or("unknown");
                                                let partner_str = ledger.get("partner_node_id")
                                                    .and_then(|v| v.as_str())
                                                    .unwrap_or("unknown");
                                                let operator_sat = ledger.get("operator_sat").and_then(|v| v.as_u64()).unwrap_or(0);
                                                let partner_sat = ledger.get("partner_sat").and_then(|v| v.as_u64()).unwrap_or(0);
                                                let deposits_sat = ledger.get("deposit_amounts_sat").and_then(|v| v.as_u64()).unwrap_or(0);
                                                let reserves_sat = ledger.get("reserves_sat").and_then(|v| v.as_u64()).unwrap_or(0);

                                                // Get operator and partner names
                                                let operator_name = self.pubkey_to_name.get(operator_str)
                                                    .map(|n| n.as_str())
                                                    .unwrap_or("Unknown");
                                                let partner_name = self.pubkey_to_name.get(partner_str)
                                                    .map(|n| n.as_str())
                                                    .unwrap_or("Unknown");

                                                // Print header: "Operator -> Partner (partner_pubkey)"
                                                println!("   {}. {} -> {} ({})", i + 1, operator_name, partner_name, partner_str);

                                                // Print balance line: "Out 2450000 sat / In 2450000 sat"
                                                println!("      Out {} sat / In {} sat", operator_sat, partner_sat);

                                                // Print deposits/reserves line: "Deposits 0 sat / Reserves 2200 sat"
                                                println!("      Deposits {} sat / Reserves {} sat", deposits_sat, reserves_sat);

                                                // Fetch and display individual deposits
                                                if deposits_sat > 0 || true { // Always try to fetch deposits
                                                    if let Ok(deposits_response) = self.client.get(&format!("{}/bitcoin-deposits/deposits/{}", node.api_url, partner_str))
                                                        .send()
                                                        .await
                                                    {
                                                        if deposits_response.status().is_success() {
                                                            if let Ok(deposits_json) = deposits_response.json::<serde_json::Value>().await {
                                                                if let Some(data) = deposits_json.get("data") {
                                                                    if let Some(deposits_array) = data.get("deposits").and_then(|v| v.as_array()) {
                                                                        if !deposits_array.is_empty() {
                                                                            println!();
                                                                            for deposit in deposits_array {
                                                                                let deposit_pubkey = deposit.get("depositor_pubkey")
                                                                                    .and_then(|v| v.as_str())
                                                                                    .unwrap_or("unknown");
                                                                                let balance = deposit.get("balance")
                                                                                    .and_then(|v| v.as_u64())
                                                                                    .unwrap_or(0);

                                                                                // Convert msat to sat for display
                                                                                let balance_sat = balance / 1000;
                                                                                println!("      {}", deposit_pubkey);
                                                                                println!("      {} sat", balance_sat);
                                                                                println!();
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }

                                            println!("📊 Summary for {}:", node.name);
                                            println!("   • Total Ledgers: {}", ledgers_array.len());

                                            // Count active ledgers
                                            let active_count = ledgers_array.iter()
                                                .filter(|ledger| {
                                                    ledger.get("status")
                                                        .and_then(|s| s.as_str())
                                                        .map(|s| s == "active")
                                                        .unwrap_or(false)
                                                })
                                                .count();
                                            println!("   • Active Ledgers: {}", active_count);
                                        }
                                    } else {
                                        println!("   📭 No ledgers data available");
                                    }
                                } else {
                                    println!("   ⚠️  No ledgers field in response");
                                }
                            } else {
                                println!("   ⚠️  Invalid response format");
                            }
                        }
                        Err(e) => println!("   ❌ Failed to parse response: {}", e),
                    }
                } else {
                    println!("   ⚠️  Bitcoin Deposits ledgers endpoint returned {}", response.status());
                }
            }
            Err(e) => println!("   ❌ Failed to connect: {}", e),
        }

        Ok(())
    }

    async fn resolve_partner_pubkey(&self, node_id: &str, partial_pubkey: &str) -> Result<String, Box<dyn Error>> {
        let node = self.nodes.get(node_id)
            .ok_or_else(|| format!("Unknown node: {}", node_id))?;

        // First, try to use it as-is if it's a full pubkey
        if partial_pubkey.len() == 66 {
            return Ok(partial_pubkey.to_string());
        }

        // Try to resolve as a node alias (e.g., "alice", "bob", "charlie")
        // Check if the input matches a known node name and get its pubkey
        for (pubkey, name) in &self.pubkey_to_name {
            if name.eq_ignore_ascii_case(partial_pubkey) {
                return Ok(pubkey.clone());
            }
        }

        // Otherwise, fetch ledgers and find matching partner by pubkey prefix
        let response = self.client
            .get(&format!("{}/bitcoin-deposits/ledgers", node.api_url))
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(format!("Failed to fetch ledgers: {}", response.status()).into());
        }

        let json: serde_json::Value = response.json().await?;
        let ledgers = json.get("data")
            .and_then(|d| d.get("ledgers"))
            .and_then(|l| l.as_array())
            .ok_or("Invalid ledgers response")?;

        let matches: Vec<String> = ledgers.iter()
            .filter_map(|ledger| {
                ledger.get("counterparty_node_id")
                    .and_then(|p| p.as_str())
                    .filter(|pubkey| pubkey.starts_with(partial_pubkey))
                    .map(|s| s.to_string())
            })
            .collect();

        match matches.len() {
            0 => Err(format!("No partner pubkey found matching '{}'", partial_pubkey).into()),
            1 => Ok(matches[0].clone()),
            _ => Err(format!("Ambiguous pubkey '{}' matches {} partners: {}",
                partial_pubkey,
                matches.len(),
                matches.iter().map(|p| &p[..16]).collect::<Vec<_>>().join(", ")
            ).into()),
        }
    }

    async fn print_ledger_updates(&self, node_id: &str, partner_pubkey: &str) -> Result<(), Box<dyn Error>> {
        let node = self.nodes.get(node_id)
            .ok_or_else(|| format!("Unknown node: {}", node_id))?;

        // Resolve partial pubkey to full pubkey
        let full_pubkey = self.resolve_partner_pubkey(node_id, partner_pubkey).await?;

        println!("📜 Ledger Update History - {} with partner {}", node.name, &full_pubkey[..16]);
        println!("{}", "=".repeat(80));

        // Make API call to get ledger updates
        let url = format!("{}/bitcoin-deposits/ledger-updates/{}", node.api_url, full_pubkey);
        match self.client.get(&url).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    match response.json::<serde_json::Value>().await {
                        Ok(json) => {
                            if let Some(data) = json.get("data") {
                                if let Some(updates) = data.get("updates") {
                                    if let Some(updates_array) = updates.as_array() {
                                        if updates_array.is_empty() {
                                            println!("   📭 No updates found for this ledger");
                                        } else {
                                            println!("   Found {} updates:", updates_array.len());
                                            println!();
                                            for (i, update) in updates_array.iter().enumerate() {
                                                println!("   {}. {}", i + 1, "-".repeat(70));

                                                if let Some(timestamp) = update.get("timestamp").and_then(|v| v.as_u64()) {
                                                    let datetime = chrono::DateTime::from_timestamp(timestamp as i64, 0)
                                                        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                                                        .unwrap_or_else(|| format!("timestamp {}", timestamp));
                                                    println!("      Time: {}", datetime);
                                                }

                                                if let Some(update_type) = update.get("update_type").and_then(|v| v.as_str()) {
                                                    println!("      Type: {}", update_type);
                                                }

                                                if let Some(deposit_pubkey) = update.get("deposit_pubkey").and_then(|v| v.as_str()) {
                                                    println!("      Deposit: {}...", &deposit_pubkey[..16]);
                                                }

                                                if let Some(amount) = update.get("amount").and_then(|v| v.as_u64()) {
                                                    println!("      Amount: {} sat", amount);
                                                }

                                                if let Some(description) = update.get("description").and_then(|v| v.as_str()) {
                                                    println!("      Description: {}", description);
                                                }

                                                if let Some(prev_hash) = update.get("previous_hash").and_then(|v| v.as_str()) {
                                                    println!("      Previous Hash: {}...", &prev_hash[..16]);
                                                }

                                                if let Some(hash) = update.get("consensus_hash").and_then(|v| v.as_str()) {
                                                    println!("      Consensus Hash: {}...", &hash[..16]);
                                                }

                                                // Show sync status
                                                let is_acknowledged = update.get("acknowledged").and_then(|v| v.as_bool()).unwrap_or(false);
                                                let is_committed = update.get("committed").and_then(|v| v.as_bool()).unwrap_or(false);
                                                if is_acknowledged || is_committed {
                                                    let mut status_parts = Vec::new();
                                                    if is_acknowledged {
                                                        status_parts.push("✓ Acknowledged");
                                                    }
                                                    if is_committed {
                                                        status_parts.push("🔒 Committed");
                                                    }
                                                    println!("      Status: {}", status_parts.join(", "));
                                                }

                                                println!();
                                            }
                                        }
                                    } else {
                                        println!("   ⚠️  Updates is not an array");
                                    }
                                } else {
                                    println!("   ⚠️  No 'updates' field in response");
                                    println!("   Response: {}", serde_json::to_string_pretty(&json).unwrap_or_else(|_| "Unable to format".to_string()));
                                }
                            } else {
                                println!("   ⚠️  No 'data' field in response");
                                println!("   Response: {}", serde_json::to_string_pretty(&json).unwrap_or_else(|_| "Unable to format".to_string()));
                            }
                        }
                        Err(e) => println!("   ❌ Failed to parse response: {}", e),
                    }
                } else {
                    let status_code = response.status().as_u16();
                    println!("   ⚠️  API returned status {}", response.status());
                    // Try to get the error message from response body
                    if let Ok(text) = response.text().await {
                        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                            if let Some(error) = json.get("error").and_then(|e| e.as_str()) {
                                println!("   Error: {}", error);
                            } else {
                                println!("   Response: {}", serde_json::to_string_pretty(&json).unwrap_or(text));
                            }
                        } else {
                            println!("   Response: {}", text);
                        }
                    }
                    if status_code == 404 {
                        println!("   Hint: Ledger might not exist for this partner");
                    }
                }
            }
            Err(e) => println!("   ❌ Failed to connect: {}", e),
        }

        Ok(())
    }

    async fn print_all_ledger_updates(&self, node_id: &str, verbose: bool) -> Result<(), Box<dyn Error>> {
        let node = self.nodes.get(node_id)
            .ok_or_else(|| format!("Unknown node: {}", node_id))?;

        println!("=== Ledger Updates - {} ==========\n", node.name);

        // Get the node's public key to filter ledgers where this node is the operator
        let node_pubkey = self.get_node_pubkey(node_id).await?;

        let url = format!("{}/bitcoin-deposits/ledger-updates", node.api_url);
        match self.client.get(&url).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    match response.json::<serde_json::Value>().await {
                        Ok(json) => {
                            if let Some(data) = json.get("data") {
                                if let Some(ledgers) = data.get("ledgers") {
                                    if let Some(ledgers_array) = ledgers.as_array() {
                                        if ledgers_array.is_empty() {
                                            println!("No ledgers found");
                                        } else {
                                            // Separate and sort ledgers: Direct first, then Partner, then Audit
                                            let mut direct_ledgers = Vec::new();
                                            let mut partner_ledgers = Vec::new();
                                            let mut audit_ledgers = Vec::new();

                                            for ledger in ledgers_array {
                                                let role = ledger.get("role").and_then(|v| v.as_str()).unwrap_or("unknown");

                                                if let (Some(operator_id), Some(partner_id)) = (
                                                    ledger.get("operator_node_id").and_then(|v| v.as_str()),
                                                    ledger.get("partner_node_id").and_then(|v| v.as_str())
                                                ) {
                                                    let is_operator = operator_id == node_pubkey;

                                                    match role {
                                                        "direct" => {
                                                            // Direct ledgers only shown when we're the operator
                                                            // Partner entries come from "partner" role (SignedAuditUpdate broadcasts)
                                                            if is_operator {
                                                                direct_ledgers.push(ledger);
                                                            }
                                                            // Don't add non-operator "direct" entries - they'd be duplicates
                                                            // of the more complete "partner" role entries
                                                        }
                                                        "partner" => {
                                                            // Partner ledgers from SignedAuditUpdate broadcasts
                                                            partner_ledgers.push(ledger);
                                                        }
                                                        "audit" => {
                                                            // Audit ledgers are third-party ledgers we're monitoring
                                                            audit_ledgers.push(ledger);
                                                        }
                                                        _ => {}
                                                    }
                                                }
                                            }

                                            // Print Direct ledgers first (with full details)
                                            for ledger in direct_ledgers {
                                                let update_count = ledger.get("update_count").and_then(|v| v.as_u64()).unwrap_or(0);

                                                if let (Some(operator_id), Some(partner_id)) = (
                                                    ledger.get("operator_node_id").and_then(|v| v.as_str()),
                                                    ledger.get("partner_node_id").and_then(|v| v.as_str())
                                                ) {
                                                    let operator_name = self.find_node_name_by_pubkey(operator_id)
                                                        .unwrap_or_else(|| "unknown".to_string());
                                                    let partner_name = self.find_node_name_by_pubkey(partner_id)
                                                        .unwrap_or_else(|| "unknown".to_string());
                                                    let ledger_addr = ledger.get("ledger_address")
                                                        .and_then(|v| v.as_str())
                                                        .unwrap_or("unknown");

                                                    // Show sync state using hash tracking
                                                    let ack_hash = ledger.get("partner_deepest_ack_hash")
                                                        .and_then(|v| v.as_str())
                                                        .unwrap_or("");
                                                    let commit_hash = ledger.get("channel_deepest_commitment_hash")
                                                        .and_then(|v| v.as_str())
                                                        .unwrap_or("");

                                                    let mut sync_status = Vec::new();
                                                    if !ack_hash.is_empty() && ack_hash != "0000000000000000000000000000000000000000000000000000000000000000" {
                                                        sync_status.push(format!("ACK:{}", &ack_hash[..8]));
                                                    }
                                                    if !commit_hash.is_empty() && commit_hash != "0000000000000000000000000000000000000000000000000000000000000000" {
                                                        sync_status.push(format!("COMMIT:{}", &commit_hash[..8]));
                                                    }
                                                    let status_display = if sync_status.is_empty() {
                                                        "Initial".to_string() // No ACKs or commitments yet - newly initialized ledger
                                                    } else {
                                                        sync_status.join(", ")
                                                    };

                                                    println!("Direct: {} → {} @ {} ({} updates) [{}]",
                                                        operator_name, partner_name, ledger_addr, update_count, status_display);

                                                    if let Some(updates) = ledger.get("updates").and_then(|v| v.as_array()) {
                                                        for update in updates {
                                                            self.print_update_line(update);
                                                        }
                                                    }
                                                    println!();
                                                }
                                            }

                                            // Print Partner ledgers (expanded or collapsed based on verbose flag)
                                            for ledger in &partner_ledgers {
                                                let update_count = ledger.get("update_count").and_then(|v| v.as_u64()).unwrap_or(0);

                                                if let (Some(operator_id), Some(partner_id)) = (
                                                    ledger.get("operator_node_id").and_then(|v| v.as_str()),
                                                    ledger.get("partner_node_id").and_then(|v| v.as_str())
                                                ) {
                                                    let operator_name = self.find_node_name_by_pubkey(operator_id)
                                                        .unwrap_or_else(|| "unknown".to_string());
                                                    let partner_name = self.find_node_name_by_pubkey(partner_id)
                                                        .unwrap_or_else(|| "unknown".to_string());

                                                    if verbose {
                                                        // Verbose mode: show all updates
                                                        println!("Partner: {} → {} ({} updates)",
                                                            operator_name, partner_name, update_count);

                                                        if let Some(updates) = ledger.get("updates").and_then(|v| v.as_array()) {
                                                            for update in updates {
                                                                self.print_update_line(update);
                                                            }
                                                        }
                                                        println!();
                                                    } else {
                                                        // Compact mode: show only summary
                                                        if let Some(updates) = ledger.get("updates").and_then(|v| v.as_array()) {
                                                            if let Some(last_update) = updates.last() {
                                                                let timestamp = last_update.get("timestamp")
                                                                    .and_then(|v| v.as_u64())
                                                                    .map(|ts| chrono::DateTime::from_timestamp(ts as i64, 0))
                                                                    .flatten()
                                                                    .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                                                                    .unwrap_or_else(|| "unknown".to_string());

                                                                let current_hash = last_update.get("consensus_hash")
                                                                    .and_then(|v| v.as_str())
                                                                    .unwrap_or("unknown");
                                                                let previous_hash = last_update.get("previous_hash")
                                                                    .and_then(|v| v.as_str())
                                                                    .unwrap_or("");

                                                                let hash_short = if current_hash.len() > 8 && previous_hash.len() > 8 {
                                                                    format!("{}~{}", &previous_hash[..8], &current_hash[..8])
                                                                } else if current_hash.len() > 8 {
                                                                    current_hash[..8].to_string()
                                                                } else {
                                                                    current_hash.to_string()
                                                                };

                                                                println!("Partner: {} → {} ({} updates) {}  [{}]",
                                                                    operator_name, partner_name, update_count, timestamp, hash_short);
                                                            }
                                                        }
                                                    }
                                                }
                                            }

                                            // Add final linefeed if we printed any partner ledgers
                                            if !partner_ledgers.is_empty() {
                                                println!();
                                            }

                                            // Print Audit ledgers (expanded or collapsed based on verbose flag)
                                            for ledger in &audit_ledgers {
                                                let update_count = ledger.get("update_count").and_then(|v| v.as_u64()).unwrap_or(0);

                                                if let (Some(operator_id), Some(partner_id)) = (
                                                    ledger.get("operator_node_id").and_then(|v| v.as_str()),
                                                    ledger.get("partner_node_id").and_then(|v| v.as_str())
                                                ) {
                                                    let operator_name = self.find_node_name_by_pubkey(operator_id)
                                                        .unwrap_or_else(|| "unknown".to_string());
                                                    let partner_name = self.find_node_name_by_pubkey(partner_id)
                                                        .unwrap_or_else(|| "unknown".to_string());

                                                    if verbose {
                                                        // Verbose mode: show all updates
                                                        println!("Audit: {} → {} ({} updates)",
                                                            operator_name, partner_name, update_count);

                                                        if let Some(updates) = ledger.get("updates").and_then(|v| v.as_array()) {
                                                            for update in updates {
                                                                self.print_update_line(update);
                                                            }
                                                        }
                                                        println!();
                                                    } else {
                                                        // Compact mode: show only summary
                                                        if let Some(updates) = ledger.get("updates").and_then(|v| v.as_array()) {
                                                            if let Some(last_update) = updates.last() {
                                                                let timestamp = last_update.get("timestamp")
                                                                    .and_then(|v| v.as_u64())
                                                                    .map(|ts| chrono::DateTime::from_timestamp(ts as i64, 0))
                                                                    .flatten()
                                                                    .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                                                                    .unwrap_or_else(|| "unknown".to_string());

                                                                let current_hash = last_update.get("consensus_hash")
                                                                    .and_then(|v| v.as_str())
                                                                    .unwrap_or("unknown");
                                                                let previous_hash = last_update.get("previous_hash")
                                                                    .and_then(|v| v.as_str())
                                                                    .unwrap_or("");

                                                                let hash_short = if current_hash.len() > 8 && previous_hash.len() > 8 {
                                                                    format!("{}~{}", &previous_hash[..8], &current_hash[..8])
                                                                } else if current_hash.len() > 8 {
                                                                    current_hash[..8].to_string()
                                                                } else {
                                                                    current_hash.to_string()
                                                                };

                                                                println!("Audit: {} → {} ({} updates) {}  [{}]",
                                                                    operator_name, partner_name, update_count, timestamp, hash_short);
                                                            }
                                                        }
                                                    }
                                                }
                                            }

                                            // Add final linefeed if we printed any audit ledgers
                                            if !audit_ledgers.is_empty() {
                                                println!();
                                            }
                                        }
                                    } else {
                                        println!("Error: Ledgers is not an array");
                                    }
                                } else {
                                    println!("Error: No 'ledgers' field in response");
                                }
                            } else {
                                println!("Error: No 'data' field in response");
                            }
                        }
                        Err(e) => println!("Error: Failed to parse response: {}", e),
                    }
                } else {
                    println!("Error: API returned status {}", response.status());
                }
            }
            Err(e) => println!("Error: Failed to connect: {}", e),
        }

        Ok(())
    }

    /// Cross-node view of ledger updates showing sync status across all nodes
    async fn print_cross_node_ledger_updates(&self) -> Result<(), Box<dyn Error>> {
        use std::collections::{HashMap, HashSet};

        println!("=== Cross-Node Ledger Updates ==========\n");

        // Collect all ledger data from all nodes
        // Key: (operator_pubkey, partner_pubkey) -> Vec of (node_name, role, updates)
        let mut all_ledger_data: HashMap<(String, String), Vec<(String, String, Vec<serde_json::Value>)>> = HashMap::new();

        // Fetch ledger updates from each node (sorted by name for deterministic order)
        let mut sorted_nodes: Vec<_> = self.nodes.iter().collect();
        sorted_nodes.sort_by(|a, b| a.1.name.cmp(&b.1.name));

        for (_node_id, node_info) in sorted_nodes {
            let url = format!("{}/bitcoin-deposits/ledger-updates", node_info.api_url);

            // Try up to 2 times with a small delay
            let mut response_opt = None;
            for attempt in 0..2 {
                if attempt > 0 {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                match self.client.get(&url).send().await {
                    Ok(r) if r.status().is_success() => {
                        response_opt = Some(r);
                        break;
                    }
                    _ => continue,
                }
            }

            if let Some(response) = response_opt {
                if let Ok(json) = response.json::<serde_json::Value>().await {
                    if let Some(ledgers) = json.get("data")
                        .and_then(|d| d.get("ledgers"))
                        .and_then(|l| l.as_array())
                    {
                        for ledger in ledgers {
                            let operator_id = ledger.get("operator_node_id")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let partner_id = ledger.get("partner_node_id")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let role = ledger.get("role")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown")
                                .to_string();
                            let updates = ledger.get("updates")
                                .and_then(|v| v.as_array())
                                .cloned()
                                .unwrap_or_default();

                            if !operator_id.is_empty() && !partner_id.is_empty() {
                                let key = (operator_id, partner_id);
                                all_ledger_data
                                    .entry(key)
                                    .or_default()
                                    .push((node_info.name.clone(), role, updates));
                            }
                        }
                    }
                }
            }
        }

        if all_ledger_data.is_empty() {
            println!("No ledgers found across any nodes.");
            return Ok(());
        }

        // For each unique ledger (operator -> partner), display updates with sync info
        // Sort alphabetically by operator name, then partner name for stable output
        let mut ledger_keys: Vec<_> = all_ledger_data.keys().cloned().collect();
        ledger_keys.sort_by(|(op1, p1), (op2, p2)| {
            let op1_name = self.find_node_name_by_pubkey(op1).unwrap_or_else(|| op1.clone());
            let op2_name = self.find_node_name_by_pubkey(op2).unwrap_or_else(|| op2.clone());
            let p1_name = self.find_node_name_by_pubkey(p1).unwrap_or_else(|| p1.clone());
            let p2_name = self.find_node_name_by_pubkey(p2).unwrap_or_else(|| p2.clone());
            (&op1_name, &p1_name).cmp(&(&op2_name, &p2_name))
        });

        for (operator_pubkey, partner_pubkey) in ledger_keys {
            let entries = all_ledger_data.get(&(operator_pubkey.clone(), partner_pubkey.clone())).unwrap();

            let operator_name = self.find_node_name_by_pubkey(&operator_pubkey)
                .unwrap_or_else(|| operator_pubkey[..8.min(operator_pubkey.len())].to_string());
            let partner_name = self.find_node_name_by_pubkey(&partner_pubkey)
                .unwrap_or_else(|| partner_pubkey[..8.min(partner_pubkey.len())].to_string());

            // Find the "direct" entry (from the operator) - this is the authoritative source
            let direct_entry = entries.iter()
                .find(|(_, role, _)| role == "direct");

            if direct_entry.is_none() {
                continue; // Skip if no direct ledger (operator's view)
            }

            let (_, _, direct_updates) = direct_entry.unwrap();

            // Find the partner entry (the partner's view of this ledger)
            let partner_entry = entries.iter()
                .find(|(_, role, _)| role == "partner");

            // Collect all audit entries
            let audit_entries: Vec<_> = entries.iter()
                .filter(|(_, role, _)| role == "audit")
                .collect();

            // Build hash sets for quick lookup
            let partner_hashes: HashSet<String> = partner_entry
                .map(|(_, _, updates)| {
                    updates.iter()
                        .filter_map(|u| u.get("consensus_hash").and_then(|v| v.as_str()).map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();

            // For each audit entry, collect their hashes
            let audit_hash_sets: Vec<HashSet<String>> = audit_entries.iter()
                .map(|(_, _, updates)| {
                    updates.iter()
                        .filter_map(|u| u.get("consensus_hash").and_then(|v| v.as_str()).map(|s| s.to_string()))
                        .collect()
                })
                .collect();

            // Print header
            println!("{} → {} ({} updates)", operator_name, partner_name, direct_updates.len());

            // Print each update from the direct ledger with sync indicators
            for update in direct_updates {
                self.print_update_line_with_sync(update, &partner_hashes, &audit_hash_sets);
            }
            println!();
        }

        Ok(())
    }

    /// Print an update line with sync status indicators
    /// Format: "  $seq [$from~$to] P#🔒 $kind $key_parameters"
    /// Where P = partner has it (✓/·), # = audit count (0-9), 🔒 = committed
    fn print_update_line_with_sync(
        &self,
        update: &serde_json::Value,
        partner_hashes: &std::collections::HashSet<String>,
        audit_hash_sets: &[std::collections::HashSet<String>],
    ) {
        print!("  ");

        // Sequence number (right-aligned, 3 chars)
        if let Some(seq) = update.get("sequence_number").and_then(|v| v.as_u64()) {
            print!("{:>3} ", seq);
        } else {
            print!("  ? ");
        }

        // Hash transition [$from~$to]
        let prev = update.get("previous_hash").and_then(|v| v.as_str()).unwrap_or("????????");
        let curr = update.get("consensus_hash").and_then(|v| v.as_str()).unwrap_or("????????");
        let prev_abbr = if prev.len() >= 8 { &prev[..8] } else { prev };
        let curr_abbr = if curr.len() >= 8 { &curr[..8] } else { curr };
        print!("[{}~{}] ", prev_abbr, curr_abbr);

        // Sync indicators: P#🔒
        // P = partner has this hash (✓ or ·)
        let partner_has = partner_hashes.contains(curr);
        let partner_indicator = if partner_has { "✓" } else { "·" };

        // # = count of audit chains that have this hash (single digit, max 9)
        let audit_count = audit_hash_sets.iter()
            .filter(|set| set.contains(curr))
            .count()
            .min(9);

        // 🔒 = committed flag
        let is_committed = update.get("committed").and_then(|v| v.as_bool()).unwrap_or(false);
        let commit_indicator = if is_committed { "🔒" } else { "  " };

        print!("{}{}{} ", partner_indicator, audit_count, commit_indicator);

        // Update type (kind) - padded to 24 chars for alignment
        let update_type = update.get("update_type").and_then(|v| v.as_str()).unwrap_or("Unknown");
        print!("{:<24}", update_type);

        // Key parameters (amount, deposit_pubkey, collateral_partner)
        let mut params = Vec::new();

        if let Some(amount) = update.get("amount").and_then(|v| v.as_u64()) {
            params.push(format!("{} sat", amount));
        }

        if let Some(pubkey) = update.get("deposit_pubkey").and_then(|v| v.as_str()) {
            let abbr = if pubkey.len() >= 8 { &pubkey[..8] } else { pubkey };
            params.push(format!("pk:{}", abbr));
        }

        if let Some(cp) = update.get("collateral_partner").and_then(|v| v.as_str()) {
            let display = self.find_node_name_by_pubkey(cp)
                .unwrap_or_else(|| {
                    if cp.len() >= 8 { cp[..8].to_string() } else { cp.to_string() }
                });
            params.push(format!("cp:{}", display));
        }

        if !params.is_empty() {
            print!(" {}", params.join(" "));
        }

        println!();
    }

    async fn print_ledger_updates_compact(&self, updates: &Vec<serde_json::Value>) {
        if updates.is_empty() {
            println!("      (No updates)");
            return;
        }

        for (i, update) in updates.iter().enumerate() {
            print!("      {}. ", i + 1);

            if let Some(update_type) = update.get("update_type").and_then(|v| v.as_str()) {
                print!("{}", update_type);
            }

            if let Some(amount) = update.get("amount").and_then(|v| v.as_u64()) {
                print!(" ({} sat)", amount);
            }

            if let Some(timestamp) = update.get("timestamp").and_then(|v| v.as_u64()) {
                let datetime = chrono::DateTime::from_timestamp(timestamp as i64, 0)
                    .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                    .unwrap_or_else(|| format!("{}", timestamp));
                print!(" at {}", datetime);
            }

            println!();
        }
        println!();
    }


    fn print_update_line(&self, update: &serde_json::Value) {
        // Format: "  $seq [$from~$to] $kind $key_parameters"
        print!("  ");

        // Sequence number (right-aligned, 3 chars)
        if let Some(seq) = update.get("sequence_number").and_then(|v| v.as_u64()) {
            print!("{:>3} ", seq);
        } else {
            print!("  ? ");
        }

        // Hash transition [$from~$to]
        let prev = update.get("previous_hash").and_then(|v| v.as_str()).unwrap_or("????????");
        let curr = update.get("consensus_hash").and_then(|v| v.as_str()).unwrap_or("????????");
        let prev_abbr = if prev.len() >= 8 { &prev[..8] } else { prev };
        let curr_abbr = if curr.len() >= 8 { &curr[..8] } else { curr };
        print!("[{}~{}] ", prev_abbr, curr_abbr);

        // Update type (kind) - padded to 24 chars for alignment
        let update_type = update.get("update_type").and_then(|v| v.as_str()).unwrap_or("Unknown");
        print!("{:<24}", update_type);

        // Key parameters (amount, deposit_pubkey, collateral_partner, status markers)
        let mut params = Vec::new();

        if let Some(amount) = update.get("amount").and_then(|v| v.as_u64()) {
            params.push(format!("{} sat", amount));
        }

        if let Some(pubkey) = update.get("deposit_pubkey").and_then(|v| v.as_str()) {
            // Abbreviate pubkey to first 8 chars
            let abbr = if pubkey.len() >= 8 { &pubkey[..8] } else { pubkey };
            params.push(format!("pk:{}", abbr));
        }

        // Collateral partner (for AddCollateralPartner, CollateralAttestation)
        if let Some(cp) = update.get("collateral_partner").and_then(|v| v.as_str()) {
            // Try to resolve to a node name
            let display = self.find_node_name_by_pubkey(cp)
                .unwrap_or_else(|| {
                    if cp.len() >= 8 { cp[..8].to_string() } else { cp.to_string() }
                });
            params.push(format!("cp:{}", display));
        }

        // Status markers
        let is_acknowledged = update.get("acknowledged").and_then(|v| v.as_bool()).unwrap_or(false);
        let is_committed = update.get("committed").and_then(|v| v.as_bool()).unwrap_or(false);
        if is_acknowledged {
            params.push("✓".to_string());
        }
        if is_committed {
            params.push("🔒".to_string());
        }

        if !params.is_empty() {
            print!(" {}", params.join(" "));
        }

        println!();
    }

    fn find_node_name_by_pubkey(&self, pubkey: &str) -> Option<String> {
        // Try exact match first
        if let Some(name) = self.pubkey_to_name.get(pubkey) {
            return Some(name.clone());
        }

        // Try prefix match (for abbreviated pubkeys)
        for (cached_pubkey, name) in &self.pubkey_to_name {
            if cached_pubkey.starts_with(pubkey) || pubkey.starts_with(cached_pubkey) {
                return Some(name.clone());
            }
        }

        None
    }

    async fn get_node_pubkey(&self, node_id: &str) -> Result<String, Box<dyn Error>> {
        let node = self.nodes.get(node_id)
            .ok_or_else(|| format!("Unknown node: {}", node_id))?;

        let info = self.get_node_info(node_id).await?;
        info.get("data")
            .and_then(|d| d.get("node_id"))
            .and_then(|id| id.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| "No node_id in info response".into())
    }

    async fn get_specific_ledger_updates(&self, node_id: &str, partner_pubkey: &str) -> Result<Vec<serde_json::Value>, Box<dyn Error>> {
        let node = self.nodes.get(node_id)
            .ok_or_else(|| format!("Unknown node: {}", node_id))?;

        let url = format!("{}/bitcoin-deposits/ledger-updates/{}", node.api_url, partner_pubkey);
        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            return Err(format!("API returned status {}", response.status()).into());
        }

        let json: serde_json::Value = response.json().await?;
        json.get("data")
            .and_then(|d| d.get("updates"))
            .and_then(|u| u.as_array())
            .map(|arr| arr.clone())
            .ok_or_else(|| "No updates in response".into())
    }

    async fn print_network_ledgers(&self) -> Result<(), Box<dyn Error>> {
        println!("📋 Bitcoin Deposits Ledgers");
        println!("{}", "=".repeat(100));
        println!("{:<10} {:<10} {:<5} {:<12} {:<12}", "Node", "Partner", "Deps", "Total Deps", "Reserves");
        println!("{}", "-".repeat(100));

        let mut total_ledgers = 0;
        let mut total_deposits_sum = 0u64;
        let mut total_reserves_sum = 0u64;

        for (_node_id, node_info) in &self.nodes {
            // Try to get ledgers from this node
            match self.client.get(&format!("{}/bitcoin-deposits/ledgers", node_info.api_url))
                .send()
                .await {
                Ok(response) => {
                    if response.status().is_success() {
                        match response.json::<Value>().await {
                            Ok(ledger_resp) => {
                                if let Some(success) = ledger_resp.get("success") {
                                    if success.as_bool().unwrap_or(false) {
                                        if let Some(data) = ledger_resp.get("data") {
                                            if let Some(ledgers) = data.get("ledgers").and_then(|l| l.as_array()) {
                                                for ledger in ledgers {
                                                    total_ledgers += 1;

                                                    // Get partner name
                                                    let partner_str = ledger.get("counterparty_node_id")
                                                        .and_then(|v| v.as_str())
                                                        .unwrap_or("unknown");
                                                    let partner_name = self.find_node_name_by_pubkey(partner_str)
                                                        .unwrap_or_else(|| {
                                                            if partner_str.len() >= 8 {
                                                                format!("{}...", &partner_str[..8])
                                                            } else {
                                                                partner_str.to_string()
                                                            }
                                                        });

                                                    // Get deposit count by fetching individual deposits
                                                    let deposit_count = if partner_str != "unknown" {
                                                        if let Ok(deposits_response) = self.client.get(&format!("{}/bitcoin-deposits/deposits/{}", node_info.api_url, partner_str))
                                                            .send()
                                                            .await {
                                                            if let Ok(deposits_json) = deposits_response.json::<Value>().await {
                                                                deposits_json.get("data")
                                                                    .and_then(|d| d.get("deposits"))
                                                                    .and_then(|d| d.as_array())
                                                                    .map(|arr| arr.len())
                                                                    .unwrap_or(0)
                                                            } else {
                                                                0
                                                            }
                                                        } else {
                                                            0
                                                        }
                                                    } else {
                                                        0
                                                    };

                                                    // Get total deposit amounts
                                                    let deposits_sat = ledger.get("deposit_amounts_sat")
                                                        .and_then(|v| v.as_u64())
                                                        .unwrap_or(0);
                                                    total_deposits_sum += deposits_sat;

                                                    // Get reserves
                                                    let reserves_sat = ledger.get("reserves_sat")
                                                        .and_then(|v| v.as_u64())
                                                        .unwrap_or(0);
                                                    total_reserves_sum += reserves_sat;

                                                    println!("{:<10} {:<10} {:<5} {:<12} {:<12}",
                                                        node_info.name,
                                                        partner_name,
                                                        deposit_count,
                                                        format!("{} sat", deposits_sat),
                                                        format!("{} sat", reserves_sat)
                                                    );
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            Err(_) => {}
                        }
                    }
                }
                Err(_) => {}
            }
        }

        println!("{}", "=".repeat(100));
        println!("📊 Summary: {} ledgers, {} sat in deposits, {} sat in reserves",
            total_ledgers, total_deposits_sum, total_reserves_sum);
        println!();
        Ok(())
    }

    async fn print_ledger_detail(&self, node_id: &str, partner_pubkey: &str) -> Result<(), Box<dyn Error>> {
        let node = self.nodes.get(node_id)
            .ok_or_else(|| format!("Unknown node: {}", node_id))?;

        // Resolve partial pubkey to full pubkey
        let full_pubkey = self.resolve_partner_pubkey(node_id, partner_pubkey).await?;

        println!("📋 Ledger Detail - {} with partner", node.name);
        println!("{}", "=".repeat(70));

        // Fetch ledger detail from API
        let url = format!("{}/bitcoin-deposits/ledger/{}", node.api_url, full_pubkey);
        match self.client.get(&url).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    match response.json::<serde_json::Value>().await {
                        Ok(json) => {
                            if let Some(data) = json.get("data") {
                                // Our pubkey
                                if let Some(operator_pubkey) = data.get("operator_pubkey").and_then(|v| v.as_str()) {
                                    let operator_name = self.find_node_name_by_pubkey(operator_pubkey)
                                        .unwrap_or_else(|| "Unknown".to_string());
                                    println!("🔑 Operator: {} ({})", operator_name, operator_pubkey);
                                }

                                // Partner pubkey
                                if let Some(partner_pubkey) = data.get("partner_pubkey").and_then(|v| v.as_str()) {
                                    let partner_name = self.find_node_name_by_pubkey(partner_pubkey)
                                        .unwrap_or_else(|| "Unknown".to_string());
                                    println!("🤝 Partner: {} ({})", partner_name, partner_pubkey);
                                }

                                println!();

                                // Deposits
                                if let Some(deposits) = data.get("total_deposits_sat").and_then(|v| v.as_u64()) {
                                    println!("💰 Total Deposits: {} sat", deposits);
                                }

                                // Max outstanding invoice
                                if let Some(max_outstanding) = data.get("max_outstanding_invoice_sat").and_then(|v| v.as_u64()) {
                                    if max_outstanding > 0 {
                                        println!("📄 Max Outstanding Invoice: {} sat", max_outstanding);
                                    } else {
                                        println!("📄 Max Outstanding Invoice: None");
                                    }
                                }

                                // Reserves
                                if let Some(reserves) = data.get("reserves_sat").and_then(|v| v.as_u64()) {
                                    println!("🏦 Declared Reserves: {} sat", reserves);
                                }

                                println!();

                                // Collateral partners
                                if let Some(collateral_partners) = data.get("collateral_partners").and_then(|v| v.as_array()) {
                                    if !collateral_partners.is_empty() {
                                        println!("🔗 Collateral Partners ({}):", collateral_partners.len());
                                        for (i, cp) in collateral_partners.iter().enumerate() {
                                            let pubkey = cp.get("pubkey").and_then(|v| v.as_str()).unwrap_or("unknown");
                                            let cp_name = self.find_node_name_by_pubkey(pubkey)
                                                .unwrap_or_else(|| "Unknown".to_string());
                                            let has_attestation = cp.get("has_attestation").and_then(|v| v.as_bool()).unwrap_or(false);

                                            println!("   {}. {} ({})", i + 1, cp_name, &pubkey[..16.min(pubkey.len())]);

                                            if has_attestation {
                                                let reserves_output = cp.get("reserves_output_amount").and_then(|v| v.as_u64()).unwrap_or(0);
                                                let reserves_required = cp.get("reserves_required").and_then(|v| v.as_u64()).unwrap_or(0);
                                                let available = cp.get("available_collateral").and_then(|v| v.as_u64()).unwrap_or(0);
                                                let block_height = cp.get("block_height").and_then(|v| v.as_u64()).unwrap_or(0);
                                                println!("      ✅ Attestation: {} sat available ({} sat output - {} sat required) @ block {}",
                                                    available, reserves_output, reserves_required, block_height);
                                            } else {
                                                println!("      ⏳ No attestation yet");
                                            }
                                        }
                                    } else {
                                        println!("🔗 Collateral Partners: None");
                                    }
                                }

                                // Partner attestation
                                if let Some(partner_attestation) = data.get("partner_attestation") {
                                    if !partner_attestation.is_null() {
                                        println!();
                                        println!("📊 Partner Attestation:");
                                        let reserves_output = partner_attestation.get("reserves_output_amount").and_then(|v| v.as_u64()).unwrap_or(0);
                                        let reserves_required = partner_attestation.get("reserves_required").and_then(|v| v.as_u64()).unwrap_or(0);
                                        let available = partner_attestation.get("available_collateral").and_then(|v| v.as_u64()).unwrap_or(0);
                                        let block_height = partner_attestation.get("block_height").and_then(|v| v.as_u64()).unwrap_or(0);
                                        println!("   {} sat available ({} sat output - {} sat required) @ block {}",
                                            available, reserves_output, reserves_required, block_height);
                                    }
                                }

                                // Total collateral
                                if let Some(total_collateral) = data.get("total_available_collateral").and_then(|v| v.as_u64()) {
                                    println!();
                                    println!("📈 Total Available Collateral: {} sat", total_collateral);
                                }
                            } else {
                                println!("   ⚠️  No 'data' field in response");
                            }
                        }
                        Err(e) => println!("   ❌ Failed to parse response: {}", e),
                    }
                } else {
                    println!("   ⚠️  API returned status {}", response.status());
                    if let Ok(text) = response.text().await {
                        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                            if let Some(error) = json.get("error").and_then(|e| e.as_str()) {
                                println!("   Error: {}", error);
                            }
                        }
                    }
                }
            }
            Err(e) => println!("   ❌ Failed to connect: {}", e),
        }

        println!();
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let matches = Command::new("status")
        .about("Bitcoin Deposits Network Status Tool")
        .version("1.0")
        .subcommand(
            Command::new("node")
                .about("Show status of a specific node")
                .arg(Arg::new("name")
                    .help(&format!("Node name ({})", NetworkConfig::all_node_names_string()))
                    .required(true)
                    .index(1))
        )
        .subcommand(
            Command::new("network")
                .about("Show status of all nodes")
        )
        .subcommand(
            Command::new("channels")
                .about("Show all network channels")
        )
        .subcommand(
            Command::new("ledgers")
                .about("Show Bitcoin Deposits ledgers")
                .arg(Arg::new("node")
                    .help(&format!("Optional: specific node name ({})", NetworkConfig::all_node_names_string()))
                    .required(false)
                    .index(1))
        )
        .subcommand(
            Command::new("ledger-updates")
                .about("Show ledger update history (cross-node view if no node specified)")
                .arg(Arg::new("node")
                    .help(&format!("Optional: node name ({}) - omit for cross-node view", NetworkConfig::all_node_names_string()))
                    .required(false)
                    .index(1))
                .arg(Arg::new("partner")
                    .help("Optional: partner node public key (shows all if omitted)")
                    .required(false)
                    .index(2))
                .arg(Arg::new("verbose")
                    .short('v')
                    .long("verbose")
                    .help("Show all updates for all ledgers (including audit ledgers)")
                    .action(clap::ArgAction::SetTrue))
        )
        .subcommand(
            Command::new("ledger")
                .about("Show detailed ledger info including collateral partners")
                .arg(Arg::new("node")
                    .help(&format!("Node name ({})", NetworkConfig::all_node_names_string()))
                    .required(true)
                    .index(1))
                .arg(Arg::new("partner")
                    .help("Partner node public key (or prefix)")
                    .required(true)
                    .index(2))
        )
        .get_matches();

    let mut status = NetworkStatus::new();

    // Initialize pubkey cache for name resolution
    let _ = status.init_pubkey_cache().await;

    match matches.subcommand() {
        Some(("node", sub_matches)) => {
            let node_name = sub_matches.get_one::<String>("name").unwrap();
            status.print_node_status(node_name).await?;
        }
        Some(("network", _)) => {
            status.print_all_nodes_status().await?;
        }
        Some(("channels", _)) => {
            status.print_network_channels().await?;
        }
        Some(("ledgers", sub_matches)) => {
            if let Some(node_name) = sub_matches.get_one::<String>("node") {
                status.print_node_ledgers(node_name).await?;
            } else {
                status.print_network_ledgers().await?;
            }
        }
        Some(("ledger-updates", sub_matches)) => {
            let verbose = sub_matches.get_flag("verbose");
            if let Some(node_name) = sub_matches.get_one::<String>("node") {
                if let Some(partner_pubkey) = sub_matches.get_one::<String>("partner") {
                    status.print_ledger_updates(node_name, partner_pubkey).await?;
                } else {
                    status.print_all_ledger_updates(node_name, verbose).await?;
                }
            } else {
                // Cross-node view when no node specified
                status.print_cross_node_ledger_updates().await?;
            }
        }
        Some(("ledger", sub_matches)) => {
            let node_name = sub_matches.get_one::<String>("node").unwrap();
            let partner_pubkey = sub_matches.get_one::<String>("partner").unwrap();
            status.print_ledger_detail(node_name, partner_pubkey).await?;
        }
        _ => {
            println!("Bitcoin Deposits Network Status Tool");
            println!("Usage:");
            println!("  status node <name>          - Show detailed status of a specific node");
            println!("  status network              - Show summary of all nodes");
            println!("  status channels             - Show all network channels");
            println!("  status ledgers [node]       - Show Bitcoin Deposits ledgers (all or specific node)");
            println!("  status ledger-updates               - Show cross-node ledger sync view (all nodes)");
            println!("  status ledger-updates <node> [-v]   - Show ledger updates for a specific node");
            println!("  status ledger <node> <partner_pubkey> - Show detailed ledger info with collateral partners");
            println!();
            println!("Available nodes: {}", NetworkConfig::all_node_names_string());
        }
    }

    Ok(())
}
