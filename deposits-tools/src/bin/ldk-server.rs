use ldk_node::{Builder, Event, Node};
use ldk_node::config::Config;
use ldk_node::entropy::NodeEntropy;
use deposits_tools::nwc_service::NWCService;
use deposits_ldk::handler::{
    RecoveryOperations, LedgerOperationsExt, DepositOperations,
    ReservesOperations, CollateralOperations
};
use deposits_ldk::service::{
    proto, endpoints,
    InitLedgerRequest, InitLedgerResponse,
    ListLedgersRequest, ListLedgersResponse,
    GetLedgerRequest, GetLedgerResponse,
    CloseLedgerRequest, CloseLedgerResponse,
    AddDepositRequest, AddDepositResponse,
    ListDepositsRequest, ListDepositsResponse,
    RemoveDepositRequest, RemoveDepositResponse,
    ReduceReservesRequest, ReduceReservesResponse,
    GetLedgerUpdatesRequest, GetLedgerUpdatesResponse,
    AddCollateralPartnerRequest, AddCollateralPartnerResponse,
    RemoveCollateralPartnerRequest, RemoveCollateralPartnerResponse,
    GetCollateralInfoRequest, GetCollateralInfoResponse,
    DepositsError,
};
use deposits_ldk::service::{ledger, deposit, reserves, collateral, updates};
use prost::Message;
use std::env;
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use chrono;
use ldk_node::bitcoin::hashes::Hash;
use ldk_node::lightning_invoice::Bolt11Invoice as LdkBolt11Invoice;
use warp::Reply;
use warp::http::StatusCode;

#[derive(Serialize, Deserialize)]
struct ApiResponse<T> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct NodeInfo {
    node_id: String,
    listening_addresses: Vec<String>,
    num_channels: usize,
    num_peers: usize,
}

#[derive(Serialize, Deserialize)]
struct ChannelInfo {
    channel_id: String,
    user_channel_id: String,
    counterparty_node_id: String,
    channel_value_sats: u64,
    balance_msat: u64,
    outbound_capacity_msat: u64,
    inbound_capacity_msat: u64,
    is_channel_ready: bool,
    is_usable: bool,
}

#[derive(Serialize, Deserialize)]
struct ConnectPeerRequest {
    pubkey: String,
    host: String,
    port: u16,
}

#[derive(Serialize, Deserialize)]
struct OpenChannelRequest {
    pubkey: String,
    amount_sat: u64,
    push_to_counterparty_msat: Option<u64>,
    announce: Option<bool>,
}

#[derive(Serialize, Deserialize)]
struct ForceCloseChannelRequest {
    user_channel_id: String,
    counterparty_node_id: String,
    reason: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct BitcoinAddressResponse {
    address: String,
}

#[derive(Serialize, Deserialize)]
struct BalanceResponse {
    balance_sat: u64,
    pending_balance_sat: u64,
}

#[derive(Serialize, Deserialize)]
struct CreateInvoiceRequest {
    amount_msat: u64,
    description: String,
    expiry_secs: Option<u32>,
}

#[derive(Serialize, Deserialize)]
struct InvoiceResponse {
    bolt11_invoice: String,
    payment_hash: String,
}

#[derive(Serialize, Deserialize)]
struct PayInvoiceRequest {
    invoice: String,
}

#[derive(Serialize, Deserialize)]
struct PaymentResponse {
    payment_hash: String,
    status: String,
}

#[derive(Serialize, Deserialize)]
struct LedgerInfo {
    ledger_id: String,
    channel_id: String,
    counterparty_node_id: String,
    status: String,
    operator_sat: u64,
    local_reserves_sat: u64,
    remote_reserves_sat: u64,
    partner_sat: u64,
    other_sat: u64,
    capacity_sat: u64,
    deposit_amounts_sat: u64,
    max_outstanding_invoices_sat: u64,
    last_updated: String,
}

#[derive(Serialize, Deserialize)]
struct LedgersResponse {
    ledgers: Vec<LedgerInfo>,
    total_ledgers: usize,
    active_ledgers: usize,
}

#[derive(Serialize, Deserialize)]
struct DepositRequest {
    /// Partner node ID to create deposit with
    partner_node_id: String,
    /// Channel ID for the deposit (optional - will auto-select if not provided)
    #[serde(default)]
    channel_id: Option<String>,
    /// Deposit public key
    deposit_pubkey: String,
    /// Optional initial amount in sats (0 for empty deposit)
    amount_sat: Option<u64>,
    /// Optional metadata for the deposit
    metadata: Option<serde_json::Value>,
}

#[derive(Serialize, Deserialize)]
struct DepositResponse {
    /// Deposit public key
    deposit_pubkey: String,
    /// Partner node ID
    partner_node_id: String,
    /// Channel ID
    channel_id: String,
    /// Deposit address (if applicable)
    deposit_address: Option<String>,
    /// Current balance
    balance_sat: u64,
    /// Creation timestamp
    created_at: String,
    /// Success status
    created: bool,
}

/// Helper to create a proto response with the given body
fn proto_response<T: Message>(msg: T) -> warp::reply::Response {
    warp::reply::with_status(
        warp::reply::with_header(
            msg.encode_to_vec(),
            "Content-Type",
            "application/octet-stream",
        ),
        StatusCode::OK,
    ).into_response()
}

/// Helper to create a proto error response
fn proto_error_response(code: &str, message: &str) -> warp::reply::Response {
    let error = DepositsError {
        code: code.to_string(),
        message: message.to_string(),
    };
    warp::reply::with_status(
        warp::reply::with_header(
            error.encode_to_vec(),
            "Content-Type",
            "application/octet-stream",
        ),
        StatusCode::BAD_REQUEST,
    ).into_response()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logger (must be done before any logging)
    // Note: No default filter - only modules specified in RUST_LOG will produce logs
    env_logger::Builder::from_env(env_logger::Env::default()).init();

    log::info!("🚀 LDK Server starting up");

    // Environment configuration
    let node_name = env::var("NODE_NAME").unwrap_or_else(|_| "default".to_string());
    log::info!("📝 Node name: {}", node_name);
    let data_dir = env::var("LDK_DATA_DIR").unwrap_or_else(|_| format!("/tmp/ldk/{}", node_name));
    let bitcoin_rpc_host = env::var("BITCOIN_RPC_HOST").unwrap_or_else(|_| "localhost".to_string());
    let bitcoin_rpc_port = env::var("BITCOIN_RPC_PORT").unwrap_or_else(|_| "18443".to_string());
    let bitcoin_rpc_user = env::var("BITCOIN_RPC_USER").unwrap_or_else(|_| "user".to_string());
    let bitcoin_rpc_password = env::var("BITCOIN_RPC_PASSWORD").unwrap_or_else(|_| "pass".to_string());
    let electrum_host = env::var("ELECTRUM_HOST").unwrap_or_else(|_| "localhost".to_string());
    let electrum_port = env::var("ELECTRUM_PORT").unwrap_or_else(|_| "3002".to_string());
    let listen_port: u16 = env::var("LISTEN_PORT").unwrap_or_else(|_| "9735".to_string()).parse()?;
    let api_port: u16 = env::var("API_PORT").unwrap_or_else(|_| "3000".to_string()).parse()?;
    let enable_deposits = env::var("ENABLE_DEPOSITS").unwrap_or_else(|_| "false".to_string()) == "true";
    let nostr_relay_url = env::var("NOSTR_RELAY_URL").unwrap_or_else(|_| "ws://localhost:7777".to_string());

    // Network configuration (regtest, signet, testnet, bitcoin)
    let network_str = env::var("NETWORK").unwrap_or_else(|_| "regtest".to_string());
    let network = match network_str.to_lowercase().as_str() {
        "mainnet" | "bitcoin" => ldk_node::bitcoin::Network::Bitcoin,
        "testnet" | "testnet3" => ldk_node::bitcoin::Network::Testnet,
        "signet" | "mutinynet" => ldk_node::bitcoin::Network::Signet,
        "regtest" | _ => ldk_node::bitcoin::Network::Regtest,
    };

    // Chain source configuration (bitcoind_rpc, esplora, electrum)
    let chain_source = env::var("CHAIN_SOURCE").unwrap_or_else(|_| "bitcoind_rpc".to_string());
    let esplora_url = env::var("ESPLORA_URL").unwrap_or_else(|_| "".to_string());

    println!("🚀 Starting LDK Node Server: {}", node_name);
    println!("📁 Data directory: {}", data_dir);
    println!("⚡ P2P port: {}", listen_port);
    println!("🌐 API port: {}", api_port);
    println!("🔗 Network: {:?}", network);
    println!("⛓️  Chain source: {}", chain_source);
    println!("₿ Bitcoin Deposits: {}", if enable_deposits { "enabled" } else { "disabled" });
    println!("📡 Nostr relay: {}", nostr_relay_url);

    // Create and configure LDK node
    let mut config = Config::default();
    config.listening_addresses = Some(vec![ldk_node::lightning::ln::msgs::SocketAddress::TcpIpV4 { addr: [0, 0, 0, 0], port: listen_port }]);
    config.network = network;

    // Set node alias from env or generate from data dir name (required for announced channels)
    let alias_str = std::env::var("LDK_ALIAS").unwrap_or_else(|_| {
        // Extract node name from data dir (e.g., "/ldk/alice" -> "alice")
        std::path::Path::new(&data_dir)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("ldk-node")
            .to_string()
    });
    // Convert to NodeAlias (32-byte array, padded with zeros)
    let mut alias_bytes = [0u8; 32];
    let alias_slice = alias_str.as_bytes();
    alias_bytes[..alias_slice.len().min(32)].copy_from_slice(&alias_slice[..alias_slice.len().min(32)]);
    config.node_alias = Some(ldk_node::lightning::routing::gossip::NodeAlias(alias_bytes));
    println!("📛 Node alias: {}", alias_str);

    // Enable trust for own 0-conf channels and set minimum depth to 0 for regtest
    config.trusted_peers_0conf = vec![];  // Trust all peers for 0-conf in regtest
    config.probing_liquidity_limit_multiplier = 3;

    let mut builder = Builder::from_config(config);
    builder.set_storage_dir_path(data_dir.clone());

    // Use log facade to forward Lightning logs to env_logger/stdout
    builder.set_log_facade_logger();

    // Configure chain source based on CHAIN_SOURCE env var
    match chain_source.to_lowercase().as_str() {
        "esplora" => {
            if esplora_url.is_empty() {
                panic!("ESPLORA_URL must be set when using esplora chain source");
            }
            println!("📡 Using Esplora: {}", esplora_url);
            builder.set_chain_source_esplora(esplora_url, None);
        }
        "electrum" => {
            let electrum_url = format!("tcp://{}:{}", electrum_host, electrum_port);
            println!("📡 Using Electrum: {}", electrum_url);
            builder.set_chain_source_electrum(electrum_url, None);
        }
        "bitcoind_rpc" | _ => {
            println!("📡 Using bitcoind RPC: {}:{}", bitcoin_rpc_host, bitcoin_rpc_port);
            builder.set_chain_source_bitcoind_rpc(
                bitcoin_rpc_host,
                bitcoin_rpc_port.parse().expect("Invalid Bitcoin RPC port"),
                bitcoin_rpc_user,
                bitcoin_rpc_password,
            );
        }
    }

    #[cfg(feature = "bitcoin-deposits")]
    if enable_deposits {
        builder.set_bitcoin_deposits_enabled(true);
        println!("✅ Bitcoin Deposits enabled");
    }

    // Create node entropy from seed file (will generate if not exists)
    let seed_path = format!("{}/keys_seed", data_dir);
    let node_entropy = NodeEntropy::from_seed_path(seed_path)?;

    let node = Arc::new(builder.build(node_entropy)?);
    node.start()?;

    println!("✅ LDK Node started successfully");
    println!("🔑 Node ID: {}", node.node_id());

    // Create NWC service BEFORE event loop so it can be used in event handlers
    let nwc_node = Arc::clone(&node);
    let nwc_relay_url = nostr_relay_url.clone();
    let nwc_private_key = std::env::var("NWC_PRIVATE_KEY").ok();
    let nwc_service = if let Some(private_key_hex) = nwc_private_key {
        NWCService::new_with_key(nwc_node, nwc_relay_url, listen_port, private_key_hex)
    } else {
        NWCService::new(nwc_node, nwc_relay_url, listen_port)
    };

    let nwc_service = match nwc_service {
        Ok(service) => {
            let nwc_pubkey = service.pubkey();
            println!("📢 NWC Service pubkey available at /nwc/pubkey: {}", nwc_pubkey);
            Arc::new(service)
        }
        Err(e) => {
            eprintln!("❌ Failed to create NWC service: {}", e);
            return Err(e);
        }
    };

    // Clone node and NWC service for the event handler
    let event_node = Arc::clone(&node);
    let event_nwc_service = Arc::clone(&nwc_service);

    // Start event handling loop
    tokio::spawn(async move {
        loop {
            // Use async version to avoid blocking the tokio runtime
            // This allows oneshot receivers to be polled properly
            let event = event_node.next_event_async().await;
            println!("📨 Event: {:?}", event);

            #[cfg(feature = "bitcoin-deposits")]
            if enable_deposits {
                match event_node.process_event_with_deposits(&event) {
                    Ok(handled) => {
                        if handled {
                            println!("✅ Event handled by Bitcoin Deposits");
                            event_node.event_handled();
                            continue;
                        }
                    }
                    Err(e) => {
                        eprintln!("❌ Bitcoin Deposits event processing error: {}", e);
                    }
                }
            }

            // Handle regular Lightning events
            match &event {
                Event::ChannelReady { .. } => {
                    println!("🎉 Channel ready!");
                }
                Event::PaymentSuccessful { payment_id, payment_preimage, .. } => {
                    println!("💰 Payment successful!");
                    if let Some(id) = payment_id {
                        let preimage_bytes = payment_preimage.map(|p| p.0);
                        event_nwc_service.handle_payment_successful(id.0, preimage_bytes).await;
                    }
                }
                Event::PaymentFailed { payment_id, reason, .. } => {
                    println!("❌ Payment failed!");
                    if let Some(id) = payment_id {
                        let reason_str = format!("{:?}", reason);
                        event_nwc_service.handle_payment_failed(id.0, reason_str).await;
                    }
                }
                Event::PaymentReceived { .. } => {
                    println!("💳 Payment received!");
                }
                _ => {}
            }

            event_node.event_handled();
        }
    });

    // Rebuild NWC access registry from persisted deposits
    if let Err(e) = nwc_service.rebuild_access_registry_from_deposits().await {
        eprintln!("⚠️  Warning: Failed to rebuild NWC access registry: {}", e);
    }

    // Start NWC service
    let nwc_service_for_task = Arc::clone(&nwc_service);
    tokio::spawn(async move {
        if let Err(e) = nwc_service_for_task.start().await {
            eprintln!("❌ NWC service error: {}", e);
        }
    });

    // Start HTTP API server
    let api_node = Arc::clone(&node);
    start_api_server(api_node, Some(nwc_service), api_port).await?;

    Ok(())
}

async fn start_api_server(node: Arc<Node>, nwc_service: Option<Arc<NWCService>>, port: u16) -> Result<(), Box<dyn std::error::Error>> {
    use warp::Filter;

    println!("🌐 Starting HTTP API server on port {}", port);

    // Health check endpoint
    let health = warp::path("health")
        .and(warp::get())
        .map(|| {
            warp::reply::json(&ApiResponse {
                success: true,
                data: Some(serde_json::json!({"status": "ok"})),
                error: None,
            })
        });

    // Node info endpoint
    let node_info = {
        let node = Arc::clone(&node);
        warp::path("info")
            .and(warp::get())
            .map(move || {
                let info = NodeInfo {
                    node_id: node.node_id().to_string(),
                    listening_addresses: node.listening_addresses().unwrap_or_default().iter().map(|a| a.to_string()).collect(),
                    num_channels: node.list_channels().len(),
                    num_peers: node.list_peers().len(),
                };
                warp::reply::json(&ApiResponse {
                    success: true,
                    data: Some(info),
                    error: None,
                })
            })
    };

    // Bitcoin address endpoint
    let bitcoin_address = {
        let node = Arc::clone(&node);
        warp::path!("bitcoin" / "address")
            .and(warp::get())
            .map(move || {
                match node.onchain_payment().new_address() {
                    Ok(address) => {
                        warp::reply::json(&ApiResponse {
                            success: true,
                            data: Some(BitcoinAddressResponse {
                                address: address.to_string(),
                            }),
                            error: None,
                        })
                    }
                    Err(e) => {
                        warp::reply::json(&ApiResponse::<BitcoinAddressResponse> {
                            success: false,
                            data: None,
                            error: Some(e.to_string()),
                        })
                    }
                }
            })
    };

    // Bitcoin balance endpoint
    let bitcoin_balance = {
        let node = Arc::clone(&node);
        warp::path!("bitcoin" / "balance")
            .and(warp::get())
            .map(move || {
                let balances = node.list_balances();
                warp::reply::json(&ApiResponse {
                    success: true,
                    data: Some(BalanceResponse {
                        balance_sat: balances.total_onchain_balance_sats,
                        pending_balance_sat: balances.total_lightning_balance_sats,
                    }),
                    error: None,
                })
            })
    };

    // Bitcoin send endpoint
    #[derive(Deserialize)]
    struct BitcoinSendRequest {
        address: String,
        amount_sat: Option<u64>,  // If None, send all
    }
    let bitcoin_send = {
        let node = Arc::clone(&node);
        warp::path!("bitcoin" / "send")
            .and(warp::post())
            .and(warp::body::json())
            .map(move |req: BitcoinSendRequest| {
                use std::str::FromStr;
                match bitcoin::Address::from_str(&req.address) {
                    Ok(address) => {
                        // Require valid network
                        let address = match address.require_network(node.config().network.into()) {
                            Ok(addr) => addr,
                            Err(e) => {
                                return warp::reply::json(&ApiResponse::<serde_json::Value> {
                                    success: false,
                                    data: None,
                                    error: Some(format!("Invalid address network: {}", e)),
                                });
                            }
                        };
                        let result = match req.amount_sat {
                            Some(amount) => node.onchain_payment().send_to_address(&address, amount, None),
                            None => node.onchain_payment().send_all_to_address(&address, false, None), // Sweep all, don't retain reserves
                        };
                        match result {
                            Ok(txid) => {
                                warp::reply::json(&ApiResponse {
                                    success: true,
                                    data: Some(serde_json::json!({
                                        "txid": txid.to_string(),
                                    })),
                                    error: None,
                                })
                            }
                            Err(e) => {
                                warp::reply::json(&ApiResponse::<serde_json::Value> {
                                    success: false,
                                    data: None,
                                    error: Some(format!("Send failed: {:?}", e)),
                                })
                            }
                        }
                    }
                    Err(e) => {
                        warp::reply::json(&ApiResponse::<serde_json::Value> {
                            success: false,
                            data: None,
                            error: Some(format!("Invalid address: {}", e)),
                        })
                    }
                }
            })
    };

    // Connect to peer endpoint
    let connect_peer = {
        let node = Arc::clone(&node);
        warp::path!("peers" / "connect")
            .and(warp::post())
            .and(warp::body::json())
            .map(move |req: ConnectPeerRequest| {
                match (
                    ldk_node::bitcoin::secp256k1::PublicKey::from_str(&req.pubkey),
                    format!("{}:{}", req.host, req.port).parse(),
                ) {
                    (Ok(pubkey), Ok(address)) => {
                        match node.connect(pubkey, address, true) {
                            Ok(_) => {
                                warp::reply::json(&ApiResponse {
                                    success: true,
                                    data: Some(serde_json::json!({"message": "Connected successfully"})),
                                    error: None,
                                })
                            }
                            Err(e) => {
                                warp::reply::json(&ApiResponse::<serde_json::Value> {
                                    success: false,
                                    data: None,
                                    error: Some(e.to_string()),
                                })
                            }
                        }
                    }
                    _ => {
                        warp::reply::json(&ApiResponse::<serde_json::Value> {
                            success: false,
                            data: None,
                            error: Some("Invalid pubkey or address".to_string()),
                        })
                    }
                }
            })
    };

    // Open channel endpoint
    let open_channel = {
        let node = Arc::clone(&node);
        warp::path!("channels" / "open")
            .and(warp::post())
            .and(warp::body::json())
            .map(move |req: OpenChannelRequest| {
                match ldk_node::bitcoin::secp256k1::PublicKey::from_str(&req.pubkey) {
                    Ok(pubkey) => {
                        // Use announced or private channel based on request
                        let result = if req.announce.unwrap_or(false) {
                            node.open_announced_channel(pubkey,
                                ldk_node::lightning::ln::msgs::SocketAddress::TcpIpV4 { addr: [127, 0, 0, 1], port: 9735 },
                                req.amount_sat,
                                req.push_to_counterparty_msat,
                                None
                            )
                        } else {
                            node.open_channel(pubkey,
                                ldk_node::lightning::ln::msgs::SocketAddress::TcpIpV4 { addr: [127, 0, 0, 1], port: 9735 },
                                req.amount_sat,
                                req.push_to_counterparty_msat,
                                None
                            )
                        };
                        match result {
                            Ok(user_channel_id) => {
                                warp::reply::json(&ApiResponse {
                                    success: true,
                                    data: Some(serde_json::json!({
                                        "channel_id": format!("{:?}", user_channel_id),
                                        "message": "Channel opening initiated"
                                    })),
                                    error: None,
                                })
                            }
                            Err(e) => {
                                warp::reply::json(&ApiResponse::<serde_json::Value> {
                                    success: false,
                                    data: None,
                                    error: Some(e.to_string()),
                                })
                            }
                        }
                    }
                    Err(e) => {
                        warp::reply::json(&ApiResponse::<serde_json::Value> {
                            success: false,
                            data: None,
                            error: Some(e.to_string()),
                        })
                    }
                }
            })
    };

    // Force close channel endpoint
    let force_close_channel = {
        let node = Arc::clone(&node);
        warp::path!("channels" / "force-close")
            .and(warp::post())
            .and(warp::body::json())
            .map(move |req: ForceCloseChannelRequest| {
                match (
                    req.user_channel_id.parse::<u128>(),
                    ldk_node::bitcoin::secp256k1::PublicKey::from_str(&req.counterparty_node_id),
                ) {
                    (Ok(user_channel_id_value), Ok(counterparty_pubkey)) => {
                        let user_channel_id = ldk_node::UserChannelId(user_channel_id_value);

                        match node.force_close_channel(&user_channel_id, counterparty_pubkey, req.reason) {
                            Ok(_) => {
                                warp::reply::json(&ApiResponse {
                                    success: true,
                                    data: Some(serde_json::json!({"message": "Channel force-closed successfully"})),
                                    error: None,
                                })
                            }
                            Err(e) => {
                                warp::reply::json(&ApiResponse::<serde_json::Value> {
                                    success: false,
                                    data: None,
                                    error: Some(e.to_string()),
                                })
                            }
                        }
                    }
                    _ => {
                        warp::reply::json(&ApiResponse::<serde_json::Value> {
                            success: false,
                            data: None,
                            error: Some("Invalid user_channel_id or counterparty_node_id".to_string()),
                        })
                    }
                }
            })
    };

    // List channels endpoint
    let list_channels = {
        let node = Arc::clone(&node);
        warp::path("channels")
            .and(warp::get())
            .map(move || {
                let channels: Vec<ChannelInfo> = node.list_channels().iter().map(|c| {
                    ChannelInfo {
                        channel_id: hex::encode(c.channel_id.0),
                        user_channel_id: c.user_channel_id.0.to_string(),
                        counterparty_node_id: c.counterparty_node_id.to_string(),
                        channel_value_sats: c.channel_value_sats,
                        balance_msat: c.outbound_capacity_msat,
                        outbound_capacity_msat: c.outbound_capacity_msat,
                        inbound_capacity_msat: c.inbound_capacity_msat,
                        is_channel_ready: c.is_channel_ready,
                        is_usable: c.is_usable,
                    }
                }).collect();

                warp::reply::json(&ApiResponse {
                    success: true,
                    data: Some(channels),
                    error: None,
                })
            })
    };

    // Create Lightning invoice endpoint
    let create_invoice = {
        let node = Arc::clone(&node);
        warp::path("invoice")
            .and(warp::post())
            .and(warp::body::json())
            .map(move |req: CreateInvoiceRequest| {
                let description = ldk_node::lightning_invoice::Bolt11InvoiceDescription::Direct(
                    ldk_node::lightning_invoice::Description::new(req.description.clone()).unwrap()
                );
                match node.bolt11_payment().receive(
                    req.amount_msat,
                    &description,
                    req.expiry_secs.unwrap_or(3600)
                ) {
                    Ok(invoice) => {
                        let payment_hash = hex::encode(invoice.payment_hash().to_byte_array());
                        warp::reply::json(&ApiResponse {
                            success: true,
                            data: Some(InvoiceResponse {
                                bolt11_invoice: invoice.to_string(),
                                payment_hash,
                            }),
                            error: None,
                        })
                    }
                    Err(e) => {
                        warp::reply::json(&ApiResponse::<InvoiceResponse> {
                            success: false,
                            data: None,
                            error: Some(e.to_string()),
                        })
                    }
                }
            })
    };

    // Pay Lightning invoice endpoint
    let pay_invoice = {
        let node = Arc::clone(&node);
        warp::path("pay")
            .and(warp::post())
            .and(warp::body::json())
            .map(move |req: PayInvoiceRequest| {
                match req.invoice.parse::<LdkBolt11Invoice>() {
                    Ok(invoice) => {
                        match node.bolt11_payment().send(&invoice, None) {
                            Ok(payment_id) => {
                                warp::reply::json(&ApiResponse {
                                    success: true,
                                    data: Some(PaymentResponse {
                                        payment_hash: format!("{:?}", payment_id),
                                        status: "sent".to_string(),
                                    }),
                                    error: None,
                                })
                            }
                            Err(e) => {
                                warp::reply::json(&ApiResponse::<PaymentResponse> {
                                    success: false,
                                    data: None,
                                    error: Some(e.to_string()),
                                })
                            }
                        }
                    }
                    Err(e) => {
                        warp::reply::json(&ApiResponse::<PaymentResponse> {
                            success: false,
                            data: None,
                            error: Some(format!("Invalid invoice: {}", e)),
                        })
                    }
                }
            })
    };

    #[cfg(feature = "bitcoin-deposits")]
    let deposits_routes = {
        let node = Arc::clone(&node);

        // Initialize Bitcoin Deposits ledger
        let node_for_init = Arc::clone(&node);
        let init_ledger = warp::path!("bitcoin-deposits" / "ledger" / "init")
            .and(warp::post())
            .and(warp::body::json())
            .and_then(move |req: serde_json::Value| {
                let node_for_init = node_for_init.clone();
                async move {
                    #[cfg(feature = "bitcoin-deposits")]
                    {
                        if let Some(bd_handler) = node_for_init.deposits() {
                            // Extract partner_pubkey from request
                            let partner_pubkey_str = req.get("partner_pubkey")
                                .and_then(|v| v.as_str())
                                .unwrap_or("");

                            if partner_pubkey_str.is_empty() {
                                return Ok::<_, warp::Rejection>(warp::reply::json(&ApiResponse::<serde_json::Value> {
                                    success: false,
                                    data: None,
                                    error: Some("partner_pubkey is required".to_string()),
                                }).into_response());
                            }

                            // Parse the partner public key
                            let partner_pubkey = match ldk_node::bitcoin::secp256k1::PublicKey::from_str(partner_pubkey_str) {
                                Ok(pk) => pk,
                                Err(e) => {
                                    return Ok(warp::reply::json(&ApiResponse::<serde_json::Value> {
                                        success: false,
                                        data: None,
                                        error: Some(format!("Invalid partner_pubkey: {}", e)),
                                    }).into_response());
                                }
                            };

                            // Generate a ledger address for this channel
                            use ldk_node::bitcoin::secp256k1::{Secp256k1, SecretKey};
                            use ldk_node::bitcoin::secp256k1::rand::rngs::OsRng;

                            let secp = Secp256k1::new();
                            let mut rng = OsRng;

                            // Generate a proper random private key
                            let secret_key = SecretKey::new(&mut rng);
                            let public_key = ldk_node::bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret_key);

                            // Create P2WPKH address (native segwit)
                            let compressed_pk = match ldk_node::bitcoin::CompressedPublicKey::try_from(ldk_node::bitcoin::PublicKey::new(public_key)) {
                                Ok(pk) => pk,
                                Err(e) => {
                                    return Ok(warp::reply::json(&ApiResponse::<serde_json::Value> {
                                        success: false,
                                        data: None,
                                        error: Some(format!("Failed to compress public key: {}", e)),
                                    }).into_response());
                                }
                            };
                            let ledger_address = ldk_node::bitcoin::Address::p2wpkh(
                                &compressed_pk,
                                ldk_node::bitcoin::Network::Regtest
                            );

                            // Store the private key for this ledger
                            if let Err(e) = bd_handler.store_ledger_private_key(partner_pubkey, secret_key) {
                                return Ok(warp::reply::json(&ApiResponse::<serde_json::Value> {
                                    success: false,
                                    data: None,
                                    error: Some(format!("Failed to store ledger private key: {}", e)),
                                }).into_response());
                            }

                            // Initiate ledger open with partner
                            // This will:
                            // 1. Send LedgerOpenRequest to partner
                            // 2. Partner creates audit ledger on their side
                            // 3. Partner sends LedgerOpenResponse
                            // 4. We create operational ledger on our side
                            match bd_handler.initiate_ledger_handshake_async(partner_pubkey, ledger_address.clone()).await {
                                Ok(()) => {
                                    Ok(warp::reply::json(&ApiResponse {
                                        success: true,
                                        data: Some(serde_json::json!({
                                            "message": "Ledger initialized successfully via handshake",
                                            "partner_pubkey": partner_pubkey_str,
                                            "ledger_address": ledger_address.to_string()
                                        })),
                                        error: None,
                                    }).into_response())
                                }
                                Err(e) => {
                                    let error_msg = format!("{}", e);
                                    // Return 409 Conflict for idempotent "already exists" errors
                                    if error_msg.contains("already exists") {
                                        Ok(warp::reply::with_status(
                                            warp::reply::json(&ApiResponse::<serde_json::Value> {
                                                success: false,
                                                data: None,
                                                error: Some(error_msg),
                                            }),
                                            warp::http::StatusCode::CONFLICT,
                                        ).into_response())
                                    } else {
                                        Ok(warp::reply::json(&ApiResponse::<serde_json::Value> {
                                            success: false,
                                            data: None,
                                            error: Some(format!("Failed to initialize ledger via handshake: {}", e)),
                                        }).into_response())
                                    }
                                }
                            }
                        } else {
                            Ok(warp::reply::json(&ApiResponse::<serde_json::Value> {
                                success: false,
                                data: None,
                                error: Some("Bitcoin Deposits not enabled".to_string()),
                            }).into_response())
                        }
                    }
                    #[cfg(not(feature = "bitcoin-deposits"))]
                    {
                        Ok::<_, warp::Rejection>(warp::reply::json(&ApiResponse::<serde_json::Value> {
                            success: false,
                            data: None,
                            error: Some("Bitcoin Deposits feature not enabled".to_string()),
                        }).into_response())
                    }
                }
            });

        // Start NWC service
        let start_nwc = warp::path!("bitcoin-deposits" / "nwc" / "start")
            .and(warp::post())
            .and(warp::body::json())
            .map(move |req: serde_json::Value| {
                // Mock implementation for now
                warp::reply::json(&ApiResponse {
                    success: true,
                    data: Some(serde_json::json!({"message": "NWC service started"})),
                    error: None,
                })
            });

        // List Bitcoin Deposits ledgers
        let node_for_ledgers = Arc::clone(&node);
        let list_ledgers = warp::path!("bitcoin-deposits" / "ledgers")
            .and(warp::get())
            .map(move || {
                #[cfg(feature = "bitcoin-deposits")]
                {
                    if let Some(bd_handler) = node_for_ledgers.deposits() {
                        let all_ledgers = bd_handler.get_all_ledger_updates();
                        let channels = node_for_ledgers.list_channels();
                        let mut ledgers = Vec::new();
                        let mut active_count = 0;

                        for ((operator_id, partner_id), _updates) in all_ledgers {
                            // Find the corresponding channel to get channel_id and status
                            let counterparty = if operator_id == node_for_ledgers.node_id() {
                                partner_id
                            } else {
                                operator_id
                            };

                            let channel = channels.iter().find(|ch| ch.counterparty_node_id == counterparty);

                            let (channel_id, status, capacity_sat) = if let Some(ch) = channel {
                                let status = if ch.is_channel_ready && ch.is_usable {
                                    active_count += 1;
                                    "active".to_string()
                                } else if ch.is_channel_ready {
                                    "ready".to_string()
                                } else {
                                    "pending".to_string()
                                };
                                (ch.channel_id.to_string(), status, ch.channel_value_sats)
                            } else {
                                ("unknown".to_string(), "unknown".to_string(), 0)
                            };

                            // Get real Bitcoin Deposits data
                            let deposits = bd_handler.get_total_deposit_balances(counterparty).unwrap_or(0);
                            let max_outstanding = bd_handler.get_max_outstanding_invoice_amount(counterparty).unwrap_or(0);
                            let (local_reserves, remote_reserves) = bd_handler.get_channel_reserves(counterparty);
                            let local_reserves = local_reserves.unwrap_or(0);
                            let remote_reserves = remote_reserves.unwrap_or(0);
                            let total_reserves = local_reserves + remote_reserves;

                            // Get balances from channel
                            let (operator_sat, partner_sat, other_sat) = if let Some(ch) = channel {
                                let operator_sat = ch.outbound_capacity_msat / 1000;
                                let partner_sat = ch.inbound_capacity_msat / 1000;
                                let accounted_sat = operator_sat + partner_sat + total_reserves;
                                let other_sat = if capacity_sat > accounted_sat {
                                    capacity_sat - accounted_sat
                                } else {
                                    0
                                };
                                (operator_sat, partner_sat, other_sat)
                            } else {
                                (0, 0, 0)
                            };

                            // Get committed ledger hashes from LDK's channel state (authoritative)
                            let (local_ledger_hash, remote_ledger_hash) = bd_handler.get_committed_ledger_hashes_from_channel(counterparty);
                            let local_hash_hex = local_ledger_hash
                                .map(|h| if h == [0u8; 32] { "n/a".to_string() } else { hex::encode(&h[..8]) })
                                .unwrap_or_else(|| "n/a".to_string());
                            let remote_hash_hex = remote_ledger_hash
                                .map(|h| if h == [0u8; 32] { "n/a".to_string() } else { hex::encode(&h[..8]) })
                                .unwrap_or_else(|| "n/a".to_string());

                            let ledger = serde_json::json!({
                                "ledger_id": format!("ledger_{}", &channel_id[0..8.min(channel_id.len())]),
                                "channel_id": channel_id,
                                "operator_node_id": operator_id.to_string(),
                                "partner_node_id": partner_id.to_string(),
                                "status": status,
                                "operator_sat": operator_sat,
                                "local_reserves_sat": local_reserves,
                                "remote_reserves_sat": remote_reserves,
                                "partner_sat": partner_sat,
                                "other_sat": other_sat,
                                "capacity_sat": capacity_sat,
                                "deposit_amounts_sat": deposits,
                                "max_outstanding_invoices_sat": max_outstanding,
                                "local_ledger_hash": local_hash_hex,
                                "remote_ledger_hash": remote_hash_hex,
                                "last_updated": chrono::Utc::now().to_rfc3339(),
                            });

                            ledgers.push(ledger);
                        }

                        return warp::reply::json(&ApiResponse {
                            success: true,
                            data: Some(serde_json::json!({
                                "total_ledgers": ledgers.len(),
                                "active_ledgers": active_count,
                                "ledgers": ledgers,
                            })),
                            error: None,
                        });
                    }
                }

                // Fallback if Bitcoin Deposits not enabled
                warp::reply::json(&ApiResponse::<serde_json::Value> {
                    success: false,
                    data: None,
                    error: Some("Bitcoin Deposits not enabled".to_string()),
                })
            });

        // Get detailed ledger info including collateral partners
        let node_for_ledger_detail = Arc::clone(&node);
        let get_ledger_detail = warp::path!("bitcoin-deposits" / "ledger" / String)
            .and(warp::get())
            .map(move |partner_pubkey_str: String| {
                #[cfg(feature = "bitcoin-deposits")]
                {
                    if let Some(bd_handler) = node_for_ledger_detail.deposits() {
                        // Parse partner pubkey
                        match partner_pubkey_str.parse::<ldk_node::bitcoin::secp256k1::PublicKey>() {
                            Ok(partner_pubkey) => {
                                let our_pubkey = node_for_ledger_detail.node_id();

                                // Get basic ledger info
                                let deposits = bd_handler.get_total_deposit_balances(partner_pubkey).unwrap_or(0);
                                let max_outstanding = bd_handler.get_max_outstanding_invoice_amount(partner_pubkey).unwrap_or(0);
                                let reserves = bd_handler.get_channel_reserves_amount(partner_pubkey).unwrap_or(0);

                                // Get collateral info
                                let collateral_info = bd_handler.get_collateral_info(partner_pubkey);

                                // Build collateral partners array
                                let collateral_partners_json: Vec<serde_json::Value> = collateral_info.as_ref()
                                    .map(|ci| ci.collateral_partners.iter()
                                        .map(|cp| serde_json::json!({
                                            "pubkey": cp.pubkey.to_string(),
                                            "collateral_amount": cp.collateral_amount,
                                            "block_height": cp.block_height,
                                            "has_attestation": cp.has_attestation,
                                        }))
                                        .collect())
                                    .unwrap_or_default();

                                // Partner attestation (if any)
                                let partner_attestation_json = collateral_info.as_ref()
                                    .and_then(|ci| ci.partner_attestation.as_ref())
                                    .map(|pa| serde_json::json!({
                                        "collateral_amount": pa.collateral_amount,
                                        "block_height": pa.block_height,
                                    }));

                                let total_collateral = collateral_info.as_ref()
                                    .map(|ci| ci.total_available_collateral)
                                    .unwrap_or(0);

                                return warp::reply::json(&ApiResponse {
                                    success: true,
                                    data: Some(serde_json::json!({
                                        "operator_pubkey": our_pubkey.to_string(),
                                        "partner_pubkey": partner_pubkey.to_string(),
                                        "total_deposits_sat": deposits,
                                        "max_outstanding_invoice_sat": max_outstanding,
                                        "reserves_sat": reserves,
                                        "collateral_partners": collateral_partners_json,
                                        "partner_attestation": partner_attestation_json,
                                        "total_available_collateral": total_collateral,
                                    })),
                                    error: None,
                                });
                            }
                            Err(_) => {
                                return warp::reply::json(&ApiResponse::<serde_json::Value> {
                                    success: false,
                                    data: None,
                                    error: Some("Invalid partner pubkey".to_string()),
                                });
                            }
                        }
                    }
                }

                warp::reply::json(&ApiResponse::<serde_json::Value> {
                    success: false,
                    data: None,
                    error: Some("Bitcoin Deposits not enabled".to_string()),
                })
            });

        // Request new deposit via DM-style request
        let node_for_deposit = Arc::clone(&node);
        let request_deposit = warp::path!("bitcoin-deposits" / "deposit" / "request")
            .and(warp::post())
            .and(warp::body::json())
            .map(move |req: DepositRequest| {
                #[cfg(feature = "bitcoin-deposits")]
                {
                    if let Some(bd_handler) = node_for_deposit.deposits() {
                        // Parse partner node ID
                        match req.partner_node_id.parse::<ldk_node::bitcoin::secp256k1::PublicKey>() {
                            Ok(partner_pubkey) => {
                                // Parse deposit pubkey
                                match req.deposit_pubkey.parse::<ldk_node::bitcoin::secp256k1::PublicKey>() {
                                    Ok(deposit_pubkey) => {
                                        // Get channel ID - either from request or auto-select
                                        let (channel_id_bytes, selected_channel_id_str) = if let Some(channel_id_str) = &req.channel_id {
                                            // Parse provided channel ID
                                            match hex::decode(channel_id_str) {
                                                Ok(channel_id_bytes) if channel_id_bytes.len() == 32 => {
                                                    let channel_id: [u8; 32] = channel_id_bytes.try_into().unwrap();
                                                    (channel_id, channel_id_str.clone())
                                                }
                                                _ => {
                                                    return warp::reply::json(&ApiResponse::<DepositResponse> {
                                                        success: false,
                                                        data: None,
                                                        error: Some("Invalid channel ID format".to_string()),
                                                    });
                                                }
                                            }
                                        } else {
                                            // Auto-select an available channel with the partner
                                            let channels = node_for_deposit.list_channels();
                                            let partner_channels: Vec<_> = channels.into_iter()
                                                .filter(|ch| ch.counterparty_node_id == partner_pubkey && ch.is_channel_ready && ch.is_usable)
                                                .collect();

                                            if partner_channels.is_empty() {
                                                return warp::reply::json(&ApiResponse::<DepositResponse> {
                                                    success: false,
                                                    data: None,
                                                    error: Some("No available channels found with specified partner".to_string()),
                                                });
                                            }

                                            // Select the first available channel (could add more sophisticated selection logic)
                                            let selected_channel = &partner_channels[0];
                                            let channel_id_str = selected_channel.channel_id.to_string();
                                            let channel_id_bytes = selected_channel.channel_id.0;
                                            (channel_id_bytes, channel_id_str)
                                        };

                                        let channel_id: [u8; 32] = channel_id_bytes;
                                                let initial_amount = req.amount_sat.unwrap_or(0);

                                                // Call actual Bitcoin Deposits handler to create deposit
                                                match bd_handler.add_deposit(partner_pubkey, deposit_pubkey, None) {
                                                    Ok(()) => {
                                                        log::info!("✅ Successfully created Bitcoin deposit for partner {} with pubkey {}",
                                                                  partner_pubkey, deposit_pubkey);
                                                    }
                                                    Err(e) => {
                                                        log::error!("❌ Failed to create Bitcoin deposit: {}", e);
                                                        return warp::reply::json(&ApiResponse::<DepositResponse> {
                                                            success: false,
                                                            data: None,
                                                            error: Some(format!("Failed to create deposit: {}", e)),
                                                        });
                                                    }
                                                }

                                                let response = DepositResponse {
                                                    deposit_pubkey: req.deposit_pubkey,
                                                    partner_node_id: req.partner_node_id,
                                                    channel_id: selected_channel_id_str,
                                                    deposit_address: Some({
                                                        // For now, use a deterministic test address based on partner pubkey
                                                        let partner_bytes = partner_pubkey.serialize();
                                                        let addr_suffix = hex::encode(&partner_bytes[..4]);
                                                        format!("tb1qtest{}", addr_suffix)
                                                    }),
                                                balance_sat: initial_amount,
                                                    created_at: chrono::Utc::now().to_rfc3339(),
                                                    created: true,
                                                };

                                                warp::reply::json(&ApiResponse {
                                                    success: true,
                                                    data: Some(response),
                                                    error: None,
                                                })
                                    },
                                    Err(e) => {
                                        warp::reply::json(&ApiResponse::<serde_json::Value> {
                                            success: false,
                                            data: None,
                                            error: Some(format!("Invalid deposit pubkey: {}", e)),
                                        })
                                    }
                                }
                            },
                            Err(e) => {
                                warp::reply::json(&ApiResponse::<serde_json::Value> {
                                    success: false,
                                    data: None,
                                    error: Some(format!("Invalid partner node ID: {}", e)),
                                })
                            }
                        }
                    } else {
                        warp::reply::json(&ApiResponse::<serde_json::Value> {
                            success: false,
                            data: None,
                            error: Some("Bitcoin Deposits not enabled".to_string()),
                        })
                    }
                }

                #[cfg(not(feature = "bitcoin-deposits"))]
                {
                    warp::reply::json(&ApiResponse::<serde_json::Value> {
                        success: false,
                        data: None,
                        error: Some("Bitcoin Deposits feature not compiled".to_string()),
                    })
                }
            });

        let node_for_deposits = node.clone();
        let get_deposits = warp::path!("bitcoin-deposits" / "deposits" / String)
            .and(warp::get())
            .map(move |partner_node_id: String| {
                #[cfg(feature = "bitcoin-deposits")]
                {
                    if let Some(bd_handler) = node_for_deposits.deposits() {
                        match partner_node_id.parse::<ldk_node::bitcoin::secp256k1::PublicKey>() {
                            Ok(partner_pubkey) => {
                                if let Some(deposits) = bd_handler.get_deposits_for_partner(partner_pubkey) {
                                    let deposit_list: Vec<serde_json::Value> = deposits.iter()
                                        .map(|(depositor_pubkey, balance, locked_balance)| {
                                            serde_json::json!({
                                                "depositor_pubkey": depositor_pubkey.to_string(),
                                                "balance": balance,
                                                "locked_balance": locked_balance,
                                            })
                                        })
                                        .collect();

                                    return warp::reply::json(&ApiResponse {
                                        success: true,
                                        data: Some(serde_json::json!({
                                            "deposits": deposit_list,
                                            "total_deposits": deposits.len(),
                                        })),
                                        error: None,
                                    });
                                } else {
                                    return warp::reply::json(&ApiResponse::<serde_json::Value> {
                                        success: false,
                                        data: None,
                                        error: Some("No ledger found for this partner".to_string()),
                                    });
                                }
                            }
                            Err(_) => {
                                return warp::reply::json(&ApiResponse::<serde_json::Value> {
                                    success: false,
                                    data: None,
                                    error: Some("Invalid partner node ID".to_string()),
                                });
                            }
                        }
                    }
                    warp::reply::json(&ApiResponse::<serde_json::Value> {
                        success: false,
                        data: None,
                        error: Some("Bitcoin Deposits not available".to_string()),
                    })
                }
                #[cfg(not(feature = "bitcoin-deposits"))]
                {
                    warp::reply::json(&ApiResponse::<serde_json::Value> {
                        success: false,
                        data: None,
                        error: Some("Bitcoin Deposits feature not compiled".to_string()),
                    })
                }
            });

        // Endpoint to get all ledger updates for all partners
        let node_for_all_updates = node.clone();
        let get_all_ledger_updates = warp::path!("bitcoin-deposits" / "ledger-updates")
            .and(warp::get())
            .map(move || {
                #[cfg(feature = "bitcoin-deposits")]
                if let Some(bd_handler) = node_for_all_updates.deposits() {
                    let all_updates = bd_handler.get_all_ledger_updates();
                    let audit_updates = bd_handler.get_all_audit_ledger_updates();
                    let signed_audit_updates = bd_handler.get_all_signed_audit_updates();
                    // Partner ledger updates from the unified Ledger structure
                    let partner_ledger_updates = bd_handler.get_all_partner_ledger_updates();

                    let mut partners_json = Vec::new();

                    // Track which ledgers are already covered by channel_ledgers to avoid duplicates
                    let mut channel_ledger_keys: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();

                    // Add direct ledgers
                    for ((operator_id, partner_id), updates) in all_updates {
                        // Track this ledger key
                        channel_ledger_keys.insert((operator_id.to_string(), partner_id.to_string()));
                        // Get sync state for this ledger
                        let counterparty = if operator_id == node_for_all_updates.node_id() {
                            partner_id
                        } else {
                            operator_id
                        };
                        let (ack_hash, commit_hash) = bd_handler.get_ledger_sync_state(counterparty)
                            .unwrap_or(([0u8; 32], [0u8; 32]));

                        let total_updates = updates.len();

                        // Find the sequence number at which the chain is ACK'd and committed
                        // All updates up to and including these sequence numbers are ACK'd/committed
                        // (because the hash at each update includes all previous updates in the chain)
                        let ack_seq = updates.iter()
                            .find(|u| u.current_state_hash == ack_hash)
                            .map(|u| u.sequence_number);
                        let commit_seq = updates.iter()
                            .find(|u| u.current_state_hash == commit_hash)
                            .map(|u| u.sequence_number);

                        let updates_json: Vec<serde_json::Value> = updates.iter()
                            .enumerate()
                            .filter_map(|(idx, update)| {
                                // Deserialize the message from bytes
                                use deposits_ldk::handler::messages::DepositsMessage;
                                use deposits_ldk::handler::ledger_ext::SignedLedgerUpdateExt;
                                let message = match update.get_message() {
                                    Ok(msg) => msg,
                                    Err(e) => {
                                        // Log first 20 bytes in hex for debugging
                                        let hex_preview: String = update.message.iter()
                                            .take(20)
                                            .map(|b| format!("{:02x}", b))
                                            .collect::<Vec<_>>()
                                            .join(" ");
                                        eprintln!("⚠️ DIRECT LEDGER: Failed to deserialize update {}/{} for {}→{}: {:?}, message bytes len={}, first bytes: {}",
                                            idx+1, total_updates, operator_id, partner_id, e, update.message.len(), hex_preview);
                                        return None;
                                    }
                                };
                                // Use operation name for LedgerUpdate, else variant name
                                let update_type = message.operation_name().unwrap_or_else(|| message.variant_name());

                                // Extract relevant fields based on message type
                                let (deposit_pubkey, amount, collateral_partner) = match &message {
                                    DepositsMessage::DepositOpen { pubkey, .. } =>
                                        (Some(*pubkey), None, None),
                                    DepositsMessage::DepositClose { pubkey, .. } =>
                                        (Some(*pubkey), None, None),
                                    DepositsMessage::ReceivingCreditPayment { deposit_pubkey, amount, .. } =>
                                        (Some(*deposit_pubkey), Some(*amount), None),
                                    DepositsMessage::SendingLockPayment { pubkey, amount, .. } =>
                                        (Some(*pubkey), Some(*amount), None),
                                    DepositsMessage::SendingFailPayment { pubkey, amount, .. } =>
                                        (Some(*pubkey), Some(*amount), None),
                                    DepositsMessage::SendingFulfillPayment { pubkey, amount, .. } =>
                                        (Some(*pubkey), Some(*amount), None),
                                    DepositsMessage::ReservesAddOutput { initial_amount, .. } =>
                                        (None, Some(*initial_amount), None),
                                    DepositsMessage::ReservesIncrease { new_amount, .. } =>
                                        (None, Some(*new_amount), None),
                                    DepositsMessage::ReservesDecrease { new_amount, .. } =>
                                        (None, Some(*new_amount), None),
                                    DepositsMessage::CollateralAddPartner { collateral_partner, .. } =>
                                        (None, None, Some(*collateral_partner)),
                                    DepositsMessage::CollateralAttestation { amount, collateral_partner, .. } =>
                                        (None, Some(*amount), Some(*collateral_partner)),
                                    DepositsMessage::CollateralIncrease { new_amount, partner_id, .. } =>
                                        (None, Some(*new_amount), Some(*partner_id)),
                                    DepositsMessage::CollateralDecrease { new_amount, partner_id, .. } =>
                                        (None, Some(*new_amount), Some(*partner_id)),
                                    DepositsMessage::CollateralStatus { amount, collateral_operator, .. } =>
                                        (None, Some(*amount), Some(*collateral_operator)),
                                    // V2 LedgerUpdate - extract from inner operation
                                    DepositsMessage::LedgerUpdate(msg) => {
                                        use deposits_core::messages::LedgerOperation;
                                        match &msg.operation {
                                            LedgerOperation::DepositOpen { pubkey, .. } => (Some(*pubkey), None, None),
                                            LedgerOperation::DepositClose { pubkey } => (Some(*pubkey), None, None),
                                            LedgerOperation::PaymentCredit { deposit_pubkey, amount, .. } => (Some(*deposit_pubkey), Some(*amount), None),
                                            LedgerOperation::PaymentLock { pubkey, amount, .. } => (Some(*pubkey), Some(*amount), None),
                                            LedgerOperation::PaymentFail { pubkey, amount, .. } => (Some(*pubkey), Some(*amount), None),
                                            LedgerOperation::PaymentFulfill { pubkey, amount, .. } => (Some(*pubkey), Some(*amount), None),
                                            LedgerOperation::TransferLock { pubkey, amount, .. } => (Some(*pubkey), Some(*amount), None),
                                            LedgerOperation::TransferFail { pubkey, .. } => (Some(*pubkey), None, None),
                                            LedgerOperation::TransferFulfill { pubkey, amount, .. } => (Some(*pubkey), Some(*amount), None),
                                            LedgerOperation::ReservesAdd { amount, .. } => (None, Some(*amount), None),
                                            LedgerOperation::ReservesIncrease { new_amount } => (None, Some(*new_amount), None),
                                            LedgerOperation::ReservesDecrease { new_amount } => (None, Some(*new_amount), None),
                                            LedgerOperation::CollateralIncrease { new_amount, .. } => (None, Some(*new_amount), None),
                                            LedgerOperation::CollateralDecrease { new_amount, .. } => (None, Some(*new_amount), None),
                                            LedgerOperation::CollateralAddPartner { collateral_partner, .. } => (None, None, Some(*collateral_partner)),
                                            LedgerOperation::CollateralRemovePartner { collateral_partner, .. } => (None, None, Some(*collateral_partner)),
                                            LedgerOperation::CollateralAttestation { amount, .. } => (None, Some(*amount), None),
                                            LedgerOperation::FeeCollect { pubkey, amount, .. } => (Some(*pubkey), Some(*amount), None),
                                            _ => (None, None, None),
                                        }
                                    }
                                    DepositsMessage::SignedUpdate(msg) => {
                                        use deposits_core::messages::LedgerOperation;
                                        match &msg.operation {
                                            LedgerOperation::DepositOpen { pubkey, .. } => (Some(*pubkey), None, None),
                                            LedgerOperation::DepositClose { pubkey } => (Some(*pubkey), None, None),
                                            LedgerOperation::PaymentCredit { deposit_pubkey, amount, .. } => (Some(*deposit_pubkey), Some(*amount), None),
                                            LedgerOperation::PaymentLock { pubkey, amount, .. } => (Some(*pubkey), Some(*amount), None),
                                            LedgerOperation::PaymentFail { pubkey, amount, .. } => (Some(*pubkey), Some(*amount), None),
                                            LedgerOperation::PaymentFulfill { pubkey, amount, .. } => (Some(*pubkey), Some(*amount), None),
                                            LedgerOperation::TransferLock { pubkey, amount, .. } => (Some(*pubkey), Some(*amount), None),
                                            LedgerOperation::TransferFail { pubkey, .. } => (Some(*pubkey), None, None),
                                            LedgerOperation::TransferFulfill { pubkey, amount, .. } => (Some(*pubkey), Some(*amount), None),
                                            LedgerOperation::ReservesAdd { amount, .. } => (None, Some(*amount), None),
                                            LedgerOperation::ReservesIncrease { new_amount } => (None, Some(*new_amount), None),
                                            LedgerOperation::ReservesDecrease { new_amount } => (None, Some(*new_amount), None),
                                            LedgerOperation::CollateralIncrease { new_amount, .. } => (None, Some(*new_amount), None),
                                            LedgerOperation::CollateralDecrease { new_amount, .. } => (None, Some(*new_amount), None),
                                            LedgerOperation::CollateralAddPartner { collateral_partner, .. } => (None, None, Some(*collateral_partner)),
                                            LedgerOperation::CollateralRemovePartner { collateral_partner, .. } => (None, None, Some(*collateral_partner)),
                                            LedgerOperation::CollateralAttestation { amount, .. } => (None, Some(*amount), None),
                                            LedgerOperation::FeeCollect { pubkey, amount, .. } => (Some(*pubkey), Some(*amount), None),
                                            _ => (None, None, None),
                                        }
                                    }
                                    _ => (None, None, None),
                                };

                                // Check if this update is acknowledged or committed
                                // An update is ACK'd if its sequence <= the sequence of the ACK'd hash
                                // An update is committed if its sequence <= the sequence of the committed hash
                                let is_acknowledged = ack_seq.map(|s| update.sequence_number <= s).unwrap_or(false);
                                let is_committed = commit_seq.map(|s| update.sequence_number <= s).unwrap_or(false);

                                Some(serde_json::json!({
                                    "update_type": update_type,
                                    "deposit_pubkey": deposit_pubkey.map(|pk| pk.to_string()),
                                    "amount": amount,
                                    "collateral_partner": collateral_partner.map(|pk| pk.to_string()),
                                    "sequence_number": update.sequence_number,
                                    "previous_hash": hex::encode(&update.previous_state_hash),
                                    "consensus_hash": hex::encode(&update.current_state_hash),
                                    "acknowledged": is_acknowledged,
                                    "committed": is_committed,
                                }))
                            })
                            .collect();

                        // Get ledger address for this ledger
                        let counterparty = if operator_id == node_for_all_updates.node_id() {
                            partner_id
                        } else {
                            operator_id
                        };
                        let ledger_address = bd_handler.get_ledger_address(counterparty)
                            .map(|addr| addr.to_string())
                            .unwrap_or_else(|_| "unknown".to_string());

                        // Set role based on whether this node is the operator or partner
                        let role = if operator_id == node_for_all_updates.node_id() {
                            "direct" // This node is the operator
                        } else {
                            "partner" // This node is the partner (has a copy of operator's ledger)
                        };

                        partners_json.push(serde_json::json!({
                            "role": role,
                            "operator_node_id": operator_id.to_string(),
                            "partner_node_id": partner_id.to_string(),
                            "counterparty_node_id": counterparty.to_string(),
                            "ledger_address": ledger_address,
                            "update_count": updates.len(),
                            "partner_deepest_ack_hash": hex::encode(&ack_hash),
                            "channel_deepest_commitment_hash": hex::encode(&commit_hash),
                            "updates": updates_json,
                        }));
                    }

                    // Add audit ledgers (old system)
                    for ((operator_id, partner_id), updates) in audit_updates {
                        let updates_json: Vec<serde_json::Value> = updates.iter()
                            .filter_map(|update| {
                                // Deserialize the message from bytes
                                use deposits_ldk::handler::messages::DepositsMessage;
                                use deposits_ldk::handler::ledger_ext::SignedLedgerUpdateExt;
                                let message = update.get_message().ok()?;
                                // Use operation name for LedgerUpdate, else variant name
                                let update_type = message.operation_name().unwrap_or_else(|| message.variant_name());

                                // Extract relevant fields based on message type
                                let (deposit_pubkey, amount, collateral_partner) = match &message {
                                    DepositsMessage::DepositOpen { pubkey, .. } =>
                                        (Some(*pubkey), None, None),
                                    DepositsMessage::DepositClose { pubkey, .. } =>
                                        (Some(*pubkey), None, None),
                                    DepositsMessage::ReceivingCreditPayment { deposit_pubkey, amount, .. } =>
                                        (Some(*deposit_pubkey), Some(*amount), None),
                                    DepositsMessage::SendingLockPayment { pubkey, amount, .. } =>
                                        (Some(*pubkey), Some(*amount), None),
                                    DepositsMessage::SendingFailPayment { pubkey, amount, .. } =>
                                        (Some(*pubkey), Some(*amount), None),
                                    DepositsMessage::SendingFulfillPayment { pubkey, amount, .. } =>
                                        (Some(*pubkey), Some(*amount), None),
                                    DepositsMessage::ReservesAddOutput { initial_amount, .. } =>
                                        (None, Some(*initial_amount), None),
                                    DepositsMessage::ReservesIncrease { new_amount, .. } =>
                                        (None, Some(*new_amount), None),
                                    DepositsMessage::ReservesDecrease { new_amount, .. } =>
                                        (None, Some(*new_amount), None),
                                    DepositsMessage::CollateralAddPartner { collateral_partner, .. } =>
                                        (None, None, Some(*collateral_partner)),
                                    DepositsMessage::CollateralAttestation { amount, collateral_partner, .. } =>
                                        (None, Some(*amount), Some(*collateral_partner)),
                                    DepositsMessage::CollateralIncrease { new_amount, partner_id, .. } =>
                                        (None, Some(*new_amount), Some(*partner_id)),
                                    DepositsMessage::CollateralDecrease { new_amount, partner_id, .. } =>
                                        (None, Some(*new_amount), Some(*partner_id)),
                                    DepositsMessage::CollateralStatus { amount, collateral_operator, .. } =>
                                        (None, Some(*amount), Some(*collateral_operator)),
                                    // V2 LedgerUpdate - extract from inner operation
                                    DepositsMessage::LedgerUpdate(msg) => {
                                        use deposits_core::messages::LedgerOperation;
                                        match &msg.operation {
                                            LedgerOperation::DepositOpen { pubkey, .. } => (Some(*pubkey), None, None),
                                            LedgerOperation::DepositClose { pubkey } => (Some(*pubkey), None, None),
                                            LedgerOperation::PaymentCredit { deposit_pubkey, amount, .. } => (Some(*deposit_pubkey), Some(*amount), None),
                                            LedgerOperation::PaymentLock { pubkey, amount, .. } => (Some(*pubkey), Some(*amount), None),
                                            LedgerOperation::PaymentFail { pubkey, amount, .. } => (Some(*pubkey), Some(*amount), None),
                                            LedgerOperation::PaymentFulfill { pubkey, amount, .. } => (Some(*pubkey), Some(*amount), None),
                                            LedgerOperation::TransferLock { pubkey, amount, .. } => (Some(*pubkey), Some(*amount), None),
                                            LedgerOperation::TransferFail { pubkey, .. } => (Some(*pubkey), None, None),
                                            LedgerOperation::TransferFulfill { pubkey, amount, .. } => (Some(*pubkey), Some(*amount), None),
                                            LedgerOperation::ReservesAdd { amount, .. } => (None, Some(*amount), None),
                                            LedgerOperation::ReservesIncrease { new_amount } => (None, Some(*new_amount), None),
                                            LedgerOperation::ReservesDecrease { new_amount } => (None, Some(*new_amount), None),
                                            LedgerOperation::CollateralIncrease { new_amount, .. } => (None, Some(*new_amount), None),
                                            LedgerOperation::CollateralDecrease { new_amount, .. } => (None, Some(*new_amount), None),
                                            LedgerOperation::CollateralAddPartner { collateral_partner, .. } => (None, None, Some(*collateral_partner)),
                                            LedgerOperation::CollateralRemovePartner { collateral_partner, .. } => (None, None, Some(*collateral_partner)),
                                            LedgerOperation::CollateralAttestation { amount, .. } => (None, Some(*amount), None),
                                            LedgerOperation::FeeCollect { pubkey, amount, .. } => (Some(*pubkey), Some(*amount), None),
                                            _ => (None, None, None),
                                        }
                                    }
                                    DepositsMessage::SignedUpdate(msg) => {
                                        use deposits_core::messages::LedgerOperation;
                                        match &msg.operation {
                                            LedgerOperation::DepositOpen { pubkey, .. } => (Some(*pubkey), None, None),
                                            LedgerOperation::DepositClose { pubkey } => (Some(*pubkey), None, None),
                                            LedgerOperation::PaymentCredit { deposit_pubkey, amount, .. } => (Some(*deposit_pubkey), Some(*amount), None),
                                            LedgerOperation::PaymentLock { pubkey, amount, .. } => (Some(*pubkey), Some(*amount), None),
                                            LedgerOperation::PaymentFail { pubkey, amount, .. } => (Some(*pubkey), Some(*amount), None),
                                            LedgerOperation::PaymentFulfill { pubkey, amount, .. } => (Some(*pubkey), Some(*amount), None),
                                            LedgerOperation::TransferLock { pubkey, amount, .. } => (Some(*pubkey), Some(*amount), None),
                                            LedgerOperation::TransferFail { pubkey, .. } => (Some(*pubkey), None, None),
                                            LedgerOperation::TransferFulfill { pubkey, amount, .. } => (Some(*pubkey), Some(*amount), None),
                                            LedgerOperation::ReservesAdd { amount, .. } => (None, Some(*amount), None),
                                            LedgerOperation::ReservesIncrease { new_amount } => (None, Some(*new_amount), None),
                                            LedgerOperation::ReservesDecrease { new_amount } => (None, Some(*new_amount), None),
                                            LedgerOperation::CollateralIncrease { new_amount, .. } => (None, Some(*new_amount), None),
                                            LedgerOperation::CollateralDecrease { new_amount, .. } => (None, Some(*new_amount), None),
                                            LedgerOperation::CollateralAddPartner { collateral_partner, .. } => (None, None, Some(*collateral_partner)),
                                            LedgerOperation::CollateralRemovePartner { collateral_partner, .. } => (None, None, Some(*collateral_partner)),
                                            LedgerOperation::CollateralAttestation { amount, .. } => (None, Some(*amount), None),
                                            LedgerOperation::FeeCollect { pubkey, amount, .. } => (Some(*pubkey), Some(*amount), None),
                                            _ => (None, None, None),
                                        }
                                    }
                                    _ => (None, None, None),
                                };

                                Some(serde_json::json!({
                                    "update_type": update_type,
                                    "deposit_pubkey": deposit_pubkey.map(|pk| pk.to_string()),
                                    "amount": amount,
                                    "collateral_partner": collateral_partner.map(|pk| pk.to_string()),
                                    "sequence_number": update.sequence_number,
                                    "previous_hash": hex::encode(&update.previous_state_hash),
                                    "consensus_hash": hex::encode(&update.current_state_hash),
                                }))
                            })
                            .collect();

                        partners_json.push(serde_json::json!({
                            "role": "audit",
                            "operator_node_id": operator_id.to_string(),
                            "partner_node_id": partner_id.to_string(),
                            "update_count": updates.len(),
                            "updates": updates_json,
                        }));
                    }

                    // Add partner ledgers from unified Ledger structure (for when we are the partner)
                    for ((operator_id, partner_id), signed_updates) in partner_ledger_updates {
                        // Only include if we are the partner (not operator, not third-party)
                        if partner_id != node_for_all_updates.node_id() {
                            continue;
                        }

                        // Skip if this ledger is already covered by channel_ledgers (avoid duplicates)
                        let key = (operator_id.to_string(), partner_id.to_string());
                        if channel_ledger_keys.contains(&key) {
                            continue;
                        }

                        let updates_json: Vec<serde_json::Value> = signed_updates.iter()
                            .map(|signed_update| {
                                // Map message type code to variant name
                                use deposits_ldk::handler::messages::type_id_to_variant_name;
                                let update_type = type_id_to_variant_name(signed_update.message_type)
                                    .map(String::from)
                                    .unwrap_or_else(|| format!("Unknown({:#06x})", signed_update.message_type));

                                serde_json::json!({
                                    "update_type": update_type,
                                    "timestamp": signed_update.timestamp,
                                    "sequence_number": signed_update.sequence_number,
                                    "previous_hash": hex::encode(&signed_update.previous_state_hash),
                                    "consensus_hash": hex::encode(&signed_update.current_state_hash),
                                    "signed": true,
                                    "message_type": format!("{:#06x}", signed_update.message_type),
                                })
                            })
                            .collect();

                        partners_json.push(serde_json::json!({
                            "role": "partner",
                            "operator_node_id": operator_id.to_string(),
                            "partner_node_id": partner_id.to_string(),
                            "update_count": updates_json.len(),  // Count excludes placeholders
                            "updates": updates_json,
                        }));
                    }

                    // Add third-party audit ledgers (signed_update_logs for auditors only)
                    for ((operator_id, partner_id), signed_updates) in signed_audit_updates {
                        // Skip if we're the operator OR if we're the partner (those are handled above)
                        if operator_id == node_for_all_updates.node_id() {
                            continue;
                        }
                        if partner_id == node_for_all_updates.node_id() {
                            continue;  // Partner views are now from partner_ledger_updates
                        }

                        // Third-party auditor view
                        let updates_json: Vec<serde_json::Value> = signed_updates.iter()
                            .map(|signed_update| {
                                // Map message type code to variant name
                                use deposits_ldk::handler::messages::type_id_to_variant_name;
                                let update_type = type_id_to_variant_name(signed_update.message_type)
                                    .map(String::from)
                                    .unwrap_or_else(|| format!("Unknown({:#06x})", signed_update.message_type));

                                serde_json::json!({
                                    "update_type": update_type,
                                    "timestamp": signed_update.timestamp,
                                    "sequence_number": signed_update.sequence_number,
                                    "previous_hash": hex::encode(&signed_update.previous_state_hash),
                                    "consensus_hash": hex::encode(&signed_update.current_state_hash),
                                    "signed": true,
                                    "message_type": format!("{:#06x}", signed_update.message_type),
                                })
                            })
                            .collect();

                        partners_json.push(serde_json::json!({
                            "role": "audit",
                            "operator_node_id": operator_id.to_string(),
                            "partner_node_id": partner_id.to_string(),
                            "update_count": signed_updates.len(),
                            "updates": updates_json,
                        }));
                    }

                    return warp::reply::json(&ApiResponse {
                        success: true,
                        data: Some(serde_json::json!({
                            "ledgers": partners_json,
                        })),
                        error: None,
                    });
                }

                warp::reply::json(&ApiResponse::<serde_json::Value> {
                    success: false,
                    data: None,
                    error: Some("Bitcoin Deposits not enabled".to_string()),
                })
            });

        let node_for_updates = node.clone();
        let get_ledger_updates = warp::path!("bitcoin-deposits" / "ledger-updates" / String)
            .and(warp::get())
            .map(move |partner_node_id: String| {
                #[cfg(feature = "bitcoin-deposits")]
                {
                    if let Some(bd_handler) = node_for_updates.deposits() {
                        match partner_node_id.parse::<ldk_node::bitcoin::secp256k1::PublicKey>() {
                            Ok(partner_pubkey) => {
                                match bd_handler.get_ledger_updates(partner_pubkey) {
                                    Ok(updates) => {
                                        let updates_json: Vec<serde_json::Value> = updates.iter()
                                            .enumerate()
                                            .filter_map(|(idx, update)| {
                                                // Deserialize the message from bytes
                                                use deposits_ldk::handler::messages::DepositsMessage;
                                                use deposits_ldk::handler::ledger_ext::SignedLedgerUpdateExt;
                                                let message = match update.get_message() {
                                                    Ok(msg) => msg,
                                                    Err(e) => {
                                                        eprintln!("⚠️ Failed to deserialize update {}: {:?}, message bytes len={}, first bytes: {:02x?}",
                                                            idx, e, update.message.len(), &update.message[..std::cmp::min(20, update.message.len())]);
                                                        return None;
                                                    }
                                                };
                                                // Use operation name for LedgerUpdate, else variant name
                                                let update_type = message.operation_name().unwrap_or_else(|| message.variant_name());

                                                // Extract relevant fields based on message type
                                                let (deposit_pubkey, amount, collateral_partner) = match &message {
                                                    DepositsMessage::DepositOpen { pubkey, .. } =>
                                                        (Some(*pubkey), None, None),
                                                    DepositsMessage::DepositClose { pubkey, .. } =>
                                                        (Some(*pubkey), None, None),
                                                    DepositsMessage::ReceivingCreditPayment { deposit_pubkey, amount, .. } =>
                                                        (Some(*deposit_pubkey), Some(*amount), None),
                                                    DepositsMessage::SendingLockPayment { pubkey, amount, .. } =>
                                                        (Some(*pubkey), Some(*amount), None),
                                                    DepositsMessage::SendingFailPayment { pubkey, amount, .. } =>
                                                        (Some(*pubkey), Some(*amount), None),
                                                    DepositsMessage::SendingFulfillPayment { pubkey, amount, .. } =>
                                                        (Some(*pubkey), Some(*amount), None),
                                                    DepositsMessage::ReservesAddOutput { initial_amount, .. } =>
                                                        (None, Some(*initial_amount), None),
                                                    DepositsMessage::ReservesIncrease { new_amount, .. } =>
                                                        (None, Some(*new_amount), None),
                                                    DepositsMessage::ReservesDecrease { new_amount, .. } =>
                                                        (None, Some(*new_amount), None),
                                                    DepositsMessage::CollateralAddPartner { collateral_partner, .. } =>
                                                        (None, None, Some(*collateral_partner)),
                                                    DepositsMessage::CollateralAttestation { amount, collateral_partner, .. } =>
                                                        (None, Some(*amount), Some(*collateral_partner)),
                                                    DepositsMessage::CollateralIncrease { new_amount, partner_id, .. } =>
                                                        (None, Some(*new_amount), Some(*partner_id)),
                                                    DepositsMessage::CollateralDecrease { new_amount, partner_id, .. } =>
                                                        (None, Some(*new_amount), Some(*partner_id)),
                                                    DepositsMessage::CollateralStatus { amount, collateral_operator, .. } =>
                                                        (None, Some(*amount), Some(*collateral_operator)),
                                                    // V2 LedgerUpdate - extract from inner operation
                                                    DepositsMessage::LedgerUpdate(msg) => {
                                                        use deposits_core::messages::LedgerOperation;
                                                        match &msg.operation {
                                                            LedgerOperation::DepositOpen { pubkey, .. } => (Some(*pubkey), None, None),
                                                            LedgerOperation::DepositClose { pubkey } => (Some(*pubkey), None, None),
                                                            LedgerOperation::PaymentCredit { deposit_pubkey, amount, .. } => (Some(*deposit_pubkey), Some(*amount), None),
                                                            LedgerOperation::PaymentLock { pubkey, amount, .. } => (Some(*pubkey), Some(*amount), None),
                                                            LedgerOperation::PaymentFail { pubkey, amount, .. } => (Some(*pubkey), Some(*amount), None),
                                                            LedgerOperation::PaymentFulfill { pubkey, amount, .. } => (Some(*pubkey), Some(*amount), None),
                                                            LedgerOperation::TransferLock { pubkey, amount, .. } => (Some(*pubkey), Some(*amount), None),
                                                            LedgerOperation::TransferFail { pubkey, .. } => (Some(*pubkey), None, None),
                                                            LedgerOperation::TransferFulfill { pubkey, amount, .. } => (Some(*pubkey), Some(*amount), None),
                                                            LedgerOperation::ReservesAdd { amount, .. } => (None, Some(*amount), None),
                                                            LedgerOperation::ReservesIncrease { new_amount } => (None, Some(*new_amount), None),
                                                            LedgerOperation::ReservesDecrease { new_amount } => (None, Some(*new_amount), None),
                                                            LedgerOperation::CollateralIncrease { new_amount, .. } => (None, Some(*new_amount), None),
                                                            LedgerOperation::CollateralDecrease { new_amount, .. } => (None, Some(*new_amount), None),
                                                            LedgerOperation::CollateralAddPartner { collateral_partner, .. } => (None, None, Some(*collateral_partner)),
                                                            LedgerOperation::CollateralRemovePartner { collateral_partner, .. } => (None, None, Some(*collateral_partner)),
                                                            LedgerOperation::CollateralAttestation { amount, .. } => (None, Some(*amount), None),
                                                            LedgerOperation::FeeCollect { pubkey, amount, .. } => (Some(*pubkey), Some(*amount), None),
                                                            _ => (None, None, None),
                                                        }
                                                    }
                                                    DepositsMessage::SignedUpdate(msg) => {
                                                        use deposits_core::messages::LedgerOperation;
                                                        match &msg.operation {
                                                            LedgerOperation::DepositOpen { pubkey, .. } => (Some(*pubkey), None, None),
                                                            LedgerOperation::DepositClose { pubkey } => (Some(*pubkey), None, None),
                                                            LedgerOperation::PaymentCredit { deposit_pubkey, amount, .. } => (Some(*deposit_pubkey), Some(*amount), None),
                                                            LedgerOperation::PaymentLock { pubkey, amount, .. } => (Some(*pubkey), Some(*amount), None),
                                                            LedgerOperation::PaymentFail { pubkey, amount, .. } => (Some(*pubkey), Some(*amount), None),
                                                            LedgerOperation::PaymentFulfill { pubkey, amount, .. } => (Some(*pubkey), Some(*amount), None),
                                                            LedgerOperation::TransferLock { pubkey, amount, .. } => (Some(*pubkey), Some(*amount), None),
                                                            LedgerOperation::TransferFail { pubkey, .. } => (Some(*pubkey), None, None),
                                                            LedgerOperation::TransferFulfill { pubkey, amount, .. } => (Some(*pubkey), Some(*amount), None),
                                                            LedgerOperation::ReservesAdd { amount, .. } => (None, Some(*amount), None),
                                                            LedgerOperation::ReservesIncrease { new_amount } => (None, Some(*new_amount), None),
                                                            LedgerOperation::ReservesDecrease { new_amount } => (None, Some(*new_amount), None),
                                                            LedgerOperation::CollateralIncrease { new_amount, .. } => (None, Some(*new_amount), None),
                                                            LedgerOperation::CollateralDecrease { new_amount, .. } => (None, Some(*new_amount), None),
                                                            LedgerOperation::CollateralAddPartner { collateral_partner, .. } => (None, None, Some(*collateral_partner)),
                                                            LedgerOperation::CollateralRemovePartner { collateral_partner, .. } => (None, None, Some(*collateral_partner)),
                                                            LedgerOperation::CollateralAttestation { amount, .. } => (None, Some(*amount), None),
                                                            LedgerOperation::FeeCollect { pubkey, amount, .. } => (Some(*pubkey), Some(*amount), None),
                                                            _ => (None, None, None),
                                                        }
                                                    }
                                                    _ => (None, None, None),
                                                };

                                                Some(serde_json::json!({
                                                    "update_type": update_type,
                                                    "deposit_pubkey": deposit_pubkey.map(|pk| pk.to_string()),
                                                    "amount": amount,
                                                    "collateral_partner": collateral_partner.map(|pk| pk.to_string()),
                                                    "sequence_number": update.sequence_number,
                                                    "previous_hash": hex::encode(&update.previous_state_hash),
                                                    "consensus_hash": hex::encode(&update.current_state_hash),
                                                }))
                                            })
                                            .collect();

                                        return warp::reply::json(&ApiResponse {
                                            success: true,
                                            data: Some(serde_json::json!({
                                                "updates": updates_json,
                                            })),
                                            error: None,
                                        });
                                    }
                                    Err(e) => {
                                        return warp::reply::json(&ApiResponse::<serde_json::Value> {
                                            success: false,
                                            data: None,
                                            error: Some(format!("Failed to get ledger updates: {}", e)),
                                        });
                                    }
                                }
                            }
                            Err(_) => {
                                return warp::reply::json(&ApiResponse::<serde_json::Value> {
                                    success: false,
                                    data: None,
                                    error: Some("Invalid partner node ID".to_string()),
                                });
                            }
                        }
                    }
                    warp::reply::json(&ApiResponse::<serde_json::Value> {
                        success: false,
                        data: None,
                        error: Some("Bitcoin Deposits not available".to_string()),
                    })
                }
                #[cfg(not(feature = "bitcoin-deposits"))]
                {
                    warp::reply::json(&ApiResponse::<serde_json::Value> {
                        success: false,
                        data: None,
                        error: Some("Bitcoin Deposits feature not compiled".to_string()),
                    })
                }
            });

        // Endpoint to remove an empty deposit
        let node_for_remove = node.clone();
        let remove_deposit = warp::path!("bitcoin-deposits" / "deposits" / String / String)
            .and(warp::delete())
            .map(move |partner_node_id: String, deposit_pubkey: String| {
                #[cfg(feature = "bitcoin-deposits")]
                {
                    if let Some(bd_handler) = node_for_remove.deposits() {
                        match (partner_node_id.parse::<ldk_node::bitcoin::secp256k1::PublicKey>(), deposit_pubkey.parse::<ldk_node::bitcoin::secp256k1::PublicKey>()) {
                            (Ok(partner_pubkey), Ok(deposit_pk)) => {
                                match bd_handler.remove_deposit(partner_pubkey, deposit_pk) {
                                    Ok(()) => {
                                        return warp::reply::json(&ApiResponse {
                                            success: true,
                                            data: Some(serde_json::json!({
                                                "message": "Deposit removed successfully",
                                                "deposit_pubkey": deposit_pubkey,
                                            })),
                                            error: None,
                                        });
                                    },
                                    Err(e) => {
                                        return warp::reply::json(&ApiResponse::<serde_json::Value> {
                                            success: false,
                                            data: None,
                                            error: Some(format!("Failed to remove deposit: {:?}", e)),
                                        });
                                    }
                                }
                            }
                            _ => {
                                return warp::reply::json(&ApiResponse::<serde_json::Value> {
                                    success: false,
                                    data: None,
                                    error: Some("Invalid partner node ID or deposit pubkey".to_string()),
                                });
                            }
                        }
                    }
                    warp::reply::json(&ApiResponse::<serde_json::Value> {
                        success: false,
                        data: None,
                        error: Some("Bitcoin Deposits not available".to_string()),
                    })
                }
                #[cfg(not(feature = "bitcoin-deposits"))]
                {
                    warp::reply::json(&ApiResponse::<serde_json::Value> {
                        success: false,
                        data: None,
                        error: Some("Bitcoin Deposits feature not compiled".to_string()),
                    })
                }
            });

        // Endpoint to close a ledger (remove deposits first)
        let node_for_close_ledger = node.clone();
        let close_ledger = warp::path!("bitcoin-deposits" / "ledgers" / String)
            .and(warp::delete())
            .map(move |partner_node_id: String| {
                #[cfg(feature = "bitcoin-deposits")]
                {
                    if let Some(bd_handler) = node_for_close_ledger.deposits() {
                        match partner_node_id.parse::<ldk_node::bitcoin::secp256k1::PublicKey>() {
                            Ok(partner_pubkey) => {
                                match bd_handler.close_ledger(partner_pubkey) {
                                    Ok(()) => {
                                        return warp::reply::json(&ApiResponse {
                                            success: true,
                                            data: Some(serde_json::json!({
                                                "message": "Ledger closed successfully",
                                                "partner_node_id": partner_node_id,
                                            })),
                                            error: None,
                                        });
                                    },
                                    Err(e) => {
                                        return warp::reply::json(&ApiResponse::<serde_json::Value> {
                                            success: false,
                                            data: None,
                                            error: Some(format!("Failed to close ledger: {:?}", e)),
                                        });
                                    }
                                }
                            }
                            _ => {
                                return warp::reply::json(&ApiResponse::<serde_json::Value> {
                                    success: false,
                                    data: None,
                                    error: Some("Invalid partner node ID".to_string()),
                                });
                            }
                        }
                    }
                    warp::reply::json(&ApiResponse::<serde_json::Value> {
                        success: false,
                        data: None,
                        error: Some("Bitcoin Deposits not available".to_string()),
                    })
                }
                #[cfg(not(feature = "bitcoin-deposits"))]
                {
                    warp::reply::json(&ApiResponse::<serde_json::Value> {
                        success: false,
                        data: None,
                        error: Some("Bitcoin Deposits feature not compiled".to_string()),
                    })
                }
            });

        // Endpoint to reduce reserves (move sats from reserves to local balance)
        let node_for_reduce_reserves = node.clone();
        let reduce_reserves = warp::path!("bitcoin-deposits" / "reserves" / "reduce")
            .and(warp::post())
            .and(warp::body::json())
            .map(move |req: serde_json::Value| {
                #[cfg(feature = "bitcoin-deposits")]
                {
                    if let Some(bd_handler) = node_for_reduce_reserves.deposits() {
                        let partner_node_id = req.get("partner_node_id").and_then(|v| v.as_str());
                        let amount = req.get("amount").and_then(|v| v.as_u64());

                        match (partner_node_id, amount) {
                            (Some(partner_str), Some(reduction_amount)) => {
                                match partner_str.parse::<ldk_node::bitcoin::secp256k1::PublicKey>() {
                                    Ok(partner_pubkey) => {
                                        match bd_handler.reduce_reserves_from_channel(partner_pubkey, reduction_amount) {
                                            Ok(()) => {
                                                return warp::reply::json(&ApiResponse {
                                                    success: true,
                                                    data: Some(serde_json::json!({
                                                        "message": "Reserves reduced successfully",
                                                        "partner_node_id": partner_str,
                                                        "amount_reduced": reduction_amount,
                                                    })),
                                                    error: None,
                                                });
                                            }
                                            Err(e) => {
                                                return warp::reply::json(&ApiResponse::<serde_json::Value> {
                                                    success: false,
                                                    data: None,
                                                    error: Some(format!("Failed to reduce reserves: {:?}", e)),
                                                });
                                            }
                                        }
                                    }
                                    _ => {
                                        return warp::reply::json(&ApiResponse::<serde_json::Value> {
                                            success: false,
                                            data: None,
                                            error: Some("Invalid partner node ID".to_string()),
                                        });
                                    }
                                }
                            }
                            _ => {
                                return warp::reply::json(&ApiResponse::<serde_json::Value> {
                                    success: false,
                                    data: None,
                                    error: Some("Missing partner_node_id or amount in request body".to_string()),
                                });
                            }
                        }
                    }
                    warp::reply::json(&ApiResponse::<serde_json::Value> {
                        success: false,
                        data: None,
                        error: Some("Bitcoin Deposits not available".to_string()),
                    })
                }
                #[cfg(not(feature = "bitcoin-deposits"))]
                {
                    warp::reply::json(&ApiResponse::<serde_json::Value> {
                        success: false,
                        data: None,
                        error: Some("Bitcoin Deposits feature not compiled".to_string()),
                    })
                }
            });

        // Endpoint to remove reserves output from channel (reserves must be 0 first)
        let node_for_remove_reserves = node.clone();
        let remove_reserves = warp::path!("bitcoin-deposits" / "reserves" / String)
            .and(warp::delete())
            .map(move |partner_node_id: String| {
                #[cfg(feature = "bitcoin-deposits")]
                {
                    if let Some(bd_handler) = node_for_remove_reserves.deposits() {
                        match partner_node_id.parse::<ldk_node::bitcoin::secp256k1::PublicKey>() {
                            Ok(partner_pubkey) => {
                                match bd_handler.remove_reserves(partner_pubkey) {
                                    Ok(()) => {
                                        return warp::reply::json(&ApiResponse {
                                            success: true,
                                            data: Some(serde_json::json!({
                                                "message": "Reserves output removed successfully",
                                                "partner_node_id": partner_node_id,
                                            })),
                                            error: None,
                                        });
                                    },
                                    Err(e) => {
                                        return warp::reply::json(&ApiResponse::<serde_json::Value> {
                                            success: false,
                                            data: None,
                                            error: Some(format!("Failed to remove reserves: {:?}", e)),
                                        });
                                    }
                                }
                            }
                            _ => {
                                return warp::reply::json(&ApiResponse::<serde_json::Value> {
                                    success: false,
                                    data: None,
                                    error: Some("Invalid partner node ID".to_string()),
                                });
                            }
                        }
                    }
                    warp::reply::json(&ApiResponse::<serde_json::Value> {
                        success: false,
                        data: None,
                        error: Some("Bitcoin Deposits not available".to_string()),
                    })
                }
                #[cfg(not(feature = "bitcoin-deposits"))]
                {
                    warp::reply::json(&ApiResponse::<serde_json::Value> {
                        success: false,
                        data: None,
                        error: Some("Bitcoin Deposits feature not compiled".to_string()),
                    })
                }
            });

        // Endpoint to add a collateral partner (async to not block the executor)
        let node_for_add_collateral = node.clone();
        let add_collateral_partner = warp::path!("bitcoin-deposits" / "collateral-partner" / "add")
            .and(warp::post())
            .and(warp::body::json())
            .and_then(move |req: serde_json::Value| {
                let node = node_for_add_collateral.clone();
                async move {
                    #[cfg(feature = "bitcoin-deposits")]
                    {
                        if let Some(bd_handler) = node.deposits() {
                            let partner_node_id = req.get("partner_node_id").and_then(|v| v.as_str());
                            let collateral_partner = req.get("collateral_partner").and_then(|v| v.as_str());

                            match (partner_node_id, collateral_partner) {
                                (Some(partner_str), Some(collateral_str)) => {
                                    match (partner_str.parse::<ldk_node::bitcoin::secp256k1::PublicKey>(),
                                           collateral_str.parse::<ldk_node::bitcoin::secp256k1::PublicKey>()) {
                                        (Ok(partner_pubkey), Ok(collateral_pubkey)) => {
                                            // Use async version - doesn't block the executor!
                                            match bd_handler.add_collateral_partner_async(partner_pubkey, collateral_pubkey).await {
                                                Ok(()) => {
                                                    return Ok::<_, warp::Rejection>(warp::reply::json(&ApiResponse {
                                                        success: true,
                                                        data: Some(serde_json::json!({
                                                            "message": "Collateral partner added successfully",
                                                            "partner_node_id": partner_str,
                                                            "collateral_partner": collateral_str,
                                                        })),
                                                        error: None,
                                                    }).into_response());
                                                }
                                                Err(e) => {
                                                    let error_msg = format!("{}", e);
                                                    // Return 409 Conflict for idempotent "already exists" errors
                                                    if error_msg.contains("already exists") {
                                                        return Ok(warp::reply::with_status(
                                                            warp::reply::json(&ApiResponse::<serde_json::Value> {
                                                                success: false,
                                                                data: None,
                                                                error: Some(error_msg),
                                                            }),
                                                            warp::http::StatusCode::CONFLICT,
                                                        ).into_response());
                                                    } else {
                                                        return Ok(warp::reply::json(&ApiResponse::<serde_json::Value> {
                                                            success: false,
                                                            data: None,
                                                            error: Some(format!("Failed to add collateral partner: {:?}", e)),
                                                        }).into_response());
                                                    }
                                                }
                                            }
                                        }
                                        _ => {
                                            return Ok(warp::reply::json(&ApiResponse::<serde_json::Value> {
                                                success: false,
                                                data: None,
                                                error: Some("Invalid partner node ID or collateral partner pubkey".to_string()),
                                            }).into_response());
                                        }
                                    }
                                }
                                _ => {
                                    return Ok(warp::reply::json(&ApiResponse::<serde_json::Value> {
                                        success: false,
                                        data: None,
                                        error: Some("Missing partner_node_id or collateral_partner in request body".to_string()),
                                    }).into_response());
                                }
                            }
                        }
                        Ok(warp::reply::json(&ApiResponse::<serde_json::Value> {
                            success: false,
                            data: None,
                            error: Some("Bitcoin Deposits not available".to_string()),
                        }).into_response())
                    }
                    #[cfg(not(feature = "bitcoin-deposits"))]
                    {
                        Ok::<_, warp::Rejection>(warp::reply::json(&ApiResponse::<serde_json::Value> {
                            success: false,
                            data: None,
                            error: Some("Bitcoin Deposits feature not compiled".to_string()),
                        }).into_response())
                    }
                }
            });

        // Endpoint to remove a collateral partner
        let node_for_remove_collateral = node.clone();
        let remove_collateral_partner = warp::path!("bitcoin-deposits" / "collateral-partner" / "remove")
            .and(warp::post())
            .and(warp::body::json())
            .map(move |req: serde_json::Value| {
                #[cfg(feature = "bitcoin-deposits")]
                {
                    if let Some(bd_handler) = node_for_remove_collateral.deposits() {
                        let partner_node_id = req.get("partner_node_id").and_then(|v| v.as_str());
                        let collateral_partner = req.get("collateral_partner").and_then(|v| v.as_str());

                        match (partner_node_id, collateral_partner) {
                            (Some(partner_str), Some(collateral_str)) => {
                                match (partner_str.parse::<ldk_node::bitcoin::secp256k1::PublicKey>(),
                                       collateral_str.parse::<ldk_node::bitcoin::secp256k1::PublicKey>()) {
                                    (Ok(partner_pubkey), Ok(collateral_pubkey)) => {
                                        match bd_handler.remove_collateral_partner(partner_pubkey, collateral_pubkey) {
                                            Ok(()) => {
                                                return warp::reply::json(&ApiResponse {
                                                    success: true,
                                                    data: Some(serde_json::json!({
                                                        "message": "Collateral partner removed successfully",
                                                        "partner_node_id": partner_str,
                                                        "collateral_partner": collateral_str,
                                                    })),
                                                    error: None,
                                                });
                                            }
                                            Err(e) => {
                                                return warp::reply::json(&ApiResponse::<serde_json::Value> {
                                                    success: false,
                                                    data: None,
                                                    error: Some(format!("Failed to remove collateral partner: {:?}", e)),
                                                });
                                            }
                                        }
                                    }
                                    _ => {
                                        return warp::reply::json(&ApiResponse::<serde_json::Value> {
                                            success: false,
                                            data: None,
                                            error: Some("Invalid partner node ID or collateral partner pubkey".to_string()),
                                        });
                                    }
                                }
                            }
                            _ => {
                                return warp::reply::json(&ApiResponse::<serde_json::Value> {
                                    success: false,
                                    data: None,
                                    error: Some("Missing partner_node_id or collateral_partner in request body".to_string()),
                                });
                            }
                        }
                    }
                    warp::reply::json(&ApiResponse::<serde_json::Value> {
                        success: false,
                        data: None,
                        error: Some("Bitcoin Deposits not available".to_string()),
                    })
                }
                #[cfg(not(feature = "bitcoin-deposits"))]
                {
                    warp::reply::json(&ApiResponse::<serde_json::Value> {
                        success: false,
                        data: None,
                        error: Some("Bitcoin Deposits feature not compiled".to_string()),
                    })
                }
            });

        // NON-CONFORMING: Unregister an invoice so funds go to node instead of deposit
        #[cfg(feature = "bitcoin-deposits-non-conforming")]
        let unregister_invoice = {
            let node_for_unregister = node.clone();
            warp::path!("bitcoin-deposits" / "non-conforming" / "unregister-invoice")
                .and(warp::post())
                .and(warp::body::json())
                .map(move |req: serde_json::Value| {
                    let payment_hash_str = req.get("payment_hash").and_then(|v| v.as_str());

                    match payment_hash_str {
                        Some(hash_str) => {
                            // Parse payment hash from hex
                            match hex::decode(hash_str) {
                                Ok(hash_bytes) if hash_bytes.len() == 32 => {
                                    let mut payment_hash = [0u8; 32];
                                    payment_hash.copy_from_slice(&hash_bytes);

                                    if let Some(lightning_service) = node_for_unregister.lightning_event_service() {
                                        let removed = lightning_service.unregister_payment_for_deposit(payment_hash);
                                        warp::reply::json(&ApiResponse {
                                            success: removed,
                                            data: Some(serde_json::json!({
                                                "payment_hash": hash_str,
                                                "unregistered": removed,
                                                "message": if removed {
                                                    "Invoice unregistered - funds will go to node instead of deposit"
                                                } else {
                                                    "Payment hash not found in registered invoices"
                                                }
                                            })),
                                            error: None,
                                        })
                                    } else {
                                        warp::reply::json(&ApiResponse::<serde_json::Value> {
                                            success: false,
                                            data: None,
                                            error: Some("Lightning event service not available".to_string()),
                                        })
                                    }
                                }
                                Ok(_) => {
                                    warp::reply::json(&ApiResponse::<serde_json::Value> {
                                        success: false,
                                        data: None,
                                        error: Some("Payment hash must be 32 bytes".to_string()),
                                    })
                                }
                                Err(e) => {
                                    warp::reply::json(&ApiResponse::<serde_json::Value> {
                                        success: false,
                                        data: None,
                                        error: Some(format!("Invalid payment hash hex: {}", e)),
                                    })
                                }
                            }
                        }
                        None => {
                            warp::reply::json(&ApiResponse::<serde_json::Value> {
                                success: false,
                                data: None,
                                error: Some("Missing payment_hash in request body".to_string()),
                            })
                        }
                    }
                })
        };

        // NON-CONFORMING: Get payment details including preimage (for fraud proof)
        #[cfg(feature = "bitcoin-deposits-non-conforming")]
        let get_payment = {
            let node_for_payment = node.clone();
            warp::path!("bitcoin-deposits" / "non-conforming" / "get-payment" / String)
                .and(warp::get())
                .map(move |payment_hash_hex: String| {
                    match hex::decode(&payment_hash_hex) {
                        Ok(hash_bytes) if hash_bytes.len() == 32 => {
                            let mut payment_hash = [0u8; 32];
                            payment_hash.copy_from_slice(&hash_bytes);
                            let payment_id = ldk_node::lightning::ln::channelmanager::PaymentId(payment_hash);

                            match node_for_payment.payment(&payment_id) {
                                Some(details) => {
                                    // Extract preimage from PaymentKind
                                    let preimage = match &details.kind {
                                        ldk_node::payment::PaymentKind::Bolt11 { preimage, .. } => {
                                            preimage.map(|p| hex::encode(p.0))
                                        }
                                        ldk_node::payment::PaymentKind::Bolt11Jit { preimage, .. } => {
                                            preimage.map(|p| hex::encode(p.0))
                                        }
                                        ldk_node::payment::PaymentKind::Spontaneous { preimage, .. } => {
                                            preimage.map(|p| hex::encode(p.0))
                                        }
                                        _ => None,
                                    };

                                    warp::reply::json(&ApiResponse {
                                        success: true,
                                        data: Some(serde_json::json!({
                                            "payment_hash": payment_hash_hex,
                                            "preimage": preimage,
                                            "amount_msat": details.amount_msat,
                                            "status": format!("{:?}", details.status),
                                            "direction": format!("{:?}", details.direction),
                                        })),
                                        error: None,
                                    })
                                }
                                None => {
                                    warp::reply::json(&ApiResponse::<serde_json::Value> {
                                        success: false,
                                        data: None,
                                        error: Some("Payment not found".to_string()),
                                    })
                                }
                            }
                        }
                        Ok(_) => {
                            warp::reply::json(&ApiResponse::<serde_json::Value> {
                                success: false,
                                data: None,
                                error: Some("Payment hash must be 32 bytes".to_string()),
                            })
                        }
                        Err(e) => {
                            warp::reply::json(&ApiResponse::<serde_json::Value> {
                                success: false,
                                data: None,
                                error: Some(format!("Invalid payment hash hex: {}", e)),
                            })
                        }
                    }
                })
        };

        // NON-CONFORMING: Drop all ledgers (for quick test environment cycling)
        #[cfg(feature = "bitcoin-deposits-non-conforming")]
        let drop_ledgers = {
            let node_for_drop = node.clone();
            warp::path!("bitcoin-deposits" / "non-conforming" / "drop-ledgers")
                .and(warp::post())
                .map(move || {
                    if let Some(bd_handler) = node_for_drop.deposits_handler() {
                        let count = bd_handler.drop_all_ledgers();
                        warp::reply::json(&ApiResponse {
                            success: true,
                            data: Some(serde_json::json!({
                                "dropped_ledgers": count,
                                "message": "All ledgers and audit state cleared"
                            })),
                            error: None,
                        })
                    } else {
                        warp::reply::json(&ApiResponse::<serde_json::Value> {
                            success: false,
                            data: None,
                            error: Some("Bitcoin deposits handler not available".to_string()),
                        })
                    }
                })
        };

        // Submit fraud proof (uncredited payment accusation)
        // This is a legitimate action - partner submits proof when operator steals funds
        let submit_fraud_proof = {
            let node_for_fraud = node.clone();
            warp::path!("bitcoin-deposits" / "submit-fraud-proof")
                .and(warp::post())
                .and(warp::body::json())
                .map(move |req: serde_json::Value| {
                    let operator_str = req.get("operator").and_then(|v| v.as_str());
                    let payment_hash_str = req.get("payment_hash").and_then(|v| v.as_str());
                    let preimage_str = req.get("preimage").and_then(|v| v.as_str());
                    let deposit_pubkey_str = req.get("deposit_pubkey").and_then(|v| v.as_str());
                    let amount_msat = req.get("amount_msat").and_then(|v| v.as_u64());

                    match (operator_str, payment_hash_str, preimage_str, deposit_pubkey_str, amount_msat) {
                        (Some(op), Some(ph), Some(pi), Some(dp), Some(amt)) => {
                            // Parse all the fields
                            let operator = match op.parse::<ldk_node::bitcoin::secp256k1::PublicKey>() {
                                Ok(pk) => pk,
                                Err(e) => return warp::reply::json(&ApiResponse::<serde_json::Value> {
                                    success: false,
                                    data: None,
                                    error: Some(format!("Invalid operator pubkey: {}", e)),
                                }),
                            };

                            let payment_hash: [u8; 32] = match hex::decode(ph) {
                                Ok(bytes) if bytes.len() == 32 => {
                                    let mut arr = [0u8; 32];
                                    arr.copy_from_slice(&bytes);
                                    arr
                                }
                                _ => return warp::reply::json(&ApiResponse::<serde_json::Value> {
                                    success: false,
                                    data: None,
                                    error: Some("Invalid payment_hash".to_string()),
                                }),
                            };

                            let preimage: [u8; 32] = match hex::decode(pi) {
                                Ok(bytes) if bytes.len() == 32 => {
                                    let mut arr = [0u8; 32];
                                    arr.copy_from_slice(&bytes);
                                    arr
                                }
                                _ => return warp::reply::json(&ApiResponse::<serde_json::Value> {
                                    success: false,
                                    data: None,
                                    error: Some("Invalid preimage".to_string()),
                                }),
                            };

                            let deposit_pubkey = match dp.parse::<ldk_node::bitcoin::secp256k1::PublicKey>() {
                                Ok(pk) => pk,
                                Err(e) => return warp::reply::json(&ApiResponse::<serde_json::Value> {
                                    success: false,
                                    data: None,
                                    error: Some(format!("Invalid deposit_pubkey: {}", e)),
                                }),
                            };

                            // Invoice cosignature - for testing, use zeros (TODO: get real cosignature)
                            let invoice_cosignature = [0u8; 64];

                            if let Some(bd_handler) = node_for_fraud.deposits() {
                                match bd_handler.broadcast_uncredited_payment_accusation(
                                    operator,
                                    payment_hash,
                                    preimage,
                                    deposit_pubkey,
                                    amt,
                                    invoice_cosignature,
                                ) {
                                    Ok(()) => {
                                        warp::reply::json(&ApiResponse {
                                            success: true,
                                            data: Some(serde_json::json!({
                                                "message": "Fraud proof validated and broadcast to auditors",
                                                "operator": op,
                                                "payment_hash": ph,
                                                "deposit_pubkey": dp,
                                                "amount_msat": amt,
                                            })),
                                            error: None,
                                        })
                                    }
                                    Err(e) => {
                                        warp::reply::json(&ApiResponse::<serde_json::Value> {
                                            success: false,
                                            data: None,
                                            error: Some(format!("Failed to broadcast fraud proof: {}", e)),
                                        })
                                    }
                                }
                            } else {
                                warp::reply::json(&ApiResponse::<serde_json::Value> {
                                    success: false,
                                    data: None,
                                    error: Some("Bitcoin Deposits not available".to_string()),
                                })
                            }
                        }
                        _ => {
                            warp::reply::json(&ApiResponse::<serde_json::Value> {
                                success: false,
                                data: None,
                                error: Some("Missing required fields: operator, payment_hash, preimage, deposit_pubkey, amount_msat".to_string()),
                            })
                        }
                    }
                })
        };

        // ===== PROTO ROUTES =====
        // These routes use protobuf encoding at /deposits/* paths

        // Proto: List Ledgers
        let node_for_proto_list = Arc::clone(&node);
        let proto_list_ledgers = warp::path!("deposits" / "list_ledgers")
            .and(warp::post())
            .and(warp::body::bytes())
            .map(move |body: warp::hyper::body::Bytes| {
                let request = match ListLedgersRequest::decode(body.as_ref()) {
                    Ok(r) => r,
                    Err(e) => return proto_error_response("DECODE_ERROR", &format!("Failed to decode request: {}", e)),
                };

                if let Some(bd_handler) = node_for_proto_list.deposits() {
                    match ledger::handle_list_ledgers(&bd_handler, request) {
                        Ok(response) => proto_response(response),
                        Err(e) => proto_error_response(&e.code, &e.message),
                    }
                } else {
                    proto_error_response("NOT_ENABLED", "Bitcoin Deposits not enabled")
                }
            });

        // Proto: Init Ledger
        let node_for_proto_init = Arc::clone(&node);
        let proto_init_ledger = warp::path!("deposits" / "init_ledger")
            .and(warp::post())
            .and(warp::body::bytes())
            .and_then(move |body: warp::hyper::body::Bytes| {
                let node = node_for_proto_init.clone();
                async move {
                    let request = match InitLedgerRequest::decode(body.as_ref()) {
                        Ok(r) => r,
                        Err(e) => return Ok::<_, warp::Rejection>(proto_error_response("DECODE_ERROR", &format!("Failed to decode request: {}", e))),
                    };

                    if let Some(bd_handler) = node.deposits() {
                        match ledger::handle_init_ledger(&bd_handler, request).await {
                            Ok(response) => Ok(proto_response(response)),
                            Err(e) => Ok(proto_error_response(&e.code, &e.message)),
                        }
                    } else {
                        Ok(proto_error_response("NOT_ENABLED", "Bitcoin Deposits not enabled"))
                    }
                }
            });

        // Proto: Close Ledger
        let node_for_proto_close = Arc::clone(&node);
        let proto_close_ledger = warp::path!("deposits" / "close_ledger")
            .and(warp::post())
            .and(warp::body::bytes())
            .map(move |body: warp::hyper::body::Bytes| {
                let request = match CloseLedgerRequest::decode(body.as_ref()) {
                    Ok(r) => r,
                    Err(e) => return proto_error_response("DECODE_ERROR", &format!("Failed to decode request: {}", e)),
                };

                if let Some(bd_handler) = node_for_proto_close.deposits() {
                    match ledger::handle_close_ledger(&bd_handler, request) {
                        Ok(response) => proto_response(response),
                        Err(e) => proto_error_response(&e.code, &e.message),
                    }
                } else {
                    proto_error_response("NOT_ENABLED", "Bitcoin Deposits not enabled")
                }
            });

        // Proto: Add Deposit
        let node_for_proto_add_deposit = Arc::clone(&node);
        let proto_add_deposit = warp::path!("deposits" / "add_deposit")
            .and(warp::post())
            .and(warp::body::bytes())
            .and_then(move |body: warp::hyper::body::Bytes| {
                let node = node_for_proto_add_deposit.clone();
                async move {
                    let request = match AddDepositRequest::decode(body.as_ref()) {
                        Ok(r) => r,
                        Err(e) => return Ok::<_, warp::Rejection>(proto_error_response("DECODE_ERROR", &format!("Failed to decode request: {}", e))),
                    };

                    if let Some(bd_handler) = node.deposits() {
                        match deposit::handle_add_deposit(&bd_handler, request).await {
                            Ok(response) => Ok(proto_response(response)),
                            Err(e) => Ok(proto_error_response(&e.code, &e.message)),
                        }
                    } else {
                        Ok(proto_error_response("NOT_ENABLED", "Bitcoin Deposits not enabled"))
                    }
                }
            });

        // Proto: List Deposits
        let node_for_proto_list_deposits = Arc::clone(&node);
        let proto_list_deposits = warp::path!("deposits" / "list_deposits")
            .and(warp::post())
            .and(warp::body::bytes())
            .map(move |body: warp::hyper::body::Bytes| {
                let request = match ListDepositsRequest::decode(body.as_ref()) {
                    Ok(r) => r,
                    Err(e) => return proto_error_response("DECODE_ERROR", &format!("Failed to decode request: {}", e)),
                };

                if let Some(bd_handler) = node_for_proto_list_deposits.deposits() {
                    match deposit::handle_list_deposits(&bd_handler, request) {
                        Ok(response) => proto_response(response),
                        Err(e) => proto_error_response(&e.code, &e.message),
                    }
                } else {
                    proto_error_response("NOT_ENABLED", "Bitcoin Deposits not enabled")
                }
            });

        // Proto: Remove Deposit
        let node_for_proto_remove_deposit = Arc::clone(&node);
        let proto_remove_deposit = warp::path!("deposits" / "remove_deposit")
            .and(warp::post())
            .and(warp::body::bytes())
            .map(move |body: warp::hyper::body::Bytes| {
                let request = match RemoveDepositRequest::decode(body.as_ref()) {
                    Ok(r) => r,
                    Err(e) => return proto_error_response("DECODE_ERROR", &format!("Failed to decode request: {}", e)),
                };

                if let Some(bd_handler) = node_for_proto_remove_deposit.deposits() {
                    match deposit::handle_remove_deposit(&bd_handler, request) {
                        Ok(response) => proto_response(response),
                        Err(e) => proto_error_response(&e.code, &e.message),
                    }
                } else {
                    proto_error_response("NOT_ENABLED", "Bitcoin Deposits not enabled")
                }
            });

        // Proto: Reduce Reserves
        let node_for_proto_reduce = Arc::clone(&node);
        let proto_reduce_reserves = warp::path!("deposits" / "reduce_reserves")
            .and(warp::post())
            .and(warp::body::bytes())
            .and_then(move |body: warp::hyper::body::Bytes| {
                let node = node_for_proto_reduce.clone();
                async move {
                    let request = match ReduceReservesRequest::decode(body.as_ref()) {
                        Ok(r) => r,
                        Err(e) => return Ok::<_, warp::Rejection>(proto_error_response("DECODE_ERROR", &format!("Failed to decode request: {}", e))),
                    };

                    if let Some(bd_handler) = node.deposits() {
                        match reserves::handle_reduce_reserves(&bd_handler, request).await {
                            Ok(response) => Ok(proto_response(response)),
                            Err(e) => Ok(proto_error_response(&e.code, &e.message)),
                        }
                    } else {
                        Ok(proto_error_response("NOT_ENABLED", "Bitcoin Deposits not enabled"))
                    }
                }
            });

        // Proto: Get Ledger Updates
        let node_for_proto_updates = Arc::clone(&node);
        let proto_get_updates = warp::path!("deposits" / "get_ledger_updates")
            .and(warp::post())
            .and(warp::body::bytes())
            .map(move |body: warp::hyper::body::Bytes| {
                let request = match GetLedgerUpdatesRequest::decode(body.as_ref()) {
                    Ok(r) => r,
                    Err(e) => return proto_error_response("DECODE_ERROR", &format!("Failed to decode request: {}", e)),
                };

                if let Some(bd_handler) = node_for_proto_updates.deposits() {
                    match updates::handle_get_ledger_updates(&bd_handler, request) {
                        Ok(response) => proto_response(response),
                        Err(e) => proto_error_response(&e.code, &e.message),
                    }
                } else {
                    proto_error_response("NOT_ENABLED", "Bitcoin Deposits not enabled")
                }
            });

        // Proto: Add Collateral Partner
        let node_for_proto_add_collateral = Arc::clone(&node);
        let proto_add_collateral = warp::path!("deposits" / "add_collateral_partner")
            .and(warp::post())
            .and(warp::body::bytes())
            .and_then(move |body: warp::hyper::body::Bytes| {
                let node = node_for_proto_add_collateral.clone();
                async move {
                    let request = match AddCollateralPartnerRequest::decode(body.as_ref()) {
                        Ok(r) => r,
                        Err(e) => return Ok::<_, warp::Rejection>(proto_error_response("DECODE_ERROR", &format!("Failed to decode request: {}", e))),
                    };

                    if let Some(bd_handler) = node.deposits() {
                        match collateral::handle_add_collateral_partner(&bd_handler, request).await {
                            Ok(response) => Ok(proto_response(response)),
                            Err(e) => Ok(proto_error_response(&e.code, &e.message)),
                        }
                    } else {
                        Ok(proto_error_response("NOT_ENABLED", "Bitcoin Deposits not enabled"))
                    }
                }
            });

        // Proto: Remove Collateral Partner
        let node_for_proto_remove_collateral = Arc::clone(&node);
        let proto_remove_collateral = warp::path!("deposits" / "remove_collateral_partner")
            .and(warp::post())
            .and(warp::body::bytes())
            .map(move |body: warp::hyper::body::Bytes| {
                let request = match RemoveCollateralPartnerRequest::decode(body.as_ref()) {
                    Ok(r) => r,
                    Err(e) => return proto_error_response("DECODE_ERROR", &format!("Failed to decode request: {}", e)),
                };

                if let Some(bd_handler) = node_for_proto_remove_collateral.deposits() {
                    match collateral::handle_remove_collateral_partner(&bd_handler, request) {
                        Ok(response) => proto_response(response),
                        Err(e) => proto_error_response(&e.code, &e.message),
                    }
                } else {
                    proto_error_response("NOT_ENABLED", "Bitcoin Deposits not enabled")
                }
            });

        // Combine proto routes (primary API)
        let proto_routes = proto_list_ledgers
            .or(proto_init_ledger)
            .or(proto_close_ledger)
            .or(proto_add_deposit)
            .or(proto_list_deposits)
            .or(proto_remove_deposit)
            .or(proto_reduce_reserves)
            .or(proto_get_updates)
            .or(proto_add_collateral)
            .or(proto_remove_collateral);

        // Management routes that don't have proto equivalents yet (keep as JSON)
        let management_routes = start_nwc
            .or(submit_fraud_proof);

        // Combine proto and management routes
        let base_routes = proto_routes.or(management_routes);

        #[cfg(feature = "bitcoin-deposits-non-conforming")]
        { base_routes.or(unregister_invoice).or(get_payment).or(drop_ledgers) }

        #[cfg(not(feature = "bitcoin-deposits-non-conforming"))]
        { base_routes }
    };

    #[cfg(not(feature = "bitcoin-deposits"))]
    let deposits_routes = warp::path!("bitcoin-deposits" / ..)
        .map(|| {
            warp::reply::json(&ApiResponse::<serde_json::Value> {
                success: false,
                data: None,
                error: Some("Bitcoin Deposits feature not enabled".to_string()),
            })
        });

    // NWC status endpoint (includes pubkey and relay info)
    let nwc_pubkey = if let Some(ref nwc_service) = nwc_service {
        let nwc_pubkey = nwc_service.pubkey().to_string();
        let relay_url = nwc_service.relay_url().to_string();
        warp::path!("nwc" / "pubkey")
            .and(warp::get())
            .map(move || {
                warp::reply::json(&ApiResponse {
                    success: true,
                    data: Some(serde_json::json!({
                        "nwc_pubkey": nwc_pubkey,
                        "relay_url": relay_url
                    })),
                    error: None,
                })
            })
            .boxed()
    } else {
        warp::path!("nwc" / "pubkey")
            .and(warp::get())
            .map(|| {
                warp::reply::json(&ApiResponse::<serde_json::Value> {
                    success: false,
                    data: None,
                    error: Some("NWC service not available".to_string()),
                })
            })
            .boxed()
    };

    // NWC connection string endpoint (includes secret for node-level access)
    // WARNING: This grants full node control - should only be accessible to authorized operators
    let nwc_connect = if let Some(ref nwc_service) = nwc_service {
        let connection_string = nwc_service.connection_string();
        let nwc_pubkey = nwc_service.pubkey().to_string();
        let relay_url = nwc_service.relay_url().to_string();
        warp::path!("nwc" / "connect")
            .and(warp::get())
            .map(move || {
                warp::reply::json(&ApiResponse {
                    success: true,
                    data: Some(serde_json::json!({
                        "connection_string": connection_string,
                        "nwc_pubkey": nwc_pubkey,
                        "relay_url": relay_url
                    })),
                    error: None,
                })
            })
            .boxed()
    } else {
        warp::path!("nwc" / "connect")
            .and(warp::get())
            .map(|| {
                warp::reply::json(&ApiResponse::<serde_json::Value> {
                    success: false,
                    data: None,
                    error: Some("NWC service not available".to_string()),
                })
            })
            .boxed()
    };

    let routes = health
        .or(node_info)
        .or(bitcoin_address)
        .or(bitcoin_balance)
        .or(bitcoin_send)
        .or(connect_peer)
        .or(open_channel)
        .or(force_close_channel)
        .or(list_channels)
        .or(create_invoice)
        .or(pay_invoice)
        .or(deposits_routes)
        .or(nwc_pubkey)
        .or(nwc_connect)
        .with(warp::cors().allow_any_origin().allow_headers(vec!["content-type"]).allow_methods(vec!["GET", "POST"]));

    println!("✅ HTTP API server listening on 0.0.0.0:{}", port);
    warp::serve(routes).run(([0, 0, 0, 0], port)).await;

    Ok(())
}
