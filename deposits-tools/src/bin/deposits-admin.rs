use bitcoin::secp256k1::{Secp256k1, SecretKey, PublicKey};
use clap::{Arg, ArgMatches, Command, CommandFactory, ValueHint};
use clap_complete::{generate, Shell};
use deposits_ldk::service::{
    endpoints,
    InitLedgerRequest, InitLedgerResponse,
    ListLedgersRequest, ListLedgersResponse,
    CloseLedgerRequest, CloseLedgerResponse,
    AddDepositRequest, AddDepositResponse,
    ListDepositsRequest, ListDepositsResponse,
    RemoveDepositRequest, RemoveDepositResponse,
    AddReservesRequest, AddReservesResponse,
    ReduceReservesRequest, ReduceReservesResponse,
    RemoveReservesRequest, RemoveReservesResponse,
    GetLedgerUpdatesRequest, GetLedgerUpdatesResponse,
    AddCollateralPartnerRequest, AddCollateralPartnerResponse,
    RemoveCollateralPartnerRequest, RemoveCollateralPartnerResponse,
    GetDepositNwcRequest, GetDepositNwcResponse,
    DepositsError,
};
use ldk_server_protos::api::{GetNodeInfoRequest, GetNodeInfoResponse};
use ldk_server_protos::endpoints::GET_NODE_INFO_PATH;
use hmac::{Hmac, Mac};
use prost::Message;
use rand::RngCore;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;
use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

const API_KEY: &str = "test_api_key";

/// Compute HMAC-SHA256 auth header for ldk-server
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

#[derive(Serialize, Deserialize, Debug)]
struct ApiResponse<T> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
}

#[derive(Debug)]
struct Cli;

impl CommandFactory for Cli {
    fn command() -> Command {
        build_cli()
    }
    fn command_for_update() -> Command {
        build_cli()
    }
}

/// Send a protobuf request and decode the response
async fn proto_request<Req: Message, Resp: Message + Default>(
    client: &Client,
    base_url: &str,
    path: &str,
    request: Req,
) -> Result<Resp, Box<dyn Error>> {
    let url = format!("{}{}", base_url, path);
    let body = request.encode_to_vec();
    let auth_header = compute_auth_header(&body);

    let response = client
        .post(&url)
        .header("Content-Type", "application/octet-stream")
        .header("X-Auth", auth_header)
        .body(body)
        .send()
        .await?;

    let status = response.status();
    let bytes = response.bytes().await?;

    if !status.is_success() {
        // Try to decode as DepositsError
        if let Ok(error) = DepositsError::decode(bytes.as_ref()) {
            return Err(format!("{}: {}", error.code, error.message).into());
        }
        return Err(format!("HTTP {}: {}", status, String::from_utf8_lossy(&bytes)).into());
    }

    let resp = Resp::decode(bytes.as_ref())?;
    Ok(resp)
}

fn resolve_port(port_or_alias: &str) -> String {
    match port_or_alias.to_lowercase().as_str() {
        "alice" => "3011".to_string(),
        "bob" => "3012".to_string(),
        "charlie" => "3013".to_string(),
        "diana" => "3014".to_string(),
        "eve" => "3015".to_string(),
        "frank" => "3016".to_string(),
        "grace" => "3017".to_string(),
        // If it's not an alias, assume it's already a port number
        _ => port_or_alias.to_string(),
    }
}

/// Resolve a node alias (alice, bob, charlie, etc.) to its node ID by querying the API
/// If the input is already a valid pubkey (66 hex chars), return it as-is
async fn resolve_node_id(client: &Client, node_id_or_alias: &str) -> Result<String, Box<dyn Error>> {
    // If it looks like a pubkey (66 hex characters), return as-is
    if node_id_or_alias.len() == 66 && node_id_or_alias.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(node_id_or_alias.to_string());
    }

    // Try to resolve as an alias
    let port = resolve_port(node_id_or_alias);
    let base_url = format!("https://localhost:{}", port);

    // Use protobuf GetNodeInfo endpoint
    let request = GetNodeInfoRequest {};
    let response: GetNodeInfoResponse = proto_request(
        client,
        &base_url,
        &format!("/{}", GET_NODE_INFO_PATH),
        request,
    ).await.map_err(|e| format!("Failed to resolve node alias '{}': {}", node_id_or_alias, e))?;

    Ok(response.node_id)
}

/// Build a lookup table from node_id -> human-readable name by querying all known nodes
async fn build_node_name_map(client: &Client) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let known_nodes = [
        ("alice", "3011"),
        ("bob", "3012"),
        ("charlie", "3013"),
        ("diana", "3014"),
        ("eve", "3015"),
        ("frank", "3016"),
        ("grace", "3017"),
    ];

    for (name, port) in known_nodes {
        let base_url = format!("https://localhost:{}", port);
        let request = GetNodeInfoRequest {};
        if let Ok(response) = proto_request::<_, GetNodeInfoResponse>(
            client,
            &base_url,
            &format!("/{}", GET_NODE_INFO_PATH),
            request,
        ).await {
            map.insert(response.node_id, name.to_string());
        }
    }
    map
}

/// Look up a node name from node_id, returns "Name (prefix..suffix)" or just "prefix..suffix"
fn format_node_id(node_id: &str, name_map: &HashMap<String, String>) -> String {
    if let Some(name) = name_map.get(node_id) {
        format!("{} ({}..{})", name, &node_id[..4], &node_id[node_id.len()-4..])
    } else {
        format!("{}..{}", &node_id[..4], &node_id[node_id.len()-4..])
    }
}

fn build_cli() -> Command {
    Command::new("deposits-admin")
        .version("1.0")
        .author("LDK Node")
        .about("Admin CLI for Bitcoin Deposits management")
        .arg(
            Arg::new("port")
                .short('p')
                .long("port")
                .value_name("PORT|ALIAS")
                .help("API port or node alias (alice=3011, bob=3012, charlie=3013, etc.)")
                .default_value("alice"),
        )
        .subcommand(
            Command::new("completions")
                .about("Generate shell completions")
                .arg(
                    Arg::new("shell")
                        .help("Shell to generate completions for")
                        .value_parser(["bash", "zsh", "fish", "powershell", "elvish"])
                        .required(true)
                        .index(1),
                ),
        )
        .subcommand(
            Command::new("_complete")
                .hide(true)
                .about("Dynamic completion helper (internal use)")
                .arg(Arg::new("type").required(true).index(1))
                .arg(Arg::new("port").required(false).index(2)),
        )
        .subcommand(
            Command::new("get-node-id")
                .about("Get the node's public key (node ID)")
        )
        .subcommand(
            Command::new("gen-keypair")
                .about("Generate a new secp256k1 keypair (outputs: secret pubkey)")
        )
        .subcommand(
            Command::new("add-ledger")
                .about("Add/initialize a new ledger with a partner")
                .arg(
                    Arg::new("partner")
                        .help("Partner node public key")
                        .value_hint(ValueHint::Other)
                        .required(true)
                        .index(1),
                ),
        )
        .subcommand(
            Command::new("remove-ledger")
                .about("Remove a ledger with a partner")
                .arg(
                    Arg::new("partner")
                        .help("Partner node public key")
                        .value_hint(ValueHint::Other)
                        .required(true)
                        .index(1),
                ),
        )
        .subcommand(
            Command::new("list-ledgers")
                .about("List all deposit ledgers"),
        )
        .subcommand(
            Command::new("list-orphans")
                .about("List orphaned updates (signed updates that couldn't be applied due to hash chain mismatch)"),
        )
        .subcommand(
            Command::new("list-deposits")
                .about("List deposits for a partner or all deposits")
                .arg(
                    Arg::new("partner")
                        .help("Partner node public key (optional - shows all if omitted)")
                        .value_hint(ValueHint::Other)
                        .index(1),
                ),
        )
        .subcommand(
            Command::new("deposit-balance")
                .about("Get balance for a specific deposit (outputs sats only)")
                .arg(
                    Arg::new("deposit-pubkey")
                        .help("Deposit public key")
                        .value_hint(ValueHint::Other)
                        .required(true)
                        .index(1),
                ),
        )
        .subcommand(
            Command::new("deposit-nwc")
                .about("Get NWC credentials for a deposit (outputs JSON for wallet file)")
                .arg(
                    Arg::new("deposit-pubkey")
                        .help("Deposit public key")
                        .value_hint(ValueHint::Other)
                        .required(true)
                        .index(1),
                ),
        )
        .subcommand(
            Command::new("get-updates")
                .about("Get ledger updates")
                .arg(
                    Arg::new("partner")
                        .help("Partner node public key (optional - shows all if omitted)")
                        .value_hint(ValueHint::Other)
                        .index(1),
                ),
        )
        .subcommand(
            Command::new("add-deposit")
                .about("Add a new deposit")
                .arg(
                    Arg::new("partner")
                        .help("Partner node public key")
                        .value_hint(ValueHint::Other)
                        .required(true)
                        .index(1),
                )
                .arg(
                    Arg::new("deposit-pubkey")
                        .help("Deposit public key")
                        .value_hint(ValueHint::Other)
                        .required(true)
                        .index(2),
                )
                .arg(
                    Arg::new("channel-id")
                        .short('c')
                        .long("channel-id")
                        .value_name("CHANNEL_ID")
                        .value_hint(ValueHint::Other)
                        .help("Channel ID (optional - auto-selects if not provided)"),
                )
                .arg(
                    Arg::new("amount")
                        .short('a')
                        .long("amount")
                        .value_name("SATS")
                        .help("Initial amount in sats (default: 0)")
                        .default_value("0"),
                ),
        )
        .subcommand(
            Command::new("remove-deposit")
                .about("Remove an empty deposit")
                .arg(
                    Arg::new("partner")
                        .help("Partner node public key")
                        .value_hint(ValueHint::Other)
                        .required(true)
                        .index(1),
                )
                .arg(
                    Arg::new("deposit-pubkey")
                        .help("Deposit public key")
                        .value_hint(ValueHint::Other)
                        .required(true)
                        .index(2),
                ),
        )
        .subcommand(
            Command::new("collect-fees")
                .about("Manually trigger fee collection for all deposits"),
        )
        .subcommand(
            Command::new("add-reserves")
                .about("Add reserves to channel (creates Taproot output with ledger hash)")
                .arg(
                    Arg::new("partner")
                        .help("Partner node public key")
                        .value_hint(ValueHint::Other)
                        .required(true)
                        .index(1),
                )
                .arg(
                    Arg::new("amount")
                        .help("Amount in sats to add")
                        .value_hint(ValueHint::Other)
                        .required(true)
                        .index(2),
                ),
        )
        .subcommand(
            Command::new("reduce-reserves")
                .about("Reduce reserves (move sats back to local balance)")
                .arg(
                    Arg::new("partner")
                        .help("Partner node public key")
                        .value_hint(ValueHint::Other)
                        .required(true)
                        .index(1),
                )
                .arg(
                    Arg::new("amount")
                        .help("Amount in sats to reduce")
                        .value_hint(ValueHint::Other)
                        .required(true)
                        .index(2),
                ),
        )
        .subcommand(
            Command::new("remove-reserves")
                .about("Remove reserves output from channel (must reduce to 0 first)")
                .arg(
                    Arg::new("partner")
                        .help("Partner node public key")
                        .value_hint(ValueHint::Other)
                        .required(true)
                        .index(1),
                ),
        )
        .subcommand(
            Command::new("add-collateral-partner")
                .about("Add a collateral partner to a ledger")
                .arg(
                    Arg::new("partner")
                        .help("Partner node for the ledger")
                        .value_hint(ValueHint::Other)
                        .required(true)
                        .index(1),
                )
                .arg(
                    Arg::new("collateral-partner")
                        .help("Node to add as collateral partner")
                        .value_hint(ValueHint::Other)
                        .required(true)
                        .index(2),
                ),
        )
        .subcommand(
            Command::new("remove-collateral-partner")
                .about("Remove a collateral partner from a ledger")
                .arg(
                    Arg::new("partner")
                        .help("Partner node for the ledger")
                        .value_hint(ValueHint::Other)
                        .required(true)
                        .index(1),
                )
                .arg(
                    Arg::new("collateral-partner")
                        .help("Node to remove as collateral partner")
                        .value_hint(ValueHint::Other)
                        .required(true)
                        .index(2),
                ),
        )
        .subcommand(
            Command::new("status")
                .about("Show node status and info")
                .arg(
                    Arg::new("node")
                        .help("Node alias or port (optional - uses default port if omitted)")
                        .index(1),
                ),
        )
        .subcommand(
            Command::new("info")
                .about("Show detailed node information"),
        )
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let matches = build_cli().get_matches();

    // Check if --port was explicitly provided or use TARGET env var, fallback to default
    let port_or_alias = if matches.value_source("port") == Some(clap::parser::ValueSource::DefaultValue) {
        // --port was not explicitly provided, check TARGET env var
        env::var("TARGET").unwrap_or_else(|_| "alice".to_string())
    } else {
        // --port was explicitly provided
        matches.get_one::<String>("port").unwrap().to_string()
    };

    let port = resolve_port(&port_or_alias);
    let base_url = format!("https://localhost:{}", port);
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("Failed to build HTTP client");

    match matches.subcommand() {
        Some(("completions", sub_m)) => {
            let shell = sub_m.get_one::<String>("shell").unwrap();
            let shell = match shell.as_str() {
                "bash" => Shell::Bash,
                "zsh" => Shell::Zsh,
                "fish" => Shell::Fish,
                "powershell" => Shell::PowerShell,
                "elvish" => Shell::Elvish,
                _ => {
                    eprintln!("Unsupported shell: {}", shell);
                    std::process::exit(1);
                }
            };
            generate(shell, &mut Cli::command(), "deposits-admin", &mut io::stdout());
            return Ok(());
        }
        Some(("_complete", sub_m)) => {
            let comp_type = sub_m.get_one::<String>("type").unwrap();
            let port_or_alias = sub_m.get_one::<String>("port").unwrap_or(&port);
            let resolved_port = resolve_port(port_or_alias);
            complete_dynamic(&client, &format!("https://localhost:{}", resolved_port), comp_type).await?;
            return Ok(());
        }
        Some(("get-node-id", _)) => {
            // Print just the node ID (for script usage)
            let request = GetNodeInfoRequest {};
            let response: GetNodeInfoResponse = proto_request(
                &client,
                &base_url,
                &format!("/{}", GET_NODE_INFO_PATH),
                request,
            ).await?;
            println!("{}", response.node_id);
        }
        Some(("gen-keypair", _)) => {
            // Generate a random secp256k1 keypair
            let secp = Secp256k1::new();
            let mut secret_bytes = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut secret_bytes);
            let secret_key = SecretKey::from_slice(&secret_bytes)
                .expect("32 random bytes are always a valid secret key");
            let public_key = PublicKey::from_secret_key(&secp, &secret_key);
            // Output: secret_hex pubkey_hex (space-separated for easy parsing)
            println!("{} {}", hex::encode(secret_bytes), hex::encode(public_key.serialize()));
        }
        Some(("add-ledger", sub_m)) => {
            add_ledger(&client, &base_url, sub_m).await?;
        }
        Some(("remove-ledger", sub_m)) => {
            remove_ledger(&client, &base_url, sub_m).await?;
        }
        Some(("list-ledgers", _)) => {
            list_ledgers(&client, &base_url).await?;
        }
        Some(("list-orphans", _)) => {
            list_orphans(&client, &base_url).await?;
        }
        Some(("list-deposits", sub_m)) => {
            let partner = if let Some(partner_input) = sub_m.get_one::<String>("partner") {
                Some(resolve_node_id(&client, partner_input).await?)
            } else {
                None
            };
            list_deposits(&client, &base_url, partner.as_deref()).await?;
        }
        Some(("deposit-balance", sub_m)) => {
            let deposit_pubkey = sub_m.get_one::<String>("deposit-pubkey").unwrap();
            deposit_balance(&client, &base_url, deposit_pubkey).await?;
        }
        Some(("deposit-nwc", sub_m)) => {
            let deposit_pubkey = sub_m.get_one::<String>("deposit-pubkey").unwrap();
            deposit_nwc(&client, &base_url, deposit_pubkey).await?;
        }
        Some(("get-updates", sub_m)) => {
            let partner = if let Some(partner_input) = sub_m.get_one::<String>("partner") {
                Some(resolve_node_id(&client, partner_input).await?)
            } else {
                None
            };
            get_updates(&client, &base_url, partner.as_deref()).await?;
        }
        Some(("add-deposit", sub_m)) => {
            add_deposit(&client, &base_url, sub_m).await?;
        }
        Some(("remove-deposit", sub_m)) => {
            remove_deposit(&client, &base_url, sub_m).await?;
        }
        Some(("collect-fees", _)) => {
            collect_fees(&client, &base_url).await?;
        }
        Some(("add-reserves", sub_m)) => {
            add_reserves(&client, &base_url, sub_m).await?;
        }
        Some(("reduce-reserves", sub_m)) => {
            reduce_reserves(&client, &base_url, sub_m).await?;
        }
        Some(("remove-reserves", sub_m)) => {
            remove_reserves(&client, &base_url, sub_m).await?;
        }
        Some(("add-collateral-partner", sub_m)) => {
            add_collateral_partner(&client, &base_url, sub_m).await?;
        }
        Some(("remove-collateral-partner", sub_m)) => {
            remove_collateral_partner(&client, &base_url, sub_m).await?;
        }
        Some(("status", sub_m)) => {
            // Use node arg if provided, otherwise use original alias (before resolution)
            let node_name = sub_m.get_one::<String>("node")
                .map(|s| s.to_string())
                .unwrap_or_else(|| port_or_alias.clone());
            let resolved_port = resolve_port(&node_name);
            let node_url = format!("https://localhost:{}", resolved_port);
            show_status(&client, &node_url, &node_name).await?;
        }
        Some(("info", _)) => {
            show_info(&client, &base_url).await?;
        }
        _ => {
            eprintln!("No subcommand provided. Use --help for usage information.");
            std::process::exit(1);
        }
    }

    Ok(())
}

async fn add_ledger(client: &Client, base_url: &str, matches: &ArgMatches) -> Result<(), Box<dyn Error>> {
    let partner_input = matches.get_one::<String>("partner").unwrap();

    // Resolve alias to node ID if needed
    let partner_pubkey = resolve_node_id(client, partner_input).await?;

    println!("🔄 Adding ledger with partner {}...", partner_pubkey);

    let request = InitLedgerRequest {
        partner_node_id: partner_pubkey.clone(),
        ledger_address: String::new(), // Auto-generated by handler
    };

    let response: InitLedgerResponse = proto_request(
        client,
        base_url,
        endpoints::DEPOSITS_INIT_LEDGER_PATH,
        request,
    ).await?;

    println!("✅ Ledger added successfully!");
    println!("Ledger ID: {}", response.ledger_id);

    Ok(())
}

async fn remove_ledger(client: &Client, base_url: &str, matches: &ArgMatches) -> Result<(), Box<dyn Error>> {
    let partner_input = matches.get_one::<String>("partner").unwrap();

    // Resolve alias to node ID if needed
    let partner_pubkey = resolve_node_id(client, partner_input).await?;

    println!("🗑️  Removing ledger with partner {}...", partner_pubkey);

    let request = CloseLedgerRequest {
        ledger_id: partner_pubkey,
    };

    let _response: CloseLedgerResponse = proto_request(
        client,
        base_url,
        endpoints::DEPOSITS_CLOSE_LEDGER_PATH,
        request,
    ).await?;

    println!("✅ Ledger removed successfully!");

    Ok(())
}

async fn list_ledgers(client: &Client, base_url: &str) -> Result<(), Box<dyn Error>> {
    log::info!("📋 Fetching ledgers...");

    let request = ListLedgersRequest {};

    let response: ListLedgersResponse = proto_request(
        client,
        base_url,
        endpoints::DEPOSITS_LIST_LEDGERS_PATH,
        request,
    ).await?;

    if response.ledgers.is_empty() {
        println!("No ledgers found.");
    } else {
        println!("Ledgers ({}):", response.ledgers.len());
        for ledger in &response.ledgers {
            println!("  Ledger: {}", ledger.ledger_id);
            println!("    Operator: {}", ledger.operator_node_id);
            println!("    Partner:  {}", ledger.partner_node_id);
            println!("    Balances: operator={} sat, partner={} sat",
                ledger.operator_balance_sat, ledger.partner_balance_sat);
            println!("    Reserves: {} sat", ledger.reserves_sat);
            println!("    Deposits: {}", ledger.deposit_count);
            println!("    Sequence: {}", ledger.sequence_number);
            println!();
        }
    }

    Ok(())
}

async fn list_orphans(_client: &Client, _base_url: &str) -> Result<(), Box<dyn Error>> {
    // TODO: Add proto support for orphans endpoint
    eprintln!("❌ list-orphans not yet implemented with proto API");
    std::process::exit(1);
}

async fn list_deposits(client: &Client, base_url: &str, partner: Option<&str>) -> Result<(), Box<dyn Error>> {
    let request = ListDepositsRequest {
        ledger_id: partner.map(|s| s.to_string()),
    };

    if partner.is_some() {
        log::info!("📋 Fetching deposits for partner {}...", partner.unwrap());
    } else {
        log::info!("📋 Fetching all deposits...");
    }

    let response: ListDepositsResponse = proto_request(
        client,
        base_url,
        endpoints::DEPOSITS_LIST_DEPOSITS_PATH,
        request,
    ).await?;

    if response.deposits.is_empty() {
        println!("No deposits found.");
    } else {
        println!("Deposits ({}):", response.deposits.len());
        for deposit in &response.deposits {
            println!("  Deposit: {}", deposit.deposit_pubkey);
            println!("    Ledger: {}", deposit.ledger_id);
            println!("    Balance: {} msat", deposit.balance_msat);
            println!("    Locked:  {} msat", deposit.locked_balance_msat);
            println!();
        }
    }

    Ok(())
}

async fn deposit_balance(client: &Client, base_url: &str, deposit_pubkey: &str) -> Result<(), Box<dyn Error>> {
    // List all deposits and find the one matching the pubkey
    let request = ListDepositsRequest { ledger_id: None };
    let response: ListDepositsResponse = proto_request(
        client,
        base_url,
        endpoints::DEPOSITS_LIST_DEPOSITS_PATH,
        request,
    ).await?;

    for deposit in &response.deposits {
        if deposit.deposit_pubkey == deposit_pubkey {
            // Output just the balance in msat (for easy script parsing)
            println!("{}", deposit.balance_msat);
            return Ok(());
        }
    }

    // Deposit not found - output 0
    println!("0");
    Ok(())
}

async fn deposit_nwc(client: &Client, base_url: &str, deposit_pubkey: &str) -> Result<(), Box<dyn Error>> {
    let request = GetDepositNwcRequest {
        deposit_pubkey: deposit_pubkey.to_string(),
    };
    let response: GetDepositNwcResponse = proto_request(
        client,
        base_url,
        endpoints::DEPOSITS_DEPOSIT_NWC_PATH,
        request,
    ).await?;

    // Output JSON for wallet file creation
    let wallet_json = serde_json::json!({
        "nwc_pubkey": response.nwc_pubkey,
        "nwc_secret": response.nwc_secret,
        "relay_url": response.relay_url,
        "connection_string": response.connection_string,
        "deposit_pubkey": deposit_pubkey
    });
    println!("{}", serde_json::to_string_pretty(&wallet_json)?);
    Ok(())
}

async fn get_updates(client: &Client, base_url: &str, partner: Option<&str>) -> Result<(), Box<dyn Error>> {
    // If no partner specified, list ledgers first to get all partner IDs
    if partner.is_none() {
        log::info!("📋 Fetching all ledger updates...");
        let list_req = ListLedgersRequest {};
        let ledgers: ListLedgersResponse = proto_request(
            client,
            base_url,
            endpoints::DEPOSITS_LIST_LEDGERS_PATH,
            list_req,
        ).await?;

        for ledger in &ledgers.ledgers {
            println!("Updates for ledger {}:", ledger.ledger_id);
            let request = GetLedgerUpdatesRequest {
                ledger_id: ledger.ledger_id.clone(),
                from_sequence: None,
                limit: None,
            };
            let response: GetLedgerUpdatesResponse = proto_request(
                client,
                base_url,
                endpoints::DEPOSITS_GET_LEDGER_UPDATES_PATH,
                request,
            ).await?;
            print_updates(&response);
        }
        return Ok(());
    }

    let partner_pubkey = partner.unwrap();
    log::info!("📋 Fetching ledger updates for partner {}...", partner_pubkey);

    let request = GetLedgerUpdatesRequest {
        ledger_id: partner_pubkey.to_string(),
        from_sequence: None,
        limit: None,
    };

    let response: GetLedgerUpdatesResponse = proto_request(
        client,
        base_url,
        endpoints::DEPOSITS_GET_LEDGER_UPDATES_PATH,
        request,
    ).await?;

    print_updates(&response);
    Ok(())
}

fn print_updates(response: &GetLedgerUpdatesResponse) {
    if response.updates.is_empty() {
        println!("  No updates found.");
    } else {
        for update in &response.updates {
            // Format: "  $seq [$prev~$curr] ack count lock $operation  params..."
            // Count: 3 if acked (operator + partner + collateral), 1 if not
            let node_count = if update.acknowledged { 3 } else { 1 };
            let ack_indicator = if update.acknowledged { "✓" } else { "·" };
            let commit_indicator = if update.committed { "🔒" } else { "  " };

            // Hash transition (first 8 chars of each)
            let prev_hash = if update.previous_hash.len() >= 8 {
                &update.previous_hash[..8]
            } else {
                &update.previous_hash
            };
            let curr_hash = if update.current_hash.len() >= 8 {
                &update.current_hash[..8]
            } else {
                &update.current_hash
            };

            // Build params string
            let mut params = Vec::new();
            if let Some(amount) = update.amount_sat {
                params.push(format!("{} sat", amount));
            }
            if let Some(ref pk) = update.deposit_pubkey {
                let pk_short = if pk.len() >= 8 { &pk[..8] } else { pk };
                params.push(format!("pk:{}", pk_short));
            }
            if let Some(ref desc) = update.description {
                params.push(desc.clone());
            }
            let params_str = if params.is_empty() {
                String::new()
            } else {
                format!("  {}", params.join(" "))
            };

            println!("  {:>3} [{}~{}] {}{}{} {:<20}{}",
                update.sequence_number,
                prev_hash,
                curr_hash,
                ack_indicator,
                node_count,
                commit_indicator,
                update.operation_type,
                params_str);
        }
    }
    println!();
}

async fn add_deposit(client: &Client, base_url: &str, matches: &ArgMatches) -> Result<(), Box<dyn Error>> {
    let partner_input = matches.get_one::<String>("partner").unwrap();
    let deposit_pubkey = matches.get_one::<String>("deposit-pubkey").unwrap();
    let _channel_id = matches.get_one::<String>("channel-id").map(|s| s.as_str());
    let _amount = matches.get_one::<String>("amount").unwrap().parse::<u64>()?;

    // Resolve alias to node ID if needed
    let partner = resolve_node_id(client, partner_input).await?;

    log::info!("🔵 Adding deposit...");
    log::debug!("  Partner: {}", partner);
    log::debug!("  Deposit pubkey: {}", deposit_pubkey);

    let request = AddDepositRequest {
        partner_node_id: partner,
        deposit_pubkey: deposit_pubkey.clone(),
    };

    let response: AddDepositResponse = proto_request(
        client,
        base_url,
        endpoints::DEPOSITS_ADD_DEPOSIT_PATH,
        request,
    ).await?;

    println!("✅ Deposit added successfully:");
    println!("  Deposit pubkey: {}", response.deposit_pubkey);

    Ok(())
}

async fn remove_deposit(client: &Client, base_url: &str, matches: &ArgMatches) -> Result<(), Box<dyn Error>> {
    let partner_input = matches.get_one::<String>("partner").unwrap();
    let deposit_pubkey = matches.get_one::<String>("deposit-pubkey").unwrap();

    // Resolve alias to node ID if needed
    let partner = resolve_node_id(client, partner_input).await?;

    log::info!("🗑️  Removing deposit...");
    log::debug!("  Partner: {}", partner);
    log::debug!("  Deposit pubkey: {}", deposit_pubkey);

    let request = RemoveDepositRequest {
        ledger_id: partner,
        deposit_pubkey: deposit_pubkey.clone(),
    };

    let _response: RemoveDepositResponse = proto_request(
        client,
        base_url,
        endpoints::DEPOSITS_REMOVE_DEPOSIT_PATH,
        request,
    ).await?;

    println!("✅ Deposit removed successfully");

    Ok(())
}

async fn collect_fees(_client: &Client, _base_url: &str) -> Result<(), Box<dyn Error>> {
    // TODO: Add proto support for collect-fees endpoint
    eprintln!("❌ collect-fees not yet implemented with proto API");
    std::process::exit(1);
}

async fn add_reserves(client: &Client, base_url: &str, matches: &ArgMatches) -> Result<(), Box<dyn Error>> {
    let partner_input = matches.get_one::<String>("partner").unwrap();
    let amount_str = matches.get_one::<String>("amount").unwrap();
    let amount: u64 = amount_str.parse()?;

    // Resolve alias to node ID if needed
    let partner = resolve_node_id(client, partner_input).await?;

    println!("📈 Adding {} sats to reserves with partner {}...", amount, partner);

    let request = AddReservesRequest {
        partner_node_id: partner,
        amount_sat: amount,
    };

    let _response: AddReservesResponse = proto_request(
        client,
        base_url,
        endpoints::DEPOSITS_ADD_RESERVES_PATH,
        request,
    ).await?;

    println!("✅ Reserves added successfully (Taproot output with ledger hash committed)");

    Ok(())
}

async fn reduce_reserves(client: &Client, base_url: &str, matches: &ArgMatches) -> Result<(), Box<dyn Error>> {
    let partner_input = matches.get_one::<String>("partner").unwrap();
    let amount_str = matches.get_one::<String>("amount").unwrap();
    let amount: u64 = amount_str.parse()?;

    // Resolve alias to node ID if needed
    let partner = resolve_node_id(client, partner_input).await?;

    println!("📉 Reducing {} sats from reserves with partner {}...", amount, partner);

    let request = ReduceReservesRequest {
        partner_node_id: partner,
        amount_sat: amount,
    };

    let _response: ReduceReservesResponse = proto_request(
        client,
        base_url,
        endpoints::DEPOSITS_REDUCE_RESERVES_PATH,
        request,
    ).await?;

    println!("✅ Reserves reduced successfully");

    Ok(())
}

async fn remove_reserves(client: &Client, base_url: &str, matches: &ArgMatches) -> Result<(), Box<dyn Error>> {
    let partner_input = matches.get_one::<String>("partner").unwrap();

    // Resolve alias to node ID if needed
    let partner_id = resolve_node_id(client, partner_input).await?;

    println!("🗑️  Removing reserves output from ledger with {}...", partner_id);

    let request = RemoveReservesRequest {
        partner_node_id: partner_id.clone(),
    };

    let _response: RemoveReservesResponse = proto_request(
        client,
        base_url,
        endpoints::DEPOSITS_REMOVE_RESERVES_PATH,
        request,
    ).await?;

    println!("✅ Reserves output removed successfully");

    Ok(())
}

async fn add_collateral_partner(client: &Client, base_url: &str, matches: &ArgMatches) -> Result<(), Box<dyn Error>> {
    let partner_input = matches.get_one::<String>("partner").unwrap();
    let collateral_input = matches.get_one::<String>("collateral-partner").unwrap();

    // Resolve aliases to node IDs if needed
    let partner_id = resolve_node_id(client, partner_input).await?;
    let collateral_partner_id = resolve_node_id(client, collateral_input).await?;

    println!("🔗 Adding collateral partner {} to ledger with {}...", collateral_partner_id, partner_id);

    let request = AddCollateralPartnerRequest {
        partner_node_id: partner_id.clone(),
        collateral_partner_id: collateral_partner_id.clone(),
    };

    let _response: AddCollateralPartnerResponse = proto_request(
        client,
        base_url,
        endpoints::DEPOSITS_ADD_COLLATERAL_PARTNER_PATH,
        request,
    ).await?;

    println!("✅ Collateral partner added successfully!");

    Ok(())
}

async fn remove_collateral_partner(client: &Client, base_url: &str, matches: &ArgMatches) -> Result<(), Box<dyn Error>> {
    let partner_input = matches.get_one::<String>("partner").unwrap();
    let collateral_input = matches.get_one::<String>("collateral-partner").unwrap();

    // Resolve aliases to node IDs if needed
    let partner_id = resolve_node_id(client, partner_input).await?;
    let collateral_partner_id = resolve_node_id(client, collateral_input).await?;

    println!("🔗 Removing collateral partner {} from ledger with {}...", collateral_partner_id, partner_id);

    let request = RemoveCollateralPartnerRequest {
        partner_node_id: partner_id.clone(),
        collateral_partner_id: collateral_partner_id.clone(),
    };

    let _response: RemoveCollateralPartnerResponse = proto_request(
        client,
        base_url,
        endpoints::DEPOSITS_REMOVE_COLLATERAL_PARTNER_PATH,
        request,
    ).await?;

    println!("✅ Collateral partner removed successfully!");

    Ok(())
}

async fn complete_dynamic(client: &Client, base_url: &str, comp_type: &str) -> Result<(), Box<dyn Error>> {
    // Dynamic completion - queries the node for real data
    match comp_type {
        "aliases" => {
            // List available node aliases
            println!("alice");
            println!("bob");
            println!("charlie");
            println!("diana");
            println!("eve");
            println!("frank");
            println!("grace");
        }
        "partners" => {
            // Get all ledgers and extract partner pubkeys
            let request = ListLedgersRequest {};
            if let Ok(response) = proto_request::<_, ListLedgersResponse>(
                client,
                base_url,
                endpoints::DEPOSITS_LIST_LEDGERS_PATH,
                request,
            ).await {
                for ledger in &response.ledgers {
                    println!("{}", ledger.partner_node_id);
                }
            }
        }
        "deposits" => {
            // Get all deposits
            let request = ListDepositsRequest { ledger_id: None };
            if let Ok(response) = proto_request::<_, ListDepositsResponse>(
                client,
                base_url,
                endpoints::DEPOSITS_LIST_DEPOSITS_PATH,
                request,
            ).await {
                for deposit in &response.deposits {
                    println!("{}", deposit.deposit_pubkey);
                }
            }
        }
        "channels" => {
            // Get all channels via info endpoint (JSON - not a deposits endpoint)
            if let Ok(resp) = client.get(&format!("{}/info", base_url)).send().await {
                if let Ok(info) = resp.json::<Value>().await {
                    if let Some(channels) = info["channels"].as_array() {
                        for channel in channels {
                            if let Some(channel_id) = channel["channel_id"].as_str() {
                                println!("{}", channel_id);
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }

    Ok(())
}

async fn show_status(client: &Client, base_url: &str, node_name: &str) -> Result<(), Box<dyn Error>> {
    println!("📡 {}", node_name);
    println!("{}", "=".repeat(60));

    // Get node info
    let info_response = client.get(&format!("{}/info", base_url)).send().await;

    let (node_id, num_channels, num_peers) = match info_response {
        Ok(resp) => {
            if let Ok(info) = resp.json::<Value>().await {
                let data = &info["data"];
                let id = data["node_id"].as_str().map(|s| s.to_string());
                let ch = data["num_channels"].as_u64().unwrap_or(0);
                let pr = data["num_peers"].as_u64().unwrap_or(0);
                (id, ch, pr)
            } else {
                (None, 0, 0)
            }
        }
        Err(e) => {
            println!("❌ Unable to connect: {}", e);
            return Ok(());
        }
    };

    // Build node name lookup table (node_id -> name)
    let node_names = build_node_name_map(client).await;

    // Get balance
    let balance = if let Ok(resp) = client.get(&format!("{}/bitcoin/balance", base_url)).send().await {
        if let Ok(bal) = resp.json::<Value>().await {
            bal["data"]["total_sat"].as_u64().unwrap_or(0)
        } else { 0 }
    } else { 0 };

    // Get NWC/Nostr info
    let (nwc_pubkey, relay_url) = if let Ok(resp) = client.get(&format!("{}/nwc/pubkey", base_url)).send().await {
        if let Ok(result) = resp.json::<ApiResponse<Value>>().await {
            if result.success {
                if let Some(data) = result.data {
                    let pk = data["nwc_pubkey"].as_str().map(|s| s.to_string());
                    let relay = data["relay_url"].as_str().map(|s| s.to_string());
                    (pk, relay)
                } else { (None, None) }
            } else { (None, None) }
        } else { (None, None) }
    } else { (None, None) };

    // Print node ID
    if let Some(ref id) = node_id {
        println!("Node: {}", id);
    }

    // Dense line: peers, channels, balance
    println!("Peers: {}  Channels: {}  Balance: {} sat", num_peers, num_channels, balance);

    // Dense line: relay info
    if let Some(relay) = relay_url {
        let short_relay = if relay.len() > 40 { &relay[..40] } else { &relay };
        if let Some(pk) = nwc_pubkey {
            println!("Relay: {}  NWC: {}...", short_relay, &pk[..16]);
        } else {
            println!("Relay: {}", short_relay);
        }
    }

    // Get channels and ledgers - show one line per channel
    let mut channel_peers: Vec<String> = Vec::new();

    let request = ListLedgersRequest {};
    if let Ok(response) = proto_request::<_, ListLedgersResponse>(
        client,
        base_url,
        endpoints::DEPOSITS_LIST_LEDGERS_PATH,
        request,
    ).await {
        if !response.ledgers.is_empty() {
            println!("Channels:");
        }
        // Deduplicate by channel_id - each channel has two ledgers
        let mut seen_channels: std::collections::HashSet<String> = std::collections::HashSet::new();

        for ledger in &response.ledgers {
            let channel_id = &ledger.channel_id;

            // Skip if we've already shown this channel
            if seen_channels.contains(channel_id) {
                continue;
            }
            seen_channels.insert(channel_id.clone());

            let partner = &ledger.partner_node_id;
            let operator = &ledger.operator_node_id;
            let status = &ledger.status;
            let operator_sat = ledger.operator_balance_sat;
            let partner_sat = ledger.partner_balance_sat;
            let reserves = ledger.reserves_sat;
            let capacity = ledger.capacity_sat;

            // Show the counterparty (the other node in the relationship)
            let counterparty = if node_id.as_ref().map(|id| id == operator).unwrap_or(false) {
                partner
            } else {
                operator
            };
            channel_peers.push(counterparty.to_string());

            // Local/remote depends on perspective
            let (to_local, to_remote) = if node_id.as_ref().map(|id| id == operator).unwrap_or(false) {
                (operator_sat, partner_sat)
            } else {
                (partner_sat, operator_sat)
            };

            let status_char = if status == "active" { "✓" } else { "…" };
            let local_hash = &ledger.local_ledger_hash;
            let remote_hash = &ledger.remote_ledger_hash;

            // Multi-line format with ledger hashes
            let peer_display = format_node_id(counterparty, &node_names);
            println!("  {} {} Capacity: {}", peer_display, status_char, capacity);
            println!("    to_local: {:>5}  reserves: {:>5}  ledger_hash: {}",
                to_local, reserves, local_hash);
            println!("    to_remote:{:>5}                   ledger_hash: {}",
                to_remote, remote_hash);
        }
    }

    // Show non-channel peers if any
    if num_peers > channel_peers.len() as u64 {
        let non_channel_peers = num_peers - channel_peers.len() as u64;
        println!("Other peers: {}", non_channel_peers);
    }

    Ok(())
}

async fn show_info(client: &Client, base_url: &str) -> Result<(), Box<dyn Error>> {
    let response = client.get(&format!("{}/info", base_url)).send().await?;
    let info: Value = response.json().await?;
    
    println!("{}", serde_json::to_string_pretty(&info)?);
    
    Ok(())
}
