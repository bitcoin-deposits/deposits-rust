//! Nostr CLI commands
//!
//! Commands for interacting with Nostr relays for ledger operations.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::OnceLock;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use bitcoin::secp256k1::{Keypair, PublicKey, Secp256k1, SecretKey};
use nostr_sdk::prelude::*;
use tokio::sync::Mutex;

use deposits_core::messages::LedgerOperation;
use deposits_core::tlv::TlvDecode;
use deposits_core::validation::LedgerExport;
use deposits_core::SignedLedgerUpdate;

use crate::nostr::{
    NostrTransportBuilder, KIND_LEDGER_DISPUTE, KIND_LEDGER_REQUEST, KIND_LEDGER_RESPONSE,
    KIND_LEDGER_UPDATE, KIND_RECOVERY_AGREE,
};
use crate::Node;

use super::common::{derive_operator_secret, parse_config};
use super::handlers;

/// Cached nostr client for CLI commands
static NOSTR_CLIENT: OnceLock<Mutex<Option<(String, Client)>>> = OnceLock::new();

/// Get or create a connected nostr client for the given relay URL
async fn get_or_create_client(relay_url: &str) -> Result<Client, Box<dyn std::error::Error>> {
    let mutex = NOSTR_CLIENT.get_or_init(|| Mutex::new(None));
    let mut guard = mutex.lock().await;

    // Check if we have a cached client for this relay
    if let Some((cached_url, client)) = guard.as_ref() {
        if cached_url == relay_url {
            return Ok(client.clone());
        }
    }

    // Create new client
    let keys = Keys::generate();
    let client = Client::new(keys);
    client.add_relay(relay_url).await
        .map_err(|e| format!("Failed to add relay: {}", e))?;
    client.connect().await;

    // Cache it
    *guard = Some((relay_url.to_string(), client.clone()));

    Ok(client)
}

/// Handle nostr subcommands
pub async fn nostr_command(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.is_empty() {
        eprintln!("Usage: deposits-bdk nostr <list|events|export|import|updates|validate|request|watch|dispute> [args...]");
        return Ok(());
    }

    match args[0].as_str() {
        "list" | "ls" => nostr_list(&args[1..]).await,
        "events" => nostr_events(&args[1..]).await,
        "export" => nostr_export(&args[1..]).await,
        "import" => nostr_import(&args[1..]).await,
        "updates" => nostr_updates(&args[1..]).await,
        "validate" => nostr_validate(&args[1..]).await,
        "request" | "req" => nostr_request(&args[1..]).await,
        "watch" => nostr_watch(&args[1..]).await,
        "dispute" => nostr_dispute(&args[1..]).await,
        cmd => {
            eprintln!("Unknown nostr subcommand: {}", cmd);
            eprintln!("Usage: deposits-bdk nostr <list|events|export|import|updates|validate|request|watch|dispute> [args...]");
            Ok(())
        }
    }
}

/// List all ledgers available on Nostr relay
pub async fn nostr_list(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let config = parse_config(args)?;

    // Get relay URL from config
    let relay_url = config
        .relays
        .first()
        .ok_or("No relay configured. Use --relay <url>")?;

    println!("Listing ledgers from Nostr relay...");
    println!("  Relay: {}", relay_url);
    println!();

    let client = get_or_create_client(relay_url).await?;

    // Fetch all ledger update events
    let filter = Filter::new().kind(Kind::Custom(KIND_LEDGER_UPDATE));

    let events = client
        .fetch_events(vec![filter], None)
        .await
        .map_err(|e| format!("Failed to fetch events: {}", e))?;

    client.disconnect().await.ok();

    if events.is_empty() {
        println!("No ledgers found.");
        return Ok(());
    }

    // Group by ledger_id and track max sequence
    let mut ledgers: HashMap<String, (u64, u64)> = HashMap::new(); // ledger_id -> (max_seq, count)

    for event in events {
        // Extract ledger_id from d tag
        let ledger_id = event.tags.iter().find_map(|tag| {
            if tag.kind() == TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::D)) {
                tag.content().map(|s| s.to_string())
            } else {
                None
            }
        });

        // Extract sequence from seq tag
        let sequence = event
            .tags
            .iter()
            .find_map(|tag| {
                if tag.kind() == TagKind::custom("seq") {
                    tag.content().and_then(|s| s.parse::<u64>().ok())
                } else {
                    None
                }
            })
            .unwrap_or(0);

        if let Some(lid) = ledger_id {
            let entry = ledgers.entry(lid).or_insert((0, 0));
            entry.0 = entry.0.max(sequence);
            entry.1 += 1;
        }
    }

    println!("Found {} ledger(s):", ledgers.len());
    println!();

    // Sort by ledger_id for consistent output
    let mut sorted: Vec<_> = ledgers.into_iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));

    for (ledger_id, (max_seq, count)) in sorted {
        println!("  {}", ledger_id);
        println!("    Updates: {} (seq 0..{})", count, max_seq);
        println!();
    }

    Ok(())
}

/// 16 ANSI colors for cycling through pubkeys
const PK_COLORS: &[&str] = &[
    "\x1b[38;5;196m", // red
    "\x1b[38;5;46m",  // green
    "\x1b[38;5;226m", // yellow
    "\x1b[38;5;21m",  // blue
    "\x1b[38;5;201m", // magenta
    "\x1b[38;5;51m",  // cyan
    "\x1b[38;5;208m", // orange
    "\x1b[38;5;129m", // purple
    "\x1b[38;5;118m", // lime
    "\x1b[38;5;213m", // pink
    "\x1b[38;5;87m",  // aqua
    "\x1b[38;5;220m", // gold
    "\x1b[38;5;99m",  // violet
    "\x1b[38;5;48m",  // sea green
    "\x1b[38;5;203m", // coral
    "\x1b[38;5;159m", // light blue
];
const RESET: &str = "\x1b[0m";

/// Get color for a pubkey, assigning new colors as needed
fn get_pk_color(
    pk: &str,
    color_map: &mut HashMap<String, usize>,
    color_by_pk: bool,
) -> &'static str {
    if !color_by_pk {
        return "";
    }
    let next_idx = color_map.len();
    let idx = *color_map.entry(pk.to_string()).or_insert(next_idx);
    PK_COLORS[idx % PK_COLORS.len()]
}

/// Show all deposits protocol events from Nostr relay
pub async fn nostr_events(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    // Parse --color-by-pk flag before passing to parse_config
    let mut color_by_pk = false;
    let mut config_args = Vec::new();

    for arg in args {
        if arg == "--color-by-pk" || arg == "--color" {
            color_by_pk = true;
        } else {
            config_args.push(arg.clone());
        }
    }

    let config = parse_config(&config_args)?;

    let relay_url = config
        .relays
        .first()
        .ok_or("No relay configured. Use --relay <url>")?;

    println!("Fetching all deposits events from Nostr relay...");
    println!("  Relay: {}", relay_url);
    if color_by_pk {
        println!("  Coloring by pubkey");
    }
    println!();

    let client = get_or_create_client(relay_url).await?;

    // Fetch all deposits protocol events
    let filter = Filter::new().kinds([
        Kind::Custom(KIND_LEDGER_UPDATE),
        Kind::Custom(KIND_LEDGER_REQUEST),
        Kind::Custom(KIND_LEDGER_RESPONSE),
        Kind::Custom(KIND_LEDGER_DISPUTE),
        Kind::Custom(KIND_RECOVERY_AGREE),
    ]);

    let events = client
        .fetch_events(vec![filter], None)
        .await
        .map_err(|e| format!("Failed to fetch events: {}", e))?;

    client.disconnect().await.ok();

    if events.is_empty() {
        println!("No events found.");
        return Ok(());
    }

    // Sort events by timestamp
    let mut events_vec: Vec<_> = events.into_iter().collect();
    events_vec.sort_by_key(|e| e.created_at);

    // Count by type
    let mut updates = 0usize;
    let mut requests = 0usize;
    let mut responses = 0usize;
    let mut disputes = 0usize;
    let mut agreements = 0usize;

    // Track pubkey -> color mapping
    let mut pk_colors: HashMap<String, usize> = HashMap::new();
    let reset = if color_by_pk { RESET } else { "" };

    println!("=== Events ({} total) ===", events_vec.len());
    println!();

    for event in &events_vec {
        let kind_num = event.kind.as_u16();
        let (kind_name, symbol) = match kind_num {
            k if k == KIND_LEDGER_UPDATE => {
                updates += 1;
                ("UPDATE", "U")
            }
            k if k == KIND_LEDGER_REQUEST => {
                requests += 1;
                ("REQUEST", "?")
            }
            k if k == KIND_LEDGER_RESPONSE => {
                responses += 1;
                ("RESPONSE", "R")
            }
            k if k == KIND_LEDGER_DISPUTE => {
                disputes += 1;
                ("DISPUTE", "!")
            }
            k if k == KIND_RECOVERY_AGREE => {
                agreements += 1;
                ("AGREE", "+")
            }
            _ => ("UNKNOWN", "?"),
        };

        // Extract d tag (ledger_id)
        let ledger_id = event
            .tags
            .iter()
            .find_map(|tag| {
                if tag.kind() == TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::D)) {
                    tag.content().map(|s| s.to_string())
                } else {
                    None
                }
            })
            .unwrap_or_else(|| "-".to_string());

        // Extract seq tag for updates
        let seq = event.tags.iter().find_map(|tag| {
            if tag.kind() == TagKind::custom("seq") {
                tag.content().and_then(|s| s.parse::<u64>().ok())
            } else {
                None
            }
        });

        let author = event.pubkey.to_string();
        let event_id = event.id.to_string();

        // Try to extract deposit_pubkey from request params for coloring
        let wallet_pk = if let Ok(json) = serde_json::from_str::<serde_json::Value>(&event.content) {
            json.get("params")
                .and_then(|p| p.get("deposit_pubkey"))
                .and_then(|pk| pk.as_str())
                .map(|s| s.to_string())
        } else {
            None
        };

        // Use wallet pk for coloring if available, otherwise fall back to author
        let color_key = wallet_pk.as_ref().unwrap_or(&author);
        let color = get_pk_color(color_key, &mut pk_colors, color_by_pk);

        // Format output based on type
        match kind_num {
            k if k == KIND_LEDGER_UPDATE => {
                let seq_str = seq.map(|s| format!("seq:{}", s)).unwrap_or_default();
                println!(
                    "{}{}{} {} {}...  ledger:{}...  {}",
                    color,
                    symbol,
                    reset,
                    kind_name,
                    &event_id[..12],
                    &ledger_id[..16.min(ledger_id.len())],
                    seq_str
                );
            }
            k if k == KIND_LEDGER_DISPUTE => {
                // Try to extract reason from content
                let reason =
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&event.content) {
                        json.get("reason")
                            .and_then(|r| r.as_str())
                            .unwrap_or("")
                            .to_string()
                    } else {
                        String::new()
                    };
                println!(
                    "{}{}{} {} {}...  ledger:{}...  from:{}{}{}...  {}",
                    color,
                    symbol,
                    reset,
                    kind_name,
                    &event_id[..12],
                    &ledger_id[..16.min(ledger_id.len())],
                    color,
                    &author[..12],
                    reset,
                    &reason[..40.min(reason.len())]
                );
            }
            k if k == KIND_RECOVERY_AGREE => {
                // Extract dispute reference
                let dispute_ref = event
                    .tags
                    .iter()
                    .find_map(|tag| {
                        if tag.kind()
                            == TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::E))
                        {
                            tag.content().map(|s| s.to_string())
                        } else {
                            None
                        }
                    })
                    .unwrap_or_else(|| "-".to_string());
                println!(
                    "{}{}{} {} {}...  dispute:{}...  from:{}{}{}...",
                    color,
                    symbol,
                    reset,
                    kind_name,
                    &event_id[..12],
                    &dispute_ref[..12.min(dispute_ref.len())],
                    color,
                    &author[..12],
                    reset
                );
            }
            k if k == KIND_LEDGER_REQUEST => {
                let req_type =
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&event.content) {
                        json.get("request_type")
                            .and_then(|r| r.as_str())
                            .unwrap_or("")
                            .to_string()
                    } else {
                        String::new()
                    };
                println!(
                    "{}{}{} {} {}...  ledger:{}...  from:{}{}{}...  type:{}",
                    color,
                    symbol,
                    reset,
                    kind_name,
                    &event_id[..12],
                    &ledger_id[..16.min(ledger_id.len())],
                    color,
                    &author[..12],
                    reset,
                    req_type
                );
            }
            k if k == KIND_LEDGER_RESPONSE => {
                println!(
                    "{}{}{} {} {}...  from:{}{}{}...",
                    color,
                    symbol,
                    reset,
                    kind_name,
                    &event_id[..12],
                    color,
                    &author[..12],
                    reset
                );
            }
            _ => {
                println!(
                    "{}{}{} {} {}...  from:{}{}{}...",
                    color,
                    symbol,
                    reset,
                    kind_name,
                    &event_id[..12],
                    color,
                    &author[..12],
                    reset
                );
            }
        }
    }

    println!();
    println!("=== Summary ===");
    println!("  Updates:    {}", updates);
    println!("  Requests:   {}", requests);
    println!("  Responses:  {}", responses);
    println!("  Disputes:   {}", disputes);
    println!("  Agreements: {}", agreements);

    // If color mode, show legend
    if color_by_pk && !pk_colors.is_empty() {
        println!();
        println!("=== Pubkey Legend ===");
        let mut sorted: Vec<_> = pk_colors.iter().collect();
        sorted.sort_by_key(|(_, idx)| *idx);
        for (pk, idx) in sorted {
            let color = PK_COLORS[*idx % PK_COLORS.len()];
            println!("  {}{}...{}", color, &pk[..16], RESET);
        }
    }

    Ok(())
}

/// Fetch ledger updates from Nostr relay (import)
pub async fn nostr_import(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut ledger_id: Option<String> = None;
    let mut config_args = Vec::new();
    let mut limit: usize = 500;
    let mut dry_run = false;
    let mut color_by_pk = false;

    let mut i = 0;
    while i < args.len() {
        if args[i] == "--limit" {
            i += 1;
            if i < args.len() {
                limit = args[i].parse().unwrap_or(500);
            }
        } else if args[i] == "--dry-run" {
            dry_run = true;
        } else if args[i] == "--color-by-pk" || args[i] == "--color" {
            color_by_pk = true;
        } else if args[i].starts_with("--") {
            config_args.push(args[i].clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
                i += 1;
            }
        } else if ledger_id.is_none() {
            ledger_id = Some(args[i].clone());
        }
        i += 1;
    }

    let config = parse_config(&config_args)?;

    // Get relay URL from config
    let relay_url = config
        .relays
        .first()
        .ok_or("No relay configured. Use --relay <url>")?;

    println!("Fetching ledger updates from Nostr...");
    println!("  Relay: {}", relay_url);
    if let Some(ref lid) = ledger_id {
        println!("  Ledger: {}", lid);
    }
    println!();

    let client = get_or_create_client(relay_url).await?;

    // Build filter
    let mut filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .limit(limit);

    if let Some(ref lid) = ledger_id {
        filter = filter.custom_tag(SingleLetterTag::lowercase(Alphabet::D), [lid.as_str()]);
    }

    // Fetch events
    let events = client
        .fetch_events(vec![filter], None)
        .await
        .map_err(|e| format!("Failed to fetch events: {}", e))?;

    client.disconnect().await.ok();

    if events.is_empty() {
        println!("No ledger updates found.");
        return Ok(());
    }

    // Group updates by ledger_id, sorted by sequence number
    let mut ledgers: BTreeMap<String, Vec<SignedLedgerUpdate>> = BTreeMap::new();

    for event in events {
        // Extract ledger_id from d tag
        let event_ledger_id = event
            .tags
            .iter()
            .find_map(|tag| {
                if tag.kind() == TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::D)) {
                    tag.content().map(|s| s.to_string())
                } else {
                    None
                }
            })
            .unwrap_or_else(|| "(unknown)".to_string());

        // Decode the update
        if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
            if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                ledgers.entry(event_ledger_id).or_default().push(update);
            }
        }
    }

    // Sort updates by sequence number but keep ALL updates (including branches)
    // Include operator_id in sort/dedup to preserve different operators' updates at same sequence
    // (e.g., parallel CustodyDisputes from different quorum members)
    for updates in ledgers.values_mut() {
        updates.sort_by_key(|u| (u.sequence_number, u.operator_id.serialize(), u.current_hash));
        // Deduplicate exact copies only (same seq, same operator, same hash)
        updates.dedup_by(|a, b| {
            a.sequence_number == b.sequence_number
                && a.operator_id == b.operator_id
                && a.current_hash == b.current_hash
        });
    }

    println!("Found {} ledger(s) with updates:", ledgers.len());

    // Create node for importing (unless dry-run)
    let node = if !dry_run {
        Some(Node::new(config).await?)
    } else {
        None
    };

    // Color map shared across all ledgers (so same pubkey gets same color)
    let mut pk_colors: HashMap<[u8; 33], usize> = HashMap::new();

    // Import each ledger
    for (lid, updates) in &ledgers {
        let short_id = &lid[..16.min(lid.len())];
        println!();
        println!("=== Ledger {}... ({} updates) ===", short_id, updates.len());

        if updates.is_empty() {
            println!("  (no updates to import)");
            continue;
        }

        // Find LedgerOpen operation to get metadata
        let ledger_open = updates.iter().find_map(|u| {
            if let Ok(op) = LedgerOperation::tlv_decode(&u.message) {
                if let LedgerOperation::LedgerOpen {
                    operator_id,
                    reserves_id,
                    ledger_address,
                    genesis_block,
                    ..
                } = op
                {
                    return Some((operator_id, reserves_id, ledger_address, genesis_block));
                }
            }
            None
        });

        let (operator_id, reserves_id, ledger_address, genesis_block) = match ledger_open {
            Some(data) => data,
            None => {
                println!("  ERROR: No LedgerOpen found - cannot import");
                continue;
            }
        };

        // Parse ledger_id from hex
        let ledger_id_bytes: [u8; 32] = match hex::decode(lid) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                arr
            }
            _ => {
                println!("  ERROR: Invalid ledger_id hex");
                continue;
            }
        };

        println!("  Operator: {}...", &operator_id.to_string()[..16]);
        println!(
            "  Reserves: {}...",
            &reserves_id[..16.min(reserves_id.len())]
        );
        println!("  Genesis: block {}", genesis_block);

        // Get current block height
        let block_height = if let Some(ref n) = node {
            n.wallet.get_block_height().unwrap_or(0)
        } else {
            0
        };

        // Create LedgerExport
        let export = LedgerExport::new(
            ledger_id_bytes,
            genesis_block,
            operator_id,
            reserves_id.clone(),
            ledger_address.clone(),
            updates.clone(),
            block_height,
        );

        if dry_run {
            println!("  (dry-run: would import {} updates)", updates.len());

            // Build tree structure: map from previous_hash to children
            let mut children: HashMap<[u8; 32], Vec<&SignedLedgerUpdate>> = HashMap::new();
            for update in updates {
                children.entry(update.previous_hash).or_default().push(update);
            }

            // Sort children by sequence number, then by operator
            for kids in children.values_mut() {
                kids.sort_by_key(|u| (u.sequence_number, u.operator_id.serialize()));
            }

            // Colors for colorized output (by wallet pk or operator)
            // Muted/calm palette - easier on the eyes
            let colors: &[&str] = &[
                "\x1b[38;5;131m", // muted red
                "\x1b[38;5;108m", // muted green
                "\x1b[38;5;179m", // muted gold
                "\x1b[38;5;67m",  // muted blue
                "\x1b[38;5;139m", // muted purple
                "\x1b[38;5;73m",  // muted cyan
                "\x1b[38;5;173m", // muted orange
                "\x1b[38;5;107m", // olive
                "\x1b[38;5;103m", // muted lavender
                "\x1b[38;5;66m",  // teal
                "\x1b[38;5;137m", // tan
                "\x1b[38;5;96m",  // plum
                "\x1b[38;5;72m",  // sea green
                "\x1b[38;5;138m", // dusty rose
                "\x1b[38;5;109m", // sage
            ];
            let reset = if color_by_pk { "\x1b[0m" } else { "" };
            // Make invalid updates REALLY obvious: bold + reverse video + bright red + blink
            let invalid_style = "\x1b[1;5;7;91m";
            let invalid_reset = "\x1b[0m"; // Always reset after invalid style

            // Helper to extract deposit_pubkey from an operation
            fn get_deposit_pubkey(op: &LedgerOperation) -> Option<[u8; 33]> {
                match op {
                    LedgerOperation::DepositOpen { pubkey, .. } => Some(pubkey.serialize()),
                    LedgerOperation::DepositClose { pubkey, .. } => Some(pubkey.serialize()),
                    LedgerOperation::CollateralLock { deposit_pubkey, .. } => Some(deposit_pubkey.serialize()),
                    LedgerOperation::OnchainCredit { deposit_pubkey, .. } => Some(deposit_pubkey.serialize()),
                    LedgerOperation::OnchainLock { deposit_pubkey, .. } => Some(deposit_pubkey.serialize()),
                    LedgerOperation::OnchainFail { deposit_pubkey, .. } => Some(deposit_pubkey.serialize()),
                    LedgerOperation::OnchainFulfill { deposit_pubkey, .. } => Some(deposit_pubkey.serialize()),
                    LedgerOperation::InvoiceCredit { deposit_pubkey, .. } => Some(deposit_pubkey.serialize()),
                    LedgerOperation::InvoiceLock { pubkey, .. } => Some(pubkey.serialize()),
                    LedgerOperation::InvoiceFail { pubkey, .. } => Some(pubkey.serialize()),
                    LedgerOperation::InvoiceFulfill { pubkey, .. } => Some(pubkey.serialize()),
                    _ => None,
                }
            }

            // Helper to get color key for an update (wallet pk or operator)
            fn get_color_key(update: &SignedLedgerUpdate) -> [u8; 33] {
                if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                    if let Some(wallet_pk) = get_deposit_pubkey(&op) {
                        return wallet_pk;
                    }
                }
                // Fall back to operator
                update.operator_id.serialize()
            }

            // Collect invalid update hashes from CustodyDispute reasons (which now contain the hash)
            // Also collect the actual invalid updates for display
            let mut invalid_hashes: HashSet<[u8; 32]> = HashSet::new();
            let mut invalid_updates: Vec<&SignedLedgerUpdate> = Vec::new();
            for update in updates {
                // Build color map (shared across ledgers)
                if color_by_pk {
                    let key = get_color_key(update);
                    let next_idx = pk_colors.len();
                    pk_colors.entry(key).or_insert(next_idx);
                }
                // Check if this is a CustodyDispute and extract the invalid hash from reason
                if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                    if let LedgerOperation::CustodyDispute { reason, .. } = op {
                        // The reason is now the invalid update's hash (64 hex chars)
                        if reason.len() == 64 {
                            if let Ok(hash_bytes) = hex::decode(&reason) {
                                if hash_bytes.len() == 32 {
                                    let mut hash: [u8; 32] = [0u8; 32];
                                    hash.copy_from_slice(&hash_bytes);
                                    invalid_hashes.insert(hash);
                                }
                            }
                        }
                    }
                }
            }

            // Find the actual invalid updates (those whose current_hash matches an invalid hash)
            // Also find the branch point hash (last valid hash before the invalid update)
            let mut branch_point_hash: Option<[u8; 32]> = None;
            for update in updates {
                if invalid_hashes.contains(&update.current_hash) {
                    invalid_updates.push(update);
                    // Find the branch point: the update at sequence - 1
                    if update.sequence_number > 0 {
                        for prev_update in updates {
                            if prev_update.sequence_number == update.sequence_number - 1 {
                                branch_point_hash = Some(prev_update.current_hash);
                                break;
                            }
                        }
                    }
                }
            }

            // Inject invalid updates at the branch point so they appear in the tree (with blinking!)
            if let Some(branch_hash) = branch_point_hash {
                for invalid_update in &invalid_updates {
                    children.entry(branch_hash).or_default().push(invalid_update);
                }
                // Re-sort that branch's children
                if let Some(kids) = children.get_mut(&branch_hash) {
                    kids.sort_by_key(|u| (u.sequence_number, u.operator_id.serialize()));
                }
            }

            // Calculate chain depth (number of descendants) for sorting branches
            // Longer chains (surviving branches) should appear last
            fn get_chain_depth(
                children: &HashMap<[u8; 32], Vec<&SignedLedgerUpdate>>,
                hash: [u8; 32],
                operator: PublicKey,
            ) -> usize {
                if let Some(kids) = children.get(&hash) {
                    // Find children that continue this operator's chain
                    let mut max_depth = 0;
                    for child in kids {
                        let is_cd = if let Ok(op) = LedgerOperation::tlv_decode(&child.message) {
                            matches!(op, LedgerOperation::CustodyDispute { .. })
                        } else {
                            false
                        };
                        // Follow same operator's chain (CustodyDispute can branch but we track by operator)
                        if child.operator_id == operator || is_cd {
                            let depth =
                                1 + get_chain_depth(children, child.current_hash, child.operator_id);
                            max_depth = max_depth.max(depth);
                        }
                    }
                    max_depth
                } else {
                    0
                }
            }

            // Print tree recursively with operator continuity tracking
            // parent_operator: None for genesis, Some(op) for subsequent nodes
            // Only show children that:
            // 1. Are CustodyDispute (can branch from any operator), or
            // 2. Have same operator_id as parent (operator continuity)
            // Branches are sorted by chain depth (ascending) so surviving chain comes last
            fn print_tree(
                children: &HashMap<[u8; 32], Vec<&SignedLedgerUpdate>>,
                parent_hash: [u8; 32],
                parent_operator: Option<PublicKey>,
                prefix: &str,
                is_branch: bool,
                pk_colors: &HashMap<[u8; 33], usize>,
                colors: &[&str],
                color_by_pk: bool,
                invalid_hashes: &HashSet<[u8; 32]>,
                invalid_style: &str,
                invalid_reset: &str,
                reset: &str,
            ) {
                if let Some(kids) = children.get(&parent_hash) {
                    // Filter children based on operator continuity rules
                    let mut filtered_kids: Vec<&&SignedLedgerUpdate> = kids
                        .iter()
                        .filter(|update| {
                            // Check if this is a CustodyDispute operation
                            let is_custody_dispute =
                                if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                                    matches!(op, LedgerOperation::CustodyDispute { .. })
                                } else {
                                    false
                                };

                            // Also show invalid updates (so they can blink)
                            let is_invalid = invalid_hashes.contains(&update.current_hash);

                            // CustodyDispute can branch from anyone
                            // Invalid updates should be shown (with blinking)
                            // Other operations must continue from same operator (or be first op from genesis)
                            is_custody_dispute
                                || is_invalid
                                || parent_operator.is_none()
                                || parent_operator == Some(update.operator_id)
                        })
                        .collect();

                    // Sort: invalid updates first (blinking), then by chain depth (ascending)
                    // so invalid updates are visible and surviving chains come last
                    filtered_kids.sort_by_key(|update| {
                        let is_invalid = invalid_hashes.contains(&update.current_hash);
                        let depth = get_chain_depth(children, update.current_hash, update.operator_id);
                        // Invalid updates get priority 0, others get their depth + 1000
                        if is_invalid {
                            0
                        } else {
                            depth + 1000
                        }
                    });

                    for (i, update) in filtered_kids.iter().enumerate() {
                        let is_last = i == filtered_kids.len() - 1;
                        let seq = update.sequence_number;
                        let prev = &update.previous_hash;
                        let curr = &update.current_hash;

                        // Determine signature status and signer
                        let has_partner_sig = update.partner_signature != [0u8; 64];
                        let has_operator_sig = update.operator_signature != [0u8; 64];
                        let sig_status = format!(
                            "[{}{}]",
                            if has_operator_sig { "O" } else { "." },
                            if has_partner_sig { "P" } else { "." }
                        );

                        let signer = if has_operator_sig {
                            let pk = update.operator_id.serialize();
                            format!("{:02x}{:02x}", pk[1], pk[2])
                        } else {
                            "....".to_string()
                        };

                        let (op_name, op_details) =
                            format_operation(update.message_type, &update.message);

                        // Tree characters for branches
                        let branch_char = if is_branch {
                            if is_last {
                                "+-"
                            } else {
                                "|-"
                            }
                        } else {
                            "  "
                        };

                        // Get color for this update (by wallet pk or operator), add blink if invalid
                        let color_key = get_color_key(update);
                        let color = if color_by_pk {
                            pk_colors.get(&color_key)
                                .map(|idx| colors[idx % colors.len()])
                                .unwrap_or("")
                        } else {
                            ""
                        };
                        let is_invalid = invalid_hashes.contains(&update.current_hash);
                        let style_start = if is_invalid {
                            format!("{}{}", invalid_style, color)
                        } else {
                            color.to_string()
                        };
                        // Always reset after invalid style to stop blinking
                        let style_end = if is_invalid { invalid_reset } else { reset };

                        println!(
                            "{}{}{}{:>4} ^{:<6} [{:02x}{:02x}~{:02x}{:02x}] {} {} {}{}{}",
                            style_start,
                            prefix,
                            branch_char,
                            seq,
                            update.block_height,
                            prev[30],
                            prev[31],
                            curr[30],
                            curr[31],
                            sig_status,
                            signer,
                            op_name,
                            if op_details.is_empty() {
                                String::new()
                            } else {
                                format!("  {}", op_details)
                            },
                            style_end
                        );

                        // Check how many children this update has (considering operator continuity)
                        let child_count = if let Some(child_kids) = children.get(&update.current_hash) {
                            child_kids
                                .iter()
                                .filter(|c| {
                                    let is_cd =
                                        if let Ok(op) = LedgerOperation::tlv_decode(&c.message) {
                                            matches!(op, LedgerOperation::CustodyDispute { .. })
                                        } else {
                                            false
                                        };
                                    is_cd || c.operator_id == update.operator_id
                                })
                                .count()
                        } else {
                            0
                        };

                        // Build prefix for children
                        let new_prefix = if is_branch {
                            format!("{}{}", prefix, if is_last { "  " } else { "| " })
                        } else {
                            prefix.to_string()
                        };

                        // Print children - mark as branch if there are multiple children at same level
                        let has_multiple_children = child_count > 1;
                        print_tree(
                            children,
                            update.current_hash,
                            Some(update.operator_id),
                            &new_prefix,
                            has_multiple_children,
                            pk_colors,
                            colors,
                            color_by_pk,
                            invalid_hashes,
                            invalid_style,
                            invalid_reset,
                            reset,
                        );
                    }
                }
            }

            // Start from genesis (previous_hash = [0; 32], no parent operator)
            print_tree(
                &children,
                [0u8; 32],
                None,
                "",
                false,
                &pk_colors,
                colors,
                color_by_pk,
                &invalid_hashes,
                invalid_style,
                invalid_reset,
                reset,
            );
        } else if let Some(ref n) = node {
            // Import the ledger
            match n.import_ledger(export) {
                Ok((report, _ledger)) => {
                    println!("  Imported successfully!");
                    println!(
                        "    Hash chain: {} of {} updates valid",
                        report.hash_chain.valid_length, report.hash_chain.total_length
                    );
                    println!(
                        "    Signatures: {} fully signed, {} operator-only",
                        report.signatures.fully_signed, report.signatures.operator_only
                    );
                    if !report.signatures.invalid_signatures.is_empty() {
                        println!(
                            "    Invalid signatures: {}",
                            report.signatures.invalid_signatures.len()
                        );
                    }
                }
                Err(e) => {
                    println!("  ERROR importing: {}", e);
                }
            }
        }
    }

    println!();
    if dry_run {
        println!("Dry run complete. Use without --dry-run to actually import.");
    } else {
        println!("Import complete.");
    }

    Ok(())
}

/// Fetch new updates for an existing ledger from Nostr
pub async fn nostr_updates(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut ledger_id: Option<String> = None;
    let mut config_args = Vec::new();
    let mut limit: usize = 500;
    let mut dry_run = false;

    let mut i = 0;
    while i < args.len() {
        if args[i] == "--limit" {
            i += 1;
            if i < args.len() {
                limit = args[i].parse().unwrap_or(500);
            }
        } else if args[i] == "--dry-run" {
            dry_run = true;
        } else if args[i].starts_with("--") {
            config_args.push(args[i].clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
                i += 1;
            }
        } else if ledger_id.is_none() {
            ledger_id = Some(args[i].clone());
        }
        i += 1;
    }

    let ledger_id = ledger_id.ok_or(
        "Usage: deposits-bdk nostr updates <ledger_id> [--dry-run] [--limit N]",
    )?;

    let config = parse_config(&config_args)?;

    // Get relay URL from config
    let relay_url = config
        .relays
        .first()
        .ok_or("No relay configured. Use --relay <url>")?;

    // Create node to access local ledger
    let node = Node::new(config.clone()).await?;

    // Find the local ledger
    let (reserves_id, local_ledger) = node.get_ledger_by_ledger_id(&ledger_id).ok_or_else(|| {
        format!(
            "Ledger {} not found locally. Use 'nostr import' first.",
            &ledger_id[..16.min(ledger_id.len())]
        )
    })?;

    let local_seq = local_ledger.sequence();
    let local_hash = local_ledger.tail_hash();

    println!("Fetching updates for ledger from Nostr...");
    println!(
        "  Ledger: {}...",
        &ledger_id[..16.min(ledger_id.len())]
    );
    println!(
        "  Reserves: {}...",
        &reserves_id[..16.min(reserves_id.len())]
    );
    println!("  Local sequence: {}", local_seq);
    println!("  Local hash: {}...", hex::encode(&local_hash[..8]));
    println!("  Relay: {}", relay_url);
    println!();

    let client = get_or_create_client(relay_url).await?;

    // Build filter for this ledger
    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .custom_tag(
            SingleLetterTag::lowercase(Alphabet::D),
            [ledger_id.as_str()],
        )
        .limit(limit);

    // Fetch events
    let events = client
        .fetch_events(vec![filter], None)
        .await
        .map_err(|e| format!("Failed to fetch events: {}", e))?;

    client.disconnect().await.ok();

    if events.is_empty() {
        println!("No updates found on Nostr.");
        return Ok(());
    }

    // Decode and sort updates
    let mut updates: Vec<SignedLedgerUpdate> = Vec::new();
    for event in events {
        if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
            if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                updates.push(update);
            }
        }
    }

    updates.sort_by_key(|u| u.sequence_number);

    println!(
        "Found {} updates on Nostr (local has {} updates)",
        updates.len(),
        local_seq + 1
    );

    // Find updates that follow our local chain
    let mut new_updates: Vec<SignedLedgerUpdate> = Vec::new();
    let mut expected_prev_hash = local_hash;

    for update in updates.iter() {
        // Skip updates we already have
        if update.sequence_number <= local_seq {
            continue;
        }

        // Check if this update follows our chain
        if update.previous_hash == expected_prev_hash {
            expected_prev_hash = update.current_hash;
            new_updates.push(update.clone());
        }
    }

    if new_updates.is_empty() {
        println!("No new updates to apply (already up to date).");
        return Ok(());
    }

    println!("Found {} new updates to apply:", new_updates.len());
    for update in &new_updates {
        let (op_name, _) = format_operation(update.message_type, &update.message);
        println!("  {} {}", update.sequence_number, op_name);
    }

    if dry_run {
        println!();
        println!("Dry run complete. Use without --dry-run to apply updates.");
        return Ok(());
    }

    // Apply updates to ledger
    println!();
    println!("Applying updates...");

    let applied = node
        .handler
        .apply_updates_to_ledger(&reserves_id, new_updates.clone())?;

    println!("Applied {} updates.", applied);
    println!("New sequence: {}", local_seq + applied as u64);

    Ok(())
}

/// Validate a ledger directly from Nostr (fetch and validate hash chain)
pub async fn nostr_validate(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut ledger_id: Option<String> = None;
    let mut config_args = Vec::new();
    let mut limit: usize = 200;

    let mut i = 0;
    while i < args.len() {
        if args[i] == "--limit" {
            i += 1;
            if i < args.len() {
                limit = args[i].parse().unwrap_or(200);
            }
        } else if args[i].starts_with("--") {
            config_args.push(args[i].clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
                i += 1;
            }
        } else if ledger_id.is_none() {
            ledger_id = Some(args[i].clone());
        }
        i += 1;
    }

    let ledger_id = ledger_id.ok_or("Ledger ID required (64-char hex hash)")?;
    let config = parse_config(&config_args)?;

    let relay_url = config
        .relays
        .first()
        .ok_or("No relay configured. Use --relay <url>")?;

    println!("Validating ledger from Nostr...");
    println!("  Relay: {}", relay_url);
    println!("  Ledger ID: {}", ledger_id);
    println!();

    let client = get_or_create_client(relay_url).await?;

    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .custom_tag(
            SingleLetterTag::lowercase(Alphabet::D),
            [ledger_id.as_str()],
        )
        .limit(limit);

    let events = client
        .fetch_events(vec![filter], None)
        .await
        .map_err(|e| format!("Failed to fetch events: {}", e))?;

    client.disconnect().await.ok();

    if events.is_empty() {
        println!("No ledger updates found on Nostr.");
        return Ok(());
    }

    // Decode all updates
    let mut updates: Vec<SignedLedgerUpdate> = Vec::new();
    for event in events.iter() {
        if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
            if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                updates.push(update);
            }
        }
    }

    if updates.is_empty() {
        println!("No valid updates could be decoded.");
        return Ok(());
    }

    // Sort by sequence number and deduplicate (relay may have duplicates)
    // Include operator_id to preserve different operators' updates at same sequence (e.g., parallel CustodyDisputes)
    updates.sort_by_key(|u| (u.sequence_number, u.operator_id));
    updates.dedup_by(|a, b| {
        a.sequence_number == b.sequence_number
            && a.operator_id == b.operator_id
            && a.current_hash == b.current_hash
    });

    println!("Found {} update(s), validating hash chain...", updates.len());
    println!();

    // Validate hash chain
    let mut valid = true;
    let mut expected_prev_hash = [0u8; 32];
    let mut last_valid_seq: i64 = -1;
    let mut errors: Vec<String> = Vec::new();

    for update in &updates {
        // Check sequence continuity
        if update.sequence_number != (last_valid_seq + 1) as u64 {
            if last_valid_seq >= 0 {
                let err = format!(
                    "Sequence gap: expected {}, got {}",
                    last_valid_seq + 1,
                    update.sequence_number
                );
                errors.push(err.clone());
                println!("  [FAIL] seq={}: {}", update.sequence_number, err);
                valid = false;
            }
        }

        // Check previous hash linkage
        if update.previous_hash != expected_prev_hash {
            let err = format!(
                "Hash chain broken: prev_hash {}... != expected {}...",
                &hex::encode(update.previous_hash)[..8],
                &hex::encode(expected_prev_hash)[..8]
            );
            errors.push(err.clone());
            println!("  [FAIL] seq={}: {}", update.sequence_number, err);
            valid = false;
        }

        // Verify the update's own hash
        let computed_hash = update.compute_hash();
        if computed_hash != update.current_hash {
            let err = format!(
                "Hash mismatch: computed {}... != stored {}...",
                &hex::encode(computed_hash)[..8],
                &hex::encode(update.current_hash)[..8]
            );
            errors.push(err.clone());
            println!("  [FAIL] seq={}: {}", update.sequence_number, err);
            valid = false;
        }

        // Update for next iteration
        expected_prev_hash = update.current_hash;
        last_valid_seq = update.sequence_number as i64;
    }

    println!();
    if valid {
        println!("Valid: YES");
        println!("  Updates: {}", updates.len());
        println!("  Sequence: 0..{}", last_valid_seq);
        println!(
            "  Tail hash: {}...",
            &hex::encode(expected_prev_hash)[..16]
        );
    } else {
        println!("Valid: NO");
        println!("  Updates: {}", updates.len());
        println!("  Errors: {}", errors.len());
        for err in &errors {
            println!("    - {}", err);
        }
    }

    Ok(())
}

/// Publish or listen for ledger disputes on Nostr
pub async fn nostr_dispute(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.is_empty() {
        eprintln!("Usage: deposits-bdk nostr dispute <publish|listen> [args...]");
        eprintln!();
        eprintln!("  publish <ledger_id> <reason> <details> [--last-hash <hex>] [--last-seq <n>] [--violation-seq <n>]");
        eprintln!("          Publish a dispute for a non-conforming ledger");
        eprintln!();
        eprintln!("  listen [--ledger <ledger_id>]");
        eprintln!("          Listen for disputes (all or specific ledger)");
        return Ok(());
    }

    match args[0].as_str() {
        "publish" | "pub" => {
            // Parse arguments
            let mut ledger_id: Option<String> = None;
            let mut reason: Option<String> = None;
            let mut details: Option<String> = None;
            let mut last_hash: [u8; 32] = [0u8; 32];
            let mut last_seq: u64 = 0;
            let mut violation_seq: Option<u64> = None;
            let mut config_args = Vec::new();

            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--last-hash" => {
                        i += 1;
                        if i < args.len() {
                            let bytes =
                                hex::decode(&args[i]).map_err(|_| "Invalid hex for --last-hash")?;
                            if bytes.len() == 32 {
                                last_hash.copy_from_slice(&bytes);
                            }
                        }
                    }
                    "--last-seq" => {
                        i += 1;
                        if i < args.len() {
                            last_seq = args[i].parse().unwrap_or(0);
                        }
                    }
                    "--violation-seq" => {
                        i += 1;
                        if i < args.len() {
                            violation_seq = Some(args[i].parse().unwrap_or(0));
                        }
                    }
                    s if s.starts_with("--") => {
                        config_args.push(args[i].clone());
                        if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                            config_args.push(args[i + 1].clone());
                            i += 1;
                        }
                    }
                    _ => {
                        if ledger_id.is_none() {
                            ledger_id = Some(args[i].clone());
                        } else if reason.is_none() {
                            reason = Some(args[i].clone());
                        } else if details.is_none() {
                            details = Some(args[i].clone());
                        }
                    }
                }
                i += 1;
            }

            let ledger_id = ledger_id.ok_or("Ledger ID required")?;
            let reason = reason.ok_or("Reason required (e.g., hash_chain_broken)")?;
            let details = details.unwrap_or_else(|| "Validation failed".to_string());
            let config = parse_config(&config_args)?;

            let relay_url = config
                .relays
                .first()
                .ok_or("No relay configured. Use --relay <url>")?
                .clone();

            // Build keypair from seed
            let secp = Secp256k1::new();
            let secret_key =
                SecretKey::from_slice(&config.seed).map_err(|e| format!("Invalid seed: {}", e))?;
            let keypair = Keypair::from_secret_key(&secp, &secret_key);

            println!("Publishing dispute...");
            println!("  Relay: {}", relay_url);
            println!("  Ledger: {}", ledger_id);
            println!("  Reason: {}", reason);
            println!("  Details: {}", details);
            println!();

            // Create transport and publish
            let transport = NostrTransportBuilder::new(secret_key)
                .relay(&relay_url)
                .build()
                .await?;

            let event_id = transport
                .publish_dispute(
                    &ledger_id,
                    &reason,
                    &details,
                    last_hash,
                    last_seq,
                    violation_seq,
                    &keypair,
                )
                .await?;

            println!("Dispute published: {}", event_id);
            transport.disconnect().await;
        }
        "listen" => {
            let mut ledger_id: Option<String> = None;
            let mut config_args = Vec::new();

            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--ledger" | "-l" => {
                        i += 1;
                        if i < args.len() {
                            ledger_id = Some(args[i].clone());
                        }
                    }
                    s if s.starts_with("--") => {
                        config_args.push(args[i].clone());
                        if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                            config_args.push(args[i + 1].clone());
                            i += 1;
                        }
                    }
                    _ => {
                        if ledger_id.is_none() {
                            ledger_id = Some(args[i].clone());
                        }
                    }
                }
                i += 1;
            }

            let config = parse_config(&config_args)?;
            let relay_url = config
                .relays
                .first()
                .ok_or("No relay configured. Use --relay <url>")?
                .clone();

            println!("Listening for disputes...");
            println!("  Relay: {}", relay_url);
            if let Some(ref lid) = ledger_id {
                println!("  Ledger: {}", lid);
            } else {
                println!("  Ledger: (all)");
            }
            println!();

            let client = get_or_create_client(&relay_url).await?;

            // Build filter
            let mut filter = Filter::new().kind(Kind::Custom(KIND_LEDGER_DISPUTE));
            if let Some(ref lid) = ledger_id {
                filter = filter.custom_tag(SingleLetterTag::lowercase(Alphabet::L), [lid.as_str()]);
            }

            // Subscribe
            client
                .subscribe(vec![filter], None)
                .await
                .map_err(|e| format!("Failed to subscribe: {}", e))?;

            println!("Subscribed to dispute events. Press Ctrl+C to stop.\n");

            // Listen for events
            loop {
                let timeout = std::time::Duration::from_secs(30);
                match tokio::time::timeout(timeout, client.notifications().recv()).await {
                    Ok(Ok(RelayPoolNotification::Event { event, .. })) => {
                        if event.kind.as_u16() == KIND_LEDGER_DISPUTE {
                            println!("=== DISPUTE RECEIVED ===");
                            println!("  Event: {}", event.id.to_hex());
                            println!("  Time: {}", event.created_at);

                            // Extract tags
                            for tag in event.tags.iter() {
                                if tag.kind()
                                    == TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::L))
                                {
                                    if let Some(v) = tag.content() {
                                        println!("  Ledger: {}", v);
                                    }
                                }
                                if tag.kind() == TagKind::custom("reason") {
                                    if let Some(v) = tag.content() {
                                        println!("  Reason: {}", v);
                                    }
                                }
                                if tag.kind() == TagKind::custom("disputer") {
                                    if let Some(v) = tag.content() {
                                        println!("  Disputer: {}...", &v[..32.min(v.len())]);
                                    }
                                }
                            }

                            // Parse content for details
                            if let Ok(dispute) =
                                serde_json::from_str::<serde_json::Value>(&event.content)
                            {
                                if let Some(details) =
                                    dispute.get("details").and_then(|v| v.as_str())
                                {
                                    println!("  Details: {}", details);
                                }
                                if let Some(last_seq) =
                                    dispute.get("last_valid_sequence").and_then(|v| v.as_u64())
                                {
                                    println!("  Last valid seq: {}", last_seq);
                                }
                                if let Some(viol_seq) =
                                    dispute.get("violation_sequence").and_then(|v| v.as_u64())
                                {
                                    println!("  Violation seq: {}", viol_seq);
                                }
                            }
                            println!();
                        }
                    }
                    Ok(Ok(_)) => {
                        // Other notification types, ignore
                    }
                    Ok(Err(_)) => {
                        // Channel error
                        break;
                    }
                    Err(_) => {
                        // Timeout - keep waiting
                        print!(".");
                        use std::io::Write;
                        std::io::stdout().flush().ok();
                    }
                }
            }

            client.disconnect().await.ok();
        }
        cmd => {
            eprintln!("Unknown dispute subcommand: {}", cmd);
            eprintln!("Usage: deposits-bdk nostr dispute <publish|listen> [args...]");
        }
    }

    Ok(())
}

/// Broadcast ledger updates to Nostr relay (export)
pub async fn nostr_export(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut ledger_id: Option<String> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with("--") {
            config_args.push(args[i].clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
                i += 1;
            }
        } else if ledger_id.is_none() && !args[i].is_empty() {
            ledger_id = Some(args[i].clone());
        }
        i += 1;
    }

    let config = parse_config(&config_args)?;

    // Get relay URL before moving config
    let relay_url = config
        .relays
        .first()
        .ok_or("No relay configured. Use --relay <url>")?
        .clone();

    // Derive secret key from seed
    let secret_key = derive_operator_secret(&config.seed, config.network)?;

    // Get the node to access the ledger
    let node = Node::new(config).await?;

    // Collect ledgers to export
    let ledgers_to_export: Vec<(String, deposits_core::Ledger)> = match &ledger_id {
        Some(lid) if lid.contains(':') => {
            // Parse ledger_id as operator:reserves_id
            let parts: Vec<&str> = lid.splitn(2, ':').collect();
            let reserves_id = parts[1];

            let (_, ledger) = node
                .get_ledger_by_reserves_key(reserves_id)
                .ok_or_else(|| format!("Ledger not found: {}", reserves_id))?;
            vec![(lid.clone(), ledger)]
        }
        Some(lid) => {
            // Check if it's a 64-char hex hash (ledger_id)
            if lid.len() == 64 && lid.chars().all(|c| c.is_ascii_hexdigit()) {
                // Direct lookup by ledger_id
                if let Some(ledger_arc) = node.list_ledgers().get(lid.as_str()) {
                    let ledger = ledger_arc.read().unwrap().clone();
                    vec![(lid.clone(), ledger)]
                } else {
                    return Err(format!(
                        "Ledger not found by hash: {}. Try using reserves_key instead.",
                        lid
                    )
                    .into());
                }
            } else if let Some((ledger_id, ledger)) = node.get_ledger_by_reserves_key(lid) {
                // Might be a reserves_key
                vec![(ledger_id, ledger)]
            } else {
                return Err(format!(
                    "Ledger not found: {}. Use ledger_id hash or reserves_key",
                    lid
                )
                .into());
            }
        }
        None => {
            // Export all ledgers
            node.list_ledgers()
                .into_iter()
                .map(|(ledger_id, ledger_arc)| {
                    let ledger = ledger_arc.read().unwrap().clone();
                    (ledger_id, ledger)
                })
                .collect()
        }
    };

    if ledgers_to_export.is_empty() {
        println!("No ledgers to export.");
        return Ok(());
    }

    println!("Exporting ledger updates to Nostr relay...");
    println!("  Relay: {}", relay_url);
    println!("  Ledgers to export: {}", ledgers_to_export.len());
    println!();

    // Create nostr transport
    let transport = NostrTransportBuilder::new(secret_key)
        .relay(&relay_url)
        .build()
        .await?;

    let mut total_exported = 0;

    for (lid, ledger) in &ledgers_to_export {
        println!("Ledger: {}", lid);
        println!("  Updates: {}", ledger.history.len());

        // Broadcast each update
        for update in &ledger.history {
            let event_id = transport.broadcast_ledger_update(update).await?;
            println!(
                "    seq={} hash={}... event={}",
                update.sequence_number,
                &hex::encode(update.current_hash)[..16],
                &event_id[..16],
            );
            total_exported += 1;
        }
        println!();
    }

    transport.disconnect().await;

    println!(
        "Export complete! {} update(s) from {} ledger(s) published.",
        total_exported,
        ledgers_to_export.len()
    );

    Ok(())
}

/// Send a request to a ledger via Nostr
pub async fn nostr_request(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut ledger_id: Option<String> = None;
    let mut action: Option<String> = None;
    let mut params: Vec<String> = Vec::new();
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with("--") {
            config_args.push(args[i].clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
                i += 1;
            }
        } else if ledger_id.is_none() {
            ledger_id = Some(args[i].clone());
        } else if action.is_none() {
            action = Some(args[i].clone());
        } else {
            params.push(args[i].clone());
        }
        i += 1;
    }

    let ledger_id = ledger_id.ok_or("Ledger ID required")?;
    let action = action.ok_or("Action required (e.g., deposit_open)")?;

    let config = parse_config(&config_args)?;

    let relay_url = config
        .relays
        .first()
        .ok_or("No relay configured. Use --relay <url>")?
        .clone();

    let secret_key = derive_operator_secret(&config.seed, config.network)?;

    // Build params JSON based on action
    let params_json = match action.as_str() {
        "deposit_open" => {
            // params: deposit_pubkey [fee_fixed] [fee_bps] [fee_frequency]
            if params.is_empty() {
                return Err("deposit_open requires: <deposit_pubkey>".into());
            }
            let mut obj = serde_json::Map::new();
            obj.insert(
                "deposit_pubkey".to_string(),
                serde_json::Value::String(params[0].clone()),
            );
            if params.len() > 1 {
                obj.insert(
                    "fee_fixed".to_string(),
                    serde_json::json!(params[1].parse::<u64>().unwrap_or(0)),
                );
            }
            if params.len() > 2 {
                obj.insert(
                    "fee_bps".to_string(),
                    serde_json::json!(params[2].parse::<u64>().unwrap_or(0)),
                );
            }
            if params.len() > 3 {
                obj.insert(
                    "fee_frequency".to_string(),
                    serde_json::json!(params[3].parse::<u32>().unwrap_or(144)),
                );
            }
            serde_json::Value::Object(obj)
        }
        "make_offer" => {
            // params: deposit_pubkey max_sats min_sats blocks_valid [fee_bps] [fee_fixed] [fee_frequency]
            if params.len() < 4 {
                return Err("make_offer requires: <deposit_pubkey> <max_sats> <min_sats> <blocks_valid> [fee_bps] [fee_fixed] [fee_frequency]".into());
            }
            let mut obj = serde_json::Map::new();
            obj.insert(
                "deposit_pubkey".to_string(),
                serde_json::Value::String(params[0].clone()),
            );
            obj.insert(
                "max_sats".to_string(),
                serde_json::json!(params[1].parse::<u64>().unwrap_or(0)),
            );
            obj.insert(
                "min_sats".to_string(),
                serde_json::json!(params[2].parse::<u64>().unwrap_or(0)),
            );
            obj.insert(
                "blocks_valid".to_string(),
                serde_json::json!(params[3].parse::<u32>().unwrap_or(144)),
            );
            // Optional fee params
            if params.len() > 4 {
                obj.insert(
                    "fee_bps".to_string(),
                    serde_json::json!(params[4].parse::<u64>().unwrap_or(0)),
                );
            }
            if params.len() > 5 {
                obj.insert(
                    "fee_fixed".to_string(),
                    serde_json::json!(params[5].parse::<u64>().unwrap_or(0)),
                );
            }
            if params.len() > 6 {
                obj.insert(
                    "fee_frequency".to_string(),
                    serde_json::json!(params[6].parse::<u32>().unwrap_or(2016)),
                );
            }
            serde_json::Value::Object(obj)
        }
        "collateral_lock" => {
            // params: deposit_secret amount_msats lock_blocks [requesting_operator]
            if params.len() < 3 {
                return Err(
                    "collateral_lock requires: <deposit_secret> <amount_msats> <lock_blocks> [requesting_operator]".into(),
                );
            }
            let mut obj = serde_json::Map::new();
            obj.insert(
                "deposit_secret".to_string(),
                serde_json::Value::String(params[0].clone()),
            );
            obj.insert(
                "amount_msats".to_string(),
                serde_json::json!(params[1].parse::<u64>().unwrap_or(0)),
            );
            obj.insert(
                "lock_blocks".to_string(),
                serde_json::json!(params[2].parse::<u32>().unwrap_or(0)),
            );
            if params.len() > 3 {
                obj.insert(
                    "requesting_operator".to_string(),
                    serde_json::Value::String(params[3].clone()),
                );
            }
            serde_json::Value::Object(obj)
        }
        "deposit_withdraw" => {
            // params: deposit_secret destination_address amount_sats
            if params.len() < 3 {
                return Err(
                    "deposit_withdraw requires: <deposit_secret> <destination_address> <amount_sats>"
                        .into(),
                );
            }
            let mut obj = serde_json::Map::new();
            obj.insert(
                "deposit_secret".to_string(),
                serde_json::Value::String(params[0].clone()),
            );
            obj.insert(
                "destination_address".to_string(),
                serde_json::Value::String(params[1].clone()),
            );
            obj.insert(
                "amount_sats".to_string(),
                serde_json::json!(params[2].parse::<u64>().unwrap_or(0)),
            );
            serde_json::Value::Object(obj)
        }
        _ => {
            // Generic: treat params as key=value pairs or just values
            let mut obj = serde_json::Map::new();
            for (i, p) in params.iter().enumerate() {
                if let Some((k, v)) = p.split_once('=') {
                    obj.insert(k.to_string(), serde_json::Value::String(v.to_string()));
                } else {
                    obj.insert(format!("arg{}", i), serde_json::Value::String(p.clone()));
                }
            }
            serde_json::Value::Object(obj)
        }
    };

    println!("Sending ledger request via Nostr...");
    println!("  Relay: {}", relay_url);
    println!("  Ledger: {}", ledger_id);
    println!("  Action: {}", action);
    println!("  Params: {}", serde_json::to_string(&params_json)?);
    let transport = NostrTransportBuilder::new(secret_key)
        .relay(&relay_url)
        .build()
        .await?;

    // Subscribe to responses for this request
    let event_id = transport
        .send_ledger_request(&ledger_id, &action, params_json)
        .await?;

    println!("Request sent! Event ID: {}", event_id);
    println!();
    println!("Waiting for response...");

    // Subscribe to the response
    transport.subscribe_to_response(&event_id).await?;

    // Wait for response with timeout, using both subscription and polling
    let mut transport = transport;
    let timeout = tokio::time::Duration::from_secs(30);
    let start = std::time::Instant::now();
    let mut last_poll = std::time::Instant::now();
    let mut poll_count = 0;

    loop {
        if start.elapsed() > timeout {
            println!("Timeout waiting for response.");
            break;
        }

        // Process events from subscription
        tokio::select! {
            _ = transport.process_events() => {}
            _ = tokio::time::sleep(tokio::time::Duration::from_millis(100)) => {}
        }

        // Check for response from subscription
        if let Some(response) = transport.try_recv_response() {
            if response.request_id == event_id {
                println!();
                if response.success {
                    println!("Response: SUCCESS");
                    if let Some(result) = &response.result {
                        println!("Result: {}", serde_json::to_string_pretty(result)?);
                    }
                } else {
                    println!("Response: ERROR");
                    if let Some(error) = &response.error {
                        println!("Error: {}", error);
                    }
                }
                break;
            }
        }

        // Poll more frequently - every 500ms for first 5 polls, then every 2 seconds
        let poll_interval = if poll_count < 5 {
            std::time::Duration::from_millis(500)
        } else {
            std::time::Duration::from_secs(2)
        };

        if last_poll.elapsed() > poll_interval {
            tracing::debug!("Polling for response to request: {}", &event_id[..16]);
            match transport.fetch_response(&event_id).await {
                Ok(Some(response)) => {
                    println!();
                    if response.success {
                        println!("Response: SUCCESS");
                        if let Some(result) = &response.result {
                            println!("Result: {}", serde_json::to_string_pretty(result)?);
                        }
                    } else {
                        println!("Response: ERROR");
                        if let Some(error) = &response.error {
                            println!("Error: {}", error);
                        }
                    }
                    break;
                }
                Ok(None) => {
                    tracing::debug!(
                        "No response found for request: {} (poll #{})",
                        &event_id[..16],
                        poll_count
                    );
                }
                Err(e) => {
                    tracing::warn!("Error fetching response: {}", e);
                }
            }
            poll_count += 1;
            last_poll = std::time::Instant::now();
        }
    }

    transport.disconnect().await;
    Ok(())
}

/// Watch for requests to a ledger and process them
pub async fn nostr_watch(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use deposits_core::messages::consts::QUORUM_JOIN;

    let mut ledger_id: Option<String> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with("--") {
            config_args.push(args[i].clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
                i += 1;
            }
        } else if ledger_id.is_none() {
            ledger_id = Some(args[i].clone());
        }
        i += 1;
    }

    let config = parse_config(&config_args)?;

    let relay_url = config
        .relays
        .first()
        .ok_or("No relay configured. Use --relay <url>")?
        .clone();

    let secret_key = derive_operator_secret(&config.seed, config.network)?;

    // Clone config for later use (collateral_lock needs to reload node)
    let config_for_reload = config.clone();

    // Get the node to process requests
    let node = Node::new(config).await?;

    // Determine ledger_id - use from args or find our primary ledger
    // The ledger_id for Nostr events is the hex hash from ledger.ledger_id_hex()
    let ledgers = node.list_ledgers();
    println!("  Loaded {} ledger(s) from disk", ledgers.len());
    for (lid, ledger_arc) in ledgers.iter() {
        let ledger = ledger_arc.read().unwrap();
        println!("    - key={}..., state_id={}...",
            &lid[..16.min(lid.len())],
            &ledger.ledger_id_hex()[..16.min(ledger.ledger_id_hex().len())]);
    }

    let ledger_id = if let Some(lid) = ledger_id {
        // Arg provided - might be reserves address (bcrt1q...), hex prefix, or full hex
        println!("  Arg provided: {}", lid);

        // First, try to match by reserves_key (bcrt1q...)
        if lid.starts_with("bcrt1") || lid.starts_with("bc1") || lid.starts_with("tb1") {
            let found = ledgers
                .iter()
                .find(|(_lid, ledger_arc)| {
                    let ledger = ledger_arc.read().unwrap();
                    ledger.reserves_key() == lid || ledger.reserves_key().starts_with(&lid)
                });
            if let Some((_, ledger_arc)) = found {
                let ledger = ledger_arc.read().unwrap();
                println!("  Matched by reserves_key");
                ledger.ledger_id_hex()
            } else {
                return Err(format!("No ledger found with reserves: {}", lid).into());
            }
        } else {
            // Try to match by hex ledger_id prefix
            let found = ledgers.iter().find(|(_, ledger_arc)| {
                let ledger = ledger_arc.read().unwrap();
                ledger.ledger_id_hex().starts_with(&lid)
            });
            if let Some((_, ledger_arc)) = found {
                let ledger = ledger_arc.read().unwrap();
                let matched_id = ledger.ledger_id_hex();
                println!("  Matched to: {}", matched_id);
                matched_id
            } else {
                // Assume it's a full or partial ledger_id and use as-is
                println!("  No match found, using arg as-is");
                lid
            }
        }
    } else {
        // Find our primary ledger
        let ledgers = node.list_ledgers();
        if ledgers.is_empty() {
            return Err("No ledgers found. Specify a ledger ID or open a ledger first.".into());
        }
        let (ledger_id, ledger_arc) = ledgers.into_iter().next().unwrap();
        let ledger = ledger_arc.read().unwrap();
        ledger.ledger_id_hex()
    };

    // Helper to scan for joined ledgers from QuorumJoin operations
    // Returns set of reserves_id strings that we need to find hex ledger_ids for
    fn scan_joined_reserves(node: &Node) -> HashSet<String> {
        let mut joined = HashSet::new();
        let ledgers = node.list_ledgers();

        for (_ledger_id, ledger_arc) in ledgers.iter() {
            let ledger = ledger_arc.read().unwrap();

            // Scan history for QuorumJoin operations
            for update in &ledger.history {
                if update.message_type == QUORUM_JOIN {
                    if let Ok(LedgerOperation::QuorumJoin { reserves_id, .. }) =
                        LedgerOperation::tlv_decode(&update.message)
                    {
                        joined.insert(reserves_id);
                    }
                }
            }
        }
        joined
    }

    // Create transport early so we can use it for ad lookups
    let transport = NostrTransportBuilder::new(secret_key)
        .relay(&relay_url)
        .build()
        .await?;

    // Find hex ledger_ids for joined ledgers by matching reserves addresses from advertisements
    let joined_reserves = scan_joined_reserves(&node);
    let mut joined_ledger_ids: HashSet<String> = HashSet::new();

    if !joined_reserves.is_empty() {
        // Fetch all advertisements to find ledger_ids for joined reserves
        let network_str = match config_for_reload.network {
            bitcoin::Network::Bitcoin => "bitcoin",
            bitcoin::Network::Testnet => "testnet",
            bitcoin::Network::Signet => "signet",
            bitcoin::Network::Regtest => "regtest",
            _ => "regtest",
        };
        if let Ok(ads) = transport.fetch_ledger_advertisements(network_str).await {
            for ad in ads {
                // Check if this ad's reserves matches any of our joined reserves
                if joined_reserves.contains(&ad.reserves_address) && ad.ledger_id != ledger_id {
                    joined_ledger_ids.insert(ad.ledger_id.clone());
                }
            }
        }
    }

    println!("Watching for requests on ledger...");
    println!("  Relay: {}", relay_url);
    println!("  Ledger: {}", ledger_id);
    if !joined_ledger_ids.is_empty() {
        println!(
            "  Also joined {} other ledger(s):",
            joined_ledger_ids.len()
        );
        for jid in &joined_ledger_ids {
            println!("    - {}...", &jid[..40.min(jid.len())]);
        }
    }
    println!("  (Will dynamically discover new QuorumJoin ledgers)");
    println!();
    println!("Press Ctrl+C to stop.");
    println!();

    // Subscribe to requests for this ledger
    transport.subscribe_to_requests(&ledger_id).await?;

    // Also subscribe to disputes for this ledger
    transport.subscribe_to_disputes(&ledger_id).await?;

    // Subscribe to requests for all joined ledgers (for custody_transfer_sign)
    for joined_id in &joined_ledger_ids {
        transport.subscribe_to_requests(joined_id).await?;
        transport.subscribe_to_disputes(joined_id).await?;
    }

    let mut transport = transport;
    let mut last_poll = std::time::Instant::now();
    let mut last_join_scan = std::time::Instant::now();
    let mut last_auto_complete = std::time::Instant::now();
    let mut seen_events: HashSet<String> = HashSet::new();

    loop {
        // Process events from subscription
        if let Err(e) = transport.process_events().await {
            tracing::warn!("Error processing events: {}", e);
        }

        // Poll as fallback for missed subscription events
        // Use 1 second to balance responsiveness and relay load (subscriptions may not be reliable)
        if last_poll.elapsed() > std::time::Duration::from_secs(1) {
            if let Ok(requests) = transport.fetch_recent_requests(60).await {
                for request in requests {
                    // Queue requests for our ledger, joined ledgers, or cross-ledger signing requests
                    let is_our_ledger = request.ledger_id == ledger_id;
                    let is_joined_ledger = joined_ledger_ids.contains(&request.ledger_id);
                    let is_cross_ledger_sign = request.action == "custody_transfer_sign"
                        || request.action == "confiscation_sign";
                    let should_queue = is_our_ledger || is_joined_ledger || is_cross_ledger_sign;

                    if should_queue && !seen_events.contains(&request.event_id) {
                        if is_cross_ledger_sign && !is_our_ledger {
                            println!(
                                "[{}] Received {} for {}ledger: {}...",
                                chrono::Utc::now().format("%H:%M:%S"),
                                request.action,
                                if is_joined_ledger {
                                    "joined "
                                } else {
                                    "external "
                                },
                                &request.ledger_id[..16.min(request.ledger_id.len())]
                            );
                        }
                        // Log queued deposit_open for debugging
                        if request.action == "deposit_open" {
                            println!(
                                "[{}] Queued deposit_open for ledger: {}...",
                                chrono::Utc::now().format("%H:%M:%S"),
                                &request.ledger_id[..16.min(request.ledger_id.len())]
                            );
                        }
                        seen_events.insert(request.event_id.clone());
                        transport.queue_request(request);
                    } else if !should_queue && !seen_events.contains(&request.event_id) {
                        // Log filtered requests - use eprintln for visibility since tests run with RUST_LOG=error
                        if request.action == "deposit_open" || request.action == "collateral_lock" {
                            eprintln!(
                                "[WARN] Filtered {}: req_ledger={}..., our_ledger={}..., is_joined={}",
                                request.action,
                                &request.ledger_id[..16.min(request.ledger_id.len())],
                                &ledger_id[..16.min(ledger_id.len())],
                                is_joined_ledger
                            );
                        }
                    }
                }
            }
            last_poll = std::time::Instant::now();
        }

        // Periodically check for funded deposits to auto-complete (every 3 seconds)
        if last_auto_complete.elapsed() > std::time::Duration::from_secs(3) {
            // Reload node to get fresh data and sync wallet
            if let Ok(mut fresh_node) = Node::new(config_for_reload.clone()).await {
                // Sync wallet first to detect new transactions
                if let Err(e) = fresh_node.sync_wallet() {
                    tracing::debug!("Wallet sync error during auto-complete: {}", e);
                }
                // Check and complete any funded deposits
                fresh_node.auto_complete_deposits().await;
            }
            last_auto_complete = std::time::Instant::now();
        }

        // Periodically rescan for new QuorumJoin operations (every 30 seconds)
        if last_join_scan.elapsed() > std::time::Duration::from_secs(30) {
            // Reload node to get fresh data
            if let Ok(fresh_node) = Node::new(config_for_reload.clone()).await {
                let current_reserves = scan_joined_reserves(&fresh_node);

                // Find ledger IDs for any new reserves by looking up advertisements
                let network_str = match config_for_reload.network {
                    bitcoin::Network::Bitcoin => "bitcoin",
                    bitcoin::Network::Testnet => "testnet",
                    bitcoin::Network::Signet => "signet",
                    bitcoin::Network::Regtest => "regtest",
                    _ => "regtest",
                };
                if let Ok(ads) = transport.fetch_ledger_advertisements(network_str).await {
                    for ad in ads {
                        if current_reserves.contains(&ad.reserves_address)
                            && ad.ledger_id != ledger_id
                            && !joined_ledger_ids.contains(&ad.ledger_id)
                        {
                            println!(
                                "[{}] Discovered new QuorumJoin: {}...",
                                chrono::Utc::now().format("%H:%M:%S"),
                                &ad.ledger_id[..40.min(ad.ledger_id.len())]
                            );

                            if let Err(e) = transport.subscribe_to_requests(&ad.ledger_id).await {
                                tracing::warn!(
                                    "Failed to subscribe to {}: {}",
                                    ad.ledger_id,
                                    e
                                );
                            }
                            if let Err(e) = transport.subscribe_to_disputes(&ad.ledger_id).await {
                                tracing::warn!(
                                    "Failed to subscribe to disputes for {}: {}",
                                    ad.ledger_id,
                                    e
                                );
                            }

                            joined_ledger_ids.insert(ad.ledger_id.clone());
                        }
                    }
                }
            }
            last_join_scan = std::time::Instant::now();
        }

        // Check for requests
        while let Some(request) = transport.try_recv_request() {
            // Note: seen_events is already checked when queuing, so no need to check here
            // Requests in the queue have already been validated for relevance

            // Skip requests not for our ledger or joined ledgers (except cross-ledger signing)
            let is_our_ledger = request.ledger_id == ledger_id;
            let is_joined_ledger = joined_ledger_ids.contains(&request.ledger_id);
            let is_cross_ledger_sign =
                request.action == "custody_transfer_sign" || request.action == "confiscation_sign";

            // Operator-only actions: only the ledger operator should handle these
            let is_operator_only = matches!(
                request.action.as_str(),
                "deposit_open" | "make_offer" | "deposit_withdraw" | "collateral_lock"
            );

            // For operator-only actions, only process if this is our ledger
            // Quorum members should NOT respond to these (they don't have the ledger data)
            if is_operator_only && !is_our_ledger {
                tracing::debug!(
                    "Skipping operator-only request {} for different ledger: {} (ours: {})",
                    request.action,
                    request.ledger_id,
                    ledger_id
                );
                continue;
            }

            if !is_our_ledger && !is_joined_ledger && !is_cross_ledger_sign {
                tracing::debug!(
                    "Skipping request for different ledger: {} (ours: {})",
                    request.ledger_id,
                    ledger_id
                );
                continue;
            }

            println!(
                "[{}] Request: action={}",
                chrono::Utc::now().format("%H:%M:%S"),
                request.action
            );
            println!("  Event: {}", &request.event_id[..16]);
            println!("  Params: {}", request.params);

            // Reload the node to get fresh ledger state from disk
            // (the CLI may have updated the ledger concurrently)
            let mut fresh_node = match Node::new(config_for_reload.clone()).await {
                Ok(n) => n,
                Err(e) => {
                    let error_msg = format!("Failed to reload node: {}", e);
                    let _ = transport
                        .send_ledger_response(&request.event_id, &request.ledger_id, false, None, Some(error_msg.clone()))
                        .await;
                    println!("  Response: ERROR - {}", error_msg);
                    continue;
                }
            };

            // For operations that require custodianship, verify we have the ledger locally
            // The real protection against fraudulent offers is client-side verification:
            // - Client checks offer's funding_address matches ledger's current reserves
            // - Client verifies offer signature is from current custodian
            //
            // TODO: Add proper custody verification once CustodyTransfer operation exists
            let requires_ledger = matches!(
                request.action.as_str(),
                "deposit_open" | "make_offer" | "deposit_withdraw" | "collateral_lock"
            );

            if requires_ledger {
                // Just verify we have the ledger locally
                let has_ledger = fresh_node.get_ledger_by_ledger_id(&request.ledger_id).is_some()
                    || fresh_node.get_ledger_by_reserves_key(&request.ledger_id).is_some();

                if !has_ledger {
                    let error_msg = "Ledger not found locally".to_string();
                    let _ = transport
                        .send_ledger_response(
                            &request.event_id,
                            &request.ledger_id,
                            false,
                            None,
                            Some(error_msg.clone()),
                        )
                        .await;
                    println!("  Response: REJECTED - {}", error_msg);
                    continue;
                }
            }

            // Process the request
            let (success, result, error) = match request.action.as_str() {
                "deposit_open" => {
                    handlers::process_deposit_open_request(
                        &mut fresh_node,
                        &ledger_id,
                        &request,
                        &transport,
                    )
                    .await
                }
                "make_offer" => {
                    handlers::process_make_offer_request(
                        &fresh_node,
                        &ledger_id,
                        &request,
                        &transport,
                    )
                    .await
                }
                "deposit_withdraw" => {
                    handlers::process_deposit_withdraw_request(&mut fresh_node, &ledger_id, &request)
                        .await
                }
                "collateral_lock" => {
                    handlers::process_collateral_lock_request(&mut fresh_node, &ledger_id, &request)
                        .await
                }
                "custody_transfer_sign" => {
                    handlers::process_custody_transfer_sign_request(
                        &fresh_node,
                        &config_for_reload,
                        &request,
                    )
                    .await
                }
                "confiscation_sign" => {
                    handlers::process_confiscation_sign_request(
                        &fresh_node,
                        &config_for_reload,
                        &request,
                    )
                    .await
                }
                "custodian_query" => {
                    handlers::process_custodian_query_request(&fresh_node, &ledger_id, &request)
                        .await
                }
                "bump" => {
                    // Trigger immediate wallet sync and auto-completion
                    println!("  Bump requested - syncing wallet and checking deposits...");
                    if let Err(e) = fresh_node.sync_wallet() {
                        (false, None, Some(format!("Wallet sync failed: {}", e)))
                    } else {
                        fresh_node.auto_complete_deposits().await;
                        (
                            true,
                            Some(serde_json::json!({"message": "Wallet synced and deposits checked"})),
                            None,
                        )
                    }
                }
                _ => {
                    // Skip actions we don't handle - the daemon will respond
                    println!(
                        "  Skipping action '{}' - handled by daemon",
                        request.action
                    );
                    continue;
                }
            };

            // Send response - always use the request's ledger_id so requester receives it
            println!(
                "  Sending response for request: {}",
                &request.event_id[..16]
            );
            match transport
                .send_ledger_response(
                    &request.event_id,
                    &request.ledger_id,
                    success,
                    result.clone(),
                    error.clone(),
                )
                .await
            {
                Ok(resp_id) => {
                    if success {
                        println!(
                            "  Response: SUCCESS (resp_id={}, req_id={})",
                            &resp_id[..16],
                            &request.event_id[..16]
                        );
                    } else {
                        println!(
                            "  Response: ERROR - {} (resp_id={}, req_id={})",
                            error.unwrap_or_default(),
                            &resp_id[..16],
                            &request.event_id[..16]
                        );
                    }
                }
                Err(e) => {
                    println!("  Failed to send response: {}", e);
                }
            }
            println!();
        }

        // Check for disputes
        while let Some(dispute) = transport.try_recv_dispute() {
            println!("!!! DISPUTE RECEIVED !!!");
            println!("  Time: {}", chrono::Utc::now().format("%H:%M:%S"));
            println!(
                "  Event: {}",
                &dispute.event_id[..16.min(dispute.event_id.len())]
            );
            println!("  Ledger: {}", dispute.ledger_id);
            println!("  Reason: {}", dispute.reason);
            println!("  Details: {}", dispute.details);
            println!(
                "  Disputer: {}...",
                &dispute.disputer_pubkey[..32.min(dispute.disputer_pubkey.len())]
            );
            println!("  Last valid seq: {}", dispute.last_valid_sequence);
            if let Some(vs) = dispute.violation_sequence {
                println!("  Violation seq: {}", vs);
            }
            println!();
            println!("  ACTION REQUIRED: Validate ledger and participate in recovery voting.");
            println!();
        }
    }
}

/// Format a ledger operation for display
pub fn format_operation(msg_type: u16, message: &[u8]) -> (String, String) {
    // First try to decode the operation from message bytes - this gives us the actual operation
    if !message.is_empty() {
        if let Ok(op) = LedgerOperation::tlv_decode(message) {
            let (name, details) = match op {
                LedgerOperation::LedgerOpen {
                    ledger_address, ..
                } => {
                    let addr_short = if ledger_address.len() > 20 {
                        format!(
                            "{}..{}",
                            &ledger_address[..8],
                            &ledger_address[ledger_address.len() - 6..]
                        )
                    } else {
                        ledger_address.clone()
                    };
                    ("LedgerOpen", format!("addr:{}", addr_short))
                }
                LedgerOperation::ReservesIncrease { new_amount, .. } => {
                    ("ReservesIncrease", format!("{} sat", new_amount))
                }
                LedgerOperation::ReservesDecrease { new_amount, .. } => {
                    ("ReservesDecrease", format!("{} sat", new_amount))
                }
                LedgerOperation::ReservesRotate {
                    reserves_id,
                    amount,
                    quorum_threshold,
                    quorum_size,
                    first_expiry_block,
                    ..
                } => {
                    let addr_short = if reserves_id.len() > 20 {
                        format!(
                            "{}..{}",
                            &reserves_id[..8],
                            &reserves_id[reserves_id.len() - 6..]
                        )
                    } else {
                        reserves_id.clone()
                    };
                    (
                        "ReservesRotate",
                        format!(
                            "addr:{}  amt:{} sat  quorum:{}/{}  expiry:{}",
                            addr_short, amount, quorum_threshold, quorum_size, first_expiry_block
                        ),
                    )
                }
                LedgerOperation::DepositOpen { pubkey, .. } => {
                    let pk_bytes = pubkey.serialize();
                    (
                        "DepositOpen",
                        format!(
                            "pk:{:02x}{:02x}{:02x}{:02x}",
                            pk_bytes[0], pk_bytes[1], pk_bytes[2], pk_bytes[3]
                        ),
                    )
                }
                LedgerOperation::DepositClose { pubkey, .. } => {
                    let pk_bytes = pubkey.serialize();
                    (
                        "DepositClose",
                        format!(
                            "pk:{:02x}{:02x}{:02x}{:02x}",
                            pk_bytes[0], pk_bytes[1], pk_bytes[2], pk_bytes[3]
                        ),
                    )
                }
                LedgerOperation::DepositUpdate { pubkey, .. } => {
                    let pk_bytes = pubkey.serialize();
                    (
                        "DepositUpdate",
                        format!(
                            "pk:{:02x}{:02x}{:02x}{:02x}",
                            pk_bytes[0], pk_bytes[1], pk_bytes[2], pk_bytes[3]
                        ),
                    )
                }
                LedgerOperation::QuorumAddMember { quorum_member, .. } => {
                    let pk_bytes = quorum_member.serialize();
                    (
                        "QuorumAddMember",
                        format!(
                            "member:{:02x}{:02x}{:02x}{:02x}",
                            pk_bytes[0], pk_bytes[1], pk_bytes[2], pk_bytes[3]
                        ),
                    )
                }
                LedgerOperation::QuorumRemoveMember { quorum_member, .. } => {
                    let pk_bytes = quorum_member.serialize();
                    (
                        "QuorumRemoveMember",
                        format!(
                            "member:{:02x}{:02x}{:02x}{:02x}",
                            pk_bytes[0], pk_bytes[1], pk_bytes[2], pk_bytes[3]
                        ),
                    )
                }
                LedgerOperation::QuorumJoin {
                    operator_id,
                    reserves_id,
                    membership_expires,
                    ..
                } => {
                    let pk_bytes = operator_id.serialize();
                    let reserves_short = if reserves_id.len() > 16 {
                        format!(
                            "{}..{}",
                            &reserves_id[..8],
                            &reserves_id[reserves_id.len() - 6..]
                        )
                    } else {
                        reserves_id.clone()
                    };
                    (
                        "QuorumJoin",
                        format!(
                            "op:{:02x}{:02x}{:02x}{:02x}  ledger:{}  expires:{}",
                            pk_bytes[0], pk_bytes[1], pk_bytes[2], pk_bytes[3], reserves_short, membership_expires
                        ),
                    )
                }
                LedgerOperation::CollateralAttestation {
                    collateral_operator,
                    amount,
                    lock_until_block,
                    ..
                } => {
                    let pk_bytes = collateral_operator.serialize();
                    (
                        "CollateralAttestation",
                        format!(
                            "from:{:02x}{:02x}{:02x}{:02x}  amt:{} msat  until_block:{}",
                            pk_bytes[0], pk_bytes[1], pk_bytes[2], pk_bytes[3], amount, lock_until_block
                        ),
                    )
                }
                LedgerOperation::CollateralLock {
                    deposit_pubkey,
                    amount,
                    lock_until_block,
                    ..
                } => {
                    let pk_bytes = deposit_pubkey.serialize();
                    (
                        "CollateralLock",
                        format!(
                            "pk:{:02x}{:02x}{:02x}{:02x}  amt:{} msat  until_block:{}",
                            pk_bytes[0], pk_bytes[1], pk_bytes[2], pk_bytes[3], amount, lock_until_block
                        ),
                    )
                }
                LedgerOperation::CollateralIncrease { .. } => ("CollateralIncrease", String::new()),
                LedgerOperation::CollateralDecrease { .. } => ("CollateralDecrease", String::new()),
                LedgerOperation::OnchainCredit {
                    deposit_pubkey,
                    amount,
                    funding_address,
                    ..
                } => {
                    let pk_bytes = deposit_pubkey.serialize();
                    let addr_short = if funding_address.len() > 20 {
                        format!(
                            "{}..{}",
                            &funding_address[..8],
                            &funding_address[funding_address.len() - 6..]
                        )
                    } else {
                        funding_address.clone()
                    };
                    (
                        "OnchainCredit",
                        format!(
                            "pk:{:02x}{:02x}{:02x}{:02x}  amt:{} msat  addr:{}",
                            pk_bytes[0], pk_bytes[1], pk_bytes[2], pk_bytes[3], amount, addr_short
                        ),
                    )
                }
                LedgerOperation::OnchainLock {
                    deposit_pubkey,
                    amount,
                    destination_address,
                    withdrawal_id,
                    ..
                } => {
                    let pk_bytes = deposit_pubkey.serialize();
                    let addr_short = if destination_address.len() > 20 {
                        format!(
                            "{}..{}",
                            &destination_address[..8],
                            &destination_address[destination_address.len() - 6..]
                        )
                    } else {
                        destination_address.clone()
                    };
                    (
                        "OnchainLock",
                        format!(
                            "pk:{:02x}{:02x}{:02x}{:02x}  amt:{} msat  wdrl:{}  addr:{}",
                            pk_bytes[0],
                            pk_bytes[1],
                            pk_bytes[2],
                            pk_bytes[3],
                            amount,
                            hex::encode(&withdrawal_id[..4]),
                            addr_short
                        ),
                    )
                }
                LedgerOperation::OnchainFail {
                    deposit_pubkey,
                    withdrawal_id,
                    ..
                } => {
                    let pk_bytes = deposit_pubkey.serialize();
                    (
                        "OnchainFail",
                        format!(
                            "pk:{:02x}{:02x}{:02x}{:02x}  wdrl:{}",
                            pk_bytes[0],
                            pk_bytes[1],
                            pk_bytes[2],
                            pk_bytes[3],
                            hex::encode(&withdrawal_id[..4])
                        ),
                    )
                }
                LedgerOperation::OnchainFulfill {
                    deposit_pubkey,
                    withdrawal_id,
                    amount,
                    txid,
                    ..
                } => {
                    let pk_bytes = deposit_pubkey.serialize();
                    (
                        "OnchainFulfill",
                        format!(
                            "pk:{:02x}{:02x}{:02x}{:02x}  amt:{} msat  wdrl:{}  txn:{}",
                            pk_bytes[0],
                            pk_bytes[1],
                            pk_bytes[2],
                            pk_bytes[3],
                            amount,
                            hex::encode(&withdrawal_id[..4]),
                            hex::encode(&txid[..4])
                        ),
                    )
                }
                LedgerOperation::InvoiceCredit {
                    deposit_pubkey,
                    amount,
                    ..
                } => {
                    let pk_bytes = deposit_pubkey.serialize();
                    (
                        "InvoiceCredit",
                        format!(
                            "pk:{:02x}{:02x}{:02x}{:02x}  amt:{} msat",
                            pk_bytes[0], pk_bytes[1], pk_bytes[2], pk_bytes[3], amount
                        ),
                    )
                }
                LedgerOperation::InvoiceLock {
                    pubkey, amount, ..
                } => {
                    let pk_bytes = pubkey.serialize();
                    (
                        "InvoiceLock",
                        format!(
                            "pk:{:02x}{:02x}{:02x}{:02x}  amt:{} msat",
                            pk_bytes[0], pk_bytes[1], pk_bytes[2], pk_bytes[3], amount
                        ),
                    )
                }
                LedgerOperation::InvoiceFail { .. } => ("InvoiceFail", String::new()),
                LedgerOperation::InvoiceFulfill { .. } => ("InvoiceFulfill", String::new()),
                LedgerOperation::FeeCollect { .. } => ("FeeCollect", String::new()),
                LedgerOperation::CustodyDispute {
                    last_valid_sequence,
                    reason,
                } => (
                    "CustodyDispute",
                    format!("last_valid_seq:{}  reason:{}", last_valid_sequence, reason),
                ),
                LedgerOperation::CustodyArmed {
                    armed_block,
                    commitment_hash,
                    target_reserves,
                } => {
                    let hash_hex = hex::encode(commitment_hash);
                    let target_short = if target_reserves.len() > 16 {
                        format!(
                            "{}..{}",
                            &target_reserves[..8],
                            &target_reserves[target_reserves.len() - 6..]
                        )
                    } else {
                        target_reserves.clone()
                    };
                    (
                        "CustodyArmed",
                        format!(
                            "armed_block:{}  commit:{}..  target:{}",
                            armed_block,
                            &hash_hex[..8],
                            target_short
                        ),
                    )
                }
                LedgerOperation::CustodyAcquire {
                    new_custodian,
                    entropy_block_height,
                    spend_txid,
                    new_reserves_address,
                    ..
                } => {
                    let pk_bytes = new_custodian.serialize();
                    let txid_hex = hex::encode(spend_txid);
                    (
                        "CustodyAcquire",
                        format!(
                            "to:{:02x}{:02x}{:02x}{:02x}  entropy_block:{}  txid:{}..  reserves:{}..{}",
                            pk_bytes[0],
                            pk_bytes[1],
                            pk_bytes[2],
                            pk_bytes[3],
                            entropy_block_height,
                            &txid_hex[..8],
                            &new_reserves_address[..10.min(new_reserves_address.len())],
                            &new_reserves_address[new_reserves_address.len().saturating_sub(6)..]
                        ),
                    )
                }
                LedgerOperation::CustodyYield => ("CustodyYield", String::new()),
                LedgerOperation::LedgerClose => ("LedgerClose", String::new()),
                LedgerOperation::Tombstone { .. } => ("Tombstone", String::new()),
            };
            return (name.to_string(), details);
        }
    }

    // Fallback: couldn't decode operation, show message type
    (format!("Unknown(0x{:04X})", msg_type), String::new())
}
