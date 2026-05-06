use std::collections::HashSet;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use deposits_core::messages::LedgerOperation;
use deposits_core::tlv::TlvDecode;
use deposits_core::SignedLedgerUpdate;
use deposits_nostr::{ledger_tag, KIND_LEDGER_UPDATE, TAG_LEDGER_ID, TAG_SEQUENCE};
use nostr_sdk::prelude::*;

use super::{COLORS, RESET};

/// Relay's max events per request (strfry default)
const RELAY_PAGE_SIZE: usize = 500;

/// Fetch all events matching a filter using pagination.
async fn fetch_all_events_paginated(
    client: &Client,
    base_filter: Filter,
) -> Result<Vec<Event>, Box<dyn std::error::Error>> {
    let mut all_events = Vec::new();
    let mut until: Option<Timestamp> = None;
    let mut seen_ids: HashSet<EventId> = HashSet::new();
    let mut last_count = 0usize;
    let mut stall_count = 0usize;

    loop {
        let mut filter = base_filter.clone().limit(RELAY_PAGE_SIZE);
        if let Some(ts) = until {
            filter = filter.until(ts);
        }

        let events = client
            .fetch_events(vec![filter], None)
            .await
            .map_err(|e| format!("Failed to fetch events: {}", e))?;

        let batch_size = events.len();
        let mut oldest_ts: Option<Timestamp> = None;
        let mut new_events = 0usize;

        for event in events {
            if oldest_ts.is_none() || event.created_at < oldest_ts.unwrap() {
                oldest_ts = Some(event.created_at);
            }
            if seen_ids.insert(event.id) {
                all_events.push(event);
                new_events += 1;
            }
        }

        // Stop if we got fewer events than page size (end of data)
        if batch_size < RELAY_PAGE_SIZE {
            break;
        }

        // Stop if we're not making progress (no new events)
        if new_events == 0 {
            stall_count += 1;
            if stall_count > 3 {
                break; // Give up after 3 stalls
            }
        } else {
            stall_count = 0;
        }

        // Stop if total count hasn't changed (safety valve)
        if all_events.len() == last_count {
            break;
        }
        last_count = all_events.len();

        // Use the oldest timestamp for next page (don't subtract 1 - rely on dedup)
        if let Some(ts) = oldest_ts {
            until = Some(ts);
        } else {
            break;
        }
    }

    Ok(all_events)
}

/// Handle ledger subcommands
pub async fn ledger_command(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.is_empty() {
        eprintln!(
            "Usage: deposits-wallet ledger <list|show|validate|custody> [args...] --relay <url>"
        );
        return Ok(());
    }

    match args[0].as_str() {
        "list" | "ls" => ledger_list(&args[1..]).await,
        "show" => ledger_show(&args[1..]).await,
        "validate" => ledger_validate(&args[1..]).await,
        "custody" => ledger_custody(&args[1..]).await,
        cmd => {
            eprintln!("Unknown ledger subcommand: {}", cmd);
            eprintln!("Usage: deposits-wallet ledger <list|show|validate|custody> [args...] --relay <url>");
            Ok(())
        }
    }
}

/// Parse relay URL from args
fn get_relay_url(args: &[String]) -> Option<String> {
    for (i, arg) in args.iter().enumerate() {
        if arg == "--relay" && i + 1 < args.len() {
            return Some(args[i + 1].clone());
        }
    }
    None
}

/// List all ledgers on the relay
async fn ledger_list(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let relay_url = get_relay_url(args).ok_or("Missing --relay <url>")?;

    println!("Fetching ledgers from {}...", relay_url);
    println!();

    let keys = Keys::generate();
    let client = Client::new(keys);
    client.add_relay(&relay_url).await?;
    client.connect().await;

    let filter = Filter::new().kind(Kind::Custom(KIND_LEDGER_UPDATE));
    let events = fetch_all_events_paginated(&client, filter).await?;

    client.disconnect().await.ok();

    if events.is_empty() {
        println!("No ledgers found.");
        return Ok(());
    }

    // Group by ledger_id and count
    let mut ledgers: std::collections::HashMap<String, (u64, usize)> =
        std::collections::HashMap::new();

    for event in &events {
        let ledger_id = event.tags.iter().find_map(|tag| {
            if tag.kind() == TagKind::SingleLetter(TAG_LEDGER_ID) {
                tag.content().map(|s| s.to_string())
            } else {
                None
            }
        });

        if let Some(lid) = ledger_id {
            // Get sequence from n tag
            let seq = event
                .tags
                .iter()
                .find_map(|tag| {
                    if tag.kind() == TagKind::SingleLetter(TAG_SEQUENCE) {
                        tag.content().and_then(|s| s.parse::<u64>().ok())
                    } else {
                        None
                    }
                })
                .unwrap_or(0);

            let entry = ledgers.entry(lid).or_insert((0, 0));
            if seq > entry.0 {
                entry.0 = seq;
            }
            entry.1 += 1;
        }
    }

    println!(
        "Found {} ledger(s) ({} total events):",
        ledgers.len(),
        events.len()
    );
    println!();

    let mut sorted: Vec<_> = ledgers.into_iter().collect();
    sorted.sort_by(|a, b| b.1 .0.cmp(&a.1 .0)); // Sort by max sequence desc

    for (lid, (max_seq, count)) in sorted {
        println!("  {}  seq={:<4} updates={}", lid, max_seq, count);
    }

    Ok(())
}

/// Find full ledger ID from partial prefix
async fn find_ledger_id(
    client: &Client,
    prefix: &str,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    // Fetch all updates to find matching ledger_id
    let filter = Filter::new().kind(Kind::Custom(KIND_LEDGER_UPDATE));
    let events = fetch_all_events_paginated(client, filter).await?;

    for event in events {
        if let Some(lid) = event.tags.iter().find_map(|tag| {
            if tag.kind() == TagKind::SingleLetter(TAG_LEDGER_ID) {
                tag.content().map(|s| s.to_string())
            } else {
                None
            }
        }) {
            if lid.starts_with(prefix) {
                return Ok(Some(lid));
            }
        }
    }
    Ok(None)
}

/// Show all updates for a specific ledger
async fn ledger_show(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let relay_url = get_relay_url(args).ok_or("Missing --relay <url>")?;

    // Check for --color-by-pk flag
    let color_by_pk = args.iter().any(|a| a == "--color-by-pk" || a == "--color");

    // Get ledger_id prefix (first non-flag arg that isn't after --relay)
    let ledger_prefix = args
        .iter()
        .enumerate()
        .find(|(i, a)| !a.starts_with("--") && (*i == 0 || args[i - 1] != "--relay"))
        .map(|(_, a)| a)
        .ok_or("Missing ledger_id")?;

    println!(
        "Fetching ledger {}... from {}...",
        &ledger_prefix[..16.min(ledger_prefix.len())],
        relay_url
    );

    let keys = Keys::generate();
    let client = Client::new(keys);
    client.add_relay(&relay_url).await?;
    client.connect().await;

    // Find full ledger ID from prefix
    let ledger_id = match find_ledger_id(&client, ledger_prefix).await? {
        Some(id) => id,
        None => {
            println!("No ledger found with prefix {}", ledger_prefix);
            client.disconnect().await.ok();
            return Ok(());
        }
    };

    println!("Found: {}", ledger_id);
    println!();
    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .custom_tag(TAG_LEDGER_ID, [ledger_tag(ledger_id.as_str())]);

    let events = fetch_all_events_paginated(&client, filter).await?;
    client.disconnect().await.ok();

    if events.is_empty() {
        println!("No updates found for ledger {}", ledger_id);
        return Ok(());
    }

    // Decode and sort updates
    let mut updates: Vec<SignedLedgerUpdate> = Vec::new();
    for event in &events {
        if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
            if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                updates.push(update);
            }
        }
    }

    updates.sort_by_key(|u| u.sequence_number);
    updates.dedup_by_key(|u| (u.sequence_number, u.content_hash));

    println!(
        "=== Ledger {} ({} updates) ===",
        &ledger_id[..16.min(ledger_id.len())],
        updates.len()
    );
    println!();

    // Track deposit_id -> color mapping
    let mut id_colors: std::collections::HashMap<[u8; 16], usize> =
        std::collections::HashMap::new();
    let mut next_color = 0usize;

    for update in &updates {
        let (op_type, deposit_id) = match LedgerOperation::tlv_decode(&update.message) {
            Ok(op) => format_operation(&op),
            Err(_) => (format!("type=0x{:04X}", update.message_type), None),
        };

        let hash_short = &hex::encode(update.content_hash)[..8];

        // Show deposit_id if present, otherwise operator
        let (id_label, id_short) = if let Some(did) = deposit_id {
            ("id", hex::encode(&did[..4]))
        } else {
            let op_bytes = update.operator_id.serialize();
            ("op", hex::encode(&op_bytes[..4]))
        };

        if color_by_pk {
            // For coloring, use deposit_id if present, otherwise hash of operator
            let color_key: [u8; 16] = if let Some(did) = deposit_id {
                did
            } else {
                let op_bytes = update.operator_id.serialize();
                let mut key = [0u8; 16];
                key.copy_from_slice(&op_bytes[..16]);
                key
            };
            let color_idx = *id_colors.entry(color_key).or_insert_with(|| {
                let idx = next_color;
                next_color = (next_color + 1) % COLORS.len();
                idx
            });
            let color = COLORS[color_idx];
            println!(
                "{}  [{:>4}] {:<16} {}={} hash={}{}",
                color, update.sequence_number, op_type, id_label, id_short, hash_short, RESET
            );
        } else {
            println!(
                "  [{:>4}] {:<16} {}={} hash={}",
                update.sequence_number, op_type, id_label, id_short, hash_short
            );
        }
    }

    Ok(())
}

/// Format operation type for display and extract deposit_id if present
fn format_operation(op: &LedgerOperation) -> (String, Option<deposits_core::types::DepositId>) {
    match op {
        LedgerOperation::LedgerOpen { .. } => ("LedgerOpen".to_string(), None),
        LedgerOperation::QuorumAddMember { .. } => ("QuorumAdd".to_string(), None),
        LedgerOperation::QuorumRemoveMember { .. } => ("QuorumRemove".to_string(), None),
        LedgerOperation::QuorumJoin { .. } => ("QuorumJoin".to_string(), None),
        LedgerOperation::DepositOpen { deposit_id, .. } => {
            ("DepositOpen".to_string(), Some(*deposit_id))
        }
        LedgerOperation::DepositClose { deposit_id, .. } => {
            ("DepositClose".to_string(), Some(*deposit_id))
        }
        LedgerOperation::FeeChange { deposit_id, .. } => {
            ("FeeChange".to_string(), Some(*deposit_id))
        }
        LedgerOperation::OnchainLock { deposit_id, .. } => {
            ("OnchainLock".to_string(), Some(*deposit_id))
        }
        LedgerOperation::OnchainFulfill { deposit_id, .. } => {
            ("OnchainFulfill".to_string(), Some(*deposit_id))
        }
        LedgerOperation::OnchainFail { deposit_id, .. } => {
            ("OnchainFail".to_string(), Some(*deposit_id))
        }
        LedgerOperation::OnchainCredit { deposit_id, .. } => {
            ("OnchainCredit".to_string(), Some(*deposit_id))
        }
        LedgerOperation::InvoiceLock { deposit_id, .. } => {
            ("InvoiceLock".to_string(), Some(*deposit_id))
        }
        LedgerOperation::InvoiceFulfill { deposit_id, .. } => {
            ("InvoiceFulfill".to_string(), Some(*deposit_id))
        }
        LedgerOperation::InvoiceFail { deposit_id, .. } => {
            ("InvoiceFail".to_string(), Some(*deposit_id))
        }
        LedgerOperation::InvoiceCredit { deposit_id, .. } => {
            ("InvoiceCredit".to_string(), Some(*deposit_id))
        }
        LedgerOperation::FeeCollect { deposit_id, .. } => {
            ("FeeCollect".to_string(), Some(*deposit_id))
        }
        LedgerOperation::QuorumBegin { .. } => ("QuorumBegin".to_string(), None),
        LedgerOperation::DepositKeyRotate { deposit_id, .. } => {
            ("DepositKeyRotate".to_string(), Some(*deposit_id))
        }
        LedgerOperation::TransferLock {
            source_deposit_id, ..
        } => ("TransferLock".to_string(), Some(*source_deposit_id)),
        LedgerOperation::TransferComplete { .. } => ("TransferComplete".to_string(), None),
        LedgerOperation::TransferFail { .. } => ("TransferFail".to_string(), None),
        LedgerOperation::DisputeEnter { .. } => ("DisputeEnter".to_string(), None),
        LedgerOperation::DisputeArmed { .. } => ("DisputeArmed".to_string(), None),
        LedgerOperation::DisputeAcquire { .. } => ("DisputeAcquire".to_string(), None),
        LedgerOperation::DisputeYield => ("DisputeYield".to_string(), None),
        LedgerOperation::DeliveryEmbed { .. } => ("DeliveryEmbed".to_string(), None),
        LedgerOperation::LedgerClose => ("LedgerClose".to_string(), None),
    }
}

/// Validate ledger hash chain
async fn ledger_validate(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let relay_url = get_relay_url(args).ok_or("Missing --relay <url>")?;

    let ledger_prefix = args
        .iter()
        .find(|a| {
            !a.starts_with("--")
                && args
                    .iter()
                    .position(|x| x == *a)
                    .map(|i| i == 0 || args[i - 1] != "--relay")
                    .unwrap_or(true)
        })
        .ok_or("Missing ledger_id")?;

    println!(
        "Validating ledger {}... from {}...",
        &ledger_prefix[..16.min(ledger_prefix.len())],
        relay_url
    );

    let keys = Keys::generate();
    let client = Client::new(keys);
    client.add_relay(&relay_url).await?;
    client.connect().await;

    // Find full ledger ID from prefix
    let ledger_id = match find_ledger_id(&client, ledger_prefix).await? {
        Some(id) => id,
        None => {
            println!("No ledger found with prefix {}", ledger_prefix);
            client.disconnect().await.ok();
            return Ok(());
        }
    };

    println!("Found: {}", ledger_id);
    println!();

    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .custom_tag(TAG_LEDGER_ID, [ledger_tag(ledger_id.as_str())]);

    let events = fetch_all_events_paginated(&client, filter).await?;
    client.disconnect().await.ok();

    if events.is_empty() {
        println!("No updates found for ledger {}", ledger_id);
        return Ok(());
    }

    // Decode and sort updates
    let mut updates: Vec<SignedLedgerUpdate> = Vec::new();
    for event in &events {
        if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
            if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                updates.push(update);
            }
        }
    }

    updates.sort_by_key(|u| u.sequence_number);

    // Check for LedgerOpen at seq 0
    let has_genesis = updates.iter().any(|u| u.sequence_number == 0);
    if !has_genesis {
        println!("ERROR: No LedgerOpen found at sequence 0");
        println!(
            "  Fetched {} updates, min seq = {}",
            updates.len(),
            updates.first().map(|u| u.sequence_number).unwrap_or(0)
        );
        return Ok(());
    }

    // Validate hash chain
    let mut errors = 0;
    let mut prev_hash = [0u8; 32];

    for update in &updates {
        if update.sequence_number == 0 {
            prev_hash = update.content_hash;
            continue;
        }

        if update.previous_hash != prev_hash {
            println!(
                "  ERROR at seq {}: prev_hash mismatch",
                update.sequence_number
            );
            println!("    expected: {}", hex::encode(prev_hash));
            println!("    got:      {}", hex::encode(update.previous_hash));
            errors += 1;
        }
        prev_hash = update.content_hash;
    }

    if errors == 0 {
        println!(
            "Hash chain valid: {} updates, final hash {}",
            updates.len(),
            &hex::encode(prev_hash)[..16]
        );
    } else {
        println!(
            "Hash chain INVALID: {} errors in {} updates",
            errors,
            updates.len()
        );
    }

    Ok(())
}

/// Custody chain event types
#[derive(Debug, Clone)]
enum CustodyEvent {
    /// Ledger opened by original operator
    LedgerOpened {
        operator: bitcoin::secp256k1::PublicKey,
        reserves_address: String,
        genesis_block: u32,
    },
    /// Quorum member added
    QuorumMemberAdded {
        member: bitcoin::secp256k1::PublicKey,
        member_ledger_id: String,
    },
    /// Reserves rotated to new address
    QuorumBegun {
        new_address: String,
        amount: u64,
        quorum_member_count: usize,
        quorum_expiry: u32,
    },
    /// Custody dispute initiated
    DisputeStarted {
        last_valid_sequence: u64,
        reason: String,
    },
    /// Candidate armed for dispute resolution
    CandidateArmed {
        armed_block: u32,
        target_reserves: String,
    },
    /// New custodian acquired custody
    DisputeAcquired {
        new_custodian: bitcoin::secp256k1::PublicKey,
        claim_txid: [u8; 32],
        new_reserves_address: String,
    },
}

/// Trace custody chain for a ledger
async fn ledger_custody(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let relay_url = get_relay_url(args).ok_or("Missing --relay <url>")?;

    let ledger_prefix = args
        .iter()
        .find(|a| {
            !a.starts_with("--")
                && args
                    .iter()
                    .position(|x| x == *a)
                    .map(|i| i == 0 || args[i - 1] != "--relay")
                    .unwrap_or(true)
        })
        .ok_or("Missing ledger_id")?;

    println!(
        "Tracing custody chain for {}...",
        &ledger_prefix[..16.min(ledger_prefix.len())]
    );
    println!();

    let keys = Keys::generate();
    let client = Client::new(keys);
    client.add_relay(&relay_url).await?;
    client.connect().await;

    // Find full ledger ID from prefix
    let ledger_id = match find_ledger_id(&client, ledger_prefix).await? {
        Some(id) => id,
        None => {
            println!("No ledger found with prefix {}", ledger_prefix);
            client.disconnect().await.ok();
            return Ok(());
        }
    };

    println!("Ledger: {}", ledger_id);
    println!();

    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .custom_tag(TAG_LEDGER_ID, [ledger_tag(ledger_id.as_str())]);

    let events = fetch_all_events_paginated(&client, filter).await?;
    client.disconnect().await.ok();

    if events.is_empty() {
        println!("No updates found for ledger");
        return Ok(());
    }

    // Decode and sort updates
    let mut updates: Vec<SignedLedgerUpdate> = Vec::new();
    for event in &events {
        if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
            if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                updates.push(update);
            }
        }
    }
    updates.sort_by_key(|u| u.sequence_number);

    // Track custody state
    let mut current_operator: Option<bitcoin::secp256k1::PublicKey> = None;
    let mut quorum_members: Vec<(bitcoin::secp256k1::PublicKey, String)> = Vec::new(); // (pubkey, ledger_id)
    let mut custody_events: Vec<(u64, u32, CustodyEvent)> = Vec::new(); // (seq, block, event)
    let mut in_dispute = false;
    let mut processed_seqs: std::collections::HashSet<u64> = std::collections::HashSet::new();

    println!("=== Custody Chain ===");
    println!();

    for update in &updates {
        // Skip duplicates (same sequence number from different publishers)
        if processed_seqs.contains(&update.sequence_number) {
            continue;
        }
        processed_seqs.insert(update.sequence_number);

        let seq = update.sequence_number;
        let block = update.block_height;
        let signer = update.operator_id;

        // Parse the operation
        if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
            match op {
                LedgerOperation::LedgerOpen {
                    operator_id,
                    reserves_id,
                    genesis_block,
                    ..
                } => {
                    current_operator = Some(operator_id);
                    println!("seq {:>4} | block {:>6} | LEDGER OPENED", seq, block);
                    println!(
                        "         |              |   Operator: {}",
                        hex::encode(operator_id.serialize())[..16].to_string() + "..."
                    );
                    println!(
                        "         |              |   Reserves: {}...",
                        &reserves_id[..20.min(reserves_id.len())]
                    );
                    custody_events.push((
                        seq,
                        block,
                        CustodyEvent::LedgerOpened {
                            operator: operator_id,
                            reserves_address: reserves_id,
                            genesis_block,
                        },
                    ));
                }
                LedgerOperation::QuorumAddMember {
                    quorum_member,
                    member_ledger_id,
                    ..
                } => {
                    // Check if already a member
                    if !quorum_members.iter().any(|(pk, _)| pk == &quorum_member) {
                        quorum_members.push((quorum_member, member_ledger_id.clone()));
                        println!("seq {:>4} | block {:>6} | QUORUM MEMBER ADDED", seq, block);
                        println!(
                            "         |              |   Member: {}...",
                            &hex::encode(quorum_member.serialize())[..16]
                        );
                        println!(
                            "         |              |   Member's ledger: {}...",
                            &member_ledger_id[..16.min(member_ledger_id.len())]
                        );
                        custody_events.push((
                            seq,
                            block,
                            CustodyEvent::QuorumMemberAdded {
                                member: quorum_member,
                                member_ledger_id,
                            },
                        ));
                    }
                }
                LedgerOperation::QuorumBegin {
                    reserves_id,
                    amount,
                    quorum_expiry,
                    quorum_members,
                    ..
                } => {
                    // Verify signer is current operator
                    let signer_valid = current_operator.map(|op| op == signer).unwrap_or(false);
                    let signer_status = if signer_valid { "✓" } else { "⚠" };

                    println!(
                        "seq {:>4} | block {:>6} | QUORUM BEGIN {}",
                        seq, block, signer_status
                    );
                    println!(
                        "         |              |   New address: {}...",
                        &reserves_id[..24.min(reserves_id.len())]
                    );
                    println!("         |              |   Amount: {} sats", amount);
                    if !quorum_members.is_empty() {
                        println!(
                            "         |              |   Quorum: {} members, expires block {}",
                            quorum_members.len(),
                            quorum_expiry
                        );
                    }
                    if !signer_valid {
                        println!(
                            "         |              |   ⚠ Signer {}... != expected operator",
                            &hex::encode(signer.serialize())[..12]
                        );
                    }
                    custody_events.push((
                        seq,
                        block,
                        CustodyEvent::QuorumBegun {
                            new_address: reserves_id,
                            amount,
                            quorum_member_count: quorum_members.len(),
                            quorum_expiry,
                        },
                    ));
                }
                LedgerOperation::DisputeEnter {
                    last_valid_sequence,
                    reason,
                } => {
                    in_dispute = true;
                    // Check if signer was a quorum member
                    let is_quorum_member = quorum_members.iter().any(|(pk, _)| pk == &signer);
                    let signer_status = if is_quorum_member {
                        "✓ quorum member"
                    } else {
                        "⚠ unknown"
                    };

                    println!(
                        "seq {:>4} | block {:>6} | ⚡ CUSTODY DISPUTE ({})",
                        seq, block, signer_status
                    );
                    println!(
                        "         |              |   Last valid seq: {}",
                        last_valid_sequence
                    );
                    println!("         |              |   Reason: {}", reason);
                    println!(
                        "         |              |   Initiated by: {}...",
                        &hex::encode(signer.serialize())[..16]
                    );
                    custody_events.push((
                        seq,
                        block,
                        CustodyEvent::DisputeStarted {
                            last_valid_sequence,
                            reason,
                        },
                    ));
                }
                LedgerOperation::DisputeArmed {
                    armed_block,
                    target_reserves,
                    ..
                } => {
                    let is_quorum_member = quorum_members.iter().any(|(pk, _)| pk == &signer);
                    let signer_status = if is_quorum_member { "✓" } else { "⚠" };

                    println!(
                        "seq {:>4} | block {:>6} | 🎯 CANDIDATE ARMED {}",
                        seq, block, signer_status
                    );
                    println!(
                        "         |              |   Candidate: {}...",
                        &hex::encode(signer.serialize())[..16]
                    );
                    println!(
                        "         |              |   Armed at block: {}",
                        armed_block
                    );
                    println!(
                        "         |              |   Target: {}...",
                        &target_reserves[..20.min(target_reserves.len())]
                    );
                    custody_events.push((
                        seq,
                        block,
                        CustodyEvent::CandidateArmed {
                            armed_block,
                            target_reserves,
                        },
                    ));
                }
                LedgerOperation::DisputeAcquire {
                    new_custodian,
                    claim_txid,
                    new_reserves_address,
                    ..
                } => {
                    let is_quorum_member =
                        quorum_members.iter().any(|(pk, _)| pk == &new_custodian);
                    let valid = if is_quorum_member { "✓" } else { "⚠" };

                    println!(
                        "seq {:>4} | block {:>6} | 👑 CUSTODY ACQUIRED {}",
                        seq, block, valid
                    );
                    println!(
                        "         |              |   New custodian: {}...",
                        &hex::encode(new_custodian.serialize())[..16]
                    );
                    println!(
                        "         |              |   Claim txid: {}...",
                        &hex::encode(claim_txid)[..16]
                    );
                    println!(
                        "         |              |   New reserves: {}...",
                        &new_reserves_address[..24.min(new_reserves_address.len())]
                    );

                    // Update current operator
                    current_operator = Some(new_custodian);
                    in_dispute = false;

                    custody_events.push((
                        seq,
                        block,
                        CustodyEvent::DisputeAcquired {
                            new_custodian,
                            claim_txid,
                            new_reserves_address,
                        },
                    ));
                }
                LedgerOperation::DisputeYield => {
                    println!("seq {:>4} | block {:>6} | 🏳️ CUSTODY YIELDED", seq, block);
                    println!(
                        "         |              |   Candidate: {}...",
                        &hex::encode(signer.serialize())[..16]
                    );
                }
                _ => {
                    // Skip non-custody operations
                }
            }
        }
    }

    // Summary
    println!();
    println!("=== Summary ===");
    println!();

    if let Some(op) = current_operator {
        println!(
            "Current custodian: {}...",
            &hex::encode(op.serialize())[..16]
        );
    }

    println!("Quorum members ({}):", quorum_members.len());
    for (i, (pk, lid)) in quorum_members.iter().enumerate() {
        println!(
            "  {}. {}... (ledger: {}...)",
            i + 1,
            &hex::encode(pk.serialize())[..16],
            &lid[..12.min(lid.len())]
        );
    }

    if in_dispute {
        println!();
        println!("⚠ LEDGER IS IN DISPUTED STATE");
    }

    // Count custody transitions
    let transitions: Vec<_> = custody_events
        .iter()
        .filter(|(_, _, e)| matches!(e, CustodyEvent::DisputeAcquired { .. }))
        .collect();

    if !transitions.is_empty() {
        println!();
        println!("Custody transitions: {}", transitions.len());
    }

    Ok(())
}
