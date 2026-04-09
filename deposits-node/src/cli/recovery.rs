//! Recovery CLI commands
//!
//! Commands for dispute resolution and custody recovery.

use std::str::FromStr;
use std::sync::OnceLock;

use bitcoin::hashes::{Hash, sha256, hash160};
use bitcoin::secp256k1::{Keypair, Secp256k1, PublicKey, Message};
use bitcoin::bip32::{DerivationPath, Xpriv};

use deposits_core::{TlvDecode, TlvEncode, SignedLedgerUpdate, CollateralAttestationMsg};
use deposits_core::messages::LedgerOperation;
use deposits_core::types::select_entropy_winner;

use crate::nostr::{NostrTransportBuilder, KIND_LEDGER_UPDATE, KIND_LEDGER_DISPUTE};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use nostr_sdk::prelude::*;
use bdk_esplora::esplora_client::Builder as EsploraBuilder;
use tokio::sync::Mutex;

use super::common::{parse_config, derive_operator_secret};

/// Cached nostr client for recovery commands
static RECOVERY_NOSTR_CLIENT: OnceLock<Mutex<Option<(String, Client)>>> = OnceLock::new();

/// Get or create a connected nostr client for the given relay URL
async fn get_or_create_client(relay_url: &str) -> Result<Client, Box<dyn std::error::Error>> {
    let mutex = RECOVERY_NOSTR_CLIENT.get_or_init(|| Mutex::new(None));
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

/// Handle recovery subcommands for non-conforming ledgers
pub async fn recovery_command(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.is_empty() {
        eprintln!("Usage: deposits-node recovery <dispute|rebuild|arm|claim|continue|spend|status> [args...]");
        eprintln!();
        eprintln!("Subcommands (Dispute Protocol):");
        eprintln!("  dispute <ledger_id> [--reason <text>]  Open dispute: publish DisputeEnter operation");
        eprintln!("  rebuild <ledger_id>                    Rebuild quorum: add members + get attestations");
        eprintln!("  arm <ledger_id>                        Pre-commit: publish DisputeArmed operation");
        eprintln!("  claim <ledger_id>                      After entropy: DisputeAcquire (win) or DisputeYield (lose)");
        eprintln!("  continue <ledger_id> [--count N]       Winner: add operations to continue the ledger");
        eprintln!("  spend <ledger_id>                      Execute on-chain spend (winner only)");
        eprintln!("  status <ledger_id>                     Show recovery status and candidates");
        eprintln!();
        eprintln!("Lottery Protocol (on-chain winner selection):");
        eprintln!("  confiscate <ledger_id>                 Build and broadcast confiscation TX to lottery");
        eprintln!("  reveal <ledger_id>                     Reveal lottery preimage via Nostr");
        eprintln!("  lottery-claim <ledger_id>              Claim lottery output if winner");
        eprintln!();
        eprintln!("Recovery flow (entropy-based):");
        eprintln!("  1. dispute - Detect violation, publish DisputeEnter (quorum disbanded)");
        eprintln!("  2. rebuild - Add new quorum members, collect attestations");
        eprintln!("  3. arm     - Publish DisputeArmed (locks in for entropy selection)");
        eprintln!("  4. (wait)  - Wait for entropy block to be mined");
        eprintln!("  5. claim   - Winner: DisputeAcquire, Losers: DisputeYield");
        eprintln!("  6. continue- Winner adds operations to resume normal ledger operation");
        eprintln!("  7. spend   - Winner broadcasts on-chain spend to claim reserves");
        eprintln!();
        eprintln!("Recovery flow (lottery-based):");
        eprintln!("  1-3. Same as above (dispute, rebuild, arm with commitment_hash)");
        eprintln!("  4. confiscate - Quorum signs TX spending reserves to lottery output");
        eprintln!("  5. reveal     - All disputants reveal their preimages");
        eprintln!("  6. lottery-claim - Winner (determined by preimage sizes) claims lottery");
        eprintln!("  7. continue   - Winner adds operations to resume normal operation");
        eprintln!();
        eprintln!("State machine: NORMAL -> DISPUTED -> ARMED -> NORMAL (winner) / TOMBSTONED (losers)");
        return Ok(());
    }

    match args[0].as_str() {
        // New dispute protocol commands
        "dispute" => recovery_dispute(&args[1..]).await,
        "rebuild" => recovery_rebuild(&args[1..]).await,
        "arm" => recovery_arm(&args[1..]).await,
        "claim" => recovery_claim_new(&args[1..]).await,
        "continue" => recovery_continue(&args[1..]).await,
        "spend" => recovery_spend(&args[1..]).await,
        "status" => recovery_status(&args[1..]).await,
        // Lottery protocol commands
        "confiscate" => recovery_confiscate(&args[1..]).await,
        "reveal" => recovery_reveal(&args[1..]).await,
        "lottery-claim" => recovery_lottery_claim(&args[1..]).await,
        "rotate-to-quorum" => recovery_rotate_to_quorum(&args[1..]).await,
        // Legacy commands (for backward compatibility)
        "start" => recovery_start(&args[1..]).await,
        "agree" => recovery_agree(&args[1..]).await,
        "prepare" => recovery_prepare(&args[1..]).await,
        "release" => recovery_release(&args[1..]).await,
        "complete" => recovery_complete(&args[1..]).await,
        "publish-transfer" => recovery_publish_transfer(&args[1..]).await,
        cmd => {
            eprintln!("Unknown recovery subcommand: {}", cmd);
            eprintln!("Usage: deposits-node recovery <dispute|rebuild|arm|claim|spend|status> [args...]");
            Ok(())
        }
    }
}

/// Start a recovery process for a non-conforming ledger
/// Validates the ledger from Nostr and publishes a dispute if invalid.
pub async fn recovery_start(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut ledger_id: Option<String> = None;
    let mut reason: Option<String> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--reason" | "-r" => {
                i += 1;
                if i < args.len() {
                    reason = Some(args[i].clone());
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

    let ledger_id = ledger_id.ok_or("Missing ledger_id")?.trim().to_string();
    let reason = reason.unwrap_or_else(|| "Non-conforming ledger detected".to_string());

    let config = parse_config(&config_args)?;
    let relay_url = config.relays.first()
        .ok_or("No relay configured. Use --relay <url>")?
        .clone();

    // Build keypair from seed
    let secp = Secp256k1::new();
    let secret_key = derive_operator_secret(&config.seed, config.network)?;
    let keypair = Keypair::from_secret_key(&secp, &secret_key);

    println!("Starting recovery for ledger: {}...", &ledger_id[..16.min(ledger_id.len())]);
    println!("  Reason: {}", reason);
    println!();

    // Fetch and validate ledger from Nostr
    println!("Fetching ledger from Nostr...");
    let client = get_or_create_client(&relay_url).await?;

    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .custom_tag(crate::nostr::TAG_LEDGER_ID, [crate::nostr::ledger_tag(ledger_id.as_str())])
        .limit(500);

    let events = client
        .fetch_events(vec![filter], None)
        .await
        .map_err(|e| format!("Failed to fetch events: {}", e))?;


    // Decode and sort updates
    let mut updates: Vec<SignedLedgerUpdate> = Vec::new();
    for event in events.iter() {
        if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
            if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                updates.push(update);
            }
        }
    }
    updates.sort_by_key(|u| (u.sequence_number, u.operator_id));
    updates.dedup_by(|a, b| a.sequence_number == b.sequence_number && a.operator_id == b.operator_id && a.current_hash == b.current_hash);

    println!("  Found {} updates", updates.len());

    // Validate the hash chain to find the violation
    let mut last_valid_hash = [0u8; 32];
    let mut last_valid_sequence: i64 = -1;
    let mut violation_details = String::new();
    let mut violation_sequence: Option<u64> = None;

    for update in &updates {
        let expected_seq = (last_valid_sequence + 1) as u64;
        if update.sequence_number != expected_seq && last_valid_sequence >= 0 {
            violation_details = format!(
                "Sequence gap at seq {}: expected {}, got {}",
                update.sequence_number, expected_seq, update.sequence_number
            );
            violation_sequence = Some(update.sequence_number);
            break;
        }

        let expected_prev = if update.sequence_number == 0 {
            [0u8; 32]
        } else {
            last_valid_hash
        };

        if update.previous_hash != expected_prev {
            violation_details = format!(
                "Hash chain broken at seq {}: expected {}..., got {}...",
                update.sequence_number,
                hex::encode(&expected_prev[..4]),
                hex::encode(&update.previous_hash[..4])
            );
            violation_sequence = Some(update.sequence_number);
            break;
        }

        let computed_hash = update.compute_hash();
        if computed_hash != update.current_hash {
            violation_details = format!(
                "Invalid hash at seq {}: computed {}..., stored {}...",
                update.sequence_number,
                hex::encode(&computed_hash[..4]),
                hex::encode(&update.current_hash[..4])
            );
            violation_sequence = Some(update.sequence_number);
            break;
        }

        last_valid_hash = update.current_hash;
        last_valid_sequence = update.sequence_number as i64;
    }

    if violation_sequence.is_none() {
        println!();
        println!("Ledger appears conforming (no violation found).");
        println!("Cannot start recovery for a conforming ledger.");
        return Ok(());
    }

    let last_valid_sequence_u64 = if last_valid_sequence >= 0 {
        last_valid_sequence as u64
    } else {
        0
    };

    println!();
    println!("Violation detected!");
    println!("  {}", violation_details);
    println!("  Last valid sequence: {}", last_valid_sequence_u64);
    println!("  Last valid hash: {}...", hex::encode(&last_valid_hash[..8]));
    println!();

    // Publish dispute to Nostr
    println!("Publishing dispute to Nostr...");
    let transport = NostrTransportBuilder::new(secret_key)
        .relay(&relay_url)
        .build()
        .await?;

    let dispute_id = transport.publish_dispute(
        &ledger_id,
        &reason,
        &violation_details,
        last_valid_hash,
        last_valid_sequence_u64,
        violation_sequence,
        &keypair,
    ).await?;

    transport.disconnect().await;

    println!("  Dispute published: {}", &dispute_id[..16]);
    println!();
    println!("Next steps:");
    println!("  1. Other quorum members run: deposits-node recovery agree {}", &ledger_id[..16]);
    println!("  2. Once enough agree, run: deposits-node recovery complete {}", &ledger_id[..16]);

    Ok(())
}

/// Agree to a recovery (respond to a dispute)
/// Independently validates the ledger and publishes agreement if violation confirmed.
pub async fn recovery_agree(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
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

    let ledger_id = ledger_id.ok_or("Missing ledger_id")?.trim().to_string();

    let config = parse_config(&config_args)?;
    let relay_url = config.relays.first()
        .ok_or("No relay configured. Use --relay <url>")?
        .clone();

    // Build keypair from seed
    let secp = Secp256k1::new();
    let secret_key = derive_operator_secret(&config.seed, config.network)?;
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let our_pubkey = PublicKey::from(keypair.public_key());

    println!("Checking for disputes on ledger: {}...", &ledger_id[..16.min(ledger_id.len())]);
    println!("  Our key: {}...", &our_pubkey.to_string()[..16]);
    println!();

    // Fetch disputes for this ledger
    let transport = NostrTransportBuilder::new(secret_key)
        .relay(&relay_url)
        .build()
        .await?;

    let disputes = transport.fetch_disputes(&ledger_id).await?;

    if disputes.is_empty() {
        println!("No disputes found for this ledger.");
        println!("Run 'recovery start' to initiate a dispute first.");
        transport.disconnect().await;
        return Ok(());
    }

    // Use the most recent dispute
    let dispute = disputes.last().unwrap();
    println!("Found dispute:");
    println!("  From: {}...", &dispute.disputer_pubkey[..16.min(dispute.disputer_pubkey.len())]);
    println!("  Reason: {}", dispute.reason);
    println!("  Details: {}", dispute.details);
    println!("  Last valid seq: {}", dispute.last_valid_sequence);
    println!("  Event: {}...", &dispute.event_id[..16]);
    println!();

    // Independently validate the ledger
    println!("Independently validating ledger...");

    let client = get_or_create_client(&relay_url).await?;

    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .custom_tag(crate::nostr::TAG_LEDGER_ID, [crate::nostr::ledger_tag(ledger_id.as_str())])
        .limit(500);

    let events = client
        .fetch_events(vec![filter], None)
        .await
        .map_err(|e| format!("Failed to fetch events: {}", e))?;


    // Decode and sort updates
    let mut updates: Vec<SignedLedgerUpdate> = Vec::new();
    for event in events.iter() {
        if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
            if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                updates.push(update);
            }
        }
    }
    updates.sort_by_key(|u| (u.sequence_number, u.operator_id));
    updates.dedup_by(|a, b| a.sequence_number == b.sequence_number && a.operator_id == b.operator_id && a.current_hash == b.current_hash);

    println!("  Found {} updates", updates.len());

    // Validate the hash chain
    let mut last_valid_hash = [0u8; 32];
    let mut last_valid_sequence: i64 = -1;
    let mut found_violation = false;

    for update in &updates {
        let expected_seq = (last_valid_sequence + 1) as u64;
        if update.sequence_number != expected_seq && last_valid_sequence >= 0 {
            found_violation = true;
            break;
        }

        let expected_prev = if update.sequence_number == 0 {
            [0u8; 32]
        } else {
            last_valid_hash
        };

        if update.previous_hash != expected_prev {
            found_violation = true;
            break;
        }

        let computed_hash = update.compute_hash();
        if computed_hash != update.current_hash {
            found_violation = true;
            break;
        }

        last_valid_hash = update.current_hash;
        last_valid_sequence = update.sequence_number as i64;
    }

    let our_last_valid = if last_valid_sequence >= 0 {
        last_valid_sequence as u64
    } else {
        0
    };

    if !found_violation {
        println!();
        println!("We did NOT find a violation. Ledger appears conforming.");
        println!("Not publishing agreement.");
        transport.disconnect().await;
        return Ok(());
    }

    println!("  Violation confirmed!");
    println!("  Our last valid sequence: {}", our_last_valid);
    println!("  Our last valid hash: {}...", hex::encode(&last_valid_hash[..8]));
    println!();

    // Publish agreement
    println!("Publishing recovery agreement...");

    let agreement_id = transport.publish_recovery_agreement(
        &ledger_id,
        &dispute.event_id,
        our_last_valid,
        last_valid_hash,
        &keypair,
    ).await?;

    transport.disconnect().await;

    println!("  Agreement published: {}", &agreement_id[..16]);
    println!();
    println!("Next step:");
    println!("  Once enough quorum members agree, run: deposits-node recovery complete {}", &ledger_id[..16]);

    Ok(())
}

/// Show recovery status for a ledger
pub async fn recovery_status(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
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

    let ledger_id = ledger_id.ok_or("Missing ledger_id")?;

    println!("Recovery status for: {}", ledger_id);
    println!();
    println!("Note: Recovery state is currently ephemeral (in-memory).");
    println!("In a production implementation, recovery state would be persisted.");
    println!();
    println!("To participate in recovery:");
    println!("  1. Validate the ledger: deposits-node nostr validate {}", ledger_id);
    println!("  2. If invalid, publish dispute: deposits-node nostr dispute publish {} <reason> <details>", ledger_id);
    println!("  3. Submit vote: deposits-node recovery vote {} non-conforming", ledger_id);
    println!("  4. Claim if eligible: deposits-node recovery claim {}", ledger_id);

    Ok(())
}

/// Execute a custody transfer for a non-conforming ledger
///
/// DEPRECATED: Use the new dispute protocol commands instead:
///   recovery dispute -> recovery rebuild -> recovery arm -> recovery claim -> recovery spend
pub async fn recovery_complete(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("WARNING: 'recovery complete' is deprecated and uses the old protocol.");
    eprintln!("Please use the new dispute protocol commands instead:");
    eprintln!("  1. recovery dispute <ledger_id>   - Open dispute with DisputeEnter");
    eprintln!("  2. recovery rebuild <ledger_id>   - Rebuild quorum");
    eprintln!("  3. recovery arm <ledger_id>       - Publish DisputeArmed pre-commitment");
    eprintln!("  4. recovery claim <ledger_id>     - Claim with DisputeAcquire/DisputeYield");
    eprintln!("  5. recovery spend <ledger_id>     - Execute on-chain spend");
    eprintln!();

    let ledger_id = args.first().ok_or("Missing ledger_id")?;
    println!("To complete recovery for ledger {}..., use the new dispute protocol:", &ledger_id[..16.min(ledger_id.len())]);
    println!("  deposits-node recovery dispute {}", ledger_id);

    Ok(())
}

/// DEPRECATED: Use the new dispute protocol commands instead
pub async fn recovery_publish_transfer(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("WARNING: 'recovery publish-transfer' is deprecated and uses the old protocol.");
    eprintln!("Please use the new dispute protocol commands instead:");
    eprintln!("  1. recovery dispute <ledger_id>   - Open dispute with DisputeEnter");
    eprintln!("  2. recovery rebuild <ledger_id>   - Rebuild quorum");
    eprintln!("  3. recovery arm <ledger_id>       - Publish DisputeArmed pre-commitment");
    eprintln!("  4. recovery claim <ledger_id>     - Claim with DisputeAcquire/DisputeYield");
    eprintln!("  5. recovery spend <ledger_id>     - Execute on-chain spend");
    eprintln!();

    let ledger_id = args.first().ok_or("Missing ledger_id")?;
    println!("To publish transfer for ledger {}..., use the new dispute protocol:", &ledger_id[..16.min(ledger_id.len())]);

    Ok(())
}

/// Prepare as a candidate for custody acquisition.
pub async fn recovery_prepare(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut ledger_id: Option<String> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            arg if arg.starts_with("--") => {
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

    let ledger_id = ledger_id.ok_or("Ledger ID required")?;
    let config = parse_config(&config_args)?;

    let relay_url = config.relays.first()
        .ok_or("No relay configured")?
        .clone();

    println!("Preparing as custody acquisition candidate...");
    println!("  Ledger: {}...", &ledger_id[..16.min(ledger_id.len())]);
    println!("  Relay: {}", relay_url);
    println!();

    let secp = Secp256k1::new();
    let xpriv = Xpriv::new_master(config.network, &config.seed)
        .map_err(|e| format!("Failed to create master key: {}", e))?;
    let operator_path = DerivationPath::from_str("m/86'/0'/0'/0/0")
        .map_err(|e| format!("Invalid derivation path: {}", e))?;
    let operator_xpriv = xpriv
        .derive_priv(&secp, &operator_path)
        .map_err(|e| format!("Failed to derive operator key: {}", e))?;
    let secret_key = operator_xpriv.private_key;
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let our_pubkey = keypair.public_key();

    println!("Our pubkey (candidate): {}...", &our_pubkey.to_string()[..16]);

    println!("Fetching ledger from Nostr...");
    let client = get_or_create_client(&relay_url).await?;

    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .custom_tag(crate::nostr::TAG_LEDGER_ID, [crate::nostr::ledger_tag(ledger_id.as_str())])
        .limit(500);

    let events = client
        .fetch_events(vec![filter], None)
        .await
        .map_err(|e| format!("Failed to fetch events: {}", e))?;

    let mut updates: Vec<SignedLedgerUpdate> = Vec::new();
    for event in events.iter() {
        if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
            if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                updates.push(update);
            }
        }
    }

    updates.sort_by_key(|u| (u.sequence_number, u.operator_id));
    updates.dedup_by(|a, b| a.sequence_number == b.sequence_number && a.operator_id == b.operator_id && a.current_hash == b.current_hash);

    println!("  Found {} updates", updates.len());

    if updates.is_empty() {
            return Err("No ledger updates found".into());
    }

    let mut last_valid_sequence = 0u64;
    let mut last_valid_hash = [0u8; 32];
    let mut violation_details = String::new();
    let mut original_operator = None;

    for (idx, update) in updates.iter().enumerate() {
        if idx == 0 {
            original_operator = Some(update.operator_id);
        }

        if idx > 0 {
            let prev = &updates[idx - 1];
            if update.previous_hash != prev.current_hash {
                violation_details = format!("Hash chain broken at seq {}", update.sequence_number);
                break;
            }
        }

        last_valid_sequence = update.sequence_number;
        last_valid_hash = update.current_hash;
    }

    if violation_details.is_empty() {
        let dispute_filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_DISPUTE))
            .custom_tag(crate::nostr::TAG_LEDGER_ID, [ledger_id.as_str()])
            .limit(10);

        let disputes = client
            .fetch_events(vec![dispute_filter], None)
            .await
            .map_err(|e| format!("Failed to fetch disputes: {}", e))?;

        if disputes.is_empty() {
                    return Err("No violation found and no dispute published. Run 'recovery start' first.".into());
        }

        violation_details = "Dispute published - preparing candidate branch".to_string();
    }

    println!("  Last valid sequence: {}", last_valid_sequence);
    println!("  Violation: {}", violation_details);

    let original_operator = original_operator.ok_or("Could not determine original operator")?;
    println!("  Original operator: {}...", &original_operator.to_string()[..16]);


    let esplora = EsploraBuilder::new(&config.electrum_url).build_blocking();
    let current_block_height = esplora.get_height()
        .map_err(|e| format!("Failed to get block height: {:?}", e))?;

    let initiation_block = current_block_height;
    let entropy_block_height = initiation_block + 6;
    let entropy_block_hash = [0u8; 32];

    println!("  Initiation block: {}", initiation_block);
    println!("  Entropy block (expected): {}", entropy_block_height);

    let custody_dispute = LedgerOperation::DisputeEnter {
        last_valid_sequence,
        reason: violation_details.clone(),
    };

    let message_bytes = custody_dispute.tlv_encode();

    let sequence = last_valid_sequence + 1;
    let mut hash_input = Vec::new();
    hash_input.extend_from_slice(&sequence.to_le_bytes());
    hash_input.extend_from_slice(&last_valid_hash);
    hash_input.extend_from_slice(&message_bytes);
    let new_hash = *sha256::Hash::hash(&hash_input).as_byte_array();

    let update_msg = format!(
        "deposits:ledger:{}:{}:{}",
        hex::encode(last_valid_hash),
        sequence,
        hex::encode(&new_hash)
    );
    let msg_hash = sha256::Hash::hash(update_msg.as_bytes());
    let signature = secp.sign_schnorr(
        &Message::from_digest(*msg_hash.as_ref()),
        &keypair
    );
    let operator_sig_bytes: [u8; 64] = *signature.as_ref();

    let ledger_id_bytes: [u8; 32] = {
        let decoded = hex::decode(&ledger_id)
            .map_err(|e| format!("Invalid ledger_id hex: {}", e))?;
        decoded.try_into().map_err(|_| "Ledger ID must be 32 bytes")?
    };

    let signed_update = SignedLedgerUpdate {
        message: message_bytes,
        message_type: 0x8001,
        operator_signature: operator_sig_bytes,
        cosigner_pubkey: None,
        member_ledger_hash: None,
            cosignatures: Vec::new(),
        cosign_signature: [0u8; 64],
        operator_id: our_pubkey,
        ledger_id: ledger_id_bytes,
        sequence_number: sequence,
        previous_hash: last_valid_hash,
        current_hash: new_hash,
        block_height: current_block_height,
        block_hash: entropy_block_hash,
    };

    println!();
    println!("Publishing DisputeEnter to Nostr...");

    let publish_transport = NostrTransportBuilder::new(secret_key)
        .relay(&relay_url)
        .build()
        .await?;

    publish_transport.broadcast_ledger_update(&signed_update).await?;

    println!();
    println!("DisputeEnter published successfully!");
    println!("  Disputer: {}...", &our_pubkey.to_string()[..16]);
    println!("  Sequence: {} (forked from {})", sequence, last_valid_sequence);
    println!("  Hash: {}...", &hex::encode(new_hash)[..16]);
    println!("  Reason: {}", violation_details);
    println!();
    println!("Next steps (dispute protocol):");
    println!("  1. Rebuild quorum: recovery rebuild <ledger_id>");
    println!("  2. Arm for entropy: recovery arm <ledger_id>");
    println!("  3. Wait for entropy block (armed_block + 6)");
    println!("  4. Claim custody: recovery claim <ledger_id>");
    println!("  5. On-chain spend: recovery spend <ledger_id>");

    Ok(())
}

/// Execute the on-chain spend to transfer reserves to the selected candidate.
/// This is the final step after all participants have revealed their preimages.
pub async fn recovery_spend(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    recovery_lottery_claim(args).await
}

/// Publish DisputeYield to close a candidate branch after not being selected.
pub async fn recovery_release(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut ledger_id: Option<String> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            arg if arg.starts_with("--") => {
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

    let ledger_id = ledger_id.ok_or("Ledger ID required")?;
    let config = parse_config(&config_args)?;

    let relay_url = config.relays.first()
        .ok_or("No relay configured")?
        .clone();

    println!("Publishing DisputeYield (closing candidate branch)...");
    println!("  Ledger: {}...", &ledger_id[..16.min(ledger_id.len())]);
    println!("  Relay: {}", relay_url);
    println!();

    let secp = Secp256k1::new();
    let xpriv = Xpriv::new_master(config.network, &config.seed)
        .map_err(|e| format!("Failed to create master key: {}", e))?;
    let operator_path = DerivationPath::from_str("m/86'/0'/0'/0/0")
        .map_err(|e| format!("Invalid derivation path: {}", e))?;
    let operator_xpriv = xpriv
        .derive_priv(&secp, &operator_path)
        .map_err(|e| format!("Failed to derive operator key: {}", e))?;
    let secret_key = operator_xpriv.private_key;
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let our_pubkey = keypair.public_key();

    println!("Our pubkey: {}...", &our_pubkey.to_string()[..16]);

    println!("Fetching our DisputeArmed branch...");
    let client = get_or_create_client(&relay_url).await?;

    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .custom_tag(crate::nostr::TAG_LEDGER_ID, [crate::nostr::ledger_tag(ledger_id.as_str())])
        .limit(500);

    let events = client
        .fetch_events(vec![filter], None)
        .await
        .map_err(|e| format!("Failed to fetch events: {}", e))?;

    let mut our_armed: Option<SignedLedgerUpdate> = None;
    for event in events.iter() {
        if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
            if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                if update.operator_id == our_pubkey {
                    if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                        if matches!(op, LedgerOperation::DisputeArmed { .. }) {
                            our_armed = Some(update);
                            break;
                        }
                    }
                }
            }
        }
    }


    let our_armed = our_armed.ok_or(
        "Could not find our DisputeArmed. Did you run 'recovery arm' first?"
    )?;

    println!("  Found our DisputeArmed at sequence {}", our_armed.sequence_number);

    let esplora = EsploraBuilder::new(&config.electrum_url).build_blocking();
    let current_block_height = esplora.get_height()
        .map_err(|e| format!("Failed to get block height: {:?}", e))?;

    let custody_release = LedgerOperation::DisputeYield;
    let message_bytes = custody_release.tlv_encode();

    let sequence = our_armed.sequence_number + 1;
    let mut hash_input = Vec::new();
    hash_input.extend_from_slice(&sequence.to_le_bytes());
    hash_input.extend_from_slice(&our_armed.current_hash);
    hash_input.extend_from_slice(&message_bytes);
    let new_hash = *sha256::Hash::hash(&hash_input).as_byte_array();

    let update_msg = format!(
        "deposits:ledger:{}:{}:{}",
        hex::encode(our_armed.current_hash),
        sequence,
        hex::encode(&new_hash)
    );
    let msg_hash = sha256::Hash::hash(update_msg.as_bytes());
    let signature = secp.sign_schnorr(
        &Message::from_digest(*msg_hash.as_ref()),
        &keypair
    );
    let operator_sig_bytes: [u8; 64] = *signature.as_ref();

    let ledger_id_bytes: [u8; 32] = {
        let decoded = hex::decode(&ledger_id)
            .map_err(|e| format!("Invalid ledger_id hex: {}", e))?;
        decoded.try_into().map_err(|_| "Ledger ID must be 32 bytes")?
    };

    let signed_update = SignedLedgerUpdate {
        message: message_bytes,
        message_type: 0x8001,
        operator_signature: operator_sig_bytes,
        cosigner_pubkey: None,
        member_ledger_hash: None,
            cosignatures: Vec::new(),
        cosign_signature: [0u8; 64],
        operator_id: our_pubkey,
        ledger_id: ledger_id_bytes,
        sequence_number: sequence,
        previous_hash: our_armed.current_hash,
        current_hash: new_hash,
        block_height: current_block_height,
        block_hash: [0u8; 32],
    };

    println!();
    println!("Publishing DisputeYield to Nostr...");

    let publish_transport = NostrTransportBuilder::new(secret_key)
        .relay(&relay_url)
        .build()
        .await?;

    publish_transport.broadcast_ledger_update(&signed_update).await?;

    println!();
    println!("DisputeYield published successfully!");
    println!("  Sequence: {}", sequence);
    println!("  Hash: {}...", &hex::encode(new_hash)[..16]);
    println!();
    println!("Your candidate branch is now closed.");
    println!("Your quorum members are released from attestation obligations.");

    Ok(())
}

// =============================================================================
// NEW DISPUTE PROTOCOL COMMANDS
// =============================================================================

/// Open a custody dispute by publishing a DisputeEnter ledger operation.
pub async fn recovery_dispute(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut ledger_id: Option<String> = None;
    let mut reason: Option<String> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--reason" | "-r" => {
                i += 1;
                if i < args.len() {
                    reason = Some(args[i].clone());
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

    let ledger_id = ledger_id.ok_or("Missing ledger_id")?.trim().to_string();
    let reason = reason.unwrap_or_else(|| "Non-conforming ledger detected".to_string());

    let config = parse_config(&config_args)?;
    let relay_url = config.relays.first()
        .ok_or("No relay configured. Use --relay <url>")?
        .clone();

    let secp = Secp256k1::new();
    let secret_key = derive_operator_secret(&config.seed, config.network)?;
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let our_pubkey = keypair.public_key();

    println!("Opening custody dispute for ledger: {}...", &ledger_id[..16.min(ledger_id.len())]);
    println!("  Reason: {}", reason);
    println!("  Our pubkey: {}", our_pubkey);
    println!();

    // Fetch ledger from Nostr
    println!("Fetching ledger from Nostr...");
    let client = get_or_create_client(&relay_url).await?;

    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .custom_tag(crate::nostr::TAG_LEDGER_ID, [crate::nostr::ledger_tag(ledger_id.as_str())])
        .limit(500);

    let events = client
        .fetch_events(vec![filter], None)
        .await
        .map_err(|e| format!("Failed to fetch events: {}", e))?;


    // Decode all updates
    let mut all_updates: Vec<SignedLedgerUpdate> = Vec::new();
    for event in events.iter() {
        if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
            if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                all_updates.push(update);
            }
        }
    }

    println!("  Found {} total updates", all_updates.len());

    // Find the original operator
    let original_operator = all_updates.iter()
        .find(|u| u.sequence_number == 0)
        .map(|u| u.operator_id)
        .ok_or("No LedgerOpen found (seq 0)")?;

    println!("  Original operator: {}...", &original_operator.to_string()[..16]);

    // Filter to only the original operator's updates
    let mut updates: Vec<&SignedLedgerUpdate> = all_updates.iter()
        .filter(|u| u.operator_id == original_operator)
        .collect();
    updates.sort_by_key(|u| u.sequence_number);
    updates.dedup_by(|a, b| a.sequence_number == b.sequence_number);

    println!("  Original operator's updates: {}", updates.len());

    // Validate the hash chain to find the last valid point
    let mut last_valid_hash = [0u8; 32];
    let mut last_valid_sequence: i64 = -1;
    let mut violation_details = String::new();
    let mut invalid_update_hash: Option<[u8; 32]> = None;

    for update in &updates {
        let expected_seq = (last_valid_sequence + 1) as u64;
        if update.sequence_number != expected_seq && last_valid_sequence >= 0 {
            violation_details = format!(
                "Sequence gap: expected {}, got {}",
                expected_seq, update.sequence_number
            );
            invalid_update_hash = Some(update.current_hash);
            break;
        }

        let expected_prev = if update.sequence_number == 0 {
            [0u8; 32]
        } else {
            last_valid_hash
        };

        if update.previous_hash != expected_prev {
            violation_details = format!(
                "Hash chain broken at seq {}: expected {}..., got {}...",
                update.sequence_number,
                hex::encode(&expected_prev[..4]),
                hex::encode(&update.previous_hash[..4])
            );
            invalid_update_hash = Some(update.current_hash);
            break;
        }

        let computed_hash = update.compute_hash();
        if computed_hash != update.current_hash {
            violation_details = format!(
                "Invalid hash at seq {}: computed {}..., stored {}...",
                update.sequence_number,
                hex::encode(&computed_hash[..4]),
                hex::encode(&update.current_hash[..4])
            );
            invalid_update_hash = Some(update.current_hash);
            break;
        }

        last_valid_hash = update.current_hash;
        last_valid_sequence = update.sequence_number as i64;
    }

    let last_valid_sequence_u64 = if last_valid_sequence >= 0 {
        last_valid_sequence as u64
    } else {
        0
    };

    if violation_details.is_empty() {
        println!();
        println!("Ledger appears conforming (no violation found).");
        println!("Cannot open dispute for a conforming ledger.");
        return Ok(());
    }

    println!();
    println!("Violation detected!");
    println!("  {}", violation_details);
    println!("  Last valid sequence: {}", last_valid_sequence_u64);
    println!("  Last valid hash: {}...", hex::encode(&last_valid_hash[..8]));

    // Create DisputeEnter operation
    let dispute_reason = if let Some(hash) = invalid_update_hash {
        hex::encode(hash)
    } else {
        violation_details.clone()
    };
    let custody_dispute = LedgerOperation::DisputeEnter {
        last_valid_sequence: last_valid_sequence_u64,
        reason: dispute_reason,
    };

    let message_bytes = custody_dispute.tlv_encode();

    let sequence = last_valid_sequence_u64 + 1;
    let mut hash_input = Vec::new();
    hash_input.extend_from_slice(&sequence.to_le_bytes());
    hash_input.extend_from_slice(&last_valid_hash);
    hash_input.extend_from_slice(&message_bytes);
    let new_hash = *sha256::Hash::hash(&hash_input).as_byte_array();

    let esplora = EsploraBuilder::new(&config.electrum_url).build_blocking();
    let current_block_height = esplora.get_height()
        .map_err(|e| format!("Failed to get block height: {:?}", e))?;

    let update_msg = format!(
        "deposits:ledger:{}:{}:{}",
        hex::encode(last_valid_hash),
        sequence,
        hex::encode(&new_hash)
    );
    let msg_hash = sha256::Hash::hash(update_msg.as_bytes());
    let signature = secp.sign_schnorr(
        &Message::from_digest(*msg_hash.as_ref()),
        &keypair
    );
    let operator_sig_bytes: [u8; 64] = *signature.as_ref();

    let ledger_id_bytes: [u8; 32] = {
        let decoded = hex::decode(&ledger_id)
            .map_err(|e| format!("Invalid ledger_id hex: {}", e))?;
        decoded.try_into().map_err(|_| "Ledger ID must be 32 bytes")?
    };

    let signed_update = SignedLedgerUpdate {
        message: message_bytes,
        message_type: 0x8001,
        operator_signature: operator_sig_bytes,
        cosigner_pubkey: None,
        member_ledger_hash: None,
            cosignatures: Vec::new(),
        cosign_signature: [0u8; 64],
        operator_id: our_pubkey,
        ledger_id: ledger_id_bytes,
        sequence_number: sequence,
        previous_hash: last_valid_hash,
        current_hash: new_hash,
        block_height: current_block_height,
        block_hash: [0u8; 32],
    };

    println!();
    println!("Publishing DisputeEnter to Nostr...");

    let publish_transport = NostrTransportBuilder::new(secret_key)
        .relay(&relay_url)
        .build()
        .await?;

    publish_transport.broadcast_ledger_update(&signed_update).await?;

    println!();
    println!("DisputeEnter published successfully!");
    println!("  Dispute opener: {}...", &our_pubkey.to_string()[..16]);
    println!("  Sequence: {} (forked from {})", sequence, last_valid_sequence_u64);
    println!("  Hash: {}...", &hex::encode(new_hash)[..16]);
    println!();
    println!("Ledger is now in DISPUTED state. Quorum has been disbanded.");
    println!();
    println!("Next steps:");
    println!("  1. Rebuild quorum: recovery rebuild {}", &ledger_id[..16]);
    println!("  2. Collect attestations from new quorum members");
    println!("  3. Pre-commit: recovery arm {}", &ledger_id[..16]);

    Ok(())
}

/// Rebuild the quorum during a dispute.
pub async fn recovery_rebuild(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.is_empty() {
        eprintln!("Usage: deposits-node recovery rebuild <ledger_id> <quorum-add|attestation|status> [args...]");
        eprintln!();
        eprintln!("Subcommands:");
        eprintln!("  quorum-add <member_pubkey>     Add a quorum member to your dispute branch");
        eprintln!("  attestation <attestation_json> Record a collateral attestation on your branch");
        eprintln!("  status                         Show current quorum/attestation state");
        return Ok(());
    }

    let ledger_id = args[0].trim().to_string();

    if args.len() < 2 {
        eprintln!("Missing subcommand. Use: quorum-add, attestation, or status");
        return Ok(());
    }

    match args[1].as_str() {
        "quorum-add" => recovery_rebuild_quorum_add(&ledger_id, &args[2..]).await,
        "attestation" => recovery_rebuild_attestation(&ledger_id, &args[2..]).await,
        "status" => recovery_rebuild_status(&ledger_id, &args[2..]).await,
        cmd => {
            eprintln!("Unknown rebuild subcommand: {}", cmd);
            eprintln!("Use: quorum-add, attestation, or status");
            Ok(())
        }
    }
}

/// Add a quorum member to our dispute branch.
/// Usage: recovery rebuild <ledger_id> quorum-add <member_pubkey> <member_ledger_id>
pub async fn recovery_rebuild_quorum_add(ledger_id: &str, args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut member_pubkey_str: Option<String> = None;
    let mut member_ledger_id: Option<String> = None;
    let mut config_args = Vec::new();

    for (i, arg) in args.iter().enumerate() {
        if arg.starts_with("--") {
            config_args.push(arg.clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
            }
        } else if member_pubkey_str.is_none() {
            member_pubkey_str = Some(arg.clone());
        } else if member_ledger_id.is_none() {
            member_ledger_id = Some(arg.clone());
        }
    }

    let member_pubkey_str = member_pubkey_str.ok_or("Missing member_pubkey")?;
    let member_ledger_id = member_ledger_id.ok_or("Missing member_ledger_id (64-char hex hash)")?;
    let member_pubkey = PublicKey::from_str(&member_pubkey_str)
        .map_err(|e| format!("Invalid member pubkey: {}", e))?;

    let config = parse_config(&config_args)?;
    let relay_url = config.relays.first()
        .ok_or("No relay configured. Use --relay <url>")?
        .clone();

    let secp = Secp256k1::new();
    let secret_key = derive_operator_secret(&config.seed, config.network)?;
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let our_pubkey = keypair.public_key();

    println!("Adding quorum member to dispute branch...");
    println!("  Ledger: {}...", &ledger_id[..16.min(ledger_id.len())]);
    println!("  Member: {}...", &member_pubkey_str[..16.min(member_pubkey_str.len())]);

    println!("Fetching ledger from Nostr...");
    let client = get_or_create_client(&relay_url).await?;

    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .custom_tag(crate::nostr::TAG_LEDGER_ID, [crate::nostr::ledger_tag(ledger_id)])
        .limit(500);

    let events = client
        .fetch_events(vec![filter], None)
        .await
        .map_err(|e| format!("Failed to fetch events: {}", e))?;

    let mut our_updates: Vec<SignedLedgerUpdate> = Vec::new();
    for event in events.iter() {
        if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
            if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                if update.operator_id == our_pubkey {
                    our_updates.push(update);
                }
            }
        }
    }

    if our_updates.is_empty() {
        return Err("No updates found from you. Run 'recovery dispute' first.".into());
    }

    our_updates.sort_by_key(|u| u.sequence_number);
    let our_latest = our_updates.last().unwrap().clone();
    println!("  Found {} updates from you, latest at sequence {}", our_updates.len(), our_latest.sequence_number);

    let esplora = EsploraBuilder::new(&config.electrum_url).build_blocking();
    let current_block_height = esplora.get_height()
        .map_err(|e| format!("Failed to get block height: {:?}", e))?;

    let operation = LedgerOperation::QuorumAddMember {
        quorum_member: member_pubkey,
        quorum_member_signature: [0u8; 64],
        member_ledger_id: member_ledger_id.clone(),
        min_fee_bps: None,
        min_fee_fixed: None,
        max_fee_period: None,
        collateral_lock_amount: None,
        collateral_lock_until: None,
        dispute_response_blocks: None,
        dispute_arm_blocks: None,
        service_response_blocks: None,
        max_transfer_timeout_blocks: None,
        max_descriptor_bytes: None,
    };

    let message_bytes = operation.tlv_encode();

    let sequence = our_latest.sequence_number + 1;
    let mut hash_input = Vec::new();
    hash_input.extend_from_slice(&sequence.to_le_bytes());
    hash_input.extend_from_slice(&our_latest.current_hash);
    hash_input.extend_from_slice(&message_bytes);
    let new_hash = *sha256::Hash::hash(&hash_input).as_byte_array();

    let update_msg = format!(
        "deposits:ledger:{}:{}:{}",
        hex::encode(our_latest.current_hash),
        sequence,
        hex::encode(&new_hash)
    );
    let msg_hash = sha256::Hash::hash(update_msg.as_bytes());
    let signature = secp.sign_schnorr(
        &Message::from_digest(*msg_hash.as_ref()),
        &keypair
    );
    let operator_sig_bytes: [u8; 64] = *signature.as_ref();

    let ledger_id_bytes: [u8; 32] = {
        let decoded = hex::decode(ledger_id)
            .map_err(|e| format!("Invalid ledger_id hex: {}", e))?;
        decoded.try_into().map_err(|_| "Ledger ID must be 32 bytes")?
    };

    let signed_update = SignedLedgerUpdate {
        message: message_bytes,
        message_type: deposits_core::messages::consts::QUORUM_ADD_MEMBER,
        operator_signature: operator_sig_bytes,
        cosigner_pubkey: None,
        member_ledger_hash: None,
            cosignatures: Vec::new(),
        cosign_signature: [0u8; 64],
        operator_id: our_pubkey,
        ledger_id: ledger_id_bytes,
        sequence_number: sequence,
        previous_hash: our_latest.current_hash,
        current_hash: new_hash,
        block_height: current_block_height,
        block_hash: [0u8; 32],
    };

    println!("Publishing QuorumAddMember to Nostr...");
    let publishing_keys = Keys::new(nostr_sdk::SecretKey::from_slice(&config.seed)
        .map_err(|e| format!("Invalid key: {}", e))?);
    let publishing_client = Client::new(publishing_keys.clone());
    publishing_client.add_relay(&relay_url).await
        .map_err(|e| format!("Failed to add relay: {}", e))?;
    publishing_client.connect().await;

    let update_bytes = signed_update.tlv_encode();
    let content = BASE64.encode(&update_bytes);

    let event = EventBuilder::new(Kind::Custom(KIND_LEDGER_UPDATE), content)
        .tags(vec![Tag::custom(TagKind::SingleLetter(crate::nostr::TAG_LEDGER_ID), [ledger_id])])
        .sign_with_keys(&publishing_keys)
        .map_err(|e| format!("Failed to sign event: {}", e))?;

    publishing_client.send_event(event).await
        .map_err(|e| format!("Failed to publish: {}", e))?;

    publishing_client.disconnect().await.ok();

    println!();
    println!("QuorumAddMember published!");
    println!("  Sequence: {}", sequence);
    println!("  Member: {}...", &member_pubkey_str[..16.min(member_pubkey_str.len())]);

    Ok(())
}

/// Record a collateral attestation on our dispute branch.
pub async fn recovery_rebuild_attestation(ledger_id: &str, args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut attestation_json: Option<String> = None;
    let mut config_args = Vec::new();

    for (i, arg) in args.iter().enumerate() {
        if arg.starts_with("--") {
            config_args.push(arg.clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
            }
        } else if attestation_json.is_none() {
            attestation_json = Some(arg.clone());
        }
    }

    let attestation_json = attestation_json.ok_or("Missing attestation_json")?;
    let attestation: CollateralAttestationMsg = serde_json::from_str(&attestation_json)
        .map_err(|e| format!("Invalid attestation JSON: {}", e))?;

    let config = parse_config(&config_args)?;
    let relay_url = config.relays.first()
        .ok_or("No relay configured. Use --relay <url>")?
        .clone();

    let secp = Secp256k1::new();
    let secret_key = derive_operator_secret(&config.seed, config.network)?;
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let our_pubkey = keypair.public_key();

    println!("Recording collateral attestation on dispute branch...");
    println!("  Ledger: {}...", &ledger_id[..16.min(ledger_id.len())]);
    println!("  From: {}...", &attestation.operator.to_string()[..16]);
    println!("  Amount: {} msats", attestation.amount);
    println!("  Lock until: block {}", attestation.lock_until_block);

    println!("Fetching ledger from Nostr...");
    let client = get_or_create_client(&relay_url).await?;

    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .custom_tag(crate::nostr::TAG_LEDGER_ID, [crate::nostr::ledger_tag(ledger_id)])
        .limit(500);

    let events = client
        .fetch_events(vec![filter], None)
        .await
        .map_err(|e| format!("Failed to fetch events: {}", e))?;

    let mut our_updates: Vec<SignedLedgerUpdate> = Vec::new();
    for event in events.iter() {
        if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
            if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                if update.operator_id == our_pubkey {
                    our_updates.push(update);
                }
            }
        }
    }

    if our_updates.is_empty() {
        return Err("No updates found from you. Run 'recovery dispute' first.".into());
    }

    our_updates.sort_by_key(|u| u.sequence_number);
    let our_latest = our_updates.last().unwrap().clone();
    println!("  Found {} updates from you, latest at sequence {}", our_updates.len(), our_latest.sequence_number);

    let esplora = EsploraBuilder::new(&config.electrum_url).build_blocking();
    let current_block_height = esplora.get_height()
        .map_err(|e| format!("Failed to get block height: {:?}", e))?;

    let operation = LedgerOperation::CollateralAttestation {
        collateral_operator: attestation.operator,
        quorum_member: attestation.quorum_member,
        collateral_ledger_id: attestation.collateral_ledger_id.clone(),
        amount: attestation.amount,
        block_height: attestation.block_height,
        lock_until_block: attestation.lock_until_block,
        signature: attestation.signature,
        ledger_hash: attestation.ledger_hash,
    };

    let message_bytes = operation.tlv_encode();

    let sequence = our_latest.sequence_number + 1;
    let mut hash_input = Vec::new();
    hash_input.extend_from_slice(&sequence.to_le_bytes());
    hash_input.extend_from_slice(&our_latest.current_hash);
    hash_input.extend_from_slice(&message_bytes);
    let new_hash = *sha256::Hash::hash(&hash_input).as_byte_array();

    let update_msg = format!(
        "deposits:ledger:{}:{}:{}",
        hex::encode(our_latest.current_hash),
        sequence,
        hex::encode(&new_hash)
    );
    let msg_hash = sha256::Hash::hash(update_msg.as_bytes());
    let signature = secp.sign_schnorr(
        &Message::from_digest(*msg_hash.as_ref()),
        &keypair
    );
    let operator_sig_bytes: [u8; 64] = *signature.as_ref();

    let ledger_id_bytes: [u8; 32] = {
        let decoded = hex::decode(ledger_id)
            .map_err(|e| format!("Invalid ledger_id hex: {}", e))?;
        decoded.try_into().map_err(|_| "Ledger ID must be 32 bytes")?
    };

    let signed_update = SignedLedgerUpdate {
        message: message_bytes,
        message_type: deposits_core::messages::consts::COLLATERAL_ATTESTATION,
        operator_signature: operator_sig_bytes,
        cosigner_pubkey: None,
        member_ledger_hash: None,
            cosignatures: Vec::new(),
        cosign_signature: [0u8; 64],
        operator_id: our_pubkey,
        ledger_id: ledger_id_bytes,
        sequence_number: sequence,
        previous_hash: our_latest.current_hash,
        current_hash: new_hash,
        block_height: current_block_height,
        block_hash: [0u8; 32],
    };

    println!("Publishing CollateralAttestation to Nostr...");
    let publishing_keys = Keys::new(nostr_sdk::SecretKey::from_slice(&config.seed)
        .map_err(|e| format!("Invalid key: {}", e))?);
    let publishing_client = Client::new(publishing_keys.clone());
    publishing_client.add_relay(&relay_url).await
        .map_err(|e| format!("Failed to add relay: {}", e))?;
    publishing_client.connect().await;

    let update_bytes = signed_update.tlv_encode();
    let content = BASE64.encode(&update_bytes);

    let event = EventBuilder::new(Kind::Custom(KIND_LEDGER_UPDATE), content)
        .tags(vec![Tag::custom(TagKind::SingleLetter(crate::nostr::TAG_LEDGER_ID), [ledger_id])])
        .sign_with_keys(&publishing_keys)
        .map_err(|e| format!("Failed to sign event: {}", e))?;

    publishing_client.send_event(event).await
        .map_err(|e| format!("Failed to publish: {}", e))?;

    publishing_client.disconnect().await.ok();

    println!();
    println!("CollateralAttestation published!");
    println!("  Sequence: {}", sequence);
    println!("  From: {}...", &attestation.operator.to_string()[..16]);
    println!("  Amount: {} msats", attestation.amount);
    println!();
    println!("Once you have enough attestations, run:");
    println!("  recovery arm {}...", &ledger_id[..16.min(ledger_id.len())]);

    Ok(())
}

/// Show the current quorum/attestation status on our dispute branch.
pub async fn recovery_rebuild_status(ledger_id: &str, args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let config = parse_config(args)?;
    let relay_url = config.relays.first()
        .ok_or("No relay configured. Use --relay <url>")?
        .clone();

    let secp = Secp256k1::new();
    let secret_key = derive_operator_secret(&config.seed, config.network)?;
    let our_pubkey = PublicKey::from_secret_key(&secp, &secret_key);

    println!("Checking dispute branch status for ledger: {}...", &ledger_id[..16.min(ledger_id.len())]);

    let client = get_or_create_client(&relay_url).await?;

    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .custom_tag(crate::nostr::TAG_LEDGER_ID, [crate::nostr::ledger_tag(ledger_id)])
        .limit(500);

    let events = client
        .fetch_events(vec![filter], None)
        .await
        .map_err(|e| format!("Failed to fetch events: {}", e))?;


    let mut our_updates: Vec<SignedLedgerUpdate> = Vec::new();
    let mut quorum_members: Vec<PublicKey> = Vec::new();
    let mut attestations: Vec<(PublicKey, u64, u32)> = Vec::new();
    let mut has_dispute = false;
    let mut has_armed = false;

    for event in events.iter() {
        if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
            if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                if update.operator_id == our_pubkey {
                    if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                        match op {
                            LedgerOperation::DisputeEnter { .. } => has_dispute = true,
                            LedgerOperation::DisputeArmed { .. } => has_armed = true,
                            LedgerOperation::QuorumAddMember { quorum_member, .. } => {
                                if !quorum_members.contains(&quorum_member) {
                                    quorum_members.push(quorum_member);
                                }
                            }
                            LedgerOperation::CollateralAttestation { collateral_operator, amount, lock_until_block, .. } => {
                                attestations.push((collateral_operator, amount, lock_until_block));
                            }
                            _ => {}
                        }
                    }
                    our_updates.push(update);
                }
            }
        }
    }

    println!();
    if our_updates.is_empty() {
        println!("No updates found from you on this ledger.");
        println!("Run 'recovery dispute <ledger_id>' first to open a dispute.");
        return Ok(());
    }

    println!("Your dispute branch status:");
    println!("  Updates: {}", our_updates.len());
    println!("  Has DisputeEnter: {}", if has_dispute { "yes" } else { "NO - run 'recovery dispute' first" });
    println!("  Has DisputeArmed: {}", if has_armed { "yes (locked in)" } else { "no" });
    println!();
    println!("Quorum members: {}", quorum_members.len());
    for member in &quorum_members {
        println!("  - {}...", &member.to_string()[..16]);
    }
    println!();
    println!("Collateral attestations: {}", attestations.len());
    for (op, amount, until) in &attestations {
        println!("  - {}... {} msats until block {}", &op.to_string()[..16], amount, until);
    }
    println!();

    if !has_dispute {
        println!("Next: Run 'recovery dispute <ledger_id>' to open a dispute.");
    } else if quorum_members.is_empty() {
        println!("Next: Add quorum members with 'recovery rebuild <ledger_id> quorum-add <pubkey>'");
    } else if attestations.is_empty() {
        println!("Next: Get attestations and record with 'recovery rebuild <ledger_id> attestation <json>'");
    } else if !has_armed {
        println!("Ready to arm! Run 'recovery arm <ledger_id>'");
    } else {
        println!("You are armed. Wait for the entropy block, then run 'recovery claim <ledger_id>'");
    }

    Ok(())
}

/// Publish DisputeArmed to pre-commit for entropy selection.
pub async fn recovery_arm(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use rand::Rng;

    let mut ledger_id: Option<String> = None;
    let mut target_reserves: Option<String> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--target-reserves" | "--target" => {
                if i + 1 < args.len() {
                    target_reserves = Some(args[i + 1].clone());
                    i += 1;
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

    let ledger_id = ledger_id.ok_or("Missing ledger_id")?.trim().to_string();
    let config = parse_config(&config_args)?;
    let relay_url = config.relays.first()
        .ok_or("No relay configured. Use --relay <url>")?
        .clone();

    let secp = Secp256k1::new();
    let secret_key = derive_operator_secret(&config.seed, config.network)?;
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let our_pubkey = keypair.public_key();

    println!("Arming (pre-committing) for ledger: {}...", &ledger_id[..16.min(ledger_id.len())]);

    println!("Fetching ledger from Nostr...");
    let client = get_or_create_client(&relay_url).await?;

    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .custom_tag(crate::nostr::TAG_LEDGER_ID, [crate::nostr::ledger_tag(ledger_id.as_str())])
        .limit(500);

    let events = client
        .fetch_events(vec![filter], None)
        .await
        .map_err(|e| format!("Failed to fetch events: {}", e))?;


    let mut our_updates: Vec<SignedLedgerUpdate> = Vec::new();
    for event in events.iter() {
        if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
            if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                if update.operator_id == our_pubkey {
                    our_updates.push(update);
                }
            }
        }
    }
    our_updates.sort_by_key(|u| u.sequence_number);

    if our_updates.is_empty() {
        return Err("No updates found from you. Did you run 'recovery dispute' first?".into());
    }

    let latest = our_updates.last().unwrap();
    println!("  Found {} updates from you", our_updates.len());
    println!("  Latest sequence: {}", latest.sequence_number);

    let esplora = EsploraBuilder::new(&config.electrum_url).build_blocking();
    let current_block_height = esplora.get_height()
        .map_err(|e| format!("Failed to get block height: {:?}", e))?;

    // Generate random preimage (17-20 bytes for lottery entropy)
    let mut rng = rand::thread_rng();
    let preimage_len = rng.gen_range(17..=20);
    let mut preimage = vec![0u8; preimage_len];
    rng.fill(&mut preimage[..]);

    // Compute commitment_hash = HASH160(preimage)
    let commitment_hash: [u8; 20] = *hash160::Hash::hash(&preimage).as_byte_array();

    // Get target_reserves address
    let target_reserves_addr = if let Some(addr) = target_reserves {
        addr
    } else {
        use bitcoin::Address;
        let pubkey_bytes: [u8; 33] = our_pubkey.serialize();
        let compressed = bitcoin::CompressedPublicKey::from_slice(&pubkey_bytes)
            .map_err(|e| format!("Invalid pubkey: {}", e))?;
        Address::p2wpkh(&compressed, config.network).to_string()
    };

    // Store preimage for later reveal
    let preimage_file = format!("{}/lottery_preimage_{}.hex",
        config.data_dir.display(),
        &ledger_id[..16.min(ledger_id.len())]);
    std::fs::write(&preimage_file, hex::encode(&preimage))
        .map_err(|e| format!("Failed to store preimage: {}", e))?;
    println!("  Stored lottery preimage in: {}", preimage_file);

    let custody_armed = LedgerOperation::DisputeArmed {
        armed_block: current_block_height,
        commitment_hash,
        target_reserves: target_reserves_addr.clone(),
    };

    let message_bytes = custody_armed.tlv_encode();

    let sequence = latest.sequence_number + 1;
    let mut hash_input = Vec::new();
    hash_input.extend_from_slice(&sequence.to_le_bytes());
    hash_input.extend_from_slice(&latest.current_hash);
    hash_input.extend_from_slice(&message_bytes);
    let new_hash = *sha256::Hash::hash(&hash_input).as_byte_array();

    let update_msg = format!(
        "deposits:ledger:{}:{}:{}",
        hex::encode(latest.current_hash),
        sequence,
        hex::encode(&new_hash)
    );
    let msg_hash = sha256::Hash::hash(update_msg.as_bytes());
    let signature = secp.sign_schnorr(
        &Message::from_digest(*msg_hash.as_ref()),
        &keypair
    );
    let operator_sig_bytes: [u8; 64] = *signature.as_ref();

    let ledger_id_bytes: [u8; 32] = {
        let decoded = hex::decode(&ledger_id)
            .map_err(|e| format!("Invalid ledger_id hex: {}", e))?;
        decoded.try_into().map_err(|_| "Ledger ID must be 32 bytes")?
    };

    let signed_update = SignedLedgerUpdate {
        message: message_bytes,
        message_type: 0x8001,
        operator_signature: operator_sig_bytes,
        cosigner_pubkey: None,
        member_ledger_hash: None,
            cosignatures: Vec::new(),
        cosign_signature: [0u8; 64],
        operator_id: our_pubkey,
        ledger_id: ledger_id_bytes,
        sequence_number: sequence,
        previous_hash: latest.current_hash,
        current_hash: new_hash,
        block_height: current_block_height,
        block_hash: [0u8; 32],
    };

    println!();
    println!("Publishing DisputeArmed to Nostr...");

    let publish_transport = NostrTransportBuilder::new(secret_key)
        .relay(&relay_url)
        .build()
        .await?;

    publish_transport.broadcast_ledger_update(&signed_update).await?;

    let entropy_block = current_block_height + 6;

    println!();
    println!("DisputeArmed published successfully!");
    println!("  Armed block: {}", current_block_height);
    println!("  Sequence: {}", sequence);
    println!("  Hash: {}...", &hex::encode(new_hash)[..16]);
    println!();
    println!("Ledger is now in ARMED state. Quorum is locked.");
    println!();
    println!("Next steps:");
    println!("  1. Wait for entropy block: {} (current: {})", entropy_block, current_block_height);
    println!("  2. After entropy block: recovery claim {}", &ledger_id[..16]);

    Ok(())
}

/// Claim custody after entropy block - publish DisputeAcquire (winner) or DisputeYield (loser).
pub async fn recovery_claim_new(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut ledger_id: Option<String> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
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

    let ledger_id = ledger_id.ok_or("Missing ledger_id")?.trim().to_string();
    let config = parse_config(&config_args)?;
    let relay_url = config.relays.first()
        .ok_or("No relay configured. Use --relay <url>")?
        .clone();

    let secp = Secp256k1::new();
    let secret_key = derive_operator_secret(&config.seed, config.network)?;
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let our_pubkey = keypair.public_key();

    println!("Claiming custody for ledger: {}...", &ledger_id[..16.min(ledger_id.len())]);

    println!("Fetching ledger from Nostr...");
    let client = get_or_create_client(&relay_url).await?;

    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .custom_tag(crate::nostr::TAG_LEDGER_ID, [crate::nostr::ledger_tag(ledger_id.as_str())])
        .limit(500);

    let events = client
        .fetch_events(vec![filter], None)
        .await
        .map_err(|e| format!("Failed to fetch events: {}", e))?;


    // Find all DisputeArmed candidates
    let mut candidates: Vec<(PublicKey, u32, SignedLedgerUpdate)> = Vec::new();
    let mut our_latest: Option<SignedLedgerUpdate> = None;
    let mut our_armed_block: Option<u32> = None;

    for event in events.iter() {
        if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
            if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                    if let LedgerOperation::DisputeArmed { armed_block, .. } = op {
                        candidates.push((update.operator_id, armed_block, update.clone()));
                        if update.operator_id == our_pubkey {
                            our_armed_block = Some(armed_block);
                        }
                    }
                }

                if update.operator_id == our_pubkey {
                    if our_latest.is_none() || update.sequence_number > our_latest.as_ref().unwrap().sequence_number {
                        our_latest = Some(update);
                    }
                }
            }
        }
    }

    if candidates.is_empty() {
        return Err("No DisputeArmed candidates found.".into());
    }

    let our_latest = our_latest.ok_or("No updates found from you")?;
    if our_armed_block.is_none() {
        return Err("You haven't published DisputeArmed yet. Run 'recovery arm' first.".into());
    }

    println!("  Found {} armed candidates", candidates.len());
    for (pk, block, _) in &candidates {
        let marker = if *pk == our_pubkey { " (you)" } else { "" };
        println!("    - {}... armed at block {}{}", &pk.to_string()[..16], block, marker);
    }

    let esplora = EsploraBuilder::new(&config.electrum_url).build_blocking();
    let current_block_height = esplora.get_height()
        .map_err(|e| format!("Failed to get block height: {:?}", e))?;

    let earliest_armed = candidates.iter().map(|(_, b, _)| *b).min().unwrap();
    let entropy_block_height = earliest_armed + 6;

    if current_block_height < entropy_block_height {
        println!();
        println!("Entropy block not yet mined!");
        println!("  Current block: {}", current_block_height);
        println!("  Entropy block: {} (need {} more blocks)", entropy_block_height, entropy_block_height - current_block_height);
        println!();
        println!("Please wait for the entropy block to be mined, then run this command again.");
        return Ok(());
    }

    let entropy_block_hash_hex = esplora.get_block_hash(entropy_block_height)
        .map_err(|e| format!("Failed to get entropy block hash: {:?}", e))?;
    let entropy_block_hash: [u8; 32] = {
        let hash_bytes = entropy_block_hash_hex.to_byte_array();
        let mut reversed = hash_bytes;
        reversed.reverse();
        reversed
    };

    println!();
    println!("Entropy block: {} (hash: {}...)", entropy_block_height, hex::encode(&entropy_block_hash[..8]));

    let eligible_candidates: Vec<PublicKey> = candidates.iter()
        .filter(|(_, armed_block, _)| *armed_block < entropy_block_height)
        .map(|(pk, _, _)| *pk)
        .collect();

    if eligible_candidates.is_empty() {
        return Err("No eligible candidates".into());
    }

    let winner = select_entropy_winner(&entropy_block_hash, &eligible_candidates)
        .ok_or("Failed to select winner")?;

    let we_won = winner == our_pubkey;

    println!();
    println!("Entropy selection result:");
    println!("  Winner: {}...", &winner.to_string()[..16]);
    println!();

    if we_won {
        println!("YOU WON! Publishing DisputeAcquire...");

        let operation = LedgerOperation::DisputeAcquire {
            new_custodian: our_pubkey,
            entropy_block_height,
            entropy_block_hash,
            spend_txid: [0u8; 32],
            new_reserves_address: String::new(),
        };

        let message_bytes = operation.tlv_encode();

        let sequence = our_latest.sequence_number + 1;
        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(&sequence.to_le_bytes());
        hash_input.extend_from_slice(&our_latest.current_hash);
        hash_input.extend_from_slice(&message_bytes);
        let new_hash = *sha256::Hash::hash(&hash_input).as_byte_array();

        let update_msg = format!(
            "deposits:ledger:{}:{}:{}",
            hex::encode(our_latest.current_hash),
            sequence,
            hex::encode(&new_hash)
        );
        let msg_hash = sha256::Hash::hash(update_msg.as_bytes());
        let signature = secp.sign_schnorr(
            &Message::from_digest(*msg_hash.as_ref()),
            &keypair
        );
        let operator_sig_bytes: [u8; 64] = *signature.as_ref();

        let ledger_id_bytes: [u8; 32] = {
            let decoded = hex::decode(&ledger_id)
                .map_err(|e| format!("Invalid ledger_id hex: {}", e))?;
            decoded.try_into().map_err(|_| "Ledger ID must be 32 bytes")?
        };

        let signed_update = SignedLedgerUpdate {
            message: message_bytes,
            message_type: 0x8001,
            operator_signature: operator_sig_bytes,
            cosigner_pubkey: None,
            member_ledger_hash: None,
            cosignatures: Vec::new(),
            cosign_signature: [0u8; 64],
            operator_id: our_pubkey,
            ledger_id: ledger_id_bytes,
            sequence_number: sequence,
            previous_hash: our_latest.current_hash,
            current_hash: new_hash,
                block_height: current_block_height,
            block_hash: entropy_block_hash,
        };

        let publish_transport = NostrTransportBuilder::new(secret_key)
            .relay(&relay_url)
            .build()
            .await?;

        publish_transport.broadcast_ledger_update(&signed_update).await?;

        println!();
        println!("DisputeAcquire published successfully!");
        println!("  Sequence: {}", sequence);
        println!("  Hash: {}...", &hex::encode(new_hash)[..16]);
    } else {
        println!("You did NOT win. Publishing DisputeYield...");

        let operation = LedgerOperation::DisputeYield;
        let message_bytes = operation.tlv_encode();

        let sequence = our_latest.sequence_number + 1;
        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(&sequence.to_le_bytes());
        hash_input.extend_from_slice(&our_latest.current_hash);
        hash_input.extend_from_slice(&message_bytes);
        let new_hash = *sha256::Hash::hash(&hash_input).as_byte_array();

        let update_msg = format!(
            "deposits:ledger:{}:{}:{}",
            hex::encode(our_latest.current_hash),
            sequence,
            hex::encode(&new_hash)
        );
        let msg_hash = sha256::Hash::hash(update_msg.as_bytes());
        let signature = secp.sign_schnorr(
            &Message::from_digest(*msg_hash.as_ref()),
            &keypair
        );
        let operator_sig_bytes: [u8; 64] = *signature.as_ref();

        let ledger_id_bytes: [u8; 32] = {
            let decoded = hex::decode(&ledger_id)
                .map_err(|e| format!("Invalid ledger_id hex: {}", e))?;
            decoded.try_into().map_err(|_| "Ledger ID must be 32 bytes")?
        };

        let signed_update = SignedLedgerUpdate {
            message: message_bytes,
            message_type: 0x8001,
            operator_signature: operator_sig_bytes,
            cosigner_pubkey: None,
            member_ledger_hash: None,
            cosignatures: Vec::new(),
            cosign_signature: [0u8; 64],
            operator_id: our_pubkey,
            ledger_id: ledger_id_bytes,
            sequence_number: sequence,
            previous_hash: our_latest.current_hash,
            current_hash: new_hash,
                block_height: current_block_height,
            block_hash: entropy_block_hash,
        };

        let publish_transport = NostrTransportBuilder::new(secret_key)
            .relay(&relay_url)
            .build()
            .await?;

        publish_transport.broadcast_ledger_update(&signed_update).await?;

        println!();
        println!("DisputeYield published successfully!");
        println!("  Sequence: {}", sequence);
        println!("  Hash: {}...", &hex::encode(new_hash)[..16]);
        println!();
        println!("Your branch is now TOMBSTONED.");
    }

    Ok(())
}

/// Continue the ledger after winning custody
pub async fn recovery_continue(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut ledger_id: Option<String> = None;
    let mut count: u32 = 2;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--count" => {
                if i + 1 < args.len() {
                    count = args[i + 1].parse().unwrap_or(2);
                    i += 1;
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

    let ledger_id = ledger_id.ok_or("Missing ledger_id")?.trim().to_string();
    let config = parse_config(&config_args)?;
    let relay_url = config.relays.first()
        .ok_or("No relay configured. Use --relay <url>")?
        .clone();

    let secp = Secp256k1::new();
    let secret_key = derive_operator_secret(&config.seed, config.network)?;
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let our_pubkey = keypair.public_key();

    println!("Continuing ledger: {}... (adding {} operations)", &ledger_id[..16.min(ledger_id.len())], count);

    println!("Fetching ledger from Nostr...");
    let client = get_or_create_client(&relay_url).await?;

    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .custom_tag(crate::nostr::TAG_LEDGER_ID, [crate::nostr::ledger_tag(ledger_id.as_str())])
        .limit(500);

    let events = client
        .fetch_events(vec![filter], None)
        .await
        .map_err(|e| format!("Failed to fetch events: {}", e))?;


    let mut our_latest: Option<SignedLedgerUpdate> = None;
    let mut has_custody_acquire = false;
    let mut original_deposit_ids: Vec<deposits_core::types::DepositId> = Vec::new();

    for event in events.iter() {
        if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
            if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                    if let LedgerOperation::DepositOpen { deposit_id, .. } = op {
                        if !original_deposit_ids.contains(&deposit_id) {
                            original_deposit_ids.push(deposit_id);
                        }
                    }
                }

                if update.operator_id == our_pubkey {
                    if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                        if matches!(op, LedgerOperation::DisputeAcquire { .. }) {
                            has_custody_acquire = true;
                        }
                    }
                    if our_latest.is_none() || update.sequence_number > our_latest.as_ref().unwrap().sequence_number {
                        our_latest = Some(update);
                    }
                }
            }
        }
    }

    let mut latest = our_latest.ok_or("No updates found from you. Did you win custody?")?;

    if !has_custody_acquire {
        return Err("You don't have DisputeAcquire. You must win custody first (recovery claim).".into());
    }

    println!("  Your latest: seq {} (hash: {}...)", latest.sequence_number, hex::encode(&latest.current_hash[..8]));

    // Use first deposit_id or derive from our pubkey
    let deposit_id = original_deposit_ids.first().copied().unwrap_or_else(|| {
        let descriptor = format!("pk({})", hex::encode(our_pubkey.serialize()));
        deposits_core::types::compute_deposit_id(&descriptor)
    });

    let esplora = EsploraBuilder::new(&config.electrum_url).build_blocking();
    let current_block_height = esplora.get_height()
        .map_err(|e| format!("Failed to get block height: {:?}", e))?;
    let block_hash_hex = esplora.get_block_hash(current_block_height)
        .map_err(|e| format!("Failed to get block hash: {:?}", e))?;
    let block_hash: [u8; 32] = {
        let hash_bytes = block_hash_hex.to_byte_array();
        let mut reversed = hash_bytes;
        reversed.reverse();
        reversed
    };

    let ledger_id_bytes: [u8; 32] = {
        let decoded = hex::decode(&ledger_id)
            .map_err(|e| format!("Invalid ledger_id hex: {}", e))?;
        decoded.try_into().map_err(|_| "Ledger ID must be 32 bytes")?
    };

    let publish_transport = NostrTransportBuilder::new(secret_key)
        .relay(&relay_url)
        .build()
        .await?;

    println!();
    println!("Adding {} continuation operations...", count);

    for op_num in 0..count {
        let mut payment_hash = [0u8; 32];
        payment_hash[0..8].copy_from_slice(&(op_num as u64).to_le_bytes());
        payment_hash[8..16].copy_from_slice(&latest.current_hash[0..8]);

        let operation = LedgerOperation::InvoiceCredit {
            payment_hash,
            deposit_id,
            amount: 50000 + (op_num as u64 * 10000),
            invoice_id: format!("post-recovery-{}", op_num + 1),
            sequence_number: latest.sequence_number + 1,
        };

        let message_bytes = operation.tlv_encode();

        let sequence = latest.sequence_number + 1;
        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(&sequence.to_le_bytes());
        hash_input.extend_from_slice(&latest.current_hash);
        hash_input.extend_from_slice(&message_bytes);
        let new_hash = *sha256::Hash::hash(&hash_input).as_byte_array();

        let update_msg = format!(
            "deposits:ledger:{}:{}:{}",
            hex::encode(latest.current_hash),
            sequence,
            hex::encode(&new_hash)
        );
        let msg_hash = sha256::Hash::hash(update_msg.as_bytes());
        let signature = secp.sign_schnorr(
            &Message::from_digest(*msg_hash.as_ref()),
            &keypair
        );
        let operator_sig_bytes: [u8; 64] = *signature.as_ref();

        let signed_update = SignedLedgerUpdate {
            message: message_bytes,
            message_type: 0x8001,
            operator_signature: operator_sig_bytes,
            cosigner_pubkey: None,
            member_ledger_hash: None,
            cosignatures: Vec::new(),
            cosign_signature: [0u8; 64],
            operator_id: our_pubkey,
            ledger_id: ledger_id_bytes,
            sequence_number: sequence,
            previous_hash: latest.current_hash,
            current_hash: new_hash,
                block_height: current_block_height,
            block_hash,
        };

        publish_transport.broadcast_ledger_update(&signed_update).await?;

        println!("  [{}/{}] seq {} - InvoiceCredit {} msat", op_num + 1, count, sequence, 50000 + (op_num as u64 * 10000));

        latest = signed_update;
    }

    println!();
    println!("Ledger continued successfully!");
    println!("  New latest: seq {} (hash: {}...)", latest.sequence_number, hex::encode(&latest.current_hash[..8]));

    Ok(())
}

// =============================================================================
// LOTTERY PROTOCOL COMMANDS
// =============================================================================

/// Build and broadcast the confiscation transaction (reserves -> lottery output).
pub async fn recovery_confiscate(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use bitcoin::secp256k1::{Keypair, Secp256k1, PublicKey, XOnlyPublicKey};
    use deposits_core::{TlvDecode, SignedLedgerUpdate};
    use deposits_core::messages::LedgerOperation;
    use deposits_core::tapscript_reserves::{LotteryScriptBuilder, LotteryParticipant};
    use crate::nostr::{NostrTransportBuilder, KIND_LEDGER_UPDATE};
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use nostr_sdk::prelude::*;

    let mut ledger_id: Option<String> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
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

    let ledger_id = ledger_id.ok_or("Missing ledger_id")?.trim().to_string();
    let config = parse_config(&config_args)?;
    let relay_url = config.relays.first()
        .ok_or("No relay configured. Use --relay <url>")?
        .clone();

    let secp = Secp256k1::new();
    let secret_key = derive_operator_secret(&config.seed, config.network)?;
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let our_pubkey = keypair.public_key();

    println!("Building confiscation transaction for ledger: {}...", &ledger_id[..16.min(ledger_id.len())]);

    // Fetch all updates from Nostr
    println!("Fetching ledger from Nostr...");
    let client = get_or_create_client(&relay_url).await?;

    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .custom_tag(crate::nostr::TAG_LEDGER_ID, [crate::nostr::ledger_tag(ledger_id.as_str())])
        .limit(500);

    let events = client
        .fetch_events(vec![filter], None)
        .await
        .map_err(|e| format!("Failed to fetch events: {}", e))?;


    // Extract DisputeArmed data and quorum info
    let mut participants: Vec<LotteryParticipant> = Vec::new();
    let mut quorum_members: Vec<PublicKey> = Vec::new();
    let mut reserves_address: Option<String> = None;
    let mut ledger_hash: Option<[u8; 32]> = None;
    let mut original_operator: Option<PublicKey> = None;

    for event in events.iter() {
        if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
            if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                    match op {
                        LedgerOperation::LedgerOpen { operator_id, .. } => {
                            original_operator = Some(operator_id);
                        }
                        LedgerOperation::QuorumAddMember { quorum_member, .. } => {
                            if !quorum_members.contains(&quorum_member) {
                                quorum_members.push(quorum_member);
                            }
                        }
                        LedgerOperation::QuorumBegin { reserves_id, ledger_hash: lh, .. } => {
                            reserves_address = Some(reserves_id);
                            ledger_hash = Some(lh);
                        }
                        LedgerOperation::DisputeArmed { commitment_hash, target_reserves, .. } => {
                            let x_only = update.operator_id.x_only_public_key().0;
                            participants.push(LotteryParticipant::new(
                                x_only,
                                commitment_hash,
                                target_reserves,
                            ));
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    if participants.len() < 2 {
        return Err(format!("Need at least 2 DisputeArmed participants, found {}", participants.len()).into());
    }

    // Sort participants by pubkey for deterministic order
    participants.sort_by(|a, b| a.pubkey.serialize().cmp(&b.pubkey.serialize()));

    // Debug: print participant order
    println!("  Participant order (confiscate):");
    for (i, p) in participants.iter().enumerate() {
        println!("    {}: {}...", i, hex::encode(&p.pubkey.serialize()[..8]));
    }

    let original_operator = original_operator.ok_or("Could not find original operator")?;
    let reserves_address_str = reserves_address.ok_or("No reserves address found")?;
    let _ledger_hash = ledger_hash.ok_or("Could not find ledger_hash")?;

    println!("  Found {} lottery participants", participants.len());
    println!("  Reserves address: {}...", &reserves_address_str[..20.min(reserves_address_str.len())]);

    // Build recovery voters (quorum minus original operator)
    let recovery_voters: Vec<XOnlyPublicKey> = quorum_members.iter()
        .filter(|pk| **pk != original_operator)
        .map(|pk| pk.x_only_public_key().0)
        .collect();

    let recovery_threshold = (recovery_voters.len() / 2) + 1;

    // Build the lottery output
    let lottery_builder = LotteryScriptBuilder::new(
        participants.clone(),
        recovery_voters,
        recovery_threshold,
        config.network,
    );

    let lottery_output = lottery_builder.build()
        .map_err(|e| format!("Failed to build lottery output: {:?}", e))?;

    println!("  Lottery address: {}", lottery_output.address);

    // Look up reserves UTXO
    use bdk_esplora::esplora_client::Builder as EsploraBuilder;
    let esplora = EsploraBuilder::new(&config.electrum_url).build_blocking();

    let reserves_addr: bitcoin::Address<bitcoin::address::NetworkUnchecked> = reserves_address_str.parse()
        .map_err(|e| format!("Invalid reserves address: {}", e))?;
    let reserves_addr = reserves_addr.require_network(config.network)
        .map_err(|e| format!("Address network mismatch: {}", e))?;

    let script_pubkey = reserves_addr.script_pubkey();
    let utxos = esplora.scripthash_txs(&script_pubkey, None)
        .map_err(|e| format!("Failed to query Esplora: {:?}", e))?;

    // Find unspent output
    let mut reserves_utxo: Option<(bitcoin::OutPoint, u64)> = None;
    for tx in &utxos {
        for (vout, output) in tx.vout.iter().enumerate() {
            if output.scriptpubkey == script_pubkey {
                let outpoint = bitcoin::OutPoint::new(tx.txid, vout as u32);
                let status = esplora.get_output_status(&tx.txid, vout as u64)
                    .map_err(|e| format!("Failed to check output status: {:?}", e))?;
                if status.map(|s| !s.spent).unwrap_or(true) {
                    reserves_utxo = Some((outpoint, output.value));
                    break;
                }
            }
        }
        if reserves_utxo.is_some() { break; }
    }

    let (reserves_outpoint, reserves_amount) = reserves_utxo
        .ok_or("No unspent reserves found")?;

    println!("  Found reserves: {} sats at {}", reserves_amount, reserves_outpoint);

    // Build confiscation transaction
    use bitcoin::{Transaction, TxIn, TxOut, Sequence, Witness, Amount};

    let fee_rate = 2u64;
    let estimated_vsize = 200u64;
    let fee = fee_rate * estimated_vsize;
    let output_amount = reserves_amount.saturating_sub(fee);

    let confiscation_tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: reserves_outpoint,
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::default(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(output_amount),
            script_pubkey: lottery_output.script_pubkey(),
        }],
    };

    // Build the Taproot reserves structure for signing
    use deposits_core::{VoterSet, ThresholdConfig, TapscriptReservesBuilder};
    use bitcoin::sighash::{SighashCache, TapSighashType};

    let ledger_hash_val = ledger_hash.ok_or("Could not find ledger_hash")?;
    let voter_set = VoterSet::new(original_operator, quorum_members.clone());
    let voter_count = voter_set.all_voters().len();
    let threshold_config = ThresholdConfig::default_for_voter_count(voter_count);

    let taproot_builder = TapscriptReservesBuilder::new(
        voter_set.clone(),
        threshold_config.clone(),
        config.network,
        ledger_hash_val,
    );

    let taproot_output = taproot_builder.build()
        .map_err(|e| format!("Failed to build Taproot output: {:?}", e))?;

    // Use quorum-override tier (threshold without tie-breaker)
    let (tier_index, tier) = threshold_config.tiers.iter()
        .enumerate()
        .find(|(_, t)| !t.requires_tie_breaker && t.threshold > 1)
        .ok_or("No quorum-override tier found")?;

    println!("  Using Tier {} for confiscation (threshold={}/{})",
        tier_index, tier.threshold, voter_count);

    // Build leaf script and compute sighash
    let leaf_script = taproot_builder.build_threshold_leaf(tier)
        .map_err(|e| format!("Failed to build leaf script: {:?}", e))?;

    let leaf_hash = bitcoin::taproot::TapLeafHash::from_script(&leaf_script, bitcoin::taproot::LeafVersion::TapScript);

    let prevouts = vec![TxOut {
        value: Amount::from_sat(reserves_amount),
        script_pubkey: reserves_addr.script_pubkey(),
    }];

    let mut confiscation_tx = confiscation_tx; // Make mutable
    let mut sighash_cache = SighashCache::new(&confiscation_tx);
    let sighash = sighash_cache.taproot_script_spend_signature_hash(
        0,
        &bitcoin::sighash::Prevouts::All(&prevouts),
        leaf_hash,
        TapSighashType::Default,
    ).map_err(|e| format!("Failed to compute sighash: {}", e))?;

    let sighash_bytes: [u8; 32] = *sighash.as_ref();

    // Sign with our key
    let msg = bitcoin::secp256k1::Message::from_digest(sighash_bytes);
    let our_signature = secp.sign_schnorr(&msg, &keypair);

    let mut signatures = std::collections::HashMap::new();
    signatures.insert(our_pubkey, our_signature.serialize());

    println!("  Signed with our key");

    // Request signatures from other quorum members
    let required_sigs = tier.threshold;
    println!("  Need {}/{} signatures", required_sigs, voter_count);

    let publish_transport = NostrTransportBuilder::new(secret_key)
        .relay(&relay_url)
        .build()
        .await?;

    if signatures.len() < required_sigs {
        println!();
        println!("  Requesting signatures from quorum members via Nostr...");

        use crate::nostr::KIND_LEDGER_RESPONSE;

        let unsigned_tx_bytes = bitcoin::consensus::encode::serialize(&confiscation_tx);
        let unsigned_tx_hex = hex::encode(&unsigned_tx_bytes);

        let request_params = serde_json::json!({
            "ledger_id": ledger_id,
            "sighash": hex::encode(sighash_bytes),
            "unsigned_tx": unsigned_tx_hex,
            "lottery_address": lottery_output.address.to_string(),
            "violation_details": "Confiscation to lottery for dispute resolution",
            "last_valid_sequence": 0,
        });

        let request_id = publish_transport.send_ledger_request(
            &ledger_id,
            "confiscation_sign",
            request_params,
        ).await.map_err(|e| format!("Failed to send sign request: {:?}", e))?;

        println!("  Request ID: {}...", &request_id[..16]);

        let max_attempts = 20;
        let poll_interval = std::time::Duration::from_secs(3);

        for attempt in 1..=max_attempts {
            tokio::time::sleep(poll_interval).await;

            let since = nostr_sdk::Timestamp::now() - 120;
            let filter = Filter::new()
                .kind(Kind::Custom(KIND_LEDGER_RESPONSE))
                .since(since);

            let response_events = publish_transport.client()
                .fetch_events(vec![filter], Some(std::time::Duration::from_secs(5)))
                .await
                .map_err(|e| format!("Failed to fetch responses: {:?}", e))?;

            for event in response_events.iter() {
                let mut is_our_request = false;
                for tag in event.tags.iter() {
                    if tag.kind() == TagKind::SingleLetter(crate::nostr::TAG_EVENT_REF) {
                        if let Some(val) = tag.content() {
                            if val == request_id {
                                is_our_request = true;
                                break;
                            }
                        }
                    }
                }

                if !is_our_request { continue; }

                if let Ok(response) = serde_json::from_str::<crate::nostr::LedgerResponse>(&event.content) {
                    if response.success {
                        if let Some(result) = &response.result {
                            if let (Some(signer_hex), Some(sig_hex)) = (
                                result.get("signer").and_then(|v| v.as_str()),
                                result.get("signature").and_then(|v| v.as_str())
                            ) {
                                if let (Ok(signer), Ok(sig_bytes)) = (
                                    signer_hex.parse::<PublicKey>(),
                                    hex::decode(sig_hex)
                                ) {
                                    if sig_bytes.len() == 64 && !signatures.contains_key(&signer) {
                                        let mut sig_arr = [0u8; 64];
                                        sig_arr.copy_from_slice(&sig_bytes);
                                        signatures.insert(signer, sig_arr);
                                        println!("    Received signature from {}...", &signer.to_string()[..16]);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            println!("    Poll {}/{}: {}/{} signatures", attempt, max_attempts, signatures.len(), required_sigs);

            if signatures.len() >= required_sigs { break; }
        }
    }

    if signatures.len() < required_sigs {
        return Err(format!(
            "Could not collect enough signatures ({}/{}). Confiscation failed.",
            signatures.len(), required_sigs
        ).into());
    }

    // Build witness
    println!();
    println!("  Building witness with {} signatures...", signatures.len());

    let control_block = taproot_output.control_block_for_tier(tier_index)
        .ok_or("Failed to get control block for tier")?;

    let mut witness = Witness::new();
    let sorted_keys = voter_set.sorted_x_only_pubkeys();

    for x_only in sorted_keys.iter().rev() {
        for voter in voter_set.all_voters() {
            if voter.x_only_public_key().0 == *x_only {
                if let Some(sig) = signatures.get(&voter) {
                    witness.push(sig);
                } else {
                    witness.push(&[] as &[u8]);
                }
                break;
            }
        }
    }

    witness.push(leaf_script.as_bytes());
    witness.push(control_block.serialize());

    confiscation_tx.input[0].witness = witness;

    // Broadcast
    println!("  Broadcasting confiscation transaction...");

    let data_dir = config.data_dir.clone();
    let wallet = crate::wallet::Wallet::new(
        config.seed,
        config.network,
        data_dir,
        config.electrum_url.clone(),
    )?;
    wallet.broadcast(&confiscation_tx)?;

    let confiscation_txid = confiscation_tx.compute_txid();
    println!();
    println!("Confiscation transaction broadcast!");
    println!("  Txid: {}", confiscation_txid);
    println!("  Lottery address: {}", lottery_output.address);
    println!();
    println!("Next steps:");
    println!("  1. Wait for confirmation");
    println!("  2. All participants run: recovery reveal {}...", &ledger_id[..16.min(ledger_id.len())]);
    println!("  3. Winner runs: recovery lottery-claim {}...", &ledger_id[..16.min(ledger_id.len())]);

    Ok(())
}

/// Reveal the lottery preimage via Nostr.
pub async fn recovery_reveal(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut ledger_id: Option<String> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
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

    let ledger_id = ledger_id.ok_or("Missing ledger_id")?.trim().to_string();
    let config = parse_config(&config_args)?;
    let relay_url = config.relays.first()
        .ok_or("No relay configured. Use --relay <url>")?
        .clone();

    let secret_key = derive_operator_secret(&config.seed, config.network)?;

    println!("Revealing lottery preimage for ledger: {}...", &ledger_id[..16.min(ledger_id.len())]);

    // Load preimage from file
    let preimage_file = format!("{}/lottery_preimage_{}.hex",
        config.data_dir.display(),
        &ledger_id[..16.min(ledger_id.len())]);

    let preimage_hex = std::fs::read_to_string(&preimage_file)
        .map_err(|e| format!("Failed to read preimage file {}: {}", preimage_file, e))?;

    let preimage = hex::decode(preimage_hex.trim())
        .map_err(|e| format!("Invalid preimage hex: {}", e))?;

    println!("  Preimage length: {} bytes (contribution: {})", preimage.len(), preimage.len() - 16);

    let transport = NostrTransportBuilder::new(secret_key)
        .relay(&relay_url)
        .build()
        .await?;

    let reveal_params = serde_json::json!({
        "ledger_id": ledger_id,
        "preimage": hex::encode(&preimage),
    });

    let request_id = transport.send_ledger_request(
        &ledger_id,
        "lottery_reveal",
        reveal_params,
    ).await.map_err(|e| format!("Failed to send reveal: {:?}", e))?;

    println!();
    println!("Lottery preimage revealed!");
    println!("  Request ID: {}...", &request_id[..16]);
    println!();
    println!("Wait for all participants to reveal, then run:");
    println!("  recovery lottery-claim {}...", &ledger_id[..16.min(ledger_id.len())]);

    Ok(())
}

/// Claim the lottery output if we are the winner.
pub async fn recovery_lottery_claim(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use bitcoin::secp256k1::{Keypair, Secp256k1, PublicKey};
    use deposits_core::{TlvDecode, SignedLedgerUpdate};
    use deposits_core::messages::LedgerOperation;
    use deposits_core::tapscript_reserves::{LotteryScriptBuilder, LotteryParticipant, LotteryOutput};
    use crate::nostr::{NostrTransportBuilder, KIND_LEDGER_UPDATE, KIND_LEDGER_REQUEST};
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use nostr_sdk::prelude::*;

    let mut ledger_id: Option<String> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
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

    let ledger_id = ledger_id.ok_or("Missing ledger_id")?.trim().to_string();
    let config = parse_config(&config_args)?;
    let relay_url = config.relays.first()
        .ok_or("No relay configured. Use --relay <url>")?
        .clone();

    let secp = Secp256k1::new();
    let secret_key = derive_operator_secret(&config.seed, config.network)?;
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let our_pubkey = keypair.public_key();

    println!("Checking lottery result for ledger: {}...", &ledger_id[..16.min(ledger_id.len())]);

    // Fetch updates and reveals from Nostr
    let client = get_or_create_client(&relay_url).await?;

    // Fetch ledger updates
    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .custom_tag(crate::nostr::TAG_LEDGER_ID, [crate::nostr::ledger_tag(ledger_id.as_str())])
        .limit(500);

    let update_events = client
        .fetch_events(vec![filter], None)
        .await
        .map_err(|e| format!("Failed to fetch updates: {}", e))?;

    // Fetch lottery reveals (tagged with "l" for ledger_id)
    let reveal_filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_REQUEST))
        .custom_tag(crate::nostr::TAG_LEDGER_REQ, [ledger_id.as_str()])
        .limit(100);

    let reveal_events = client
        .fetch_events(vec![reveal_filter], None)
        .await
        .map_err(|e| format!("Failed to fetch reveals: {}", e))?;


    // Extract DisputeArmed participants
    let mut participants: Vec<(PublicKey, LotteryParticipant)> = Vec::new();

    for event in update_events.iter() {
        if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
            if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                    if let LedgerOperation::DisputeArmed { commitment_hash, target_reserves, .. } = op {
                        let x_only = update.operator_id.x_only_public_key().0;
                        participants.push((update.operator_id, LotteryParticipant::new(
                            x_only,
                            commitment_hash,
                            target_reserves,
                        )));
                    }
                }
            }
        }
    }

    if participants.is_empty() {
        return Err("No DisputeArmed participants found".into());
    }

    // Sort participants by x-only pubkey for deterministic order (must match confiscate)
    participants.sort_by(|a, b| a.1.pubkey.serialize().cmp(&b.1.pubkey.serialize()));

    // Debug: print participant order with full details
    println!("  Participant order (lottery-claim):");
    for (i, (op_id, p)) in participants.iter().enumerate() {
        let op_hex = hex::encode(&op_id.serialize()[..8]);
        let xonly_hex = hex::encode(&p.pubkey.serialize()[..8]);
        let target_short = if p.target_reserves.len() > 20 {
            format!("{}...", &p.target_reserves[..20])
        } else {
            p.target_reserves.clone()
        };
        println!("    {}: x-only={} op_id={} target={}", i, xonly_hex, op_hex, target_short);
    }

    println!("  Found {} participants", participants.len());

    // Collect revealed preimages (keyed by x-only pubkey to match Bitcoin pubkeys)
    let mut preimages: std::collections::HashMap<String, Vec<u8>> = std::collections::HashMap::new();

    println!("  Checking {} reveal events...", reveal_events.len());

    for event in reveal_events.iter() {
        // Check if this is a lottery_reveal action (action is in a tag, not content)
        let is_lottery_reveal = event.tags.iter().any(|tag| {
            tag.kind() == TagKind::custom("action") &&
            tag.content().map(|c| c == "lottery_reveal").unwrap_or(false)
        });

        if is_lottery_reveal {
            // Content is directly the params: {"ledger_id": "...", "preimage": "..."}
            if let Ok(content) = serde_json::from_str::<serde_json::Value>(&event.content) {
                if let Some(preimage_hex) = content.get("preimage").and_then(|v| v.as_str()) {
                    if let Ok(preimage) = hex::decode(preimage_hex) {
                        // Use event pubkey (x-only) to identify revealer
                        println!("    Found reveal from: {}...", &event.pubkey.to_string()[..16]);
                        preimages.insert(event.pubkey.to_string(), preimage);
                    }
                }
            }
        }
    }

    println!("  Found {} preimage reveals", preimages.len());

    if preimages.len() < participants.len() {
        println!();
        println!("Not all preimages revealed yet.");
        println!("  Have: {}, Need: {}", preimages.len(), participants.len());
        println!();
        println!("Waiting for remaining participants to run 'recovery reveal'...");
        return Ok(());
    }

    // Match preimages to participants and calculate winner
    // Use x-only pubkey format for matching (Nostr event pubkeys are x-only)
    let mut ordered_preimages: Vec<Vec<u8>> = Vec::new();
    for (pubkey, participant) in &participants {
        // Convert Bitcoin PublicKey to x-only format to match Nostr pubkeys
        let x_only = pubkey.x_only_public_key().0;
        let pubkey_str = x_only.to_string();
        if let Some(preimage) = preimages.get(&pubkey_str) {
            // Debug: verify hash matches commitment
            let computed_hash: [u8; 20] = *bitcoin::hashes::hash160::Hash::hash(preimage).as_byte_array();
            let expected_hash = participant.commitment_hash;
            if computed_hash != expected_hash {
                println!("  WARNING: Hash mismatch for {}...", &pubkey_str[..16]);
                println!("    Preimage: {}...", &hex::encode(preimage)[..32.min(preimage.len()*2)]);
                println!("    Computed HASH160:  {}", hex::encode(&computed_hash));
                println!("    Expected (commit): {}", hex::encode(&expected_hash));
            } else {
                println!("  Hash OK for {}...", &pubkey_str[..16]);
            }
            ordered_preimages.push(preimage.clone());
        } else {
            return Err(format!("Missing preimage from participant {}", &pubkey_str[..16]).into());
        }
    }

    let winner_index = LotteryOutput::calculate_winner(&ordered_preimages)
        .map_err(|e| format!("Failed to calculate winner: {:?}", e))?;

    let (winner_pubkey, winner_participant) = &participants[winner_index];

    println!();
    println!("Lottery result:");
    for (i, preimage) in ordered_preimages.iter().enumerate() {
        let marker = if i == winner_index { " <-- WINNER" } else { "" };
        println!("  Participant {}: {} bytes (contribution {}){}", i, preimage.len(), preimage.len() - 16, marker);
    }
    println!();
    println!("Winner: {}...", &winner_pubkey.to_string()[..16]);
    println!("Target reserves: {}...", &winner_participant.target_reserves[..20.min(winner_participant.target_reserves.len())]);

    if *winner_pubkey != our_pubkey {
        println!();
        println!("You did not win. Run 'recovery release' to publish DisputeYield.");
        return Ok(());
    }

    println!();
    println!("YOU WON! Building claim transaction...");
    println!();

    // Extract quorum members and original operator from ledger
    let mut quorum_members: Vec<PublicKey> = Vec::new();
    let mut original_operator: Option<PublicKey> = None;

    for event in update_events.iter() {
        if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
            if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                if update.sequence_number == 0 {
                    original_operator = Some(update.operator_id);
                }
                if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                    if let LedgerOperation::QuorumAddMember { quorum_member, .. } = op {
                        if !quorum_members.contains(&quorum_member) {
                            quorum_members.push(quorum_member);
                        }
                    }
                }
            }
        }
    }

    let original_operator = original_operator.ok_or("Could not find original operator")?;

    // Build the recovery voters list (quorum members minus original operator)
    let recovery_voters: Vec<bitcoin::secp256k1::XOnlyPublicKey> = quorum_members.iter()
        .filter(|pk| **pk != original_operator)
        .map(|pk| pk.x_only_public_key().0)
        .collect();

    println!("  Original operator: {}...", &original_operator.to_string()[..16]);
    println!("  Quorum members: {}", quorum_members.len());
    println!("  Recovery voters: {}", recovery_voters.len());

    // Build lottery participants (just the LotteryParticipant part)
    let lottery_participants: Vec<LotteryParticipant> = participants.iter()
        .map(|(_, p)| p.clone())
        .collect();

    // Calculate recovery threshold (majority of recovery voters)
    let recovery_threshold = (recovery_voters.len() + 1) / 2;
    if recovery_threshold == 0 {
        return Err("Not enough recovery voters".into());
    }

    // Build the lottery output to get the address and scripts
    let lottery_builder = LotteryScriptBuilder::new(
        lottery_participants.clone(),
        recovery_voters.clone(),
        recovery_threshold,
        config.network,
    );

    let lottery_output = lottery_builder.build()
        .map_err(|e| format!("Failed to build lottery output: {:?}", e))?;

    println!("  Lottery address: {}...", &lottery_output.address.to_string()[..20]);

    // Find the lottery UTXO on-chain
    use bdk_esplora::esplora_client::Builder as EsploraBuilder;
    let esplora = EsploraBuilder::new(&config.electrum_url).build_blocking();

    let lottery_script = lottery_output.address.script_pubkey();

    // Query for transactions at the lottery address
    let txs = esplora.scripthash_txs(&lottery_script, None)
        .map_err(|e| format!("Failed to query lottery address: {:?}", e))?;

    // Find unspent output
    let mut lottery_utxo: Option<(bitcoin::OutPoint, u64)> = None;
    for tx in &txs {
        for (vout, output) in tx.vout.iter().enumerate() {
            if output.scriptpubkey == lottery_script {
                let outpoint = bitcoin::OutPoint::new(tx.txid, vout as u32);
                let status = esplora.get_output_status(&tx.txid, vout as u64)
                    .map_err(|e| format!("Failed to check output status: {:?}", e))?;
                if status.map(|s| !s.spent).unwrap_or(true) {
                    lottery_utxo = Some((outpoint, output.value));
                    break;
                }
            }
        }
        if lottery_utxo.is_some() { break; }
    }

    let (lottery_outpoint, lottery_amount) = lottery_utxo
        .ok_or("No unspent UTXO found at lottery address. Was confiscation transaction confirmed?")?;

    println!("  Found lottery UTXO: {} ({} sats)", lottery_outpoint, lottery_amount);

    // Parse the winner's target_reserves address
    let target_address: bitcoin::Address<bitcoin::address::NetworkUnchecked> = winner_participant.target_reserves.parse()
        .map_err(|e| format!("Invalid target_reserves address: {}", e))?;
    let target_address = target_address.require_network(config.network)
        .map_err(|e| format!("Address network mismatch: {}", e))?;

    // Build claim transaction
    use bitcoin::{ScriptBuf, Witness, Amount, TxIn, TxOut};

    let claim_fee = 400u64; // Reasonable fee for single-input tx
    let output_amount = lottery_amount.saturating_sub(claim_fee);

    let claim_tx = bitcoin::Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: lottery_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(output_amount),
            script_pubkey: target_address.script_pubkey(),
        }],
    };

    // Compute sighash for the lottery script path
    use bitcoin::sighash::{SighashCache, TapSighashType};
    use bitcoin::taproot::TapLeafHash;

    let prevouts = vec![TxOut {
        value: Amount::from_sat(lottery_amount),
        script_pubkey: lottery_script.clone(),
    }];

    let leaf_hash = TapLeafHash::from_script(&lottery_output.lottery_script, bitcoin::taproot::LeafVersion::TapScript);

    let mut sighash_cache = SighashCache::new(&claim_tx);
    let sighash = sighash_cache.taproot_script_spend_signature_hash(
        0,
        &bitcoin::sighash::Prevouts::All(&prevouts),
        leaf_hash,
        TapSighashType::Default,
    ).map_err(|e| format!("Failed to compute sighash: {}", e))?;

    let sighash_bytes: [u8; 32] = *sighash.as_ref();

    // Sign with our key
    let msg = bitcoin::secp256k1::Message::from_digest(sighash_bytes);
    let signature = secp.sign_schnorr(&msg, &keypair);
    let sig_bytes: [u8; 64] = *signature.as_ref();

    println!("  Signed claim transaction");

    // Create witness
    let witness = lottery_output.create_claim_witness(&sig_bytes, &ordered_preimages)
        .map_err(|e| format!("Failed to create witness: {:?}", e))?;

    let mut claim_tx = claim_tx;
    claim_tx.input[0].witness = witness;

    // Broadcast
    println!("  Broadcasting claim transaction...");

    let data_dir = config.data_dir.clone();
    let wallet = crate::wallet::Wallet::new(
        config.seed,
        config.network,
        data_dir,
        config.electrum_url.clone(),
    )?;
    wallet.broadcast(&claim_tx)?;

    let claim_txid = claim_tx.compute_txid();
    println!();
    println!("Claim transaction broadcast!");
    println!("  Txid: {}", claim_txid);
    println!("  Output: {} sats to {}", output_amount, winner_participant.target_reserves);

    // Publish DisputeAcquire to Nostr
    println!();
    println!("Publishing DisputeAcquire to Nostr...");

    use bitcoin::hashes::{sha256, Hash};
    use deposits_core::TlvEncode;

    // Find our DisputeArmed to get sequence number and hash
    let mut our_armed: Option<SignedLedgerUpdate> = None;
    for event in update_events.iter() {
        if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
            if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                if update.operator_id == our_pubkey {
                    if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                        if matches!(op, LedgerOperation::DisputeArmed { .. }) {
                            our_armed = Some(update);
                        }
                    }
                }
            }
        }
    }

    let our_armed = our_armed.ok_or("Could not find our DisputeArmed update")?;

    // Get current block for entropy reference
    let current_block_height = esplora.get_height()
        .map_err(|e| format!("Failed to get block height: {:?}", e))?;
    let current_block_hash = esplora.get_block_hash(current_block_height)
        .map_err(|e| format!("Failed to get block hash: {:?}", e))?;
    let current_block_hash: [u8; 32] = *current_block_hash.as_ref();

    // Create DisputeAcquire operation
    let spend_txid_bytes: [u8; 32] = *claim_txid.as_ref();

    let operation = LedgerOperation::DisputeAcquire {
        new_custodian: our_pubkey,
        entropy_block_height: current_block_height,
        entropy_block_hash: current_block_hash,
        spend_txid: spend_txid_bytes,
        new_reserves_address: winner_participant.target_reserves.clone(),
    };

    let message_bytes = operation.tlv_encode();

    // Build update continuing from our DisputeArmed
    let sequence = our_armed.sequence_number + 1;
    let mut hash_input = Vec::new();
    hash_input.extend_from_slice(&sequence.to_le_bytes());
    hash_input.extend_from_slice(&our_armed.current_hash);
    hash_input.extend_from_slice(&message_bytes);
    let new_hash = *sha256::Hash::hash(&hash_input).as_byte_array();

    // Sign the update
    let update_msg = format!(
        "deposits:ledger:{}:{}:{}",
        hex::encode(our_armed.current_hash),
        sequence,
        hex::encode(&new_hash)
    );
    let msg_hash = sha256::Hash::hash(update_msg.as_bytes());
    let msg = bitcoin::secp256k1::Message::from_digest(*msg_hash.as_ref());
    let signature = secp.sign_schnorr(&msg, &keypair);
    let operator_sig_bytes: [u8; 64] = *signature.as_ref();

    // Parse ledger_id into bytes
    let ledger_id_bytes: [u8; 32] = {
        let decoded = hex::decode(&ledger_id)
            .map_err(|e| format!("Invalid ledger_id hex: {}", e))?;
        decoded.try_into().map_err(|_| "Ledger ID must be 32 bytes")?
    };

    let signed_update = SignedLedgerUpdate {
        message: message_bytes,
        message_type: 0x8001,
        operator_signature: operator_sig_bytes,
        cosigner_pubkey: None,
        member_ledger_hash: None,
            cosignatures: Vec::new(),
        cosign_signature: [0u8; 64],
        operator_id: our_pubkey,
        ledger_id: ledger_id_bytes,
        sequence_number: sequence,
        previous_hash: our_armed.current_hash,
        current_hash: new_hash,
        block_height: current_block_height,
        block_hash: current_block_hash,
    };

    // Publish to Nostr
    let publish_transport = NostrTransportBuilder::new(secret_key)
        .relay(&relay_url)
        .build()
        .await?;

    publish_transport.broadcast_ledger_update(&signed_update).await?;

    println!();
    println!("DisputeAcquire published successfully!");
    println!("  Sequence: {}", sequence);
    println!("  Hash: {}...", &hex::encode(new_hash)[..16]);
    println!("  Spend txid: {}...", &hex::encode(spend_txid_bytes)[..16]);
    println!("  New reserves: {}...", &winner_participant.target_reserves[..20.min(winner_participant.target_reserves.len())]);
    println!();
    println!("Custody transfer complete. You are now the operator.");
    println!();
    println!("Next: Run 'recovery rotate-to-quorum {}' to move funds to quorum-controlled Taproot address.", &ledger_id[..16.min(ledger_id.len())]);

    Ok(())
}

/// Rotate lottery winnings to a quorum-controlled Taproot address.
pub async fn recovery_rotate_to_quorum(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use bitcoin::hashes::{sha256, Hash};
    use bitcoin::secp256k1::{Keypair, Secp256k1, PublicKey};
    use deposits_core::{TlvDecode, TlvEncode, SignedLedgerUpdate, VoterSet, ThresholdConfig, TapscriptReservesBuilder};
    use deposits_core::messages::LedgerOperation;
    use crate::nostr::NostrTransportBuilder;
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use nostr_sdk::prelude::*;
    use bdk_esplora::esplora_client::Builder as EsploraBuilder;
    use bitcoin::{Transaction, TxIn, TxOut, Witness, Amount, ScriptBuf};

    let mut ledger_id: Option<String> = None;
    let mut config_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
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

    let ledger_id = ledger_id.ok_or("Missing ledger_id")?.trim().to_string();
    let config = parse_config(&config_args)?;
    let relay_url = config.relays.first()
        .ok_or("No relay configured. Use --relay <url>")?
        .clone();

    let secp = Secp256k1::new();
    let secret_key = derive_operator_secret(&config.seed, config.network)?;
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let our_pubkey = keypair.public_key();

    println!("Rotating lottery winnings to quorum-controlled Taproot...");
    println!("  Ledger: {}...", &ledger_id[..16.min(ledger_id.len())]);

    // Fetch ledger updates from Nostr
    let client = get_or_create_client(&relay_url).await?;

    let filter = Filter::new()
        .kind(Kind::Custom(crate::nostr::KIND_LEDGER_UPDATE))
        .custom_tag(crate::nostr::TAG_LEDGER_ID, [crate::nostr::ledger_tag(ledger_id.as_str())])
        .limit(500);

    let events = client
        .fetch_events(vec![filter], None)
        .await
        .map_err(|e| format!("Failed to fetch updates: {}", e))?;


    // Decode updates and find our branch
    let mut updates: Vec<SignedLedgerUpdate> = Vec::new();
    for event in events.iter() {
        if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
            if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                updates.push(update);
            }
        }
    }

    updates.sort_by_key(|u| (u.sequence_number, u.operator_id));
    updates.dedup_by(|a, b| a.sequence_number == b.sequence_number && a.operator_id == b.operator_id && a.current_hash == b.current_hash);

    // Find our updates (we're the new operator after DisputeAcquire)
    let our_updates: Vec<&SignedLedgerUpdate> = updates.iter()
        .filter(|u| u.operator_id == our_pubkey)
        .collect();

    if our_updates.is_empty() {
        return Err("No updates found from you. Did you win the lottery?".into());
    }

    // Find our DisputeAcquire to get the current reserves address
    let mut current_reserves_address: Option<String> = None;
    let mut our_latest: Option<&SignedLedgerUpdate> = None;

    for update in &our_updates {
        if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
            if let LedgerOperation::DisputeAcquire { new_reserves_address, .. } = op {
                current_reserves_address = Some(new_reserves_address);
            }
        }
        if our_latest.is_none() || update.sequence_number > our_latest.unwrap().sequence_number {
            our_latest = Some(update);
        }
    }

    let current_reserves_address = current_reserves_address
        .ok_or("Could not find DisputeAcquire with reserves address")?;
    let our_latest = our_latest.ok_or("Could not find latest update")?;

    println!("  Current reserves: {}...", &current_reserves_address[..20.min(current_reserves_address.len())]);
    println!("  Latest sequence: {}", our_latest.sequence_number);

    // Get quorum members from our branch (rebuilt during dispute)
    let mut quorum_members: Vec<PublicKey> = Vec::new();
    for update in &our_updates {
        if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
            if let LedgerOperation::QuorumAddMember { quorum_member, .. } = op {
                if !quorum_members.contains(&quorum_member) {
                    quorum_members.push(quorum_member);
                }
            }
        }
    }

    if quorum_members.is_empty() {
        return Err("No quorum members found. Did you rebuild the quorum?".into());
    }

    println!("  Quorum members: {}", quorum_members.len());

    // Find the UTXO at current_reserves_address
    let esplora = EsploraBuilder::new(&config.electrum_url).build_blocking();

    let reserves_addr: bitcoin::Address<bitcoin::address::NetworkUnchecked> = current_reserves_address.parse()
        .map_err(|e| format!("Invalid reserves address: {}", e))?;
    let reserves_addr = reserves_addr.require_network(config.network)
        .map_err(|e| format!("Address network mismatch: {}", e))?;

    let script_pubkey = reserves_addr.script_pubkey();
    let txs = esplora.scripthash_txs(&script_pubkey, None)
        .map_err(|e| format!("Failed to query address: {:?}", e))?;

    // Find unspent output
    let mut reserves_utxo: Option<(bitcoin::OutPoint, u64)> = None;
    for tx in &txs {
        for (vout, output) in tx.vout.iter().enumerate() {
            if output.scriptpubkey == script_pubkey {
                let outpoint = bitcoin::OutPoint::new(tx.txid, vout as u32);
                let status = esplora.get_output_status(&tx.txid, vout as u64)
                    .map_err(|e| format!("Failed to check output status: {:?}", e))?;
                if status.map(|s| !s.spent).unwrap_or(true) {
                    reserves_utxo = Some((outpoint, output.value));
                    break;
                }
            }
        }
        if reserves_utxo.is_some() { break; }
    }

    let (reserves_outpoint, reserves_amount) = reserves_utxo
        .ok_or("No unspent UTXO found at reserves address")?;

    println!("  Found UTXO: {} ({} sats)", reserves_outpoint, reserves_amount);

    // Compute ledger hash for Taproot address derivation
    let ledger_hash: [u8; 32] = our_latest.current_hash;

    // Build Taproot quorum address
    let voter_set = VoterSet::new(our_pubkey, quorum_members.clone());
    let voter_count = voter_set.all_voters().len();
    let threshold_config = ThresholdConfig::default_for_voter_count(voter_count);

    let taproot_builder = TapscriptReservesBuilder::new(
        voter_set,
        threshold_config,
        config.network,
        ledger_hash,
    );

    let taproot_output = taproot_builder.build()
        .map_err(|e| format!("Failed to build Taproot output: {:?}", e))?;

    let new_reserves_address = &taproot_output.address;
    println!("  New Taproot address: {}...", &new_reserves_address.to_string()[..20]);

    // Build rotation transaction
    let fee = 200u64;
    let output_amount = reserves_amount.saturating_sub(fee);

    let mut rotation_tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: reserves_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(output_amount),
            script_pubkey: new_reserves_address.script_pubkey(),
        }],
    };

    // Sign the transaction (P2WPKH input)
    use bitcoin::sighash::{SighashCache, EcdsaSighashType};

    let mut sighash_cache = SighashCache::new(&rotation_tx);
    let sighash = sighash_cache.p2wpkh_signature_hash(
        0,
        &script_pubkey,
        Amount::from_sat(reserves_amount),
        EcdsaSighashType::All,
    ).map_err(|e| format!("Failed to compute sighash: {}", e))?;

    let msg = bitcoin::secp256k1::Message::from_digest(*sighash.as_ref());
    let ecdsa_sig = secp.sign_ecdsa(&msg, &secret_key);
    let signature = bitcoin::ecdsa::Signature::sighash_all(ecdsa_sig);

    // Build witness for P2WPKH
    let mut witness = Witness::new();
    witness.push(signature.serialize());
    witness.push(our_pubkey.serialize());
    rotation_tx.input[0].witness = witness;

    // Broadcast
    println!("  Broadcasting rotation transaction...");

    let data_dir = config.data_dir.clone();
    let wallet = crate::wallet::Wallet::new(
        config.seed,
        config.network,
        data_dir,
        config.electrum_url.clone(),
    )?;
    wallet.broadcast(&rotation_tx)?;

    let rotation_txid = rotation_tx.compute_txid();
    println!("  Rotation txid: {}", rotation_txid);

    // Publish QuorumBegin operation
    println!();
    println!("Publishing QuorumBegin to Nostr...");

    let txid_bytes: [u8; 32] = *rotation_txid.as_ref();

    // Get current block height for quorum_expiry calculation
    let current_block_height = esplora.get_height()
        .map_err(|e| format!("Failed to get block height: {:?}", e))?;
    let current_block_hash = esplora.get_block_hash(current_block_height)
        .map_err(|e| format!("Failed to get block hash: {:?}", e))?;
    let block_hash: [u8; 32] = *current_block_hash.as_ref();

    let quorum_size = (quorum_members.len() + 1) as u8;
    let quorum_threshold = (quorum_size / 2) + 1;
    let quorum_expiry = current_block_height + 144; // ~1 day for degraded spending

    let operation = LedgerOperation::QuorumBegin {
        reserves_id: new_reserves_address.to_string(),
        spending_txid: txid_bytes,
        new_outpoint_txid: txid_bytes,
        new_outpoint_vout: 0,
        amount: output_amount,
        quorum_expiry,
        ledger_hash,
        quorum_members: quorum_members.clone(),
        total_collateral: 0, // recovery — collateral will be re-attested
    };

    let message_bytes = operation.tlv_encode();

    let sequence = our_latest.sequence_number + 1;
    let mut hash_input = Vec::new();
    hash_input.extend_from_slice(&sequence.to_le_bytes());
    hash_input.extend_from_slice(&our_latest.current_hash);
    hash_input.extend_from_slice(&message_bytes);
    let new_hash = *sha256::Hash::hash(&hash_input).as_byte_array();

    let update_msg = format!(
        "deposits:ledger:{}:{}:{}",
        hex::encode(our_latest.current_hash),
        sequence,
        hex::encode(&new_hash)
    );
    let msg_hash = sha256::Hash::hash(update_msg.as_bytes());
    let msg = bitcoin::secp256k1::Message::from_digest(*msg_hash.as_ref());
    let signature = secp.sign_schnorr(&msg, &keypair);
    let operator_sig_bytes: [u8; 64] = *signature.as_ref();

    let ledger_id_bytes: [u8; 32] = {
        let decoded = hex::decode(&ledger_id)
            .map_err(|e| format!("Invalid ledger_id hex: {}", e))?;
        decoded.try_into().map_err(|_| "Ledger ID must be 32 bytes")?
    };

    let signed_update = SignedLedgerUpdate {
        message: message_bytes,
        message_type: 0x8001,
        operator_signature: operator_sig_bytes,
        cosigner_pubkey: None,
        member_ledger_hash: None,
            cosignatures: Vec::new(),
        cosign_signature: [0u8; 64],
        operator_id: our_pubkey,
        ledger_id: ledger_id_bytes,
        sequence_number: sequence,
        previous_hash: our_latest.current_hash,
        current_hash: new_hash,
        block_height: current_block_height,
        block_hash,
    };

    let publish_transport = NostrTransportBuilder::new(secret_key)
        .relay(&relay_url)
        .build()
        .await?;

    publish_transport.broadcast_ledger_update(&signed_update).await?;

    println!();
    println!("Reserves rotated to quorum-controlled Taproot!");
    println!("  New address: {}", new_reserves_address);
    println!("  Amount: {} sats", output_amount);
    println!("  Quorum: {}-of-{}", (quorum_members.len() + 1) / 2 + 1, quorum_members.len() + 1);
    println!("  Sequence: {}", sequence);

    Ok(())
}
