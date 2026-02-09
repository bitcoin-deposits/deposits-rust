//! Recovery CLI commands
//!
//! Commands for dispute resolution and custody recovery.

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

use std::str::FromStr;

use super::common::{parse_config, derive_operator_secret};

/// Handle recovery subcommands for non-conforming ledgers
pub async fn recovery_command(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.is_empty() {
        eprintln!("Usage: deposits-bdk recovery <dispute|rebuild|arm|claim|continue|spend|status> [args...]");
        eprintln!();
        eprintln!("Subcommands (Dispute Protocol):");
        eprintln!("  dispute <ledger_id> [--reason <text>]  Open dispute: publish CustodyDispute operation");
        eprintln!("  rebuild <ledger_id>                    Rebuild quorum: add members + get attestations");
        eprintln!("  arm <ledger_id>                        Pre-commit: publish CustodyArmed operation");
        eprintln!("  claim <ledger_id>                      After entropy: CustodyAcquire (win) or CustodyYield (lose)");
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
        eprintln!("  1. dispute - Detect violation, publish CustodyDispute (quorum disbanded)");
        eprintln!("  2. rebuild - Add new quorum members, collect attestations");
        eprintln!("  3. arm     - Publish CustodyArmed (locks in for entropy selection)");
        eprintln!("  4. (wait)  - Wait for entropy block to be mined");
        eprintln!("  5. claim   - Winner: CustodyAcquire, Losers: CustodyYield");
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
            eprintln!("Usage: deposits-bdk recovery <dispute|rebuild|arm|claim|spend|status> [args...]");
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
    let keys = Keys::generate();
    let client = Client::new(keys);
    client.add_relay(&relay_url).await
        .map_err(|e| format!("Failed to add relay: {}", e))?;
    client.connect().await;

    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .custom_tag(SingleLetterTag::lowercase(Alphabet::D), [ledger_id.as_str()])
        .limit(500);

    let events = client
        .fetch_events(vec![filter], None)
        .await
        .map_err(|e| format!("Failed to fetch events: {}", e))?;

    client.disconnect().await.ok();

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
    println!("  1. Other quorum members run: deposits-bdk recovery agree {}", &ledger_id[..16]);
    println!("  2. Once enough agree, run: deposits-bdk recovery complete {}", &ledger_id[..16]);

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

    let keys = Keys::generate();
    let client = Client::new(keys);
    client.add_relay(&relay_url).await
        .map_err(|e| format!("Failed to add relay: {}", e))?;
    client.connect().await;

    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .custom_tag(SingleLetterTag::lowercase(Alphabet::D), [ledger_id.as_str()])
        .limit(500);

    let events = client
        .fetch_events(vec![filter], None)
        .await
        .map_err(|e| format!("Failed to fetch events: {}", e))?;

    client.disconnect().await.ok();

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
    println!("  Once enough quorum members agree, run: deposits-bdk recovery complete {}", &ledger_id[..16]);

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
    println!("  1. Validate the ledger: deposits-bdk nostr validate {}", ledger_id);
    println!("  2. If invalid, publish dispute: deposits-bdk nostr dispute publish {} <reason> <details>", ledger_id);
    println!("  3. Submit vote: deposits-bdk recovery vote {} non-conforming", ledger_id);
    println!("  4. Claim if eligible: deposits-bdk recovery claim {}", ledger_id);

    Ok(())
}

/// Execute a custody transfer for a non-conforming ledger
///
/// DEPRECATED: Use the new dispute protocol commands instead:
///   recovery dispute -> recovery rebuild -> recovery arm -> recovery claim -> recovery spend
pub async fn recovery_complete(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("WARNING: 'recovery complete' is deprecated and uses the old protocol.");
    eprintln!("Please use the new dispute protocol commands instead:");
    eprintln!("  1. recovery dispute <ledger_id>   - Open dispute with CustodyDispute");
    eprintln!("  2. recovery rebuild <ledger_id>   - Rebuild quorum");
    eprintln!("  3. recovery arm <ledger_id>       - Publish CustodyArmed pre-commitment");
    eprintln!("  4. recovery claim <ledger_id>     - Claim with CustodyAcquire/CustodyYield");
    eprintln!("  5. recovery spend <ledger_id>     - Execute on-chain spend");
    eprintln!();

    let ledger_id = args.first().ok_or("Missing ledger_id")?;
    println!("To complete recovery for ledger {}..., use the new dispute protocol:", &ledger_id[..16.min(ledger_id.len())]);
    println!("  deposits-bdk recovery dispute {}", ledger_id);

    Ok(())
}

/// DEPRECATED: Use the new dispute protocol commands instead
pub async fn recovery_publish_transfer(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("WARNING: 'recovery publish-transfer' is deprecated and uses the old protocol.");
    eprintln!("Please use the new dispute protocol commands instead:");
    eprintln!("  1. recovery dispute <ledger_id>   - Open dispute with CustodyDispute");
    eprintln!("  2. recovery rebuild <ledger_id>   - Rebuild quorum");
    eprintln!("  3. recovery arm <ledger_id>       - Publish CustodyArmed pre-commitment");
    eprintln!("  4. recovery claim <ledger_id>     - Claim with CustodyAcquire/CustodyYield");
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
    let keys = Keys::generate();
    let client = Client::new(keys);
    client.add_relay(&relay_url).await
        .map_err(|e| format!("Failed to add relay: {}", e))?;
    client.connect().await;

    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .custom_tag(SingleLetterTag::lowercase(Alphabet::D), [ledger_id.as_str()])
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
        client.disconnect().await?;
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
            .custom_tag(SingleLetterTag::lowercase(Alphabet::D), [ledger_id.as_str()])
            .limit(10);

        let disputes = client
            .fetch_events(vec![dispute_filter], None)
            .await
            .map_err(|e| format!("Failed to fetch disputes: {}", e))?;

        if disputes.is_empty() {
            client.disconnect().await?;
            return Err("No violation found and no dispute published. Run 'recovery start' first.".into());
        }

        violation_details = "Dispute published - preparing candidate branch".to_string();
    }

    println!("  Last valid sequence: {}", last_valid_sequence);
    println!("  Violation: {}", violation_details);

    let original_operator = original_operator.ok_or("Could not determine original operator")?;
    println!("  Original operator: {}...", &original_operator.to_string()[..16]);

    client.disconnect().await?;

    let esplora = EsploraBuilder::new(&config.electrum_url).build_blocking();
    let current_block_height = esplora.get_height()
        .map_err(|e| format!("Failed to get block height: {:?}", e))?;

    let initiation_block = current_block_height;
    let entropy_block_height = initiation_block + 6;
    let entropy_block_hash = [0u8; 32];

    println!("  Initiation block: {}", initiation_block);
    println!("  Entropy block (expected): {}", entropy_block_height);

    let custody_dispute = LedgerOperation::CustodyDispute {
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
        partner_signature: [0u8; 64],
        operator_id: our_pubkey,
        ledger_id: ledger_id_bytes,
        sequence_number: sequence,
        previous_hash: last_valid_hash,
        current_hash: new_hash,
        timestamp: deposits_core::now_unix_timestamp(),
        block_height: current_block_height,
        block_hash: entropy_block_hash,
    };

    println!();
    println!("Publishing CustodyDispute to Nostr...");

    let publish_transport = NostrTransportBuilder::new(secret_key)
        .relay(&relay_url)
        .build()
        .await?;

    publish_transport.broadcast_ledger_update(&signed_update).await?;

    println!();
    println!("CustodyDispute published successfully!");
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
pub async fn recovery_spend(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    println!("Running on-chain spend (delegating to recovery complete)...");
    println!();
    recovery_complete(args).await
}

/// Publish CustodyYield to close a candidate branch after not being selected.
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

    println!("Publishing CustodyYield (closing candidate branch)...");
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

    println!("Fetching our CustodyArmed branch...");
    let keys = Keys::generate();
    let client = Client::new(keys);
    client.add_relay(&relay_url).await
        .map_err(|e| format!("Failed to add relay: {}", e))?;
    client.connect().await;

    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .custom_tag(SingleLetterTag::lowercase(Alphabet::D), [ledger_id.as_str()])
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
                        if matches!(op, LedgerOperation::CustodyArmed { .. }) {
                            our_armed = Some(update);
                            break;
                        }
                    }
                }
            }
        }
    }

    client.disconnect().await?;

    let our_armed = our_armed.ok_or(
        "Could not find our CustodyArmed. Did you run 'recovery arm' first?"
    )?;

    println!("  Found our CustodyArmed at sequence {}", our_armed.sequence_number);

    let esplora = EsploraBuilder::new(&config.electrum_url).build_blocking();
    let current_block_height = esplora.get_height()
        .map_err(|e| format!("Failed to get block height: {:?}", e))?;

    let custody_release = LedgerOperation::CustodyYield;
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
        partner_signature: [0u8; 64],
        operator_id: our_pubkey,
        ledger_id: ledger_id_bytes,
        sequence_number: sequence,
        previous_hash: our_armed.current_hash,
        current_hash: new_hash,
        timestamp: deposits_core::now_unix_timestamp(),
        block_height: current_block_height,
        block_hash: [0u8; 32],
    };

    println!();
    println!("Publishing CustodyYield to Nostr...");

    let publish_transport = NostrTransportBuilder::new(secret_key)
        .relay(&relay_url)
        .build()
        .await?;

    publish_transport.broadcast_ledger_update(&signed_update).await?;

    println!();
    println!("CustodyYield published successfully!");
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

/// Open a custody dispute by publishing a CustodyDispute ledger operation.
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
    let keys = Keys::generate();
    let client = Client::new(keys);
    client.add_relay(&relay_url).await
        .map_err(|e| format!("Failed to add relay: {}", e))?;
    client.connect().await;

    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .custom_tag(SingleLetterTag::lowercase(Alphabet::D), [ledger_id.as_str()])
        .limit(500);

    let events = client
        .fetch_events(vec![filter], None)
        .await
        .map_err(|e| format!("Failed to fetch events: {}", e))?;

    client.disconnect().await.ok();

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

    // Create CustodyDispute operation
    let dispute_reason = if let Some(hash) = invalid_update_hash {
        hex::encode(hash)
    } else {
        violation_details.clone()
    };
    let custody_dispute = LedgerOperation::CustodyDispute {
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
        partner_signature: [0u8; 64],
        operator_id: our_pubkey,
        ledger_id: ledger_id_bytes,
        sequence_number: sequence,
        previous_hash: last_valid_hash,
        current_hash: new_hash,
        timestamp: deposits_core::now_unix_timestamp(),
        block_height: current_block_height,
        block_hash: [0u8; 32],
    };

    println!();
    println!("Publishing CustodyDispute to Nostr...");

    let publish_transport = NostrTransportBuilder::new(secret_key)
        .relay(&relay_url)
        .build()
        .await?;

    publish_transport.broadcast_ledger_update(&signed_update).await?;

    println!();
    println!("CustodyDispute published successfully!");
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
        eprintln!("Usage: deposits-bdk recovery rebuild <ledger_id> <quorum-add|attestation|status> [args...]");
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
pub async fn recovery_rebuild_quorum_add(ledger_id: &str, args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut member_pubkey_str: Option<String> = None;
    let mut config_args = Vec::new();

    for (i, arg) in args.iter().enumerate() {
        if arg.starts_with("--") {
            config_args.push(arg.clone());
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                config_args.push(args[i + 1].clone());
            }
        } else if member_pubkey_str.is_none() {
            member_pubkey_str = Some(arg.clone());
        }
    }

    let member_pubkey_str = member_pubkey_str.ok_or("Missing member_pubkey")?;
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
    let keys = Keys::generate();
    let client = Client::new(keys);
    client.add_relay(&relay_url).await
        .map_err(|e| format!("Failed to add relay: {}", e))?;
    client.connect().await;

    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .custom_tag(SingleLetterTag::lowercase(Alphabet::D), [ledger_id])
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
        partner_signature: [0u8; 64],
        operator_id: our_pubkey,
        ledger_id: ledger_id_bytes,
        sequence_number: sequence,
        previous_hash: our_latest.current_hash,
        current_hash: new_hash,
        timestamp: deposits_core::now_unix_timestamp(),
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
        .tags(vec![Tag::custom(TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::D)), [ledger_id])])
        .sign_with_keys(&publishing_keys)
        .map_err(|e| format!("Failed to sign event: {}", e))?;

    publishing_client.send_event(event).await
        .map_err(|e| format!("Failed to publish: {}", e))?;

    publishing_client.disconnect().await.ok();
    client.disconnect().await.ok();

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
    let keys = Keys::generate();
    let client = Client::new(keys);
    client.add_relay(&relay_url).await
        .map_err(|e| format!("Failed to add relay: {}", e))?;
    client.connect().await;

    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .custom_tag(SingleLetterTag::lowercase(Alphabet::D), [ledger_id])
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
        partner_signature: [0u8; 64],
        operator_id: our_pubkey,
        ledger_id: ledger_id_bytes,
        sequence_number: sequence,
        previous_hash: our_latest.current_hash,
        current_hash: new_hash,
        timestamp: deposits_core::now_unix_timestamp(),
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
        .tags(vec![Tag::custom(TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::D)), [ledger_id])])
        .sign_with_keys(&publishing_keys)
        .map_err(|e| format!("Failed to sign event: {}", e))?;

    publishing_client.send_event(event).await
        .map_err(|e| format!("Failed to publish: {}", e))?;

    publishing_client.disconnect().await.ok();
    client.disconnect().await.ok();

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

    let keys = Keys::generate();
    let client = Client::new(keys);
    client.add_relay(&relay_url).await
        .map_err(|e| format!("Failed to add relay: {}", e))?;
    client.connect().await;

    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .custom_tag(SingleLetterTag::lowercase(Alphabet::D), [ledger_id])
        .limit(500);

    let events = client
        .fetch_events(vec![filter], None)
        .await
        .map_err(|e| format!("Failed to fetch events: {}", e))?;

    client.disconnect().await.ok();

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
                            LedgerOperation::CustodyDispute { .. } => has_dispute = true,
                            LedgerOperation::CustodyArmed { .. } => has_armed = true,
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
    println!("  Has CustodyDispute: {}", if has_dispute { "yes" } else { "NO - run 'recovery dispute' first" });
    println!("  Has CustodyArmed: {}", if has_armed { "yes (locked in)" } else { "no" });
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

/// Publish CustodyArmed to pre-commit for entropy selection.
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
    let keys = Keys::generate();
    let client = Client::new(keys);
    client.add_relay(&relay_url).await
        .map_err(|e| format!("Failed to add relay: {}", e))?;
    client.connect().await;

    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .custom_tag(SingleLetterTag::lowercase(Alphabet::D), [ledger_id.as_str()])
        .limit(500);

    let events = client
        .fetch_events(vec![filter], None)
        .await
        .map_err(|e| format!("Failed to fetch events: {}", e))?;

    client.disconnect().await.ok();

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

    let custody_armed = LedgerOperation::CustodyArmed {
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
        partner_signature: [0u8; 64],
        operator_id: our_pubkey,
        ledger_id: ledger_id_bytes,
        sequence_number: sequence,
        previous_hash: latest.current_hash,
        current_hash: new_hash,
        timestamp: deposits_core::now_unix_timestamp(),
        block_height: current_block_height,
        block_hash: [0u8; 32],
    };

    println!();
    println!("Publishing CustodyArmed to Nostr...");

    let publish_transport = NostrTransportBuilder::new(secret_key)
        .relay(&relay_url)
        .build()
        .await?;

    publish_transport.broadcast_ledger_update(&signed_update).await?;

    let entropy_block = current_block_height + 6;

    println!();
    println!("CustodyArmed published successfully!");
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

/// Claim custody after entropy block - publish CustodyAcquire (winner) or CustodyYield (loser).
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
    let keys = Keys::generate();
    let client = Client::new(keys);
    client.add_relay(&relay_url).await
        .map_err(|e| format!("Failed to add relay: {}", e))?;
    client.connect().await;

    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .custom_tag(SingleLetterTag::lowercase(Alphabet::D), [ledger_id.as_str()])
        .limit(500);

    let events = client
        .fetch_events(vec![filter], None)
        .await
        .map_err(|e| format!("Failed to fetch events: {}", e))?;

    client.disconnect().await.ok();

    // Find all CustodyArmed candidates
    let mut candidates: Vec<(PublicKey, u32, SignedLedgerUpdate)> = Vec::new();
    let mut our_latest: Option<SignedLedgerUpdate> = None;
    let mut our_armed_block: Option<u32> = None;

    for event in events.iter() {
        if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
            if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                    if let LedgerOperation::CustodyArmed { armed_block, .. } = op {
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
        return Err("No CustodyArmed candidates found.".into());
    }

    let our_latest = our_latest.ok_or("No updates found from you")?;
    if our_armed_block.is_none() {
        return Err("You haven't published CustodyArmed yet. Run 'recovery arm' first.".into());
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
        println!("YOU WON! Publishing CustodyAcquire...");

        let operation = LedgerOperation::CustodyAcquire {
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
            partner_signature: [0u8; 64],
            operator_id: our_pubkey,
            ledger_id: ledger_id_bytes,
            sequence_number: sequence,
            previous_hash: our_latest.current_hash,
            current_hash: new_hash,
            timestamp: deposits_core::now_unix_timestamp(),
            block_height: current_block_height,
            block_hash: entropy_block_hash,
        };

        let publish_transport = NostrTransportBuilder::new(secret_key)
            .relay(&relay_url)
            .build()
            .await?;

        publish_transport.broadcast_ledger_update(&signed_update).await?;

        println!();
        println!("CustodyAcquire published successfully!");
        println!("  Sequence: {}", sequence);
        println!("  Hash: {}...", &hex::encode(new_hash)[..16]);
    } else {
        println!("You did NOT win. Publishing CustodyYield...");

        let operation = LedgerOperation::CustodyYield;
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
            partner_signature: [0u8; 64],
            operator_id: our_pubkey,
            ledger_id: ledger_id_bytes,
            sequence_number: sequence,
            previous_hash: our_latest.current_hash,
            current_hash: new_hash,
            timestamp: deposits_core::now_unix_timestamp(),
            block_height: current_block_height,
            block_hash: entropy_block_hash,
        };

        let publish_transport = NostrTransportBuilder::new(secret_key)
            .relay(&relay_url)
            .build()
            .await?;

        publish_transport.broadcast_ledger_update(&signed_update).await?;

        println!();
        println!("CustodyYield published successfully!");
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
    let keys = Keys::generate();
    let client = Client::new(keys);
    client.add_relay(&relay_url).await
        .map_err(|e| format!("Failed to add relay: {}", e))?;
    client.connect().await;

    let filter = Filter::new()
        .kind(Kind::Custom(KIND_LEDGER_UPDATE))
        .custom_tag(SingleLetterTag::lowercase(Alphabet::D), [ledger_id.as_str()])
        .limit(500);

    let events = client
        .fetch_events(vec![filter], None)
        .await
        .map_err(|e| format!("Failed to fetch events: {}", e))?;

    client.disconnect().await.ok();

    let mut our_latest: Option<SignedLedgerUpdate> = None;
    let mut has_custody_acquire = false;
    let mut original_depositors: Vec<PublicKey> = Vec::new();

    for event in events.iter() {
        if let Ok(tlv_bytes) = BASE64.decode(&event.content) {
            if let Ok(update) = SignedLedgerUpdate::tlv_decode(&tlv_bytes) {
                if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                    if let LedgerOperation::DepositOpen { pubkey, .. } = op {
                        if !original_depositors.contains(&pubkey) {
                            original_depositors.push(pubkey);
                        }
                    }
                }

                if update.operator_id == our_pubkey {
                    if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                        if matches!(op, LedgerOperation::CustodyAcquire { .. }) {
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
        return Err("You don't have CustodyAcquire. You must win custody first (recovery claim).".into());
    }

    println!("  Your latest: seq {} (hash: {}...)", latest.sequence_number, hex::encode(&latest.current_hash[..8]));

    let depositor_pubkey = original_depositors.first().copied().unwrap_or(our_pubkey);

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
            deposit_pubkey: depositor_pubkey,
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
            partner_signature: [0u8; 64],
            operator_id: our_pubkey,
            ledger_id: ledger_id_bytes,
            sequence_number: sequence,
            previous_hash: latest.current_hash,
            current_hash: new_hash,
            timestamp: deposits_core::now_unix_timestamp(),
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

    println!("Building confiscation transaction for ledger: {}...", &ledger_id[..16.min(ledger_id.len())]);
    println!("Note: Full implementation requires quorum signatures. See recovery lottery-claim.");

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

    println!("Checking lottery result for ledger: {}...", &ledger_id[..16.min(ledger_id.len())]);
    println!("Note: Full implementation requires collecting all revealed preimages from Nostr.");

    Ok(())
}

/// Rotate lottery winnings to a quorum-controlled Taproot address.
pub async fn recovery_rotate_to_quorum(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
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

    println!("Rotating lottery winnings to quorum-controlled Taproot...");
    println!("  Ledger: {}...", &ledger_id[..16.min(ledger_id.len())]);
    println!("Note: Full implementation requires on-chain transaction.");

    Ok(())
}
