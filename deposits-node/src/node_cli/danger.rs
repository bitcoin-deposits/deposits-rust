// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Dangerous testing commands - only available with the `dangerous-testing` feature.

use super::parse_config;
use crate::Node;

pub async fn danger_command(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.is_empty() {
        eprintln!("Usage: deposits-node danger <subcommand> [args...]");
        eprintln!("Subcommands:");
        eprintln!("  publish-invalid <reserves_id> <violation_type>");
        return Ok(());
    }

    match args[0].as_str() {
        "publish-invalid" => danger_publish_invalid(&args[1..]).await,
        cmd => {
            eprintln!("Unknown danger subcommand: {}", cmd);
            eprintln!("Available: publish-invalid");
            Ok(())
        }
    }
}

/// Publish an invalid ledger update to test recovery mechanisms.
/// WARNING: This creates non-conforming updates that break protocol rules.
async fn danger_publish_invalid(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
    use deposits_core::SignedLedgerUpdate;
    use crate::nostr::NostrTransportBuilder;
    use sha2::{Digest, Sha256};

    if args.len() < 2 {
        eprintln!("Usage: deposits-node danger publish-invalid <reserves_id> <violation_type> [options...]");
        eprintln!();
        eprintln!("Violation types:");
        eprintln!("  invalid-hash   - Wrong previous_hash linkage");
        eprintln!("  skip-sequence  - Skip ahead in sequence numbers");
        eprintln!("  replay         - Replay an old update");
        eprintln!();
        eprintln!("Examples:");
        eprintln!("  danger publish-invalid bcrt1q... invalid-hash");
        eprintln!("  danger publish-invalid bcrt1q... skip-sequence");
        return Ok(());
    }

    let reserves_id_arg = &args[0];
    let violation_type = &args[1];
    let config_args: Vec<String> = args.iter().skip(2).cloned().collect();

    let config = parse_config(&config_args)?;

    let relay_url = config
        .relays
        .first()
        .ok_or("No relay configured. Use --relay <url>")?
        .clone();

    let secret_key = super::derive_operator_secret(&config.seed, config.network)?;
    let secp = Secp256k1::new();

    // Get the node to access the ledger
    let node = Node::new(config).await?;

    // Resolve reserves_id to ledger_id
    let (ledger_id, ledger) = node
        .get_ledger_with_id(reserves_id_arg)
        .ok_or_else(|| format!("Ledger not found: {}", reserves_id_arg))?;

    if ledger.history.is_empty() {
        return Err("Ledger has no history - cannot create invalid update".into());
    }

    let last_update = ledger.history.last().unwrap();
    let current_seq = last_update.sequence_number;
    let current_hash = last_update.current_hash;

    println!("=== DANGER: Publishing Invalid Ledger Update ===");
    println!();
    println!("WARNING: This creates a non-conforming update!");
    println!("Only use for testing recovery mechanisms.");
    println!();
    println!("Ledger: {}", ledger_id);
    println!("Current sequence: {}", current_seq);
    println!("Current hash: {}...", &hex::encode(current_hash)[..16]);
    println!("Violation type: {}", violation_type);
    println!();

    // Create the invalid update based on violation type
    let invalid_update: SignedLedgerUpdate = match violation_type.as_str() {
        "invalid-hash" => {
            let wrong_prev_hash = {
                let mut h = current_hash;
                h[0] ^= 0xFF;
                h[1] ^= 0xAA;
                h
            };

            let dummy_message = vec![0u8; 8];
            let message_type: u16 = 0x0001;
            let new_seq = current_seq + 1;

            let computed_hash = {
                let mut hasher = Sha256::new();
                hasher.update(&new_seq.to_le_bytes());
                hasher.update(&wrong_prev_hash);
                hasher.update(&dummy_message);
                let result = hasher.finalize();
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&result);
                hash
            };

            let signing_data = {
                let mut data = Vec::new();
                data.extend_from_slice(&dummy_message);
                data.extend_from_slice(&message_type.to_le_bytes());
                data.extend_from_slice(&new_seq.to_le_bytes());
                data.extend_from_slice(&wrong_prev_hash);
                data.extend_from_slice(&computed_hash);
                data
            };

            let msg_hash = sha256_hash(&signing_data);
            let message = Message::from_digest(msg_hash);
            let sig = secp.sign_schnorr(&message, &secret_key.keypair(&secp));
            let operator_signature = sig.serialize();

            SignedLedgerUpdate {
                message: dummy_message,
                message_type,
                operator_id: node.node_id,
                ledger_id: ledger.ledger_id(),
                sequence_number: new_seq,
                previous_hash: wrong_prev_hash,
                current_hash: computed_hash,
                block_height: 0,
                block_hash: [0u8; 32],
                cosign_signature: [0u8; 64],
                operator_signature,
                cosigner_pubkey: None,
                member_ledger_hash: None,
                cosignatures: Vec::new(),
            }
        }

        "skip-sequence" => {
            let skipped_seq = current_seq + 5;

            let dummy_message = vec![0u8; 8];
            let message_type: u16 = 0x0001;

            let computed_hash = {
                let mut hasher = Sha256::new();
                hasher.update(&skipped_seq.to_le_bytes());
                hasher.update(&current_hash);
                hasher.update(&dummy_message);
                let result = hasher.finalize();
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&result);
                hash
            };

            let signing_data = {
                let mut data = Vec::new();
                data.extend_from_slice(&dummy_message);
                data.extend_from_slice(&message_type.to_le_bytes());
                data.extend_from_slice(&skipped_seq.to_le_bytes());
                data.extend_from_slice(&current_hash);
                data.extend_from_slice(&computed_hash);
                data
            };

            let msg_hash = sha256_hash(&signing_data);
            let message = Message::from_digest(msg_hash);
            let sig = secp.sign_schnorr(&message, &secret_key.keypair(&secp));
            let operator_signature = sig.serialize();

            SignedLedgerUpdate {
                message: dummy_message,
                message_type,
                operator_id: node.node_id,
                ledger_id: ledger.ledger_id(),
                sequence_number: skipped_seq,
                previous_hash: current_hash,
                current_hash: computed_hash,
                block_height: 0,
                block_hash: [0u8; 32],
                cosign_signature: [0u8; 64],
                operator_signature,
                cosigner_pubkey: None,
                member_ledger_hash: None,
                cosignatures: Vec::new(),
            }
        }

        "replay" => {
            if ledger.history.len() < 2 {
                return Err("Need at least 2 updates to create replay attack".into());
            }

            let old_update = &ledger.history[ledger.history.len() / 2];
            let mut replayed = old_update.clone();

            let signing_data = {
                let mut data = Vec::new();
                data.extend_from_slice(&replayed.message);
                data.extend_from_slice(&replayed.message_type.to_le_bytes());
                data.extend_from_slice(&replayed.sequence_number.to_le_bytes());
                data.extend_from_slice(&replayed.previous_hash);
                data.extend_from_slice(&replayed.current_hash);
                data
            };

            let msg_hash = sha256_hash(&signing_data);
            let message = Message::from_digest(msg_hash);
            let sig = secp.sign_schnorr(&message, &secret_key.keypair(&secp));
            replayed.operator_signature = sig.serialize();

            println!("Replaying update at sequence {}", replayed.sequence_number);

            replayed
        }

        unknown => {
            return Err(format!(
                "Unknown violation type: {}. Valid: invalid-hash, skip-sequence, replay",
                unknown
            )
            .into());
        }
    };

    println!("Created invalid update:");
    println!("  Sequence: {}", invalid_update.sequence_number);
    println!(
        "  Previous hash: {}...",
        &hex::encode(invalid_update.previous_hash)[..16]
    );
    println!(
        "  Current hash: {}...",
        &hex::encode(invalid_update.current_hash)[..16]
    );

    // Broadcast to Nostr
    println!();
    println!("Broadcasting to relay: {}", relay_url);

    let transport = NostrTransportBuilder::new(secret_key)
        .relay(&relay_url)
        .build()
        .await?;

    let event_id = transport.broadcast_ledger_update(&invalid_update).await?;

    transport.disconnect().await;

    println!("Published invalid update!");
    println!("  Event ID: {}", event_id);
    println!();
    println!("To test recovery, try:");
    println!(
        "  deposits-node nostr import {}:{}",
        node.node_id, ledger_id
    );
    println!("  deposits-node ledger validate {}", ledger_id);

    Ok(())
}

fn sha256_hash(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}
