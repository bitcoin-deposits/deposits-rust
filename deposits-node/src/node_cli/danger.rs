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
        "forge-stale-cosig" => danger_forge_stale_cosig(&args[1..]).await,
        cmd => {
            eprintln!("Unknown danger subcommand: {}", cmd);
            eprintln!("Available: publish-invalid, forge-stale-cosig");
            Ok(())
        }
    }
}

/// Publish a SignedLedgerUpdate signed by the operator that carries a
/// CosignEntry whose `member_ledger_hash` references a deliberately
/// stale state of a real quorum member's ledger. Used by the fraud-
/// proof integration test as the "evidence" the StaleCosignature
/// verifier inspects.
///
/// Usage: `danger forge-stale-cosig <reserves_id> <stale_member_hash_hex> <block_height>`
async fn danger_forge_stale_cosig(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use crate::nostr::NostrTransportBuilder;
    use bitcoin::secp256k1::{Keypair, Message, Secp256k1};
    use deposits_core::messages::LedgerOperation;
    use deposits_core::types::CosignEntry;
    use deposits_core::SignedLedgerUpdate;
    use deposits_core::TlvEncode;
    use sha2::{Digest, Sha256};

    if args.len() < 3 {
        eprintln!(
            "Usage: deposits-node danger forge-stale-cosig <reserves_id> <stale_member_hash_hex> <block_height>"
        );
        return Ok(());
    }

    let reserves_id = &args[0];
    let stale_member_hash: [u8; 32] = {
        let bytes = hex::decode(&args[1])?;
        bytes
            .try_into()
            .map_err(|_| "stale_member_hash must be 32 bytes")?
    };
    let block_height: u32 = args[2].parse()?;

    let mut config_args = Vec::new();
    let mut i = 3;
    while i < args.len() {
        config_args.push(args[i].clone());
        if i + 1 < args.len() && !args[i + 1].starts_with("--") {
            config_args.push(args[i + 1].clone());
            i += 1;
        }
        i += 1;
    }
    let config = parse_config(&config_args)?;
    let relay_url = config
        .relays
        .first()
        .ok_or("No relay configured")?
        .clone();
    let data_dir = config.data_dir.clone();

    let secp = Secp256k1::new();
    let secret_key = super::derive_operator_secret(&config.seed, config.network)?;
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let operator_pubkey = keypair.public_key();

    let node = Node::new(config).await?;
    let (ledger_id, ledger) = node
        .get_ledger_with_id(reserves_id)
        .ok_or_else(|| format!("Ledger not found: {}", reserves_id))?;
    let last = ledger
        .history
        .last()
        .ok_or("Ledger has no history")?
        .clone();
    let next_seq = last.sequence_number + 1;
    let prev_chain_hash = last.chain_hash();

    // No-op operation that records the forgery without touching state.
    let op = LedgerOperation::DeliveryEmbed {
        request_hash: [0u8; 32], // random padding; not used for staleness
        target_ledger_id: ledger.state.ledger_id,
        target_operator: operator_pubkey,
    };
    let message_bytes = op.tlv_encode();
    let message_type = op.message_type();

    // Forge: set cosignatures to a single CosignEntry with the stale hash.
    let cosignatures = vec![CosignEntry {
        cosigner_pubkey: operator_pubkey, // anyone valid; verifier only checks
                                          // the member_ledger_hash field
        cosign_signature: [0u8; 64],
        member_ledger_hash: stale_member_hash,
    }];

    // content_hash is derived after construction via the protocol's
    // multi-cosig formula (`SignedLedgerUpdate::compute_hash`). The TLV
    // wire format omits content_hash entirely; receivers recompute it on
    // decode, so we MUST use the canonical formula here or our on-disk
    // chain_hash will diverge from every other peer's view.
    let cosign_signature = [0u8; 64];
    let mut update = SignedLedgerUpdate {
        message: message_bytes,
        message_type,
        operator_id: operator_pubkey,
        ledger_id: ledger.state.ledger_id,
        sequence_number: next_seq,
        previous_hash: prev_chain_hash,
        content_hash: [0u8; 32],
        block_height,
        block_hash: [0u8; 32],
        cosign_signature,
        operator_signature: [0u8; 64],
        cosigner_pubkey: None,
        member_ledger_hash: None,
        cosignatures,
    };
    update.content_hash = update.compute_hash();
    let content_hash = update.content_hash;

    // Sign with operator's key over operator_signing_data.
    let signing_data = update.operator_signing_data();
    let hash = Sha256::digest(&signing_data);
    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(&hash);
    let msg = Message::from_digest(hash_bytes);
    let sig = secp.sign_schnorr_no_aux_rand(&msg, &keypair);
    update.operator_signature = sig.serialize();

    println!("Forged stale-cosignature update:");
    println!("  Ledger:      {}", ledger_id);
    println!("  Sequence:    {}", next_seq);
    println!("  Block:       {}", block_height);
    println!(
        "  Stale hash:  {}...",
        &hex::encode(stale_member_hash)[..16]
    );
    println!(
        "  Content:     {}...",
        &hex::encode(content_hash)[..16]
    );
    println!();

    let transport = NostrTransportBuilder::new(secret_key)
        .relay(&relay_url)
        .build()
        .await?;
    let event_id = transport.broadcast_ledger_update(&update).await?;
    // Give the relay pool time to flush — `broadcast_ledger_update`
    // returns when the message is queued for the relay, not when the
    // relay has acknowledged the EVENT message. Disconnecting too fast
    // (sub-millisecond) tears the WebSocket down before strfry sees it.
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    transport.disconnect().await;

    // Op0's daemon skips inbound updates on its own ledger (`handle_ledger_update`
    // returns early when operator_key == self.node_id) so the daemon won't
    // persist this forge. Append directly to the JSONL so subsequent CLI
    // invocations and disk-readers see the chain at the new tip.
    append_update_to_local_jsonl(&data_dir, &ledger_id, &update)?;

    println!("Broadcast: {}", event_id);
    Ok(())
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
    let content_hash = last_update.content_hash;

    println!("=== DANGER: Publishing Invalid Ledger Update ===");
    println!();
    println!("WARNING: This creates a non-conforming update!");
    println!("Only use for testing recovery mechanisms.");
    println!();
    println!("Ledger: {}", ledger_id);
    println!("Current sequence: {}", current_seq);
    println!("Current hash: {}...", &hex::encode(content_hash)[..16]);
    println!("Violation type: {}", violation_type);
    println!();

    // Create the invalid update based on violation type
    let invalid_update: SignedLedgerUpdate = match violation_type.as_str() {
        "invalid-hash" => {
            let wrong_prev_hash = {
                let mut h = content_hash;
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
                content_hash: computed_hash,
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
                hasher.update(&content_hash);
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
                data.extend_from_slice(&content_hash);
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
                previous_hash: content_hash,
                content_hash: computed_hash,
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
                data.extend_from_slice(&replayed.content_hash);
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
        &hex::encode(invalid_update.content_hash)[..16]
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

/// Append a SignedLedgerUpdate as a `{"type":"Update", ...}` JSONL row to
/// the operator's on-disk ledger log. Used by CLI commands (forge,
/// embed-hash) that produce updates the running daemon won't persist
/// itself (e.g. updates on the operator's own ledger arriving inbound,
/// which the daemon skips by design).
pub(crate) fn append_update_to_local_jsonl(
    data_dir: &std::path::Path,
    ledger_id: &str,
    update: &deposits_core::SignedLedgerUpdate,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;

    let path = data_dir
        .join("wallet/ledgers")
        .join(format!("{}.jsonl", ledger_id));
    // Build a JSON object that matches the daemon's `LedgerLogRow::Update`
    // wire shape: a SignedLedgerUpdate flattened with `"type":"Update"`.
    let mut value = serde_json::to_value(update)?;
    if let Some(obj) = value.as_object_mut() {
        obj.insert("type".to_string(), serde_json::Value::String("Update".into()));
    }
    let json = serde_json::to_string(&value)?;

    // The daemon's `append_updates_to_disk` writes `"\n{LINE}"` (no
    // trailing newline), so the file may end mid-line. Probe the last byte;
    // if it isn't '\n', prepend one so our row doesn't concatenate onto the
    // previous line and produce invalid JSON.
    let needs_lead_nl = match std::fs::metadata(&path) {
        Ok(m) if m.len() > 0 => {
            use std::io::{Read, Seek, SeekFrom};
            let mut f = std::fs::File::open(&path)?;
            f.seek(SeekFrom::End(-1))?;
            let mut last = [0u8; 1];
            f.read_exact(&mut last)?;
            last[0] != b'\n'
        }
        _ => false,
    };

    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(&path)?;
    if needs_lead_nl {
        file.write_all(b"\n")?;
    }
    file.write_all(json.as_bytes())?;
    file.write_all(b"\n")?;
    Ok(())
}
